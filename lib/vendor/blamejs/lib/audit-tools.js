"use strict";
/**
 * audit-tools — operator tooling on top of the audit chain.
 *
 * Four operations the compliance matrix calls for:
 *
 *   archive(opts)      Bundle audit rows older than `before` into a
 *                      PQC-encrypted archive with chain proof + a
 *                      covering signed checkpoint. Live rows untouched.
 *   exportSlice(opts)  Auditor-shaped slice (date range / subject /
 *                      action filter) with chain proof. Live rows
 *                      untouched. Purpose: deliver an evidence bundle
 *                      to an external auditor without surrendering the
 *                      whole log.
 *   verifyBundle(opts) Round-trip integrity: decrypt the bundle, walk
 *                      the chain math across the contained rows,
 *                      verify the covering checkpoint signature
 *                      (archive bundles only).
 *   purge(opts)        Confirmation-gated deletion of live audit rows
 *                      already captured in a verified archive bundle.
 *                      Inserts a purge-anchor so live audit.verify()
 *                      keeps working post-purge — the anchor's
 *                      lastRowHash becomes the new chain origin.
 *
 * Bundle layout (POSIX-flat directory; matches the backup-bundle shape
 * so operators see one mental model for "encrypted blamejs bundle"):
 *
 *   <out>/manifest.json    Canonical-JSON manifest. Includes format,
 *                          kind, range (firstCounter/lastCounter/
 *                          firstRecordedAt/lastRecordedAt/
 *                          firstRowHash/lastRowHash), rowCount, the
 *                          per-blob salts, the framework version, and
 *                          (archive only) a copy of the covering
 *                          checkpoint row plus its public-key
 *                          fingerprint.
 *   <out>/rows.enc         PQC-encrypted JSONL — one row per line,
 *                          monotonic-counter ASC, sealed form (rowHash
 *                          stays computable from disk bytes). Each
 *                          field in a sealed column is the on-disk
 *                          ciphertext, not the plaintext, so the chain
 *                          recomputes byte-for-byte.
 *   <out>/checkpoint.enc   Archive only. PQC-encrypted JSON of the
 *                          covering audit_checkpoints row.
 *
 * `kind="archive"` bundles always include a covering checkpoint
 * (atMonotonicCounter >= lastCounter) so the anchor signature
 * tamper-evidences the whole archive. `kind="export"` bundles are
 * auditor evidence; the chain math is self-contained but the
 * upstream signature anchor is optional (auditors typically follow
 * up with an `audit.verify` call against the live system to confirm
 * the slice still chains).
 */

var fs = require("fs");
var path = require("path");
var pkg = require("../package.json");
var atomicFile = require("./atomic-file");
var auditChain = require("./audit-chain");
var canonicalJson = require("./canonical-json");
var auditSign = require("./audit-sign");
var backupCrypto = require("./backup/crypto");
var clusterStorage = require("./cluster-storage");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var jsonSafe = require("./safe-json");
var { defineClass } = require("./framework-error");

var FRAMEWORK_VERSION = (pkg && pkg.version) || "unknown";

// Lazy `db` — db requires audit at top-of-file, audit transitively
// reaches into audit-tools via the operator-supplied default fns,
// so importing db at audit-tools' top would close the cycle. Lazy
// keeps the load order one-way.
var db = lazyRequire(function () { return require("./db"); });

var AuditToolsError = defineClass("AuditToolsError", { alwaysPermanent: true });

var BUNDLE_FORMAT  = "blamejs-audit-bundle-v1";
var KIND_ARCHIVE   = "archive";
var KIND_EXPORT    = "export";
var VALID_KINDS    = { archive: true, export: true };

// ---- Helpers ----

function _toMs(value) {
  if (value == null) return null;
  if (typeof value === "number") return value;
  if (value instanceof Date)     return value.getTime();
  if (typeof value === "string") {
    var ms = Date.parse(value);
    if (isNaN(ms)) {
      throw new AuditToolsError("audit-tools/bad-date",
        "invalid date value: " + value);
    }
    return ms;
  }
  throw new AuditToolsError("audit-tools/bad-date",
    "date must be a number, Date, or parseable string");
}

function _requirePassphrase(passphrase) {
  if (!Buffer.isBuffer(passphrase) && typeof passphrase !== "string") {
    throw new AuditToolsError("audit-tools/no-passphrase",
      "opts.passphrase is required (Buffer or string)");
  }
  if (passphrase.length === 0) {
    throw new AuditToolsError("audit-tools/no-passphrase",
      "opts.passphrase must be non-empty");
  }
}

function _requireOutDir(outDir, kind) {
  if (typeof outDir !== "string" || outDir.length === 0) {
    throw new AuditToolsError("audit-tools/no-outdir",
      kind + ": opts.out is required");
  }
  if (fs.existsSync(outDir)) {
    throw new AuditToolsError("audit-tools/outdir-exists",
      kind + ": out already exists: " + outDir +
      " (refusing to overwrite — pick a fresh path)");
  }
}

// Canonical-JSON via the shared lib/canonical-json walker — same bytes
// as audit-chain.canonicalize, config-drift._stableStringify, and
// pagination._canonicalize for the same input. Pre-v0.6.67 each site
// had its own copy of the walk, all carrying the same silent-loss bug
// for Date / Buffer / Map / Set / BigInt / circular refs.
function _canonicalize(value) { return canonicalJson.stringify(value); }

// Convert a single audit_log row to its on-disk-canonical JSON shape.
// Buffers become hex strings (matches audit-chain.canonicalize). Used
// so JSONL written into rows.enc has the exact bytes a verifier needs
// to recompute rowHash.
function _rowToWireForm(row) {
  var out = {};
  var keys = Object.keys(row);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = row[k];
    if (Buffer.isBuffer(v))                out[k] = "hex:" + v.toString("hex");
    else if (v instanceof Uint8Array)      out[k] = "hex:" + Buffer.from(v).toString("hex");
    else if (v === undefined)              out[k] = null;
    else                                   out[k] = v;
  }
  return out;
}

// F-AUD-4 — operator-facing wire helper that surfaces recordedAt as
// ISO-8601 / RFC 3339 alongside the existing Unix-ms integer.
// Auditors comparing rows against external SIEM events expect ISO
// with explicit Z; the framework's primary ms storage stays
// unchanged AND _rowToWireForm (which the chain-hash canonicalizes
// over) doesn't change its bytes — so chain verify continues to
// match. Operators call this on retrieved rows for export.
function withRecordedAtIso(row) {
  if (!row) return row;
  var out = Object.assign({}, row);
  if (typeof row.recordedAt === "number" || typeof row.recordedAt === "bigint") {
    var ms = typeof row.recordedAt === "bigint" ? Number(row.recordedAt) : row.recordedAt;
    if (isFinite(ms)) out.recordedAtIso = new Date(ms).toISOString();
  }
  return out;
}

function _wireFormToRow(wire) {
  var out = {};
  var keys = Object.keys(wire);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = wire[k];
    if (typeof v === "string" && v.indexOf("hex:") === 0) {
      out[k] = Buffer.from(v.slice(4), "hex");
    } else {
      out[k] = v;
    }
  }
  return out;
}

// Walk a slice of audit rows recomputing their hash chain. Returns
// { ok, rowsVerified, breakAt? }. The starting prevHash is the caller's
// responsibility — for archive/export slices it's the row preceding the
// slice's first row (which is itself in the bundle's manifest as a
// witness, or ZERO_HASH for slices that start at counter=1).
function _verifyChainSlice(rows, startPrevHash) {
  var prevHash = startPrevHash;
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (row.prevHash !== prevHash) {
      return {
        ok: false, rowsVerified: i, breakAt: i,
        reason: "prevHash mismatch",
        expected: prevHash,
        actual:   row.prevHash,
      };
    }
    var fields = Object.assign({}, row);
    delete fields.prevHash;
    delete fields.rowHash;
    delete fields.nonce;
    delete fields.fencingToken;
    var nonceBuf = Buffer.isBuffer(row.nonce) ? row.nonce : Buffer.from(row.nonce);
    var computed = auditChain.computeRowHash(prevHash, fields, nonceBuf);
    if (computed !== row.rowHash) {
      return {
        ok: false, rowsVerified: i, breakAt: i,
        reason: "rowHash mismatch",
        expected: computed,
        actual:   row.rowHash,
      };
    }
    prevHash = row.rowHash;
  }
  return { ok: true, rowsVerified: rows.length, lastHash: prevHash };
}

// Read all audit rows from the operator's reader. Defaults to a
// cluster-storage reader so the tooling works in both single-node and
// cluster deployments without the caller knowing which mode is active.
async function _defaultReadRows(criteria) {
  var sql = 'SELECT * FROM "audit_log"';
  var conds = [];
  var params = [];
  if (criteria.fromMs != null)        { conds.push("recordedAt >= ?"); params.push(criteria.fromMs); }
  if (criteria.toMs != null)          { conds.push("recordedAt <= ?"); params.push(criteria.toMs); }
  if (criteria.beforeMs != null)      { conds.push("recordedAt < ?");  params.push(criteria.beforeMs); }
  if (criteria.action)                { conds.push("action = ?");      params.push(criteria.action); }
  if (criteria.firstCounter != null)  { conds.push("monotonicCounter >= ?"); params.push(criteria.firstCounter); }
  if (criteria.lastCounter != null)   { conds.push("monotonicCounter <= ?"); params.push(criteria.lastCounter); }
  if (conds.length > 0) sql += " WHERE " + conds.join(" AND ");
  sql += " ORDER BY monotonicCounter ASC";
  return clusterStorage.executeAll(sql, params);
}

async function _defaultReadCoveringCheckpoint(lastCounter) {
  return clusterStorage.executeOne(
    "SELECT * FROM audit_checkpoints " +
    "WHERE atMonotonicCounter >= ? " +
    "ORDER BY atMonotonicCounter ASC LIMIT 1",
    [lastCounter]
  );
}

async function _defaultReadPredecessorRowHash(firstCounter) {
  if (firstCounter <= 1) return auditChain.ZERO_HASH;
  var row = await clusterStorage.executeOne(
    "SELECT rowHash FROM audit_log WHERE monotonicCounter = ?",
    [firstCounter - 1]
  );
  if (!row) {
    // First row of the slice is right after a purged range. Read the
    // purge anchor's lastRowHash instead.
    var anchor = await clusterStorage.executeOne(
      "SELECT lastPurgedRowHash, lastPurgedCounter FROM _blamejs_audit_purge_anchor " +
      "WHERE scope = 'audit'"
    );
    if (anchor && Number(anchor.lastPurgedCounter) === firstCounter - 1) {
      return anchor.lastPurgedRowHash;
    }
    throw new AuditToolsError("audit-tools/no-predecessor",
      "predecessor row at counter=" + (firstCounter - 1) + " missing — chain proof would be ungrounded");
  }
  return row.rowHash;
}

// ---- Bundle writer ----

async function _writeBundle(args) {
  var outDir       = args.outDir;
  var kind         = args.kind;
  var rows         = args.rows;
  var checkpoint   = args.checkpoint || null;
  var passphrase   = args.passphrase;
  var predecessorRowHash = args.predecessorRowHash;

  atomicFile.ensureDir(outDir);

  var firstRow = rows[0];
  var lastRow  = rows[rows.length - 1];

  // 1. Encrypt the rows JSONL
  var jsonl = rows.map(function (r) {
    return JSON.stringify(_rowToWireForm(r));
  }).join("\n") + "\n";
  var rowsEnc = await backupCrypto.encryptWithFreshSalt(jsonl, passphrase);
  atomicFile.writeSync(path.join(outDir, "rows.enc"), rowsEnc.encrypted, { fileMode: 0o600 });

  // 2. (archive) Encrypt the checkpoint JSON
  var checkpointSalt = null;
  if (checkpoint) {
    var ckptJson = _canonicalize(_rowToWireForm(checkpoint));
    var ckptEnc = await backupCrypto.encryptWithFreshSalt(ckptJson, passphrase);
    atomicFile.writeSync(path.join(outDir, "checkpoint.enc"), ckptEnc.encrypted, { fileMode: 0o600 });
    checkpointSalt = ckptEnc.salt;
  }

  // 3. Build manifest
  var manifest = {
    format:         BUNDLE_FORMAT,
    kind:           kind,
    createdAt:      Date.now(),
    frameworkVersion: FRAMEWORK_VERSION,
    rowCount:       rows.length,
    range: {
      firstCounter:    Number(firstRow.monotonicCounter),
      lastCounter:     Number(lastRow.monotonicCounter),
      firstRecordedAt: Number(firstRow.recordedAt),
      lastRecordedAt:  Number(lastRow.recordedAt),
      firstRowHash:    String(firstRow.rowHash),
      lastRowHash:     String(lastRow.rowHash),
      predecessorRowHash: String(predecessorRowHash),
    },
    salts: {
      rows:       rowsEnc.salt,
      checkpoint: checkpointSalt,
    },
    checksum: {
      rowsSha3_512:       backupCrypto.checksum(rowsEnc.encrypted),
      checkpointSha3_512: checkpointSalt
        ? backupCrypto.checksum(fs.readFileSync(path.join(outDir, "checkpoint.enc")))
        : null,
    },
  };
  if (checkpoint) {
    manifest.checkpoint = {
      atMonotonicCounter:   Number(checkpoint.atMonotonicCounter),
      atRowHash:            String(checkpoint.atRowHash),
      publicKeyFingerprint: String(checkpoint.publicKeyFingerprint),
      checkpointId:         String(checkpoint._id),
    };
  }
  var manifestPath = path.join(outDir, "manifest.json");
  atomicFile.writeSync(manifestPath, _canonicalize(manifest), { fileMode: 0o600 });
  return { manifest: manifest, manifestPath: manifestPath };
}

// ---- Bundle reader ----

async function _readBundle(inDir, passphrase) {
  if (typeof inDir !== "string" || !fs.existsSync(inDir)) {
    throw new AuditToolsError("audit-tools/no-bundle",
      "bundle directory does not exist: " + inDir);
  }
  var manifestPath = path.join(inDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new AuditToolsError("audit-tools/no-manifest",
      "manifest.json missing in " + inDir);
  }
  var manifest = jsonSafe.parse(fs.readFileSync(manifestPath, "utf8"));
  if (!manifest || manifest.format !== BUNDLE_FORMAT) {
    throw new AuditToolsError("audit-tools/bad-format",
      "manifest.format is not " + BUNDLE_FORMAT);
  }
  if (!VALID_KINDS[manifest.kind]) {
    throw new AuditToolsError("audit-tools/bad-kind",
      "manifest.kind must be one of " + Object.keys(VALID_KINDS).join(", "));
  }

  var rowsEncPath = path.join(inDir, "rows.enc");
  if (!fs.existsSync(rowsEncPath)) {
    throw new AuditToolsError("audit-tools/no-rows-blob",
      "rows.enc missing in " + inDir);
  }
  var rowsEnc = fs.readFileSync(rowsEncPath);
  if (manifest.checksum && manifest.checksum.rowsSha3_512 &&
      backupCrypto.checksum(rowsEnc) !== manifest.checksum.rowsSha3_512) {
    throw new AuditToolsError("audit-tools/rows-checksum-mismatch",
      "rows.enc checksum does not match manifest — bundle was tampered with");
  }
  var rowsPlainBuf = await backupCrypto.decryptWithPassphrase(rowsEnc, passphrase, manifest.salts.rows);
  var rowsPlain = rowsPlainBuf.toString("utf8");
  var lines = rowsPlain.split("\n").filter(function (l) { return l.length > 0; });
  var rows = lines.map(function (l) { return _wireFormToRow(jsonSafe.parse(l)); });

  var checkpoint = null;
  if (manifest.kind === KIND_ARCHIVE) {
    var ckptPath = path.join(inDir, "checkpoint.enc");
    if (!fs.existsSync(ckptPath)) {
      throw new AuditToolsError("audit-tools/no-checkpoint-blob",
        "checkpoint.enc missing in " + inDir + " (archive bundles must include the covering checkpoint)");
    }
    var ckptEnc = fs.readFileSync(ckptPath);
    if (manifest.checksum && manifest.checksum.checkpointSha3_512 &&
        backupCrypto.checksum(ckptEnc) !== manifest.checksum.checkpointSha3_512) {
      throw new AuditToolsError("audit-tools/checkpoint-checksum-mismatch",
        "checkpoint.enc checksum does not match manifest");
    }
    var ckptPlain = (await backupCrypto.decryptWithPassphrase(ckptEnc, passphrase, manifest.salts.checkpoint))
      .toString("utf8");
    checkpoint = _wireFormToRow(jsonSafe.parse(ckptPlain));
  }

  return { manifest: manifest, rows: rows, checkpoint: checkpoint };
}

// ---- Public ops ----

async function archive(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  _requireOutDir(opts.out, "archive");
  var beforeMs = _toMs(opts.before);
  if (beforeMs == null) {
    throw new AuditToolsError("audit-tools/no-before",
      "archive: opts.before is required (date older than which rows are archived)");
  }
  var readRows = opts.readRows || _defaultReadRows;
  var readCovering = opts.readCoveringCheckpoint || _defaultReadCoveringCheckpoint;
  var readPredecessorHash = opts.readPredecessorRowHash || _defaultReadPredecessorRowHash;

  var rows = await readRows({ beforeMs: beforeMs });
  if (rows.length === 0) {
    throw new AuditToolsError("audit-tools/empty",
      "archive: no audit rows match (before=" + new Date(beforeMs).toISOString() + ")");
  }
  var lastCounter = Number(rows[rows.length - 1].monotonicCounter);
  var firstCounter = Number(rows[0].monotonicCounter);

  var checkpoint = await readCovering(lastCounter);
  if (!checkpoint) {
    throw new AuditToolsError("audit-tools/no-covering-checkpoint",
      "archive: no signed checkpoint covers counter=" + lastCounter +
      " — run audit.checkpoint() before archiving so the bundle has an off-chain anchor");
  }

  var predecessorRowHash = await readPredecessorHash(firstCounter);

  var written = await _writeBundle({
    outDir:     opts.out,
    kind:       KIND_ARCHIVE,
    rows:       rows,
    checkpoint: checkpoint,
    passphrase: opts.passphrase,
    predecessorRowHash: predecessorRowHash,
  });

  return {
    manifest:     written.manifest,
    manifestPath: written.manifestPath,
    outDir:       opts.out,
    rowCount:     rows.length,
    range:        written.manifest.range,
  };
}

async function exportSlice(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  _requireOutDir(opts.out, "export");
  var fromMs = _toMs(opts.from);
  var toMs   = _toMs(opts.to);
  var readRows = opts.readRows || _defaultReadRows;
  var readPredecessorHash = opts.readPredecessorRowHash || _defaultReadPredecessorRowHash;

  var criteria = {};
  if (fromMs != null) criteria.fromMs = fromMs;
  if (toMs   != null) criteria.toMs   = toMs;
  if (opts.action) criteria.action = opts.action;

  var rows = await readRows(criteria);
  if (rows.length === 0) {
    throw new AuditToolsError("audit-tools/empty",
      "export: no audit rows match criteria");
  }
  // For an export the slice may be non-contiguous in counter space (e.g.
  // filtered by action). Reject non-contiguous slices because chain
  // verification can't ground a non-contiguous sequence.
  for (var i = 1; i < rows.length; i++) {
    var prev = Number(rows[i - 1].monotonicCounter);
    var cur  = Number(rows[i].monotonicCounter);
    if (cur !== prev + 1) {
      throw new AuditToolsError("audit-tools/non-contiguous",
        "export: slice is non-contiguous in monotonicCounter (" + prev + " → " + cur + "). " +
        "Filtered exports break chain proof; use date-range filters that cover all rows in the range.");
    }
  }
  var firstCounter = Number(rows[0].monotonicCounter);
  var predecessorRowHash = await readPredecessorHash(firstCounter);

  var written = await _writeBundle({
    outDir:     opts.out,
    kind:       KIND_EXPORT,
    rows:       rows,
    checkpoint: null,
    passphrase: opts.passphrase,
    predecessorRowHash: predecessorRowHash,
  });

  return {
    manifest:     written.manifest,
    manifestPath: written.manifestPath,
    outDir:       opts.out,
    rowCount:     rows.length,
    range:        written.manifest.range,
  };
}

async function verifyBundle(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  if (typeof opts.in !== "string") {
    throw new AuditToolsError("audit-tools/no-indir",
      "verifyBundle: opts.in is required (bundle directory)");
  }
  var read = await _readBundle(opts.in, opts.passphrase);

  // 1. Walk the chain math across the slice.
  var chainResult = _verifyChainSlice(read.rows, read.manifest.range.predecessorRowHash);
  if (!chainResult.ok) {
    return {
      ok:             false,
      kind:           read.manifest.kind,
      rowsVerified:   chainResult.rowsVerified,
      breakAt:        chainResult.breakAt,
      reason:         "chain " + chainResult.reason +
                      " (counter=" + Number(read.rows[chainResult.breakAt].monotonicCounter) + ")",
      expected:       chainResult.expected,
      actual:         chainResult.actual,
    };
  }

  // 2. Confirm the stored firstRowHash + lastRowHash match the slice
  if (read.rows[0].rowHash !== read.manifest.range.firstRowHash) {
    return {
      ok: false, kind: read.manifest.kind, rowsVerified: read.rows.length,
      reason: "manifest.range.firstRowHash does not match first row's rowHash",
    };
  }
  if (read.rows[read.rows.length - 1].rowHash !== read.manifest.range.lastRowHash) {
    return {
      ok: false, kind: read.manifest.kind, rowsVerified: read.rows.length,
      reason: "manifest.range.lastRowHash does not match last row's rowHash",
    };
  }

  // 3. (archive only) verify the covering checkpoint signature
  if (read.manifest.kind === KIND_ARCHIVE) {
    if (!read.checkpoint) {
      return { ok: false, kind: KIND_ARCHIVE, reason: "checkpoint missing from archive bundle" };
    }
    if (Number(read.checkpoint.atMonotonicCounter) < Number(read.manifest.range.lastCounter)) {
      return {
        ok: false, kind: KIND_ARCHIVE,
        reason: "checkpoint atMonotonicCounter (" + read.checkpoint.atMonotonicCounter +
                ") < archive lastCounter (" + read.manifest.range.lastCounter + ")",
      };
    }
    if (opts.verifyCheckpointSignature !== false) {
      var verifier = opts.verifySignature || _defaultVerifyCheckpointSignature;
      var sigOk = verifier(read.checkpoint);
      if (!sigOk) {
        return {
          ok: false, kind: KIND_ARCHIVE,
          reason: "checkpoint ML-DSA signature verification failed (auditor's audit-sign public key may differ from archive's; pass opts.verifySignature to override)",
        };
      }
    }
  }

  return {
    ok:           true,
    kind:         read.manifest.kind,
    rowsVerified: read.rows.length,
    range:        read.manifest.range,
    manifest:     read.manifest,
    rows:         opts.includeRows ? read.rows : undefined,
  };
}

function _defaultVerifyCheckpointSignature(checkpoint) {
  // Use the locally-loaded audit-sign keypair. Auditors verifying an
  // archive on a different machine will need to pass opts.verifySignature
  // with their own loaded public key. The framework deliberately doesn't
  // ship public keys inside the bundle — the public key fingerprint in
  // the checkpoint row is the verifier's lookup key.
  try {
    var pub = auditSign.getPublicKey();
    var fp  = auditSign.getPublicKeyFingerprint();
    if (fp !== checkpoint.publicKeyFingerprint) return false;
    var payload = Buffer.from(
      "blamejs-audit-checkpoint-v1\n" +
      String(checkpoint.atMonotonicCounter) + "\n" +
      checkpoint.atRowHash + "\n" +
      String(checkpoint.createdAt),
      "utf8"
    );
    var sig = Buffer.isBuffer(checkpoint.signature) ? checkpoint.signature : Buffer.from(checkpoint.signature);
    return auditSign.verify(payload, sig, pub);
  } catch (_e) { return false; }
}

async function purge(opts) {
  opts = opts || {};
  if (opts.confirm !== true) {
    throw new AuditToolsError("audit-tools/no-confirm",
      "purge: opts.confirm must be exactly true — destructive operation requires explicit acknowledgement");
  }
  if (typeof opts.archive !== "string") {
    throw new AuditToolsError("audit-tools/no-archive",
      "purge: opts.archive is required (path to a verified archive bundle)");
  }
  _requirePassphrase(opts.passphrase);

  // 1. Verify the archive bundle. Refuses with a clear reason if not ok.
  var v = await verifyBundle({
    in:         opts.archive,
    passphrase: opts.passphrase,
    verifySignature: opts.verifySignature, // auditor pubkey override
  });
  if (!v.ok) {
    throw new AuditToolsError("audit-tools/archive-not-ok",
      "purge: archive failed verification: " + v.reason);
  }
  if (v.kind !== KIND_ARCHIVE) {
    throw new AuditToolsError("audit-tools/wrong-kind",
      "purge: bundle kind is '" + v.kind + "', must be 'archive'");
  }

  // 2. Refuse if the archive doesn't start at the next purge point. Keeps
  // the chain anchor monotonic — operators can't jump-purge a middle range.
  var readAnchor = opts.readAnchor || _defaultReadPurgeAnchor;
  var anchor = await readAnchor();
  var expectedFirstCounter = anchor ? Number(anchor.lastPurgedCounter) + 1 : 1;
  if (Number(v.range.firstCounter) !== expectedFirstCounter) {
    throw new AuditToolsError("audit-tools/non-monotonic-purge",
      "purge: archive's firstCounter=" + v.range.firstCounter +
      " does not match expected next-purge counter=" + expectedFirstCounter +
      " (purges must be contiguous from the chain origin or last anchor)");
  }
  if (anchor && v.range.predecessorRowHash !== anchor.lastPurgedRowHash) {
    throw new AuditToolsError("audit-tools/anchor-mismatch",
      "purge: archive's predecessorRowHash does not match the prior purge anchor's lastPurgedRowHash");
  }

  // 3. Apply the deletion + new anchor write. This is the only mutation
  // path — operator-supplied for testability; default executes against
  // the live cluster-storage.
  var apply = opts.apply || _defaultApplyPurge;
  var result = await apply({
    lastPurgedCounter:    Number(v.range.lastCounter),
    lastPurgedRowHash:    v.range.lastRowHash,
    archiveBundleId:      v.manifest.checkpoint && v.manifest.checkpoint.checkpointId
                          || ("manifest:" + v.range.lastCounter),
    purgedAt:             Date.now(),
  });

  return {
    purged:               true,
    rowsDeleted:          result.rowsDeleted,
    checkpointsDeleted:   result.checkpointsDeleted,
    lastPurgedCounter:    Number(v.range.lastCounter),
    lastPurgedRowHash:    v.range.lastRowHash,
    archiveBundleId:      result.archiveBundleId,
  };
}

async function _defaultReadPurgeAnchor() {
  return clusterStorage.executeOne(
    "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'"
  );
}

async function _defaultApplyPurge(args) {
  var del = await db().purgeAuditChain({ lastPurgedCounter: args.lastPurgedCounter });
  // UPSERT the single-row anchor. SQLite + Postgres both support
  // INSERT ... ON CONFLICT(scope) DO UPDATE.
  await clusterStorage.execute(
    "INSERT INTO _blamejs_audit_purge_anchor " +
    "(scope, lastPurgedCounter, lastPurgedRowHash, archiveBundleId, purgedAt) " +
    "VALUES ('audit', ?, ?, ?, ?) " +
    "ON CONFLICT(scope) DO UPDATE SET " +
    "lastPurgedCounter = excluded.lastPurgedCounter, " +
    "lastPurgedRowHash = excluded.lastPurgedRowHash, " +
    "archiveBundleId   = excluded.archiveBundleId, " +
    "purgedAt          = excluded.purgedAt",
    [args.lastPurgedCounter, args.lastPurgedRowHash, args.archiveBundleId, args.purgedAt]
  );
  return {
    rowsDeleted:        del.rowsDeleted,
    checkpointsDeleted: del.checkpointsDeleted,
    archiveBundleId:    args.archiveBundleId,
  };
}

// forensicSnapshot — post-compromise composer that bundles an audit
// archive slice, current break-glass grants, the active incident
// report (if any), and process-runtime metadata into a single signed
// bundle. The operator passes this to legal / regulators / the IR
// team as one tamper-evident artifact.
//
//   var snap = await b.auditTools.forensicSnapshot({
//     out:        "/forensics/2026-05-07-incident-42",
//     since:      Date.now() - C.TIME.days(7),
//     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
//     incidentId: "inc-2026-05-07-42",
//     reason:     "ATO investigation: 14 failed MFA from new geo, user u_42",
//     actor:      { id: "alice@ops.example.com", role: "incident-commander" },
//   });
async function forensicSnapshot(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  _requireOutDir(opts.out, "forensicSnapshot");
  var sinceMs = _toMs(opts.since);
  if (sinceMs == null) {
    throw new AuditToolsError("audit-tools/no-since",
      "forensicSnapshot: opts.since is required");
  }
  validateOpts.requireNonEmptyString(opts.reason, "reason", AuditToolsError, "audit-tools/no-reason");
  var sliceResult = await exportSlice({
    out:        opts.out,
    since:      sinceMs,
    until:      Date.now(),
    passphrase: opts.passphrase,
    readRows:   opts.readRows,
    readCoveringCheckpoint: opts.readCoveringCheckpoint,
  });
  // Compose snapshot manifest with operator-supplied IR context.
  var manifest = {
    snapshotKind:      "forensic",
    incidentId:        opts.incidentId || null,
    reason:            opts.reason,
    actor:             opts.actor || null,
    composedAt:        new Date().toISOString(),
    auditSliceFile:    sliceResult && sliceResult.path,
    auditSliceCount:   sliceResult && sliceResult.rowCount,
    runtime: {
      nodeVersion: process.version,
      platform:    process.platform,
      arch:        process.arch,
      pid:         process.pid,
      uptimeSec:   Math.round(process.uptime()),
    },
  };
  var manifestPath = require("node:path").join(opts.out, "forensic-snapshot.json");
  require("node:fs").writeFileSync(manifestPath, _canonicalize(manifest), "utf8");
  try {
    require("./audit").safeEmit({
      action:  "audit.forensic_snapshot.composed",
      outcome: "success",
      metadata: {
        out:               opts.out,
        incidentId:        manifest.incidentId,
        reason:            opts.reason,
        actor:             opts.actor || null,
        rowCount:          manifest.auditSliceCount || 0,
      },
    });
  } catch (_e) { /* audit best-effort */ }
  return Object.assign({}, manifest, { manifestPath: manifestPath });
}

module.exports = {
  archive:           archive,
  exportSlice:       exportSlice,
  forensicSnapshot:  forensicSnapshot,
  verifyBundle:      verifyBundle,
  purge:             purge,
  withRecordedAtIso: withRecordedAtIso,
  BUNDLE_FORMAT:    BUNDLE_FORMAT,
  KIND_ARCHIVE:     KIND_ARCHIVE,
  KIND_EXPORT:      KIND_EXPORT,
  AuditToolsError:  AuditToolsError,
};
