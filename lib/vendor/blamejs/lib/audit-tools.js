"use strict";
/**
 * @module b.auditTools
 * @nav    Observability
 * @title  Audit Tools
 *
 * @intro
 *   Operator-side audit-chain inspection / export — verify chain
 *   integrity end-to-end, export RFC 8785 canonical-JSON slices,
 *   format rows for downstream SIEM (CADF / ISO 19395), and generate
 *   tamper-evident compliance-evidence bundles auditors can verify
 *   off-line.
 *
 *   Four core operations on top of the live `audit_log` chain:
 *
 *     archive(opts)      Bundle rows older than `before` into a
 *                        PQC-encrypted archive with chain proof + a
 *                        covering signed checkpoint. Live rows are
 *                        untouched until a separate `purge()` call.
 *     exportSlice(opts)  Auditor-shaped slice (date range / action
 *                        filter) with chain proof — deliver evidence
 *                        to an external auditor without surrendering
 *                        the whole log.
 *     verifyBundle(opts) Round-trip integrity: decrypt the bundle,
 *                        walk chain math across the contained rows,
 *                        verify the covering checkpoint's ML-DSA
 *                        signature (archive bundles only).
 *     purge(opts)        Confirmation-gated deletion of live rows
 *                        already captured in a verified archive
 *                        bundle. Inserts a purge-anchor so
 *                        `b.audit.verify()` keeps working post-purge.
 *
 *   Bundle layout (POSIX-flat directory; matches the backup-bundle
 *   shape so operators see one mental model for "encrypted blamejs
 *   bundle"):
 *
 *     <out>/manifest.json   Canonical-JSON manifest (format / kind /
 *                           range / rowCount / per-blob salts /
 *                           framework version; archive bundles also
 *                           carry the covering checkpoint summary).
 *     <out>/rows.enc        PQC-encrypted JSONL of audit rows in
 *                           sealed form so rowHash stays computable
 *                           from disk bytes byte-for-byte.
 *     <out>/checkpoint.enc  Archive-only. PQC-encrypted JSON of the
 *                           covering audit_checkpoints row.
 *
 *   `kind="archive"` bundles always include a covering checkpoint
 *   (atMonotonicCounter >= lastCounter) so the off-chain signature
 *   tamper-evidences the whole archive. `kind="export"` bundles are
 *   auditor evidence; the chain math is self-contained, with the
 *   upstream signature anchor optional.
 *
 * @card
 *   Operator-side audit-chain inspection / export — verify chain integrity end-to-end, export RFC 8785 canonical-JSON slices, format rows for downstream SIEM (CADF / ISO 19395), and generate tamper-evident compliance-evidence bundles auditors can verify off-line.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var pkg = require("../package.json");
var atomicFile = require("./atomic-file");
var auditChain = require("./audit-chain");
var canonicalJson = require("./canonical-json");
var auditSign = require("./audit-sign");
var backupCrypto = require("./backup/crypto");
var clusterStorage = require("./cluster-storage");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var safeJson = require("./safe-json");
var { defineClass } = require("./framework-error");

var FRAMEWORK_VERSION = (pkg && pkg.version) || "unknown";

// Lazy `db` — db requires audit at top-of-file, audit transitively
// reaches into audit-tools via the operator-supplied default fns,
// so importing db at audit-tools' top would close the cycle. Lazy
// keeps the load order one-way.
var db = lazyRequire(function () { return require("./db"); });
var audit = lazyRequire(function () { return require("./audit"); });

var AuditToolsError = defineClass("AuditToolsError", { alwaysPermanent: true });

// Dual-control gate constants for the audit_log physical purge. The
// purge erases signed audit history, so when an operator has declared
// audit_log under b.db.declareRequireDualControl the deletion requires
// a consumed m-of-n grant whose action matches AUDIT_LOG_PURGE_ACTION —
// the same separation-of-duties control b.db.eraseHard enforces (NIST
// SP 800-53 AU-9 + AC-5, HIPAA 45 CFR 164.312(b), PCI-DSS v4.0 10.5.1 /
// 10.7, SEC 17a-4(f), CWE-778).
var AUDIT_LOG_GATE_TABLE   = "audit_log";
var AUDIT_LOG_PURGE_ACTION = "auditTools.purge";

function _resolveDualControlGate(opts) {
  var checker = typeof opts.checkDualControlGate === "function"
    ? opts.checkDualControlGate
    : function (t) { return db()._checkDualControlGate(t); };
  try { return checker(AUDIT_LOG_GATE_TABLE); }
  catch (_e) { return null; }
}

function _emitPurgeDenied(gate, reason) {
  try {
    audit().safeEmit({
      action:   "auditTools.purge.denied",
      outcome:  "denied",
      reason:   reason,
      metadata: { table: AUDIT_LOG_GATE_TABLE, m: gate.m, n: gate.n, posture: gate.posture || null },
    });
  } catch (_e) { /* drop-silent — denial audit is best-effort */ }
}

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
  if (nodeFs.existsSync(outDir)) {
    throw new AuditToolsError("audit-tools/outdir-exists",
      kind + ": out already exists: " + outDir +
      " (refusing to overwrite — pick a fresh path)");
  }
}

// Canonical-JSON via the shared lib/canonical-json walker — same bytes
// as audit-chain.canonicalize, config-drift._stableStringify, and
// pagination._canonicalize for the same input. Pre-v0.6.67 each site
// had its own copy of the walk, all carrying the same silent-loss bug
// for Date / Buffer / Map / Set / BigInt / circular renodeFs.
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

// Operator-facing wire helper that surfaces recordedAt as
// ISO-8601 / RFC 3339 alongside the existing Unix-ms integer.
// Auditors comparing rows against external SIEM events expect ISO
// with explicit Z; the framework's primary ms storage stays
// unchanged AND _rowToWireForm (which the chain-hash canonicalizes
// over) doesn't change its bytes — so chain verify continues to
// match. Operators call this on retrieved rows for export.
/**
 * @primitive b.auditTools.withRecordedAtIso
 * @signature b.auditTools.withRecordedAtIso(row)
 * @since     0.7.30
 * @related   b.auditTools.exportSlice, b.auditTools.exportCadf
 *
 * Surface `recordedAt` as ISO-8601 / RFC 3339 (with explicit `Z`)
 * alongside the framework's primary Unix-ms integer. Auditors
 * comparing rows against external SIEM events expect ISO; the chain
 * hash is unaffected because the canonical wire form used for
 * hashing doesn't include the derived `recordedAtIso` field.
 *
 * Returns a shallow copy with `recordedAtIso` added when
 * `recordedAt` is a finite number / bigint; otherwise returns the
 * input unchanged.
 *
 * @example
 *   var row = { _id: "evt-1", recordedAt: 1762560000000, action: "auth.login" };
 *   var formatted = b.auditTools.withRecordedAtIso(row);
 *   // → { _id: "evt-1", recordedAt: 1762560000000,
 *   //     recordedAtIso: "2025-11-08T00:00:00.000Z", action: "auth.login" }
 */
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

// Assemble the encrypted bundle entirely in memory: returns the
// manifest plus an ordered { filename: Buffer } map. Pure — no
// filesystem touch — so it backs both the on-disk writer and the
// returnBytes / serverless path. The bundle is always the same 2-3
// files (rows.enc, optional checkpoint.enc, manifest.json) whether it
// lands on disk or ships as bytes.
async function _buildBundle(args) {
  var kind         = args.kind;
  var rows         = args.rows;
  var checkpoint   = args.checkpoint || null;
  var passphrase   = args.passphrase;
  var predecessorRowHash = args.predecessorRowHash;

  var firstRow = rows[0];
  var lastRow  = rows[rows.length - 1];
  var files = {};

  // 1. Encrypt the rows JSONL
  var jsonl = rows.map(function (r) {
    return JSON.stringify(_rowToWireForm(r));
  }).join("\n") + "\n";
  var rowsEnc = await backupCrypto.encryptWithFreshSalt(jsonl, passphrase);
  files["rows.enc"] = rowsEnc.encrypted;

  // 2. (archive) Encrypt the checkpoint JSON
  var checkpointSalt = null;
  var checkpointEncrypted = null;
  if (checkpoint) {
    var ckptJson = _canonicalize(_rowToWireForm(checkpoint));
    var ckptEnc = await backupCrypto.encryptWithFreshSalt(ckptJson, passphrase);
    files["checkpoint.enc"] = ckptEnc.encrypted;
    checkpointSalt = ckptEnc.salt;
    checkpointEncrypted = ckptEnc.encrypted;
  }

  // 3. Build manifest — checksums computed from the in-memory buffers
  // (no read-back of what we just wrote).
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
      checkpointSha3_512: checkpointEncrypted
        ? backupCrypto.checksum(checkpointEncrypted)
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
  files["manifest.json"] = Buffer.from(_canonicalize(manifest), "utf8");
  return { manifest: manifest, files: files };
}

async function _writeBundle(args) {
  var outDir = args.outDir;
  var built  = await _buildBundle(args);

  atomicFile.ensureDir(outDir);
  atomicFile.writeSync(nodePath.join(outDir, "rows.enc"), built.files["rows.enc"], { fileMode: 0o600 });
  if (built.files["checkpoint.enc"]) {
    atomicFile.writeSync(nodePath.join(outDir, "checkpoint.enc"), built.files["checkpoint.enc"], { fileMode: 0o600 });
  }
  var manifestPath = nodePath.join(outDir, "manifest.json");
  atomicFile.writeSync(manifestPath, built.files["manifest.json"], { fileMode: 0o600 });
  return { manifest: built.manifest, manifestPath: manifestPath };
}

// ---- Bundle reader ----

async function _readBundle(inDir, passphrase) {
  if (typeof inDir !== "string" || !nodeFs.existsSync(inDir)) {
    throw new AuditToolsError("audit-tools/no-bundle",
      "bundle directory does not exist: " + inDir);
  }
  var manifestPath = nodePath.join(inDir, "manifest.json");
  if (!nodeFs.existsSync(manifestPath)) {
    throw new AuditToolsError("audit-tools/no-manifest",
      "manifest.json missing in " + inDir);
  }
  var manifest = safeJson.parse(nodeFs.readFileSync(manifestPath, "utf8"));
  if (!manifest || manifest.format !== BUNDLE_FORMAT) {
    throw new AuditToolsError("audit-tools/bad-format",
      "manifest.format is not " + BUNDLE_FORMAT);
  }
  if (!VALID_KINDS[manifest.kind]) {
    throw new AuditToolsError("audit-tools/bad-kind",
      "manifest.kind must be one of " + Object.keys(VALID_KINDS).join(", "));
  }

  var rowsEncPath = nodePath.join(inDir, "rows.enc");
  if (!nodeFs.existsSync(rowsEncPath)) {
    throw new AuditToolsError("audit-tools/no-rows-blob",
      "rows.enc missing in " + inDir);
  }
  var rowsEnc = nodeFs.readFileSync(rowsEncPath);
  if (manifest.checksum && manifest.checksum.rowsSha3_512 &&
      backupCrypto.checksum(rowsEnc) !== manifest.checksum.rowsSha3_512) {
    throw new AuditToolsError("audit-tools/rows-checksum-mismatch",
      "rows.enc checksum does not match manifest — bundle was tampered with");
  }
  var rowsPlainBuf = await backupCrypto.decryptWithPassphrase(rowsEnc, passphrase, manifest.salts.rows);
  var rowsPlain = rowsPlainBuf.toString("utf8");
  var lines = rowsPlain.split("\n").filter(function (l) { return l.length > 0; });
  var rows = lines.map(function (l) { return _wireFormToRow(safeJson.parse(l)); });

  var checkpoint = null;
  if (manifest.kind === KIND_ARCHIVE) {
    var ckptPath = nodePath.join(inDir, "checkpoint.enc");
    if (!nodeFs.existsSync(ckptPath)) {
      throw new AuditToolsError("audit-tools/no-checkpoint-blob",
        "checkpoint.enc missing in " + inDir + " (archive bundles must include the covering checkpoint)");
    }
    var ckptEnc = nodeFs.readFileSync(ckptPath);
    if (manifest.checksum && manifest.checksum.checkpointSha3_512 &&
        backupCrypto.checksum(ckptEnc) !== manifest.checksum.checkpointSha3_512) {
      throw new AuditToolsError("audit-tools/checkpoint-checksum-mismatch",
        "checkpoint.enc checksum does not match manifest");
    }
    var ckptPlain = (await backupCrypto.decryptWithPassphrase(ckptEnc, passphrase, manifest.salts.checkpoint))
      .toString("utf8");
    checkpoint = _wireFormToRow(safeJson.parse(ckptPlain));
  }

  return { manifest: manifest, rows: rows, checkpoint: checkpoint };
}

// ---- Public ops ----

/**
 * @primitive b.auditTools.archive
 * @signature b.auditTools.archive(opts)
 * @since     0.7.30
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.auditTools.verifyBundle, b.auditTools.purge, b.audit.checkpoint
 *
 * Bundle every audit row older than `opts.before` into a
 * PQC-encrypted archive (XChaCha20-Poly1305 + Argon2id-derived key)
 * containing a chain proof and the covering ML-DSA-87 checkpoint.
 * Live rows are untouched — call `b.auditTools.purge` separately
 * once the archive is verified.
 *
 * Refuses if `opts.out` exists, no rows match, or no signed
 * checkpoint covers the slice (run `b.audit.checkpoint()` first).
 *
 * Pass `returnBytes: true` instead of `out` for the bundle as an
 * in-memory `{ filename: Buffer }` map (`rows.enc` + `checkpoint.enc`
 * + `manifest.json`) — the read-only / serverless path. `out` and
 * `returnBytes` are mutually exclusive.
 *
 * @opts
 *   out:        string,         // fresh directory path (omit when returnBytes)
 *   returnBytes:boolean,        // true → return { manifest, files } in memory, no disk
 *   before:     number|Date|string,  // archive rows recordedAt < this
 *   passphrase: Buffer|string,  // bundle-encryption passphrase
 *
 * @example
 *   var ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
 *   var result = await b.auditTools.archive({
 *     out:        "/var/audit/2026-Q1.bundle",
 *     before:     ninetyDaysAgo,
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *   });
 *   // → { rowCount: 14823, range: { firstCounter: 1, lastCounter: 14823, ... },
 *   //     manifestPath: "/var/audit/2026-Q1.bundle/manifest.json", ... }
 */
async function archive(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  var returnBytes = opts.returnBytes === true;
  if (returnBytes && opts.out !== undefined) {
    throw new AuditToolsError("audit-tools/out-and-return-bytes",
      "archive: specify either opts.out (write to disk) or opts.returnBytes (in-memory bytes), not both");
  }
  if (!returnBytes) _requireOutDir(opts.out, "archive");
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

  if (returnBytes) {
    var built = await _buildBundle({
      kind:       KIND_ARCHIVE,
      rows:       rows,
      checkpoint: checkpoint,
      passphrase: opts.passphrase,
      predecessorRowHash: predecessorRowHash,
    });
    return {
      manifest: built.manifest,
      files:    built.files,
      rowCount: rows.length,
      range:    built.manifest.range,
    };
  }

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

/**
 * @primitive b.auditTools.exportSlice
 * @signature b.auditTools.exportSlice(opts)
 * @since     0.7.30
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.auditTools.archive, b.auditTools.verifyBundle, b.auditTools.exportCadf
 *
 * Auditor-shaped slice — bundle the audit rows in `[from, to]`
 * (optionally filtered by exact `action`) into a PQC-encrypted
 * directory carrying chain-proof material. Refuses non-contiguous
 * slices because chain verification cannot ground a sequence with
 * gaps in `monotonicCounter`.
 *
 * Use date-range filters that cover every row in the range; an
 * action filter that drops intermediate counters is rejected with
 * `audit-tools/non-contiguous`.
 *
 * Pass `returnBytes: true` instead of `out` to get the bundle as an
 * in-memory `{ filename: Buffer }` map (`rows.enc` + `manifest.json`)
 * with no filesystem touch — the read-only / serverless path; ship it
 * to object storage or over the wire. `out` and `returnBytes` are
 * mutually exclusive.
 *
 * @opts
 *   out:        string,                // fresh directory path (omit when returnBytes)
 *   returnBytes:boolean,               // true → return { manifest, files } in memory, no disk
 *   from:       number|Date|string,    // recordedAt >= this (inclusive)
 *   to:         number|Date|string,    // recordedAt <= this (inclusive)
 *   action:     string,                // exact action match (optional)
 *   passphrase: Buffer|string,         // bundle-encryption passphrase
 *
 * @example
 *   var bundle = await b.auditTools.exportSlice({
 *     out:        "/tmp/audit-2026-q1.bundle",
 *     from:       "2026-01-01T00:00:00Z",
 *     to:         "2026-03-31T23:59:59Z",
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *   });
 *   // → { rowCount: 4218, manifest: { kind: "export", ... }, ... }
 */
async function exportSlice(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  var returnBytes = opts.returnBytes === true;
  if (returnBytes && opts.out !== undefined) {
    throw new AuditToolsError("audit-tools/out-and-return-bytes",
      "export: specify either opts.out (write to disk) or opts.returnBytes (in-memory bytes), not both");
  }
  if (!returnBytes) _requireOutDir(opts.out, "export");
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

  if (returnBytes) {
    var built = await _buildBundle({
      kind:       KIND_EXPORT,
      rows:       rows,
      checkpoint: null,
      passphrase: opts.passphrase,
      predecessorRowHash: predecessorRowHash,
    });
    return {
      manifest: built.manifest,
      files:    built.files,
      rowCount: rows.length,
      range:    built.manifest.range,
    };
  }

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

/**
 * @primitive b.auditTools.verifyBundle
 * @signature b.auditTools.verifyBundle(opts)
 * @since     0.7.30
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.auditTools.archive, b.auditTools.exportSlice, b.auditTools.purge
 *
 * Round-trip integrity check on a bundle directory: decrypt
 * `rows.enc`, walk the prevHash → rowHash chain across the contained
 * rows starting from the manifest's `predecessorRowHash` witness,
 * confirm `firstRowHash` / `lastRowHash` match, and (archive only)
 * verify the covering checkpoint's ML-DSA-87 signature against the
 * locally-loaded audit-sign public key (or `opts.verifySignature`
 * for cross-machine auditors).
 *
 * Returns `{ ok: true, kind, rowsVerified, range, manifest }` on
 * success or `{ ok: false, reason, breakAt? }` at the first break.
 *
 * @opts
 *   in:                          string,               // bundle directory
 *   passphrase:                  Buffer|string,        // decryption passphrase
 *   verifyCheckpointSignature:   boolean,              // default true
 *   verifySignature:             function(checkpoint), // override the default verifier
 *   includeRows:                 boolean,              // attach decrypted rows to result
 *
 * @example
 *   var result = await b.auditTools.verifyBundle({
 *     in:         "/var/audit/2026-Q1.bundle",
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *   });
 *   if (!result.ok) {
 *     console.error("bundle integrity break:", result.reason);
 *     process.exit(1);
 *   }
 *   // → { ok: true, kind: "archive", rowsVerified: 14823, range: { ... } }
 */
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

/**
 * @primitive b.auditTools.purge
 * @signature b.auditTools.purge(opts)
 * @since     0.7.30
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.auditTools.archive, b.auditTools.verifyBundle, b.audit.verify
 *
 * Confirmation-gated deletion of live audit rows already captured in
 * a verified archive bundle. Refuses unless `opts.confirm === true`,
 * the bundle verifies clean as `kind="archive"`, and the bundle's
 * `firstCounter` / `predecessorRowHash` match the next contiguous
 * purge point on disk. Inserts a `_blamejs_audit_purge_anchor` row
 * so `b.audit.verify()` keeps chaining post-purge — the anchor's
 * `lastPurgedRowHash` becomes the new chain origin.
 *
 * @opts
 *   confirm:          true,               // exact `true` required
 *   archive:          string,             // path to a verified archive bundle
 *   passphrase:       Buffer|string,      // bundle decryption passphrase
 *   verifySignature:  function(checkpoint),// auditor pubkey override
 *   dualControlGrant: object,             // required when audit_log is declared under b.db.declareRequireDualControl — from b.dualControl.consume({ action: "auditTools.purge" })
 *
 * @example
 *   var result = await b.auditTools.purge({
 *     confirm:    true,
 *     archive:    "/var/audit/2026-Q1.bundle",
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *   });
 *   // → { purged: true, rowsDeleted: 14823, lastPurgedCounter: 14823, ... }
 */
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

  // Dual-control gate. When audit_log is declared under
  // b.db.declareRequireDualControl, the physical purge requires a
  // consumed m-of-n grant — confirm:true alone is not enough. Mirrors
  // b.db.eraseHard, and additionally binds the grant's action so a
  // grant minted for a different operation can't be replayed here.
  var dcGate = _resolveDualControlGate(opts);
  if (dcGate) {
    var grant = opts.dualControlGrant;
    if (!grant) {
      _emitPurgeDenied(dcGate, "no-grant");
      throw new AuditToolsError("audit-tools/dual-control-required",
        "purge: audit_log is under dual control (m=" + dcGate.m + ", n=" + dcGate.n +
        "); pass opts.dualControlGrant from b.dualControl.consume({ action: \"" +
        AUDIT_LOG_PURGE_ACTION + "\" }).");
    }
    if (grant.ready !== true) {
      _emitPurgeDenied(dcGate, "grant-not-ready");
      throw new AuditToolsError("audit-tools/dual-control-grant-not-ready",
        "purge: opts.dualControlGrant.ready must be true (a consumed m-of-n grant)");
    }
    if (grant.action !== AUDIT_LOG_PURGE_ACTION) {
      _emitPurgeDenied(dcGate, "grant-action-mismatch");
      throw new AuditToolsError("audit-tools/dual-control-grant-mismatch",
        "purge: dualControlGrant.action is '" + grant.action + "', must be '" +
        AUDIT_LOG_PURGE_ACTION + "'");
    }
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
    dualControlConsumed:  !!dcGate,
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

/**
 * @primitive b.auditTools.forensicSnapshot
 * @signature b.auditTools.forensicSnapshot(opts)
 * @since     0.8.40
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404, dora, nis2
 * @related   b.auditTools.exportSlice, b.auditTools.archive
 *
 * Post-compromise composer that bundles an audit slice (from
 * `since` → now) plus operator-supplied incident metadata
 * (incidentId, reason, actor) and runtime fingerprint (Node version
 * / platform / pid / uptime) into a single tamper-evident artifact
 * for legal / regulators / the IR team. Emits an
 * `audit.forensic_snapshot.composed` audit event so the act of
 * composing the snapshot is itself on-chain.
 *
 * Pass `returnBytes: true` instead of `out` for the snapshot as an
 * in-memory `{ filename: Buffer }` map (the slice's `rows.enc` +
 * `manifest.json` plus `forensic-snapshot.json`) — the read-only /
 * serverless path. `out` and `returnBytes` are mutually exclusive.
 *
 * @opts
 *   out:        string,               // fresh directory path (omit when returnBytes)
 *   returnBytes:boolean,              // true → return { ...manifest, files } in memory, no disk
 *   since:      number|Date|string,   // include rows recordedAt >= this (windowed since → now)
 *   passphrase: Buffer|string,        // bundle-encryption passphrase
 *   reason:     string,               // required incident-context reason
 *   incidentId: string,               // optional ticket / incident id
 *   actor:      { id, role },         // optional incident-commander identity
 *
 * @example
 *   var snap = await b.auditTools.forensicSnapshot({
 *     out:        "/forensics/2026-05-08-inc-42",
 *     since:      Date.now() - 7 * 24 * 60 * 60 * 1000,
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *     incidentId: "inc-2026-05-08-42",
 *     reason:     "ATO investigation: 14 failed MFA from new geo, user u-42",
 *     actor:      { id: "alice@ops.example.com", role: "incident-commander" },
 *   });
 *   // → { snapshotKind: "forensic", incidentId: "inc-2026-05-08-42", ... }
 */
async function forensicSnapshot(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  var returnBytes = opts.returnBytes === true;
  if (returnBytes && opts.out !== undefined) {
    throw new AuditToolsError("audit-tools/out-and-return-bytes",
      "forensicSnapshot: specify either opts.out (write to disk) or opts.returnBytes (in-memory bytes), not both");
  }
  if (!returnBytes) _requireOutDir(opts.out, "forensicSnapshot");
  var sinceMs = _toMs(opts.since);
  if (sinceMs == null) {
    throw new AuditToolsError("audit-tools/no-since",
      "forensicSnapshot: opts.since is required");
  }
  validateOpts.requireNonEmptyString(opts.reason, "reason", AuditToolsError, "audit-tools/no-reason");
  // exportSlice windows by from/to — pass the requested `since` as `from`
  // and now as `to` so the snapshot captures only the incident window
  // rather than the entire audit history.
  var sliceResult = await exportSlice({
    out:         returnBytes ? undefined : opts.out,
    returnBytes: returnBytes,
    from:        sinceMs,
    to:          Date.now(),
    passphrase:  opts.passphrase,
    readRows:    opts.readRows,
    readCoveringCheckpoint: opts.readCoveringCheckpoint,
  });
  // Compose snapshot manifest with operator-supplied IR context. The
  // audit slice lands as rows.enc inside the bundle either way.
  var manifest = {
    snapshotKind:      "forensic",
    incidentId:        opts.incidentId || null,
    reason:            opts.reason,
    actor:             opts.actor || null,
    composedAt:        new Date().toISOString(),
    auditSliceFile:    returnBytes ? "rows.enc" : (sliceResult && sliceResult.manifestPath),
    auditSliceCount:   sliceResult && sliceResult.rowCount,
    runtime: {
      nodeVersion: process.version,
      platform:    process.platform,
      arch:        process.arch,
      pid:         process.pid,
      uptimeSec:   Math.round(process.uptime()),
    },
  };
  var manifestBytes = Buffer.from(_canonicalize(manifest), "utf8");
  var manifestPath = null;
  if (!returnBytes) {
    manifestPath = nodePath.join(opts.out, "forensic-snapshot.json");
    atomicFile.writeSync(manifestPath, manifestBytes, { fileMode: 0o600 });
  }
  try {
    require("./audit").safeEmit({
      action:  "audit.forensic_snapshot.composed",
      outcome: "success",
      metadata: {
        out:               returnBytes ? null : opts.out,
        incidentId:        manifest.incidentId,
        reason:            opts.reason,
        actor:             opts.actor || null,
        rowCount:          manifest.auditSliceCount || 0,
      },
    });
  } catch (_e) { /* audit best-effort */ }
  if (returnBytes) {
    // Mirror the on-disk layout: the slice's files plus the IR wrapper.
    var files = Object.assign({}, sliceResult.files);
    files["forensic-snapshot.json"] = manifestBytes;
    return Object.assign({}, manifest, { files: files });
  }
  return Object.assign({}, manifest, { manifestPath: manifestPath });
}

// CADF (Cloud Auditing Data Federation, ISO/IEC 19395:2017) is the
// OpenStack/FedRAMP-tier cloud-audit envelope auditors increasingly
// expect for federated tooling (cross-tenant SIEM, CSP reporting).
//
// We map blamejs audit fields onto CADF attributes:
//
//   blamejs                CADF
//   ---------------------- ----------------------------------
//   _id                    eventid (UUID-ish)
//   action                 action (typed verb namespace)
//   outcome                outcome (success | failure | unknown | pending)
//   actorUserId            initiator.id (typed via initiator.typeURI)
//   resourceKind+resourceId target.id + target.typeURI
//   recordedAt             eventTime (ISO-8601)
//   reason                 reason.reasonCode + reason.policyType
//   metadata               attachments[] (operator-supplied free-form)
//   prevHash/rowHash       observer.id link to chain anchor
//
// CADF requires every event to declare its observer (the auditing
// system). We declare blamejs as the observer with a typeURI of
// service/audit. The framework version pins observer.id so an auditor
// can correlate envelope-level events back to a deployment.
function _toCadfOutcome(outcome) {
  if (outcome === "success") return "success";
  if (outcome === "failure" || outcome === "denied") return "failure";
  if (outcome === "warning") return "unknown";
  return outcome || "unknown";
}

function _toCadfEvent(row) {
  var meta = null;
  if (row.metadata) {
    try { meta = typeof row.metadata === "string" ? safeJson.parse(row.metadata) : row.metadata; }
    catch (_e) { meta = { raw: String(row.metadata) }; }
  }
  var ev = {
    typeURI:   "http://schemas.dmtf.org/cloud/audit/1.0/event",
    eventType: "activity",
    id:        row._id,
    eventTime: new Date(Number(row.recordedAt)).toISOString(),
    action:    row.action,
    outcome:   _toCadfOutcome(row.outcome),
    initiator: {
      id:      row.actorUserIdHash || row.actorUserId || "unknown",
      typeURI: "service/security/account/user",
      addresses: row.actorIp ? [{ url: row.actorIp, name: "actorIp" }] : undefined,
      name:    row.actorSessionId || undefined,
    },
    target: {
      id:      row.resourceIdHash || row.resourceId || row.resourceKind || "n/a",
      typeURI: row.resourceKind ? ("service/storage/" + row.resourceKind) : "service/security",
    },
    observer: {
      id:      "blamejs:" + (pkg.version || "unknown"),
      typeURI: "service/security/audit",
      name:    "blamejs.audit",
    },
    reason: row.reason ? {
      reasonCode: String(row.reason).slice(0, 256),                                // reason cap
      policyType: "blamejs.audit-chain",
    } : undefined,
    attachments: meta ? [{
      contentType: "application/json",
      content:     JSON.stringify(meta),
      name:        "blamejs.metadata",
    }] : undefined,
    // Custom CADF extension — anchors back into the audit chain.
    "blamejs:chain": {
      monotonicCounter: Number(row.monotonicCounter),
      prevHash:         row.prevHash,
      rowHash:          row.rowHash,
    },
  };
  return ev;
}

/**
 * @primitive b.auditTools.exportCadf
 * @signature b.auditTools.exportCadf(opts)
 * @since     0.7.30
 * @compliance soc2, pci-dss, gdpr
 * @related   b.auditTools.exportAudit, b.auditTools.exportSlice
 *
 * Format an audit slice as a CADF event-batch (Cloud Auditing Data
 * Federation, ISO/IEC 19395:2017 + DMTF) — the FedRAMP / OpenStack
 * envelope cross-tenant SIEMs and CSP reporting tools expect for
 * federated tooling. Maps blamejs fields onto CADF attributes
 * (initiator / target / observer / outcome / reason) and embeds a
 * `blamejs:chain` extension carrying `monotonicCounter` / prevHash /
 * rowHash so auditors can correlate the envelope back to the chain.
 *
 * Returns an object with `events: [...]` ready to ship as JSON.
 *
 * @opts
 *   format:   "cadf",                // optional — defaults to "cadf"
 *   from:     number|Date|string,    // recordedAt >= this
 *   to:       number|Date|string,    // recordedAt <= this
 *   action:   string,                // exact action filter
 *
 * @example
 *   var batch = await b.auditTools.exportCadf({
 *     from:   "2026-05-01T00:00:00Z",
 *     to:     "2026-05-08T00:00:00Z",
 *     action: "auth.login",
 *   });
 *   // → { typeURI: ".../event-batch", framework: "blamejs", events: [...] }
 */
async function exportCadf(opts) {
  opts = opts || {};
  if (opts.format !== undefined && opts.format !== "cadf") {
    throw new AuditToolsError("audit-tools/bad-format",
      "audit.export: format must be 'cadf' for exportCadf");
  }
  var fromMs = _toMs(opts.from);
  var toMs   = _toMs(opts.to);
  var readRows = opts.readRows || _defaultReadRows;
  var criteria = {};
  if (fromMs != null) criteria.fromMs = fromMs;
  if (toMs   != null) criteria.toMs   = toMs;
  if (opts.action) criteria.action = opts.action;
  var rows = await readRows(criteria);
  var events = new Array(rows.length);
  for (var i = 0; i < rows.length; i++) {
    events[i] = _toCadfEvent(rows[i]);
  }
  return {
    typeURI:        "http://schemas.dmtf.org/cloud/audit/1.0/event-batch",
    framework:      "blamejs",
    frameworkVersion: pkg.version,
    range: {
      from: fromMs != null ? new Date(fromMs).toISOString() : null,
      to:   toMs   != null ? new Date(toMs).toISOString()   : null,
    },
    events: events,
  };
}

// Operator-facing dispatcher — `b.audit.export({ format })`. Future
// formats register here.
/**
 * @primitive b.auditTools.exportAudit
 * @signature b.auditTools.exportAudit(opts)
 * @since     0.7.30
 * @compliance soc2, pci-dss, gdpr
 * @related   b.auditTools.exportCadf, b.auditTools.exportSlice
 *
 * Format dispatcher for downstream-SIEM exports. Reads `opts.format`
 * (default `"cadf"`) and delegates to the matching formatter. Future
 * envelope formats (CEF / OCSF / etc.) register here so callers stay
 * on a stable signature even when the framework adds formats.
 *
 * @opts
 *   format:   "cadf",                // selector — defaults to "cadf"
 *   from:     number|Date|string,    // recordedAt >= this
 *   to:       number|Date|string,    // recordedAt <= this
 *   action:   string,                // exact action filter
 *
 * @example
 *   var batch = await b.auditTools.exportAudit({
 *     format: "cadf",
 *     from:   "2026-05-01T00:00:00Z",
 *     to:     "2026-05-08T00:00:00Z",
 *   });
 *   // → { typeURI: ".../event-batch", framework: "blamejs", events: [...] }
 */
async function exportAudit(opts) {
  opts = opts || {};
  var format = opts.format || "cadf";
  if (format === "cadf") return await exportCadf(opts);
  throw new AuditToolsError("audit-tools/bad-format",
    "audit.export: format must be one of: cadf (got '" + format + "')");
}

module.exports = {
  archive:           archive,
  exportSlice:       exportSlice,
  exportAudit:       exportAudit,
  exportCadf:        exportCadf,
  forensicSnapshot:  forensicSnapshot,
  verifyBundle:      verifyBundle,
  purge:             purge,
  withRecordedAtIso: withRecordedAtIso,
  BUNDLE_FORMAT:    BUNDLE_FORMAT,
  KIND_ARCHIVE:     KIND_ARCHIVE,
  KIND_EXPORT:      KIND_EXPORT,
  AuditToolsError:  AuditToolsError,
};
