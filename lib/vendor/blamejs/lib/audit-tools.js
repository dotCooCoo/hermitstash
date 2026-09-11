// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.auditTools
 * @nav    Observability
 * @title  Audit Tools
 *
 * @intro
 *   Operator-side audit-chain inspection / export — verify chain
 *   integrity end-to-end, export RFC 8785 canonical-JSON slices,
 *   format rows for downstream SIEM (CADF / DMTF DSP0262), and generate
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
 *   Operator-side audit-chain inspection / export — verify chain integrity end-to-end, export RFC 8785 canonical-JSON slices, format rows for downstream SIEM (CADF / DMTF DSP0262), and generate tamper-evident compliance-evidence bundles auditors can verify off-line.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var pkg = require("../package.json");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var auditChain = require("./audit-chain");
var canonicalJson = require("./canonical-json");
var auditSign = require("./audit-sign");
var backupCrypto = require("./backup/crypto");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var frameworkFiles = require("./framework-files");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var safeJson = require("./safe-json");
var sql = require("./sql");
var { defineClass } = require("./framework-error");

var FRAMEWORK_VERSION = (pkg && pkg.version) || "unknown";

// Lazy `db` — db requires audit at top-of-file, audit transitively
// reaches into audit-tools via the operator-supplied default fns,
// so importing db at audit-tools' top would close the cycle. Lazy
// keeps the load order one-way.
var db = lazyRequire(function () { return require("./db"); });
var audit = lazyRequire(function () { return require("./audit"); });

var AuditToolsError = defineClass("AuditToolsError", { alwaysPermanent: true });

function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

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

function _canonicalize(value) { return canonicalJson.stringify(value); }

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

async function _defaultReadRows(criteria) {
  var qb = sql.select("audit_log", _sqlOpts());
  if (criteria.fromMs != null)       qb.whereOp("recordedAt", ">=", criteria.fromMs);
  if (criteria.toMs != null)         qb.whereOp("recordedAt", "<=", criteria.toMs);
  if (criteria.beforeMs != null)     qb.whereOp("recordedAt", "<", criteria.beforeMs);
  if (criteria.action)               qb.where("action", criteria.action);
  if (criteria.firstCounter != null) qb.whereOp("monotonicCounter", ">=", criteria.firstCounter);
  if (criteria.lastCounter != null)  qb.whereOp("monotonicCounter", "<=", criteria.lastCounter);
  qb.orderBy("monotonicCounter", "asc");
  var built = qb.toSql();
  return clusterStorage.executeAll(built.sql, built.params);
}

async function _defaultReadLowestLiveCounter(lastCounter) {
  var built = sql.select("audit_log", _sqlOpts())
    .whereOp("monotonicCounter", "<=", lastCounter)
    .orderBy("monotonicCounter", "asc")
    .limit(1)
    .toSql();
  var row = await clusterStorage.executeOne(built.sql, built.params);
  return row ? Number(row.monotonicCounter) : null;
}

async function _defaultReadCoveringCheckpoint(lastCounter) {
  var built = sql.select("audit_checkpoints", _sqlOpts())
    .whereOp("atMonotonicCounter", ">=", lastCounter)
    .orderBy("atMonotonicCounter", "asc")
    .limit(1)
    .toSql();
  return clusterStorage.executeOne(built.sql, built.params);
}

async function _defaultReadPredecessorRowHash(firstCounter) {
  if (firstCounter <= 1) return auditChain.ZERO_HASH;
  var rowBuilt = sql.select("audit_log", _sqlOpts())
    .columns(["rowHash"])
    .where("monotonicCounter", firstCounter - 1)
    .toSql();
  var row = await clusterStorage.executeOne(rowBuilt.sql, rowBuilt.params);
  if (!row) {
    // clusterStorage rewrites it. allow:hand-rolled-sql — bare logical key.
    var anchor = await _defaultReadPurgeAnchor();
    if (anchor && Number(anchor.lastPurgedCounter) === firstCounter - 1) {
      var policy = _anchorVerifyOpts();
      var verdict = auditChain.verifyPurgeAnchor(anchor, policy);
      if (!_anchorBelievable(verdict, policy)) {
        throw new AuditToolsError("audit-tools/anchor-not-verified",
          "predecessor row at counter=" + (firstCounter - 1) +
          " is covered by a purge anchor that cannot be believed — " + verdict.reason);
      }
      return anchor.lastPurgedRowHash;
    }
    throw new AuditToolsError("audit-tools/no-predecessor",
      "predecessor row at counter=" + (firstCounter - 1) + " missing — chain proof would be ungrounded");
  }
  return row.rowHash;
}

async function _buildBundle(args) {
  var kind         = args.kind;
  var rows         = args.rows;
  var witnessRows  = args.witnessRows || [];
  var checkpoint   = args.checkpoint || null;
  var passphrase   = args.passphrase;
  var predecessorRowHash = args.predecessorRowHash;

  var firstRow = rows[0];
  var lastRow  = rows[rows.length - 1];
  var files = {};

  var jsonl = rows.concat(witnessRows).map(function (r) {
    return JSON.stringify(_rowToWireForm(r));
  }).join("\n") + "\n";
  var rowsEnc = await backupCrypto.encryptWithFreshSalt(jsonl, passphrase);
  files[frameworkFiles.fileName("rowsEnc")] = rowsEnc.encrypted;

  var checkpointSalt = null;
  var checkpointEncrypted = null;
  if (checkpoint) {
    var ckptJson = _canonicalize(_rowToWireForm(checkpoint));
    var ckptEnc = await backupCrypto.encryptWithFreshSalt(ckptJson, passphrase);
    files[frameworkFiles.fileName("checkpointEnc")] = ckptEnc.encrypted;
    checkpointSalt = ckptEnc.salt;
    checkpointEncrypted = ckptEnc.encrypted;
  }

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
  atomicFile.writeSync(nodePath.join(outDir, frameworkFiles.fileName("rowsEnc")), built.files[frameworkFiles.fileName("rowsEnc")], { fileMode: 0o600 });
  if (built.files[frameworkFiles.fileName("checkpointEnc")]) {
    atomicFile.writeSync(nodePath.join(outDir, frameworkFiles.fileName("checkpointEnc")), built.files[frameworkFiles.fileName("checkpointEnc")], { fileMode: 0o600 });
  }
  var manifestPath = nodePath.join(outDir, "manifest.json");
  atomicFile.writeSync(manifestPath, built.files["manifest.json"], { fileMode: 0o600 });
  return { manifest: built.manifest, manifestPath: manifestPath };
}

async function _readBundle(inDir, passphrase) {
  if (typeof inDir !== "string" || !nodeFs.existsSync(inDir)) {
    throw new AuditToolsError("audit-tools/no-bundle",
      "bundle directory does not exist: " + inDir);
  }
  var manifestPath = nodePath.join(inDir, "manifest.json");
  var manifest = safeJson.parse(atomicFile.fdSafeReadSync(manifestPath, {
    maxBytes: C.BYTES.mib(4), encoding: "utf8",
    errorFor: function (kind, detail) {
      if (kind === "enoent") return new AuditToolsError("audit-tools/no-manifest", "manifest.json missing in " + inDir);
      if (kind === "too-large") return new AuditToolsError("audit-tools/bad-format", "manifest.json too large (" + detail.size + " > " + detail.max + ")");
      return new AuditToolsError("audit-tools/bad-format", "manifest.json unreadable: " + kind);
    },
  }), { maxBytes: C.BYTES.mib(4) });
  if (!manifest || manifest.format !== BUNDLE_FORMAT) {
    throw new AuditToolsError("audit-tools/bad-format",
      "manifest.format is not " + BUNDLE_FORMAT);
  }
  if (!Object.prototype.hasOwnProperty.call(VALID_KINDS, manifest.kind)) {
    throw new AuditToolsError("audit-tools/bad-kind",
      "manifest.kind must be one of " + Object.keys(VALID_KINDS).join(", "));
  }

  var rowsEncPath = nodePath.join(inDir, frameworkFiles.fileName("rowsEnc"));
  var rowsEnc = atomicFile.fdSafeReadSync(rowsEncPath, {
    maxBytes: C.BYTES.mib(512),
    errorFor: function (kind) {
      if (kind === "enoent") return new AuditToolsError("audit-tools/no-rows-blob", "rows.enc missing in " + inDir);
      if (kind === "too-large") return new AuditToolsError("audit-tools/rows-too-large", "rows.enc exceeds the bundle size cap");
      return new AuditToolsError("audit-tools/no-rows-blob", "rows.enc unreadable: " + kind);
    },
  });
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
    var ckptPath = nodePath.join(inDir, frameworkFiles.fileName("checkpointEnc"));
    var ckptEnc = atomicFile.fdSafeReadSync(ckptPath, {
      maxBytes: C.BYTES.mib(4),
      errorFor: function (kind) {
        if (kind === "enoent") return new AuditToolsError("audit-tools/no-checkpoint-blob", "checkpoint.enc missing in " + inDir + " (archive bundles must include the covering checkpoint)");
        if (kind === "too-large") return new AuditToolsError("audit-tools/checkpoint-too-large", "checkpoint.enc exceeds the cap");
        return new AuditToolsError("audit-tools/no-checkpoint-blob", "checkpoint.enc unreadable: " + kind);
      },
    });
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

  var anchorCounter = Number(checkpoint.atMonotonicCounter);
  var witnessRows = [];
  if (anchorCounter > lastCounter) {
    witnessRows = await readRows({ firstCounter: lastCounter + 1, lastCounter: anchorCounter });
    var witnessTip = witnessRows.length ? Number(witnessRows[witnessRows.length - 1].monotonicCounter) : null;
    if (witnessTip !== anchorCounter) {
      throw new AuditToolsError("audit-tools/anchor-rows-missing",
        "archive: covering checkpoint anchors counter=" + anchorCounter +
        " but the rows up to it are not all available (read up to " + witnessTip +
        ") — cannot prove the slice chains to the signed anchor");
    }
  }

  if (returnBytes) {
    var built = await _buildBundle({
      kind:       KIND_ARCHIVE,
      rows:       rows,
      witnessRows: witnessRows,
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
    witnessRows: witnessRows,
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

  var lastCounterN = Number(read.manifest.range.lastCounter);
  var sliceLastRow = null;
  for (var ri = 0; ri < read.rows.length; ri++) {
    if (Number(read.rows[ri].monotonicCounter) === lastCounterN) { sliceLastRow = read.rows[ri]; break; }
  }
  if (read.rows[0].rowHash !== read.manifest.range.firstRowHash) {
    return {
      ok: false, kind: read.manifest.kind, rowsVerified: read.rows.length,
      reason: "manifest.range.firstRowHash does not match first row's rowHash",
    };
  }
  if (Number(read.manifest.range.firstCounter) !== Number(read.rows[0].monotonicCounter)) {
    return {
      ok: false, kind: read.manifest.kind, rowsVerified: read.rows.length,
      reason: "manifest.range.firstCounter (" + read.manifest.range.firstCounter +
              ") does not match the first archived row's monotonicCounter (" +
              read.rows[0].monotonicCounter + ") — the claimed range is wider than the rows present",
      expected: String(read.rows[0].monotonicCounter),
      actual:   String(read.manifest.range.firstCounter),
    };
  }
  if (!sliceLastRow) {
    return {
      ok: false, kind: read.manifest.kind, rowsVerified: read.rows.length,
      reason: "manifest.range.lastCounter (" + read.manifest.range.lastCounter +
              ") names no row present in the bundle",
    };
  }
  if (!sliceLastRow || sliceLastRow.rowHash !== read.manifest.range.lastRowHash) {
    return {
      ok: false, kind: read.manifest.kind, rowsVerified: read.rows.length,
      reason: "manifest.range.lastRowHash does not match the slice row at lastCounter",
    };
  }

  if (read.manifest.kind === KIND_ARCHIVE) {
    if (!read.checkpoint) {
      return { ok: false, kind: KIND_ARCHIVE, reason: "checkpoint missing from archive bundle" };
    }
    if (Number(read.checkpoint.atMonotonicCounter) < lastCounterN) {
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
    var anchorCounterN = Number(read.checkpoint.atMonotonicCounter);
    var anchoredRow = null;
    for (var ai = 0; ai < read.rows.length; ai++) {
      if (Number(read.rows[ai].monotonicCounter) === anchorCounterN) { anchoredRow = read.rows[ai]; break; }
    }
    if (!anchoredRow) {
      return {
        ok: false, kind: KIND_ARCHIVE,
        reason: "checkpoint anchors counter=" + anchorCounterN +
                " but no such row is present in the bundle — checkpoint not bound to the archived slice",
      };
    }
    if (anchoredRow.rowHash !== read.checkpoint.atRowHash) {
      return {
        ok: false, kind: KIND_ARCHIVE,
        reason: "checkpoint atRowHash does not match the bundle row at counter=" + anchorCounterN +
                " — the signed anchor does not bind this slice",
        expected: read.checkpoint.atRowHash,
        actual:   anchoredRow.rowHash,
      };
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

  var v = await verifyBundle({
    in:         opts.archive,
    passphrase: opts.passphrase,
    verifySignature: opts.verifySignature,
  });
  if (!v.ok) {
    throw new AuditToolsError("audit-tools/archive-not-ok",
      "purge: archive failed verification: " + v.reason);
  }
  if (v.kind !== KIND_ARCHIVE) {
    throw new AuditToolsError("audit-tools/wrong-kind",
      "purge: bundle kind is '" + v.kind + "', must be 'archive'");
  }

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

  var checksums = v.manifest.checksum || {};
  var missingDigests = [];
  if (!checksums.rowsSha3_512) missingDigests.push("rowsSha3_512");
  if (!checksums.checkpointSha3_512) missingDigests.push("checkpointSha3_512");
  if (missingDigests.length > 0) {
    throw new AuditToolsError("audit-tools/archive-digest-missing",
      "purge: the archive's manifest records no " + missingDigests.join(" or ") +
      ", so the anchor would sign an empty digest and a later reader would fall " +
      "back to trusting the manifest's own checksum. Nothing was deleted — " +
      "re-create the archive with b.auditTools.archive.");
  }

  var readAnchor = opts.readAnchor || _defaultReadPurgeAnchor;
  var apply = opts.apply || _defaultApplyPurge;
  var applyArgs = {
    firstPurgedCounter:   Number(v.range.firstCounter),
    lastPurgedCounter:    Number(v.range.lastCounter),
    lastPurgedRowHash:    v.range.lastRowHash,
    archiveBundleId:      v.manifest.checkpoint && v.manifest.checkpoint.checkpointId
                          || ("manifest:" + v.range.lastCounter),
    archiveRowsDigest:    String(checksums.rowsSha3_512),
    archiveCheckpointDigest: String(checksums.checkpointSha3_512),
    archiveManifestDigest: String(backupCrypto.checksum(
      Buffer.from(_canonicalize(v.manifest), "utf8"))),
    purgedAt:             Date.now(),
  };

  var result = await audit().withChainLock(async function () {
    cluster.requireLeader();

    var anchor = await readAnchor();

    if (anchor) {
      var priorPolicy = _anchorVerifyOpts();
      var priorVerdict = auditChain.verifyPurgeAnchor(anchor, priorPolicy);
      if (!_anchorBelievable(priorVerdict, priorPolicy)) {
        throw new AuditToolsError("audit-tools/prior-anchor-not-verified",
          "purge: the existing purge anchor cannot be extended — " + priorVerdict.reason +
          ". Extending it would sign a boundary that covers whatever it already claims.");
      }
    }

    if (anchor && Number(anchor.fencingToken || 0) > cluster.fencingToken()) {
      throw new AuditToolsError("audit-tools/fenced-out",
        "purge refused before deleting anything: the stored purge anchor carries " +
        "fencingToken=" + anchor.fencingToken + ", above this node's " +
        cluster.fencingToken() + " — a higher-token leader has superseded it.");
    }

    var anchorFirst = anchor ? Number(anchor.firstPurgedCounter || 0) : 0;
    var expectedRetryFirst = anchorFirst;
    if (anchor && anchorFirst === 0) {
      expectedRetryFirst = await _defaultReadLowestLiveCounter(
        Number(anchor.lastPurgedCounter));
    }
    var isRetryOfAnchoredRange = !!anchor &&
      Number(anchor.lastPurgedCounter) === Number(v.range.lastCounter) &&
      anchor.lastPurgedRowHash === v.range.lastRowHash &&
      expectedRetryFirst !== null &&
      expectedRetryFirst === Number(v.range.firstCounter);

    if (!isRetryOfAnchoredRange) {
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
    }

    _signPurgeAnchorInto(applyArgs);

    return await apply(applyArgs);
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

/**
 * @primitive b.auditTools.signExistingPurgeAnchor
 * @signature b.auditTools.signExistingPurgeAnchor(opts?)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditChain.verifyPurgeAnchor, b.auditTools.purge
 *
 * Sign the purge anchor a previous version left unsigned, pinning the boundary
 * it already claims so it can never be moved again. Returns
 * `{ signed: false, reason }` when there is nothing to do — no anchor, an
 * anchor that is already signed, or a deployment running without audit
 * signing — and `{ signed: true, lastPurgedCounter, publicKeyFingerprint }`
 * when it wrote one.
 *
 * This is the upgrade path, and it exists because refusing an unsigned anchor
 * would otherwise strand the installation that has one: re-running the purge
 * is turned away by the contiguity guard, which requires an archive starting
 * one counter past the recorded boundary, and the boundary is exactly what is
 * in question. Reached through `b.db.init({ acceptUnsignedPurgeAnchor: true })`
 * once, after which the flag does nothing and should be removed.
 *
 * It pins what is already there rather than proving it. An operator who wants
 * the boundary PROVEN verifies the retained archive against the chain with
 * `b.auditTools.verifyBundle` before running this; nothing here can tell a
 * boundary a previous version wrote from one somebody else did, which is the
 * whole reason the signature exists.
 *
 * It also repairs the other way an anchor stops verifying without being
 * forged: naming a key that has since been rotated out. There the existing
 * signature is checked under that rotated key first, so a tampered anchor is
 * refused rather than re-signed into a valid one.
 *
 * @opts
 *   allow: string[],  // default: ["unsigned", "rotated-key"] — which situations this call may repair. `b.db.init` passes only what its own flags asserted, so one flag cannot buy the other's repair; they are different claims
 *
 * @example
 *   var r = await b.auditTools.signExistingPurgeAnchor();
 *   // → { signed: true, lastPurgedCounter: 4200, publicKeyFingerprint: "<hex>" }
 */
async function signExistingPurgeAnchor(opts) {
  opts = opts || {};
  var allow = Array.isArray(opts.allow) ? opts.allow : ["unsigned", "rotated-key"];
  if (_purgeAnchorSigningDisabled()) {
    return { signed: false, reason: "audit signing is not configured" };
  }
  return await audit().withChainLock(async function () {
    cluster.requireLeader();

    var anchor = await _defaultReadPurgeAnchor();
    if (!anchor) return { signed: false, reason: "no purge anchor" };

    var verdict = auditChain.verifyPurgeAnchor(anchor, { allowUnsigned: true });
    if (verdict.status === "valid") {
      return { signed: false, reason: "purge anchor is already signed" };
    }
    if (verdict.status !== "unsigned" && verdict.status !== "rotated-key") {
      throw new AuditToolsError("audit-tools/anchor-not-signable",
        "signExistingPurgeAnchor: " + verdict.reason);
    }
    if (allow.indexOf(verdict.status) === -1) {
      return { signed: false,
        reason: "purge anchor is " + verdict.status + ", which this call was not " +
          "authorized to repair (allow: " + allow.join(", ") + ")" };
    }
    if (verdict.status === "rotated-key") {
      var rotatedPem = null;
      try { rotatedPem = auditSign.getPublicKeyByFingerprint(String(anchor.publicKeyFingerprint)); }
      catch (_e) { rotatedPem = null; }
      var genuine = false;
      try {
        genuine = !!rotatedPem &&
          auditChain.purgeAnchorSignatureVerifies(anchor, anchor.signature, rotatedPem);
      } catch (_e2) { genuine = false; }
      if (!genuine) {
        throw new AuditToolsError("audit-tools/anchor-not-signable",
          "signExistingPurgeAnchor: the anchor names a rotated-out key but its " +
          "signature does not verify under that key either — re-signing would " +
          "turn a detectable problem into a permanent one");
      }
    }

    var args = {
      lastPurgedCounter: Number(anchor.lastPurgedCounter),
      lastPurgedRowHash: anchor.lastPurgedRowHash,
      archiveBundleId:   String(anchor.archiveBundleId),
      purgedAt:          Number(anchor.purgedAt),
      firstPurgedCounter: Number(anchor.firstPurgedCounter || 0),
      archiveRowsDigest:  anchor.archiveRowsDigest == null ? "" : String(anchor.archiveRowsDigest),
      archiveCheckpointDigest: anchor.archiveCheckpointDigest == null
                          ? "" : String(anchor.archiveCheckpointDigest),
      archiveManifestDigest: anchor.archiveManifestDigest == null
                          ? "" : String(anchor.archiveManifestDigest),
    };
    _signPurgeAnchorInto(args);
    await _writePurgeAnchor(args);
    return {
      signed:               true,
      repaired:             verdict.status,
      lastPurgedCounter:    args.lastPurgedCounter,
      publicKeyFingerprint: args.publicKeyFingerprint,
    };
  });
}

function _purgeAnchorSigningDisabled() {
  return auditSign.getMode() == null;
}

function _anchorVerifyOpts() {
  var policy = audit().getPurgeAnchorPolicy();
  return {
    resolvePublicKey: policy.resolvePublicKey,
    allowUnsigned:    policy.allowUnsigned || _purgeAnchorSigningDisabled(),
    allowUnchecked:   policy.allowUnchecked,
  };
}

function _anchorBelievable(verdict, policy) {
  if (verdict.status === "valid") return true;
  if (verdict.status === "unsigned" && verdict.accepted) return true;
  return verdict.status === "unchecked" && policy.allowUnchecked === true;
}

function _signPurgeAnchorInto(args) {
  if (_purgeAnchorSigningDisabled()) return args;
  args.scope = "audit";
  if (args.fencingToken == null) args.fencingToken = cluster.fencingToken();
  args.signature = auditSign.sign(auditChain.purgeAnchorPayload(args));
  args.publicKeyFingerprint = auditSign.getPublicKeyFingerprint();
  return args;
}

async function _defaultReadPurgeAnchor() {
  // clusterStorage rewrites it. allow:hand-rolled-sql — bare logical key.
  var built = sql.select("_blamejs_audit_purge_anchor", _sqlOpts())   // allow:hand-rolled-sql
    .where("scope", "audit")
    .toSql();
  return clusterStorage.executeOne(built.sql, built.params);
}

function _isSameAnchorRecord(surviving, args) {
  var wroteSig = args.signature == null ? null : Buffer.from(args.signature);
  var onDisk = surviving.signature == null ? null : Buffer.from(surviving.signature);
  if (wroteSig && onDisk) {
    return wroteSig.length === onDisk.length && wroteSig.equals(onDisk);
  }
  return String(surviving.archiveBundleId) === String(args.archiveBundleId) &&
    String(surviving.archiveRowsDigest == null ? "" : surviving.archiveRowsDigest) ===
      String(args.archiveRowsDigest == null ? "" : args.archiveRowsDigest) &&
    String(surviving.archiveCheckpointDigest == null ? "" : surviving.archiveCheckpointDigest) ===
      String(args.archiveCheckpointDigest == null ? "" : args.archiveCheckpointDigest) &&
    String(surviving.archiveManifestDigest == null ? "" : surviving.archiveManifestDigest) ===
      String(args.archiveManifestDigest == null ? "" : args.archiveManifestDigest) &&
    Number(surviving.fencingToken || 0) === Number(args.fencingToken || 0);
}

async function _defaultApplyPurge(args) {
  await _writePurgeAnchor(args);

  var surviving = await _defaultReadPurgeAnchor();
  var licensed = surviving ? Number(surviving.lastPurgedCounter) : -1;
  if (licensed < 0) {
    throw new AuditToolsError("audit-tools/anchor-vanished",
      "the purge anchor was removed between recording the boundary and deleting " +
      "the rows it covers; nothing was deleted.");
  }

  if (licensed !== Number(args.lastPurgedCounter) ||
      String(surviving.lastPurgedRowHash) !== String(args.lastPurgedRowHash) ||
      !_isSameAnchorRecord(surviving, args)) {
    throw new AuditToolsError("audit-tools/anchor-superseded",
      "the purge anchor recorded at counter=" + args.lastPurgedCounter +
      " was replaced before its rows were deleted; the boundary now in force is " +
      licensed + ". Nothing was deleted by this call. Keep the archive — the " +
      "range it covers has not been purged — and reconcile against the anchor " +
      "the surviving leader wrote.");
  }
  var deleteThrough = Math.min(Number(args.lastPurgedCounter), licensed);

  var del;
  try {
    del = await db().purgeAuditChain({ lastPurgedCounter: deleteThrough });
  } catch (e) {
    throw new AuditToolsError("audit-tools/purge-incomplete",
      "the purge boundary at counter=" + args.lastPurgedCounter + " was recorded, " +
      "but deleting the rows it covers failed: " + ((e && e.message) || String(e)) +
      ". Those rows are still present and verification will skip them until they " +
      "are removed. Re-run this purge with the same archive once the cause is fixed.");
  }
  return {
    rowsDeleted:        del.rowsDeleted,
    checkpointsDeleted: del.checkpointsDeleted,
    archiveBundleId:    args.archiveBundleId,
  };
}

async function _writePurgeAnchor(args) {
  // columns + binds 'audit'. allow:hand-rolled-sql — bare logical key.
  var fencingToken = args.fencingToken == null ? cluster.fencingToken() : args.fencingToken;
  var fence = await clusterStorage.fencedUpsert({
    table:      "_blamejs_audit_purge_anchor",   // allow:hand-rolled-sql — bare logical key
    keyColumns: ["scope"],
    label:      "auditTools.writePurgeAnchor",
    fenceColumns: ["fencingToken", "lastPurgedCounter"],
    values: {
      scope:             "audit",
      lastPurgedCounter: args.lastPurgedCounter,
      lastPurgedRowHash: args.lastPurgedRowHash,
      archiveBundleId:   args.archiveBundleId,
      purgedAt:          args.purgedAt,
      firstPurgedCounter: Number(args.firstPurgedCounter || 0),
      archiveRowsDigest:  args.archiveRowsDigest == null ? "" : String(args.archiveRowsDigest),
      archiveCheckpointDigest: args.archiveCheckpointDigest == null
                          ? "" : String(args.archiveCheckpointDigest),
      archiveManifestDigest: args.archiveManifestDigest == null
                          ? "" : String(args.archiveManifestDigest),
      signature:            args.signature == null ? null : args.signature,
      publicKeyFingerprint: args.publicKeyFingerprint == null ? null : args.publicKeyFingerprint,
      fencingToken:         fencingToken,
    },
  });
  if (fence.fenced) {
    throw new AuditToolsError("audit-tools/fenced-out",
      "purge anchor write rejected: fencingToken=" + fencingToken +
      " is below the stored token — a higher-token leader has superseded this " +
      "node. The rows for this range may already be deleted; do not re-run the " +
      "purge from here, and reconcile against the anchor the surviving leader wrote.");
  }
  audit().invalidateChainOrigin();
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
  var sliceResult = await exportSlice({
    out:         returnBytes ? undefined : opts.out,
    returnBytes: returnBytes,
    from:        sinceMs,
    to:          Date.now(),
    passphrase:  opts.passphrase,
    readRows:    opts.readRows,
    readCoveringCheckpoint: opts.readCoveringCheckpoint,
  });
  var manifest = {
    snapshotKind:      "forensic",
    incidentId:        opts.incidentId || null,
    reason:            opts.reason,
    actor:             opts.actor || null,
    composedAt:        new Date().toISOString(),
    auditSliceFile:    returnBytes ? frameworkFiles.fileName("rowsEnc") : (sliceResult && sliceResult.manifestPath),
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
    var files = Object.assign({}, sliceResult.files);
    files["forensic-snapshot.json"] = manifestBytes;
    return Object.assign({}, manifest, { files: files });
  }
  return Object.assign({}, manifest, { manifestPath: manifestPath });
}

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
      reasonCode: String(row.reason).slice(0, 256),
      policyType: "blamejs.audit-chain",
    } : undefined,
    attachments: meta ? [{
      contentType: "application/json",
      content:     JSON.stringify(meta),
      name:        "blamejs.metadata",
    }] : undefined,
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
 * Federation, DMTF DSP0262) — the FedRAMP / OpenStack
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
  signExistingPurgeAnchor: signExistingPurgeAnchor,
  withRecordedAtIso: withRecordedAtIso,
  BUNDLE_FORMAT:    BUNDLE_FORMAT,
  KIND_ARCHIVE:     KIND_ARCHIVE,
  KIND_EXPORT:      KIND_EXPORT,
  AuditToolsError:  AuditToolsError,
};
