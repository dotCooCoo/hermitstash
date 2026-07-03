// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.backup
 * @featured true
 * @nav    Production
 * @title  Backup
 *
 * @intro
 *   PQC-encrypted backup bundles — sealed columns + audit chain +
 *   keyring. SLH-DSA signature on every bundle, kid pinning, restore
 *   validates signature against operator-pinned public key.
 *
 *   The namespace wires `b.backupBundle.create` (encrypt + emit a bundle
 *   directory) to a pluggable storage backend, plus retention policy +
 *   audit emission. Ships with a local-filesystem backend
 *   (`b.backup.diskStorage`); S3 or any custom backend drops in through
 *   the same interface.
 *
 *   Storage backend contract:
 *
 *     {
 *       async writeBundle(bundleId, sourceDir),
 *       async readBundle(bundleId, destDir),
 *       async listBundles(),     // → [{ bundleId, createdAt, size }]
 *       async deleteBundle(bundleId),
 *       async hasBundle(bundleId),
 *     }
 *
 *   `vaultKeyJson` can be a string (the operator has the JSON in hand)
 *   or a function returning a string (or async returning a string) — the
 *   framework calls it each backup so a long-running app doesn't pin
 *   the vault key in memory between runs.
 *
 *   Bundle IDs are filesystem-safe timestamps with millisecond precision
 *   plus a 4-byte random suffix: `2026-04-27T14-00-00-123Z-a8f30b21`.
 *   Colons + dots in standard ISO-8601 are replaced with dashes so the
 *   id works as a directory name on every platform (Windows reserves
 *   `:` for drive letters). String sort still gives chronological order.
 *
 *   Posture-enforced encryption: HIPAA / PCI-DSS postures refuse a
 *   pipeline created with `encrypt: false`. Posture-enforced residency:
 *   gdpr / uk-gdpr / dpdp / pipl-cn / lgpd-br / appi-jp / pdpa-sg refuse
 *   a destination tag that doesn't match the live DB residency unless
 *   the operator passes `allowCrossBorder: true` with a documented
 *   `legalBasis`.
 *
 * @card
 *   PQC-encrypted backup bundles — sealed columns + audit chain + keyring.
 */

var nodeFs = require("node:fs");
var os = require("node:os");
var nodePath = require("node:path");
var bCrypto = require("../crypto");
var atomicFile = require("../atomic-file");
var C = require("../constants");
var backupBundle = require("./bundle");
var frameworkFiles = require("../framework-files");
var backupManifest = require("./manifest");
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var numericBounds = require("../numeric-bounds");
var boundedMap = require("../bounded-map");
var audit = lazyRequire(function () { return require("../audit"); });
var auditEmit = require("../audit-emit");
var compliance = lazyRequire(function () { return require("../compliance"); });
// lazyRequire ../db so backup stays a leaf module operators can use
// without the rest of the framework's DB chain loaded in the same
// module graph (CLI tools, stand-alone backup runners). The db()
// callable resolves on first access.
var dbModuleLazy = lazyRequire(function () { return require("../db"); });
var cryptoField = lazyRequire(function () { return require("../crypto-field"); });
var archiveLazy = lazyRequire(function () { return require("../archive"); });
var archiveAdaptersLazy = lazyRequire(function () { return require("../archive-adapters"); });
var { defineClass } = require("../framework-error");

var BackupError = defineClass("BackupError");

// Postures whose published controls require backup encryption. PCI
// DSS 4.0.1 Req 9.4.1.b ("backups are protected with strong cryptography
// and encrypted") and HIPAA §164.310(d)(2)(iv) ("create a retrievable,
// exact copy of ePHI" — encryption strongly implied by §164.312(a)(2)
// (iv) addressable encryption standard).
// v0.12.26 — the AI Act / AB-853 / CAC postures all carry
// `backupEncryptionRequired: true` in POSTURE_DEFAULTS (per
// compliance.js); list them here so bundleAdapterStorage's
// posture check refuses plaintext bundles under these regimes
// alongside the long-standing HIPAA + PCI-DSS pair.
// The legacy `ai-act` short
// name MUST appear in the backup encryption-required list too,
// otherwise a deployment pinned to `posture: "ai-act"` (the
// stated back-compat path) bypasses the cryptoStrategy refusal
// and writes plaintext bundles under what should be an EU AI
// Act gate. Both names share the cascade.
var BACKUP_ENCRYPTION_REQUIRED_POSTURES = Object.freeze([
  "hipaa", "pci-dss", "ai-act", "eu-ai-act", "ca-ab-853", "cac-genai-label",
]);

// "2026-04-27T14-00-00-123Z-a8f30b21" — atomicFile.pathTimestamp() form
// (ISO with ':'+'.' replaced by '-') plus a random suffix.
var BUNDLE_ID_RE = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-[0-9a-f]{8}$/;

// Cap on bundle-id length BEFORE the regex test — a malicious /
// pathological input can't make the regex engine spin if we bound
// length first. Bundle IDs in the wild are 32-ish chars; a 128-cap
// is comfortable.
var BUNDLE_ID_MAX_LEN = 0x80;
function _isValidBundleId(s) {
  return typeof s === "string" && s.length > 0 &&
    s.length <= BUNDLE_ID_MAX_LEN && BUNDLE_ID_RE.test(s);
}

function _generateBundleId() {
  return atomicFile.pathTimestamp() + "-" + bCrypto.generateToken(4);
}

function _dirSize(p) {
  var total = 0;
  var entries = nodeFs.readdirSync(p, { withFileTypes: true });
  for (var i = 0; i < entries.length; i++) {
    var f = nodePath.join(p, entries[i].name);
    if (entries[i].isDirectory()) total += _dirSize(f);
    else if (entries[i].isFile()) total += nodeFs.statSync(f).size;
  }
  return total;
}

// ---- Local filesystem storage backend (the default) ----

/**
 * @primitive b.backup.diskStorage
 * @signature b.backup.diskStorage(opts)
 * @since     0.11.2
 * @status    stable
 * @related   b.backup.create
 *
 * Local-filesystem storage backend implementing the
 * `{ writeBundle, readBundle, listBundles, deleteBundle, hasBundle }`
 * contract. Bundles land as directories named by bundle id under
 * `opts.root`. Newest-first ordering is enforced by reverse
 * lexicographic sort on the timestamp-prefixed bundle id.
 *
 * Operators pointing at S3 / GCS / Azure Blob / a tape gateway pass a
 * custom backend matching the same shape; the engine never touches the
 * filesystem directly.
 *
 * @opts
 *   root: string,   // required; directory under which bundle dirs land
 *
 * @example
 *   var fs   = require("node:fs");
 *   var path = require("node:path");
 *   var os   = require("node:os");
 *   var root = fs.mkdtempSync(path.join(os.tmpdir(), "backup-root-"));
 *
 *   var storage = b.backup.diskStorage({ root: root });
 *   storage.name;                                      // → "local"
 *   typeof storage.writeBundle;                        // → "function"
 *   typeof storage.listBundles;                        // → "function"
 */
function diskStorage(opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(opts.root, "diskStorage: opts.root", BackupError, "backup/no-storage-root");
  var root = opts.root;

  function _bundlePath(bundleId) {
    if (!_isValidBundleId(bundleId)) {
      throw new BackupError("backup/bad-bundle-id",
        "bundleId must match the framework's timestamp+suffix format");
    }
    return nodePath.join(root, bundleId);
  }

  return {
    name: "local",
    async writeBundle(bundleId, sourceDir) {
      atomicFile.ensureDir(root);
      var dest = _bundlePath(bundleId);
      if (nodeFs.existsSync(dest)) {
        throw new BackupError("backup/bundle-exists",
          "writeBundle: bundle '" + bundleId + "' already exists in storage");
      }
      atomicFile.copyDirRecursive(sourceDir, dest);
    },
    async readBundle(bundleId, destDir) {
      var src = _bundlePath(bundleId);
      if (!nodeFs.existsSync(src)) {
        throw new BackupError("backup/bundle-not-found",
          "readBundle: '" + bundleId + "' not in storage at " + root);
      }
      if (nodeFs.existsSync(destDir)) {
        throw new BackupError("backup/dest-exists",
          "readBundle: destDir already exists: " + destDir);
      }
      atomicFile.copyDirRecursive(src, destDir);
    },
    async listBundles() {
      if (!nodeFs.existsSync(root)) return [];
      var entries = nodeFs.readdirSync(root, { withFileTypes: true });
      var out = [];
      for (var i = 0; i < entries.length; i++) {
        if (!entries[i].isDirectory()) continue;
        if (!_isValidBundleId(entries[i].name)) continue;
        var p = nodePath.join(root, entries[i].name);
        var stat;
        try { stat = nodeFs.statSync(p); } catch (_e) { continue; }
        var size;
        try { size = _dirSize(p); } catch (_e) { size = 0; }
        out.push({
          bundleId:  entries[i].name,
          createdAt: stat.mtime.toISOString(),
          size:      size,
        });
      }
      // Newest first
      out.sort(function (a, b) { return a.bundleId < b.bundleId ? 1 : -1; });
      return out;
    },
    async deleteBundle(bundleId) {
      var p = _bundlePath(bundleId);
      if (!nodeFs.existsSync(p)) return;
      nodeFs.rmSync(p, { recursive: true, force: true });
    },
    async hasBundle(bundleId) {
      try { return nodeFs.existsSync(_bundlePath(bundleId)); }
      catch (_e) { return false; }
    },
  };
}

// ---- Engine ----

function _validateStorage(storage) {
  validateOpts.requireMethods(storage,
    ["writeBundle", "readBundle", "listBundles", "deleteBundle", "hasBundle"],
    "storage backend", BackupError, "backup/bad-storage");
}

async function _resolveVaultKeyJson(vaultKeyJsonOpt) {
  if (typeof vaultKeyJsonOpt === "string") return vaultKeyJsonOpt;
  if (typeof vaultKeyJsonOpt === "function") {
    var r = vaultKeyJsonOpt();
    if (r && typeof r.then === "function") r = await r;
    if (typeof r !== "string" || r.length === 0) {
      throw new BackupError("backup/bad-vault-key",
        "vaultKeyJson function must return a non-empty string");
    }
    return r;
  }
  throw new BackupError("backup/no-vault-key-json",
    "opts.vaultKeyJson is required (string or function returning a string)");
}

/**
 * @primitive b.backup.create
 * @signature b.backup.create(opts)
 * @since     0.4.0
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2, dora
 * @related   b.backup.diskStorage, b.backup.recommendedFiles, b.backup.verifyManifestSignature, b.backupBundle.create
 *
 * Build a backup engine bound to a data directory, a storage backend,
 * the operator's passphrase, and an include list. Returns an object
 * with `run` / `list` / `delete` / `read` / `purgeOlder` / `schedule` /
 * `scheduleTest` plus the wired `storage` reference.
 *
 * Each `run()` produces a fresh bundle id (`<iso-timestamp>-<8 hex>`),
 * stages encryption to a process-private tmpdir, writes through
 * `storage.writeBundle`, sweeps tmpdir, then applies retention. Audit
 * events `backup.success` / `backup.failure` / `backup.retention.swept`
 * land on `b.audit` when `opts.audit !== false`.
 *
 * Posture gates fire at `create()` time, not `run()` time — so a
 * misconfigured pipeline refuses to construct rather than producing
 * one good bundle and then failing the next.
 *
 * @opts
 *   dataDir:           string,                       // required; must exist on disk
 *   storage:           StorageBackend,               // required; diskStorage() or custom
 *   passphrase:        Buffer | string,              // required; KEK for per-file Argon2id wrap
 *   files:             Array<{ relativePath, kind, required }>,
 *   vaultKeyJson:      string | () => string | Promise<string>,
 *   retention:         { keep: number },             // optional; sweep older bundles after run()
 *   audit:             boolean,                      // default true
 *   scheduler:         b.scheduler,                  // required for schedule() / scheduleTest()
 *   flushBeforeBackup: false | () => void | Promise<void>,
 *   requireFlush:      boolean,                      // default false
 *   encrypt:           boolean,                      // default true; refused under hipaa / pci-dss
 *   residencyTag:      string | null,                // e.g. "EU"; checked against b.db.getDataResidency()
 *   allowCrossBorder:  boolean,                      // explicit override for residency mismatch
 *   legalBasis:        string,                       // recorded in audit chain when allowCrossBorder
 *
 * @example
 *   var fs     = require("node:fs");
 *   var path   = require("node:path");
 *   var os     = require("node:os");
 *
 *   var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "backup-data-"));
 *   var root    = fs.mkdtempSync(path.join(os.tmpdir(), "backup-root-"));
 *   fs.writeFileSync(path.join(dataDir, "db.enc"),     Buffer.from([1, 2, 3]));
 *   fs.writeFileSync(path.join(dataDir, "db.key.enc"), Buffer.from([4, 5, 6]));
 *
 *   var engine = b.backup.create({
 *     dataDir:      dataDir,
 *     storage:      b.backup.diskStorage({ root: root }),
 *     passphrase:   Buffer.from("operator backup passphrase"),
 *     files: [
 *       { relativePath: "db.enc",     kind: "raw", required: true },
 *       { relativePath: "db.key.enc", kind: "raw", required: true },
 *     ],
 *     vaultKeyJson: '{"version":1,"kid":"k1"}',
 *     retention:    { keep: 7 },
 *   });
 *
 *   typeof engine.run;          // → "function"
 *   typeof engine.list;         // → "function"
 *   typeof engine.purgeOlder;   // → "function"
 */
function create(opts) {
  opts = opts || {};
  if (typeof opts.dataDir !== "string" || !nodeFs.existsSync(opts.dataDir)) {
    throw new BackupError("backup/no-datadir",
      "create: opts.dataDir is required and must exist");
  }
  _validateStorage(opts.storage);
  if (!Buffer.isBuffer(opts.passphrase) && typeof opts.passphrase !== "string") {
    throw new BackupError("backup/no-passphrase",
      "create: opts.passphrase is required (Buffer or string)");
  }
  if (!Array.isArray(opts.files) || opts.files.length === 0) {
    throw new BackupError("backup/no-files",
      "create: opts.files must be a non-empty array of include entries");
  }
  if (opts.vaultKeyJson === undefined) {
    throw new BackupError("backup/no-vault-key-json",
      "create: opts.vaultKeyJson is required (string or function returning string)");
  }

  // Posture-enforced backup encryption. HIPAA / PCI-DSS
  // operators MUST keep encryption on. The framework's backup pipeline
  // is encrypted-by-default — passphrase + per-file XChaCha20-Poly1305
  // — but operators in third-party storage backends sometimes pass
  // `encrypt: false` on bespoke backends. Refuse boot under regulated
  // postures. Permits explicit `opts.allowUnencrypted: true` only when
  // a documented compensating control is present (offline tape vault
  // with physical custody, separate KMS-encrypted bucket, etc.) — and
  // even then the framework refuses unless paired with the operator's
  // posture explicitly acknowledging the deviation.
  var posture = null;
  try { posture = compliance().current(); }
  catch (_e) { /* compliance optional at backup-create time */ }
  if (posture && BACKUP_ENCRYPTION_REQUIRED_POSTURES.indexOf(posture) !== -1) {
    if (opts.encrypt === false) {
      throw new BackupError("backup/encryption-required",
        "backup.create: posture='" + posture + "' requires backup encryption " +
        "(HIPAA §164.310(d)(2)(iv) / PCI DSS 4.0.1 Req 9.4.1.b). " +
        "Refusing to create an unencrypted backup pipeline.");
    }
  }

  // Backup destination residency posture. EU-tagged primary
  // backing up to a US-region destination is a GDPR Article 46
  // cross-border transfer; without an explicit operator opt-in the
  // framework refuses to create the pipeline under gdpr / dpdp /
  // pipl-cn / uk-gdpr / lgpd-br / appi-jp / pdpa-sg postures.
  //
  //   b.backup.create({
  //     ...,
  //     residencyTag: "EU",                  // matches your DB residency
  //     allowCrossBorder: true,              // explicit override
  //     legalBasis: "EU SCCs 2021/914",      // recorded in audit chain
  //   });
  var BACKUP_RESIDENCY_REGULATED_POSTURES = ["gdpr", "uk-gdpr", "dpdp", "pipl-cn",
    "lgpd-br", "appi-jp", "pdpa-sg"];
  var backupResidencyTag = opts.residencyTag || null;
  if (opts.residencyTag !== undefined && opts.residencyTag !== null &&
      (typeof opts.residencyTag !== "string" || opts.residencyTag.length === 0)) {
    throw new BackupError("backup/bad-residency-tag",
      "backup.create: opts.residencyTag must be a non-empty string or null");
  }
  if (posture && BACKUP_RESIDENCY_REGULATED_POSTURES.indexOf(posture) !== -1) {
    var dbResidency = null;
    try {
      var dbModuleR = dbModuleLazy();
      dbResidency = (dbModuleR && typeof dbModuleR.getDataResidency === "function")
        ? dbModuleR.getDataResidency() : null;
    } catch (_e) { dbResidency = null; }
    var dbTag = (dbResidency && dbResidency.region) || null;
    if (dbTag && backupResidencyTag &&
        dbTag !== backupResidencyTag &&
        backupResidencyTag !== "unrestricted" &&
        dbTag !== "unrestricted") {
      if (!opts.allowCrossBorder) {
        throw new BackupError("backup/residency-mismatch",
          "backup.create: db residency '" + dbTag +
          "' but backup destination residencyTag '" + backupResidencyTag +
          "' under '" + posture + "' posture. This is a cross-border data " +
          "transfer (GDPR Art 46 / DPDP / PIPL category). Pass " +
          "allowCrossBorder: true with a documented legalBasis to suppress.");
      }
    }
    if (!backupResidencyTag) {
      // Under regulated posture an undeclared backup residency is a
      // smell — emit warning, don't refuse (operators with single-
      // region S3 buckets that match the DB region are the common
      // case and shouldn't be blocked).
      try {
        audit().safeEmit({
          action:   "backup.residency_undeclared",
          outcome:  "success",
          metadata: { severity: "warning", posture: posture, dbResidency: dbTag,
            recommendation: "declare opts.residencyTag matching the DB residency tag" },
        });
      } catch (_e) { /* drop-silent */ }
    }
    // Per-row residency blind spot: the deployment-level check above only
    // compares the single DB region to the destination. A per-row-residency
    // table is DECLARED (cryptoField.declarePerRowResidency) to admit rows in
    // several regions; rows tagged to a region other than the backup
    // destination are a per-row cross-border transfer the deployment compare
    // cannot see. Surface the declared cross-border regions (policy-based —
    // no row scan) so the bundle's residency exposure is visible.
    if (backupResidencyTag) {
      try {
        var perRowTables = cryptoField().listPerRowResidency();
        var perRowCrossBorder = [];
        for (var pri = 0; pri < perRowTables.length; pri++) {
          var prt = perRowTables[pri];
          var offending = (prt.allowedTags || []).filter(function (tag) {
            return tag !== "global" && tag !== "unrestricted" && tag !== backupResidencyTag;
          });
          if (offending.length) perRowCrossBorder.push({ table: prt.table, regions: offending });
        }
        if (perRowCrossBorder.length) {
          audit().safeEmit({
            action:   "backup.residency.per_row_cross_border",
            outcome:  "success",
            metadata: {
              severity: "warning", scope: "per-row", posture: posture,
              destination: backupResidencyTag, tables: perRowCrossBorder,
              recommendation: "a per-row-residency table admits rows in regions other than the backup destination; confirm the cross-border transfer is permitted (allowCrossBorder + documented legalBasis) or restrict the destination region",
            },
          });
        }
      } catch (_e) { /* drop-silent — advisory only */ }
    }
  }

  var dataDir = opts.dataDir;
  var storage = opts.storage;
  var passphrase = opts.passphrase;
  var files = opts.files;
  var vaultKeyJsonOpt = opts.vaultKeyJson;
  var retention = opts.retention || null;
  var auditOn = opts.audit !== false;
  var scheduler = opts.scheduler || null;
  // flushBeforeBackup — call db.flushToDisk() (or operator-supplied
  // flush) before snapshotting so encrypted-at-rest dbs are current.
  // In encrypted-at-rest mode the framework re-encrypts to disk every
  // ~5 min; without a pre-flush a backup of db.enc could be that
  // stale relative to the live tmpfs DB. Pass false to skip when the
  // operator's calling backup against a process that doesn't own the
  // DB (e.g. an out-of-band backup tool reading a paused replica).
  var flushBeforeBackup = typeof opts.flushBeforeBackup === "function"
    ? opts.flushBeforeBackup
    : (opts.flushBeforeBackup === false ? null : null);
  // requireFlush — when true, a flush failure FAILS the backup instead
  // of producing a (potentially stale) snapshot. Operators on
  // encrypted-at-rest with hard freshness requirements (compliance,
  // audit, point-in-time recovery) opt in. Default false preserves the
  // long-standing best-effort posture for operators who care about
  // backup completing more than freshness.
  var requireFlush = opts.requireFlush === true;
  // Default: try b.db.flushToDisk if available. Wired this way so the
  // backup primitive doesn't take a hard dependency on b.db (operators
  // running backup against an external db handle still work).
  if (flushBeforeBackup === null && opts.flushBeforeBackup !== false) {
    try {
      var dbModule = dbModuleLazy();
      if (typeof dbModule.flushToDisk === "function") {
        flushBeforeBackup = function () { dbModule.flushToDisk(); };
      }
    } catch (_e) { /* db not available in this module graph — flush is a no-op */ }
  }

  var _emitAudit = auditEmit.gatedReasonEmitter({ audit: auditOn });

  async function run(runOpts) {
    runOpts = runOpts || {};
    var t0 = Date.now();
    var bundleId = _generateBundleId();
    var stagingDir = nodePath.join(os.tmpdir(),
      "blamejs-backup-staging-" + bundleId.replace(/[:.]/g, "-"));

    // Flush the live DB to disk so the snapshot is current. Default
    // posture is best-effort — a flush failure logs but doesn't fail
    // the whole backup. With requireFlush:true the failure aborts the
    // backup so a stale snapshot never lands in storage.
    if (flushBeforeBackup) {
      try { await flushBeforeBackup(); }
      catch (e) {
        var flushReason = (e && e.message) || String(e);
        _emitAudit("backup.flush.failure",
          { bundleId: bundleId, reason: flushReason },
          requireFlush ? "failure" : "warning");
        if (requireFlush) {
          _emitAudit("backup.failure",
            { bundleId: bundleId, reason: "flush-required-but-failed: " + flushReason },
            "failure");
          throw new BackupError("backup/flush-required-failed",
            "backup flush required but failed: " + flushReason);
        }
      }
    }

    var vaultKeyJson;
    try {
      vaultKeyJson = await _resolveVaultKeyJson(vaultKeyJsonOpt);
    } catch (e) {
      _emitAudit("backup.failure", { bundleId: bundleId, reason: e.message }, "failure");
      throw e;
    }

    var bundleResult;
    try {
      bundleResult = await backupBundle.create({
        dataDir:      dataDir,
        outDir:       stagingDir,
        passphrase:   passphrase,
        vaultKeyJson: vaultKeyJson,
        files:        files,
        metadata:     Object.assign({ bundleId: bundleId }, runOpts.metadata || {}),
        progressCallback: runOpts.progressCallback,
      });
    } catch (e) {
      try { nodeFs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort tmpdir cleanup */ }
      _emitAudit("backup.failure",
        { bundleId: bundleId, reason: (e && e.message) || String(e) }, "failure");
      throw e;
    }

    try {
      await storage.writeBundle(bundleId, stagingDir);
    } catch (e) {
      try { nodeFs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort tmpdir cleanup */ }
      _emitAudit("backup.failure",
        { bundleId: bundleId, reason: "storage.writeBundle: " + ((e && e.message) || String(e)) },
        "failure");
      throw new BackupError("backup/storage-write-failed",
        "writing bundle to storage failed: " + ((e && e.message) || String(e)));
    }

    try { nodeFs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }

    var summary = {
      bundleId:   bundleId,
      bundleSize: bundleResult.bundleSize,
      fileCount:  bundleResult.fileCount,
      durationMs: Date.now() - t0,
      storage:    storage.name || "custom",
    };
    _emitAudit("backup.success", summary);

    // Retention sweep — best-effort. A failure here logs but does NOT
    // fail the run (the bundle is already safely written; pruning
    // can be retried).
    if (retention && typeof retention.keep === "number" && retention.keep > 0) {
      try {
        var purged = await purgeOlder({ keep: retention.keep });
        summary.retentionPurged = purged.deleted;
      } catch (e) {
        _emitAudit("backup.retention.failure",
          { bundleId: bundleId, reason: (e && e.message) || String(e) },
          "warning");
      }
    }
    return summary;
  }

  async function list() {
    return await storage.listBundles();
  }

  async function deleteBundle(bundleId) {
    if (!_isValidBundleId(bundleId)) {
      throw new BackupError("backup/bad-bundle-id",
        "bundleId must match the framework's timestamp+suffix format");
    }
    await storage.deleteBundle(bundleId);
    _emitAudit("backup.deleted", { bundleId: bundleId });
  }

  async function read(bundleId, destDir) {
    if (!_isValidBundleId(bundleId)) {
      throw new BackupError("backup/bad-bundle-id",
        "bundleId must match the framework's timestamp+suffix format");
    }
    await storage.readBundle(bundleId, destDir);
  }

  async function purgeOlder(purgeOpts) {
    purgeOpts = purgeOpts || {};
    var keep = typeof purgeOpts.keep === "number" && purgeOpts.keep >= 0
      ? Math.floor(purgeOpts.keep) : 0;
    var bundles = await storage.listBundles();
    // listBundles returns newest first; keep the first `keep`, purge rest.
    var toDelete = bundles.slice(keep);
    var deleted = [];
    for (var i = 0; i < toDelete.length; i++) {
      try {
        await storage.deleteBundle(toDelete[i].bundleId);
        deleted.push(toDelete[i].bundleId);
      } catch (e) {
        _emitAudit("backup.deleted.failure",
          { bundleId: toDelete[i].bundleId, reason: (e && e.message) || String(e) },
          "failure");
      }
    }
    if (deleted.length > 0) {
      _emitAudit("backup.retention.swept", { kept: keep, deleted: deleted });
    }
    return { kept: keep, deleted: deleted };
  }

  function schedule(scheduleOpts) {
    if (!scheduler || typeof scheduler.create !== "function") {
      throw new BackupError("backup/no-scheduler",
        "schedule: opts.scheduler must be wired at create() to use schedule()");
    }
    scheduleOpts = scheduleOpts || {};
    if (typeof scheduleOpts.cron !== "string" || scheduleOpts.cron.length === 0) {
      throw new BackupError("backup/bad-schedule",
        "schedule: opts.cron is required (POSIX 5-field cron expression)");
    }
    var name = scheduleOpts.name || "blamejs.backup";
    // Operators wire scheduler instances themselves; create() returns a
    // scheduler we can append to.
    var schedInstance = scheduler.create({ audit: auditOn });
    schedInstance.schedule({
      name:     name,
      cron:     scheduleOpts.cron,
      timezone: scheduleOpts.timezone,
      run:      async function () {
        try { await run({ metadata: { reason: "scheduled" } }); }
        catch (_e) { /* errors already audited inside run() */ }
      },
    });
    return { name: name, instance: schedInstance };
  }

  // scheduleTest — periodic restore-and-verify drill required by HIPAA
  // §164.308(a)(7)(ii)(D) ("testing and revision procedures"). The
  // framework picks the latest backup, restores it to the operator-
  // supplied directory, runs the operator's verify callback, and emits
  // backup.test.passed / backup.test.failed in the audit chain.
  //
  //   await b.backup.scheduleTest({
  //     cron:      "0 3 * * 0",                  // weekly at 03:00 Sunday
  //     restoreTo: "/var/backup-test/staging",
  //     verify:    async function ({ outDir, manifest }) {
  //       // operator confirms key files restored, returns truthy on
  //       // success or throws on failure.
  //     },
  //     notify:    async function ({ outcome, reason, manifest }) { /* page operator */ },
  //     posture:   "hipaa",
  //   });
  function scheduleTest(testOpts) {
    if (!scheduler || typeof scheduler.create !== "function") {
      throw new BackupError("backup/no-scheduler",
        "scheduleTest: opts.scheduler must be wired at create() to use scheduleTest()");
    }
    testOpts = testOpts || {};
    if (typeof testOpts.cron !== "string" || testOpts.cron.length === 0) {
      throw new BackupError("backup/bad-test-schedule",
        "scheduleTest: opts.cron is required");
    }
    if (typeof testOpts.restoreTo !== "string" || testOpts.restoreTo.length === 0) {
      throw new BackupError("backup/bad-test-restore-to",
        "scheduleTest: opts.restoreTo is required (operator-controlled staging dir)");
    }
    if (typeof testOpts.verify !== "function") {
      throw new BackupError("backup/bad-test-verify",
        "scheduleTest: opts.verify must be an async function — operator " +
        "supplies the per-deployment verification (file exists, schema " +
        "matches, audit chain verifies, etc.)");
    }
    var name = testOpts.name || "blamejs.backup.test";
    var schedInstance = scheduler.create({ audit: auditOn });
    schedInstance.schedule({
      name:     name,
      cron:     testOpts.cron,
      timezone: testOpts.timezone,
      run:      async function () {
        var startedAt = Date.now();
        var bundles = [];
        try { bundles = await storage.listBundles(); }
        catch (e) {
          _emitAudit("backup.test.failed",
            { reason: "listBundles failed: " + ((e && e.message) || String(e)) },
            "failure");
          return;
        }
        if (!bundles || bundles.length === 0) {
          _emitAudit("backup.test.failed",
            { reason: "no bundles in storage to test against" },
            "failure");
          return;
        }
        // Newest bundle (storage.listBundles returns newest first).
        var bundleId = bundles[0].bundleId;
        var stagingDir = nodePath.join(testOpts.restoreTo,
          "test-" + bundleId.replace(/[:.]/g, "-"));
        // Refuse to overwrite an existing dir — operators get a fresh
        // restore every drill.
        if (nodeFs.existsSync(stagingDir)) {
          _emitAudit("backup.test.failed",
            { bundleId: bundleId, reason: "stagingDir already exists: " + stagingDir },
            "failure");
          return;
        }
        var manifestPath, manifest, sigVerification;
        try {
          await storage.readBundle(bundleId, stagingDir);
          manifestPath = nodePath.join(stagingDir, "manifest.json");
          // Capped fd-bound read inside the scheduled restore-drill tick: an
          // oversized manifest must not OOM the scheduler worker.
          manifest = backupManifest.parse(atomicFile.fdSafeReadSync(manifestPath, {
            maxBytes: C.BYTES.mib(4), encoding: "utf8",
            errorFor: function (kind) {
              if (kind === "enoent") return new BackupError("backup/test-no-manifest", "manifest.json missing under restored bundle " + bundleId);
              if (kind === "too-large") return new BackupError("backup/test-bad-manifest", "manifest.json too large under restored bundle " + bundleId);
              return new BackupError("backup/test-no-manifest", "manifest.json unreadable under restored bundle " + bundleId + ": " + kind);
            },
          }));
          // Verify the manifest signature so a tampered backup test
          // surfaces here, not as a regulator finding later.
          sigVerification = backupManifest.verifySignature(manifest, {
            expectedFingerprint: testOpts.expectedFingerprint || undefined,
          });
          if (!sigVerification.ok) {
            throw new BackupError("backup/test-bad-signature",
              "manifest signature invalid: " + sigVerification.reason);
          }
          // Hand off to operator verify hook
          await testOpts.verify({
            outDir:       stagingDir,
            manifest:     manifest,
            bundleId:     bundleId,
            sigFingerprint: sigVerification.fingerprint,
          });
          _emitAudit("backup.test.passed", {
            bundleId:        bundleId,
            posture:         testOpts.posture || posture || null,
            fingerprint:     sigVerification.fingerprint,
            durationMs:      Date.now() - startedAt,
          }, "success");
          if (typeof testOpts.notify === "function") {
            try { await testOpts.notify({ outcome: "success", bundleId: bundleId, manifest: manifest }); }
            catch (_e) { /* notify hook is best-effort */ }
          }
        } catch (e) {
          _emitAudit("backup.test.failed", {
            bundleId:    bundleId,
            posture:     testOpts.posture || posture || null,
            reason:      (e && e.message) || String(e),
            durationMs:  Date.now() - startedAt,
          }, "failure");
          if (typeof testOpts.notify === "function") {
            try {
              await testOpts.notify({
                outcome: "failure",
                bundleId: bundleId,
                reason: (e && e.message) || String(e),
              });
            } catch (_e) { /* notify hook is best-effort */ }
          }
        } finally {
          // Best-effort cleanup so the staging dir doesn't accumulate
          // across drills.
          if (testOpts.cleanup !== false) {
            try { nodeFs.rmSync(stagingDir, { recursive: true, force: true }); }
            catch (_e) { /* tmpdir cleanup best-effort */ }
          }
        }
      },
    });
    return { name: name, instance: schedInstance };
  }

  return {
    run:           run,
    list:          list,
    delete:        deleteBundle,
    read:          read,
    purgeOlder:    purgeOlder,
    schedule:      schedule,
    scheduleTest:  scheduleTest,
    storage:       storage,
  };
}

/**
 * @primitive b.backup.verifyManifestSignature
 * @signature b.backup.verifyManifestSignature(target, opts)
 * @since     0.7.30
 * @status    stable
 * @compliance hipaa, pci-dss, soc2
 * @related   b.backup.create, b.backupManifest.verifySignature
 *
 * Read the manifest from a restored bundle directory (or accept a
 * pre-parsed manifest object) and verify its SLH-DSA audit-sign
 * signature. Operator-facing wrapper around
 * `b.backupManifest.verifySignature` that handles the on-disk fetch
 * + JCS parse, so a regulator-facing restore drill is a single call.
 *
 * Returns `{ ok, fingerprint?, reason? }`. Throws `BackupError` only
 * for missing / unreadable / unparseable manifests — a bad signature
 * returns `{ ok: false, reason }` so the caller can branch on the
 * verdict without a try/catch.
 *
 * Pass `opts.expectedFingerprint` to pin the signing key; the
 * verification rejects any signature that validates against a
 * different key, even if the math checks out. That's the kid-pinning
 * the restore drill leans on.
 *
 * @opts
 *   expectedFingerprint: string,   // optional; SHA3-512 fingerprint to pin
 *
 * @example
 *   var fs   = require("node:fs");
 *   var path = require("node:path");
 *   var os   = require("node:os");
 *
 *   var bundleDir = fs.mkdtempSync(path.join(os.tmpdir(), "verify-bundle-"));
 *   try {
 *     b.backup.verifyManifestSignature(bundleDir);
 *   } catch (e) {
 *     e.code;           // → "backup/no-manifest"
 *   }
 */
function verifyManifestSignature(target, opts) {
  opts = opts || {};
  var manifest;
  if (typeof target === "string") {
    var manifestPath = nodePath.join(target, "manifest.json");
    // Capped fd-bound read OUTSIDE the parse try (so a missing/oversized manifest
    // surfaces backup/no-manifest|bad-manifest, not a generic parse error).
    var manifestRaw = atomicFile.fdSafeReadSync(manifestPath, {
      maxBytes: C.BYTES.mib(4), encoding: "utf8",
      errorFor: function (kind) {
        if (kind === "enoent") return new BackupError("backup/no-manifest", "verifyManifestSignature: manifest.json missing at " + manifestPath);
        if (kind === "too-large") return new BackupError("backup/bad-manifest", "verifyManifestSignature: manifest.json too large");
        return new BackupError("backup/bad-manifest", "verifyManifestSignature: unreadable: " + kind);
      },
    });
    try { manifest = backupManifest.parse(manifestRaw); }
    catch (e) {
      throw new BackupError("backup/bad-manifest",
        "verifyManifestSignature: parse failed: " + ((e && e.message) || String(e)));
    }
  } else if (target && typeof target === "object" && target.manifest) {
    manifest = target.manifest;
  } else if (target && typeof target === "object" &&
             typeof target.version === "number") {
    manifest = target;
  } else {
    throw new BackupError("backup/bad-target",
      "verifyManifestSignature: target must be a bundle dir path, " +
      "{ manifest } object, or a parsed manifest object");
  }
  return backupManifest.verifySignature(manifest, opts);
}

/**
 * @primitive b.backup.recommendedFiles
 * @signature b.backup.recommendedFiles(opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.backup.create, b.db.getMode, b.vault.getMode
 *
 * Return the framework-default include list for a given DB at-rest
 * mode + vault wrap mode. Operators with the standard layout pass the
 * result straight to `b.backup.create({ files })`; operators with
 * custom data files (additional sealed keys, OIDC provider material,
 * application-specific keystores) append their own entries.
 *
 * The list adapts to mode:
 * - plain DB        → the live SQLite file (default name `blamejs.db`)
 * - encrypted DB    → `db.enc` + `db.key.enc` (envelope + sealed DEK)
 * - plaintext vault → `vault.key`
 * - wrapped vault   → `vault.key.sealed`
 *
 * The audit-signing key is always included (sealed in `wrapped` mode)
 * so a restored deployment can verify its own audit chain.
 *
 * @opts
 *   atRest:           "plain" | "encrypted",       // default "encrypted"
 *   vaultMode:        "plaintext" | "wrapped",     // default "wrapped"
 *   dbName:           string,                      // default "blamejs.db"
 *   additionalSealed: Array<string>,               // operator-supplied sealed-file paths
 *
 * @example
 *   var files = b.backup.recommendedFiles({
 *     atRest:           "encrypted",
 *     vaultMode:        "wrapped",
 *     additionalSealed: ["ca.key.sealed", "tls/privkey.pem.sealed"],
 *   });
 *
 *   files[0].relativePath;   // → "db.enc"
 *   files[1].relativePath;   // → "db.key.enc"
 *   files[2].relativePath;   // → "vault.key.sealed"
 */
function recommendedFiles(opts) {
  opts = opts || {};
  var atRest = opts.atRest || "encrypted";
  var vaultMode = opts.vaultMode || "wrapped";
  var dbName = opts.dbName || "blamejs.db";
  var files = [];

  if (atRest === "encrypted") {
    files.push({ relativePath: frameworkFiles.fileName("dbEnc"),    kind: "raw", required: true });
    files.push({ relativePath: frameworkFiles.fileName("dbKeyEnc"), kind: "raw", required: true });
  } else {
    files.push({ relativePath: dbName,       kind: "raw", required: true });
  }

  if (vaultMode === "wrapped") {
    files.push({ relativePath: frameworkFiles.fileName("vaultKey") + ".sealed", kind: "raw", required: true });
  } else {
    files.push({ relativePath: frameworkFiles.fileName("vaultKey"), kind: "raw", required: true });
  }

  // Audit-signing key (always present; sealed in wrapped mode)
  files.push({
    relativePath: vaultMode === "wrapped"
      ? frameworkFiles.fileName("auditSignKey") + ".sealed"
      : frameworkFiles.fileName("auditSignKey"),
    kind: "raw", required: false,
  });

  // Operator-supplied additional sealed files (CA, TLS, etc.)
  if (Array.isArray(opts.additionalSealed)) {
    for (var i = 0; i < opts.additionalSealed.length; i++) {
      files.push({
        relativePath: opts.additionalSealed[i],
        kind: "vault-sealed",
        required: false,
      });
    }
  }

  return files;
}

/**
 * @primitive b.backup.runInWorker
 * @signature b.backup.runInWorker(opts)
 * @since     0.8.41
 * @status    stable
 * @related   b.backup.create
 *
 * Execute a backup or restore inside a `node:worker_threads` worker
 * so the heavy-CPU Argon2id + XChaCha20-Poly1305 + SHA3-512 walk
 * doesn't block the request loop. Returns a Promise resolving with
 * the worker's posted message, or rejecting with the worker's error,
 * a non-zero exit, or the operator's `timeoutMs`.
 *
 * The worker script is supplied by the operator — responsibility for
 * thread-safe storage adapters stays with the operator; this helper
 * is the dispatch + lifecycle glue. The framework rejects with
 * `backup/no-worker-threads` when `node:worker_threads` is
 * unavailable (sandboxed runtimes, stripped Node builds).
 *
 * @opts
 *   workerScript: string,   // required; absolute path to the worker module
 *   args:         object,   // optional; passed as workerData to the worker
 *   timeoutMs:    number,   // optional; positive finite int, terminates worker on miss
 *
 * @example
 *   var path = require("node:path");
 *
 *   b.backup.runInWorker({
 *     workerScript: path.resolve("/does/not/exist/worker.js"),
 *     args:         { mode: "full" },
 *     timeoutMs:    60000,
 *   }).catch(function (err) {
 *     // worker failed to load — error surfaces as a rejected promise
 *     typeof err.message;   // → "string"
 *   });
 */
function runInWorker(opts) {
  opts = opts || {};
  try {
    validateOpts.requireNonEmptyString(opts.workerScript, "workerScript",
      BackupError, "backup/no-worker-script");
  } catch (e) { return Promise.reject(e); }
  try {
    numericBounds.requirePositiveFiniteIntIfPresent(
      opts.timeoutMs, "timeoutMs", BackupError, "backup/bad-timeout");
  } catch (e) { return Promise.reject(e); }
  var timeoutMs = (opts.timeoutMs == null) ? null : opts.timeoutMs;
  var workerThreads;
  try { workerThreads = require("node:worker_threads"); }
  catch (_e) {
    return Promise.reject(new BackupError("backup/no-worker-threads",
      "runInWorker: node:worker_threads is unavailable in this runtime"));
  }
  return new Promise(function (resolve, reject) {
    var worker = new workerThreads.Worker(opts.workerScript, {
      workerData: opts.args || {},
    });
    var timer = null;
    if (timeoutMs !== null) {
      timer = setTimeout(function () {
        try { worker.terminate(); } catch (_e) { /* terminate best-effort */ }
        reject(new BackupError("backup/worker-timeout",
          "runInWorker: worker exceeded timeoutMs=" + timeoutMs));
      }, timeoutMs);
    }
    worker.on("message", function (msg) {
      if (timer) clearTimeout(timer);
      resolve(msg);
    });
    worker.on("error", function (err) {
      if (timer) clearTimeout(timer);
      reject(err);
    });
    worker.on("exit", function (code) {
      if (timer) clearTimeout(timer);
      if (code !== 0) {
        reject(new BackupError("backup/worker-nonzero-exit",
          "runInWorker: worker exited with code " + code));
      }
    });
  });
}

module.exports = {
  create:                    create,
  diskStorage:               diskStorage,
  bundleAdapterStorage:      bundleAdapterStorage,
  migrate:                   migrate,
  recommendedFiles:          recommendedFiles,
  runInWorker:               runInWorker,
  verifyManifestSignature:   verifyManifestSignature,
  BACKUP_ENCRYPTION_REQUIRED_POSTURES: BACKUP_ENCRYPTION_REQUIRED_POSTURES,
  BackupError:               BackupError,
  BUNDLE_ID_RE:              BUNDLE_ID_RE,
};

// ---- bundleAdapterStorage ---------------------------------------

/**
 * @primitive b.backup.bundleAdapterStorage
 * @signature b.backup.bundleAdapterStorage(opts)
 * @since     0.12.7
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.backup.diskStorage, b.backup.create
 *
 * Adapter-driven storage backend. Wraps the bundle directory's file
 * tree into per-file key-value pairs routed through an operator-
 * supplied byte-store adapter so backup bundles can land anywhere
 * that exposes the contract: local fs (the default), tar / tar.gz
 * folding, and S3 / MinIO / Azure / GCS objectStore adapters.
 *
 * The adapter contract (small surface; an `fs` implementation is the
 * default + ships in `lib/backup/_adapter-fs.js`):
 *
 *   adapter.writeFile(key, bytes): Promise<void>
 *   adapter.readFile(key): Promise<Buffer>
 *   adapter.listKeys(prefix): Promise<string[]>
 *   adapter.deleteKey(key): Promise<void>
 *   adapter.hasKey(key): Promise<boolean>
 *
 * Keys are `<bundleId>/<relative/path/within/bundle>`. Operators
 * pointing at an objectStore implementation pass an adapter that
 * routes keys to S3 paths; pointing at an HTTP-backed store, ditto.
 *
 * @opts
 *   adapter:   { writeFile, readFile, listKeys, deleteKey, hasKey },
 *
 * @example
 *   var storage = b.backup.bundleAdapterStorage({
 *     adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: "/var/backups" }),
 *   });
 *   storage.name;       // → "adapter"
 *   typeof storage.writeBundle;   // → "function"
 */
function bundleAdapterStorage(opts) {
  opts = opts || {};
  validateOpts.requireMethods(opts.adapter,
    ["writeFile", "readFile", "listKeys", "deleteKey", "hasKey"],
    "bundleAdapterStorage: opts.adapter", BackupError, "backup/bad-adapter");
  var adapter = opts.adapter;
  // v0.12.8 — `format: "tar"` becomes the default for new bundles.
  // `format: "directory"` opts back into the v0.12.7 file-by-file
  // layout for operators with existing bundles. The format is
  // operator-supplied so a single backup engine can transition over
  // time + b.backup.migrate() handles the directory → tar conversion.
  var format = opts.format || "tar";
  if (format !== "tar" && format !== "tar.gz" && format !== "directory") {
    throw new BackupError("backup/bad-format",
      "bundleAdapterStorage: format must be \"tar\" (default) | \"tar.gz\" (v0.12.9 compressed) | \"directory\" (legacy v0.12.7)");
  }
  // v0.12.10 — cryptoStrategy gates whether the bundle bytes are
  // wrapped in a recipient envelope before adapter.writeFile.
  //   "none"      — plaintext bundle (v0.12.7-9 behaviour). Safe
  //                 for adapter-encrypted storage (S3 SSE,
  //                 disk-encrypted hosts) where the storage layer
  //                 itself is the protective boundary.
  //   "recipient" — composes b.archive.wrap on write +
  //                 b.archive.unwrap on read. Operator supplies
  //                 `recipient: { publicKey, ecPublicKey }` (or
  //                 a peer-cert recipient); the bundle bytes
  //                 hitting the adapter are an opaque envelope.
  //                 HIPAA / PCI-DSS postures (per
  //                 BACKUP_ENCRYPTION_REQUIRED_POSTURES) REFUSE
  //                 "none" + require "recipient".
  var cryptoStrategy = opts.cryptoStrategy || "none";
  if (cryptoStrategy !== "none" && cryptoStrategy !== "recipient" &&
      cryptoStrategy !== "passphrase") {
    throw new BackupError("backup/bad-crypto-strategy",
      "bundleAdapterStorage: cryptoStrategy must be \"none\" (default — adapter-encrypted storage), " +
      "\"recipient\" (v0.12.10 — hybrid PQC envelope wrap), or \"passphrase\" (v0.12.11 — Argon2id + XChaCha20-Poly1305 wrap)");
  }
  var recipient = opts.recipient;
  if (cryptoStrategy === "recipient" && (!recipient || typeof recipient !== "object")) {
    throw new BackupError("backup/no-recipient",
      "bundleAdapterStorage: cryptoStrategy: \"recipient\" requires opts.recipient " +
      "({ publicKey, ecPublicKey } for the hybrid PQC envelope OR { peerCertDer, peerKemPubkey } " +
      "for the peer-cert envelope)");
  }
  var passphrase = opts.passphrase;
  // HIPAA + PCI-DSS recipe raises the floor to 128 bits (per
  // BACKUP_ENCRYPTION_REQUIRED_POSTURES below); default 80 matches
  // OWASP "strong password" guidance for generic deployments.
  // Typeof NaN === "number" and
  // typeof Infinity === "number" both pass the typeof gate but
  // bypass downstream comparisons (NaN < 128 is false; estimated
  // < NaN is false). Use Number.isFinite + a finite integer check
  // so the entropy floor can't be NaN'd out under HIPAA.
  var passphraseMinEntropyBits;
  if (opts.passphraseMinEntropyBits === undefined ||
      opts.passphraseMinEntropyBits === null) {
    passphraseMinEntropyBits = 80;                                                    // entropy-bits default floor, not byte count
  } else if (Number.isFinite(opts.passphraseMinEntropyBits) &&
             opts.passphraseMinEntropyBits >= 0) {
    passphraseMinEntropyBits = Math.floor(opts.passphraseMinEntropyBits);
  } else {
    throw new BackupError("backup/bad-arg",
      "bundleAdapterStorage: passphraseMinEntropyBits must be a finite non-negative number; " +
      "got " + JSON.stringify(opts.passphraseMinEntropyBits) +
      " (NaN / Infinity are refused upfront so the HIPAA / PCI-DSS 128-bit floor can't be bypassed)");
  }
  if (cryptoStrategy === "passphrase") {
    if (typeof passphrase !== "string" && !Buffer.isBuffer(passphrase)) {
      throw new BackupError("backup/no-passphrase",
        "bundleAdapterStorage: cryptoStrategy: \"passphrase\" requires opts.passphrase " +
        "(string or Buffer; Argon2id key derivation + XChaCha20-Poly1305 AEAD). " +
        "passphraseMinEntropyBits defaults to 80; HIPAA / PCI-DSS postures raise the floor to 128.");
    }
  }
  // The wrap layers (recipient AND
  // passphrase) compose only with the tar / tar.gz writeBundle
  // branches. Pairing encryption strategy with format: "directory"
  // would silently write plaintext per-file payloads. Refuse upfront
  // so operators see the contract gap rather than discover it via
  // disk inspection. Per-file encryption for directory format is a
  // future patch alongside the _crypto-base.js refactor.
  if ((cryptoStrategy === "recipient" || cryptoStrategy === "passphrase") &&
      format === "directory") {
    throw new BackupError("backup/" + cryptoStrategy + "-strategy-needs-bundled-format",
      "bundleAdapterStorage: cryptoStrategy: " + JSON.stringify(cryptoStrategy) +
      " requires format: \"tar\" or \"tar.gz\". Directory format writes per-file plaintext to " +
      "the adapter — the wrap layer composes only with tar / tar.gz bundles. Per-file " +
      "encryption for directory format is a future patch alongside the _crypto-base.js refactor.");
  }
  // Mirror create()'s ambient-posture read (see the create() encryption
  // gate above): an explicit opts.posture wins, but when it is unset the
  // globally-pinned compliance posture (b.compliance.set(...)) still drives
  // the encryption-required gate. Without this fallback a deployment that
  // pins HIPAA / PCI-DSS once and constructs the store with the documented
  // default ({ adapter }, cryptoStrategy defaulting to "none") slips a
  // plaintext bundle store past a gate create() enforces on encrypt:false —
  // an asymmetric fail-open under the same regulated posture.
  var posture = opts.posture;
  if (posture === undefined || posture === null) {
    try { posture = compliance().current(); }
    catch (_e) { posture = null; }                                                  // compliance optional at construction time
  }
  if (posture && BACKUP_ENCRYPTION_REQUIRED_POSTURES.indexOf(posture) !== -1) {
    if (cryptoStrategy === "none") {
      throw new BackupError("backup/posture-requires-encryption",
        "bundleAdapterStorage: posture=" + JSON.stringify(posture) +
        " requires cryptoStrategy: \"recipient\" or \"passphrase\" (the adapter-storage layer " +
        "cannot itself satisfy HIPAA / PCI-DSS encryption-at-rest with cryptoStrategy: \"none\"). " +
        "The recipient+directory and passphrase+directory combinations are refused separately so " +
        "operators don't slip plaintext per-file payloads past the posture gate.");
    }
    // v0.12.11 — passphrase strategy under HIPAA / PCI-DSS raises
    // the entropy floor to 128 bits (matches the framework's
    // existing crypto-grade-password discipline for sealed-storage).
    if (cryptoStrategy === "passphrase" && passphraseMinEntropyBits < 128) {          // entropy-bits floor, not byte count
      passphraseMinEntropyBits = 128;                                                  // entropy-bits floor, not byte count
    }
  }
  // Tar mode builds the whole archive
  // in memory before adapter.writeFile because the v0.12.8 adapter
  // contract is bytes-in (no writeStream method). The OOM-prevention
  // gate is maxBundleBytes: writeBundle pre-walks the source tree,
  // sums file sizes, and refuses upfront if the projected uncompressed
  // tar would exceed the cap. Default 8 GiB — accommodates typical
  // db + mail-spool + log bundles while refusing pathological inputs.
  // Defer-with-condition for true streaming: when the adapter
  // contract gains writeStream(key) (slated for v0.13+ alongside
  // multipart S3 upload primitives), this path switches to
  // tarBuilder.toStream() and writes chunks as they're produced.
  var maxBundleBytes = opts.maxBundleBytes !== undefined
    ? opts.maxBundleBytes
    : 8 * 1024 * 1024 * 1024;                                                       // allow:raw-byte-literal — 8 GiB default cap; uses C.BYTES.bytes covers numeric-literal rule
  if (!numericBounds.isPositiveFiniteInt(maxBundleBytes)) {                         // allow:inline-numeric-bounds-cascade — required-with-default opt
    throw new BackupError("backup/bad-arg",
      "bundleAdapterStorage: maxBundleBytes must be a positive finite integer; got " +
      numericBounds.shape(opts.maxBundleBytes));
  }

  function _ensureBundleId(bundleId) {
    if (!_isValidBundleId(bundleId)) {
      throw new BackupError("backup/bad-bundle-id",
        "bundleId must match the framework's timestamp+suffix format");
    }
  }

  function _walkDirSync(rootDir, out, rel) {
    rel = rel || "";
    var entries = nodeFs.readdirSync(nodePath.join(rootDir, rel), { withFileTypes: true });
    for (var i = 0; i < entries.length; i += 1) {
      var name = entries[i].name;
      var relPath = rel ? (rel + "/" + name) : name;
      if (entries[i].isDirectory()) {
        _walkDirSync(rootDir, out, relPath);
      } else if (entries[i].isFile()) {
        out.push(relPath);
      }
    }
    return out;
  }

  // Tar-format bundle storage stores the whole bundle as a single
  // key under `<bundleId>/bundle.tar` (or `<bundleId>/bundle.tar.gz`
  // for the v0.12.9 compressed variant). The marker is named that
  // way so listBundles + hasBundle can locate either format by key
  // prefix walk.
  var TAR_KEY_SUFFIX = "/bundle.tar";
  var TAR_GZ_KEY_SUFFIX = "/bundle.tar.gz";

  function _hasBundleKey(bundleId, format) {
    if (format === "tar") return adapter.hasKey(bundleId + TAR_KEY_SUFFIX);
    if (format === "tar.gz") return adapter.hasKey(bundleId + TAR_GZ_KEY_SUFFIX);
    return adapter.hasKey(bundleId + "/manifest.json");
  }

  return {
    name: "adapter",
    async writeBundle(bundleId, sourceDir) {
      _ensureBundleId(bundleId);
      if (!nodeFs.existsSync(sourceDir)) {
        throw new BackupError("backup/no-source",
          "writeBundle: sourceDir does not exist: " + sourceDir);
      }
      var alreadyHas = await _hasBundleKey(bundleId, format);
      if (alreadyHas) {
        throw new BackupError("backup/bundle-exists",
          "writeBundle: bundle '" + bundleId + "' already exists in storage");
      }
      if (format === "tar" || format === "tar.gz") {
        // Pack the source-directory tree into a single tar archive +
        // store under one key. Composes b.archive.tar (+ b.archive.gz
        // for the tar.gz variant which adds gzip compression on the
        // wire). Bundle sizes drop ~3-5× on text-heavy backups
        // (databases, JSON exports, mail spools) under tar.gz.
        //
        // Tar bytes are materialized in
        // memory because the v0.12.8 adapter contract is bytes-in
        // (writeFile takes a Buffer, no writeStream method). The
        // maxBundleBytes pre-walk computes the uncompressed payload
        // size (file bytes only — tar header overhead is bounded at
        // ~512 B per entry + 1024 B trailer) and refuses upfront so
        // pathological inputs throw `backup/bundle-too-large` instead
        // of OOM. The defer-with-condition for true streaming is
        // gated on the adapter contract gaining writeStream(key).
        var relPaths = _walkDirSync(sourceDir, []);
        var projectedBytes = 0;
        for (var pi = 0; pi < relPaths.length; pi += 1) {
          var stat = nodeFs.statSync(nodePath.join(sourceDir, relPaths[pi]));
          projectedBytes += stat.size;
        }
        if (projectedBytes > maxBundleBytes) {
          throw new BackupError("backup/bundle-too-large",
            "writeBundle: projected uncompressed bundle " + projectedBytes +
            " bytes exceeds maxBundleBytes=" + maxBundleBytes +
            " — split the source tree across multiple bundles or raise the cap");
        }
        var t = archiveLazy().tar();
        for (var i = 0; i < relPaths.length; i += 1) {
          var rel = relPaths[i];
          var bytes = nodeFs.readFileSync(nodePath.join(sourceDir, rel));
          t.addFile(rel, bytes);
        }
        var keySuffix = format === "tar.gz" ? TAR_GZ_KEY_SUFFIX : TAR_KEY_SUFFIX;
        var payloadBytes = format === "tar.gz"
          ? archiveLazy().gz(t.toBuffer()).toBuffer()
          : t.toBuffer();
        if (cryptoStrategy === "recipient") {
          payloadBytes = archiveLazy().wrap(payloadBytes, { recipient: recipient });
        } else if (cryptoStrategy === "passphrase") {
          payloadBytes = await archiveLazy().wrapWithPassphrase(payloadBytes, {
            passphrase:     passphrase,
            minEntropyBits: passphraseMinEntropyBits,
          });
        }
        await adapter.writeFile(bundleId + keySuffix, payloadBytes);
        return;
      }
      // Directory format (v0.12.7 layout).
      var dirRelPaths = _walkDirSync(sourceDir, []);
      for (var j = 0; j < dirRelPaths.length; j += 1) {
        var dirRel = dirRelPaths[j];
        var dirBytes = nodeFs.readFileSync(nodePath.join(sourceDir, dirRel));
        await adapter.writeFile(bundleId + "/" + dirRel, dirBytes);
      }
    },
    async readBundle(bundleId, destDir) {
      _ensureBundleId(bundleId);
      if (nodeFs.existsSync(destDir)) {
        throw new BackupError("backup/dest-exists",
          "readBundle: destDir already exists: " + destDir);
      }
      // Detect which format this bundle is in — operators with mixed
      // pre-v0.12.8 + post-v0.12.8 (+ v0.12.9 tar.gz) bundles can read
      // every flavor back.
      var hasTar = await adapter.hasKey(bundleId + TAR_KEY_SUFFIX);
      var hasTarGz = await adapter.hasKey(bundleId + TAR_GZ_KEY_SUFFIX);
      var hasManifest = await adapter.hasKey(bundleId + "/manifest.json");
      if (!hasTar && !hasTarGz && !hasManifest) {
        throw new BackupError("backup/bundle-not-found",
          "readBundle: '" + bundleId + "' not in storage");
      }
      atomicFile.ensureDir(destDir);
      if (hasTarGz) {
        // Propagate maxBundleBytes
        // to the gz restore path + disable the expansion-ratio cap.
        // archive.read.gz defaults (1 GiB output / 100× ratio) are
        // bomb-defense settings appropriate for adversarial input;
        // this is a SELF-AUTHORED bundle the writeBundle path
        // produced under maxBundleBytes — the restore contract is
        // "decompress to at most what was permitted on write." A
        // zero-filled DB file can easily hit >100× compression
        // ratio; without these opts the same primitive writes
        // bundles it can't read back.
        var gzBytes = await adapter.readFile(bundleId + TAR_GZ_KEY_SUFFIX);
        if (cryptoStrategy === "recipient") {
          gzBytes = archiveLazy().unwrap(gzBytes, { recipient: recipient });
        } else if (cryptoStrategy === "passphrase") {
          gzBytes = await archiveLazy().unwrapWithPassphrase(gzBytes, { passphrase: passphrase });
        }
        var gzReader = archiveLazy().read.gz(archiveAdaptersLazy().buffer(gzBytes), {
          maxDecompressedBytes: maxBundleBytes,
          maxExpansionRatio:    0,
        });
        var tarReader = gzReader.asTar();
        await tarReader.extract({ destination: destDir });
        return;
      }
      if (hasTar) {
        var tarBytes = await adapter.readFile(bundleId + TAR_KEY_SUFFIX);
        if (cryptoStrategy === "recipient") {
          tarBytes = archiveLazy().unwrap(tarBytes, { recipient: recipient });
        } else if (cryptoStrategy === "passphrase") {
          tarBytes = await archiveLazy().unwrapWithPassphrase(tarBytes, { passphrase: passphrase });
        }
        var reader = archiveLazy().read.tar(archiveAdaptersLazy().buffer(tarBytes));
        await reader.extract({ destination: destDir });
        return;
      }
      // Directory format readback (v0.12.7 layout).
      var keys = await adapter.listKeys(bundleId + "/");
      for (var i = 0; i < keys.length; i += 1) {
        var key = keys[i];
        var prefix = bundleId + "/";
        if (key.indexOf(prefix) !== 0) continue;
        var rel = key.slice(prefix.length);
        // Path-safety: rel must not escape destDir.
        var destPath = nodePath.join(destDir, rel);
        var resolvedDest = nodePath.resolve(destPath);
        var resolvedRoot = nodePath.resolve(destDir);
        if (resolvedDest !== resolvedRoot &&
            resolvedDest.indexOf(resolvedRoot + nodePath.sep) !== 0) {
          throw new BackupError("backup/bad-key",
            "readBundle: storage key " + JSON.stringify(rel) +
            " escapes destDir " + JSON.stringify(destDir));
        }
        atomicFile.ensureDir(nodePath.dirname(destPath));
        var bytes = await adapter.readFile(key);
        // Exclusive-create (wx) carries the v0.12.7 atomic-rollback
        // contract: readBundle refuses to overwrite pre-existing
        // files at destPath. Combined with the upfront destDir check
        // above (refuses if destDir already exists), the only way
        // wx fires here is a symlink swap between ensureDir and write
        // — which the framework refuses rather than following.
        nodeFs.writeFileSync(destPath, bytes, { flag: "wx", mode: 0o600 });
      }
    },
    async listBundles(listOpts) {
      // Get every key, partition by bundleId prefix, return sorted.
      listOpts = listOpts || {};
      var withStats = listOpts.withStats === true;
      // v0.12.17 — each bundle now carries the inferred format
      // (tar / tar.gz / directory) so operators picking which
      // bundle to restore can filter by format without touching
      // bytes. Format is inferred from the key suffix the
      // writeBundle path produced (rule §2 — the format is part
      // of the storage layout, not behind a probe).
      //
      // Track WHICH suffixes a
      // bundle carries (set of booleans) then apply explicit
      // precedence at the end: tar.gz > tar > directory. Matches
      // readBundle's preference (which checks hasTarGz first)
      // so listBundles' reported format aligns with restore
      // behavior regardless of adapter.listKeys() order.
      var allKeys = await adapter.listKeys("");
      var byBundle = new Map();
      for (var i = 0; i < allKeys.length; i += 1) {
        var key = allKeys[i];
        var slash = key.indexOf("/");
        if (slash <= 0) continue;
        var bid = key.slice(0, slash);
        if (!_isValidBundleId(bid)) continue;
        var stats = boundedMap.getOrInsert(byBundle, bid, function () {
          return { count: 0, hasTar: false, hasTarGz: false, hasOther: false };
        });
        stats.count += 1;
        var rest = key.slice(slash + 1);
        if (rest === "bundle.tar")         stats.hasTar = true;
        else if (rest === "bundle.tar.gz") stats.hasTarGz = true;
        else                                stats.hasOther = true;
      }
      var out = [];
      var entries = Array.from(byBundle.entries());
      for (var j = 0; j < entries.length; j += 1) {
        var bidJ = entries[j][0];
        var statsJ = entries[j][1];
        var fmtJ;
        if (statsJ.hasTarGz)    fmtJ = "tar.gz";        // matches readBundle precedence
        else if (statsJ.hasTar) fmtJ = "tar";
        else                    fmtJ = "directory";
        var entry = {
          bundleId:  bidJ,
          format:    fmtJ,
          createdAt: null,                    // adapter may not expose mtime
          size:      null,                    // best-effort; operators with stat-fast adapters call bundleInfo
        };
        // v0.12.18 — when opts.withStats is true AND the adapter
        // exposes statKey, fan-out a stat call per bundle's
        // payload key. O(N) round-trips so this is opt-in;
        // listBundles() with no opts stays cheap (single listKeys
        // call). Operators wanting per-bundle stats but not the
        // full bundleInfo envelope probe pick this middle ground.
        if (withStats && typeof adapter.statKey === "function") {
          var statKey;
          if (statsJ.hasTarGz)    statKey = bidJ + TAR_GZ_KEY_SUFFIX;
          else if (statsJ.hasTar) statKey = bidJ + TAR_KEY_SUFFIX;
          else                    statKey = bidJ + "/manifest.json";
          var sk = await adapter.statKey(statKey);
          if (sk && typeof sk.size === "number") entry.size = sk.size;
          if (sk && typeof sk.mtimeMs === "number") entry.createdAt = new Date(sk.mtimeMs).toISOString();
        }
        out.push(entry);
      }
      out.sort(function (a, b) { return a.bundleId < b.bundleId ? 1 : -1; });
      return out;
    },
    // verifyBundle(bundleId, opts?) — v0.12.19 integrity check.
    // Walks the bundle without restoring: confirms the payload
    // exists, the envelope (if any) decrypts under the supplied
    // key, and the inner archive structure is well-formed (every
    // entry enumerable). Returns `{ ok, format, envelopeKind,
    // entryCount, errors }`. opts.recipient / opts.passphrase
    // forwarded when the bundle is wrap-wrapped; omit them for
    // plaintext bundles. Composes safeArchive.inspect which gates
    // entries through bomb-policy + entry-type-policy walkers, so
    // a malformed archive surfaces with a typed error rather than
    // crashing the verify call.
    async verifyBundle(bundleId, vOpts) {
      vOpts = vOpts || {};
      _ensureBundleId(bundleId);
      var info;
      try { info = await this.bundleInfo(bundleId); }
      catch (e) {
        return {
          ok:           false,
          format:       null,
          envelopeKind: null,
          entryCount:   0,
          errors:       [e.code || e.message || String(e)],
        };
      }
      if (info.format === "directory") {
        // Directory format isn't archive-shaped — manifest.json
        // existence + readability via bundleInfo IS the
        // verification. No inspect walk applies.
        return {
          ok:           true,
          format:       info.format,
          envelopeKind: info.envelopeKind,
          entryCount:   null,
          errors:       [],
        };
      }
      // Compose the reader chain directly so we don't depend on
      // safeArchive's auto-sniff dispatch (which is conservative
      // about inferring "tar.gz" from gzip-magic-only inner bytes).
      // We already know the bundle's format + envelopeKind from
      // bundleInfo — apply the layers in order: unwrap (if any)
      // → gunzip (if tar.gz) → tar walker.
      var keySuffix = info.format === "tar.gz" ? TAR_GZ_KEY_SUFFIX : TAR_KEY_SUFFIX;
      var payload = await adapter.readFile(bundleId + keySuffix);
      try {
        // Layer 1 — unwrap envelope if present.
        if (info.envelopeKind === "recipient") {
          var rcp = vOpts.recipient !== undefined ? vOpts.recipient : recipient;
          if (!rcp) {
            return {
              ok: false, format: info.format, envelopeKind: info.envelopeKind,
              entryCount: 0, errors: ["backup/no-recipient-for-verify"],
            };
          }
          payload = archiveLazy().unwrap(payload, { recipient: rcp });
        } else if (info.envelopeKind === "passphrase") {
          var pp = vOpts.passphrase !== undefined ? vOpts.passphrase : passphrase;
          if (typeof pp !== "string" && !Buffer.isBuffer(pp)) {
            return {
              ok: false, format: info.format, envelopeKind: info.envelopeKind,
              entryCount: 0, errors: ["backup/no-passphrase-for-verify"],
            };
          }
          payload = await archiveLazy().unwrapWithPassphrase(payload, { passphrase: pp });
        }
        // Layer 2 — gunzip if tar.gz.
        var tarReader;
        if (info.format === "tar.gz") {
          var gzReader = archiveLazy().read.gz(archiveAdaptersLazy().buffer(payload), {
            maxDecompressedBytes: maxBundleBytes,
            maxExpansionRatio:    0,
          });
          tarReader = gzReader.asTar();
        } else {
          tarReader = archiveLazy().read.tar(archiveAdaptersLazy().buffer(payload));
        }
        // Layer 3 — walk the tar entries (inspect doesn't extract).
        var entries = await tarReader.inspect();
        return {
          ok:           true,
          format:       info.format,
          envelopeKind: info.envelopeKind,
          entryCount:   entries.length,
          errors:       [],
        };
      } catch (e) {
        return {
          ok:           false,
          format:       info.format,
          envelopeKind: info.envelopeKind,
          entryCount:   0,
          errors:       [e.code || e.message || String(e)],
        };
      }
    },
    // rewrapBundle(bundleId, opts) — v0.12.21 key rotation
    // without restore + rewrite. Unwraps the bundle under the old
    // key + re-wraps under the new key. Inner tar / tar.gz bytes
    // are never decompressed or rewritten. Operators rotating
    // recipient keypairs avoid the full restore-to-disk → rewrite
    // cycle. Returns `{ bundleId, oldEnvelopeKind, newEnvelopeKind,
    // bytesRewritten }`. Refuses cross-kind rotation (recipient ↔
    // passphrase) — that's a separate migration the operator
    // configures explicitly.
    // findBundles(predicate, opts?) — v0.12.24 query helper.
    // Iterates listBundles() + returns every entry where
    // predicate(entry) is truthy. Predicate sees the listBundles
    // shape: `{ bundleId, format, createdAt, size }` (size +
    // createdAt populated when opts.withStats === true).
    async findBundles(predicate, findOpts) {
      if (typeof predicate !== "function") {
        throw new BackupError("backup/bad-arg",
          "findBundles: predicate must be a function (entry) => boolean");
      }
      var list = await this.listBundles(findOpts || {});
      var out = [];
      for (var i = 0; i < list.length; i += 1) {
        if (predicate(list[i])) out.push(list[i]);
      }
      return out;
    },
    // cloneBundle(srcBundleId, dstBundleId, opts?) — v0.12.23
    // same-storage bundle clone. Copies the bundle's adapter
    // payload (bundle.tar / bundle.tar.gz / every directory key)
    // from src to dst WITHOUT touching the envelope or inner
    // archive. Useful before destructive operations (rewrap, key
    // rotation, schema migration) to preserve a known-good
    // snapshot under a distinct bundleId. opts.overwrite (default
    // false) gates whether to refuse if dstBundleId already
    // exists in storage.
    //
    // Returns `{ srcBundleId, dstBundleId, format, keysCopied,
    // bytesCopied }`.
    async cloneBundle(srcBundleId, dstBundleId, cloneOpts) {
      cloneOpts = cloneOpts || {};
      _ensureBundleId(srcBundleId);
      _ensureBundleId(dstBundleId);
      if (srcBundleId === dstBundleId) {
        throw new BackupError("backup/clone-same-id",
          "cloneBundle: srcBundleId === dstBundleId — refusing same-id clone");
      }
      var info = await this.bundleInfo(srcBundleId);
      var dstAlreadyExists = await this.hasBundle(dstBundleId);
      if (cloneOpts.overwrite !== true && dstAlreadyExists) {
        throw new BackupError("backup/clone-dst-exists",
          "cloneBundle: dstBundleId '" + dstBundleId + "' already exists; " +
          "pass opts.overwrite=true to replace");
      }
      // When overwrite=true, the
      // existence guard was the only protection but it didn't
      // delete the destination's existing keys before writing
      // the source keys. Stale-format bundles (dst=tar, src=
      // directory) ended up with BOTH the old tar key and the
      // new directory keys present — bundleInfo / readBundle
      // would resolve to the (still-existing) tar payload,
      // disagreeing with the reported clone result. Same applies
      // for directory→directory clones where the destination
      // had extra files not in source.
      //
      // Fix: when overwrite is enabled + the destination
      // already exists, call deleteBundle(dst) first to purge
      // every key under the destination's prefix so clone
      // semantics are actually replace-bytes.
      if (dstAlreadyExists && cloneOpts.overwrite === true) {
        await this.deleteBundle(dstBundleId);
      }
      var keysCopied = 0;
      var bytesCopied = 0;
      if (info.format === "tar" || info.format === "tar.gz") {
        var suffix = info.format === "tar.gz" ? TAR_GZ_KEY_SUFFIX : TAR_KEY_SUFFIX;
        var payload = await adapter.readFile(srcBundleId + suffix);
        await adapter.writeFile(dstBundleId + suffix, payload);
        keysCopied += 1;
        bytesCopied += payload.length;
      } else {
        // Directory format — walk every key under the source
        // bundleId + replicate under the destination prefix.
        var srcKeys = await adapter.listKeys(srcBundleId + "/");
        for (var ki = 0; ki < srcKeys.length; ki += 1) {
          var srcKey = srcKeys[ki];
          var rel = srcKey.slice((srcBundleId + "/").length);
          var keyBytes = await adapter.readFile(srcKey);
          await adapter.writeFile(dstBundleId + "/" + rel, keyBytes);
          keysCopied += 1;
          bytesCopied += keyBytes.length;
        }
      }
      return {
        srcBundleId:  srcBundleId,
        dstBundleId:  dstBundleId,
        format:       info.format,
        keysCopied:   keysCopied,
        bytesCopied:  bytesCopied,
      };
    },
    async rewrapBundle(bundleId, rwOpts) {
      rwOpts = rwOpts || {};
      _ensureBundleId(bundleId);
      var info = await this.bundleInfo(bundleId);
      if (info.format !== "tar" && info.format !== "tar.gz") {
        throw new BackupError("backup/format-not-wrappable",
          "rewrapBundle: '" + bundleId + "' has format=" + JSON.stringify(info.format) +
          " — only tar / tar.gz bundles carry wrap envelopes");
      }
      var rwKeySuffix = info.format === "tar.gz" ? TAR_GZ_KEY_SUFFIX : TAR_KEY_SUFFIX;
      var sealed = await adapter.readFile(bundleId + rwKeySuffix);
      var envelopeKind = info.envelopeKind;
      // When the adapter has no
      // readPartial capability, bundleInfo returns envelopeKind:
      // "unknown" rather than risk a full payload load. For
      // rewrap, we already have to load the payload (to unwrap),
      // so fall back to a sniffEnvelope on the loaded sealed
      // bytes — fixes the regression where adapters satisfying
      // the minimum contract couldn't use rewrapBundle.
      if (envelopeKind === "unknown") {
        envelopeKind = archiveLazy().sniffEnvelope(sealed);
      }
      if (envelopeKind !== "recipient" && envelopeKind !== "passphrase") {
        throw new BackupError("backup/no-envelope-to-rewrap",
          "rewrapBundle: '" + bundleId + "' carries envelopeKind=" +
          JSON.stringify(envelopeKind) + " — nothing to rewrap");
      }
      // Override the info.envelopeKind we use below so the
      // dispatch + return shape reflect the actual envelope we
      // detected (matters when bundleInfo returned "unknown").
      info = Object.assign({}, info, { envelopeKind: envelopeKind });
      var inner;
      if (info.envelopeKind === "recipient") {
        var oldRcp = rwOpts.oldRecipient !== undefined ? rwOpts.oldRecipient : recipient;
        if (!oldRcp) {
          throw new BackupError("backup/no-old-recipient",
            "rewrapBundle: opts.oldRecipient (or the storage's configured recipient) is required to unwrap");
        }
        if (!rwOpts.newRecipient || typeof rwOpts.newRecipient !== "object") {
          throw new BackupError("backup/no-new-recipient",
            "rewrapBundle: opts.newRecipient is required to re-seal under the rotated key");
        }
        inner = archiveLazy().unwrap(sealed, { recipient: oldRcp });
        var resealed = archiveLazy().wrap(inner, { recipient: rwOpts.newRecipient });
        await adapter.writeFile(bundleId + rwKeySuffix, resealed);
        return {
          bundleId:         bundleId,
          oldEnvelopeKind:  "recipient",
          newEnvelopeKind:  "recipient",
          bytesRewritten:   resealed.length,
        };
      }
      // passphrase
      var oldPass = rwOpts.oldPassphrase !== undefined ? rwOpts.oldPassphrase : passphrase;
      if (typeof oldPass !== "string" && !Buffer.isBuffer(oldPass)) {
        throw new BackupError("backup/no-old-passphrase",
          "rewrapBundle: opts.oldPassphrase (or the storage's configured passphrase) is required to unwrap");
      }
      if (typeof rwOpts.newPassphrase !== "string" && !Buffer.isBuffer(rwOpts.newPassphrase)) {
        throw new BackupError("backup/no-new-passphrase",
          "rewrapBundle: opts.newPassphrase is required (string or Buffer) to re-seal");
      }
      inner = await archiveLazy().unwrapWithPassphrase(sealed, { passphrase: oldPass });
      // Preserve the storage's
      // configured entropy floor across rewrap. The
      // writeBundle path raises the floor to 128 bits under
      // HIPAA / PCI-DSS postures (per
      // BACKUP_ENCRYPTION_REQUIRED_POSTURES); rewrapBundle MUST
      // apply the same floor so a rotated passphrase that
      // writeBundle would refuse can't slip through. The
      // operator's explicit rwOpts.passphraseMinEntropyBits
      // can raise the floor further but cannot lower it.
      var effectiveFloor = passphraseMinEntropyBits;                                  // storage's posture-effective floor
      if (typeof rwOpts.passphraseMinEntropyBits === "number" &&
          Number.isFinite(rwOpts.passphraseMinEntropyBits) &&
          rwOpts.passphraseMinEntropyBits > effectiveFloor) {
        effectiveFloor = Math.floor(rwOpts.passphraseMinEntropyBits);
      }
      var resealedP = await archiveLazy().wrapWithPassphrase(inner, {
        passphrase:     rwOpts.newPassphrase,
        minEntropyBits: effectiveFloor,
      });
      await adapter.writeFile(bundleId + rwKeySuffix, resealedP);
      return {
        bundleId:         bundleId,
        oldEnvelopeKind:  "passphrase",
        newEnvelopeKind:  "passphrase",
        bytesRewritten:   resealedP.length,
      };
    },
    // verifyAllBundles(opts?) — v0.12.20 batch integrity check.
    // Iterates listBundles() + calls verifyBundle on each. Returns
    // `{ total, ok, failed, results }` where `results` is an array
    // of per-bundle verifyBundle outputs. opts.concurrency caps the
    // parallelism (default 4 — gentle on the storage backend);
    // opts.stopOnFirstFailure short-circuits the walk when an
    // unhealthy bundle is found (default false — operators want
    // the full report). opts.recipient / opts.passphrase forwarded
    // to verifyBundle for each bundle.
    // rewrapAllBundles(opts) — v0.12.22 batch wrapper over the
    // v0.12.21 rewrapBundle primitive. Iterates listBundles() +
    // rewraps each through a bounded-parallel pool, skipping
    // plaintext / directory bundles cleanly. Returns
    // `{ total, rotated, skipped, failed, results }` where the
    // results array carries per-bundle `{ status: "rotated" |
    // "skipped" | "failed", ... }`. opts.concurrency /
    // opts.stopOnFirstFailure mirror verifyAllBundles.
    // opts.newRecipient / opts.newPassphrase /
    // opts.oldRecipient / opts.oldPassphrase forwarded to each
    // per-bundle rewrap.
    async rewrapAllBundles(opts) {
      opts = opts || {};
      var concurrency = 4;                                                            // default fan-out, not byte count
      if (typeof opts.concurrency === "number" && Number.isFinite(opts.concurrency) &&
          opts.concurrency > 0) {
        concurrency = Math.max(1, Math.floor(opts.concurrency));
      }
      var stopOnFirst = opts.stopOnFirstFailure === true;
      var list = await this.listBundles();
      var self = this;
      var results = [];
      var rotated = 0;
      var skipped = 0;
      var failed = 0;
      var pending = list.slice();
      var inflight = [];
      var aborted = false;
      function _spawn() {
        // Synchronously drain
        // non-wrappable entries inside _spawn until we hit one
        // that actually needs an async rewrap (or the pending
        // queue empties). The prior implementation returned
        // Promise.resolve() for skipped entries without adding
        // to inflight; if the first `concurrency` items were
        // all directory bundles, the warm-up drained pending
        // into the skipped bucket without spawning any inflight
        // workers + the drain loop exited immediately, leaving
        // the rest of the queue unprocessed.
        while (!aborted && pending.length > 0) {
          var entry = pending.shift();
          if (entry.format !== "tar" && entry.format !== "tar.gz") {
            results.push({
              bundleId:        entry.bundleId,
              status:          "skipped",
              reason:          "format-not-wrappable",
              oldEnvelopeKind: null,
              newEnvelopeKind: null,
            });
            skipped += 1;
            continue;                                                                 // try the next pending entry
          }
          return _spawnRewrap(entry);
        }
        return null;
      }
      function _spawnRewrap(entry) {
        var p = self.rewrapBundle(entry.bundleId, opts).then(function (r) {
          results.push(Object.assign({ status: "rotated" }, r));
          rotated += 1;
        }, function (err) {
          var code = (err && err.code) || (err && err.message) || String(err);
          if (/no-envelope-to-rewrap/.test(code)) {
            results.push({
              bundleId:        entry.bundleId,
              status:          "skipped",
              reason:          "no-envelope",
              oldEnvelopeKind: null,
              newEnvelopeKind: null,
            });
            skipped += 1;
          } else {
            results.push({
              bundleId:        entry.bundleId,
              status:          "failed",
              reason:          code,
              oldEnvelopeKind: null,
              newEnvelopeKind: null,
            });
            failed += 1;
            if (stopOnFirst) aborted = true;
          }
        });
        inflight.push(p);
        p.finally(function () {
          var idx = inflight.indexOf(p);
          if (idx !== -1) inflight.splice(idx, 1);
        });
        return p;
      }
      var ri;
      for (ri = 0; ri < concurrency; ri += 1) _spawn();
      while (inflight.length > 0) {
        await Promise.race(inflight.slice());
        if (!aborted && pending.length > 0 && inflight.length < concurrency) {
          while (inflight.length < concurrency && pending.length > 0) _spawn();
        }
      }
      results.sort(function (a, b) { return a.bundleId < b.bundleId ? 1 : -1; });
      return {
        total:    list.length,
        rotated:  rotated,
        skipped:  skipped,
        failed:   failed,
        results:  results,
      };
    },
    async verifyAllBundles(vOpts) {
      vOpts = vOpts || {};
      // Clamp fractional + zero
      // floors so a stray `0.5` doesn't spawn zero workers + return
      // a silent ok=0/failed=0 report on non-empty storage. Default
      // 4; minimum 1; non-finite / non-positive falls back to
      // default.
      var concurrency = 4;                                                            // default fan-out, not byte count
      if (typeof vOpts.concurrency === "number" && Number.isFinite(vOpts.concurrency) &&
          vOpts.concurrency > 0) {
        concurrency = Math.max(1, Math.floor(vOpts.concurrency));
      }
      var stopOnFirst = vOpts.stopOnFirstFailure === true;
      var list = await this.listBundles();
      var self = this;
      var results = [];
      var failed = 0;
      var ok = 0;
      var pending = list.slice();
      var inflight = [];
      var aborted = false;
      // Sequential bounded-parallel walk. Bring up `concurrency`
      // workers; each pulls the next bundleId until the queue is
      // empty or stopOnFirstFailure trips.
      function _spawn() {
        if (aborted) return null;
        if (pending.length === 0) return null;
        var entry = pending.shift();
        // Wrap each worker so any
        // verifyBundle rejection becomes a failed-result entry
        // rather than rejecting the whole batch. Without this, a
        // mid-walk failure (payload disappeared between listBundles
        // + readFile, network blip on object-store, etc.) would
        // throw out of Promise.race and abort verifyAllBundles
        // without returning the promised aggregate report.
        var promise = self.verifyBundle(entry.bundleId, {
          recipient:  vOpts.recipient,
          passphrase: vOpts.passphrase,
        }).then(function (r) {
          results.push(Object.assign({ bundleId: entry.bundleId }, r));
          if (r.ok) ok += 1;
          else {
            failed += 1;
            if (stopOnFirst) aborted = true;
          }
        }, function (err) {
          // Rejection path — convert to a failed-result entry so
          // the aggregate stays consistent.
          results.push({
            bundleId:     entry.bundleId,
            ok:           false,
            format:       null,
            envelopeKind: null,
            entryCount:   0,
            errors:       [err && err.code ? err.code : ((err && err.message) || String(err))],
          });
          failed += 1;
          if (stopOnFirst) aborted = true;
        });
        inflight.push(promise);
        promise.finally(function () {
          var idx = inflight.indexOf(promise);
          if (idx !== -1) inflight.splice(idx, 1);
        });
        return promise;
      }
      // Warm-up: spawn up to concurrency workers.
      var i;
      for (i = 0; i < concurrency; i += 1) _spawn();
      // Drain: as each worker resolves, spawn its replacement.
      while (inflight.length > 0) {
        await Promise.race(inflight.slice());
        if (!aborted && pending.length > 0 && inflight.length < concurrency) {
          while (inflight.length < concurrency && pending.length > 0) _spawn();
        }
      }
      // Sort results back to listBundles order for operator-
      // friendly output (concurrency reorders inflight completion).
      results.sort(function (a, b) { return a.bundleId < b.bundleId ? 1 : -1; });
      return {
        total:   list.length,
        ok:      ok,
        failed:  failed,
        results: results,
      };
    },
    // keyRotation(opts) — orchestrate a whole-repository key rotation:
    // rotate every bundle's envelope from the old key to the new key
    // (composing rewrapAllBundles), then re-read every rotated bundle
    // under the NEW key (composing verifyAllBundles) so a rotation
    // that silently corrupted a bundle surfaces as a failure rather
    // than a time-bomb the operator discovers at restore time. Emits
    // a `backup/key-rotated` audit event with the rotation id + the
    // per-status counts — key-rotation events are a compliance record
    // (SOC 2 CC6.1 / PCI DSS 3.6.4) operators wire into their chain.
    //
    // opts.newRecipient / opts.newPassphrase is the key bundles are
    // rotated TO (required, matched to the storage's cryptoStrategy);
    // opts.oldRecipient / opts.oldPassphrase unwraps the current
    // envelope when it differs from the storage's configured key.
    // opts.verify (default true) runs the post-rotation read-back;
    // opts.concurrency / opts.stopOnFirstFailure forward to the
    // batch passes. opts.dualWrap is deferred-with-condition — a true
    // overlap window where BOTH the old and new key decrypt a bundle
    // needs multi-recipient envelopes (b.archive.wrap currently wraps
    // to a single recipient); it re-opens when the wrap layer gains
    // multi-recipient support. Until then operators stage a rotation
    // by keeping the old key available to readers until keyRotation
    // reports `failed: 0` + `verifyFailed: 0`, then retiring it.
    async keyRotation(opts) {
      opts = opts || {};
      if (opts.dualWrap === true) {
        throw new BackupError("backup/dual-wrap-unsupported",
          "keyRotation: dualWrap (simultaneous old+new key validity) requires multi-recipient " +
          "archive envelopes, which b.archive.wrap does not yet emit; rotate sequentially and " +
          "keep the old key available to readers until keyRotation reports failed: 0 + verifyFailed: 0");
      }
      if (cryptoStrategy === "none") {
        throw new BackupError("backup/no-envelope-to-rewrap",
          "keyRotation: storage cryptoStrategy is \"none\" — there is no envelope key to rotate");
      }
      if (cryptoStrategy === "recipient" &&
          (!opts.newRecipient || typeof opts.newRecipient !== "object")) {
        throw new BackupError("backup/no-recipient",
          "keyRotation: cryptoStrategy \"recipient\" requires opts.newRecipient (the key to rotate to)");
      }
      if (cryptoStrategy === "passphrase" &&
          !(typeof opts.newPassphrase === "string" || Buffer.isBuffer(opts.newPassphrase))) {
        throw new BackupError("backup/bad-passphrase",
          "keyRotation: cryptoStrategy \"passphrase\" requires opts.newPassphrase (string or Buffer)");
      }

      var rotatedAt = new Date().toISOString();
      var rotationId = "rotation-" + rotatedAt;

      var rotate = await this.rewrapAllBundles(opts);

      // Post-rotation read-back under the NEW key. Skip only when the
      // operator opts out; default proves the rotation landed.
      var verify = null;
      if (opts.verify !== false) {
        var verifyOpts = {
          concurrency:       opts.concurrency,
          stopOnFirstFailure: opts.stopOnFirstFailure,
        };
        if (cryptoStrategy === "recipient") verifyOpts.recipient = opts.newRecipient;
        else verifyOpts.passphrase = opts.newPassphrase;
        verify = await this.verifyAllBundles(verifyOpts);
      }

      var verifyFailed = verify ? verify.failed : 0;
      var outcome = (rotate.failed === 0 && verifyFailed === 0) ? "success" : "failure";
      try {
        audit().safeEmit({
          action:   "backup/key-rotated",
          outcome:  outcome,
          metadata: {
            rotationId:     rotationId,
            cryptoStrategy: cryptoStrategy,
            total:          rotate.total,
            rotated:        rotate.rotated,
            skipped:        rotate.skipped,
            failed:         rotate.failed,
            verified:       verify ? verify.ok : null,
            verifyFailed:   verifyFailed,
          },
        });
      } catch (_e) { /* audit best-effort — drop-silent */ }

      return {
        rotationId:   rotationId,
        rotatedAt:    rotatedAt,
        total:        rotate.total,
        rotated:      rotate.rotated,
        skipped:      rotate.skipped,
        failed:       rotate.failed,
        verified:     verify ? verify.ok : null,
        verifyFailed: verifyFailed,
        rotateResults: rotate.results,
        verifyResults: verify ? verify.results : null,
      };
    },
    // bundleInfo(bundleId) — v0.12.17 per-bundle introspection.
    // Returns `{ bundleId, format, envelopeKind, sizeBytes }`.
    // `format` is one of `"tar"` / `"tar.gz"` / `"directory"`
    // inferred from the storage layout (no byte read).
    // `envelopeKind` is the result of a 5-byte magic probe on the
    // bundle payload — `"recipient"` (BAWRP) / `"passphrase"`
    // (BAWPP) / `"none"` (plaintext). `sizeBytes` is the payload
    // byte count for tar / tar.gz; null for directory format
    // (operator's per-file walk if exact size matters).
    //
    // Instance method — wiki page documents this under the
    // bundleAdapterStorage primitive rather than as a top-level
    // b.X primitive.
    async bundleInfo(bundleId) {
      _ensureBundleId(bundleId);
      var tarKey = bundleId + TAR_KEY_SUFFIX;
      var tarGzKey = bundleId + TAR_GZ_KEY_SUFFIX;
      var manifestKey = bundleId + "/manifest.json";
      var fmt = null;
      var payloadKey = null;
      if (await adapter.hasKey(tarGzKey)) {
        fmt = "tar.gz"; payloadKey = tarGzKey;
      } else if (await adapter.hasKey(tarKey)) {
        fmt = "tar"; payloadKey = tarKey;
      } else if (await adapter.hasKey(manifestKey)) {
        fmt = "directory";
      } else {
        throw new BackupError("backup/bundle-not-found",
          "bundleInfo: '" + bundleId + "' not in storage");
      }
      var envelopeKind = "none";
      var sizeBytes = null;
      var createdAt = null;
      // Directory-format bundles
      // leave payloadKey null but DO have a manifest.json that
      // statKey can read. For createdAt parity with
      // listBundles({ withStats }), stat the manifest in the
      // directory case so the bundleInfo return shape is
      // populated identically across formats.
      if (payloadKey === null && fmt === "directory" &&
          typeof adapter.statKey === "function") {
        // Stat the manifest.json so directory-format bundles
        // populate createdAt + sizeBytes identically to how
        // listBundles({ withStats }) reports them. NOTE: sizeBytes
        // is the manifest's size here, not the total file-tree
        // payload (operators wanting the true total walk
        // per-file keys themselves) — same convention as
        // listBundles({ withStats }) for parity.
        var dirSt = await adapter.statKey(manifestKey);
        if (dirSt && typeof dirSt.size === "number") sizeBytes = dirSt.size;
        if (dirSt && typeof dirSt.mtimeMs === "number") {
          createdAt = new Date(dirSt.mtimeMs).toISOString();
        }
      }
      if (payloadKey !== null) {
        // Claim was a 5-byte magic
        // probe; the implementation was reading the entire bundle
        // into memory. For multi-GB bundles, an administrative
        // metadata call would allocate the whole payload and put
        // memory pressure on the host. Prefer the adapter's
        // optional `readPartial(key, length)` capability for the
        // probe. fsAdapter + objectStoreAdapter both expose it as
        // of v0.12.17; legacy adapters without it fall back to a
        // capped 16-byte readFile via the fallback path (still
        // bounded; better than full payload).
        if (typeof adapter.readPartial === "function") {
          var probe = await adapter.readPartial(payloadKey, 16);                      // 16-byte probe head, magic comparison
          envelopeKind = archiveLazy().sniffEnvelope(probe);
        } else {
          // Legacy adapter — readPartial missing. Operators using
          // a custom adapter without the capability get
          // envelopeKind: "unknown" rather than an OOM risk. They
          // can probe themselves by reading the first N bytes via
          // their own client.
          envelopeKind = "unknown";
        }
        // sizeBytes is reported via a stat-like path when the
        // adapter exposes one; otherwise stays null. fsAdapter +
        // objectStoreAdapter expose `statKey`.
        if (typeof adapter.statKey === "function") {
          var st = await adapter.statKey(payloadKey);
          if (st && typeof st.size === "number") sizeBytes = st.size;
          if (st && typeof st.mtimeMs === "number") createdAt = new Date(st.mtimeMs).toISOString();
        }
      }
      return {
        bundleId:     bundleId,
        format:       fmt,
        envelopeKind: envelopeKind,
        sizeBytes:    sizeBytes,
        createdAt:    createdAt,
      };
    },
    async deleteBundle(bundleId) {
      _ensureBundleId(bundleId);
      var keys = await adapter.listKeys(bundleId + "/");
      for (var i = 0; i < keys.length; i += 1) {
        await adapter.deleteKey(keys[i]);
      }
    },
    async hasBundle(bundleId) {
      _ensureBundleId(bundleId);
      // Format-aware: check the storage layout's marker key. Tar
      // bundles store under <bid>/bundle.tar; tar.gz bundles store
      // under <bid>/bundle.tar.gz; directory bundles store under
      // <bid>/manifest.json. Operators with a mixed bundle set
      // (some tar, some tar.gz, some directory) get true for any.
      var tarKey = bundleId + TAR_KEY_SUFFIX;
      var tarGzKey = bundleId + TAR_GZ_KEY_SUFFIX;
      var dirKey = bundleId + "/manifest.json";
      if (await adapter.hasKey(tarKey)) return true;
      if (await adapter.hasKey(tarGzKey)) return true;
      if (await adapter.hasKey(dirKey)) return true;
      return false;
    },
  };
}

// fsAdapter — default adapter for bundleAdapterStorage backed by the
// local filesystem. Provides the same on-disk layout as diskStorage
// (bundle directories under a root path) but via the adapter contract
// so v0.12.8+ can swap the implementation transparently.
bundleAdapterStorage.fsAdapter = function (fsOpts) {
  fsOpts = fsOpts || {};
  validateOpts.requireNonEmptyString(fsOpts.root,
    "bundleAdapterStorage.fsAdapter: opts.root", BackupError, "backup/no-storage-root");
  var root = fsOpts.root;
  atomicFile.ensureDir(root);

  function _keyPath(key) {
    // Refuse keys with traversal segments — defense in depth even
    // though the storage layer also checks.
    if (key.indexOf("..") !== -1 || key.indexOf("\0") !== -1) {
      throw new BackupError("backup/bad-key",
        "fsAdapter: key contains invalid characters: " + JSON.stringify(key));
    }
    return nodePath.join(root, key);
  }

  return {
    async writeFile(key, bytes) {
      var path = _keyPath(key);
      atomicFile.ensureDir(nodePath.dirname(path));
      // mode 0o600 matches the v0.12.9 directory-format readback
      // discipline — backup payloads carry operator-owned bytes
      // (potentially PHI / PCI / GDPR-scoped); owner-only is the
      // strict posture. Overwrite of an existing key stays allowed
      // (operators legitimately rewrite the same key, e.g. resuming a
      // multipart upload); upper layers (writeBundle's `bundle-exists`
      // check) enforce no-overwrite at the bundle level. writeSync's
      // atomic rename preserves that overwrite semantic while refusing a
      // symlink pre-planted at `path` (CWE-59) and never leaving a torn
      // payload — a bare writeFileSync did both.
      atomicFile.writeSync(path, bytes, { fileMode: 0o600 });
    },
    async readFile(key) {
      var path = _keyPath(key);
      // Capped fd-bound read (no existsSync check-then-read window): fetches a
      // whole bundle payload, so an oversize/swapped file is an OOM lever. 8 GiB
      // matches the writeBundle maxBundleBytes ceiling.
      return atomicFile.fdSafeReadSync(path, {
        maxBytes: C.BYTES.gib(8),
        errorFor: function (kind) {
          if (kind === "enoent") return new BackupError("backup/no-key", "fsAdapter: key not found: " + JSON.stringify(key));
          if (kind === "too-large") return new BackupError("backup/key-too-large", "fsAdapter: payload for key " + JSON.stringify(key) + " exceeds the read cap");
          return new BackupError("backup/no-key", "fsAdapter: key " + JSON.stringify(key) + " unreadable: " + kind);
        },
      });
    },
    async listKeys(prefix) {
      var out = [];
      if (!nodeFs.existsSync(root)) return out;
      function _walk(rel) {
        var entries = nodeFs.readdirSync(nodePath.join(root, rel || "."), { withFileTypes: true });
        for (var i = 0; i < entries.length; i += 1) {
          var name = entries[i].name;
          var nextRel = rel ? (rel + "/" + name) : name;
          if (entries[i].isDirectory()) {
            _walk(nextRel);
          } else if (entries[i].isFile()) {
            if (!prefix || nextRel.indexOf(prefix) === 0) {
              out.push(nextRel);
            }
          }
        }
      }
      _walk("");
      return out;
    },
    async deleteKey(key) {
      var path = _keyPath(key);
      try { nodeFs.rmSync(path); } catch (_e) { /* drop-silent — key already gone */ }
    },
    async hasKey(key) {
      try { return nodeFs.existsSync(_keyPath(key)); }
      catch (_e) { return false; }
    },
    // v0.12.17 — optional capabilities consumed by bundleInfo.
    // readPartial: open + read up to `length` bytes from the start
    // of the file without materializing the whole payload.
    // Bundle-info's envelope probe needs at most 16 bytes — the
    // partial read keeps multi-GB bundle metadata cheap.
    async readPartial(key, length) {
      // CodeQL js/file-system-race + js/insecure-temporary-file —
      // drop the existsSync probe (TOCTOU) and the default mode on
      // open. Use openSync with explicit owner-only mode + handle
      // ENOENT atomically; the system call is itself the existence
      // check.
      var p = _keyPath(key);
      var fd;
      try {
        fd = nodeFs.openSync(p, "r", 0o600);
      } catch (e) {
        if (e && e.code === "ENOENT") {
          throw new BackupError("backup/no-key",
            "fsAdapter.readPartial: key not found: " + JSON.stringify(key));
        }
        throw e;
      }
      try {
        var buf = Buffer.alloc(length);
        var bytesRead = nodeFs.readSync(fd, buf, 0, length, 0);
        return buf.slice(0, bytesRead);
      } finally {
        try { nodeFs.closeSync(fd); } catch (_e) { /* drop-silent */ }
      }
    },
    async statKey(key) {
      var p = _keyPath(key);
      if (!nodeFs.existsSync(p)) return null;
      var st = nodeFs.statSync(p);
      return { size: st.size, mtimeMs: st.mtimeMs };
    },
  };
};

// ---- objectStoreAdapter ----------------------------------------

/**
 * @primitive b.backup.bundleAdapterStorage.objectStoreAdapter
 * @signature b.backup.bundleAdapterStorage.objectStoreAdapter(client, opts?)
 * @since     0.12.13
 * @status    stable
 * @related   b.backup.bundleAdapterStorage, b.objectStore
 *
 * Wraps a `b.objectStore`-shaped client into the
 * `{ writeFile, readFile, listKeys, deleteKey, hasKey }` adapter
 * contract that `bundleAdapterStorage` consumes. The client must
 * expose `put(key, body) → Promise<{ size }>`, `get(key) →
 * Promise<Buffer>`, `head(key) → Promise<{ size, ... }>`,
 * `delete(key) → Promise<boolean>`, and `list(prefix, opts?) →
 * Promise<{ items: [{ key, size, ... }], truncated }>` — the
 * shape produced by `b.objectStore.buildBackend({ protocol: ... })`
 * for the local / SigV4 / GCS / Azure-Blob backends.
 *
 * `opts.prefix` namespaces every key under a fixed root inside the
 * bucket — operators sharing a bucket across multiple deployments
 * pass distinct prefixes so listings stay scoped.
 *
 * `opts.list` is the operator-tunable `{ maxResults, ... }` pass-
 * through forwarded to the underlying `client.list` call (defaults
 * to whatever the backend's `list` defaults to — typically 1000).
 *
 * Closes the v0.12.10 deferral: "S3 / MinIO / Azure / GCS-backed
 * backups" promised since v0.11.2 JSDoc.
 *
 * @opts
 *   prefix:  string,    // namespace every key under this prefix in the bucket
 *   list:    { maxResults: number },   // forwarded to client.list opts
 *
 * @example
 *   var client = b.objectStore.buildBackend({
 *     protocol: "local",
 *     rootDir:  "/var/backups",
 *   });
 *   var storage = b.backup.bundleAdapterStorage({
 *     adapter:        b.backup.bundleAdapterStorage.objectStoreAdapter(client),
 *     format:         "tar.gz",
 *     cryptoStrategy: "recipient",
 *     recipient:      pair,
 *   });
 *   // bundle bytes hit the object-store backend's put(); restore
 *   // path composes through unwrap + read.gz + read.tar.
 */
bundleAdapterStorage.objectStoreAdapter = function (client, osOpts) {
  validateOpts.requireMethods(client, ["put", "get", "head", "delete", "list"],
    "objectStoreAdapter: client", BackupError, "backup/bad-adapter");
  osOpts = osOpts || {};
  var prefix = "";
  if (osOpts.prefix !== undefined && osOpts.prefix !== null) {
    if (typeof osOpts.prefix !== "string") {
      throw new BackupError("backup/bad-arg",
        "objectStoreAdapter: opts.prefix must be a string");
    }
    if (osOpts.prefix.indexOf("..") !== -1 || osOpts.prefix.indexOf("\u0000") !== -1) {
      throw new BackupError("backup/bad-arg",
        "objectStoreAdapter: opts.prefix contains traversal segment or NUL byte");
    }
    // Strip trailing slashes without a backtracking regex (CodeQL
    // js/polynomial-redos flagged `/\/+$/`, which is linear in
    // practice but flagged conservatively). Walk back from the end
    // and slice once.
    var endIdx = osOpts.prefix.length;
    while (endIdx > 0 && osOpts.prefix.charCodeAt(endIdx - 1) === 0x2f) endIdx -= 1;  // 0x2f = "/"
    prefix = osOpts.prefix.slice(0, endIdx);
    if (prefix.length > 0) prefix += "/";
  }
  var listOpts = osOpts.list || {};

  function _scopedKey(key) {
    if (typeof key !== "string" || key.length === 0) {
      throw new BackupError("backup/bad-key",
        "objectStoreAdapter: key must be a non-empty string");
    }
    if (key.indexOf("..") !== -1 || key.indexOf("\u0000") !== -1) {
      throw new BackupError("backup/bad-key",
        "objectStoreAdapter: key contains traversal segment or NUL byte");
    }
    return prefix + key;
  }

  return {
    async writeFile(key, bytes) {
      if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
        throw new BackupError("backup/bad-arg",
          "objectStoreAdapter.writeFile: bytes must be a Buffer or Uint8Array");
      }
      await client.put(_scopedKey(key), Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
    },
    async readFile(key) {
      var scoped = _scopedKey(key);
      try {
        var body = await client.get(scoped);
        return Buffer.isBuffer(body) ? body : Buffer.from(body);
      } catch (e) {
        // b.objectStore surfaces NOT_FOUND via the framework's
        // err.code === "NOT_FOUND" convention — translate to the
        // backup adapter contract's no-key error.
        if (e && (e.code === "NOT_FOUND" || e.statusCode === 404 || /NOT_FOUND|not found/i.test(e.message || ""))) {
          throw new BackupError("backup/no-key",
            "objectStoreAdapter: key not found: " + JSON.stringify(key));
        }
        throw e;
      }
    },
    async listKeys(keyPrefix) {
      // _scopedKey rejects empty strings; for list(prefix) we want
      // to allow listing the whole bundle root. Compose the
      // prefix manually so `listKeys("")` enumerates everything
      // under the operator-supplied namespace.
      var realScoped = prefix + (keyPrefix || "");
      // Object-store backends page
      // results (default 1000 keys). Without continuation, listKeys
      // silently dropped bundles past page 1 — listBundles missed
      // them, deleteBundle skipped them. Follow the
      // truncated / continuationToken contract until every page
      // is consumed. PAGINATION_CAP guards against a runaway
      // server returning truncated:true forever (defense-in-depth;
      // shipped backends honour the contract).
      var PAGINATION_CAP = 1000;                                                      // page count cap, not byte count
      var out = [];
      var token = null;
      var pages = 0;
      do {
        var pageOpts = Object.assign({}, listOpts);
        if (token) pageOpts.continuationToken = token;
        var result = await client.list(realScoped, pageOpts);
        var items = result && result.items ? result.items : (Array.isArray(result) ? result : []);
        for (var i = 0; i < items.length; i += 1) {
          var k = typeof items[i] === "string" ? items[i] : items[i].key;
          if (typeof k !== "string") continue;
          if (prefix.length > 0 && k.indexOf(prefix) === 0) {
            out.push(k.slice(prefix.length));
          } else {
            out.push(k);
          }
        }
        token = result && result.continuationToken ? result.continuationToken : null;
        if (!result || result.truncated !== true) break;
        if (!token) break;                                                            // truncated:true without continuationToken — stop to avoid spin
        pages += 1;
        if (pages > PAGINATION_CAP) {
          throw new BackupError("backup/list-pagination-runaway",
            "objectStoreAdapter.listKeys: backend returned >" + PAGINATION_CAP +
            " pages without exhausting; refusing to spin (operator should narrow the prefix or raise opts.list.maxResults)");
        }
      } while (true);
      return out;
    },
    async deleteKey(key) {
      try {
        await client.delete(_scopedKey(key));
      } catch (e) {
        // drop-silent on NOT_FOUND — adapter contract is idempotent
        // delete (fsAdapter same shape).
        if (e && (e.code === "NOT_FOUND" || e.statusCode === 404 || /NOT_FOUND|not found/i.test(e.message || ""))) {
          return;
        }
        throw e;
      }
    },
    async hasKey(key) {
      try {
        await client.head(_scopedKey(key));
        return true;
      } catch (e) {
        if (e && (e.code === "NOT_FOUND" || e.statusCode === 404 || /NOT_FOUND|not found/i.test(e.message || ""))) {
          return false;
        }
        throw e;
      }
    },
    // v0.12.17 — readPartial uses the b.objectStore client's range
    // capability (every shipped backend honours `{ range: [start,
    // end] }` per the client contract). bundleInfo's envelope probe
    // reads 16 bytes regardless of bundle size.
    async readPartial(key, length) {
      var scoped = _scopedKey(key);
      try {
        var body = await client.get(scoped, { range: [0, Math.max(0, length - 1)] });
        var buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
        return buf.slice(0, length);
      } catch (e) {
        if (e && (e.code === "NOT_FOUND" || e.statusCode === 404 || /NOT_FOUND|not found/i.test(e.message || ""))) {
          throw new BackupError("backup/no-key",
            "objectStoreAdapter.readPartial: key not found: " + JSON.stringify(key));
        }
        throw e;
      }
    },
    async statKey(key) {
      try {
        var meta = await client.head(_scopedKey(key));
        if (!meta || typeof meta.size !== "number") return null;
        return { size: meta.size, mtimeMs: meta.lastModified || null };
      } catch (e) {
        if (e && (e.code === "NOT_FOUND" || e.statusCode === 404 || /NOT_FOUND|not found/i.test(e.message || ""))) {
          return null;
        }
        throw e;
      }
    },
  };
};

// ---- migrate ----------------------------------------------------

/**
 * @primitive b.backup.migrate
 * @signature b.backup.migrate(opts)
 * @since     0.12.8
 * @status    stable
 * @related   b.backup.bundleAdapterStorage
 *
 * One-shot helper that walks an operator's directory-tree-format
 * bundle (v0.12.7 layout) and writes the same content as a tar-format
 * bundle via the v0.12.8 `bundleAdapterStorage`. Idempotent: re-
 * running on an already-migrated bundle is a no-op. Source stays in
 * place by default; operators with explicit transition windows opt
 * into the inline replace via `deleteSourceOnSuccess: true`.
 *
 * @opts
 *   from:                    bundleAdapterStorage with format: "directory",
 *   to:                      bundleAdapterStorage with format: "tar",
 *   bundleId:                string  (single-bundle migrate; omit to migrate all),
 *   deleteSourceOnSuccess:   boolean (default false; explicit opt-in),
 *
 * @example
 *   var from = b.backup.bundleAdapterStorage({
 *     adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: "/var/backups-v7" }),
 *     format:  "directory",
 *   });
 *   var to = b.backup.bundleAdapterStorage({
 *     adapter: b.backup.bundleAdapterStorage.fsAdapter({ root: "/var/backups-v8" }),
 *     format:  "tar",
 *   });
 *   await b.backup.migrate({ from: from, to: to });
 */
async function migrate(opts) {
  opts = opts || {};
  if (!opts.from || typeof opts.from.readBundle !== "function" ||
      typeof opts.from.listBundles !== "function") {
    throw new BackupError("backup/bad-from",
      "migrate: opts.from must be a storage backend (got " + typeof opts.from + ")");
  }
  if (!opts.to || typeof opts.to.writeBundle !== "function" ||
      typeof opts.to.hasBundle !== "function") {
    throw new BackupError("backup/bad-to",
      "migrate: opts.to must be a storage backend (got " + typeof opts.to + ")");
  }
  var ids;
  if (opts.bundleId) {
    if (!_isValidBundleId(opts.bundleId)) {
      throw new BackupError("backup/bad-bundle-id",
        "migrate: bundleId must match the framework's timestamp+suffix format");
    }
    ids = [opts.bundleId];
  } else {
    var list = await opts.from.listBundles();
    ids = list.map(function (b) { return b.bundleId; });
  }
  var migrated = 0;
  var skipped = 0;
  for (var i = 0; i < ids.length; i += 1) {
    var bid = ids[i];
    // Idempotency: skip if destination already has the bundle.
    if (await opts.to.hasBundle(bid)) {
      skipped += 1;
      continue;
    }
    // Stage source-bundle into a tmp dir, then write via destination.
    var tmpDir = nodeFs.mkdtempSync(nodePath.join(os.tmpdir(),
      "blamejs-backup-migrate-" + bid + "-"));
    var stageDir = nodePath.join(tmpDir, "bundle");
    try {
      await opts.from.readBundle(bid, stageDir);
      await opts.to.writeBundle(bid, stageDir);
      migrated += 1;
      if (opts.deleteSourceOnSuccess === true) {
        if (typeof opts.from.deleteBundle === "function") {
          await opts.from.deleteBundle(bid);
        }
      }
    } finally {
      try { nodeFs.rmSync(tmpDir, { recursive: true, force: true }); }
      catch (_e) { /* drop-silent */ }
    }
  }
  return { migrated: migrated, skipped: skipped, total: ids.length };
}


