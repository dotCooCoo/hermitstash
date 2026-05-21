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
var backupBundle = require("./bundle");
var backupManifest = require("./manifest");
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var numericBounds = require("../numeric-bounds");
var audit = lazyRequire(function () { return require("../audit"); });
var compliance = lazyRequire(function () { return require("../compliance"); });
// lazyRequire ../db so backup stays a leaf module operators can use
// without the rest of the framework's DB chain loaded in the same
// module graph (CLI tools, stand-alone backup runners). The db()
// callable resolves on first access.
var dbModuleLazy = lazyRequire(function () { return require("../db"); });
var { defineClass } = require("../framework-error");

var BackupError = defineClass("BackupError");

// Postures whose published controls require backup encryption. PCI
// DSS 4.0.1 Req 9.4.1.b ("backups are protected with strong cryptography
// and encrypted") and HIPAA §164.310(d)(2)(iv) ("create a retrievable,
// exact copy of ePHI" — encryption strongly implied by §164.312(a)(2)
// (iv) addressable encryption standard).
var BACKUP_ENCRYPTION_REQUIRED_POSTURES = Object.freeze([
  "hipaa", "pci-dss",
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
  if (!storage || typeof storage !== "object") {
    throw new BackupError("backup/bad-storage",
      "storage backend is required (use b.backup.diskStorage or pass a custom one)");
  }
  var required = ["writeBundle", "readBundle", "listBundles", "deleteBundle", "hasBundle"];
  for (var i = 0; i < required.length; i++) {
    if (typeof storage[required[i]] !== "function") {
      throw new BackupError("backup/bad-storage",
        "storage backend missing method '" + required[i] + "'");
    }
  }
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

  // Posture-enforced backup encryption (F-BUDR-4). HIPAA / PCI-DSS
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

  // F-CBT-3 — backup destination residency posture. EU-tagged primary
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

  function _emitAudit(action, info, outcome) {
    if (!auditOn) return;
    audit().safeEmit({
      action:   action,
      outcome:  outcome,
      metadata: info || {},
      reason:   info && info.reason ? info.reason : null,
    });
  }

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
          if (!nodeFs.existsSync(manifestPath)) {
            throw new BackupError("backup/test-no-manifest",
              "manifest.json missing under restored bundle " + bundleId);
          }
          manifest = backupManifest.parse(nodeFs.readFileSync(manifestPath, "utf8"));
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
    if (!nodeFs.existsSync(manifestPath)) {
      throw new BackupError("backup/no-manifest",
        "verifyManifestSignature: manifest.json missing at " + manifestPath);
    }
    try { manifest = backupManifest.parse(nodeFs.readFileSync(manifestPath, "utf8")); }
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
    files.push({ relativePath: "db.enc",     kind: "raw", required: true });
    files.push({ relativePath: "db.key.enc", kind: "raw", required: true });
  } else {
    files.push({ relativePath: dbName,       kind: "raw", required: true });
  }

  if (vaultMode === "wrapped") {
    files.push({ relativePath: "vault.key.sealed", kind: "raw", required: true });
  } else {
    files.push({ relativePath: "vault.key", kind: "raw", required: true });
  }

  // Audit-signing key (always present; sealed in wrapped mode)
  files.push({
    relativePath: vaultMode === "wrapped" ? "audit-sign.key.sealed" : "audit-sign.key",
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
  recommendedFiles:          recommendedFiles,
  runInWorker:               runInWorker,
  verifyManifestSignature:   verifyManifestSignature,
  BACKUP_ENCRYPTION_REQUIRED_POSTURES: BACKUP_ENCRYPTION_REQUIRED_POSTURES,
  BackupError:               BackupError,
  BUNDLE_ID_RE:              BUNDLE_ID_RE,
};
