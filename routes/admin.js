/**
 * Admin domain routes — every endpoint gated by requireAdmin middleware.
 *
 * This is a large multi-domain surface (deliberately kept in one file per
 * CLAUDE.md Rule 5: routes live in existing files that own the domain, and
 * the "admin" domain spans the full management surface). Sub-domains covered:
 *   - Dashboard + activity / file / bundle / blocklist / task inspection
 *   - Settings (site config) and environment introspection
 *   - Backup, restore, and manifest browsing
 *   - Export (users, files, audit)
 *   - Logo upload and removal (SVG sanitized via lib/sanitize-svg)
 *   - mTLS CA status, regeneration, and enforcement toggle
 *   - API key issuance, revocation, and cert enrollment
 *   - Webhook CRUD and delivery inspection
 *   - Team management (members, invites, revocation)
 *   - Sync-client registry + remote trigger
 *
 * Heavier business logic lives in app/domain/admin/*.service.js — this file
 * is intentionally thin glue: parseJson → validator → service → send.
 * When a sub-domain outgrows that shape, extract a service; don't fatten
 * the route handler.
 */
var fs = require("fs");
var path = require("path");
var audit = require("../lib/audit");
var { PATHS } = require("../lib/constants");
var logger = require("../app/shared/logger");
var config = require("../lib/config");
var usersRepo = require("../app/data/repositories/users.repo");
var filesRepo = require("../app/data/repositories/files.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var auditRepo = require("../app/data/repositories/audit.repo");
var blockedIpsRepo = require("../app/data/repositories/blockedIps.repo");
var credentialsRepo = require("../app/data/repositories/credentials.repo");
var apiKeysRepo = require("../app/data/repositories/apiKeys.repo");
var webhooksRepo = require("../app/data/repositories/webhooks.repo");
var teamsRepo = require("../app/data/repositories/teams.repo");
var { parseJson, parseMultipart } = require("../lib/multipart");
var { hashPassword, generateToken, sha3Hash } = require("../lib/crypto");
var mtlsCa = require("../lib/mtls-ca");
var syncRegistry = require("../lib/sync-registry");
var storage = require("../lib/storage");
var requireAdmin = require("../middleware/require-admin");
var { send, host } = require("../middleware/send");
var adminValidator = require("../app/http/validators/admin.validator");
var exportService = require("../app/domain/admin/export.service");
var settingsService = require("../app/domain/admin/settings.service");
var sessionService = require("../app/domain/auth/session.service");
var { validateEmail, validatePassword } = require("../app/shared/validate");
var stashRepo = require("../app/data/repositories/stash.repo");
var S3Client = require("../lib/s3-client");
var backup = require("../lib/backup");
var { getQuotaCounts } = require("../lib/email");
var scheduler = require("../lib/scheduler");
var { sanitizeSvg } = require("../lib/sanitize-svg");

// Recursive sum of all file sizes under `dir`. Used by the dashboard to report
// real on-disk storage including chunks, orphan files, and empty bundle dirs that
// aren't represented in the file table. Returns 0 if dir is missing/unreadable.
function walkDiskUsage(dir) {
  if (!fs.existsSync(dir)) return 0;
  var total = 0;
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_e) { return 0; }
  for (var i = 0; i < entries.length; i++) {
    var full = path.join(dir, entries[i].name);
    if (entries[i].isDirectory()) {
      total += walkDiskUsage(full);
    } else if (entries[i].isFile()) {
      try { total += fs.statSync(full).size; } catch (_e) { /* file may have been removed between readdir and stat */ }
    }
  }
  return total;
}

// Dashboard renders need diskUsage, but the walk is O(n_files) and synchronous.
// On installs with tens of thousands of files this stalled the admin page.
// Use a 5-minute TTL cache with lazy background refresh: the first request
// seeds the cache, subsequent requests read the cached number and kick off a
// fresh walk in the background when the TTL expires.
var _diskUsageCache = { bytes: 0, computedAt: 0, computing: false };
var DISK_USAGE_TTL_MS = 5 * 60 * 1000;

function refreshDiskUsageAsync(dir) {
  if (_diskUsageCache.computing) return;
  _diskUsageCache.computing = true;
  setImmediate(function () {
    try {
      _diskUsageCache.bytes = walkDiskUsage(dir);
      _diskUsageCache.computedAt = Date.now();
    } finally {
      _diskUsageCache.computing = false;
    }
  });
}

function diskUsage(dir) {
  var now = Date.now();
  var stale = now - _diskUsageCache.computedAt > DISK_USAGE_TTL_MS;
  if (_diskUsageCache.computedAt === 0) {
    // First call — do a synchronous walk so the dashboard has a real number
    // on initial render. Subsequent stale-refreshes run in the background.
    _diskUsageCache.bytes = walkDiskUsage(dir);
    _diskUsageCache.computedAt = now;
  } else if (stale) {
    refreshDiskUsageAsync(dir);
  }
  return _diskUsageCache.bytes;
}

module.exports = function (app) {
  // Admin dashboard
  app.get("/admin", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var totalUsers = usersRepo.count({});

    // Live files: exclude tombstones (storagePath cleared, deletedAt set), in-progress
    // chunked uploads, and vault-encrypted system files. Tombstones still carry their
    // pre-delete `size` on the record — counting them inflates the displayed storage and
    // hides the discrepancy between this dashboard and the storage migration preview.
    var liveFiles = filesRepo.findAll({ status: { $ne: "chunking" }, vaultEncrypted: { $ne: "true" } })
      .filter(function (f) { return !f.deletedAt; });
    var totalFiles = liveFiles.length;
    var totalDownloads = liveFiles.reduce(function(s, f) { return s + (f.downloads || 0); }, 0);

    // Storage = bytes physically used. S3 portion comes from the file table (HEAD per
    // object would be too slow on every dashboard view). Local portion is a directory
    // walk so we capture chunks, orphan files, and empty bundle dirs that aren't in
    // the file table — i.e. the actual disk footprint, not just the accounted footprint.
    var s3Bytes = liveFiles
      .filter(function (f) { return f.storagePath && f.storagePath.indexOf("s3://") === 0; })
      .reduce(function(s, f) { return s + (f.size || 0); }, 0);
    var localBytes = diskUsage(storage.uploadDir);
    var totalSize = s3Bytes + localBytes;

    // Bundles: surface "empty" bundles (complete bundles with zero live files) so
    // operators can see accounting noise from sync deletes, expired drops, etc. and
    // run Orphan Cleanup → "stale bundles" to remove them.
    var allCompleteBundles = bundlesRepo.findAll({ status: "complete" });
    var bundleFileCounts = {};
    for (var i = 0; i < liveFiles.length; i++) {
      var bid = liveFiles[i].bundleId;
      if (bid) bundleFileCounts[bid] = (bundleFileCounts[bid] || 0) + 1;
    }
    var emptyBundles = allCompleteBundles.filter(function(b) { return !bundleFileCounts[b._id]; }).length;
    var totalBundles = allCompleteBundles.length;

    audit.log(audit.ACTIONS.ADMIN_DASHBOARD_VIEWED, { req: req });
    send(res, "admin", {
      user: req.user, files: [], bundles: [],
      stats: {
        totalFiles: totalFiles,
        totalUsers: totalUsers,
        totalBundles: totalBundles,
        emptyBundles: emptyBundles,
        totalSize: totalSize,
        totalDownloads: totalDownloads,
      },
      host: host(req),
    });
  });

  // Activity feed API
  app.get("/admin/activity/api", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var recent = auditRepo.findPaginated({}, { limit: 20, offset: 0, orderBy: "createdAt", orderDir: "DESC" });
    res.json({ entries: recent.data });
  });

  // Files API (paginated)
  app.get("/admin/files/api", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var pag = adminValidator.validatePaginationParams(req.query);
    var page = pag.page;
    var limit = pag.limit;
    var q = req.query.q || "";
    var opts = { limit: limit, offset: (page - 1) * limit, orderBy: "createdAt", orderDir: "DESC" };
    var result;
    if (q) {
      result = filesRepo.searchPaginated(["shareIdHash"], q, { status: "complete", vaultEncrypted: { $ne: "true" } }, opts);
    } else {
      result = filesRepo.findPaginated({ status: { $ne: "chunking" }, vaultEncrypted: { $ne: "true" } }, opts);
    }
    var pages = Math.ceil(result.total / limit) || 1;

    // Enrich files with uploader attribution when missing
    var userCache = {};
    var mapped = result.data.map(function (f) {
      var obj = Object.assign({}, f);
      // If file has uploadedBy (user ID) but no uploaderEmail, look up the user
      if (obj.uploadedBy && obj.uploadedBy !== "public" && obj.uploadedBy !== "deleted" && !obj.uploaderEmail) {
        if (!userCache[obj.uploadedBy]) {
          var u = usersRepo.findById(obj.uploadedBy);
          userCache[obj.uploadedBy] = u || null;
        }
        var cached = userCache[obj.uploadedBy];
        if (cached) {
          obj.uploaderEmail = cached.email || "";
          obj.uploaderName = obj.uploaderName || cached.displayName || "";
        }
      }
      obj.uploaderName = obj.uploaderName || "";
      obj.uploaderEmail = obj.uploaderEmail || "";
      return obj;
    });

    res.json({ files: mapped, total: result.total, page: page, pages: pages, limit: limit });
  });

  // Bundles API (paginated)
  app.get("/admin/bundles/api", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var pag = adminValidator.validatePaginationParams(req.query);
    var page = pag.page;
    var limit = pag.limit;
    var opts = { limit: limit, offset: (page - 1) * limit, orderBy: "createdAt", orderDir: "DESC" };
    var result = bundlesRepo.findPaginated({ status: "complete" }, opts);
    var pages = Math.ceil(result.total / limit) || 1;
    // Enrich each bundle with live file count + size computed from the files
    // table directly. Avoids displaying stale bundle.receivedFiles /
    // bundle.totalSize when counter maintenance has fallen out of sync
    // (e.g. legacy admin-deletes that didn't decrement totalSize).
    var enriched = result.data.map(function (b) {
      var bundleFiles = filesRepo.findAll({ bundleId: b._id })
        .filter(function (f) { return !f.deletedAt; });
      var liveSize = bundleFiles.reduce(function (s, f) { return s + (f.size || 0); }, 0);
      return Object.assign({}, b, {
        liveFileCount: bundleFiles.length,
        liveFileSize: liveSize,
      });
    });
    res.json({ bundles: enriched, total: result.total, page: page, pages: pages, limit: limit });
  });

  // Delete file (admin)
  app.post("/admin/files/:shareId/delete", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    var doc = filesRepo.findByShareId(req.params.shareId);
    if (!doc) return res.status(404).json({ error: "Not found." });
    if (doc.storagePath) await storage.deleteFile(doc.storagePath);
    filesRepo.remove(doc._id);
    if (doc.bundleId) {
      var bundle = bundlesRepo.findById(doc.bundleId);
      if (bundle) {
        // Decrement BOTH counters. Previously only receivedFiles was updated,
        // leaving bundle.totalSize stale — admin-deleted files would vanish
        // from the count but their bytes stuck around in the cached total,
        // producing "0 files / 899 KB" zombies in the bundle list.
        bundlesRepo.update(doc.bundleId, { $set: {
          receivedFiles: Math.max(0, (bundle.receivedFiles || 0) - 1),
          totalSize: Math.max(0, (bundle.totalSize || 0) - (doc.size || 0)),
        } });
        // Decrement stash totalBytes if bundle belongs to a stash page
        if (bundle.stashId) {
          try { stashRepo.decrementBytes(bundle.stashId, doc.size); } catch (_e) {}
        }
      }
    }
    audit.log(audit.ACTIONS.ADMIN_FILE_DELETED, { targetId: doc._id, targetEmail: doc.uploaderEmail, details: "file: " + doc.originalName + ", size: " + doc.size, req: req });
    res.json({ success: true });
  });

  // Delete bundle + all files
  app.post("/admin/bundles/:shareId/delete", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    var bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) return res.status(404).json({ error: "Not found." });
    var bf = filesRepo.findByBundleShareId(bundle.shareId);
    for (var f of bf) {
      if (f.storagePath) await storage.deleteFile(f.storagePath);
      filesRepo.remove(f._id);
    }
    // Decrement stash stats if bundle belongs to a stash page
    if (bundle.stashId) {
      try { stashRepo.decrementBundleStats(bundle.stashId, bundle.totalSize); } catch (_e) { /* stash may have been deleted */ }
    }
    bundlesRepo.remove(bundle._id);
    audit.log(audit.ACTIONS.ADMIN_BUNDLE_DELETED, { targetId: bundle._id, targetEmail: bundle.uploaderEmail, details: "shareId: " + req.params.shareId + ", files: " + bf.length, req: req });
    res.json({ success: true });
  });

  // Settings API
  app.get("/admin/settings", (req, res) => {
    if (!requireAdmin(req, res)) return;
    audit.log(audit.ACTIONS.ADMIN_SETTINGS_VIEWED, { req: req });
    res.json(settingsService.getAllSettings());
  });

  // Environment info (Docker, Node, env overrides)
  app.get("/admin/environment", (req, res) => {
    if (!requireAdmin(req, res)) return;
    res.json(config.getEnvironment());
  });

  // Download database backup
  app.get("/admin/backup/db", (req, res) => {
    if (!requireAdmin(req, res)) return;
    // Prefer encrypted-at-rest copy; fall back to plain DB for dev/custom setups
    var encDbPath = PATHS.DB_ENC;
    var plainDbPath = process.env.HERMITSTASH_DB_PATH || path.join(path.dirname(encDbPath), "hermitstash.db");
    var dbPath = fs.existsSync(encDbPath) ? encDbPath : plainDbPath;
    var isEnc = dbPath === encDbPath;
    if (!fs.existsSync(dbPath)) { res.writeHead(404); return res.end("No database found"); }
    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Database backup downloaded" + (isEnc ? " (encrypted)" : ""), req: req });
    var ext = isEnc ? ".db.enc" : ".db";
    res.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": "attachment; filename=\"hermitstash-backup-" + new Date().toISOString().slice(0,10) + ext + "\""
    });
    fs.createReadStream(dbPath).pipe(res);
  });

  // ---- Storage S3 test ----

  app.post("/admin/storage/test", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var s = function(v) { return (v || "").trim(); };
      var masked = function(v) { return /^\u2022+$/.test(v || ""); };
      var client = new S3Client({
        bucket: s(body.bucket) || config.storage.s3.bucket,
        region: s(body.region) || config.storage.s3.region || "us-east-1",
        accessKey: masked(body.accessKey) ? config.storage.s3.accessKey : s(body.accessKey),
        secretKey: masked(body.secretKey) ? config.storage.s3.secretKey : s(body.secretKey),
        endpoint: s(body.endpoint !== undefined ? body.endpoint : config.storage.s3.endpoint),
      });
      await client.testConnection();
      res.json({ success: true });
    } catch (err) {
      res.json({ error: "Connection failed: " + err.message });
    }
  });

  // ---- Off-site backup (S3-compatible) ----

  app.post("/admin/backup/run", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var passphrase = String(body.passphrase || "").trim();
      if (!passphrase) return res.json({ error: "Backup passphrase is required." });

      // Verify passphrase if hash is set
      if (config.backup.passphraseHash) {
        var valid = await backup.verifyPassphrase(passphrase);
        if (!valid) return res.json({ error: "Incorrect backup passphrase." });
      }

      var manifest = await backup.runBackup(passphrase);
      res.json({ success: true, stats: manifest.stats });
    } catch (err) {
      res.json({ error: "Backup failed: " + err.message });
    }
  });

  app.post("/admin/backup/test", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var s = function(v) { return (v || "").trim(); };
      var masked = function(v) { return /^\u2022+$/.test(v || ""); };
      await backup.testConnection({
        bucket: s(body.bucket) || config.backup.s3.bucket,
        region: s(body.region) || config.backup.s3.region || "us-east-1",
        accessKey: masked(body.accessKey) ? config.backup.s3.accessKey : s(body.accessKey),
        secretKey: masked(body.secretKey) ? config.backup.s3.secretKey : s(body.secretKey),
        endpoint: s(body.endpoint !== undefined ? body.endpoint : config.backup.s3.endpoint),
      });
      res.json({ success: true });
    } catch (err) {
      res.json({ error: "Connection failed: " + err.message });
    }
  });

  app.get("/admin/backup/history", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var history = await backup.getBackupHistory();
      res.json({ success: true, history: history });
    } catch (err) {
      res.json({ error: "Failed to load history: " + err.message });
    }
  });

  app.get("/admin/backup/manifest", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    var timestamp = req.query.timestamp;
    if (!timestamp) return res.status(400).json({ error: "timestamp required" });
    try {
      var manifest = await backup.getBackupManifest(timestamp);
      if (!manifest) return res.status(404).json({ error: "Backup not found" });
      res.json(manifest);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/admin/backup/delete", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    var body = await parseJson(req);
    var timestamp = String(body.timestamp || "");
    if (!timestamp) return res.status(400).json({ error: "timestamp required" });
    try {
      var backend = backup.getBackend();
      var allKeys = await backend.list("backups/");
      // Find the prefix for this backup by matching the manifest header
      var manifestKeys = allKeys.filter(function (k) { return k.endsWith("/manifest.json"); });
      var targetPrefix = null;
      for (var i = 0; i < manifestKeys.length; i++) {
        try {
          var data = await backend.getBuffer(manifestKeys[i]);
          var m = JSON.parse(data.toString("utf8"));
          if (m.timestamp === timestamp) { targetPrefix = manifestKeys[i].replace("manifest.json", ""); break; }
        } catch (_e) { /* skip unreadable/corrupt manifest — continue scanning */ }
      }
      if (!targetPrefix) return res.status(404).json({ error: "Backup not found" });
      // Delete all files under this backup's prefix
      var prefixKeys = allKeys.filter(function (k) { return k.startsWith(targetPrefix); });
      for (var j = 0; j < prefixKeys.length; j++) await backend.del(prefixKeys[j]);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Deleted backup: " + timestamp + " (" + prefixKeys.length + " objects)", req: req });
      res.json({ success: true, deleted: prefixKeys.length });
    } catch (err) {
      res.status(500).json({ error: "Delete failed: " + err.message });
    }
  });

  app.post("/admin/restore/run", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    var body = await parseJson(req);
    var passphrase = String(body.passphrase || "");
    var timestamp = String(body.timestamp || "");
    if (!passphrase || !timestamp) return res.status(400).json({ error: "passphrase and timestamp required" });
    // dryRun: download + decrypt + checksum-verify every file, but skip
    // all writes + the process.exit restart. Used by E2E tests to validate
    // the restore crypto/integrity path without mutating on-disk state.
    // Operators can also use it to preview a restore before committing.
    var dryRun = body.dryRun === true;

    // Verify passphrase if hash is set
    if (config.backup.passphraseHash) {
      var valid = await backup.verifyPassphrase(passphrase);
      if (!valid) return res.status(403).json({ error: "Invalid passphrase." });
    }

    audit.log(audit.ACTIONS.RESTORE_STARTED, { details: "Restore initiated from backup: " + timestamp + (dryRun ? " (dry-run)" : ""), req: req });

    try {
      var result = await backup.runRestore(passphrase, timestamp, { dryRun: dryRun });
      res.json({ success: true, restarting: !dryRun, dryRun: dryRun, stats: result.stats });
      if (!dryRun) {
        // Graceful shutdown — let the response flush, then exit so Docker/systemd restarts
        setTimeout(function () { process.exit(0); }, 500);
      }
    } catch (err) {
      logger.error("Restore failed", { error: err.message });
      res.status(500).json({ error: "Restore failed: " + err.message });
    }
  });

  // Export users as CSV
  app.get("/admin/export/users", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var check = adminValidator.validateExportParams("users");
    if (check.error) return res.status(400).json({ error: check.error });
    var csv = exportService.exportUsersCsv();
    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Users CSV exported", req: req });
    res.writeHead(200, { "Content-Type": "text/csv", "Content-Disposition": "attachment; filename=\"users-export.csv\"" });
    res.end(csv);
  });

  // Export files as CSV
  app.get("/admin/export/files", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var check = adminValidator.validateExportParams("files");
    if (check.error) return res.status(400).json({ error: check.error });
    var csv = exportService.exportFilesCsv();
    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Files CSV exported", req: req });
    res.writeHead(200, { "Content-Type": "text/csv", "Content-Disposition": "attachment; filename=\"files-export.csv\"" });
    res.end(csv);
  });

  // IP Blocklist
  app.get("/admin/blocklist/api", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var all = blockedIpsRepo.findAll({});
    res.json({ ips: all });
  });

  app.post("/admin/blocklist/add", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    var body = await parseJson(req);
    var check = adminValidator.validateBlocklistInput(body);
    if (check.error) return res.status(400).json({ error: check.error });
    if (blockedIpsRepo.findOne({ ip: check.ip })) return res.status(400).json({ error: "Already blocked." });
    blockedIpsRepo.create({ ip: check.ip, reason: check.reason, blockedBy: req.user._id, createdAt: new Date().toISOString() });
    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "IP blocked", req: req });
    res.json({ success: true });
  });

  app.post("/admin/blocklist/remove", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    var body = await parseJson(req);
    blockedIpsRepo.remove({ ip: body.ip });
    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "IP unblocked", req: req });
    res.json({ success: true });
  });

  // Email quota status
  app.get("/admin/email/quota", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var counts = getQuotaCounts();
    res.json({
      backend: config.email.backend,
      configured: config.email.backend.includes("resend") ? !!config.email.resendApiKey : !!config.email.host,
      daily: counts.daily,
      dailyLimit: config.email.resendQuotaDaily,
      monthly: counts.monthly,
      monthlyLimit: config.email.resendQuotaMonthly,
    });
  });

  app.get("/admin/tasks/api", (req, res) => {
    if (!requireAdmin(req, res)) return;
    res.json({ tasks: scheduler.getStatus() });
  });

  // Proxy detection — check request headers for proxy indicators
  app.get("/admin/proxy/detect", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var hints = {};
    hints.detected = false;
    hints.headers = {};

    var fwd = req.headers["x-forwarded-for"];
    var realIp = req.headers["x-real-ip"];
    var proto = req.headers["x-forwarded-proto"];
    var via = req.headers["via"];

    if (fwd || realIp || proto || via) {
      hints.detected = true;
      if (fwd) hints.headers["X-Forwarded-For"] = fwd;
      if (realIp) hints.headers["X-Real-IP"] = realIp;
      if (proto) hints.headers["X-Forwarded-Proto"] = proto;
      if (via) hints.headers["Via"] = via;
    }

    // Guess proxy type from header patterns
    hints.guess = null;
    if (realIp && fwd) hints.guess = "nginx";
    else if (fwd && !realIp) hints.guess = "caddy";
    if (via && /apache/i.test(via)) hints.guess = "apache";

    res.json(hints);
  });

  app.post("/admin/settings", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var check = adminValidator.validateSettingsInput(body);
      if (check.error) return res.status(400).json({ error: check.error });
      var result = settingsService.updateSettings(check.settings);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: settingsService.buildAuditDetails(result), req: req });
      res.json({ success: true, updated: result.updated, restart: result.restart, warnings: result.warnings });
    } catch (e) {
      logger.error("Settings error", { error: e.message || String(e) });
      var status = e.isAppError ? e.statusCode : 400;
      res.status(status).json({ error: e.message || "Failed to save settings." });
    }
  });

  // Logo upload — with magic byte validation and SVG sanitization.
  // Stored in DATA_DIR (writable volume), served via explicit GET /img/custom/:name
  // route in server.js. The app source tree is a read-only image layer in Docker,
  // so writes into public/img/ fail with EACCES on fresh deployments.
  var LOGO_DIR = PATHS.CUSTOM_LOGO_DIR;
  var { detectContentType } = require("../app/http/validators/upload.validator");

  app.post("/admin/logo/upload", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var { files: uploaded } = await parseMultipart(req, 2 * 1024 * 1024); // 2MB max
      var file = uploaded[0];
      if (!file) return res.status(400).json({ error: "No file uploaded." });

      // Validate actual content, not just claimed MIME type
      var ext = detectContentType(file.data);
      if (!ext || [".png", ".jpg", ".gif", ".webp", ".svg"].indexOf(ext) === -1) return res.status(400).json({ error: "Invalid image. Upload a PNG, JPG, SVG, WebP, or GIF." });

      var data = file.data;

      // SVG: sanitize to strip scripts, event handlers, and external references
      if (ext === ".svg") {
        var raw = data.toString("utf8");
        var clean = sanitizeSvg(raw);
        if (!clean || clean.length < 10) return res.status(400).json({ error: "SVG rejected — could not sanitize safely." });
        data = Buffer.from(clean, "utf8");
      }

      if (!fs.existsSync(LOGO_DIR)) fs.mkdirSync(LOGO_DIR, { recursive: true });

      // Remove old custom logo
      try {
        var existing = fs.readdirSync(LOGO_DIR);
        existing.forEach(function (f) { if (f.startsWith("logo")) fs.unlinkSync(path.join(LOGO_DIR, f)); });
      } catch (_e) { /* LOGO_DIR may not exist on first upload */ }

      var filename = "logo" + ext;
      fs.writeFileSync(path.join(LOGO_DIR, filename), data);

      var logoPath = "/img/custom/" + filename;
      config.updateSettings({ customLogo: logoPath });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Custom logo uploaded: " + filename + " (" + data.length + " bytes)", req: req });
      res.json({ success: true, path: logoPath });
    } catch (e) {
      logger.error("Logo upload error", { error: e.message || String(e) });
      res.status(500).json({ error: "Upload failed." });
    }
  });

  app.post("/admin/logo/remove", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      if (fs.existsSync(LOGO_DIR)) {
        var existing = fs.readdirSync(LOGO_DIR);
        existing.forEach(function (f) { if (f.startsWith("logo")) fs.unlinkSync(path.join(LOGO_DIR, f)); });
      }
      config.updateSettings({ customLogo: "" });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Custom logo removed", req: req });
      res.json({ success: true });
    } catch (err) {
      logger.error("[admin/logo/remove] Error", { error: err.message, stack: err.stack });
      res.status(500).json({ error: "Failed to remove logo." });
    }
  });

  // Toggle the enforceMtls setting. Reachable via:
  //   - admin session (standard cookie auth) — through the Auth pane toggle
  //   - Bearer admin API key — for sync-client / CLI tooling that needs to
  //     re-enable the web UI when the admin is locked out of the browser.
  // This is also on the web-guard's always-allowed list so a Bearer admin
  // can always reach it even while enforceMtls is on.
  app.post("/admin/api/enforce-mtls", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var enabled = body && body.enabled === true;
      config.updateSettings({ enforceMtls: enabled ? "true" : "false" });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "enforceMtls " + (enabled ? "enabled" : "disabled"), req: req });
      res.json({ success: true, enforceMtls: enabled });
    } catch (e) {
      logger.error("enforce-mtls toggle error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to update enforceMtls." });
    }
  });

  // CA status — exposes whether the on-disk CA is current-generation or
  // legacy. The Danger Zone card reads this to conditionally surface the
  // "regeneration recommended" banner.
  app.get("/admin/api/mtls-ca/status", (req, res) => {
    if (!requireAdmin(req, res)) return;
    res.json(mtlsCa.getCaStatus());
  });

  // Regenerate the mTLS CA. Used when the algorithm envelope in lib/mtls-ca.js
  // is upgraded (CA_GENERATION bump) and the existing CA needs to be lifted
  // to the new generation. Orchestration:
  //   1. Pre-generate a new CA keypair in memory (no disk write yet)
  //   2. For every live sync WS connection, issue a new client cert signed by
  //      the new CA and push it via `ca:rotation` message. The existing
  //      TLS/WS connection stays open (uses the OLD cert) through the ack
  //      window, so clients can persist new credentials without reconnecting.
  //   3. Wait up to ACK_TIMEOUT_MS for clients to confirm via `ca:rotation-ack`
  //   4. Commit the new CA to disk (atomic rename)
  //   5. Delete orphaned browser cert api_keys (they were issued by the old
  //      CA — no longer trusted post-restart; admin redownloads from panel)
  //   6. Write a regen flag so post-restart admin UI can surface a banner
  //   7. process.exit(0) so Docker/systemd restarts us with the new CA loaded
  // Offline sync clients miss the rotation — their certs become invalid and
  // they must re-enroll via /sync/enroll with a fresh enrollment code.
  app.post("/admin/api/mtls-ca/regenerate", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      if (!body || body.confirm !== "REGEN") {
        return res.status(400).json({ error: "Confirmation required: POST { confirm: 'REGEN' }" });
      }
      if (!mtlsCa.caExists()) {
        return res.status(400).json({ error: "No CA exists yet. Nothing to regenerate." });
      }
      // skipRestart: run the full orchestration (version check → in-memory CA
      // generation → WS broadcast → ack collection → summary response) but do
      // NOT commit to disk and do NOT exit. Useful for:
      //   1. E2E tests that need to verify the rotation protocol against a
      //      shared server without destroying the old CA (which would break
      //      client certs already issued by it).
      //   2. Operators who want to preview what rotation would do and trigger
      //      the commit + restart themselves via a separate mechanism.
      var skipRestart = body.skipRestart === true;

      var ACK_TIMEOUT_MS = 15000;
      var RESTART_DELAY_MS = 1000; // gap between ack-window close and process.exit

      // Generate the new CA in memory — not yet written to disk
      var fresh = await mtlsCa.generateNewCaInMemory();

      // Categorize existing cert-bound api_keys
      var allCertKeys = apiKeysRepo.findAll().filter(function (k) { return !!k.certFingerprint; });
      var browserCerts = allCertKeys.filter(function (k) { return (k.keyHash || "").indexOf("browser:") === 0; });
      var syncCerts = allCertKeys.filter(function (k) { return (k.keyHash || "").indexOf("browser:") !== 0; });

      // Find unique connected sync apiKeys (clients may have multiple bundle
      // connections open under the same key — dedupe so we rotate each key once)
      var liveConns = syncRegistry.listSyncConnections();
      var liveByKeyId = new Map();
      for (var lc = 0; lc < liveConns.length; lc++) {
        if (!liveByKeyId.has(liveConns[lc].apiKeyId)) {
          liveByKeyId.set(liveConns[lc].apiKeyId, liveConns[lc]);
        }
      }

      var summary = {
        caGenerationBefore: mtlsCa.getCaStatus().generation,
        caGenerationAfter: mtlsCa.CA_GENERATION,
        syncCertsTotal: syncCerts.length,
        syncClientsConnected: liveByKeyId.size,
        syncClientsAcked: 0,
        syncClientsOffline: Math.max(syncCerts.length - liveByKeyId.size, 0),
        browserCertsRevoked: browserCerts.length,
        restartInMs: 0,
      };

      function finalize(note) {
        if (skipRestart) {
          // Dry-run mode: skip commit, skip browser cert revocation, skip
          // exit. The in-memory new CA and the pre-signed client certs are
          // discarded. The DB-side fingerprint updates on connected clients
          // still happened (already issued above) — callers using skipRestart
          // should understand this mutates api_keys.certFingerprint.
          audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "mTLS CA regenerate dry-run (skipRestart): " + JSON.stringify(summary), req: req });
          logger.info("[mTLS] CA regenerate dry-run — not committing, not exiting", { summary: summary, note: note });
          return;
        }
        // Write a flag file so startup-checks can show a post-restart banner
        try {
          fs.writeFileSync(path.join(PATHS.DATA_DIR, "ca-regen-flag.json"), JSON.stringify({
            at: new Date().toISOString(),
            summary: summary,
            byUser: req.session && req.session.userId ? req.session.userId : null,
          }));
        } catch (_e) { /* regen flag file is best-effort — startup banner only */ }
        // Commit CA files atomically
        mtlsCa.commitNewCa(fresh.caCertPem, fresh.caKeyPem);
        // Delete browser cert api_keys — their cert was issued by the old CA
        for (var bc = 0; bc < browserCerts.length; bc++) {
          try { apiKeysRepo.remove(browserCerts[bc]._id); } catch (_e) {}
        }
        audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "mTLS CA regenerated: " + JSON.stringify(summary), req: req });
        logger.info("[mTLS] CA regenerated — exiting for restart", { summary: summary, note: note });
        // Give the HTTP response time to flush before exit
        setTimeout(function () { process.exit(0); }, RESTART_DELAY_MS);
      }

      // Fast path: no live sync clients → skip rotation, commit + exit
      if (liveByKeyId.size === 0) {
        summary.restartInMs = RESTART_DELAY_MS;
        res.json({ ok: true, summary: summary, note: "No active sync clients — committing new CA and restarting." });
        finalize("fast-path");
        return;
      }

      // Rotation path: pre-sign new certs, push to each connected client,
      // update DB with new fingerprints, await acks.
      var ackCount = 0;
      var ackPromises = [];
      var liveEntries = Array.from(liveByKeyId.entries());
      for (var le = 0; le < liveEntries.length; le++) {
        var keyId = liveEntries[le][0];
        var conn = liveEntries[le][1];
        var apiKey = apiKeysRepo.findOne({ _id: keyId });
        if (!apiKey) continue;
        var cn = apiKey.prefix || "client";
        var newCert = await mtlsCa.generateClientCertWithCa(cn, fresh.caCertPem, fresh.caKeyPem);
        if (!newCert) continue;
        // Update fingerprint binding — any subsequent request with the old
        // cert will fail per-key binding check, but the existing WS stays
        // open since TLS doesn't re-validate on an already-authenticated
        // connection. After restart, clients reconnect with the new cert.
        // In skipRestart mode, leave the DB unchanged so the shared server
        // remains usable by subsequent tests (old cert still validates).
        if (!skipRestart) {
          var newFp = sha3Hash(newCert.cert);
          apiKeysRepo.update(apiKey._id, { $set: {
            certFingerprint: newFp,
            certIssuedAt: newCert.issuedAt,
            certExpiresAt: newCert.expiresAt,
          } });
        }
        // Wire ack callback
        (function (kid) {
          var resolveFn;
          ackPromises.push(new Promise(function (r) { resolveFn = r; }));
          syncRegistry.caRotationAckCallbacks.set(kid, function () {
            ackCount++;
            resolveFn(true);
          });
        })(keyId);
        // Push rotation message. dryRun: true tells clients to ack without
        // writing files to disk — so a skipRestart test doesn't clobber
        // the client's real cert/key/CA files.
        try {
          conn.ws.send(JSON.stringify({
            type: "ca:rotation",
            newCaPem: fresh.caCertPem,
            newCertPem: newCert.cert,
            newKeyPem: newCert.key,
            restartInMs: ACK_TIMEOUT_MS + RESTART_DELAY_MS,
            dryRun: skipRestart,
          }));
        } catch (_e) { /* WS send failure — client will reconnect with new cert after restart */ }
      }

      summary.restartInMs = ACK_TIMEOUT_MS + RESTART_DELAY_MS;

      // Race allSettled against the ack-window timeout
      var timeoutP = new Promise(function (r) { setTimeout(function () { r("timeout"); }, ACK_TIMEOUT_MS); });
      await Promise.race([Promise.allSettled(ackPromises), timeoutP]);

      // Clear ack callbacks so stray late acks don't leak
      for (var ce = 0; ce < liveEntries.length; ce++) {
        syncRegistry.caRotationAckCallbacks.delete(liveEntries[ce][0]);
      }

      summary.syncClientsAcked = ackCount;

      // Respond with the summary BEFORE committing + exiting so the admin UI
      // sees the ack count and knows which clients will need manual recovery.
      res.json({ ok: true, summary: summary, note: "CA rotation pushed to " + liveByKeyId.size + " client(s); " + ackCount + " acked. Committing and restarting." });
      finalize("rotation-path");
    } catch (e) {
      logger.error("CA regeneration failed", { error: e.message || String(e), stack: e.stack });
      if (!res.headersSent) res.status(500).json({ error: "CA regeneration failed: " + (e.message || String(e)) });
    }
  });

  // Revoke all sessions (emergency: force all users to re-login)
  app.post("/admin/sessions/revoke-all", (req, res) => {
    if (!requireAdmin(req, res)) return;
    sessionService.revokeAll(req);
    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "All sessions revoked", req: req });
    res.json({ success: true, message: "All sessions revoked. Everyone must re-login." });
  });

  // Purge all users except the current admin
  app.post("/admin/purge/users", (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var allUsers = usersRepo.findAll({ _id: { $ne: req.user._id } });
      var count = allUsers.length;
      for (var i = 0; i < allUsers.length; i++) {
        credentialsRepo.removeByUser(allUsers[i]._id);
        usersRepo.deleteUser(allUsers[i]._id, "deleted");
      }
      // Unlink files from deleted users
      var orphaned = filesRepo.findAll({});
      for (var j = 0; j < orphaned.length; j++) {
        if (orphaned[j].uploadedBy && orphaned[j].uploadedBy !== req.user._id && orphaned[j].uploadedBy !== "public") {
          filesRepo.update(orphaned[j]._id, { $set: { uploadedBy: "deleted" } });
        }
      }
      sessionService.revokeAll(req);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Purged " + count + " users", req: req });
      res.json({ success: true, deleted: count });
    } catch (e) {
      logger.error("Purge users error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to purge users." });
    }
  });

  // Purge all files and bundles
  app.post("/admin/purge/files", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var allFiles = filesRepo.findAll({});
      var fileCount = allFiles.length;
      for (var i = 0; i < allFiles.length; i++) {
        if (allFiles[i].storagePath) {
          try { await storage.deleteFile(allFiles[i].storagePath); } catch (_e) { /* cleanup — storage file may already be gone */ }
        }
        filesRepo.remove(allFiles[i]._id);
      }
      var allBundles = bundlesRepo.findAll({});
      var bundleCount = allBundles.length;
      for (var j = 0; j < allBundles.length; j++) {
        bundlesRepo.remove(allBundles[j]._id);
      }
      // Reset all stash stats since their bundles are gone
      try {
        var allStash = stashRepo.findAll();
        for (var k = 0; k < allStash.length; k++) {
          stashRepo.update(allStash[k]._id, { $set: { bundleCount: 0, totalBytes: 0 } });
        }
      } catch (_e) { /* stash stats reset is best-effort — files already purged */ }
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Purged " + fileCount + " files, " + bundleCount + " bundles", req: req });
      res.json({ success: true, deletedFiles: fileCount, deletedBundles: bundleCount });
    } catch (e) {
      logger.error("Purge files error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to purge files." });
    }
  });

  // Purge entire database (factory reset, keeps current admin)
  app.post("/admin/purge/database", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var check = adminValidator.validatePurgeConfirmation(body);
      if (check.error) return res.status(400).json({ error: check.error });

      // Delete all files from disk
      var allFiles = filesRepo.findAll({});
      for (var i = 0; i < allFiles.length; i++) {
        if (allFiles[i].storagePath) {
          try { await storage.deleteFile(allFiles[i].storagePath); } catch (_e) { /* cleanup — storage file may already be gone */ }
        }
      }

      // Purge all tables except settings, keep current admin user
      var allUsers = usersRepo.findAll({ _id: { $ne: req.user._id } });
      for (var u = 0; u < allUsers.length; u++) usersRepo.deleteUser(allUsers[u]._id, "deleted");
      var allF = filesRepo.findAll({});
      for (var f = 0; f < allF.length; f++) filesRepo.remove(allF[f]._id);
      var allB = bundlesRepo.findAll({});
      for (var b = 0; b < allB.length; b++) bundlesRepo.remove(allB[b]._id);
      var allCreds = credentialsRepo.find({});
      for (var c = 0; c < allCreds.length; c++) {
        if (allCreds[c].userId !== req.user._id) credentialsRepo.remove({ _id: allCreds[c]._id });
      }
      var allKeys = apiKeysRepo.findAll({});
      for (var k = 0; k < allKeys.length; k++) apiKeysRepo.remove(allKeys[k]._id);
      var allHooks = webhooksRepo.findAll();
      for (var w = 0; w < allHooks.length; w++) webhooksRepo.remove(allHooks[w]._id);
      var allAudit = auditRepo.findAll({});
      for (var a = 0; a < allAudit.length; a++) auditRepo.remove(allAudit[a]._id);
      var allTeams = teamsRepo.findAllTeams({});
      for (var t = 0; t < allTeams.length; t++) {
        teamsRepo.removeAllMembers(allTeams[t]._id);
        teamsRepo.removeTeam(allTeams[t]._id);
      }
      // Purge customer stash pages
      try {
        var allStash = stashRepo.findAll();
        for (var st = 0; st < allStash.length; st++) stashRepo.remove(allStash[st]._id);
      } catch (_e) { /* stash purge is best-effort — database reset still completes */ }

      sessionService.revokeAll(req);
      // Log after purge so at least one audit entry exists
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Full database purge (factory reset)", req: req });
      res.json({ success: true });
    } catch (e) {
      logger.error("Purge database error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to purge database." });
    }
  });

  // ---- First-run setup wizard ----

  app.get("/admin/setup", (req, res) => {
    if (!requireAdmin(req, res)) return;
    if (config.setupComplete) return res.redirect("/admin");
    send(res, "setup", { user: req.user, host: host(req), config: {
      siteName: config.siteName, rpName: config.rpName, rpId: config.rpId, rpOrigin: config.rpOrigin,
      sessionSecret: config.sessionSecret === "change-me-please" ? "" : "set",
    }});
  });

  app.post("/admin/setup", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    if (config.setupComplete) return res.status(400).json({ error: "Setup already completed." });
    try {
      var body = await parseJson(req);
      var errors = [];

      // 1. Require admin email change from default
      var emailCheck = validateEmail(body.adminEmail);
      if (!emailCheck.valid) {
        errors.push(emailCheck.reason);
      } else if (emailCheck.email === "admin@hermitstash.com") {
        errors.push("Change the default admin email before continuing.");
      } else if (emailCheck.email !== req.user.email) {
        var email = emailCheck.email;
        var existing = usersRepo.findByEmail(email);
        if (existing && existing._id !== req.user._id) {
          errors.push("Email already in use.");
        } else {
          usersRepo.update(req.user._id, { $set: { email: email } });
        }
      }

      // 2. Require password change from default
      var pwCheck = validatePassword(body.adminPassword);
      if (!pwCheck.valid) {
        errors.push(pwCheck.reason);
      } else {
        var hash = await hashPassword(body.adminPassword);
        usersRepo.update(req.user._id, { $set: { passwordHash: hash } });
      }

      // 3. Update settings
      var settings = {};
      if (body.siteName) settings.siteName = body.siteName;
      settings.sessionSecret = body.sessionSecret || generateToken(32);
      if (body.rpName) settings.rpName = body.rpName;
      if (body.rpId) settings.rpId = body.rpId;
      if (body.rpOrigin) settings.rpOrigin = body.rpOrigin;
      if (Object.keys(settings).length > 0) {
        config.updateSettings(settings);
      }

      if (errors.length > 0) {
        return res.status(400).json({ error: errors.join(" ") });
      }

      // Mark setup as complete
      config.updateSettings({ setupComplete: "true" });

      // Remove the initial-admin-password.txt plaintext file now that the
      // operator has chosen their own credentials.
      try {
        if (fs.existsSync(PATHS.INITIAL_ADMIN_PASSWORD)) fs.unlinkSync(PATHS.INITIAL_ADMIN_PASSWORD);
      } catch (e) {
        logger.error("Failed to remove initial-admin-password.txt", { error: e.message || String(e) });
      }

      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Initial setup completed", req: req });
      res.json({ success: true, redirect: "/admin" });
    } catch (e) {
      logger.error("Setup error", { error: e.message || String(e) });
      res.status(500).json({ error: "Setup failed." });
    }
  });

  // ---- Storage migration (local ↔ S3) ----

  var migrationService = require("../app/domain/admin/storage-migration.service");
  var _migrationRunning = false;
  var _migrationResult = null;

  app.get("/admin/storage/migration/preview", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var direction = req.query.direction;
    if (direction !== "local-to-s3" && direction !== "s3-to-local") {
      return res.status(400).json({ error: "direction must be 'local-to-s3' or 's3-to-local'" });
    }
    try {
      var preview = migrationService.migrationPreview(direction);
      res.json(preview);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post("/admin/storage/migration/start", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    if (_migrationRunning || (_migrationResult && _migrationResult.status === "running")) {
      return res.status(409).json({ error: "Migration already in progress." });
    }

    var body = await parseJson(req);
    var direction = body.direction;
    if (direction !== "local-to-s3" && direction !== "s3-to-local") {
      return res.status(400).json({ error: "direction must be 'local-to-s3' or 's3-to-local'" });
    }

    _migrationRunning = true;
    _migrationResult = { status: "running", direction: direction, migrated: 0, skipped: 0, failed: 0, total: 0, errors: [] };

    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Storage migration started: " + direction, req: req });

    // Run async — respond immediately so the UI can poll status
    migrationService.migrateStorage(direction, function (progress) {
      _migrationResult.migrated = progress.migrated;
      _migrationResult.skipped = progress.skipped;
      _migrationResult.failed = progress.failed;
      _migrationResult.total = progress.total;
    }).then(function (result) {
      _migrationRunning = false;
      _migrationResult = { status: "complete", direction: direction, migrated: result.migrated, skipped: result.skipped, failed: result.failed, total: result.total, errors: result.errors.slice(0, 50) };
      var newBackend = direction === "local-to-s3" ? "s3" : "local";
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Storage migration complete: " + result.migrated + " migrated, " + result.failed + " failed. Switch backend to '" + newBackend + "' to use new storage." });
      logger.info("[migration] Complete", { direction: direction, migrated: result.migrated, failed: result.failed });
    }).catch(function (err) {
      _migrationRunning = false;
      _migrationResult = { status: "error", direction: direction, error: err.message, migrated: _migrationResult.migrated, failed: _migrationResult.failed, total: _migrationResult.total, errors: [] };
      logger.error("[migration] Failed", { direction: direction, error: err.message });
    });

    res.json({ status: "started", direction: direction });
  });

  app.get("/admin/storage/migration/status", (req, res) => {
    if (!requireAdmin(req, res)) return;
    if (!_migrationResult) return res.json({ status: "idle" });
    res.json(_migrationResult);
  });

  // ---- Orphan cleanup (storage files with no DB record) ----

  var orphanJob = require("../app/jobs/orphan-cleanup.job");

  app.get("/admin/storage/orphans/scan", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var local = orphanJob.scanLocalOrphans();
      var s3 = await orphanJob.scanS3Orphans();
      var dangling = await orphanJob.scanDanglingRecords();
      var emptyBundles = orphanJob.scanEmptyBundles();
      var localBytes = 0;
      for (var i = 0; i < local.orphans.length; i++) localBytes += local.orphans[i].size || 0;
      res.json({
        local: { orphans: local.orphans.length, scanned: local.totalScanned, bytes: localBytes },
        s3: { orphans: s3.orphans.length, scanned: s3.totalScanned, error: s3.error || null },
        dangling: { records: dangling.length },
        emptyBundles: { count: emptyBundles.length },
      });
    } catch (e) {
      logger.error("Orphan scan error", { error: e.message });
      res.status(500).json({ error: "Scan failed: " + e.message });
    }
  });

  app.post("/admin/storage/orphans/clean", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var result = { local: 0, s3: 0, dangling: 0, emptyBundles: 0 };

      if (body.local !== false) {
        var localScan = orphanJob.scanLocalOrphans();
        result.local = orphanJob.deleteLocalOrphans(localScan.orphans);
      }
      if (body.s3 !== false) {
        var s3Scan = await orphanJob.scanS3Orphans();
        result.s3 = await orphanJob.deleteS3Orphans(s3Scan.orphans);
      }
      if (body.dangling === true) {
        var danglingRecords = await orphanJob.scanDanglingRecords();
        for (var i = 0; i < danglingRecords.length; i++) {
          filesRepo.remove(danglingRecords[i].fileId);
        }
        result.dangling = danglingRecords.length;
      }
      if (body.emptyBundles === true) {
        var emptyScan = orphanJob.scanEmptyBundles();
        result.emptyBundles = orphanJob.deleteEmptyBundles(emptyScan);
      }

      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, {
        details: "Orphan cleanup: " + result.local + " local, " + result.s3 + " S3, " + result.dangling + " dangling records, " + result.emptyBundles + " empty bundles removed",
        req: req,
      });
      res.json({ success: true, deleted: result });
    } catch (e) {
      logger.error("Orphan cleanup error", { error: e.message });
      res.status(500).json({ error: "Cleanup failed: " + e.message });
    }
  });
};
