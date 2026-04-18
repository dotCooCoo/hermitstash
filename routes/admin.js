var fs = require("fs");
var path = require("path");
var audit = require("../lib/audit");
var { PATHS } = require("../lib/constants");
var logger = require("../app/shared/logger");
const config = require("../lib/config");
var usersRepo = require("../app/data/repositories/users.repo");
var filesRepo = require("../app/data/repositories/files.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var auditRepo = require("../app/data/repositories/audit.repo");
var blockedIpsRepo = require("../app/data/repositories/blockedIps.repo");
var credentialsRepo = require("../app/data/repositories/credentials.repo");
var apiKeysRepo = require("../app/data/repositories/apiKeys.repo");
var webhooksRepo = require("../app/data/repositories/webhooks.repo");
var teamsRepo = require("../app/data/repositories/teams.repo");
const { parseJson, parseMultipart } = require("../lib/multipart");
const { hashPassword, generateToken } = require("../lib/crypto");
const storage = require("../lib/storage");
const requireAdmin = require("../middleware/require-admin");
const { send, host } = require("../middleware/send");
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

module.exports = function (app) {
  // Admin dashboard
  app.get("/admin", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var totalUsers = usersRepo.count({});
    var totalFiles = filesRepo.count({ status: { $ne: "chunking" }, vaultEncrypted: { $ne: "true" } });
    var totalBundles = bundlesRepo.count({ status: "complete" });
    var allFiles = filesRepo.findAll({ status: { $ne: "chunking" }, vaultEncrypted: { $ne: "true" } });
    var totalSize = allFiles.reduce(function(s, f) { return s + (f.size || 0); }, 0);
    var totalDownloads = allFiles.reduce(function(s, f) { return s + (f.downloads || 0); }, 0);
    audit.log(audit.ACTIONS.ADMIN_DASHBOARD_VIEWED, { req: req });
    send(res, "admin", {
      user: req.user, files: [], bundles: [],
      stats: { totalFiles: totalFiles, totalUsers: totalUsers, totalBundles: totalBundles, totalSize: totalSize, totalDownloads: totalDownloads },
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
    res.json({ bundles: result.data, total: result.total, page: page, pages: pages, limit: limit });
  });

  // Delete file (admin)
  app.post("/admin/files/:shareId/delete", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const doc = filesRepo.findByShareId(req.params.shareId);
    if (!doc) return res.status(404).json({ error: "Not found." });
    if (doc.storagePath) await storage.deleteFile(doc.storagePath);
    filesRepo.remove(doc._id);
    if (doc.bundleId) {
      var bundle = bundlesRepo.findById(doc.bundleId);
      if (bundle) {
        bundlesRepo.update(doc.bundleId, { $set: { receivedFiles: Math.max(0, (bundle.receivedFiles || 0) - 1) } });
        // Decrement stash totalBytes if bundle belongs to a stash page
        if (bundle.stashId) {
          try {
            var stash = stashRepo.findById(bundle.stashId);
            if (stash) {
              stashRepo.update(stash._id, { $set: { totalBytes: Math.max(0, (parseInt(stash.totalBytes, 10) || 0) - (doc.size || 0)) } });
            }
          } catch (_e) {}
        }
      }
    }
    audit.log(audit.ACTIONS.ADMIN_FILE_DELETED, { targetId: doc._id, targetEmail: doc.uploaderEmail, details: "file: " + doc.originalName + ", size: " + doc.size, req: req });
    res.json({ success: true });
  });

  // Delete bundle + all files
  app.post("/admin/bundles/:shareId/delete", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const bundle = bundlesRepo.findByShareId(req.params.shareId);
    if (!bundle) return res.status(404).json({ error: "Not found." });
    const bf = filesRepo.findByBundleShareId(bundle.shareId);
    for (const f of bf) {
      if (f.storagePath) await storage.deleteFile(f.storagePath);
      filesRepo.remove(f._id);
    }
    // Decrement stash stats if bundle belongs to a stash page
    if (bundle.stashId) {
      try {
        var stash = stashRepo.findById(bundle.stashId);
        if (stash) {
          stashRepo.update(stash._id, { $set: {
            bundleCount: Math.max(0, (parseInt(stash.bundleCount, 10) || 0) - 1),
            totalBytes: Math.max(0, (parseInt(stash.totalBytes, 10) || 0) - (bundle.totalSize || 0)),
          }});
        }
      } catch (_e) { /* stash may have been deleted */ }
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
        } catch (_e) {}
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

    // Verify passphrase if hash is set
    if (config.backup.passphraseHash) {
      var valid = await backup.verifyPassphrase(passphrase);
      if (!valid) return res.status(403).json({ error: "Invalid passphrase." });
    }

    audit.log(audit.ACTIONS.RESTORE_STARTED, { details: "Restore initiated from backup: " + timestamp, req: req });

    try {
      var result = await backup.runRestore(passphrase, timestamp);
      res.json({ success: true, restarting: true, stats: result.stats });
      // Graceful shutdown — let the response flush, then exit so Docker/systemd restarts
      setTimeout(function () { process.exit(0); }, 500);
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
    var server = req.headers["server"];

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
      const body = await parseJson(req);
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

  // Logo upload — with magic byte validation and SVG sanitization
  var LOGO_DIR = path.join(__dirname, "..", "public", "img", "custom");
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
      } catch (_e) {}

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
    } catch (_e) {
      res.status(500).json({ error: "Failed to remove logo." });
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
          try { await storage.deleteFile(allFiles[i].storagePath); } catch (_e) {}
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
      } catch (_e) {}
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
          try { await storage.deleteFile(allFiles[i].storagePath); } catch (_e) {}
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
      } catch (_e) {}

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
      var localBytes = 0;
      for (var i = 0; i < local.orphans.length; i++) localBytes += local.orphans[i].size || 0;
      res.json({
        local: { orphans: local.orphans.length, scanned: local.totalScanned, bytes: localBytes },
        s3: { orphans: s3.orphans.length, scanned: s3.totalScanned, error: s3.error || null },
        dangling: { records: dangling.length },
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
      var result = { local: 0, s3: 0, dangling: 0 };

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

      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, {
        details: "Orphan cleanup: " + result.local + " local, " + result.s3 + " S3, " + result.dangling + " dangling records removed",
        req: req,
      });
      res.json({ success: true, deleted: result });
    } catch (e) {
      logger.error("Orphan cleanup error", { error: e.message });
      res.status(500).json({ error: "Cleanup failed: " + e.message });
    }
  });
};
