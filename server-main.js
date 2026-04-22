// -- Core libs --
var path = require("path");
var fs = require("fs");
var url = require("node:url");

// -- lib/ modules --
var config = require("./lib/config");
var C = require("./lib/constants");
var { Router, serveStatic } = require("./lib/router");
var { sessionMiddleware } = require("./lib/session");
var db = require("./lib/db");
var { users } = db;
var { hashPassword, sha3Hash, generateBytes } = require("./lib/crypto");
var storage = require("./lib/storage");
var audit = require("./lib/audit");
var logger = require("./app/shared/logger");
var { sendHtml } = require("./lib/template");
var { parseJson } = require("./lib/multipart");
var certUtils = require("./lib/cert-utils");
var mtlsCa = require("./lib/mtls-ca");
var { createPQCGate } = require("./lib/pqc-gate");
var scheduler = require("./lib/scheduler");
var { acceptUpgrade, rejectUpgrade } = require("./lib/ws");
var syncEmitter = require("./lib/sync-emitter");

// -- middleware/ --
var { send } = require("./middleware/send");
var attachUser = require("./middleware/attach-user");
var errorHandler = require("./middleware/error-handler");

// -- app/ modules --
var startupChecks = require("./app/bootstrap/startup-checks");
var txHelper = require("./app/data/db/transaction");
var originPolicy = require("./app/security/origin-policy");
var apiKeysRepo = require("./app/data/repositories/apiKeys.repo");
var bundlesRepo = require("./app/data/repositories/bundles.repo");
var filesRepo = require("./app/data/repositories/files.repo");
var usersRepo = require("./app/data/repositories/users.repo");
var { handleSyncFileRename } = require("./app/domain/uploads/upload.handler");
var chunkGcJob = require("./app/jobs/chunk-gc.job");
var expiryCleanupJob = require("./app/jobs/expiry-cleanup.job");
var orphanCleanupJob = require("./app/jobs/orphan-cleanup.job");
var certExpiryJob = require("./app/jobs/cert-expiry.job");
var backupJob = require("./app/jobs/backup.job");

var app = new Router();

// Ensure dirs
var dataDir = C.DATA_DIR;
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
// storage.js creates the upload dir on require; ensure it exists for local backend
if (config.storage.backend === "local") {
  if (!fs.existsSync(storage.uploadDir)) fs.mkdirSync(storage.uploadDir, { recursive: true });
}

// Startup invariant checks — warn on insecure config, exit on critical issues
startupChecks.run();

// Default admin account (first run only)
// Generates a random initial password, logs it to stdout with a banner, and
// writes it to <dataDir>/initial-admin-password.txt (0600) so it survives
// restart. The file is deleted on setup-wizard completion.
if (users.count({}) === 0 && config.localAuth) {
  var initialPassword = generateBytes(12).toString("base64").replace(/[+/=]/g, "").slice(0, 16);
  hashPassword(initialPassword).then(function (hash) {
    users.insert({
      email: "admin@hermitstash.com", displayName: "Admin",
      passwordHash: hash, authType: "local", role: "admin", status: "active",
      createdAt: new Date().toISOString(), lastLogin: new Date().toISOString(),
    });
    try {
      fs.writeFileSync(C.PATHS.INITIAL_ADMIN_PASSWORD, initialPassword + "\n", { mode: 0o600 });
    } catch (e) {
      logger.error("Failed to write initial-admin-password.txt", { error: e.message || String(e) });
    }
    var banner = "\n" +
      "================================================================\n" +
      "  HermitStash first-run admin credentials\n" +
      "  email:    admin@hermitstash.com\n" +
      "  password: " + initialPassword + "\n" +
      "  (also written to " + C.PATHS.INITIAL_ADMIN_PASSWORD + ")\n" +
      "  Log in and complete the setup wizard to change these.\n" +
      "================================================================\n";
    process.stdout.write(banner);
    audit.log(audit.ACTIONS.DEFAULT_ADMIN_CREATED, { performedBy: "system", targetEmail: "admin@hermitstash.com" });
  });
}

// Initialize transaction helper with SQLite instance
txHelper.init(db.getDb ? db.getDb() : null);

// Middleware
app.use(require("./middleware/request-id"));
// Web-guard runs early so we avoid any template/CSP/static processing for
// requests that will be dropped. No-op when config.enforceMtls is false
// (default), so existing deployments see zero behavior change.
app.use(require("./middleware/web-guard"));
app.use(require("./middleware/security-headers"));
// Restrictive CSP for user-uploaded content (custom logos) — defense in depth against SVG XSS
app.use(function (req, res, next) {
  if (req.pathname && (req.pathname.startsWith("/img/custom/") || req.pathname.startsWith("/img/stash/"))) {
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");
    res.setHeader("X-Content-Type-Options", "nosniff");
  }
  next();
});
app.use(require("./middleware/ip-check"));
app.use(require("./middleware/bot-guard"));
app.use(require("./middleware/cors"));
app.use(serveStatic(path.join(__dirname, "public")));

// Serve admin custom logo + per-stash logos from the writable data directory.
// These are user-uploaded assets that can't live under public/img/ because the
// app source tree is read-only in Docker. Must come AFTER serveStatic so the
// static middleware's 404 fallthrough reaches us; must come BEFORE auth-
// protected routes so public pages (landing, stash pages) can load logos.
function serveLogoFrom(dir) {
  return function (req, res) {
    var name = String(req.params.name || "").replace(/[^A-Za-z0-9._-]/g, "");
    if (!name) { res.writeHead(404); return res.end(); }
    var full = path.join(dir, name);
    var resolved = path.resolve(full);
    if (!resolved.startsWith(path.resolve(dir))) { res.writeHead(404); return res.end(); }
    if (!fs.existsSync(resolved)) { res.writeHead(404); return res.end(); }
    var ext = path.extname(resolved).toLowerCase();
    var mime = ext === ".svg" ? "image/svg+xml"
             : ext === ".png" ? "image/png"
             : ext === ".jpg" || ext === ".jpeg" ? "image/jpeg"
             : ext === ".gif" ? "image/gif"
             : ext === ".webp" ? "image/webp"
             : "application/octet-stream";
    res.writeHead(200, { "Content-Type": mime, "Cache-Control": "public, max-age=3600" });
    fs.createReadStream(resolved).pipe(res);
  };
}
app.get("/img/custom/:name", serveLogoFrom(C.PATHS.CUSTOM_LOGO_DIR));
app.get("/img/stash/:name", serveLogoFrom(C.PATHS.STASH_LOGO_DIR));

// Migrate any pre-existing logos from the old public/img/{custom,stash}/
// locations to their new homes under DATA_DIR. Runs every boot. Logs every
// decision so operators can see exactly why a migration did or didn't copy.
(function migrateLogos() {
  var migrations = [
    { label: "custom", from: path.join(__dirname, "public", "img", "custom"), to: C.PATHS.CUSTOM_LOGO_DIR },
    { label: "stash",  from: path.join(__dirname, "public", "img", "stash"),  to: C.PATHS.STASH_LOGO_DIR },
  ];
  migrations.forEach(function (m) {
    if (!fs.existsSync(m.from)) {
      logger.info("[logo-migrate] " + m.label + ": source dir missing, nothing to migrate", { from: m.from });
      return;
    }
    var entries;
    try { entries = fs.readdirSync(m.from); }
    catch (e) { logger.error("[logo-migrate] " + m.label + ": readdir failed", { from: m.from, error: e.message }); return; }
    if (entries.length === 0) {
      logger.info("[logo-migrate] " + m.label + ": source dir empty", { from: m.from });
      return;
    }
    try { if (!fs.existsSync(m.to)) fs.mkdirSync(m.to, { recursive: true }); }
    catch (e) { logger.error("[logo-migrate] " + m.label + ": mkdir target failed", { to: m.to, error: e.message }); return; }

    var copied = 0, skipped = 0, failed = 0;
    entries.forEach(function (f) {
      var src = path.join(m.from, f);
      var dst = path.join(m.to, f);
      try {
        if (!fs.statSync(src).isFile()) { skipped++; return; }
        if (fs.existsSync(dst)) { skipped++; return; }
        fs.copyFileSync(src, dst);
        logger.info("[logo-migrate] " + m.label + ": copied " + f, { src: src, dst: dst });
        copied++;
      } catch (e) {
        logger.error("[logo-migrate] " + m.label + ": copy failed for " + f, { src: src, dst: dst, error: e.message });
        failed++;
      }
    });
    logger.info("[logo-migrate] " + m.label + ": done", { copied: copied, skipped: skipped, failed: failed, total: entries.length });
  });
})();

// Health check — before auth so it's fast and unauthenticated
app.get("/health", function (req, res) {
  var origin = req.headers.origin || "";
  // Build allowed origins from rpOrigin (the app's own domain) + healthCorsOrigins (gateway domains)
  var allowed = [];
  if (config.rpOrigin) allowed.push(config.rpOrigin);
  if (config.healthCorsOrigins) {
    config.healthCorsOrigins.forEach(function (o) { if (allowed.indexOf(o) === -1) allowed.push(o); });
  }
  var corsHeader = allowed.indexOf(origin) !== -1 ? origin : (allowed[0] || "*");
  var headers = { "Content-Type": "application/json", "Vary": "Origin" };
  if (corsHeader) headers["Access-Control-Allow-Origin"] = corsHeader;
  res.writeHead(200, headers);
  res.end(JSON.stringify({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() }));
});
app.get("/sitemap.xml", function (req, res) {
  var origin = originPolicy.getOrigin();
  var today = new Date().toISOString().split("T")[0];
  res.writeHead(200, { "Content-Type": "application/xml", "Cache-Control": "public, max-age=86400" });
  res.end('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n<url><loc>' + origin + '/</loc><lastmod>' + today + '</lastmod><changefreq>weekly</changefreq><priority>1.0</priority></url>\n<url><loc>' + origin + '/drop</loc><lastmod>' + today + '</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n<url><loc>' + origin + '/privacy</loc><changefreq>monthly</changefreq><priority>0.3</priority></url>\n<url><loc>' + origin + '/terms</loc><changefreq>monthly</changefreq><priority>0.3</priority></url>\n</urlset>');
});
// Sync enrollment — before auth so unauthenticated clients can redeem codes
app.post("/sync/enroll", require("./lib/rate-limit").middleware("sync-enroll", 5, C.TIME.FIVE_MIN), async function (req, res) {
  try {
    var body = await parseJson(req);
    var code = String(body.code || "").trim().toUpperCase();
    if (!code) {
      res.writeHead(400, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Enrollment code required." }));
    }

    // Look up by hash
    var codeHash = sha3Hash(C.HASH_PREFIX.ENROLLMENT + code);
    var records = db.enrollmentCodes.find({ status: "pending" })
      .filter(function (r) { return r.codeHash === codeHash && r.expiresAt > new Date().toISOString(); });

    if (records.length === 0) {
      res.writeHead(401, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Invalid or expired enrollment code." }));
    }

    var record = records[0];

    // Mark as redeemed (one-time use)
    db.enrollmentCodes.update({ _id: record._id }, { $set: { status: "redeemed" } });

    // Return the provisioning bundle
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      success: true,
      apiKey: record.apiKey || null,
      clientCert: record.clientCert,
      clientKey: record.clientKey,
      caCert: record.caCert,
      stashId: record.stashId || null,
      bundleId: record.bundleId || null,
      reissue: record.reissue || false,
    }));

    audit.log(audit.ACTIONS.ENROLLMENT_REDEEMED, { details: "Sync enrollment code redeemed", req: req });
  } catch (err) {
    // Don't leak the specific error to the client (it may reference DB rows,
    // crypto state, etc.) — but log it so operators can diagnose failed
    // enrollment attempts.
    logger.error("[sync/enroll] Error", { error: err.message, stack: err.stack });
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Enrollment failed." }));
  }
});

// Sync cert renewal — scope + cert-binding checks come from the shared
// sync-guards middleware. The endpoint itself only does things specific to
// renewal: presence-of-cert (required for this endpoint even if the key has
// no certFingerprint — the cert proof-of-possession IS the second factor),
// revocation check, and actual cert generation.
app.post("/sync/renew-cert",
  require("./lib/rate-limit").middleware("sync-renew", 5, C.TIME.FIVE_MIN),
  require("./middleware/sync-guards").requireSyncAuth({ requireBundle: false }),
  async function (req, res) {
    try {
      // Renewal REQUIRES a client certificate — not just "matches fingerprint
      // if one is set". This is tighter than the generic sync-guards check;
      // the cert is the second authn factor for this specific operation.
      var peerCert = req.socket && req.socket.getPeerCertificate ? req.socket.getPeerCertificate() : null;
      if (!peerCert || !peerCert.subject || !req.socket.authorized) {
        res.writeHead(403, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "mTLS client certificate required for renewal." }));
      }

      // Check cert is not revoked (indexed lookup, not full-table scan)
      if (certUtils.isCertRevoked(peerCert.fingerprint256)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Certificate has been revoked." }));
      }

      // Generate new client certificate
      await mtlsCa.initCA();
      var newCert = await mtlsCa.generateClientCert(req.apiKey.prefix);
      if (!newCert) {
        res.writeHead(500, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Certificate generation failed." }));
      }

      // Update cert tracking on the API key
      apiKeysRepo.update(req.apiKey._id, { $set: {
        certIssuedAt: newCert.issuedAt,
        certExpiresAt: newCert.expiresAt,
        certFingerprint: sha3Hash(newCert.cert),
      }});

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        success: true,
        clientCert: newCert.cert,
        clientKey: newCert.key,
        caCert: newCert.ca,
        issuedAt: newCert.issuedAt,
        expiresAt: newCert.expiresAt,
      }));

      audit.log(audit.ACTIONS.CERT_RENEWED, { details: "Sync client auto-renewed certificate: " + req.apiKey.prefix, req: req });
    } catch (err) {
      logger.error("[sync/renew-cert] Error", { error: err.message, stack: err.stack });
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Certificate renewal failed." }));
    }
  }
);

app.use(sessionMiddleware);
app.use(attachUser);
app.use(require("./middleware/api-auth"));
app.use(require("./middleware/api-encrypt"));
app.use(require("./app/security/csrf-policy").csrfMiddleware);

// Maintenance mode — blocks non-admin access when enabled
app.use(function (req, res, next) {
  if (!config.maintenanceMode) return next();
  // Allow admin and auth routes through
  if (req.user && req.user.role === "admin") return next();
  if (req.pathname && req.pathname.startsWith("/auth")) return next();
  if (req.pathname && req.pathname.startsWith("/admin")) return next();
  if (req.pathname && (req.pathname.startsWith("/css") || req.pathname.startsWith("/js") || req.pathname.startsWith("/img"))) return next();
  sendHtml(res, "maintenance", {
    brand: { siteName: config.siteName, logo: config.customLogo || C.paths.logo },
    assets: { css: C.paths.css + "?v=" + C.cssVersion },
  }, 503);
});

// Dynamic manifest — config for user text, constants for paths/theme
app.get("/manifest.json", (req, res) => {
  res.json({
    name: config.siteName,
    short_name: config.siteName,
    description: config.dropSubtitle,
    start_url: "/",
    display: "standalone",
    background_color: C.theme.bgColor,
    theme_color: C.theme.color,
    icons: [
      { src: C.paths.favicon32, sizes: "32x32", type: "image/png" },
      { src: C.paths.icon192, sizes: "192x192", type: "image/png" },
      { src: C.paths.icon512, sizes: "512x512", type: "image/png" },
    ],
  });
});

// First-run setup redirect — admin must complete setup before using the app
app.use(function (req, res, next) {
  if (config.setupComplete) return next();
  // Allow static assets, auth, and the setup page itself
  if (req.pathname && (req.pathname.startsWith("/css") || req.pathname.startsWith("/js") || req.pathname.startsWith("/img"))) return next();
  if (req.pathname && req.pathname.startsWith("/auth")) return next();
  if (req.pathname && req.pathname.startsWith("/admin/setup")) return next();
  // Redirect admins to setup
  if (req.user && req.user.role === "admin") {
    res.writeHead(302, { Location: "/admin/setup" });
    return res.end();
  }
  next();
});

// Routes
require("./routes/auth")(app);
require("./routes/password-reset")(app);
require("./routes/dashboard")(app);
require("./routes/files")(app);
require("./routes/drop")(app);
require("./routes/bundles")(app);
require("./routes/users")(app);
require("./routes/audit")(app);
require("./routes/profile")(app);
require("./routes/admin")(app);
require("./routes/apikeys")(app);
require("./routes/browser-certs")(app);
require("./routes/webhooks")(app);
require("./routes/verification")(app);
require("./routes/passkey")(app);
require("./routes/two-factor")(app);
require("./routes/teams")(app);
require("./routes/vault")(app);
require("./routes/stash")(app);

// Sync file rename — API key authed, uses bundleId directly (sync clients don't have shareId).
// All pre-checks (scope / ownership / boundBundleId / certFingerprint) run in
// middleware/sync-guards.js so every /sync/* endpoint inherits the same gate chain.
app.post("/sync/rename",
  require("./lib/rate-limit").middleware("sync-file-rename", 100, C.TIME.ONE_MIN),
  require("./middleware/sync-guards").requireSyncAuth({ requireBundle: true }),
  async function (req, res) {
    try {
      var result = await handleSyncFileRename({
        bundleId: req.body.bundleId,
        oldRelativePath: req.body.oldRelativePath,
        newRelativePath: req.body.newRelativePath,
        req: req,
      });
      if (result.error) { res.writeHead(result.status || 400, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ error: result.error })); }
      res.json(result);
    } catch (err) {
      logger.error("[sync/rename] Error", { error: err.message, stack: err.stack });
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Rename failed." }));
    }
  }
);

// Custom 404 page
app.onNotFound(function (req, res) {
  send(res, "error", { user: req.user || null, title: "Page Not Found", message: "The page you're looking for doesn't exist or has been moved." }, 404);
});

// Centralized error handler — catches all unhandled errors from routes
app.onError(errorHandler);

// Scheduled tasks
scheduler.register("file_expiry_cleanup", C.TIME.ONE_HOUR, function () { // hourly
  return expiryCleanupJob.cleanupExpiredFiles().catch(function (e) { logger.error("file_expiry_cleanup failed", { error: e.message }); });
});
scheduler.register("email_sends_cleanup", C.TIME.ONE_DAY, function () { // daily
  try {
    var cutoff = new Date(Date.now() - C.TIME.NINETY_DAYS).toISOString(); // 90 days
    db.rawExec("DELETE FROM email_sends WHERE createdAt < ?", cutoff);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_tokens_cleanup", C.TIME.ONE_DAY, function () { // daily
  try {
    var now = new Date().toISOString();
    db.rawExec("DELETE FROM verification_tokens WHERE expiresAt < ?", now);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_bundles_cleanup", C.TIME.ONE_HOUR, function () { // hourly
  try {
    db.rawExec("DELETE FROM bundles WHERE status = 'uploading' AND createdAt < ?",
      new Date(Date.now() - C.TIME.ONE_DAY).toISOString()); // stale uploads > 24h
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("chunk_gc", C.TIME.ONE_HOUR, function () { // hourly
  try { chunkGcJob.cleanupStaleChunks(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_invites_cleanup", C.TIME.ONE_DAY, function () { // daily
  try {
    var now = new Date().toISOString();
    db.rawExec("DELETE FROM invites WHERE status = 'pending' AND expiresAt < ?", now);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("tombstone_cleanup", C.TIME.ONE_DAY, function () { // daily
  try { expiryCleanupJob.cleanupTombstones(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_enrollment_codes_cleanup", C.TIME.ONE_HOUR, function () { // hourly
  try { expiryCleanupJob.cleanupExpiredEnrollmentCodes(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_access_codes_cleanup", C.TIME.ONE_HOUR, function () { // hourly
  try { expiryCleanupJob.cleanupExpiredAccessCodes(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("bundle_lockout_cleanup", C.TIME.ONE_HOUR, function () { // hourly
  // Remove lockout rows that haven't seen an attempt in 24h.
  // lastAttempt is a raw ISO8601 string, safe to compare in SQL.
  try {
    var cutoff = new Date(Date.now() - C.TIME.ONE_DAY).toISOString();
    db.rawExec("DELETE FROM bundle_access_lockouts WHERE lastAttempt < ?", cutoff);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("orphan_storage_cleanup", C.TIME.ONE_DAY, async function () { // daily
  try {
    var local = orphanCleanupJob.scanLocalOrphans();
    var deleted = orphanCleanupJob.deleteLocalOrphans(local.orphans);
    if (deleted > 0) logger.info("[orphan-cleanup] Removed " + deleted + " orphaned local files");
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("cert_expiry_check", C.TIME.ONE_DAY, function () { // daily
  return certExpiryJob.run().catch(function (e) { logger.error("cert_expiry_check failed", { error: e.message }); });
});
scheduler.register("incremental_vacuum", C.TIME.ONE_DAY, function () { // daily
  try { db.rawExec("PRAGMA incremental_vacuum(100)"); } catch (_e) { /* reclaim ~100 pages — best-effort */ }
});
scheduler.register("shm_usage_monitor", C.TIME.FIVE_MIN, function () { // every 5 minutes
  if (process.platform === "win32") return; // statfsSync not available on Windows
  var tmpdir = process.env.HERMITSTASH_TMPDIR || (fs.existsSync("/dev/shm") ? "/dev/shm" : null);
  if (!tmpdir) return;
  try {
    var stats = fs.statfsSync(tmpdir);
    var totalMB = Math.round(stats.blocks * stats.bsize / 1048576);
    var usedMB = Math.round((stats.blocks - stats.bfree) * stats.bsize / 1048576);
    var pct = totalMB > 0 ? Math.round(usedMB / totalMB * 100) : 0;
    if (pct >= 90) {
      logger.error("[SHM] " + tmpdir + " is " + pct + "% full (" + usedMB + "/" + totalMB + " MB) — database writes may fail. Increase shm_size immediately.");
    } else if (pct >= 75) {
      logger.warn("[SHM] " + tmpdir + " is " + pct + "% full (" + usedMB + "/" + totalMB + " MB) — consider increasing shm_size.");
    }
  } catch (_e) {} // statfsSync not available on all platforms
});
if (config.backup && config.backup.enabled) {
  scheduler.register("backup", config.backup.schedule || C.TIME.ONE_DAY, function () {
    return backupJob.run();
  }, { skipInitial: true, baseline: config.backup.timeOfDay, timezone: config.backup.timezone });
}
scheduler.start();

// TLS configuration — conditional HTTPS with PQC hybrid key exchange
var TLS_CERT = process.env.TLS_CERT || path.join(C.PATHS.TLS_DIR, "fullchain.pem");
var TLS_KEY = process.env.TLS_KEY || path.join(C.PATHS.TLS_DIR, "privkey.pem");
var PQC_ENFORCE = process.env.PQC_ENFORCE !== "false"; // default: true
var INTERNAL_TLS_PORT = parseInt(process.env.INTERNAL_TLS_PORT, 10) || 3001;
var tlsOptions = null;
var tlsEnabled = false;

if (fs.existsSync(TLS_CERT) && fs.existsSync(TLS_KEY)) {
  try {
    var mtlsCaCert = mtlsCa.caExists() ? fs.readFileSync(mtlsCa.CA_CERT_PATH) : null;
    // Hard mTLS enforcement at the TLS layer — boot-time only.
    //   unset:  follow DB config.enforceMtls for app-layer soft enforcement
    //   "true": rejectUnauthorized: true — TLS handshake rejects non-mTLS
    //   "false": forces all enforcement off (escape hatch for locked-out
    //           operators). Also disables app-layer soft enforcement in
    //           middleware/web-guard.js by overriding config.enforceMtls.
    var mtlsStrict = process.env.ENFORCE_MTLS_STRICT;
    if (mtlsStrict === "false") config.enforceMtls = false; // escape hatch
    var hardMtls = mtlsStrict === "true" && !!mtlsCaCert;
    tlsOptions = {
      cert: fs.readFileSync(TLS_CERT),
      key: fs.readFileSync(TLS_KEY),
      groups: C.TLS_GROUP_PREFERENCE,
      minVersion: "TLSv1.3",
      requestCert: !!mtlsCaCert,
      // Hard mode rejects non-mTLS at the TLS layer — no HTTP processing at all.
      // Soft mode keeps the handshake lenient and lets middleware/web-guard.js
      // drop at the app layer. Per-route mTLS checks (e.g. /sync/renew-cert)
      // validate socket.authorized regardless of this flag.
      rejectUnauthorized: hardMtls,
      ca: mtlsCaCert ? [mtlsCaCert] : undefined,
    };
    tlsEnabled = true;
    logger.info("[TLS] PQC TLS enabled", { groups: C.TLS_GROUP_PREFERENCE.join(" + ") });
  } catch (e) {
    logger.error("[TLS] Failed to load certificates", { error: e.message });
  }
} else {
  logger.warn("[TLS] No certificate found — starting in HTTP mode (no PQC protection)", { certPath: TLS_CERT });
}

// Start — with PQC gate if TLS enabled and enforcement is on
var protocol = tlsEnabled ? "https" : "http";
var server; // the HTTPS/HTTP server (WebSocket upgrade handler attaches here)
var gateServer = null; // the TCP gate (public-facing, if PQC enforcement enabled)

if (tlsEnabled && PQC_ENFORCE) {
  // PQC enforcement: internal HTTPS on 127.0.0.1, PQC gate on public port
  server = app.listen(INTERNAL_TLS_PORT, function () {
    logger.info("[PQC] Internal HTTPS server listening on 127.0.0.1:" + INTERNAL_TLS_PORT);
  }, tlsOptions, "127.0.0.1");

  gateServer = createPQCGate(INTERNAL_TLS_PORT);
  gateServer.listen(config.port, function () {
    logger.info("HermitStash is running", {
      url: protocol + "://localhost:" + config.port,
      tls: "PQC enforced (" + C.TLS_GROUP_PREFERENCE[0] + ")",
      pqcGate: "active on port " + config.port + " → 127.0.0.1:" + INTERNAL_TLS_PORT,
      storage: config.storage.backend + " -> " + storage.uploadDir,
      email: config.email.host || "disabled",
      auth: (config.localAuth ? "local" : "") + (config.localAuth && config.google.clientID ? " + " : "") + (config.google.clientID ? "google" : ""),
      timeout: config.uploadTimeout / 1000 + "s",
      concurrency: config.uploadConcurrency,
    });
    audit.log(audit.ACTIONS.SERVER_STARTED, { performedBy: "system", details: "port: " + config.port + ", tls: pqc-enforced, storage: " + config.storage.backend });
  });
} else {
  // No PQC enforcement: HTTPS directly on public port (or HTTP fallback)
  server = app.listen(config.port, function () {
    logger.info("HermitStash is running", {
      url: protocol + "://localhost:" + config.port,
      tls: tlsEnabled ? "PQC preferred (not enforced)" : "disabled",
      storage: config.storage.backend + " -> " + storage.uploadDir,
      email: config.email.host || "disabled",
      auth: (config.localAuth ? "local" : "") + (config.localAuth && config.google.clientID ? " + " : "") + (config.google.clientID ? "google" : ""),
      timeout: config.uploadTimeout / 1000 + "s",
      concurrency: config.uploadConcurrency,
    });
    audit.log(audit.ACTIONS.SERVER_STARTED, { performedBy: "system", details: "port: " + config.port + ", tls: " + (tlsEnabled ? "pqc-preferred" : "none") + ", storage: " + config.storage.backend });
  }, tlsOptions);
}
server.timeout = config.uploadTimeout;

// Certificate reload on renewal (Let's Encrypt certs update on disk)
if (tlsEnabled) {
  fs.watchFile(TLS_CERT, { interval: C.TIME.ONE_HOUR }, function () {
    try {
      var newContext = {
        cert: fs.readFileSync(TLS_CERT),
        key: fs.readFileSync(TLS_KEY),
        groups: C.TLS_GROUP_PREFERENCE,
        minVersion: "TLSv1.3",
      };
      server.setSecureContext(newContext);
      logger.info("[TLS] Certificate reloaded");
    } catch (e) {
      logger.error("[TLS] Certificate reload failed", { error: e.message });
    }
  });
}

// ---- WebSocket Sync Channel ----

// WS connection registry + helpers live in lib/sync-registry.js so both the
// upgrade handler here and the admin CA regeneration endpoint can share the
// same Maps without a server.js ↔ routes/admin.js circular require.
var syncRegistry = require("./lib/sync-registry");
var syncConnections = syncRegistry.syncConnections;
var apiKeyConnectionCount = syncRegistry.apiKeyConnectionCount;
var caRotationAckCallbacks = syncRegistry.caRotationAckCallbacks;

var SYNC_MAX_CONNECTIONS_PER_KEY = 5;
var SYNC_HEARTBEAT_INTERVAL = 30000;
var SYNC_MAX_MESSAGES_PER_MIN = 60;
var SYNC_MAX_MESSAGE_SIZE = 65536;

server.on("upgrade", function (req, socket, head) {
  // Parse URL
  var parsed = url.parse(req.url, true);
  if (parsed.pathname !== "/sync/ws") {
    // Not a sync WebSocket — ignore (let other handlers take it, or close)
    socket.destroy();
    return;
  }

  // mTLS check (if CA is configured) — client must present a valid cert.
  // Default is strict: when CA exists, a valid client cert is required.
  // Operators can set MTLS_REQUIRED=false as an explicit bring-up escape,
  // which skips the presence check but keeps revocation/expiry enforcement
  // for clients that do present a cert, and still honors per-key cert
  // binding (see apiKey.certFingerprint check below).
  //
  // The fingerprint itself isn't captured locally — sync-guards.js re-reads
  // it from the socket when it needs to enforce per-key cert binding, so a
  // second copy here would only risk drift.
  if (mtlsCaCert) {
    var peerCert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
    var hasValidCert = peerCert && peerCert.subject && socket.authorized;
    if (!hasValidCert) {
      if (process.env.MTLS_REQUIRED !== "false") {
        return rejectUpgrade(socket, 403, "Forbidden");
      }
      // MTLS_REQUIRED=false — permit (still requires API key). Per-key cert
      // binding below will still block keys that were enrolled with a cert.
    } else {
      // Check revocation list (indexed lookup, not full-table scan)
      if (certUtils.isCertRevoked(peerCert.fingerprint256)) {
        return rejectUpgrade(socket, 403, "Forbidden");
      }
      // Check certificate expiry
      if (peerCert.valid_to) {
        var certExpiry = new Date(peerCert.valid_to);
        if (certExpiry < new Date()) {
          return rejectUpgrade(socket, 403, "Certificate expired");
        }
      }
    }
  }

  // Auth: Bearer token from Authorization header only.
  // Query string tokens are not accepted — they leak via proxy logs, Referer
  // headers, and browser history. lib/http-utils.extractBearerToken handles
  // whitespace normalization consistently with api-auth middleware.
  var token = require("./lib/http-utils").extractBearerToken(req);
  if (!token) {
    return rejectUpgrade(socket, 401, "Unauthorized");
  }

  // Validate API key using the same mechanism as api-auth middleware
  var keyHash = sha3Hash(token);
  var apiKey = db.apiKeys.findOne({ keyHash: keyHash });
  if (!apiKey) {
    return rejectUpgrade(socket, 401, "Unauthorized");
  }

  // Delegate scope / cert-binding / bundle-binding checks to the shared
  // sync-guards helpers so this upgrade handler can't drift out of sync
  // with /sync/rename + /sync/renew-cert (see middleware/sync-guards.js).
  // Bundle lookup + stash binding + user activity stay inline here because
  // they use rejectUpgrade's raw-socket response path.
  var syncGuards = require("./middleware/sync-guards");

  var certErr = syncGuards.enforceCertBinding(apiKey, socket);
  if (certErr) return rejectUpgrade(socket, certErr.status, certErr.error);

  var scopeErr = syncGuards.enforceSyncScope(apiKey);
  if (scopeErr) return rejectUpgrade(socket, scopeErr.status, scopeErr.error);

  var user = usersRepo.findById(apiKey.userId);
  if (!user || user.status !== "active") {
    return rejectUpgrade(socket, 403, "Forbidden");
  }

  // Validate bundleId
  var bundleId = parsed.query.bundleId;
  if (!bundleId) {
    return rejectUpgrade(socket, 400, "Bad Request");
  }
  var bundle = bundlesRepo.findById(bundleId);
  if (!bundle || bundle.bundleType !== "sync") {
    return rejectUpgrade(socket, 404, "Not Found");
  }

  var bindErr = syncGuards.enforceBundleBinding(apiKey, bundleId);
  if (bindErr) return rejectUpgrade(socket, bindErr.status, bindErr.error);

  if (apiKey.boundStashId && bundle.stashId !== apiKey.boundStashId) {
    return rejectUpgrade(socket, 403, "Forbidden");
  }
  // Ownership check: must be the key's user, admin, or a stash-scoped token.
  // WS semantics differ slightly from /sync/rename — a stash-scoped token is
  // allowed across all bundles in the stash, so we don't call
  // enforceBundleOwnership here.
  if (bundle.ownerId !== user._id && user.role !== "admin" && !apiKey.boundStashId) {
    return rejectUpgrade(socket, 403, "Forbidden");
  }

  // Connection limit per API key
  var keyId = apiKey._id;
  var keyCount = apiKeyConnectionCount.get(keyId) || 0;
  if (keyCount >= SYNC_MAX_CONNECTIONS_PER_KEY) {
    return rejectUpgrade(socket, 429, "Too Many Requests");
  }

  // Validate since param
  var since = parseInt(parsed.query.since, 10);
  if (isNaN(since) || since < 0) since = 0;

  // Complete WebSocket handshake
  var ws = acceptUpgrade(req, socket, head);
  if (!ws) {
    return rejectUpgrade(socket, 400, "Bad Request");
  }

  // Register connection
  if (!syncConnections.has(bundleId)) syncConnections.set(bundleId, new Set());
  var connEntry = { ws: ws, apiKeyId: keyId };
  syncConnections.get(bundleId).add(connEntry);
  apiKeyConnectionCount.set(keyId, keyCount + 1);

  // Inbound message rate limiting
  var msgCount = 0;
  var msgResetTimer = setInterval(function () { msgCount = 0; }, C.TIME.ONE_MIN);
  var violations = 0;

  // Catch-up: send events since the given seq
  if (since > 0) {
    var catchupFiles = filesRepo.findAll({ bundleId: bundle._id })
      .filter(function (f) { return (f.seq || 0) > since; })
      .sort(function (a, b) { return (a.seq || 0) - (b.seq || 0); });
    for (var i = 0; i < catchupFiles.length; i++) {
      var f = catchupFiles[i];
      var evType = f.deletedAt ? "file_removed" : "file_added";
      var ev = { type: evType, fileId: f._id, relativePath: f.relativePath, seq: f.seq || 0 };
      if (!f.deletedAt) { ev.checksum = f.checksum; ev.size = f.size; }
      ws.send(JSON.stringify(ev));
    }
  }
  // Signal catch-up complete
  ws.send(JSON.stringify({ type: "heartbeat", seq: bundle.seq || 0, timestamp: new Date().toISOString() }));

  // Real-time event listener
  var syncListener = function (event) {
    try { ws.send(JSON.stringify(event)); } catch (_e) {}
  };
  syncEmitter.on("sync:" + bundleId, syncListener);

  // Send immediate heartbeat on connect so clients know the connection is live
  try {
    ws.send(JSON.stringify({ type: "heartbeat", seq: bundle.seq || 0, timestamp: new Date().toISOString() }));
  } catch (_e) { /* socket may have closed between upgrade and first write */ }

  // Heartbeat interval
  var heartbeatTimer = setInterval(function () {
    try {
      var freshBundle = bundlesRepo.findById(bundleId);
      ws.send(JSON.stringify({ type: "heartbeat", seq: freshBundle ? freshBundle.seq || 0 : 0, timestamp: new Date().toISOString() }));
      ws.ping();
    } catch (_e) { /* client disconnected between heartbeats — close handler runs next tick */ }
  }, SYNC_HEARTBEAT_INTERVAL);

  // Pong timeout detection
  var pongReceived = true;
  var pongCheckTimer = setInterval(function () {
    if (!pongReceived) {
      ws.close(1001, "Pong timeout");
      return;
    }
    pongReceived = false;
  }, SYNC_HEARTBEAT_INTERVAL);

  ws.on("pong", function () { pongReceived = true; });

  // Inbound message handling
  ws.on("message", function (data) {
    msgCount++;
    if (msgCount > SYNC_MAX_MESSAGES_PER_MIN) {
      violations++;
      ws.send(JSON.stringify({ type: "error", code: "rate_limited", message: "Too many messages", retryAfter: 60 }));
      if (violations >= 3) { ws.close(1008, "Rate limit exceeded"); }
      return;
    }
    if (data.length > SYNC_MAX_MESSAGE_SIZE) {
      ws.send(JSON.stringify({ type: "error", code: "message_too_large", message: "Max 64KB per message" }));
      return;
    }
    try {
      var msg = JSON.parse(data);
      if (!msg || !msg.type) {
        ws.send(JSON.stringify({ type: "error", code: "invalid_json", message: "Missing type field" }));
        return;
      }
      if (msg.type === "ack") {
        // Client acknowledges receipt — no server action needed in v1
      } else if (msg.type === "ca:rotation-ack") {
        // Sync client has persisted the new cert/key/CA bundle sent via
        // ca:rotation. Fire the per-apiKeyId callback that the admin
        // regeneration endpoint is awaiting so it knows this client is
        // ready for the restart. See routes/admin.js.
        var ackCb = caRotationAckCallbacks.get(keyId);
        if (ackCb) { try { ackCb(); } catch (_e) {} }
      } else if (msg.type === "catch_up") {
        var catchSince = parseInt(msg.since, 10) || 0;
        var files = filesRepo.findAll({ bundleId: bundle._id })
          .filter(function (f) { return (f.seq || 0) > catchSince; })
          .sort(function (a, b) { return (a.seq || 0) - (b.seq || 0); });
        for (var j = 0; j < files.length; j++) {
          var cf = files[j];
          var t = cf.deletedAt ? "file_removed" : "file_added";
          var e = { type: t, fileId: cf._id, relativePath: cf.relativePath, seq: cf.seq || 0 };
          if (!cf.deletedAt) { e.checksum = cf.checksum; e.size = cf.size; }
          ws.send(JSON.stringify(e));
        }
        var fb = bundlesRepo.findById(bundleId);
        ws.send(JSON.stringify({ type: "heartbeat", seq: fb ? fb.seq || 0 : 0, timestamp: new Date().toISOString() }));
      } else if (msg.type === "ping") {
        var pb = bundlesRepo.findById(bundleId);
        ws.send(JSON.stringify({ type: "heartbeat", seq: pb ? pb.seq || 0 : 0, timestamp: new Date().toISOString() }));
      } else {
        ws.send(JSON.stringify({ type: "error", code: "unknown_type", message: "Unrecognized message type: " + msg.type }));
      }
    } catch (_e) {
      ws.send(JSON.stringify({ type: "error", code: "invalid_json", message: "Invalid JSON" }));
    }
  });

  // Cleanup on close
  ws.on("close", function () {
    syncEmitter.off("sync:" + bundleId, syncListener);
    clearInterval(heartbeatTimer);
    clearInterval(pongCheckTimer);
    clearInterval(msgResetTimer);
    if (syncConnections.has(bundleId)) {
      syncConnections.get(bundleId).delete(connEntry);
      if (syncConnections.get(bundleId).size === 0) syncConnections.delete(bundleId);
    }
    var currentCount = apiKeyConnectionCount.get(keyId) || 0;
    if (currentCount > 1) apiKeyConnectionCount.set(keyId, currentCount - 1);
    else apiKeyConnectionCount.delete(keyId);
  });

  // Strip token from logged URL
  var logUrl = parsed.pathname + "?bundleId=" + bundleId + "&since=" + since;
  logger.info("[Sync] WebSocket connected", { bundleId: bundleId, user: user._id, url: logUrl });
});

// Graceful shutdown — stop accepting connections, drain in-flight requests, then exit
var shuttingDown = false;
function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info("Shutdown initiated", { signal: signal });

  // Close all WebSocket connections so server.close() can drain
  syncConnections.forEach(function (conns) {
    conns.forEach(function (entry) {
      try { if (entry.ws && entry.ws.readyState === 1) entry.ws.close(1001, "Server shutting down"); } catch (_e) { /* socket may already be closed */ }
    });
  });

  // Unwatch TLS cert to remove persistent file watcher
  if (tlsEnabled) try { fs.unwatchFile(TLS_CERT); } catch (_e) {}

  // Stop accepting new connections
  if (gateServer) gateServer.close();
  server.close(function () {
    logger.info("All connections drained, exiting");
    process.exit(0); // db.js "exit" handler encrypts the DB
  });

  // Force exit after 10 seconds if connections don't drain
  var forceTimer = setTimeout(function () {
    logger.warn("Shutdown timeout reached, forcing exit");
    process.exit(1);
  }, 10000);
  forceTimer.unref();
}

process.on("SIGTERM", function () { gracefulShutdown("SIGTERM"); });
process.on("SIGINT", function () { gracefulShutdown("SIGINT"); });
