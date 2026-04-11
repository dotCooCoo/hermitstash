const path = require("path");
const fs = require("fs");
const config = require("./lib/config");
const C = require("./lib/constants");
const { Router, serveStatic } = require("./lib/router");
const { sessionMiddleware } = require("./lib/session");
const { users } = require("./lib/db");
const { hashPassword } = require("./lib/crypto");
const storage = require("./lib/storage");
const audit = require("./lib/audit");
const logger = require("./app/shared/logger");
const { sendHtml } = require("./lib/template");
const { send } = require("./middleware/send");
const attachUser = require("./middleware/attach-user");
const errorHandler = require("./middleware/error-handler");

const app = new Router();

// Ensure dirs
for (const d of ["data", "uploads"]) {
  const p = path.join(__dirname, d);
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

// Startup invariant checks — warn on insecure config, exit on critical issues
{
  var startupChecks = require("./app/bootstrap/startup-checks");
  startupChecks.run();
}

// Default admin account (first run only)
if (users.count({}) === 0 && config.localAuth) {
  hashPassword("admin").then((hash) => {
    users.insert({
      email: "admin@hermitstash.com", displayName: "Admin",
      passwordHash: hash, authType: "local", role: "admin", status: "active",
      createdAt: new Date().toISOString(), lastLogin: new Date().toISOString(),
    });
    logger.info("Default admin created", { email: "admin@hermitstash.com", hint: "Complete the setup wizard to change these credentials." });
    audit.log(audit.ACTIONS.DEFAULT_ADMIN_CREATED, { performedBy: "system", targetEmail: "admin@hermitstash.com" });
  });
}

// Initialize transaction helper with SQLite instance
var txHelper = require("./app/data/db/transaction");
txHelper.init(require("./lib/db").getDb ? require("./lib/db").getDb() : null);

// Middleware
app.use(require("./middleware/request-id"));
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
app.use(require("./middleware/cors"));
app.use(serveStatic(path.join(__dirname, "public")));
// Health check — before auth so it's fast and unauthenticated
app.get("/health", function (req, res) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() }));
});
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
require("./routes/webhooks")(app);
require("./routes/verification")(app);
require("./routes/passkey")(app);
require("./routes/two-factor")(app);
require("./routes/teams")(app);
require("./routes/vault")(app);
require("./routes/stash")(app);

// Custom 404 page
app.onNotFound(function (req, res) {
  send(res, "error", { user: req.user || null, title: "Page Not Found", message: "The page you're looking for doesn't exist or has been moved." }, 404);
});

// Centralized error handler — catches all unhandled errors from routes
app.onError(errorHandler);

// Scheduled tasks
var scheduler = require("./lib/scheduler");
var expiry = require("./lib/expiry");
var db = require("./lib/db");
scheduler.register("file_expiry_cleanup", 3600000, expiry.cleanupExpired); // hourly
scheduler.register("email_sends_cleanup", 86400000, function () { // daily
  try {
    var cutoff = new Date(Date.now() - 90 * 86400000).toISOString(); // 90 days
    db.rawExec("DELETE FROM email_sends WHERE createdAt < ?", cutoff);
  } catch (_e) {}
});
scheduler.register("expired_tokens_cleanup", 86400000, function () { // daily
  try {
    var now = new Date().toISOString();
    db.rawExec("DELETE FROM verification_tokens WHERE expiresAt < ?", now);
  } catch (_e) {}
});
scheduler.register("expired_bundles_cleanup", 3600000, function () { // hourly
  try {
    var now = new Date().toISOString();
    db.rawExec("DELETE FROM bundles WHERE status = 'uploading' AND createdAt < ?",
      new Date(Date.now() - 24 * 3600000).toISOString()); // stale uploads > 24h
  } catch (_e) {}
});
scheduler.register("chunk_gc", 3600000, function () { // hourly
  try { require("./app/jobs/chunk-gc.job").cleanupStaleChunks(); } catch (_e) {}
});
scheduler.register("expired_invites_cleanup", 86400000, function () { // daily
  try {
    var now = new Date().toISOString();
    db.rawExec("DELETE FROM invites WHERE status = 'pending' AND expiresAt < ?", now);
  } catch (_e) {}
});
scheduler.register("expired_access_codes_cleanup", 3600000, function () { // hourly
  try { require("./app/jobs/expiry-cleanup.job").cleanupExpiredAccessCodes(); } catch (_e) {}
});
scheduler.register("incremental_vacuum", 86400000, function () { // daily
  try { db.rawExec("PRAGMA incremental_vacuum(100)"); } catch (_e) {} // reclaim ~100 pages
});
scheduler.start();

// Start
const server = app.listen(config.port, () => {
  logger.info("HermitStash is running", {
    url: "http://localhost:" + config.port,
    storage: config.storage.backend + " -> " + storage.uploadDir,
    email: config.email.host || "disabled",
    auth: (config.localAuth ? "local" : "") + (config.localAuth && config.google.clientID ? " + " : "") + (config.google.clientID ? "google" : ""),
    timeout: config.uploadTimeout / 1000 + "s",
    concurrency: config.uploadConcurrency,
  });
  audit.log(audit.ACTIONS.SERVER_STARTED, { performedBy: "system", details: "port: " + config.port + ", storage: " + config.storage.backend });
});
server.timeout = config.uploadTimeout;

// Graceful shutdown — stop accepting connections, drain in-flight requests, then exit
var shuttingDown = false;
function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info("Shutdown initiated", { signal: signal });

  // Stop accepting new connections
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
