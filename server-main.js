// -- Core libs --
var path = require("path");
var fs = require("fs");
var url = require("node:url");

// -- lib/ modules --
var config = require("./lib/config");
var C = require("./lib/constants");
var { Router } = require("./lib/vendor/blamejs").router;
var { sessionMiddleware } = require("./lib/session");
var db = require("./lib/db");
var { users } = db;
;
var storage = require("./lib/storage");
var audit = require("./lib/audit");
var logger = require("./app/shared/logger");
var { sendHtml } = require("./lib/template");
var certUtils = require("./lib/cert-utils");
var mtlsCa = require("./lib/mtls-ca");

// WebSocket upgrade — handshake handled by b.websocket.handleUpgrade,
// which writes the 101 and returns a WebSocketConnection (or null on
// handshake failure with the response already sent). rejectUpgrade is
// for HS-side auth/scope failures that need to refuse BEFORE the
// handshake completes; it writes a plain HTTP/1.1 response and closes.
function rejectUpgrade(socket, statusCode, message) {
  try {
    socket.write("HTTP/1.1 " + statusCode + " " + message + "\r\n\r\n");
    socket.destroy();
  } catch (_e) { /* socket may have already closed — rejection complete either way */ }
}
var syncEmitter = require("./lib/sync-emitter");
var rateLimit = require("./lib/rate-limit");

// -- vendored framework --
var b = require("./lib/vendor/blamejs");
var apiEncryptKeypair = require("./lib/api-encrypt-keypair");

// Shared scheduler instance (b.scheduler.create() returns fresh per call,
// so register-here-getStatus-from-routes/admin needs a shared module-
// scoped instance). Created once at boot.
var scheduler = require("./lib/scheduler");

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
var { AppError } = require("./app/shared/errors");
var chunkGcJob = require("./app/jobs/chunk-gc.job");
var expiryCleanupJob = require("./app/jobs/expiry-cleanup.job");
var orphanCleanupJob = require("./app/jobs/orphan-cleanup.job");
var certExpiryJob = require("./app/jobs/cert-expiry.job");
var backupJob = require("./app/jobs/backup.job");

// Allow res.redirect() to send users to Google's OAuth endpoint. Listed
// explicitly per origin — wildcards aren't accepted, and HTTP origins
// are refused at construction. Add other OAuth providers here when wired.
var app = new Router({
  allowedRedirectOrigins: ["https://accounts.google.com"],
});

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
  var initialPassword = b.crypto.generateBytes(12).toString("base64").replace(/[+/=]/g, "").slice(0, 16);
  b.auth.password.hash(initialPassword).then(function (hash) {
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
// Pre-session middleware pipeline composed via b.middleware.composePipeline
// (v0.9.43+). The entry array IS the order; the composer detects conflicts at
// registration time (duplicate names / non-monotonic positions / canonical
// mismatches) and emits a system.middleware.compose.pipeline_built audit at
// boot. Canonical positions are documented in
// lib/vendor/blamejs/lib/middleware/compose-pipeline.js — names matching
// CANONICAL_POSITIONS get warning-on-mismatch; HS-specific names get an
// explicit position number in the slot they belong to.
app.use(b.middleware.composePipeline([
  { name: "requestId",        mw: require("./middleware/request-id") },
  // Web-guard runs early so we avoid any template/CSP/static processing for
  // requests that will be dropped. No-op when config.enforceMtls is false
  // (default), so existing deployments see zero behavior change.
  { name: "webGuard",         mw: require("./middleware/web-guard"),       position: 6 },
  { name: "securityHeaders",  mw: require("./middleware/security-headers") },
  // Restrictive CSP override for user-uploaded content (custom logos) —
  // defense in depth against SVG XSS. Runs AFTER securityHeaders (position
  // 25) so its broader CSP gets overwritten for the gated paths only.
  { name: "uploadedAssetsCsp", mw: function (req, res, next) {
    if (req.pathname && (req.pathname.startsWith("/img/custom/") || req.pathname.startsWith("/img/stash/"))) {
      res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");
      res.setHeader("X-Content-Type-Options", "nosniff");
    }
    next();
  }, position: 26 },
  { name: "ipCheck",          mw: require("./middleware/ip-check"),         position: 27 },
  { name: "botGuard",         mw: require("./middleware/bot-guard") },
  { name: "cors",             mw: require("./middleware/cors"),              position: 44 },
  // b.staticServe adds ETag/304 conditional handling + RFC 7233 Range over
  // the curated build output in public/. contentSafety is disabled because
  // this directory holds operator-controlled assets (CSS/JS bundles, fonts,
  // brand-logo SVGs exported by the design toolchain with <style>/PI markers
  // the strict guard refuses); the SVG-XSS surface is the user-uploaded
  // logo dirs, gated separately by uploadedAssetsCsp + serveLogoFrom. Serves
  // GET/HEAD, falls through with next() on miss/dir so the logo routes below
  // still resolve.
  { name: "staticAssets",     mw: b.staticServe.create({
      root: path.join(__dirname, "public"),
      contentSafety: null,
      contentSafetyDisabledReason: "operator-curated public build output (css/js/fonts/brand-svg); no untrusted uploads served from this mount",
    }), position: 45 },
]));

// Serve admin custom logo + per-stash logos from the writable data directory.
// These are user-uploaded assets that can't live under public/img/ because the
// app source tree is read-only in Docker. Must come AFTER the staticAssets
// middleware so its 404 fallthrough reaches us; must come BEFORE auth-
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

// Health check — before auth so it's fast and unauthenticated. CORS is
// handled by the global `cors` middleware (position 44) using CORS_ORIGINS;
// the gateway origin needs to be on that allowlist like any other cross-
// origin caller.
app.get("/health", function (req, res) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() }));
});
app.get("/sitemap.xml", function (req, res) {
  var origin = originPolicy.getOrigin();
  var today = new Date().toISOString().split("T")[0];
  res.writeHead(200, { "Content-Type": "application/xml", "Cache-Control": "public, max-age=86400" });
  res.end('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n<url><loc>' + origin + '/</loc><lastmod>' + today + '</lastmod><changefreq>weekly</changefreq><priority>1.0</priority></url>\n<url><loc>' + origin + '/drop</loc><lastmod>' + today + '</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n<url><loc>' + origin + '/privacy</loc><changefreq>monthly</changefreq><priority>0.3</priority></url>\n<url><loc>' + origin + '/terms</loc><changefreq>monthly</changefreq><priority>0.3</priority></url>\n</urlset>');
});
// Sync enrollment — before auth so unauthenticated clients can redeem codes
// Operator-tunable: sites with multi-device fleets may legitimately need
// more than 5 enrollments / 5 min from the same source IP (e.g. a kiosk
// rollout from one provisioning workstation). Codes are 64-bit-entropy
// one-time-use one-hour-expiry, so the lower bound on attacker brute-force
// stays cosmically out of reach at any reasonable cap. Default stays 5.
var SYNC_ENROLL_MAX = parseInt(process.env.SYNC_ENROLL_MAX, 10) || 5;
app.post("/sync/enroll", rateLimit.guard({ scope: "sync-enroll", max: SYNC_ENROLL_MAX, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async function (req, res) {
  try {
    var body = (await b.parsers.json(req)) || {};
    var code = String(body.code || "").trim().toUpperCase();
    if (!code) {
      return b.problemDetails.send(res, {
        type: "https://hermitstash.com/problems/validation-error",
        title: "Validation Error",
        status: 400,
        detail: "Enrollment code required.",
      });
    }

    // Look up by hash
    var codeHash = b.crypto.namespaceHash(C.HASH_PREFIX.ENROLLMENT, code);
    var records = db.enrollmentCodes.find({ status: "pending" })
      .filter(function (r) { return r.codeHash === codeHash && r.expiresAt > new Date().toISOString(); });

    if (records.length === 0) {
      return b.problemDetails.send(res, {
        type: "https://hermitstash.com/problems/auth-required",
        title: "Auth Required",
        status: 401,
        detail: "Invalid or expired enrollment code.",
      });
    }

    var record = records[0];

    // Mark as redeemed (one-time use)
    db.enrollmentCodes.update({ _id: record._id }, { $set: { status: "redeemed" } });

    // Stash-bound enrollments (the default flow from routes/stash.js's
    // sync-token issuer) record stashId but leave bundleId null because
    // the bundle binding lives on the stash row. Resolve it here so the
    // client gets a populated bundleId without having to re-query the
    // server — saveSyncConfig in hermitstash-sync requires either
    // bundleId or shareId, and a missing value means the daemon can
    // never establish the sync target.
    var resolvedBundleId = record.bundleId || null;
    if (!resolvedBundleId && record.stashId) {
      try {
        var stash = db.customerStash.findOne({ _id: record.stashId });
        if (stash && stash.syncBundleId) resolvedBundleId = stash.syncBundleId;
      } catch (_e) { /* stash lookup best-effort — fall through with null */ }
    }

    // Resolve shareId from the bundle row. Sync clients need this for the
    // initial-sync pull (`GET /b/:shareId` seeds the daemon with the
    // bundle's existing files at enroll-time); without it the WebSocket
    // connection establishes but the local mirror starts empty and only
    // catches files uploaded AFTER connect.
    var resolvedShareId = null;
    if (resolvedBundleId) {
      try {
        var bundle = db.bundles.findOne({ _id: resolvedBundleId });
        if (bundle && bundle.shareId) resolvedShareId = bundle.shareId;
      } catch (_e) { /* bundle lookup best-effort — fall through with null */ }
    }

    // Return the provisioning bundle
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      success: true,
      apiKey: record.apiKey || null,
      clientCert: record.clientCert,
      clientKey: record.clientKey,
      caCert: record.caCert,
      stashId: record.stashId || null,
      bundleId: resolvedBundleId,
      shareId: resolvedShareId,
      reissue: record.reissue || false,
    }));

    audit.log(audit.ACTIONS.ENROLLMENT_REDEEMED, { details: "Sync enrollment code redeemed", req: req });
  } catch (err) {
    // Don't leak the specific error to the client (it may reference DB rows,
    // crypto state, etc.) — but log it so operators can diagnose failed
    // enrollment attempts.
    logger.error("[sync/enroll] Error", { error: err.message, stack: err.stack });
    b.problemDetails.send(res, {
      type: "https://hermitstash.com/problems/internal-error",
      title: "Internal Error",
      status: 500,
      detail: "Enrollment failed.",
    });
  }
});

// Sync cert renewal — scope + cert-binding checks come from the shared
// sync-guards middleware. The endpoint itself only does things specific to
// renewal: presence-of-cert (required for this endpoint even if the key has
// no certFingerprint — the cert proof-of-possession IS the second factor),
// revocation check, and actual cert generation.
app.post("/sync/renew-cert",
  rateLimit.guard({ scope: "sync-renew", max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }),
  require("./middleware/sync-guards").requireSyncAuth({ requireBundle: false }),
  async function (req, res) {
    try {
      // Renewal REQUIRES a client certificate — not just "matches fingerprint
      // if one is set". This is tighter than the generic sync-guards check;
      // the cert is the second authn factor for this specific operation.
      var peerCert = req.socket && req.socket.getPeerCertificate ? req.socket.getPeerCertificate() : null;
      if (!peerCert || !peerCert.subject || !req.socket.authorized) {
        return b.problemDetails.send(res, {
          type: "https://hermitstash.com/problems/forbidden",
          title: "Forbidden",
          status: 403,
          detail: "mTLS client certificate required for renewal.",
        });
      }

      // Check cert is not revoked (indexed lookup, not full-table scan)
      if (certUtils.isCertRevoked(peerCert.fingerprint256)) {
        return b.problemDetails.send(res, {
          type: "https://hermitstash.com/problems/forbidden",
          title: "Forbidden",
          status: 403,
          detail: "Certificate has been revoked.",
        });
      }

      // Generate new client certificate
      await mtlsCa.initCA();
      var newCert = await mtlsCa.generateClientCert({ cn: req.apiKey.prefix });
      if (!newCert) {
        return b.problemDetails.send(res, {
          type: "https://hermitstash.com/problems/internal-error",
          title: "Internal Error",
          status: 500,
          detail: "Certificate generation failed.",
        });
      }

      // Update cert tracking on the API key
      apiKeysRepo.update(req.apiKey._id, { $set: {
        certIssuedAt: newCert.issuedAt,
        certExpiresAt: newCert.expiresAt,
        certFingerprint: certUtils.certFingerprintSha3(newCert.cert),
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
      b.problemDetails.send(res, {
        type: "https://hermitstash.com/problems/internal-error",
        title: "Internal Error",
        status: 500,
        detail: "Certificate renewal failed.",
      });
    }
  }
);

app.use(sessionMiddleware);
app.use(attachUser);
app.use(require("./middleware/api-auth"));

// ---- blamejs per-session apiEncrypt protocol (v1.9.15) ----
//
// PQC payload-encryption protocol for routes that carry sensitive
// JSON bodies. Server publishes its long-lived keypair (ML-KEM-1024
// + P-384 ECDH hybrid) at /.well-known/blamejs-pubkey. Clients fetch
// the pubkey, generate a session key, wrap it to the server pubkey
// via the framework's encrypt envelope, send `_ek` on first JSON-
// bodied request, then continue the session with `_sid` + `_ctr` on
// subsequent requests.
//
// blamejs scope (narrow — JSON POSTs only):
//   GET    /.well-known/blamejs-pubkey   — pubkey advertisement
//   POST   /drop/init                    — bundle initialization
//   POST   /drop/finalize/:bundleId      — bundle finalization
//   POST   /sync/rename                  — sync file rename
//
// Out of blamejs scope (handled by legacy api-encrypt's Bearer-skip
// path): GET /b/:shareId, DELETE /files/:fileId, multipart uploads,
// binary downloads. These go plaintext for Bearer-authenticated
// clients (sync) and stay legacy-encrypted for cookie-authenticated
// clients (browser). TLS / mTLS protects the wire for plaintext
// paths; the legacy layer continues to set res._apiKey so HTML
// templates render the apiKey for browser-side JS.
//
// Legacy api-encrypt is carved out for blamejs scope so the two
// layers never both wrap res.json on the same request.
var blamejsKeypair = apiEncryptKeypair.loadOrGenerate();
var blamejsApiEncrypt = b.middleware.apiEncrypt({
  keypair:     blamejsKeypair,
  keying:      "per-session",
  exemptPaths: ["/.well-known/blamejs-pubkey"],
});
var blamejsBodyParser = b.middleware.bodyParser({
  json:       { limit: b.constants.BYTES.mib(2) },
  urlencoded: false,
  text:       false,
  raw:        false,
  multipart:  false,
});

// blamejs apiEncrypt scope is gated on TWO things: (1) the route is in
// the carve-out list below, AND (2) the request is Bearer-authenticated
// (`req.apiKey` set by api-auth). Cookie-authenticated browser clients
// fall through to legacy api-encrypt — public/js/api.js wraps fetch with
// the legacy `{_e, _t}` envelope and does not speak the blamejs `_ek/
// _ct/_ts/_nonce` shape. Mixing the two layers on the same request is
// what produced "encrypted-payload-required" rejections on browser
// uploads to /drop/init when the gate matched only on path. Bearer-
// authenticated sync clients speak the blamejs envelope; cookie-
// authenticated browsers continue on legacy until a future browser-side
// migration to the blamejs envelope.
//
// /.well-known/blamejs-pubkey stays open to all callers — it's the
// pubkey advertisement that bootstraps blamejs sessions for Bearer
// clients in the first place.
function isBlamejsApiEncryptPath(req) {
  var p = req.pathname || "";
  if (p === "/.well-known/blamejs-pubkey") return true;
  if (!req.apiKey) return false;
  if (p === "/drop/init") return req.method === "POST";
  if (p.indexOf("/drop/finalize/") === 0) return req.method === "POST";
  if (p === "/sync/rename") return req.method === "POST";
  return false;
}

// Legacy api-encrypt — skip when blamejs handles the path. The carve-out
// list mirrors isBlamejsApiEncryptPath() so the two layers never both
// wrap res.json on the same request.
var legacyApiEncrypt = require("./middleware/api-encrypt");
app.use(function legacyApiEncryptCarve(req, res, next) {
  if (isBlamejsApiEncryptPath(req)) return next();
  return legacyApiEncrypt(req, res, next);
});

// blamejs body-parser — populates req.body from JSON for blamejs paths
// so the apiEncrypt middleware (which reads req.body, not the stream)
// can decrypt. Skipped for non-body methods so the pubkey GET passes
// straight through to its route handler.
app.use(function blamejsBodyParserGate(req, res, next) {
  if (!isBlamejsApiEncryptPath(req)) return next();
  if (req.method !== "POST" && req.method !== "PUT" && req.method !== "PATCH") return next();
  return blamejsBodyParser(req, res, next);
});

// blamejs apiEncrypt — decrypts `_ek/_ct/_ts/_nonce` (or `_sid/_ctr/_ct`
// on subsequent requests) and replaces req.body with the plaintext.
// Wraps res.json to encrypt outgoing responses with the session key.
// The pubkey route is in exemptPaths above so this layer no-ops there.
app.use(function blamejsApiEncryptGate(req, res, next) {
  if (!isBlamejsApiEncryptPath(req)) return next();
  return blamejsApiEncrypt(req, res, next);
});

// publishPublicKey route — plain-JSON pre-encrypt advertisement of the
// server's hybrid keypair. Clients pin / rotate against this document.
app.get("/.well-known/blamejs-pubkey", blamejsApiEncrypt.publishPublicKey());

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

// First-run setup redirect — admin must complete setup before using the app.
// Bearer-authed sync clients bypass: api-auth resolves a sync API key to its
// owner (the admin user), which would otherwise trigger the wizard redirect
// even when everything is correctly configured at the transport level.
// Setup is a browser-only flow; programmatic callers should never see the 302.
app.use(function (req, res, next) {
  if (config.setupComplete) return next();
  if (req.apiKey) return next();
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

// Forced TOTP re-enrollment guard — when a session has used a legacy SHA-1
// TOTP secret to satisfy 2FA, every subsequent request is gated on completing
// the re-pair to SHA-512 (set in routes/two-factor.js /2fa/verify). The guard
// allows: static assets, the re-enroll page + its API endpoints, logout,
// and the auth routes themselves so the user can sign out cleanly.
app.use(function (req, res, next) {
  if (!req.session || req.session.requiresTotpReEnroll !== "true") return next();
  var p = req.pathname || "";
  if (p === "/2fa/re-enroll" || p === "/2fa/re-enroll/start" || p === "/2fa/re-enroll/confirm") return next();
  if (p === "/auth/logout" || p === "/logout") return next();
  if (p.startsWith("/css") || p.startsWith("/js") || p.startsWith("/img") || p.startsWith("/fonts")) return next();
  // HTML navigations get redirected; XHR/JSON callers get a structured 403.
  var accept = (req.headers && req.headers.accept) || "";
  if (accept.indexOf("text/html") !== -1) {
    res.writeHead(302, { Location: "/2fa/re-enroll" });
    return res.end();
  }
  // This problem document carries `code` + `redirect` extension fields the
  // browser reads to navigate to the re-enroll page, so it can't collapse to a
  // bare thrown AppError (the error handler emits only type/title/status/detail).
  // On an api-encrypt session res.json is the encrypting wrap; route the full
  // document through it so the body isn't shipped cleartext via res.end.
  var reenrollProblem = {
    type: "https://hermitstash.com/problems/forbidden",
    title: "Forbidden",
    status: 403,
    detail: "TOTP re-enrollment required.",
    code: "TOTP_REENROLL_REQUIRED",
    redirect: "/2fa/re-enroll",
  };
  if ((res._apiEncryptJson || req.apiEncryptSessionKey) && typeof res.json === "function") {
    res.statusCode = 403;
    res.setHeader("Cache-Control", "no-store");
    res.json(reenrollProblem);
    return;
  }
  b.problemDetails.send(res, reenrollProblem);
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
  rateLimit.guard({ scope: "sync-file-rename", max: 100, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }),
  require("./middleware/sync-guards").requireSyncAuth({ requireBundle: true }),
  async function (req, res) {
    var result = await handleSyncFileRename({
      bundleId: req.body.bundleId,
      oldRelativePath: req.body.oldRelativePath,
      newRelativePath: req.body.newRelativePath,
      req: req,
    });
    // Throw at the boundary so the centralized error handler renders the
    // problem-details document. On a sync session the response is wrapped by
    // apiEncrypt, so the handler routes the error through res.json — keeping
    // it encrypted rather than emitting cleartext via problemDetails.send.
    if (result.error) {
      var rs = result.status || 400;
      var code = rs === 404 ? "NOT_FOUND" : rs === 403 ? "FORBIDDEN" : rs === 409 ? "CONFLICT" : "VALIDATION_ERROR";
      throw new AppError(result.error, rs, code);
    }
    res.json(result);
  }
);

// Custom 404 page
app.onNotFound(function (req, res) {
  send(res, "error", { user: req.user || null, title: "Page Not Found", message: "The page you're looking for doesn't exist or has been moved." }, 404);
});

// Centralized error handler — catches all unhandled errors from routes
app.onError(errorHandler);

// Scheduled tasks
scheduler.register("file_expiry_cleanup", C.TIME.hours(1), function () { // hourly
  return expiryCleanupJob.cleanupExpiredFiles().catch(function (e) { logger.error("file_expiry_cleanup failed", { error: e.message }); });
});
scheduler.register("email_sends_cleanup", C.TIME.days(1), function () { // daily
  try {
    var cutoff = new Date(Date.now() - C.TIME.days(90)).toISOString(); // 90 days
    db.rawExec("DELETE FROM email_sends WHERE createdAt < ?", cutoff);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_tokens_cleanup", C.TIME.days(1), function () { // daily
  try {
    var now = new Date().toISOString();
    db.rawExec("DELETE FROM verification_tokens WHERE expiresAt < ?", now);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_bundles_cleanup", C.TIME.hours(1), function () { // hourly
  try {
    db.rawExec("DELETE FROM bundles WHERE status = 'uploading' AND createdAt < ?",
      new Date(Date.now() - C.TIME.days(1)).toISOString()); // stale uploads > 24h
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("chunk_gc", C.TIME.hours(1), function () { // hourly
  try { chunkGcJob.cleanupStaleChunks(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_invites_cleanup", C.TIME.days(1), function () { // daily
  try {
    var now = new Date().toISOString();
    db.rawExec("DELETE FROM invites WHERE status = 'pending' AND expiresAt < ?", now);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("tombstone_cleanup", C.TIME.days(1), function () { // daily
  try { expiryCleanupJob.cleanupTombstones(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_enrollment_codes_cleanup", C.TIME.hours(1), function () { // hourly
  try { expiryCleanupJob.cleanupExpiredEnrollmentCodes(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_access_codes_cleanup", C.TIME.hours(1), function () { // hourly
  try { expiryCleanupJob.cleanupExpiredAccessCodes(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_idempotency_keys_cleanup", C.TIME.hours(1), function () { // hourly
  try { expiryCleanupJob.cleanupExpiredIdempotencyKeys(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("bundle_lockout_cleanup", C.TIME.hours(1), function () { // hourly
  // Remove lockout rows that haven't seen an attempt in 24h.
  // lastAttempt is a raw ISO8601 string, safe to compare in SQL.
  try {
    var cutoff = new Date(Date.now() - C.TIME.days(1)).toISOString();
    db.rawExec("DELETE FROM bundle_access_lockouts WHERE lastAttempt < ?", cutoff);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("orphan_storage_cleanup", C.TIME.days(1), async function () { // daily
  try {
    var local = orphanCleanupJob.scanLocalOrphans();
    var deleted = orphanCleanupJob.deleteLocalOrphans(local.orphans);
    if (deleted > 0) logger.info("[orphan-cleanup] Removed " + deleted + " orphaned local files");
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("cert_expiry_check", C.TIME.days(1), function () { // daily
  return certExpiryJob.run().catch(function (e) { logger.error("cert_expiry_check failed", { error: e.message }); });
});
scheduler.register("incremental_vacuum", C.TIME.days(1), function () { // daily
  try { db.rawExec("PRAGMA incremental_vacuum(100)"); } catch (_e) { /* reclaim ~100 pages — best-effort */ }
});
scheduler.register("shm_usage_monitor", C.TIME.minutes(5), function () { // every 5 minutes
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
  scheduler.register("backup", config.backup.schedule || C.TIME.days(1), function () {
    return backupJob.run();
  }, { skipInitial: true, baseline: config.backup.timeOfDay, timezone: config.backup.timezone });
}
scheduler.start();

// TLS configuration — conditional HTTPS with PQC hybrid key exchange.
// v1.9.4: TLS_KEY can be plaintext (data/tls/privkey.pem) OR vault-sealed
// (data/tls/privkey.pem.sealed). Loaded via lib/pem-seal dispatch table
// keyed on TLS_KEY_SEALED env var (auto/required/disabled).
var TLS_CERT = process.env.TLS_CERT || path.join(C.PATHS.TLS_DIR, "fullchain.pem");
var TLS_KEY = process.env.TLS_KEY || path.join(C.PATHS.TLS_DIR, "privkey.pem");
var TLS_KEY_SEALED = TLS_KEY + ".sealed";
var pemSeal = require("./lib/pem-seal");
var PQC_ENFORCE = process.env.PQC_ENFORCE !== "false"; // default: true
var INTERNAL_TLS_PORT = parseInt(process.env.INTERNAL_TLS_PORT, 10) || 3001;
var tlsOptions = null;
var tlsEnabled = false;

// True when a TLS key is available in either form. Cert MUST be plaintext
// (it's public material; no sealing benefit).
function tlsKeyAvailable() {
  return fs.existsSync(TLS_KEY) || fs.existsSync(TLS_KEY_SEALED);
}

if (fs.existsSync(TLS_CERT) && tlsKeyAvailable()) {
  try {
    // Read from the singleton's resolved cert path — operators may have
    // overridden it via MTLS_CA_CERT to an absolute path outside DATA_DIR.
    var mtlsCaCert = mtlsCa.exists() ? fs.readFileSync(mtlsCa.paths.caCert) : null;
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
      key: pemSeal.loadPemDispatch(TLS_KEY, TLS_KEY_SEALED, "TLS_KEY_SEALED"),
      groups: b.constants.TLS_GROUP_PREFERENCE,
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
    logger.info("[TLS] PQC TLS enabled", {
      groups: b.constants.TLS_GROUP_PREFERENCE.join(" + "),
      keySealed: fs.existsSync(TLS_KEY_SEALED),
    });
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

  gateServer = b.pqcGate.create({ internalPort: INTERNAL_TLS_PORT, log: logger });
  gateServer.listen(config.port, function () {
    logger.info("HermitStash is running", {
      url: protocol + "://localhost:" + config.port,
      tls: "PQC enforced (" + b.constants.TLS_GROUP_PREFERENCE[0] + ")",
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

// Certificate reload on renewal (Let's Encrypt / ACME tooling updates the
// PEM files on disk). Watches the cert file at a 1-minute poll cadence so
// renewals propagate to the live TLS context within a minute.
//
// v1.9.4 ACME auto-reconcile: when TLS_KEY_SEALED=required and ACME tools
// drop a plaintext privkey.pem into the watched directory, this callback
// auto-seals the plaintext (pemSeal round-trips it through vault.seal),
// deletes the plaintext, and reloads. This means certbot/acme.sh hooks
// don't need to know about the sealing — they keep writing plaintext as
// they always have, and the watcher converts on the fly.
function reloadTlsContext() {
  // ACME reconcile: if we're in sealed-required mode and a plaintext
  // privkey.pem exists, that's a freshly-renewed key from ACME. Seal it.
  var modeRequired = (process.env.TLS_KEY_SEALED || "auto").toLowerCase() === "required";
  if (modeRequired && fs.existsSync(TLS_KEY) && !fs.existsSync(TLS_KEY_SEALED)) {
    try {
      pemSeal.sealPemFile(TLS_KEY, TLS_KEY_SEALED);
      logger.info("[TLS] Auto-sealed plaintext privkey from ACME renewal", {
        path: TLS_KEY_SEALED,
      });
    } catch (e) {
      logger.error("[TLS] Auto-seal failed during ACME reconcile", { error: e.message });
      return; // don't reload with potentially mismatched key
    }
  } else if (modeRequired && fs.existsSync(TLS_KEY) && fs.existsSync(TLS_KEY_SEALED)) {
    // Edge case: sealed already exists AND ACME wrote a new plaintext.
    // The plaintext is the FRESHER key; replace the sealed one with it.
    try {
      fs.unlinkSync(TLS_KEY_SEALED);
      pemSeal.sealPemFile(TLS_KEY, TLS_KEY_SEALED);
      logger.info("[TLS] Auto-sealed ACME renewal (replacing previous sealed key)", {
        path: TLS_KEY_SEALED,
      });
    } catch (e) {
      logger.error("[TLS] Auto-seal failed during ACME reconcile (replace path)", { error: e.message });
      return;
    }
  }

  try {
    var newContext = {
      cert: fs.readFileSync(TLS_CERT),
      key: pemSeal.loadPemDispatch(TLS_KEY, TLS_KEY_SEALED, "TLS_KEY_SEALED"),
      groups: b.constants.TLS_GROUP_PREFERENCE,
      minVersion: "TLSv1.3",
    };
    server.setSecureContext(newContext);
    logger.info("[TLS] Certificate reloaded");
  } catch (e) {
    logger.error("[TLS] Certificate reload failed", { error: e.message });
  }
}

if (tlsEnabled) {
  // Poll cadence: 1 minute (was 1 hour pre-v1.9.4). Spec §12.Q2 — cheap
  // polling is fine and shortens the ACME-renewal-to-active-key window.
  fs.watchFile(TLS_CERT, { interval: C.TIME.minutes(1) }, reloadTlsContext);
  // SIGHUP triggers an immediate reload — used by scripts/tls-key-seal.js
  // --reload after manually sealing a freshly-rotated key.
  process.on("SIGHUP", function () {
    logger.info("[TLS] SIGHUP received — reloading TLS context");
    reloadTlsContext();
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
var SYNC_HEARTBEAT_INTERVAL = C.TIME.seconds(30);
var SYNC_MAX_MESSAGES_PER_MIN = 60;
var SYNC_MAX_MESSAGE_SIZE = C.BYTES.kib(64);

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
  // headers, and browser history. b.requestHelpers.extractBearer also refuses
  // requests with multiple Authorization headers (CWE-345).
  var token = b.requestHelpers.extractBearer(req);
  if (!token) {
    return rejectUpgrade(socket, 401, "Unauthorized");
  }

  // Validate API key using the same mechanism as api-auth middleware
  var keyHash = b.crypto.sha3Hash(token);
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

  // Complete WebSocket handshake (b.websocket.handleUpgrade writes the
  // 101 and returns null on a malformed request with the response
  // already sent — no further rejectUpgrade needed in that case).
  var ws = b.websocket.handleUpgrade(req, socket, head, {
    maxMessageBytes: SYNC_MAX_MESSAGE_SIZE,
  });
  if (!ws) return;
  // b.websocket.WebSocketConnection.send() throws on a closed connection
  // (HS's previous impl was silent). Wrap every send so the delivery path
  // is fire-and-forget — close cleanup handles the EE unwiring on the
  // next tick. Local closure so the helper captures `ws` cleanly.
  function safeSend(data) {
    try { ws.send(data); } catch (_e) { /* connection closed mid-write */ }
  }

  // Register connection
  if (!syncConnections.has(bundleId)) syncConnections.set(bundleId, new Set());
  var connEntry = { ws: ws, apiKeyId: keyId };
  syncConnections.get(bundleId).add(connEntry);
  apiKeyConnectionCount.set(keyId, keyCount + 1);

  // Inbound message rate limiting
  var msgCount = 0;
  var msgResetTimer = setInterval(function () { msgCount = 0; }, C.TIME.minutes(1));
  msgResetTimer.unref();
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
      safeSend(JSON.stringify(ev));
    }
  }
  // Signal catch-up complete
  safeSend(JSON.stringify({ type: "heartbeat", seq: bundle.seq || 0, timestamp: new Date().toISOString() }));

  // Real-time event listener
  var syncListener = function (event) {
    try { safeSend(JSON.stringify(event)); } catch (_e) {}
  };
  syncEmitter.on("sync:" + bundleId, syncListener);

  // Send immediate heartbeat on connect so clients know the connection is live
  try {
    safeSend(JSON.stringify({ type: "heartbeat", seq: bundle.seq || 0, timestamp: new Date().toISOString() }));
  } catch (_e) { /* socket may have closed between upgrade and first write */ }

  // Heartbeat interval
  var heartbeatTimer = setInterval(function () {
    try {
      var freshBundle = bundlesRepo.findById(bundleId);
      safeSend(JSON.stringify({ type: "heartbeat", seq: freshBundle ? freshBundle.seq || 0 : 0, timestamp: new Date().toISOString() }));
      ws.ping();
    } catch (_e) { /* client disconnected between heartbeats — close handler runs next tick */ }
  }, SYNC_HEARTBEAT_INTERVAL);
  heartbeatTimer.unref();

  // Pong timeout detection
  var pongReceived = true;
  var pongCheckTimer = setInterval(function () {
    if (!pongReceived) {
      ws.close(1001, "Pong timeout");
      return;
    }
    pongReceived = false;
  }, SYNC_HEARTBEAT_INTERVAL);
  pongCheckTimer.unref();

  ws.on("pong", function () { pongReceived = true; });

  // Inbound message handling
  ws.on("message", function (data) {
    msgCount++;
    if (msgCount > SYNC_MAX_MESSAGES_PER_MIN) {
      violations++;
      safeSend(JSON.stringify({ type: "error", code: "rate_limited", message: "Too many messages", retryAfter: 60 }));
      if (violations >= 3) { ws.close(1008, "Rate limit exceeded"); }
      return;
    }
    if (data.length > SYNC_MAX_MESSAGE_SIZE) {
      safeSend(JSON.stringify({ type: "error", code: "message_too_large", message: "Max 64KB per message" }));
      return;
    }
    try {
      var msg = JSON.parse(data);
      if (!msg || !msg.type) {
        safeSend(JSON.stringify({ type: "error", code: "invalid_json", message: "Missing type field" }));
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
          safeSend(JSON.stringify(e));
        }
        var fb = bundlesRepo.findById(bundleId);
        safeSend(JSON.stringify({ type: "heartbeat", seq: fb ? fb.seq || 0 : 0, timestamp: new Date().toISOString() }));
      } else if (msg.type === "ping") {
        var pb = bundlesRepo.findById(bundleId);
        safeSend(JSON.stringify({ type: "heartbeat", seq: pb ? pb.seq || 0 : 0, timestamp: new Date().toISOString() }));
      } else {
        safeSend(JSON.stringify({ type: "error", code: "unknown_type", message: "Unrecognized message type: " + msg.type }));
      }
    } catch (_e) {
      safeSend(JSON.stringify({ type: "error", code: "invalid_json", message: "Invalid JSON" }));
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
      try { if (entry.ws && entry.ws.readyState === "open") entry.ws.close(1001, "Server shutting down"); } catch (_e) { /* socket may already be closed */ }
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
  }, C.TIME.seconds(10));
  forceTimer.unref();
}

process.on("SIGTERM", function () { gracefulShutdown("SIGTERM"); });
process.on("SIGINT", function () { gracefulShutdown("SIGINT"); });
