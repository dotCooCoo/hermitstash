var path = require("node:path");
var fs = require("node:fs");

// codebase-patterns:allow-file process-exit — this is the server entry point;
// boot-fatal aborts and graceful-shutdown exits (post-restore, mTLS CA regen, DB
// re-encrypt) are inherent to its role, not library code unilaterally exiting.
// codebase-patterns:allow-file raw-process-env — bootstrap reads env directly
// because it runs before (and in order to build) the config layer; config.js is
// the canonical reader for everything downstream.

var config = require("./lib/config");
var C = require("./lib/constants");
var { Router } = require("./lib/vendor/blamejs").router;
var { sessionMiddleware } = require("./lib/session");
var db = require("./lib/db");
var { users } = db;
var storage = require("./lib/storage");
var audit = require("./lib/audit");
var clientIp = require("./lib/client-ip");
var logger = require("./app/shared/logger");
var certUtils = require("./lib/cert-utils");
var runtimeState = require("./lib/runtime-state");
var mtlsCa = require("./lib/mtls-ca");

// For auth and scope failures that must refuse before the handshake completes.
// A failure after that point is b.websocket.handleUpgrade's to report.
function rejectUpgrade(socket, statusCode, message) {
  try {
    socket.write("HTTP/1.1 " + statusCode + " " + message + "\r\n\r\n");
    socket.destroy();
  } catch (_e) { /* socket may have already closed — rejection complete either way */ }
}
var syncEmitter = require("./lib/sync-emitter");
var rateLimit = require("./lib/rate-limit");

var b = require("./lib/vendor/blamejs");
var apiEncryptKeypair = require("./lib/api-encrypt-keypair");

// b.scheduler.create() returns a fresh instance per call, so jobs registered
// here would be invisible to routes/admin's status view without a shared one.
var scheduler = require("./lib/scheduler");

var { emitError } = require("./middleware/respond-error");
var attachUser = require("./middleware/attach-user");
var errorHandler = require("./middleware/error-handler");

var startupChecks = require("./app/bootstrap/startup-checks");
var txHelper = require("./app/data/db/transaction");
var originPolicy = require("./app/security/origin-policy");
var adminFence = require("./app/security/admin-fence");
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

// Every res.redirect() target must be listed here. Wildcards are not accepted
// and an http:// origin is refused at construction.
var app = new Router({
  allowedRedirectOrigins: ["https://accounts.google.com"],
});

var dataDir = C.DATA_DIR;
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (config.storage.backend === "local") {
  if (!fs.existsSync(storage.uploadDir)) fs.mkdirSync(storage.uploadDir, { recursive: true });
}

startupChecks.run();

// The generated password is written to disk as well as logged, because a
// container's first-boot output is often gone by the time anyone reads it.
// The setup wizard deletes the file on completion.
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

txHelper.init(db.getDb ? db.getDb() : null);

// The array order is the pipeline order. A name the framework recognises picks
// up its canonical position; anything HS-specific needs an explicit one, and
// the composer refuses duplicates and out-of-order positions at boot.
app.use(b.middleware.composePipeline([
  { name: "requestId",        mw: require("./middleware/request-id") },
  // Early, so a request that will be dropped costs no template, CSP or static
  // work. Does nothing unless config.enforceMtls is on.
  { name: "webGuard",         mw: require("./middleware/web-guard"),       position: 6 },
  // Strips the `tailscale serve` identity headers from every peer except the
  // loopback serve proxy, and must run before anything can read a forged copy.
  // Strips them even with Tailscale disabled.
  { name: "tailscaleIdentity", mw: require("./lib/tailscale").middleware, position: 7 },
  { name: "securityHeaders",  mw: require("./middleware/security-headers") },
  // User-uploaded logos get a CSP of their own against SVG XSS. Runs after
  // securityHeaders so it overwrites the broader policy on these paths only.
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
  // Falls through with next() on a miss, so the logo routes below still resolve.
  { name: "staticAssets",     mw: b.staticServe.create({
      root: path.join(__dirname, "public"),
      contentSafety: null,
      contentSafetyDisabledReason: "operator-curated public build output (css/js/fonts/brand-svg); no untrusted uploads served from this mount",
    }), position: 45 },
  // Without this the pipeline fails OPEN: composePipeline re-emits an inner
  // throw as next(err), the outer router's next ignores the error argument, and
  // the request reaches its route handler with ipCheck, securityHeaders,
  // botGuard and cors all skipped. Ending the response here halts the chain.
  { name: "errorHandler", position: 90, mw: function (err, req, res, _next) {
    try { require("./app/shared/logger").error("security pipeline error — failing closed", { error: err && err.message, path: req && req.pathname }); } catch (_e) { /* logging must never break the fail-closed response */ }
    if (!res.writableEnded) {
      b.problemDetails.send(res, { type: "https://hermitstash.com/problems/internal", title: "Internal Server Error", status: 500 });
    }
  } },
]));

// Uploaded logos live under the data directory because the source tree is
// read-only in Docker. Mounted after staticAssets so its 404 falls through to
// here, and before the authenticated routes so public pages can load them.
function serveLogoFrom(dir) {
  return function (req, res) {
    var name = String(req.params.name || "").replace(/[^A-Za-z0-9._-]/g, "");
    if (!name) { res.writeHead(404); return res.end(); }
    // Catches the sibling-prefix escape a bare startsWith(dir) misses.
    var resolved = b.safePath.confineToBase(dir, name);
    if (!resolved) { res.writeHead(404); return res.end(); }
    if (!fs.existsSync(resolved)) { res.writeHead(404); return res.end(); }
    var ext = path.extname(resolved).toLowerCase();
    var mime = ext === ".svg" ? "image/svg+xml"
             : ext === ".png" ? "image/png"
             : ext === ".jpg" || ext === ".jpeg" ? "image/jpeg"
             : ext === ".gif" ? "image/gif"
             : ext === ".webp" ? "image/webp"
             : "application/octet-stream";
    // O_NOFOLLOW refuses a symlink swapped in after the check above (CWE-367).
    var fd;
    try {
      fd = b.atomicFile.openNoFollowSync(resolved);
    } catch (_e) {
      res.writeHead(404); return res.end();
    }
    res.writeHead(200, { "Content-Type": mime, "Cache-Control": "public, max-age=3600" });
    var stream = fs.createReadStream(resolved, { fd: fd });
    stream.on("error", function () { if (!res.writableEnded) res.end(); });
    stream.pipe(res);
  };
}
app.get("/img/custom/:name", serveLogoFrom(C.PATHS.CUSTOM_LOGO_DIR));
app.get("/img/stash/:name", serveLogoFrom(C.PATHS.STASH_LOGO_DIR));

// Moves logos left under public/img/ by an older install into DATA_DIR.
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

// A gateway polling this cross-origin needs its origin in CORS_ORIGINS like any
// other caller. `status` stays "ok" whenever the process is serving, because
// that is what the Dockerfile, compose and kubernetes probes test — maintenance
// is reported alongside it so an orchestrator does not conclude the container
// is dead while an operator works on it.
app.get("/health", function (req, res) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    status: "ok",
    maintenance: !!config.maintenanceMode,
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  }));
});
app.get("/sitemap.xml", function (req, res) {
  var origin = originPolicy.getOrigin();
  var today = new Date().toISOString().split("T")[0];
  res.writeHead(200, { "Content-Type": "application/xml", "Cache-Control": "public, max-age=86400" });
  res.end('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n<url><loc>' + origin + '/</loc><lastmod>' + today + '</lastmod><changefreq>weekly</changefreq><priority>1.0</priority></url>\n<url><loc>' + origin + '/drop</loc><lastmod>' + today + '</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n<url><loc>' + origin + '/privacy</loc><changefreq>monthly</changefreq><priority>0.3</priority></url>\n<url><loc>' + origin + '/terms</loc><changefreq>monthly</changefreq><priority>0.3</priority></url>\n</urlset>');
});
// Raise this where a fleet enrolls from one provisioning workstation. Codes
// carry 64 bits of entropy and expire in an hour, so a higher cap does not put
// brute force in reach.
var SYNC_ENROLL_MAX = parseInt(process.env.SYNC_ENROLL_MAX, 10) || 5;
app.post("/sync/enroll", rateLimit.guard({ max: SYNC_ENROLL_MAX, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async function (req, res) {
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

    // Query the blind index rather than filtering pending rows in JS: that
    // would field-decrypt every provisioned credential bundle on an
    // unauthenticated request, and compare the code in plaintext.
    var codeHash = b.crypto.namespaceHash(C.HASH_PREFIX.ENROLLMENT, code);
    var nowIso = new Date().toISOString();
    var records = db.enrollmentCodes.find({ codeHash: codeHash, status: "pending" })
      .filter(function (r) { return r.expiresAt > nowIso; });

    if (records.length === 0) {
      return b.problemDetails.send(res, {
        type: "https://hermitstash.com/problems/auth-required",
        title: "Auth Required",
        status: 401,
        detail: "Invalid or expired enrollment code.",
      });
    }

    var record = records[0];

    // status:"pending" in the WHERE makes this a compare-and-swap, so of two
    // concurrent redemptions the loser changes no rows and is refused here,
    // before any certificate or key is emitted (CWE-367).
    var claimed = db.enrollmentCodes.update({ _id: record._id, status: "pending" }, { $set: { status: "redeemed" } });
    if (!claimed) {
      return b.problemDetails.send(res, {
        type: "https://hermitstash.com/problems/auth-required",
        title: "Auth Required", status: 401, detail: "Invalid or expired enrollment code.",
      });
    }

    // The cert-expiry job stages a renewal code without moving the key's
    // certFingerprint, so an offline client's current certificate keeps working
    // — rebinding at staging time would 403 it everywhere including the routes
    // it needs to recover. Redemption is where that binding is owed, so it
    // moves here, with the new lifetime, for the next sweep to measure.
    if (record.reissue && record.originalKeyId && record.clientCert) {
      try {
        apiKeysRepo.update(record.originalKeyId, { $set: {
          certFingerprint: certUtils.certFingerprintSha3(record.clientCert),
          certIssuedAt: new Date().toISOString(),
          certExpiresAt: record.certExpiresAt || null,
        }});
      } catch (_e) { /* realignment best-effort — client can fall back to /sync/renew-cert */ }
    }

    // A stash-bound enrollment leaves bundleId null because the binding lives
    // on the stash row. The sync client needs either bundleId or shareId to
    // save a config at all, so both are resolved here rather than left to it.
    var resolvedBundleId = record.bundleId || null;
    if (!resolvedBundleId && record.stashId) {
      try {
        var stash = db.customerStash.findOne({ _id: record.stashId });
        if (stash && stash.syncBundleId) resolvedBundleId = stash.syncBundleId;
      } catch (_e) { /* stash lookup best-effort — fall through with null */ }
    }

    // Without shareId the daemon connects but its mirror starts empty: it has
    // no way to pull the bundle's existing files, only ones uploaded later.
    var resolvedShareId = null;
    if (resolvedBundleId) {
      try {
        var bundle = db.bundles.findOne({ _id: resolvedBundleId });
        if (bundle && bundle.shareId) resolvedShareId = bundle.shareId;
      } catch (_e) { /* bundle lookup best-effort — fall through with null */ }
    }

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

    // The response was assembled from the in-memory record, so the row holds a
    // raw API key, a client key and a CA certificate that nothing will read
    // again. Leaving it for the hourly sweep keeps those at rest for no reason.
    try { db.enrollmentCodes.remove({ _id: record._id }); } catch (_e) { /* sweep backstop */ }

    audit.log(audit.ACTIONS.ENROLLMENT_REDEEMED, { details: "Sync enrollment code redeemed", req: req });
  } catch (err) {
    logger.error("[sync/enroll] Error", { error: err.message, stack: err.stack });
    b.problemDetails.send(res, {
      type: "https://hermitstash.com/problems/internal-error",
      title: "Internal Error",
      status: 500,
      detail: "Enrollment failed.",
    });
  }
});

// A certificate must be presented even when the key carries no
// certFingerprint: possession of it is the second factor for this endpoint.
// Scope and binding checks come from the sync-guards middleware.
app.post("/sync/renew-cert",
  rateLimit.guard({ max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }),
  require("./middleware/sync-guards").requireSyncAuth({ requireBundle: false }),
  async function (req, res) {
    try {
      var peerCert = req.socket && req.socket.getPeerCertificate ? req.socket.getPeerCertificate() : null;
      if (!peerCert || !peerCert.subject || !req.socket.authorized) {
        return b.problemDetails.send(res, {
          type: "https://hermitstash.com/problems/forbidden",
          title: "Forbidden",
          status: 403,
          detail: "mTLS client certificate required for renewal.",
        });
      }

      if (certUtils.isPeerCertRevoked(peerCert)) {
        return b.problemDetails.send(res, {
          type: "https://hermitstash.com/problems/forbidden",
          title: "Forbidden",
          status: 403,
          detail: "Certificate has been revoked.",
        });
      }

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

// Two payload-encryption layers run here, and they must never both wrap
// res.json on one request — that is what the carve-outs below exist for.
// isBlamejsApiEncryptPath() is the single definition of which layer owns a
// request; everything else defers to it.
var blamejsKeypair;
try {
  blamejsKeypair = apiEncryptKeypair.loadOrGenerate();
} catch (e) {
  logger.error("api-encrypt keypair load failed", { error: e && e.message });
  process.exit(1);
}
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

// Bearer clients speak the blamejs envelope; browsers speak the legacy one, so
// the gate needs `req.apiKey` as well as the path. Matching on path alone
// rejected browser uploads to /drop/init as "encrypted-payload-required".
// The pubkey route stays open to everyone — it bootstraps the sessions.
function isBlamejsApiEncryptPath(req) {
  var p = req.pathname || "";
  if (p === "/.well-known/blamejs-pubkey") return true;
  if (!req.apiKey) return false;
  if (p === "/drop/init") return req.method === "POST";
  if (p.indexOf("/drop/finalize/") === 0) return req.method === "POST";
  if (p === "/sync/rename") return req.method === "POST";
  return false;
}

var legacyApiEncrypt = require("./middleware/api-encrypt");
app.use(function legacyApiEncryptCarve(req, res, next) {
  if (isBlamejsApiEncryptPath(req)) return next();
  return legacyApiEncrypt(req, res, next);
});

// apiEncrypt reads req.body rather than the stream, so the body has to be
// parsed before it can decrypt.
app.use(function blamejsBodyParserGate(req, res, next) {
  if (!isBlamejsApiEncryptPath(req)) return next();
  if (req.method !== "POST" && req.method !== "PUT" && req.method !== "PATCH") return next();
  return blamejsBodyParser(req, res, next);
});

app.use(function blamejsApiEncryptGate(req, res, next) {
  if (!isBlamejsApiEncryptPath(req)) return next();
  return blamejsApiEncrypt(req, res, next);
});

// Clients pin and rotate against this document.
app.get("/.well-known/blamejs-pubkey", blamejsApiEncrypt.publishPublicKey());

app.use(require("./app/security/csrf-policy").csrfMiddleware);

app.use(require("./middleware/maintenance"));

// Sits on top of requireAdmin rather than replacing it: requireAdmin stops the
// wrong user, this stops /admin being reachable at all from outside the
// operator's network, which is what limits the damage of a leaked credential.
// A miss answers 404, so a probe cannot tell the fence is there.
if (Array.isArray(config.adminAllowedCidrs) && config.adminAllowedCidrs.length > 0) {
  app.use(adminFence.create(config.adminAllowedCidrs));
  logger.info("[admin-fence] /admin restricted to operator CIDR allowlist", {
    cidrs: config.adminAllowedCidrs.length,
  });
}

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

// Setup is a browser flow, so a programmatic caller must never see the 302.
// api-auth resolves a sync API key to its owner — usually the admin — which
// would otherwise send a correctly configured client to the wizard.
app.use(function (req, res, next) {
  if (config.setupComplete) return next();
  if (req.apiKey) return next();
  if (req.pathname && (req.pathname.startsWith("/css") || req.pathname.startsWith("/js") || req.pathname.startsWith("/img"))) return next();
  if (req.pathname && req.pathname.startsWith("/auth")) return next();
  if (req.pathname && req.pathname.startsWith("/admin/setup")) return next();
  if (req.user && req.user.role === "admin") {
    res.writeHead(302, { Location: "/admin/setup" });
    return res.end();
  }
  next();
});

// A session that satisfied 2FA with a legacy SHA-1 secret is held here until it
// re-pairs to SHA-512. Signing out stays reachable, so nobody is trapped.
app.use(function (req, res, next) {
  if (!req.session || req.session.requiresTotpReEnroll !== "true") return next();
  var p = req.pathname || "";
  if (p === "/2fa/re-enroll" || p === "/2fa/re-enroll/start" || p === "/2fa/re-enroll/confirm") return next();
  if (p === "/auth/logout" || p === "/logout") return next();
  if (p.startsWith("/css") || p.startsWith("/js") || p.startsWith("/img") || p.startsWith("/fonts")) return next();
  var accept = (req.headers && req.headers.accept) || "";
  if (accept.indexOf("text/html") !== -1) {
    res.writeHead(302, { Location: "/2fa/re-enroll" });
    return res.end();
  }
  // The `code` and `redirect` fields are what the browser navigates on, and a
  // thrown AppError would drop them — the error handler emits only
  // type/title/status/detail. res.json is the encrypting wrap on an
  // api-encrypt session, so the document goes through it rather than res.end.
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

// Takes bundleId directly, because a sync client has no shareId.
app.post("/sync/rename",
  rateLimit.guard({ max: 100, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }),
  require("./middleware/sync-guards").requireSyncAuth({ requireBundle: true }),
  async function (req, res) {
    var result = await handleSyncFileRename({
      bundleId: req.body.bundleId,
      oldRelativePath: req.body.oldRelativePath,
      newRelativePath: req.body.newRelativePath,
      req: req,
    });
    // Thrown rather than answered here: on a sync session res.json is the
    // encrypting wrap, and problemDetails.send would emit cleartext.
    if (result.error) {
      var rs = result.status || 400;
      var code = rs === 404 ? "NOT_FOUND" : rs === 403 ? "FORBIDDEN" : rs === 409 ? "CONFLICT" : "VALIDATION_ERROR";
      throw new AppError(result.error, rs, code);
    }
    res.json(result);
  }
);

// Content-negotiated: the error template for browsers, problem+json for the rest.
app.onNotFound(function (req, res) {
  emitError(req, res, {
    status: 404,
    code: "NOT_FOUND",
    htmlTitle: "Page Not Found",
    detail: "The page you're looking for doesn't exist or has been moved.",
  });
});

app.onError(errorHandler);

scheduler.register("file_expiry_cleanup", C.TIME.hours(1), function () {
  return expiryCleanupJob.cleanupExpiredFiles().catch(function (e) { logger.error("file_expiry_cleanup failed", { error: e.message }); });
});
scheduler.register("email_sends_cleanup", C.TIME.days(1), function () {
  try {
    var cutoff = new Date(Date.now() - C.TIME.days(90)).toISOString();
    db.rawExec("DELETE FROM email_sends WHERE createdAt < ?", cutoff);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_tokens_cleanup", C.TIME.days(1), function () {
  try {
    var now = new Date().toISOString();
    db.rawExec("DELETE FROM verification_tokens WHERE expiresAt < ?", now);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_bundles_cleanup", C.TIME.hours(1), function () {
  // Not a raw row DELETE: that would orphan the files and chunk directories.
  expiryCleanupJob.cleanupStaleBundles().catch(function (_e) { /* scheduled cleanup — retry next tick */ });
});
scheduler.register("chunk_gc", C.TIME.hours(1), function () {
  try { chunkGcJob.cleanupStaleChunks(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_invites_cleanup", C.TIME.days(1), function () {
  try {
    var now = new Date().toISOString();
    db.rawExec("DELETE FROM invites WHERE status = 'pending' AND expiresAt < ?", now);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("tombstone_cleanup", C.TIME.days(1), function () {
  try { expiryCleanupJob.cleanupTombstones(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_enrollment_codes_cleanup", C.TIME.hours(1), function () {
  try { expiryCleanupJob.cleanupExpiredEnrollmentCodes(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_access_codes_cleanup", C.TIME.hours(1), function () {
  try { expiryCleanupJob.cleanupExpiredAccessCodes(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("expired_idempotency_keys_cleanup", C.TIME.hours(1), function () {
  try { expiryCleanupJob.cleanupExpiredIdempotencyKeys(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("webhook_deliveries_cleanup", C.TIME.days(1), function () {
  try { expiryCleanupJob.cleanupWebhookDeliveries(); } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("bundle_lockout_cleanup", C.TIME.hours(1), function () {
  // lastAttempt is a raw ISO8601 string, so it compares correctly in SQL.
  try {
    var cutoff = new Date(Date.now() - C.TIME.days(1)).toISOString();
    db.rawExec("DELETE FROM bundle_access_lockouts WHERE lastAttempt < ?", cutoff);
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("orphan_storage_cleanup", C.TIME.days(1), async function () {
  try {
    var local = orphanCleanupJob.scanLocalOrphans();
    var deleted = orphanCleanupJob.deleteLocalOrphans(local.orphans);
    if (deleted > 0) logger.info("[orphan-cleanup] Removed " + deleted + " orphaned local files");
  } catch (_e) { /* scheduled cleanup — retry next tick */ }
});
scheduler.register("cert_expiry_check", C.TIME.days(1), function () {
  return certExpiryJob.run().catch(function (e) { logger.error("cert_expiry_check failed", { error: e.message }); });
});
scheduler.register("incremental_vacuum", C.TIME.days(1), function () {
  try { db.rawExec("PRAGMA incremental_vacuum(100)"); } catch (_e) { /* reclaim ~100 pages — best-effort */ }
});
scheduler.register("shm_usage_monitor", C.TIME.minutes(5), function () {
  if (process.platform === "win32") return; // statfsSync not available on Windows
  var tmpdir = process.env.HERMITSTASH_TMPDIR || (fs.existsSync("/dev/shm") ? "/dev/shm" : null);
  if (!tmpdir) return;
  try {
    var stats = fs.statfsSync(tmpdir);
    var totalMB = Math.round(stats.blocks * stats.bsize / C.BYTES.mib(1));
    var usedMB = Math.round((stats.blocks - stats.bfree) * stats.bsize / C.BYTES.mib(1));
    var pct = totalMB > 0 ? Math.round(usedMB / totalMB * 100) : 0;
    if (pct >= 90) {
      logger.error("[SHM] " + tmpdir + " is " + pct + "% full (" + usedMB + "/" + totalMB + " MB) — database writes may fail. Increase shm_size immediately.");
    } else if (pct >= 75) {
      logger.warn("[SHM] " + tmpdir + " is " + pct + "% full (" + usedMB + "/" + totalMB + " MB) — consider increasing shm_size.");
    }
  } catch (_e) {} // allow:silent-catch — statfsSync not available on all platforms
});
if (config.backup && config.backup.enabled) {
  // schedule(), not register(): register takes three parameters and discards an
  // options object, which drops the operator's time-of-day anchor and leaves
  // the backup firing at process start plus 24h, re-anchored by every restart.
  scheduler.schedule({
    name: "backup",
    every: config.backup.schedule || C.TIME.days(1),
    baseline: config.backup.timeOfDay,
    timezone: config.backup.timezone,
    run: function () { return backupJob.run(); },
  });
}

// A mismatch logs and continues by default, because an operator investigating
// one still wants the app up. AUDIT_CHAIN_STRICT turns it into a refusal.
if (config.auditChainEnabled) {
  var auditChainService = require("./app/domain/admin/audit.service");
  auditChainService.verifyAuditChain().then(function (result) {
    if (result && result.ok) {
      logger.info("[audit-chain] verified at boot", { rowsVerified: result.rowsVerified });
    } else {
      logger.error("[audit-chain] verification FAILED — audit log may have been tampered with", {
        reason: result && result.reason, breakAt: result && result.breakAt, breakRowId: result && result.breakRowId,
      });
      if (config.auditChainStrict) {
        logger.error("[audit-chain] AUDIT_CHAIN_STRICT is set — refusing to boot");
        process.exit(1);
      }
    }
  }).catch(function (e) {
    logger.error("[audit-chain] boot verification errored", { error: e && e.message });
    if (config.auditChainStrict) process.exit(1);
  });

  scheduler.register("audit_chain_verify", C.TIME.days(1), function () {
    return auditChainService.verifyAuditChain().then(function (result) {
      if (!result || !result.ok) {
        logger.error("[audit-chain] scheduled verification FAILED", {
          reason: result && result.reason, breakAt: result && result.breakAt, breakRowId: result && result.breakRowId,
        });
      }
    }).catch(function (e) { logger.error("audit_chain_verify failed", { error: e && e.message }); });
  });
}

scheduler.start();

// The key may be plaintext or vault-sealed; TLS_KEY_SEALED (auto, required or
// disabled) decides which forms lib/pem-seal will accept.
var TLS_CERT = process.env.TLS_CERT || path.join(C.PATHS.TLS_DIR, "fullchain.pem");
var TLS_KEY = process.env.TLS_KEY || path.join(C.PATHS.TLS_DIR, "privkey.pem");
var TLS_KEY_SEALED = TLS_KEY + ".sealed";
var pemSeal = require("./lib/pem-seal");
var PQC_ENFORCE = process.env.PQC_ENFORCE !== "false"; // default: true
var INTERNAL_TLS_PORT = parseInt(process.env.INTERNAL_TLS_PORT, 10) || 3001;

/**
 * The listener's key-exchange groups, colon-separated for `ecdhCurve`.
 *
 * The option MUST be `ecdhCurve`. Node has no `groups` TLS option, so a
 * `groups:` key is accepted and silently discarded and the listener falls back
 * to OpenSSL defaults that exclude the ML-KEM hybrids — which inverts the
 * posture: a hybrid-only client is refused, a dual client negotiates classical
 * X25519, and the boot banner still reports PQC as enforced. `ecdhCurve` is
 * validated, so a typo fails at boot instead of degrading in silence.
 *
 * Under enforcement the classical last resort is dropped, because TLS picks
 * from the mutual set and a client listing classical first would otherwise
 * negotiate it despite offering a hybrid. Ordering is set in lib/constants.js.
 */
function listenerGroupList() {
  var groups = C.TLS_GROUP_PREFERENCE;
  if (PQC_ENFORCE) groups = groups.filter(function (g) { return /MLKEM/i.test(g); });
  return groups.join(":");
}

// The trust bundle is assembled in lib/tls-context.js so the renewal path and
// its regression test build the same object.
var tlsContext = require("./lib/tls-context");
var tlsOptions = null;
var tlsEnabled = false;

// Only the key is ever sealed; the certificate is public material.
function tlsKeyAvailable() {
  return fs.existsSync(TLS_KEY) || fs.existsSync(TLS_KEY_SEALED);
}

if (fs.existsSync(TLS_CERT) && tlsKeyAvailable()) {
  try {
    // Read through the singleton, since MTLS_CA_CERT can point outside
    // DATA_DIR. Kept separate from the trust bundle because the WebSocket
    // upgrade guard reads it as "is mTLS configured at all".
    var mtlsCaCert = mtlsCa.exists() ? fs.readFileSync(mtlsCa.paths.caCert) : null;
    var caList = tlsContext.caListSync();
    var haveMtlsCa = caList.length > 0;
    // Read at boot only. "false" is the escape hatch for an operator who has
    // locked themselves out, and lib/config.js honours it on every rebuild so a
    // settings hot-reload cannot quietly re-lock them.
    var mtlsStrict = process.env.ENFORCE_MTLS_STRICT;
    var hardMtls = mtlsStrict === "true" && haveMtlsCa;
    tlsOptions = {
      cert: fs.readFileSync(TLS_CERT),
      key: pemSeal.loadPemDispatch(TLS_KEY, TLS_KEY_SEALED, "TLS_KEY_SEALED"),
      ecdhCurve: listenerGroupList(),
      minVersion: "TLSv1.3",
      requestCert: haveMtlsCa,
      // Hard mode refuses at the handshake, before any HTTP processing; soft
      // mode leaves the drop to middleware/web-guard.js. Per-route checks read
      // socket.authorized either way.
      rejectUnauthorized: hardMtls,
      ca: haveMtlsCa ? caList : undefined,
    };
    tlsEnabled = true;
    // The admin security panel reads this rather than re-deriving the posture
    // from the same files, which is how it drifted from the listener before.
    runtimeState.set({ tlsEnabled: true, hardMtls: hardMtls });
    // Report the list the listener was given. A banner naming a group it will
    // not negotiate is how the earlier classical fallback went unnoticed.
    logger.info("[TLS] PQC TLS enabled", {
      groups: listenerGroupList().split(":").join(" + "),
      keySealed: fs.existsSync(TLS_KEY_SEALED),
    });
  } catch (e) {
    // Both files were present and the listener still did not come up, usually a
    // sealed key that will not load under the configured mode. Recorded so the
    // security panel reports HTTP instead of inferring TLS from those files.
    runtimeState.set({ tlsEnabled: false, hardMtls: false });
    logger.error("[TLS] Failed to load certificates", { error: e.message });
  }
} else {
  runtimeState.set({ tlsEnabled: false, hardMtls: false });
  logger.warn("[TLS] No certificate found — starting in HTTP mode (no PQC protection)", { certPath: TLS_CERT });
}

// With Tailscale on and no explicit RP_ORIGIN, the WebAuthn origin and rpId
// come from this node's MagicDNS name. Deliberately not awaited — a failure
// logs and leaves the defaults standing rather than holding up boot.
try {
  require("./lib/tailscale").applyHostnameAutoConfig().catch(function (e) {
    logger.warn("[tailscale] hostname auto-config failed", { error: e && e.message });
  });
} catch (_e) { /* tailscale disabled / module load — never blocks boot */ }

var protocol = tlsEnabled ? "https" : "http";
var server; // WebSocket upgrades attach here
var gateServer = null; // public-facing TCP gate, only under PQC enforcement

if (tlsEnabled && PQC_ENFORCE) {
  // Under enforcement HTTPS moves to loopback and the gate takes the public
  // port, so a ClientHello without a PQC group is refused before TLS begins.
  server = app.listen(INTERNAL_TLS_PORT, function () {
    logger.info("[PQC] Internal HTTPS server listening on 127.0.0.1:" + INTERNAL_TLS_PORT);
  }, tlsOptions, "127.0.0.1");

  gateServer = b.pqcGate.create({ internalPort: INTERNAL_TLS_PORT, log: logger });
  gateServer.listen(config.port, function () {
    logger.info("HermitStash is running", {
      url: protocol + "://localhost:" + config.port,
      tls: "PQC enforced (" + listenerGroupList().split(":")[0] + ")",
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

// Seals a plaintext key certbot or acme.sh has just written, so renewal hooks
// never need to know sealing exists. async because the trust bundle is read
// through each authority's locked snapshot, so a reload landing mid-rotation
// does not see a torn state. Neither caller awaits it, so every failure path
// has to be caught in here.
async function reloadTlsContext() {
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
    // Both present means ACME wrote a new plaintext beside an older sealed
    // key, so the plaintext is the fresher of the two.
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
    // setSecureContext replaces the context wholesale — an omitted option is
    // assigned undefined, not carried over — so the trust bundle and the
    // compression list must be supplied again or the first renewal turns client
    // certificate verification off for the rest of the process.
    var newContext = await tlsContext.reloadContext({
      cert: fs.readFileSync(TLS_CERT),
      key: pemSeal.loadPemDispatch(TLS_KEY, TLS_KEY_SEALED, "TLS_KEY_SEALED"),
      ecdhCurve: listenerGroupList(),
    });
    server.setSecureContext(newContext);
    logger.info("[TLS] Certificate reloaded", { trustAnchors: newContext.ca ? newContext.ca.length : 0 });
  } catch (e) {
    logger.error("[TLS] Certificate reload failed", { error: e.message });
  }
}

if (tlsEnabled) {
  // Neither caller awaits reloadTlsContext, so both attach a rejection handler.
  // Without one, a throw on a path its internal try does not cover becomes an
  // unhandled rejection and terminates the process — a failed reload must leave
  // the listener serving the previous certificate, never exit.
  function runTlsReload(reason) {
    reloadTlsContext().catch(function (e) {
      logger.error("[TLS] Certificate reload failed", { reason: reason, error: e.message });
    });
  }
  fs.watchFile(TLS_CERT, { interval: C.TIME.minutes(1) }, function () { runTlsReload("cert-file-changed"); });
  // scripts/tls-key-seal.js --reload sends this after sealing a rotated key.
  process.on("SIGHUP", function () {
    logger.info("[TLS] SIGHUP received — reloading TLS context");
    runTlsReload("sighup");
  });
}

// The registry lives in its own module so the upgrade handler here and the
// admin CA-regeneration endpoint can share one set of Maps without a circular
// require between this file and routes/admin.js.
var syncRegistry = require("./lib/sync-registry");
var syncConnections = syncRegistry.syncConnections;
var apiKeyConnectionCount = syncRegistry.apiKeyConnectionCount;
var caRotationAckCallbacks = syncRegistry.caRotationAckCallbacks;

var SYNC_MAX_CONNECTIONS_PER_KEY = 5;
var SYNC_HEARTBEAT_INTERVAL = C.TIME.seconds(30);
var SYNC_MAX_MESSAGES_PER_MIN = 60;
var SYNC_MAX_MESSAGE_SIZE = C.BYTES.kib(64);
// The change feed is paged so a since=0 request cannot make the server
// field-crypto-decrypt a whole bundle at once. The client advances `since` to
// the last seq it received.
var SYNC_CATCH_UP_PAGE = 200;
// A flood ceiling on the whole IP, not a per-client cap: a fleet behind one NAT
// reconnecting after a restart must clear it, while a single source flooding
// unauthenticated handshakes is cut to a few per second.
var SYNC_WS_UPGRADE_MAX = parseInt(process.env.SYNC_WS_UPGRADE_MAX, 10) || 600;

// server.on("upgrade") never enters the HTTP middleware pipeline, so ip-check
// and the per-IP rate limit are structurally skipped here — without this, a
// banned IP with a valid key still connects and an unauthenticated attacker
// reaches the apiKeys lookup unthrottled. Keyed on the same bucket the HTTP
// guards use. onDeny only flags the verdict, because a raw socket has no res.
var wsUpgradeThrottle = b.middleware.rateLimit({
  max: SYNC_WS_UPGRADE_MAX,
  windowMs: C.TIME.minutes(1),
  algorithm: "fixed-window",
  keyFn: clientIp.rateKey,
  clientIpResolver: function (req) { return clientIp.getIp(req); },
  header: false,
  onDeny: function (req) { req._wsUpgradeThrottled = true; },
});

// The stub response exists to swallow the limiter's default write; the verdict
// arrives via onDeny instead.
function wsUpgradeOverLimit(req) {
  req._wsUpgradeThrottled = false;
  var stubRes = { setHeader: function () {}, writeHead: function () { return stubRes; }, end: function () {}, writableEnded: true, headersSent: true };
  wsUpgradeThrottle(req, stubRes, function () {});
  return req._wsUpgradeThrottled === true;
}

// How a sync client identifies itself across reconnects, so its own stale
// connection can be dropped rather than counted against the per-key ceiling.
var SYNC_INSTANCE_HEADER = "x-hermitstash-instance";
var SYNC_INSTANCE_MAX_LEN = 64;

/**
 * The client instance id from the upgrade request, or null.
 *
 * Grants no authority — it only selects which of the same key's connections to
 * close — but it is attacker-supplied and compared against ids the server
 * holds, so it is bounded and charset-restricted first. A malformed value reads
 * as "not sent": refusing the whole upgrade over a cosmetic header is worse.
 */
function clientInstanceId(req) {
  var raw = req && req.headers && req.headers[SYNC_INSTANCE_HEADER];
  if (typeof raw !== "string") return null;
  var v = raw.trim();
  if (!v || v.length > SYNC_INSTANCE_MAX_LEN) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(v)) return null;
  return v;
}

server.on("upgrade", function (req, socket, head) {
  // req.url is relative, which the WHATWG parser rejects, hence the synthetic
  // base. ALLOW_WS_ALL because this is an inbound request-target, not an
  // outbound URL — the https-only default would refuse the ws base.
  var parsed;
  try {
    parsed = b.safeUrl.parse("ws://placeholder.invalid" + req.url, {
      allowedProtocols: b.safeUrl.ALLOW_WS_ALL,
    });
  } catch (_e) {
    socket.destroy();
    return;
  }
  if (parsed.pathname !== "/sync/ws") {
    socket.destroy();
    return;
  }

  // Both run ahead of any mTLS, certificate or key-lookup work.
  var clientAddr = clientIp.getIp(req);
  if (clientAddr && db.blockedIps.findOne({ ip: clientAddr })) {
    return rejectUpgrade(socket, 403, "Forbidden");
  }
  if (wsUpgradeOverLimit(req)) {
    return rejectUpgrade(socket, 429, "Too Many Requests");
  }

  // With a CA configured a valid client certificate is required.
  // MTLS_REQUIRED=false is a bring-up escape that skips only the presence
  // check: revocation, expiry and per-key binding still apply to any
  // certificate that is presented.
  if (mtlsCaCert) {
    var peerCert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
    var hasValidCert = peerCert && peerCert.subject && socket.authorized;
    if (!hasValidCert) {
      if (process.env.MTLS_REQUIRED !== "false") {
        return rejectUpgrade(socket, 403, "Forbidden");
      }
    } else {
      if (certUtils.isPeerCertRevoked(peerCert)) {
        return rejectUpgrade(socket, 403, "Forbidden");
      }
      // Fails closed on an unparseable valid_to: a comparison against Invalid
      // Date is always false, which would admit a malformed certificate. A
      // valid X.509 peer certificate always carries a parseable notAfter.
      var certExpiry = peerCert.valid_to ? Date.parse(peerCert.valid_to) : NaN;
      if (!Number.isFinite(certExpiry) || certExpiry < Date.now()) {
        return rejectUpgrade(socket, 403, "Certificate expired");
      }
    }
  }

  // Header only. A query-string token leaks through proxy logs, Referer
  // headers and browser history. extractBearer also refuses a request carrying
  // more than one Authorization header (CWE-345).
  var token = b.requestHelpers.extractBearer(req);
  if (!token) {
    return rejectUpgrade(socket, 401, "Unauthorized");
  }

  var keyHash = b.crypto.sha3Hash(token);
  var apiKey = db.apiKeys.findOne({ keyHash: keyHash });
  if (!apiKey) {
    return rejectUpgrade(socket, 401, "Unauthorized");
  }

  // Shared with /sync/rename and /sync/renew-cert so the three cannot drift.
  // The checks below stay inline because they answer on the raw socket.
  var syncGuards = require("./middleware/sync-guards");

  var certErr = syncGuards.enforceCertBinding(apiKey, socket);
  if (certErr) return rejectUpgrade(socket, certErr.status, certErr.error);

  var scopeErr = syncGuards.enforceSyncScope(apiKey);
  if (scopeErr) return rejectUpgrade(socket, scopeErr.status, scopeErr.error);

  var user = usersRepo.findById(apiKey.userId);
  if (!user || user.status !== "active") {
    return rejectUpgrade(socket, 403, "Forbidden");
  }

  var bundleId = parsed.searchParams.get("bundleId");
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
  // Not enforceBundleOwnership: here a stash-scoped token reaches every bundle
  // in its stash, which /sync/rename does not allow.
  if (bundle.ownerId !== user._id && user.role !== "admin" && !apiKey.boundStashId) {
    return rejectUpgrade(socket, 403, "Forbidden");
  }

  // Let a reconnecting client reclaim its own slot first. The count drops only
  // in the close handler, and an unclean drop goes unnoticed until the pong
  // timeout, so a client returning inside that window would be refused on
  // account of its own ghost. Match on the instance id and NEVER on
  // (key, bundle): one key legitimately holds several connections to a bundle,
  // and a broader match would close another subscriber's live socket.
  var keyId = apiKey._id;
  var instanceId = clientInstanceId(req);
  if (instanceId) syncRegistry.supersedeSameInstance(bundleId, keyId, instanceId);
  var keyCount = apiKeyConnectionCount.get(keyId) || 0;
  if (keyCount >= SYNC_MAX_CONNECTIONS_PER_KEY) {
    return rejectUpgrade(socket, 429, "Too Many Requests");
  }

  var since = parseInt(parsed.searchParams.get("since"), 10);
  if (isNaN(since) || since < 0) since = 0;

  // Returns null with the response already sent on a malformed request, so a
  // further rejectUpgrade would be a second write.
  var ws = b.websocket.handleUpgrade(req, socket, head, {
    maxMessageBytes: SYNC_MAX_MESSAGE_SIZE,
  });
  if (!ws) return;
  // send() throws on a closed connection, and every push here is
  // fire-and-forget — the close handler unwires the listener a tick later.
  function safeSend(data) {
    try { ws.send(data); } catch (_e) { /* connection closed mid-write */ }
  }

  // `counted` marks this entry as holding a slot. supersedeSameInstance clears
  // it when it reclaims one early, so the close handler cannot decrement twice.
  if (!syncConnections.has(bundleId)) syncConnections.set(bundleId, new Set());
  var connEntry = { ws: ws, apiKeyId: keyId, instanceId: instanceId, counted: true };
  syncConnections.get(bundleId).add(connEntry);
  apiKeyConnectionCount.set(keyId, keyCount + 1);

  var msgCount = 0;
  var msgResetTimer = setInterval(function () { msgCount = 0; }, C.TIME.minutes(1));
  msgResetTimer.unref();
  var violations = 0;

  // `since` is attacker-controlled and since=0 asks for the whole bundle, so
  // the query filters, orders and limits in SQL on the raw columns. The flat
  // 60-per-minute message cap does not bound decrypt work proportional to file
  // count.
  if (since > 0) {
    var catchupFiles = filesRepo.findBundleChangesSince(bundle._id, since, SYNC_CATCH_UP_PAGE);
    for (var i = 0; i < catchupFiles.length; i++) {
      var f = catchupFiles[i];
      var evType = f.deletedAt ? "file_removed" : "file_added";
      var ev = { type: evType, fileId: f._id, relativePath: f.relativePath, seq: f.seq || 0 };
      if (!f.deletedAt) { ev.checksum = f.checksum; ev.size = f.size; }
      safeSend(JSON.stringify(ev));
    }
  }
  // Signals catch-up complete.
  safeSend(JSON.stringify({ type: "heartbeat", seq: bundle.seq || 0, timestamp: new Date().toISOString() }));

  var syncListener = function (event) {
    try { safeSend(JSON.stringify(event)); } catch (_e) {} // allow:silent-catch — best-effort WS push; a dead socket is reaped elsewhere
  };
  syncEmitter.on("sync:" + bundleId, syncListener);

  try {
    safeSend(JSON.stringify({ type: "heartbeat", seq: bundle.seq || 0, timestamp: new Date().toISOString() }));
  } catch (_e) { /* socket may have closed between upgrade and first write */ }

  var heartbeatTimer = setInterval(function () {
    try {
      // TLS never re-validates an authenticated connection, so an open change
      // feed would otherwise outlive its credential. Re-reading the key and
      // user each beat tears one down within an interval even when the
      // immediate close on revoke or deactivate was missed.
      var freshKey = apiKeysRepo.findOne({ _id: keyId });
      var freshUser = freshKey ? usersRepo.findById(freshKey.userId) : null;
      if (!freshKey || !freshUser || freshUser.status !== "active") {
        ws.close(4401, "credential revoked");
        return;
      }
      var freshBundle = bundlesRepo.findById(bundleId);
      safeSend(JSON.stringify({ type: "heartbeat", seq: freshBundle ? freshBundle.seq || 0 : 0, timestamp: new Date().toISOString() }));
      ws.ping();
    } catch (_e) { /* client disconnected between heartbeats — close handler runs next tick */ }
  }, SYNC_HEARTBEAT_INTERVAL);
  heartbeatTimer.unref();

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
      var msg = b.safeJson.parse(data, { maxBytes: SYNC_MAX_MESSAGE_SIZE, maxDepth: 32 });
      if (!msg || !msg.type) {
        safeSend(JSON.stringify({ type: "error", code: "invalid_json", message: "Missing type field" }));
        return;
      }
      if (msg.type === "ack") {
        // Receipt acknowledgement; nothing for the server to do.
      } else if (msg.type === "ca:rotation-ack") {
        // The client has persisted the bundle sent via ca:rotation. Releases
        // the admin regeneration endpoint, which waits for every client.
        var ackCb = caRotationAckCallbacks.get(keyId);
        if (ackCb) { try { ackCb(); } catch (_e) {} } // allow:silent-catch — best-effort ack callback
      } else if (msg.type === "catch_up") {
        var catchSince = parseInt(msg.since, 10) || 0;
        var files = filesRepo.findBundleChangesSince(bundle._id, catchSince, SYNC_CATCH_UP_PAGE);
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

  ws.on("close", function () {
    syncEmitter.off("sync:" + bundleId, syncListener);
    clearInterval(heartbeatTimer);
    clearInterval(pongCheckTimer);
    clearInterval(msgResetTimer);
    if (syncConnections.has(bundleId)) {
      syncConnections.get(bundleId).delete(connEntry);
      if (syncConnections.get(bundleId).size === 0) syncConnections.delete(bundleId);
    }
    if (!connEntry.counted) return;
    connEntry.counted = false;
    var currentCount = apiKeyConnectionCount.get(keyId) || 0;
    if (currentCount > 1) apiKeyConnectionCount.set(keyId, currentCount - 1);
    else apiKeyConnectionCount.delete(keyId);
  });

  // Rebuilt rather than logged as received, so no token reaches the log.
  var logUrl = parsed.pathname + "?bundleId=" + bundleId + "&since=" + since;
  logger.info("[Sync] WebSocket connected", { bundleId: bundleId, user: user._id, url: logUrl });
});

var shuttingDown = false;
function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info("Shutdown initiated", { signal: signal });

  // server.close() will not drain while these are open.
  syncConnections.forEach(function (conns) {
    conns.forEach(function (entry) {
      try { if (entry.ws && entry.ws.readyState === "open") entry.ws.close(1001, "Server shutting down"); } catch (_e) { /* socket may already be closed */ }
    });
  });

  if (tlsEnabled) try { fs.unwatchFile(TLS_CERT); } catch (_e) {} // allow:silent-catch — best-effort cert-watcher teardown

  if (gateServer) gateServer.close();
  server.close(function () {
    logger.info("All connections drained, exiting");
    process.exit(0); // db.js "exit" handler encrypts the DB
  });

  var forceTimer = setTimeout(function () {
    logger.warn("Shutdown timeout reached, forcing exit");
    process.exit(1);
  }, C.TIME.seconds(10));
  forceTimer.unref();
}

process.on("SIGTERM", function () { gracefulShutdown("SIGTERM"); });
process.on("SIGINT", function () { gracefulShutdown("SIGINT"); });
