"use strict";
// buildApp — single source of truth for the wiki's framework wiring.
// Both server.js and test/e2e.js call this so the live and in-process
// boots stay in sync.
//
// Call shape:
//   var app = await buildApp({
//     dataDir:       "./data",
//     port:          8080,            // 0 for ephemeral
//     adminEmail:    "admin@blamejs.com",
//     adminPassword: "...",           // optional; null skips seed
//     webhookUrl:    null,
//     webhookSecret: null,
//   });
//
// Returns { app, info? } from b.createApp + listen.

var path = require("node:path");
var b = require("@blamejs/core");
var adminRoute = require("../routes/admin");
var integrationRoutes = require("../routes/integration");
var pagesRoute = require("../routes/pages");

// Strict CSP — drops 'unsafe-inline' from style-src + script-src. All
// assets are external; cspNonce middleware adds 'nonce-XYZ' when the
// app actually needs an inline element.
var STRICT_CSP =
  "default-src 'self'; " +
  "script-src 'self'; " +
  "style-src 'self'; " +
  "img-src 'self' data:; " +
  "font-src 'self'; " +
  "connect-src 'self'; " +
  "frame-ancestors 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'; " +
  "object-src 'none';";

// Schema for admin_users (pages table is owned by migrations/).
// _blamejs_api_keys is part of FRAMEWORK_SCHEMA so the framework
// creates it automatically — apiKey usage just needs the registry.
var SCHEMA = [
  {
    name: "admin_users",
    columns: {
      id:           "TEXT PRIMARY KEY",
      email:        "TEXT NOT NULL UNIQUE",
      passwordHash: "TEXT NOT NULL",
      createdAt:    "INTEGER NOT NULL",
    },
    sealedFields: [],
  },
];

async function buildApp(opts) {
  opts = opts || {};
  if (!opts.dataDir) throw new Error("buildApp: opts.dataDir is required");

  var dataDir = opts.dataDir;
  var port = opts.port !== undefined ? opts.port : b.constants.BYTES.bytes(8080);
  var adminEmail = opts.adminEmail || "admin@blamejs.com";
  var adminPassword = opts.adminPassword || null;
  var webhookUrl = opts.webhookUrl || null;
  var webhookSecret = opts.webhookSecret || null;

  // ---- Build client assets via b.bundler ----
  // Hashes wiki.js + editor.js into public/dist/<name>.<hash>.js so
  // operators get cache-busting via filename and SRI-friendly content
  // hashes. Manifest map ({ wiki: "wiki.4a8c.js", ... }) is passed to
  // templates as `assets.<name>` so views render the hashed path.
  var bundler = b.bundler.create({
    entries: {
      wiki:   path.join(__dirname, "..", "src", "wiki.js"),
      editor: path.join(__dirname, "..", "src", "editor.js"),
    },
    outdir:   path.join(__dirname, "..", "public", "dist"),
    manifest: "manifest.json",
    hashLen:  b.constants.BYTES.bytes(16),
  });
  var bundleResult = await bundler.build();
  var assets = {};
  for (var i = 0; i < bundleResult.outputs.length; i++) {
    var out = bundleResult.outputs[i];
    // outputs[].path is absolute; we want the URL-style relative to
    // the public/ root: "/dist/<filename>".
    assets[out.name] = "/dist/" + path.basename(out.path);
  }

  // ---- Register app-specific audit namespace ----
  // The framework refuses to write events on namespaces it doesn't know
  // about (and silently drops with a warning). The wiki emits wiki.login,
  // wiki.page.edited, etc., so register up front.
  b.audit.registerNamespace("wiki");

  // ---- Build framework primitives ----
  var template = b.template.create({
    viewsDir: path.join(__dirname, "..", "views"),
  });
  // Compile every view at boot — a `{% if not foo %}` typo (or any
  // template syntax error) fails the deploy here instead of surfacing
  // as a 500 the first time an operator clicks the route.
  template.precompileAll();

  var pageCache = b.cache.create({
    namespace: "wiki.page",
    ttlMs:     b.constants.TIME.minutes(5),
    audit:     b.audit,
  });

  var perms = b.permissions.create({
    // Role table — perms.require("wiki:admin") matches when a user has
    // either the "wiki:admin" scope directly OR the "admin" role that
    // grants it. Only the admin role is enforced by this example; add
    // a viewer role mapped to wiki:read here when adding read-gated
    // routes (e.g. drafts, private pages).
    roles: { admin: ["wiki:admin"] },
    audit: b.audit,
    resolver: function (req) {
      if (!req.user) return null;
      return {
        scopes: req.user.scopes || [],
        roles:  req.user.roles  || [],
      };
    },
  });

  var i18n = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: {} },
  });

  var healthChecks = b.middleware.health({
    livenessPath:  "/healthz",
    readinessPath: "/readyz",
    startupPath:   "/startupz",
  });
  healthChecks.registerCheck("db", function () {
    try { b.db.prepare("SELECT 1").get(); return true; }
    catch (_e) { return false; }
  }, { tier: "readiness", critical: true });

  // ---- Notify dispatcher ----
  // Always-on: log channel for dev visibility.
  // Operator-gated: webhook channel if WIKI_WEBHOOK_URL + _SECRET set.
  var notifyChannels = {
    log: b.notify.transports.log({ name: "wiki.log" }),
  };
  var webhookSigner = null;
  if (webhookUrl && webhookSecret) {
    // Compose b.webhook.signer with notify.transports.httpJson via the
    // signing hook — operator-side webhook receivers verify the
    // X-Signature header to prove origin.
    webhookSigner = b.webhook.signer({
      algo: "hmac-sha3-512",
      keys: { v1: webhookSecret },
    });
    notifyChannels.webhook = b.notify.transports.httpJson({
      url:     webhookUrl,
      name:    "wiki.webhook",
      signing: { sign: function (body) { return webhookSigner.headers(body); } },
    });
  }
  var notify = b.notify.create({
    channels: notifyChannels,
    audit:    b.audit,
  });

  // ---- API key registry (content-management keys) ----
  var apiKeys = b.apiKey.create({
    namespace: "wiki",
    audit:     b.audit,
  });

  // ---- Brute-force lockout for /login ----
  // Per-key failed-attempt tracking with exponential backoff. The
  // namespace stays narrow ("wiki.login") so other auth surfaces keep
  // independent counters. State lives in pageCache's parent backend
  // (memory in single-node, cluster in cluster mode); the cache TTL
  // self-cleans entries that haven't seen a recent failure.
  var loginLockout = b.auth.lockout.create({
    namespace: "wiki.login",
    cache:     b.cache.create({ namespace: "wiki.auth.lockout.login", backend: "memory" }),
    audit:     b.audit,
  });

  // Trust-proxy posture: when WIKI_TRUST_PROXY is set (the operator is
  // behind a TLS terminator that injects x-forwarded-proto), the wiki
  // honours that header for cookie Secure-flag detection. Default off
  // so a misconfigured deployment doesn't accept attacker-supplied
  // x-forwarded-proto: https as proof the request was over TLS.
  var trustProxy = b.safeEnv.readVar("WIKI_TRUST_PROXY", { type: "boolean", default: false });

  // Network allowlist for /admin paths — when WIKI_ADMIN_ALLOWED_CIDRS
  // is set (comma-separated CIDR list), the wiki mounts
  // b.middleware.networkAllowlist as the in-process CIDR fence above
  // the application-layer auth gate. Operators behind a reverse proxy
  // typically configure this at the proxy / NACL layer instead and
  // leave the env var unset; this is the in-process fallback.
  var adminAllowedCidrs = (b.safeEnv.readVar("WIKI_ADMIN_ALLOWED_CIDRS") || "")
    .split(",").map(function (s) { return s.trim(); }).filter(function (s) { return s.length > 0; });
  // Optional deny-list for the same paths — "10.0.0.0/8 except
  // 10.0.99.0/24" patterns. Comma-separated CIDR list; empty = no
  // deny rules.
  var adminDeniedCidrs = (b.safeEnv.readVar("WIKI_ADMIN_DENIED_CIDRS") || "")
    .split(",").map(function (s) { return s.trim(); }).filter(function (s) { return s.length > 0; });

  // Network configurability — read NTP / DNS / proxy / DPI-trust / socket
  // env vars and apply them before the framework's outbound code paths
  // open any sockets. Operators in air-gapped or proxied environments
  // configure entirely via env without touching code.
  b.network.bootFromEnv({ env: process.env, audit: b.audit });

  // Optional log-stream sink — driven by BLAMEJS_LOG_STREAM_PROTOCOL
  // and friends (BLAMEJS_LOG_STREAM_URL, AWS_*, etc.). Framework-level
  // env vars; bootFromEnv reads them, validates, and wires the
  // matching backend. Skipped silently when the protocol env var is
  // unset, so dev `npm start` keeps stdout-only logging.
  b.logStream.bootFromEnv({ env: process.env });

  // Queue backend — local SQLite by default; Redis when
  // BLAMEJS_QUEUE_PROTOCOL=redis + BLAMEJS_QUEUE_REDIS_URL set. Wired
  // unconditionally so the wiki picks up the operator's env-driven
  // choice without code changes; integration tests rely on this to
  // exercise both backends through the same app entrypoint.
  b.queue.bootFromEnv({ env: process.env });

  // Integration-test mode — mount /test/* routes and wire test-only
  // primitives (alt cache, mail transport, object-store backend) when
  // WIKI_INTEGRATION_TEST=1. Production deploys MUST NOT set this var;
  // the routes are guarded by the mount-gate below and otherwise
  // unreachable.
  var integrationMode = b.safeEnv.readVar("WIKI_INTEGRATION_TEST", { type: "boolean", default: false });
  var testCache = null;
  var testMail = null;
  var testObjectStore = null;
  var testMtlsCa = null;
  if (integrationMode) {
    testCache = b.cache.create({
      namespace: "wiki.integration.cache",
      audit:     b.audit,
    });
    var smtpHost = b.safeEnv.readVar("WIKI_INTEGRATION_SMTP_HOST");
    if (smtpHost) {
      testMail = b.mail.transports.smtp({
        host:               smtpHost,
        port:               b.safeEnv.readVar("WIKI_INTEGRATION_SMTP_PORT", { type: "number", default: 1025 }),
        ehloName:           b.safeEnv.readVar("WIKI_INTEGRATION_SMTP_EHLO") || "blamejs-wiki",
        timeoutMs:          b.constants.TIME.seconds(5),
        rejectUnauthorized: b.safeEnv.readVar("WIKI_INTEGRATION_SMTP_REJECT_UNAUTHORIZED") !== "false",
      });
    }
    var s3Endpoint = b.safeEnv.readVar("WIKI_INTEGRATION_S3_ENDPOINT");
    if (s3Endpoint) {
      testObjectStore = b.objectStore.buildBackend({
        name:             "wiki-integration-s3",
        protocol:         "sigv4",
        endpoint:         s3Endpoint,
        region:           b.safeEnv.readVar("WIKI_INTEGRATION_S3_REGION") || "us-east-1",
        bucket:           b.safeEnv.readVar("WIKI_INTEGRATION_S3_BUCKET"),
        accessKeyId:      b.safeEnv.readVar("WIKI_INTEGRATION_S3_ACCESS_KEY"),
        secretAccessKey:  b.safeEnv.readVar("WIKI_INTEGRATION_S3_SECRET_KEY"),
        forcePathStyle:   true,
        allowInternal:    true,
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        classifications:  ["operational"],
        residencyTag:     "unrestricted",
      });
    }
    var mtlsDir = b.safeEnv.readVar("WIKI_INTEGRATION_MTLS_DIR");
    if (mtlsDir) {
      testMtlsCa = b.mtlsCa.create({ dataDir: mtlsDir });
    }
  }

  // Boot-time security policy assertions. WIKI_REQUIRE_PROD_ASSERTS=1
  // makes the wiki refuse to boot when the operator's production
  // posture is incomplete (vault not wrapped, db not encrypted, etc.).
  // Default off so a developer's `npm start` doesn't have to set every
  // production knob; production deploys flip this on in the .env.
  var requireProdAsserts = b.safeEnv.readVar("WIKI_REQUIRE_PROD_ASSERTS", { type: "boolean", default: false });

  // ---- Posture auto-detect ----
  // The wiki ships in plaintext defaults so a quick local boot just works.
  // When the operator sets BLAMEJS_VAULT_PASSPHRASE in the env, the wiki
  // takes that as the production-posture signal and flips to wrapped vault
  // + encrypted DB at rest. Same for BLAMEJS_AUDIT_SIGNING_PASSPHRASE →
  // wrapped audit-sign key. WIKI_VAULT_MODE / WIKI_DB_AT_REST /
  // WIKI_AUDIT_SIGNING_MODE override the auto-detect explicitly.
  var hasVaultPass = !!b.safeEnv.readVar("BLAMEJS_VAULT_PASSPHRASE");
  var hasAuditPass = !!b.safeEnv.readVar("BLAMEJS_AUDIT_SIGNING_PASSPHRASE");
  var vaultMode    = b.safeEnv.readVar("WIKI_VAULT_MODE")
                  || (hasVaultPass ? "wrapped"   : "plaintext");
  var dbAtRest     = b.safeEnv.readVar("WIKI_DB_AT_REST")
                  || (hasVaultPass ? "encrypted" : "plain");
  var auditMode    = b.safeEnv.readVar("WIKI_AUDIT_SIGNING_MODE")
                  || (hasAuditPass ? "wrapped"   : "plaintext");

  // ---- Boot the app ----
  var app = await b.createApp({
    dataDir: dataDir,
    schema:  SCHEMA,
    vault:   { mode: vaultMode },
    db:      {
      atRest:       dbAtRest,
      auditSigning: { mode: auditMode },
    },
    port:    port,
    middleware: {
      requestId:       true,
      securityHeaders: { csp: STRICT_CSP },
      botGuard:        { skipPaths: ["/healthz", "/readyz", "/startupz", "/robots.txt", "/sitemap.xml"] },
      cors: {
        // No third-party origins — only this app's own forms post
        // here. The Fetch spec sends an Origin header on every same-
        // origin POST, so we still need to tell CORS which origin is
        // "self". For local dev (HTTP, default port) the framework
        // can infer it from the request; production deployments
        // behind TLS terminators should pass siteOrigin explicitly.
        origins:     [],
        credentials: false,
      },
      rateLimit: {
        // burst sized as 2 minutes' worth of refill at 2 tokens/sec —
        // an idle visitor accrues a full minute-scale buffer between
        // bursts so static-asset preloads don't trip the limiter.
        backend:         "memory",
        burst:           b.constants.TIME.minutes(2),
        refillPerSecond: 2,
        skipPaths:       ["/healthz", "/readyz"],
      },
    },
    routes: function (router) {
      router.use(healthChecks.middleware());
      // CIDR fence on /admin paths when WIKI_ADMIN_ALLOWED_CIDRS is
      // set. Mounted FIRST so a probe from a disallowed network gets
      // a 404 (default denyStatus) before any other middleware runs.
      // The fence stays inert (no-op middleware) when the env var is
      // unset — operators using a reverse proxy / NACL leave this off.
      if (adminAllowedCidrs.length > 0) {
        router.use(b.middleware.networkAllowlist({
          paths:        ["/admin", "/admin/", "/healthz/internal"],
          allowedCidrs: adminAllowedCidrs,
          deniedCidrs:  adminDeniedCidrs,
          trustProxy:   trustProxy,
          audit:        b.audit,
        }));
      }
      router.use(b.middleware.bodyParser({ urlencoded: true, json: true }));
      var nonceMw = b.middleware.cspNonce();
      router.use(nonceMw);

      // Integration-test routes are mounted BEFORE attachUser /
      // csrfProtect / staticServe so the test suite doesn't have to
      // round-trip a CSRF token for every POST. The whole namespace
      // is gated by WIKI_INTEGRATION_TEST=1; production deploys must
      // never set that env var. The path-prefix /test/ keeps the
      // namespace well-separated from any production route.
      if (integrationMode) {
        integrationRoutes.register(router, {
          testCache:       testCache,
          testMail:        testMail,
          testObjectStore: testObjectStore,
          mtlsCa:          testMtlsCa,
        });
      }
      router.use(b.middleware.compression());
      router.use(i18n.middleware());

      router.use(b.middleware.attachUser({
        cookieName: "wiki_sid",
        tokenFrom:  "cookie",
        userLoader: async function (verifiedSession) {
          var row = b.db.prepare(
            "SELECT id, email FROM admin_users WHERE id = ?"
          ).get(verifiedSession.userId);
          if (!row) return null;
          var scopes = (verifiedSession.data && Array.isArray(verifiedSession.data.scopes))
            ? verifiedSession.data.scopes : [];
          return { userId: row.id, email: row.email, scopes: scopes };
        },
      }));
      // CSRF — double-submit cookie pattern. Integration mode (gated
      // by WIKI_INTEGRATION_TEST=1, never set in production) skips
      // CSRF entirely so test POSTs against /test/* don't have to
      // round-trip a token cookie. Production deployments always run
      // with the full middleware stack.
      if (!integrationMode) {
        router.use(b.middleware.csrfProtect({
          cookie:    { name: "wiki_csrf" },
          fieldName: "csrf",   // wiki templates use <input name="csrf">
        }));
      }
      router.use(b.staticServe.create({
        root: path.join(__dirname, "..", "public"),
      }));

      // ---- Public + admin routes ----
      // Order: specific paths first, then admin, then /:group catch-all.
      var routeCtx = {
        db:           b.db,
        template:     template,
        audit:        b.audit,
        pageCache:    pageCache,
        perms:        perms,
        passwordAuth: b.auth.password,
        session:      b.session,
        notify:       notify,
        apiKeys:      apiKeys,
        loginLockout: loginLockout,
        trustProxy:   trustProxy,
        assets:       assets,
        nonceMw:      nonceMw,
        siteUrl:      opts.siteUrl || "https://blamejs.com",
      };
      pagesRoute.registerSpecific(router, routeCtx);
      adminRoute.register(router, routeCtx);
      pagesRoute.registerCatchAll(router, routeCtx);
    },
  });

  // ---- Run migrations (pages + FTS5) ----
  var migrations = b.migrations.create({
    dir: path.join(__dirname, "..", "migrations"),
    db:  b.db,
  });
  await migrations.up();

  // ---- Seed admin user if missing ----
  if (adminPassword) {
    var existingAdmin = b.db.prepare(
      "SELECT id FROM admin_users WHERE email = ?"
    ).get(adminEmail);
    if (!existingAdmin) {
      var hash = await b.auth.password.hash(adminPassword);
      b.db.prepare(
        "INSERT INTO admin_users (id, email, passwordHash, createdAt) VALUES (?, ?, ?, ?)"
      ).run(
        "admin-" + b.crypto.generateToken(b.constants.BYTES.bytes(8)),
        adminEmail,
        hash,
        Date.now()
      );
    }
  }

  // ---- Run page seeders for prod env ----
  var seeders = b.seeders.create({
    dir: path.join(__dirname, "..", "seeders"),
    db:  b.db,
  });
  await seeders.run({ env: "prod" });

  // ---- Scheduler: periodic session purge + cache stats ----
  // Direct-function tasks (no jobs needed for these housekeepers).
  // Cluster-mode operators get exactly-once-globally behavior via the
  // scheduler's tick-claim table; single-process apps just run once.
  var scheduler = b.scheduler.create();
  scheduler.schedule({
    name:  "wiki.session.purge",
    every: b.constants.TIME.hours(1),
    run:   async function () {
      var n = await b.session.purgeExpired();
      b.observability.event("wiki.session.purged", n, { task: "wiki.session.purge" });
    },
  });
  scheduler.schedule({
    name:  "wiki.cache.stats",
    every: b.constants.TIME.minutes(5),
    run:   async function () {
      try {
        var size = await pageCache.size();
        b.observability.event("wiki.cache.size", size, {});
      } catch (_e) { /* observability best-effort */ }
    },
  });
  // Schedule timers ref the event loop; in tests we want to skip start
  // to avoid keeping the process alive. Operators (server.js) call start.

  // Production-posture gate. WIKI_REQUIRE_PROD_ASSERTS=1 in the .env
  // makes the wiki refuse to boot when the operator's posture is
  // incomplete. Default off so a developer's `npm start` doesn't have
  // to set every production knob.
  if (requireProdAsserts) {
    await b.security.assertProduction({
      audit:    b.audit,
      vault:    "wrapped",
      dbAtRest: "encrypted",
      auditSigning: "wrapped",
      ntpStrict:    true,
      forbidNodeEnv: ["development", "dev", "test"],
      requireEnv:    ["WIKI_ADMIN_PASSWORD", "BLAMEJS_VAULT_PASSPHRASE", "BLAMEJS_AUDIT_SIGNING_PASSPHRASE"],
      dataDir:       dataDir,
    });
  }

  return {
    app:       app,
    notify:    notify,
    apiKeys:   apiKeys,
    scheduler: scheduler,
    pageCache: pageCache,
    assets:    assets,
    bundler:   bundler,
  };
}

module.exports = { buildApp: buildApp };
