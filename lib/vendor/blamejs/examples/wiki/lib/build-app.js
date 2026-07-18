// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// buildApp — single source of truth for the wiki's framework wiring.
// Both server.js and test/e2e.js call this so the live and in-process
// boots stay in sync.
//
// Call shape:
//   var app = await buildApp({
//     dataDir:       "./data",
//     port:          3008,            // 0 for ephemeral
//     adminEmail:    "admin@blamejs.com",
//     adminPassword: "...",           // optional; null skips seed
//     webhookUrl:    null,
//     webhookSecret: null,
//   });
//
// Returns { app, info? } from b.createApp + listen.

var fs = require("node:fs");
var path = require("node:path");
var b = require("@blamejs/core");
var adminRoute = require("../routes/admin");
var integrationRoutes = require("../routes/integration");
var pagesRoute = require("../routes/pages");
var symbolIndex = require("./symbol-index");
var pagesSeeder = require("../seeders/prod/pages/_index");

// Typed boot error — extends FrameworkError and carries a stable .code so a
// caller can dispatch on the failure instead of string-matching the message.
var BuildAppError = b.frameworkError.defineClass("BuildAppError");

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
  if (!opts.dataDir) throw new BuildAppError("wiki/missing-data-dir", "buildApp: opts.dataDir is required");

  var dataDir = opts.dataDir;
  var port = opts.port !== undefined ? opts.port : b.constants.BYTES.bytes(3008);
  var adminEmail = opts.adminEmail || "admin@blamejs.com";
  var adminPassword = opts.adminPassword || null;
  var webhookUrl = opts.webhookUrl || null;
  var webhookSecret = opts.webhookSecret || null;
  // Rate-limit burst (token count). Default: 2 minutes' worth of refill at
  // 2 tokens/sec, ample for real browsing. Overridable so the e2e link/nav
  // crawler — which fetches every page in a tight loop, far above any human
  // rate — isn't 429'd while exercising completeness.
  var rateLimitBurst = opts.rateLimitBurst !== undefined
    ? opts.rateLimitBurst
    : 2 * (b.constants.TIME.minutes(2) / b.constants.TIME.seconds(1));

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

  // ---- Content-hash wiki.css ----
  // Browsers cache /wiki.css aggressively (the URL has no hash). When
  // the CSS rewrites between releases, operators end up with mismatched
  // CSS+HTML in their browser tab — e.g. new HTML classes like .pill
  // styled by the new CSS, but the cached old CSS knows nothing about
  // them so the elements render unstyled-or-invisible. Solve by giving
  // the CSS the same content-hash treatment the JS bundles get; the
  // template references `assets.css` which always points to the
  // freshly-hashed filename.
  try {
    var crypto = require("node:crypto");
    var publicDir = path.join(__dirname, "..", "public");
    var cssRaw = fs.readFileSync(path.join(publicDir, "wiki.css"), "utf8");
    var cssHash = crypto.createHash("sha256").update(cssRaw).digest("hex").slice(0, b.constants.BYTES.bytes(16));
    var hashedCssName = "wiki." + cssHash + ".css";
    fs.writeFileSync(path.join(publicDir, "dist", hashedCssName), cssRaw, "utf8");
    assets.css = "/dist/" + hashedCssName;
  } catch (e) {
     
    console.warn("[buildApp] wiki.css hashing failed; falling back to /wiki.css:", e && e.message); // allow:console-direct — wiki tooling, b.log not yet initialised at boot
    assets.css = "/wiki.css";
  }

  // ---- Build symbol-index manifest at /dist/symbol-index.json ----
  // The wiki sidebar's autocomplete fetches this static JSON resource
  // at first keystroke. Generation is synchronous + cheap (regex over
  // ~40 page bodies); regenerated on every boot so a wiki edit never
  // ships stale autocomplete data.
  try {
    var symbolManifest = symbolIndex.build(pagesSeeder);
    var distDir = path.join(__dirname, "..", "public", "dist");
    if (!fs.existsSync(distDir)) fs.mkdirSync(distDir, { recursive: true });
    fs.writeFileSync(
      path.join(distDir, "symbol-index.json"),
      JSON.stringify(symbolManifest),
      "utf8"
    );
  } catch (e) {
    // Symbol index is purely additive — a build failure here must not
    // crash the app. Log + continue; autocomplete falls back to empty.
     
    console.warn("[buildApp] symbol-index build failed:", e && e.message); // allow:console-direct — wiki tooling, b.log not yet initialised at boot
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
  // Reverse-proxy CIDRs for the deployment. X-Forwarded-For / -Proto are
  // honored only when the request's immediate peer is one of these
  // (peer-gating) — without it the framework uses the socket address /
  // real TLS state and ignores the forgeable headers, so a direct caller
  // can't spoof an allowed IP or claim https. Drives both the /admin CIDR
  // gate and the admin Secure-cookie HTTPS detection.
  var adminTrustedProxies = (b.safeEnv.readVar("WIKI_ADMIN_TRUSTED_PROXIES") || "")
    .split(",").map(function (s) { return s.trim(); }).filter(function (s) { return s.length > 0; });
  // Peer-gated HTTPS detector for the admin Secure-cookie flag — resolves
  // "https" only when X-Forwarded-Proto arrives via a trusted proxy, else
  // from the real TLS socket. Replaces a bare trust-proxy boolean a direct
  // caller could forge to suppress the Secure attribute.
  var secureProtocol = b.requestHelpers.trustedProtocol({ trustedProxies: adminTrustedProxies }).resolve;

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
      // Peer-gate X-Forwarded-Proto with the same trusted-proxy CIDRs as the
      // admin Secure-cookie detector, so behind a TLS-terminating proxy
      // (Caddy/nginx) the framework resolves "https" and emits its strong HSTS
      // (max-age + includeSubDomains + preload) rather than suppressing it on
      // the http hop from the proxy. Empty (dev / no proxy) keeps HSTS gated on
      // the real TLS socket — a direct caller can't forge https to force it.
      securityHeaders: { csp: STRICT_CSP, trustedProxies: adminTrustedProxies },
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
        // burst is a TOKEN COUNT, not a duration: 2 minutes' worth of refill at
        // 2 tokens/sec, so an idle visitor accrues a minute-scale buffer between
        // bursts and static-asset preloads don't trip the limiter. Expressed as
        // refillPerSecond × window-in-seconds so the count is never a bare magic
        // number. (Was C.TIME.minutes(2) = 120000 — a ms/count unit error that
        // set burst to 120k and effectively disabled the limiter.)
        backend:         "memory",
        refillPerSecond: 2,
        burst:           rateLimitBurst,
        skipPaths:       ["/healthz", "/readyz"],
      },
      // cookies + cspNonce + fetchMetadata ride createApp's secure
      // defaults. bodyParser + CSRF are configured here so the wiki's
      // own cookie + field names flow through the default wiring rather
      // than being mounted separately.
      bodyParser: { urlencoded: true, json: true },
      // CSRF double-submit cookie. Integration mode (WIKI_INTEGRATION_TEST=1,
      // never set in production) disables CSRF so test POSTs against
      // /test/* don't have to round-trip a token cookie.
      csrf: integrationMode
        ? false
        : { cookie: { name: "wiki_csrf" }, fieldName: "csrf" },
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
          paths:          ["/admin", "/admin/", "/healthz/internal"],
          allowedCidrs:   adminAllowedCidrs,
          deniedCidrs:    adminDeniedCidrs,
          trustedProxies: adminTrustedProxies,
          audit:          b.audit,
        }));
      }
      // bodyParser + cspNonce are wired by createApp (see the middleware
      // block above). This cspNonce instance is kept ONLY for its
      // PLACEHOLDER + substitute() cacheable-render helpers — they read
      // the per-request req.cspNonce that createApp's wiring already set,
      // so the instance is never mounted again (that would be a no-op).
      var nonceMw = b.middleware.cspNonce();

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
      // CSRF is wired by createApp (see middleware.csrf above) — the
      // wiki's wiki_csrf cookie + csrf field name flow through that
      // default, so it is not mounted again here.
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
        secureProtocol: secureProtocol,
        assets:       assets,
        nonceMw:      nonceMw,
        siteUrl:      opts.siteUrl || "https://blamejs.com",
      };
      // ---- Age-gated demo route ----
      // Demonstrates b.middleware.ageGate riding the full wired stack
      // (securityHeaders, compression, rate limit). The age is derived
      // from the ?age= query field via Number(): a value that fails to
      // parse yields NaN, which the gate classifies as "unknown" and
      // answers with the child-safety privacy defaults (Cache-Control:
      // private, no-store; Referrer-Policy: no-referrer;
      // X-Privacy-Posture) instead of admitting the request as an
      // adult. consentRequired follows the COPPA threshold (13 and
      // under); requireAge stays null so the route classifies + sets
      // headers without refusing. Registered as a literal path so it
      // wins over the /:group catch-all.
      var ageGateDemo = b.middleware.ageGate({
        getAge: function (req) {
          return Number(req.query && req.query.age);
        },
        consentRequired: 13,
      });
      router.get("/age-check", function (req, res, next) {
        // ageGate publishes its classification on req.locals when the
        // object exists; seed it so the handler below can echo the
        // decision back to the caller.
        if (!req.locals || typeof req.locals !== "object") req.locals = {};
        return next();
      }, ageGateDemo, function (req, res) {
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(JSON.stringify({
          classification: (req.locals && req.locals.ageGateClassification) || null,
        }));
      });

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
