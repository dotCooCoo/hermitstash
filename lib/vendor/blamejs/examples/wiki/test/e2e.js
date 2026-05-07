"use strict";
// Wiki app e2e — boots the same wiring as server.js (via shared
// lib/build-app.js) on an ephemeral port, hits each route via node:http
// with realistic browser headers, asserts response codes and body
// content, then shuts down. The bot-guard / Sec-Fetch / rate-limit
// middleware run unmodified; the test sends the headers a real browser
// would. Accept-Encoding: identity opts out of compression so substring
// assertions don't have to decompress.

var http = require("node:http");
var path = require("node:path");
var fs = require("node:fs");
var b = require("@blamejs/core");
var { buildApp } = require("../lib/build-app");

// Persistent output to .test-output/wiki-e2e.log at the framework
// repo root so agents iterating on a failing run can grep the file
// instead of re-running. The .test-output/ dir is gitignored.
// Tee semantics — original stdout/stderr passthrough preserved so
// CI annotations + npm exit-code propagation work unchanged.
(function () {
  var REPO_ROOT_FOR_LOG = path.resolve(__dirname, "..", "..", "..");
  var LOG_DIR = path.join(REPO_ROOT_FOR_LOG, ".test-output");
  try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_e) { /* best-effort */ }
  var stream;
  try { stream = fs.createWriteStream(path.join(LOG_DIR, "wiki-e2e.log"), { flags: "w" }); }
  catch (_e) { return; /* CI runners with read-only checkout: skip log */ }
  var origStdout = process.stdout.write.bind(process.stdout);
  var origStderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = function (c, enc, cb) {
    try { stream.write(c, enc); } catch (_e) { /* best-effort */ }
    return origStdout(c, enc, cb);
  };
  process.stderr.write = function (c, enc, cb) {
    try { stream.write(c, enc); } catch (_e) { /* best-effort */ }
    return origStderr(c, enc, cb);
  };
})();
var sectionValidator = require("./validate-primitive-sections");
var envSnapshotValidator = require("./validate-env-snapshot");
var cliSnapshotValidator = require("./validate-cli-snapshot");
var codebasePatterns = require("./codebase-patterns.test");

// DATA_DIR honors a BLAMEJS_E2E_DATA_DIR override so the host e2e and
// the Linux-container e2e can run in parallel without colliding on
// the same disk path. Container invocations set BLAMEJS_E2E_DATA_DIR=
// /tmp/data-e2e (a path inside the container's overlay FS, not the
// host-mounted source tree).
var DATA_DIR = process.env.BLAMEJS_E2E_DATA_DIR ||
               path.join(__dirname, "..", "data-e2e");
var ADMIN_EMAIL = "admin-e2e@blamejs.com";
var ADMIN_PASSWORD = "e2e-test-password-x9k2";

// Browser-shaped headers — see test docstring above.
var BROWSER_HEADERS = {
  "user-agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language":  "en-US,en;q=0.9",
  "accept-encoding":  "identity",
  "sec-fetch-dest":   "document",
  "sec-fetch-mode":   "navigate",
  "sec-fetch-site":   "none",
};

function _request(opts, body) {
  return new Promise(function (resolve, reject) {
    var req = http.request(opts, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        var raw = Buffer.concat(chunks);
        resolve({
          statusCode: res.statusCode,
          headers:    res.headers,
          body:       raw.toString("utf8"),
          rawBuffer:  raw,
        });
      });
    });
    req.on("error", reject);
    req.setTimeout(5000, function () { req.destroy(new Error("request timed out — server stalled")); });
    if (body) req.write(body);
    req.end();
  });
}

async function _bootApp() {
  if (fs.existsSync(DATA_DIR)) fs.rmSync(DATA_DIR, { recursive: true, force: true });
  return buildApp({
    dataDir:       DATA_DIR,
    port:          0,                 // ephemeral
    adminEmail:    ADMIN_EMAIL,
    adminPassword: ADMIN_PASSWORD,
  });
}

var checks = 0;
var failures = [];
function assert(name, cond) {
  checks++;
  if (!cond) { failures.push(name); console.error("  ✗ " + name); }
  else       { console.log("  ✓ " + name); }
}

async function run() {
  // Step 0a — wiki primitive-section convention check (rule §11).
  // Runs before app boot so a structural docs gap surfaces immediately;
  // operators don't pay the boot cost when the gate would have failed
  // anyway.
  var validatorExit = sectionValidator.run({});
  if (validatorExit !== 0) {
    console.error("[wiki-e2e] aborted — primitive-section validator failed " +
      "(see lines above). Fix the missing pieces or add to the allowlist " +
      "with a one-line reason.");
    process.exit(validatorExit);
  }

  // Step 0b — wiki codebase-patterns gate. Same bug-class detectors as
  // the framework's test/layer-0-primitives/codebase-patterns.test.js,
  // applied to the wiki app's own JS surface. Catches drift in
  // operator-shipped code on the same patterns that bit the framework.
  var patternsExit = codebasePatterns.run();
  if (patternsExit !== 0) {
    console.error("[wiki-e2e] aborted — codebase-patterns gate failed " +
      "(see lines above). Fix violations or add documented allow markers.");
    process.exit(patternsExit);
  }

  console.log("[wiki-e2e] booting…");
  var built = await _bootApp();
  // Don't call scheduler.start() in tests — would ref the event loop
  // and prevent clean exit.
  var info = await built.app.listen({ port: 0 });
  var port = info.port;
  console.log("[wiki-e2e] listening on :" + port);

  try {
    var home = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/",
      headers: BROWSER_HEADERS,
    });
    assert("GET / → 200",                    home.statusCode === 200);
    assert("GET / body has 'blamejs'",       /blamejs/i.test(home.body));
    assert("GET / body has nav",             /rail-nav/i.test(home.body));
    assert("GET / loads strict CSP (no unsafe-inline)",
           home.headers["content-security-policy"] &&
           home.headers["content-security-policy"].indexOf("'unsafe-inline'") === -1);
    assert("GET / links Prism CSS",          /\/vendor\/prism\.css/.test(home.body));
    // Bundler emits hashed filenames: /dist/wiki.<16-hex>.js
    assert("GET / links bundled wiki.js",
           /\/dist\/wiki\.[a-f0-9]{16}\.js/.test(home.body));
    assert("GET / links logo PNG",           /\/img\/blamejs-logo\.png/.test(home.body));

    var health = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/healthz",
      headers: BROWSER_HEADERS,
    });
    assert("GET /healthz → 200",             health.statusCode === 200);
    assert("GET /healthz JSON has status:ok", /"status"\s*:\s*"ok"/.test(health.body));

    var ready = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/readyz",
      headers: BROWSER_HEADERS,
    });
    assert("GET /readyz → 200 (db check passes)", ready.statusCode === 200);

    var welcome = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/welcome",
      headers: BROWSER_HEADERS,
    });
    assert("GET /welcome → 200",       welcome.statusCode === 200);
    assert("welcome page mentions blamejs",  /blamejs/i.test(welcome.body));
    assert("welcome page has hello-world section",
           /hello-world/.test(welcome.body));
    assert("welcome page has design-tenets section",
           /design-tenets/.test(welcome.body));
    assert("welcome page links to concern groups",
           /href="\/observability"/.test(welcome.body) &&
           /href="\/auth"/.test(welcome.body));

    var obs = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/observability",
      headers: BROWSER_HEADERS,
    });
    assert("GET /observability → 200", obs.statusCode === 200);
    assert("observability page covers audit chain",
           /audit chain/i.test(obs.body) && /tamper-evident/i.test(obs.body));
    assert("observability page documents the 5 W's",
           /actor\.userId/.test(obs.body) && /actor\.requestId/.test(obs.body));
    assert("observability page covers tracing pass-through",
           /pass-through/i.test(obs.body) && /OTel/i.test(obs.body));
    assert("observability page includes redaction recipe",
           /b\.redact\.redact/.test(obs.body));
    assert("observability page covers OTel export",
           /b\.otelExport/.test(obs.body) && /OTLP/.test(obs.body));

    var auth = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/auth",
      headers: BROWSER_HEADERS,
    });
    assert("GET /auth → 200", auth.statusCode === 200);
    assert("auth page covers passwords + Argon2id",
           /Argon2id/.test(auth.body) && /b\.auth\.password/.test(auth.body));
    assert("auth page covers passkeys (WebAuthn)",
           /WebAuthn/.test(auth.body) && /b\.auth\.passkey/.test(auth.body));
    assert("auth page covers OAuth providers",
           /b\.auth\.oauth/.test(auth.body) && /PKCE/.test(auth.body));

    var access = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/access-control",
      headers: BROWSER_HEADERS,
    });
    assert("GET /access-control → 200", access.statusCode === 200);
    assert("access-control page covers RBAC roles",
           /b\.permissions/.test(access.body) && /inherits/.test(access.body));
    assert("access-control page covers break-glass",
           /b\.breakGlass/.test(access.body) && /grant/i.test(access.body));

    var database = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/database",
      headers: BROWSER_HEADERS,
    });
    assert("GET /database → 200", database.statusCode === 200);
    assert("database page covers sealed columns",
           /sealedFields/.test(database.body));
    assert("database page covers migrations advisory lock",
           /advisory lock/.test(database.body) && /SHA3-512/.test(database.body));

    var objectStore = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/object-store",
      headers: BROWSER_HEADERS,
    });
    assert("GET /object-store → 200", objectStore.statusCode === 200);
    assert("object-store page covers presigned uploads",
           /presignedUploadPolicy/.test(objectStore.body) && /SigV4/.test(objectStore.body));

    var queueCache = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/queue-cache",
      headers: BROWSER_HEADERS,
    });
    assert("GET /queue-cache → 200", queueCache.statusCode === 200);
    assert("queue-cache page covers queue + jobs",
           /b\.queue/.test(queueCache.body) && /b\.jobs/.test(queueCache.body));

    var routing = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/routing",
      headers: BROWSER_HEADERS,
    });
    assert("GET /routing → 200", routing.statusCode === 200);
    assert("routing page covers schema-validated routes",
           /b\.safeSchema/.test(routing.body));

    var middleware = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/middleware",
      headers: BROWSER_HEADERS,
    });
    assert("GET /middleware → 200", middleware.statusCode === 200);
    assert("middleware page documents the default stack",
           /requestId/.test(middleware.body) && /securityHeaders/.test(middleware.body) && /csrfProtect/.test(middleware.body));
    assert("middleware page covers cspNonce",
           /cspNonce/.test(middleware.body));
    assert("middleware page covers SSE",
           /Server-Sent Events|sseChannel/.test(middleware.body));

    var outboundHttp = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/outbound-http",
      headers: BROWSER_HEADERS,
    });
    assert("GET /outbound-http → 200", outboundHttp.statusCode === 200);
    assert("outbound-http page covers SSRF defense",
           /b\.ssrfGuard/.test(outboundHttp.body) && /SSRF/.test(outboundHttp.body));
    assert("outbound-http page covers signed webhooks",
           /b\.webhook/.test(outboundHttp.body));

    var safeParsers = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/safe-parsers",
      headers: BROWSER_HEADERS,
    });
    assert("GET /safe-parsers → 200", safeParsers.statusCode === 200);
    assert("safe-parsers page covers safeJson + parsers",
           /b\.safeJson/.test(safeParsers.body) && /b\.parsers/.test(safeParsers.body));
    assert("safe-parsers page covers config primitive",
           /b\.config/.test(safeParsers.body));

    var crypto = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/crypto-vault",
      headers: BROWSER_HEADERS,
    });
    assert("GET /crypto-vault → 200", crypto.statusCode === 200);
    assert("crypto page documents the storage envelope",
           /envelope/i.test(crypto.body) && /0xE1/.test(crypto.body));
    assert("crypto page covers ML-KEM + P-384 hybrid",
           /ML-KEM-1024/.test(crypto.body) && /P-384/.test(crypto.body));
    assert("crypto page covers vault wrapped vs plaintext",
           /wrapped/.test(crypto.body) && /BLAMEJS_VAULT_PASSPHRASE/.test(crypto.body));
    assert("crypto page covers PQ signatures",
           /SLH-DSA-SHAKE-256f/.test(crypto.body));

    var networkCrypto = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/network-crypto",
      headers: BROWSER_HEADERS,
    });
    assert("GET /network-crypto → 200", networkCrypto.statusCode === 200);
    assert("network-crypto page covers mTLS CA",
           /b\.mtlsCa/.test(networkCrypto.body));

    var testing = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/testing",
      headers: BROWSER_HEADERS,
    });
    assert("GET /testing → 200", testing.statusCode === 200);
    assert("testing page covers fakeClock",
           /fakeClock/.test(testing.body) && /clk\.advance/.test(testing.body));
    assert("testing page covers captureAudit + captureObservability",
           /captureAudit/.test(testing.body) && /captureObservability/.test(testing.body));

    var websockets = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/websockets",
      headers: BROWSER_HEADERS,
    });
    assert("GET /websockets → 200", websockets.statusCode === 200);
    assert("websockets page covers websocketChannels fan-out",
           /websocketChannels/.test(websockets.body) && /publish/.test(websockets.body));

    var mail = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/mail",
      headers: BROWSER_HEADERS,
    });
    assert("GET /mail → 200", mail.statusCode === 200);
    assert("mail page covers bounce intake",
           /b\.mailBounce/.test(mail.body) && /Postmark/.test(mail.body));
    assert("mail page covers DKIM signing",
           /DKIM/.test(mail.body));

    var notifications = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/notifications",
      headers: BROWSER_HEADERS,
    });
    assert("GET /notifications → 200", notifications.statusCode === 200);
    assert("notifications page covers b.notify transports",
           /b\.notify\.transports\.log/.test(notifications.body) && /httpJson/.test(notifications.body));

    var i18n = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/i18n-locale",
      headers: BROWSER_HEADERS,
    });
    assert("GET /i18n-locale → 200", i18n.statusCode === 200);
    assert("i18n page covers ICU MessageFormat plurals",
           /MessageFormat/.test(i18n.body) && /plural/.test(i18n.body));
    assert("i18n page covers RTL detection",
           /req\.dir/.test(i18n.body) && /rtl/.test(i18n.body));

    var formatHelpers = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/format-helpers",
      headers: BROWSER_HEADERS,
    });
    assert("GET /format-helpers → 200", formatHelpers.statusCode === 200);
    assert("format-helpers page covers csv + uuid + slug + time",
           /b\.csv/.test(formatHelpers.body) && /b\.uuid/.test(formatHelpers.body) &&
           /b\.slug/.test(formatHelpers.body) && /b\.time/.test(formatHelpers.body));
    assert("format-helpers page covers archive + pagination + forms",
           /b\.archive/.test(formatHelpers.body) && /b\.pagination/.test(formatHelpers.body) &&
           /b\.forms/.test(formatHelpers.body));

    var cluster = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/cluster",
      headers: BROWSER_HEADERS,
    });
    assert("GET /cluster → 200", cluster.statusCode === 200);
    assert("cluster page covers exactly-once-globally scheduler",
           /exactly once globally/.test(cluster.body) && /fencing token/.test(cluster.body));
    assert("cluster page covers ntpCheck",
           /b\.ntpCheck/.test(cluster.body));

    var reliability = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/reliability",
      headers: BROWSER_HEADERS,
    });
    assert("GET /reliability → 200", reliability.statusCode === 200);
    assert("reliability page covers retry + circuit breaker",
           /b\.retry\.withRetry/.test(reliability.body) && /CircuitBreaker/.test(reliability.body));

    var compliancePatterns = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/compliance-patterns",
      headers: BROWSER_HEADERS,
    });
    assert("GET /compliance-patterns → 200", compliancePatterns.statusCode === 200);
    assert("compliance-patterns page covers all three threat models",
           /sealed columns/i.test(compliancePatterns.body) &&
           /break-glass/i.test(compliancePatterns.body) &&
           /search_path/i.test(compliancePatterns.body));
    assert("compliance-patterns page covers connectAs",
           /connectAs/.test(compliancePatterns.body));
    assert("compliance-patterns page covers read-replica routing",
           /read\.query|replicaFallbackToPrimary/.test(compliancePatterns.body));
    assert("compliance-patterns page covers dbRoleFor middleware",
           /dbRoleFor/.test(compliancePatterns.body) &&
           /dbRoleBackends/.test(compliancePatterns.body));
    assert("compliance-patterns page covers declareRowPolicy + sessionGucs",
           /declareRowPolicy/.test(compliancePatterns.body) &&
           /sessionGucs/.test(compliancePatterns.body));
    assert("compliance-patterns page documents tenant-per-row vs tenant-per-schema",
           /tenant-per-row/i.test(compliancePatterns.body) &&
           /tenant-per-schema/i.test(compliancePatterns.body));
    assert("compliance-patterns page has Pick-your-defenses decision tree",
           /Pick your defenses/i.test(compliancePatterns.body) &&
           /What are you defending against/i.test(compliancePatterns.body));

    var backupRestore = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/backup-restore",
      headers: BROWSER_HEADERS,
    });
    assert("GET /backup-restore → 200", backupRestore.statusCode === 200);
    assert("backup-restore page covers backup primitive + chain",
           /b\.backup/.test(backupRestore.body) && /prev-hash chain|chain/i.test(backupRestore.body));
    assert("backup-restore page documents backup encryption format",
           /XChaCha20-Poly1305/.test(backupRestore.body) && /Argon2id/.test(backupRestore.body));
    assert("backup-restore page documents backup CLI surface",
           /blamejs backup/.test(backupRestore.body));

    // Canonicalization: /<group>/index 301-redirects to /<group> so
    // there's one canonical URL for the landing page.
    var redirect = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/welcome/index",
      headers: BROWSER_HEADERS,
    });
    assert("GET /welcome/index → 301 to /welcome",
           redirect.statusCode === 301 && (redirect.headers.location || "") === "/welcome");

    var search = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/search?q=blamejs",
      headers: BROWSER_HEADERS,
    });
    assert("GET /search?q=blamejs → 200",    search.statusCode === 200);
    assert("search shows query echo",        /blamejs/i.test(search.body));

    var noPage = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/missing/missing",
      headers: BROWSER_HEADERS,
    });
    assert("GET /missing/missing → 404",     noPage.statusCode === 404);

    var anonAdmin = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/admin",
      headers: BROWSER_HEADERS,
    });
    assert("anon GET /admin → 401",          anonAdmin.statusCode === 401);

    var loginGet = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/login",
      headers: BROWSER_HEADERS,
    });
    assert("GET /login → 200",               loginGet.statusCode === 200);
    assert("login form has csrf hidden field", /name="csrf"/.test(loginGet.body));

    // ---- POST /login + authenticated /admin ---- (the missing leg
    // that previously hid the session-cookie return-shape bug).
    var csrfMatch = loginGet.body.match(/name="csrf"\s+value="([0-9a-f]+)"/);
    assert("login form has populated csrf token", !!(csrfMatch && csrfMatch[1]));
    var csrf = csrfMatch ? csrfMatch[1] : "";
    // Pull the wiki_csrf cookie off the GET response so the POST carries it.
    var setCookieRaw = loginGet.headers["set-cookie"] || [];
    var cookieHeader = (Array.isArray(setCookieRaw) ? setCookieRaw : [setCookieRaw])
      .map(function (sc) { return String(sc).split(";")[0]; })
      .join("; ");
    assert("GET /login set wiki_csrf cookie", /wiki_csrf=/.test(cookieHeader));

    var loginPostBody = "csrf=" + encodeURIComponent(csrf) +
      "&email=" + encodeURIComponent(ADMIN_EMAIL) +
      "&password=" + encodeURIComponent(ADMIN_PASSWORD);
    var loginPost = await _request({
      method: "POST", host: "127.0.0.1", port: port, path: "/login",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "content-type":   "application/x-www-form-urlencoded",
        "content-length": Buffer.byteLength(loginPostBody),
        "origin":         "http://127.0.0.1:" + port,
        "sec-fetch-site": "same-origin",
        "cookie":         cookieHeader,
      }),
    }, loginPostBody);
    assert("POST /login redirects to /admin (302)",
           loginPost.statusCode === 302 && /\/admin/.test(loginPost.headers.location || ""));
    var sessionSetCookie = loginPost.headers["set-cookie"] || [];
    var sessionCookie = (Array.isArray(sessionSetCookie) ? sessionSetCookie : [sessionSetCookie])
      .map(function (sc) { return String(sc); })
      .find(function (sc) { return /^wiki_sid=/.test(sc); }) || "";
    assert("POST /login sets wiki_sid cookie", /^wiki_sid=[^;]+/.test(sessionCookie));
    assert("wiki_sid value is a non-empty token (not '[object Object]')",
           !/wiki_sid=(\[object|undefined|null|\s*;)/.test(sessionCookie) &&
           /^wiki_sid=[a-f0-9]{16,}/.test(sessionCookie));

    var sessionCookieValue = sessionCookie.split(";")[0]; // wiki_sid=<token>
    var fullCookie = cookieHeader + "; " + sessionCookieValue;
    var authedAdmin = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/admin",
      headers: Object.assign({}, BROWSER_HEADERS, { cookie: fullCookie }),
    });
    assert("authenticated GET /admin → 200",
           authedAdmin.statusCode === 200);
    assert("authenticated /admin renders admin dashboard",
           /admin/i.test(authedAdmin.body) && !/missing_actor/.test(authedAdmin.body));

    // Walk every authenticated admin route reachable via GET — this
    // catches template syntax errors / handler-side regressions that
    // would otherwise only surface when an operator clicks the link.
    var authedRoutes = [
      { path: "/admin/edit",                   needle: /name="title"/i },
      { path: "/admin/edit/welcome/index",     needle: /welcome/i },
      { path: "/admin/api-keys",               needle: /api keys/i },
    ];
    for (var ar = 0; ar < authedRoutes.length; ar++) {
      var rt = authedRoutes[ar];
      var routeResp = await _request({
        method: "GET", host: "127.0.0.1", port: port, path: rt.path,
        headers: Object.assign({}, BROWSER_HEADERS, { cookie: fullCookie }),
      });
      assert("authenticated GET " + rt.path + " → 200", routeResp.statusCode === 200);
      assert("authenticated GET " + rt.path + " body matches expected content",
             rt.needle.test(routeResp.body));
      assert("authenticated GET " + rt.path + " not a 500/template error",
             !/INTERNAL_ERROR|trailing tokens|template:/i.test(routeResp.body));
    }

    // ---- Brute-force lockout on /login ----
    // Hammer /login with bad credentials for an unknown email; after
    // a few attempts the lockout primitive should respond 429 and
    // include a Retry-After header. Use a different email than the
    // valid admin so the legitimate account isn't locked.
    var bfEmail = "bf-target@example.test";
    var lockoutHit = false;
    for (var bfAttempt = 0; bfAttempt < 8; bfAttempt++) {
      var bfBody = "csrf=" + encodeURIComponent(csrf) +
        "&email=" + encodeURIComponent(bfEmail) +
        "&password=wrong-pass-" + bfAttempt;
      var bfResp = await _request({
        method: "POST", host: "127.0.0.1", port: port, path: "/login",
        headers: Object.assign({}, BROWSER_HEADERS, {
          "content-type":   "application/x-www-form-urlencoded",
          "content-length": Buffer.byteLength(bfBody),
          "origin":         "http://127.0.0.1:" + port,
          "sec-fetch-site": "same-origin",
          "cookie":         cookieHeader,
        }),
      }, bfBody);
      if (bfResp.statusCode === 429) {
        lockoutHit = true;
        assert("lockout response carries Retry-After header",
               typeof bfResp.headers["retry-after"] === "string" &&
               /^\d+$/.test(bfResp.headers["retry-after"]));
        break;
      }
    }
    assert("brute-force lockout engages within 8 bad-cred attempts",
           lockoutHit === true);

    // Negative case: malformed CSRF on POST must be refused (403 with
    // "CSRF token mismatch" — the form value doesn't match the cookie).
    var badCsrfBody = "csrf=deadbeef" +
      "&email=" + encodeURIComponent(ADMIN_EMAIL) +
      "&password=" + encodeURIComponent(ADMIN_PASSWORD);
    var badCsrf = await _request({
      method: "POST", host: "127.0.0.1", port: port, path: "/login",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "content-type":   "application/x-www-form-urlencoded",
        "content-length": Buffer.byteLength(badCsrfBody),
        "origin":         "http://127.0.0.1:" + port,
        "sec-fetch-site": "same-origin",
        "cookie":         cookieHeader,
      }),
    }, badCsrfBody);
    assert("POST /login with bad CSRF → 403",
           badCsrf.statusCode === 403);
    assert("POST /login with bad CSRF body mentions mismatch",
           /CSRF token mismatch/i.test(badCsrf.body));

    // ---- Static asset checks ----
    var prismJs = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/vendor/prism.js",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("GET /vendor/prism.js → 200",     prismJs.statusCode === 200);
    assert("prism.js mentions Prism",        /Prism/.test(prismJs.body));
    assert("prism.js bundles javascript grammar",
           /Prism\.languages\.javascript/.test(prismJs.body));

    var prismCss = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/vendor/prism.css",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "sec-fetch-dest": "style", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("GET /vendor/prism.css → 200",    prismCss.statusCode === 200);
    assert("prism.css is non-empty (theme actually vendored)",
           prismCss.body.length > 500);
    assert("prism.css defines token rules",
           /\.token\.keyword/.test(prismCss.body) && /\.token\.string/.test(prismCss.body));
    assert("prism.css uses tomorrow theme dark bg",
           /background:#2d2d2d/.test(prismCss.body));

    // Bundled wiki.js — extract the hashed path from the home HTML
    // and verify staticServe returns the bundled artifact.
    var wikiBundleMatch = home.body.match(/\/dist\/(wiki\.[a-f0-9]{16}\.js)/);
    assert("home HTML includes bundled wiki.js path", !!wikiBundleMatch);
    if (wikiBundleMatch) {
      var bundledWiki = await _request({
        method: "GET", host: "127.0.0.1", port: port, path: "/dist/" + wikiBundleMatch[1],
        headers: Object.assign({}, BROWSER_HEADERS, {
          "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors",
        }),
      });
      assert("GET bundled wiki.js → 200",    bundledWiki.statusCode === 200);
      assert("bundled wiki.js mentions IntersectionObserver",
             /IntersectionObserver/.test(bundledWiki.body));
    }
    // Bundler manifest is published to /dist/manifest.json
    var manifest = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/dist/manifest.json",
      headers: BROWSER_HEADERS,
    });
    assert("GET /dist/manifest.json → 200",  manifest.statusCode === 200);
    assert("manifest maps wiki + editor entries",
           /wiki\.[a-f0-9]{16}\.js/.test(manifest.body) &&
           /editor\.[a-f0-9]{16}\.js/.test(manifest.body));

    var wikiCss = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/wiki.css",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "sec-fetch-dest": "style", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("GET /wiki.css → 200",            wikiCss.statusCode === 200);

    var logo = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/img/blamejs-logo.png",
      headers: Object.assign({}, BROWSER_HEADERS, {
        "sec-fetch-dest": "image", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("GET /img/blamejs-logo.png → 200", logo.statusCode === 200);
    assert("logo is served as image/png",
           /image\/png/.test(logo.headers["content-type"] || ""));

    // ---- Compression-on path (what real browsers actually do) ----
    // Regression: every other request in this suite uses
    // Accept-Encoding: identity for assertion convenience. That hid
    // a real backpressure stall in the framework's compression
    // middleware where stream.pipe(res) of a file > 16 KB hung
    // because the wrapped res.write returned false on compressor
    // backpressure but never re-emitted 'drain'. These checks force
    // the gzip/br code path so the regression can't recur.
    var zlib = require("node:zlib");
    var COMPRESS_HEADERS = Object.assign({}, BROWSER_HEADERS, {
      "accept-encoding": "gzip, br",
    });

    // Static file served by staticServe + piped through compression.
    // prism.js is 39 KB — well past zlib's 16 KB highWaterMark.
    var prismCompressed = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/vendor/prism.js",
      headers: Object.assign({}, COMPRESS_HEADERS, {
        "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors",
      }),
    });
    assert("compressed prism.js → 200 (no stall)",
           prismCompressed.statusCode === 200);
    assert("compressed prism.js: Content-Encoding present",
           !!prismCompressed.headers["content-encoding"]);
    assert("compressed prism.js: no Content-Length (chunked)",
           prismCompressed.headers["content-length"] === undefined);
    var enc = prismCompressed.headers["content-encoding"];
    var prismDecoded =
      enc === "br"   ? zlib.brotliDecompressSync(prismCompressed.rawBuffer) :
      enc === "gzip" ? zlib.gunzipSync(prismCompressed.rawBuffer) :
                       prismCompressed.rawBuffer;
    assert("compressed prism.js decompresses to bundle",
           /Prism\.languages\.javascript/.test(prismDecoded.toString("utf8")));

    // Templated HTML page served by routes/pages.js + cached + piped
    // through compression.
    var welcomeCompressed = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/welcome",
      headers: COMPRESS_HEADERS,
    });
    assert("compressed /welcome → 200 (no stall)",
           welcomeCompressed.statusCode === 200);
    assert("compressed /welcome: Content-Encoding present",
           !!welcomeCompressed.headers["content-encoding"]);
    var pageEnc = welcomeCompressed.headers["content-encoding"];
    var welcomeDecoded =
      pageEnc === "br"   ? zlib.brotliDecompressSync(welcomeCompressed.rawBuffer) :
      pageEnc === "gzip" ? zlib.gunzipSync(welcomeCompressed.rawBuffer) :
                           welcomeCompressed.rawBuffer;
    var welcomeHtml = welcomeDecoded.toString("utf8");
    assert("compressed welcome page contains body",
           /blamejs/i.test(welcomeHtml) && /<h1/.test(welcomeHtml));
    // CSP nonce must match between header and every rendered script
    // tag (regression for the cached-stale-nonce bug — the page cache
    // held a render with a frozen nonce, but the CSP header rotated
    // per request, so script tags had a nonce the browser rejected).
    var cspMatch = (welcomeCompressed.headers["content-security-policy"] || "")
      .match(/'nonce-([A-Za-z0-9+/=]+)'/);
    var headerNonce  = cspMatch ? cspMatch[1] : null;
    var scriptNonces = [];
    var nonceRe = /<script[^>]+nonce="([^"]+)"/g;
    var m;
    while ((m = nonceRe.exec(welcomeHtml)) !== null) scriptNonces.push(m[1]);
    assert("compressed welcome page: header CSP nonce present", headerNonce !== null);
    assert("compressed welcome page: at least one nonced script",
           scriptNonces.length > 0);
    assert("compressed welcome page: every script nonce matches CSP header nonce",
           headerNonce !== null &&
           scriptNonces.length > 0 &&
           scriptNonces.every(function (n) { return n === headerNonce; }));

    // Second hit — same path, served from page cache. The cached HTML
    // contains a placeholder; substitution at serve time has to give
    // it a fresh nonce that matches the new CSP header.
    var welcome2 = await _request({
      method: "GET", host: "127.0.0.1", port: port, path: "/welcome",
      headers: COMPRESS_HEADERS,
    });
    var cached2enc = welcome2.headers["content-encoding"];
    var welcome2Html = (
      cached2enc === "br"   ? zlib.brotliDecompressSync(welcome2.rawBuffer) :
      cached2enc === "gzip" ? zlib.gunzipSync(welcome2.rawBuffer) :
                              welcome2.rawBuffer
    ).toString("utf8");
    var csp2    = (welcome2.headers["content-security-policy"] || "").match(/'nonce-([A-Za-z0-9+/=]+)'/);
    var script2 = welcome2Html.match(/<script[^>]+nonce="([^"]+)"/);
    assert("cached page re-render: CSP nonce rotates between requests",
           csp2 !== null && headerNonce !== null && csp2[1] !== headerNonce);
    assert("cached page re-render: script nonce tracks the new CSP nonce",
           csp2 !== null && script2 !== null && script2[1] === csp2[1]);

    // ---- Page-content completeness ----
    // Walk every concern-group landing page, extract internal links
    // and code-block language classes, and verify they all resolve /
    // are valid. Catches things like a typo'd <a href="/auht-...">
    // (typo) or a <code class="language-rust"> when Rust isn't in the
    // Prism bundle.
    var GROUPS = [
      "welcome",
      "database", "object-store", "queue-cache",
      "auth", "access-control",
      "crypto-vault", "network-crypto",
      "routing", "middleware", "outbound-http",
      "safe-parsers",
      "websockets", "mail", "notifications",
      "observability", "testing", "i18n-locale",
      "format-helpers",
      "compliance-patterns",
      "cluster", "reliability", "backup-restore",
    ];
    // Evaluate the bundle in a sandbox and read Prism.languages directly.
    // Source-text scanning misses languages bound through the IIFE
    // local (e.g. `e.languages.bash` inside `(function(e){...})(Prism)`).
    var vm = require("node:vm");
    var sandbox = {
      window:                 {},
      self:                   {},
      document:               { readyState: "complete", currentScript: null, addEventListener: function () {}, getElementsByTagName: function () { return []; } },
      Element:                function () {},
      requestAnimationFrame:  function () {},
    };
    sandbox.window = sandbox; sandbox.self = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(prismJs.body, sandbox, { filename: "prism.js" });
    var prismLangs = new Set(Object.keys((sandbox.Prism && sandbox.Prism.languages) || {}));
    assert("Prism bundle exposes javascript + bash + html",
           prismLangs.has("javascript") && prismLangs.has("bash") && prismLangs.has("html"));

    var allInternalLinks = new Set();
    var allLanguages     = new Set();
    for (var gi = 0; gi < GROUPS.length; gi++) {
      var page = await _request({
        method: "GET", host: "127.0.0.1", port: port, path: "/" + GROUPS[gi],
        headers: BROWSER_HEADERS,
      });
      assert("completeness: GET /" + GROUPS[gi] + " → 200", page.statusCode === 200);
      var bodyOnly = page.body;
      // Internal links — only paths that start with "/" and don't
      // include "://"; ignore hash-only fragments.
      var linkRe = /href="(\/[a-z0-9][a-z0-9/_\-#]*)"/g;
      var lm = bodyOnly.match(linkRe) || [];
      lm.forEach(function (s) {
        var href = s.replace(/^href="/, "").replace(/"$/, "");
        var withoutHash = href.indexOf("#") === -1 ? href : href.slice(0, href.indexOf("#"));
        if (withoutHash) allInternalLinks.add(withoutHash);
      });
      // Code-block languages
      var codeRe = /<code\s+class="language-([a-z0-9]+)"/g;
      var cm = bodyOnly.match(codeRe) || [];
      cm.forEach(function (s) {
        var lang = s.replace(/^<code\s+class="language-/, "").replace(/"$/, "");
        allLanguages.add(lang);
      });
    }
    assert("completeness: scanned ≥10 internal links",     allInternalLinks.size >= 10);
    assert("completeness: scanned ≥3 code-block languages", allLanguages.size >= 3);

    // ---- env-var snapshot gate ----
    // Catches drift between the wiki's source `process.env.X` reads,
    // the framework's `safeEnv.readVar("X")` reads (in lib/), and the
    // env knobs declared in docker-compose.yml + docker-compose.prod.yml.
    // Same UX as api-snapshot — refresh with BLAMEJS_UPDATE_ENV_SNAPSHOT=1.
    var envCaptured = envSnapshotValidator.captureSnapshot();
    var envVerdict  = envSnapshotValidator.compareSnapshot(envCaptured);
    assert("env-snapshot: file exists (run BLAMEJS_UPDATE_ENV_SNAPSHOT=1 if missing)",
      envVerdict.initialized);
    assert("env-snapshot: no drift between captured + committed snapshot (" +
      envVerdict.drift.length + " field(s) drifted)",
      envVerdict.drift.length === 0);
    if (envVerdict.drift.length > 0) {
      envVerdict.drift.forEach(function (d) {
        var sign = d.kind === "added" ? "+" : "-";
        console.error("  env-snapshot " + sign + " " + d.field + ": " + d.keys.join(", "));
      });
    }
    assert("env-snapshot: no source-only / compose-only gaps (" +
      envVerdict.gaps.length + " gap(s))",
      envVerdict.gaps.length === 0);
    if (envVerdict.gaps.length > 0) {
      envVerdict.gaps.forEach(function (g) {
        console.error("  env-snapshot " + g.side + ": " + g.key);
      });
    }

    // ---- CLI surface snapshot gate ----
    // Catches drift between lib/cli.js (subcommands + flags), README's
    // CLI section, and wiki references. Same UX as api-snapshot +
    // env-snapshot — refresh with BLAMEJS_UPDATE_CLI_SNAPSHOT=1.
    var cliCaptured = cliSnapshotValidator.captureSnapshot();
    var cliVerdict  = cliSnapshotValidator.compareSnapshot(cliCaptured);
    assert("cli-snapshot: file exists (run BLAMEJS_UPDATE_CLI_SNAPSHOT=1 if missing)",
      cliVerdict.initialized);
    assert("cli-snapshot: no drift between captured + committed snapshot (" +
      cliVerdict.drift.length + " field(s) drifted)",
      cliVerdict.drift.length === 0);
    if (cliVerdict.drift.length > 0) {
      cliVerdict.drift.forEach(function (d) {
        var sign = d.kind === "added" ? "+" : "-";
        console.error("  cli-snapshot " + sign + " " + d.field + ": " + d.keys.join(", "));
      });
    }
    assert("cli-snapshot: no cli-only / readme-only gaps (" +
      cliVerdict.gaps.length + " gap(s))",
      cliVerdict.gaps.length === 0);
    if (cliVerdict.gaps.length > 0) {
      cliVerdict.gaps.forEach(function (g) {
        console.error("  cli-snapshot " + g.side + ": " + g.key);
      });
    }

    // Every language used in a docs code block must be loadable by
    // the Prism bundle we ship.
    var unknownLangs = [];
    allLanguages.forEach(function (lang) {
      if (!prismLangs.has(lang)) unknownLangs.push(lang);
    });
    assert("completeness: every code-block language is in the Prism bundle " +
           (unknownLangs.length > 0 ? "(unknown: " + unknownLangs.join(",") + ")" : ""),
           unknownLangs.length === 0);

    // Every internal link resolves (2xx or 3xx). Skips links to
    // /admin (auth-gated) and /login (form route).
    var brokenLinks = [];
    var linksToFetch = [];
    allInternalLinks.forEach(function (link) {
      if (link === "/admin" || link === "/login" || link === "/logout") return;
      linksToFetch.push(link);
    });
    for (var li = 0; li < linksToFetch.length; li++) {
      var link = linksToFetch[li];
      var resp = await _request({
        method: "GET", host: "127.0.0.1", port: port, path: link,
        headers: BROWSER_HEADERS,
      });
      if (resp.statusCode < 200 || resp.statusCode >= 400) {
        brokenLinks.push(link + " → " + resp.statusCode);
      }
    }
    assert("completeness: every internal link resolves (no 4xx/5xx) " +
           (brokenLinks.length > 0 ? "broken: " + brokenLinks.join(", ") : ""),
           brokenLinks.length === 0);

    // Post-boot pass — example execution. Each non-opts javascript example
    // block is parsed, symbol-resolution-checked against the live
    // framework, then run in a sandboxed async wrapper. Examples that
    // legitimately reference operator-stubbed names (req/res/db rows)
    // get the harness stubs and pass; examples whose `b.X.Y` references
    // don't resolve fail the gate (drift).
    var execReport = await sectionValidator.runExamples(b);
    assert("examples: zero syntax errors across primitive sections (" +
           execReport.syntaxFailed.length + " failed)",
           execReport.syntaxFailed.length === 0);
    if (execReport.syntaxFailed.length > 0) {
      execReport.syntaxFailed.forEach(function (f) {
        console.error("  syntax: " + f.slug + " :: " + f.heading + " — " + f.error);
      });
    }
    assert("examples: every b.X.Y reference resolves on the live framework (" +
           execReport.symbolFailed.length + " drift)",
           execReport.symbolFailed.length === 0);
    if (execReport.symbolFailed.length > 0) {
      execReport.symbolFailed.forEach(function (f) {
        console.error("  symbol drift: " + f.slug + " :: " + f.heading +
          " — unresolved: " + f.unresolved.join(", "));
      });
    }
    // Execution: each example runs in a forked child against a fresh
    // framework instance with the canonical test fixture (vault, db
    // with reference schema, audit live, queue init'd, externalDb with
    // a fake Postgres-dialect backend). Stubs in scope: req, res,
    // env(), pg, connectPrimary/replica/replica1/replica2, rawConnect,
    // rawQuery, log, etc. Examples that throw at the framework
    // boundary fail the gate — that's drift the wiki author should
    // fix.
    // Print every failure BEFORE the assert — assert throws on
    // failure, so anything after it would never execute (and the
    // operator would never see WHICH example failed). Drift bug
    // caught when the parallel-fork failure detail wasn't surfacing
    // to .test-output/wiki-e2e.log.
    if (execReport.executionFailed.length > 0) {
      execReport.executionFailed.forEach(function (f) {
        console.error("  exec fail: " + f.slug + " :: " + f.heading);
        console.error("    status: " + f.status);
        if (f.missing) console.error("    missing identifier: " + f.missing);
        if (f.error)   console.error("    error: " + f.error);
        if (f.stack)   console.error("    stack: " + f.stack);
      });
    }
    assert("examples: zero runtime failures across primitive sections (" +
           execReport.executionFailed.length + " failed, " +
           execReport.ran + " ran clean)",
           execReport.executionFailed.length === 0);
  } finally {
    await built.app.shutdown();
  }

  console.log("");
  if (failures.length > 0) {
    console.error("[wiki-e2e] FAIL — " + failures.length + " of " + checks + " checks failed:");
    failures.forEach(function (f) { console.error("  - " + f); });
    process.exit(1);
  }
  console.log("[wiki-e2e] OK — " + checks + " checks passed");
}

run().catch(function (e) {
  console.error("[wiki-e2e] FATAL:", e && e.stack || e);
  process.exit(1);
});
