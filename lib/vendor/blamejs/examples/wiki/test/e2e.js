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
var envSnapshotValidator = require("./validate-env-snapshot");
var cliSnapshotValidator = require("./validate-cli-snapshot");
var codebasePatterns = require("./codebase-patterns.test");
var sourceCommentBlocksValidator = require("./validate-source-comment-blocks");
var navCoverageValidator = require("./validate-nav-coverage");
var siteCoverageValidator = require("./validate-site-coverage");

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
  // Step 0a-pre — source-driven comment-block validator. Runs before
  // the primitive-section validator because a malformed @primitive
  // block would feed bad bodies into the seeder (and thus into the
  // section validator's input). Cheaper to fail fast at the source.
  var sourceFindings = sourceCommentBlocksValidator.validate();
  if (sourceFindings.length > 0) {
    console.error("[wiki-e2e] source comment-block validator: " + sourceFindings.length + " finding(s):");
    sourceFindings.forEach(function (f, i) {
      console.error("  " + (i + 1) + ". " + f.file + (f.primitive ? " :: " + f.primitive : ""));
      console.error("     " + f.msg);
    });
    console.error("[wiki-e2e] aborted — fix the @primitive blocks or add to the e2e --report bypass.");
    process.exit(1);
  }
  console.log("[wiki-e2e] source comment-block validator: OK");

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
    // Since v0.8.61 the framework's sid is wrapped in b.vault.seal,
    // so the cookie value is `vault:<base64-envelope>`, not the
    // pre-v0.8.61 hex form. Defend against the [object Object] /
    // undefined / null stringification regressions, then assert the
    // sealed-prefix shape.
    assert("wiki_sid value is a non-empty token (not '[object Object]')",
           !/wiki_sid=(\[object|undefined|null|\s*;)/.test(sessionCookie) &&
           /^wiki_sid=vault:[A-Za-z0-9+/=_-]{16,}/.test(sessionCookie));

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
    // Derive the page list from site.config — the wiki is now source-
    // driven (every @module block in lib/ produces a page) and the
    // hand-authored slug list went stale every release.
    var siteCfg = require("../site.config");
    var GROUPS = siteCfg.expectedSlugs();
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

    // ---- Site coverage gate ----
    // Validates the unified site.config.js drives nav, cards, and
    // page-generator curation consistently — every entry resolves to
    // exactly one seeded page, every seeded page is registered in
    // site.config, every nav group is non-empty, every card has a
    // description, every concept/namespace/harvest reference resolves.
    var siteFindings = siteCoverageValidator.validate({
      dbPath: path.join(DATA_DIR, "blamejs.db"),
    });
    assert("site-coverage: 0 findings (got " + siteFindings.length + ")", siteFindings.length === 0);
    if (siteFindings.length > 0) {
      siteFindings.forEach(function (f) {
        console.error("  site-cov: [" + f.kind + "] " + f.slug + " — " + f.msg);
      });
    }

    // ---- Nav coverage gate ----
    // Walks every entry in lib/nav.js (Welcome + every group's items),
    // hits the live HTTP listener, and asserts each page renders 200
    // with a populated <main> body (H1 matching the nav title +
    // at least one paragraph + at least one sub-heading / code block /
    // card-grid). Catches placeholder pages, stale nav entries
    // pointing at deleted pages, and template-render regressions.
    await navCoverageValidator.validate.call({
      port: info.port, host: "127.0.0.1",
    });
    // The validator reads its port from --port=NNN; for in-process boot
    // we fork the env var as well so the in-line require's IIFE picks
    // up the ephemeral port (the validator's port arg defaults to 3211
    // when invoked standalone).
    // The validator binds to PORT 3211 by default; when running under
    // e2e on an ephemeral port, re-do the walk through the local
    // request helper so we hit info.port directly.
    var navEntries = require("../lib/nav").NAV_GROUPS.reduce(function (acc, g) {
      g.items.forEach(function (it) { acc.push({ slug: it.slug, title: it.title, group: g.name }); });
      return acc;
    }, [{ slug: "welcome", title: "Welcome", group: null }]);
    var navFailures = [];
    for (var ni = 0; ni < navEntries.length; ni++) {
      var ne = navEntries[ni];
      var navPage = await _request({
        method: "GET", host: "127.0.0.1", port: info.port, path: "/" + ne.slug,
        headers: BROWSER_HEADERS,
      });
      if (navPage.statusCode !== 200) {
        navFailures.push("/" + ne.slug + " -> " + navPage.statusCode); continue;
      }
      var b2 = navPage.body;
      var mainStart = b2.indexOf("<main"), mainEnd = b2.indexOf("</main>");
      if (mainStart === -1 || mainEnd === -1) { navFailures.push("/" + ne.slug + " missing <main>"); continue; }
      var mainSlice = b2.slice(mainStart, mainEnd);
      var h1m = mainSlice.match(/<h1[^>]*>([\s\S]*?)<\/h1>/);
      if (!h1m) { navFailures.push("/" + ne.slug + " missing <h1>"); continue; }
      var h1Text = h1m[1].replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim();
      if (h1Text !== ne.title && h1Text.indexOf(ne.title) === -1) {
        navFailures.push("/" + ne.slug + " <h1> `" + h1Text + "` ≠ `" + ne.title + "`");
        continue;
      }
      var paraCount = (mainSlice.match(/<p[\s>]/g) || []).length;
      var preCount = (mainSlice.match(/<pre[\s>]/g) || []).length;
      var h2Count = (mainSlice.match(/<h2[\s>]/g) || []).length;
      var h3Count = (mainSlice.match(/<h3[\s>]/g) || []).length;
      var hasCards = mainSlice.indexOf("card-grid") !== -1;
      if (paraCount === 0 || (preCount === 0 && h2Count === 0 && h3Count === 0 && !hasCards)) {
        navFailures.push("/" + ne.slug + " has no populated content (p=" + paraCount + " pre=" + preCount + " h2=" + h2Count + " h3=" + h3Count + " cards=" + hasCards + ")");
      }
    }
    assert("nav-coverage: every nav entry (" + navEntries.length + ") reaches a populated page (" + navFailures.length + " failure(s))",
      navFailures.length === 0);
    if (navFailures.length > 0) {
      navFailures.forEach(function (f) { console.error("  nav-cov: " + f); });
    }

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

    // Note: post-boot example execution is now handled by
    // validate-source-comment-blocks.js's syntax-parse pass earlier
    // in the run (Step 0a-pre). The legacy hand-authored-seeder
    // example runner (`validate-primitive-sections.runExamples`) was
    // retired with the source-driven wiki migration — every example
    // body lives in a `@example` block in lib/, parsed via
    // `vm.Script` at validation time. Runtime symbol-resolution
    // checking is currently weaker than the legacy fork-per-example
    // path; re-add as a separate gate when needed.
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
