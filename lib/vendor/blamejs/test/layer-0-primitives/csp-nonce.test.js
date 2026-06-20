"use strict";
/**
 * csp-nonce — per-request CSP nonce + render integration.
 *
 * Run standalone: `node test/layer-0-primitives/csp-nonce.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _cspReq() {
  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method = "GET";
  req.url = "/";
  req.headers = {};
  req.socket = { remoteAddress: "127.0.0.1" };
  return req;
}

function _cspRes(initialCsp) {
  var headers = {};
  if (initialCsp) headers["content-security-policy"] = initialCsp;
  return {
    setHeader:    function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:    function (k)    { return headers[k.toLowerCase()]; },
    removeHeader: function (k)    { delete headers[k.toLowerCase()]; },
    locals:       {},
    _headers:     headers,
  };
}

function testCspNonceSurface() {
  check("b.middleware.cspNonce is a function",      typeof b.middleware.cspNonce === "function");
  var raw = b.middleware._modules.cspNonce;
  check("CspNonceError is a class",                 typeof raw.CspNonceError === "function");
  check("DEFAULT_DIRECTIVES exposed",               Array.isArray(raw.DEFAULT_DIRECTIVES));
  check("_injectNonce exposed for tests",           typeof raw._injectNonce === "function");
}

function testCspNonceParseSerialize() {
  var raw = b.middleware._modules.cspNonce;
  var parts = raw._parseCsp("default-src 'self'; script-src 'self'; img-src 'self' data:");
  check("parse: 3 directives",                       parts.length === 3);
  check("parse: directive name lowercased",          parts[0].name === "default-src");
  check("parse: values captured",                    parts[2].values.length === 2);
  var serialized = raw._serializeCsp(parts);
  check("serialize: round-trips",
        serialized.indexOf("default-src 'self'") !== -1 &&
        serialized.indexOf("img-src 'self' data:") !== -1);
}

function testCspNonceInjectNonceIntoExisting() {
  var raw = b.middleware._modules.cspNonce;
  var before = "default-src 'self'; script-src 'self'; style-src 'self'";
  var after = raw._injectNonce(before, "ABC123==", ["script-src", "style-src"], false);
  check("inject: nonce on script-src",   after.indexOf("script-src 'self' 'nonce-ABC123=='") !== -1);
  check("inject: nonce on style-src",    after.indexOf("style-src 'self' 'nonce-ABC123=='") !== -1);
  check("inject: default-src untouched", after.indexOf("default-src 'self'") !== -1);
}

function testCspNonceInjectAddsMissingDirective() {
  var raw = b.middleware._modules.cspNonce;
  var before = "default-src 'self'";
  var after = raw._injectNonce(before, "XYZ", ["script-src", "style-src"], false);
  check("inject: missing script-src appended",  after.indexOf("script-src 'nonce-XYZ'") !== -1);
  check("inject: missing style-src appended",   after.indexOf("style-src 'nonce-XYZ'") !== -1);
}

function testCspNonceInjectStrictDynamic() {
  var raw = b.middleware._modules.cspNonce;
  var after = raw._injectNonce("script-src 'self'", "T", ["script-src"], true);
  check("inject: script-src gets strict-dynamic when opted in",
        after.indexOf("'strict-dynamic'") !== -1);
  var styleOnly = raw._injectNonce("style-src 'self'", "T", ["style-src"], true);
  check("inject: style-src does NOT get strict-dynamic",
        styleOnly.indexOf("'strict-dynamic'") === -1);
}

function testCspNonceInjectIdempotent() {
  var raw = b.middleware._modules.cspNonce;
  var once = raw._injectNonce("script-src 'self'", "N1", ["script-src"], false);
  var twice = raw._injectNonce(once, "N1", ["script-src"], false);
  var matches = twice.match(/'nonce-N1'/g) || [];
  check("inject: re-running with same nonce doesn't duplicate", matches.length === 1);
}

function testCspNonceInjectBuildsFromScratch() {
  var raw = b.middleware._modules.cspNonce;
  var fresh = raw._injectNonce(undefined, "FRESH", ["script-src"], false);
  check("inject: no existing CSP → built from scratch",
        fresh.indexOf("default-src 'self'") !== -1 &&
        fresh.indexOf("'nonce-FRESH'") !== -1);
}

async function testCspNonceMiddlewareSetsReqAndLocals() {
  var mw = b.middleware.cspNonce({ always: true });
  var req = _cspReq();
  var res = _cspRes("script-src 'self'");
  await new Promise(function (resolve) {
    mw(req, res, function () { resolve(); });
  });
  check("middleware: req.cspNonce set",         typeof req.cspNonce === "string" && req.cspNonce.length > 0);
  check("middleware: res.locals.cspNonce set",  res.locals.cspNonce === req.cspNonce);
  check("middleware: CSP header patched with nonce",
        res._headers["content-security-policy"].indexOf("'nonce-" + req.cspNonce + "'") !== -1);
}

async function testCspNonceMiddlewareCustomProperty() {
  var mw = b.middleware.cspNonce({ always: true, property: "myNonce" });
  var req = _cspReq();
  var res = _cspRes("script-src 'self'");
  await new Promise(function (resolve) { mw(req, res, function () { resolve(); }); });
  check("custom property: req.myNonce set",     typeof req.myNonce === "string");
  check("custom property: res.locals.myNonce set", res.locals.myNonce === req.myNonce);
  check("custom property: req.cspNonce NOT set", req.cspNonce === undefined);
}

async function testCspNonceMiddlewareSkipsWhenNoCspAndNotAlways() {
  var mw = b.middleware.cspNonce({});
  var req = _cspReq();
  var res = _cspRes(null);
  await new Promise(function (resolve) { mw(req, res, function () { resolve(); }); });
  check("no-CSP path: req.cspNonce still set",       typeof req.cspNonce === "string");
  check("no-CSP path: no CSP header created",        res._headers["content-security-policy"] === undefined);
}

async function testCspNonceMiddlewareAlwaysCreatesCsp() {
  var mw = b.middleware.cspNonce({ always: true });
  var req = _cspReq();
  var res = _cspRes(null);
  await new Promise(function (resolve) { mw(req, res, function () { resolve(); }); });
  check("always: CSP header created from scratch",
        typeof res._headers["content-security-policy"] === "string" &&
        res._headers["content-security-policy"].indexOf("'nonce-") !== -1);
}

async function testCspNonceMiddlewareNonceLengthDefault() {
  var mw = b.middleware.cspNonce({ always: true });
  var req = _cspReq();
  var res = _cspRes(null);
  await new Promise(function (resolve) { mw(req, res, function () { resolve(); }); });
  check("default nonce length: ~24 chars",     req.cspNonce.length === 24);
}

async function testCspNonceMiddlewareCustomNonceLength() {
  var mw = b.middleware.cspNonce({ always: true, nonceBytes: 32 });
  var req = _cspReq();
  var res = _cspRes(null);
  await new Promise(function (resolve) { mw(req, res, function () { resolve(); }); });
  check("custom nonce length: ~44 chars for 32 bytes",   req.cspNonce.length === 44);
}

async function testCspNonceUniquenessAcrossRequests() {
  var mw = b.middleware.cspNonce({ always: true });
  var seen = new Set();
  for (var i = 0; i < 50; i++) {
    var req = _cspReq();
    var res = _cspRes(null);
    await new Promise(function (resolve) { mw(req, res, function () { resolve(); }); });
    seen.add(req.cspNonce);
  }
  check("uniqueness: 50 requests → 50 distinct nonces", seen.size === 50);
}

function testCspNonceConfigValidation() {
  var threw;

  threw = null;
  try { b.middleware.cspNonce({ nonceBytes: 8 }); } catch (e) { threw = e; }
  check("config: nonceBytes < 16 rejected", threw && threw.code === "csp-nonce/bad-nonce-bytes");

  threw = null;
  try { b.middleware.cspNonce({ directives: [""] }); } catch (e) { threw = e; }
  check("config: empty directive rejected", threw && threw.code === "csp-nonce/bad-directive");

  threw = null;
  try { b.middleware.cspNonce({ directives: [123] }); } catch (e) { threw = e; }
  check("config: non-string directive rejected", threw && threw.code === "csp-nonce/bad-directive");
}

async function testCspNonceLayeredOnSecurityHeaders() {
  var sh = b.middleware.securityHeaders();
  var nonce = b.middleware.cspNonce({});
  var req = _cspReq();
  var res = _cspRes(null);
  await new Promise(function (resolve) {
    sh(req, res, function () {
      nonce(req, res, function () { resolve(); });
    });
  });
  var csp = res._headers["content-security-policy"];
  check("layered: security-headers default-src present",   csp.indexOf("default-src 'self'") !== -1);
  check("layered: nonce injected on script-src",            csp.indexOf("'nonce-" + req.cspNonce + "'") !== -1);
  check("layered: req.cspNonce available after both layers", typeof req.cspNonce === "string");
}

function testRenderHtmlAutoMergesResLocals() {
  var stubEngine = {
    render: function (viewName, data) {
      return JSON.stringify({ view: viewName, data: data });
    },
  };
  var r = b.render.create({ engine: stubEngine });
  var captured = null;
  var res = {
    writableEnded: false,
    locals: { cspNonce: "from-locals", requestId: "rid-1" },
    writeHead: function (status, headers) { captured = { status: status, headers: headers }; },
    end: function (body) { captured.body = body; },
  };
  r.html(res, "home", { user: "Alice" });
  var rendered = JSON.parse(captured.body);
  check("render.html: res.locals.cspNonce auto-merged into data",
        rendered.data.cspNonce === "from-locals");
  check("render.html: res.locals.requestId auto-merged",
        rendered.data.requestId === "rid-1");
  check("render.html: operator data preserved",
        rendered.data.user === "Alice");
}

function testRenderHtmlOperatorDataOverridesLocals() {
  var stubEngine = {
    render: function (_v, data) { return JSON.stringify(data); },
  };
  var r = b.render.create({ engine: stubEngine });
  var captured = null;
  var res = {
    writableEnded: false,
    locals: { cspNonce: "locals-value" },
    writeHead: function () {},
    end: function (body) { captured = body; },
  };
  r.html(res, "view", { cspNonce: "operator-override" });
  var rendered = JSON.parse(captured);
  check("render.html: operator data wins on collision",
        rendered.cspNonce === "operator-override");
}

// ---- Cacheable-render API: PLACEHOLDER + substitute() ----

function testCspNoncePlaceholderIsPerInstanceRandom() {
  var a = b.middleware.cspNonce();
  var b1 = b.middleware.cspNonce();
  check("placeholder is a non-empty string",   typeof a.PLACEHOLDER === "string" && a.PLACEHOLDER.length > 0);
  check("placeholder differs across instances", a.PLACEHOLDER !== b1.PLACEHOLDER);
  check("placeholder shape is recognizable",   /^__BLAMEJS_CSP_NONCE_[a-f0-9]+__$/.test(a.PLACEHOLDER));
}

function testCspNoncePlaceholderHonorsOperatorOverride() {
  var pinned = "__OPERATOR_PINNED_TOKEN__";
  var mw = b.middleware.cspNonce({ placeholder: pinned });
  check("operator-pinned placeholder is used as-is", mw.PLACEHOLDER === pinned);
}

function testCspNoncePlaceholderInvalidTypeThrows() {
  // Bad config → throw at create time so the operator's typo surfaces
  // at app boot, not as silently-broken cache substitution three days
  // later.
  var threwOnNumber = null;
  try { b.middleware.cspNonce({ placeholder: 42 }); }
  catch (e) { threwOnNumber = e; }
  check("placeholder: number throws CspNonceError",
        threwOnNumber && threwOnNumber.code === "csp-nonce/bad-placeholder");

  var threwOnEmpty = null;
  try { b.middleware.cspNonce({ placeholder: "" }); }
  catch (e) { threwOnEmpty = e; }
  check("placeholder: empty string throws CspNonceError",
        threwOnEmpty && threwOnEmpty.code === "csp-nonce/bad-placeholder");

  var threwOnNull = null;
  try { b.middleware.cspNonce({ placeholder: null }); }
  catch (e) { threwOnNull = e; }
  check("placeholder: null throws CspNonceError",
        threwOnNull && threwOnNull.code === "csp-nonce/bad-placeholder");

  // undefined / not-passed → silently use the default. NOT a throw.
  var ok = b.middleware.cspNonce({ /* no placeholder */ });
  check("placeholder: undefined uses the default (no throw)",
        typeof ok.PLACEHOLDER === "string" && ok.PLACEHOLDER.length > 0);
}

function testCspNonceSubstituteReplacesPlaceholderWithReqNonce() {
  var mw = b.middleware.cspNonce();
  var html = '<script nonce="' + mw.PLACEHOLDER + '">x</script>' +
             '<style nonce="' + mw.PLACEHOLDER + '">y</style>';
  var req = { cspNonce: "real-nonce-abc" };
  var out = mw.substitute(html, req);
  check("substitute replaces every placeholder occurrence",
        out === '<script nonce="real-nonce-abc">x</script><style nonce="real-nonce-abc">y</style>');
}

function testCspNonceSubstituteAcceptsRawNonceString() {
  var mw = b.middleware.cspNonce();
  var html = '<script nonce="' + mw.PLACEHOLDER + '">x</script>';
  var out = mw.substitute(html, "literal-nonce-xyz");
  check("substitute accepts a raw string nonce",
        out === '<script nonce="literal-nonce-xyz">x</script>');
}

function testCspNonceSubstituteHonorsCustomProperty() {
  var mw = b.middleware.cspNonce({ property: "myNonce" });
  var html = '<script nonce="' + mw.PLACEHOLDER + '">x</script>';
  var req = { myNonce: "custom-prop-nonce" };
  var out = mw.substitute(html, req);
  check("substitute reads from operator-supplied property",
        out === '<script nonce="custom-prop-nonce">x</script>');
}

function testCspNonceSubstituteHandlesEmptyAndMissing() {
  var mw = b.middleware.cspNonce();
  check("substitute on empty html returns empty",          mw.substitute("", { cspNonce: "x" }) === "");
  check("substitute on null html returns null",            mw.substitute(null, { cspNonce: "x" }) === null);
  check("substitute with no placeholder returns input as-is",
        mw.substitute("<p>no token</p>", { cspNonce: "x" }) === "<p>no token</p>");
  var html = '<script nonce="' + mw.PLACEHOLDER + '">x</script>';
  check("substitute with null req substitutes empty (so the placeholder doesn't leak)",
        mw.substitute(html, null) === '<script nonce="">x</script>');
}

// Drives the middleware twice on the same cached HTML to confirm
// each request gets its own nonce in BOTH the CSP header and the
// substituted script tags. This is the canonical regression for the
// cached-stale-nonce class of bug.
async function testCspNonceCacheableRoundTripIntegration() {
  var mw = b.middleware.cspNonce();
  var cachedHtml =
    '<head>' +
    '  <script src="/a.js" nonce="' + mw.PLACEHOLDER + '"></script>' +
    '  <script src="/b.js" nonce="' + mw.PLACEHOLDER + '"></script>' +
    '</head>';

  function _drive() {
    return new Promise(function (resolve) {
      var req = _cspReq();
      var res = _cspRes("default-src 'self'");
      mw(req, res, function () {
        var rendered = mw.substitute(cachedHtml, req);
        var headerCsp = res.getHeader("content-security-policy") || "";
        var headerNonce = (headerCsp.match(/'nonce-([A-Za-z0-9+/=]+)'/) || [])[1] || null;
        var nonceAttrs = rendered.match(/nonce="([^"]+)"/g) || [];
        var scriptNonces = nonceAttrs.map(function (s) { return s.slice(7, -1); });
        resolve({ headerNonce: headerNonce, scriptNonces: scriptNonces });
      });
    });
  }

  var r1 = await _drive();
  var r2 = await _drive();

  check("cache hit #1: header nonce present",            r1.headerNonce !== null);
  check("cache hit #1: every script nonce matches header",
        r1.scriptNonces.length === 2 &&
        r1.scriptNonces.every(function (n) { return n === r1.headerNonce; }));
  check("cache hit #2: header nonce rotated between requests",
        r1.headerNonce !== r2.headerNonce);
  check("cache hit #2: every script nonce matches the rotated header nonce",
        r2.scriptNonces.length === 2 &&
        r2.scriptNonces.every(function (n) { return n === r2.headerNonce; }));
}

async function run() {
  testCspNonceSurface();
  testCspNonceParseSerialize();
  testCspNonceInjectNonceIntoExisting();
  testCspNonceInjectAddsMissingDirective();
  testCspNonceInjectStrictDynamic();
  testCspNonceInjectIdempotent();
  testCspNonceInjectBuildsFromScratch();
  await testCspNonceMiddlewareSetsReqAndLocals();
  await testCspNonceMiddlewareCustomProperty();
  await testCspNonceMiddlewareSkipsWhenNoCspAndNotAlways();
  await testCspNonceMiddlewareAlwaysCreatesCsp();
  await testCspNonceMiddlewareNonceLengthDefault();
  await testCspNonceMiddlewareCustomNonceLength();
  await testCspNonceUniquenessAcrossRequests();
  testCspNonceConfigValidation();
  await testCspNonceLayeredOnSecurityHeaders();
  testRenderHtmlAutoMergesResLocals();
  testRenderHtmlOperatorDataOverridesLocals();
  testCspNoncePlaceholderIsPerInstanceRandom();
  testCspNoncePlaceholderHonorsOperatorOverride();
  testCspNoncePlaceholderInvalidTypeThrows();
  testCspNonceSubstituteReplacesPlaceholderWithReqNonce();
  testCspNonceSubstituteAcceptsRawNonceString();
  testCspNonceSubstituteHonorsCustomProperty();
  testCspNonceSubstituteHandlesEmptyAndMissing();
  await testCspNonceCacheableRoundTripIntegration();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); }
  );
}
