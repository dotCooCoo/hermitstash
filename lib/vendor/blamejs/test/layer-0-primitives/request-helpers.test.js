"use strict";
/**
 * request-helpers — resolveRoute + captureResponseStatus.
 *
 * Run standalone: `node test/layer-0-primitives/request-helpers.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _bodyRes  = helpers._bodyRes;

function testSurface() {
  check("b.requestHelpers exposed",                  typeof b.requestHelpers === "object");
  check("resolveRoute is a function",                typeof b.requestHelpers.resolveRoute === "function");
  check("captureResponseStatus is a function",       typeof b.requestHelpers.captureResponseStatus === "function");
}

function testResolveRoutePrefersRoutePattern() {
  var r = b.requestHelpers.resolveRoute({
    routePattern: "/users/:id",
    url:          "/users/42?q=x",
  });
  check("resolveRoute: prefers routePattern over URL", r === "/users/:id");
}

function testResolveRouteFallsBackToUrl() {
  var r = b.requestHelpers.resolveRoute({ url: "/raw-path?x=1" });
  check("resolveRoute: URL fallback strips query",   r === "/raw-path");
}

function testResolveRouteEmptyOrMissingUrl() {
  check("resolveRoute: missing url → /",   b.requestHelpers.resolveRoute({}) === "/");
  check("resolveRoute: empty url → /",     b.requestHelpers.resolveRoute({ url: "" }) === "/");
  check("resolveRoute: null req safe",     b.requestHelpers.resolveRoute(null) === "/");
}

function testResolveRouteIgnoresEmptyRoutePattern() {
  var r = b.requestHelpers.resolveRoute({
    routePattern: "",      // empty string = router didn't resolve
    url:          "/foo",
  });
  check("resolveRoute: empty routePattern falls through to URL", r === "/foo");
}

async function testCaptureStatusFromWriteHead() {
  var res = _bodyRes();
  var captured = null;
  b.requestHelpers.captureResponseStatus(res, function (status) { captured = status; });
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    res.writeHead(404);
    res.end();
  });
  check("captureResponseStatus: writeHead status captured", captured === 404);
}

async function testCaptureStatusFromStatusCode() {
  var res = _bodyRes();
  var captured = null;
  b.requestHelpers.captureResponseStatus(res, function (status) { captured = status; });
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    res.statusCode = 503;
    res.end();
  });
  check("captureResponseStatus: res.statusCode captured (no writeHead)",
        captured === 503);
}

async function testCaptureStatusDefaults200() {
  var res = _bodyRes();
  var captured = null;
  b.requestHelpers.captureResponseStatus(res, function (status) { captured = status; });
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    res.statusCode = undefined;
    res.end();
  });
  check("captureResponseStatus: default 200 when nothing set",
        captured === 200);
}

async function testCaptureStatusOnEndThrowDoesntBreakResponse() {
  var res = _bodyRes();
  b.requestHelpers.captureResponseStatus(res, function () {
    throw new Error("instrumentation bug");
  });
  var threw = null;
  try {
    await new Promise(function (resolve) {
      res.on("finish", resolve);
      res.statusCode = 200;
      res.end();
    });
  } catch (e) { threw = e; }
  check("captureResponseStatus: onEnd throw does not break response", threw === null);
}

function testCaptureStatusValidatesArgs() {
  var threwNoOnEnd = null;
  try { b.requestHelpers.captureResponseStatus(_bodyRes()); }
  catch (e) { threwNoOnEnd = e; }
  check("captureResponseStatus: rejects missing onEnd", threwNoOnEnd !== null);
}

function testParseListHeader() {
  var rh = b.requestHelpers;
  check("parseListHeader: basic",
        JSON.stringify(rh.parseListHeader("a,b,c")) === '["a","b","c"]');
  check("parseListHeader: trims whitespace",
        JSON.stringify(rh.parseListHeader("a, b , c")) === '["a","b","c"]');
  check("parseListHeader: filters empty",
        JSON.stringify(rh.parseListHeader("a,, ,b")) === '["a","b"]');
  check("parseListHeader: lowercase opt",
        JSON.stringify(rh.parseListHeader("Foo, BAR", { lowercase: true })) === '["foo","bar"]');
  check("parseListHeader: lowercase off (default)",
        JSON.stringify(rh.parseListHeader("Foo, BAR")) === '["Foo","BAR"]');
  check("parseListHeader: null input → []",
        rh.parseListHeader(null).length === 0);
  check("parseListHeader: undefined input → []",
        rh.parseListHeader(undefined).length === 0);
  check("parseListHeader: empty string → []",
        rh.parseListHeader("").length === 0);
  check("parseListHeader: number coerced",
        JSON.stringify(rh.parseListHeader(42)) === '["42"]');
  check("parseListHeader: only commas → []",
        rh.parseListHeader(",,,").length === 0);
  check("parseListHeader: trailing comma tolerated",
        JSON.stringify(rh.parseListHeader("a,b,")) === '["a","b"]');
  check("parseListHeader: tabs/spaces trimmed",
        JSON.stringify(rh.parseListHeader("\ta\t,\tb\n")) === '["a","b"]');
}

function testSafeHeadersDistinct() {
  check("safeHeadersDistinct is fn", typeof b.requestHelpers.safeHeadersDistinct === "function");

  var out = b.requestHelpers.safeHeadersDistinct({
    rawHeaders: ["Content-Type", "application/json", "X-Foo", "a", "X-Foo", "b"],
  });
  check("safeHeadersDistinct: lowercases names", !!out["content-type"] && !!out["x-foo"]);
  check("safeHeadersDistinct: collects multi values",
        Array.isArray(out["x-foo"]) && out["x-foo"].length === 2 &&
        out["x-foo"][0] === "a" && out["x-foo"][1] === "b");

  var hostile = b.requestHelpers.safeHeadersDistinct({
    rawHeaders: ["__proto__", "polluted", "constructor", "evil", "X-Real", "ok"],
  });
  check("safeHeadersDistinct: __proto__ refused",   hostile["__proto__"] === undefined);
  check("safeHeadersDistinct: constructor refused", hostile.constructor === undefined);
  check("safeHeadersDistinct: real header passes",  hostile["x-real"] && hostile["x-real"][0] === "ok");

  var np = b.requestHelpers.safeHeadersDistinct({ rawHeaders: ["X-A", "1"] });
  check("safeHeadersDistinct: null prototype", Object.getPrototypeOf(np) === null);

  var empty = b.requestHelpers.safeHeadersDistinct({});
  check("safeHeadersDistinct: missing rawHeaders", Object.keys(empty).length === 0);
}

function testExtractBearerSurface() {
  check("extractBearer is a function", typeof b.requestHelpers.extractBearer === "function");
}

function testExtractBearerHappyPath() {
  var token = b.requestHelpers.extractBearer({
    headers: { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" },
  });
  check("extractBearer: returns the token from Authorization: Bearer ...",
        token === "eyJhbGciOiJIUzI1NiJ9.payload.sig");
}

function testExtractBearerCaseInsensitiveScheme() {
  // RFC 6750 §2.1 — scheme is case-insensitive.
  var lower = b.requestHelpers.extractBearer({
    headers: { authorization: "bearer abc" },
  });
  var upper = b.requestHelpers.extractBearer({
    headers: { authorization: "BEARER abc" },
  });
  var mixed = b.requestHelpers.extractBearer({
    headers: { authorization: "BeArEr abc" },
  });
  check("extractBearer: lowercase scheme accepted", lower === "abc");
  check("extractBearer: uppercase scheme accepted", upper === "abc");
  check("extractBearer: mixed-case scheme accepted", mixed === "abc");
}

function testExtractBearerCapitalAuthorizationKey() {
  // Some shim layers populate `Authorization` with capital A; Node's
  // http parser lowercases by default but the helper tolerates the
  // capital form too.
  var token = b.requestHelpers.extractBearer({
    headers: { Authorization: "Bearer abc" },
  });
  check("extractBearer: tolerates capital Authorization key", token === "abc");
}

function testExtractBearerMissingHeader() {
  check("extractBearer: missing Authorization → null",
        b.requestHelpers.extractBearer({ headers: {} }) === null);
  check("extractBearer: empty Authorization → null",
        b.requestHelpers.extractBearer({ headers: { authorization: "" } }) === null);
  check("extractBearer: null req → null",
        b.requestHelpers.extractBearer(null) === null);
  check("extractBearer: missing headers → null",
        b.requestHelpers.extractBearer({}) === null);
}

function testExtractBearerNonBearerScheme() {
  check("extractBearer: Basic scheme → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Basic dXNlcjpwYXNz" },
        }) === null);
  check("extractBearer: Digest scheme → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Digest abc" },
        }) === null);
}

function testExtractBearerMalformed() {
  check("extractBearer: 'Bearer' (no token) → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer" },
        }) === null);
  check("extractBearer: 'Bearer ' (empty token) → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer " },
        }) === null);
  check("extractBearer: 'Bearer  abc' (double space surface) returns null when token is empty",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer       " },
        }) === null);
}

function testExtractBearerControlBytes() {
  // CRLF injection / response-splitting class.
  check("extractBearer: CR in header → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc\rinjected" },
        }) === null);
  check("extractBearer: LF in header → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc\ninjected" },
        }) === null);
  check("extractBearer: NUL in header → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc\x00trail" },
        }) === null);
  check("extractBearer: tab in header → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc\tdef" },
        }) === null);
}

function testExtractBearerEmbeddedSpace() {
  // Embedded space slips a second value past callers reading suffixes
  // as JWT / opaque-id.
  check("extractBearer: embedded space in token → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: "Bearer abc def" },
        }) === null);
}

function testExtractBearerMultipleAuthHeaders() {
  // CWE-345 trust mismatch — refuse multi-Authorization.
  var twoRaw = b.requestHelpers.extractBearer({
    rawHeaders: ["Authorization", "Bearer first", "Authorization", "Bearer second"],
    headers:    { authorization: "Bearer first" },
  });
  check("extractBearer: multiple Authorization rawHeaders → null", twoRaw === null);

  // Pre-folded duplicate (Node's default: Authorization values get
  // joined with ", "). Comma in value triggers the same refusal.
  var folded = b.requestHelpers.extractBearer({
    headers: { authorization: "Bearer first, Bearer second" },
  });
  check("extractBearer: comma-folded duplicate Authorization → null", folded === null);
}

function testExtractBearerNonString() {
  check("extractBearer: non-string Authorization → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: 42 },
        }) === null);
  check("extractBearer: array Authorization → null",
        b.requestHelpers.extractBearer({
          headers: { authorization: ["Bearer abc"] },
        }) === null);
}

function testExtractBearerLeadingTrailingSpaces() {
  // Tolerate leading/trailing whitespace in the token portion (RFC 7230
  // OWS) while still rejecting embedded spaces.
  var t = b.requestHelpers.extractBearer({
    headers: { authorization: "Bearer  abc  " },
  });
  check("extractBearer: trims leading + trailing whitespace from token", t === "abc");
}

async function run() {
  testSurface();
  testSafeHeadersDistinct();
  testResolveRoutePrefersRoutePattern();
  testResolveRouteFallsBackToUrl();
  testResolveRouteEmptyOrMissingUrl();
  testResolveRouteIgnoresEmptyRoutePattern();
  await testCaptureStatusFromWriteHead();
  await testCaptureStatusFromStatusCode();
  await testCaptureStatusDefaults200();
  await testCaptureStatusOnEndThrowDoesntBreakResponse();
  testCaptureStatusValidatesArgs();
  testParseListHeader();
  testExtractBearerSurface();
  testExtractBearerHappyPath();
  testExtractBearerCaseInsensitiveScheme();
  testExtractBearerCapitalAuthorizationKey();
  testExtractBearerMissingHeader();
  testExtractBearerNonBearerScheme();
  testExtractBearerMalformed();
  testExtractBearerControlBytes();
  testExtractBearerEmbeddedSpace();
  testExtractBearerMultipleAuthHeaders();
  testExtractBearerNonString();
  testExtractBearerLeadingTrailingSpaces();
  testMakeSkipMatcher();
  testMakeResourceAuditEmitter();
}

function testMakeResourceAuditEmitter() {
  var events = [];
  var sink = { safeEmit: function (e) { events.push(e); } };

  // idFor derives the resource id; no req → no actor.
  var emit = b.requestHelpers.makeResourceAuditEmitter(sink, "auth.lockout",
    function (key) { return "ns:" + key; });
  check("makeResourceAuditEmitter: returns an emitter", typeof emit === "function");
  emit("locked", "k1", "denied", { attempts: 3 }, null);
  check("makeResourceAuditEmitter: event action/outcome",
    events[0] && events[0].action === "locked" && events[0].outcome === "denied");
  check("makeResourceAuditEmitter: resource kind + idFor-derived id",
    events[0].resource && events[0].resource.kind === "auth.lockout" && events[0].resource.id === "ns:k1");
  check("makeResourceAuditEmitter: metadata passed through", events[0].metadata.attempts === 3);
  check("makeResourceAuditEmitter: no req → no actor", events[0].actor === undefined);

  // default idFor = key verbatim; req → actor stamped.
  var emit2 = b.requestHelpers.makeResourceAuditEmitter(sink, "session.device");
  emit2("rotated", "tok-hash", "success", {}, { socket: { remoteAddress: "1.2.3.4" }, headers: {} });
  check("makeResourceAuditEmitter: default idFor is the key verbatim", events[1].resource.id === "tok-hash");
  check("makeResourceAuditEmitter: req → actor stamped", events[1].actor !== undefined);

  // falsy sink → disabled (operator opted out).
  var n = events.length;
  b.requestHelpers.makeResourceAuditEmitter(null, "x")("a", "k", "o", {}, null);
  check("makeResourceAuditEmitter: falsy sink disables emit", events.length === n);

  // a throwing sink is swallowed (never breaks the request).
  var threw = false;
  try {
    b.requestHelpers.makeResourceAuditEmitter({ safeEmit: function () { throw new Error("boom"); } }, "x")
      ("a", "k", "o", {}, null);
  } catch (_e) { threw = true; }
  check("makeResourceAuditEmitter: throwing sink is drop-silent", threw === false);
}

function testMakeSkipMatcher() {
  var shouldSkip = b.requestHelpers.makeSkipMatcher(
    { skipPaths: ["/healthz", /^\/webhooks\//] }, "test.makeSkipMatcher");
  check("makeSkipMatcher: returns a predicate", typeof shouldSkip === "function");
  check("makeSkipMatcher: string-prefix match",     shouldSkip({ pathname: "/healthz" }) === true);
  check("makeSkipMatcher: regexp match",            shouldSkip({ pathname: "/webhooks/stripe" }) === true);
  check("makeSkipMatcher: non-matching path",       shouldSkip({ pathname: "/account" }) === false);
  check("makeSkipMatcher: falls back to req.url",   shouldSkip({ url: "/healthz" }) === true);
  check("makeSkipMatcher: falls back to req.originalUrl", shouldSkip({ originalUrl: "/healthz" }) === true);
  check("makeSkipMatcher: missing path → '/' (no skip)", shouldSkip({}) === false);

  // SEGMENT-BOUNDARY (not raw startsWith) — the guard-bypass fix. "/healthz"
  // must NOT skip the sibling "/healthzzz", but MUST skip the descendant.
  check("makeSkipMatcher: segment boundary — sibling NOT skipped", shouldSkip({ pathname: "/healthzzz" }) === false);
  check("makeSkipMatcher: segment boundary — descendant skipped",  shouldSkip({ pathname: "/healthz/ready" }) === true);
  // Query string is stripped before matching (match on path, never the query).
  check("makeSkipMatcher: query string stripped", shouldSkip({ url: "/healthz?ready=1" }) === true);
  check("makeSkipMatcher: query can't fake a match", shouldSkip({ url: "/account?x=/healthz" }) === false);

  // A string entry ending in "/" is itself a segment prefix.
  var slashEntry = b.requestHelpers.makeSkipMatcher({ skipPaths: ["/api/"] }, "test.slash");
  check("makeSkipMatcher: trailing-slash entry matches descendant", slashEntry({ pathname: "/api/v1" }) === true);
  check("makeSkipMatcher: trailing-slash entry rejects sibling",    slashEntry({ pathname: "/apixyz" }) === false);

  // exact:true — whole-path equality only, no descendant.
  var exactM = b.requestHelpers.makeSkipMatcher({ skipPaths: ["/foo"], exact: true }, "test.exact");
  check("makeSkipMatcher: exact matches whole path", exactM({ pathname: "/foo" }) === true);
  check("makeSkipMatcher: exact rejects descendant",  exactM({ pathname: "/foo/bar" }) === false);

  // skip(req) predicate composes; a throwing predicate fails CLOSED (keeps guard ON).
  var withFn = b.requestHelpers.makeSkipMatcher(
    { skip: function (req) { return req.method === "OPTIONS"; } }, "test.skipFn");
  check("makeSkipMatcher: skip predicate true",     withFn({ method: "OPTIONS" }) === true);
  check("makeSkipMatcher: skip predicate false",    withFn({ method: "POST" }) === false);
  var throwing = b.requestHelpers.makeSkipMatcher(
    { skip: function () { throw new Error("boom"); } }, "test.skipThrow");
  check("makeSkipMatcher: throwing predicate fails closed (no skip)", throwing({}) === false);

  // Build-time validation: a bad skipPaths entry dies at boot, not on first request.
  check("makeSkipMatcher: non-array skipPaths throws",
        (function () { try { b.requestHelpers.makeSkipMatcher({ skipPaths: "x" }); return false; }
                       catch (e) { return e instanceof TypeError; } })());
  check("makeSkipMatcher: bad skipPaths entry throws",
        (function () { try { b.requestHelpers.makeSkipMatcher({ skipPaths: [123] }); return false; }
                       catch (e) { return e instanceof TypeError; } })());
  check("makeSkipMatcher: non-function skip throws",
        (function () { try { b.requestHelpers.makeSkipMatcher({ skip: "x" }); return false; }
                       catch (e) { return e instanceof TypeError; } })());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("request-helpers tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
