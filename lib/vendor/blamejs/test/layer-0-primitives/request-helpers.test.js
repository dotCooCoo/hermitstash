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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("request-helpers tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
