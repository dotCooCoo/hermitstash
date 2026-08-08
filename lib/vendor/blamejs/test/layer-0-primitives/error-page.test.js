// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.errorPage — router error handler (rich dev page + safe prod page).
 *
 * Drives the real consumer path: `b.errorPage.create({...})` returns a
 * `handler(err, req, res)` fn that classifies, logs, audits, negotiates
 * JSON-vs-HTML, and writes the response. Every assertion reads back the
 * response the mock `res` captured (status / headers / body).
 */

var helpers  = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var _mockReq = helpers._mockReq;
var _mockRes = helpers._mockRes;

// Quiet operator logger so the non-logging tests don't spew 4xx/5xx
// chatter to the console. makeViaOrFallback routes through log[level]
// when present, so these no-ops suppress the fallback bootLog.
var quietLog = {
  debug: function () {}, info: function () {},
  warn:  function () {}, error: function () {}, fatal: function () {},
};

function cap(res)     { return res._captured(); }
function bodyOf(res)  { return res._captured().body; }
function jsonOf(res)  { return JSON.parse(res._captured().body); }
function ctOf(res)    { return res._captured().headers["content-type"]; }

// A JSON-forcing handler in each mode keeps the classification tests
// free of Accept-header juggling.
function prodJson(extra) {
  return b.errorPage.create(Object.assign({ mode: "prod", audit: false, log: quietLog, defaultFormat: "json" }, extra || {}));
}
function devJson(extra) {
  return b.errorPage.create(Object.assign({ mode: "dev", audit: false, log: quietLog, defaultFormat: "json" }, extra || {}));
}
function jsonReq() {
  return _mockReq({ method: "POST", url: "/api/x", headers: { accept: "application/json" } });
}

// ---------------------------------------------------------------------

function testSurface() {
  check("b.errorPage namespace present",       typeof b.errorPage === "object");
  check("b.errorPage.create is a function",    typeof b.errorPage.create === "function");
  check("STATUS_REASONS 404",                  b.errorPage.STATUS_REASONS[404] === "Not Found");
  check("STATUS_REASONS 500",                  b.errorPage.STATUS_REASONS[500] === "Internal Server Error");
  check("STATUS_REASONS 401",                  b.errorPage.STATUS_REASONS[401] === "Unauthorized");
  check("STATUS_REASONS 429",                  b.errorPage.STATUS_REASONS[429] === "Too Many Requests");
  // opts = opts || {} — undefined opts is tolerated (auto-detect mode).
  check("create() with no opts returns a handler", typeof b.errorPage.create() === "function");
  // handler.mode is exposed for operators.
  check("handler.mode reflects prod",          b.errorPage.create({ mode: "prod", audit: false }).mode === "prod");
  check("handler.mode reflects dev",           b.errorPage.create({ mode: "dev", audit: false }).mode === "dev");
}

function testClassifyViaJson() {
  var h = prodJson();

  // Plain Error → 500, unclassified, generic message (no leak).
  var r = _mockRes();
  h(new Error("DB pwd hunter2"), jsonReq(), r);
  var p = jsonOf(r);
  check("plain Error → 500 status",            cap(r).status === 500);
  check("plain Error → INTERNAL_ERROR code",   p.error.code === "INTERNAL_ERROR");
  check("plain Error → generic message",       p.error.message === "Internal Server Error");
  check("plain Error hides operator message",  bodyOf(r).indexOf("hunter2") === -1);

  // isAppError with statusCode + code + message → all preserved (4xx).
  var r2 = _mockRes();
  h(Object.assign(new Error("nope"), { isAppError: true, statusCode: 404, code: "NOT_FOUND" }), jsonReq(), r2);
  var p2 = jsonOf(r2);
  check("AppError 404 status",                 cap(r2).status === 404);
  check("AppError 404 code preserved",         p2.error.code === "NOT_FOUND");
  check("AppError 404 message preserved",      p2.error.message === "nope");

  // isAppError with statusCode but NO code/message → defaults kick in.
  var r3 = _mockRes();
  h({ isAppError: true, statusCode: 404 }, jsonReq(), r3);
  var p3 = jsonOf(r3);
  check("AppError no-code → APP_ERROR default", p3.error.code === "APP_ERROR");
  check("AppError no-message → reason phrase",  p3.error.message === "Not Found");

  // isAppError with NO statusCode → 500 but classified (message shown).
  var r4 = _mockRes();
  h({ isAppError: true }, jsonReq(), r4);
  var p4 = jsonOf(r4);
  check("AppError no-status → 500",             cap(r4).status === 500);
  check("AppError classified-500 shows reason", p4.error.message === "Internal Server Error");

  // isAuthError → 401 with defaults.
  var r5 = _mockRes();
  h({ isAuthError: true }, jsonReq(), r5);
  var p5 = jsonOf(r5);
  check("isAuthError → 401",                    cap(r5).status === 401);
  check("isAuthError default code AUTH_FAILED", p5.error.code === "AUTH_FAILED");
  check("isAuthError default message",          p5.error.message === "Unauthorized");

  // isAuthError with explicit code + message.
  var r5b = _mockRes();
  h({ isAuthError: true, code: "BAD_TOKEN", message: "token expired" }, jsonReq(), r5b);
  var p5b = jsonOf(r5b);
  check("isAuthError explicit code preserved",  p5b.error.code === "BAD_TOKEN");
  check("isAuthError explicit message preserved", p5b.error.message === "token expired");

  // code === "VALIDATION_ERROR" → 400.
  var r6 = _mockRes();
  h({ code: "VALIDATION_ERROR", message: "bad field" }, jsonReq(), r6);
  var p6 = jsonOf(r6);
  check("VALIDATION_ERROR code → 400",          cap(r6).status === 400);
  check("VALIDATION_ERROR message preserved",   p6.error.message === "bad field");

  // name === "ValidationError" (no code) → 400 with default code.
  var r7 = _mockRes();
  h({ name: "ValidationError", message: "shape" }, jsonReq(), r7);
  var p7 = jsonOf(r7);
  check("ValidationError name → 400",           cap(r7).status === 400);
  check("ValidationError name → default code",  p7.error.code === "VALIDATION_ERROR");

  // isSafeJsonError → 400, path surfaced into the envelope.
  var r8 = _mockRes();
  h({ isSafeJsonError: true, message: "bad json", path: "a.b.c" }, jsonReq(), r8);
  var p8 = jsonOf(r8);
  check("isSafeJsonError → 400",                cap(r8).status === 400);
  check("isSafeJsonError default code",         p8.error.code === "json/invalid");
  check("isSafeJsonError path surfaced",        p8.error.path === "a.b.c");

  // Permanent framework errors → 400. Cover all three flag families.
  ["isStorageError", "isQueueError", "isExternalDbError"].forEach(function (flag) {
    var e = { permanent: true, message: "perm-" + flag };
    e[flag] = true;
    var rr = _mockRes();
    h(e, jsonReq(), rr);
    check("permanent " + flag + " → 400",       cap(rr).status === 400);
    check("permanent " + flag + " message",     jsonOf(rr).error.message === "perm-" + flag);
  });

  // Storage error WITHOUT permanent + no statusCode → falls through to
  // the unclassified 500 (the `&& err.permanent` false side).
  var r9 = _mockRes();
  h({ isStorageError: true, message: "transient" }, jsonReq(), r9);
  var p9 = jsonOf(r9);
  check("non-permanent storage → 500",          cap(r9).status === 500);
  check("non-permanent storage hides message",  p9.error.message === "Internal Server Error");

  // Bare statusCode number (no isAppError) → that status, classified.
  var r10 = _mockRes();
  h({ statusCode: 403, message: "denied" }, jsonReq(), r10);
  var p10 = jsonOf(r10);
  check("bare statusCode 403 classified",       cap(r10).status === 403);
  check("bare statusCode default code ERROR",   p10.error.code === "ERROR");
  check("bare statusCode message preserved",    p10.error.message === "denied");

  // Unknown status (no reason-phrase, no message) → "Error" fallback.
  var r11 = _mockRes();
  h({ statusCode: 418 }, jsonReq(), r11);
  var p11 = jsonOf(r11);
  check("unknown status 418 passthrough",       cap(r11).status === 418);
  check("unknown status message → 'Error'",     p11.error.message === "Error");
}

function testClassifyDefaultMessages() {
  // Each error below omits its message (and sometimes code) so the
  // `err.X || "<default>"` right-hand fallbacks in _classify execute.
  var h = prodJson();

  // isAppError, unknown status, no message → message falls to "Error".
  var r1 = _mockRes();
  h({ isAppError: true, statusCode: 418 }, jsonReq(), r1);
  check("AppError unknown-status no-message → 'Error'", jsonOf(r1).error.message === "Error");

  // VALIDATION_ERROR code, no message → "Bad Request".
  var r2 = _mockRes();
  h({ code: "VALIDATION_ERROR" }, jsonReq(), r2);
  check("VALIDATION_ERROR no-message → 'Bad Request'", jsonOf(r2).error.message === "Bad Request");

  // isSafeJsonError bare (no code / message / path) → all defaults.
  var r3 = _mockRes();
  h({ isSafeJsonError: true }, jsonReq(), r3);
  var p3 = jsonOf(r3);
  check("safeJson bare → default code",        p3.error.code === "json/invalid");
  check("safeJson bare → default message",     p3.error.message === "Bad Request");
  check("safeJson bare → no path member",      p3.error.path === undefined);

  // Permanent framework error, no message → "Bad Request".
  var r4 = _mockRes();
  h({ isQueueError: true, permanent: true }, jsonReq(), r4);
  check("permanent no-message → 'Bad Request'", jsonOf(r4).error.message === "Bad Request");

  // Unrecognized object with no code/message → the 500 defaults.
  var r5 = _mockRes();
  h({ foo: 1 }, jsonReq(), r5);
  var p5 = jsonOf(r5);
  check("unrecognized object → INTERNAL_ERROR", p5.error.code === "INTERNAL_ERROR");
  check("unrecognized object → generic message", p5.error.message === "Internal Server Error");
}

function testDevHtmlEdgeReq() {
  // Bare request (no method / url / headers) driven down the dev HTML
  // render exercises the `req.method || ""` / `req.url || ""` fallbacks
  // and the empty-headers branch (no Headers sub-table).
  var h = b.errorPage.create({ mode: "dev", audit: false, log: quietLog, defaultFormat: "html" });
  var rBare = _mockRes();
  h(new Error("bare"), {}, rBare);
  var body = bodyOf(rBare);
  check("dev bare-req renders without throwing", body.indexOf("<!doctype html>") !== -1);
  check("dev bare-req shows Request section",     body.indexOf("<h2>Request</h2>") !== -1);
  check("dev bare-req omits Headers sub-table",   body.indexOf("<h3>Headers</h3>") === -1);

  // Unknown status in dev → title + header reason fall back to "Error".
  var rUnknown = _mockRes();
  h({ statusCode: 418, message: "teapot" }, {}, rUnknown);
  var body2 = bodyOf(rUnknown);
  check("dev unknown-status status shown",        body2.indexOf("418") !== -1);
  check("dev unknown-status reason → 'Error'",    body2.indexOf("Error") !== -1);
  check("dev unknown-status message shown",       body2.indexOf("teapot") !== -1);
}

function testNonObjectErrors() {
  var h = prodJson();

  var rNull = _mockRes();
  h(null, jsonReq(), rNull);
  check("null err → 500",                       cap(rNull).status === 500);
  check("null err → INTERNAL_ERROR",            jsonOf(rNull).error.code === "INTERNAL_ERROR");

  var rStr = _mockRes();
  h("boom-string", jsonReq(), rStr);
  check("string err → 500",                     cap(rStr).status === 500);
  check("string err → generic message",         jsonOf(rStr).error.message === "Internal Server Error");
}

function testContentNegotiation() {
  // defaultFormat: "json" always JSON even when Accept says html.
  var hJson = b.errorPage.create({ mode: "prod", audit: false, log: quietLog, defaultFormat: "json" });
  var rJ = _mockRes();
  hJson(new Error("x"), _mockReq({ method: "GET", headers: { accept: "text/html" } }), rJ);
  check("defaultFormat json → JSON despite Accept html", /application\/json/.test(ctOf(rJ)));

  // defaultFormat: "html" always HTML even when Accept says json.
  var hHtml = b.errorPage.create({ mode: "prod", audit: false, log: quietLog, defaultFormat: "html" });
  var rH = _mockRes();
  hHtml(new Error("x"), _mockReq({ method: "POST", headers: { accept: "application/json" } }), rH);
  check("defaultFormat html → HTML despite Accept json", /text\/html/.test(ctOf(rH)));

  // defaultFormat "auto" (explicit) negotiates via Accept.
  var hAuto = b.errorPage.create({ mode: "prod", audit: false, log: quietLog, defaultFormat: "auto" });
  var rA1 = _mockRes();
  hAuto(new Error("x"), _mockReq({ headers: { accept: "application/json" } }), rA1);
  check("auto + Accept json → JSON",            /application\/json/.test(ctOf(rA1)));
  var rA2 = _mockRes();
  hAuto(new Error("x"), _mockReq({ headers: { accept: "text/html" } }), rA2);
  check("auto + Accept html → HTML",            /text\/html/.test(ctOf(rA2)));

  // Empty Accept heuristic: non-GET → JSON, GET → HTML.
  var rPost = _mockRes();
  hAuto(new Error("x"), _mockReq({ method: "POST", headers: {} }), rPost);
  check("empty Accept + POST → JSON",           /application\/json/.test(ctOf(rPost)));
  var rGet = _mockRes();
  hAuto(new Error("x"), _mockReq({ method: "GET", headers: {} }), rGet);
  check("empty Accept + GET → HTML",            /text\/html/.test(ctOf(rGet)));
}

function testProdHtml() {
  var h = b.errorPage.create({ mode: "prod", audit: false, log: quietLog, brand: "acme", contact: "ops@acme.test" });
  var req = _mockReq({ method: "GET", url: "/x", headers: { accept: "text/html" } });

  var r = _mockRes();
  h(new Error("secret-detail hunter2"), req, r);
  var body = bodyOf(r);
  check("prod 500 → 500 status",               cap(r).status === 500);
  check("prod 500 → text/html",                /text\/html/.test(ctOf(r)));
  check("prod hides operator message",         body.indexOf("hunter2") === -1);
  check("prod shows generic reason",           body.indexOf("Internal Server Error") !== -1);
  check("prod page carries no stack",          body.indexOf(".js:") === -1 && body.indexOf("\n    at ") === -1);
  check("prod brand reflected",                body.indexOf("acme") !== -1);
  check("prod contact block rendered",         body.indexOf("ops@acme.test") !== -1 && body.indexOf("mailto:") !== -1);

  // Default brand ("blamejs") when brand omitted; no contact block when omitted.
  var hBare = b.errorPage.create({ mode: "prod", audit: false, log: quietLog });
  var rB = _mockRes();
  hBare(new Error("x"), req, rB);
  check("prod default brand blamejs",          bodyOf(rB).indexOf("blamejs") !== -1);
  check("prod without contact omits contact",  bodyOf(rB).indexOf("mailto:") === -1);

  // Unknown status → title/reason falls back to "Error".
  var rU = _mockRes();
  hBare({ statusCode: 599 }, req, rU);
  check("prod unknown status shown verbatim",  bodyOf(rU).indexOf("599") !== -1);
  check("prod unknown status reason → Error",  bodyOf(rU).indexOf("Error") !== -1);
}

function testDevHtml() {
  var h = b.errorPage.create({ mode: "dev", audit: false, log: quietLog, brand: "dev-brand" });
  var req = _mockReq({
    method: "POST", url: "/api/widget?id=42",
    headers: { accept: "text/html", "user-agent": "ua/1" },
  });
  req.id = "req-777";

  var r = _mockRes();
  h(new Error("widget exploded"), req, r);
  var body = bodyOf(r);
  check("dev 500 → 500 status",                cap(r).status === 500);
  check("dev shows operator message",          body.indexOf("widget exploded") !== -1);
  check("dev shows request method + url",      body.indexOf("POST") !== -1 && body.indexOf("/api/widget") !== -1);
  check("dev shows requestId row",             body.indexOf("req-777") !== -1);
  check("dev includes Stack section",          body.indexOf("Stack") !== -1);
  check("dev brand reflected",                 body.indexOf("dev-brand") !== -1);

  // Classified error → err-code div rendered in the dev header.
  var rC = _mockRes();
  h(Object.assign(new Error("m"), { isAppError: true, statusCode: 400, code: "MY_CODE" }), req, rC);
  check("dev renders error code div",          bodyOf(rC).indexOf("MY_CODE") !== -1);

  // showStack:false suppresses the Stack section.
  var hNoStack = b.errorPage.create({ mode: "dev", audit: false, log: quietLog, showStack: false });
  var rNS = _mockRes();
  hNoStack(new Error("boom"), req, rNS);
  check("dev showStack:false omits Stack section", bodyOf(rNS).indexOf("Stack") === -1);

  // showRequestInfo:false suppresses the Request section.
  var hNoReq = b.errorPage.create({ mode: "dev", audit: false, log: quietLog, showRequestInfo: false });
  var rNR = _mockRes();
  hNoReq(new Error("boom"), req, rNR);
  check("dev showRequestInfo:false omits Request section", bodyOf(rNR).indexOf("<h2>Request</h2>") === -1);

  // Default dev brand when omitted.
  var hDef = b.errorPage.create({ mode: "dev", audit: false, log: quietLog });
  var rD = _mockRes();
  hDef(new Error("x"), req, rD);
  check("dev default brand blamejs",           bodyOf(rD).indexOf("blamejs") !== -1);
}

function testHeaderRedaction() {
  var h = b.errorPage.create({ mode: "dev", audit: false, log: quietLog });
  var req = _mockReq({
    method: "GET", url: "/x",
    headers: {
      accept:          "text/html",
      "user-agent":    "keep-me-ua",
      cookie:          "session=SECRETCOOKIE",
      authorization:   "Bearer SECRETBEARER",
      "x-api-key":     "SECRETAPIKEY",
      "x-csrf-token":  "SECRETCSRF",
      "x-refresh-token": "SECRETREFRESH",
      "x-tenant":      "acme-tenant",
    },
  });
  var r = _mockRes();
  h(new Error("boom"), req, r);
  var body = bodyOf(r);

  // Sensitive header VALUES must not appear.
  check("cookie value redacted",               body.indexOf("SECRETCOOKIE") === -1);
  check("authorization value redacted",        body.indexOf("SECRETBEARER") === -1);
  check("x-api-key value redacted",            body.indexOf("SECRETAPIKEY") === -1);
  check("x-csrf-token value redacted",         body.indexOf("SECRETCSRF") === -1);
  check("token-substring header redacted",     body.indexOf("SECRETREFRESH") === -1);
  check("redaction marker present",            body.indexOf("[REDACTED]") !== -1);
  // CRITICAL: non-sensitive headers SURVIVE — redaction must not scrub
  // everything.
  check("user-agent value preserved",          body.indexOf("keep-me-ua") !== -1);
  check("non-sensitive header preserved",      body.indexOf("acme-tenant") !== -1);
}

function testEnvVars() {
  var req = _mockReq({ method: "GET", url: "/x", headers: { accept: "text/html" } });

  // Default: no Environment section even in dev.
  var hOff = b.errorPage.create({ mode: "dev", audit: false, log: quietLog });
  var rOff = _mockRes();
  hOff(new Error("e"), req, rOff);
  check("dev omits Environment section by default", bodyOf(rOff).indexOf("Environment") === -1);

  var prevH = process.env.BLAMEJS_COV_HARMLESS;
  var prevS = process.env.BLAMEJS_COV_SECRET;
  process.env.BLAMEJS_COV_HARMLESS = "publicvalue";
  process.env.BLAMEJS_COV_SECRET   = "leakme";
  try {
    var hOn = b.errorPage.create({ mode: "dev", audit: false, log: quietLog, showEnvVars: true });
    var rOn = _mockRes();
    hOn(new Error("e"), req, rOn);
    var body = bodyOf(rOn);
    check("showEnvVars renders Environment section", body.indexOf("Environment") !== -1);
    check("showEnvVars shows non-secret key",    body.indexOf("BLAMEJS_COV_HARMLESS") !== -1);
    // CRITICAL: the harmless VALUE survives (not just the key name).
    check("showEnvVars preserves non-secret value", body.indexOf("publicvalue") !== -1);
    check("showEnvVars redacts SECRET-shaped key", body.indexOf("BLAMEJS_COV_SECRET") === -1);
    check("showEnvVars never leaks secret value",  body.indexOf("leakme") === -1);
  } finally {
    if (prevH === undefined) delete process.env.BLAMEJS_COV_HARMLESS; else process.env.BLAMEJS_COV_HARMLESS = prevH;
    if (prevS === undefined) delete process.env.BLAMEJS_COV_SECRET;   else process.env.BLAMEJS_COV_SECRET = prevS;
  }
}

function testJsonEnvelope() {
  // prod 4xx: classified → message + code preserved, no stack.
  var rp = _mockRes();
  prodJson()(Object.assign(new Error("bad input"), { isAppError: true, statusCode: 400, code: "VALIDATION_ERROR" }), jsonReq(), rp);
  var pp = jsonOf(rp);
  check("prod json 4xx status",                cap(rp).status === 400);
  check("prod json 4xx message preserved",     pp.error.message === "bad input");
  check("prod json 4xx code preserved",        pp.error.code === "VALIDATION_ERROR");
  check("prod json 4xx has no stack",          pp.error.stack === undefined);

  // prod 500: hidden message, no stack.
  var rp5 = _mockRes();
  prodJson()(new Error("DB pwd hunter2"), jsonReq(), rp5);
  var pp5 = jsonOf(rp5);
  check("prod json 500 hides message",         pp5.error.message === "Internal Server Error");
  check("prod json 500 has no stack",          pp5.error.stack === undefined);

  // dev 500: stack included (default showStack true).
  var rd = _mockRes();
  devJson()(new Error("kaboom"), jsonReq(), rd);
  var pd = jsonOf(rd);
  check("dev json 500 includes stack",         typeof pd.error.stack === "string" && /kaboom/.test(pd.error.stack));

  // dev 500 with showStack:false → no stack in JSON.
  var rd2 = _mockRes();
  devJson({ showStack: false })(new Error("kaboom2"), jsonReq(), rd2);
  check("dev json 500 showStack:false omits stack", jsonOf(rd2).error.stack === undefined);

  // dev 4xx: even with showStack, stack only added for >=500.
  var rd3 = _mockRes();
  devJson()({ statusCode: 400, message: "nope" }, jsonReq(), rd3);
  check("dev json 4xx omits stack (status<500)", jsonOf(rd3).error.stack === undefined);
}

function testApiEncryptEncode() {
  var h = prodJson();

  // Present + successful → body is the encoded envelope; the original
  // error info survives inside it (preserved value).
  var reqEnc = jsonReq();
  reqEnc.apiEncryptEncode = function (obj) { return { enc: true, inner: obj }; };
  var r = _mockRes();
  h(Object.assign(new Error("m"), { isAppError: true, statusCode: 400, code: "C" }), reqEnc, r);
  var p = jsonOf(r);
  check("apiEncryptEncode wraps the body",     p.enc === true);
  check("apiEncryptEncode preserves inner error", p.inner && p.inner.error && p.inner.error.code === "C");
  check("apiEncryptEncode preserves status",   cap(r).status === 400);

  // Throwing encoder → falls back to the plain envelope (error survives,
  // no enc wrapper, message intact).
  var reqBad = jsonReq();
  reqBad.apiEncryptEncode = function () { throw new Error("seal failed"); };
  var r2 = _mockRes();
  h(Object.assign(new Error("m2"), { isAppError: true, statusCode: 422, code: "C2" }), reqBad, r2);
  var p2 = jsonOf(r2);
  check("throwing encoder → plain envelope",   p2.enc === undefined && p2.error && p2.error.code === "C2");
  check("throwing encoder preserves status",   cap(r2).status === 422);
}

function testJsonFormatterHook() {
  var seen = [];
  var h = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "json",
    jsonFormatter: function (info, req) {
      seen.push({ status: info.status, code: info.code, url: req && req.url });
      return { contentType: "application/vnd.api+json", body: JSON.stringify({ ok: String(info.status) }) };
    },
  });
  var r = _mockRes();
  h(Object.assign(new Error("nope"), { isAppError: true, statusCode: 422, code: "X" }), jsonReq(), r);
  check("jsonFormatter ran with classified info", seen.length === 1 && seen[0].status === 422 && seen[0].url === "/api/x");
  check("jsonFormatter status preserved",      cap(r).status === 422);
  check("jsonFormatter custom content type",   ctOf(r) === "application/vnd.api+json");
  check("jsonFormatter body verbatim",         bodyOf(r) === '{"ok":"422"}');

  // Empty contentType → default application/json content type.
  var hEmptyCt = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "json",
    jsonFormatter: function () { return { contentType: "", body: "x" }; },
  });
  var rEmpty = _mockRes();
  hEmptyCt(new Error("x"), jsonReq(), rEmpty);
  check("jsonFormatter empty ct → default json ct", /application\/json/.test(ctOf(rEmpty)));

  // Object body (not string/buffer) → JSON.stringify'd.
  var hObj = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "json",
    jsonFormatter: function () { return { body: { a: 1 } }; },
  });
  var rObj = _mockRes();
  hObj(new Error("x"), jsonReq(), rObj);
  check("jsonFormatter object body stringified", bodyOf(rObj) === '{"a":1}');

  // Buffer body → written as-is.
  var hBuf = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "json",
    jsonFormatter: function () { return { body: Buffer.from('{"buf":1}') }; },
  });
  var rBuf = _mockRes();
  hBuf(new Error("x"), jsonReq(), rBuf);
  check("jsonFormatter buffer body written",   bodyOf(rBuf) === '{"buf":1}');

  // Throwing formatter → falls through to the default framework envelope.
  var hThrow = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "json",
    jsonFormatter: function () { throw new Error("fmt boom"); },
  });
  var rThrow = _mockRes();
  hThrow(Object.assign(new Error("m"), { isAppError: true, statusCode: 400, code: "FALLBACK" }), jsonReq(), rThrow);
  var pThrow = jsonOf(rThrow);
  check("throwing formatter → default envelope", pThrow.error && pThrow.error.code === "FALLBACK");
  check("throwing formatter preserves status", cap(rThrow).status === 400);

  // Formatter returning null / no-body → falls through to default.
  var hNull = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "json",
    jsonFormatter: function () { return null; },
  });
  var rNull = _mockRes();
  hNull(Object.assign(new Error("m"), { isAppError: true, statusCode: 409, code: "N" }), jsonReq(), rNull);
  check("null formatter → default envelope",   jsonOf(rNull).error.code === "N" && cap(rNull).status === 409);

  // Config-time validation: non-function jsonFormatter throws a TypeError.
  var threw = null;
  try { b.errorPage.create({ jsonFormatter: 123 }); } catch (e) { threw = e; }
  check("non-function jsonFormatter → TypeError", threw instanceof TypeError);
}

function testRenderHtmlHook() {
  // Hook returns a string → used verbatim as the HTML body.
  var h = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "html",
    renderHtml: function (info) { return "<custom>" + info.status + "</custom>"; },
  });
  var r = _mockRes();
  h(Object.assign(new Error("m"), { isAppError: true, statusCode: 404, code: "C" }), _mockReq({ headers: { accept: "text/html" } }), r);
  check("renderHtml string used verbatim",     bodyOf(r) === "<custom>404</custom>");
  check("renderHtml keeps text/html ct",       /text\/html/.test(ctOf(r)));
  check("renderHtml keeps classified status",  cap(r).status === 404);

  // Throwing hook → falls back to the built-in page.
  var hThrow = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "html",
    renderHtml: function () { throw new Error("render boom"); },
  });
  var rThrow = _mockRes();
  hThrow(new Error("x"), _mockReq({ headers: { accept: "text/html" } }), rThrow);
  check("throwing renderHtml → built-in fallback", bodyOf(rThrow).indexOf("<!doctype html>") !== -1);

  // Non-string return → also falls back to built-in page.
  var hNonStr = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "html",
    renderHtml: function () { return 42; },
  });
  var rNonStr = _mockRes();
  hNonStr(new Error("x"), _mockReq({ headers: { accept: "text/html" } }), rNonStr);
  check("non-string renderHtml → built-in fallback", bodyOf(rNonStr).indexOf("<!doctype html>") !== -1);

  // Config-time validation: non-function renderHtml throws a TypeError.
  var threw = null;
  try { b.errorPage.create({ renderHtml: "nope" }); } catch (e) { threw = e; }
  check("non-function renderHtml → TypeError",  threw instanceof TypeError);
}

function testProblemDetails() {
  var h = b.errorPage.create({ mode: "prod", audit: false, log: quietLog, defaultFormat: "json", problemDetails: true });

  var r = _mockRes();
  h(Object.assign(new Error("bad input"), { isAppError: true, statusCode: 400, code: "VALIDATION_ERROR" }), jsonReq(), r);
  // problemDetails.respond writes status via res.statusCode (not
  // writeHead), so read the public property here.
  check("problemDetails 400 status",           r.statusCode === 400);
  check("problemDetails problem+json ct",      /application\/problem\+json/.test(ctOf(r)));
  var doc = jsonOf(r);
  check("problemDetails status field",         doc.status === 400);
  check("problemDetails title from reason",    doc.title === "Bad Request");
  check("problemDetails detail carries message", doc.detail === "bad input");
  check("problemDetails code extension",        doc.code === "VALIDATION_ERROR");

  // 500 still hides the operator-private message under problem+json.
  var r2 = _mockRes();
  h(new Error("DB pwd hunter2"), jsonReq(), r2);
  var doc2 = jsonOf(r2);
  check("problemDetails 500 hides message",    doc2.status === 500 && doc2.detail === "Internal Server Error" && doc2.detail.indexOf("hunter2") === -1);

  // Unknown status → title falls back to "Error" (no reason phrase).
  var r3 = _mockRes();
  h({ statusCode: 418, message: "teapot" }, jsonReq(), r3);
  var doc3 = jsonOf(r3);
  check("problemDetails unknown-status title → Error", doc3.title === "Error" && doc3.status === 418);

  // respond() throwing (res tears down mid-write) is swallowed — the
  // original error must never be masked by a response-teardown error.
  var rBoom = _mockRes();
  rBoom.setHeader = function () { throw new Error("setHeader boom"); };
  var threw = null;
  try { h(new Error("x"), jsonReq(), rBoom); } catch (e) { threw = e; }
  check("problemDetails respond throw swallowed", threw === null);
}

function testOnErrorHook() {
  // Hook returns true → takes over the response entirely.
  var seen = [];
  var hTakeover = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog,
    onError: function (err, req, res, info) {
      seen.push({ status: info.status, code: info.code });
      res.writeHead(418, { "Content-Type": "text/plain" });
      res.end("teapot");
      return true;
    },
  });
  var r = _mockRes();
  hTakeover(Object.assign(new Error("bad"), { isAppError: true, statusCode: 400, code: "X" }), jsonReq(), r);
  check("onError hook received classified info", seen.length === 1 && seen[0].status === 400);
  check("onError takeover status honored",      cap(r).status === 418);
  check("onError takeover body honored",        bodyOf(r) === "teapot");

  // Hook ends the response but returns falsy → still stops (writableEnded).
  var hEnds = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog,
    onError: function (err, req, res) { res.end("ended-by-hook"); /* returns undefined */ },
  });
  var rEnds = _mockRes();
  hEnds(new Error("x"), _mockReq({ headers: { accept: "text/html" } }), rEnds);
  check("onError ends res → framework does not overwrite", bodyOf(rEnds) === "ended-by-hook");

  // Throwing hook → logged, then flow continues to the default page.
  var logged = [];
  var hThrow = b.errorPage.create({
    mode: "prod", audit: false,
    log: { warn: function () {}, error: function (m) { logged.push(m); }, info: function () {} },
    onError: function () { throw new Error("hook boom"); },
  });
  var rThrow = _mockRes();
  hThrow(new Error("x"), _mockReq({ headers: { accept: "text/html" } }), rThrow);
  // The hook error is logged first (before flow continues and the 500 logs
  // its own "unhandled error"), so pin the message and its position.
  check("throwing hook logged the onError-hook error", logged[0] === "errors-page onError hook threw");
  check("throwing hook → default page still written", bodyOf(rThrow).indexOf("<!doctype html>") !== -1);
  check("throwing hook → status still written",  cap(rThrow).status === 500);

  // Hook returns false and does not end → normal flow proceeds.
  var hFalse = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog,
    onError: function () { return false; },
  });
  var rFalse = _mockRes();
  hFalse(Object.assign(new Error("m"), { isAppError: true, statusCode: 404, code: "C" }), _mockReq({ headers: { accept: "text/html" } }), rFalse);
  check("hook returns false → framework writes response", cap(rFalse).status === 404 && bodyOf(rFalse).indexOf("<!doctype html>") !== -1);
}

function testWriteResponseFallbacks() {
  var h = b.errorPage.create({ mode: "prod", audit: false, log: quietLog });
  var req = _mockReq({ headers: { accept: "text/html" } });

  // Shim exposing only setHeader (no writeHead) → the setHeader fallback
  // path in _writeResponse sets res.statusCode + Content-Type directly.
  var rShim = _mockRes();
  delete rShim.writeHead;
  h(new Error("x"), req, rShim);
  check("no-writeHead shim → statusCode set",   rShim.statusCode === 500);
  check("no-writeHead shim → content-type set", cap(rShim).headers["content-type"] === "text/html; charset=utf-8");
  check("no-writeHead shim → cache-control set", cap(rShim).headers["cache-control"] === "no-store");
  check("no-writeHead shim → body written",     bodyOf(rShim).indexOf("<!doctype html>") !== -1);

  // writeHead throwing → last-resort plain-text end("Internal Server Error").
  var rBoom = _mockRes();
  rBoom.writeHead = function () { throw new Error("head boom"); };
  h(new Error("x"), req, rBoom);
  check("writeHead throw → plain-text fallback body", bodyOf(rBoom) === "Internal Server Error");
  check("writeHead throw → response still ended",     cap(rBoom).ended === true);

  // writeHead AND end both throwing → the last-resort inner catch
  // swallows the socket-gone error rather than letting it escape.
  var rDouble = _mockRes();
  rDouble.writeHead = function () { throw new Error("head boom"); };
  rDouble.end       = function () { throw new Error("end boom"); };
  var threwDouble = null;
  try { h(new Error("x"), req, rDouble); } catch (e) { threwDouble = e; }
  check("double-throw response fully swallowed", threwDouble === null);

  // Already-ended response → handler writes nothing.
  var rEnded = _mockRes();
  rEnded.writableEnded = true;
  var endCalls = 0;
  rEnded.end = function () { endCalls += 1; };
  h(new Error("late"), req, rEnded);
  check("writableEnded → no write, no end() call", cap(rEnded).status === null && endCalls === 0);
}

function testDefaultFormatValidation() {
  var threw = null;
  try { b.errorPage.create({ defaultFormat: "xml" }); } catch (e) { threw = e; }
  check("bad defaultFormat throws",            threw instanceof Error && /defaultFormat/.test(threw.message));

  // Valid values do not throw.
  var ok = true;
  try {
    b.errorPage.create({ defaultFormat: "auto", audit: false });
    b.errorPage.create({ defaultFormat: "json", audit: false });
    b.errorPage.create({ defaultFormat: "html", audit: false });
  } catch (_e) { ok = false; }
  check("auto/json/html defaultFormat accepted", ok);
}

function testModeAutoDetect() {
  var prev = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "production";
    check("NODE_ENV=production → prod mode",   b.errorPage.create({ audit: false }).mode === "prod");
    process.env.NODE_ENV = "development";
    check("NODE_ENV=development → dev mode",   b.errorPage.create({ audit: false }).mode === "dev");
    delete process.env.NODE_ENV;
    check("no NODE_ENV → dev mode (safe default)", b.errorPage.create({ audit: false }).mode === "dev");
  } finally {
    if (prev === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prev;
  }
}

function testAuditPath() {
  // Audit ON (the default). Capture the emitted audit record to pin the
  // security invariants of this branch, not just that the response
  // survives it: it MUST route through audit().safeEmit (which redacts the
  // secret-bearing stack/reason fields — CWE-532) and NEVER the un-redacted
  // emit(); outcome is failure for 5xx and denied for 4xx; metadata.stack is
  // attached only for 5xx; the session id resolves from session.sid or
  // session.id; and actor.ip honors the trustProxy boundary (a forwarded
  // address is trusted only when trustProxy opts in). Stub both audit sinks
  // on the shared module the lib late-binds to.
  var auditMod = b.audit; // the shared audit module the lib late-binds to
  var origSafe = auditMod.safeEmit, origEmit = auditMod.emit;
  var seenAudit = [], rawEmitCalls = 0;
  auditMod.safeEmit = function (ev) { seenAudit.push(ev); };
  auditMod.emit     = function () { rawEmitCalls++; };

  var rA, rB, rC;
  try {
    // A — 5xx, trustProxy:true trusts the X-Forwarded-For, session.sid, custom action.
    var hTrue = b.errorPage.create({ mode: "prod", log: quietLog, defaultFormat: "json", trustProxy: true, auditAction: "custom.error" });
    var reqA = _mockReq({ method: "POST", url: "/api/x", headers: { accept: "application/json", "x-forwarded-for": "203.0.113.9" } });
    reqA.id = "rid-1";
    reqA.session = { sid: "sess-abc" };
    rA = _mockRes();
    hTrue(new Error("5xx audit"), reqA, rA);

    // B — 4xx, session.id (no sid), numeric trustProxy.
    var hNum = b.errorPage.create({ mode: "prod", log: quietLog, defaultFormat: "json", trustProxy: 2 });
    var reqB = _mockReq({ method: "GET", url: "/api/y", headers: { accept: "application/json" } });
    reqB.requestId = "rid-2";
    reqB.session = { id: "sess-xyz" };
    rB = _mockRes();
    hNum({ isAppError: true, statusCode: 403, code: "FORBID", message: "denied" }, reqB, rB);

    // C — 4xx, DEFAULT trustProxy: a forwarded address from an untrusted
    // peer must NOT reach the audit actor (the boundary discriminator).
    var hDef = b.errorPage.create({ mode: "prod", log: quietLog, defaultFormat: "json" });
    var reqC = _mockReq({ method: "POST", url: "/api/z", headers: { accept: "application/json", "x-forwarded-for": "198.51.100.7" } });
    rC = _mockRes();
    hDef({ isAppError: true, statusCode: 401, code: "UNAUTH" }, reqC, rC);
  } finally {
    auditMod.safeEmit = origSafe;
    auditMod.emit = origEmit;
  }

  // The audit branch is best-effort and drop-silent — the classified
  // response is untouched by it.
  check("audit(trustProxy true, 500) status survives", cap(rA).status === 500);
  check("audit(trustProxy true) envelope survives",    jsonOf(rA).error.code === "INTERNAL_ERROR");
  check("audit(trustProxy numeric, 4xx) status survives", cap(rB).status === 403);
  check("audit(trustProxy numeric) message survives",     jsonOf(rB).error.message === "denied");
  check("audit(default trustProxy, 401) status survives", cap(rC).status === 401);

  // Security invariants of the emitted record.
  check("audit routes through safeEmit, never the un-redacted emit()", rawEmitCalls === 0);
  check("every error is audited (one safeEmit each)", seenAudit.length === 3);
  // A — 5xx.
  check("audit 5xx → outcome failure",              seenAudit[0].outcome === "failure");
  check("audit 5xx → metadata.stack attached",      typeof seenAudit[0].metadata.stack === "string" && seenAudit[0].metadata.stack.length > 0);
  check("audit → custom auditAction honored",       seenAudit[0].action === "custom.error");
  check("audit → trustProxy:true trusts forwarded IP", seenAudit[0].actor.ip === "203.0.113.9");
  check("audit → session.sid → actor.sessionId",    seenAudit[0].actor.sessionId === "sess-abc");
  check("audit 5xx → metadata.status matches",      seenAudit[0].metadata.status === 500);
  // B — 4xx.
  check("audit 4xx → outcome denied",               seenAudit[1].outcome === "denied");
  check("audit 4xx → no stack in metadata",         seenAudit[1].metadata.stack === null);
  check("audit → session.id → actor.sessionId",     seenAudit[1].actor.sessionId === "sess-xyz");
  // C — 4xx, default trustProxy ignores the forwarded address.
  check("audit 401 → outcome denied",               seenAudit[2].outcome === "denied");
  check("audit 401 → no stack in metadata",         seenAudit[2].metadata.stack === null);
  check("audit → default trustProxy ignores forwarded IP", seenAudit[2].actor.ip !== "198.51.100.7");
  check("audit → default action when unset",        seenAudit[2].action === "request.error");
}

function testLoggerInjection() {
  var captured = [];
  var fakeLog = {
    warn:  function (msg, fields) { captured.push({ level: "warn",  msg: msg, fields: fields }); },
    error: function (msg, fields) { captured.push({ level: "error", msg: msg, fields: fields }); },
    info:  function () {},
  };
  var h = b.errorPage.create({ mode: "prod", audit: false, log: fakeLog });
  var req = _mockReq({ method: "GET", url: "/x", headers: {} });

  var r500 = _mockRes();
  h(new Error("kaboom"), req, r500);
  check("500 logged at error level",           captured.length === 1 && captured[0].level === "error");
  check("500 log fields include status + url + stack",
        captured[0].fields.status === 500 && captured[0].fields.url === "/x" && typeof captured[0].fields.stack === "string");

  captured.length = 0;
  var r404 = _mockRes();
  h(Object.assign(new Error("missing"), { isAppError: true, statusCode: 404 }), req, r404);
  check("404 logged at warn level",            captured.length === 1 && captured[0].level === "warn");
  check("404 warn log carries no stack noise",  captured[0].fields.stack === undefined);
}

function testHooksThrowWithoutMessage() {
  // The three shaping hooks each log `(e && e.message) || String(e)`.
  // A thrown value with NO `.message` (throw null) exercises the
  // `String(e)` fallback and confirms the flow still recovers.

  // onError throws null → logged, continues to the default page.
  var hOnErr = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog,
    onError: function () { throw null; },   // eslint-disable-line no-throw-literal
  });
  var rOn = _mockRes();
  hOnErr(new Error("x"), _mockReq({ headers: { accept: "text/html" } }), rOn);
  check("onError throw-null recovers to default page", bodyOf(rOn).indexOf("<!doctype html>") !== -1 && cap(rOn).status === 500);

  // jsonFormatter throws null → falls back to the default envelope.
  var hFmt = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "json",
    jsonFormatter: function () { throw null; },   // eslint-disable-line no-throw-literal
  });
  var rFmt = _mockRes();
  hFmt(Object.assign(new Error("m"), { isAppError: true, statusCode: 400, code: "C" }), jsonReq(), rFmt);
  check("jsonFormatter throw-null → default envelope", jsonOf(rFmt).error.code === "C" && cap(rFmt).status === 400);

  // renderHtml throws null → falls back to the built-in page.
  var hHtml = b.errorPage.create({
    mode: "prod", audit: false, log: quietLog, defaultFormat: "html",
    renderHtml: function () { throw null; },   // eslint-disable-line no-throw-literal
  });
  var rHtml = _mockRes();
  hHtml(new Error("x"), _mockReq({ headers: { accept: "text/html" } }), rHtml);
  check("renderHtml throw-null → built-in fallback", bodyOf(rHtml).indexOf("<!doctype html>") !== -1);
}

async function run() {
  testSurface();
  testClassifyViaJson();
  testClassifyDefaultMessages();
  testDevHtmlEdgeReq();
  testNonObjectErrors();
  testContentNegotiation();
  testProdHtml();
  testDevHtml();
  testHeaderRedaction();
  testEnvVars();
  testJsonEnvelope();
  testApiEncryptEncode();
  testJsonFormatterHook();
  testRenderHtmlHook();
  testProblemDetails();
  testOnErrorHook();
  testWriteResponseFallbacks();
  testHooksThrowWithoutMessage();
  testDefaultFormatValidation();
  testModeAutoDetect();
  testAuditPath();
  testLoggerInjection();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
