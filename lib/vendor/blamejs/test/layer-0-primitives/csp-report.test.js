"use strict";
/**
 * b.middleware.cspReport — Reporting-API endpoint for CSP / COEP /
 * COOP / Permissions-Policy violations.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var _bodyReq = helpers._bodyReq;

function _capRes() {
  var sent = {};
  return {
    headersSent: false,
    writeHead: function (s, h) { sent.status = s; sent.headers = h; },
    end:       function () { sent.ended = true; },
    _sent:     sent,
  };
}

async function run() {
  var middleware = b.middleware.cspReport({});
  check("middleware.cspReport returns a function", typeof middleware === "function");

  var sent = {};
  var req = { method: "GET", headers: {} };
  var res = {
    headersSent: false,
    writeHead: function (s, h) { sent.status = s; sent.headers = h; },
    end:       function () { sent.ended = true; },
  };
  await middleware(req, res, function () {});
  check("middleware.cspReport: GET returns 405",
    sent.status === 405 && sent.ended === true);

  await testOnRejectFiresOnEveryRejection();
  testOnRejectRejectsNonFunction();
  await testValidPostReachesOnReport();
  await testOversizedPostRefused();
  await testAuditDefaultEmitsViolationRow();
  await testAuditFalseSuppressesViolationRow();
  testMaxBytesGarbageThrowsAtCreate();
}

// SUCCESS path for the audit side effect: a valid POST with the default
// audit:true emits one `csp.violation` row per normalized report, AND
// returns 204 with the report still processed (onReport reached). The
// @opts block documents `audit: boolean, // default true`; this asserts
// the default actually emits.
async function testAuditDefaultEmitsViolationRow() {
  var rows = [];
  var origEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (rec) {
    if (rec && rec.action === "csp.violation") rows.push(rec);
    return origEmit.apply(b.audit, arguments);
  };
  var reports = [];
  var res = _capRes();
  try {
    var mw = b.middleware.cspReport({ onReport: function (r) { reports.push(r); } });
    var payload = JSON.stringify([{
      type: "csp-violation",
      url:  "https://app.example.com/",
      body: { effectiveDirective: "script-src", blockedURL: "https://evil.example/x.js" },
    }]);
    await mw(_bodyReq("POST", { "content-type": "application/reports+json" }, payload), res, function () {});
  } finally {
    b.audit.safeEmit = origEmit;
  }
  check("cspReport: audit default returns 204 with report processed",
        res._sent.status === 204 && reports.length === 1);
  check("cspReport: audit default emits one csp.violation row",
        rows.length === 1 && rows[0].metadata.effectiveDirective === "script-src");
}

// audit:false suppresses the audit emission while the report is STILL
// processed end-to-end: no `csp.violation` row, but onReport reached and
// 204 returned. Operators who route violations through their own metrics
// sink shouldn't pay for the duplicate audit row.
async function testAuditFalseSuppressesViolationRow() {
  var rows = [];
  var origEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (rec) {
    if (rec && rec.action === "csp.violation") rows.push(rec);
    return origEmit.apply(b.audit, arguments);
  };
  var reports = [];
  var res = _capRes();
  try {
    var mw = b.middleware.cspReport({
      audit:    false,
      onReport: function (r) { reports.push(r); },
    });
    var payload = JSON.stringify([{
      type: "csp-violation",
      url:  "https://app.example.com/",
      body: { effectiveDirective: "img-src" },
    }]);
    await mw(_bodyReq("POST", { "content-type": "application/reports+json" }, payload), res, function () {});
  } finally {
    b.audit.safeEmit = origEmit;
  }
  check("cspReport: audit:false still returns 204 with report processed",
        res._sent.status === 204 && reports.length === 1 &&
        reports[0].body.effectiveDirective === "img-src");
  check("cspReport: audit:false emits no csp.violation row",
        rows.length === 0);
}

// maxBytes is a byte count routed through validateOpts.optionalPositiveInt
// — garbage (string / negative / NaN / fractional) throws at create()
// rather than silently falling back to the 64 KiB default while the
// sibling onReject one line below would have thrown.
function testMaxBytesGarbageThrowsAtCreate() {
  var bad = ["nope", -1, NaN, 1.5, Infinity, 0];
  for (var i = 0; i < bad.length; i++) {
    var threw = false;
    try { b.middleware.cspReport({ maxBytes: bad[i] }); }
    catch (_e) { threw = true; }
    check("cspReport: maxBytes garbage throws at create (" + String(bad[i]) + ")", threw);
  }
  // A valid positive integer is accepted; absent stays the default.
  var ok = false;
  try { b.middleware.cspReport({ maxBytes: 1024 }); ok = true; } catch (_e) { ok = false; }
  check("cspReport: valid maxBytes accepted at create", ok);
}

// The SUCCESS path: a valid POST with a parseable report body must reach
// the normalize / audit / onReport pipeline and return 204. A prior
// collector-call bug turned EVERY POST into a 413 (the endpoint never
// parsed anything); no test exercised an end-to-end POST-with-body, so
// smoke stayed green while the endpoint was dead. This is that test.
async function testValidPostReachesOnReport() {
  var reports = [];
  var res = _capRes();
  var mw = b.middleware.cspReport({ onReport: function (r) { reports.push(r); } });
  var payload = JSON.stringify([{
    type: "csp-violation",
    url:  "https://app.example.com/",
    body: { effectiveDirective: "script-src", blockedURL: "https://evil.example/x.js" },
  }]);
  await mw(_bodyReq("POST", { "content-type": "application/reports+json" }, payload), res, function () {});
  check("cspReport: valid POST returns 204",
        res._sent.status === 204 && res._sent.ended === true);
  check("cspReport: valid POST reaches onReport with the normalized report",
        reports.length === 1 && reports[0].body.effectiveDirective === "script-src");
}

// The byte cap still fires through the collector: a body over maxBytes
// is refused 413 and surfaces onReject "payload-too-large".
async function testOversizedPostRefused() {
  var rejected = null;
  var res = _capRes();
  var mw = b.middleware.cspReport({
    maxBytes:  8,
    onReject:  function (req, res, info) { rejected = info; },
  });
  await mw(_bodyReq("POST", {}, "[{\"type\":\"csp-violation\",\"body\":{}}]"), res, function () {});
  check("cspReport: body over maxBytes returns 413", res._sent.status === 413);
  check("cspReport: oversize fires onReject payload-too-large",
        rejected !== null && rejected.reason === "payload-too-large");
}

// onReject surfaces the otherwise-empty-bodied 405 / 413 / 400 refusals
// to the operator (W3C Reporting API §3.1 — the browser ignores the
// rejection body, so onReject is the only signal a metrics sink gets).
// reason ∈ { method-not-allowed (405), payload-too-large (413),
// invalid-json (400) } and always matches the status that was written.
var REASON_FOR_STATUS = { 405: "method-not-allowed", 413: "payload-too-large", 400: "invalid-json" };

async function testOnRejectFiresOnEveryRejection() {
  // 405 — non-POST. Short-circuits before the body collector, so this
  // path is deterministic.
  var got405 = null;
  var mw405 = b.middleware.cspReport({
    onReject: function (req, res, info) { got405 = info; },
  });
  var res405 = _capRes();
  await mw405({ method: "GET", headers: {} }, res405, function () {});
  check("onReject: fired on 405",
        got405 && got405.status === 405 && got405.reason === "method-not-allowed");
  check("onReject: response still written on 405",
        res405._sent.status === 405 && res405._sent.ended === true);

  // POST refusal — onReject fires and its {status, reason} agrees with
  // the status the middleware wrote. Asserting the mapping (rather than a
  // hard-coded status) keeps this test correct independent of which body
  // refusal a given input lands on.
  var gotPost = null;
  var postRes = _capRes();
  var mwPost = b.middleware.cspReport({
    onReject: function (req, res, info) { gotPost = info; },
  });
  await mwPost(_bodyReq("POST", {}, "{bad"), postRes, function () {});
  check("onReject: fired on POST refusal",            gotPost !== null);
  check("onReject: reason maps to written status",
        gotPost && REASON_FOR_STATUS[gotPost.status] === gotPost.reason &&
        gotPost.status === postRes._sent.status);

  // A throwing hook is swallowed — the endpoint still writes the refusal.
  var resThrow = _capRes();
  var mwThrow = b.middleware.cspReport({
    onReject: function () { throw new Error("sink broke"); },
  });
  await mwThrow({ method: "GET", headers: {} }, resThrow, function () {});
  check("onReject: throwing hook does not crash the endpoint",
        resThrow._sent.status === 405 && resThrow._sent.ended === true);
}

function testOnRejectRejectsNonFunction() {
  var threw = false;
  try { b.middleware.cspReport({ onReject: "nope" }); }
  catch (e) { threw = e instanceof TypeError; }
  check("onReject: non-function rejected at config time", threw);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[csp-report] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
