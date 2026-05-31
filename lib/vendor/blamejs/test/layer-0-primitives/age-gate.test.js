"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function _mockReq(opts) {
  opts = opts || {};
  return { url: opts.url || "/", method: opts.method || "GET", headers: opts.headers || {}, user: opts.user, locals: {} };
}
function _mockRes() {
  var captured = { status: 0, body: null, headers: {}, ended: false };
  return {
    writableEnded: false,
    writeHead: function (s, h) { captured.status = s; if (h) Object.assign(captured.headers, h); },
    setHeader: function (n, v) { captured.headers[n] = v; },
    end: function (b) { captured.body = b; captured.ended = true; this.writableEnded = true; },
    _captured: captured,
  };
}

(function run() {
  var aboveCalls = 0;
  var ag = b.middleware.ageGate({
    audit: false,
    getAge:           function (req) { return req.user && req.user.age; },
    consentRequired:  18,
  });
  ag(_mockReq({ user: { age: 21 } }), _mockRes(), function () { aboveCalls++; });
  check("above-threshold passes", aboveCalls === 1);

  var belowRes = _mockRes();
  ag(_mockReq({ user: { age: 12 } }), belowRes, function () {});
  check("below-threshold sets X-Privacy-Posture", belowRes._captured.headers["X-Privacy-Posture"] === "below-threshold");

  // privacyPostureHeader override + suppression
  var customHdr = b.middleware.ageGate({
    audit: false,
    getAge:               function (req) { return req.user && req.user.age; },
    consentRequired:      18,
    privacyPostureHeader: "X-Age-Band",
  });
  var customRes = _mockRes();
  customHdr(_mockReq({ user: { age: 12 } }), customRes, function () {});
  check("custom privacyPostureHeader used", customRes._captured.headers["X-Age-Band"] === "below-threshold");
  check("custom privacyPostureHeader replaces default", customRes._captured.headers["X-Privacy-Posture"] === undefined);

  var suppressed = b.middleware.ageGate({
    audit: false,
    getAge:               function (req) { return req.user && req.user.age; },
    consentRequired:      18,
    privacyPostureHeader: false,
  });
  var suppressedRes = _mockRes();
  suppressed(_mockReq({ user: { age: 12 } }), suppressedRes, function () {});
  check("privacyPostureHeader:false suppresses the header", suppressedRes._captured.headers["X-Privacy-Posture"] === undefined);

  // requireAge gate
  var hardGate = b.middleware.ageGate({
    audit: false,
    getAge:           function (req) { return req.user && req.user.age; },
    requireAge:       18,
    consentRequired:  18,
  });
  var refusedRes = _mockRes();
  hardGate(_mockReq({ user: { age: 12 } }), refusedRes, function () {});
  check("ageGate refuses below-threshold without consent 451", refusedRes._captured.status === 451);

  var consentedCalls = 0;
  var consentedRes = _mockRes();
  hardGate(_mockReq({ user: { age: 12 } }), consentedRes, function () { consentedCalls++; });
  // Note: hasParentalConsent is null in this gate, so still refused.
  check("ageGate without hasParentalConsent still refuses", consentedRes._captured.status === 451 && consentedCalls === 0);

  var withConsent = b.middleware.ageGate({
    audit: false,
    getAge:           function (req) { return req.user && req.user.age; },
    requireAge:       18,
    consentRequired:  18,
    hasParentalConsent: function (req) { return !!(req.user && req.user.parentalConsent); },
  });
  var consentPassedCalls = 0;
  withConsent(_mockReq({ user: { age: 12, parentalConsent: true } }), _mockRes(), function () { consentPassedCalls++; });
  check("ageGate passes when parentalConsent present", consentPassedCalls === 1);

  var threwBadGetAge = false;
  try { b.middleware.ageGate({ audit: false, getAge: "nope" }); }
  catch (e) { threwBadGetAge = e.code === "age-gate/bad-get-age"; }
  check("ageGate refuses non-fn getAge", threwBadGetAge);

  console.log("OK — ageGate tests");
})();
