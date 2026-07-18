// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

function run() {
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

  // A getAge that computes a NON-FINITE number (NaN from parseInt on a
  // malformed birth field / date math, or ±Infinity) must NOT be read as a
  // confirmed adult. typeof NaN === "number" and `NaN < consentRequired`
  // is false, so the classifier fell through to "above-threshold" — silently
  // dropping every child-safety privacy default for a user whose age simply
  // failed to compute (an attacker-influenced fail-open when the birth field
  // is request-derived). A non-finite age is classified "unknown" (privacy
  // headers applied), consistent with a null / non-number return.
  var nanGate = b.middleware.ageGate({
    audit: false,
    getAge:          function () { return Number("not-a-birth-year"); },   // NaN
    consentRequired: 18,
  });
  var nanRes = _mockRes();
  var nanNext = 0;
  nanGate(_mockReq({ url: "/kids", method: "POST" }), nanRes, function () { nanNext++; });
  check("NaN age classified unknown, not above-threshold",
    nanRes._captured.headers["X-Privacy-Posture"] === "unknown");
  check("NaN age applies the no-store privacy default",
    nanRes._captured.headers["Cache-Control"] === "private, no-store");
  check("NaN age still flows downstream as unknown (privacy posture, no hard block)",
    nanNext === 1 && nanRes._captured.status === 0);

  var infGate = b.middleware.ageGate({
    audit: false,
    getAge:          function () { return Infinity; },
    consentRequired: 18,
  });
  var infRes = _mockRes();
  infGate(_mockReq({ url: "/kids", method: "POST" }), infRes, function () {});
  check("Infinity age classified unknown (non-finite is not a valid age)",
    infRes._captured.headers["X-Privacy-Posture"] === "unknown");

  var threwBadGetAge = false;
  try { b.middleware.ageGate({ audit: false, getAge: "nope" }); }
  catch (e) { threwBadGetAge = e.code === "age-gate/bad-get-age"; }
  check("ageGate refuses non-fn getAge", threwBadGetAge);

  console.log("OK — ageGate tests");
}

module.exports = { run: run };
if (require.main === module) run();
