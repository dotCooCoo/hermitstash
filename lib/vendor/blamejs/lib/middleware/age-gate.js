// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var defineClass = require("../framework-error").defineClass;
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var requestHelpers = require("../request-helpers");
var denyResponse = require("./deny-response").denyResponse;

var audit = lazyRequire(function () { return require("../audit"); });

var AgeGateError = defineClass("AgeGateError", { alwaysPermanent: true });

/**
 * @primitive b.middleware.ageGate
 * @signature b.middleware.ageGate(opts)
 * @since     0.1.0
 * @compliance gdpr, ferpa, ccpa
 * @related   b.middleware.gpc
 *
 * Classifies the request against an operator-supplied age predicate
 * and applies COPPA / UK Children's Code / California AADC defaults
 * (no-store cache, no-referrer, X-Privacy-Posture header) for
 * below-threshold + unknown-age requests. `requireAge` is the hard
 * legal floor: a request classified below threshold without a
 * parental-consent record is refused with HTTP 451. It is evaluated
 * within the consent classification, so it takes effect only when
 * `consentRequired` is also set (that is what classifies a request as
 * below-threshold); `requireAge` alone, with `consentRequired: null`,
 * never classifies a request as below-threshold and so the 451 never
 * fires. Every classification decision is audited.
 *
 * @opts
 *   {
 *     getAge:             function(req): number|null,  // required
 *     requireAge:         number|null,                  // 451 floor; requires consentRequired set
 *     consentRequired:    number|null,                  // require consent below; enables below-threshold classification
 *     hasParentalConsent: function(req): boolean,
 *     skipPaths:          string[],
 *     errorMessage:       string,
 *     privacyPostureHeader: string,                     // default "X-Privacy-Posture"; null/false to suppress
 *     audit:              boolean,                      // default true
 *     onDeny:             function(req, res, info): void,  // own the 451; info = { status, reason, age, classification, requireAge }
 *     problemDetails:     boolean,                      // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.ageGate({
 *     getAge:           function (req) { return (req.user && req.user.age) || null; },
 *     requireAge:       null,
 *     consentRequired:  13,
 *     hasParentalConsent: function (req) { return req.user && req.user.parentalConsent === true; },
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "getAge", "requireAge", "consentRequired",
    "hasParentalConsent", "skipPaths", "errorMessage", "privacyPostureHeader",
    "onDeny", "problemDetails",
  ], "middleware.ageGate");

  if (typeof opts.getAge !== "function") {
    throw new AgeGateError("age-gate/bad-get-age",
      "middleware.ageGate: opts.getAge must be a function (req) -> number | null");
  }
  var getAge = opts.getAge;
  var requireAge = (typeof opts.requireAge === "number" && opts.requireAge > 0)            // allow:numeric-opt-Infinity-intentional — age threshold; an Infinity bound is fail-closed (denies everyone), never a bypass
    ? opts.requireAge : null;
  var consentRequired = (typeof opts.consentRequired === "number" && opts.consentRequired > 0)  // allow:numeric-opt-Infinity-intentional — age threshold; an Infinity bound is fail-closed (classifies everyone below-threshold), never a bypass
    ? opts.consentRequired : null;
  var hasParentalConsent = typeof opts.hasParentalConsent === "function" ? opts.hasParentalConsent : null;
  var skipPaths = Array.isArray(opts.skipPaths) ? opts.skipPaths.slice() : [];
  var errorMessage = typeof opts.errorMessage === "string" && opts.errorMessage.length > 0
    ? opts.errorMessage : "service unavailable without parental consent";
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;
  var privacyPostureHeader;
  if (opts.privacyPostureHeader === null || opts.privacyPostureHeader === false) {
    privacyPostureHeader = null;
  } else if (typeof opts.privacyPostureHeader === "string" && opts.privacyPostureHeader.length > 0) {
    privacyPostureHeader = opts.privacyPostureHeader;
  } else {
    privacyPostureHeader = "X-Privacy-Posture";
  }

  var _shouldSkip = requestHelpers.makeSkipMatcher({ skipPaths: skipPaths }, "middleware.ageGate");

  var _emitAudit = audit().namespaced("middleware.age_gate", opts.audit);

  return function ageGateMiddleware(req, res, next) {
    if (_shouldSkip(req)) return next();

    var age;
    try { age = getAge(req); }
    catch (e) {
      _emitAudit("get_age_failed", "failure", { error: (e && e.message) || String(e) });
      age = null;
    }

    var classification;
    if (age === null || typeof age !== "number" || !isFinite(age)) classification = "unknown";
    else if (consentRequired !== null && age < consentRequired) classification = "below-threshold";
    else classification = "above-threshold";

    if (classification !== "above-threshold") {
      if (typeof res.setHeader === "function") {
        res.setHeader("Cache-Control",   "private, no-store");
        res.setHeader("Referrer-Policy", "no-referrer");
        if (privacyPostureHeader) res.setHeader(privacyPostureHeader, classification);
      }
    }

    if (requireAge !== null && classification === "below-threshold" && (age === null || age < requireAge)) {
      var hasConsent = hasParentalConsent ? !!hasParentalConsent(req) : false;
      if (!hasConsent) {
        _emitAudit("refused", "denied", { age: age, classification: classification, requireAge: requireAge });
        denyResponse(req, res, {
          onDeny:        onDeny,
          problem:       problemMode,
          status:        C.HTTP.STATUS.UNAVAILABLE_FOR_LEGAL_REASONS,
          info:          { status: C.HTTP.STATUS.UNAVAILABLE_FOR_LEGAL_REASONS, reason: "parental-consent-required",
            age: age, classification: classification, requireAge: requireAge },
          problemCode:   "parental-consent-required",
          problemTitle:  "Unavailable For Legal Reasons",
          problemDetail: errorMessage,
          problemExt:    { requireAge: requireAge, parentalConsent: false },
          headers:       { "Cache-Control": "no-store, private" },
          contentType:   "application/json; charset=utf-8",
          body:          JSON.stringify({ error: errorMessage, requireAge: requireAge, parentalConsent: false }),
        });
        return;
      }
    }

    if (req.locals && typeof req.locals === "object") {
      req.locals.ageGateClassification = classification;
    }
    _emitAudit("classified", "success", { classification: classification, age: age });
    return next();
  };
}

module.exports = {
  create:       create,
  AgeGateError: AgeGateError,
};
