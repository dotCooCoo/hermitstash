"use strict";
/**
 * ageGate middleware — request-level age classification + high-privacy
 * default headers for routes that need stricter handling for users
 * below an operator-configured age threshold.
 *
 * COPPA (US, 13 and under), UK Children's Code (16 and under),
 * California AADC (18 and under), and similar regimes require
 * operators to apply heightened privacy protections when serving
 * users below a regulatory age. The middleware:
 *
 *   1. Reads the operator's `getAge(req)` predicate to classify the
 *      request as "above-threshold" / "below-threshold" / "unknown"
 *   2. Sets high-privacy defaults on below-threshold + unknown
 *      responses:
 *      - `Cache-Control: private, no-store`
 *      - `Referrer-Policy: no-referrer`
 *      - `X-Privacy-Posture: below-threshold`
 *   3. Refuses with 451 (Unavailable For Legal Reasons) when the
 *      operator-supplied requireAge: 18 is set and the request is
 *      below threshold without a parental-consent record
 *   4. Audits the classification decision
 *
 *   var gate = b.middleware.ageGate({
 *     getAge:           function (req) {
 *       if (req.user && typeof req.user.age === "number") return req.user.age;
 *       return null;                                // unknown
 *     },
 *     requireAge:       null,                       // null = don't gate, just headers
 *     consentRequired:  18,                          // require parental consent below this
 *     hasParentalConsent: function (req) {
 *       return req.user && req.user.parentalConsent === true;
 *     },
 *   });
 *   router.use(gate);
 */

var defineClass = require("../framework-error").defineClass;
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");

var audit = lazyRequire(function () { return require("../audit"); });

var AgeGateError = defineClass("AgeGateError", { alwaysPermanent: true });

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "getAge", "requireAge", "consentRequired",
    "hasParentalConsent", "skipPaths", "errorMessage",
  ], "middleware.ageGate");

  if (typeof opts.getAge !== "function") {
    throw new AgeGateError("age-gate/bad-get-age",
      "middleware.ageGate: opts.getAge must be a function (req) -> number | null");
  }
  var getAge = opts.getAge;
  var requireAge = (typeof opts.requireAge === "number" && opts.requireAge > 0)            // allow:numeric-opt-Infinity — age is operator domain, not a bytes/time-shaped opt
    ? opts.requireAge : null;
  var consentRequired = (typeof opts.consentRequired === "number" && opts.consentRequired > 0)  // allow:numeric-opt-Infinity — age threshold, not a bytes/time-shaped opt
    ? opts.consentRequired : null;
  var hasParentalConsent = typeof opts.hasParentalConsent === "function" ? opts.hasParentalConsent : null;
  var skipPaths = Array.isArray(opts.skipPaths) ? opts.skipPaths.slice() : [];
  var auditOn = opts.audit !== false;
  var errorMessage = typeof opts.errorMessage === "string" && opts.errorMessage.length > 0
    ? opts.errorMessage : "service unavailable without parental consent";

  function _shouldSkip(req) {
    if (skipPaths.length === 0) return false;
    var p = req.url || "";
    var qpos = p.indexOf("?");
    if (qpos !== -1) p = p.slice(0, qpos);
    for (var i = 0; i < skipPaths.length; i++) {
      var s = skipPaths[i];
      if (typeof s === "string" && (p === s || p.indexOf(s + "/") === 0)) return true;
      if (s instanceof RegExp && s.test(p)) return true;
    }
    return false;
  }

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   "middleware.age_gate." + action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  return function ageGateMiddleware(req, res, next) {
    if (_shouldSkip(req)) return next();

    var age;
    try { age = getAge(req); }
    catch (e) {
      _emitAudit("get_age_failed", "failure", { error: (e && e.message) || String(e) });
      age = null;
    }

    var classification;
    if (age === null || typeof age !== "number") classification = "unknown";
    else if (consentRequired !== null && age < consentRequired) classification = "below-threshold";
    else classification = "above-threshold";

    if (classification !== "above-threshold") {
      if (typeof res.setHeader === "function") {
        res.setHeader("Cache-Control",   "private, no-store");
        res.setHeader("Referrer-Policy", "no-referrer");
        res.setHeader("X-Privacy-Posture", classification);
      }
    }

    if (requireAge !== null && classification === "below-threshold" && (age === null || age < requireAge)) {
      var hasConsent = hasParentalConsent ? !!hasParentalConsent(req) : false;
      if (!hasConsent) {
        _emitAudit("refused", "denied", { age: age, classification: classification, requireAge: requireAge });
        if (!res.writableEnded && typeof res.writeHead === "function") {
          res.writeHead(451, {                                                            // allow:raw-byte-literal — HTTP 451 Unavailable For Legal Reasons
            "Content-Type":  "application/json; charset=utf-8",
            "Cache-Control": "no-store, private",
          });
          res.end(JSON.stringify({ error: errorMessage, requireAge: requireAge, parentalConsent: false }));
        }
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
