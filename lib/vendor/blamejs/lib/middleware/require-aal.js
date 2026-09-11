// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var { AuthError } = require("../framework-error");

var aal = lazyRequire(function () { return require("../auth/aal"); });
var audit = lazyRequire(function () { return require("../audit"); });

function _writeUnauthorized(req, res, requiredBand, actualBand, realm, onDeny, problemMode) {
  if (res.headersSent) return;
  var body = JSON.stringify({
    error:             "step_up_required",
    error_description: "AAL " + requiredBand + " is required for this resource",
    required_aal:      requiredBand,
    actual_aal:        actualBand || null,
  });
  var realmStr = realm ? ' realm="' + realm + '"' : "";
  var challenge = "AAL-StepUp" + realmStr + ', required="' + requiredBand + '"';
  denyResponse(req, res, {
    onDeny:        onDeny,
    problem:       problemMode,
    status:        C.HTTP.STATUS.UNAUTHORIZED,
    info:          { status: C.HTTP.STATUS.UNAUTHORIZED, reason: "step_up_required",
      required_aal: requiredBand, actual_aal: actualBand || null },
    problemCode:   "step-up-required",
    problemTitle:  "Step-Up Authentication Required",
    problemDetail: "AAL " + requiredBand + " is required for this resource.",
    problemExt:    { required_aal: requiredBand, actual_aal: actualBand || null },
    headers:       {
      "WWW-Authenticate": challenge,
      "Cache-Control":    "no-store",
    },
    contentType:   "application/json; charset=utf-8",
    body:          body,
  });
}

/**
 * @primitive b.middleware.requireAal
 * @signature b.middleware.requireAal(opts)
 * @since     0.1.0
 * @related   b.middleware.requireStepUp, b.middleware.requireAuth
 *
 * Gates routes by NIST SP 800-63-4 Authenticator Assurance Level
 * (AAL1 / AAL2 / AAL3). Reads the actual band from `req.user.aal`
 * by default; operators with a different shape pass `getAal(req)`.
 * Refuses below-minimum requests with HTTP 401 +
 * `WWW-Authenticate: AAL-StepUp realm="<X>", required="<minimum>"`
 * — the bespoke scheme name signals the frontend to trigger a
 * step-up flow (re-prompt for TOTP / passkey). Throws at create()
 * on an invalid `minimum` band. Emits `auth.aal.granted` /
 * `auth.aal.denied` audit events.
 *
 * @opts
 *   {
 *     minimum: "AAL1"|"AAL2"|"AAL3",   // required
 *     getAal:  function(req): string,
 *     realm:   string,
 *     audit:   boolean,                // default true
 *     onDeny:  function(req, res, info): void,  // own the 401; info = { status, reason, required_aal, actual_aal }
 *     problemDetails: boolean,         // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use("/admin", b.middleware.requireAal({ minimum: "AAL2" }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "minimum", "getAal", "audit", "realm", "onDeny", "problemDetails",
  ], "middleware.requireAal");

  var minimum = opts.minimum;
  if (!aal().isValidBand(minimum)) {
    throw new AuthError("auth-aal/bad-minimum",
      "middleware.requireAal: opts.minimum must be one of " +
      aal().BANDS.join(", ") + " (got " + JSON.stringify(minimum) + ")");
  }
  validateOpts.optionalFunction(opts.getAal,
    "middleware.requireAal: getAal", AuthError, "auth-aal/bad-opt");

  var auditOn = opts.audit !== false;
  var realm = (typeof opts.realm === "string" && opts.realm.length > 0) ? opts.realm : null;
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;

  return function requireAalMiddleware(req, res, next) {
    var actual = null;
    if (typeof opts.getAal === "function") {
      try { actual = opts.getAal(req); } catch (_e) { actual = null; }
    } else if (req.user && typeof req.user.aal === "string") {
      actual = req.user.aal;
    }

    if (!aal().meets(actual, minimum)) {
      if (auditOn) {
        try {
          audit().safeEmit({
            action:  "auth.aal.denied",
            actor:   { clientIp: requestHelpers.clientIp(req), userId: req.user && req.user.id },
            outcome: "denied",
            metadata: {
              required: minimum,
              actual:   actual || null,
              route:    req.url,
            },
          });
        } catch (_ignored) { /* drop-silent */ }
      }
      return _writeUnauthorized(req, res, minimum, actual, realm, onDeny, problemMode);
    }

    if (auditOn) {
      try {
        audit().safeEmit({
          action:  "auth.aal.granted",
          actor:   { clientIp: requestHelpers.clientIp(req), userId: req.user && req.user.id },
          outcome: "success",
          metadata: { aal: actual, required: minimum, route: req.url },
        });
      } catch (_ignored) { /* drop-silent */ }
    }
    return next();
  };
}

module.exports = {
  create: create,
};
