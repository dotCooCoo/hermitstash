"use strict";
/**
 * require-aal middleware — gate routes by NIST SP 800-63-4 AAL band.
 *
 *   var stepUp = b.middleware.requireAal({ minimum: "AAL2" });
 *   router.use("/admin", stepUp);
 *
 * Reads the AAL band from `req.user.aal` by default. Operators with a
 * different shape pass `getAal(req)` returning the band string.
 *
 * On failure the middleware writes 401 with
 * `WWW-Authenticate: AAL-StepUp realm="<X>", required="<minimum>"`
 * — the bespoke scheme name signals to the operator's frontend that a
 * step-up flow should be triggered (re-prompt for TOTP / passkey).
 *
 * Audit:
 *   auth.aal.granted — request passed (carries the actual band)
 *   auth.aal.denied  — request below the required minimum
 */

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

var aal = lazyRequire(function () { return require("../auth/aal"); });
var audit = lazyRequire(function () { return require("../audit"); });

function _writeUnauthorized(res, requiredBand, actualBand, realm) {
  if (res.headersSent) return;
  var body = JSON.stringify({
    error:             "step_up_required",
    error_description: "AAL " + requiredBand + " is required for this resource",
    required_aal:      requiredBand,
    actual_aal:        actualBand || null,
  });
  var realmStr = realm ? ' realm="' + realm + '"' : "";
  var challenge = "AAL-StepUp" + realmStr + ', required="' + requiredBand + '"';
  res.writeHead(401, {                                                             // allow:raw-byte-literal — HTTP 401 status
    "Content-Type":     "application/json; charset=utf-8",
    "Content-Length":   Buffer.byteLength(body),
    "WWW-Authenticate": challenge,
  });
  res.end(body);
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
    "minimum", "getAal", "audit", "realm",
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
      return _writeUnauthorized(res, minimum, actual, realm);
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
