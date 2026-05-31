"use strict";
/**
 * fetch-metadata — Sec-Fetch-Site / Sec-Fetch-Mode / Sec-Fetch-Dest
 * isolation primitive (Resource Isolation Policy / Site Isolation —
 * https://web.dev/fetch-metadata/).
 *
 * Browsers attach Sec-Fetch-* headers describing the FETCH context
 * (same-site? cross-site? typed-URL? navigation? script load?).
 * This middleware refuses cross-site requests on state-changing
 * methods unless the operator explicitly allowlists them — a second-
 * line defense alongside CSRF tokens.
 *
 *   var fmGate = b.middleware.fetchMetadata({
 *     allowSameSite:    true,           // default
 *     allowCrossSite:   false,          // default — refuse cross-site state changes
 *     allowedDest:      ["empty", "document"],   // operator allowlist of Sec-Fetch-Dest
 *     allowedNavigate:  true,           // allow direct navigations (typed URL / bookmark)
 *     methods:          ["POST","PUT","DELETE","PATCH"],
 *     audit:            true,
 *   });
 *   router.use("/api", fmGate);
 *
 * Refusal shape: 403 application/json + audit row. Same-origin /
 * same-site requests pass through; cross-site refused unless
 * allowedDest contains the request's Sec-Fetch-Dest. None / undefined
 * (legacy browsers without fetch-metadata) is treated per
 * `allowMissing` (default true — don't break older clients).
 *
 * Fail-open posture: when the request is missing Sec-Fetch-* entirely
 * (curl, server-to-server, browser <Chrome 76 / <Firefox 90 / <Safari
 * 16.4), the gate defers to other auth/CSRF layers. The browser-fetch-
 * metadata isolation IS the value-add; non-browser clients carry their
 * own auth threat model.
 */

var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var lazyRequire = require("../lazy-require");
var denyResponse = require("./deny-response").denyResponse;

var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });

var DEFAULT_METHODS = Object.freeze(["POST", "PUT", "DELETE", "PATCH"]);

function _writeReject(req, res, message, reason, onDeny, problemMode) {
  denyResponse(req, res, {
    onDeny:        onDeny,
    problem:       problemMode,
    status:        requestHelpers.HTTP_STATUS.FORBIDDEN,
    info:          { status: 403, reason: reason },
    problemCode:   "fetch-metadata-refused",
    problemTitle:  "Forbidden",
    problemDetail: message,
    contentType:   "application/json; charset=utf-8",
    body:          JSON.stringify({ error: message }),
  });
}

/**
 * @primitive b.middleware.fetchMetadata
 * @signature b.middleware.fetchMetadata(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.cors, b.middleware.csrfProtect
 *
 * Resource Isolation Policy enforced via Sec-Fetch-Site / -Mode /
 * -Dest. Constructed via `b.middleware.fetchMetadata(opts)`; the
 * resulting middleware has the `(req, res, next)` shape shown above. Refuses cross-site requests on state-changing methods
 * unless the operator allowlists them — second-line defense
 * alongside CSRF tokens. Same-origin / same-site requests pass
 * through. Cross-site is refused with HTTP 403 unless `allowedDest`
 * contains the request's `Sec-Fetch-Dest`. Legacy browsers without
 * Sec-Fetch-* default to `allowMissing: true` so the gate doesn't
 * break older clients — the browser-fetch-metadata isolation IS
 * the value-add; non-browser callers carry their own auth threat
 * model.
 *
 * @opts
 *   {
 *     allowSameSite:   boolean,    // default true
 *     allowCrossSite:  boolean,    // default false
 *     allowMissing:    boolean,    // default true
 *     allowedDest:     string[],
 *     allowedNavigate: boolean,    // default true
 *     methods:         string[],   // default POST/PUT/DELETE/PATCH
 *     audit:           boolean,    // default true
 *     onDeny:          function(req, res, info): void,  // own the 403; info = { status, reason }
 *     problemDetails:  boolean,    // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use("/api", b.middleware.fetchMetadata({
 *     allowSameSite:   true,
 *     allowCrossSite:  false,
 *     allowedDest:     ["empty", "document"],
 *     allowedNavigate: true,
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "allowSameSite", "allowCrossSite", "allowMissing",
    "allowedDest", "allowedNavigate", "methods", "audit", "onDeny", "problemDetails",
  ], "middleware.fetchMetadata");

  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;
  var allowSameSite   = opts.allowSameSite !== false;
  var allowCrossSite  = opts.allowCrossSite === true;
  var allowMissing    = opts.allowMissing !== false;
  var allowedDest     = Array.isArray(opts.allowedDest)    ? opts.allowedDest.slice()    : null;
  var allowedNavigate = opts.allowedNavigate !== false;
  var methods         = (opts.methods || DEFAULT_METHODS).map(function (m) { return m.toUpperCase(); });
  var auditOn         = opts.audit !== false;

  function _emitDenied(req, reason) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   "auth.fetch_metadata.denied",
        outcome:  "denied",
        actor:    requestHelpers.extractActorContext(req),
        reason:   reason,
        metadata: { method: req.method, path: (req.url || "").split("?")[0] },
      });
    } catch (_e) { /* audit best-effort */ }
  }

  return function fetchMetadata(req, res, next) {
    // Idempotent: a second fetch-metadata mount this request is a no-op.
    if (req._fetchMetadataChecked) return next();
    req._fetchMetadataChecked = true;
    if (methods.indexOf(req.method) === -1) return next();

    var headers = req.headers || {};
    var site = headers["sec-fetch-site"];
    var mode = headers["sec-fetch-mode"];
    var dest = headers["sec-fetch-dest"];

    if (typeof site !== "string" || site.length === 0) {
      // No Sec-Fetch-Site header — legacy browser or non-browser client.
      // Defer to other auth/CSRF layers per allowMissing.
      if (!allowMissing) {
        _emitDenied(req, "fetch-metadata-missing");
        return _writeReject(req, res, "Fetch-metadata required.", "fetch-metadata-missing", onDeny, problemMode);
      }
      return next();
    }

    // Direct navigations — typed URL, bookmark, history navigation.
    if (site === "none") {
      if (allowedNavigate) return next();
      _emitDenied(req, "navigate-disallowed");
      return _writeReject(req, res, "Direct navigation not allowed for this method.", "navigation-not-allowed", onDeny, problemMode);
    }

    if (site === "same-origin") return next();

    if (site === "same-site") {
      if (allowSameSite) return next();
      _emitDenied(req, "same-site-disallowed");
      return _writeReject(req, res, "Same-site request not allowed.", "same-site-not-allowed", onDeny, problemMode);
    }

    // cross-site
    if (allowCrossSite) return next();
    if (allowedDest && typeof dest === "string" && allowedDest.indexOf(dest) !== -1) {
      return next();
    }
    _emitDenied(req, "cross-site-refused (mode=" + (mode || "?") +
                     ", dest=" + (dest || "?") + ")");
    try { observability().count("auth.fetch_metadata.cross_site_refused", 1, {}); }
    catch (_e) { /* best-effort */ }
    return _writeReject(req, res, "Cross-site request refused.", "cross-site-refused", onDeny, problemMode);
  };
}

module.exports = { create: create };
