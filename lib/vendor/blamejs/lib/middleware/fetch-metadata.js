// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
// Monotonic per-process counter giving each fetchMetadata mount a unique
// idempotency id (see GATE_ID in create) so a stricter sub-route instance is
// not silently disabled by an earlier lenient one sharing a global flag.
var _fmGateSeq = 0;

// Sec-Fetch-Dest request-destination vocabulary (Fetch Standard §3.2.6
// "destination", https://fetch.spec.whatwg.org/#concept-request-destination;
// surfaced as the Sec-Fetch-Dest header by the Fetch Metadata Request
// Headers spec, https://www.w3.org/TR/fetch-metadata/#sec-fetch-dest-header).
// "webidentity" (FedCM credentialed-request destination,
// https://w3c.github.io/FedCM/) is included so an operator can recognize
// and gate FedCM traffic first-class — a webidentity Sec-Fetch-Dest on a
// route that is not a FedCM identity endpoint is a request worth refusing.
var KNOWN_DESTINATIONS = Object.freeze([
  "audio", "audioworklet", "document", "embed", "empty", "fencedframe",
  "font", "frame", "iframe", "image", "json", "manifest", "object",
  "paintworklet", "report", "script", "serviceworker", "sharedworker",
  "style", "track", "video", "webidentity", "worker", "xslt",
]);
var KNOWN_DEST_SET = Object.create(null);
(function () {
  for (var i = 0; i < KNOWN_DESTINATIONS.length; i += 1) {
    KNOWN_DEST_SET[KNOWN_DESTINATIONS[i]] = true;
  }
})();

// Sec-Fetch-Storage-Access status values (Storage Access API,
// https://privacycg.github.io/storage-access-headers/ — the header is
// distinct from Sec-Fetch-Dest). The browser sends this only on cross-site
// credentialed requests. "active" / "inactive" both indicate the embedded
// context can (active) or could (inactive, permission granted but not yet
// exercised) reach unpartitioned cross-site cookies; "none" carries no
// such capability. A route that does not participate in the Storage Access
// flow may refuse the active/inactive escalation.
var STORAGE_ACCESS_ESCALATED = Object.freeze({ active: true, inactive: true });

function _validateDestList(list, label) {
  // Config-time tier — an unknown Sec-Fetch-Dest value in a strict
  // allow/deny list is almost always an operator typo (e.g. "web-identity"
  // for "webidentity"). Throw at boot per the config/entry-point tier so
  // the typo surfaces before it silently fails to match at request time.
  if (!Array.isArray(list)) return;
  for (var i = 0; i < list.length; i += 1) {
    if (!Object.prototype.hasOwnProperty.call(KNOWN_DEST_SET, list[i])) {
      throw new Error("middleware.fetchMetadata: " + label + "[" + i +
        "] is not a known Sec-Fetch-Dest value (got '" + String(list[i]) +
        "'). Known destinations: " + KNOWN_DESTINATIONS.join(", ") + ".");
    }
  }
}

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
 * The Sec-Fetch-Dest vocabulary tracks the Fetch Standard request-
 * destination list, including `webidentity` (FedCM credentialed
 * requests). `deniedDest` refuses chosen destinations outright on the
 * gated methods — a FedCM `webidentity` Sec-Fetch-Dest hitting a route
 * that is not an identity endpoint is refused. The Storage Access API
 * escalation (a cross-site request carrying `Sec-Fetch-Storage-Access:
 * active` / `inactive`) is REFUSED BY DEFAULT (v0.15.0) on routes that do
 * not participate in the Storage Access flow; operators running an
 * embedded-iframe SaaS that legitimately uses the API opt back in with
 * `allowStorageAccess: true`. `deniedDest` stays opt-in (unset = no
 * destination is denied outright).
 *
 * @opts
 *   {
 *     allowSameSite:      boolean,    // default true
 *     allowCrossSite:     boolean,    // default false
 *     allowMissing:       boolean,    // default true
 *     allowedDest:        string[],   // cross-site allowlist of Sec-Fetch-Dest values
 *     deniedDest:         string[],   // Sec-Fetch-Dest values refused on gated methods regardless of site (e.g. ["webidentity"])
 *     allowStorageAccess: boolean,    // default false — refuses Sec-Fetch-Storage-Access: active|inactive; pass true to opt back in for Storage-Access-flow routes
 *     strictDest:         boolean,    // default false — true throws at config time on an allowedDest/deniedDest value outside the known Sec-Fetch-Dest vocabulary
 *     allowedNavigate:    boolean,    // default true
 *     methods:            string[],   // default POST/PUT/DELETE/PATCH
 *     audit:              boolean,    // default true
 *     onDeny:             function(req, res, info): void,  // own the 403; info = { status, reason }
 *     problemDetails:     boolean,    // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
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
    "allowedDest", "deniedDest", "allowStorageAccess", "strictDest",
    "allowedNavigate", "methods", "audit", "onDeny", "problemDetails",
    "skipPaths", "skip",
  ], "middleware.fetchMetadata");
  validateOpts.optionalBoolean(opts.allowStorageAccess, "middleware.fetchMetadata: allowStorageAccess");
  validateOpts.optionalBoolean(opts.strictDest, "middleware.fetchMetadata: strictDest");
  validateOpts.optionalNonEmptyStringArray(opts.deniedDest, "middleware.fetchMetadata: deniedDest");
  if (opts.strictDest === true) {
    _validateDestList(opts.allowedDest, "allowedDest");
    _validateDestList(opts.deniedDest, "deniedDest");
  }

  // Per-path exemption (string-prefix / RegExp / skip predicate), validated at
  // create() — exempt a webhook / cookieless edge-cached route from the
  // fetch-metadata gate without disabling the app-level mount.
  var _shouldSkip = requestHelpers.makeSkipMatcher(opts, "middleware.fetchMetadata");

  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;
  var allowSameSite      = opts.allowSameSite !== false;
  var allowCrossSite     = opts.allowCrossSite === true;
  var allowMissing       = opts.allowMissing !== false;
  var allowedDest        = Array.isArray(opts.allowedDest)    ? opts.allowedDest.slice()    : null;
  // Storage Access escalation default-deny (v0.15.0): a cross-site
  // credentialed request carrying Sec-Fetch-Storage-Access: active|inactive
  // is REFUSED by default on the gated methods, because that header signals
  // the embedded context can reach unpartitioned cross-site cookies — a
  // capability a route that does not participate in the Storage Access flow
  // should not silently honor. Operators running an embedded-iframe SaaS
  // that legitimately uses the Storage Access API opt back in with
  // allowStorageAccess: true.
  var allowStorageAccess = opts.allowStorageAccess === true;
  // deniedDest → a null-prototype membership map; an operator-supplied
  // destination string is never assigned onto a plain object, so no
  // reserved name (__proto__ / constructor / prototype) can pollute it.
  var deniedDest = null;
  if (Array.isArray(opts.deniedDest) && opts.deniedDest.length > 0) {
    deniedDest = Object.create(null);
    for (var di = 0; di < opts.deniedDest.length; di += 1) {
      deniedDest[opts.deniedDest[di]] = true;
    }
  }
  var allowedNavigate = opts.allowedNavigate !== false;
  // An empty methods array is truthy, so `opts.methods || DEFAULT_METHODS`
  // would keep `[]` and `methods.indexOf(req.method) === -1` would be true for
  // EVERY request — silently turning the gate into a pass-through. Reject a
  // present-but-empty/garbage list at config time (fail-fast, don't degrade
  // the gate to a no-op).
  if (opts.methods !== undefined) {
    if (!Array.isArray(opts.methods) || opts.methods.length === 0 ||
        !opts.methods.every(function (m) { return typeof m === "string" && m.length > 0; })) {
      throw new Error("middleware.fetchMetadata: opts.methods must be a non-empty array of HTTP method tokens (omit it for the POST/PUT/DELETE/PATCH default)");
    }
  }
  var methods         = (opts.methods || DEFAULT_METHODS).map(function (m) { return m.toUpperCase(); });
  var auditOn         = opts.audit !== false;
  // Per-instance idempotency id: a request carries a Set of gates that have
  // already run. The OLD shared `req._fetchMetadataChecked` boolean let the
  // FIRST fetch-metadata mount (e.g. the lenient app-level default) permanently
  // disable a STRICTER instance layered on a sub-route. Keying by a unique id
  // lets each distinct mount run once while the SAME instance mounted twice
  // still no-ops.
  var GATE_ID = "fm:" + (_fmGateSeq++);

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
    // Idempotent PER INSTANCE: the same mount running twice on a request is a
    // no-op, but a distinct (e.g. stricter sub-route) instance still evaluates.
    if (!req._fetchMetadataGates) req._fetchMetadataGates = Object.create(null);
    if (req._fetchMetadataGates[GATE_ID]) return next();
    req._fetchMetadataGates[GATE_ID] = true;
    if (_shouldSkip(req)) return next();
    if (methods.indexOf(req.method) === -1) return next();

    var headers = req.headers || {};
    var site = headers["sec-fetch-site"];
    var mode = headers["sec-fetch-mode"];
    var dest = headers["sec-fetch-dest"];

    // Destination refusal — independent of site. A FedCM `webidentity`
    // (or any operator-denied) Sec-Fetch-Dest on a route that is not an
    // identity endpoint is refused outright. The membership test is exact
    // (null-prototype map keyed on the verbatim header value), never a
    // substring scan.
    if (deniedDest && typeof dest === "string" && deniedDest[dest] === true) {
      _emitDenied(req, "dest-denied (dest=" + dest + ")");
      return _writeReject(req, res, "Request destination not allowed for this route.", "dest-not-allowed", onDeny, problemMode);
    }

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
    // Storage Access API escalation — the browser sends
    // Sec-Fetch-Storage-Access only on cross-site credentialed requests.
    // active|inactive both mean the embedded context can / could reach
    // unpartitioned cross-site cookies; refuse it on routes that do not
    // participate in the Storage Access flow. Exact membership, never a
    // substring scan. Checked before the allowCrossSite shortcut so the
    // escalation is gated even when cross-site is otherwise permitted.
    var storageAccess = headers["sec-fetch-storage-access"];
    if (!allowStorageAccess && typeof storageAccess === "string" &&
        STORAGE_ACCESS_ESCALATED[storageAccess] === true) {
      _emitDenied(req, "storage-access-refused (status=" + storageAccess + ")");
      return _writeReject(req, res, "Storage Access escalation not allowed for this route.", "storage-access-refused", onDeny, problemMode);
    }
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
