"use strict";
/**
 * CORS middleware — allow-list-only by default. No '*' wildcard support
 * for credentialed requests (which spec disallows anyway). Operators must
 * explicitly enumerate origins they trust.
 *
 * Same-origin requests pass through without consulting the allow-list:
 * the Fetch spec instructs browsers to send an Origin header on every
 * POST / PUT / PATCH / DELETE — even same-origin ones — so an empty
 * allow-list would otherwise refuse the operator's own login form.
 * Same-origin is detected by:
 *   1. Origin === opts.siteOrigin if configured (explicit, recommended —
 *      works behind TLS-terminating proxies where the framework can't
 *      infer scheme), or
 *   2. Origin === request's inferred scheme/host/port (from req.socket
 *      and req.headers.host — correct for direct deployments).
 *
 * Origin: null shortcut (opt-in via strictNullOrigin: false): browsers
 * send `Origin: null` on form-navigation POSTs from a page whose response
 * carries `Referrer-Policy: no-referrer` (or similarly strict policy) —
 * the Origin is opaqued to prevent a cross-site leak. The Sec-Fetch-Site
 * Fetch-metadata signal distinguishes a same-origin nav from a genuine
 * cross-site post in that opaque-origin world. Default is to REFUSE the
 * shortcut (strictNullOrigin: true) — non-browser clients can forge
 * Sec-Fetch-Site freely, and operators using `refuseUnknown: true` as a
 * stricter "refuse unrecognized origin" policy expect the gate to hold.
 * Operators with a no-referrer page that legitimately produces
 * Origin: null on same-origin POSTs flip strictNullOrigin: false.
 *
 * Options:
 *   {
 *     origins:        [ 'https://app.example.com', /^https:\/\/.+\.example\.com$/ ]
 *     siteOrigin:     'https://wiki.example.com'    // string OR array
 *     methods:        [ 'GET', 'POST', 'PUT', 'DELETE', 'PATCH' ]
 *     headers:        [ 'Content-Type', 'Authorization', 'X-Request-Id' ]
 *     exposeHeaders:  [ 'X-Request-Id', 'X-Response-Time' ]
 *     credentials:    true     (sets Access-Control-Allow-Credentials: true)
 *     maxAgeSeconds:  600
 *     refuseUnknown:  true     (refuse cross-origin requests from unlisted
 *                                origins instead of just omitting CORS headers)
 *     strictNullOrigin: true   (default — refuse Origin: null even with
 *                                Sec-Fetch-Site: same-origin. Set false to
 *                                allow the no-referrer-page edge case.)
 *   }
 *
 * Audit: refuseUnknown blocks emit system.cors.block with the offending Origin.
 *
 * Configuration validation: opts.siteOrigin must parse as an http(s) URL,
 * opts.origins entries must be strings or RegExp. Bad config surfaces at
 * create() not at first cross-origin request.
 */
var C = require("../constants");
var lazyRequire = require("../lazy-require");
var audit = lazyRequire(function () { return require("../audit"); });
var requestHelpers = require("../request-helpers");
var safeUrl = require("../safe-url");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

// CORS audit events use the proxy-aware client IP only when the
// operator opts in via `trustProxy`. Default refuses forwarded
// headers — same boundary as the rest of the v0.5.3 trustProxy sweep.
function _xffIpFor(trustProxy) {
  return function (req) {
    return requestHelpers.clientIp(req, { trustProxy: trustProxy });
  };
}

var CorsError = defineClass("CorsError", { alwaysPermanent: true });

// allowList entries:
//   - { kind: "string", canonical: "https://app.example.com", original: "..." }
//   - { kind: "regex",  pattern: /.../  }
// Both raw entry and the inbound origin run through _canonicalOrigin
// before equality so case differences ("https://APP" vs "https://app")
// and default-port differences ("https://x:443" vs "https://x") match.
function _matchOrigin(origin, allowList) {
  if (!origin) return null;
  var canon = _canonicalOrigin(origin);
  for (var i = 0; i < allowList.length; i++) {
    var entry = allowList[i];
    if (entry.kind === "string") {
      if (canon !== null && entry.canonical === canon) return origin;
    } else if (entry.kind === "regex") {
      // Regex entries match against the raw origin (operator wrote the
      // pattern with whatever case / port shape they intended). Also try
      // the canonical form so case-insensitive intent works without /i.
      if (entry.pattern.test(origin)) return origin;
      if (canon !== null && entry.pattern.test(canon)) return origin;
    }
  }
  return null;
}

// Normalize an origin string by parsing it through safeUrl and
// returning `protocol//host[:port]` with no trailing slash. Used for
// equality checks that have to handle case differences and the URL
// parser's auto-port-omission for default ports (80/443).
//
// safeUrl defaults to ALLOW_HTTP_TLS (https only). CORS origins
// legitimately include http for local dev; pass ALLOW_HTTP_ALL.
function _canonicalOrigin(input) {
  if (!input || typeof input !== "string") return null;
  try {
    var parsed = safeUrl.parse(input, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
    var proto  = parsed.protocol;          // "http:" or "https:"
    var host   = parsed.hostname.toLowerCase();
    var port   = parsed.port;              // "" when default
    return proto + "//" + host + (port ? ":" + port : "");
  } catch (_e) {
    return null;
  }
}

// Build the request's own origin from req when opts.siteOrigin isn't
// supplied. Works for direct deployments (no proxy); operators behind
// a TLS-terminating proxy that doesn't forward correct Host should set
// opts.siteOrigin explicitly.
function _inferRequestOrigin(req, trustProxy) {
  if (!req || !req.headers) return null;
  var host = req.headers.host;
  if (!host) return null;
  // Protocol resolution honors the operator's trustProxy opt — without
  // it, X-Forwarded-Proto is ignored as attacker-forgeable.
  var proto = requestHelpers.requestProtocol(req, { trustProxy: trustProxy });
  return _canonicalOrigin(proto + "://" + host);
}

function _isSameOrigin(req, originHeader, configuredSiteOrigins, trustProxy, strictNullOrigin) {
  // Origin: null arrives when a browser opaques the Origin (e.g.
  // Referrer-Policy: no-referrer on the page). Sec-Fetch-Site can
  // distinguish the same-origin case, but non-browser clients can forge
  // that header freely — strictNullOrigin: true (default) refuses the
  // shortcut so refuseUnknown holds against forged callers. Operators
  // with a legitimate no-referrer page flip strictNullOrigin: false.
  if (originHeader === "null") {
    if (strictNullOrigin) return false;
    var sfs = req && req.headers && req.headers["sec-fetch-site"];
    if (sfs === "same-origin" || sfs === "none") return true;
    return false;
  }
  var canonOrigin = _canonicalOrigin(originHeader);
  if (!canonOrigin) return false;
  // Operator-supplied site origins take priority — they're the
  // authoritative source for "this request is one of mine".
  if (configuredSiteOrigins && configuredSiteOrigins.length > 0) {
    for (var i = 0; i < configuredSiteOrigins.length; i++) {
      if (configuredSiteOrigins[i] === canonOrigin) return true;
    }
    return false;
  }
  // Fall back to inferring from the request itself. trustProxy threads
  // through so operators behind a TLS terminator with X-Forwarded-Proto
  // can opt in to consult the header.
  var reqOrigin = _inferRequestOrigin(req, trustProxy);
  return reqOrigin !== null && reqOrigin === canonOrigin;
}

function create(opts) {
  opts = opts || {};

  validateOpts(opts, [
    "origins", "siteOrigin", "methods", "headers", "exposeHeaders",
    "credentials", "maxAgeSeconds", "refuseUnknown", "trustProxy",
    "strictNullOrigin",
  ], "middleware.cors");
  var trustProxy = opts.trustProxy === true || typeof opts.trustProxy === "number"
    ? opts.trustProxy : false;
  var _xffIp = _xffIpFor(trustProxy);

  // Build a canonicalized allowList at create() time. String entries
  // get parsed through _canonicalOrigin so case + default-port
  // differences match consistently between the configured value and
  // the inbound Origin header. RegExp entries stay as the operator
  // wrote them.
  var rawOrigins = opts.origins || [];
  var origins = [];
  for (var oi = 0; oi < rawOrigins.length; oi++) {
    var entry = rawOrigins[oi];
    if (typeof entry === "string") {
      var canonEntry = _canonicalOrigin(entry);
      if (canonEntry === null) {
        throw new CorsError("cors/bad-origin",
          "origins[" + oi + "]='" + entry + "' is not a parseable http(s) URL");
      }
      origins.push({ kind: "string", canonical: canonEntry, original: entry });
    } else if (entry instanceof RegExp) {
      origins.push({ kind: "regex", pattern: entry });
    } else {
      throw new CorsError("cors/bad-origin",
        "origins[" + oi + "] must be a string or RegExp (got " + typeof entry + ")");
    }
  }

  // Throw at create() on bad opts.siteOrigin — must parse as http(s) URL.
  // Accept string OR array of strings.
  var siteOrigins = [];
  if (opts.siteOrigin !== undefined && opts.siteOrigin !== null) {
    var rawList = Array.isArray(opts.siteOrigin) ? opts.siteOrigin : [opts.siteOrigin];
    for (var si = 0; si < rawList.length; si++) {
      var raw = rawList[si];
      if (typeof raw !== "string" || raw.length === 0) {
        throw new CorsError("cors/bad-site-origin",
          "siteOrigin[" + si + "] must be a non-empty string (got " + typeof raw + ")");
      }
      var canon = _canonicalOrigin(raw);
      if (!canon) {
        throw new CorsError("cors/bad-site-origin",
          "siteOrigin[" + si + "]='" + raw + "' is not a parseable http(s) URL");
      }
      siteOrigins.push(canon);
    }
  }

  var methods = (opts.methods || ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]).join(", ");
  var headersList = (opts.headers || ["Content-Type", "Authorization", "X-Request-Id"]).slice();
  var headers = headersList.join(", ");
  // Pre-compute the lowercase allowlist once at create() time so the
  // preflight path doesn't re-derive it per-request from the joined
  // string. Avoids coupling allow-list validation to the wire-format
  // serialization.
  var allowedHeadersSet = headersList.map(function (h) { return String(h).trim().toLowerCase(); });
  var exposeHeaders = (opts.exposeHeaders || ["X-Request-Id"]).join(", ");
  var credentials = !!opts.credentials;
  var maxAge = String(opts.maxAgeSeconds || (C.TIME.minutes(10) / C.TIME.seconds(1)));
  var refuseUnknown = opts.refuseUnknown !== false;
  // strictNullOrigin defaults true: refuse Origin: null even with
  // Sec-Fetch-Site: same-origin (non-browser callers can forge that
  // header). Operators with a no-referrer page producing legitimate
  // Origin: null on same-origin POSTs flip to false explicitly.
  var strictNullOrigin = opts.strictNullOrigin !== false;

  return function cors(req, res, next) {
    var origin = req.headers && req.headers.origin;
    if (!origin) return next();   // not a cross-origin request

    // Same-origin POST/PUT/etc. carry an Origin header per the Fetch
    // spec but should not be subject to CORS allow-listing — they're
    // the operator's own site talking to itself.
    if (_isSameOrigin(req, origin, siteOrigins, trustProxy, strictNullOrigin)) return next();

    var matched = _matchOrigin(origin, origins);
    if (!matched) {
      if (refuseUnknown) {
        try {
          audit().emit({
            actor:    requestHelpers.extractActorContext(req, { ip: _xffIp(req) }),
            action:   "system.cors.block",
            outcome:  "denied",
            reason:   "origin not in allow-list",
            metadata: { origin: origin, method: req.method, path: req.pathname || req.url, requestId: req.requestId },
            requestId: req.requestId,
          });
        } catch (_e) { /* audit best-effort */ }
        if (typeof res.writeHead === "function") {
          res.writeHead(requestHelpers.HTTP_STATUS.FORBIDDEN, { "Content-Type": "text/plain" });
          res.end("CORS: origin not allowed");
          return;
        }
      }
      return next();   // permissive mode: just don't set CORS headers
    }

    if (typeof res.setHeader === "function") {
      res.setHeader("Access-Control-Allow-Origin", matched);
      // Append "Origin" to Vary instead of overwriting — compression /
      // auth helpers may have set their own Vary tokens that the cache
      // layer needs to keep.
      requestHelpers.appendVary(res, "Origin");
      if (credentials) res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Access-Control-Expose-Headers", exposeHeaders);
    }

    if (req.method === "OPTIONS" && req.headers["access-control-request-method"]) {
      // Preflight. In refuseUnknown mode, validate the requested
      // headers against the configured allow-list — refuse with 403
      // if the client asks for a header we don't allow. Spec says
      // browsers enforce, but server-side enforcement keeps the
      // framework's strict-by-default posture consistent.
      if (refuseUnknown) {
        var requestedHdrs = req.headers["access-control-request-headers"];
        if (requestedHdrs) {
          var asked = requestHelpers.parseListHeader(requestedHdrs, { lowercase: true });
          for (var ah = 0; ah < asked.length; ah++) {
            if (allowedHeadersSet.indexOf(asked[ah]) === -1) {
              if (typeof res.writeHead === "function") {
                res.writeHead(requestHelpers.HTTP_STATUS.FORBIDDEN, { "Content-Type": "text/plain" });
                res.end("CORS: requested header '" + asked[ah] + "' not in allow-list");
              }
              return;
            }
          }
        }
      }
      if (typeof res.setHeader === "function") {
        res.setHeader("Access-Control-Allow-Methods", methods);
        res.setHeader("Access-Control-Allow-Headers", headers);
        res.setHeader("Access-Control-Max-Age", maxAge);
      }
      if (typeof res.writeHead === "function") {
        res.writeHead(requestHelpers.HTTP_STATUS.NO_CONTENT);
        res.end();
      }
      return;
    }

    next();
  };
}

module.exports = {
  create:    create,
  CorsError: CorsError,
};
