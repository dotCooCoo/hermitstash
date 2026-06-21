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
var denyResponse = require("./deny-response").denyResponse;
var { defineClass } = require("../framework-error");

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
function _inferRequestOrigin(req, protoResolve) {
  if (!req || !req.headers) return null;
  var host = req.headers.host;
  if (!host) return null;
  // Peer-gated protocol resolution — X-Forwarded-Proto is honored only from a
  // trusted proxy (else the TLS socket), so a direct caller can't forge the
  // inferred origin's scheme to slip past the same-origin check.
  var proto = protoResolve(req);
  return _canonicalOrigin(proto + "://" + host);
}

function _isSameOrigin(req, originHeader, configuredSiteOrigins, protoResolve, strictNullOrigin) {
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
  // Fall back to inferring from the request itself. The peer-gated protocol
  // resolver threads through so operators behind a TLS terminator consult
  // X-Forwarded-Proto only from a trusted peer.
  var reqOrigin = _inferRequestOrigin(req, protoResolve);
  return reqOrigin !== null && reqOrigin === canonOrigin;
}

/**
 * @primitive b.middleware.cors
 * @signature b.middleware.cors(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.csrfProtect, b.middleware.fetchMetadata
 *
 * Cross-Origin Resource Sharing handler. Constructed via
 * `b.middleware.cors(opts)`; the resulting middleware has the
 * `(req, res, next)` shape shown above. Allowlist matches strings
 * (canonicalized) and RegExp entries. Handles preflights,
 * `Access-Control-Allow-*` response headers, and
 * `strictNullOrigin: true` (default) refuses `Origin: null` even
 * with `Sec-Fetch-Site: same-origin` since non-browser callers can
 * forge that header. `siteOrigin` declares the framework's own
 * origin(s) for same-origin shortcuts. Throws at create() on
 * unparseable origin entries — operators catch typos at boot.
 *
 * @opts
 *   {
 *     origins:          Array<string|RegExp>,
 *     siteOrigin:       string|string[],
 *     methods:          string[],   // default GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS
 *     headers:          string[],   // default Content-Type,Authorization,X-Request-Id
 *     exposeHeaders:    string[],   // default X-Request-Id
 *     credentials:      boolean,
 *     maxAgeSeconds:    number,     // default 600
 *     refuseUnknown:    boolean,    // default true
 *     strictNullOrigin: boolean,    // default true
 *     trustedProxies:   string|string[],  // CIDRs of your reverse proxies — peer-gates X-Forwarded-Proto for same-origin inference
 *     protocolResolver: function(req): "http"|"https",  // own the HTTPS decision
 *     clientIpResolver: function(req): string|null,     // own the audit-actor IP
 *     trustProxy:       boolean|number,    // legacy; refused unless paired with trustedProxies/resolver (spoofable)
 *     onDeny:           function(req, res, info): void,  // own every refusal; info = { status, reason, origin, header? }
 *     problemDetails:   boolean,    // default false — emit RFC 9457 application/problem+json instead of text/plain
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.cors({
 *     origins:    ["https://app.example.com", /\.example\.com$/],
 *     siteOrigin: "https://example.com",
 *     methods:    ["GET", "POST"],
 *   }));
 */
function create(opts) {
  opts = opts || {};

  validateOpts(opts, [
    "origins", "siteOrigin", "methods", "headers", "exposeHeaders",
    "credentials", "maxAgeSeconds", "refuseUnknown", "trustProxy",
    "trustedProxies", "clientIpResolver", "protocolResolver",
    "strictNullOrigin", "allowPrivateNetwork", "onDeny", "problemDetails",
  ], "middleware.cors");
  // The request scheme feeds the same-origin determination, and a bare
  // trustProxy trusts a forgeable X-Forwarded-Proto from any caller. Peer-gate
  // both protocol and the audit-actor IP via trustedProxies (CIDRs) or own them
  // via protocolResolver / clientIpResolver. A bare trustProxy is refused.
  var _proto, _ip;
  try {
    _proto = requestHelpers.trustedProtocol({ trustedProxies: opts.trustedProxies, protocolResolver: opts.protocolResolver });
    _ip    = requestHelpers.trustedClientIp({ trustedProxies: opts.trustedProxies, clientIpResolver: opts.clientIpResolver });
  } catch (e) { throw new CorsError("cors/bad-opt", e.message); }
  if ((opts.trustProxy === true || typeof opts.trustProxy === "number") && !_proto.peerGated) {
    throw new CorsError("cors/bad-opt",
      "trustProxy is spoofable — a direct caller could forge X-Forwarded-Proto to alter the " +
      "same-origin decision. Declare your reverse proxies via trustedProxies: [\"10.0.0.0/8\", …] " +
      "or supply protocolResolver(req) / clientIpResolver(req).");
  }
  var _xffIp = _ip.resolve;

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
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;

  function _refuse(req, res, reason, body, ext) {
    denyResponse(req, res, {
      onDeny:        onDeny,
      problem:       problemMode,
      status:        requestHelpers.HTTP_STATUS.FORBIDDEN,
      info:          Object.assign({ status: 403, reason: reason }, ext || {}),
      problemCode:   "cors-refused",
      problemTitle:  "Forbidden",
      problemDetail: body,
      contentType:   "text/plain",
      body:          body,
    });
  }

  return function cors(req, res, next) {
    var origin = req.headers && req.headers.origin;
    if (!origin) return next();   // not a cross-origin request

    // Same-origin POST/PUT/etc. carry an Origin header per the Fetch
    // spec but should not be subject to CORS allow-listing — they're
    // the operator's own site talking to itself.
    if (_isSameOrigin(req, origin, siteOrigins, _proto.resolve, strictNullOrigin)) return next();

    var matched = _matchOrigin(origin, origins);
    if (!matched) {
      // Always append Vary: Origin when the request carried an Origin
      // header — otherwise downstream caches that previously cached a
      // matched-origin response (with ACAO + Vary: Origin set) may
      // serve the wrong cached entry to this unmatched-origin
      // request, OR cache the no-CORS response and replay it for a
      // future matched-origin request. Cheap; matches Fetch-spec
      // discipline.
      if (typeof res.setHeader === "function") {
        try { requestHelpers.appendVary(res, "Origin"); } catch (_e) { /* best-effort */ }
      }
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
        if (typeof res.writeHead === "function" || onDeny) {
          _refuse(req, res, "origin-not-allowed", "CORS: origin not allowed", { origin: origin });
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
              _refuse(req, res, "requested-header-not-allowed",
                "CORS: requested header '" + asked[ah] + "' not in allow-list",
                { origin: origin, header: asked[ah] });
              return;
            }
          }
        }
      }
      // Private Network Access (PNA) preflight — Chrome's W3C draft
      // sends `Access-Control-Request-Private-Network: true` when a
      // public-internet page tries to fetch a private/local resource
      // (RFC 1918 / loopback). Servers MUST acknowledge with
      // `Access-Control-Allow-Private-Network: true` to permit. The
      // framework refuses by default — operators with a deliberate
      // public-to-private flow opt in via `allowPrivateNetwork: true`
      // (audited reason) at create-time.
      var pnaRequested = req.headers["access-control-request-private-network"];
      if (pnaRequested === "true") {
        if (opts.allowPrivateNetwork === true) {
          if (typeof res.setHeader === "function") {
            res.setHeader("Access-Control-Allow-Private-Network", "true");
          }
        } else {
          _refuse(req, res, "private-network-not-permitted",
            "CORS: Private Network Access not permitted (set allowPrivateNetwork:true with audited reason to opt in)",
            { origin: origin });
          return;
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
