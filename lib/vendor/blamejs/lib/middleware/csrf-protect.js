"use strict";
/**
 * csrf-protect — middleware that issues CSRF tokens to safe-method
 * requests AND rejects state-changing requests whose submitted token
 * doesn't match.
 *
 * Mount AFTER attachUser (when using session-stored tokens) and AFTER
 * bodyParser (when reading the token from a form field). Safe methods
 * (GET / HEAD / OPTIONS) pass through; the gate fires on POST / PUT /
 * DELETE / PATCH (configurable via opts.methods).
 *
 * Token storage — pick ONE:
 *
 *   A. Cookie-stored ("double-submit cookie", default)
 *      opts.cookie = true | { name, sameSite, secure, path, httpOnly }
 *
 *      The middleware reads the token from the configured cookie. On
 *      safe-method requests with no token cookie, it generates one and
 *      sets the cookie on the response. The same value is exposed on
 *      `req.csrfToken` for templates to render into a hidden form field.
 *      State-changing requests verify the submitted token matches the
 *      cookie value. SameSite=Lax (default) blocks cross-site form
 *      POSTs from carrying the cookie.
 *
 *      httpOnly defaults to FALSE — JavaScript needs to read it for AJAX
 *      requests. Operators relying solely on server-rendered forms can
 *      flip it to true.
 *
 *   B. Operator-supplied tokenLookup (session-stored, etc.)
 *      opts.tokenLookup = (req) => string|null
 *
 *      The middleware calls tokenLookup(req) to fetch the expected
 *      token. Use this when CSRF tokens live in your session store
 *      (e.g. req.session.data.csrfToken). Issuance + req.csrfToken
 *      exposure are the operator's responsibility in this mode.
 *
 * If neither is supplied, the middleware throws at create() —
 * config-time validation, no silent passthrough.
 *
 * Submitted-token sources tried in order on state-changing requests:
 *   1. Header `X-CSRF-Token` (or opts.headerName)
 *   2. Body field `_csrf` (or opts.fieldName) — requires bodyParser
 *      mounted before csrfProtect
 *
 * On mismatch:
 *   - Audit emit (auth.csrf.denied) with method + path + IP + reason
 *   - 403 application/json: { error: "CSRF token mismatch." }
 *   - next() NOT called
 *
 * Full options:
 *   {
 *     cookie:      true | {                  EITHER this...
 *       name:      auto: "__Host-csrf" over HTTPS, "csrf" over HTTP.
 *                  Operators with a custom name override here; the framework
 *                  validates that __Host-* names carry path="/" and Secure.
 *       sameSite:  "Lax" | "Strict" | "None",
 *       secure:    auto-detected from request scheme,
 *       path:      "/",
 *       httpOnly:  false,
 *     },
 *     tokenLookup: (req) => string|null      ...OR this
 *
 *     fieldName:   "_csrf"                   form-body field name
 *     headerName:  "X-CSRF-Token"            header name
 *     methods:     ["POST", "PUT", "DELETE", "PATCH"]
 *     audit:        true
 *   }
 */
var lazyRequire = require("../lazy-require");
var forms = require("../forms");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var audit = lazyRequire(function () { return require("../audit"); });

var DEFAULT_FIELD_NAME    = "_csrf";
var DEFAULT_HEADER_NAME   = "X-CSRF-Token";
var DEFAULT_METHODS       = Object.freeze(["POST", "PUT", "DELETE", "PATCH"]);

// Default cookie name uses the RFC 6265bis __Host- prefix when the request
// is over HTTPS. The prefix forces browsers to refuse the cookie unless
// it carries Secure + Path=/ + no Domain attribute — closing the
// "malicious sibling subdomain sets a cookie on the parent domain to
// subvert double-submit verification" attack class. On plain HTTP (dev),
// browsers reject __Host- entirely, so we fall back to the bare name.
var DEFAULT_COOKIE_NAME_SECURE   = "__Host-csrf";
var DEFAULT_COOKIE_NAME_INSECURE = "csrf";

function _parseCookieHeader(header) {
  // Minimal cookie-header parser — RFC 6265 §5.2 form. Ignores attributes,
  // just splits the name=value pairs. Keys that appear multiple times
  // resolve to the FIRST occurrence (browsers send pairs left-to-right
  // by registration order; the first is the most-specific path).
  // Collect [name, value] pairs, then materialize the cookie map via
  // Object.fromEntries onto a null-prototype object. The cookie name is
  // attacker-controlled (Cookie request header), so it is never used as a
  // computed-write key (`out[name] = value` / `seen[name] = true`) — that
  // is the CWE-915 unsafe-reflection / CWE-1321 prototype-pollution sink.
  // First-occurrence-wins de-duplication tracks names in a Set (add/has
  // are method calls, not tainted-key property writes); POISONED names
  // (`__proto__` / `constructor` / `prototype`) are dropped; and the
  // null-prototype accumulator means even a slipped name cannot reach
  // Object.prototype.
  if (typeof header !== "string" || header.length === 0) return Object.create(null);
  var parts = header.split(/;\s*/);
  var seen = new Set();
  var pairs = [];
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i];
    var eq = p.indexOf("=");
    if (eq === -1) continue;
    var k = p.slice(0, eq).trim();
    if (k.length === 0) continue;
    if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
    if (seen.has(k)) continue;  // first-occurrence wins
    seen.add(k);
    var v = p.slice(eq + 1).trim();
    if (v.length >= 2 && v.charCodeAt(0) === 0x22 && v.charCodeAt(v.length - 1) === 0x22) {
      v = v.slice(1, -1);
    }
    pairs.push([k, v]);
  }
  return Object.assign(Object.create(null), Object.fromEntries(pairs));
}

// `_isHttps` defers to `requestHelpers.requestProtocol` so the
// per-middleware `trustProxy` opt gates whether X-Forwarded-Proto is
// consulted. Without trustProxy, an attacker could otherwise forge
// the header to force the Secure cookie attribute (and inversely,
// suppress it) on direct-to-server connections.
function _isHttpsFor(trustProxy) {
  return function (req) {
    return requestHelpers.requestProtocol(req, { trustProxy: trustProxy }) === "https";
  };
}

function _formatSetCookie(name, value, opts) {
  var parts = [name + "=" + value];
  parts.push("Path=" + (opts.path || "/"));
  parts.push("SameSite=" + (opts.sameSite || "Lax"));
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure)   parts.push("Secure");
  if (opts.maxAge != null) parts.push("Max-Age=" + opts.maxAge);
  return parts.join("; ");
}

function _appendSetCookie(res, value) {
  // Don't clobber other Set-Cookie headers the route may have already
  // queued (login session cookie, etc.). Use res.appendHeader when
  // available; else array-merge manually.
  if (typeof res.appendHeader === "function") {
    res.appendHeader("Set-Cookie", value);
    return;
  }
  var existing = typeof res.getHeader === "function" ? res.getHeader("Set-Cookie") : undefined;
  if (existing == null) {
    res.setHeader("Set-Cookie", value);
  } else if (Array.isArray(existing)) {
    res.setHeader("Set-Cookie", existing.concat(value));
  } else {
    res.setHeader("Set-Cookie", [existing, value]);
  }
}

// csrf-protect does NOT buffer or parse the request body itself.
// Operators who use form-urlencoded POSTs MUST register
// `b.middleware.bodyParser()` before csrf-protect so that
// `req.body[fieldName]` is populated. Header-token submissions
// (X-CSRF-Token) work without bodyParser. The body-parser primitive
// owns size caps, content-type dispatch, and prototype-pollution
// defense; csrf-protect just reads the validated value.

// Origin / Referer cross-check helper. Returns null when the request's
// origin is acceptable, or a short reason string ("origin-mismatch" /
// "referer-mismatch" / "no-origin-or-referer" / "malformed-url") when
// it should be refused. Compares against opts.allowedOrigins (when
// supplied) OR same-origin (the request's own Host header).
//
// Implementation note — we deliberately don't run safeUrl here; safeUrl
// throws on file:// / data:// schemes which would crash the middleware
// instead of refusing the request. URL constructor + try/catch is the
// right shape for "is this URL well-formed and what's its origin?".
function _checkOriginAllowed(req, allowedOrigins, isHttpsFn, requireOrigin) {
  var headers = req.headers || {};
  var origin = headers.origin;
  var referer = headers.referer;
  if (typeof origin !== "string" && typeof referer !== "string") {
    // No Origin/Referer at all — common for non-browser clients
    // (curl, server-to-server). The token check still applies; this
    // gate doesn't add to it. Defense-in-depth against a stolen
    // cookie via a browser-rendered cross-origin fetch IS the value;
    // headless clients carry their own auth threat model.
    if (requireOrigin === true) {
      return { allowed: false, reason: "missing-origin-and-referer" };
    }
    return null;
  }

  var requestOrigin = (isHttpsFn && isHttpsFn(req) ? "https://" : "http://") +
                      (headers.host || "");

  function _originOf(rawUrl) {
    try {
      var u = new URL(rawUrl);                                                   // allow:raw-new-url — origin-shape inspection (NOT outbound). Intentionally tolerates file:// / data: which safeUrl.parse refuses.
      return u.origin;                                                           // "https://host:port" — no path / query / fragment
    } catch (_e) { return null; }
  }

  function _isAllowed(candidateOrigin) {
    if (!candidateOrigin) return false;
    if (candidateOrigin === requestOrigin) return true;
    if (Array.isArray(allowedOrigins)) {
      for (var i = 0; i < allowedOrigins.length; i += 1) {
        if (candidateOrigin === allowedOrigins[i]) return true;
      }
    }
    return false;
  }

  if (typeof origin === "string" && origin.length > 0) {
    var oo = _originOf(origin);
    if (oo === null) return "malformed-origin";
    if (!_isAllowed(oo)) return "origin-mismatch (" + oo + " vs " + requestOrigin + ")";
    return null;
  }
  // Origin absent — fall back to Referer.
  var ro = _originOf(referer);
  if (ro === null) return "malformed-referer";
  if (!_isAllowed(ro)) return "referer-mismatch (" + ro + " vs " + requestOrigin + ")";
  return null;
}

function _writeReject(req, res, message, reason, onDeny, problemMode) {
  denyResponse(req, res, {
    onDeny:        onDeny,
    problem:       problemMode,
    status:        requestHelpers.HTTP_STATUS.FORBIDDEN,
    info:          { status: 403, reason: reason },
    problemCode:   "csrf-refused",
    problemTitle:  "Forbidden",
    problemDetail: message,
    contentType:   "application/json; charset=utf-8",
    body:          JSON.stringify({ error: message }),
  });
}

/**
 * @primitive b.middleware.csrfProtect
 * @signature b.middleware.csrfProtect(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.cors, b.middleware.fetchMetadata
 *
 * Issues CSRF tokens to safe-method requests and rejects state-
 * changing requests whose submitted token doesn't match. Constructed
 * via `b.middleware.csrfProtect(opts)`; the resulting middleware
 * has the `(req, res, next)` shape shown above. Two
 * storage modes (mutually exclusive, exactly one required):
 * (a) cookie-stored double-submit (default — `__Host-csrf` over
 * HTTPS, SameSite=Lax) where the framework issues + reads the
 * cookie; (b) operator-supplied `tokenLookup(req)` for session-
 * stored tokens. Submitted-token sources: header (default
 * `X-CSRF-Token`) then body field (default `_csrf`). Refuses with
 * HTTP 403 + audits `auth.csrf.denied` on mismatch. Mount AFTER
 * `attachUser` (session lookup) and `bodyParser` (form-field read).
 *
 * @opts
 *   {
 *     cookie:                 boolean | { name, sameSite, secure, path, httpOnly },
 *     tokenLookup:            function(req): string|null,
 *     fieldName:              string,    // default "_csrf"
 *     headerName:             string,    // default "X-CSRF-Token"
 *     methods:                string[],  // default POST/PUT/DELETE/PATCH
 *     checkOrigin:            boolean,
 *     allowedOrigins:         string[],
 *     requireOrigin:          boolean,
 *     requireJsonContentType: boolean,
 *     trustProxy:             boolean|number,
 *     audit:                  boolean,
 *     skipStateless:          boolean,   // default false — skip validation for Authorization-header / cookieless (not-CSRF-able) requests
 *     onDeny:                 function(req, res, info): void,  // own the 403; info = { status, reason }
 *     problemDetails:         boolean,   // default false — emit RFC 9457 application/problem+json instead of the default JSON envelope
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.csrfProtect({
 *     cookie:        true,
 *     checkOrigin:   true,
 *     requireOrigin: true,
 *   }));
 */
function create(opts) {
  opts = opts || {};

  validateOpts(opts, [
    "cookie", "tokenLookup", "fieldName", "headerName", "methods", "audit",
    "trustProxy", "checkOrigin", "allowedOrigins", "requireJsonContentType",
    "requireOrigin", "skipStateless", "onDeny", "problemDetails",
  ], "middleware.csrfProtect");
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;
  var trustProxy = opts.trustProxy === true || typeof opts.trustProxy === "number"
    ? opts.trustProxy : false;
  var _isHttps = _isHttpsFor(trustProxy);

  // Throw at create() — exactly one issuance source allowed.
  var hasCookie = opts.cookie != null && opts.cookie !== false;
  var hasLookup = typeof opts.tokenLookup === "function";
  if (hasCookie && hasLookup) {
    throw new Error("middleware.csrfProtect: opts.cookie and opts.tokenLookup are " +
      "mutually exclusive — pick one (cookie = double-submit, tokenLookup = session-stored)");
  }
  if (!hasCookie && !hasLookup) {
    throw new Error("middleware.csrfProtect: opts.cookie or opts.tokenLookup is required");
  }

  var fieldName  = opts.fieldName  || DEFAULT_FIELD_NAME;
  var headerName = (opts.headerName || DEFAULT_HEADER_NAME).toLowerCase();
  var methods    = (opts.methods || DEFAULT_METHODS).map(function (m) { return m.toUpperCase(); });
  var auditOn    = opts.audit !== false;

  // Origin / Referer cross-check — second-line defense alongside the
  // double-submit token. If the request's Origin (or Referer when
  // Origin is absent — Safari pre-12, certain CORS mode requests)
  // doesn't resolve to a same-origin or operator-allowlisted origin,
  // refuse before the token check.
  //
  // Default: enabled (defense-in-depth — same shape as bot-guard /
  // rate-limit / CSP nonce — every default ON).
  // Operator opt-out: opts.checkOrigin = false.
  // Operator allowlist: opts.allowedOrigins = ["https://app.example.com"].
  var checkOrigin = opts.checkOrigin !== false;
  var allowedOrigins = Array.isArray(opts.allowedOrigins)
    ? opts.allowedOrigins.slice() : null;

  // requireJsonContentType — strict-fetch mode for JSON-only API
  // surfaces. State-changing requests without `Content-Type:
  // application/json` are refused before the token check. The browser's
  // form-encoded POST shape is the canonical CSRF vector — a malicious
  // page can <form action="/transfer" method=POST> a victim into a
  // state-changing request without a preflight; an `application/json`
  // body forces a CORS preflight (the browser refuses to skip it for
  // non-simple Content-Type values), so an attacker without an
  // operator-allowlisted CORS origin can't reach the route at all.
  // Operators with HTML form submissions on the same routes (mixed
  // SPA + classic form pages) leave this opt-out (default).
  var requireJsonCt = opts.requireJsonContentType === true;

  // requireOrigin — when true, refuse state-changing requests that
  // carry NO Origin/Referer at all. Default false (back-compat for
  // server-to-server / curl callers). Operators on a browser-only
  // route mount the middleware with `requireOrigin: true` so the
  // documented "no headers = bypass for non-browser" pass-through
  // is opt-in rather than silent.
  var requireOriginOpt = opts.requireOrigin === true;

  // skipStateless — skip token VALIDATION for requests that carry an
  // Authorization header (bearer / token auth) or no Cookie header at
  // all. Such requests are not CSRF-able: CSRF abuses a victim's ambient
  // cookie credential, and a token-authenticated or cookieless request
  // has none to abuse. The token is still ISSUED on safe methods so a
  // later cookie-authenticated browser flow on the same app works. Default
  // false (strict — every state-changing request is validated). createApp
  // wires its default csrf with this on so mixed browser-form + token-API
  // surfaces don't reject legitimate API clients. Cross-site form CSRF is
  // unaffected: the browser auto-sends the victim's cookies, so the attack
  // request always carries a Cookie header and is validated.
  var skipStateless = opts.skipStateless === true;

  // Cookie issuance config (only when opts.cookie is set).
  var cookieCfg = null;
  if (hasCookie) {
    var raw = opts.cookie === true ? {} : opts.cookie;
    if (typeof raw !== "object") {
      throw new Error("middleware.csrfProtect: opts.cookie must be true or an object");
    }
    cookieCfg = {
      // name: explicit operator override wins; otherwise auto-resolved
      // per-request based on whether the cookie is being issued Secure.
      name:     raw.name || null,
      sameSite: raw.sameSite || "Lax",
      // secure: undefined means auto-detect from request scheme; explicit
      // true/false overrides.
      secure:   raw.secure,
      path:     raw.path     || "/",
      httpOnly: !!raw.httpOnly,
      maxAge:   raw.maxAge != null ? raw.maxAge : null,
    };
    if (["Lax", "Strict", "None"].indexOf(cookieCfg.sameSite) === -1) {
      throw new Error("middleware.csrfProtect: opts.cookie.sameSite must be Lax|Strict|None");
    }
    // __Host- prefix safety: if operator picks a __Host- name, the
    // Path/Domain/Secure constraints must be compatible. Path must be "/",
    // no Domain (we never set one), Secure resolved per-request. Catch
    // operator-side typos (e.g. __Host-csrf with a custom path) at boot.
    if (cookieCfg.name && /^__Host-/.test(cookieCfg.name)) {
      if (cookieCfg.path !== "/") {
        throw new Error("middleware.csrfProtect: __Host-* cookie name requires path='/'");
      }
      if (cookieCfg.secure === false) {
        throw new Error("middleware.csrfProtect: __Host-* cookie name requires secure (cannot be explicit false)");
      }
    }
  }

  // Resolve the cookie name for a specific request — operator override
  // wins; otherwise __Host-csrf when the cookie will be Secure, plain
  // csrf when over HTTP (browsers reject __Host- without Secure).
  function _resolveCookieName(req) {
    if (cookieCfg.name) return cookieCfg.name;
    var willBeSecure = cookieCfg.secure == null ? _isHttps(req) : !!cookieCfg.secure;
    return willBeSecure ? DEFAULT_COOKIE_NAME_SECURE : DEFAULT_COOKIE_NAME_INSECURE;
  }

  function _emitDenied(req, reason) {
    if (!auditOn) return;
    audit().safeEmit({
      action:   "auth.csrf.denied",
      outcome:  "denied",
      actor:    requestHelpers.extractActorContext(req),
      reason:   reason,
      metadata: { method: req.method, path: (req.url || "").split("?")[0] },
    });
  }

  // Issuance path (cookie mode): on safe-method requests with no cookie,
  // generate a token and queue it for the response. Always populate
  // req.csrfToken so templates have something to render.
  function _issueIfNeeded(req, res) {
    if (!cookieCfg) return null;
    var cookieName = _resolveCookieName(req);
    var cookies = _parseCookieHeader(req.headers && req.headers.cookie);
    var existing = cookies[cookieName];
    // Strict 64-hex-char check matches the byte-length of every token
    // forms.generateCsrfToken() produces (CSRF_TOKEN_BYTES = 32 bytes
    // → 64 hex chars). The previous {2,} floor accepted any 2-char
    // hex string a sibling-subdomain XSS could plant on plain HTTP
    // (cookie name falls back to `csrf` when the request isn't HTTPS,
    // so the `__Host-` prefix safety doesn't apply). Attacker plants
    // `csrf=ab` then submits matching X-CSRF-Token to bypass the
    // double-submit gate.
    if (existing && /^[a-f0-9]{64}$/.test(existing)) {
      req.csrfToken = existing;
      return existing;
    }
    if (existing && !/^[a-f0-9]{64}$/.test(existing)) {
      // Audit-emit so operators see when a planted/short cookie is
      // refused — surfaces the attack class in compliance logs.
      try {
        audit().safeEmit({
          action: "csrf.bad_cookie_value",
          outcome: "denied",
          metadata: { cookieName: cookieName, length: existing.length },
        });
      } catch (_e) { /* drop-silent */ }
    }
    var fresh = forms.generateCsrfToken();
    var setCookie = _formatSetCookie(cookieName, fresh, {
      path:     cookieCfg.path,
      sameSite: cookieCfg.sameSite,
      secure:   cookieCfg.secure == null ? _isHttps(req) : !!cookieCfg.secure,
      httpOnly: cookieCfg.httpOnly,
      maxAge:   cookieCfg.maxAge,
    });
    _appendSetCookie(res, setCookie);
    req.csrfToken = fresh;
    return fresh;
  }

  return function csrfProtect(req, res, next) {
    // Idempotent: a second csrf mount this request (e.g. createApp wired
    // it AND an operator mounted it again) is a no-op — the first instance
    // already issued + validated.
    if (req._csrfApplied) return next();
    req._csrfApplied = true;

    // Issue/refresh the token on EVERY request (safe + state-changing)
    // when running in cookie mode — templates rendered after a POST
    // (e.g. error response) still need req.csrfToken populated.
    var expected = _issueIfNeeded(req, res);

    if (methods.indexOf(req.method) === -1) return next();

    // Stateless / token-authenticated requests are not CSRF-able — the
    // token was still issued above for any later browser flow.
    if (skipStateless) {
      var hasAuthHeader = !!(req.headers && req.headers.authorization);
      var hasCookieHeader = !!(req.headers && req.headers.cookie);
      if (hasAuthHeader || !hasCookieHeader) return next();
    }

    // requireJsonContentType — refuse before the token check.
    if (requireJsonCt) {
      var ct = req.headers && req.headers["content-type"];
      var bare = (typeof ct === "string" ? ct.split(";")[0].trim().toLowerCase() : "");
      if (bare !== "application/json") {
        _emitDenied(req, "non-JSON content-type: " + (bare || "<absent>"));
        return _writeReject(req, res, "CSRF: state-changing requests require Content-Type: application/json.", "content-type-required", onDeny, problemMode);
      }
    }

    // Origin / Referer cross-check (defense-in-depth alongside the
    // double-submit token). Refuses cross-origin state-changing
    // requests even when the token is valid (e.g. operator-mistaken
    // CORS configuration that exposes the cookie).
    if (checkOrigin) {
      var originReason = _checkOriginAllowed(req, allowedOrigins, _isHttps, requireOriginOpt);
      if (originReason !== null) {
        _emitDenied(req, "origin/referer: " + originReason);
        return _writeReject(req, res, "CSRF cross-origin request refused.", "cross-origin-refused", onDeny, problemMode);
      }
    }

    if (!cookieCfg) {
      // Session-stored mode — operator's tokenLookup is the source.
      expected = opts.tokenLookup(req);
    }
    if (!expected) {
      _emitDenied(req, cookieCfg ? "no token cookie issued yet" : "no expected token in session");
      return _writeReject(req, res, "CSRF token mismatch.", "token-mismatch", onDeny, problemMode);
    }

    // Header path first — covers JSON / AJAX / multipart cases.
    var submitted = req.headers && req.headers[headerName];
    if (typeof submitted !== "string" || submitted.length === 0) {
      // Fall back to body field if bodyParser already populated req.body.
      // Operators with form-urlencoded POSTs are expected to register
      // bodyParser before csrf-protect; body buffering / parsing lives
      // in bodyParser, not here.
      if (req.body && typeof req.body === "object") {
        var v = req.body[fieldName];
        if (typeof v === "string") submitted = v;
      }
    }

    if (!forms.verifyCsrfToken(submitted || "", expected)) {
      _emitDenied(req, "submitted token does not match expected");
      return _writeReject(req, res, "CSRF token mismatch.", "token-mismatch", onDeny, problemMode);
    }

    return next();
  };
}

module.exports = { create: create };
