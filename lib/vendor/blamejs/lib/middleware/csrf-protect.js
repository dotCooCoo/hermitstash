// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("../constants");
var cookies = require("../cookies");
var lazyRequire = require("../lazy-require");
var pick = require("../pick");
var forms = require("../forms");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var audit = lazyRequire(function () { return require("../audit"); });

var DEFAULT_FIELD_NAME    = "_csrf";
var DEFAULT_HEADER_NAME   = "X-CSRF-Token";
var DEFAULT_METHODS       = Object.freeze(["POST", "PUT", "DELETE", "PATCH"]);
var _csrfGateSeq = 0;

var DEFAULT_COOKIE_NAME_SECURE   = "__Host-csrf";
var DEFAULT_COOKIE_NAME_INSECURE = "csrf";

function _parseCookieHeader(header) {
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
    if (pick.isPoisonedKey(k)) continue;
    if (seen.has(k)) continue;
    seen.add(k);
    var v = p.slice(eq + 1).trim();
    if (v.length >= 2 && v.charCodeAt(0) === 0x22 && v.charCodeAt(v.length - 1) === 0x22) {
      v = v.slice(1, -1);
    }
    pairs.push([k, v]);
  }
  return Object.assign(Object.create(null), Object.fromEntries(pairs));
}


function _checkOriginAllowed(req, allowedOrigins, isHttpsFn, requireOrigin) {
  var headers = req.headers || {};
  var origin = headers.origin;
  var referer = headers.referer;
  if (typeof origin !== "string" && typeof referer !== "string") {
    if (requireOrigin === true) {
      return "missing-origin-and-referer";
    }
    return null;
  }

  function _originOf(rawUrl) {
    try {
      var u = new URL(rawUrl);                                                   // allow:raw-new-url-parse-only — origin-shape inspection (NOT outbound). Intentionally tolerates file:// / data: which safeUrl.parse refuses.
      return u.origin;
    } catch (_e) { return null; }
  }

  var requestOrigin = _originOf((isHttpsFn && isHttpsFn(req) ? "https://" : "http://") +
                                (requestHelpers.requestHost(req) || ""));

  function _isAllowed(candidateOrigin) {
    if (!candidateOrigin) return false;
    if (requestOrigin !== null && candidateOrigin === requestOrigin) return true;
    if (Array.isArray(allowedOrigins)) {
      for (var i = 0; i < allowedOrigins.length; i += 1) {
        if (candidateOrigin === _originOf(allowedOrigins[i])) return true;
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
    info:          { status: C.HTTP.STATUS.FORBIDDEN, reason: reason },
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
 *     trustedProxies:         string|string[],  // CIDRs of your reverse proxies — peer-gates X-Forwarded-Proto for the Secure-cookie decision
 *     protocolResolver:       function(req): "http"|"https",  // own the HTTPS decision
 *     trustProxy:             boolean|number,    // legacy; refused unless paired with trustedProxies/protocolResolver (spoofable)
 *     audit:                  boolean,
 *     skipStateless:          boolean,   // default false — skip the token check for cookieless (not-CSRF-able) requests. Turns on the absence of the ambient credential only: an Authorization header is not part of the test, and it never waives `checkOrigin`.
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
    "trustProxy", "trustedProxies", "protocolResolver",
    "checkOrigin", "allowedOrigins", "requireJsonContentType",
    "requireOrigin", "skipStateless", "skipPaths", "skip", "onDeny", "problemDetails",
  ], "middleware.csrfProtect");
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;
  var _proto;
  try {
    _proto = requestHelpers.trustedProtocol({
      trustedProxies:   opts.trustedProxies,
      protocolResolver: opts.protocolResolver,
    });
  } catch (e) { throw new Error("middleware.csrfProtect: " + e.message); }
  if ((opts.trustProxy === true || typeof opts.trustProxy === "number") && !_proto.peerGated) {
    throw new Error("middleware.csrfProtect: trustProxy is spoofable for the Secure-cookie " +
      "decision — a direct caller could forge X-Forwarded-Proto. Declare your reverse proxies " +
      "via trustedProxies: [\"10.0.0.0/8\", …] or supply protocolResolver(req).");
  }
  function _isHttps(req) { return _proto.resolve(req) === "https"; }

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
  if (opts.methods !== undefined) {
    if (!Array.isArray(opts.methods) || opts.methods.length === 0 ||
        !opts.methods.every(function (m) { return typeof m === "string" && m.length > 0; })) {
      throw new Error("middleware.csrfProtect: opts.methods must be a non-empty array of HTTP method tokens (omit it for the POST/PUT/DELETE/PATCH default)");
    }
  }
  var methods    = (opts.methods || DEFAULT_METHODS).map(function (m) { return m.toUpperCase(); });
  var auditOn    = opts.audit !== false;
  var GATE_ID = "csrf:" + (_csrfGateSeq++);

  var checkOrigin = opts.checkOrigin !== false;
  var allowedOrigins = Array.isArray(opts.allowedOrigins)
    ? opts.allowedOrigins.slice() : null;

  var requireJsonCt = opts.requireJsonContentType === true;

  var requireOriginOpt = opts.requireOrigin === true;

  var skipStateless = opts.skipStateless === true;

  var _shouldSkip = requestHelpers.makeSkipMatcher(opts, "middleware.csrfProtect");

  var cookieCfg = null;
  if (hasCookie) {
    var raw = opts.cookie === true ? {} : opts.cookie;
    if (typeof raw !== "object") {
      throw new Error("middleware.csrfProtect: opts.cookie must be true or an object");
    }
    cookieCfg = {
      name:     raw.name || null,
      sameSite: raw.sameSite || "Lax",
      secure:   raw.secure,
      path:     raw.path     || "/",
      httpOnly: !!raw.httpOnly,
      maxAge:   raw.maxAge != null ? raw.maxAge : null,
    };
    if (["Lax", "Strict", "None"].indexOf(cookieCfg.sameSite) === -1) {
      throw new Error("middleware.csrfProtect: opts.cookie.sameSite must be Lax|Strict|None");
    }
    if (cookieCfg.name) {
      var lowerCookieName = cookieCfg.name.toLowerCase();
      var isHostPrefix   = lowerCookieName.indexOf("__host-") === 0;
      var isSecurePrefix = lowerCookieName.indexOf("__secure-") === 0;
      if (isHostPrefix && cookieCfg.path !== "/") {
        throw new Error("middleware.csrfProtect: __Host-* cookie name requires path='/'");
      }
      if (isHostPrefix && cookieCfg.secure === false) {
        throw new Error("middleware.csrfProtect: __Host-* cookie name requires secure (cannot be explicit false)");
      }
      if (isSecurePrefix && cookieCfg.secure === false) {
        throw new Error("middleware.csrfProtect: __Secure-* cookie name requires secure (cannot be explicit false)");
      }
      if ((isHostPrefix || isSecurePrefix) && cookieCfg.secure == null) {
        throw new Error("middleware.csrfProtect: " +
          (isHostPrefix ? "__Host-*" : "__Secure-*") +
          " cookie name requires an explicit cookie.secure: true — " +
          "auto-detected secure emits the prefix without Secure on a plain-HTTP " +
          "request, which browsers reject");
      }
    }
  }

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

  function _issueIfNeeded(req, res) {
    if (!cookieCfg) return null;
    var cookieName = _resolveCookieName(req);
    var requestCookies = _parseCookieHeader(req.headers && req.headers.cookie);
    var existing = requestCookies[cookieName];
    if (existing && /^[a-f0-9]{64}$/.test(existing)) {
      req.csrfToken = existing;
      return existing;
    }
    if (!req._csrfIssuedCookies) req._csrfIssuedCookies = Object.create(null);
    if (Object.prototype.hasOwnProperty.call(req._csrfIssuedCookies, cookieName)) {
      req.csrfToken = req._csrfIssuedCookies[cookieName];
      return req.csrfToken;
    }
    if (existing && !/^[a-f0-9]{64}$/.test(existing)) {
      try {
        audit().safeEmit({
          action: "csrf.bad_cookie_value",
          outcome: "denied",
          metadata: { cookieName: cookieName, length: existing.length },
        });
      } catch (_e) { /* drop-silent */ }
    }
    var fresh = forms.generateCsrfToken();
    var setCookie = cookies.serialize(cookieName, fresh, {
      path:     cookieCfg.path,
      sameSite: cookieCfg.sameSite,
      secure:   cookieCfg.secure == null ? _isHttps(req) : !!cookieCfg.secure,
      httpOnly: cookieCfg.httpOnly,
      maxAge:   cookieCfg.maxAge,
    });
    cookies.appendSetCookie(res, setCookie);
    req._csrfIssuedCookies[cookieName] = fresh;
    req.csrfToken = fresh;
    return fresh;
  }

  return function csrfProtect(req, res, next) {
    if (!req._csrfGates) req._csrfGates = Object.create(null);
    if (req._csrfGates[GATE_ID]) return next();
    req._csrfGates[GATE_ID] = true;

    var expected = _issueIfNeeded(req, res);

    if (_shouldSkip(req)) return next();

    if (methods.indexOf(req.method) === -1) return next();

    if (requireJsonCt) {
      var ct = req.headers && req.headers["content-type"];
      var bare = (typeof ct === "string" ? ct.split(";")[0].trim().toLowerCase() : "");
      if (bare !== "application/json") {
        _emitDenied(req, "non-JSON content-type: " + (bare || "<absent>"));
        return _writeReject(req, res, "CSRF: state-changing requests require Content-Type: application/json.", "content-type-required", onDeny, problemMode);
      }
    }

    if (checkOrigin) {
      var originReason = _checkOriginAllowed(req, allowedOrigins, _isHttps, requireOriginOpt);
      if (originReason !== null) {
        _emitDenied(req, "origin/referer: " + originReason);
        return _writeReject(req, res, "CSRF cross-origin request refused.", "cross-origin-refused", onDeny, problemMode);
      }
    }

    if (skipStateless && !(req.headers && req.headers.cookie)) return next();

    if (!cookieCfg) {
      expected = opts.tokenLookup(req);
    }
    if (!expected) {
      _emitDenied(req, cookieCfg ? "no token cookie issued yet" : "no expected token in session");
      return _writeReject(req, res, "CSRF token mismatch.", "token-mismatch", onDeny, problemMode);
    }

    var submitted = req.headers && req.headers[headerName];
    if (typeof submitted !== "string" || submitted.length === 0) {
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
