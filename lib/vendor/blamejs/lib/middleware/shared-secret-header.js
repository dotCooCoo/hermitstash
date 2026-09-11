// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var codepointClass = require("../codepoint-class");
var bCrypto = require("../crypto");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var safeBuffer = require("../safe-buffer");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var { AuthError } = require("../framework-error");

var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });

var _err = AuthError.factory;

var _TCHAR_SPECIALS = "!#$%&'*+-.^_`|~";
function _rawHeaderCount(req, lowerName) {
  var raw = req && req.rawHeaders;
  if (!Array.isArray(raw)) return -1;
  var n = 0;
  for (var i = 0; i + 1 < raw.length; i += 2) {
    if (String(raw[i]).toLowerCase() === lowerName) n += 1;
  }
  return n;
}

function _firstNonTokenChar(s) {
  for (var i = 0; i < s.length; i += 1) {
    var cc = s.charCodeAt(i);
    if (codepointClass.isAsciiAlnum(cc)) continue;
    if (_TCHAR_SPECIALS.indexOf(s.charAt(i)) !== -1) continue;
    return i;
  }
  return -1;
}

/**
 * @primitive b.middleware.sharedSecretHeader
 * @signature b.middleware.sharedSecretHeader(req, res, next)
 * @since     0.18.44
 * @status    stable
 * @related   b.middleware.bearerAuth, b.webhookHmac, b.crypto.timingSafeEqual
 *
 * Require a named header to carry a shared secret, compared in constant time.
 * The shape internal service-to-service calls, cron triggers and platform
 * bridges use, alongside `bearerAuth` for `Authorization: Bearer` and
 * `b.webhookHmac` for a signed webhook. Constructed via
 * `b.middleware.sharedSecretHeader(opts)`; the resulting middleware has the
 * `(req, res, next)` shape shown above.
 *
 * `secret` is either the value itself or a function returning it — the
 * resolver form covers a secrets manager or a rotating value, and may be
 * async. Whichever form, an absent or empty secret REFUSES every request. That
 * is the documented default rather than a flag, because the alternative is a
 * deployment that forgot its environment variable, accepts everything, and
 * looks configured.
 *
 * A resolver that THROWS is treated differently from one that returns nothing.
 * Returning nothing means unconfigured, which is an authentication failure —
 * 401. Throwing means the secret could not be fetched, which is not: the
 * caller may well hold the right value and the framework cannot tell. That
 * still denies, but with 503, so the log shows a dependency outage instead of
 * credential failures and a monitor does not page the wrong team.
 *
 * A resolver that returns something which is not a secret — a `Buffer` from a
 * secrets-manager SDK, a number, a parsed JSON envelope — takes the same 503,
 * for the same reason: no usable secret was obtained. Reporting that as 401
 * would tell the operator their callers are wrong and bury a bug in their own
 * resolver under a wall of credential failures.
 *
 * `headerName` must be an RFC 9110 §5.1 token, and a name carrying a space, a
 * colon or any other delimiter is refused at construction. Such a name can
 * never match an incoming header, so the gate would refuse every request
 * forever — and those refusals are indistinguishable from a caller presenting
 * the wrong secret, which is the worst place for a typo to surface.
 *
 * Every refusal — absent header, wrong length, wrong value, repeated header,
 * unconfigured secret — produces the same status and body, so the gate is not
 * an oracle for which of them it was.
 *
 * The repeated-header refusal reads `req.rawHeaders`, because Node joins
 * duplicate custom headers into one comma-separated string rather than an
 * array: without it, a secret equal to the joined value would authenticate a
 * request in which no single header carried it. That reaches as far as this
 * process can see. A reverse proxy that MERGES duplicates before Node receives
 * them leaves one header on the wire and nothing to detect — if the deployment
 * relies on this refusal, configure the proxy to reject duplicate occurrences
 * of the header rather than fold them.
 *
 * @opts
 *   headerName:     string,     // required — an RFC 9110 token, e.g. "x-internal-secret"
 *   secret:         string | function,   // value, or () => value (may be async)
 *   audit:          boolean,    // default true — emit auth.shared_secret.* rows
 *   errorMessage:   string,     // default "Unauthorized"
 *   onDeny:         function,   // custom refusal writer
 *   problemDetails: boolean,    // RFC 9457 application/problem+json refusals
 *
 * @example
 *   router.use("/internal", b.middleware.sharedSecretHeader({
 *     headerName: "x-internal-secret",
 *     secret:     process.env.INTERNAL_SECRET,
 *   }));
 *   // → a request without the exact secret never reaches the route
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "headerName", "secret", "audit", "errorMessage", "onDeny", "problemDetails",
  ], "middleware.sharedSecretHeader");

  var headerName = opts.headerName;
  if (typeof headerName !== "string" || headerName.length === 0) {
    throw _err("auth-shared-secret/bad-header-name",
      "middleware.sharedSecretHeader: opts.headerName must be a non-empty string");
  }
  if (_firstNonTokenChar(headerName) !== -1) {
    throw _err("auth-shared-secret/bad-header-name",
      "middleware.sharedSecretHeader: opts.headerName must be an RFC 9110 token " +
      "(no spaces, colons or delimiters); got " + JSON.stringify(headerName));
  }
  var headerKey = headerName.toLowerCase();

  if (opts.secret !== undefined && opts.secret !== null &&
      typeof opts.secret !== "string" && typeof opts.secret !== "function") {
    throw _err("auth-shared-secret/bad-secret",
      "middleware.sharedSecretHeader: opts.secret must be a string or a function " +
      "returning one; got " + typeof opts.secret);
  }

  var auditOn = opts.audit !== false;
  var errorMessage = typeof opts.errorMessage === "string" ? opts.errorMessage : "Unauthorized";
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;

  function _emit(req, action, reason) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   action,
        outcome:  "denied",
        reason:   reason,
        actor:    requestHelpers.extractActorContext(req),
        metadata: { header: headerKey, method: req.method, path: requestHelpers.resolveRoute(req) },
      });
    } catch (_e) { /* drop-silent — an audit failure must not decide the request */ }
  }

  function _refuse(req, res, status, reason) {
    if (res.writableEnded) return;
    denyResponse(req, res, {
      onDeny:        onDeny,
      problem:       problemMode,
      status:        status,
      info:          { status: status, reason: reason },
      problemCode:   "shared-secret-" + reason,
      problemTitle:  status === C.HTTP.STATUS.SERVICE_UNAVAILABLE ? "Service Unavailable" : "Unauthorized",
      problemDetail: errorMessage,
      contentType:   "text/plain; charset=utf-8",
      body:          errorMessage,
    });
  }

  return async function sharedSecretHeader(req, res, next) {
    var headers = req.headers || {};
    var presented = headers[headerKey];

    if (Array.isArray(presented) || _rawHeaderCount(req, headerKey) > 1) {
      _emit(req, "auth.shared_secret.failure", "header-repeated");
      return _refuse(req, res, C.HTTP.STATUS.UNAUTHORIZED, "unauthorized");
    }

    if (typeof presented !== "string" || presented.length === 0) {
      _emit(req, "auth.shared_secret.failure", "header-absent");
      return _refuse(req, res, C.HTTP.STATUS.UNAUTHORIZED, "unauthorized");
    }

    var want;
    if (typeof opts.secret === "function") {
      try {
        want = await opts.secret(req);
      } catch (e) {
        try {
          observability().safeEvent("auth.shared_secret.unavailable", 1, { header: headerKey });
        } catch (_o) { /* drop-silent — see above */ }
        _emit(req, "auth.shared_secret.unavailable", "secret-resolver-failed: " + ((e && e.message) || String(e)));
        return _refuse(req, res, C.HTTP.STATUS.SERVICE_UNAVAILABLE, "unavailable");
      }
    } else {
      want = opts.secret;
    }

    if (want !== undefined && want !== null && typeof want !== "string") {
      try {
        observability().safeEvent("auth.shared_secret.unavailable", 1, { header: headerKey });
      } catch (_o) { /* drop-silent — telemetry never decides the response */ }
      _emit(req, "auth.shared_secret.unavailable",
        "secret-resolver-returned-" + (Buffer.isBuffer(want) ? "buffer" : typeof want));
      return _refuse(req, res, C.HTTP.STATUS.SERVICE_UNAVAILABLE, "unavailable");
    }

    if (typeof want !== "string" || want.length === 0) {
      _emit(req, "auth.shared_secret.failure", "secret-not-configured");
      return _refuse(req, res, C.HTTP.STATUS.UNAUTHORIZED, "unauthorized");
    }


    var got = safeBuffer.toBuffer(presented, { encoding: "utf8" });
    var expected = safeBuffer.toBuffer(want, { encoding: "utf8" });
    if (got.length !== expected.length || !bCrypto.timingSafeEqual(got, expected)) {
      _emit(req, "auth.shared_secret.failure", "mismatch");
      return _refuse(req, res, C.HTTP.STATUS.UNAUTHORIZED, "unauthorized");
    }

    if (auditOn) {
      try {
        audit().safeEmit({
          action:   "auth.shared_secret.success",
          outcome:  "success",
          actor:    requestHelpers.extractActorContext(req),
          metadata: { header: headerKey, method: req.method, path: requestHelpers.resolveRoute(req) },
        });
      } catch (_e) { /* drop-silent */ }
    }
    return next();
  };
}

module.exports = { create: create };
