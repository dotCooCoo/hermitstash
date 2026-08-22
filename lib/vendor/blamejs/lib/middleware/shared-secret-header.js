// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * shared-secret-header middleware — a named header carrying a shared secret,
 * compared in constant time.
 *
 * This is the third common way a request authenticates itself. The other two
 * already have primitives: `Authorization: Bearer` is `b.middleware.bearerAuth`,
 * and a signed webhook is `b.webhookHmac` / `b.webhook.verify`. A named custom
 * header holding a fixed secret is what internal service-to-service calls,
 * cron triggers and platform bridges use, and hand-rolling it puts four
 * conditions in one expression that have to be in the right order:
 *
 *   - the LENGTH check comes first, because `b.crypto.timingSafeEqual` throws
 *     on a length mismatch rather than returning false. A compare that runs
 *     first turns a wrong-length header into a 500.
 *   - an UNCONFIGURED secret refuses. A deployment that forgot the environment
 *     variable is otherwise wide open, and looks configured.
 *   - the compare does not short-circuit, which is the whole reason
 *     timingSafeEqual is there and the thing a `===` "optimisation" removes.
 *   - an AVAILABILITY failure is not an authentication failure. A secret
 *     resolver that throws still denies — fail closed — but answers 503, so an
 *     operator sees a dependency outage rather than a flood of bad
 *     credentials, and a caller holding the right secret is not told it is
 *     wrong.
 *
 * Every refusal is byte-identical, so the gate cannot be used as an oracle for
 * which condition failed.
 */

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

// RFC 9110 §5.6.2 tchar: "!#$%&'*+-.^_`|~", DIGIT, ALPHA. Everything else is a
// delimiter or a control and cannot appear in a field name. Index of the first
// offending character, or -1.
var _TCHAR_SPECIALS = "!#$%&'*+-.^_`|~";
// How many times `lowerName` appears on the wire. node's IncomingMessage JOINS
// duplicate custom headers into one comma-separated string rather than exposing
// an array (only a documented few, like set-cookie, become arrays), so an
// Array.isArray() check never fires for a custom header — and `rawHeaders` is
// the only place the duplication is still visible.
//
// Returns -1 when the request does not expose rawHeaders at all (a non-node
// request object, or a framework that rebuilds the request), so the caller can
// tell "no duplicates" from "cannot tell" instead of reading the second as the
// first.
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
  // A field name is an RFC 9110 §5.1 token. A name carrying a space, a colon or
  // any other delimiter can never match an incoming header, so the gate would
  // refuse every request forever — and those 401s are indistinguishable from a
  // caller presenting the wrong secret. That is a configuration typo, so it
  // belongs at boot where the operator sees it, not at request time where it
  // looks like an attack.
  if (_firstNonTokenChar(headerName) !== -1) {
    throw _err("auth-shared-secret/bad-header-name",
      "middleware.sharedSecretHeader: opts.headerName must be an RFC 9110 token " +
      "(no spaces, colons or delimiters); got " + JSON.stringify(headerName));
  }
  // Node lowercases incoming header names; normalise once at construction so
  // an operator can configure it in any case.
  var headerKey = headerName.toLowerCase();

  // A secret that is neither a string nor a resolver is a configuration
  // mistake, and belongs at boot rather than as a per-request surprise. An
  // ABSENT secret is deliberately NOT refused here: that is the deployment
  // that forgot its environment variable, and it must fail closed at request
  // time rather than stop the process from starting, so the operator sees
  // 401s and an audit trail rather than a boot loop.
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

  // One refusal writer for every deny path. The status varies (401 vs 503)
  // because those are different facts about the world, but the BODY does not:
  // a caller must not be able to tell an absent header from a wrong value.
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

    // A repeated header is refused, whichever way the runtime represents it.
    // node JOINS duplicate custom headers into one comma-separated string
    // rather than an array, so checking Array.isArray alone would never fire
    // on a real request — and a secret that happened to equal the joined value
    // ("alpha, beta" against header lines `alpha` and `beta`) would
    // authenticate a request in which NO single header carried the secret.
    // Verified against node directly: two lines arrive as "alpha, beta" with
    // both occurrences visible only in rawHeaders.
    //
    // Refused before the secret is resolved: the request is malformed whatever
    // the configuration is, and there is no reason to call an operator's
    // resolver for it.
    if (Array.isArray(presented) || _rawHeaderCount(req, headerKey) > 1) {
      _emit(req, "auth.shared_secret.failure", "header-repeated");
      return _refuse(req, res, C.HTTP.STATUS.UNAUTHORIZED, "unauthorized");
    }

    // Absence is decided BEFORE the secret is resolved. `opts.secret` may be a
    // resolver backed by a secrets manager, and awaiting it first let an
    // unauthenticated client drive that dependency once per request — traffic
    // and latency it never had to earn, and an outage it could amplify — while
    // presenting no credential at all.
    //
    // The verdict is unchanged; only its cost is. During a resolver outage a
    // request with no header now answers 401 rather than 503, which is the more
    // accurate of the two: the caller brought no credential, so the
    // dependency's health is not what decided it.
    if (typeof presented !== "string" || presented.length === 0) {
      _emit(req, "auth.shared_secret.failure", "header-absent");
      return _refuse(req, res, C.HTTP.STATUS.UNAUTHORIZED, "unauthorized");
    }

    var want;
    if (typeof opts.secret === "function") {
      try {
        want = await opts.secret(req);
      } catch (e) {
        // The secret could not be FETCHED. Not an auth failure — the caller
        // may hold the right value and there is no way to know. Deny, but say
        // so honestly.
        //
        // Contained, including the lazy module load: a broken metrics registry
        // must not throw past this point, because the throw would escape the
        // handler and the router would answer 500. Telemetry does not get to
        // decide the response — least of all on the path whose whole purpose
        // is to fail closed with an honest 503.
        try {
          observability().safeEvent("auth.shared_secret.unavailable", 1, { header: headerKey });
        } catch (_o) { /* drop-silent — see above */ }
        _emit(req, "auth.shared_secret.unavailable", "secret-resolver-failed: " + ((e && e.message) || String(e)));
        return _refuse(req, res, C.HTTP.STATUS.SERVICE_UNAVAILABLE, "unavailable");
      }
    } else {
      want = opts.secret;
    }

    // A resolver that hands back something that is NOT a secret — a Buffer
    // from a secrets-manager SDK, a number, a parsed JSON envelope — is a bug
    // in the resolver, not a deployment that forgot to configure one. Both
    // deny, but reporting this as 401 tells the operator their CALLERS are
    // wrong and buries the real cause under a wall of credential failures. It
    // is the same fact as a resolver that threw: no usable secret was
    // obtained, so it takes the same 503.
    if (want !== undefined && want !== null && typeof want !== "string") {
      try {
        observability().safeEvent("auth.shared_secret.unavailable", 1, { header: headerKey });
      } catch (_o) { /* drop-silent — telemetry never decides the response */ }
      _emit(req, "auth.shared_secret.unavailable",
        "secret-resolver-returned-" + (Buffer.isBuffer(want) ? "buffer" : typeof want));
      return _refuse(req, res, C.HTTP.STATUS.SERVICE_UNAVAILABLE, "unavailable");
    }

    // Unconfigured refuses. FIRST, before anything about the request, so a
    // deployment missing its secret cannot be talked into accepting by any
    // header at all.
    if (typeof want !== "string" || want.length === 0) {
      _emit(req, "auth.shared_secret.failure", "secret-not-configured");
      return _refuse(req, res, C.HTTP.STATUS.UNAUTHORIZED, "unauthorized");
    }


    var got = safeBuffer.toBuffer(presented, { encoding: "utf8" });
    var expected = safeBuffer.toBuffer(want, { encoding: "utf8" });
    // Length BEFORE the compare: timingSafeEqual throws on a length mismatch
    // rather than returning false, so a compare-first ordering turns a
    // wrong-length header into a 500. The length of a secret is not itself a
    // secret, so answering early here leaks nothing the header size did not.
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
