"use strict";
/**
 * Shared deny-path response writer for the request-lifecycle
 * middlewares that refuse a request (401 / 403 / 405 / 415 / 429 /
 * 451 / misdirected-request). Every deny-path middleware routes its
 * refusal through `denyResponse` so a consumer gets one uniform way
 * to shape it, instead of each middleware hardcoding its own body +
 * Content-Type.
 *
 * Three resolution modes, checked in order:
 *
 *   1. `onDeny(req, res, info)` operator hook — when supplied, the
 *      consumer owns the response. `info` carries the machine
 *      `status` / `reason` plus the middleware-specific fields. The
 *      hook is wrapped so a throw is audited (via `ctx.onThrow`) and
 *      then falls through to the default write rather than crashing
 *      the request that triggered the refusal. A hook that returns
 *      without writing also falls through — the response can never
 *      hang on a no-op hook.
 *
 *   2. `problem: true` — emit RFC 9457 `application/problem+json` by
 *      composing `b.problemDetails`. The middleware supplies the
 *      `type` / `title` / `detail` and any extension members; the
 *      deny-path response headers (`Allow` / `WWW-Authenticate` /
 *      `Retry-After` / `Accept`) are merged onto the problem
 *      response so content negotiation does not drop them.
 *
 *   3. Default — the middleware's existing body + Content-Type. No
 *      behavior change when neither knob is set.
 *
 * This is an internal helper (no public `b.*` surface); the consumer
 * contract is the `onDeny` / `problemDetails` opts documented on each
 * middleware that composes it.
 */

var problemDetails = require("../problem-details");

function _isFn(x) { return typeof x === "function"; }

function _mergeInto(target, extra) {
  if (!extra || typeof extra !== "object") return target;
  var keys = Object.keys(extra);
  for (var i = 0; i < keys.length; i += 1) {
    target[keys[i]] = extra[keys[i]];
  }
  return target;
}

/**
 * Resolve a deny-path refusal through the uniform hook / problem+json
 * / default chain. Returns whatever the `onDeny` hook returns when it
 * owns the response, otherwise `undefined`.
 *
 * ctx fields:
 *   onDeny:        function (req, res, info) | null  — operator hook
 *   problem:       boolean   — emit application/problem+json
 *   status:        number    — HTTP status (100..599)
 *   info:          object    — passed verbatim to onDeny; also seeds
 *                              the problem document (status / reason)
 *   problemType:   string?   — RFC 9457 `type` (URI reference); when
 *                              absent, built from `problemCode`
 *   problemCode:   string?   — type-URI suffix; resolves to
 *                              `<problemDetails base>/<code>` (the same
 *                              `<base>/<code>` convention as fromError)
 *   problemTitle:  string?   — RFC 9457 `title`
 *   problemDetail: string?   — RFC 9457 `detail`
 *   problemExt:    object?   — extra problem members (reserved names
 *                              dropped); siblings per RFC 9457 §3.2
 *   headers:       object?   — extra response headers (Allow /
 *                              WWW-Authenticate / Retry-After / Accept
 *                              / Cache-Control)
 *   contentType:   string    — default-mode Content-Type
 *   body:          string|Buffer — default-mode body
 *   onThrow:       function (err) ? — audit sink when onDeny throws
 */
function denyResponse(req, res, ctx) {
  var info = (ctx.info && typeof ctx.info === "object") ? ctx.info : {};

  if (_isFn(ctx.onDeny)) {
    try {
      var returned = ctx.onDeny(req, res, info);
      if (res.writableEnded) return returned;
      // Hook ran but did not write — fall through to the default so
      // the response can never hang on a no-op hook.
    } catch (e) {
      if (_isFn(ctx.onThrow)) {
        try { ctx.onThrow(e); } catch (_e) { /* drop-silent */ }
      }
      if (res.writableEnded) return undefined;
      // Hook threw before writing — fall through to the default.
    }
  }

  if (res.writableEnded || !_isFn(res.writeHead)) return undefined;

  var extra = (ctx.headers && typeof ctx.headers === "object") ? ctx.headers : null;

  if (ctx.problem) {
    var fields = { status: ctx.status };
    if (ctx.problemType)   fields.type   = ctx.problemType;
    if (ctx.problemTitle)  fields.title  = ctx.problemTitle;
    if (ctx.problemDetail) fields.detail = ctx.problemDetail;
    if (ctx.problemExt && typeof ctx.problemExt === "object") {
      var ek = Object.keys(ctx.problemExt);
      for (var i = 0; i < ek.length; i += 1) {
        if (problemDetails.RESERVED_FIELDS.indexOf(ek[i]) === -1) {
          fields[ek[i]] = ctx.problemExt[ek[i]];
        }
      }
    }
    var problem;
    try {
      problem = problemDetails.create(fields);
    } catch (_e) {
      // A bad extension shape (prototype-pollution key, out-of-range
      // status) must not turn a refusal into a 500 — degrade to the
      // bare status document.
      problem = problemDetails.create({ status: ctx.status });
    }
    // Set the deny-path headers before respond() so content
    // negotiation does not lose Allow / WWW-Authenticate / Retry-After.
    if (extra) {
      var hk = Object.keys(extra);
      for (var h = 0; h < hk.length; h += 1) {
        res.setHeader(hk[h], extra[hk[h]]);
      }
    }
    problemDetails.respond(res, problem);
    return undefined;
  }

  var head = _mergeInto({ "Content-Type": ctx.contentType }, extra);
  res.writeHead(ctx.status, head);
  res.end((ctx.body === undefined || ctx.body === null) ? "" : ctx.body);
  return undefined;
}

module.exports = {
  denyResponse: denyResponse,
};
