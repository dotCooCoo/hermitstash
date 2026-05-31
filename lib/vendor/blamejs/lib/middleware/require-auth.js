"use strict";
/**
 * require-auth middleware — gates routes that require an authenticated
 * user. Mount AFTER attachUser; this middleware reads `req.user` and
 * either lets the request through or rejects it.
 *
 * Rejection shape:
 *   - JSON-preferring caller (Accept includes application/json, or
 *     X-Requested-With: XMLHttpRequest):
 *     401 application/json with { error: "Authentication required." }
 *   - Browser-preferring caller, when opts.redirectTo is set:
 *     302 with Location header
 *   - Otherwise:
 *     401 text/plain
 *
 * Note: the Content-Type of the REQUEST is intentionally NOT a signal.
 * A server-to-server POST with `Content-Type: application/json` and no
 * `Accept` header should get the same response shape as any other
 * unauthenticated request — Content-Type describes what the client
 * SENT, not what they want back. Operators with a non-default
 * preference contract supply opts.prefersJson.
 *
 * Always emits `auth.required.denied` audit event on rejection (when
 * opts.audit !== false). The event records request method + path +
 * client IP — keys-only, no body content.
 *
 * Options:
 *   {
 *     redirectTo:    null         (optional URL for browser redirects;
 *                                   when set, prefersJson()=false rejections
 *                                   produce 302 instead of 401 text/plain)
 *     prefersJson:   function     (optional override; defaults to checking
 *                                   Accept / X-Requested-With — NOT
 *                                   Content-Type, see the note above)
 *     errorMessage:  'Authentication required.'
 *     audit:         true         (emit auth.required.denied on reject)
 *   }
 */
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var audit = lazyRequire(function () { return require("../audit"); });

function _defaultPrefersJson(req) {
  var h = req.headers || {};
  if (typeof h.accept === "string" && h.accept.indexOf("application/json") !== -1) return true;
  if (h["x-requested-with"] === "XMLHttpRequest") return true;
  return false;
}

/**
 * @primitive b.middleware.requireAuth
 * @signature b.middleware.requireAuth(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.attachUser, b.middleware.bearerAuth, b.middleware.requireAal
 *
 * Gates routes that require an authenticated user. Constructed via
 * `b.middleware.requireAuth(opts)`; the resulting middleware has
 * the `(req, res, next)` shape shown above. Mount AFTER
 * `attachUser`; this middleware reads `req.user` and either passes
 * the request or rejects. JSON-preferring callers (Accept includes
 * `application/json` or `X-Requested-With: XMLHttpRequest`) get 401
 * `application/json`; browser-preferring with `redirectTo` get 302
 * Location; otherwise 401 `text/plain`. The REQUEST Content-Type
 * is intentionally NOT a signal — what the client SENT is not
 * what they want BACK. Always emits `auth.required.denied` audit
 * (method + path + client IP, no body content).
 *
 * @opts
 *   {
 *     redirectTo:   string,                            // 302 location for browser
 *     prefersJson:  function(req): boolean,
 *     errorMessage: string,                            // default "Authentication required."
 *     audit:        boolean,                           // default true
 *     onDeny:       function(req, res, info): void,    // own any refusal shape; info = { status, reason, redirectTo }
 *     problemDetails: boolean,                         // default false — emit RFC 9457 application/problem+json for the 401 (redirect path unaffected)
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.attachUser({ userLoader: async function () { return { id: 1 }; } }));
 *   app.use(b.middleware.requireAuth({ redirectTo: "/login" }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "redirectTo", "prefersJson", "errorMessage", "audit", "onDeny", "problemDetails",
  ], "middleware.requireAuth");
  var redirectTo  = opts.redirectTo  || null;
  var prefersJson = typeof opts.prefersJson === "function"
    ? opts.prefersJson
    : _defaultPrefersJson;
  var msg     = opts.errorMessage || "Authentication required.";
  var auditOn = opts.audit !== false;
  var onDeny  = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;

  return function requireAuth(req, res, next) {
    if (req.user) return next();

    if (auditOn) {
      try {
        audit().emit({
          action:   "auth.required.denied",
          outcome:  "denied",
          actor:    requestHelpers.extractActorContext(req),
          reason:   "no authenticated user on request",
          metadata: { method: req.method, path: req.pathname || (req.url || "").split("?")[0] },
        });
      } catch (_e) { /* audit best-effort */ }
    }

    // Operator hook owns ANY refusal shape (json / redirect / text)
    // before the default content-negotiation runs.
    if (onDeny) {
      try {
        var returned = onDeny(req, res, { status: 401, reason: "no-authenticated-user", redirectTo: redirectTo });
        if (res.writableEnded) return returned;
      } catch (_e) {
        if (res.writableEnded) return;
        // fall through to default
      }
    }

    // RFC 9111 §5.2.2.5 — auth-gated paths SHOULD emit
    // Cache-Control: no-store so a shared cache (or browser
    // back-button cache) can't replay a 401 / redirect / payload
    // intended for an unauthenticated context to a different user.
    // Pre-v0.8.70 the framework's auth middlewares emitted no
    // cache directive, leaving the operator to set it themselves;
    // forgetting it under a CDN that respects Cache-Control was
    // a routine misconfiguration.
    var wantsJson = prefersJson(req);
    if (!wantsJson && redirectTo) {
      if (!res.writableEnded && typeof res.writeHead === "function") {
        // 302 Found — RFC 7231 §6.4.3. Not in HTTP_STATUS table.
        res.writeHead(302, { "Location": redirectTo, "Cache-Control": "no-store" });
        res.end();
      }
      return;
    }
    denyResponse(req, res, {
      problem:       problemMode,
      status:        requestHelpers.HTTP_STATUS.UNAUTHORIZED,
      info:          { status: 401, reason: "no-authenticated-user" },
      problemCode:   "authentication-required",
      problemTitle:  "Unauthorized",
      problemDetail: msg,
      headers:       { "Cache-Control": "no-store" },
      contentType:   wantsJson ? "application/json" : "text/plain",
      body:          wantsJson ? JSON.stringify({ error: msg }) : msg,
    });
  };
}

module.exports = {
  create:               create,
  _defaultPrefersJson:  _defaultPrefersJson,
};
