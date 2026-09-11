// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("../constants");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var safeAsync = require("../safe-async");
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

    if (onDeny) {
      try {
        var returned = safeAsync.containRejection(
          onDeny(req, res, { status: C.HTTP.STATUS.UNAUTHORIZED, reason: "no-authenticated-user", redirectTo: redirectTo }),
          null);
        if (res.writableEnded) return returned;
      } catch (_e) {
        if (res.writableEnded) return;
      }
    }

    var wantsJson = prefersJson(req);
    if (!wantsJson && redirectTo) {
      if (!res.writableEnded && typeof res.writeHead === "function") {
        res.writeHead(C.HTTP.STATUS.FOUND, { "Location": redirectTo, "Cache-Control": "no-store" });
        res.end();
      }
      return;
    }
    denyResponse(req, res, {
      problem:       problemMode,
      status:        requestHelpers.HTTP_STATUS.UNAUTHORIZED,
      info:          { status: C.HTTP.STATUS.UNAUTHORIZED, reason: "no-authenticated-user" },
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
