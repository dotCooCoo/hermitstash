// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.middleware.noCache
 * @nav        Middleware
 * @title      Cache-Control: no-store
 * @order      410
 *
 * @intro
 *   RFC 9111 §5.2.2.5 `Cache-Control: no-store` middleware for paths
 *   that serve operator-individualized content (account pages,
 *   transactional pages, API responses with PII, auth-gated routes).
 *   Sets `Cache-Control: no-store` + `Pragma: no-cache` (HTTP/1.0
 *   compatibility) + `Vary: Cookie, Authorization` so intermediate
 *   caches don't store a personalized response keyed by URL alone.
 *
 *   Per the 2026-05-11 audit's web-browser hardening gap: many
 *   primitives (`b.middleware.requireAuth` etc.) already set
 *   no-store on the 401 refuse path, but operator routes serving
 *   AUTHENTICATED content lacked a centralized no-store middleware.
 *   This is it.
 *
 *   Compose with `b.middleware.requireAuth` for the standard
 *   auth-gated shape:
 *
 *     app.use("/account", b.middleware.requireAuth());
 *     app.use("/account", b.middleware.noCache());
 *
 *   Or use the predicate form to apply only when the route matches
 *   an operator-supplied test:
 *
 *     app.use(b.middleware.noCache({
 *       when: function (req) {
 *         return req.url.indexOf("/api/private/") === 0;
 *       },
 *     }));
 *
 * @card
 *   RFC 9111 §5.2.2.5 Cache-Control: no-store middleware for auth-gated / individualized response paths — sets no-store + Pragma + Vary headers so intermediate caches don't store personalized responses keyed by URL alone.
 */

var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var NoCacheError = defineClass("NoCacheError", { alwaysPermanent: true });

var DEFAULT_VARY = "Cookie, Authorization";

/**
 * @primitive b.middleware.noCache
 * @signature b.middleware.noCache(opts?)
 * @since     0.8.86
 * @status    stable
 *
 * Build the no-cache middleware. With no opts, applies to every
 * request: sets `Cache-Control: no-store`, `Pragma: no-cache`,
 * `Vary: Cookie, Authorization`. Pass `opts.when(req)` for a
 * conditional path predicate.
 *
 * @opts
 *   when:    function (req) → boolean,   // optional — only set headers when truthy
 *   cacheControl: string,                 // override "no-store" (e.g. "no-store, private")
 *   vary:    string,                      // override the Vary header (default "Cookie, Authorization")
 *   skipExisting: boolean,                // default false — when true, skip when Cache-Control is already set
 *
 * @example
 *   app.use("/account", b.middleware.requireAuth(), b.middleware.noCache());
 *
 *   // Conditional — only for the API subtree
 *   app.use(b.middleware.noCache({
 *     when: function (req) { return req.url.indexOf("/api/private/") === 0; },
 *   }));
 */
function create(opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Array.isArray(opts)) {
    throw new NoCacheError("no-cache/bad-opts",
      "middleware.noCache: opts must be an object when provided", true);
  }
  validateOpts.optionalFunction(
    opts.when, "noCache.when", NoCacheError, "no-cache/bad-when");
  validateOpts.optionalNonEmptyString(
    opts.cacheControl, "noCache.cacheControl", NoCacheError, "no-cache/bad-cache-control");
  validateOpts.optionalNonEmptyString(
    opts.vary, "noCache.vary", NoCacheError, "no-cache/bad-vary");

  var cacheControl = opts.cacheControl || "no-store";
  var vary         = opts.vary || DEFAULT_VARY;
  var skipExisting = opts.skipExisting === true;
  var when         = opts.when;

  return function noCacheMiddleware(req, res, next) {
    if (when && !when(req)) return next();
    if (skipExisting && typeof res.getHeader === "function" && res.getHeader("Cache-Control")) {
      return next();
    }
    res.setHeader("Cache-Control", cacheControl);
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Vary", vary);
    next();
  };
}

module.exports = create;
module.exports.create        = create;
module.exports.NoCacheError  = NoCacheError;
module.exports.DEFAULT_VARY  = DEFAULT_VARY;
