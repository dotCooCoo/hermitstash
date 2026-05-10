"use strict";
/**
 * @module     b.middleware.clearSiteData
 * @nav        HTTP
 * @title      Clear-Site-Data
 * @order      120
 * @card       RFC 9527 Clear-Site-Data middleware — wipe browser-side
 *             state (cookies, storage, cache, executionContexts) when
 *             a session ends. Mount on logout/erase routes; the
 *             header tells the UA to drop everything before navigating
 *             away so the next request starts clean.
 *
 * @intro
 *   The framework's logout primitive should not just delete the
 *   server-side session — it should tell the user-agent to drop every
 *   browser-side trace too. RFC 9527 Clear-Site-Data is the header
 *   that does it: the UA sees the response and synchronously evicts
 *   the named state types BEFORE running any subsequent navigation
 *   code, so a stale tab doesn't leak post-logout requests carrying
 *   the previous user's cookies.
 *
 *   Common shape on a logout endpoint:
 *
 *     app.post("/logout", [
 *       b.middleware.requireAuth(),
 *       async function (req, res) {
 *         await req.session.destroy();
 *         b.middleware.clearSiteData()(req, res, function () {});
 *         res.redirect("/");
 *       },
 *     ]);
 *
 *   Or as drop-in middleware on every route under a path prefix:
 *
 *     app.use("/account/erase", b.middleware.clearSiteData());
 *
 *   Default types: `cookies`, `storage`, `cache`, `executionContexts`.
 *   Operators wanting a narrower wipe (e.g. only `cache`) pass
 *   `{ types: ["cache"] }`. Wildcard `"*"` is supported but discouraged
 *   — it tells the UA to wipe the whole origin including cross-tab
 *   service workers, which often surprises operators.
 */

var validateOpts = require("../validate-opts");

// RFC 9527 §3 — the canonical token set. `clientHints` was added in
// the 2024 revision; `executionContexts` reloads any documents the
// origin currently has open (closes XSS-style hijacked tabs).
var KNOWN_TYPES = {
  "cookies":            true,
  "storage":            true,
  "cache":              true,
  "executionContexts":  true,
  "clientHints":        true,
  "*":                  true,
};

var DEFAULT_TYPES = ["cookies", "storage", "cache", "executionContexts"];

/**
 * @primitive b.middleware.clearSiteData
 * @signature b.middleware.clearSiteData(req, res, next)
 * @since     0.8.53
 * @status    stable
 * @related   b.middleware.securityHeaders, b.session
 *
 * Builds middleware that emits an RFC 9527 Clear-Site-Data response
 * header. Mount on logout / account-erase / consent-revoke routes
 * so the user-agent wipes browser-side state synchronously before
 * the next navigation. Without this header, a logged-out tab can
 * still carry cookies and cached responses past the server-side
 * session destruction, leaking post-logout requests.
 *
 * @opts
 *   {
 *     types: Array<"cookies"|"storage"|"cache"|"executionContexts"|"clientHints"|"*">,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.post("/logout", [
 *     b.middleware.clearSiteData(),
 *     async function (req, res) {
 *       await req.session.destroy();
 *       res.redirect("/");
 *     },
 *   ]);
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["types"], "middleware.clearSiteData");
  var types = opts.types === undefined ? DEFAULT_TYPES : opts.types;
  if (!Array.isArray(types) || types.length === 0) {
    throw new TypeError("middleware.clearSiteData: opts.types must be a non-empty array");
  }
  for (var i = 0; i < types.length; i += 1) {
    var t = types[i];
    if (typeof t !== "string" || !KNOWN_TYPES[t]) {
      throw new TypeError(
        "middleware.clearSiteData: unknown type '" + t +
        "' (expected one of: " + Object.keys(KNOWN_TYPES).join(", ") + ")");
    }
  }
  // Header value is a comma-separated list of double-quoted tokens
  // per RFC 9527 §3 (Structured Field Value List of Strings). Build
  // once at construction time — runtime cost is one setHeader call.
  var headerValue = types.map(function (t) { return '"' + t + '"'; }).join(", ");

  return function clearSiteData(req, res, next) {
    if (typeof res.setHeader === "function") {
      res.setHeader("Clear-Site-Data", headerValue);
    }
    next();
  };
}

module.exports = {
  create:        create,
  KNOWN_TYPES:   Object.keys(KNOWN_TYPES),
  DEFAULT_TYPES: DEFAULT_TYPES,
};
