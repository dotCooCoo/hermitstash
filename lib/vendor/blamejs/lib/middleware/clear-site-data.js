// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
/**
 * @primitive b.middleware.clearSiteData.headerValue
 * @signature b.middleware.clearSiteData.headerValue(types, label?)
 * @since      0.15.9
 * @status     stable
 * @related    b.middleware.clearSiteData, b.session.logout
 *
 * Build the RFC 9527 §3 Clear-Site-Data header value from a list of directive
 * types — a comma-separated list of double-quoted tokens — validating each
 * against the known set (`cookies`, `storage`, `cache`, `executionContexts`).
 * The middleware factory and `b.session.logout` both compose it so every
 * emitter produces the same validated header instead of hand-rolling the
 * quoting. Throws a `TypeError` on an unknown directive or a non-array input
 * (config-time / entry-point tier).
 *
 * @example
 *   b.middleware.clearSiteData.headerValue(["cookies", "storage"]);
 *   // → '"cookies", "storage"'
 */
function headerValue(types, label) {
  label = label || "middleware.clearSiteData";
  if (!Array.isArray(types) || types.length === 0) {
    throw new TypeError(label + ": types must be a non-empty array");
  }
  for (var i = 0; i < types.length; i += 1) {
    var t = types[i];
    // hasOwnProperty, not `KNOWN_TYPES[t]`: a bracket lookup on the plain-object
    // allowlist resolves inherited members ("toString" / "constructor" /
    // "hasOwnProperty") to truthy functions, so those would pass validation and
    // be emitted as bogus Clear-Site-Data directives (prototype shadowing).
    if (typeof t !== "string" || !Object.prototype.hasOwnProperty.call(KNOWN_TYPES, t)) {
      throw new TypeError(
        label + ": unknown type '" + t +
        "' (expected one of: " + Object.keys(KNOWN_TYPES).join(", ") + ")");
    }
  }
  return types.map(function (t) { return '"' + t + '"'; }).join(", ");
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["types"], "middleware.clearSiteData");
  var types = opts.types === undefined ? DEFAULT_TYPES : opts.types;
  // Header value built once at construction; runtime cost is one setHeader.
  var headerVal = headerValue(types, "middleware.clearSiteData");

  return function clearSiteData(req, res, next) {
    if (typeof res.setHeader === "function") {
      res.setHeader("Clear-Site-Data", headerVal);
    }
    next();
  };
}

module.exports = {
  create:        create,
  // The shared RFC 9527 header-value builder — b.session.logout composes it so
  // the logout path emits the same validated Clear-Site-Data header.
  headerValue:   headerValue,
  KNOWN_TYPES:   Object.keys(KNOWN_TYPES),
  DEFAULT_TYPES: DEFAULT_TYPES,
};
