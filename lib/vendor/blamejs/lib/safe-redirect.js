// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module b.safeRedirect
 * @nav    Validation
 * @title  Safe Redirect
 * @slug   safe-redirect
 *
 * @intro
 *   Decide where a <code>Location</code> header may point when the target
 *   came from the request. An open redirect is a phishing primitive: an
 *   attacker sends a victim to a link on the real site and the site forwards
 *   them to one it does not control, carrying the trust of the first domain.
 *
 *   A target is answered unchanged only when it stays on this site, or names
 *   an origin or host the caller listed. Everything else answers the
 *   fallback, so a caller that forgets to check still sends the browser
 *   somewhere safe.
 *
 * @card
 *   Resolve a request-supplied redirect target against the origins and hosts
 *   you allow, answering a fallback for anything else, so a Location header
 *   cannot be pointed off-site by whoever made the request.
 */

var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var codepointClass = require("./codepoint-class");

var DEFAULT_FALLBACK = "/";

function _hasControlChar(s) {
  return codepointClass.firstControlCharOffset(s, { forbidTab: true }) !== -1;
}

/**
 * @primitive b.safeRedirect.resolve
 * @signature b.safeRedirect.resolve(rawTarget, opts?)
 * @since     0.7.21
 * @status    stable
 * @compliance soc2, pci-dss
 * @related   b.safeUrl.parse, b.middleware.securityHeaders
 *
 * Answer the URL a redirect may use, given the one the request asked for.
 * A same-site target, meaning one that starts with `/`, `?` or `#`, comes
 * back unchanged. An absolute target comes back only when its origin matches
 * `base`, or appears in `allowedOrigins`, or its host appears in
 * `allowedHosts`. Anything else answers `fallback`.
 *
 * A protocol-relative target such as `//evil.example` is treated as absolute
 * and refused, and so is the backslash spelling browsers accept. A target
 * carrying a control character, including a tab, is refused rather than
 * trimmed, because a header splitting on one is a second bug.
 *
 * Naming none of `base`, `allowedOrigins` or `allowedHosts` means no
 * absolute target is allowed, so the off-site case stays closed until a
 * caller opens it.
 *
 * @opts
 *   base:           string,     // this site's URL; a target on its origin is allowed
 *   allowedOrigins: string[],   // origins allowed in full, compared lowercased
 *   allowedHosts:   string[],   // hosts allowed on any port, compared lowercased
 *   fallback:       string,     // where a refused target goes; default "/"
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.safeRedirect.resolve("/account", { base: "https://app.example" });
 *   // → "/account"
 *
 *   b.safeRedirect.resolve("//evil.example/pay", { base: "https://app.example" });
 *   // → "/"
 *
 *   b.safeRedirect.resolve("https://docs.example/start", {
 *     base: "https://app.example", allowedHosts: ["docs.example"],
 *   });
 *   // → "https://docs.example/start"
 */
function resolve(rawTarget, opts) {
  opts = opts || {};
  validateOpts(opts, ["base", "allowedOrigins", "allowedHosts", "fallback"], "safeRedirect.resolve");

  var fallback = typeof opts.fallback === "string" ? opts.fallback : DEFAULT_FALLBACK;
  if (typeof rawTarget !== "string" || rawTarget.length === 0) return fallback;
  if (_hasControlChar(rawTarget)) return fallback;

  if (rawTarget.length >= 2) {
    var p0 = rawTarget.charAt(0);
    var p1 = rawTarget.charAt(1);
    if ((p0 === "/" || p0 === "\\") && (p1 === "/" || p1 === "\\")) return fallback;
  }

  if (rawTarget.charAt(0) === "/" || rawTarget.charAt(0) === "?" ||
      rawTarget.charAt(0) === "#") {
    return rawTarget;
  }

  var allowedOrigins = Array.isArray(opts.allowedOrigins) ? opts.allowedOrigins : null;
  var allowedHosts   = Array.isArray(opts.allowedHosts)   ? opts.allowedHosts   : null;

  var baseOrigin = null;
  if (typeof opts.base === "string" && opts.base.length > 0) {
    try {
      baseOrigin = safeUrl.parse(opts.base, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS }).origin;
    } catch (_e) { baseOrigin = null; }
  }

  if (!allowedOrigins && !allowedHosts && baseOrigin === null) {
    return fallback;
  }

  var parsed;
  try { parsed = safeUrl.parse(rawTarget, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS }); }
  catch (_e) { return fallback; }

  if (baseOrigin !== null && parsed.origin === baseOrigin) return rawTarget;
  if (allowedOrigins) {
    for (var i = 0; i < allowedOrigins.length; i += 1) {
      if (parsed.origin === String(allowedOrigins[i]).toLowerCase()) return rawTarget;
    }
  }
  if (allowedHosts) {
    for (var j = 0; j < allowedHosts.length; j += 1) {
      var allowedHost = String(allowedHosts[j]).toLowerCase();
      if (parsed.host === allowedHost || parsed.hostname === allowedHost) {
        return rawTarget;
      }
    }
  }
  return fallback;
}

module.exports = {
  resolve:           resolve,
  DEFAULT_FALLBACK:  DEFAULT_FALLBACK,
};
