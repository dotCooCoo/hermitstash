// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * safe-redirect — open-redirect (CWE-601) defense for operator-supplied
 * post-login `?next=` / `?return_to=` parameters and similar redirect
 * targets.
 *
 * The vulnerability: an attacker phishes a victim with a link like
 * `https://app.example.com/login?next=https://attacker.example.com`.
 * After login, a naive `res.writeHead(302, { Location: req.query.next })`
 * sends the user to attacker.example.com under the trust of app.example.com.
 *
 *   var safe = b.safeRedirect.resolve(rawNext, {
 *     base:           "https://app.example.com",
 *     allowedOrigins: ["https://app.example.com"],
 *     allowedHosts:   ["app.example.com"],
 *     fallback:       "/dashboard",
 *   });
 *   // → safe path or fallback (never attacker.example.com)
 *
 * Decision rules (in order):
 *
 *   1. rawTarget is null / empty / non-string → fallback
 *   2. rawTarget starts with "//" or "\\" → fallback (protocol-relative
 *      open redirect — `//attacker.com/path` interpreted as
 *      `https://attacker.com/path` by browsers)
 *   3. rawTarget contains a control char / null / CR / LF → fallback
 *      (header-injection vector)
 *   4. rawTarget is a relative path starting with "/" → safe (same-
 *      origin by definition)
 *   5. rawTarget is a fragment / search-only ("#x" / "?q=1") → safe
 *   6. rawTarget is a full URL → parse + check origin against
 *      allowedOrigins (or host against allowedHosts when the operator
 *      doesn't care about scheme/port match)
 *   7. anything else (data:, javascript:, malformed) → fallback
 *
 * Returns the safe URL string (path + query + fragment for relative;
 * full URL for allowed full URLs; fallback otherwise). Operators
 * pass the result directly to `res.writeHead(302, { Location: ... })`.
 */

var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var codepointClass = require("./codepoint-class");

var DEFAULT_FALLBACK = "/";

function _hasControlChar(s) {
  return codepointClass.firstControlCharOffset(s, { forbidTab: true }) !== -1;
}

function resolve(rawTarget, opts) {
  opts = opts || {};
  validateOpts(opts, ["base", "allowedOrigins", "allowedHosts", "fallback"], "safeRedirect.resolve");

  var fallback = typeof opts.fallback === "string" ? opts.fallback : DEFAULT_FALLBACK;
  if (typeof rawTarget !== "string" || rawTarget.length === 0) return fallback;
  if (_hasControlChar(rawTarget)) return fallback;

  // Reject protocol-relative ("//host/...") and back-slash variant
  // ("\\host\..." — IE / older browsers may interpret as auth).
  if (rawTarget.length >= 2) {
    var p0 = rawTarget.charAt(0);
    var p1 = rawTarget.charAt(1);
    if ((p0 === "/" || p0 === "\\") && (p1 === "/" || p1 === "\\")) return fallback;
  }

  // Same-origin relative (path / query / fragment) — safe by definition.
  if (rawTarget.charAt(0) === "/" || rawTarget.charAt(0) === "?" ||
      rawTarget.charAt(0) === "#") {
    return rawTarget;
  }

  // Full URL — parse and check against allowlist.
  var allowedOrigins = Array.isArray(opts.allowedOrigins) ? opts.allowedOrigins : null;
  var allowedHosts   = Array.isArray(opts.allowedHosts)   ? opts.allowedHosts   : null;

  // The application's own origin (opts.base) is same-origin by
  // definition, so a full URL pointing at it is safe even when the
  // operator supplied no explicit allowedOrigins / allowedHosts. Derive
  // the origin from base and treat it as an implicitly-allowed origin.
  var baseOrigin = null;
  if (typeof opts.base === "string" && opts.base.length > 0) {
    try {
      baseOrigin = safeUrl.parse(opts.base, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS }).origin;
    } catch (_e) { baseOrigin = null; }
  }

  if (!allowedOrigins && !allowedHosts && baseOrigin === null) {
    // Operator gave no allowlist and no usable base — refuse all full
    // URLs (the safe default).
    return fallback;
  }

  var parsed;
  try { parsed = safeUrl.parse(rawTarget, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS }); }
  catch (_e) { return fallback; }

  if (baseOrigin !== null && parsed.origin === baseOrigin) return rawTarget;
  if (allowedOrigins) {
    for (var i = 0; i < allowedOrigins.length; i += 1) {
      if (parsed.origin === allowedOrigins[i]) return rawTarget;
    }
  }
  if (allowedHosts) {
    for (var j = 0; j < allowedHosts.length; j += 1) {
      if (parsed.host === allowedHosts[j] || parsed.hostname === allowedHosts[j]) {
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
