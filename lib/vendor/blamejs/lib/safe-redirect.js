// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
