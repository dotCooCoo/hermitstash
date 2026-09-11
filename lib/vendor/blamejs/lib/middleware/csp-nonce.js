// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var bCrypto = require("../crypto");
var numericBounds = require("../numeric-bounds");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var CspNonceError = defineClass("CspNonceError", { alwaysPermanent: true });

var DEFAULT_DIRECTIVES = Object.freeze(["script-src", "style-src"]);
var DEFAULT_NONCE_BYTES = C.BYTES.bytes(16);
var MIN_NONCE_BYTES = C.BYTES.bytes(16);
var PLACEHOLDER_PREFIX = "__BLAMEJS_CSP_NONCE_";
var PLACEHOLDER_SUFFIX = "__";
var PLACEHOLDER_RAND_BYTES = C.BYTES.bytes(16);

function _buildSubstitute(placeholder, property) {
  return function substitute(html, reqOrNonce) {
    if (typeof html !== "string" || html.length === 0) return html;
    if (html.indexOf(placeholder) === -1) return html;
    var nonce;
    if (typeof reqOrNonce === "string") {
      nonce = reqOrNonce;
    } else if (reqOrNonce && typeof reqOrNonce === "object") {
      nonce = reqOrNonce[property] ||
              (reqOrNonce.res && reqOrNonce.res.locals && reqOrNonce.res.locals[property]) ||
              "";
    } else {
      nonce = "";
    }
    return html.split(placeholder).join(nonce);
  };
}

function _defaultCsp(nonceToken) {
  return "default-src 'self'; " +
         "script-src 'self' " + nonceToken + "; " +
         "style-src 'self' " + nonceToken + "; " +
         "img-src 'self' data:; " +
         "frame-ancestors 'none'; " +
         "base-uri 'self'; " +
         "form-action 'self'; " +
         "object-src 'none'";
}

function _parseCsp(headerValue) {
  var parts = String(headerValue).split(";");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    var tokens = p.split(/\s+/);
    var name = tokens.shift().toLowerCase();
    out.push({ name: name, values: tokens });
  }
  return out;
}

function _serializeCsp(parts) {
  return parts.map(function (p) {
    if (p.values.length === 0) return p.name;
    return p.name + " " + p.values.join(" ");
  }).join("; ");
}

function _injectNonce(cspHeader, nonce, directives, strictDynamic) {
  var nonceToken = "'nonce-" + nonce + "'";
  if (!cspHeader) {
    return _defaultCsp(nonceToken);
  }
  var parts = _parseCsp(cspHeader);
  var seen = Object.create(null);
  for (var i = 0; i < parts.length; i++) {
    var name = parts[i].name;
    seen[name] = i;
    if (directives.indexOf(name) !== -1) {
      if (parts[i].values.indexOf(nonceToken) === -1) {
        parts[i].values.push(nonceToken);
      }
      if (strictDynamic && name === "script-src" && parts[i].values.indexOf("'strict-dynamic'") === -1) {
        parts[i].values.push("'strict-dynamic'");
      }
    }
  }
  for (var j = 0; j < directives.length; j++) {
    var d = directives[j].toLowerCase();
    if (Object.prototype.hasOwnProperty.call(seen, d)) continue;
    var values = [nonceToken];
    if (strictDynamic && d === "script-src") values.push("'strict-dynamic'");
    parts.push({ name: d, values: values });
  }
  return _serializeCsp(parts);
}

/**
 * @primitive b.middleware.cspNonce
 * @signature b.middleware.cspNonce(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.securityHeaders, b.middleware.cspReport
 *
 * Per-request CSP nonce + render integration. Constructed via
 * `b.middleware.cspNonce(opts)`; the resulting middleware has the
 * `(req, res, next)` shape shown above. Generates a fresh
 * random nonce (16 bytes / 24 chars base64 by default), attaches it
 * to `req.cspNonce` and `res.locals.cspNonce` (auto-merged into
 * template data), and patches the existing Content-Security-Policy
 * header to append `'nonce-XYZ'` to the configured directives
 * (default: script-src + style-src). With `strictDynamic: true`,
 * appends `'strict-dynamic'` so nonced scripts can load dependencies
 * without origin allowlisting (recommended for SPA hydration). Mount
 * after `securityHeaders`. Below-16-byte nonces are refused at
 * config time.
 *
 * @opts
 *   {
 *     directives:    string[],   // default ["script-src", "style-src"]
 *     nonceBytes:    number,     // default 16; minimum 16
 *     strictDynamic: boolean,
 *     headerName:    string,     // default "Content-Security-Policy"
 *     property:      string,     // default "cspNonce"
 *     always:        boolean,
 *     placeholder:   string,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.securityHeaders());
 *   app.use(b.middleware.cspNonce({
 *     directives:    ["script-src", "style-src"],
 *     nonceBytes:    16,
 *     strictDynamic: true,
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "directives", "nonceBytes", "strictDynamic", "headerName",
    "property", "always", "placeholder",
  ], "middleware.cspNonce");
  var directives = Array.isArray(opts.directives) && opts.directives.length > 0
                     ? opts.directives.slice() : DEFAULT_DIRECTIVES.slice();
  for (var i = 0; i < directives.length; i++) {
    if (typeof directives[i] !== "string" || directives[i].length === 0) {
      throw new CspNonceError("csp-nonce/bad-directive",
        "directives must be non-empty strings (e.g. 'script-src')");
    }
    directives[i] = directives[i].toLowerCase();
  }
  var nonceBytes = opts.nonceBytes !== undefined ? opts.nonceBytes : DEFAULT_NONCE_BYTES;
  if (!numericBounds.isPositiveFiniteInt(nonceBytes)) {
    throw new CspNonceError("csp-nonce/bad-nonce-bytes",
      "nonceBytes must be a positive finite integer; got " +
        numericBounds.shape(nonceBytes));
  }
  if (nonceBytes < MIN_NONCE_BYTES) {
    throw new CspNonceError("csp-nonce/bad-nonce-bytes",
      "nonceBytes must be >= " + MIN_NONCE_BYTES + " (got " + nonceBytes + "). " +
      "CSP nonces below 128 bits weaken the security boundary.");
  }
  var strictDynamic = !!opts.strictDynamic;
  var headerName = opts.headerName || "Content-Security-Policy";
  var property = (typeof opts.property === "string" && opts.property.length > 0) ? opts.property : "cspNonce";
  var always = !!opts.always;

  var placeholder;
  if (opts.placeholder === undefined) {
    placeholder = PLACEHOLDER_PREFIX +
                  bCrypto.generateToken(PLACEHOLDER_RAND_BYTES) +
                  PLACEHOLDER_SUFFIX;
  } else if (typeof opts.placeholder !== "string" || opts.placeholder.length === 0) {
    throw new CspNonceError("csp-nonce/bad-placeholder",
      "placeholder must be a non-empty string (got " + typeof opts.placeholder + " " +
      JSON.stringify(opts.placeholder) + "). Pass nothing to use the default per-instance random token.");
  } else {
    placeholder = opts.placeholder;
  }

  function cspNonce(req, res, next) {
    if (req[property] !== undefined) return next();
    var nonce = bCrypto.generateBytes(nonceBytes).toString("base64");

    req[property] = nonce;
    if (!res.locals || typeof res.locals !== "object") res.locals = {};
    res.locals[property] = nonce;

    if (typeof res.setHeader !== "function" || typeof res.getHeader !== "function") {
      return next();
    }

    var existing = res.getHeader(headerName);
    if (!existing && !always) {
      return next();
    }
    var patched = _injectNonce(existing, nonce, directives, strictDynamic);
    res.setHeader(headerName, patched);
    return next();
  }

  cspNonce.PLACEHOLDER = placeholder;
  cspNonce.substitute  = _buildSubstitute(placeholder, property);
  return cspNonce;
}

module.exports = {
  create:                create,
  CspNonceError:         CspNonceError,
  DEFAULT_DIRECTIVES:    DEFAULT_DIRECTIVES,
  _injectNonce:          _injectNonce,
  _parseCsp:             _parseCsp,
  _serializeCsp:         _serializeCsp,
};
