// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.clientHints
 * @nav        HTTP
 * @title      Sec-CH-UA Client Hints
 * @order      316
 *
 * @intro
 *   User-Agent Client Hints parser. Browsers replacing the
 *   freeform `User-Agent` string send a family of `Sec-CH-UA-*`
 *   request headers carrying structured-fields data per RFC 8941:
 *
 *     Sec-CH-UA: "Chromium";v="124", "Not-A.Brand";v="99", "Google Chrome";v="124"
 *     Sec-CH-UA-Mobile: ?0
 *     Sec-CH-UA-Platform: "Windows"
 *     Sec-CH-UA-Platform-Version: "15.0.0"
 *     Sec-CH-UA-Arch: "x86"
 *     Sec-CH-UA-Bitness: "64"
 *     Sec-CH-UA-Model: ""
 *     Sec-CH-UA-Full-Version-List: "Chromium";v="124.0.6367.91", ...
 *     Sec-CH-UA-WoW64: ?0
 *     Sec-CH-UA-Form-Factors: "Desktop"
 *
 *   `parse(headers)` walks an HTTP request's headers map and returns
 *   a normalized object — brand list with versions, mobile boolean,
 *   platform / platform-version / arch / bitness / model / form-
 *   factors strings — plus the raw RFC 8941 parsed shape for any
 *   header the operator wants to inspect verbatim.
 *
 *   Operators use it to:
 *     - Replace freeform UA-string parsing (deprecated; brittle).
 *     - Negotiate per-platform CSS / JS bundles (Sec-CH-UA-Platform).
 *     - Detect mobile-class clients without UA-sniffing.
 *     - Audit fingerprinting-style header negotiation.
 *
 *   The primitive treats every header as defensive request-shape
 *   input — returns `null` for absent / malformed headers, throws
 *   only on explicit control-character / header-injection-shape
 *   input. Operators upstream of this primitive (proxies, framework
 *   middleware) already split CRLF; the in-string control-byte
 *   check is a defense-in-depth layer.
 *
 *   `acceptList()` builds the `Accept-CH` response header so the
 *   operator advertises which client-hint headers the page wants.
 *
 * @card
 *   RFC 8941 / W3C Client Hints — parse `Sec-CH-UA*` request headers
 *   (brand list, mobile, platform, arch, model, form-factors) and
 *   build the `Accept-CH` response header for hint negotiation.
 */

var structuredFields = require("./structured-fields");
var { defineClass } = require("./framework-error");

var ClientHintsError = defineClass("ClientHintsError",
  { alwaysPermanent: true });

// Well-known Sec-CH-UA-* header names (W3C UA-CH spec + IETF
// draft-davidben-http-client-hint-reliability). Operators looking up
// the canonical name for an Accept-CH response use this constant; we
// keep it as a frozen array so a future hint addition is one-line.
var KNOWN_HINTS = Object.freeze([
  "Sec-CH-UA",
  "Sec-CH-UA-Mobile",
  "Sec-CH-UA-Platform",
  "Sec-CH-UA-Platform-Version",
  "Sec-CH-UA-Arch",
  "Sec-CH-UA-Bitness",
  "Sec-CH-UA-Model",
  "Sec-CH-UA-Full-Version-List",
  "Sec-CH-UA-WoW64",
  "Sec-CH-UA-Form-Factors",
  "Sec-CH-Prefers-Reduced-Motion",
  "Sec-CH-Prefers-Reduced-Transparency",
  "Sec-CH-Prefers-Color-Scheme",
  "Sec-CH-Prefers-Contrast",
  "Sec-CH-Save-Data",
  "Sec-CH-Viewport-Width",
  "Sec-CH-Viewport-Height",
  "Sec-CH-DPR",
  "Sec-CH-Width",
  "Sec-CH-Downlink",
  "Sec-CH-RTT",
  "Sec-CH-ECT",
]);

var KNOWN_HINTS_LC = {};
for (var _h = 0; _h < KNOWN_HINTS.length; _h += 1) {
  KNOWN_HINTS_LC[KNOWN_HINTS[_h].toLowerCase()] = KNOWN_HINTS[_h];
}

function _scanControlBytes(s, headerName) {
  structuredFields.refuseControlBytes(s, {
    ErrorClass: ClientHintsError,
    code:       "client-hints/bad-header-value",
    label:      "parse: " + headerName,
  });
}

// RFC 8941 §3.3.3 sf-string — quoted-string with backslash-escape for
// `"` and `\`. Defensive parser that tolerates unquoted bare tokens
// (some operators forward a header whose quote-shape was already
// stripped by an upstream proxy).
function _parseSfString(s) {
  var t = s.trim();
  if (t.length === 0) return "";
  if (t.charAt(0) === "\"") {
    if (t.charAt(t.length - 1) !== "\"") return null;
    // Single-pass RFC 8941 unescape — chained .replace() mis-decodes
    // an escaped backslash adjacent to another escape.
    return structuredFields.unescapeSfStringBody(t.slice(1, -1));
  }
  return t;
}

// RFC 8941 §3.3.6 sf-boolean — `?1` (true) / `?0` (false). Returns
// null for any other shape so callers can detect malformed values.
function _parseSfBoolean(s) {
  var t = s.trim();
  if (t === "?1") return true;
  if (t === "?0") return false;
  return null;
}

// RFC 8941 §3.1.1 sf-list — comma-separated members, each potentially
// carrying `;key=value;flag` parameters. For Sec-CH-UA the members are
// sf-strings with a `;v="<version>"` parameter giving the brand
// version. Returns `[ { brand, version, params } ]` or `null` for
// malformed input.
function _parseSfBrandList(s) {
  var t = s.trim();
  if (t.length === 0) return [];
  // Walk via the shared quote-aware top-level `,` splitter. RFC 8941
  // sf-list members don't allow parenthesized inner-list values in
  // the Sec-CH-UA grammar (only sf-string + parameters), so the
  // simple top-level comma split suffices — no `depth` tracking
  // needed (the earlier inline shape carried defensive paren
  // tracking left over from a generic sf-list walker prototype).
  var pieces = structuredFields.splitTopLevel(t, ",");
  var out = [];
  for (var i = 0; i < pieces.length; i += 1) {
    var piece = pieces[i].trim();
    if (piece.length === 0) continue;
    var parsed = _parseBrandMember(piece);
    if (parsed !== null) out.push(parsed);
  }
  return out;
}

function _parseBrandMember(piece) {
  // member ::= sf-string ( ';' parameter )*
  // RFC 8941 §4.1.1.4 — parameter values can be sf-string. A bare
  // `piece.split(";")` would slice through `;v="1.2; 3"` and corrupt
  // the parameter value. Use the shared quote-aware splitter so the
  // tracking shape stays consistent across every framework parser.
  var params = structuredFields.splitTopLevel(piece, ";");
  if (params.length === 0) return null;
  var brand = _parseSfString(params[0].trim());
  if (brand === null) return null;
  var member = { brand: brand, version: null, params: {} };
  var kvps = structuredFields.parseKeyValuePieces(params, 1);
  for (var i = 0; i < kvps.length; i += 1) {
    var kv = kvps[i];
    if (kv.value === null) { member.params[kv.key] = true; continue; }
    var v = _parseSfString(kv.value);
    member.params[kv.key] = v;
    if (kv.key === "v" && v !== null) member.version = v;
  }
  return member;
}

/**
 * @primitive b.clientHints.parse
 * @signature b.clientHints.parse(headers)
 * @since     0.8.91
 * @status    stable
 * @related   b.clientHints.acceptList, b.clientHints.isKnownHint
 *
 * Parse the Sec-CH-UA-* family from an HTTP request's headers object.
 * `headers` is the Node `req.headers` shape (header names are
 * already lowercased per Node convention). Returns a normalized
 * `{ brands, mobile, platform, platformVersion, arch, bitness, model,
 *    fullVersionList, wow64, formFactors, raw }` shape:
 *
 *   - `brands`: `[ { brand, version, params } ]` from `Sec-CH-UA`
 *   - `mobile`: boolean from `Sec-CH-UA-Mobile` (?1/?0) — null if absent / malformed
 *   - `platform`: sf-string from `Sec-CH-UA-Platform`
 *   - `platformVersion`: sf-string from `Sec-CH-UA-Platform-Version`
 *   - `arch`: sf-string from `Sec-CH-UA-Arch`
 *   - `bitness`: sf-string from `Sec-CH-UA-Bitness`
 *   - `model`: sf-string from `Sec-CH-UA-Model`
 *   - `fullVersionList`: brand-list from `Sec-CH-UA-Full-Version-List`
 *   - `wow64`: boolean from `Sec-CH-UA-WoW64`
 *   - `formFactors`: brand-list from `Sec-CH-UA-Form-Factors`
 *   - `raw`: `{ "<header-name-lc>": "<raw-value>" }` for every Sec-CH-*
 *     header in the input, so operators can audit the full set without
 *     re-walking `req.headers`.
 *
 * Returns `null` when `headers` is not an object. Individual fields
 * are `null` when the corresponding header is absent or malformed
 * (defensive request-shape reader). Refuses control characters in
 * any present Sec-CH-* value (header-injection defense).
 *
 * @example
 *   var ch = b.clientHints.parse(req.headers);
 *   if (ch && ch.mobile === true) renderMobilePage(req, res);
 *   else if (ch && ch.platform === "Windows") renderWindowsPage(req, res);
 *   else renderDefaultPage(req, res);
 */
function parse(headers) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) return null;
  var raw = {};
  var keys = Object.keys(headers);
  for (var k = 0; k < keys.length; k += 1) {
    var name = keys[k].toLowerCase();
    if (name.indexOf("sec-ch-") !== 0) continue;
    var val = headers[keys[k]];
    if (val === undefined || val === null) continue;
    if (typeof val !== "string") val = String(val);
    _scanControlBytes(val, name);
    raw[name] = val;
  }

  return {
    brands:           raw["sec-ch-ua"] ? _parseSfBrandList(raw["sec-ch-ua"]) : null,
    mobile:           raw["sec-ch-ua-mobile"] !== undefined ? _parseSfBoolean(raw["sec-ch-ua-mobile"]) : null,
    platform:         raw["sec-ch-ua-platform"] !== undefined ? _parseSfString(raw["sec-ch-ua-platform"]) : null,
    platformVersion:  raw["sec-ch-ua-platform-version"] !== undefined ? _parseSfString(raw["sec-ch-ua-platform-version"]) : null,
    arch:             raw["sec-ch-ua-arch"] !== undefined ? _parseSfString(raw["sec-ch-ua-arch"]) : null,
    bitness:          raw["sec-ch-ua-bitness"] !== undefined ? _parseSfString(raw["sec-ch-ua-bitness"]) : null,
    model:            raw["sec-ch-ua-model"] !== undefined ? _parseSfString(raw["sec-ch-ua-model"]) : null,
    fullVersionList:  raw["sec-ch-ua-full-version-list"] ? _parseSfBrandList(raw["sec-ch-ua-full-version-list"]) : null,
    wow64:            raw["sec-ch-ua-wow64"] !== undefined ? _parseSfBoolean(raw["sec-ch-ua-wow64"]) : null,
    formFactors:      raw["sec-ch-ua-form-factors"] ? _parseSfBrandList(raw["sec-ch-ua-form-factors"]) : null,
    raw:              raw,
  };
}

/**
 * @primitive b.clientHints.acceptList
 * @signature b.clientHints.acceptList(hintNames)
 * @since     0.8.91
 * @status    stable
 * @related   b.clientHints.parse, b.clientHints.isKnownHint
 *
 * Build the `Accept-CH` response header value advertising which
 * client-hint request headers the operator wants the browser to
 * include on subsequent requests. `hintNames` is an array of
 * canonical Sec-CH-* header names; the primitive refuses unknown
 * hint names (typo defense — `accept-ch: Sec-CH-UA-Plateform`
 * silently neuters the negotiation).
 *
 * Operators set `Accept-CH` on the HTML document response. The
 * browser sends the listed hints on every subsequent same-origin
 * navigation / sub-resource request.
 *
 * @example
 *   res.setHeader("Accept-CH", b.clientHints.acceptList([
 *     "Sec-CH-UA-Platform",
 *     "Sec-CH-UA-Platform-Version",
 *     "Sec-CH-UA-Mobile",
 *   ]));
 *   // → "Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Mobile"
 */
function acceptList(hintNames) {
  if (!Array.isArray(hintNames) || hintNames.length === 0) {
    throw new ClientHintsError("client-hints/bad-hint-list",
      "acceptList: hintNames must be a non-empty array of Sec-CH-* names");
  }
  var seen = {};
  var out = [];
  for (var i = 0; i < hintNames.length; i += 1) {
    var n = hintNames[i];
    if (typeof n !== "string" || n.length === 0) {
      throw new ClientHintsError("client-hints/bad-hint-name",
        "acceptList: hintNames[" + i + "] must be a non-empty string");
    }
    var canonical = KNOWN_HINTS_LC[n.toLowerCase()];
    if (!canonical) {
      throw new ClientHintsError("client-hints/unknown-hint",
        "acceptList: '" + n + "' is not a known client-hint header " +
        "(see b.clientHints.KNOWN_HINTS for the list)");
    }
    if (seen[canonical]) continue;
    seen[canonical] = true;
    out.push(canonical);
  }
  return out.join(", ");
}

/**
 * @primitive b.clientHints.isKnownHint
 * @signature b.clientHints.isKnownHint(headerName)
 * @since     0.8.91
 * @status    stable
 *
 * Returns `true` when `headerName` matches one of the well-known
 * Sec-CH-* hint headers (case-insensitive). Operators auditing
 * inbound headers walk the request and call this to identify
 * negotiation-related hints without keyword-matching.
 *
 * @example
 *   b.clientHints.isKnownHint("Sec-CH-UA-Mobile");    // → true
 *   b.clientHints.isKnownHint("sec-ch-ua-platform");  // → true
 *   b.clientHints.isKnownHint("X-Custom");            // → false
 */
function isKnownHint(headerName) {
  if (typeof headerName !== "string" || headerName.length === 0) return false;
  return Object.prototype.hasOwnProperty.call(KNOWN_HINTS_LC, headerName.toLowerCase());
}

module.exports = {
  parse:            parse,
  acceptList:       acceptList,
  isKnownHint:      isKnownHint,
  KNOWN_HINTS:      KNOWN_HINTS,
  ClientHintsError: ClientHintsError,
};
