// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.uriTemplate
 * @nav    HTTP
 * @title  URI Templates
 *
 * @intro
 *   Expand <a href="https://www.rfc-editor.org/rfc/rfc6570">RFC 6570</a> URI
 *   Templates — the <code>{var}</code> syntax that OpenAPI links, HAL
 *   <code>_links</code>, and hypermedia API clients use to turn a template
 *   plus a set of variables into a concrete URI. The full Level 4 grammar
 *   is supported: every operator (<code>{+var}</code> reserved,
 *   <code>{#var}</code> fragment, <code>{.var}</code> label,
 *   <code>{/var}</code> path, <code>{;var}</code> path-style parameters,
 *   <code>{?var}</code> query, <code>{&amp;var}</code> query continuation),
 *   the <code>{var:3}</code> prefix modifier, and the <code>{var*}</code>
 *   explode modifier for lists and associative arrays.
 *
 *   <code>expand(template, vars)</code> returns the expanded string;
 *   <code>compile(template)</code> parses once and returns a reusable
 *   <code>{ expand }</code> for templates applied to many variable sets. A
 *   malformed template (an unclosed expression, an unknown operator, or a
 *   non-numeric prefix) throws <code>UriTemplateError</code>.
 *
 * @card
 *   RFC 6570 URI Template expansion (full Level 4 — every operator, the
 *   <code>:N</code> prefix and <code>*</code> explode modifiers) — the
 *   <code>{var}</code> syntax behind OpenAPI links and HAL hypermedia.
 */

var { defineClass } = require("./framework-error");
var codepointClass = require("./codepoint-class");

var UriTemplateError = defineClass("UriTemplateError", { alwaysPermanent: true });

var MAX_PREFIX = 10000;                                     // RFC 6570 caps prefix length at 9999

// Operator table (RFC 6570 §2.2 / §3.2.1). first = prefix when any value is
// present; sep = separator between values; named = emit "name=value";
// ifemp = string used when a named value is empty; reserved = allow the
// reserved set through unencoded.
var OPERATORS = {
  "":  { first: "",  sep: ",", named: false, ifemp: "",  reserved: false },
  "+": { first: "",  sep: ",", named: false, ifemp: "",  reserved: true },
  "#": { first: "#", sep: ",", named: false, ifemp: "",  reserved: true },
  ".": { first: ".", sep: ".", named: false, ifemp: "",  reserved: false },
  "/": { first: "/", sep: "/", named: false, ifemp: "",  reserved: false },
  ";": { first: ";", sep: ";", named: true,  ifemp: "",  reserved: false },
  "?": { first: "?", sep: "&", named: true,  ifemp: "=", reserved: false },
  "&": { first: "&", sep: "&", named: true,  ifemp: "=", reserved: false },
};

var UNRESERVED = /[A-Za-z0-9\-._~]/;
// Reserved = gen-delims + sub-delims (RFC 3986 §2.2).
var RESERVED = /[:/?#[\]@!$&'()*+,;=]/;

function _pctEncode(str, allowReserved) {
  var out = "";
  for (var i = 0; i < str.length; i++) {
    var ch = str.charAt(i);
    // Preserve existing percent-encoded triplets when the reserved set is
    // allowed (operators "+" and "#").
    // allow:regex-no-length-cap — the substr is a fixed 2-char window
    if (allowReserved && ch === "%" && codepointClass.HEX_PAIR_RE.test(str.substr(i + 1, 2))) {
      out += str.substr(i, 3); i += 2; continue;
    }
    if (UNRESERVED.test(ch) || (allowReserved && RESERVED.test(ch))) { out += ch; continue; }
    // Percent-encode the character's raw UTF-8 bytes (handles surrogate
    // pairs). encodeURIComponent is not used — it leaves !*'() unencoded,
    // which RFC 6570 unreserved-only expansion must escape.
    var cp = str.codePointAt(i);
    var bytes = Buffer.from(String.fromCodePoint(cp), "utf8");
    for (var b = 0; b < bytes.length; b++) out += "%" + bytes[b].toString(16).toUpperCase().padStart(2, "0");   // hex radix
    if (cp > 0xFFFF) i++;   // consumed a surrogate pair   // BMP boundary for surrogate-pair detection
  }
  return out;
}

function _allDigits(s) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i++) { var c = s.charCodeAt(i); if (c < 48 || c > 57) return false; }   // ASCII '0'..'9' code-point bounds
  return true;
}

// A composite member/value is "defined" unless it is undefined or null
// (an empty string, 0, or false is defined and expands).
function _memberDefined(v) { return v !== undefined && v !== null; }

function _isDefined(v) {
  if (v === undefined || v === null) return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === "object") return Object.keys(v).length > 0;
  return true;
}
function _toStr(v) {
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return String(v);
}

// A literal run may not contain a stray "}" (an unmatched expression close)
// — RFC 6570 literals exclude "{" and "}".
function _checkLiteral(lit) {
  if (lit.indexOf("}") !== -1) throw new UriTemplateError("uri-template/unmatched-brace", "uriTemplate: unmatched '}' in template literal");
}

// Parse a template into an array of literal strings + expression objects.
function _parse(template) {
  if (typeof template !== "string") throw new UriTemplateError("uri-template/bad-template", "uriTemplate: template must be a string");
  var parts = [];
  var i = 0;
  while (i < template.length) {
    var open = template.indexOf("{", i);
    if (open === -1) { _checkLiteral(template.slice(i)); parts.push({ literal: template.slice(i) }); break; }
    if (open > i) { _checkLiteral(template.slice(i, open)); parts.push({ literal: template.slice(i, open) }); }
    var close = template.indexOf("}", open);
    if (close === -1) throw new UriTemplateError("uri-template/unclosed", "uriTemplate: unclosed expression at index " + open);
    parts.push(_parseExpr(template.slice(open + 1, close)));
    i = close + 1;
  }
  return parts;
}

function _parseExpr(body) {
  if (body.length === 0) throw new UriTemplateError("uri-template/empty-expression", "uriTemplate: empty expression {}");
  var op = "";
  var c0 = body.charAt(0);
  if ("+#./;?&".indexOf(c0) !== -1) { op = c0; body = body.slice(1); }
  else if ("=,!@|".indexOf(c0) !== -1) {
    // Operators reserved by RFC 6570 §2.2 for future extensions → error.
    throw new UriTemplateError("uri-template/reserved-operator", "uriTemplate: operator '" + c0 + "' is reserved");
  }
  var specs = body.split(",").map(function (raw) {
    if (raw.length === 0) throw new UriTemplateError("uri-template/bad-varspec", "uriTemplate: empty variable name");
    var explode = false, prefix = null;
    var name = raw;
    if (raw.charAt(raw.length - 1) === "*") { explode = true; name = raw.slice(0, -1); }
    else {
      var colon = raw.indexOf(":");
      if (colon !== -1) {
        name = raw.slice(0, colon);
        var n = raw.slice(colon + 1);
        if (!_allDigits(n)) throw new UriTemplateError("uri-template/bad-prefix", "uriTemplate: prefix length must be a non-negative integer");
        prefix = parseInt(n, 10);
        if (prefix >= MAX_PREFIX) throw new UriTemplateError("uri-template/bad-prefix", "uriTemplate: prefix length exceeds 9999");
      }
    }
    if (!/^(?:[A-Za-z0-9_]|%[0-9A-Fa-f]{2})(?:\.?(?:[A-Za-z0-9_]|%[0-9A-Fa-f]{2}))*$/.test(name)) {
      throw new UriTemplateError("uri-template/bad-varname", "uriTemplate: invalid variable name '" + name + "'");
    }
    return { name: name, explode: explode, prefix: prefix };
  });
  return { op: op, specs: specs };
}

function _expandExpr(expr, vars) {
  var o = OPERATORS[expr.op];
  var pieces = [];
  expr.specs.forEach(function (spec) {
    // Own-property only: a varspec name is parse-derived from the template, so
    // it can be `constructor` / `toString` / `__proto__` / any prototype-
    // polluted key. A bare `vars[spec.name]` would read the INHERITED member
    // and expand a function source (or a planted prototype value) into the URI.
    // RFC 6570 §3.2.1 treats an undefined variable as omitted, so an inherited
    // name must be undefined here — never a prototype-chain read.
    var value = Object.prototype.hasOwnProperty.call(vars, spec.name)
      ? vars[spec.name] : undefined;
    if (!_isDefined(value)) return;

    if (typeof value !== "object") {
      // Simple string/number/boolean value.
      var s = _toStr(value);
      if (spec.prefix !== null) s = _sliceChars(s, spec.prefix);
      pieces.push(_named(o, spec.name, _pctEncode(s, o.reserved), s.length === 0));
    } else if (Array.isArray(value)) {
      if (spec.prefix !== null) throw new UriTemplateError("uri-template/prefix-on-list", "uriTemplate: prefix modifier cannot apply to a list");
      // Undefined / null members are ignored (RFC 6570 §3.2.1); a list with
      // no defined members is treated as undefined and omitted entirely.
      var members = value.filter(_memberDefined);
      if (members.length === 0) return;
      if (!spec.explode) {
        var joined = members.map(function (m) { return _pctEncode(_toStr(m), o.reserved); }).join(",");
        pieces.push(_named(o, spec.name, joined, false));
      } else {
        members.forEach(function (m) {
          pieces.push(_named(o, spec.name, _pctEncode(_toStr(m), o.reserved), _toStr(m).length === 0));
        });
      }
    } else {
      // Associative array (object). Pairs whose value is undefined / null
      // are omitted (RFC 6570 §3.2.1).
      if (spec.prefix !== null) throw new UriTemplateError("uri-template/prefix-on-map", "uriTemplate: prefix modifier cannot apply to a map");
      var keys = Object.keys(value).filter(function (k) { return _memberDefined(value[k]); });
      if (keys.length === 0) return;
      if (!spec.explode) {
        var pairs = [];
        keys.forEach(function (k) { pairs.push(_pctEncode(k, o.reserved)); pairs.push(_pctEncode(_toStr(value[k]), o.reserved)); });
        pieces.push(_named(o, spec.name, pairs.join(","), false));
      } else {
        keys.forEach(function (k) {
          // Exploded map: the key becomes the name.
          pieces.push(_namedPair(o, _pctEncode(k, o.reserved), _pctEncode(_toStr(value[k]), o.reserved)));
        });
      }
    }
  });
  if (pieces.length === 0) return "";
  return o.first + pieces.join(o.sep);
}

// Build one "name=value" (or bare value) piece for a non-exploded or
// string varspec.
function _named(o, name, encodedValue, isEmpty) {
  if (!o.named) return encodedValue;
  if (isEmpty) return name + o.ifemp;
  return name + "=" + encodedValue;
}
// Exploded map pair: key is already the name.
function _namedPair(o, encodedKey, encodedValue) {
  if (!o.named) return encodedKey + "=" + encodedValue;
  if (encodedValue.length === 0) return encodedKey + o.ifemp;
  return encodedKey + "=" + encodedValue;
}

// Truncate to N Unicode code points (RFC 6570 prefix length is in chars).
function _sliceChars(s, n) {
  var out = "", count = 0;
  for (var i = 0; i < s.length && count < n; i++) {
    var cp = s.codePointAt(i);
    out += String.fromCodePoint(cp);
    if (cp > 0xFFFF) i++;   // BMP boundary for surrogate pairs
    count++;
  }
  return out;
}

/**
 * @primitive  b.uriTemplate.compile
 * @signature  b.uriTemplate.compile(template)
 * @since      0.12.66
 * @status     stable
 * @related    b.uriTemplate.expand, b.hal, b.linkHeader
 *
 * Parse an RFC 6570 URI Template once and return a reusable
 * <code>{ expand(vars) }</code>, so a template applied to many variable
 * sets is parsed a single time. Throws <code>UriTemplateError</code> if the
 * template is malformed.
 *
 * @example
 *   var t = b.uriTemplate.compile("/users/{id}{?fields*}");
 *   t.expand({ id: 7, fields: ["name", "email"] });
 *   // → "/users/7?fields=name&fields=email"
 */
function compile(template) {
  var parts = _parse(template);
  return {
    expand: function (vars) {
      vars = vars || {};
      var out = "";
      for (var i = 0; i < parts.length; i++) {
        out += Object.prototype.hasOwnProperty.call(parts[i], "literal") ? parts[i].literal : _expandExpr(parts[i], vars);
      }
      return out;
    },
  };
}

/**
 * @primitive  b.uriTemplate.expand
 * @signature  b.uriTemplate.expand(template, vars)
 * @since      0.12.66
 * @status     stable
 * @related    b.uriTemplate.compile
 *
 * Expand an RFC 6570 URI Template against a set of variables and return the
 * resulting URI string. Variable values may be strings, numbers, booleans,
 * arrays (lists), or plain objects (associative arrays); an undefined,
 * null, or empty list/map variable is omitted. Reserved-set encoding,
 * <code>:N</code> prefixes, and <code>*</code> explosion follow RFC 6570
 * §3.2. Throws <code>UriTemplateError</code> on a malformed template.
 *
 * @example
 *   b.uriTemplate.expand("{/path}/here{?q,limit}",
 *     { path: "search", q: "json schema", limit: 10 });
 *   // → "/search/here?q=json%20schema&limit=10"
 */
function expand(template, vars) {
  return compile(template).expand(vars);
}

module.exports = {
  expand:           expand,
  compile:          compile,
  UriTemplateError: UriTemplateError,
};
