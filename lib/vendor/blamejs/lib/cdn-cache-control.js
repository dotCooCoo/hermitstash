// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.cdnCacheControl
 * @nav        HTTP
 * @title      RFC 9213 Targeted Cache-Control
 * @order      315
 *
 * @intro
 *   RFC 9213 Targeted HTTP Cache-Control directives. Operators address
 *   specific layers in the caching chain by setting parallel headers
 *   that share the `Cache-Control` directive grammar but apply only
 *   to caches matching the target. The well-known shapes:
 *
 *     Cache-Control:         max-age=60         (user-agent cache)
 *     CDN-Cache-Control:     max-age=3600       (every CDN class cache)
 *     Cloudflare-CDN-Cache-Control: max-age=86400  (CDN-specific override)
 *     Vercel-CDN-Cache-Control:     max-age=86400  (CDN-specific override)
 *     Surrogate-Control:     max-age=3600       (W3C Edge Architecture)
 *
 *   The same response can carry multiple targeted variants — a CDN
 *   that recognizes its operator-specific header uses that one; CDNs
 *   without a match fall back to `CDN-Cache-Control`; user agents
 *   apply only the plain `Cache-Control`. The framework treats every
 *   variant as the same RFC 9111 §5.2.2 directive grammar.
 *
 *   `build({...})` emits a directive string for any of the targeted
 *   headers; the operator chooses which header name to set. `parse()`
 *   round-trips: decode an inbound directive list into a normalized
 *   object with numeric maxAge / staleWhileRevalidate, boolean flags
 *   (public / private / noStore / noCache / mustRevalidate / immutable),
 *   and the raw `directives` map for unknown / extension keys.
 *
 *   `TARGETED_HEADERS` lists the well-known header names the operator
 *   may set; an explicit allowlist instead of guessing prevents
 *   operators from emitting a malformed `CDN-Cache-Control-X-Custom`
 *   header that no cache will look at.
 *
 * @card
 *   RFC 9213 Targeted Cache-Control — build / parse `CDN-Cache-Control`,
 *   `Surrogate-Control`, and operator-specific (`Cloudflare-` / `Vercel-`
 *   / `Fastly-`) variants with the same directive grammar as plain
 *   `Cache-Control`.
 */

var numericBounds    = require("./numeric-bounds");
var structuredFields = require("./structured-fields");
var validateOpts     = require("./validate-opts");
var { defineClass } = require("./framework-error");

var CdnCacheControlError = defineClass("CdnCacheControlError",
  { alwaysPermanent: true });

// RFC 9213 §3 — well-known targeted header names. The list is curated
// (not regex-matched) because operators routinely typo `CDN-Cache-
// Control` into `Cdn-CacheControl` etc. and a typo silently emits a
// header no cache will read. Operators with a CDN not on this list
// pass the header name verbatim to `build()` via `headerName:` for
// audit visibility — the value still goes through directive
// validation.
var TARGETED_HEADERS = Object.freeze([
  "Cache-Control",
  "CDN-Cache-Control",
  "Surrogate-Control",
  "Cloudflare-CDN-Cache-Control",
  "Vercel-CDN-Cache-Control",
  "Fastly-CDN-Cache-Control",
  "Akamai-CDN-Cache-Control",
  "Netlify-CDN-Cache-Control",
]);

var TARGETED_LC = {};
for (var _i = 0; _i < TARGETED_HEADERS.length; _i += 1) {
  TARGETED_LC[TARGETED_HEADERS[_i].toLowerCase()] = TARGETED_HEADERS[_i];
}

// RFC 9111 §5.2 — directive grammar. Numeric directives carry a
// delta-seconds value; boolean directives appear as bare tokens.
var BOOLEAN_DIRECTIVES = Object.freeze([
  "public", "private", "no-store", "no-cache",
  "must-revalidate", "proxy-revalidate", "immutable",
  "no-transform", "must-understand",
]);
var NUMERIC_DIRECTIVES = Object.freeze([
  "max-age", "s-maxage",
  "stale-while-revalidate", "stale-if-error",
  "min-fresh", "max-stale",
]);

// camelCase → kebab-case so `build({ maxAge: 60 })` emits `max-age=60`.
var KEBAB = {
  maxAge:               "max-age",
  sMaxAge:              "s-maxage",
  staleWhileRevalidate: "stale-while-revalidate",
  staleIfError:         "stale-if-error",
  minFresh:             "min-fresh",
  maxStale:             "max-stale",
  noStore:              "no-store",
  noCache:              "no-cache",
  mustRevalidate:       "must-revalidate",
  proxyRevalidate:      "proxy-revalidate",
  mustUnderstand:       "must-understand",
  noTransform:          "no-transform",
};

// RFC 7234 §5.2 token: `token = 1*tchar` where tchar excludes delimiter
// chars. Directive keys are tchar-only and conventionally ASCII-lower.
var DIRECTIVE_KEY_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;                                           // allow:duplicate-regex — RFC 7234 §5.2 tchar (=RFC 8941 token shape)

// Internal validation tier: throw at config-time. build() is the
// operator-facing entry, parse() is the request-shape reader (returns
// defensive defaults on garbage rather than throwing).

function _isNonNegInt(v) {
  return typeof v === "number" && isFinite(v) && v >= 0 && Math.floor(v) === v;
}

/**
 * @primitive b.cdnCacheControl.build
 * @signature b.cdnCacheControl.build(opts)
 * @since     0.8.91
 * @status    stable
 * @related   b.cdnCacheControl.parse, b.cdnCacheControl.isTargetedHeader
 *
 * Build a Cache-Control-style directive list string for any RFC 9213
 * targeted header. `opts` accepts the standard RFC 9111 §5.2.2
 * directives in camelCase (`maxAge`, `sMaxAge`, `staleWhileRevalidate`,
 * `staleIfError`, `mustRevalidate`, etc.) — kebab-case keys
 * (`max-age`, `s-maxage`, ...) also pass through unchanged for
 * operators porting from existing header-building code.
 *
 * Numeric directives accept non-negative finite integers; the
 * primitive refuses negative / non-integer / `Infinity` / `NaN`
 * inputs (the directive grammar requires delta-seconds). Boolean
 * directives only emit when explicitly `true`; `false` / `undefined`
 * omit the token.
 *
 * Returns the directive list string ready to be assigned to any
 * header in `TARGETED_HEADERS`. Caller is responsible for choosing
 * which header name to set.
 *
 * @opts
 *   maxAge:               number,   // max-age=N (user-agent + shared)
 *   sMaxAge:              number,   // s-maxage=N (shared caches only)
 *   staleWhileRevalidate: number,   // RFC 5861 §3
 *   staleIfError:         number,   // RFC 5861 §4
 *   minFresh:             number,   // request directive
 *   maxStale:             number,   // request directive
 *   public:               boolean,
 *   private:              boolean,
 *   noStore:              boolean,
 *   noCache:              boolean,
 *   mustRevalidate:       boolean,
 *   proxyRevalidate:      boolean,
 *   mustUnderstand:       boolean,  // RFC 8246
 *   noTransform:          boolean,
 *   immutable:            boolean,  // RFC 8246
 *   extensions:           object,   // raw key→value/true map for non-standard directives
 *
 * @example
 *   res.setHeader("CDN-Cache-Control", b.cdnCacheControl.build({
 *     public:               true,
 *     sMaxAge:              3600,
 *     staleWhileRevalidate: 60,
 *     staleIfError:         86400,
 *   }));
 *   // → "public, s-maxage=3600, stale-while-revalidate=60, stale-if-error=86400"
 *
 *   res.setHeader("Cache-Control", b.cdnCacheControl.build({
 *     private: true, maxAge: 0, noStore: true,
 *   }));
 *   // → "private, max-age=0, no-store"
 */
function build(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new CdnCacheControlError("cdn-cache-control/bad-opts",
      "build: opts must be a non-null object", true);
  }
  // Conflict check: public + private is incoherent per RFC 9111 §5.2.2;
  // operators almost always meant one or the other.
  if (opts.public === true && opts.private === true) {
    throw new CdnCacheControlError("cdn-cache-control/conflicting-visibility",
      "build: cannot set both 'public' and 'private' (RFC 9111 §5.2.2.5/§5.2.2.6)");
  }

  var seen = {};
  var parts = [];

  // Visibility booleans first (operator-facing readability)
  if (opts.public  === true) { parts.push("public");  seen.public  = true; }
  if (opts.private === true) { parts.push("private"); seen.private = true; }

  // Numeric directives, both camelCase and raw kebab-case keys
  var numericKeys = [
    "maxAge", "max-age",
    "sMaxAge", "s-maxage",
    "staleWhileRevalidate", "stale-while-revalidate",
    "staleIfError", "stale-if-error",
    "minFresh", "min-fresh",
    "maxStale", "max-stale",
  ];
  for (var i = 0; i < numericKeys.length; i += 1) {
    var k = numericKeys[i];
    if (opts[k] === undefined || opts[k] === null) continue;
    if (!_isNonNegInt(opts[k])) {
      throw new CdnCacheControlError("cdn-cache-control/bad-numeric",
        "build: " + k + " must be a non-negative finite integer (got " +
        typeof opts[k] + " " + String(opts[k]) + ")");
    }
    var kebab = KEBAB[k] || k;
    if (!seen[kebab]) {
      parts.push(kebab + "=" + opts[k]);
      seen[kebab] = true;
    }
  }

  // Remaining boolean directives
  var boolKeys = [
    "noStore", "no-store",
    "noCache", "no-cache",
    "mustRevalidate",  "must-revalidate",
    "proxyRevalidate", "proxy-revalidate",
    "mustUnderstand",  "must-understand",
    "noTransform",     "no-transform",
    "immutable",
  ];
  for (var j = 0; j < boolKeys.length; j += 1) {
    var bk = boolKeys[j];
    if (opts[bk] === true) {
      var bkebab = KEBAB[bk] || bk;
      if (!seen[bkebab]) {
        parts.push(bkebab);
        seen[bkebab] = true;
      }
    } else if (opts[bk] !== undefined && opts[bk] !== false && opts[bk] !== null) {
      throw new CdnCacheControlError("cdn-cache-control/bad-boolean",
        "build: " + bk + " must be a boolean (got " + typeof opts[bk] + ")");
    }
  }

  // Operator-supplied extension directives (must be RFC 7234 tchar
  // shape; values are either `true` for bare token or string/number
  // for token=value). Refuses delimiter / control / whitespace in
  // keys so the assembled list can't carry an injection.
  if (opts.extensions !== undefined && opts.extensions !== null) {
    validateOpts.optionalPlainObject(opts.extensions, "opts.extensions",
      CdnCacheControlError, "cdn-cache-control/bad-extensions",
      "non-null object of <directive-key>: true | token-string | non-negative integer");
    var ekeys = Object.keys(opts.extensions);
    // Bound directive-key + value length BEFORE regex test so a
    // multi-MB attacker-supplied string can't burn CPU on the tchar
    // regex. RFC 7234 §5.2 token directives are tiny in practice
    // (max-age = 7 chars, stale-while-revalidate = 22); 64 is the
    // operator-headroom ceiling.
    var DIRECTIVE_MAX = 64;                                                                        // directive key/value length cap
    for (var e = 0; e < ekeys.length; e += 1) {
      var ek = ekeys[e];
      if (ek.length === 0 || ek.length > DIRECTIVE_MAX || !DIRECTIVE_KEY_RE.test(ek)) {
        throw new CdnCacheControlError("cdn-cache-control/bad-extension-key",
          "build: extensions['" + ek + "'] — key must match RFC 7234 §5.2 token grammar " +
          "(<= " + DIRECTIVE_MAX + " chars)");
      }
      if (seen[ek]) continue;
      var ev = opts.extensions[ek];
      if (ev === true) {
        parts.push(ek);
        seen[ek] = true;
      } else if (typeof ev === "string") {
        // Value must be either RFC 7234 token OR sf-string quoted.
        // We only emit unquoted-token form; operators with delimiter
        // chars must pre-quote and supply via raw header set.
        if (ev.length === 0 || ev.length > DIRECTIVE_MAX || !DIRECTIVE_KEY_RE.test(ev)) {
          throw new CdnCacheControlError("cdn-cache-control/bad-extension-value",
            "build: extensions['" + ek + "'] string value must match RFC 7234 §5.2 token grammar " +
            "(<= " + DIRECTIVE_MAX + " chars); " +
            "for quoted-string values set the header directly");
        }
        parts.push(ek + "=" + ev);
        seen[ek] = true;
      } else if (_isNonNegInt(ev)) {
        parts.push(ek + "=" + ev);
        seen[ek] = true;
      } else {
        throw new CdnCacheControlError("cdn-cache-control/bad-extension-value",
          "build: extensions['" + ek + "'] must be true | token-string | non-negative integer");
      }
    }
  }

  if (parts.length === 0) {
    throw new CdnCacheControlError("cdn-cache-control/empty",
      "build: no directives supplied — refuse to emit an empty Cache-Control list");
  }
  return parts.join(", ");
}

/**
 * @primitive b.cdnCacheControl.parse
 * @signature b.cdnCacheControl.parse(headerValue)
 * @since     0.8.91
 * @status    stable
 * @related   b.cdnCacheControl.build
 *
 * Parse a Cache-Control-style directive list (from any RFC 9213
 * targeted header) into a normalized object. Returns `null` for
 * absent / empty / non-string input — operator code branches on
 * `null` vs the populated shape.
 *
 * Numeric directives are surfaced as camelCase number fields
 * (`maxAge`, `sMaxAge`, `staleWhileRevalidate`, `staleIfError`,
 * `minFresh`, `maxStale`); boolean directives as camelCase boolean
 * fields. Unknown directives land in `directives` (a `name → value`
 * map where boolean directives map to `true` and value-bearing
 * directives map to the raw string).
 *
 * Defensive parser: tolerates trailing semicolons, repeated whitespace,
 * and unquoted-quoted-string values; refuses control characters in
 * the header value (CR/LF/NUL/DEL header-injection shape) by throwing
 * `cdn-cache-control/bad-header-value`. ASCII HT remains permitted
 * (structural folding whitespace).
 *
 * @example
 *   b.cdnCacheControl.parse("public, s-maxage=3600, stale-while-revalidate=60");
 *   // → { public: true, sMaxAge: 3600, staleWhileRevalidate: 60, directives: {} }
 *
 *   b.cdnCacheControl.parse("private, no-store, x-foo=bar");
 *   // → { private: true, noStore: true, directives: { "x-foo": "bar" } }
 */
function parse(headerValue) {
  if (typeof headerValue !== "string") return null;
  structuredFields.refuseControlBytes(headerValue, {
    ErrorClass: CdnCacheControlError,
    code:       "cdn-cache-control/bad-header-value",
    label:      "parse",
  });
  var trimmed = headerValue.trim();
  if (trimmed.length === 0) return null;

  var out = { directives: {} };
  var kvps = structuredFields.parseKeyValuePieces(
    structuredFields.splitTopLevel(trimmed, ","));
  for (var p = 0; p < kvps.length; p += 1) {
    var kvp = kvps[p];
    var key, val, bare;
    if (kvp.value === null) {
      key = kvp.key;
      val = "";
      bare = true;
    }
    else {
      key = kvp.key;
      val = kvp.value.trim();
      bare = false;
      // Unquote sf-string per RFC 8941 §3.3.3 (defensive — operators
      // routinely emit `s-maxage="3600"` even though the directive is
      // numeric, and the spec says quoted-string is also valid). The
      // RFC 9111 `private="Authorization, Cookie"` qualified form
      // arrives here too — the top-level comma splitter already
      // preserved the inner comma; this just strips the surrounding
      // quotes so operators read the field-name list directly.
      var _unq = structuredFields.unquoteSfString(val);
      if (_unq !== null) val = _unq;
    }
    if (key.length === 0) continue;

    // Numeric directive → coerce to non-negative integer or skip.
    // RFC 9111 §5.2.1.2: bare `max-stale` (no argument) means "accept
    // a stale response of any age" — surface as Infinity rather than
    // coercing Number(true) === 1 (which would materially change
    // request semantics and reject otherwise-acceptable cached
    // responses). Other numeric directives in bare form aren't
    // RFC-defined; treat their bare form as absent.
    if (NUMERIC_DIRECTIVES.indexOf(key) !== -1) {
      if (bare) {
        if (key === "max-stale") {
          out[_camel(key)] = Infinity;
        }
        continue;
      }
      // RFC 9111 delta-seconds is 1*DIGIT — Number() would also accept hex
      // ("0x10"), exponential ("1e3"), and surrounding whitespace, which are
      // not valid cache-directive values. Round-trip parseInt to require pure
      // decimal digits.
      var n = parseInt(val, 10);
      if (Number.isFinite(n) && n >= 0 && String(n) === val) {
        out[_camel(key)] = n;
      }
      continue;
    }
    // Boolean directive → presence == enabled. RFC 9111 §5.2.2.6
    // (`private`) and §5.2.2.4 (`no-cache`) carry an OPTIONAL field-
    // name list as a qualified-form argument: `private="Authorization"`
    // means "only Authorization is the private bit". The directive is
    // STILL enabled — the argument narrows the scope, not the verdict.
    // A previous version coerced (val === "" || val === "true") which
    // inverted the meaning of a qualified directive.
    if (BOOLEAN_DIRECTIVES.indexOf(key) !== -1) {
      out[_camel(key)] = true;
      // Qualified form: surface the field-name list on `fields` so
      // operators reading the parse output can apply the narrower
      // scope without re-parsing.
      if (!bare && val.length > 0) {
        if (!out.fields) out.fields = {};
        out.fields[_camel(key)] = _splitFieldNameList(val);
      }
      continue;
    }
    // Unknown / extension directive → land in `directives` map.
    // Bare form → true; valued form → the (possibly unquoted) string.
    out.directives[key] = bare ? true : val;
  }
  return out;
}

// Field-name list (RFC 9111 §5.2.2.6 `private="A, B"`). Inner
// comma-separated header-field-name list; values are tokens per
// RFC 9110 §5.1. Lowercased + trimmed per piece.
function _splitFieldNameList(s) {
  var parts = s.split(",");
  var out = [];
  for (var i = 0; i < parts.length; i += 1) {
    var t = parts[i].trim();
    if (t.length > 0) out.push(t.toLowerCase());
  }
  return out;
}

// Reverse of KEBAB — directive-name → camelCase the parser surfaces.
// Maintained explicitly because `s-maxage` has no internal hyphen
// (the spec spells it `s-maxage`, not `s-max-age`) so a generic
// kebab → camel transform produces `sMaxage`. We want `sMaxAge` so
// the parse output mirrors the build input.
var CAMEL_OVERRIDE = {
  "s-maxage": "sMaxAge",
};
function _camel(kebab) {
  if (CAMEL_OVERRIDE[kebab]) return CAMEL_OVERRIDE[kebab];
  return kebab.replace(/-([a-z])/g, function (_, ch) { return ch.toUpperCase(); });
}

/**
 * @primitive b.cdnCacheControl.isTargetedHeader
 * @signature b.cdnCacheControl.isTargetedHeader(headerName)
 * @since     0.8.91
 * @status    stable
 * @related   b.cdnCacheControl.parse, b.cdnCacheControl.build
 *
 * Returns `true` when `headerName` matches one of the well-known RFC
 * 9213 targeted header names (case-insensitive). Operators auditing
 * an inbound response's cache headers walk the response headers and
 * call this to identify which directive lists were intended for which
 * cache class.
 *
 * @example
 *   b.cdnCacheControl.isTargetedHeader("CDN-Cache-Control");       // → true
 *   b.cdnCacheControl.isTargetedHeader("cloudflare-cdn-cache-control"); // → true
 *   b.cdnCacheControl.isTargetedHeader("Cache");                   // → false
 */
function isTargetedHeader(headerName) {
  if (typeof headerName !== "string" || headerName.length === 0) return false;
  return Object.prototype.hasOwnProperty.call(TARGETED_LC, headerName.toLowerCase());
}

module.exports = {
  build:              build,
  parse:              parse,
  isTargetedHeader:   isTargetedHeader,
  TARGETED_HEADERS:   TARGETED_HEADERS,
  BOOLEAN_DIRECTIVES: BOOLEAN_DIRECTIVES,
  NUMERIC_DIRECTIVES: NUMERIC_DIRECTIVES,
  CdnCacheControlError: CdnCacheControlError,
};

// Reserved for future field validation paths; kept in canonical
// require ordering.
void numericBounds;
void validateOpts;
