// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.slug
 * @nav    Tools
 * @title  Slug
 *
 * @intro
 *   URL-safe slug generation with two normalization paths and a uniqueness
 *   helper.
 *
 *   The default ASCII path uses Unicode NFKD decomposition + combining-mark
 *   strip (`café` → `cafe`) and drops anything outside `[a-zA-Z0-9]`. The
 *   `preserveUnicode: true` path uses NFC and only drops Unicode
 *   punctuation, symbols, and separators — Cyrillic, Greek, CJK, and other
 *   scripts pass through. Operators with non-Latin user content opt into
 *   preserveUnicode.
 *
 *   `b.slug` is a callable function with the rest of the API hung off it
 *   (callable-namespace pattern): `b.slug.create` builds a bound slugger
 *   pre-configured with operator opts, and `b.slug.unique` resolves the
 *   first un-taken candidate against an operator-supplied `isUsed`
 *   predicate (numeric suffixes `-2`, `-3`, … on collision).
 *
 *   Validation policy: opts and `title` are validated at the call site
 *   (throw on bad input). Titles that normalize to empty are tolerant —
 *   `opts.fallback` is returned instead of throwing. `unique()` exhausting
 *   `maxAttempts` throws `SlugError`.
 *
 *   Reserved web slugs (admin, api, login, …) live on `b.slug.RESERVED`
 *   as a mutable Set; operators extend it once at boot and pass it into
 *   their `isUsed` predicate.
 *
 * @card
 *   URL-safe slug generation with two normalization paths and a uniqueness helper.
 */

var codepointClass = require("./codepoint-class");
var numericChecks = require("./numeric-checks");
var { SlugError } = require("./framework-error");
var _err = SlugError.factory;

var DEFAULT_SLUG_MAX_LENGTH = 0x50;

var DEFAULTS = Object.freeze({
  separator:       "-",
  lowercase:       true,
  maxLength:       DEFAULT_SLUG_MAX_LENGTH,
  preserveUnicode: false,
  fallback:        "",
});

var _RESERVED = Object.freeze([
  "admin", "api", "auth", "login", "logout", "signup", "signin", "signout",
  "register", "settings", "account", "profile", "users", "user", "me",
  "static", "assets", "public", "favicon.ico", "robots.txt", "sitemap.xml",
  "health", "metrics", "ping", "status",
  "docs", "doc", "help", "support", "terms", "privacy", "legal",
  "search", "feed", "rss", "atom",
  "new", "edit", "delete", "create", "update",
]);

var _isPositiveInt = numericChecks.isPositiveInt;

function _validateOpts(name, opts) {
  if (typeof opts.separator !== "string" || opts.separator.length !== 1) {
    throw _err("slug/bad-opt", name + ": separator must be a single-character string, got " +
      typeof opts.separator + " " + JSON.stringify(opts.separator), true);
  }
  if (typeof opts.lowercase !== "boolean") {
    throw _err("slug/bad-opt", name + ": lowercase must be a boolean, got " + typeof opts.lowercase, true);
  }
  if (opts.maxLength !== null && !_isPositiveInt(opts.maxLength)) {
    throw _err("slug/bad-opt", name + ": maxLength must be a positive integer or null, got " +
      typeof opts.maxLength + " " + JSON.stringify(opts.maxLength), true);
  }
  if (typeof opts.preserveUnicode !== "boolean") {
    throw _err("slug/bad-opt", name + ": preserveUnicode must be a boolean, got " +
      typeof opts.preserveUnicode, true);
  }
  if (typeof opts.fallback !== "string") {
    throw _err("slug/bad-opt", name + ": fallback must be a string, got " + typeof opts.fallback, true);
  }
}

var _COMBINING_MARKS = /\p{M}+/gu;
function _asciiAlnumToSeparator(s, sep) {
  var out = "";
  var inRun = false;
  for (var i = 0; i < s.length; i += 1) {
    if (codepointClass.isAsciiAlnum(s.charCodeAt(i))) {
      out += s.charAt(i);
      inRun = false;
    } else if (!inRun) {
      out += sep;
      inRun = true;
    }
  }
  return out;
}
var _UNICODE_NON_ALNUM = /[\p{P}\p{S}\p{Z}\p{C}]+/gu;

function _slugify(title, opts) {
  if (typeof title !== "string") {
    throw _err("slug/bad-title", "slug: title must be a string, got " + typeof title, true);
  }

  var sep = opts.separator;

  var s = title;

  if (opts.preserveUnicode) {
    s = s.normalize("NFC");
    s = s.replace(_UNICODE_NON_ALNUM, sep);
  } else {
    s = s.normalize("NFKD").replace(_COMBINING_MARKS, "");
    s = _asciiAlnumToSeparator(s, sep);
  }

  if (opts.lowercase) {
    s = s.toLowerCase();
  }

  s = _collapseAndTrim(s, sep);

  if (opts.maxLength !== null && s.length > opts.maxLength) {
    s = _truncateAtSeparator(s, opts.maxLength, sep);
  }

  if (s.length === 0) return opts.fallback;
  return s;
}

function _collapseAndTrim(s, sep) {
  if (s.length === 0) return s;
  var out = "";
  var lastWasSep = true;
  for (var i = 0; i < s.length; i++) {
    var ch = s.charAt(i);
    if (ch === sep) {
      if (lastWasSep) continue;
      lastWasSep = true;
      out += ch;
    } else {
      lastWasSep = false;
      out += ch;
    }
  }
  if (out.length > 0 && out.charAt(out.length - 1) === sep) {
    out = out.slice(0, out.length - 1);
  }
  return out;
}

function _truncateAtSeparator(s, maxLength, sep) {
  if (s.length <= maxLength) return s;
  var slice = s.slice(0, maxLength);
  var lastSep = slice.lastIndexOf(sep);
  if (lastSep > 0) return slice.slice(0, lastSep);
  return slice;
}

/**
 * @primitive b.slug
 * @signature b.slug(title, callOpts)
 * @since     0.1.0
 * @related   b.slug.create, b.slug.unique
 *
 * Slugify a title. The default path produces lowercase ASCII separated by
 * `-`: accents fold (`café` → `cafe`), runs of non-alphanumerics collapse
 * to a single separator, and the result is trimmed of leading/trailing
 * separators and capped at `maxLength` (truncating at a separator
 * boundary when possible). Empty results return `opts.fallback`.
 *
 * `preserveUnicode: true` keeps letters and digits in any script and
 * only drops punctuation/symbols/separators — the right choice for
 * non-Latin user content.
 *
 * @opts
 *   separator:       string,   // single-char join between tokens (default "-")
 *   lowercase:       boolean,  // lowercase output (default true, locale-independent)
 *   maxLength:       number,   // hard cap on output length, or null for none (default 80)
 *   preserveUnicode: boolean,  // keep non-ASCII letters/digits (default false)
 *   fallback:        string,   // returned when title normalizes to empty (default "")
 *
 * @example
 *   b.slug("Hello, World!");
 *   // → "hello-world"
 *
 *   b.slug("café résumé");
 *   // → "cafe-resume"
 *
 *   b.slug("Привет мир", { preserveUnicode: true });
 *   // → "привет-мир"
 *
 *   b.slug("a".repeat(200), { maxLength: 10 });
 *   // → "aaaaaaaaaa"
 *
 *   b.slug("---", { fallback: "untitled" });
 *   // → "untitled"
 */
function slug(title, callOpts) {
  var opts = Object.assign({}, DEFAULTS, callOpts || {});
  _validateOpts("slug", opts);
  return _slugify(title, opts);
}

/**
 * @primitive b.slug.create
 * @signature b.slug.create(creatorOpts)
 * @since     0.1.0
 * @related   b.slug, b.slug.unique
 *
 * Build a bound slugger pre-configured with operator opts. Returns a
 * function with the same signature as `b.slug` — per-call opts merge
 * over the bound opts, so the operator picks defaults once at boot and
 * call sites stay short. Useful when one section of the app slugs with
 * non-default settings (longer maxLength, Unicode-preserving, custom
 * separator).
 *
 * @opts
 *   separator:       string,   // single-char join between tokens (default "-")
 *   lowercase:       boolean,  // lowercase output (default true)
 *   maxLength:       number,   // hard cap on output length, or null for none (default 80)
 *   preserveUnicode: boolean,  // keep non-ASCII letters/digits (default false)
 *   fallback:        string,   // returned when title normalizes to empty (default "")
 *
 * @example
 *   var titleSlug = b.slug.create({ maxLength: 60, preserveUnicode: true });
 *   titleSlug("Привет мир");
 *   // → "привет-мир"
 *
 *   titleSlug("Hello, World!");
 *   // → "hello-world"
 *
 *   // Per-call opts override creator opts:
 *   titleSlug("Hello, World!", { separator: "_" });
 *   // → "hello_world"
 */
function create(creatorOpts) {
  var merged = Object.assign({}, DEFAULTS, creatorOpts || {});
  _validateOpts("slug.create", merged);
  return function boundSlug(title, callOpts) {
    var opts = Object.assign({}, merged, callOpts || {});
    _validateOpts("slug", opts);
    return _slugify(title, opts);
  };
}

/**
 * @primitive b.slug.unique
 * @signature b.slug.unique(title, isUsed, callOpts)
 * @since     0.1.0
 * @related   b.slug, b.slug.create
 *
 * Resolve the first un-taken slug for `title` against an operator-supplied
 * `isUsed(candidate)` predicate (sync or async). The bare slug is tried
 * first; on collision the function appends a numeric suffix (`-2`, `-3`,
 * …) and re-checks until `isUsed` returns falsy or `maxAttempts` is
 * exhausted. When the suffix would push past `maxLength`, the base is
 * truncated at a separator boundary so the final candidate fits. Throws
 * `SlugError` on exhaustion.
 *
 * @opts
 *   separator:       string,   // single-char join between tokens (default "-")
 *   lowercase:       boolean,  // lowercase output (default true)
 *   maxLength:       number,   // hard cap on output length, or null for none (default 80)
 *   preserveUnicode: boolean,  // keep non-ASCII letters/digits (default false)
 *   fallback:        string,   // returned when title normalizes to empty (default "")
 *   maxAttempts:     number,   // total tries including bare base (default 100)
 *   start:           number,   // first numeric suffix (default 2)
 *   suffixSeparator: string,   // separator between base and suffix (default opts.separator)
 *
 * @example
 *   var taken = new Set(["hello-world", "hello-world-2"]);
 *   async function isUsed(cand) { return taken.has(cand); }
 *
 *   var s1 = await b.slug.unique("Hello, World!", isUsed);
 *   // → "hello-world-3"
 *
 *   var s2 = await b.slug.unique("Brand New Title", isUsed);
 *   // → "brand-new-title"
 *
 *   // Custom suffix separator + start index:
 *   var s3 = await b.slug.unique("Hello, World!", isUsed, {
 *     suffixSeparator: "_",
 *     start: 10,
 *   });
 *   // → "hello-world_10"
 */
async function unique(title, isUsed, callOpts) {
  if (typeof isUsed !== "function") {
    throw _err("slug/bad-isused", "slug.unique: isUsed must be a function, got " + typeof isUsed, true);
  }
  callOpts = callOpts || {};
  var opts = Object.assign({}, DEFAULTS, callOpts);
  _validateOpts("slug.unique", opts);

  var maxAttempts = (callOpts.maxAttempts !== undefined) ? callOpts.maxAttempts : 100;
  if (!_isPositiveInt(maxAttempts)) {
    throw _err("slug/bad-opt", "slug.unique: maxAttempts must be a positive integer, got " +
      typeof maxAttempts + " " + JSON.stringify(maxAttempts), true);
  }
  var start = (callOpts.start !== undefined) ? callOpts.start : 2;
  if (!_isPositiveInt(start)) {
    throw _err("slug/bad-opt", "slug.unique: start must be a positive integer, got " +
      typeof start + " " + JSON.stringify(start), true);
  }
  var suffixSep = (callOpts.suffixSeparator !== undefined) ? callOpts.suffixSeparator : opts.separator;
  if (typeof suffixSep !== "string" || suffixSep.length === 0) {
    throw _err("slug/bad-opt", "slug.unique: suffixSeparator must be a non-empty string, got " +
      typeof suffixSep, true);
  }

  var base = _slugify(title, opts);
  var used = await isUsed(base);
  if (!used) return base;

  for (var i = 0; i < maxAttempts - 1; i++) {
    var n = start + i;
    var candidate = base + suffixSep + n;
    if (opts.maxLength !== null && candidate.length > opts.maxLength) {
      var roomForBase = opts.maxLength - (suffixSep.length + String(n).length);
      if (roomForBase < 1) {
        throw _err("slug/unique-exhausted",
          "slug.unique: maxLength " + opts.maxLength + " too small for suffix '" +
          suffixSep + n + "' (base would need " + roomForBase + " chars)", true);
      }
      var truncBase = _truncateAtSeparator(base, roomForBase, opts.separator);
      candidate = truncBase + suffixSep + n;
    }
    var taken = await isUsed(candidate);
    if (!taken) return candidate;
  }

  throw _err("slug/unique-exhausted",
    "slug.unique: exhausted " + maxAttempts + " attempts for base '" + base + "'", true);
}

slug.create    = create;
slug.unique    = unique;
slug.RESERVED  = new Set(_RESERVED);
slug.DEFAULTS  = DEFAULTS;
slug.SlugError = SlugError;

module.exports = slug;
