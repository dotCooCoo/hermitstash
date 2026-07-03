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

var numericChecks = require("./numeric-checks");
var { SlugError } = require("./framework-error");
var _err = SlugError.factory;

// ---- Defaults ----

// Default slug max length — 0x50 (80 chars). Long enough for nearly any
// title, short enough to keep URLs / file paths comfortable on every OS.
var DEFAULT_SLUG_MAX_LENGTH = 0x50;

var DEFAULTS = Object.freeze({
  separator:       "-",
  lowercase:       true,
  maxLength:       DEFAULT_SLUG_MAX_LENGTH,
  preserveUnicode: false,
  fallback:        "",
});

// Common reserved web slugs. Operators extend (e.g. via Set union with
// router.getReservedSlugs()) and pass into b.slug.unique's isUsed predicate.
// Returned as a fresh Set on each access via the getter so callers cannot
// mutate the shared reference.
var _RESERVED = Object.freeze([
  "admin", "api", "auth", "login", "logout", "signup", "signin", "signout",
  "register", "settings", "account", "profile", "users", "user", "me",
  "static", "assets", "public", "favicon.ico", "robots.txt", "sitemap.xml",
  "health", "metrics", "ping", "status",
  "docs", "doc", "help", "support", "terms", "privacy", "legal",
  "search", "feed", "rss", "atom",
  "new", "edit", "delete", "create", "update",
]);

// ---- Call-site validation helpers (throw on bad input) ----

var _isPositiveInt = numericChecks.isPositiveInt;

function _validateOpts(name, opts) {
  if (typeof opts.separator !== "string" || opts.separator.length !== 1) {
    throw _err("BAD_OPT", name + ": separator must be a single-character string, got " +
      typeof opts.separator + " " + JSON.stringify(opts.separator), true);
  }
  if (typeof opts.lowercase !== "boolean") {
    throw _err("BAD_OPT", name + ": lowercase must be a boolean, got " + typeof opts.lowercase, true);
  }
  if (opts.maxLength !== null && !_isPositiveInt(opts.maxLength)) {
    throw _err("BAD_OPT", name + ": maxLength must be a positive integer or null, got " +
      typeof opts.maxLength + " " + JSON.stringify(opts.maxLength), true);
  }
  if (typeof opts.preserveUnicode !== "boolean") {
    throw _err("BAD_OPT", name + ": preserveUnicode must be a boolean, got " +
      typeof opts.preserveUnicode, true);
  }
  if (typeof opts.fallback !== "string") {
    throw _err("BAD_OPT", name + ": fallback must be a string, got " + typeof opts.fallback, true);
  }
}

// ---- Core slugify ----

// Drops Unicode marks (combining accents) after NFKD decomposition.
// The two regexes are pre-compiled because slug() is on the hot path
// for any title-driven workflow (uploads, bundle creation, seeders).
var _COMBINING_MARKS = /\p{M}+/gu;
// Anything outside ASCII alphanumeric → separator (default ASCII path).
var _NON_ASCII_ALNUM = /[^a-zA-Z0-9]+/g;
// Unicode-preserving path: drop punctuation, symbols, separators only.
// \p{P} = Punctuation, \p{S} = Symbol, \p{Z} = Separator (incl. spaces),
// \p{C} = Control/format. Letters and Numbers in any script pass through.
var _UNICODE_NON_ALNUM = /[\p{P}\p{S}\p{Z}\p{C}]+/gu;

function _slugify(title, opts) {
  if (typeof title !== "string") {
    throw _err("BAD_TITLE", "slug: title must be a string, got " + typeof title, true);
  }

  var sep = opts.separator;

  var s = title;

  if (opts.preserveUnicode) {
    s = s.normalize("NFC");
    s = s.replace(_UNICODE_NON_ALNUM, sep);
  } else {
    s = s.normalize("NFKD").replace(_COMBINING_MARKS, "");
    s = s.replace(_NON_ASCII_ALNUM, sep);
  }

  if (opts.lowercase) {
    // Use locale-independent toLowerCase for both paths so slug output
    // is deterministic across hosts (Turkish-locale dotted-i etc. would
    // otherwise drift).
    s = s.toLowerCase();
  }

  // Collapse runs of the chosen separator + trim leading/trailing
  // separators, character-by-character. _validateOpts enforces
  // sep.length === 1, so a linear scan is correct and avoids
  // compiling a regex from operator input.
  s = _collapseAndTrim(s, sep);

  if (opts.maxLength !== null && s.length > opts.maxLength) {
    s = _truncateAtSeparator(s, opts.maxLength, sep);
  }

  if (s.length === 0) return opts.fallback;
  return s;
}

// Single-pass collapse + trim — replaces the dynamic-RegExp-on-sep pair
// previously used here. sep is enforced 1-char by _validateOpts.
function _collapseAndTrim(s, sep) {
  if (s.length === 0) return s;
  var out = "";
  var lastWasSep = true;   // suppress leading separators
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
  // Strip a trailing separator (the loop emits one if the last
  // non-collapsed run was separator).
  if (out.length > 0 && out.charAt(out.length - 1) === sep) {
    out = out.slice(0, out.length - 1);
  }
  return out;
}

// Truncate at the last separator that keeps length ≤ maxLength.
// If there's no separator within the cap, fall back to char truncation
// (single-token long inputs).
function _truncateAtSeparator(s, maxLength, sep) {
  if (s.length <= maxLength) return s;
  var slice = s.slice(0, maxLength);
  var lastSep = slice.lastIndexOf(sep);
  if (lastSep > 0) return slice.slice(0, lastSep);
  return slice;
}

// ---- Public surface ----

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
  // Bound function: per-call opts override creator opts.
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
    throw _err("BAD_ISUSED", "slug.unique: isUsed must be a function, got " + typeof isUsed, true);
  }
  callOpts = callOpts || {};
  var opts = Object.assign({}, DEFAULTS, callOpts);
  _validateOpts("slug.unique", opts);

  var maxAttempts = (callOpts.maxAttempts !== undefined) ? callOpts.maxAttempts : 100;
  if (!_isPositiveInt(maxAttempts)) {
    throw _err("BAD_OPT", "slug.unique: maxAttempts must be a positive integer, got " +
      typeof maxAttempts + " " + JSON.stringify(maxAttempts), true);
  }
  var start = (callOpts.start !== undefined) ? callOpts.start : 2;
  if (!_isPositiveInt(start)) {
    throw _err("BAD_OPT", "slug.unique: start must be a positive integer, got " +
      typeof start + " " + JSON.stringify(start), true);
  }
  var suffixSep = (callOpts.suffixSeparator !== undefined) ? callOpts.suffixSeparator : opts.separator;
  if (typeof suffixSep !== "string" || suffixSep.length === 0) {
    throw _err("BAD_OPT", "slug.unique: suffixSeparator must be a non-empty string, got " +
      typeof suffixSep, true);
  }

  var base = _slugify(title, opts);
  // First attempt: bare base.
  var used = await isUsed(base);
  if (!used) return base;

  // Subsequent attempts: base + suffixSep + n, starting at `start`.
  // The bare base counted as attempt 1; we have maxAttempts-1 numeric tries left.
  for (var i = 0; i < maxAttempts - 1; i++) {
    var n = start + i;
    var candidate = base + suffixSep + n;
    // If maxLength would be exceeded by the suffix, truncate the base further
    // so the final candidate fits.
    if (opts.maxLength !== null && candidate.length > opts.maxLength) {
      var roomForBase = opts.maxLength - (suffixSep.length + String(n).length);
      if (roomForBase < 1) {
        // Pathological case: caller's maxLength can't hold any base with this suffix.
        throw _err("UNIQUE_EXHAUSTED",
          "slug.unique: maxLength " + opts.maxLength + " too small for suffix '" +
          suffixSep + n + "' (base would need " + roomForBase + " chars)", true);
      }
      var truncBase = _truncateAtSeparator(base, roomForBase, opts.separator);
      candidate = truncBase + suffixSep + n;
    }
    var taken = await isUsed(candidate);
    if (!taken) return candidate;
  }

  throw _err("UNIQUE_EXHAUSTED",
    "slug.unique: exhausted " + maxAttempts + " attempts for base '" + base + "'", true);
}

// b.slug is the function itself with sub-API hung off it (callable
// namespace pattern). Operators get the 90% case (`b.slug("title")`) in
// one line and reach the rest via `b.slug.create`, `b.slug.unique`,
// `b.slug.RESERVED`, `b.slug.DEFAULTS`, `b.slug.SlugError`.
//
// The shared RESERVED Set is intentionally mutable so an app can
// extend it once at boot:
//   b.slug.RESERVED.add("my-reserved-route");
slug.create    = create;
slug.unique    = unique;
slug.RESERVED  = new Set(_RESERVED);
slug.DEFAULTS  = DEFAULTS;
slug.SlugError = SlugError;

module.exports = slug;
