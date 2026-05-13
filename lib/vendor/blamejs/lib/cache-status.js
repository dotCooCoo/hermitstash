"use strict";
/**
 * @module     b.cacheStatus
 * @nav        HTTP
 * @title      RFC 9211 Cache-Status
 * @order      310
 *
 * @intro
 *   RFC 9211 Cache-Status response header builder + parser. The
 *   `Cache-Status` header documents which intermediate cache (CDN,
 *   reverse proxy, application cache) handled a request — operators
 *   diagnosing why a request was slow / stale / not-cached read the
 *   header and see the entire cache-decision chain instead of
 *   guessing from elapsed-time metrics.
 *
 *   Each cache in the response path appends a comma-separated entry:
 *
 *     Cache-Status: ExampleCache; hit; fwd=stale; ttl=600
 *
 *   Where:
 *     - The first token is the cache identifier (sf-string)
 *     - Parameters follow as `key` or `key=value` pairs
 *     - Standard parameters per RFC 9211 §2: `hit`, `fwd`, `fwd-status`,
 *       `ttl`, `stored`, `collapsed`, `key`, `detail`
 *
 *   `b.cacheStatus.append(prevHeader, entry)` builds a single
 *   well-formed entry and appends to whatever previous caches in the
 *   chain wrote. `b.cacheStatus.parse(headerValue)` returns the
 *   parsed chain as an array of `{ cache, params }` records.
 *
 * @card
 *   RFC 9211 Cache-Status header — documents which intermediate caches handled a request with structured `hit` / `fwd` / `ttl` parameters so operators diagnose cache-decision chains.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var CacheStatusError = defineClass("CacheStatusError", { alwaysPermanent: true });

// RFC 9211 §2 — cache identifier is a Structured-Fields Item: sf-token
// (RFC 8941 §3.3.4) OR sf-string. We accept sf-token shape bare; an
// operator wanting an identifier with sf-delimiter chars (comma /
// semicolon / quote / backslash / whitespace) can emit it quoted via
// the operator-side sf-string form themselves, but this builder
// refuses raw delimiters since they would split into multiple list
// members or break the parameter grammar downstream. Token grammar
// per RFC 8941: starts with ALPHA or "*", continues with tchar / ":"
// / "/". tchar excludes `, ; " \ space and all controls.
var CACHE_NAME_RE   = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*$/;                                 // allow:duplicate-regex — sf-token shape per RFC 8941 §3.3.4
var CACHE_NAME_MAX  = 128;                                                                         // allow:raw-byte-literal — cache-name length cap, not bytes
var FWD_VALUES = Object.freeze(["bypass", "method", "uri-miss", "vary-miss", "miss", "request", "stale", "partial"]);
var BOOLEAN_PARAMS = Object.freeze(["hit", "stored", "collapsed"]);
// Reserved parameter names per RFC 9211 §2 — the framework knows their
// semantics (hit/stored/collapsed are flags, fwd is enum, ttl is number,
// fwd-status is HTTP status, key + detail are sf-strings). Operators
// passing other keys get passed-through verbatim as token=value.
var KNOWN_PARAMS = Object.freeze(["hit", "fwd", "fwd-status", "ttl", "stored", "collapsed", "key", "detail"]);

function _sfStringQuote(s) {
  // RFC 8941 sf-string — quoted-string with escaping for " and \.
  // Operator-supplied detail/key strings get the full quote-escape.
  return "\"" + String(s).replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + "\"";
}

/**
 * @primitive b.cacheStatus.append
 * @signature b.cacheStatus.append(prevHeader, entry)
 * @since     0.8.86
 * @status    stable
 * @related   b.cacheStatus.parse, b.cacheStatus.entry
 *
 * Append a Cache-Status entry to an existing chain header. `prevHeader`
 * is the inbound Cache-Status string (empty / undefined / null means
 * "this is the first entry"). `entry` is an object describing the
 * current cache's decision. Returns the combined header string.
 *
 * @opts
 *   cache:      string,  // required — cache identifier (e.g. "ExampleCDN")
 *   hit:        boolean, // true if served from cache
 *   fwd:        string,  // one of: bypass | method | uri-miss | vary-miss
 *                        //          | miss | request | stale | partial
 *   fwdStatus:  number,  // HTTP status the upstream returned (when fwd)
 *   ttl:        number,  // remaining freshness lifetime in seconds
 *   stored:     boolean, // true if the response was newly stored
 *   collapsed:  boolean, // true if request-collapsing merged this with another
 *   key:        string,  // operator-defined cache-key shape
 *   detail:     string,  // free-form diagnostic note
 *
 * @example
 *   res.setHeader("Cache-Status",
 *     b.cacheStatus.append(req.headers["cache-status"], {
 *       cache: "blamejs",
 *       hit:   false,
 *       fwd:   "miss",
 *       stored: true,
 *       ttl:   3600,
 *     }));
 *   // → "ExampleCDN; hit; ttl=300, blamejs; fwd=miss; stored; ttl=3600"
 */
function append(prevHeader, entry) {
  var formatted = entryString(entry);
  if (typeof prevHeader === "string" && prevHeader.length > 0) {
    return prevHeader + ", " + formatted;
  }
  return formatted;
}

/**
 * @primitive b.cacheStatus.entry
 * @signature b.cacheStatus.entry(entry)
 * @since     0.8.86
 * @status    stable
 * @related   b.cacheStatus.append, b.cacheStatus.parse
 *
 * Format a single Cache-Status entry without combining with a prior
 * chain. Useful when the operator wants to write the header without
 * regard to upstream entries (e.g. an origin-only deployment).
 *
 * @example
 *   res.setHeader("Cache-Status", b.cacheStatus.entry({
 *     cache: "blamejs", hit: true, ttl: 600,
 *   }));
 *   // → "blamejs; hit; ttl=600"
 */
function entryString(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    throw new CacheStatusError("cache-status/bad-entry",
      "entry must be a non-null object", true);
  }
  validateOpts.requireNonEmptyString(
    entry.cache, "entry.cache", CacheStatusError, "cache-status/bad-cache-name");
  if (entry.cache.length > CACHE_NAME_MAX || !CACHE_NAME_RE.test(entry.cache)) {
    throw new CacheStatusError("cache-status/bad-cache-name",
      "entry.cache '" + entry.cache + "' must be a structured-fields token " +
      "(RFC 8941 §3.3.4: starts with ALPHA or '*', uses tchar / ':' / '/' only — " +
      "no comma / semicolon / quote / backslash / whitespace) and <= " +
      CACHE_NAME_MAX + " chars. Quote-and-escape an operator-supplied label " +
      "via b.cacheStatus.entry({ ..., key: '<label>' }) instead.");
  }
  var parts = [entry.cache];

  // Booleans — emit as bare-token when truthy.
  for (var i = 0; i < BOOLEAN_PARAMS.length; i += 1) {
    if (entry[BOOLEAN_PARAMS[i]] === true) parts.push(BOOLEAN_PARAMS[i]);
  }

  if (entry.fwd !== undefined && entry.fwd !== null) {
    if (typeof entry.fwd !== "string" || FWD_VALUES.indexOf(entry.fwd) === -1) {
      throw new CacheStatusError("cache-status/bad-fwd",
        "entry.fwd must be one of " + FWD_VALUES.join(", "));
    }
    parts.push("fwd=" + entry.fwd);
  }
  if (entry.fwdStatus !== undefined && entry.fwdStatus !== null) {
    if (typeof entry.fwdStatus !== "number" || !Number.isInteger(entry.fwdStatus) ||
        entry.fwdStatus < 100 || entry.fwdStatus > 599) {                                          // allow:raw-byte-literal — HTTP status range
      throw new CacheStatusError("cache-status/bad-fwd-status",
        "entry.fwdStatus must be an integer 100..599");
    }
    parts.push("fwd-status=" + entry.fwdStatus);
  }
  if (entry.ttl !== undefined && entry.ttl !== null) {
    // RFC 9211 §2.2 — ttl is a signed Integer. Negative values are
    // explicitly valid: a `hit` paired with `ttl=-30` reports the
    // response was served stale by 30 seconds (typically with
    // `fwd=stale`). Refusing negatives would block the very scenario
    // `fwd=stale` exists to surface.
    if (typeof entry.ttl !== "number" || !Number.isInteger(entry.ttl)) {
      throw new CacheStatusError("cache-status/bad-ttl",
        "entry.ttl must be an integer (negative permitted for stale-cache hits per RFC 9211 §2.2)");
    }
    parts.push("ttl=" + entry.ttl);
  }
  if (entry.key !== undefined && entry.key !== null) {
    if (typeof entry.key !== "string") {
      throw new CacheStatusError("cache-status/bad-key",
        "entry.key must be a string when provided");
    }
    parts.push("key=" + _sfStringQuote(entry.key));
  }
  if (entry.detail !== undefined && entry.detail !== null) {
    if (typeof entry.detail !== "string") {
      throw new CacheStatusError("cache-status/bad-detail",
        "entry.detail must be a string when provided");
    }
    parts.push("detail=" + _sfStringQuote(entry.detail));
  }
  return parts.join("; ");
}

/**
 * @primitive b.cacheStatus.parse
 * @signature b.cacheStatus.parse(headerValue)
 * @since     0.8.86
 * @status    stable
 * @related   b.cacheStatus.append, b.cacheStatus.entry
 *
 * Parse a Cache-Status header into an array of `{ cache, params }`
 * records, one per cache in the chain. The params object carries the
 * RFC 9211 §2 standard parameters as proper types (`hit`/`stored`/
 * `collapsed` as booleans, `ttl`/`fwdStatus` as numbers, `fwd` as the
 * raw enum string, `key`/`detail` as unquoted strings). Unknown
 * params survive as raw string values so operators inspecting custom
 * cache implementations can read them.
 *
 * Empty / non-string / malformed inputs return `[]` — defensive
 * request-shape reader returns sane defaults rather than throwing.
 *
 * @example
 *   var chain = b.cacheStatus.parse(
 *     'ExampleCDN; hit; ttl=300, blamejs; fwd=miss; stored; ttl=3600');
 *   // chain[0] = { cache: "ExampleCDN", params: { hit: true, ttl: 300 } }
 *   // chain[1] = { cache: "blamejs", params: { fwd: "miss", stored: true, ttl: 3600 } }
 */
function parse(headerValue) {
  if (typeof headerValue !== "string" || headerValue.length === 0) return [];
  var out = [];
  // Split entries on commas NOT inside quoted strings.
  var entries = _splitTopLevel(headerValue, ",");
  for (var i = 0; i < entries.length; i += 1) {
    var raw = entries[i].trim();
    if (raw.length === 0) continue;
    var fields = _splitTopLevel(raw, ";").map(function (s) { return s.trim(); });
    var cache = fields.shift();
    if (!cache) continue;
    var params = {};
    for (var j = 0; j < fields.length; j += 1) {
      var f = fields[j];
      if (f.length === 0) continue;
      var eq = f.indexOf("=");
      if (eq === -1) {
        // Bare token — boolean
        params[f] = true;
        continue;
      }
      var name = f.slice(0, eq).trim();
      var val  = f.slice(eq + 1).trim();
      params[_normalizeParamName(name)] = _parseParamValue(name, val);
    }
    out.push({ cache: cache, params: params });
  }
  return out;
}

function _normalizeParamName(n) {
  // RFC 9211 §2 uses fwd-status as the canonical name; surface as
  // `fwdStatus` in the parsed object for JS-natural access.
  if (n === "fwd-status") return "fwdStatus";
  return n;
}

function _parseParamValue(name, raw) {
  if (raw.length >= 2 && raw.charAt(0) === "\"" && raw.charAt(raw.length - 1) === "\"") {
    // sf-string — unquote + unescape.
    return raw.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  if (name === "ttl" || name === "fwd-status" || name === "fwdStatus") {
    var n = Number(raw);
    return Number.isFinite(n) ? n : raw;
  }
  return raw;
}

function _splitTopLevel(s, sep) {
  var out = [];
  var buf = "";
  var inQuotes = false;
  var escaped = false;
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charAt(i);
    if (escaped) { buf += c; escaped = false; continue; }
    if (c === "\\" && inQuotes) { buf += c; escaped = true; continue; }
    if (c === "\"") { inQuotes = !inQuotes; buf += c; continue; }
    if (c === sep && !inQuotes) { out.push(buf); buf = ""; continue; }
    buf += c;
  }
  if (buf.length > 0) out.push(buf);
  return out;
}

module.exports = {
  append:           append,
  entry:            entryString,
  parse:            parse,
  FWD_VALUES:       FWD_VALUES,
  KNOWN_PARAMS:     KNOWN_PARAMS,
  CacheStatusError: CacheStatusError,
};
