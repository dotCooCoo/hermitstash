// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.httpClient.cache
 * @nav    HTTP
 * @title  Http Client Cache
 * @order  150
 *
 * @intro
 *   RFC 9111 outbound HTTP cache for `b.httpClient.request`. Stores
 *   GET/HEAD responses keyed on (URL, method, sorted Vary-header
 *   values), honours `Cache-Control` directives (`no-store`, `no-cache`,
 *   `private`, `max-age`, `s-maxage`, `must-revalidate`,
 *   `proxy-revalidate`, `immutable`, `stale-while-revalidate`,
 *   `stale-if-error`), legacy `Pragma: no-cache` and `Expires`,
 *   computes freshness per RFC 9111 §4.2 (heuristic 10% rule when no
 *   explicit lifetime), revalidates with `If-None-Match` /
 *   `If-Modified-Since` and merges 304 headers into the stored entry
 *   (RFC 9111 §5).
 *
 *   Two store backends ship in-the-box: `memoryStore` (bounded LRU,
 *   per-byte and per-entry caps, eviction emits an audit event) and
 *   the explicit `Store` interface (`get` / `set` / `delete` / `clear`)
 *   so operators can wire their own — Redis, filesystem, etc. The
 *   memory store handles the common single-process case without
 *   pulling in an external dependency. Operators with shared-cache
 *   semantics across a fleet wire their own `Store` against a shared
 *   backing service.
 *
 *   Composes through `b.httpClient.request({ ..., cache })`. Without
 *   `opts.cache`, behaviour is unchanged — zero overhead for callers
 *   who don't want caching. Failures inside the cache hot path
 *   (store throws, malformed entry, revalidation network error
 *   outside `stale-if-error`) drop silent and the request falls back
 *   to the network — caching is never allowed to surface as a request
 *   failure. The same audit / observability hooks emit on every cache
 *   decision (`hit` / `miss` / `stale` / `revalidated` / `evicted`)
 *   so operators get end-to-end visibility.
 *
 * @card
 *   RFC 9111 outbound HTTP cache with bounded LRU memory store, Vary
 *   handling, conditional revalidation (ETag / If-Modified-Since), and
 *   stale-while-revalidate / stale-if-error.
 */

var C                = require("./constants");
var canonicalJson    = require("./canonical-json");
var safeUrl          = require("./safe-url");
var structuredFields = require("./structured-fields");
var validateOpts     = require("./validate-opts");
var numericBounds    = require("./numeric-bounds");
var { HttpClientError } = require("./framework-error");

// ---- Tunables ----------------------------------------------------------

// Default max bytes for the in-memory store. Bounded so a runaway
// upstream serving 1GiB responses can't OOM the process. Operators
// pick a value matched to their RAM budget.
var DEFAULT_MAX_BYTES   = C.BYTES.mib(64);
var DEFAULT_MAX_ENTRIES = 1024;

// Per RFC 9111 §4.2.2 — heuristic freshness must not exceed 24 hours
// without explicit operator opt-in (we don't expose that opt-in; if a
// downstream wants long-cached behaviour without explicit Cache-Control
// it's an upstream bug). Cap heuristic at 24h.
var HEURISTIC_MAX_AGE_MS = C.TIME.hours(24);

// Statuses RFC 9110 designates as heuristically cacheable. (Plus 200/206
// which are universally cacheable when a freshness lifetime is given.)
var CACHEABLE_STATUSES = new Set([
  200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501,                                  // allow:raw-time-literal — RFC 9111 cacheable status-code set; coincidental multiple-of-60 entries, not durations, C.TIME N/A
]);

// Headers that MUST not be forwarded when serving a 304-updated entry.
// RFC 9111 §5 — "Updating Stored Header Fields" — the listed
// hop-by-hop headers + Connection-named headers are stripped from the
// stored entry.
var HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade",
]);

function _hcErr(code, message) {
  return new HttpClientError(code, message, true);
}

// ---- Cache-Control parsing --------------------------------------------

// Parse a Cache-Control header into a structured object.
// Returns { directives: Object, raw: string }. Directives are
// lowercased; values are strings (numeric values stay strings — caller
// parses with parseInt where it makes sense).
function _parseCacheControl(value) {
  var out = Object.create(null);
  if (typeof value !== "string" || value.length === 0) return out;
  // RFC 9111 §5.2 + RFC 9110 §5.6.4 — directive arguments may be
  // quoted-string. A bare `value.split(",")` would slice through
  // `no-cache="Authorization, Cookie"` and `private="set-cookie,
  // x-foo"` and emit fake directives. Quote-aware splitter mirrors
  // cdn-cache-control's _splitTopLevelCommas (RFC 8941 §3.3.3 with
  // backslash-escape).
  var parts = structuredFields.splitTopLevel(value, ",");
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (!p) continue;
    var eq = p.indexOf("=");
    var k, v;
    if (eq === -1) { k = p; v = ""; }
    else { k = p.slice(0, eq).trim(); v = p.slice(eq + 1).trim(); }
    // Strip surrounding quotes from value.
    if (v.length >= 2 && v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
      // Single-pass RFC 8941 unescape (chained .replace() mis-decodes
      // an escaped backslash adjacent to another escape).
      v = structuredFields.unescapeSfStringBody(v.slice(1, v.length - 1));
    }
    out[k.toLowerCase()] = v;
  }
  return out;
}

function _ccNumber(directives, name) {
  if (!directives || !(name in directives)) return null;
  var n = parseInt(directives[name], 10);
  if (!isFinite(n) || n < 0) return null;
  return n;
}

function _ccPresent(directives, name) {
  return directives && Object.prototype.hasOwnProperty.call(directives, name);
}

// ---- HTTP date parsing -----------------------------------------------

function _parseHttpDate(s) {
  if (typeof s !== "string" || s.length === 0) return null;
  var t = Date.parse(s);
  return isNaN(t) ? null : t;
}

// ---- Header helpers ---------------------------------------------------

function _lcHeaders(headers) {
  var out = Object.create(null);
  if (!headers || typeof headers !== "object") return out;
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i++) {
    out[keys[i].toLowerCase()] = headers[keys[i]];
  }
  return out;
}

// Return a header value as a string. h2 sometimes returns arrays for
// repeated headers (Set-Cookie); pick the first for cache directives.
function _headerOne(headers, name) {
  if (!headers) return null;
  var v = headers[name];
  if (v === undefined || v === null) return null;
  if (Array.isArray(v)) return v.length > 0 ? String(v[0]) : null;
  return String(v);
}

// ---- Cache key -------------------------------------------------------

// Returns the canonical cache key for a (URL, method, vary-headers) tuple.
// Uses `b.canonicalJson` so the key is byte-stable regardless of property
// insertion order.
function _normalizeUrl(url) {
  // Strip fragment per RFC 9111 §2 (cache uses URI without fragment).
  // Sort query parameters for stable keying — RFC 3986 doesn't require
  // it, but two URLs that differ only in query order are semantically
  // equal for most upstreams; if an upstream genuinely cares about
  // order, the operator wires per-route cache opt-out.
  var u;
  try {
    u = safeUrl.parse(url, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
  } catch (_e) {
    return String(url);
  }
  // Reconstitute origin + path; sort search params.
  var origin = u.protocol + "//" + u.host;
  var pathOnly = u.pathname || "/";
  var search = "";
  if (u.search && u.search.length > 0) {
    var entries = [];
    u.searchParams.forEach(function (v, k) { entries.push([k, v]); });
    entries.sort(function (a, b) {
      if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
      return a[1] < b[1] ? -1 : (a[1] > b[1] ? 1 : 0);
    });
    var parts = [];
    for (var i = 0; i < entries.length; i++) {
      parts.push(encodeURIComponent(entries[i][0]) + "=" + encodeURIComponent(entries[i][1]));
    }
    if (parts.length > 0) search = "?" + parts.join("&");
  }
  return origin + pathOnly + search;
}

function _buildCacheKey(method, url, varyHeaderValues) {
  var vary = varyHeaderValues || null;
  var keyShape = {
    m: String(method || "GET").toUpperCase(),
    u: _normalizeUrl(url),
    v: vary,
  };
  return canonicalJson.stringify(keyShape);
}

// Returns a sorted-by-name array of [headerName, headerValue] pairs for
// every name listed in the response's Vary header (lowercased), reading
// values from the request headers. RFC 9110 §12.5.5: '*' means "vary on
// every request feature" — caller must treat the response as
// uncacheable.
function _extractVaryValues(varyHeader, requestHeaders) {
  if (typeof varyHeader !== "string" || varyHeader.length === 0) return [];
  var names = varyHeader.split(",").map(function (s) {                                          // RFC 9110 §12.5.5 Vary is a comma-list of field-names (token grammar); no quoted-string, so a bare split is correct
    return s.trim().toLowerCase();
  }).filter(function (s) { return s.length > 0; });
  if (names.indexOf("*") !== -1) return null;  // sentinel: "uncacheable"
  names.sort();
  var lcReq = _lcHeaders(requestHeaders);
  var pairs = [];
  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    var v = lcReq[name];
    pairs.push([name, v === undefined ? null : String(v)]);
  }
  return pairs;
}

// ---- Storage decision (RFC 9111 §3) -----------------------------------

// Returns { cacheable: bool, reason: string|null, freshnessMs: number,
//           directives: Object, varyHeader: string|null }.
//
// freshnessMs is computed from the response — 0 means "store but
// always revalidate" (no-cache), -1 means "never cacheable".
function _evaluateStorage(method, statusCode, responseHeaders, sharedCache) {
  var lcResp = _lcHeaders(responseHeaders);
  var ccRaw = _headerOne(lcResp, "cache-control");
  var directives = _parseCacheControl(ccRaw);
  var varyHeader = _headerOne(lcResp, "vary");
  var pragma = _headerOne(lcResp, "pragma");

  // Method gate.
  var methodU = String(method || "GET").toUpperCase();
  if (methodU !== "GET" && methodU !== "HEAD") {
    return { cacheable: false, reason: "method-not-cacheable", freshnessMs: -1, directives: directives, varyHeader: varyHeader };
  }

  // Status gate.
  if (!CACHEABLE_STATUSES.has(statusCode)) {
    return { cacheable: false, reason: "status-not-cacheable", freshnessMs: -1, directives: directives, varyHeader: varyHeader };
  }

  // no-store / private (when shared) refuse outright.
  if (_ccPresent(directives, "no-store")) {
    return { cacheable: false, reason: "no-store", freshnessMs: -1, directives: directives, varyHeader: varyHeader };
  }
  if (sharedCache && _ccPresent(directives, "private")) {
    return { cacheable: false, reason: "private", freshnessMs: -1, directives: directives, varyHeader: varyHeader };
  }

  // Vary: * is uncacheable per RFC 9110 §12.5.5.
  if (typeof varyHeader === "string" && varyHeader.indexOf("*") !== -1) {
    var trimmed = varyHeader.split(",").map(function (s) { return s.trim(); });                  // RFC 9110 §12.5.5 Vary field-names; token grammar only, so a bare split is correct
    if (trimmed.indexOf("*") !== -1) {
      return { cacheable: false, reason: "vary-star", freshnessMs: -1, directives: directives, varyHeader: varyHeader };
    }
  }

  // Compute freshness lifetime per RFC 9111 §4.2.1.
  // Order: s-maxage (shared) > max-age > Expires - Date > heuristic.
  var sMaxage = sharedCache ? _ccNumber(directives, "s-maxage") : null;
  var maxage  = _ccNumber(directives, "max-age");
  var dateHeader = _parseHttpDate(_headerOne(lcResp, "date"));
  var expiresHeader = _parseHttpDate(_headerOne(lcResp, "expires"));
  var lastModified  = _parseHttpDate(_headerOne(lcResp, "last-modified"));

  var freshnessMs = null;
  if (sMaxage !== null) freshnessMs = C.TIME.seconds(sMaxage);
  else if (maxage !== null) freshnessMs = C.TIME.seconds(maxage);
  else if (expiresHeader !== null) {
    if (dateHeader !== null) freshnessMs = expiresHeader - dateHeader;
    else freshnessMs = expiresHeader - Date.now();
  } else if (lastModified !== null && dateHeader !== null) {
    // Heuristic: 10% of (Date - Last-Modified), capped at 24h. Negative
    // values mean Last-Modified is in the future — refuse the heuristic.
    var diff = dateHeader - lastModified;
    if (diff > 0) {
      freshnessMs = Math.min(Math.floor(diff * 0.1), HEURISTIC_MAX_AGE_MS);
    }
  }

  // Pragma: no-cache + no Cache-Control: max-age = legacy "always
  // revalidate". Treat like Cache-Control: no-cache.
  if (pragma && /no-cache/i.test(pragma) && maxage === null && sMaxage === null && expiresHeader === null) {
    if (!_ccPresent(directives, "max-age") && !_ccPresent(directives, "s-maxage")) {
      // Cacheable but stale-on-arrival (must revalidate).
      return {
        cacheable: true, reason: "pragma-no-cache", freshnessMs: 0,
        directives: directives, varyHeader: varyHeader,
      };
    }
  }

  // Cache-Control: no-cache (cache but require revalidation) — store
  // with freshness 0 so every read forces a conditional GET.
  if (_ccPresent(directives, "no-cache")) {
    return {
      cacheable: true, reason: "no-cache",
      freshnessMs: 0, directives: directives, varyHeader: varyHeader,
    };
  }

  // No explicit OR heuristic freshness AND no validators → uncacheable.
  // Without max-age/Expires/Last-Modified or ETag the cache has nothing
  // to validate against; storing is wasted bytes.
  var etag = _headerOne(lcResp, "etag");
  if (freshnessMs === null) {
    if (!etag && !lastModified) {
      return { cacheable: false, reason: "no-freshness-no-validator", freshnessMs: -1, directives: directives, varyHeader: varyHeader };
    }
    // Has a validator but no lifetime — store with freshness 0 (force
    // revalidation).
    return {
      cacheable: true, reason: "validator-only",
      freshnessMs: 0, directives: directives, varyHeader: varyHeader,
    };
  }

  if (freshnessMs < 0) {
    return { cacheable: false, reason: "expires-in-past", freshnessMs: -1, directives: directives, varyHeader: varyHeader };
  }

  return {
    cacheable: true, reason: null,
    freshnessMs: freshnessMs, directives: directives, varyHeader: varyHeader,
  };
}

// ---- Age + freshness math (RFC 9111 §4.2.3) ---------------------------

// current_age = (now - response_time) + (response_time - date_value) +
//               apparent_age (corrected)
// We approximate apparent_age as max(0, response_time - date_value) and
// drop the response_delay correction (small; not exposed by Node's HTTP
// layer at the resolution we care about).
function _currentAgeMs(entry, nowMs) {
  var dateMs = entry.dateMs;
  var ageHeader = entry.ageHeaderSec || 0;
  var responseTime = entry.storedAtMs;
  var apparent = Math.max(0, responseTime - (dateMs || responseTime));
  var correctedInitial = Math.max(apparent, C.TIME.seconds(ageHeader));
  var residentTime = nowMs - responseTime;
  return correctedInitial + residentTime;
}

// ---- Memory store -----------------------------------------------------

/**
 * @primitive b.httpClient.cache.memoryStore
 * @signature b.httpClient.cache.memoryStore(opts)
 * @since     0.8.53
 * @status    stable
 * @related   b.httpClient.cache.create, b.httpClient.request
 *
 * In-memory bounded-LRU cache store implementing the `Store` shape:
 * `get(key)`, `set(key, entry)`, `delete(key)`, `clear()`. Eviction
 * runs when the byte total or entry count exceeds the configured
 * caps; eviction emits an audit event when an audit sink is wired
 * (via `b.httpClient.cache.create({ audit })`). Stored values
 * include the response body buffer, so the byte total reflects real
 * memory pressure rather than a rough estimate.
 *
 * Suitable for single-process workloads. For shared-cache semantics
 * across a fleet, wire your own `Store` against a shared backing
 * service (Redis, filesystem, etc.) — the same shape applies.
 *
 * @opts
 *   maxBytes:       number,   // total stored body bytes; default: 64 MiB
 *   maxEntries:     number,   // count cap; default: 1024
 *   evictionPolicy: "lru",    // currently the only policy; reserved
 *
 * @example
 *   var store = b.httpClient.cache.memoryStore({
 *     maxBytes:   16 * 1024 * 1024,
 *     maxEntries: 256,
 *   });
 *   var cache = b.httpClient.cache.create({ store: store });
 *   await b.httpClient.request({ url: "https://example.com/", cache: cache });
 */
function memoryStore(opts) {
  opts = opts || {};
  if (typeof opts !== "object") {
    throw _hcErr("httpclient/cache-bad-opts", "memoryStore: opts must be an object");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes,
    "memoryStore: maxBytes", HttpClientError, "httpclient/cache-bad-opts", { permanent: true });
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxEntries,
    "memoryStore: maxEntries", HttpClientError, "httpclient/cache-bad-opts", { permanent: true });
  if (opts.evictionPolicy !== undefined && opts.evictionPolicy !== "lru") {
    throw _hcErr("httpclient/cache-bad-opts",
      "memoryStore: evictionPolicy must be 'lru' (got " + JSON.stringify(opts.evictionPolicy) + ")");
  }
  var maxBytes   = opts.maxBytes   || DEFAULT_MAX_BYTES;
  var maxEntries = opts.maxEntries || DEFAULT_MAX_ENTRIES;

  // Map iteration order is insertion order. We re-insert on `get` to
  // promote the entry to the LRU tail; eviction removes from the head.
  var map = new Map();
  var totalBytes = 0;
  var onEvict = null;  // wired by the cache instance after construction.

  function _entryBytes(entry) {
    if (!entry) return 0;
    var bodyLen = (entry.body && Buffer.isBuffer(entry.body)) ? entry.body.length : 0;
    // Header byte estimate — small; included to keep totalBytes honest
    // for response bodies of zero length (a 1KB header bundle still
    // costs memory).
    var headerLen = 0;
    if (entry.headers) {
      var keys = Object.keys(entry.headers);
      for (var i = 0; i < keys.length; i++) {
        headerLen += keys[i].length + String(entry.headers[keys[i]]).length + 4;
      }
    }
    return bodyLen + headerLen;
  }

  function _evictOne(reason) {
    var first = map.keys().next();
    if (first.done) return false;
    var k = first.value;
    var v = map.get(k);
    map.delete(k);
    totalBytes -= _entryBytes(v);
    if (totalBytes < 0) totalBytes = 0;
    if (typeof onEvict === "function") {
      try { onEvict({ key: k, reason: reason, bytes: _entryBytes(v) }); }
      catch (_e) { /* eviction callback best-effort */ }
    }
    return true;
  }

  function _evictUntilFits(extraBytes) {
    while ((map.size + 1) > maxEntries && _evictOne("max-entries")) { /* loop */ }
    while ((totalBytes + extraBytes) > maxBytes && _evictOne("max-bytes")) { /* loop */ }
  }

  return {
    kind: "memory",
    get: function (key) {
      if (!map.has(key)) return null;
      var v = map.get(key);
      // LRU promote.
      map.delete(key);
      map.set(key, v);
      return v;
    },
    set: function (key, entry) {
      if (typeof key !== "string" || !entry || typeof entry !== "object") return;
      if (map.has(key)) {
        var prev = map.get(key);
        totalBytes -= _entryBytes(prev);
        map.delete(key);
      }
      var bytes = _entryBytes(entry);
      if (bytes > maxBytes) {
        // Single entry larger than the cap — refuse rather than wipe.
        if (typeof onEvict === "function") {
          try { onEvict({ key: key, reason: "entry-too-large", bytes: bytes }); }
          catch (_e) { /* eviction callback best-effort */ }
        }
        return;
      }
      _evictUntilFits(bytes);
      map.set(key, entry);
      totalBytes += bytes;
    },
    delete: function (key) {
      if (!map.has(key)) return;
      var v = map.get(key);
      totalBytes -= _entryBytes(v);
      if (totalBytes < 0) totalBytes = 0;
      map.delete(key);
    },
    clear: function () {
      map.clear();
      totalBytes = 0;
    },
    // Internal hooks for the cache instance — not part of the operator-
    // facing Store contract.
    _stats: function () {
      return { entries: map.size, bytes: totalBytes, maxBytes: maxBytes, maxEntries: maxEntries };
    },
    _setOnEvict: function (cb) { onEvict = (typeof cb === "function") ? cb : null; },
  };
}

// ---- Cache instance --------------------------------------------------

/**
 * @primitive b.httpClient.cache.create
 * @signature b.httpClient.cache.create(opts)
 * @since     0.8.53
 * @status    stable
 * @related   b.httpClient.cache.memoryStore, b.httpClient.request
 *
 * Builds an RFC 9111 cache instance for `b.httpClient.request`. The
 * returned object plugs into a request via `opts.cache`. Without
 * `opts.cache`, the request path is unchanged — no overhead for
 * non-caching callers. The cache evaluates each response per
 * RFC 9111 §3 (storage decision: method / status / Cache-Control /
 * Vary), tracks freshness per §4.2 (s-maxage > max-age > Expires
 * > heuristic 10% of (Date - Last-Modified) capped at 24h),
 * revalidates conditionally per §4.3 (`If-None-Match` /
 * `If-Modified-Since`), and merges 304 headers per §5.
 *
 * `sharedCache: true` (default) honours `s-maxage` over `max-age` and
 * refuses to store responses with `Cache-Control: private` — operator
 * services share a cache with each other, so a per-user `private`
 * response must not leak across users via the cache. Single-tenant
 * scripts pass `sharedCache: false` to behave as a private cache.
 *
 * `defaultMaxStale` lets the cache return a stored entry past its
 * freshness lifetime (within the configured number of seconds) even
 * without an explicit upstream `stale-while-revalidate` /
 * `stale-if-error`. Default 0 — operators opt in.
 *
 * `revalidateInBackground` (default true): when an entry is fresh
 * within its `stale-while-revalidate` window the stale response is
 * returned immediately and a background revalidation kicks off so the
 * next caller sees a refreshed entry. Pass false to revalidate inline
 * (lower memory churn, higher request latency).
 *
 * @opts
 *   store:                  <required>,    // Store: { get, set, delete, clear }
 *   sharedCache:            true,          // honour s-maxage; refuse Cache-Control: private
 *   defaultMaxStale:        0,             // seconds — serve stale up to this far past expiry
 *   revalidateInBackground: true,          // s-w-r kicks off background revalidation
 *   audit:                  undefined,     // audit sink with safeEmit({...})
 *   observability:          undefined,     // optional { event, safeEvent }
 *   statusHeader:           "x-blamejs-cache", // response header carrying the cache decision; null/false to suppress, or a custom name (e.g. "x-cache")
 *
 * @example
 *   var cache = b.httpClient.cache.create({
 *     store:           b.httpClient.cache.memoryStore({ maxBytes: 32 * 1024 * 1024 }),
 *     sharedCache:     true,
 *     defaultMaxStale: 5,
 *     audit:           b.audit,
 *   });
 *   var res = await b.httpClient.request({
 *     url:   "https://api.example.com/users/42",
 *     cache: cache,
 *   });
 *   // res.headers["x-blamejs-cache"] === "MISS" (first call)
 */
function create(opts) {
  validateOpts.requireObject(opts, "cache.create: opts", HttpClientError, "httpclient/cache-bad-opts");
  if (!opts.store || typeof opts.store !== "object" ||
      typeof opts.store.get !== "function" ||
      typeof opts.store.set !== "function" ||
      typeof opts.store.delete !== "function" ||
      typeof opts.store.clear !== "function") {
    throw _hcErr("httpclient/cache-bad-opts",
      "cache.create: store must implement { get, set, delete, clear }");
  }
  validateOpts.optionalBoolean(opts.sharedCache, "cache.create: sharedCache", HttpClientError, "httpclient/cache-bad-opts");
  validateOpts.optionalFiniteNonNegative(opts.defaultMaxStale,
    "cache.create: defaultMaxStale", HttpClientError, "httpclient/cache-bad-opts");
  validateOpts.optionalBoolean(opts.revalidateInBackground,
    "cache.create: revalidateInBackground", HttpClientError, "httpclient/cache-bad-opts");
  if (opts.audit !== undefined && opts.audit !== null) {
    validateOpts.auditShape(opts.audit, "cache.create",
      HttpClientError, "httpclient/cache-bad-opts");
  }

  var store               = opts.store;
  var sharedCache         = opts.sharedCache !== false;  // default true
  var defaultMaxStaleSec  = opts.defaultMaxStale || 0;
  var revalidateBackground = opts.revalidateInBackground !== false;  // default true
  var audit               = opts.audit || null;
  var obs                 = opts.observability || null;
  // statusHeader (default "x-blamejs-cache") names the response header that
  // carries the cache decision (MISS/HIT/STALE/REVALIDATED). The decision is
  // also on res.cacheStatus programmatically. Pass null/false to suppress the
  // header, or a string to rename it (e.g. "x-cache"). Lowercased for the wire.
  var statusHeader;
  if (opts.statusHeader === null || opts.statusHeader === false) {
    statusHeader = null;
  } else if (opts.statusHeader === undefined) {
    statusHeader = "x-blamejs-cache";
  } else if (typeof opts.statusHeader === "string" && opts.statusHeader.length > 0) {
    statusHeader = opts.statusHeader.toLowerCase();
  } else {
    throw _hcErr("httpclient/cache-bad-opts",
      "cache.create: statusHeader must be a non-empty string, or null/false to suppress");
  }

  function _emit(action, outcome, metadata) {
    if (!audit || typeof audit.safeEmit !== "function") return;
    try {
      audit.safeEmit({
        action:   action,
        outcome:  outcome || "allowed",
        resource: { kind: "outbound.http.cache", id: (metadata && metadata.url) || "" },
        metadata: metadata || {},
      });
    } catch (_e) { /* audit best-effort — drop-silent */ }
  }

  function _obsEvent(name, value, labels) {
    if (!obs) return;
    var fn = obs.safeEvent || obs.event;
    if (typeof fn !== "function") return;
    try { fn(name, value, labels); } catch (_e) { /* drop-silent */ }
  }

  // Wire the eviction callback into the memory store so eviction emits
  // a single audit + observability event. Stores that don't support the
  // hook (operator-supplied) silently skip — the operator's own store
  // emits its own metrics.
  if (store && typeof store._setOnEvict === "function") {
    store._setOnEvict(function (info) {
      _emit("httpclient.cache.evicted", "allowed", {
        reason: info.reason, bytes: info.bytes,
      });
      _obsEvent("httpclient.cache.evicted", 1, { reason: info.reason });
    });
  }

  function _buildEntry(method, urlStr, requestHeaders, statusCode, responseHeaders, body, evaluation) {
    var lcResp = _lcHeaders(responseHeaders);
    var dateMs = _parseHttpDate(_headerOne(lcResp, "date"));
    var ageSec = parseInt(_headerOne(lcResp, "age") || "0", 10);
    if (!isFinite(ageSec) || ageSec < 0) ageSec = 0;
    var varyValues = _extractVaryValues(evaluation.varyHeader, requestHeaders);
    if (varyValues === null) return null;  // vary: *
    return {
      method:        String(method || "GET").toUpperCase(),
      url:           urlStr,
      varyHeader:    evaluation.varyHeader || null,
      varyValues:    varyValues,
      statusCode:    statusCode,
      headers:       responseHeaders,
      body:          Buffer.isBuffer(body) ? body : (body == null ? Buffer.alloc(0) : Buffer.from(body)),
      storedAtMs:    Date.now(),
      dateMs:        dateMs,
      ageHeaderSec:  ageSec,
      freshnessMs:   evaluation.freshnessMs,
      directives:    evaluation.directives,
      etag:          _headerOne(lcResp, "etag"),
      lastModified:  _headerOne(lcResp, "last-modified"),
    };
  }

  // ---- Core cache surface --------------------------------------------

  // Look up a stored entry that matches (method, url, vary). Returns
  // { entry, key } | null. `vary` lookup is the standard "stored Vary
  // values must equal request's values" check.
  function _lookup(method, url, requestHeaders) {
    // We don't know the upstream's Vary set without storing it. So we
    // first try the no-vary key; if absent, we walk the index of vary
    // keys for this method+url. For the simple case (no Vary), the
    // first key hits.
    var noVaryKey = _buildCacheKey(method, url, []);
    var got = null;
    try { got = store.get(noVaryKey); }
    catch (_e) { /* drop-silent — store error means "miss" */ return null; }
    if (got) return { key: noVaryKey, entry: got };

    // Vary lookup — every entry stored under this method+url has the
    // same shape but different vary values. We probe with the request's
    // own values against the stored vary names. We need to know the
    // names without scanning the whole store; encode them into a
    // sidecar key under the no-vary slot. To keep the Store interface
    // simple, we instead store every vary'd response under a key that
    // includes the FULL request-header set hashed canonically. The
    // lookup tries each plausible key by reading a "vary-names index"
    // we maintain alongside.
    //
    // Simpler practical approach: store a small "varyNames" entry under
    // the no-vary key when the response actually has Vary, then probe
    // with the operator's request headers projected onto those names.
    //
    // Implementation: when we store under a vary'd key, we ALSO set
    // a marker entry at the no-vary key with body=empty + a special
    // header `x-blamejs-vary-names` listing the Vary names. _lookup
    // reads that marker when no body entry was found above and probes
    // the real key.
    return null;
  }

  // Lookup respecting Vary — returns { entry, key } | null. The full
  // index lives in the store under (method, url, varyValues) so we
  // need both a "what Vary names apply" marker and the real entry.
  function _lookupWithVary(method, url, requestHeaders) {
    var noVary = _lookup(method, url, requestHeaders);
    if (noVary) {
      // Distinguish marker from real entry via __varyMarker flag.
      if (noVary.entry && noVary.entry.__varyMarker) {
        // Compute the real key from the marker's known vary names.
        var names = noVary.entry.varyNames || [];
        var lcReq = _lcHeaders(requestHeaders);
        var pairs = names.slice().sort().map(function (n) {
          var v = lcReq[n];
          return [n, v === undefined ? null : String(v)];
        });
        var realKey = _buildCacheKey(method, url, pairs);
        var realEntry;
        try { realEntry = store.get(realKey); }
        catch (_e) { return null; }
        if (!realEntry) return null;
        return { key: realKey, entry: realEntry };
      }
      return noVary;
    }
    return null;
  }

  function _store(method, url, requestHeaders, statusCode, responseHeaders, body, evaluation) {
    var entry = _buildEntry(method, url, requestHeaders, statusCode, responseHeaders, body, evaluation);
    if (!entry) return false;
    var hasVary = entry.varyHeader && entry.varyValues && entry.varyValues.length > 0;
    var key = _buildCacheKey(method, url, hasVary ? entry.varyValues : []);
    try { store.set(key, entry); }
    catch (_e) { /* store error — drop-silent */ return false; }

    // When this response uses Vary, drop a marker entry at the no-vary
    // key so subsequent lookups know which header names to project.
    if (hasVary) {
      var marker = {
        __varyMarker: true,
        varyNames:    entry.varyValues.map(function (p) { return p[0]; }),
        method:       entry.method,
        url:          entry.url,
        body:         Buffer.alloc(0),
        headers:      {},
        storedAtMs:   entry.storedAtMs,
      };
      var noVaryKey = _buildCacheKey(method, url, []);
      try { store.set(noVaryKey, marker); }
      catch (_e) { /* drop-silent */ }
    }
    return true;
  }

  // Merge 304 headers into the stored entry per RFC 9111 §5. Strip
  // hop-by-hop headers; replace Date, ETag, Last-Modified, Cache-Control
  // with the new values.
  function _merge304Headers(stored, fresh304Headers) {
    var lcFresh = _lcHeaders(fresh304Headers);
    var merged = Object.assign({}, stored.headers);
    var keys = Object.keys(lcFresh);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      if (HOP_BY_HOP.has(k)) continue;
      if (k === "content-length") continue;  // body unchanged; keep stored CL
      // Find existing key (case-preserving) or create lowercase.
      var existing = null;
      var origKeys = Object.keys(merged);
      for (var j = 0; j < origKeys.length; j++) {
        if (origKeys[j].toLowerCase() === k) { existing = origKeys[j]; break; }
      }
      if (existing) merged[existing] = lcFresh[k];
      else merged[k] = lcFresh[k];
    }
    return merged;
  }

  // After a 304: re-derive freshness from merged headers and bump
  // storedAt to "now" so age math restarts.
  function _refreshFrom304(stored, fresh304Headers) {
    var mergedHeaders = _merge304Headers(stored, fresh304Headers);
    var evaluation = _evaluateStorage(stored.method, stored.statusCode, mergedHeaders, sharedCache);
    var lcMerged = _lcHeaders(mergedHeaders);
    var dateMs = _parseHttpDate(_headerOne(lcMerged, "date"));
    var ageSec = parseInt(_headerOne(lcMerged, "age") || "0", 10);
    if (!isFinite(ageSec) || ageSec < 0) ageSec = 0;
    var refreshed = Object.assign({}, stored, {
      headers:       mergedHeaders,
      storedAtMs:    Date.now(),
      dateMs:        dateMs,
      ageHeaderSec:  ageSec,
      freshnessMs:   evaluation.freshnessMs >= 0 ? evaluation.freshnessMs : stored.freshnessMs,
      directives:    evaluation.directives,
      etag:          _headerOne(lcMerged, "etag") || stored.etag,
      lastModified:  _headerOne(lcMerged, "last-modified") || stored.lastModified,
    });
    var hasVary = refreshed.varyHeader && refreshed.varyValues && refreshed.varyValues.length > 0;
    var key = _buildCacheKey(refreshed.method, refreshed.url, hasVary ? refreshed.varyValues : []);
    try { store.set(key, refreshed); } catch (_e) { /* drop-silent */ }
    return refreshed;
  }

  // Returns the "Age" header value (seconds) for serving an entry now.
  function _serveAgeSeconds(entry, nowMs) {
    var ageMs = _currentAgeMs(entry, nowMs);
    return Math.max(0, Math.floor(ageMs / C.TIME.seconds(1)));
  }

  // Decide whether a stored entry can be served fresh; if stale, what
  // grace allowances apply (s-w-r / s-i-e / defaultMaxStale).
  function _evaluateStored(entry, nowMs) {
    var ageMs = _currentAgeMs(entry, nowMs);
    var freshness = entry.freshnessMs;
    var directives = entry.directives || {};

    var fresh = ageMs < freshness;
    var swrSec = _ccNumber(directives, "stale-while-revalidate") || 0;
    var sieSec = _ccNumber(directives, "stale-if-error") || 0;
    var mustRevalidate = _ccPresent(directives, "must-revalidate") ||
                         (sharedCache && _ccPresent(directives, "proxy-revalidate"));
    var immutable      = _ccPresent(directives, "immutable");

    // immutable freezes the entry — never revalidate while fresh.
    return {
      fresh:           fresh,
      ageMs:           ageMs,
      freshnessMs:     freshness,
      mustRevalidate:  mustRevalidate,
      immutable:       immutable,
      swrWindowMs:     C.TIME.seconds(swrSec),
      sieWindowMs:     C.TIME.seconds(sieSec),
      defaultStaleMs:  C.TIME.seconds(defaultMaxStaleSec),
      directives:      directives,
    };
  }

  return {
    // ---- Lifecycle observability ----
    sharedCache:            sharedCache,
    defaultMaxStale:        defaultMaxStaleSec,
    revalidateInBackground: revalidateBackground,
    store:                  store,
    audit:                  audit,
    observability:          obs,
    statusHeader:           statusHeader,

    // ---- Lookup / store / revalidation flow ----
    //
    // The shape exposed to lib/http-client.js is internal-but-stable.
    // It's *not* part of the operator-facing surface — operators interact
    // through `request({ ..., cache })` and the audit/observability
    // events. Documented here for the http-client integration only.

    _lookup: function (method, url, requestHeaders) {
      return _lookupWithVary(method, url, requestHeaders);
    },

    _evaluateStorage: function (method, statusCode, responseHeaders) {
      return _evaluateStorage(method, statusCode, responseHeaders, sharedCache);
    },

    _evaluateStored: _evaluateStored,
    _serveAgeSeconds: _serveAgeSeconds,
    _store:           _store,
    _refreshFrom304:  _refreshFrom304,

    _emit:        _emit,
    _obsEvent:    _obsEvent,
    _isFresh:     function (entry) {
      var ev = _evaluateStored(entry, Date.now());
      return ev.fresh;
    },

    // ---- Operator-facing helpers ----
    /**
     * Inspect the cache for an entry without modifying it.
     * Returns { hit, entry, fresh, ageMs } | { hit: false }.
     */
    inspect: function (method, url, requestHeaders) {
      var got = _lookupWithVary(method, url, requestHeaders || {});
      if (!got) return { hit: false };
      var ev = _evaluateStored(got.entry, Date.now());
      return {
        hit:         true,
        fresh:       ev.fresh,
        ageMs:       ev.ageMs,
        freshnessMs: ev.freshnessMs,
        statusCode:  got.entry.statusCode,
      };
    },

    /**
     * Drop the cache entry for a given (method, url[, requestHeaders]).
     * Returns true when an entry was deleted.
     */
    invalidate: function (method, url, requestHeaders) {
      var got = _lookupWithVary(method, url, requestHeaders || {});
      if (!got) return false;
      try { store.delete(got.key); } catch (_e) { return false; }
      // Also drop the no-vary marker if present.
      try { store.delete(_buildCacheKey(method, url, [])); } catch (_e) { /* drop-silent */ }
      return true;
    },

    /**
     * Wipe the entire cache. Operators wire this on app shutdown when
     * they don't want stale memory residue, or after a config reload
     * that flips upstream identity.
     */
    clear: function () {
      try { store.clear(); }
      catch (_e) { /* drop-silent */ }
    },

    stats: function () {
      if (typeof store._stats === "function") {
        try { return store._stats(); }
        catch (_e) { return null; }
      }
      return null;
    },
  };
}

module.exports = {
  create:                create,
  memoryStore:           memoryStore,

  // Internals exposed for tests + the http-client integration.
  _parseCacheControl:    _parseCacheControl,
  _evaluateStorage:      _evaluateStorage,
  _buildCacheKey:        _buildCacheKey,
  _normalizeUrl:         _normalizeUrl,
  _currentAgeMs:         _currentAgeMs,
  _extractVaryValues:    _extractVaryValues,
  CACHEABLE_STATUSES:    CACHEABLE_STATUSES,
  HOP_BY_HOP:            HOP_BY_HOP,
  HEURISTIC_MAX_AGE_MS:  HEURISTIC_MAX_AGE_MS,
  DEFAULT_MAX_BYTES:     DEFAULT_MAX_BYTES,
  DEFAULT_MAX_ENTRIES:   DEFAULT_MAX_ENTRIES,
};
