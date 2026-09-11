// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var boundedMap = require("../bounded-map");
var C = require("../constants");
var frameworkSchema = require("../framework-schema");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var safeAsync = require("../safe-async");
var sql = require("../sql");
var validateOpts = require("../validate-opts");
var clusterStorage = require("../cluster-storage");
var denyResponse = require("./deny-response").denyResponse;

var RATE_LIMIT_TABLE = "_blamejs_rate_limit_counters";   // allow:hand-rolled-sql — canonical logical table-name declaration
function _rateLimitSqlTable() { return frameworkSchema.tableName(RATE_LIMIT_TABLE); }

function _rateLimitSqlOpts() { return { dialect: clusterStorage.dialect() }; }

function _conflictRefs(dialect, table) {
  if (dialect === "mysql") {
    return {
      proposed: function (col) { return "VALUES(`" + col + "`)"; },
      existing: function (col) { return "`" + table + "`.`" + col + "`"; },
    };
  }
  return {
    proposed: function (col) { return "EXCLUDED.\"" + col + "\""; },
    existing: function (col) { return "\"" + table + "\".\"" + col + "\""; },
  };
}

var audit  = lazyRequire(function () { return require("../audit"); });
var logger = lazyRequire(function () { return require("../log").boot("rate-limit"); });

function _requirePositiveNumber(name, value) {
  if (typeof value !== "number" || !isFinite(value) || value <= 0) {
    throw new Error("middleware.rateLimit: " + name + " must be a positive finite number, got " +
      JSON.stringify(value));
  }
}

function _memoryBackend(opts) {
  var algorithm = opts.algorithm || "token-bucket";
  if (algorithm !== "token-bucket" && algorithm !== "fixed-window") {
    throw new Error("middleware.rateLimit: algorithm must be 'token-bucket' or 'fixed-window', got " +
      JSON.stringify(algorithm));
  }
  if (algorithm === "fixed-window") return _memoryFixedWindowBackend(opts);
  return _memoryTokenBucketBackend(opts);
}

function _memoryTokenBucketBackend(opts) {
  var clock = opts.clock || Date.now;
  var burst = opts.burst != null ? opts.burst : C.TIME.minutes(1) / C.TIME.seconds(1);
  var refillPerSecond = opts.refillPerSecond != null ? opts.refillPerSecond : 10;
  _requirePositiveNumber("burst", burst);
  _requirePositiveNumber("refillPerSecond", refillPerSecond);
  var buckets = new Map();

  var gcInterval = safeAsync.repeating(function () {
    var cutoff = clock() - C.TIME.hours(1);
    for (var k of buckets.keys()) {
      if (buckets.get(k).lastRefillAt < cutoff) buckets.delete(k);
    }
  }, C.TIME.minutes(5), { name: "rate-limit-gc" });

  function take(key, _cost) {
    var now = clock();
    var existed = buckets.has(key);
    var b = boundedMap.getOrInsert(buckets, key, function () {
      return { tokens: burst, lastRefillAt: now };
    });
    if (existed) {
      var elapsed = (now - b.lastRefillAt) / C.TIME.seconds(1);
      b.tokens = Math.min(burst, b.tokens + elapsed * refillPerSecond);
      b.lastRefillAt = now;
    }
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return {
        allowed:    true,
        limit:      burst,
        remaining:  Math.floor(b.tokens),
        retryAfter: 0,
      };
    }
    var deficit = 1 - b.tokens;
    var waitMs = Math.ceil(C.TIME.seconds(deficit / refillPerSecond));
    return {
      allowed:    false,
      limit:      burst,
      remaining:  0,
      retryAfter: Math.ceil(waitMs / C.TIME.seconds(1)),
    };
  }

  function reset(key) {
    buckets.delete(key);
  }

  function resetAll() {
    buckets.clear();
  }

  function close() {
    try { gcInterval.stop(); } catch (_e) { /* timer already stopped */ }
    buckets.clear();
  }

  return { take: take, reset: reset, resetAll: resetAll, close: close };
}

function _memoryFixedWindowBackend(opts) {
  var clock = opts.clock || Date.now;
  var max = opts.max != null ? opts.max
          : opts.limit != null ? opts.limit
          : C.TIME.minutes(1) / C.TIME.seconds(1);
  var windowMs = opts.windowMs != null ? opts.windowMs : C.TIME.minutes(1);
  _requirePositiveNumber("max", max);
  _requirePositiveNumber("windowMs", windowMs);

  var counters = new Map();

  var gcInterval = safeAsync.repeating(function () {
    var now = clock();
    for (var k of counters.keys()) {
      var c = counters.get(k);
      if (c.windowStart + windowMs * 2 < now) counters.delete(k);
    }
  }, C.TIME.minutes(5), { name: "rate-limit-fixed-window-gc" });

  function take(key, _cost) {
    var now = clock();
    var windowStart = Math.floor(now / windowMs) * windowMs;
    var c = boundedMap.getOrInsert(counters, key, function () {
      return { windowStart: windowStart, count: 0 };
    });
    if (c.windowStart !== windowStart) {
      c.windowStart = windowStart;
      c.count = 0;
    }
    c.count += 1;
    if (c.count <= max) {
      return {
        allowed:    true,
        limit:      max,
        remaining:  Math.max(0, max - c.count),
        retryAfter: 0,
      };
    }
    var retryMs = (windowStart + windowMs) - now;
    return {
      allowed:    false,
      limit:      max,
      remaining:  0,
      retryAfter: Math.max(1, Math.ceil(retryMs / C.TIME.seconds(1))),
    };
  }

  function reset(key) { counters.delete(key); }

  function resetAll() { counters.clear(); }

  function close() {
    try { gcInterval.stop(); } catch (_e) { /* timer already stopped */ }
    counters.clear();
  }

  return { take: take, reset: reset, resetAll: resetAll, close: close };
}

function _clusterBackend(opts) {
  var clock = Date.now;
  var limit    = opts.limit    != null ? opts.limit    : C.TIME.minutes(1) / C.TIME.seconds(1);
  var windowMs = opts.windowMs != null ? opts.windowMs : C.TIME.minutes(1);
  var pruneIntervalMs = opts.pruneIntervalMs != null
    ? opts.pruneIntervalMs : C.TIME.minutes(5);
  _requirePositiveNumber("limit", limit);
  _requirePositiveNumber("windowMs", windowMs);
  _requirePositiveNumber("pruneIntervalMs", pruneIntervalMs);
  var lastPruneAt = 0;

  function _maybePrune() {
    var now = clock();
    if (now - lastPruneAt < pruneIntervalMs) return;
    lastPruneAt = now;
    var cutoff = now - windowMs;
    var built = sql.delete(_rateLimitSqlTable(), _rateLimitSqlOpts())
      .where("windowStart", "<", cutoff)
      .toSql();
    clusterStorage.execute(built.sql, built.params).catch(function (e) {
      try {
        logger().warn("rate-limit prune failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* logger best-effort */ }
    });
  }

  async function take(key, _cost) {
    var now = clock();
    var windowStart = Math.floor(now / windowMs) * windowMs;

    var t = _rateLimitSqlTable();
    var dialect = clusterStorage.dialect();
    var refs = _conflictRefs(dialect, t);
    var newerWindow = refs.proposed("windowStart") + " > " + refs.existing("windowStart");
    var countExpr = "CASE WHEN " + newerWindow + " THEN 1 ELSE " +
      refs.existing("count") + " + 1 END";
    var windowExpr = "CASE WHEN " + newerWindow + " THEN " + refs.proposed("windowStart") +
      " ELSE " + refs.existing("windowStart") + " END";
    var built = sql.upsert(t, _rateLimitSqlOpts())
      .columns(["key", "windowStart", "count"])
      .values({ key: key, windowStart: windowStart, count: 1 })
      .onConflict(["key"])
      .doUpdate({ count: countExpr, windowStart: windowExpr })
      .returning(["count", "windowStart"])
      .toSql();
    var row;
    if (built.readbackSql) {
      await clusterStorage.execute(built.sql, built.params);
      var readback = await clusterStorage.execute(built.readbackSql.sql, built.readbackSql.params);
      row = readback.rows && readback.rows[0];
    } else {
      var result = await clusterStorage.execute(built.sql, built.params);
      row = result.rows && result.rows[0];
    }
    var count = row ? Number(row.count) : 1;
    var rowWindow = row ? Number(row.windowStart) : windowStart;

    _maybePrune();

    if (count <= limit) {
      return {
        allowed:    true,
        limit:      limit,
        remaining:  Math.max(0, limit - count),
        retryAfter: 0,
      };
    }
    var retryMs = (rowWindow + windowMs) - now;
    return {
      allowed:    false,
      limit:      limit,
      remaining:  0,
      retryAfter: Math.max(1, Math.ceil(retryMs / C.TIME.seconds(1))),
    };
  }

  async function reset(key) {
    var built = sql.delete(_rateLimitSqlTable(), _rateLimitSqlOpts())
      .where("key", key)
      .toSql();
    await clusterStorage.execute(built.sql, built.params);
  }

  function close() { /* no resources to release */ }

  return { take: take, reset: reset, close: close };
}

function _resolveBackend(opts) {
  var requested = opts.backend;
  if (requested && typeof requested === "object" && typeof requested.take === "function") {
    return requested;
  }
  if (requested === "cluster") {
    if (opts.clock) {
      throw new Error("middleware.rateLimit: clock cannot be combined with " +
        "backend: \"cluster\" — the window boundary is shared across nodes and " +
        "computed from this reading, so nodes on different clocks would not " +
        "share a window. Use the memory backend for a caller-supplied clock.");
    }
    return _clusterBackend(opts);
  }
  if (!requested || requested === "memory") return _memoryBackend(opts);
  throw new Error("rate-limit: unknown backend '" + requested +
                  "' (must be 'memory', 'cluster', or { take, reset })");
}

/**
 * @primitive b.middleware.rateLimit
 * @signature b.middleware.rateLimit(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.dailyByteQuota, b.middleware.botGuard
 *
 * Pluggable-backend rate limiter. Constructed via
 * `b.middleware.rateLimit(opts)`; the resulting middleware has the
 * `(req, res, next)` shape shown above. Default `memory` backend offers
 * `token-bucket` (smooths bursts) and `fixed-window` algorithms;
 * `cluster` backend uses `_blamejs_rate_limit_counters` for
 * multi-node accurate fixed-window counts. Operators bring their
 * own `{ take, reset }` for Redis / Memcached. Per-IP by default;
 * `keyFn(req)` overrides for per-user / per-API-key / per-route.
 * Refuses with HTTP 429 + `X-RateLimit-*` headers and emits
 * `system.ratelimit.block` audit on every hit.
 *
 * @opts
 *   {
 *     keyFn:           function(req): string,
 *     statusOnLimit:   number,           // default 429
 *     bodyOnLimit:     string,           // default "Too Many Requests"
 *     onDeny:          function(req, res, info): void,  // own the refusal response; info = { status, reason, limit, remaining, retryAfter, key }
 *     problemDetails:  boolean,          // default false — emit RFC 9457 application/problem+json instead of text/plain
 *     header:          boolean,          // default true
 *     headerPrefix:    string,           // default "X-RateLimit-" — builds <prefix>Limit / <prefix>Remaining (e.g. "RateLimit-" for the IETF draft names)
 *     skipPaths:       Array<string|RegExp>,
 *     scope:           "global"|"per-route",
 *     backend:         "memory"|"cluster"|{ take, reset },
 *     algorithm:       "token-bucket"|"fixed-window",
 *     burst:           number,
 *     refillPerSecond: number,
 *     max:             number,
 *     limit:           number,
 *     windowMs:        number,
 *     pruneIntervalMs: number,
 *     trustedProxies:  string|string[],  // CIDRs of your reverse proxies — peer-gates X-Forwarded-For for the IP key
 *     clientIpResolver: function(req): string|null,  // own the rate-limit key's client IP
 *     ipKeyMode:       "exact"|"prefix64",  // default "exact"; "prefix64" keys IPv6 by its /64 (IPv4 stays exact) so one end-site can't rotate the low 64 bits to evade the limit
 *     trustProxy:      boolean|number,   // legacy; refused with the default IP key (spoofable) — use trustedProxies
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.rateLimit({
 *     backend:         "memory",
 *     algorithm:       "token-bucket",
 *     burst:           60,
 *     refillPerSecond: 10,
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "keyFn", "statusOnLimit", "bodyOnLimit", "onDeny", "problemDetails",
    "header", "headerPrefix", "skipPaths", "scope", "ipKeyMode",
    "backend", "trustProxy", "trustedProxies", "clientIpResolver", "algorithm",
    "clock",
    "burst", "refillPerSecond",
    "max", "limit", "windowMs", "pruneIntervalMs",
  ], "middleware.rateLimit");
  if (opts.clock !== undefined && opts.clock !== null && typeof opts.clock !== "function") {
    throw new Error("middleware.rateLimit: clock must be a function returning epoch " +
      "milliseconds, got " + JSON.stringify(opts.clock));
  }
  ["keyFn", "onDeny"].forEach(function (name) {
    var v = opts[name];
    if (v !== undefined && v !== null && typeof v !== "function") {
      throw new Error("middleware.rateLimit: " + name + " must be a function, got " +
        JSON.stringify(v));
    }
  });
  var _ipResolver;
  try {
    _ipResolver = requestHelpers.trustedClientIp({
      trustedProxies:   opts.trustedProxies,
      clientIpResolver: opts.clientIpResolver,
    });
  } catch (e) { throw new Error("middleware.rateLimit: " + e.message); }
  var trustProxyBare = opts.trustProxy === true || typeof opts.trustProxy === "number";
  if (trustProxyBare && !_ipResolver.peerGated && !opts.keyFn) {
    throw new Error("middleware.rateLimit: trustProxy is spoofable — a caller can forge " +
      "X-Forwarded-For to evade the limit or poison another IP's bucket. Declare your " +
      "reverse proxies via trustedProxies: [\"10.0.0.0/8\", …], supply clientIpResolver(req), " +
      "or set your own keyFn.");
  }
  var _clientIp = function (req) { return _ipResolver.resolve(req) || "unknown"; };
  if (opts.ipKeyMode !== undefined && opts.ipKeyMode !== "exact" && opts.ipKeyMode !== "prefix64") {
    throw new Error("middleware.rateLimit: ipKeyMode must be \"exact\" (default) or \"prefix64\"");
  }
  var _defaultKey = (opts.ipKeyMode === "prefix64")
    ? function (req) {
        var ip = _ipResolver.resolve(req);
        if (!ip) return "unknown";
        return requestHelpers.ipKey(ip, { ipv6Bits: 64 }) || ip;
      }
    : _clientIp;
  var keyFn = opts.keyFn || _defaultKey;
  var statusOnLimit = opts.statusOnLimit || 429;
  var bodyOnLimit = opts.bodyOnLimit !== undefined ? opts.bodyOnLimit : "Too Many Requests";
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;
  var emitHeaders = opts.header !== false;
  var headerPrefix = (typeof opts.headerPrefix === "string" && opts.headerPrefix.length > 0)
    ? opts.headerPrefix : "X-RateLimit-";
  var limitHeader = headerPrefix + "Limit";   // allow:hand-rolled-sql — HTTP response-header name (X-RateLimit-Limit), not a SQL LIMIT clause
  var remainingHeader = headerPrefix + "Remaining";
  var _shouldSkip = requestHelpers.makeSkipMatcher(opts, "middleware.rateLimit");
  var scope = opts.scope || "global";

  var backend = _resolveBackend(opts);

  function _writeBlocked(req, res, k, verdict) {
    if (emitHeaders && typeof res.setHeader === "function") {
      res.setHeader(limitHeader, String(verdict.limit));
      res.setHeader(remainingHeader, String(verdict.remaining));
      if (verdict.retryAfter > 0) res.setHeader("Retry-After", String(verdict.retryAfter));
    }
    try {
      audit().emit({
        actor:    requestHelpers.extractActorContext(req, { ip: _clientIp(req) }),
        action:   "system.ratelimit.block",
        outcome:  "denied",
        reason:   "rate limit exceeded",
        metadata: { key: k, method: req.method, path: req.pathname || req.url, retryAfter: verdict.retryAfter },
        requestId: req.requestId,
      });
    } catch (_e) { /* audit best-effort */ }
    var retryAfter = verdict.retryAfter > 0 ? verdict.retryAfter : null;
    denyResponse(req, res, {
      onDeny:        onDeny,
      problem:       problemMode,
      status:        statusOnLimit,
      info:          { status: statusOnLimit, reason: "rate-limit-exceeded",
        limit: verdict.limit, remaining: verdict.remaining,
        retryAfter: verdict.retryAfter, key: k },
      problemCode:   "rate-limit-exceeded",
      problemTitle:  "Too Many Requests",
      problemDetail: "Request rate limit exceeded; retry after the indicated interval.",
      problemExt:    retryAfter !== null ? { retryAfter: retryAfter } : null,
      contentType:   "text/plain",
      body:          bodyOnLimit,
    });
  }

  var middleware = function rateLimit(req, res, next) {
    if (_shouldSkip(req)) return next();
    var k = keyFn(req);
    if (scope === "per-route") {
      var routePath = req.pathname || (req.url || "/").split("?")[0] || "/";
      k = (req.method || "GET") + ":" + routePath + "|" + k;
    }

    function _handle(verdict) {
      if (emitHeaders && typeof res.setHeader === "function") {
        res.setHeader(limitHeader, String(verdict.limit));
        res.setHeader(remainingHeader, String(verdict.remaining));
      }
      if (!verdict.allowed) return _writeBlocked(req, res, k, verdict);
      next();
    }
    function _onErr(e) {
      try {
        logger().error("rate-limit backend take() failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* best-effort */ }
      next();
    }

    var verdictOrPromise;
    try {
      verdictOrPromise = backend.take(k, 1);
    } catch (e) { return _onErr(e); }

    if (verdictOrPromise && typeof verdictOrPromise.then === "function") {
      verdictOrPromise.then(_handle, _onErr);
    } else {
      _handle(verdictOrPromise);
    }
  };

  middleware.reset = function (key) { return backend.reset(key); };
  middleware.resetAll = function () {
    if (typeof backend.resetAll === "function") return backend.resetAll();
    return null;
  };
  middleware.close = function () {
    _instances.delete(middleware);
    return backend.close && backend.close();
  };

  _instances.add(middleware);
  return middleware;
}

var _instances = new Set();

function instances() {
  return Array.from(_instances);
}

function resetAll() {
  var n = 0;
  _instances.forEach(function (m) {
    try { m.resetAll(); n += 1; } catch (_e) { /* best-effort */ }
  });
  return n;
}

module.exports = {
  create:           create,
  instances:        instances,
  resetAll:         resetAll,
  _memoryBackend:              _memoryBackend,
  _memoryTokenBucketBackend:   _memoryTokenBucketBackend,
  _memoryFixedWindowBackend:   _memoryFixedWindowBackend,
  _clusterBackend:             _clusterBackend,
};
