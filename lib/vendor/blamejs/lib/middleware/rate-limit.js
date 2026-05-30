"use strict";
/**
 * Rate-limit middleware — pluggable backend, default in-memory.
 *
 * Per-IP by default; key extractor is configurable (per-user, per-API-key,
 * per-route). Two built-in backends, two in-memory algorithms:
 *
 *   - 'memory' (default) — in-process counter. The `algorithm` opt
 *     selects the shape:
 *       'token-bucket' (default) — each key gets `burst` tokens up
 *         front; tokens refill at `refillPerSecond`; each request
 *         costs 1 token. Smooths bursty traffic.
 *       'fixed-window' — per-key counter resets at the start of each
 *         window (`windowMs`); allow up to `max` per window. Matches
 *         the cluster backend's algorithm without an SQL hop. Cheaper
 *         per request than token-bucket; tradeoff is the boundary
 *         burst at window edges (worst case 2*max in 1*windowMs).
 *
 *   - 'cluster' — fixed-window counter shared across the cluster
 *     via `_blamejs_rate_limit_counters`. Atomic INSERT...ON CONFLICT
 *     increments per key within a window and rolls over when the
 *     window advances. Multi-process / multi-node accurate.
 *
 *     Cluster opt-in implies fixed-window because that's what models
 *     cleanly in SQL — the operator-facing config keys for the
 *     cluster backend match the fixed-window memory shape.
 *
 * Operators can also pass a custom `{ take, reset }` object as the
 * backend for Redis / Memcached / etc.
 *
 * Options:
 *   {
 *     keyFn:           (req) → 'rate-key'    (default: client IP)
 *     statusOnLimit:   429
 *     bodyOnLimit:     'Too Many Requests'
 *     header:          true                    // set X-RateLimit-* response headers
 *     skipPaths:       []                      // string-prefix or regex matchers
 *     scope:           'global' | 'per-route'  (default 'global')
 *     backend:         'memory' (default) | 'cluster' | { take, reset }
 *     algorithm:       'token-bucket' (default) | 'fixed-window'
 *                                              // memory backend only; ignored
 *                                              // for cluster backend (which is
 *                                              // always fixed-window) and custom
 *                                              // backend objects (operator decides)
 *
 *     // Memory backend, token-bucket algorithm:
 *     burst:           60                       // initial token bucket size
 *     refillPerSecond: 10                       // sustained throughput
 *
 *     // Memory backend, fixed-window algorithm + cluster backend:
 *     max:             60                       // max requests per window (memory only)
 *     limit:           60                       // alias of `max` (cluster backend uses this name)
 *     windowMs:        C.TIME.minutes(1)        // window duration
 *     pruneIntervalMs: C.TIME.minutes(5)        // cluster: how often the leader prunes expired rows
 *   }
 *
 * Audit: every limit hit emits system.ratelimit.block with the key + path.
 */
var C = require("../constants");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var safeAsync = require("../safe-async");
var validateOpts = require("../validate-opts");
var clusterStorage = require("../cluster-storage");

var audit  = lazyRequire(function () { return require("../audit"); });
var logger = lazyRequire(function () { return require("../log").boot("rate-limit"); });

// `_clientIp` defers to `requestHelpers.clientIp`, threading the
// per-middleware `trustProxy` opt. Default refuses forwarded headers
// (returning the socket address only) — operators behind a sanitizing
// reverse proxy opt in via `trustProxy: true` (or a hop count).
function _clientIpFor(trustProxy) {
  return function (req) {
    var ip = requestHelpers.clientIp(req, { trustProxy: trustProxy });
    return ip || "unknown";
  };
}

// Reject NaN / Infinity / negative / non-positive / non-number at create
// time so a misconfigured rate-limit can't silently degrade to "no
// limit" or produce divide-by-zero verdicts at request time.
function _requirePositiveNumber(name, value) {
  if (typeof value !== "number" || !isFinite(value) || value <= 0) {
    throw new Error("middleware.rateLimit: " + name + " must be a positive finite number, got " +
      JSON.stringify(value));
  }
}

// ---- Memory backend ----
//
// `algorithm: "token-bucket"` (default) — smoothed throughput.
// `algorithm: "fixed-window"` — per-key counter resets at the start of
//                                each window. Boundary-burst tradeoff
//                                in exchange for matching the cluster
//                                backend's shape without an SQL hop.

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
  // Default 1-per-second tokens fully refilled in 1 minute = 60 tokens.
  var burst = opts.burst != null ? opts.burst : C.TIME.minutes(1) / C.TIME.seconds(1);
  var refillPerSecond = opts.refillPerSecond != null ? opts.refillPerSecond : 10;
  _requirePositiveNumber("burst", burst);
  _requirePositiveNumber("refillPerSecond", refillPerSecond);
  var buckets = new Map();

  // Periodic GC of stale buckets so the map doesn't grow unbounded.
  var gcInterval = safeAsync.repeating(function () {
    var cutoff = Date.now() - C.TIME.hours(1);
    for (var k of buckets.keys()) {
      if (buckets.get(k).lastRefillAt < cutoff) buckets.delete(k);
    }
  }, C.TIME.minutes(5), { name: "rate-limit-gc" });

  // Memory backend returns verdicts SYNCHRONOUSLY — no awaitable.
  // The middleware checks `.then` to decide whether to chain. Keeping
  // the hot path synchronous means single-process apps pay no
  // microtask cost per request.
  function take(key, _cost) {
    var now = Date.now();
    var b = buckets.get(key);
    if (!b) {
      b = { tokens: burst, lastRefillAt: now };
      buckets.set(key, b);
    } else {
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

// Fixed-window in-memory algorithm — per-key counter that resets at the
// start of each window. Same shape as the cluster backend but without
// the SQL hop, so single-process apps that want fixed-window semantics
// (e.g. matching a cluster-backend deploy in dev) avoid setting up a DB.
function _memoryFixedWindowBackend(opts) {
  // `max` is the memory-fixed-window operator-facing name. `limit` is
  // accepted as an alias so a config can switch from the cluster
  // backend to memory + fixed-window without renaming opts.
  var max = opts.max != null ? opts.max
          : opts.limit != null ? opts.limit
          : C.TIME.minutes(1) / C.TIME.seconds(1);
  var windowMs = opts.windowMs != null ? opts.windowMs : C.TIME.minutes(1);
  _requirePositiveNumber("max", max);
  _requirePositiveNumber("windowMs", windowMs);

  var counters = new Map();

  // Periodic GC of stale counters so the map doesn't grow unbounded.
  var gcInterval = safeAsync.repeating(function () {
    var now = Date.now();
    for (var k of counters.keys()) {
      var c = counters.get(k);
      if (c.windowStart + windowMs * 2 < now) counters.delete(k);
    }
  }, C.TIME.minutes(5), { name: "rate-limit-fixed-window-gc" });

  // Synchronous take — same hot-path shape as the token-bucket backend
  // so the middleware doesn't pay a microtask cost when memory-fixed
  // is selected.
  function take(key, _cost) {
    var now = Date.now();
    var windowStart = Math.floor(now / windowMs) * windowMs;
    var c = counters.get(key);
    if (!c || c.windowStart !== windowStart) {
      c = { windowStart: windowStart, count: 0 };
      counters.set(key, c);
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

// ---- Cluster backend (fixed-window counter, SQL-backed) ----

function _clusterBackend(opts) {
  // Default 60 requests per 1-minute window — derive the count from
  // the same C.TIME source so the cadence stays in one place.
  var limit    = opts.limit    != null ? opts.limit    : C.TIME.minutes(1) / C.TIME.seconds(1);
  var windowMs = opts.windowMs != null ? opts.windowMs : C.TIME.minutes(1);
  var pruneIntervalMs = opts.pruneIntervalMs != null
    ? opts.pruneIntervalMs : C.TIME.minutes(5);
  _requirePositiveNumber("limit", limit);
  _requirePositiveNumber("windowMs", windowMs);
  _requirePositiveNumber("pruneIntervalMs", pruneIntervalMs);
  var lastPruneAt = 0;

  // Best-effort prune of expired window rows. Rate-limited at the
  // call site so we don't hammer the DB on every request.
  function _maybePrune() {
    var now = Date.now();
    if (now - lastPruneAt < pruneIntervalMs) return;
    lastPruneAt = now;
    var cutoff = now - windowMs;
    clusterStorage.execute(
      "DELETE FROM _blamejs_rate_limit_counters WHERE windowStart < ?",
      [cutoff]
    ).catch(function (e) {
      try {
        logger().warn("rate-limit prune failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* logger best-effort */ }
    });
  }

  async function take(key, _cost) {
    var now = Date.now();
    var windowStart = Math.floor(now / windowMs) * windowMs;

    // Atomic increment: a fresh window resets count to 1; an existing
    // row in the same window gets count + 1. Postgres + SQLite both
    // support ON CONFLICT...DO UPDATE...RETURNING.
    var result = await clusterStorage.execute(
      "INSERT INTO _blamejs_rate_limit_counters (key, windowStart, count) " +
      "VALUES (?, ?, 1) " +
      "ON CONFLICT (key) DO UPDATE SET " +
      "  count = CASE " +
      "    WHEN excluded.windowStart > _blamejs_rate_limit_counters.windowStart " +
      "    THEN 1 " +
      "    ELSE _blamejs_rate_limit_counters.count + 1 " +
      "  END, " +
      "  windowStart = CASE " +
      "    WHEN excluded.windowStart > _blamejs_rate_limit_counters.windowStart " +
      "    THEN excluded.windowStart " +
      "    ELSE _blamejs_rate_limit_counters.windowStart " +
      "  END " +
      "RETURNING count, windowStart",
      [key, windowStart]
    );
    var row = result.rows && result.rows[0];
    var count = row ? row.count : 1;
    var rowWindow = row ? row.windowStart : windowStart;

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
    await clusterStorage.execute(
      "DELETE FROM _blamejs_rate_limit_counters WHERE key = ?",
      [key]
    );
  }

  function close() { /* no resources to release */ }

  return { take: take, reset: reset, close: close };
}

// ---- Backend resolution ----

function _resolveBackend(opts) {
  var requested = opts.backend;
  if (requested && typeof requested === "object" && typeof requested.take === "function") {
    return requested;  // operator-supplied custom backend
  }
  if (requested === "cluster") return _clusterBackend(opts);
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
 *     header:          boolean,          // default true
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
 *     trustProxy:      boolean|number,
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
    "keyFn", "statusOnLimit", "bodyOnLimit", "header", "skipPaths", "scope",
    "backend", "trustProxy", "algorithm",
    // memory backend (token-bucket)
    "burst", "refillPerSecond",
    // memory backend (fixed-window) + cluster backend
    "max", "limit", "windowMs", "pruneIntervalMs",
  ], "middleware.rateLimit");
  var trustProxy = opts.trustProxy === true || typeof opts.trustProxy === "number"
    ? opts.trustProxy : false;
  var _clientIp = _clientIpFor(trustProxy);
  var keyFn = opts.keyFn || _clientIp;
  var statusOnLimit = opts.statusOnLimit || 429;
  var bodyOnLimit = opts.bodyOnLimit !== undefined ? opts.bodyOnLimit : "Too Many Requests";
  var emitHeaders = opts.header !== false;
  var skipPaths = opts.skipPaths || [];
  // Throw at create(): each entry must be a string prefix or a RegExp.
  // Anything else would crash _shouldSkip with TypeError on the first request.
  for (var sp = 0; sp < skipPaths.length; sp++) {
    if (typeof skipPaths[sp] !== "string" && !(skipPaths[sp] instanceof RegExp)) {
      throw new Error("middleware.rateLimit: skipPaths[" + sp +
        "] must be a string prefix or RegExp, got " + typeof skipPaths[sp]);
    }
  }
  var scope = opts.scope || "global";

  var backend = _resolveBackend(opts);

  function _shouldSkip(req) {
    var path = req.pathname || req.url || "/";
    for (var i = 0; i < skipPaths.length; i++) {
      if (typeof skipPaths[i] === "string" ? path.indexOf(skipPaths[i]) === 0 : skipPaths[i].test(path)) {
        return true;
      }
    }
    return false;
  }

  function _writeBlocked(req, res, k, verdict) {
    if (emitHeaders && typeof res.setHeader === "function") {
      res.setHeader("X-RateLimit-Limit", String(verdict.limit));
      res.setHeader("X-RateLimit-Remaining", String(verdict.remaining));
      if (verdict.retryAfter > 0) res.setHeader("Retry-After", String(verdict.retryAfter));
    }
    try {
      // Override `ip` with the x-forwarded-for-aware client IP so the
      // audit event carries the proxied origin even when extractActorContext
      // would have read the socket address.
      audit().emit({
        actor:    requestHelpers.extractActorContext(req, { ip: _clientIp(req) }),
        action:   "system.ratelimit.block",
        outcome:  "denied",
        reason:   "rate limit exceeded",
        metadata: { key: k, method: req.method, path: req.pathname || req.url, retryAfter: verdict.retryAfter },
        requestId: req.requestId,
      });
    } catch (_e) { /* audit best-effort */ }
    if (typeof res.writeHead === "function") {
      res.writeHead(statusOnLimit, { "Content-Type": "text/plain" });
      res.end(bodyOnLimit);
    }
  }

  var middleware = function rateLimit(req, res, next) {
    if (_shouldSkip(req)) return next();
    var k = keyFn(req);
    if (scope === "per-route") k = (req.method || "GET") + ":" + (req.pathname || req.url || "/") + "|" + k;

    function _handle(verdict) {
      if (emitHeaders && typeof res.setHeader === "function") {
        res.setHeader("X-RateLimit-Limit", String(verdict.limit));
        res.setHeader("X-RateLimit-Remaining", String(verdict.remaining));
      }
      if (!verdict.allowed) return _writeBlocked(req, res, k, verdict);
      next();
    }
    function _onErr(e) {
      // Fail-open on backend errors. The framework's job is to throttle
      // attackers, not to crash the request path. Surface the error to
      // ops via boot logger; the next request retries.
      try {
        logger().error("rate-limit backend take() failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* best-effort */ }
      next();
    }

    // Memory backend returns sync; cluster / custom backends return a
    // Promise. Detect via `.then` so the hot path stays synchronous.
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

  // Expose a couple of operator hooks on the middleware function.
  middleware.reset = function (key) { return backend.reset(key); };
  // Global drop-all for the in-memory backend. Used by incident-
  // response workflows ("operator confirmed false-positive lockout
  // wave, drop the whole table") + by test suites that need a clean
  // slate between cases without re-creating the middleware. For the
  // cluster backend this is a no-op (cluster backends are
  // multi-process and require operator-side coordination — flushing
  // a shared row table from one replica races every other replica's
  // in-flight take() calls).
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

// Module-level registry of every rate-limit middleware in the running
// process. Operators reach for this during incident response: when a
// false-positive lockout wave hits, an oncall script can iterate
// `instances()` and call `.resetAll()` on each, without having to
// thread a reference to every rate-limit middleware through wherever
// the response code runs. Tests use it to assert a clean slate.
//
// Lifetime: a middleware joins on `create()` return and leaves on
// `middleware.close()`. Long-lived servers create rate-limiters once at
// boot; throwaway middlewares (tests, sandboxes) must close() to
// deregister. We deliberately don't use WeakRef here — operators want
// strong, observable membership ("did this rate-limiter actually get
// created?"), and the count is bounded by how many limiters an app
// configures, not how much traffic it sees.
var _instances = new Set();

function instances() {
  return Array.from(_instances);
}

// Global drop-all across every middleware in the process. Returns the
// number of instances that responded to resetAll (cluster-backed
// middlewares no-op their own resetAll but still count toward the
// total so operators see all instances were addressed).
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
  // Backends exported for tests + advanced operator wiring.
  _memoryBackend:              _memoryBackend,
  _memoryTokenBucketBackend:   _memoryTokenBucketBackend,
  _memoryFixedWindowBackend:   _memoryFixedWindowBackend,
  _clusterBackend:             _clusterBackend,
};
