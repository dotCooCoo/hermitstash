/**
 * In-memory rate limiter.
 * Tracks attempts per key (usually IP) per action within a sliding window.
 * Returns { allowed, remaining, retryAfter } on each check.
 */
var b = require("./vendor/blamejs");
var audit = require("./audit");
var C = require("./constants");

var stores = {}; // action -> { key -> { count, resetAt } }

// Hard cap on live keys per action. Under a distributed botnet flood, an
// attacker could otherwise grow this map to millions of entries between the
// 60s cleanup sweeps. When we hit the cap, evict the oldest 10% by resetAt.
var MAX_KEYS_PER_ACTION = 100000; // allow:raw-byte-literal — entry-count cap, not bytes
var EVICT_BATCH_FRACTION = 0.1;

function evictOldest(store) {
  var keys = Object.keys(store);
  var n = Math.max(1, Math.floor(keys.length * EVICT_BATCH_FRACTION));
  // Partial sort would be nicer; Object.keys is already O(n) and we only
  // evict on overflow (rare). Plain sort is fine.
  keys.sort(function (a, b) { return store[a].resetAt - store[b].resetAt; });
  for (var i = 0; i < n; i++) delete store[keys[i]];
}

var cleanupTimer = setInterval(function () { // allow:timer-no-unref — unref() called on cleanupTimer immediately after this setInterval block (lint window cap of 5 lines below misses it)
  var now = Date.now();
  for (var action in stores) {
    var store = stores[action];
    for (var key in store) {
      if (now > store[key].resetAt) delete store[key];
    }
  }
}, C.TIME.minutes(1));
cleanupTimer.unref();

/**
 * Check and increment rate limit.
 * @param {string} action - Rate limit category (e.g. "login", "upload")
 * @param {string} key - Identifier to limit (usually IP)
 * @param {number} max - Max attempts per window
 * @param {number} windowMs - Window duration in ms
 * @returns {{ allowed: boolean, remaining: number, retryAfter: number }}
 */
function check(action, key, max, windowMs) {
  if (!key) return { allowed: true, remaining: max, retryAfter: 0 };

  if (!stores[action]) stores[action] = {};
  var store = stores[action];
  var now = Date.now();

  if (!store[key] || now > store[key].resetAt) {
    // Guard against memory exhaustion before inserting a new key.
    if (!store[key] && Object.keys(store).length >= MAX_KEYS_PER_ACTION) {
      evictOldest(store);
    }
    store[key] = { count: 0, resetAt: now + windowMs };
  }

  store[key].count++;

  if (store[key].count > max) {
    var retryAfter = Math.ceil((store[key].resetAt - now) / C.TIME.seconds(1));
    return { allowed: false, remaining: 0, retryAfter: retryAfter };
  }

  return { allowed: true, remaining: max - store[key].count, retryAfter: 0 };
}

/**
 * Reset rate limit for a key (e.g. after successful login).
 */
function reset(action, key) {
  if (stores[action] && stores[action][key]) {
    delete stores[action][key];
  }
}

/**
 * Extract client IP from request.
 * Delegates to lib/client-ip.js — the single canonical HS wrapper that
 * applies the trustProxy gate before reading X-Forwarded-For.
 */
var clientIp = require("./client-ip");

function getIp(req) {
  return clientIp.getIp(req);
}

/**
 * Route middleware for rate limiting.
 * Uses 3-arg (req, res, next) signature so the router stops the chain
 * when the request is rate-limited (next is never called).
 * Chain as: app.post("/path", b.middleware.rateLimit({ scope: "action", max: max, windowMs: windowMs, algorithm: "fixed-window" }), handler)
 */
function middleware(action, max, windowMs) {
  return function (req, res, next) {
    var ip = getIp(req);
    var result = check(action, ip, max, windowMs);

    if (!result.allowed) {
      audit.log(audit.ACTIONS.RATE_LIMIT_HIT, {
        details: "action: " + action + ", ip: " + (ip || "unknown"),
        req: req,
      });
      res.writeHead(429, { "Content-Type": "application/json", "Retry-After": String(result.retryAfter) });
      res.end(JSON.stringify({ error: "Too many requests. Try again in " + result.retryAfter + " seconds." }));
      return;
    }
    next();
  };
}

// ---- Test-harness reset across every b.middleware.rateLimit instance ----
//
// Pre-0.8.77 HermitStash monkey-patched b.middleware.rateLimit to maintain
// a local registry so test harnesses could flush every limiter between
// runs. blamejs 0.8.77 added a module-level registry of its own —
// `b.middleware._modules.rateLimit.{instances, resetAll}` — so the
// monkey-patch is now dead weight. resetAllInstances is kept as a thin
// alias so existing test-helper call sites don't have to change.
function resetAllInstances() {
  // The `key` argument the old API accepted is no longer meaningful — the
  // framework's resetAll() clears all keys across all instances, which is
  // exactly what test harnesses need between cases. Callers passing a key
  // were never relying on per-key semantics here (per-key reset uses the
  // returned middleware's own .reset(key) at call site).
  return b.middleware._modules.rateLimit.resetAll();
}

module.exports = { check, reset, getIp, middleware, resetAllInstances };
