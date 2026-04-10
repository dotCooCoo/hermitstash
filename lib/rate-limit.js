/**
 * In-memory rate limiter.
 * Tracks attempts per key (usually IP) per action within a sliding window.
 * Returns { allowed, remaining, retryAfter } on each check.
 */
var audit = require("./audit");

var stores = {}; // action -> { key -> { count, resetAt } }

var cleanupTimer = setInterval(function () {
  var now = Date.now();
  for (var action in stores) {
    var store = stores[action];
    for (var key in store) {
      if (now > store[key].resetAt) delete store[key];
    }
  }
}, 60000);
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
    store[key] = { count: 0, resetAt: now + windowMs };
  }

  store[key].count++;

  if (store[key].count > max) {
    var retryAfter = Math.ceil((store[key].resetAt - now) / 1000);
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
 * Only trusts X-Forwarded-For when TRUST_PROXY is configured and the
 * direct connection comes from a trusted proxy IP. Otherwise uses
 * the socket remote address to prevent XFF spoofing.
 */
// Lazy-load config once (avoids circular dep during early module init)
var _config = null;
function getConfig() { if (!_config) { try { _config = require("./config"); } catch (_e) {} } return _config; }

function getIp(req) {
  if (!req) return null;
  var socketIp = req.socket && req.socket.remoteAddress || null;
  var fwd = req.headers && req.headers["x-forwarded-for"];
  if (fwd) {
    var trustedProxies = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];
    var cfg = getConfig();
    if (cfg && cfg.trustProxy) trustedProxies.push.apply(trustedProxies, String(cfg.trustProxy).split(",").map(function(s) { return s.trim(); }));
    if (socketIp && trustedProxies.indexOf(socketIp) !== -1) {
      return fwd.split(",")[0].trim();
    }
  }
  return socketIp;
}

/**
 * Route handler guard for rate limiting.
 * Works with the custom Router (handlers called as (req, res), no next).
 * If rate limited, sends 429 and ends the response.
 * Chain as: app.post("/path", rateLimit.middleware("action", max, windowMs), handler)
 */
function middleware(action, max, windowMs) {
  return function (req, res) {
    var ip = getIp(req);
    var result = check(action, ip, max, windowMs);

    if (!result.allowed) {
      audit.log(audit.ACTIONS.RATE_LIMIT_HIT, {
        details: "action: " + action + ", ip: " + (ip || "unknown"),
        req: req,
      });
      res.writeHead(429, { "Content-Type": "application/json", "Retry-After": String(result.retryAfter) });
      res.end(JSON.stringify({ error: "Too many requests. Try again in " + result.retryAfter + " seconds." }));
    }
    // If allowed, don't end res — next handler in chain runs automatically
  };
}

module.exports = { check, reset, getIp, middleware };
