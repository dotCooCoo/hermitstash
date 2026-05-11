/**
 * HermitStash-aware client-IP extraction.
 *
 * b.requestHelpers.clientIp doesn't trust X-Forwarded-For unless the
 * caller explicitly opts in. HermitStash trusts XFF when the socket
 * peer is on the trusted-proxy list — 127.0.0.1 / ::1 / ::ffff:127.0.0.1
 * (Docker / nginx-front-end deployments) plus any additional proxies
 * the operator added via the TRUST_PROXY config.
 *
 * Single helper so the policy lives in one place; callers don't
 * reimplement trust decisions per route.
 */
// codebase-patterns:allow-file raw-remote-addr — THIS file is HermitStash's
//   canonical clientIp wrapper (mirrors lib/vendor/blamejs/lib/request-helpers.js's
//   role in blamejs). The raw socket read is the trust-gate decision: is the
//   connecting peer one of our trusted reverse proxies? Only then do we
//   honor X-Forwarded-For. Downstream callers go through getIp(), not the
//   raw field.
"use strict";

var b = require("./vendor/blamejs");

var DEFAULT_TRUSTED = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];

// Lazy config require to avoid load-cycle during startup (config → vault
// → log paths can pull client-ip via audit).
// allow:inline-require — require sits inside b.lazyRequire's loader; the
// outer is the framework primitive, the inner is the deferred load.
var configLazy = b.lazyRequire(function () {
  try { return require("./config"); } catch (_e) { return null; } // allow:silent-catch — config-not-yet-loaded during boot is expected; fall back to DEFAULT_TRUSTED // allow:inline-require — wrapped by b.lazyRequire loader above
});

function _trustList() {
  var cfg = configLazy();
  if (!cfg || !cfg.trustProxy) return DEFAULT_TRUSTED;
  var extra = String(cfg.trustProxy).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  return DEFAULT_TRUSTED.concat(extra);
}

function getIp(req) {
  if (!req) return null;
  var socketIp = req.socket && req.socket.remoteAddress || null;
  var trust = !!socketIp && _trustList().indexOf(socketIp) !== -1;
  return b.requestHelpers.clientIp(req, { trustProxy: trust });
}

module.exports = { getIp: getIp };
