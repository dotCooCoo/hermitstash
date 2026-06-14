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
  try { return require("./config"); } catch (_e) { return null; } // allow:inline-require — deferred load wrapped by b.lazyRequire; config-not-yet-loaded at boot falls back to DEFAULT_TRUSTED
});

function _trustList() {
  var cfg = configLazy();
  if (!cfg || !cfg.trustProxy) return DEFAULT_TRUSTED;
  var extra = String(cfg.trustProxy).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  return DEFAULT_TRUSTED.concat(extra);
}

// Number of reverse-proxy hops that append to X-Forwarded-For. The bundled
// nginx uses `$proxy_add_x_forwarded_for`, which appends exactly one ($remote_addr).
// We must select the RIGHTMOST-untrusted XFF entry (the one our proxy appended),
// not the leftmost (which the client can forge); the framework does that when
// trustProxy is the hop COUNT rather than the boolean `true`.
function _trustHops() {
  var cfg = configLazy();
  var n = cfg ? parseInt(cfg.trustProxyHops, 10) : NaN;
  return (Number.isFinite(n) && n >= 1) ? n : 1;
}

// Canonicalize an address to a single representation so the blocklist, the
// rate-limit key, and the audit log all key off the same string. An
// IPv4-mapped IPv6 peer (::ffff:1.2.3.4 — common on a dual-stack listener or a
// proxy forwarding a mapped form) is folded to its dotted-quad so a block on
// 1.2.3.4 also catches it, and the inverse can't be used to evade a block;
// IPv6 is lowercased. (Full IPv6 zero-compression normalization is not
// attempted — a given listener surfaces a consistent form.)
function canonicalize(ip) {
  if (typeof ip !== "string" || !ip) return ip;
  var lower = ip.toLowerCase();
  var m = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(lower);
  return m ? m[1] : lower;
}

function getIp(req) {
  if (!req) return null;
  var socketIp = req.socket && req.socket.remoteAddress || null;
  // Trust gate reads the raw socket peer (DEFAULT_TRUSTED carries both the
  // dotted-quad and IPv4-mapped loopback forms); only the returned client
  // address is canonicalized, so every consumer keys off one representation.
  var trusted = !!socketIp && _trustList().indexOf(socketIp) !== -1;
  // Pass a hop COUNT (not boolean true): the framework returns the
  // rightmost-untrusted X-Forwarded-For entry (the value our reverse proxy
  // appended) instead of the attacker-forgeable leftmost one. A client could
  // otherwise rotate XFF to spoof its IP and evade the blocklist / rate limit.
  return canonicalize(b.requestHelpers.clientIp(req, { trustProxy: trusted ? _trustHops() : false }));
}

module.exports = { getIp: getIp, canonicalize: canonicalize };
