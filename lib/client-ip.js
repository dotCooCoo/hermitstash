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
"use strict";

var b = require("./vendor/blamejs");

var DEFAULT_TRUSTED = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];

// Lazy config require to avoid load-cycle during startup.
var _config = null;
function _trustList() {
  if (!_config) {
    try { _config = require("./config"); }
    catch (_e) { return DEFAULT_TRUSTED; }
  }
  if (!_config.trustProxy) return DEFAULT_TRUSTED;
  var extra = String(_config.trustProxy).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  return DEFAULT_TRUSTED.concat(extra);
}

function getIp(req) {
  if (!req) return null;
  var socketIp = req.socket && req.socket.remoteAddress || null;
  var trust = !!socketIp && _trustList().indexOf(socketIp) !== -1;
  return b.requestHelpers.clientIp(req, { trustProxy: trust });
}

module.exports = { getIp: getIp };
