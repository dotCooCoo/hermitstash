"use strict";
/**
 * pqc-agent — outbound HTTPS agent locked to PQC group preference.
 *
 * The framework's posture is "all outbound TLS is PQC-only". This is
 * the single primitive that defines what that means at the agent
 * level: TLSv1.3 minimum, ecdhCurve set to the framework's PQC hybrid
 * preference (constants.TLS_GROUP_CURVE_STR), keep-alive on.
 *
 * Two surfaces:
 *
 *   1. b.pqcAgent.agent — a process-wide default agent, lazy-built on
 *      first access. Use this for one-off outbound calls that go
 *      through node:https directly:
 *
 *        https.request(url, { agent: b.pqcAgent.agent }, ...);
 *
 *   2. b.pqcAgent.create(opts) — build a fresh agent with custom
 *      pool / timeout opts. ecdhCurve and minVersion CANNOT be
 *      weakened via opts; operator-supplied values for those are
 *      ignored and the framework's defaults win. Operators who need
 *      a non-PQC agent for a deliberate one-off integration with a
 *      non-PQC server construct their own new https.Agent() directly,
 *      outside this primitive.
 *
 * lib/http-client.js's transport cache uses pqcAgent.create() under
 * the hood, so the framework's bundled HTTP client and any operator-
 * direct https.request calls converge on the same agent posture.
 */

var https = require("node:https");
var http  = require("node:http");
var C = require("./constants");
var networkTls = require("./network-tls");

// Defaults for connection pooling. These ARE overridable via opts —
// only the cryptographic posture (ecdhCurve / minVersion) is locked.
var DEFAULT_OPTS = {
  keepAlive:      true,
  keepAliveMsecs: C.TIME.seconds(30),
  maxSockets:     50,
  // Pool counts are protocol-side concurrency tunables, not byte
  // quantities — hex form keeps the byte-shape detector out of it.
  maxFreeSockets: 0x10,
  scheduling:     "lifo",
};

function _buildAgentOpts(opts) {
  opts = opts || {};
  var merged = Object.assign({}, DEFAULT_OPTS, opts);
  merged.ecdhCurve  = C.TLS_GROUP_CURVE_STR;
  merged.minVersion = "TLSv1.3";
  if (networkTls && typeof networkTls.applyToContext === "function") {
    merged = networkTls.applyToContext({ base: merged });
  }
  return merged;
}

function create(opts) {
  return new https.Agent(_buildAgentOpts(opts));
}

// http (cleartext) variant — same pool defaults but obviously no TLS
// posture to enforce. Operator-side, almost no caller wants this; it
// exists so http-client's h1 transport for cleartext origins (h2c
// fixtures, internal services) shares the pool tuning.
function createHttp(opts) {
  return new http.Agent(Object.assign({}, DEFAULT_OPTS, opts || {}));
}

// Lazy-built default agent. Most callers use this; the lazy build
// avoids creating an https.Agent at require time for processes that
// never make an outbound HTTPS call.
var _defaultAgent = null;
function _getDefaultAgent() {
  if (!_defaultAgent) _defaultAgent = create();
  return _defaultAgent;
}

module.exports = {
  // Read property — getter so the agent is built on first access.
  get agent()  { return _getDefaultAgent(); },
  create:      create,
  createHttp:  createHttp,
  DEFAULT_OPTS: DEFAULT_OPTS,
  enforced:    true,
};
