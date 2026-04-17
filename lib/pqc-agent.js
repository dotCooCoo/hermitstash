/**
 * Global PQC-configured HTTPS agent for outbound connections.
 * All outbound HTTPS requests must use this agent.
 * PQC-only — no classical fallback. Connection fails if remote doesn't support PQC.
 */
var https = require("node:https");
var { TLS_GROUP_CURVE_STR } = require("./constants");

var agent = new https.Agent({
  ecdhCurve: TLS_GROUP_CURVE_STR,
  minVersion: "TLSv1.3",
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 50,
});

module.exports = { agent: agent, enforced: true };
