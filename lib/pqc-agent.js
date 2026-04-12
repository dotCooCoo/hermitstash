/**
 * Global PQC-configured HTTPS agent for outbound connections.
 * All outbound HTTPS requests must use this agent.
 * PQC-only — no classical fallback. Connection fails if remote doesn't support PQC.
 */
var https = require("node:https");

var agent = new https.Agent({
  ecdhCurve: "X25519MLKEM768:SecP256r1MLKEM768",
  minVersion: "TLSv1.3",
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 50,
});

module.exports = { agent: agent, enforced: true };
