/**
 * Global PQC-configured HTTPS agent for outbound connections.
 * All outbound HTTPS requests should use this agent.
 *
 * PQC_OUTBOUND_ENFORCE=true (default): PQC-only groups, connection fails
 * if the remote server doesn't support PQC TLS.
 * PQC_OUTBOUND_ENFORCE=false: PQC preferred but classical fallback allowed.
 */
var https = require("node:https");

var enforce = process.env.PQC_OUTBOUND_ENFORCE !== "false";

var pqcAgent = new https.Agent({
  ecdhCurve: "X25519MLKEM768:SecP256r1MLKEM768",
  minVersion: "TLSv1.3",
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 50,
});

var pqcPreferredAgent = new https.Agent({
  ecdhCurve: "X25519MLKEM768:SecP256r1MLKEM768:X25519:prime256v1:secp384r1",
  minVersion: "TLSv1.3",
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 50,
});

module.exports = {
  agent: enforce ? pqcAgent : pqcPreferredAgent,
  enforced: enforce,
};
