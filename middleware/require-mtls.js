/**
 * mTLS middleware — enforces client certificate authentication.
 * Applied to sync WebSocket routes only, not to web UI or public uploads.
 */
var { sha3Hash } = require("../lib/crypto");
var { HASH_PREFIX } = require("../lib/constants");

module.exports = function requireMtls(req, res) {
  var cert = req.socket ? req.socket.getPeerCertificate() : null;

  if (!cert || !cert.subject) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Client certificate required for sync operations." }));
    return false;
  }

  if (!req.client || !req.client.authorized) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Client certificate not trusted." }));
    return false;
  }

  // Check revocation list (indexed lookup, not full-table scan)
  try {
    if (require("../lib/cert-utils").isCertRevoked(cert.fingerprint256)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Certificate has been revoked." }));
      return false;
    }
  } catch (_e) { /* cert_revocations table may not exist yet */ }

  req.mtlsClient = {
    cn: cert.subject.CN,
    fingerprint: cert.fingerprint256,
  };

  return true;
};
