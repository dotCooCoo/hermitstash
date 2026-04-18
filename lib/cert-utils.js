/**
 * Certificate utility functions — single source of truth for cert fingerprint
 * hashing and revocation checking. Every callsite uses these instead of
 * reimplementing the hash computation or doing full-table scans.
 */
var { sha3Hash } = require("./crypto");
var { HASH_PREFIX } = require("./constants");

/**
 * Hash a certificate fingerprint for revocation lookups.
 * Uses the CERT_FP hash prefix for consistency across all callsites.
 * @param {string} fingerprint256 — cert.fingerprint256 from Node TLS
 * @returns {string} SHA3-512 hash suitable for DB lookup
 */
function hashCertFingerprint(fingerprint256) {
  return sha3Hash(HASH_PREFIX.CERT_FP + (fingerprint256 || ""));
}

/**
 * Check whether a certificate has been revoked.
 * Uses indexed findOne() instead of full-table scan + JS filter.
 * @param {string} fingerprint256 — cert.fingerprint256 from Node TLS
 * @returns {boolean} true if revoked
 */
function isCertRevoked(fingerprint256) {
  var db = require("./db");
  var fpHash = hashCertFingerprint(fingerprint256);
  var match = db.certRevocations.findOne({ fingerprintHash: fpHash });
  return !!match;
}

module.exports = { hashCertFingerprint, isCertRevoked };
