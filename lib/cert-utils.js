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

/**
 * Revoke a certificate by fingerprint. Writes to cert_revocations so future
 * TLS handshakes with this cert are rejected by isCertRevoked().
 * Idempotent — a second call for the same fingerprint is a no-op.
 * @param {string} fingerprint256 — cert.fingerprint256 from Node TLS
 * @param {string} cn — common name for audit trail (optional)
 * @param {string} reason — human-readable reason (optional)
 * @returns {boolean} true if a new record was written
 */
function revokeCert(fingerprint256, cn, reason) {
  if (!fingerprint256) return false;
  var db = require("./db");
  var fpHash = hashCertFingerprint(fingerprint256);
  var existing = db.certRevocations.findOne({ fingerprintHash: fpHash });
  if (existing) return false;
  db.certRevocations.insert({
    fingerprintHash: fpHash,
    cn: cn || "",
    reason: reason || "",
    revokedAt: new Date().toISOString(),
  });
  return true;
}

/**
 * Generate an enrollment code (HSTASH-XXXX-XXXX-XXXX) and its hash.
 * @returns {{ codeRaw: string, codeHash: string }}
 */
function generateEnrollmentCode() {
  var { generateBytes } = require("./crypto");
  var codeBytes = generateBytes(8);
  var codeRaw = "HSTASH-" + codeBytes.toString("hex").toUpperCase().match(/.{4}/g).join("-");
  var codeHash = sha3Hash(HASH_PREFIX.ENROLLMENT + codeRaw);
  return { codeRaw: codeRaw, codeHash: codeHash };
}

module.exports = { hashCertFingerprint, isCertRevoked, revokeCert, generateEnrollmentCode };
