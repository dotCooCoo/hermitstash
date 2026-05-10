/**
 * Certificate utility functions — single source of truth for cert fingerprint
 * hashing and revocation checking. Every callsite uses these instead of
 * reimplementing the hash computation or doing full-table scans.
 */
var b = require("./vendor/blamejs");
var { HASH_PREFIX } = require("./constants");

/**
 * Hash a certificate fingerprint for revocation lookups.
 * Uses the CERT_FP hash prefix for consistency across all callsites.
 * @param {string} fingerprint256 — cert.fingerprint256 from Node TLS
 * @returns {string} SHA3-512 hash suitable for DB lookup
 */
function hashCertFingerprint(fingerprint256) {
  return b.crypto.namespaceHash(HASH_PREFIX.CERT_FP, fingerprint256 || "");
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
 * Canonicalize a PEM certificate to a single byte-form: BEGIN line, base64
 * body wrapped at 64 chars, END line, terminating newline. Required because
 * the source of a PEM (peculiar/x509 .toString("pem"), openssl, on-disk
 * file) varies in trailing whitespace and line wrapping. Without canonical
 * form, sha3(certIssuedAtServer) !== sha3(reconstructedFromPeerCertRaw)
 * and enforceCertBinding always 403s sync clients.
 * @param {string} pem — any PEM-encoded X.509 certificate
 * @returns {string} canonical PEM (always ends with `\n`)
 */
function canonicalCertPem(pem) {
  if (!pem) return "";
  var body = String(pem).replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/g, "");
  if (!body) return "";
  var derB64 = Buffer.from(body, "base64").toString("base64");
  return "-----BEGIN CERTIFICATE-----\n" + derB64.match(/.{1,64}/g).join("\n") + "\n-----END CERTIFICATE-----\n";
}

/**
 * Compute the canonical SHA3-512 fingerprint over a cert. Single source of
 * truth — issuance (routes/stash.js, server-main.js cert renewal) AND
 * verification (middleware/sync-guards.js peer cert) both go through here
 * so they hash identical bytes.
 * @param {string} pem — PEM string
 * @returns {string} SHA3-512 hex digest
 */
function certFingerprintSha3(pem) {
  return b.crypto.sha3Hash(canonicalCertPem(pem));
}

/**
 * Generate an enrollment code (HSTASH-XXXX-XXXX-XXXX) and its hash.
 * @returns {{ codeRaw: string, codeHash: string }}
 */
function generateEnrollmentCode() {
  ;
  var codeBytes = b.crypto.generateBytes(8);
  var codeRaw = "HSTASH-" + codeBytes.toString("hex").toUpperCase().match(/.{4}/g).join("-");
  var codeHash = b.crypto.namespaceHash(HASH_PREFIX.ENROLLMENT, codeRaw);
  return { codeRaw: codeRaw, codeHash: codeHash };
}

module.exports = { hashCertFingerprint, isCertRevoked, revokeCert, generateEnrollmentCode, canonicalCertPem, certFingerprintSha3 };
