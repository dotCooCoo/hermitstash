/**
 * mTLS Certificate Authority — manages CA keypair and client certificate generation.
 *
 * Uses OpenSSL CLI via child_process.execFile (async) for certificate operations.
 * Synchronous variants block the event loop for ~10–50 ms per call on ECDSA keygen,
 * which was a visible stall on /sync/renew-cert and stash-sync-token creation.
 * ECDSA P-384 for signatures (PQC cert signatures planned when OS TLS stacks
 * support ML-DSA).
 */
var crypto = require("crypto");
var fs = require("fs");
var path = require("path");
var util = require("util");
var childProcess = require("child_process");
var opensslRun = util.promisify(childProcess.execFile);
var logger = require("../app/shared/logger");

var _C = require("./constants");
var DATA_DIR = _C.DATA_DIR;
var CA_KEY_PATH = _C.PATHS.CA_KEY;
var CA_CERT_PATH = _C.PATHS.CA_CERT;

/**
 * Initialize the CA. Generates a new CA keypair if one doesn't exist.
 * Returns { key, cert } buffers or null if OpenSSL is not available.
 */
async function initCA() {
  if (fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH)) {
    return { key: fs.readFileSync(CA_KEY_PATH), cert: fs.readFileSync(CA_CERT_PATH) };
  }

  try {
    // Generate CA private key (ECDSA P-384)
    await opensslRun("openssl", ["ecparam", "-genkey", "-name", "secp384r1", "-noout", "-out", CA_KEY_PATH], { stdio: "pipe" });
    fs.chmodSync(CA_KEY_PATH, 0o600);

    // Self-sign the CA certificate (10 year validity)
    await opensslRun("openssl", ["req", "-new", "-x509", "-key", CA_KEY_PATH, "-out", CA_CERT_PATH, "-days", "3650", "-subj", "/CN=HermitStash Sync CA/O=HermitStash"], { stdio: "pipe" });

    logger.info("[mTLS] CA keypair generated", { keyPath: CA_KEY_PATH, certPath: CA_CERT_PATH });
    return { key: fs.readFileSync(CA_KEY_PATH), cert: fs.readFileSync(CA_CERT_PATH) };
  } catch (e) {
    logger.error("[mTLS] Failed to generate CA — OpenSSL may not be available", { error: e.message });
    return null;
  }
}

/**
 * Generate a client certificate signed by the CA.
 *
 * @param {string} cn — Common Name (use sync token prefix, e.g., "hs_a1b2")
 * @param {number} validityDays — certificate validity (default 365)
 * @returns {{ cert: string, key: string, ca: string }} PEM strings, or null on failure
 */
async function generateClientCert(cn, validityDays) {
  validityDays = validityDays || 365;
  var ca = await initCA();
  if (!ca) return null;

  // Sanitize CN — only alphanumeric + underscore
  cn = String(cn).replace(/[^a-zA-Z0-9_]/g, "").slice(0, 50) || "client";

  var tmpDir = path.join(DATA_DIR, "tmp-cert-" + Date.now() + "-" + crypto.randomBytes(4).toString("hex"));
  try {
    fs.mkdirSync(tmpDir, { recursive: true });
    var clientKeyPath = path.join(tmpDir, "client.key");
    var clientCsrPath = path.join(tmpDir, "client.csr");
    var clientCertPath = path.join(tmpDir, "client.crt");

    // Generate client key
    await opensslRun("openssl", ["ecparam", "-genkey", "-name", "secp384r1", "-noout", "-out", clientKeyPath], { stdio: "pipe" });

    // Generate CSR
    await opensslRun("openssl", ["req", "-new", "-key", clientKeyPath, "-out", clientCsrPath, "-subj", "/CN=" + cn + "/O=HermitStash Sync Client"], { stdio: "pipe" });

    // Sign with CA
    await opensslRun("openssl", ["x509", "-req", "-in", clientCsrPath, "-CA", CA_CERT_PATH, "-CAkey", CA_KEY_PATH, "-CAcreateserial", "-out", clientCertPath, "-days", String(validityDays)], { stdio: "pipe" });

    var now = new Date();
    var result = {
      cert: fs.readFileSync(clientCertPath, "utf8"),
      key: fs.readFileSync(clientKeyPath, "utf8"),
      ca: fs.readFileSync(CA_CERT_PATH, "utf8"),
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + validityDays * 86400000).toISOString(),
    };

    return result;
  } catch (e) {
    logger.error("[mTLS] Failed to generate client certificate", { error: e.message, cn: cn });
    return null;
  } finally {
    // Clean up temp files — never leave private keys on disk
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

/**
 * Check if the CA is initialized.
 */
function caExists() {
  return fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH);
}

module.exports = { initCA, generateClientCert, caExists, CA_KEY_PATH, CA_CERT_PATH };
