/**
 * mTLS Certificate Authority — manages CA keypair and client certificate generation.
 *
 * Pure-JS implementation via vendored @peculiar/x509 + pkijs. No openssl CLI
 * dependency. Works in any Node 24.8+ environment (uses node:crypto.webcrypto
 * internally, which ships with the runtime).
 *
 * Algorithm envelope:
 *   - CA signature: ECDSA P-384 with SHA-384 hash (see CA_SIG_ALG)
 *   - Client cert signature: same as CA (chain consistency)
 *   - PKCS#12 key bag: PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA512 + P12_ITER iterations
 *   - PKCS#12 cert bag: same as key bag
 *   - PKCS#12 outer MAC: HMAC-SHA-512 + PBKDF2 + P12_ITER iterations
 *
 * These are centralized in the ALG_* constants below so the primitives can be
 * swapped atomically when browser/OS support lands for:
 *   - ML-DSA-87 or SLH-DSA-SHAKE-256f cert signatures (post-quantum)
 *   - AES-256-GCM key bag (once all major OS cert importers accept it)
 *   - PBMAC1 outer MAC (RFC 9579) once it's broadly supported
 *
 * Search for TODO(pqc-certs) and TODO(pkcs12-upgrade) to find the upgrade points.
 */
var crypto = require("crypto");
// Random bytes go through generateBytes() from lib/crypto.js for the
// SHA3-wrapped defense-in-depth RNG — see regression.test.js convention.
var { generateBytes } = require("./crypto");
var fs = require("fs");
var logger = require("../app/shared/logger");

var _C = require("./constants");
var CA_KEY_PATH = _C.PATHS.CA_KEY;
var CA_CERT_PATH = _C.PATHS.CA_CERT;

// Vendored peculiar-pki bundle: @peculiar/x509 + pkijs + reflect-metadata +
// ASN.1 transitive deps. CryptoEngine is pre-bound to node:webcrypto inside
// the bundle entry (see scripts/vendor-update.sh peculiar-pki case).
var pki = require("./vendor/pki.cjs");
var x509 = pki.x509;
var pkijs = pki.pkijs;
var webcrypto = pki.crypto;

// ---- Algorithm envelope ----
// Bump these together when upgrading. See TODOs below for swap criteria.
//
// TODO(pqc-certs): switch to { name: "ML-DSA-87" } or { name: "SLH-DSA-SHAKE-256f" }
//   when all mainstream browsers + OS cert stores can verify PQ signatures on
//   client certificates. As of 2026-04 none do — issuing PQ-signed certs today
//   would break mTLS handshake validation in every browser. Node 24.8+ webcrypto
//   supports ML-DSA via OpenSSL 3.5; pkijs likely needs a version bump to accept
//   the algorithm name in X509CertificateGenerator.create().
var CA_KEY_ALG = { name: "ECDSA", namedCurve: "P-384" };
var CA_SIG_ALG = { name: "ECDSA", hash: "SHA-384" };
var CA_KEY_USAGES = ["sign", "verify"];

// ---- CA generation marker ----
// Bump this constant atomically with any change to the algorithm envelope above
// (CA_KEY_ALG, CA_SIG_ALG, P12_*). Every CA issued by initCA() embeds its
// generation in the subject DN as OU=CAv{N}. On boot we parse the existing CA's
// OU — if it's missing or lower than CA_GENERATION, the admin Danger Zone shows
// a legacy warning and prompts regeneration. Untagged CAs (pre-v1.8.8) are
// treated as generation 1 so the first regen lifts them to 2.
//
// Generation history:
//   1 (pre-tagged) — openssl CLI era, SHA-256 cert sigs, 600k PBKDF2 iters
//   2 (v1.8.8+)   — pure-JS pkijs era, SHA-384 cert sigs, 2M PBKDF2 iters,
//                   SHA-512 PRF, AES-256-CBC key bags
var CA_GENERATION = 2;

// TODO(pkcs12-upgrade):
//   - contentEncryptionAlgorithm → { name: "AES-GCM", length: 256 } once
//     Windows 10/11 cert importer + macOS Keychain universally accept it.
//     As of 2026-04 pkijs supports the encoding but some OS importers fail
//     the integrity check on PBES2-AES-GCM key bags. CBC stays universal.
//   - Swap outer MAC for PBMAC1 (RFC 9579 PKCS#12 v3) once broadly supported.
//     pkijs exposes this via PFX.makeInternalValues( pbmac1: true ) though the
//     exact API is under evolution.
var P12_CONTENT_ENC = { name: "AES-CBC", length: 256 };
var P12_KDF_HASH = "SHA-512"; // PBKDF2 PRF for key derivation AND outer MAC
var P12_MAC_HASH = "SHA-512";
var P12_ITER = 2000000; // PBKDF2 iterations (both encryption and MAC)

// ---- Helper: persist a webcrypto CryptoKey pair to PEM ----
async function exportKeyPairToPem(keyPair) {
  var pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  var spki = await webcrypto.subtle.exportKey("spki", keyPair.publicKey);
  return {
    privatePem: "-----BEGIN PRIVATE KEY-----\n" + Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n") + "\n-----END PRIVATE KEY-----\n",
    publicPem: "-----BEGIN PUBLIC KEY-----\n" + Buffer.from(spki).toString("base64").match(/.{1,64}/g).join("\n") + "\n-----END PUBLIC KEY-----\n",
  };
}

// ---- Helper: load a PEM private key back into a webcrypto CryptoKey ----
// Import a PEM private key regardless of its on-disk format. Existing CA keys
// may be SEC1 ("BEGIN EC PRIVATE KEY"), PKCS#1 ("BEGIN RSA PRIVATE KEY"), or
// PKCS#8 ("BEGIN PRIVATE KEY") — e.g. older deployments (and the sync test
// harness) use openssl's default ecparam output which is SEC1. Node's
// createPrivateKey accepts all three and normalizes; we then emit PKCS#8 DER
// which webcrypto's importKey requires.
//
// extractable=true required when the key will be re-exported (e.g. for
// PKCS#12 shrouded key bag). Defaults to false for sign-only usages where
// the key should never leave the process.
async function importPemPrivateKey(pem, alg, usages, extractable) {
  var keyObj = crypto.createPrivateKey(pem);
  var pkcs8Der = keyObj.export({ format: "der", type: "pkcs8" });
  return webcrypto.subtle.importKey("pkcs8", pkcs8Der, alg, !!extractable, usages);
}
// ---- Helper: parse a PEM cert into an X509Certificate via @peculiar/x509 ----
function parseCertPem(pem) {
  return new x509.X509Certificate(pem);
}

// ---- Helper: extract CA generation from subject DN ----
// Returns the integer N from OU=CAv{N} in the cert's subject DN, or 1 if no
// such OU is present (untagged legacy CA).
function parseCaGeneration(caCertPem) {
  try {
    var cert = parseCertPem(caCertPem);
    // cert.subject is a string like "CN=HermitStash Sync CA, OU=CAv2, O=HermitStash"
    var m = /OU=CAv(\d+)/.exec(cert.subject || "");
    return m ? parseInt(m[1], 10) : 1;
  } catch (_e) {
    return 1;
  }
}

/**
 * Return CA status — presence, generation, and whether it's behind the current
 * algorithm envelope. Used by startup-checks and the admin Danger Zone to
 * surface a regeneration prompt after an upgrade.
 */
function getCaStatus() {
  if (!caExists()) return { exists: false, generation: 0, isLegacy: false, current: CA_GENERATION };
  var pem = fs.readFileSync(CA_CERT_PATH, "utf8");
  var gen = parseCaGeneration(pem);
  return { exists: true, generation: gen, isLegacy: gen < CA_GENERATION, current: CA_GENERATION };
}

/**
 * Generate a fresh CA keypair + self-signed cert in memory, without touching
 * disk. Used by both initCA() (first-time bootstrap) and the admin-triggered
 * regeneration flow (where we need the new CA loaded into TLS trust before
 * the old files are replaced, so active clients get rotated before restart).
 */
async function generateNewCaInMemory() {
  var keys = await webcrypto.subtle.generateKey(CA_KEY_ALG, true, CA_KEY_USAGES);
  var caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: generateBytes(16).toString("hex"),
    name: "CN=HermitStash Sync CA,OU=CAv" + CA_GENERATION + ",O=HermitStash",
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 10 * 365 * 86400000), // 10 years
    signingAlgorithm: CA_SIG_ALG,
    keys: keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true
      ),
    ],
  });
  var pem = await exportKeyPairToPem(keys);
  return { caCertPem: caCert.toString("pem"), caKeyPem: pem.privatePem };
}

/**
 * Atomically replace the on-disk CA files with the provided PEMs.
 * Writes via temp + rename so a crash mid-write can't leave a half-written CA.
 */
function commitNewCa(caCertPem, caKeyPem) {
  var keyTmp = CA_KEY_PATH + ".tmp";
  var certTmp = CA_CERT_PATH + ".tmp";
  fs.writeFileSync(keyTmp, caKeyPem, { mode: 0o600 });
  fs.writeFileSync(certTmp, caCertPem);
  fs.renameSync(keyTmp, CA_KEY_PATH);
  fs.renameSync(certTmp, CA_CERT_PATH);
}

/**
 * Initialize the CA. Generates a new CA keypair if one doesn't exist.
 * Returns { key: Buffer (PEM), cert: Buffer (PEM) } or null on failure.
 */
async function initCA() {
  if (fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH)) {
    return { key: fs.readFileSync(CA_KEY_PATH), cert: fs.readFileSync(CA_CERT_PATH) };
  }
  try {
    var fresh = await generateNewCaInMemory();
    commitNewCa(fresh.caCertPem, fresh.caKeyPem);
    logger.info("[mTLS] CA keypair generated (pure JS)", { keyPath: CA_KEY_PATH, certPath: CA_CERT_PATH, sigAlg: CA_SIG_ALG, generation: CA_GENERATION });
    return { key: fs.readFileSync(CA_KEY_PATH), cert: fs.readFileSync(CA_CERT_PATH) };
  } catch (e) {
    logger.error("[mTLS] Failed to generate CA", { error: e.message });
    return null;
  }
}

/**
 * Internal: issue a client cert signed by the provided CA PEMs. Extracted so
 * both generateClientCert (load-from-disk) and generateClientCertWithCa
 * (caller-supplied, used during dual-CA rotation) share one implementation.
 */
async function _signClientCert(cn, caCertPem, caKeyPem, validityDays) {
  validityDays = validityDays || 365;
  cn = String(cn).replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 50) || "client";

  try {
    var caPrivateKey = await importPemPrivateKey(caKeyPem, CA_KEY_ALG, ["sign"]);
    var caCert = parseCertPem(caCertPem);
    var clientKeys = await webcrypto.subtle.generateKey(CA_KEY_ALG, true, CA_KEY_USAGES);
    var now = new Date();
    var clientCert = await x509.X509CertificateGenerator.create({
      serialNumber: generateBytes(16).toString("hex"),
      subject: "CN=" + cn + ",O=HermitStash Sync Client",
      issuer: caCert.subject,
      notBefore: now,
      notAfter: new Date(now.getTime() + validityDays * 86400000),
      signingAlgorithm: CA_SIG_ALG,
      publicKey: clientKeys.publicKey,
      signingKey: caPrivateKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
          true
        ),
        new x509.ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.2"], true), // clientAuth
      ],
    });
    var pem = await exportKeyPairToPem(clientKeys);
    return {
      cert: clientCert.toString("pem"),
      key: pem.privatePem,
      ca: caCertPem,
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + validityDays * 86400000).toISOString(),
    };
  } catch (e) {
    logger.error("[mTLS] Failed to generate client certificate", { error: e.message, cn: cn });
    return null;
  }
}

/**
 * Generate a client certificate signed by the on-disk CA. Lazy-initializes
 * the CA if it doesn't yet exist.
 *
 * @param {string} cn — Common Name (use sync token prefix, e.g., "hs_a1b2")
 * @param {number} validityDays — certificate validity (default 365)
 * @returns {Promise<{ cert, key, ca, issuedAt, expiresAt } | null>} PEM strings
 */
async function generateClientCert(cn, validityDays) {
  var ca = await initCA();
  if (!ca) return null;
  return _signClientCert(cn, ca.cert.toString("utf8"), ca.key.toString("utf8"), validityDays);
}

/**
 * Generate a client certificate signed by the caller-supplied CA PEMs. Used
 * by the admin regeneration flow to pre-sign new client certs with a freshly
 * generated (not-yet-persisted) CA so active sync clients can rotate before
 * the on-disk CA is swapped and the server restarts.
 */
async function generateClientCertWithCa(cn, caCertPem, caKeyPem, validityDays) {
  return _signClientCert(cn, caCertPem, caKeyPem, validityDays);
}

/**
 * Generate a client cert and package it as PKCS#12 for browser import.
 *
 * Layout: one PFX envelope containing two SafeContents — one for the
 * PKCS#8-shrouded private key, one for the client + CA certs. Both
 * SafeContents are encrypted with PBES2 + AES-256-CBC and the outer PFX
 * integrity is an HMAC-SHA-512 PBKDF2'd from the password. All KDFs use
 * 2,000,000 iterations (well above OWASP's 2023 recommendation).
 *
 * @param {string} cn — Common Name (e.g., "alice-laptop")
 * @param {string} password — PKCS#12 encryption password
 * @param {number} validityDays — cert validity (default 365)
 * @returns {Promise<{ p12, fingerprint256, certPem, issuedAt, expiresAt } | null>}
 */
async function generateClientP12(cn, password, validityDays) {
  if (!password || typeof password !== "string" || password.length < 1) {
    throw new Error("Password is required for PKCS#12 packaging");
  }
  var client = await generateClientCert(cn, validityDays);
  if (!client) return null;

  try {
    // Export client private key as PKCS#8 DER for the shrouded key bag.
    // Must import as extractable so we can exportKey to pkcs8 below.
    var clientPrivateKey = await importPemPrivateKey(client.key, CA_KEY_ALG, ["sign"], true);
    var pkcs8Der = await webcrypto.subtle.exportKey("pkcs8", clientPrivateKey);
    var privateKeyInfo = pkijs.PrivateKeyInfo.fromBER(pkcs8Der);

    // Parse client + CA certs into pkijs Certificate objects
    var clientX509 = parseCertPem(client.cert);
    var caX509 = parseCertPem(client.ca);
    var clientPkijsCert = pkijs.Certificate.fromBER(clientX509.rawData);
    var caPkijsCert = pkijs.Certificate.fromBER(caX509.rawData);

    var passwordBuf = Buffer.from(password, "utf8");

    var pfx = new pkijs.PFX({
      parsedValue: {
        integrityMode: 0, // PasswordMode (outer HMAC-PBKDF2)
        authenticatedSafe: new pkijs.AuthenticatedSafe({
          parsedValue: {
            safeContents: [
              {
                privacyMode: 1, // PasswordPrivacyMode (PBES2)
                value: new pkijs.SafeContents({
                  safeBags: [
                    new pkijs.SafeBag({
                      bagId: "1.2.840.113549.1.12.10.1.2", // pkcs-12-pkcs-8ShroudedKeyBag
                      bagValue: new pkijs.PKCS8ShroudedKeyBag({ parsedValue: privateKeyInfo }),
                    }),
                  ],
                }),
              },
              {
                privacyMode: 1,
                value: new pkijs.SafeContents({
                  safeBags: [
                    new pkijs.SafeBag({
                      bagId: "1.2.840.113549.1.12.10.1.3", // pkcs-12-certBag
                      bagValue: new pkijs.CertBag({ parsedValue: clientPkijsCert }),
                    }),
                    new pkijs.SafeBag({
                      bagId: "1.2.840.113549.1.12.10.1.3",
                      bagValue: new pkijs.CertBag({ parsedValue: caPkijsCert }),
                    }),
                  ],
                }),
              },
            ],
          },
        }),
      },
    });

    // Encrypt the shrouded-key bag contents (inner protection of the key itself)
    await pfx.parsedValue.authenticatedSafe.parsedValue.safeContents[0].value.safeBags[0].bagValue.makeInternalValues({
      password: passwordBuf,
      contentEncryptionAlgorithm: P12_CONTENT_ENC,
      hmacHashAlgorithm: P12_KDF_HASH,
      iterationCount: P12_ITER,
    });

    // Encrypt each SafeContents envelope
    await pfx.parsedValue.authenticatedSafe.makeInternalValues({
      safeContents: [
        { password: passwordBuf, contentEncryptionAlgorithm: P12_CONTENT_ENC, hmacHashAlgorithm: P12_KDF_HASH, iterationCount: P12_ITER },
        { password: passwordBuf, contentEncryptionAlgorithm: P12_CONTENT_ENC, hmacHashAlgorithm: P12_KDF_HASH, iterationCount: P12_ITER },
      ],
    });

    // Outer PFX integrity MAC (HMAC-SHA-512, 2M-iter PBKDF2)
    await pfx.makeInternalValues({
      password: passwordBuf,
      iterations: P12_ITER,
      pbkdf2HashAlgorithm: P12_KDF_HASH,
      hmacHashAlgorithm: P12_MAC_HASH,
    });

    var pfxDer = pfx.toSchema().toBER(false);
    var p12Buf = Buffer.from(pfxDer);

    // fingerprint256 is the same SHA-256 hex that Node's tls returns as
    // socket.getPeerCertificate().fingerprint256 (colon-separated uppercase hex).
    // Node's X509Certificate produces it natively so downstream per-key cert
    // binding checks match without extra normalization.
    var der = new crypto.X509Certificate(client.cert);
    var fp256 = der.fingerprint256;

    return {
      p12: p12Buf,
      fingerprint256: fp256,
      certPem: client.cert,
      issuedAt: client.issuedAt,
      expiresAt: client.expiresAt,
    };
  } catch (e) {
    logger.error("[mTLS] Failed to build PKCS#12", { error: e.message, cn: cn });
    return null;
  }
}

/**
 * Check if the CA is initialized.
 */
function caExists() {
  return fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH);
}

module.exports = {
  initCA,
  generateClientCert,
  generateClientCertWithCa,
  generateClientP12,
  generateNewCaInMemory,
  commitNewCa,
  caExists,
  getCaStatus,
  parseCaGeneration,
  CA_GENERATION: CA_GENERATION,
  CA_KEY_PATH: CA_KEY_PATH,
  CA_CERT_PATH: CA_CERT_PATH,
};
