// codebase-patterns:allow-file raw-process-env — bootstrap reads of CA_KEY_SEALED / MTLS_BROWSER_CA_KEY / MTLS_BROWSER_CA_CERT before b.mtlsCa.create takes over
/**
 * Process-wide singleton for HermitStash's BROWSER-cert mTLS CA.
 *
 * A SECOND CA, separate from the sync CA (lib/mtls-ca.js), pinned to the
 * classical ECDSA-P384-SHA384 algorithm. It signs the PKCS#12 client certs
 * humans import into a browser / OS keystore to reach the web UI when
 * enforceMtls is on. It is kept classical on purpose: today's browsers and OS
 * keystores cannot complete an ML-DSA TLS client-auth handshake, nor import a
 * PBMAC1 (RFC 9879) PKCS#12 — so the sync CA can migrate to the PQC (ML-DSA-87)
 * default while browser certs stay universally importable. The TLS server trusts
 * BOTH CAs' certs in its mTLS `ca` bundle, and revocation covers both.
 *
 * Own generation (C.CA_BROWSER_GENERATION) and own on-disk files
 * (ca-browser.crt / ca-browser.key[.sealed], ca-browser-revocations.json,
 * ca-browser.crl) so it is generated, rotated, and revoked independently of the
 * sync CA. Generated lazily on the first browser-cert issuance (initCA()).
 *
 * Every caller does `var mtlsCaBrowser = require("./mtls-ca-browser")` and calls
 * the b.mtlsCa instance methods directly — `exists`, `status`, `initCA`,
 * `generateClientP12`, `revoke`, etc.
 */
"use strict";

var nodeFs = require("node:fs");
var b = require("./vendor/blamejs");
var C = require("./constants");
var vault = require("./vault");

// blamejs accepts only `required` / `disabled`; HS's `auto` falls back to
// whichever mode matches the on-disk browser-CA sealed file (mirrors mtls-ca.js).
function _resolveCaKeySealedMode() {
  var env = (process.env.CA_KEY_SEALED || "auto").toLowerCase();
  if (env === "required" || env === "disabled") return env;
  return nodeFs.existsSync(C.PATHS.CA_BROWSER_KEY_SEALED) ? "required" : "disabled";
}

// Operators may point the browser CA key/cert at absolute paths (read-only
// secret volume) via MTLS_BROWSER_CA_KEY / MTLS_BROWSER_CA_CERT.
var caKeyOverride  = process.env.MTLS_BROWSER_CA_KEY  || null;
var caCertOverride = process.env.MTLS_BROWSER_CA_CERT || null;
module.exports = b.mtlsCa.create({
  dataDir:          C.DATA_DIR,
  paths: {
    caKey:        caKeyOverride  || "ca-browser.key",
    caKeySealed:  (caKeyOverride || "ca-browser.key") + ".sealed",
    caCert:       caCertOverride || "ca-browser.crt",
    // Own revocation registry + CRL + retained-root + issuance ledger +
    // generation watermark + algorithm label so EVERY b.mtlsCa on-disk artifact
    // is distinct from the sync CA's. Both handles share DATA_DIR, and the
    // defaults (ca.prev.crt / issuance.json / revoked-generation / ca.algorithm)
    // would otherwise be shared: the sync CA's retained root would appear in the
    // browser CA's trust bundle, and — since both handles record every issued
    // leaf into the ledger — a generation-scoped revocation on one CA would sweep
    // the other's certs. Split all six, mirroring the revocations/crl split.
    revocations:       "ca-browser-revocations.json",
    crl:               "ca-browser.crl",
    caCertPrev:        "ca-browser.prev.crt",
    issuance:          "ca-browser-issuance.json",
    revokedGeneration: "ca-browser-revoked-generation",
    algorithm:         "ca-browser.algorithm",
  },
  caKeySealedMode: _resolveCaKeySealedMode(),
  generation:      C.CA_BROWSER_GENERATION,
  // Pin classical: the whole chain (CA + every leaf + its PKCS#12 MAC tier) is
  // ECDSA-P384-SHA384 with RFC 7292 MacData, so the .p12 imports into any
  // browser / OS keystore and the leaf completes a normal TLS client handshake.
  algorithm:       "ECDSA-P384-SHA384",
  vault:           vault,
});
