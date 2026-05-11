// codebase-patterns:allow-file raw-process-env — bootstrap reads of CA_KEY_SEALED / MTLS_CA_KEY / MTLS_CA_CERT before b.mtlsCa.create takes over
/**
 * Process-wide singleton for HermitStash's mTLS CA.
 *
 * Wraps `b.mtlsCa.create` with HS bootstrap: the data-dir paths,
 * `lib/vault` for sealed-key encryption, the cert-stack generation
 * (`C.CA_GENERATION`), and an `auto` resolution for the
 * `CA_KEY_SEALED` env var (blamejs only accepts `required` / `disabled`,
 * so `auto` falls back to whichever mode matches the on-disk file).
 *
 * Every caller does `var mtlsCa = require("./mtls-ca")` and calls the
 * b.mtlsCa instance methods directly — `exists`, `status`, `initCA`,
 * `generateClientCert({ cn, validityDays })`, `generateClientP12`,
 * `commit`, `revoke`, etc. Routes that need to sign against a freshly-
 * generated, not-yet-committed CA bypass the singleton and use
 * `b.mtlsEngine.{generateCa, signClientCert}` directly.
 *
 * Singleton because multiple `b.mtlsCa.create` instances would each
 * cache state separately while racing on the same on-disk CA files.
 */
"use strict";

var fs = require("fs");
var b = require("./vendor/blamejs");
var C = require("./constants");
var vault = require("./vault");

function _resolveCaKeySealedMode() {
  var env = (process.env.CA_KEY_SEALED || "auto").toLowerCase();
  if (env === "required" || env === "disabled") return env;
  return fs.existsSync(C.PATHS.CA_KEY_SEALED) ? "required" : "disabled";
}

// Filenames default to ca.key / ca.key.sealed / ca.crt under dataDir.
// Operators may point the CA private key + cert at absolute paths
// outside dataDir via MTLS_CA_KEY / MTLS_CA_CERT — used by E2E tests
// that pre-generate CAs in a separate fixture directory and by
// deployments that mount certs from a read-only secrets volume.
// Requires blamejs ≥ 0.8.59 (absolute paths in opts.paths pass through
// unchanged; relative paths are joined under dataDir).
var caKeyOverride  = process.env.MTLS_CA_KEY  || null;
var caCertOverride = process.env.MTLS_CA_CERT || null;
module.exports = b.mtlsCa.create({
  dataDir:          C.DATA_DIR,
  paths: {
    caKey:        caKeyOverride  || "ca.key",
    caKeySealed:  (caKeyOverride || "ca.key") + ".sealed",
    caCert:       caCertOverride || "ca.crt",
  },
  caKeySealedMode: _resolveCaKeySealedMode(),
  generation:      C.CA_GENERATION,
  vault:           vault,
});
