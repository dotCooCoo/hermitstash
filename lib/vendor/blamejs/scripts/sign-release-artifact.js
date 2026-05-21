#!/usr/bin/env node
"use strict";
/**
 * Workflow-side helper: sign a release artifact (typically the npm
 * tarball) with the framework's ML-DSA-65 release-signing key, then
 * write the signature alongside as `<artifact>.mldsa.sig`.
 *
 * Invoked from `.github/workflows/npm-publish.yml`'s pack step:
 *
 *   node scripts/sign-release-artifact.js dist/blamejs-core-X.Y.Z.tgz
 *
 * Reads the private key from `RELEASE_PQC_SIGNING_KEY` (base64url-
 * encoded). The pubkey lives in `keys/release-pqc-pub.json` (in-tree)
 * and the script cross-checks: after signing, it verifies the
 * signature against the in-tree pubkey before writing the .sig file.
 * If verify fails, the script refuses to write (defends against a
 * stale / wrong env secret silently producing un-verifiable
 * signatures).
 */

var b      = require("..");
var fs     = require("node:fs");
var path   = require("node:path");

function fail(msg) {
  process.stderr.write("[sign-release-artifact] " + msg + "\n");
  process.exit(1);
}

function readPubKey() {
  var pubPath = path.resolve(__dirname, "..", "keys", "release-pqc-pub.json");
  var raw;
  try { raw = fs.readFileSync(pubPath, "utf8"); }
  catch (e) { fail("cannot read " + pubPath + ": " + (e && e.message || e)); }
  var doc;
  try { doc = JSON.parse(raw); }
  catch (e) { fail("malformed " + pubPath + ": " + (e && e.message || e)); }
  if (doc.algorithm !== "ml-dsa-65") {
    fail("unexpected algorithm in pubkey: " + JSON.stringify(doc.algorithm) +
      " (expected ml-dsa-65); re-run scripts/generate-release-signing-key.js to migrate");
  }
  if (typeof doc.publicKey !== "string" || doc.publicKey.length === 0) {
    fail("publicKey missing/empty in " + pubPath);
  }
  return new Uint8Array(Buffer.from(doc.publicKey, "base64url"));
}

function main() {
  var artifactPath = process.argv[2];
  if (!artifactPath) fail("usage: node scripts/sign-release-artifact.js <artifact-path>");

  var secB64 = process.env.RELEASE_PQC_SIGNING_KEY;
  if (!secB64 || secB64.length === 0) {
    fail("RELEASE_PQC_SIGNING_KEY env not set. Run scripts/generate-release-signing-key.js once + set the secret in the npm-publish env.");
  }

  var secretKey = new Uint8Array(Buffer.from(secB64, "base64url"));
  if (secretKey.length !== 4032) {                                                    // allow:raw-byte-literal — FIPS 204 ML-DSA-65 secret-key byte length
    fail("RELEASE_PQC_SIGNING_KEY decodes to " + secretKey.length +
      " bytes; expected 4032 (FIPS 204 ML-DSA-65). Key may be corrupted.");
  }
  var publicKey = readPubKey();
  if (publicKey.length !== 1952) {                                                    // allow:raw-byte-literal — FIPS 204 ML-DSA-65 public-key byte length
    fail("in-tree publicKey decodes to " + publicKey.length +
      " bytes; expected 1952 (FIPS 204 ML-DSA-65). keys/release-pqc-pub.json corrupted.");
  }

  var artifactBytes = new Uint8Array(fs.readFileSync(artifactPath));
  process.stderr.write("[sign-release-artifact] signing " + artifactPath +
    " (" + artifactBytes.length + " bytes) with ml-dsa-65...\n");

  var sigBytes = b.pqcSoftware.ml_dsa_65.sign(artifactBytes, secretKey);

  // Self-verify against the in-tree pubkey before writing — defends
  // against an env secret that doesn't match the published pubkey.
  // If verify fails, refuse to write — the operator-side verification
  // path would also fail, and the workflow's downstream `gh release
  // create` step would attach a signature that no one can verify.
  var ok = b.pqcSoftware.ml_dsa_65.verify(sigBytes, artifactBytes, publicKey);
  if (!ok) {
    fail("self-verify FAILED — RELEASE_PQC_SIGNING_KEY does NOT match keys/release-pqc-pub.json. " +
      "Either the env secret is stale (re-run scripts/generate-release-signing-key.js + update secret) " +
      "or keys/release-pqc-pub.json was committed without the matching secret update. Refusing to write a non-verifiable .sig.");
  }

  var sigPath = artifactPath + ".mldsa.sig";
  fs.writeFileSync(sigPath, Buffer.from(sigBytes));
  process.stderr.write("[sign-release-artifact] OK — wrote " + sigPath +
    " (" + sigBytes.length + " bytes); self-verified against in-tree pubkey\n");
}

main();
