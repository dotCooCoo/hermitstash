#!/usr/bin/env node
"use strict";
/**
 * One-time setup: generate the ML-DSA-65 release-signing keypair
 * the docker-publish workflow uses to sign every release artifact.
 *
 * Run this ONCE locally before the first PQC-signed release. The
 * script:
 *   - Writes the PUBLIC key to `keys/release-pqc-pub.json` (commit
 *     this file — operators verify against the in-tree pubkey).
 *   - Prints the PRIVATE key (base64url) to stdout. Store as the
 *     `RELEASE_PQC_SIGNING_KEY` secret in the public repo's `release`
 *     GitHub Actions environment.
 *   - Prints the public-key fingerprint (SHA3-512 of the raw
 *     public-key bytes). Add to SECURITY.md so operators can verify
 *     the in-tree pubkey out of band against the signed commit.
 *
 * Re-running this script ROTATES the key. To rotate:
 *   1. Run this script (overwrites keys/release-pqc-pub.json).
 *   2. Update `RELEASE_PQC_SIGNING_KEY` env secret in the release env.
 *   3. Update SECURITY.md with the new fingerprint.
 *   4. Commit + ship a release.
 *   Previously-signed releases remain verifiable against the OLD
 *   public key — operators can `git log keys/release-pqc-pub.json`
 *   to walk the history.
 *
 * Algorithm: ML-DSA-65 (FIPS 204 / RFC 9909) — NIST PQC security
 * level 3 (~192-bit classical, ~96-bit post-quantum). Matches the
 * framework's audit-chain signer choice and the project's PQC stack.
 */

var b      = require("../lib/vendor/blamejs");
var fs     = require("node:fs");
var path   = require("node:path");
var crypto = require("node:crypto");

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function sha3_512_hex(buf) {
  return crypto.createHash("sha3-512").update(buf).digest("hex");
}

function main() {
  var pair = b.pqcSoftware.ml_dsa_65.keygen();
  var pubBytes = Buffer.from(pair.publicKey);
  var secBytes = Buffer.from(pair.secretKey);
  var fingerprint = sha3_512_hex(pubBytes);
  var pubJson = {
    algorithm:             "ml-dsa-65",
    publicKey:             b64url(pubBytes),
    fingerprint_sha3_512:  fingerprint,
    createdAt:             new Date().toISOString().slice(0, 10),
    rotation_note:         "Re-running scripts/generate-release-signing-key.js rotates the key. Update RELEASE_PQC_SIGNING_KEY secret + SECURITY.md fingerprint in the same commit.",
  };

  var pubPath = path.resolve(__dirname, "..", "keys", "release-pqc-pub.json");
  fs.mkdirSync(path.dirname(pubPath), { recursive: true });
  fs.writeFileSync(pubPath, JSON.stringify(pubJson, null, 2) + "\n");

  process.stderr.write("\n=== ML-DSA-65 release-signing keypair ===\n\n");
  process.stderr.write("Public key written to: " + pubPath + "\n");
  process.stderr.write("Fingerprint (SHA3-512): " + fingerprint + "\n\n");
  process.stderr.write("Private key (base64url, paste into RELEASE_PQC_SIGNING_KEY secret):\n");
  process.stderr.write("------------------------\n");
  process.stdout.write(b64url(secBytes) + "\n");
  process.stderr.write("------------------------\n\n");
  process.stderr.write("Next steps:\n");
  process.stderr.write("  1. Verify the public-key write:\n");
  process.stderr.write("       cat " + pubPath + "\n");
  process.stderr.write("  2. Set the secret in the public repo's release environment:\n");
  process.stderr.write("       gh secret set RELEASE_PQC_SIGNING_KEY --env release \\\n");
  process.stderr.write("         --repo dotCooCoo/hermitstash --body \"<paste from above>\"\n");
  process.stderr.write("  3. Update SECURITY.md with the fingerprint above.\n");
  process.stderr.write("  4. Commit keys/release-pqc-pub.json + SECURITY.md, ship a release.\n");
}

main();
