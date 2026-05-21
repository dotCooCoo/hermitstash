#!/usr/bin/env node
"use strict";
/**
 * Compute SHA-256 + SHA3-512 digests of a release artifact (the
 * docker-save tarball of the published image) and write each to a
 * sidecar file in `sha256sum` / `sha3sum -a 512` compatible format:
 *
 *   <artifact>.sha256     — `<hex>  <filename>` (one line)
 *   <artifact>.sha3-512   — `<hex>  <filename>` (one line)
 *
 * SHA-256 is the conventional release-checksum operators expect on a
 * release page; verify via:
 *   sha256sum -c hermitstash-vX.Y.Z.image.tar.sha256
 *
 * SHA3-512 is the framework's PQC-first hash choice — same algorithm
 * the audit chain, CMS SignedData encoder, and vault-wrap envelope
 * hash with. Operators with a strict PQC-only verification posture
 * use this sidecar to verify the artifact bytes at ~256-bit
 * pre-Grover / ~128-bit post-Grover collision security. Verify via:
 *   openssl dgst -sha3-512 hermitstash-vX.Y.Z.image.tar
 *
 * Invoked from `.github/workflows/docker-publish.yml` after the image
 * is saved to a tarball:
 *   node scripts/sha3-digest.js artifacts/hermitstash-vX.Y.Z.image.tar
 */

var fs     = require("node:fs");
var path   = require("node:path");
var crypto = require("node:crypto");

function fail(msg) {
  process.stderr.write("[release-digests] " + msg + "\n");
  process.exit(1);
}

function _writeDigest(artifactPath, algorithm, sidecarExt) {
  var bytes;
  try { bytes = fs.readFileSync(artifactPath); }
  catch (e) { fail("cannot read " + artifactPath + ": " + (e && e.message || e)); }
  var digest = crypto.createHash(algorithm).update(bytes).digest("hex");
  var base = path.basename(artifactPath);
  var sidecarPath = artifactPath + "." + sidecarExt;
  fs.writeFileSync(sidecarPath, digest + "  " + base + "\n");
  process.stderr.write("[release-digests] OK — wrote " + sidecarPath + "\n");
  process.stderr.write("[release-digests] " + algorithm + ":  " + digest + "  " + base + "\n");
}

function main() {
  var artifactPath = process.argv[2];
  if (!artifactPath) fail("usage: node scripts/sha3-digest.js <artifact-path>");
  _writeDigest(artifactPath, "sha256",   "sha256");
  _writeDigest(artifactPath, "sha3-512", "sha3-512");
}

main();
