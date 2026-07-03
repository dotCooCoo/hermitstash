#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Workflow-side helper: compute classical (SHA-256) AND PQC-first
 * (SHA3-512) digests of a release artifact (typically the npm
 * tarball) and write each to a sidecar file in `sha256sum` /
 * `sha3sum -a 512` compatible format:
 *
 *   <artifact>.sha256     — `<hex>  <filename>` (one line)
 *   <artifact>.sha3-512   — `<hex>  <filename>` (one line)
 *
 * SHA-256 is the conventional release-checksum operators expect to
 * find on a release page; verify via:
 *
 *   sha256sum -c @blamejs-core-X.Y.Z.tgz.sha256
 *
 * SHA3-512 is the framework's PQC-first hash choice — same
 * algorithm the audit chain, CMS SignedData encoder, and vault-
 * wrap envelope hash with. Operators with a strict PQC-only
 * verification posture use this sidecar to verify the tarball
 * BYTES at ~256-bit pre-Grover / ~128-bit post-Grover collision
 * security — twice the post-quantum margin of SHA-256. Verify via:
 *
 *   openssl dgst -sha3-512 @blamejs-core-X.Y.Z.tgz
 *   (compare against the .sha3-512 sidecar)
 *
 * Invoked from `.github/workflows/npm-publish.yml`'s pack step:
 *
 *   node scripts/sha3-digest.js dist/blamejs-core-X.Y.Z.tgz
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
  // Emit BOTH sidecars in one pass so the workflow only has to
  // invoke one script per artifact.
  _writeDigest(artifactPath, "sha256",   "sha256");
  _writeDigest(artifactPath, "sha3-512", "sha3-512");
}

main();
