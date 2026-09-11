// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.selfUpdate.standaloneVerifier
 * @nav        Production
 * @title      Self-Update Standalone Verifier
 * @order      640
 *
 * @intro
 *   Zero-dep companion to `b.selfUpdate.verify` for install-pipeline
 *   contexts that run BEFORE the framework itself is installed —
 *   Dockerfile build stages, `install.sh`, `update.sh`, SEA-bundle
 *   verification at deploy time. The full `b.selfUpdate.verify`
 *   chain reaches into `b.crypto`, `b.httpClient`, `b.audit`, vendor
 *   imports, etc.; none of those exist yet when an operator's
 *   install script runs `node verify-release.js` against the
 *   downloaded artifact.
 *
 *   This module is intentionally hermetic — `node:crypto` + `node:fs`
 *   only, no framework imports, no third-party modules. Operators
 *   physically copy the file into their install pipeline alongside a
 *   public-key module they own. Both go into version control on the
 *   operator's side; neither updates without their explicit action.
 *
 *   Surface (single function):
 *
 *     verify(assetPath, signaturePath, pubkeyPem, opts?) → {
 *       ok:         boolean,
 *       sha3_512:   string,   // hex digest of asset bytes (SBOM correlation)
 *       sha256:     string,   // hex digest of asset bytes (defense-in-depth)
 *       alg:        string,   // detected algorithm: "ecdsa-p384" | "ed25519" | "ml-dsa-87"
 *     }
 *
 *   The function refuses to load the asset into memory in one go;
 *   it streams the bytes through both hashers + the signature
 *   verifier so multi-GB SEA bundles don't OOM the install runner.
 *
 *   Throws on:
 *     - missing asset / signature / pubkey file
 *     - unrecognized pubkey PEM shape
 *     - signature length mismatch with the algorithm
 *     - cryptographic verify failure
 *
 *   Per the operator's request that surfaced this primitive
 *   (hermitstash-sync 2026-05-13): the install pipeline needs P-384
 *   ECDSA + SHA3-512 as the baseline cross-check. ML-DSA-87 is also
 *   supported when the operator's pubkey carries the corresponding
 *   OID (Node 22+ via the FIPS 204 OIDs in node:crypto).
 *
 *   ## How operators consume this
 *
 *   ```sh
 *   # one-time copy at framework-install time:
 *   cp "$(node -p "require('@blamejs/core').selfUpdate.standaloneVerifier.path")" \
 *      install/standalone-verifier.js
 *   ```
 *
 *   ```js
 *   // install/verify-release.js (operator-owned, in their repo):
 *   var verifier = require("./standalone-verifier");
 *   var pubkey = require("./release-pubkey");  // operator-owned PEM
 *
 *   var result = verifier.verify(
 *     "/tmp/blamejs-sea-bundle",
 *     "/tmp/blamejs-sea-bundle.sig",
 *     pubkey,
 *   );
 *   if (!result.ok) {
 *     process.stderr.write("release verification FAILED\n");
 *     process.exit(1);
 *   }
 *   process.stdout.write("verified " + result.alg + " sha3-512=" + result.sha3_512 + "\n");
 *   ```
 *
 *   The module is also reachable as `b.selfUpdate.standaloneVerifier.verify`
 *   from inside a fully-installed framework process — useful for tests
 *   that exercise the same code path the operator's install pipeline
 *   does, without forking a subprocess.
 *
 * @card
 *   Zero-dep verifier for use BEFORE the framework is installed.
 *   Install-pipeline scripts copy this file alongside an operator-owned
 *   pubkey to verify signed release artifacts during Dockerfile build
 *   or systemd `install.sh`. node:crypto + node:fs only.
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");

function _svErr(kind, message) {
  var e = new Error(message);
  e.kind = kind;
  return e;
}

function _detectAlg(pubkeyPem) {
  var key;
  try {
    key = nodeCrypto.createPublicKey(pubkeyPem);
  } catch (e) {
    throw _svErr("bad-pubkey", "standalone-verifier: pubkey PEM did not parse: " +
                    (e && e.message ? e.message : String(e)));
  }
  var t = key.asymmetricKeyType;
  if (t === "ec") {
    var curve = key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve;
    if (curve === "P-384" || curve === "secp384r1") return { alg: "ecdsa-p384", key: key };
    throw _svErr("unsupported-key", "standalone-verifier: unsupported EC curve '" + curve + "' (need P-384)");
  }
  if (t === "ed25519") return { alg: "ed25519", key: key };
  if (t === "ml-dsa-87" || t === "ml-dsa") return { alg: "ml-dsa-87", key: key };
  throw _svErr("unsupported-key", "standalone-verifier: unrecognized pubkey type '" + t + "' " +
                  "(need ecdsa-p384, ed25519, or ml-dsa-87)");
}

function _readDerLen(buf, off) {
  if (off >= buf.length) return null;
  var first = buf[off];
  if (first < 0x80) return { len: first, next: off + 1 };
  var numBytes = first & 0x7f;
  if (numBytes === 0 || numBytes > 4) return null;
  if (off + 1 + numBytes > buf.length) return null;
  var len = 0;
  for (var i = 0; i < numBytes; i++) len = (len * 256) + buf[off + 1 + i];
  return { len: len, next: off + 1 + numBytes };
}
function _readDerInteger(buf, off) {
  if (off >= buf.length || buf[off] !== 0x02) return null;
  var l = _readDerLen(buf, off + 1);
  if (l === null || l.len === 0) return null;
  var end = l.next + l.len;
  if (end > buf.length) return null;
  return { next: end };
}
function _looksLikeDerEcdsa(sig) {
  if (sig.length < 8 || sig[0] !== 0x30) return false;
  var seq = _readDerLen(sig, 1);
  if (seq === null) return false;
  if (seq.next + seq.len !== sig.length) return false;
  var r = _readDerInteger(sig, seq.next);
  if (r === null) return false;
  var s = _readDerInteger(sig, r.next);
  if (s === null) return false;
  return s.next === sig.length;
}

/**
 * @primitive b.selfUpdate.standaloneVerifier.verify
 * @signature b.selfUpdate.standaloneVerifier.verify(assetPath, signaturePath, pubkeyPem, opts?)
 * @since     0.9.13
 * @status    stable
 * @related   b.selfUpdate.verify
 *
 * Verify a signed release asset using only `node:crypto` + `node:fs`
 * (no framework imports). For install-pipeline contexts where the
 * framework itself is not yet installed.
 *
 * Streams the asset in 64 KiB chunks through SHA-256 + SHA-3-512 + the
 * signature verifier in parallel — single allocation peak (one buffer
 * sized to fstat(asset).size for Ed25519 / ML-DSA-87, ECDSA P-384 needs
 * no buffer because createVerify is incremental). The signature commits
 * to a SHA3-512 digest and the ECDSA encoding is dispatched by structure
 * (DER SEQUENCE vs raw IEEE-P1363), so both encodings of a SHA3-512-signed
 * P-384 sidecar verify.
 *
 * Returns `{ ok, sha3_512, sha256, alg, bytes, digests }` on success;
 * throws on unrecognized pubkey shape, missing files, or signature
 * mismatch. `alg` is one of `"ecdsa-p384"`, `"ed25519"`, `"ml-dsa-87"`
 * (auto-detected from the pubkey PEM). `bytes` is the verified asset byte
 * count; `digests` maps each requested `opts.extraDigests` name to its
 * hex digest (computed in the same single pass).
 *
 * @opts
 *   maxAssetBytes: number,   // asset-size ceiling (default 2 GiB); refuse a larger asset before hashing
 *   extraDigests:  array,    // additional node:crypto digest names to compute in the same stream
 *
 * @example
 *   var verifier = require("./standalone-verifier");
 *   var pubkey   = require("./release-pubkey");
 *   var result   = verifier.verify(
 *     "/tmp/blamejs-sea-bundle",
 *     "/tmp/blamejs-sea-bundle.sig",
 *     pubkey,
 *   );
 *   if (!result.ok) process.exit(1);
 *   process.stdout.write("verified " + result.alg + " sha3-512=" + result.sha3_512 + "\n");
 */
function verify(assetPath, signaturePath, pubkeyPem, opts) {
  opts = opts || {};
  var maxAssetBytes = (typeof opts.maxAssetBytes === "number" && isFinite(opts.maxAssetBytes) &&
                       opts.maxAssetBytes > 0)
    ? opts.maxAssetBytes
    : (2 * 1024 * 1024 * 1024);   // allow:raw-byte-literal — zero-dep module, 2 GiB asset ceiling
  var extraDigests = Array.isArray(opts.extraDigests) ? opts.extraDigests : [];

  if (typeof assetPath !== "string" || assetPath.length === 0) {
    throw _svErr("bad-input", "standalone-verifier.verify: assetPath must be a non-empty string");
  }
  if (typeof signaturePath !== "string" || signaturePath.length === 0) {
    throw _svErr("bad-input", "standalone-verifier.verify: signaturePath must be a non-empty string");
  }
  if (typeof pubkeyPem !== "string" || pubkeyPem.indexOf("-----BEGIN ") !== 0) {
    throw _svErr("bad-input", "standalone-verifier.verify: pubkeyPem must be a PEM-encoded public key string");
  }

  var assetFd;
  try {
    assetFd = nodeFs.openSync(assetPath, "r");
  } catch (e) {
    throw _svErr("asset-not-found", "standalone-verifier.verify: asset not found at " + assetPath +
                    " — " + (e && e.message ? e.message : String(e)));
  }
  var sigFd;
  try {
    sigFd = nodeFs.openSync(signaturePath, "r");
  } catch (e) {
    nodeFs.closeSync(assetFd);
    throw _svErr("sig-not-found", "standalone-verifier.verify: signature not found at " + signaturePath +
                    " — " + (e && e.message ? e.message : String(e)));
  }
  var signature;
  try {
    var sigStat = nodeFs.fstatSync(sigFd);
    if (sigStat.size > 64 * 1024) {   // allow:raw-byte-literal — zero-dep module
      throw _svErr("sig-too-large", "standalone-verifier.verify: signature file implausibly large (" +
                      sigStat.size + " bytes)");
    }
    signature = Buffer.allocUnsafe(sigStat.size);
    if (sigStat.size > 0) nodeFs.readSync(sigFd, signature, 0, sigStat.size, 0);
  } finally {
    nodeFs.closeSync(sigFd);
  }
  if (signature.length === 0) {
    nodeFs.closeSync(assetFd);
    throw _svErr("sig-empty", "standalone-verifier.verify: signature file is empty");
  }

  var detected;
  try {
    detected = _detectAlg(pubkeyPem);
  } catch (e) {
    nodeFs.closeSync(assetFd);
    throw e;
  }
  var alg = detected.alg;
  var key = detected.key;

  var assetStat = nodeFs.fstatSync(assetFd);
  if (assetStat.size > maxAssetBytes) {
    nodeFs.closeSync(assetFd);
    throw _svErr("asset-too-large", "standalone-verifier.verify: asset implausibly large (" +
                    assetStat.size + " bytes) — exceeds the " + maxAssetBytes + "-byte asset ceiling");
  }
  var sha256 = nodeCrypto.createHash("sha256");
  var sha3   = nodeCrypto.createHash("sha3-512");
  var extraHashers = [];
  for (var xd = 0; xd < extraDigests.length; xd += 1) {
    extraHashers.push({ name: extraDigests[xd], hash: nodeCrypto.createHash(extraDigests[xd]) });
  }
  var verifier = (alg === "ecdsa-p384") ? nodeCrypto.createVerify("sha3-512") : null;
  var fullBuf  = null;
  var fullOff  = 0;
  if (verifier === null) {
    fullBuf = Buffer.allocUnsafe(assetStat.size);
  }

  try {
    var chunk = Buffer.allocUnsafe(64 * 1024);   // allow:raw-byte-literal — module is zero-dep by contract; cannot import C.BYTES
    while (true) {
      var remaining = assetStat.size - fullOff;
      if (remaining <= 0) break;
      var capped = chunk.length;
      if (remaining < capped) capped = remaining;
      var n = nodeFs.readSync(assetFd, chunk, 0, capped, null);
      if (n === 0) break;
      var slice = chunk.subarray(0, n);
      sha256.update(slice);
      sha3.update(slice);
      for (var xh = 0; xh < extraHashers.length; xh += 1) extraHashers[xh].hash.update(slice);
      if (verifier) verifier.update(slice);
      if (fullBuf) {
        slice.copy(fullBuf, fullOff);
      }
      fullOff += n;
    }
  } finally {
    nodeFs.closeSync(assetFd);
  }
  if (fullOff !== assetStat.size) {
    throw _svErr("size-race", "standalone-verifier.verify: asset '" + assetPath +
                    "' changed size during read (expected " + assetStat.size +
                    " bytes per fstat, read " + fullOff +
                    " bytes) — refusing to return a hash that may not match the on-disk file");
  }

  var sha256Hex = sha256.digest("hex");
  var sha3Hex   = sha3.digest("hex");
  var digests   = {};
  for (var dh = 0; dh < extraHashers.length; dh += 1) {
    digests[extraHashers[dh].name] = extraHashers[dh].hash.digest("hex");
  }

  var ok = false;
  if (alg === "ecdsa-p384") {
    var coordLen = 48;
    var dsaEncoding;
    if (_looksLikeDerEcdsa(signature)) {
      dsaEncoding = "der";
    } else if (signature.length === coordLen * 2) {
      dsaEncoding = "ieee-p1363";
    } else {
      throw _svErr("bad-sig-encoding", "standalone-verifier.verify: ecdsa-p384 signature is neither a " +
                      "well-formed DER SEQUENCE nor a raw " + (coordLen * 2) +
                      "-byte IEEE-P1363 pair (length " + signature.length +
                      ") — refusing to guess the encoding");
    }
    ok = verifier.verify({ key: key, dsaEncoding: dsaEncoding }, signature);
  } else if (alg === "ed25519") {
    ok = nodeCrypto.verify(null, fullBuf.subarray(0, fullOff), key, signature);
  } else if (alg === "ml-dsa-87") {
    ok = nodeCrypto.verify(null, fullBuf.subarray(0, fullOff), key, signature);
  }

  if (!ok) {
    throw _svErr("verify-failed", "standalone-verifier.verify: " + alg + " signature INVALID for " +
                    assetPath + " (sha3-512=" + sha3Hex.slice(0, 16) + "...). " +
                    "Either the asset was tampered with after signing, the signature " +
                    "doesn't match this asset, or the pubkey doesn't match the signing key.");
  }

  return {
    ok:       true,
    sha3_512: sha3Hex,
    sha256:   sha256Hex,
    alg:      alg,
    bytes:    fullOff,
    digests:  digests,
  };
}

module.exports = {
  verify: verify,
  path:   __filename,
};
