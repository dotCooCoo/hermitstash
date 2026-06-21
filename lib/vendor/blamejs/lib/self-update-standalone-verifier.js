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

// _streamHashAndVerify — read the asset in 64 KiB chunks, feed each
// chunk into sha256, sha3-512, AND the signature verifier in parallel.
// Single pass over the file; no in-memory copy. node:crypto's
// `createVerify` consumes streaming input via `.update()` for ECDSA +
// EdDSA; ML-DSA's `crypto.verify` requires the full payload, so we
// also accumulate to a buffer ONLY when the alg requires it.
function _detectAlg(pubkeyPem) {
  // Inspect the PEM header / SPKI for a recognizable curve / OID. The
  // pubkey PEM carries the algorithm identifier in the SPKI ASN.1; we
  // load it via createPublicKey() and read `asymmetricKeyType` +
  // `asymmetricKeyDetails.namedCurve`.
  var key;
  try {
    key = nodeCrypto.createPublicKey(pubkeyPem);
  } catch (e) {
    throw new Error("standalone-verifier: pubkey PEM did not parse: " +
                    (e && e.message ? e.message : String(e)));
  }
  var t = key.asymmetricKeyType;
  if (t === "ec") {
    var curve = key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve;
    if (curve === "P-384" || curve === "secp384r1") return { alg: "ecdsa-p384", key: key };
    throw new Error("standalone-verifier: unsupported EC curve '" + curve + "' (need P-384)");
  }
  if (t === "ed25519") return { alg: "ed25519", key: key };
  if (t === "ml-dsa-87" || t === "ml-dsa") return { alg: "ml-dsa-87", key: key };
  throw new Error("standalone-verifier: unrecognized pubkey type '" + t + "' " +
                  "(need ecdsa-p384, ed25519, or ml-dsa-87)");
}

/**
 * @primitive b.selfUpdate.standaloneVerifier.verify
 * @signature b.selfUpdate.standaloneVerifier.verify(assetPath, signaturePath, pubkeyPem)
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
 * no buffer because createVerify is incremental).
 *
 * Returns `{ ok, sha3_512, sha256, alg }` on success; throws on
 * unrecognized pubkey shape, missing files, or signature mismatch.
 * `alg` is one of `"ecdsa-p384"`, `"ed25519"`, `"ml-dsa-87"` (auto-
 * detected from the pubkey PEM).
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
function verify(assetPath, signaturePath, pubkeyPem) {
  if (typeof assetPath !== "string" || assetPath.length === 0) {
    throw new Error("standalone-verifier.verify: assetPath must be a non-empty string");
  }
  if (typeof signaturePath !== "string" || signaturePath.length === 0) {
    throw new Error("standalone-verifier.verify: signaturePath must be a non-empty string");
  }
  if (typeof pubkeyPem !== "string" || pubkeyPem.indexOf("-----BEGIN ") !== 0) {
    throw new Error("standalone-verifier.verify: pubkeyPem must be a PEM-encoded public key string");
  }

  // Open both files BEFORE parsing the pubkey so we own stable fds
  // against TOCTOU races (CodeQL js/file-system-race) — checking
  // existsSync before readFileSync leaves a swap window. Asset opens
  // first so a missing-asset path surfaces before a missing-sig path.
  var assetFd;
  try {
    assetFd = nodeFs.openSync(assetPath, "r");
  } catch (e) {
    throw new Error("standalone-verifier.verify: asset not found at " + assetPath +
                    " — " + (e && e.message ? e.message : String(e)));
  }
  var sigFd;
  try {
    sigFd = nodeFs.openSync(signaturePath, "r");
  } catch (e) {
    nodeFs.closeSync(assetFd);
    throw new Error("standalone-verifier.verify: signature not found at " + signaturePath +
                    " — " + (e && e.message ? e.message : String(e)));
  }
  var signature;
  try {
    var sigStat = nodeFs.fstatSync(sigFd);
    // Bound the alloc: the largest supported signature (ML-DSA-87) is ~4.6 KB;
    // 64 KiB is far above any legitimate sig and stops Buffer.allocUnsafe(stat.size)
    // from OOM-ing if signaturePath is pointed at a giant file. Zero-dep by
    // contract — inline literal, cannot import C.BYTES.
    if (sigStat.size > 64 * 1024) {   // allow:raw-byte-literal — zero-dep module
      throw new Error("standalone-verifier.verify: signature file implausibly large (" +
                      sigStat.size + " bytes)");
    }
    signature = Buffer.allocUnsafe(sigStat.size);
    if (sigStat.size > 0) nodeFs.readSync(sigFd, signature, 0, sigStat.size, 0);
  } finally {
    nodeFs.closeSync(sigFd);
  }
  if (signature.length === 0) {
    nodeFs.closeSync(assetFd);
    throw new Error("standalone-verifier.verify: signature file is empty");
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

  // Stream the asset through both hashers. For ECDSA we stream through
  // createVerify (incremental). For Ed25519 / ML-DSA we pre-allocate
  // ONE buffer of stat.size and stream-fill it at increasing offsets —
  // single allocation peak, not the 2× peak that Buffer.concat([...chunks])
  // produces. 64 KiB chunks match the framework's hash-while-streaming
  // convention elsewhere.
  //
  // Hardening (v0.9.58): fstat the asset BEFORE the read loop
  // for every alg path, clamp every readSync to (assetStat.size -
  // fullOff), and reject if the final fullOff diverges from
  // assetStat.size. A grow-during-read race (writer appends as we
  // hash) previously fed extra bytes to the hashers but not to the
  // pre-sized fullBuf — the returned sha3_512 then didn't match what
  // signature-verify or the operator's later byte-set compare saw.
  // The clamp + final-equality refusal forces every hash + verify byte
  // to come from the same {0..assetStat.size} range fixed at open
  // time.
  var assetStat = nodeFs.fstatSync(assetFd);
  // Bound the asset alloc before Buffer.allocUnsafe(assetStat.size): a self-update
  // bundle (SEA) is intentionally large, so the ceiling is generous (2 GiB), but
  // it stops a signaturePath/assetPath pointed at an unbounded file from OOM-ing
  // the verifier before any byte is hashed. Zero-dep by contract — inline literal.
  if (assetStat.size > 2 * 1024 * 1024 * 1024) {   // allow:raw-byte-literal — zero-dep module, 2 GiB asset ceiling
    throw new Error("standalone-verifier.verify: asset implausibly large (" +
                    assetStat.size + " bytes) — exceeds the 2 GiB self-update ceiling");
  }
  var sha256 = nodeCrypto.createHash("sha256");
  var sha3   = nodeCrypto.createHash("sha3-512");
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
      // Clamp the read to the remaining bytes the verifier and hashers
      // are allowed to see. Without this, a concurrent appender grows
      // the file under us and the readSync returns more bytes than the
      // fullBuf was sized for.
      var capped = chunk.length;                                                                     // buffer length is the read upper bound
      if (remaining < capped) capped = remaining;
      var n = nodeFs.readSync(assetFd, chunk, 0, capped, null);
      if (n === 0) break;
      var slice = chunk.subarray(0, n);
      sha256.update(slice);
      sha3.update(slice);
      if (verifier) verifier.update(slice);
      if (fullBuf) {
        slice.copy(fullBuf, fullOff);
      }
      fullOff += n;
    }
  } finally {
    nodeFs.closeSync(assetFd);
  }
  // Final byte-count gate. If fullOff != assetStat.size, the file was
  // truncated under us (read fewer bytes than stat said) or grew
  // beyond what the clamp let through. Both cases mean the hashers
  // and verifier saw a different byte set than the on-disk file.
  if (fullOff !== assetStat.size) {
    throw new Error("standalone-verifier.verify: asset '" + assetPath +
                    "' changed size during read (expected " + assetStat.size +
                    " bytes per fstat, read " + fullOff +
                    " bytes) — refusing to return a hash that may not match the on-disk file");
  }

  var sha256Hex = sha256.digest("hex");
  var sha3Hex   = sha3.digest("hex");

  var ok = false;
  if (alg === "ecdsa-p384") {
    // P-384 IEEE-P1363 sigs are exactly 96 bytes (48-byte r || 48-byte s).
    // P-384 DER sigs are variable (~100-104 bytes — ASN.1 SEQUENCE
    // wrapping two INTEGERs). Detect by length so we only call
    // verifier.verify ONCE — calling it a second time after a failed
    // verify returns stale state and silently passes tampered assets.
    // 96 = P-384 IEEE-P1363 signature length; protocol constant, not a byte-size.
    var dsaEncoding = signature.length === 96 ? "ieee-p1363" : "der";   // IEEE-P1363 P-384 signature length
    ok = verifier.verify({ key: key, dsaEncoding: dsaEncoding }, signature);
  } else if (alg === "ed25519") {
    // fullBuf may be shorter than allocated (sparse files / size-races);
    // slice to fullOff so verify sees only the bytes we actually read.
    ok = nodeCrypto.verify(null, fullBuf.subarray(0, fullOff), key, signature);
  } else if (alg === "ml-dsa-87") {
    ok = nodeCrypto.verify(null, fullBuf.subarray(0, fullOff), key, signature);
  }

  if (!ok) {
    throw new Error("standalone-verifier.verify: " + alg + " signature INVALID for " +
                    assetPath + " (sha3-512=" + sha3Hex.slice(0, 16) + "...). " +   // 16-char hex prefix for forensic display, not bytes
                    "Either the asset was tampered with after signing, the signature " +
                    "doesn't match this asset, or the pubkey doesn't match the signing key.");
  }

  return {
    ok:       true,
    sha3_512: sha3Hex,
    sha256:   sha256Hex,
    alg:      alg,
  };
}

module.exports = {
  verify: verify,
  // Absolute path to this module file. Operators copy it via:
  //   cp "$(node -p "require('@blamejs/core').selfUpdate.standaloneVerifier.path")" \
  //      install/standalone-verifier.js
  path:   __filename,
};
