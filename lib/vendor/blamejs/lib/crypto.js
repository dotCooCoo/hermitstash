// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.crypto
 * @featured true
 * @nav    Crypto
 * @title  Crypto
 *
 * @intro
 *   The framework's PQC-first cryptography surface. Every default is
 *   post-quantum-aware: ML-KEM-1024 + ECDH P-384 hybrid for key
 *   encapsulation (FIPS 203 + classical defense-in-depth), XChaCha20-
 *   Poly1305 for authenticated symmetric encryption (24-byte nonce —
 *   no nonce-reuse risk under high volume), SHAKE256 as the KDF
 *   (FIPS 202 XOF — arbitrary output length), SHA3-512 for hashing,
 *   HMAC-SHA3-512 for keyed integrity, and ML-DSA-87 / SLH-DSA-SHAKE-
 *   256f for signatures (auto-detected from the key PEM). Argon2id
 *   passphrase stretching lives in `b.vaultWrap`, not here.
 *
 *   Envelope wire format (length-prefixed, self-describing):
 *
 *     byte 0 : ENVELOPE_MAGIC
 *     byte 1 : KEM ID         (ML_KEM_1024 / ML_KEM_1024_P384 / ML_KEM_768_X25519)
 *     byte 2 : CIPHER ID      (XCHACHA20_POLY1305)
 *     byte 3 : KDF ID         (SHAKE256)
 *     ...    : KEM ciphertext, ephemeral ECDH pubkey, nonce, AEAD ciphertext
 *
 *   The four-byte header is bound as AEAD AAD so an algorithm-
 *   substitution attack (a tampered byte-1 KEM ID, byte-2 cipher ID,
 *   etc.) fails Poly1305 verification. Old envelopes decrypt under the
 *   IDs written into their header; new writes use the active suite.
 *   The KDF additionally absorbs a NIST SP 800-56C r2 §4.1 FixedInfo
 *   suite-binding label so a key derived under one suite is not
 *   silently usable under another.
 *
 *   Three KEM hybrids ship: ML-KEM-1024 KEM-only (legacy single-
 *   component), ML-KEM-1024 + ECDH P-384 (framework default), and
 *   ML-KEM-768 + X25519 (IETF / Cloudflare / Chrome TLS 1.3 codepoint
 *   0x11EC — smaller payload, wider browser interop).
 *
 *   SHA-1 / SHA-256 / AES-GCM / classical-only ECDH are intentionally
 *   absent from the public surface. Operators who genuinely need them
 *   call `node:crypto` directly so the choice surfaces in their code.
 *
 * @card
 *   The framework's PQC-first cryptography surface.
 */
var nodeCrypto = require("node:crypto");
var nodeFs = require("node:fs");
var nodeTypes = require("node:util").types;
var { pipeline } = require("node:stream/promises");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var asn1 = require("./asn1-der");
var { CryptoKeyError } = require("./framework-error");
// Circular: audit imports b.crypto for sha3Hash + envelope sign. Lazy-
// load the audit module so the legacy-envelope decrypt path can emit
// `system.crypto.decrypt.allow_legacy` events without an inline
// require() inside setImmediate. (The framework's convention is
// top-of-file require() except where a documented circular-load
// reason forces lazy-load; this is one of those reasons.)
var lazyRequire = require("./lazy-require");
var audit       = lazyRequire(function () { return require("./audit"); });
// safe-buffer hosts the canonical hasCrlf(s) helper used by every
// log-injection / CRLF-smuggling refusal in the framework. Lazy-
// loaded because safe-buffer.js itself imports b.crypto for
// hex-compare helpers (circular).
var safeAsync   = lazyRequire(function () { return require("./safe-async"); });
var safeBuffer  = lazyRequire(function () { return require("./safe-buffer"); });
// pqc-software requires this module (b.crypto) — lazy-load to break the
// cycle. Only the power-on self-test needs it here.
var pqcSoftware = lazyRequire(function () { return require("./pqc-software"); });
// network-tls requires this module (b.crypto) at top-of-file — lazy-load
// to break the cycle. Only spkiPinVerifier composes its RFC 9525 strict
// hostname/SAN matcher.
var networkTls  = lazyRequire(function () { return require("./network-tls"); });
// The vendored PKI toolkit (3.5 MB) is loaded on the first compromised-key
// check rather than with b.crypto.
var pki         = lazyRequire(function () { return require("./vendor/blamejs-pki.cjs"); });

var STREAM_HASH_ALGORITHMS = Object.freeze({
  "sha3-256":   { algorithm: "sha3-256",   needsOutputLength: false },
  "sha3-384":   { algorithm: "sha3-384",   needsOutputLength: false },
  "sha3-512":   { algorithm: "sha3-512",   needsOutputLength: false },
  "sha512":     { algorithm: "sha512",     needsOutputLength: false },
  "shake256":   { algorithm: "shake256",   needsOutputLength: true  },
});
var STREAM_HASH_DEFAULT = "sha3-512";
var SHAKE256_DEFAULT_LEN = 64;

function hash(data, algorithm, outputLength) {
  var opts = outputLength ? { outputLength: outputLength } : undefined;
  return nodeCrypto.createHash(algorithm, opts).update(data).digest();
}

var HMAC_ALGS = {
  "sha256": 1, "sha384": 1, "sha512": 1,
  "sha3-256": 1, "sha3-384": 1, "sha3-512": 1,
};

/**
 * @primitive b.crypto.hmac
 * @signature b.crypto.hmac(key, data, algorithm?)
 * @since     0.18.8
 * @status    stable
 * @related   b.crypto.timingSafeEqual, b.crypto.sha3Hash
 *
 * Lowercase-hex HMAC of `data` keyed by `key`. The `algorithm` defaults to the
 * framework's PQC-first SHA3-512 — call `b.crypto.hmac(key, data)` for keyed
 * integrity (webhook signatures, request-auth tags, audit-chain links) and it
 * is strong by default. Pass an explicit weaker algorithm ONLY to interop with
 * an external scheme that fixes it — e.g. Stripe / Tailscale webhook signatures
 * require `"sha256"`. The algorithm is validated against a SHA-2 / SHA-3
 * allowlist, so a typo or a broken choice (SHA-1 / MD5) throws at the entry tier
 * rather than silently signing under a surprise hash. `key` and `data` accept a
 * Buffer or string. Compare tags with `b.crypto.timingSafeEqual`, never `==`.
 *
 * @example
 *   var tag = b.crypto.hmac("shared-secret", "POST /webhook|123");
 *   // → SHA3-512 HMAC (128 hex chars) — the PQC-first default
 *   var stripe = b.crypto.hmac(process.env.WHSEC, ts + "." + rawBody, "sha256");
 *   // → HMAC-SHA256 (64 hex chars) — explicit opt-down for external interop
 */
function hmac(key, data, algorithm) {
  var alg = algorithm === undefined ? "sha3-512" : algorithm;
  if (typeof alg !== "string" || !Object.prototype.hasOwnProperty.call(HMAC_ALGS, alg)) {
    throw new TypeError(
      "crypto.hmac: algorithm must be one of " + Object.keys(HMAC_ALGS).join(", ") +
      " (SHA-1 / MD5 are refused), got " +
      (alg === null ? "null" : JSON.stringify(alg)));
  }
  if (typeof key !== "string" && !Buffer.isBuffer(key)) {
    throw new TypeError("crypto.hmac: key must be a Buffer or string, got " +
      (key === null ? "null" : typeof key));
  }
  if (typeof data !== "string" && !Buffer.isBuffer(data)) {
    throw new TypeError("crypto.hmac: data must be a Buffer or string, got " +
      (data === null ? "null" : typeof data));
  }
  return nodeCrypto.createHmac(alg, key).update(data).digest("hex");
}

/**
 * @primitive b.crypto.hashStream
 * @signature b.crypto.hashStream(readable, algorithm)
 * @since     0.5.0
 * @related   b.crypto.hashFile, b.crypto.sha3Hash
 *
 * Streams a Readable through `createHash(algorithm)` and resolves with
 * the raw digest Buffer. Default algorithm is SHA3-512. Algorithm is
 * validated against the allowlist (sha3-256 / sha3-384 / sha3-512 /
 * sha512 / shake256) so a typo or weak choice throws at config time
 * rather than producing a digest under a surprise algorithm. Read-
 * only — no audit emit.
 *
 * @example
 *   var fs = require("fs");
 *   var stream = fs.createReadStream("/etc/hosts");
 *   b.crypto.hashStream(stream, "sha3-512").then(function (digest) {
 *     digest.toString("hex");
 *     // → "abcd0123...e8f9" (128 hex chars, SHA3-512 = 64 bytes)
 *   });
 */
function hashStream(readable, algorithm) {
  var alg = (algorithm || STREAM_HASH_DEFAULT).toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(STREAM_HASH_ALGORITHMS, alg)) {
    return Promise.reject(new TypeError(
      "crypto.hashStream: unsupported algorithm '" + algorithm +
      "' (allowed: " + Object.keys(STREAM_HASH_ALGORITHMS).join(", ") + ")"
    ));
  }
  var entry = STREAM_HASH_ALGORITHMS[alg];
  if (!readable || typeof readable.pipe !== "function") {
    return Promise.reject(new TypeError(
      "crypto.hashStream: readable must be a Readable stream"
    ));
  }
  var hashOpts = entry.needsOutputLength ? { outputLength: SHAKE256_DEFAULT_LEN } : undefined;
  var digester = nodeCrypto.createHash(entry.algorithm, hashOpts);
  return pipeline(readable, digester).then(function () {
    return digester.digest();
  });
}

/**
 * @primitive b.crypto.hashFile
 * @signature b.crypto.hashFile(filePath, algorithm)
 * @since     0.5.0
 * @related   b.crypto.hashStream, b.crypto.sha3Hash
 *
 * Opens `filePath` as a Readable and streams it through `hashStream`.
 * Resolves with the raw digest Buffer. Default algorithm is SHA3-512.
 * Read-only — no audit emit; the path is operator-supplied and the
 * digest is the only observable side-effect.
 *
 * @example
 *   b.crypto.hashFile("/etc/hosts", "sha3-256").then(function (digest) {
 *     digest.toString("hex");
 *     // → "0123abcd...ef89" (64 hex chars, SHA3-256 = 32 bytes)
 *   });
 */
function hashFile(filePath, algorithm) {
  if (typeof filePath !== "string" || filePath.length === 0) {
    return Promise.reject(new TypeError(
      "crypto.hashFile: path must be a non-empty string"
    ));
  }
  return hashStream(nodeFs.createReadStream(filePath), algorithm);
}

function _hashFileMulti(filePath, algorithms, opts) {
  var maxBytes      = opts && opts.maxBytesPerFile;
  var followSymlink = opts && opts.followSymlinks === true;
  return new Promise(function (resolve, reject) {
    var st;
    try { st = nodeFs.lstatSync(filePath); }
    catch (statErr) {
      var statWrapped = new Error("crypto.hashFilesParallel: stat failed for '" +
        filePath + "': " + (statErr && statErr.message ? statErr.message : String(statErr)));
      if (statErr) {
        statWrapped.code    = statErr.code;
        statWrapped.errno   = statErr.errno;
        statWrapped.syscall = statErr.syscall;
        statWrapped.cause   = statErr;
      }
      statWrapped.path = filePath;
      reject(statWrapped);
      return;
    }
    if (st.isSymbolicLink() && !followSymlink) {
      var symErr = new Error("crypto.hashFilesParallel: refusing symlink '" +
        filePath + "' — pass {followSymlinks: true} to opt in (an attacker " +
        "with write access to the input list can otherwise direct the hasher " +
        "to files the caller cannot read directly)");
      symErr.code = "crypto/hash-refused-symlink";
      symErr.path = filePath;
      reject(symErr);
      return;
    }
    if (!st.isFile() && !st.isSymbolicLink()) {
      var nonRegularErr = new Error("crypto.hashFilesParallel: refusing non-regular file '" +
        filePath + "' (FIFOs / sockets / character / block devices read indefinitely " +
        "or return platform-undefined bytes; hashing them is meaningless and " +
        "DoS-prone). Type: " +
        (st.isFIFO() ? "FIFO" :
         st.isSocket() ? "socket" :
         st.isBlockDevice() ? "block-device" :
         st.isCharacterDevice() ? "char-device" :
         st.isDirectory() ? "directory" : "unknown"));
      nonRegularErr.code = "crypto/hash-refused-non-regular-file";
      nonRegularErr.path = filePath;
      reject(nonRegularErr);
      return;
    }
    var hashers = new Array(algorithms.length);
    for (var i = 0; i < algorithms.length; i += 1) {
      try { hashers[i] = nodeCrypto.createHash(algorithms[i]); }
      catch (e) {
        reject(new Error("crypto.hashFilesParallel: unknown algorithm '" +
          algorithms[i] + "': " + (e && e.message ? e.message : String(e))));
        return;
      }
    }
    var byteLength = 0;
    var aborted = false;
    var stream = nodeFs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", function (chunk) {
      if (aborted) return;
      byteLength += chunk.length;
      if (maxBytes && byteLength > maxBytes) {
        aborted = true;
        try { stream.destroy(); } catch (_e) { /* best-effort */ }
        var maxBytesErr = new Error("crypto.hashFilesParallel: file '" + filePath +
          "' exceeded opts.maxBytesPerFile (" + maxBytes +
          " bytes); refusing to continue hashing");
        maxBytesErr.code = "crypto/hash-max-bytes-exceeded";
        maxBytesErr.path = filePath;
        reject(maxBytesErr);
        return;
      }
      for (var j = 0; j < hashers.length; j += 1) hashers[j].update(chunk);
    });
    stream.on("end", function () {
      if (aborted) return;
      var out = { path: filePath, byteLength: byteLength };
      for (var k = 0; k < hashers.length; k += 1) {
        out[algorithms[k].replace(/-/g, "_")] = hashers[k].digest("hex");
      }
      resolve(out);
    });
  });
}

/**
 * @primitive b.crypto.hashFilesParallel
 * @signature b.crypto.hashFilesParallel(filePaths, opts?)
 * @since     0.9.14
 * @status    stable
 * @related   b.crypto.hashFile, b.crypto.hashStream
 *
 * Hash many files in parallel, streaming each one through one or
 * more digest algorithms in a single read pass. Returns an array of
 * `{ path, byteLength, sha256, sha3_512, ... }` records in the same
 * order as `filePaths`. Concurrency is operator-tunable; the default
 * (`min(8, filePaths.length)`) matches the framework's
 * hash-while-streaming convention elsewhere without saturating the
 * fs read queue on spinning-disk hosts.
 *
 * The common consumer-side reason to reach for this primitive is
 * SBOM regeneration / vendor-data integrity sweeps / release-asset
 * bundling — situations where N files each need both SHA-256 (legacy
 * compat) and SHA-3-512 (PQC-first) digests and rolling a worker
 * pool by hand means the same two-loop, capture-N-promises, settle-Q
 * boilerplate every release.
 *
 * @opts
 *   algorithms?:     string[], // default ["sha256", "sha3-512"]; any node:crypto-known digest
 *   concurrency?:    number,   // default min(8, filePaths.length); 1..256
 *   onProgress?:     function (completed, total) // best-effort; thrown errors swallowed
 *   maxBytesPerFile?: number,  // default C.BYTES.gib(1) — DoS cap; oversized inputs reject
 *   followSymlinks?: boolean,  // default false — refuse symlinks unless explicitly opted in
 *
 * @example
 *   var rows = await b.crypto.hashFilesParallel(
 *     ["/var/lib/blamejs/asset-a.bin",
 *      "/var/lib/blamejs/asset-b.bin"],
 *     { algorithms: ["sha256", "sha3-512"], concurrency: 4 }
 *   );
 *   // rows[0] → { path: "...asset-a.bin", byteLength: 4096,
 *   //            sha256: "...", sha3_512: "..." }
 */
function hashFilesParallel(filePaths, opts) {
  if (!Array.isArray(filePaths)) {
    return Promise.reject(new TypeError(
      "crypto.hashFilesParallel: filePaths must be an array of non-empty strings"
    ));
  }
  for (var i = 0; i < filePaths.length; i += 1) {
    if (typeof filePaths[i] !== "string" || filePaths[i].length === 0) {
      return Promise.reject(new TypeError(
        "crypto.hashFilesParallel: filePaths[" + i + "] must be a non-empty string"
      ));
    }
  }
  opts = opts || {};
  var algorithms = opts.algorithms !== undefined
    ? opts.algorithms : ["sha256", "sha3-512"];
  if (!Array.isArray(algorithms) || algorithms.length === 0) {
    return Promise.reject(new TypeError(
      "crypto.hashFilesParallel: opts.algorithms must be a non-empty array"
    ));
  }
  for (var ai = 0; ai < algorithms.length; ai += 1) {
    if (typeof algorithms[ai] !== "string" || algorithms[ai].length === 0) {
      return Promise.reject(new TypeError(
        "crypto.hashFilesParallel: opts.algorithms[" + ai + "] must be a non-empty string"
      ));
    }
  }
  var concurrency = opts.concurrency !== undefined
    ? opts.concurrency
    : Math.min(8, Math.max(1, filePaths.length));
  if (typeof concurrency !== "number" || !isFinite(concurrency) ||
      concurrency < 1 || concurrency > 256 ||
      Math.floor(concurrency) !== concurrency) {
    return Promise.reject(new TypeError(
      "crypto.hashFilesParallel: opts.concurrency must be an integer in [1, 256], got " + concurrency
    ));
  }
  var onProgress = opts.onProgress;
  if (onProgress !== undefined && typeof onProgress !== "function") {
    return Promise.reject(new TypeError(
      "crypto.hashFilesParallel: opts.onProgress must be a function when supplied"
    ));
  }
  var maxBytesPerFile = opts.maxBytesPerFile !== undefined
    ? opts.maxBytesPerFile : C.BYTES.gib(1);
  if (!numericBounds.isPositiveFiniteInt(maxBytesPerFile)) {
    return Promise.reject(new TypeError(
      "crypto.hashFilesParallel: opts.maxBytesPerFile must be a positive integer, got " + maxBytesPerFile
    ));
  }
  var followSymlinks = opts.followSymlinks === true;
  if (filePaths.length === 0) return Promise.resolve([]);

  var hashOpts = {
    maxBytesPerFile: maxBytesPerFile,
    followSymlinks:  followSymlinks,
  };
  var results = new Array(filePaths.length);
  var nextIdx = 0;
  var completed = 0;
  var total = filePaths.length;
  function _worker() {
    function _step() {
      var idx = nextIdx;
      nextIdx += 1;
      if (idx >= total) return Promise.resolve();
      return _hashFileMulti(filePaths[idx], algorithms, hashOpts).then(function (rec) {
        results[idx] = rec;
        completed += 1;
        safeAsync().safeApply(onProgress, [completed, total]);
        return _step();
      });
    }
    return _step();
  }
  var workerCount = Math.min(concurrency, total);
  var workers = new Array(workerCount);
  for (var w = 0; w < workerCount; w += 1) workers[w] = _worker();
  return Promise.all(workers).then(function () { return results; });
}

function random(byteLength) {
  var n = byteLength || 32;
  var drawN = n < 2 ? 2 : n;
  var out = nodeCrypto.createHash("shake256", { outputLength: drawN })
    .update(nodeCrypto.randomBytes(drawN))
    .digest();
  return drawN === n ? out : out.subarray(0, n);
}

/**
 * @primitive b.crypto.randomInt
 * @signature b.crypto.randomInt(min, max)
 * @since     0.10.7
 * @status    stable
 *
 * Cryptographically-secure uniform integer in `[min, max)`. Substrate
 * wrapper that routes every framework integer draw (DNS query-ID,
 * DMARC `pct` sampling, retry jitter) through one greppable primitive.
 * Both bounds must be safe integers, `max > min`, and the half-open
 * span must not exceed 2^48 (the underlying runtime's hard cap).
 *
 * @example
 *   var n = b.crypto.randomInt(0, 100);
 *   // → integer in [0, 100)
 */
function randomInt(min, max) {
  if (typeof min !== "number" || !Number.isInteger(min)) {
    throw new TypeError("b.crypto.randomInt: min must be an integer");
  }
  if (typeof max !== "number" || !Number.isInteger(max)) {
    throw new TypeError("b.crypto.randomInt: max must be an integer");
  }
  if (max <= min) {
    throw new RangeError("b.crypto.randomInt: max must be greater than min");
  }
  return nodeCrypto.randomInt(min, max);
}

function generateKeyPair(algorithm, options) {
  var pair = nodeCrypto.generateKeyPairSync(algorithm, Object.assign({
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  }, options || {}));
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

/**
 * @primitive b.crypto.timingSafeEqual
 * @signature b.crypto.timingSafeEqual(a, b)
 * @since     0.1.0
 * @related   b.crypto.hmac
 *
 * Constant-time equality comparison. Accepts only Buffer or string
 * inputs — non-string non-Buffer arguments throw at the entry tier so
 * a `Object.prototype.toString`-poisoned caller can't redirect the
 * compare through arbitrary attacker-controlled bytes. Returns
 * `false` immediately when lengths differ (length itself is not a
 * secret), then routes equal-length inputs through
 * `crypto.timingSafeEqual`. Use when comparing HMAC digests, session
 * tokens, password-reset codes, or any attacker-influenced value
 * where a timing oracle would leak bits.
 *
 * @example
 *   var expected = b.crypto.hmac("server-key", "payload");
 *   var supplied = "ab12...e9";   // from request header / body
 *   var ok = b.crypto.timingSafeEqual(supplied, expected);
 *   // → true when bytes match, false otherwise (no early exit on mismatch)
 */
function timingSafeEqual(a, b) {
  if (!Buffer.isBuffer(a) && typeof a !== "string") {
    throw new TypeError(
      "crypto.timingSafeEqual: argument 'a' must be a Buffer or string, got " +
      (a === null ? "null" : typeof a)
    );
  }
  if (!Buffer.isBuffer(b) && typeof b !== "string") {
    throw new TypeError(
      "crypto.timingSafeEqual: argument 'b' must be a Buffer or string, got " +
      (b === null ? "null" : typeof b)
    );
  }
  var bufA = Buffer.isBuffer(a) ? a : Buffer.from(a, "utf8");
  var bufB = Buffer.isBuffer(b) ? b : Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return nodeCrypto.timingSafeEqual(bufA, bufB);
}

/**
 * @primitive b.crypto.timingSafeEqualAny
 * @signature b.crypto.timingSafeEqualAny(presented, candidates)
 * @since     0.18.36
 * @status    stable
 * @related   b.crypto.timingSafeEqual, b.crypto.isCertRevoked, b.crypto.spkiPinVerifier
 *
 * Returns `true` when `presented` equals any entry of `candidates`, comparing
 * against EVERY entry whatever the outcome. A per-candidate compare in a loop
 * that stops at the first match answers a second question nobody asked — how
 * far down the list the match was — and the caller's own timing then reports
 * it: matching the first pinned key returns sooner than matching the last, and
 * matching nothing runs the whole list. That is a position oracle over a secret
 * ordering, so this loop has no `break`, no `return` inside it, and folds each
 * result into an accumulator instead.
 *
 * A length mismatch short-circuits a single comparison, and that leaks nothing:
 * the lengths compared here are digest and fingerprint sizes fixed by an
 * algorithm, not secrets. `presented` and each candidate may be a Buffer or a
 * string; a candidate that is neither counts as a non-match rather than
 * throwing, because a deny list assembled from operator config should not fail
 * the request on one malformed row.
 *
 * Entry-tier on `presented` and on the array itself: a caller that passes the
 * wrong shape has a bug, and the compare would otherwise silently answer
 * `false` for every input.
 *
 * @example
 *   var ok = b.crypto.timingSafeEqualAny(presentedKey, [primary, previous]);
 *   // → true when it matches either, in the same time either way
 */
function timingSafeEqualAny(presented, candidates) {
  if (!Buffer.isBuffer(presented) && typeof presented !== "string") {
    throw new TypeError(
      "crypto.timingSafeEqualAny: argument 'presented' must be a Buffer or " +
      "string, got " + (presented === null ? "null" : typeof presented)
    );
  }
  if (!Array.isArray(candidates)) {
    throw new TypeError(
      "crypto.timingSafeEqualAny: argument 'candidates' must be an array, got " +
      (candidates === null ? "null" : typeof candidates)
    );
  }
  var presentedBuf = Buffer.isBuffer(presented)
    ? presented : Buffer.from(presented, "utf8");
  var matched = false;
  for (var i = 0; i < candidates.length; i += 1) {
    var candidate = candidates[i];
    if (!Buffer.isBuffer(candidate) && typeof candidate !== "string") continue;
    var candidateBuf = Buffer.isBuffer(candidate)
      ? candidate : Buffer.from(candidate, "utf8");
    if (candidateBuf.length !== presentedBuf.length) continue;
    if (nodeCrypto.timingSafeEqual(presentedBuf, candidateBuf)) matched = true;
  }
  return matched;
}

/**
 * @primitive b.crypto.sha3Hash
 * @signature b.crypto.sha3Hash(data)
 * @since     0.1.0
 * @related   b.crypto.hmac, b.crypto.kdf, b.crypto.hashFile
 *
 * Returns the lowercase-hex SHA3-512 digest of the input. SHA3-512 is
 * the framework's default hash — collision-resistant, sponge-based,
 * and PQC-aligned (no quantum speedup beyond Grover's). Suitable for
 * content fingerprints, integrity checks, derived-column inputs, and
 * Merkle-tree leaves.
 *
 * @example
 *   var digest = b.crypto.sha3Hash("hello world");
 *   // → "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df..."
 */
function sha3Hash(data) { return hash(data, "sha3-512").toString("hex"); }

/**
 * @primitive b.crypto.kdf
 * @signature b.crypto.kdf(input, outputLength)
 * @since     0.1.0
 * @related   b.crypto.sha3Hash, b.crypto.generateBytes
 *
 * SHAKE256-based key derivation. Returns a Buffer of exactly
 * `outputLength` bytes derived from `input`. SHAKE256 is an XOF
 * (extendable-output function) — arbitrary output length without the
 * truncation pitfalls of fixed-width SHA3 + slice. Used internally
 * for envelope symmetric-key derivation; operators reach for it when
 * they need application-specific subkeys with explicit length.
 *
 * @example
 *   var seed = Buffer.from("master-secret|session-42", "utf8");
 *   var subkey = b.crypto.kdf(seed, 32);
 *   subkey.length;
 *   // → 32 (32-byte XChaCha20 key)
 */
function kdf(input, outputLength) { return hash(input, "shake256", outputLength); }

var NAMESPACE_HASH_PREFIX_MAX_BYTES = 64;

/**
 * @primitive b.crypto.namespaceHash
 * @signature b.crypto.namespaceHash(prefix, value, opts)
 * @since     0.6.0
 * @related   b.crypto.sha3Hash, b.credentialHash.hash
 *
 * App-namespaced indexable SHA3-512 hash for derived-hash columns
 * (emailHash, certFpHash, externalIdHash). Returns lowercase hex —
 * stable, indexable column values across every supported database.
 * Centralizes prefix-shape validation: NUL / CR / LF in `prefix` are
 * refused outright, and `prefix` is bounded to 64 UTF-8 bytes so an
 * operator can't smuggle log-injection or oversized labels into
 * derived-column inputs. Use when the goal is exact-match lookup,
 * NOT credential storage — for password-style storage use
 * `b.credentialHash.hash`.
 *
 * @opts
 *   reserved: object,   // accepted but ignored — reserved for a future algorithm-selection knob
 *
 * @example
 *   var emailHash = b.crypto.namespaceHash("email", "alice@example.com");
 *   // → "1f3a...c08d" (128 hex chars, SHA3-512 of "email:alice@example.com")
 *
 *   var certFpHash = b.crypto.namespaceHash("cert-fp", Buffer.from([1, 2, 3, 4]));
 *   // Buffer/Uint8Array values are coerced to UTF-8 string before hashing.
 */
function namespaceHash(prefix, value, opts) {
  if (opts && typeof opts !== "object") {
    throw new TypeError("crypto.namespaceHash: opts must be a plain object when provided");
  }
  if (typeof prefix !== "string") {
    throw new TypeError("crypto.namespaceHash: prefix must be a string");
  }
  if (prefix.length === 0) {
    throw new TypeError("crypto.namespaceHash: prefix must be non-empty");
  }
  if (Buffer.byteLength(prefix, "utf8") > NAMESPACE_HASH_PREFIX_MAX_BYTES) {
    throw new TypeError(
      "crypto.namespaceHash: prefix exceeds " + NAMESPACE_HASH_PREFIX_MAX_BYTES +
      " bytes (UTF-8); operator-derived prefixes should be short labels"
    );
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000\r\n]/.test(prefix)) {
    throw new TypeError(
      "crypto.namespaceHash: prefix contains NUL / CR / LF — refuse"
    );
  }
  var valueStr;
  var valueWasString = false;
  if (typeof value === "string") {
    valueStr = value;
    valueWasString = true;
  } else if (Buffer.isBuffer(value)) {
    valueStr = value.toString("utf8");
  } else if (nodeTypes.isUint8Array(value)) {
    valueStr = Buffer.from(value).toString("utf8");
  } else {
    throw new TypeError(
      "crypto.namespaceHash: value must be a string, Buffer, or Uint8Array"
    );
  }
  if (valueWasString && safeBuffer().hasCrlf(valueStr)) {
    throw new TypeError(
      "crypto.namespaceHash: value (string-typed) contains CR / LF — refuse"
    );
  }
  return hash(prefix + ":" + valueStr, "sha3-512").toString("hex");
}

function _suiteFixedInfo(kemId, cipherId, kdfId) {
  return Buffer.concat([
    Buffer.from(C.ENVELOPE_FIXED_INFO_LABEL, "utf8"),
    Buffer.from([0x00, kemId, cipherId, kdfId, 0x00]),
  ]);
}

/**
 * @primitive b.crypto.generateBytes
 * @signature b.crypto.generateBytes(byteLength)
 * @since     0.1.0
 * @related   b.crypto.generateToken, b.uuid.v4
 *
 * Cryptographically secure random Buffer of length `byteLength`
 * (default 32). The bytes are SHAKE256(OS-RNG bytes) — defense-in-
 * depth over `crypto.randomBytes` so a hypothetical OS-RNG weakness
 * is not directly observable downstream. Use for session IDs, KDF
 * salts, AEAD nonces, anything requiring unpredictable bytes.
 *
 * @example
 *   var sessionId = b.crypto.generateBytes(16).toString("hex");
 *   // → 32 hex chars, a fresh draw of 16 random bytes: "5b8f2a4c...4f7c1b5d"
 *
 *   var nonce = b.crypto.generateBytes(24);   // XChaCha20-Poly1305 nonce
 *   nonce.length;
 *   // → 24
 */
function generateBytes(byteLength) { return Buffer.from(random(byteLength)); }

/**
 * @primitive b.crypto.generateToken
 * @signature b.crypto.generateToken(byteLength)
 * @since     0.1.0
 * @related   b.crypto.generateBytes, b.uuid.v4
 *
 * Hex-encoded random token. Same entropy source as `generateBytes`
 * (SHAKE256 over OS-RNG bytes) but returned as a lowercase hex string
 * — convenient for HTTP headers, URL parameters, log fields, or any
 * context where a Buffer would need to be encoded anyway. Default
 * `byteLength` is 32 (64 hex chars, ~256 bits of entropy).
 *
 * @example
 *   var token = b.crypto.generateToken();
 *   token.length;
 *   // → 64 (32 bytes hex-encoded)
 *
 *   var shortId = b.crypto.generateToken(8);
 *   // → "a3f9...b1" (16 hex chars, 8 random bytes)
 */
function generateToken(byteLength) { return random(byteLength || 32).toString("hex"); }

/**
 * @primitive b.crypto.toBase64Url
 * @signature b.crypto.toBase64Url(buf)
 * @since     0.9.45
 * @status    stable
 * @related   b.crypto.fromBase64Url
 *
 * RFC 4648 §5 base64url-encode a Buffer / Uint8Array / string. Routes
 * through Node's built-in `"base64url"` encoding rather than the
 * historical inline `.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_")`
 * pattern. Without this helper, every JWS / JWT / DPoP / WebAuthn /
 * DNS-base64url / pagination-cursor / GCS-signed-URL call site
 * reinvented the same three-replace pipeline — and the trailing
 * `=+$` regex is polynomial-ReDoS-vulnerable per CodeQL
 * `js/polynomial-redos`. Node's built-in encoder is linear time, no
 * regex, no backtracking surface.
 *
 * Input shape: Buffer / Uint8Array → encoded; string → treated as
 * UTF-8 bytes then encoded.
 *
 * @example
 *   b.crypto.toBase64Url(Buffer.from("hello"));
 *   // → "aGVsbG8"
 *
 *   b.crypto.toBase64Url("hello");
 *   // → "aGVsbG8"
 */
function toBase64Url(buf) {
  if (typeof buf === "string") return Buffer.from(buf, "utf8").toString("base64url");
  if (Buffer.isBuffer(buf)) return buf.toString("base64url");
  if (nodeTypes.isUint8Array(buf)) return Buffer.from(buf).toString("base64url");
  throw new TypeError("crypto.toBase64Url: input must be Buffer, Uint8Array, or string");
}

/**
 * @primitive b.crypto.fromBase64Url
 * @signature b.crypto.fromBase64Url(s, opts?)
 * @since     0.9.45
 * @status    stable
 * @related   b.crypto.toBase64Url
 *
 * RFC 4648 §5 base64url-decode a string into a Buffer. Inverse of
 * `toBase64Url`. Operators previously reached for `Buffer.from(s,
 * "base64url")` directly; this wrapper validates the input is a
 * string + provides a single grep-able call site for the round-trip
 * pair.
 *
 * Strict mode (default) refuses non-canonical input — chars outside
 * the RFC 4648 §5 alphabet, length-mod-4-of-1, mixed `+/` from
 * standard base64, trailing garbage. Defends the CWE-347 /
 * CWE-1286 signature-canonicalization footgun where a permissive
 * base64url decoder silently tolerates a tampered JWS / JWT signature
 * (non-canonical bytes decoding to the same buffer). Operators with a
 * documented lossy legacy payload opt out per call via
 * `{ strict: false }`.
 *
 * @opts
 *   strict: boolean   // default: true — refuse non-canonical input
 *
 * @example
 *   var buf = b.crypto.fromBase64Url("aGVsbG8");
 *   buf.toString("utf8");
 *   // → "hello"
 */
var _BASE64URL_STRICT_RE = /^[A-Za-z0-9_-]*={0,2}$/;

function fromBase64Url(s, opts) {
  if (typeof s !== "string") {
    throw new TypeError("crypto.fromBase64Url: input must be a string");
  }
  var strict = !opts || opts.strict !== false;
  if (strict) {
    var trimEnd = s.length;
    while (trimEnd > 0 && s.charCodeAt(trimEnd - 1) === 0x3D) trimEnd -= 1;
    var unpadded = s.slice(0, trimEnd);
    if (!_BASE64URL_STRICT_RE.test(s)) {
      throw new TypeError(
        "crypto.fromBase64Url: input contains characters outside RFC 4648 §5 " +
        "base64url alphabet (A-Z a-z 0-9 - _ =) — pass {strict:false} to allow non-canonical input"
      );
    }
    if (unpadded.length % 4 === 1) {
      throw new TypeError(
        "crypto.fromBase64Url: input length %% 4 === 1 is not a valid base64url encoding " +
        "(every conforming encoder produces 0 / 2 / 3 remainder; got " + unpadded.length + " chars)"
      );
    }
  }
  return Buffer.from(s, "base64url");
}

/**
 * @primitive b.crypto.makeBase64UrlDecoder
 * @signature b.crypto.makeBase64UrlDecoder(opts)
 * @since     0.15.13
 * @status    stable
 * @related   b.crypto.fromBase64Url, b.crypto.toBase64Url
 *
 * Bind the strict `fromBase64Url` decoder to one module's error contract,
 * returning a `decode(s)` that translates the decoder's `TypeError` (bad
 * type or non-canonical input) into the caller's typed error. Every
 * base64url-carrying surface — JWT segments, DPoP / OAuth tokens, status
 * lists, pagination cursors — wrapped `fromBase64Url` in the same
 * `if (typeof s !== "string") throw new XError(...); try { return
 * fromBase64Url(s); } catch { throw new XError(...); }` shape, differing
 * only in error class, code, and the two messages; this owns that binding.
 *
 * `opts.badMessage` is thrown on any decode failure (non-canonical /
 * malformed input — the strict decoder rejects the CWE-347 signature-
 * canonicalization footgun). `opts.typeMessage` is optional: when set, a
 * non-string input throws it directly (the common case names the field —
 * "cursor must be a string"); when omitted, a non-string falls through to
 * `badMessage` like any other decode failure.
 *
 * @opts
 *   errorClass:  Function,  // required — (code, message) error constructor
 *   code:        string,    // required — error code for both throws
 *   badMessage:  string,    // required — message on a decode failure
 *   typeMessage: string,    // optional — message on a non-string input
 *
 * @example
 *   var b = require("blamejs");
 *
 *   function JwtError(code, message) { this.code = code; this.message = message; }
 *   var decodeSeg = b.crypto.makeBase64UrlDecoder({
 *     errorClass:  JwtError,
 *     code:        "jwt/malformed",
 *     typeMessage: "expected base64url string",
 *     badMessage:  "JWT segment is not valid base64url",
 *   });
 *   decodeSeg("aGVsbG8");   // → <Buffer 68 65 6c 6c 6f>
 *   // decodeSeg("!!!") throws JwtError("jwt/malformed", "JWT segment is not valid base64url")
 */
function makeBase64UrlDecoder(opts) {
  if (!opts || typeof opts !== "object") {
    throw new TypeError("crypto.makeBase64UrlDecoder: opts is required");
  }
  if (typeof opts.errorClass !== "function") {
    throw new TypeError("crypto.makeBase64UrlDecoder: opts.errorClass must be a constructor");
  }
  if (typeof opts.badMessage !== "string") {
    throw new TypeError("crypto.makeBase64UrlDecoder: opts.badMessage must be a string");
  }
  var ErrorClass = opts.errorClass;
  var code = opts.code;
  var typeMessage = opts.typeMessage;
  var badMessage = opts.badMessage;
  return function decode(s) {
    if (typeMessage !== undefined && typeof s !== "string") {
      throw new ErrorClass(code, typeMessage);
    }
    try {
      return fromBase64Url(s);
    } catch (_e) {
      throw new ErrorClass(code, badMessage);
    }
  };
}

var SRI_ALGORITHMS = { "sha256": "sha256", "sha384": "sha384", "sha512": "sha512" };

/**
 * @primitive b.crypto.sri
 * @signature b.crypto.sri(content, opts)
 * @since     0.5.0
 * @related   b.staticServe
 *
 * Computes a W3C Subresource Integrity 1.0 attribute string —
 * `sha###-base64` — that operators paste into `<script integrity>` or
 * `<link integrity>` tags. Defends against CDN compromise and ISP
 * MITM injection: the browser refuses to load the resource when its
 * computed hash diverges from the integrity attribute. SRI 1.0 §3.2
 * supports sha256 / sha384 / sha512; sha384 is the recommended
 * default (collision margin without sha512's 64-byte overhead). Pass
 * an array of contents to emit multiple integrity tokens space-
 * separated per §3.3 (browser picks the strongest it recognizes).
 *
 * @opts
 *   algorithm: string,   // "sha256" | "sha384" | "sha512" — default "sha384"
 *
 * @example
 *   var attr = b.crypto.sri(Buffer.from("alert(1);", "utf8"), { algorithm: "sha384" });
 *   // → "sha384-dnux3uAPxaf+IhCrFG1D/XVNzP1XLDNcn3Pe3jyxouEAoot5kfwC5u8rMwNhE5oi"
 *
 *   var multi = b.crypto.sri(["payload-a", "payload-b"], { algorithm: "sha512" });
 *   // → "sha512-... sha512-..." (two tokens, space-separated)
 */
function sri(content, opts) {
  opts = opts || {};
  var algorithm = (opts.algorithm || "sha384").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(SRI_ALGORITHMS, algorithm)) {
    throw new Error("crypto.sri: unsupported algorithm '" + algorithm +
      "' (W3C SRI 1.0 §3.2 supports sha256/sha384/sha512)");
  }
  if (Array.isArray(content)) {
    return content.map(function (c) { return sri(c, opts); }).join(" ");
  }
  var buf;
  if (Buffer.isBuffer(content)) buf = content;
  else if (typeof content === "string") buf = Buffer.from(content, "utf8");
  else if (nodeTypes.isUint8Array(content)) buf = Buffer.from(content);
  else throw new Error("crypto.sri: content must be a Buffer, Uint8Array, string, or array of those");
  var digest = nodeCrypto.createHash(algorithm).update(buf).digest("base64");
  return algorithm + "-" + digest;
}

/**
 * @primitive b.crypto.generateEncryptionKeyPair
 * @signature b.crypto.generateEncryptionKeyPair()
 * @since     0.1.0
 * @related   b.crypto.encrypt, b.crypto.decrypt, b.crypto.generateMlkem768X25519KeyPair
 *
 * Generates a hybrid recipient keypair for `b.crypto.encrypt`:
 * ML-KEM-1024 (FIPS 203 PQC KEM) plus ECDH P-384 (classical defense-
 * in-depth). Returns `{ publicKey, privateKey, ecPublicKey,
 * ecPrivateKey }` — all four PEMs. Persist the private halves in
 * sealed storage; publish the public halves to recipients. The
 * framework default for at-rest envelopes and api-encrypt strategies.
 *
 * @example
 *   var pair = b.crypto.generateEncryptionKeyPair();
 *   var sealed = b.crypto.encrypt("secret payload", {
 *     publicKey:    pair.publicKey,
 *     ecPublicKey:  pair.ecPublicKey,
 *   });
 *   var roundTrip = b.crypto.decrypt(sealed, {
 *     privateKey:    pair.privateKey,
 *     ecPrivateKey:  pair.ecPrivateKey,
 *   });
 *   // → "secret payload"
 */
function generateEncryptionKeyPair() {
  var mlkem = generateKeyPair("ml-kem-1024");
  var ec = generateKeyPair("ec", { namedCurve: "P-384" });
  return {
    publicKey:    mlkem.publicKey,
    privateKey:   mlkem.privateKey,
    ecPublicKey:  ec.publicKey,
    ecPrivateKey: ec.privateKey,
  };
}

/**
 * @primitive b.crypto.generateSigningKeyPair
 * @signature b.crypto.generateSigningKeyPair(algorithm)
 * @since     0.1.0
 * @related   b.crypto.sign, b.crypto.verify
 *
 * Generates a PQC signature keypair. Default algorithm is `ml-dsa-87`
 * (FIPS 204 — lattice-based, fast verify); pass `slh-dsa-shake-256f`
 * for hash-based signatures (larger, slower, but minimal cryptographic
 * assumptions — useful for long-lived audit-chain keys). Returns
 * `{ publicKey, privateKey }` PEMs. The signing primitives auto-
 * detect the algorithm from the key PEM, so callers don't need to
 * pass it explicitly to `sign` / `verify`.
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair();
 *   var sig = b.crypto.sign("audit:row=42|action=delete", pair.privateKey);
 *   var ok  = b.crypto.verify("audit:row=42|action=delete", sig, pair.publicKey);
 *   // → true
 *
 *   // Hash-based alternative:
 *   var slh = b.crypto.generateSigningKeyPair("slh-dsa-shake-256f");
 */
function generateSigningKeyPair(algorithm) {
  return generateKeyPair(algorithm || "ml-dsa-87");
}

/**
 * @primitive b.crypto.sign
 * @signature b.crypto.sign(data, privateKeyPem)
 * @since     0.1.0
 * @related   b.crypto.verify, b.crypto.generateSigningKeyPair
 *
 * Produces a PQC signature over `data`. Algorithm is auto-detected
 * from the private-key PEM (ML-DSA-87 lattice / SLH-DSA-SHAKE-256f
 * hash-based). Returns a Buffer. Pair with `b.crypto.verify` on the
 * recipient side; use for audit-chain links, webhook tags,
 * cross-service request signatures. A compromised private key
 * (`b.crypto.compromisedKey`) throws `crypto/compromised-key` and signs
 * nothing, and a key that cannot be read throws `crypto/bad-key`.
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair();
 *   var sig = b.crypto.sign("payload-to-sign", pair.privateKey);
 *   sig.length > 0;
 *   // → true (ML-DSA-87 signature ~ 4627 bytes)
 */
function sign(data, privateKeyPem) {
  assertNotCompromised(privateKeyPem, { label: "crypto.sign: the private key" });
  return nodeCrypto.sign(null, Buffer.from(data), privateKeyPem);
}

/**
 * @primitive b.crypto.verify
 * @signature b.crypto.verify(data, signature, publicKeyPem)
 * @since     0.1.0
 * @related   b.crypto.sign, b.crypto.generateSigningKeyPair
 *
 * Verifies a signature produced by `b.crypto.sign`. Returns `true` on
 * a valid signature, `false` otherwise — never throws on a malformed
 * signature, so operators don't need to wrap the call. Algorithm is
 * auto-detected from the public-key PEM. A signature by a compromised key
 * (`b.crypto.compromisedKey`) returns `false`.
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair();
 *   var sig  = b.crypto.sign("hello", pair.privateKey);
 *   var ok   = b.crypto.verify("hello", sig, pair.publicKey);
 *   // → true
 *
 *   var tampered = b.crypto.verify("HELLO", sig, pair.publicKey);
 *   // → false (data mismatch)
 */
function verify(data, signature, publicKeyPem) {
  if (!nodeCrypto.verify(null, Buffer.from(data), publicKeyPem, signature)) return false;
  return compromisedKey(_publicKeyOf(publicKeyPem)) === null;
}

function _isKeyObjectOrCryptoKey(value) {
  return value instanceof nodeCrypto.KeyObject ||
    (typeof globalThis.CryptoKey === "function" && value instanceof globalThis.CryptoKey);
}

function _unwrapKeyInput(input) {
  if (input && typeof input === "object" && !_isKeyObjectOrCryptoKey(input) && _isKeyObjectOrCryptoKey(input.key)) {
    return input.key;
  }
  return input;
}

function _publicKeyOf(input) {
  input = _unwrapKeyInput(input);
  if (input instanceof nodeCrypto.KeyObject) {
    return input.type === "public" ? input : nodeCrypto.createPublicKey(input);
  }
  if (typeof globalThis.CryptoKey === "function" && input instanceof globalThis.CryptoKey) {
    return _publicKeyOf(nodeCrypto.KeyObject.from(input));
  }
  return nodeCrypto.createPublicKey(input);
}

function _publicKeyOrNull(pem) {
  try { return nodeCrypto.createPublicKey(pem); } catch (_e) { return null; }
}

/**
 * @primitive b.crypto.importPublicJwk
 * @signature b.crypto.importPublicJwk(jwk, opts?)
 * @since     0.15.13
 * @status    stable
 * @related   b.crypto.verify
 *
 * Import a JWK as a public `KeyObject` via
 * `crypto.createPublicKey({ key, format: "jwk" })`, translating the Node
 * import failure into a caller-supplied typed error. Untrusted JWKs reach
 * this from DID documents (`publicKeyJwk`), DNSKEY records, and COSE_Key
 * structures — each module validates the `kty` / `crv` it accepts BEFORE
 * calling, then hands the assembled JWK here for the final import + error
 * translation that was otherwise hand-rolled identically in every one.
 * Centralizing it gives one place to harden untrusted-JWK import.
 *
 * On failure, when `opts.errorClass` is supplied the thrown error is
 * `new opts.errorClass(opts.code, opts.messagePrefix + nodeFailureDetail)`
 * so the operator sees the module's own code + a message naming the
 * source; without it the original Node error propagates unchanged.
 *
 * A key that `b.crypto.compromisedKey` reports is refused: the error is
 * `new opts.errorClass(opts.compromisedCode || opts.code, ...)`, or
 * `CryptoKeyError("crypto/compromised-key")` without `opts.errorClass`. A
 * key `compromisedKey` cannot read throws `crypto/bad-key`.
 *
 * @opts
 *   errorClass:      Function,  // (code, message) error constructor
 *   code:            string,    // error code passed to errorClass
 *   compromisedCode: string,    // code for a compromised key. default: opts.code
 *   messagePrefix:   string,    // text before the Node failure detail. default: ""
 *
 * @example
 *   var b = require("blamejs");
 *
 *   function KeyError(code, message) { this.code = code; this.message = message; }
 *   var key = b.crypto.importPublicJwk(
 *     { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
 *     { errorClass: KeyError, code: "bad-key", messagePrefix: "bad key: " });
 *   // → <KeyObject>  (or throws KeyError("bad-key", "bad key: <detail>"))
 */
function importPublicJwk(jwk, opts) {
  opts = opts || {};
  var key;
  try {
    key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  } catch (e) {
    if (typeof opts.errorClass === "function") {
      throw new opts.errorClass(opts.code, (opts.messagePrefix || "") + ((e && e.message) || e));
    }
    throw e;
  }
  var found = compromisedKey(key);
  if (found !== null) {
    var message = (opts.messagePrefix || "") + "the key is a compromised key: " + found.reason;
    if (typeof opts.errorClass === "function") {
      throw new opts.errorClass(opts.compromisedCode || opts.code, message);
    }
    throw new CryptoKeyError("crypto/compromised-key", message);
  }
  return key;
}

var _CURVE_NAMES = Object.freeze({
  "P-256": "prime256v1", "prime256v1": "prime256v1", "secp256r1": "prime256v1",
  "P-384": "secp384r1",  "secp384r1":  "secp384r1",
  "P-521": "secp521r1",  "secp521r1":  "secp521r1",
});

function _keySpecList(accepted) {
  var list = Array.isArray(accepted) ? accepted : [accepted];
  if (list.length === 0) {
    throw new CryptoKeyError("crypto/bad-key-spec",
      "crypto.assertKeyType: accepted must name at least one key type");
  }
  return list.map(function (spec) {
    if (typeof spec === "string" && spec.length > 0) return { type: spec, curve: null };
    if (spec && typeof spec === "object" && typeof spec.type === "string" && spec.type.length > 0) {
      if (spec.curve === undefined || spec.curve === null) return { type: spec.type, curve: null };
      var curve = typeof spec.curve === "string" &&
        Object.prototype.hasOwnProperty.call(_CURVE_NAMES, spec.curve) ? _CURVE_NAMES[spec.curve] : null;
      if (!curve) {
        throw new CryptoKeyError("crypto/bad-key-spec",
          "crypto.assertKeyType: unknown curve " + JSON.stringify(spec.curve) +
          " (use P-256, P-384 or P-521)");
      }
      return { type: spec.type, curve: curve };
    }
    throw new CryptoKeyError("crypto/bad-key-spec",
      "crypto.assertKeyType: each accepted entry must be a key type string or { type, curve }");
  });
}

function _describeKeySpec(s) { return s.curve ? s.type + " (" + s.curve + ")" : s.type; }

/**
 * @primitive b.crypto.assertKeyType
 * @signature b.crypto.assertKeyType(key, accepted, opts?)
 * @since     0.21.3
 * @status    stable
 * @related   b.crypto.encrypt, b.crypto.decrypt, b.crypto.importPublicJwk
 *
 * Checks that a `KeyObject` is of one of the `accepted` key types and returns
 * it.
 *
 * `accepted` is an `asymmetricKeyType` string (`"ml-kem-1024"`, `"ed25519"`,
 * `"rsa"`), an object `{ type: "ec", curve: "P-384" }` (the curve may also be
 * given by its OpenSSL name, such as `"secp384r1"`), or an array of either.
 * A value that is not a `KeyObject` is refused the same way as a key of the
 * wrong type.
 *
 * Throws `crypto/key-type-mismatch` (a `CryptoKeyError`), or
 * `new opts.errorClass(opts.code, message)` when `opts.errorClass` is given.
 * An empty or malformed `accepted` throws `crypto/bad-key-spec`.
 *
 * @opts
 *   errorClass:  Function,  // (code, message) error constructor
 *   code:        string,    // error code passed to errorClass. default: "crypto/key-type-mismatch"
 *   label:       string,    // names the key in the message. default: "key"
 *
 * @example
 *   var { createPublicKey } = require("node:crypto");
 *   var pair = b.crypto.generateEncryptionKeyPair();
 *   var pub = createPublicKey(pair.ecPublicKey);
 *   b.crypto.assertKeyType(pub, { type: "ec", curve: "P-384" });
 *   // → pub
 *   b.crypto.assertKeyType(pub, "ml-kem-1024");
 *   // → throws CryptoKeyError("crypto/key-type-mismatch", ...)
 */
function assertKeyType(key, accepted, opts) {
  return _checkKeyAgainst(key, _keySpecList(accepted), opts || {});
}

function _checkKeyAgainst(key, specs, opts) {
  var isKey = key instanceof nodeCrypto.KeyObject && typeof key.asymmetricKeyType === "string";
  var gotType = isKey ? key.asymmetricKeyType : null;
  var gotCurve = isKey && key.asymmetricKeyDetails ? (key.asymmetricKeyDetails.namedCurve || null) : null;
  for (var i = 0; i < specs.length; i += 1) {
    if (specs[i].type === gotType && (specs[i].curve === null || specs[i].curve === gotCurve)) return key;
  }
  var got = isKey ? (gotCurve ? gotType + " (" + gotCurve + ")" : gotType) : "a value that is not a KeyObject";
  var message = (opts.label || "key") + " must be " + specs.map(_describeKeySpec).join(" or ") +
    ", got " + got;
  if (typeof opts.errorClass === "function") {
    throw new opts.errorClass(opts.code || "crypto/key-type-mismatch", message);
  }
  throw new CryptoKeyError(opts.code || "crypto/key-type-mismatch", message);
}

function _assertEnvelopeKeyType(pem, kind, specs, label) {
  var key = kind === "private" ? nodeCrypto.createPrivateKey(pem) : nodeCrypto.createPublicKey(pem);
  return _checkKeyAgainst(key, specs, { label: label });
}

var _SMALL_SCALAR_CURVES = Object.freeze({
  "prime256v1": 32, "secp384r1": 48, "secp521r1": 66, "secp256k1": 32,
});
var _smallScalarX = Object.create(null);
var _listedKeys = null;
var _certVerdicts = new Map();
var _textVerdicts = new Map();
var _objectVerdicts = new WeakMap();
var _VERDICT_CACHE_MAX = 4096;                                                   // allow:raw-byte-literal — entry count, not bytes

function _boundedSet(map, k, v) {
  if (map.size >= _VERDICT_CACHE_MAX) map.delete(map.keys().next().value);
  map.set(k, v);
}

function _smallScalarSet(curve) {
  var set = _smallScalarX[curve];
  if (set) return set;
  var width = _SMALL_SCALAR_CURVES[curve];
  set = new Set();
  for (var d = 1; d < 256; d += 1) {                                              // allow:raw-byte-literal — scalar bound, CABF TLS BR 6.1.1.3
    var ecdh = nodeCrypto.createECDH(curve);
    var priv = Buffer.alloc(width);
    priv[width - 1] = d;
    ecdh.setPrivateKey(priv);
    set.add(ecdh.getPublicKey().subarray(1, 1 + width).toString("hex"));
  }
  _smallScalarX[curve] = set;
  return set;
}

function _listedKeyMap() {
  if (_listedKeys) return _listedKeys;
  var m = new Map();
  pki().trust.knownCompromisedKeys().forEach(function (k) { m.set(k.spkiSha256, k); });
  _listedKeys = m;
  return m;
}

function _badKey(detail) {
  return new CryptoKeyError("crypto/bad-key",
    "crypto.compromisedKey: the value could not be read as a public key, private key or certificate" +
    (detail ? " (" + detail + ")" : ""));
}

var _CERTIFICATE_PEM_LABELS = Object.freeze({
  "CERTIFICATE": true, "X509 CERTIFICATE": true, "TRUSTED CERTIFICATE": true,
});

function _pemBlocks(text) {
  var blocks = [];
  var lines = text.replace(/\r\n/g, "\n").split("\n");
  var label = null;
  var body = [];
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i].trim();
    if (label === null) {
      if (line.indexOf("-----BEGIN ") === 0 && line.slice(-5) === "-----") {
        label = line.slice(11, -5);
        body = [];
      }
    } else if (line === "-----END " + label + "-----") {
      blocks.push({ label: label, der: Buffer.from(body.join(""), "base64") });
      label = null;
    } else {
      body.push(line);
    }
  }
  return blocks;
}

function _certificateDer(block) {
  if (block.label !== "TRUSTED CERTIFICATE") return block.der;
  return block.der.subarray(0, asn1.readNode(block.der, 0).totalLength);
}

function _certificatesInPem(text) {
  var out = [];
  _pemBlocks(text).forEach(function (blk) {
    if (_CERTIFICATE_PEM_LABELS[blk.label] !== true) return;
    try { out.push(_certificateDer(blk)); } catch (_e) { /* a block that is not DER holds no certificate */ }
  });
  return out;
}

function _certificateFromDer(der) {
  var b64 = Buffer.from(der).toString("base64");
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return new nodeCrypto.X509Certificate("-----BEGIN CERTIFICATE-----\n" + lines.join("\n") +
    "\n-----END CERTIFICATE-----\n");
}

function _startsAsDer(bytes) {
  return bytes.length > 0 && bytes[0] === 0x30;
}

function _x509(input) {
  if (nodeTypes.isUint8Array(input) && _startsAsDer(input)) return _certificateFromDer(input);
  return new nodeCrypto.X509Certificate(input);
}

function _isDerSequence(node) {
  return node.tag === asn1.TAG.SEQUENCE && node.tagClass === asn1.TAG_CLASS.UNIVERSAL && node.constructed === true;
}

function _derShape(der) {
  try {
    var node = asn1.readNode(der, 0);
    if (!_isDerSequence(node) || node.totalLength !== der.length) return null;
    var kids = asn1.readSequence(node.value);
    if (kids.length === 0 || !_isDerSequence(kids[0])) return null;
    if (kids.length === 3) return "certificate";
    if (kids.length === 2) return "spki";
  } catch (_e) { return null; }
  return null;
}

function _isCertificateObject(key) {
  return key instanceof nodeCrypto.X509Certificate ||
    (!!key && typeof key === "object" && nodeTypes.isUint8Array(key.raw) && typeof key.fingerprint256 === "string");
}

function _readPemText(text, certs, keys) {
  var blocks = _pemBlocks(text);
  var keyBlocks = 0;
  blocks.forEach(function (blk) {
    if (_CERTIFICATE_PEM_LABELS[blk.label] === true) { certs.push(_certificateDer(blk)); return; }
    keyBlocks += 1;
    var single = "-----BEGIN " + blk.label + "-----\n" +
      blk.der.toString("base64") + "\n-----END " + blk.label + "-----\n";
    var blockKey = _publicKeyOrNull(single);
    if (blockKey) keys.push(blockKey);
  });
  if (keyBlocks > 0 || blocks.length === 0) keys.push(nodeCrypto.createPublicKey(text));
}

function _readKeyInputs(key) {
  key = _unwrapKeyInput(key);
  var certs = [];
  var keys = [];
  try {
    if (key instanceof nodeCrypto.KeyObject) {
      if (key.type === "secret") throw _badKey("a secret key has no public half");
      keys.push(key.type === "public" ? key : nodeCrypto.createPublicKey(key));
    } else if (_isCertificateObject(key)) {
      certs.push(Buffer.from(key.raw));
    } else if (typeof globalThis.CryptoKey === "function" && key instanceof globalThis.CryptoKey) {
      var fromCryptoKey = nodeCrypto.KeyObject.from(key);
      if (fromCryptoKey.type === "secret") throw _badKey("a secret key has no public half");
      keys.push(fromCryptoKey.type === "public" ? fromCryptoKey : nodeCrypto.createPublicKey(fromCryptoKey));
    } else if (typeof key === "string") {
      _readPemText(key, certs, keys);
    } else if (nodeTypes.isUint8Array(key)) {
      var der = Buffer.from(key);
      var shape = _derShape(der);
      if (shape === "certificate") certs.push(der);
      else if (shape === null && !_startsAsDer(der) && der.indexOf("-----BEGIN ") !== -1) {
        _readPemText(der.toString("utf8"), certs, keys);
      }
      else keys.push(nodeCrypto.createPublicKey({ key: der, format: "der", type: "spki" }));
    } else if (key && typeof key === "object" && typeof key.kty === "string") {
      keys.push(nodeCrypto.createPublicKey({ key: key, format: "jwk" }));
    } else if (key && typeof key === "object" && key.key !== undefined) {
      keys.push(nodeCrypto.createPublicKey(key));
    }
  } catch (e) {
    if (e instanceof CryptoKeyError) throw e;
    throw _badKey((e && e.message) || String(e));
  }
  if (certs.length === 0 && keys.length === 0) throw _badKey(key === null ? "null" : typeof key);
  return { certs: certs, keys: keys };
}

function _canonicalSpki(publicKey) {
  var type = publicKey.asymmetricKeyType;
  if (type === "ec") {
    var jwk = null;
    try { jwk = publicKey.export({ format: "jwk" }); } catch (_e) { jwk = null; }
    if (jwk) {
      return nodeCrypto.createPublicKey({ format: "jwk", key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } })
        .export({ type: "spki", format: "der" });
    }
  }
  if (type === "rsa-pss") {
    var spki = publicKey.export({ type: "spki", format: "der" });
    var rsaPublicKey = asn1.readBitString(asn1.readSequence(asn1.readNode(spki, 0).value)[1]);
    return nodeCrypto.createPublicKey({ key: rsaPublicKey, format: "der", type: "pkcs1" })
      .export({ type: "spki", format: "der" });
  }
  return publicKey.export({ type: "spki", format: "der" });
}

function _keyVerdict(publicKey) {
  var entry = _listedKeyMap().get(
    nodeCrypto.createHash("sha256").update(_canonicalSpki(publicKey)).digest("hex"));
  if (entry) {
    return Object.freeze({ id: "listed", reason: entry.name + ": " + entry.reason });
  }
  var curve = publicKey.asymmetricKeyType === "ec" && publicKey.asymmetricKeyDetails
    ? publicKey.asymmetricKeyDetails.namedCurve : null;
  if (publicKey.asymmetricKeyType === "ec" && !curve) {
    throw _badKey("an EC key whose explicit curve parameters name no standard curve cannot be checked");
  }
  if (curve && Object.prototype.hasOwnProperty.call(_SMALL_SCALAR_CURVES, curve)) {
    var width = _SMALL_SCALAR_CURVES[curve];
    var x = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
    var xHex = Buffer.concat([Buffer.alloc(Math.max(0, width - x.length)), x]).toString("hex");
    if (_smallScalarSet(curve).has(xHex)) {
      return Object.freeze({
        id: "small-ec-scalar",
        reason: "the " + curve + " private key is within 255 of zero or of the group order, so anyone can " +
          "recover it from the public key",
      });
    }
  }
  return null;
}

var _LINT_LISTED = "lint/key-compromise/known-compromised-key";
var _LINT_SMALL_SCALAR = "lint/key-compromise/small-ec-private-key";

function _lintVerdict(certDer) {
  var report = null;
  try { report = pki().lint.certificate(certDer, { profile: "key-compromise" }); } catch (_e) { report = null; }
  var ran = report && Array.isArray(report.ran) ? report.ran : [];
  if (!report || !Array.isArray(report.findings) || (report.counts && report.counts.fatal > 0) ||
      ran.indexOf(_LINT_LISTED) === -1) {
    return { judged: false, verdict: null };
  }
  for (var i = 0; i < report.findings.length; i += 1) {
    var f = report.findings[i];
    if (f.id === _LINT_LISTED) {
      var entry = null;
      try { entry = _listedKeyMap().get(pki().trust.spkiDigest(certDer)) || null; } catch (_e) { entry = null; }
      return { judged: true, verdict: Object.freeze({ id: "listed", reason: entry ? entry.name + ": " + entry.reason : f.message }) };
    }
    if (f.id === _LINT_SMALL_SCALAR) {
      return { judged: true, verdict: Object.freeze({ id: "small-ec-scalar", reason: f.message }) };
    }
  }
  return { judged: true, verdict: null };
}

function _certVerdict(certDer) {
  var cacheKey = nodeCrypto.createHash("sha256").update(certDer).digest("hex");
  if (_certVerdicts.has(cacheKey)) return _certVerdicts.get(cacheKey);
  var nodeKey = null;
  var nodeError = null;
  try { nodeKey = _certificateFromDer(certDer).publicKey; } catch (e) { nodeError = e; }
  var verdict = nodeKey !== null ? _keyVerdict(nodeKey) : null;
  if (verdict === null) {
    var lint = _lintVerdict(certDer);
    if (lint.verdict !== null) verdict = lint.verdict;
    else if (nodeKey === null && !lint.judged) {
      throw _badKey("node could not load the certificate's key (" + ((nodeError && nodeError.message) || nodeError) +
        ") and the @blamejs/pki key-compromise lint could not read the certificate");
    }
  }
  _boundedSet(_certVerdicts, cacheKey, verdict);
  return verdict;
}

function _isIdentityCacheable(key) {
  return key instanceof nodeCrypto.KeyObject || key instanceof nodeCrypto.X509Certificate ||
    (typeof globalThis.CryptoKey === "function" && key instanceof globalThis.CryptoKey);
}

/**
 * @primitive b.crypto.compromisedKey
 * @signature b.crypto.compromisedKey(key)
 * @since     0.21.4
 * @status    stable
 * @related   b.crypto.assertNotCompromised, b.x509Chain.resolveChain
 *
 * Reports whether anyone can hold the private half of `key`. Returns `null`
 * for an ordinary key, or a frozen `{ id, reason }`:
 *
 * - `"listed"`: the key is one of the compromised keys `@blamejs/pki`
 *   publishes (for example the eMudhra CA keys, Superfish, eDellRoot and the
 *   PKfail platform key). A key matches however it is encoded: an EC key in
 *   compressed or uncompressed form, an RSA key under rsaEncryption or
 *   RSASSA-PSS.
 * - `"small-ec-scalar"`: a P-256, P-384, P-521 or secp256k1 key whose private
 *   scalar is below 256 or within 255 of the group order.
 *
 * `key` is a public or private `KeyObject`, a WebCrypto `CryptoKey`, an
 * `X509Certificate`, PEM text as a string or Buffer, a certificate or
 * SubjectPublicKeyInfo in DER, a public JWK, or a node key-input object such
 * as `{ key: pem }`. PEM text is checked block by block: every certificate
 * (under the `CERTIFICATE`, `X509 CERTIFICATE` or `TRUSTED CERTIFICATE`
 * label) and the key node reads from any key block, and the first compromised
 * one is reported. A Buffer or Uint8Array that is one DER SEQUENCE spanning
 * every byte is read as a certificate (three elements) or a
 * SubjectPublicKeyInfo (two elements), whatever text its fields carry; other
 * bytes are read as PEM text. An object with a Uint8Array `raw` and a string
 * `fingerprint256`, as an `X509Certificate` has, is read as the certificate
 * in `raw`.
 *
 * A certificate is judged by the key node loads from it and by
 * `@blamejs/pki`'s key-compromise lint, and a report from either one is
 * returned. When node cannot load the key (a composite ML-DSA key, for
 * example), the lint judges the certificate alone, and when the lint cannot
 * parse the certificate, node's key judges it alone. A certificate that
 * neither can read, a value that is none of the forms above, or a secret key
 * throws `crypto/bad-key`.
 *
 * The first check of a key on one of the four curves builds a table of 255
 * points for that curve.
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair();
 *   b.crypto.compromisedKey(pair.publicKey);
 *   // → null
 */
function compromisedKey(key) {
  var identity = _isIdentityCacheable(key);
  if (identity && _objectVerdicts.has(key)) return _objectVerdicts.get(key);
  var textKey = null;
  if (typeof key === "string") {
    textKey = "s:" + nodeCrypto.createHash("sha256").update(key, "utf8").digest("hex");
  } else if (nodeTypes.isUint8Array(key)) {
    textKey = "b:" + nodeCrypto.createHash("sha256").update(key).digest("hex");
  }
  if (textKey !== null && _textVerdicts.has(textKey)) return _textVerdicts.get(textKey);
  var read = _readKeyInputs(key);
  var verdict = null;
  for (var k = 0; k < read.keys.length && verdict === null; k += 1) verdict = _keyVerdict(read.keys[k]);
  for (var c = 0; c < read.certs.length && verdict === null; c += 1) verdict = _certVerdict(read.certs[c]);
  if (identity) _objectVerdicts.set(key, verdict);
  else if (textKey !== null) _boundedSet(_textVerdicts, textKey, verdict);
  return verdict;
}

/**
 * @primitive b.crypto.assertNotCompromised
 * @signature b.crypto.assertNotCompromised(key, opts?)
 * @since     0.21.4
 * @status    stable
 * @related   b.crypto.compromisedKey, b.crypto.assertKeyType
 *
 * Returns `key` unchanged when `b.crypto.compromisedKey(key)` is `null`, and
 * throws otherwise. The error is `CryptoKeyError("crypto/compromised-key")`,
 * or `new opts.errorClass(opts.code, message)` when `opts.errorClass` is
 * given. The message names the key with `opts.label` and gives the reason.
 * An unreadable `key` throws `crypto/bad-key` as `compromisedKey` does.
 *
 * @opts
 *   errorClass:  Function,  // (code, message) error constructor
 *   code:        string,    // error code passed to errorClass. default: "crypto/compromised-key"
 *   label:       string,    // names the key in the message. default: "key"
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair();
 *   b.crypto.assertNotCompromised(pair.publicKey, { label: "signing key" });
 *   // → pair.publicKey
 */
function assertNotCompromised(key, opts) {
  opts = opts || {};
  var found = compromisedKey(key);
  if (found === null) return key;
  var message = (opts.label || "key") + " is a compromised key: " + found.reason;
  if (typeof opts.errorClass === "function") {
    throw new opts.errorClass(opts.code || "crypto/compromised-key", message);
  }
  throw new CryptoKeyError(opts.code || "crypto/compromised-key", message);
}

var _KEM_KEY_SPECS_BY_ID = {};
_KEM_KEY_SPECS_BY_ID[C.KEM_IDS.ML_KEM_1024]       = _keySpecList("ml-kem-1024");
_KEM_KEY_SPECS_BY_ID[C.KEM_IDS.ML_KEM_1024_P384]  = _keySpecList("ml-kem-1024");
_KEM_KEY_SPECS_BY_ID[C.KEM_IDS.ML_KEM_768_X25519] = _keySpecList("ml-kem-768");
var _P384 = _keySpecList({ type: "ec", curve: "P-384" });
var _X25519 = _keySpecList("x25519");

var _hybridDisabledAuditEmitted = false;

/**
 * @primitive b.crypto.encrypt
 * @signature b.crypto.encrypt(plaintext, publicKeys)
 * @since     0.1.0
 * @related   b.crypto.decrypt, b.crypto.generateEncryptionKeyPair, b.crypto.encryptMlkem768X25519
 *
 * Seals `plaintext` into a base64 envelope under the recipient's
 * keypair. Default suite is ML-KEM-1024 + ECDH P-384 hybrid (FIPS 203
 * KEM with classical defense-in-depth) plus SHAKE256 KDF and
 * XChaCha20-Poly1305 AEAD. The 4-byte envelope header (magic + KEM
 * ID + cipher ID + KDF ID) is bound as AEAD AAD so an algorithm-
 * substitution attack on the header fails Poly1305 verification.
 * Pass `{ publicKey, ecPublicKey }` for the hybrid path; passing only
 * an ML-KEM PEM falls back to KEM-only and emits a one-shot
 * `system.crypto.hybrid_disabled` audit (operators wanting the silent
 * KEM-only path call `encryptMlkem768X25519` or seal manually).
 * A `publicKey` that is not an ML-KEM-1024 key, or an `ecPublicKey`
 * that is not a P-384 key, throws `crypto/key-type-mismatch`.
 *
 * @example
 *   var pair = b.crypto.generateEncryptionKeyPair();
 *   var sealed = b.crypto.encrypt("PHI: patient-42 dx=...", {
 *     publicKey:    pair.publicKey,
 *     ecPublicKey:  pair.ecPublicKey,
 *   });
 *   typeof sealed;
 *   // → "string" (base64 envelope)
 *
 *   var plain = b.crypto.decrypt(sealed, {
 *     privateKey:    pair.privateKey,
 *     ecPrivateKey:  pair.ecPrivateKey,
 *   });
 *   // → "PHI: patient-42 dx=..."
 */
function encrypt(plaintext, publicKeys) {
  var mlkemPubPem = typeof publicKeys === "string" ? publicKeys : publicKeys.publicKey;
  var ecPubPem = typeof publicKeys === "string" ? null : publicKeys.ecPublicKey;
  if (!ecPubPem) {
    if (!_hybridDisabledAuditEmitted) {
      _hybridDisabledAuditEmitted = true;
      setImmediate(function () {
        try {
          audit().safeEmit({
            action:   "system.crypto.hybrid_disabled",
            outcome:  "success",
            metadata: { reason: "no-ec-public-key", note: "encrypt() received only mlkem; ecPublicKey absent — call encryptMlkemOnly explicitly to silence (audited once per process)" },
          });
        } catch (_e) { /* drop-silent — best-effort */ }
      });
    }
    return encryptMlkemOnly(plaintext, mlkemPubPem);
  }

  var mlkemPub = _assertEnvelopeKeyType(mlkemPubPem, "public", _KEM_KEY_SPECS_BY_ID[C.ACTIVE.KEM],
    "crypto.encrypt: publicKey");
  var ecPub = _assertEnvelopeKeyType(ecPubPem, "public", _P384, "crypto.encrypt: ecPublicKey");
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var ephEc = generateKeyPair("ec", {
    namedCurve: "P-384",
    publicKeyEncoding:  { type: "spki",  format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var ecSs = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(ephEc.privateKey),
    publicKey:  ecPub,
  });
  var key = kdf(Buffer.concat([kem.sharedKey, ecSs,
    _suiteFixedInfo(C.ACTIVE.KEM, C.ACTIVE.CIPHER, C.ACTIVE.KDF)]),
    C.BYTES.bytes(32));
  var nonce = generateBytes(C.BYTES.bytes(24));
  var headerAad = Buffer.from([C.ENVELOPE_MAGIC, C.ACTIVE.KEM, C.ACTIVE.CIPHER, C.ACTIVE.KDF]);
  var ct = xchacha20poly1305(key, nonce, headerAad).encrypt(Buffer.from(plaintext, "utf8"));

  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  var ecEphDer = ephEc.publicKey;
  var ecEphLen = Buffer.alloc(2); ecEphLen.writeUInt16BE(ecEphDer.length);

  return Buffer.concat([
    headerAad,
    kemCtLen, kem.ciphertext, ecEphLen, ecEphDer, nonce, Buffer.from(ct),
  ]).toString("base64");
}

function encryptMlkemOnly(plaintext, publicKeyPem) {
  var mlkemPub = _assertEnvelopeKeyType(publicKeyPem, "public",
    _KEM_KEY_SPECS_BY_ID[C.KEM_IDS.ML_KEM_1024], "crypto.encrypt: publicKey");
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var key = kdf(Buffer.concat([kem.sharedKey,
    _suiteFixedInfo(C.KEM_IDS.ML_KEM_1024, C.ACTIVE.CIPHER, C.ACTIVE.KDF)]),
    C.BYTES.bytes(32));
  var nonce = generateBytes(C.BYTES.bytes(24));
  var headerAad = Buffer.from([C.ENVELOPE_MAGIC, C.KEM_IDS.ML_KEM_1024,
    C.ACTIVE.CIPHER, C.ACTIVE.KDF]);
  var ct = xchacha20poly1305(key, nonce, headerAad).encrypt(Buffer.from(plaintext, "utf8"));
  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  return Buffer.concat([
    headerAad,
    kemCtLen, kem.ciphertext, nonce, Buffer.from(ct),
  ]).toString("base64");
}

/**
 * @primitive b.crypto.decrypt
 * @signature b.crypto.decrypt(ciphertext, privateKeys, opts?)
 * @since     0.1.0
 * @related   b.crypto.encrypt, b.crypto.generateEncryptionKeyPair, b.crypto.decryptMlkem768X25519
 *
 * Opens a base64 envelope produced by `b.crypto.encrypt`. The
 * envelope header is parsed first and the decrypt path dispatches by
 * KEM ID — ML-KEM-1024 + P-384, ML-KEM-1024 KEM-only, or ML-KEM-768 +
 * X25519 — so old envelopes continue to decrypt under whichever suite
 * sealed them while new writes use the active suite. Throws on
 * malformed magic, unsupported cipher / KDF, or Poly1305 tag failure.
 * Pass `{ privateKey, ecPrivateKey }` for the default hybrid; the
 * ML-KEM-768 + X25519 KEM ID also requires `x25519PrivateKey`.
 * The `privateKey` must be an ML-KEM-1024 key for the first two KEM IDs
 * and an ML-KEM-768 key for the third, `ecPrivateKey` a P-384 key and
 * `x25519PrivateKey` an X25519 key; any other key type throws
 * `crypto/key-type-mismatch` before the KEM runs.
 *
 * ## Legacy 0xE1 envelopes (`opts.allowLegacy: true`)
 *
 * The framework's envelope magic byte was bumped from 0xE1 to 0xE2
 * pre-v1 to enforce a NIST SP 800-56C r2 §4.1 FixedInfo / RFC 9180
 * §5.1 suite-binding KDF input — SHAKE256 absorbs the suite-id triple
 * (kemId / cipherId / kdfId) plus the literal "blamejs/v1" label
 * alongside the shared secret(s), so the same key cannot be reused
 * across suites without distinct derived material. 0xE1 envelopes
 * lack this binding.
 *
 * By default 0xE1 envelopes are refused with a hard error directing
 * the operator to re-seal under 0xE2. Operators with at-rest data
 * sealed pre-bump (rare; the bump landed before any operator started
 * depending on the framework) pass `opts.allowLegacy: true` to read
 * the old envelope, then immediately re-seal via `b.crypto.encrypt`
 * to migrate. Each legacy decrypt emits a `crypto.decrypt.allow_legacy`
 * audit event so the migration window is visible in the audit log.
 *
 * @opts
 *   allowLegacy:  boolean   // default false — when true, 0xE1 envelopes
 *                            // decrypt via the pre-FixedInfo KDF path
 *
 * @example
 *   var pair = b.crypto.generateEncryptionKeyPair();
 *   var sealed = b.crypto.encrypt("session-token=abc123", {
 *     publicKey:    pair.publicKey,
 *     ecPublicKey:  pair.ecPublicKey,
 *   });
 *   var opened = b.crypto.decrypt(sealed, {
 *     privateKey:    pair.privateKey,
 *     ecPrivateKey:  pair.ecPrivateKey,
 *   });
 *   // → "session-token=abc123"
 *
 *   // Legacy 0xE1 migration:
 *   var plaintext = b.crypto.decrypt(legacyBlob, oldKeys, { allowLegacy: true });
 *   var resealed  = b.crypto.encrypt(plaintext, newKeys);   // now 0xE2
 */
function decrypt(ciphertext, privateKeys, opts) {
  opts = opts || {};
  validateOpts.optionalBoolean(opts.allowLegacy,
    "crypto.decrypt: opts.allowLegacy (anything other than a boolean was read for its " +
    "truthiness, so the legacy envelope was read without the caller opting in to it)");
  var packed = Buffer.from(ciphertext, "base64");
  if (packed[0] === 0xE1) {
    if (!opts || !opts.allowLegacy) {
      throw new Error("Invalid envelope: legacy 0xE1 format predates the FixedInfo " +
        "KDF binding (NIST SP 800-56C r2 §4.1) — re-seal data under the current envelope, " +
        "or pass { allowLegacy: true } to opt in to one-shot read for migration");
    }
    function _emitLegacyAudit(outcome, extra) {
      setImmediate(function () {
        try {
          audit().safeEmit({
            action:   "system.crypto.decrypt.allow_legacy",
            outcome:  outcome,
            metadata: Object.assign({ magic: "0xE1", kemId: packed[1] }, extra || {}),
          });
        } catch (_e) { /* drop-silent — audit best-effort */ }
      });
    }
    var plaintext;
    try {
      plaintext = decryptEnvelope(packed, privateKeys, { omitFixedInfo: true });
    } catch (e) {
      _emitLegacyAudit("failure", { reason: (e && e.message) || "decrypt threw" });
      throw e;
    }
    _emitLegacyAudit("success", {});
    return plaintext;
  }
  if (packed[0] !== C.ENVELOPE_MAGIC) {
    throw new Error("Invalid envelope: unsupported format");
  }
  return decryptEnvelope(packed, privateKeys,
    opts && opts.raw === true ? { raw: true } : undefined);
}

function _envU16(buf, at) {
  if (at + 2 > buf.length) {
    throw new Error("Invalid envelope: truncated (expected a 2-byte length at offset " + at + ")");
  }
  return buf.readUInt16BE(at);
}

function _envSlice(buf, at, label) {
  var len = _envU16(buf, at);
  at += 2;
  if (at + len > buf.length) {
    throw new Error("Invalid envelope: truncated (declared " + len + "-byte " +
      label + " at offset " + at + " exceeds the " + buf.length + "-byte envelope)");
  }
  return { bytes: buf.subarray(at, at + len), pos: at + len };
}

function decryptEnvelope(packed, privateKeys, internalOpts) {
  if (!Buffer.isBuffer(packed) || packed.length < 4) {
    throw new Error("Invalid envelope: too short (need at least the 4-byte suite header)");
  }
  var kemId = packed[1], cipherId = packed[2], kdfId = packed[3], pos = 4;

  var omitFixedInfo = !!(internalOpts && internalOpts.omitFixedInfo);

  if (cipherId !== C.CIPHER_IDS.XCHACHA20_POLY1305) {
    throw new Error("Invalid envelope: unsupported cipher (only XChaCha20-Poly1305 supported)");
  }
  if (kdfId !== C.KDF_IDS.SHAKE256) {
    throw new Error("Invalid envelope: unsupported KDF (only SHAKE256 supported)");
  }

  var kemSlice = _envSlice(packed, pos, "KEM ciphertext");
  var kemCt = kemSlice.bytes; pos = kemSlice.pos;

  var kemKeyType = Object.prototype.hasOwnProperty.call(_KEM_KEY_SPECS_BY_ID, kemId)
    ? _KEM_KEY_SPECS_BY_ID[kemId] : null;
  if (kemKeyType === null) {
    throw new Error("Invalid envelope: unsupported KEM ID " + kemId);
  }
  var mlkemPriv = _assertEnvelopeKeyType(
    typeof privateKeys === "string" ? privateKeys : privateKeys.privateKey,
    "private", kemKeyType, "crypto.decrypt: privateKey");
  var mlkemSs = nodeCrypto.decapsulate(mlkemPriv, kemCt);
  var symmetricKey;
  var fixedInfo = omitFixedInfo ? Buffer.alloc(0) : _suiteFixedInfo(kemId, cipherId, kdfId);

  if (kemId === C.KEM_IDS.ML_KEM_1024_P384) {
    var ecEphSlice = _envSlice(packed, pos, "EC ephemeral public key");
    var ecEphDer = ecEphSlice.bytes; pos = ecEphSlice.pos;
    var ecPrivPem = typeof privateKeys === "string" ? null : privateKeys.ecPrivateKey;
    if (!ecPrivPem) throw new Error("Hybrid KEM requires EC private key");
    var ecSs = nodeCrypto.diffieHellman({
      privateKey: _assertEnvelopeKeyType(ecPrivPem, "private", _P384, "crypto.decrypt: ecPrivateKey"),
      publicKey:  nodeCrypto.createPublicKey({ key: ecEphDer, type: "spki", format: "der" }),
    });
    symmetricKey = kdf(Buffer.concat([mlkemSs, ecSs, fixedInfo]), C.BYTES.bytes(32));
  } else if (kemId === C.KEM_IDS.ML_KEM_1024) {
    symmetricKey = kdf(Buffer.concat([mlkemSs, fixedInfo]), C.BYTES.bytes(32));
  } else if (kemId === C.KEM_IDS.ML_KEM_768_X25519) {
    var x25519EphSlice = _envSlice(packed, pos, "X25519 ephemeral public key");
    var x25519EphDer = x25519EphSlice.bytes; pos = x25519EphSlice.pos;
    var x25519PrivPem = typeof privateKeys === "string" ? null : privateKeys.x25519PrivateKey;
    if (!x25519PrivPem) throw new Error("ML-KEM-768 + X25519 hybrid envelope requires x25519PrivateKey");
    var x25519Ss = nodeCrypto.diffieHellman({
      privateKey: _assertEnvelopeKeyType(x25519PrivPem, "private", _X25519,
        "crypto.decrypt: x25519PrivateKey"),
      publicKey:  nodeCrypto.createPublicKey({ key: x25519EphDer, type: "spki", format: "der" }),
    });
    symmetricKey = kdf(Buffer.concat([mlkemSs, x25519Ss, fixedInfo]), C.BYTES.bytes(32));
  } else {
    throw new Error("Invalid envelope: unsupported KEM ID " + kemId);
  }

  var nonceLen = C.BYTES.bytes(24);
  var tagLen = C.BYTES.bytes(16);
  if (pos + nonceLen + tagLen > packed.length) {
    throw new Error("Invalid envelope: truncated (expected a " + nonceLen +
      "-byte nonce and a " + tagLen + "-byte authentication tag at offset " + pos + ")");
  }
  var nonce = packed.subarray(pos, pos + nonceLen); pos += nonceLen;
  var headerAad = packed.subarray(0, 4);
  var plainBuf = Buffer.from(
    xchacha20poly1305(symmetricKey, nonce, headerAad).decrypt(packed.subarray(pos))
  );
  if (internalOpts && internalOpts.raw === true) return plainBuf;
  return plainBuf.toString("utf8");
}

/**
 * @primitive b.crypto.encryptPacked
 * @signature b.crypto.encryptPacked(buffer, key, aad)
 * @since     0.1.0
 * @related   b.crypto.decryptPacked, b.crypto.encrypt
 *
 * Symmetric (key-already-known) authenticated encryption. Returns a
 * self-describing Buffer: 1-byte format ID + 24-byte XChaCha20-
 * Poly1305 nonce + ciphertext+tag. Operators who already hold a
 * symmetric key (sealed-storage cell encryption, break-glass row
 * encryption) reach for this instead of the envelope variants. The
 * optional `aad` (additional authenticated data) is mixed into the
 * Poly1305 tag; encrypt-time and decrypt-time AAD must match exactly
 * or decryption fails. Wire it for context-binding (e.g. `(table,
 * rowId, column)` so a ciphertext from row A literally cannot decrypt
 * as row B even with the same key).
 *
 * @example
 *   var key  = b.crypto.generateBytes(32);
 *   var data = Buffer.from("row-42 column-ssn", "utf8");
 *   var aad  = Buffer.from("patients|42|ssn", "utf8");
 *   var packed = b.crypto.encryptPacked(data, key, aad);
 *   var plain  = b.crypto.decryptPacked(packed, key, aad);
 *   plain.toString("utf8");
 *   // → "row-42 column-ssn"
 */
function encryptPacked(buffer, key, aad) {
  var nonce = random(C.BYTES.bytes(24));
  var ct = xchacha20poly1305(key, nonce, aad ? Buffer.from(aad) : undefined).encrypt(buffer);
  return Buffer.concat([
    Buffer.from([C.FORMAT.XCHACHA20_POLY1305]),
    Buffer.from(nonce),
    Buffer.from(ct),
  ]);
}

/**
 * @primitive b.crypto.decryptPacked
 * @signature b.crypto.decryptPacked(packed, key, aad)
 * @since     0.1.0
 * @related   b.crypto.encryptPacked
 *
 * Inverse of `encryptPacked`. Reads the 1-byte format ID, extracts
 * the 24-byte XChaCha20-Poly1305 nonce, and decrypts the trailing
 * ciphertext under `key` + `aad`. Throws on unsupported format byte
 * or AAD / tag mismatch — operators wrap when a graceful per-cell
 * fallback is required.
 *
 * @example
 *   var key  = b.crypto.generateBytes(32);
 *   var aad  = Buffer.from("audit|2026-05-08", "utf8");
 *   var pkt  = b.crypto.encryptPacked(Buffer.from("hello", "utf8"), key, aad);
 *   var open = b.crypto.decryptPacked(pkt, key, aad);
 *   open.toString("utf8");
 *   // → "hello"
 */
function decryptPacked(packed, key, aad) {
  if (packed[0] !== C.FORMAT.XCHACHA20_POLY1305) {
    throw new Error("Invalid packed format: unsupported version");
  }
  if (packed.length < 1 + C.BYTES.bytes(24) + C.BYTES.bytes(16)) {
    throw new Error("Invalid packed format: truncated (need at least a 1-byte " +
      "version, a 24-byte nonce, and a 16-byte authentication tag)");
  }
  return Buffer.from(
    xchacha20poly1305(key, packed.subarray(1, 25), aad ? Buffer.from(aad) : undefined)
      .decrypt(packed.subarray(25))
  );
}

/**
 * @primitive b.crypto.generateMlkem768X25519KeyPair
 * @signature b.crypto.generateMlkem768X25519KeyPair()
 * @since     0.7.28
 * @related   b.crypto.encryptMlkem768X25519, b.crypto.decryptMlkem768X25519, b.crypto.generateEncryptionKeyPair
 *
 * Generates the IETF / Cloudflare / Chrome TLS 1.3 hybrid keypair
 * (codepoint 0x11EC): ML-KEM-768 (FIPS 203) + X25519 (RFC 7748).
 * Smaller payload than ML-KEM-1024 + P-384 (~1.1 KB vs ~1.6 KB) and
 * wider interop with peers using the same hybrid (Cloudflare
 * Workers, Chrome, browsers offering hybrid PQ key share). Returns
 * `{ mlkemPublicKey, mlkemPrivateKey, x25519PublicKey,
 * x25519PrivateKey }`.
 *
 * @example
 *   var pair = b.crypto.generateMlkem768X25519KeyPair();
 *   var sealed = b.crypto.encryptMlkem768X25519("interop payload", {
 *     mlkemPublicKey:   pair.mlkemPublicKey,
 *     x25519PublicKey:  pair.x25519PublicKey,
 *   });
 *   var plain = b.crypto.decryptMlkem768X25519(sealed, {
 *     privateKey:       pair.mlkemPrivateKey,
 *     x25519PrivateKey: pair.x25519PrivateKey,
 *   });
 *   // → "interop payload"
 */
function generateMlkem768X25519KeyPair() {
  var mlkem = generateKeyPair("ml-kem-768");
  var x25519 = generateKeyPair("x25519");
  return {
    mlkemPublicKey:    mlkem.publicKey,
    mlkemPrivateKey:   mlkem.privateKey,
    x25519PublicKey:   x25519.publicKey,
    x25519PrivateKey:  x25519.privateKey,
  };
}

/**
 * @primitive b.crypto.encryptMlkem768X25519
 * @signature b.crypto.encryptMlkem768X25519(plaintext, recipient)
 * @since     0.7.28
 * @related   b.crypto.decryptMlkem768X25519, b.crypto.encrypt, b.crypto.generateMlkem768X25519KeyPair
 *
 * Seals `plaintext` under the IETF / Cloudflare / Chrome TLS 1.3
 * hybrid (ML-KEM-768 + X25519). Recipient shape is
 * `{ mlkemPublicKey, x25519PublicKey }` — both PEMs. Same envelope
 * wire format as the default hybrid; the KEM ID byte is
 * `KEM_IDS.ML_KEM_768_X25519` so `b.crypto.decrypt` dispatches
 * correctly on the receive side. Reach for this when the recipient
 * publishes ML-KEM-768 + X25519 keys (TLS-1.3 codepoint 0x11EC peers,
 * cross-stack interop with Cloudflare Workers or Chrome-side WebCrypto).
 * An `mlkemPublicKey` that is not an ML-KEM-768 key, or an
 * `x25519PublicKey` that is not an X25519 key, throws
 * `crypto/key-type-mismatch`.
 *
 * @example
 *   var pair = b.crypto.generateMlkem768X25519KeyPair();
 *   var sealed = b.crypto.encryptMlkem768X25519("cross-stack message", {
 *     mlkemPublicKey:   pair.mlkemPublicKey,
 *     x25519PublicKey:  pair.x25519PublicKey,
 *   });
 *   typeof sealed;
 *   // → "string" (base64 envelope, ~1.1 KB for short plaintexts)
 */
function encryptMlkem768X25519(plaintext, recipient) {
  if (!recipient || !recipient.mlkemPublicKey || !recipient.x25519PublicKey) {
    throw new Error("encryptMlkem768X25519 requires { mlkemPublicKey, x25519PublicKey }");
  }
  var mlkemPub = _assertEnvelopeKeyType(recipient.mlkemPublicKey, "public",
    _KEM_KEY_SPECS_BY_ID[C.KEM_IDS.ML_KEM_768_X25519], "crypto.encryptMlkem768X25519: mlkemPublicKey");
  var x25519Pub = _assertEnvelopeKeyType(recipient.x25519PublicKey, "public", _X25519,
    "crypto.encryptMlkem768X25519: x25519PublicKey");
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var ephX25519 = generateKeyPair("x25519", {
    publicKeyEncoding:  { type: "spki",  format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var x25519Ss = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(ephX25519.privateKey),
    publicKey:  x25519Pub,
  });
  var key = kdf(Buffer.concat([kem.sharedKey, x25519Ss,
    _suiteFixedInfo(C.KEM_IDS.ML_KEM_768_X25519, C.ACTIVE.CIPHER, C.ACTIVE.KDF)]),
    C.BYTES.bytes(32));
  var nonce = generateBytes(C.BYTES.bytes(24));
  var headerAad = Buffer.from([C.ENVELOPE_MAGIC, C.KEM_IDS.ML_KEM_768_X25519,
    C.ACTIVE.CIPHER, C.ACTIVE.KDF]);
  var ct = xchacha20poly1305(key, nonce, headerAad).encrypt(Buffer.from(plaintext, "utf8"));

  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  var x25519EphDer = ephX25519.publicKey;
  var x25519EphLen = Buffer.alloc(2); x25519EphLen.writeUInt16BE(x25519EphDer.length);

  return Buffer.concat([
    headerAad,
    kemCtLen, kem.ciphertext, x25519EphLen, x25519EphDer, nonce, Buffer.from(ct),
  ]).toString("base64");
}

/**
 * @primitive b.crypto.decryptMlkem768X25519
 * @signature b.crypto.decryptMlkem768X25519(ciphertext, recipient)
 * @since     0.7.28
 * @related   b.crypto.encryptMlkem768X25519, b.crypto.decrypt
 *
 * Symmetric named-pair to `encryptMlkem768X25519`. Rejects any
 * envelope whose KEM ID byte is not `ML_KEM_768_X25519` so an
 * operator who calls this with a ciphertext sealed under a different
 * algorithm gets a clear error rather than the generic dispatch path.
 * The recipient carries two private keys: `privateKey`, which is the
 * ML-KEM-768 PEM and NOT the framework default ML-KEM-1024, and
 * `x25519PrivateKey`, which is the X25519 PEM. A `privateKey` that is not
 * an ML-KEM-768 key, or an `x25519PrivateKey` that is not an X25519 key,
 * throws `crypto/key-type-mismatch`.
 *
 * @example
 *   var pair = b.crypto.generateMlkem768X25519KeyPair();
 *   var sealed = b.crypto.encryptMlkem768X25519("interop", {
 *     mlkemPublicKey:   pair.mlkemPublicKey,
 *     x25519PublicKey:  pair.x25519PublicKey,
 *   });
 *   var plain = b.crypto.decryptMlkem768X25519(sealed, {
 *     privateKey:       pair.mlkemPrivateKey,
 *     x25519PrivateKey: pair.x25519PrivateKey,
 *   });
 *   // → "interop"
 */
function decryptMlkem768X25519(ciphertext, recipient) {
  if (!recipient || typeof recipient !== "object" ||
      !recipient.privateKey || !recipient.x25519PrivateKey) {
    throw new Error("decryptMlkem768X25519 requires both a privateKey, which is the " +
                    "ML-KEM-768 PEM, and an x25519PrivateKey, which is the X25519 PEM");
  }
  var packed = Buffer.from(ciphertext, "base64");
  if (packed[0] !== C.ENVELOPE_MAGIC) {
    throw new Error("decryptMlkem768X25519: invalid envelope (bad magic byte)");
  }
  if (packed[1] !== C.KEM_IDS.ML_KEM_768_X25519) {
    throw new Error("decryptMlkem768X25519: envelope KEM ID is " + packed[1] +
                    ", expected " + C.KEM_IDS.ML_KEM_768_X25519 +
                    " (ML_KEM_768_X25519). Use b.crypto.decrypt for KEM-id dispatch.");
  }
  return decryptEnvelope(packed, recipient);
}

function _extractEcdhP384FromCert(certDer) {
  var cert = _x509(certDer);
  var keyObj = cert.publicKey;
  var details = keyObj.asymmetricKeyDetails || {};
  if (keyObj.asymmetricKeyType !== "ec" ||
      details.namedCurve !== "secp384r1") {
    var err = new Error(
      "cert public key is not ECDH P-384 (got asymmetricKeyType=" +
      keyObj.asymmetricKeyType + ", namedCurve=" + details.namedCurve + ")");
    err.code = "crypto/cert-key-not-ecdh-p384";
    throw err;
  }
  return keyObj.export({ type: "spki", format: "pem" });
}

/**
 * @primitive b.crypto.encryptEnvelopeAsCertPeer
 * @signature b.crypto.encryptEnvelopeAsCertPeer(plaintext, opts)
 * @since     0.7.0
 * @related   b.crypto.decryptEnvelopeAsCertPeer, b.crypto.encrypt
 *
 * Produces an envelope sealed to a peer identified by their TLS cert
 * (P-384 ECDH half) plus a peer-supplied ML-KEM-1024 pubkey. The wire
 * format is identical to `b.crypto.encrypt`; only the input keys
 * differ. Use for sealed-storage records with peer recipients,
 * cross-service messages between cert-identified peers without a
 * shared framework keypair, or audit-log entries tagged with peer
 * recipients. The cert must carry an ECDH P-384 SubjectPublicKeyInfo;
 * any other key throws `crypto/cert-key-not-ecdh-p384`. A
 * `peerKemPubkey` that is not an ML-KEM-1024 public key throws
 * `crypto/key-type-mismatch`.
 *
 * @opts
 *   peerCertDer:    Buffer,   // peer's TLS cert as DER bytes (Buffer or Uint8Array)
 *   peerKemPubkey:  string,   // peer's ML-KEM-1024 pubkey PEM (non-empty string)
 *
 * @example
 *   var fs = require("fs");
 *   var peerCertDer   = fs.readFileSync("/etc/ssl/peer.cert.der");
 *   var peerKemPubkey = fs.readFileSync("/etc/ssl/peer.mlkem.pem", "utf8");
 *   var sealed = b.crypto.encryptEnvelopeAsCertPeer("cross-peer payload", {
 *     peerCertDer:    peerCertDer,
 *     peerKemPubkey:  peerKemPubkey,
 *   });
 *   typeof sealed;
 *   // → "string" (base64 envelope)
 */
function encryptEnvelopeAsCertPeer(plaintext, opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("encryptEnvelopeAsCertPeer: opts object required");
  }
  if (!opts.peerCertDer) {
    var e1 = new Error("peerCertDer required (peer's TLS cert as DER bytes)");
    e1.code = "crypto/peer-cert-missing";
    throw e1;
  }
  if (typeof opts.peerKemPubkey !== "string") {
    var e2 = new Error("peerKemPubkey required (peer's ML-KEM-1024 pubkey PEM)");
    e2.code = "crypto/peer-kem-pubkey-missing";
    throw e2;
  }
  if (opts.peerKemPubkey.length === 0) {
    var e2b = new Error("peerKemPubkey is empty");
    e2b.code = "crypto/peer-kem-pubkey-missing";
    throw e2b;
  }
  var ecPubPem = _extractEcdhP384FromCert(opts.peerCertDer);
  return encrypt(plaintext, {
    publicKey:   opts.peerKemPubkey,
    ecPublicKey: ecPubPem,
  });
}

/**
 * @primitive b.crypto.decryptEnvelopeAsCertPeer
 * @signature b.crypto.decryptEnvelopeAsCertPeer(envelope, opts)
 * @since     0.7.0
 * @related   b.crypto.encryptEnvelopeAsCertPeer, b.crypto.decrypt
 *
 * Decrypts an envelope sealed to this operator's TLS cert ECDH-pubkey
 * + ML-KEM-1024 pubkey. `certPrivateKey` accepts either a node:crypto
 * `KeyObject` (ECDH P-384, namedCurve secp384r1) or its PEM-encoded
 * pkcs8 string; `kemSecret` is always the ML-KEM-1024 PEM. A non-
 * P-384 cert key throws `crypto/cert-key-not-ecdh-p384`. A `kemSecret`
 * that is not an ML-KEM-1024 private key, or a PEM `certPrivateKey` that
 * is not a P-384 key, throws `crypto/key-type-mismatch`. Mirror of
 * `encryptEnvelopeAsCertPeer` for the receive side.
 *
 * @opts
 *   certPrivateKey: object,   // KeyObject or PEM string — ECDH P-384 priv (secp384r1)
 *   kemSecret:      string,   // operator's ML-KEM-1024 priv PEM (non-empty)
 *
 * @example
 *   var fs = require("fs");
 *   var ourCertPriv  = fs.readFileSync("/etc/ssl/our.cert.key.pem", "utf8");
 *   var ourKemSecret = fs.readFileSync("/etc/ssl/our.mlkem.priv.pem", "utf8");
 *   var sealed = "AaECA..."; // base64 envelope received from peer
 *   var plain = b.crypto.decryptEnvelopeAsCertPeer(sealed, {
 *     certPrivateKey: ourCertPriv,
 *     kemSecret:      ourKemSecret,
 *   });
 *   typeof plain;
 *   // → "string"
 */
function decryptEnvelopeAsCertPeer(envelope, opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("decryptEnvelopeAsCertPeer: opts object required");
  }
  if (!opts.certPrivateKey) {
    var e1 = new Error("certPrivateKey required");
    e1.code = "crypto/cert-private-key-missing";
    throw e1;
  }
  if (typeof opts.kemSecret !== "string") {
    var e2 = new Error("kemSecret required (operator's ML-KEM-1024 priv PEM)");
    e2.code = "crypto/kem-secret-missing";
    throw e2;
  }
  if (opts.kemSecret.length === 0) {
    var e2b = new Error("kemSecret is empty");
    e2b.code = "crypto/kem-secret-missing";
    throw e2b;
  }
  var ecPrivPem;
  if (typeof opts.certPrivateKey === "string") {
    ecPrivPem = opts.certPrivateKey;
  } else if (typeof opts.certPrivateKey.export === "function") {
    var details = opts.certPrivateKey.asymmetricKeyDetails || {};
    if (opts.certPrivateKey.asymmetricKeyType !== "ec" ||
        details.namedCurve !== "secp384r1") {
      var e3 = new Error(
        "certPrivateKey is not ECDH P-384 (got asymmetricKeyType=" +
        opts.certPrivateKey.asymmetricKeyType + ", namedCurve=" +
        details.namedCurve + ")");
      e3.code = "crypto/cert-key-not-ecdh-p384";
      throw e3;
    }
    ecPrivPem = opts.certPrivateKey.export({ type: "pkcs8", format: "pem" });
  } else {
    var e4 = new Error("certPrivateKey must be a KeyObject or PEM string");
    e4.code = "crypto/cert-private-key-bad-shape";
    throw e4;
  }
  return decrypt(envelope, {
    privateKey:   opts.kemSecret,
    ecPrivateKey: ecPrivPem,
  });
}

function _pemToDer(pemOrDer) {
  if (Buffer.isBuffer(pemOrDer)) return pemOrDer;
  if (typeof pemOrDer !== "string") {
    throw new TypeError("crypto.hashCertFingerprint: input must be a Buffer (DER) or a PEM-encoded string");
  }
  if (safeBuffer().byteLengthOf(pemOrDer) > C.BYTES.kib(64)) {
    throw new TypeError(
      "crypto.hashCertFingerprint: PEM input exceeds 64 KiB (" +
      pemOrDer.length + " bytes); refuse oversized input to avoid " +
      "polynomial-ReDoS on the BEGIN/END marker regex"
    );
  }
  var match = pemOrDer.match(/-----BEGIN [A-Z0-9 ]+-----([\s\S]+?)-----END [A-Z0-9 ]+-----/);
  if (!match) {
    throw new TypeError("crypto.hashCertFingerprint: PEM input lacks BEGIN/END markers");
  }
  return Buffer.from(match[1].replace(/\s+/g, ""), "base64");
}
/**
 * @primitive b.crypto.hashCertFingerprint
 * @signature b.crypto.hashCertFingerprint(pemOrDer)
 * @since     0.7.0
 * @related   b.crypto.isCertRevoked, b.crypto.sha3Hash
 *
 * Computes a stable SHA3-512 fingerprint of an X.509 certificate.
 * Accepts either DER bytes (Buffer) or a PEM string (BEGIN/END
 * envelope is stripped, base64 body decoded). Returns
 * `{ hex, colon }` so callers can compare against either rendering
 * style — lowercase hex (concise, log-friendly) or uppercase
 * colon-separated hex (matches `openssl x509 -fingerprint` output
 * shape). Use for peer-cert pinning, mTLS bootstrap allowlists,
 * webhook verification, certificate-transparency cross-checks.
 *
 * @example
 *   var fs = require("fs");
 *   var pem = fs.readFileSync("/etc/ssl/peer.cert.pem", "utf8");
 *   var fp  = b.crypto.hashCertFingerprint(pem);
 *   fp.hex.length;
 *   // → 128 (SHA3-512 = 64 bytes hex-encoded)
 *   fp.colon.split(":").length;
 *   // → 64 (one byte per group)
 */
function hashCertFingerprint(pemOrDer) {
  var der = _pemToDer(pemOrDer);
  var digest = hash(der, "sha3-512");
  var hex = digest.toString("hex");
  var colon = hex.toUpperCase().match(/.{2}/g).join(":");
  return { hex: hex, colon: colon };
}
/**
 * @primitive b.crypto.isCertRevoked
 * @signature b.crypto.isCertRevoked(pemOrDer, denyList)
 * @since     0.7.0
 * @related   b.crypto.hashCertFingerprint, b.crypto.timingSafeEqual
 *
 * Returns `true` when the cert's SHA3-512 fingerprint matches any
 * entry in `denyList`. `denyList` entries may be the colon-separated
 * uppercase hex form, the lowercase hex form, or both — every
 * comparison runs through `crypto.timingSafeEqual` so the answer
 * doesn't leak which entry matched. Use for cert-transparency-style
 * deny lists, revoked-peer sweeps, or compromised-CA blocking.
 *
 * @example
 *   var fs   = require("fs");
 *   var pem  = fs.readFileSync("/etc/ssl/peer.cert.pem", "utf8");
 *   var deny = ["DEADBEEF:CAFEBABE:1234:5678:..."];
 *   var revoked = b.crypto.isCertRevoked(pem, deny);
 *   // → false (when the fingerprint is not in the deny list)
 */
function isCertRevoked(pemOrDer, denyList) {
  if (!Array.isArray(denyList)) {
    throw new TypeError("crypto.isCertRevoked: denyList must be an array of fingerprint strings");
  }
  var fp = hashCertFingerprint(pemOrDer);
  var fpHex = Buffer.from(fp.hex, "hex");
  var fpColon = Buffer.from(fp.colon);
  var colonEntries = [];
  var hexEntries = [];
  for (var i = 0; i < denyList.length; i++) {
    var entry = denyList[i];
    if (typeof entry !== "string" || entry.length === 0) continue;
    if (entry.indexOf(":") !== -1) colonEntries.push(Buffer.from(entry.toUpperCase()));
    else hexEntries.push(Buffer.from(entry.toLowerCase(), "hex"));
  }
  var hitColon = timingSafeEqualAny(fpColon, colonEntries);
  var hitHex = timingSafeEqualAny(fpHex, hexEntries);
  return hitColon || hitHex;
}

var SPKI_PIN_PREFIX = "sha256/";

function _decodeSpkiPin(pinStr, ctx) {
  if (typeof pinStr !== "string" || pinStr.length === 0) {
    throw new TypeError(ctx + ": each pin must be a non-empty 'sha256/<base64>' string");
  }
  if (pinStr.indexOf(SPKI_PIN_PREFIX) !== 0) {
    throw new TypeError(ctx + ": pin '" + pinStr +
      "' must carry the RFC 7469 'sha256/' prefix");
  }
  var body = pinStr.slice(SPKI_PIN_PREFIX.length);
  var buf = Buffer.from(body, "base64");
  if (buf.length !== 32 || buf.toString("base64") !== body) {
    throw new TypeError(ctx + ": pin '" + pinStr +
      "' must be base64 of a 32-byte SHA-256 SPKI digest");
  }
  return buf;
}

/**
 * @primitive b.crypto.spkiPin
 * @signature b.crypto.spkiPin(pemOrDer)
 * @since     0.17.13
 * @status    stable
 * @related   b.crypto.spkiPinVerifier, b.crypto.hashCertFingerprint
 *
 * Computes the RFC 7469 (HPKP §2.4) public-key pin of an X.509
 * certificate: `base64(SHA-256(SubjectPublicKeyInfo DER))`. Accepts DER
 * bytes (Buffer) or a PEM string (BEGIN/END envelope stripped, base64
 * body decoded — same 64 KiB ReDoS cap as `hashCertFingerprint`).
 * Returns `{ sha256, b64, hex }`: `sha256` is the `sha256/<base64>` wire
 * form browsers and `curl --pinnedpubkey` render, `b64` the bare base64
 * body, `hex` the lowercase-hex digest.
 *
 * Unlike `hashCertFingerprint` (SHA3-512 over the WHOLE certificate), an
 * SPKI pin binds only the public key, so it survives certificate reissue
 * on the same key pair — the property RFC 7469 pinning relies on.
 *
 * This is the one place SHA-256 appears on the b.crypto surface: it is an
 * RFC 7469 interop wire constant (browsers / curl / OpenSSL pin stores),
 * not a framework hashing default. The pin binds the peer's long-term
 * SPKI, not the ephemeral PQC key-exchange group negotiated per TLS
 * handshake.
 *
 * @example
 *   var fs  = require("fs");
 *   var pem = fs.readFileSync("/etc/ssl/peer.cert.pem", "utf8");
 *   var pin = b.crypto.spkiPin(pem);
 *   pin.sha256;
 *   // → "sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="
 */
function spkiPin(pemOrDer) {
  var der = _pemToDer(pemOrDer);
  var spkiDer = _certificateFromDer(der)
    .publicKey.export({ type: "spki", format: "der" });
  var digest = nodeCrypto.createHash("sha256").update(spkiDer).digest();
  var b64 = digest.toString("base64");
  return { sha256: SPKI_PIN_PREFIX + b64, b64: b64, hex: digest.toString("hex") };
}

/**
 * @primitive b.crypto.spkiPinVerifier
 * @signature b.crypto.spkiPinVerifier(opts)
 * @since     0.17.13
 * @status    stable
 * @related   b.crypto.spkiPin, b.network.tls.checkServerIdentity9525
 *
 * Builds a `tls.checkServerIdentity`-compatible `(host, cert) =>
 * Error | undefined` that enforces RFC 7469 public-key pinning on top of
 * RFC 9525 strict hostname verification. Pass the returned function as
 * `tls.connect({ checkServerIdentity })`.
 *
 * The verifier first walks the certificate chain the server sent until it
 * reaches a trust anchor of the connection: the dial's `ca`, or Node's
 * default store when the dial sets none. It then checks hostname/SAN
 * identity (via `b.network.tls.checkServerIdentity9525`, SAN-required, no
 * Common Name fallback), so a pin match on a certificate issued for the
 * wrong name is still refused. Only when identity passes does it derive the
 * peer's SPKI pin from the presented DER and constant-time-compare
 * (`crypto.timingSafeEqual`) it against every configured pin. Returns an
 * `Error` with code `tls/compromised-key` when a certificate on that path or
 * the anchor it reaches carries a compromised key (see
 * `b.crypto.compromisedKey`) even if a pin matches, an `Error` with code
 * `tls/server-chain-unverifiable` when the chain does not lead to a trust
 * anchor of the connection, the identity `Error` on a hostname/SAN failure,
 * an `Error` with code `crypto/spki-pin-mismatch` when no pin matches, or
 * `undefined` when chain, identity and pin check out.
 *
 * `opts.pins` MUST be an array of at least two `sha256/<base64>` pins:
 * RFC 7469 §4.3 requires a backup pin corresponding to a key not in the
 * current chain so key rotation does not brick the pinned endpoint. When
 * `opts.hostname` is set, the certificate identity is checked against it
 * instead of the host argument Node supplies — pin the expected name
 * explicitly. Produce pin strings with `b.crypto.spkiPin(...).sha256`.
 *
 * @opts
 *   pins:      string[],  // required — >= 2 'sha256/<base64>' pins (RFC 7469 backup-pin rule)
 *   hostname:  string,    // optional — verify cert identity against this name instead of the host arg
 *
 * @example
 *   var tls    = require("node:tls");
 *   var verify = b.crypto.spkiPinVerifier({
 *     pins: [
 *       "sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
 *       "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",   // backup key
 *     ],
 *   });
 *   var sock = tls.connect({
 *     host: "api.example.com",
 *     port: 443,
 *     checkServerIdentity: verify,
 *   });
 */
function spkiPinVerifier(opts) {
  if (!opts || typeof opts !== "object") {
    throw new TypeError("crypto.spkiPinVerifier: opts is required");
  }
  if (!Array.isArray(opts.pins)) {
    throw new TypeError(
      "crypto.spkiPinVerifier: opts.pins must be an array of 'sha256/<base64>' pins"
    );
  }
  var distinctPins = [];
  for (var dpi = 0; dpi < opts.pins.length; dpi += 1) {
    if (distinctPins.indexOf(opts.pins[dpi]) === -1) distinctPins.push(opts.pins[dpi]);
  }
  if (distinctPins.length < 2) {
    throw new TypeError(
      "crypto.spkiPinVerifier: opts.pins must contain at least two DISTINCT " +
      "'sha256/<base64>' pins — RFC 7469 §4.3 requires a backup pin " +
      "corresponding to a key not in the current chain so key rotation " +
      "does not brick the pinned endpoint"
    );
  }
  var pinBufs = new Array(distinctPins.length);
  for (var pi = 0; pi < distinctPins.length; pi += 1) {
    pinBufs[pi] = _decodeSpkiPin(distinctPins[pi], "crypto.spkiPinVerifier");
  }
  var expectedHost = opts.hostname;
  if (expectedHost !== undefined &&
      (typeof expectedHost !== "string" || expectedHost.length === 0)) {
    throw new TypeError(
      "crypto.spkiPinVerifier: opts.hostname must be a non-empty string when supplied"
    );
  }
  return networkTls()._withCompromisedChainCheck(function verifySpkiPin(host, cert) {
    var effectiveHost = expectedHost !== undefined ? expectedHost : host;
    var identityError = networkTls().checkServerIdentity9525(effectiveHost, cert);
    if (identityError) return identityError;
    if (!cert || !Buffer.isBuffer(cert.raw)) {
      var noDerErr = new Error(
        "crypto.spkiPinVerifier: peer cert object carries no DER `raw` bytes to pin"
      );
      noDerErr.code = "crypto/spki-pin-no-peer-der";
      return noDerErr;
    }
    var peerBuf;
    try {
      peerBuf = Buffer.from(spkiPin(cert.raw).b64, "base64");
    } catch (parseErr) {
      var peerErr = new Error(
        "crypto.spkiPinVerifier: failed to derive peer SPKI pin (" +
        (parseErr && parseErr.message ? parseErr.message : String(parseErr)) + ")"
      );
      peerErr.code = "crypto/spki-pin-peer-parse-failed";
      return peerErr;
    }
    var matched = false;
    for (var mi = 0; mi < pinBufs.length; mi += 1) {
      if (peerBuf.length === pinBufs[mi].length &&
          nodeCrypto.timingSafeEqual(peerBuf, pinBufs[mi])) {
        matched = true;
      }
    }
    if (!matched) {
      var mismatchErr = new Error(
        "crypto.spkiPinVerifier: peer SPKI pin (" + SPKI_PIN_PREFIX +
        peerBuf.toString("base64") + ") does not match any configured pin"
      );
      mismatchErr.code = "crypto/spki-pin-mismatch";
      return mismatchErr;
    }
    return undefined;
  });
}

var SUPPORTED_KEM_ALGORITHMS = Object.freeze([
  { id: "ml-kem-1024",          envelopeId: C.KEM_IDS.ML_KEM_1024,        description: "ML-KEM-1024 KEM-only (legacy single-component)" },
  { id: "ml-kem-1024-p384",     envelopeId: C.KEM_IDS.ML_KEM_1024_P384,   description: "ML-KEM-1024 + ECDH P-384 hybrid (framework default)" },
  { id: "ml-kem-768-x25519",    envelopeId: C.KEM_IDS.ML_KEM_768_X25519,  description: "ML-KEM-768 + X25519 hybrid (IETF / Cloudflare / Chrome TLS 1.3 codepoint 0x11EC)" },
]);

var KAT_SHA3_512_ABC = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
var KAT_SHA3_256_ABC = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
var KAT_SHAKE256_ABC_32 = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739";

/**
 * @primitive b.crypto.selfTest
 * @signature b.crypto.selfTest(opts?)
 * @since     0.12.43
 * @status    stable
 * @compliance soc2, hipaa, pci-dss
 * @related   b.crypto.sha3Hash, b.crypto.encrypt
 *
 * Run a power-on self-test over the framework's cryptographic
 * primitives — the integrity check FIPS 140-3 requires of a validated
 * module. The hash / XOF checks are known-answer tests against NIST FIPS
 * 202 vectors (SHA3-256 / SHA3-512 / SHAKE256); the AEAD check
 * round-trips XChaCha20-Poly1305 and confirms a tampered ciphertext is
 * rejected; the post-quantum checks run a pairwise-consistency +
 * negative test for ML-KEM-1024, ML-DSA-87, and SLH-DSA-SHAKE-256f.
 * Returns a structured report and, by default, throws on any failure so
 * a broken crypto stack fails closed at boot rather than silently
 * producing bad output.
 *
 * @opts
 *   {
 *     throwOnFailure?: boolean,  // default true — throw if any check fails
 *   }
 *
 * @example
 *   var report = b.crypto.selfTest();
 *   // -> { ok: true, results: [ { name, ok }, ... ], failures: [], ranAt }
 */
function selfTest(opts) {
  opts = opts || {};
  var results = [];
  function record(name, fn) {
    try { fn(); results.push({ name: name, ok: true }); }
    catch (e) { results.push({ name: name, ok: false, detail: (e && e.message) || String(e) }); }
  }
  function assert(cond, msg) { if (!cond) throw new Error(msg); }

  record("SHA3-512 KAT (FIPS 202)", function () {
    assert(sha3Hash("abc") === KAT_SHA3_512_ABC, "SHA3-512(\"abc\") does not match the FIPS 202 vector");
  });
  record("SHA3-256 KAT (FIPS 202)", function () {
    assert(hash("abc", "sha3-256").toString("hex") === KAT_SHA3_256_ABC, "SHA3-256(\"abc\") does not match the FIPS 202 vector");
  });
  record("SHAKE256 KAT (FIPS 202)", function () {
    assert(hash("abc", "shake256", C.BYTES.bytes(32)).toString("hex") === KAT_SHAKE256_ABC_32, "SHAKE256(\"abc\") does not match the FIPS 202 vector");
  });
  record("HMAC-SHA3-512 determinism", function () {
    var k = Buffer.from("self-test-hmac-key", "utf8");
    assert(timingSafeEqual(hmac(k, "abc"), hmac(k, "abc")), "HMAC-SHA3-512 is not deterministic");
    assert(!timingSafeEqual(hmac(k, "abc"), hmac(k, "abd")), "HMAC-SHA3-512 collided on distinct inputs");
  });
  record("XChaCha20-Poly1305 round-trip + tamper-detect", function () {
    var key = generateBytes(C.BYTES.bytes(32));
    var pt = Buffer.from("blamejs crypto self-test plaintext", "utf8");
    var packed = encryptPacked(pt, key);
    assert(decryptPacked(packed, key).equals(pt), "AEAD round-trip did not recover the plaintext");
    var bad = Buffer.from(packed); bad[bad.length - 1] ^= 0xff;
    var rejected = false;
    try { decryptPacked(bad, key); } catch (_e) { rejected = true; }
    assert(rejected, "AEAD accepted a tampered ciphertext");
  });

  var pqc = pqcSoftware();
  record("ML-KEM-1024 encaps/decaps pairwise consistency", function () {
    var kp = pqc.ml_kem_1024.keygen();
    var enc = pqc.ml_kem_1024.encapsulate(kp.publicKey);
    var ss = pqc.ml_kem_1024.decapsulate(enc.cipherText, kp.secretKey);
    assert(timingSafeEqual(Buffer.from(ss), Buffer.from(enc.sharedSecret)), "ML-KEM-1024 decapsulated secret does not match");
  });
  record("ML-DSA-87 sign/verify + negative", function () {
    var kp = pqc.ml_dsa_87.keygen();
    var msg = Buffer.from("blamejs ML-DSA self-test", "utf8");
    var sig = pqc.ml_dsa_87.sign(msg, kp.secretKey);
    assert(pqc.ml_dsa_87.verify(sig, msg, kp.publicKey), "ML-DSA-87 rejected a valid signature");
    var bad = Buffer.from(sig); bad[0] ^= 0xff;
    assert(!pqc.ml_dsa_87.verify(bad, msg, kp.publicKey), "ML-DSA-87 accepted a tampered signature");
  });
  record("SLH-DSA-SHAKE-256f sign/verify + negative", function () {
    var kp = pqc.slh_dsa_shake_256f.keygen();
    var msg = Buffer.from("blamejs SLH-DSA self-test", "utf8");
    var sig = pqc.slh_dsa_shake_256f.sign(msg, kp.secretKey);
    assert(pqc.slh_dsa_shake_256f.verify(sig, msg, kp.publicKey), "SLH-DSA-SHAKE-256f rejected a valid signature");
    var bad = Buffer.from(sig); bad[0] ^= 0xff;
    assert(!pqc.slh_dsa_shake_256f.verify(bad, msg, kp.publicKey), "SLH-DSA-SHAKE-256f accepted a tampered signature");
  });

  var failures = results.filter(function (r) { return !r.ok; });
  var report = { ok: failures.length === 0, results: results, failures: failures, ranAt: new Date().toISOString() };
  if (failures.length && opts.throwOnFailure !== false) {
    var err = new Error("crypto.selfTest: " + failures.length + " self-test(s) failed: " +
      failures.map(function (f) { return f.name; }).join("; "));
    err.code = "crypto/self-test-failed";
    err.report = report;
    throw err;
  }
  return report;
}

module.exports = {
  sri:                          sri,
  selfTest:                     selfTest,
  sha3Hash:                    sha3Hash,
  hmac:                        hmac,
  hashFile:                    hashFile,
  hashFilesParallel:           hashFilesParallel,
  hashStream:                  hashStream,
  namespaceHash:               namespaceHash,
  kdf:                         kdf,
  timingSafeEqual:             timingSafeEqual,
  timingSafeEqualAny:          timingSafeEqualAny,
  hashCertFingerprint:         hashCertFingerprint,
  isCertRevoked:               isCertRevoked,
  spkiPin:                     spkiPin,
  spkiPinVerifier:             spkiPinVerifier,
  generateBytes:               generateBytes,
  generateToken:               generateToken,
  randomInt:                   randomInt,
  toBase64Url:                 toBase64Url,
  fromBase64Url:               fromBase64Url,
  generateEncryptionKeyPair:   generateEncryptionKeyPair,
  generateSigningKeyPair:      generateSigningKeyPair,
  generateMlkem768X25519KeyPair: generateMlkem768X25519KeyPair,
  sign:                        sign,
  verify:                      verify,
  importPublicJwk:             importPublicJwk,
  assertKeyType:               assertKeyType,
  compromisedKey:              compromisedKey,
  assertNotCompromised:        assertNotCompromised,
  _certificatesInPem:          _certificatesInPem,
  _certificateFromDer:         _certificateFromDer,
  _x509:                       _x509,
  CryptoKeyError:             CryptoKeyError,
  makeBase64UrlDecoder:        makeBase64UrlDecoder,
  encrypt:                     encrypt,
  decrypt:                     decrypt,
  encryptMlkem768X25519:       encryptMlkem768X25519,
  decryptMlkem768X25519:       decryptMlkem768X25519,
  encryptEnvelopeAsCertPeer:   encryptEnvelopeAsCertPeer,
  decryptEnvelopeAsCertPeer:   decryptEnvelopeAsCertPeer,
  SUPPORTED_KEM_ALGORITHMS:    SUPPORTED_KEM_ALGORITHMS,
  encryptPacked:               encryptPacked,
  decryptPacked:               decryptPacked,
};
