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
var { pipeline } = require("node:stream/promises");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
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
var safeBuffer  = lazyRequire(function () { return require("./safe-buffer"); });
// pqc-software requires this module (b.crypto) — lazy-load to break the
// cycle. Only the power-on self-test needs it here.
var pqcSoftware = lazyRequire(function () { return require("./pqc-software"); });

// Streaming-hash algorithm allowlist. Mirrors the framework's PQC-
// first crypto policy: SHA3 / SHAKE family is the default surface;
// SHA-512 is permitted for legitimate interop (signing artifacts that
// downstream verifiers compute as SHA-512). MD5 / SHA-1 / SHA-256 are
// not on the list — operators who genuinely need them call
// node:crypto directly so the choice surfaces in their code.
var STREAM_HASH_ALGORITHMS = Object.freeze({
  "sha3-256":   { algorithm: "sha3-256",   needsOutputLength: false },
  "sha3-384":   { algorithm: "sha3-384",   needsOutputLength: false },
  "sha3-512":   { algorithm: "sha3-512",   needsOutputLength: false },
  "sha512":     { algorithm: "sha512",     needsOutputLength: false },
  "shake256":   { algorithm: "shake256",   needsOutputLength: true  },
});
var STREAM_HASH_DEFAULT = "sha3-512";
var SHAKE256_DEFAULT_LEN = 64;

// ===========================================================
// Core primitives — everything else is built from these
// ===========================================================

function hash(data, algorithm, outputLength) {
  var opts = outputLength ? { outputLength: outputLength } : undefined;
  return nodeCrypto.createHash(algorithm, opts).update(data).digest();
}

function hmac(key, data, algorithm) {
  return nodeCrypto.createHmac(algorithm, key).update(data).digest("hex");
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
  // Own-property guard, not a truthiness check: STREAM_HASH_ALGORITHMS is a
  // plain object, so a name colliding with an Object.prototype member
  // ("constructor" → the Object constructor, "__proto__" → Object.prototype)
  // would read back a truthy inherited value, slip past `if (!entry)`, and then
  // throw ERR_INVALID_ARG_TYPE synchronously at createHash(entry.algorithm ===
  // undefined) — a sync throw from a Promise-returning function. Refuse it here
  // as the documented Promise.reject, matching b.crypto.sri's algorithm guard.
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

// _hashFileMulti — single-pass stream of a file through N hashers in
// parallel. Returns { path, byteLength, <alg>: hex } for every
// `algorithms` entry. Used by hashFilesParallel below; not exported
// directly because the common case is the parallel-many shape.
//
// Hardening (v0.9.58):
//   - lstat-then-stat so symlinks are detected before open; refused
//     unless opts.followSymlinks === true (default false — a symlink-
//     in-input-list attack lets a write-restricted caller hash files
//     they can't otherwise reach).
//   - Refuses non-regular files (FIFOs / sockets / block / char
//     devices) which read indefinitely or return platform-undefined
//     bytes. The same path also defeats /dev/zero-as-input DoS.
//   - opts.maxBytesPerFile (default C.BYTES.gib(1)) caps the bytes
//     read per file; oversized inputs reject before exhausting heap.
function _hashFileMulti(filePath, algorithms, opts) {
  var maxBytes      = opts && opts.maxBytesPerFile;
  var followSymlink = opts && opts.followSymlinks === true;
  return new Promise(function (resolve, reject) {
    // Pre-open lstat: detect symlinks + special files before opening the
    // stream. Open-then-stat is racy under symlink-swap; lstat the path
    // itself ahead of createReadStream.
    var st;
    try { st = nodeFs.lstatSync(filePath); }
    catch (statErr) {
      reject(new Error("crypto.hashFilesParallel: stat failed for '" +
        filePath + "': " + (statErr && statErr.message ? statErr.message : String(statErr))));
      return;
    }
    if (st.isSymbolicLink() && !followSymlink) {
      reject(new Error("crypto.hashFilesParallel: refusing symlink '" +
        filePath + "' — pass {followSymlinks: true} to opt in (an attacker " +
        "with write access to the input list can otherwise direct the hasher " +
        "to files the caller cannot read directly)"));
      return;
    }
    if (!st.isFile() && !st.isSymbolicLink()) {
      reject(new Error("crypto.hashFilesParallel: refusing non-regular file '" +
        filePath + "' (FIFOs / sockets / character / block devices read indefinitely " +
        "or return platform-undefined bytes; hashing them is meaningless and " +
        "DoS-prone). Type: " +
        (st.isFIFO() ? "FIFO" :
         st.isSocket() ? "socket" :
         st.isBlockDevice() ? "block-device" :
         st.isCharacterDevice() ? "char-device" :
         st.isDirectory() ? "directory" : "unknown")));
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
        reject(new Error("crypto.hashFilesParallel: file '" + filePath +
          "' exceeded opts.maxBytesPerFile (" + maxBytes +
          " bytes); refusing to continue hashing"));
        return;
      }
      for (var j = 0; j < hashers.length; j += 1) hashers[j].update(chunk);
    });
    stream.on("end", function () {
      if (aborted) return;
      var out = { path: filePath, byteLength: byteLength };
      for (var k = 0; k < hashers.length; k += 1) {
        // Field name = algorithm with `-` → `_` so "sha3-512" surfaces
        // as `out.sha3_512` (matches the standalone-verifier shape).
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
    : Math.min(8, Math.max(1, filePaths.length));                                                  // worker fan-out cap, not bytes
  if (typeof concurrency !== "number" || !isFinite(concurrency) ||
      concurrency < 1 || concurrency > 256 ||                                                       // concurrency upper cap
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
  // DoS cap. Default 1 GiB per file; operators with larger
  // legitimate hashing workloads (firmware images, vendor packs)
  // override per-call.
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
        if (onProgress) {
          try { onProgress(completed, total); }
          catch (_e) { /* progress callback errors are not fatal */ }
        }
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
  // SHAKE256 over OS-RNG bytes. The OS RNG (nodeCrypto.randomBytes) is
  // already cryptographically secure on modern platforms; passing
  // through a hash adds defense-in-depth (stops a hypothetical
  // randomBytes weakness from being directly observable downstream)
  // without measurable cost. SHAKE256 is the right XOF here because it
  // supports arbitrary output length — the previous implementation
  // used SHA3-512 + subarray, which silently truncated to 64 bytes
  // when callers requested more. SHAKE256 is also already the
  // framework's KDF / browser-side derivation primitive, so the same
  // hash family does double duty.
  //
  // Node's SHAKE256 XOF is non-uniform at outputLength 1 (the byte
  // values 0x00 and 0xff never occur and the low bit skews to ~0.54);
  // outputLength >= 2 is uniform. Draw at least 2 bytes and slice so a
  // 1-byte request still returns a uniform byte.
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
 * @related   b.crypto.hmacSha3
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
 *   var expected = b.crypto.hmacSha3("server-key", "payload");
 *   var supplied = "ab12...e9";   // from request header / body
 *   var ok = b.crypto.timingSafeEqual(supplied, expected);
 *   // → true when bytes match, false otherwise (no early exit on mismatch)
 */
function timingSafeEqual(a, b) {
  // Entry-tier validation. The prior `Buffer.from(String(x))` coercion
  // let a prototype-pollution-influenced caller (Object whose toString
  // returns attacker-chosen bytes) redirect the compare through bytes
  // that have nothing to do with the supplied value. Refuse any
  // non-string non-Buffer input outright.
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

// ===========================================================
// Public API — built on core primitives
// ===========================================================

// ---- Hashing ----
/**
 * @primitive b.crypto.sha3Hash
 * @signature b.crypto.sha3Hash(data)
 * @since     0.1.0
 * @related   b.crypto.hmacSha3, b.crypto.kdf, b.crypto.hashFile
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
 * @primitive b.crypto.hmacSha3
 * @signature b.crypto.hmacSha3(key, data)
 * @since     0.1.0
 * @related   b.crypto.sha3Hash, b.crypto.timingSafeEqual
 *
 * Returns the lowercase-hex HMAC-SHA3-512 of `data` keyed by `key`.
 * Use for keyed integrity checks (webhook signatures, request
 * authentication tags, audit-chain links). Pair with
 * `b.crypto.timingSafeEqual` when comparing supplied vs computed tags.
 *
 * @example
 *   var tag = b.crypto.hmacSha3("shared-secret", "POST /webhook|123");
 *   // → "8f1c...d4e2" (128 hex chars, HMAC-SHA3-512 = 64 bytes)
 */
function hmacSha3(key, data) { return hmac(key, data, "sha3-512"); }

// (SHA-1 is intentionally NOT exported from b.crypto. The framework's
//  only legitimate SHA-1 use is the HaveIBeenPwned k-anonymity API in
//  lib/auth/password.js, which imports lib/framework-sha1-hibp.js
//  directly. Public b.crypto.sha1* is permanently off the table — a
//  future caller wanting SHA-1 for storage / signing / fingerprinting
//  would re-introduce a broken primitive into the crypto surface this
//  framework spent every other line keeping out.)

// ---- KDF ----
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

// ---- App-namespaced indexable hash (for derived-hash columns) ----
//
// b.crypto.namespaceHash(prefix, value) → hex-encoded SHA3-512 of
// `prefix + ":" + value`. Operators wire this into derived-hash
// columns (emailHash, certFpHash, externalIdHash) where the goal is
// indexed exact-match lookup, NOT credential storage. Returns hex —
// not the envelope-versioned base64 b.credentialHash.hash returns —
// because hex strings are stable, indexable column values across
// every database backend the framework supports.
//
// Why a separate primitive vs `b.crypto.sha3Hash(prefix + ":" + value)`:
//   - Centralized prefix-shape validation (NUL/CR/LF rejection,
//     length bound) — operator can't accidentally smuggle a
//     framework-derived prefix through a user-controlled value.
//   - Clear name documents the intent ("indexable namespace hash"
//     vs "raw content digest"), so callers are less likely to
//     reach for the credential-storage primitive when they want a
//     read-only lookup hash.
//
// Read-only / deterministic — no audit emit (the input is operator-
// supplied; the digest is the only observable side-effect, returned
// to the caller). NUL / CR / LF in `prefix` are refused so an
// operator can't smuggle a control sequence into framework or
// downstream tooling that consumes the audit log; the bound on
// `prefix` length prevents oversized namespace separators (the
// framework's HASH_PREFIX entries are <= 16 bytes).
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
  // opts reserved for future extension (algorithm selection); current
  // surface is fixed to SHA3-512 — no operator demand for SHAKE256
  // variable-length output here, since the indexed column shape is
  // fixed-width hex.
  if (opts && typeof opts !== "object") {
    throw new TypeError("crypto.namespaceHash: opts must be a plain object when provided");
  }
  if (typeof prefix !== "string") {
    throw new TypeError("crypto.namespaceHash: prefix must be a string");
  }
  if (prefix.length === 0) {
    throw new TypeError("crypto.namespaceHash: prefix must be non-empty");
  }
  // Byte-length bound — operator's prefix is the namespace label and
  // shouldn't bloat the hash input. Use Buffer.byteLength so multi-
  // byte UTF-8 prefixes can't slip through a code-unit-only check.
  if (Buffer.byteLength(prefix, "utf8") > NAMESPACE_HASH_PREFIX_MAX_BYTES) {
    throw new TypeError(
      "crypto.namespaceHash: prefix exceeds " + NAMESPACE_HASH_PREFIX_MAX_BYTES +
      " bytes (UTF-8); operator-derived prefixes should be short labels"
    );
  }
  // NUL / CR / LF in prefix — refuse outright. NUL truncates in many
  // C-string consumers (audit-log path, downstream DB tooling); CR/LF
  // smuggles log-injection patterns into anything that renders the
  // prefix verbatim.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000\r\n]/.test(prefix)) {
    throw new TypeError(
      "crypto.namespaceHash: prefix contains NUL / CR / LF — refuse"
    );
  }
  // value is the operator-supplied content. Coerce Buffer/Uint8Array
  // to utf-8 string for concatenation; reject anything else so the
  // caller surfaces the type error explicitly rather than silently
  // hashing `[object Object]`.
  var valueStr;
  var valueWasString = false;
  if (typeof value === "string") {
    valueStr = value;
    valueWasString = true;
  } else if (Buffer.isBuffer(value)) {
    valueStr = value.toString("utf8");
  } else if (value instanceof Uint8Array) {
    valueStr = Buffer.from(value).toString("utf8");
  } else {
    throw new TypeError(
      "crypto.namespaceHash: value must be a string, Buffer, or Uint8Array"
    );
  }
  // Refuse CR / LF in string-typed values. The prior gap let an
  // attacker-controlled string `value` (e.g. an HTTP header that
  // becomes an Idempotency-Key) smuggle log-injection / record-
  // separator bytes into any consumer that logs the value verbatim
  // before hashing (debug paths, audit envelopes, derived-column
  // shadow logs). NUL is NOT refused — multiple internal callers
  // use NUL as a composite-key separator (`method\0actorId\0key`
  // shape in agent-idempotency / mail-greylist / compose-pipeline),
  // and NUL is not a log-injection byte in any standard logger. NUL
  // in operator-supplied content is the operator-boundary
  // responsibility. Buffer / Uint8Array inputs remain operator-side
  // opaque bytes by contract — namespaceHash treats them as raw
  // bytes to be digested without rendering, so the control-char
  // gate does not apply there either.
  if (valueWasString && safeBuffer().hasCrlf(valueStr)) {
    throw new TypeError(
      "crypto.namespaceHash: value (string-typed) contains CR / LF — refuse"
    );
  }
  return hash(prefix + ":" + valueStr, "sha3-512").toString("hex");
}

// _suiteFixedInfo — NIST SP 800-56C r2 §4.1 OtherInfo / RFC 9180
// (HPKE) §5.1 suite_id binding. Returns the byte string that the KDF
// MUST absorb alongside the shared-secret(s) so a key derived under
// one suite is not silently usable under a different suite. Same
// label is recovered on decrypt by re-reading the envelope-prefix
// bytes (kemId / cipherId / kdfId).
function _suiteFixedInfo(kemId, cipherId, kdfId) {
  return Buffer.concat([
    Buffer.from(C.ENVELOPE_FIXED_INFO_LABEL, "utf8"),
    Buffer.from([0x00, kemId, cipherId, kdfId, 0x00]),
  ]);
}

// ---- Random ----
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
 *   // → "5b8f2a4c7d1e9f0b3c6a8d2e4f7c1b5d" (32 hex chars, 16 random bytes)
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
  if (buf instanceof Uint8Array) return Buffer.from(buf).toString("base64url");
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
// RFC 4648 §5 alphabet for base64url, with optional padding. The
// canonical form has no padding, the URL-safe alphabet (`-_`), and a
// length consistent with the byte count (length % 4 ∈ {0, 2, 3}; the
// `length % 4 === 1` shape is impossible to produce by any conforming
// encoder and signals truncated / forged input).
var _BASE64URL_STRICT_RE = /^[A-Za-z0-9_-]*={0,2}$/;

function fromBase64Url(s, opts) {
  if (typeof s !== "string") {
    throw new TypeError("crypto.fromBase64Url: input must be a string");
  }
  // Crypto callers (JWT signature payloads, JWS / COSE encoded values,
  // OAuth `state` round-tripping) MUST reject non-canonical / malformed
  // input. The Node base64url decoder silently tolerates trailing
  // garbage, mixed `+/` from standard base64, missing padding errors,
  // and length-mod-4 shapes — the CWE-347 / CWE-1286 signature-
  // canonicalization footgun. Strict mode
  // (the default) refuses anything outside the RFC 4648 §5 alphabet +
  // length rules. Operators with a known-lossy legacy payload pass
  // `{ strict: false }` to opt out per call.
  var strict = !opts || opts.strict !== false;
  if (strict) {
    // Manual trailing-`=` strip — avoids the polynomial-regex shape
    // `/=+$/` CodeQL flags, where `=+` can backtrack on long input
    // ending in many `=`. Walking from end is O(n) worst-case.
    var trimEnd = s.length;
    while (trimEnd > 0 && s.charCodeAt(trimEnd - 1) === 0x3D) trimEnd -= 1;          // '=' codepoint
    var unpadded = s.slice(0, trimEnd);
    if (!_BASE64URL_STRICT_RE.test(s)) {
      throw new TypeError(
        "crypto.fromBase64Url: input contains characters outside RFC 4648 §5 " +
        "base64url alphabet (A-Z a-z 0-9 - _ =) — pass {strict:false} to allow non-canonical input"
      );
    }
    if (unpadded.length % 4 === 1) {                                                                 // base64 group length, not bytes
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

// ---- Subresource Integrity (W3C SRI 1.0) ----
//
// b.crypto.sri(content, { algorithm? }) — returns a `sha###-base64`
// integrity attribute string operators paste into <script integrity="...">
// or <link integrity="..."> tags. Defends against CDN compromise + ISP
// MITM injection — the browser refuses to load the resource when its
// hash diverges from the integrity attribute.
//
// W3C SRI 1.0 §3.2 lists sha256 / sha384 / sha512 as the supported
// digest algorithms; sha384 is the recommended default (collision
// margin without sha512's 64-byte overhead).
//
//   b.crypto.sri(scriptBuffer, { algorithm: "sha384" })
//   → "sha384-AbCdEf...="
//
//   b.crypto.sri(["a", "b"], { algorithm: "sha384" })   // array → multi-hash
//   → "sha384-X1... sha384-X2..."   (per W3C §3.3 multi-integrity)
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
  // Array input — emit multiple integrity tokens space-separated per
  // W3C §3.3 (browser picks the strongest one it recognizes).
  if (Array.isArray(content)) {
    return content.map(function (c) { return sri(c, opts); }).join(" ");
  }
  var buf;
  if (Buffer.isBuffer(content)) buf = content;
  else if (typeof content === "string") buf = Buffer.from(content, "utf8");
  else if (content instanceof Uint8Array) buf = Buffer.from(content);
  else throw new Error("crypto.sri: content must be a Buffer, Uint8Array, string, or array of those");
  var digest = nodeCrypto.createHash(algorithm).update(buf).digest("base64");
  return algorithm + "-" + digest;
}

// ---- Key generation ----
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

// ---- Signatures (auto-detect algorithm from key PEM) ----
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
 * cross-service request signatures.
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair();
 *   var sig = b.crypto.sign("payload-to-sign", pair.privateKey);
 *   sig.length > 0;
 *   // → true (ML-DSA-87 signature ~ 4627 bytes)
 */
function sign(data, privateKeyPem) {
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
 * auto-detected from the public-key PEM.
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
  return nodeCrypto.verify(null, Buffer.from(data), publicKeyPem, signature);
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
 * Centralising it gives one place to harden untrusted-JWK import.
 *
 * On failure, when `opts.errorClass` is supplied the thrown error is
 * `new opts.errorClass(opts.code, opts.messagePrefix + nodeFailureDetail)`
 * so the operator sees the module's own code + a message naming the
 * source; without it the original Node error propagates unchanged.
 *
 * @opts
 *   errorClass:    Function,  // (code, message) error constructor
 *   code:          string,    // error code passed to errorClass
 *   messagePrefix: string,    // text before the Node failure detail. default: ""
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
  try {
    return nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  } catch (e) {
    if (typeof opts.errorClass === "function") {
      throw new opts.errorClass(opts.code, (opts.messagePrefix || "") + ((e && e.message) || e));
    }
    throw e;
  }
}

// Track whether the hybrid-disabled audit has been emitted at least
// once per process, so a high-volume KEM-only deployment doesn't peg
// the audit bus with one event per encrypt() call. Operators who want
// the per-call signal can call encryptMlkemOnly directly (which never
// emits) or read the metric at b.metrics — the count is preserved.
var _hybridDisabledAuditEmitted = false;

// ---- Envelope encrypt (ML-KEM-1024 + P-384 ECDH hybrid + SHAKE256 + XChaCha20) ----
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
    // Operator passed only an ML-KEM public key — silently dropping
    // the P-384 hybrid leg means the operator's defense-in-depth
    // posture (classical ECDH backstop on top of PQC KEM) is gone
    // without any signal. Audit ONCE per process (M2 audit-dedup —
    // pre-v0.8.22 every plain-KEM call emitted, pegging the audit
    // bus). Operators who genuinely want KEM-only should call
    // encryptMlkemOnly explicitly so this audit doesn't fire.
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

  var mlkemPub = nodeCrypto.createPublicKey(mlkemPubPem);
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var ephEc = generateKeyPair("ec", {
    namedCurve: "P-384",
    publicKeyEncoding:  { type: "spki",  format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var ecSs = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(ephEc.privateKey),
    publicKey:  nodeCrypto.createPublicKey(ecPubPem),
  });
  var key = kdf(Buffer.concat([kem.sharedKey, ecSs,
    _suiteFixedInfo(C.ACTIVE.KEM, C.ACTIVE.CIPHER, C.ACTIVE.KDF)]),
    C.BYTES.bytes(32));
  var nonce = generateBytes(C.BYTES.bytes(24));
  // Bind the 4-byte envelope header (MAGIC + kemId + cipherId + kdfId)
  // as AAD so a tampered header (algorithm-substitution attack) fails
  // the Poly1305 tag.
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
  var kem = nodeCrypto.encapsulate(nodeCrypto.createPublicKey(publicKeyPem));
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

// ---- Envelope decrypt (dispatches on envelope IDs, supports both KEM IDs) ----
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
  var packed = Buffer.from(ciphertext, "base64");
  if (packed[0] === 0xE1) {                                                       // legacy envelope magic
    if (!opts || !opts.allowLegacy) {
      throw new Error("Invalid envelope: legacy 0xE1 format predates the FixedInfo " +
        "KDF binding (NIST SP 800-56C r2 §4.1) — re-seal data under the current envelope, " +
        "or pass { allowLegacy: true } to opt in to one-shot read for migration");
    }
    // Audit-emit every legacy decrypt so the migration window is
    // visible. Emit success ONLY on actual decrypt success; emit
    // failure on throw. Before this fix, the audit fired
    // before decryptEnvelope() ran, so corrupted 0xE1 blobs / wrong
    // private keys / unsupported KEMs got logged as successful legacy
    // decrypts when the call actually threw, inflating real success
    // rates during migration windows. Audit module is top-of-file
    // lazy-loaded (var audit above) so this hot-path emit doesn't
    // re-resolve the require() cache on every legacy decrypt.
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
  // `opts.raw: true` returns the decrypted Buffer rather than the
  // utf8-decoded string. Callers carrying binary plaintext (JWE
  // experimental wrapper, future signed-blob carriers) opt in to keep
  // arbitrary bytes lossless; default stays utf8-string for backwards
  // compatibility with the existing API contract.
  return decryptEnvelope(packed, privateKeys,
    opts && opts.raw === true ? { raw: true } : undefined);
}

// Bounds-checked 2-byte length read — a bare _envU16(packed, pos) on a
// truncated envelope throws a raw Node RangeError that escapes the documented
// "Invalid envelope: ..." error contract (untrusted ciphertext must fail with
// the typed envelope error, not a stack-trace-leaking RangeError).
function _envU16(buf, at) {
  if (at + 2 > buf.length) {
    throw new Error("Invalid envelope: truncated (expected a 2-byte length at offset " + at + ")");
  }
  return buf.readUInt16BE(at);
}

// Read a 2-byte-length-prefixed component and bounds-check that the declared
// body actually fits in the envelope BEFORE slicing it. Without this a
// truncated envelope hands an under-length component (a short KEM ciphertext /
// ephemeral public key) to Node crypto, which throws a raw
// "Failed to perform decapsulation" / key-parse error that escapes the
// documented "Invalid envelope: ..." contract. Returns { bytes, pos } where
// pos is the offset past the component. A well-formed envelope always carries
// each declared component in full, so this never rejects a valid input.
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

  // The legacy 0xE1 envelope predates the FixedInfo / suite-binding
  // KDF input; the same wire format otherwise. The dispatcher passes
  // omitFixedInfo: true for the 0xE1 path and the KDF input below
  // skips the _suiteFixedInfo concat.
  var omitFixedInfo = !!(internalOpts && internalOpts.omitFixedInfo);

  if (cipherId !== C.CIPHER_IDS.XCHACHA20_POLY1305) {
    throw new Error("Invalid envelope: unsupported cipher (only XChaCha20-Poly1305 supported)");
  }
  if (kdfId !== C.KDF_IDS.SHAKE256) {
    throw new Error("Invalid envelope: unsupported KDF (only SHAKE256 supported)");
  }

  var kemSlice = _envSlice(packed, pos, "KEM ciphertext");
  var kemCt = kemSlice.bytes; pos = kemSlice.pos;

  var mlkemPriv = nodeCrypto.createPrivateKey(
    typeof privateKeys === "string" ? privateKeys : privateKeys.privateKey
  );
  var mlkemSs = nodeCrypto.decapsulate(mlkemPriv, kemCt);
  var symmetricKey;
  var fixedInfo = omitFixedInfo ? Buffer.alloc(0) : _suiteFixedInfo(kemId, cipherId, kdfId);

  if (kemId === C.KEM_IDS.ML_KEM_1024_P384) {
    var ecEphSlice = _envSlice(packed, pos, "EC ephemeral public key");
    var ecEphDer = ecEphSlice.bytes; pos = ecEphSlice.pos;
    var ecPrivPem = typeof privateKeys === "string" ? null : privateKeys.ecPrivateKey;
    if (!ecPrivPem) throw new Error("Hybrid KEM requires EC private key");
    var ecSs = nodeCrypto.diffieHellman({
      privateKey: nodeCrypto.createPrivateKey(ecPrivPem),
      publicKey:  nodeCrypto.createPublicKey({ key: ecEphDer, type: "spki", format: "der" }),
    });
    symmetricKey = kdf(Buffer.concat([mlkemSs, ecSs, fixedInfo]), C.BYTES.bytes(32));
  } else if (kemId === C.KEM_IDS.ML_KEM_1024) {
    symmetricKey = kdf(Buffer.concat([mlkemSs, fixedInfo]), C.BYTES.bytes(32));
  } else if (kemId === C.KEM_IDS.ML_KEM_768_X25519) {
    // ML-KEM-768 + X25519 hybrid envelope. The mlkemPriv must be an
    // ML-KEM-768 key (not 1024); operators are responsible for passing
    // the correct keypair via privateKeys when the envelope was sealed
    // with this algorithm. Same length-prefixed shape as the P-384
    // hybrid: 2-byte ec-eph-len + DER X25519 pubkey + nonce + ct.
    var x25519EphSlice = _envSlice(packed, pos, "X25519 ephemeral public key");
    var x25519EphDer = x25519EphSlice.bytes; pos = x25519EphSlice.pos;
    var x25519PrivPem = typeof privateKeys === "string" ? null : privateKeys.x25519PrivateKey;
    if (!x25519PrivPem) throw new Error("ML-KEM-768 + X25519 hybrid envelope requires x25519PrivateKey");
    var x25519Ss = nodeCrypto.diffieHellman({
      privateKey: nodeCrypto.createPrivateKey(x25519PrivPem),
      publicKey:  nodeCrypto.createPublicKey({ key: x25519EphDer, type: "spki", format: "der" }),
    });
    symmetricKey = kdf(Buffer.concat([mlkemSs, x25519Ss, fixedInfo]), C.BYTES.bytes(32));
  } else {
    throw new Error("Invalid envelope: unsupported KEM ID " + kemId);
  }

  // Bounds-check the trailing nonce + AEAD tag before slicing them out. A
  // truncated envelope (untrusted ciphertext) that ends inside the 24-byte
  // nonce or before the 16-byte Poly1305 tag otherwise reaches the cipher as
  // an under-length nonce / ciphertext and surfaces as a raw noble
  // RangeError ("nonce"/"ciphertext" length) — escaping the documented
  // "Invalid envelope: ..." error contract exactly the way an unchecked
  // _envU16 read would (see _envU16 above). Fail with the typed envelope
  // error instead. A valid envelope always carries a full nonce and at
  // least the tag, so this never rejects a well-formed input.
  var nonceLen = C.BYTES.bytes(24);
  var tagLen = C.BYTES.bytes(16);
  if (pos + nonceLen + tagLen > packed.length) {
    throw new Error("Invalid envelope: truncated (expected a " + nonceLen +
      "-byte nonce and a " + tagLen + "-byte authentication tag at offset " + pos + ")");
  }
  var nonce = packed.subarray(pos, pos + nonceLen); pos += nonceLen;
  // Re-derive the 4-byte envelope-header AAD from the bytes we just
  // dispatched on. A tampered header (algorithm-substitution attack)
  // surfaces here as a Poly1305 tag verification failure.
  var headerAad = packed.subarray(0, 4);                                          // envelope-header byte slice
  var plainBuf = Buffer.from(
    xchacha20poly1305(symmetricKey, nonce, headerAad).decrypt(packed.subarray(pos))
  );
  if (internalOpts && internalOpts.raw === true) return plainBuf;
  return plainBuf.toString("utf8");
}

// ---- Symmetric buffer encrypt/decrypt (for storage) ----
//
// Optional `aad` (additional authenticated data) is mixed into the
// Poly1305 tag — encrypt-time and decrypt-time AAD must match exactly
// or decrypt fails. Used by primitives that want encryption-context
// binding (b.breakGlass.encryptCell binds (table, rowId, column) so a
// ciphertext from row A literally cannot decrypt as row B even with
// the same key).
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
  // A packed blob shorter than the 1-byte format id + 24-byte nonce +
  // 16-byte Poly1305 tag is truncated / corrupt (untrusted or damaged
  // storage cell); slicing the nonce / ciphertext out of it otherwise
  // reaches the cipher as an under-length nonce and throws a raw noble
  // RangeError that escapes this function's typed error contract (mirrors
  // the envelope decrypt bounds check). A valid packet is always at least
  // this long, so this never rejects a well-formed input.
  if (packed.length < 1 + C.BYTES.bytes(24) + C.BYTES.bytes(16)) {
    throw new Error("Invalid packed format: truncated (need at least a 1-byte " +
      "version, a 24-byte nonce, and a 16-byte authentication tag)");
  }
  return Buffer.from(
    xchacha20poly1305(key, packed.subarray(1, 25), aad ? Buffer.from(aad) : undefined)
      .decrypt(packed.subarray(25))
  );
}

// ---- ML-KEM-768 + X25519 hybrid (TLS-interop envelope) ----
//
// The IETF / Cloudflare / Chrome standardized hybrid for TLS 1.3
// (codepoint 0x11EC). Smaller payload than ML-KEM-1024 + P-384
// (~1.1 KB vs ~1.6 KB), wider interop with peers using the same
// hybrid (Cloudflare Workers, Chrome, blamejs-on-the-other-side).
//
// Operators wire this when the recipient publishes ML-KEM-768 +
// X25519 keys. Generation:
//
//   var pair = b.crypto.generateMlkem768X25519KeyPair();
//   // → { mlkemPublicKey, mlkemPrivateKey,
//   //     x25519PublicKey, x25519PrivateKey }
//
//   var envelope = b.crypto.encryptMlkem768X25519(plaintext, {
//     mlkemPublicKey:    recipient.mlkemPublicKey,
//     x25519PublicKey:   recipient.x25519PublicKey,
//   });
//
// Decryption goes through the existing b.crypto.decrypt(envelope,
// privateKeys) — the envelope-magic dispatch handles KEM_IDS.
// ML_KEM_768_X25519. privateKeys MUST shape as { privateKey,
// x25519PrivateKey } — privateKey is the ML-KEM-768 PEM, NOT the
// default ML-KEM-1024.

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
  var mlkemPub = nodeCrypto.createPublicKey(recipient.mlkemPublicKey);
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var ephX25519 = generateKeyPair("x25519", {
    publicKeyEncoding:  { type: "spki",  format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var x25519Ss = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(ephX25519.privateKey),
    publicKey:  nodeCrypto.createPublicKey(recipient.x25519PublicKey),
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

// Symmetric named-pair to encryptMlkem768X25519. Operators wiring the
// IETF / Cloudflare / Chrome TLS-1.3 hybrid (codepoint 0x11EC) want
// the encrypt + decrypt halves under symmetric, discoverable names.
//
// The generic b.crypto.decrypt already dispatches by KEM ID and
// handles ML_KEM_768_X25519 envelopes correctly; this helper REJECTS
// any other KEM ID at the head, so an operator who calls
// decryptMlkem768X25519 with a ciphertext sealed under a different
// algorithm gets a clear error rather than the generic "unsupported
// KEM ID" path.
//
//   recipient: { privateKey, x25519PrivateKey }   — operator's keys
//   ciphertext: base64 envelope from encryptMlkem768X25519
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
 * Recipient shape is `{ privateKey, x25519PrivateKey }` — `privateKey`
 * is the ML-KEM-768 PEM, NOT the framework default ML-KEM-1024.
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
    throw new Error("decryptMlkem768X25519 requires { privateKey, x25519PrivateKey } " +
                    "(privateKey is the ML-KEM-768 PEM, x25519PrivateKey is the X25519 PEM)");
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

// ---- Cert-peer envelope primitives ----
//
// The framework's default `encrypt` / `decrypt` source the recipient
// from a published framework keypair (operator owns both halves). The
// cert-peer variants source the recipient from a TLS peer cert (peer
// owns the ECDH P-384 half) plus a peer-supplied ML-KEM-1024 pubkey.
// Wire format is unchanged — the envelope dispatches on the same
// version bytes and KEM ID. Only the input keys differ.
//
// Use cases beyond the b.middleware.apiEncrypt strategy:
//   - Sealed-storage records with peer recipients (operator A seals
//     to operator B's TLS cert + KEM pubkey).
//   - Cross-service messages between cert-identified peers without
//     a shared framework keypair.
//   - Audit log entries tagged with peer recipients.

function _extractEcdhP384FromCert(certDer) {
  // The cert's SubjectPublicKeyInfo carries the ECDH P-384 pubkey when
  // the cert is issued for that curve. node:crypto's X509Certificate
  // exposes `publicKey` as a KeyObject; we only export the SPKI as PEM
  // so the existing `encrypt` path consumes the same shape it accepts
  // for `ecPublicKey`.
  var cert = new nodeCrypto.X509Certificate(certDer);
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

// encryptEnvelopeAsCertPeer — produce a cert-bound envelope for the
// peer identified by their TLS cert + ML-KEM-1024 pubkey.
//
//   var envelope = b.crypto.encryptEnvelopeAsCertPeer(plaintext, {
//     peerCertDer:    Buffer | Uint8Array,    // peer's TLS cert (DER)
//     peerKemPubkey:  string,                  // peer's ML-KEM-1024 pubkey PEM
//   });
/**
 * @primitive b.crypto.encryptEnvelopeAsCertPeer
 * @signature b.crypto.encryptEnvelopeAsCertPeer(plaintext, opts)
 * @since     0.7.0
 * @related   b.crypto.decryptEnvelopeAsCertPeer, b.crypto.encrypt
 *
 * Produces an envelope sealed to a peer identified by their TLS cert
 * (P-384 ECDH half) plus a peer-supplied ML-KEM-1024 pubkey. The wire
 * format is identical to `b.crypto.encrypt` — only the input keys
 * differ. Use for sealed-storage records with peer recipients,
 * cross-service messages between cert-identified peers without a
 * shared framework keypair, or audit-log entries tagged with peer
 * recipients. The cert must carry an ECDH P-384 SubjectPublicKeyInfo
 * — anything else throws `crypto/cert-key-not-ecdh-p384`.
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
  if (typeof opts.peerKemPubkey !== "string") {                                  // allow:inline-require-non-empty-string-validation — crypto module avoids validateOpts dependency to stay minimal
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

// decryptEnvelopeAsCertPeer — decrypt an envelope sealed to this
// operator's TLS cert ECDH-pubkey + ML-KEM-1024 pubkey.
//
//   var plaintext = b.crypto.decryptEnvelopeAsCertPeer(envelope, {
//     certPrivateKey: KeyObject | string,    // this operator's cert P-384 priv
//     kemSecret:      string,                 // this operator's ML-KEM-1024 priv PEM
//   });
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
 * P-384 cert key throws `crypto/cert-key-not-ecdh-p384`. Mirror of
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
  if (typeof opts.kemSecret !== "string") {                                      // allow:inline-require-non-empty-string-validation — crypto module avoids validateOpts dependency to stay minimal
    var e2 = new Error("kemSecret required (operator's ML-KEM-1024 priv PEM)");
    e2.code = "crypto/kem-secret-missing";
    throw e2;
  }
  if (opts.kemSecret.length === 0) {
    var e2b = new Error("kemSecret is empty");
    e2b.code = "crypto/kem-secret-missing";
    throw e2b;
  }
  // Normalize certPrivateKey to PEM string (existing decrypt accepts
  // PEM string).
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

// Operator-audit accessor — exposes every supported KEM hybrid for
// compliance audit visibility ("which envelopes does this deploy
// accept on decrypt?").
// ---- Certificate fingerprint helpers ----
//
// Operators pinning peer-cert fingerprints (mtls bootstrap, webhook
// verification, certificate transparency cross-checks) want a stable
// SHA3-512 hash of the DER bytes plus a colon-separated hex form that
// matches what most operator tooling renders for X.509 fingerprints.
// hashCertFingerprint accepts either a Buffer (DER) or a PEM string;
// if PEM, the BEGIN/END envelope is stripped and the base64 body is
// decoded before hashing. The hash is the framework's standard SHA3-
// 512 (not SHA-256 — operators using OpenSSL's `-sha256` defaults can
// keep their own SHA-256 hashes, this primitive is the framework-
// canonical form). Returns { hex, colon } so callers can compare
// against either rendering.
function _pemToDer(pemOrDer) {
  if (Buffer.isBuffer(pemOrDer)) return pemOrDer;
  if (typeof pemOrDer !== "string") {
    throw new TypeError("crypto.hashCertFingerprint: input must be a Buffer (DER) or a PEM-encoded string");
  }
  // Bound the regex input. The /-----BEGIN .+? -----END/ pattern is
  // lazy-quantified, which CodeQL flags as polynomial-ReDoS
  // (js/polynomial-redos) when fed multi-MB attacker-controlled input
  // — every backtrack step is O(n) and the pattern is on a hot path
  // for mTLS bootstrap / webhook verification / peer-cert pinning.
  // 64 KiB caps the largest plausible PEM (a P-384 cert + chain) at
  // ~3× margin while refusing pathological inputs outright.
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
  // Colon-separated, uppercase — matches openssl x509 -fingerprint
  // output style (which is SHA-1 by default, but the rendering shape
  // operators expect is the same).
  var colon = hex.toUpperCase().match(/.{2}/g).join(":");
  return { hex: hex, colon: colon };
}
// Compares a peer's PEM/DER cert against an allowlist of pinned
// fingerprints. Allowlist entries may be the colon form, the lower-
// case hex form, or both — every comparison runs through
// timingSafeEqual to avoid leaking which entry matched.
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
  for (var i = 0; i < denyList.length; i++) {
    var entry = denyList[i];
    if (typeof entry !== "string" || entry.length === 0) continue;
    var normalized = entry.indexOf(":") !== -1 ? entry.toUpperCase() : entry.toLowerCase();
    var normalizedBuf = entry.indexOf(":") !== -1 ? Buffer.from(normalized) : Buffer.from(normalized, "hex");
    var compareBuf  = entry.indexOf(":") !== -1 ? fpColon : fpHex;
    if (normalizedBuf.length === compareBuf.length &&
        nodeCrypto.timingSafeEqual(normalizedBuf, compareBuf)) {
      return true;
    }
  }
  return false;
}

var SUPPORTED_KEM_ALGORITHMS = Object.freeze([
  { id: "ml-kem-1024",          envelopeId: C.KEM_IDS.ML_KEM_1024,        description: "ML-KEM-1024 KEM-only (legacy single-component)" },
  { id: "ml-kem-1024-p384",     envelopeId: C.KEM_IDS.ML_KEM_1024_P384,   description: "ML-KEM-1024 + ECDH P-384 hybrid (framework default)" },
  { id: "ml-kem-768-x25519",    envelopeId: C.KEM_IDS.ML_KEM_768_X25519,  description: "ML-KEM-768 + X25519 hybrid (IETF / Cloudflare / Chrome TLS 1.3 codepoint 0x11EC)" },
]);

// Note: legacy 0xE1 envelope minting (used only by test round-trip
// coverage) lives at `lib/_test/crypto-fixtures.js` —
// `mintLegacyEnvelope0xE1`. The function is NOT auto-exported on
// `b.crypto.*` because (a) operator code has no production use for
// it (the framework's only contract is READING pre-bump 0xE1 data
// via `decrypt(..., { allowLegacy: true })`), and (b) exposing a
// mint helper widens the attack surface of the `allowLegacy: true`
// decrypt path. Tests require it directly:
//
//   var fixtures = require("blamejs/lib/_test/crypto-fixtures");
//   var blob = fixtures.mintLegacyEnvelope0xE1(plaintext, recipient);

// ---- FIPS 140-3-style power-on self-test ----
//
// Known-answer tests (KATs) for the deterministic primitives — the
// hash / XOF digests are NIST FIPS 202 published vectors, so this
// confirms the framework's hashing matches the standard, not merely
// itself. The PQC algorithms have no seed-injection API (node generates
// the keypair randomness internally), so they get FIPS 140-3 §10.3
// pairwise-consistency + negative tests (a fresh keypair must
// sign->verify / encaps->decaps consistently, and a tampered signature
// must be rejected) rather than a fixed-seed KAT.
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
    assert(timingSafeEqual(hmacSha3(k, "abc"), hmacSha3(k, "abc")), "HMAC-SHA3-512 is not deterministic");
    assert(!timingSafeEqual(hmacSha3(k, "abc"), hmacSha3(k, "abd")), "HMAC-SHA3-512 collided on distinct inputs");
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

  // Post-quantum pairwise-consistency + negative tests. PQC is an
  // optional vendored dependency — a load failure surfaces as a failed
  // check rather than a silent skip.
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
  // Hashing
  sha3Hash:                    sha3Hash,
  hmacSha3:                    hmacSha3,
  hashFile:                    hashFile,
  hashFilesParallel:           hashFilesParallel,
  hashStream:                  hashStream,
  namespaceHash:               namespaceHash,
  kdf:                         kdf,
  // Comparison
  timingSafeEqual:             timingSafeEqual,
  // Cert fingerprint helpers
  hashCertFingerprint:         hashCertFingerprint,
  isCertRevoked:               isCertRevoked,
  // Random
  generateBytes:               generateBytes,
  generateToken:               generateToken,
  randomInt:                   randomInt,
  toBase64Url:                 toBase64Url,
  fromBase64Url:               fromBase64Url,
  // Keys
  generateEncryptionKeyPair:   generateEncryptionKeyPair,
  generateSigningKeyPair:      generateSigningKeyPair,
  generateMlkem768X25519KeyPair: generateMlkem768X25519KeyPair,
  // Signatures
  sign:                        sign,
  verify:                      verify,
  importPublicJwk:             importPublicJwk,
  makeBase64UrlDecoder:        makeBase64UrlDecoder,
  // Envelope encrypt/decrypt
  encrypt:                     encrypt,
  decrypt:                     decrypt,
  encryptMlkem768X25519:       encryptMlkem768X25519,
  decryptMlkem768X25519:       decryptMlkem768X25519,
  encryptEnvelopeAsCertPeer:   encryptEnvelopeAsCertPeer,
  decryptEnvelopeAsCertPeer:   decryptEnvelopeAsCertPeer,
  SUPPORTED_KEM_ALGORITHMS:    SUPPORTED_KEM_ALGORITHMS,
  // Symmetric buffer encrypt/decrypt
  encryptPacked:               encryptPacked,
  decryptPacked:               decryptPacked,
};
