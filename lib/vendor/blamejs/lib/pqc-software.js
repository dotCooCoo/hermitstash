"use strict";
/**
 * @module b.pqcSoftware
 * @nav    Crypto
 * @title  PQC Software
 *
 * @intro
 *   Pure-JS post-quantum cryptography wrapper around the vendored
 *   `@noble/post-quantum` bundle (`lib/vendor/noble-post-quantum.cjs`).
 *   Ships the FIPS-203 ML-KEM family, FIPS-204 ML-DSA family, and
 *   FIPS-205 SLH-DSA family (both SHAKE and SHA-2 hash variants) as
 *   first-class accessors on `b.pqcSoftware.*`.
 *
 *   Defaults pin to the highest category-5 parameter set per family:
 *   `DEFAULT_KEM` = ML-KEM-1024, `DEFAULT_LATTICE_SIG` = ML-DSA-87,
 *   `DEFAULT_HASH_SIG` = SLH-DSA-SHAKE-256f. Ciphertexts are FIPS-203
 *   conformant in both directions — output produced by Node's
 *   WebCrypto ML-KEM-1024 (used by `b.crypto.encrypt` and
 *   `b.middleware.apiEncrypt`) decapsulates here, and vice versa,
 *   making this the reference-implementation path for interop tests
 *   against Node WebCrypto or a hardware HSM.
 *
 *   Each KEM exposes `keygen()` / `encapsulate()` / `decapsulate()`;
 *   each signature object exposes `keygen()` / `sign()` / `verify()`
 *   — both shapes match the upstream `@noble/post-quantum` API
 *   directly, so the module is also re-bundlable into a browser
 *   build that ships `b.middleware.apiEncrypt.client`.
 *
 *   The vendored bundle is a build artifact. In deployments that
 *   stripped `lib/vendor/`, `isAvailable()` returns `false` and every
 *   accessor returns a stub that throws `PqcError` on call —
 *   operators in that posture fall back to Node WebCrypto via
 *   `b.crypto.encrypt` / `b.crypto.decrypt`.
 *
 * @card
 *   Pure-JS post-quantum cryptography wrapper around the vendored `@noble/post-quantum` bundle (`lib/vendor/noble-post-quantum.cjs`).
 */

var { defineClass } = require("./framework-error");
var bCrypto = require("./crypto");
var PqcError = defineClass("PqcError", { alwaysPermanent: true });

var _vendoredOnce = null;
var _loadError    = null;

function _load() {
  if (_vendoredOnce !== null || _loadError !== null) return _vendoredOnce;
  try {
    // Inline-require: deliberate — the vendored bundle is loaded
    // on-demand so deployments that strip lib/vendor/ still boot
    // without crashing on first import of this module. Stub fallback
    // is below.
    _vendoredOnce = require("./vendor/noble-post-quantum.cjs"); // allow:inline-require — graceful-fallback shim
    return _vendoredOnce;
  } catch (e) {
    _loadError = e;
    _vendoredOnce = null;
    return null;
  }
}

function _stubFor(name) {
  return {
    info: { type: name, available: false },
    keygen:      function () { _throwUnavailable(name); },
    encapsulate: function () { _throwUnavailable(name); },
    decapsulate: function () { _throwUnavailable(name); },
    sign:        function () { _throwUnavailable(name); },
    verify:      function () { _throwUnavailable(name); },
  };
}

function _throwUnavailable(name) {
  throw new PqcError("pqc-software/unavailable",
    "b.pqcSoftware." + name + ": vendored bundle lib/vendor/noble-post-quantum.cjs " +
    "could not be loaded (" + (_loadError && _loadError.message || "unknown") + ") — " +
    "if this is a deliberately-stripped deployment, use Node WebCrypto ML-KEM " +
    "(b.crypto.encrypt / decrypt) instead. To restore: " +
    "scripts/vendor-update.sh @noble/post-quantum");
}

function _accessor(name) {
  var bundle = _load();
  if (!bundle) return _stubFor(name);
  var algo = bundle[name];
  if (!algo) return _stubFor(name);
  return algo;
}

/**
 * @primitive b.pqcSoftware.isAvailable
 * @signature b.pqcSoftware.isAvailable()
 * @since     0.7.28
 * @status    stable
 * @related   b.pqcSoftware.listAlgorithms, b.pqcSoftware.runKnownAnswerTest
 *
 * Returns `true` when the vendored `@noble/post-quantum` bundle loaded
 * successfully and its KEM / signature objects are wired into the
 * accessors. Returns `false` when `lib/vendor/noble-post-quantum.cjs`
 * is missing or threw at require time — every accessor in that
 * posture returns a stub whose primitive calls throw `PqcError`.
 *
 * @example
 *   var b = require("blamejs").create();
 *   if (b.pqcSoftware.isAvailable()) {
 *     var ss = b.pqcSoftware.DEFAULT_KEM.keygen();
 *     ss.publicKey.length;
 *     // → 1568 (ML-KEM-1024 public key, FIPS 203 §8 |pk| = 1568)
 *   }
 */
function isAvailable() {
  return _load() !== null;
}

/**
 * @primitive b.pqcSoftware.listAlgorithms
 * @signature b.pqcSoftware.listAlgorithms()
 * @since     0.7.28
 * @status    stable
 * @related   b.pqcSoftware.isAvailable, b.pqcSoftware.runKnownAnswerTest
 *
 * Returns the names of every PQC algorithm exposed on the
 * `b.pqcSoftware` surface — the three ML-KEM parameter sets, the
 * three ML-DSA parameter sets, and six SLH-DSA parameter sets (three
 * SHAKE + three SHA-2). Returns an empty array when the vendored
 * bundle is unavailable.
 *
 * @example
 *   var b = require("blamejs").create();
 *   var names = b.pqcSoftware.listAlgorithms();
 *   names.indexOf("ml_kem_1024") >= 0;
 *   // → true (when the vendored bundle is present)
 */
function listAlgorithms() {
  if (!isAvailable()) return [];
  return [
    "ml_kem_512", "ml_kem_768", "ml_kem_1024",
    "ml_dsa_44",  "ml_dsa_65",  "ml_dsa_87",
    "slh_dsa_sha2_128f",  "slh_dsa_sha2_192f",  "slh_dsa_sha2_256f",
    "slh_dsa_shake_128f", "slh_dsa_shake_192f", "slh_dsa_shake_256f",
  ];
}

// Each accessor delegates to the bundle on demand. Naming follows
// the framework's underscore-separated convention; the bundle uses
// the same names with `_` already, so they map 1:1.
var pqc = {
  PqcError:  PqcError,
  isAvailable:    isAvailable,
  listAlgorithms: listAlgorithms,
};

Object.defineProperty(pqc, "ml_kem_512", {
  enumerable: true,
  get: function () { return _accessor("ml_kem512"); },
});
Object.defineProperty(pqc, "ml_kem_768", {
  enumerable: true,
  get: function () { return _accessor("ml_kem768"); },
});
Object.defineProperty(pqc, "ml_kem_1024", {
  enumerable: true,
  get: function () { return _accessor("ml_kem1024"); },
});
Object.defineProperty(pqc, "ml_dsa_44", {
  enumerable: true,
  get: function () { return _accessor("ml_dsa44"); },
});
Object.defineProperty(pqc, "ml_dsa_65", {
  enumerable: true,
  get: function () { return _accessor("ml_dsa65"); },
});
Object.defineProperty(pqc, "ml_dsa_87", {
  enumerable: true,
  get: function () { return _accessor("ml_dsa87"); },
});
Object.defineProperty(pqc, "slh_dsa_sha2_128f", {
  enumerable: true,
  get: function () { return _accessor("slh_dsa_sha2_128f"); },
});
Object.defineProperty(pqc, "slh_dsa_sha2_192f", {
  enumerable: true,
  get: function () { return _accessor("slh_dsa_sha2_192f"); },
});
Object.defineProperty(pqc, "slh_dsa_sha2_256f", {
  enumerable: true,
  get: function () { return _accessor("slh_dsa_sha2_256f"); },
});
Object.defineProperty(pqc, "slh_dsa_shake_128f", {
  enumerable: true,
  get: function () { return _accessor("slh_dsa_shake_128f"); },
});
Object.defineProperty(pqc, "slh_dsa_shake_192f", {
  enumerable: true,
  get: function () { return _accessor("slh_dsa_shake_192f"); },
});
Object.defineProperty(pqc, "slh_dsa_shake_256f", {
  enumerable: true,
  get: function () { return _accessor("slh_dsa_shake_256f"); },
});

// Security-first defaults — highest level wins.
Object.defineProperty(pqc, "DEFAULT_KEM", {
  enumerable: true,
  get: function () { return _accessor("ml_kem1024"); },
});
Object.defineProperty(pqc, "DEFAULT_LATTICE_SIG", {
  enumerable: true,
  get: function () { return _accessor("ml_dsa87"); },
});
Object.defineProperty(pqc, "DEFAULT_HASH_SIG", {
  enumerable: true,
  get: function () { return _accessor("slh_dsa_shake_256f"); },
});

/**
 * @primitive b.pqcSoftware.runKnownAnswerTest
 * @signature b.pqcSoftware.runKnownAnswerTest()
 * @since     0.7.28
 * @status    stable
 * @related   b.pqcSoftware.isAvailable, b.pqcSoftware.listAlgorithms
 *
 * Round-trips ML-KEM-1024 against itself with a self-generated
 * keypair: `keygen` → `encapsulate` → `decapsulate`, then a
 * constant-time compare of the two shared secrets. This is a self-
 * consistency gate, not the FIPS 203 Appendix A KAT vectors (those
 * ~800 KB of test data are intentionally not vendored). The check
 * fails fast at boot if the vendored bundle is broken, rather than
 * mid-request when an envelope decrypt aborts.
 *
 * Returns `{ ok, reason?, sharedSecretLength? }`. `ok: true` means
 * keygen / encapsulate / decapsulate cycled cleanly and the two
 * shared secrets are byte-identical (32 bytes per FIPS 203 §1).
 *
 * @example
 *   var b = require("blamejs").create();
 *   var result = b.pqcSoftware.runKnownAnswerTest();
 *   result.ok;
 *   // → true (or { ok: false, reason: "<diagnostic>" } when broken)
 */
function runKnownAnswerTest() {
  if (!isAvailable()) {
    return { ok: false, reason: "vendored @noble/post-quantum bundle not loadable" };
  }
  try {
    var kem = _accessor("ml_kem1024");
    var kp = kem.keygen();
    var enc = kem.encapsulate(kp.publicKey);
    var ssAlice = enc.sharedSecret;
    var ssBob = kem.decapsulate(enc.cipherText, kp.secretKey);
    if (!ssAlice || !ssBob) {
      return { ok: false, reason: "keygen/encapsulate/decapsulate returned falsy" };
    }
    if (ssAlice.length !== 32 || ssBob.length !== 32) {                            // allow:raw-byte-literal — FIPS 203 §1 K_size = 32 bytes
      return { ok: false, reason: "shared-secret length mismatch (expected 32 bytes)" };
    }
    // Constant-time compare via the framework wrapper. The KAT runs
    // at boot only, but using the timing-safe path keeps the wider
    // pattern-detector signal clean.
    if (!bCrypto.timingSafeEqual(Buffer.from(ssAlice), Buffer.from(ssBob))) {
      return { ok: false, reason: "shared-secret bytes diverge" };
    }
    return { ok: true, sharedSecretLength: ssAlice.length };
  } catch (e) {
    return { ok: false, reason: "exception: " + (e && e.message) };
  }
}

pqc.runKnownAnswerTest = runKnownAnswerTest;

module.exports = pqc;
