"use strict";
/**
 * b.pqcSoftware — pure-JS post-quantum primitives sourced from the
 * vendored @noble/post-quantum bundle (lib/vendor/noble-post-quantum.cjs).
 *
 * Usable server-side and client-side. Ciphertexts are FIPS 203
 * conformant in both directions — encapsulating with Node's WebCrypto
 * ML-KEM-1024 (used by b.crypto.encrypt / b.middleware.apiEncrypt)
 * decapsulates with b.pqcSoftware.ml_kem_1024 and vice versa.
 *
 * Operator wiring:
 *
 *   - Server-side: import b.pqcSoftware directly. Use it as the
 *     primary PQC path on Node releases without the experimental
 *     WebCrypto ML-KEM extension, or for reference-implementation
 *     interop testing against Node WebCrypto / hardware HSMs.
 *
 *   - Client-side: re-bundle this module or import @noble/post-quantum
 *     directly into the build that ships b.middleware.apiEncrypt.client.
 *
 * Defaults pin to the highest cat-5 level:
 *
 *   - DEFAULT_KEM         = ML-KEM-1024 (FIPS 203)
 *   - DEFAULT_LATTICE_SIG = ML-DSA-87   (FIPS 204)
 *   - DEFAULT_HASH_SIG    = SLH-DSA-SHAKE-256f (FIPS 205)
 *
 * Public surface (b.pqcSoftware.*):
 *
 *   .ml_kem_1024 / .ml_kem_768 / .ml_kem_512   — FIPS 203 KEM objects
 *   .ml_dsa_87 / .ml_dsa_65 / .ml_dsa_44       — FIPS 204 lattice sig
 *   .slh_dsa_shake_256f / 192f / 128f          — FIPS 205 (SHAKE)
 *   .slh_dsa_sha2_256f / 192f / 128f           — FIPS 205 (SHA-2)
 *
 *   .DEFAULT_KEM         — alias to ml_kem_1024
 *   .DEFAULT_LATTICE_SIG — alias to ml_dsa_87
 *   .DEFAULT_HASH_SIG    — alias to slh_dsa_shake_256f
 *
 *   .isAvailable()    — boolean: is the vendored bundle loadable?
 *   .listAlgorithms() — string[] of algorithm names
 *
 * Each KEM / signature object exposes `keygen()` / `encapsulate()` /
 * `decapsulate()` (KEMs) or `keygen()` / `sign()` / `verify()`
 * (signatures), matching the @noble/post-quantum API directly.
 *
 * Operators chaining this into other primitives:
 *
 *   var pqc = b.pqcSoftware;
 *   var kp  = pqc.DEFAULT_KEM.keygen();
 *   var enc = pqc.DEFAULT_KEM.encapsulate(kp.publicKey);
 *   //  enc.cipherText / enc.sharedSecret
 *
 * Note on availability: the bundle is a build artifact in
 * lib/vendor/noble-post-quantum.cjs. In tightly-locked deployments
 * where operators stripped the vendor directory, .isAvailable()
 * returns false and the module exposes a stub that throws on every
 * primitive call.
 */

var { defineClass } = require("./framework-error");
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

function isAvailable() {
  return _load() !== null;
}

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

module.exports = pqc;
