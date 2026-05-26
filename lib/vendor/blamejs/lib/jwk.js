"use strict";
/**
 * @module b.jwk
 * @nav    Identity
 * @title  JWK Thumbprint
 *
 * @intro
 *   Compute the <a href="https://www.rfc-editor.org/rfc/rfc7638">RFC 7638</a>
 *   thumbprint of a JSON Web Key — the canonical, hash-based identifier used
 *   to name a key (DPoP <code>jkt</code> bindings, ACME account-key
 *   thumbprints per RFC 8555, DBSC session pins, and <code>kid</code>
 *   derivation). The thumbprint is
 *   <code>base64url(SHA-256(canonical-JSON))</code>, where the canonical
 *   JSON contains only the key-type's required members, with member names
 *   in lexicographic order and no whitespace — so the same key always
 *   produces the same thumbprint regardless of how its JWK was serialized.
 *
 *   <code>thumbprint(jwk)</code> returns the base64url digest;
 *   <code>canonicalize(jwk)</code> returns the exact JSON string that is
 *   hashed. The standard key types are supported — EC, RSA, oct, and OKP
 *   (RFC 8037 Ed25519 / X25519) — plus AKP, the IANA key type Node uses for
 *   ML-DSA / SLH-DSA post-quantum public keys. SHA-256 is the default;
 *   <code>hash: "sha384" | "sha512"</code> selects a longer digest
 *   (RFC 9278 thumbprint-with-hash).
 *
 * @card
 *   RFC 7638 JWK thumbprint — the canonical
 *   <code>base64url(SHA-256(canonical-JSON))</code> identifier for a JSON
 *   Web Key (EC / RSA / oct / OKP / AKP), behind DPoP <code>jkt</code>,
 *   ACME account keys, and DBSC session pins.
 */

var nodeCrypto = require("node:crypto");
var canonicalJson = require("./canonical-json");
var { defineClass } = require("./framework-error");

var JwkError = defineClass("JwkError", { alwaysPermanent: true });

var HASHES = { sha256: "sha256", sha384: "sha384", sha512: "sha512" };

// RFC 7638 §3.2 + JWA: the required members per key type, which (and only
// which) participate in the thumbprint. Listed for documentation; the
// canonical form is produced with lexicographic ordering regardless.
var REQUIRED = {
  EC:  ["crv", "kty", "x", "y"],
  RSA: ["e", "kty", "n"],
  oct: ["k", "kty"],
  OKP: ["crv", "kty", "x"],   // RFC 8037
  AKP: ["alg", "kty", "pub"], // IANA AKP — ML-DSA / SLH-DSA public keys
};

function _requiredMembers(jwk) {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    throw new JwkError("jwk/bad-jwk", "jwk: must be a JWK object");
  }
  if (typeof jwk.kty !== "string" || jwk.kty.length === 0) {
    throw new JwkError("jwk/bad-jwk", "jwk: 'kty' is required");
  }
  var names = REQUIRED[jwk.kty];
  if (!names) throw new JwkError("jwk/unsupported-kty", "jwk: unsupported kty '" + jwk.kty + "'");
  var out = {};
  for (var i = 0; i < names.length; i++) {
    var n = names[i];
    if (typeof jwk[n] !== "string" || jwk[n].length === 0) {
      throw new JwkError("jwk/bad-jwk", "jwk: " + jwk.kty + " key requires a string '" + n + "' member");
    }
    out[n] = jwk[n];
  }
  return out;
}

/**
 * @primitive  b.jwk.canonicalize
 * @signature  b.jwk.canonicalize(jwk)
 * @since      0.12.68
 * @status     stable
 * @related    b.jwk.thumbprint
 *
 * Return the RFC 7638 canonical JSON string for a JWK — only the key-type's
 * required members, member names in lexicographic order, no whitespace.
 * This is the exact input that <code>thumbprint</code> hashes. Throws
 * <code>JwkError</code> for a missing <code>kty</code>, an unsupported key
 * type, or a missing required member.
 *
 * @example
 *   b.jwk.canonicalize({ kty: "EC", crv: "P-256", x: "...", y: "...", use: "sig" });
 *   // → '{"crv":"P-256","kty":"EC","x":"...","y":"..."}'  (use omitted)
 */
function canonicalize(jwk) {
  return canonicalJson.stringify(_requiredMembers(jwk));
}

/**
 * @primitive  b.jwk.thumbprint
 * @signature  b.jwk.thumbprint(jwk, opts?)
 * @since      0.12.68
 * @status     stable
 * @related    b.jwk.canonicalize
 *
 * Compute the RFC 7638 thumbprint of a JWK:
 * <code>base64url(hash(canonicalJSON))</code>. Only the key-type's required
 * members feed the hash, so optional fields (<code>kid</code>,
 * <code>use</code>, <code>alg</code>, …) never change the result. SHA-256
 * is the default digest; <code>hash</code> selects a longer one. Throws
 * <code>JwkError</code> on an invalid JWK or unknown hash.
 *
 * @opts
 *   hash:   "sha256" | "sha384" | "sha512",   // default: "sha256"
 *
 * @example
 *   b.jwk.thumbprint({ kty: "RSA", e: "AQAB", n: "0vx7ago...DKgw" });
 *   // → "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
 */
function thumbprint(jwk, opts) {
  opts = opts || {};
  var hash = HASHES[opts.hash || "sha256"];
  if (!hash) throw new JwkError("jwk/bad-hash", "jwk.thumbprint: hash must be sha256, sha384, or sha512");
  var canon = canonicalize(jwk);
  return nodeCrypto.createHash(hash).update(canon, "utf8").digest("base64url");
}

module.exports = {
  thumbprint:   thumbprint,
  canonicalize: canonicalize,
  REQUIRED:     REQUIRED,
  JwkError:     JwkError,
};
