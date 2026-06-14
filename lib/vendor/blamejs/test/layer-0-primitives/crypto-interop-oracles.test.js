"use strict";
/**
 * crypto-interop-oracles — prove the framework's "external interop" and
 * "FIPS/NIST" crypto claims against INDEPENDENT oracles, not the
 * framework's own verifier.
 *
 * The advertised surface that this file holds to account:
 *
 *   - b.auth.jws.sign — docstring: "exists strictly for interop with
 *     external ecosystems" (OAuth/OIDC OPs, FAPI, wallets). Every other
 *     test round-trips a token through b.auth.jwt.verifyExternal — the
 *     framework's OWN verifier. Here a from-scratch RFC 7515 verifier
 *     built on node:crypto (no framework code in the verify path) checks
 *     an ES256 and an EdDSA token, proving a third party who never
 *     touches blamejs can verify what blamejs signed.
 *
 *   - b.pqcSoftware.{ml_kem_1024, ml_dsa_87, slh_dsa_shake_256f} — the
 *     module advertises "FIPS-203 / FIPS-204 / FIPS-205" and the
 *     "reference-implementation path for interop tests against Node
 *     WebCrypto or a hardware HSM". b.crypto.selfTest's PQC legs are
 *     pairwise-consistency only (generate a fresh keypair, round-trip it
 *     against itself) and b.pqcSoftware.runKnownAnswerTest's own
 *     docstring concedes it is "a self-consistency gate, NOT the FIPS 203
 *     Appendix A KAT vectors". This file closes that gap two ways:
 *
 *       (a) A frozen cross-implementation KNOWN-ANSWER vector. ML-KEM-1024
 *           keygen + encapsulate are deterministic from a seed (d||z) and
 *           a message (m); the vendored pure-JS @noble/post-quantum bundle
 *           and Node's native OpenSSL-backed ML-KEM — two fully
 *           independent FIPS-203 implementations — agree on the resulting
 *           shared secret. That agreed value is embedded as the expected
 *           answer; the noble primitive must reproduce it byte-for-byte.
 *
 *       (b) A live cross-implementation oracle on every run. The vendored
 *           pure-JS primitive is checked against Node's native OpenSSL
 *           implementation in BOTH directions for ML-KEM (encaps↔decaps),
 *           and the spec answer for the signature families comes FROM
 *           OpenSSL: OpenSSL signs, the framework's noble primitive
 *           verifies (ML-DSA-87 and SLH-DSA-SHAKE-256f), then the
 *           reverse. A pure-JS lattice/hash-sig implementation agreeing
 *           with a C/OpenSSL one is the substance of a KAT — neither
 *           shares code with the other.
 *
 * No bypass: real vendored bundle, real node:crypto, no rejectUnauthorized
 * shortcuts, no require-cache mock of anything under test. The native
 * ML-KEM / ML-DSA / SLH-DSA primitives are an independent implementation,
 * not a stand-in for the thing under test (the vendored noble bundle).
 *
 * Native PQC is a Node-26 surface. Where it is unavailable the live
 * cross-impl legs report a coverage finding and the frozen KAT (which
 * needs no native crypto) still runs — so the FIPS conformance claim is
 * always exercised against at least one off-framework anchor.
 */

var nodeCrypto = require("node:crypto");
var b = require("../..");
var check = require("../helpers/check").check;

// ---------------------------------------------------------------------------
// Independent RFC 7515 compact-JWS verifier — node:crypto only, ZERO
// framework code. This is the "different verifier" the framework's own
// jws.verify is not.
// ---------------------------------------------------------------------------

function b64uToBuf(s) {
  var t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return Buffer.from(t, "base64");
}

// Verify a compact JWS using only node:crypto. Mirrors RFC 7515 §5.2:
// recompute the signing input (ASCII of "<protected>.<payload>"), pick
// the verify parameters from the protected header's alg, and run
// crypto.verify against the operator-supplied public key.
function rfc7515Verify(token, publicKey) {
  var parts = token.split(".");
  if (parts.length !== 3) throw new Error("not a 3-part compact JWS");
  var header = JSON.parse(b64uToBuf(parts[0]).toString("utf8"));
  var signingInput = Buffer.from(parts[0] + "." + parts[1], "ascii");
  var sig = b64uToBuf(parts[2]);
  var alg = header.alg;
  if (alg === "ES256") {
    return {
      header: header,
      valid: nodeCrypto.verify("sha256", signingInput,
        { key: publicKey, dsaEncoding: "ieee-p1363" }, sig),
    };
  }
  if (alg === "ES384") {
    return {
      header: header,
      valid: nodeCrypto.verify("sha384", signingInput,
        { key: publicKey, dsaEncoding: "ieee-p1363" }, sig),
    };
  }
  if (alg === "EdDSA") {
    return { header: header, valid: nodeCrypto.verify(null, signingInput, publicKey, sig) };
  }
  if (alg === "RS256") {
    return { header: header, valid: nodeCrypto.verify("sha256", signingInput, publicKey, sig) };
  }
  throw new Error("independent verifier does not implement alg " + alg);
}

// ---------------------------------------------------------------------------
// Frozen cross-implementation ML-KEM-1024 KNOWN-ANSWER VECTOR.
//
// Derived deterministically (FIPS 203 is deterministic given the keygen
// seed d||z and the encapsulation message m) and confirmed identical by
// BOTH the vendored pure-JS @noble/post-quantum bundle AND Node's native
// OpenSSL ML-KEM-1024. The shared secret below is the value those two
// independent implementations agree on; the framework primitive must
// reproduce it. This anchor needs no native crypto, so it pins the FIPS
// conformance claim even on runtimes that lack native ML-KEM.
// ---------------------------------------------------------------------------

var MLKEM1024_KAT = {
  // 64-byte keygen seed (d || z), FIPS 203 §7.1.
  seedHex: "000102030405060708090a0b0c0d0e0f" +
           "101112131415161718191a1b1c1d1e1f" +
           "202122232425262728292a2b2c2d2e2f" +
           "303132333435363738393a3b3c3d3e3f",
  // 32-byte encapsulation message m, FIPS 203 §7.2.
  msgHex:  "0202020202020202020202020202020202020202020202020202020202020202",
  // Expected 32-byte shared secret K, agreed by noble + OpenSSL.
  sharedSecretHex: "7ca83e2bf9cdbdf7ebe24146efdd9a40a256e83c437d132d2048acf853fbbe46",
};

// ---------------------------------------------------------------------------
// Native-PQC availability probe (Node 26+). Used to gate the live
// cross-impl legs; the frozen KAT runs regardless.
// ---------------------------------------------------------------------------

// Whether this runtime can import an AKP (post-quantum) private key from a JWK
// for the given keygen alg — the exact operation each cross-implementation
// oracle leg performs. The AKP JWK *import* path is Node 26+ for ML-KEM and
// SLH-DSA; only ML-DSA JWK import is wired on the Node 24.14 floor. Probing the
// full generate -> export-to-JWK -> import-from-JWK round-trip (rather than just
// keygen, which exists for every alg on Node 24) lets a leg be SKIPPED — not
// FAILED — on a runtime that cannot perform the import the oracle relies on.
function nativeJwkImportWorks(keygenAlg) {
  try {
    var kp = nodeCrypto.generateKeyPairSync(keygenAlg);
    var jwk = kp.privateKey.export({ format: "jwk" });
    nodeCrypto.createPrivateKey({ key: jwk, format: "jwk" });
    return true;
  } catch (_e) { return false; }
}
function nativeMlKemAvailable() { return nativeJwkImportWorks("ml-kem-1024"); }
function nativeMlDsaAvailable() { return nativeJwkImportWorks("ml-dsa-87"); }
function nativeSlhDsaAvailable() { return nativeJwkImportWorks("slh-dsa-shake-256f"); }

function b64u(buf) { return Buffer.from(buf).toString("base64url"); }

var coverageFindings = [];

function run() {
  var pq = b.pqcSoftware;
  check("vendored PQC bundle is available", pq.isAvailable() === true);

  // =====================================================================
  // (1) b.auth.jws.sign verified by an INDEPENDENT RFC 7515 verifier.
  // =====================================================================

  // --- ES256 ---
  var ecKeys = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var es256Token = b.auth.jws.sign(
    { iss: "blamejs-client", aud: "https://as.example.com", response_type: "code" },
    { privateKey: ecKeys.privateKey, typ: "oauth-authz-req+jwt", kid: "c1" });
  var es256r = rfc7515Verify(es256Token, ecKeys.publicKey);
  check("jws.sign ES256: independent RFC 7515 verifier accepts", es256r.valid === true);
  check("jws.sign ES256: header alg derived from key", es256r.header.alg === "ES256");
  check("jws.sign ES256: typ + kid present in protected header",
    es256r.header.typ === "oauth-authz-req+jwt" && es256r.header.kid === "c1");

  // A tampered payload must fail the independent verifier — proves the
  // verify path actually checks the signature, not just structure.
  var es256Parts = es256Token.split(".");
  var forgedPayload = b64u(Buffer.from(JSON.stringify(
    { iss: "attacker", aud: "https://as.example.com", response_type: "code" }), "utf8"));
  var es256Forged = es256Parts[0] + "." + forgedPayload + "." + es256Parts[2];
  var es256ForgedR = rfc7515Verify(es256Forged, ecKeys.publicKey);
  check("jws.sign ES256: tampered payload rejected by independent verifier",
    es256ForgedR.valid === false);

  // Wrong key must fail — proves the signature binds to the signer's key.
  var otherEc = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  check("jws.sign ES256: wrong public key rejected by independent verifier",
    rfc7515Verify(es256Token, otherEc.publicKey).valid === false);

  // --- EdDSA ---
  var edKeys = nodeCrypto.generateKeyPairSync("ed25519");
  var edToken = b.auth.jws.sign({ sub: "user-42", scope: "openid" }, { privateKey: edKeys.privateKey });
  var edR = rfc7515Verify(edToken, edKeys.publicKey);
  check("jws.sign EdDSA: independent RFC 7515 verifier accepts", edR.valid === true);
  check("jws.sign EdDSA: header alg derived from key", edR.header.alg === "EdDSA");
  check("jws.sign EdDSA: wrong key rejected by independent verifier",
    rfc7515Verify(edToken, nodeCrypto.generateKeyPairSync("ed25519").publicKey).valid === false);

  // --- RS256 ---
  var rsaKeys = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsToken = b.auth.jws.sign({ iss: "rp", aud: "op" }, { privateKey: rsaKeys.privateKey });
  var rsR = rfc7515Verify(rsToken, rsaKeys.publicKey);
  check("jws.sign RS256: independent RFC 7515 verifier accepts", rsR.valid === true);
  check("jws.sign RS256: header alg derived from RSA key", rsR.header.alg === "RS256");

  // =====================================================================
  // (2a) ML-KEM-1024 FROZEN cross-implementation KNOWN-ANSWER vector.
  // The framework primitive must produce the exact spec shared secret
  // that two independent FIPS-203 implementations agree on.
  // =====================================================================

  var katSeed = Buffer.from(MLKEM1024_KAT.seedHex, "hex");
  var katMsg = Buffer.from(MLKEM1024_KAT.msgHex, "hex");
  var katExpected = Buffer.from(MLKEM1024_KAT.sharedSecretHex, "hex");

  check("ML-KEM-1024 KAT: seed is 64 bytes (d||z)", katSeed.length === 64);
  check("ML-KEM-1024 KAT: message is 32 bytes (m)", katMsg.length === 32);

  var katKp = pq.ml_kem_1024.keygen(katSeed);
  check("ML-KEM-1024 KAT: deterministic keygen pk size (FIPS 203 |ek|=1568)",
    katKp.publicKey.length === 1568);
  check("ML-KEM-1024 KAT: deterministic keygen sk size (FIPS 203 |dk|=3168)",
    katKp.secretKey.length === 3168);

  var katEnc = pq.ml_kem_1024.encapsulate(katKp.publicKey, katMsg);
  check("ML-KEM-1024 KAT: ciphertext size (FIPS 203 |c|=1568)",
    katEnc.cipherText.length === 1568);
  check("ML-KEM-1024 KAT: encapsulated shared secret matches frozen spec answer",
    Buffer.from(katEnc.sharedSecret).equals(katExpected));

  var katSs = pq.ml_kem_1024.decapsulate(katEnc.cipherText, katKp.secretKey);
  check("ML-KEM-1024 KAT: decapsulated shared secret matches frozen spec answer",
    Buffer.from(katSs).equals(katExpected));

  // Re-run to assert determinism — a non-deterministic keygen/encaps
  // would make the frozen vector meaningless.
  var katKp2 = pq.ml_kem_1024.keygen(katSeed);
  var katEnc2 = pq.ml_kem_1024.encapsulate(katKp2.publicKey, katMsg);
  check("ML-KEM-1024 KAT: keygen is deterministic from the seed",
    Buffer.from(katKp.publicKey).equals(Buffer.from(katKp2.publicKey)));
  check("ML-KEM-1024 KAT: encapsulate is deterministic from (pk, m)",
    Buffer.from(katEnc.cipherText).equals(Buffer.from(katEnc2.cipherText)));

  // =====================================================================
  // (2b) Live cross-implementation oracle: vendored pure-JS noble bundle
  // vs Node native OpenSSL. Independent in both directions.
  // =====================================================================

  if (nativeMlKemAvailable()) {
    // Cross-check the frozen KAT's public key against OpenSSL too:
    // import noble's (seed, pk) and have OpenSSL decapsulate noble's
    // ciphertext — the independent impl must derive the same secret.
    var natPriv = nodeCrypto.createPrivateKey({
      key: { kty: "AKP", alg: "ML-KEM-1024", priv: b64u(katSeed), pub: b64u(katKp.publicKey) },
      format: "jwk",
    });
    var natDecaps = nodeCrypto.decapsulate(natPriv, Buffer.from(katEnc.cipherText));
    check("ML-KEM-1024 live: OpenSSL accepts noble's deterministic key + ciphertext",
      Buffer.from(natDecaps).equals(katExpected));

    // Fresh random keypair, noble encapsulates -> OpenSSL decapsulates.
    var freshSeed = nodeCrypto.randomBytes(64);
    var freshKp = pq.ml_kem_1024.keygen(freshSeed);
    var freshEnc = pq.ml_kem_1024.encapsulate(freshKp.publicKey);
    var freshPriv = nodeCrypto.createPrivateKey({
      key: { kty: "AKP", alg: "ML-KEM-1024", priv: b64u(freshSeed), pub: b64u(freshKp.publicKey) },
      format: "jwk",
    });
    var ossDecaps = nodeCrypto.decapsulate(freshPriv, Buffer.from(freshEnc.cipherText));
    check("ML-KEM-1024 live: noble encaps -> OpenSSL decaps agree",
      Buffer.from(freshEnc.sharedSecret).equals(Buffer.from(ossDecaps)));

    // Reverse: OpenSSL encapsulates -> noble decapsulates.
    var ossEnc = nodeCrypto.encapsulate(nodeCrypto.createPublicKey(freshPriv));
    var nobleDecaps = pq.ml_kem_1024.decapsulate(ossEnc.ciphertext, freshKp.secretKey);
    check("ML-KEM-1024 live: OpenSSL encaps -> noble decaps agree",
      Buffer.from(ossEnc.sharedKey).equals(Buffer.from(nobleDecaps)));

    // A different keypair must NOT recover the secret — proves the KEM
    // binds the secret to the key, not to the ciphertext shape.
    var wrongSeed = nodeCrypto.randomBytes(64);
    var wrongKp = pq.ml_kem_1024.keygen(wrongSeed);
    var wrongDecaps = pq.ml_kem_1024.decapsulate(freshEnc.cipherText, wrongKp.secretKey);
    check("ML-KEM-1024 live: wrong secret key does not recover the shared secret",
      !Buffer.from(wrongDecaps).equals(Buffer.from(freshEnc.sharedSecret)));
  } else {
    coverageFindings.push("ML-KEM-1024 live cross-impl (Node native OpenSSL) " +
      "unavailable on this runtime — frozen cross-impl KAT still ran.");
  }

  // =====================================================================
  // (3) ML-DSA-87 — spec answer FROM OpenSSL: OpenSSL signs, the
  // framework's noble primitive verifies. Then the reverse.
  // =====================================================================

  if (nativeMlDsaAvailable()) {
    var dsaSeed = nodeCrypto.randomBytes(32);
    var dsaKp = pq.ml_dsa_87.keygen(dsaSeed);
    check("ML-DSA-87: keygen pk size (FIPS 204 |pk|=2592)", dsaKp.publicKey.length === 2592);

    var dsaMsg = Buffer.from("cross-impl ML-DSA-87 known-answer message", "utf8");
    // Import noble's (seed, pk) into OpenSSL; OpenSSL is the signer.
    var dsaNatPriv = nodeCrypto.createPrivateKey({
      key: { kty: "AKP", alg: "ML-DSA-87", priv: b64u(dsaSeed), pub: b64u(dsaKp.publicKey) },
      format: "jwk",
    });
    var ossSig = nodeCrypto.sign(null, dsaMsg, dsaNatPriv);
    check("ML-DSA-87: OpenSSL produced a non-empty signature", ossSig.length > 0);
    // The framework's pure-JS verifier accepts an OpenSSL-produced sig.
    check("ML-DSA-87: noble verifies an OpenSSL-signed message (spec answer = accept)",
      pq.ml_dsa_87.verify(Buffer.from(ossSig), dsaMsg, dsaKp.publicKey) === true);
    // Tamper the OpenSSL signature -> noble must reject.
    var ossSigTamp = Buffer.from(ossSig); ossSigTamp[0] ^= 0xff;
    check("ML-DSA-87: noble rejects a tampered OpenSSL signature",
      pq.ml_dsa_87.verify(ossSigTamp, dsaMsg, dsaKp.publicKey) === false);
    // Wrong message -> noble must reject.
    check("ML-DSA-87: noble rejects an OpenSSL sig over a different message",
      pq.ml_dsa_87.verify(Buffer.from(ossSig),
        Buffer.from("different message", "utf8"), dsaKp.publicKey) === false);

    // Reverse: noble signs -> OpenSSL verifies (spec answer = accept).
    var nobleSig = pq.ml_dsa_87.sign(dsaMsg, dsaKp.secretKey);
    var dsaNatPub = nodeCrypto.createPublicKey(dsaNatPriv);
    check("ML-DSA-87: OpenSSL verifies a noble-signed message",
      nodeCrypto.verify(null, dsaMsg, dsaNatPub, Buffer.from(nobleSig)) === true);
  } else {
    coverageFindings.push("ML-DSA-87 cross-impl (Node native OpenSSL) unavailable " +
      "on this runtime — no off-framework signature oracle exercised for ML-DSA-87.");
  }

  // =====================================================================
  // (4) SLH-DSA-SHAKE-256f — spec answer FROM OpenSSL, same shape.
  // =====================================================================

  if (nativeSlhDsaAvailable()) {
    var slh = pq.slh_dsa_shake_256f;
    var slhKp = slh.keygen();
    check("SLH-DSA-SHAKE-256f: keygen pk size (FIPS 205 |pk|=64)", slhKp.publicKey.length === 64);

    var slhMsg = Buffer.from("cross-impl SLH-DSA-SHAKE-256f known-answer message", "utf8");
    // OpenSSL is the signer. Native SLH-DSA's JWK private field is the
    // full secret key, which matches noble's secretKey byte layout.
    var slhNatPriv = nodeCrypto.createPrivateKey({
      key: { kty: "AKP", alg: "SLH-DSA-SHAKE-256f", priv: b64u(slhKp.secretKey), pub: b64u(slhKp.publicKey) },
      format: "jwk",
    });
    var slhOssSig = nodeCrypto.sign(null, slhMsg, slhNatPriv);
    check("SLH-DSA-SHAKE-256f: OpenSSL produced a non-empty signature", slhOssSig.length > 0);
    check("SLH-DSA-SHAKE-256f: noble verifies an OpenSSL-signed message (spec answer = accept)",
      slh.verify(Buffer.from(slhOssSig), slhMsg, slhKp.publicKey) === true);
    var slhTamp = Buffer.from(slhOssSig); slhTamp[0] ^= 0xff;
    check("SLH-DSA-SHAKE-256f: noble rejects a tampered OpenSSL signature",
      slh.verify(slhTamp, slhMsg, slhKp.publicKey) === false);

    // Reverse: noble signs -> OpenSSL verifies.
    var slhNobleSig = slh.sign(slhMsg, slhKp.secretKey);
    var slhNatPub = nodeCrypto.createPublicKey(slhNatPriv);
    check("SLH-DSA-SHAKE-256f: OpenSSL verifies a noble-signed message",
      nodeCrypto.verify(null, slhMsg, slhNatPub, Buffer.from(slhNobleSig)) === true);
  } else {
    coverageFindings.push("SLH-DSA-SHAKE-256f cross-impl (Node native OpenSSL) " +
      "unavailable on this runtime — no off-framework signature oracle exercised for SLH-DSA.");
  }

  // =====================================================================
  // Coverage findings — where no independent oracle was achievable.
  // COSE_Sign1 (b.cose.sign) and PGP (b.mail.crypto.pgp) are NOT proven
  // here against an external verifier; an independent CBOR Sig_structure
  // reconstruction (COSE) and a GnuPG cross-verify (PGP) are the next
  // oracles to build. b.crypto.selfTest's PQC legs remain
  // pairwise-only — this file is the independent KAT coverage they lack.
  // =====================================================================
  coverageFindings.push("COSE_Sign1 (b.cose.sign) NOT verified against an independent " +
    "oracle here — requires a from-scratch CBOR Sig_structure verifier.");
  coverageFindings.push("PGP (b.mail.crypto.pgp) NOT cross-verified against GnuPG here — " +
    "requires gpg in PATH (not assumed in layer-0).");
  coverageFindings.push("b.crypto.selfTest's ML-KEM/ML-DSA/SLH-DSA legs remain " +
    "pairwise-consistency only; this file supplies the independent-oracle / frozen-KAT coverage.");

  if (coverageFindings.length) {
    console.log("Coverage findings:");
    coverageFindings.forEach(function (f) { console.log("  - " + f); });
  }

  console.log("OK — crypto-interop-oracles tests");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); } catch (e) { console.error(e); process.exit(1); }
}
