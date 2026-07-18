// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto adversarial + malformed-input hardening across the public
 * surface — the error/rejection half of the primitives whose happy path
 * lives in crypto.test.js / crypto-envelope.test.js / crypto-base64url.test.js.
 *
 * Every decrypt / verify assertion here drives the exported consumer path
 * (b.crypto.decrypt / b.crypto.verify / b.crypto.decryptPacked) with a
 * tampered, truncated, wrong-key, wrong-suite, or otherwise hostile input
 * built from real ML-KEM / ML-DSA / SLH-DSA / XChaCha20 fixtures — so the
 * signature-PASSING adversarial shapes (implicit-rejection KEM, bit-flipped
 * AEAD, downgraded suite header) are exercised, not merely parse failures.
 * The security contract under test is fail-CLOSED: a decrypt / verify of a
 * tampered input must reject (throw a typed envelope error, or return false)
 * — never accept, never return a value, never leak a raw runtime error past
 * the module's documented "Invalid envelope: ..." contract.
 *
 * Run standalone: `node test/layer-0-primitives/crypto-adversarial.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- Signature verify: an attacker-controlled signature must NEVER verify
// true and must NEVER throw (the documented contract: false, not an
// exception, on a malformed signature). Driven for both PQC signature
// families the framework auto-detects.
function testVerifyAdversarial() {
  var pair = b.crypto.generateSigningKeyPair();            // ml-dsa-87 default
  var msg  = "audit:row=42|action=delete";
  var sig  = b.crypto.sign(msg, pair.privateKey);
  check("sign→verify round-trips (ml-dsa-87)", b.crypto.verify(msg, sig, pair.publicKey) === true);

  // Every tampered / malformed signature shape → false, no throw.
  var bitflip = Buffer.from(sig); bitflip[0] ^= 0xff;
  check("verify rejects a bit-flipped signature", b.crypto.verify(msg, bitflip, pair.publicKey) === false);
  check("verify rejects a truncated signature",   b.crypto.verify(msg, sig.subarray(0, 100), pair.publicKey) === false);
  check("verify rejects an oversized signature",  b.crypto.verify(msg, Buffer.concat([sig, Buffer.from([1, 2, 3])]), pair.publicKey) === false);
  check("verify rejects an empty signature",      b.crypto.verify(msg, Buffer.alloc(0), pair.publicKey) === false);
  check("verify rejects a garbage signature",     b.crypto.verify(msg, Buffer.from("not-a-signature-at-all"), pair.publicKey) === false);
  check("verify rejects a hex-string signature",  b.crypto.verify(msg, sig.toString("hex"), pair.publicKey) === false);
  check("verify rejects the right sig over tampered data", b.crypto.verify("audit:row=43|action=delete", sig, pair.publicKey) === false);

  // A signature that is valid under a DIFFERENT key must not verify under this one.
  var other = b.crypto.generateSigningKeyPair();
  check("verify rejects a signature from a different keypair", b.crypto.verify(msg, sig, other.publicKey) === false);

  // SLH-DSA-SHAKE-256f — the hash-based family. Round-trip + tamper.
  var slh    = b.crypto.generateSigningKeyPair("slh-dsa-shake-256f");
  var slhSig = b.crypto.sign(msg, slh.privateKey);
  check("sign→verify round-trips (slh-dsa-shake-256f)", b.crypto.verify(msg, slhSig, slh.publicKey) === true);
  var slhBad = Buffer.from(slhSig); slhBad[5] ^= 0xff;
  check("verify rejects a tampered slh-dsa signature", b.crypto.verify(msg, slhBad, slh.publicKey) === false);
  // The two families produce distinctly-sized signatures (auto-detect works
  // off the key PEM, not a caller-passed algorithm id).
  check("ml-dsa and slh-dsa signatures differ in length", sig.length !== slhSig.length);

  // sign() with a public key PEM (operator error) surfaces the failure.
  var signThrew = false;
  try { b.crypto.sign(msg, pair.publicKey); } catch (_e) { signThrew = true; }
  check("sign refuses a public key as the signing key", signThrew);
}

// ---- Envelope decrypt error matrix. Each malformed / hostile envelope
// must reject with the module's typed "Invalid envelope: ..." contract (or
// a Poly1305 tag failure), driven through the public b.crypto.decrypt.
function testDecryptErrorMatrix() {
  var keys = b.crypto.generateEncryptionKeyPair();
  var full = Buffer.from(b.crypto.encrypt("hybrid envelope adversarial body", keys), "base64");

  function decryptThrows(label, buf, keyMaterial, match) {
    var threw = null;
    try { b.crypto.decrypt(buf.toString("base64"), keyMaterial || keys); }
    catch (e) { threw = e; }
    check(label, threw && match.test(threw.message));
  }

  // Unsupported magic byte (neither 0xE1 legacy nor 0xE2 current).
  decryptThrows("decrypt refuses an unsupported magic byte", Buffer.alloc(12), keys, /unsupported format/);
  // Too short to hold the 4-byte suite header.
  decryptThrows("decrypt refuses a header shorter than 4 bytes", Buffer.from([0xE2, 0x03, 0x02]), keys, /too short/);
  // Valid header but truncated at the 2-byte KEM-ct length prefix.
  decryptThrows("decrypt refuses truncation at the length prefix", full.subarray(0, 5), keys, /truncated/);
  // Suite-substitution on the header: unsupported cipher / KDF / KEM id.
  var badCipher = Buffer.from(full); badCipher[2] = 0x09;
  decryptThrows("decrypt refuses an unsupported cipher id", badCipher, keys, /unsupported cipher/);
  var badKdf = Buffer.from(full); badKdf[3] = 0x07;
  decryptThrows("decrypt refuses an unsupported KDF id", badKdf, keys, /unsupported KDF/);
  var badKem = Buffer.from(full); badKem[1] = 0x7A;
  decryptThrows("decrypt refuses an unsupported KEM id", badKem, keys, /unsupported KEM ID/);

  // Hybrid (ML-KEM-1024 + P-384) envelope opened without the EC private key.
  decryptThrows("decrypt refuses a hybrid envelope missing the EC private key",
    full, { privateKey: keys.privateKey }, /Hybrid KEM requires EC private key/);

  // Implicit-rejection KEM: a bit-flip inside the ML-KEM ciphertext yields a
  // DIFFERENT shared secret (FIPS 203 implicit rejection), so the derived key
  // is wrong and the AEAD tag fails — the ciphertext is NOT accepted.
  var tamperedKemCt = Buffer.from(full); tamperedKemCt[7] ^= 0xff;
  decryptThrows("decrypt rejects a tampered KEM ciphertext (implicit rejection → tag failure)",
    tamperedKemCt, keys, /tag|invalid|auth/i);
  // Bit-flip in the trailing AEAD body → Poly1305 failure.
  var tamperedBody = Buffer.from(full); tamperedBody[full.length - 1] ^= 0xff;
  decryptThrows("decrypt rejects a tampered AEAD body", tamperedBody, keys, /tag|invalid|auth/i);

  // Mismatched recipient — a fresh, unrelated keypair cannot open the envelope.
  var wrong = b.crypto.generateEncryptionKeyPair();
  decryptThrows("decrypt rejects a mismatched recipient keypair", full, wrong, /tag|invalid|auth|Decapsulation/i);

  // ML-KEM-768 + X25519 envelope opened through the generic dispatcher
  // without the required x25519 private key.
  var p768 = b.crypto.generateMlkem768X25519KeyPair();
  var env768 = Buffer.from(b.crypto.encryptMlkem768X25519("interop body", {
    mlkemPublicKey:  p768.mlkemPublicKey,
    x25519PublicKey: p768.x25519PublicKey,
  }), "base64");
  decryptThrows("decrypt refuses an ML-KEM-768 envelope missing x25519PrivateKey",
    env768, { privateKey: p768.mlkemPrivateKey }, /requires x25519PrivateKey/);
}

// ---- Truncated-envelope contract (root-fix regression). A truncated
// envelope (untrusted ciphertext) must fail with the typed
// "Invalid envelope: ..." error at EVERY truncation length — never a raw
// RangeError leaking noble-cipher internals past the documented contract,
// the same class the _envU16 bounds check already closes for the length
// prefixes. Before the fix, a truncation landing inside the 24-byte nonce
// or the 16-byte Poly1305 tag surfaced a raw RangeError.
function testTruncationNeverLeaksRangeError() {
  var keys = b.crypto.generateEncryptionKeyPair();
  var plaintext = "truncation probe payload — every offset must reject typed";

  // Exercise all three KEM suites so the shared nonce/tag bounds check is
  // proven across the hybrid, KEM-only, and ML-KEM-768 dispatch arms.
  var p768 = b.crypto.generateMlkem768X25519KeyPair();
  var suites = [
    {
      name: "hybrid ML-KEM-1024 + P-384",
      full: Buffer.from(b.crypto.encrypt(plaintext, keys), "base64"),
      key:  keys,
    },
    {
      name: "KEM-only ML-KEM-1024",
      full: Buffer.from(b.crypto.encrypt(plaintext, keys.publicKey), "base64"),
      key:  { privateKey: keys.privateKey },
    },
    {
      name: "ML-KEM-768 + X25519",
      full: Buffer.from(b.crypto.encryptMlkem768X25519(plaintext, {
        mlkemPublicKey:  p768.mlkemPublicKey,
        x25519PublicKey: p768.x25519PublicKey,
      }), "base64"),
      key:  { privateKey: p768.mlkemPrivateKey, x25519PrivateKey: p768.x25519PrivateKey },
    },
  ];

  for (var s = 0; s < suites.length; s += 1) {
    var suite = suites[s];
    var full = suite.full;
    // Every truncation offset must reject either with the typed
    // "Invalid envelope"/"Invalid packed" contract (a truncation in the header,
    // a length-prefixed KEM ciphertext / ephemeral key, or the nonce/tag
    // region) or with the genuine AEAD "invalid tag" authentication failure (a
    // truncation inside the ciphertext body, where the structure is intact but
    // Poly1305 fails) — NEVER a raw low-level crypto leak: a noble RangeError
    // ("nonce" length) or a Node "Failed to perform decapsulation" / key-parse
    // error from handing an under-length component to Node crypto. The agent's
    // original test caught only RangeError, so the decapsulation leak (a
    // truncation inside the length-prefixed KEM ciphertext, reaching
    // nodeCrypto.decapsulate before the trailing bounds check) slipped through.
    var leaked = null;
    for (var n = full.length - 1; n >= 1 && leaked === null; n -= 1) {
      try { b.crypto.decrypt(full.subarray(0, n).toString("base64"), suite.key); }
      catch (e) {
        var msg = (e && e.message) || String(e);
        if (e instanceof RangeError || !/Invalid envelope|Invalid packed|invalid tag/i.test(msg)) {
          leaked = { n: n, msg: msg };
        }
      }
    }
    check("decrypt rejects every truncation of a " + suite.name +
      " envelope with the typed contract or a genuine AEAD tag failure " +
      "(no raw RangeError / decapsulation error): " +
      (leaked ? leaked.n + "→" + leaked.msg : "clean"),
      leaked === null);

    // A truncation landing inside the nonce/tag region rejects with the
    // typed envelope error (positive lock on the contract, not just the
    // absence of a RangeError). ctLen = plaintext bytes + 16-byte tag; land
    // 4 bytes into the 24-byte nonce.
    var ctLen = Buffer.byteLength(plaintext, "utf8") + 16;
    var inNonce = full.length - ctLen - 4;
    var nonceErr = null;
    try { b.crypto.decrypt(full.subarray(0, inNonce).toString("base64"), suite.key); }
    catch (e) { nonceErr = e; }
    check("decrypt rejects a nonce-region truncation with the typed envelope error (" + suite.name + ")",
      nonceErr && !(nonceErr instanceof RangeError) && /Invalid envelope/.test(nonceErr.message));
  }
}

// ---- KEM-only fallback + raw mode round-trips (positive paths that reach
// the encryptMlkemOnly / ML_KEM_1024 decrypt arm and the raw:true return).
function testKemOnlyAndRawRoundTrips() {
  var keys = b.crypto.generateEncryptionKeyPair();

  // encrypt() with only an ML-KEM public key (string form) drops to KEM-only
  // and still round-trips through the ML_KEM_1024 decrypt arm.
  var sealedStr = b.crypto.encrypt("kem-only via string pubkey", keys.publicKey);
  check("KEM-only (string pubkey) round-trips",
    b.crypto.decrypt(sealedStr, { privateKey: keys.privateKey }) === "kem-only via string pubkey");

  // encrypt() with an object carrying only publicKey (no ecPublicKey) takes
  // the same fallback (and emits the one-shot hybrid_disabled audit).
  var sealedObj = b.crypto.encrypt("kem-only via object", { publicKey: keys.publicKey });
  check("KEM-only (object, no ecPublicKey) round-trips",
    b.crypto.decrypt(sealedObj, { privateKey: keys.privateKey }) === "kem-only via object");

  // decrypt accepts the private key as a bare PEM string too (the
  // `typeof privateKeys === "string" ? privateKeys : privateKeys.privateKey`
  // shape) for the KEM-only suite.
  check("KEM-only decrypt accepts a bare PEM-string private key",
    b.crypto.decrypt(sealedStr, keys.privateKey) === "kem-only via string pubkey");

  // raw:true returns the decrypted Buffer rather than a utf8 string.
  var sealedHybrid = b.crypto.encrypt("binary-carrier body", keys);
  var rawOut = b.crypto.decrypt(sealedHybrid, keys, { raw: true });
  check("decrypt raw:true returns a Buffer", Buffer.isBuffer(rawOut) && rawOut.toString("utf8") === "binary-carrier body");
}

// ---- Symmetric packed decrypt error matrix (b.crypto.decryptPacked).
function testDecryptPackedErrors() {
  var key    = b.crypto.generateBytes(32);
  var packed = b.crypto.encryptPacked(Buffer.from("row-42 column-ssn", "utf8"), key);

  // Round-trip sanity (the happy path lives elsewhere, but anchor the fixture).
  check("encryptPacked→decryptPacked round-trips",
    b.crypto.decryptPacked(packed, key).toString("utf8") === "row-42 column-ssn");

  // Unsupported format byte.
  var badFmt = Buffer.from(packed); badFmt[0] = 0x09;
  var fmtThrew = null;
  try { b.crypto.decryptPacked(badFmt, key); } catch (e) { fmtThrew = e; }
  check("decryptPacked refuses an unsupported format byte",
    fmtThrew && /unsupported version/.test(fmtThrew.message));

  // AAD binding: a ciphertext sealed under one AAD cannot open under another.
  var aadPacked = b.crypto.encryptPacked(Buffer.from("bound cell", "utf8"), key, Buffer.from("patients|42|ssn"));
  var aadThrew = null;
  try { b.crypto.decryptPacked(aadPacked, key, Buffer.from("patients|43|ssn")); } catch (e) { aadThrew = e; }
  check("decryptPacked rejects a mismatched AAD (context binding holds)",
    aadThrew && /tag|invalid|auth/i.test(aadThrew.message));

  // Truncated packed blob (untrusted / corrupt storage cell) — must reject
  // with the typed "Invalid packed format" contract, not a raw RangeError
  // from the nonce/ciphertext subarray (same root as the envelope bounds
  // check).
  var leaked = null;
  for (var n = packed.length - 1; n >= 1 && leaked === null; n -= 1) {
    try { b.crypto.decryptPacked(packed.subarray(0, n), key); }
    catch (e) { if (e instanceof RangeError) leaked = { n: n, msg: e.message }; }
  }
  check("decryptPacked never leaks a raw RangeError on a truncated blob", leaked === null);
  var shortThrew = null;
  try { b.crypto.decryptPacked(Buffer.from([0x02]), key); } catch (e) { shortThrew = e; }
  check("decryptPacked rejects a too-short blob with the typed format error",
    shortThrew && !(shortThrew instanceof RangeError) && /Invalid packed format/.test(shortThrew.message));
}

// ---- base64url strict canonicalization (CWE-347 / CWE-1286). The strict
// decoder is the signature-canonicalization boundary — a length-mod-4-of-1
// shape is impossible for any conforming encoder and must be refused, while
// {strict:false} lets a documented lossy legacy payload through.
function testBase64UrlCanonicalization() {
  var lenOneThrew = null;
  try { b.crypto.fromBase64Url("aGVsbG8AA"); } catch (e) { lenOneThrew = e; }   // 9 chars → len % 4 === 1
  check("fromBase64Url (strict) refuses a length-mod-4-of-1 encoding",
    lenOneThrew instanceof TypeError && /length %% 4 === 1|% 4/.test(lenOneThrew.message));

  // Strict mode still accepts the canonical PADDED form (RFC 4648 §5 allows
  // optional `=` padding) — exercises the trailing-`=` strip before the
  // length check. "AQIDBA==" decodes to the 4 bytes [1,2,3,4].
  var padded = b.crypto.fromBase64Url("AQIDBA==");
  check("fromBase64Url (strict) accepts canonical padded input",
    Buffer.isBuffer(padded) && padded.equals(Buffer.from([1, 2, 3, 4])));

  // {strict:false} tolerates non-canonical input (opt-out escape hatch).
  check("fromBase64Url {strict:false} tolerates non-canonical garbage",
    Buffer.isBuffer(b.crypto.fromBase64Url("!!!", { strict: false })));
  check("fromBase64Url {strict:false} still decodes a canonical value",
    b.crypto.fromBase64Url("aGVsbG8", { strict: false }).toString("utf8") === "hello");
}

// ---- Constant-time compare entry-tier validation (b.crypto.timingSafeEqual).
function testTimingSafeEqualEntryTier() {
  // Length mismatch returns false immediately (length is not a secret).
  check("timingSafeEqual returns false on length mismatch",
    b.crypto.timingSafeEqual("abc", "abcd") === false);
  // Non-string / non-Buffer arguments throw at the entry tier so a
  // toString-poisoned caller cannot redirect the compare through arbitrary bytes.
  var aThrew = null;
  try { b.crypto.timingSafeEqual(42, "x"); } catch (e) { aThrew = e; }
  check("timingSafeEqual refuses a non-Buffer/non-string first argument",
    aThrew instanceof TypeError && /argument 'a'/.test(aThrew.message));
  var bThrew = null;
  try { b.crypto.timingSafeEqual("x", null); } catch (e) { bThrew = e; }
  check("timingSafeEqual refuses a null second argument",
    bThrew instanceof TypeError && /argument 'b'/.test(bThrew.message));
}

// ---- Remaining config-time throws on the hashing surface driven here for
// completeness (namespaceHash CRLF-in-value, hashCertFingerprint oversized
// PEM). Both are entry-tier rejections that keep hostile bytes out of
// derived-column inputs / the ReDoS-bounded PEM parser.
function testHashingSurfaceRejections() {
  var crlfThrew = null;
  try { b.crypto.namespaceHash("bj-email", "line1\r\nline2"); } catch (e) { crlfThrew = e; }
  check("namespaceHash refuses a CR/LF string value (log-injection barrier)",
    crlfThrew instanceof TypeError && /CR \/ LF/.test(crlfThrew.message));

  var oversizedThrew = null;
  try {
    var big = "-----BEGIN CERTIFICATE-----\n" + new Array(70001).join("A") + "\n-----END CERTIFICATE-----";
    b.crypto.hashCertFingerprint(big);
  } catch (e) { oversizedThrew = e; }
  check("hashCertFingerprint refuses an oversized PEM (ReDoS bound)",
    oversizedThrew instanceof TypeError && /exceeds 64 KiB/.test(oversizedThrew.message));

  // generateToken default length is 32 bytes → 64 hex chars.
  var tok = b.crypto.generateToken();
  check("generateToken default is 64 hex chars (32 bytes)", typeof tok === "string" && tok.length === 64 && /^[0-9a-f]+$/.test(tok));
}

function run() {
  testVerifyAdversarial();
  testDecryptErrorMatrix();
  testTruncationNeverLeaksRangeError();
  testKemOnlyAndRawRoundTrips();
  testDecryptPackedErrors();
  testBase64UrlCanonicalization();
  testTimingSafeEqualEntryTier();
  testHashingSurfaceRejections();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[crypto-adversarial] OK — " + helpers.getChecks() + " checks"); }
  catch (e) { console.error(e && e.stack || e); process.exit(1); }
}
