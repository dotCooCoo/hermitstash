// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.cose COSE_Sign1 (RFC 9052) sign/verify over the in-tree
 * b.cbor codec. Classical ECDSA / EdDSA (final COSE ids, useable
 * today) + ML-DSA-87 (draft id, PQC-forward). Bounded decode +
 * crit-bypass + alg-allowlist + tamper + external-aad binding.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var nodeCrypto = require("node:crypto");

var EC = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
var EC384 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
var EC521 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp521r1" });
var ED = nodeCrypto.generateKeyPairSync("ed25519");
var ML = nodeCrypto.generateKeyPairSync("ml-dsa-87");

function testSurface() {
  check("b.cose.sign exposed", typeof b.cose.sign === "function");
  check("b.cose.verify exposed", typeof b.cose.verify === "function");
  check("b.cose.encrypt0 exposed", typeof b.cose.encrypt0 === "function");
  check("b.cose.decrypt0 exposed", typeof b.cose.decrypt0 === "function");
  check("b.cose.ALGORITHMS exposes COSE alg ids", b.cose.ALGORITHMS["ES256"] === -7 && b.cose.ALGORITHMS["ML-DSA-87"] === -50);
  check("b.cose.AEAD_ALGORITHMS exposes AEAD ids", b.cose.AEAD_ALGORITHMS["ChaCha20-Poly1305"] === 24 && b.cose.AEAD_ALGORITHMS["A256GCM"] === 3);
  check("b.cose.COSE_SIGN1_TAG is 18", b.cose.COSE_SIGN1_TAG === 18);
  check("b.cose.COSE_ENCRYPT0_TAG is 16", b.cose.COSE_ENCRYPT0_TAG === 16);
  check("b.cose.CoseError exposed", typeof b.cose.CoseError === "function");
}

function testEncrypt0() {
  var key = b.crypto.generateBytes(32);
  var enc = b.cose.encrypt0(Buffer.from("secret-payload"), { alg: "ChaCha20-Poly1305", key: key });
  check("encrypt0: tagged COSE_Encrypt0 (tag 16 → 0xd0)", enc[0] === 0xd0);
  var d = b.cose.decrypt0(enc, { key: key, algorithms: ["ChaCha20-Poly1305"] });
  check("encrypt0: round-trips plaintext + alg", d.plaintext.toString() === "secret-payload" && d.alg === "ChaCha20-Poly1305");

  var wrongKey = null;
  try { b.cose.decrypt0(enc, { key: b.crypto.generateBytes(32), algorithms: ["ChaCha20-Poly1305"] }); } catch (e) { wrongKey = e; }
  check("decrypt0: wrong key refused", wrongKey && wrongKey.code === "cose/decrypt-failed");

  var t = Buffer.from(enc); t[t.length - 1] ^= 0xff;
  var tampered = null;
  try { b.cose.decrypt0(t, { key: key, algorithms: ["ChaCha20-Poly1305"] }); } catch (e) { tampered = e; }
  check("decrypt0: tampered ciphertext refused", tampered && tampered.code === "cose/decrypt-failed");

  var notAllowed = null;
  try { b.cose.decrypt0(enc, { key: key, algorithms: ["A256GCM"] }); } catch (e) { notAllowed = e; }
  check("decrypt0: alg not in allowlist refused", notAllowed && notAllowed.code === "cose/alg-not-allowed");

  // A256GCM opt-in round-trip.
  var encG = b.cose.encrypt0(Buffer.from("g"), { alg: "A256GCM", key: key });
  check("encrypt0: A256GCM round-trip", b.cose.decrypt0(encG, { key: key, algorithms: ["A256GCM"] }).plaintext.toString() === "g");

  // external_aad must match.
  var encA = b.cose.encrypt0(Buffer.from("z"), { key: key, externalAad: Buffer.from("ctx-A") });
  var aadMismatch = null;
  try { b.cose.decrypt0(encA, { key: key, algorithms: ["ChaCha20-Poly1305"], externalAad: Buffer.from("ctx-B") }); } catch (e) { aadMismatch = e; }
  check("decrypt0: external_aad mismatch refused", aadMismatch && aadMismatch.code === "cose/decrypt-failed");

  // Key-length + algorithms-required validation.
  var badKey = null;
  try { b.cose.encrypt0(Buffer.from("x"), { alg: "A128GCM", key: key }); } catch (e) { badKey = e; }   // 32-byte key for A128GCM (needs 16)
  check("encrypt0: wrong key length refused", badKey && badKey.code === "cose/bad-key");
  var noAlgs = null;
  try { b.cose.decrypt0(enc, { key: key }); } catch (e) { noAlgs = e; }
  check("decrypt0: missing algorithms refused", noAlgs && noAlgs.code === "cose/algorithms-required");

  // Codex P2 on PR #187 — an unprotectedHeaders override of label 5
  // (IV) would emit a token whose stored IV disagrees with the AEAD
  // IV (undecryptable); it must be refused.
  var ivOverride = null;
  try { b.cose.encrypt0(Buffer.from("x"), { key: key, unprotectedHeaders: { 5: Buffer.alloc(12) } }); } catch (e) { ivOverride = e; }
  check("encrypt0: unprotectedHeaders IV override (label 5) refused", ivOverride && ivOverride.code === "cose/reserved-header");
  // A non-IV unprotected header is still allowed + surfaced.
  var withHdr = b.cose.encrypt0(Buffer.from("x"), { key: key, unprotectedHeaders: { 4: Buffer.from("kid-1") } });
  check("encrypt0: non-IV unprotected header preserved", b.cose.decrypt0(withHdr, { key: key, algorithms: ["ChaCha20-Poly1305"] }).unprotectedHeaders.get(4).toString() === "kid-1");
}

async function testClassicalUseableToday() {
  var s = await b.cose.sign(Buffer.from("hello"), { alg: "ES256", privateKey: EC.privateKey, kid: "k1" });
  check("ES256: output is a tagged COSE_Sign1 (tag 18 → 0xd2)", s[0] === 0xd2);
  var v = await b.cose.verify(s, { algorithms: ["ES256"], publicKey: EC.publicKey });
  check("ES256: round-trips payload + alg", v.payload.toString() === "hello" && v.alg === "ES256");
  check("ES256: kid surfaced in unprotected headers", Buffer.isBuffer(v.unprotectedHeaders.get(4)) && v.unprotectedHeaders.get(4).toString() === "k1");
  check("ES256: alg in protected header", v.protectedHeaders.get(1) === -7);

  var sed = await b.cose.sign("msg", { alg: "EdDSA", privateKey: ED.privateKey });
  check("EdDSA: round-trips (string payload → bstr)", (await b.cose.verify(sed, { algorithms: ["EdDSA"], publicKey: ED.publicKey })).payload.toString() === "msg");
}

async function testProtectedHeaders() {
  // Extra integrity-protected headers (numeric labels) ride in the
  // protected map and are covered by the signature — a CWT_Claims map
  // (label 15) is the SCITT case.
  var cwtClaims = new Map([[1, "iss.example"], [2, "subject-id"]]);
  var s = await b.cose.sign(Buffer.from("artifact"), {
    alg: "ES256", privateKey: EC.privateKey,
    protectedHeaders: { 15: cwtClaims }, contentType: "application/spdx+json",
  });
  var v = await b.cose.verify(s, { algorithms: ["ES256"], publicKey: EC.publicKey });
  check("protectedHeaders: label 15 (CWT_Claims) in protected map", v.protectedHeaders.get(15) instanceof Map && v.protectedHeaders.get(15).get(1) === "iss.example");
  check("protectedHeaders: string content-type (label 3) preserved", v.protectedHeaders.get(3) === "application/spdx+json");

  // alg (label 1) is reserved — protectedHeaders cannot override it.
  var reserved = null;
  try {
    await b.cose.sign(Buffer.from("x"), { alg: "ES256", privateKey: EC.privateKey, protectedHeaders: { 1: -7 } });
  } catch (e) { reserved = e; }
  check("protectedHeaders: setting label 1 (alg) refused", reserved && reserved.code === "cose/reserved-header");

  // A protected-header object accepts a Map too (integer keys preserved).
  var sMap = await b.cose.sign(Buffer.from("y"), {
    alg: "ES256", privateKey: EC.privateKey, protectedHeaders: new Map([[15, cwtClaims]]),
  });
  var vMap = await b.cose.verify(sMap, { algorithms: ["ES256"], publicKey: EC.publicKey });
  check("protectedHeaders: Map input round-trips", vMap.protectedHeaders.get(15).get(2) === "subject-id");
}

async function testPqcForward() {
  var s = await b.cose.sign(Buffer.from("pqc"), { alg: "ML-DSA-87", privateKey: ML.privateKey });
  var v = await b.cose.verify(s, { algorithms: ["ML-DSA-87"], publicKey: ML.publicKey });
  check("ML-DSA-87: round-trips (COSE alg -50, draft)", v.payload.toString() === "pqc" && v.alg === "ML-DSA-87" && v.protectedHeaders.get(1) === -50);
}

async function testTamperAndAllowlist() {
  var s = await b.cose.sign(Buffer.from("data"), { alg: "ES256", privateKey: EC.privateKey });
  var t = Buffer.from(s); t[t.length - 1] ^= 0xff;
  var tampered = null;
  try { await b.cose.verify(t, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { tampered = e; }
  check("verify: tampered signature refused", tampered && tampered.code === "cose/bad-signature");

  var notAllowed = null;
  try { await b.cose.verify(s, { algorithms: ["EdDSA"], publicKey: EC.publicKey }); } catch (e) { notAllowed = e; }
  check("verify: alg not in allowlist refused", notAllowed && notAllowed.code === "cose/alg-not-allowed");

  // external_aad must match what was signed.
  var sa = await b.cose.sign(Buffer.from("d"), { alg: "ES256", privateKey: EC.privateKey, externalAad: Buffer.from("ctx-A") });
  var aadMismatch = null;
  try { await b.cose.verify(sa, { algorithms: ["ES256"], publicKey: EC.publicKey, externalAad: Buffer.from("ctx-B") }); } catch (e) { aadMismatch = e; }
  check("verify: external_aad mismatch refused", aadMismatch && aadMismatch.code === "cose/bad-signature");
  var aadOk = await b.cose.verify(sa, { algorithms: ["ES256"], publicKey: EC.publicKey, externalAad: Buffer.from("ctx-A") });
  check("verify: matching external_aad accepted", aadOk.payload.toString() === "d");
}

async function testCritBypassDefense() {
  // Craft a COSE_Sign1 whose protected header lists an unknown crit
  // label (99). The crit check fires before signature verification —
  // an unknown mandatory label must be refused (RFC 9052 §3.1).
  var protMap = new Map([[1, -7], [2, [99]]]);
  var protectedBstr = b.cbor.encode(protMap);
  var arr = [protectedBstr, new Map(), Buffer.from("p"), Buffer.from([0, 0])];
  var coseBytes = b.cbor.encode(new b.cbor.Tag(18, arr));
  var refused = null;
  try { await b.cose.verify(coseBytes, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { refused = e; }
  check("verify: unknown crit label refused (crit-bypass defense)", refused && refused.code === "cose/crit-unknown");
}

async function testValidation() {
  var bads = [
    [function () { return b.cose.sign(Buffer.from("x"), { alg: "SLH-DSA-SHAKE-256f", privateKey: ML.privateKey }); }, "cose/unsignable-alg"],
    [function () { return b.cose.sign(Buffer.from("x"), { alg: "ES256" }); }, "cose/no-key"],
    [function () { return b.cose.verify(Buffer.from([0x84]), { publicKey: EC.publicKey }); }, "cose/algorithms-required"],
    [function () { return b.cose.verify(Buffer.from([0x84]), { algorithms: ["ES256"] }); }, "cose/no-key"],
  ];
  var ok = true;
  for (var i = 0; i < bads.length; i++) {
    var caught = null;
    try { await bads[i][0](); } catch (e) { caught = e; }
    if (!caught || caught.code !== bads[i][1]) { ok = false; check("validation " + i + " expected " + bads[i][1] + " got " + (caught && caught.code), false); }
  }
  check("sign/verify: malformed args throw the right codes", ok);

  // A detached (nil) payload without opts.externalPayload is refused.
  var protBstr = b.cbor.encode(new Map([[1, -7]]));
  var detached = b.cbor.encode(new b.cbor.Tag(18, [protBstr, new Map(), null, Buffer.from([0, 0])]));
  var det = null;
  try { await b.cose.verify(detached, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { det = e; }
  check("verify: detached payload without externalPayload refused", det && det.code === "cose/detached-no-payload");

  // Codex P2 on PR #184 — a non-byte payload (text string here) must
  // be refused, not returned as a non-Buffer.
  var textPayload = b.cbor.encode(new b.cbor.Tag(18, [protBstr, new Map(), "not-bytes", Buffer.from([0, 0])]));
  var np = null;
  try { await b.cose.verify(textPayload, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { np = e; }
  check("verify: non-byte payload refused", np && np.code === "cose/malformed");

  // Codex P2 on PR #184 — a non-map unprotected header must be refused,
  // not silently coerced to empty.
  var badUnprot = b.cbor.encode(new b.cbor.Tag(18, [protBstr, ["array-not-map"], Buffer.from("p"), Buffer.from([0, 0])]));
  var bu = null;
  try { await b.cose.verify(badUnprot, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { bu = e; }
  check("verify: non-map unprotected header refused", bu && bu.code === "cose/malformed");
}

async function testDetachedPayload() {
  var payload = Buffer.from("detached COSE payload", "utf8");
  var det = await b.cose.sign(payload, { alg: "ES256", privateKey: EC.privateKey, detached: true });
  // payload slot must be nil
  var arr = b.cbor.decode(det, { allowedTags: [18] }).value;
  check("detached: payload slot is nil", arr[2] === null);
  var out = await b.cose.verify(det, { algorithms: ["ES256"], publicKey: EC.publicKey, externalPayload: payload });
  check("detached: verify with externalPayload returns it", out.payload.equals(payload));

  var noPay = null;
  try { await b.cose.verify(det, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { noPay = e; }
  check("detached: verify without externalPayload refused", noPay && noPay.code === "cose/detached-no-payload");

  var wrong = null;
  try { await b.cose.verify(det, { algorithms: ["ES256"], publicKey: EC.publicKey, externalPayload: Buffer.from("x") }); } catch (e) { wrong = e; }
  check("detached: wrong externalPayload fails signature", wrong && wrong.code === "cose/bad-signature");

  // attached token + externalPayload is ambiguous
  var att = await b.cose.sign(payload, { alg: "ES256", privateKey: EC.privateKey });
  var amb = null;
  try { await b.cose.verify(att, { algorithms: ["ES256"], publicKey: EC.publicKey, externalPayload: payload }); } catch (e) { amb = e; }
  check("detached: externalPayload on an attached token refused", amb && amb.code === "cose/payload-ambiguous");
}

async function testImportKey() {
  // EC2 P-256 COSE_Key built from the JWK, then used to verify.
  var jwk = EC.publicKey.export({ format: "jwk" });
  var coseKey = new Map([[1, 2], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]);
  var imported = b.cose.importKey(coseKey);
  check("importKey: EC2 P-256 matches the JWK x", imported.export({ format: "jwk" }).x === jwk.x);
  var att = await b.cose.sign(Buffer.from("k"), { alg: "ES256", privateKey: EC.privateKey });
  check("importKey: imported key verifies a COSE_Sign1", (await b.cose.verify(att, { algorithms: ["ES256"], publicKey: imported })).payload.toString() === "k");

  // OKP Ed25519
  var ejwk = ED.publicKey.export({ format: "jwk" });
  var okp = new Map([[1, 1], [-1, 6], [-2, Buffer.from(ejwk.x, "base64url")]]);
  check("importKey: OKP Ed25519", b.cose.importKey(okp).asymmetricKeyType === "ed25519");

  // unsupported curve / kty refused
  var bad = null;
  try { b.cose.importKey(new Map([[1, 2], [-1, 99], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]])); } catch (e) { bad = e; }
  check("importKey: unsupported EC2 curve refused", bad && bad.code === "cose/unsupported-key");
  var badKty = null;
  try { b.cose.importKey(new Map([[1, 4], [-2, Buffer.from(jwk.x, "base64url")]])); } catch (e) { badKty = e; }
  check("importKey: unsupported kty refused", badKty && (badKty.code === "cose/unsupported-key" || badKty.code === "cose/bad-cose-key"));

  // secp256k1 (crv id 8) is refused — b.cose has no ES256K path, so
  // accepting it would let it verify under ES256 (alg/curve mis-binding).
  var k1 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  var k1jwk = k1.publicKey.export({ format: "jwk" });
  var secpBad = null;
  try { b.cose.importKey(new Map([[1, 2], [-1, 8], [-2, Buffer.from(k1jwk.x, "base64url")], [-3, Buffer.from(k1jwk.y, "base64url")]])); } catch (e) { secpBad = e; }
  check("importKey: secp256k1 refused (no ES256K binding)", secpBad && secpBad.code === "cose/unsupported-key");

  // A plain object (integer-string keys) is coerced to a COSE_Key map and
  // imports the same key — the non-Map input path.
  var objKey = { 1: 2, "-1": 1, "-2": Buffer.from(jwk.x, "base64url"), "-3": Buffer.from(jwk.y, "base64url") };
  check("importKey: plain-object COSE_Key coerced + imported", b.cose.importKey(objKey).asymmetricKeyType === "ec");

  // A non-object / non-map (number, array) is refused rather than coerced.
  var notObj = null;
  try { b.cose.importKey(42); } catch (e) { notObj = e; }
  check("importKey: non-object COSE_Key refused", notObj && notObj.code === "cose/bad-cose-key");
  var arrKey = null;
  try { b.cose.importKey([1, 2, 3]); } catch (e) { arrKey = e; }
  check("importKey: array COSE_Key refused", arrKey && arrKey.code === "cose/bad-cose-key");

  // OKP with a non-Ed25519 curve id is refused.
  var okpBad = null;
  try { b.cose.importKey(new Map([[1, 1], [-1, 99], [-2, Buffer.alloc(32)]])); } catch (e) { okpBad = e; }
  check("importKey: OKP non-Ed25519 curve refused", okpBad && okpBad.code === "cose/unsupported-key");
}

async function testExportKey() {
  // EC2 P-256 → COSE_Key bytes → decode → importKey round-trips, and
  // the re-imported key verifies a COSE_Sign1 the original signed.
  var bytes = b.cose.exportKey(EC.publicKey, { alg: "ES256", kid: "key-1" });
  check("exportKey: returns CBOR bytes", Buffer.isBuffer(bytes));
  var map = b.cbor.decode(bytes);
  check("exportKey: kty=EC2 (2)", map.get(1) === 2);
  check("exportKey: crv=P-256 (1)", map.get(-1) === 1);
  check("exportKey: x matches the JWK", map.get(-2).toString("base64url") === EC.publicKey.export({ format: "jwk" }).x);
  check("exportKey: alg label 3 = ES256 (-7)", map.get(3) === -7);
  check("exportKey: kid label 2 = 'key-1'", Buffer.isBuffer(map.get(2)) && map.get(2).toString("utf8") === "key-1");
  var reimported = b.cose.importKey(map);
  var att = await b.cose.sign(Buffer.from("rt"), { alg: "ES256", privateKey: EC.privateKey });
  check("exportKey → importKey: round-trips for verification",
    (await b.cose.verify(att, { algorithms: ["ES256"], publicKey: reimported })).payload.toString() === "rt");

  // OKP Ed25519 round-trip.
  var edBytes = b.cose.exportKey(ED.publicKey);
  var edMap = b.cbor.decode(edBytes);
  check("exportKey: OKP kty=1 + crv Ed25519 (6)", edMap.get(1) === 1 && edMap.get(-1) === 6);
  check("exportKey: OKP re-imports to ed25519",
    b.cose.importKey(edMap).asymmetricKeyType === "ed25519");

  // A private key exports its PUBLIC half (never the secret).
  var fromPriv = b.cbor.decode(b.cose.exportKey(EC.privateKey));
  check("exportKey: private key exports the public coordinates",
    fromPriv.get(-2).toString("base64url") === EC.publicKey.export({ format: "jwk" }).x);

  // Unsupported curve / key type / bad opts refused.
  var k1 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  var secpBad = null;
  try { b.cose.exportKey(k1.publicKey); } catch (e) { secpBad = e; }
  check("exportKey: secp256k1 refused", secpBad && secpBad.code === "cose/unsupported-key");
  var notKey = null;
  try { b.cose.exportKey({ not: "a key" }); } catch (e) { notKey = e; }
  check("exportKey: non-KeyObject refused", notKey && notKey.code === "cose/bad-key");
  var badAlg = null;
  try { b.cose.exportKey(EC.publicKey, { alg: "NOPE" }); } catch (e) { badAlg = e; }
  check("exportKey: unknown alg refused", badAlg && badAlg.code === "cose/unknown-alg");

  // An OKP key on a non-Ed25519 curve (X25519) has no COSE alg here and
  // is refused rather than emitting a COSE_Key no verifier would accept.
  var x = nodeCrypto.generateKeyPairSync("x25519");
  var xBad = null;
  try { b.cose.exportKey(x.publicKey); } catch (e) { xBad = e; }
  check("exportKey: X25519 (OKP non-Ed25519) refused", xBad && xBad.code === "cose/unsupported-key");

  // A non-EC / non-OKP key type (RSA) is refused.
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaBad = null;
  try { b.cose.exportKey(rsa.publicKey); } catch (e) { rsaBad = e; }
  check("exportKey: RSA key type refused", rsaBad && rsaBad.code === "cose/unsupported-key");

  // kid supplied as a Buffer is stored verbatim as COSE_Key label 2.
  var kidBuf = Buffer.from([0x01, 0x02, 0x03]);
  var withKidBuf = b.cbor.decode(b.cose.exportKey(EC.publicKey, { kid: kidBuf }));
  check("exportKey: Buffer kid stored as label 2", Buffer.isBuffer(withKidBuf.get(2)) && withKidBuf.get(2).equals(kidBuf));

  // kid that is neither a Buffer nor a string is refused.
  var badKid = null;
  try { b.cose.exportKey(EC.publicKey, { kid: 123 }); } catch (e) { badKid = e; }
  check("exportKey: non-Buffer/string kid refused", badKid && badKid.code === "cose/bad-kid");
}

async function testAlgKeyTypeConfusion() {
  // Null-digest alg/key-type confusion: EdDSA and ML-DSA-87 both sign
  // with a null digest, so node:crypto dispatches verify() on the KEY
  // type and ignores the declared COSE alg. Without a key-type binding an
  // EdDSA signature is accepted under an ML-DSA-87-only ("PQC-only")
  // allowlist, and an ML-DSA-87 signature under an EdDSA-only allowlist —
  // a full alg-allowlist bypass (the allowlist is the security control).
  // The forged bytes are built by hand because b.cose.sign now refuses to
  // emit a mislabeled token.
  function forge(algId, signKey, payloadStr) {
    var protectedBstr = b.cbor.encode(new Map([[1, algId]]));
    var payload = Buffer.from(payloadStr, "utf8");
    var ss = b.cbor.encode(["Signature1", protectedBstr, Buffer.alloc(0), payload]);
    var sig = nodeCrypto.sign(null, ss, signKey);
    return b.cbor.encode(new b.cbor.Tag(18, [protectedBstr, new Map(), payload, sig]));
  }
  // EdDSA signature, DECLARED ML-DSA-87 (-50), verified against an
  // Ed25519 key under a PQC-only allowlist.
  var e1 = null;
  try { await b.cose.verify(forge(-50, ED.privateKey, "forged"), { algorithms: ["ML-DSA-87"], publicKey: ED.publicKey }); } catch (e) { e1 = e; }
  check("verify: EdDSA sig rejected under ML-DSA-87-only allowlist (alg/key confusion)", e1 && e1.code === "cose/alg-key-mismatch");

  // ML-DSA-87 signature, DECLARED EdDSA (-8), verified against an ML-DSA
  // key under an EdDSA-only allowlist.
  var e2 = null;
  try { await b.cose.verify(forge(-8, ML.privateKey, "forged2"), { algorithms: ["EdDSA"], publicKey: ML.publicKey }); } catch (e) { e2 = e; }
  check("verify: ML-DSA-87 sig rejected under EdDSA-only allowlist (alg/key confusion)", e2 && e2.code === "cose/alg-key-mismatch");

  // Sign side: naming one alg but supplying the other key type must be
  // refused, never emit a mislabeled token.
  var e3 = null;
  try { await b.cose.sign(Buffer.from("x"), { alg: "EdDSA", privateKey: ML.privateKey }); } catch (e) { e3 = e; }
  check("sign: EdDSA alg with an ML-DSA key refused (no mislabeled token)", e3 && e3.code === "cose/alg-key-mismatch");
  var e4 = null;
  try { await b.cose.sign(Buffer.from("x"), { alg: "ML-DSA-87", privateKey: ED.privateKey }); } catch (e) { e4 = e; }
  check("sign: ML-DSA-87 alg with an Ed25519 key refused", e4 && e4.code === "cose/alg-key-mismatch");

  // Regression: the legitimate pairings still verify.
  var okEd = await b.cose.sign(Buffer.from("ed-ok"), { alg: "EdDSA", privateKey: ED.privateKey });
  check("EdDSA legit pairing still verifies", (await b.cose.verify(okEd, { algorithms: ["EdDSA"], publicKey: ED.publicKey })).payload.toString() === "ed-ok");
  var okMl = await b.cose.sign(Buffer.from("ml-ok"), { alg: "ML-DSA-87", privateKey: ML.privateKey });
  check("ML-DSA-87 legit pairing still verifies", (await b.cose.verify(okMl, { algorithms: ["ML-DSA-87"], publicKey: ML.publicKey })).payload.toString() === "ml-ok");
}

async function testEcAlgCurveVerify() {
  // A COSE_Sign1 DECLARING ES512 (-36) but carrying a P-256 key: node
  // verifies a sha512 signature against the P-256 key as self-consistent,
  // so the alg->curve binding must refuse it even when ES512 is
  // allowlisted (RFC 9053 §2 alg/curve confusion).
  var protectedBstr = b.cbor.encode(new Map([[1, -36]]));
  var payload = Buffer.from("es512-over-p256");
  var ss = b.cbor.encode(["Signature1", protectedBstr, Buffer.alloc(0), payload]);
  var sig = nodeCrypto.sign("sha512", ss, { key: EC.privateKey, dsaEncoding: "ieee-p1363" });
  var forged = b.cbor.encode(new b.cbor.Tag(18, [protectedBstr, new Map(), payload, sig]));
  var refused = null;
  try { await b.cose.verify(forged, { algorithms: ["ES512"], publicKey: EC.publicKey }); } catch (e) { refused = e; }
  check("verify: ES512 declared over a P-256 key refused (alg/curve binding)", refused && refused.code === "cose/alg-curve-mismatch");
}

async function testUnprotectedAlgNotHonored() {
  // alg (label 1) is integrity-read from the PROTECTED header only. A
  // token with an empty protected header but a valid-looking alg smuggled
  // into the UNPROTECTED bucket must NOT be honored — it is refused as an
  // unknown protected alg, never verified under the smuggled alg (even
  // though the signature and key would otherwise match).
  var payload = Buffer.from("no-protected-alg");
  var ss = b.cbor.encode(["Signature1", Buffer.alloc(0), Buffer.alloc(0), payload]);
  var sig = nodeCrypto.sign(null, ss, ED.privateKey);
  var forged = b.cbor.encode(new b.cbor.Tag(18, [Buffer.alloc(0), new Map([[1, -8]]), payload, sig]));
  var refused = null;
  try { await b.cose.verify(forged, { algorithms: ["EdDSA"], publicKey: ED.publicKey }); } catch (e) { refused = e; }
  check("verify: alg in the unprotected bucket is not honored", refused && refused.code === "cose/unknown-alg");
}

async function testBareUntagged() {
  // RFC 9052 permits an untagged COSE_Sign1 (a bare 4-element array). The
  // verifier accepts both the tagged (18) and bare forms.
  var tagged = await b.cose.sign(Buffer.from("bare"), { alg: "ES256", privateKey: EC.privateKey });
  var arr = b.cbor.decode(tagged, { allowedTags: [18] }).value;
  var bare = b.cbor.encode(arr);
  check("verify: bare form is a raw CBOR array (no 0xd2 tag)", bare[0] !== 0xd2);
  var out = await b.cose.verify(bare, { algorithms: ["ES256"], publicKey: EC.publicKey });
  check("verify: bare (untagged) COSE_Sign1 verifies", out.payload.toString() === "bare");
}

async function testKeyResolver() {
  // keyResolver receives the protected + unprotected header maps and
  // returns the verification key (kid resolution). The resolved key still
  // goes through the alg/key binding.
  var s = await b.cose.sign(Buffer.from("resolve-me"), { alg: "ES256", privateKey: EC.privateKey, kid: "kr-1" });
  var seenKid = null, sawProt = false;
  var out = await b.cose.verify(s, {
    algorithms: ["ES256"],
    keyResolver: function (prot, unprot) {
      sawProt = (prot instanceof Map) && prot.get(1) === -7;
      var kid = unprot.get(4);
      seenKid = Buffer.isBuffer(kid) ? kid.toString("utf8") : null;
      return EC.publicKey;
    },
  });
  check("keyResolver: resolves the key and verifies", out.payload.toString() === "resolve-me");
  check("keyResolver: called with protected + unprotected maps (kid read)", sawProt && seenKid === "kr-1");

  // Resolver returning the WRONG key → signature refused (not fail-open).
  var wrongEc = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var bad = null;
  try { await b.cose.verify(s, { algorithms: ["ES256"], keyResolver: function () { return wrongEc.publicKey; } }); } catch (e) { bad = e; }
  check("keyResolver: wrong resolved key refused", bad && bad.code === "cose/bad-signature");

  // Resolver returning a wrong-curve key for the declared ES256 → refused
  // by the alg/curve binding, not verified.
  var p384 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  var mismatch = null;
  try { await b.cose.verify(s, { algorithms: ["ES256"], keyResolver: function () { return p384.publicKey; } }); } catch (e) { mismatch = e; }
  check("keyResolver: wrong-curve resolved key refused (alg/curve binding)", mismatch && mismatch.code === "cose/alg-curve-mismatch");
}

async function testMalformedVerifyBranches() {
  var protBstr = b.cbor.encode(new Map([[1, -7]]));
  var sig = Buffer.from([0, 0]);
  var payload = Buffer.from("p");
  async function code(bytes) {
    try { await b.cose.verify(bytes, { algorithms: ["ES256"], publicKey: EC.publicKey }); return null; }
    catch (e) { return e.code; }
  }
  check("verify: wrong array length refused",
    (await code(b.cbor.encode(new b.cbor.Tag(18, [protBstr, new Map(), payload])))) === "cose/malformed");
  check("verify: non-bstr protected header refused",
    (await code(b.cbor.encode(new b.cbor.Tag(18, [new Map(), new Map(), payload, sig])))) === "cose/malformed");
  check("verify: non-bstr signature refused",
    (await code(b.cbor.encode(new b.cbor.Tag(18, [protBstr, new Map(), payload, "not-bytes"])))) === "cose/malformed");
  check("verify: protected header that is not a CBOR map refused",
    (await code(b.cbor.encode(new b.cbor.Tag(18, [b.cbor.encode([1, 2, 3]), new Map(), payload, sig])))) === "cose/malformed");
  check("verify: crit (label 2) not an array refused",
    (await code(b.cbor.encode(new b.cbor.Tag(18, [b.cbor.encode(new Map([[1, -7], [2, 99]])), new Map(), payload, sig])))) === "cose/bad-crit");
  // crit names an understood label (3 = content-type) that is ABSENT from
  // the protected header — a crit that references nothing must be refused.
  check("verify: crit lists an absent (understood) label refused",
    (await code(b.cbor.encode(new b.cbor.Tag(18, [b.cbor.encode(new Map([[1, -7], [2, [3]]])), new Map(), payload, sig])))) === "cose/crit-absent");
}

async function testEsAlgVariants() {
  // ES384 (P-384) and ES512 (P-521) through the real b.cose.sign/verify
  // consumer path — the sha384 / sha512 digest params and the
  // secp384r1 / secp521r1 alg→curve bindings, alongside the P-256/ES256
  // the rest of the suite exercises.
  var s384 = await b.cose.sign(Buffer.from("es384"), { alg: "ES384", privateKey: EC384.privateKey });
  var v384 = await b.cose.verify(s384, { algorithms: ["ES384"], publicKey: EC384.publicKey });
  check("ES384: round-trips over P-384", v384.payload.toString() === "es384" && v384.alg === "ES384" && v384.protectedHeaders.get(1) === -35);

  var s512 = await b.cose.sign(Buffer.from("es512"), { alg: "ES512", privateKey: EC521.privateKey });
  var v512 = await b.cose.verify(s512, { algorithms: ["ES512"], publicKey: EC521.publicKey });
  check("ES512: round-trips over P-521", v512.payload.toString() === "es512" && v512.alg === "ES512" && v512.protectedHeaders.get(1) === -36);

  // The alg→curve binding refuses a P-384 key under ES512 even though
  // both are EC keys (wrong-curve confusion).
  var s512b = await b.cose.sign(Buffer.from("x"), { alg: "ES512", privateKey: EC521.privateKey });
  var mism = null;
  try { await b.cose.verify(s512b, { algorithms: ["ES512"], publicKey: EC384.publicKey }); } catch (e) { mism = e; }
  check("ES512 declared, P-384 key refused (alg/curve binding)", mism && mism.code === "cose/alg-curve-mismatch");
}

async function testKeyLoadFailures() {
  // A well-formed COSE_Sign1 verified with a publicKey that is not a
  // loadable key → the _toKeyObject load failure surfaces as cose/bad-key
  // (fail-closed), never a raw node error.
  var s = await b.cose.sign(Buffer.from("x"), { alg: "ES256", privateKey: EC.privateKey });
  var badPub = null;
  try { await b.cose.verify(s, { algorithms: ["ES256"], publicKey: Buffer.from("not-a-pem-key") }); } catch (e) { badPub = e; }
  check("verify: unloadable publicKey refused (cose/bad-key)", badPub && badPub.code === "cose/bad-key");

  // A keyResolver returning null is fail-closed — the null goes through
  // the same load path and is refused, never treated as a verified key.
  var nullResolver = null;
  try { await b.cose.verify(s, { algorithms: ["ES256"], keyResolver: function () { return null; } }); } catch (e) { nullResolver = e; }
  check("verify: keyResolver returning null refused (cose/bad-key)", nullResolver && nullResolver.code === "cose/bad-key");

  // Sign with an unloadable private key → cose/bad-key.
  var badPriv = null;
  try { await b.cose.sign(Buffer.from("x"), { alg: "ES256", privateKey: Buffer.from("garbage") }); } catch (e) { badPriv = e; }
  check("sign: unloadable privateKey refused (cose/bad-key)", badPriv && badPriv.code === "cose/bad-key");

  // A valid ES256 token verified against an Ed25519 key: the alg→curve
  // binding message path where the key is not EC (got=null, key type
  // reported as ed25519), not verified.
  var edMismatch = null;
  try { await b.cose.verify(s, { algorithms: ["ES256"], publicKey: ED.publicKey }); } catch (e) { edMismatch = e; }
  check("verify: ES256 token with an Ed25519 key refused (alg/curve binding)",
    edMismatch && edMismatch.code === "cose/alg-curve-mismatch" && /ed25519/.test(edMismatch.message));

  // A non-byte payload to sign is refused by the byte coercer.
  var badBytes = null;
  try { await b.cose.sign(12345, { alg: "ES256", privateKey: EC.privateKey }); } catch (e) { badBytes = e; }
  check("sign: non-byte payload refused (cose/bad-bytes)", badBytes && badBytes.code === "cose/bad-bytes");
}

async function testSignAndVerifyHeaderBranches() {
  // Extra unprotected headers on sign ride through and surface on verify.
  var s = await b.cose.sign(Buffer.from("hdr"), {
    alg: "ES256", privateKey: EC.privateKey, unprotectedHeaders: { 4: Buffer.from("kid-uh") },
  });
  var v = await b.cose.verify(s, { algorithms: ["ES256"], publicKey: EC.publicKey });
  check("sign: extra unprotectedHeaders surface on verify", v.unprotectedHeaders.get(4).toString() === "kid-uh");

  // An algorithms allowlist naming an unknown alg name is refused at the
  // allowlist-validation loop (before any decode).
  var unknownAlg = null;
  try { await b.cose.verify(s, { algorithms: ["NOPE"], publicKey: EC.publicKey }); } catch (e) { unknownAlg = e; }
  check("verify: unknown alg name in allowlist refused", unknownAlg && unknownAlg.code === "cose/unknown-alg");
}

function testEncrypt0Branches() {
  var key = b.crypto.generateBytes(32);

  // Unknown AEAD alg name refused.
  var unknown = null;
  try { b.cose.encrypt0(Buffer.from("x"), { alg: "BOGUS", key: key }); } catch (e) { unknown = e; }
  check("encrypt0: unknown alg refused", unknown && unknown.code === "cose/unknown-alg");

  // An explicit (correct-length) IV is honored and round-trips.
  var iv = b.crypto.generateBytes(12);
  var encIv = b.cose.encrypt0(Buffer.from("with-iv"), { key: key, iv: iv });
  var dIv = b.cose.decrypt0(encIv, { key: key, algorithms: ["ChaCha20-Poly1305"] });
  check("encrypt0: explicit IV round-trips + is stored in unprotected label 5",
    dIv.plaintext.toString() === "with-iv" && dIv.unprotectedHeaders.get(5).equals(iv));

  // A wrong-length explicit IV is refused.
  var badIv = null;
  try { b.cose.encrypt0(Buffer.from("x"), { key: key, iv: Buffer.alloc(8) }); } catch (e) { badIv = e; }
  check("encrypt0: wrong-length IV refused", badIv && badIv.code === "cose/bad-iv");

  // A128GCM (16-byte key) full round-trip — the third AEAD alg's params.
  var k16 = b.crypto.generateBytes(16);
  var encA = b.cose.encrypt0(Buffer.from("aes128"), { alg: "A128GCM", key: k16 });
  check("encrypt0: A128GCM round-trip (16-byte key)",
    b.cose.decrypt0(encA, { key: k16, algorithms: ["A128GCM"] }).plaintext.toString() === "aes128");
}

function testDecrypt0Malformed() {
  var key = b.crypto.generateBytes(32);
  function code(bytes, o) {
    try { b.cose.decrypt0(bytes, o || { key: key, algorithms: ["ChaCha20-Poly1305"] }); return null; }
    catch (e) { return e.code; }
  }
  var protBstr = b.cbor.encode(new Map([[1, 24]]));
  var iv12 = new Map([[5, Buffer.alloc(12)]]);

  // Bare (untagged) COSE_Encrypt0 array verifies like the tagged form.
  var enc = b.cose.encrypt0(Buffer.from("bare-enc"), { key: key });
  var bare = b.cbor.encode(b.cbor.decode(enc, { allowedTags: [16] }).value);
  check("decrypt0: bare (untagged) COSE_Encrypt0 decrypts",
    b.cose.decrypt0(bare, { key: key, algorithms: ["ChaCha20-Poly1305"] }).plaintext.toString() === "bare-enc");

  check("decrypt0: wrong array length refused",
    code(b.cbor.encode(new b.cbor.Tag(16, [protBstr, new Map()]))) === "cose/malformed");
  check("decrypt0: non-bstr protected header refused",
    code(b.cbor.encode(new b.cbor.Tag(16, [new Map(), iv12, Buffer.alloc(20)]))) === "cose/malformed");
  check("decrypt0: non-bstr ciphertext refused",
    code(b.cbor.encode(new b.cbor.Tag(16, [protBstr, iv12, "not-bytes"]))) === "cose/malformed");
  check("decrypt0: non-map unprotected header refused",
    code(b.cbor.encode(new b.cbor.Tag(16, [protBstr, ["array-not-map"], Buffer.alloc(20)]))) === "cose/malformed");
  check("decrypt0: protected header that is not a CBOR map refused",
    code(b.cbor.encode(new b.cbor.Tag(16, [b.cbor.encode([1, 2, 3]), iv12, Buffer.alloc(20)]))) === "cose/malformed");
  // Empty protected header → no alg → unrecognized AEAD id.
  check("decrypt0: empty protected header (no alg) refused as unknown-alg",
    code(b.cbor.encode(new b.cbor.Tag(16, [Buffer.alloc(0), iv12, Buffer.alloc(20)]))) === "cose/unknown-alg");
  check("decrypt0: unrecognized AEAD alg id refused",
    code(b.cbor.encode(new b.cbor.Tag(16, [b.cbor.encode(new Map([[1, 99]])), iv12, Buffer.alloc(20)]))) === "cose/unknown-alg");
  // Wrong key length for the declared alg (16-byte key for ChaCha's 32).
  check("decrypt0: wrong key length for declared alg refused",
    code(enc, { key: b.crypto.generateBytes(16), algorithms: ["ChaCha20-Poly1305"] }) === "cose/bad-key");
  // Missing IV in the unprotected header.
  check("decrypt0: missing IV refused",
    code(b.cbor.encode(new b.cbor.Tag(16, [protBstr, new Map(), Buffer.alloc(20)]))) === "cose/bad-iv");
  // Ciphertext shorter than the AEAD tag (valid key + IV, short ct).
  check("decrypt0: ciphertext shorter than the AEAD tag refused",
    code(b.cbor.encode(new b.cbor.Tag(16, [protBstr, iv12, Buffer.alloc(10)]))) === "cose/malformed");

  // Cross-algorithm AEAD confusion: a real ChaCha20-Poly1305 token whose
  // protected header is rewritten to A256GCM (both 32-byte-key / 12-byte-IV)
  // must NOT decrypt — the protected header is bound as AEAD associated
  // data via the Enc_structure, so the tag fails.
  var real = b.cose.encrypt0(Buffer.from("secret"), { alg: "ChaCha20-Poly1305", key: key });
  var rarr = b.cbor.decode(real, { allowedTags: [16] }).value;
  var forged = b.cbor.encode(new b.cbor.Tag(16, [b.cbor.encode(new Map([[1, 3]])), rarr[1], rarr[2]]));
  check("decrypt0: cross-alg header rewrite (ChaCha→A256GCM) refused (AAD binds alg)",
    code(forged, { key: key, algorithms: ["A256GCM"] }) === "cose/decrypt-failed");
}

function testMac0Branches() {
  var key = nodeCrypto.randomBytes(32);
  var protBstr = b.cbor.encode(new Map([[1, 5]]));
  var payload = Buffer.from("p");
  var tag32 = Buffer.alloc(32);
  function code(bytes, o) {
    try { b.cose.macVerify0(bytes, o || { algorithms: ["HMAC-256/256"], key: key }); return null; }
    catch (e) { return e.code; }
  }

  // Unknown MAC alg name on mac0 refused.
  var unk = null;
  try { b.cose.mac0(payload, { alg: "BOGUS", key: key }); } catch (e) { unk = e; }
  check("mac0: unknown alg refused", unk && unk.code === "cose/unsignable-alg");

  // Extra unprotected headers surface on macVerify0.
  var mu = b.cose.mac0(payload, { alg: "HMAC-256/256", key: key, unprotectedHeaders: { 4: Buffer.from("kid-m") } });
  check("mac0: extra unprotectedHeaders surface on verify",
    b.cose.macVerify0(mu, { algorithms: ["HMAC-256/256"], key: key }).unprotectedHeaders.get(4).toString() === "kid-m");

  // Bare (untagged) COSE_Mac0 verifies like the tagged form.
  var m = b.cose.mac0(payload, { alg: "HMAC-256/256", key: key });
  var bare = b.cbor.encode(b.cbor.decode(m, { allowedTags: [17] }).value);
  check("macVerify0: bare (untagged) COSE_Mac0 verifies",
    b.cose.macVerify0(bare, { algorithms: ["HMAC-256/256"], key: key }).payload.equals(payload));

  // opts.algorithms required + unknown alg name + missing key.
  check("macVerify0: missing algorithms refused", code(m, { key: key }) === "cose/algorithms-required");
  check("macVerify0: unknown alg name in allowlist refused", code(m, { algorithms: ["NOPE"], key: key }) === "cose/unknown-alg");
  check("macVerify0: missing key refused", code(m, { algorithms: ["HMAC-256/256"] }) === "cose/no-key");

  // Structural malformations.
  check("macVerify0: wrong array length refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [protBstr, new Map(), payload]))) === "cose/malformed");
  check("macVerify0: non-bstr protected header refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [new Map(), new Map(), payload, tag32]))) === "cose/malformed");
  check("macVerify0: non-bstr tag refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [protBstr, new Map(), payload, "not-bytes"]))) === "cose/malformed");
  check("macVerify0: non-map unprotected header refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [protBstr, ["array"], payload, tag32]))) === "cose/malformed");
  check("macVerify0: externalPayload on an attached token refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [protBstr, new Map(), payload, tag32])),
      { algorithms: ["HMAC-256/256"], key: key, externalPayload: payload }) === "cose/payload-ambiguous");
  check("macVerify0: non-byte payload refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [protBstr, new Map(), "text", tag32]))) === "cose/malformed");
  check("macVerify0: empty protected header (no alg) refused as unknown-alg",
    code(b.cbor.encode(new b.cbor.Tag(17, [Buffer.alloc(0), new Map(), payload, tag32]))) === "cose/unknown-alg");
  check("macVerify0: protected header that is not a CBOR map refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [b.cbor.encode([1, 2, 3]), new Map(), payload, tag32]))) === "cose/malformed");
  check("macVerify0: crit (label 2) not an array refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [b.cbor.encode(new Map([[1, 5], [2, 99]])), new Map(), payload, tag32]))) === "cose/bad-crit");
  check("macVerify0: crit lists an absent (understood) label refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [b.cbor.encode(new Map([[1, 5], [2, [3]]])), new Map(), payload, tag32]))) === "cose/crit-absent");
  check("macVerify0: unrecognized MAC alg id refused",
    code(b.cbor.encode(new b.cbor.Tag(17, [b.cbor.encode(new Map([[1, 99]])), new Map(), payload, tag32]))) === "cose/unknown-alg");

  // A truncated tag (length mismatch) is refused as cose/bad-tag, never a
  // raw length-mismatch throw from the constant-time compare.
  var marr = b.cbor.decode(m, { allowedTags: [17] }).value;
  var truncated = b.cbor.encode(new b.cbor.Tag(17, [marr[0], marr[1], marr[2], Buffer.alloc(5)]));
  check("macVerify0: truncated tag refused (cose/bad-tag)", code(truncated) === "cose/bad-tag");
}

async function run() {
  testSurface();
  testEncrypt0();
  await testClassicalUseableToday();
  await testEsAlgVariants();
  await testProtectedHeaders();
  await testPqcForward();
  await testTamperAndAllowlist();
  await testCritBypassDefense();
  await testAlgKeyTypeConfusion();
  await testEcAlgCurveVerify();
  await testUnprotectedAlgNotHonored();
  await testBareUntagged();
  await testKeyResolver();
  await testKeyLoadFailures();
  await testSignAndVerifyHeaderBranches();
  await testMalformedVerifyBranches();
  await testValidation();
  await testDetachedPayload();
  await testImportKey();
  await testExportKey();
  testEncrypt0Branches();
  testDecrypt0Malformed();
  testMac0();
  testMac0Branches();
}

function testMac0() {
  var key = nodeCrypto.randomBytes(32);
  var pt = Buffer.from("cose mac0 payload", "utf8");
  var m = b.cose.mac0(pt, { alg: "HMAC-256/256", key: key });
  check("mac0: tagged COSE_Mac0 (tag 17 → 0xd1)", m[0] === 0xd1);
  var out = b.cose.macVerify0(m, { algorithms: ["HMAC-256/256"], key: key });
  check("mac0: round-trips payload + alg", out.payload.equals(pt) && out.alg === "HMAC-256/256");

  var wrongKey = null;
  try { b.cose.macVerify0(m, { algorithms: ["HMAC-256/256"], key: nodeCrypto.randomBytes(32) }); } catch (e) { wrongKey = e; }
  check("mac0: wrong key refused", wrongKey && wrongKey.code === "cose/bad-tag");

  var tampered = Buffer.from(m); tampered[tampered.length - 1] ^= 0xff;
  var tamp = null;
  try { b.cose.macVerify0(tampered, { algorithms: ["HMAC-256/256"], key: key }); } catch (e) { tamp = e; }
  check("mac0: tampered tag refused", tamp && tamp.code === "cose/bad-tag");

  var notAllowed = null;
  try { b.cose.macVerify0(m, { algorithms: ["HMAC-512/512"], key: key }); } catch (e) { notAllowed = e; }
  check("mac0: alg not in allowlist refused", notAllowed && notAllowed.code === "cose/alg-not-allowed");

  var md = b.cose.mac0(pt, { alg: "HMAC-384/384", key: key, detached: true });
  check("mac0: detached verify with externalPayload", b.cose.macVerify0(md, { algorithms: ["HMAC-384/384"], key: key, externalPayload: pt }).payload.equals(pt));
  var noPay = null;
  try { b.cose.macVerify0(md, { algorithms: ["HMAC-384/384"], key: key }); } catch (e) { noPay = e; }
  check("mac0: detached without externalPayload refused", noPay && noPay.code === "cose/detached-no-payload");

  var ma = b.cose.mac0(pt, { alg: "HMAC-512/512", key: key, externalAad: Buffer.from("ctx-A", "utf8") });
  var aadBad = null;
  try { b.cose.macVerify0(ma, { algorithms: ["HMAC-512/512"], key: key, externalAad: Buffer.from("ctx-B", "utf8") }); } catch (e) { aadBad = e; }
  check("mac0: external_aad mismatch refused", aadBad && aadBad.code === "cose/bad-tag");

  // crit-bypass defense: a COSE_Mac0 marking an unknown critical header
  // is refused (matching b.cose.verify).
  var protCrit = b.cbor.encode(new Map([[1, 5], [2, [99]]]));
  var macCrit = b.cbor.encode(new b.cbor.Tag(17, [protCrit, new Map(), Buffer.from("x", "utf8"), Buffer.alloc(32)]));
  var critErr = null;
  try { b.cose.macVerify0(macCrit, { algorithms: ["HMAC-256/256"], key: key }); } catch (e) { critErr = e; }
  check("mac0: unknown crit header refused", critErr && critErr.code === "cose/crit-unknown");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cose] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
