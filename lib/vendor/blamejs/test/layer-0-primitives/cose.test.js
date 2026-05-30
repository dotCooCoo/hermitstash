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
}

async function run() {
  testSurface();
  testEncrypt0();
  await testClassicalUseableToday();
  await testProtectedHeaders();
  await testPqcForward();
  await testTamperAndAllowlist();
  await testCritBypassDefense();
  await testValidation();
  await testDetachedPayload();
  await testImportKey();
  await testExportKey();
  testMac0();
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
