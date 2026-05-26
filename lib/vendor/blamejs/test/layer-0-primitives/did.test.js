"use strict";
/**
 * Layer 0 — b.did (W3C DID resolution: did:key + did:web).
 * Covers the published did:key spec vector (an independent-implementation
 * oracle), Ed25519 / P-256 / P-384 / secp256k1 keyToDid ↔ resolve
 * round-trips, did:web URL derivation + document extraction
 * (publicKeyMultibase + publicKeyJwk), the integration with b.vc
 * (resolve an issuer DID → verify its credential), and the refusal paths.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var nodeCrypto = require("node:crypto");

// Published did:key Ed25519 example (W3C CCG did:key test vector).
var SPEC_ED25519 = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

function testSurface() {
  check("b.did.parse is a function", typeof b.did.parse === "function");
  check("b.did.resolve is a function", typeof b.did.resolve === "function");
  check("b.did.keyToDid is a function", typeof b.did.keyToDid === "function");
  check("b.did.MULTICODEC maps Ed25519", b.did.MULTICODEC[0xed].name === "Ed25519");
  check("b.did.DidError is a class", typeof b.did.DidError === "function");
}

function testSpecVector() {
  var r = b.did.resolve(SPEC_ED25519);
  check("spec vector: resolves to an Ed25519 key", r.verificationMethods[0].publicKey.asymmetricKeyType === "ed25519");
  check("spec vector: verificationMethod type Ed25519", r.verificationMethods[0].type === "Ed25519");
  check("spec vector: DID document has assertionMethod + authentication", r.didDocument.assertionMethod.length === 1 && r.didDocument.authentication.length === 1);
  // Re-encoding the resolved key must reproduce the exact published DID —
  // an independent-implementation interop check.
  check("spec vector: keyToDid round-trips the published DID", b.did.keyToDid(r.verificationMethods[0].publicKey) === SPEC_ED25519);
}

// Key equality via JWK (an EC point imported from a compressed form may
// re-export with a different point_conversion_form, so SPKI bytes can
// differ even for the same key — compare the coordinates instead).
function _spkiEq(a, b2) {
  var ja = a.export({ format: "jwk" }), jb = b2.export({ format: "jwk" });
  return ja.kty === jb.kty && ja.crv === jb.crv && ja.x === jb.x && (ja.y || "") === (jb.y || "");
}

function testRoundTrips() {
  // Ed25519
  var ed = nodeCrypto.generateKeyPairSync("ed25519");
  var edDid = b.did.keyToDid(ed.publicKey);
  check("Ed25519: did:key starts z6Mk", edDid.indexOf("did:key:z6Mk") === 0);
  check("Ed25519: resolve round-trips the key", _spkiEq(b.did.resolve(edDid).verificationMethods[0].publicKey, ed.publicKey));

  // P-256 (the EUDI / mdoc curve) — did:key starts zDna
  var p = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var pDid = b.did.keyToDid(p.publicKey);
  check("P-256: did:key starts zDn", pDid.indexOf("did:key:zDn") === 0);
  check("P-256: resolve round-trips the key", _spkiEq(b.did.resolve(pDid).verificationMethods[0].publicKey, p.publicKey));

  // P-384
  var p384 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  check("P-384: resolve round-trips the key", _spkiEq(b.did.resolve(b.did.keyToDid(p384.publicKey)).verificationMethods[0].publicKey, p384.publicKey));

  // secp256k1
  var k1 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  check("secp256k1: resolve round-trips the key", _spkiEq(b.did.resolve(b.did.keyToDid(k1.publicKey)).verificationMethods[0].publicKey, k1.publicKey));
}

async function testCredentialIntegration() {
  // The point of b.did: resolve an issuer DID, then verify its credential.
  var issuer = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var issuerDid = b.did.keyToDid(issuer.publicKey);
  var cred = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential"], issuer: issuerDid,
    credentialSubject: { id: "did:example:subject" },
  };
  var jws = await b.vc.issue(cred, { securing: "jose", alg: "ES256", privateKey: issuer.privateKey });
  var resolvedKey = b.did.resolve(issuerDid).verificationMethods[0].publicKey;
  var out = await b.vc.verify(jws, { algorithms: ["ES256"], publicKey: resolvedKey, expectedIssuer: issuerDid });
  check("integration: resolved issuer DID verifies its b.vc credential", out.issuer === issuerDid);
}

function testDidWeb() {
  var p = b.did.parse("did:web:example.com:issuers:42");
  check("did:web: method + id parsed", p.method === "web" && p.id === "example.com:issuers:42");
  check("did:web: path URL derived", p.url === "https://example.com/issuers/42/did.json");
  check("did:web: bare host → .well-known", b.did.parse("did:web:example.com").url === "https://example.com/.well-known/did.json");
  // Port encoded as %3A in the host is decoded to ':'.
  check("did:web: %3A port decoded in host", b.did.parse("did:web:example.com%3A8443:a").url === "https://example.com:8443/a/did.json");
  // Escaped reserved chars in a PATH segment stay verbatim (not turned
  // into URL control syntax) — a path %3F must not become '?'.
  check("did:web: escaped delimiter in path preserved", b.did.parse("did:web:example.com:foo%3Fbar").url === "https://example.com/foo%3Fbar/did.json");
  // A malformed percent-escape must not throw a raw URIError.
  var pctCode = (function () { try { b.did.parse("did:web:example.com:%"); return "ok"; } catch (e) { return e.code || e.name; } })();
  check("did:web: malformed escape does not throw URIError", pctCode === "ok");

  var issuer = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var webDid = "did:web:example.com";
  // publicKeyJwk verification method
  var docJwk = {
    "@context": ["https://www.w3.org/ns/did/v1"], id: webDid,
    verificationMethod: [{ id: webDid + "#k1", controller: webDid, type: "JsonWebKey2020", publicKeyJwk: issuer.publicKey.export({ format: "jwk" }) }],
  };
  var rJwk = b.did.resolve(webDid, { document: docJwk });
  check("did:web: publicKeyJwk → KeyObject", _spkiEq(rJwk.verificationMethods[0].publicKey, issuer.publicKey));

  // publicKeyMultibase verification method (did:key-style)
  var ed = nodeCrypto.generateKeyPairSync("ed25519");
  var multibase = b.did.keyToDid(ed.publicKey).slice("did:key:".length);
  var docMb = {
    "@context": ["https://www.w3.org/ns/did/v1"], id: webDid,
    verificationMethod: [{ id: webDid + "#k1", controller: webDid, type: "Multikey", publicKeyMultibase: multibase }],
  };
  check("did:web: publicKeyMultibase → KeyObject", _spkiEq(b.did.resolve(webDid, { document: docMb }).verificationMethods[0].publicKey, ed.publicKey));
}

function testRefusals() {
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("not a DID refused", code(function () { b.did.parse("https://x"); }) === "did/bad-did");
  check("unsupported method refused", code(function () { b.did.resolve("did:ion:abc"); }) === "did/unsupported-method");
  check("did:web without document refused", code(function () { b.did.resolve("did:web:example.com"); }) === "did/document-required");
  check("did:key non-multibase refused", code(function () { b.did.resolve("did:key:Qabc"); }) === "did/bad-did");
  check("did:key bad base58 refused", code(function () { b.did.resolve("did:key:z0OIl"); }) === "did/bad-base58");
  check("did:web document id mismatch refused", code(function () {
    b.did.resolve("did:web:example.com", { document: { id: "did:web:evil.com", verificationMethod: [] } });
  }) === "did/document-mismatch");
  // RSA key cannot be a did:key
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  check("RSA key → unsupported", code(function () { b.did.keyToDid(rsa.publicKey); }) === "did/unsupported-key");
}

function testDidJwk() {
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var ed = nodeCrypto.generateKeyPairSync("ed25519");

  var dj = b.did.keyToDid(ec.publicKey, { method: "jwk" });
  check("did:jwk: keyToDid produces a did:jwk", dj.indexOf("did:jwk:") === 0);
  check("did:jwk: parse method", b.did.parse(dj).method === "jwk");
  var r = b.did.resolve(dj);
  check("did:jwk: resolves to the key", _spkiEq(r.verificationMethods[0].publicKey, ec.publicKey));
  check("did:jwk: vm type JsonWebKey2020 + publicKeyJwk", r.verificationMethods[0].type === "JsonWebKey2020" && !!r.didDocument.verificationMethod[0].publicKeyJwk);
  check("did:jwk: Ed25519 round-trips", _spkiEq(b.did.resolve(b.did.keyToDid(ed.publicKey, { method: "jwk" })).verificationMethods[0].publicKey, ed.publicKey));
  // keyToDid default is still did:key
  check("did:jwk: keyToDid default is did:key", b.did.keyToDid(ec.publicKey).indexOf("did:key:") === 0);
  // private member is stripped from the produced did:jwk
  var decoded = JSON.parse(Buffer.from(dj.slice("did:jwk:".length), "base64url").toString("utf8"));
  check("did:jwk: no private 'd' member encoded", decoded.d === undefined && typeof decoded.x === "string");

  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("did:jwk: non-JSON id refused", code(function () { b.did.resolve("did:jwk:" + Buffer.from("not json", "utf8").toString("base64url")); }) === "did/bad-jwk");
  check("did:jwk: unsupported kty refused", code(function () {
    b.did.resolve("did:jwk:" + Buffer.from(JSON.stringify({ kty: "RSA", n: "x", e: "AQAB" }), "utf8").toString("base64url"));
  }) === "did/unsupported-key");
  // keyToDid must also refuse an unsupported key when emitting did:jwk —
  // generation and resolution share the allowlist so the DID round-trips.
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  check("did:jwk: keyToDid refuses RSA (round-trip guarantee)", code(function () { b.did.keyToDid(rsa.publicKey, { method: "jwk" }); }) === "did/unsupported-key");
}

async function run() {
  testSurface();
  testSpecVector();
  testRoundTrips();
  await testCredentialIntegration();
  testDidWeb();
  testDidJwk();
  testRefusals();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[did] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
