"use strict";
/**
 * Layer 0 — b.mdoc (ISO 18013-5 mdoc / mDL issuer-data verification).
 * A pure-node mock issuer builds an IssuerSigned structure (COSE_Sign1
 * IssuerAuth over a Tag-24 MobileSecurityObject, with the signer cert in
 * the x5chain header) so the verifier's full path is exercised: COSE
 * signature, MSO validity window, per-element digest matching against
 * the MSO, selective disclosure, and the tamper / expiry / docType /
 * malformed-validity refusal paths. The trust core (COSE_Sign1 + CBOR)
 * is the framework's tested b.cose / b.cbor substrate.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var asn1 = require("../../lib/asn1-der");
var cbor = b.cbor;
var nodeCrypto = require("node:crypto");

var NS = "org.iso.18013.5.1";
var DOCTYPE = "org.iso.18013.5.1.mDL";

function _algId(oid, withNull) {
  return withNull ? asn1.writeSequence([asn1.writeOid(oid), asn1.writeNull()]) : asn1.writeSequence([asn1.writeOid(oid)]);
}
function _name(cn) {
  return asn1.writeSequence([asn1.writeSet([asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)])])]);
}
function _utc(d) { return asn1.writeNode(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z", "ascii")); }

// Minimal self-signed EC cert (mdoc issuer-data verify reads the key,
// not an EKU). Returns { certDer, key, pem }.
function _makeCert(cn) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var spki = kp.publicKey.export({ type: "spki", format: "der" });
  var sa = _algId("1.2.840.10045.4.3.2", false);
  var nm = _name(cn || "mDL Issuer");
  var now = Date.now();
  var tbs = asn1.writeSequence([
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),
    asn1.writeInteger(Buffer.from([0x2a])), sa, nm,
    asn1.writeSequence([_utc(new Date(now - 86400000)), _utc(new Date(now + 86400000 * 3650))]),
    nm, spki,
  ]);
  var certDer = asn1.writeSequence([tbs, sa, asn1.writeBitString(nodeCrypto.sign("sha256", tbs, kp.privateKey), 0)]);
  return { certDer: certDer, key: kp.privateKey, pem: new nodeCrypto.X509Certificate(certDer).toString() };
}

// Build an IssuerSigned (CBOR bytes). opts: { elements, validFrom,
// validUntil, docType, digestAlg } — defaults are a valid mDL.
async function _makeMdoc(cert, opts) {
  opts = opts || {};
  var elements = opts.elements || [["family_name", "Doe"], ["age_over_18", true], ["given_name", "Jane"]];
  var digestNode = opts.digestNode || "sha256";
  var digestAlg = opts.digestAlg || "SHA-256";
  var now = Date.now();
  var items = [];
  var digests = new Map();
  elements.forEach(function (el, i) {
    var inner = cbor.encode(new Map([
      ["digestID", i], ["random", nodeCrypto.randomBytes(32)],
      ["elementIdentifier", el[0]], ["elementValue", el[1]],
    ]));
    items.push(new cbor.Tag(24, inner));
    digests.set(i, nodeCrypto.createHash(digestNode).update(cbor.encode(new cbor.Tag(24, inner))).digest());
  });
  var validFromMs = opts.validFrom != null ? opts.validFrom : now - 86400000;
  var validUntilMs = opts.validUntil != null ? opts.validUntil : now + 86400000 * 3650;
  var validUntilTag = opts.validUntilRaw !== undefined ? opts.validUntilRaw : new cbor.Tag(0, new Date(validUntilMs).toISOString());
  var mso = new Map([
    ["version", "1.0"], ["digestAlgorithm", digestAlg], ["docType", opts.docType || DOCTYPE],
    ["valueDigests", new Map([[NS, digests]])],
    ["validityInfo", new Map([
      ["signed", new cbor.Tag(0, new Date(now).toISOString())],
      ["validFrom", new cbor.Tag(0, new Date(validFromMs).toISOString())],
      ["validUntil", validUntilTag],
    ])],
  ]);
  // Optional deviceKeyInfo.deviceKey (a COSE_Key) for device-auth tests.
  if (opts.deviceJwk) {
    mso.set("deviceKeyInfo", new Map([["deviceKey", new Map([
      [1, 2], [-1, 1],
      [-2, Buffer.from(opts.deviceJwk.x, "base64url")],
      [-3, Buffer.from(opts.deviceJwk.y, "base64url")],
    ])]]));
  }
  var payload = cbor.encode(new cbor.Tag(24, cbor.encode(mso)));
  var signed = await b.cose.sign(payload, { alg: opts.alg || "ES256", privateKey: cert.key, unprotectedHeaders: { 33: cert.certDer } });
  var issuerAuth = cbor.decode(signed, { allowedTags: [18, 24] }).value;
  return cbor.encode(new Map([["nameSpaces", new Map([[NS, items]])], ["issuerAuth", issuerAuth]]));
}

function testSurface() {
  check("b.mdoc.verifyIssuerSigned is a function", typeof b.mdoc.verifyIssuerSigned === "function");
  check("b.mdoc.DIGEST_ALGS has SHA-256", b.mdoc.DIGEST_ALGS["SHA-256"] === "sha256");
  check("b.mdoc.MdocError is a class", typeof b.mdoc.MdocError === "function");
}

async function testRoundTrip() {
  var cert = _makeCert();
  var mdoc = await _makeMdoc(cert);
  var out = await b.mdoc.verifyIssuerSigned(mdoc, { algorithms: ["ES256"], expectedDocType: DOCTYPE });
  check("verify: docType", out.docType === DOCTYPE);
  check("verify: alg reported", out.alg === "ES256");
  check("verify: digestAlgorithm", out.digestAlgorithm === "SHA-256");
  check("verify: disclosed elements extracted", out.namespaces[NS].family_name === "Doe" && out.namespaces[NS].age_over_18 === true && out.namespaces[NS].given_name === "Jane");
  check("verify: validityInfo dates returned", out.validityInfo.validUntil instanceof Date);
  check("verify: signerCert PEM returned", /BEGIN CERTIFICATE/.test(out.signerCert));

  // chain verify against the self-signed issuer as anchor
  var ok = await b.mdoc.verifyIssuerSigned(mdoc, { algorithms: ["ES256"], trustAnchorsPem: cert.pem });
  check("verify: chain to issuer anchor (string)", ok.docType === DOCTYPE);
}

async function testDigestAndSignatureRefusals() {
  var cert = _makeCert();
  var mdoc = await _makeMdoc(cert);

  // Tamper a disclosed element's value: re-pack one IssuerSignedItem
  // with a changed value but keep the MSO digest → digest mismatch.
  var top = cbor.decode(mdoc, { allowedTags: [0, 1, 24, 1004] });
  var items = top.get("nameSpaces").get(NS);
  var inner0 = cbor.decode(items[0].value, { allowedTags: [0, 1, 24, 1004] });
  inner0.set("elementValue", "Tampered");
  items[0] = new cbor.Tag(24, cbor.encode(inner0));
  var tampered = cbor.encode(top);
  var e1 = null;
  try { await b.mdoc.verifyIssuerSigned(tampered, { algorithms: ["ES256"] }); } catch (e) { e1 = e; }
  check("verify: tampered element refused (digest-mismatch)", e1 && e1.code === "mdoc/digest-mismatch");

  // Tamper the COSE signature deterministically (flip a byte in the
  // issuerAuth signature element) → bad-signature.
  var top2 = cbor.decode(mdoc, { allowedTags: [0, 1, 24, 1004] });
  var ia = top2.get("issuerAuth");
  ia[3] = Buffer.from(ia[3]); ia[3][0] ^= 0xff;
  var bad = cbor.encode(top2);
  var e2 = null;
  try { await b.mdoc.verifyIssuerSigned(bad, { algorithms: ["ES256"] }); } catch (e) { e2 = e; }
  check("verify: tampered COSE signature refused", e2 && e2.code === "cose/bad-signature");

  // A malformed x5chain certificate surfaces a clean error (not raw OpenSSL).
  var top3 = cbor.decode(mdoc, { allowedTags: [0, 1, 24, 1004] });
  top3.get("issuerAuth")[1].set(33, Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]));
  var e6 = null;
  try { await b.mdoc.verifyIssuerSigned(cbor.encode(top3), { algorithms: ["ES256"] }); } catch (e) { e6 = e; }
  check("verify: malformed x5chain cert refused cleanly", e6 && e6.code === "mdoc/bad-cert");

  // alg outside allowlist
  var e3 = null;
  try { await b.mdoc.verifyIssuerSigned(mdoc, { algorithms: ["EdDSA"] }); } catch (e) { e3 = e; }
  check("verify: alg outside allowlist refused", e3 && (e3.code === "cose/alg-not-allowed"));
}

async function testValidityAndDocType() {
  var cert = _makeCert();

  // expired (valid window 10 days ago .. 1 day ago)
  var expired = await _makeMdoc(cert, { validFrom: Date.now() - 86400000 * 10, validUntil: Date.now() - 86400000 });
  var e1 = null;
  try { await b.mdoc.verifyIssuerSigned(expired, { algorithms: ["ES256"] }); } catch (e) { e1 = e; }
  check("verify: expired credential refused", e1 && e1.code === "mdoc/expired");

  // not yet valid
  var future = await _makeMdoc(cert, { validFrom: Date.now() + 86400000 * 30 });
  var e2 = null;
  try { await b.mdoc.verifyIssuerSigned(future, { algorithms: ["ES256"] }); } catch (e) { e2 = e; }
  check("verify: not-yet-valid credential refused", e2 && e2.code === "mdoc/not-yet-valid");

  // opts.at within window accepts an otherwise-expired credential
  var ok = await b.mdoc.verifyIssuerSigned(expired, { algorithms: ["ES256"], at: new Date(Date.now() - 86400000 * 2) });
  check("verify: opts.at within window accepts", ok.docType === DOCTYPE);

  // docType mismatch
  var e3 = null;
  try { await b.mdoc.verifyIssuerSigned(await _makeMdoc(cert), { algorithms: ["ES256"], expectedDocType: "org.iso.18013.5.1.photoID" }); } catch (e) { e3 = e; }
  check("verify: docType mismatch refused", e3 && e3.code === "mdoc/doctype-mismatch");

  // malformed validUntil (a non-date) fails closed
  var badValidity = await _makeMdoc(cert, { validUntilRaw: new cbor.Tag(0, "not-a-date") });
  var e4 = null;
  try { await b.mdoc.verifyIssuerSigned(badValidity, { algorithms: ["ES256"] }); } catch (e) { e4 = e; }
  check("verify: malformed validUntil refused (fail closed)", e4 && e4.code === "mdoc/bad-validity");

  // invalid opts.at refused (lesson carried from b.tsa / b.vc)
  var e5 = null;
  try { await b.mdoc.verifyIssuerSigned(await _makeMdoc(cert), { algorithms: ["ES256"], at: new Date("nope") }); } catch (e) { e5 = e; }
  check("verify: invalid opts.at refused", e5 && e5.code === "mdoc/bad-at");

  // Two signed IssuerSignedItems with the same elementIdentifier (each
  // with a valid MSO digest) is ambiguous → fail closed, not last-wins.
  var dup = await _makeMdoc(cert, { elements: [["family_name", "Doe"], ["family_name", "Roe"]] });
  var e6 = null;
  try { await b.mdoc.verifyIssuerSigned(dup, { algorithms: ["ES256"] }); } catch (e) { e6 = e; }
  check("verify: duplicate elementIdentifier refused", e6 && e6.code === "mdoc/duplicate-element");
}

async function testChainAndInputGuards() {
  var cert = _makeCert();
  var mdoc = await _makeMdoc(cert);

  // unrelated anchor → untrusted
  var other = _makeCert("Unrelated Root");
  var e1 = null;
  try { await b.mdoc.verifyIssuerSigned(mdoc, { algorithms: ["ES256"], trustAnchorsPem: [other.pem] }); } catch (e) { e1 = e; }
  check("verify: unrelated anchor refused", e1 && e1.code === "mdoc/untrusted-chain");

  // empty trust-anchor shape refused (no fail-open)
  var e2 = null;
  try { await b.mdoc.verifyIssuerSigned(mdoc, { algorithms: ["ES256"], trustAnchorsPem: [] }); } catch (e) { e2 = e; }
  check("verify: empty trustAnchorsPem refused", e2 && e2.code === "mdoc/bad-trust-anchors");

  // garbage input → not CBOR / malformed
  var e3 = null;
  try { await b.mdoc.verifyIssuerSigned(Buffer.from([0x00, 0x01]), { algorithms: ["ES256"] }); } catch (e) { e3 = e; }
  check("verify: garbage input refused", e3 && (e3.code === "mdoc/malformed" || e3.code === "mdoc/bad-input" || /cbor/.test(e3.code || "")));

  // missing algorithms
  var e4 = null;
  try { await b.mdoc.verifyIssuerSigned(mdoc, {}); } catch (e) { e4 = e; }
  check("verify: missing algorithms refused", e4 && e4.code === "mdoc/algorithms-required");
}

async function testDeviceAuth() {
  var cert = _makeCert();
  var device = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var deviceJwk = device.publicKey.export({ format: "jwk" });
  // issuer-signed mdoc carrying the device key in the MSO
  var mdoc = await _makeMdoc(cert, { deviceJwk: deviceJwk });
  var issuer = await b.mdoc.verifyIssuerSigned(mdoc, { algorithms: ["ES256"] });
  check("verifyIssuerSigned: returns the deviceKey", issuer.deviceKey instanceof Map || (issuer.deviceKey && typeof issuer.deviceKey === "object"));

  // build a DeviceSigned: detached COSE_Sign1 over DeviceAuthentication
  var sessionTranscript = ["DE-bytes", "ER-bytes", ["handover", 1]];
  var deviceNsBytes = new cbor.Tag(24, cbor.encode(new Map()));
  var da = ["DeviceAuthentication", sessionTranscript, DOCTYPE, deviceNsBytes];
  var daBytes = cbor.encode(new cbor.Tag(24, cbor.encode(da)));
  var sig = await b.cose.sign(daBytes, { alg: "ES256", privateKey: device.privateKey, detached: true });
  var sigArr = cbor.decode(sig, { allowedTags: [18, 24] }).value;
  var deviceSigned = new Map([["nameSpaces", deviceNsBytes], ["deviceAuth", new Map([["deviceSignature", sigArr]])]]);

  var out = await b.mdoc.verifyDeviceAuth({ deviceKey: issuer.deviceKey, deviceSigned: deviceSigned, docType: DOCTYPE, sessionTranscript: sessionTranscript, algorithms: ["ES256"] });
  check("verifyDeviceAuth: verifies with the MSO device key", out.docType === DOCTYPE && out.alg === "ES256");

  // wrong session transcript → signature fails (binding works)
  var e1 = null;
  try { await b.mdoc.verifyDeviceAuth({ deviceKey: issuer.deviceKey, deviceSigned: deviceSigned, docType: DOCTYPE, sessionTranscript: ["tampered"], algorithms: ["ES256"] }); } catch (e) { e1 = e; }
  check("verifyDeviceAuth: wrong sessionTranscript refused", e1 && e1.code === "cose/bad-signature");

  // wrong docType → signature fails
  var e2 = null;
  try { await b.mdoc.verifyDeviceAuth({ deviceKey: issuer.deviceKey, deviceSigned: deviceSigned, docType: "org.iso.18013.5.1.other", sessionTranscript: sessionTranscript, algorithms: ["ES256"] }); } catch (e) { e2 = e; }
  check("verifyDeviceAuth: wrong docType refused", e2 && e2.code === "cose/bad-signature");

  // MAC variant → unsupported (deferred)
  var dsMac = new Map([["nameSpaces", deviceNsBytes], ["deviceAuth", new Map([["deviceMac", [Buffer.alloc(3), new Map(), null, Buffer.alloc(8)]]])]]);
  var e3 = null;
  try { await b.mdoc.verifyDeviceAuth({ deviceKey: issuer.deviceKey, deviceSigned: dsMac, docType: DOCTYPE, sessionTranscript: sessionTranscript, algorithms: ["ES256"] }); } catch (e) { e3 = e; }
  check("verifyDeviceAuth: MAC variant refused (deferred)", e3 && e3.code === "mdoc/device-mac-unsupported");

  // missing sessionTranscript
  var e4 = null;
  try { await b.mdoc.verifyDeviceAuth({ deviceKey: issuer.deviceKey, deviceSigned: deviceSigned, docType: DOCTYPE, algorithms: ["ES256"] }); } catch (e) { e4 = e; }
  check("verifyDeviceAuth: missing sessionTranscript refused", e4 && e4.code === "mdoc/no-session-transcript");
}

async function run() {
  testSurface();
  await testRoundTrip();
  await testDigestAndSignatureRefusals();
  await testValidityAndDocType();
  await testChainAndInputGuards();
  await testDeviceAuth();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mdoc] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
