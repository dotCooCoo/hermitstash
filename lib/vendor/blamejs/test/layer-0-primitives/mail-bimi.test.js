// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.bimi — RFC 9091 BIMI policy lookup, VMC + CMC chain validation,
 * and Tiny-PS SVG profile enforcement.
 *
 * Coverage:
 *   - Existing recordShape / parseRecord / fetchPolicy contract.
 *   - validateTinyPsSvg covering each violation class
 *     (root, version, baseProfile, viewBox, doctype, processing
 *     instruction, forbidden element, animation element, event-handler
 *     attr, external href, style attr, byte cap).
 *   - fetchAndVerifyMark with a self-signed test root + leaf,
 *     stubbed httpClient, exercising chain success / chain mismatch /
 *     domain mismatch / missing EKU / no-trust-anchors / bad-pem.
 *
 * Live network is NOT used. The httpClient stub returns a buffer body
 * that mirrors b.httpClient.request's response shape.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var pki    = require("../../lib/vendor/blamejs-pki.cjs");
var build  = pki.asn1.build;
var subtle = pki.webcrypto.subtle;

// ---- existing-surface tests ----

function testSurface() {
  check("mail.bimi.recordShape is a function",
        typeof b.mail.bimi.recordShape === "function");
  check("mail.bimi.parseRecord is a function",
        typeof b.mail.bimi.parseRecord === "function");
  check("mail.bimi.fetchPolicy is a function",
        typeof b.mail.bimi.fetchPolicy === "function");
  check("mail.bimi.fetchAndVerifyMark is a function",
        typeof b.mail.bimi.fetchAndVerifyMark === "function");
  check("mail.bimi.validateTinyPsSvg is a function",
        typeof b.mail.bimi.validateTinyPsSvg === "function");
  check("frameworkError.MailBimiError exposed",
        typeof b.frameworkError.MailBimiError === "function");
  check("BIMI_EKU OID surface",
        b.mail.bimi.BIMI_EKU_MARK_VERIFICATION === "1.3.6.1.5.5.7.3.31");
  check("VMC policy OID surface",
        b.mail.bimi.VMC_POLICY_OID === "1.3.6.1.4.1.53087.1.1");
  check("CMC policy OID surface",
        b.mail.bimi.CMC_POLICY_OID === "1.3.6.1.4.1.53087.1.2");
}

function testRecordShape() {
  var rec = b.mail.bimi.recordShape({
    logoUrl: "https://example.com/bimi/logo.svg",
    vmcUrl:  "https://example.com/bimi/cert.pem",
  });
  check("recordShape produces canonical form",
        rec === "v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/cert.pem");
}

function testParseRecord() {
  var rv = b.mail.bimi.parseRecord("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem");
  check("parseRecord returns shape",
        rv && rv.v === "BIMI1" && rv.l === "https://example.com/logo.svg" &&
        rv.a === "https://example.com/cert.pem");

  var rv2 = b.mail.bimi.parseRecord("v=BIMI2; l=https://example.com/logo.svg");
  check("parseRecord rejects bad version",
        rv2 === null);

  var rv3 = b.mail.bimi.parseRecord("");
  check("parseRecord rejects empty", rv3 === null);
}

// ---- Tiny-PS SVG validation ----

var GOOD_SVG = '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 32 32" ' +
  'xmlns="http://www.w3.org/2000/svg"><circle cx="16" cy="16" r="16" fill="red"/></svg>';

function testTinyPsSvgValid() {
  var rv = b.mail.bimi.validateTinyPsSvg(GOOD_SVG);
  check("tiny-ps: valid SVG passes",
        rv.ok === true && rv.violations.length === 0);
}

function testTinyPsSvgValidWithXmlProlog() {
  var withProlog = '<?xml version="1.0" encoding="UTF-8"?>' + GOOD_SVG;
  var rv = b.mail.bimi.validateTinyPsSvg(withProlog);
  check("tiny-ps: XML prolog allowed",
        rv.ok === true && rv.violations.length === 0);
}

function testTinyPsSvgValidBufferInput() {
  var rv = b.mail.bimi.validateTinyPsSvg(Buffer.from(GOOD_SVG, "utf8"));
  check("tiny-ps: Buffer input accepted",
        rv.ok === true);
}

function testTinyPsSvgRootNotSvg() {
  var rv = b.mail.bimi.validateTinyPsSvg('<html version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"></html>');
  check("tiny-ps: non-svg root flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "root-not-svg"; }));
}

function testTinyPsSvgBadVersion() {
  var rv = b.mail.bimi.validateTinyPsSvg('<svg version="1.1" baseProfile="tiny-ps" viewBox="0 0 1 1"></svg>');
  check("tiny-ps: bad version flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "bad-version"; }));
}

function testTinyPsSvgBadBaseProfile() {
  var rv = b.mail.bimi.validateTinyPsSvg('<svg version="1.2" viewBox="0 0 1 1"></svg>');
  check("tiny-ps: missing baseProfile flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "bad-base-profile"; }));
}

function testTinyPsSvgMissingViewBox() {
  var rv = b.mail.bimi.validateTinyPsSvg('<svg version="1.2" baseProfile="tiny-ps"></svg>');
  check("tiny-ps: missing viewBox flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "missing-viewbox"; }));
}

function testTinyPsSvgScript() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><script>alert(1)</script></svg>');
  check("tiny-ps: <script> flagged",
        !rv.ok && rv.violations.some(function (v) {
          return v.code === "element-forbidden" && v.message.indexOf("<script>") !== -1;
        }));
}

function testTinyPsSvgStyleElement() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><style>.x{color:red}</style></svg>');
  check("tiny-ps: <style> flagged",
        !rv.ok && rv.violations.some(function (v) {
          return v.code === "element-forbidden" && v.message.indexOf("<style>") !== -1;
        }));
}

function testTinyPsSvgForeignObject() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><foreignObject></foreignObject></svg>');
  check("tiny-ps: <foreignObject> flagged",
        !rv.ok && rv.violations.some(function (v) {
          return v.code === "element-forbidden" && v.message.indexOf("<foreignobject>") !== -1;
        }));
}

function testTinyPsSvgAnimate() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1">' +
      '<animate attributeName="fill" from="red" to="blue"/></svg>');
  check("tiny-ps: <animate> flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "element-forbidden"; }));
}

function testTinyPsSvgFilter() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><filter id="f"></filter></svg>');
  check("tiny-ps: <filter> flagged",
        !rv.ok && rv.violations.some(function (v) {
          return v.code === "element-forbidden" && v.message.indexOf("<filter>") !== -1;
        }));
}

function testTinyPsSvgImage() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><image href="https://e.com/x.png"/></svg>');
  check("tiny-ps: <image> flagged",
        !rv.ok && rv.violations.some(function (v) {
          return v.code === "element-forbidden" && v.message.indexOf("<image>") !== -1;
        }));
}

function testTinyPsSvgExternalHref() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><a href="https://evil.com">x</a></svg>');
  check("tiny-ps: external href flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "external-ref-forbidden"; }));
}

function testTinyPsSvgFragmentHrefAllowed() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><a href="#frag">x</a></svg>');
  check("tiny-ps: #fragment href allowed",
        rv.ok === true);
}

function testTinyPsSvgEventHandler() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1" onload="alert(1)"></svg>');
  check("tiny-ps: onload flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "event-handler-forbidden"; }));
}

function testTinyPsSvgStyleAttr() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1" style="color:red"></svg>');
  check("tiny-ps: style attr flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "style-attr-forbidden"; }));
}

function testTinyPsSvgDoctype() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<!DOCTYPE svg><svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"></svg>');
  check("tiny-ps: <!DOCTYPE> flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "doctype-forbidden"; }));
}

function testTinyPsSvgMultipleRoots() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"></svg>' +
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"></svg>');
  check("tiny-ps: multiple roots flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "multiple-root-elements"; }));
}

function testTinyPsSvgTooLarge() {
  var threw = null;
  try {
    var big = '<svg viewBox="0 0 1 1">' + "x".repeat(40000) + '</svg>';
    b.mail.bimi.validateTinyPsSvg(big);
  } catch (e) { threw = e; }
  check("tiny-ps: too-large throws bimi/svg-too-large",
        threw && threw.code === "bimi/svg-too-large");
}

function testTinyPsSvgBadInput() {
  var threw = null;
  try { b.mail.bimi.validateTinyPsSvg(123); }
  catch (e) { threw = e; }
  check("tiny-ps: non-bytes input throws",
        threw && threw.code === "bimi/svg-tiny-ps-violation");
}

// ---- fetchAndVerifyMark with a self-signed test cert chain ----

var YEAR_MS = 365 * 24 * 60 * 60 * 1000;
var BIMI_EKU_OID = "1.3.6.1.5.5.7.3.31";
var ID_PE_LOGOTYPE_OID = "1.3.6.1.5.5.7.1.12";

// RFC 5280 sec. 4.2.1 certificate-extension OIDs, dotted-decimal — used to
// hand-encode Extension DER for the array (pre-encoded) form of
// pki.x509.sign, which the custom id-pe-logotype extension forces (the
// named-extension object form cannot mix with a raw custom extension).
var OID_BASIC_CONSTRAINTS = "2.5.29.19";
var OID_KEY_USAGE = "2.5.29.15";
var OID_SAN = "2.5.29.17";
var OID_EKU = "2.5.29.37";
var OID_CERT_POLICIES = "2.5.29.32";

// ECDSA P-256 key pair (WebCrypto CryptoKeys). subtle is the vendored
// @blamejs/pki WebCrypto surface.
function _genKey() {
  return subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}
// The SPKI DER (what pki.x509.sign certifies) of a public CryptoKey.
async function _spki(publicKey) {
  return Buffer.from(await subtle.exportKey("spki", publicKey));
}
// The PKCS#8 private key as PEM. pki.x509.sign derives the signature
// scheme case-consistently from the encoded key, so the private key is
// passed as PEM rather than a raw CryptoKey.
async function _keyPem(privateKey) {
  return String(await pki.key.export(privateKey, { format: "pem" }));
}

// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
// extnValue OCTET STRING }. A FALSE critical is omitted (DER DEFAULT).
// `valueContent` is the raw extnValue bytes (wrapped in the OCTET STRING).
function _extDer(oidStr, critical, valueContent) {
  var kids = [build.oid(oidStr)];
  if (critical) kids.push(build.boolean(true));
  kids.push(build.octetString(valueContent));
  return build.sequence(kids);
}
// GeneralName forms this file uses (RFC 5280 sec. 4.2.1.6): dNSName [2],
// uniformResourceIdentifier [6], both IA5String context-primitives.
var _SAN_TAG = { dns: 2, url: 6 };
var _SAN_FORM = { dns: "dNSName", url: "uniformResourceIdentifier" };
function _generalNameDer(entry) {
  var tag = _SAN_TAG[entry.type];
  if (tag === undefined) throw new Error("unsupported SAN type " + entry.type);
  return build.contextPrimitive(tag, Buffer.from(entry.value, "latin1"));
}
// { type, value } SAN entries -> pki.x509.sign's GeneralName object form.
function _sanObjectEntries(entries) {
  return entries.map(function (e) {
    var form = _SAN_FORM[e.type];
    if (!form) throw new Error("unsupported SAN type " + e.type);
    var o = {}; o[form] = e.value; return o;
  });
}
// Pre-encoded Extension DER builders (array form).
function _sanExtDer(entries) {
  return _extDer(OID_SAN, false, build.sequence(entries.map(_generalNameDer)));
}
function _ekuExtDer(oids) {
  return _extDer(OID_EKU, false, build.sequence(oids.map(function (o) { return build.oid(o); })));
}
function _bcLeafExtDer() {
  // A leaf's basicConstraints: cA=FALSE (empty SEQUENCE), critical.
  return _extDer(OID_BASIC_CONSTRAINTS, true, build.sequence([]));
}
function _kuExtDer(bits) {
  return _extDer(OID_KEY_USAGE, true, build.namedBitString(bits));
}
function _certPoliciesExtDer(oids) {
  return _extDer(OID_CERT_POLICIES, false,
    build.sequence(oids.map(function (o) { return build.sequence([build.oid(o)]); })));
}

// _logotypeExtension — a minimal RFC 3709 id-pe-logotype extension whose
// value is `SEQUENCE { OCTET STRING <svg...> }`, exercising both the
// constructed-recursion and primitive-match paths of the framework's
// best-effort embedded-SVG scanner. The SVG stays < 128 bytes so every
// DER length is single-byte. Returns a pre-encoded Extension DER Buffer.
function _logotypeExtension(svgText) {
  var svg = Buffer.from(svgText, "utf8");
  var octet = Buffer.concat([Buffer.from([0x04, svg.length]), svg]);
  var seq = Buffer.concat([Buffer.from([0x30, octet.length]), octet]);
  return _extDer(ID_PE_LOGOTYPE_OID, false, seq);
}

// _logotypeExtensionRaw — id-pe-logotype extension over caller-supplied
// DER, so a test can exercise the scanner's non-SVG-leaf, no-match, and
// truncated-SEQUENCE fallback branches directly. Returns a pre-encoded
// Extension DER Buffer.
function _logotypeExtensionRaw(innerDer) {
  return _extDer(ID_PE_LOGOTYPE_OID, false, innerDer);
}

// A short DER OCTET STRING whose bytes are not an SVG magic prefix.
var _OCTET_NON_SVG = Buffer.from([0x04, 0x04, 0x78, 0x78, 0x78, 0x78]);
function _octetOf(text) {
  var b2 = Buffer.from(text, "utf8");
  return Buffer.concat([Buffer.from([0x04, b2.length]), b2]);
}
function _derSequence(contentBuf) {
  return Buffer.concat([Buffer.from([0x30, contentBuf.length]), contentBuf]);
}

// The leaf's extension set. Without a custom logotype the named-extension
// object form is used; a custom logotype forces the array (pre-encoded
// DER) form for the whole set, since the two forms cannot be mixed.
function _buildLeafExtensions(opts) {
  var sanDomain = opts.sanDomain || "example.com";
  var includeBimiEku = opts.includeBimiEku !== false;
  var sanEntries = opts.noSan ? null : (opts.sanEntries || [{ type: "dns", value: sanDomain }]);
  var hasCustomLogotype = !!(opts.logoSvg || opts.logotypeExt);

  if (!hasCustomLogotype) {
    var ext = {
      basicConstraints: { cA: false, critical: true },
      keyUsage:         ["digitalSignature"], keyUsageCritical: true,
    };
    if (sanEntries) ext.subjectAltName = _sanObjectEntries(sanEntries);
    if (includeBimiEku) {
      ext.extendedKeyUsage = [BIMI_EKU_OID];
      ext.extendedKeyUsageCritical = false;
    }
    if (opts.policyOid) ext.certificatePolicies = [opts.policyOid];
    return ext;
  }

  var arr = [_bcLeafExtDer(), _kuExtDer([0])];   // digitalSignature = bit 0
  if (sanEntries) arr.push(_sanExtDer(sanEntries));
  if (includeBimiEku) arr.push(_ekuExtDer([BIMI_EKU_OID]));
  if (opts.policyOid) arr.push(_certPoliciesExtDer([opts.policyOid]));
  if (opts.logoSvg) arr.push(_logotypeExtension(opts.logoSvg));
  if (opts.logotypeExt) arr.push(opts.logotypeExt);
  return arr;
}

async function _generateTestChain(opts) {
  opts = opts || {};
  var sanDomain = opts.sanDomain || "example.com";

  var caKeys = await _genKey();
  var leafKeys = await _genKey();

  var now = new Date();
  var notAfter = new Date(now.getTime() + YEAR_MS);
  var leafNotBefore = opts.leafNotBefore || now;
  var leafNotAfter = opts.leafNotAfter || notAfter;

  var caSpki = await _spki(caKeys.publicKey);
  var caKeyPem = await _keyPem(caKeys.privateKey);
  var leafSpki = await _spki(leafKeys.publicKey);

  var rootPem = await pki.x509.sign({
    subject:          "BIMI Test Root",
    subjectPublicKey: caSpki,
    serialNumber:     "0x01",
    notBefore:        now,
    notAfter:         notAfter,
    extensions: {
      basicConstraints: { cA: true, pathLen: 1, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { key: caKeyPem }, { pem: true });

  // The leaf is CA-signed by the root cert (issuer DN copied byte-exact
  // from the root's subject).
  var leafPem = await pki.x509.sign({
    subject:          sanDomain,
    subjectPublicKey: leafSpki,
    serialNumber:     "0x02",
    notBefore:        leafNotBefore,
    notAfter:         leafNotAfter,
    extensions:       _buildLeafExtensions(opts),
  }, { cert: rootPem, key: caKeyPem }, { pem: true });

  return {
    rootPem: rootPem,
    leafPem: leafPem,
  };
}

// _generateThreeLevelChain — root -> intermediate -> leaf, so the fetched
// PEM body carries [leaf, intermediate] and the trust anchor is the root.
// Drives the intermediate-walk branch of the chain verifier.
async function _generateThreeLevelChain() {
  var rootKeys = await _genKey();
  var interKeys = await _genKey();
  var leafKeys = await _genKey();
  var now = new Date();
  var far = new Date(now.getTime() + 10 * YEAR_MS);

  var rootSpki = await _spki(rootKeys.publicKey);
  var rootKeyPem = await _keyPem(rootKeys.privateKey);
  var interSpki = await _spki(interKeys.publicKey);
  var interKeyPem = await _keyPem(interKeys.privateKey);
  var leafSpki = await _spki(leafKeys.publicKey);

  var rootPem = await pki.x509.sign({
    subject: "BIMI Test Root", subjectPublicKey: rootSpki, serialNumber: "0x01",
    notBefore: now, notAfter: far,
    extensions: {
      basicConstraints: { cA: true, pathLen: 2, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { key: rootKeyPem }, { pem: true });

  var interPem = await pki.x509.sign({
    subject: "BIMI Test Intermediate", subjectPublicKey: interSpki, serialNumber: "0x02",
    notBefore: now, notAfter: far,
    extensions: {
      basicConstraints: { cA: true, pathLen: 0, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { cert: rootPem, key: rootKeyPem }, { pem: true });

  var leafPem = await pki.x509.sign({
    subject: "example.com", subjectPublicKey: leafSpki, serialNumber: "0x03",
    notBefore: now, notAfter: far,
    extensions: {
      basicConstraints: { cA: false, critical: true },
      subjectAltName:   [{ dNSName: "example.com" }],
      extendedKeyUsage: [BIMI_EKU_OID], extendedKeyUsageCritical: false,
    },
  }, { cert: interPem, key: interKeyPem }, { pem: true });

  return {
    rootPem: rootPem,
    intermediatePem: interPem,
    leafPem: leafPem,
  };
}

// _generateSelfSignedScenario — a self-signed leaf (with SAN + BIMI EKU)
// paired with an unrelated root as the trust anchor. The verifier reaches
// the "self-signed root not in bundle" branch. The leaf omits keyUsage so
// node's checkIssued(self) treats it as a valid self-issuer (a
// keyUsage-without-keyCertSign issuer would be rejected).
async function _generateSelfSignedScenario() {
  var leafKeys = await _genKey();
  var otherKeys = await _genKey();
  var now = new Date();
  var far = new Date(now.getTime() + 10 * YEAR_MS);

  var leafSpki = await _spki(leafKeys.publicKey);
  var leafKeyPem = await _keyPem(leafKeys.privateKey);
  var otherSpki = await _spki(otherKeys.publicKey);
  var otherKeyPem = await _keyPem(otherKeys.privateKey);

  var leafPem = await pki.x509.sign({
    subject: "example.com", subjectPublicKey: leafSpki, serialNumber: "0x05",
    notBefore: now, notAfter: far,
    extensions: {
      basicConstraints: { cA: false, critical: true },
      subjectAltName:   [{ dNSName: "example.com" }],
      extendedKeyUsage: [BIMI_EKU_OID], extendedKeyUsageCritical: false,
    },
  }, { key: leafKeyPem }, { pem: true });

  var otherPem = await pki.x509.sign({
    subject: "Unrelated Root", subjectPublicKey: otherSpki, serialNumber: "0x06",
    notBefore: now, notAfter: far,
    extensions: {
      basicConstraints: { cA: true, pathLen: 1, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { key: otherKeyPem }, { pem: true });

  return {
    leafPem: leafPem,
    otherRootPem: otherPem,
  };
}

function _stubHttpClient(body, statusCode) {
  return {
    request: function (_opts) {
      return Promise.resolve({
        statusCode: statusCode === undefined ? 200 : statusCode,
        headers:    {},
        body:       Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8"),
      });
    },
  };
}

async function testFetchAndVerifyMarkSuccess() {
  var chain = await _generateTestChain({ sanDomain: "example.com" });
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:           "example.com",
    vmcUrl:           "https://example.com/cert.pem",
    trustAnchorsPem:  chain.rootPem,
    httpClient:       _stubHttpClient(chain.leafPem),
  });
  check("fetchAndVerifyMark: ok with valid chain",
        rv.ok === true && rv.vmcType === "vmc" &&
        rv.certificate && typeof rv.certificate.notAfter === "string");
}

async function testFetchAndVerifyMarkCmc() {
  var chain = await _generateTestChain({
    sanDomain: "example.com",
    policyOid: b.mail.bimi.CMC_POLICY_OID,
  });
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:           "example.com",
    vmcUrl:           "https://example.com/cert.pem",
    trustAnchorsPem:  chain.rootPem,
    httpClient:       _stubHttpClient(chain.leafPem),
  });
  check("fetchAndVerifyMark: CMC policy OID surfaces vmcType=cmc",
        rv.ok === true && rv.vmcType === "cmc" &&
        rv.certificate.policyOids.indexOf(b.mail.bimi.CMC_POLICY_OID) !== -1);
}

async function testFetchAndVerifyMarkChainInvalid() {
  // Issue chain1 leaf, but provide chain2 root as the trust anchor —
  // chain validation MUST fail.
  var chain1 = await _generateTestChain({ sanDomain: "example.com" });
  var chain2 = await _generateTestChain({ sanDomain: "example.com" });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:           "example.com",
      vmcUrl:           "https://example.com/cert.pem",
      trustAnchorsPem:  chain2.rootPem,
      httpClient:       _stubHttpClient(chain1.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: untrusted chain throws bimi/vmc-chain-invalid",
        threw && threw.code === "bimi/vmc-chain-invalid");
}

async function testFetchAndVerifyMarkDomainMismatch() {
  var chain = await _generateTestChain({ sanDomain: "other.com" });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:           "example.com",
      vmcUrl:           "https://example.com/cert.pem",
      trustAnchorsPem:  chain.rootPem,
      httpClient:       _stubHttpClient(chain.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: SAN mismatch throws bimi/vmc-domain-mismatch",
        threw && threw.code === "bimi/vmc-domain-mismatch");
}

async function testFetchAndVerifyMarkMissingEku() {
  var chain = await _generateTestChain({ sanDomain: "example.com", includeBimiEku: false });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:           "example.com",
      vmcUrl:           "https://example.com/cert.pem",
      trustAnchorsPem:  chain.rootPem,
      httpClient:       _stubHttpClient(chain.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: missing BIMI EKU throws bimi/vmc-policy-oid-missing",
        threw && threw.code === "bimi/vmc-policy-oid-missing");
}

async function testFetchAndVerifyMarkNoTrustAnchors() {
  var chain = await _generateTestChain({ sanDomain: "example.com" });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:           "example.com",
      vmcUrl:           "https://example.com/cert.pem",
      trustAnchorsPem:  "",
      httpClient:       _stubHttpClient(chain.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: empty trust-anchor bundle throws",
        threw && threw.code === "bimi/vmc-chain-invalid" &&
        /no trust anchors configured/.test(threw.message));
}

async function testFetchAndVerifyMarkBadPemBody() {
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:           "example.com",
      vmcUrl:           "https://example.com/cert.pem",
      trustAnchorsPem:  "ignored",
      httpClient:       _stubHttpClient("not a pem"),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: non-PEM body throws bimi/vmc-fetch-failed",
        threw && threw.code === "bimi/vmc-fetch-failed");
}

async function testFetchAndVerifyMarkHttpStatusFailure() {
  var chain = await _generateTestChain({ sanDomain: "example.com" });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:           "example.com",
      vmcUrl:           "https://example.com/cert.pem",
      trustAnchorsPem:  chain.rootPem,
      httpClient:       _stubHttpClient(chain.leafPem, 404),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: 404 status throws bimi/vmc-fetch-failed",
        threw && threw.code === "bimi/vmc-fetch-failed");
}

async function testFetchAndVerifyMarkBadOpts() {
  var threw = null;
  try { await b.mail.bimi.fetchAndVerifyMark({ domain: "" }); }
  catch (e) { threw = e; }
  check("fetchAndVerifyMark: empty domain throws bimi/bad-opts",
        threw && threw.code === "bimi/bad-opts");

  threw = null;
  try { await b.mail.bimi.fetchAndVerifyMark({ domain: "example.com" }); }
  catch (e) { threw = e; }
  check("fetchAndVerifyMark: missing vmcUrl/cmcUrl throws bimi/bad-opts",
        threw && threw.code === "bimi/bad-opts");

  threw = null;
  try { await b.mail.bimi.fetchAndVerifyMark({ domain: "example.com", vmcUrl: "http://insecure" }); }
  catch (e) { threw = e; }
  check("fetchAndVerifyMark: non-https vmcUrl throws bimi/bad-opts",
        threw && threw.code === "bimi/bad-opts");
}

// ---- recordShape adversarial branches ----

function testRecordShapeNonHttpsLogo() {
  var threw = null;
  try { b.mail.bimi.recordShape({ logoUrl: "http://example.com/logo.svg" }); }
  catch (e) { threw = e; }
  check("recordShape: non-https logoUrl throws mail-bimi/bad-logoUrl",
        threw && threw.code === "mail-bimi/bad-logoUrl");
}

function testRecordShapeSemicolonLogo() {
  // A semicolon survives safeUrl.parse (legal in the path) but must be
  // refused as a TXT record-separator injection vector.
  var threw = null;
  try { b.mail.bimi.recordShape({ logoUrl: "https://example.com/logo.svg;a=evil" }); }
  catch (e) { threw = e; }
  check("recordShape: record-separator in logoUrl throws mail-bimi/bad-logo",
        threw && threw.code === "mail-bimi/bad-logo");
}

function testRecordShapeSemicolonVmc() {
  var threw = null;
  try {
    b.mail.bimi.recordShape({
      logoUrl: "https://example.com/logo.svg",
      vmcUrl:  "https://example.com/cert.pem;a=evil",
    });
  } catch (e) { threw = e; }
  check("recordShape: record-separator in vmcUrl throws mail-bimi/bad-vmc",
        threw && threw.code === "mail-bimi/bad-vmc");
}

function testRecordShapeNonHttpsVmc() {
  var threw = null;
  try {
    b.mail.bimi.recordShape({
      logoUrl: "https://example.com/logo.svg",
      vmcUrl:  "http://example.com/cert.pem",
    });
  } catch (e) { threw = e; }
  check("recordShape: non-https vmcUrl throws mail-bimi/bad-vmcUrl",
        threw && threw.code === "mail-bimi/bad-vmcUrl");
}

// ---- parseRecord defensive branches ----

function testParseRecordNonString() {
  check("parseRecord: number input returns null",
        b.mail.bimi.parseRecord(12345) === null);
  check("parseRecord: null input returns null",
        b.mail.bimi.parseRecord(null) === null);
}

function testParseRecordTooLong() {
  var big = "v=BIMI1; l=https://example.com/" + "a".repeat(2100);
  check("parseRecord: record over 2 KiB cap returns null",
        b.mail.bimi.parseRecord(big) === null);
}

// ---- fetchPolicy (DNS lookup path) ----

function _dnsStub(rows) {
  return function (_qname, _type) { return Promise.resolve(rows); };
}
function _dnsReject(err) {
  return function () { return Promise.reject(err); };
}

async function testFetchPolicySuccess() {
  var pol = await b.mail.bimi.fetchPolicy("example.com", {
    dnsLookup: _dnsStub([
      ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem"],
    ]),
  });
  check("fetchPolicy: resolves and parses the BIMI record",
        pol && pol.v === "BIMI1" &&
        pol.l === "https://example.com/logo.svg" &&
        pol.a === "https://example.com/cert.pem");
}

async function testFetchPolicySelectorMultiChunk() {
  // Non-default selector; first record is not BIMI (skipped), second is a
  // multi-chunk TXT that must be joined before parsing.
  var pol = await b.mail.bimi.fetchPolicy("example.com", {
    selector:  "brand",
    dnsLookup: _dnsStub([
      ["v=spf1 -all"],
      ["v=BIMI1; ", "l=https://example.com/logo.svg"],
    ]),
  });
  check("fetchPolicy: selector + multi-chunk record joins and parses",
        pol && pol.v === "BIMI1" && pol.l === "https://example.com/logo.svg");
}

async function testFetchPolicyStringRow() {
  // A resolver that returns flat string rows (not string[] chunks) must
  // still parse — the record is coerced via String(rec).
  var pol = await b.mail.bimi.fetchPolicy("example.com", {
    dnsLookup: _dnsStub(["v=BIMI1; l=https://example.com/logo.svg"]),
  });
  check("fetchPolicy: flat string TXT row is coerced and parsed",
        pol && pol.v === "BIMI1" && pol.l === "https://example.com/logo.svg");
}

async function testFetchPolicyNoBimiRecord() {
  var pol = await b.mail.bimi.fetchPolicy("example.com", {
    dnsLookup: _dnsStub([["v=spf1 -all"], ["random text"]]),
  });
  check("fetchPolicy: no v=BIMI1 record returns null", pol === null);
}

async function testFetchPolicyAbsence() {
  // ENODATA / ENOTFOUND => absence, not error => null.
  var e = new Error("no TXT records");
  e.code = "ENODATA";
  var pol = await b.mail.bimi.fetchPolicy("example.com", {
    dnsLookup: _dnsReject(e),
  });
  check("fetchPolicy: ENODATA absence returns null", pol === null);
}

async function testFetchPolicyLookupFailure() {
  var threw = null;
  try {
    await b.mail.bimi.fetchPolicy("example.com", {
      dnsLookup: _dnsReject(new Error("SERVFAIL")),
    });
  } catch (err) { threw = err; }
  check("fetchPolicy: non-absence lookup failure throws mail-bimi/lookup-failed",
        threw && threw.code === "mail-bimi/lookup-failed");
}

async function testFetchPolicyBadDomain() {
  var threw = null;
  try { await b.mail.bimi.fetchPolicy(""); }
  catch (err) { threw = err; }
  check("fetchPolicy: empty domain throws mail-bimi/bad-domain",
        threw && threw.code === "mail-bimi/bad-domain");
}

// ---- validateTinyPsSvg additional tokenizer / cap branches ----

function testTinyPsSvgTooLargeBuffer() {
  var threw = null;
  try { b.mail.bimi.validateTinyPsSvg(Buffer.alloc(40000, 0x20)); }
  catch (e) { threw = e; }
  check("tiny-ps: oversized Buffer throws bimi/svg-too-large",
        threw && threw.code === "bimi/svg-too-large");
}

function testTinyPsSvgComment() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><!-- a comment --></svg>');
  check("tiny-ps: well-formed comment is allowed", rv.ok === true);
}

function testTinyPsSvgUnterminatedComment() {
  var threw = null;
  try {
    b.mail.bimi.validateTinyPsSvg(
      '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><!-- never closed');
  } catch (e) { threw = e; }
  check("tiny-ps: unterminated comment throws bimi/svg-tiny-ps-violation (parse-failed)",
        threw && threw.code === "bimi/svg-tiny-ps-violation" &&
        /parse-failed/.test(threw.message));
}

function testTinyPsSvgCdata() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><title><![CDATA[hi]]></title></svg>');
  check("tiny-ps: CDATA section is tolerated", rv.ok === true);
}

function testTinyPsSvgUnterminatedCdata() {
  var threw = null;
  try {
    b.mail.bimi.validateTinyPsSvg(
      '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><![CDATA[unterminated');
  } catch (e) { threw = e; }
  check("tiny-ps: unterminated CDATA throws parse-failed",
        threw && threw.code === "bimi/svg-tiny-ps-violation");
}

function testTinyPsSvgDeclaration() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<!ENTITY foo "bar"><svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"></svg>');
  check("tiny-ps: non-DOCTYPE declaration flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "declaration-forbidden"; }));
}

function testTinyPsSvgUnterminatedDeclaration() {
  var threw = null;
  try { b.mail.bimi.validateTinyPsSvg("<!ENTITY foo"); }
  catch (e) { threw = e; }
  check("tiny-ps: unterminated declaration throws parse-failed",
        threw && threw.code === "bimi/svg-tiny-ps-violation");
}

function testTinyPsSvgProcessingInstruction() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><?php echo 1 ?></svg>');
  check("tiny-ps: non-xml processing instruction flagged",
        !rv.ok && rv.violations.some(function (v) { return v.code === "pi-forbidden"; }));
}

function testTinyPsSvgAnimatePrefixElement() {
  // Starts with "animate" but is not in the static forbidden list — the
  // prefix rule must still refuse it (future SMIL animation elements).
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><animateColor/></svg>');
  check("tiny-ps: animate-prefixed element flagged as animation",
        !rv.ok && rv.violations.some(function (v) {
          return v.code === "element-forbidden" && /animation element/.test(v.message);
        }));
}

function testTinyPsSvgTrailingText() {
  var rv = b.mail.bimi.validateTinyPsSvg(GOOD_SVG + "trailing text after root");
  check("tiny-ps: trailing text after root is tokenized without crash",
        rv.ok === true);
}

function testTinyPsSvgUnterminatedDoctype() {
  var threw = null;
  try { b.mail.bimi.validateTinyPsSvg("<!DOCTYPE svg"); }
  catch (e) { threw = e; }
  check("tiny-ps: unterminated doctype throws parse-failed",
        threw && threw.code === "bimi/svg-tiny-ps-violation");
}

function testTinyPsSvgUnterminatedProcessingInstruction() {
  var threw = null;
  try { b.mail.bimi.validateTinyPsSvg("<?xml foo"); }
  catch (e) { threw = e; }
  check("tiny-ps: unterminated processing instruction throws parse-failed",
        threw && threw.code === "bimi/svg-tiny-ps-violation");
}

function testTinyPsSvgUnterminatedEndTag() {
  var threw = null;
  try {
    b.mail.bimi.validateTinyPsSvg(
      '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"></svg');
  } catch (e) { threw = e; }
  check("tiny-ps: unterminated end tag throws parse-failed",
        threw && threw.code === "bimi/svg-tiny-ps-violation");
}

function testTinyPsSvgUnterminatedStartTag() {
  var threw = null;
  try { b.mail.bimi.validateTinyPsSvg('<svg version="1.2"'); }
  catch (e) { threw = e; }
  check("tiny-ps: unterminated start tag throws parse-failed",
        threw && threw.code === "bimi/svg-tiny-ps-violation");
}

function testTinyPsSvgSingleQuotedAttrs() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    "<svg version='1.2' baseProfile='tiny-ps' viewBox='0 0 1 1'></svg>");
  check("tiny-ps: single-quoted attributes accepted", rv.ok === true);
}

function testTinyPsSvgMissingVersion() {
  var rv = b.mail.bimi.validateTinyPsSvg(
    '<svg baseProfile="tiny-ps" viewBox="0 0 1 1"></svg>');
  check("tiny-ps: entirely-missing version flagged as (missing)",
        !rv.ok && rv.violations.some(function (v) {
          return v.code === "bad-version" && /\(missing\)/.test(v.message);
        }));
}

// ---- fetchAndVerifyMark additional error / chain / audit branches ----

function _throwingHttpClient(err) {
  return { request: function () { return Promise.reject(err); } };
}

async function testFetchAndVerifyMarkRequestThrows() {
  var chain = await _generateTestChain();
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.rootPem,
      httpClient:      _throwingHttpClient(new Error("ECONNREFUSED")),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: transport error throws bimi/vmc-fetch-failed",
        threw && threw.code === "bimi/vmc-fetch-failed" && /ECONNREFUSED/.test(threw.message));
}

async function testFetchAndVerifyMarkNoPemBlocks() {
  // Body contains a BEGIN marker (passes the has-PEM check) but no END —
  // _splitPemChain yields zero blocks.
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: "anchor",
      httpClient:      _stubHttpClient("-----BEGIN CERTIFICATE-----\nabc\n"),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: BEGIN-only body throws (no CERTIFICATE blocks)",
        threw && threw.code === "bimi/vmc-fetch-failed" &&
        /no CERTIFICATE blocks/.test(threw.message));
}

async function testFetchAndVerifyMarkGarbageIntermediate() {
  var chain = await _generateTestChain();
  var body = chain.leafPem +
    "\n-----BEGIN CERTIFICATE-----\nnot-valid-der\n-----END CERTIFICATE-----\n";
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.rootPem,
      httpClient:      _stubHttpClient(body),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: unparseable intermediate throws bimi/vmc-chain-invalid",
        threw && threw.code === "bimi/vmc-chain-invalid" &&
        /X.509 parse failed/.test(threw.message));
}

async function testFetchAndVerifyMarkGarbageTrustAnchor() {
  var chain = await _generateTestChain();
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: "-----BEGIN CERTIFICATE-----\nnot-valid\n-----END CERTIFICATE-----",
      httpClient:      _stubHttpClient(chain.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: unparseable trust anchor throws bimi/vmc-chain-invalid",
        threw && threw.code === "bimi/vmc-chain-invalid" &&
        /trust-anchor PEM parse failed/.test(threw.message));
}

async function testFetchAndVerifyMarkExpiredCert() {
  var chain = await _generateTestChain({
    leafNotBefore: new Date(Date.now() - 2 * YEAR_MS),
    leafNotAfter:  new Date(Date.now() - YEAR_MS),
  });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.rootPem,
      httpClient:      _stubHttpClient(chain.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: expired leaf throws bimi/vmc-chain-invalid (expired)",
        threw && threw.code === "bimi/vmc-chain-invalid" && /expired/.test(threw.message));
}

async function testFetchAndVerifyMarkNotYetValidCert() {
  var chain = await _generateTestChain({
    leafNotBefore: new Date(Date.now() + YEAR_MS),
    leafNotAfter:  new Date(Date.now() + 2 * YEAR_MS),
  });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.rootPem,
      httpClient:      _stubHttpClient(chain.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: not-yet-valid leaf throws bimi/vmc-chain-invalid",
        threw && threw.code === "bimi/vmc-chain-invalid" && /not-yet-valid/.test(threw.message));
}

async function testFetchAndVerifyMarkThreeLevelChain() {
  var chain = await _generateThreeLevelChain();
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(chain.leafPem + "\n" + chain.intermediatePem),
  });
  check("fetchAndVerifyMark: leaf->intermediate->root chain validates",
        rv.ok === true && rv.vmcType === "vmc");
}

async function testFetchAndVerifyMarkSelfSignedNotInBundle() {
  var scenario = await _generateSelfSignedScenario();
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: scenario.otherRootPem,
      httpClient:      _stubHttpClient(scenario.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: self-signed leaf not in bundle throws chain-invalid",
        threw && threw.code === "bimi/vmc-chain-invalid" &&
        /self-signed root not in trust-anchor/.test(threw.message));
}

async function testFetchAndVerifyMarkUriSanSuccess() {
  var chain = await _generateTestChain({
    sanEntries: [{ type: "url", value: "https://example.com" }],
  });
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(chain.leafPem),
  });
  check("fetchAndVerifyMark: URI-form SAN matches the BIMI domain",
        rv.ok === true);
}

async function testFetchAndVerifyMarkUriSanMalformed() {
  // A URI SAN carrying userinfo is refused by the URL parser — the SAN
  // matcher must fail closed (no substring fallback) rather than vouch for
  // the domain. documents current behavior.
  var chain = await _generateTestChain({
    sanEntries: [{ type: "url", value: "https://evil@example.com" }],
  });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.rootPem,
      httpClient:      _stubHttpClient(chain.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: unparseable URI SAN fails closed (domain-mismatch)",
        threw && threw.code === "bimi/vmc-domain-mismatch");
}

async function testFetchAndVerifyMarkNoSan() {
  var chain = await _generateTestChain({ noSan: true });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.rootPem,
      httpClient:      _stubHttpClient(chain.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: certificate without SAN throws domain-mismatch (none)",
        threw && threw.code === "bimi/vmc-domain-mismatch" && /\(none\)/.test(threw.message));
}

async function testFetchAndVerifyMarkLogotypeSvg() {
  var svgStr = '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"></svg>';
  var chain = await _generateTestChain({ logoSvg: svgStr });
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(chain.leafPem),
  });
  check("fetchAndVerifyMark: RFC 3709 logotype SVG is extracted onto mark.svg",
        rv.ok === true && typeof rv.mark.svg === "string" &&
        rv.mark.svg.indexOf("<svg") !== -1);
}

async function testFetchAndVerifyMarkLogotypeNonSvgLeafThenSvg() {
  // A logotype SEQUENCE whose first leaf is not an SVG magic prefix — the
  // scanner skips it and keeps descending to the SVG leaf.
  var svgStr = '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"></svg>';
  var seq = _derSequence(Buffer.concat([_OCTET_NON_SVG, _octetOf(svgStr)]));
  var chain = await _generateTestChain({ logotypeExt: _logotypeExtensionRaw(seq) });
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(chain.leafPem),
  });
  check("fetchAndVerifyMark: scanner skips non-SVG leaf and finds the SVG",
        rv.ok === true && typeof rv.mark.svg === "string" &&
        rv.mark.svg.indexOf("<svg") !== -1);
}

async function testFetchAndVerifyMarkLogotypeNoSvg() {
  // A logotype SEQUENCE with no SVG payload — the scan returns null and the
  // mark carries no svg.
  var seq = _derSequence(_OCTET_NON_SVG);
  var chain = await _generateTestChain({ logotypeExt: _logotypeExtensionRaw(seq) });
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(chain.leafPem),
  });
  check("fetchAndVerifyMark: logotype without SVG yields mark.svg === null",
        rv.ok === true && rv.mark.svg === null);
}

async function testFetchAndVerifyMarkLogotypeTruncatedSequence() {
  // Logotype value where the outer SEQUENCE fails a full sequence-decode
  // (trailing incomplete TLV) but the first complete TLV still decodes to
  // the SVG — exercises the readNode fallback in the scanner.
  var inner = Buffer.from([0x30, 0x07, 0x04, 0x04, 0x3C, 0x73, 0x76, 0x67, 0xFF]);
  var chain = await _generateTestChain({ logotypeExt: _logotypeExtensionRaw(inner) });
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(chain.leafPem),
  });
  check("fetchAndVerifyMark: scanner recovers SVG via readNode fallback",
        rv.ok === true && typeof rv.mark.svg === "string" &&
        rv.mark.svg.indexOf("<svg") !== -1);
}

async function testFetchAndVerifyMarkStringBodyAndExplicitOpts() {
  // Response body delivered as a string (not Buffer) with explicit
  // timeoutMs / maxResponseBytes overrides.
  var chain = await _generateTestChain();
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:           "example.com",
    vmcUrl:           "https://example.com/cert.pem",
    trustAnchorsPem:  chain.rootPem,
    timeoutMs:        5000,
    maxResponseBytes: 65536,
    httpClient:       {
      request: function () {
        return Promise.resolve({ statusCode: 200, headers: {}, body: chain.leafPem });
      },
    },
  });
  check("fetchAndVerifyMark: string body + explicit timeout/maxBytes validates",
        rv.ok === true);
}

async function testFetchAndVerifyMarkAuditSinkSuccess() {
  var chain = await _generateTestChain();
  var events = [];
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:           "example.com",
    vmcUrl:           "https://example.com/cert.pem",
    trustAnchorsPem:  chain.rootPem,
    httpClient:       _stubHttpClient(chain.leafPem),
    evidenceDocument: "https://example.com/evidence.pdf",
    audit:            { safeEmit: function (rec) { events.push(rec); } },
  });
  check("fetchAndVerifyMark: operator audit sink receives the success event",
        rv.ok === true &&
        rv.mark.evidenceDocument === "https://example.com/evidence.pdf" &&
        events.some(function (e) {
          return e.action === "mail.bimi.vmc.verified" && e.outcome === "success";
        }));
}

async function testFetchAndVerifyMarkAuditSinkThrows() {
  // A throwing audit sink must NOT break the verify hot path (drop-silent).
  var chain = await _generateTestChain();
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(chain.leafPem),
    audit:           { safeEmit: function () { throw new Error("sink boom"); } },
  });
  check("fetchAndVerifyMark: throwing audit sink is swallowed (verify still succeeds)",
        rv.ok === true);
}

// _generateFourLevelChain — root -> interA -> interB -> leaf. The fetched
// body carries [leaf, interB, interA] (interB BEFORE interA on purpose):
// walking interB's issuer, the verifier encounters interB itself in the
// intermediates array before interA, exercising the `cand === current`
// self-skip branch of _verifyCertChain.
async function _generateFourLevelChain() {
  var rootKeys = await _genKey();
  var interAKeys = await _genKey();
  var interBKeys = await _genKey();
  var leafKeys = await _genKey();
  var now = new Date();
  var far = new Date(now.getTime() + 10 * YEAR_MS);

  var rootKeyPem = await _keyPem(rootKeys.privateKey);
  var interAKeyPem = await _keyPem(interAKeys.privateKey);
  var interBKeyPem = await _keyPem(interBKeys.privateKey);

  var rootPem = await pki.x509.sign({
    subject: "BIMI Test Root", subjectPublicKey: await _spki(rootKeys.publicKey),
    serialNumber: "0x01", notBefore: now, notAfter: far,
    extensions: {
      basicConstraints: { cA: true, pathLen: 3, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { key: rootKeyPem }, { pem: true });

  var interAPem = await pki.x509.sign({
    subject: "BIMI Test Intermediate A", subjectPublicKey: await _spki(interAKeys.publicKey),
    serialNumber: "0x02", notBefore: now, notAfter: far,
    extensions: {
      basicConstraints: { cA: true, pathLen: 2, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { cert: rootPem, key: rootKeyPem }, { pem: true });

  var interBPem = await pki.x509.sign({
    subject: "BIMI Test Intermediate B", subjectPublicKey: await _spki(interBKeys.publicKey),
    serialNumber: "0x03", notBefore: now, notAfter: far,
    extensions: {
      basicConstraints: { cA: true, pathLen: 0, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { cert: interAPem, key: interAKeyPem }, { pem: true });

  var leafPem = await pki.x509.sign({
    subject: "example.com", subjectPublicKey: await _spki(leafKeys.publicKey),
    serialNumber: "0x04", notBefore: now, notAfter: far,
    extensions: {
      basicConstraints: { cA: false, critical: true },
      subjectAltName:   [{ dNSName: "example.com" }],
      extendedKeyUsage: [BIMI_EKU_OID], extendedKeyUsageCritical: false,
    },
  }, { cert: interBPem, key: interBKeyPem }, { pem: true });

  return { rootPem: rootPem, interAPem: interAPem, interBPem: interBPem, leafPem: leafPem };
}

function testTinyPsSvgBareUnquotedAttrs() {
  // Bare (unquoted) version / baseProfile values exercise the third alternation
  // of the attribute regex (the `[^\s>]+` capture, m[5]) — distinct from the
  // double-quoted (m[3]) and single-quoted (m[4]) paths. viewBox stays a valid
  // quoted four-number box so this stays valid if viewBox format checking tightens.
  var rv = b.mail.bimi.validateTinyPsSvg(
    "<svg version=1.2 baseProfile=tiny-ps viewBox=\"0 0 1 1\"></svg>");
  check("tiny-ps: bare unquoted version/baseProfile are parsed and validate",
        rv.ok === true && rv.violations.length === 0);
}

async function testFetchAndVerifyMarkRequestRejectsNonError() {
  // The httpClient rejects with a NON-Error value (a bare string). The
  // fetch-failed path must fall back to String(e) for both the audit
  // reason and the thrown message.
  var chain = await _generateTestChain();
  var nonErr = "socket hang up (bare-string reason)";
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.rootPem,
      httpClient:      _throwingHttpClient(nonErr),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: non-Error rejection uses String(e) fallback in message",
        threw && threw.code === "bimi/vmc-fetch-failed" &&
        threw.message.indexOf("bare-string reason") !== -1);
}

async function testFetchAndVerifyMarkNullBody() {
  // A 200 response with a null body: the `rsp.body || ""` fallback yields
  // an empty string, which fails the has-PEM check.
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: "anchor",
      httpClient:      { request: function () {
        return Promise.resolve({ statusCode: 200, headers: {}, body: null });
      } },
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: null response body coerces to empty and throws vmc-fetch-failed",
        threw && threw.code === "bimi/vmc-fetch-failed" &&
        /not a PEM-encoded CERTIFICATE chain/.test(threw.message));
}

async function testFetchAndVerifyMarkFourLevelChain() {
  // A deeper leaf -> interB -> interA -> root chain validates to a VMC. The body
  // orders the intermediates [interB, interA], so the issuer walk encounters
  // interB before interA and exercises the self-skip continue; because interB is
  // not its own issuer the walk still selects interA either way, so this pins the
  // multi-intermediate happy path rather than the self-skip in isolation.
  var chain = await _generateFourLevelChain();
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(
      chain.leafPem + "\n" + chain.interBPem + "\n" + chain.interAPem),
  });
  check("fetchAndVerifyMark: a four-level leaf->interB->interA->root chain validates to a VMC",
        rv.ok === true && rv.vmcType === "vmc");
}

async function testFetchAndVerifyMarkDomainCanonicalizesEmpty() {
  // The empty-canonical-domain guard is a SAN-authorization backstop: an operator
  // BIMI domain that canonicalizes to "" (here via a path separator) must NEVER
  // match a cert whose DNS SAN ALSO canonicalizes to "". The fixture's SAN is
  // "a..b" — itself canonicalizing to "" — so without the `dom.length === 0`
  // guard the matcher would compare "" === "" and vouch this garbage-SAN cert for
  // the domain (SAN-authorization bypass). With the guard it fails closed. The
  // "" SAN makes this test RED if the guard is removed (the prior example.com SAN
  // passed either way, so it did not protect the guard).
  var chain = await _generateTestChain({ sanEntries: [{ type: "dns", value: "a..b" }] });
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com/evil",   // canonicalizes to ""
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.rootPem,
      httpClient:      _stubHttpClient(chain.leafPem),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: an empty-canonical domain never matches an empty-canonical SAN (fails closed, domain-mismatch)",
        threw && threw.code === "bimi/vmc-domain-mismatch");
}

async function testFetchAndVerifyMarkLogotypeShortOctet() {
  // A logotype SEQUENCE whose only leaf is a < 4-byte OCTET STRING — the
  // scanner rejects it as too short to hold a magic prefix and yields no
  // svg.
  var shortSeq = _derSequence(Buffer.from([0x04, 0x02, 0x41, 0x42]));
  var chain = await _generateTestChain({ logotypeExt: _logotypeExtensionRaw(shortSeq) });
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(chain.leafPem),
  });
  check("fetchAndVerifyMark: short (<4B) logotype leaf yields mark.svg === null",
        rv.ok === true && rv.mark.svg === null);
}

async function testFetchAndVerifyMarkLogotypeUnparseableInner() {
  // A logotype whose inner constructed value fails BOTH readSequence and
  // the single-node readNode fallback (truncated child TLV) — the scanner
  // returns null via the inner catch.
  var badInner = Buffer.from([0x30, 0x03, 0x04, 0x05, 0x41]);
  var chain = await _generateTestChain({ logotypeExt: _logotypeExtensionRaw(badInner) });
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "example.com",
    vmcUrl:          "https://example.com/cert.pem",
    trustAnchorsPem: chain.rootPem,
    httpClient:      _stubHttpClient(chain.leafPem),
  });
  check("fetchAndVerifyMark: unparseable logotype inner yields mark.svg === null",
        rv.ok === true && rv.mark.svg === null);
}

// _generateDeepChain — a leaf plus `depth` CA intermediates, each issued by
// the next (leaf <- i1 <- i2 <- ... <- i{depth}), with the top intermediate
// self-signed. Paired with an UNRELATED trust anchor that issues nothing in
// the chain, so the verifier never matches an anchor and never hits a
// self-signed root it recognizes — it walks link by link until the
// MAX_DEPTH-bounded loop is exhausted. depth === 8 drives the
// "chain depth exceeded" branch of _verifyCertChain.
async function _generateDeepChain(depth) {
  var now = new Date();
  var far = new Date(now.getTime() + 10 * YEAR_MS);

  // interKeys[0] => i1 (issues the leaf) ... interKeys[depth-1] => i{depth} (top).
  var interKeys = [];
  for (var k = 0; k < depth; k += 1) interKeys.push(await _genKey());
  var leafKeys = await _genKey();

  var interPems = new Array(depth);
  var topIdx = depth - 1;
  var topKeyPem = await _keyPem(interKeys[topIdx].privateKey);
  // Top intermediate: self-signed CA. It is only ever referenced as the
  // issuer at the final walk step (becoming `current` exactly as the loop
  // exits), so its self-signed status is never inspected.
  interPems[topIdx] = await pki.x509.sign({
    subject:          "BIMI Deep Intermediate " + depth,
    subjectPublicKey: await _spki(interKeys[topIdx].publicKey),
    serialNumber:     "0x" + (0x60 + depth).toString(16),
    notBefore:        now,
    notAfter:         far,
    extensions: {
      basicConstraints: { cA: true, pathLen: depth - 1, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { key: topKeyPem }, { pem: true });

  for (var j = depth - 2; j >= 0; j -= 1) {
    var issuerKeyPem = await _keyPem(interKeys[j + 1].privateKey);
    interPems[j] = await pki.x509.sign({
      subject:          "BIMI Deep Intermediate " + (j + 1),
      subjectPublicKey: await _spki(interKeys[j].publicKey),
      serialNumber:     "0x" + (0x60 + j + 1).toString(16),
      notBefore:        now,
      notAfter:         far,
      extensions: {
        // pathLen must strictly decrease down the chain (RFC 5280 4.2.1.9);
        // i{j+1} issues the CA i{j} whose own pathLen is j.
        basicConstraints: { cA: true, pathLen: j, critical: true },
        keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
      },
    }, { cert: interPems[j + 1], key: issuerKeyPem }, { pem: true });
  }

  var i1KeyPem = await _keyPem(interKeys[0].privateKey);
  var leafPem = await pki.x509.sign({
    subject:          "example.com",
    subjectPublicKey: await _spki(leafKeys.publicKey),
    serialNumber:     "0x4a",
    notBefore:        now,
    notAfter:         far,
    extensions: {
      basicConstraints: { cA: false, critical: true },
      subjectAltName:   [{ dNSName: "example.com" }],
      extendedKeyUsage: [BIMI_EKU_OID], extendedKeyUsageCritical: false,
    },
  }, { cert: interPems[0], key: i1KeyPem }, { pem: true });

  // An unrelated CA used as the sole trust anchor. It issued none of the
  // chain certs, so issuerValidlyIssued(anchor, current) is false at every
  // depth and the walk is never short-circuited by an anchor match.
  var otherKeys = await _genKey();
  var otherKeyPem = await _keyPem(otherKeys.privateKey);
  var unrelatedRootPem = await pki.x509.sign({
    subject:          "BIMI Deep Unrelated Root",
    subjectPublicKey: await _spki(otherKeys.publicKey),
    serialNumber:     "0x5a",
    notBefore:        now,
    notAfter:         far,
    extensions: {
      basicConstraints: { cA: true, pathLen: 1, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { key: otherKeyPem }, { pem: true });

  return {
    leafPem:          leafPem,
    intermediatePems: interPems,
    unrelatedRootPem: unrelatedRootPem,
  };
}

async function testFetchAndVerifyMarkChainDepthExceeded() {
  // A chain longer than the verifier's MAX_DEPTH (8): leaf + 8 CA
  // intermediates, each validly issued by the next, with an UNRELATED trust
  // anchor that matches nothing. The issuer walk terminates on neither an
  // anchor nor a recognized self-signed root, so the depth-bounded loop is
  // exhausted and validation fails specifically with "chain depth exceeded"
  // (not "no issuer found" — every link resolves an issuer).
  var chain = await _generateDeepChain(8);
  var body = chain.leafPem + "\n" + chain.intermediatePems.join("\n");
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.unrelatedRootPem,
      httpClient:      _stubHttpClient(body),
    });
  } catch (e) { threw = e; }
  check("fetchAndVerifyMark: chain deeper than MAX_DEPTH throws chain-invalid (depth exceeded)",
        threw && threw.code === "bimi/vmc-chain-invalid" &&
        /chain depth exceeded 8/.test(threw.message));
}

async function run() {
  testSurface();
  testRecordShape();
  testParseRecord();

  testTinyPsSvgValid();
  testTinyPsSvgValidWithXmlProlog();
  testTinyPsSvgValidBufferInput();
  testTinyPsSvgRootNotSvg();
  testTinyPsSvgBadVersion();
  testTinyPsSvgBadBaseProfile();
  testTinyPsSvgMissingViewBox();
  testTinyPsSvgScript();
  testTinyPsSvgStyleElement();
  testTinyPsSvgForeignObject();
  testTinyPsSvgAnimate();
  testTinyPsSvgFilter();
  testTinyPsSvgImage();
  testTinyPsSvgExternalHref();
  testTinyPsSvgFragmentHrefAllowed();
  testTinyPsSvgEventHandler();
  testTinyPsSvgStyleAttr();
  testTinyPsSvgDoctype();
  testTinyPsSvgMultipleRoots();
  testTinyPsSvgTooLarge();
  testTinyPsSvgBadInput();

  testRecordShapeNonHttpsLogo();
  testRecordShapeSemicolonLogo();
  testRecordShapeSemicolonVmc();
  testRecordShapeNonHttpsVmc();
  testParseRecordNonString();
  testParseRecordTooLong();

  testTinyPsSvgTooLargeBuffer();
  testTinyPsSvgComment();
  testTinyPsSvgUnterminatedComment();
  testTinyPsSvgCdata();
  testTinyPsSvgUnterminatedCdata();
  testTinyPsSvgDeclaration();
  testTinyPsSvgUnterminatedDeclaration();
  testTinyPsSvgProcessingInstruction();
  testTinyPsSvgAnimatePrefixElement();
  testTinyPsSvgTrailingText();
  testTinyPsSvgUnterminatedDoctype();
  testTinyPsSvgUnterminatedProcessingInstruction();
  testTinyPsSvgUnterminatedEndTag();
  testTinyPsSvgUnterminatedStartTag();
  testTinyPsSvgSingleQuotedAttrs();
  testTinyPsSvgMissingVersion();
  testTinyPsSvgBareUnquotedAttrs();

  await testFetchAndVerifyMarkSuccess();
  await testFetchAndVerifyMarkCmc();
  await testFetchAndVerifyMarkChainInvalid();
  await testFetchAndVerifyMarkDomainMismatch();
  await testFetchAndVerifyMarkMissingEku();
  await testFetchAndVerifyMarkNoTrustAnchors();
  await testFetchAndVerifyMarkBadPemBody();
  await testFetchAndVerifyMarkHttpStatusFailure();
  await testFetchAndVerifyMarkBadOpts();

  await testFetchPolicySuccess();
  await testFetchPolicySelectorMultiChunk();
  await testFetchPolicyStringRow();
  await testFetchPolicyNoBimiRecord();
  await testFetchPolicyAbsence();
  await testFetchPolicyLookupFailure();
  await testFetchPolicyBadDomain();

  await testFetchAndVerifyMarkRequestThrows();
  await testFetchAndVerifyMarkNoPemBlocks();
  await testFetchAndVerifyMarkGarbageIntermediate();
  await testFetchAndVerifyMarkGarbageTrustAnchor();
  await testFetchAndVerifyMarkExpiredCert();
  await testFetchAndVerifyMarkNotYetValidCert();
  await testFetchAndVerifyMarkThreeLevelChain();
  await testFetchAndVerifyMarkSelfSignedNotInBundle();
  await testFetchAndVerifyMarkUriSanSuccess();
  await testFetchAndVerifyMarkUriSanMalformed();
  await testFetchAndVerifyMarkNoSan();
  await testFetchAndVerifyMarkLogotypeSvg();
  await testFetchAndVerifyMarkLogotypeNonSvgLeafThenSvg();
  await testFetchAndVerifyMarkLogotypeNoSvg();
  await testFetchAndVerifyMarkLogotypeTruncatedSequence();
  await testFetchAndVerifyMarkStringBodyAndExplicitOpts();
  await testFetchAndVerifyMarkAuditSinkSuccess();
  await testFetchAndVerifyMarkAuditSinkThrows();

  await testFetchAndVerifyMarkRequestRejectsNonError();
  await testFetchAndVerifyMarkNullBody();
  await testFetchAndVerifyMarkFourLevelChain();
  await testFetchAndVerifyMarkChainDepthExceeded();
  await testFetchAndVerifyMarkDomainCanonicalizesEmpty();
  await testFetchAndVerifyMarkLogotypeShortOctet();
  await testFetchAndVerifyMarkLogotypeUnparseableInner();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
