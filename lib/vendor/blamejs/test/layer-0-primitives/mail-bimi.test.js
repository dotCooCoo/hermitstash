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

var pki = require("../../lib/vendor/pki.cjs");
var x509 = pki.x509;
var nodeCrypto = require("crypto");

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

function _genKey() {
  return pki.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

// _logotypeExtension — a minimal RFC 3709 id-pe-logotype extension whose
// value is `SEQUENCE { OCTET STRING <svg...> }`, exercising both the
// constructed-recursion and primitive-match paths of the framework's
// best-effort embedded-SVG scanner. The SVG stays < 128 bytes so every
// DER length is single-byte.
function _logotypeExtension(svgText) {
  var svg = Buffer.from(svgText, "utf8");
  var octet = Buffer.concat([Buffer.from([0x04, svg.length]), svg]);
  var seq = Buffer.concat([Buffer.from([0x30, octet.length]), octet]);
  return new x509.Extension(ID_PE_LOGOTYPE_OID, false, seq);
}

// _logotypeExtensionRaw — id-pe-logotype extension over caller-supplied
// DER, so a test can exercise the scanner's non-SVG-leaf, no-match, and
// truncated-SEQUENCE fallback branches directly.
function _logotypeExtensionRaw(innerDer) {
  return new x509.Extension(ID_PE_LOGOTYPE_OID, false, innerDer);
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

async function _generateTestChain(opts) {
  opts = opts || {};
  var sanDomain = opts.sanDomain || "example.com";
  var includeBimiEku = opts.includeBimiEku !== false;

  var caKeys = await _genKey();
  var leafKeys = await _genKey();

  var now = new Date();
  var notAfter = new Date(now.getTime() + YEAR_MS);
  var leafNotBefore = opts.leafNotBefore || now;
  var leafNotAfter = opts.leafNotAfter || notAfter;

  var ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=BIMI Test Root",
    notBefore: now,
    notAfter: notAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys: caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 1, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });

  var leafExts = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(
      x509.KeyUsageFlags.digitalSignature, true),
  ];
  if (!opts.noSan) {
    var sanEntries = opts.sanEntries || [{ type: "dns", value: sanDomain }];
    leafExts.push(new x509.SubjectAlternativeNameExtension(sanEntries));
  }
  if (includeBimiEku) {
    leafExts.push(new x509.ExtendedKeyUsageExtension([BIMI_EKU_OID], false));
  }
  if (opts.policyOid) {
    // Add a CertificatePolicies extension carrying the supplied OID so
    // VMC vs CMC can be distinguished. Compose the extension via the
    // pkijs/asn1 path the vendor bundle exposes.
    leafExts.push(new x509.CertificatePolicyExtension([opts.policyOid], false));
  }
  if (opts.logoSvg) {
    leafExts.push(_logotypeExtension(opts.logoSvg));
  }
  if (opts.logotypeExt) {
    leafExts.push(opts.logotypeExt);
  }

  var leaf = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    issuer: ca.subject,
    subject: "CN=" + sanDomain,
    notBefore: leafNotBefore,
    notAfter: leafNotAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    publicKey: leafKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: leafExts,
  });

  return {
    rootPem: ca.toString("pem"),
    leafPem: leaf.toString("pem"),
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
  var alg = { name: "ECDSA", hash: "SHA-256" };
  var caUsage = x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign;

  var root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01", name: "CN=BIMI Test Root", notBefore: now, notAfter: far,
    signingAlgorithm: alg, keys: rootKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 2, true),
      new x509.KeyUsagesExtension(caUsage, true),
    ],
  });
  var inter = await x509.X509CertificateGenerator.create({
    serialNumber: "02", issuer: root.subject, subject: "CN=BIMI Test Intermediate",
    notBefore: now, notAfter: far, signingAlgorithm: alg,
    publicKey: interKeys.publicKey, signingKey: rootKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(caUsage, true),
    ],
  });
  var leaf = await x509.X509CertificateGenerator.create({
    serialNumber: "03", issuer: inter.subject, subject: "CN=example.com",
    notBefore: now, notAfter: far, signingAlgorithm: alg,
    publicKey: leafKeys.publicKey, signingKey: interKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "example.com" }]),
      new x509.ExtendedKeyUsageExtension([BIMI_EKU_OID], false),
    ],
  });
  return {
    rootPem: root.toString("pem"),
    intermediatePem: inter.toString("pem"),
    leafPem: leaf.toString("pem"),
  };
}

// _generateSelfSignedScenario — a self-signed leaf (with SAN + BIMI EKU)
// paired with an unrelated root as the trust anchor. The verifier reaches
// the "self-signed root not in bundle" branch.
async function _generateSelfSignedScenario() {
  var leafKeys = await _genKey();
  var otherKeys = await _genKey();
  var now = new Date();
  var far = new Date(now.getTime() + 10 * YEAR_MS);
  var alg = { name: "ECDSA", hash: "SHA-256" };

  var leaf = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "05", name: "CN=example.com", notBefore: now, notAfter: far,
    signingAlgorithm: alg, keys: leafKeys,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "example.com" }]),
      new x509.ExtendedKeyUsageExtension([BIMI_EKU_OID], false),
    ],
  });
  var other = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "06", name: "CN=Unrelated Root", notBefore: now, notAfter: far,
    signingAlgorithm: alg, keys: otherKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 1, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return {
    leafPem: leaf.toString("pem"),
    otherRootPem: other.toString("pem"),
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

  // Suppress unused warning - reserved for future fixture-based negative tests.
  void nodeCrypto;
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
