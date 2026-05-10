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

async function _generateTestChain(opts) {
  opts = opts || {};
  var sanDomain = opts.sanDomain || "example.com";
  var includeBimiEku = opts.includeBimiEku !== false;
  var bimiEkuOid = "1.3.6.1.5.5.7.3.31";

  var caKeys = await pki.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var leafKeys = await pki.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

  var now = new Date();
  var notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

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
    new x509.SubjectAlternativeNameExtension([
      { type: "dns", value: sanDomain },
    ]),
  ];
  if (includeBimiEku) {
    leafExts.push(new x509.ExtendedKeyUsageExtension([bimiEkuOid], false));
  }
  if (opts.policyOid) {
    // Add a CertificatePolicies extension carrying the supplied OID so
    // VMC vs CMC can be distinguished. Compose the extension via the
    // pkijs/asn1 path the vendor bundle exposes.
    leafExts.push(new x509.CertificatePolicyExtension([opts.policyOid], false));
  }

  var leaf = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    issuer: ca.subject,
    subject: "CN=" + sanDomain,
    notBefore: now,
    notAfter: notAfter,
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

  await testFetchAndVerifyMarkSuccess();
  await testFetchAndVerifyMarkCmc();
  await testFetchAndVerifyMarkChainInvalid();
  await testFetchAndVerifyMarkDomainMismatch();
  await testFetchAndVerifyMarkMissingEku();
  await testFetchAndVerifyMarkNoTrustAnchors();
  await testFetchAndVerifyMarkBadPemBody();
  await testFetchAndVerifyMarkHttpStatusFailure();
  await testFetchAndVerifyMarkBadOpts();

  // Suppress unused warning - reserved for future fixture-based negative tests.
  void nodeCrypto;
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
