"use strict";
/**
 * b.auth.fidoMds3 — x5c cert validity-window must fail closed when the
 * notBefore / notAfter dates are present but unparseable.
 *
 * _validateChain reads chain[v].validFrom / .validTo and feeds them to
 * Date.parse. A cert whose encoded validity dates parse to NaN (e.g. a
 * malformed / hand-forged DER) makes isFinite(notBefore) /
 * isFinite(notAfter) false, which — pre-fix — SKIPS both the
 * not-yet-valid and the expired checks, so the cert sails through the
 * validity window unchecked. The verifier must instead refuse with
 * fido-mds3/cert-bad-validity.
 *
 * The test drives the real fetch() consumer path with a mocked
 * httpClient serving a genuine RS256-signed BLOB whose self-signed leaf
 * is also the operator-supplied caCertificate, so absent the validity
 * bug the chain anchors and the JWS verifies — the validity-window
 * check is the only gate left. node:crypto's X509Certificate is
 * overridden so the parsed leaf reports an unparseable validFrom while
 * every other cert behaviour (verify / checkIssued / publicKey /
 * fingerprint256) stays real.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var check   = helpers.check;

// Mint an RSA self-signed cert + matching private-key PEM via the
// vendored pki bundle, mirroring the sibling fido-mds3 test fixture.
async function _makeSelfSignedRsaCert() {
  var pki  = require("../../lib/vendor/pki.cjs");
  var x509 = pki.x509;
  var keys = await nodeCrypto.webcrypto.subtle.generateKey(
    { name:           "RSASSA-PKCS1-v1_5",
      modulusLength:  2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash:           "SHA-256" },
    true, ["sign", "verify"]);
  var now      = new Date();
  var notAfter = new Date(now.getTime() + 7 * 86400000);
  var cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber:     "01",
    name:             "CN=blamejs-mds3-test-root",
    notBefore:        now,
    notAfter:         notAfter,
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    keys:             keys,
    extensions:       [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.digitalSignature,
        true),
    ],
  });
  var pkcs8  = await nodeCrypto.webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  var pkB64  = Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n");
  var keyPem = "-----BEGIN PRIVATE KEY-----\n" + pkB64 + "\n-----END PRIVATE KEY-----\n";
  return { keyPem: keyPem, certPem: cert.toString("pem") };
}

function _b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function _makeBlob(payload, keyPem, certPem) {
  var derB64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  var header     = { alg: "RS256", typ: "JWT", x5c: [derB64] };
  var headerB64  = _b64url(JSON.stringify(header));
  var payloadB64 = _b64url(JSON.stringify(payload));
  var signingInput = headerB64 + "." + payloadB64;
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"), {
    key:     keyPem,
    padding: nodeCrypto.constants.RSA_PKCS1_PADDING,
  });
  return signingInput + "." + _b64url(sig);
}

function _futureDateString(daysFromNow) {
  var d = new Date(Date.now() + daysFromNow * 86400000);
  return d.toISOString().slice(0, 10);
}

// Make every freshly-parsed X509Certificate report an unparseable
// validFrom (Date.parse -> NaN) while keeping all real cert behaviour.
async function _withUnparseableValidFrom(fn) {
  var realX509 = nodeCrypto.X509Certificate;
  function Wrapped(arg) {
    var c = new realX509(arg);
    Object.defineProperty(c, "validFrom", {
      configurable: true,
      get: function () { return "GARBAGE-NOT-A-DATE"; },
    });
    return c;
  }
  nodeCrypto.X509Certificate = Wrapped;
  try { return await fn(); }
  finally { nodeCrypto.X509Certificate = realX509; }
}

async function run() {
  var pair = await _makeSelfSignedRsaCert();
  var payload = {
    legalHeader: "Test BLOB",
    no: 1,
    nextUpdate: _futureDateString(7),
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      metadataStatement: { description: "Test entry" },
      statusReports: [{ status: "FIDO_CERTIFIED_L2" }],
    }],
  };
  var token = _makeBlob(payload, pair.keyPem, pair.certPem);

  // Mock httpClient.request via require-cache override (sibling pattern).
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () {
      return { statusCode: 200, headers: {}, body: Buffer.from(token, "ascii") };
    },
  });

  // Re-require the verifier so it captures both the mocked httpClient and
  // the wrapped X509Certificate through its module-level references.
  var fmPath = require.resolve("../../lib/auth/fido-mds3");
  delete require.cache[fmPath];
  var fm = require(fmPath);

  var threw = null;
  try {
    await _withUnparseableValidFrom(async function () {
      await fm.fetch({
        url:           "https://test.invalid/mds3",
        caCertificate: pair.certPem,
        force:         true,
      });
    });
  } catch (e) {
    threw = e;
  } finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[fmPath];
  }

  check("fetch rejects a cert with present-but-unparseable validity dates",
        threw !== null);
  check("rejection is fido-mds3/cert-bad-validity (fail closed, not silently accepted)",
        threw && /cert-bad-validity/.test(threw.code || ""));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
