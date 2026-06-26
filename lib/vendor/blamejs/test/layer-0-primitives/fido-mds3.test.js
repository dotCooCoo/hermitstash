"use strict";
/**
 * b.auth.fidoMds3 — FIDO MDS3 metadata BLOB verifier + AAGUID lookup.
 *
 * Covers:
 *   - lookupAaguid: dashed/undashed match, non-existent AAGUID, bad input.
 *   - verifyAuthenticator: clean accept, REVOKED refusal,
 *     USER_KEY_PHYSICAL_COMPROMISE refusal, certified-level surfacing,
 *     unknown AAGUID accept-with-statement-null path.
 *   - fetch: JWS round-trip with a synthetic BLOB (self-signed cert
 *     used as both leaf and trust root via the caCertificate override),
 *     httpClient mocked at the require-cache level.
 *   - Error class: FidoMds3Error reachable via framework-error.
 *
 * Standing up a real MDS3 BLOB is intractable for a primitive test
 * (~5 MB JSON, JWS-signed with a real CA chain). The synthetic BLOB
 * exercises the full verify path with a self-signed leaf; the
 * caCertificate override is the operator escape hatch the primitive
 * itself documents.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var fwkErr = require("../../lib/framework-error");

// Mint an RSA self-signed cert + matching private-key PEM via the
// vendored pki bundle. RS256 keeps the JWS verification path simple
// and matches the real FIDO Alliance BLOB shape. The same cert is
// used as both the JWS leaf (x5c[0]) and the trust root passed via
// caCertificate so the chain anchors against itself — this is the
// operator escape-hatch path the primitive itself documents.
async function _makeSelfSignedRsaCert() {
  var pki = require("../../lib/vendor/pki.cjs");
  var x509 = pki.x509;
  var keys = await nodeCrypto.webcrypto.subtle.generateKey(
    { name:           "RSASSA-PKCS1-v1_5",
      modulusLength:  2048,                                                        // allow:raw-byte-literal — RSA modulus bits
      publicExponent: new Uint8Array([1, 0, 1]),                                   // allow:raw-byte-literal — RSA F4 exponent
      hash:           "SHA-256" },
    true, ["sign", "verify"]);
  var now = new Date();
  var notAfter = new Date(now.getTime() + 7 * 86400000);                           // allow:raw-byte-literal — fixture validity ms
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
  var pkcs8 = await nodeCrypto.webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  var pkB64 = Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n");  // allow:raw-byte-literal — RFC 7468 line width
  var keyPem = "-----BEGIN PRIVATE KEY-----\n" + pkB64 + "\n-----END PRIVATE KEY-----\n";
  return { keyPem: keyPem, certPem: cert.toString("pem") };
}

function _b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

// Build a synthetic JWS-signed MDS3 BLOB. payload is the inner JSON;
// keyPem signs it with RS256; certPem is the leaf x5c entry.
function _makeBlob(payload, keyPem, certPem) {
  // Strip PEM markers + whitespace from cert to get DER-base64.
  var derB64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  var header = { alg: "RS256", typ: "JWT", x5c: [derB64] };
  var headerB64  = _b64url(JSON.stringify(header));
  var payloadB64 = _b64url(JSON.stringify(payload));
  var signingInput = headerB64 + "." + payloadB64;
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"), {
    key:     keyPem,
    padding: nodeCrypto.constants.RSA_PKCS1_PADDING,
  });
  return signingInput + "." + _b64url(sig);
}

// In-future date (YYYY-MM-DD) so nextUpdate parsing succeeds.
function _futureDateString(daysFromNow) {
  var d = new Date(Date.now() + daysFromNow * 86400000);                           // allow:raw-byte-literal — ms-per-day
  return d.toISOString().slice(0, 10);                                             // allow:raw-byte-literal — ISO date prefix length
}

// ---- surface ----

function testSurface() {
  check("auth.fidoMds3 namespace present", typeof b.auth.fidoMds3 === "object");
  check("fidoMds3.fetch is a function",               typeof b.auth.fidoMds3.fetch === "function");
  check("fidoMds3.lookupAaguid is a function",        typeof b.auth.fidoMds3.lookupAaguid === "function");
  check("fidoMds3.verifyAuthenticator is a function", typeof b.auth.fidoMds3.verifyAuthenticator === "function");
  check("FidoMds3Error registered in framework-error",
        typeof fwkErr.FidoMds3Error === "function");
  // Smoke: error carries the standard isXxxError flag + code/message.
  var e = new fwkErr.FidoMds3Error("fido-mds3/test", "test message");
  check("FidoMds3Error carries isFidoMds3Error",      e.isFidoMds3Error === true);
  check("FidoMds3Error carries code",                 e.code === "fido-mds3/test");
  check("FidoMds3Error always permanent",             e.permanent === true);
}

// ---- lookupAaguid ----

function testLookupAaguid() {
  var blob = {
    entries: [
      {
        aaguid: "01234567-89ab-cdef-0123-456789abcdef",
        metadataStatement: { description: "Test A" },
        statusReports: [],
      },
      {
        // Undashed AAGUID — some BLOBs ship in this form for status
        // reports. lookupAaguid normalizes both sides.
        aaguid: "fedcba9876543210fedcba9876543210",
        metadataStatement: { description: "Test B" },
        statusReports: [],
      },
    ],
  };
  var a = b.auth.fidoMds3.lookupAaguid(blob, "01234567-89ab-cdef-0123-456789abcdef");
  check("lookupAaguid finds dashed entry",
        a && a.metadataStatement.description === "Test A");

  // Same AAGUID without dashes resolves the same entry.
  var aUndashed = b.auth.fidoMds3.lookupAaguid(blob, "0123456789abcdef0123456789abcdef");
  check("lookupAaguid normalizes dashes on input",
        aUndashed && aUndashed.metadataStatement.description === "Test A");

  // Reverse: dashed input against undashed entry.
  var bm = b.auth.fidoMds3.lookupAaguid(blob, "fedcba98-7654-3210-fedc-ba9876543210");
  check("lookupAaguid normalizes dashes on stored entries",
        bm && bm.metadataStatement.description === "Test B");

  // Not present.
  var miss = b.auth.fidoMds3.lookupAaguid(blob, "00000000-0000-0000-0000-000000000000");
  check("lookupAaguid returns null on miss", miss === null);

  // Bad inputs.
  var threw = null;
  try { b.auth.fidoMds3.lookupAaguid(null, "00000000-0000-0000-0000-000000000000"); }
  catch (e) { threw = e; }
  check("lookupAaguid throws on null blob",
        threw && /bad-blob/.test(threw.code || ""));

  threw = null;
  try { b.auth.fidoMds3.lookupAaguid(blob, ""); } catch (e) { threw = e; }
  check("lookupAaguid throws on empty aaguid",
        threw && /bad-aaguid/.test(threw.code || ""));

  threw = null;
  try { b.auth.fidoMds3.lookupAaguid(blob, "not-a-uuid"); } catch (e) { threw = e; }
  check("lookupAaguid throws on non-UUID input",
        threw && /bad-aaguid/.test(threw.code || ""));
}

// ---- verifyAuthenticator ----

function testVerifyAuthenticatorClean() {
  var blob = {
    entries: [
      {
        aaguid: "01234567-89ab-cdef-0123-456789abcdef",
        metadataStatement: { description: "Test A" },
        statusReports: [
          { status: "FIDO_CERTIFIED_L1" },
          { status: "FIDO_CERTIFIED_L2" },
        ],
      },
    ],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("verifyAuthenticator ok=true on clean entry", rv.ok === true);
  check("verifyAuthenticator surfaces statement",
        rv.statement && rv.statement.description === "Test A");
  check("verifyAuthenticator certifiedLevel reflects the latest report",
        rv.certifiedLevel.level === 2 && rv.certifiedLevel.plus === false);
}

function testVerifyAuthenticatorDecertified() {
  // A later NOT_FIDO_CERTIFIED decertifies the authenticator: certifiedLevel
  // must reset to 0, not report the historical max — otherwise a step-up / risk
  // policy that requires L2 accepts a now-uncertified authenticator.
  var blob = {
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      metadataStatement: { description: "Test A" },
      statusReports: [
        { status: "FIDO_CERTIFIED_L2",  effectiveDate: "2020-01-01" },
        { status: "NOT_FIDO_CERTIFIED", effectiveDate: "2023-01-01" },
      ],
    }],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("verifyAuthenticator: later NOT_FIDO_CERTIFIED resets certifiedLevel to 0",
        rv.certifiedLevel.level === 0 && rv.certifiedLevel.plus === false);

  // A downgrade (L3 then L1) reports the CURRENT L1, not the historical L3.
  var blob2 = {
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      metadataStatement: { description: "Test B" },
      statusReports: [
        { status: "FIDO_CERTIFIED_L3", effectiveDate: "2019-01-01" },
        { status: "FIDO_CERTIFIED_L1", effectiveDate: "2024-01-01" },
      ],
    }],
  };
  var rv2 = b.auth.fidoMds3.verifyAuthenticator(blob2, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("verifyAuthenticator: certifiedLevel is the latest report, not the historical max",
        rv2.certifiedLevel.level === 1);
}

function testVerifyAuthenticatorRevoked() {
  var blob = {
    entries: [
      {
        aaguid: "01234567-89ab-cdef-0123-456789abcdef",
        metadataStatement: { description: "Test A" },
        statusReports: [
          { status: "FIDO_CERTIFIED_L1" },
          { status: "REVOKED", effectiveDate: "2023-01-01" },
        ],
      },
    ],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("verifyAuthenticator ok=false on REVOKED status",
        rv.ok === false);
  check("verifyAuthenticator reason mentions REVOKED",
        rv.reason && /REVOKED/.test(rv.reason));
}

function testVerifyAuthenticatorPhysicalCompromise() {
  var blob = {
    entries: [
      {
        aaguid: "01234567-89ab-cdef-0123-456789abcdef",
        statusReports: [{ status: "USER_KEY_PHYSICAL_COMPROMISE" }],
      },
    ],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("verifyAuthenticator ok=false on USER_KEY_PHYSICAL_COMPROMISE",
        rv.ok === false);
}

function testVerifyAuthenticatorRemoteCompromise() {
  var blob = {
    entries: [
      {
        aaguid: "01234567-89ab-cdef-0123-456789abcdef",
        statusReports: [{ status: "USER_KEY_REMOTE_COMPROMISE" }],
      },
    ],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("verifyAuthenticator ok=false on USER_KEY_REMOTE_COMPROMISE",
        rv.ok === false);
}

function testVerifyAuthenticatorUnknownAaguid() {
  var blob = { entries: [] };
  // v0.9.2 fail-closed default: an AAGUID not in the BLOB now
  // refuses by default. Operators who genuinely accept unknown
  // authenticators (test fixtures, pre-certification pilots) opt
  // in via allowUnknownAaguid: true.
  var rvDefault = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("verifyAuthenticator ok=false on unknown AAGUID (fail-closed default)",
        rvDefault.ok === false);
  check("verifyAuthenticator reason='aaguid-not-in-blob' on unknown",
        rvDefault.reason === "aaguid-not-in-blob");
  // Opt-in fail-open for unknown AAGUIDs.
  var rvOptIn = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  }, { allowUnknownAaguid: true });
  check("verifyAuthenticator ok=true with allowUnknownAaguid",
        rvOptIn.ok === true);
  check("verifyAuthenticator statement=null on unknown AAGUID",
        rvOptIn.statement === null);
  check("verifyAuthenticator reason notes operator opt-in",
        /allowUnknownAaguid/.test(rvOptIn.reason));
}

function testVerifyAuthenticatorBadInputs() {
  var threw = null;
  try { b.auth.fidoMds3.verifyAuthenticator(null, { aaguid: "x" }); }
  catch (e) { threw = e; }
  check("verifyAuthenticator throws on null blob",
        threw && /bad-blob/.test(threw.code || ""));

  threw = null;
  try { b.auth.fidoMds3.verifyAuthenticator({ entries: [] }, null); }
  catch (e) { threw = e; }
  check("verifyAuthenticator throws on null registrationInfo",
        threw && /bad-registrationinfo/.test(threw.code || ""));

  threw = null;
  try { b.auth.fidoMds3.verifyAuthenticator({ entries: [] }, {}); }
  catch (e) { threw = e; }
  check("verifyAuthenticator throws on missing aaguid",
        threw && /bad-registrationinfo/.test(threw.code || ""));
}

function testCertifiedLevelPlus() {
  var blob = {
    entries: [
      {
        aaguid: "01234567-89ab-cdef-0123-456789abcdef",
        statusReports: [
          { status: "FIDO_CERTIFIED_L3" },
          { status: "FIDO_CERTIFIED_L3_PLUS" },
        ],
      },
    ],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("certifiedLevel L3 plus surfaced",
        rv.certifiedLevel.level === 3 && rv.certifiedLevel.plus === true);
}

// ---- fetch (synthetic BLOB) ----

async function testFetchRoundTrip() {
  var pair = await _makeSelfSignedRsaCert();
  var payload = {
    legalHeader: "Test BLOB",
    no: 42,
    nextUpdate: _futureDateString(7),                                              // allow:raw-byte-literal — fixture days-out
    entries: [
      {
        aaguid: "01234567-89ab-cdef-0123-456789abcdef",
        metadataStatement: { description: "Test entry" },
        statusReports: [{ status: "FIDO_CERTIFIED_L2" }],
      },
    ],
  };
  var token = _makeBlob(payload, pair.keyPem, pair.certPem);

  // Mock httpClient.request via require-cache override.
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () {
      return { statusCode: 200, headers: {}, body: Buffer.from(token, "ascii") }; // allow:raw-byte-literal — HTTP success
    },
  });

  // Force fido-mds3 to re-resolve httpClient.
  var fmPath = require.resolve("../../lib/auth/fido-mds3");
  delete require.cache[fmPath];
  var fm = require(fmPath);

  try {
    var blob = await fm.fetch({
      url:           "https://test.invalid/mds3",
      caCertificate: pair.certPem,
      force:         true,
    });
    check("fetch returns parsed BLOB with entries", Array.isArray(blob.entries) && blob.entries.length === 1);
    check("fetch returns no=42",                    blob.no === 42);                // allow:raw-byte-literal — fixture identifier
    check("fetch parses nextUpdate to Date",        blob.nextUpdate instanceof Date);

    // Compose with verifyAuthenticator using the synthetic blob.
    var rv = fm.verifyAuthenticator(blob, {
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
    });
    check("verifyAuthenticator over fetched blob ok=true", rv.ok === true);
    check("verifyAuthenticator over fetched blob L2",
          rv.certifiedLevel.level === 2);
  } finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[fmPath];
  }
}

async function testFetchRejectsNonHttps() {
  var threw = null;
  try { await b.auth.fidoMds3.fetch({ url: "http://insecure.example/mds3" }); }
  catch (e) { threw = e; }
  check("fetch rejects non-HTTPS url",
        threw && /bad-url/.test(threw.code || ""));
}

async function testFetchRejectsEmptyUrl() {
  var threw = null;
  try { await b.auth.fidoMds3.fetch({ url: "" }); } catch (e) { threw = e; }
  // Empty url falls back to default (https), so this should NOT throw on bad-url
  // Actually url is "" (falsy) -> default URL (https) -> won't reach bad-url.
  // Validate by passing a bad url with a non-string instead.
  threw = null;
  try { await b.auth.fidoMds3.fetch({ url: 5 }); } catch (e) { threw = e; }
  check("fetch rejects non-string url",
        threw && /bad-url/.test(threw.code || ""));
}

async function testFetchRejectsBadTimeout() {
  var threw = null;
  try { await b.auth.fidoMds3.fetch({ timeoutMs: -1 }); }                          // allow:raw-byte-literal — invalid timeout
  catch (e) { threw = e; }
  check("fetch rejects negative timeoutMs",
        threw && /bad-timeout/.test(threw.code || ""));
}

async function testInternalVerifyRejectsBadJws() {
  // Smoke the inner verifier with garbage input — the public surface
  // hits this path through fetch but the inner is exercised in tests
  // for shape coverage.
  var fm = require("../../lib/auth/fido-mds3");
  var threw = null;
  try { fm._verifyAndParseBlob(""); } catch (e) { threw = e; }
  check("_verifyAndParseBlob rejects empty string",
        threw && /bad-jws/.test(threw.code || ""));

  threw = null;
  try { fm._verifyAndParseBlob("a.b"); } catch (e) { threw = e; }
  check("_verifyAndParseBlob rejects 2-part JWS",
        threw && /bad-jws/.test(threw.code || ""));
}

// ---- run ----

// fido-mds3.fetch dials the MDS3 endpoint through the shared httpClient
// keep-alive transport pool; a cached client socket finalizes its destroy on a
// later event-loop turn, past the forked worker's grace window. Reset the pool,
// then poll until every TCP handle has actually drained so it doesn't outlive
// run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "fido-mds3: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    testSurface();
    testLookupAaguid();
    testVerifyAuthenticatorClean();
    testVerifyAuthenticatorRevoked();
    testVerifyAuthenticatorDecertified();
    testVerifyAuthenticatorPhysicalCompromise();
    testVerifyAuthenticatorRemoteCompromise();
    testVerifyAuthenticatorUnknownAaguid();
    testVerifyAuthenticatorBadInputs();
    testCertifiedLevelPlus();
    await testFetchRoundTrip();
    await testFetchRejectsNonHttps();
    await testFetchRejectsEmptyUrl();
    await testFetchRejectsBadTimeout();
    await testInternalVerifyRejectsBadJws();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
