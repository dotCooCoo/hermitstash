// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

// Mint a self-signed cert + matching private-key PEM via the vendored pki
// bundle. `opts.algo` selects the key type ("RSA" default / "EC" P-256 /
// "Ed25519") so a single builder drives the RS256 / ES256 / alg-mismatch JWS
// verify branches; `opts.ca` toggles basicConstraints cA (false exercises the
// fingerprint-anchor fallback, which accepts a pinned non-CA leaf only on an
// exact fingerprint match); `opts.notBefore` / `opts.notAfter` drive the
// not-yet-valid / expired validity-window refusals. The cert is used as both
// the JWS leaf (x5c[0]) and the trust root passed via caCertificate so the
// chain anchors against itself — the operator escape-hatch the primitive docs.
async function _makeCert(opts) {
  opts = opts || {};
  var pki = require("../../lib/vendor/pki.cjs");
  var x509 = pki.x509;
  var algo = opts.algo || "RSA";
  var isCa = opts.ca === undefined ? true : opts.ca;
  var now = new Date();
  var notBefore = opts.notBefore || now;
  var notAfter  = opts.notAfter  || new Date(now.getTime() + 7 * 86400000);        // allow:raw-byte-literal — fixture validity ms
  var genAlg, signAlg;
  if (algo === "EC") {
    genAlg  = { name: "ECDSA", namedCurve: "P-256" };
    signAlg = { name: "ECDSA", hash: "SHA-256" };
  } else if (algo === "Ed25519") {
    genAlg  = { name: "Ed25519" };
    signAlg = { name: "Ed25519" };
  } else {
    genAlg  = { name:           "RSASSA-PKCS1-v1_5",
                modulusLength:  2048,                                              // allow:raw-byte-literal — RSA modulus bits
                publicExponent: new Uint8Array([1, 0, 1]),                         // allow:raw-byte-literal — RSA F4 exponent
                hash:           "SHA-256" };
    signAlg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  }
  var keys = await nodeCrypto.webcrypto.subtle.generateKey(genAlg, true, ["sign", "verify"]);
  var exts = [ new x509.BasicConstraintsExtension(isCa, 0, true) ];
  if (isCa) exts.push(new x509.KeyUsagesExtension(
    x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.digitalSignature, true));
  var cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber:     opts.serial || "01",
    name:             "CN=" + (opts.cn || "blamejs-mds3-test-root"),
    notBefore:        notBefore,
    notAfter:         notAfter,
    signingAlgorithm: signAlg,
    keys:             keys,
    extensions:       exts,
  });
  var pkcs8 = await nodeCrypto.webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  var pkB64 = Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n");  // allow:raw-byte-literal — RFC 7468 line width
  var keyPem = "-----BEGIN PRIVATE KEY-----\n" + pkB64 + "\n-----END PRIVATE KEY-----\n";
  return { keyPem: keyPem, certPem: cert.toString("pem") };
}

// RS256 self-signed cert — the common case, matching the real FIDO Alliance
// BLOB shape. Thin wrapper over the general builder.
async function _makeSelfSignedRsaCert() {
  return _makeCert({});
}

function _b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

// Assemble the compact JWS from a caller-supplied header + payload, signing the
// signing-input with `hashAlgo` + `signOpts` (node:crypto.sign options). One
// core so the RS256 / ES256 / PS256 / Ed25519 fixture builders don't each
// re-roll the base64url-segment-then-sign body.
function _makeBlobSig(header, payload, keyPem, hashAlgo, signOpts) {
  var headerB64  = _b64url(JSON.stringify(header));
  var payloadB64 = _b64url(JSON.stringify(payload));
  var signingInput = headerB64 + "." + payloadB64;
  var sig = nodeCrypto.sign(hashAlgo, Buffer.from(signingInput, "ascii"),
                            Object.assign({ key: keyPem }, signOpts || {}));
  return signingInput + "." + _b64url(sig);
}

// Build a synthetic JWS-signed MDS3 BLOB. payload is the inner JSON;
// keyPem signs it with RS256; certPem is the leaf x5c entry.
function _makeBlob(payload, keyPem, certPem) {
  var header = { alg: "RS256", typ: "JWT", x5c: [_certDerB64(certPem)] };
  return _makeBlobSig(header, payload, keyPem, "sha256",
                      { padding: nodeCrypto.constants.RSA_PKCS1_PADDING });
}

// In-future date (YYYY-MM-DD) so nextUpdate parsing succeeds. A negative
// argument produces a PAST date (used to drive the stale-BLOB refusal).
function _futureDateString(daysFromNow) {
  var d = new Date(Date.now() + daysFromNow * 86400000);                           // allow:raw-byte-literal — ms-per-day
  return d.toISOString().slice(0, 10);                                             // allow:raw-byte-literal — ISO date prefix length
}

// Strip PEM markers + whitespace from a cert to get its DER-base64 (x5c form).
function _certDerB64(certPem) {
  return certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
}

// Like _makeBlob but the caller supplies the full JWS header (so a test can
// override alg / x5c to exercise the header-adversarial branches). The payload
// is still RS256-signed with keyPem, so the signature segment is valid,
// non-empty base64url even when the header advertises a different alg — the
// verifier reaches its alg check before the signature check.
function _makeBlobRaw(header, payload, keyPem) {
  return _makeBlobSig(header, payload, keyPem, "sha256",
                      { padding: nodeCrypto.constants.RSA_PKCS1_PADDING });
}

// Mock httpClient.request with `handler`, reload fido-mds3 so it re-resolves
// the lazyRequire'd httpClient against the mock, run fn(fm), then restore the
// require cache. Mirrors testFetchRoundTrip's require-cache override so no real
// network handle is ever opened.
async function _withMockedHttp(handler, fn) {
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, { request: handler });
  var fmPath = require.resolve("../../lib/auth/fido-mds3");
  delete require.cache[fmPath];
  var fm = require(fmPath);
  try {
    return await fn(fm);
  } finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[fmPath];
  }
}

// A request handler returning a 200 with `token` as the body.
function _respondWith(token) {
  return async function () {
    return { statusCode: 200, headers: {}, body: Buffer.from(token, "ascii") };    // allow:raw-byte-literal — HTTP success
  };
}

// Patch the vendored SettingsService.getRootCertificates (the DEFAULT-trust-root
// resolver used when no caCertificate override is supplied), run fn, restore.
// `fakeGetter` receives the { identifier } arg fido-mds3 passes and returns the
// PEM array (or throws) so the no-trust-root fail-closed branch and the
// default-roots stale refusal can be driven without a live vendored bundle
// edit. fido-mds3 reads _wa.SettingsService.getRootCertificates dynamically at
// resolve time, so no module reload is needed — the same cached vendor object
// backs both this test and the primitive.
async function _withMockedRoots(fakeGetter, fn) {
  var wa = require("../../lib/vendor/simplewebauthn-server.cjs");
  var svc = wa.SettingsService;
  var orig = svc.getRootCertificates;
  svc.getRootCertificates = fakeGetter;
  try {
    return await fn();
  } finally {
    svc.getRootCertificates = orig;
  }
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

function testVerifyAuthenticatorAttestationKeyCompromise() {
  // ATTESTATION_KEY_COMPROMISE is in the FIDO MDS3 3.1.4 compromise bucket: the
  // manufacturer's batch-signing key is suspect, so every credential attested
  // under it MUST be refused. Sibling of the REVOKED / USER_KEY_* refusals but
  // previously untested.
  var blob = {
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      metadataStatement: { description: "Compromised batch key" },
      statusReports: [{ status: "ATTESTATION_KEY_COMPROMISE" }],
    }],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("verifyAuthenticator ok=false on ATTESTATION_KEY_COMPROMISE", rv.ok === false);
  check("verifyAuthenticator reason cites ATTESTATION_KEY_COMPROMISE",
        rv.reason && /ATTESTATION_KEY_COMPROMISE/.test(rv.reason));
}

function testCertifiedLevelMissingDateOrdering() {
  // A decertification (NOT_FIDO_CERTIFIED) appended AFTER a dated grant but
  // WITHOUT its own effectiveDate must still win by array order (append order
  // == chronological per spec). If the undated report is coerced to "" and run
  // through a lexical compare it loses to every earlier DATED report, so
  // certifiedLevel freezes at the stale L2 and a step-up policy requiring L2
  // would accept a now-decertified authenticator (authenticator-assurance
  // bypass).
  var decertBlob = {
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      statusReports: [
        { status: "FIDO_CERTIFIED_L2", effectiveDate: "2020-01-01" },
        { status: "NOT_FIDO_CERTIFIED" },   // later in array, no effectiveDate
      ],
    }],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(decertBlob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("certifiedLevel: undated later NOT_FIDO_CERTIFIED decertifies to level 0",
        rv.certifiedLevel.level === 0 && rv.certifiedLevel.plus === false);

  // A downgrade whose newer level report has no effectiveDate must report the
  // CURRENT (later) L1, not the historical dated L3.
  var downgradeBlob = {
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      statusReports: [
        { status: "FIDO_CERTIFIED_L3", effectiveDate: "2019-01-01" },
        { status: "FIDO_CERTIFIED_L1" },   // later in array, no effectiveDate
      ],
    }],
  };
  var rv2 = b.auth.fidoMds3.verifyAuthenticator(downgradeBlob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("certifiedLevel: undated later downgrade reports current L1, not historical L3",
        rv2.certifiedLevel.level === 1);

  // Symmetric case: an UPGRADE (later, higher level) whose effectiveDate is
  // absent must also win by array order and report the current L3 — not be
  // suppressed because its coerced "" loses the lexical compare against the
  // earlier dated L1.
  var upgradeBlob = {
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      statusReports: [
        { status: "FIDO_CERTIFIED_L1", effectiveDate: "2024-01-01" },
        { status: "FIDO_CERTIFIED_L3" },   // later in array, no effectiveDate
      ],
    }],
  };
  var rv3 = b.auth.fidoMds3.verifyAuthenticator(upgradeBlob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("certifiedLevel: undated later upgrade reports current L3, not earlier L1",
        rv3.certifiedLevel.level === 3);
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

async function testFetchRejectsStaleBlob() {
  // A signed-but-expired BLOB (nextUpdate in the past) must be refused by the
  // operator-facing fetch path, not accepted and cached. The internal
  // _verifyAndParseBlob refuses stale BLOBs; fetch is the path operators
  // actually drive, and it must enforce the same refusal (otherwise an attacker
  // serving an ancient BLOB freezes the revoked-authenticator list at a chosen
  // time).
  var pair = await _makeSelfSignedRsaCert();
  var payload = {
    legalHeader: "Stale BLOB",
    no: 7,
    nextUpdate: _futureDateString(-7),   // 7 days in the PAST — stale
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      metadataStatement: { description: "Stale entry" },
      statusReports: [{ status: "REVOKED", effectiveDate: "2020-01-01" }],
    }],
  };
  var token = _makeBlob(payload, pair.keyPem, pair.certPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://stale.invalid/mds3", caCertificate: pair.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a stale BLOB (nextUpdate in the past)",
        threw && /blob-stale/.test(threw.code || ""));
}

async function testFetchTamperedSignature() {
  // Swap the payload segment after signing, keep the original header + sig: the
  // signature no longer covers the payload, so the verify seam must refuse.
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 1, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, pair.keyPem, pair.certPem);
  var parts = token.split(".");
  var forgedPayload = _b64url(JSON.stringify({
    no: 999, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "ffffffff-ffff-ffff-ffff-ffffffffffff", statusReports: [] }],
  }));
  var forged = parts[0] + "." + forgedPayload + "." + parts[2];
  var threw = null;
  await _withMockedHttp(_respondWith(forged), async function (fm) {
    try {
      await fm.fetch({ url: "https://tamper.invalid/mds3", caCertificate: pair.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a BLOB whose signature does not cover the payload",
        threw && /bad-signature/.test(threw.code || ""));
}

async function testFetchWrongTrustRoot() {
  // The BLOB is signed by `signer`; the operator pins a DIFFERENT root
  // (`stranger`). The x5c tail cannot anchor to it -> chain-not-anchored.
  var signer   = await _makeSelfSignedRsaCert();
  var stranger = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 2, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, signer.keyPem, signer.certPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://wrongroot.invalid/mds3", caCertificate: stranger.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a BLOB that does not anchor to the pinned trust root",
        threw && /chain-not-anchored/.test(threw.code || ""));
}

async function testFetchUnsupportedAlg() {
  // HS256 (HMAC) is the canonical alg-confusion vector; the MDS3 verifier's alg
  // table has no HMAC/none entry, so it must refuse rather than treat the leaf
  // cert's public key as an HMAC secret. The chain still anchors (self-signed
  // via caCertificate), so the refusal proves the alg gate, not chain failure.
  var pair = await _makeSelfSignedRsaCert();
  var header = { alg: "HS256", typ: "JWT", x5c: [_certDerB64(pair.certPem)] };
  var token = _makeBlobRaw(header, {
    no: 3, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, pair.keyPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://badalg.invalid/mds3", caCertificate: pair.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses an HMAC alg (no alg-confusion path)",
        threw && /unsupported-alg/.test(threw.code || ""));
}

async function testFetchRejectsImpossibleNextUpdate() {
  // 2026-02-31 is not a real calendar date; _parseNextUpdate must reject it
  // (Date.UTC would silently normalise it to 2026-03-03 and let a malformed
  // nextUpdate masquerade as a valid future timestamp). Driven through fetch.
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 1, nextUpdate: "2026-02-31",
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, pair.keyPem, pair.certPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://baddate.invalid/mds3", caCertificate: pair.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch rejects an impossible calendar nextUpdate (2026-02-31)",
        threw && /bad-payload/.test(threw.code || ""));
}

async function testFetchMalformedBlobHeaders() {
  var pair = await _makeSelfSignedRsaCert();
  var goodPayload = {
    no: 1, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  };
  var noAlg  = _makeBlobRaw({ typ: "JWT", x5c: [_certDerB64(pair.certPem)] }, goodPayload, pair.keyPem);
  var noX5c  = _makeBlobRaw({ alg: "RS256", typ: "JWT" }, goodPayload, pair.keyPem);
  var badX5c = _makeBlobRaw({ alg: "RS256", typ: "JWT", x5c: ["!!!not-a-cert!!!"] }, goodPayload, pair.keyPem);

  async function fetchExpect(token, codeRe, label) {
    var threw = null;
    await _withMockedHttp(_respondWith(token), async function (fm) {
      try {
        await fm.fetch({ url: "https://malformed.invalid/mds3", caCertificate: pair.certPem, force: true });
      } catch (e) { threw = e; }
    });
    check(label, threw && codeRe.test(threw.code || ""));
  }
  await fetchExpect(noAlg,  /bad-jws-header/, "fetch rejects a header missing alg");
  await fetchExpect(noX5c,  /bad-jws-header/, "fetch rejects a header missing x5c");
  await fetchExpect(badX5c, /bad-x5c/,        "fetch rejects an unparseable x5c cert");
}

async function testFetchRejectsBadStatus() {
  // Root resolution (a plain string caCertificate) succeeds before the request;
  // the non-2xx status is refused inside the loader.
  var threw = null;
  await _withMockedHttp(async function () {
    return { statusCode: 404, headers: {}, body: Buffer.from("not found", "ascii") };  // allow:raw-byte-literal — HTTP error
  }, async function (fm) {
    try {
      await fm.fetch({ url: "https://notfound.invalid/mds3", caCertificate: "ca-not-reached", force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a non-2xx HTTP status",
        threw && /bad-status/.test(threw.code || ""));
}

async function testFetchNetworkFailure() {
  var threw = null;
  await _withMockedHttp(async function () {
    throw new Error("ECONNREFUSED synthetic");
  }, async function (fm) {
    try {
      await fm.fetch({ url: "https://down.invalid/mds3", caCertificate: "ca-not-reached", force: true });
    } catch (e) { threw = e; }
  });
  check("fetch wraps a transport failure as fido-mds3/network",
        threw && /fido-mds3\/network/.test(threw.code || ""));
}

async function testFetchBadCaCertificate() {
  // _resolveRoots runs before any HTTP; each bad shape fails closed with
  // bad-ca. No mock needed — the throw precedes the request.
  async function expectBadCa(ca, label) {
    var threw = null;
    try { await b.auth.fidoMds3.fetch({ url: "https://x.invalid/mds3", caCertificate: ca }); }
    catch (e) { threw = e; }
    check(label, threw && /bad-ca/.test(threw.code || ""));
  }
  await expectBadCa([], "fetch rejects an empty caCertificate array");
  await expectBadCa([123], "fetch rejects a non-string caCertificate array element");  // allow:raw-byte-literal — bad type sample
  await expectBadCa(5, "fetch rejects a non-string/non-array caCertificate");          // allow:raw-byte-literal — bad type sample
}

async function testFetchCacheHitAndForceBypass() {
  // The cache path: a non-force second call is served from cache (no new HTTP);
  // force:true bypasses the cache and refetches.
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 100, nextUpdate: _futureDateString(7),                                      // allow:raw-byte-literal — fixture identifier
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, pair.keyPem, pair.certPem);
  var calls = 0;
  await _withMockedHttp(async function () {
    calls += 1;
    return { statusCode: 200, headers: {}, body: Buffer.from(token, "ascii") };     // allow:raw-byte-literal — HTTP success
  }, async function (fm) {
    var url = "https://cache.invalid/mds3";
    var a = await fm.fetch({ url: url, caCertificate: pair.certPem, force: true });
    check("fetch (force) performs one HTTP call", calls === 1 && a.no === 100);      // allow:raw-byte-literal — fixture identifier
    var hit = await fm.fetch({ url: url, caCertificate: pair.certPem });
    check("fetch serves the second (non-force) call from cache", calls === 1 && hit.no === 100);  // allow:raw-byte-literal — fixture identifier
    var refetched = await fm.fetch({ url: url, caCertificate: pair.certPem, force: true });
    check("fetch force:true bypasses the cache and refetches", calls === 2 && refetched.no === 100);  // allow:raw-byte-literal — fixture identifier
  });
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

// ---- fetch: x5c chain validity + anchoring adversarial branches ----

async function testFetchExpiredSigningCert() {
  // A signed BLOB whose leaf certificate has already expired must be refused,
  // even though the JWS signature itself would verify. An attacker replaying an
  // ancient BLOB signed under a now-expired cert must not slip past the validity
  // window (fail-open would pin operators to a frozen, possibly-revoked list).
  var expired = await _makeCert({
    notBefore: new Date(Date.now() - 30 * 86400000),                               // allow:raw-byte-literal — fixture days
    notAfter:  new Date(Date.now() - 10 * 86400000),                               // allow:raw-byte-literal — fixture days
  });
  var token = _makeBlob({
    no: 1, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, expired.keyPem, expired.certPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://expired.invalid/mds3", caCertificate: expired.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a BLOB whose leaf signing cert has expired",
        threw && /cert-expired/.test(threw.code || ""));
}

async function testFetchNotYetValidCert() {
  // A leaf certificate whose notBefore is in the future is not yet valid and
  // must be refused — a pre-dated / clock-skew forgery must not validate.
  var future = await _makeCert({
    notBefore: new Date(Date.now() + 20 * 86400000),                               // allow:raw-byte-literal — fixture days
    notAfter:  new Date(Date.now() + 40 * 86400000),                               // allow:raw-byte-literal — fixture days
  });
  var token = _makeBlob({
    no: 1, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, future.keyPem, future.certPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://notyet.invalid/mds3", caCertificate: future.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a BLOB whose leaf signing cert is not yet valid",
        threw && /cert-not-yet-valid/.test(threw.code || ""));
}

async function testFetchBrokenChain() {
  // A two-cert x5c where the leaf is NOT validly issued by the second link must
  // be refused with chain-broken — a cert spliced into the chain that did not
  // sign the leaf cannot bridge it to the root, even when that second cert is
  // itself the pinned trust anchor.
  var leaf  = await _makeCert({ cn: "blamejs-leaf" });
  var other = await _makeCert({ cn: "blamejs-other-ca" });
  var header = { alg: "RS256", typ: "JWT",
                 x5c: [_certDerB64(leaf.certPem), _certDerB64(other.certPem)] };
  var token = _makeBlobRaw(header, {
    no: 1, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, leaf.keyPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://broken.invalid/mds3", caCertificate: other.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a two-cert chain whose leaf is not issued by the next link",
        threw && /chain-broken/.test(threw.code || ""));
}

async function testFetchGarbageRootInArrayStillAnchors() {
  // caCertificate as an ARRAY exercises the array-of-PEMs override path; a
  // garbage PEM among the roots must be skipped (parse-fail -> continue), and a
  // valid trailing root still anchors the chain.
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 5, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef",
                metadataStatement: { description: "arr" }, statusReports: [] }],
  }, pair.keyPem, pair.certPem);
  var garbageRoot = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n";
  var blob = null, threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      blob = await fm.fetch({ url: "https://arrroot.invalid/mds3",
                             caCertificate: [garbageRoot, pair.certPem], force: true });
    } catch (e) { threw = e; }
  });
  check("fetch skips an unparseable root in the caCertificate array and anchors on a valid one",
        !threw && blob && blob.no === 5);                                          // allow:raw-byte-literal — fixture identifier
}

async function testFetchFingerprintAnchorsPinnedNonCaLeaf() {
  // A self-signed, NON-CA leaf pinned as the trust root anchors via the exact
  // fingerprint256-match fallback: issuerValidlyIssued fails because the pinned
  // cert asserts basicConstraints cA:FALSE, but an operator pinning that exact
  // cert as their root trusts it by identity. Covers the CAs-ship-root-in-x5c
  // convenience branch (a SHA-256 collision would be needed to abuse it).
  var leaf = await _makeCert({ ca: false });
  var token = _makeBlob({
    no: 6, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, leaf.keyPem, leaf.certPem);
  var blob = null, threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      blob = await fm.fetch({ url: "https://fp.invalid/mds3", caCertificate: leaf.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch anchors a pinned non-CA leaf via exact fingerprint match",
        !threw && blob && blob.no === 6);                                          // allow:raw-byte-literal — fixture identifier
}

// ---- fetch: JWS alg verify branches (ES256 / PS256 / alg-key mismatch) ----

async function testFetchEs256() {
  // An ES256 (ECDSA P-256) BLOB exercises the dsaEncoding verify branch. MDS3 is
  // RS256 in practice, but the shared alg table lists ES256; a real ES256 BLOB
  // must validate without a code edit.
  var ec = await _makeCert({ algo: "EC" });
  var header = { alg: "ES256", typ: "JWT", x5c: [_certDerB64(ec.certPem)] };
  var token = _makeBlobSig(header, {
    no: 7, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef",
                metadataStatement: { description: "ec" }, statusReports: [] }],
  }, ec.keyPem, "sha256", { dsaEncoding: "ieee-p1363" });
  var blob = null, threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      blob = await fm.fetch({ url: "https://es256.invalid/mds3", caCertificate: ec.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch verifies an ES256 (ECDSA) BLOB",
        !threw && blob && blob.no === 7);                                          // allow:raw-byte-literal — fixture identifier
}

async function testFetchPs256() {
  // A PS256 (RSASSA-PSS) BLOB exercises the saltLength verify branch. The
  // signer's RSA_PSS_SALTLEN_DIGEST salt equals the SHA-256 digest length, which
  // is exactly the salt length the shared verifier expects for PS256.
  var rsa = await _makeSelfSignedRsaCert();
  var header = { alg: "PS256", typ: "JWT", x5c: [_certDerB64(rsa.certPem)] };
  var token = _makeBlobSig(header, {
    no: 8, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, rsa.keyPem, "sha256", {
    padding:    nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST,
  });
  var blob = null, threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      blob = await fm.fetch({ url: "https://ps256.invalid/mds3", caCertificate: rsa.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch verifies a PS256 (RSASSA-PSS) BLOB",
        !threw && blob && blob.no === 8);                                          // allow:raw-byte-literal — fixture identifier
}

async function testFetchAlgKeyTypeMismatch() {
  // A header advertising RS256 (a hash + RSA-padding verify) over a leaf carrying
  // an Ed25519 key makes node:crypto.verify throw ("invalid digest"); the
  // verifier must CATCH it and refuse as bad-signature rather than let the
  // exception crash the request. Alg/key-type confusion is refused, not
  // propagated.
  var ed = await _makeCert({ algo: "Ed25519" });
  var header = { alg: "RS256", typ: "JWT", x5c: [_certDerB64(ed.certPem)] };
  var token = _makeBlobSig(header, {
    no: 9, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, ed.keyPem, null, {});
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://algmix.invalid/mds3", caCertificate: ed.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses (not crashes) when the leaf key type cannot satisfy the header alg",
        threw && /bad-signature/.test(threw.code || ""));
}

// ---- fetch: JWS parse-segment adversarial branches ----

async function testFetchBadJwsSegment() {
  // A JWS whose SIGNATURE segment carries a non-base64url character is refused at
  // decode (bad-jws-segment). The header/payload segments are decoded inside a
  // try that rewraps any decode failure as bad-jws-json, so the signature
  // segment — decoded outside that try — is the one that surfaces the raw
  // segment error; a mangled sig can't be quietly coerced to empty bytes.
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 1, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, pair.keyPem, pair.certPem);
  var parts = token.split(".");
  var mangled = parts[0] + "." + parts[1] + "." + parts[2] + "#bad";   // '#' is not base64url
  var threw = null;
  await _withMockedHttp(_respondWith(mangled), async function (fm) {
    try {
      await fm.fetch({ url: "https://seg.invalid/mds3", caCertificate: pair.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a JWS signature segment with a non-base64url character",
        threw && /bad-jws-segment/.test(threw.code || ""));
}

async function testFetchBadJwsJson() {
  // A header segment that is valid base64url but decodes to invalid JSON is
  // refused as bad-jws-json (the decode succeeds, the parse fails).
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 1, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, pair.keyPem, pair.certPem);
  var parts = token.split(".");
  var mangled = _b64url("{ not valid json ") + "." + parts[1] + "." + parts[2];
  var threw = null;
  await _withMockedHttp(_respondWith(mangled), async function (fm) {
    try {
      await fm.fetch({ url: "https://json.invalid/mds3", caCertificate: pair.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a base64url header that is not valid JSON",
        threw && /bad-jws-json/.test(threw.code || ""));
}

async function testFetchBadX5cElements() {
  // x5c array present but the element itself is unusable. An empty-string and a
  // non-string element are refused as bad-x5c (inside chain validation); an
  // EMPTY x5c array is refused earlier as bad-jws-header (the header-shape gate).
  var pair = await _makeSelfSignedRsaCert();
  var goodPayload = {
    no: 1, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  };
  var emptyStr  = _makeBlobRaw({ alg: "RS256", typ: "JWT", x5c: [""]  }, goodPayload, pair.keyPem);
  var nonString = _makeBlobRaw({ alg: "RS256", typ: "JWT", x5c: [123] }, goodPayload, pair.keyPem);  // allow:raw-byte-literal — bad x5c type
  var emptyArr  = _makeBlobRaw({ alg: "RS256", typ: "JWT", x5c: []    }, goodPayload, pair.keyPem);
  async function fetchExpect(token, codeRe, label) {
    var threw = null;
    await _withMockedHttp(_respondWith(token), async function (fm) {
      try {
        await fm.fetch({ url: "https://x5c.invalid/mds3", caCertificate: pair.certPem, force: true });
      } catch (e) { threw = e; }
    });
    check(label, threw && codeRe.test(threw.code || ""));
  }
  await fetchExpect(emptyStr,  /bad-x5c/,        "fetch rejects an empty-string x5c element");
  await fetchExpect(nonString, /bad-x5c/,        "fetch rejects a non-string x5c element");
  await fetchExpect(emptyArr,  /bad-jws-header/, "fetch rejects an empty x5c array");
}

// ---- fetch: payload-shape + nextUpdate adversarial branches ----

async function testFetchPayloadMissingEntries() {
  // A validly-signed, anchored BLOB whose payload lacks an entries array is
  // refused as bad-payload.
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({ no: 1, nextUpdate: _futureDateString(7) }, pair.keyPem, pair.certPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://noentries.invalid/mds3", caCertificate: pair.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a payload with no entries array",
        threw && /bad-payload/.test(threw.code || ""));
}

async function testFetchPayloadMissingNo() {
  // A payload with entries but no numeric 'no' sequence number is refused.
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({ nextUpdate: _futureDateString(7), entries: [] }, pair.keyPem, pair.certPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      await fm.fetch({ url: "https://nono.invalid/mds3", caCertificate: pair.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch refuses a payload missing the numeric 'no'",
        threw && /bad-payload/.test(threw.code || ""));
}

async function testFetchBadNextUpdateShapes() {
  // nextUpdate must be a real YYYY-MM-DD calendar date. A non-string value, a
  // non-date string, and an out-of-range month each parse to null and are
  // refused as bad-payload (a malformed nextUpdate must not masquerade as a
  // valid future timestamp and influence the cache-TTL clamp).
  var pair = await _makeSelfSignedRsaCert();
  function payload(nu) {
    return { no: 1, nextUpdate: nu,
             entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }] };
  }
  var numberNu = _makeBlob(payload(20260101), pair.keyPem, pair.certPem);          // allow:raw-byte-literal — non-string nextUpdate
  var wordNu   = _makeBlob(payload("not-a-date"),  pair.keyPem, pair.certPem);
  var badMonth = _makeBlob(payload("2026-13-15"),  pair.keyPem, pair.certPem);
  async function fetchExpect(token, label) {
    var threw = null;
    await _withMockedHttp(_respondWith(token), async function (fm) {
      try {
        await fm.fetch({ url: "https://nu.invalid/mds3", caCertificate: pair.certPem, force: true });
      } catch (e) { threw = e; }
    });
    check(label, threw && /bad-payload/.test(threw.code || ""));
  }
  await fetchExpect(numberNu, "fetch refuses a non-string nextUpdate");
  await fetchExpect(wordNu,   "fetch refuses a nextUpdate that is not a date");
  await fetchExpect(badMonth, "fetch refuses a nextUpdate with an out-of-range month");
}

async function testFetchFarFutureNextUpdateClampsTtl() {
  // A nextUpdate far beyond the 30-day cache ceiling is still accepted; the TTL
  // clamp caps the cached lifetime at the ceiling so a runaway nextUpdate can't
  // freeze trust indefinitely.
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 11, nextUpdate: _futureDateString(45),                                     // allow:raw-byte-literal — beyond 30-day ceiling
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, pair.keyPem, pair.certPem);
  var blob = null, threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try {
      blob = await fm.fetch({ url: "https://farfuture.invalid/mds3", caCertificate: pair.certPem, force: true });
    } catch (e) { threw = e; }
  });
  check("fetch accepts a far-future nextUpdate (TTL clamped to the ceiling)",
        !threw && blob && blob.no === 11);                                         // allow:raw-byte-literal — fixture identifier
}

// ---- fetch / parse: default-trust-root resolution branches ----

async function testFetchNoTrustRootWhenVendorEmpty() {
  // When the DEFAULT trust-root resolver yields no anchors, fetch must fail
  // closed with no-trust-root rather than proceed against an empty root set
  // (which would let any chain "anchor" against nothing). Driven for an empty
  // return, a null return, and a throwing resolver.
  async function expectNoRoot(getter, label) {
    var threw = null;
    await _withMockedRoots(getter, async function () {
      try { await b.auth.fidoMds3.fetch({ url: "https://noroot.invalid/mds3" }); }
      catch (e) { threw = e; }
    });
    check(label, threw && /no-trust-root/.test(threw.code || ""));
  }
  await expectNoRoot(function () { return []; },
                     "fetch fails closed when the default root set is empty");
  await expectNoRoot(function () { return null; },
                     "fetch fails closed when the default root resolver returns null");
  await expectNoRoot(function () { throw new Error("vendor boom"); },
                     "fetch fails closed when the default root resolver throws");
}

async function testParsePathRefusesStaleBlob() {
  // The internal parse path (_verifyAndParseBlob, DEFAULT vendored roots) must
  // enforce the same stale-BLOB refusal as fetch — both route through the one
  // shared verifier. Pinning the default root to a self-signed cert lets the
  // parse path reach the stale check on an anchoring chain and confirms it
  // refuses a nextUpdate-in-the-past BLOB (the v0.16.18 fail-open class, on the
  // non-fetch path).
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 1, nextUpdate: _futureDateString(-7),   // 7 days in the PAST — stale
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, pair.keyPem, pair.certPem);
  var threw = null;
  await _withMockedRoots(function () { return [pair.certPem]; }, async function () {
    try { b.auth.fidoMds3._verifyAndParseBlob(token); }
    catch (e) { threw = e; }
  });
  check("_verifyAndParseBlob (default-roots parse path) refuses a stale BLOB",
        threw && /blob-stale/.test(threw.code || ""));
}

async function testFetchNoArgUsesDefaultRoots() {
  // fetch() with no argument object exercises the opts-defaulting path and the
  // real vendored default-root resolution. A synthetic BLOB signed by a test
  // cert cannot anchor to the genuine FIDO root, so it is refused — proving
  // fetch() reaches root resolution + chain anchoring even with no opts passed.
  var pair = await _makeSelfSignedRsaCert();
  var token = _makeBlob({
    no: 1, nextUpdate: _futureDateString(7),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef", statusReports: [] }],
  }, pair.keyPem, pair.certPem);
  var threw = null;
  await _withMockedHttp(_respondWith(token), async function (fm) {
    try { await fm.fetch(); }
    catch (e) { threw = e; }
  });
  check("fetch() with no opts resolves default roots and refuses an unanchored BLOB",
        threw && /chain-not-anchored/.test(threw.code || ""));
}

async function testFetchNetworkFailureNonError() {
  // The transport rejection is normalized to fido-mds3/network even when it is
  // not a well-formed Error (a message-less value); the network wrapper falls
  // back to String(e) rather than surfacing "undefined" in the audit + message.
  var threw = null;
  await _withMockedHttp(async function () {
    var rejection = new Error("");   // Error with an empty message
    throw rejection;
  }, async function (fm) {
    try {
      await fm.fetch({ url: "https://nonerr.invalid/mds3", caCertificate: "ca-not-reached", force: true });
    } catch (e) { threw = e; }
  });
  check("fetch normalizes a message-less transport rejection to fido-mds3/network",
        threw && /fido-mds3\/network/.test(threw.code || ""));
}

// ---- lookupAaguid / certifiedLevel malformed-entry branches ----

function testLookupAaguidSkipsMalformedEntries() {
  // Entries that are null or whose aaguid is non-string are skipped during
  // lookup; a valid later entry still resolves.
  var blob = {
    entries: [
      null,
      { aaguid: 12345, metadataStatement: { description: "non-string aaguid" } },  // allow:raw-byte-literal — malformed entry
      { aaguid: "01234567-89ab-cdef-0123-456789abcdef",
        metadataStatement: { description: "good" }, statusReports: [] },
    ],
  };
  var hit = b.auth.fidoMds3.lookupAaguid(blob, "01234567-89ab-cdef-0123-456789abcdef");
  check("lookupAaguid skips null + non-string-aaguid entries and still finds the match",
        hit && hit.metadataStatement.description === "good");
}

function testCertifiedLevelSkipsMalformedReports() {
  // A null report, a non-string status, and an over-64-char status token are all
  // skipped when resolving the certified level; only the well-formed grant
  // counts. Guards the length-bound-before-regex convention (an unbounded status
  // must never reach the CERT_LEVEL_RE test).
  var blob = {
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      statusReports: [
        null,
        { status: 42 },                                                            // allow:raw-byte-literal — non-string status
        { status: "A".repeat(65) },                                                // allow:raw-byte-literal — over-64-char status
        { status: "FIDO_CERTIFIED_L1" },
      ],
    }],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("certifiedLevel ignores null / non-string / over-long status reports",
        rv.certifiedLevel.level === 1 && rv.ok === true);
}

function testVerifyAuthenticatorEntryWithoutStatusReports() {
  // An entry that omits statusReports (a non-array) is treated as an empty report
  // list: ok=true, certifiedLevel 0. Exercises the non-array coercion in
  // verifyAuthenticator.
  var blob = {
    entries: [{
      aaguid: "01234567-89ab-cdef-0123-456789abcdef",
      metadataStatement: { description: "no reports" },
    }],
  };
  var rv = b.auth.fidoMds3.verifyAuthenticator(blob, {
    aaguid: "01234567-89ab-cdef-0123-456789abcdef",
  });
  check("verifyAuthenticator treats a missing statusReports as empty (ok=true, level 0)",
        rv.ok === true && rv.certifiedLevel.level === 0 &&
        rv.statement && rv.statement.description === "no reports");
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
    testVerifyAuthenticatorAttestationKeyCompromise();
    testVerifyAuthenticatorUnknownAaguid();
    testVerifyAuthenticatorBadInputs();
    testCertifiedLevelPlus();
    testCertifiedLevelMissingDateOrdering();
    await testFetchRoundTrip();
    await testFetchRejectsStaleBlob();
    await testFetchTamperedSignature();
    await testFetchWrongTrustRoot();
    await testFetchUnsupportedAlg();
    await testFetchRejectsImpossibleNextUpdate();
    await testFetchMalformedBlobHeaders();
    await testFetchRejectsBadStatus();
    await testFetchNetworkFailure();
    await testFetchBadCaCertificate();
    await testFetchCacheHitAndForceBypass();
    await testFetchRejectsNonHttps();
    await testFetchRejectsEmptyUrl();
    await testFetchRejectsBadTimeout();
    await testInternalVerifyRejectsBadJws();
    await testFetchExpiredSigningCert();
    await testFetchNotYetValidCert();
    await testFetchBrokenChain();
    await testFetchGarbageRootInArrayStillAnchors();
    await testFetchFingerprintAnchorsPinnedNonCaLeaf();
    await testFetchEs256();
    await testFetchPs256();
    await testFetchAlgKeyTypeMismatch();
    await testFetchBadJwsSegment();
    await testFetchBadJwsJson();
    await testFetchBadX5cElements();
    await testFetchPayloadMissingEntries();
    await testFetchPayloadMissingNo();
    await testFetchBadNextUpdateShapes();
    await testFetchFarFutureNextUpdateClampsTtl();
    await testFetchNoTrustRootWhenVendorEmpty();
    await testParsePathRefusesStaleBlob();
    await testFetchNoArgUsesDefaultRoots();
    await testFetchNetworkFailureNonError();
    testLookupAaguidSkipsMalformedEntries();
    testCertifiedLevelSkipsMalformedReports();
    testVerifyAuthenticatorEntryWithoutStatusReports();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
