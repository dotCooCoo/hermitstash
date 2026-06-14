// Regression coverage for browser certificate issuance (routes/browser-certs.js).
//
// The generate route guarded on — and built its tracking-row keyHash from — a
// `result.fingerprint256` field that the CA package step never returns, so
// every PKCS#12 generation threw a 500 ("Certificate generation failed").
// Nothing exercised the issuance path, so the dead feature shipped unnoticed.
//
// This locks the contract the route now depends on: the CA returns
// { p12, certPem, issuedAt, expiresAt } with NO fingerprint256, and the
// SHA3-512 fingerprint the mTLS gate pins on is derived from certPem. If a
// vendor bump changes the package shape, or someone reintroduces a
// fingerprint256 dependency, this goes red.
var { describe, it } = require("node:test");
var assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");
var { certFingerprintSha3 } = require("../../lib/cert-utils");

describe("browser cert PKCS#12 issuance contract", function () {
  it("packageP12 returns { p12, certPem } with no fingerprint256; SHA3-512 fingerprint derives from certPem", async function () {
    var ca = await b.mtlsEngine.generateCa({});
    assert.ok(ca && ca.caCertPem && ca.caKeyPem, "generateCa returns a CA keypair");

    var result = await b.mtlsEngine.packageP12({
      cn: "regress-browser",
      password: "regression-password-123",
      validityDays: 365,
      caCertPem: ca.caCertPem,
      caKeyPem: ca.caKeyPem,
    });

    assert.ok(Buffer.isBuffer(result.p12), "result.p12 is a Buffer");
    assert.ok(
      typeof result.certPem === "string" && result.certPem.includes("BEGIN CERTIFICATE"),
      "result.certPem is a PEM string"
    );

    // The route must NOT depend on a fingerprint256 field — the CA does not
    // return one. (If a later vendor bump adds it, it is a conventional
    // SHA-256 fingerprint, not the SHA3-512 the gate and revocation key on.)
    assert.strictEqual(
      result.fingerprint256,
      undefined,
      "packageP12 result carries no fingerprint256 — the route derives the fingerprint from certPem"
    );

    var fp = certFingerprintSha3(result.certPem);
    assert.match(fp, /^[0-9a-f]{128}$/, "SHA3-512 fingerprint is 128 lowercase hex chars");
  });
});
