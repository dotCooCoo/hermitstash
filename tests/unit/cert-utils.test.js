const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");

const certUtils = require(path.join(__dirname, "..", "..", "lib", "cert-utils"));

describe("cert-utils canonicalCertPem", function () {
  it("returns '' (no throw) for a PEM whose base64 body decodes to zero bytes", function () {
    // body "=" base64-decodes to empty bytes → derB64 "" → "".match(/.{1,64}/g)
    // is null → .join() would throw a TypeError. The empty-decode guard returns a
    // stable empty canonical form (which hashes deterministically and simply never
    // matches a revocation row) instead of crashing the fingerprint/revocation path.
    var pem = "-----BEGIN CERTIFICATE-----\n=\n-----END CERTIFICATE-----";
    assert.strictEqual(certUtils.canonicalCertPem(pem), "");
  });

  it("certFingerprintSha3 does not throw on a malformed (empty-decode) cert", function () {
    var pem = "-----BEGIN CERTIFICATE-----\n=\n-----END CERTIFICATE-----";
    var fp = certUtils.certFingerprintSha3(pem);
    assert.strictEqual(typeof fp, "string", "fingerprint of a malformed cert is a deterministic string, not a throw");
  });

  it("returns '' for an empty / whitespace-only PEM body", function () {
    assert.strictEqual(certUtils.canonicalCertPem("-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----"), "");
    assert.strictEqual(certUtils.canonicalCertPem(""), "");
  });

  it("canonicalizes a valid base64 body into a stable 64-column wrapped form", function () {
    var der = Buffer.from("some deterministic bytes for a canonical-form round-trip test").toString("base64");
    var out = certUtils.canonicalCertPem("-----BEGIN CERTIFICATE-----\n" + der + "\n-----END CERTIFICATE-----");
    assert.ok(out.startsWith("-----BEGIN CERTIFICATE-----\n"), "begins with the BEGIN line");
    assert.ok(out.endsWith("\n-----END CERTIFICATE-----\n"), "ends with the END line + newline");
    // Idempotent: canonicalizing the canonical form yields the same bytes.
    assert.strictEqual(certUtils.canonicalCertPem(out), out, "canonical form is a fixed point");
  });
});
