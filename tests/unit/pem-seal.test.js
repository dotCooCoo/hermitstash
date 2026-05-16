var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");

// Isolated harness — vault module loads cleanly against an isolated DB
var testId = b.crypto.generateToken(4);
var harnessDir = path.join(__dirname, "..", "..", "data", "pem-seal-test-" + testId);
process.env.HERMITSTASH_DATA_DIR = harnessDir;
process.env.HERMITSTASH_DB_PATH = path.join(harnessDir, "h.db");
fs.mkdirSync(harnessDir, { recursive: true });

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var pemSeal = require("../../lib/pem-seal");

before(async function () {
  await vault.init();
});

after(function () {
  try { fs.rmSync(harnessDir, { recursive: true, force: true }); } catch {}
});

function tmpPath(suffix) {
  return path.join(harnessDir, "case-" + b.crypto.generateToken(3) + (suffix || ""));
}

var EC_PEM = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIN3J9vN2pQ8K7bTk+a9YFr6lJ6JaH4QnT5h2L8mZbXJqoAoGCCqGSM49\nAwEHoUQDQgAEqRz0J2N4YlH4R7QkXZPp3LqV2cGmK8x3jVfL5eWqHlBbR3K6tLwM\nJaHfQfL9X5sJqV2cGmK8x3jVfL5eWqHlBb==\n-----END EC PRIVATE KEY-----\n";
var RSA_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDH3vFOAKr4NpQp\n9Z7mqXJ8KkjQHrLpW3rN6TkJ4M5LrXN8vV7L3jH9pRlFqJ6Nz3kT8mOcQc7dHhZE\nQAtKqzVCqGm0Vp6NQXnvA8OfHuTqE9bqf3jK9LcW5N0pXWQ8ZHrV9Q2PqHJdRpJ8\n-----END PRIVATE KEY-----\n";

describe("pem-seal.isPemContent", function () {

  it("accepts EC PRIVATE KEY", function () {
    assert.strictEqual(pemSeal.isPemContent(Buffer.from(EC_PEM)), true);
  });

  it("accepts RSA-style PRIVATE KEY", function () {
    assert.strictEqual(pemSeal.isPemContent(Buffer.from(RSA_PEM)), true);
  });

  it("accepts CERTIFICATE", function () {
    assert.strictEqual(pemSeal.isPemContent(Buffer.from("-----BEGIN CERTIFICATE-----\nMIID==\n-----END CERTIFICATE-----")), true);
  });

  it("rejects content without -----BEGIN header", function () {
    assert.strictEqual(pemSeal.isPemContent(Buffer.from("just some random bytes")), false);
  });

  it("rejects empty buffer", function () {
    assert.strictEqual(pemSeal.isPemContent(Buffer.from("")), false);
  });
});

describe("pem-seal.sealPemFile + unsealPemFile round-trip", function () {

  function roundTrip(pemStr) {
    var plain = tmpPath(".pem");
    var sealed = plain + ".sealed";
    fs.writeFileSync(plain, pemStr);

    pemSeal.sealPemFile(plain, sealed);
    assert.ok(!fs.existsSync(plain), "plaintext should be deleted by default");
    assert.ok(fs.existsSync(sealed), "sealed file should exist");
    assert.ok(!fs.existsSync(sealed + ".tmp"), "no leftover .tmp");
    assert.ok(!fs.existsSync(sealed + ".migration-pending"), "marker cleaned up");

    var sealedBytes = fs.readFileSync(sealed, "utf8");
    assert.match(sealedBytes, /^vault:/);

    pemSeal.unsealPemFile(sealed, plain);
    assert.ok(fs.existsSync(plain), "plaintext restored");
    assert.ok(!fs.existsSync(sealed), "sealed cleaned up");
    assert.ok(!fs.existsSync(plain + ".unseal-pending"), "marker cleaned up");

    assert.strictEqual(fs.readFileSync(plain, "utf8"), pemStr, "byte-exact round trip");

    fs.unlinkSync(plain);
  }

  it("EC private key", function () { roundTrip(EC_PEM); });
  it("RSA-style private key", function () { roundTrip(RSA_PEM); });

  it("--keep-plaintext retains the source file", function () {
    var plain = tmpPath(".pem");
    var sealed = plain + ".sealed";
    fs.writeFileSync(plain, EC_PEM);
    pemSeal.sealPemFile(plain, sealed, { keepPlaintext: true });
    assert.ok(fs.existsSync(plain), "plaintext retained");
    assert.ok(fs.existsSync(sealed));
    fs.unlinkSync(plain);
    fs.unlinkSync(sealed);
  });

  it("100 seals produce 100 unique envelopes", function () {
    var seen = {};
    for (var i = 0; i < 100; i++) {
      var plain = tmpPath(".pem");
      var sealed = plain + ".sealed";
      fs.writeFileSync(plain, EC_PEM);
      pemSeal.sealPemFile(plain, sealed);
      var content = fs.readFileSync(sealed, "utf8");
      assert.ok(!seen[content], "envelope must not repeat");
      seen[content] = true;
      fs.unlinkSync(sealed);
    }
  });
});

describe("pem-seal.sealPemFile guards", function () {

  it("rejects non-PEM input (no -----BEGIN header)", function () {
    var plain = tmpPath(".bad");
    var sealed = plain + ".sealed";
    fs.writeFileSync(plain, "this is plain text, not a PEM");
    assert.throws(function () {
      pemSeal.sealPemFile(plain, sealed);
    }, /does not look like a PEM/);
    fs.unlinkSync(plain);
  });

  it("refuses to overwrite an existing sealed file", function () {
    var plain = tmpPath(".pem");
    var sealed = plain + ".sealed";
    fs.writeFileSync(plain, EC_PEM);
    fs.writeFileSync(sealed, "vault:already-here");
    assert.throws(function () {
      pemSeal.sealPemFile(plain, sealed);
    }, /already exists/);
    fs.unlinkSync(plain);
    fs.unlinkSync(sealed);
  });

  it("errors on missing source", function () {
    assert.throws(function () {
      pemSeal.sealPemFile(tmpPath(".nonexistent"), tmpPath(".sealed"));
    }, /does not exist/);
  });
});

describe("pem-seal.loadPemDispatch (6-state table)", function () {

  function setup(state) {
    var plain = tmpPath(".pem");
    var sealed = plain + ".sealed";
    if (state.hasPlain) fs.writeFileSync(plain, EC_PEM);
    if (state.hasSealed) {
      // Genuine sealed value
      var tmpPlain = tmpPath(".tmp.pem");
      fs.writeFileSync(tmpPlain, EC_PEM);
      pemSeal.sealPemFile(tmpPlain, sealed);
    }
    return { plain: plain, sealed: sealed };
  }
  function cleanup(p) {
    try { fs.unlinkSync(p.plain); } catch {}
    try { fs.unlinkSync(p.sealed); } catch {}
  }

  it("plain only + mode auto → loads plain", function () {
    delete process.env.TEST_MODE_VAR;
    var p = setup({ hasPlain: true });
    var buf = pemSeal.loadPemDispatch(p.plain, p.sealed, "TEST_MODE_VAR");
    assert.strictEqual(buf.toString("utf8"), EC_PEM);
    cleanup(p);
  });

  it("plain only + mode required → FATAL", function () {
    process.env.TEST_MODE_VAR = "required";
    var p = setup({ hasPlain: true });
    assert.throws(function () {
      pemSeal.loadPemDispatch(p.plain, p.sealed, "TEST_MODE_VAR");
    }, /Config mismatch.*plaintext.*required/);
    delete process.env.TEST_MODE_VAR;
    cleanup(p);
  });

  it("sealed only + mode auto → unseals and loads", function () {
    delete process.env.TEST_MODE_VAR;
    var p = setup({ hasSealed: true });
    var buf = pemSeal.loadPemDispatch(p.plain, p.sealed, "TEST_MODE_VAR");
    assert.strictEqual(buf.toString("utf8"), EC_PEM);
    cleanup(p);
  });

  it("sealed only + mode disabled → FATAL", function () {
    process.env.TEST_MODE_VAR = "disabled";
    var p = setup({ hasSealed: true });
    assert.throws(function () {
      pemSeal.loadPemDispatch(p.plain, p.sealed, "TEST_MODE_VAR");
    }, /Config mismatch.*disabled/);
    delete process.env.TEST_MODE_VAR;
    cleanup(p);
  });

  it("both files → invariant violation FATAL", function () {
    delete process.env.TEST_MODE_VAR;
    var p = setup({ hasPlain: true, hasSealed: true });
    assert.throws(function () {
      pemSeal.loadPemDispatch(p.plain, p.sealed, "TEST_MODE_VAR");
    }, /Invariant violation/);
    cleanup(p);
  });

  it("neither file → returns null (caller bootstraps)", function () {
    var p = { plain: tmpPath(".pem"), sealed: tmpPath(".sealed") };
    var result = pemSeal.loadPemDispatch(p.plain, p.sealed, "TEST_MODE_VAR");
    assert.strictEqual(result, null);
  });
});
