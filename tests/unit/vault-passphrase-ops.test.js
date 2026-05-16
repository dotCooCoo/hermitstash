/**
 * Vault-passphrase-ops unit tests.
 *
 * Exercises the seal/unseal core that both the CLI
 * (scripts/vault-passphrase-{setup,remove}.js) and the admin UI route
 * (POST /admin/security/{seal,unseal}/vault-passphrase) call. Round-trip
 * + pre-flight + wrong-passphrase rejection.
 */
var { describe, it, before, after, beforeEach } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var harnessDir = path.join(__dirname, "..", "..", "data", "vpops-test-" + testId);
process.env.HERMITSTASH_DATA_DIR = harnessDir;
process.env.HERMITSTASH_DB_PATH = path.join(harnessDir, "h.db");
fs.mkdirSync(harnessDir, { recursive: true });

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var ops = require("../../lib/vault-passphrase-ops");
var C = require("../../lib/constants");

before(async function () { await vault.init(); });

after(function () {
  try { fs.rmSync(harnessDir, { recursive: true, force: true }); } catch {}
});

beforeEach(function () {
  // Some tests change file state; restore plaintext-only baseline before each
  try { if (fs.existsSync(C.PATHS.VAULT_KEY_SEALED) && !fs.existsSync(C.PATHS.VAULT_KEY)) {
    // unseal back to plaintext if a previous test left us sealed
    return ops.unsealVaultKey(Buffer.from("test-passphrase-baseline", "utf8")).catch(function() {});
  }} catch {}
});

describe("vault-passphrase-ops.preflightSealable", function () {
  it("returns ok=true when vault.key exists and no sealed/marker present", function () {
    var r = ops.preflightSealable();
    assert.strictEqual(r.ok, true);
  });

  it("returns ok=false with reason when sealed file already exists", async function () {
    var pw = Buffer.from("test-pre-sealed-1", "utf8");
    await ops.sealVaultKey(pw, {});
    var r = ops.preflightSealable();
    assert.strictEqual(r.ok, false);
    assert.match(r.reason, /already exists|nothing to seal/);
    // restore baseline
    await ops.unsealVaultKey(pw);
  });
});

describe("vault-passphrase-ops.preflightUnsealable", function () {
  it("returns ok=false when no sealed file exists", function () {
    var r = ops.preflightUnsealable();
    assert.strictEqual(r.ok, false);
    assert.match(r.reason, /does not exist/);
  });

  it("returns ok=true when sealed file exists and no plaintext present", async function () {
    var pw = Buffer.from("test-pre-unseal-1", "utf8");
    await ops.sealVaultKey(pw, {});
    var r = ops.preflightUnsealable();
    assert.strictEqual(r.ok, true);
    await ops.unsealVaultKey(pw);
  });
});

describe("vault-passphrase-ops.sealVaultKey + unsealVaultKey round-trip", function () {
  it("seals plaintext + deletes original, then unseals back byte-exact", async function () {
    var originalBytes = fs.readFileSync(C.PATHS.VAULT_KEY);
    var pw = Buffer.from("round-trip-test-passphrase", "utf8");

    var sealed = await ops.sealVaultKey(pw, {});
    assert.strictEqual(sealed.plaintextDeleted, true);
    assert.ok(!fs.existsSync(C.PATHS.VAULT_KEY), "plaintext should be deleted by default");
    assert.ok(fs.existsSync(C.PATHS.VAULT_KEY_SEALED), "sealed file should exist");
    assert.ok(!fs.existsSync(C.PATHS.VAULT_KEY_MIGRATION_PENDING), "marker cleaned up");

    var unsealed = await ops.unsealVaultKey(pw);
    assert.ok(fs.existsSync(C.PATHS.VAULT_KEY), "plaintext restored");
    assert.ok(!fs.existsSync(C.PATHS.VAULT_KEY_SEALED), "sealed file gone");
    assert.ok(!fs.existsSync(C.PATHS.VAULT_KEY_UNSEAL_PENDING), "unseal-marker cleaned up");

    var restored = fs.readFileSync(C.PATHS.VAULT_KEY);
    assert.strictEqual(Buffer.compare(originalBytes, restored), 0, "byte-exact round trip");
  });

  it("keepPlaintext leaves vault.key in place", async function () {
    var pw = Buffer.from("keep-plaintext-test", "utf8");
    var sealed = await ops.sealVaultKey(pw, { keepPlaintext: true });
    assert.strictEqual(sealed.plaintextDeleted, false);
    assert.ok(fs.existsSync(C.PATHS.VAULT_KEY), "plaintext retained");
    assert.ok(fs.existsSync(C.PATHS.VAULT_KEY_SEALED), "sealed exists");
    // Manual cleanup since invariant violation would block unseal preflight
    fs.unlinkSync(C.PATHS.VAULT_KEY_SEALED);
  });
});

describe("vault-passphrase-ops.unsealVaultKey rejection paths", function () {
  it("rejects wrong passphrase without modifying sealed file", async function () {
    var pw = Buffer.from("the-correct-one", "utf8");
    await ops.sealVaultKey(pw, {});
    var sealedBytesBefore = fs.readFileSync(C.PATHS.VAULT_KEY_SEALED);

    await assert.rejects(
      ops.unsealVaultKey(Buffer.from("the-wrong-one", "utf8")),
      /passphrase rejected/
    );

    var sealedBytesAfter = fs.readFileSync(C.PATHS.VAULT_KEY_SEALED);
    assert.strictEqual(Buffer.compare(sealedBytesBefore, sealedBytesAfter), 0, "sealed file untouched on wrong passphrase");
    assert.ok(!fs.existsSync(C.PATHS.VAULT_KEY), "plaintext NOT created on wrong passphrase");

    // Cleanup with correct passphrase
    await ops.unsealVaultKey(pw);
  });

  it("preflight rejects when both files exist", async function () {
    var pw = Buffer.from("preflight-both-exist", "utf8");
    await ops.sealVaultKey(pw, { keepPlaintext: true });
    var r = ops.preflightUnsealable();
    assert.strictEqual(r.ok, false);
    assert.match(r.reason, /already exists/);
    fs.unlinkSync(C.PATHS.VAULT_KEY_SEALED);
  });
});
