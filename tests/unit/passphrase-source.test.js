/**
 * Unit tests for lib/passphrase-source.js — env / file / stdin drivers.
 *
 * Stdin is not exercised directly here (it requires a TTY mock which is
 * awkward); stdin behavior is covered by integration tests that spawn the
 * setup CLI with a fake TTY.
 */
var { describe, it, beforeEach, afterEach } = require("node:test");
var assert = require("node:assert");
var fs = require("fs");
var os = require("os");
var path = require("path");

// Each test in this file needs to reset the env. Use beforeEach to clear,
// and restore the original env at the end.
var origEnv = { ...process.env };

function clearVaultEnv() {
  delete process.env.VAULT_PASSPHRASE;
  delete process.env.VAULT_PASSPHRASE_FILE;
  delete process.env.VAULT_PASSPHRASE_SOURCE;
}

function restoreEnv() {
  clearVaultEnv();
  if (origEnv.VAULT_PASSPHRASE) process.env.VAULT_PASSPHRASE = origEnv.VAULT_PASSPHRASE;
  if (origEnv.VAULT_PASSPHRASE_FILE) process.env.VAULT_PASSPHRASE_FILE = origEnv.VAULT_PASSPHRASE_FILE;
  if (origEnv.VAULT_PASSPHRASE_SOURCE) process.env.VAULT_PASSPHRASE_SOURCE = origEnv.VAULT_PASSPHRASE_SOURCE;
}

// Clear module cache so each test gets fresh state (since the module has no
// internal state this is defensive only).
function freshModule() {
  delete require.cache[require.resolve("../../lib/passphrase-source")];
  return require("../../lib/passphrase-source");
}

describe("passphrase-source env driver", function () {
  beforeEach(function () { clearVaultEnv(); });
  afterEach(function () { restoreEnv(); });

  it("reads VAULT_PASSPHRASE and strips it from process.env", async function () {
    process.env.VAULT_PASSPHRASE = "hunter2";
    var ps = freshModule();
    var buf = await ps.fromEnv();
    assert.strictEqual(buf.toString("utf8"), "hunter2");
    assert.strictEqual(process.env.VAULT_PASSPHRASE, undefined, "should have been stripped after read");
  });

  it("rejects when VAULT_PASSPHRASE is unset", async function () {
    var ps = freshModule();
    await assert.rejects(ps.fromEnv(), /not set or is empty/);
  });

  it("rejects when VAULT_PASSPHRASE is empty string", async function () {
    process.env.VAULT_PASSPHRASE = "";
    var ps = freshModule();
    await assert.rejects(ps.fromEnv(), /not set or is empty/);
  });

  it("accepts UTF-8 non-ASCII passphrase", async function () {
    process.env.VAULT_PASSPHRASE = "пароль-空格-🔒";
    var ps = freshModule();
    var buf = await ps.fromEnv();
    assert.strictEqual(buf.toString("utf8"), "пароль-空格-🔒");
  });

  it("accepts whitespace-containing passphrase", async function () {
    process.env.VAULT_PASSPHRASE = "  spaces preserved  ";
    var ps = freshModule();
    var buf = await ps.fromEnv();
    assert.strictEqual(buf.toString("utf8"), "  spaces preserved  ");
  });

  it("rejects passphrase over 4096 bytes", async function () {
    process.env.VAULT_PASSPHRASE = "x".repeat(5000);
    var ps = freshModule();
    await assert.rejects(ps.fromEnv(), /exceeds 4096 byte limit/);
  });
});

describe("passphrase-source file driver", function () {
  var tmpDir, filePath;

  beforeEach(function () {
    clearVaultEnv();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-ps-test-"));
    filePath = path.join(tmpDir, "passphrase");
  });

  afterEach(function () {
    restoreEnv();
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  });

  it("reads passphrase from file", async function () {
    fs.writeFileSync(filePath, "file-passphrase", { mode: 0o600 });
    var ps = freshModule();
    var buf = await ps.fromFile(filePath);
    assert.strictEqual(buf.toString("utf8"), "file-passphrase");
  });

  it("trims trailing \\n", async function () {
    fs.writeFileSync(filePath, "with-newline\n");
    var ps = freshModule();
    var buf = await ps.fromFile(filePath);
    assert.strictEqual(buf.toString("utf8"), "with-newline");
  });

  it("trims trailing \\r\\n (Windows)", async function () {
    fs.writeFileSync(filePath, "windows-line\r\n");
    var ps = freshModule();
    var buf = await ps.fromFile(filePath);
    assert.strictEqual(buf.toString("utf8"), "windows-line");
  });

  it("trims multiple trailing newlines", async function () {
    fs.writeFileSync(filePath, "pw\n\n\n");
    var ps = freshModule();
    var buf = await ps.fromFile(filePath);
    assert.strictEqual(buf.toString("utf8"), "pw");
  });

  it("preserves leading whitespace", async function () {
    fs.writeFileSync(filePath, "  leading-preserved\n");
    var ps = freshModule();
    var buf = await ps.fromFile(filePath);
    assert.strictEqual(buf.toString("utf8"), "  leading-preserved");
  });

  it("preserves internal whitespace", async function () {
    fs.writeFileSync(filePath, "has internal spaces\n");
    var ps = freshModule();
    var buf = await ps.fromFile(filePath);
    assert.strictEqual(buf.toString("utf8"), "has internal spaces");
  });

  it("rejects empty file", async function () {
    fs.writeFileSync(filePath, "");
    var ps = freshModule();
    await assert.rejects(ps.fromFile(filePath), /passphrase is empty/);
  });

  it("rejects whitespace-only-newlines file (empty after trim)", async function () {
    fs.writeFileSync(filePath, "\n\n\n");
    var ps = freshModule();
    await assert.rejects(ps.fromFile(filePath), /passphrase is empty/);
  });

  it("rejects missing file with informative error", async function () {
    var ps = freshModule();
    await assert.rejects(
      ps.fromFile(path.join(tmpDir, "nonexistent")),
      /failed to read VAULT_PASSPHRASE_FILE/
    );
  });

  it("rejects missing-path argument", async function () {
    var ps = freshModule();
    await assert.rejects(ps.fromFile(""), /VAULT_PASSPHRASE_FILE is not set/);
    await assert.rejects(ps.fromFile(null), /VAULT_PASSPHRASE_FILE is not set/);
    await assert.rejects(ps.fromFile(undefined), /VAULT_PASSPHRASE_FILE is not set/);
  });

  it("accepts binary passphrase file", async function () {
    var bytes = Buffer.from([0x00, 0x01, 0xFF, 0xFE, 0x80]);
    fs.writeFileSync(filePath, bytes);
    var ps = freshModule();
    var buf = await ps.fromFile(filePath);
    assert.strictEqual(Buffer.compare(buf, bytes), 0);
  });
});

describe("passphrase-source selection (sourceKind)", function () {
  beforeEach(function () { clearVaultEnv(); });
  afterEach(function () { restoreEnv(); });

  it("auto → file when VAULT_PASSPHRASE_FILE is set", function () {
    process.env.VAULT_PASSPHRASE_FILE = "/tmp/fake";
    process.env.VAULT_PASSPHRASE = "also-set"; // file takes priority
    var ps = freshModule();
    assert.strictEqual(ps.sourceKind(), "file");
  });

  it("auto → env when only VAULT_PASSPHRASE is set", function () {
    process.env.VAULT_PASSPHRASE = "pw";
    var ps = freshModule();
    assert.strictEqual(ps.sourceKind(), "env");
  });

  it("explicit env forces env source", function () {
    process.env.VAULT_PASSPHRASE_SOURCE = "env";
    process.env.VAULT_PASSPHRASE_FILE = "/tmp/would-win-in-auto";
    var ps = freshModule();
    assert.strictEqual(ps.sourceKind(), "env");
  });

  it("explicit file forces file source", function () {
    process.env.VAULT_PASSPHRASE_SOURCE = "file";
    var ps = freshModule();
    assert.strictEqual(ps.sourceKind(), "file");
  });

  it("explicit stdin forces stdin source", function () {
    process.env.VAULT_PASSPHRASE_SOURCE = "stdin";
    var ps = freshModule();
    assert.strictEqual(ps.sourceKind(), "stdin");
  });

  it("rejects unknown VAULT_PASSPHRASE_SOURCE value", function () {
    process.env.VAULT_PASSPHRASE_SOURCE = "aws-kms";
    var ps = freshModule();
    assert.throws(function () { ps.sourceKind(); }, /Unknown VAULT_PASSPHRASE_SOURCE/);
  });

  it("is case-insensitive on source name", function () {
    process.env.VAULT_PASSPHRASE_SOURCE = "FILE";
    var ps = freshModule();
    assert.strictEqual(ps.sourceKind(), "file");
  });
});

describe("passphrase-source getPassphrase dispatch", function () {
  var tmpDir, filePath;

  beforeEach(function () {
    clearVaultEnv();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-ps-test-"));
    filePath = path.join(tmpDir, "passphrase");
  });

  afterEach(function () {
    restoreEnv();
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  });

  it("dispatches to env source correctly", async function () {
    process.env.VAULT_PASSPHRASE = "from-env";
    var ps = freshModule();
    var buf = await ps.getPassphrase();
    assert.strictEqual(buf.toString("utf8"), "from-env");
  });

  it("dispatches to file source correctly", async function () {
    fs.writeFileSync(filePath, "from-file\n");
    process.env.VAULT_PASSPHRASE_FILE = filePath;
    var ps = freshModule();
    var buf = await ps.getPassphrase();
    assert.strictEqual(buf.toString("utf8"), "from-file");
  });

  it("file beats env when both set (auto priority)", async function () {
    fs.writeFileSync(filePath, "file-wins");
    process.env.VAULT_PASSPHRASE_FILE = filePath;
    process.env.VAULT_PASSPHRASE = "env-loses";
    var ps = freshModule();
    var buf = await ps.getPassphrase();
    assert.strictEqual(buf.toString("utf8"), "file-wins");
  });

  it("rejects when no source available and no TTY", async function () {
    // Tests run in Node subprocess — stdin is not a TTY
    var ps = freshModule();
    await assert.rejects(ps.getPassphrase(), /No passphrase source available|stdin.*TTY/);
  });
});
