"use strict";

// Regression: lib/db.js getDbEncKey() + lib/vault.js loadKeysSync() must FAIL
// CLOSED when an encrypted database already exists but the vault key on disk no
// longer matches. The historical bug: a lost / mismatched data/vault.key made
// vault.unseal(db.key.enc) throw (Poly1305 tag failure), the catch treated that
// as corruption, regenerated a fresh DB key, and atomically overwrote db.key.enc
// — the only sealed copy of the real DB key — leaving hermitstash.db.enc
// permanently undecryptable (irreversible data loss).
//
// We boot HS in a child process (the guards call process.exit(1), which can't be
// caught in-process), then swap data/vault.key for a non-matching keypair while
// db.enc / db.key.enc persist, and assert: boot REFUSES (exit 1) AND db.key.enc
// is byte-for-byte unchanged. A genuine first run (no db.enc) still boots clean.

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const b = require("../../lib/vendor/blamejs");

const projectRoot = path.join(__dirname, "..", "..");
const vaultKeyName = "vault.key";
const dbEncName = "hermitstash.db.enc";
const dbKeyEncName = "db.key.enc";

// Boots lib/db (whose module load runs decryptDbFile() → getDbEncKey()) against
// the given data dir, then exits normally so db.js's process.on("exit") encrypt
// handler writes db.enc + db.key.enc. Returns the child's exit code.
function bootInChild(dataDir) {
  var script =
    "(async function () {" +
    "  var vault = require(" + JSON.stringify(path.join(projectRoot, "lib", "vault")) + ");" +
    "  await vault.init();" +
    "  require(" + JSON.stringify(path.join(projectRoot, "lib", "db")) + ");" +
    "})().then(function () { process.exit(0); }, function (e) {" +
    "  console.error('boot-threw:', e && e.message); process.exit(2);" +
    "});";

  var res = spawnSync(process.execPath, ["-e", script], {
    cwd: projectRoot,
    env: Object.assign({}, process.env, {
      HERMITSTASH_DATA_DIR: dataDir,
      // Use the data dir itself as the plaintext-DB working area (no tmpfs in
      // the test sandbox). Leave HERMITSTASH_DB_PATH UNSET so db.js's encPath
      // stays live (it is null when an explicit DB path is given) — that's the
      // production code path the fail-closed guards protect.
      HERMITSTASH_ALLOW_DISK_DB: "true",
      NODE_ENV: "development",
      VAULT_PASSPHRASE_MODE: "disabled",
    }),
    encoding: "utf8",
  });
  return { code: res.status, stdout: res.stdout, stderr: res.stderr };
}

function mkTmpDataDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hs-dbkey-failclosed-"));
}

test("fresh first run boots clean and creates the encrypted DB artifacts", function () {
  var dataDir = mkTmpDataDir();
  try {
    var r = bootInChild(dataDir);
    assert.strictEqual(r.code, 0, "first run should boot cleanly; stderr=" + r.stderr);
    assert.ok(fs.existsSync(path.join(dataDir, vaultKeyName)), "vault.key created");
    assert.ok(fs.existsSync(path.join(dataDir, dbEncName)), "db.enc created on exit");
    assert.ok(fs.existsSync(path.join(dataDir, dbKeyEncName)), "db.key.enc created");
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test("mismatched vault.key with an existing db.enc fails closed and never rewrites db.key.enc", function () {
  var dataDir = mkTmpDataDir();
  try {
    // 1) Genuine first boot — populates vault.key, db.enc, db.key.enc.
    var first = bootInChild(dataDir);
    assert.strictEqual(first.code, 0, "setup boot should succeed; stderr=" + first.stderr);

    var dbKeyEncPath = path.join(dataDir, dbKeyEncName);
    var dbEncPath = path.join(dataDir, dbEncName);
    assert.ok(fs.existsSync(dbEncPath), "db.enc present after setup boot");
    assert.ok(fs.existsSync(dbKeyEncPath), "db.key.enc present after setup boot");

    // Snapshot the sealed DB key before the destructive scenario.
    var dbKeyEncBefore = fs.readFileSync(dbKeyEncPath);

    // 2) Replace data/vault.key with a NON-matching keypair (simulates a vault
    //    key lost and restored from the wrong backup). db.enc / db.key.enc
    //    survive and are still sealed to the ORIGINAL keypair.
    var wrongKeys = b.crypto.generateEncryptionKeyPair();
    fs.writeFileSync(
      path.join(dataDir, vaultKeyName),
      JSON.stringify(wrongKeys, null, 2),
      { mode: 0o600 }
    );

    // 3) Boot again — must REFUSE (process.exit(1)), not regenerate the DB key.
    var second = bootInChild(dataDir);
    assert.strictEqual(second.code, 1, "boot must fail closed (exit 1) on mismatched vault.key; stderr=" + second.stderr);

    // 4) The only sealed copy of the real DB key must be byte-for-byte intact.
    var dbKeyEncAfter = fs.readFileSync(dbKeyEncPath);
    assert.ok(
      dbKeyEncBefore.equals(dbKeyEncAfter),
      "db.key.enc must NOT be rewritten when boot fails closed"
    );
    // And db.enc must be untouched too.
    assert.ok(fs.existsSync(dbEncPath), "db.enc must still exist after fail-closed boot");
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test("missing vault.key with an existing db.enc fails closed instead of minting a new keypair", function () {
  var dataDir = mkTmpDataDir();
  try {
    // Genuine first boot — populates vault.key, db.enc, db.key.enc.
    var first = bootInChild(dataDir);
    assert.strictEqual(first.code, 0, "setup boot should succeed; stderr=" + first.stderr);

    var dbKeyEncPath = path.join(dataDir, dbKeyEncName);
    var dbKeyEncBefore = fs.readFileSync(dbKeyEncPath);

    // Delete data/vault.key entirely (lost key) while the encrypted DB persists.
    // loadKeysSync() must NOT silently generate a fresh keypair here — that would
    // strand db.enc. It must fail closed.
    fs.rmSync(path.join(dataDir, vaultKeyName), { force: true });

    var second = bootInChild(dataDir);
    assert.strictEqual(second.code, 1, "missing vault.key with db.enc present must fail closed (exit 1); stderr=" + second.stderr);

    // No new vault.key may have been written, and db.key.enc must be intact.
    assert.ok(!fs.existsSync(path.join(dataDir, vaultKeyName)), "must NOT mint a new vault.key when db.enc exists");
    assert.ok(fs.readFileSync(dbKeyEncPath).equals(dbKeyEncBefore), "db.key.enc must be unchanged");
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
