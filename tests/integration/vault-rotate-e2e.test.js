/**
 * E2E integration: full vault key rotation cycle via the CLI.
 *
 * Covers:
 *   - Plaintext-mode rotation (no passphrase)
 *   - Wrapped-mode rotation (same passphrase across rotation)
 *   - Wrapped-mode rotation with a new passphrase
 *
 * Each test builds a fixture data directory with a realistic encrypted DB,
 * invokes scripts/vault-key-rotate.js via child_process, then confirms:
 *   - Rotated data decrypts with the new vault
 *   - Rotated data FAILS to decrypt with the old vault (true rotation)
 *   - data.old.<ts>/ is retained and decrypts with the old vault (valid backup)
 *
 * Backup/restore interop is covered by the top-level tests/run-all.js suite
 * run from the sync repo — this file exercises the rotation tool itself.
 */
var { describe, it, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var os = require("os");
var crypto = require("crypto");
var { spawnSync } = require("child_process");
var { DatabaseSync } = require("node:sqlite");

var REPO_ROOT = path.resolve(__dirname, "..", "..");
var cryptoLib = require(path.join(REPO_ROOT, "lib", "crypto"));
var b = require(path.join(REPO_ROOT, "lib", "vendor", "blamejs"));
var { VAULT_PREFIX } = require(path.join(REPO_ROOT, "lib", "constants"));

var testRoot = path.join(os.tmpdir(), "vault-rotate-e2e-" + b.crypto.generateToken(4));
fs.mkdirSync(testRoot, { recursive: true });

after(function () {
  fs.rmSync(testRoot, { recursive: true, force: true });
});

function sealWith(keys, plaintext) {
  // Produce a 0xE2 envelope so the fixture matches what the live
  // server writes today. lib/crypto.js still encrypts with the legacy
  // 0xE1 magic for HS's own decrypt path, but the rotate tool reads
  // through b.crypto.decrypt which rejects 0xE1 (it predates the
  // FixedInfo KDF binding from NIST SP 800-56C r2 §4.1).
  return VAULT_PREFIX + b.crypto.encrypt(plaintext, keys);
}

function buildFixture(dataDir, oldKeys, opts) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  opts = opts || {};

  if (opts.wrapped) {
    // Defer: caller wraps the key after building the DB, since wrapping is async
  } else {
    fs.writeFileSync(path.join(dataDir, "vault.key"), JSON.stringify(oldKeys), { mode: 0o600 });
  }

  var dbKey = cryptoLib.generateBytes(32);
  fs.writeFileSync(path.join(dataDir, "db.key.enc"),
    VAULT_PREFIX + b.crypto.encrypt(dbKey.toString("base64"), oldKeys), { mode: 0o600 });

  var tmpDb = path.join(dataDir, "build.db");
  var db = new DatabaseSync(tmpDb);
  db.prepare("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, displayName TEXT, status TEXT, createdAt TEXT, data TEXT)").run();
  db.prepare("CREATE TABLE audit_log (_id TEXT PRIMARY KEY, action TEXT, details TEXT, createdAt TEXT, data TEXT)").run();

  for (var i = 0; i < 20; i++) {
    db.prepare("INSERT INTO users (_id, email, displayName, status, createdAt, data) VALUES (?, ?, ?, ?, ?, ?)").run(
      "u" + i,
      sealWith(oldKeys, "user" + i + "@example.com"),
      sealWith(oldKeys, "User " + i),
      "active",
      new Date().toISOString(),
      JSON.stringify({ vaultEnabled: sealWith(oldKeys, "true") })
    );
  }
  for (var j = 0; j < 30; j++) {
    db.prepare("INSERT INTO audit_log (_id, action, details, createdAt) VALUES (?, ?, ?, ?)").run(
      "a" + j,
      sealWith(oldKeys, "login"),
      sealWith(oldKeys, "event " + j),
      new Date().toISOString()
    );
  }
  db.close();

  fs.writeFileSync(path.join(dataDir, "hermitstash.db.enc"),
    b.crypto.encryptPacked(fs.readFileSync(tmpDb), dbKey));
  fs.unlinkSync(tmpDb);

  return { dataDir: dataDir, oldKeys: oldKeys, dbKey: dbKey };
}

async function wrapVaultKey(dataDir, keys, passphrase) {
  var b = require(path.join(REPO_ROOT, "lib", "vendor", "blamejs"));
  var sealed = await b.vaultWrap.wrap(JSON.stringify(keys), Buffer.from(passphrase, "utf8"));
  fs.writeFileSync(path.join(dataDir, "vault.key.sealed"), sealed, { mode: 0o600 });
}

function runRotate(dataDir, env, args) {
  var fullEnv = Object.assign({
    HERMITSTASH_DATA_DIR: dataDir,
    ARGON2_FAST: "1",
    PORT: "18997",
  }, process.env, env || {});
  var finalArgs = ["scripts/vault-key-rotate.js", "--allow-root"].concat(args || []);
  return spawnSync("node", finalArgs, {
    cwd: REPO_ROOT, env: fullEnv, encoding: "utf8", timeout: 90000,
  });
}

function readVaultKey(dataDir) {
  if (fs.existsSync(path.join(dataDir, "vault.key"))) {
    return JSON.parse(fs.readFileSync(path.join(dataDir, "vault.key"), "utf8"));
  }
  return null;
}

async function unwrapVaultKey(dataDir, passphrase) {
  var b = require(path.join(REPO_ROOT, "lib", "vendor", "blamejs"));
  var sealed = fs.readFileSync(path.join(dataDir, "vault.key.sealed"));
  var plain = await b.vaultWrap.unwrap(sealed, Buffer.from(passphrase, "utf8"));
  return JSON.parse(plain.toString("utf8"));
}

function decryptLiveDb(dataDir, keys) {
  var sealedDbKey = fs.readFileSync(path.join(dataDir, "db.key.enc"), "utf8").trim();
  var dbKey = Buffer.from(
    b.crypto.decrypt(sealedDbKey.substring(VAULT_PREFIX.length), keys),
    "base64"
  );
  var packed = fs.readFileSync(path.join(dataDir, "hermitstash.db.enc"));
  var plain = b.crypto.decryptPacked(packed, dbKey);
  var tmpPath = path.join(dataDir, ".probe-" + Date.now() + ".db");
  fs.writeFileSync(tmpPath, plain);
  var db = new DatabaseSync(tmpPath);
  var rows = db.prepare("SELECT * FROM users ORDER BY _id LIMIT 5").all();
  db.close();
  try { fs.unlinkSync(tmpPath); } catch {}
  return { rows: rows, dbKey: dbKey };
}

function findDataOldDir(parent, dataBasename) {
  var entries = fs.readdirSync(parent);
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].indexOf(dataBasename + ".old.") === 0) return path.join(parent, entries[i]);
  }
  return null;
}

describe("vault-rotate E2E: plaintext mode", function () {

  it("full lifecycle — rotate, verify new works, old fails, backup retained", async function () {
    var dataDir = path.join(testRoot, "plain-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);

    var r = runRotate(dataDir, {}, []);
    assert.strictEqual(r.status, 0, "rotate exit: " + r.status + "\nstdout: " + r.stdout + "\nstderr: " + r.stderr);

    // After rotation:
    //   data/ has new vault.key and re-encrypted DB
    //   data.old.<ts>/ has the original vault.key and original DB
    var newKeys = readVaultKey(dataDir);
    assert.ok(newKeys);
    assert.notStrictEqual(newKeys.privateKey, oldKeys.privateKey, "new keys must be distinct");

    var parent = path.dirname(dataDir);
    var dataBase = path.basename(dataDir);
    var oldDir = findDataOldDir(parent, dataBase);
    assert.ok(oldDir, "data.old.<ts>/ should exist");

    // Rotated data decrypts with new keys
    var probe = decryptLiveDb(dataDir, newKeys);
    assert.ok(probe.rows.length > 0);
    var firstEmail = b.crypto.decrypt(probe.rows[0].email.substring(VAULT_PREFIX.length), newKeys);
    assert.match(firstEmail, /@example\.com$/);

    // Old backup still decrypts with old keys
    var oldBackupKeys = readVaultKey(oldDir);
    assert.ok(oldBackupKeys);
    var oldProbe = decryptLiveDb(oldDir, oldBackupKeys);
    assert.ok(oldProbe.rows.length > 0);

    // Rotated values FAIL with old keys (true rotation check)
    var sealedInNew = probe.rows[0].email;
    assert.throws(function () {
      b.crypto.decrypt(sealedInNew.substring(VAULT_PREFIX.length), oldKeys);
    }, "old keys must not decrypt rotated values");

    // db.key.enc in new data must also not be readable with old keys
    var newSealedDbKey = fs.readFileSync(path.join(dataDir, "db.key.enc"), "utf8").trim();
    assert.throws(function () {
      b.crypto.decrypt(newSealedDbKey.substring(VAULT_PREFIX.length), oldKeys);
    });

    // Underlying dbKey VALUE unchanged (spec §2.1)
    var oldDbKeySealed = fs.readFileSync(path.join(oldDir, "db.key.enc"), "utf8").trim();
    var oldUnderlying = b.crypto.decrypt(oldDbKeySealed.substring(VAULT_PREFIX.length), oldKeys);
    var newUnderlying = b.crypto.decrypt(newSealedDbKey.substring(VAULT_PREFIX.length), newKeys);
    assert.strictEqual(oldUnderlying, newUnderlying);
  });

  it("--dry-run leaves data/ untouched and doesn't create data.old.*", function () {
    var dataDir = path.join(testRoot, "dry-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);

    var originalVaultKey = fs.readFileSync(path.join(dataDir, "vault.key"), "utf8");
    var originalDbEnc = fs.readFileSync(path.join(dataDir, "hermitstash.db.enc"));

    var r = runRotate(dataDir, {}, ["--dry-run"]);
    assert.strictEqual(r.status, 0, "dry-run exit: " + r.status + "\nstderr: " + r.stderr);

    assert.strictEqual(fs.readFileSync(path.join(dataDir, "vault.key"), "utf8"), originalVaultKey,
      "vault.key must be byte-exact after dry run");
    assert.strictEqual(Buffer.compare(fs.readFileSync(path.join(dataDir, "hermitstash.db.enc")), originalDbEnc), 0);

    var parent = path.dirname(dataDir);
    var oldDir = findDataOldDir(parent, path.basename(dataDir));
    assert.strictEqual(oldDir, null, "no data.old.* should be created on dry run");
    assert.ok(!fs.existsSync(dataDir + ".rotating"), "staging dir cleaned up");
  });

  it("pre-flight refuses when stale data.rotating/ exists", function () {
    var dataDir = path.join(testRoot, "stale-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);
    fs.mkdirSync(dataDir + ".rotating");

    var r = runRotate(dataDir, {}, []);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /stale.*\.rotating exists/);
  });
});

describe("vault-rotate E2E: wrapped mode", function () {

  it("full lifecycle — rotate with SAME passphrase, new keypair, old backup retained", async function () {
    var dataDir = path.join(testRoot, "wrap-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);
    // Remove plaintext vault.key and replace with wrapped
    fs.unlinkSync(path.join(dataDir, "vault.key"));
    var pw = "correct horse battery staple";
    await wrapVaultKey(dataDir, oldKeys, pw);

    var r = runRotate(dataDir, {
      VAULT_PASSPHRASE_OLD: pw,
      VAULT_PASSPHRASE_NEW: pw, // same passphrase, rotating only the keypair
    }, []);
    assert.strictEqual(r.status, 0, "rotate exit: " + r.status + "\nstdout: " + r.stdout + "\nstderr: " + r.stderr);

    // Unwrap new vault.key.sealed with SAME passphrase
    var newKeys = await unwrapVaultKey(dataDir, pw);
    assert.ok(newKeys);
    assert.notStrictEqual(newKeys.privateKey, oldKeys.privateKey);

    // Rotated data decrypts with new keys
    var probe = decryptLiveDb(dataDir, newKeys);
    assert.ok(probe.rows.length > 0);
    var firstEmail = b.crypto.decrypt(probe.rows[0].email.substring(VAULT_PREFIX.length), newKeys);
    assert.match(firstEmail, /@example\.com$/);

    // Old data.old.<ts>/ should still be unwrappable with the SAME passphrase and contain oldKeys
    var parent = path.dirname(dataDir);
    var oldDir = findDataOldDir(parent, path.basename(dataDir));
    assert.ok(oldDir);
    var retrievedOldKeys = await unwrapVaultKey(oldDir, pw);
    assert.strictEqual(retrievedOldKeys.privateKey, oldKeys.privateKey);
  });

  it("full lifecycle — rotate with NEW passphrase", async function () {
    var dataDir = path.join(testRoot, "wrap-newpw-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);
    fs.unlinkSync(path.join(dataDir, "vault.key"));
    var oldPw = "original passphrase abc";
    var newPw = "brand new passphrase xyz";
    await wrapVaultKey(dataDir, oldKeys, oldPw);

    var r = runRotate(dataDir, {
      VAULT_PASSPHRASE_OLD: oldPw,
      VAULT_PASSPHRASE_NEW: newPw,
    }, []);
    assert.strictEqual(r.status, 0, "rotate exit: " + r.status + "\nstderr: " + r.stderr);

    // New sealed file must unwrap with NEW passphrase and FAIL with old
    var newKeys = await unwrapVaultKey(dataDir, newPw);
    assert.ok(newKeys);
    await assert.rejects(unwrapVaultKey(dataDir, oldPw));

    // Old backup still unwraps with ORIGINAL passphrase
    var parent = path.dirname(dataDir);
    var oldDir = findDataOldDir(parent, path.basename(dataDir));
    var originalKeysFromBackup = await unwrapVaultKey(oldDir, oldPw);
    assert.strictEqual(originalKeysFromBackup.privateKey, oldKeys.privateKey);
  });

  it("rejects wrong OLD passphrase without touching data/", async function () {
    var dataDir = path.join(testRoot, "badpw-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);
    fs.unlinkSync(path.join(dataDir, "vault.key"));
    await wrapVaultKey(dataDir, oldKeys, "the correct one");

    var originalSealed = fs.readFileSync(path.join(dataDir, "vault.key.sealed"));
    var r = runRotate(dataDir, {
      VAULT_PASSPHRASE_OLD: "THE WRONG ONE",
      VAULT_PASSPHRASE_NEW: "something",
    }, []);
    assert.notStrictEqual(r.status, 0, "must fail with wrong old passphrase");
    // data/ must be untouched
    assert.strictEqual(Buffer.compare(fs.readFileSync(path.join(dataDir, "vault.key.sealed")), originalSealed), 0);
    var parent = path.dirname(dataDir);
    assert.strictEqual(findDataOldDir(parent, path.basename(dataDir)), null, "no data.old.* on failure");
    assert.ok(!fs.existsSync(dataDir + ".rotating"), "staging cleaned up on failure");
  });
});
