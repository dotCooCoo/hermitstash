/**
 * E2E integration: full vault key rotation cycle via the CLI.
 *
 * Covers:
 *   - Plaintext-mode rotation (no passphrase)
 *   - Wrapped-mode rotation (same passphrase across rotation)
 *   - Wrapped-mode rotation with a new passphrase
 *
 * Each test builds a fixture data directory with a realistic encrypted DB,
 * written bound to the data directory as a running server writes it, invokes
 * scripts/vault-key-rotate.js via child_process, then confirms:
 *   - Rotated data decrypts with the new vault
 *   - Rotated data FAILS to decrypt with the old vault (true rotation)
 *   - .rotation-old-<ts>/ is retained inside the data directory and decrypts
 *     with the old vault (valid backup)
 *   - scripts/vault-key-verify.js passes on the rotated directory
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
var fieldCrypto = require(path.join(REPO_ROOT, "lib", "field-crypto"));
var { VAULT_PREFIX, DATA_DIR_INTERNAL, TIME } = require(path.join(REPO_ROOT, "lib", "constants"));
// The PRODUCTION db.enc codec (the module lib/db.js's boot path uses), so the
// fixture writes db.enc the way a running server does and the reads below
// decrypt it the way the server will.
var dbEncCodec = require(path.join(REPO_ROOT, "lib", "db-enc-codec"));

// Register HS's field-crypto schemas (users → aad:true, rowIdField:"_id",
// schemaVersion:"1") so this parent test process can build a REAL AAD-bound
// cell whose AAD tuple matches what the rotate pipeline reconstructs in its
// child process (it calls the same registerWithBlamejs()).
fieldCrypto.registerWithBlamejs();

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

// Build the canonical column AAD for a (table, rowId, column) under HS's
// registered schema (rowIdField "_id", schemaVersion "1") via the SAME
// builder the seal path and the rotate pipeline use (cryptoField._aadParts),
// so the rotation walker reconstructs the identical AAD tuple and recognizes
// the cell.
function aadPartsFor(table, column, rowId) {
  var schema = b.cryptoField.getSchema(table);
  return b.cryptoField._aadParts(schema, table, column, { _id: rowId });
}

// Seal a REAL AAD-bound ("vault.aad:") cell under an explicit vault root.
// rootKeysJson matches getKeysJson() exactly (JSON.stringify(keys, null, 2))
// so a cell sealed here under oldKeys is recognized + re-sealed by rotate.
function sealAadWith(keys, table, column, rowId, plaintext) {
  return b.vault.aad.sealRoot(plaintext, aadPartsFor(table, column, rowId),
    JSON.stringify(keys, null, 2));
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
    var rowId = "u" + i;
    // When the caller asks for an AAD cell on this row, seal the email column
    // as a REAL "vault.aad:" cell (AEAD-bound to table+_id+column+schemaVersion)
    // instead of the legacy "vault:" envelope, so the fixture exercises the
    // rotate pipeline's AAD re-seal branch alongside the legacy branch.
    var emailPlain = "user" + i + "@example.com";
    var emailSealed = (opts.aadCell && opts.aadCell.rowId === rowId)
      ? sealAadWith(oldKeys, "users", "email", rowId, emailPlain)
      : sealWith(oldKeys, emailPlain);
    db.prepare("INSERT INTO users (_id, email, displayName, status, createdAt, data) VALUES (?, ?, ?, ?, ?, ?)").run(
      rowId,
      emailSealed,
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

  // Bound to the data directory, as lib/db.js writes it on a running server.
  fs.writeFileSync(path.join(dataDir, "hermitstash.db.enc"),
    dbEncCodec.encryptDbEnc(fs.readFileSync(tmpDb), dbKey, dataDir));
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

// Decrypt hermitstash.db.enc → plaintext SQLite bytes through the production
// codec. Both the live DB and the retained .rotation-old-<ts> copy are bound to
// the data directory path, so a copy read from the old directory passes that
// path as boundDir.
function decryptDbBytes(dir, dbKey, boundDir) {
  var packed = fs.readFileSync(path.join(dir, "hermitstash.db.enc"));
  return dbEncCodec.decryptDbEnc(packed, dbKey, boundDir || dir);
}

function readDbKey(dataDir, keys) {
  var sealedDbKey = fs.readFileSync(path.join(dataDir, "db.key.enc"), "utf8").trim();
  return Buffer.from(
    b.crypto.decrypt(sealedDbKey.substring(VAULT_PREFIX.length), keys),
    "base64"
  );
}

function decryptLiveDb(dataDir, keys, boundDir) {
  var dbKey = readDbKey(dataDir, keys);
  var plain = decryptDbBytes(dataDir, dbKey, boundDir);
  var tmpPath = path.join(dataDir, ".probe-" + Date.now() + ".db");
  fs.writeFileSync(tmpPath, plain);
  var db = new DatabaseSync(tmpPath);
  var rows = db.prepare("SELECT * FROM users ORDER BY _id LIMIT 5").all();
  db.close();
  try { fs.unlinkSync(tmpPath); } catch {}
  return { rows: rows, dbKey: dbKey };
}

// Read one specific cell's RAW stored value (the sealed string as-is, no
// unseal) from the live encrypted DB. Used to capture an AAD cell's ciphertext
// before vs. after rotation so the test can prove the bytes actually changed.
function readRawCell(dataDir, keys, table, rowId, column, boundDir) {
  var dbKey = readDbKey(dataDir, keys);
  var plain = decryptDbBytes(dataDir, dbKey, boundDir);
  var tmpPath = path.join(dataDir, ".rawcell-" + Date.now() + "-" + b.crypto.generateToken(3) + ".db");
  fs.writeFileSync(tmpPath, plain);
  var db = new DatabaseSync(tmpPath);
  var row = db.prepare("SELECT " + column + " AS v FROM " + table + " WHERE _id = ?").get(rowId);
  db.close();
  try { fs.unlinkSync(tmpPath); } catch {}
  return row ? row.v : null;
}

// The directory a completed rotation leaves the pre-rotation entries in.
function findOldDir(dataDir) {
  var entries = fs.readdirSync(dataDir);
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].indexOf(DATA_DIR_INTERNAL.ROTATION_OLD_PREFIX) === 0) return path.join(dataDir, entries[i]);
  }
  return null;
}

function stagingDir(dataDir) {
  return path.join(dataDir, DATA_DIR_INTERNAL.ROTATION_STAGING);
}

// Nothing outside the data directory is created: no sibling staging, marker
// or old directory.
function assertNoSiblings(dataDir) {
  var base = path.basename(dataDir);
  var siblings = fs.readdirSync(path.dirname(dataDir)).filter(function (n) {
    return n !== base && n.indexOf(base) === 0;
  });
  assert.deepStrictEqual(siblings, [], "no entries are created next to the data directory");
}

describe("vault-rotate E2E: plaintext mode", function () {

  it("full lifecycle — rotate, verify new works, old fails, backup retained", async function () {
    var dataDir = path.join(testRoot, "plain-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);
    // These files hold state the rotation does not rewrite. The swap replaces
    // the data directory with the rotated copy, so the copy has to carry each.
    var kept = {
      "revocations.json": "[]", "ca.crl-number": "7\n", "revoked-generation": "2",
      "audit-sign.key": "signing key", "custom-logos/logo.png": "png",
    };
    Object.keys(kept).forEach(function (rel) {
      fs.mkdirSync(path.dirname(path.join(dataDir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dataDir, rel), kept[rel]);
    });

    var r = runRotate(dataDir, {}, []);
    assert.strictEqual(r.status, 0, "rotate exit: " + r.status + "\nstdout: " + r.stdout + "\nstderr: " + r.stderr);
    Object.keys(kept).forEach(function (rel) {
      assert.strictEqual(fs.readFileSync(path.join(dataDir, rel), "utf8"), kept[rel],
        rel + " is in the data directory after the swap, unchanged");
    });

    // After rotation:
    //   data/ has new vault.key and re-encrypted DB
    //   data/.rotation-old-<ts>/ has the original vault.key and original DB
    var newKeys = readVaultKey(dataDir);
    assert.ok(newKeys);
    assert.notStrictEqual(newKeys.privateKey, oldKeys.privateKey, "new keys must be distinct");

    var oldDir = findOldDir(dataDir);
    assert.ok(oldDir, ".rotation-old-<ts>/ should exist inside the data directory");
    assertNoSiblings(dataDir);
    assert.ok(!fs.existsSync(stagingDir(dataDir)), "the staging directory is gone after the swap");
    assert.ok(!fs.existsSync(path.join(dataDir, DATA_DIR_INTERNAL.ROTATION_MARKER)), "the swap marker is gone");

    // Rotated data decrypts with new keys
    var probe = decryptLiveDb(dataDir, newKeys);
    assert.ok(probe.rows.length > 0);
    var firstEmail = b.crypto.decrypt(probe.rows[0].email.substring(VAULT_PREFIX.length), newKeys);
    assert.match(firstEmail, /@example\.com$/);

    // The retained copy decrypts with old keys, bound to the data directory path
    var oldBackupKeys = readVaultKey(oldDir);
    assert.ok(oldBackupKeys);
    var oldProbe = decryptLiveDb(oldDir, oldBackupKeys, dataDir);
    assert.ok(oldProbe.rows.length > 0);

    // The documented post-rotation check passes on the rotated directory
    var v = runVerify(dataDir, {});
    assert.strictEqual(v.status, 0, "verify exit: " + v.status + "\nstdout: " + v.stdout + "\nstderr: " + v.stderr);
    assert.match(v.stdout, /All sampled sealed columns decrypt cleanly/);

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

  it("AAD-bound (vault.aad:) cell survives rotation — re-sealed old→new root", function () {
    var dataDir = path.join(testRoot, "aad-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    var aadRowId = "u1";        // present in decryptLiveDb's first-5 sample
    var aadPlain = "user1@example.com";
    buildFixture(dataDir, oldKeys, { aadCell: { rowId: aadRowId } });

    var aadParts = aadPartsFor("users", "email", aadRowId);
    var oldRootJson = JSON.stringify(oldKeys, null, 2);

    // Capture the AAD cell's ciphertext BEFORE rotation. Confirm the fixture
    // really planted a vault.aad: cell that opens under the old root.
    var before = readRawCell(dataDir, oldKeys, "users", aadRowId, "email");
    assert.ok(b.vault.aad.isAadSealed(before), "fixture must plant a vault.aad: cell");
    assert.strictEqual(b.vault.aad.unsealRoot(before, aadParts, oldRootJson), aadPlain,
      "AAD cell must open under the OLD root before rotation");

    // (1) Rotation succeeds. rotate self-verifies AAD cells under the new root
    // (verify() in rotate.js) and would EXIT NON-ZERO if the cell could not be
    // re-sealed — so exit 0 already implies the AAD cell was handled.
    var r = runRotate(dataDir, {}, []);
    assert.strictEqual(r.status, 0, "rotate exit: " + r.status + "\nstdout: " + r.stdout + "\nstderr: " + r.stderr);

    var newKeys = readVaultKey(dataDir);
    assert.ok(newKeys);
    assert.notStrictEqual(newKeys.privateKey, oldKeys.privateKey, "new keys must be distinct");
    var newRootJson = JSON.stringify(newKeys, null, 2);

    // (2) Cell is still AAD-shaped AND its ciphertext bytes CHANGED — proving
    // it was actually re-encrypted, not passed through verbatim.
    var after = readRawCell(dataDir, newKeys, "users", aadRowId, "email");
    assert.ok(b.vault.aad.isAadSealed(after), "rotated cell must keep the vault.aad: prefix");
    assert.notStrictEqual(after, before, "AAD ciphertext must change — the cell was RE-SEALED, not copied through");

    // (3) Cell decrypts to the original plaintext under the NEW root.
    assert.strictEqual(b.vault.aad.unsealRoot(after, aadParts, newRootJson), aadPlain,
      "rotated AAD cell must open to the original plaintext under the NEW root");

    // (4) Cell does NOT decrypt under the OLD root (true rotation).
    assert.throws(function () {
      b.vault.aad.unsealRoot(after, aadParts, oldRootJson);
    }, /aead-mismatch|authentication failed/, "OLD root must not open the rotated AAD cell");

    // The .rotation-old-<ts>/ copy still holds the pre-rotation cell under the old root.
    var oldDir = findOldDir(dataDir);
    assert.ok(oldDir, ".rotation-old-<ts>/ should exist");
    var oldBackupKeys = readVaultKey(oldDir);
    var backupCell = readRawCell(oldDir, oldBackupKeys, "users", aadRowId, "email", dataDir);
    assert.strictEqual(backupCell, before, "backup must retain the original AAD ciphertext");
    assert.strictEqual(b.vault.aad.unsealRoot(backupCell, aadParts, JSON.stringify(oldBackupKeys, null, 2)), aadPlain);
  });

  it("--dry-run leaves data/ untouched and doesn't create .rotation-old-*", function () {
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

    assert.strictEqual(findOldDir(dataDir), null, "no .rotation-old-* should be created on dry run");
    assert.ok(!fs.existsSync(stagingDir(dataDir)), "staging dir cleaned up");
    assertNoSiblings(dataDir);
  });

  it("pre-flight refuses when a stale staging directory exists", function () {
    var dataDir = path.join(testRoot, "stale-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);
    fs.mkdirSync(stagingDir(dataDir));

    var r = runRotate(dataDir, {}, []);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /stale .*\.rotation-staging exists/);
  });

  it("pre-flight refuses when a swap marker exists", function () {
    var dataDir = path.join(testRoot, "marker-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);
    fs.writeFileSync(path.join(dataDir, DATA_DIR_INTERNAL.ROTATION_MARKER), "{}");

    var r = runRotate(dataDir, {}, []);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /a previous rotation stopped during its swap/);
  });

  it("refuses while a fresh server lease is in the data directory, and runs once it is stale", function () {
    var dataDir = path.join(testRoot, "lease-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);
    var leasePath = path.join(dataDir, DATA_DIR_INTERNAL.SERVER_LEASE);
    var lease = { kind: "server", pid: 4242, hostname: "other-container", token: "t",
      startedAt: new Date().toISOString(), heartbeatAt: new Date().toISOString() };
    fs.writeFileSync(leasePath, JSON.stringify(lease));
    var originalDbEnc = fs.readFileSync(path.join(dataDir, "hermitstash.db.enc"));

    var r = runRotate(dataDir, {}, []);
    assert.strictEqual(r.status, 1, "stdout: " + r.stdout + "\nstderr: " + r.stderr);
    assert.match(r.stderr, /a HermitStash server \(pid 4242 on other-container, last refreshed \d+s ago\) holds .*\.server-lease/);
    assert.strictEqual(Buffer.compare(fs.readFileSync(path.join(dataDir, "hermitstash.db.enc")), originalDbEnc), 0);
    assert.strictEqual(JSON.parse(fs.readFileSync(leasePath, "utf8")).token, "t", "the refused tool leaves the lease alone");

    lease.heartbeatAt = new Date(Date.now() - TIME.minutes(5)).toISOString();
    fs.writeFileSync(leasePath, JSON.stringify(lease));
    var r2 = runRotate(dataDir, {}, []);
    assert.strictEqual(r2.status, 0, "stdout: " + r2.stdout + "\nstderr: " + r2.stderr);
    assert.ok(!fs.existsSync(leasePath), "the tool took the stale lease over and deleted it when it exited");
    assert.ok(!fs.existsSync(path.join(findOldDir(dataDir), DATA_DIR_INTERNAL.SERVER_LEASE)),
      "the lease is not moved into the retained copy");
  });

  it("a second rotation does not carry the first rotation's retained copy", function () {
    var dataDir = path.join(testRoot, "twice-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);

    var r1 = runRotate(dataDir, {}, []);
    assert.strictEqual(r1.status, 0, "first rotate: " + r1.stderr);
    var firstOld = path.basename(findOldDir(dataDir));
    var keysAfterFirst = readVaultKey(dataDir);

    var r2 = runRotate(dataDir, {}, []);
    assert.strictEqual(r2.status, 0, "second rotate: " + r2.stderr);
    var oldDirs = fs.readdirSync(dataDir).filter(function (n) {
      return n.indexOf(DATA_DIR_INTERNAL.ROTATION_OLD_PREFIX) === 0;
    }).sort();
    assert.strictEqual(oldDirs.length, 2, "each rotation keeps its own retained copy: " + oldDirs.join(", "));
    var secondOld = oldDirs.filter(function (n) { return n !== firstOld; })[0];
    assert.ok(!fs.existsSync(path.join(dataDir, secondOld, firstOld)),
      "the first retained copy stays at the top of the data directory");
    assert.strictEqual(readVaultKey(path.join(dataDir, secondOld)).privateKey, keysAfterFirst.privateKey);
    assert.strictEqual(runVerify(dataDir, {}).status, 0);
  });
});

describe("vault-key-verify: server-written data directory", function () {

  it("passes on a data directory that has not been rotated", function () {
    var dataDir = path.join(testRoot, "verify-fresh-" + b.crypto.generateToken(3));
    buildFixture(dataDir, cryptoLib.generateEncryptionKeyPair());

    var r = runVerify(dataDir, {});
    assert.strictEqual(r.status, 0, "verify exit: " + r.status + "\nstdout: " + r.stdout + "\nstderr: " + r.stderr);
    assert.doesNotMatch(r.stderr, /corrupt/);
    var leftovers = fs.readdirSync(dataDir).filter(function (n) { return /^\.verify-.*\.db/.test(n); });
    assert.deepStrictEqual(leftovers, [], "the temporary plaintext copy is removed");
    assertNoSiblings(dataDir);
  });

  it("reports a database bound to a different data directory path", function () {
    var dataDir = path.join(testRoot, "verify-moved-" + b.crypto.generateToken(3));
    var fixture = buildFixture(dataDir, cryptoLib.generateEncryptionKeyPair());
    var plain = dbEncCodec.decryptDbEnc(fs.readFileSync(path.join(dataDir, "hermitstash.db.enc")), fixture.dbKey, dataDir);
    fs.writeFileSync(path.join(dataDir, "hermitstash.db.enc"),
      dbEncCodec.encryptDbEnc(plain, fixture.dbKey, "/app/data"));

    var r = runVerify(dataDir, {});
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /hermitstash\.db\.enc cannot be decrypted/);
    assert.match(r.stderr, /same HERMITSTASH_DATA_DIR the server uses/);
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

    // The .rotation-old-<ts>/ copy should still unwrap with the SAME passphrase and contain oldKeys
    var oldDir = findOldDir(dataDir);
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
    var oldDir = findOldDir(dataDir);
    var originalKeysFromBackup = await unwrapVaultKey(oldDir, oldPw);
    assert.strictEqual(originalKeysFromBackup.privateKey, oldKeys.privateKey);

    // The verify tool reads the rotated directory with the NEW passphrase
    var v = runVerify(dataDir, { VAULT_PASSPHRASE: newPw });
    assert.strictEqual(v.status, 0, "verify exit: " + v.status + "\nstdout: " + v.stdout + "\nstderr: " + v.stderr);
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
    assert.match(r.stderr, /current passphrase rejected: /);
    // data/ must be untouched
    assert.strictEqual(Buffer.compare(fs.readFileSync(path.join(dataDir, "vault.key.sealed")), originalSealed), 0);
    assert.strictEqual(findOldDir(dataDir), null, "no .rotation-old-* on failure");
    assert.ok(!fs.existsSync(stagingDir(dataDir)), "staging cleaned up on failure");
  });

  it("reports a truncated vault.key.sealed as unreadable, not as a rejected passphrase", async function () {
    var dataDir = path.join(testRoot, "trunc-" + b.crypto.generateToken(3));
    var oldKeys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, oldKeys);
    fs.unlinkSync(path.join(dataDir, "vault.key"));
    var pw = "the correct one";
    await wrapVaultKey(dataDir, oldKeys, pw);
    var sealedPath = path.join(dataDir, "vault.key.sealed");
    var truncated = fs.readFileSync(sealedPath).subarray(0, 30);
    fs.writeFileSync(sealedPath, truncated);

    var r = runRotate(dataDir, { VAULT_PASSPHRASE_OLD: pw, VAULT_PASSPHRASE_NEW: pw }, []);
    assert.notStrictEqual(r.status, 0, "must fail on a truncated sealed file");
    assert.match(r.stderr, /vault\.key\.sealed could not be unwrapped: /);
    assert.match(r.stderr, /The passphrase was not checked\./);
    assert.doesNotMatch(r.stderr, /passphrase rejected/);
    assert.strictEqual(Buffer.compare(fs.readFileSync(sealedPath), truncated), 0, "vault.key.sealed is unchanged");
    assert.strictEqual(findOldDir(dataDir), null, "no .rotation-old-* on failure");
    assert.ok(!fs.existsSync(stagingDir(dataDir)), "no staging directory is left");
  });
});

function runVerify(dataDir, env) {
  var fullEnv = Object.assign({}, process.env, {
    HERMITSTASH_DATA_DIR: dataDir,
    ARGON2_FAST: "1",
  }, env || {});
  return spawnSync("node", ["scripts/vault-key-verify.js"], {
    cwd: REPO_ROOT, env: fullEnv, encoding: "utf8", timeout: 90000,
  });
}

describe("vault-key-verify: wrapped vault key that cannot be unsealed", function () {

  it("reports a wrong passphrase as rejected", async function () {
    var dataDir = path.join(testRoot, "verify-badpw-" + b.crypto.generateToken(3));
    var keys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, keys);
    fs.unlinkSync(path.join(dataDir, "vault.key"));
    await wrapVaultKey(dataDir, keys, "the correct one");

    var r = runVerify(dataDir, { VAULT_PASSPHRASE: "THE WRONG ONE" });
    assert.strictEqual(r.status, 1, "exit: " + r.status + "\nstderr: " + r.stderr);
    assert.match(r.stderr, /ERROR: passphrase rejected: /);
  });

  it("reports a truncated vault.key.sealed as unreadable, not as a rejected passphrase", async function () {
    var dataDir = path.join(testRoot, "verify-trunc-" + b.crypto.generateToken(3));
    var keys = cryptoLib.generateEncryptionKeyPair();
    buildFixture(dataDir, keys);
    fs.unlinkSync(path.join(dataDir, "vault.key"));
    var pw = "the correct one";
    await wrapVaultKey(dataDir, keys, pw);
    var sealedPath = path.join(dataDir, "vault.key.sealed");
    fs.writeFileSync(sealedPath, fs.readFileSync(sealedPath).subarray(0, 30));

    var r = runVerify(dataDir, { VAULT_PASSPHRASE: pw });
    assert.strictEqual(r.status, 1, "exit: " + r.status + "\nstderr: " + r.stderr);
    assert.match(r.stderr, /ERROR: vault\.key\.sealed could not be unwrapped: /);
    assert.match(r.stderr, /The passphrase was not checked\./);
    assert.doesNotMatch(r.stderr, /passphrase rejected/);
  });
});
