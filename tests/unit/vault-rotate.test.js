var { describe, it, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var crypto = require("crypto");
var { DatabaseSync } = require("node:sqlite");
var b = require("../../lib/vendor/blamejs");

// Use an isolated HERMITSTASH_DB_PATH so required lib modules load without
// touching any shared data/. The vault-rotate module itself is pure wrt its
// db input, but lib/field-crypto transitively requires lib/vault which reads
// process.env at load time.
var testId = b.crypto.generateToken(4);
var testHarnessDir = path.join(__dirname, "..", "..", "data", "vrtest-" + testId);
process.env.HERMITSTASH_DB_PATH = path.join(testHarnessDir, "harness.db");
fs.mkdirSync(testHarnessDir, { recursive: true });

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

b = require("../../lib/vendor/blamejs");
var C = require("../../lib/constants");
var fieldCrypto = require("../../lib/field-crypto");
var { VAULT_PREFIX } = C;

// Populate b.cryptoField with HS's FIELD_SCHEMA before any
// b.vaultRotate call — its schema walker reads from b.cryptoField.
fieldCrypto.registerWithBlamejs();

// Adapter shims so the existing test bodies (written against HS's
// prior wrapper) can drive b.vaultRotate.* without rewriting every
// assertion. New tests should call b.vaultRotate straight.
// validateSchemaMatch defaults to the full FIELD_SCHEMA table list so
// missing-table warnings still fire (matches HS's prior wrapper).
var FIELD_SCHEMA_TABLES = Object.keys(fieldCrypto.FIELD_SCHEMA);
var ROTATION_PATHS = {
  encryptedDb:      "hermitstash.db.enc",
  dbKeySealed:      "db.key.enc",
  vaultKeyPlain:    "vault.key",
  vaultKeySealed:   "vault.key.sealed",
  additionalSealed: C.ROTATION_SEALED_FILES.filter(function (e) { return e.relativePath !== "db.key.enc"; }),
  verbatimFiles:    C.ROTATION_VERBATIM_FILES,
  verbatimDirs:     C.ROTATION_VERBATIM_DIRS,
};
var vaultRotate = {
  validateSchemaMatch: function (db, opts) {
    return b.vaultRotate.validateSchemaMatch(db, Object.assign({
      infraColumns: C.ROTATION_INFRA_COLUMNS,
      tables:       FIELD_SCHEMA_TABLES,
    }, opts || {}));
  },
  formatValidationResult: b.vaultRotate.formatValidationResult,
  rotateDataDirectory: function (opts) {
    return b.vaultRotate.rotate(Object.assign({}, opts, {
      paths: Object.assign({}, ROTATION_PATHS, opts.paths || {}),
    }));
  },
  verifyRotation: function (keys, db, opts) {
    return b.vaultRotate.verify(Object.assign({ keys: keys, db: db }, opts || {}));
  },
};

after(function () {
  try { fs.rmSync(testHarnessDir, { recursive: true, force: true }); } catch {}
  try { fs.unlinkSync(process.env.HERMITSTASH_DB_PATH); } catch {}
  try { fs.unlinkSync(process.env.HERMITSTASH_DB_PATH + "-shm"); } catch {}
  try { fs.unlinkSync(process.env.HERMITSTASH_DB_PATH + "-wal"); } catch {}
});

function newDb() {
  var dbPath = path.join(testHarnessDir, "case-" + b.crypto.generateToken(3) + ".db");
  return { path: dbPath, db: new DatabaseSync(dbPath) };
}

// Seal under blamejs's 0xE2 envelope (b.crypto.encrypt). lib/crypto's
// encrypt still emits 0xE1 (legacy) which b.vaultRotate.rotate rejects.
function sealWith(keys, plaintext) {
  return VAULT_PREFIX + b.crypto.encrypt(plaintext, keys);
}

// =====================================================================
// Part 1 — validateSchemaMatch
// =====================================================================

describe("vault-rotate.validateSchemaMatch", function () {

  it("returns 0 errors on a clean fixture with a subset of FIELD_SCHEMA tables", function () {
    var h = newDb();
    try {
      h.db.prepare(
        "CREATE TABLE users (" +
        "  _id TEXT PRIMARY KEY, email TEXT, displayName TEXT, avatar TEXT, googleId TEXT," +
        "  passwordHash TEXT, authType TEXT, vaultEnabled TEXT, vaultPublicKey TEXT," +
        "  vaultStealth TEXT, vaultMode TEXT, vaultSeed TEXT, totpLastStep TEXT," +
        "  totpSecret TEXT, totpEnabled TEXT, totpBackupCodes TEXT, emailHash TEXT," +
        "  status TEXT, role TEXT, failedLoginAttempts INTEGER, lockedUntil TEXT," +
        "  createdAt TEXT, lastLogin TEXT, data TEXT" +
        ")"
      ).run();
      var result = vaultRotate.validateSchemaMatch(h.db);
      assert.strictEqual(result.errors.length, 0, JSON.stringify(result.errors));
      // Warnings expected for OTHER tables not in this minimal fixture
      var missingTableWarn = result.warnings.filter(function (w) { return w.kind === "table_missing"; });
      assert.ok(missingTableWarn.length > 0, "expected missing-table warnings");
    } finally {
      h.db.close();
      try { fs.unlinkSync(h.path); } catch {}
    }
  });

  it("FATAL: vault:-prefixed value in a column not in FIELD_SCHEMA.seal triggers drift error", function () {
    var h = newDb();
    try {
      h.db.prepare(
        "CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, surpriseColumn TEXT, data TEXT)"
      ).run();
      var oldKeys = b.crypto.generateEncryptionKeyPair();
      h.db.prepare("INSERT INTO users (_id, email, surpriseColumn) VALUES (?, ?, ?)").run(
        "u1", "plain", sealWith(oldKeys, "secret")
      );
      var result = vaultRotate.validateSchemaMatch(h.db);
      var driftErrs = result.errors.filter(function (e) { return e.kind === "drift"; });
      assert.strictEqual(driftErrs.length, 1);
      assert.strictEqual(driftErrs[0].column, "surpriseColumn");
      assert.match(driftErrs[0].message, /encrypted under the OLD key/);
    } finally {
      h.db.close();
      try { fs.unlinkSync(h.path); } catch {}
    }
  });

  it("NO drift false-positive on vault:-prefixed values inside the `data` overflow JSON column", function () {
    var h = newDb();
    try {
      h.db.prepare("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, data TEXT)").run();
      var oldKeys = b.crypto.generateEncryptionKeyPair();
      h.db.prepare("INSERT INTO users (_id, email, data) VALUES (?, ?, ?)").run(
        "u1", "plain", JSON.stringify({ someOverflowField: sealWith(oldKeys, "ok") })
      );
      var result = vaultRotate.validateSchemaMatch(h.db);
      assert.strictEqual(result.errors.length, 0, "data overflow must never trigger drift");
    } finally {
      h.db.close();
      try { fs.unlinkSync(h.path); } catch {}
    }
  });

  it("warns (non-fatal) when a FIELD_SCHEMA.seal column is absent from the live schema", function () {
    var h = newDb();
    try {
      // users: exists, but missing the `displayName` column declared in FIELD_SCHEMA
      h.db.prepare("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, data TEXT)").run();
      var result = vaultRotate.validateSchemaMatch(h.db);
      var missingCol = result.warnings.filter(function (w) {
        return w.kind === "sealed_col_missing" && w.column === "displayName";
      });
      assert.strictEqual(missingCol.length, 1);
      assert.strictEqual(result.errors.length, 0);
    } finally {
      h.db.close();
      try { fs.unlinkSync(h.path); } catch {}
    }
  });
});

// =====================================================================
// Part 2 — rotateDataDirectory
// =====================================================================

describe("vault-rotate.rotateDataDirectory", function () {

  function buildFixtureDataDir(oldKeys, userCount, auditCount) {
    var dir = path.join(testHarnessDir, "fixture-" + b.crypto.generateToken(4));
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    fs.writeFileSync(path.join(dir, "vault.key"), JSON.stringify(oldKeys), { mode: 0o600 });

    var dbKey = b.crypto.generateBytes(32);
    fs.writeFileSync(path.join(dir, "db.key.enc"),
      VAULT_PREFIX + b.crypto.encrypt(dbKey.toString("base64"), oldKeys), { mode: 0o600 });

    var tmpDb = path.join(dir, "build.db");
    var db = new DatabaseSync(tmpDb);
    db.prepare("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, displayName TEXT, status TEXT, createdAt TEXT, data TEXT)").run();
    db.prepare("CREATE TABLE audit_log (_id TEXT PRIMARY KEY, action TEXT, details TEXT, createdAt TEXT, data TEXT)").run();

    for (var i = 0; i < userCount; i++) {
      db.prepare("INSERT INTO users (_id, email, displayName, status, createdAt, data) VALUES (?, ?, ?, ?, ?, ?)").run(
        "u" + i,
        sealWith(oldKeys, "u" + i + "@ex.com"),
        sealWith(oldKeys, "User " + i),
        "active",
        new Date().toISOString(),
        JSON.stringify({ vaultEnabled: sealWith(oldKeys, "true") }) // overflow with sealed value
      );
    }
    for (var j = 0; j < auditCount; j++) {
      db.prepare("INSERT INTO audit_log (_id, action, details, createdAt) VALUES (?, ?, ?, ?)").run(
        "a" + j,
        sealWith(oldKeys, "login"),
        sealWith(oldKeys, "event " + j),
        new Date().toISOString()
      );
    }
    db.close();

    fs.writeFileSync(path.join(dir, "hermitstash.db.enc"),
      b.crypto.encryptPacked(fs.readFileSync(tmpDb), dbKey));
    fs.unlinkSync(tmpDb);

    return { dir: dir, dbKey: dbKey };
  }

  function cleanupFixture(fix) {
    try { fs.rmSync(fix.dir, { recursive: true, force: true }); } catch {}
  }

  it("rotates a synthetic fixture end-to-end (10 users + 20 audit rows)", async function () {
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();
    var fix = buildFixtureDataDir(oldKeys, 10, 20);
    var stagingDir = fix.dir + ".staging";

    try {
      var result = await vaultRotate.rotateDataDirectory({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: fix.dir, stagingDir: stagingDir,
        mode: "plaintext",
      });
      assert.ok(result.totalRowsProcessed > 0);
      assert.ok(result.verifyResult.ok);
      assert.strictEqual(result.verifyResult.failures.length, 0);
      assert.strictEqual(result.verifyResult.regressions.length, 0);

      // Original data dir untouched
      assert.ok(fs.existsSync(path.join(fix.dir, "hermitstash.db.enc")));

      // Staging is complete
      assert.ok(fs.existsSync(path.join(stagingDir, "vault.key")));
      assert.ok(fs.existsSync(path.join(stagingDir, "db.key.enc")));
      assert.ok(fs.existsSync(path.join(stagingDir, "hermitstash.db.enc")));
    } finally {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch {}
      cleanupFixture(fix);
    }
  });

  it("rotation is real: staging sealed values decrypt with newKeys, fail with oldKeys", async function () {
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();
    var fix = buildFixtureDataDir(oldKeys, 5, 0);
    var stagingDir = fix.dir + ".staging";

    try {
      await vaultRotate.rotateDataDirectory({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: fix.dir, stagingDir: stagingDir,
        mode: "plaintext",
      });

      // Read staged DB, verify with both key sets
      var newDbKeySealed = fs.readFileSync(path.join(stagingDir, "db.key.enc"), "utf8").trim();
      var newDbKey = Buffer.from(
        b.crypto.decrypt(newDbKeySealed.substring(VAULT_PREFIX.length), newKeys),
        "base64"
      );
      var plain = b.crypto.decryptPacked(
        fs.readFileSync(path.join(stagingDir, "hermitstash.db.enc")),
        newDbKey
      );
      var tmpDb = path.join(stagingDir, "verify-unit.db");
      fs.writeFileSync(tmpDb, plain);
      var db = new DatabaseSync(tmpDb);
      var row = db.prepare("SELECT * FROM users LIMIT 1").get();
      db.close();
      try { fs.unlinkSync(tmpDb); } catch {}

      var email = row.email;
      var payload = email.substring(VAULT_PREFIX.length);
      // newKeys succeeds
      var plainEmail = b.crypto.decrypt(payload, newKeys);
      assert.match(plainEmail, /@ex\.com$/);
      // oldKeys fails
      assert.throws(function () { b.crypto.decrypt(payload, oldKeys); });

      // db.key.enc under OLD keys must also fail
      assert.throws(function () {
        b.crypto.decrypt(newDbKeySealed.substring(VAULT_PREFIX.length), oldKeys);
      });
    } finally {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch {}
      cleanupFixture(fix);
    }
  });

  it("rotation preserves the underlying DB file encryption key (32-byte value)", async function () {
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();
    var fix = buildFixtureDataDir(oldKeys, 3, 0);
    var stagingDir = fix.dir + ".staging";

    try {
      await vaultRotate.rotateDataDirectory({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: fix.dir, stagingDir: stagingDir,
        mode: "plaintext",
      });

      var newSealed = fs.readFileSync(path.join(stagingDir, "db.key.enc"), "utf8").trim();
      var newDbKey = Buffer.from(
        b.crypto.decrypt(newSealed.substring(VAULT_PREFIX.length), newKeys),
        "base64"
      );
      assert.strictEqual(Buffer.compare(newDbKey, fix.dbKey), 0, "dbKey value must survive rotation unchanged");
    } finally {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch {}
      cleanupFixture(fix);
    }
  });

  it("refuses when stagingDir already exists", async function () {
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();
    var fix = buildFixtureDataDir(oldKeys, 1, 0);
    var stagingDir = fix.dir + ".staging";
    fs.mkdirSync(stagingDir);

    try {
      await assert.rejects(
        vaultRotate.rotateDataDirectory({
          oldKeys: oldKeys, newKeys: newKeys,
          dataDir: fix.dir, stagingDir: stagingDir,
          mode: "plaintext",
        }),
        /stagingDir already exists/
      );
    } finally {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch {}
      cleanupFixture(fix);
    }
  });

  it("round-trip verification correctly detects a stuck-with-old-keys regression", function () {
    // We don't actually have a bug to exploit, but we can construct a DB where
    // NO rotation happened and pass it to verifyRotation with oldKeys flag.
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var h = newDb();
    try {
      h.db.prepare("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, displayName TEXT, data TEXT)").run();
      for (var i = 0; i < 10; i++) {
        h.db.prepare("INSERT INTO users (_id, email, displayName) VALUES (?, ?, ?)").run(
          "u" + i, sealWith(oldKeys, "u" + i + "@x"), sealWith(oldKeys, "U " + i)
        );
      }
      // Verify with oldKeys as BOTH current and old — should detect at least one row
      // where oldKeys still decrypts (i.e. regression).
      var result = vaultRotate.verifyRotation(oldKeys, h.db, { oldKeys: oldKeys });
      assert.strictEqual(result.ok, false);
      assert.ok(result.regressions.length > 0, "expected regression detection");
    } finally {
      h.db.close();
      try { fs.unlinkSync(h.path); } catch {}
    }
  });
});
