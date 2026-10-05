var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var os = require("os");
var crypto = require("crypto");
var { DatabaseSync } = require("node:sqlite");
var b = require("../../lib/vendor/blamejs");

// Use an isolated HERMITSTASH_DB_PATH so required lib modules load without
// touching any shared data/. The vault-rotate module itself is pure wrt its
// db input, but lib/field-crypto transitively requires lib/vault which reads
// process.env at load time.
var testId = b.crypto.generateToken(4);
var testHarnessDir = path.join(os.tmpdir(), "hermitstash-vrtest-" + testId);
process.env.HERMITSTASH_DB_PATH = path.join(testHarnessDir, "harness.db");
fs.mkdirSync(testHarnessDir, { recursive: true });

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

b = require("../../lib/vendor/blamejs");
var C = require("../../lib/constants");
var fieldCrypto = require("../../lib/field-crypto");
var vault = require("../../lib/vault");
var rotationInventory = require("../../lib/rotation-inventory");
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
};
var vaultRotate = {
  validateSchemaMatch: function (db, opts) {
    return b.vaultRotate.validateSchemaMatch(db, Object.assign({
      infraColumns: C.ROTATION_INFRA_COLUMNS,
      tables:       FIELD_SCHEMA_TABLES,
    }, opts || {}));
  },
  formatValidationResult: b.vaultRotate.formatValidationResult,
  // This runs the same inventory and symlink step as scripts/vault-key-rotate.js.
  rotateDataDirectory: async function (opts) {
    var paths = Object.assign({}, ROTATION_PATHS, opts.paths || {});
    var carried = rotationInventory.carriedEntries(opts.dataDir, paths);
    paths.verbatimFiles = carried.verbatimFiles;
    paths.verbatimDirs = carried.verbatimDirs;
    var result = await b.vaultRotate.rotate(Object.assign({}, opts, {
      paths: paths,
      // HS uses none of the agent/dsr/archive-tenant external AAD stores that
      // blamejs 0.15.x now requires acknowledging before rotation; production
      // passes the same flag (scripts/vault-key-rotate.js).
      externalAadResealed: true,
    }));
    rotationInventory.recreateSymlinks(opts.stagingDir, carried.symlinks);
    return result;
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
      // Guarded like the unlink below it: close() runs first, so an unguarded
      // throw here both replaced the assertion error and skipped the unlink.
      try { h.db.close(); } catch (_e) { /* best effort */ }
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
      // Guarded like the unlink below it: close() runs first, so an unguarded
      // throw here both replaced the assertion error and skipped the unlink.
      try { h.db.close(); } catch (_e) { /* best effort */ }
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
      // Guarded like the unlink below it: close() runs first, so an unguarded
      // throw here both replaced the assertion error and skipped the unlink.
      try { h.db.close(); } catch (_e) { /* best effort */ }
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
      // Guarded like the unlink below it: close() runs first, so an unguarded
      // throw here both replaced the assertion error and skipped the unlink.
      try { h.db.close(); } catch (_e) { /* best effort */ }
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

  it("carries every file the rotation does not rewrite into the rotated copy", async function () {
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();
    var fix = buildFixtureDataDir(oldKeys, 1, 1);
    var stagingDir = fix.dir + ".staging";
    // The swap replaces the data directory with the rotated copy, so each of
    // these would be lost if the copy left it out.
    var carried = {
      "ca.crt": "sync CA cert", "ca.key": "sync CA key", "revocations.json": "[]", "ca.crl": "crl",
      "ca.crl-number": "7\n", "ca.crl-number.published": "7\n", "issuance.json": "[]",
      "revoked-generation": "2", "ca.algorithm": "ML-DSA-87", "ca-migration.json": "{}",
      "ca-browser.crt": "browser CA cert", "ca-browser-revocations.json": "[]",
      "ca-browser.crl-number": "3\n", "audit-sign.key": "signing key",
      "audit-schema-context.marker": "applied", "derived-hash-keyed.marker": "{}",
      "custom-logos/logo.png": "png", "stash-logos/s1/logo.png": "png",
      "audit-archives/audit-1.json": "{}", "tls/fullchain.pem": "chain",
    };
    var transient = ["ca.crt.lock", "hermitstash.db.enc.tmp-0123456789abcdef", "hermitstash-0a1b.db",
      "vault.key.sealed.tmp"];
    Object.keys(carried).forEach(function (rel) {
      fs.mkdirSync(path.dirname(path.join(fix.dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(fix.dir, rel), carried[rel]);
    });
    transient.forEach(function (rel) { fs.writeFileSync(path.join(fix.dir, rel), "x"); });
    fs.writeFileSync(path.join(fix.dir, "tls", "privkey.pem.sealed"),
      VAULT_PREFIX + b.crypto.encrypt("TLS PRIVATE KEY", oldKeys));

    try {
      await vaultRotate.rotateDataDirectory({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: fix.dir, stagingDir: stagingDir,
        mode: "plaintext",
      });
      Object.keys(carried).forEach(function (rel) {
        var p = path.join(stagingDir, rel);
        assert.ok(fs.existsSync(p), rel + " is in the rotated copy");
        assert.strictEqual(fs.readFileSync(p, "utf8"), carried[rel], rel + " is carried unchanged");
      });
      transient.forEach(function (rel) {
        assert.ok(!fs.existsSync(path.join(stagingDir, rel)), rel + " is not carried");
      });
      var sealed = fs.readFileSync(path.join(stagingDir, "tls", "privkey.pem.sealed"), "utf8");
      assert.strictEqual(b.crypto.decrypt(sealed.substring(VAULT_PREFIX.length), newKeys), "TLS PRIVATE KEY",
        "the sealed TLS key in a carried directory is re-sealed under the new keypair");
    } finally {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch {}
      cleanupFixture(fix);
    }
  });

  it("recreates a symbolic link in the rotated copy", async function (t) {
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();
    var fix = buildFixtureDataDir(oldKeys, 1, 0);
    var stagingDir = fix.dir + ".staging";
    fs.mkdirSync(path.join(fix.dir, "tls"));
    fs.writeFileSync(path.join(fix.dir, "tls", "fullchain.pem"), "chain");

    try {
      try {
        fs.symlinkSync("fullchain.pem", path.join(fix.dir, "tls", "cert.pem"));
      } catch (e) {
        if (e.code === "EPERM") { t.skip("this host does not allow creating symbolic links"); return; }
        throw e;
      }
      await vaultRotate.rotateDataDirectory({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: fix.dir, stagingDir: stagingDir,
        mode: "plaintext",
      });
      var link = path.join(stagingDir, "tls", "cert.pem");
      assert.ok(fs.lstatSync(link).isSymbolicLink(), "tls/cert.pem is a symbolic link in the rotated copy");
      assert.strictEqual(fs.readlinkSync(link), "fullchain.pem");
      assert.strictEqual(fs.readFileSync(path.join(stagingDir, "tls", "fullchain.pem"), "utf8"), "chain");
    } finally {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch {}
      cleanupFixture(fix);
    }
  });

  it("writes a rewritten file that was a symbolic link as a regular file", async function (t) {
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();
    var fix = buildFixtureDataDir(oldKeys, 1, 0);
    var stagingDir = fix.dir + ".staging";
    var keysDir = fix.dir + ".keys";
    fs.mkdirSync(keysDir);
    fs.renameSync(path.join(fix.dir, "vault.key"), path.join(keysDir, "vault.key"));

    try {
      try {
        fs.symlinkSync(path.join(keysDir, "vault.key"), path.join(fix.dir, "vault.key"));
      } catch (e) {
        if (e.code === "EPERM") { t.skip("this host does not allow creating symbolic links"); return; }
        throw e;
      }
      await vaultRotate.rotateDataDirectory({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: fix.dir, stagingDir: stagingDir,
        mode: "plaintext",
      });
      var staged = path.join(stagingDir, "vault.key");
      assert.ok(!fs.lstatSync(staged).isSymbolicLink(), "vault.key is a regular file in the rotated copy");
      assert.deepStrictEqual(JSON.parse(fs.readFileSync(staged, "utf8")), JSON.parse(JSON.stringify(newKeys)),
        "vault.key in the rotated copy holds the new keypair");
    } finally {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch {}
      try { fs.rmSync(keysDir, { recursive: true, force: true }); } catch {}
      cleanupFixture(fix);
    }
  });

  it("copies a linked directory that holds a re-sealed file into a real directory", async function (t) {
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();
    var fix = buildFixtureDataDir(oldKeys, 1, 0);
    var stagingDir = fix.dir + ".staging";
    var tlsTarget = fix.dir + ".tls";
    fs.mkdirSync(tlsTarget);
    fs.writeFileSync(path.join(tlsTarget, "fullchain.pem"), "chain");
    fs.writeFileSync(path.join(tlsTarget, "privkey.pem.sealed"),
      VAULT_PREFIX + b.crypto.encrypt("TLS PRIVATE KEY", oldKeys));

    try {
      try {
        fs.symlinkSync(tlsTarget, path.join(fix.dir, "tls"), "dir");
      } catch (e) {
        if (e.code === "EPERM") { t.skip("this host does not allow creating symbolic links"); return; }
        throw e;
      }
      await vaultRotate.rotateDataDirectory({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: fix.dir, stagingDir: stagingDir,
        mode: "plaintext",
      });
      var stagedTls = path.join(stagingDir, "tls");
      assert.ok(fs.lstatSync(stagedTls).isDirectory(), "tls is a real directory in the rotated copy");
      assert.strictEqual(fs.readFileSync(path.join(stagedTls, "fullchain.pem"), "utf8"), "chain");
      var sealed = fs.readFileSync(path.join(stagedTls, "privkey.pem.sealed"), "utf8");
      assert.strictEqual(b.crypto.decrypt(sealed.substring(VAULT_PREFIX.length), newKeys), "TLS PRIVATE KEY",
        "the sealed TLS key is re-sealed under the new keypair");
      var original = fs.readFileSync(path.join(tlsTarget, "privkey.pem.sealed"), "utf8");
      assert.strictEqual(b.crypto.decrypt(original.substring(VAULT_PREFIX.length), oldKeys), "TLS PRIVATE KEY",
        "the link target outside the data directory is left as it was");
    } finally {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch {}
      try { fs.rmSync(tlsTarget, { recursive: true, force: true }); } catch {}
      cleanupFixture(fix);
    }
  });

  it("rotation is real: staging sealed values decrypt with newKeys, fail with oldKeys", async function () {
    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();
    var fix = buildFixtureDataDir(oldKeys, 5, 0);
    var stagingDir = fix.dir + ".staging";

    try {
      var result = await vaultRotate.rotateDataDirectory({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: fix.dir, stagingDir: stagingDir,
        mode: "plaintext",
      });

      // The rotation's own verify decrypts every staged sealed cell under the NEW
      // keys (ok / no failures) and asserts NONE still decrypt under the OLD keys
      // (no regressions) — the AAD-aware equivalent of "decrypt with newKeys, fail
      // with oldKeys". A raw b.crypto.decrypt can't verify these: registered
      // columns AND db.key.enc are re-sealed vault/AAD-bound, so they need the
      // row AAD, which only the framework verify supplies.
      assert.ok(result.verifyResult.ok, "staged sealed values decrypt under the new keys");
      assert.strictEqual(result.verifyResult.failures.length, 0, "no decrypt failures under the new keys");
      assert.strictEqual(result.verifyResult.regressions.length, 0, "no value still decrypts under the retired keys");
      assert.ok(result.totalRowsProcessed > 0, "rotation actually processed rows");
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
      // Guarded like the unlink below it: close() runs first, so an unguarded
      // throw here both replaced the assertion error and skipped the unlink.
      try { h.db.close(); } catch (_e) { /* best effort */ }
      try { fs.unlinkSync(h.path); } catch {}
    }
  });
});

describe("vault-key rotation relies on the b.atomicFile.copyDirRecursive contract", function () {
  it("copyDirRecursive copies nested regular files byte for byte and leaves symbolic links out", function (t) {
    // b.vaultRotate.rotate copies each verbatimDirs entry with this primitive.
    var src = path.join(testHarnessDir, "copy-src-" + b.crypto.generateToken(3));
    var dest = src + ".copy";
    fs.mkdirSync(path.join(src, "s1"), { recursive: true });
    fs.writeFileSync(path.join(src, "logo.png"), "png");
    fs.writeFileSync(path.join(src, "s1", "logo.png"), "nested png");
    var linked = true;
    try { fs.symlinkSync("logo.png", path.join(src, "link.png")); }
    catch (e) { if (e.code !== "EPERM") throw e; linked = false; }
    try {
      assert.deepStrictEqual(b.atomicFile.copyDirRecursive(src, dest), { fileCount: 2, byteCount: 13 });
      assert.strictEqual(fs.readFileSync(path.join(dest, "logo.png"), "utf8"), "png");
      assert.strictEqual(fs.readFileSync(path.join(dest, "s1", "logo.png"), "utf8"), "nested png");
      if (linked) {
        assert.strictEqual(fs.readdirSync(dest).indexOf("link.png"), -1,
          "carriedEntries lists a directory that holds a link file by file because the copy leaves the link out");
      } else {
        t.diagnostic("this host does not allow creating symbolic links, so the link case did not run");
      }
    } finally {
      fs.rmSync(src, { recursive: true, force: true });
      fs.rmSync(dest, { recursive: true, force: true });
    }
  });
});
