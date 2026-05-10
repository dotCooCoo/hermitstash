"use strict";
/**
 * b.db.init — v0.8.58 additions:
 *   - opts.frameworkTables: false  (skip provisioning audit_log/consent_log)
 *   - opts.auditSigning: false     (skip audit-signing-key bootstrap)
 *   - opts.encryptedDbPath / opts.encryptedDbName / opts.dbKeyPath
 *   - b.db.snapshot()              (in-memory encrypted Buffer)
 */

var helpers = require("../helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;

async function _resetState() {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  process.env.BLAMEJS_VAULT_PASSPHRASE = "test-passphrase-suite";
  process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = "test-passphrase-suite";
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
}

async function testFrameworkTablesOff() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fto-"));
  await _resetState();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  await b.db.init({
    dataDir: tmpDir,
    atRest:  "plain",
    frameworkTables: false,
    schema:  [{ name: "audit_log", columns: { _id: "TEXT PRIMARY KEY", payload: "TEXT" } }],
  });
  check("frameworkTables: false — operator's own audit_log accepted",
    typeof b.db.from === "function");
  // The operator's audit_log is now writable — the framework's
  // append-only triggers were skipped under frameworkTables: false.
  b.db.from("audit_log").insertOne({ _id: "x1", payload: "operator-controlled" });
  b.db.from("audit_log").where({ _id: "x1" }).updateOne({ payload: "mutated" });
  check("frameworkTables: false — operator can UPDATE own audit_log",
    b.db.from("audit_log").where({ _id: "x1" }).first().payload === "mutated");
  await b.db.close();
}

async function testAuditSigningOff() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aso-"));
  await _resetState();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  await b.db.init({
    dataDir:       tmpDir,
    atRest:        "plain",
    auditSigning:  false,
    schema:        [{ name: "things", columns: { _id: "TEXT PRIMARY KEY" } }],
  });
  check("auditSigning: false — db.init succeeds with no signing key",
    typeof b.db.from === "function");
  // Audit-signing keypair MUST NOT exist on disk.
  check("auditSigning: false — no audit-sign keypair file written",
    !fs.existsSync(path.join(tmpDir, "audit-sign.key")));
  await b.db.close();
}

async function testEncryptedDbNameOverride() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "enc-"));
  await _resetState();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  await b.db.init({
    dataDir:           tmpDir,
    tmpDir:            path.join(tmpDir, "tmpfs"),
    encryptedDbName:   "custom.enc",
    frameworkTables:   false,
    auditSigning:      false,
    schema:            [{ name: "x", columns: { _id: "TEXT PRIMARY KEY" } }],
  });
  await b.db.flushToDisk();
  check("encryptedDbName: custom.enc landed at <dataDir>/custom.enc",
    fs.existsSync(path.join(tmpDir, "custom.enc")));
  check("default db.enc NOT created when name override is in effect",
    !fs.existsSync(path.join(tmpDir, "db.enc")));
  await b.db.close();
}

async function testDbKeyPathOverride() {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "dkp-d-"));
  var keyDir  = fs.mkdtempSync(path.join(os.tmpdir(), "dkp-k-"));
  var customKeyPath = path.join(keyDir, "kms.fronted.key.enc");
  await _resetState();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  await b.db.init({
    dataDir:           dataDir,
    tmpDir:            path.join(dataDir, "tmpfs"),
    dbKeyPath:         customKeyPath,
    frameworkTables:   false,
    auditSigning:      false,
    schema:            [{ name: "x", columns: { _id: "TEXT PRIMARY KEY" } }],
  });
  check("dbKeyPath: key file lands at the operator-supplied path",
    fs.existsSync(customKeyPath));
  check("default db.key.enc under dataDir is NOT created",
    !fs.existsSync(path.join(dataDir, "db.key.enc")));
  await b.db.close();
}

async function testSnapshot() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "snap-"));
  await _resetState();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  await b.db.init({
    dataDir:          tmpDir,
    tmpDir:           path.join(tmpDir, "tmpfs"),
    frameworkTables:  false,
    auditSigning:     false,
    schema:           [{ name: "ledger", columns: { _id: "TEXT PRIMARY KEY", balance: "INTEGER" } }],
  });
  b.db.from("ledger").insertOne({ _id: "acct1", balance: 100 });
  var snap = b.db.snapshot();
  check("snapshot returns a Buffer",       Buffer.isBuffer(snap));
  check("snapshot is non-empty",           snap.length > 0);
  // Encrypted-mode snapshot should NOT match a raw SQLite header
  // (`SQLite format 3\0`) — confirm the envelope is applied.
  check("snapshot bytes are encrypted (no SQLite header)",
    !snap.slice(0, 16).toString("ascii").startsWith("SQLite format 3"));
  await b.db.close();
}

async function testSnapshotPlainMode() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "snap-p-"));
  await _resetState();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  await b.db.init({
    dataDir:          tmpDir,
    atRest:           "plain",
    frameworkTables:  false,
    auditSigning:     false,
    schema:           [{ name: "x", columns: { _id: "TEXT PRIMARY KEY" } }],
  });
  b.db.from("x").insertOne({ _id: "1" });
  var snap = b.db.snapshot();
  check("snapshot returns Buffer in plain mode too", Buffer.isBuffer(snap));
  // Plain mode returns the raw SQLite file — header SHOULD match.
  check("plain-mode snapshot has SQLite magic header",
    snap.slice(0, 16).toString("ascii").startsWith("SQLite format 3"));
  await b.db.close();
}

async function run() {
  await testFrameworkTablesOff();
  await testAuditSigningOff();
  await testEncryptedDbNameOverride();
  await testDbKeyPathOverride();
  await testSnapshot();
  await testSnapshotPlainMode();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message, e.stack); process.exit(1); }
  );
}
