/**
 * Unit test for the operation-lock latch invariant in lib/backup.js.
 *
 * runBackup() / runRestore() set _operationRunning before reading vault/db
 * state (getKeysJson / snapshotEncryptedDb / getCurrentPassphrase). Those
 * pre-worker strands can throw; if the throw escaped with the lock latched,
 * every subsequent backup AND restore would short-circuit on the in-progress
 * guard until process restart. The lock-holding region is wrapped in
 * try/finally so the lock releases unconditionally — this test proves it by
 * forcing a pre-worker throw and asserting the lock is free afterward AND that
 * a second call surfaces the same underlying error rather than the bogus
 * "already in progress" message.
 *
 * The vault/db/audit/config/storage modules are stubbed via the require cache
 * before lib/backup.js is loaded, so backup's lazyRequire(() => require(...))
 * resolves to the stubs without touching real crypto/DB state.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("node:path");

var LIB = path.resolve(__dirname, "..", "..", "lib");

function stub(relName, exports) {
  var resolved = require.resolve(path.join(LIB, relName));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exports };
  return resolved;
}

describe("backup operation-lock latch (try/finally release)", function () {
  var backup;
  var stubbed = [];
  var vaultThrows = true;

  before(function () {
    // Stub audit so the BACKUP_STARTED/FAILED logging is a no-op.
    stubbed.push(stub("audit.js", { log: function () {}, ACTIONS: new Proxy({}, { get: function () { return "stub_action"; } }) }));
    // Stub config with the minimal shape runBackup/runRestore read.
    stubbed.push(stub("config.js", { backup: { scope: "db", retention: 7, timeoutMs: 1000 }, storage: { backend: "local" } }));
    // Stub storage (uploadDir export).
    stubbed.push(stub("storage.js", { uploadDir: "/tmp/uploads" }));
    // Stub vault: getKeysJson throws (the pre-worker strand under test);
    // getCurrentPassphrase throws too (the restore-side strand).
    stubbed.push(stub("vault.js", {
      getKeysJson: function () { if (vaultThrows) throw new Error("vault not initialized — synthetic test throw"); return "{}"; },
      getCurrentPassphrase: function () { if (vaultThrows) throw new Error("vault not initialized — synthetic test throw"); return Buffer.from("pw"); },
    }));
    // Stub db (snapshotEncryptedDb).
    stubbed.push(stub("db.js", { snapshotEncryptedDb: function () { return Buffer.from("snap"); } }));
    // s3-client only constructed inside the worker; backup.js's getBackend
    // path isn't hit by runBackup/runRestore, so leave it real (unused here).
    backup = require(path.join(LIB, "backup.js"));
  });

  after(function () {
    // Evict the stubs + backup so other tests get the real modules.
    for (var i = 0; i < stubbed.length; i++) delete require.cache[stubbed[i]];
    delete require.cache[require.resolve(path.join(LIB, "backup.js"))];
  });

  it("runBackup releases the lock when getKeysJson() throws before the worker", async function () {
    assert.strictEqual(backup.isOperationRunning(), false, "lock starts free");
    await assert.rejects(
      backup.runBackup("pw"),
      /vault not initialized — synthetic test throw/,
      "pre-worker throw propagates the real error"
    );
    assert.strictEqual(backup.isOperationRunning(), false, "lock released after pre-worker throw");
  });

  it("a subsequent runBackup is not wedged by a stale lock", async function () {
    // Second call must surface the SAME underlying error, NOT the
    // 'already in progress' guard message — proving the lock didn't latch.
    await assert.rejects(
      backup.runBackup("pw"),
      function (err) {
        assert.doesNotMatch(err.message, /already in progress/, "lock did not latch");
        assert.match(err.message, /vault not initialized/);
        return true;
      }
    );
  });

  it("runRestore releases the lock when getCurrentPassphrase() throws before the worker", async function () {
    // Wrapped mode + non-dry-run reaches getCurrentPassphrase() pre-worker.
    process.env.VAULT_PASSPHRASE_MODE = "required";
    try {
      assert.strictEqual(backup.isOperationRunning(), false, "lock free before restore");
      await assert.rejects(
        backup.runRestore("pw", "2026-01-01T00-00-00-000Z", { dryRun: false }),
        /vault not initialized — synthetic test throw/,
        "restore pre-worker throw propagates"
      );
      assert.strictEqual(backup.isOperationRunning(), false, "lock released after restore pre-worker throw");
    } finally {
      delete process.env.VAULT_PASSPHRASE_MODE;
    }
  });
});
