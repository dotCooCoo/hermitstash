var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");

// Use an isolated test database
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-audit-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

// Clear require cache so all lib modules load fresh against the test DB
Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var db = require("../../lib/db");
var audit = require("../../lib/audit");
var { sha3Hash } = require("../../lib/crypto");

// Sealed columns + field-crypto's keyed-MAC blind index need the vault MAC key.
before(async function () { await vault.init(); });

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

describe("audit", function () {

  // ---- ACTIONS ----

  describe("ACTIONS", function () {
    it("exports ACTIONS object", function () {
      assert.ok(audit.ACTIONS, "ACTIONS should be exported");
      assert.strictEqual(typeof audit.ACTIONS, "object");
    });

    it("has auth action types", function () {
      assert.strictEqual(audit.ACTIONS.LOGIN_SUCCESS, "login_success");
      assert.strictEqual(audit.ACTIONS.LOGIN_FAILED_BAD_PASSWORD, "login_failed_bad_password");
      assert.strictEqual(audit.ACTIONS.LOGIN_FAILED_NO_ACCOUNT, "login_failed_no_account");
      assert.strictEqual(audit.ACTIONS.USER_REGISTERED, "user_registered");
      assert.strictEqual(audit.ACTIONS.LOGOUT, "logout");
    });

    it("has file operation action types", function () {
      assert.strictEqual(audit.ACTIONS.BUNDLE_INITIALIZED, "bundle_initialized");
      assert.strictEqual(audit.ACTIONS.BUNDLE_FILE_UPLOADED, "bundle_file_uploaded");
      assert.strictEqual(audit.ACTIONS.BUNDLE_FINALIZED, "bundle_finalized");
      assert.strictEqual(audit.ACTIONS.FILE_DOWNLOADED, "file_downloaded");
      assert.strictEqual(audit.ACTIONS.FILE_DELETED, "file_deleted");
    });

    it("has admin action types", function () {
      assert.strictEqual(audit.ACTIONS.ADMIN_DASHBOARD_VIEWED, "admin_dashboard_viewed");
      assert.strictEqual(audit.ACTIONS.ADMIN_FILE_DELETED, "admin_file_deleted");
      assert.strictEqual(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, "admin_settings_changed");
    });

    it("has user management action types", function () {
      assert.strictEqual(audit.ACTIONS.USER_CREATED_BY_ADMIN, "user_created_by_admin");
      assert.strictEqual(audit.ACTIONS.USER_ROLE_CHANGED, "user_role_changed");
      assert.strictEqual(audit.ACTIONS.USER_SUSPENDED, "user_suspended");
      assert.strictEqual(audit.ACTIONS.USER_DELETED, "user_deleted");
    });

    it("has system action types", function () {
      assert.strictEqual(audit.ACTIONS.SERVER_STARTED, "server_started");
      assert.strictEqual(audit.ACTIONS.DEFAULT_ADMIN_CREATED, "default_admin_created");
      assert.strictEqual(audit.ACTIONS.VAULT_KEY_GENERATED, "vault_key_generated");
    });

    it("has cleanup action types", function () {
      assert.strictEqual(audit.ACTIONS.FILE_EXPIRY_CLEANUP, "file_expiry_cleanup");
      assert.strictEqual(audit.ACTIONS.AUDIT_RETENTION_CLEANUP, "audit_retention_cleanup");
    });

    it("has passkey action types", function () {
      assert.strictEqual(audit.ACTIONS.PASSKEY_REGISTERED, "passkey_registered");
      assert.strictEqual(audit.ACTIONS.PASSKEY_LOGIN_SUCCESS, "passkey_login_success");
      assert.strictEqual(audit.ACTIONS.PASSKEY_LOGIN_FAILED, "passkey_login_failed");
      assert.strictEqual(audit.ACTIONS.PASSKEY_REMOVED, "passkey_removed");
    });

    it("has TOTP action types", function () {
      assert.strictEqual(audit.ACTIONS.TOTP_ENABLED, "totp_enabled");
      assert.strictEqual(audit.ACTIONS.TOTP_DISABLED, "totp_disabled");
      assert.strictEqual(audit.ACTIONS.TOTP_FAILED, "totp_failed");
    });

    it("has team action types", function () {
      assert.strictEqual(audit.ACTIONS.TEAM_CREATED, "team_created");
      assert.strictEqual(audit.ACTIONS.TEAM_DELETED, "team_deleted");
      assert.strictEqual(audit.ACTIONS.TEAM_MEMBER_ADDED, "team_member_added");
      assert.strictEqual(audit.ACTIONS.TEAM_MEMBER_REMOVED, "team_member_removed");
    });

    it("has security action types", function () {
      assert.strictEqual(audit.ACTIONS.SUSPENDED_USER_BLOCKED, "suspended_user_blocked");
      assert.strictEqual(audit.ACTIONS.ADMIN_ACCESS_DENIED, "admin_access_denied");
      assert.strictEqual(audit.ACTIONS.RATE_LIMIT_HIT, "rate_limit_hit");
    });

    it("has email action types", function () {
      assert.strictEqual(audit.ACTIONS.EMAIL_SENT, "email_sent");
      assert.strictEqual(audit.ACTIONS.EMAIL_SEND_FAILED, "email_send_failed");
      assert.strictEqual(audit.ACTIONS.EMAIL_QUOTA_EXCEEDED, "email_quota_exceeded");
      assert.strictEqual(audit.ACTIONS.EMAIL_VERIFICATION_SENT, "email_verification_sent");
      assert.strictEqual(audit.ACTIONS.EMAIL_VERIFIED, "email_verified");
    });

    it("all action values are lowercase snake_case strings", function () {
      for (var key in audit.ACTIONS) {
        var val = audit.ACTIONS[key];
        assert.strictEqual(typeof val, "string", key + " should be a string");
        assert.ok(/^[a-z_]+$/.test(val), key + " value '" + val + "' should be lowercase snake_case");
      }
    });
  });

  // ---- log() ----

  describe("log", function () {
    it("creates an audit entry in the database", function () {
      var countBefore = db.auditLog.count();
      audit.log(audit.ACTIONS.SERVER_STARTED, {
        performedBy: "system",
        details: "Test server start"
      });
      var countAfter = db.auditLog.count();
      assert.strictEqual(countAfter, countBefore + 1, "should have one more audit entry");
    });

    it("entry has required fields", function () {
      audit.log(audit.ACTIONS.USER_REGISTERED, {
        performedBy: "system",
        targetId: "user-123",
        targetEmail: "new@example.com",
        details: "New user registered"
      });
      // Find the most recent entry by reading all and taking last
      var entries = db.auditLog.find({});
      var entry = entries[entries.length - 1];
      assert.ok(entry._id, "entry should have _id");
      assert.ok(entry.action, "entry should have action");
      assert.ok(entry.createdAt, "entry should have createdAt");
    });

    it("stores action field as the correct action type", function () {
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, {
        performedBy: "user-abc",
        details: "Test login"
      });
      var entries = db.auditLog.find({});
      var entry = entries[entries.length - 1];
      assert.strictEqual(entry.action, "login_success");
    });

    it("stores targetId and targetEmail", function () {
      audit.log(audit.ACTIONS.FILE_DELETED, {
        performedBy: "admin-1",
        targetId: "file-999",
        targetEmail: "owner@example.com",
        details: "Admin deleted file"
      });
      var entries = db.auditLog.find({});
      var entry = entries[entries.length - 1];
      assert.strictEqual(entry.targetId, "file-999");
      assert.strictEqual(entry.targetEmail, "owner@example.com");
    });

    it("stores performedBy and performedByEmail", function () {
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, {
        performedBy: "admin-42",
        performedByEmail: "admin@example.com",
        details: "Changed site name"
      });
      var entries = db.auditLog.find({});
      var entry = entries[entries.length - 1];
      assert.strictEqual(entry.performedBy, "admin-42");
      assert.strictEqual(entry.performedByEmail, "admin@example.com");
    });

    it("stores details field", function () {
      var msg = "User logged in from Chrome on Windows";
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, {
        performedBy: "user-1",
        details: msg
      });
      var entries = db.auditLog.find({});
      var entry = entries[entries.length - 1];
      assert.strictEqual(entry.details, msg);
    });

    it("generates ISO timestamp for createdAt", function () {
      audit.log(audit.ACTIONS.LOGOUT, { performedBy: "user-ts" });
      var entries = db.auditLog.find({});
      var entry = entries[entries.length - 1];
      // ISO 8601 format check
      assert.ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/.test(entry.createdAt),
        "createdAt should be ISO 8601 format, got: " + entry.createdAt);
    });

    it("hashes IP from req with SHA3 and truncates to 16 chars", function () {
      var fakeReq = {
        socket: { remoteAddress: "203.0.113.50" },
        headers: {}
      };
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, {
        req: fakeReq,
        performedBy: "ip-test"
      });
      // Read the raw (still sealed) entry from DB
      var rawEntries = db.auditLog.raw().find({});
      var rawEntry = rawEntries[rawEntries.length - 1];
      // Unseal using audit.unsealEntry to get the actual stored ip
      var unsealed = audit.unsealEntry(rawEntry);
      // The IP should be hashed and truncated to 16 chars
      var expectedHash = sha3Hash("hs-ip:203.0.113.50").substring(0, 16);
      assert.strictEqual(unsealed.ip, expectedHash, "IP should be SHA3-hashed and truncated");
      assert.strictEqual(unsealed.ip.length, 16, "hashed IP should be 16 chars");
    });

    it("ip is null when no req provided", function () {
      audit.log(audit.ACTIONS.SERVER_STARTED, {
        performedBy: "system",
        details: "No IP test"
      });
      var rawEntries = db.auditLog.raw().find({});
      var rawEntry = rawEntries[rawEntries.length - 1];
      var unsealed = audit.unsealEntry(rawEntry);
      // Either null or undefined = "ip was not captured" — the exact shape
      // depends on whether the field was stored as NULL in a SQL column
      // (→ undefined on read via _merge strip) or in the JSON overflow
      // (→ null preserved). Both represent absence.
      assert.ok(unsealed.ip == null, "ip should be absent when no req (got " + JSON.stringify(unsealed.ip) + ")");
    });

    it("auto-populates performedBy from req.user", function () {
      var fakeReq = {
        socket: { remoteAddress: "127.0.0.1" },
        headers: {},
        user: { _id: "auto-user-id", email: "auto@example.com" }
      };
      audit.log(audit.ACTIONS.FILE_DOWNLOADED, {
        req: fakeReq,
        targetId: "file-auto"
      });
      var entries = db.auditLog.find({});
      var entry = entries[entries.length - 1];
      assert.strictEqual(entry.performedBy, "auto-user-id");
      assert.strictEqual(entry.performedByEmail, "auto@example.com");
    });

    it("explicit performedBy overrides req.user", function () {
      var fakeReq = {
        socket: { remoteAddress: "127.0.0.1" },
        headers: {},
        user: { _id: "req-user", email: "req@test.com" }
      };
      audit.log(audit.ACTIONS.ADMIN_FILE_DELETED, {
        req: fakeReq,
        performedBy: "explicit-admin",
        performedByEmail: "explicit@test.com"
      });
      var entries = db.auditLog.find({});
      var entry = entries[entries.length - 1];
      assert.strictEqual(entry.performedBy, "explicit-admin");
      assert.strictEqual(entry.performedByEmail, "explicit@test.com");
    });

    it("handles null opts gracefully", function () {
      // log() with no opts should not throw
      assert.doesNotThrow(function () {
        audit.log(audit.ACTIONS.SERVER_STARTED);
      });
    });

    it("null fields default correctly", function () {
      audit.log(audit.ACTIONS.SERVER_STARTED, {});
      var entries = db.auditLog.find({});
      var entry = entries[entries.length - 1];
      // SQL-column fields stored as NULL → _merge strips them → undefined
      assert.strictEqual(entry.targetId, undefined);
      assert.strictEqual(entry.targetEmail, undefined);
      assert.strictEqual(entry.performedBy, undefined);
      assert.strictEqual(entry.performedByEmail, undefined);
      assert.strictEqual(entry.details, undefined);
      // ip may be null (JSON overflow path) or undefined (SQL-column path with
      // _merge strip). Both represent absence of an IP on this audit record.
      assert.ok(entry.ip == null, "ip should be absent (got " + JSON.stringify(entry.ip) + ")");
    });
  });

  // ---- Stealth mode ----

  describe("stealth mode", function () {
    it("skips logging when stealth option is true", function () {
      var countBefore = db.auditLog.count();
      audit.log(audit.ACTIONS.FILE_DOWNLOADED, {
        stealth: true,
        performedBy: "stealth-user",
        details: "This should not be logged"
      });
      var countAfter = db.auditLog.count();
      assert.strictEqual(countAfter, countBefore, "stealth=true should skip audit entry");
    });

    it("skips logging for vault ops when user has stealth enabled", function () {
      var countBefore = db.auditLog.count();
      var fakeReq = {
        socket: { remoteAddress: "127.0.0.1" },
        headers: {},
        user: { _id: "stealth-u", vaultStealth: "true" }
      };
      audit.log(audit.ACTIONS.FILE_DOWNLOADED, {
        req: fakeReq,
        vaultOp: true,
        details: "Stealth vault op"
      });
      var countAfter = db.auditLog.count();
      assert.strictEqual(countAfter, countBefore, "vault op with stealth user should be skipped");
    });

    it("does not skip non-vault ops even if user has stealth", function () {
      var countBefore = db.auditLog.count();
      var fakeReq = {
        socket: { remoteAddress: "127.0.0.1" },
        headers: {},
        user: { _id: "stealth-u2", vaultStealth: "true" }
      };
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, {
        req: fakeReq,
        details: "Normal login (not a vault op)"
      });
      var countAfter = db.auditLog.count();
      assert.strictEqual(countAfter, countBefore + 1, "non-vault ops should still be logged");
    });
  });

  // ---- Rate limiting ----

  describe("rate limiting", function () {
    it("logs all INVALID_SESSION actions (no inline rate limiting)", function () {
      var fakeReq = {
        socket: { remoteAddress: "10.10.10.10" },
        headers: {}
      };
      var countBefore = db.auditLog.count();
      audit.log(audit.ACTIONS.INVALID_SESSION, { req: fakeReq, details: "First" });
      audit.log(audit.ACTIONS.INVALID_SESSION, { req: fakeReq, details: "Second" });
      var countAfter = db.auditLog.count();
      assert.strictEqual(countAfter, countBefore + 2, "both calls should be logged");
    });

    it("does not rate-limit different actions", function () {
      var countBefore = db.auditLog.count();
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, { performedBy: "rl-test1", details: "Action 1" });
      audit.log(audit.ACTIONS.LOGOUT, { performedBy: "rl-test2", details: "Action 2" });
      var countAfter = db.auditLog.count();
      assert.strictEqual(countAfter, countBefore + 2, "different actions should not be rate-limited");
    });
  });

  // ---- Tamper-evidence chain (AUDIT_CHAIN on) ----

  describe("tamper-evidence chain", function () {
    var config = require("../../lib/config");
    var auditService = require("../../app/domain/admin/audit.service");

    // Enable the chain for this block only; restore after so the rest of the
    // suite keeps the default synchronous (chain-off) write path.
    before(function () { config.auditChainEnabled = true; });
    after(function () { config.auditChainEnabled = false; });

    it("writes a verifiable chain: counters increase, prevHash links, row0 anchors ZERO_HASH", async function () {
      var N = 5;
      for (var i = 0; i < N; i++) {
        audit.log(audit.ACTIONS.LOGIN_SUCCESS, { performedBy: "chain-user-" + i, details: "chain entry " + i });
      }
      await audit.drainChain();

      var rows = db.rawQuery("SELECT monotonicCounter, prevHash, rowHash FROM audit_log WHERE monotonicCounter IS NOT NULL ORDER BY monotonicCounter ASC");
      assert.ok(rows.length >= N, "should have at least " + N + " chained rows");

      // monotonicCounter strictly increasing by 1
      for (var j = 1; j < rows.length; j++) {
        assert.strictEqual(rows[j].monotonicCounter, rows[j - 1].monotonicCounter + 1,
          "monotonicCounter should increase by exactly 1");
      }
      // prevHash[i] === rowHash[i-1]
      for (var k = 1; k < rows.length; k++) {
        assert.strictEqual(rows[k].prevHash, rows[k - 1].rowHash,
          "each row's prevHash should equal the previous row's rowHash");
      }
      // First row anchors on ZERO_HASH
      assert.strictEqual(rows[0].prevHash, b.auditChain.ZERO_HASH,
        "the first chained row should anchor on ZERO_HASH");
      // nonce stored as a 16-byte BLOB (not a JSON-mangled string)
      var nonceMeta = db.rawGet("SELECT typeof(nonce) as t, length(nonce) as n FROM audit_log WHERE monotonicCounter IS NOT NULL ORDER BY monotonicCounter ASC LIMIT 1");
      assert.strictEqual(nonceMeta.t, "blob", "nonce should be stored as a BLOB");
      assert.strictEqual(nonceMeta.n, 16, "nonce should be 16 bytes");
    });

    it("verifyAuditChain returns ok with the full row count on an untampered chain", async function () {
      await audit.drainChain();
      var total = db.rawGet("SELECT COUNT(*) as c FROM audit_log WHERE monotonicCounter IS NOT NULL").c;
      var result = await auditService.verifyAuditChain();
      assert.strictEqual(result.ok, true, "untampered chain should verify ok");
      assert.strictEqual(result.rowsVerified, total, "should verify every chained row");
    });

    it("verifyAuditChain detects a mutated rowHash (tamper)", async function () {
      await audit.drainChain();
      // Mutate the rowHash of the second chained row.
      var target = db.rawGet("SELECT monotonicCounter FROM audit_log WHERE monotonicCounter IS NOT NULL ORDER BY monotonicCounter ASC LIMIT 1 OFFSET 1");
      db.rawExec("UPDATE audit_log SET rowHash = ? WHERE monotonicCounter = ?",
        "0".repeat(128), target.monotonicCounter);

      var result = await auditService.verifyAuditChain();
      assert.strictEqual(result.ok, false, "tampered chain must fail verification");
      assert.ok(result.reason && /mismatch/.test(result.reason), "should report a hash mismatch");
    });
  });

  // ---- unsealEntry ----

  describe("unsealEntry", function () {
    it("unseals a raw audit log entry", function () {
      audit.log(audit.ACTIONS.USER_REGISTERED, {
        performedBy: "unseal-test",
        performedByEmail: "unseal@test.com",
        targetId: "target-unseal",
        targetEmail: "target@test.com",
        details: "Unseal test entry"
      });
      var rawEntries = db.auditLog.raw().find({});
      var rawEntry = rawEntries[rawEntries.length - 1];
      // Raw entry should have vault-sealed values
      assert.ok(String(rawEntry.action).startsWith("vault.aad:") || String(rawEntry.action).startsWith("vault:"), "raw action should be vault-sealed");

      var unsealed = audit.unsealEntry(rawEntry);
      assert.strictEqual(unsealed.action, "user_registered");
      assert.strictEqual(unsealed.performedBy, "unseal-test");
      assert.strictEqual(unsealed.performedByEmail, "unseal@test.com");
      assert.strictEqual(unsealed.targetId, "target-unseal");
      assert.strictEqual(unsealed.targetEmail, "target@test.com");
      assert.strictEqual(unsealed.details, "Unseal test entry");
    });

    it("returns null for null input", function () {
      assert.strictEqual(audit.unsealEntry(null), null);
    });

    it("returns undefined for undefined input", function () {
      assert.strictEqual(audit.unsealEntry(undefined), undefined);
    });
  });
});
