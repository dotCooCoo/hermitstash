const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const crypto = require("crypto");
const b = require("../../lib/vendor/blamejs");

var testEnv = require("../helpers/test-env");

process.env.LOCAL_AUTH = "true";
process.env.REGISTRATION_OPEN = "true";
process.env.EMAIL_VERIFICATION = "false";
process.env.PUBLIC_UPLOAD = "true";

var vault = require(path.join(testEnv.projectRoot, "lib", "vault"));
var { hashEmail, sha3Hash } = require(path.join(testEnv.projectRoot, "lib", "crypto"));
// b.auth.password.hash is the framework primitive HS routes use for
// password hashing (Argon2id). lib/crypto.js doesn't export a
// `hashPassword` — historically the test imported from there but the
// function moved to b.auth.password before HS adopted the framework.
var hashPassword = function (p) { return b.auth.password.hash(String(p)); };
var db = require(path.join(testEnv.projectRoot, "lib", "db"));
var audit = require(path.join(testEnv.projectRoot, "lib", "audit"));

after(function () { testEnv.cleanup(); });

describe("zero-plaintext database verification", function () {
  describe("users table", function () {
    it("email is vault-sealed", async function () {
      var hash = await hashPassword("test");
      var doc = db.users.insert({
        email: "alice@example.com",
        displayName: "Alice",
        passwordHash: hash, authType: "local", role: "user", status: "active",
        createdAt: new Date().toISOString(),
      });
      var raw = db.users.raw().findOne({ _id: doc._id });
      assert.ok(raw.email.startsWith("vault:"), "email should be vault-sealed");
      assert.ok(raw.displayName.startsWith("vault:"), "displayName should be vault-sealed");
      assert.ok(raw.passwordHash.startsWith("vault:"), "passwordHash should be vault-sealed (HS defense-in-depth — see lib/field-crypto.js users.seal)");
      assert.ok(vault.unseal(raw.passwordHash).startsWith("$argon2id$"), "unsealed passwordHash should be Argon2id PHC");
      assert.ok(raw.emailHash.length > 50, "emailHash should be SHA3 hash");
      assert.ok(!raw.emailHash.startsWith("vault:"), "emailHash should be hash not sealed");
      // Verify unseal roundtrip
      assert.strictEqual(vault.unseal(raw.email), "alice@example.com");
      assert.strictEqual(vault.unseal(raw.displayName), "Alice");
      db.users.remove({ _id: doc._id });
    });

    it("emailHash enables lookup without decryption", async function () {
      var hash = await hashPassword("test");
      db.users.insert({
        email: "bob@test.com",
        displayName: "Bob", passwordHash: hash, authType: "local",
        role: "user", status: "active", createdAt: new Date().toISOString(),
      });
      // Query by plaintext email — auto-translated to emailHash lookup
      var found = db.users.findOne({ email: "bob@test.com" });
      assert.ok(found, "should find by email (auto-translated to emailHash)");
      assert.strictEqual(found.email, "bob@test.com");
      db.users.remove({ _id: found._id });
    });

    it("googleId is sealed when present", function () {
      var doc = db.users.insert({
        googleId: "g12345", email: "g@test.com",
        displayName: "Google User",
        avatar: "https://photo.url/pic.jpg",
        authType: "google", role: "user", status: "active", createdAt: new Date().toISOString(),
      });
      var raw = db.users.raw().findOne({ _id: doc._id });
      assert.ok(raw.googleId.startsWith("vault:"), "googleId should be sealed");
      assert.ok(raw.avatar.startsWith("vault:"), "avatar should be sealed");
      db.users.remove({ _id: doc._id });
    });
  });

  describe("files table", function () {
    it("file metadata is vault-sealed", function () {
      var doc = db.files.insert({
        shareId: "f1", originalName: "secret-report.pdf",
        relativePath: "documents/secret-report.pdf",
        storagePath: "bundles/abc/123.pdf",
        mimeType: "application/pdf",
        uploaderEmail: "uploader@test.com",
        size: 1024, status: "complete", createdAt: new Date().toISOString(),
      });
      var raw = db.files.raw().findOne({ _id: doc._id });
      assert.ok(raw.originalName.startsWith("vault:"), "originalName should be sealed");
      assert.ok(raw.relativePath.startsWith("vault:"), "relativePath should be sealed");
      assert.ok(raw.storagePath.startsWith("vault:"), "storagePath should be sealed");
      assert.ok(raw.mimeType.startsWith("vault:"), "mimeType should be sealed");
      assert.ok(raw.uploaderEmail.startsWith("vault:"), "uploaderEmail should be sealed");
      assert.strictEqual(vault.unseal(raw.originalName), "secret-report.pdf");
      db.files.remove({ _id: doc._id });
    });
  });

  describe("bundles table", function () {
    it("uploader PII is vault-sealed", function () {
      var doc = db.bundles.insert({
        shareId: "b1", uploaderName: "Uploader Person",
        uploaderEmail: "up@test.com",
        status: "complete", createdAt: new Date().toISOString(),
      });
      var raw = db.bundles.raw().findOne({ _id: doc._id });
      assert.ok(raw.uploaderName.startsWith("vault:"), "uploaderName should be sealed");
      assert.ok(raw.uploaderEmail.startsWith("vault:"), "uploaderEmail should be sealed");
      db.bundles.remove({ _id: doc._id });
    });
  });

  describe("audit_log table", function () {
    it("emails and details are vault-sealed, IP is hashed", function () {
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, {
        targetId: "user1", targetEmail: "target@test.com",
        performedByEmail: "performer@test.com", details: "authType: local",
        req: { headers: {}, socket: { remoteAddress: "192.168.1.100" } },
      });
      // Use .raw() to see sealed values in the DB
      var allRaw = db.auditLog.raw().find({});
      var entry = allRaw.filter(function (e) {
        return audit.unsealEntry(e).action === "login_success";
      }).pop();
      assert.ok(entry, "should find a login_success audit entry");
      assert.ok(entry.action.startsWith("vault:"), "action should be sealed");
      assert.ok(entry.targetEmail.startsWith("vault:"), "targetEmail should be sealed");
      assert.ok(entry.performedByEmail.startsWith("vault:"), "performedByEmail should be sealed");
      assert.ok(entry.details.startsWith("vault:"), "details should be sealed");
      assert.ok(entry.ip && entry.ip.startsWith("vault:"), "IP should be vault-sealed");
      assert.ok(!entry.userAgent, "userAgent should not be stored");
      // Verify unseal
      var unsealed = audit.unsealEntry(entry);
      assert.strictEqual(unsealed.targetEmail, "target@test.com");
      assert.strictEqual(unsealed.details, "authType: local");
    });
  });

  describe("api_keys table", function () {
    it("name, prefix, permissions are vault-sealed", function () {
      var doc = db.apiKeys.insert({
        name: "My API Key", keyHash: sha3Hash("hs_test123"),
        prefix: "hs_test", permissions: "upload",
        userId: "u1", createdAt: new Date().toISOString(),
      });
      var raw = db.apiKeys.raw().findOne({ _id: doc._id });
      assert.ok(raw.name.startsWith("vault:"), "name should be sealed");
      assert.ok(raw.prefix.startsWith("vault:"), "prefix should be sealed");
      assert.ok(raw.permissions.startsWith("vault:"), "permissions should be sealed");
      assert.ok(!raw.keyHash.startsWith("vault:"), "keyHash should be SHA3 hash not sealed");
      db.apiKeys.remove({ _id: doc._id });
    });
  });

  describe("webhooks table", function () {
    it("url, events, secret are vault-sealed", function () {
      var doc = db.webhooks.insert({
        url: "https://example.com/hook",
        events: "bundle_finalized",
        secret: "webhook-secret-123",
        active: "true", createdBy: "u1", createdAt: new Date().toISOString(),
      });
      var raw = db.webhooks.raw().findOne({ _id: doc._id });
      assert.ok(raw.url.startsWith("vault:"), "url should be sealed");
      assert.ok(raw.events.startsWith("vault:"), "events should be sealed");
      assert.ok(raw.secret.startsWith("vault:"), "secret should be sealed");
      db.webhooks.remove({ _id: doc._id });
    });
  });

  describe("blocked_ips table", function () {
    it("IP is SHA3-hashed, reason is vault-sealed", function () {
      var doc = db.blockedIps.insert({
        ip: "10.0.0.1", reason: "Suspicious activity",
        blockedBy: "u1", createdAt: new Date().toISOString(),
      });
      var raw = db.blockedIps.raw().findOne({ _id: doc._id });
      assert.ok(!raw.ip.startsWith("vault:"), "ip should be hash not sealed");
      assert.ok(raw.ip.length > 50, "ip should be full SHA3 hash");
      assert.ok(raw.reason.startsWith("vault:"), "reason should be sealed");
      db.blockedIps.remove({ _id: doc._id });
    });
  });

  describe("credentials table", function () {
    it("credentialId and publicKey are vault-sealed", function () {
      var doc = db.credentials.insert({
        userId: "u1", credentialId: "cred-id-bytes",
        publicKey: "public-key-bytes",
        counter: 0, deviceType: "multiDevice", createdAt: new Date().toISOString(),
      });
      var raw = db.credentials.raw().findOne({ _id: doc._id });
      assert.ok(raw.credentialId.startsWith("vault:"), "credentialId should be sealed");
      assert.ok(raw.publicKey.startsWith("vault:"), "publicKey should be sealed");
      db.credentials.remove({ _id: doc._id });
    });
  });

  describe("verification_tokens table", function () {
    it("token is SHA3-hashed (not sealed, not plaintext)", function () {
      var rawToken = b.crypto.generateToken(32);
      var tokenHash = sha3Hash(rawToken);
      var doc = db.verificationTokens.insert({
        userId: "u1", token: tokenHash, type: "email",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        createdAt: new Date().toISOString(),
      });
      var raw = db.verificationTokens.findOne({ _id: doc._id });
      assert.ok(!raw.token.startsWith("vault:"), "token should be hash not sealed");
      assert.strictEqual(raw.token.length, 128, "should be SHA3-512 hash (128 hex)");
      assert.notStrictEqual(raw.token, rawToken, "should not store raw token");
      db.verificationTokens.remove({ _id: doc._id });
    });
  });
});
