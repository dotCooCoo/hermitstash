const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const b = require("../../lib/vendor/blamejs");

// Isolated test database for config tests
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-cfg-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;
process.env.LOCAL_AUTH = "true";
process.env.REGISTRATION_OPEN = "true";
process.env.EMAIL_VERIFICATION = "false";

// Clear module cache so config.js and db.js load fresh
Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var projectRoot = path.join(__dirname, "..", "..");
var config = require(path.join(projectRoot, "lib", "config"));
var { getSettings, updateSettings } = config;
var vault = require(path.join(projectRoot, "lib", "vault"));
var db = require(path.join(projectRoot, "lib", "db"));

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
});

describe("config", function () {
  // -----------------------------------------------------------------------
  // updateSettings round-trip
  // -----------------------------------------------------------------------
  describe("updateSettings", function () {
    it("saves to DB and applies to memory", function () {
      var result = updateSettings({ siteName: "TestSite" });
      assert.ok(result.updated.includes("siteName"), "siteName should be in updated list");
      assert.strictEqual(config.siteName, "TestSite", "config.siteName should be updated in memory");

      // Verify the value is sealed in the DB (use .raw() to bypass auto-unseal)
      var row = db.settings.raw().findOne({ key: "SITE_NAME" });
      assert.ok(row, "settings row should exist in DB");
      assert.ok(row.value.startsWith("vault:"), "DB value should be vault-sealed");
      assert.strictEqual(vault.unseal(row.value), "TestSite", "unsealed DB value should match");
    });

    it("returns updated keys array", function () {
      var result = updateSettings({ dropTitle: "Drop Here", dropSubtitle: "Just do it" });
      assert.ok(result.updated.includes("dropTitle"), "dropTitle should be in updated list");
      assert.ok(result.updated.includes("dropSubtitle"), "dropSubtitle should be in updated list");
      assert.strictEqual(result.updated.length, 2, "should have exactly 2 updated keys");
    });

    it("ignores unknown keys", function () {
      var result = updateSettings({ totallyFakeKey: "whatever" });
      assert.strictEqual(result.updated.length, 0, "unknown key should not be in updated list");
    });

    it("returns restart:true for restart-required keys", function () {
      var result = updateSettings({ port: "4000" });
      assert.strictEqual(result.restart, true, "port change should require restart");
      assert.strictEqual(config.port, 4000, "config.port should be updated");
    });

    it("returns restart:false for non-restart keys", function () {
      var result = updateSettings({ siteName: "NoRestart" });
      assert.strictEqual(result.restart, false, "siteName change should not require restart");
    });

    it("handles multiple keys including restart and non-restart", function () {
      var result = updateSettings({ siteName: "Mixed", sessionSecret: "new-secret-value" });
      assert.strictEqual(result.restart, true, "sessionSecret change should require restart");
      assert.ok(result.updated.includes("siteName"));
      assert.ok(result.updated.includes("sessionSecret"));
    });

    it("updates boolean settings correctly", function () {
      updateSettings({ registrationOpen: "false" });
      assert.strictEqual(config.registrationOpen, false, "should parse 'false' to boolean false");

      updateSettings({ registrationOpen: "true" });
      assert.strictEqual(config.registrationOpen, true, "should parse 'true' to boolean true");
    });

    it("updates nested config properties", function () {
      updateSettings({ smtpHost: "mail.example.com", smtpPort: "465" });
      assert.strictEqual(config.email.host, "mail.example.com");
      assert.strictEqual(config.email.port, 465);
    });

    it("updates list settings (comma-separated)", function () {
      updateSettings({ allowedDomains: "example.com, test.org" });
      assert.deepStrictEqual(config.allowedDomains, ["example.com", "test.org"]);

      // Restore
      updateSettings({ allowedDomains: "" });
      assert.deepStrictEqual(config.allowedDomains, []);
    });
  });

  // -----------------------------------------------------------------------
  // Sensitive value masking
  // -----------------------------------------------------------------------
  describe("sensitive value masking", function () {
    it("getSettings masks sessionSecret with bullet chars", function () {
      // Ensure sessionSecret has a real value
      var origSecret = config.sessionSecret;
      if (!origSecret || origSecret.length === 0) {
        config.sessionSecret = "test-secret-for-masking";
      }
      var settings = getSettings();
      assert.ok(settings.sessionSecret.length > 0, "masked sessionSecret should not be empty");
      assert.ok(/^\u2022+$/.test(settings.sessionSecret), "sessionSecret should be all bullet chars, got: " + settings.sessionSecret);
      config.sessionSecret = origSecret;
    });

    it("getSettings masks smtpPass with bullet chars", function () {
      config.email.pass = "real-smtp-password";
      var settings = getSettings();
      assert.ok(settings.smtpPass.length > 0, "masked smtpPass should not be empty");
      assert.ok(/^\u2022+$/.test(settings.smtpPass), "smtpPass should be all bullet chars");
    });

    it("getSettings masks googleClientSecret with bullet chars", function () {
      config.google.clientSecret = "google-secret-value";
      var settings = getSettings();
      assert.ok(/^\u2022+$/.test(settings.googleClientSecret), "googleClientSecret should be all bullet chars");
    });

    it("getSettings masks s3AccessKey with bullet chars", function () {
      config.storage.s3.accessKey = "AKIAIOSFODNN7EXAMPLE";
      var settings = getSettings();
      assert.ok(/^\u2022+$/.test(settings.s3AccessKey), "s3AccessKey should be all bullet chars");
    });

    it("getSettings masks s3SecretKey with bullet chars", function () {
      config.storage.s3.secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
      var settings = getSettings();
      assert.ok(/^\u2022+$/.test(settings.s3SecretKey), "s3SecretKey should be all bullet chars");
    });

    it("getSettings returns empty string for empty sensitive values", function () {
      config.email.resendApiKey = "";
      var settings = getSettings();
      assert.strictEqual(settings.resendApiKey, "", "empty sensitive value should remain empty");
    });

    it("mask length is capped at 20 bullets", function () {
      config.google.clientSecret = "a".repeat(50);
      var settings = getSettings();
      assert.strictEqual(settings.googleClientSecret.length, 20, "mask should be capped at 20 bullets");
    });
  });

  // -----------------------------------------------------------------------
  // Skip masked values on update (bullet-masked sensitive keys)
  // -----------------------------------------------------------------------
  describe("skip masked values", function () {
    it("updateSettings skips bullet-masked value for smtpPass", function () {
      // Set a real password first
      updateSettings({ smtpPass: "realpassword" });
      assert.strictEqual(config.email.pass, "realpassword", "password should be set");

      // Now send the masked (bullet) version — should be skipped
      var bullets = "\u2022".repeat(20);
      var result = updateSettings({ smtpPass: bullets });
      assert.ok(!result.updated.includes("smtpPass"), "smtpPass should NOT be in updated list when masked");
      assert.strictEqual(config.email.pass, "realpassword", "password should remain unchanged after masked update");
    });

    it("updateSettings skips bullet-masked value for sessionSecret", function () {
      updateSettings({ sessionSecret: "real-session-secret" });
      var before = config.sessionSecret;

      var bullets = "\u2022".repeat(19);
      var result = updateSettings({ sessionSecret: bullets });
      assert.ok(!result.updated.includes("sessionSecret"), "sessionSecret should NOT be in updated list");
      assert.strictEqual(config.sessionSecret, before, "sessionSecret should remain unchanged");
    });

    it("updateSettings skips bullet-masked value for s3SecretKey", function () {
      updateSettings({ s3SecretKey: "real-s3-key" });
      var before = config.storage.s3.secretKey;

      var bullets = "\u2022".repeat(11);
      var result = updateSettings({ s3SecretKey: bullets });
      assert.ok(!result.updated.includes("s3SecretKey"), "s3SecretKey should NOT be in updated list");
      assert.strictEqual(config.storage.s3.secretKey, before, "s3SecretKey should remain unchanged");
    });

    it("updateSettings allows real values for sensitive keys (not bullets)", function () {
      updateSettings({ smtpPass: "old-password" });
      var result = updateSettings({ smtpPass: "new-password" });
      assert.ok(result.updated.includes("smtpPass"), "smtpPass should be updated with real value");
      assert.strictEqual(config.email.pass, "new-password");
    });
  });

  // -----------------------------------------------------------------------
  // getSettings returns all settings
  // -----------------------------------------------------------------------
  describe("getSettings", function () {
    it("returns all expected setting keys", function () {
      var settings = getSettings();
      var expectedKeys = [
        "siteName", "customLogo", "dropTitle", "dropSubtitle", "landingEnabled",
        "heroTitle", "heroSubtitle", "maintenanceMode", "announcementBanner",
        "port", "sessionSecret", "googleClientID", "googleClientSecret",
        "googleCallbackURL", "allowedDomains", "adminEmails", "allowedExtensions",
        "maxFileSize", "uploadTimeout", "uploadConcurrency", "uploadRetries",
        "localAuth", "registrationOpen", "fileExpiryDays", "storageQuotaBytes",
        "publicUpload", "publicMaxFiles", "publicMaxBundleSize",
        "storageBackend", "uploadDir", "s3Bucket", "s3Region",
        "s3AccessKey", "s3SecretKey", "s3Endpoint",
        "emailBackend", "resendApiKey", "resendQuotaDaily", "resendQuotaMonthly",
        "smtpHost", "smtpPort", "smtpUser", "smtpPass", "smtpFrom",
        "emailTemplateSubject", "emailTemplateHeader", "emailTemplateFooter",
        "emailVerification", "passkeyEnabled", "rpName", "rpId", "rpOrigin",
        "themeAccentColor", "themeBgColor", "themeFont", "trustProxy",
      ];
      for (var i = 0; i < expectedKeys.length; i++) {
        assert.ok(expectedKeys[i] in settings, "getSettings should include key: " + expectedKeys[i]);
      }
    });

    it("returns plain values for non-sensitive fields", function () {
      updateSettings({ siteName: "PlainCheck" });
      var settings = getSettings();
      assert.strictEqual(settings.siteName, "PlainCheck", "non-sensitive value should be plaintext");
    });

    it("returns comma-joined string for list fields", function () {
      updateSettings({ allowedDomains: "a.com, b.com, c.com" });
      var settings = getSettings();
      assert.strictEqual(settings.allowedDomains, "a.com, b.com, c.com");
      // Restore
      updateSettings({ allowedDomains: "" });
    });

    it("reflects in-memory changes from updateSettings", function () {
      updateSettings({ dropTitle: "Settings Round Trip" });
      var settings = getSettings();
      assert.strictEqual(settings.dropTitle, "Settings Round Trip");
    });
  });

  // -----------------------------------------------------------------------
  // DB persistence: values survive updateSettings round-trip
  // -----------------------------------------------------------------------
  describe("DB persistence", function () {
    it("saved settings are vault-sealed in DB", function () {
      updateSettings({ heroTitle: "My Hero" });
      var row = db.settings.raw().findOne({ key: "HERO_TITLE" });
      assert.ok(row, "setting should exist in DB");
      assert.ok(row.value.startsWith("vault:"), "value should be vault-sealed");
      assert.strictEqual(vault.unseal(row.value), "My Hero");
    });

    it("overwriting a setting updates existing DB row", function () {
      updateSettings({ heroSubtitle: "First" });
      var first = db.settings.findOne({ key: "HERO_SUBTITLE" });
      assert.ok(first);

      updateSettings({ heroSubtitle: "Second" });
      var second = db.settings.findOne({ key: "HERO_SUBTITLE" });
      assert.ok(second);
      assert.strictEqual(vault.unseal(second.value), "Second");
      // Same row ID — upsert, not duplicate
      assert.strictEqual(first._id, second._id, "should update same row, not insert duplicate");
    });

    it("updatedAt timestamp is set on save", function () {
      var before = new Date().toISOString();
      updateSettings({ announcementBanner: "Test banner" });
      var row = db.settings.findOne({ key: "ANNOUNCEMENT_BANNER" });
      assert.ok(row.updatedAt, "updatedAt should be set");
      assert.ok(row.updatedAt >= before, "updatedAt should be at or after the test start time");
    });
  });
});
