/**
 * SIEM level/outcome classification.
 *
 * The forwarder classifies an audit action by WHOLE snake_case token, not
 * substring — so a negated action (user_unsuspended) is not misread as its base
 * (suspend), and a security event that carries no failure word (rate_limit_hit,
 * email_quota_exceeded) is still raised to warn/failure.
 */
var { describe, it } = require("node:test");
var assert = require("node:assert");
var siem = require("../../lib/audit-siem");

describe("audit-siem classification", function () {
  describe("_level (warn vs info)", function () {
    it("raises genuine failures to warn", function () {
      ["login_failed_bad_password", "admin_fence_denied", "auth_failed_page", "restore_failed"].forEach(function (a) {
        assert.strictEqual(siem._level(a), "warn", a + " should be warn");
      });
    });

    it("raises keyword-free security events (the under-alert cases) to warn", function () {
      assert.strictEqual(siem._level("rate_limit_hit"), "warn");
      assert.strictEqual(siem._level("email_quota_exceeded"), "warn");
    });

    it("raises deliberate security actions to warn without a failure word", function () {
      assert.strictEqual(siem._level("cert_revoked"), "warn");
    });

    it("does NOT misclassify a negated action by substring", function () {
      // "user_unsuspended" contains the substring "suspend" but is a success.
      assert.strictEqual(siem._level("user_unsuspended"), "info", "unsuspended must not match suspend");
    });

    it("leaves ordinary events at info", function () {
      ["login_success", "bundle_viewed", "file_downloaded", "password_reset_success"].forEach(function (a) {
        assert.strictEqual(siem._level(a), "info", a + " should be info");
      });
    });
  });

  describe("_outcome (failure vs success)", function () {
    it("marks refused/failed requests as failure", function () {
      ["login_failed_no_account", "admin_access_denied", "rate_limit_hit", "email_quota_exceeded"].forEach(function (a) {
        assert.strictEqual(siem._outcome(a), "failure", a + " should be failure");
      });
    });

    it("marks a deliberate revoke/unsuspend as success (not failure)", function () {
      assert.strictEqual(siem._outcome("cert_revoked"), "success", "a revoke succeeds");
      assert.strictEqual(siem._outcome("user_unsuspended"), "success", "an unsuspend succeeds");
    });

    it("marks ordinary successes as success", function () {
      assert.strictEqual(siem._outcome("passkey_login_success"), "success");
    });
  });
});
