/**
 * settings-schema URL validation.
 *
 * Regression: between v1.9.39 and v1.11.15, isValidUrl called
 * b.safeUrl.parse without opts.allowedProtocols, so blamejs's default
 * https-only allowlist refused every http:// value. The validator's own
 * return-value check accepts both http: and https: — the parse just had to
 * not throw first. RP_ORIGIN=http://umbrel-dev.local:3080 (and any other
 * cleartext setting) silently fell back to the code default, breaking
 * cross-origin requests with "Forbidden" via origin-policy.
 */
var { describe, it } = require("node:test");
var assert = require("node:assert");
var settingsSchema = require("../../lib/settings-schema");

describe("settings-schema url validation", function () {
  it("accepts http:// values for url-typed settings", function () {
    var keys = ["rpOrigin", "googleCallbackURL", "s3Endpoint", "backupS3Endpoint"];
    for (var i = 0; i < keys.length; i += 1) {
      var r = settingsSchema.validate(keys[i], "http://umbrel-dev.local:3080");
      assert.strictEqual(r.valid, true,
        keys[i] + " must accept http:// values (got: " + (r.error || "ok") + ")");
    }
  });

  it("accepts https:// values for url-typed settings", function () {
    var r = settingsSchema.validate("rpOrigin", "https://example.com");
    assert.strictEqual(r.valid, true);
  });

  it("rejects non-http(s) protocols", function () {
    var r = settingsSchema.validate("rpOrigin", "ftp://example.com");
    assert.strictEqual(r.valid, false);
    assert.match(r.error, /invalid URL/);
  });

  it("rejects malformed URLs", function () {
    var r = settingsSchema.validate("rpOrigin", "not a url");
    assert.strictEqual(r.valid, false);
    assert.match(r.error, /invalid URL/);
  });

  it("accepts empty string (= use default)", function () {
    var r = settingsSchema.validate("rpOrigin", "");
    assert.strictEqual(r.valid, true);
  });
});
