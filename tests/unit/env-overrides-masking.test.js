/**
 * Env-var masking in the admin Environment Overrides surface
 * (lib/config.js getEnvironment).
 *
 * The defect class this guards against: a sensitive env var added to
 * settingsMap without being added to sensitiveKeys, which would display
 * the raw secret in the admin UI.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var harnessDir = path.join(__dirname, "..", "..", "data", "env-mask-test-" + testId);
process.env.HERMITSTASH_DATA_DIR = harnessDir;
process.env.HERMITSTASH_DB_PATH = path.join(harnessDir, "h.db");
fs.mkdirSync(harnessDir, { recursive: true });

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var config = require("../../lib/config");

before(async function () { await vault.init(); });

after(function () {
  try { fs.rmSync(harnessDir, { recursive: true, force: true }); } catch {}
});

describe("env-var masking in getEnvironment()", function () {

  // The exhaustive list — every env var in settingsMap that holds a secret.
  // If a new sensitive var is added to settingsMap, it MUST also land in
  // lib/config.js sensitiveKeys, OR this test will catch it.
  var SECRET_ENV_VARS = [
    { env: "SESSION_SECRET",         val: "session-real-secret-abc123" },
    { env: "GOOGLE_CLIENT_SECRET",   val: "google-real-secret-xyz789" },
    { env: "S3_ACCESS_KEY",          val: "AKIA-real-access-key" },
    { env: "S3_SECRET_KEY",          val: "secret-s3-key-bytes-here" },
    { env: "SMTP_PASS",              val: "smtp-real-password" },
    { env: "RESEND_API_KEY",         val: "re_real_api_token" },
    { env: "BACKUP_S3_ACCESS_KEY",   val: "BAK-real-access" },
    { env: "BACKUP_S3_SECRET_KEY",   val: "BAK-real-secret" },
    { env: "BACKUP_PASSPHRASE",      val: "real-backup-passphrase-bytes" },
    { env: "BACKUP_PASSPHRASE_HASH", val: "$argon2id$v=19$m=65536,t=3,p=4$REAL-HASH-BYTES" },
  ];

  it("REGRESSION: every sensitive env var is masked in envOverrides", function () {
    // Set every secret env var. After getEnvironment() runs, none of the
    // raw values must appear anywhere in the response payload.
    for (var i = 0; i < SECRET_ENV_VARS.length; i++) {
      process.env[SECRET_ENV_VARS[i].env] = SECRET_ENV_VARS[i].val;
    }

    try {
      var env = config.getEnvironment();
      var serialized = JSON.stringify(env);

      for (var j = 0; j < SECRET_ENV_VARS.length; j++) {
        var rawSecret = SECRET_ENV_VARS[j].val;
        assert.ok(
          serialized.indexOf(rawSecret) === -1,
          "REGRESSION: raw secret value for " + SECRET_ENV_VARS[j].env +
          " (\"" + rawSecret + "\") appears in getEnvironment() output. " +
          "Add the corresponding settingsMap key to sensitiveKeys in lib/config.js."
        );
      }
    } finally {
      // Cleanup so other tests in the same process aren't polluted
      for (var k = 0; k < SECRET_ENV_VARS.length; k++) {
        delete process.env[SECRET_ENV_VARS[k].env];
      }
    }
  });

  it("VAULT_PASSPHRASE and VAULT_PASSPHRASE_FILE are NEVER surfaced in envOverrides", function () {
    // Boot-time secrets are intentionally absent from settingsMap entirely;
    // they should never appear in envOverrides regardless of value.
    process.env.VAULT_PASSPHRASE = "vault-real-secret-must-not-leak";
    process.env.VAULT_PASSPHRASE_FILE = "/run/secrets/vault-secret-path";

    try {
      var env = config.getEnvironment();
      var serialized = JSON.stringify(env);

      assert.strictEqual(serialized.indexOf("vault-real-secret-must-not-leak"), -1,
        "VAULT_PASSPHRASE value must not appear in env response");
      assert.strictEqual(serialized.indexOf("/run/secrets/vault-secret-path"), -1,
        "VAULT_PASSPHRASE_FILE path must not appear in env response (reveals secret location)");

      // The MODE flag is a non-secret status indicator — should appear
      assert.ok("vaultPassphraseMode" in env, "vaultPassphraseMode is a non-secret status flag and should be exposed");
    } finally {
      delete process.env.VAULT_PASSPHRASE;
      delete process.env.VAULT_PASSPHRASE_FILE;
    }
  });

  it("env vars NOT marked sensitive ARE surfaced as their actual value", function () {
    // Sanity check: the masking is selective, not blanket. Non-sensitive
    // env vars (e.g. PORT, BACKUP_S3_BUCKET) should display their value
    // so operators can verify config.
    process.env.BACKUP_S3_BUCKET = "my-non-secret-bucket-name";
    try {
      var env = config.getEnvironment();
      var bucketOverride = env.envOverrides.filter(function (o) { return o.env === "BACKUP_S3_BUCKET"; })[0];
      assert.ok(bucketOverride, "non-sensitive override should appear");
      assert.strictEqual(bucketOverride.value, "my-non-secret-bucket-name");
    } finally {
      delete process.env.BACKUP_S3_BUCKET;
    }
  });
});
