const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const b = require("../../lib/vendor/blamejs");

// Isolated test database for config-durability tests.
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-cfgdur-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;
process.env.LOCAL_AUTH = "true";
process.env.REGISTRATION_OPEN = "true";
process.env.EMAIL_VERIFICATION = "false";

// #14: the lockout escape hatch is in env at load time, with a DB-persisted
// ENFORCE_MTLS=true (saved below) that would otherwise win on every rebuild.
process.env.ENFORCE_MTLS_STRICT = "false";

// #15: an out-of-range PORT (schema max 65535). The load path must fall back to
// the schema default (3000) instead of binding 99999 at listen() time.
process.env.PORT = "99999";

// Clear module cache so config.js and db.js load fresh against this env + DB.
Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var projectRoot = path.join(__dirname, "..", "..");
var config = require(path.join(projectRoot, "lib", "config"));
var { updateSettings } = config;
var vault = require(path.join(projectRoot, "lib", "vault"));

before(async function () { await vault.init(); });

after(function () {
  delete process.env.ENFORCE_MTLS_STRICT;
  delete process.env.PORT;
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
});

describe("config durability", function () {
  // ---------------------------------------------------------------------
  // #14 — ENFORCE_MTLS_STRICT=false survives a settings hot-reload
  // ---------------------------------------------------------------------
  describe("ENFORCE_MTLS_STRICT=false escape hatch", function () {
    it("stays off after a settings hot-reload that re-reads DB ENFORCE_MTLS=true", function () {
      // Boot value: strict-false override already forces it off.
      assert.strictEqual(config.enforceMtls, false, "boot config.enforceMtls should be false under the strict-false override");

      // Persist ENFORCE_MTLS=true to the DB (the value that would lock the
      // operator out). This also triggers a hot-reload via _syncHydrateFromDb.
      updateSettings({ enforceMtls: "true" });
      assert.strictEqual(config.enforceMtls, false, "after persisting ENFORCE_MTLS=true, the strict-false override must keep enforceMtls false");

      // Verify the DB actually holds the true value (so the override, not a
      // missing row, is what keeps enforcement off).
      var db = require(path.join(projectRoot, "lib", "db"));
      assert.strictEqual(db.settings.findOne({ key: "ENFORCE_MTLS" }).value, "true", "DB should persist ENFORCE_MTLS=true");

      // An UNRELATED settings save fires another rebuild (_build re-reads
      // DB > env); the override must continue to win.
      updateSettings({ siteName: "MtlsReloadProbe" });
      assert.strictEqual(config.siteName, "MtlsReloadProbe", "unrelated save should apply");
      assert.strictEqual(config.enforceMtls, false, "config.enforceMtls must stay false across an unrelated hot-reload");
    });
  });

  // ---------------------------------------------------------------------
  // #15 — out-of-range env values fall back to the schema default on load
  // ---------------------------------------------------------------------
  describe("out-of-range env load fallback", function () {
    it("uses the schema default for an out-of-range PORT instead of binding the bad value", function () {
      // PORT=99999 (> schema max 65535) was set before load.
      assert.strictEqual(config.port, 3000, "out-of-range PORT must fall back to the default 3000, not 99999");
    });

    it("honors an in-range env value", function () {
      // Persist a valid port through the save path, then confirm load keeps it.
      updateSettings({ port: "4000" });
      assert.strictEqual(config.port, 4000, "an in-range PORT must be honored");
    });

    it("falls back to the default for an invalid BACKUP_TIMEZONE", function () {
      // settings-schema rejects America/Foobar; the load path must return the
      // "UTC" default rather than the bad string verbatim.
      var db = require(path.join(projectRoot, "lib", "db"));
      // Write the bad value straight into the DB settings row (the admin save
      // path would reject it, so seed it directly to exercise the LOAD-path
      // fallback specifically).
      var sealed = vault.seal("America/Foobar");
      var existing = db.settings.raw().findOne({ key: "BACKUP_TIMEZONE" });
      if (existing) db.settings.raw().update({ key: "BACKUP_TIMEZONE" }, { $set: { value: sealed } });
      else db.settings.raw().insert({ _id: "BACKUP_TIMEZONE", key: "BACKUP_TIMEZONE", value: sealed, updatedAt: new Date().toISOString() });

      // Trigger a hot-reload so the seeded DB row reaches cfg.value, then read.
      // The BACKUP_TIMEZONE default resolves to the server TZ (machine-dependent),
      // so assert the invalid value is NOT used verbatim rather than pinning a
      // literal default.
      updateSettings({ siteName: "TzReloadProbe" });
      assert.notStrictEqual(config.backup.timezone, "America/Foobar", "invalid BACKUP_TIMEZONE must not be used verbatim");
    });
  });
});
