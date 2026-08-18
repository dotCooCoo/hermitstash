// F-5 regression: the archive signature covered only BUNDLE_VERSION + checksum +
// createdAt, leaving the plaintext top-level manifest (count / firstCounter /
// lastCounter / fingerprint / …) unsigned. listArchives reads those fields, so an
// on-disk manifest edit was undetectable. The fix folds a hash of the FULL
// top-level manifest into the signed payload, so any manifest edit breaks verify.
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var os = require("os");
var path = require("path");
var fs = require("fs");

var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-audit-manifest-"));
process.env.HERMITSTASH_DATA_DIR = dataDir;
process.env.HERMITSTASH_DB_PATH = path.join(dataDir, "hermitstash.db");
// Also the directory lib/db sweeps at load, deleting every other
// hermitstash-*.db in it. Redirecting only the data directory leaves that on
// /dev/shm wherever it exists — which is CI — so concurrent test processes
// delete each other's databases there.
process.env.HERMITSTASH_TMPDIR = dataDir;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var db = require("../../lib/db");
var config = require("../../lib/config");
var audit = require("../../lib/audit");
var auditArchive = require("../../lib/audit-archive");
var C = require("../../lib/constants");

var PASS = "correct-horse-battery-staple-manifest";

before(async function () {
  await vault.init();
  config.auditChainEnabled = true;
  config.auditArchivePassphrase = PASS;
});
after(function () {
  config.auditChainEnabled = false;
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {}
});

function archiveFile(id) {
  return path.join(C.PATHS.AUDIT_ARCHIVE_DIR, id + ".json");
}

describe("audit archive top-level manifest integrity (F-5)", function () {
  var archiveId;

  before(async function () {
    for (var i = 0; i < 8; i++) {
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, { performedBy: "arch-" + i, details: "row " + i });
    }
    await audit.drainChain();
    var res = await auditArchive.archiveNow({ keep: 3, passphrase: PASS });
    archiveId = res.id;
    assert.ok(archiveId, "archive should have been created");
  });

  it("an untampered archive verifies ok", async function () {
    var v = await auditArchive.verifyArchive(archiveId, PASS);
    assert.strictEqual(v.ok, true, "freshly written archive must verify: " + v.reason);
  });

  it("editing the top-level manifest count breaks verification", async function () {
    var file = archiveFile(archiveId);
    var env = JSON.parse(fs.readFileSync(file, "utf8"));
    env.manifest.count = env.manifest.count + 500; // spoof the row count listArchives shows
    fs.writeFileSync(file, JSON.stringify(env));

    var v = await auditArchive.verifyArchive(archiveId, PASS);
    assert.strictEqual(v.ok, false, "a manifest edit must fail verification");
  });

  it("editing the top-level manifest lastCounter breaks verification", async function () {
    var file = archiveFile(archiveId);
    var env = JSON.parse(fs.readFileSync(file, "utf8"));
    // Restore count, tamper a different field — the whole manifest is covered.
    env.manifest.count = env.manifest.count - 500;
    env.manifest.lastCounter = (env.manifest.lastCounter || 0) + 1;
    fs.writeFileSync(file, JSON.stringify(env));

    var v = await auditArchive.verifyArchive(archiveId, PASS);
    assert.strictEqual(v.ok, false, "a manifest lastCounter edit must fail verification");
  });

  it("restoring the original manifest verifies ok again (edit, not passphrase, was the cause)", async function () {
    var file = archiveFile(archiveId);
    var env = JSON.parse(fs.readFileSync(file, "utf8"));
    env.manifest.lastCounter = (env.manifest.lastCounter || 1) - 1;
    fs.writeFileSync(file, JSON.stringify(env));

    var v = await auditArchive.verifyArchive(archiveId, PASS);
    assert.strictEqual(v.ok, true, "restoring the manifest must verify ok: " + v.reason);
  });

  it("editing the encrypted body is caught by the checksum, before any decryption", async function () {
    // The manifest is left untouched here, so this is the other half of the
    // integrity story: the ciphertext itself. It is checked by checksum before
    // the passphrase is used, so a corrupted or swapped body is reported as
    // corruption rather than surfacing as a decryption failure that reads like
    // a wrong passphrase.
    var file = archiveFile(archiveId);
    var original = fs.readFileSync(file, "utf8");
    var env = JSON.parse(original);
    var raw = Buffer.from(env.data, "base64");
    raw[raw.length - 1] = raw[raw.length - 1] ^ 0xFF;
    env.data = raw.toString("base64");
    fs.writeFileSync(file, JSON.stringify(env));
    try {
      var v = await auditArchive.verifyArchive(archiveId, PASS);
      assert.strictEqual(v.ok, false, "an edited body must fail verification");
      assert.match(v.reason || "", /checksum mismatch/i,
        "and must be named as corruption, not a passphrase problem: " + v.reason);
    } finally {
      fs.writeFileSync(file, original);
    }

    var restored = await auditArchive.verifyArchive(archiveId, PASS);
    assert.strictEqual(restored.ok, true, "restoring the body verifies again: " + restored.reason);
  });
});
