const { describe, it, after } = require("node:test");
const assert = require("node:assert");
const cp = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

// Regression test for the post-restore exit-encrypt clobber (lib/db.js).
//
// In production (encPath != null) the process.on("exit") handler re-encrypts the
// in-memory tmpfs DB over db.enc. After a restore writes a fresh, authoritative
// db.enc + db.key.enc, that exit-time re-encrypt would overwrite the restored
// bytes with the STALE tmpfs copy (under the OLD key) — reverting the restore or
// bricking the next boot. db.suppressExitEncrypt() must stop that.
//
// The suite E2E cannot see this: it sets HERMITSTASH_DB_PATH, which forces
// encPath = null, so the exit-time re-encrypt is a no-op there. This test runs
// three fresh processes with a real encPath (HERMITSTASH_DATA_DIR + TMPDIR, and
// crucially NO HERMITSTASH_DB_PATH) to exercise the production path.

const REPO = path.resolve(__dirname, "..", "..");

function runPhase(dataDir, script) {
  return cp.execFileSync(process.execPath, ["-e", script], {
    env: Object.assign({}, process.env, {
      HERMITSTASH_DATA_DIR: dataDir,
      HERMITSTASH_TMPDIR: dataDir,
      HERMITSTASH_ALLOW_DISK_DB: "true",
      VAULT_PASSPHRASE_MODE: "disabled",
      // Ensure the production encPath branch: HERMITSTASH_DB_PATH must be absent.
      HERMITSTASH_DB_PATH: "",
    }),
    encoding: "utf8",
    timeout: 60000,
  });
}

// A phase body: init the vault (plaintext), require db, run `body`, then exit(0)
// so the exit-encrypt handler fires.
function phase(body) {
  return `
    var vault = require(${JSON.stringify(REPO)} + "/lib/vault");
    vault.init().then(function () {
      var db = require(${JSON.stringify(REPO)} + "/lib/db");
      ${body}
      process.exit(0);
    }).catch(function (e) { console.error("PHASE-ERR:" + (e && e.message)); process.exit(3); });
  `;
}

describe("restore exit-encrypt clobber", function () {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-restore-test-"));

  after(function () {
    try { fs.rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch (_e) { /* best-effort */ }
  });

  it("suppressExitEncrypt keeps the restored db.enc from being clobbered by the stale tmpfs DB", function () {
    // Phase A — write marker A and let the exit handler encrypt it into db.enc.
    runPhase(dataDir, phase(`db.getDb().prepare("INSERT OR IGNORE INTO blocked_ips (_id) VALUES ('markerA')").run();`));

    // Phase B — load db.enc (has A), mutate tmpfs (add B), then call
    // suppressExitEncrypt() so the exit handler must NOT persist the mutation.
    runPhase(dataDir, phase(`
      db.getDb().prepare("INSERT OR IGNORE INTO blocked_ips (_id) VALUES ('markerB')").run();
      db.suppressExitEncrypt();
    `));

    // Phase C — boot from db.enc and report which markers survived.
    var out = runPhase(dataDir, phase(`
      var a = db.getDb().prepare("SELECT _id FROM blocked_ips WHERE _id='markerA'").get();
      var b = db.getDb().prepare("SELECT _id FROM blocked_ips WHERE _id='markerB'").get();
      console.log("RESULT:" + JSON.stringify({ a: !!a, b: !!b }));
    `));

    var m = /RESULT:(\{.*\})/.exec(out);
    assert.ok(m, "phase C did not report a result — output was:\n" + out);
    var res = JSON.parse(m[1]);
    assert.strictEqual(res.a, true, "the pre-suppress data (markerA) must survive in db.enc");
    assert.strictEqual(res.b, false, "the stale tmpfs mutation (markerB) must NOT have been re-encrypted over db.enc after suppressExitEncrypt()");
  });
});
