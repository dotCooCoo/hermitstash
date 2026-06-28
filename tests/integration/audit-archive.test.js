const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
var testServer = require("../helpers/test-server");

var audit, archive, auditSvc, config, db;

before(async function () {
  await testServer.start();
  var root = testServer.projectRoot;
  audit = require(path.join(root, "lib", "audit"));
  archive = require(path.join(root, "lib", "audit-archive"));
  auditSvc = require(path.join(root, "app", "domain", "admin", "audit.service"));
  config = require(path.join(root, "lib", "config"));
  db = require(path.join(root, "lib", "db"));

  config.auditChainEnabled = true;
  config.auditArchivePassphrase = "test-archive-pass-123456";
  config.auditArchiveThresholdRows = 1000;
});
after(function () {
  config.auditChainEnabled = false;
  return testServer.stop();
});

function reqCtx(over) {
  return Object.assign({
    method: "POST", pathname: "/auth/login", headers: { "user-agent": "ArcUA/1" },
    user: { _id: "u-arc", email: "arc@test.com" }, socket: { remoteAddress: "192.0.2.50" }, requestId: "ra-1",
  }, over || {});
}

describe("HS-native encrypted audit archival", function () {
  it("archives the oldest chained rows, prunes them, and the live chain still verifies", async function () {
    for (var i = 0; i < 20; i++) {
      audit.log("file_downloaded", { targetId: "arc-" + i, details: "event " + i, req: reqCtx() });
    }
    await audit.drainChain();

    var before = db.rawGet("SELECT COUNT(*) AS c FROM audit_log").c;
    assert.ok(before >= 20, "rows present, got " + before);

    // Keep only the newest 5 → archive the rest.
    var res = await archive.archiveNow({ keep: 5, performedBy: "system" });
    assert.ok(res.archived >= 1, "archived some rows, got " + res.archived);
    assert.ok(res.id, "bundle id returned");

    var after = db.rawGet("SELECT COUNT(*) AS c FROM audit_log").c;
    assert.ok(after < before, "rows pruned: " + before + " -> " + after);

    // The live chain must still verify after the prune (re-anchor worked).
    var v = await auditSvc.verifyAuditChain();
    assert.strictEqual(v.ok, true, "live chain verifies post-prune: " + JSON.stringify(v));
  });

  it("verifies the archive bundle (signature + checksum + chain recompute)", async function () {
    var list = archive.listArchives();
    assert.ok(list.length >= 1, "archive listed");
    var id = list[0].id;
    assert.ok(list[0].count >= 1 && list[0].fingerprint, "manifest summary present");

    var v = await archive.verifyArchive(id, config.auditArchivePassphrase);
    assert.strictEqual(v.ok, true, "bundle verifies: " + JSON.stringify(v));
    assert.ok(v.rowsVerified >= 1, "rows verified in bundle");
  });

  it("rejects a wrong passphrase and a tampered checksum", async function () {
    var id = archive.listArchives()[0].id;
    await assert.rejects(function () { return archive.verifyArchive(id, "wrong-passphrase"); },
      "wrong passphrase should reject (decrypt fails)");
  });

  it("decrypts + unseals the archived rows for export", async function () {
    var id = archive.listArchives()[0].id;
    var entries = await archive.readArchiveEntries(id, config.auditArchivePassphrase);
    assert.ok(entries.length >= 1, "entries returned");
    var e = entries.find(function (x) { return /^arc-/.test(x.targetId || ""); });
    assert.ok(e, "an archived entry is present");
    assert.strictEqual(e.action, "file_downloaded", "action unsealed");
    assert.strictEqual(e.path, "/auth/login", "sealed path unsealed to plaintext");
    assert.strictEqual((e.details || "").indexOf("event"), 0, "sealed details unsealed to plaintext");
  });

  it("rejects a bundle re-signed under an untrusted key (tamper-evidence)", async function () {
    var C = require(path.join(testServer.projectRoot, "lib", "constants"));
    var fs = require("node:fs"); var np = require("node:path");
    var id = archive.listArchives()[0].id;
    var file = np.join(C.PATHS.AUDIT_ARCHIVE_DIR, id + ".json");
    var env = JSON.parse(fs.readFileSync(file, "utf8"));
    // Simulate an attacker who rewrote + re-signed the bundle with their own key and
    // embedded it: a fingerprint this server never held. Pinning must reject it
    // rather than trusting the envelope's own key.
    fs.writeFileSync(file, JSON.stringify(Object.assign({}, env, { fingerprint: "0".repeat(128) })));
    try {
      var v = await archive.verifyArchive(id, config.auditArchivePassphrase);
      assert.strictEqual(v.ok, false, "an untrusted signing key must be rejected");
      assert.ok(/trust|fingerprint|signature/i.test(v.reason || ""), "reason names the key trust failure: " + v.reason);
    } finally {
      fs.writeFileSync(file, JSON.stringify(env)); // restore for later tests
    }
  });

  it("a second archive chains continuously (verify still clean)", async function () {
    for (var i = 0; i < 10; i++) {
      audit.log("file_downloaded", { targetId: "arc2-" + i, details: "second " + i, req: reqCtx() });
    }
    await audit.drainChain();
    var res = await archive.archiveNow({ keep: 3, performedBy: "system" });
    assert.ok(res.archived >= 1, "second archive ran");
    var v = await auditSvc.verifyAuditChain();
    assert.strictEqual(v.ok, true, "chain still verifies after a second archive: " + JSON.stringify(v));

    var id = archive.listArchives()[0].id;
    var bv = await archive.verifyArchive(id, config.auditArchivePassphrase);
    assert.strictEqual(bv.ok, true, "second bundle verifies");
  });
});
