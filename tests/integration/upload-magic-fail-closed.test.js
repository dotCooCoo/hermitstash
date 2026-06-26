/**
 * Regression: the magic-byte / polyglot validation gate in the upload handler
 * must fail CLOSED on an internal error. The gate is wrapped in try/catch; if
 * an exception in validateMagicBytes is swallowed and falls through to the
 * save, a defense-in-depth check silently becomes an accept. This exercises the
 * single-file /drop/file path with validateMagicBytes monkeypatched to throw
 * and asserts the upload is REJECTED and an UPLOAD_REJECTED audit row lands.
 */
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var b = require("../../lib/vendor/blamejs");
var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
});

after(function () { return testServer.stop(); });

// Poll the audit_log for a row matching the predicate — audit.log is
// fire-and-forget (chained insert resolves off the request lifecycle), so the
// row may land a tick or two after the HTTP response. Read through the db
// accessor (auto-unseals action/details) and filter in JS.
async function findAuditRow(predicate) {
  var { auditLog } = require(path.join(testServer.projectRoot, "lib", "db"));
  for (var attempt = 0; attempt < 50; attempt++) {
    var rows = auditLog.find({});
    var hit = rows.find(predicate);
    if (hit) return hit;
    await b.safeAsync.sleep(20, { unref: true });
  }
  return null;
}

describe("upload magic-byte gate fails closed", function () {
  var bundleId;

  it("POST /drop/init creates a bundle", async function () {
    await client.initApiKey();
    var res = await client.post("/drop/init", {
      json: { uploaderName: "Tester", uploaderEmail: "tester@test.com", fileCount: 1, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(res.status, 200);
    assert.ok(res.json.bundleId);
    bundleId = res.json.bundleId;
  });

  it("rejects the upload and audits it when magic-byte validation throws", async function () {
    var uploadValidator = require(path.join(testServer.projectRoot, "app", "http", "validators", "upload.validator"));
    var original = uploadValidator.validateMagicBytes;
    uploadValidator.validateMagicBytes = function () {
      throw new Error("simulated internal validation failure");
    };

    try {
      var res = await client.uploadFile(
        "/drop/file/" + bundleId, "file", "boom.txt",
        "Hello world content", { relativePath: "boom.txt" }
      );

      // Fail closed: the request must be rejected, not saved.
      assert.notStrictEqual(res.status, 200, "upload must not succeed when the magic-byte gate throws");
      assert.ok(!(res.json && res.json.success), "response must not report success");

      // The file must NOT appear in the bundle.
      var { files } = require(path.join(testServer.projectRoot, "lib", "db"));
      var stored = files.find({ bundleId: bundleId });
      assert.strictEqual(stored.length, 0, "no file record should be created on a failed magic-byte gate");

      // An UPLOAD_REJECTED audit row must have been written.
      var row = await findAuditRow(function (r) {
        return r.action === "upload_rejected" &&
          r.targetId === bundleId &&
          typeof r.details === "string" &&
          r.details.indexOf("Could not validate file content.") !== -1;
      });
      assert.ok(row, "an UPLOAD_REJECTED audit row should be written on the fail-closed path");
    } finally {
      uploadValidator.validateMagicBytes = original;
    }
  });
});
