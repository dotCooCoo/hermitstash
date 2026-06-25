var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var b = require("../../lib/vendor/blamejs");

// Isolated test database — load all lib modules fresh against it.
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-webhook-svc-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var db = require("../../lib/db");
var webhooksRepo = require("../../app/data/repositories/webhooks.repo");
var webhookService = require("../../app/domain/integrations/webhook.service");
var expiryJob = require("../../app/jobs/expiry-cleanup.job");

before(async function () { await vault.init(); });

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

describe("webhook service — event allowlist (create)", function () {
  // Finding #8: the UI offered event names the server never fires, producing
  // silently-dead webhooks. create() now rejects any non-wildcard event not in
  // the known-event set at the boundary. The events check runs BEFORE the SSRF
  // host resolution, so an unknown event throws without any DNS lookup.

  it("rejects an unknown dot-separated event (the old UI value)", async function () {
    await assert.rejects(
      function () { return webhookService.create("https://example.com/hook", "bundle.finalized", "tester"); },
      function (err) { return /Unknown event/.test(err.message) && /bundle\.finalized/.test(err.message); }
    );
  });

  it("rejects a never-emitted event name", async function () {
    await assert.rejects(
      function () { return webhookService.create("https://example.com/hook", "file.uploaded", "tester"); },
      /Unknown event/
    );
  });

  it("rejects a mixed list where one event is unknown", async function () {
    await assert.rejects(
      function () { return webhookService.create("https://example.com/hook", "bundle_finalized,bogus_event", "tester"); },
      /Unknown event 'bogus_event'/
    );
  });

  it("does not reject the wildcard '*' on the event check (passes to URL validation)", async function () {
    // "*" is the wildcard — it must not be rejected by the event allowlist.
    // A bad host then fails at the SSRF/URL stage, proving the event check let
    // it through rather than throwing "Unknown event".
    await assert.rejects(
      function () { return webhookService.create("http://127.0.0.1/hook", "*", "tester"); },
      function (err) { return !/Unknown event/.test(err.message); }
    );
  });

  it("does not reject a known underscore event on the event check", async function () {
    // Known event passes the allowlist; the subsequent failure (if any) is not
    // an "Unknown event" error.
    await assert.rejects(
      function () { return webhookService.create("http://127.0.0.1/hook", "bundle_finalized,cert_expiring,cert_renewed", "tester"); },
      function (err) { return !/Unknown event/.test(err.message); }
    );
  });
});

describe("webhook service — dispatchSingle re-checks active (finding #9)", function () {
  it("resolves without delivering when the hook was toggled inactive", async function () {
    var hook = webhooksRepo.create({
      url: "https://example.com/hook",
      events: "*",
      secret: b.crypto.generateToken(32),
      active: "false", // toggled off after the job was enqueued
      createdBy: "tester",
      createdAt: new Date().toISOString(),
    });

    var before = db.webhookDeliveries.find({ webhookId: hook._id }).length;
    var result = await webhookService.dispatchSingle(hook._id, "bundle_finalized", { x: 1 }, 1);
    var after = db.webhookDeliveries.find({ webhookId: hook._id }).length;

    assert.strictEqual(result, undefined, "deliberate skip resolves (no retryable error)");
    assert.strictEqual(after, before, "no delivery row inserted for an inactive hook");
  });

  it("resolves without delivering when the hook no longer exists", async function () {
    var result = await webhookService.dispatchSingle("nonexistent-hook-id", "bundle_finalized", { x: 1 }, 1);
    assert.strictEqual(result, undefined);
  });
});

describe("expiry cleanup — webhook_deliveries retention (finding #10)", function () {
  it("exports cleanupWebhookDeliveries", function () {
    assert.strictEqual(typeof expiryJob.cleanupWebhookDeliveries, "function");
  });

  it("removes deliveries older than the retention window and preserves recent ones", function () {
    var old = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString(); // 31 days ago
    var recent = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(); // 1 day ago

    db.webhookDeliveries.insert({ _id: "wd-old-1", webhookId: "h1", event: "bundle_finalized", status: "success", statusCode: 200, error: null, attempts: 1, createdAt: old });
    db.webhookDeliveries.insert({ _id: "wd-old-2", webhookId: "h1", event: "bundle_finalized", status: "failed", statusCode: 500, error: "HTTP 500", attempts: 3, createdAt: old });
    db.webhookDeliveries.insert({ _id: "wd-recent-1", webhookId: "h1", event: "bundle_finalized", status: "success", statusCode: 200, error: null, attempts: 1, createdAt: recent });

    var removed = expiryJob.cleanupWebhookDeliveries();

    assert.ok(removed >= 2, "both old rows removed (got " + removed + ")");
    assert.strictEqual(db.webhookDeliveries.findOne({ _id: "wd-old-1" }), null);
    assert.strictEqual(db.webhookDeliveries.findOne({ _id: "wd-old-2" }), null);
    assert.ok(db.webhookDeliveries.findOne({ _id: "wd-recent-1" }), "recent row preserved");

    db.webhookDeliveries.remove({ _id: "wd-recent-1" });
  });

  it("returns 0 when there are no old deliveries", function () {
    var removed = expiryJob.cleanupWebhookDeliveries();
    assert.strictEqual(removed, 0);
  });
});
