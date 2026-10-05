var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var b = require("../../lib/vendor/blamejs");

// Isolated test database — load all lib modules fresh against it.
var testId = b.crypto.generateToken(4);
var scratch = require("../helpers/isolate-db");
var testDbPath = path.join(scratch.dir, "test-webhook-sig-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var webhooksRepo = require("../../app/data/repositories/webhooks.repo");
var webhookService = require("../../app/domain/integrations/webhook.service");

// The cache wipe above dropped the blamejs instance `b` was bound to; re-acquire
// it so the object we stub (b.httpClient) is the very instance webhook.service
// loaded, not a stale sibling copy.
b = require("../../lib/vendor/blamejs");

before(async function () { await vault.init(); });

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

// F-7: an outbound webhook was signed with a bare, unversioned body HMAC
// (X-Webhook-Signature) that carried no timestamp binding — a captured delivery
// could be replayed indefinitely, and there was no version prefix for algorithm
// agility. Delivery now signs with StandardWebhooks (standardwebhooks.com):
// the HMAC covers `<webhook-id>.<webhook-timestamp>.<body>` and ships as the
// versioned `v1,<base64>` scheme alongside webhook-id / webhook-timestamp headers.
describe("webhook dispatch — StandardWebhooks signature (F-7)", function () {
  it("emits webhook-id/webhook-timestamp/webhook-signature and drops the legacy X-Webhook-Signature header", async function () {
    var secret = b.crypto.generateToken(32);
    var hook = webhooksRepo.create({
      url: "https://example.com/hook",
      events: "*",
      secret: secret,
      active: "true",
      createdBy: "tester",
      createdAt: new Date().toISOString(),
    });

    // Stub the framework HTTP client so we capture the request without a real
    // delivery (the client's SSRF gate would reject anything reachable anyway).
    var captured = null;
    var orig = b.httpClient.request;
    b.httpClient.request = function (opts) { captured = opts; return Promise.resolve({ statusCode: 200 }); };
    try {
      await webhookService.dispatchSingle(hook._id, "bundle_finalized", { x: 1 }, 1);
    } finally {
      b.httpClient.request = orig;
    }

    assert.ok(captured, "httpClient.request was called");
    assert.strictEqual(captured.headers["X-Webhook-Signature"], undefined, "legacy bare-HMAC header removed");
    assert.ok(captured.headers["webhook-id"], "webhook-id header present");
    assert.ok(captured.headers["webhook-timestamp"], "webhook-timestamp header present");
    assert.ok(/^v1,/.test(captured.headers["webhook-signature"] || ""), "versioned v1 signature scheme");

    // The emitted signature verifies against the shared secret over id.timestamp.body.
    var v = b.standardWebhooks.verify({
      headers: captured.headers,
      body: captured.body,
      secret: Buffer.from(secret, "utf8"),
    });
    assert.strictEqual(v.valid, true, "signature verifies under StandardWebhooks");

    // Replay/tamper guard: a body swap must break verification.
    assert.throws(function () {
      b.standardWebhooks.verify({
        headers: captured.headers,
        body: captured.body + "tampered",
        secret: Buffer.from(secret, "utf8"),
      });
    }, /signature/i, "tampered body fails verification");
  });

  it("omits signature headers when the hook has no secret", async function () {
    var hook = webhooksRepo.create({
      url: "https://example.com/hook",
      events: "*",
      secret: "",
      active: "true",
      createdBy: "tester",
      createdAt: new Date().toISOString(),
    });

    var captured = null;
    var orig = b.httpClient.request;
    b.httpClient.request = function (opts) { captured = opts; return Promise.resolve({ statusCode: 200 }); };
    try {
      await webhookService.dispatchSingle(hook._id, "bundle_finalized", { x: 1 }, 1);
    } finally {
      b.httpClient.request = orig;
    }

    assert.ok(captured, "httpClient.request was called");
    assert.strictEqual(captured.headers["webhook-signature"], undefined, "no signature header without a secret");
    assert.strictEqual(captured.headers["Content-Type"], "application/json");
  });
});

describe("webhook dispatch relies on the b.standardWebhooks.sign contract", function () {
  it("sign accepts the UTF-8 bytes of a stored webhook secret and returns the three standard headers", function () {
    // webhook.service create() stores b.crypto.generateToken(32), which is 64
    // hex characters.
    var secret = Buffer.from(b.crypto.generateToken(32), "utf8");
    assert.strictEqual(secret.length, 64);
    var signed = b.standardWebhooks.sign({ body: '{"event":"bundle_finalized"}', secret: secret });
    assert.deepStrictEqual(Object.keys(signed.headers).sort(),
      ["webhook-id", "webhook-signature", "webhook-timestamp"]);
    assert.match(signed.headers["webhook-id"], /^msg_[0-9a-f]+$/);
    assert.match(signed.headers["webhook-timestamp"], /^[0-9]+$/);
    assert.match(signed.headers["webhook-signature"], /^v1,[A-Za-z0-9+/]+={0,2}$/);
  });

  it("sign refuses a secret shorter than 32 bytes", function () {
    assert.throws(function () {
      b.standardWebhooks.sign({ body: "{}", secret: Buffer.alloc(31) });
    }, function (e) { return e.code === "standard-webhooks/bad-secret"; });
  });

  it("the signature covers the timestamp header it is sent with", function () {
    var secret = Buffer.from(b.crypto.generateToken(32), "utf8");
    var ts = Math.floor(Date.now() / 1000) - 10;
    var signed = b.standardWebhooks.sign({ body: "{}", secret: secret, timestamp: ts });
    var moved = Object.assign({}, signed.headers, { "webhook-timestamp": String(ts + 1) });
    assert.throws(function () {
      b.standardWebhooks.verify({ headers: moved, body: "{}", secret: secret });
    }, function (e) { return e.code === "standard-webhooks/bad-signature"; });
  });
});
