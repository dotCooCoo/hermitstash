"use strict";

/**
 * Turning public uploads off has to stop content entering.
 *
 * PUBLIC_UPLOAD is the switch an operator reaches for when a portal is being
 * abused. Four routes read it — the page, the bundle init, the single-file
 * upload and the chunk upload — and only the first two had a test. The two
 * uncovered ones are the ones that carry the bytes: a switch that closed the
 * front door and left the file routes open would look like it worked, right up
 * until someone kept an init from before the flip and pushed content through.
 *
 * The property is "no new content enters", not "every route 403s". Finalizing
 * deliberately has no gate: it admits no bytes, it closes a bundle whose content
 * arrived while uploads were still permitted, and refusing it would strand a
 * half-finished upload rather than protect anything. That is asserted here so
 * the asymmetry reads as a decision rather than an omission.
 */

var { describe, it, before, after, afterEach } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var config;
var saved;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  await client.initApiKey();
  config = require(path.join(testServer.projectRoot, "lib", "config"));
  saved = config.publicUpload;
});
after(function () {
  if (config) config.publicUpload = saved;
  return testServer.stop();
});
afterEach(function () { config.publicUpload = saved; });

// Started while uploads are permitted, so the switch is the only thing that
// changes between the control and the case.
async function startBundle(name) {
  config.publicUpload = true;
  var init = await client.post("/drop/init", {
    json: { uploaderName: name, fileCount: 2, skippedCount: 0, skippedFiles: [] },
  });
  assert.strictEqual(init.status, 200, "precondition: a bundle starts while uploads are on");
  return init.json;
}

describe("with public uploads switched off", function () {
  it("refuses a single-file upload to a bundle started beforehand", async function () {
    var b = await startBundle("beforeflip");
    config.publicUpload = false;

    var res = await client.uploadFile("/drop/file/" + b.bundleId, "file", "after.txt",
      "content that must not land", { relativePath: "after.txt" });
    assert.strictEqual(res.status, 403,
      "holding an init from before the switch must not carry bytes through it");
  });

  it("refuses a chunk upload to a bundle started beforehand", async function () {
    // The chunked path is the one any upload of real size takes, so leaving it
    // open would leave the larger hole.
    //
    // The control is the SAME request with the switch on, sent first, and it has
    // to SUCCEED — not merely avoid a 403. Written as "not 403" it passed on a
    // 400 "File type not allowed: .bin", so the chunk never landed and the 403
    // after the flip proved nothing about the switch. An allowed extension is
    // what makes the control mean something.
    var b = await startBundle("beforeflipchunk");

    var allowed = await client.uploadFile("/drop/chunk/" + b.bundleId, "chunk", "big.txt",
      "chunk bytes", { fileId: "f1", chunkIndex: "0", totalChunks: "2", filename: "big.txt" });
    assert.strictEqual(allowed.status, 200,
      "precondition: this exact chunk request lands while uploads are on, got "
      + allowed.status + " " + JSON.stringify(allowed.json || allowed.text || "").slice(0, 160));

    config.publicUpload = false;
    var refused = await client.uploadFile("/drop/chunk/" + b.bundleId, "chunk", "big.txt",
      "chunk bytes", { fileId: "f1", chunkIndex: "1", totalChunks: "2", filename: "big.txt" });
    assert.strictEqual(refused.status, 403, "and refused once the switch is off");
  });

  it("refuses a new bundle and the page itself", async function () {
    config.publicUpload = false;
    assert.strictEqual((await client.get("/drop")).status, 403, "the page");
    assert.strictEqual((await client.post("/drop/init", {
      json: { uploaderName: "X", fileCount: 1, skippedCount: 0, skippedFiles: [] },
    })).status, 403, "a new bundle");
  });
});

describe("with public uploads on", function () {
  it("accepts the same requests the switch refuses", async function () {
    // The control. Four routes refusing everything would satisfy the cases above
    // without the switch doing anything at all.
    var b = await startBundle("switchon");
    var file = await client.uploadFile("/drop/file/" + b.bundleId, "file", "ok.txt",
      "content", { relativePath: "ok.txt" });
    assert.strictEqual(file.status, 200, "a single file lands while uploads are on");
    assert.strictEqual((await client.get("/drop")).status, 200, "and the page is served");
  });
});

describe("finalizing is gated too", function () {
  it("refuses to publish a bundle staged before the switch was flipped", async function () {
    // Finalize is the step that publishes: it mints the share URL, mails the
    // uploader, notifies the admins and fires the webhooks. An operator who
    // switches uploads off to stop abuse does not expect a bundle staged
    // moments earlier to go out anyway — which is the one case that could still
    // slip through, since with the switch off nothing new can be staged.
    var b = await startBundle("finalizeafter");
    var up = await client.uploadFile("/drop/file/" + b.bundleId, "file", "done.txt",
      "content", { relativePath: "done.txt" });
    assert.strictEqual(up.status, 200, "precondition: the content lands while uploads are on");

    config.publicUpload = false;
    var res = await client.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    });
    assert.strictEqual(res.status, 403,
      "publishing is part of the upload surface the switch turns off");
  });

  it("does not replay the refusal to a client retrying with an idempotency key", async function () {
    // The refusal must not be cached. The idempotency store persists 4xx as
    // well as 2xx — a client error is normally the caller's own mistake and
    // deterministic — but this one is the server's state, and the operator can
    // flip it back. Cached, the same key would be answered "disabled" for the
    // full twenty-four-hour window after uploads were re-enabled, turning a
    // pause into a day-long outage for that client.
    var b = await startBundle("idempotentresume");
    var up = await client.uploadFile("/drop/file/" + b.bundleId, "file", "idem.txt",
      "content", { relativePath: "idem.txt" });
    assert.strictEqual(up.status, 200, "precondition: the content lands");

    var key = "switch-replay-" + Date.now();
    config.publicUpload = false;
    var refused = await client.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
      headers: { "Idempotency-Key": key },
    });
    assert.strictEqual(refused.status, 403, "held while the switch is off");

    config.publicUpload = true;
    var retried = await client.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
      headers: { "Idempotency-Key": key },
    });
    assert.strictEqual(retried.status, 200,
      "the same key must finalize once uploads are on, not replay the cached refusal");
  });

  it("refuses a replay of an earlier success while the switch is off, and honours it after", async function () {
    // The accepted cost of checking in front of the cache. A client whose
    // finalize succeeded but whose response was lost gets "disabled" rather
    // than its share URL while the portal is off — and the same key is
    // answered from the cache the moment it is back on. Asserted so the
    // behaviour is a decision rather than something discovered in an incident.
    var b = await startBundle("replaywhileoff");
    await client.uploadFile("/drop/file/" + b.bundleId, "file", "replay.txt",
      "content", { relativePath: "replay.txt" });

    var key = "replay-success-" + Date.now();
    var first = await client.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
      headers: { "Idempotency-Key": key },
    });
    assert.strictEqual(first.status, 200, "precondition: it finalizes while uploads are on");
    var shareId = first.json.shareId;

    config.publicUpload = false;
    assert.strictEqual((await client.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
      headers: { "Idempotency-Key": key },
    })).status, 403, "the replay is refused while the portal is off");

    config.publicUpload = true;
    var afterOn = await client.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
      headers: { "Idempotency-Key": key },
    });
    assert.strictEqual(afterOn.status, 200, "and is served again once it is on");
    assert.strictEqual(afterOn.json.shareId, shareId,
      "with the same share id, so nothing was lost by the pause");
  });

  it("leaves a signed-in user's bundle alone", async function () {
    // The setting says "Allow anonymous file uploads (no login required)", so it
    // governs anonymous publication. A bundle with an owner is a signed-in
    // user's — or a sync client's — and taking the switch beyond what it says
    // would stop those callers completing work they had every right to.
    var owner = new TestClient(testServer.baseUrl());
    owner.clearCookies();
    await owner.initApiKey();
    await owner.post("/auth/register", {
      json: { displayName: "Switch Owner", email: "switchowner@test.com", password: "password123" },
    });

    config.publicUpload = true;
    var init = await owner.post("/drop/init", {
      json: { uploaderName: "Switch Owner", fileCount: 1, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(init.status, 200, "precondition: the owner starts a bundle");
    await owner.uploadFile("/drop/file/" + init.json.bundleId, "file", "owned.txt",
      "content", { relativePath: "owned.txt" });

    config.publicUpload = false;
    var res = await owner.post("/drop/finalize/" + init.json.bundleId, {
      json: { finalizeToken: init.json.finalizeToken },
    });
    assert.strictEqual(res.status, 200,
      "an owned bundle is not an anonymous upload and finalizes regardless of the switch");
  });

  it("publishes it once the switch goes back on", async function () {
    // Held, not destroyed. The staged upload is still there and still valid;
    // turning the portal back on lets it complete, so the switch is a pause
    // rather than a way to lose somebody's upload.
    var b = await startBundle("finalizeresume");
    var up = await client.uploadFile("/drop/file/" + b.bundleId, "file", "resume.txt",
      "content", { relativePath: "resume.txt" });
    assert.strictEqual(up.status, 200, "precondition: the content lands");

    config.publicUpload = false;
    assert.strictEqual((await client.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    })).status, 403, "held while the switch is off");

    config.publicUpload = true;
    var res = await client.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    });
    assert.strictEqual(res.status, 200, "and completes when it is on again");
    assert.strictEqual(res.json.success, true);
  });
});
