"use strict";

/**
 * Asking a stash page for an access code must not reveal who is on its allow
 * list.
 *
 * The endpoint is public and unauthenticated. If an allowed address answers
 * differently from one that is not — a different status, a different body, or
 * measurably later — then anyone can walk a customer's staff list against it.
 * The route is written to prevent that: both answers are the same generic
 * sentence, and the mail send is deliberately not awaited so an allowed address
 * does not respond slower than the one that returned immediately.
 *
 * tests/security/stash-email-allowlist.test.js covers the matching rule itself.
 * This covers what the endpoint gives back, which is the part an attacker sees.
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

var GATED = "gated-co";
var OPEN = "open-co";
var DISABLED = "disabled-co";

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());

  var stashRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "stash.repo"));
  stashRepo.create({
    name: "Gated Co", slug: GATED, enabled: "true", accessMode: "email",
    allowedEmails: "insider@gated.example,@partner.example",
    createdAt: new Date().toISOString(),
  });
  stashRepo.create({
    name: "Open Co", slug: OPEN, enabled: "true", accessMode: "open",
    createdAt: new Date().toISOString(),
  });
  stashRepo.create({
    name: "Disabled Co", slug: DISABLED, enabled: "false", accessMode: "email",
    allowedEmails: "insider@gated.example", createdAt: new Date().toISOString(),
  });
});

after(function () { return testServer.stop(); });

async function requestCode(slug, email) {
  // The endpoint is rate limited at 5 per 5 minutes, which these cases would
  // otherwise trip; reset so each asks a clean question.
  testServer.resetAllRateLimits();
  await client.initApiKey();
  return client.post("/stash/" + slug + "/request-code", { json: { email: email } });
}

describe("stash access-code requests do not reveal the allow list", function () {
  it("answers an allowed address and a stranger identically", async function () {
    // The property the whole endpoint is shaped around.
    var allowed = await requestCode(GATED, "insider@gated.example");
    var stranger = await requestCode(GATED, "nobody@elsewhere.example");

    assert.strictEqual(allowed.status, 200);
    assert.strictEqual(stranger.status, 200);
    assert.deepStrictEqual(allowed.json, stranger.json,
      "the two answers must be byte-identical, or the body is an oracle");
    assert.match(allowed.json.message, /If this email has access/);
  });

  it("answers a domain-allowed address the same way too", async function () {
    var viaDomain = await requestCode(GATED, "anyone@partner.example");
    var stranger = await requestCode(GATED, "anyone@notpartner.example");
    assert.deepStrictEqual(viaDomain.json, stranger.json);
  });

  it("says the same thing on a stash with no email gate at all", async function () {
    // An open page has no list to be on. Answering differently here would say
    // which pages are gated, which is its own disclosure.
    var open = await requestCode(OPEN, "anyone@example.com");
    var gated = await requestCode(GATED, "nobody@elsewhere.example");
    assert.strictEqual(open.status, 200);
    assert.deepStrictEqual(open.json, gated.json);
  });

  it("does not distinguish a disabled stash from one that never existed", async function () {
    var disabled = await requestCode(DISABLED, "insider@gated.example");
    var missing = await requestCode("no-such-stash", "insider@gated.example");
    assert.strictEqual(disabled.status, 404);
    assert.strictEqual(missing.status, 404);
    // The status alone is not the answer an attacker reads. A body saying
    // "disabled" against one saying "not found" tells them the page exists,
    // which is the fact being withheld.
    assert.deepStrictEqual(disabled.json, missing.json,
      "the refusal bodies must match, or the difference is the disclosure");
    assert.strictEqual(disabled.headers["content-type"], missing.headers["content-type"],
      "and so must the content type");
  });

  it("refuses a malformed address before it consults anything", async function () {
    var res = await requestCode(GATED, "not-an-email");
    assert.strictEqual(res.status, 400);
  });

  it("refuses a missing address the same way", async function () {
    testServer.resetAllRateLimits();
    await client.initApiKey();
    var res = await client.post("/stash/" + GATED + "/request-code", { json: {} });
    assert.strictEqual(res.status, 400);
  });

  it("is rate limited, so the identical answers cannot be walked at speed", async function () {
    // Indistinguishable answers still leak if an attacker may ask without
    // limit. The cap is what turns the oracle from cheap into impractical.
    testServer.resetAllRateLimits();
    await client.initApiKey();
    var statuses = [];
    for (var i = 0; i < 7; i++) {
      var r = await client.post("/stash/" + GATED + "/request-code",
        { json: { email: "probe" + i + "@elsewhere.example" } });
      statuses.push(r.status);
    }
    assert.ok(statuses.indexOf(429) !== -1,
      "the endpoint must start refusing within a short burst; saw " + statuses.join(","));
    testServer.resetAllRateLimits();
  });
});
