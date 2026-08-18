"use strict";

/**
 * What a stash slug is allowed to be, and what a stash's access mode ends up as.
 *
 * The slug becomes a public path — /stash/<slug> — so the rules on it are not
 * cosmetic. A slug matching a system route would shadow it, and the reserved
 * check is the only thing standing between an admin typo and a customer page
 * mounted over an application route. A slug outside the permitted character set
 * would put arbitrary text into a URL that other code goes on to build links
 * from.
 *
 * The access mode is the other half: it decides whether a visitor needs a
 * password, an allow-listed email, both, or nothing. It is derived rather than
 * stored directly, so "open" is what you get when neither gate was accepted —
 * including when a gate was supplied but silently discarded as unparseable,
 * which is the case worth pinning.
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());

  var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
  var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
  var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
  users.insert({
    email: vault.seal("slugadmin@test.com"), emailHash: hashEmail("slugadmin@test.com"),
    displayName: vault.seal("Slug Admin"), passwordHash: await b.auth.password.hash("adminpass123"),
    authType: "local", role: "admin", status: "active", createdAt: new Date().toISOString(),
  });
});

after(function () { return testServer.stop(); });

async function loginAdmin() {
  client.clearCookies();
  await client.initApiKey();
  testServer.resetAllRateLimits();
  var r = await client.post("/auth/login", { json: { email: "slugadmin@test.com", password: "adminpass123" } });
  assert.strictEqual(r.json.success, true, "admin login should succeed");
}

function create(body) {
  return client.post("/admin/stash/create", { json: body });
}

describe("stash slug rules", function () {
  before(loginAdmin);

  it("accepts a plain lowercase slug with an interior hyphen", async function () {
    var res = await create({ name: "Good One", slug: "good-one" });
    assert.strictEqual(res.json.success, true, JSON.stringify(res.json));
  });

  it("requires both a name and a slug", async function () {
    assert.strictEqual((await create({ slug: "no-name" })).status, 400);
    assert.strictEqual((await create({ name: "No Slug" })).status, 400);
  });

  it("refuses a one-character slug", async function () {
    // Short slugs collide with the reserved set and read as typos.
    assert.strictEqual((await create({ name: "Too Short", slug: "a" })).status, 400);
  });

  it("refuses anything outside lowercase alphanumerics and hyphens", async function () {
    // The slug lands in a public URL other code builds links from. Case is NOT
    // in this list: the route lowercases before validating, so "UPPER" is
    // normalised rather than refused (pinned in the trimming case below).
    var bad = ["Has Space", "under_score", "dot.slug", "slash/slug", "percent%20", "uniçode"];
    for (var i = 0; i < bad.length; i++) {
      var res = await create({ name: "Bad", slug: bad[i] });
      assert.strictEqual(res.status, 400, JSON.stringify(bad[i]) + " must be refused");
    }
  });

  it("refuses leading and trailing hyphens, and doubled ones", async function () {
    assert.strictEqual((await create({ name: "Lead", slug: "-lead" })).status, 400);
    assert.strictEqual((await create({ name: "Trail", slug: "trail-" })).status, 400);
    assert.strictEqual((await create({ name: "Double", slug: "a--b" })).status, 400);
  });

  it("refuses a slug that would shadow a system route", async function () {
    // Reserved means the FIRST path segment of a registered route. Stash pages
    // live under /stash/<slug>, so one of these could not shadow anything today
    // — the check is defence in depth against the day a slug is mounted at the
    // top level. Each of these is a real registered segment; "api" deliberately
    // is not one (API routes are nested under /admin/api), which is why it is
    // absent rather than expected to fail.
    var reservedSegments = ["admin", "auth", "dashboard", "stash", "drop", "teams"];
    var accepted = [];
    for (var i = 0; i < reservedSegments.length; i++) {
      var res = await create({ name: "Shadow", slug: reservedSegments[i] });
      if (res.status !== 400) accepted.push(reservedSegments[i] + " -> " + res.status);
    }
    assert.deepStrictEqual(accepted, [],
      "every registered top-level segment must be refused as a slug");
  });

  it("refuses a slug already taken", async function () {
    await create({ name: "First", slug: "taken-slug" });
    var again = await create({ name: "Second", slug: "taken-slug" });
    assert.strictEqual(again.status, 400);
  });

  it("lowercases and trims what it is given rather than refusing it", async function () {
    var res = await create({ name: "  Spaced  ", slug: "  Mixed-Case  " });
    assert.strictEqual(res.json.success, true, JSON.stringify(res.json));
    var stashRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "stash.repo"));
    assert.ok(stashRepo.findBySlug("mixed-case"), "stored lowercased and trimmed");
  });
});

describe("stash access mode", function () {
  before(loginAdmin);

  function modeOf(slug) {
    var stashRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "stash.repo"));
    var s = stashRepo.findBySlug(slug);
    assert.ok(s, "stash " + slug + " should exist");
    return s.accessMode;
  }

  it("is open when neither gate is set", async function () {
    await create({ name: "Open", slug: "mode-open" });
    assert.strictEqual(modeOf("mode-open"), "open");
  });

  it("is password when only a password is set", async function () {
    await create({ name: "Pw", slug: "mode-pw", password: "hunter2" });
    assert.strictEqual(modeOf("mode-pw"), "password");
  });

  it("is email when only an allow list is set", async function () {
    await create({ name: "Em", slug: "mode-email", allowedEmails: "a@example.com" });
    assert.strictEqual(modeOf("mode-email"), "email");
  });

  it("is both when both are set", async function () {
    await create({ name: "Both", slug: "mode-both", password: "hunter2", allowedEmails: "@example.com" });
    assert.strictEqual(modeOf("mode-both"), "both");
  });

  it("refuses a password too short to be one", async function () {
    assert.strictEqual((await create({ name: "Short", slug: "mode-shortpw", password: "abc" })).status, 400);
  });

  it("keeps a domain entry and a full address, and drops what is neither", async function () {
    await create({
      name: "Mixed", slug: "mode-mixed",
      allowedEmails: "@corp.example, person@example.com, not-an-email, , @",
    });
    var stashRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "stash.repo"));
    var s = stashRepo.findBySlug("mode-mixed");
    var kept = String(s.allowedEmails || "").split(",");
    assert.deepStrictEqual(kept, ["@corp.example", "person@example.com"]);
    assert.strictEqual(s.accessMode, "email");
  });

  it("falls back to open when every allow-list entry was unusable", async function () {
    // The case worth pinning: an admin sets a gate, every entry is discarded as
    // unparseable, and the page ends up public. It should not read as "email".
    await create({ name: "Junk", slug: "mode-junk", allowedEmails: "not-an-email, also-bad, @" });
    assert.strictEqual(modeOf("mode-junk"), "open",
      "a gate that parsed to nothing is not a gate — the mode must say the page is open");
  });
});
