"use strict";

/**
 * The two admin operations that take a passphrase refuse before they act.
 *
 * POST /admin/backup/run encrypts a copy of the database and the uploads to
 * off-site storage under the passphrase it is given. POST
 * /admin/security/unseal/vault-passphrase writes the vault key back to disk in
 * plaintext. Each demands a passphrase, and each verifies it before doing
 * anything — a backup written under an unverified passphrase is a backup nobody
 * can restore, and it fails silently, because the write succeeds.
 *
 * Only the refusals are exercised here. Both success paths reach out to storage
 * the test has no business creating, and the refusals are where the value is
 * anyway: they are what stands between an empty field and an unrecoverable
 * archive.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var config;
var savedHash;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  config = require(path.join(testServer.projectRoot, "lib", "config"));
  savedHash = config.backup && config.backup.passphraseHash;

  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/register", {
    json: { displayName: "Gate Admin", email: "gateadmin@test.com", password: "password123" },
  });
});
after(async function () {
  if (config && config.backup) config.backup.passphraseHash = savedHash;
  await testServer.stop();
});

async function asAdmin() {
  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/login", { json: { email: "gateadmin@test.com", password: "password123" } });
}

describe("running a backup", function () {
  it("refuses an absent or blank passphrase", async function () {
    await asAdmin();
    // Whitespace is trimmed before the check, so a field of spaces is empty.
    for (const body of [{}, { passphrase: "" }, { passphrase: "   " }, { passphrase: null }]) {
      var res = await client.post("/admin/backup/run", { json: body });
      assert.strictEqual(res.status, 400, "expected a refusal for " + JSON.stringify(body));
      assert.match(String(res.json.detail || res.json.error || ""), /passphrase is required/i);
    }
  });

  it("refuses a passphrase that does not match the configured one", async function () {
    // Without this the backup is written under whatever was typed, and the
    // mistake only surfaces at restore, when the archive is the only copy left.
    var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
    config.backup.passphraseHash = await b.auth.password.hash("the-real-passphrase");
    await asAdmin();

    var res = await client.post("/admin/backup/run", { json: { passphrase: "not-the-real-one" } });
    assert.strictEqual(res.status, 401, "a wrong passphrase is an authentication failure, not a bad request");
    assert.match(String(res.json.detail || res.json.error || ""), /incorrect backup passphrase/i);
  });

  it("is refused for a signed-in non-admin", async function () {
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/register", {
      json: { displayName: "Ordinary", email: "ordinary-backup@test.com", password: "password123" },
    });
    var res = await client.post("/admin/backup/run", { json: { passphrase: "the-real-passphrase" } });
    assert.strictEqual(res.status, 403);
  });
});

describe("unsealing the vault key", function () {
  it("refuses anything that is not a non-empty string", async function () {
    // The value is turned into a Buffer and used as key material; a number or a
    // null would become something unintended rather than being rejected.
    await asAdmin();
    for (const body of [{}, { passphrase: "" }, { passphrase: null }, { passphrase: 12345 },
      { passphrase: [] }, { passphrase: { toString: 1 } }]) {
      var res = await client.post("/admin/security/unseal/vault-passphrase", { json: body });
      assert.strictEqual(res.status, 400, "expected a refusal for " + JSON.stringify(body));
      assert.match(String(res.json.detail || res.json.error || ""), /passphrase is required/i);
    }
  });

  it("is refused for a signed-in non-admin", async function () {
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/register", {
      json: { displayName: "Ordinary Two", email: "ordinary-unseal@test.com", password: "password123" },
    });
    var res = await client.post("/admin/security/unseal/vault-passphrase", {
      json: { passphrase: "anything" },
    });
    assert.strictEqual(res.status, 403);
  });
});
