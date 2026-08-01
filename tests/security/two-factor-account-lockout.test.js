/**
 * D-4 — /2fa/verify per-account failed-attempt ceiling (IP-rotation resistant).
 *
 * The route's only brute-force defense used to be a per-IP rate limit, which an
 * attacker holding one pending-2FA session evades by rotating source IPs. A
 * per-account (per-pending-session) failure counter now tears the pending 2FA
 * session down after MAX_2FA_ATTEMPTS failures, independent of source IP.
 *
 * The test simulates IP rotation by resetting the per-IP limiter before each
 * attempt (each rotation = a fresh per-IP bucket), so only the per-account
 * ceiling can stop the guessing.
 *
 * BONUS (same file) — routes/two-factor.js dropped the redundant
 * vault.unseal(user.totpSecret): totpSecret is in the users seal list
 * (lib/field-crypto.js), so usersRepo.findById already returns it unsealed. The
 * happy-path test below proves the removal didn't break verification, and
 * asserts totpSecret reads back as plaintext (not ciphertext).
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");

var b, usersRepo, replayNonce;
var totp = require(path.join(testServer.projectRoot, "lib", "totp"));
var totpSecret;

function getCurrentCode(secret) {
  return totp.computeCode(secret, Math.floor(Date.now() / 30000));
}

function detail(res) {
  return (res.json && (res.json.detail || res.json.error)) || "";
}

before(async function () {
  await testServer.start();
  b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  usersRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "users.repo"));
  replayNonce = require(path.join(testServer.projectRoot, "lib", "replay-nonce"));

  // Register (auto-logs in) then enable 2FA so login requires a second factor.
  var client = new TestClient(testServer.baseUrl());
  await client.initApiKey();
  await client.post("/auth/register", {
    json: { displayName: "Lockout User", email: "lockout@test.com", password: "password123" },
  });
  var setup = await client.post("/2fa/setup", { json: {} });
  totpSecret = setup.json.secret;
  var confirm = await client.post("/2fa/confirm", { json: { code: getCurrentCode(totpSecret) } });
  assert.strictEqual(confirm.json.success, true, "2FA enrollment should succeed");
});

after(function () { return testServer.stop(); });

describe("2FA per-account lockout (D-4)", function () {
  it("N failed codes for one pending user invalidate the pending session regardless of IP", async function () {
    var client = new TestClient(testServer.baseUrl());
    await client.initApiKey();
    testServer.resetAllRateLimits();
    var login = await client.post("/auth/login", { json: { email: "lockout@test.com", password: "password123" } });
    assert.strictEqual(login.json.requires2fa, true, "login should be pending 2FA");

    // Five wrong codes. Resetting the per-IP limiter before each attempt is the
    // in-test equivalent of an attacker rotating IPs (a fresh bucket each time),
    // so the per-IP limit never trips — only the per-account ceiling can.
    var last;
    for (var i = 0; i < 5; i++) {
      testServer.resetAllRateLimits();
      last = await client.post("/2fa/verify", { json: { code: "000000" } });
      assert.notStrictEqual(last.status, 200, "a wrong code must never authenticate (attempt " + (i + 1) + ")");
    }

    // The ceiling was crossed — the final failure reports the pending session
    // was torn down (NOT a plain "Invalid 2FA code").
    assert.ok(/log in again|too many/i.test(detail(last)),
      "final failed attempt should report the pending session was invalidated, got: " + detail(last));

    // A subsequent verify with the CORRECT code and a fresh rate-limit bucket
    // must still be rejected: the pending 2FA session no longer exists.
    testServer.resetAllRateLimits();
    replayNonce._resetForTests();
    var recovered = await client.post("/2fa/verify", { json: { code: getCurrentCode(totpSecret) } });
    assert.notStrictEqual(recovered.status, 200, "no valid pending session — a correct code must not authenticate");
    assert.notStrictEqual(recovered.json && recovered.json.success, true, "must not grant a session");
    assert.ok(/no pending|log in again/i.test(detail(recovered)),
      "should indicate no pending 2FA verification, got: " + detail(recovered));
  });

  // BONUS — the redundant-unseal removal must not break verification.
  it("a valid TOTP code still completes 2FA, and totpSecret reads back unsealed", async function () {
    var client = new TestClient(testServer.baseUrl());
    await client.initApiKey();
    testServer.resetAllRateLimits();
    var login = await client.post("/auth/login", { json: { email: "lockout@test.com", password: "password123" } });
    assert.strictEqual(login.json.requires2fa, true);

    // Clear replay state so the current code verifies within this window.
    var u = usersRepo.findByEmail("lockout@test.com");
    usersRepo.update(u._id, { $set: { totpLastStep: null } });
    replayNonce._resetForTests();
    testServer.resetAllRateLimits();

    var res = await client.post("/2fa/verify", { json: { code: getCurrentCode(totpSecret) } });
    assert.strictEqual(res.json && res.json.success, true, "correct code must complete 2FA (unseal removal must not break verify)");

    // Determination: totpSecret is auto-unsealed on read (users seal list), so
    // findById returns the plaintext secret — NOT a 'vault:' / 'vault.aad:'
    // ciphertext. This is exactly what made the second vault.unseal() redundant.
    var fresh = usersRepo.findByEmail("lockout@test.com");
    assert.strictEqual(fresh.totpSecret, totpSecret, "findById must return totpSecret already unsealed (== plaintext)");
    assert.ok(!/^vault[:.]/.test(String(fresh.totpSecret)), "totpSecret must not read back as ciphertext");
  });
});
