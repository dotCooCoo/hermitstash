/**
 * D-3 — passkey login account-status / credential-existence oracle.
 *
 * routes/passkey.js used to check account status (suspended / pending) and throw
 * DISTINCT errors BEFORE verifyAuthentication, and returned "Unknown passkey"
 * for an unrecognized credentialId vs "Passkey verification failed" for a bad
 * assertion. A caller who knows a credentialId but holds no private key could
 * therefore learn account state (suspended/pending) and credential existence
 * without ever proving possession.
 *
 * The fix runs verifyAuthentication FIRST and applies the suspended/pending gate
 * only after a cryptographically-verified assertion, returning ONE
 * indistinguishable failure otherwise. This test drives three cases —
 * suspended account, active account, and an unknown credential — each with a
 * bogus (unverifiable) assertion, and asserts the caller-visible responses are
 * identical.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");

var b, db, credentialsRepo, replayNonce;
var activeCredIdB64url, suspendedCredIdB64url, unknownCredIdB64url;

before(async function () {
  await testServer.start();
  b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  db = require(path.join(testServer.projectRoot, "lib", "db"));
  credentialsRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "credentials.repo"));
  replayNonce = require(path.join(testServer.projectRoot, "lib", "replay-nonce"));

  function seedUserWithCred(email, status) {
    db.users.insert({
      email: email, displayName: email, role: "user", status: status,
      authType: "local", createdAt: new Date().toISOString(),
    });
    var u = db.users.findOne({ email: email });
    var rawId = b.crypto.generateBytes(32);
    credentialsRepo.create({
      userId: u._id,
      credentialId: rawId.toString("base64"),         // stored base64 (sealed at rest)
      publicKey: b.crypto.generateBytes(65).toString("base64"), // bogus COSE — verification fails regardless
      counter: 0,
      deviceType: "unknown",
      backedUp: 0,
      transports: null,
      createdAt: new Date().toISOString(),
    });
    return rawId.toString("base64url");                // what the client sends as body.id
  }

  activeCredIdB64url = seedUserWithCred("passkey-active@test.com", "active");
  suspendedCredIdB64url = seedUserWithCred("passkey-suspended@test.com", "suspended");
  unknownCredIdB64url = b.crypto.generateBytes(32).toString("base64url"); // matches no stored credential
});

after(function () { return testServer.stop(); });

function detail(res) {
  return (res.json && (res.json.detail || res.json.error)) || "";
}

// A fresh anonymous client mints a single-use challenge, then submits a bogus
// assertion carrying the given credentialId. The assertion never verifies, so
// the ONLY thing that can vary across cases is how the route reports failure.
async function verifyWithBogusAssertion(credIdB64url) {
  var client = new TestClient(testServer.baseUrl());
  await client.initApiKey();
  testServer.resetAllRateLimits();
  replayNonce._resetForTests(); // each fresh challenge must be claimable
  var opts = await client.post("/passkey/login/options", { json: {} });
  assert.strictEqual(opts.status, 200, "login/options should mint a challenge, got " + opts.status);
  var body = { id: credIdB64url, rawId: credIdB64url, response: {}, type: "public-key" };
  return client.post("/passkey/login/verify", { json: body });
}

describe("passkey login status/enumeration oracle (D-3)", function () {
  it("suspended, active, and unknown-credential all yield an indistinguishable failure", async function () {
    var active = await verifyWithBogusAssertion(activeCredIdB64url);
    var suspended = await verifyWithBogusAssertion(suspendedCredIdB64url);
    var unknown = await verifyWithBogusAssertion(unknownCredIdB64url);

    // None may authenticate; none may crash with 5xx.
    [active, suspended, unknown].forEach(function (r) {
      assert.notStrictEqual(r.status, 200, "a bogus assertion must never authenticate");
      assert.ok(r.status < 500, "verify must not crash with 5xx, got " + r.status + " / " + detail(r));
    });

    // The account-state gate must not fire before verification: a suspended
    // account must not be revealed as suspended pre-verification.
    assert.notStrictEqual(suspended.status, 403, "suspended state must not leak before verification");
    assert.ok(!/suspend/i.test(detail(suspended)), "response must not reveal suspended state: " + detail(suspended));

    // Every caller-visible signal is identical across the three cases.
    assert.strictEqual(active.status, suspended.status, "active vs suspended status must match (" + active.status + " vs " + suspended.status + ")");
    assert.strictEqual(active.status, unknown.status, "active vs unknown status must match (" + active.status + " vs " + unknown.status + ")");
    assert.strictEqual(detail(active), detail(suspended), "active vs suspended detail must match");
    assert.strictEqual(detail(active), detail(unknown), "active vs unknown detail must match");
  });
});
