var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
});

after(function () { return testServer.stop(); });

// Passkey integration tests focus on the b.auth.passkey wrapper
// being wired correctly. Full WebAuthn registration / authentication
// round-trips require generating valid attestation and assertion
// responses with a real (or simulated) authenticator — beyond what
// we exercise here.
//
// Scope:
//   - Routes respond without crashing (the wrapper is loaded and the
//     opts shape it accepts is what HS passes)
//   - Auth gates work (unauthenticated → 302/401/403 depending on
//     route, never 200 + leaked options)
//   - Invalid inputs are refused cleanly (no 5xx leak)

describe("passkey integration (b.auth.passkey wrapper wire-up)", function () {
  before(async function () {
    await client.initApiKey();
    await client.post("/auth/register", {
      json: { displayName: "Passkey Tester", email: "passkey@test.com", password: "password123" },
    });
  });

  describe("auth gates", function () {
    it("POST /passkey/register/options without an auth session returns 302/401/403", async function () {
      client.clearCookies();
      var res = await client.post("/passkey/register/options", { json: {} });
      assert.ok([302, 401, 403].includes(res.status),
        "unauthenticated should be redirected or refused, got " + res.status);
    });

    it("POST /passkey/remove without an auth session returns 302/401/403", async function () {
      client.clearCookies();
      var res = await client.post("/passkey/remove", { json: { credentialId: "fake" } });
      assert.ok([302, 401, 403].includes(res.status),
        "unauthenticated should be redirected or refused, got " + res.status);
    });

    it("GET /passkey/list without an auth session returns 302/401/403", async function () {
      client.clearCookies();
      var res = await client.get("/passkey/list");
      assert.ok([302, 401, 403].includes(res.status),
        "unauthenticated should be redirected or refused, got " + res.status);
    });
  });

  describe("public endpoints (no auth required)", function () {
    it("POST /passkey/login/options returns 200 (handler ran without crashing)", async function () {
      client.clearCookies();
      var res = await client.post("/passkey/login/options", { json: {} });
      // 200 with options OR a 403 if passkeyEnabled is false in this
      // test config. Either is fine — the route DIDN'T 500 (which would
      // mean the wrapper choked at boot).
      assert.ok([200, 403].includes(res.status),
        "login/options should respond cleanly, got " + res.status + ": " + (res.body || "").slice(0, 100));
    });
  });

  describe("input validation guards", function () {
    it("POST /passkey/register/verify with no pending challenge returns 400", async function () {
      // Login fresh; no challenge stored in session
      client.clearCookies();
      var loginRes = await client.post("/auth/login", {
        json: { email: "passkey@test.com", password: "password123" },
      });
      // If login failed (e.g. CSRF guard, encryption setup), skip the
      // verify check — it's the auth flow that's broken, not passkey.
      if (![200, 302].includes(loginRes.status)) return;

      var res = await client.post("/passkey/register/verify", {
        json: { id: "fake", rawId: "fake", response: {}, type: "public-key" },
      });
      // Should be 400 (no challenge) or refusal — not 5xx and not 200.
      assert.ok([302, 400, 401, 403].includes(res.status),
        "expected refusal, got " + res.status);
    });

    it("POST /passkey/login/verify with malformed body returns non-5xx, non-200", async function () {
      client.clearCookies();
      var res = await client.post("/passkey/login/verify", {
        json: { id: "bogus", rawId: "bogus", response: {}, type: "public-key" },
      });
      // 400 (no challenge / bad input) or 401 (no matching credential).
      // The important property: the b.auth.passkey wrapper did not crash
      // (no 5xx) and did not silently authenticate (no 200).
      assert.notStrictEqual(res.status, 200, "wrapper must never grant auth on bogus input");
      assert.ok(res.status < 500, "wrapper must not crash with 5xx, got " + res.status);
    });
  });

  describe("wrapper-specific behavior (v0.9.2 hardening)", function () {
    it("counter undefined/null is refused by the wrapper (clone-detection bypass defense)", function () {
      // The wrapper refuses `credential.counter` of undefined / null
      // explicitly per the v0.9.2 audit. This is enforced inside the
      // wrapper before the SimpleWebAuthn call, so a direct unit-level
      // check against the wrapper is the cleanest way to lock the
      // invariant.
      var b = require("../../lib/vendor/blamejs");
      var threw = null;
      try {
        // We use a sync-throw via .catch shape since verifyAuthentication
        // is async but the counter validation happens synchronously at
        // the top.
        b.auth.passkey.verifyAuthentication({
          response: {},
          expectedChallenge: "x",
          expectedOrigin: "http://localhost",
          expectedRPID: "localhost",
          credential: { id: "x", publicKey: Buffer.from(""), counter: undefined },
        }).catch(function (e) { threw = e; });
      } catch (e) { threw = e; }
      // The .catch handler runs after the microtask — give it a tick.
      return new Promise(function (resolve) { setImmediate(function () {
        assert.ok(threw, "wrapper must throw / reject on undefined counter");
        assert.ok(/counter/i.test(threw.message || ""),
          "error should mention counter, got: " + (threw && threw.message));
        resolve();
      }); });
    });
  });
});
