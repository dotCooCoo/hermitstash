/**
 * Sign in with Tailscale — end-to-end over the real HTTP route.
 *
 * The test client connects over loopback, so the peer-gate on the
 * Tailscale-User-* family trusts it exactly as it would the in-container
 * `tailscale serve` proxy. This exercises the full path:
 *   trusted header family → tailscale.identityFrom → resolveTailscaleUser
 *   (admin-gated provision) → sessionService.completeLogin → session.
 * The per-request peer strip (forged headers from a non-loopback peer) is
 * covered at the unit level in tests/unit/tailscale-sso.test.js.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");

before(async function () {
  await testServer.start({
    env: {
      TAILSCALE_ENABLED: "true",
      TAILSCALE_SSO: "true",
      TAILSCALE_SSO_ALLOWLIST: "e2e-allowed@example.com",
    },
  });
});

after(function () { return testServer.stop(); });

describe("Sign in with Tailscale — HTTP route", function () {
  it("provisions + signs in an allowlisted tailnet user from a loopback serve request", async function () {
    var client = new TestClient(testServer.baseUrl());
    var res = await client.get("/auth/tailscale", { headers: {
      "Tailscale-User-Login": "e2e-allowed@example.com",
      "Tailscale-User-Name": "E2E Allowed",
    }});
    assert.strictEqual(res.status, 302, "sign-in redirects");
    assert.strictEqual(res.location, "/dashboard", "an allowlisted tailnet user gets a full session");

    // The session reaches an auth-gated page.
    var dash = await client.get("/dashboard");
    assert.strictEqual(dash.status, 200, "the established session reaches the dashboard");
  });

  it("refuses a tailnet user the admin gate does not permit", async function () {
    var client = new TestClient(testServer.baseUrl());
    var res = await client.get("/auth/tailscale", { headers: {
      "Tailscale-User-Login": "e2e-denied@example.com",
      "Tailscale-User-Name": "E2E Denied",
    }});
    assert.strictEqual(res.status, 302, "refusal redirects");
    assert.strictEqual(res.location, "/auth/failed", "a non-allowlisted tailnet user is refused");

    var dash = await client.get("/dashboard");
    assert.notStrictEqual(dash.status, 200, "no session was established for a refused user");
  });

  it("fails closed when no tailnet identity is present (Funnel / direct client)", async function () {
    var client = new TestClient(testServer.baseUrl());
    var res = await client.get("/auth/tailscale");
    assert.strictEqual(res.status, 302, "no-identity request redirects");
    assert.strictEqual(res.location, "/auth/failed", "no tailnet identity ⇒ not signed in");
  });

  it("offers the Tailscale sign-in option on the login page", async function () {
    var client = new TestClient(testServer.baseUrl());
    var res = await client.get("/auth/login");
    assert.strictEqual(res.status, 200);
    assert.ok(/Sign in with Tailscale/.test(res.text || ""), "login page offers Tailscale sign-in");
    assert.ok(/\/auth\/tailscale/.test(res.text || ""), "login page links the Tailscale route");
  });
});
