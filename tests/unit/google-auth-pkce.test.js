const { describe, it, before } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var projectRoot = path.join(__dirname, "..", "..");
var vault = require(path.join(projectRoot, "lib", "vault"));
var b = require(path.join(projectRoot, "lib", "vendor", "blamejs"));
var googleAuth;

before(async function () {
  await vault.init();
  googleAuth = require(path.join(projectRoot, "lib", "google-auth"));
});

describe("google-auth PKCE (RFC 7636 / OAuth 2.1)", function () {
  it("getAuthUrl includes code_challenge + S256 when a challenge is passed", function () {
    var pkce = b.auth.oauth._generatePkce();
    var u = new URL(googleAuth.getAuthUrl("state123", {}, pkce.challenge));
    assert.strictEqual(u.searchParams.get("code_challenge"), pkce.challenge, "challenge is forwarded");
    assert.strictEqual(u.searchParams.get("code_challenge_method"), "S256", "method is S256");
    assert.strictEqual(u.searchParams.get("state"), "state123");
    assert.strictEqual(u.searchParams.get("response_type"), "code");
  });

  it("getAuthUrl omits PKCE params when no challenge is passed (back-compat)", function () {
    var u = new URL(googleAuth.getAuthUrl("state123", {}));
    assert.strictEqual(u.searchParams.get("code_challenge"), null);
    assert.strictEqual(u.searchParams.get("code_challenge_method"), null);
  });

  it("exchangeCode sends the PKCE code_verifier to the token endpoint", async function () {
    var orig = b.httpClient.request;
    var capturedTokenBody = null;
    b.httpClient.request = function (opts) {
      if (String(opts.url).indexOf("/token") !== -1) {
        capturedTokenBody = opts.body;
        return Promise.resolve({ statusCode: 200, body: Buffer.from(JSON.stringify({ access_token: "at" })) });
      }
      // userinfo → a verified profile so exchangeCode resolves.
      return Promise.resolve({ statusCode: 200, body: Buffer.from(JSON.stringify({ sub: "gid", email: "x@test.com", email_verified: true, name: "X" })) });
    };
    try {
      var profile = await googleAuth.exchangeCode("the-code", {}, "the-verifier-abc");
      assert.ok(capturedTokenBody, "a token-exchange request was made");
      assert.match(capturedTokenBody, /code_verifier=the-verifier-abc/, "token exchange carries the PKCE code_verifier");
      assert.strictEqual(profile.googleId, "gid");
      assert.strictEqual(profile.email, "x@test.com");
    } finally {
      b.httpClient.request = orig;
    }
  });

  it("exchangeCode surfaces a non-2xx Google response as an HTTP-status error", async function () {
    var orig = b.httpClient.request;
    b.httpClient.request = function () {
      return Promise.resolve({ statusCode: 401, body: Buffer.from(JSON.stringify({ error: "invalid_grant" })) });
    };
    try {
      await assert.rejects(
        googleAuth.exchangeCode("bad-code", {}, "v"),
        /HTTP 401/,
        "a 401 fails loud with the true status, not an opaque downstream error"
      );
    } finally {
      b.httpClient.request = orig;
    }
  });
});
