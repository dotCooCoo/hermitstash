var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");

// G2 — passkey challenge TOCTOU. POST /passkey/login/verify reads
// req.session.passkeyChallenge and delete()s it IN MEMORY; that delete is
// persisted only at res.end via the deferred session flush. Two concurrent
// verifies on the same anonymous hs_sid both read the same challenge before
// either flushes, so both pass the "No pending passkey challenge" check. The
// replayNonce.claimOnce gate added in routes/passkey.js closes that window —
// the same primitive routes/two-factor.js uses for the TOTP step / backup
// code. The claim happens BEFORE credential verification, so an unmatched
// (bogus) credential still exercises the replay path.

describe("passkey challenge replay (G2 TOCTOU)", function () {
  before(async function () {
    await testServer.start();
  });

  after(function () { return testServer.stop(); });

  // A fresh anonymous client whose session holds exactly one pending challenge.
  async function clientWithPendingChallenge() {
    var client = new TestClient(testServer.baseUrl());
    await client.initApiKey();
    var opts = await client.post("/passkey/login/options", { json: {} });
    assert.strictEqual(opts.status, 200, "login/options should mint a challenge, got " + opts.status);
    assert.ok(opts.json && opts.json.challenge, "login/options must return a challenge");
    return { client: client, challenge: opts.json.challenge };
  }

  // A verify body that carries a syntactically present but unknown credential.
  // It will never match a stored credential, so the request can only ever reach
  // 401 — but WHICH 401 (challenge-replay vs unknown-credential) is what the
  // claim gate decides.
  var bogusAssertion = { id: "bogus-credential-id", rawId: "bogus", response: {}, type: "public-key" };

  function detailOf(res) {
    return (res.json && (res.json.detail || res.json.error)) || "";
  }

  it("two concurrent verifies never both pass the challenge gate", async function () {
    var ctx = await clientWithPendingChallenge();

    // Fire both on the SAME cookie/session. Whether the harness happens to
    // serialize the session read or genuinely overlaps it, the invariant the
    // claim gate guarantees is the same: the challenge is a single-use token,
    // so AT MOST ONE request may pass the challenge gate and reach credential
    // matching ("Unknown passkey"). The other is refused — either as a claimed
    // replay ("already used") or, if it read after the flush, as having no
    // pending challenge. Neither may authenticate; neither may 5xx.
    var results = await Promise.all([
      ctx.client.post("/passkey/login/verify", { json: bogusAssertion }),
      ctx.client.post("/passkey/login/verify", { json: bogusAssertion }),
    ]);

    results.forEach(function (r) {
      assert.notStrictEqual(r.status, 200, "a bogus assertion must never authenticate");
      assert.ok(r.status < 500, "verify must not crash with 5xx, got " + r.status);
    });

    var details = results.map(detailOf);
    var pastChallengeGate = details.filter(function (d) { return /unknown passkey/i.test(d); });

    assert.ok(pastChallengeGate.length <= 1,
      "at most one concurrent verify may pass the single-use challenge gate, got details: " + JSON.stringify(details));
    var refused = details.filter(function (d) { return /already used|no pending passkey challenge/i.test(d); });
    assert.ok(refused.length >= 1,
      "the other concurrent verify must be refused, got details: " + JSON.stringify(details));
  });

  it("a sequential second verify on the same challenge is refused, never authenticated", async function () {
    var ctx = await clientWithPendingChallenge();

    // First verify claims the challenge. It fails on the bogus credential
    // ("Unknown passkey"), but the claim is recorded for that challenge value.
    var first = await ctx.client.post("/passkey/login/verify", { json: bogusAssertion });
    assert.notStrictEqual(first.status, 200);
    assert.ok(/unknown passkey/i.test(detailOf(first)),
      "first verify should reach credential matching, got: " + detailOf(first));

    // A second verify on the same session must NOT pass the challenge gate —
    // refused either as a claimed replay or as having no pending challenge.
    var second = await ctx.client.post("/passkey/login/verify", { json: bogusAssertion });
    assert.notStrictEqual(second.status, 200, "a replayed challenge must never authenticate");
    assert.ok(/already used|no pending passkey challenge/i.test(detailOf(second)),
      "second verify must be refused, got: " + detailOf(second));
  });

  it("the claim gate marks a given challenge value single-use (replayNonce primitive)", async function () {
    // The route claims "passkey:chal:" + sha3Hash(challenge). Re-deriving the
    // exact key proves the gate rejects a second claim of the SAME challenge —
    // the property that closes the concurrent-read window regardless of how the
    // session flush is scheduled. Mirrors two-factor.js's TOTP-step claim.
    var b = require(testServer.projectRoot + "/lib/vendor/blamejs");
    var replayNonce = require(testServer.projectRoot + "/lib/replay-nonce");
    var C = require(testServer.projectRoot + "/lib/constants");

    var ctx = await clientWithPendingChallenge();
    var key = "passkey:chal:" + b.crypto.sha3Hash(ctx.challenge);

    var firstClaim = await replayNonce.claimOnce(key, C.TIME.minutes(2));
    var secondClaim = await replayNonce.claimOnce(key, C.TIME.minutes(2));

    assert.strictEqual(firstClaim, true, "first claim of a fresh challenge must succeed");
    assert.strictEqual(secondClaim, false, "a second claim of the same challenge must be rejected");
  });
});
