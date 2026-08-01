/**
 * D-5 — session.service must not carry pending-auth state into a full session.
 *
 * req.regenerateSession copies session.data forward wholesale (lib/session.js),
 * so loginUser / complete2fa used to leave stale pendingTotpUserId /
 * pendingTotpSecret / pendingReEnrollSecret (etc.) behind after a completed
 * login — a fully-authenticated session could carry another auth attempt's
 * half-finished pending state (a stale pendingTotpUserId could even point at a
 * different user). loginUser and complete2fa now clear every pending-auth key.
 *
 * regenerateSession is mocked to mirror lib/session.js's carry-forward
 * semantics; no server boot is required, but the harness is used so the module
 * loads against a configured data dir.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");

var sessionService;
var PENDING_KEYS = [
  "pendingTotpUserId",
  "pendingTotpExpires",
  "pendingTotpFailures",
  "pendingTotpSecret",
  "pendingReEnrollSecret",
  "requiresTotpReEnroll",
];

before(async function () {
  await testServer.start();
  sessionService = require(path.join(testServer.projectRoot, "app", "domain", "auth", "session.service"));
});

after(function () { return testServer.stop(); });

// A req whose regenerateSession mirrors lib/session.js: session.data is copied
// forward onto the new (rotated) session. The storage-layer userId binding
// (opts.userId) is intentionally NOT written onto req.session — the service is
// responsible for setting req.session.userId itself.
function makeReq(initialSession) {
  var req = { session: Object.assign({}, initialSession) };
  req.regenerateSession = async function () {
    var carried = Object.assign({}, req.session);
    delete carried.__bj_fingerprint;
    req.session = carried;
  };
  return req;
}

function fullPending(extra) {
  return Object.assign({
    pendingTotpUserId: "victim-user-id",
    pendingTotpExpires: Date.now() + 100000,
    pendingTotpFailures: 3,
    pendingTotpSecret: "PENDING-SETUP-SECRET",
    pendingReEnrollSecret: "PENDING-REENROLL-SECRET",
    requiresTotpReEnroll: "true",
    _csrf: "keep-me",   // a non-pending key that must survive
  }, extra || {});
}

describe("session.service pending-auth cleanup (D-5)", function () {
  it("loginUser clears every pending-auth key, sets userId, and preserves other state", async function () {
    var req = makeReq(fullPending());
    await sessionService.loginUser(req, "real-user-id");

    PENDING_KEYS.forEach(function (k) {
      assert.ok(!(k in req.session), "pending key must be cleared after loginUser: " + k);
    });
    assert.strictEqual(req.session.userId, "real-user-id", "userId must be set");
    assert.strictEqual(req.session._csrf, "keep-me", "non-pending session state must survive");
  });

  it("complete2fa promotes the pending user and clears every pending-auth key", async function () {
    var req = makeReq(fullPending());
    var uid = await sessionService.complete2fa(req);

    assert.strictEqual(uid, "victim-user-id", "returns the pending userId it promoted");
    assert.strictEqual(req.session.userId, "victim-user-id", "userId bound to the promoted user");
    PENDING_KEYS.forEach(function (k) {
      assert.ok(!(k in req.session), "pending key must be cleared after complete2fa: " + k);
    });
    assert.strictEqual(req.session._csrf, "keep-me", "non-pending session state must survive");
  });

  it("start2faPending starts each cycle with a clean failure counter", async function () {
    // A session that carried a stale failure count from a prior cycle must not
    // inherit it — the new pending cycle starts fresh.
    var req = makeReq({ pendingTotpFailures: 4, requiresTotpReEnroll: "true", _csrf: "keep-me" });
    await sessionService.start2faPending(req, "new-pending-user");

    assert.strictEqual(req.session.pendingTotpUserId, "new-pending-user");
    assert.ok(!("pendingTotpFailures" in req.session), "stale failure count must be dropped");
    assert.ok(!("requiresTotpReEnroll" in req.session), "stale re-enroll flag must be dropped");
    assert.strictEqual(req.session._csrf, "keep-me", "non-pending session state must survive");
  });
});
