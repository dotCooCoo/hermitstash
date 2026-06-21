const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");

var b = require("../../lib/vendor/blamejs");
var session = require("../../lib/session");

// clearSessionsForUser must absorb ONLY the post-DELETE stateless valid-from
// bump failure — HS uses a pluggable session store (b.session.useStore) and
// never calls b.db.init(), so destroyAllForUser deletes the store rows (the
// only sessions HS has) and THEN throws while trying to raise the framework's
// stateless valid-from boundary. That post-revocation throw is safe to swallow;
// any error meaning the revocation itself failed MUST propagate.
//
// blamejs 0.15.x re-wraps that bump failure: the raw "db/not-initialized" is
// caught and re-thrown as a SessionError("MISCONFIGURED", "...stateless
// valid-from boundary...the store-backed rows were already deleted..."). The
// swallow matches that re-wrap by its distinctive message — but NOT the OTHER
// "MISCONFIGURED" throw (userIdHash derived-hash schema not registered), which
// is a genuine misconfiguration and must surface.
describe("session.clearSessionsForUser — revocation-failure swallow (blamejs#340 / 0.15.x re-wrap)", function () {
  var orig;
  before(function () { orig = b.session.destroyAllForUser; });
  after(function () { b.session.destroyAllForUser = orig; });

  function stub(fn) { b.session.destroyAllForUser = fn; }

  it("returns 0 for a falsy userId without calling the framework", async function () {
    var called = false;
    stub(async function () { called = true; return 5; });
    assert.strictEqual(await session.clearSessionsForUser(null), 0);
    assert.strictEqual(called, false);
  });

  it("passes through the revoked count on success", async function () {
    stub(async function () { return 3; });
    assert.strictEqual(await session.clearSessionsForUser("u1"), 3);
  });

  it("absorbs the raw db/not-initialized post-delete bump (returns 0)", async function () {
    stub(async function () { var e = new Error("db not initialized"); e.code = "db/not-initialized"; throw e; });
    assert.strictEqual(await session.clearSessionsForUser("u1"), 0);
  });

  it("absorbs the 0.15.x MISCONFIGURED re-wrap of the post-delete bump (returns 0)", async function () {
    stub(async function () {
      var e = new Error(
        "session.destroyAllForUser raises the stateless valid-from boundary (so a " +
        "logout-everywhere also revokes sealed-cookie / JWT sessions), which requires " +
        "b.db.init(). The store-backed rows were already deleted; rerun after b.db.init().");
      e.code = "MISCONFIGURED"; e.isSessionError = true; throw e;
    });
    assert.strictEqual(await session.clearSessionsForUser("u1"), 0);
  });

  it("PROPAGATES the MISCONFIGURED userIdHash-schema-not-registered error (genuine misconfig)", async function () {
    stub(async function () {
      var e = new Error(
        "session.destroyAllForUser: the session table's userIdHash derived-hash schema is " +
        "not registered. It is registered during b.db.init().");
      e.code = "MISCONFIGURED"; e.isSessionError = true; throw e;
    });
    await assert.rejects(function () { return session.clearSessionsForUser("u1"); }, /userIdHash derived-hash schema/);
  });

  it("PROPAGATES an unrelated error (the revocation itself failed)", async function () {
    stub(async function () { var e = new Error("disk full"); e.code = "EIO"; throw e; });
    await assert.rejects(function () { return session.clearSessionsForUser("u1"); }, /disk full/);
  });
});
