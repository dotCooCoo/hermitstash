const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const nodeCrypto = require("crypto");

// Isolated test DB so the vault + session store load cleanly. Set before any
// HermitStash module is required so lib/session wires its store against it.
var testDbPath = path.join(__dirname, "..", "..", "data", "test-session-revoke-" + nodeCrypto.randomBytes(4).toString("hex") + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

var b = require("../../lib/vendor/blamejs");
var vault = require("../../lib/vault");
var session = require("../../lib/session");

// clearSessionsForUser revokes every session for a user: b.session.destroyAllForUser
// DELETEs the store-backed rows and raises the stateless valid-from boundary. As of
// blamejs 0.15.16 that boundary write falls back to the configured session store
// when no framework DB is initialized (HS's model — own DB lifecycle, store-verified
// sessions, no b.db.init), so it resolves cleanly. The old post-delete swallow that
// absorbed db/not-initialized / its MISCONFIGURED re-wrap is removed: a failure now
// means the revocation itself failed and MUST propagate (fail closed).
describe("session.clearSessionsForUser — real destroyAllForUser path (0.15.16+ store fallback)", function () {
  before(async function () {
    await vault.init();
    require("../../lib/db");
  });

  after(function () {
    ["", "-shm", "-wal", ".enc"].forEach(function (s) { try { fs.unlinkSync(testDbPath + s); } catch (_e) { /* best effort */ } });
  });

  it("returns 0 for a falsy userId without calling the framework", async function () {
    var orig = b.session.destroyAllForUser;
    var called = false;
    b.session.destroyAllForUser = async function () { called = true; return 5; };
    try {
      assert.strictEqual(await session.clearSessionsForUser(null), 0);
      assert.strictEqual(called, false);
    } finally { b.session.destroyAllForUser = orig; }
  });

  it("resolves cleanly against the real store-backed path (no swallow required)", async function () {
    // The genuine 0.15.16+ path: a store-backed consumer with no b.db.init(). A user
    // with no live sessions revokes to 0 without throwing the old db/not-initialized
    // / MISCONFIGURED re-wrap the removed swallow used to absorb.
    var n = await session.clearSessionsForUser("revoke-user-" + nodeCrypto.randomBytes(4).toString("hex"));
    assert.strictEqual(typeof n, "number");
    assert.ok(n >= 0);
  });

  it("passes through the revoked count on success", async function () {
    var orig = b.session.destroyAllForUser;
    b.session.destroyAllForUser = async function () { return 3; };
    try {
      assert.strictEqual(await session.clearSessionsForUser("u1"), 3);
    } finally { b.session.destroyAllForUser = orig; }
  });

  it("PROPAGATES a revocation failure (fail closed — never reports a failed revoke as 0)", async function () {
    var orig = b.session.destroyAllForUser;
    b.session.destroyAllForUser = async function () {
      var e = new Error("store DELETE failed"); e.code = "store/io-error"; throw e;
    };
    try {
      await assert.rejects(function () { return session.clearSessionsForUser("u1"); }, /store DELETE failed/);
    } finally { b.session.destroyAllForUser = orig; }
  });
});
