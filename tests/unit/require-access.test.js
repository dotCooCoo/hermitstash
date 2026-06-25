var { describe, it } = require("node:test");
var assert = require("node:assert");

var { checkLock, isBundleLocked, isStashLocked } = require("../../middleware/require-access");

describe("require-access checkLock", function () {

  describe("password mode", function () {
    it("locks when no session value, unlocks when truthy", function () {
      var r = { accessMode: "password", passwordHash: "x" };
      assert.strictEqual(checkLock(r, "k", {}), "password");
      assert.strictEqual(checkLock(r, "k", { k: true }), false);
    });
  });

  describe("open mode", function () {
    it("never locks", function () {
      assert.strictEqual(checkLock({ accessMode: "open" }, "k", {}), false);
    });
  });

  describe("email mode — revocation re-validation (finding #7)", function () {
    var resource = { accessMode: "email" };

    it("locks with no session", function () {
      assert.strictEqual(checkLock(resource, "k", {}), "email");
    });

    it("unlocks when the session email is still on the current allow-list", function () {
      var match = function (e) { return e === "alice@x.com"; };
      assert.strictEqual(checkLock(resource, "k", { k: "alice@x.com" }, match), false);
    });

    it("re-locks when the session email was removed from the current allow-list", function () {
      var match = function (e) { return e === "bob@x.com"; }; // alice removed
      assert.strictEqual(checkLock(resource, "k", { k: "alice@x.com" }, match), "email");
    });

    it("unlocks on mere presence when no matcher is supplied (back-compat)", function () {
      assert.strictEqual(checkLock(resource, "k", { k: "alice@x.com" }), false);
    });

    it("re-validates an object session value via emailVerified", function () {
      var match = function (e) { return e === "alice@x.com"; };
      assert.strictEqual(checkLock(resource, "k", { k: { emailVerified: "gone@x.com" } }, match), "email");
      assert.strictEqual(checkLock(resource, "k", { k: { emailVerified: "alice@x.com" } }, match), false);
    });
  });

  describe("both mode — email re-validation (finding #7)", function () {
    var resource = { accessMode: "both", passwordHash: "x" };

    it("requires a verified email string", function () {
      assert.strictEqual(checkLock(resource, "k", { k: true }), "email");
      assert.strictEqual(checkLock(resource, "k", {}), "email");
    });

    it("re-locks to email when the verified email was revoked, even with password flag set", function () {
      var match = function (e) { return e === "bob@x.com"; };
      var s = { k: { emailVerified: "alice@x.com", passwordVerified: true } };
      assert.strictEqual(checkLock(resource, "k", s, match), "email");
    });

    it("needs password when email valid but password not yet verified", function () {
      var match = function (e) { return e === "alice@x.com"; };
      var s = { k: { emailVerified: "alice@x.com", passwordVerified: false } };
      assert.strictEqual(checkLock(resource, "k", s, match), "email-then-password");
    });

    it("unlocks when email valid and password verified", function () {
      var match = function (e) { return e === "alice@x.com"; };
      var s = { k: { emailVerified: "alice@x.com", passwordVerified: true } };
      assert.strictEqual(checkLock(resource, "k", s, match), false);
    });
  });

  describe("isStashLocked keys by stable _id, not slug (finding #12)", function () {
    it("derives the session key from stash._id", function () {
      var stash = { _id: "STASH_ID_1", slug: "acme", accessMode: "password", passwordHash: "x" };
      // Session carries an unlock under the _id key -> unlocked
      assert.strictEqual(isStashLocked(stash, { "stashUnlocked_STASH_ID_1": true }), false);
      // A stale slug-keyed value must NOT unlock (the old carry-over bug)
      assert.strictEqual(isStashLocked(stash, { "stashUnlocked_acme": true }), "password");
    });

    it("a freed-and-reused slug carries no prior unlock", function () {
      // Session unlocked stash A (id A1) at slug "acme".
      var session = { "stashUnlocked_A1": true };
      // Admin recreates a differently-gated stash B (id B2) at the same slug.
      var stashB = { _id: "B2", slug: "acme", accessMode: "password", passwordHash: "y" };
      assert.strictEqual(isStashLocked(stashB, session), "password",
        "new stash at a reused slug must present its own gate");
    });
  });

  describe("isBundleLocked passes the allow-matcher through (finding #7)", function () {
    it("re-locks a revoked email-gated bundle", function () {
      var bundle = { shareId: "SID", accessMode: "email" };
      var session = { "bundle_SID": "alice@x.com" };
      var revoked = function () { return false; };
      assert.strictEqual(isBundleLocked(bundle, session, revoked), "email");
      var allowed = function (e) { return e === "alice@x.com"; };
      assert.strictEqual(isBundleLocked(bundle, session, allowed), false);
    });
  });
});
