const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const b = require("../../lib/vendor/blamejs");

// Isolated test database (mirrors tests/unit/db.test.js bootstrap).
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-db-lockout-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var accessLockout;
before(async function () {
  await vault.init();
  require("../../lib/db");
  accessLockout = require("../../lib/access-lockout");
});

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
  try { fs.unlinkSync(testDbPath.replace(".db", "") + ".db.enc"); } catch {}
});

describe("access-lockout (finding #3 — shared subnet-keyed backoff)", function () {
  var IP = "203.0.113.47";

  it("no lockout before the threshold; arms at the threshold", function () {
    var ns = "test-arm";
    var id = "res1";
    var i;
    for (i = 0; i < accessLockout.THRESHOLD - 1; i++) {
      var r = accessLockout.recordFailure(ns, id, IP);
      assert.strictEqual(r.retryAfter, 0, "no backoff before threshold");
    }
    assert.strictEqual(accessLockout.lockedFor(accessLockout.getLockout(ns, id, IP)), 0);
    var armed = accessLockout.recordFailure(ns, id, IP);
    assert.ok(armed.retryAfter >= 30, "threshold failure arms a >=30s backoff");
    assert.ok(accessLockout.lockedFor(accessLockout.getLockout(ns, id, IP)) > 0, "now locked");
  });

  it("backoff doubles past the threshold", function () {
    var ns = "test-double";
    var id = "res1";
    var i, last = 0;
    for (i = 0; i < accessLockout.THRESHOLD; i++) accessLockout.recordFailure(ns, id, IP);
    var first = accessLockout.recordFailure(ns, id, IP).retryAfter; // threshold+1
    var second = accessLockout.recordFailure(ns, id, IP).retryAfter; // threshold+2
    assert.strictEqual(second, first * 2, "each extra failure doubles the window");
    last = second;
    assert.ok(last > 0);
  });

  it("clearLockout removes the counter (success path)", function () {
    var ns = "test-clear";
    var id = "res1";
    for (var i = 0; i < accessLockout.THRESHOLD; i++) accessLockout.recordFailure(ns, id, IP);
    assert.ok(accessLockout.getLockout(ns, id, IP), "row exists");
    accessLockout.clearLockout(ns, id, IP);
    assert.strictEqual(accessLockout.getLockout(ns, id, IP), null, "row gone after clear");
    assert.strictEqual(accessLockout.lockedFor(accessLockout.getLockout(ns, id, IP)), 0);
  });

  it("namespaces are disjoint — bundle and stash counters never collide", function () {
    var id = "shared-id";
    for (var i = 0; i < accessLockout.THRESHOLD; i++) accessLockout.recordFailure("bundle", id, IP);
    assert.ok(accessLockout.lockedFor(accessLockout.getLockout("bundle", id, IP)) > 0, "bundle locked");
    assert.strictEqual(accessLockout.lockedFor(accessLockout.getLockout("stash", id, IP)), 0,
      "same id under the stash namespace is NOT locked");
  });

  it("keys on the routing subnet — addresses within a /24 share one counter", function () {
    var ns = "test-subnet";
    var id = "res1";
    // Two distinct hosts in the same /24 must map to the same lockout bucket,
    // so rotating the host octet can't reset the counter.
    accessLockout.recordFailure(ns, id, "198.51.100.10");
    var viaSibling = accessLockout.getLockout(ns, id, "198.51.100.250");
    assert.ok(viaSibling && viaSibling.failures === 1,
      "a sibling address in the same /24 sees the same counter");
    // A different /24 is a separate bucket.
    assert.strictEqual(accessLockout.getLockout(ns, id, "198.51.101.10"), null,
      "a different /24 is an independent counter");
  });

  it("lockedFor fails CLOSED on a non-finite lastAttempt (stays locked, never NaN)", function () {
    // A malformed / non-parseable lastAttempt used to make Date.parse return NaN,
    // which propagated through the elapsed math so the gate returned NaN and the
    // caller's `retryAfter > 0` silently skipped the lockout (fail-open). It must
    // now keep the account locked for the full backoff window.
    var armed = accessLockout.THRESHOLD + 1;
    var backoff = accessLockout.lockedFor({ failures: armed, lastAttempt: "not-a-date" });
    assert.ok(Number.isFinite(backoff) && backoff > 0,
      "an unparseable lastAttempt keeps the lockout armed, not disabled");
    // An absent lastAttempt on an armed row is equally unverifiable → still locked.
    var missing = accessLockout.lockedFor({ failures: armed, lastAttempt: null });
    assert.ok(Number.isFinite(missing) && missing > 0, "a missing lastAttempt also stays locked");
    // Below the threshold there is no lock regardless of lastAttempt.
    assert.strictEqual(accessLockout.lockedFor({ failures: 0, lastAttempt: "not-a-date" }), 0);
  });
});
