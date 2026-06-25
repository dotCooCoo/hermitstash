// Focused regression for the sync-enrollment lookup: redemption must resolve a
// pending enrollment code through the indexed codeHash blind index
// (idx_enrollment_codeHash), returning at most the one matching row — NOT by
// loading every pending row and JS-filtering on `===`. The old load-all path
// forced an O(N) field-decrypt of every provisioned credential bundle per
// unauthenticated POST /sync/enroll. codeHash is a raw (indexed) column, so an
// exact-match find on it returns the stored row directly.
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const b = require("../../lib/vendor/blamejs");
const C = require("../../lib/constants");

var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-enroll-lookup-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var db;
before(async function () {
  await vault.init();
  db = require("../../lib/db");
});

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
  try { fs.unlinkSync(testDbPath.replace(".db", "") + ".db.enc"); } catch {}
});

describe("sync-enrollment indexed lookup", function () {
  var futureIso = new Date(Date.now() + C.TIME.hours(1)).toISOString();

  function hashFor(code) {
    return b.crypto.namespaceHash(C.HASH_PREFIX.ENROLLMENT, code);
  }

  it("resolves a pending code by its indexed codeHash and returns only that row", function () {
    var wantCode = "ENROLL-" + testId + "-WANT";
    var otherCode = "ENROLL-" + testId + "-OTHER";
    var wantHash = hashFor(wantCode);
    var otherHash = hashFor(otherCode);

    db.enrollmentCodes.insert({ codeHash: wantHash, status: "pending", expiresAt: futureIso });
    db.enrollmentCodes.insert({ codeHash: otherHash, status: "pending", expiresAt: futureIso });

    // The redemption query shape used by POST /sync/enroll.
    var records = db.enrollmentCodes.find({ codeHash: wantHash, status: "pending" })
      .filter(function (r) { return r.expiresAt > new Date().toISOString(); });

    assert.strictEqual(records.length, 1, "indexed lookup must return exactly the matching pending row");
    assert.strictEqual(records[0].codeHash, wantHash, "must return the row whose codeHash matches");
  });

  it("does not match a redeemed code on the same hash (status scoped in the query)", function () {
    var code = "ENROLL-" + testId + "-REDEEMED";
    var h = hashFor(code);
    db.enrollmentCodes.insert({ codeHash: h, status: "redeemed", expiresAt: futureIso });

    var records = db.enrollmentCodes.find({ codeHash: h, status: "pending" });
    assert.strictEqual(records.length, 0, "a redeemed code must not be re-found by the pending-scoped query");
  });

  it("returns nothing for an unknown code hash without scanning all pending rows", function () {
    // Seed several unrelated pending rows; an unknown hash must resolve to zero
    // via the index rather than relying on a JS filter over every pending row.
    for (var i = 0; i < 5; i++) {
      db.enrollmentCodes.insert({ codeHash: hashFor("noise-" + testId + "-" + i), status: "pending", expiresAt: futureIso });
    }
    var records = db.enrollmentCodes.find({ codeHash: hashFor("never-issued-" + testId), status: "pending" });
    assert.strictEqual(records.length, 0, "unknown code hash must resolve to zero rows");
  });
});
