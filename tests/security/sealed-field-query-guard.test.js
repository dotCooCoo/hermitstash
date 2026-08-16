"use strict";

/**
 * A query the storage cannot answer must say so, not answer wrongly.
 *
 * Sealed columns hold ciphertext. A handful of them also carry a derived blind
 * index, and equality or $in over those is answerable by matching digests.
 * Everything else is not: comparing an operand to ciphertext compiles a
 * predicate that is silently wrong rather than erroring.
 *
 * The guard existed and its comment described exactly this, but it was gated on
 * the field carrying a derived index — so it only ever fired for that handful.
 * A merely sealed column fell through to the pass-through the comment warns
 * about:
 *
 *   find({ authType: "google" })            matched NOTHING
 *   find({ authType: { $ne: "google" } })   matched EVERYTHING, google included
 *
 * The second is the one that matters: a query written to exclude a row returns
 * it. No shipped call site queries a sealed column without an index, so this
 * was a trap rather than a live fault — the next person to write one would have
 * got a wrong answer with nothing to indicate it.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var testEnv = require("../helpers/test-env");
var tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-sealq-"));
process.env.HERMITSTASH_DATA_DIR = tmpDataDir;

var vault = require("../../lib/vault");
var db = require("../../lib/db");
var fieldCrypto = require("../../lib/field-crypto");

before(async function () {
  await vault.init();
  db.users.insert({ _id: "sq1", email: "sq-a@example.test", role: "user", authType: "local" });
  db.users.insert({ _id: "sq2", email: "sq-b@example.test", role: "user", authType: "google" });
});

after(function () {
  try { db.users.remove({ _id: "sq1" }); db.users.remove({ _id: "sq2" }); } catch (_e) { /* best effort */ }
  if (testEnv && typeof testEnv.cleanup === "function") testEnv.cleanup();
  try { fs.rmSync(tmpDataDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

describe("queries over sealed columns", function () {
  it("authType is sealed and has no derived index — the shape this is about", function () {
    // The premise. If authType ever gains an index, this test is measuring
    // something else and should be pointed at another field.
    assert.ok(fieldCrypto.getSealedFields("users").indexOf("authType") !== -1,
      "authType must be sealed for this test to mean anything");
    assert.equal(fieldCrypto.lookupHash("users", "authType", "probe"), null,
      "and must have no derived index");
  });

  it("refuses $ne over a sealed column instead of matching every row", function () {
    // The dangerous direction: written to exclude the google user, it returned
    // the google user.
    assert.throws(
      function () { return db.users.find({ authType: { $ne: "google" } }); },
      /Unsupported query on sealed field 'authType'/,
      "a $ne that cannot be evaluated must raise, not return everything");
  });

  it("refuses equality over a sealed column instead of matching none", function () {
    assert.throws(
      function () { return db.users.find({ authType: "google" }); },
      /Unsupported query on sealed field 'authType'/,
      "an equality that cannot be evaluated must raise, not return nothing");
  });

  it("refuses $in over a sealed column with no derived index", function () {
    assert.throws(
      function () { return db.users.find({ authType: { $in: ["google", "local"] } }); },
      /Cannot \$in-query sealed field 'authType'|Unsupported query on sealed field/,
      "an $in that cannot be blind-indexed must raise");
  });

  it("still answers equality over a sealed column that HAS a derived index", function () {
    // The guard is worthless if it also refuses the queries the product runs.
    // These are the shapes every repository uses.
    assert.ok(fieldCrypto.lookupHash("users", "email", "probe"), "email must carry an index");
    var found = db.users.find({ email: "sq-a@example.test" });
    assert.equal(found.length, 1, "a blind-indexed lookup must still work");
    assert.equal(found[0]._id, "sq1");
  });

  it("still answers queries over raw columns", function () {
    var found = db.users.find({ role: "user" });
    assert.ok(found.length >= 2, "raw columns are unaffected");
  });

  it("still answers an empty $in as no rows, on sealed and raw columns alike", function () {
    // "none of these" is an ordinary query — callers build the list
    // dynamically and it comes out empty. It needs no comparison against the
    // column at all, so refusing it would break a working shape in the name of
    // a guard against wrong answers.
    assert.deepEqual(db.users.find({ email: { $in: [] } }), [],
      "an empty $in over a sealed, indexed column must return no rows");
    assert.deepEqual(db.users.find({ authType: { $in: [] } }), [],
      "and over a sealed column with no index");
    assert.deepEqual(db.users.find({ role: { $in: [] } }), [],
      "and over a raw column");
  });

  it("answers a blank operand as no rows rather than raising", function () {
    // A blank search or login field is ordinary input. Nothing can match it —
    // writes create no digest for an empty source — so the answer is an empty
    // result, and it was one before this guard existed. Raising here would turn
    // a submitted empty form into an application error.
    assert.deepEqual(db.users.find({ email: "" }), [], "blank string over a derived field");
    assert.deepEqual(db.users.find({ email: null }), [], "null over a derived field");
    assert.deepEqual(db.users.find({ authType: "" }), [], "blank over a sealed field with no index");
    assert.deepEqual(db.users.find({ email: undefined }), [],
      "and undefined, which a live caller reaches on the certificate reissue path");
  });

  it("refuses both halves of a boolean sealed column, not just one", function () {
    // The write path stores `false` as a raw "0.0" and `true` as ciphertext in
    // the same column, so before this guard `{vaultEnabled:false}` matched by
    // accident of that encoding while `{vaultEnabled:true}` matched nothing.
    // Permitting the falsy half — which looks like a kindness — would leave one
    // value of a boolean queryable and the other silently not, which is the
    // shape being fixed. Pinned so it is not softened back.
    assert.ok(fieldCrypto.getSealedFields("users").indexOf("vaultEnabled") !== -1,
      "vaultEnabled must be sealed for this to mean anything");
    assert.throws(function () { return db.users.find({ vaultEnabled: false }); },
      /Unsupported query on sealed field 'vaultEnabled'/, "false must be refused");
    assert.throws(function () { return db.users.find({ vaultEnabled: true }); },
      /Unsupported query on sealed field 'vaultEnabled'/, "and so must true");
  });

  it("names the way out in the message", function () {
    // Someone hitting this needs to know what to do, and the answer is not
    // "add an index" — it is to unseal and filter in JS.
    try {
      db.users.find({ authType: { $ne: "google" } });
      assert.fail("expected a throw");
    } catch (e) {
      assert.match(e.message, /unseal and filter in JS/i,
        "the error should say how to get the answer: " + e.message);
    }
  });
});
