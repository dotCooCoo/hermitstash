"use strict";
/**
 * b.cryptoField derived-hash dual-read + upgrade-on-read auto-migrate.
 *
 * The derived-hash default flipped from salted-sha3 (128 hex) to the keyed
 * MAC hmac-shake256 (64 hex) in v0.15.0. The mode is resolved at
 * registerTable from the current default and is NOT persisted, so on upgrade
 * a row written under the OLD default still carries the salted-sha3 digest in
 * its lookup column while new lookups compute the keyed-MAC digest — a silent
 * index miss (find-by-email / destroyAllForUser would skip the legacy row).
 *
 * This proves the non-breaking landing:
 *   1. lookupHashCandidates returns BOTH the keyed-MAC and the legacy
 *      salted-sha3 digest, so a match-EITHER query finds the legacy row.
 *   2. unsealRow upgrade-on-read re-hashes a row whose derived-hash column
 *      holds the legacy salted digest to the keyed-MAC form (in the returned
 *      row AND, with a writable db handle, durably on disk), so the candidate
 *      set collapses back to a single value over time.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");
var { setupTestDb, teardownTestDb } = require("../helpers/db");

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-dual-"));
  try {
    // The default users fixture: sealedFields ["email","name"],
    // derivedHashes { emailHash: { from: "email", normalize: lowercase } },
    // keyed-MAC default mode.
    await setupTestDb(dir);

    var email = "Alice@Example.com";   // mixed-case → normalize lowercases it

    // ---- 1. dual-read: lookupHashCandidates names both digests ----
    var keyed = b.cryptoField.lookupHash("users", "email", email);
    check("active lookup hash is the keyed MAC (64 hex)",
      keyed && keyed.value.length === 64);
    check("lookupHash surfaces the legacy salted digest as legacyValue (128 hex)",
      typeof keyed.legacyValue === "string" && keyed.legacyValue.length === 128);

    // The legacy digest the lib computes is the byte-form a pre-v0.15.0 row
    // carries; treat it as ground truth for the forged legacy row below.
    var legacyHash = keyed.legacyValue;
    check("legacy digest is the salted-sha3 SHA3-512 width (128 hex), distinct from the keyed MAC",
      legacyHash.length === 128 && legacyHash !== keyed.value);

    var cands = b.cryptoField.lookupHashCandidates("users", "email", email);
    check("lookupHashCandidates returns the derived field name",
      cands && cands.field === "emailHash");
    check("candidates list carries BOTH the keyed and legacy digests (match-either)",
      cands.values.length === 2 &&
      cands.values.indexOf(keyed.value) !== -1 &&
      cands.values.indexOf(legacyHash) !== -1);

    // ---- 2. forge a LEGACY-indexed row on disk ----
    // Seal the email under the live envelope but OVERWRITE the derived-hash
    // column with the legacy salted digest, mimicking a row written before
    // the default flipped. Insert via the raw handle so the framework's
    // write boundary doesn't recompute emailHash to the keyed form.
    var sealed = b.cryptoField.sealRow("users", { _id: "u-legacy", email: email, name: "Alice" });
    sealed.emailHash = legacyHash;   // pin the LEGACY digest, not the keyed one
    b.db.prepare(
      'INSERT INTO "users" ("_id","email","emailHash","name") VALUES (?,?,?,?)'
    ).run(sealed._id, sealed.email, sealed.emailHash, sealed.name);

    var onDiskBefore = b.db.prepare('SELECT "emailHash" AS h FROM "users" WHERE _id = ?').get("u-legacy");
    check("forged row stores the legacy salted-sha3 emailHash on disk",
      onDiskBefore.h === legacyHash && onDiskBefore.h.length === 128);

    // A match-either query (the candidate list) FINDS the legacy row even
    // though the keyed-only lookup would have missed it.
    var foundLegacy = b.db.prepare(
      'SELECT _id FROM "users" WHERE "emailHash" = ?'
    ).get(legacyHash);
    check("legacy-indexed row is found via the legacy candidate hash",
      foundLegacy && foundLegacy._id === "u-legacy");
    var missedByKeyed = b.db.prepare(
      'SELECT _id FROM "users" WHERE "emailHash" = ?'
    ).get(keyed.value);
    check("keyed-only lookup MISSES the legacy row (why dual-read is needed)",
      missedByKeyed === undefined || missedByKeyed === null);

    // ---- 3. upgrade-on-read: unsealRow re-hashes to the keyed MAC ----
    var rawRow = b.db.prepare('SELECT * FROM "users" WHERE _id = ?').get("u-legacy");
    // Pass the writable local db handle so the durable rewrite fires.
    var unsealed = b.cryptoField.unsealRow("users", rawRow, "actor-1", b.db);
    check("unsealRow decrypted the sealed email back to plaintext",
      unsealed.email === email);
    check("upgrade-on-read: returned row's emailHash is now the keyed MAC",
      unsealed.emailHash === keyed.value && unsealed.emailHash.length === 64);

    var onDiskAfter = b.db.prepare('SELECT "emailHash" AS h FROM "users" WHERE _id = ?').get("u-legacy");
    check("upgrade-on-read: the row's emailHash was durably re-written to the keyed MAC",
      onDiskAfter.h === keyed.value && onDiskAfter.h.length === 64);

    // After the upgrade, the keyed-only lookup now finds the row directly.
    var foundKeyed = b.db.prepare(
      'SELECT _id FROM "users" WHERE "emailHash" = ?'
    ).get(keyed.value);
    check("post-migrate: keyed-only lookup now finds the upgraded row",
      foundKeyed && foundKeyed._id === "u-legacy");

    // ---- 4. idempotence: a row already keyed is left untouched ----
    var rawRow2 = b.db.prepare('SELECT * FROM "users" WHERE _id = ?').get("u-legacy");
    var unsealed2 = b.cryptoField.unsealRow("users", rawRow2, "actor-1", b.db);
    check("re-reading an already-keyed row leaves its emailHash unchanged",
      unsealed2.emailHash === keyed.value);

    // ---- 5. no-handle read resolves the framework db for the rewrite ----
    // Re-forge a legacy row, unseal WITHOUT an explicit dbHandle: unsealRow
    // resolves the framework's local db itself (the same fallback the K_row
    // read path uses), so the returned row carries the keyed hash AND the
    // durable rewrite still lands — keyed reads must work on every path.
    var sealed3 = b.cryptoField.sealRow("users", { _id: "u-legacy-2", email: email, name: "Bob" });
    sealed3.emailHash = legacyHash;
    b.db.prepare(
      'INSERT INTO "users" ("_id","email","emailHash","name") VALUES (?,?,?,?)'
    ).run(sealed3._id, sealed3.email, sealed3.emailHash, sealed3.name);
    var raw3 = b.db.prepare('SELECT * FROM "users" WHERE _id = ?').get("u-legacy-2");
    var unsealedNoHandle = b.cryptoField.unsealRow("users", raw3);   // no explicit dbHandle
    check("no-handle unseal surfaces the keyed hash on the returned row",
      unsealedNoHandle.emailHash === keyed.value);
    var disk3 = b.db.prepare('SELECT "emailHash" AS h FROM "users" WHERE _id = ?').get("u-legacy-2");
    check("no-handle unseal still durably upgrades via the resolved framework db",
      disk3.h === keyed.value);

    // ---- 6. THE REAL CONSUMER PATH: b.db.from().where on a sealed field ----
    // Operators — and the framework's own api-key / session / audit / mail
    // stores — find a row by a sealed field through the equality rewrite,
    // which MUST dual-read across the keyed-MAC flip or it silently drops
    // un-migrated rows (the keyed-only lookup misses the legacy digest).
    // Forge a FRESH legacy row (not yet upgraded) and find it via the real
    // query path — this is the path the primitive-only test above never
    // exercised.
    var sealed6 = b.cryptoField.sealRow("users", { _id: "u-legacy-q", email: email, name: "Dave" });
    sealed6.emailHash = legacyHash;
    b.db.prepare(
      'INSERT INTO "users" ("_id","email","emailHash","name") VALUES (?,?,?,?)'
    ).run(sealed6._id, sealed6.email, sealed6.emailHash, sealed6.name);
    var viaQuery = await b.db.from("users").where("email", email).all();
    check("real consumer path (b.db.from().where on a sealed field) finds the un-migrated legacy row",
      Array.isArray(viaQuery) && viaQuery.some(function (r) { return r._id === "u-legacy-q"; }));

    // b.db.hashCandidatesFor — the db-level dual-read helper the framework's
    // bespoke stores (consent/subject) compose for whereIn lookups.
    var dbCands = b.db.hashCandidatesFor("users", "email", email);
    check("b.db.hashCandidatesFor returns both the keyed and legacy digests",
      dbCands && dbCands.field === "emailHash" && dbCands.values.length === 2);

    console.log("OK — crypto-field dual-read + auto-migrate tests");
  } finally {
    await teardownTestDb(dir);
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
