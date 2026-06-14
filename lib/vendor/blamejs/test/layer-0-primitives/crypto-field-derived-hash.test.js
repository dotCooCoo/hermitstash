"use strict";
/**
 * b.cryptoField derived-hash modes.
 *
 * Equality-lookup ("derived") hashes for sealed columns can be computed
 * two ways:
 *   - hmac-shake256 (default, v0.15.0) — keyed MAC off
 *                               vault.getDerivedHashMacKey, so an attacker
 *                               who recovers the per-deployment salt alone
 *                               cannot correlate low-entropy plaintexts.
 *   - salted-sha3   (opt-out) — SHA3-512 over a per-deployment salt;
 *                               byte-compatible with the legacy index.
 *
 * The mode is chosen per-table (derivedHashMode) or per-column
 * (spec.mode). The decision lives in _computeDerivedHash; call sites
 * must never hand-roll the hash.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-dh-"));
  await b.vault.init({ mode: "plaintext", dataDir: dir });

  // ---- DEFAULT (v0.15.0) is the keyed MAC: hmac-shake256 → 64 hex chars.
  // A table that declares no derivedHashMode gets the keyed digest so an
  // attacker who recovers the salt alone can't correlate plaintexts. ----
  b.cryptoField.registerTable("cf_dh_default", {
    sealedFields: ["email"],
    derivedHashes: { emailHash: { from: "email" } },
  });
  var defaultH = b.cryptoField.lookupHash("cf_dh_default", "email", "a@b.com").value;
  check("derivedHashMode default is keyed hmac-shake256 (64 hex)", defaultH.length === 64);
  check("default keyed hash is deterministic",
    defaultH === b.cryptoField.lookupHash("cf_dh_default", "email", "a@b.com").value);

  // ---- documented opt-out: derivedHashMode:'salted-sha3' restores the
  // deterministic-per-deployment SHA3-512 digest → 128 hex chars. ----
  b.cryptoField.registerTable("cf_dh_t1", {
    sealedFields: ["email"],
    derivedHashes: { emailHash: { from: "email" } },
    derivedHashMode: "salted-sha3",
  });
  var saltedH = b.cryptoField.lookupHash("cf_dh_t1", "email", "a@b.com").value;
  check("salted-sha3 opt-out is 128 hex (SHA3-512)", saltedH.length === 128);
  check("salted-sha3 is deterministic",
    saltedH === b.cryptoField.lookupHash("cf_dh_t1", "email", "a@b.com").value);

  // ---- hmac-shake256 table mode (explicit): SHAKE256/32 → 64 hex chars ----
  b.cryptoField.registerTable("cf_dh_t2", {
    sealedFields: ["email"],
    derivedHashes: { emailHash: { from: "email" } },
    derivedHashMode: "hmac-shake256",
  });
  var keyedH = b.cryptoField.lookupHash("cf_dh_t2", "email", "a@b.com").value;
  check("hmac-shake256 is 64 hex (SHAKE256/32)", keyedH.length === 64);
  check("hmac-shake256 is deterministic",
    keyedH === b.cryptoField.lookupHash("cf_dh_t2", "email", "a@b.com").value);
  check("keyed hash differs from salted hash", keyedH !== saltedH);
  check("explicit keyed mode matches the new default", keyedH === defaultH);

  // ---- per-column mode override on a salted-default table ----
  b.cryptoField.registerTable("cf_dh_t3", {
    sealedFields: ["ssn"],
    derivedHashes: { ssnHash: { from: "ssn", mode: "hmac-shake256" } },
  });
  check("per-column hmac-shake256 override → 64 hex",
    b.cryptoField.lookupHash("cf_dh_t3", "ssn", "x").value.length === 64);

  // ---- MAC key surface: 32 bytes, per-deployment ----
  var macKey = b.vault.getDerivedHashMacKey();
  check("getDerivedHashMacKey is a 32-byte Buffer",
    Buffer.isBuffer(macKey) && macKey.length === 32);

  // A fresh deployment (new vault dir + MAC key) yields a different
  // keyed hash for the same input — the keyed hash is bound to the MAC
  // key, not just the input.
  var dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-dh2-"));
  b.vault._resetForTest();
  await b.vault.init({ mode: "plaintext", dataDir: dir2 });
  b.cryptoField.registerTable("cf_dh_t2", {
    sealedFields: ["email"],
    derivedHashes: { emailHash: { from: "email" } },
    derivedHashMode: "hmac-shake256",
  });
  var keyedH2 = b.cryptoField.lookupHash("cf_dh_t2", "email", "a@b.com").value;
  check("new deployment MAC key → different keyed hash", keyedH2 !== keyedH);

  // ---- input validation: unknown modes are rejected at registerTable ----
  var badTableMode = false;
  try { b.cryptoField.registerTable("cf_dh_bad", { derivedHashMode: "md5" }); }
  catch (e) { badTableMode = /derivedHashMode must be/.test(e.message); }
  check("bad derivedHashMode throws at registerTable", badTableMode);

  var badColMode = false;
  try {
    b.cryptoField.registerTable("cf_dh_bad2", {
      derivedHashes: { h: { from: "x", mode: "rot13" } },
    });
  } catch (e) { badColMode = /mode must be/.test(e.message); }
  check("bad per-column mode throws at registerTable", badColMode);

  // ---- computeNamespacedHash: pseudo-field indexed hash (FTS substrate) ----
  // Wraps _computeDerivedHash for namespaces that have no registered
  // derived-hash column (e.g. the sealed-token mail-store FTS index).
  var ns = "bj-mail_messages-body:fts:";

  // Default mode is salted-sha3 → byte-identical to the legacy hand-roll.
  var saltHex = b.vault.getDerivedHashSalt().toString("hex");
  var legacyRef = b.crypto.sha3Hash(saltHex + ns + "kubernetes");
  var cnhDefault = b.cryptoField.computeNamespacedHash(ns, "kubernetes");
  check("computeNamespacedHash default is salted-sha3 (128 hex)", cnhDefault.length === 128);
  check("computeNamespacedHash default == legacy hand-roll", cnhDefault === legacyRef);

  // truncateBytes slices the hex to that many bytes (2 hex chars each).
  var cnhTrunc = b.cryptoField.computeNamespacedHash(ns, "kubernetes",
    { mode: "salted-sha3", truncateBytes: 8 });
  check("computeNamespacedHash truncateBytes:8 -> 16 hex", cnhTrunc.length === 16);
  check("computeNamespacedHash truncate is a prefix of full", legacyRef.slice(0, 16) === cnhTrunc);

  // Keyed mode differs from the salted default and is unforgeable
  // without the MAC key.
  var cnhKeyed = b.cryptoField.computeNamespacedHash(ns, "kubernetes",
    { mode: "hmac-shake256", truncateBytes: 8 });
  check("computeNamespacedHash hmac-shake256 -> 16 hex", /^[0-9a-f]{16}$/.test(cnhKeyed));
  check("computeNamespacedHash keyed differs from salted", cnhKeyed !== cnhTrunc);
  check("computeNamespacedHash is deterministic",
    cnhKeyed === b.cryptoField.computeNamespacedHash(ns, "kubernetes",
      { mode: "hmac-shake256", truncateBytes: 8 }));

  // Config-time throws: bad mode, non-positive / non-integer truncateBytes.
  var cnhBadMode = false;
  try { b.cryptoField.computeNamespacedHash(ns, "x", { mode: "md5" }); }
  catch (e) { cnhBadMode = /mode must be/.test(e.message); }
  check("computeNamespacedHash bad mode throws", cnhBadMode);

  var cnhBadTruncZero = false;
  try { b.cryptoField.computeNamespacedHash(ns, "x", { truncateBytes: 0 }); }
  catch (e) { cnhBadTruncZero = /truncateBytes must be/.test(e.message); }
  check("computeNamespacedHash truncateBytes:0 throws", cnhBadTruncZero);

  var cnhBadTruncFloat = false;
  try { b.cryptoField.computeNamespacedHash(ns, "x", { truncateBytes: 2.5 }); }
  catch (e) { cnhBadTruncFloat = /truncateBytes must be/.test(e.message); }
  check("computeNamespacedHash non-integer truncateBytes throws", cnhBadTruncFloat);

  console.log("OK — crypto-field derived-hash tests");
}

module.exports = { run: run };
if (require.main === module) {
  // Rethrow on failure so Node surfaces the error and exits non-zero,
  // instead of logging the caught error object — a taint analyzer traces
  // a logged error back to the test passphrase fixture (a non-secret
  // constant) and raises a false clear-text-logging alert.
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
