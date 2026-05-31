"use strict";
/**
 * b.cryptoField derived-hash modes.
 *
 * Equality-lookup ("derived") hashes for sealed columns can be computed
 * two ways:
 *   - salted-sha3   (default) — SHA3-512 over a per-deployment salt.
 *   - hmac-shake256 (opt-in)  — keyed MAC off vault.getDerivedHashMacKey,
 *                               so the hash is unforgeable without the
 *                               per-deployment MAC key.
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

  // ---- salted-sha3 is the default: SHA3-512 → 128 hex chars ----
  b.cryptoField.registerTable("cf_dh_t1", {
    sealedFields: ["email"],
    derivedHashes: { emailHash: { from: "email" } },
  });
  var saltedH = b.cryptoField.lookupHash("cf_dh_t1", "email", "a@b.com").value;
  check("salted-sha3 default is 128 hex (SHA3-512)", saltedH.length === 128);
  check("salted-sha3 is deterministic",
    saltedH === b.cryptoField.lookupHash("cf_dh_t1", "email", "a@b.com").value);

  // ---- hmac-shake256 table mode: SHAKE256/32 → 64 hex chars ----
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
