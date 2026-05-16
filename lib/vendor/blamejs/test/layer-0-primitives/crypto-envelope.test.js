"use strict";
/**
 * b.crypto envelope wire format — FixedInfo-bound KDF + 4-byte
 * envelope-header AAD round trip. The decrypt path reconstructs
 * both bindings from the envelope prefix; a tampered header
 * surfaces as a Poly1305 tag failure.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  var keys = b.crypto.generateEncryptionKeyPair();
  var ct = b.crypto.encrypt("blamejs envelope test", keys);
  var pt = b.crypto.decrypt(ct, keys);
  check("crypto.encrypt → decrypt round trip", pt === "blamejs envelope test");

  var raw = Buffer.from(ct, "base64");
  check("envelope magic byte = 0xE2 (FixedInfo-bound)", raw[0] === 0xE2);

  // Tamper with the cipherId byte — bypasses the unsupported-cipher
  // check (since the same id is the only one accepted) and forces
  // the Poly1305 tag check on the AAD-bound header to fail.
  var tampered = Buffer.from(raw);
  tampered[2] = (tampered[2] ^ 0x01) & 0xff;                                       // allow:raw-byte-literal — single-bit flip in cipherId
  var threw;
  try { b.crypto.decrypt(tampered.toString("base64"), keys); }
  catch (e) { threw = e; }
  check("decrypt refuses header-tampered envelope",
    threw && /unsupported|invalid|tag|auth/i.test(threw.message));

  // Legacy 0xE1 envelope — refused by default.
  var legacy = Buffer.alloc(64);
  legacy[0] = 0xE1;
  var threwLegacy;
  try { b.crypto.decrypt(legacy.toString("base64"), keys); }
  catch (e) { threwLegacy = e; }
  check("decrypt refuses legacy 0xE1 envelope by default",
    threwLegacy && /legacy 0xE1|FixedInfo/i.test(threwLegacy.message));

  // Legacy 0xE1 envelope — refusal message points operators at the
  // allowLegacy opt-in for migration.
  check("decrypt refusal hints at allowLegacy migration path",
    threwLegacy && /allowLegacy/.test(threwLegacy.message));

  // Round-trip an actual 0xE1-shape envelope under allowLegacy: true.
  // Mint by sealing under the production encrypt() and patching:
  //   - magic byte 0xE2 → 0xE1
  //   - re-derive the symmetricKey from the same KEM material WITHOUT
  //     FixedInfo (pre-bump KDF input shape), re-encrypt the body,
  //     re-emit the envelope.
  // This is test-only — operators never mint 0xE1; they only READ it.
  var fixturePlaintext = "legacy-payload";
  var fixtureBlob = b.crypto._mintLegacyEnvelope0xE1(fixturePlaintext, {
    publicKey:   keys.publicKey,
    ecPublicKey: keys.ecPublicKey,
  });
  var opened = b.crypto.decrypt(fixtureBlob, keys, { allowLegacy: true });
  check("decrypt round-trips a 0xE1 envelope under allowLegacy",
    opened === fixturePlaintext);

  // allowLegacy: true on a current 0xE2 envelope does not change behavior.
  var currentBlob = b.crypto.encrypt("not-legacy", {
    publicKey:   keys.publicKey,
    ecPublicKey: keys.ecPublicKey,
  });
  var openedCurrent = b.crypto.decrypt(currentBlob, keys, { allowLegacy: true });
  check("decrypt with allowLegacy still opens current envelope",
    openedCurrent === "not-legacy");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[crypto-envelope] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
