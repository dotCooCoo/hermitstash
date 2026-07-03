// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.vault.aad — AAD-bound sealed columns.
 */

var b = require("../..");
var check = require("../helpers/check").check;
var fs = require("fs");
var path = require("path");
var os  = require("os");

function rejects(label, fn, pattern) {
  var threw = false; var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && (pattern.test ? pattern.test(msg) : msg.indexOf(pattern) !== -1));
}

async function run() {
  // ---- module shape ----
  check("b.vault.aad is object",                 typeof b.vault.aad === "object");
  check("b.vault.aad.seal is fn",                typeof b.vault.aad.seal === "function");
  check("b.vault.aad.unseal is fn",              typeof b.vault.aad.unseal === "function");
  check("b.vault.aad.reseal is fn",              typeof b.vault.aad.reseal === "function");
  check("b.vault.aad.isAadSealed is fn",         typeof b.vault.aad.isAadSealed === "function");
  check("b.vault.aad.buildColumnAad is fn",      typeof b.vault.aad.buildColumnAad === "function");
  check("b.vault.aad.buildContextAad is fn",     typeof b.vault.aad.buildContextAad === "function");
  check("b.vault.aad.AAD_PREFIX",                b.vault.aad.AAD_PREFIX === "vault.aad:");

  // ---- vault must be initialized ----
  // Seal before init throws via the vault path.
  rejects("seal: vault not initialized",
    function () { b.vault.aad.seal("plaintext", { table: "users", rowId: "u1", column: "email" }); },
    /vault\.init\(\) must be awaited/);

  // ---- initialize vault on a temp dir ----
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-aad-"));
  await b.vault.init({ dataDir: tmp, mode: "plaintext" });

  // ---- buildColumnAad ----
  var colAad = b.vault.aad.buildColumnAad({
    table: "users", rowId: "u-42", column: "email", schemaVersion: "v3",
  });
  check("buildColumnAad: table",                 colAad.table === "users");
  check("buildColumnAad: rowId stringified",     colAad.rowId === "u-42");
  check("buildColumnAad: column",                colAad.column === "email");
  check("buildColumnAad: schemaVersion",         colAad.schemaVersion === "v3");

  // schemaVersion default
  var noVer = b.vault.aad.buildColumnAad({
    table: "x", rowId: "1", column: "y",
  });
  check("buildColumnAad: schemaVersion default",  noVer.schemaVersion === "1");

  // numeric rowId stringified
  var numRow = b.vault.aad.buildColumnAad({
    table: "x", rowId: 42, column: "y",
  });
  check("buildColumnAad: numeric rowId → string", numRow.rowId === "42");

  rejects("buildColumnAad: missing table",
    function () { b.vault.aad.buildColumnAad({ rowId: "1", column: "x" }); }, /table/);
  rejects("buildColumnAad: missing rowId",
    function () { b.vault.aad.buildColumnAad({ table: "x", column: "y" }); }, /rowId/);
  rejects("buildColumnAad: missing column",
    function () { b.vault.aad.buildColumnAad({ table: "x", rowId: "1" }); }, /column/);

  // ---- seal/unseal happy path ----
  var aad1 = b.vault.aad.buildColumnAad({
    table: "users", rowId: "u-1", column: "email",
  });
  var sealed = b.vault.aad.seal("alice@example.com", aad1);
  check("seal: produces aad-prefixed string",     b.vault.aad.isAadSealed(sealed) === true);
  check("isAadSealed: prefix recognized",         sealed.indexOf("vault.aad:") === 0);

  var unsealed = b.vault.aad.unseal(sealed, aad1);
  check("unseal: round-trip",                     unsealed === "alice@example.com");

  // ---- AEAD authentication: different AAD breaks decrypt ----
  var aadOther = b.vault.aad.buildColumnAad({
    table: "users", rowId: "u-2", column: "email",       // different rowId
  });
  rejects("unseal: different rowId AAD → AEAD mismatch",
    function () { b.vault.aad.unseal(sealed, aadOther); },
    /AEAD authentication failed/);

  var aadDifferentColumn = b.vault.aad.buildColumnAad({
    table: "users", rowId: "u-1", column: "phone",       // different column
  });
  rejects("unseal: different column AAD → AEAD mismatch",
    function () { b.vault.aad.unseal(sealed, aadDifferentColumn); },
    /AEAD authentication failed/);

  var aadDifferentTable = b.vault.aad.buildColumnAad({
    table: "audit", rowId: "u-1", column: "email",       // different table
  });
  rejects("unseal: different table AAD → AEAD mismatch",
    function () { b.vault.aad.unseal(sealed, aadDifferentTable); },
    /AEAD authentication failed/);

  var aadDifferentVersion = b.vault.aad.buildColumnAad({
    table: "users", rowId: "u-1", column: "email", schemaVersion: "v2",
  });
  rejects("unseal: different schemaVersion AAD → AEAD mismatch",
    function () { b.vault.aad.unseal(sealed, aadDifferentVersion); },
    /AEAD authentication failed/);

  // ---- isAadSealed ----
  check("isAadSealed: plain string",             b.vault.aad.isAadSealed("plain") === false);
  check("isAadSealed: null",                     b.vault.aad.isAadSealed(null) === false);
  check("isAadSealed: number",                   b.vault.aad.isAadSealed(42) === false);

  // ---- buildContextAad ----
  var contextAad = b.vault.aad.buildContextAad({
    tenantId: "t-1", purpose: "analytics-export",
  });
  check("buildContextAad: tenantId",              contextAad.tenantId === "t-1");
  check("buildContextAad: purpose",               contextAad.purpose === "analytics-export");

  // null fields stripped
  var withNull = b.vault.aad.buildContextAad({
    tenantId: "t-1", purpose: null, missing: undefined, kept: "yes",
  });
  check("buildContextAad: null stripped",         withNull.purpose === undefined);
  check("buildContextAad: undefined stripped",    withNull.missing === undefined);
  check("buildContextAad: kept retained",         withNull.kept === "yes");

  rejects("buildContextAad: empty obj",
    function () { b.vault.aad.buildContextAad({}); }, /at least one/);
  rejects("buildContextAad: array",
    function () { b.vault.aad.buildContextAad([1, 2]); }, /plain object/);

  // poisoned keys stripped
  var poisoned = b.vault.aad.buildContextAad({
    tenantId: "t-1", "__proto__": "evil", "constructor": "evil",
  });
  check("buildContextAad: poisoned keys stripped", poisoned.__proto__ === Object.prototype);

  // ---- canonical-form determinism: order-insensitive ----
  var aadA = { table: "users", rowId: "u-1", column: "email", schemaVersion: "1" };
  var aadB = { schemaVersion: "1", column: "email", rowId: "u-1", table: "users" };
  var sealedA = b.vault.aad.seal("data", aadA);
  var openedB = b.vault.aad.unseal(sealedA, aadB);
  check("canonical AAD: order-insensitive",      openedB === "data");

  // ---- reseal ----
  var fromAad = b.vault.aad.buildColumnAad({
    table: "users", rowId: "u-1", column: "email",
  });
  var toAad = b.vault.aad.buildColumnAad({
    table: "users", rowId: "u-1", column: "email", schemaVersion: "v2",
  });
  var sealedFrom = b.vault.aad.seal("hello", fromAad);
  var sealedTo = b.vault.aad.reseal(sealedFrom, fromAad, toAad);
  check("reseal: produces new aad-sealed value",  b.vault.aad.isAadSealed(sealedTo));
  check("reseal: decrypts with new AAD",          b.vault.aad.unseal(sealedTo, toAad) === "hello");
  rejects("reseal: old AAD no longer works",
    function () { b.vault.aad.unseal(sealedTo, fromAad); }, /AEAD/);

  // reseal with bad source AAD throws
  rejects("reseal: wrong source AAD",
    function () { b.vault.aad.reseal(sealedFrom, toAad, fromAad); }, /AEAD/);

  // ---- error shapes ----
  rejects("seal: null plaintext",
    function () { b.vault.aad.seal(null, fromAad); }, /required/);
  rejects("seal: empty string",
    function () { b.vault.aad.seal("", fromAad); }, /non-empty/);
  rejects("seal: bad AAD shape",
    function () { b.vault.aad.seal("hi", null); }, /must be a plain object/);
  rejects("seal: empty AAD",
    function () { b.vault.aad.seal("hi", {}); }, /at least one/);
  rejects("seal: array AAD",
    function () { b.vault.aad.seal("hi", [1, 2]); }, /plain object/);

  // double-seal refused
  rejects("seal: refuses double-seal",
    function () { b.vault.aad.seal(sealed, fromAad); }, /already.*sealed/i);

  // ---- unseal error shapes ----
  rejects("unseal: not aad-sealed",
    function () { b.vault.aad.unseal("plaintext", fromAad); }, /not AAD-sealed/);
  rejects("unseal: null value",
    function () { b.vault.aad.unseal(null, fromAad); }, /non-empty string/);
  rejects("unseal: corrupted base64",
    function () { b.vault.aad.unseal("vault.aad:###not-base64###", fromAad); }, /AEAD authentication failed/);
  rejects("unseal: tampered ciphertext",
    function () {
      var s = b.vault.aad.seal("data", fromAad);
      var b64 = s.slice("vault.aad:".length);
      var buf = Buffer.from(b64, "base64");
      buf[buf.length - 1] = buf[buf.length - 1] ^ 0xFF;       // allow:raw-byte-literal — flip tag byte
      b.vault.aad.unseal("vault.aad:" + buf.toString("base64"), fromAad);
    },
    /AEAD authentication failed/);

  // ---- AAD with non-string / non-number / non-boolean values ----
  rejects("seal: object value in AAD",
    function () {
      b.vault.aad.seal("hi", { table: "u", rowId: { nested: "obj" } });
    },
    /must be string \/ number \/ boolean/);
  rejects("seal: array value in AAD",
    function () {
      b.vault.aad.seal("hi", { table: "u", rowId: [1, 2] });
    },
    /must be string \/ number \/ boolean/);

  // boolean value accepted
  var boolAad = { table: "users", rowId: "1", column: "active", flag: true };
  var sealedBool = b.vault.aad.seal("data", boolAad);
  check("seal: boolean AAD field",                b.vault.aad.unseal(sealedBool, boolAad) === "data");

  // numeric value accepted
  var numAad = { table: "users", rowId: 42, column: "x" };
  var sealedNum = b.vault.aad.seal("hello", numAad);
  check("seal: numeric AAD field",                b.vault.aad.unseal(sealedNum, numAad) === "hello");

  // ---- copy-paste-attack scenario ----
  // Operator seals two distinct rows' values. Attacker swaps the
  // ciphertexts. Both unseals should fail.
  var aliceAad = b.vault.aad.buildColumnAad({
    table: "users", rowId: "alice", column: "phone",
  });
  var bobAad = b.vault.aad.buildColumnAad({
    table: "users", rowId: "bob", column: "phone",
  });
  var aliceSealed = b.vault.aad.seal("+1-555-0101", aliceAad);
  var bobSealed   = b.vault.aad.seal("+1-555-0202", bobAad);

  // Attacker stores Alice's sealed value in Bob's row
  rejects("copy-paste: Alice → Bob fails",
    function () { b.vault.aad.unseal(aliceSealed, bobAad); }, /AEAD/);
  rejects("copy-paste: Bob → Alice fails",
    function () { b.vault.aad.unseal(bobSealed, aliceAad); }, /AEAD/);
  // But each row's own seal still works
  check("non-attack: Alice's own value works",   b.vault.aad.unseal(aliceSealed, aliceAad) === "+1-555-0101");
  check("non-attack: Bob's own value works",     b.vault.aad.unseal(bobSealed, bobAad) === "+1-555-0202");

  // ---- nonce uniqueness — two seals of same plaintext + AAD differ ----
  var s1 = b.vault.aad.seal("identical", aliceAad);
  var s2 = b.vault.aad.seal("identical", aliceAad);
  check("seal: non-deterministic (nonce uniqueness)", s1 !== s2);
  // both decrypt correctly
  check("seal: both nonces decrypt",             b.vault.aad.unseal(s1, aliceAad) === "identical");
  check("seal: both nonces decrypt (s2)",        b.vault.aad.unseal(s2, aliceAad) === "identical");

  // ---- AAD field name = poisoned key refused ----
  rejects("seal: __proto__ field name",
    function () {
      var evil = {};
      evil["__proto__"] = "x";
      evil.table = "u";
      // Object.keys won't return __proto__ from a literal, so we need
      // to inject it directly.
      Object.defineProperty(evil, "__proto__",
        { value: "x", enumerable: true, configurable: true });
      b.vault.aad.seal("hi", evil);
    },
    /forbidden|poisoned|table|must be a plain object/);

  // ---- vault rotation breaks prior seals (per design) ----
  // Skip this — would re-init the vault and conflict with concurrent tests

  // b.vault.getDerivedHashSalt — D-H1 per-deployment salt for
  // crypto-field derivedHashes. Just check the surface here; the
  // round-trip is exercised through the existing crypto-field tests.
  check("b.vault.getDerivedHashSalt is fn",
    typeof b.vault.getDerivedHashSalt === "function");

  console.log("OK — vault-aad tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { console.error(err); process.exit(1); });
}
