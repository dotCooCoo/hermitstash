// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.crypto facade — the cross-protocol surface that sits above the
 * pgp + smime sub-namespaces (lib/mail-crypto.js).
 *
 * The two sub-modules each define their OWN `MailCryptoError` class via
 * defineClass, so `instanceof` does not span them. `isMailCryptoError`
 * is the duck-type check that returns true for a MailCryptoError raised
 * by EITHER protocol, giving operators one cross-protocol catch-all.
 * These tests drive the facade through real errors thrown by each
 * sub-namespace (not synthetic shapes) and pin the negative cases.
 *
 * Run standalone: `node test/layer-0-primitives/mail-crypto.test.js`
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// Capture a real MailCryptoError raised by the PGP sub-namespace. A
// malformed WKD email is refused at computeUrl with a pgp-side
// MailCryptoError — the operator-visible failure path.
function _pgpError() {
  try { b.mail.crypto.pgp.experimental.wkd.computeUrl("no-at-sign"); return null; }
  catch (e) { return e; }
}

// Capture a real MailCryptoError raised by the S/MIME sub-namespace.
// verifyAll(null) fails the entry-point requireObject guard with an
// smime-side MailCryptoError.
function _smimeError() {
  try { b.mail.crypto.smime.verifyAll(null); return null; }
  catch (e) { return e; }
}

function testSurface() {
  check("facade: b.mail.crypto namespace",           typeof b.mail.crypto === "object");
  check("facade: isMailCryptoError is a function",   typeof b.mail.crypto.isMailCryptoError === "function");
  check("facade: MailCryptoError class re-exported", typeof b.mail.crypto.MailCryptoError === "function");
}

// The whole reason the facade helper exists: each sub-module defines a
// DISTINCT MailCryptoError class, so instanceof against the facade class
// only spans one protocol — but isMailCryptoError spans both.
function testCrossProtocolTrue() {
  var pgpErr   = _pgpError();
  var smimeErr = _smimeError();
  check("pgp path actually threw a MailCryptoError",
    pgpErr && pgpErr.code === "mail-crypto/pgp/bad-email");
  check("smime path actually threw a MailCryptoError",
    smimeErr && smimeErr.code === "mail-crypto/smime/bad-opts");

  check("isMailCryptoError true for a PGP-raised error",
    b.mail.crypto.isMailCryptoError(pgpErr) === true);
  check("isMailCryptoError true for an S/MIME-raised error",
    b.mail.crypto.isMailCryptoError(smimeErr) === true);

  // The facade class is the PGP one; the S/MIME error is a genuinely
  // different class, so instanceof does NOT span it — which is precisely
  // the gap isMailCryptoError closes.
  check("PGP error is instanceof the facade MailCryptoError",
    pgpErr instanceof b.mail.crypto.MailCryptoError);
  check("S/MIME error is NOT instanceof the facade class (distinct class)",
    (smimeErr instanceof b.mail.crypto.MailCryptoError) === false);
  check("isMailCryptoError spans the class boundary instanceof cannot",
    b.mail.crypto.isMailCryptoError(smimeErr) === true &&
    (smimeErr instanceof b.mail.crypto.MailCryptoError) === false);
}

function testNegatives() {
  check("false for a plain Error",       b.mail.crypto.isMailCryptoError(new Error("x")) === false);
  check("false for a TypeError",         b.mail.crypto.isMailCryptoError(new TypeError("x")) === false);
  check("false for null",                b.mail.crypto.isMailCryptoError(null) === false);
  check("false for undefined",           b.mail.crypto.isMailCryptoError(undefined) === false);
  check("false for a string",            b.mail.crypto.isMailCryptoError("MailCryptoError") === false);
  check("false for a number",            b.mail.crypto.isMailCryptoError(42) === false);
  check("false for a bare object",       b.mail.crypto.isMailCryptoError({}) === false);
  // A non-true flag value must not pass the === true check.
  check("false when the flag is truthy-but-not-true",
    b.mail.crypto.isMailCryptoError({ isMailCryptoError: 1 }) === false);
}

// The advertised contract is a duck-type on the `isMailCryptoError === true`
// flag both classes set — not class identity. An object carrying that exact
// flag is classified true by design (documents current behavior).
function testDuckTypeContract() {
  check("duck-type: an object with isMailCryptoError===true is classified true",
    b.mail.crypto.isMailCryptoError({ isMailCryptoError: true }) === true);
}

function run() {
  testSurface();
  testCrossProtocolTrue();
  testNegatives();
  testDuckTypeContract();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("[mail-crypto] OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  }
}
