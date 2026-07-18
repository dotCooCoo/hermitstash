// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeBuffer.stripCrlf — remove every CR and LF from a string,
 * substituting the replacement argument (default ""). Used to
 * neutralize header-injection / smuggling vectors when the framework
 * must serialize an operator-supplied string into a CRLF-delimited
 * protocol line and prefers silent stripping over rejecting. Non-string
 * input passes through unchanged.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function run() {
  var sb = b.safeBuffer;

  // ---- default replacement drops CR/LF entirely ----
  check("b.safeBuffer.stripCrlf: CRLF removed with the empty-string default",
    b.safeBuffer.stripCrlf("ok\r\nbad") === "okbad");
  check("stripCrlf: a bare CR is removed", sb.stripCrlf("a\rb") === "ab");
  check("stripCrlf: a bare LF is removed", sb.stripCrlf("a\nb") === "ab");
  check("stripCrlf: every CR/LF in a run is removed",
    sb.stripCrlf("h\r\ni\rj\nk") === "hijk");

  // ---- header-injection scenario the primitive exists for ----
  // An operator value carrying a CRLF + a forged header must collapse
  // onto one line so it can't smuggle a second header.
  check("stripCrlf: neutralizes a CRLF header-injection payload",
    b.safeBuffer.stripCrlf("value\r\nX-Injected: evil") === "valueX-Injected: evil");

  // ---- custom replacement ----
  check("stripCrlf: custom replacement substitutes each CR/LF",
    b.safeBuffer.stripCrlf("a\nb\nc", " ") === "a b c");
  check("stripCrlf: each CR and LF is replaced individually",
    sb.stripCrlf("h\r\ni", "-") === "h--i");
  check("stripCrlf: an explicit empty replacement matches the default",
    sb.stripCrlf("a\nb", "") === "ab");

  // ---- no CR/LF present → unchanged ----
  check("stripCrlf: a clean string is returned unchanged",
    sb.stripCrlf("no-newlines-here") === "no-newlines-here");
  check("stripCrlf: an empty string stays empty", sb.stripCrlf("") === "");

  // ---- non-string passthrough (advertised) ----
  check("stripCrlf: a number passes through unchanged", b.safeBuffer.stripCrlf(42) === 42);
  check("stripCrlf: undefined passes through unchanged", sb.stripCrlf(undefined) === undefined);
  check("stripCrlf: null passes through unchanged", sb.stripCrlf(null) === null);
  var obj = { a: 1 };
  check("stripCrlf: a non-string object passes through by identity", sb.stripCrlf(obj) === obj);

  // ---- byteLengthOfIfMeasurable: measures byte-carriers, null for the rest ----
  check("byteLengthOfIfMeasurable: string → UTF-8 byte length",
    b.safeBuffer.byteLengthOfIfMeasurable("中") === 3);
  check("byteLengthOfIfMeasurable: Buffer → length",
    b.safeBuffer.byteLengthOfIfMeasurable(Buffer.from([1, 2, 3, 4])) === 4);
  check("byteLengthOfIfMeasurable: Uint8Array → length",
    b.safeBuffer.byteLengthOfIfMeasurable(new Uint8Array(5)) === 5);
  // The non-byte-carrier cases the guard-family byte cap must skip rather than
  // crash on — a plain Array, an array-like object, a number, null/undefined.
  check("byteLengthOfIfMeasurable: plain Array → null",
    b.safeBuffer.byteLengthOfIfMeasurable([1, 2, 3]) === null);
  check("byteLengthOfIfMeasurable: array-like object → null",
    b.safeBuffer.byteLengthOfIfMeasurable({ length: 1e9 }) === null);
  check("byteLengthOfIfMeasurable: number → null",
    b.safeBuffer.byteLengthOfIfMeasurable(42) === null);
  check("byteLengthOfIfMeasurable: null → null",
    b.safeBuffer.byteLengthOfIfMeasurable(null) === null);
  check("byteLengthOfIfMeasurable: undefined → null",
    b.safeBuffer.byteLengthOfIfMeasurable(undefined) === null);
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
