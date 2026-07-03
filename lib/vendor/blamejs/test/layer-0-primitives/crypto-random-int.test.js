// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.randomInt — CSPRNG-backed uniform integer in [min, max).
 *
 * Run standalone: `node test/layer-0-primitives/crypto-random-int.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function testRangeContract() {
  var n = b.crypto.randomInt(0, 100);
  check("returns a number",       typeof n === "number");
  check("integer-valued",         Math.floor(n) === n);
  check("at or above min",        n >= 0);
  check("strictly below max",     n < 100);

  // Tight half-open range — single integer { 7 } via [7, 8).
  var seven = b.crypto.randomInt(7, 8);
  check("single-integer range pins value", seven === 7);

  // Negative bounds round-trip.
  var neg = b.crypto.randomInt(-10, -5);
  check("negative range above min",        neg >= -10);
  check("negative range strictly below max", neg < -5);
}

function testDispersion() {
  // 256 draws over [0, 16): every bucket should appear at least once
  // with overwhelming probability for a uniform CSPRNG. Two missing
  // buckets in a row would suggest a stuck bit.
  var hist = new Array(16);
  for (var i = 0; i < 16; i += 1) hist[i] = 0;
  for (var j = 0; j < 256; j += 1) hist[b.crypto.randomInt(0, 16)] += 1;
  var emptyBuckets = 0;
  for (var k = 0; k < 16; k += 1) if (hist[k] === 0) emptyBuckets += 1;
  check("every bucket hit at least once in 256 draws", emptyBuckets === 0);
}

function testInputValidation() {
  var threw;
  threw = false;
  try { b.crypto.randomInt("a", 10); } catch (_e) { threw = true; }
  check("string min throws TypeError", threw);

  threw = false;
  try { b.crypto.randomInt(0, "b"); } catch (_e) { threw = true; }
  check("string max throws TypeError", threw);

  threw = false;
  try { b.crypto.randomInt(1.5, 10); } catch (_e) { threw = true; }
  check("non-integer min throws TypeError", threw);

  threw = false;
  try { b.crypto.randomInt(10, 10); } catch (_e) { threw = true; }
  check("max === min throws RangeError", threw);

  threw = false;
  try { b.crypto.randomInt(10, 5); } catch (_e) { threw = true; }
  check("max < min throws RangeError", threw);
}

function testGenerateBytesUniformity() {
  // Regression: Node's SHAKE256 XOF is non-uniform at outputLength 1
  // (byte values 0x00 / 0xff never occur, low bit skews to ~0.54).
  // b.crypto.random draws >= 2 bytes and slices so a 1-byte request
  // is still uniform — without this, every per-byte CSPRNG consumer
  // (e.g. b.ai.dp noise sampling) would inherit the bias.
  var N = 60000;
  var sawZero = false, sawMax = false, lowBitOnes = 0;
  for (var i = 0; i < N; i += 1) {
    var byte = b.crypto.generateBytes(1)[0];
    if (byte === 0) sawZero = true;
    if (byte === 255) sawMax = true;                       // allow:raw-byte-literal — 0xff byte value, not a size
    lowBitOnes += (byte & 1);
  }
  check("generateBytes(1) can emit 0x00", sawZero);
  check("generateBytes(1) can emit 0xff", sawMax);
  var lowBitFrac = lowBitOnes / N;
  check("generateBytes(1) low bit is balanced (~0.5)", lowBitFrac > 0.47 && lowBitFrac < 0.53);
}

function run() {
  testRangeContract();
  testDispersion();
  testInputValidation();
  testGenerateBytesUniformity();
}

if (require.main === module) run();
module.exports = { run: run };
