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

function run() {
  testRangeContract();
  testDispersion();
  testInputValidation();
}

if (require.main === module) run();
module.exports = { run: run };
