// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * numeric-bounds — shared-validator layer-0 tests.
 *
 * v0.6.69 introduced lib/numeric-bounds.js to centralise the
 * `typeof === "number" && X > 0` pattern that was vulnerable to
 * Infinity / NaN bypass across at least 5 call sites (atomicFile,
 * safeBuffer (toBuffer + normalizeText + boundedChunkCollector),
 * csv, safeUrl, mailBounce). This test exercises both the helper
 * itself and a handful of consumer-side smoke calls so regressions
 * at any one call site fail loudly.
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var nb = require("../../lib/numeric-bounds");

function testHelperPredicate() {
  // Positive finite int — accepts
  check("isPositiveFiniteInt(1)",          nb.isPositiveFiniteInt(1) === true);
  check("isPositiveFiniteInt(64)",         nb.isPositiveFiniteInt(64) === true);
  check("isPositiveFiniteInt(67108864)",   nb.isPositiveFiniteInt(67108864) === true);

  // Rejected
  check("isPositiveFiniteInt(0)",          nb.isPositiveFiniteInt(0) === false);
  check("isPositiveFiniteInt(-1)",         nb.isPositiveFiniteInt(-1) === false);
  check("isPositiveFiniteInt(Infinity)",   nb.isPositiveFiniteInt(Infinity) === false);
  check("isPositiveFiniteInt(-Infinity)",  nb.isPositiveFiniteInt(-Infinity) === false);
  check("isPositiveFiniteInt(NaN)",        nb.isPositiveFiniteInt(NaN) === false);
  check("isPositiveFiniteInt(3.5)",        nb.isPositiveFiniteInt(3.5) === false);
  check("isPositiveFiniteInt('100')",      nb.isPositiveFiniteInt("100") === false);
  check("isPositiveFiniteInt(null)",       nb.isPositiveFiniteInt(null) === false);
  check("isPositiveFiniteInt(undefined)",  nb.isPositiveFiniteInt(undefined) === false);
  check("isPositiveFiniteInt(true)",       nb.isPositiveFiniteInt(true) === false);

  // Non-negative variant — same as above but accepts 0
  check("isNonNegativeFiniteInt(0)",       nb.isNonNegativeFiniteInt(0) === true);
  check("isNonNegativeFiniteInt(-1)",      nb.isNonNegativeFiniteInt(-1) === false);
  check("isNonNegativeFiniteInt(Infinity)",nb.isNonNegativeFiniteInt(Infinity) === false);
  check("isNonNegativeFiniteInt(NaN)",     nb.isNonNegativeFiniteInt(NaN) === false);

  // Shape format
  check("shape(Infinity)",   nb.shape(Infinity)   === "number Infinity");
  check("shape(NaN)",        nb.shape(NaN)        === "number NaN");
  check("shape(-1)",         nb.shape(-1)         === "number -1");
  check("shape(0.5)",        nb.shape(0.5)        === "number 0.5");
  check("shape('100')",      nb.shape("100")      === 'string "100"');
  check("shape(null)",       nb.shape(null)       === "object null");
  check("shape(undefined)",  nb.shape(undefined)  === "undefined undefined");
  check("shape(true)",       nb.shape(true)       === "boolean true");
}

function _expect(label, fn, expectedCode) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label,
        threw && threw.code === expectedCode);
}

function testConsumersRejectInfinity() {
  // safeBuffer.boundedChunkCollector
  _expect("boundedChunkCollector rejects Infinity",
    function () { b.safeBuffer.boundedChunkCollector({ maxBytes: Infinity }); },
    "buffer/bad-arg");
  _expect("boundedChunkCollector rejects NaN",
    function () { b.safeBuffer.boundedChunkCollector({ maxBytes: NaN }); },
    "buffer/bad-arg");

  // safeBuffer.toBuffer
  _expect("safeBuffer.toBuffer rejects Infinity",
    function () { b.safeBuffer.toBuffer("hi", { maxBytes: Infinity }); },
    "buffer/bad-arg");

  // safeBuffer.normalizeText
  _expect("safeBuffer.normalizeText rejects Infinity",
    function () { b.safeBuffer.normalizeText("hi", { maxBytes: Infinity }); },
    "buffer/bad-arg");

  // atomicFile.readSync
  _expect("atomicFile.readSync rejects Infinity",
    function () { b.atomicFile.readSync("package.json", { maxBytes: Infinity }); },
    "atomic-file/bad-opt");

  // csv.parse
  _expect("csv.parse rejects Infinity",
    function () { b.csv.parse("a,b\n1,2", { maxBytes: Infinity }); },
    "csv/bad-opt");
  _expect("csv.parse rejects NaN",
    function () { b.csv.parse("a,b\n1,2", { maxBytes: NaN }); },
    "csv/bad-opt");

  // safeUrl.parse
  _expect("safeUrl.parse rejects maxUrlLength Infinity",
    function () { b.safeUrl.parse("https://x.com", { maxUrlLength: Infinity }); },
    "safe-url/bad-opt");

  // mailBounce.handler
  _expect("mailBounce rejects maxBytes Infinity",
    function () { b.mailBounce.handler({ vendor: "postmark", maxBytes: Infinity }); },
    "mail-bounce/bad-opt");

  // v0.6.70 — csp-nonce middleware. Pre-fix the typeof-only check
  // accepted Infinity / NaN, then crashed per-request inside
  // crypto.generateBytes(Infinity) with ERR_OUT_OF_RANGE.
  _expect("csp-nonce rejects nonceBytes Infinity",
    function () { b.middleware.cspNonce({ nonceBytes: Infinity }); },
    "csp-nonce/bad-nonce-bytes");
  _expect("csp-nonce rejects nonceBytes NaN",
    function () { b.middleware.cspNonce({ nonceBytes: NaN }); },
    "csp-nonce/bad-nonce-bytes");
  _expect("csp-nonce rejects nonceBytes 1.5",
    function () { b.middleware.cspNonce({ nonceBytes: 16.5 }); },
    "csp-nonce/bad-nonce-bytes");
}

function testConsumersAcceptLegitimate() {
  // Each accept path — these MUST not throw with legitimate inputs.
  b.safeBuffer.boundedChunkCollector({ maxBytes: 1024 });
  b.safeBuffer.toBuffer("hi", { maxBytes: 1024 });
  b.safeBuffer.normalizeText("hi", { maxBytes: 1024 });
  b.atomicFile.readSync("package.json", { maxBytes: 1000000 });
  b.csv.parse("a,b\n1,2", { maxBytes: 1000 });
  b.safeUrl.parse("https://x.com", { maxUrlLength: 50000 });
  b.mailBounce.handler({ vendor: "postmark" });
  check("legitimate maxBytes / maxUrlLength inputs pass through every consumer", true);
}

function _ErrK(code, message) { this.code = code; this.message = message; }

function testRequirePositiveFiniteInt() {
  // The REQUIRED sibling of requirePositiveFiniteIntIfPresent: unlike the
  // IfPresent form (which skips when undefined), the required form throws on
  // a missing value — so a required numeric opt can't slip through absent.
  check("requirePositiveFiniteInt accepts a valid value",
    nb.requirePositiveFiniteInt(5, "x", _ErrK, "n/bad") === 5);
  _expect("requirePositiveFiniteInt THROWS on undefined (required, not IfPresent)",
    function () { nb.requirePositiveFiniteInt(undefined, "x", _ErrK, "n/bad"); }, "n/bad");
  _expect("requirePositiveFiniteInt rejects Infinity",
    function () { nb.requirePositiveFiniteInt(Infinity, "x", _ErrK, "n/bad"); }, "n/bad");
  _expect("requirePositiveFiniteInt rejects 0 (not positive)",
    function () { nb.requirePositiveFiniteInt(0, "x", _ErrK, "n/bad"); }, "n/bad");
  // Optional { min, max } range — the bundler/mail-scan/safe-decompress shape.
  check("requirePositiveFiniteInt accepts in-range",
    nb.requirePositiveFiniteInt(50, "x", _ErrK, "n/bad", { min: 1, max: 100 }) === 50);
  _expect("requirePositiveFiniteInt rejects above max",
    function () { nb.requirePositiveFiniteInt(101, "x", _ErrK, "n/bad", { max: 100 }); }, "n/bad");
  _expect("requirePositiveFiniteInt rejects below min",
    function () { nb.requirePositiveFiniteInt(2, "x", _ErrK, "n/bad", { min: 5 }); }, "n/bad");
  var msg = null;
  try { nb.requirePositiveFiniteInt(70000, "port", _ErrK, "n/bad", { max: 65535 }); }
  catch (e) { msg = e.message; }
  check("range error names the bound + the offending shape",
    /<= 65535/.test(msg || "") && /number 70000/.test(msg || ""));
}

async function run() {
  testHelperPredicate();
  testRequirePositiveFiniteInt();
  testConsumersRejectInfinity();
  testConsumersAcceptLegitimate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
