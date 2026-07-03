// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditChain.verifyChain — a corrupted / tampered purge anchor must fail
 * CLOSED with a clear { ok:false, reason }, not throw. The anchor's
 * lastPurgedRowHash seeds prevHash; a non-128-hex value used to flow into
 * computeRowHash, which throws "prevHash must be a 128-char hex" — turning a
 * defensive verify into an uncaught exception. A non-numeric lastPurgedCounter
 * (NaN) would skip nothing and surface as an opaque chain-break.
 *
 * Driven through a mock queryAllAsync (no DB) — the fix returns before the
 * chain-rows query, so the rows mock is irrelevant.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockQuery(anchorRow) {
  return function (sql /*, params */) {
    if (typeof sql === "string" && sql.indexOf("purge_anchor") !== -1) {
      return Promise.resolve(anchorRow ? [anchorRow] : []);
    }
    // Chain-rows query — a single plausible row (never reached on a corrupt
    // anchor, but present so the non-corrupt branch could walk).
    return Promise.resolve([]);
  };
}

async function _verify(anchorRow) {
  var threw = null, result = null;
  try { result = await b.auditChain.verifyChain(_mockQuery(anchorRow), "audit_log", {}); }
  catch (e) { threw = e; }
  return { threw: threw, result: result };
}

async function run() {
  // Non-hex lastPurgedRowHash → { ok:false, reason }, NOT a throw.
  var bad1 = await _verify({ lastPurgedRowHash: "GARBAGE-not-hex", lastPurgedCounter: "5" });
  check("corrupted anchor (non-hex hash) does not throw", bad1.threw === null);
  check("corrupted anchor (non-hex hash) → ok:false", bad1.result && bad1.result.ok === false);
  check("corrupted anchor → reason names the anchor",
        bad1.result && /anchor/i.test(bad1.result.reason || ""));

  // Wrong-length hex hash → also refused.
  var bad2 = await _verify({ lastPurgedRowHash: "abcd", lastPurgedCounter: "1" });
  check("corrupted anchor (short hash) → ok:false, no throw",
        bad2.threw === null && bad2.result && bad2.result.ok === false);

  // Non-numeric lastPurgedCounter → refused (NaN would skip nothing).
  var validHash = b.auditChain.ZERO_HASH;
  var bad3 = await _verify({ lastPurgedRowHash: validHash, lastPurgedCounter: "not-a-number" });
  check("corrupted anchor (non-numeric counter) → ok:false, no throw",
        bad3.threw === null && bad3.result && bad3.result.ok === false);

  // No anchor at all (never purged) → verifies the (empty) chain fine, ok:true.
  var none = await _verify(null);
  check("no purge anchor → verifies cleanly (ok:true)", none.threw === null && none.result && none.result.ok === true);

  console.log("[audit-chain-corrupted-anchor] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {}, function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); });
}
