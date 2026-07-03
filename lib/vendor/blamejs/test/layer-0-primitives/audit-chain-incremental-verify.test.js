// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditChain.verifyChain({ from, to }) — incremental audit-chain verify.
 *
 * verify() advertises from/to (start/end monotonicCounter) for "incremental
 * verify after a known-good checkpoint", but verifyChain ignored them and always
 * walked the whole chain. The fix scopes the walk to [from, to] and anchors
 * `from` on the predecessor row's rowHash so the scoped chain math is correct.
 * Security-critical: an in-range tamper MUST be caught; an out-of-range tamper is
 * (correctly) out of scope for an incremental verify.
 *
 * Driven through a mock queryAllAsync over a synthetic, genuinely-chained set of
 * rows (audit_log is append-only, so a real UPDATE can't forge a tamper).
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var ac = b.auditChain;

function _mkChain(n) {
  var rows = [];
  var prev = ac.ZERO_HASH;
  for (var i = 1; i <= n; i++) {
    var nonce = Buffer.alloc(16, i);
    var fields = { monotonicCounter: i, action: "test.row", outcome: "success" };
    var rowHash = ac.computeRowHash(prev, fields, nonce);
    rows.push(Object.assign({}, fields, { prevHash: prev, rowHash: rowHash, nonce: nonce }));
    prev = rowHash;
  }
  return rows;
}

function _mockQuery(chainRows) {
  return function (sql) {
    if (typeof sql === "string" && sql.indexOf("purge_anchor") !== -1) return Promise.resolve([]);
    // Return a shallow copy so verifyChain's coerce/filter can't mutate ours.
    return Promise.resolve(chainRows.map(function (r) { return Object.assign({}, r); }));
  };
}

async function _verify(chainRows, opts) {
  return await ac.verifyChain(_mockQuery(chainRows), "audit_log", opts || {});
}

async function run() {
  var chain = _mkChain(6);

  check("full verify of a clean chain → ok", (await _verify(chain)).ok === true);
  // Incremental from a mid counter: must anchor on row 3's rowHash. A naive
  // ZERO_HASH anchor would falsely report a prevHash break on row 4.
  check("incremental {from:4} on clean chain → ok (predecessor-anchored)",
        (await _verify(chain, { from: 4 })).ok === true);
  check("bounded {to:3} on clean chain → ok", (await _verify(chain, { to: 3 })).ok === true);
  check("windowed {from:3,to:5} on clean chain → ok", (await _verify(chain, { from: 3, to: 5 })).ok === true);

  // Tamper row 5 (counter 5): flip a hashed field so its stored rowHash no
  // longer matches the recompute.
  var tampered = chain.map(function (r) { return Object.assign({}, r); });
  tampered[4].outcome = "TAMPERED";   // counter 5

  check("full verify catches the tamper", (await _verify(tampered)).ok === false);
  check("incremental {from:4} catches in-range tamper (counter 5)",
        (await _verify(tampered, { from: 4 })).ok === false);
  // Counter 5 is below from=6 → out of scope for that incremental verify.
  check("incremental {from:6} → ok (tamper at 5 out of scope)",
        (await _verify(tampered, { from: 6 })).ok === true);
  // Counter 5 is above to=4 → out of the window.
  check("bounded {to:4} → ok (tamper at 5 above the window)",
        (await _verify(tampered, { to: 4 })).ok === true);

  // rowsVerified reflects the scoped count, not the whole chain.
  var inc = await _verify(chain, { from: 4 });
  check("incremental rowsVerified is the scoped count (3 rows: 4,5,6)", inc.rowsVerified === 3);

  console.log("[audit-chain-incremental-verify] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {}, function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); });
}
