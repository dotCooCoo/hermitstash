// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Memory rate-limit backends — get-or-insert routing regression guard.
 *
 * Both in-memory backends keep a request-keyed Map (token buckets /
 * fixed-window counters) and lazily create the per-key record on first
 * sight. This pins the observable verdict behaviour across the
 * insert path AND the existing-record path (token refill / window
 * rollover) so the routing of those get-or-insert sites through
 * b.boundedMap.getOrInsert stays behaviour-identical.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  var rateLimitMod = b.middleware._modules.rateLimit;

  // ---- token-bucket backend ----
  var tb = rateLimitMod._memoryTokenBucketBackend({ burst: 3, refillPerSecond: 1 });

  // First take on a brand-new key inserts the bucket and spends one token.
  var t1 = tb.take("ip-a", 1);
  check("token-bucket: first take allowed", t1.allowed === true);
  check("token-bucket: first take reports full burst as limit", t1.limit === 3);
  check("token-bucket: first take remaining = burst - 1", t1.remaining === 2);

  // Subsequent takes on the SAME key hit the existing-bucket branch and
  // keep decrementing (no refill in the same millisecond window).
  var t2 = tb.take("ip-a", 1);
  check("token-bucket: second take allowed", t2.allowed === true);
  check("token-bucket: second take remaining decremented", t2.remaining === 1);
  var t3 = tb.take("ip-a", 1);
  check("token-bucket: third take allowed", t3.allowed === true);
  var t4 = tb.take("ip-a", 1);
  check("token-bucket: fourth take denied (bucket drained)", t4.allowed === false);
  check("token-bucket: denied verdict has retryAfter", t4.retryAfter >= 1);

  // A different key gets its own fresh bucket (independent insert).
  var u1 = tb.take("ip-b", 1);
  check("token-bucket: distinct key gets fresh bucket", u1.allowed === true && u1.remaining === 2);

  // reset drops the key; the next take re-inserts a full bucket.
  tb.reset("ip-a");
  var t5 = tb.take("ip-a", 1);
  check("token-bucket: after reset, bucket re-inserted full", t5.allowed === true && t5.remaining === 2);
  tb.close();

  // ---- fixed-window backend ----
  var fw = rateLimitMod._memoryFixedWindowBackend({ max: 2, windowMs: 60000 });

  // First take inserts the counter (count -> 1).
  var f1 = fw.take("ip-c", 1);
  check("fixed-window: first take allowed", f1.allowed === true);
  check("fixed-window: first take limit = max", f1.limit === 2);
  check("fixed-window: first take remaining = max - 1", f1.remaining === 1);

  // Same window increments the existing counter.
  var f2 = fw.take("ip-c", 1);
  check("fixed-window: second take allowed (at max)", f2.allowed === true);
  check("fixed-window: second take remaining 0", f2.remaining === 0);
  var f3 = fw.take("ip-c", 1);
  check("fixed-window: third take over max denied", f3.allowed === false);
  check("fixed-window: denied verdict has retryAfter", f3.retryAfter >= 1);

  // Distinct key inserts its own counter.
  var g1 = fw.take("ip-d", 1);
  check("fixed-window: distinct key gets fresh counter", g1.allowed === true && g1.remaining === 1);

  // reset drops the key; next take re-inserts.
  fw.reset("ip-c");
  var f4 = fw.take("ip-c", 1);
  check("fixed-window: after reset, counter re-inserted", f4.allowed === true && f4.remaining === 1);
  fw.close();

  // ---- fixed-window: window rollover re-seeds the existing key ----
  // Drive a 1ms window so a real wall-clock advance rolls the window and
  // exercises the "key present but window changed -> re-seed" branch.
  var fwRoll = rateLimitMod._memoryFixedWindowBackend({ max: 1, windowMs: 1 });
  var r1 = fwRoll.take("ip-e", 1);
  check("fixed-window rollover: first take allowed", r1.allowed === true);
  await helpers.waitUntil(function () {
    // Once the wall clock advances past the 1ms window, a fresh take
    // re-seeds count to 1 and is allowed again on the SAME key.
    var v = fwRoll.take("ip-e", 1);
    return v.allowed === true;
  }, { timeoutMs: 5000, label: "fixed-window rollover: same key allowed in new window" });
  check("fixed-window rollover: same key re-seeded in new window", true);
  fwRoll.close();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
