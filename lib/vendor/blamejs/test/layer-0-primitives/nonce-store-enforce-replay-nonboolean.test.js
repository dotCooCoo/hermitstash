// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.nonceStore.enforceReplay — fail CLOSED on any non-truthy checkAndInsert
 * return, not only a literal `false`.
 *
 * enforceReplay is the shared anti-replay helper b.auth.jwt.verify and
 * b.auth.dpop route their replay defense through. The nonce-store docstring
 * recommends fronting it with "Redis SETNX, Memcached add" backends — but
 * those return a NON-`false` falsy value on a duplicate:
 *
 *   - node-redis `SET key val NX`  → "OK" on insert, `null` on existing key
 *   - the SETNX command / SQL INSERT → 1 on insert, 0 on existing row
 *
 * A replay therefore surfaces to enforceReplay as `null` / `0`, neither of
 * which is `=== false`. An exact-literal compare admits the replayed token
 * (fail OPEN) — the exact class the framework already fixed at every inline
 * consumer (oauth.js `!inserted`, api-encrypt `!freshNonce`,
 * graphql-federation `!fresh`, webhook `!fresh`) but missed in the shared
 * helper. enforceReplay must refuse unless checkAndInsert positively confirms
 * the jti was first-seen (a truthy result).
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function RErr(code, message) { this.code = code; this.message = message; }

// A store whose checkAndInsert reports fresh via `freshVal` and replay via
// `replayVal` — models the recommended Redis-SETNX / SQL-INSERT backends.
function _shapedStore(freshVal, replayVal) {
  var seen = Object.create(null);
  return {
    checkAndInsert: function (nonce) {
      if (Object.prototype.hasOwnProperty.call(seen, nonce)) return Promise.resolve(replayVal);
      seen[nonce] = true;
      return Promise.resolve(freshVal);
    },
  };
}

async function _firstPassesThenReplayRefused(store, label) {
  var ropts = { errorClass: RErr, storeFailedCode: "x/store-failed", replayCode: "x/replay", tokenLabel: "token" };
  var exp = Date.now() + 60000;

  // First sighting must pass (truthy fresh value → no throw).
  var firstThrew = false;
  try { await b.nonceStore.enforceReplay(store, "jti-A", exp, ropts); }
  catch (_e) { firstThrew = true; }
  check(label + ": first use of a jti passes (truthy fresh admitted)", firstThrew === false);

  // Second sighting is a REPLAY. Store signals it via a non-`false` falsy
  // value; enforceReplay MUST refuse it (fail closed).
  var replayErr = null;
  try { await b.nonceStore.enforceReplay(store, "jti-A", exp, ropts); }
  catch (e) { replayErr = e; }
  check(label + ": replay refused with the replay code (fail closed, not fail open)",
    replayErr instanceof RErr && replayErr.code === "x/replay");
}

async function run() {
  // node-redis `SET ... NX` shape: "OK" on insert, null on existing key.
  await _firstPassesThenReplayRefused(_shapedStore("OK", null), "redis SET NX (OK/null)");

  // SETNX command / SQL INSERT ... ON CONFLICT shape: 1 on insert, 0 on dup.
  await _firstPassesThenReplayRefused(_shapedStore(1, 0), "setnx / sql insert (1/0)");

  // A store that returns undefined on a duplicate (a lax adapter) must also
  // fail closed rather than admit the replay.
  await _firstPassesThenReplayRefused(_shapedStore(true, undefined), "lax adapter (true/undefined)");

  // The canonical b.nonceStore contract (strict boolean) still works.
  await _firstPassesThenReplayRefused(_shapedStore(true, false), "canonical boolean (true/false)");

  console.log("OK — nonce-store enforceReplay non-boolean fail-closed tests");
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
