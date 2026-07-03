// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.nonceStore.release(nonce) — the rollback half of reserve -> commit ->
 * rollback (#325).
 *
 * An eager checkAndInsert claim with no un-claim inverts the at-least-once
 * contract: when downstream processing fails and the provider redelivers, the
 * already-claimed id reads as a replay and the event is dropped. release()
 * un-claims so the redelivery is reprocessed. The cluster backend's release
 * (DELETE by nonce hash) is exercised in the live-integration suite; here we
 * cover the memory + custom backends.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  var exp = Date.now() + 60000;

  // ---- memory backend: reserve -> replay -> release -> re-reserve ----
  var s = b.nonceStore.create({ backend: "memory" });
  check("#325 first claim wins (reserve)", (await s.checkAndInsert("evt-1", exp)) === true);
  check("#325 a concurrent duplicate reads as replay", (await s.checkAndInsert("evt-1", exp)) === false);
  check("#325 release un-claims a live nonce (returns true)", (await s.release("evt-1")) === true);
  check("#325 a redelivery after release is reprocessed (re-claim wins)",
    (await s.checkAndInsert("evt-1", exp)) === true);
  check("#325 commit path: WITHOUT release the duplicate stays suppressed",
    (await s.checkAndInsert("evt-1", exp)) === false);
  check("#325 release of a never-claimed nonce returns false", (await s.release("never-seen")) === false);

  var threwBad = false;
  try { await s.release(""); } catch (e) { threwBad = /INVALID_NONCE/.test(e.code || ""); }
  check("#325 release rejects an empty nonce", threwBad);
  s.close();

  // ---- custom backend: release forwarded when present, loud when absent ----
  var forwarded = null;
  var withRelease = b.nonceStore.create({ backend: {
    checkAndInsert: function () { return Promise.resolve(true); },
    release:        function (n) { forwarded = n; return Promise.resolve(true); },
  } });
  await withRelease.release("evt-Z");
  check("#325 a custom backend's release() is forwarded", forwarded === "evt-Z");

  var withoutRelease = b.nonceStore.create({ backend: {
    checkAndInsert: function () { return Promise.resolve(true); },
  } });
  var threwNoRel = false;
  try { await withoutRelease.release("x"); } catch (e) { threwNoRel = /BACKEND_NO_RELEASE/.test(e.code || ""); }
  check("#325 a custom backend without release() fails loudly (no silent dropped rollback)", threwNoRel);

  // ---- enforceReplay: first use passes; replay refused; store-throw fails closed ----
  function RErr(code, message) { this.code = code; this.message = message; }
  var ropts = { errorClass: RErr, storeFailedCode: "x/store-failed", replayCode: "x/replay", tokenLabel: "token" };
  var rs = b.nonceStore.create({ backend: "memory" });
  await b.nonceStore.enforceReplay(rs, "jti-A", exp, ropts);
  check("enforceReplay: first use of a jti passes (no throw)", true);
  var replayErr = null;
  try { await b.nonceStore.enforceReplay(rs, "jti-A", exp, ropts); } catch (e) { replayErr = e; }
  check("enforceReplay: a re-used jti is refused with the replay code + message",
    replayErr instanceof RErr && replayErr.code === "x/replay" &&
    replayErr.message === "token jti='jti-A' has been seen before — replay refused");
  rs.close();

  // A store failure must fail CLOSED (store-failed error), never silently pass.
  var failStore = b.nonceStore.create({ backend: {
    checkAndInsert: function () { return Promise.reject(new Error("db down")); },
  } });
  var storeErr = null;
  try { await b.nonceStore.enforceReplay(failStore, "jti-B", exp, ropts); } catch (e) { storeErr = e; }
  check("enforceReplay: a store failure fails closed (store-failed code, not a pass)",
    storeErr instanceof RErr && storeErr.code === "x/store-failed" &&
    storeErr.message.indexOf("replayStore.checkAndInsert threw: db down") === 0);
}

module.exports = { run: run };
