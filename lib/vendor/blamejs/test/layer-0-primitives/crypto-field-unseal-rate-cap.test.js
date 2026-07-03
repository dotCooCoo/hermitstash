// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cryptoField unseal-failure rate cap (CWE-307).
 *
 * A DB-write attacker who can write `vault:<crafted>` / `vault.aad:<…>`
 * payloads to sealed columns can force KEM-decapsulation / AEAD-verify on
 * attacker-controlled bytes on every read. unsealRow already nulls the
 * field + emits system.crypto.unseal_failed; the per-(actor, table,
 * column) sliding-window failure cap bounds the oracle: past `threshold`
 * failures inside `windowMs`, further unseal attempts for that tuple are
 * refused for `cooldownMs` with a typed CryptoFieldRateError + a distinct
 * system.crypto.unseal_rate_exceeded audit. The cap is ON BY DEFAULT
 * (v0.15.0) — armed at module load — so the oracle is bounded out of the
 * box; configureUnsealRateCap tunes the thresholds, and
 * configureUnsealRateCap(null) is the documented opt-out to audit-only.
 *
 * Every window / cooldown assertion drives an INJECTED clock — no real
 * sleeps — so the test is deterministic on contended runners.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

// A value that is shaped like an AAD-sealed envelope but is garbage —
// vaultAad.unseal throws on it, driving unsealRow's catch path.
var FORGED = "vault.aad:Zm9yZ2VkLWdhcmJhZ2U=";

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-ratecap-"));
  await b.vault.init({ mode: "plaintext", dataDir: dir });

  b.cryptoField.registerTable("cf_ratecap", {
    sealedFields: ["secret", "other"], aad: true, rowIdField: "id",
  });

  // ---- config-time validation (THROW tier) ----
  function throws(re, fn) {
    try { fn(); return false; } catch (e) { return re.test(e.message); }
  }
  check("bad threshold (0) throws",
    throws(/threshold must be/, function () { b.cryptoField.configureUnsealRateCap({ threshold: 0 }); }));
  check("bad threshold (Infinity) throws",
    throws(/threshold must be/, function () { b.cryptoField.configureUnsealRateCap({ threshold: Infinity }); }));
  check("bad threshold (float) throws",
    throws(/threshold must be/, function () { b.cryptoField.configureUnsealRateCap({ threshold: 2.5 }); }));
  check("bad windowMs throws",
    throws(/windowMs must be/, function () { b.cryptoField.configureUnsealRateCap({ threshold: 3, windowMs: -1 }); }));
  check("bad cooldownMs throws",
    throws(/cooldownMs must be/, function () { b.cryptoField.configureUnsealRateCap({ threshold: 3, cooldownMs: 0 }); }));
  check("bad now (not a function) throws",
    throws(/now must be/, function () { b.cryptoField.configureUnsealRateCap({ threshold: 3, now: 5 }); }));
  check("bad onAudit (not a function) throws",
    throws(/onAudit must be/, function () { b.cryptoField.configureUnsealRateCap({ threshold: 3, onAudit: "x" }); }));
  check("unknown opt key throws",
    throws(/unknown|allowed|cryptoField.configureUnsealRateCap/i,
      function () { b.cryptoField.configureUnsealRateCap({ threshold: 3, bogus: 1 }); }));

  // ---- default ON (v0.15.0): the cap is armed at module load, so a
  // forged-ciphertext oracle is bounded with no operator action. The
  // default threshold (10) trips well before 50 hammered unseals. ----
  b.cryptoField.clearRateCapForTest();   // restores the secure DEFAULT cap
  var defaultThrew = false;
  for (var k = 0; k < 50; k++) {
    try { b.cryptoField.unsealRow("cf_ratecap", { id: "r1", secret: FORGED }, "default-attacker"); }
    catch (e) {
      if (e.code === "crypto-field/unseal-rate-exceeded") defaultThrew = true;
    }
  }
  check("cap default-ON: forged-unseal oracle is bounded out of the box",
    defaultThrew === true);

  // ---- documented opt-out: configureUnsealRateCap(null) restores the
  // pre-v0.15.0 audit-only behaviour (no throw on a forged read). ----
  b.cryptoField.configureUnsealRateCap(null);
  var offThrew = false;
  for (var k2 = 0; k2 < 50; k2++) {
    try { b.cryptoField.unsealRow("cf_ratecap", { id: "r1", secret: FORGED }, "optout-attacker"); }
    catch (_e) { offThrew = true; }
  }
  check("opt-out (configureUnsealRateCap(null)): 50 forged unseals never throw",
    offThrew === false);

  // ---- injected clock + audit sink ----
  var nowMs = 1000000;
  function clock() { return nowMs; }
  var audits = [];
  b.cryptoField.configureUnsealRateCap({
    threshold: 3, windowMs: 60000, cooldownMs: 300000,
    now: clock,
    onAudit: function (ev) { audits.push(ev); },
  });

  // The first `threshold-1` forged unseals null the field but do NOT trip.
  var r1 = { id: "r1", secret: FORGED };
  check("forged unseal #1 nulls field, no throw",
    b.cryptoField.unsealRow("cf_ratecap", r1, "attacker").secret === null);
  check("forged unseal #2 nulls field, no throw",
    b.cryptoField.unsealRow("cf_ratecap", r1, "attacker").secret === null);
  check("no rate audit before threshold reached", audits.length === 0);

  // The 3rd failure (== threshold) trips the cap: it still returns (nulls
  // the field) AND arms the cooldown + emits the distinct audit once.
  var third = b.cryptoField.unsealRow("cf_ratecap", r1, "attacker");
  check("threshold-th forged unseal still returns (field nulled)", third.secret === null);
  check("rate-exceeded audit emitted once on the trip transition", audits.length === 1);
  check("rate audit action is system.crypto.unseal_rate_exceeded",
    audits[0].action === "system.crypto.unseal_rate_exceeded");
  check("rate audit outcome is denied", audits[0].outcome === "denied");
  check("rate audit carries the tuple + caps",
    audits[0].metadata.table === "cf_ratecap" &&
    audits[0].metadata.field === "secret" &&
    audits[0].metadata.actor === "attacker" &&
    audits[0].metadata.threshold === 3);

  // Now in cooldown: the NEXT unseal of that tuple is REFUSED with the
  // typed error (oracle no longer exercised), and re-emits the audit.
  var refused = false, refusedCode = null;
  try { b.cryptoField.unsealRow("cf_ratecap", { id: "r1", secret: FORGED }, "attacker"); }
  catch (e) { refused = true; refusedCode = e.code; }
  check("cooldown refuses further unseal with a throw", refused === true);
  check("refusal is CryptoFieldRateError typed code",
    refusedCode === "crypto-field/unseal-rate-exceeded");
  check("refusal instanceof CryptoFieldRateError",
    (function () {
      try { b.cryptoField.unsealRow("cf_ratecap", { id: "r1", secret: FORGED }, "attacker"); return false; }
      catch (e) { return e instanceof b.cryptoField.CryptoFieldRateError; }
    })());
  check("each cooldown refusal re-emits the rate audit", audits.length >= 3);

  // ---- per-tuple isolation: a DIFFERENT column for the same actor is
  // unaffected (its own window is independent). ----
  var otherCol = b.cryptoField.unsealRow("cf_ratecap", { id: "r9", other: FORGED }, "attacker");
  check("different column for same actor is not in cooldown (nulls, no throw)",
    otherCol.other === null);

  // A DIFFERENT actor on the same column is likewise independent.
  var otherActor = b.cryptoField.unsealRow("cf_ratecap", { id: "r9", secret: FORGED }, "honest-user");
  check("different actor on same column is not in cooldown (nulls, no throw)",
    otherActor.secret === null);

  // ---- cooldown expiry: advance the injected clock past cooldownMs;
  // the tuple unseals normally again (a valid round-trip succeeds). ----
  nowMs += 300000 + 1;
  var validRow = b.cryptoField.sealRow("cf_ratecap", { id: "rok", secret: "plaintext-ok" });
  check("after cooldown expiry a VALID unseal succeeds again",
    b.cryptoField.unsealRow("cf_ratecap", validRow, "attacker").secret === "plaintext-ok");

  // ---- sliding window: re-arm a fresh cap; two failures, then advance
  // the clock past the window, then one more failure → still under
  // threshold (the first two slid out), so NO trip. ----
  audits.length = 0;
  nowMs = 5000000;
  b.cryptoField.configureUnsealRateCap({
    threshold: 3, windowMs: 60000, cooldownMs: 300000,
    now: clock,
    onAudit: function (ev) { audits.push(ev); },
  });
  b.cryptoField.unsealRow("cf_ratecap", { id: "w1", secret: FORGED }, "slider");
  b.cryptoField.unsealRow("cf_ratecap", { id: "w1", secret: FORGED }, "slider");
  nowMs += 60000 + 1;                          // both prior failures slide out of the window
  var afterSlide = b.cryptoField.unsealRow("cf_ratecap", { id: "w1", secret: FORGED }, "slider");
  check("sliding window: failures older than windowMs do not count toward threshold",
    afterSlide.secret === null && audits.length === 0);

  // Two MORE failures inside the new window DO trip (1 surviving + 2 new
  // = 3 == threshold).
  b.cryptoField.unsealRow("cf_ratecap", { id: "w1", secret: FORGED }, "slider");
  b.cryptoField.unsealRow("cf_ratecap", { id: "w1", secret: FORGED }, "slider");
  check("three failures within one window trip the cap", audits.length === 1);

  // ---- disable path: configureUnsealRateCap(null) restores audit-only ----
  b.cryptoField.configureUnsealRateCap(null);
  var afterDisable = false;
  try { b.cryptoField.unsealRow("cf_ratecap", { id: "w1", secret: FORGED }, "slider"); }
  catch (_e) { afterDisable = true; }
  check("configureUnsealRateCap(null) turns the cap back off (no throw)", afterDisable === false);

  b.cryptoField.clearRateCapForTest();
  console.log("OK — crypto-field unseal-rate-cap tests");
}

module.exports = { run: run };
if (require.main === module) {
  // Rethrow on failure so Node surfaces the error and exits non-zero,
  // instead of logging the caught error object (a taint analyzer would
  // trace a logged error back to a fixture and raise a false clear-text-
  // logging alert).
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
