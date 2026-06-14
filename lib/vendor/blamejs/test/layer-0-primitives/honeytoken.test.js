"use strict";
/**
 * b.honeytoken — canary credential framework.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  var honey = b.honeytoken.create({});
  check("honeytoken.create returns issue/lookup/revoke",
    typeof honey.issue === "function" && typeof honey.lookup === "function" &&
    typeof honey.revoke === "function" && typeof honey.size === "function");

  var issued = honey.issue({ kind: "apiKey", metadata: { plantedAt: "test" } });
  check("honeytoken.issue: returns id + value",
    typeof issued.id === "string" && typeof issued.value === "string" &&
    issued.value.indexOf("bk_canary_") === 0);

  var record = honey.lookup(issued.value, { ip: "203.0.113.5" });
  check("honeytoken.lookup: tripped record returned",
    record && record.id === issued.id && record.kind === "apiKey");

  check("honeytoken.lookup: unknown value returns null",
    honey.lookup("not-a-canary") === null);

  check("honeytoken.revoke: known id removed",
    honey.revoke(issued.id) === true && honey.size() === 0);

  var threw;
  try { honey.issue({ kind: "garbage" }); } catch (e) { threw = e; }
  check("honeytoken.issue: unknown kind throws",
    threw && threw.code === "honeytoken/unknown-kind");

  check("honeytoken.KINDS exports the supported list",
    Array.isArray(b.honeytoken.KINDS) && b.honeytoken.KINDS.indexOf("apiKey") !== -1);

  check("honeytoken.HoneytokenError class registered",
    typeof b.honeytoken.HoneytokenError === "function");

  // ---- injected audit sink (opts.audit) ----
  // The documented `audit: b.audit` sink must receive issued + tripped
  // rows when supplied, instead of the module's default audit log.
  var captured = [];
  var sink = { safeEmit: function (rec) { captured.push(rec); } };
  var honeyInj = b.honeytoken.create({ audit: sink });
  var injIssued = honeyInj.issue({ kind: "url", metadata: { plantedAt: "admin-listing" } });
  check("honeytoken.audit: injected sink received issued row",
    captured.length === 1 && captured[0].action === "honeytoken.issued" &&
    captured[0].metadata.id === injIssued.id && captured[0].metadata.kind === "url");
  honeyInj.lookup(injIssued.value, { ip: "198.51.100.7" });
  check("honeytoken.audit: injected sink received tripped row",
    captured.length === 2 && captured[1].action === "honeytoken.tripped" &&
    captured[1].outcome === "failure" && captured[1].metadata.id === injIssued.id &&
    captured[1].metadata.observedActor && captured[1].metadata.observedActor.ip === "198.51.100.7");
  check("honeytoken.audit: lookup miss emits nothing to the sink",
    honeyInj.lookup("not-a-canary") === null && captured.length === 2);

  // Default path (no sink) still emits to the module audit log without
  // throwing — exercised by the surface tests above, asserted here via
  // a fresh registry whose issue/lookup don't blow up.
  var honeyDefault = b.honeytoken.create({});
  var d = honeyDefault.issue({ kind: "rowId", metadata: null });
  check("honeytoken.audit: default sink path issues without throwing",
    typeof d.value === "string" && d.value.indexOf("ht_canary_") === 0);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[honeytoken] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
