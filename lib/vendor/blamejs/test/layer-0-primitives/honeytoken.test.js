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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[honeytoken] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
