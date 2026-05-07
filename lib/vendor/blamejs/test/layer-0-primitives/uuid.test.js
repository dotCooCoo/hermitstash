"use strict";
/**
 * b.uuid — RFC 4122 v4 + RFC 9562 v7 generation, parse/validate.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _isHex(s) { return /^[0-9a-f]+$/i.test(s); }

async function run() {
  // ---- Surface ----
  check("b.uuid namespace present",       typeof b.uuid === "object");
  check("b.uuid.v4 is fn",                typeof b.uuid.v4 === "function");
  check("b.uuid.v7 is fn",                typeof b.uuid.v7 === "function");
  check("b.uuid.parse is fn",             typeof b.uuid.parse === "function");
  check("b.uuid.isValid is fn",           typeof b.uuid.isValid === "function");

  // ---- v4 ----
  var u4 = b.uuid.v4();
  check("v4 returns canonical 8-4-4-4-12 form",
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(u4));
  check("v4 sets version nibble to 4",        u4.charAt(14) === "4");
  check("v4 variant is RFC 4122",             /[89ab]/i.test(u4.charAt(19)));
  // Two consecutive v4s differ
  var a4 = b.uuid.v4();
  var b4 = b.uuid.v4();
  check("v4 is random across calls",          a4 !== b4);

  // ---- v7 ----
  var u7 = b.uuid.v7();
  check("v7 returns canonical 8-4-4-4-12 form",
        /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(u7));
  check("v7 sets version nibble to 7",        u7.charAt(14) === "7");
  check("v7 variant is RFC 4122",             /[89ab]/i.test(u7.charAt(19)));

  // v7 is time-ordered: an earlier `now` produces a UUID that sorts < a later one
  var early = b.uuid.v7({ now: 1000 });
  var late  = b.uuid.v7({ now: 2000000 });
  check("v7 is time-sortable (early < late)", early < late);

  // ms timestamp round-trips through bytes 0-5
  var fixed = b.uuid.v7({ now: 0x123456789abc });
  // bytes 0-5 = 12 34 56 78 9a bc → first 12 hex chars (excluding the dashes after 8 + 4)
  check("v7 timestamp encoded in first 48 bits",
        fixed.slice(0, 8) + fixed.slice(9, 13) === "123456789abc");

  // ---- parse ----
  var p4 = b.uuid.parse(u4);
  check("parse(v4): ok",                      p4.ok === true);
  check("parse(v4): version = 4",             p4.version === 4);
  check("parse(v4): bytes is 16-byte Buffer", Buffer.isBuffer(p4.bytes) && p4.bytes.length === 16);

  var p7 = b.uuid.parse(u7);
  check("parse(v7): version = 7",             p7.version === 7);

  // Bad inputs
  check("parse(non-string) → ok:false",       b.uuid.parse(42).ok === false);
  check("parse(empty) → ok:false",            b.uuid.parse("").ok === false);
  check("parse(too short) → ok:false",        b.uuid.parse("abc").ok === false);
  check("parse(no dashes) → ok:false",        b.uuid.parse(u4.replace(/-/g, "")).ok === false);
  // Bad version (0 not valid)
  var badVer = "12345678-1234-0123-8123-123456789012";
  check("parse(version 0) → ok:false",        b.uuid.parse(badVer).ok === false);
  // Bad variant (high two bits 00 instead of 10)
  var badVar = "12345678-1234-4123-0123-123456789012";
  check("parse(bad variant) → ok:false",      b.uuid.parse(badVar).ok === false);

  // ---- isValid (loose) ----
  check("isValid(v4) === true",                b.uuid.isValid(u4) === true);
  check("isValid(v7) === true",                b.uuid.isValid(u7) === true);
  check("isValid('not-a-uuid') === false",     b.uuid.isValid("not-a-uuid") === false);
  check("isValid(uppercase) accepted",         b.uuid.isValid(u4.toUpperCase()) === true);
  check("isValid(non-string) === false",       b.uuid.isValid(42) === false);

  // Hex-only check on bytes/groups
  var groups = u4.split("-");
  check("v4 group lengths 8/4/4/4/12",
        groups[0].length === 8 && groups[1].length === 4 && groups[2].length === 4 &&
        groups[3].length === 4 && groups[4].length === 12);
  check("v4 groups are all hex",
        groups.every(_isHex));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
