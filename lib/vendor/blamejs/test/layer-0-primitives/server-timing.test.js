"use strict";
/**
 * b.serverTiming — W3C Server-Timing response header builder.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("serverTiming.create is fn", typeof b.serverTiming.create === "function");
  check("serverTiming.entry is fn",  typeof b.serverTiming.entry === "function");
  check("ServerTimingError is a constructor",
        typeof b.serverTiming.ServerTimingError === "function");
}

function testCreateAndMark() {
  var t = b.serverTiming.create();
  t.mark("db.query", 12.5, "user fetch");
  t.mark("encrypt", 3.1);
  t.mark("cache.miss");
  var header = t.toHeader();
  check("toHeader: chains 3 entries",
        header.split(", ").length === 3);
  check("toHeader: first entry has dur+desc",
        header.indexOf('db.query; dur=12.5; desc="user fetch"') === 0);
  check("toHeader: integer dur formatted without decimals",
        header.indexOf("encrypt; dur=3.1") !== -1);
  check("toHeader: bare metric without dur",
        header.indexOf(", cache.miss") !== -1);
}

function testMarkRefusesBadShape() {
  var t = b.serverTiming.create();
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("mark: empty name",        function () { t.mark(""); }, "server-timing/bad-name");
  expectCode("mark: invalid name chars", function () { t.mark("bad name"); }, "server-timing/bad-name");
  expectCode("mark: negative duration", function () { t.mark("x", -1); }, "server-timing/bad-duration");
  expectCode("mark: NaN duration",      function () { t.mark("x", NaN); }, "server-timing/bad-duration");
}

async function testMeasureAsync() {
  var t = b.serverTiming.create();
  var result = await t.measure("db.lookup", async function () {
    return 42;
  });
  check("measure: returns fn result", result === 42);
  var snap = t.snapshot();
  check("measure: persists mark", snap.length === 1 && snap[0].name === "db.lookup");
  check("measure: dur recorded",   typeof snap[0].dur === "number" && snap[0].dur >= 0);
}

async function testMeasureThrows() {
  var t = b.serverTiming.create();
  var threw = null;
  try {
    await t.measure("bad", function () { throw new Error("boom"); });
  } catch (e) { threw = e; }
  check("measure: rethrows fn errors", threw && threw.message === "boom");
  var snap = t.snapshot();
  check("measure: still marked on throw (with desc=error)",
        snap.length === 1 && snap[0].desc === "error");
}

function testEntryShorthand() {
  check("entry: single shorthand",
        b.serverTiming.entry("db.query", 12.5, "user fetch")
        === 'db.query; dur=12.5; desc="user fetch"');
  check("entry: no desc",
        b.serverTiming.entry("x", 0) === "x; dur=0");
  check("entry: no dur",
        b.serverTiming.entry("x") === "x");
}

async function run() {
  testSurface();
  testCreateAndMark();
  testMarkRefusesBadShape();
  await testMeasureAsync();
  await testMeasureThrows();
  testEntryShorthand();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
