"use strict";
/**
 * b.csv — RFC 4180 parser + serializer with operator-friendly defaults.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  // ---- Surface ----
  check("b.csv namespace present",        typeof b.csv === "object");
  check("b.csv.parse is fn",              typeof b.csv.parse === "function");
  check("b.csv.stringify is fn",          typeof b.csv.stringify === "function");
  check("b.csv.CsvError is class",        typeof b.csv.CsvError === "function");
  check("b.parsers.csv removed",          typeof b.parsers.csv === "undefined");

  // ---- parse: header mode (returns array of objects) ----
  var p1 = b.csv.parse("a,b,c\n1,2,3\n4,5,6\n");
  check("parse: header mode → 2 rows",     p1.length === 2);
  check("parse: row 0 keyed by header",    p1[0].a === "1" && p1[0].b === "2" && p1[0].c === "3");
  check("parse: row 1 keyed by header",    p1[1].a === "4");

  // CRLF
  var p2 = b.csv.parse("a,b\r\n1,2\r\n3,4\r\n");
  check("parse: CRLF row terminators",     p2.length === 2 && p2[1].b === "4");

  // No trailing newline
  var p3 = b.csv.parse("a,b\n1,2");
  check("parse: no trailing newline ok",   p3.length === 1 && p3[0].a === "1");

  // BOM stripped
  var p4 = b.csv.parse("﻿a,b\n1,2\n");
  check("parse: leading BOM consumed",     p4[0].a === "1");

  // Buffer input + Uint8Array input
  var p4b = b.csv.parse(Buffer.from("a,b\n1,2"));
  check("parse: Buffer input accepted",    p4b[0].a === "1");
  var p4u = b.csv.parse(new Uint8Array(Buffer.from("a,b\n1,2")));
  check("parse: Uint8Array input accepted", p4u[0].a === "1");

  // Quoted fields with embedded comma + escaped quote + newline
  var quoted = "a,b\n\"hello, world\",\"he said \"\"hi\"\"\"\n\"line 1\nline 2\",x\n";
  var p5 = b.csv.parse(quoted);
  check("parse: quoted comma in field",     p5[0].a === "hello, world");
  check("parse: escaped quote (\"\" → \")", p5[0].b === 'he said "hi"');
  check("parse: embedded newline in quotes",p5[1].a === "line 1\nline 2");

  // No-header mode (returns array of arrays)
  var p6 = b.csv.parse("1,2,3\n4,5,6\n", { header: false });
  check("parse: no-header returns array of arrays",
        p6.length === 2 && p6[0][0] === "1" && p6[1][2] === "6");

  // trim: true
  var p6b = b.csv.parse("a,b\n  hi  , there\n", { trim: true });
  check("parse: trim option strips cell whitespace",
        p6b[0].a === "hi" && p6b[0].b === "there");

  // ---- parse: validation ----
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("parse-validate: " + label,  threw && codeRe.test(threw.code || ""));
  }
  rejects("number input",              function () { b.csv.parse(42); }, /csv\/bad-input/);
  rejects("multi-char delimiter",      function () { b.csv.parse("a,b\n1,2", { delimiter: ",," }); }, /csv\/bad-delimiter/);
  rejects("CR delimiter",              function () { b.csv.parse("a,b", { delimiter: "\r" }); }, /csv\/bad-delimiter/);
  rejects("delimiter same as quote",   function () { b.csv.parse("a,b", { delimiter: "\"" }); }, /csv\/bad-delimiter/);
  rejects("over maxBytes",             function () { b.csv.parse("a,b\n", { maxBytes: 1 }); }, /csv\/too-large/);
  rejects("over maxRows",              function () { b.csv.parse("a\n1\n2\n3\n4\n5\n", { header: false, maxRows: 3 }); }, /csv\/too-many-rows/);
  rejects("over maxFieldBytes",        function () { b.csv.parse("a\n" + "x".repeat(20), { header: false, maxFieldBytes: 5 }); }, /csv\/field-too-large/);
  rejects("unterminated quote",        function () { b.csv.parse("a,b\n\"unclosed,1\n2,3"); }, /csv\/unterminated-quote/);
  rejects("bad onBadRow value",        function () { b.csv.parse("a,b\n1,2,3", { onBadRow: "panic" }); }, /csv\/bad-opt/);

  // Row-length mismatch — throw vs skip
  var threwRowMismatch = null;
  try { b.csv.parse("a,b,c\n1,2\n"); } catch (e) { threwRowMismatch = e; }
  check("parse: row-length mismatch throws by default",
        threwRowMismatch && /csv\/row-length-mismatch/.test(threwRowMismatch.code));
  var skipped = b.csv.parse("a,b,c\n1,2\n4,5,6\n", { onBadRow: "skip" });
  check("parse: onBadRow=skip drops bad row",
        skipped.length === 1 && skipped[0].a === "4");

  // Custom delimiter (semicolon, tab)
  var p7 = b.csv.parse("a;b\n1;2\n", { delimiter: ";" });
  check("parse: semicolon delimiter",   p7[0].b === "2");
  var p7b = b.csv.parse("a\tb\n1\t2\n", { delimiter: "\t" });
  check("parse: TAB delimiter",         p7b[0].a === "1" && p7b[0].b === "2");

  // ---- stringify (basic) ----
  var s1 = b.csv.stringify([{ a: "1", b: "2" }, { a: "3", b: "4" }]);
  check("stringify: emits header + rows",
        s1.indexOf("a,b\r\n1,2\r\n3,4") === 0);

  // Cells needing quoting
  var s2 = b.csv.stringify([{ a: 'hello, "world"', b: "ok" }]);
  check("stringify: quotes commas + escapes inner quotes",
        s2.indexOf('"hello, ""world""",ok') !== -1);

  // No-header
  var s3 = b.csv.stringify([{ a: "1", b: "2" }], { header: false });
  check("stringify: header=false skips header row",
        s3.indexOf("a,b") === -1 && s3.indexOf("1,2") === 0);

  // Explicit columns ordering
  var s4 = b.csv.stringify([{ a: "1", b: "2", c: "3" }], { columns: ["c", "a"] });
  check("stringify: explicit columns ordering",
        s4.indexOf("c,a\r\n3,1") === 0);

  // Array-of-arrays input (no header by default in this shape)
  var s5 = b.csv.stringify([["x", "y"], ["1", "2"]], { header: false });
  check("stringify: array-of-arrays",
        s5.indexOf("x,y\r\n1,2") === 0);

  // null / undefined → empty cell
  var s6 = b.csv.stringify([{ a: null, b: undefined, c: "v" }]);
  check("stringify: null/undef → empty",
        /a,b,c\r\n,,v/.test(s6));

  // Custom EOL
  var s7 = b.csv.stringify([{ a: "1" }], { eol: "\n" });
  check("stringify: \\n EOL",            s7 === "a\n1");

  // alwaysQuote
  var s8 = b.csv.stringify([{ a: "1", b: "2" }], { alwaysQuote: true });
  check("stringify: alwaysQuote wraps every cell",
        s8.indexOf("\"a\",\"b\"\r\n\"1\",\"2\"") === 0);

  // ---- b.csv is for trusted-source-only emission ----
  // RFC 4180 quoting is the only escape work b.csv performs. Cells from
  // user-supplied input MUST go through b.guardCsv (which handles formula
  // triggers, dangerous-function denylist, bidi / homoglyph / control /
  // null / BOM / dialect threats). Confirm b.csv does not pretend to
  // defend against formula injection itself.
  var raw = b.csv.stringify([{ a: "=SUM(A1)" }]);
  check("stringify: leaves =formula cell untouched (no false-confidence prefix)",
        /^a\r\n=SUM\(A1\)/.test(raw));

  // ---- Round-trip ----
  var src = [
    { name: "Alice",     email: "a@example.com", note: 'said "hi"' },
    { name: "Bob, Jr.",  email: "b@example.com", note: "line1\nline2" },
  ];
  var written = b.csv.stringify(src);
  var read = b.csv.parse(written);
  check("round-trip: row count preserved",   read.length === 2);
  check("round-trip: comma in name preserved",
        read[1].name === "Bob, Jr.");
  check("round-trip: embedded quote preserved",
        read[0].note === 'said "hi"');
  check("round-trip: embedded newline preserved",
        read[1].note === "line1\nline2");

  // Round-trip preserves cell content byte-for-byte (b.csv does no
  // formula-injection mutation — that's b.guardCsv's responsibility).
  var fz = b.csv.stringify([{ a: "=A1" }]);
  var fzParsed = b.csv.parse(fz);
  check("round-trip: cell content unchanged",  fzParsed[0].a === "=A1");

  // ---- stringify validation ----
  function rejectsS(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("stringify-validate: " + label,  threw && codeRe.test(threw.code || ""));
  }
  rejectsS("non-array input",       function () { b.csv.stringify("nope"); }, /csv\/bad-input/);
  rejectsS("non-object row",        function () { b.csv.stringify([42]); }, /csv\/bad-input/);
  rejectsS("delim same as quote",   function () { b.csv.stringify([{ a: 1 }], { delimiter: "\"" }); }, /csv\/bad-delimiter/);
  rejectsS("bad eol",               function () { b.csv.stringify([{ a: 1 }], { eol: "X" }); }, /csv\/bad-opt/);
  check("stringify: empty array → empty string",   b.csv.stringify([]) === "");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
