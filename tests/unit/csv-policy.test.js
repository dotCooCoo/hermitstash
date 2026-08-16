const { describe, it } = require("node:test");
const assert = require("node:assert");
const b = require("../../lib/vendor/blamejs");

const { buildCsv } = require("../../app/security/csv-policy");

// The migrated module delegates to b.guardCsv.serialize. These tests lock
// (1) byte-level output parity with the prior hand-rolled escaper for
// ordinary data, (2) the hardening that only fires on hostile cells, and
// (3) that an export never throws on a hostile field. Special characters
// are built with String.fromCharCode so the source stays pure ASCII.

const ch = String.fromCharCode;
const BIDI = ch(0x202e);       // RIGHT-TO-LEFT OVERRIDE (Trojan Source)
const BEL = ch(0x07);          // C0 control
const NUL = ch(0x00);          // NUL byte
const FW_EQ = ch(0xff1d);      // FULLWIDTH EQUALS SIGN (formula homoglyph)

const one = (header, value) => buildCsv([header], [{ v: value }], (r) => [r.v]);

// A quoted CSV cell. Since blamejs 0.18.28 a row containing a disarmed formula
// is emitted fully quoted, with the apostrophe INSIDE the quotes — a leading
// apostrophe outside them is not part of the value a strict reader parses, so
// it does not reliably mark the cell as literal text. Rows needing no prefix
// are unquoted exactly as before. Written through this helper because spelling
// the expected bytes inline needs three levels of quoting and stops being
// readable as "this is what the file contains".
const q = (s) => '"' + s + '"';
const qRow = (...cells) => cells.map(q).join(",") + "\n";

describe("csv-policy — buildCsv output format (parity with the prior escaper)", function () {
  it("emits header + rows terminated by LF", function () {
    assert.strictEqual(
      buildCsv(["a", "b"], [{ x: 1, y: 2 }, { x: 3, y: 4 }], (r) => [r.x, r.y]),
      "a,b\n1,2\n3,4\n"
    );
  });

  it("prefixes a leading formula trigger with an apostrophe (=, +, -, @)", function () {
    assert.strictEqual(one("c", "=SUM(A1)"), qRow("c") + qRow("'=SUM(A1)"));
    assert.strictEqual(one("c", "+1"), qRow("c") + qRow("'+1"));
    assert.strictEqual(one("c", "-5"), qRow("c") + qRow("'-5"));
    assert.strictEqual(one("c", "@handle"), qRow("c") + qRow("'@handle"));
  });

  it("quotes cells containing a comma / quote / newline (doubling inner quotes)", function () {
    assert.strictEqual(one("c", "a,b"), 'c\n"a,b"\n');
    assert.strictEqual(one("c", 'he said "hi"'), 'c\n"he said ""hi"""\n');
    assert.strictEqual(one("c", "line1\nline2"), 'c\n"line1\nline2"\n');
  });

  it("preserves trailing whitespace (no trim)", function () {
    assert.strictEqual(one("c", "trail   "), "c\ntrail   \n");
  });

  it("renders empty string and null as empty cells", function () {
    assert.strictEqual(buildCsv(["a", "b"], [{}], () => ["", null]), "a,b\n,\n");
  });

  it("renders a numeric zero", function () {
    assert.strictEqual(one("c", 0), "c\n0\n");
  });

  it("returns a header-only line for a zero-row export", function () {
    assert.strictEqual(buildCsv(["id", "email"], [], () => []), "id,email\n");
  });
});

describe("csv-policy — hardening (only hostile cells are altered, always safer)", function () {
  it("strips a Unicode bidi override (CVE-2021-42574 Trojan Source)", function () {
    assert.strictEqual(one("c", "admin" + BIDI + "nimda"), "c\nadminnimda\n");
  });

  it("strips a C0 control character (BEL)", function () {
    assert.strictEqual(one("c", "a" + BEL + "b"), "c\nab\n");
  });

  it("strips a NUL byte", function () {
    assert.strictEqual(one("c", "a" + NUL + "b"), "c\nab\n");
  });

  it("apostrophe-prefixes a leading pipe", function () {
    assert.strictEqual(one("c", "|cmd"), qRow("c") + qRow("'|cmd"));
  });

  it("apostrophe-prefixes a leading full-width homoglyph (U+FF1D)", function () {
    assert.strictEqual(one("c", FW_EQ + "SUM(1)"), qRow("c") + qRow("'" + FW_EQ + "SUM(1)"));
  });

  it("never throws on a hostile field (control / bidi / NUL are stripped, not rejected)", function () {
    assert.doesNotThrow(function () {
      buildCsv(["c"], [{ v: "x" + BIDI + BEL + "y" }], (r) => [r.v]);
    });
  });
});

describe("csv-policy — never 500 on a large legitimate export (regression guards)", function () {
  it("does not throw past the default 1,048,576-row cap (admin export is uncapped)", function () {
    const rows = [];
    for (let i = 0; i < 1048577; i++) rows.push(i);
    assert.doesNotThrow(function () { buildCsv(["n"], rows, (r) => [r]); });
  });

  it("does not throw on a cell larger than 64 KiB", function () {
    assert.doesNotThrow(function () { one("c", "z".repeat(70000)); });
  });

  it("renders a number above MAX_SAFE_INTEGER as the prior String(value) form", function () {
    assert.strictEqual(one("c", 1e21), "c\n1e+21\n");
  });
});

describe("csv-policy — escaping edge cases", function () {
  it("apostrophe-prefixes AND quotes a formula cell that also contains a comma", function () {
    assert.strictEqual(one("c", "=cmd,x"), qRow("c") + qRow("'=cmd,x"));
  });

  it("apostrophe-prefixes a leading TAB formula trigger", function () {
    assert.strictEqual(one("c", ch(0x09) + "x"), qRow("c") + qRow("'" + ch(0x09) + "x"));
  });

  it("disarms the hostile cell in a mixed multi-row export, terminated by LF", function () {
    // One hostile cell now quotes the whole export rather than that cell alone.
    // The apostrophe still lands on the offending value only; what widened is
    // the quoting, which is what puts the prefix inside the field where a
    // reader treats it as literal text.
    assert.strictEqual(
      buildCsv(["a", "b"], [{ a: "ok", b: "=x" }, { a: "y", b: "z" }], (r) => [r.a, r.b]),
      qRow("a", "b") + qRow("ok", "'=x") + qRow("y", "z")
    );
  });
});

describe("csv-policy — b.guardCsv contract (the primitive buildCsv delegates to)", function () {
  it("escapeCell with prefix-quote prepends an apostrophe to a formula trigger", function () {
    assert.strictEqual(b.guardCsv.escapeCell("=x", { formulaInjectionPolicy: "prefix-quote" }), "'=x");
  });

  it("serialize emits a header row + LF-separated records", function () {
    const out = b.guardCsv.serialize([["alice", "ok"]], { headers: ["name", "note"], lineEnding: "\n" });
    assert.match(out, /^name,note\nalice,ok$/);
  });
});
