"use strict";
/**
 * mime-parse — RFC 5322 / 2045 header-block + MIME structure parsing shared by
 * the mail stack (email, dsn, arf, auth, bounce). Covers the header-block
 * classifier (fields / malformed / folding / header-body boundary), the
 * parseHeaderBlock fields view, header/body bisection, Content-Type parsing,
 * case-insensitive header lookup, and multipart partitioning.
 *
 * classifyHeaderBlock.malformed is the header-injection signal (a header-section
 * line that is neither a `name: value` field nor a folding continuation) that
 * the silent-skip parsers used to drop; guard-email consumes it.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var mp      = require("../../lib/mime-parse");

function _eq(label, actual, expected) {
  check(label, JSON.stringify(actual) === JSON.stringify(expected));
}

function testClassifyHeaderBlockFields() {
  var r = mp.classifyHeaderBlock("A: 1\r\nB: 2\r\n boldfold\r\n\r\nbody");
  _eq("classify: fields parsed, folding collapsed to single SP",
    r.fields, [{ name: "A", value: "1" }, { name: "B", value: "2 boldfold" }]);
  check("classify: clean block has no malformed lines", r.malformed.length === 0);
}

function testClassifyHeaderBlockMalformed() {
  var r = mp.classifyHeaderBlock("garbage\r\nTo: x@y.com");
  _eq("classify: a colon-less header-section line is malformed (injection signal)",
    r.malformed, [{ lineIndex: 0, line: "garbage", reason: "no-colon" }]);
  _eq("classify: the valid field after it still parses",
    r.fields, [{ name: "To", value: "x@y.com" }]);
}

function testClassifyHeaderBlockBoundary() {
  // A non-field line AFTER the blank header/body boundary is BODY — not flagged.
  var r = mp.classifyHeaderBlock("A: 1\r\n\r\nnot-a-header-line");
  check("classify: boundary-aware — body lines are not malformed", r.malformed.length === 0);
  _eq("classify: only the header section is parsed into fields",
    r.fields, [{ name: "A", value: "1" }]);
}

function testClassifyHeaderBlockBadInput() {
  check("classify: null → empty structure", mp.classifyHeaderBlock(null).fields.length === 0);
  check("classify: undefined → empty structure", mp.classifyHeaderBlock(undefined).malformed.length === 0);
}

function testParseHeaderBlockIsFieldsView() {
  _eq("parseHeaderBlock returns the classifier's fields",
    mp.parseHeaderBlock("From: a\r\nTo: b"),
    [{ name: "From", value: "a" }, { name: "To", value: "b" }]);
  // Equivalence with classifyHeaderBlock.fields on the same input.
  var raw = "Subject: hi\r\n there\r\nFrom: a@b.com";
  _eq("parseHeaderBlock === classifyHeaderBlock(x).fields",
    mp.parseHeaderBlock(raw), mp.classifyHeaderBlock(raw).fields);
}

function testSplitHeadersAndBody() {
  var s = mp.splitHeadersAndBody("H: v\r\n\r\nthe body\r\nline2");
  _eq("split: header section parsed", s.headers, [{ name: "H", value: "v" }]);
  check("split: body preserved verbatim after the blank line", s.body === "the body\r\nline2");
  var none = mp.splitHeadersAndBody("H: v\r\nI: w");
  check("split: no blank line → empty body", none.body === "");
}

function testParseContentType() {
  var ct = mp.parseContentType("text/html; charset=utf-8; boundary=xyz");
  check("parseContentType: type lowercased", ct.type === "text/html");
  check("parseContentType: charset param", ct.params.charset === "utf-8");
  check("parseContentType: boundary param", ct.params.boundary === "xyz");
}

function testFindHeader() {
  var hs = [{ name: "From", value: "a" }, { name: "to", value: "b" }];
  check("findHeader: case-insensitive match", mp.findHeader(hs, "TO") === "b");
  check("findHeader: missing → null/undefined", !mp.findHeader(hs, "Subject"));
}

function testSplitMimeParts() {
  _eq("splitMimeParts: partitions on --boundary, drops preamble + close",
    mp.splitMimeParts("preamble\r\n--bnd\r\npart1\r\n--bnd\r\npart2\r\n--bnd--\r\n", "bnd"),
    ["part1", "part2"]);
  _eq("splitMimeParts: empty boundary → no parts",
    mp.splitMimeParts("anything", ""), []);
}

function run() {
  testClassifyHeaderBlockFields();
  testClassifyHeaderBlockMalformed();
  testClassifyHeaderBlockBoundary();
  testClassifyHeaderBlockBadInput();
  testParseHeaderBlockIsFieldsView();
  testSplitHeadersAndBody();
  testParseContentType();
  testFindHeader();
  testSplitMimeParts();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mime-parse] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
