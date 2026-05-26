"use strict";
/**
 * Layer 0 — b.linkHeader (RFC 8288 Web Linking).
 * Oracle: the RFC 8288 §3.5 worked examples plus GitHub-style pagination
 * links, parsed to the documented shape and round-tripped through
 * serialize.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var lh = b.linkHeader;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testSurface() {
  check("b.linkHeader.parse is a function", typeof lh.parse === "function");
  check("b.linkHeader.serialize is a function", typeof lh.serialize === "function");
  check("b.linkHeader.LinkHeaderError is the typed error class", typeof b.linkHeader.LinkHeaderError === "function");
}

function testParse() {
  // RFC 8288 §3.5 example.
  var parsed = lh.parse('<http://example.com/TheBook/chapter2>; rel="previous"; title="previous chapter"');
  check("parse: single link uri", parsed.length === 1 && parsed[0].uri === "http://example.com/TheBook/chapter2");
  check("parse: rel relation", parsed[0].rel.join() === "previous");
  check("parse: quoted title param", parsed[0].params.title === "previous chapter");

  // GitHub-style pagination — multiple links, comma-separated.
  var page = lh.parse('<https://api.example/x?page=2>; rel="next", <https://api.example/x?page=9>; rel="last", <https://api.example/x?page=1>; rel="first"');
  check("parse: multiple links", page.length === 3 && page[0].rel[0] === "next" && page[1].rel[0] === "last" && page[2].rel[0] === "first");

  // A comma INSIDE a quoted parameter does not split the list.
  var quoted = lh.parse('<https://x/1>; rel="next"; title="a, b, c"');
  check("parse: comma inside quoted param does not split", quoted.length === 1 && quoted[0].params.title === "a, b, c");

  // Space-separated rel values.
  var multi = lh.parse('<https://x>; rel="start http://example.net/relation/other"');
  check("parse: space-separated rel", multi[0].rel.length === 2 && multi[0].rel[0] === "start");

  // Unquoted token param.
  var tok = lh.parse("<https://x>; rel=next; type=text/html");
  check("parse: unquoted token params", tok[0].rel[0] === "next" && tok[0].params.type === "text/html");

  // A comma INSIDE the <uri-reference> is part of the URI, not a separator.
  var commaUri = lh.parse('<https://example.com/a,b>; rel="next"');
  check("parse: comma inside <uri> does not split", commaUri.length === 1 && commaUri[0].uri === "https://example.com/a,b");
  var commaUri2 = lh.parse('<https://x/a,b>; rel="next", <https://x/c,d>; rel="prev"');
  check("parse: comma-bearing URIs across multiple links", commaUri2.length === 2 && commaUri2[0].uri === "https://x/a,b" && commaUri2[1].uri === "https://x/c,d");

  // RFC 8288 §3.3: a duplicate rel keeps the FIRST occurrence.
  var dupRel = lh.parse('<https://x>; rel="next"; rel="prev"');
  check("parse: duplicate rel keeps the first", dupRel[0].rel.join() === "next");
}

function testSerialize() {
  var s = lh.serialize([
    { uri: "https://api/x?page=2", rel: "next" },
    { uri: "https://api/x?page=9", rel: "last", params: { title: "end" } },
  ]);
  check("serialize: pagination links", s === '<https://api/x?page=2>; rel="next", <https://api/x?page=9>; rel="last"; title="end"');
  // Round-trip.
  var rt = lh.parse(s);
  check("serialize→parse round-trips uri/rel/params", rt.length === 2 && rt[0].uri === "https://api/x?page=2" && rt[1].params.title === "end");
  // rel array → space-joined.
  check("serialize: rel array", lh.serialize({ uri: "https://x", rel: ["start", "next"] }) === '<https://x>; rel="start next"');
  // Parameter values are quoted (always valid; required for non-tokens like text/html).
  check("serialize: param values quoted", lh.serialize({ uri: "https://x", rel: "next", params: { type: "text/html" } }) === '<https://x>; rel="next"; type="text/html"');
}

function testRefusals() {
  check("parse: missing <uri> refused", code(function () { lh.parse('rel="next"'); }) === "link-header/bad-link");
  check("parse: unterminated <uri> refused", code(function () { lh.parse('<https://x; rel="next"'); }) === "link-header/bad-link");
  check("parse: non-string refused", code(function () { lh.parse(42); }) === "link-header/bad-input");
  check("parse: control bytes refused", code(function () { lh.parse("<https://x>;\x01rel=next"); }) === "link-header/bad-input");
  check("serialize: missing uri refused", code(function () { lh.serialize([{ rel: "next" }]); }) === "link-header/bad-link");
  check("serialize: angle bracket in uri refused", code(function () { lh.serialize([{ uri: "https://x<y", rel: "next" }]); }) === "link-header/bad-link");
  // LinkHeaderError is the thrown type.
  var threw = null; try { lh.parse(42); } catch (e) { threw = e; }
  check("LinkHeaderError is the typed error", threw instanceof lh.LinkHeaderError);
}

async function run() {
  testSurface();
  testParse();
  testSerialize();
  testRefusals();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[link-header] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
