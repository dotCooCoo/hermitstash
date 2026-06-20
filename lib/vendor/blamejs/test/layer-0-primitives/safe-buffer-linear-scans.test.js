"use strict";
/**
 * b.safeBuffer linear-scan helpers that replace O(n^2) regexes (ReDoS class).
 *
 * stripTrailingHspace and indexAfterOpenTag each replace a regex whose
 * backtracking is quadratic in V8 on adversarial input:
 *   - stripTrailingHspace: /[ \t]+$/        (greedy-then-$)
 *   - indexAfterOpenTag:   /<tag[^>]*>/     (greedy-bracket-then->)
 *
 * Each test asserts (1) byte-for-byte output parity with the regex it
 * replaces on every edge case, and (2) that a 400K-char adversarial input
 * — which drives the regex to multiple seconds — completes near-instantly.
 * The perf bound is deliberately loose (500ms) so it discriminates the
 * O(n) fix from the O(n^2) regression (~8s) without flaking on a contended
 * runner.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var TRAILING_HSPACE_RE = /[ \t]+$/;

function _elapsedMs(fn) {
  var s = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - s) / 1e6;
}

function run() {
  var sb = b.safeBuffer;

  // ---- stripTrailingHspace: byte-identical to /[ \t]+$/ replace ----
  var cases = [
    "hello   ", "a b\t\t", "hello \n", "hello \n   ", "", "   ", "\t\t\t",
    "no-trailing", "trailing tab\t", "mixed \t \t ", " leading kept",
    "internal  spaces  kept x", "unicode café  ", "line1\nline2  ",
  ];
  var allParity = true;
  for (var i = 0; i < cases.length; i++) {
    var got = sb.stripTrailingHspace(cases[i]);
    var want = cases[i].replace(TRAILING_HSPACE_RE, "");
    if (got !== want) { allParity = false; break; }
  }
  check("stripTrailingHspace: byte-identical to /[ \\t]+$/ on every edge case", allParity);
  check("stripTrailingHspace: trailing \\n preserved (JS $ without /m)",
    sb.stripTrailingHspace("hello \n") === "hello \n");
  check("stripTrailingHspace: non-string passthrough", sb.stripTrailingHspace(42) === 42);

  var bigWs = "content" + " ".repeat(400000);
  var msStrip = _elapsedMs(function () { sb.stripTrailingHspace(bigWs); });
  check("stripTrailingHspace: linear on 400K trailing spaces (< 500ms; regex was ~85s)", msStrip < 500);
  check("stripTrailingHspace: 400K-space result correct", sb.stripTrailingHspace(bigWs) === "content");

  // ---- indexAfterOpenTag: parity with /<body[^>]*>/i for real HTML ----
  // Direct fully-qualified call (also satisfies the public-primitive
  // coverage gate, which scans for the b.safeBuffer.* token form).
  check("b.safeBuffer.indexAfterOpenTag: bare <body> → past the '>'",
    b.safeBuffer.indexAfterOpenTag("<body>x", "body") === 6);

  function oldIdx(html, tag) {
    var m = html.match(new RegExp("<" + tag + "[^>]*>", "i"));
    return m ? m.index + m[0].length : -1;
  }
  var htmls = [
    "<!doctype html><html><head></head><body data-x=\"1\">CONTENT</body>",
    "<body>bare", "<BODY id=a>x", "<html><body class=x>hi", "no body here",
    "<body\nmultiline\nattrs>z",
  ];
  var idxParity = true;
  for (var j = 0; j < htmls.length; j++) {
    // For inputs without a degenerate <bodyfoo>, the helper agrees with the regex.
    if (sb.indexAfterOpenTag(htmls[j], "body") !== oldIdx(htmls[j], "body")) { idxParity = false; break; }
  }
  check("indexAfterOpenTag: agrees with /<body[^>]*>/i on real HTML", idxParity);
  check("indexAfterOpenTag: stricter than regex — <bodyfoo> is NOT a <body>",
    sb.indexAfterOpenTag("<bodyfoo>hi", "body") === -1);
  check("indexAfterOpenTag: absent tag → -1", sb.indexAfterOpenTag("<p>x</p>", "body") === -1);
  check("indexAfterOpenTag: unterminated <body → -1", sb.indexAfterOpenTag("<body no close", "body") === -1);
  check("indexAfterOpenTag: non-string → -1", sb.indexAfterOpenTag(42, "body") === -1);

  var bigBody = "<body".repeat(80000); // 400K chars, 80K starts, no closing >
  var msIdx = _elapsedMs(function () { sb.indexAfterOpenTag(bigBody, "body"); });
  check("indexAfterOpenTag: linear on 80K <body starts (< 500ms; regex was ~8.6s)", msIdx < 500);
  check("indexAfterOpenTag: degenerate input → -1 (no terminated tag)",
    sb.indexAfterOpenTag(bigBody, "body") === -1);

  // ---- makeByteCoercer: bind toBuffer to a module's error contract ----
  function FakeErr(code, message) { this.code = code; this.message = message; }
  var coerce = sb.makeByteCoercer({
    errorClass:    FakeErr,
    typeCode:      "fake/bad-bytes",
    messagePrefix: "fake: ",
    messageSuffix: " must be bytes",
    allowString:   false,
  });
  check("makeByteCoercer: passes a Buffer through",
    Buffer.isBuffer(coerce(Buffer.from([1, 2]), "field")) &&
    coerce(Buffer.from([1, 2]), "field").length === 2);
  check("makeByteCoercer: coerces a Uint8Array to Buffer",
    Buffer.isBuffer(coerce(new Uint8Array([3, 4]), "field")));
  var bcErr = null;
  try { coerce("nope", "myField"); } catch (e) { bcErr = e; }
  check("makeByteCoercer: type mismatch throws the bound class with interpolated message",
    bcErr instanceof FakeErr && bcErr.code === "fake/bad-bytes" &&
    bcErr.message === "fake: myField must be bytes");

  // encoding variant: an encoded string is accepted + decoded.
  var hexCoerce = sb.makeByteCoercer({
    errorClass: FakeErr, typeCode: "fake/hex",
    messagePrefix: "fake: ", messageSuffix: " must be hex", encoding: "hex",
  });
  check("makeByteCoercer: encoding accepts + decodes an encoded string",
    hexCoerce("0102", "h").length === 2 && hexCoerce("0102", "h")[0] === 1);

  // config-time validation.
  function bcRejects(label, fn) {
    var threw = null; try { fn(); } catch (e) { threw = e; }
    check("makeByteCoercer: rejects " + label, threw && threw.code === "buffer/bad-arg");
  }
  bcRejects("missing opts",      function () { sb.makeByteCoercer(); });
  bcRejects("non-fn errorClass", function () { sb.makeByteCoercer({ errorClass: 5, typeCode: "x" }); });
  bcRejects("empty typeCode",    function () { sb.makeByteCoercer({ errorClass: FakeErr, typeCode: "" }); });
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
