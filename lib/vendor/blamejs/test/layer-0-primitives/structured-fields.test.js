"use strict";
/**
 * b.structuredFields — RFC 8941 helpers (splitTopLevel /
 * refuseControlBytes / containsControlBytes / unquoteSfString).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSplitTopLevelComma() {
  check("splitTopLevel: simple comma list",
    JSON.stringify(b.structuredFields.splitTopLevel("a, b, c", ",")) ===
      JSON.stringify(["a", " b", " c"]));

  // Quoted comma is preserved within the piece.
  check("splitTopLevel: quoted comma preserved",
    JSON.stringify(b.structuredFields.splitTopLevel('private="A, B", max-age=60', ",")) ===
      JSON.stringify(['private="A, B"', ' max-age=60']));

  // Backslash-escape inside quoted-string.
  var withEscape = b.structuredFields.splitTopLevel('a="x\\",y", b', ",");
  check("splitTopLevel: backslash-escaped quote inside quoted string",
        withEscape.length === 2 && withEscape[1] === " b");

  // Empty input + non-string input.
  check("splitTopLevel: empty string → empty array",
    JSON.stringify(b.structuredFields.splitTopLevel("", ",")) === JSON.stringify([]));
  check("splitTopLevel: non-string → empty array",
    JSON.stringify(b.structuredFields.splitTopLevel(null, ",")) === JSON.stringify([]));

  // Unterminated quote drops the trailing piece silently.
  var unterminated = b.structuredFields.splitTopLevel('a, b="oops', ",");
  check("splitTopLevel: unterminated quote drops trailing piece",
        unterminated.length === 1 && unterminated[0] === "a");
}

function testSplitTopLevelSemi() {
  check("splitTopLevel: semicolon list",
    JSON.stringify(b.structuredFields.splitTopLevel("a;b;c", ";")) ===
      JSON.stringify(["a", "b", "c"]));
  check("splitTopLevel: quoted semicolon preserved",
    JSON.stringify(b.structuredFields.splitTopLevel('a=1;b="x;y";c=3', ";")) ===
      JSON.stringify(["a=1", 'b="x;y"', "c=3"]));

  // Invalid separator throws.
  var threw = null;
  try { b.structuredFields.splitTopLevel("a|b", "|"); } catch (e) { threw = e; }
  check("splitTopLevel: invalid separator throws TypeError",
        threw instanceof TypeError);
}

function testParseTagList() {
  var ptl = b.structuredFields.parseTagList;
  // Default: `;` sep, `=` kv, lower-cased keys, raw values.
  check("parseTagList: simple ;/= list, keys lower-cased",
    JSON.stringify(ptl("v=DKIM1; K=rsa; p=ABC")) ===
      JSON.stringify([["v", "DKIM1"], ["k", "rsa"], ["p", "ABC"]]));
  // Empty entries + entries without a kv separator are skipped.
  check("parseTagList: empty + no-kv entries skipped",
    JSON.stringify(ptl("a=1; ; novalue ;b=2")) ===
      JSON.stringify([["a", "1"], ["b", "2"]]));
  // Repeated keys are PRESERVED as pairs (no last-wins collapse) —
  // MTA-STS relies on this for repeated mx: lines.
  check("parseTagList: repeated keys preserved as pairs",
    JSON.stringify(ptl("mx=a; mx=b; mx=c")) ===
      JSON.stringify([["mx", "a"], ["mx", "b"], ["mx", "c"]]));
  // unfold collapses CRLF+WSP folds to a space before splitting (DKIM FWS).
  check("parseTagList: unfold collapses folded value",
    JSON.stringify(ptl("p=ABC\r\n DEF", { unfold: true, stripValueWs: true })) ===
      JSON.stringify([["p", "ABCDEF"]]));
  // stripValueWs removes all whitespace inside a value (DKIM/ARC FWS).
  check("parseTagList: stripValueWs removes internal whitespace",
    JSON.stringify(ptl("p=A B\tC", { stripValueWs: true })) ===
      JSON.stringify([["p", "ABC"]]));
  // Regex sep + colon kv (MTA-STS shape), value whitespace kept.
  check("parseTagList: regex sep + colon kv",
    JSON.stringify(ptl("version: STSv1\r\nmode: enforce\nmx: a", { sep: /\r?\n/, kvSep: ":" })) ===
      JSON.stringify([["version", "STSv1"], ["mode", "enforce"], ["mx", "a"]]));
  // lowerKey:false keeps original key case; first `=` wins (value may hold `=`).
  check("parseTagList: lowerKey:false preserves case, first kvSep wins",
    JSON.stringify(ptl("Key=a=b=c", { lowerKey: false })) ===
      JSON.stringify([["Key", "a=b=c"]]));
  // Non-string input is coerced (String()) — empty/garbage yields [].
  check("parseTagList: empty string → []",
    JSON.stringify(ptl("")) === JSON.stringify([]));
}

function testRefuseControlBytes() {
  var SfError = b.structuredFields.refuseControlBytes;
  // Generate a generic framework-error-shaped class for the test.
  function FakeErr(code, message) { this.code = code; this.message = message; }
  FakeErr.prototype = Object.create(Error.prototype);

  // Permitted: HT (folding ws), printable ASCII, high-bit chars.
  b.structuredFields.refuseControlBytes("\thello\tworld\t", {
    ErrorClass: FakeErr, code: "x/c", label: "test",
  });
  check("refuseControlBytes: ASCII HT permitted by default", true);

  // Refused: CR / LF / NUL / DEL.
  function expectThrow(label, value) {
    var threw = null;
    try {
      b.structuredFields.refuseControlBytes(value, {
        ErrorClass: FakeErr, code: "x/c", label: "test",
      });
    } catch (e) { threw = e; }
    check(label, threw && threw.code === "x/c");
  }
  expectThrow("refuseControlBytes: leading \\n refused",      "\nfoo");
  expectThrow("refuseControlBytes: trailing \\r refused",     "foo\r");
  expectThrow("refuseControlBytes: leading NUL refused",      "\x00foo");
  expectThrow("refuseControlBytes: trailing DEL refused",     "foo\x7F");
  expectThrow("refuseControlBytes: embedded NUL refused",     "a\x00b");

  // useNativeError: TypeError(message) instead of FrameworkError(code, message).
  var threwNative = null;
  try {
    b.structuredFields.refuseControlBytes("\nbad", {
      ErrorClass: TypeError, code: "x/c", label: "native",
      useNativeError: true,
    });
  } catch (e) { threwNative = e; }
  check("refuseControlBytes: useNativeError yields TypeError",
        threwNative instanceof TypeError &&
        /control characters/.test(threwNative.message));

  // allowHt: false refuses HT too.
  var threwHt = null;
  try {
    b.structuredFields.refuseControlBytes("\tfoo", {
      ErrorClass: FakeErr, code: "x/c", label: "no-ht",
      allowHt: false,
    });
  } catch (e) { threwHt = e; }
  check("refuseControlBytes: allowHt=false refuses HT", threwHt && threwHt.code === "x/c");

  // Non-string input → no-op.
  b.structuredFields.refuseControlBytes(null, {
    ErrorClass: FakeErr, code: "x/c", label: "null",
  });
  b.structuredFields.refuseControlBytes(undefined, {
    ErrorClass: FakeErr, code: "x/c", label: "undef",
  });
  check("refuseControlBytes: non-string is no-op", true);

  // Required opts.
  function expectOptThrow(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw instanceof TypeError);
  }
  expectOptThrow("refuseControlBytes: missing ErrorClass throws TypeError",
                 function () { b.structuredFields.refuseControlBytes("x", { code: "x/c", label: "l" }); });
  expectOptThrow("refuseControlBytes: missing code throws TypeError",
                 function () { b.structuredFields.refuseControlBytes("x", { ErrorClass: FakeErr, label: "l" }); });
  expectOptThrow("refuseControlBytes: missing label throws TypeError",
                 function () { b.structuredFields.refuseControlBytes("x", { ErrorClass: FakeErr, code: "x/c" }); });
  expectOptThrow("refuseControlBytes: missing opts throws TypeError",
                 function () { b.structuredFields.refuseControlBytes("x", null); });
  void SfError;
}

function testContainsControlBytes() {
  check("containsControlBytes: clean string → false",
        b.structuredFields.containsControlBytes("hello world") === false);
  check("containsControlBytes: HT allowed by default",
        b.structuredFields.containsControlBytes("\thello") === false);
  check("containsControlBytes: HT refused when allowHt:false",
        b.structuredFields.containsControlBytes("\thello", { allowHt: false }) === true);
  check("containsControlBytes: leading \\n → true",
        b.structuredFields.containsControlBytes("\nfoo") === true);
  check("containsControlBytes: trailing \\r → true",
        b.structuredFields.containsControlBytes("foo\r") === true);
  check("containsControlBytes: NUL → true",
        b.structuredFields.containsControlBytes("a\x00b") === true);
  check("containsControlBytes: DEL → true",
        b.structuredFields.containsControlBytes("foo\x7F") === true);
  check("containsControlBytes: non-string → false",
        b.structuredFields.containsControlBytes(null) === false);
}

function testUnquoteSfString() {
  check("unquoteSfString: plain quoted",
        b.structuredFields.unquoteSfString('"hello"') === "hello");
  check("unquoteSfString: escaped quote",
        b.structuredFields.unquoteSfString('"a\\"b"') === 'a"b');
  check("unquoteSfString: escaped backslash",
        b.structuredFields.unquoteSfString('"a\\\\b"') === "a\\b");
  check("unquoteSfString: bare token passes through",
        b.structuredFields.unquoteSfString("bare-token") === "bare-token");
  check("unquoteSfString: unterminated quote returns null",
        b.structuredFields.unquoteSfString('"oops') === null);
  // v0.15.12 (#77) — adjacent / repeated escapes the old two-pass .replace()
  // decode mangled. unquoteSfString routes through the single-pass
  // unescapeSfStringBody; the two-pass form returned a DOUBLED backslash for a
  // lone escaped backslash.
  check("unquoteSfString: lone escaped backslash decodes to a single backslash",
        b.structuredFields.unquoteSfString('"\\\\"') === "\\");
  check("unquoteSfString: escaped backslash adjacent to escaped quote",
        b.structuredFields.unquoteSfString('"\\\\\\""') === "\\\"");
  check("unescapeSfStringBody: lone escaped backslash -> single",
        b.structuredFields.unescapeSfStringBody("\\\\") === "\\");
  check("unescapeSfStringBody: two escaped backslashes -> two",
        b.structuredFields.unescapeSfStringBody("\\\\\\\\") === "\\\\");
  check("unescapeSfStringBody: non-string passthrough",
        b.structuredFields.unescapeSfStringBody(42) === 42);
  check("unquoteSfString: empty returns empty",
        b.structuredFields.unquoteSfString("") === "");
  check("unquoteSfString: whitespace-only returns empty",
        b.structuredFields.unquoteSfString("   ") === "");
  check("unquoteSfString: non-string passes through",
        b.structuredFields.unquoteSfString(null) === null);
}

function testForEachKeyValue() {
  // Bare entries (no kvSep → null value) are skipped; surviving values trimmed;
  // index reflects the kvps position (so the skipped bare entry leaves a gap).
  var kvps = b.structuredFields.parseKeyValuePieces("a = 1 ; b ; c=3".split(";"));
  var seen = [];
  b.structuredFields.forEachKeyValue(kvps, function (key, value, i) {
    seen.push([key, value, i]);
  });
  check("forEachKeyValue: skips bare (null-value) entries", seen.length === 2);
  check("forEachKeyValue: trims surviving values + passes key",
        seen[0][0] === "a" && seen[0][1] === "1" &&
        seen[1][0] === "c" && seen[1][1] === "3");
  check("forEachKeyValue: index reflects kvps position (bare skipped)",
        seen[0][2] === 0 && seen[1][2] === 2);

  // A handler `return` skips the current entry — `continue` semantics.
  var kept = [];
  b.structuredFields.forEachKeyValue(
    b.structuredFields.parseKeyValuePieces("x=1; y=2; z=3".split(";")),
    function (key) { if (key === "y") return; kept.push(key); });
  check("forEachKeyValue: handler return skips like continue", kept.join(",") === "x,z");

  // Non-function handler throws at the wiring (config-time tier).
  var threw = null;
  try { b.structuredFields.forEachKeyValue([], "nope"); } catch (e) { threw = e; }
  check("forEachKeyValue: non-function handler throws TypeError", threw instanceof TypeError);
}

function testUnfoldHeaderContinuations() {
  // RFC 5322 header unfolding: a CRLF (or bare LF) followed by WSP is
  // folding whitespace — unfold collapses each run to a single space so a
  // wrapped header value (DKIM/DMARC/Authentication-Results, etc.) parses
  // as one logical line.
  check("unfoldHeaderContinuations collapses CRLF+WSP to a single space",
    b.structuredFields.unfoldHeaderContinuations("v=DKIM1;\r\n  k=rsa") === "v=DKIM1; k=rsa");
  check("unfoldHeaderContinuations handles bare LF + tab",
    b.structuredFields.unfoldHeaderContinuations("a=1;\n\tb=2") === "a=1; b=2");
  check("unfoldHeaderContinuations leaves an unfolded value unchanged",
    b.structuredFields.unfoldHeaderContinuations("a=1; b=2") === "a=1; b=2");
}

async function run() {
  testSplitTopLevelComma();
  testSplitTopLevelSemi();
  testParseTagList();
  testForEachKeyValue();
  testRefuseControlBytes();
  testContainsControlBytes();
  testUnquoteSfString();
  testUnfoldHeaderContinuations();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
