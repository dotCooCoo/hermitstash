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
  check("unquoteSfString: empty returns empty",
        b.structuredFields.unquoteSfString("") === "");
  check("unquoteSfString: whitespace-only returns empty",
        b.structuredFields.unquoteSfString("   ") === "");
  check("unquoteSfString: non-string passes through",
        b.structuredFields.unquoteSfString(null) === null);
}

async function run() {
  testSplitTopLevelComma();
  testSplitTopLevelSemi();
  testRefuseControlBytes();
  testContainsControlBytes();
  testUnquoteSfString();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
