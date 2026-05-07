"use strict";
/**
 * b.slug — URL-safe slug generation with diacritic strip + uniqueness.
 *
 * Run standalone: `node test/layer-0-primitives/slug.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- Surface ----

function testSlugSurface() {
  check("b.slug is a function",                 typeof b.slug === "function");
  check("b.slug.create is a function",          typeof b.slug.create === "function");
  check("b.slug.unique is async fn",            typeof b.slug.unique === "function");
  check("b.slug.RESERVED is a Set",             b.slug.RESERVED instanceof Set);
  check("b.slug.DEFAULTS is frozen",            Object.isFrozen(b.slug.DEFAULTS));
  check("b.slug.SlugError is a class",          typeof b.slug.SlugError === "function");
  check("DEFAULTS.separator default '-'",       b.slug.DEFAULTS.separator === "-");
  check("DEFAULTS.lowercase default true",      b.slug.DEFAULTS.lowercase === true);
  check("DEFAULTS.maxLength default 80",        b.slug.DEFAULTS.maxLength === 80);
  check("DEFAULTS.preserveUnicode default false", b.slug.DEFAULTS.preserveUnicode === false);
  check("DEFAULTS.fallback default ''",         b.slug.DEFAULTS.fallback === "");
}

function testReservedSet() {
  var r = b.slug.RESERVED;
  var expected = ["admin", "api", "auth", "login", "logout", "signup",
                  "settings", "account", "users", "me", "static", "assets",
                  "public", "favicon.ico", "robots.txt", "sitemap.xml",
                  "health", "metrics"];
  for (var i = 0; i < expected.length; i++) {
    check("RESERVED contains " + expected[i], r.has(expected[i]));
  }
  check("RESERVED is mutable for app extension",
        (function () {
          var ok = !r.has("__test_extra__");
          r.add("__test_extra__");
          var ok2 = r.has("__test_extra__");
          r.delete("__test_extra__");
          return ok && ok2;
        })());
}

// ---- Basic ASCII ----

function testBasicAscii() {
  check("simple title",        b.slug("Hello, World!") === "hello-world");
  check("punctuation runs",    b.slug("  Foo --- Bar  !!! ") === "foo-bar");
  check("slashes",             b.slug("a/b\\c") === "a-b-c");
  check("digits preserved",    b.slug("Top 10 Hits") === "top-10-hits");
  check("alpha only",          b.slug("abc") === "abc");
  check("ampersand becomes sep", b.slug("Cats & Dogs") === "cats-dogs");
}

function testLowercase() {
  check("default lowercases",  b.slug("Hello-World") === "hello-world");
  check("opts.lowercase=false preserves case",
        b.slug("Hello World", { lowercase: false }) === "Hello-World");
}

function testDiacritics() {
  check("café → cafe",            b.slug("café") === "cafe");
  check("naïve → naive",          b.slug("naïve") === "naive");
  check("Ñoño → nono",            b.slug("Ñoño") === "nono");
  check("über → uber",            b.slug("über") === "uber");
  check("résumé → resume",        b.slug("résumé") === "resume");
  check("Crème Brûlée → creme-brulee", b.slug("Crème Brûlée") === "creme-brulee");
}

function testSeparatorCollapse() {
  check("triple separator collapsed", b.slug("foo---bar") === "foo-bar");
  check("leading separators trimmed", b.slug("--foo") === "foo");
  check("trailing separators trimmed", b.slug("foo--") === "foo");
  check("both ends trimmed", b.slug("---foo---bar---") === "foo-bar");
}

function testCustomSeparator() {
  check("underscore separator",
        b.slug("hello world", { separator: "_" }) === "hello_world");
  check("dot separator",
        b.slug("hello world", { separator: "." }) === "hello.world");
  check("dot collapses with consecutive runs",
        b.slug("foo --- bar", { separator: "." }) === "foo.bar");
}

function testMaxLength() {
  // "the quick brown fox" → "the-quick-brown-fox" (19 chars)
  check("maxLength 12 truncates at separator",
        b.slug("the quick brown fox", { maxLength: 12 }) === "the-quick");
  check("maxLength null disables truncation",
        b.slug("the quick brown fox", { maxLength: null }) === "the-quick-brown-fox");
  check("maxLength fallback to char-trunc when no separator fits",
        b.slug("supercalifragilisticexpialidocious", { maxLength: 10 }) === "supercalif");
  check("maxLength larger than slug returns full slug",
        b.slug("hi", { maxLength: 100 }) === "hi");
}

function testEmptyAndPunctuationOnly() {
  check("empty string → empty",        b.slug("") === "");
  check("whitespace only → empty",     b.slug("   ") === "");
  check("punctuation only → empty",    b.slug("!!!") === "");
  check("fallback respected on empty",
        b.slug("", { fallback: "untitled" }) === "untitled");
  check("fallback on whitespace",
        b.slug("   ", { fallback: "untitled" }) === "untitled");
  check("fallback on punctuation",
        b.slug("!!!", { fallback: "untitled" }) === "untitled");
}

function testPreserveUnicode() {
  check("default ASCII drops Cyrillic",
        b.slug("Привет мир") === "");
  check("preserveUnicode keeps Cyrillic",
        b.slug("Привет мир", { preserveUnicode: true }) === "привет-мир");
  check("preserveUnicode keeps Greek",
        b.slug("Καλημέρα κόσμε", { preserveUnicode: true }) === "καλημέρα-κόσμε");
  check("preserveUnicode strips punctuation",
        b.slug("Привет, мир!", { preserveUnicode: true }) === "привет-мир");
  check("preserveUnicode keeps CJK letters",
        b.slug("你好 世界", { preserveUnicode: true }) === "你好-世界");
}

function testIdempotent() {
  var s = b.slug("Hello, World!");
  check("slug(slug(x)) === slug(x)", b.slug(s) === s);
  var u = b.slug("Привет мир", { preserveUnicode: true });
  check("preserveUnicode idempotent",
        b.slug(u, { preserveUnicode: true }) === u);
}

// ---- create() ----

function testCreate() {
  var s60 = b.slug.create({ maxLength: 60, separator: "_" });
  check("create returns a function",   typeof s60 === "function");
  check("create binds opts",           s60("Hello World") === "hello_world");
  check("create maxLength applied",
        s60("a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a")
          .length <= 60);
  check("per-call opt overrides creator",
        s60("Hello World", { separator: "-" }) === "hello-world");
  check("create with no opts uses defaults",
        b.slug.create()("Hello World") === "hello-world");
}

// ---- unique() ----

async function testUniqueBaseAvailable() {
  var s = await b.slug.unique("Hello World", function (cand) { return false; });
  check("unique: returns base when not used", s === "hello-world");
}

async function testUniqueWithCollision() {
  var taken = new Set(["hello-world", "hello-world-2"]);
  var s = await b.slug.unique("Hello World", function (cand) {
    return taken.has(cand);
  });
  check("unique: skips taken bases", s === "hello-world-3");
}

async function testUniqueAsyncIsUsed() {
  var taken = new Set(["foo", "foo-2"]);
  var s = await b.slug.unique("Foo", async function (cand) {
    return taken.has(cand);
  });
  check("unique: awaits async isUsed", s === "foo-3");
}

async function testUniqueRespectsStart() {
  var seen = [];
  var s = await b.slug.unique("Hello", function (cand) {
    seen.push(cand);
    return cand !== "hello-7";
  }, { start: 5 });
  check("unique: respects start at 5",
        s === "hello-7" && seen[0] === "hello" &&
        seen[1] === "hello-5" && seen[2] === "hello-6" && seen[3] === "hello-7");
}

async function testUniqueExhausts() {
  var threw = null;
  try {
    await b.slug.unique("Hello", function () { return true; },
      { maxAttempts: 5 });
  } catch (e) { threw = e; }
  check("unique: throws SlugError on exhaustion",
        threw && threw.code === "UNIQUE_EXHAUSTED");
  check("unique: error mentions base slug",
        threw && /hello/.test(threw.message));
}

async function testUniqueRespectsMaxLength() {
  var taken = new Set(["the-quick"]);
  var s = await b.slug.unique("the quick brown fox", function (cand) {
    return taken.has(cand);
  }, { maxLength: 12 });
  // Base "the-quick" (9 chars) + "-2" (2) = 11 ≤ 12 → fits as-is.
  check("unique: candidate fits maxLength",
        s === "the-quick-2" && s.length <= 12);
}

async function testUniqueTruncatesBaseWhenNeeded() {
  // Base of 10 chars, maxLength 11, suffix "-9999" (5 chars) → base must
  // shrink to 6 chars. Single-token so char-truncated.
  var taken = new Set();
  for (var i = 2; i <= 9999; i++) taken.add("supercal-" + i);
  taken.add("supercal");
  // Even simpler: base = "abcdefghij" (10), maxLength 11, suffix "-2" (2):
  // candidate "abcdefghij-2" (12) > 11 → truncate base to 9: "abcdefghi-2" (11).
  var s = await b.slug.unique("abcdefghij", function (cand) { return cand === "abcdefghij"; },
    { maxLength: 11 });
  check("unique: truncates base to fit suffix",
        s.length <= 11 && /-2$/.test(s));
}

async function testUniqueCustomSuffixSeparator() {
  var taken = new Set(["foo"]);
  var s = await b.slug.unique("foo", function (cand) { return taken.has(cand); },
    { suffixSeparator: "_" });
  check("unique: suffixSeparator applied", s === "foo_2");
}

// ---- Input validation (rejects bad opts at call site) ----

function testRejectsBadOpts() {
  function expectThrow(label, fn, codeOrRegex) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    if (codeOrRegex instanceof RegExp) {
      check(label, threw && codeOrRegex.test(threw.message));
    } else {
      check(label, threw && threw.code === codeOrRegex);
    }
  }
  expectThrow("rejects multi-char separator",
    function () { b.slug("hi", { separator: "--" }); }, "BAD_OPT");
  expectThrow("rejects empty separator",
    function () { b.slug("hi", { separator: "" }); }, "BAD_OPT");
  expectThrow("rejects non-string separator",
    function () { b.slug("hi", { separator: 1 }); }, "BAD_OPT");
  expectThrow("rejects non-bool lowercase",
    function () { b.slug("hi", { lowercase: "yes" }); }, "BAD_OPT");
  expectThrow("rejects NaN maxLength",
    function () { b.slug("hi", { maxLength: NaN }); }, "BAD_OPT");
  expectThrow("rejects negative maxLength",
    function () { b.slug("hi", { maxLength: -1 }); }, "BAD_OPT");
  expectThrow("rejects float maxLength",
    function () { b.slug("hi", { maxLength: 1.5 }); }, "BAD_OPT");
  expectThrow("rejects non-bool preserveUnicode",
    function () { b.slug("hi", { preserveUnicode: "yes" }); }, "BAD_OPT");
  expectThrow("rejects non-string fallback",
    function () { b.slug("hi", { fallback: 42 }); }, "BAD_OPT");
  expectThrow("rejects non-string title",
    function () { b.slug(undefined); }, "BAD_TITLE");
  expectThrow("rejects null title",
    function () { b.slug(null); }, "BAD_TITLE");
  expectThrow("rejects number title",
    function () { b.slug(42); }, "BAD_TITLE");

  // create() validation
  expectThrow("create rejects bad opts",
    function () { b.slug.create({ separator: "--" }); }, "BAD_OPT");
}

async function testUniqueRejectsBadOpts() {
  function makePromiseExpect(label, fn, code) {
    return fn().then(
      function () { check(label + " — should have thrown", false); },
      function (e) { check(label, e && e.code === code); }
    );
  }
  await makePromiseExpect("unique rejects non-fn isUsed",
    function () { return b.slug.unique("hi", "not a fn"); },
    "BAD_ISUSED");
  await makePromiseExpect("unique rejects 0 maxAttempts",
    function () { return b.slug.unique("hi", function () { return false; },
      { maxAttempts: 0 }); },
    "BAD_OPT");
  await makePromiseExpect("unique rejects negative start",
    function () { return b.slug.unique("hi", function () { return false; },
      { start: -1 }); },
    "BAD_OPT");
  await makePromiseExpect("unique rejects empty suffixSeparator",
    function () { return b.slug.unique("hi", function () { return false; },
      { suffixSeparator: "" }); },
    "BAD_OPT");
}

// ---- Run ----

async function run() {
  testSlugSurface();
  testReservedSet();

  testBasicAscii();
  testLowercase();
  testDiacritics();
  testSeparatorCollapse();
  testCustomSeparator();
  testMaxLength();
  testEmptyAndPunctuationOnly();
  testPreserveUnicode();
  testIdempotent();
  testCreate();

  await testUniqueBaseAvailable();
  await testUniqueWithCollision();
  await testUniqueAsyncIsUsed();
  await testUniqueRespectsStart();
  await testUniqueExhausts();
  await testUniqueRespectsMaxLength();
  await testUniqueTruncatesBaseWhenNeeded();
  await testUniqueCustomSuffixSeparator();

  testRejectsBadOpts();
  await testUniqueRejectsBadOpts();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
