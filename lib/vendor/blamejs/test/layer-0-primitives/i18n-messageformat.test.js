"use strict";
/**
 * b.i18n.messageFormat — ICU MessageFormat parser + evaluator tests.
 *
 * Covers the supported subset (plural / select / selectordinal /
 * argument / hash / quote-escape) plus rejection paths for
 * unsupported types and structural errors.
 */
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var mf = b.i18n.messageFormat;

async function testSurface() {
  check("b.i18n.messageFormat exposed",
        typeof b.i18n.messageFormat === "object");
  check("b.i18n.messageFormat.format is fn",
        typeof b.i18n.messageFormat.format === "function");
  check("b.i18n.messageFormat.parse is fn",
        typeof b.i18n.messageFormat.parse === "function");
  check("b.i18n.messageFormat.looksLikeMessageFormat is fn",
        typeof b.i18n.messageFormat.looksLikeMessageFormat === "function");
}

async function testLiteral() {
  check("plain literal passes through unchanged",
        mf.format("Hello, world", {}) === "Hello, world");
  check("literal with no placeholders ignores vars",
        mf.format("Hello", { ignored: true }) === "Hello");
}

async function testSimpleArgument() {
  check("{name} interpolates",
        mf.format("Hello {name}", { name: "Alice" }) === "Hello Alice");
  check("missing arg renders empty (existing-test compat)",
        mf.format("Hello {name}", {}) === "Hello ");
  check("null arg renders empty",
        mf.format("Hello {name}", { name: null }) === "Hello ");
  check("number arg renders as string",
        mf.format("Count: {n}", { n: 42 }) === "Count: 42");
}

async function testPluralExact() {
  // =N exact-match cases override CLDR category lookup.
  var t = "{count, plural, =0 {no items} =1 {one item} =2 {two items} other {# items}}";
  check("plural =0 matches",  mf.format(t, { count: 0 }) === "no items");
  check("plural =1 matches",  mf.format(t, { count: 1 }) === "one item");
  check("plural =2 matches",  mf.format(t, { count: 2 }) === "two items");
  check("plural other (5)",   mf.format(t, { count: 5 }) === "5 items");
  check("plural other (100)", mf.format(t, { count: 100 }) === "100 items");
}

async function testPluralCldrCategories() {
  var t = "{n, plural, one {# day} other {# days}}";
  check("CLDR 'one' for n=1 (en)", mf.format(t, { n: 1 }, "en") === "1 day");
  check("CLDR 'other' for n=2 (en)", mf.format(t, { n: 2 }, "en") === "2 days");
  // Russian uses 'few' / 'many' categories.
  var ru = "{n, plural, one {# день} few {# дня} many {# дней} other {# дней}}";
  check("Russian 'one' for n=1",  mf.format(ru, { n: 1 }, "ru") === "1 день");
  check("Russian 'few' for n=2",  mf.format(ru, { n: 2 }, "ru") === "2 дня");
  check("Russian 'many' for n=5", mf.format(ru, { n: 5 }, "ru") === "5 дней");
}

async function testPluralOffset() {
  // ICU spec: =N matches against the original value; CLDR category
  // lookup uses (n - offset); # renders as (n - offset).
  var t = "{n, plural, offset:1 =0 {only you} =1 {you and one other} other {you and # others}}";
  check("offset: =1 matches n=1 (literal-match against original)",
        mf.format(t, { n: 1 }) === "you and one other");
  check("offset: # renders as n-offset for n=4",
        mf.format(t, { n: 4 }) === "you and 3 others");
  check("offset: # renders as n-offset for n=2",
        mf.format(t, { n: 2 }) === "you and 1 others");
}

async function testSelect() {
  var t = "{gender, select, female {She} male {He} other {They}} did it.";
  check("select female",  mf.format(t, { gender: "female" }) === "She did it.");
  check("select male",    mf.format(t, { gender: "male" }) === "He did it.");
  check("select other",   mf.format(t, { gender: "neutral" }) === "They did it.");
  check("select missing var → other",
        mf.format(t, {}) === "They did it.");
}

async function testSelectOrdinal() {
  // English ordinals: 1st, 2nd, 3rd, 4th-..., 21st, 22nd, 23rd, ...
  var t = "{place, selectordinal, one {#st} two {#nd} few {#rd} other {#th}} place";
  check("ordinal 1st",  mf.format(t, { place: 1 }, "en") === "1st place");
  check("ordinal 2nd",  mf.format(t, { place: 2 }, "en") === "2nd place");
  check("ordinal 3rd",  mf.format(t, { place: 3 }, "en") === "3rd place");
  check("ordinal 4th",  mf.format(t, { place: 4 }, "en") === "4th place");
  check("ordinal 21st", mf.format(t, { place: 21 }, "en") === "21st place");
}

async function testNested() {
  var t = "{n, plural, =0 {no friends} other {{gender, select, female {she} male {he} other {they}} has # friends}}";
  check("nested: 0 friends",
        mf.format(t, { n: 0, gender: "female" }) === "no friends");
  check("nested: female + 5",
        mf.format(t, { n: 5, gender: "female" }) === "she has 5 friends");
  check("nested: male + 1",
        mf.format(t, { n: 1, gender: "male" }) === "he has 1 friends");
  check("nested: other gender",
        mf.format(t, { n: 3, gender: "x" }) === "they has 3 friends");
}

async function testQuoteEscape() {
  // ''   → literal '
  check("'' → literal apostrophe",
        mf.format("Don''t", {}) === "Don't");
  // '{...'  → literal {...
  check("'{name}' → literal {name}",
        mf.format("Use '{name}' as a literal", { name: "X" }) === "Use {name} as a literal");
  // '#'  → literal # (only meaningful inside a plural body — outside
  //         it's just a literal apostrophe-#-apostrophe)
  check("plural body: '#' → literal #",
        mf.format("{n, plural, other {has '#' inside}}", { n: 1 }) === "has # inside");
}

async function testParseRejections() {
  function shouldThrow(label, template, codeRe) {
    var threw = null;
    try { mf.parse(template); } catch (e) { threw = e; }
    check("parse rejects: " + label,
          threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("non-string input", 123, /BAD_TEMPLATE/);
  shouldThrow("plural without other", "{n, plural, =1 {x}}", /BAD_TEMPLATE/);
  shouldThrow("select without other", "{g, select, m {x}}", /BAD_TEMPLATE/);
  shouldThrow("unsupported type", "{x, number, integer}", /BAD_TEMPLATE/);
  shouldThrow("missing argument name", "{,plural,other {x}}", /BAD_TEMPLATE/);
}

async function testFormatRejections() {
  // Plural with non-numeric arg.
  var threw = null;
  try { mf.format("{n, plural, other {ok}}", { n: "not a number" }); }
  catch (e) { threw = e; }
  check("plural with non-numeric arg throws BAD_VAR",
        threw && /BAD_VAR/.test(threw.code || ""));
}

async function testLooksLikeMessageFormat() {
  check("plural detected",
        mf.looksLikeMessageFormat("{n, plural, other {x}}") === true);
  check("select detected",
        mf.looksLikeMessageFormat("{g, select, other {x}}") === true);
  check("selectordinal detected",
        mf.looksLikeMessageFormat("{p, selectordinal, other {x}}") === true);
  check("simple {var} NOT detected (uses simple interpolator)",
        mf.looksLikeMessageFormat("Hello {name}") === false);
  check("plain text NOT detected",
        mf.looksLikeMessageFormat("no placeholders here") === false);
  check("non-string returns false",
        mf.looksLikeMessageFormat(null) === false);
}

async function testT_integration() {
  // End-to-end through b.i18n.t
  var i = b.i18n.create({
    locales: ["en"],
    defaultLocale: "en",
    translations: {
      en: {
        inbox: { summary: "You have {count, plural, =0 {no messages} =1 {# message} other {# messages}}." },
        liked: "{gender, select, female {She} male {He} other {They}} liked it.",
        simple: "Hello {name}",
      },
    },
  });
  check("t() routes plural-shape through MessageFormat",
        i.t("inbox.summary", { count: 0 }) === "You have no messages.");
  check("t() routes select through MessageFormat",
        i.t("liked", { gender: "male" }) === "He liked it.");
  check("t() leaves simple {var} on legacy interpolator (no MessageFormat detection)",
        i.t("simple", { name: "World" }) === "Hello World");
}

async function run() {
  await testSurface();
  await testLiteral();
  await testSimpleArgument();
  await testPluralExact();
  await testPluralCldrCategories();
  await testPluralOffset();
  await testSelect();
  await testSelectOrdinal();
  await testNested();
  await testQuoteEscape();
  await testParseRejections();
  await testFormatRejections();
  await testLooksLikeMessageFormat();
  await testT_integration();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[i18n-messageformat] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
