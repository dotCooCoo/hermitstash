// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.i18n — translation + locale negotiation primitive.
 *
 * Run standalone: `node test/layer-0-primitives/i18n.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b         = helpers.b;
var fs        = helpers.fs;
var os        = helpers.os;
var path      = helpers.path;
var check     = helpers.check;
var _mockReq  = helpers._mockReq;
var _mockRes  = helpers._mockRes;

// ---- Surface ----

function testSurface() {
  check("b.i18n namespace present",          typeof b.i18n === "object");
  check("b.i18n.create is a function",       typeof b.i18n.create === "function");
  check("b.i18n.I18nError class",            typeof b.i18n.I18nError === "function");
  check("b.i18n.DEFAULTS frozen",            Object.isFrozen(b.i18n.DEFAULTS));
  check("b.i18n.RTL_LANGUAGES frozen Set",   b.i18n.RTL_LANGUAGES instanceof Set);
  check("RTL_LANGUAGES contains ar",         b.i18n.RTL_LANGUAGES.has("ar"));
  check("RTL_LANGUAGES contains he",         b.i18n.RTL_LANGUAGES.has("he"));
  check("RTL_LANGUAGES contains fa",         b.i18n.RTL_LANGUAGES.has("fa"));
  check("PLURAL_CATEGORIES exposed",         Array.isArray(b.i18n.PLURAL_CATEGORIES));
  check("PLURAL_CATEGORIES has 'other'",     b.i18n.PLURAL_CATEGORIES.indexOf("other") !== -1);
  check("PLURAL_CATEGORIES has 'one'",       b.i18n.PLURAL_CATEGORIES.indexOf("one") !== -1);
  check("PLURAL_CATEGORIES has 'few'",       b.i18n.PLURAL_CATEGORIES.indexOf("few") !== -1);
  check("PLURAL_CATEGORIES has 'many'",      b.i18n.PLURAL_CATEGORIES.indexOf("many") !== -1);
  check("PLURAL_CATEGORIES has 'zero'",      b.i18n.PLURAL_CATEGORIES.indexOf("zero") !== -1);
  check("PLURAL_CATEGORIES has 'two'",       b.i18n.PLURAL_CATEGORIES.indexOf("two") !== -1);

  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
  });
  check("instance.t fn",                     typeof i.t === "function");
  check("instance.tn fn",                    typeof i.tn === "function");
  check("instance.has fn",                   typeof i.has === "function");
  check("instance.formatNumber fn",          typeof i.formatNumber === "function");
  check("instance.formatDate fn",            typeof i.formatDate === "function");
  check("instance.formatRelative fn",        typeof i.formatRelative === "function");
  check("instance.formatList fn",            typeof i.formatList === "function");
  check("instance.displayName fn",           typeof i.displayName === "function");
  check("instance.setLocale fn",             typeof i.setLocale === "function");
  check("instance.dir fn",                   typeof i.dir === "function");
  check("instance.locales fn",               typeof i.locales === "function");
  check("instance.translations fn",          typeof i.translations === "function");
  check("instance.middleware fn",            typeof i.middleware === "function");
  check("instance.locale getter reflects defaultLocale",
        i.locale === "en");
}

// ---- Input validation (rejects bad opts at create time) ----

function testValidation() {
  var threwNoOpts = false;
  try { b.i18n.create(); } catch (_e) { threwNoOpts = true; }
  check("create() with no opts throws",      threwNoOpts);

  var threwNoDefault = false;
  try { b.i18n.create({ locales: ["en"] }); } catch (_e) { threwNoDefault = true; }
  check("create() without defaultLocale throws", threwNoDefault);

  var threwNoLocales = false;
  try { b.i18n.create({ defaultLocale: "en" }); } catch (_e) { threwNoLocales = true; }
  check("create() without locales throws",    threwNoLocales);

  // `getCanonicalLocales` is permissive for tags like "english" (private-
  // use). To test rejection we use shapes it actually rejects: tags
  // with underscores or invalid characters.
  var threwBadTag = false;
  try { b.i18n.create({ defaultLocale: "not_a_tag", locales: ["not_a_tag"] }); }
  catch (_e) { threwBadTag = true; }
  check("create() with non-BCP47 tag throws", threwBadTag);

  var threwDefaultNotInLocales = false;
  try { b.i18n.create({ defaultLocale: "fr", locales: ["en", "es"] }); }
  catch (_e) { threwDefaultNotInLocales = true; }
  check("create() with defaultLocale not in locales throws",
        threwDefaultNotInLocales);

  var threwBoth = false;
  try {
    b.i18n.create({
      defaultLocale: "en", locales: ["en"],
      translations: { en: {} }, dir: "/x",
    });
  } catch (_e) { threwBoth = true; }
  check("create() with both translations + dir throws", threwBoth);

  var threwBadMissingKey = false;
  try {
    b.i18n.create({
      defaultLocale: "en", locales: ["en"], missingKey: "wat",
    });
  } catch (_e) { threwBadMissingKey = true; }
  check("create() with bad missingKey policy throws", threwBadMissingKey);

  var threwBadObs = false;
  try {
    b.i18n.create({
      defaultLocale: "en", locales: ["en"], observability: { /* no event */ },
    });
  } catch (_e) { threwBadObs = true; }
  check("create() with bad observability shape throws", threwBadObs);

  var threwBadInterp = false;
  try {
    b.i18n.create({
      defaultLocale: "en", locales: ["en"], interpolation: { start: "" },
    });
  } catch (_e) { threwBadInterp = true; }
  check("create() with empty interpolation.start throws", threwBadInterp);
}

// ---- Translation tree validation at load ----

function testTranslationTreeValidation() {
  // Plural shape missing 'other' must throw at load
  var threwMissingOther = false;
  try {
    b.i18n.create({
      defaultLocale: "en",
      locales:       ["en"],
      translations: {
        en: { items: { one: "{count} item" } },
      },
    });
  } catch (_e) { threwMissingOther = true; }
  check("plural shape missing 'other' throws at load",
        threwMissingOther);

  // Unknown plural category typo must throw
  var threwBadCategory = false;
  try {
    b.i18n.create({
      defaultLocale: "en",
      locales:       ["en"],
      translations: {
        en: { items: { other: "{count} items", ohter: "typo" } },
      },
    });
  } catch (_e) { threwBadCategory = true; }
  check("unknown plural category throws at load",
        threwBadCategory);
}

// ---- Basic t() + nested keys ----

function testBasicLookup() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations: {
      en: {
        greeting: "Hello, {name}!",
        nav: { home: "Home", about: "About" },
      },
    },
  });
  check("simple lookup",                      i.t("greeting", { name: "Bob" }) === "Hello, Bob!");
  check("nested key lookup",                  i.t("nav.home") === "Home");
  check("nested key lookup 2",                i.t("nav.about") === "About");
  check("has() resolved key",                 i.has("nav.home") === true);
  check("has() missing key",                  i.has("nav.missing") === false);
  check("has() namespace returns false (not a leaf)",
        i.has("nav") === false);
}

// ---- Missing key behavior ----

function testMissingKey() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { greet: "Hello" } },
  });
  check("missing key returns key (default policy)",
        i.t("does.not.exist") === "does.not.exist");
  check("missing key with default opt returns default",
        i.t("does.not.exist", null, { default: "fallback" }) === "fallback");

  var iThrow = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    missingKey:    "throw",
    translations:  { en: { greet: "Hello" } },
  });
  var threw = false;
  try { iThrow.t("does.not.exist"); } catch (_e) { threw = true; }
  check("missingKey: 'throw' throws on miss",  threw);

  var customCalls = [];
  var iCustom = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    missingKey:    function (key, locale) {
      customCalls.push({ key: key, locale: locale });
      return "[[" + key + "]]";
    },
    translations:  { en: { greet: "Hello" } },
  });
  check("missingKey fn called + return propagated",
        iCustom.t("zzz") === "[[zzz]]" &&
        customCalls.length === 1 &&
        customCalls[0].key === "zzz");
}

// ---- Locale fallback chain ----

function testLocaleFallbackChain() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es", "fr"],
    translations: {
      en: { greet: "Hello", only_en: "EN" },
      es: { greet: "Hola" },
      fr: { greet: "Bonjour" },
    },
  });
  // es has greet; missing key falls through to en (default)
  check("fallback to defaultLocale on miss",
        i.t("only_en", null, { locale: "es" }) === "EN");

  // Subtag stripping: pt-BR → pt → fallback
  var i2 = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "pt", "pt-BR"],
    translations: {
      en:        { greet: "Hello" },
      pt:        { greet: "Olá" },
      "pt-BR":   { greet: "Oi" },
    },
  });
  check("pt-BR resolves to its own translation",
        i2.t("greet", null, { locale: "pt-BR" }) === "Oi");

  // Non-existent pt-BR key strips to pt
  var i3 = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "pt", "pt-BR"],
    translations: {
      en:      { greet: "Hello", farewell: "Bye" },
      pt:      { greet: "Olá", farewell: "Adeus" },
      "pt-BR": { greet: "Oi" },
    },
  });
  check("pt-BR missing key falls back to pt",
        i3.t("farewell", null, { locale: "pt-BR" }) === "Adeus");

  // fallbackLocale: null disables cross-locale fallback
  var i4 = b.i18n.create({
    defaultLocale:  "en",
    fallbackLocale: null,
    locales:        ["en", "es"],
    translations: {
      en: { greet: "Hello", only_en: "EN" },
      es: { greet: "Hola" },
    },
  });
  // Without fallback chain, only_en is missing in es
  check("fallbackLocale: null disables cross-locale fallback",
        i4.t("only_en", null, { locale: "es" }) === "only_en");
}

// ---- Plural rules via Intl.PluralRules ----

function testPluralRulesEn() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations: {
      en: { items: { one: "{count} item", other: "{count} items" } },
    },
  });
  check("en count=1 → one branch",            i.tn("items", 1) === "1 item");
  check("en count=0 → other branch",          i.tn("items", 0) === "0 items");
  check("en count=5 → other branch",          i.tn("items", 5) === "5 items");
  check("en count=21 → other branch",         i.tn("items", 21) === "21 items");
}

function testPluralRulesJa() {
  // Japanese has only "other" in CLDR cardinal rules
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "ja"],
    translations: {
      en: { items: { one: "{count} item", other: "{count} items" } },
      ja: { items: { other: "{count}個" } },
    },
  });
  check("ja count=1 → other (no 'one' in CLDR)",
        i.tn("items", 1, null, { locale: "ja" }) === "1個");
  check("ja count=5 → other",
        i.tn("items", 5, null, { locale: "ja" }) === "5個");
}

function testPluralRulesRu() {
  // Russian has zero (none), one, few (2-4 except teens), many (5+ + teens), other (fractions)
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "ru"],
    translations: {
      en: { items: { one: "{count} item", other: "{count} items" } },
      ru: { items: {
        one:   "{count} элемент",
        few:   "{count} элемента",
        many:  "{count} элементов",
        other: "{count} элементов",
      } },
    },
  });
  check("ru count=1 → 'one' branch",
        i.tn("items", 1, null, { locale: "ru" }) === "1 элемент");
  check("ru count=2 → 'few' branch",
        i.tn("items", 2, null, { locale: "ru" }) === "2 элемента");
  check("ru count=5 → 'many' branch",
        i.tn("items", 5, null, { locale: "ru" }) === "5 элементов");
}

function testPluralRulesAr() {
  // Arabic has all CLDR categories: zero, one, two, few, many, other
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "ar"],
    translations: {
      en: { items: { one: "{count}", other: "{count}" } },
      ar: { items: {
        zero:  "صفر",
        one:   "واحد",
        two:   "اثنان",
        few:   "{count} (few)",
        many:  "{count} (many)",
        other: "{count} (other)",
      } },
    },
  });
  check("ar count=0 → zero branch",
        i.tn("items", 0, null, { locale: "ar" }) === "صفر");
  check("ar count=1 → one branch",
        i.tn("items", 1, null, { locale: "ar" }) === "واحد");
  check("ar count=2 → two branch",
        i.tn("items", 2, null, { locale: "ar" }) === "اثنان");
}

// ---- Interpolation ----

function testInterpolationBasic() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations: {
      en: {
        named:     "Hello, {name}!",
        multi:     "{a} and {b}",
        nullVar:   "value: {x}",
      },
    },
  });
  check("named interpolation",                i.t("named", { name: "Alice" }) === "Hello, Alice!");
  check("multiple interpolation",             i.t("multi", { a: "x", b: "y" }) === "x and y");
  check("missing var renders literal",        i.t("named") === "Hello, {name}!");
  check("null var renders empty",             i.t("nullVar", { x: null }) === "value: ");
  check("undefined var renders empty",        i.t("nullVar", { x: undefined }) === "value: {x}");   // var absent → literal
}

function testInterpolationStrict() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    interpolation: { strict: true },
    translations:  { en: { hello: "Hello, {name}!" } },
  });
  var threw = false;
  try { i.t("hello"); } catch (_e) { threw = true; }
  check("strict interpolation throws on missing var", threw);
}

function testInterpolationCustomDelimiters() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    interpolation: { start: "{{", end: "}}" },
    translations:  { en: { hello: "Hello, {{name}}!" } },
  });
  check("custom delimiters {{...}} interpolate",
        i.t("hello", { name: "Bob" }) === "Hello, Bob!");
}

function testInterpolationEscape() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    interpolation: {
      escape: function (s) {
        return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      },
    },
    translations:  { en: { greet: "Hi {name}" } },
  });
  check("custom escape function applied to interpolated values",
        i.t("greet", { name: "<Bob>" }) === "Hi &lt;Bob&gt;");
}

// ---- Formatters ----

function testFormatNumber() {
  var i = b.i18n.create({
    defaultLocale: "en-US",
    locales:       ["en-US", "de-DE", "fr-FR"],
  });
  check("formatNumber en-US default",
        i.formatNumber(1234.5) === "1,234.5");
  check("formatNumber de-DE",
        i.formatNumber(1234.5, undefined, { locale: "de-DE" }) === "1.234,5");
  check("formatNumber currency en-US",
        i.formatNumber(1234.5, { style: "currency", currency: "USD" }) === "$1,234.50");

  var threw = false;
  try { i.formatNumber("not-a-number"); } catch (_e) { threw = true; }
  check("formatNumber throws on non-number input", threw);
}

function testFormatDate() {
  var i = b.i18n.create({
    defaultLocale: "en-US",
    locales:       ["en-US", "ja-JP"],
  });
  // Use a known epoch ms (2024-01-15 UTC)
  var d = new Date(Date.UTC(2024, 0, 15));
  var enUS = i.formatDate(d, { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" });
  check("formatDate en-US contains January and 2024",
        /January/.test(enUS) && /2024/.test(enUS));

  var jaJP = i.formatDate(d, { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" }, { locale: "ja-JP" });
  check("formatDate ja-JP contains 2024年",
        /2024年/.test(jaJP));

  var threw = false;
  try { i.formatDate("not a valid date string at all"); } catch (_e) { threw = true; }
  check("formatDate throws on unparseable input", threw);
}

function testFormatRelative() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es"],
  });
  check("formatRelative en -5 minute",
        i.formatRelative(-5, "minute") === "5 minutes ago");
  check("formatRelative en +3 day",
        i.formatRelative(3, "day") === "in 3 days");
  check("formatRelative es -5 minute is in Spanish",
        i.formatRelative(-5, "minute", { locale: "es" }).indexOf("hace") !== -1);
}

function testFormatList() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
  });
  check("formatList en conjunction (default)",
        i.formatList(["A", "B", "C"]) === "A, B, and C");
  check("formatList en disjunction",
        i.formatList(["A", "B", "C"], { type: "disjunction" }) === "A, B, or C");
  check("formatList empty array → ''",
        i.formatList([]) === "");
}

function testDisplayName() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "fr"],
  });
  check("displayName fr language under en → French",
        i.displayName("fr", "language") === "French");
  check("displayName fr language under fr → français",
        i.displayName("fr", "language", { locale: "fr" }) === "français");
  check("displayName US region under en → United States",
        i.displayName("US", "region") === "United States");

  var threw = false;
  try { i.displayName("fr", "wrong"); } catch (_e) { threw = true; }
  check("displayName with bad type throws",  threw);
}

// ---- setLocale + locale getter ----

function testSetLocale() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es"],
    translations: {
      en: { greet: "Hello" },
      es: { greet: "Hola" },
    },
  });
  check("locale getter starts at default",   i.locale === "en");
  check("t() uses default locale",            i.t("greet") === "Hello");
  i.setLocale("es");
  check("setLocale changed instance default", i.locale === "es");
  check("t() now resolves under new default", i.t("greet") === "Hola");

  var threw = false;
  try { i.setLocale("not_a_tag"); } catch (_e) { threw = true; }
  check("setLocale rejects bad BCP 47 tag",   threw);
}

// ---- dir() ----

function testDir() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "ar", "he", "fa"],
  });
  check("dir() en → ltr",                     i.dir() === "ltr");
  check("dir({ locale: 'ar' }) → rtl",        i.dir({ locale: "ar" }) === "rtl");
  check("dir({ locale: 'he' }) → rtl",        i.dir({ locale: "he" }) === "rtl");
  check("dir({ locale: 'fa' }) → rtl",        i.dir({ locale: "fa" }) === "rtl");
  check("dir({ locale: 'ar-EG' }) → rtl (subtag-stripped)",
        i.dir({ locale: "ar-EG" }) === "rtl");
}

// ---- Loading from dir ----

function testLoadFromDir() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-i18n-"));
  try {
    fs.writeFileSync(
      path.join(tmpDir, "en.json"),
      JSON.stringify({ greet: "Hello", items: { one: "{count} item", other: "{count} items" } })
    );
    fs.writeFileSync(
      path.join(tmpDir, "es.json"),
      JSON.stringify({ greet: "Hola" })
    );
    var i = b.i18n.create({
      defaultLocale: "en",
      locales:       ["en", "es"],
      dir:           tmpDir,
    });
    check("loaded en/greet from dir",          i.t("greet") === "Hello");
    check("loaded es/greet from dir",          i.t("greet", null, { locale: "es" }) === "Hola");
    check("loaded en plural rules",            i.tn("items", 5) === "5 items");

    // Bad JSON file
    fs.writeFileSync(path.join(tmpDir, "fr.json"), "{ not: valid json");
    var threw = false;
    try {
      b.i18n.create({
        defaultLocale: "en",
        locales:       ["en", "fr"],
        dir:           tmpDir,
      });
    } catch (_e) { threw = true; }
    check("malformed JSON throws LOAD_FAILED", threw);

    // Missing locale file
    var threwMissing = false;
    try {
      b.i18n.create({
        defaultLocale: "en",
        locales:       ["en", "ja"],
        dir:           tmpDir,
      });
    } catch (_e) { threwMissing = true; }
    check("missing locale file throws LOAD_FAILED", threwMissing);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

// ---- Middleware ----

function testMiddlewareAcceptLanguageNegotiation() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es", "fr"],
    translations: {
      en: { greet: "Hello" },
      es: { greet: "Hola" },
      fr: { greet: "Bonjour" },
    },
  });
  var mw = i.middleware();

  function runMw(headers) {
    var req = _mockReq();
    req.headers = headers || {};
    var res = _mockRes();
    var nextCalled = false;
    mw(req, res, function () { nextCalled = true; });
    return { req: req, res: res, nextCalled: nextCalled };
  }

  // Direct match
  var r1 = runMw({ "accept-language": "es,en;q=0.5" });
  check("Accept-Language: es resolves to es",   r1.req.locale === "es");
  check("middleware called next()",             r1.nextCalled === true);
  check("req.t bound to resolved locale",
        r1.req.t("greet") === "Hola");

  // Subtag stripping: es-MX → es
  var r2 = runMw({ "accept-language": "es-MX,en;q=0.5" });
  check("Accept-Language: es-MX resolves via prefix to es",
        r2.req.locale === "es");

  // Q-value priority
  var r3 = runMw({ "accept-language": "fr;q=0.5,es;q=0.9" });
  check("higher-q wins (es over fr)",           r3.req.locale === "es");

  // q=0 excludes
  var r4 = runMw({ "accept-language": "es;q=0,fr" });
  check("q=0 excludes; resolves to fr",         r4.req.locale === "fr");

  // No header → defaultLocale
  var r5 = runMw({});
  check("missing header → defaultLocale",       r5.req.locale === "en");

  // Unknown locales → defaultLocale
  var r6 = runMw({ "accept-language": "xx,yy" });
  check("unknown locales → defaultLocale",      r6.req.locale === "en");

  // res.locals.* attached for renderer auto-merge
  check("res.locals.locale attached",           r1.res.locals.locale === "es");
  check("res.locals.t attached",                typeof r1.res.locals.t === "function");
  check("res.locals.dir attached",              typeof r1.res.locals.dir === "string");
  check("res.locals.tn attached",               typeof r1.res.locals.tn === "function");
}

function testMiddlewareExplicitOverride() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es"],
    translations: {
      en: { greet: "Hello" },
      es: { greet: "Hola" },
    },
  });
  var mw = i.middleware({ queryParam: "lang" });

  // ?lang=es trumps Accept-Language: en
  var req = _mockReq();
  req.headers = { "accept-language": "en" };
  req.query = { lang: "es" };
  var res = _mockRes();
  mw(req, res, function () {});
  check("query param ?lang=es overrides Accept-Language",
        req.locale === "es");

  // Cookie override (operator opt-in)
  var mw2 = i.middleware({ cookieName: "preferredLang" });
  var req2 = _mockReq();
  req2.headers = { "accept-language": "en" };
  req2.cookies = { preferredLang: "es" };
  var res2 = _mockRes();
  mw2(req2, res2, function () {});
  check("cookie name override resolves to es",  req2.locale === "es");
}

function testMiddlewareNeverCrashesOnBadHeader() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
  });
  var mw = i.middleware();
  var req = _mockReq();
  req.headers = { "accept-language": ";;;;" };
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("malformed Accept-Language doesn't crash; next() called",
        nextCalled === true);
  check("malformed Accept-Language → defaultLocale",
        req.locale === "en");
}

// ---- Observability ----

function testObservabilityEmission() {
  var cap = b.testing.captureMetricsTap();
  try {
    var i = b.i18n.create({
      defaultLocale: "en",
      locales:       ["en", "es"],
      translations: {
        en: { greet: "Hello", only_en: "EN" },
        es: { greet: "Hola" },
      },
    });
    i.t("does.not.exist");           // → i18n.missing
    i.t("only_en", null, { locale: "es" }); // → i18n.miss.fallback
    i.formatNumber(1234.5);           // → i18n.format.created (number)
    i.formatNumber(1234.5);           // cache hit, no new event
  } finally {
    cap.restore();
  }
  check("emits i18n.missing on missing key",
        cap.byName("i18n.missing").length > 0);
  check("emits i18n.miss.fallback on cross-locale resolution",
        cap.byName("i18n.miss.fallback").length > 0);
  check("emits i18n.format.created on first formatter alloc",
        cap.byName("i18n.format.created").length > 0);

  // Cache hit on second formatNumber call: only ONE format.created event
  check("formatter cached — only one i18n.format.created on repeat call",
        cap.byName("i18n.format.created").length === 1);
}

// ---- Operator-supplied observability shape ----

function testOperatorObservability() {
  var captured = [];
  var customObs = {
    event: function (name, value, labels) {
      captured.push({ name: name, labels: labels || {} });
    },
  };
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    observability: customObs,
    translations:  { en: { greet: "Hello" } },
  });
  i.t("does.not.exist");
  var names = captured.map(function (e) { return e.name; });
  check("operator-supplied observability receives events",
        names.indexOf("i18n.missing") !== -1);
}

// ---- Shared parseQualityList helper ----

function testParseQualityListShared() {
  check("requestHelpers.parseQualityList is exported",
        typeof b.requestHelpers.parseQualityList === "function");
  var parsed = b.requestHelpers.parseQualityList("br;q=1.0, gzip;q=0.5, *;q=0");
  check("parses Accept-Encoding shape",
        parsed.length === 3 &&
        parsed[0].value === "br" &&
        parsed[1].value === "gzip" &&
        parsed[2].q === 0);
  // Empty string returns []
  check("empty string → []",
        b.requestHelpers.parseQualityList("").length === 0);
  // q > 1 is malformed input (RFC mandates q ∈ [0, 1]); we clamp to 1
  // rather than reject, since the rest of the list still has useful
  // semantics. Negative q is not RFC-valid and the regex doesn't
  // capture leading minus — the q simply parses as the absolute value
  // (operator-side bug surfaces as an unexpected q rank, not a crash).
  var weird = b.requestHelpers.parseQualityList("a;q=2.0,b;q=0.5");
  check("q > 1 clamped to 1",
        weird.find(function (e) { return e.value === "a"; }).q === 1);
  check("q within range preserved",
        weird.find(function (e) { return e.value === "b"; }).q === 0.5);
}

// ---- run ----

async function run() {
  testSurface();
  testValidation();
  testTranslationTreeValidation();
  testBasicLookup();
  testMissingKey();
  testLocaleFallbackChain();
  testPluralRulesEn();
  testPluralRulesJa();
  testPluralRulesRu();
  testPluralRulesAr();
  testInterpolationBasic();
  testInterpolationStrict();
  testInterpolationCustomDelimiters();
  testInterpolationEscape();
  testFormatNumber();
  testFormatDate();
  testFormatRelative();
  testFormatList();
  testDisplayName();
  testSetLocale();
  testDir();
  testLoadFromDir();
  testMiddlewareAcceptLanguageNegotiation();
  testMiddlewareExplicitOverride();
  testMiddlewareNeverCrashesOnBadHeader();
  testObservabilityEmission();
  testOperatorObservability();
  testParseQualityListShared();

  // v0.4.14
  testOrdinalPlural();
  testToShortcut();
  testOnMissingKeyHook();
  testOnMissingKeyValidation();
  testLazyLoadEagerOnly();
  testLazyLoadFiresOnDemand();
  testLazyLoadValidatesOnLoad();
  testLazyLoadRejectsInlineTranslations();
  testEagerLocalesValidation();
  testLocaleChain();

  // Adversarial / defensive branch coverage + bug guards
  testDirCustomRtlCaseInsensitive();
  testNamespaceShadowFallsBack();
  testKeyValidation();
  testGetTranslationsFor();
  testSetLocaleNonConfigured();
  testFormatterCallSiteThrows();
  testMessageFormatViaT();
  testMessageFormatNamespaceSurface();
  testInterpolationSameDelimiter();
  testMiddlewareResolver();
  testLocaleChainFallbackValidation();

  // Deeper adversarial / defensive branch coverage
  testValidationDeepBranches();
  testResolveLocaleBadOverride();
  testTnNonFiniteCount();
  testPluralCategoryFallsToOther();
  testNegotiateReverseMatch();
  testMiddlewareEdgeCases();
  testLoadDirReadFailure();
  testDisplayNameCurrencyScript();
  testFormatDateNumberAndString();
  testInterpolationUnclosedDefault();

  // Bulk feature-path coverage
  testFallbackLocaleDistinctFromDefault();
  testEmptyAndDottedThroughLeaf();
  testPluralWithoutCount();
  testTnToWithExtraVars();
  testFormatNumberStyles();
  testFormatDateStyles();
  testFormatRelativeNumeric();
  testFormatListStyles();
  testDisplayNameLocaleOverride();
  testLocalesGetterCopy();
  testChainThroughUnpopulatedLocale();
  testNegotiationEdgeBranches();
  testLazyLoadDefaultEagerOnly();
  testObservabilitySinkThrowSwallowed();
  testMiddlewareBoundHelpers();
  testMiddlewareCatchNeverCrashes();
  testMiddlewareCustomHeaderName();
  testMessageFormatFeaturePathsViaT();
  testLocaleChainFalsyOpts();
}

// create() must reject every malformed sub-opt shape at boot (the
// config-time throw tier), not just the ones the happy-path tests touch.
function testValidationDeepBranches() {
  function throwsCreate(opts) {
    try { b.i18n.create(opts); return false; } catch (_e) { return true; }
  }
  var base = { defaultLocale: "en", locales: ["en"] };
  function withBase(extra) { return Object.assign({}, base, extra); }

  check("interpolation as a non-object throws",
        throwsCreate(withBase({ interpolation: 42 })));
  check("interpolation.end empty string throws",
        throwsCreate(withBase({ interpolation: { end: "" } })));
  check("interpolation.escape non-function throws",
        throwsCreate(withBase({ interpolation: { escape: 42 } })));
  check("interpolation.strict non-boolean throws",
        throwsCreate(withBase({ interpolation: { strict: "yes" } })));

  check("rtlLanguages non-array throws",
        throwsCreate(withBase({ rtlLanguages: "ar" })));
  check("rtlLanguages with an empty-string entry throws",
        throwsCreate(withBase({ rtlLanguages: ["ar", ""] })));
  check("rtlLanguages with a non-string entry throws",
        throwsCreate(withBase({ rtlLanguages: ["ar", 42] })));

  check("translations as an array throws",
        throwsCreate(withBase({ translations: [] })));
  check("translations as null throws",
        throwsCreate(withBase({ translations: null })));

  check("fallbackLocale with an invalid BCP 47 tag throws",
        throwsCreate({ defaultLocale: "en", locales: ["en", "es"], fallbackLocale: "not_a_tag" }));
  check("fallbackLocale not present in locales throws",
        throwsCreate({ defaultLocale: "en", locales: ["en", "es"], fallbackLocale: "fr" }));

  // Translation-tree leaf that is neither a string nor a nested object.
  check("translation leaf that is a number throws at load",
        throwsCreate(withBase({ translations: { en: { count: 5 } } })));
  check("translation leaf that is an array throws at load",
        throwsCreate(withBase({ translations: { en: { list: [1, 2] } } })));

  check("eagerLocales as a non-array throws",
        throwsCreate({ defaultLocale: "en", locales: ["en"], lazyLoad: true, dir: "/x", eagerLocales: "en" }));
}

// A caller-supplied locale override of the wrong type or a malformed tag
// throws BAD_LOCALE at the call site (not silently coerced) — the same
// _resolveLocale guard for every t / formatter / dir entry point.
function testResolveLocaleBadOverride() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { greet: "Hello" } },
  });
  function throwsAt(fn) { try { fn(); return false; } catch (_e) { return true; } }

  check("t() with a non-string locale override throws",
        throwsAt(function () { i.t("greet", null, { locale: 42 }); }));
  check("t() with a malformed locale override tag throws",
        throwsAt(function () { i.t("greet", null, { locale: "not_a_tag" }); }));
  check("formatNumber() with a malformed locale override throws",
        throwsAt(function () { i.formatNumber(5, undefined, { locale: "not_a_tag" }); }));
  check("dir() with a non-string locale override throws",
        throwsAt(function () { i.dir({ locale: 42 }); }));
  check("has() with a malformed locale override throws",
        throwsAt(function () { i.has("greet", { locale: "not_a_tag" }); }));

  // A null/undefined override resolves the current locale (no throw).
  check("t() with a null locale override uses the current locale",
        i.t("greet", null, { locale: null }) === "Hello");
}

function testTnNonFiniteCount() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { items: { one: "{count} item", other: "{count} items" } } },
  });
  function throwsAt(fn) { try { fn(); return false; } catch (_e) { return true; } }
  check("tn() rejects NaN count",       throwsAt(function () { i.tn("items", NaN); }));
  check("tn() rejects Infinity count",  throwsAt(function () { i.tn("items", Infinity); }));
  check("tn() rejects a non-number count",
        throwsAt(function () { i.tn("items", "5"); }));
}

// When Intl.PluralRules selects a CLDR category the translation entry does
// not declare, _selectPlural falls back to the mandatory `other` key rather
// than rendering undefined.
function testPluralCategoryFallsToOther() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "ru"],
    translations: {
      en: { items: { one: "{count} item", other: "{count} items" } },
      // Russian selects "few" for 2 and "many" for 5, but this entry only
      // declares one + other — both must fall through to `other`.
      ru: { items: { one: "{count} штука", other: "{count} (other)" } },
    },
  });
  check("ru count=2 (selects 'few', not declared) → falls to other",
        i.tn("items", 2, null, { locale: "ru" }) === "2 (other)");
  check("ru count=5 (selects 'many', not declared) → falls to other",
        i.tn("items", 5, null, { locale: "ru" }) === "5 (other)");
}

// Reverse negotiation: a broad requested tag ("pt") resolves to a more
// specific configured tag ("pt-BR") when no exact / prefix match exists.
function testNegotiateReverseMatch() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "pt-BR"],
    translations:  { en: { greet: "Hello" }, "pt-BR": { greet: "Oi" } },
  });
  var mw = i.middleware();
  var req = _mockReq();
  req.headers = { "accept-language": "pt" };
  mw(req, _mockRes(), function () {});
  check("broad requested 'pt' reverse-matches configured 'pt-BR'",
        req.locale === "pt-BR");
  check("req.t bound to the reverse-matched locale",
        req.t("greet") === "Oi");
}

function testMiddlewareEdgeCases() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es"],
    translations:  { en: { greet: "Hello" }, es: { greet: "Hola" } },
  });

  // res is null (next-only pipelines): must bind req.* and not crash.
  var mwNoRes = i.middleware();
  var reqNoRes = _mockReq();
  reqNoRes.headers = { "accept-language": "es" };
  var nextCalled = false;
  var crashed = false;
  try { mwNoRes(reqNoRes, null, function () { nextCalled = true; }); }
  catch (_e) { crashed = true; }
  check("middleware with res=null does not crash", crashed === false);
  check("middleware with res=null still binds req.locale + calls next",
        reqNoRes.locale === "es" && nextCalled === true);

  // cookieName configured but the request carries no cookies → falls through
  // to header negotiation without crashing.
  var mwCookie = i.middleware({ cookieName: "lang" });
  var reqCookie = _mockReq();
  reqCookie.headers = { "accept-language": "es" };
  // no reqCookie.cookies at all
  mwCookie(reqCookie, _mockRes(), function () {});
  check("cookieName set but no cookies present → header negotiation",
        reqCookie.locale === "es");

  // Explicit query value that is not a configured locale falls through.
  var mwQuery = i.middleware();
  var reqQuery = _mockReq();
  reqQuery.headers = { "accept-language": "es" };
  reqQuery.query = { lang: "zz-not-configured" };
  mwQuery(reqQuery, _mockRes(), function () {});
  check("query lang not in configured set → header negotiation",
        reqQuery.locale === "es");
}

// _loadFromDir surfaces a read failure (not just missing/parse) as a typed
// LOAD_FAILED — a path that exists but cannot be read as a file (a directory
// standing where <locale>.json is expected) exercises the read-error branch.
function testLoadDirReadFailure() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-i18n-readfail-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "en.json"), JSON.stringify({ greet: "Hello" }));
    // Create a DIRECTORY named de.json so existsSync() is true but reading
    // it as a file throws EISDIR.
    fs.mkdirSync(path.join(tmpDir, "de.json"));
    var threw = false;
    try {
      b.i18n.create({ defaultLocale: "en", locales: ["en", "de"], dir: tmpDir });
    } catch (_e) { threw = true; }
    check("unreadable locale file (directory) throws LOAD_FAILED", threw);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

function testDisplayNameCurrencyScript() {
  var i = b.i18n.create({ defaultLocale: "en", locales: ["en"] });
  var cur = i.displayName("USD", "currency");
  check("displayName currency type returns a non-empty string",
        typeof cur === "string" && cur.length > 0);
  var scr = i.displayName("Latn", "script");
  check("displayName script type returns a non-empty string",
        typeof scr === "string" && scr.length > 0);
}

// formatDate accepts a Date, a numeric epoch, or a parseable string — the
// two non-Date branches beyond the happy-path Date input.
function testFormatDateNumberAndString() {
  var i = b.i18n.create({ defaultLocale: "en-US", locales: ["en-US"] });
  var epoch = Date.UTC(2024, 0, 15);
  var fromNum = i.formatDate(epoch, { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" });
  check("formatDate from a numeric epoch renders 2024",
        /2024/.test(fromNum) && /January/.test(fromNum));
  var fromStr = i.formatDate("2024-01-15T00:00:00Z", { year: "numeric", timeZone: "UTC" });
  check("formatDate from a parseable string renders 2024",
        /2024/.test(fromStr));
}

// An unclosed default {var} delimiter is rendered literally (never crashes,
// never drops the tail of the template).
function testInterpolationUnclosedDefault() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { partial: "Hello {name" } },
  });
  check("unclosed {var} delimiter renders literally",
        i.t("partial", { name: "Bob" }) === "Hello {name");
}

function testLocaleChain() {
  function arrEq(a, e) { return JSON.stringify(a) === JSON.stringify(e); }
  check("localeChain: fr-CA → fr → en (fallback en)",
        arrEq(b.i18n.localeChain("fr-CA", { defaultLocale: "en", fallbackLocale: "en" }),
              ["fr-CA", "fr", "en"]));
  check("localeChain: strict (fallback null) does not jump to default",
        arrEq(b.i18n.localeChain("zh-Hant-TW", { defaultLocale: "en", fallbackLocale: null }),
              ["zh-Hant-TW", "zh-Hant", "zh"]));
  check("localeChain: omitted fallback defaults to defaultLocale",
        b.i18n.localeChain("de-DE", { defaultLocale: "en" }).indexOf("en") !== -1);
  check("localeChain: bad locale throws",
        (function () { try { b.i18n.localeChain("", { defaultLocale: "en" }); return false; }
                       catch (_e) { return true; } })());
  check("localeChain: configured-set membership enforced",
        (function () { try {
          b.i18n.localeChain("fr", { defaultLocale: "en", locales: ["fr", "de"] }); return false;
        } catch (_e) { return true; } })());
}

// ---- v0.4.14 ordinal + onMissingKey + lazyLoad ----

function testOrdinalPlural() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  {
      en: {
        rank: {
          one:   "{count}st",
          two:   "{count}nd",
          few:   "{count}rd",
          other: "{count}th",
        },
      },
    },
  });
  check("ordinal: 1 → '1st'",   i.t("rank", { count: 1 }, { ordinal: true }) === "1st");
  check("ordinal: 2 → '2nd'",   i.t("rank", { count: 2 }, { ordinal: true }) === "2nd");
  check("ordinal: 3 → '3rd'",   i.t("rank", { count: 3 }, { ordinal: true }) === "3rd");
  check("ordinal: 4 → '4th'",   i.t("rank", { count: 4 }, { ordinal: true }) === "4th");
  check("ordinal: 21 → '21st'", i.t("rank", { count: 21 }, { ordinal: true }) === "21st");
  check("ordinal: 22 → '22nd'", i.t("rank", { count: 22 }, { ordinal: true }) === "22nd");
  // Without ordinal: en cardinal returns 'one' for 1, 'other' otherwise
  check("cardinal still works (non-ordinal)",  i.t("rank", { count: 1 }) === "1st");
  check("cardinal: 2 hits 'other'",            i.t("rank", { count: 2 }) === "2th");
}

function testToShortcut() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  {
      en: { place: { one: "{count}st place", two: "{count}nd", few: "{count}rd", other: "{count}th" } },
    },
  });
  check("to(): ordinal 1",  i.to("place", 1) === "1st place");
  check("to(): ordinal 4",  i.to("place", 4) === "4th");

  var threw = false;
  try { i.to("place", "not-a-number"); } catch (_e) { threw = true; }
  check("to(): rejects non-finite count",       threw);
}

function testOnMissingKeyHook() {
  var calls = [];
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { hi: "Hello" } },
    onMissingKey:  function (key, locale) { calls.push({ key: key, locale: locale }); },
  });
  i.t("known.key");                              // miss; hits the hook
  i.t("hi");                                     // hit; does not
  i.t("missing.again");                          // miss again
  check("onMissingKey: called for missing keys", calls.length === 2);
  check("onMissingKey: receives key + locale",
        calls[0].key === "known.key" && calls[0].locale === "en");

  // Hook throwing must not break the request
  var i2 = b.i18n.create({
    defaultLocale: "en", locales: ["en"], translations: { en: {} },
    onMissingKey: function () { throw new Error("hook bug"); },
  });
  var v = i2.t("missing");
  check("onMissingKey: hook throw doesn't break t()", v === "missing");
}

function testOnMissingKeyValidation() {
  var threw = false;
  try {
    b.i18n.create({
      defaultLocale: "en", locales: ["en"], translations: {},
      onMissingKey: 42,
    });
  } catch (_e) { threw = true; }
  check("onMissingKey: rejects non-function",    threw);
}

function testLazyLoadEagerOnly() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-i18n-lazy-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "en.json"), JSON.stringify({ greet: "Hello" }));
    fs.writeFileSync(path.join(tmpDir, "es.json"), JSON.stringify({ greet: "Hola" }));
    fs.writeFileSync(path.join(tmpDir, "fr.json"), JSON.stringify({ greet: "Bonjour" }));

    var i = b.i18n.create({
      defaultLocale: "en",
      locales:       ["en", "es", "fr"],
      eagerLocales:  ["en"],
      lazyLoad:      true,
      dir:           tmpDir,
    });
    // English (eager): immediately available without a file read after create
    check("lazyLoad: eager locale resolved", i.t("greet", null, { locale: "en" }) === "Hello");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

function testLazyLoadFiresOnDemand() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-i18n-lazy-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "en.json"), JSON.stringify({ greet: "Hello" }));
    fs.writeFileSync(path.join(tmpDir, "es.json"), JSON.stringify({ greet: "Hola" }));

    var lazyEvents = [];
    var i = b.i18n.create({
      defaultLocale: "en",
      locales:       ["en", "es"],
      eagerLocales:  ["en"],
      lazyLoad:      true,
      dir:           tmpDir,
      observability: { event: function (name, _v, l) { if (name === "i18n.lazyLoad") lazyEvents.push(l); } },
    });
    var hello = i.t("greet", null, { locale: "es" });
    check("lazyLoad: lazy locale resolved on demand", hello === "Hola");
    check("lazyLoad: lazyLoad observability emitted",
          lazyEvents.length === 1 && lazyEvents[0].locale === "es");

    // Second call: no extra load — instance caches.
    i.t("greet", null, { locale: "es" });
    check("lazyLoad: second hit reuses cached locale", lazyEvents.length === 1);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

function testLazyLoadValidatesOnLoad() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-i18n-lazy-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "en.json"), JSON.stringify({ greet: "Hello" }));
    // Bad shape: plural-shape entry missing 'other' — load-time validation should throw.
    fs.writeFileSync(path.join(tmpDir, "es.json"),
                     JSON.stringify({ count: { one: "uno" } }));

    var i = b.i18n.create({
      defaultLocale: "en",
      locales:       ["en", "es"],
      eagerLocales:  ["en"],
      lazyLoad:      true,
      dir:           tmpDir,
    });
    var threw = false;
    try { i.t("count", { count: 1 }, { locale: "es" }); } catch (_e) { threw = true; }
    check("lazyLoad: bad-shape locale throws on load", threw);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

function testLazyLoadRejectsInlineTranslations() {
  var threw = false;
  try {
    b.i18n.create({
      defaultLocale: "en",
      locales:       ["en"],
      lazyLoad:      true,
      translations:  { en: { hi: "Hi" } },
    });
  } catch (_e) { threw = true; }
  check("lazyLoad: rejects inline translations",  threw);
}

function testEagerLocalesValidation() {
  var threw = false;
  try {
    b.i18n.create({
      defaultLocale: "en",
      locales:       ["en"],
      eagerLocales:  ["fr"],   // not in locales
      lazyLoad:      true,
      dir:           "/tmp",
    });
  } catch (_e) { threw = true; }
  check("eagerLocales: must be subset of locales", threw);
}

// ---- Adversarial / defensive branch coverage ----

// dir() folds the requested locale's primary subtag to lower case before
// the RTL-membership test. A custom rtlLanguages list must be folded the
// same way — otherwise an operator-supplied entry like "AR" or "CKB"
// silently never matches and an RTL language renders left-to-right.
function testDirCustomRtlCaseInsensitive() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    rtlLanguages:  ["AR", "ckb", "KU"],   // mixed / upper-case custom entries
  });
  check("dir(ar) rtl even when custom list entry is upper-case 'AR'",
        i.dir({ locale: "ar" }) === "rtl");
  check("dir(AR-EG) rtl (subtag-stripped + case-folded)",
        i.dir({ locale: "AR-EG" }) === "rtl");
  check("dir(ku) rtl even when custom list entry is upper-case 'KU'",
        i.dir({ locale: "ku" }) === "rtl");
  check("dir(ckb) rtl (lower-case custom entry)",
        i.dir({ locale: "ckb" }) === "rtl");
  check("dir(en) ltr (not in custom rtl list)",
        i.dir({ locale: "en" }) === "ltr");
}

// A key that resolves to a nested namespace object in the requested locale
// must NOT shadow a real leaf translation defined in a fallback locale —
// the lookup should skip the non-renderable namespace and keep walking the
// fallback chain instead of leaking the raw key into the UI.
function testNamespaceShadowFallsBack() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "fr"],
    translations: {
      en: { title: "English Title", greet: "Hello" },
      fr: { title: { sub: "Sous-titre" }, greet: "Bonjour" },
    },
  });
  check("namespace in requested locale falls through to fallback leaf",
        i.t("title", null, { locale: "fr" }) === "English Title");
  check("fr's own leaf still resolves normally",
        i.t("greet", null, { locale: "fr" }) === "Bonjour");
  check("has() reports true when a fallback locale supplies the leaf",
        i.has("title", { locale: "fr" }) === true);

  // Subtag-strip variant: pt-BR has a namespace, pt has the leaf.
  var i2 = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "pt", "pt-BR"],
    translations: {
      en:      { menu: "Menu" },
      pt:      { menu: "Menu PT" },
      "pt-BR": { menu: { file: "Arquivo" } },   // namespace shadows the leaf
    },
  });
  check("subtag-strip skips namespace shadow and resolves parent leaf",
        i2.t("menu", null, { locale: "pt-BR" }) === "Menu PT");

  // A namespace key with no leaf anywhere in the chain is still a miss.
  var i3 = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { nav: { home: "Home" } } },
  });
  check("namespace key with no leaf in chain is a miss (returns key)",
        i3.t("nav") === "nav");
  check("has() false for a pure namespace key",
        i3.has("nav") === false);
}

function testKeyValidation() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { greet: "Hello" } },
  });
  var threwNonString = false;
  try { i.t(123); } catch (_e) { threwNonString = true; }
  check("t() rejects non-string key", threwNonString);

  var threwEmpty = false;
  try { i.t(""); } catch (_e) { threwEmpty = true; }
  check("t() rejects empty-string key", threwEmpty);

  check("has() returns false for non-string key (no throw)",
        i.has(123) === false);
  check("has() returns false for empty key (no throw)",
        i.has("") === false);
}

function testGetTranslationsFor() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { greet: "Hello" } },
  });
  var threw = false;
  try { i.translations(123); } catch (_e) { threw = true; }
  check("translations() rejects non-string locale", threw);
  check("translations() returns null for an unloaded locale",
        i.translations("zz") === null);
  check("translations() returns the loaded tree for a known locale",
        i.translations("en") && i.translations("en").greet === "Hello");
}

// setLocale permits a valid-but-unconfigured tag (operators experiment);
// it emits i18n.miss.locale and still resolves through the fallback chain.
function testSetLocaleNonConfigured() {
  var events = [];
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    observability: { event: function (name, _v, l) { events.push({ name: name, labels: l || {} }); } },
    translations:  { en: { greet: "Hello" } },
  });
  i.setLocale("de");   // valid BCP 47, not in configured locales
  check("setLocale accepts a valid non-configured tag", i.locale === "de");
  check("setLocale emits i18n.miss.locale for a non-configured tag",
        events.some(function (e) { return e.name === "i18n.miss.locale" && e.labels.requested === "de"; }));
  check("t() under the non-configured locale falls through to defaultLocale",
        i.t("greet") === "Hello");
}

// The formatter helpers throw a typed I18nError on the inputs they screen
// (empty / non-array / bad enum) — the call-site-throw validation tier.
function testFormatterCallSiteThrows() {
  var i = b.i18n.create({ defaultLocale: "en", locales: ["en"] });

  var threwUnit = false;
  try { i.formatRelative(5, ""); } catch (_e) { threwUnit = true; }
  check("formatRelative rejects empty unit", threwUnit);

  var threwRelVal = false;
  try { i.formatRelative(Infinity, "day"); } catch (_e) { threwRelVal = true; }
  check("formatRelative rejects non-finite value", threwRelVal);

  var threwList = false;
  try { i.formatList("not-an-array"); } catch (_e) { threwList = true; }
  check("formatList rejects non-array", threwList);

  var threwCode = false;
  try { i.displayName("", "language"); } catch (_e) { threwCode = true; }
  check("displayName rejects empty code", threwCode);

  var threwDateNull = false;
  try { i.formatDate(null); } catch (_e) { threwDateNull = true; }
  check("formatDate rejects null value", threwDateNull);
}

// ICU MessageFormat is auto-detected by t() when the entry carries
// {arg, plural|select|selectordinal ...} syntax, or forced with
// { messageFormat: true }. Drive the real t() consumer path.
function testMessageFormatViaT() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations: {
      en: {
        role:  "{role, select, admin {Administrator} other {Member}}",
        inbox: "You have {n, plural, =0 {no messages} one {# message} other {# messages}}.",
        rank:  "{pos, selectordinal, one {#st} two {#nd} few {#rd} other {#th}} place",
      },
    },
  });
  check("t() auto-detects select and renders the matched case",
        i.t("role", { role: "admin" }) === "Administrator");
  check("t() select falls to 'other' for an unmatched case",
        i.t("role", { role: "editor" }) === "Member");
  check("t() plural exact =0 case",
        i.t("inbox", { n: 0 }) === "You have no messages.");
  check("t() plural 'one' with # placeholder",
        i.t("inbox", { n: 1 }) === "You have 1 message.");
  check("t() plural 'other' with # placeholder",
        i.t("inbox", { n: 5 }) === "You have 5 messages.");
  check("t() selectordinal renders ordinal category",
        i.t("rank", { pos: 3 }) === "3rd place");
  check("t() selectordinal teen-boundary (21 → 21st)",
        i.t("rank", { pos: 21 }) === "21st place");

  // Forcing messageFormat on a malformed template surfaces a typed error.
  var iBad = b.i18n.create({
    defaultLocale: "en", locales: ["en"],
    translations:  { en: { broken: "{x, plural, one {a}}" } },   // missing 'other'
  });
  var threw = false;
  try { iBad.t("broken", { x: 1 }, { messageFormat: true }); } catch (_e) { threw = true; }
  check("t() with messageFormat:true throws on a malformed template", threw);
}

function testMessageFormatNamespaceSurface() {
  var mf = b.i18n.messageFormat;
  check("messageFormat namespace exposes format", typeof mf.format === "function");
  check("messageFormat namespace exposes parse", typeof mf.parse === "function");
  check("messageFormat namespace exposes looksLikeMessageFormat",
        typeof mf.looksLikeMessageFormat === "function");
  check("looksLikeMessageFormat true for plural syntax",
        mf.looksLikeMessageFormat("{n, plural, other {x}}") === true);
  check("looksLikeMessageFormat false for plain interpolation",
        mf.looksLikeMessageFormat("Hello {name}") === false);
  check("mf.format select matched case",
        mf.format("{g, select, male {He} other {They}}", { g: "male" }) === "He");
  check("mf.format select unmatched → other",
        mf.format("{g, select, male {He} other {They}}", { g: "x" }) === "They");

  // Prototype-pollution: an operator/end-user select value that names an
  // Object.prototype member must fall through to the `other` case, not return
  // an inherited member (which renders garbage, or throws when rendered as a
  // non-array — a request DoS). Every case-map lookup is own-property only.
  var protoKeys = ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"];
  for (var pk = 0; pk < protoKeys.length; pk++) {
    var out;
    try { out = mf.format("{g, select, male {He} other {They}}", { g: protoKeys[pk] }); }
    catch (e3) { out = "THREW:" + (e3 && e3.message); }
    check("mf.format select proto-key '" + protoKeys[pk] + "' falls to other (no proto leak / DoS)",
          out === "They");
  }
  check("mf.format plural resolves its own `other` (no proto leak)",
        mf.format("{n, plural, other {N items}}", { n: 5 }) === "N items");

  // Malformed templates fail as typed errors, never a raw crash.
  var threwUnclosed = false;
  try { mf.parse("{x, plural, other {a"); } catch (e) {
    threwUnclosed = (e && e.name === "I18nMessageFormatError");
  }
  check("mf.parse throws typed I18nMessageFormatError on unclosed body",
        threwUnclosed);
  var threwDeep = false;
  try {
    var deep = "";
    for (var d = 0; d < 300; d++) deep += "{a,select,x{";
    deep += "Z";
    for (var d2 = 0; d2 < 300; d2++) deep += "}}";
    mf.parse(deep);
  } catch (e2) { threwDeep = (e2 && e2.name === "I18nMessageFormatError"); }
  check("mf.parse caps nesting depth with a typed error (no stack overflow)",
        threwDeep);
}

function testInterpolationSameDelimiter() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    interpolation: { start: "%", end: "%" },
    translations:  { en: { a: "%x% and %y%", stray: "50% done" } },
  });
  check("same-delimiter interpolation replaces both placeholders",
        i.t("a", { x: "1", y: "2" }) === "1 and 2");
  check("same-delimiter: a lone unmatched delimiter is left literal",
        i.t("stray") === "50% done");
}

function testMiddlewareResolver() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es"],
    translations:  { en: { greet: "Hello" }, es: { greet: "Hola" } },
  });

  // Resolver wins over Accept-Language.
  var mw = i.middleware({ resolver: function (req) { return req.myLang; } });
  var req = _mockReq();
  req.headers = { "accept-language": "en" };
  req.myLang = "es";
  mw(req, _mockRes(), function () {});
  check("resolver return value wins over Accept-Language", req.locale === "es");

  // Resolver returning an invalid / non-configured tag falls through.
  var mw2 = i.middleware({ resolver: function () { return "zz-not-configured"; } });
  var req2 = _mockReq();
  req2.headers = { "accept-language": "es" };
  mw2(req2, _mockRes(), function () {});
  check("resolver invalid value falls through to header negotiation",
        req2.locale === "es");

  // Resolver throwing must not crash the request.
  var mw3 = i.middleware({ resolver: function () { throw new Error("resolver bug"); } });
  var req3 = _mockReq();
  req3.headers = { "accept-language": "es" };
  var nextCalled = false;
  mw3(req3, _mockRes(), function () { nextCalled = true; });
  check("resolver throw is swallowed; next() still called", nextCalled === true);
  check("resolver throw falls through to header negotiation", req3.locale === "es");
}

function testLocaleChainFallbackValidation() {
  var threwBadFallback = false;
  try { b.i18n.localeChain("fr", { defaultLocale: "en", fallbackLocale: "not_a_tag" }); }
  catch (_e) { threwBadFallback = true; }
  check("localeChain rejects an invalid fallbackLocale tag", threwBadFallback);

  var threwFallbackNotConfigured = false;
  try {
    b.i18n.localeChain("fr", { defaultLocale: "en", locales: ["en", "fr"], fallbackLocale: "de" });
  } catch (_e) { threwFallbackNotConfigured = true; }
  check("localeChain enforces fallbackLocale membership in configured locales",
        threwFallbackNotConfigured);

  var threwBadDefault = false;
  try { b.i18n.localeChain("fr", { defaultLocale: "not_a_tag" }); }
  catch (_e) { threwBadDefault = true; }
  check("localeChain rejects an invalid defaultLocale tag", threwBadDefault);
}

// ---- Bulk feature-path coverage: formatters, negotiation, fallback,
// ICU message format, lazy load, middleware binding ----

// A fallbackLocale distinct from defaultLocale must appear in the resolved
// chain AFTER the requested locale and its parents, with defaultLocale as the
// final baseline — both cross-locale hops fire, de-duplicated.
function testFallbackLocaleDistinctFromDefault() {
  var i = b.i18n.create({
    defaultLocale:  "fr",
    fallbackLocale: "en",
    locales:        ["en", "fr", "es"],
    translations: {
      en: { only_en: "EN", shared: "EN shared" },
      fr: { greet: "Bonjour" },
    },
  });
  check("chain for es is [es, en (fallback), fr (default)]",
        JSON.stringify(i._localeChain("es")) === JSON.stringify(["es", "en", "fr"]));
  check("miss in es resolves via fallbackLocale en before default fr",
        i.t("only_en", null, { locale: "es" }) === "EN");
  check("requested locale then fallback then default, de-duplicated",
        i._localeChain("en").indexOf("fr") === i._localeChain("en").length - 1);
}

// An empty-string translation value renders as empty (the early-return path in
// the interpolator), and a dotted key that walks THROUGH a string leaf returns
// the key (never crashes descending into a non-object).
function testEmptyAndDottedThroughLeaf() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { empty: "", greet: "Hello", ns: {} } },
  });
  check("empty-string translation renders as empty string",
        i.t("empty") === "");
  check("has() true for an empty-string leaf",
        i.has("empty") === true);
  check("dotted key walking through a string leaf returns the key",
        i.t("greet.deeper.leaf") === "greet.deeper.leaf");
  check("an empty-object entry loads (not a plural shape) and is a namespace miss",
        i.t("ns") === "ns");
}

// t() on a plural-shaped entry with no numeric count in vars defaults the count
// to 0 and selects the corresponding category (en: 0 → other).
function testPluralWithoutCount() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { items: { one: "{count} item", other: "{count} items" } } },
  });
  check("plural entry with no count in vars → count 0 → other",
        i.t("items") === "{count} items");
  check("plural entry with explicit count in vars renders one",
        i.t("items", { count: 1 }) === "1 item");
}

// tn / to called WITH a caller vars object merge count into a copy (rather than
// the count-only fast path), so extra interpolation vars survive.
function testTnToWithExtraVars() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  {
      en: {
        items: { one: "{name}: {count} item", other: "{name}: {count} items" },
        place: { one: "{who} {count}st", two: "{who} {count}nd", few: "{who} {count}rd", other: "{who} {count}th" },
      },
    },
  });
  check("tn() merges caller vars alongside count",
        i.tn("items", 3, { name: "Cart" }) === "Cart: 3 items");
  check("tn() singular with caller vars",
        i.tn("items", 1, { name: "Cart" }) === "Cart: 1 item");
  check("to() merges caller vars alongside ordinal count",
        i.to("place", 2, { who: "Runner" }) === "Runner 2nd");
}

// formatNumber across styles/locales — percent, currency, unit, notation — the
// bulk Intl.NumberFormat surface an operator drives.
function testFormatNumberStyles() {
  var i = b.i18n.create({
    defaultLocale: "en-US",
    locales:       ["en-US", "de-DE", "ja-JP"],
  });
  check("formatNumber percent",
        i.formatNumber(0.25, { style: "percent" }) === "25%");
  check("formatNumber currency EUR under de-DE",
        i.formatNumber(1234.5, { style: "currency", currency: "EUR" }, { locale: "de-DE" }).indexOf("€") !== -1);
  check("formatNumber currency JPY has no fraction digits",
        i.formatNumber(1234, { style: "currency", currency: "JPY" }, { locale: "ja-JP" }).indexOf("1,234") !== -1);
  check("formatNumber unit (kilometer)",
        typeof i.formatNumber(5, { style: "unit", unit: "kilometer" }) === "string" &&
        i.formatNumber(5, { style: "unit", unit: "kilometer" }).indexOf("5") !== -1);
  check("formatNumber compact notation",
        i.formatNumber(1200000, { notation: "compact" }).length > 0);
  check("formatNumber minimumFractionDigits pads",
        i.formatNumber(5, { minimumFractionDigits: 2 }) === "5.00");
  check("formatNumber -0 is finite and formats",
        i.formatNumber(-0) === "-0" || i.formatNumber(-0) === "0");
}

// formatDate across dateStyle/timeStyle presets and the no-formatOpts branch
// (falls to the locale default formatter).
function testFormatDateStyles() {
  var i = b.i18n.create({ defaultLocale: "en-US", locales: ["en-US", "ja-JP"] });
  var d = new Date(Date.UTC(2024, 0, 15, 13, 30, 0));
  check("formatDate with no formatOpts returns a non-empty string",
        typeof i.formatDate(d) === "string" && i.formatDate(d).length > 0);
  check("formatDate dateStyle:full contains 2024",
        /2024/.test(i.formatDate(d, { dateStyle: "full", timeZone: "UTC" })));
  check("formatDate timeStyle:short renders a time",
        /\d/.test(i.formatDate(d, { timeStyle: "short", timeZone: "UTC" })));
  check("formatDate ja-JP dateStyle:long contains 年",
        /年/.test(i.formatDate(d, { dateStyle: "long", timeZone: "UTC" }, { locale: "ja-JP" })));
}

// formatRelative with the `numeric` opt threads it into the formatter — "auto"
// yields word forms ("today" / "tomorrow"), "always" keeps the numeric form.
function testFormatRelativeNumeric() {
  var i = b.i18n.create({ defaultLocale: "en", locales: ["en"] });
  check("formatRelative numeric:auto 0 day → 'today'",
        i.formatRelative(0, "day", { numeric: "auto" }) === "today");
  check("formatRelative numeric:auto -1 day → 'yesterday'",
        i.formatRelative(-1, "day", { numeric: "auto" }) === "yesterday");
  check("formatRelative numeric:always 0 day keeps numeric form",
        i.formatRelative(0, "day", { numeric: "always" }) === "in 0 days");
  check("formatRelative default (no numeric) uses numeric form",
        i.formatRelative(0, "day") === "in 0 days");
}

// formatList across type + style — conjunction/disjunction/unit and short/narrow.
function testFormatListStyles() {
  var i = b.i18n.create({ defaultLocale: "en", locales: ["en"] });
  check("formatList unit type joins without 'and'",
        i.formatList(["5 min", "30 sec"], { type: "unit" }).indexOf("5 min") !== -1);
  check("formatList disjunction short style",
        typeof i.formatList(["A", "B"], { type: "disjunction", style: "short" }) === "string");
  check("formatList single item returns that item",
        i.formatList(["Only"]) === "Only");
  check("formatList two items conjunction",
        i.formatList(["A", "B"]) === "A and B");
}

// displayName currency/script honor a caller locale override.
function testDisplayNameLocaleOverride() {
  var i = b.i18n.create({ defaultLocale: "en", locales: ["en", "fr"] });
  check("displayName region under fr locale is localized",
        typeof i.displayName("US", "region", { locale: "fr" }) === "string");
  check("displayName currency under a locale override renders",
        i.displayName("EUR", "currency", { locale: "fr" }).length > 0);
  check("displayName script under a locale override renders",
        i.displayName("Latn", "script", { locale: "fr" }).length > 0);
}

// i.locales() returns a defensive copy of the configured set.
function testLocalesGetterCopy() {
  var i = b.i18n.create({ defaultLocale: "en", locales: ["en", "es", "fr"] });
  var l1 = i.locales();
  check("locales() returns the configured set",
        JSON.stringify(l1) === JSON.stringify(["en", "es", "fr"]));
  l1.push("zz");
  check("locales() returns a copy — mutating it does not affect the instance",
        i.locales().indexOf("zz") === -1);
}

// A non-lazy instance whose fallback chain includes a configured locale with no
// inline translations tree still resolves (the load-ensure no-ops, chain walks on).
function testChainThroughUnpopulatedLocale() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es", "fr"],
    translations:  { en: { greet: "Hello" } },   // es + fr have no tree
  });
  check("lookup under es (no tree) falls through to en",
        i.t("greet", null, { locale: "es" }) === "Hello");
  check("lookup under fr (no tree) falls through to en",
        i.t("greet", null, { locale: "fr" }) === "Hello");
  check("translations() returns null for a configured-but-unpopulated locale",
        i.translations("es") === null);
}

// Accept-Language negotiation edge branches: an all-q=0 list excludes every
// entry and falls to the default; a multi-level requested tag prefix-matches a
// broader configured tag by stripping subtags one at a time.
function testNegotiationEdgeBranches() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "zh", "pt"],
    translations:  { en: { g: "Hello" }, zh: { g: "你好" }, pt: { g: "Olá" } },
  });
  function loc(header) {
    var req = _mockReq();
    req.headers = { "accept-language": header };
    i.middleware()(req, _mockRes(), function () {});
    return req.locale;
  }
  check("all-q=0 Accept-Language excludes everything → defaultLocale",
        loc("zh;q=0,pt;q=0") === "en");
  check("multi-level tag zh-Hant-TW prefix-matches configured zh",
        loc("zh-Hant-TW") === "zh");
  check("single q=0 entry → defaultLocale",
        loc("pt;q=0") === "en");
}

// lazyLoad with no eagerLocales loads only the defaultLocale at create; other
// locales stream in on first lookup.
function testLazyLoadDefaultEagerOnly() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-i18n-lazydef-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "en.json"), JSON.stringify({ greet: "Hello" }));
    fs.writeFileSync(path.join(tmpDir, "es.json"), JSON.stringify({ greet: "Hola" }));
    var i = b.i18n.create({
      defaultLocale: "en",
      locales:       ["en", "es"],
      lazyLoad:      true,        // no eagerLocales → defaults to [defaultLocale]
      dir:           tmpDir,
    });
    check("lazyLoad w/o eagerLocales: default locale available immediately",
          i.t("greet") === "Hello");
    check("lazyLoad w/o eagerLocales: other locale streams in on demand",
          i.t("greet", null, { locale: "es" }) === "Hola");
    // A valid-but-unconfigured locale override on a lazy instance: the
    // load-ensure sees it is not in the configured set and no-ops, so the
    // lookup falls through the chain to the default locale (no file read,
    // no crash).
    check("lazy instance: unconfigured locale override falls through to default",
          i.t("greet", null, { locale: "de" }) === "Hello");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

// An observability sink that throws must never break a translation call — the
// emit is wrapped drop-silent.
function testObservabilitySinkThrowSwallowed() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    observability: { event: function () { throw new Error("sink boom"); } },
    translations:  { en: { greet: "Hello" } },
  });
  var v;
  var crashed = false;
  try { v = i.t("does.not.exist"); } catch (_e) { crashed = true; }
  check("throwing observability sink does not crash t()", crashed === false);
  check("t() still returns the key when the sink throws", v === "does.not.exist");
}

// The middleware binds req.t / req.tn / req.to / req.dir and mirrors them onto
// res.locals; the bound helpers default the locale to the negotiated one while
// still honoring an explicit override.
function testMiddlewareBoundHelpers() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es"],
    translations:  {
      en: { greet: "Hello", items: { one: "{count} item", other: "{count} items" },
            rank: { one: "{count}st", two: "{count}nd", few: "{count}rd", other: "{count}th" } },
      es: { greet: "Hola", items: { one: "{count} artículo", other: "{count} artículos" },
            rank: { one: "{count}º", two: "{count}º", few: "{count}º", other: "{count}º" } },
    },
  });
  var req = _mockReq();
  req.headers = { "accept-language": "es" };
  var res = _mockRes();
  i.middleware()(req, res, function () {});

  check("req.tn bound to the negotiated locale",
        req.tn("items", 5) === "5 artículos");
  check("req.to bound to the negotiated locale",
        req.to("rank", 1) === "1º");
  check("req.to honors an explicit locale override in callerOpts",
        req.to("rank", 1, null, { locale: "en" }) === "1st");
  check("req.t honors an explicit locale override over the negotiated one",
        req.t("greet", null, { locale: "en" }) === "Hello");
  check("req.tn honors an explicit locale override",
        req.tn("items", 1, null, { locale: "en" }) === "1 item");
  check("req.dir returns a direction for the negotiated locale",
        req.dir() === "ltr");
  check("res.locals.to bound",     typeof res.locals.to === "function");
  check("res.locals.tn bound",     typeof res.locals.tn === "function");
  check("res.locals.t via res.locals resolves the negotiated locale",
        res.locals.t("greet") === "Hola");
}

// The middleware never lets an i18n error escape onto the request path: if
// reading a request field throws, it swallows, sets req.locale to the current
// default, and still calls next().
function testMiddlewareCatchNeverCrashes() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations:  { en: { greet: "Hello" } },
  });
  var req = _mockReq();
  req.headers = {};
  // A query getter that throws forces the try/catch guard in the middleware.
  Object.defineProperty(req, "query", {
    get: function () { throw new Error("query access boom"); },
    configurable: true,
  });
  var res = _mockRes();
  var nextCalled = false;
  var crashed = false;
  try { i.middleware()(req, res, function () { nextCalled = true; }); }
  catch (_e) { crashed = true; }
  check("middleware swallows a throwing request field", crashed === false);
  check("middleware still calls next() after swallowing", nextCalled === true);
  check("middleware falls back to the current default locale on error",
        req.locale === "en");
}

// A custom headerName reads the negotiation source from a non-standard header.
function testMiddlewareCustomHeaderName() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en", "es"],
    translations:  { en: { greet: "Hello" }, es: { greet: "Hola" } },
  });
  var req = _mockReq();
  req.headers = { "x-locale": "es" };
  i.middleware({ headerName: "X-Locale" })(req, _mockRes(), function () {});
  check("custom headerName negotiates from the named header",
        req.locale === "es");
}

// ICU MessageFormat feature surface driven through t(): nested plural inside
// select, plural offset, selectordinal, and the # placeholder.
function testMessageFormatFeaturePathsViaT() {
  var i = b.i18n.create({
    defaultLocale: "en",
    locales:       ["en"],
    translations: {
      en: {
        nested: "{tier, select, pro {{n, plural, one {# pro seat} other {# pro seats}}} other {{n, plural, one {# seat} other {# seats}}}}",
        party:  "{n, plural, offset:1 =0 {nobody} one {you and # other} other {you and # others}}",
        medal:  "{p, selectordinal, one {#st} two {#nd} few {#rd} other {#th}} place",
        exact:  "{n, plural, =0 {no items} =1 {a single item} other {# items}}",
      },
    },
  });
  check("nested select→plural (pro, one)",
        i.t("nested", { tier: "pro", n: 1 }) === "1 pro seat");
  check("nested select→plural (pro, other)",
        i.t("nested", { tier: "pro", n: 4 }) === "4 pro seats");
  check("nested select falls to other branch",
        i.t("nested", { tier: "free", n: 2 }) === "2 seats");
  check("plural offset =0 exact case",
        i.t("party", { n: 0 }) === "nobody");
  check("plural offset one case subtracts the offset in #",
        i.t("party", { n: 2 }) === "you and 1 other");
  check("plural offset other case subtracts the offset in #",
        i.t("party", { n: 4 }) === "you and 3 others");
  check("selectordinal few (3rd)",
        i.t("medal", { p: 3 }) === "3rd place");
  check("selectordinal other (11th)",
        i.t("medal", { p: 11 }) === "11th place");
  check("plural exact =1 literal case beats the 'one' category",
        i.t("exact", { n: 1 }) === "a single item");
  check("plural exact falls to other for a non-literal count",
        i.t("exact", { n: 7 }) === "7 items");

  // messageFormat: true forces the ICU path even for a plain-looking entry.
  var i2 = b.i18n.create({
    defaultLocale: "en", locales: ["en"],
    translations: { en: { plain: "just text {x}" } },
  });
  check("messageFormat:true on a plain entry renders the literal placeholder text",
        typeof i2.t("plain", { x: "v" }, { messageFormat: true }) === "string");
}

// localeChain called with a falsy opts argument still validates (and throws on
// the now-missing defaultLocale) rather than dereferencing undefined.
function testLocaleChainFalsyOpts() {
  var threw = false;
  try { b.i18n.localeChain("fr", null); } catch (_e) { threw = true; }
  check("localeChain('fr', null) throws (defaultLocale required)", threw);

  // A configured-set that DOES include the members passes membership validation
  // and returns the chain (the happy path through the membership guard).
  var chain = b.i18n.localeChain("fr-CA", {
    defaultLocale: "en", fallbackLocale: "en", locales: ["en", "fr", "fr-CA"],
  });
  check("localeChain with a valid configured set returns the chain",
        JSON.stringify(chain) === JSON.stringify(["fr-CA", "fr", "en"]));
}

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
