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

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
