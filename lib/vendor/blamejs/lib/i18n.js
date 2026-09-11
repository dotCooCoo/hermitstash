// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.i18n
 * @nav    Tools
 * @title  i18n
 *
 * @intro
 *   ICU MessageFormat + CLDR Plural Rules + locale-aware Intl
 *   formatters with translation lookup. Built on Node 24's bundled
 *   `Intl.*` (`PluralRules`, `NumberFormat`, `DateTimeFormat`,
 *   `RelativeTimeFormat`, `ListFormat`, `DisplayNames`) — zero
 *   vendoring, zero CLDR data shipped, the runtime owns it.
 *
 *   Lookup chain: `t("nav.home", vars, { locale })` walks the
 *   subtag-stripped chain (`pt-BR` → `pt`), then falls through to the
 *   configured `fallbackLocale` and finally `defaultLocale` unless
 *   `fallbackLocale: null` (strict "this locale or miss"). Plural-
 *   shaped values use CLDR cardinal keys (`zero` / `one` / `two` /
 *   `few` / `many` / `other`); `other` is mandatory and validated at
 *   load. Ordinal plurals route through a separate `Intl.PluralRules({
 *   type: "ordinal" })` cache via `to(key, count)`.
 *
 *   Translation file format (JSON loaded eagerly from `opts.dir` or
 *   inline via `opts.translations`):
 *
 *     {
 *       "greeting": "Hello, {name}!",
 *       "items":   { "one": "{count} item", "other": "{count} items" },
 *       "nav":     { "home": "Home", "about": "About" }
 *     }
 *
 *   ICU MessageFormat (`{name, plural, ...}` / `{name, select, ...}` /
 *   `{name, selectordinal, ...}`) is auto-detected by `t()`; operators
 *   force the path with `t(key, vars, { messageFormat: true })`. The
 *   companion `b.i18n.messageFormat` namespace exposes the parser /
 *   formatter for use outside an instance.
 *
 *   Validation policy:
 *     - `create()` throws on bad opts (boot).
 *     - Bad BCP 47 locale at any boundary → throw at call site.
 *     - `t(missingKey)` → return the key + emit `i18n.missing`
 *       observability event (never throws unless `missingKey: "throw"`).
 *     - Plural shape missing `other` → throw at load time.
 *     - Missing interpolation var renders as literal `{var}` unless
 *       `interpolation.strict: true`.
 *     - `formatNumber` / `formatDate` / `formatRelative` / `formatList`
 *       throw at call site on a non-finite value or unparseable date.
 *     - Middleware `Accept-Language` parse error falls back to the
 *       default locale; the request never crashes on a bad header.
 *
 *   Security stance: translation values come from operator-controlled
 *   files, not user input. `{var}` interpolation does NOT html-escape;
 *   `b.template` already escapes at render time. For non-template
 *   contexts, pass `interpolation.escape: fn`.
 *
 * @card
 *   ICU MessageFormat + CLDR Plural Rules + locale-aware Intl formatters with translation lookup.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { I18nError } = require("./framework-error");
var { boundedMap, getOrInsert } = require("./bounded-map");

var FORMATTER_CACHE_MAX_ENTRIES = 512;

var observability = lazyRequire(function () { return require("./observability"); });

var _err = I18nError.factory;

var PLURAL_CATEGORIES = Object.freeze(["zero", "one", "two", "few", "many", "other"]);

var RTL_LANGUAGES = Object.freeze(new Set([
  "ar",
  "fa",
  "he",
  "ur",
  "ps",
  "sd",
  "yi",
  "ckb",
  "dv",
]));

var DEFAULTS = Object.freeze({
  fallbackLocale:   null,
  missingKey:       "return-key",
  interpolation:    Object.freeze({ start: "{", end: "}", strict: false }),
  RTL_LANGUAGES:    RTL_LANGUAGES,
});

function _isValidBcp47(tag) {
  if (typeof tag !== "string" || tag.length === 0) return false;
  try {
    var canonical = Intl.getCanonicalLocales(tag);
    return canonical.length === 1;
  } catch (_e) {
    return false;
  }
}

function _validateLocale(name, value) {
  if (!_isValidBcp47(value)) {
    throw _err("i18n/bad-locale", name + " must be a valid BCP 47 language tag, got " +
      JSON.stringify(value));
  }
}

function _validateLocaleArray(name, value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw _err("i18n/bad-opt", name + " must be a non-empty array of BCP 47 tags");
  }
  for (var i = 0; i < value.length; i++) {
    _validateLocale(name + "[" + i + "]", value[i]);
  }
}

function _buildLocaleChain(locale, fallbackLocale, defaultLocale) {
  var chain = [];
  var current = locale;
  while (current && chain.indexOf(current) === -1) {
    chain.push(current);
    var dash = current.lastIndexOf("-");
    if (dash === -1) break;
    current = current.slice(0, dash);
  }
  if (fallbackLocale === null) return chain;
  if (chain.indexOf(fallbackLocale) === -1) chain.push(fallbackLocale);
  if (chain.indexOf(defaultLocale) === -1) chain.push(defaultLocale);
  return chain;
}

/**
 * @primitive  b.i18n.localeChain
 * @signature  b.i18n.localeChain(locale, opts)
 * @since      0.15.13
 * @status     stable
 * @related    b.i18n.create
 *
 * Resolve a requested BCP 47 locale to its ordered fallback chain — the same
 * subtag-strip logic the file-backed `t()` lookup uses, surfaced as a pure,
 * instance-independent function so a data-backed consumer (translations in a
 * database row, a CMS page, a CDN-cached asset) can drive its own per-`(resource,
 * locale, field)` lookups on the framework's BCP 47 fallback instead of
 * re-deriving subtag stripping by hand.
 *
 * Pure: no file loading, no message lookup. The chain is the requested locale,
 * then each subtag-stripped parent ("fr-CA" -> "fr"), then `fallbackLocale`,
 * then `defaultLocale`, de-duplicated. `fallbackLocale: null` gives strict
 * "this locale or its parents only" (no cross-locale jump).
 *
 * @opts
 *   defaultLocale:  string,          // BCP 47; required; the final baseline
 *   fallbackLocale: string | null,   // null = strict; omitted = defaultLocale
 *   locales:        string[],        // optional configured set; when given, defaultLocale + fallbackLocale must be members
 *
 * @example
 *   b.i18n.localeChain("fr-CA", { defaultLocale: "en", fallbackLocale: "en" });
 *   // → ["fr-CA", "fr", "en"]
 *   b.i18n.localeChain("zh-Hant-TW", { defaultLocale: "en", fallbackLocale: null });
 *   // → ["zh-Hant-TW", "zh-Hant", "zh"]   (strict — no jump to en)
 */
function localeChain(locale, opts) {
  opts = opts || {};
  _validateLocale("i18n.localeChain: locale", locale);
  _validateLocale("i18n.localeChain: defaultLocale", opts.defaultLocale);
  var defaultLocale = opts.defaultLocale;
  var fallbackLocale = (opts.fallbackLocale === null) ? null
    : ((opts.fallbackLocale === undefined) ? defaultLocale : opts.fallbackLocale);
  if (fallbackLocale !== null) _validateLocale("i18n.localeChain: fallbackLocale", fallbackLocale);
  if (opts.locales !== undefined) {
    _validateLocaleArray("i18n.localeChain: locales", opts.locales);
    if (opts.locales.indexOf(defaultLocale) === -1) {
      throw _err("i18n/bad-opt", "i18n.localeChain: defaultLocale '" + defaultLocale +
        "' must be one of the configured locales");
    }
    if (fallbackLocale !== null && opts.locales.indexOf(fallbackLocale) === -1) {
      throw _err("i18n/bad-opt", "i18n.localeChain: fallbackLocale '" + fallbackLocale +
        "' must be one of the configured locales");
    }
  }
  return _buildLocaleChain(locale, fallbackLocale, defaultLocale);
}

function _validateInterpolation(value) {
  if (value === undefined) return DEFAULTS.interpolation;
  if (typeof value !== "object" || value === null) {
    throw _err("i18n/bad-opt", "i18n.create: interpolation must be an object");
  }
  var start = value.start !== undefined ? value.start : DEFAULTS.interpolation.start;
  var end   = value.end   !== undefined ? value.end   : DEFAULTS.interpolation.end;
  if (typeof start !== "string" || start.length === 0) {
    throw _err("i18n/bad-opt", "i18n.create: interpolation.start must be a non-empty string");
  }
  if (typeof end !== "string" || end.length === 0) {
    throw _err("i18n/bad-opt", "i18n.create: interpolation.end must be a non-empty string");
  }
  if (value.escape !== undefined && typeof value.escape !== "function") {
    throw _err("i18n/bad-opt", "i18n.create: interpolation.escape must be a function");
  }
  if (value.strict !== undefined && typeof value.strict !== "boolean") {
    throw _err("i18n/bad-opt", "i18n.create: interpolation.strict must be a boolean");
  }
  return Object.freeze({
    start:  start,
    end:    end,
    escape: value.escape || null,
    strict: value.strict === true,
  });
}

function _validateMissingKeyPolicy(value) {
  if (value === undefined) return DEFAULTS.missingKey;
  if (value === "return-key" || value === "throw") return value;
  if (typeof value === "function") return value;
  throw _err("i18n/bad-opt",
    "i18n.create: missingKey must be 'return-key' / 'throw' / function, got " +
    JSON.stringify(value));
}

function _validateRtlList(value) {
  if (value === undefined) return RTL_LANGUAGES;
  if (!Array.isArray(value)) {
    throw _err("i18n/bad-opt", "i18n.create: rtlLanguages must be an array of language subtags");
  }
  var normalized = [];
  for (var i = 0; i < value.length; i++) {
    if (typeof value[i] !== "string" || value[i].length === 0) {
      throw _err("i18n/bad-opt", "i18n.create: rtlLanguages[" + i + "] must be a non-empty string");
    }
    normalized.push(value[i].toLowerCase());
  }
  return new Set(normalized);
}

function _isPluralShape(node) {
  if (!node || typeof node !== "object" || Array.isArray(node)) return false;
  var keys = Object.keys(node);
  if (keys.length === 0) return false;
  var hasCldrKey = false;
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (PLURAL_CATEGORIES.indexOf(k) !== -1) hasCldrKey = true;
    if (typeof node[k] !== "string") return false;
  }
  return hasCldrKey;
}

function _validateTranslationTree(locale, node, dottedPath) {
  if (typeof node === "string") return;
  if (!node || typeof node !== "object" || Array.isArray(node)) {
    throw _err("i18n/bad-translations",
      "i18n: locale '" + locale + "' key '" + dottedPath +
      "': value must be a string or nested object");
  }
  if (_isPluralShape(node)) {
    if (typeof node.other !== "string") {
      throw _err("i18n/bad-translations",
        "i18n: locale '" + locale + "' key '" + dottedPath +
        "': plural-shaped entries must include an 'other' key (CLDR mandatory)");
    }
    var keys = Object.keys(node);
    for (var i = 0; i < keys.length; i++) {
      if (PLURAL_CATEGORIES.indexOf(keys[i]) === -1) {
        throw _err("i18n/bad-translations",
          "i18n: locale '" + locale + "' key '" + dottedPath +
          "' has unknown plural category '" + keys[i] +
          "' (allowed: " + PLURAL_CATEGORIES.join(", ") + ")");
      }
    }
    return;
  }
  var nestedKeys = Object.keys(node);
  for (var j = 0; j < nestedKeys.length; j++) {
    var k = nestedKeys[j];
    _validateTranslationTree(locale, node[k],
      dottedPath ? (dottedPath + "." + k) : k);
  }
}

function _loadFromDir(dir, locales) {
  var out = {};
  for (var i = 0; i < locales.length; i++) {
    var locale = locales[i];
    var filePath = nodePath.join(dir, locale + ".json");
    if (!nodeFs.existsSync(filePath)) {
      throw _err("i18n/load-failed",
        "i18n: translations file not found for locale '" + locale + "': " + filePath);
    }
    var raw;
    try { raw = nodeFs.readFileSync(filePath, "utf8"); }
    catch (e) {
      throw _err("i18n/load-failed",
        "i18n: failed to read '" + filePath + "': " + ((e && e.message) || String(e)));
    }
    try { out[locale] = safeJson.parse(raw); }
    catch (e) {
      throw _err("i18n/load-failed",
        "i18n: failed to parse JSON for locale '" + locale + "' (" + filePath + "): " +
        ((e && e.message) || String(e)));
    }
  }
  return out;
}

function _validateCreateOpts(opts) {
  validateOpts.requireObject(opts, "i18n.create", I18nError);
  _validateLocale("i18n.create: defaultLocale", opts.defaultLocale);
  _validateLocaleArray("i18n.create: locales", opts.locales);
  if (opts.locales.indexOf(opts.defaultLocale) === -1) {
    throw _err("i18n/bad-opt",
      "i18n.create: defaultLocale '" + opts.defaultLocale +
      "' must be present in locales array");
  }
  if (opts.fallbackLocale !== undefined && opts.fallbackLocale !== null) {
    _validateLocale("i18n.create: fallbackLocale", opts.fallbackLocale);
    if (opts.locales.indexOf(opts.fallbackLocale) === -1) {
      throw _err("i18n/bad-opt",
        "i18n.create: fallbackLocale '" + opts.fallbackLocale +
        "' must be present in locales array");
    }
  }
  if (opts.translations !== undefined && opts.dir !== undefined) {
    throw _err("i18n/bad-opt",
      "i18n.create: pass either translations OR dir, not both");
  }
  if (opts.translations !== undefined) {
    if (typeof opts.translations !== "object" || opts.translations === null || Array.isArray(opts.translations)) {
      throw _err("i18n/bad-opt", "i18n.create: translations must be an object keyed by locale");
    }
  }
  validateOpts.optionalNonEmptyString(opts.dir, "i18n.create: dir", I18nError);
  validateOpts.observabilityShape(opts.observability, "i18n.create", I18nError);
  validateOpts.optionalFunction(opts.clock, "i18n.create: clock", I18nError);
}

function _resolveKey(tree, dottedKey) {
  if (!tree || typeof tree !== "object") return undefined;
  if (typeof dottedKey !== "string" || dottedKey.length === 0) return undefined;
  if (dottedKey.indexOf(".") === -1) return tree[dottedKey];
  var parts = dottedKey.split(".");
  var node = tree;
  for (var i = 0; i < parts.length; i++) {
    if (!node || typeof node !== "object") return undefined;
    node = node[parts[i]];
    if (node === undefined) return undefined;
  }
  return node;
}

function _interpolate(template, vars, interpolation) {
  if (!template || typeof template !== "string") return template;
  if (!vars || typeof vars !== "object") vars = {};
  var start = interpolation.start;
  var end = interpolation.end;
  var escape = interpolation.escape;
  var out = "";
  var i = 0;
  while (i < template.length) {
    var openIdx = template.indexOf(start, i);
    if (openIdx === -1) {
      out += template.slice(i);
      break;
    }
    out += template.slice(i, openIdx);
    var closeIdx = template.indexOf(end, openIdx + start.length);
    if (closeIdx === -1) {
      out += template.slice(openIdx);
      break;
    }
    var name = template.slice(openIdx + start.length, closeIdx).trim();
    var hasVar = Object.prototype.hasOwnProperty.call(vars, name) && vars[name] !== undefined;
    if (hasVar) {
      var value = vars[name];
      var stringified = (value === null) ? "" : String(value);
      out += escape ? escape(stringified) : stringified;
    } else {
      if (interpolation.strict) {
        throw _err("i18n/missing-var",
          "i18n: missing interpolation var '" + name + "' in '" + template + "'");
      }
      out += template.slice(openIdx, closeIdx + end.length);
    }
    i = closeIdx + end.length;
  }
  return out;
}

function _makeFormatterCache(make, kind, emitObs) {
  var cache = boundedMap({ maxEntries: FORMATTER_CACHE_MAX_ENTRIES, policy: "evict-oldest" });
  return function getFormatter(locale, formatOpts) {
    var optsKey = formatOpts ? JSON.stringify(formatOpts) : "";
    var cacheKey = locale + "\x1f" + optsKey;
    return getOrInsert(cache, cacheKey, function () {
      var f = make(locale, formatOpts);
      emitObs("i18n.format.created", { kind: kind, locale: locale });
      return f;
    });
  };
}

/**
 * @primitive b.i18n.create
 * @signature b.i18n.create(opts)
 * @since     0.6.0
 * @status    stable
 * @related   b.template.render
 *
 * Build an i18n instance bound to a fixed `locales` set. The returned
 * object exposes translation (`t` / `tn` / `to` / `has`), Intl
 * formatters (`formatNumber` / `formatDate` / `formatRelative` /
 * `formatList` / `displayName`), locale state (`setLocale` /
 * `locale` / `locales()` / `dir()`), translation introspection
 * (`translations(locale)`), and an Express-shaped `middleware()` that
 * negotiates the request locale (resolver → query → cookie →
 * `Accept-Language`) and binds `req.t` / `req.tn` / `req.to` /
 * `req.dir` / `res.locals.t` etc. for handlers.
 *
 * Throws `I18nError` at boot on a malformed locale tag, a
 * `defaultLocale` not present in `locales`, a plural-shaped entry
 * missing `other`, an unknown CLDR plural key, or a missing
 * translation file when `dir` is supplied without `lazyLoad`.
 *
 * @opts
 *   defaultLocale:   string,                       // BCP 47 tag; required, must appear in locales
 *   locales:         [string],                     // BCP 47 tags; required, non-empty
 *   fallbackLocale:  string | null,                // null = strict; default = defaultLocale
 *   translations:    { [locale: string]: object }, // inline trees (mutually exclusive with dir)
 *   dir:             string,                       // load <dir>/<locale>.json (mutually exclusive with translations)
 *   eagerLocales:    [string],                     // with lazyLoad: which locales to load at create
 *   lazyLoad:        boolean,                      // with dir: load other locales on first lookup; default false
 *   interpolation:   { start?: string, end?: string, escape?: fn, strict?: boolean },
 *   missingKey:      "return-key" | "throw" | (key, locale) => string,
 *   onMissingKey:    (key, locale) => void,        // observability hook (best-effort)
 *   rtlLanguages:    [string],                     // override the framework default RTL list
 *   observability:   { event: (name, value, labels) => void },
 *   clock:           () => number,                 // ms-since-epoch override (testing)
 *
 * @example
 *   var i = b.i18n.create({
 *     defaultLocale: "en",
 *     locales:       ["en", "es", "fr", "ja", "ar"],
 *     translations: {
 *       en: { greeting: "Hello, {name}!", items: { one: "{count} item", other: "{count} items" } },
 *       es: { greeting: "Hola, {name}!" },
 *     },
 *   });
 *
 *   i.t("greeting", { name: "Alice" });                                 // → "Hello, Alice!"
 *   i.tn("items", 5);                                                   // → "5 items"
 *   i.t("greeting", { name: "Ana" }, { locale: "es" });                 // → "Hola, Ana!"
 *   i.formatNumber(1234.5, { style: "currency", currency: "USD" });     // → "$1,234.50"
 *   i.formatRelative(-5, "minute");                                     // → "5 minutes ago"
 *   i.dir({ locale: "ar" });                                            // → "rtl"
 *   i.has("nav.missing");                                               // → false
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "defaultLocale", "locales", "fallbackLocale",
    "translations", "dir", "eagerLocales", "lazyLoad",
    "interpolation", "missingKey", "onMissingKey", "rtlLanguages",
    "observability", "clock",
  ], "b.i18n");
  _validateCreateOpts(opts);

  if (opts.lazyLoad === true && opts.translations) {
    throw _err("i18n/bad-opt", "i18n.create: lazyLoad: true requires dir-based loading; " +
      "translations: { ... } is inline-only and already complete at create time");
  }
  if (opts.eagerLocales !== undefined) {
    if (!Array.isArray(opts.eagerLocales)) {
      throw _err("i18n/bad-opt", "i18n.create: eagerLocales must be an array of BCP 47 tags");
    }
    for (var ei = 0; ei < opts.eagerLocales.length; ei++) {
      _validateLocale("i18n.create: eagerLocales[" + ei + "]", opts.eagerLocales[ei]);
      if (opts.locales.indexOf(opts.eagerLocales[ei]) === -1) {
        throw _err("i18n/bad-opt", "i18n.create: eagerLocales[" + ei + "] '" +
          opts.eagerLocales[ei] + "' must be in locales array");
      }
    }
  }
  if (opts.onMissingKey !== undefined && typeof opts.onMissingKey !== "function") {
    throw _err("i18n/bad-opt", "i18n.create: onMissingKey must be a function (key, locale)");
  }

  var defaultLocale = opts.defaultLocale;
  var locales = opts.locales.slice();
  var fallbackLocale = (opts.fallbackLocale === null) ? null
    : ((opts.fallbackLocale === undefined) ? defaultLocale : opts.fallbackLocale);
  var interpolation = _validateInterpolation(opts.interpolation);
  var missingKeyPolicy = _validateMissingKeyPolicy(opts.missingKey);
  var rtlSet = _validateRtlList(opts.rtlLanguages);
  var operatorObs = opts.observability || null;

  var translations;
  var lazyLoadEnabled = false;
  var lazyLoadDir = null;
  var loadedSet = new Set();
  if (opts.dir) {
    if (opts.lazyLoad === true) {
      lazyLoadEnabled = true;
      lazyLoadDir = opts.dir;
      var eager = Array.isArray(opts.eagerLocales) && opts.eagerLocales.length > 0
                    ? opts.eagerLocales
                    : [defaultLocale];
      translations = _loadFromDir(opts.dir, eager);
      for (var ei2 = 0; ei2 < eager.length; ei2++) loadedSet.add(eager[ei2]);
    } else {
      translations = _loadFromDir(opts.dir, locales);
      for (var ei3 = 0; ei3 < locales.length; ei3++) loadedSet.add(locales[ei3]);
    }
  } else if (opts.translations) {
    translations = opts.translations;
    for (var ei4 = 0; ei4 < locales.length; ei4++) {
      if (translations[locales[ei4]]) loadedSet.add(locales[ei4]);
    }
  } else {
    translations = {};
  }
  var onMissingKey = opts.onMissingKey || null;
  Object.keys(translations).forEach(function (loc) {
    if (translations[loc]) {
      _validateTranslationTree(loc, translations[loc], "");
    }
  });

  function _ensureLocaleLoaded(locale) {
    if (loadedSet.has(locale)) return;
    if (!lazyLoadEnabled || !lazyLoadDir) return;
    if (!localesSet.has(locale)) return;
    var loaded = _loadFromDir(lazyLoadDir, [locale]);
    translations[locale] = loaded[locale];
    _validateTranslationTree(locale, translations[locale], "");
    loadedSet.add(locale);
    _emitObs("i18n.lazyLoad", { locale: locale });
  }
  var localesSet = new Set(locales);
  var currentLocale = defaultLocale;

  function _emitObs(name, labels) {
    try {
      if (operatorObs) operatorObs.event(name, 1, labels || {});
      else observability().event(name, 1, labels || {});
    } catch (_e) { /* drop-silent — observability sink must not crash i18n calls */ }
  }

  var pluralRulesByLocale = {};
  function _pluralRulesFor(locale) {
    var r = pluralRulesByLocale[locale];
    if (!r) {
      r = new Intl.PluralRules(locale);
      pluralRulesByLocale[locale] = r;
    }
    return r;
  }

  var numberFormatter = _makeFormatterCache(
    function (locale, fopts) { return new Intl.NumberFormat(locale, fopts || undefined); },
    "number", _emitObs);
  var dateFormatter = _makeFormatterCache(
    function (locale, fopts) { return new Intl.DateTimeFormat(locale, fopts || undefined); },
    "date", _emitObs);
  var relativeFormatter = _makeFormatterCache(
    function (locale, fopts) { return new Intl.RelativeTimeFormat(locale, fopts || undefined); },
    "relative", _emitObs);
  var listFormatter = _makeFormatterCache(
    function (locale, fopts) { return new Intl.ListFormat(locale, fopts || undefined); },
    "list", _emitObs);
  var displayNamesFormatter = _makeFormatterCache(
    function (locale, fopts) { return new Intl.DisplayNames([locale], fopts || { type: "language" }); },
    "displayNames", _emitObs);

  function _resolveLocale(callerLocale) {
    if (callerLocale === undefined || callerLocale === null) return currentLocale;
    if (typeof callerLocale !== "string") {
      throw _err("i18n/bad-locale", "i18n: locale override must be a string");
    }
    if (!_isValidBcp47(callerLocale)) {
      throw _err("i18n/bad-locale", "i18n: locale '" + callerLocale + "' is not a valid BCP 47 tag");
    }
    return callerLocale;
  }

  function _localeChain(locale) {
    return _buildLocaleChain(locale, fallbackLocale, defaultLocale);
  }

  function _lookupRaw(key, locale) {
    var chain = _localeChain(locale);
    for (var i = 0; i < chain.length; i++) {
      var loc = chain[i];
      _ensureLocaleLoaded(loc);
      if (!translations[loc]) continue;
      var v = _resolveKey(translations[loc], key);
      if (v === undefined) continue;
      if (typeof v === "string" || _isPluralShape(v)) {
        return { value: v, foundIn: loc };
      }
    }
    return null;
  }

  var ordinalRulesByLocale = {};
  function _ordinalRulesFor(locale) {
    var r = ordinalRulesByLocale[locale];
    if (!r) {
      r = new Intl.PluralRules(locale, { type: "ordinal" });
      ordinalRulesByLocale[locale] = r;
    }
    return r;
  }

  function _selectPlural(node, count, locale, ordinal) {
    var rules = ordinal ? _ordinalRulesFor(locale) : _pluralRulesFor(locale);
    var category = rules.select(count);
    if (typeof node[category] === "string") return node[category];
    return node.other;
  }

  function t(key, vars, callerOpts) {
    if (typeof key !== "string" || key.length === 0) {
      throw _err("i18n/bad-key", "i18n.t: key must be a non-empty string, got " + typeof key);
    }
    callerOpts = callerOpts || {};
    var locale = _resolveLocale(callerOpts.locale);
    var found = _lookupRaw(key, locale);

    if (!found) {
      _emitObs("i18n.missing", { locale: locale, key: key });
      safeAsync.safeApply(onMissingKey, [key, locale]);
      if (callerOpts.default !== undefined) return callerOpts.default;
      if (typeof missingKeyPolicy === "function") {
        return missingKeyPolicy(key, locale);
      }
      if (missingKeyPolicy === "throw") {
        throw _err("i18n/missing-key",
          "i18n.t: key '" + key + "' missing in locale chain for '" + locale + "'");
      }
      return key;
    }

    if (found.foundIn !== locale) {
      _emitObs("i18n.miss.fallback", { locale: locale, key: key });
    }

    var raw;
    if (typeof found.value === "string") {
      raw = found.value;
    } else {
      var count = (vars && typeof vars.count === "number") ? vars.count : 0;
      raw = _selectPlural(found.value, count, found.foundIn, callerOpts.ordinal === true);
    }

    var useMf = callerOpts.messageFormat === true ||
                messageFormat.looksLikeMessageFormat(raw);
    if (useMf) {
      return messageFormat.format(raw, vars, found.foundIn);
    }
    return _interpolate(raw, vars, interpolation);
  }

  function tn(key, count, vars, callerOpts) {
    if (typeof count !== "number" || !isFinite(count)) {
      throw _err("i18n/bad-input", "i18n.tn: count must be a finite number, got " +
        (typeof count) + " " + JSON.stringify(count));
    }
    var merged = vars ? Object.assign({}, vars, { count: count }) : { count: count };
    return t(key, merged, callerOpts);
  }

  function to(key, count, vars, callerOpts) {
    if (typeof count !== "number" || !isFinite(count)) {
      throw _err("i18n/bad-input", "i18n.to: count must be a finite number, got " +
        (typeof count) + " " + JSON.stringify(count));
    }
    var merged = vars ? Object.assign({}, vars, { count: count }) : { count: count };
    var withOrdinal = Object.assign({}, callerOpts || {}, { ordinal: true });
    return t(key, merged, withOrdinal);
  }

  function has(key, callerOpts) {
    callerOpts = callerOpts || {};
    if (typeof key !== "string" || key.length === 0) return false;
    var locale = _resolveLocale(callerOpts.locale);
    return _lookupRaw(key, locale) !== null;
  }

  function formatNumber(value, formatOpts, callerOpts) {
    if (typeof value !== "number" || !isFinite(value)) {
      throw _err("i18n/bad-input", "i18n.formatNumber: value must be a finite number, got " +
        (typeof value) + " " + JSON.stringify(value));
    }
    callerOpts = callerOpts || {};
    var locale = _resolveLocale(callerOpts.locale);
    return numberFormatter(locale, formatOpts).format(value);
  }

  function formatDate(value, formatOpts, callerOpts) {
    var d = (value instanceof Date) ? value
          : (typeof value === "number" || typeof value === "string") ? new Date(value)
          : null;
    if (!d || isNaN(d.getTime())) {
      throw _err("i18n/bad-input", "i18n.formatDate: value must be a Date / number / parseable string");
    }
    callerOpts = callerOpts || {};
    var locale = _resolveLocale(callerOpts.locale);
    return dateFormatter(locale, formatOpts).format(d);
  }

  function formatRelative(value, unit, callerOpts) {
    if (typeof value !== "number" || !isFinite(value)) {
      throw _err("i18n/bad-input", "i18n.formatRelative: value must be a finite number");
    }
    if (typeof unit !== "string" || unit.length === 0) {
      throw _err("i18n/bad-input", "i18n.formatRelative: unit must be a non-empty string");
    }
    callerOpts = callerOpts || {};
    var locale = _resolveLocale(callerOpts.locale);
    var fopts = callerOpts.numeric ? { numeric: callerOpts.numeric } : undefined;
    return relativeFormatter(locale, fopts).format(value, unit);
  }

  function formatList(items, formatOpts, callerOpts) {
    if (!Array.isArray(items)) {
      throw _err("i18n/bad-input", "i18n.formatList: items must be an array of strings");
    }
    callerOpts = callerOpts || {};
    var locale = _resolveLocale(callerOpts.locale);
    return listFormatter(locale, formatOpts).format(items);
  }

  function displayName(code, type, callerOpts) {
    if (typeof code !== "string" || code.length === 0) {
      throw _err("i18n/bad-input", "i18n.displayName: code must be a non-empty string");
    }
    var allowed = ["language", "region", "currency", "script"];
    if (allowed.indexOf(type) === -1) {
      throw _err("i18n/bad-input", "i18n.displayName: type must be one of " + allowed.join(", "));
    }
    callerOpts = callerOpts || {};
    var locale = _resolveLocale(callerOpts.locale);
    var f = displayNamesFormatter(locale, { type: type });
    return f.of(code);
  }

  function setLocale(newLocale) {
    _validateLocale("i18n.setLocale", newLocale);
    if (!localesSet.has(newLocale)) {
      _emitObs("i18n.miss.locale", { requested: newLocale, resolved: defaultLocale });
    }
    currentLocale = newLocale;
  }

  function dir(callerOpts) {
    callerOpts = callerOpts || {};
    var locale = _resolveLocale(callerOpts.locale);
    var primary = locale.split("-")[0].toLowerCase();
    return rtlSet.has(primary) ? "rtl" : "ltr";
  }

  function getTranslationsFor(locale) {
    if (typeof locale !== "string" || locale.length === 0) {
      throw _err("i18n/bad-input", "i18n.translations: locale must be a string");
    }
    return translations[locale] || null;
  }

  function _negotiateLocale(parsedList) {
    for (var i = 0; i < parsedList.length; i++) {
      var requested = parsedList[i].value;
      if (parsedList[i].q === 0) continue;
      if (localesSet.has(requested)) return requested;
      var dash = requested.lastIndexOf("-");
      while (dash !== -1) {
        var prefix = requested.slice(0, dash);
        if (localesSet.has(prefix)) return prefix;
        dash = prefix.lastIndexOf("-");
      }
      for (var j = 0; j < locales.length; j++) {
        var loc = locales[j];
        if (loc.toLowerCase().split("-")[0] === requested.toLowerCase().split("-")[0]) {
          return loc;
        }
      }
    }
    return defaultLocale;
  }

  function middleware(mwOpts) {
    mwOpts = mwOpts || {};
    var headerName = (mwOpts.headerName || "accept-language").toLowerCase();
    var queryParam = mwOpts.queryParam || "lang";
    var cookieName = mwOpts.cookieName || null;
    var resolver   = typeof mwOpts.resolver === "function" ? mwOpts.resolver : null;

    return function i18nMiddleware(req, res, next) {
      try {
        var explicit = null;
        if (resolver) {
          try { explicit = resolver(req); }
          catch (_e) { explicit = null; }
        }
        if (!explicit && req.query && typeof req.query[queryParam] === "string") {
          explicit = req.query[queryParam];
        }
        if (!explicit && cookieName && req.cookies && typeof req.cookies[cookieName] === "string") {
          explicit = req.cookies[cookieName];
        }

        var resolvedLocale;
        if (explicit && _isValidBcp47(explicit) && localesSet.has(explicit)) {
          resolvedLocale = explicit;
        } else {
          var headerValue = (req.headers && req.headers[headerName]) || null;
          var parsed = requestHelpers.parseQualityList(headerValue);
          resolvedLocale = _negotiateLocale(parsed);
        }

        function reqT(key, vars, callerOpts) {
          var c = callerOpts ? Object.assign({}, callerOpts) : {};
          if (c.locale === undefined) c.locale = resolvedLocale;
          return t(key, vars, c);
        }
        function reqTn(key, count, vars, callerOpts) {
          var c = callerOpts ? Object.assign({}, callerOpts) : {};
          if (c.locale === undefined) c.locale = resolvedLocale;
          return tn(key, count, vars, c);
        }
        function reqTo(key, count, vars, callerOpts) {
          var c = callerOpts ? Object.assign({}, callerOpts) : {};
          if (c.locale === undefined) c.locale = resolvedLocale;
          return to(key, count, vars, c);
        }
        function reqDir() {
          return dir({ locale: resolvedLocale });
        }

        req.locale = resolvedLocale;
        req.t = reqT;
        req.tn = reqTn;
        req.to = reqTo;
        req.dir = reqDir;
        if (res && typeof res === "object") {
          if (!res.locals) res.locals = {};
          res.locals.locale = resolvedLocale;
          res.locals.t = reqT;
          res.locals.tn = reqTn;
          res.locals.to = reqTo;
          res.locals.dir = reqDir();
        }
      } catch (_e) {
        req.locale = currentLocale;
      }
      next();
    };
  }

  return {
    t:               t,
    tn:              tn,
    to:              to,
    has:             has,
    formatNumber:    formatNumber,
    formatDate:      formatDate,
    formatRelative:  formatRelative,
    formatList:      formatList,
    displayName:     displayName,
    setLocale:       setLocale,
    dir:             dir,
    locales:         function () { return locales.slice(); },
    translations:    getTranslationsFor,
    middleware:      middleware,
    get locale() { return currentLocale; },
    _localeChain:    _localeChain,
  };
}

var messageFormat = require("./i18n-messageformat");

module.exports = {
  create:            create,
  localeChain:       localeChain,
  messageFormat:     messageFormat,
  I18nError:         I18nError,
  DEFAULTS:          DEFAULTS,
  RTL_LANGUAGES:     RTL_LANGUAGES,
  PLURAL_CATEGORIES: PLURAL_CATEGORIES,
};
