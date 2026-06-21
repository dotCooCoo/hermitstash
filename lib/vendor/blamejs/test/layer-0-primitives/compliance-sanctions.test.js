"use strict";
/**
 * Tests for b.compliance.sanctions and the underlying fuzzy module.
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var sanctions = b.compliance.sanctions;
var fuzzy = sanctions.fuzzy;

// ---- normalize ----

function testNormalize() {
  check("normalize: lowercase",
        fuzzy.normalize("Alice Smith") === "alice smith");
  check("normalize: collapses whitespace",
        fuzzy.normalize("Alice    Smith") === "alice smith");
  check("normalize: strips diacritics",
        fuzzy.normalize("Müller") === "muller");
  check("normalize: strips multi-char diacritics",
        fuzzy.normalize("Straße") === "strasse");
  check("normalize: preserves apostrophe + hyphen",
        fuzzy.normalize("O'Brien-Smith") === "o'brien-smith");
  check("normalize: strips punctuation",
        fuzzy.normalize("Smith, John (Mr.)") === "smith john mr");
  check("normalize: empty string",
        fuzzy.normalize("") === "");
  check("normalize: non-string returns empty",
        fuzzy.normalize(null) === "");
}

function testTokenize() {
  var tokens = fuzzy.tokenize("Alice Smith Brown");
  check("tokenize: 3 tokens",
        tokens.length === 3 && tokens[0] === "alice" && tokens[2] === "brown");
  check("tokenize: empty input",
        fuzzy.tokenize("").length === 0);
  check("tokenize: input over cap throws",
        (function () {
          try { fuzzy.tokenize("a".repeat(600)); return false; }
          catch (_e) { return true; }
        })());
}

// ---- Levenshtein ----

function testLevenshtein() {
  check("levenshtein: identical",   fuzzy.levenshtein("kitten", "kitten") === 0);
  check("levenshtein: empty a",     fuzzy.levenshtein("", "abc") === 3);
  check("levenshtein: empty b",     fuzzy.levenshtein("abc", "") === 3);
  check("levenshtein: classic 3",   fuzzy.levenshtein("kitten", "sitting") === 3);
  check("levenshtein: cap exit",
        fuzzy.levenshtein("totally different", "another string", 3) === 4);
  check("levenshtein: length-delta cap",
        fuzzy.levenshtein("a", "abcdefg", 3) === 4);
}

// ---- Jaro / Jaro-Winkler ----

function testJaro() {
  // From Winkler's paper
  var s = fuzzy.jaro("MARTHA", "MARHTA");
  check("jaro: MARTHA/MARHTA close to 0.944",
        Math.abs(s - 0.944) < 0.01);
  check("jaro: identical = 1", fuzzy.jaro("smith", "smith") === 1);
  check("jaro: empty = 0",     fuzzy.jaro("", "") === 0);
  check("jaro: no match = 0",  fuzzy.jaro("abc", "xyz") === 0);
}

function testJaroWinkler() {
  // Winkler boost for shared prefix
  var jw = fuzzy.jaroWinkler("MARTHA", "MARHTA");
  var j  = fuzzy.jaro("MARTHA", "MARHTA");
  check("jaroWinkler: prefix boost vs jaro",
        jw > j);
  check("jaroWinkler: prefix-weight bound",
        (function () {
          try { fuzzy.jaroWinkler("a", "b", 0.5); return false; }
          catch (_e) { return true; }
        })());
}

// ---- Token-set similarity ----

function testTokenSetSimilarity() {
  // Same tokens, different order
  var s = fuzzy.tokenSetSimilarity("John Smith", "Smith John");
  check("tokenSetSimilarity: order-invariant", s >= 0.9);
  // Subset match (extra word)
  var s2 = fuzzy.tokenSetSimilarity("John Smith", "John Smith Jr");
  check("tokenSetSimilarity: subset still high", s2 >= 0.6);
  // Different names
  var s3 = fuzzy.tokenSetSimilarity("John Smith", "Alice Brown");
  check("tokenSetSimilarity: different = low", s3 < 0.3);
}

// ---- Substring containment ----

function testSubstringContains() {
  check("substringContains: token-bounded match",
        fuzzy.substringContains("Acme Corp Limited", "Acme Corp"));
  check("substringContains: not partial-token",
        !fuzzy.substringContains("Acmecorp Limited", "Acme"));
  check("substringContains: case-insensitive",
        fuzzy.substringContains("acme corp limited", "Acme Corp"));
}

// ---- Initials match ----

function testInitialsMatch() {
  check("initialsMatch: J Smith / John Smith",
        fuzzy.initialsMatch("J Smith", "John Smith"));
  check("initialsMatch: full + full not by default",
        !fuzzy.initialsMatch("Bob Smith", "John Smith"));
  check("initialsMatch: token count must match",
        !fuzzy.initialsMatch("J", "John Smith"));
}

// ---- Sanctions screen ----

function _sampleEntries() {
  return [
    {
      id:           "OFAC-1",
      primaryName:  "JOHN ALEXANDER SMITH",
      aliases:      ["JOHN A SMITH", "JOHNNY SMITH"],
      type:         "individual",
      programs:     ["RUSSIA-EO13662"],
      country:      "RU",
      listedAt:     "2024-03-15",
    },
    {
      id:           "OFAC-2",
      primaryName:  "ACME CORPORATION",
      aliases:      ["ACME CORP", "ACME LLC"],
      type:         "entity",
      programs:     ["SDGT"],
      country:      "IR",
      listedAt:     "2023-06-01",
    },
    {
      id:           "OFAC-3",
      primaryName:  "MOHAMMED AL-FARSI",
      aliases:      ["MUHAMMAD AL FARSI", "MOHAMED AL FARSI"],
      type:         "individual",
      programs:     ["SDGT"],
      country:      "SY",
      listedAt:     "2022-01-10",
    },
  ];
}

function testCreateAndScreenExact() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "ofac-sdn",
    fuzzy:     { strategy: "exact" },
  });
  check("create: index size = 3", screener.size() === 3);

  // Exact match on primary name
  var r1 = screener.screen({ name: "JOHN ALEXANDER SMITH" });
  check("screen exact: match found", r1.match === true);
  check("screen exact: 1 hit",       r1.hits.length === 1);
  check("screen exact: correct id",  r1.hits[0].entryId === "OFAC-1");

  // Exact match on alias
  var r2 = screener.screen({ name: "ACME CORP" });
  check("screen exact: alias match", r2.match === true && r2.hits[0].entryId === "OFAC-2");

  // No match
  var r3 = screener.screen({ name: "Random Person" });
  check("screen exact: no match",    r3.match === false);
}

function testScreenJaroWinkler() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "ofac-sdn",
    fuzzy:     { strategy: "jaro-winkler", threshold: 0.85 },
  });
  // Typo on first name
  var r = screener.screen({ name: "John Aleksander Smyth" });
  check("screen jw: typo still matches",
        r.match === true && r.hits[0].entryId === "OFAC-1");
  check("screen jw: score >= threshold",
        r.hits[0].score >= 0.85);

  // Transliteration variation — should match the AL-FARSI entry
  var r2 = screener.screen({ name: "Muhamed AlFarsi" });
  check("screen jw: transliteration close",
        r2.match === true && r2.hits[0].entryId === "OFAC-3");
}

function testScreenLevenshtein() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "ofac-sdn",
    fuzzy:     { strategy: "levenshtein", maxLevenshtein: 3, threshold: 0.7 },
  });
  // 1-char typo
  var r = screener.screen({ name: "John Alexander Smithx" });
  check("screen lev: 1-char typo matches",
        r.match === true && r.hits[0].entryId === "OFAC-1");
  // Far-from-list
  var r2 = screener.screen({ name: "Completely Unrelated" });
  check("screen lev: unrelated no match", r2.match === false);
}

function testScreenSubstringMatch() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "ofac-sdn",
    fuzzy:     { strategy: "jaro-winkler", threshold: 0.85 },
  });
  // Operator's record has extra words; SDN entry is a substring
  var r = screener.screen({ name: "Acme Corporation Limited Liability" });
  check("screen substring: matches SDN substring",
        r.match === true && r.hits[0].entryId === "OFAC-2");
}

function testScreenTypeFilter() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "ofac-sdn",
    fuzzy:     { strategy: "jaro-winkler", threshold: 0.85 },
  });
  // Searching for an entity but providing individual type — should
  // skip the entity (Acme Corporation is an entity)
  var r = screener.screen({ name: "Acme Corporation", type: "individual" });
  check("screen type filter: entity matches still allowed",
        r.match === true && r.hits[0].type === "entity");

  // A sanctions screen MUST over-match on the NAME: a sanctioned INDIVIDUAL
  // screened with a DIFFERING operator-asserted type (the counterparty's
  // unverified self-classification) must STILL match — previously the type
  // filter `continue`d past it, an under-match / fail-open false negative.
  var rv = screener.screen({ name: "JOHN ALEXANDER SMITH", type: "vessel" });
  check("screen: sanctioned individual still matches under a differing type",
        rv.match === true && rv.hits.length >= 1 && rv.hits[0].type === "individual");
  check("screen: type mismatch surfaced as non-dispositive typeMatch:false",
        rv.hits[0].typeMatch === false);
  var rmatch = screener.screen({ name: "JOHN ALEXANDER SMITH", type: "individual" });
  check("screen: typeMatch true when asserted type matches", rmatch.hits[0].typeMatch === true);
  var rnotype = screener.screen({ name: "JOHN ALEXANDER SMITH" });
  check("screen: typeMatch null when no type asserted", rnotype.hits[0].typeMatch === null);
}

function testScreenCorrectAlgorithmEcho() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "eu-csl",
    fuzzy:     { strategy: "exact" },
  });
  var r = screener.screen({ name: "JOHN ALEXANDER SMITH" });
  check("screen: result echoes algorithm",
        r.algorithm === "eu-csl");
}

function testCreateValidation() {
  var threwBadAlg = false;
  try {
    sanctions.create({ entries: [], algorithm: "INVALID" });
  } catch (_e) { threwBadAlg = true; }
  check("create: invalid algorithm throws", threwBadAlg);

  var threwBadEntries = false;
  try {
    sanctions.create({ entries: "not-an-array", algorithm: "ofac-sdn" });
  } catch (_e) { threwBadEntries = true; }
  check("create: non-array entries throws", threwBadEntries);

  var threwBadStrategy = false;
  try {
    sanctions.create({
      entries: [], algorithm: "custom",
      fuzzy: { strategy: "INVALID" },
    });
  } catch (_e) { threwBadStrategy = true; }
  check("create: invalid strategy throws", threwBadStrategy);

  var threwBadThreshold = false;
  try {
    sanctions.create({
      entries: [], algorithm: "custom",
      fuzzy: { threshold: 1.5 },
    });
  } catch (_e) { threwBadThreshold = true; }
  check("create: out-of-range threshold throws", threwBadThreshold);
}

function testScreenInputValidation() {
  var screener = sanctions.create({
    entries: _sampleEntries(), algorithm: "ofac-sdn",
  });
  var threwNoName = false;
  try { screener.screen({}); } catch (_e) { threwNoName = true; }
  check("screen: missing name throws", threwNoName);

  var threwBadType = false;
  try {
    screener.screen({ name: "Alice", type: "INVALID" });
  } catch (_e) { threwBadType = true; }
  check("screen: invalid type throws", threwBadType);

  var threwLong = false;
  try {
    screener.screen({ name: "a".repeat(600) });
  } catch (_e) { threwLong = true; }
  check("screen: name over cap throws", threwLong);
}

// ---- Parser shims ----

function testParseOfacCsvRow() {
  var entry = sanctions.parseOfacCsvRow({
    ent_num:      12345,
    SDN_Name:     "JOHN SMITH",
    SDN_Type:     "individual",
    Program:      "RUSSIA-EO13662; SDGT",
    Country:      "RU",
    Publish_Date: "2024-03-15",
  });
  check("parseOfacCsvRow: id formed", entry.id === "OFAC-12345");
  check("parseOfacCsvRow: name", entry.primaryName === "JOHN SMITH");
  check("parseOfacCsvRow: programs split",
        entry.programs.length === 2 && entry.programs[0] === "RUSSIA-EO13662");

  check("parseOfacCsvRow: empty/null returns null",
        sanctions.parseOfacCsvRow(null) === null);
  check("parseOfacCsvRow: missing name returns null",
        sanctions.parseOfacCsvRow({ ent_num: 1 }) === null);
}

function testMergeAliases() {
  var entries = [{
    id: "OFAC-1", primaryName: "JOHN SMITH", aliases: [],
    type: "individual", programs: [], country: null, listedAt: null,
    remarks: null, raw: null,
  }];
  var aliasRows = [{
    entId: "OFAC-1", altType: "aka", altName: "JOHNNY SMITH", remarks: null,
  }];
  var merged = sanctions.mergeAliases(entries, aliasRows);
  check("mergeAliases: alias merged",
        merged[0].aliases.length === 1 && merged[0].aliases[0] === "JOHNNY SMITH");
}

function testParseEuCslEntry() {
  var entry = sanctions.parseEuCslEntry({
    logicalId: 999,
    nameAlias: [
      { wholeName: "Acme Bank" },
      { wholeName: "Acme Banking Group" },
    ],
    subjectType:     "enterprise",
    regulation:      "(EU) 269/2014",
    country:         "RU",
    designationDate: "2022-02-25",
  });
  check("parseEuCslEntry: id formed", entry.id === "EU-CSL-999");
  check("parseEuCslEntry: primary name", entry.primaryName === "Acme Bank");
  check("parseEuCslEntry: aliases extracted",
        entry.aliases.length === 1 && entry.aliases[0] === "Acme Banking Group");
  check("parseEuCslEntry: type entity", entry.type === "entity");
}

function testParseUn1267Entry() {
  var entry = sanctions.parseUn1267Entry({
    REFERENCE_NUMBER: "QDi.001",
    NAME:             "ABDUL RAUF",
    NAME_TYPE:        "Individual",
    ALIAS_NAMES:      "ABDULRAUF; AYI",
    LISTED_ON:        "2001-10-08",
  });
  check("parseUn1267Entry: id formed", entry.id === "UN-1267-QDi.001");
  check("parseUn1267Entry: name", entry.primaryName === "ABDUL RAUF");
  check("parseUn1267Entry: aliases parsed",
        entry.aliases.length === 2);
}

// ---- entryById helper ----

function testEntryById() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "ofac-sdn",
  });
  var e = screener.entryById("OFAC-1");
  check("entryById: returns entry", e && e.primaryName === "JOHN ALEXANDER SMITH");
  check("entryById: unknown returns null", screener.entryById("OFAC-99999") === null);
}

// ---- Bulk + snapshot + reload ----

function testScreenBulk() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "ofac-sdn",
    fuzzy:     { strategy: "exact" },
  });
  var results = screener.screenBulk([
    { name: "JOHN ALEXANDER SMITH" },
    { name: "ACME CORP" },
    { name: "Random Person" },
  ]);
  check("screenBulk: 3 results",      results.length === 3);
  check("screenBulk: 0 matches",      results[0].match === true);
  check("screenBulk: 1 matches",      results[1].match === true);
  check("screenBulk: 2 no match",     results[2].match === false);
}

function testScreenBulkValidation() {
  var screener = sanctions.create({
    entries: _sampleEntries(), algorithm: "ofac-sdn",
  });
  var threw = false;
  try { screener.screenBulk("not-array"); } catch (_e) { threw = true; }
  check("screenBulk: non-array throws", threw);
}

function testSnapshot() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "ofac-sdn",
    ruleVersion: "ofac-2026-05-06",
  });
  var snap = screener.snapshot();
  check("snapshot: algorithm",     snap.algorithm === "ofac-sdn");
  check("snapshot: ruleVersion",   snap.ruleVersion === "ofac-2026-05-06");
  check("snapshot: entryCount",    snap.entryCount === 3);
  check("snapshot: digest format", typeof snap.digest === "string" && /^[0-9a-f]+$/.test(snap.digest));
  check("snapshot: digest deterministic",
        screener.snapshot().digest === snap.digest);
  check("snapshot: digestAlg",     snap.digestAlg === "sha3-512-trunc128");
}

function testReload() {
  var screener = sanctions.create({
    entries:   _sampleEntries(),
    algorithm: "ofac-sdn",
  });
  check("reload: initial size 3",  screener.size() === 3);

  // Drop entry-1, add a new one
  var newEntries = [
    _sampleEntries()[1],
    _sampleEntries()[2],
    {
      id:           "OFAC-99",
      primaryName:  "NEW SANCTIONED ENTITY",
      aliases:      [],
      type:         "entity",
      programs:     ["NEW-EO"],
      country:      "KP",
      listedAt:     "2026-05-06",
    },
  ];
  var diff = screener.reload(newEntries);
  check("reload: 1 added",          diff.addedIds.length === 1 && diff.addedIds[0] === "OFAC-99");
  check("reload: 1 removed",        diff.removedIds.length === 1 && diff.removedIds[0] === "OFAC-1");
  check("reload: newSize 3",        diff.newSize === 3);
  check("reload: ruleVersion changed",
        diff.ruleVersion.indexOf("reloadedAt") !== -1);

  // Old entry no longer in index
  var r1 = screener.screen({ name: "JOHN ALEXANDER SMITH" });
  check("reload: old entry no longer matches", r1.match === false);
  // New entry matches
  var r2 = screener.screen({ name: "NEW SANCTIONED ENTITY" });
  check("reload: new entry matches",
        r2.match === true && r2.hits[0].entryId === "OFAC-99");
}

function testReloadValidation() {
  var screener = sanctions.create({ entries: [], algorithm: "custom" });
  var threw = false;
  try { screener.reload("not-array"); } catch (_e) { threw = true; }
  check("reload: non-array throws", threw);
}

// ---- Aliases ----

function testAliasExpand() {
  var aliases = sanctions.aliases;
  var expanded = aliases.expand("Bill J. Smith");
  check("aliases.expand: includes original",
        expanded.indexOf("bill j smith") !== -1 ||
        expanded.indexOf("bill j. smith") !== -1);
  // Should include the William → Bill expansion
  var hasWilliam = expanded.some(function (s) {
    return s.toLowerCase().indexOf("william") !== -1;
  });
  check("aliases.expand: includes William variant", hasWilliam);
}

function testAliasInitials() {
  var aliases = sanctions.aliases;
  var expanded = aliases.expand("John Smith");
  // Should include J. Smith or J Smith
  var hasInitial = expanded.some(function (s) {
    return /^j\.? smith$/i.test(s);
  });
  check("aliases.expand: includes J Smith initial", hasInitial);
}

function testAliasReverseOrder() {
  var aliases = sanctions.aliases;
  var expanded = aliases.expand("John Smith");
  // Should include "Smith John" or "Smith, John"
  var hasReversed = expanded.some(function (s) {
    return /smith[, ]+john/i.test(s);
  });
  check("aliases.expand: includes Last First form", hasReversed);
}

function testAliasNoDuplicates() {
  var aliases = sanctions.aliases;
  var expanded = aliases.expand("Bill Bill Bill");
  // Should not duplicate identical token-swap results
  var seen = Object.create(null);
  var dupCount = 0;
  for (var i = 0; i < expanded.length; i++) {
    var key = expanded[i].toLowerCase().replace(/[^a-z ]/g, " ").replace(/\s+/g, " ").trim();
    if (seen[key]) dupCount += 1;
    seen[key] = true;
  }
  check("aliases.expand: no duplicates", dupCount === 0);
}

function testAliasEmpty() {
  var aliases = sanctions.aliases;
  check("aliases.expand: empty string",  aliases.expand("").length === 0);
  check("aliases.expand: null",          aliases.expand(null).length === 0);
}

function testAliasExtraPairs() {
  var aliases = sanctions.aliases;
  // Operator-supplied extra pair
  var expanded = aliases.expand("Volodymyr Smith", {
    extraPairs: [["volodymyr", "vladimir"]],
  });
  var hasVladimir = expanded.some(function (s) {
    return s.toLowerCase().indexOf("vladimir") !== -1;
  });
  check("aliases.expand: extraPairs respected", hasVladimir);
}

function testAliasIntegrationWithScreen() {
  var screener = sanctions.create({
    entries: [{
      id:           "OFAC-9",
      primaryName:  "WILLIAM ALEXANDER SMITH",
      aliases:      [],
      type:         "individual",
      programs:     [],
      country:      null,
      listedAt:     null,
    }],
    algorithm: "ofac-sdn",
    fuzzy:     { strategy: "jaro-winkler", threshold: 0.85 },
  });
  // Direct screen with nickname won't match SDN's formal name well
  var direct = screener.screen({ name: "Bill Smith" });
  // Now expand aliases first
  var expanded = sanctions.aliases.expand("Bill Smith");
  var withAliases = screener.screen({
    name:    "Bill Smith",
    aliases: expanded,
  });
  // The expansion should improve match probability at least
  check("aliases integration: expansion considered",
        Array.isArray(expanded) && expanded.length > 1);
  // At minimum, the expanded form should generate a higher top-hit
  // score than the bare form (William matches WILLIAM exactly)
  if (withAliases.match && direct.match) {
    check("aliases integration: expanded score >= direct",
          withAliases.hits[0].score >= direct.hits[0].score);
  } else {
    check("aliases integration: expanded matches when direct doesn't",
          withAliases.match === true);
  }
}

// ---- Fetcher ----

async function testFetcherTickRefresh() {
  var screener = sanctions.create({
    entries: _sampleEntries(), algorithm: "ofac-sdn",
  });
  var refreshed = null;
  var fetchCalls = 0;
  var fetcher = sanctions.fetcher.create({
    screener:    screener,
    intervalMs:  60000,
    fetchOnStart: false,
    fetch:        async function () {
      fetchCalls += 1;
      // Return fresh entries with one added/one removed
      return [
        _sampleEntries()[0],
        _sampleEntries()[1],
        {
          id:           "OFAC-100",
          primaryName:  "FRESH ENTITY",
          aliases:      [],
          type:         "entity",
          programs:     [],
          country:      null,
          listedAt:     null,
        },
      ];
    },
    onRefreshed: function (diff) { refreshed = diff; },
  });
  await fetcher._tickOnce();
  check("fetcher: fetch called",      fetchCalls === 1);
  check("fetcher: onRefreshed fired", refreshed !== null);
  check("fetcher: diff has added",
        refreshed && refreshed.addedIds.length === 1 && refreshed.addedIds[0] === "OFAC-100");
  check("fetcher: diff has removed",
        refreshed.removedIds.length === 1 && refreshed.removedIds[0] === "OFAC-3");
  check("fetcher: stats updated",
        fetcher.stats().refreshCount === 1);
}

async function testFetcherFetchFailure() {
  var screener = sanctions.create({ entries: _sampleEntries(), algorithm: "ofac-sdn" });
  var errors = [];
  var fetcher = sanctions.fetcher.create({
    screener:    screener,
    intervalMs:  60000,
    fetchOnStart: false,
    fetch:        async function () { throw new Error("network failed"); },
    onError:      function (e) { errors.push(e.message); },
  });
  await fetcher._tickOnce();
  check("fetcher: fetch error captured",
        errors.length === 1 && errors[0] === "network failed");
  check("fetcher: stats failure count",
        fetcher.stats().failureCount === 1);
  check("fetcher: original screener still works",
        screener.size() === 3);
}

async function testFetcherEmptyResult() {
  var screener = sanctions.create({ entries: _sampleEntries(), algorithm: "ofac-sdn" });
  var refreshed = null;
  var fetcher = sanctions.fetcher.create({
    screener:    screener,
    intervalMs:  60000,
    fetchOnStart: false,
    fetch:        async function () { return []; },
    onRefreshed: function (d) { refreshed = d; },
  });
  await fetcher._tickOnce();
  check("fetcher: empty fetch skipped (no reload)",
        refreshed === null);
  check("fetcher: original screener still works",
        screener.size() === 3);
}

function testFetcherValidation() {
  var threwBadScreener = false;
  try {
    sanctions.fetcher.create({
      fetch: async function () {},
    });
  } catch (_e) { threwBadScreener = true; }
  check("fetcher.create: missing screener throws", threwBadScreener);

  var threwBadFetch = false;
  try {
    sanctions.fetcher.create({
      screener: sanctions.create({ entries: [], algorithm: "custom" }),
    });
  } catch (_e) { threwBadFetch = true; }
  check("fetcher.create: missing fetch throws", threwBadFetch);
}

// ---- Run all ----

(function run() {
  testNormalize();
  testTokenize();
  testLevenshtein();
  testJaro();
  testJaroWinkler();
  testTokenSetSimilarity();
  testSubstringContains();
  testInitialsMatch();
  testCreateAndScreenExact();
  testScreenJaroWinkler();
  testScreenLevenshtein();
  testScreenSubstringMatch();
  testScreenTypeFilter();
  testScreenCorrectAlgorithmEcho();
  testCreateValidation();
  testScreenInputValidation();
  testParseOfacCsvRow();
  testMergeAliases();
  testParseEuCslEntry();
  testParseUn1267Entry();
  testEntryById();
  testScreenBulk();
  testScreenBulkValidation();
  testSnapshot();
  testReload();
  testReloadValidation();
  testAliasExpand();
  testAliasInitials();
  testAliasReverseOrder();
  testAliasNoDuplicates();
  testAliasEmpty();
  testAliasExtraPairs();
  testAliasIntegrationWithScreen();
})();

// Fetcher tests are async; run them in their own block
(async function fetcherTests() {
  await testFetcherTickRefresh();
  await testFetcherFetchFailure();
  await testFetcherEmptyResult();
  testFetcherValidation();
})().catch(function (e) { console.error(e); process.exit(1); });
