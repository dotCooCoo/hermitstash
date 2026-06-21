"use strict";
/**
 * b.compliance.sanctions — sanctions-list screening.
 *
 * Operators handling KYC / payment / customer-onboarding flows screen
 * names against the U.S. Treasury OFAC Specially Designated Nationals
 * list, the EU Consolidated Sanctions List (CSL), the UK HMT
 * consolidated list, the UN 1267 Al-Qaida/Taliban list, and adjacent
 * regulatory lists. The framework owns the indexing + match algorithm;
 * the operator owns the daily fetch + format-specific parsing.
 *
 *   var screener = b.compliance.sanctions.create({
 *     entries:    parsedSdnList,    // operator-supplied
 *     algorithm:  "ofac-sdn",       // | "eu-csl" | "uk-hmt" | "un-1267" |
 *                                    //   "custom"
 *     fuzzy: {
 *       enabled:   true,
 *       threshold: 0.85,            // Jaro-Winkler threshold; 0..1
 *       strategy:  "jaro-winkler",  // | "levenshtein" | "exact"
 *       maxLevenshtein: 3,          // max edit distance per "levenshtein"
 *     },
 *     audit:      true,
 *   });
 *
 *   var result = await screener.screen({
 *     name:        "John Smith",
 *     dateOfBirth: "1980-01-15",
 *     country:     "US",
 *     type:        "individual",    // | "entity" | "vessel" | "aircraft"
 *     aliases:     ["J Smith", "Jonny Smith"],
 *   });
 *   // → {
 *   //     match: true | false,
 *   //     hits:  [{ entryId, name, score, reason, listed, programs }],
 *   //     screenedAt, algorithm, ruleVersion,
 *   //   }
 *
 * Entry shape (operator parses raw list into this canonical shape):
 *   {
 *     id:           "OFAC-12345",
 *     primaryName:  "JOHN SMITH",
 *     aliases:      ["J SMITH", "JONNY SMITH"],
 *     type:         "individual" | "entity" | "vessel" | "aircraft",
 *     programs:     ["SDGT", "RUSSIA-EO13662"],   // sanction programs
 *     listedAt:     "2024-03-15",
 *     country:      "RU",
 *     dateOfBirth:  ["1980-01-15"],               // optional disambiguator
 *     remarks:      "...",
 *     // operator-side fields preserved verbatim:
 *     raw:          <any>,
 *   }
 *
 * Audit emissions (audit namespace `compliance`):
 *   compliance.sanctions.screened   — every screen() call (match or no-match)
 *   compliance.sanctions.matched    — every screen() with at least one hit
 *
 * The framework does NOT vendor the list itself: list contents change
 * daily and have legal-distribution implications. Operators fetch from
 * the source (treasury.gov for OFAC, sanctionsmap.eu for EU CSL,
 * gov.uk for HMT, scsanctions.un.org for UN 1267) on a daily schedule
 * and pass the parsed array.
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var fuzzy = require("./compliance-sanctions-fuzzy");
var aliases = require("./compliance-sanctions-aliases");
var fetcher = require("./compliance-sanctions-fetcher");
var { defineClass } = require("./framework-error");

var SanctionsError = defineClass("SanctionsError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var VALID_ALGORITHMS = Object.freeze([
  "ofac-sdn",   // U.S. Treasury Specially Designated Nationals
  "eu-csl",     // EU Consolidated Sanctions List
  "uk-hmt",     // UK HM Treasury consolidated
  "un-1267",    // UN Security Council 1267/1989/2253
  "custom",     // operator-defined list
]);

var VALID_STRATEGIES = Object.freeze([
  "jaro-winkler",
  "levenshtein",
  "exact",
]);

var VALID_TYPES = Object.freeze([
  "individual",
  "entity",
  "vessel",
  "aircraft",
]);

// ---- Parser shims ----
//
// Operators feed pre-parsed entries to create(); the framework also
// ships parser shims for the common public formats. Parsers run on
// the operator side (network fetch + format conversion) and return
// the canonical entry shape. The framework's parsers are minimal:
// just enough to extract id + primaryName + aliases + programs from
// the canonical XML/JSON shape that each sanctions authority ships.

// OFAC SDN — the Treasury distributes XML and CSV; we accept the
// parsed CSV-row shape (operator runs b.parsers.safeCsv). Each row:
//   { ent_num, SDN_Name, SDN_Type, Program, Title, Call_Sign, ... }
function parseOfacCsvRow(row) {
  if (!row || typeof row !== "object") return null;
  if (!row.SDN_Name || row.ent_num === undefined) return null;
  return {
    id:           "OFAC-" + String(row.ent_num),
    primaryName:  String(row.SDN_Name).trim(),
    aliases:      [],     // OFAC distributes aliases in a separate alt-names file
    type:         _ofacTypeToCanonical(row.SDN_Type),
    programs:     row.Program ? String(row.Program).split(";").map(function (s) { return s.trim(); }).filter(Boolean) : [],
    country:      row.Country ? String(row.Country).trim() : null,
    listedAt:     row.Publish_Date ? String(row.Publish_Date) : null,
    remarks:      row.Remarks ? String(row.Remarks) : null,
    raw:          row,
  };
}

function _ofacTypeToCanonical(t) {
  switch (String(t || "").toLowerCase()) {
    case "individual": return "individual";
    case "entity":     return "entity";
    case "vessel":     return "vessel";
    case "aircraft":   return "aircraft";
    default:           return "entity";
  }
}

// OFAC alias rows from the alt-names file:
//   { ent_num, alt_num, alt_type, alt_name, alt_remarks }
// merged into the primary entry by operator code via mergeAliases().
function parseOfacAliasRow(row) {
  if (!row || typeof row !== "object") return null;
  if (row.ent_num === undefined || !row.alt_name) return null;
  return {
    entId:    "OFAC-" + String(row.ent_num),
    altType:  String(row.alt_type || "aka"),
    altName:  String(row.alt_name).trim(),
    remarks:  row.alt_remarks ? String(row.alt_remarks) : null,
  };
}

function mergeAliases(entries, aliasRows) {
  if (!Array.isArray(entries)) return [];
  if (!Array.isArray(aliasRows)) return entries;
  var byId = Object.create(null);
  for (var i = 0; i < entries.length; i++) byId[entries[i].id] = entries[i];
  for (var j = 0; j < aliasRows.length; j++) {
    var alias = aliasRows[j];
    var entry = byId[alias.entId];
    if (entry) entry.aliases.push(alias.altName);
  }
  return entries;
}

// EU CSL — the EU distributes XML; operator parses with b.parsers.safeXml
// and feeds the per-entity dict (subjectType, nameAlias, regulation, etc.)
function parseEuCslEntry(entity) {
  if (!entity || typeof entity !== "object") return null;
  var nameAliases = entity.nameAlias || entity.NAMEALIAS || [];
  if (!Array.isArray(nameAliases)) nameAliases = [nameAliases];
  if (nameAliases.length === 0) return null;
  var primary = nameAliases[0];
  return {
    id:          "EU-CSL-" + String(entity.logicalId || entity.LOGICALID || ""),
    primaryName: String(primary.wholeName || primary.WHOLENAME || "").trim(),
    aliases:     nameAliases.slice(1).map(function (a) {
      return String(a.wholeName || a.WHOLENAME || "").trim();
    }).filter(Boolean),
    type:        _euTypeToCanonical(entity.subjectType || entity.SUBJECTTYPE),
    programs:    entity.regulation ? [String(entity.regulation)] : [],
    country:     entity.country || null,
    listedAt:    entity.designationDate || null,
    remarks:     entity.remark || null,
    raw:         entity,
  };
}

function _euTypeToCanonical(t) {
  switch (String(t || "").toLowerCase()) {
    case "person":   return "individual";
    case "enterprise": return "entity";
    case "vessel":   return "vessel";
    case "aircraft": return "aircraft";
    default:         return "entity";
  }
}

// UN 1267 list — XML-based, similar to EU shape but different field
// names. Operators parse the XML root then feed individual entries.
function parseUn1267Entry(entry) {
  if (!entry || typeof entry !== "object") return null;
  var name = entry.NAME || entry.name || entry.FIRST_NAME || "";
  if (!name) return null;
  var aliases = [];
  if (Array.isArray(entry.ALIASES)) aliases = entry.ALIASES.slice();
  else if (typeof entry.ALIAS_NAMES === "string") {
    aliases = entry.ALIAS_NAMES.split(";").map(function (s) { return s.trim(); }).filter(Boolean);
  }
  return {
    id:          "UN-1267-" + String(entry.REFERENCE_NUMBER || entry.DATAID || ""),
    primaryName: String(name).trim(),
    aliases:     aliases,
    type:        entry.NAME_TYPE === "Entity" ? "entity" : "individual",
    programs:    ["UN-1267"],
    country:     entry.COUNTRY || entry.NATIONALITY || null,
    listedAt:    entry.LISTED_ON || null,
    remarks:     entry.COMMENTS || null,
    raw:         entry,
  };
}

// ---- Index + screen ----

function _normalizeEntry(e) {
  // Defensive copy + normalise primaryName/aliases for fast match.
  var norm = {
    id:           e.id,
    primaryName:  e.primaryName || "",
    aliases:      Array.isArray(e.aliases) ? e.aliases.slice() : [],
    type:         e.type || "entity",
    programs:     Array.isArray(e.programs) ? e.programs.slice() : [],
    country:      e.country || null,
    listedAt:     e.listedAt || null,
    dateOfBirth:  Array.isArray(e.dateOfBirth) ? e.dateOfBirth.slice() : (e.dateOfBirth ? [e.dateOfBirth] : []),
    remarks:      e.remarks || null,
    raw:          e.raw || null,
  };
  // Pre-tokenize for the matcher
  norm._allNamesNormalized = [norm.primaryName].concat(norm.aliases)
    .map(fuzzy.normalize)
    .filter(function (s) { return s.length > 0; });
  return norm;
}

function create(opts) {
  validateOpts.requireObject(opts, "compliance.sanctions", SanctionsError);
  validateOpts(opts, [
    "entries", "algorithm", "fuzzy", "audit", "ruleVersion",
  ], "compliance.sanctions.create");

  if (!Array.isArray(opts.entries)) {
    throw new SanctionsError("sanctions/no-entries",
      "compliance.sanctions.create: entries must be an array");
  }
  var algorithm = opts.algorithm || "custom";
  if (VALID_ALGORITHMS.indexOf(algorithm) === -1) {
    throw new SanctionsError("sanctions/bad-algorithm",
      "compliance.sanctions.create: algorithm must be one of " +
      VALID_ALGORITHMS.join(", "));
  }
  var fuzzyOpts = opts.fuzzy || {};
  if (typeof fuzzyOpts !== "object" || Array.isArray(fuzzyOpts)) {
    throw new SanctionsError("sanctions/bad-fuzzy",
      "compliance.sanctions.create: fuzzy must be an object");
  }
  var fuzzyEnabled = fuzzyOpts.enabled !== false;
  var fuzzyThreshold = (typeof fuzzyOpts.threshold === "number" && isFinite(fuzzyOpts.threshold))
    ? fuzzyOpts.threshold : 0.85;
  if (fuzzyThreshold < 0 || fuzzyThreshold > 1) {
    throw new SanctionsError("sanctions/bad-threshold",
      "compliance.sanctions.create: fuzzy.threshold must be in [0, 1]");
  }
  var fuzzyStrategy = fuzzyOpts.strategy || "jaro-winkler";
  if (VALID_STRATEGIES.indexOf(fuzzyStrategy) === -1) {
    throw new SanctionsError("sanctions/bad-strategy",
      "compliance.sanctions.create: fuzzy.strategy must be one of " +
      VALID_STRATEGIES.join(", "));
  }
  var maxLevenshtein = (typeof fuzzyOpts.maxLevenshtein === "number" && isFinite(fuzzyOpts.maxLevenshtein))
    ? fuzzyOpts.maxLevenshtein : 3;                                                // default edit-distance cap (operator-tunable)
  var auditOn = opts.audit !== false;
  var ruleVersion = opts.ruleVersion || ("entries:" + opts.entries.length);

  // Index — normalize all entries up front (O(N*M) once) so screen()
  // is O(N*K) where K is the number of names+aliases per entry. For a
  // 30k-entry list with ~3 aliases each, the index uses ~90k normalized
  // strings.
  var index = opts.entries.map(_normalizeEntry);

  var _emitAudit = audit().namespaced(null, { audit: auditOn });

  var _emitMetric = observability().namespaced("compliance.sanctions");

  function _exactMatch(qNorm, candidate) {
    for (var i = 0; i < candidate._allNamesNormalized.length; i++) {
      if (candidate._allNamesNormalized[i] === qNorm) return 1.0;
    }
    return 0;
  }

  function _jaroWinklerMatch(qNorm, candidate) {
    var bestScore = 0;
    var bestName = "";
    for (var i = 0; i < candidate._allNamesNormalized.length; i++) {
      var name = candidate._allNamesNormalized[i];
      var s = fuzzy.tokenSetSimilarity(qNorm, name, {
        threshold: fuzzyThreshold,
      });
      if (s > bestScore) {
        bestScore = s;
        bestName = name;
      }
      // Also try direct Jaro-Winkler on the whole strings
      var s2 = fuzzy.jaroWinkler(qNorm, name);
      if (s2 > bestScore) {
        bestScore = s2;
        bestName = name;
      }
      // Substring containment scores 0.92 (high but below exact)
      if (fuzzy.substringContains(name, qNorm)) {
        if (0.92 > bestScore) { bestScore = 0.92; bestName = name; }                // substring-match score weight
      }
      if (fuzzy.substringContains(qNorm, name)) {
        if (0.92 > bestScore) { bestScore = 0.92; bestName = name; }                // substring-match score weight
      }
    }
    return { score: bestScore, name: bestName };
  }

  function _levenshteinMatch(qNorm, candidate) {
    var bestScore = 0;
    var bestName = "";
    for (var i = 0; i < candidate._allNamesNormalized.length; i++) {
      var name = candidate._allNamesNormalized[i];
      var dist = fuzzy.levenshtein(qNorm, name, maxLevenshtein);
      if (dist > maxLevenshtein) continue;
      // Distance → score: distance 0 → 1.0; distance maxLev → 0.0.
      var maxLen = Math.max(qNorm.length, name.length);
      if (maxLen === 0) continue;
      var score = Math.max(0, 1 - dist / maxLen);
      if (score > bestScore) { bestScore = score; bestName = name; }
    }
    return { score: bestScore, name: bestName };
  }

  function screen(input) {
    if (!input || typeof input !== "object") {
      throw new SanctionsError("sanctions/bad-input",
        "screen: input must be an object");
    }
    if (typeof input.name !== "string" || input.name.length === 0) {
      throw new SanctionsError("sanctions/no-name",
        "screen: input.name is required");
    }
    if (input.name.length > fuzzy.MAX_INPUT_LEN) {
      throw new SanctionsError("sanctions/name-too-long",
        "screen: input.name exceeds " + fuzzy.MAX_INPUT_LEN + " char cap");
    }
    if (input.type !== undefined && VALID_TYPES.indexOf(input.type) === -1) {
      throw new SanctionsError("sanctions/bad-type",
        "screen: input.type must be one of " + VALID_TYPES.join(", "));
    }
    var queryName = fuzzy.normalize(input.name);
    var queryAliases = Array.isArray(input.aliases)
      ? input.aliases.map(fuzzy.normalize).filter(function (s) { return s.length > 0; })
      : [];
    var queryNames = [queryName].concat(queryAliases);

    var hits = [];
    var screenedAt = Date.now();

    for (var c = 0; c < index.length; c++) {
      var candidate = index[c];
      // A sanctions screen MUST over-match on the legally-operative NAME. The
      // operator-asserted input.type is an unverified counterparty
      // self-classification, NOT data-driven non-match confidence — using it to
      // EXCLUDE a name hit inverts the screen to under-match (a false negative
      // that processes a payment which should have been blocked). So never skip
      // a candidate on type; the name match runs against every record and the
      // type mismatch is surfaced as a non-dispositive `typeMatch` signal on
      // each hit for operator triage.

      var bestForCandidate = { score: 0, name: "" };
      for (var qi = 0; qi < queryNames.length; qi++) {
        var qn = queryNames[qi];
        var match;
        if (!fuzzyEnabled || fuzzyStrategy === "exact") {
          var exact = _exactMatch(qn, candidate);
          match = { score: exact, name: candidate.primaryName };
        } else if (fuzzyStrategy === "jaro-winkler") {
          match = _jaroWinklerMatch(qn, candidate);
        } else {
          match = _levenshteinMatch(qn, candidate);
        }
        if (match.score > bestForCandidate.score) {
          bestForCandidate = match;
        }
      }
      if (bestForCandidate.score >= fuzzyThreshold) {
        hits.push({
          entryId:   candidate.id,
          name:      candidate.primaryName,
          matchedOn: bestForCandidate.name,
          score:     bestForCandidate.score,
          reason:    bestForCandidate.score >= 0.99 ? "exact-or-near-exact" :
                     bestForCandidate.score >= 0.92 ? "substring-or-token-match" :
                     "fuzzy",
          listed:    candidate.listedAt,
          programs:  candidate.programs,
          type:      candidate.type,
          typeMatch: input.type ? candidate.type === input.type : null,
          country:   candidate.country,
        });
      }
    }
    // Sort hits by descending score
    hits.sort(function (a, b) { return b.score - a.score; });

    var matched = hits.length > 0;
    var result = {
      match:        matched,
      hits:         hits,
      query:        { name: input.name, type: input.type || null,
                      country: input.country || null,
                      dateOfBirth: input.dateOfBirth || null },
      screenedAt:   screenedAt,
      algorithm:    algorithm,
      ruleVersion:  ruleVersion,
      strategy:     fuzzyEnabled ? fuzzyStrategy : "exact",
      threshold:    fuzzyThreshold,
    };
    _emitAudit("compliance.sanctions.screened", "success", {
      algorithm: algorithm, matched: matched,
      hits: hits.length, ruleVersion: ruleVersion,
    });
    if (matched) {
      _emitAudit("compliance.sanctions.matched", "success", {
        algorithm: algorithm, hits: hits.length,
        topScore: hits[0].score, topProgram: hits[0].programs && hits[0].programs[0],
      });
      _emitMetric("matched", 1, { algorithm: algorithm });
    }
    _emitMetric("screened", 1, { algorithm: algorithm });
    return result;
  }

  function size() { return index.length; }
  function entryById(id) {
    for (var i = 0; i < index.length; i++) {
      if (index[i].id === id) return index[i];
    }
    return null;
  }

  // screenBulk — convenience wrapper that screens an array of inputs
  // and returns the per-input result array. Operators screening a
  // batch of records (KYC list import, periodic re-screen of existing
  // customers) call this once instead of looping; the wrapper still
  // emits one audit event per input so the audit chain stays per-row.
  function screenBulk(inputs) {
    if (!Array.isArray(inputs)) {
      throw new SanctionsError("sanctions/bad-bulk",
        "screenBulk: inputs must be an array");
    }
    var out = [];
    for (var i = 0; i < inputs.length; i++) {
      out.push(screen(inputs[i]));
    }
    return out;
  }

  // snapshot — returns a content-derived hash + count of the active
  // rule index, useful for compliance audit trails ("we screened
  // ticket X against rule snapshot SHA-3 abcd..."). The snapshot is a
  // truncated SHA-3-512 of the sorted entry ids; collisions are
  // ignorable for the audit-trail use case (operators store the
  // ruleVersion + entry count alongside).
  function snapshot() {
    var nodeCrypto = require("node:crypto");
    var ids = index.map(function (e) { return e.id; }).sort();
    var hash = nodeCrypto.createHash("sha3-512");
    for (var i = 0; i < ids.length; i++) hash.update(ids[i]);
    return {
      algorithm:    algorithm,
      ruleVersion:  ruleVersion,
      entryCount:   index.length,
      digest:       hash.digest("hex").slice(0, 32),                                // first 32 hex chars (128 bits) of SHA-3 digest, sufficient for snapshot identity
      digestAlg:    "sha3-512-trunc128",
      capturedAt:   Date.now(),
    };
  }

  // reload — atomically swap the index to a fresh entry list. Returns
  // a diff describing how the index changed (added / removed). The
  // operator's daily-fetch worker uses this; the swap is atomic from
  // the caller's perspective (screen() always sees the old or new
  // index, never a partial state).
  function reload(newEntries) {
    if (!Array.isArray(newEntries)) {
      throw new SanctionsError("sanctions/bad-reload",
        "reload: newEntries must be an array");
    }
    var oldIds = Object.create(null);
    for (var i = 0; i < index.length; i++) oldIds[index[i].id] = true;
    var newIndex = newEntries.map(_normalizeEntry);
    var newIds = Object.create(null);
    for (var j = 0; j < newIndex.length; j++) newIds[newIndex[j].id] = true;
    var added = [];
    var removed = [];
    for (var k = 0; k < newIndex.length; k++) {
      if (!oldIds[newIndex[k].id]) added.push(newIndex[k].id);
    }
    for (var l = 0; l < index.length; l++) {
      if (!newIds[index[l].id]) removed.push(index[l].id);
    }
    // Atomic swap (single reference assignment)
    index = newIndex;
    ruleVersion = "entries:" + index.length + ";reloadedAt:" + Date.now();
    _emitAudit("compliance.sanctions.reloaded", "success", {
      added: added.length, removed: removed.length,
      newSize: index.length, ruleVersion: ruleVersion,
    });
    _emitMetric("reloaded", 1, { algorithm: algorithm });
    return {
      addedIds:    added,
      removedIds:  removed,
      newSize:     index.length,
      ruleVersion: ruleVersion,
    };
  }

  return {
    screen:        screen,
    screenBulk:    screenBulk,
    snapshot:      snapshot,
    reload:        reload,
    size:          size,
    entryById:     entryById,
    algorithm:     algorithm,
    ruleVersion:   ruleVersion,
    threshold:     fuzzyThreshold,
    strategy:      fuzzyEnabled ? fuzzyStrategy : "exact",
    // Exposed for tests + advanced operator workflows
    _index:        index,
  };
}

module.exports = {
  create:              create,
  parseOfacCsvRow:     parseOfacCsvRow,
  parseOfacAliasRow:   parseOfacAliasRow,
  mergeAliases:        mergeAliases,
  parseEuCslEntry:     parseEuCslEntry,
  parseUn1267Entry:    parseUn1267Entry,
  fuzzy:               fuzzy,
  aliases:             aliases,
  fetcher:             fetcher,
  VALID_ALGORITHMS:    VALID_ALGORITHMS,
  VALID_STRATEGIES:    VALID_STRATEGIES,
  VALID_TYPES:         VALID_TYPES,
  SanctionsError:      SanctionsError,
};
