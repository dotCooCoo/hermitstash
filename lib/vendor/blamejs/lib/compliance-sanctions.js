// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
  "ofac-sdn",
  "eu-csl",
  "uk-hmt",
  "un-1267",
  "custom",
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

function parseOfacCsvRow(row) {
  if (!row || typeof row !== "object") return null;
  if (!row.SDN_Name || row.ent_num === undefined) return null;
  return {
    id:           "OFAC-" + String(row.ent_num),
    primaryName:  String(row.SDN_Name).trim(),
    aliases:      [],
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

function parseUn1267Entry(entry) {
  if (!entry || typeof entry !== "object") return null;
  var name = entry.NAME || entry.name || entry.FIRST_NAME || "";
  if (!name) return null;
  var entryAliases = [];
  if (Array.isArray(entry.ALIASES)) entryAliases = entry.ALIASES.slice();
  else if (typeof entry.ALIAS_NAMES === "string") {
    entryAliases = entry.ALIAS_NAMES.split(";").map(function (s) { return s.trim(); }).filter(Boolean);
  }
  return {
    id:          "UN-1267-" + String(entry.REFERENCE_NUMBER || entry.DATAID || ""),
    primaryName: String(name).trim(),
    aliases:     entryAliases,
    type:        entry.NAME_TYPE === "Entity" ? "entity" : "individual",
    programs:    ["UN-1267"],
    country:     entry.COUNTRY || entry.NATIONALITY || null,
    listedAt:    entry.LISTED_ON || null,
    remarks:     entry.COMMENTS || null,
    raw:         entry,
  };
}

function _normalizeEntry(e) {
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
    ? fuzzyOpts.maxLevenshtein : 3;
  var auditOn = opts.audit !== false;
  var ruleVersion = opts.ruleVersion || ("entries:" + opts.entries.length);

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
      var s2 = fuzzy.jaroWinkler(qNorm, name);
      if (s2 > bestScore) {
        bestScore = s2;
        bestName = name;
      }
      if (fuzzy.substringContains(name, qNorm)) {
        if (0.92 > bestScore) { bestScore = 0.92; bestName = name; }
      }
      if (fuzzy.substringContains(qNorm, name)) {
        if (0.92 > bestScore) { bestScore = 0.92; bestName = name; }
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

  function snapshot() {
    var nodeCrypto = require("node:crypto");
    var ids = index.map(function (e) { return e.id; }).sort();
    var hash = nodeCrypto.createHash("sha3-512");
    for (var i = 0; i < ids.length; i++) hash.update(ids[i]);
    return {
      algorithm:    algorithm,
      ruleVersion:  ruleVersion,
      entryCount:   index.length,
      digest:       hash.digest("hex").slice(0, 32),
      digestAlg:    "sha3-512-trunc128",
      capturedAt:   Date.now(),
    };
  }

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
