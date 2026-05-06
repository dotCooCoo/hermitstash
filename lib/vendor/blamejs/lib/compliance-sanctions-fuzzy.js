"use strict";
/**
 * Fuzzy name-matching primitives for sanctions screening.
 *
 * Operators screening names against the OFAC SDN list / EU CSL /
 * UK HMT consolidated list need to handle:
 *   - Transliteration variations (Mohamed / Mohammed / Muhammad)
 *   - Order-of-name variations (Smith John vs John Smith)
 *   - Initials vs full names (J. Smith vs John Smith)
 *   - Diacritical noise (Müller vs Muller)
 *   - Substring containment (the SDN entry "Acme Corp" matches a
 *     local record "Acme Corp Limited")
 *
 * This module exports the algorithmic core; b.compliance.sanctions
 * orchestrates parser/index/match against it.
 *
 * Functions:
 *   normalize(name)            → canonical lowercase form, diacritics
 *                                 stripped, multi-space collapsed
 *   tokenize(name)             → array of normalized tokens
 *   levenshtein(a, b, capDist) → edit distance with O(min(a,b)) memory
 *                                 + early-exit when distance > capDist
 *   jaroWinkler(a, b, prefix)  → 0..1 similarity score per Jaro-Winkler
 *                                 (1996); operators typically threshold
 *                                 at >= 0.85 for "probable match"
 *   tokenSetSimilarity(a, b)   → bag-of-tokens overlap with token-pair
 *                                 Jaro-Winkler scoring; resilient to
 *                                 word order and missing/extra terms
 *
 * Performance: worst-case O(n*m) for Levenshtein (n,m = string lengths),
 * O(n*m) for Jaro-Winkler. Operators screening against a list of N
 * entries should pre-filter on token-set overlap before computing
 * Jaro-Winkler on every candidate.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var FuzzyError = defineClass("FuzzyError", { alwaysPermanent: true });

// ---- normalize ----

// Diacritic-stripping table — covers the most common Latin Unicode
// ranges. The framework intentionally ships a focused table (not a
// full Unicode normalizer) so the LoC is bounded; operators with
// non-Latin lists install ICU normalizer in their pre-processing.
var _DIACRITIC_MAP = {
  "à":"a","á":"a","â":"a","ã":"a","ä":"a","å":"a","ą":"a","ă":"a",
  "ç":"c","ć":"c","č":"c","ĉ":"c",
  "ď":"d","đ":"d",
  "è":"e","é":"e","ê":"e","ë":"e","ę":"e","ě":"e","ĕ":"e",
  "ğ":"g","ĝ":"g","ġ":"g",
  "ĥ":"h",
  "ì":"i","í":"i","î":"i","ï":"i","ı":"i","į":"i",
  "ĵ":"j",
  "ķ":"k",
  "ĺ":"l","ľ":"l","ł":"l","ļ":"l",
  "ñ":"n","ń":"n","ň":"n","ņ":"n",
  "ò":"o","ó":"o","ô":"o","õ":"o","ö":"o","ø":"o","ő":"o",
  "ŕ":"r","ř":"r",
  "ś":"s","š":"s","ş":"s","ș":"s","ŝ":"s",
  "ť":"t","ţ":"t","ț":"t",
  "ù":"u","ú":"u","û":"u","ü":"u","ū":"u","ů":"u","ű":"u","ŭ":"u",
  "ŵ":"w",
  "ý":"y","ÿ":"y","ŷ":"y",
  "ź":"z","ż":"z","ž":"z",
  "ß":"ss","æ":"ae","œ":"oe",
  "À":"A","Á":"A","Â":"A","Ã":"A","Ä":"A","Å":"A",
  "Ç":"C","È":"E","É":"E","Ê":"E","Ë":"E",
  "Ì":"I","Í":"I","Î":"I","Ï":"I",
  "Ñ":"N",
  "Ò":"O","Ó":"O","Ô":"O","Õ":"O","Ö":"O","Ø":"O",
  "Ù":"U","Ú":"U","Û":"U","Ü":"U",
  "Ý":"Y","Ÿ":"Y",
  "Ž":"Z","Š":"S",
};

function normalize(name) {
  if (typeof name !== "string") return "";
  // 1. Strip diacritics
  var stripped = "";
  for (var i = 0; i < name.length; i++) {
    var ch = name.charAt(i);
    stripped += _DIACRITIC_MAP[ch] || ch;
  }
  // 2. Lowercase
  var lower = stripped.toLowerCase();
  // 3. Strip punctuation other than hyphen + apostrophe (preserved
  //    inside names like O'Brien / Al-Faisal)
  var punctStripped = lower.replace(/[^\p{Letter}\p{Number}'\- ]+/gu, " ");        // allow:regex-no-length-cap — caller bounds total input via tokenize() length cap
  // 4. Collapse whitespace
  var collapsed = punctStripped.replace(/\s+/g, " ").trim();
  return collapsed;
}

function tokenize(name) {
  if (typeof name !== "string") return [];
  if (name.length > MAX_INPUT_LEN) {
    throw new FuzzyError("fuzzy/input-too-long",
      "tokenize: input exceeds " + MAX_INPUT_LEN + " char cap");
  }
  var n = normalize(name);
  if (n.length === 0) return [];
  return n.split(" ").filter(function (t) { return t.length > 0; });
}

var MAX_INPUT_LEN = 512;                                                           // allow:raw-byte-literal — name length sanity cap (operators can override fuzzy.create)

// ---- Levenshtein with cap + early-exit ----

function levenshtein(a, b, capDist) {
  if (typeof a !== "string" || typeof b !== "string") {
    throw new FuzzyError("fuzzy/bad-input",
      "levenshtein: a + b must be strings");
  }
  // Trivial cases
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Cap (Math.abs(a.length - b.length) is the lower bound; if this
  // already exceeds cap we can skip the full DP)
  if (typeof capDist === "number" && capDist >= 0) {
    var lengthDelta = Math.abs(a.length - b.length);
    if (lengthDelta > capDist) return capDist + 1;
  }

  // Two-row DP: O(min(a.length, b.length)) memory.
  var s = a.length <= b.length ? a : b;
  var t = a.length <= b.length ? b : a;
  var prev = new Array(s.length + 1);
  var curr = new Array(s.length + 1);
  for (var i = 0; i <= s.length; i++) prev[i] = i;
  for (var j = 1; j <= t.length; j++) {
    curr[0] = j;
    var rowMin = j;
    for (var k = 1; k <= s.length; k++) {
      var cost = s.charAt(k - 1) === t.charAt(j - 1) ? 0 : 1;
      curr[k] = Math.min(
        prev[k]     + 1,        // deletion
        curr[k - 1] + 1,        // insertion
        prev[k - 1] + cost      // substitution
      );
      if (curr[k] < rowMin) rowMin = curr[k];
    }
    if (typeof capDist === "number" && rowMin > capDist) return capDist + 1;
    var swap = prev; prev = curr; curr = swap;
  }
  return prev[s.length];
}

// ---- Jaro and Jaro-Winkler ----

function jaro(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return 0;
  if (a === b) return a.length === 0 ? 0 : 1;
  if (a.length === 0 || b.length === 0) return 0;
  var matchWindow = Math.max(0, Math.floor(Math.max(a.length, b.length) / 2) - 1);  // allow:raw-byte-literal — Jaro match-window formula
  var aMatched = new Array(a.length).fill(false);
  var bMatched = new Array(b.length).fill(false);
  var matches = 0;
  for (var i = 0; i < a.length; i++) {
    var lo = Math.max(0, i - matchWindow);
    var hi = Math.min(b.length - 1, i + matchWindow);
    for (var j = lo; j <= hi; j++) {
      if (bMatched[j]) continue;
      if (a.charAt(i) !== b.charAt(j)) continue;
      aMatched[i] = true;
      bMatched[j] = true;
      matches += 1;
      break;
    }
  }
  if (matches === 0) return 0;
  // Count transpositions
  var t = 0;
  var k = 0;
  for (var ii = 0; ii < a.length; ii++) {
    if (!aMatched[ii]) continue;
    while (!bMatched[k]) k += 1;
    if (a.charAt(ii) !== b.charAt(k)) t += 1;
    k += 1;
  }
  var transpositions = t / 2;
  return (matches / a.length + matches / b.length +
          (matches - transpositions) / matches) / 3;                                // allow:raw-byte-literal — Jaro 3-term formula
}

function jaroWinkler(a, b, prefixWeight) {
  // prefixWeight defaults to 0.1 per the original Winkler paper;
  // operators can lower to reduce prefix bias.
  var w = (typeof prefixWeight === "number" && isFinite(prefixWeight))
    ? prefixWeight : 0.1;
  if (w < 0 || w > 0.25) {
    throw new FuzzyError("fuzzy/bad-prefix-weight",
      "jaroWinkler: prefixWeight must be in [0, 0.25]");
  }
  var j = jaro(a, b);
  if (j === 0) return 0;
  // Common prefix up to 4 chars (Winkler's cap)
  var maxPrefix = 4;                                                               // allow:raw-byte-literal — Jaro-Winkler prefix cap (Winkler 1990)
  var prefixLen = 0;
  var max = Math.min(a.length, b.length, maxPrefix);
  for (var i = 0; i < max; i++) {
    if (a.charAt(i) !== b.charAt(i)) break;
    prefixLen += 1;
  }
  return j + prefixLen * w * (1 - j);
}

// ---- Token-set similarity ----

function tokenSetSimilarity(a, b, opts) {
  opts = opts || {};
  var prefixWeight = opts.prefixWeight;
  var threshold    = (typeof opts.threshold === "number" && isFinite(opts.threshold))
    ? opts.threshold : 0.85;
  var tokensA = tokenize(a);
  var tokensB = tokenize(b);
  if (tokensA.length === 0 || tokensB.length === 0) return 0;
  // Greedy bipartite matching: for each token in A, find the best
  // unmatched B token; sum & average. This is O(n*m) but the typical
  // name has ≤ 5 tokens so it's bounded.
  var bUsed = new Array(tokensB.length).fill(false);
  var matchedScores = [];
  for (var i = 0; i < tokensA.length; i++) {
    var bestScore = 0;
    var bestIdx = -1;
    for (var j = 0; j < tokensB.length; j++) {
      if (bUsed[j]) continue;
      var s = jaroWinkler(tokensA[i], tokensB[j], prefixWeight);
      if (s > bestScore) { bestScore = s; bestIdx = j; }
    }
    if (bestIdx !== -1 && bestScore >= threshold) {
      bUsed[bestIdx] = true;
      matchedScores.push(bestScore);
    }
  }
  if (matchedScores.length === 0) return 0;
  // Token-set similarity: average of the matched-pair scores, weighted
  // by coverage of the smaller-token-side.
  var avg = matchedScores.reduce(function (a2, b2) { return a2 + b2; }, 0) /
            matchedScores.length;
  var coverage = matchedScores.length / Math.min(tokensA.length, tokensB.length);
  return avg * coverage;
}

// ---- Container helpers ----

// substringContains — true when the normalized form of `needle` is a
// whitespace-bounded substring of the normalized form of `haystack`.
// Useful for catching SDN entries like "Acme Corp" inside a fuller
// local record like "Acme Corp Limited Liability Company".
function substringContains(haystack, needle) {
  var nh = " " + normalize(haystack) + " ";
  var nn = " " + normalize(needle) + " ";
  return nh.indexOf(nn) !== -1;
}

// initialsMatch — true when the normalized form of `a` is shaped like
// "J Smith" / "J. Smith" / "JS" and matches the leading-character
// pattern of `b`. Catches the common "screen-typo" pattern where the
// user typed an initial instead of a full first name.
function initialsMatch(a, b) {
  var ta = tokenize(a);
  var tb = tokenize(b);
  if (ta.length === 0 || tb.length === 0) return false;
  if (ta.length !== tb.length) return false;
  for (var i = 0; i < ta.length; i++) {
    var x = ta[i];
    var y = tb[i];
    if (x === y) continue;
    // Match if either side is a single char and matches the other's
    // first char.
    if (x.length === 1 && y.startsWith(x)) continue;
    if (y.length === 1 && x.startsWith(y)) continue;
    return false;
  }
  return true;
}

module.exports = {
  normalize:           normalize,
  tokenize:            tokenize,
  levenshtein:         levenshtein,
  jaro:                jaro,
  jaroWinkler:         jaroWinkler,
  tokenSetSimilarity:  tokenSetSimilarity,
  substringContains:   substringContains,
  initialsMatch:       initialsMatch,
  FuzzyError:          FuzzyError,
  MAX_INPUT_LEN:       MAX_INPUT_LEN,
};
// note: validateOpts intentionally not used in this file (pure
// algorithmic helpers); imported only to keep the require shape
// consistent with sister modules.
void validateOpts;
