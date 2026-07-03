// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Alias-expansion helpers for sanctions screening.
 *
 * The OFAC SDN list / EU CSL / UK HMT consolidated list publish a
 * primary name + a small set of formal aliases per entry. Real-world
 * input doesn't match those forms exactly: people use nicknames
 * (Bill / William, Mike / Michael), transliteration variants
 * (Mohamed / Mohammed / Muhammad), and initials (J. Smith).
 *
 * This module expands a candidate name into the set of plausible
 * forms that should screen-match against the same SDN entry. Operators
 * call expand() before screen() to broaden the match scope:
 *
 *   var aliases = b.compliance.sanctions.aliases.expand("Bill J. Smith");
 *   var result = screener.screen({
 *     name:    "Bill J. Smith",
 *     aliases: aliases,
 *   });
 *
 * The expansion is deterministic + idempotent. Operators with
 * domain-specific names (Cyrillic / Arabic) extend via opts.extra.
 */

var fuzzy = require("./compliance-sanctions-fuzzy");

// Common nickname → formal-name pairs. The framework ships a focused
// table for English/European names; operators with non-Western lists
// extend via opts.extraPairs at expand() time.
var NICKNAME_PAIRS = Object.freeze([
  ["bill",     "william"],
  ["bob",      "robert"],
  ["dick",     "richard"],
  ["mike",     "michael"],
  ["nick",     "nicholas"],
  ["tom",      "thomas"],
  ["jim",      "james"],
  ["jack",     "john"],
  ["chris",    "christopher"],
  ["dan",      "daniel"],
  ["dave",     "david"],
  ["matt",     "matthew"],
  ["alex",     "alexander"],
  ["sam",      "samuel"],
  ["pat",      "patrick"],
  ["tony",     "anthony"],
  ["ben",      "benjamin"],
  ["joe",      "joseph"],
  ["ed",       "edward"],
  ["fred",     "frederick"],
  ["greg",     "gregory"],
  ["liz",      "elizabeth"],
  ["beth",     "elizabeth"],
  ["meg",      "margaret"],
  ["maggie",   "margaret"],
  ["kate",     "katherine"],
  ["kathy",    "katherine"],
  ["sue",      "susan"],
  ["jen",      "jennifer"],
  ["jenny",    "jennifer"],
  ["nat",      "natalie"],
  ["mohamed",  "mohammed"],
  ["muhammad", "mohammed"],
  ["abd",      "abdul"],
  ["abu",      "abou"],
  ["yusuf",    "yousef"],
  ["yasin",    "yaseen"],
  ["hussein",  "hussain"],
]);

function _expandNickname(token) {
  var alts = [];
  var lower = token.toLowerCase();
  for (var i = 0; i < NICKNAME_PAIRS.length; i++) {
    var pair = NICKNAME_PAIRS[i];
    if (lower === pair[0]) alts.push(pair[1]);
    else if (lower === pair[1]) alts.push(pair[0]);
  }
  return alts;
}

function _expandInitials(tokens) {
  // Build "J. Smith" / "JS" forms
  var alts = [];
  if (tokens.length >= 2) {
    var first = tokens[0];
    var rest = tokens.slice(1).join(" ");
    if (first.length > 1) {
      // J Smith / J. Smith
      alts.push(first.charAt(0) + " " + rest);
      alts.push(first.charAt(0) + ". " + rest);
    }
    // Last + first
    alts.push(tokens[tokens.length - 1] + " " + tokens.slice(0, -1).join(" "));
    // Last, First
    alts.push(tokens[tokens.length - 1] + ", " + tokens.slice(0, -1).join(" "));
  }
  if (tokens.length === 2) {
    // Initials-only "JS"
    alts.push(tokens[0].charAt(0) + tokens[1].charAt(0));
  }
  return alts;
}

function _expandTokenLevel(tokens) {
  // For each token, swap with each plausible nickname/transliteration,
  // emit the resulting full name.
  var alts = [];
  for (var i = 0; i < tokens.length; i++) {
    var swaps = _expandNickname(tokens[i]);
    for (var j = 0; j < swaps.length; j++) {
      var newTokens = tokens.slice();
      newTokens[i] = swaps[j];
      alts.push(newTokens.join(" "));
    }
  }
  return alts;
}

function expand(name, opts) {
  opts = opts || {};
  if (typeof name !== "string" || name.length === 0) return [];
  var tokens = fuzzy.tokenize(name);
  if (tokens.length === 0) return [];
  var seen = Object.create(null);
  var out = [];
  function _add(s) {
    if (typeof s !== "string" || s.length === 0) return;
    var key = fuzzy.normalize(s);
    if (key.length === 0) return;
    if (seen[key]) return;
    seen[key] = true;
    out.push(s);
  }
  // 1. The original (normalised)
  _add(tokens.join(" "));
  // 2. Initial-form variants
  var initials = _expandInitials(tokens);
  for (var i = 0; i < initials.length; i++) _add(initials[i]);
  // 3. Token-level nickname/transliteration swaps
  var swaps = _expandTokenLevel(tokens);
  for (var j = 0; j < swaps.length; j++) _add(swaps[j]);
  // 4. Operator-supplied extras
  if (Array.isArray(opts.extra)) {
    for (var k = 0; k < opts.extra.length; k++) _add(opts.extra[k]);
  }
  if (Array.isArray(opts.extraPairs)) {
    for (var p = 0; p < opts.extraPairs.length; p++) {
      var pair = opts.extraPairs[p];
      if (!Array.isArray(pair) || pair.length !== 2) continue;
      for (var ti = 0; ti < tokens.length; ti++) {
        var lower = tokens[ti].toLowerCase();
        if (lower === pair[0]) {
          var nt1 = tokens.slice(); nt1[ti] = pair[1]; _add(nt1.join(" "));
        } else if (lower === pair[1]) {
          var nt2 = tokens.slice(); nt2[ti] = pair[0]; _add(nt2.join(" "));
        }
      }
    }
  }
  return out;
}

module.exports = {
  expand:          expand,
  NICKNAME_PAIRS:  NICKNAME_PAIRS,
};
