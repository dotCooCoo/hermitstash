// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var fuzzy = require("./compliance-sanctions-fuzzy");

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
  var alts = [];
  if (tokens.length >= 2) {
    var first = tokens[0];
    var rest = tokens.slice(1).join(" ");
    if (first.length > 1) {
      alts.push(first.charAt(0) + " " + rest);
      alts.push(first.charAt(0) + ". " + rest);
    }
    alts.push(tokens[tokens.length - 1] + " " + tokens.slice(0, -1).join(" "));
    alts.push(tokens[tokens.length - 1] + ", " + tokens.slice(0, -1).join(" "));
  }
  if (tokens.length === 2) {
    alts.push(tokens[0].charAt(0) + tokens[1].charAt(0));
  }
  return alts;
}

function _expandTokenLevel(tokens) {
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
  _add(tokens.join(" "));
  var initials = _expandInitials(tokens);
  for (var i = 0; i < initials.length; i++) _add(initials[i]);
  var swaps = _expandTokenLevel(tokens);
  for (var j = 0; j < swaps.length; j++) _add(swaps[j]);
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
