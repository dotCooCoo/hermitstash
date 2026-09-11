// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var lazyRequire = require("./lazy-require");
var boundedMap = require("./bounded-map");
var safeObject = require("./safe-object");
var { defineClass } = require("./framework-error");

var I18nMessageFormatError = defineClass("I18nMessageFormatError",
  { alwaysPermanent: true });

function _err(code, message) {
  return new I18nMessageFormatError(code, message, true);
}

var MAX_NESTING_DEPTH = 100;

function parse(template) {
  if (typeof template !== "string") {
    throw _err("i18n-messageformat/bad-template",
      "messageFormat.parse: template must be a string, got " + typeof template);
  }
  var state = { src: template, pos: 0 };
  var nodes = _parseSequence(state,  true);
  if (state.pos < state.src.length) {
    throw _err("i18n-messageformat/bad-template",
      "messageFormat.parse: unexpected '" + state.src[state.pos] +
      "' at position " + state.pos);
  }
  return nodes;
}

function _parseSequence(state, topLevel) {
  state.depth = (state.depth || 0) + 1;
  if (state.depth > MAX_NESTING_DEPTH) {
    throw _err("i18n-messageformat/bad-template",
      "messageFormat.parse: case nesting too deep (max " +
      MAX_NESTING_DEPTH + ")");
  }
  var nodes = [];
  var lit = "";
  while (state.pos < state.src.length) {
    var ch = state.src[state.pos];
    if (ch === "}" && !topLevel) {
      break;
    }
    if (ch === "{") {
      if (lit.length > 0) { nodes.push({ type: "literal", value: lit }); lit = ""; }
      nodes.push(_parseArgument(state));
      continue;
    }
    if (ch === "#" && !topLevel) {
      if (lit.length > 0) { nodes.push({ type: "literal", value: lit }); lit = ""; }
      nodes.push({ type: "hash" });
      state.pos += 1;
      continue;
    }
    if (ch === "'") {
      state.pos += 1;
      if (state.pos >= state.src.length) { lit += "'"; break; }
      var next = state.src[state.pos];
      if (next === "'") {
        lit += "'";
        state.pos += 1;
        continue;
      }
      if (next === "{" || next === "}" || next === "#" || next === "|") {
        var endQuote = state.src.indexOf("'", state.pos);
        if (endQuote === -1) {
          lit += state.src.slice(state.pos);
          state.pos = state.src.length;
        } else {
          lit += state.src.slice(state.pos, endQuote);
          state.pos = endQuote + 1;
        }
        continue;
      }
      lit += "'";
      continue;
    }
    lit += ch;
    state.pos += 1;
  }
  if (lit.length > 0) nodes.push({ type: "literal", value: lit });
  state.depth -= 1;
  return nodes;
}

function _parseArgument(state) {
  if (state.src[state.pos] !== "{") {
    throw _err("i18n-messageformat/bad-template", "expected '{' at " + state.pos);
  }
  state.pos += 1;
  _skipWs(state);
  var name = _parseIdentifier(state);
  if (!name) {
    throw _err("i18n-messageformat/bad-template",
      "missing argument name at position " + state.pos);
  }
  _skipWs(state);
  var ch = state.src[state.pos];
  if (ch === "}") {
    state.pos += 1;
    return { type: "argument", name: name };
  }
  if (ch !== ",") {
    throw _err("i18n-messageformat/bad-template",
      "expected ',' or '}' after argument name '" + name +
      "' at position " + state.pos);
  }
  state.pos += 1;
  _skipWs(state);
  var typeName = _parseIdentifier(state);
  if (!typeName) {
    throw _err("i18n-messageformat/bad-template",
      "missing argument type after ',' for '" + name + "'");
  }
  _skipWs(state);
  if (typeName === "plural" || typeName === "selectordinal") {
    return _parsePluralLike(state, name, typeName === "selectordinal" ? "ordinal" : "plural");
  }
  if (typeName === "select") {
    return _parseSelect(state, name);
  }
  throw _err("i18n-messageformat/bad-template",
    "unsupported argument type '" + typeName + "' (supported: plural, " +
    "selectordinal, select)");
}

function _parsePluralLike(state, name, kind) {
  if (state.src[state.pos] === ",") { state.pos += 1; _skipWs(state); }
  var offset = 0;
  if (state.src.slice(state.pos, state.pos + 7) === "offset:") {
    state.pos += 7;
    offset = _parseInteger(state);
    _skipWs(state);
  }
  var cases = {};
  while (state.pos < state.src.length && state.src[state.pos] !== "}") {
    var caseKey = _parseCaseKey(state);
    _skipWs(state);
    if (state.src[state.pos] !== "{") {
      throw _err("i18n-messageformat/bad-template",
        "expected '{' after plural case '" + caseKey +
        "' at position " + state.pos);
    }
    state.pos += 1;
    var body = _parseSequence(state, false);
    if (state.src[state.pos] !== "}") {
      throw _err("i18n-messageformat/bad-template",
        "unclosed plural case body at position " + state.pos);
    }
    state.pos += 1;
    cases[caseKey] = body;
    _skipWs(state);
  }
  if (state.src[state.pos] !== "}") {
    throw _err("i18n-messageformat/bad-template",
      "unclosed plural argument for '" + name + "'");
  }
  if (!cases.other) {
    throw _err("i18n-messageformat/bad-template",
      "plural argument '" + name + "' missing required 'other' case");
  }
  state.pos += 1;
  return { type: kind, name: name, offset: offset, cases: cases };
}

function _parseSelect(state, name) {
  if (state.src[state.pos] === ",") { state.pos += 1; _skipWs(state); }
  var cases = {};
  while (state.pos < state.src.length && state.src[state.pos] !== "}") {
    var caseKey = _parseIdentifier(state);
    if (!caseKey) {
      throw _err("i18n-messageformat/bad-template",
        "expected select case identifier at position " + state.pos);
    }
    _skipWs(state);
    if (state.src[state.pos] !== "{") {
      throw _err("i18n-messageformat/bad-template",
        "expected '{' after select case '" + caseKey +
        "' at position " + state.pos);
    }
    state.pos += 1;
    var body = _parseSequence(state, false);
    if (state.src[state.pos] !== "}") {
      throw _err("i18n-messageformat/bad-template",
        "unclosed select case body at position " + state.pos);
    }
    state.pos += 1;
    cases[caseKey] = body;
    _skipWs(state);
  }
  if (state.src[state.pos] !== "}") {
    throw _err("i18n-messageformat/bad-template",
      "unclosed select argument for '" + name + "'");
  }
  if (!cases.other) {
    throw _err("i18n-messageformat/bad-template",
      "select argument '" + name + "' missing required 'other' case");
  }
  state.pos += 1;
  return { type: "select", name: name, cases: cases };
}

function _parseIdentifier(state) {
  var start = state.pos;
  while (state.pos < state.src.length) {
    var ch = state.src[state.pos];
    if (ch === "{" || ch === "}" || ch === "," || ch === "#" || ch === "'") break;
    if (/\s/.test(ch)) break;
    state.pos += 1;
  }
  return state.src.slice(start, state.pos);
}

function _parseCaseKey(state) {
  if (state.src[state.pos] === "=") {
    state.pos += 1;
    var n = _parseInteger(state);
    return "=" + n;
  }
  return _parseIdentifier(state);
}

function _parseInteger(state) {
  var start = state.pos;
  if (state.src[state.pos] === "-") state.pos += 1;
  while (state.pos < state.src.length && /[0-9]/.test(state.src[state.pos])) {
    state.pos += 1;
  }
  if (state.pos === start) {
    throw _err("i18n-messageformat/bad-template", "expected integer at position " + state.pos);
  }
  return parseInt(state.src.slice(start, state.pos), 10);
}

function _skipWs(state) {
  while (state.pos < state.src.length && /\s/.test(state.src[state.pos])) {
    state.pos += 1;
  }
}

var _pluralRulesCache = new Map();
function _pluralRules(locale, type) {
  var key = locale + "\x1f" + type;
  return boundedMap.getOrInsert(_pluralRulesCache, key, function () {
    return new Intl.PluralRules(locale, { type: type });
  });
}

function format(template, vars, locale) {
  var nodes = parse(template);
  return _renderSequence(nodes, vars || {}, locale || "en", null, 0);
}

function _renderSequence(nodes, vars, locale, hashContext, depth) {
  depth = depth || 0;
  if (depth > MAX_NESTING_DEPTH) {
    throw _err("i18n-messageformat/bad-template",
      "messageFormat: render nesting too deep (max " + MAX_NESTING_DEPTH + ")");
  }
  var out = "";
  for (var i = 0; i < nodes.length; i++) {
    out += _renderNode(nodes[i], vars, locale, hashContext, depth);
  }
  return out;
}

function _ownCase(cases, key) {
  return safeObject.ownProp(cases, key);
}

function _ownVar(vars, name) {
  return safeObject.ownProp(vars, name);
}

function _renderNode(node, vars, locale, hashContext, depth) {
  if (node.type === "literal") return node.value;
  if (node.type === "hash") {
    return hashContext != null ? String(hashContext) : "#";
  }
  if (node.type === "argument") {
    var v = _ownVar(vars, node.name);
    return v === undefined ? "" : (v === null ? "" : String(v));
  }
  if (node.type === "plural" || node.type === "ordinal") {
    var raw = _ownVar(vars, node.name);
    var n = Number(raw);
    if (!Number.isFinite(n)) {
      throw _err("i18n-messageformat/bad-var",
        "plural arg '" + node.name + "' must be a number, got " +
        typeof raw + " " + JSON.stringify(raw));
    }
    var adjusted = n - (node.offset || 0);
    var exact = "=" + n;
    var caseBody = _ownCase(node.cases, exact);
    if (!caseBody) {
      var pr = _pluralRules(locale, node.type === "ordinal" ? "ordinal" : "cardinal");
      var category = pr.select(adjusted);
      caseBody = _ownCase(node.cases, category) || _ownCase(node.cases, "other");
    }
    return _renderSequence(caseBody, vars, locale, adjusted, depth + 1);
  }
  if (node.type === "select") {
    var sv = _ownVar(vars, node.name);
    var key = (sv === undefined || sv === null) ? "other" : String(sv);
    var body = _ownCase(node.cases, key) || _ownCase(node.cases, "other");
    return _renderSequence(body, vars, locale, hashContext, depth + 1);
  }
  return "";
}

function looksLikeMessageFormat(template) {
  if (typeof template !== "string") return false;
  return /\{[^{}]+,\s*(plural|select|selectordinal)\b/.test(template);
}

module.exports = {
  parse:                 parse,
  format:                format,
  looksLikeMessageFormat: looksLikeMessageFormat,
  I18nMessageFormatError: I18nMessageFormatError,
  _resetCacheForTest:    function () { _pluralRulesCache.clear(); },
};

void lazyRequire;
