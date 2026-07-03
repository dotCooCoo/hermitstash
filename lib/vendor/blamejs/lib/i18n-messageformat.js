// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * i18n-messageformat — ICU MessageFormat parser + evaluator.
 *
 * The framework's `b.i18n` translation file format is JSON-shaped with
 * CLDR plural keys at the JSON level (one / few / many / other under a
 * key like `inbox.unread`). That covers the simple plural case but not
 * the nested / inline patterns common in real-world translations:
 * gendered selects, plural forms with embedded variables, ordinals,
 * arguments inside cases.
 *
 * ICU MessageFormat is the standard syntax for those cases:
 *
 *   You have {count, plural, =0 {no messages} =1 {# message} other {# messages}}.
 *   {gender, select, female {She} male {He} other {They}} liked your post.
 *   {n, plural, one {# day} other {# days}} until {event}.
 *
 * This module is a minimal-but-correct subset:
 *
 *   - `{argName}`                            — simple replacement
 *   - `{argName, plural, =N {...} cat {...} other {...}}` (with optional
 *     `offset:N` and `#` placeholder for the plural arg minus offset)
 *   - `{argName, selectordinal, =N {...} ... other {...}}` (CLDR ordinal)
 *   - `{argName, select, caseA {...} caseB {...} other {...}}`
 *   - Nested arguments inside any case body
 *   - `'{'` / `'}'` literal escapes (ICU spec — single-quote pair is the
 *     escape mechanism; `''` renders as a literal apostrophe)
 *   - CLDR cardinal categories via `Intl.PluralRules` for `plural`
 *   - CLDR ordinal categories via `Intl.PluralRules({ type: "ordinal" })`
 *
 * Out of scope (operators wanting these reach for the full
 * `messageformat` package and pre-format strings before storage):
 *
 *   - Inline `number` / `date` / `time` formatters (use `formatNumber` /
 *     `formatDate` from b.i18n separately and inline the result)
 *   - Choice-format (deprecated by ICU in favor of plural)
 *   - Custom user-defined argument types
 *
 * Operator API:
 *
 *   var msg = b.i18n.messageFormat.format(template, vars, locale?);
 *
 * Used by `b.i18n.t(key, vars, { messageFormat: true })` when the
 * translation entry contains MessageFormat syntax. Existing plural-
 * shaped JSON entries continue to work unchanged.
 */
var lazyRequire = require("./lazy-require");
var boundedMap = require("./bounded-map");
var { defineClass } = require("./framework-error");

var I18nMessageFormatError = defineClass("I18nMessageFormatError",
  { alwaysPermanent: true });

// ---- Tokenizer ----
//
// ICU MessageFormat is a small enough grammar that hand-rolling a
// recursive-descent parser is cleaner than threading a tokenizer +
// parser layer. We do scan apostrophe-escapes up-front though — the
// `'{'` and `'}'` patterns flip the next character to literal,
// `''` renders as a literal apostrophe.

function _err(code, message) {
  return new I18nMessageFormatError(code, message, true);
}

// Maximum case-nesting depth. The parser and the renderer both recurse
// once per nested plural/select case body; a template like
// `{a,select,x{{b,select,x{{c,select,...}}}}}` nested thousands deep would
// otherwise overflow the V8 stack with an uncaught RangeError. Templates
// usually come from operator translation files, but format()/parse() are
// public and `b.i18n.t(key, vars, { messageFormat: true })` renders entries
// that may be operator-supplied per-tenant, so a hostile template must fail
// as a typed BAD_TEMPLATE rather than crashing the process. Real
// translations nest 2-3 deep; 100 is far beyond any legitimate message yet
// well under native overflow.
var MAX_NESTING_DEPTH = 100;

// ---- Parser ----
//
// AST node shapes:
//   { type: "literal",  value: string }
//   { type: "argument", name: string }                          // {name}
//   { type: "plural",   name, offset, cases: { key: nodes[] } } // {n, plural, ...}
//   { type: "select",   name, cases: { key: nodes[] } }
//   { type: "ordinal",  name, offset, cases: { key: nodes[] } } // {n, selectordinal, ...}
//   { type: "hash"      }                                        // # inside plural body

function parse(template) {
  if (typeof template !== "string") {
    throw _err("BAD_TEMPLATE",
      "messageFormat.parse: template must be a string, got " + typeof template);
  }
  var state = { src: template, pos: 0 };
  var nodes = _parseSequence(state, /* topLevel */ true);
  if (state.pos < state.src.length) {
    throw _err("BAD_TEMPLATE",
      "messageFormat.parse: unexpected '" + state.src[state.pos] +
      "' at position " + state.pos);
  }
  return nodes;
}

function _parseSequence(state, topLevel) {
  state.depth = (state.depth || 0) + 1;
  if (state.depth > MAX_NESTING_DEPTH) {
    throw _err("BAD_TEMPLATE",
      "messageFormat.parse: case nesting too deep (max " +
      MAX_NESTING_DEPTH + ")");
  }
  var nodes = [];
  var lit = "";
  while (state.pos < state.src.length) {
    var ch = state.src[state.pos];
    if (ch === "}" && !topLevel) {
      // Caller will consume the closing brace.
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
      // ICU-spec apostrophe handling:
      //   ''        → literal "'"
      //   '{'       → literal "{"
      //   '}'       → literal "}"
      //   '#'       → literal "#" (only inside a plural body)
      //   'X'       → literal "'X" (X not a special char) — this is
      //               the `quoting` rule. We also handle '{...'
      //               sequences that quote an entire run.
      state.pos += 1;
      if (state.pos >= state.src.length) { lit += "'"; break; }
      var next = state.src[state.pos];
      if (next === "'") {
        lit += "'";
        state.pos += 1;
        continue;
      }
      // If the next char is a special metachar, the quote runs to the
      // next single-quote (or end of string).
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
      // Lone apostrophe — render literally.
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
  // Consume opening '{'.
  if (state.src[state.pos] !== "{") {
    throw _err("BAD_TEMPLATE", "expected '{' at " + state.pos);
  }
  state.pos += 1;
  _skipWs(state);
  var name = _parseIdentifier(state);
  if (!name) {
    throw _err("BAD_TEMPLATE",
      "missing argument name at position " + state.pos);
  }
  _skipWs(state);
  var ch = state.src[state.pos];
  if (ch === "}") {
    state.pos += 1;
    return { type: "argument", name: name };
  }
  if (ch !== ",") {
    throw _err("BAD_TEMPLATE",
      "expected ',' or '}' after argument name '" + name +
      "' at position " + state.pos);
  }
  state.pos += 1;
  _skipWs(state);
  var typeName = _parseIdentifier(state);
  if (!typeName) {
    throw _err("BAD_TEMPLATE",
      "missing argument type after ',' for '" + name + "'");
  }
  _skipWs(state);
  if (typeName === "plural" || typeName === "selectordinal") {
    return _parsePluralLike(state, name, typeName === "selectordinal" ? "ordinal" : "plural");
  }
  if (typeName === "select") {
    return _parseSelect(state, name);
  }
  throw _err("BAD_TEMPLATE",
    "unsupported argument type '" + typeName + "' (supported: plural, " +
    "selectordinal, select)");
}

function _parsePluralLike(state, name, kind) {
  // Optional ',' before the cases — the spec allows both `plural,
  // offset:0 ...` and `plural, =0 ...` immediately after the type.
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
      throw _err("BAD_TEMPLATE",
        "expected '{' after plural case '" + caseKey +
        "' at position " + state.pos);
    }
    state.pos += 1;
    var body = _parseSequence(state, false);
    if (state.src[state.pos] !== "}") {
      throw _err("BAD_TEMPLATE",
        "unclosed plural case body at position " + state.pos);
    }
    state.pos += 1;
    cases[caseKey] = body;
    _skipWs(state);
  }
  if (state.src[state.pos] !== "}") {
    throw _err("BAD_TEMPLATE",
      "unclosed plural argument for '" + name + "'");
  }
  if (!cases.other) {
    throw _err("BAD_TEMPLATE",
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
      throw _err("BAD_TEMPLATE",
        "expected select case identifier at position " + state.pos);
    }
    _skipWs(state);
    if (state.src[state.pos] !== "{") {
      throw _err("BAD_TEMPLATE",
        "expected '{' after select case '" + caseKey +
        "' at position " + state.pos);
    }
    state.pos += 1;
    var body = _parseSequence(state, false);
    if (state.src[state.pos] !== "}") {
      throw _err("BAD_TEMPLATE",
        "unclosed select case body at position " + state.pos);
    }
    state.pos += 1;
    cases[caseKey] = body;
    _skipWs(state);
  }
  if (state.src[state.pos] !== "}") {
    throw _err("BAD_TEMPLATE",
      "unclosed select argument for '" + name + "'");
  }
  if (!cases.other) {
    throw _err("BAD_TEMPLATE",
      "select argument '" + name + "' missing required 'other' case");
  }
  state.pos += 1;
  return { type: "select", name: name, cases: cases };
}

function _parseIdentifier(state) {
  var start = state.pos;
  while (state.pos < state.src.length) {
    var ch = state.src[state.pos];
    // Identifiers per ICU: anything not whitespace or special char.
    if (ch === "{" || ch === "}" || ch === "," || ch === "#" || ch === "'") break;
    if (/\s/.test(ch)) break;
    state.pos += 1;
  }
  return state.src.slice(start, state.pos);
}

function _parseCaseKey(state) {
  // CLDR plural keys: zero / one / two / few / many / other, OR
  // explicit `=N` literal-match keys.
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
    throw _err("BAD_TEMPLATE", "expected integer at position " + state.pos);
  }
  return parseInt(state.src.slice(start, state.pos), 10);
}

function _skipWs(state) {
  while (state.pos < state.src.length && /\s/.test(state.src[state.pos])) {
    state.pos += 1;
  }
}

// ---- Evaluator ----

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
  // parse() already bounds AST nesting to MAX_NESTING_DEPTH, so this guard
  // is defence-in-depth for any future caller that hands render a hand-built
  // tree — it must still fail typed rather than overflow the stack.
  if (depth > MAX_NESTING_DEPTH) {
    throw _err("BAD_TEMPLATE",
      "messageFormat: render nesting too deep (max " + MAX_NESTING_DEPTH + ")");
  }
  var out = "";
  for (var i = 0; i < nodes.length; i++) {
    out += _renderNode(nodes[i], vars, locale, hashContext, depth);
  }
  return out;
}

function _renderNode(node, vars, locale, hashContext, depth) {
  if (node.type === "literal") return node.value;
  if (node.type === "hash") {
    return hashContext != null ? String(hashContext) : "#";
  }
  if (node.type === "argument") {
    var v = vars[node.name];
    return v === undefined ? "" : (v === null ? "" : String(v));
  }
  if (node.type === "plural" || node.type === "ordinal") {
    var raw = vars[node.name];
    var n = Number(raw);
    if (!Number.isFinite(n)) {
      throw _err("BAD_VAR",
        "plural arg '" + node.name + "' must be a number, got " +
        typeof raw + " " + JSON.stringify(raw));
    }
    var adjusted = n - (node.offset || 0);
    var exact = "=" + n;
    var caseBody = node.cases[exact];
    if (!caseBody) {
      var pr = _pluralRules(locale, node.type === "ordinal" ? "ordinal" : "cardinal");
      var category = pr.select(adjusted);
      caseBody = node.cases[category] || node.cases.other;
    }
    return _renderSequence(caseBody, vars, locale, adjusted, depth + 1);
  }
  if (node.type === "select") {
    var sv = vars[node.name];
    var key = (sv === undefined || sv === null) ? "other" : String(sv);
    var body = node.cases[key] || node.cases.other;
    return _renderSequence(body, vars, locale, hashContext, depth + 1);
  }
  return "";
}

// ---- Detection helper for b.i18n.t() integration ----
//
// A string contains MessageFormat syntax if it has a `{...,...}` shape.
// Plain `{var}` interpolation is forwarded to the existing simple path
// (no plural / select / nested cases), matching backward compat. Used
// by `b.i18n.t(key, vars, { messageFormat: true })` to pick the
// renderer based on the entry.
function looksLikeMessageFormat(template) {
  if (typeof template !== "string") return false;
  // Cheap structural check — full-syntax detection comes from parse()
  // throwing if it isn't valid MessageFormat.
  return /\{[^{}]+,\s*(plural|select|selectordinal)\b/.test(template);
}

module.exports = {
  parse:                 parse,
  format:                format,
  looksLikeMessageFormat: looksLikeMessageFormat,
  I18nMessageFormatError: I18nMessageFormatError,
  // Test-only — clear plural-rules cache between locale rotations.
  _resetCacheForTest:    function () { _pluralRulesCache.clear(); },
};

// Reserved for future expansion — keeps the require() side-effect-free.
void lazyRequire;
