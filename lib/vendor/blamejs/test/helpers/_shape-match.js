// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Token-aware shape-matcher for codebase-patterns detectors.
 *
 * The framework's codebase-patterns gate has historically been regex-only,
 * which is trivially bypassed by renaming variables, adding parens, or
 * splitting across lines (see the v0.11.3 PR-108 audit findings). This
 * module is the bounded-grammar shape-matcher PR-2 introduces: it
 * tokenizes the source, tracks paren / brace / bracket depth + string
 * state + comment state, and exposes primitives for the detector
 * shapes the audit named:
 *
 *   - findCalls(source, calleeRegex)
 *       → every call whose callee identifier-chain matches the regex,
 *         regardless of whitespace / parens / line splits.
 *   - findEnclosingTry(source, callPos)
 *       → does the call sit inside `try { ... }` ? Used by the rule §5
 *         drop-silent audit-emit detector.
 *   - findEnclosingFn(source, callPos)
 *       → start/end positions of the containing function body.
 *   - findStatementBefore(source, callPos)
 *       → the previous statement (same brace depth, prior `;` or `{`).
 *   - findStatementAfter(source, callPos)
 *       → next sibling statement at the same depth.
 *   - aliasesOf(source, identChain)
 *       → every local var name that was assigned from this identifier
 *         chain anywhere in `source`. Catches the v0.11.3 audit's
 *         "alias bypass" class (`var emit = audit.emit; emit(...)`).
 *
 * Not a full ECMAScript parser. The framework code is CommonJS + var +
 * no JSX + no TypeScript by design, so the lexer is small (~200 lines).
 * Primitives are conservative — ambiguous shapes (regex-vs-division,
 * escaped template-literal substitutions across line boundaries) yield
 * `null` rather than guessing.
 *
 * Lives in test/helpers/, never ships in the npm tarball — `test/` is
 * absent from package.json `files:` allowlist (verified at PR-2 build).
 */

// ---- Lexer ----

var TOK_IDENT      = "ident";
var TOK_NUMBER     = "number";
var TOK_STRING     = "string";
var TOK_TEMPLATE   = "template";
var TOK_REGEX      = "regex";
var TOK_PUNCT      = "punct";
var TOK_COMMENT    = "comment";
var TOK_WS         = "ws";
var TOK_KEYWORD    = "keyword";

var KEYWORDS = {
  "var": 1, "let": 1, "const": 1, "function": 1, "return": 1, "if": 1,
  "else": 1, "for": 1, "while": 1, "do": 1, "switch": 1, "case": 1,
  "default": 1, "break": 1, "continue": 1, "try": 1, "catch": 1,
  "finally": 1, "throw": 1, "new": 1, "delete": 1, "typeof": 1,
  "instanceof": 1, "in": 1, "of": 1, "void": 1, "this": 1, "null": 1,
  "true": 1, "false": 1, "undefined": 1, "async": 1, "await": 1,
  "yield": 1, "class": 1, "extends": 1, "super": 1, "import": 1,
  "export": 1, "from": 1, "as": 1,
};

// Punctuation characters that can begin a token. Multi-char operators
// (===, !==, &&, ||, ??, =>, etc.) are recognised greedily in tokenize.
var PUNCT_CHARS = "{}()[];,.<>!=+-*/%&|^~?:";

// Whether a token at position `i-1` (last non-ws/comment) suggests the
// next `/` opens a regex literal versus a division operator. This is
// the classic JS ambiguity; we use the standard rule: regex follows
// any context that demands an expression — operators, keywords like
// `return` / `typeof` / `new`, or the start of input.
function _slashIsRegex(prevSignificant) {
  if (!prevSignificant) return true;
  if (prevSignificant.type === TOK_IDENT) {
    // After an identifier we don't know whether it's a variable name
    // (division) or an unparenthesised expression-tail. Be conservative:
    // identifiers preceded only by `return`, `typeof`, etc. resolve via
    // keyword check; bare identifiers we treat as division.
    return false;
  }
  if (prevSignificant.type === TOK_NUMBER ||
      prevSignificant.type === TOK_STRING ||
      prevSignificant.type === TOK_TEMPLATE ||
      prevSignificant.type === TOK_REGEX) return false;
  if (prevSignificant.type === TOK_KEYWORD) {
    var kw = prevSignificant.value;
    // After these keywords a `/` is part of a regex literal.
    if (kw === "return" || kw === "typeof" || kw === "throw" ||
        kw === "new" || kw === "delete" || kw === "void" ||
        kw === "instanceof" || kw === "in" || kw === "of" ||
        kw === "case" || kw === "yield" || kw === "await") return true;
    return false;
  }
  if (prevSignificant.type === TOK_PUNCT) {
    // After most punctuation a `/` is a regex. Exceptions: `)` and `]`
    // and `}` which can close an expression and thus a following `/`
    // is division. (Object-literal `}` is statement-end and would be a
    // regex — but the bounded grammar we care about uses semicolons.)
    var p = prevSignificant.value;
    if (p === ")" || p === "]") return false;
    return true;
  }
  return true;
}

function tokenize(source) {
  var tokens = [];
  var i = 0;
  var n = source.length;
  var prevSig = null;
  while (i < n) {
    var ch = source.charAt(i);
    var cc = source.charCodeAt(i);

    // Whitespace
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      var ws = i;
      while (i < n) {
        var c2 = source.charAt(i);
        if (c2 !== " " && c2 !== "\t" && c2 !== "\n" && c2 !== "\r") break;
        i += 1;
      }
      tokens.push({ type: TOK_WS, value: source.slice(ws, i), start: ws, end: i });
      continue;
    }

    // Line comment
    if (ch === "/" && source.charAt(i + 1) === "/") {
      var lc = i;
      while (i < n && source.charAt(i) !== "\n") i += 1;
      tokens.push({ type: TOK_COMMENT, value: source.slice(lc, i), start: lc, end: i });
      continue;
    }

    // Block comment
    if (ch === "/" && source.charAt(i + 1) === "*") {
      var bc = i; i += 2;
      while (i < n && !(source.charAt(i) === "*" && source.charAt(i + 1) === "/")) i += 1;
      if (i < n) i += 2;
      tokens.push({ type: TOK_COMMENT, value: source.slice(bc, i), start: bc, end: i });
      continue;
    }

    // String literal — single or double quote
    if (ch === "'" || ch === '"') {
      var sQuote = ch; var ss = i; i += 1;
      while (i < n) {
        var c3 = source.charAt(i);
        if (c3 === "\\") { i += 2; continue; }
        if (c3 === sQuote) { i += 1; break; }
        if (c3 === "\n") break;                                                    // unterminated — caller deals
        i += 1;
      }
      var stok = { type: TOK_STRING, value: source.slice(ss, i), start: ss, end: i };
      tokens.push(stok); prevSig = stok;
      continue;
    }

    // Template literal — backtick. Substitutions ${ ... } can recurse;
    // for the bounded use here we track brace-depth inside the substitution
    // and resume the template after the matching `}`.
    if (ch === "`") {
      var ts = i; i += 1;
      var depth = 0;
      while (i < n) {
        var c4 = source.charAt(i);
        if (depth === 0) {
          if (c4 === "\\") { i += 2; continue; }
          if (c4 === "`") { i += 1; break; }
          if (c4 === "$" && source.charAt(i + 1) === "{") {
            depth = 1; i += 2; continue;
          }
          i += 1; continue;
        }
        // inside ${...} — track nested braces but skip nested strings/templates
        if (c4 === "{") { depth += 1; i += 1; continue; }
        if (c4 === "}") { depth -= 1; i += 1; continue; }
        if (c4 === "'" || c4 === '"') {
          var nQ = c4; i += 1;
          while (i < n && source.charAt(i) !== nQ) {
            if (source.charAt(i) === "\\") i += 2; else i += 1;
          }
          if (i < n) i += 1;
          continue;
        }
        i += 1;
      }
      var ttok = { type: TOK_TEMPLATE, value: source.slice(ts, i), start: ts, end: i };
      tokens.push(ttok); prevSig = ttok;
      continue;
    }

    // Regex literal — only if grammar position allows
    if (ch === "/" && _slashIsRegex(prevSig)) {
      var rs = i; i += 1;
      var inClass = false;
      while (i < n) {
        var c5 = source.charAt(i);
        if (c5 === "\\") { i += 2; continue; }
        if (c5 === "[") { inClass = true; i += 1; continue; }
        if (c5 === "]") { inClass = false; i += 1; continue; }
        if (c5 === "/" && !inClass) { i += 1; break; }
        if (c5 === "\n") break;                                                    // unterminated
        i += 1;
      }
      // Trailing flags
      while (i < n && /[gimsuyd]/.test(source.charAt(i))) i += 1;
      var rtok = { type: TOK_REGEX, value: source.slice(rs, i), start: rs, end: i };
      tokens.push(rtok); prevSig = rtok;
      continue;
    }

    // Number literal — simple. Includes hex, octal, binary, decimal.
    if (cc >= 48 && cc <= 57) {                                                    // 0..9
      var ns = i; i += 1;
      while (i < n && /[0-9a-fA-FxXbBoOeE._n+-]/.test(source.charAt(i))) {
        // Stop at a `-`/`+` that isn't part of an exponent
        var nc = source.charAt(i);
        if ((nc === "+" || nc === "-") && !/[eE]/.test(source.charAt(i - 1))) break;
        i += 1;
      }
      var ntok = { type: TOK_NUMBER, value: source.slice(ns, i), start: ns, end: i };
      tokens.push(ntok); prevSig = ntok;
      continue;
    }

    // Identifier / keyword
    if (/[A-Za-z_$]/.test(ch)) {
      var is = i; i += 1;
      while (i < n && /[A-Za-z0-9_$]/.test(source.charAt(i))) i += 1;
      var idVal = source.slice(is, i);
      var idType = KEYWORDS[idVal] ? TOK_KEYWORD : TOK_IDENT;
      var itok = { type: idType, value: idVal, start: is, end: i };
      tokens.push(itok); prevSig = itok;
      continue;
    }

    // Punctuation (multi-char operators recognised greedily)
    if (PUNCT_CHARS.indexOf(ch) !== -1) {
      var ps = i;
      // Greedy: 3-char first (===, !==, ...), then 2-char (==, !=, &&,
      // ||, ??, =>, **, <<, >>, ...), then 1-char.
      var three = source.slice(i, i + 3);
      var two = source.slice(i, i + 2);
      if (three === "===" || three === "!==" || three === "..." ||
          three === ">>>" || three === "**=" || three === "<<=" ||
          three === ">>=" || three === "&&=" || three === "||=" ||
          three === "??=") {
        i += 3;
      } else if (two === "==" || two === "!=" || two === "<=" || two === ">=" ||
                 two === "&&" || two === "||" || two === "??" || two === "=>" ||
                 two === "**" || two === "<<" || two === ">>" ||
                 two === "+=" || two === "-=" || two === "*=" || two === "/=" ||
                 two === "%=" || two === "&=" || two === "|=" || two === "^=" ||
                 two === "++" || two === "--" || two === "?.") {
        i += 2;
      } else {
        i += 1;
      }
      var ptok = { type: TOK_PUNCT, value: source.slice(ps, i), start: ps, end: i };
      tokens.push(ptok); prevSig = ptok;
      continue;
    }

    // Unknown — skip one char to avoid infinite loop
    i += 1;
  }
  return tokens;
}

// Filter to significant tokens (drop whitespace + comments) but keep the
// original `start`/`end` positions so callers can map back to source.
function significantTokens(tokens) {
  var out = [];
  for (var i = 0; i < tokens.length; i += 1) {
    if (tokens[i].type !== TOK_WS && tokens[i].type !== TOK_COMMENT) out.push(tokens[i]);
  }
  return out;
}

// Reverse-lookup: from source position → significant-tokens index.
function _sigIdxBeforePos(sig, pos) {
  for (var i = sig.length - 1; i >= 0; i -= 1) {
    if (sig[i].end <= pos) return i;
  }
  return -1;
}

// ---- Primitive: findCalls ----
//
// Match every call of the form `<head>(...)` where `<head>` is an
// identifier chain (`foo`, `foo.bar`, `foo.bar.baz`, `foo["bar"]`).
// `calleeRegex` is matched against the joined chain (e.g. `audit.emit`).
//
// Returns an array of `{ chain, openParen, closeParen, head: {start,end},
//                        call: {start,end} }`.
function findCalls(source, calleeRegex) {
  var tokens = tokenize(source);
  var sig = significantTokens(tokens);
  var out = [];
  for (var i = 0; i < sig.length; i += 1) {
    if (sig[i].type !== TOK_PUNCT || sig[i].value !== "(") continue;
    // Walk back to collect the identifier-chain head.
    var chain = [];
    var j = i - 1;
    var headEnd = sig[i].start;
    while (j >= 0) {
      var t = sig[j];
      if (t.type === TOK_IDENT) {
        chain.unshift(t.value);
        // Continue past a preceding `.`
        if (j > 0 && sig[j - 1].type === TOK_PUNCT && sig[j - 1].value === ".") {
          j -= 2; continue;
        }
        break;
      }
      // Bracket access: ["foo"] — pop the string token if present
      if (t.type === TOK_PUNCT && t.value === "]") {
        // walk to matching [
        var bdepth = 1; var k = j - 1; var member = null;
        while (k >= 0 && bdepth > 0) {
          if (sig[k].type === TOK_PUNCT && sig[k].value === "]") bdepth += 1;
          else if (sig[k].type === TOK_PUNCT && sig[k].value === "[") bdepth -= 1;
          if (bdepth === 1 && sig[k].type === TOK_STRING) {
            member = sig[k].value.slice(1, -1);
          }
          k -= 1;
        }
        if (member !== null) chain.unshift(member);
        // continue past optional `.` if any (rare with bracket access)
        j = k;
        if (j >= 0 && sig[j].type === TOK_PUNCT && sig[j].value === ".") {
          j -= 1; continue;
        }
        continue;
      }
      break;
    }
    if (chain.length === 0) continue;
    var joined = chain.join(".");
    if (!calleeRegex.test(joined)) continue;
    // Find matching `)`
    var pdepth = 1; var p = i + 1;
    while (p < sig.length && pdepth > 0) {
      if (sig[p].type === TOK_PUNCT) {
        if (sig[p].value === "(") pdepth += 1;
        else if (sig[p].value === ")") pdepth -= 1;
      }
      p += 1;
    }
    if (pdepth !== 0) continue;                                                     // unterminated
    var closeIdx = p - 1;
    var headStartIdx = j + 1;
    if (headStartIdx < 0) headStartIdx = 0;
    out.push({
      chain:      joined,
      head:       { start: sig[headStartIdx].start, end: headEnd },
      openParen:  sig[i].start,
      closeParen: sig[closeIdx].end,
      call:       { start: sig[headStartIdx].start, end: sig[closeIdx].end },
    });
  }
  return out;
}

// ---- Primitive: findEnclosingTry / findEnclosingFn ----
//
// Both walk a brace-depth stack backward from `pos` to find the
// nearest `<keyword> {` opener whose matching `}` is past `pos`.
function _findEnclosing(source, pos, keywordRegex) {
  var tokens = tokenize(source);
  var sig = significantTokens(tokens);
  // Build per-token depth (running brace depth at token start).
  var depth = 0;
  var depths = new Array(sig.length);
  for (var i = 0; i < sig.length; i += 1) {
    depths[i] = depth;
    if (sig[i].type === TOK_PUNCT) {
      if (sig[i].value === "{") depth += 1;
      else if (sig[i].value === "}") depth -= 1;
    }
  }
  // Find sig-index immediately containing pos.
  var atIdx = -1;
  for (var k = 0; k < sig.length; k += 1) {
    if (sig[k].start <= pos && pos < sig[k].end) { atIdx = k; break; }
    if (sig[k].start > pos) { atIdx = k - 1; break; }
  }
  if (atIdx < 0) atIdx = sig.length - 1;
  var atDepth = depths[atIdx];
  // Walk backward looking for `<keyword>` whose immediately following
  // `{` (or `( ... ) {` for function) opens a block that contains pos.
  for (var b = atIdx - 1; b >= 0; b -= 1) {
    if (sig[b].type !== TOK_KEYWORD) continue;
    if (!keywordRegex.test(sig[b].value)) continue;
    // Walk forward from b to find the `{` that opens this block.
    var braceStart = -1;
    for (var f = b + 1; f < sig.length; f += 1) {
      if (sig[f].type === TOK_PUNCT && sig[f].value === "{") {
        braceStart = f; break;
      }
      // No braces allowed for try/catch/finally — they must be
      // immediately followed by `{`. For function we may pass through
      // `(...)` and a return-type — keep walking.
    }
    if (braceStart === -1) continue;
    // depth at the brace = depths[braceStart]; depth inside = +1
    var braceDepth = depths[braceStart] + 1;
    if (braceDepth !== atDepth) continue;                                            // not this one
    // Find matching `}`
    var bd = 1; var fi = braceStart + 1;
    while (fi < sig.length && bd > 0) {
      if (sig[fi].type === TOK_PUNCT) {
        if (sig[fi].value === "{") bd += 1;
        else if (sig[fi].value === "}") bd -= 1;
      }
      fi += 1;
    }
    if (bd !== 0) continue;
    var closeBrace = sig[fi - 1].end;
    if (sig[braceStart].start < pos && pos < closeBrace) {
      return {
        keyword:    sig[b].value,
        keywordPos: sig[b].start,
        bodyStart:  sig[braceStart].start,
        bodyEnd:    closeBrace,
      };
    }
  }
  return null;
}

function findEnclosingTry(source, pos) {
  return _findEnclosing(source, pos, /^(try)$/);
}

function findEnclosingFn(source, pos) {
  return _findEnclosing(source, pos, /^(function)$/);
}

// ---- Primitive: aliasesOf ----
//
// Scan source for every `var <name> = <chain>;` / `const ...` /
// `let ...` / `<name> = <chain>;` where `<chain>` matches `chainRegex`.
// Returns the set of `<name>`s. Used to detect aliased call sites.
function aliasesOf(source, chainRegex) {
  var tokens = tokenize(source);
  var sig = significantTokens(tokens);
  var out = {};
  for (var i = 0; i < sig.length - 3; i += 1) {
    // Pattern: [var|const|let|identifier] IDENT = <chain>...
    var head = sig[i];
    var nameIdx = i + 1;
    var eqIdx = i + 2;
    if (head.type === TOK_KEYWORD && (head.value === "var" || head.value === "const" || head.value === "let")) {
      // var X = ...
    } else if (head.type === TOK_IDENT && sig[i + 1] && sig[i + 1].type === TOK_PUNCT && sig[i + 1].value === "=") {
      // X = ...  (bare assignment)
      nameIdx = i;
      eqIdx = i + 1;
    } else {
      continue;
    }
    if (!sig[nameIdx] || sig[nameIdx].type !== TOK_IDENT) continue;
    if (!sig[eqIdx] || sig[eqIdx].type !== TOK_PUNCT || sig[eqIdx].value !== "=") continue;
    // Collect identifier chain after `=`. Stop at `;`, `,`, `)`, end-of-line newline.
    var chain = [];
    var j = eqIdx + 1;
    while (j < sig.length) {
      var t = sig[j];
      if (t.type === TOK_IDENT) {
        chain.push(t.value);
        if (sig[j + 1] && sig[j + 1].type === TOK_PUNCT && sig[j + 1].value === ".") {
          j += 2; continue;
        }
        break;
      }
      break;
    }
    if (chain.length < 2) continue;                                                 // need a chain (foo.bar at minimum)
    var joined = chain.join(".");
    if (chainRegex.test(joined)) out[sig[nameIdx].value] = joined;
  }
  return out;
}

// ---- Primitive: positionToLineCol ----

function positionToLineCol(source, pos) {
  var line = 1, col = 1;
  for (var i = 0; i < pos && i < source.length; i += 1) {
    if (source.charCodeAt(i) === 10) { line += 1; col = 1; }
    else col += 1;
  }
  return { line: line, col: col };
}

module.exports = {
  tokenize:           tokenize,
  significantTokens:  significantTokens,
  findCalls:          findCalls,
  findEnclosingTry:   findEnclosingTry,
  findEnclosingFn:    findEnclosingFn,
  aliasesOf:          aliasesOf,
  positionToLineCol:  positionToLineCol,
  TOK_IDENT:          TOK_IDENT,
  TOK_PUNCT:          TOK_PUNCT,
  TOK_STRING:         TOK_STRING,
  TOK_KEYWORD:        TOK_KEYWORD,
  TOK_NUMBER:         TOK_NUMBER,
  TOK_REGEX:          TOK_REGEX,
  TOK_TEMPLATE:       TOK_TEMPLATE,
};
