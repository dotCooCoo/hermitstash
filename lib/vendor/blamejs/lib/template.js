// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.template
 * @nav    HTTP
 * @title  Template
 *
 * @intro
 *   Server-side HTML template engine. Handlebars-flavored tag
 *   syntax (`{{ expr }}` HTML-escaped, `{{{ expr }}}` raw, `{{> name }}`
 *   partials, `{% extends "layout" %}` / `{% block name %}` inheritance,
 *   `{% if %}` / `{% for %}` directives) parsed into a small AST and
 *   walked at render time against an operator-supplied data scope.
 *
 *   No `eval`, no dynamic Function constructor, no `vm.runInThisContext`
 *   — the expression grammar is a fixed recursive-descent Pratt parser
 *   and member access is restricted to own properties (the parser
 *   refuses `foo.constructor` / `foo.__proto__` walks out of the data
 *   scope). Custom helpers are operator-provided functions in the data
 *   scope (e.g. `{{ helpers.formatDate(d) }}`); when `opts.sandbox ===
 *   true` each helper source string is wrapped through `b.sandbox.run`
 *   so helper code runs in a worker-thread isolate with timeout + byte
 *   cap.
 *
 *   `precompileAll()` walks `viewsDir` at boot, parsing every `.html`
 *   file so template syntax errors fail the deploy rather than the
 *   first user request. Compiled ASTs are cached unless `cache: false`
 *   is set on the engine — operators turn caching off for live-reload
 *   workflows.
 *
 * @card
 *   Server-side HTML template engine.
 */
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var markupEscape = require("./markup-escape").markupEscape;

// Lazy because b.template can be loaded before b.sandbox (which pulls
// in node:worker_threads). Operators not opting into sandboxed helpers
// shouldn't pay the worker_threads boot.
var sandboxModule = lazyRequire(function () { return require("./sandbox"); });

var MAX_TEMPLATE_DEPTH = 0x10;

var DEFAULT_STRING_TEMPLATE_BYTES = require("./constants").BYTES.kib(256);

/**
 * @primitive b.template.escapeHtml
 * @signature b.template.escapeHtml(value)
 * @since     0.1.0
 * @related   b.template.create, b.template.render
 *
 * HTML-entity escapes the five attack-relevant characters (`&`, `<`,
 * `>`, `"`, `'`). Non-string inputs are coerced via `String(value)`;
 * `null` and `undefined` become the empty string. Used internally by
 * `{{ expr }}` interpolation; exported because operators occasionally
 * reach for the same escape from non-template paths (form-error
 * rendering, CSV-cell-as-HTML pre-escape).
 *
 * @example
 *   b.template.escapeHtml("<script>alert(1)</script>");
 *   // → "&lt;script&gt;alert(1)&lt;/script&gt;"
 *
 *   b.template.escapeHtml(null);   // → ""
 *   b.template.escapeHtml(42);     // → "42"
 */
function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return markupEscape(value, { apos: "&#x27;" });
}

function _resolveViewPath(viewsDir, viewName) {
  if (typeof viewName !== "string" || viewName.length === 0) {
    throw new Error("template: view name must be a non-empty string");
  }
  if (viewName.indexOf("..") !== -1 || viewName.indexOf("\0") !== -1) {
    throw new Error("template: view name contains forbidden character: " + JSON.stringify(viewName));
  }
  var resolved = nodePath.resolve(viewsDir, viewName + ".html");
  var resolvedDir = nodePath.resolve(viewsDir);
  if (resolved !== resolvedDir &&
      !resolved.startsWith(resolvedDir + nodePath.sep)) {
    throw new Error("template: view path escapes viewsDir: " + viewName);
  }
  if (!nodeFs.existsSync(resolved)) {
    throw new Error("template: view not found: " + viewName);
  }
  return resolved;
}

function _resolvePartialPath(viewsDir, partialName) {
  if (typeof partialName !== "string" || partialName.length === 0) return null;
  if (partialName.indexOf("..") !== -1 || partialName.indexOf("\0") !== -1) return null;
  var resolved = nodePath.resolve(viewsDir, "partials", partialName + ".html");
  var partialsDir = nodePath.resolve(viewsDir, "partials");
  if (resolved !== partialsDir &&
      !resolved.startsWith(partialsDir + nodePath.sep)) return null;
  return nodeFs.existsSync(resolved) ? resolved : null;
}

var EXTENDS_RE = /^\s*\{%\s*extends\s+"([^"]+)"\s*%\}\s*/;
var BLOCK_TAG_RE = /\{%\s*block\s+([A-Za-z_][A-Za-z0-9_-]*)\s*%\}|\{%\s*endblock\s*%\}/g;

function _replaceBlocks(source, replacer) {
  var out = "";
  var pos = 0;
  var openMatch = null;
  var iter = source.matchAll(BLOCK_TAG_RE);
  var m = iter.next();
  while (!m.done) {
    var tag = m.value;
    if (tag[1] !== undefined) {
      if (!openMatch) openMatch = tag;
    } else if (openMatch) {
      var contentStart = openMatch.index + openMatch[0].length;
      out += source.slice(pos, openMatch.index) +
             replacer(openMatch[1], source.slice(contentStart, tag.index));
      pos = tag.index + tag[0].length;
      openMatch = null;
    }
    m = iter.next();
  }
  return out + source.slice(pos);
}

function _extractBlocks(source) {
  var blocks = {};
  var rest = _replaceBlocks(source, function (name, content) {
    blocks[name] = content;
    return "";
  });
  return { rest: rest, blocks: blocks };
}

function _substituteBlocks(parentSource, childBlocks) {
  return _replaceBlocks(parentSource, function (name, defaultContent) {
    return Object.prototype.hasOwnProperty.call(childBlocks, name)
      ? childBlocks[name]
      : defaultContent;
  });
}

function _resolveExtends(loadView, source) {
  var allOverrides = {};
  var current = source;
  var depth = 0;
  while (true) {
    if (depth > MAX_TEMPLATE_DEPTH) {
      throw new Error("template: layout inheritance depth exceeded " + MAX_TEMPLATE_DEPTH +
        " — possible extends cycle");
    }
    var m = current.match(EXTENDS_RE);
    if (!m) break;
    var parentName = m[1];
    var childRest = current.slice(m[0].length);
    var extracted = _extractBlocks(childRest);
    for (var k in extracted.blocks) {
      if (Object.prototype.hasOwnProperty.call(extracted.blocks, k) &&
          !Object.prototype.hasOwnProperty.call(allOverrides, k)) {
        allOverrides[k] = extracted.blocks[k];
      }
    }
    current = loadView(parentName);
    if (typeof current !== "string") {
      throw new Error("template: {% extends \"" + parentName + "\" %} could not be resolved");
    }
    depth++;
  }
  return _substituteBlocks(current, allOverrides);
}

function _inlinePartials(loadPartial, source, depth) {
  if (depth > MAX_TEMPLATE_DEPTH) {
    throw new Error("template: partial recursion depth exceeded " + MAX_TEMPLATE_DEPTH +
      " — possible cycle");
  }
  return source.replace(/\{\{>\s*([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}/g, function (_, name) {
    var sub = loadPartial(name);
    if (typeof sub !== "string") return "";
    return _inlinePartials(loadPartial, sub, depth + 1);
  });
}

function _tokenize(source) {
  var tokens = [];
  var i = 0;
  var len = source.length;
  while (i < len) {
    var codeStart = source.indexOf("{%", i);
    var rawStart  = source.indexOf("{{{", i);
    var exprStart = source.indexOf("{{", i);
    var nextTag = len;
    var tagType = null;
    if (codeStart !== -1 && codeStart < nextTag) { nextTag = codeStart; tagType = "code"; }
    if (rawStart  !== -1 && rawStart  < nextTag) { nextTag = rawStart;  tagType = "raw"; }
    if (exprStart !== -1 && exprStart < nextTag) { nextTag = exprStart; tagType = "expr"; }
    if (rawStart !== -1 && rawStart === nextTag && tagType === "expr") tagType = "raw";
    if (nextTag > i) {
      tokens.push({ kind: "LITERAL", text: source.slice(i, nextTag) });
    }
    if (tagType === null) break;
    if (tagType === "raw") {
      var endRaw = source.indexOf("}}}", nextTag + 3);
      if (endRaw === -1) throw new Error("template: unterminated {{{ raw }}} tag");
      tokens.push({ kind: "EXPR_RAW", expr: source.slice(nextTag + 3, endRaw).trim() });
      i = endRaw + 3;
    } else if (tagType === "expr") {
      var endExpr = source.indexOf("}}", nextTag + 2);
      if (endExpr === -1) throw new Error("template: unterminated {{ expression }} tag");
      tokens.push({ kind: "EXPR_ESCAPED", expr: source.slice(nextTag + 2, endExpr).trim() });
      i = endExpr + 2;
    } else {
      var endCode = source.indexOf("%}", nextTag + 2);
      if (endCode === -1) throw new Error("template: unterminated {% directive %} tag");
      tokens.push({ kind: "DIRECTIVE", body: source.slice(nextTag + 2, endCode).trim() });
      i = endCode + 2;
    }
  }
  return tokens;
}

var DIRECTIVE_HEAD_RE = /^([a-z]+)(?:\s+([\s\S]+))?$/;

function _parseTokens(tokens) {
  var pos = 0;
  function peek() { return tokens[pos]; }
  function next() { return tokens[pos++]; }

  function parseBody(terminators) {
    var body = [];
    while (pos < tokens.length) {
      var t = peek();
      if (t.kind === "LITERAL")     { next(); body.push({ type: "Literal",  text: t.text });                          continue; }
      if (t.kind === "EXPR_ESCAPED"){ next(); body.push({ type: "EscExpr",  expr: _parseExpression(t.expr) });        continue; }
      if (t.kind === "EXPR_RAW")    { next(); body.push({ type: "RawExpr",  expr: _parseExpression(t.expr) });        continue; }
      var m = t.body.match(DIRECTIVE_HEAD_RE);
      if (!m) throw new Error("template: malformed directive: {% " + t.body + " %}");
      var head = m[1];
      var tail = m[2] || "";
      if (terminators && terminators.indexOf(head) !== -1) {
        return body;
      }
      next();
      if (head === "if") {
        var cond = _parseExpression(tail);
        var thenBody = parseBody(["else", "endif"]);
        var elseBody = null;
        var sentinel = peek();
        if (sentinel && sentinel.kind === "DIRECTIVE" && /^else\b/.test(sentinel.body)) {
          next();
          elseBody = parseBody(["endif"]);
        }
        var endTok = next();
        if (!endTok || endTok.kind !== "DIRECTIVE" || !/^endif\b/.test(endTok.body)) {
          throw new Error("template: missing {% endif %}");
        }
        body.push({ type: "If", cond: cond, thenBody: thenBody, elseBody: elseBody });
        continue;
      }
      if (head === "for") {
        var forMatch = tail.match(/^([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([\s\S]+)$/);
        if (!forMatch) throw new Error("template: invalid for syntax: {% for " + tail + " %}");
        var binding = forMatch[1];
        var srcExpr = _parseExpression(forMatch[2]);
        var loopBody = parseBody(["endfor"]);
        var endFor = next();
        if (!endFor || endFor.kind !== "DIRECTIVE" || !/^endfor\b/.test(endFor.body)) {
          throw new Error("template: missing {% endfor %}");
        }
        body.push({ type: "For", binding: binding, source: srcExpr, body: loopBody });
        continue;
      }
      if (head === "block" || head === "endblock") {
        continue;
      }
      if (head === "extends") {
        throw new Error("template: {% extends %} must be the first non-whitespace in the file");
      }
      throw new Error("template: unknown directive: {% " + t.body + " %}");
    }
    if (terminators && terminators.length > 0) {
      throw new Error("template: unexpected end of template — expected one of: " + terminators.join(", "));
    }
    return body;
  }

  return { type: "Template", body: parseBody(null) };
}

function _tokenizeExpr(src) {
  var tokens = [];
  var i = 0;
  while (i < src.length) {
    var c = src[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r") { i++; continue; }
    if (c === '"' || c === "'") {
      var quote = c;
      i++;
      var s = "";
      while (i < src.length && src[i] !== quote) {
        if (src[i] === "\\" && i + 1 < src.length) {
          var esc = src[i + 1];
          if (esc === "n") s += "\n";
          else if (esc === "t") s += "\t";
          else if (esc === "r") s += "\r";
          else if (esc === "\\") s += "\\";
          else s += esc;
          i += 2;
          continue;
        }
        s += src[i++];
      }
      if (i >= src.length) throw new Error("template: unterminated string in expression");
      i++;
      tokens.push({ kind: "STRING", value: s });
      continue;
    }
    if ((c >= "0" && c <= "9") || (c === "." && src[i + 1] >= "0" && src[i + 1] <= "9")) {
      var nstart = i;
      while (i < src.length && ((src[i] >= "0" && src[i] <= "9") || src[i] === ".")) i++;
      tokens.push({ kind: "NUMBER", value: parseFloat(src.slice(nstart, i)) });
      continue;
    }
    if ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_" || c === "$") {
      var istart = i;
      while (i < src.length && (
        (src[i] >= "a" && src[i] <= "z") || (src[i] >= "A" && src[i] <= "Z") ||
        (src[i] >= "0" && src[i] <= "9") || src[i] === "_" || src[i] === "$"
      )) i++;
      var name = src.slice(istart, i);
      if (name === "true")  tokens.push({ kind: "BOOL", value: true });
      else if (name === "false") tokens.push({ kind: "BOOL", value: false });
      else if (name === "null")  tokens.push({ kind: "NULL" });
      else tokens.push({ kind: "IDENT", name: name });
      continue;
    }
    var two = src.slice(i, i + 2);
    var three = src.slice(i, i + 3);
    if (three === "===" || three === "!==") { tokens.push({ kind: "OP", op: three }); i += 3; continue; }
    if (two === "==" || two === "!=" || two === "<=" || two === ">=" ||
        two === "&&" || two === "||") {
      tokens.push({ kind: "OP", op: two }); i += 2; continue;
    }
    if ("+-*/!<>?:.,()[]".indexOf(c) !== -1) {
      tokens.push({ kind: "OP", op: c });
      i++;
      continue;
    }
    throw new Error("template: unexpected character in expression: '" + c + "' at offset " + i);
  }
  return tokens;
}

function _parseExpression(src) {
  var tokens = _tokenizeExpr(src);
  var pos = 0;
  function peek() { return tokens[pos]; }
  function eat(kind, op) {
    var t = tokens[pos];
    if (!t) return null;
    if (t.kind !== kind) return null;
    if (op !== undefined && t.op !== op) return null;
    pos++;
    return t;
  }
  function expect(kind, op) {
    var t = eat(kind, op);
    if (!t) {
      var got = tokens[pos] ? (tokens[pos].kind + (tokens[pos].op ? ":" + tokens[pos].op : "")) : "EOF";
      throw new Error("template: expected " + kind + (op ? "(" + op + ")" : "") + " got " + got);
    }
    return t;
  }

  function parseTernary() {
    var cond = parseLogicalOr();
    if (eat("OP", "?")) {
      var thenE = parseLogicalOr();
      expect("OP", ":");
      var elseE = parseLogicalOr();
      return { type: "Ternary", cond: cond, thenE: thenE, elseE: elseE };
    }
    return cond;
  }
  function parseLogicalOr() {
    var left = parseLogicalAnd();
    while (eat("OP", "||")) {
      var right = parseLogicalAnd();
      left = { type: "Binary", op: "||", left: left, right: right };
    }
    return left;
  }
  function parseLogicalAnd() {
    var left = parseEquality();
    while (eat("OP", "&&")) {
      var right = parseEquality();
      left = { type: "Binary", op: "&&", left: left, right: right };
    }
    return left;
  }
  function parseEquality() {
    var left = parseComparison();
    while (true) {
      var op = eat("OP", "===") || eat("OP", "!==") || eat("OP", "==") || eat("OP", "!=");
      if (!op) break;
      var right = parseComparison();
      left = { type: "Binary", op: op.op, left: left, right: right };
    }
    return left;
  }
  function parseComparison() {
    var left = parseAdditive();
    while (true) {
      var op = eat("OP", "<=") || eat("OP", ">=") || eat("OP", "<") || eat("OP", ">");
      if (!op) break;
      var right = parseAdditive();
      left = { type: "Binary", op: op.op, left: left, right: right };
    }
    return left;
  }
  function parseAdditive() {
    var left = parseMultiplicative();
    while (true) {
      var op = eat("OP", "+") || eat("OP", "-");
      if (!op) break;
      var right = parseMultiplicative();
      left = { type: "Binary", op: op.op, left: left, right: right };
    }
    return left;
  }
  function parseMultiplicative() {
    var left = parseUnary();
    while (true) {
      var op = eat("OP", "*") || eat("OP", "/");
      if (!op) break;
      var right = parseUnary();
      left = { type: "Binary", op: op.op, left: left, right: right };
    }
    return left;
  }
  function parseUnary() {
    if (eat("OP", "!"))  return { type: "Unary", op: "!", arg: parseUnary() };
    if (eat("OP", "-"))  return { type: "Unary", op: "-", arg: parseUnary() };
    return parsePostfix();
  }
  function parsePostfix() {
    var expr = parsePrimary();
    while (true) {
      if (eat("OP", ".")) {
        var ident = expect("IDENT");
        expr = { type: "Member", object: expr, property: ident.name, computed: false };
      } else if (eat("OP", "[")) {
        var idx = parseTernary();
        expect("OP", "]");
        expr = { type: "Member", object: expr, property: idx, computed: true };
      } else if (eat("OP", "(")) {
        var args = [];
        if (peek() && !(peek().kind === "OP" && peek().op === ")")) {
          args.push(parseTernary());
          while (eat("OP", ",")) args.push(parseTernary());
        }
        expect("OP", ")");
        expr = { type: "Call", callee: expr, args: args };
      } else break;
    }
    return expr;
  }
  function parsePrimary() {
    var t = peek();
    if (!t) throw new Error("template: unexpected end of expression");
    if (t.kind === "STRING") { pos++; return { type: "Literal", value: t.value }; }
    if (t.kind === "NUMBER") { pos++; return { type: "Literal", value: t.value }; }
    if (t.kind === "BOOL")   { pos++; return { type: "Literal", value: t.value }; }
    if (t.kind === "NULL")   { pos++; return { type: "Literal", value: null }; }
    if (t.kind === "IDENT")  { pos++; return { type: "Identifier", name: t.name }; }
    if (t.kind === "OP" && t.op === "(") {
      pos++;
      var inner = parseTernary();
      expect("OP", ")");
      return inner;
    }
    throw new Error("template: unexpected token in expression: " +
      (t.kind + (t.op ? ":" + t.op : "")));
  }

  var ast = parseTernary();
  if (pos < tokens.length) {
    var rest = tokens[pos];
    throw new Error("template: trailing tokens in expression: " +
      (rest.kind + (rest.op ? ":" + rest.op : "")));
  }
  return ast;
}

function _scopeLookup(scopes, name) {
  for (var i = scopes.length - 1; i >= 0; i--) {
    var s = scopes[i];
    if (s !== null && s !== undefined && Object.prototype.hasOwnProperty.call(s, name)) {
      return s[name];
    }
  }
  return undefined;
}

function _evalExpr(node, scopes) {
  switch (node.type) {
  case "Literal":     return node.value;
  case "Identifier":  return _scopeLookup(scopes, node.name);
  case "Member":
    var obj = _evalExpr(node.object, scopes);
    if (obj === null || obj === undefined) return undefined;
    var key = node.computed ? _evalExpr(node.property, scopes) : node.property;
    if (Object.prototype.hasOwnProperty.call(obj, key) ||
        (Array.isArray(obj) && key === "length")) {
      return obj[key];
    }
    return undefined;
  case "Call":
    var callee = _evalExpr(node.callee, scopes);
    if (typeof callee !== "function") {
      throw new Error("template: cannot call non-function: " +
        (node.callee.type === "Member" ? node.callee.property : node.callee.name || "<expr>"));
    }
    var args = [];
    for (var ai = 0; ai < node.args.length; ai++) {
      args.push(_evalExpr(node.args[ai], scopes));
    }
    var thisRef = null;
    if (node.callee.type === "Member") {
      thisRef = _evalExpr(node.callee.object, scopes);
    }
    return callee.apply(thisRef, args);
  case "Unary":
    var v = _evalExpr(node.arg, scopes);
    if (node.op === "!") return !v;
    if (node.op === "-") return -Number(v);
    throw new Error("template: unknown unary op: " + node.op);
  case "Binary":
    if (node.op === "&&") return _evalExpr(node.left, scopes) && _evalExpr(node.right, scopes);
    if (node.op === "||") return _evalExpr(node.left, scopes) || _evalExpr(node.right, scopes);
    var L = _evalExpr(node.left, scopes);
    var R = _evalExpr(node.right, scopes);
    switch (node.op) {
    case "===": return L === R;
    case "!==": return L !== R;
    // eslint-disable-next-line eqeqeq -- template language operator
    case "==":  return L == R;
    // eslint-disable-next-line eqeqeq -- template language operator
    case "!=":  return L != R;
    case "<":   return L <  R;
    case "<=":  return L <= R;
    case ">":   return L >  R;
    case ">=":  return L >= R;
    case "+":   return L + R;
    case "-":   return L - R;
    case "*":   return L * R;
    case "/":   return L / R;
    default:    throw new Error("template: unknown binary op: " + node.op);
    }
  case "Ternary":
    return _evalExpr(node.cond, scopes) ? _evalExpr(node.thenE, scopes) : _evalExpr(node.elseE, scopes);
  default:
    throw new Error("template: unknown expression node type: " + node.type);
  }
}

function _evalBlock(nodes, scopes, escFn) {
  var out = "";
  for (var i = 0; i < nodes.length; i++) {
    var n = nodes[i];
    switch (n.type) {
    case "Literal":   out += n.text; break;
    case "EscExpr":
      out += escFn(_evalExpr(n.expr, scopes));
      break;
    case "RawExpr":
      var rawV = _evalExpr(n.expr, scopes);
      if (rawV !== null && rawV !== undefined) out += String(rawV);
      break;
    case "If":
      if (_evalExpr(n.cond, scopes)) {
        out += _evalBlock(n.thenBody, scopes, escFn);
      } else if (n.elseBody) {
        out += _evalBlock(n.elseBody, scopes, escFn);
      }
      break;
    case "For":
      var src = _evalExpr(n.source, scopes);
      if (src && typeof src.length === "number") {
        for (var fi = 0; fi < src.length; fi++) {
          var loopScope = {};
          loopScope[n.binding] = src[fi];
          scopes.push(loopScope);
          out += _evalBlock(n.body, scopes, escFn);
          scopes.pop();
        }
      }
      break;
    default:
      throw new Error("template: unknown block node type: " + n.type);
    }
  }
  return out;
}

/**
 * @primitive b.template.create
 * @signature b.template.create(opts)
 * @since     0.1.0
 * @related   b.template.render, b.template.escapeHtml
 *
 * Builds an engine instance. With `opts.viewsDir` the returned object
 * exposes `render(viewName, data?)` for one-shot rendering,
 * `compile(viewName)` for AST-only access (caches under viewName),
 * `precompileAll()` for boot-time validation of every `.html` file
 * under `viewsDir`, and `reset()` to drop the AST cache (useful in
 * live-reload workflows).
 *
 * `viewsDir` is optional: an engine created without it serves from a
 * source STRING via `renderString(source, data?, opts?)` and
 * `compileString(source, opts?)` — the read-only / serverless path with
 * no disk read. `{% extends %}` and `{{> partial}}` in a string source
 * resolve through `opts.resolve(name) -> string` (without it, an extends
 * throws and a missing partial inlines empty). The file-backed
 * render/compile/precompileAll refuse when no `viewsDir` is configured.
 *
 * View names are resolved against `viewsDir`; names containing `..`
 * or NUL are refused, and resolved paths outside `viewsDir` throw.
 * Layout-extends and partial-inclusion recursion are bounded at
 * depth 16 to defend against accidental cycles.
 *
 * @opts
 *   viewsDir:        string,                       // optional — directory of .html templates; omit for string-only (renderString) use
 *   cache:           boolean,                      // default true; set false for live-reload
 *   escapeHtml:      function (value) → string,    // override the default 5-character HTML escape
 *   sandbox:         boolean,                      // when true, sandboxHelpers run through b.sandbox.run
 *   sandboxHelpers:  Object<string, string>,        // map of helperName → JS source executed inside the sandbox
 *   sandboxOpts:     { timeoutMs, maxBytes, allowed },
 *
 * @example
 *   // requires: a views directory on disk
 *   var engine = b.template.create({ viewsDir: "./views" });
 *   engine.precompileAll();                                   // fail boot on syntax errors
 *   var html = engine.render("dashboard", { user: { name: "Ada" } });
 *   // → "<h1>Hello Ada</h1>"
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["viewsDir", "cache", "escapeHtml", "sandbox", "sandboxHelpers", "sandboxOpts"], "b.template");
  var viewsDir = null;
  if (opts.viewsDir) {
    if (!nodeFs.existsSync(opts.viewsDir)) {
      throw new Error("template: viewsDir does not exist: " + opts.viewsDir);
    }
    viewsDir = nodePath.resolve(opts.viewsDir);
  }
  var cacheOn = opts.cache !== false;
  var customEscape = typeof opts.escapeHtml === "function" ? opts.escapeHtml : escapeHtml;
  var astCache = {};

  var sandboxedHelpers = null;
  if (opts.sandbox === true) {
    var sbHelpers = opts.sandboxHelpers || {};
    if (typeof sbHelpers !== "object" || Array.isArray(sbHelpers)) {
      throw new Error("template.create: opts.sandboxHelpers must be a { name -> source } object");
    }
    var sbOpts = opts.sandboxOpts || {};
    if (typeof sbOpts !== "object" || Array.isArray(sbOpts)) {
      throw new Error("template.create: opts.sandboxOpts must be an object");
    }
    var sandbox = sandboxModule();
    sandboxedHelpers = {};
    var helperNames = Object.keys(sbHelpers);
    for (var hi = 0; hi < helperNames.length; hi += 1) {
      var hname = helperNames[hi];
      var hsource = sbHelpers[hname];
      if (typeof hsource !== "string" || hsource.length === 0) {
        throw new Error("template.create: opts.sandboxHelpers[" + JSON.stringify(hname) + "] must be a non-empty string");
      }
      sandboxedHelpers[hname] = (function (capturedSource) {
        return function (helperInput) {
          return sandbox.run({
            source:    capturedSource,
            input:     helperInput,
            timeoutMs: sbOpts.timeoutMs,
            maxBytes:  sbOpts.maxBytes,
            allowed:   sbOpts.allowed,
          }).then(function (r) { return r.result; });
        };
      }(hsource));
    }
  }

  function _loadViewFile(name) {
    return nodeFs.readFileSync(_resolveViewPath(viewsDir, name), "utf8");
  }
  function _loadPartialFile(name) {
    var p = _resolvePartialPath(viewsDir, name);
    return p ? nodeFs.readFileSync(p, "utf8") : null;
  }

  function compile(viewName) {
    if (!viewsDir) {
      throw new Error("template: viewsDir not configured — use renderString/compileString for string sources");
    }
    if (cacheOn && astCache[viewName]) return astCache[viewName];
    var source = nodeFs.readFileSync(_resolveViewPath(viewsDir, viewName), "utf8");
    source = _resolveExtends(_loadViewFile, source);
    source = _inlinePartials(_loadPartialFile, source, 0);
    var tokens = _tokenize(source);
    var ast = _parseTokens(tokens);
    if (cacheOn) astCache[viewName] = ast;
    return ast;
  }

  function render(viewName, data) {
    var ast = compile(viewName);
    return _evalBlock(ast.body, [data || {}], customEscape);
  }

  function _stringLoaders(sopts, maxBytes) {
    var resolve = sopts && sopts.resolve;
    if (resolve !== undefined && typeof resolve !== "function") {
      throw new Error("template.compileString: opts.resolve must be a function (name) => string");
    }
    function _capped(s, what) {
      if (typeof s === "string" && Buffer.byteLength(s, "utf8") > maxBytes) {
        throw new Error("template.compileString: " + what + " exceeds maxBytes=" + maxBytes);
      }
      return s;
    }
    var loadView = function (name) {
      var s = resolve ? resolve(name) : undefined;
      if (typeof s !== "string") {
        throw new Error("template.compileString: {% extends \"" + name +
          "\" %} needs opts.resolve(name) to return the layout source");
      }
      return _capped(s, "resolved layout '" + name + "'");
    };
    var loadPartial = function (name) {
      var s = resolve ? resolve(name) : null;
      return typeof s === "string" ? _capped(s, "resolved partial '" + name + "'") : null;
    };
    return { loadView: loadView, loadPartial: loadPartial };
  }

  function compileString(source, sopts) {
    if (typeof source !== "string") {
      throw new Error("template.compileString(source): source must be a string");
    }
    var maxBytes = (sopts && typeof sopts.maxBytes === "number") ? sopts.maxBytes : DEFAULT_STRING_TEMPLATE_BYTES;
    if (Buffer.byteLength(source, "utf8") > maxBytes) {
      throw new Error("template.compileString: source exceeds maxBytes=" + maxBytes +
        " — string templates are bounded against hostile input; raise opts.maxBytes if intentional");
    }
    var ld = _stringLoaders(sopts, maxBytes);
    var resolved = _resolveExtends(ld.loadView, source);
    resolved = _inlinePartials(ld.loadPartial, resolved, 0);
    return _parseTokens(_tokenize(resolved));
  }

  function renderString(source, data, sopts) {
    if (sopts === undefined && data && typeof data === "object" &&
        typeof data.resolve === "function") {
      sopts = data;
      data = undefined;
    }
    var ast = compileString(source, sopts);
    return _evalBlock(ast.body, [data || {}], customEscape);
  }

  function reset() { astCache = {}; }

  function precompileAll() {
    if (!viewsDir) {
      throw new Error("template: viewsDir not configured — precompileAll requires a views directory");
    }
    var compiled = [];
    function walk(dir, prefix) {
      var entries = nodeFs.readdirSync(dir, { withFileTypes: true });
      for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        var rel = prefix ? prefix + "/" + e.name : e.name;
        if (e.isDirectory()) {
          walk(nodePath.join(dir, e.name), rel);
        } else if (e.isFile() && /\.html$/.test(e.name)) {
          var viewName = rel.replace(/\.html$/, "");
          try {
            compile(viewName);
          } catch (err) {
            var wrapped = new Error("template: precompile failed for view '" +
              viewName + "': " + (err && err.message || String(err)));
            wrapped.cause = err;
            wrapped.viewName = viewName;
            throw wrapped;
          }
          compiled.push(viewName);
        }
      }
    }
    walk(viewsDir, "");
    return compiled;
  }

  return {
    compile:        compile,
    render:         render,
    compileString:  compileString,
    renderString:   renderString,
    reset:          reset,
    precompileAll:  precompileAll,
    viewsDir:       viewsDir,
    escapeHtml:     customEscape,
  };
}

var _default = null;
function _ensureDefault() {
  if (!_default) {
    var defaultDir = nodePath.resolve(process.cwd(), "views");
    if (!nodeFs.existsSync(defaultDir)) {
      throw new Error("template.render() default uses <cwd>/views which doesn't exist; " +
        "call template.create({ viewsDir }) for a custom location");
    }
    _default = create({ viewsDir: defaultDir });
  }
  return _default;
}

/**
 * @primitive b.template.render
 * @signature b.template.render(viewName, data?)
 * @since     0.1.0
 * @related   b.template.create
 *
 * Convenience renderer that lazily binds a default engine instance
 * to `<cwd>/views` on first call, then dispatches to its `render()`.
 * Operators with custom view directories (multi-tenant apps,
 * non-cwd-rooted deploys) call `b.template.create({ viewsDir })`
 * instead and keep the engine in their app scope.
 *
 * @example
 *   // requires: ./views/welcome.html on disk
 *   var html = b.template.render("welcome", { name: "Ada" });
 *   // → "<h1>Welcome, Ada</h1>"
 */
function render(viewName, data) {
  return _ensureDefault().render(viewName, data);
}

function _resetDefaultForTest() { _default = null; }

module.exports = {
  create:               create,
  render:               render,
  escapeHtml:           escapeHtml,
  _resetDefaultForTest: _resetDefaultForTest,
};
