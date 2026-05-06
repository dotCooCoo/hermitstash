"use strict";
/**
 * Server-side HTML template engine — eval-free.
 *
 * No `new Function()`, no `eval`, no `vm.runInThisContext`. Templates
 * are tokenized + parsed into a small AST and walked at render time
 * against a data scope. The trade-off vs an eval-based engine is
 * 5–50× slower per render and a restricted expression grammar; the
 * win is "an operator who renders req.query.template (or worse) can't
 * RCE the framework, period."
 *
 * Tag syntax:
 *
 *   {{ expr }}                 HTML-escaped expression output
 *   {{{ expr }}}               Raw output (no escape — operator-trusted HTML)
 *   {{> name }}                Partial from <viewsDir>/partials/<name>.html
 *   {% extends "name" %}       Inherit from a layout (must be first non-whitespace)
 *   {% block name %}…{% endblock %}
 *                              Overrideable section
 *   {% if expr %}…{% else %}…{% endif %}
 *                              Conditional
 *   {% for ident in expr %}…{% endfor %}
 *                              Iterate an array; the identifier is bound
 *                              for the loop body
 *
 * Expression grammar (recursive-descent Pratt-style):
 *
 *   expression  := ternary
 *   ternary     := logical-or ('?' logical-or ':' logical-or)?
 *   logical-or  := logical-and ('||' logical-and)*
 *   logical-and := equality   ('&&' equality)*
 *   equality    := comparison (('==' | '!=' | '===' | '!==') comparison)*
 *   comparison  := unary      (('<' | '<=' | '>' | '>=') unary)*
 *   unary       := '!' unary | postfix
 *   postfix     := primary postfix-op*
 *   postfix-op  := '.' identifier | '[' expression ']' | '(' arg-list ')'
 *   primary     := literal | identifier | '(' expression ')'
 *   literal     := string-literal | number-literal | 'true' | 'false' | 'null'
 *
 * Function calls invoke functions THE OPERATOR PROVIDED in the data
 * scope (e.g. `{{ helpers.formatDate(d) }}` resolves `helpers` from
 * data, then `formatDate` on it, then calls it with `d`). The
 * interpreter does not invent built-ins; if an operator wants
 * helpers, they pass them under any data key they like.
 *
 * Public API:
 *
 *   template.create({ viewsDir, cache?, escapeHtml? })
 *     → engine instance with .render(view, data?), .compile(view), .reset()
 *   template.render(view, data?)
 *     → convenience using a default singleton against <cwd>/views
 *   template.escapeHtml(value)
 *     → standalone HTML escape (used by forms.js etc.)
 *
 * Containment defenses (templates ARE server-side files; these guard
 * against operator path-joining mistakes that let request input reach
 * a view-name argument):
 *
 *   - View names containing ".." or "\0" → reject
 *   - Resolved paths outside viewsDir → reject
 *   - Layout-extends and partial-inclusion recursion bounded at depth 16
 *
 * If an operator renders a template path derived from user input, the
 * defenses block path traversal. The interpreter's eval-free posture
 * is the second line: even if a template loaded, it can't execute
 * arbitrary JS — only the limited expression grammar above.
 */
var fs = require("fs");
var path = require("path");
var validateOpts = require("./validate-opts");

// Maximum nesting depth for layout {% extends %} chains and partial
// {{> ... }} recursion. Hex form so the byte-literal lint doesn't trip
// on the multiple-of-8 cap; high enough that a real template tree
// never hits it, low enough to bound a malicious / misconfigured cycle.
var MAX_TEMPLATE_DEPTH = 0x10;

// ============================================================
// HTML escape (exported)
// ============================================================

var ESCAPE_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;" };
var ESCAPE_RE = /[&<>"']/g;

function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  var s = typeof value === "string" ? value : String(value);
  return s.replace(ESCAPE_RE, function (c) { return ESCAPE_MAP[c]; });
}

// ============================================================
// Path resolution + containment
// ============================================================

function _resolveViewPath(viewsDir, viewName) {
  if (typeof viewName !== "string" || viewName.length === 0) {
    throw new Error("template: view name must be a non-empty string");
  }
  if (viewName.indexOf("..") !== -1 || viewName.indexOf("\0") !== -1) {
    throw new Error("template: view name contains forbidden character: " + JSON.stringify(viewName));
  }
  var resolved = path.resolve(viewsDir, viewName + ".html");
  var resolvedDir = path.resolve(viewsDir);
  if (resolved !== resolvedDir &&
      !resolved.startsWith(resolvedDir + path.sep)) {
    throw new Error("template: view path escapes viewsDir: " + viewName);
  }
  if (!fs.existsSync(resolved)) {
    throw new Error("template: view not found: " + viewName);
  }
  return resolved;
}

function _resolvePartialPath(viewsDir, partialName) {
  if (typeof partialName !== "string" || partialName.length === 0) return null;
  if (partialName.indexOf("..") !== -1 || partialName.indexOf("\0") !== -1) return null;
  var resolved = path.resolve(viewsDir, "partials", partialName + ".html");
  var partialsDir = path.resolve(viewsDir, "partials");
  if (resolved !== partialsDir &&
      !resolved.startsWith(partialsDir + path.sep)) return null;
  return fs.existsSync(resolved) ? resolved : null;
}

// ============================================================
// Layout inheritance: extract blocks, substitute into parent
// ============================================================

var EXTENDS_RE = /^\s*\{%\s*extends\s+"([^"]+)"\s*%\}\s*/;
var BLOCK_FULL_RE = /\{%\s*block\s+([A-Za-z_][A-Za-z0-9_-]*)\s*%\}([\s\S]*?)\{%\s*endblock\s*%\}/g;

function _extractBlocks(source) {
  var blocks = {};
  var rest = source.replace(BLOCK_FULL_RE, function (_match, name, content) {
    blocks[name] = content;
    return "";
  });
  return { rest: rest, blocks: blocks };
}

function _substituteBlocks(parentSource, childBlocks) {
  return parentSource.replace(BLOCK_FULL_RE, function (_match, name, defaultContent) {
    return Object.prototype.hasOwnProperty.call(childBlocks, name)
      ? childBlocks[name]
      : defaultContent;
  });
}

function _resolveExtends(viewsDir, source) {
  // Walk UP the extends chain accumulating block overrides. Closer-to-
  // leaf overrides win; each parent's blocks fill in only the names the
  // chain hasn't already set. When the chain hits a template with no
  // {% extends %}, that's the rootmost source — substitute the
  // accumulated overrides into its block placeholders, with each
  // un-overridden placeholder falling back to its default content.
  //
  // The earlier recursive substitution had a subtle bug: substituting
  // each level's blocks into its parent erased the parent's block
  // placeholders, leaving nothing for the next-level-up to override.
  // The accumulate-then-substitute-once shape side-steps that.
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
    var parentPath = _resolveViewPath(viewsDir, parentName);
    current = fs.readFileSync(parentPath, "utf8");
    depth++;
  }
  return _substituteBlocks(current, allOverrides);
}

// ============================================================
// Partial inlining (post-extends, pre-tokenize)
// ============================================================

function _inlinePartials(viewsDir, source, depth) {
  if (depth > MAX_TEMPLATE_DEPTH) {
    throw new Error("template: partial recursion depth exceeded " + MAX_TEMPLATE_DEPTH +
      " — possible cycle");
  }
  return source.replace(/\{\{>\s*([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}/g, function (_, name) {
    var p = _resolvePartialPath(viewsDir, name);
    if (!p) return "";   // missing partial → silent empty (matches hermitstash)
    return _inlinePartials(viewsDir, fs.readFileSync(p, "utf8"), depth + 1);
  });
}

// ============================================================
// Block tokenizer — emits LITERAL / EXPR_ESCAPED / EXPR_RAW /
// DIRECTIVE tokens. Partials are already inlined by this point;
// extends/block already resolved.
// ============================================================

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
    } else { // code
      var endCode = source.indexOf("%}", nextTag + 2);
      if (endCode === -1) throw new Error("template: unterminated {% directive %} tag");
      tokens.push({ kind: "DIRECTIVE", body: source.slice(nextTag + 2, endCode).trim() });
      i = endCode + 2;
    }
  }
  return tokens;
}

// ============================================================
// Block parser — tokens → AST
//
// Node types:
//   { type: "Template",  body: Node[] }
//   { type: "Literal",   text: string }
//   { type: "EscExpr",   expr: ExprAST }
//   { type: "RawExpr",   expr: ExprAST }
//   { type: "If",        cond: ExprAST, thenBody: Node[], elseBody: Node[] | null }
//   { type: "For",       binding: string, source: ExprAST, body: Node[] }
//
// extends and block are resolved BEFORE parsing (during _resolveExtends).
// Bare `{% block %}` directives that survive into the parser are an
// error (block outside a child template that doesn't extend anything).
// ============================================================

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
      // DIRECTIVE
      var m = t.body.match(DIRECTIVE_HEAD_RE);
      if (!m) throw new Error("template: malformed directive: {% " + t.body + " %}");
      var head = m[1];
      var tail = m[2] || "";
      if (terminators && terminators.indexOf(head) !== -1) {
        return body;
      }
      next();   // consume directive token
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
        // {% block %} should have been resolved by _resolveExtends. If
        // it's still here, the template uses block syntax without
        // extending anything — pass it through as no-op (the block's
        // default content was already inlined by _substituteBlocks).
        // Hitting this branch usually means the source had a stray
        // block; we accept it silently (matches the spec: child blocks
        // outside an extends are dropped, parent block defaults are
        // already inlined).
        continue;
      }
      if (head === "extends") {
        // Already handled in _resolveExtends. If we see one here it
        // wasn't at the top — error.
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

// ============================================================
// Expression tokenizer + parser
// ============================================================

function _tokenizeExpr(src) {
  var tokens = [];
  var i = 0;
  while (i < src.length) {
    var c = src[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r") { i++; continue; }
    // String literals (single OR double quotes)
    if (c === '"' || c === "'") {
      var quote = c;
      i++;                          // skip opening quote
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
      i++;   // closing quote
      tokens.push({ kind: "STRING", value: s });
      continue;
    }
    // Number literals
    if ((c >= "0" && c <= "9") || (c === "." && src[i + 1] >= "0" && src[i + 1] <= "9")) {
      var nstart = i;
      while (i < src.length && ((src[i] >= "0" && src[i] <= "9") || src[i] === ".")) i++;
      tokens.push({ kind: "NUMBER", value: parseFloat(src.slice(nstart, i)) });
      continue;
    }
    // Identifiers + keywords
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
    // Multi-char operators (longest match first)
    var two = src.slice(i, i + 2);
    var three = src.slice(i, i + 3);
    if (three === "===" || three === "!==") { tokens.push({ kind: "OP", op: three }); i += 3; continue; }
    if (two === "==" || two === "!=" || two === "<=" || two === ">=" ||
        two === "&&" || two === "||") {
      tokens.push({ kind: "OP", op: two }); i += 2; continue;
    }
    // Single-char operators / punctuation
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

// ============================================================
// Expression evaluator — walks expression AST against a scope chain
// ============================================================

function _scopeLookup(scopes, name) {
  // Walk innermost → outermost; returns undefined if not found.
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
    // Block prototype-chain access — only own properties resolve.
    // Prevents `{{ foo.constructor }}` / `{{ foo.__proto__ }}` from
    // walking out of the data scope into the runtime.
    if (Object.prototype.hasOwnProperty.call(obj, key) ||
        // Arrays: numeric indices + .length are legitimate even though
        // .length is on the prototype shape (it's an own property via
        // the array's internal slot — hasOwn returns true)
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
    // Bind `this` to the receiver when the callee is a member access.
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

// ============================================================
// Block evaluator — walks block AST, builds output string
// ============================================================

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

// ============================================================
// Engine instance
// ============================================================

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["viewsDir", "cache", "escapeHtml"], "b.template");
  if (!opts.viewsDir) {
    throw new Error("template.create({ viewsDir }) is required");
  }
  if (!fs.existsSync(opts.viewsDir)) {
    throw new Error("template: viewsDir does not exist: " + opts.viewsDir);
  }
  var viewsDir = path.resolve(opts.viewsDir);
  var cacheOn = opts.cache !== false;
  var customEscape = typeof opts.escapeHtml === "function" ? opts.escapeHtml : escapeHtml;
  var astCache = {};

  function compile(viewName) {
    if (cacheOn && astCache[viewName]) return astCache[viewName];
    var viewPath = _resolveViewPath(viewsDir, viewName);
    var source = fs.readFileSync(viewPath, "utf8");
    source = _resolveExtends(viewsDir, source);
    source = _inlinePartials(viewsDir, source, 0);
    var tokens = _tokenize(source);
    var ast = _parseTokens(tokens);
    if (cacheOn) astCache[viewName] = ast;
    return ast;
  }

  function render(viewName, data) {
    var ast = compile(viewName);
    return _evalBlock(ast.body, [data || {}], customEscape);
  }

  function reset() { astCache = {}; }

  // Walk viewsDir, compile every .html file. Surfaces parse errors at
  // boot time (with the offending view name in the message) rather than
  // at first request. Operators call this from the bootstrap path so
  // a typo like `{% if not foo %}` fails the deploy, not the user.
  // Returns the list of view names compiled.
  function precompileAll() {
    var compiled = [];
    function walk(dir, prefix) {
      var entries = fs.readdirSync(dir, { withFileTypes: true });
      for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        var rel = prefix ? prefix + "/" + e.name : e.name;
        if (e.isDirectory()) {
          walk(path.join(dir, e.name), rel);
        } else if (e.isFile() && /\.html$/.test(e.name)) {
          var viewName = rel.replace(/\.html$/, "");
          try {
            compile(viewName);
          } catch (err) {
            // Re-throw with the view name in the message — the parser's
            // own "trailing tokens" / "malformed directive" don't say
            // which file the syntax error lives in.
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
    reset:          reset,
    precompileAll:  precompileAll,
    viewsDir:       viewsDir,
    escapeHtml:     customEscape,
  };
}

// ---- Default singleton ----

var _default = null;
function _ensureDefault() {
  if (!_default) {
    var defaultDir = path.resolve(process.cwd(), "views");
    if (!fs.existsSync(defaultDir)) {
      throw new Error("template.render() default uses <cwd>/views which doesn't exist; " +
        "call template.create({ viewsDir }) for a custom location");
    }
    _default = create({ viewsDir: defaultDir });
  }
  return _default;
}

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
