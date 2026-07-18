// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.template — the eval-free server-side HTML template engine.
 *
 * escapeHtml has its own dedicated pin (template-escape-html.test.js); this
 * file exercises the render/compile machinery and — the point of the file —
 * the error / adversarial / defensive / option-default branches that the
 * happy-path examples never reach: path-containment rejection, unterminated
 * and malformed tags, the expression-grammar parse errors, the eval-time
 * guards (own-property-only member access, call-of-non-function), the
 * string-source (renderString) byte cap + resolve-callback contract, extends
 * / partial recursion caps, cache/reset behavior, precompileAll boot
 * validation, and the create() opt validation (viewsDir, sandbox opts).
 *
 * The XSS boundary is asserted throughout: {{ expr }} output is HTML-escaped,
 * {{{ raw }}} is not, and injection-shaped data lands escaped in the output.
 *
 * Run standalone: `node test/layer-0-primitives/template.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;
var check = helpers.check;

var NUL = String.fromCharCode(0);

// ---- tiny local fixtures ----

function _mkdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-template-"));
}
function _write(dir, rel, content) {
  var abs = path.join(dir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}
function _rm(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

// A file-backed engine seeded with a { relPath -> content } map.
function _fileEngine(files, opts) {
  var dir = _mkdir();
  Object.keys(files || {}).forEach(function (rel) { _write(dir, rel, files[rel]); });
  var engine = b.template.create(Object.assign({ viewsDir: dir }, opts || {}));
  return { dir: dir, engine: engine, cleanup: function () { _rm(dir); } };
}

function _expectThrows(label, fn, substr) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label + " — throws", threw !== null);
  if (substr && threw) {
    check(label + " — message contains " + JSON.stringify(substr),
          String(threw.message).indexOf(substr) !== -1);
  }
}

// ============================================================
// Happy-path render (files) — the baseline the error branches sit around
// ============================================================

function testFileRenderHappyPathEscapes() {
  var ctx = _fileEngine({
    "page.html":
      "<h1>{{ title }}</h1>" +
      "{% if show %}<p>{{ body }}</p>{% else %}<p>hidden</p>{% endif %}" +
      "<ul>{% for item in items %}<li>{{ item.name }}</li>{% endfor %}</ul>" +
      "<footer>{{{ rawHtml }}}</footer>",
  });
  try {
    var out = ctx.engine.render("page", {
      title: "<script>alert(1)</script>",
      show: true,
      body: "a & b",
      items: [{ name: "<b>x</b>" }, { name: "y'z" }],
      rawHtml: "<em>trusted</em>",
    });
    // {{ }} escapes the five attack chars; {{{ }}} passes raw.
    check("title HTML-escaped in {{ }}",
          out.indexOf("<h1>&lt;script&gt;alert(1)&lt;/script&gt;</h1>") !== -1);
    check("if-branch body escaped", out.indexOf("<p>a &amp; b</p>") !== -1);
    check("for-loop escapes each item",
          out.indexOf("<li>&lt;b&gt;x&lt;/b&gt;</li>") !== -1 &&
          out.indexOf("<li>y&#x27;z</li>") !== -1);
    check("{{{ raw }}} not escaped", out.indexOf("<footer><em>trusted</em></footer>") !== -1);

    // else-branch + no-else (elseBody null) paths.
    var elseOut = ctx.engine.render("page", { title: "t", show: false, body: "x", items: [], rawHtml: "" });
    check("else branch renders when cond false", elseOut.indexOf("<p>hidden</p>") !== -1);
    check("empty for-loop emits nothing", elseOut.indexOf("<ul></ul>") !== -1);
    check("engine exposes resolved viewsDir", ctx.engine.viewsDir === path.resolve(ctx.dir));
    check("engine exposes escapeHtml", ctx.engine.escapeHtml === b.template.escapeHtml);
  } finally {
    ctx.cleanup();
  }
}

// ============================================================
// Path containment — _resolveViewPath rejections
// ============================================================

function testViewPathContainment() {
  var ctx = _fileEngine({ "index.html": "ok" });
  try {
    check("valid view renders", ctx.engine.render("index") === "ok");
    _expectThrows("view name with ..", function () { ctx.engine.render("../secret"); },
                  "forbidden character");
    _expectThrows("view name with NUL", function () { ctx.engine.render("foo" + NUL + "bar"); },
                  "forbidden character");
    _expectThrows("empty view name", function () { ctx.engine.render(""); },
                  "non-empty string");
    _expectThrows("non-string view name", function () { ctx.engine.render(123); },
                  "non-empty string");
    _expectThrows("missing view", function () { ctx.engine.render("does-not-exist"); },
                  "view not found");
    // Absolute view name (no "..") resolves outside viewsDir → escape guard.
    var escapee = path.parse(ctx.dir).root + "blamejs_escape_probe";
    _expectThrows("absolute name escapes viewsDir", function () { ctx.engine.render(escapee); },
                  "escapes viewsDir");
  } finally {
    ctx.cleanup();
  }
}

// ============================================================
// Partials — inlining, missing → empty, recursion cap
// ============================================================

function testPartials() {
  var ctx = _fileEngine({
    "host.html":            "top {{> header }} mid {{> missing }} bot",
    "partials/header.html": "<nav>{{ label }}</nav>",
    "loop-host.html":       "{{> loopy }}",
    "partials/loopy.html":  "x{{> loopy }}",
  });
  try {
    var out = ctx.engine.render("host", { label: "a<b" });
    check("present partial inlined + inner expr escaped",
          out === "top <nav>a&lt;b</nav> mid  bot");
    check("missing partial inlines empty (no crash)", out.indexOf("mid  bot") !== -1);
    _expectThrows("self-referential partial hits recursion cap",
                  function () { ctx.engine.render("loop-host", {}); },
                  "partial recursion depth exceeded");
  } finally {
    ctx.cleanup();
  }
}

// ============================================================
// Layout inheritance — extends/block, override, cycle, misplacement
// ============================================================

function testLayoutInheritance() {
  var ctx = _fileEngine({
    "child.html":  '{% extends "layout" %}{% block content %}<i>{{ who }}</i>{% endblock %}',
    "layout.html": "<main>{% block content %}default{% endblock %}<span>{% block side %}s{% endblock %}</span></main>",
    // extends cycle a→b→a
    "cyc-a.html":  '{% extends "cyc-b" %}',
    "cyc-b.html":  '{% extends "cyc-a" %}',
  });
  try {
    var out = ctx.engine.render("child", { who: "a&b" });
    check("child block overrides parent placeholder + escapes",
          out.indexOf("<main><i>a&amp;b</i>") !== -1);
    check("un-overridden parent block keeps its default",
          out.indexOf("<span>s</span>") !== -1);
    _expectThrows("extends cycle hits inheritance depth cap",
                  function () { ctx.engine.render("cyc-a", {}); },
                  "layout inheritance depth exceeded");
    _expectThrows("{% extends %} not at top is rejected",
                  function () { ctx.engine.renderString('hi {% extends "layout" %}'); },
                  "must be the first non-whitespace");
  } finally {
    ctx.cleanup();
  }
}

// ============================================================
// String-source path — renderString / compileString byte cap + resolve
// ============================================================

function testStringSource() {
  var engine = b.template.create();   // no viewsDir → string-only engine

  // Happy: escaping still applies on the string path.
  check("renderString escapes {{ }}",
        engine.renderString("<p>{{ v }}</p>", { v: "<x>" }) === "<p>&lt;x&gt;</p>");
  check("renderString {{{ }}} raw on string path",
        engine.renderString("{{{ v }}}", { v: "<x>" }) === "<x>");
  check("renderString plain literal (no tags)",
        engine.renderString("just text") === "just text");

  // Source-type + byte cap.
  _expectThrows("compileString rejects non-string source",
                function () { engine.compileString(123); }, "must be a string");
  _expectThrows("renderString honors opts.maxBytes cap",
                function () { engine.renderString("hello", {}, { maxBytes: 3 }); },
                "exceeds maxBytes=3");
  // Default 256 KiB cap on hostile string input.
  _expectThrows("renderString hits default byte cap on oversized input",
                function () { engine.renderString("x".repeat(300000)); }, "exceeds maxBytes");

  // resolve-callback contract.
  _expectThrows("opts.resolve must be a function",
                function () { engine.renderString("x", {}, { resolve: 123 }); },
                "resolve must be a function");
  _expectThrows("extends on string path without resolve throws",
                function () { engine.renderString('{% extends "base" %}'); },
                "needs opts.resolve");

  var resolveLayout = function () {
    return "<main>{% block body %}def{% endblock %}</main>";
  };
  check("extends resolves through opts.resolve",
        engine.renderString('{% extends "base" %}{% block body %}<b>{{ w }}</b>{% endblock %}',
                            { w: "a&b" }, { resolve: resolveLayout }) ===
        "<main><b>a&amp;b</b></main>");

  // Two-arg disambiguation: renderString(source, { resolve }) — the middle arg
  // is the opts object (data omitted) when it carries a function `resolve`.
  check("renderString(source, {resolve}) treats 2nd arg as opts",
        engine.renderString('{% extends "b" %}{% block c %}Z{% endblock %}',
                            { resolve: function () { return "{% block c %}d{% endblock %}"; } }) === "Z");

  // Missing partial on the string path (resolve → null) inlines empty.
  check("string-path missing partial inlines empty",
        engine.renderString("a{{> p }}b", {}, { resolve: function () { return null; } }) === "ab");
  // Partial on the string path with NO resolve configured also inlines empty
  // (loadPartial returns null when resolve is absent — no throw, unlike extends).
  check("string-path partial without resolve inlines empty",
        engine.renderString("a{{> p }}b") === "ab");
  check("string-path present partial inlined",
        engine.renderString("a{{> p }}b", {}, { resolve: function () { return "X"; } }) === "aXb");

  // The per-resolved-source byte cap (_capped) fires on oversized layout/partial.
  _expectThrows("resolved layout over cap rejected",
                function () {
                  engine.renderString('{% extends "big" %}{% block b %}x{% endblock %}',
                    {}, { maxBytes: 80, resolve: function () { return "{% block b %}" + "y".repeat(500) + "{% endblock %}"; } });
                }, "resolved layout");
  _expectThrows("resolved partial over cap rejected",
                function () {
                  engine.renderString("a{{> big }}b",
                    {}, { maxBytes: 80, resolve: function () { return "y".repeat(500); } });
                }, "resolved partial");

  // String-path extends / partial recursion caps.
  _expectThrows("string extends cycle hits cap",
                function () { engine.renderString('{% extends "a" %}', {}, { resolve: function () { return '{% extends "a" %}'; } }); },
                "layout inheritance depth exceeded");
  _expectThrows("string partial cycle hits cap",
                function () { engine.renderString("{{> p }}", {}, { resolve: function () { return "{{> p }}"; } }); },
                "partial recursion depth exceeded");
}

// ============================================================
// Block tokenizer / parser structural errors
// ============================================================

function testTokenizeAndParseErrors() {
  var e = b.template.create();
  _expectThrows("unterminated {{ }}",  function () { e.renderString("a {{ x"); }, "unterminated {{ expression }}");
  _expectThrows("unterminated {{{ }}}", function () { e.renderString("a {{{ x"); }, "unterminated {{{ raw }}}");
  _expectThrows("unterminated {% %}",  function () { e.renderString("a {% x"); }, "unterminated {% directive %}");

  _expectThrows("malformed directive (non-alpha head)",
                function () { e.renderString("{% 123 %}"); }, "malformed directive");
  _expectThrows("unknown directive",
                function () { e.renderString("{% frobnicate %}"); }, "unknown directive");
  _expectThrows("invalid for syntax (no 'in')",
                function () { e.renderString("{% for x %}{% endfor %}"); }, "invalid for syntax");
  _expectThrows("truncated if → unexpected end of template",
                function () { e.renderString("{% if a %}yes"); }, "unexpected end of template");
  _expectThrows("truncated for → unexpected end of template",
                function () { e.renderString("{% for x in xs %}body"); }, "unexpected end of template");

  // Stray {% block %} outside an extends is accepted (default already inlined).
  check("stray block passes through as no-op",
        e.renderString("{% block b %}hi{% endblock %}") === "hi");
  // An UNPAIRED block / endblock survives the pre-parse block substitution and
  // reaches the parser's block/endblock pass-through (a no-op there).
  check("stray unpaired {% endblock %} is a parser no-op",
        e.renderString("x{% endblock %}y") === "xy");
  check("stray unclosed {% block %} open is a parser no-op",
        e.renderString("a{% block z %}b") === "ab");
  check("if/else/endif renders then-branch",
        e.renderString("{% if a %}Y{% else %}N{% endif %}", { a: 1 }) === "Y");
  check("if with no else and false cond → empty (elseBody null)",
        e.renderString("{% if a %}Y{% endif %}", { a: 0 }) === "");
}

// ============================================================
// Expression grammar — operators + parse errors
// ============================================================

function testExpressionGrammar() {
  var e = b.template.create();
  function r(src, data) { return e.renderString("{{ " + src + " }}", data || {}); }

  check("addition",        r("1 + 2") === "3");
  check("subtraction",     r("10 - 3") === "7");
  check("multiplication",  r("2 * 4") === "8");
  check("division",        r("9 / 3") === "3");
  check("paren precedence", r("(1 + 2) * 3") === "9");
  check("unary minus",     r("-n", { n: 5 }) === "-5");
  check("unary not",       r("!flag", { flag: false }) === "true");
  check("logical and",     r("a && b", { a: true, b: "kept" }) === "kept");
  check("logical or",      r("a || b", { a: 0, b: "fallback" }) === "fallback");
  check("loose ==",        r("a == b", { a: 1, b: "1" }) === "true");
  check("strict ===",      r("a === b", { a: 1, b: "1" }) === "false");
  check("loose !=",        r("a != b", { a: 1, b: 2 }) === "true");
  check("strict !==",      r("a !== b", { a: 1, b: 1 }) === "false");
  check("less than",       r("a < b", { a: 1, b: 2 }) === "true");
  check("less-equal",      r("a <= b", { a: 2, b: 2 }) === "true");
  check("greater than",    r("a > b", { a: 3, b: 2 }) === "true");
  check("greater-equal",   r("a >= b", { a: 2, b: 3 }) === "false");
  check("ternary",         r("c ? 'yes' : 'no'", { c: true }) === "yes");
  check("boolean literal true",  r("true") === "true");
  check("boolean literal false", r("false") === "false");
  check("null literal → empty",  r("null") === "");
  check("number literal",  r("42") === "42");
  check("decimal literal", r(".5") === "0.5");

  // String escape sequences in the expression tokenizer (raw output so the
  // control chars survive, not HTML-escaped).
  check("string \\n escape", e.renderString('{{{ "a\\nb" }}}') === "a\nb");
  check("string \\t escape", e.renderString('{{{ "a\\tb" }}}') === "a\tb");
  check("string \\r escape", e.renderString('{{{ "a\\rb" }}}') === "a\rb");
  check("string \\\\ escape", e.renderString('{{{ "a\\\\b" }}}') === "a\\b");
  check("unknown string escape passes char through",
        e.renderString('{{{ "a\\qb" }}}') === "aqb");

  // Parse-time errors.
  _expectThrows("empty expression",     function () { r(""); }, "unexpected end of expression");
  _expectThrows("member without ident", function () { r("a."); }, "expected IDENT");
  // expect() names the actually-present token (not just EOF) — `.` followed by
  // a non-identifier reports the token: an operator carries its op ("OP:+"),
  // a value token carries just its kind ("STRING").
  _expectThrows("member followed by operator names the op",
                function () { r("a.+"); }, "got OP:+");
  _expectThrows("member followed by value token names its kind",
                function () { r('a."str"'); }, "got STRING");
  _expectThrows("unclosed computed idx", function () { r("a[0"); }, "expected OP(])");
  _expectThrows("unclosed paren group",  function () { r("(1"); }, "expected OP(");
  _expectThrows("unterminated call arg-list", function () { r("f("); }, "expected OP(");
  _expectThrows("unexpected token (bare op)", function () { r(")"); }, "unexpected token in expression");
  _expectThrows("trailing tokens (ident)", function () { r("a b"); }, "trailing tokens");
  // Trailing token that IS an operator reports its op in the message.
  _expectThrows("trailing operator token names its op", function () { r("a ]"); }, "OP:]");
  _expectThrows("unterminated string",    function () { r('"abc'); }, "unterminated string");
  _expectThrows("unexpected char in expr", function () { r("@"); }, "unexpected character in expression");
}

// ============================================================
// Expression evaluator — member guards, calls, this-binding
// ============================================================

function testEvalSemantics() {
  var e = b.template.create();
  function r(src, data) { return e.renderString("{{ " + src + " }}", data || {}); }

  // Member on null/undefined → undefined → empty (no crash).
  check("member on missing base → empty", r("a.b.c", {}) === "");
  check("computed member reads own prop",
        r("obj[key]", { obj: { hit: "yes" }, key: "hit" }) === "yes");
  check("array .length is legitimate", r("arr.length", { arr: [1, 2, 3] }) === "3");
  check("array non-index member miss → empty (own-prop guard)",
        r("arr.missing", { arr: [1, 2, 3] }) === "");

  // Prototype-chain access is blocked — only own props resolve.
  check("obj.constructor is undefined (not the Function)",
        r("obj.constructor", { obj: { a: 1 } }) === "");
  check("obj.__proto__ is undefined (own-prop guard)",
        r("obj.__proto__", { obj: { a: 1 } }) === "");
  check("obj.toString is undefined (inherited, blocked)",
        r("obj.toString", { obj: { a: 1 } }) === "");

  // Operator-provided helper calls, with `this` bound to the receiver.
  check("helper call from data scope",
        r("fmt(x)", { fmt: function (n) { return "n=" + n; }, x: 7 }) === "n=7");
  check("call with a leading unary-minus arg parses",
        r("fmt(-1)", { fmt: function (n) { return "n=" + n; } }) === "n=-1");
  check("multi-argument call (comma-separated arg list)",
        r("cat(a, b, c)", { cat: function (x, y, z) { return x + y + z; }, a: "p", b: "q", c: "r" }) === "pqr");
  check("method call binds this to receiver",
        r("obj.greet()", { obj: { who: "Ada", greet: function () { return this.who; } } }) === "Ada");
  _expectThrows("calling a non-function (identifier) throws + names it",
                function () { r("notfn()", { notfn: "a string" }); }, "cannot call non-function: notfn");
  _expectThrows("calling a non-function member names the property",
                function () { r("o.x()", { o: { x: "not a fn" } }); }, "cannot call non-function: x");
  _expectThrows("calling a non-function non-name callee reports <expr>",
                function () { r("(1)()", {}); }, "cannot call non-function: <expr>");

  // Ternary false-branch selects the else expression.
  check("ternary false branch selects else",
        r("c ? 'yes' : 'no'", { c: false }) === "no");

  // for-loop over a non-array-like (a number) iterates nothing.
  check("for over non-iterable emits nothing",
        e.renderString("{% for x in n %}!{% endfor %}", { n: 5 }) === "");
  // for over a string is length-indexable → iterates chars.
  check("for over string iterates code units",
        e.renderString("{% for c in s %}{{ c }}{% endfor %}", { s: "ab" }) === "ab");
  // Raw expr resolving to null/undefined emits nothing.
  check("raw expr null → empty", e.renderString("[{{{ missing }}}]") === "[]");
  // Escaped expr resolving to undefined emits empty string.
  check("escaped expr undefined → empty", e.renderString("[{{ missing }}]") === "[]");
}

// ============================================================
// Engine option validation + cache/reset + precompileAll
// ============================================================

function testCreateOptsAndCache() {
  // Unknown opt rejected by validateOpts.
  _expectThrows("unknown create opt rejected",
                function () { b.template.create({ bogusOption: 1 }); }, "unknown option");
  // Nonexistent viewsDir rejected.
  _expectThrows("nonexistent viewsDir rejected",
                function () { b.template.create({ viewsDir: path.join(os.tmpdir(), "blamejs-no-such-" + Date.now()) }); },
                "viewsDir does not exist");

  // String-only engine (no viewsDir) → file APIs refuse.
  var stringOnly = b.template.create();
  _expectThrows("render() without viewsDir refuses",
                function () { stringOnly.render("x"); }, "viewsDir not configured");
  _expectThrows("compile() without viewsDir refuses",
                function () { stringOnly.compile("x"); }, "viewsDir not configured");
  _expectThrows("precompileAll() without viewsDir refuses",
                function () { stringOnly.precompileAll(); }, "viewsDir not configured");

  // Custom escapeHtml override is used by {{ }} interpolation.
  var ctx = _fileEngine({ "v.html": "[{{ x }}]" }, { escapeHtml: function () { return "REPLACED"; } });
  try {
    check("custom escapeHtml override applied", ctx.engine.render("v", { x: "<b>" }) === "[REPLACED]");
    check("engine.escapeHtml is the override", ctx.engine.escapeHtml("anything") === "REPLACED");
  } finally {
    ctx.cleanup();
  }

  // cache ON (default): edit-after-compile is NOT seen until reset().
  var cached = _fileEngine({ "p.html": "v1" });
  try {
    check("first render v1", cached.engine.render("p") === "v1");
    _write(cached.dir, "p.html", "v2");
    check("cache-on: stale AST still returns v1", cached.engine.render("p") === "v1");
    cached.engine.reset();
    check("reset() drops cache → v2", cached.engine.render("p") === "v2");
  } finally {
    cached.cleanup();
  }

  // cache OFF: every render re-reads the file.
  var live = _fileEngine({ "p.html": "a" }, { cache: false });
  try {
    check("cache-off first read a", live.engine.render("p") === "a");
    _write(live.dir, "p.html", "b");
    check("cache-off sees edit immediately → b", live.engine.render("p") === "b");
  } finally {
    live.cleanup();
  }
}

function testPrecompileAll() {
  var ok = _fileEngine({
    "a.html":     "{{ x }}",
    "sub/b.html": "{% if y %}z{% endif %}",
  });
  try {
    var list = ok.engine.precompileAll();
    check("precompileAll returns every compiled view", list.length === 2);
    check("precompileAll walks subdirs",
          list.indexOf("a") !== -1 && list.indexOf("sub/b") !== -1);
  } finally {
    ok.cleanup();
  }

  var bad = _fileEngine({ "broken.html": "{% frobnicate %}" });
  try {
    var threw = null;
    try { bad.engine.precompileAll(); } catch (err) { threw = err; }
    check("precompileAll surfaces a parse error", threw !== null);
    check("wrapped error names the offending view",
          threw && threw.viewName === "broken" &&
          String(threw.message).indexOf("precompile failed for view 'broken'") !== -1);
    check("wrapped error keeps the underlying cause", threw && threw.cause instanceof Error);
  } finally {
    bad.cleanup();
  }
}

// ============================================================
// Sandbox-helper opt validation (construction only — no worker spun)
// ============================================================

function testSandboxHelperValidation() {
  var dir = _mkdir();
  try {
    _expectThrows("sandboxHelpers must be an object (array rejected)",
                  function () { b.template.create({ viewsDir: dir, sandbox: true, sandboxHelpers: [] }); },
                  "sandboxHelpers must be");
    _expectThrows("sandboxOpts must be an object (array rejected)",
                  function () { b.template.create({ viewsDir: dir, sandbox: true, sandboxHelpers: {}, sandboxOpts: [] }); },
                  "sandboxOpts must be an object");
    _expectThrows("helper source must be a non-empty string (empty rejected)",
                  function () { b.template.create({ viewsDir: dir, sandbox: true, sandboxHelpers: { h: "" } }); },
                  "must be a non-empty string");
    _expectThrows("helper source must be a string (number rejected)",
                  function () { b.template.create({ viewsDir: dir, sandbox: true, sandboxHelpers: { h: 123 } }); },
                  "must be a non-empty string");
    // sandbox:true with sandboxHelpers omitted defaults to an empty helper set.
    var noHelpers = b.template.create({ viewsDir: dir, sandbox: true });
    check("sandbox true without sandboxHelpers still builds",
          noHelpers && typeof noHelpers.render === "function");
    // Valid sandbox config builds the engine (helper is wrapped, not run).
    var engine = b.template.create({
      viewsDir: dir, sandbox: true,
      sandboxHelpers: { upper: "return String(input).toUpperCase();" },
      sandboxOpts: { timeoutMs: 100 },
    });
    check("valid sandbox config yields an engine", engine && typeof engine.render === "function");
  } finally {
    _rm(dir);
  }
}

// ============================================================
// Module-level render() + lazy default engine (<cwd>/views)
// ============================================================

function testModuleRenderDefault() {
  var origCwd = process.cwd();
  var base = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-template-cwd-"));
  try {
    // No <cwd>/views → the lazy default refuses.
    b.template._resetDefaultForTest();
    process.chdir(base);
    _expectThrows("module render without <cwd>/views throws",
                  function () { b.template.render("welcome", {}); }, "which doesn't exist");

    // Create <cwd>/views and render through the module singleton.
    b.template._resetDefaultForTest();
    fs.mkdirSync(path.join(base, "views"));
    fs.writeFileSync(path.join(base, "views", "welcome.html"), "<h1>Hi {{ name }}</h1>");
    var out = b.template.render("welcome", { name: "<b>" });
    check("module render binds <cwd>/views + escapes", out === "<h1>Hi &lt;b&gt;</h1>");
  } finally {
    b.template._resetDefaultForTest();
    process.chdir(origCwd);
    _rm(base);
  }
}

// ============================================================

function run() {
  testFileRenderHappyPathEscapes();
  testViewPathContainment();
  testPartials();
  testLayoutInheritance();
  testStringSource();
  testTokenizeAndParseErrors();
  testExpressionGrammar();
  testEvalSemantics();
  testCreateOptsAndCache();
  testPrecompileAll();
  testSandboxHelperValidation();
  testModuleRenderDefault();

  console.log("OK — template (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); }
  catch (e) { console.error("FAIL: " + (e && e.message)); process.exit(1); }
}
