/**
 * Canonical ESLint config — used by both local dev (`npx eslint .`) and CI.
 *
 * Previously this lived in two places (tests/eslint.config.js + an inline
 * heredoc in .github/workflows/ci.yml) which silently drifted. Some rules
 * were active in CI only, so developers running lint locally saw a false
 * "all clean" signal for rules that would fail CI. This single file is the
 * source of truth.
 *
 * When editing: every rule here runs in CI. If a rule produces false
 * positives for the codebase, turn it off here — don't add per-line
 * disable-comments.
 */
// Dev dependencies live in tests/node_modules, not beside this file. Node
// resolves them only when the caller sets NODE_PATH — which scripts/release.js
// does and nothing else does, so `npx eslint .` from the repo root, and any test
// that loads this config, failed with a bare "Cannot find module". Resolving the
// fallback here makes the canonical config work however it is invoked.
function _devDep(name) {
  try { return require(name); }
  catch (_e) { return require(require("node:path").join(__dirname, "tests", "node_modules", name)); }
}
var security = _devDep("eslint-plugin-security");

// A constant-time comparison inside a loop that stops at the first match answers
// a question nobody asked: how far down the list the match was. The caller's own
// response time then reports it — matching the first candidate returns sooner
// than matching the last. Every comparison being individually constant-time does
// not help, because the leak is the ITERATION COUNT.
//
// This runs as an ESLint rule rather than a source-scanning check in the
// patterns gate, and that choice was earned. The scanning version had to decide
// what negates a call, where a branch ends, whether a `return` belongs to the
// loop or to a callback inside it, and whether a `break` leaves this loop or a
// nested one — which is re-implementing the grammar with regexes, and it got
// each of those wrong in turn. ESLint is handed a parsed tree, so every one of
// those questions is already answered before the rule is asked.
var LOOPS = ["ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement", "DoWhileStatement"];
var FUNCS = ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"];

function _isTimingCompare(node) {
  var c = node.callee;
  if (c.type === "Identifier") return /^timingSafeEqual$/.test(c.name);
  if (c.type === "MemberExpression" && c.property && c.property.type === "Identifier") {
    return /^timingSafeEqual$/.test(c.property.name);
  }
  return false;
}

// Is `node` used positively within `test`? A mismatch fail-fast — `!eq(...)`,
// `eq(...) === false`, `eq(...) !== true` — stops on a candidate that did not
// match, which reveals nothing about position.
function _isPositive(node, ancestors, testNode) {
  var cur = node;
  // Count the flips rather than stopping at the first one. `!!eq(...)` is a
  // positive match that exits on a hit and leaks the position exactly as the
  // bare call does; treating any `!` as a mismatch guard reads it as safe.
  var flips = 0;
  for (var i = ancestors.length - 1; i >= 0; i--) {
    var p = ancestors[i];
    if (p.type === "UnaryExpression" && p.operator === "!" && p.argument === cur) flips += 1;
    if (p.type === "BinaryExpression") {
      var other = p.left === cur ? p.right : (p.right === cur ? p.left : null);
      if (other && other.type === "Literal") {
        if ((p.operator === "===" || p.operator === "==") && other.value === false) flips += 1;
        if ((p.operator === "!==" || p.operator === "!=") && other.value === true) flips += 1;
      }
    }
    cur = p;
    if (p === testNode) break;
  }
  return flips % 2 === 0;
}

// Does `branch` exit the loop `loop`? A return or throw does, unless it sits
// inside a nested function. A break does only when it targets this loop — an
// unlabelled break inside a nested loop or switch leaves that construct, and the
// candidate scan carries on.
// Every label declared INSIDE the loop's body. A break aimed at one of these
// leaves that construct and the iteration continues, so it is not a loop exit —
// including a labelled block that sits in the loop but outside the branch, which
// looking only inside the branch missed. A label ON the loop itself is not in
// here, so `outer: for (…) { … break outer; }` still counts.
function _labelsInside(loop, sourceCode) {
  var names = [];
  (function walk(node) {
    if (!node || typeof node.type !== "string") return;
    if (node.type === "LabeledStatement") names.push(node.label.name);
    var keys = sourceCode.visitorKeys[node.type] || Object.keys(node);
    for (var k = 0; k < keys.length; k++) {
      var child = node[keys[k]];
      if (Array.isArray(child)) { for (var j = 0; j < child.length; j++) walk(child[j]); }
      else if (child && typeof child.type === "string") walk(child);
    }
  })(loop.body);
  return names;
}

function _exitsLoop(branch, loop, sourceCode) {
  var found = false;
  var scoped = _labelsInside(loop, sourceCode);
  // The candidate loop's OWN label, if it carries one. `outer: for (…) { …
  // continue outer; }` moves to the next candidate and is not an exit, while
  // the same statement inside a nested loop abandons the scan.
  var ownLabel = (loop.parent && loop.parent.type === "LabeledStatement")
    ? loop.parent.label.name : null;
  (function walk(node, fnDepth, breakDepth, innerLabels) {
    if (found || !node || typeof node.type !== "string") return;
    if (FUNCS.indexOf(node.type) !== -1) fnDepth += 1;
    if (node.type === "LabeledStatement") innerLabels = innerLabels.concat([node.label.name]);
    // The branch itself may BE a loop or switch — `if (eq(…)) while (c) break;`
    // — and it owns that break just as a nested one would. Excluding the branch
    // node read the break as leaving the candidate loop.
    var ownsBreak = LOOPS.indexOf(node.type) !== -1 || node.type === "SwitchStatement";
    if (ownsBreak) breakDepth += 1;
    if (fnDepth === 0) {
      if (node.type === "ReturnStatement" || node.type === "ThrowStatement") { found = true; return; }
      if (node.type === "BreakStatement") {
        if (node.label) {
          // Only a label on something enclosing the LOOP carries control past
          // it. A label declared anywhere inside the loop body — in this branch
          // or in a block beside it — ends within the iteration.
          var name = node.label.name;
          if (innerLabels.indexOf(name) === -1 && scoped.indexOf(name) === -1) { found = true; return; }
        } else if (breakDepth === 0) { found = true; return; }
      }
      if (node.type === "ContinueStatement") {
        // A bare `continue` moves to the next candidate — the loop runs on, and
        // that is the correct shape. A LABELLED continue aimed at an enclosing
        // loop abandons this loop's remaining candidates entirely, which is the
        // same early exit a labelled break performs.
        if (node.label && node.label.name !== ownLabel && scoped.indexOf(node.label.name) === -1) {
          found = true; return;
        }
      }
    }
    var keys = sourceCode.visitorKeys[node.type] || Object.keys(node);
    for (var k = 0; k < keys.length; k++) {
      var child = node[keys[k]];
      if (Array.isArray(child)) { for (var j = 0; j < child.length; j++) walk(child[j], fnDepth, breakDepth, innerLabels); }
      else if (child && typeof child.type === "string") walk(child, fnDepth, breakDepth, innerLabels);
    }
  })(branch, 0, 0, []);
  return found;
}

var noEarlyExitTimingCompare = {
  meta: {
    type: "problem",
    docs: { description: "a constant-time compare in a loop must compare every candidate" },
    schema: [],
    messages: {
      earlyExit:
        "This constant-time comparison sits in a loop that stops at the first match, so the response time reports the match's POSITION. Compare every candidate — keep the first match with a guard placed after the comparison (`if (eq(...) && idx === -1) idx = i;`), or use b.crypto.timingSafeEqualAny when only a boolean is needed.",
    },
  },
  create: function (context) {
    var sourceCode = context.sourceCode || context.getSourceCode();
    return {
      CallExpression: function (node) {
        if (!_isTimingCompare(node)) return;
        var ancestors = sourceCode.getAncestors ? sourceCode.getAncestors(node) : context.getAncestors();

        // The enclosing if-test this call participates in, and the enclosing
        // loop — both only while no function boundary intervenes.
        var ifNode = null;
        var loop = null;
        for (var i = ancestors.length - 1; i >= 0; i--) {
          var a = ancestors[i];
          if (FUNCS.indexOf(a.type) !== -1) break;
          if (!ifNode && a.type === "IfStatement") { ifNode = a; continue; }
          if (ifNode && LOOPS.indexOf(a.type) !== -1) { loop = a; break; }
        }
        if (ifNode && loop) {
          // The call must be in the CONDITION, not the body.
          var inTest = node.range[0] >= ifNode.test.range[0] && node.range[1] <= ifNode.test.range[1];
          // A ternary between the call and the test decides polarity by which
          // arm carries which value, which this does not read. Same reasoning as
          // the wrapper list below: decline rather than guess.
          var viaTernary = ancestors.some(function (a) {
            return a.type === "ConditionalExpression"
              && a.range[0] >= ifNode.test.range[0] && a.range[1] <= ifNode.test.range[1];
          });
          if (inTest && !viaTernary) {
            // Whichever branch a MATCH selects is the one that matters. A
            // negated condition sends the match to the alternate, so
            // `if (!eq(...)) continue; else return c;` exits on the first match
            // exactly as the positive form does — checking only the consequent
            // reads it as safe.
            var onMatch = _isPositive(node, ancestors, ifNode.test) ? ifNode.consequent : ifNode.alternate;
            if (onMatch && _exitsLoop(onMatch, loop, sourceCode)) {
              context.report({ node: node, messageId: "earlyExit" });
            }
          }
          return;
        }

        // Stored-result form: `var matched = eq(a, c); if (matched) break;`.
        // The same leak, and the ordinary way to write it once the condition
        // grows past one line — so the name has to be followed, not just the
        // call site inspected.
        // Walk out through expression wrappers before deciding this is not an
        // assignment. `var hit = eq(a, c) === true;` and `hit = eq(a, c) &&
        // enabled;` store the comparison just as plainly as a bare call does;
        // requiring the call to BE the initialiser let both through.
        // ConditionalExpression is deliberately NOT here. Its polarity depends
        // on which arm holds which literal — `eq(…) ? false : true` inverts —
        // and a wrapper whose direction this cannot read is one that reports
        // mismatch fail-fast code as a leak. For an error-level gate, declining
        // to judge a shape is the safe direction; missing `hit = eq(…) ? true :
        // false` costs a detection nobody writes, while a false positive blocks
        // the release on correct code.
        var WRAPPERS = ["UnaryExpression", "BinaryExpression", "LogicalExpression"];
        var stored = node;
        var enclosing = null;
        var decl = null;
        // Following the wrapper is not enough — it can INVERT the value.
        // `let mismatch = !eq(a, c); if (mismatch) return false;` is a fail-fast
        // on a non-match and reveals no position, so counting the binding as a
        // match reports correct code. Track the flips through the initialiser
        // and fold them into the condition's own polarity below.
        var storedFlips = 0;
        var prev = node;
        for (var d = ancestors.length - 1; d >= 0; d--) {
          var an = ancestors[d];
          if (FUNCS.indexOf(an.type) !== -1) break;
          if (!decl && WRAPPERS.indexOf(an.type) !== -1) {
            if (an.type === "UnaryExpression" && an.operator === "!" && an.argument === prev) storedFlips += 1;
            if (an.type === "BinaryExpression") {
              var o = an.left === prev ? an.right : (an.right === prev ? an.left : null);
              if (o && o.type === "Literal") {
                if ((an.operator === "===" || an.operator === "==") && o.value === false) storedFlips += 1;
                if ((an.operator === "!==" || an.operator === "!=") && o.value === true) storedFlips += 1;
              }
            }
            stored = an; prev = an; continue;
          }
          if (!decl && an.type === "VariableDeclarator" && an.init === stored) decl = an;
          if (!decl && an.type === "AssignmentExpression" && an.right === stored) decl = an;
          if (decl && LOOPS.indexOf(an.type) !== -1) { enclosing = an; break; }
        }
        if (!decl || !enclosing) return;
        var idNode = decl.id || (decl.left && decl.left.type === "Identifier" ? decl.left : null);
        if (!idNode) return;

        // Resolve the BINDING, not the name. An inner block may shadow it —
        // `var hit = eq(...); { let hit = true; if (hit) break; }` — and the
        // inner `hit` has nothing to do with the comparison.
        //
        // Resolved through the identifier's own reference rather than by
        // matching definition nodes: `let hit; ... hit = eq(...)` writes through
        // a reference whose identifier is NOT any def's node, so a def-identity
        // check can never match it and the plain assignment form — the one this
        // block exists to catch — went unreported.
        var variable = null;
        var scope = sourceCode.getScope ? sourceCode.getScope(idNode) : null;
        while (scope && !variable) {
          for (var ri = 0; ri < scope.references.length; ri++) {
            if (scope.references[ri].identifier === idNode && scope.references[ri].resolved) {
              variable = scope.references[ri].resolved;
              break;
            }
          }
          if (!variable) {
            for (var vi = 0; vi < scope.variables.length; vi++) {
              if (scope.variables[vi].defs.some(function (d) { return d.name === idNode; })) {
                variable = scope.variables[vi];
                break;
              }
            }
          }
          scope = scope.upper;
        }
        if (!variable) return;

        // Each place that binding is READ. The condition gets the same polarity
        // analysis a direct call does, so `if (hit === true)`, `if (!!hit)` and
        // `if (hit && enabled)` are treated as the match branches they are —
        // requiring the identifier to BE the whole test recognised only the
        // simplest spelling of the same leak.
        var hit = variable.references.some(function (ref) {
          if (!ref.isRead()) return false;
          var idf = ref.identifier;
          // The read must be INSIDE the loop. A decision taken after it —
          // `for (…) { hit = eq(…); } if (hit) return …;` — is the correct
          // shape: every candidate was compared and the answer used once. Left
          // unscoped, that secure form is reported and the gate blocks it.
          if (idf.range[0] < enclosing.range[0] || idf.range[1] > enclosing.range[1]) return false;
          var chain = [];
          var walkUp = idf.parent;
          while (walkUp && walkUp.type !== "IfStatement") {
            if (["UnaryExpression", "BinaryExpression", "LogicalExpression"].indexOf(walkUp.type) === -1) return false;
            chain.push(walkUp);
            walkUp = walkUp.parent;
          }
          if (!walkUp || walkUp.type !== "IfStatement") return false;
          // The condition's polarity combined with the initialiser's: a negated
          // store read positively is a MISMATCH branch, and vice versa.
          var positiveMatch = _isPositive(idf, chain, walkUp.test) === (storedFlips % 2 === 0);
          var branch = positiveMatch ? walkUp.consequent : walkUp.alternate;
          return !!branch && _exitsLoop(branch, enclosing, sourceCode);
        });
        if (hit) context.report({ node: node, messageId: "earlyExit" });
      },
    };
  },
};

module.exports = [
  {
    ignores: [
      "node_modules/**",
      "tests/**",
      "public/js/**",
      "lib/vendor/**",
      ".vendor-blamejs.tmp/**",
      "template/**",
      "scripts/**",
      "deploy/**",
      ".test-output/**",
    ],
  },
  {
    files: ["**/*.js"],
    plugins: {
      security: security,
      hermitstash: { rules: { "no-early-exit-timing-compare": noEarlyExitTimingCompare } },
    },
    linterOptions: { reportUnusedDisableDirectives: "error" },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        require: "readonly",
        module: "readonly",
        exports: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
        process: "readonly",
        console: "readonly",
        Buffer: "readonly",
        setTimeout: "readonly",
        setInterval: "readonly",
        setImmediate: "readonly",
        clearTimeout: "readonly",
        clearInterval: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        global: "readonly",
        crypto: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
      },
    },
    rules: {
      "hermitstash/no-early-exit-timing-compare": "error",
      // Promoted to error: these accumulated silently across two refactor
      // passes (v1.8.14 auth-gate consolidation, v1.8.15 resolveLocalPath
      // extraction) because "warn" only surfaced as CI annotations that
      // noone bounced on. Prefix intentionally unused vars with `_` to
      // skip the check (argsIgnorePattern + caughtErrorsIgnorePattern).
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
      // Flat config does not enable this by default, and nothing else here was
      // catching a read of a name that is never declared. A refactor that
      // deletes a `var` still referenced further down produces code that parses,
      // lints clean, boots, and then throws ReferenceError the first time that
      // path runs — which for a request handler means the first request of that
      // shape, not startup. `no-unused-vars` only sees the other half of that
      // mistake (a binding left behind), so it cannot substitute.
      "no-undef": "error",
      "no-console": "off",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-self-compare": "error",
      "no-constructor-return": "error",
      "no-new-wrappers": "error",
      "no-throw-literal": "error",

      "security/detect-eval-with-expression": "error",
      "security/detect-child-process": "warn",
      "security/detect-unsafe-regex": "error",
      "security/detect-buffer-noassert": "error",
      "security/detect-new-buffer": "error",
      "security/detect-possible-timing-attacks": "warn",
      "security/detect-pseudoRandomBytes": "warn",
      "security/detect-object-injection": "off",
      "security/detect-non-literal-fs-filename": "off",
      "security/detect-non-literal-require": "off",
      "security/detect-non-literal-regexp": "off",
    },
  },
];
