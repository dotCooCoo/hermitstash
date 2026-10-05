// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardGraphql
 * @nav    Guards
 * @title  Guard Graphql
 *
 * @intro
 *   GraphQL request-shape safety guard — validates user-supplied
 *   request bundles against the canonical query-shape DoS catalog
 *   BEFORE the framework hands the query to a schema-aware
 *   executor. KIND is `graphql-request`; the gate consumes
 *   `ctx.graphqlRequest` (or `ctx.gql`) shape `{ query,
 *   operationName?, variables?, extensions? }`. Pair downstream
 *   with the operator's schema-aware parser — this layer is the
 *   shape / depth / breadth contract that runs before any
 *   schema-resolution work.
 *
 *   Query depth caps: deeply-nested selection sets multiply
 *   exponentially against schema depth, bypassing per-field rate
 *   limits. The gate's `_measureQueryShape` walker measures two
 *   depths without a full lex/parse (the operator's executor
 *   handles full parsing) and caps the larger: the raw syntactic
 *   brace nesting, which bounds the recursion a downstream parser
 *   performs on inline fragments and argument objects, and the
 *   fragment-resolved execution depth, which follows `...fragment`
 *   spreads so a shallow operation whose fragment chain nests deep
 *   is measured at its resolved depth. Every definition is
 *   measured, not only the operations, since a parser constructs an
 *   unused fragment before validation rejects it. Strict caps at 8,
 *   balanced 12, permissive 24. The cap fires as
 *   `graphql.depth-exceeded`, the query-shape amplification DoS
 *   class.
 *
 *   Alias-amplification caps: the same field repeated under
 *   different aliases (`a:friend b:friend c:friend ...`) bypasses
 *   per-field limits because each alias is a separate selection.
 *   The distinct alias count is taken per selection set. Strict
 *   caps at 8 aliases per selection-set, balanced 16, permissive
 *   32. Fires as `graphql.alias-bomb`, the breadth-amplification
 *   DoS class.
 *
 *   Fragment-cycle defense: a fragment spread that resolves back to
 *   itself has unbounded resolved depth, so the depth walker refuses
 *   it as `graphql.depth-exceeded` rather than passing a byte-small
 *   query a naive resolver would loop on. The total-bytes cap
 *   (`maxBytes`) and per-query cap (`maxQueryBytes`) bound the
 *   worst-case parser-DoS shape regardless of cycle structure.
 *
 *   Introspection toggle: `__schema` / `__type` queries leak
 *   schema details and tooling expects them in development but
 *   not production. Strict refuses (production posture); balanced
 *   audits; permissive allows. Detection is substring-match on
 *   the query string — fast and impossible to evade with
 *   whitespace tricks.
 *
 *   Persisted-query allowlist: when the operator opts in via
 *   `persistedQueryPolicy: "require"`, the request must carry
 *   `extensions.persistedQuery.sha256Hash`. Free-form queries
 *   are refused as `graphql.persisted-query-missing` — eliminates
 *   ad-hoc query attack surface entirely (operator pre-approves
 *   the catalog of permitted queries by hash).
 *
 *   Operation-name allowlist: when `opts.allowedOperations` is
 *   set, the request `operationName` must be in the list.
 *   Complements the persisted-query approach for operators that
 *   keep free-form queries on but want a denylist for ad-hoc
 *   shapes.
 *
 *   Variable shape validation: when `opts.variableShapes` declares
 *   `{ varName: "string"|"number"|"boolean"|"object" }`, the gate
 *   refuses any `variables` entry whose `typeof` doesn't match.
 *   Catches type-confusion exploits where executors silently
 *   coerce (string-for-ID-expecting-Int).
 *
 *   Batch defense: operators supporting `[{},{}]` batch arrays get
 *   N requests for one HTTP hit. Strict refuses batches outright;
 *   balanced caps at 10; permissive 50. Each batch entry is
 *   validated with the same threat catalog applied recursively.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. BIDI / null /
 *   control / zero-width universal-refuse applies on the query
 *   string at every profile so trojan-source codepoints can't
 *   ride inside a query identifier.
 *
 * @card
 *   GraphQL request-shape safety guard — validates user-supplied request bundles against the canonical query-shape DoS catalog BEFORE the framework hands the query to a schema-aware executor.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var pick = require("./pick");
var { GuardGraphqlError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var IDENTIFIER_POSITION_PREFIXES = ",({:";

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    introspectionPolicy:        "reject",
    persistedQueryPolicy:       "audit",
    operationNamePolicy:        "audit",
    batchPolicy:                "reject",
    aliasBombPolicy:            "reject",
    depthPolicy:                "reject",
    variableShapePolicy:        "reject",
    maxDepth:                   8,
    maxAliasesPerSelection:     8,
    maxBatchSize:               1,
    maxQueryBytes:              C.BYTES.kib(8),
    maxVariableBytes:           C.BYTES.kib(8),
    maxBytes:                   C.BYTES.kib(32),
    maxRuntimeMs:               C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    introspectionPolicy:        "audit",
    persistedQueryPolicy:       "audit",
    operationNamePolicy:        "audit",
    batchPolicy:                "audit",
    aliasBombPolicy:            "audit",
    depthPolicy:                "audit",
    variableShapePolicy:        "audit",
    maxDepth:                   12,
    maxAliasesPerSelection:     16,
    maxBatchSize:               10,
    maxQueryBytes:              C.BYTES.kib(16),
    maxVariableBytes:           C.BYTES.kib(16),
    maxBytes:                   C.BYTES.kib(64),
    maxRuntimeMs:               C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    introspectionPolicy:        "allow",
    persistedQueryPolicy:       "allow",
    operationNamePolicy:        "allow",
    batchPolicy:                "allow",
    aliasBombPolicy:            "audit",
    depthPolicy:                "audit",
    variableShapePolicy:        "audit",
    maxDepth:                   24,
    maxAliasesPerSelection:     32,
    maxBatchSize:               50,
    maxQueryBytes:              C.BYTES.kib(64),
    maxVariableBytes:           C.BYTES.kib(64),
    maxBytes:                   C.BYTES.kib(256),
    maxRuntimeMs:               C.TIME.seconds(2),
  },
});

function _hasProtoPoisonName(query) {
  if (typeof query !== "string") return false;
  for (var i = 0; i < query.length; i += 1) {
    var cc = query.charCodeAt(i);
    if (!codepointClass.inRanges(cc, codepointClass.WHITESPACE_RANGES) &&
        IDENTIFIER_POSITION_PREFIXES.indexOf(query.charAt(i)) === -1) continue;
    var at = query.charAt(i + 1) === "$" ? i + 2 : i + 1;
    for (var n = 0; n < pick.POISONED_KEYS.length; n += 1) {
      var name = pick.POISONED_KEYS[n];
      if (!query.startsWith(name, at)) continue;
      if (!codepointClass.isIdentifierChar(query.charCodeAt(at + name.length))) return true;
    }
  }
  return false;
}

function _parseSelectionUnits(query) {
  var units = Object.create(null);
  var opRoots = [];
  var frames = [];
  var inString = false;
  var inBlock = false;
  var inComment = false;
  var escapeNext = false;
  var parenDepth = 0;
  var pendingInline = false;
  var pendingFragName = null;
  var atDefStart = true;
  var expectFragName = false;
  var lastWordText = "";
  var lastWordEnd = -1;
  var i = 0;
  var len = query.length;
  while (i < len) {
    var c = query.charAt(i);
    if (inComment) {
      if (c === "\n" || c === "\r") inComment = false;
      i += 1;
      continue;
    }
    if (inBlock) {
      if (c === "\\" && query.charAt(i + 1) === '"' && query.charAt(i + 2) === '"' &&
          query.charAt(i + 3) === '"') {
        i += 4;
        continue;
      }
      if (c === '"' && query.charAt(i + 1) === '"' && query.charAt(i + 2) === '"') {
        inBlock = false;
        i += 3;
        continue;
      }
      i += 1;
      continue;
    }
    if (inString) {
      if (escapeNext) { escapeNext = false; i += 1; continue; }
      if (c === "\\") { escapeNext = true; i += 1; continue; }
      if (c === '"') inString = false;
      i += 1;
      continue;
    }
    if (c === '"') {
      if (query.charAt(i + 1) === '"' && query.charAt(i + 2) === '"') {
        inBlock = true;
        i += 3;
        continue;
      }
      inString = true;
      i += 1;
      continue;
    }
    if (c === "#") { inComment = true; i += 1; continue; }
    if (parenDepth > 0) {
      if (c === "(") parenDepth += 1;
      else if (c === ")") parenDepth -= 1;
      i += 1;
      continue;
    }
    if (c === "(") { parenDepth += 1; i += 1; continue; }
    if (c === "." && query.charAt(i + 1) === "." && query.charAt(i + 2) === ".") {
      var j = i + 3;
      while (j < len) {
        var wc = query.charAt(j);
        if (wc === " " || wc === "\t" || wc === "\n" || wc === "\r" || wc === "," ||
            query.charCodeAt(j) === 0xFEFF) { j += 1; continue; }
        if (wc === "#") { while (j < len && query.charAt(j) !== "\n" && query.charAt(j) !== "\r") j += 1; continue; }
        break;
      }
      if (query.charAt(j) === "{" || query.charAt(j) === "@") {
        pendingInline = true;
        i = j;
        continue;
      }
      var s = j;
      while (j < len && codepointClass.isIdentifierChar(query.charCodeAt(j))) j += 1;
      var spreadName = query.slice(s, j);
      if (spreadName === "on") {
        pendingInline = true;
        i = j;
        continue;
      }
      if (spreadName && frames.length) frames[frames.length - 1].spreads.push(spreadName);
      i = j;
      continue;
    }
    if (c === "{") {
      var frame = { aliasNames: Object.create(null), fieldChildren: [], inlineChildren: [], spreads: [] };
      if (frames.length === 0) {
        if (pendingFragName !== null) { units[pendingFragName] = frame; pendingFragName = null; }
        else opRoots.push(frame);
      } else {
        var parent = frames[frames.length - 1];
        if (pendingInline) parent.inlineChildren.push(frame);
        else parent.fieldChildren.push(frame);
      }
      pendingInline = false;
      atDefStart = false;
      expectFragName = false;
      frames.push(frame);
      i += 1;
      continue;
    }
    if (c === "}") {
      if (frames.length) frames.pop();
      pendingInline = false;
      if (frames.length === 0) atDefStart = true;
      i += 1;
      continue;
    }
    if (c === ":") {
      if (frames.length && lastWordEnd === i) {
        frames[frames.length - 1].aliasNames[lastWordText] = true;
      }
      i += 1;
      continue;
    }
    if (codepointClass.isIdentifierChar(query.charCodeAt(i))) {
      var w0 = i;
      while (i < len && codepointClass.isIdentifierChar(query.charCodeAt(i))) i += 1;
      var word = query.slice(w0, i);
      lastWordText = word;
      lastWordEnd = i;
      if (frames.length === 0) {
        if (expectFragName) { pendingFragName = word; expectFragName = false; atDefStart = false; }
        else if (atDefStart) { if (word === "fragment") expectFragName = true; atDefStart = false; }
      }
      continue;
    }
    i += 1;
  }
  return { units: units, opRoots: opRoots };
}

function _collectFragmentRefs(frame, acc) {
  var stack = [frame];
  while (stack.length) {
    var f = stack.pop();
    for (var s = 0; s < f.spreads.length; s += 1) acc[f.spreads[s]] = true;
    for (var a = 0; a < f.fieldChildren.length; a += 1) stack.push(f.fieldChildren[a]);
    for (var n = 0; n < f.inlineChildren.length; n += 1) stack.push(f.inlineChildren[n]);
  }
}

function _hasFragmentCycle(units) {
  var refs = Object.create(null);
  var names = Object.keys(units);
  for (var a = 0; a < names.length; a += 1) {
    var acc = Object.create(null);
    _collectFragmentRefs(units[names[a]], acc);
    refs[names[a]] = Object.keys(acc);
  }
  var state = Object.create(null);
  for (var i = 0; i < names.length; i += 1) {
    if (state[names[i]] !== undefined) continue;
    state[names[i]] = 1;
    var stack = [{ name: names[i], idx: 0 }];
    while (stack.length) {
      var top = stack[stack.length - 1];
      var deps = refs[top.name] || [];
      if (top.idx < deps.length) {
        var m = deps[top.idx];
        top.idx += 1;
        if (!(m in refs)) continue;
        if (state[m] === 1) return true;
        if (state[m] === undefined) { state[m] = 1; stack.push({ name: m, idx: 0 }); }
      } else {
        state[top.name] = 2;
        stack.pop();
      }
    }
  }
  return false;
}

function _maxFrameAliases(parsed) {
  var maxAliases = 0;
  var stack = [];
  var r;
  for (r = 0; r < parsed.opRoots.length; r += 1) stack.push(parsed.opRoots[r]);
  var names = Object.keys(parsed.units);
  for (r = 0; r < names.length; r += 1) stack.push(parsed.units[names[r]]);
  while (stack.length) {
    var f = stack.pop();
    var n = Object.keys(f.aliasNames).length;
    if (n > maxAliases) maxAliases = n;
    for (var a = 0; a < f.fieldChildren.length; a += 1) stack.push(f.fieldChildren[a]);
    for (var b = 0; b < f.inlineChildren.length; b += 1) stack.push(f.inlineChildren[b]);
  }
  return maxAliases;
}

function _resolvedDepth(parsed, units) {
  var childDepthMemo = new Map();
  var expanded = new Set();
  function pushSuccessors(frame, stack) {
    var k;
    for (k = 0; k < frame.fieldChildren.length; k += 1) stack.push(frame.fieldChildren[k]);
    for (k = 0; k < frame.inlineChildren.length; k += 1) stack.push(frame.inlineChildren[k]);
    for (k = 0; k < frame.spreads.length; k += 1) {
      var r = units[frame.spreads[k]];
      if (r) stack.push(r);
    }
  }
  function childDepthOf(frame) {
    var best = 0;
    var k, v, r;
    for (k = 0; k < frame.fieldChildren.length; k += 1) {
      v = 1 + childDepthMemo.get(frame.fieldChildren[k]);
      if (v > best) best = v;
    }
    for (k = 0; k < frame.inlineChildren.length; k += 1) {
      v = childDepthMemo.get(frame.inlineChildren[k]);
      if (v > best) best = v;
    }
    for (k = 0; k < frame.spreads.length; k += 1) {
      r = units[frame.spreads[k]];
      if (r) { v = childDepthMemo.get(r); if (v > best) best = v; }
    }
    return best;
  }
  function maxChildDepth(root) {
    var stack = [root];
    while (stack.length) {
      var frame = stack[stack.length - 1];
      if (childDepthMemo.has(frame)) { stack.pop(); continue; }
      if (expanded.has(frame)) {
        childDepthMemo.set(frame, childDepthOf(frame));
        stack.pop();
      } else {
        expanded.add(frame);
        pushSuccessors(frame, stack);
      }
    }
    return childDepthMemo.get(root);
  }
  var maxDepth = 0;
  var roots = parsed.opRoots.slice();
  var names = Object.keys(units);
  for (var n = 0; n < names.length; n += 1) roots.push(units[names[n]]);
  for (var i = 0; i < roots.length; i += 1) {
    var d = 1 + maxChildDepth(roots[i]);
    if (d > maxDepth) maxDepth = d;
  }
  return maxDepth;
}

function _maxBraceDepth(query) {
  var depth = 0;
  var maxDepth = 0;
  var inString = false;
  var inBlock = false;
  var inComment = false;
  var escapeNext = false;
  var i = 0;
  var len = query.length;
  while (i < len) {
    var c = query.charAt(i);
    if (inComment) {
      if (c === "\n" || c === "\r") inComment = false;
      i += 1;
      continue;
    }
    if (inBlock) {
      if (c === "\\" && query.charAt(i + 1) === '"' && query.charAt(i + 2) === '"' &&
          query.charAt(i + 3) === '"') { i += 4; continue; }
      if (c === '"' && query.charAt(i + 1) === '"' && query.charAt(i + 2) === '"') {
        inBlock = false;
        i += 3;
        continue;
      }
      i += 1;
      continue;
    }
    if (inString) {
      if (escapeNext) { escapeNext = false; i += 1; continue; }
      if (c === "\\") { escapeNext = true; i += 1; continue; }
      if (c === '"') inString = false;
      i += 1;
      continue;
    }
    if (c === '"') {
      if (query.charAt(i + 1) === '"' && query.charAt(i + 2) === '"') { inBlock = true; i += 3; continue; }
      inString = true;
      i += 1;
      continue;
    }
    if (c === "#") { inComment = true; i += 1; continue; }
    if (c === "{") {
      depth += 1;
      if (depth > maxDepth) maxDepth = depth;
    } else if (c === "}") {
      depth -= 1;
      if (depth < 0) depth = 0;
    }
    i += 1;
  }
  return maxDepth;
}

function _measureQueryShape(query) {
  var parsed = _parseSelectionUnits(query);
  var cyclic = _hasFragmentCycle(parsed.units);
  var maxAliases = _maxFrameAliases(parsed);
  var syntacticDepth = _maxBraceDepth(query);
  var resolvedDepth = cyclic ? 0 : _resolvedDepth(parsed, parsed.units);
  return {
    maxAliases: maxAliases,
    effectiveDepth: resolvedDepth > syntacticDepth ? resolvedDepth : syntacticDepth,
    cyclicFragment: cyclic,
  };
}

function _detectIssues(req, opts) {
  var issues = [];
  if (!req || typeof req !== "object") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "graphql.bad-input",
              snippet: "graphql request is not an object" }];
  }

  if (Array.isArray(req)) {
    if (opts.batchPolicy !== "allow") {
      if (opts.batchPolicy === "reject" || req.length > opts.maxBatchSize) {
        issues.push({
          kind: "batch-size",
          severity: opts.batchPolicy === "reject" ? "high" : "warn",
          ruleId: "graphql.batch-size",
          snippet: "GraphQL batch length " + req.length + " exceeds " +
                   "maxBatchSize " + opts.maxBatchSize +
                   (opts.batchPolicy === "reject" ?
                    " (strict refuses any batch)" : ""),
        });
        if (opts.batchPolicy === "reject") return issues;
      }
    }
    for (var bi = 0; bi < req.length; bi += 1) {
      var sub = _detectIssues(req[bi], opts);
      for (var si = 0; si < sub.length; si += 1) {
        issues.push(Object.assign({}, sub[si], {
          snippet: "[batch[" + bi + "]] " + sub[si].snippet,
        }));
      }
    }
    return issues;
  }

  try {
    var totalBytes = Buffer.byteLength(JSON.stringify(req), "utf8");
    if (totalBytes > opts.maxBytes) {
      return [{ kind: "request-cap", severity: "high",
                ruleId: "graphql.request-cap",
                snippet: "graphql request " + totalBytes + " bytes " +
                         "exceeds maxBytes " + opts.maxBytes }];
    }
  } catch (_e) { /* unstringifiable surfaces below */ }

  if (typeof req.query !== "string" || req.query.length === 0) {
    issues.push({
      kind: "query-missing", severity: "high",
      ruleId: "graphql.query-missing",
      snippet: "graphql request missing `query` string",
    });
    return issues;
  }
  if (Buffer.byteLength(req.query, "utf8") > opts.maxQueryBytes) {
    issues.push({
      kind: "query-cap", severity: "high",
      ruleId: "graphql.query-cap",
      snippet: "query " + req.query.length + " bytes exceeds " +
               "maxQueryBytes " + opts.maxQueryBytes,
    });
    return issues;
  }

  var charThreats = codepointClass.detectCharThreats(req.query, opts, "graphql");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

  if (req.variables !== undefined) {
    try {
      var varBytes = Buffer.byteLength(JSON.stringify(req.variables), "utf8");
      if (varBytes > opts.maxVariableBytes) {
        issues.push({
          kind: "variables-cap", severity: "high",
          ruleId: "graphql.variables-cap",
          snippet: "variables exceed maxVariableBytes " + opts.maxVariableBytes,
        });
      }
    } catch (_e) { /* unstringifiable variables */ }
  }

  var pVar = req.variables;
  var pHas = Object.prototype.hasOwnProperty;
  var pName = (pVar && typeof pVar === "object" && !Array.isArray(pVar) &&
    pick.POISONED_KEYS.find(function (pk) { return pHas.call(pVar, pk); })) || null;
  if (pName) {
    issues.push({
      kind: "variable-prototype-poison", severity: "critical",
      ruleId: "graphql.variable-prototype-poison",
      snippet: "variable name `" + pName + "` — prototype-pollution " +
               "gadget (CVE-2026-32621)",
    });
  }
  if (_hasProtoPoisonName(req.query)) {
    issues.push({
      kind: "query-prototype-poison", severity: "critical",
      ruleId: "graphql.query-prototype-poison",
      snippet: "query references `__proto__` / `constructor` / " +
               "`prototype` as a field / alias / variable — prototype-" +
               "pollution gadget (CVE-2026-32621)",
    });
  }

  if (opts.introspectionPolicy !== "allow") {
    if (req.query.indexOf("__schema") !== -1 ||
        req.query.indexOf("__type") !== -1) {
      issues.push({
        kind: "introspection",
        severity: opts.introspectionPolicy === "reject" ? "high" : "warn",
        ruleId: "graphql.introspection",
        snippet: "query contains `__schema` / `__type` introspection — " +
                 "leaks schema details in production",
      });
    }
  }

  if (opts.persistedQueryPolicy === "require") {
    var ext = req.extensions;
    var hasPersisted = ext && ext.persistedQuery &&
                       typeof ext.persistedQuery.sha256Hash === "string";
    if (!hasPersisted) {
      issues.push({
        kind: "persisted-query-missing", severity: "high",
        ruleId: "graphql.persisted-query-missing",
        snippet: "persistedQueryPolicy is `require` but request carries " +
                 "no extensions.persistedQuery.sha256Hash",
      });
    }
  }

  if (Array.isArray(opts.allowedOperations) &&
      opts.operationNamePolicy !== "allow") {
    if (typeof req.operationName !== "string" ||
        opts.allowedOperations.indexOf(req.operationName) === -1) {
      issues.push({
        kind: "operation-not-allowed",
        severity: opts.operationNamePolicy === "reject" ? "high" : "warn",
        ruleId: "graphql.operation-not-allowed",
        snippet: "operationName `" + (req.operationName || "<missing>") +
                 "` not in operator allowlist",
      });
    }
  }

  var shape = _measureQueryShape(req.query);
  if (opts.depthPolicy !== "allow" &&
      (shape.cyclicFragment || shape.effectiveDepth > opts.maxDepth)) {
    issues.push({
      kind: "depth-exceeded",
      severity: opts.depthPolicy === "reject" ? "high" : "warn",
      ruleId: "graphql.depth-exceeded",
      snippet: shape.cyclicFragment
        ? "query depth is unbounded: a fragment spread resolves cyclically, " +
          "exceeding maxDepth " + opts.maxDepth + " (query-shape DoS class)"
        : "fragment-resolved query depth " + shape.effectiveDepth +
          " exceeds maxDepth " + opts.maxDepth + " (query-shape DoS class)",
    });
  }
  if (opts.aliasBombPolicy !== "allow" &&
      shape.maxAliases > opts.maxAliasesPerSelection) {
    issues.push({
      kind: "alias-bomb",
      severity: opts.aliasBombPolicy === "reject" ? "high" : "warn",
      ruleId: "graphql.alias-bomb",
      snippet: "selection-set alias count " + shape.maxAliases +
               " exceeds maxAliasesPerSelection " +
               opts.maxAliasesPerSelection +
               " (alias-bomb breadth-amplification DoS class)",
    });
  }

  if (opts.variableShapePolicy !== "allow" &&
      opts.variableShapes && typeof opts.variableShapes === "object" &&
      req.variables && typeof req.variables === "object") {
    var keys = Object.keys(opts.variableShapes);
    for (var ki = 0; ki < keys.length; ki += 1) {
      var k = keys[ki];
      var expected = opts.variableShapes[k];
      var actual = req.variables[k];
      if (actual === undefined) continue;
      if (typeof actual !== expected) {
        issues.push({
          kind: "variable-type-confusion",
          severity: opts.variableShapePolicy === "reject" ? "high" : "warn",
          ruleId: "graphql.variable-type-confusion",
          snippet: "variable `" + k + "` is " + typeof actual +
                   ", expected " + expected,
        });
      }
    }
  }

  return issues;
}

/**
 * @primitive  b.guardGraphql.validate
 * @signature  b.guardGraphql.validate(input, opts?)
 * @since      0.7.49
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardGraphql.sanitize, b.guardGraphql.gate
 *
 * Apply the full guard-graphql threat catalog to a request bundle
 * (or batch array). Returns `{ ok, issues }` per
 * `gateContract.aggregateIssues`. Detected classes include
 * `query-missing`, `query-cap`, `variables-cap`, `request-cap`,
 * `batch-size`, `introspection`, `persisted-query-missing`,
 * `operation-not-allowed`, `depth-exceeded`, `alias-bomb`,
 * `variable-type-confusion`, plus codepoint-class issues on the
 * query string. Operator-supplied opts are bounds-checked; bad
 * opts throw `GuardGraphqlError("graphql/bad-opt")`.
 *
 * @opts
 *   profile:                 "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   introspectionPolicy:     "reject"|"audit"|"allow",
 *   persistedQueryPolicy:    "require"|"audit"|"allow",
 *   operationNamePolicy:     "reject"|"audit"|"allow",
 *   batchPolicy:             "reject"|"audit"|"allow",
 *   aliasBombPolicy:         "reject"|"audit"|"allow",
 *   depthPolicy:             "reject"|"audit"|"allow",
 *   variableShapePolicy:     "reject"|"audit"|"allow",
 *   allowedOperations:       string[],
 *   variableShapes:          { [name: string]: "string"|"number"|"boolean"|"object" },
 *   maxDepth:                number,
 *   maxAliasesPerSelection:  number,
 *   maxBatchSize:            number,
 *   maxQueryBytes:           number,
 *   maxVariableBytes:        number,
 *   maxBytes:                number,
 *
 * @example
 *   var hostile = {
 *     query: "query Inspect { __schema { types { name } } }",
 *     operationName: "Inspect",
 *   };
 *   var rv = b.guardGraphql.validate(hostile, { profile: "strict" });
 *   rv.ok;                                              // → false
 *   rv.issues[0].ruleId;                                // → "graphql.introspection"
 *
 *   var benign = {
 *     query: "query GetMe { me { id name } }",
 *     operationName: "GetMe",
 *   };
 *   var ok = b.guardGraphql.validate(benign, { profile: "strict" });
 *   ok.ok;                                              // → true
 */

/**
 * @primitive  b.guardGraphql.sanitize
 * @signature  b.guardGraphql.sanitize(input, opts?)
 * @since      0.7.49
 * @status     stable
 * @related    b.guardGraphql.validate, b.guardGraphql.gate
 *
 * Pass-through-or-throw form of `validate`. GraphQL request
 * bundles can't be partially repaired — depth bombs, alias
 * amplification, and introspection leaks are refuse-class
 * outcomes, not something the guard can patch up safely.
 * Returns the input unchanged when the issue list contains no
 * `critical` / `high` entries; throws `GuardGraphqlError`
 * carrying the offending `ruleId` otherwise.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:        every guardGraphql.validate opt is honored,
 *
 * @example
 *   try {
 *     b.guardGraphql.sanitize({
 *       query: "query Inspect { __schema { types { name } } }",
 *       operationName: "Inspect",
 *     }, { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                           // → "graphql.introspection"
 *   }
 */
var _sanitizeTransform = gateContract.identitySanitize;

/**
 * @primitive  b.guardGraphql.gate
 * @signature  b.guardGraphql.gate(opts?)
 * @since      0.7.49
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardGraphql.validate, b.guardGraphql.sanitize
 *
 * Build a `gateContract.buildGuardGate`-shaped gate that pulls
 * `ctx.graphqlRequest` (or `ctx.gql`) and dispatches to
 * `validate`. Returns `{ ok: true, action: "serve" }` when the
 * issue list is empty, `{ ok: true, action: "audit-only", issues }`
 * when only low-severity issues fire, and `{ ok: false, action:
 * "refuse", issues }` on any `critical` / `high` issue. Compose
 * into the GraphQL request handler before any schema-resolution
 * work — refusal short-circuits hostile depth / alias / batch
 * shapes before they reach the executor.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,            // gate label for audit trails
 *   ...:        every guardGraphql.validate opt is honored,
 *
 * @example
 *   var gqlGate = b.guardGraphql.gate({ profile: "strict" });
 *   var rv = await gqlGate.check({
 *     graphqlRequest: {
 *       query: "{ a:me { id } b:me { id } c:me { id } d:me { id } " +
 *              "e:me { id } f:me { id } g:me { id } h:me { id } " +
 *              "i:me { id } }",
 *     },
 *   });
 *   rv.action;                                          // → "refuse"
 *   rv.issues[0].ruleId;                                // → "graphql.alias-bomb"
 */
function gate(opts) {
  opts = _guard.resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardGraphql:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var req = ctx && (ctx.graphqlRequest || ctx.gql);
      if (!req) return { ok: true, action: "serve" };
      var rv = module.exports.validate(req, opts);
      return gateContract.severityDisposition(rv.issues);
    });
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind: "graphql-request",
  benignBytes: Buffer.from(JSON.stringify({
    query: "query GetMe { me { id name } }",
    operationName: "GetMe",
  }), "utf8"),
  hostileBytes: Buffer.from(JSON.stringify({
    query: "query Inspect { __schema { types { name } } }",
    operationName: "Inspect",
  }), "utf8"),
  benignGraphqlRequest: {
    query: "query GetMe { me { id name } }",
    operationName: "GetMe",
  },
  hostileGraphqlRequest: {
    query: "query Inspect { __schema { types { name } } }",
    operationName: "Inspect",
  },
});

var POLICY_ENUM = gateContract.policyVocabulary([
  "introspectionPolicy", "operationNamePolicy", "batchPolicy",
  "aliasBombPolicy", "depthPolicy", "variableShapePolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow, {
  persistedQueryPolicy: ["require", "audit", "audit-only", "allow"],
});

var _guard = module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "graphql",
  kind:        "graphql-request",
  errorClass:  GuardGraphqlError,
  profiles:    PROFILES,
  base:        512,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:            _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:           ["maxBytes", "maxQueryBytes", "maxVariableBytes",
                      "maxDepth", "maxAliasesPerSelection", "maxBatchSize"],
  gate:        gate,
});
