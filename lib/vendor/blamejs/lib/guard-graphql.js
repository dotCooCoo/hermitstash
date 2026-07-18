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
 *   limits. The gate's `_measureQueryShape` walker counts
 *   brace-depth without a full lex/parse (the operator's executor
 *   handles full parsing); strict caps at 8, balanced 12,
 *   permissive 24. The cap fires as `graphql.depth-exceeded` —
 *   the canonical N²-amplification DoS class.
 *
 *   Alias-amplification caps: the same field repeated under
 *   different aliases (`a:friend b:friend c:friend ...`) bypasses
 *   per-field limits because each alias is a separate selection.
 *   Strict caps at 8 aliases per selection-set, balanced 16,
 *   permissive 32. Fires as `graphql.alias-bomb` —
 *   breadth-amplification DoS class.
 *
 *   Fragment-cycle defense: operator's executor handles cyclic
 *   fragment refs at parse time; the guard's contribution is the
 *   total-bytes cap (`maxBytes`) and per-query cap
 *   (`maxQueryBytes`), which bound the worst-case parser-DoS
 *   shape regardless of cycle structure.
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

// Query-body proto-poison literal (CVE-2026-32621). Matches the bare
// identifier in field / alias / variable-declaration positions —
// `$__proto__: String`, `__proto__: realField`, `__proto__ { ... }`,
// and the no-whitespace alias form `query { a:__proto__ }` /
// `query { a:constructor }` (GraphQL parsers accept the colon with
// or without trailing whitespace, so `:` is a valid identifier-
// position prefix that must also trigger refusal).
var PROTO_POISON_QUERY_RE = /[\s,({:]\$?(?:__proto__|constructor|prototype)\b/;

// ---- Profile presets ----

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
    maxDepth:                   8,                                               // selection-set depth ceiling
    maxAliasesPerSelection:     8,                                               // alias breadth ceiling
    maxBatchSize:               1,                                               // strict refuses batch
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
    maxDepth:                   12,                                              // selection-set depth ceiling
    maxAliasesPerSelection:     16,                                              // alias breadth ceiling
    maxBatchSize:               10,                                              // batch size ceiling
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
    maxDepth:                   24,                                              // selection-set depth ceiling
    maxAliasesPerSelection:     32,                                              // alias breadth ceiling
    maxBatchSize:               50,                                              // batch size ceiling
    maxQueryBytes:              C.BYTES.kib(64),
    maxVariableBytes:           C.BYTES.kib(64),
    maxBytes:                   C.BYTES.kib(256),
    maxRuntimeMs:               C.TIME.seconds(2),
  },
});

// _measureQueryShape — walks the query string and computes
// brace-depth + per-selection-set alias counts using simple paren
// counting. Not a full GraphQL parser (operator runs the schema-
// aware parser downstream); the heuristic catches DoS shapes
// without a full lex/parse.
function _measureQueryShape(query) {
  var maxDepth = 0;
  var maxAliases = 0;
  var depth = 0;
  var inString = false;
  var inComment = false;
  var escapeNext = false;                                                        // inside a string, the previous char was an unescaped backslash
  var aliasStack = [0];                                                          // per-selection-set alias counter (top of stack = current set)
  for (var i = 0; i < query.length; i += 1) {
    var c = query.charAt(i);
    if (inComment) {
      if (c === "\n") inComment = false;
      continue;
    }
    if (inString) {
      // Escaped-quote handling must track the backslash RUN, not just the
      // single preceding char. `"\\"` is a complete string (its backslash is
      // itself escaped), so a naive `charAt(i - 1) !== "\\"` test reads the
      // closing quote as escaped, leaves the walker stuck in-string, and
      // blinds it to every following brace / colon — silently under-counting
      // depth and alias breadth so a depth-bomb or alias-bomb rides through as
      // shape-clean (a fail-open DoS-measurement bypass on valid GraphQL).
      // Toggle on each backslash: a closing quote ends the string only after
      // an EVEN run (escapeNext false).
      if (escapeNext) { escapeNext = false; continue; }
      if (c === "\\") { escapeNext = true; continue; }
      if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; continue; }
    if (c === "#") { inComment = true; continue; }
    if (c === "{") {
      depth += 1;
      if (depth > maxDepth) maxDepth = depth;
      aliasStack.push(0);
    } else if (c === "}") {
      // Capture the current selection-set's alias count before popping
      // — otherwise we lose the per-block max when the block closes.
      var current = aliasStack[aliasStack.length - 1] || 0;
      if (current > maxAliases) maxAliases = current;
      depth -= 1;
      // Never pop the base counter: an unbalanced leading `}` would otherwise
      // desync the stack from `depth`, and a subsequent `depth`-indexed
      // increment lands on an absent slot (`undefined + 1 === NaN`), poisoning
      // every later comparison so an alias-bomb reads as clean.
      if (aliasStack.length > 1) aliasStack.pop();
      if (depth < 0) depth = 0;
    } else if (c === ":") {
      // Alias / argument indicator — `alias: field` / `field(arg: value)`.
      // Increment the CURRENT selection-set's counter (top of stack) when the
      // char before `:` looks like an identifier. Using the stack top rather
      // than a `depth` index keeps counting correct even when a malformed
      // brace run has decoupled `depth` from the stack length.
      var prev = i > 0 ? query.charAt(i - 1) : "";
      if (/[A-Za-z0-9_]/.test(prev) && aliasStack.length > 1) {
        aliasStack[aliasStack.length - 1] += 1;
      }
    }
  }
  // Final sweep covers any unclosed selection-sets (operator-supplied
  // syntactically-invalid queries).
  for (var ai = 0; ai < aliasStack.length; ai += 1) {
    if (aliasStack[ai] > maxAliases) maxAliases = aliasStack[ai];
  }
  return { maxDepth: maxDepth, maxAliases: maxAliases };
}

function _detectIssues(req, opts) {
  var issues = [];
  if (!req || typeof req !== "object") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "graphql.bad-input",
              snippet: "graphql request is not an object" }];
  }

  // Batch handling.
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
    // Apply per-request validation to each entry.
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

  // Total-bytes cap.
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

  // Codepoint-class threats on the query.
  var charThreats = codepointClass.detectCharThreats(req.query, opts, "graphql");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

  // Variables byte cap.
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

  // Prototype-pollution defense (CVE-2026-32621). A `__proto__` /
  // `constructor` / `prototype` variable key OR query-body identifier
  // pivots a downstream deep-merge / deep-set into a poisoned shape.
  // Refused at every profile.
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
  if (PROTO_POISON_QUERY_RE.test(req.query)) {                                   // allow:regex-no-length-cap — input bounded by maxQueryBytes above
    issues.push({
      kind: "query-prototype-poison", severity: "critical",
      ruleId: "graphql.query-prototype-poison",
      snippet: "query references `__proto__` / `constructor` / " +
               "`prototype` as a field / alias / variable — prototype-" +
               "pollution gadget (CVE-2026-32621)",
    });
  }

  // Introspection.
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

  // Persisted-query enforcement.
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

  // Operation-name allowlist.
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

  // Query shape — depth + alias bombs.
  var shape = _measureQueryShape(req.query);
  if (opts.depthPolicy !== "allow" && shape.maxDepth > opts.maxDepth) {
    issues.push({
      kind: "depth-exceeded",
      severity: opts.depthPolicy === "reject" ? "high" : "warn",
      ruleId: "graphql.depth-exceeded",
      snippet: "query depth " + shape.maxDepth + " exceeds maxDepth " +
               opts.maxDepth + " — N² query-shape DoS class",
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
               " — alias-bomb breadth-DoS class",
    });
  }

  // Variable shape (operator-declared via opts.variableShapes).
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
 * opts throw `GuardGraphqlError("graphql.bad-opt")`.
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
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues) below — `validate(input, opts) = aggregateIssues(detect(
// input, resolveOpts(opts)))`, with the byte / depth / alias / batch caps
// declared via `intOpts`. The @primitive block above documents the
// resulting public ABI.

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
// _sanitizeTransform — the guard-specific normalize applied by defineGuard's
// generated sanitize AFTER resolve → detect → throw-on-refusal. GraphQL
// request bundles can't be partially repaired; once detection passes with no
// critical/high issue, the input is returned unchanged.
function _sanitizeTransform(input) {
  return input;
}

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
      // validate is assembled by defineGuard (from `detect` below) and lives
      // on the frozen module.exports; the gate is only invoked at runtime,
      // after the export is assigned. Behaviour is identical to the prior
      // local validate (resolve → intOpts → aggregateIssues(detect)).
      var rv = module.exports.validate(req, opts);
      return gateContract.severityDisposition(rv.issues);
    });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below — their wiki sections render from the
// single-sourced @abiTemplate blocks in gate-contract.js.

// ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
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

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize / bespoke gate) passed through verbatim.
// The custom KIND ("graphql-request") is accepted because the bespoke
// gate reads its own ctx fields (ctx.graphqlRequest / ctx.gql).
var _guard = module.exports = gateContract.defineGuard({
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
