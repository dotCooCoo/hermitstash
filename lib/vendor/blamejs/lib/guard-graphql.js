"use strict";
/**
 * guard-graphql — GraphQL request-shape safety primitive
 * (b.guardGraphql).
 *
 * Validates user-supplied GraphQL request bundles against the
 * canonical query-shape DoS catalog before the framework hands the
 * query to a schema-aware executor. KIND="graphql-request" — consumes
 * `ctx.graphqlRequest` shape: { query, operationName?, variables? }.
 *
 * Threat catalog:
 *   - Query depth bombs — deeply-nested selection sets multiply N²
 *     against schema depth, bypassing field-level rate limits.
 *   - Query breadth / alias bombs — same field repeated under
 *     different aliases (`a:friend b:friend c:friend ...`) bypasses
 *     per-field limits.
 *   - Variable type confusion — variables passed as the wrong shape
 *     (string for ID expecting Int, object for scalar). Many
 *     executors coerce silently; the guard refuses non-shape-matching
 *     types when the operator declares variable shapes.
 *   - Introspection in production — `__schema` / `__type` queries
 *     leak schema details; refused unless operator opts in.
 *   - Batch query DoS — operators supporting [{},{}] batch arrays
 *     get N requests for one HTTP hit; the guard caps batch length.
 *   - Persisted-query opt-in — when operatorRequiresPersistedQuery,
 *     refuse free-form queries that don't carry a persisted-query
 *     hash extension.
 *   - Operation-name allowlist — operator may pin operationName to
 *     a whitelist of named operations (denylist for ad-hoc queries).
 *   - Excessive query / variable / total byte length — parser DoS.
 *   - BIDI / null / control / zero-width universal refuse on the
 *     query string.
 *
 *   var rv = b.guardGraphql.validate(req, { profile: "strict" });
 *   var g  = b.guardGraphql.gate({ profile: "strict" });
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardGraphqlError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardGraphqlError.factory;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:                 "reject",
    controlPolicy:              "reject",
    nullBytePolicy:             "reject",
    zeroWidthPolicy:            "reject",
    introspectionPolicy:        "reject",
    persistedQueryPolicy:       "audit",
    operationNamePolicy:        "audit",
    batchPolicy:                "reject",
    aliasBombPolicy:            "reject",
    depthPolicy:                "reject",
    variableShapePolicy:        "reject",
    maxDepth:                   8,                                               // allow:raw-byte-literal — selection-set depth ceiling
    maxAliasesPerSelection:     8,                                               // allow:raw-byte-literal — alias breadth ceiling
    maxBatchSize:               1,                                               // allow:raw-byte-literal — strict refuses batch
    maxQueryBytes:              C.BYTES.kib(8),
    maxVariableBytes:           C.BYTES.kib(8),
    maxBytes:                   C.BYTES.kib(32),
    maxRuntimeMs:               C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:                 "reject",
    controlPolicy:              "reject",
    nullBytePolicy:             "reject",
    zeroWidthPolicy:            "reject",
    introspectionPolicy:        "audit",
    persistedQueryPolicy:       "audit",
    operationNamePolicy:        "audit",
    batchPolicy:                "audit",
    aliasBombPolicy:            "audit",
    depthPolicy:                "audit",
    variableShapePolicy:        "audit",
    maxDepth:                   12,                                              // allow:raw-byte-literal — selection-set depth ceiling
    maxAliasesPerSelection:     16,                                              // allow:raw-byte-literal — alias breadth ceiling
    maxBatchSize:               10,                                              // allow:raw-byte-literal — batch size ceiling
    maxQueryBytes:              C.BYTES.kib(16),
    maxVariableBytes:           C.BYTES.kib(16),
    maxBytes:                   C.BYTES.kib(64),
    maxRuntimeMs:               C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:                 "reject",                                        // BIDI refused at every profile
    controlPolicy:              "reject",                                        // controls refused at every profile
    nullBytePolicy:             "reject",                                        // null refused at every profile
    zeroWidthPolicy:            "reject",                                        // zero-width refused at every profile
    introspectionPolicy:        "allow",
    persistedQueryPolicy:       "allow",
    operationNamePolicy:        "allow",
    batchPolicy:                "allow",
    aliasBombPolicy:            "audit",
    depthPolicy:                "audit",
    variableShapePolicy:        "audit",
    maxDepth:                   24,                                              // allow:raw-byte-literal — selection-set depth ceiling
    maxAliasesPerSelection:     32,                                              // allow:raw-byte-literal — alias breadth ceiling
    maxBatchSize:               50,                                              // allow:raw-byte-literal — batch size ceiling
    maxQueryBytes:              C.BYTES.kib(64),
    maxVariableBytes:           C.BYTES.kib(64),
    maxBytes:                   C.BYTES.kib(256),
    maxRuntimeMs:               C.TIME.seconds(2),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(1024),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardGraphqlError,
    errCodePrefix:      "graphql",
  });
}

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
  var aliasCounts = [0];                                                         // per-depth alias counter
  for (var i = 0; i < query.length; i += 1) {
    var c = query.charAt(i);
    if (inComment) {
      if (c === "\n") inComment = false;
      continue;
    }
    if (inString) {
      if (c === '"' && query.charAt(i - 1) !== "\\") inString = false;
      continue;
    }
    if (c === '"') { inString = true; continue; }
    if (c === "#") { inComment = true; continue; }
    if (c === "{") {
      depth += 1;
      if (depth > maxDepth) maxDepth = depth;
      aliasCounts.push(0);
    } else if (c === "}") {
      // Capture the current selection-set's alias count before popping
      // — otherwise we lose the per-block max when the block closes.
      var current = aliasCounts[aliasCounts.length - 1] || 0;
      if (current > maxAliases) maxAliases = current;
      depth -= 1;
      aliasCounts.pop();
      if (depth < 0) depth = 0;
    } else if (c === ":") {
      // Alias indicator — `alias: field`. Increment the current depth's
      // counter when the char before `:` looks like an identifier.
      var prev = i > 0 ? query.charAt(i - 1) : "";
      if (/[A-Za-z0-9_]/.test(prev) && depth > 0) {
        aliasCounts[depth] += 1;
      }
    }
  }
  // Final sweep covers any unclosed selection-sets (operator-supplied
  // syntactically-invalid queries).
  for (var ai = 0; ai < aliasCounts.length; ai += 1) {
    if (aliasCounts[ai] > maxAliases) maxAliases = aliasCounts[ai];
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

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxQueryBytes", "maxVariableBytes",
     "maxDepth", "maxAliasesPerSelection", "maxBatchSize"],
    "guardGraphql.validate", GuardGraphqlError, "graphql.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "graphql.refused",
        "guardGraphql.sanitize: " + issues[i].snippet);
    }
  }
  return input;
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardGraphql:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var req = ctx && (ctx.graphqlRequest || ctx.gql);
      if (!req) return { ok: true, action: "serve" };
      var rv = validate(req, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical";
      });
      var hasHigh = rv.issues.some(function (i) {
        return i.severity === "high";
      });
      if (!hasCritical && !hasHigh) {
        return { ok: true, action: "audit-only", issues: rv.issues };
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "graphql");
}

var _gqlRulePacks = gateContract.makeRulePackLoader(GuardGraphqlError, "graphql");
var loadRulePack = _gqlRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "graphql",
  KIND:                "graphql-request",
  INTEGRATION_FIXTURES: Object.freeze({
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
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardGraphqlError:   GuardGraphqlError,
};
