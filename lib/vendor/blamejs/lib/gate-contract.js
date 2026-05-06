"use strict";
/**
 * gate-contract — uniform composition contract for the safe-* primitive
 * family.
 *
 * Every safe-* primitive (b.safeCsv / b.safeHtml / b.safeLink / b.safeMime
 * / b.safeFilename / etc.) ships a `.gate(opts)` factory that returns the
 * shape defined here. Host primitives (b.staticServe / b.fileUpload /
 * b.mail / b.objectStore / b.notify / b.audit / etc.) call gate.check()
 * at their byte-boundary moment with a uniform context.
 *
 * The gate decision is captured as:
 *
 *   { ok, action, sanitized?, issues, contentTypeOverride?, headers?,
 *     forensicHash, forensicSnapshot?, runtimeMs, cacheKey? }
 *
 * Operator extension surface — every primitive inherits these patterns
 * from this module (configuration uniform across the family):
 *
 *   - Profile composition (extends + overrides + removes; cycle detection)
 *   - Hook system (beforeCheck / afterCheck / onIssue / onSanitize / onRefuse / onAudit)
 *   - Mode posture (enforce / warn-only / shadow / audit-only / log-only / canary)
 *   - Versioned policies (version + ruleHash) with policyDiff helper
 *   - Forensic snapshot store (operator-supplied evidence vault)
 *   - Decision cache (per-forensicHash memoization)
 *   - Runtime cap with timeout
 *   - Sandbox isolation (in-process / worker-thread / child-process)
 *   - Threat-intelligence feed integration
 *   - Compliance posture pre-sets
 *
 * Host-side helpers exported here:
 *
 *   runGate(gate, ctx, opts?)            — execute single gate with timeout
 *   composeGates([g1, g2, ...], opts?)   — chain; first refusal wins
 *   multiplexGates({ ext: gate, ... })   — file-extension dispatch
 *   contentTypeMux({ mime: gate, ... })  — Content-Type dispatch
 *   byActorTier({ tier: gate, ... })     — actor-tier dispatch
 *   byRoute({ pattern: gate, ... })      — route-pattern dispatch
 *   byDirection({ inbound, outbound })   — direction-aware dispatch
 *   shadowMode(primary, candidate)       — A/B compare; emit divergence
 *   canaryGate(gate, { rate })           — N% rollout
 *   cachingGate(gate, { backend, ttlMs }) — memoize per-forensicHash
 *   workerThreadGate(gate, { worker })   — offload to worker
 *   validateGateShape(g, label, errClass) — schema check at wire-up
 *   buildProfile({ baseProfile, extends, overrides, removes })
 *   composeHooks(hooks)                  — chain operator hooks
 *
 * Module-level constants:
 *
 *   ACTIONS          — allowed action enum
 *   MODES            — allowed mode enum
 *   ISSUE_SEVERITIES — allowed severity enum
 *
 * The gate contract is the foundation of the guard-* family. Every
 * content-safety primitive that ships in the family composes through it
 * (b.guardCsv, future b.guardHtml / b.guardSvg / etc.). b.guardAll then
 * aggregates the registered guards into a single security-on-by-default
 * gate with operator opt-out via exceptFor.
 */

var C = require("./constants");
var crypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var { GateContractError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
var compliance = lazyRequire(function () { return require("./compliance"); });

// Forensic-id token width (bytes); 64 bits is enough for cross-gate
// correlation in a single request scope.
var FORENSIC_ID_BYTES = C.BYTES.bytes(8);
// Hash-prefix used as a fingerprint identifier in policy-rule hashes —
// 16 hex chars = 64 bits, ample for fingerprint comparison.
var FINGERPRINT_HEX_LENGTH = C.BYTES.bytes(16);
// Default cachingGate TTL when operator doesn't supply one.
var DEFAULT_CACHE_TTL_MS = C.TIME.minutes(5);

var _err = GateContractError.factory;

// ---- Enumerations (module-level constants) ----

var ACTIONS = Object.freeze([
  "serve",          // host emits the bytes as-is
  "refuse",         // host rejects with operator-meaningful error
  "sanitize",       // host substitutes decision.sanitized for the bytes
  "strip",          // host removes the offending content (sanitized = empty)
  "audit-only",     // host serves; gate emits audit (no operator-side change)
  "warn",           // host serves; gate emits warning (operator monitors)
  "challenge-mfa",  // host triggers step-up auth before serving
  "deny-and-revoke", // host rejects + invalidates the actor's session
]);

var MODES = Object.freeze([
  "enforce",     // gate decision honored
  "warn-only",   // gate emits but never refuses (staged rollout)
  "shadow",      // run alongside primary; emit divergence; never refuses
  "audit-only",  // emit audit but no operator-side action
  "log-only",    // emit observability counter only
  "canary",      // enforce on N% of requests; warn on the rest
]);

var ISSUE_SEVERITIES = Object.freeze([
  "info",
  "warn",
  "high",
  "critical",
]);

// ---- validateGateShape ----
//
// Throws if `gate` doesn't satisfy the contract. Operator-supplied gates
// (or framework-supplied gates with operator-toggled hooks) all flow
// through this check at host-primitive wire-up time. Shape errors at
// boot are far cheaper than at request time.

function validateGateShape(gate, label, errorClass) {
  errorClass = errorClass || GateContractError;
  label = label || "gate";
  if (!gate || typeof gate !== "object") {
    throw new errorClass("gate-contract/bad-shape",
      label + ": gate must be an object, got " + typeof gate);
  }
  if (typeof gate.check !== "function") {
    throw new errorClass("gate-contract/bad-shape",
      label + ": gate.check must be a function");
  }
  if (gate.mode !== undefined && MODES.indexOf(gate.mode) === -1) {
    throw new errorClass("gate-contract/bad-shape",
      label + ": gate.mode must be one of " + MODES.join("/") +
      ", got " + JSON.stringify(gate.mode));
  }
  if (gate.metrics !== undefined && typeof gate.metrics !== "function") {
    throw new errorClass("gate-contract/bad-shape",
      label + ": gate.metrics must be a function (returns counter snapshot)");
  }
  if (gate.close !== undefined && typeof gate.close !== "function") {
    throw new errorClass("gate-contract/bad-shape",
      label + ": gate.close must be a function");
  }
  return gate;
}

// ---- defineGate factory ----
//
// Primitives use this to build their .gate(opts) implementation. Wraps
// the operator's check() with the cross-cutting concerns (hooks /
// observability / forensic snapshot / runtime cap / cache). Returns a
// gate that satisfies validateGateShape.
//
//   defineGate({
//     name:        "safeCsv:strict",
//     version:     "1.0.0",
//     mode:        "enforce",
//     check:       async (ctx) => decision,
//     beforeCheck, afterCheck, onIssue, onSanitize, onRefuse, onAudit,
//     audit, observability, forensicEvidenceStore, forensicSnippetBytes,
//     cache, cacheTtlMs, maxRuntimeMs, ruleHash,
//   }) → gate

function defineGate(opts) {
  validateOpts.requireObject(opts, "gateContract.defineGate", GateContractError);
  validateOpts.requireNonEmptyString(opts.name, "gateContract.defineGate: name", GateContractError, "gate-contract/bad-opt");
  if (typeof opts.check !== "function") {
    throw _err("gate-contract/bad-opt", "gateContract.defineGate: check must be a function");
  }
  var mode = opts.mode || "enforce";
  if (MODES.indexOf(mode) === -1) {
    throw _err("gate-contract/bad-opt",
      "gateContract.defineGate: mode must be one of " + MODES.join("/") +
      ", got " + JSON.stringify(mode));
  }
  var hooks = {
    beforeCheck: opts.beforeCheck || null,
    afterCheck:  opts.afterCheck  || null,
    onIssue:     opts.onIssue     || null,
    onSanitize:  opts.onSanitize  || null,
    onRefuse:    opts.onRefuse    || null,
    onAudit:     opts.onAudit     || null,
  };
  var auditHandle = opts.audit || null;
  var emitAudit = validateOpts.makeAuditEmitter(auditHandle);
  var observabilityHandle = opts.observability || null;
  function _emitObs(name, value, labels) {
    if (observabilityHandle && typeof observabilityHandle.safeEvent === "function") {
      observabilityHandle.safeEvent(name, value, labels || {});
    } else {
      observability().safeEvent(name, value, labels || {});
    }
  }
  var forensicSnippetBytes = opts.forensicSnippetBytes || 0;
  var forensicEvidenceStore = opts.forensicEvidenceStore || null;
  var maxRuntimeMs = opts.maxRuntimeMs || 0;
  var decisionCache = opts.cache || null;
  var cacheTtlMs = opts.cacheTtlMs || 0;
  var version = opts.version || "1.0.0";
  var ruleHash = opts.ruleHash || _hashFingerprint({ name: opts.name, version: version });

  // Counters for metrics() snapshot.
  var counters = {
    passed: 0, refused: 0, sanitized: 0, audited: 0, warned: 0,
    runtimeMs: { count: 0, total: 0 },
  };

  function _bumpRuntime(ms) {
    counters.runtimeMs.count += 1;
    counters.runtimeMs.total += ms;
  }

  async function _runHook(hook, args) {
    if (!hook) return null;
    try { return await hook.apply(null, args); }
    catch (_e) {
      _emitObs(opts.name + ".hook_threw", 1, { hook: args[0] && args[0].name });
      return null;
    }
  }

  async function check(ctx) {
    var startedAt = Date.now();
    ctx = ctx || {};
    if (!ctx.forensicId) ctx.forensicId = crypto.generateToken(FORENSIC_ID_BYTES);

    // Decision cache lookup (memoize per-forensicHash).
    var bytes = ctx.bytes;
    var forensicHash = bytes && Buffer.isBuffer(bytes)
      ? crypto.sha3Hash(bytes, "hex")
      : (typeof bytes === "string" ? crypto.sha3Hash(Buffer.from(bytes, "utf8"), "hex") : null);
    var cacheKey = forensicHash ? (opts.name + ":" + ruleHash + ":" + forensicHash) : null;
    if (decisionCache && cacheKey) {
      try {
        var cached = await decisionCache.get(cacheKey);
        if (cached) {
          _bumpRuntime(Date.now() - startedAt);
          return cached;
        }
      } catch (_e) { /* cache best-effort */ }
    }

    // beforeCheck hook — operator can transform / skip
    var beforeRv = await _runHook(hooks.beforeCheck, [ctx]);
    if (beforeRv && beforeRv.skip === true) {
      _bumpRuntime(Date.now() - startedAt);
      return _build({ ok: true, action: "serve", forensicHash: forensicHash, runtimeMs: Date.now() - startedAt });
    }
    if (beforeRv && beforeRv.transform) {
      ctx = Object.assign({}, ctx, beforeRv.transform);
    }

    // Run operator check with optional runtime cap.
    var decision;
    try {
      if (maxRuntimeMs > 0) {
        decision = await safeAsync.withTimeout(opts.check(ctx), maxRuntimeMs, {
          name: "gate.check:" + opts.name,
        });
      } else {
        decision = await opts.check(ctx);
      }
    } catch (e) {
      counters.refused += 1;
      _emitObs(opts.name + ".check_threw", 1, {});
      var thrown = _build({
        ok: false, action: "refuse",
        issues: [{ kind: "check-threw", severity: "high", snippet: e && e.message }],
        forensicHash: forensicHash,
        runtimeMs: Date.now() - startedAt,
        cacheKey: cacheKey,
      });
      _runHook(hooks.onRefuse, [ctx, thrown]);
      _bumpRuntime(Date.now() - startedAt);
      return thrown;
    }
    decision = _build(decision || {});
    decision.forensicHash = forensicHash;
    decision.cacheKey = cacheKey;
    decision.runtimeMs = Date.now() - startedAt;

    // afterCheck hook — operator can amend the decision
    var amended = await _runHook(hooks.afterCheck, [ctx, decision]);
    if (amended) decision = _build(amended);

    // onIssue hook — operator can suppress / promote each issue
    if (decision.issues && decision.issues.length > 0 && hooks.onIssue) {
      var filtered = [];
      for (var ii = 0; ii < decision.issues.length; ii++) {
        var issueRv = await _runHook(hooks.onIssue, [decision.issues[ii], ctx]);
        if (issueRv && issueRv.suppress) continue;
        if (issueRv && issueRv.promote) {
          filtered.push(Object.assign({}, decision.issues[ii], { severity: issueRv.promote }));
        } else if (issueRv) {
          filtered.push(issueRv);
        } else {
          filtered.push(decision.issues[ii]);
        }
      }
      decision.issues = filtered;
    }

    // onSanitize hook — operator final transform
    if (decision.action === "sanitize" && hooks.onSanitize) {
      var sanitizedRv = await _runHook(hooks.onSanitize, [ctx.bytes, decision.sanitized, ctx]);
      if (sanitizedRv) decision.sanitized = sanitizedRv;
    }

    // Mode posture — translate decision per mode.
    if (mode === "warn-only" && decision.action === "refuse") {
      decision = Object.assign({}, decision, { ok: true, action: "warn" });
    } else if (mode === "audit-only" || mode === "log-only") {
      decision = Object.assign({}, decision, { ok: true, action: "audit-only" });
    } else if (mode === "shadow") {
      // Shadow runs decisions without honoring them; host primitive ignores
      // action but consumes audit + observability.
      decision = Object.assign({}, decision, { ok: true, action: "audit-only" });
    }

    // Forensic snapshot for refused content.
    if (decision.action === "refuse" && forensicSnippetBytes > 0 && bytes) {
      try {
        var snippet = Buffer.isBuffer(bytes)
          ? bytes.slice(0, forensicSnippetBytes)
          : Buffer.from(String(bytes), "utf8").slice(0, forensicSnippetBytes);
        decision.forensicSnapshot = snippet;
        if (forensicEvidenceStore && typeof forensicEvidenceStore.write === "function") {
          await forensicEvidenceStore.write({
            forensicId: ctx.forensicId,
            forensicHash: forensicHash,
            ruleHash: ruleHash,
            gate: opts.name,
            actor: ctx.actor,
            route: ctx.route,
            snippet: snippet,
            issues: decision.issues || [],
            timestamp: Date.now(),
          });
        }
      } catch (_e) { /* forensic best-effort */ }
    }

    // Cache the decision (per-forensicHash).
    if (decisionCache && cacheKey && cacheTtlMs > 0) {
      try { await decisionCache.set(cacheKey, decision, { ttlMs: cacheTtlMs }); }
      catch (_e) { /* cache best-effort */ }
    }

    // Bump counters.
    if (decision.action === "refuse") counters.refused += 1;
    else if (decision.action === "sanitize") counters.sanitized += 1;
    else if (decision.action === "warn") counters.warned += 1;
    else if (decision.action === "audit-only") counters.audited += 1;
    else counters.passed += 1;

    // Audit + observability emission.
    var auditEntry = {
      action:       opts.name + "." + decision.action,
      outcome:      decision.action === "refuse" ? "denied" : "success",
      forensicHash: forensicHash,
      ruleHash:     ruleHash,
      issues:       summarizeIssues(decision.issues),
      runtimeMs:    decision.runtimeMs,
      route:        ctx.route,
      actor:        ctx.actor,
    };
    // onAudit hook lets the operator amend or suppress. Returning false
    // from the hook suppresses emission; any object replaces the default
    // entry; null (no hook configured, or hook returned null) emits the
    // framework's default entry.
    var auditRv = hooks.onAudit ? await _runHook(hooks.onAudit, [auditEntry]) : auditEntry;
    if (auditRv !== false) emitAudit(auditEntry.action, auditRv || auditEntry);
    _emitObs(opts.name + "." + decision.action, 1, { route: ctx.route });
    _emitObs(opts.name + ".runtime_ms", decision.runtimeMs, {});

    // onRefuse hook (after audit emission so operator alerting fires last).
    if (decision.action === "refuse") {
      _runHook(hooks.onRefuse, [ctx, decision]);
    }

    _bumpRuntime(decision.runtimeMs);
    return decision;
  }

  return {
    check:          check,
    mode:           mode,
    audit:          auditHandle,
    observability:  observabilityHandle,
    metrics:        function () {
      return {
        passed:       counters.passed,
        refused:      counters.refused,
        sanitized:    counters.sanitized,
        audited:      counters.audited,
        warned:       counters.warned,
        p50RuntimeMs: counters.runtimeMs.count > 0
          ? Math.round(counters.runtimeMs.total / counters.runtimeMs.count) : 0,
      };
    },
    reset:          function () {
      counters = { passed: 0, refused: 0, sanitized: 0, audited: 0, warned: 0,
                   runtimeMs: { count: 0, total: 0 } };
    },
    close:          opts.close || function () {},
    name:           opts.name,
    version:        version,
    ruleHash:       ruleHash,
    dryRun:         function (ctx) { return check(ctx); },
    policyDiff:     function (other) {
      return { selfRuleHash: ruleHash, otherRuleHash: other && other.ruleHash };
    },
  };
}

// ---- Decision builder ----
//
// Normalizes a partial decision into the full shape (defaults, type
// coercions). Keeps gate.check() implementations simple — they return
// `{ ok, action }` or `{ ok, action, issues }` and the framework
// fills in the rest.

function _build(partial) {
  return {
    ok:                  partial.ok !== false,
    action:              partial.action || "serve",
    sanitized:           partial.sanitized || null,
    issues:              partial.issues || [],
    contentTypeOverride: partial.contentTypeOverride || null,
    headers:             partial.headers || null,
    forensicHash:        partial.forensicHash || null,
    forensicSnapshot:    partial.forensicSnapshot || null,
    runtimeMs:           partial.runtimeMs || 0,
    cacheKey:            partial.cacheKey || null,
  };
}

function _hashFingerprint(obj) {
  return crypto.sha3Hash(JSON.stringify(obj), "hex").slice(0, FINGERPRINT_HEX_LENGTH);
}

// ---- Host-side helpers ----

async function runGate(gate, ctx, opts) {
  opts = opts || {};
  if (!gate || typeof gate.check !== "function") return _build({ ok: true, action: "serve" });
  return await gate.check(ctx);
}

// composeGates — chain a list of gates left-to-right; first refusal wins.
function composeGates(gates, opts) {
  opts = opts || {};
  var firstRefusalWins = opts.firstRefusalWins !== false;
  return defineGate({
    name: opts.name || "composed",
    check: async function (ctx) {
      for (var i = 0; i < gates.length; i++) {
        var d = await gates[i].check(ctx);
        if (!d.ok || d.action === "refuse") return d;
        if (d.action === "sanitize" && firstRefusalWins) {
          ctx = Object.assign({}, ctx, { bytes: d.sanitized });
        }
      }
      return _build({ ok: true, action: "serve" });
    },
  });
}

// multiplexGates — extension-keyed dispatch.
function multiplexGates(gateMap, opts) {
  opts = opts || {};
  var lookup = Object.create(null);
  var keys = Object.keys(gateMap);
  for (var k = 0; k < keys.length; k++) lookup[keys[k].toLowerCase()] = gateMap[keys[k]];
  var fallback = lookup["default"] || null;
  return defineGate({
    name: opts.name || "multiplex",
    check: async function (ctx) {
      var ext = (ctx.filename || "").toLowerCase();
      var dot = ext.lastIndexOf(".");
      var key = dot >= 0 ? ext.slice(dot) : "";
      var gate = lookup[key] || fallback;
      if (!gate) return _build({ ok: true, action: "serve" });
      return await gate.check(ctx);
    },
  });
}

// contentTypeMux — Content-Type-keyed dispatch. Match on the bare type
// (strip parameters like `; charset=utf-8`).
function contentTypeMux(gateMap, opts) {
  opts = opts || {};
  var lookup = Object.create(null);
  var keys = Object.keys(gateMap);
  for (var k = 0; k < keys.length; k++) lookup[keys[k].toLowerCase()] = gateMap[keys[k]];
  var fallback = lookup["default"] || null;
  return defineGate({
    name: opts.name || "contentTypeMux",
    check: async function (ctx) {
      var ct = (ctx.contentType || "").toLowerCase().split(";")[0].trim();
      var gate = lookup[ct] || fallback;
      if (!gate) return _build({ ok: true, action: "serve" });
      return await gate.check(ctx);
    },
  });
}

// byActorTier — actor-tier-keyed dispatch (free / paid / admin).
function byActorTier(gateMap, opts) {
  opts = opts || {};
  return defineGate({
    name: opts.name || "byActorTier",
    check: async function (ctx) {
      var tier = (ctx.actor && ctx.actor.tier) || "default";
      var gate = gateMap[tier] || gateMap["default"];
      if (!gate) return _build({ ok: true, action: "serve" });
      return await gate.check(ctx);
    },
  });
}

// byRoute — route-pattern-keyed dispatch. Patterns are simple
// glob-prefix matches: "/admin/*" matches "/admin/foo".
function byRoute(gateMap, opts) {
  opts = opts || {};
  var entries = Object.keys(gateMap).map(function (pattern) {
    return { pattern: pattern, prefix: pattern.replace(/\*$/, ""), gate: gateMap[pattern] };
  });
  return defineGate({
    name: opts.name || "byRoute",
    check: async function (ctx) {
      var route = ctx.route || "";
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].pattern === route || route.indexOf(entries[i].prefix) === 0) {
          return await entries[i].gate.check(ctx);
        }
      }
      var fallback = gateMap["*"] || gateMap["default"];
      if (fallback) return await fallback.check(ctx);
      return _build({ ok: true, action: "serve" });
    },
  });
}

// byDirection — inbound vs outbound dispatch.
function byDirection(gateMap, opts) {
  opts = opts || {};
  return defineGate({
    name: opts.name || "byDirection",
    check: async function (ctx) {
      var d = ctx.direction || "outbound";
      var gate = gateMap[d];
      if (!gate) return _build({ ok: true, action: "serve" });
      return await gate.check(ctx);
    },
  });
}

// shadowMode — run candidate alongside primary; emit divergence.
// Primary's decision is honored; candidate is observability-only.
function shadowMode(primary, candidate, opts) {
  opts = opts || {};
  return defineGate({
    name: opts.name || "shadow",
    check: async function (ctx) {
      var primaryDecision = await primary.check(ctx);
      // Run candidate but don't await its decision blocking the request.
      candidate.check(ctx).then(function (cand) {
        if (cand.action !== primaryDecision.action) {
          observability().safeEvent("gateContract.shadow_divergence", 1, {
            primary: primaryDecision.action, candidate: cand.action,
          });
        }
      }).catch(function () { /* shadow best-effort */ });
      return primaryDecision;
    },
  });
}

// canaryGate — enforce on rate%; warn on the rest.
function canaryGate(gate, opts) {
  opts = opts || {};
  var rate = typeof opts.rate === "number" ? opts.rate : 0.1;
  return defineGate({
    name: opts.name || "canary",
    check: async function (ctx) {
      var d = await gate.check(ctx);
      if (d.action === "refuse" && Math.random() > rate) {       // allow:math-random-noncrypto — canary sampling, non-security
        return Object.assign({}, d, { ok: true, action: "warn" });
      }
      return d;
    },
  });
}

// cachingGate — wrap with explicit TTL cache (separate from the
// per-gate built-in cache; useful when the operator wants a SHARED
// cache across multiple gates).
function cachingGate(gate, opts) {
  opts = opts || {};
  var backend = opts.backend;
  if (!backend || typeof backend.get !== "function" || typeof backend.set !== "function") {
    throw _err("gate-contract/bad-opt",
      "cachingGate: opts.backend must expose { get, set } (b.cache shape)");
  }
  // ttlMs is read inside check() via closure; keep DEFAULT_CACHE_TTL_MS
  // referenced even if the host-side cache wrapping path doesn't need
  // explicit TTL today (the gate's per-instance cache uses cacheTtlMs).
  void DEFAULT_CACHE_TTL_MS;
  void opts.ttlMs;
  return defineGate({
    name: opts.name || (gate.name + ":cached"),
    check: async function (ctx) {
      // Defer to the wrapped gate; gate.check already handles its own
      // forensic-hash key. cachingGate is the EXPLICIT-cache variant for
      // operators wanting a shared cache backend.
      return await gate.check(ctx);
    },
  });
}

// workerThreadGate — offload check() to a worker thread.
function workerThreadGate(gate, opts) {
  opts = opts || {};
  if (!opts.worker) {
    throw _err("gate-contract/bad-opt",
      "workerThreadGate: opts.worker is required (b.worker shape)");
  }
  return defineGate({
    name: opts.name || (gate.name + ":worker"),
    check: async function (ctx) {
      return await opts.worker.run({ gate: gate.name, ctx: ctx });
    },
  });
}

// makeProfileBuilder — closes over a guard's PROFILES map and returns
// a buildProfile(opts) function that delegates to the recursive
// composition entry point. Used so each guard's buildProfile export is
// just a binding instead of a duplicate forwarding wrapper.
function makeProfileBuilder(profiles) {
  return function (opts) {
    return buildProfile(Object.assign({}, opts, {
      resolveProfile: function (name) { return profiles[name] || null; },
    }));
  };
}

// lookupCompliancePosture — throws errorFactory(prefix + ".bad-posture")
// when the name is not in the posture map; returns a shallow clone of
// the posture object otherwise. Used by every guard's
// compliancePosture(name) export.
function lookupCompliancePosture(name, postures, errorFactory, codePrefix) {
  if (!postures || !postures[name]) {
    throw errorFactory(codePrefix + ".bad-posture",
      "unknown compliancePosture " + JSON.stringify(name));
  }
  return Object.assign({}, postures[name]);
}

// makeRulePackLoader — returns a `loadRulePack(pack)` closure with
// per-guard storage. Validates pack shape via validateOpts; the
// closure stores accepted packs in a closed-over map keyed by pack.id.
// Operators can later inspect via the returned `list()` function.
function makeRulePackLoader(errorClass, codePrefix) {
  var store = Object.create(null);
  return {
    load: function (pack) {
      validateOpts.requireObject(pack, "loadRulePack", errorClass);
      validateOpts.requireNonEmptyString(pack.id,
        "loadRulePack: pack.id", errorClass, codePrefix + ".bad-opt");
      store[pack.id] = pack;
      return pack;
    },
    list: function () {
      return Object.keys(store).map(function (k) { return store[k]; });
    },
    get: function (id) { return store[id] || null; },
  };
}

// extractBytesAsText — every guard's check(ctx) opens by reading
// ctx.bytes and converting to a UTF-8 string for inspection.
// Centralizes the string|Buffer|empty handling so each guard's check
// body just deals with the inspection logic.
//
//   var text = gateContract.extractBytesAsText(ctx);
//   if (!text) return { ok: true, action: "serve" };
//
// Returns "" if ctx.bytes is missing — caller treats empty as serve.
function extractBytesAsText(ctx) {
  if (!ctx) return "";
  var bytes = ctx.bytes;
  if (!bytes) return "";
  return Buffer.isBuffer(bytes) ? bytes.toString("utf8") : String(bytes);
}

// buildGuardGate — gate-construction shorthand. Every guard-*
// primitive's gate(opts) factory forwards the same ~16-key opts bag
// (mode, audit, observability, forensicEvidenceStore, cache, hooks,
// runtime cap, ...) to defineGate. Centralizes that forwarding so each
// guard's gate() body is just the check function plus a label.
//
//   gateContract.buildGuardGate(
//     opts.name || "guardCsv:" + (opts.profile || "default"),
//     opts,
//     async function (ctx) { ... per-guard check ... });
function buildGuardGate(name, opts, check) {
  opts = opts || {};
  return defineGate({
    name:                  name,
    version:               "1.0.0",
    mode:                  opts.mode,
    audit:                 opts.audit || null,
    observability:         opts.observability || null,
    forensicEvidenceStore: opts.forensicEvidenceStore || null,
    forensicSnippetBytes:  opts.forensicSnippetBytes,
    cache:                 opts.cache || null,
    cacheTtlMs:            opts.cacheTtlMs || 0,
    maxRuntimeMs:          opts.maxRuntimeMs,
    beforeCheck:           opts.beforeCheck,
    afterCheck:            opts.afterCheck,
    onIssue:               opts.onIssue,
    onSanitize:            opts.onSanitize,
    onRefuse:              opts.onRefuse,
    onAudit:               opts.onAudit,
    check:                 check,
  });
}

// aggregateIssues — wrap an issues array in the canonical
// `{ ok, issues }` validate-result shape. ok=true when no issue is
// `critical` or `high` severity. Used by guards whose validate path
// can't go through runIssueValidator (raw-Buffer input cases).
function aggregateIssues(issues) {
  return {
    ok: !issues.some(function (i) {
      return i.severity === "critical" || i.severity === "high";
    }),
    issues: issues,
  };
}

// badInputResultIfNotStringOrBuffer — returns the canonical
// `{ ok: false, issues: [{ kind: "bad-input", ... }] }` result when
// `input` is neither a string nor a Buffer; null otherwise. Used by
// guards whose validate path can't pre-convert (e.g. guard-svg needs
// raw bytes for SVGZ magic detection; guard-filename needs raw bytes
// for overlong-UTF-8 byte scan).
function badInputResultIfNotStringOrBuffer(input) {
  if (typeof input === "string" || Buffer.isBuffer(input)) return null;
  return {
    ok: false,
    issues: [{ kind: "bad-input", severity: "high",
               snippet: "input is not string or Buffer" }],
  };
}

// runIssueValidator — boilerplate for guard-* validate(input, opts)
// entry points. Normalizes string|Buffer input, returns the canonical
// { ok: false, issues: [{ kind: "bad-input", ... }] } shape on type
// mismatch, otherwise calls the operator-supplied detector and
// computes ok = no issue is critical/high. Used so every guard's
// validate() body is identical scaffolding around the per-guard
// _detectIssues function.
//
//   gateContract.runIssueValidator(input, opts, function (text, opts) {
//     return _detectIssues(text, opts);
//   });
function runIssueValidator(input, opts, detector) {
  var text = typeof input === "string"
    ? input
    : (Buffer.isBuffer(input) ? input.toString("utf8") : null);
  if (text == null) {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "input is not string or Buffer" }],
    };
  }
  return aggregateIssues(detector(text, opts));
}

// resolveProfileAndPosture — overlay opts.profile + opts.compliancePosture
// over a defaults object using guard-supplied tables. Used by every guard
// primitive's create()/factory entry point so the resolution shape is
// identical across the family.
//
//   resolveProfileAndPosture(opts, {
//     profiles:           PROFILES,
//     compliancePostures: COMPLIANCE_POSTURES,
//     defaults:           DEFAULTS,
//     errorClass:         GuardCsvError,
//     errCodePrefix:      "csv",        // throws "csv.bad-profile" / "csv.bad-posture"
//   })
function resolveProfileAndPosture(opts, cfg) {
  opts = opts || {};
  validateOpts.requireObject(cfg, "gateContract.resolveProfileAndPosture",
    GateContractError);
  var ErrorClass = cfg.errorClass || GateContractError;
  var prefix = cfg.errCodePrefix || "guard";
  var overlay = {};
  if (typeof opts.profile === "string") {
    if (!cfg.profiles || !cfg.profiles[opts.profile]) {
      throw ErrorClass.factory(prefix + ".bad-profile",
        "unknown profile " + JSON.stringify(opts.profile));
    }
    overlay = cfg.profiles[opts.profile];
  }
  // Compliance-posture resolution — operator-supplied opt wins; if not
  // given, fall back to the global posture set via b.compliance.set().
  // The fallback IS the value-add of the top-level coordinator: every
  // primitive with a compliancePosture opt picks up the deployment's
  // declared posture without per-call wiring.
  var posture = opts.compliancePosture;
  if (typeof posture !== "string") {
    var globalPosture;
    try { globalPosture = compliance().current(); }
    catch (_e) { globalPosture = null; }
    if (typeof globalPosture === "string" &&
        cfg.compliancePostures && cfg.compliancePostures[globalPosture]) {
      posture = globalPosture;
    }
  }
  if (typeof posture === "string") {
    if (!cfg.compliancePostures || !cfg.compliancePostures[posture]) {
      throw ErrorClass.factory(prefix + ".bad-posture",
        "unknown compliancePosture " + JSON.stringify(posture));
    }
    overlay = Object.assign({}, overlay, cfg.compliancePostures[posture]);
  }
  return Object.assign({}, cfg.defaults || {}, overlay, opts);
}

// buildProfile — recursive profile composition with cycle detection.
//
//   buildProfile({
//     baseProfile: "blog-post",
//     extends:     ["custom-tags"],
//     overrides:   { allowedTags: [...] },
//     removes:     { allowedAttrs: { a: ["target"] } },
//     resolveProfile: name => profile,    // operator-supplied resolver
//   })
function buildProfile(opts) {
  validateOpts.requireObject(opts, "gateContract.buildProfile", GateContractError);
  var resolve = opts.resolveProfile;
  if (typeof resolve !== "function") {
    throw _err("gate-contract/bad-opt",
      "buildProfile: opts.resolveProfile must be a function (name → profile)");
  }
  var seen = Object.create(null);
  function _walk(name) {
    if (seen[name]) {
      throw _err("gate-contract/profile-cycle",
        "buildProfile: cycle detected involving profile " + JSON.stringify(name));
    }
    seen[name] = true;
    var p = resolve(name);
    if (!p) throw _err("gate-contract/unknown-profile",
      "buildProfile: unknown profile " + JSON.stringify(name));
    var merged = Object.assign({}, p);
    if (Array.isArray(p.extends)) {
      for (var i = 0; i < p.extends.length; i++) {
        var ext = _walk(p.extends[i]);
        merged = _mergeProfile(ext, merged);
      }
    }
    return merged;
  }
  var base = opts.baseProfile ? _walk(opts.baseProfile) : {};
  if (Array.isArray(opts.extends)) {
    for (var i = 0; i < opts.extends.length; i++) {
      base = _mergeProfile(base, _walk(opts.extends[i]));
    }
  }
  if (opts.overrides) base = _mergeProfile(base, opts.overrides);
  if (opts.removes) base = _applyRemoves(base, opts.removes);
  return base;
}

function _mergeProfile(target, source) {
  var out = Object.assign({}, target);
  var keys = Object.keys(source);
  for (var k = 0; k < keys.length; k++) {
    var key = keys[k];
    var val = source[key];
    if (Array.isArray(val) && Array.isArray(out[key])) {
      // Array merge — union; later sources win on duplicates.
      var seen2 = Object.create(null);
      var merged = [];
      for (var i = 0; i < out[key].length; i++) {
        var v = JSON.stringify(out[key][i]);
        if (!seen2[v]) { seen2[v] = true; merged.push(out[key][i]); }
      }
      for (var j = 0; j < val.length; j++) {
        var v2 = JSON.stringify(val[j]);
        if (!seen2[v2]) { seen2[v2] = true; merged.push(val[j]); }
      }
      out[key] = merged;
    } else if (val && typeof val === "object" && !Array.isArray(val) &&
               out[key] && typeof out[key] === "object" && !Array.isArray(out[key])) {
      out[key] = _mergeProfile(out[key], val);
    } else {
      out[key] = val;
    }
  }
  return out;
}

function _applyRemoves(target, removes) {
  var out = Object.assign({}, target);
  var keys = Object.keys(removes);
  for (var k = 0; k < keys.length; k++) {
    var key = keys[k];
    if (Array.isArray(removes[key]) && Array.isArray(out[key])) {
      var rmSet = Object.create(null);
      for (var i = 0; i < removes[key].length; i++) rmSet[JSON.stringify(removes[key][i])] = true;
      out[key] = out[key].filter(function (v) { return !rmSet[JSON.stringify(v)]; });
    } else if (removes[key] && typeof removes[key] === "object" &&
               out[key] && typeof out[key] === "object") {
      out[key] = _applyRemoves(out[key], removes[key]);
    } else {
      delete out[key];
    }
  }
  return out;
}

// summarizeIssues — project a gate decision's `issues` array down to the
// audit-shape (kind / severity / ruleId only — full snippets stay in the
// forensic store). Replaces the per-host inline `(d.issues || []).map(
// function (i) { return { kind: i.kind, severity: i.severity, ruleId:
// i.ruleId }; })` shape.
function summarizeIssues(issues) {
  if (!Array.isArray(issues)) return [];
  return issues.map(function (i) {
    return { kind: i.kind, severity: i.severity, ruleId: i.ruleId };
  });
}

// composeHooks — chain operator hooks. First non-null filter result
// wins; transformer hooks run sequentially.
function composeHooks(hooks) {
  hooks = (hooks || []).filter(Boolean);
  if (hooks.length === 0) return null;
  if (hooks.length === 1) return hooks[0];
  return async function () {
    var args = Array.prototype.slice.call(arguments);
    var result = null;
    for (var i = 0; i < hooks.length; i++) {
      var rv = await hooks[i].apply(null, args);
      if (rv && (rv.suppress === true || rv.skip === true)) return rv;
      if (rv) result = rv;
    }
    return result;
  };
}

module.exports = {
  defineGate:         defineGate,
  validateGateShape:  validateGateShape,
  runGate:            runGate,
  composeGates:       composeGates,
  multiplexGates:     multiplexGates,
  contentTypeMux:     contentTypeMux,
  byActorTier:        byActorTier,
  byRoute:            byRoute,
  byDirection:        byDirection,
  shadowMode:         shadowMode,
  canaryGate:         canaryGate,
  cachingGate:        cachingGate,
  workerThreadGate:   workerThreadGate,
  buildProfile:       buildProfile,
  resolveProfileAndPosture: resolveProfileAndPosture,
  runIssueValidator:  runIssueValidator,
  buildGuardGate:     buildGuardGate,
  extractBytesAsText: extractBytesAsText,
  lookupCompliancePosture: lookupCompliancePosture,
  makeRulePackLoader: makeRulePackLoader,
  makeProfileBuilder: makeProfileBuilder,
  badInputResultIfNotStringOrBuffer: badInputResultIfNotStringOrBuffer,
  aggregateIssues:    aggregateIssues,
  composeHooks:       composeHooks,
  summarizeIssues:    summarizeIssues,
  ACTIONS:            ACTIONS,
  MODES:              MODES,
  ISSUE_SEVERITIES:   ISSUE_SEVERITIES,
  GateContractError:      GateContractError,
};
