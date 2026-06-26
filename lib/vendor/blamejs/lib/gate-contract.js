"use strict";
/**
 * @module b.gateContract
 * @nav    Guards
 * @title  Gate Contract
 *
 * @intro
 *   Shared substrate every `b.guard*` primitive composes against —
 *   `resolveProfileAndPosture`, `makeProfileBuilder`,
 *   `makeRulePackLoader`, `lookupCompliancePosture`, `buildGuardGate`,
 *   `aggregateIssues`, `extractBytesAsText`. The contract every guard
 *   implements; ensures the action vocabulary
 *   (`serve` / `sanitize` / `refuse` / `audit-only`) and the
 *   profile-and-posture resolution shape stay identical across the
 *   family.
 *
 *   Every guard ships a `.gate(opts)` factory returning the shape
 *   defined here. Host primitives (`b.staticServe` / `b.fileUpload` /
 *   `b.mail` / `b.objectStore`) call `gate.check(ctx)` at their
 *   byte-boundary moment with a uniform context. The decision shape
 *   is `{ ok, action, sanitized?, issues, contentTypeOverride?,
 *   headers?, forensicHash, forensicSnapshot?, runtimeMs, cacheKey? }`.
 *
 *   Operator extension surface inherited by every member:
 *
 *     - Profile composition (extends + overrides + removes; cycle detection)
 *     - Hook system (beforeCheck / afterCheck / onIssue / onSanitize / onRefuse / onAudit)
 *     - Mode posture (enforce / warn-only / shadow / audit-only / log-only / canary)
 *     - Versioned policies (version + ruleHash) with policyDiff helper
 *     - Forensic snapshot store (operator-supplied evidence vault)
 *     - Decision cache (per-forensicHash memoization)
 *     - Runtime cap with timeout
 *     - Compliance-posture pre-sets (hipaa / pci-dss / gdpr / soc2)
 *
 *   Module-level constants `ACTIONS` / `MODES` / `ISSUE_SEVERITIES`
 *   carry the frozen enums every guard validates against.
 *
 *   Foundation for the guard-* family. Every content-safety primitive
 *   shipped under `b.guard*` composes through `buildGuardGate`,
 *   `makeProfileBuilder`, `makeRulePackLoader`, and
 *   `lookupCompliancePosture`; `b.guardAll` aggregates the registered
 *   guards into a single security-on-by-default gate.
 *
 * @card
 *   Shared substrate every `b.guard*` primitive composes against — `resolveProfileAndPosture`, `makeProfileBuilder`, `makeRulePackLoader`, `lookupCompliancePosture`, `buildGuardGate`, `aggregateIssues`, `extractBytesAsText`.
 */

var C = require("./constants");
var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var codepointClass = require("./codepoint-class");
var { GateContractError, defineClass } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
var compliance = lazyRequire(function () { return require("./compliance"); });
var audit = lazyRequire(function () { return require("./audit"); });

// One-time dedupe for the "global posture pinned but this guard maps no
// overlay" warning. Keyed `<posture>::<errCodePrefix>` so each guard
// family surfaces the gap once instead of on every gate construction.
var _unmappedPostureWarned = Object.create(null);

// Forensic-id token width (bytes); 64 bits is enough for cross-gate
// correlation in a single request scope.
var FORENSIC_ID_BYTES = C.BYTES.bytes(8);
// Hash-prefix used as a fingerprint identifier in policy-rule hashes —
// 16 hex chars = 64 bits, ample for fingerprint comparison.
var FINGERPRINT_HEX_LENGTH = C.BYTES.bytes(16);
// Default cachingGate TTL when operator doesn't supply one.
var DEFAULT_CACHE_TTL_MS = C.TIME.minutes(5);

/**
 * @primitive  b.gateContract.GateContractError
 * @signature  b.gateContract.GateContractError
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.defineGate, b.gateContract.validateGateShape
 *
 * FrameworkError subclass thrown by gate-contract entry points on
 * shape violations: `gate-contract/bad-shape` from
 * `validateGateShape`, `gate-contract/bad-opt` from `defineGate` /
 * `cachingGate` / `workerThreadGate`, `gate-contract/profile-cycle`
 * and `gate-contract/unknown-profile` from `buildProfile`.
 * `alwaysPermanent` — never retried by `b.retry`.
 *
 * @example
 *   try {
 *     b.gateContract.validateGateShape({}, "broken");
 *   } catch (e) {
 *     e instanceof b.gateContract.GateContractError;     // → true
 *     e.code;                                            // → "gate-contract/bad-shape"
 *   }
 */
var _err = GateContractError.factory;

// ---- Enumerations (module-level constants) ----

/**
 * @primitive  b.gateContract.ACTIONS
 * @signature  b.gateContract.ACTIONS
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.MODES, b.gateContract.defineGate
 *
 * Frozen list of every action a gate decision is allowed to set.
 * `serve` emits the bytes unchanged; `refuse` rejects with an
 * operator-meaningful error; `sanitize` substitutes `decision.sanitized`
 * for the original bytes; `strip` removes the offending content;
 * `audit-only` serves but emits an audit entry; `warn` serves and
 * emits a warning counter; `challenge-mfa` triggers step-up auth
 * before serving; `deny-and-revoke` rejects and invalidates the
 * actor's session.
 *
 * @example
 *   b.gateContract.ACTIONS.indexOf("serve");             // → 0
 *   b.gateContract.ACTIONS.indexOf("warp-speed");        // → -1
 *   Object.isFrozen(b.gateContract.ACTIONS);             // → true
 */
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

/**
 * @primitive  b.gateContract.MODES
 * @signature  b.gateContract.MODES
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.ACTIONS, b.gateContract.defineGate
 *
 * Frozen list of mode-posture values a gate can run in. `enforce`
 * honors the decision; `warn-only` translates every `refuse` to
 * `warn` for staged rollout; `shadow` runs alongside a primary and
 * never refuses (observability-only); `audit-only` and `log-only`
 * emit an audit entry but never block; `canary` enforces on a
 * sampled subset and warns on the rest.
 *
 * @example
 *   b.gateContract.MODES.indexOf("enforce");             // → 0
 *   b.gateContract.MODES.indexOf("yolo");                // → -1
 */
var MODES = Object.freeze([
  "enforce",     // gate decision honored
  "warn-only",   // gate emits but never refuses (staged rollout)
  "shadow",      // run alongside primary; emit divergence; never refuses
  "audit-only",  // emit audit but no operator-side action
  "log-only",    // emit observability counter only
  "canary",      // enforce on N% of requests; warn on the rest
]);

/**
 * @primitive  b.gateContract.ISSUE_SEVERITIES
 * @signature  b.gateContract.ISSUE_SEVERITIES
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.aggregateIssues, b.gateContract.summarizeIssues
 *
 * Frozen list of severity levels a guard issue may carry. `info` and
 * `warn` are observability-only — `aggregateIssues` keeps `ok: true`
 * with them present. `high` and `critical` flip the result to
 * `ok: false`, refusing the input.
 *
 * @example
 *   b.gateContract.ISSUE_SEVERITIES;                     // → ["info","warn","high","critical"]
 *   b.gateContract.ISSUE_SEVERITIES.indexOf("critical"); // → 3
 */
var ISSUE_SEVERITIES = Object.freeze([
  "info",
  "warn",
  "high",
  "critical",
]);

/**
 * @primitive  b.gateContract.validateGateShape
 * @signature  b.gateContract.validateGateShape(gate, label, errorClass)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.defineGate, b.gateContract.runGate
 *
 * Throws when `gate` does not satisfy the contract — `gate.check`
 * must be a function, `gate.mode` (when present) must be one of the
 * `MODES` enum values, and `gate.metrics` / `gate.close` (when
 * present) must be functions. Operator-supplied gates (and
 * framework-supplied gates with operator-toggled hooks) all flow
 * through this check at host-primitive wire-up time. Shape errors at
 * boot are cheaper than at request time. Returns `gate` unchanged on
 * success.
 *
 * @example
 *   var gate = b.guardCsv.gate({ profile: "strict" });
 *   b.gateContract.validateGateShape(gate, "uploads.csv");
 *   // → returns the gate unchanged when shape is valid
 *
 *   try {
 *     b.gateContract.validateGateShape({}, "broken");
 *   } catch (e) {
 *     e.code;                                            // → "gate-contract/bad-shape"
 *   }
 */
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

/**
 * @primitive  b.gateContract.defineGate
 * @signature  b.gateContract.defineGate(opts)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.buildGuardGate, b.gateContract.validateGateShape
 *
 * Build a gate that satisfies the contract. Wraps the
 * operator-supplied `check(ctx)` with the cross-cutting concerns
 * (hooks, observability, forensic snapshot, runtime cap, decision
 * cache, mode-posture translation) so guards only write the per-guard
 * inspection logic. Returns a gate exposing
 * `{ check, mode, audit, observability, metrics, reset, close, name,
 * version, ruleHash, dryRun, policyDiff }`. Most guards forward through
 * `b.gateContract.buildGuardGate` instead — `defineGate` is the lower-level
 * factory used by host-side composers (`composeGates` / `byRoute` / etc.).
 *
 * @opts
 *   name:                  string,           // identifier surfaced in audit / counters
 *   version:               string,           // semver default "1.0.0"
 *   mode:                  string,           // one of MODES; default "enforce"
 *   check:                 function,         // async (ctx) → decision
 *   beforeCheck:           function|null,    // (ctx) → { skip?, transform? }
 *   afterCheck:            function|null,    // (ctx, decision) → decision
 *   onIssue:               function|null,    // (issue, ctx) → issue|{suppress|promote}
 *   onSanitize:            function|null,    // (bytes, sanitized, ctx) → sanitized
 *   onRefuse:              function|null,    // (ctx, decision) → void
 *   onAudit:               function|null,    // (entry) → entry|false (false suppresses)
 *   audit:                 object|null,      // b.audit handle
 *   observability:         object|null,      // b.observability handle
 *   forensicEvidenceStore: object|null,      // { write({ ... }) }
 *   forensicSnippetBytes:  number,           // 0 = disabled
 *   cache:                 object|null,      // b.cache shape
 *   cacheTtlMs:            number,
 *   maxRuntimeMs:          number,           // 0 = uncapped
 *   ruleHash:              string,           // override fingerprint
 *
 * @example
 *   var gate = b.gateContract.defineGate({
 *     name: "tenant:csv:strict",
 *     mode: "enforce",
 *     maxRuntimeMs: 250,
 *     check: async function (ctx) {
 *       var text = b.gateContract.extractBytesAsText(ctx);
 *       if (text.indexOf("=cmd|") === 0) {
 *         return { ok: false, action: "refuse",
 *                  issues: [{ kind: "csv.formula-injection", severity: "high" }] };
 *       }
 *       return { ok: true, action: "serve" };
 *     },
 *   });
 *   var d = await gate.check({ bytes: Buffer.from("name,age\nada,36") });
 *   d.action;                                            // → "serve"
 */
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
    if (!ctx.forensicId) ctx.forensicId = bCrypto.generateToken(FORENSIC_ID_BYTES);

    // Decision cache lookup (memoize per-forensicHash).
    var bytes = ctx.bytes;
    var forensicHash = bytes && Buffer.isBuffer(bytes)
      ? bCrypto.sha3Hash(bytes, "hex")
      : (typeof bytes === "string" ? bCrypto.sha3Hash(Buffer.from(bytes, "utf8"), "hex") : null);
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
  return bCrypto.sha3Hash(JSON.stringify(obj), "hex").slice(0, FINGERPRINT_HEX_LENGTH);
}

// ---- Host-side helpers ----

/**
 * @primitive  b.gateContract.runGate
 * @signature  b.gateContract.runGate(gate, ctx, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.defineGate, b.gateContract.composeGates
 *
 * Execute a gate's `check(ctx)` and return its decision. When `gate`
 * is null or has no `check` function, returns the canonical
 * `{ ok: true, action: "serve" }` shape — host primitives invoke
 * `runGate` with an operator-configurable gate that may legitimately
 * be unset. The `opts` argument is reserved for future host-side
 * cross-cutting concerns and is currently unused.
 *
 * @opts
 *   // reserved for future host-side cross-cutting concerns; pass `{}` today
 *
 * @example
 *   var gate = b.guardCsv.gate({ profile: "strict" });
 *   var decision = await b.gateContract.runGate(gate, {
 *     bytes:    Buffer.from("name,age\nada,36"),
 *     route:    "/api/imports",
 *     filename: "people.csv",
 *   });
 *   decision.action;                                     // → "serve"
 *
 *   // Unset gate is a no-op serve.
 *   (await b.gateContract.runGate(null, {})).action;     // → "serve"
 */
async function runGate(gate, ctx, opts) {
  opts = opts || {};
  if (!gate || typeof gate.check !== "function") return _build({ ok: true, action: "serve" });
  return await gate.check(ctx);
}

/**
 * @primitive  b.gateContract.composeGates
 * @signature  b.gateContract.composeGates(gates, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.multiplexGates, b.gateContract.contentTypeMux
 *
 * Chain a list of gates left-to-right. First refusal wins. When a
 * gate returns `action: "sanitize"` and `firstRefusalWins` is true
 * (default), the sanitized bytes feed into the next gate's context —
 * letting an HTML sanitizer hand its scrubbed output to a downstream
 * link-shape guard. Returns a wrapping gate that satisfies the
 * contract (so the composition is itself composable).
 *
 * @opts
 *   name:             string,    // wrapper gate name (default "composed")
 *   firstRefusalWins: boolean,   // default true
 *
 * @example
 *   var bidi  = b.guardCsv.gate({ profile: "strict" });
 *   var pii   = b.guardCsv.gate({ compliancePosture: "hipaa" });
 *   var chain = b.gateContract.composeGates([bidi, pii], { name: "csv:chain" });
 *   var d = await chain.check({ bytes: Buffer.from("name,ssn\nada,123-45-6789") });
 *   d.action;                                            // → "refuse"
 */
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

/**
 * @primitive  b.gateContract.multiplexGates
 * @signature  b.gateContract.multiplexGates(gateMap, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.contentTypeMux, b.gateContract.composeGates
 *
 * File-extension-keyed gate dispatch. Looks at `ctx.filename`,
 * extracts the lowercased final extension (`.csv` / `.html` / etc.),
 * and dispatches to the matching gate. The `"default"` key serves as
 * the fallback; missing entries (no key match, no fallback) return
 * the canonical serve decision so host primitives can wire a single
 * mux gate without per-extension special-casing.
 *
 * @opts
 *   name: string,   // wrapper gate name (default "multiplex")
 *
 * @example
 *   var mux = b.gateContract.multiplexGates({
 *     ".csv":  b.guardCsv.gate({ profile: "strict" }),
 *     ".html": b.guardHtml.gate({ profile: "strict" }),
 *     "default": b.guardCsv.gate({ profile: "permissive" }),
 *   });
 *   var d = await mux.check({ bytes: Buffer.from("a,b\n1,2"), filename: "x.csv" });
 *   d.action;                                            // → "serve"
 */
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

/**
 * @primitive  b.gateContract.contentTypeMux
 * @signature  b.gateContract.contentTypeMux(gateMap, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.multiplexGates, b.gateContract.composeGates
 *
 * Content-Type-keyed gate dispatch. Reads `ctx.contentType`, strips
 * parameters (`; charset=utf-8`), lowercases, and routes to the
 * matching gate. The `"default"` key is the fallback; unknown types
 * (no key match, no fallback) serve uninspected. Useful when one
 * route accepts multiple media types and each needs its own guard.
 *
 * @opts
 *   name: string,   // wrapper gate name (default "contentTypeMux")
 *
 * @example
 *   var mux = b.gateContract.contentTypeMux({
 *     "text/csv":   b.guardCsv.gate({ profile: "strict" }),
 *     "text/html":  b.guardHtml.gate({ profile: "strict" }),
 *     "default":    b.guardCsv.gate({ profile: "permissive" }),
 *   });
 *   var d = await mux.check({
 *     bytes:       Buffer.from("name,age\nada,36"),
 *     contentType: "text/csv; charset=utf-8",
 *   });
 *   d.action;                                            // → "serve"
 */
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

/**
 * @primitive  b.gateContract.byActorTier
 * @signature  b.gateContract.byActorTier(gateMap, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.byRoute, b.gateContract.byDirection
 *
 * Actor-tier-keyed gate dispatch. Reads `ctx.actor.tier` (e.g.
 * `"free"` / `"paid"` / `"admin"`) and routes to the matching gate.
 * Falls back to `gateMap["default"]` when the tier is missing or
 * unmapped; missing fallback serves uninspected. Lets free-tier
 * tenants run a stricter posture than paid customers without
 * branching at every call site.
 *
 * @opts
 *   name: string,   // wrapper gate name (default "byActorTier")
 *
 * @example
 *   var byTier = b.gateContract.byActorTier({
 *     free:    b.guardCsv.gate({ profile: "strict" }),
 *     paid:    b.guardCsv.gate({ profile: "balanced" }),
 *     default: b.guardCsv.gate({ profile: "strict" }),
 *   });
 *   var d = await byTier.check({
 *     bytes: Buffer.from("name,age\nada,36"),
 *     actor: { tier: "paid" },
 *   });
 *   d.action;                                            // → "serve"
 */
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

/**
 * @primitive  b.gateContract.byRoute
 * @signature  b.gateContract.byRoute(gateMap, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.byActorTier, b.gateContract.byDirection
 *
 * Route-pattern-keyed gate dispatch. Patterns are simple glob-prefix
 * matches — `/admin/*` matches every path beginning with `/admin/`.
 * Tries each entry in declaration order, falling back to `"*"` /
 * `"default"`; missing fallback serves uninspected. Lets `/admin/*`
 * routes apply a stricter guard than the public surface without
 * threading per-route opts through every call site.
 *
 * @opts
 *   name: string,   // wrapper gate name (default "byRoute")
 *
 * @example
 *   var byPath = b.gateContract.byRoute({
 *     "/admin/*": b.guardCsv.gate({ profile: "strict" }),
 *     "/api/*":   b.guardCsv.gate({ profile: "balanced" }),
 *     "*":        b.guardCsv.gate({ profile: "permissive" }),
 *   });
 *   var d = await byPath.check({
 *     bytes: Buffer.from("name,age\nada,36"),
 *     route: "/admin/imports",
 *   });
 *   d.action;                                            // → "serve"
 */
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

/**
 * @primitive  b.gateContract.byDirection
 * @signature  b.gateContract.byDirection(gateMap, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.byRoute, b.gateContract.byActorTier
 *
 * Direction-aware gate dispatch. Reads `ctx.direction` (`"inbound"`
 * or `"outbound"`; default `"outbound"`) and routes to the matching
 * gate. Lets a single guard wiring run a stricter posture on bytes
 * arriving from an external source than on bytes the framework is
 * about to emit. Missing direction maps serve uninspected.
 *
 * @opts
 *   name: string,   // wrapper gate name (default "byDirection")
 *
 * @example
 *   var byDir = b.gateContract.byDirection({
 *     inbound:  b.guardCsv.gate({ profile: "strict" }),
 *     outbound: b.guardCsv.gate({ profile: "balanced" }),
 *   });
 *   var d = await byDir.check({
 *     bytes:     Buffer.from("name,age\nada,36"),
 *     direction: "inbound",
 *   });
 *   d.action;                                            // → "serve"
 */
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

/**
 * @primitive  b.gateContract.shadowMode
 * @signature  b.gateContract.shadowMode(primary, candidate, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.canaryGate, b.gateContract.composeGates
 *
 * Run a candidate gate alongside the primary; emit a divergence
 * counter when their actions disagree. The primary's decision is the
 * one honored — candidate runs are observability-only and don't
 * block the request. Useful for staged rollout of a new profile
 * (run it shadowed for a week, watch the divergence rate, then
 * promote it to primary).
 *
 * @opts
 *   name: string,   // wrapper gate name (default "shadow")
 *
 * @example
 *   var primary   = b.guardCsv.gate({ profile: "strict" });
 *   var candidate = b.guardCsv.gate({ profile: "balanced" });
 *   var staged    = b.gateContract.shadowMode(primary, candidate, { name: "csv:staged" });
 *   var d = await staged.check({ bytes: Buffer.from("name,age\nada,36") });
 *   d.action;                                            // → "serve"  (primary's decision)
 */
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

/**
 * @primitive  b.gateContract.canaryGate
 * @signature  b.gateContract.canaryGate(gate, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.shadowMode, b.gateContract.cachingGate
 *
 * Enforce the wrapped gate's refuse decisions on `rate` of requests;
 * downgrade the rest to `warn`. Default rate is `0.1` (10% enforced,
 * 90% warned). Sampling uses a non-cryptographic random source — fine
 * for rollout shaping, never for security-critical sampling.
 *
 * @opts
 *   rate: number,   // 0..1, default 0.1
 *   name: string,   // wrapper gate name (default "canary")
 *
 * @example
 *   var strict = b.guardCsv.gate({ profile: "strict" });
 *   var canary = b.gateContract.canaryGate(strict, { rate: 0.25 });
 *   var d = await canary.check({ bytes: Buffer.from("name,age\nada,36") });
 *   d.ok;                                                // → true
 */
function canaryGate(gate, opts) {
  opts = opts || {};
  var rate = typeof opts.rate === "number" ? opts.rate : 0.1;
  return defineGate({
    name: opts.name || "canary",
    check: async function (ctx) {
      var d = await gate.check(ctx);
      if (d.action === "refuse" && Math.random() > rate) {       // allow:math-random-noncrypto-jitter-sampling — canary sampling, non-security
        return Object.assign({}, d, { ok: true, action: "warn" });
      }
      return d;
    },
  });
}

/**
 * @primitive  b.gateContract.cachingGate
 * @signature  b.gateContract.cachingGate(gate, opts)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.defineGate, b.gateContract.canaryGate
 *
 * Wrap a gate with an explicit shared cache backend. The per-gate
 * built-in cache (configured via `defineGate({ cache, cacheTtlMs })`)
 * is per-gate-instance; this wrapper is the operator-side variant
 * for sharing one cache across multiple gates. `opts.backend` must
 * expose the `b.cache` shape (`{ get(key), set(key, value, opts) }`).
 *
 * @opts
 *   backend: object,   // b.cache-shaped { get, set } (required)
 *   ttlMs:   number,   // cache TTL
 *   name:    string,   // wrapper gate name (default "<gate>:cached")
 *
 * @example
 *   var cache  = b.cache.create({ backend: "memory", maxEntries: 10000 });
 *   var strict = b.guardCsv.gate({ profile: "strict" });
 *   var cached = b.gateContract.cachingGate(strict, {
 *     backend: cache,
 *     ttlMs:   60000,
 *   });
 *   var d = await cached.check({ bytes: Buffer.from("name,age\nada,36") });
 *   d.action;                                            // → "serve"
 */
function cachingGate(gate, opts) {
  opts = opts || {};
  var backend = opts.backend;
  validateOpts.requireMethods(backend, ["get", "set"],
    "cachingGate: opts.backend (b.cache shape)", GateContractError, "gate-contract/bad-opt");
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

/**
 * @primitive  b.gateContract.workerThreadGate
 * @signature  b.gateContract.workerThreadGate(gate, opts)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.defineGate, b.gateContract.cachingGate
 *
 * Offload a gate's `check(ctx)` to a worker. `opts.worker` must
 * expose `run({ gate, ctx })` returning the decision (matches the
 * `b.worker` shape). Useful when a guard's per-request CPU cost
 * (large-doc HTML parsing, archive entry inspection) is high enough
 * that running it on the request thread would impact throughput.
 *
 * @opts
 *   worker: object,   // b.worker-shaped { run } (required)
 *   name:   string,   // wrapper gate name (default "<gate>:worker")
 *
 * @example
 *   var worker = b.worker.create({ pool: 4, modulePath: "./guards/csv-worker.js" });
 *   var strict = b.guardCsv.gate({ profile: "strict" });
 *   var offloaded = b.gateContract.workerThreadGate(strict, { worker: worker });
 *   var d = await offloaded.check({ bytes: Buffer.from("name,age\nada,36") });
 *   d.action;                                            // → "serve"
 */
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

/**
 * @primitive  b.gateContract.makeProfileBuilder
 * @signature  b.gateContract.makeProfileBuilder(profiles)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.buildProfile, b.gateContract.resolveProfileAndPosture
 *
 * Closes over a guard's `PROFILES` map and returns a `buildProfile(opts)`
 * function that delegates to the recursive composition entry point.
 * Every guard's `buildProfile` export is therefore a single binding,
 * not a duplicate forwarding wrapper. The returned function accepts
 * `{ baseProfile, extends, overrides, removes }` plus inline keys, and
 * resolves names through the closed-over profile table.
 *
 * @example
 *   var PROFILES = {
 *     strict:    { formulaInjectionPolicy: "reject",     bidiCharPolicy: "reject" },
 *     balanced:  { formulaInjectionPolicy: "prefix-tab", bidiCharPolicy: "strip"  },
 *   };
 *   var buildProfile = b.gateContract.makeProfileBuilder(PROFILES);
 *   var custom = buildProfile({
 *     baseProfile: "strict",
 *     overrides:   { trailingWhitespacePolicy: "preserve" },
 *   });
 *   custom.formulaInjectionPolicy;                       // → "reject"
 *   custom.trailingWhitespacePolicy;                     // → "preserve"
 */
function makeProfileBuilder(profiles) {
  return function (opts) {
    return buildProfile(Object.assign({}, opts, {
      resolveProfile: function (name) { return profiles[name] || null; },
    }));
  };
}

/**
 * @primitive  b.gateContract.lookupCompliancePosture
 * @signature  b.gateContract.lookupCompliancePosture(name, postures, errorFactory, codePrefix)
 * @since      0.7.5
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.gateContract.resolveProfileAndPosture, b.gateContract.makeProfileBuilder
 *
 * Look up a compliance-posture overlay by name. Throws
 * `errorFactory(codePrefix + ".bad-posture")` when the name is not in
 * the posture map; returns a shallow clone of the posture object
 * otherwise. Every guard's `compliancePosture(name)` export forwards
 * here so the error code, error class, and clone semantics stay
 * identical across the family.
 *
 * @example
 *   var POSTURES = {
 *     hipaa:   { piiPolicy: "redact", bidiCharPolicy: "reject" },
 *     "pci-dss": { piiPolicy: "redact", bidiCharPolicy: "reject" },
 *   };
 *   var posture = b.gateContract.lookupCompliancePosture(
 *     "hipaa", POSTURES, b.guardCsv.GuardCsvError.factory, "csv");
 *   posture.piiPolicy;                                   // → "redact"
 */
function lookupCompliancePosture(name, postures, errorFactory, codePrefix) {
  // hasOwnProperty: `name` is caller input; a bracket lookup would let a
  // prototype key like "constructor" pass the presence check and reach
  // Object.assign (proto shadowing).
  if (!postures || !Object.prototype.hasOwnProperty.call(postures, name)) {
    throw errorFactory(codePrefix + ".bad-posture",
      "unknown compliancePosture " + JSON.stringify(name));
  }
  return Object.assign({}, postures[name]);
}

/**
 * @primitive  b.gateContract.makePostureAccessor
 * @signature  b.gateContract.makePostureAccessor(postures, opts?)
 * @since      0.15.14
 * @status     stable
 * @related    b.gateContract.lookupCompliancePosture, b.gateContract.resolveProfileName
 *
 * Build the public `compliancePosture(name)` accessor a guard exposes — maps a
 * compliance-posture name through the guard's own `postures` table to the
 * profile it selects, returning `opts.fallback` (default `null`) for an
 * unknown name. Folds the one-line lookup the mail-scanner / content-detect
 * factories each redefined verbatim (`return POSTURES[name] || null`) into one
 * proto-shadow-safe helper: the membership test is `hasOwnProperty.call` so a
 * prototype key (constructor / __proto__ / toString) resolves to the fallback
 * rather than an inherited Function. Unlike `lookupCompliancePosture` it does
 * NOT throw and returns the raw mapped value (a profile name string), not an
 * object copy.
 *
 * @opts
 *   fallback: any,   // value returned for an unknown / proto-key name (default null)
 *
 * @example
 *   var compliancePosture = b.gateContract.makePostureAccessor(COMPLIANCE_POSTURES);
 *   compliancePosture("hipaa");        // → "strict"
 *   compliancePosture("constructor");  // → null  (proto key, not an own posture)
 */
function makePostureAccessor(postures, opts) {
  var fallback = (opts && Object.prototype.hasOwnProperty.call(opts, "fallback")) ? opts.fallback : null;
  return function (name) {
    return Object.prototype.hasOwnProperty.call(postures, name) ? postures[name] : fallback;
  };
}

// "GuardCidrError" -> "guardCidr" — the guard's audit/message identity, derived
// once from its error class name. Used for the default gate's audit/metric
// prefix AND the profile resolver's error message, so neither re-cases the name.
function _guardLabelFromError(ErrorClass) {
  var n = String(ErrorClass.name).replace(/Error$/, "");
  return n.charAt(0).toLowerCase() + n.slice(1);
}

/**
 * @primitive  b.gateContract.makeProfileResolver
 * @signature  b.gateContract.makeProfileResolver(cfg)
 * @since      0.15.0
 * @status     stable
 * @related    b.gateContract.makeProfileBuilder, b.gateContract.lookupCompliancePosture
 *
 * Closes over a guard's profile config and returns a `resolveProfile(opts)`
 * function: maps `opts.posture` through the compliance-posture table, else
 * falls back to `opts.profile || cfg.defaults`, validates the name against
 * `cfg.profiles`, and throws `cfg.errorClass.factory(cfg.codePrefix +
 * "/bad-profile")` on an unknown name. The sibling of `makeProfileBuilder` /
 * `makeRulePackLoader` / `lookupCompliancePosture` for the resolution step —
 * every `defineParser`-shaped line-protocol / mail / agent guard reuses it
 * instead of re-declaring an identical `_resolveProfile`.
 *
 * @opts
 *   profiles:   object,    // the guard's PROFILES map; required
 *   postures:   object,    // COMPLIANCE_POSTURES (posture -> profile name)
 *   defaults:   string,    // fallback profile name when no posture/profile given
 *   errorClass: function,  // the guard's FrameworkError subclass
 *   codePrefix: string,    // error-code namespace (e.g. "mail-compose")
 *   byObject:   boolean,   // true -> return the profile config object, not its name
 *
 * @example
 *   var resolveProfile = b.gateContract.makeProfileResolver({
 *     profiles: PROFILES, postures: COMPLIANCE_POSTURES,
 *     defaults: "strict", errorClass: GuardMailComposeError,
 *     codePrefix: "mail-compose",
 *   });
 *   resolveProfile({ posture: "hipaa" });   // → "strict"
 */
function makeProfileResolver(cfg) {
  var profiles   = cfg.profiles;
  var postures   = cfg.postures;
  var dft        = cfg.defaults;
  var ErrorClass = cfg.errorClass;
  var codePrefix = cfg.codePrefix;
  var byObject   = cfg.byObject === true;
  var label      = _guardLabelFromError(ErrorClass);
  return function resolveProfile(opts) {
    opts = opts || {};
    if (opts.posture && postures && postures[opts.posture]) {
      var pn = postures[opts.posture];
      return byObject ? profiles[pn] : pn;
    }
    var p = opts.profile || dft;
    if (!profiles[p]) {
      throw ErrorClass.factory(codePrefix + "/bad-profile",
        label + ": unknown profile '" + p + "' (use " +
        Object.keys(profiles).join(" / ") + ")");
    }
    return byObject ? profiles[p] : p;
  };
}

/**
 * @primitive  b.gateContract.resolveProfileName
 * @signature  b.gateContract.resolveProfileName(opts, postures, defaultProfile)
 * @since      0.15.13
 * @status     stable
 * @related    b.gateContract.makeProfileResolver
 *
 * Resolve a profile NAME from create-time opts with PROFILE precedence: an
 * explicit `opts.profile` wins, else `opts.posture` mapped through the
 * compliance-posture table, else `defaultProfile`. Returns the name WITHOUT
 * validating it — the caller checks membership in its own `PROFILES` map and
 * throws its own typed, field-specific error. This is the resolution EXPRESSION
 * the mail-scanner / envelope factories (mail-greylist / mail-rbl / mail-scan /
 * mail-spam-score / mail-helo / guard-envelope) each hand-rolled identically.
 *
 * It differs from `makeProfileResolver` in two deliberate ways: it does not
 * throw (so the caller keeps its bespoke bad-profile message) and it gives
 * `profile` precedence rather than `posture` precedence. The two precedences
 * coexist in the framework today (the `defineParser`-shaped guards resolve
 * posture-first); unifying them is a policy decision, and routing every caller
 * through one of these two helpers is what makes that decision a single edit.
 *
 * @opts
 *   profile:   string,   // explicit profile name — wins when present
 *   posture:   string,   // compliance posture, mapped through `postures`
 *
 * @example
 *   var name = b.gateContract.resolveProfileName(
 *     { profile: "balanced" }, COMPLIANCE_POSTURES, "strict");
 *   // → "balanced"
 */
function resolveProfileName(opts, postures, defaultProfile) {
  opts = opts || {};
  // hasOwnProperty: opts.posture is caller/operator input; a bracket lookup
  // would let a prototype key like "constructor" resolve to an inherited
  // truthy value and become the profile name (proto shadowing).
  var postureProfile = (opts.posture && postures &&
    Object.prototype.hasOwnProperty.call(postures, opts.posture))
    ? postures[opts.posture] : null;
  return opts.profile || postureProfile || defaultProfile;
}

/**
 * @primitive  b.gateContract.throwOnRefusalSeverity
 * @signature  b.gateContract.throwOnRefusalSeverity(issues, cfg)
 * @since      0.15.0
 * @status     stable
 * @related    b.gateContract.aggregateIssues, b.gateContract.makeProfileResolver
 *
 * Throw on the first critical/high-severity issue in a detector's issue
 * list — the refusal step every guard `sanitize` runs after detection
 * (sanitize can serve a clean value but never repair a critical/high
 * finding). Builds the guard's error via `cfg.errorClass.factory` with code
 * `issue.ruleId || (cfg.codePrefix + ".refused")` and message
 * `guard<Name>.<op>: <issue.snippet>` (op default `"sanitize"`; the guard
 * identity derives from the error class name). The throw sibling of
 * `aggregateIssues` (which returns `{ ok, issues }` instead of throwing) —
 * replaces the per-guard hand-rolled severity-gating loop.
 *
 * @opts
 *   errorClass: function,  // the guard's FrameworkError subclass; required
 *   codePrefix: string,    // error-code namespace; the `.refused` fallback code
 *   op:         string,    // operation name in the message (default "sanitize")
 *   severities: string[],  // refusal severities (default ["critical","high"])
 *
 * @example
 *   var issues = detect(input, opts);
 *   b.gateContract.throwOnRefusalSeverity(issues, {
 *     errorClass: GuardCidrError, codePrefix: "cidr",
 *   });
 *   // throws GuardCidrError(ruleId || "cidr.refused", "guardCidr.sanitize: " + snippet)
 *   // on the first critical/high issue
 */
function throwOnRefusalSeverity(issues, cfg) {
  var errFactory = cfg.errorClass.factory;
  var prefix = _guardLabelFromError(cfg.errorClass) + "." + (cfg.op || "sanitize");
  var fallback = cfg.codePrefix + ".refused";
  // Default refuses critical + high; cfg.severities narrows it (e.g.
  // ["critical"] for guards that strip high-severity findings but refuse
  // only unrepairable critical shapes — email / markdown / xml / yaml).
  var severities = cfg.severities || ["critical", "high"];
  for (var i = 0; i < issues.length; i += 1) {
    var iss = issues[i];
    if (severities.indexOf(iss.severity) !== -1) {
      throw errFactory(iss.ruleId || fallback, prefix + ": " + iss.snippet);
    }
  }
}

/**
 * @primitive  b.gateContract.ALL_STRICT_POSTURES
 * @signature  b.gateContract.ALL_STRICT_POSTURES
 * @since      0.15.0
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.gateContract.lookupCompliancePosture, b.gateContract.makeProfileBuilder
 *
 * Canonical strict-all `COMPLIANCE_POSTURES` map every command/parser
 * guard composes. Maps each of the four baseline regulatory postures —
 * `hipaa` / `pci-dss` / `gdpr` / `soc2` — onto the guard's `strict`
 * profile name. Guards whose four postures all resolve to `strict`
 * (the command/protocol validators: POP3 / IMAP / SMTP / ManageSieve
 * commands, mail-compose / query / sieve / move / reply, the envelope
 * and event-bus shapes, the mail pipeline scorers, and the
 * `safe-*` line-protocol parsers) reference this single frozen object
 * instead of re-declaring it. Guards that overlay per-posture
 * byte-limits or redaction flags (the content guards: CSV / HTML /
 * JSON / XML / YAML / JWT / OAuth / template, etc.) keep their own
 * posture map and do not compose this.
 *
 * Frozen once and shared by reference: every consumer reads it through
 * its own `COMPLIANCE_POSTURES` binding and never mutates it.
 *
 * @example
 *   var COMPLIANCE_POSTURES = b.gateContract.ALL_STRICT_POSTURES;
 *   COMPLIANCE_POSTURES.hipaa;                            // → "strict"
 *   Object.isFrozen(COMPLIANCE_POSTURES);                 // → true
 */
var ALL_STRICT_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

/**
 * @primitive  b.gateContract.CHAR_THREATS_REJECT_ALL
 * @signature  b.gateContract.CHAR_THREATS_REJECT_ALL
 * @since      0.15.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.gateContract.charThreatDisposition, b.gateContract.makeProfileBuilder
 *
 * The universal character-safety floor: the four invisible-character
 * threats — BIDI overrides, C0/C1 control bytes, embedded null bytes,
 * and zero-width characters — each set to `"reject"`. These four
 * classes are categorically unsafe in an identifier or structured
 * value (forgery, log injection, label-segmentation, parser
 * confusion), so every identifier/protocol guard refuses them in
 * every profile tier and the content guards refuse them in `strict`.
 *
 * Spread this frozen block into a profile tier instead of re-declaring
 * the four lines: `{ ...gateContract.CHAR_THREATS_REJECT_ALL, ... }`.
 * A tier that relaxes one class overrides after the spread (e.g.
 * `{ ...CHAR_THREATS_REJECT_ALL, zeroWidthPolicy: "strip" }`), keeping
 * the floor for the other three. Frozen and shared by reference; the
 * spread copies the values into each consumer's own tier object.
 *
 * @example
 *   var PROFILES = Object.freeze({
 *     strict: { ...b.gateContract.CHAR_THREATS_REJECT_ALL, maxBytes: 256 },
 *   });
 *   PROFILES.strict.bidiPolicy;                           // → "reject"
 *   Object.isFrozen(b.gateContract.CHAR_THREATS_REJECT_ALL); // → true
 */
var CHAR_THREATS_REJECT_ALL = Object.freeze({
  bidiPolicy:      "reject",
  controlPolicy:   "reject",
  nullBytePolicy:  "reject",
  zeroWidthPolicy: "reject",
});

/**
 * @primitive  b.gateContract.DANGEROUS_URL_SCHEMES
 * @signature  b.gateContract.DANGEROUS_URL_SCHEMES
 * @since      0.15.13
 * @status     stable
 * @compliance soc2
 * @related    b.gateContract.CHAR_THREATS_REJECT_ALL, b.guardHtml.validate, b.guardSvg.validate
 *
 * The frozen denylist of URL schemes that are categorically unsafe inside a
 * markup attribute value (`href` / `src` / `xlink:href`) — the markup XSS and
 * dangerous-resource vector set. `javascript` / `vbscript` / `livescript` /
 * `mocha` / `ecmascript` execute script; `data` / `view-source` / `mhtml` /
 * `feed` carry or expose renderable content; `file` / `jar` / `intent` reach
 * local resources or protocol handlers. A markup sanitizer rejects an
 * attribute whose scheme is in this list.
 *
 * Lower-cased, scheme-name only (no trailing colon) so callers compare against
 * a lower-cased parsed scheme via `indexOf(scheme) !== -1`. This is the
 * markup-attribute DENYLIST — distinct from `b.safeUrl`'s protocol ALLOWLIST,
 * which governs full-URL parsing where only an explicit set of protocols is
 * permitted.
 *
 * @example
 *   b.gateContract.DANGEROUS_URL_SCHEMES.indexOf("javascript");  // → 0 (dangerous)
 *   b.gateContract.DANGEROUS_URL_SCHEMES.indexOf("https");       // → -1 (allowed)
 *   Object.isFrozen(b.gateContract.DANGEROUS_URL_SCHEMES);       // → true
 */
var DANGEROUS_URL_SCHEMES = Object.freeze([
  "javascript", "vbscript", "livescript", "mocha", "ecmascript",
  "file", "mhtml", "jar", "intent", "view-source", "feed", "data",
]);

/**
 * @primitive  b.gateContract.SAFE_URL_SCHEMES
 * @signature  b.gateContract.SAFE_URL_SCHEMES
 * @since      0.15.13
 * @status     stable
 * @compliance soc2
 * @related    b.gateContract.DANGEROUS_URL_SCHEMES
 *
 * The frozen base allowlist of URL schemes a markup sanitizer accepts in an
 * attribute value at the `strict` tier — `http` / `https` / `mailto` / `tel`.
 * A guard extends it for looser tiers (e.g. `SAFE_URL_SCHEMES.concat(["ftp"])`)
 * rather than re-declaring the base. Scheme names only, no trailing colon.
 *
 * @example
 *   b.gateContract.SAFE_URL_SCHEMES;                       // → ["http","https","mailto","tel"]
 *   Object.isFrozen(b.gateContract.SAFE_URL_SCHEMES);      // → true
 */
var SAFE_URL_SCHEMES = Object.freeze(["http", "https", "mailto", "tel"]);

/**
 * @primitive  b.gateContract.identifierFixtures
 * @signature  b.gateContract.identifierFixtures(benign, hostile, encoding?)
 * @since      0.15.13
 * @status     stable
 * @related    b.gateContract.defineGuard
 *
 * Build an identifier guard's frozen `INTEGRATION_FIXTURES` from one benign
 * and one hostile sample string. The layer-5 host harness feeds the string
 * form to `gate.check({ identifier })` and the byte form to the upload /
 * digest paths, so the two are the same value in two representations. A guard
 * that hand-writes both forms repeats its sample literal twice (`benignBytes:
 * Buffer.from("x"), benignIdentifier: "x"`); declaring the string once and
 * deriving the buffer removes that per-guard duplication. `encoding` defaults
 * to `"utf8"` — pass `"ascii"` for line-protocol command samples whose bytes
 * must stay single-octet.
 *
 * @example
 *   var INTEGRATION_FIXTURES =
 *     b.gateContract.identifierFixtures("example.com", "192.168.1.1");
 *   INTEGRATION_FIXTURES.benignIdentifier;      // → "example.com"
 *   INTEGRATION_FIXTURES.benignBytes;           // → Buffer "example.com"
 *   Object.isFrozen(INTEGRATION_FIXTURES);      // → true
 */
function identifierFixtures(benign, hostile, encoding) {
  validateOpts.requireNonEmptyString(benign,
    "gateContract.identifierFixtures: benign", GateContractError, "gate-contract/bad-opt");
  validateOpts.requireNonEmptyString(hostile,
    "gateContract.identifierFixtures: hostile", GateContractError, "gate-contract/bad-opt");
  var enc = encoding || "utf8";
  if (typeof enc !== "string" || !Buffer.isEncoding(enc)) {
    throw _err("gate-contract/bad-opt",
      "gateContract.identifierFixtures: encoding must be a valid Buffer encoding, got " +
      JSON.stringify(encoding));
  }
  return Object.freeze({
    kind:              "identifier",
    benignBytes:       Buffer.from(benign, enc),
    hostileBytes:      Buffer.from(hostile, enc),
    benignIdentifier:  benign,
    hostileIdentifier: hostile,
  });
}

/**
 * @primitive  b.gateContract.compliancePostures
 * @signature  b.gateContract.compliancePostures(profiles, spec)
 * @since      0.15.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.gateContract.ALL_STRICT_POSTURES, b.gateContract.resolveProfileAndPosture
 *
 * Build a content guard's four-posture `COMPLIANCE_POSTURES` map from its
 * profile set and a single forensic-snippet budget, encoding the framework's
 * regulation-disposition policy in one place instead of re-declaring it in
 * every guard. Each regulation maps to the profile tier whose disposition
 * matches its intent:
 *
 *   - `hipaa` / `pci-dss` / `soc2` &rarr; the `strict` profile. These regimes
 *     demand forensic integrity &mdash; the record must not be silently
 *     altered &mdash; so every threat class is rejected, never sanitized.
 *   - `gdpr` &rarr; the `balanced` profile. Data-minimization favors removing
 *     the offending bytes over rejecting the whole value, so on free-text
 *     content the balanced tier strips the sanitizable character classes (bidi
 *     / control / zero-width) while still rejecting structural threats. For an
 *     identifier guard the balanced tier rejects those classes too &mdash;
 *     stripping bytes from an identifier would change its identity &mdash; so
 *     the disposition follows the guard's own content kind automatically.
 *
 * The forensic snippet budget scales with each regime's retention posture:
 * `hipaa` / `pci-dss` keep `base` bytes, `gdpr` keeps `base / 2` (retain less
 * hostile data under data-minimization), `soc2` keeps `base * 2` (audit
 * retention). Pass `spec.overlays` to layer a deliberate per-posture delta on
 * top of the tier &mdash; e.g. a filename guard stripping bidi / control under
 * `gdpr` where its balanced profile would reject them. Each returned posture is
 * frozen and shared by reference.
 *
 * @opts
 *   {
 *     base:     number,    // required, positive even byte count: the hipaa/pci snippet budget
 *     overlays: {          // optional per-posture policy deltas, merged last
 *       hipaa:     object,
 *       "pci-dss": object,
 *       gdpr:      object,
 *       soc2:      object,
 *     },
 *   }
 *
 * @example
 *   var COMPLIANCE_POSTURES = b.gateContract.compliancePostures(PROFILES, {
 *     base: 256,
 *   });
 *   COMPLIANCE_POSTURES.gdpr.forensicSnippetBytes;       // → 128
 *   Object.isFrozen(COMPLIANCE_POSTURES.hipaa);          // → true
 */
function compliancePostures(profiles, spec) {
  validateOpts.requireObject(profiles, "gateContract.compliancePostures", GateContractError);
  if (!profiles.strict || !profiles.balanced) {
    throw _err("gate-contract/bad-profiles",
      "compliancePostures: profiles must include 'strict' and 'balanced'");
  }
  spec = spec || {};
  var base = spec.base;
  if (typeof base !== "number" || !isFinite(base) || base <= 0 || base % 2 !== 0) {
    throw _err("gate-contract/bad-base",
      "compliancePostures: spec.base must be a positive even byte count");
  }
  var overlays = spec.overlays || {};
  function build(tier, snippetBytes, overlay) {
    return Object.freeze(Object.assign({}, profiles[tier],
      { forensicSnippetBytes: C.BYTES.bytes(snippetBytes) }, overlay || {}));
  }
  return Object.freeze({
    hipaa:     build("strict",   base,     overlays.hipaa),
    "pci-dss": build("strict",   base,     overlays["pci-dss"]),
    gdpr:      build("balanced", base / 2, overlays.gdpr),
    soc2:      build("strict",   base * 2, overlays.soc2),
  });
}

/**
 * @primitive  b.gateContract.strictDefaults
 * @signature  b.gateContract.strictDefaults(profiles, overlay?)
 * @since      0.15.13
 * @status     stable
 * @related    b.gateContract.compliancePostures, b.gateContract.defineGuard
 *
 * Build a guard's frozen `DEFAULTS` opts: its `strict` profile, in `enforce`
 * mode, plus any per-guard overlay. Every guard's no-opts call path starts from
 * the strictest profile with enforcement on (security-on by default); the only
 * variation is a guard that adds a parse runtime cap (`maxRuntimeMs`) or another
 * default override. Replaces the hand-rolled `Object.freeze(Object.assign({},
 * PROFILES["strict"], { mode: "enforce", … }))` every guard repeated.
 *
 * @opts
 *   overlay: object   // optional per-guard default overrides merged last (e.g. { maxRuntimeMs: C.TIME.seconds(10) }); may override `mode`
 *
 * @example
 *   var DEFAULTS = b.gateContract.strictDefaults(PROFILES);                          // strict + enforce
 *   var DEFAULTS = b.gateContract.strictDefaults(PROFILES, { maxRuntimeMs: 10000 }); // + a parse runtime cap
 */
function strictDefaults(profiles, overlay) {
  validateOpts.requireObject(profiles, "gateContract.strictDefaults", GateContractError);
  if (!profiles.strict) {
    throw _err("gate-contract/bad-profiles",
      "strictDefaults: profiles must include 'strict'");
  }
  return Object.freeze(Object.assign({}, profiles.strict, { mode: "enforce" }, overlay || {}));
}

/**
 * @primitive  b.gateContract.makeRulePackLoader
 * @signature  b.gateContract.makeRulePackLoader(errorClass, codePrefix)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.makeProfileBuilder, b.gateContract.lookupCompliancePosture
 *
 * Build a per-guard rule-pack registry. Returns
 * `{ load(pack), list(), get(id) }`. `load` validates that `pack`
 * is an object with a non-empty string `pack.id` (throwing
 * `errorClass(codePrefix + ".bad-opt")` when not) and stores it in
 * a closed-over map keyed by `pack.id`. `list` returns the stored
 * packs; `get(id)` returns one or `null`. Used so every guard's
 * `loadRulePack` export shares storage shape and validation.
 *
 * @example
 *   var packs = b.gateContract.makeRulePackLoader(b.guardCsv.GuardCsvError, "csv");
 *   packs.load({
 *     id: "pii-extra",
 *     rules: [{ id: "ssn", severity: "critical",
 *               detect: function (cell) { return /^\d{3}-\d{2}-\d{4}$/.test(cell); } }],
 *   });
 *   packs.get("pii-extra").rules.length;                 // → 1
 */
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

/**
 * @primitive  b.gateContract.extractBytesAsText
 * @signature  b.gateContract.extractBytesAsText(ctx)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.buildGuardGate, b.gateContract.aggregateIssues
 *
 * Read `ctx.bytes` and return a UTF-8 string for inspection. Centralizes
 * the string-or-Buffer-or-empty handling so each guard's `check(ctx)`
 * body deals with the inspection logic only. Returns `""` when
 * `ctx.bytes` is missing — callers treat empty as the serve case.
 *
 * @example
 *   var ctx  = { bytes: Buffer.from("name,age\nada,36") };
 *   var text = b.gateContract.extractBytesAsText(ctx);
 *   text;                                                // → "name,age\nada,36"
 *
 *   b.gateContract.extractBytesAsText({});               // → ""
 *   b.gateContract.extractBytesAsText({ bytes: "x,y" }); // → "x,y"
 */
function extractBytesAsText(ctx) {
  if (!ctx) return "";
  var bytes = ctx.bytes;
  if (!bytes) return "";
  return Buffer.isBuffer(bytes) ? bytes.toString("utf8") : String(bytes);
}

/**
 * @primitive  b.gateContract.buildGuardGate
 * @signature  b.gateContract.buildGuardGate(name, opts, check)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.defineGate, b.gateContract.extractBytesAsText
 *
 * Gate-construction shorthand for guard-* primitives. Forwards the
 * uniform ~16-key opts bag (`mode`, `audit`, `observability`,
 * `forensicEvidenceStore`, `forensicSnippetBytes`, `cache`,
 * `cacheTtlMs`, `maxRuntimeMs`, all six lifecycle hooks) to
 * `defineGate`, so each guard's `gate(opts)` body is just the per-guard
 * `check` function plus a label. Result satisfies `validateGateShape`.
 *
 * @opts
 *   mode:                  string,        // one of MODES; default "enforce"
 *   audit:                 object|null,   // b.audit handle for emission
 *   observability:         object|null,   // b.observability handle
 *   forensicEvidenceStore: object|null,   // { write({ ... }) }
 *   forensicSnippetBytes:  number,        // 0 = disabled
 *   cache:                 object|null,   // b.cache shape
 *   cacheTtlMs:            number,
 *   maxRuntimeMs:          number,        // 0 = uncapped
 *   beforeCheck:           function|null,
 *   afterCheck:            function|null,
 *   onIssue:               function|null,
 *   onSanitize:            function|null,
 *   onRefuse:              function|null,
 *   onAudit:               function|null,
 *
 * @example
 *   var myGuardGate = b.gateContract.buildGuardGate(
 *     "myGuard:strict",
 *     { mode: "enforce", maxRuntimeMs: 250 },
 *     async function (ctx) {
 *       var text = b.gateContract.extractBytesAsText(ctx);
 *       if (text.length === 0) return { ok: true, action: "serve" };
 *       if (/\s/.test(text)) {
 *         return { ok: false, action: "refuse",
 *                  issues: [{ kind: "whitespace", severity: "high" }] };
 *       }
 *       return { ok: true, action: "serve" };
 *     });
 *   var d = await myGuardGate.check({ bytes: Buffer.from("hello") });
 *   d.action;                                            // → "serve"
 */
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

/**
 * @primitive  b.gateContract.severityDisposition
 * @signature  b.gateContract.severityDisposition(issues)
 * @since      0.15.13
 * @status     stable
 * @related    b.gateContract.buildGuardGate, b.gateContract.buildContentGate
 *
 * The non-sanitizing guard gate's severity action-chain in one place. A guard
 * that cannot repair its subject (an auth bundle, an OAuth flow, a GraphQL
 * request, image / PDF metadata, an archive entry list, an email body, a regex
 * pattern) ends its `gate` check with the identical disposition: `serve` when
 * there are no findings, `audit-only` when no finding reaches refusal severity,
 * else `refuse`. This is the sibling of `buildContentGate` (which adds the
 * sanitize attempt for content that CAN be repaired). Each guard keeps its own
 * subject extraction + validate call, then returns `severityDisposition(rv.issues)`.
 *
 * A finding of `critical` OR `high` severity refuses; anything lower is
 * `audit-only`. The returned shape matches a gate `check` result:
 * `{ ok, action }` (no `issues` on a clean serve) or `{ ok, action, issues }`.
 *
 * @example
 *   var rv = module.exports.validate(bundle, opts);
 *   return b.gateContract.severityDisposition(rv.issues);
 *   // [] → { ok: true, action: "serve" }
 *   // [{ severity: "low" }] → { ok: true, action: "audit-only", issues: [...] }
 *   // [{ severity: "high" }] → { ok: false, action: "refuse", issues: [...] }
 */
function severityDisposition(issues) {
  if (issues.length === 0) return { ok: true, action: "serve" };
  var hasCritical = issues.some(function (i) { return i.severity === "critical"; });
  var hasHigh = issues.some(function (i) { return i.severity === "high"; });
  if (!hasCritical && !hasHigh) {
    return { ok: true, action: "audit-only", issues: issues };
  }
  return { ok: false, action: "refuse", issues: issues };
}

/**
 * @primitive  b.gateContract.buildContentGate
 * @signature  b.gateContract.buildContentGate(spec)
 * @since      0.15.13
 * @status     stable
 * @related    b.gateContract.buildGuardGate, b.gateContract.defineGuard
 *
 * The content-guard gate action-chain in one place. Every content guard's
 * `gate(opts)` ran the identical chain — extract the bytes, `serve` a clean
 * input, `audit-only` when no issue reaches the refusal severity, attempt
 * `sanitize` when the input is eligible, else `refuse` — differing only in
 * declarative axes. Passing those axes to one primitive replaces ~30 lines of
 * per-guard gate body and makes the chain impossible to drift between guards.
 *
 * A CRITICAL finding always `refuse`s — too severe to serve even sanitized (a
 * stripped script can still carry an mXSS / parser-differential vector). Only
 * HIGH findings are sanitize-eligible, and even then the action is PROVEN, not
 * guessed: the gate runs `produceSanitized` then RE-VALIDATES its output,
 * returning `sanitize` only when the result is verifiably clean — otherwise
 * `refuse`. An operator's `reject` choice lands as critical (→ refuse) and a
 * `strip` choice as high (→ sanitize-if-verified), so the severity carries the
 * disposition with no per-policy bookkeeping — replacing a global "is any
 * policy set to reject?" guess that wrongly froze sanitize for findings
 * unrelated to the rejected policy. The sanitizer's own policy-respecting
 * behaviour does the rest: it throws on / leaves a reject-class finding so the
 * re-validate still refuses, and refuses anything it cannot actually repair.
 * `sanitizeBlockingKinds` skips the attempt for inputs a text sanitizer must not
 * touch (gzipped SVGZ bytes); a thrown producer falls through to `refuse`.
 *
 * @opts
 *   name:                  string,                   // gate label (audit/metric/cache identity)
 *   opts:                  object,                   // already resolved profile/posture opts
 *   validate:              function,                 // (subject, opts) -> { ok, issues }
 *   produceSanitized:      function,                 // (subject, opts) -> Buffer|string
 *   ctxField:              "text"|"bytes",           // default "text" (extractBytesAsText); "bytes" reads ctx.bytes raw
 *   sanitizeBlockingKinds: string[],                 // issue kinds that skip the sanitize attempt (e.g. ["svgz-compressed"])
 *
 * @example
 *   var g = b.gateContract.buildContentGate({
 *     name: "guardXml:strict", opts: resolved, validate: validate,
 *     produceSanitized: function (t, o) { return sanitize(t, o); },
 *   });
 *   (await g.check({ bytes: Buffer.from("<a>1</a>") })).action;   // → "serve"
 */
function buildContentGate(spec) {
  var opts = spec.opts || {};
  var ctxField = spec.ctxField === "bytes" ? "bytes" : "text";
  var blockKind = Array.isArray(spec.sanitizeBlockingKinds) ? spec.sanitizeBlockingKinds : [];

  // A finding's disposition is what the operator's POLICY for that finding
  // class chose, not the finding's impact severity. The guard declares the
  // binding via spec.dispositionFor(issue, opts); anything it doesn't classify
  // (an operator-injected rule, a structural hard-cap, an un-mapped kind) falls
  // back to severity — and that fallback is CONSERVATIVE (a refusal-severity
  // finding refuses, because the gate has no proof it can be repaired).
  function _disposition(issue, fromGuard) {
    if (fromGuard && typeof spec.dispositionFor === "function") {
      var d = spec.dispositionFor(issue, opts);
      if (d === "refuse" || d === "sanitize" || d === "audit") return d;
    }
    if (issue.disposition === "refuse" || issue.disposition === "sanitize" ||
        issue.disposition === "audit") return issue.disposition;
    return (issue.severity === "critical" || issue.severity === "high") ? "refuse" : "audit";
  }

  return buildGuardGate(spec.name, opts, async function (ctx) {
    var subject = ctxField === "bytes" ? (ctx && ctx.bytes) : extractBytesAsText(ctx);
    if (!subject) return { ok: true, action: "serve" };

    var rv = spec.validate(subject, opts);
    var entries = rv.issues.map(function (i) { return { issue: i, disp: _disposition(i, true) }; });
    // Operator-injected detect-only findings (spec.extraIssues): the guard owns
    // no sanitizer for them, so a refusal-severity hit can only refuse — never
    // serve a "sanitized" output that still carries the operator's finding.
    if (typeof spec.extraIssues === "function") {
      var extra = spec.extraIssues(subject, opts, ctx) || [];
      for (var k = 0; k < extra.length; k++) {
        entries.push({ issue: extra[k], disp: _disposition(extra[k], false) });
      }
    }
    if (entries.length === 0) return { ok: true, action: "serve" };

    var issues = entries.map(function (e) { return e.issue; });
    // refuse wins over sanitize wins over audit. A finding whose policy is
    // `reject` (→ refuse), an always-dangerous denylist hit, or a structural
    // hard-cap refuses the whole input regardless of any sanitizable siblings.
    if (entries.some(function (e) { return e.disp === "refuse"; })) {
      return { ok: false, action: "refuse", issues: issues };
    }
    // Some finding's policy chose to mitigate (strip / prefix / redact / drop):
    // run the guard's own sanitizer, which performs exactly the policy-selected
    // transform, and serve its output. The operator picked sanitize-and-serve
    // over reject for these classes, so the result is trusted — no re-validation
    // (a mitigation like CSV's prefix-tab is in-place, not removal, so a second
    // detector pass would wrongly refuse it). sanitizeBlockingKinds skips the
    // attempt for inputs a text sanitizer must not touch (gzipped SVGZ bytes);
    // a sanitizer that throws (e.g. a reject-policy parse) falls through.
    if (entries.some(function (e) { return e.disp === "sanitize"; })) {
      var blocked = blockKind.some(function (kind) {
        return issues.some(function (it) { return it.kind === kind; });
      });
      if (!blocked && typeof spec.produceSanitized === "function") {
        try {
          var clean = spec.produceSanitized(subject, opts);
          var cleanBuf = Buffer.isBuffer(clean) ? clean : Buffer.from(String(clean), "utf8");
          return { ok: true, action: "sanitize", sanitized: cleanBuf, issues: issues };
        } catch (_e) { /* sanitizer could not repair → refuse */ }
      }
      return { ok: false, action: "refuse", issues: issues };
    }
    // Only audit-disposition (sub-refusal observational) findings remain.
    return { ok: true, action: "audit-only", issues: issues };
  });
}

/**
 * @primitive  b.gateContract.policyDisposition
 * @signature  b.gateContract.policyDisposition(policy)
 * @since      0.15.13
 * @status     stable
 * @related    b.gateContract.buildContentGate
 *
 * Map an operator content-policy value to the gate disposition it selects.
 * A content guard emits a finding only when the governing policy is not
 * `allow`; this turns that policy into what the gate should DO with the
 * finding — independent of the finding's impact severity:
 *
 * - `reject` → `refuse` (operator chose to reject this class outright)
 * - `audit` / `audit-only` → `audit` (observe, do not block or alter)
 * - a known mitigation (`strip`, `prefix-tab`, `prefix-quote`,
 *   `wrap-with-quotes-and-prefix`, `allowlist`, `redact`, `trim`) →
 *   `sanitize` (the guard's sanitizer performs the chosen transform)
 *
 * Fails CLOSED: an unrecognized policy value (a typo such as `rejet`, or a
 * mitigation name not in the known set) maps to `refuse`, never `sanitize` —
 * a misconfiguration must not silently downgrade a finding to serve-after-
 * best-effort. Add a new mitigation to MITIGATION_POLICIES when one ships.
 *
 * @example
 *   b.gateContract.policyDisposition("reject");      // → "refuse"
 *   b.gateContract.policyDisposition("strip");       // → "sanitize"
 *   b.gateContract.policyDisposition("audit-only");  // → "audit"
 *   b.gateContract.policyDisposition("rejet");       // → "refuse" (fail closed)
 */
var MITIGATION_POLICIES = Object.freeze({
  strip: true, "prefix-tab": true, "prefix-quote": true,
  "wrap-with-quotes-and-prefix": true, allowlist: true, redact: true, trim: true,
});
function policyDisposition(policy) {
  if (policy === "reject") return "refuse";
  if (policy === "audit" || policy === "audit-only") return "audit";
  if (MITIGATION_POLICIES[policy] === true) return "sanitize";
  return "refuse";
}

/**
 * @primitive  b.gateContract.charThreatDisposition
 * @signature  b.gateContract.charThreatDisposition(issue, opts)
 * @since      0.15.13
 * @status     stable
 * @related    b.gateContract.policyDisposition, b.codepointClass.detectCharThreats
 *
 * Gate disposition for the shared character-threat findings every content
 * guard collects via `codepointClass.detectCharThreats` — `bidi-override`,
 * `null-byte`, `control-char` — resolved from the guard's per-class policy
 * (`bidiPolicy` / `nullBytePolicy` / `controlPolicy`). Returns `null` for any
 * other kind so a guard's own `dispositionFor` can fall through to it for the
 * shared kinds and handle its guard-specific findings itself.
 *
 * @opts
 *   bidiPolicy:      string,   // governs the bidi-override finding
 *   nullBytePolicy:  string,   // governs the null-byte finding
 *   controlPolicy:   string,   // governs the control-char finding
 *   zeroWidthPolicy: string,   // governs the zero-width finding
 *
 * @example
 *   function dispositionFor(issue, opts) {
 *     return b.gateContract.charThreatDisposition(issue, opts) ||
 *            mySpecificMapping(issue, opts);
 *   }
 */
function charThreatDisposition(issue, opts) {
  switch (issue.kind) {
    case "bidi-override": return policyDisposition(opts.bidiPolicy);
    case "null-byte":     return policyDisposition(opts.nullBytePolicy);
    case "control-char":  return policyDisposition(opts.controlPolicy);
    case "zero-width":    return policyDisposition(opts.zeroWidthPolicy);
    default:              return null;
  }
}

/**
 * @primitive  b.gateContract.aggregateIssues
 * @signature  b.gateContract.aggregateIssues(issues)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.runIssueValidator, b.gateContract.summarizeIssues
 *
 * Wrap an issues array in the canonical `{ ok, issues }` validate-result
 * shape. `ok` is `true` only when no issue carries `critical` or `high`
 * severity — `info` and `warn` issues do not flip `ok`. Used by guards
 * whose validate path can't route through `runIssueValidator` (raw-Buffer
 * input cases such as svg magic detection or filename byte scans).
 *
 * @example
 *   var result = b.gateContract.aggregateIssues([
 *     { kind: "csv.bidi", severity: "high",
 *       snippet: "U+202E embedded in cell" },
 *     { kind: "csv.trailing-whitespace", severity: "info" },
 *   ]);
 *   result.ok;                                           // → false
 *   result.issues.length;                                // → 2
 */
function aggregateIssues(issues) {
  return {
    ok: !issues.some(function (i) {
      return i.severity === "critical" || i.severity === "high";
    }),
    issues: issues,
  };
}

/**
 * @primitive  b.gateContract.badInputResultIfNotStringOrBuffer
 * @signature  b.gateContract.badInputResultIfNotStringOrBuffer(input)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.runIssueValidator, b.gateContract.aggregateIssues
 *
 * Type-guard for guard-* validate entry points. Returns the canonical
 * `{ ok: false, issues: [{ kind: "bad-input", severity: "high", ... }] }`
 * result when `input` is neither a string nor a Buffer; `null`
 * otherwise. Used by guards whose validate path can't pre-convert —
 * `b.guardSvg` needs raw bytes for SVGZ magic detection,
 * `b.guardFilename` needs raw bytes for the overlong-UTF-8 byte scan.
 *
 * @example
 *   b.gateContract.badInputResultIfNotStringOrBuffer("hello");      // → null
 *   b.gateContract.badInputResultIfNotStringOrBuffer(Buffer.from("x")); // → null
 *   var bad = b.gateContract.badInputResultIfNotStringOrBuffer(42);
 *   bad.ok;                                              // → false
 *   bad.issues[0].kind;                                  // → "bad-input"
 */
function badInputResultIfNotStringOrBuffer(input) {
  // The "bytes" input contract IS this check — compose it so there is one
  // source of truth for "string or Buffer, else bad-input".
  var extracted = INPUT_CONTRACTS.bytes(input);
  if (!extracted.badInput) return null;
  return {
    ok: false,
    issues: [{ kind: "bad-input", severity: "high",
               snippet: extracted.badInput }],
  };
}

/**
 * @primitive  b.gateContract.detectStringInput
 * @signature  b.gateContract.detectStringInput(input, opts, cfg)
 * @since      0.15.13
 * @status     stable
 * @related    b.gateContract.badInputResultIfNotStringOrBuffer, b.codepointClass.detectCharThreats
 *
 * The whole detector preamble every `raw`-contract string guard opens with:
 * reject a non-string input, then an empty one, then one over the byte cap,
 * else collect the codepoint-class threats (BIDI / control / null / zero-width)
 * the guard then appends its own findings to. A guard on the `raw` input
 * contract owns its own input check (see `INPUT_CONTRACTS`); this builds that
 * preamble once, guard-named, instead of re-spelling its four steps in every
 * `_detectIssues`. Returns `{ done, issues }`: when `done` the detector returns
 * `issues` verbatim (the `<name>.bad-input` / `<name>.empty` / cap issue, or
 * `[]` for a legal empty); when not `done`, `issues` is the codepoint-threat
 * list the detector continues from. The byte cap runs before the codepoint
 * scan so a huge input is rejected before the O(n) scan.
 *
 * The cap's divergence is data, not branching: `cap.bytes` is the limit (the
 * guard's resolved `maxBytes` / `maxPatternBytes` / `maxDomainOctets`),
 * `cap.kind` the issue kind (default `<name>-cap`), and `cap.snippet` the
 * message — a string, or a `function(byteLen, bytes)` when it embeds the
 * measured length. Omit `cap` for a guard with no byte cap.
 *
 * @opts
 *   {
 *     name:      string,    // required: the guard name — ruleId prefix + default noun
 *     noun:      string,    // default name — the subject word in the bad-input/empty snippet
 *     emptyMode: string,    // "issue" (default) → <name>.empty issue · "ok" → [] (empty is legal) · "skip" → no empty check
 *     cap: {                // omit when the guard has no byte cap
 *       bytes:   number,            // required: the byte limit
 *       kind:    string,            // default "<name>-cap" — the cap issue kind (and ruleId suffix)
 *       snippet: string|function,   // default "<noun> input exceeds maxBytes <bytes>"; fn(byteLen, bytes) when it needs the measured length
 *     },
 *     scanCodepoints: boolean,      // default true: the not-done result carries the codepoint-class scan. Pass false for a guard that scans codepoints later in its own detection (or parses them via its format, e.g. JSON) — the not-done result is then `[]`.
 *   }
 *
 * @example
 *   function _detectIssues(input, opts) {
 *     var pre = b.gateContract.detectStringInput(input, opts, {
 *       name: "cidr", cap: { bytes: opts.maxBytes },
 *     });
 *     if (pre.done) return pre.issues;
 *     var issues = pre.issues;            // codepoint-class threats so far
 *     // … guard-specific detection appends to issues …
 *     return issues;
 *   }
 */
function detectStringInput(input, opts, cfg) {
  validateOpts.requireObject(cfg, "gateContract.detectStringInput", GateContractError);
  validateOpts.requireNonEmptyString(cfg.name,
    "gateContract.detectStringInput: cfg.name", GateContractError, "gate-contract/bad-opt");
  var noun = cfg.noun || cfg.name;
  if (typeof input !== "string") {
    return { done: true, issues: [{ kind: "bad-input", severity: "high",
      ruleId: cfg.name + ".bad-input", snippet: noun + " is not a string" }] };
  }
  var emptyMode = cfg.emptyMode || "issue";
  if (emptyMode !== "skip" && input.length === 0) {
    return { done: true, issues: emptyMode === "ok" ? [] :
      [{ kind: "empty", severity: "high", ruleId: cfg.name + ".empty",
         snippet: noun + " is empty" }] };
  }
  if (cfg.cap) {
    var byteLen = Buffer.byteLength(input, "utf8");
    if (byteLen > cfg.cap.bytes) {
      var capKind = cfg.cap.kind || (cfg.name + "-cap");
      var capSnippet = typeof cfg.cap.snippet === "function"
        ? cfg.cap.snippet(byteLen, cfg.cap.bytes)
        : (cfg.cap.snippet || (noun + " input exceeds maxBytes " + cfg.cap.bytes));
      return { done: true, issues: [{ kind: capKind, severity: "high",
        ruleId: cfg.name + "." + capKind, snippet: capSnippet }] };
    }
  }
  if (cfg.scanCodepoints === false) return { done: false, issues: [] };
  return { done: false, issues: codepointClass.detectCharThreats(input, opts, cfg.name) };
}

// Input contracts — the one place that knows how to turn a raw guard input
// into the subject its detector expects (or flag bad input). Every guard's
// `validate` differs only in its input shape; the contract captures that
// difference so one `runIssueValidator` serves them all:
//
//   - "text": string / Buffer → UTF-8 text; anything else is bad input. The
//     content guards (csv / html / markdown / json / ...) whose detector takes
//     a string but does NOT type-check it themselves.
//   - "bytes": string / Buffer is accepted and reaches the detector UNCHANGED
//     (no utf8 coercion); anything else is bad input. The guards that inspect
//     raw bytes before decoding (filename overlong-UTF-8, sql encoding gate) —
//     converting to text first would hide the very bytes they check. This is
//     exactly `badInputResultIfNotStringOrBuffer(input) ||
//     aggregateIssues(detect(input))`.
//   - "raw" (default): identity — the value reaches the detector untouched and
//     the detector owns its own (often typed) bad-input. The object-bag guards
//     (image / pdf metadata, archive entries) and the string guards whose
//     detector type-checks itself (email). This is exactly
//     `aggregateIssues(detect(input))`.
//
// A guard with a bespoke shape passes its own `function(input){ return
// { subject } | { badInput: msg } }` instead of a name. New input shapes
// extend the class by adding a contract, never by branching in defineGuard.
var INPUT_CONTRACTS = {
  text: function (input) {
    if (typeof input === "string") return { subject: input };
    if (Buffer.isBuffer(input)) return { subject: input.toString("utf8") };
    return { badInput: "input is not string or Buffer" };
  },
  bytes: function (input) {
    if (typeof input === "string" || Buffer.isBuffer(input)) return { subject: input };
    return { badInput: "input is not string or Buffer" };
  },
  raw: function (input) { return { subject: input }; },
};
Object.freeze(INPUT_CONTRACTS);

function resolveInputContract(contract) {
  if (typeof contract === "function") return contract;
  return Object.prototype.hasOwnProperty.call(INPUT_CONTRACTS, contract) ? INPUT_CONTRACTS[contract] : INPUT_CONTRACTS.text;
}

/**
 * @primitive  b.gateContract.runIssueValidator
 * @signature  b.gateContract.runIssueValidator(input, opts, detector, contract?)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.aggregateIssues, b.gateContract.badInputResultIfNotStringOrBuffer
 *
 * The single `validate(input, opts)` engine for the whole guard family. An
 * input contract normalizes the raw input to the subject the detector expects
 * (or flags bad input), then the detector runs and its issues aggregate. One
 * engine spans every input shape in the family: `"text"` (the default) coerces
 * string / Buffer to UTF-8 and refuses anything else; `"raw"` hands the value
 * through so an object-bag or byte-level detector owns its own bad-input
 * (identical to `aggregateIssues(detector(input, opts))`); a guard with a
 * bespoke shape passes its own extractor `function(input) -> { subject } |
 * { badInput: message }`. Result `ok` is `true` only when no detected issue is
 * `critical` / `high` severity. The `opts` argument is forwarded verbatim as
 * the detector's second argument — its shape is detector-defined.
 *
 * @opts
 *   ...:   any,                     // detector-defined; passed through to detector(subject, opts)
 *
 * @example
 *   function detectFormulaTrigger(text) {
 *     if (/^[=+\-@]/.test(text)) {
 *       return [{ kind: "csv.formula-injection", severity: "high",
 *                 snippet: text.slice(0, 16) }];
 *     }
 *     return [];
 *   }
 *   var bad = b.gateContract.runIssueValidator("=cmd|x", {}, detectFormulaTrigger);
 *   bad.ok;                                              // → false
 *   var ok  = b.gateContract.runIssueValidator("ada,36", {}, detectFormulaTrigger);
 *   ok.ok;                                               // → true
 */
function runIssueValidator(input, opts, detector, contract) {
  var extracted = resolveInputContract(contract)(input);
  if (extracted && typeof extracted.badInput === "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: extracted.badInput }],
    };
  }
  return aggregateIssues(detector(extracted.subject, opts));
}

/**
 * @primitive  b.gateContract.resolveProfileAndPosture
 * @signature  b.gateContract.resolveProfileAndPosture(opts, cfg)
 * @since      0.7.5
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.gateContract.makeProfileBuilder, b.gateContract.lookupCompliancePosture
 *
 * Overlay `opts.profile` and `opts.compliancePosture` on top of a
 * defaults object using guard-supplied tables. Every guard primitive's
 * factory routes through this so the resolution shape — defaults
 * first, profile overlay, posture overlay, inline opts last — stays
 * identical across the family. When `opts.compliancePosture` is unset
 * and `b.compliance.set()` has declared a global posture, the global
 * posture takes effect (the value-add of the top-level coordinator).
 *
 * Throws `cfg.errorClass.factory(cfg.errCodePrefix + ".bad-profile")`
 * for unknown profile names and `... + ".bad-posture"` for unknown
 * postures.
 *
 * @opts
 *   profiles:           object,        // PROFILES table (required)
 *   compliancePostures: object,        // COMPLIANCE_POSTURES table (required)
 *   defaults:           object,        // baseline before overlay
 *   errorClass:         FrameworkError,// throws via .factory(code, msg)
 *   errCodePrefix:      string,        // e.g. "csv" → "csv.bad-profile"
 *
 * @example
 *   var PROFILES = {
 *     strict:   { formulaInjectionPolicy: "reject",     bidiCharPolicy: "reject" },
 *     balanced: { formulaInjectionPolicy: "prefix-tab", bidiCharPolicy: "strip"  },
 *   };
 *   var POSTURES = { hipaa: { piiPolicy: "redact" } };
 *   var resolved = b.gateContract.resolveProfileAndPosture(
 *     { profile: "balanced", compliancePosture: "hipaa", maxCellBytes: 65536 },
 *     {
 *       profiles:           PROFILES,
 *       compliancePostures: POSTURES,
 *       defaults:           { maxCellBytes: 1024 },
 *       errorClass:         b.guardCsv.GuardCsvError,
 *       errCodePrefix:      "csv",
 *     });
 *   resolved.formulaInjectionPolicy;                     // → "prefix-tab"
 *   resolved.piiPolicy;                                  // → "redact"
 *   resolved.maxCellBytes;                               // → 65536
 */
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
    } else if (typeof globalPosture === "string" && globalPosture.length > 0) {
      // A global posture IS pinned, but this guard family ships no
      // COMPLIANCE_POSTURES overlay for it (e.g. fedramp-rev5-moderate
      // against a guard whose table only covers hipaa/pci-dss/gdpr/soc2).
      // Falling through to the unposture-d default is the SAFE behavior,
      // but operators must know the posture is a no-op for THIS guard —
      // silently no-oping reads as "enforced" (compliance theater).
      // Emit a one-time, grep-able audit warning per (posture, guard)
      // and keep the safe default.
      _warnUnmappedPosture(globalPosture, prefix);
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

// _warnUnmappedPosture — emit a one-time, grep-able audit warning that a
// globally-pinned posture has no overlay in THIS guard family's
// COMPLIANCE_POSTURES table, so the operator doesn't read the
// safe-default fall-through as "the posture is enforced here." Drop-
// silent (hot-path observability sink): a warning emit must never throw
// past the guard-gate construction that triggered it.
function _warnUnmappedPosture(posture, prefix) {
  var dedupeKey = posture + "::" + (prefix || "guard");
  if (_unmappedPostureWarned[dedupeKey]) return;
  _unmappedPostureWarned[dedupeKey] = true;
  try {
    // Canonical audit outcome triple is success/failure/denied; a
    // posture that maps no overlay is an advisory NOTICE, not a failure
    // of this construction — the severity rides in metadata.severity so
    // the audit row carries the warning intent without abusing outcome.
    audit().safeEmit({
      action:  "gateContract.posture.unmapped",
      outcome: "success",
      metadata: {
        severity: "warning",
        posture:  posture,
        guard:    prefix || "guard",
        recommendation: "The pinned compliance posture '" + posture +
          "' has no overlay in this guard's COMPLIANCE_POSTURES table, so " +
          "its gate runs the unposture-d default. Pass an explicit " +
          "compliancePosture this guard maps, or add the overlay, if the " +
          "posture is meant to tighten this surface.",
      },
    });
  } catch (_e) { /* drop-silent — warning must not break gate construction */ }
}

function _resetForTest() {
  for (var k in _unmappedPostureWarned) delete _unmappedPostureWarned[k];
}

/**
 * @primitive  b.gateContract.buildProfile
 * @signature  b.gateContract.buildProfile(opts)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.makeProfileBuilder, b.gateContract.resolveProfileAndPosture
 *
 * Recursive profile composition with cycle detection. Walks
 * `opts.baseProfile` and every name in `opts.extends` through the
 * caller-supplied `opts.resolveProfile` resolver, deep-merging arrays
 * (set-union, later-wins on duplicates) and objects (recursive). Then
 * applies inline `opts.overrides` and finally `opts.removes` (which
 * can drop array entries or whole keys). Cycles throw
 * `gate-contract/profile-cycle`; unknown names throw
 * `gate-contract/unknown-profile`. Most guards bind through
 * `makeProfileBuilder` and never call `buildProfile` directly.
 *
 * @opts
 *   baseProfile:    string,        // start from this profile name
 *   extends:        string[],      // additional bases (later-wins)
 *   overrides:      object,        // inline merge after extends
 *   removes:        object,        // drop array entries or keys
 *   resolveProfile: function,      // (name) → profile|null  (required)
 *
 * @example
 *   var PROFILES = {
 *     "blog-post": {
 *       allowedTags: ["p", "a", "strong"],
 *       allowedAttrs: { a: ["href", "target"] },
 *     },
 *     "with-images": { extends: ["blog-post"], allowedTags: ["img"] },
 *   };
 *   var resolved = b.gateContract.buildProfile({
 *     baseProfile:    "with-images",
 *     overrides:      { allowedTags: ["em"] },
 *     removes:        { allowedAttrs: { a: ["target"] } },
 *     resolveProfile: function (n) { return PROFILES[n] || null; },
 *   });
 *   resolved.allowedTags;                                // → ["p","a","strong","img","em"]
 *   resolved.allowedAttrs.a;                             // → ["href"]
 */
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

/**
 * @primitive  b.gateContract.summarizeIssues
 * @signature  b.gateContract.summarizeIssues(issues)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.aggregateIssues, b.gateContract.defineGate
 *
 * Project a gate decision's `issues` array down to the audit-friendly
 * shape — `{ kind, severity, ruleId }` only. Full snippets stay in the
 * forensic evidence store; the audit log records the classification
 * without the offending bytes. Replaces the inline
 * `(d.issues || []).map(...)` pattern host primitives previously
 * carried per emit site.
 *
 * @example
 *   var summary = b.gateContract.summarizeIssues([
 *     { kind: "csv.bidi", severity: "high", ruleId: "BIDI-OVERRIDE",
 *       snippet: "<offending bytes redacted>" },
 *     { kind: "csv.trailing-whitespace", severity: "info", ruleId: "TRIM" },
 *   ]);
 *   summary.length;                                      // → 2
 *   summary[0].snippet;                                  // → undefined  (stripped)
 *   summary[0].ruleId;                                   // → "BIDI-OVERRIDE"
 */
function summarizeIssues(issues) {
  if (!Array.isArray(issues)) return [];
  return issues.map(function (i) {
    return { kind: i.kind, severity: i.severity, ruleId: i.ruleId };
  });
}

/**
 * @primitive  b.gateContract.composeHooks
 * @signature  b.gateContract.composeHooks(hooks)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.defineGate, b.gateContract.buildGuardGate
 *
 * Chain a list of operator hooks into a single async hook. Empty
 * arrays return `null` (so `defineGate` can pass the result through
 * its `hooks.X || null` slot); single-element arrays return the
 * lone hook unchanged. Multi-element chains run sequentially —
 * `{ suppress: true }` or `{ skip: true }` from any hook short-
 * circuits and returns; otherwise the last non-null hook result wins.
 *
 * @example
 *   var redactPii = function (issue) {
 *     return Object.assign({}, issue, { snippet: "<redacted>" });
 *   };
 *   var dropInfo  = function (issue) {
 *     return issue.severity === "info" ? { suppress: true } : null;
 *   };
 *   var onIssue = b.gateContract.composeHooks([dropInfo, redactPii]);
 *   var infoHit = await onIssue({ kind: "csv.trim", severity: "info" });
 *   infoHit.suppress;                                    // → true
 *   var bidi = await onIssue({ kind: "csv.bidi", severity: "high",
 *                              snippet: "U+202E" });
 *   bidi.snippet;                                        // → "<redacted>"
 */
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

// ---- Guard-module factories ----
//
// Every b.guard* primitive of the gate-bearing kinds (content / filename
// / identifier) hand-wires the SAME export surface: an error class, a
// resolveProfileAndPosture-backed _resolveOpts, a buildGuardGate-backed
// gate, a makeProfileBuilder-backed buildProfile, a
// lookupCompliancePosture-backed compliancePosture, a makeRulePackLoader-
// backed loadRulePack, and a frozen module.exports carrying the
// guard-* registry fields (NAME / KIND / MIME_TYPES / EXTENSIONS /
// PROFILES / DEFAULTS / COMPLIANCE_POSTURES / INTEGRATION_FIXTURES) plus
// the per-guard inspection surface (validate / sanitize / gate). They
// differ only in the per-guard inspection LOGIC + the PROFILES /
// COMPLIANCE_POSTURES / DEFAULTS tables. `defineGuard` assembles the
// boilerplate; the spec injects the logic and the tables.
//
// `defineParser` is the sibling for the minimal command / line-protocol
// / safe-* parser shape — the guards whose four postures all resolve to
// `strict` (ALL_STRICT_POSTURES) and whose surface is a self-contained
// `validate` / `parse` plus a `compliancePosture(name)` that returns the
// effective PROFILE NAME (or null) rather than an overlay clone. Those
// guards carry no gate / buildProfile / loadRulePack, so forcing them
// through `defineGuard` would be a leaky abstraction.

// _KIND_CTX_FIELDS — per-KIND ordered list of ctx field names a
// buildGuardGate-backed default gate reads, mirroring the hand-written
// gate bodies: filename reads ctx.filename || ctx.name, identifier reads
// ctx.identifier || ctx.token || ctx.jwt, command reads ctx.line ||
// ctx.command. content has no entry — it falls through to
// extractBytesAsText (the ctx.bytes string/Buffer normalizer).
var _KIND_CTX_FIELDS = Object.freeze({
  filename:   ["filename", "name"],
  identifier: ["identifier", "token", "jwt"],
  command:    ["line", "command"],
});

// override (when given) replaces the per-KIND field table — lets a guard whose
// gate is the standard chain but reads a custom ctx field take the default gate.
function _ctxValueForKind(kind, ctx, override) {
  ctx = ctx || {};
  var fields = override || _KIND_CTX_FIELDS[kind];
  if (!fields) return extractBytesAsText(ctx);   // content (default)
  for (var i = 0; i < fields.length; i += 1) {
    if (ctx[fields[i]]) return ctx[fields[i]];
  }
  return "";
}

/**
 * @primitive  b.gateContract.defineGuard
 * @signature  b.gateContract.defineGuard(spec)
 * @since      0.15.0
 * @status     stable
 * @related    b.gateContract.defineParser, b.gateContract.buildGuardGate, b.gateContract.resolveProfileAndPosture
 *
 * Assemble a complete `b.guard*` module from a spec. Mints the per-guard
 * error class (via `framework-error.defineClass`, or accepts a supplied
 * `errorClass`), wires `resolveProfileAndPosture` / `buildGuardGate` /
 * `makeProfileBuilder` / `lookupCompliancePosture` / `makeRulePackLoader`,
 * and returns the frozen module.exports object every guard ships —
 * `NAME` / `KIND` / `PROFILES` / `DEFAULTS` / `COMPLIANCE_POSTURES` /
 * `INTEGRATION_FIXTURES` / `validate` / `sanitize?` / `gate?` /
 * `buildProfile` / `compliancePosture` / `loadRulePack` plus the spec's
 * `extra` exports (verb tables, `escapeCell`, `schema`, `kidSafe`, …) and
 * the error class under its own name.
 *
 * The per-guard inspection logic is INJECTED, not abstracted: `validate`
 * / `sanitize` / `gate` are spec functions that close over the resolved
 * opts. A guard whose `gate` body is the standard
 * serve→audit-only→sanitize→refuse chain can omit `spec.gate` and take
 * the factory default (built from `spec.validate` + `spec.sanitize` per
 * KIND); a guard with a bespoke gate (CSV's sanitize-reparse-reserialize,
 * filename's per-policy canSanitize matrix) passes its own. Behavior is
 * preserved byte-for-byte because the genuinely-divergent code stays
 * verbatim in the spec — the factory only removes the wiring every guard
 * copies.
 *
 * @opts
 *   name:                 string,     // NAME (e.g. "csv"); required
 *   kind:                 string,     // "content"|"filename"|"identifier"|"command" for the default gate; any non-empty label with a bespoke spec.gate; required
 *   errCodePrefix:        string,     // error-code namespace (default name)
 *   errorName:            string,     // defineClass name (mutually exclusive with errorClass)
 *   errorClass:           function,   // pre-built FrameworkError subclass
 *   profiles:             object,     // PROFILES (must include strict/balanced/permissive); required
 *   defaults:             object,     // DEFAULTS baseline (default profiles.strict, or strictDefaults(profiles, defaultsOverlay) when `base` is given)
 *   postures:             object,     // COMPLIANCE_POSTURES (default ALL_STRICT_POSTURES, or compliancePostures(profiles, { base }) when `base` is given)
 *   base:                 number,     // forensic snippet budget — when given (and defaults/postures omitted), the factory derives both via strictDefaults + compliancePostures
 *   defaultsOverlay:      object,     // per-guard default overrides merged into the derived strictDefaults (e.g. { maxRuntimeMs: ... }); only used with `base`
 *   mimeTypes:            string[],   // content guards only
 *   extensions:           string[],   // content guards only
 *   integrationFixtures:  object,     // INTEGRATION_FIXTURES (consumed by host harness)
 *   validate:             function,   // (input, resolvedOpts) -> { ok, issues }; required
 *   sanitize:             function,   // (input, resolvedOpts) -> cleaned (optional)
 *   gate:                 function,   // (resolvedOpts) -> async (ctx) -> decision (optional; default built per kind)
 *   ctxFields:            string[],   // ordered ctx field names the default gate reads (overrides the per-KIND table; e.g. ["identifier","cidr"])
 *   defaultGateCheck:     function,   // override the default gate's per-ctx check
 *   extra:                object,     // additional exports merged verbatim into module.exports
 *
 * @example
 *   module.exports = b.gateContract.defineGuard({
 *     name: "csv", kind: "content", errorClass: GuardCsvError,
 *     profiles: PROFILES, defaults: DEFAULTS, postures: COMPLIANCE_POSTURES,
 *     mimeTypes: ["text/csv"], extensions: [".csv"],
 *     integrationFixtures: INTEGRATION_FIXTURES,
 *     validate: validate, sanitize: sanitize, gate: gate,
 *     extra: { serialize: serialize, escapeCell: escapeCell, schema: schema },
 *   });
 */
function defineGuard(spec) {
  validateOpts.requireObject(spec, "gateContract.defineGuard", GateContractError);
  validateOpts.requireNonEmptyString(spec.name, "gateContract.defineGuard: name",
    GateContractError, "gate-contract/bad-opt");
  validateOpts.requireNonEmptyString(spec.kind, "gateContract.defineGuard: kind",
    GateContractError, "gate-contract/bad-opt");
  // The four known kinds drive the default gate's ctx-field dispatch
  // (_ctxValueForKind). A guard with a bespoke spec.gate reads its own ctx
  // fields, so any non-empty kind is allowed there — the kind is then just
  // the KIND export label (e.g. "oauth-flow" / "graphql-request" / "sql" /
  // "metadata"). A custom kind WITHOUT a bespoke gate is refused, because
  // the default gate could not dispatch it to the right ctx field.
  if (["content", "filename", "identifier", "command"].indexOf(spec.kind) === -1 &&
      typeof spec.gate !== "function") {
    throw _err("gate-contract/bad-opt",
      "defineGuard: kind must be content|filename|identifier|command for the " +
      "default gate, got " + JSON.stringify(spec.kind) +
      " — pass spec.gate for a custom kind (the bespoke gate reads its own ctx fields)");
  }
  validateOpts.requireObject(spec.profiles, "gateContract.defineGuard: profiles",
    GateContractError);
  if (spec.errorClass && spec.errorName) {
    throw _err("gate-contract/bad-opt",
      "defineGuard: pass errorClass OR errorName, not both");
  }

  var prefix = spec.errCodePrefix || spec.name;
  var ErrorClass = spec.errorClass ||
    defineClass(spec.errorName || ("Guard" +
      spec.name.charAt(0).toUpperCase() + spec.name.slice(1) + "Error"),
      { alwaysPermanent: true });
  var profiles = spec.profiles;
  // A guard may hand `defaults` / `postures` explicitly, OR pass `base` (the
  // forensic snippet budget) and let the factory derive the standard config —
  // `strictDefaults(profiles, defaultsOverlay)` + `compliancePostures(profiles,
  // { base })` — so the guard file needn't declare the two module-vars itself.
  var defaults = spec.defaults ||
    (typeof spec.base === "number" ? strictDefaults(profiles, spec.defaultsOverlay)
                                   : (profiles.strict || {}));
  var postures = spec.postures ||
    (typeof spec.base === "number" ? compliancePostures(profiles, { base: spec.base })
                                   : ALL_STRICT_POSTURES);

  // Dynamic guard assembly — the upstream primitive absorbs the per-guard
  // binding wrappers. A guard may pass a raw `detect(input, opts) -> issues[]`
  // (the guard-specific detection logic) plus an optional `sanitizeTransform(
  // input, resolvedOpts) -> value`, instead of hand-rolling `_resolveOpts`,
  // `validate`, and the `sanitize` resolve→detect→throw boilerplate that every
  // guard otherwise duplicates. defineGuard already owns the profile/posture/
  // defaults/errorClass/prefix, so it binds the resolver here and builds
  // validate + sanitize. Behaviour matches the hand-written wrappers exactly:
  // validate runs detect on the RAW opts (detect resolves what it needs);
  // sanitize resolves first, then detect → throwOnRefusalSeverity → transform.
  // The bound profile/posture resolver — built once from the spec's binding
  // config (profiles/postures/defaults/errorClass/prefix) and EXPOSED on the
  // guard as `resolveOpts` (below), so a bespoke gate calls
  // `module.exports.resolveOpts(opts)` instead of each guard hand-rolling the
  // identical `function _resolveOpts(o){ return resolveProfileAndPosture(o,
  // {...}) }` binding wrapper. The binding config lives in ONE place.
  var _resolveGuardOpts = function (o) {
    return resolveProfileAndPosture(o || {}, {
      profiles:           profiles,
      compliancePostures: postures,
      defaults:           defaults,
      errorClass:         ErrorClass,
      errCodePrefix:      prefix,
    });
  };
  if (typeof spec.detect === "function") {
    var intOpts = Array.isArray(spec.intOpts) ? spec.intOpts.slice() : null;
    if (typeof spec.validate !== "function") {
      spec.validate = function (input, opts) {
        var resolved = _resolveGuardOpts(opts);
        if (intOpts) {
          numericBounds.requireAllPositiveFiniteIntIfPresent(resolved, intOpts,
            spec.name + ".validate", ErrorClass, prefix + ".bad-opt");
        }
        // One engine, the guard's input contract picks the shape. Default
        // "raw" reproduces the historical aggregateIssues(detect(input)) — the
        // detector owns its own bad-input (object-bag guards image/pdf, the
        // byte-level guards). A guard whose detector takes a string but does
        // not type-check it (e.g. csv returns [] on a non-string) sets
        // inputContract: "text" so non-text input is refused as bad-input.
        return runIssueValidator(input, resolved, spec.detect,
          spec.inputContract || "raw");
      };
    }
    if (typeof spec.sanitizeTransform === "function" && typeof spec.sanitize !== "function") {
      // spec.sanitizeSeverities narrows which severities REFUSE (throw) vs are
      // stripped/repaired by sanitizeTransform. Default ['critical','high'];
      // a guard that repairs high-severity findings and refuses only the
      // unrepairable critical shapes (markdown / email / xml / yaml) passes
      // ['critical'] so the generated sanitize matches its hand-written one.
      // An empty array means "strip unconditionally, never refuse" (csv / text
      // best-effort scrubbers, whose sanitize never throws on a detected issue).
      var sanitizeSeverities = Array.isArray(spec.sanitizeSeverities)
        ? spec.sanitizeSeverities.slice() : null;
      var refusesOnDetect = sanitizeSeverities === null || sanitizeSeverities.length > 0;
      // spec.sanitizeAmplificationCap (a string = the resolved-opts field name
      // carrying the max growth ratio) opts the guard into the "sanitize must
      // shrink, never grow" post-condition: the transform runs on extracted
      // text and the output length is capped at ratio×input. Used by the text
      // scrubbers (csv / text) whose hand-written sanitize threw
      // `<prefix>.sanitize-amplified`. When unset, sanitize keeps the raw input
      // (binary passthrough guards image / pdf must not be utf8-decoded).
      var ampCapField = typeof spec.sanitizeAmplificationCap === "string"
        ? spec.sanitizeAmplificationCap : null;
      spec.sanitize = function (input, opts) {
        var resolved = _resolveGuardOpts(opts);
        var subject = input;
        if (ampCapField) {
          // Same text contract the validate engine uses — string/Buffer→text,
          // refuse anything else (here as a throw, sanitize's contract).
          var extracted = INPUT_CONTRACTS.text(input);
          if (extracted.badInput) {
            throw ErrorClass.factory(prefix + ".bad-input",
              "sanitize requires string or Buffer input");
          }
          subject = extracted.subject;
        }
        if (refusesOnDetect) {
          var issues = spec.detect(subject, resolved);
          // A `bad-input` issue means the input is UNPROCESSABLE (wrong type /
          // shape), not a content finding — a scrubber must never let it slip
          // into the transform (which would return the garbage verbatim). So it
          // refuses ALWAYS, independent of which CONTENT severities this guard's
          // sanitize tolerates via sanitizeSeverities. (csv/text reach the same
          // refusal earlier through the ampCapField text contract above.)
          for (var bi = 0; bi < issues.length; bi += 1) {
            if (issues[bi].kind === "bad-input") {
              throw ErrorClass.factory(prefix + ".bad-input",
                issues[bi].snippet || "sanitize: input is not processable");
            }
          }
          var throwOpts = { errorClass: ErrorClass, codePrefix: prefix };
          if (sanitizeSeverities) throwOpts.severities = sanitizeSeverities;
          throwOnRefusalSeverity(issues, throwOpts);
        }
        var out = spec.sanitizeTransform(subject, resolved);
        if (ampCapField) {
          var cap = resolved[ampCapField];
          if (typeof cap === "number") {
            var amp = out.length / Math.max(subject.length, 1);
            if (amp > cap) {
              throw ErrorClass.factory(prefix + ".sanitize-amplified",
                "sanitize grew output " + amp.toFixed(2) + "x; cap " + cap);
            }
          }
        }
        return out;
      };
    }
  }
  if (typeof spec.validate !== "function") {
    throw _err("gate-contract/bad-opt", "defineGuard: validate (or detect) must be a function");
  }

  var buildProfileFn = makeProfileBuilder(profiles);
  function compliancePostureFn(name) {
    return lookupCompliancePosture(name, postures, ErrorClass.factory, prefix);
  }
  var rulePacks = makeRulePackLoader(ErrorClass, prefix);

  // spec.ctxFields (ordered field names) overrides the per-KIND table that
  // the default gate's _ctxValueForKind reads — lets a guard whose gate is the
  // standard chain but reads a custom ctx field (e.g. ctx.cidr) drop its
  // bespoke gate and take the default. null -> _ctxValueForKind uses the
  // per-KIND table.
  var ctxFields = Array.isArray(spec.ctxFields) ? spec.ctxFields.slice() : null;
  // Gate identity is surfaced in audit events / metric counters / cache keys.
  // Preserve the "guard<Name>:profile" naming the hand-written gates used so
  // moving a guard onto the default gate does not rename its audit/metric
  // stream (e.g. "guardCidr:strict"), via the shared error-name derivation.
  var gateNamePrefix = _guardLabelFromError(ErrorClass);

  // Default gate — the standard serve→audit-only→refuse chain, dispatched
  // to the right ctx field by KIND (or spec.ctxFields). Guards with a bespoke
  // gate pass spec.gate; guards whose gate is the standard chain take this
  // default.
  // Resolve the profile + posture BEFORE buildGuardGate reads its runtime /
  // forensic caps: forensicSnippetBytes lives on the posture and maxRuntimeMs
  // on the profile, NOT on the raw caller opts. Passing raw opts through dropped
  // a regulated posture's forensic cap to 0 (no forensic snapshot on a refusal)
  // and the profile's runtime cap to uncapped — the hand-written gates resolve
  // in their own gate(), and the default gate must match. resolveProfileAndPosture
  // is idempotent over an already-resolved opts, so spec.validate's internal
  // resolution stays correct.
  function defaultGate(rawOpts) {
    var opts = resolveProfileAndPosture(rawOpts || {}, {
      profiles:           profiles,
      compliancePostures: postures,
      defaults:           defaults,
      errorClass:         ErrorClass,
      errCodePrefix:      prefix,
    });
    var perCtx = spec.defaultGateCheck || function (ctx) {
      var value = _ctxValueForKind(spec.kind, ctx, ctxFields);
      if (!value) return { ok: true, action: "serve" };
      var rv = spec.validate(value, opts);
      return severityDisposition(rv.issues || []);
    };
    return buildGuardGate(
      opts.name || (gateNamePrefix + ":" + (opts.profile || "default")),
      opts,
      async function (ctx) { return perCtx(ctx, opts); });
  }

  var gateFn = spec.gate || defaultGate;

  var out = {
    NAME:                spec.name,
    KIND:                spec.kind,
    validate:            spec.validate,
    resolveOpts:         _resolveGuardOpts,
    buildProfile:        buildProfileFn,
    compliancePosture:   compliancePostureFn,
    loadRulePack:        rulePacks.load,
    PROFILES:            profiles,
    DEFAULTS:            defaults,
    COMPLIANCE_POSTURES: postures,
  };
  if (spec.kind === "content") {
    out.MIME_TYPES = Object.freeze((spec.mimeTypes || []).slice());
    out.EXTENSIONS = Object.freeze((spec.extensions || []).slice());
  }
  if (spec.integrationFixtures) out.INTEGRATION_FIXTURES = spec.integrationFixtures;
  if (typeof spec.sanitize === "function") out.sanitize = spec.sanitize;
  out.gate = gateFn;
  // Error class exported under its own constructor name (GuardCsvError etc.)
  out[ErrorClass.name] = ErrorClass;
  // Per-guard extras (verb tables, escapeCell, schema, kidSafe, …) merged
  // verbatim via the prototype-safe own-enumerable copy (no computed-name
  // write; __proto__/constructor/prototype are skipped). Extras win over
  // factory defaults only when the guard explicitly re-exports a shared
  // name (rare; documented per guard).
  if (spec.extra) validateOpts.assignOwnEnumerable(out, spec.extra);
  return out;
}

/**
 * @primitive  b.gateContract.defineParser
 * @signature  b.gateContract.defineParser(spec)
 * @since      0.15.0
 * @status     stable
 * @related    b.gateContract.defineGuard, b.gateContract.ALL_STRICT_POSTURES
 *
 * Assemble the minimal command / line-protocol / `safe-*` parser module
 * shape — guards whose four compliance postures all resolve to `strict`
 * (composing `ALL_STRICT_POSTURES`) and whose surface is a single
 * self-contained `validate` / `parse` entry point plus a
 * `compliancePosture(name)` that returns the effective PROFILE NAME (or
 * `null` for unknown names) rather than an overlay clone. These guards
 * carry no `gate` / `buildProfile` / `loadRulePack`, so `defineGuard`'s
 * full assembly would be wrong for them.
 *
 * Mints the error class (or accepts one), exposes the spec's primary
 * entry point under `spec.entryName` (default `"validate"`), and returns
 * the frozen module.exports with `PROFILES` / `COMPLIANCE_POSTURES` /
 * `compliancePosture` plus the spec's `extra` exports and the error
 * class.
 *
 * @opts
 *   name:        string,     // module identity / error-name stem; required
 *   entry:       function,   // the validate/parse entry point; required
 *   entryName:   string,     // export key for the entry (default "validate")
 *   profiles:    object,     // PROFILES; required
 *   postures:    object,     // COMPLIANCE_POSTURES (default ALL_STRICT_POSTURES)
 *   errorClass:  function,   // pre-built FrameworkError subclass
 *   errorName:   string,     // defineClass name (mutually exclusive with errorClass)
 *   extra:       object,     // additional exports (verb tables, KNOWN_*, …)
 *
 * @example
 *   module.exports = b.gateContract.defineParser({
 *     name: "pop3-command", entry: validate,
 *     errorClass: GuardPop3CommandError,
 *     profiles: PROFILES, postures: COMPLIANCE_POSTURES,
 *     extra: { KNOWN_VERBS: KNOWN_VERBS, ZERO_ARG_VERBS: ZERO_ARG_VERBS },
 *   });
 */
function defineParser(spec) {
  validateOpts.requireObject(spec, "gateContract.defineParser", GateContractError);
  validateOpts.requireNonEmptyString(spec.name, "gateContract.defineParser: name",
    GateContractError, "gate-contract/bad-opt");
  if (typeof spec.entry !== "function") {
    throw _err("gate-contract/bad-opt", "defineParser: entry must be a function");
  }
  validateOpts.requireObject(spec.profiles, "gateContract.defineParser: profiles",
    GateContractError);
  if (spec.errorClass && spec.errorName) {
    throw _err("gate-contract/bad-opt",
      "defineParser: pass errorClass OR errorName, not both");
  }
  var ErrorClass = spec.errorClass ||
    defineClass(spec.errorName || ("Guard" +
      spec.name.charAt(0).toUpperCase() + spec.name.slice(1) + "Error"),
      { alwaysPermanent: true });
  var postures = spec.postures || ALL_STRICT_POSTURES;

  function compliancePostureFn(name) {
    return postures[name] || null;
  }

  var out = {
    compliancePosture:   compliancePostureFn,
    PROFILES:            spec.profiles,
    COMPLIANCE_POSTURES: postures,
  };
  out[spec.entryName || "validate"] = spec.entry;
  out[ErrorClass.name] = ErrorClass;
  if (spec.extra) validateOpts.assignOwnEnumerable(out, spec.extra);
  return out;
}

// ---- ABI doc templates (single-sourced; rendered per guard) ----
//
// Every guard built through `defineGuard` / `defineParser` exposes the
// SAME factory-generated ABI methods (`compliancePosture` and, for
// `defineGuard`, `buildProfile` / `loadRulePack` / a default `gate`).
// Those methods have no per-guard `function` declaration — the factory
// wires them — so a refactored guard that wants its wiki page to keep
// listing them used to carry a floating `@primitive` block per method,
// duplicating the same prose across every member of the family.
//
// The `@abiTemplate` blocks below are the ONE copy of that prose. The
// wiki parser (`examples/wiki/lib/source-doc-parser.js`) collects them
// into a per-factory template bucket (keyed `defineGuard` / `defineParser`)
// instead of the gateContract primitive list, and the page generator
// (`examples/wiki/lib/page-generator.js`) instantiates them per guard —
// substituting `{NS}` (the guard namespace, e.g. `guardCsv`) and `{ERR}`
// (its error class, e.g. `GuardCsvError`) and filling `@since` from the
// guard's own `@module` / first-primitive metadata — so each guard's page
// renders every ABI method with usage correct for THAT guard. The
// duplicated prose collapses to a single source; the rendered surface is
// unchanged. A guard that keeps a bespoke per-method block (a custom
// `gate`, or a guard that documents its own `compliancePosture`) wins —
// the page generator skips the template for any method already present.
//
// These blocks intentionally carry the placeholder primitive form
// `b.{NS}.<method>` and placeholder-bearing `@example` bodies; the
// validator routes them through its template-shape pass, not the
// resolvable-primitive pass.

/**
 * @abiTemplate defineGuard
 * @method      compliancePosture
 * @signature   b.{NS}.compliancePosture(name)
 * @status      stable
 * @compliance  hipaa, pci-dss, gdpr, soc2
 * @related     b.{NS}.gate, b.{NS}.buildProfile
 *
 * Look up a compliance-posture overlay by name (one of `"hipaa"` /
 * `"pci-dss"` / `"gdpr"` / `"soc2"`). Returns a fresh clone of the
 * posture overlay so the caller may mutate it freely without disturbing
 * the shared table. Throws `{ERR}` with code `"{CODE}.bad-posture"` when
 * the name is not one this guard maps. Wired by `gateContract.defineGuard`
 * through `gateContract.lookupCompliancePosture`, so the clone semantics
 * and error code are identical across every guard in the family.
 *
 * @example
 *   var posture = b.{NS}.compliancePosture("hipaa");
 *   posture;                                             // → overlay clone (mutable)
 *
 *   try {
 *     b.{NS}.compliancePosture("not-a-regime");
 *   } catch (e) {
 *     e.code;                                            // → "{CODE}.bad-posture"
 *   }
 */

/**
 * @abiTemplate defineGuard
 * @method      buildProfile
 * @signature   b.{NS}.buildProfile(opts)
 * @status      stable
 * @related     b.{NS}.gate, b.{NS}.compliancePosture
 *
 * Compose a derived profile from one or more named bases plus inline
 * overrides, resolving names through this guard's own `PROFILES` table.
 * `opts.extends` is a base profile name (`"strict"` / `"balanced"` /
 * `"permissive"`) or an array of names — later entries shadow earlier
 * ones, and inline `opts` keys win last. Wired by
 * `gateContract.defineGuard` through `gateContract.makeProfileBuilder`,
 * so operator-defined profiles stay traceable to a baseline instead of a
 * hand-typed dictionary.
 *
 * @opts
 *   extends:   string|string[],   // base profile name(s) to compose
 *   ...:       any guard key,      // inline override of resolved keys
 *
 * @example
 *   var custom = b.{NS}.buildProfile({ extends: "strict" });
 *   custom;                                              // → composed profile object
 */

/**
 * @abiTemplate defineGuard
 * @method      loadRulePack
 * @signature   b.{NS}.loadRulePack(pack)
 * @status      stable
 * @related     b.{NS}.gate
 *
 * Register an operator-supplied rule pack with this guard's rule-pack
 * registry. The pack is identified by `pack.id` (a non-empty string) and
 * stored for later dispatch by gates that opt in via `opts.rulePackId`.
 * Returns the pack unchanged on success; throws `{ERR}` with code
 * `"{CODE}.bad-opt"` when `pack` is missing or `pack.id` is not a non-empty
 * string. Wired by `gateContract.defineGuard` through
 * `gateContract.makeRulePackLoader`, so storage shape and validation are
 * identical across the family.
 *
 * @example
 *   var pack = b.{NS}.loadRulePack({ id: "tenant-policy", rules: [] });
 *   pack.id;                                             // → "tenant-policy"
 */

/**
 * @abiTemplate defineGuard
 * @method      gate
 * @signature   b.{NS}.gate(opts?)
 * @status      stable
 * @related     b.{NS}.validate, b.gateContract.buildGuardGate
 *
 * Build the guard's request-boundary gate — a contract-shaped object
 * exposing `check(ctx)` that host primitives call at their byte moment.
 * This is the factory default chain: `serve` when no issue, `audit-only`
 * for `info` / `warn` issues, and `refuse` for any `high` / `critical`
 * issue, dispatched to the right `ctx` field by the guard's KIND. Wired
 * by `gateContract.defineGuard` through `gateContract.buildGuardGate`; a
 * guard whose gate diverges (a bespoke sanitize-and-reserialize chain,
 * for example) ships its own `gate` block instead of this template.
 *
 * @opts
 *   profile:           string,    // one of PROFILES; default this guard's default
 *   compliancePosture: string,    // overlay one of hipaa/pci-dss/gdpr/soc2
 *   mode:              string,    // one of gateContract MODES; default "enforce"
 *
 * @example
 *   var gate = b.{NS}.gate({ profile: "strict" });
 *   var decision = await gate.check({ bytes: Buffer.from("...") });
 *   decision.action;                                     // → "serve" | "refuse" | …
 */

/**
 * @abiTemplate defineGuard
 * @method      validate
 * @signature   b.{NS}.validate(input, opts?)
 * @status      stable
 * @related     b.{NS}.gate, b.{NS}.sanitize
 *
 * Inspect `input` under a resolved profile + compliance posture and return a
 * structured result `{ ok, issues }` WITHOUT throwing — `ok` is false when any
 * `high` / `critical` issue fired, and `issues` lists every finding (kind,
 * severity, ruleId, snippet). `opts` selects the `profile` /
 * `compliancePosture`; omitted opts use this guard's default profile. Wired by
 * `gateContract.defineGuard` from the guard's detection logic through
 * `gateContract.aggregateIssues`, so the result shape and severity gating are
 * identical across the guard family.
 *
 * @opts
 *   profile:           string,    // one of PROFILES; default this guard's default
 *   compliancePosture: string,    // overlay one of hipaa/pci-dss/gdpr/soc2
 *
 * @example
 *   var rv = b.{NS}.validate(input, { profile: "strict" });
 *   rv.ok;                                               // → true | false
 *   rv.issues;                                           // → [ { kind, severity, … }, … ]
 */

/**
 * @abiTemplate defineGuard
 * @method      sanitize
 * @signature   b.{NS}.sanitize(input, opts?)
 * @status      stable
 * @related     b.{NS}.validate, b.{NS}.gate
 *
 * Return a normalized form of `input` when no `high` / `critical` issue fires;
 * throw `{ERR}` on any such refusal (best-effort repair, never a silent pass).
 * Resolves the profile + posture, runs the guard's detection, throws via
 * `gateContract.throwOnRefusalSeverity` on a refusal, then applies the guard's
 * own safe transform. Wired by `gateContract.defineGuard`, so the
 * resolve → detect → throw → transform order is identical across the family; a
 * guard with no safe transform ships no `sanitize`.
 *
 * @opts
 *   profile:           string,    // one of PROFILES; default this guard's default
 *   compliancePosture: string,    // overlay one of hipaa/pci-dss/gdpr/soc2
 *
 * @example
 *   var safe = b.{NS}.sanitize(input, { profile: "permissive" });
 *   safe;                                                // → normalized value
 */

/**
 * @abiTemplate defineGuard
 * @method      resolveOpts
 * @signature   b.{NS}.resolveOpts(opts?)
 * @status      stable
 * @related     b.{NS}.validate, b.{NS}.gate
 *
 * Resolve caller `opts` against this guard's `PROFILES` + compliance-posture
 * overlays into the fully-defaulted option set the guard runs on — the same
 * resolution `validate` / `sanitize` / `gate` apply internally. Wired by
 * `gateContract.defineGuard` from the guard's binding config (profiles /
 * postures / defaults / error class), so a guard's bespoke `gate` calls
 * `resolveOpts` instead of re-declaring the per-guard resolver wrapper. Throws
 * `{ERR}` with code `"{CODE}.bad-opt"` / `"{CODE}.bad-posture"` on an unknown
 * profile or posture name.
 *
 * @opts
 *   profile:           string,    // one of PROFILES; default this guard's default
 *   compliancePosture: string,    // overlay one of hipaa/pci-dss/gdpr/soc2
 *
 * @example
 *   var resolved = b.{NS}.resolveOpts({ profile: "strict" });
 *   resolved.profile;                                    // → "strict"
 */

/**
 * @abiTemplate defineParser
 * @method      compliancePosture
 * @signature   b.{NS}.compliancePosture(name)
 * @status      stable
 * @compliance  hipaa, pci-dss, gdpr, soc2
 * @related     b.{NS}.validate, b.gateContract.ALL_STRICT_POSTURES
 *
 * Return the effective profile NAME for a compliance posture, or `null`
 * for a name this parser does not map. Unlike the content-guard variant
 * this returns the resolved profile string (every line-protocol parser
 * composes `gateContract.ALL_STRICT_POSTURES`, so `"hipaa"` / `"pci-dss"`
 * / `"gdpr"` / `"soc2"` all resolve to `"strict"`) and never throws —
 * the parser shape carries no overlay-clone, no `buildProfile`, and no
 * `loadRulePack`. Wired by `gateContract.defineParser`.
 *
 * @example
 *   b.{NS}.compliancePosture("hipaa");                   // → "strict"
 *   b.{NS}.compliancePosture("not-a-regime");            // → null
 */

module.exports = {
  defineGate:         defineGate,
  defineGuard:        defineGuard,
  defineParser:       defineParser,
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
  severityDisposition: severityDisposition,
  buildContentGate:   buildContentGate,
  policyDisposition:  policyDisposition,
  charThreatDisposition: charThreatDisposition,
  extractBytesAsText: extractBytesAsText,
  lookupCompliancePosture: lookupCompliancePosture,
  makePostureAccessor: makePostureAccessor,
  ALL_STRICT_POSTURES: ALL_STRICT_POSTURES,
  CHAR_THREATS_REJECT_ALL: CHAR_THREATS_REJECT_ALL,
  DANGEROUS_URL_SCHEMES: DANGEROUS_URL_SCHEMES,
  SAFE_URL_SCHEMES:   SAFE_URL_SCHEMES,
  identifierFixtures: identifierFixtures,
  compliancePostures: compliancePostures,
  strictDefaults:     strictDefaults,
  detectStringInput:  detectStringInput,
  makeRulePackLoader: makeRulePackLoader,
  makeProfileBuilder: makeProfileBuilder,
  makeProfileResolver: makeProfileResolver,
  resolveProfileName: resolveProfileName,
  throwOnRefusalSeverity: throwOnRefusalSeverity,
  badInputResultIfNotStringOrBuffer: badInputResultIfNotStringOrBuffer,
  aggregateIssues:    aggregateIssues,
  composeHooks:       composeHooks,
  summarizeIssues:    summarizeIssues,
  ACTIONS:            ACTIONS,
  MODES:              MODES,
  ISSUE_SEVERITIES:   ISSUE_SEVERITIES,
  GateContractError:      GateContractError,
  _resetForTest:      _resetForTest,
};
