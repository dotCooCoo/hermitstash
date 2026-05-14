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
      if (d.action === "refuse" && Math.random() > rate) {       // allow:math-random-noncrypto — canary sampling, non-security
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
  if (!postures || !postures[name]) {
    throw errorFactory(codePrefix + ".bad-posture",
      "unknown compliancePosture " + JSON.stringify(name));
  }
  return Object.assign({}, postures[name]);
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
  if (typeof input === "string" || Buffer.isBuffer(input)) return null;
  return {
    ok: false,
    issues: [{ kind: "bad-input", severity: "high",
               snippet: "input is not string or Buffer" }],
  };
}

/**
 * @primitive  b.gateContract.runIssueValidator
 * @signature  b.gateContract.runIssueValidator(input, opts, detector)
 * @since      0.7.5
 * @status     stable
 * @related    b.gateContract.aggregateIssues, b.gateContract.badInputResultIfNotStringOrBuffer
 *
 * Boilerplate for guard-* `validate(input, opts)` entry points.
 * Normalizes string-or-Buffer input to a UTF-8 string, returns the
 * canonical `{ ok: false, issues: [{ kind: "bad-input", ... }] }` shape
 * on type mismatch, otherwise calls the operator-supplied `detector`
 * and aggregates its issues array. Result `ok` is `true` only when no
 * detected issue is `critical` / `high` severity. Lets every guard's
 * `validate()` body be identical scaffolding around the per-guard
 * detector. The `opts` argument is forwarded verbatim as the second
 * argument to `detector(text, opts)` — its shape is detector-defined,
 * not constrained by gate-contract.
 *
 * @opts
 *   ...:   any,                     // detector-defined; passed through to detector(text, opts)
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
