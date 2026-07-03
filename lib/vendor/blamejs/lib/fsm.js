// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.fsm
 * @nav        Agent
 * @title      FSM
 * @order      76
 *
 * @intro
 *   Auditable in-process finite-state machine. Declare states +
 *   transitions at construction time; guards + on-enter / on-exit
 *   side-effects fire on every transition; every transition lands
 *   in the audit chain.
 *
 *   `b.fsm` is the lighter sibling of `b.agent.saga`. Saga handles
 *   distributed multi-step transactions with compensation across
 *   process / network boundaries (composes outbox + idempotency +
 *   persisted state). `b.fsm` handles in-process state lifecycles —
 *   order placed → paid → shipped → delivered, subscription
 *   trialing → active → past-due → canceled, refund requested →
 *   approved → processed → settled. They're complementary; reach
 *   for fsm when the lifecycle lives inside one process and saga
 *   when it spans multiple steps that each need their own
 *   compensation.
 *
 *   ```js
 *   var orderFsm = b.fsm.define({
 *     name:    "order",
 *     initial: "placed",
 *     states: {
 *       placed:    {},
 *       paid:      { onEnter: function (ctx) { ctx.paidAt = Date.now(); } },
 *       shipped:   {},
 *       delivered: {},
 *       canceled:  {},
 *     },
 *     transitions: [
 *       { from: "placed",  to: "paid",      on: "pay" },
 *       { from: "paid",    to: "shipped",   on: "ship",
 *         guard: function (ctx) { return ctx.address != null; } },
 *       { from: "shipped", to: "delivered", on: "deliver" },
 *       { from: "placed",  to: "canceled",  on: "cancel" },
 *       { from: "paid",    to: "canceled",  on: "cancel" },
 *     ],
 *   });
 *   var order = orderFsm.create({ initialContext: { address: "..." } });
 *   await order.transition("pay");
 *   await order.transition("ship");
 *   order.state;    // → "shipped"
 *   ```
 *
 *   ## Scope
 *
 *   v1 ships the flat statechart variant — every state lives at the
 *   same level. Hierarchical (nested) states, parallel regions, and
 *   history pseudo-states are deferred-with-condition: re-open when
 *   an operator surfaces a lifecycle that the flat-variant
 *   workaround (compose multiple FSMs) can't express. References:
 *   Harel statecharts (1987); UML State Machine (OMG UML 2.5.1 §14);
 *   ISO/IEC 19505 (UML).
 *
 *   ## Transition discipline
 *
 *   * Guards are pure predicates — no side effects. A guard that
 *     returns false refuses the transition with `fsm/guard-refused`.
 *   * `onExit` on the current state runs before `onEnter` on the
 *     next state. Both may be sync or return a Promise; the
 *     primitive awaits the promise before returning from
 *     `.transition()`.
 *   * Concurrent `.transition()` calls serialize through an
 *     in-instance lock — `transition()` returns a Promise that
 *     other concurrent calls await before they start.
 *   * Every transition emits `fsm.<machineName>.transition` via
 *     `audit.safeEmit` (drop-silent — operator audit-sink failures
 *     don't crash the caller). The state commits before the
 *     destination's `onEnter` runs, so a throwing `onEnter` still
 *     records the transition (with outcome `failure` + the error)
 *     rather than silently losing the audit entry.
 *   * `instance.target(event)` resolves a transition's destination
 *     state side-effect-free — same edge + guard check as `can()` but
 *     returns the to-state (or `null` when the edge is illegal /
 *     guard-refused). Use it to compose an external compare-and-swap
 *     (the cross-instance claim on autocommit-only substrates) without
 *     calling `transition()` before the claim is known to land.
 *   * `transition(event, { audit: false })` suppresses the built-in
 *     emit so that composition can emit its own enriched record once
 *     the external claim resolves.
 *
 *   ## Serialization
 *
 *   `.toJSON()` returns `{ state, history, context }`. The factory
 *   returned from `define()` exposes `.restore(snapshot)` which
 *   rebuilds an Instance with the captured state + history +
 *   context. The Machine definition is NOT in the snapshot — the
 *   operator pairs the snapshot with the same definition they used
 *   to create it. This avoids snapshot-rollover-on-definition-edit
 *   ambiguity.
 *
 * @card
 *   Auditable in-process FSM with guards, on-enter / on-exit
 *   side-effects, concurrent-transition serialization, and
 *   toJSON / restore round-trip. Lighter sibling of b.agent.saga.
 */

var lazyRequire   = require("./lazy-require");
var { defineClass } = require("./framework-error");
var safeSql       = require("./safe-sql");

var audit = lazyRequire(function () { return require("./audit"); });

var FsmError = defineClass("FsmError", { alwaysPermanent: true });

// Identifier-shape only. State + transition names are emitted in
// audit metadata and could end up in operator-side SQL / dashboards;
// refuse arbitrary strings at define-time so injection-shaped names
// (`order; DROP TABLE`, `<script>`, control bytes) can never reach
// downstream sinks. Routes through safeSql.DEFAULT_IDENTIFIER_RE +
// MAX_IDENTIFIER_LENGTH so the framework-canonical identifier shape
// is the only declared identifier shape across primitives.
var IDENT_RE       = safeSql.DEFAULT_IDENTIFIER_RE;
var IDENT_MAX_LEN  = safeSql.MAX_IDENTIFIER_LENGTH;

function _assertIdent(value, label) {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > IDENT_MAX_LEN || !IDENT_RE.test(value)) {
    throw new FsmError("fsm/bad-name",
      label + " must match " + IDENT_RE +
      " and be <= " + IDENT_MAX_LEN + " chars (got " +
      JSON.stringify(value) + ")");
  }
}

/**
 * @primitive b.fsm.define
 * @signature b.fsm.define(definition)
 * @since     0.11.25
 * @status    stable
 * @related   b.agent.saga.create
 *
 * Compile a machine definition. Returns a frozen factory exposing
 * `create({ initialContext? })` to instantiate new machines and
 * `restore(snapshot)` to rebuild from a `.toJSON()` output.
 *
 * Throws `FsmError` on any malformed definition: missing name /
 * initial / states / transitions, state name or transition name
 * that isn't identifier-shape, transition referencing an unknown
 * `from` / `to` state, duplicate (from, on) pair, or initial state
 * not declared in `states`.
 *
 * @opts
 *   name:        string,         // required (identifier-shape)
 *   initial:     string,         // required; must be a key of states
 *   states:      object,         // { <name>: { onEnter?, onExit? }, ... }
 *   transitions: Array<{ from, to, on, guard? }>,
 *
 * @example
 *   var fsm = b.fsm.define({
 *     name: "door", initial: "closed",
 *     states: { closed: {}, open: {} },
 *     transitions: [
 *       { from: "closed", to: "open",   on: "open"  },
 *       { from: "open",   to: "closed", on: "close" },
 *     ],
 *   });
 *   var door = fsm.create();
 *   await door.transition("open");
 */
function define(definition) {
  if (!definition || typeof definition !== "object") {
    throw new FsmError("fsm/bad-input", "define: definition must be an object");
  }
  _assertIdent(definition.name, "define: definition.name");
  if (typeof definition.initial !== "string") {
    throw new FsmError("fsm/bad-input", "define: definition.initial required");
  }
  if (!definition.states || typeof definition.states !== "object") {
    throw new FsmError("fsm/bad-input", "define: definition.states must be an object");
  }
  if (!Array.isArray(definition.transitions)) {
    throw new FsmError("fsm/bad-input", "define: definition.transitions must be an array");
  }
  var stateNames = Object.keys(definition.states);
  if (stateNames.length === 0) {
    throw new FsmError("fsm/bad-input", "define: at least one state required");
  }
  for (var si = 0; si < stateNames.length; si++) {
    _assertIdent(stateNames[si], "define: state name");
    var sBody = definition.states[stateNames[si]];
    if (sBody && typeof sBody === "object") {
      if (sBody.onEnter !== undefined && typeof sBody.onEnter !== "function") {
        throw new FsmError("fsm/bad-input",
          "define: states." + stateNames[si] + ".onEnter must be a function");
      }
      if (sBody.onExit !== undefined && typeof sBody.onExit !== "function") {
        throw new FsmError("fsm/bad-input",
          "define: states." + stateNames[si] + ".onExit must be a function");
      }
    }
  }
  if (!Object.prototype.hasOwnProperty.call(definition.states, definition.initial)) {
    throw new FsmError("fsm/bad-input",
      "define: initial state '" + definition.initial + "' not declared in states");
  }
  if (definition.transitions.length === 0) {
    throw new FsmError("fsm/bad-input", "define: at least one transition required");
  }
  // (from, on) pair must be unique. Walking the array twice is cheap;
  // the alternative (silently take the last-declared) hides a
  // definition bug that would manifest at runtime as the "wrong"
  // transition firing.
  var seenPairs = Object.create(null);
  var transitionsByName = Object.create(null);
  for (var ti = 0; ti < definition.transitions.length; ti++) {
    var t = definition.transitions[ti];
    if (!t || typeof t !== "object") {
      throw new FsmError("fsm/bad-input",
        "define: transitions[" + ti + "] must be an object");
    }
    _assertIdent(t.from, "define: transitions[" + ti + "].from");
    _assertIdent(t.to,   "define: transitions[" + ti + "].to");
    _assertIdent(t.on,   "define: transitions[" + ti + "].on");
    if (!Object.prototype.hasOwnProperty.call(definition.states, t.from)) {
      throw new FsmError("fsm/bad-input",
        "define: transition '" + t.on + "' references unknown from-state '" + t.from + "'");
    }
    if (!Object.prototype.hasOwnProperty.call(definition.states, t.to)) {
      throw new FsmError("fsm/bad-input",
        "define: transition '" + t.on + "' references unknown to-state '" + t.to + "'");
    }
    if (t.guard !== undefined && typeof t.guard !== "function") {
      throw new FsmError("fsm/bad-input",
        "define: transition '" + t.on + "'.guard must be a function");
    }
    var pairKey = t.from + "→" + t.on;
    if (seenPairs[pairKey]) {
      throw new FsmError("fsm/bad-input",
        "define: duplicate transition (from='" + t.from + "', on='" + t.on + "')");
    }
    seenPairs[pairKey] = true;
    if (!transitionsByName[t.on]) transitionsByName[t.on] = [];
    transitionsByName[t.on].push({ from: t.from, to: t.to, guard: t.guard || null });
  }
  // Deep-clone the caller-provided `states` + `transitions` objects
  // before freezing. The shallow freeze on the outer object alone
  // leaves the inner references mutable by the caller, so a post-
  // define mutation of `definition.states.foo.onEnter` would silently
  // change runtime behaviour across every Instance the factory built.
  // Clone-then-freeze cuts the reference link.
  var clonedStates = Object.create(null);
  var stateKeys = Object.keys(definition.states);
  for (var sk = 0; sk < stateKeys.length; sk += 1) {
    var sName = stateKeys[sk];
    var sClonedBody = definition.states[sName] || {};
    clonedStates[sName] = Object.freeze({
      onEnter: sClonedBody.onEnter || null,
      onExit:  sClonedBody.onExit  || null,
    });
  }
  Object.freeze(clonedStates);
  var clonedTransitions = definition.transitions.map(function (t) {
    return Object.freeze({
      from:  t.from,
      to:    t.to,
      on:    t.on,
      guard: t.guard || null,
    });
  });
  Object.freeze(clonedTransitions);
  var frozenDef = Object.freeze({
    name:        definition.name,
    initial:     definition.initial,
    states:      clonedStates,
    transitions: clonedTransitions,
    _byName:     transitionsByName,
  });
  var factory = {
    name:    definition.name,
    define:  frozenDef,
    create:  function (opts) { return _createInstance(frozenDef, opts || {}); },
    restore: function (snapshot) { return _restoreInstance(frozenDef, snapshot); },
    FsmError: FsmError,
  };
  return Object.freeze(factory);
}

function _createInstance(def, opts) {
  var initialContext = (opts.initialContext && typeof opts.initialContext === "object")
    ? Object.assign({}, opts.initialContext)
    : {};
  return _buildInstance(def, def.initial, [], initialContext);
}

function _restoreInstance(def, snapshot) {
  if (!snapshot || typeof snapshot !== "object") {
    throw new FsmError("fsm/bad-input", "restore: snapshot must be an object");
  }
  if (typeof snapshot.state !== "string" ||
      !Object.prototype.hasOwnProperty.call(def.states, snapshot.state)) {
    throw new FsmError("fsm/bad-input",
      "restore: snapshot.state '" + snapshot.state + "' not declared in machine '" + def.name + "'");
  }
  var hist = Array.isArray(snapshot.history) ? snapshot.history.slice() : [];
  var ctx = (snapshot.context && typeof snapshot.context === "object")
    ? Object.assign({}, snapshot.context)
    : {};
  return _buildInstance(def, snapshot.state, hist, ctx);
}

function _buildInstance(def, initialState, initialHistory, initialContext) {
  // Concurrent .transition() calls chain off this promise. Every
  // transition replaces _lock with its own resolution promise so
  // subsequent calls await the in-flight transition before starting.
  // This is the in-memory equivalent of "single-flight" — operators
  // who need cross-process serialization use b.agent.idempotency or
  // b.agent.orchestrator's leader-elected singleton.
  var instance = {
    state:    initialState,
    context:  initialContext,
    history:  initialHistory,
    _lock:    Promise.resolve(),
    _def:     def,
  };
  instance.allowed   = function () { return _allowed(instance); };
  instance.can       = function (name) { return _can(instance, name); };
  // Side-effect-free destination resolver — mirrors can() but returns the
  // to-state (or null). Lets a consumer composing an EXTERNAL compare-and-swap
  // (e.g. b.sql.guardedUpdate on an autocommit-only substrate) build the
  // `SET status = <to>` claim without calling transition(), which would mutate
  // state and emit an audit before the cross-instance claim is known to land.
  instance.target    = function (name) { return _resolveTarget(instance, name); };
  instance.transition = function (name, opts) { return _enqueueTransition(instance, name, opts || {}); };
  instance.toJSON    = function () { return _toJSON(instance); };
  return instance;
}

function _allowed(instance) {
  var byName = instance._def._byName;
  var out = [];
  var seen = Object.create(null);
  var keys = Object.keys(byName);
  for (var i = 0; i < keys.length; i++) {
    var defs = byName[keys[i]];
    for (var j = 0; j < defs.length; j++) {
      if (defs[j].from === instance.state && !seen[keys[i]]) {
        out.push(keys[i]);
        seen[keys[i]] = true;
        break;
      }
    }
  }
  return out;
}

// Resolve the destination state for `name` from the current state,
// side-effect-free: matches the (from, on) edge and runs the PURE guard
// (guards are contractually side-effect-free). Returns the to-state string
// when the transition is allowed, or null when the edge is illegal from the
// current state or the guard refuses / throws. The single source of truth
// for both can() (boolean) and target() (destination) so they can never
// disagree about whether an edge is takeable.
function _resolveTarget(instance, name) {
  if (typeof name !== "string") return null;
  var defs = instance._def._byName[name];
  if (!defs) return null;
  for (var i = 0; i < defs.length; i++) {
    var t = defs[i];
    if (t.from !== instance.state) continue;
    if (t.guard) {
      var verdict;
      try { verdict = t.guard(instance.context); }
      catch (_e) { return null; }
      if (verdict !== true) return null;
    }
    return t.to;
  }
  return null;
}

// A to-state is always a non-empty identifier (validated at define-time), so
// "resolved !== null" is an exact "is this edge takeable" test.
function _can(instance, name) {
  return _resolveTarget(instance, name) !== null;
}

function _enqueueTransition(instance, name, opts) {
  // Chain the new transition onto the existing lock — concurrent
  // calls serialize. Errors from the previous transition do not
  // prevent the next from running (operator semantics: a failed
  // transition leaves state unchanged; the next operator-requested
  // transition still gets to try).
  var next = instance._lock.then(
    function () { return _runTransition(instance, name, opts); },
    function () { return _runTransition(instance, name, opts); }
  );
  // The lock tracks completion regardless of outcome so the NEXT
  // caller waits, but bury the rejection on the lock itself so an
  // unhandled-rejection warning doesn't fire on a stray transition
  // that nobody else awaits.
  instance._lock = next.then(function () {}, function () {});
  return next;
}

async function _runTransition(instance, name, opts) {
  if (typeof name !== "string") {
    throw new FsmError("fsm/bad-input", "transition: name must be a string");
  }
  var defs = instance._def._byName[name];
  if (!defs) {
    throw new FsmError("fsm/illegal-transition",
      "transition: '" + name + "' is not declared in machine '" + instance._def.name + "'");
  }
  // Find a matching transition for the current state.
  var matched = null;
  for (var i = 0; i < defs.length; i++) {
    if (defs[i].from === instance.state) { matched = defs[i]; break; }
  }
  if (!matched) {
    throw new FsmError("fsm/illegal-transition",
      "transition: '" + name + "' not allowed from state '" + instance.state +
      "' (machine '" + instance._def.name + "')");
  }
  if (matched.guard) {
    var verdict;
    try { verdict = matched.guard(instance.context); }
    catch (guardErr) {
      throw new FsmError("fsm/guard-threw",
        "transition: '" + name + "' guard threw: " +
        ((guardErr && guardErr.message) || String(guardErr)));
    }
    if (verdict !== true) {
      throw new FsmError("fsm/guard-refused",
        "transition: '" + name + "' refused by guard (from state '" +
        instance.state + "')");
    }
  }
  var fromState = instance.state;
  var toState   = matched.to;
  var fromBody  = instance._def.states[fromState];
  var toBody    = instance._def.states[toState];
  // onExit runs FIRST so the operator's exit cleanup completes
  // before the new state's onEnter starts. A throw from either side-
  // effect propagates to the caller; the state still advances after
  // onExit (because onExit committed the cleanup the operator
  // intended) but onEnter throws leave the state in the new value
  // with an exception surfaced — operators wrap onEnter in their own
  // try/catch when they want to roll back to the prior state.
  if (fromBody && typeof fromBody.onExit === "function") {
    var exitResult = fromBody.onExit(instance.context);
    if (exitResult && typeof exitResult.then === "function") {
      await exitResult;
    }
  }
  instance.state = toState;
  var historyEntry = {
    from: fromState,
    to:   toState,
    on:   name,
    at:   Date.now(),
  };
  if (opts.actor != null)    historyEntry.actor    = opts.actor;
  if (opts.metadata != null) historyEntry.metadata = opts.metadata;
  instance.history.push(historyEntry);
  // onEnter on the destination state. The state is ALREADY committed and the
  // history entry pushed, so the transition is durable no matter what onEnter
  // does. A throw from onEnter must still surface to the caller (operators
  // wrap it to roll back), but it must NOT skip the audit emit below: the
  // state moved, and "every transition lands in the audit chain" is the
  // primitive's contract. Capture the onEnter error, always emit, then
  // re-throw — otherwise a throwing onEnter leaves a committed state change
  // with no audit record (a compliance hole for HIPAA/SOX/PCI state trails).
  var enterErr = null;
  if (toBody && typeof toBody.onEnter === "function") {
    try {
      var enterResult = toBody.onEnter(instance.context);
      if (enterResult && typeof enterResult.then === "function") {
        await enterResult;
      }
    } catch (e) {
      enterErr = e;
    }
  }
  // Audit emission is drop-silent — operator audit-sink failures never crash
  // the caller. The .safeEmit wrapper is itself drop-silent; the additional
  // try/catch protects against the lazy-loaded audit module throwing at
  // first-access time. Suppressed when the caller passes { audit: false } so a
  // composition driving an external compare-and-swap can emit its OWN enriched
  // record (with the claim's rowCount / external txn id) once the claim is
  // known to have landed — see instance.target(). When onEnter threw, the
  // record still fires but stamps outcome "failure" + the error so an auditor
  // sees the transition committed with a failed entry hook.
  if (opts.audit !== false) {
    try {
      var auditMeta = {
        from:       fromState,
        to:         toState,
        transition: name,
        machine:    instance._def.name,
        callerMeta: opts.metadata || null,
      };
      if (enterErr) auditMeta.onEnterError = enterErr.message || String(enterErr);
      audit().namespaced("fsm")(instance._def.name + ".transition",
        enterErr ? "failure" : "success", auditMeta,
        { actor: opts.actor ? { id: opts.actor } : { id: "<system>" } });
    } catch (_e) { /* drop-silent — audit best-effort */ }
  }
  if (enterErr) throw enterErr;
  return { from: fromState, to: toState, on: name };
}

function _toJSON(instance) {
  return {
    state:   instance.state,
    history: instance.history.slice(),
    context: Object.assign({}, instance.context),
  };
}

module.exports = {
  define:   define,
  FsmError: FsmError,
};
