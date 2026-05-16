"use strict";
/**
 * @module     b.agent.postureChain
 * @nav        Agent
 * @title      Agent Posture Chain
 * @order      80
 *
 * @intro
 *   Set-based compliance posture propagated across every agent
 *   boundary (sub-agent delegation, queue envelopes, event-bus
 *   payloads, saga steps). The hard rule: **target's posture set MUST
 *   be a SUPERSET of source's posture set.** A "downgrade" (target
 *   missing a regime the source requires) is refused at the boundary.
 *
 *   Compliance regimes (HIPAA / PCI-DSS / GDPR / SOC2) protect
 *   DIFFERENT regulated-data classes — they're orthogonal, not a
 *   linear lattice. A clinic that processes payment cards operates
 *   under BOTH HIPAA + PCI; an EU clinic adds GDPR; an aggregator
 *   may add SOC2. Set semantics match how real-world regulations
 *   actually overlap.
 *
 *   ```js
 *   var chain = b.agent.postureChain.create({});
 *
 *   var sourceSet = ["hipaa", "pci-dss"];
 *   var targetSet = ["pci-dss"];           // missing hipaa
 *
 *   chain.isSubset(targetSet, sourceSet);  // false — target lacks hipaa
 *   chain.canDelegate(sourceSet, targetSet, "mail.fetch");
 *   // → false; agent.posture-chain.canDelegate-denied audit emit
 *   ```
 *
 *   ## Per-module declaration
 *
 *   Each module declares its applicable regimes via a static
 *   `POSTURES` export OR an `@compliance` JSDoc tag. The agent
 *   primitive's posture SET = union of all composed modules' declared
 *   regimes (operator can narrow at composition time).
 *
 *   ## Hop trail
 *
 *   Every cross-boundary envelope carries `{ postureSet, chainTrail,
 *   enteredAt, hopCount }`. Hop count caps at default 16 — defends
 *   infinite recursion across agent delegation. `appendHop` extends
 *   the trail when an envelope crosses a new boundary.
 *
 * @card
 *   Set-based compliance posture propagated across every boundary.
 *   target.set ⊇ source.set required; downgrade refused. Hop-trail
 *   tracking for audit + debugging.
 */

var lazyRequire             = require("./lazy-require");
var { defineClass }         = require("./framework-error");
var guardPostureChain       = require("./guard-posture-chain");
var agentAudit              = require("./agent-audit");

var audit                   = lazyRequire(function () { return require("./audit"); });

var AgentPostureChainError = defineClass("AgentPostureChainError", { alwaysPermanent: true });

var BUILTIN_REGIMES = Object.freeze(["hipaa", "pci-dss", "gdpr", "soc2"]);

/**
 * @primitive b.agent.postureChain.create
 * @signature b.agent.postureChain.create(opts)
 * @since     0.9.28
 * @status    stable
 * @related   b.agent.tenant.create, b.agent.eventBus.create
 *
 * Create the posture-chain facade. Returns an instance with
 * `isSubset` / `union` / `canDelegate` / `declareRegime` / `validate`
 * / `appendHop`.
 *
 * @opts
 *   audit:  b.audit namespace,   // optional
 *
 * @example
 *   var chain = b.agent.postureChain.create({});
 *   chain.isSubset(["pci-dss"], ["hipaa", "pci-dss"]); // → false
 */
function create(opts) {
  opts = opts || {};
  var auditImpl = opts.audit || audit();
  var declaredRegimes = Object.create(null);
  for (var i = 0; i < BUILTIN_REGIMES.length; i += 1) declaredRegimes[BUILTIN_REGIMES[i]] = true;
  return {
    declareRegime: function (name)                          { return _declareRegime(declaredRegimes, name); },
    isSubset:      function (targetSet, sourceSet)          { return _isSubset(targetSet, sourceSet); },
    union:         function ()                              { return _union.apply(null, arguments); },
    canDelegate:   function (sourceSet, targetSet, method)  { return _canDelegate(sourceSet, targetSet, method, auditImpl); },
    appendHop:     function (envelope, hopName)             { return _appendHop(envelope, hopName); },
    validate:      function (envelope, agentPostureSet)     { return _validate(envelope, agentPostureSet, auditImpl); },
    REGIMES:       Object.freeze(Object.keys(declaredRegimes)),
    AgentPostureChainError: AgentPostureChainError,
    _declaredRegimes: declaredRegimes,
  };
}

function _declareRegime(declaredRegimes, name) {
  if (typeof name !== "string" || name.length === 0) {
    throw new AgentPostureChainError("agent-posture-chain/bad-regime",
      "declareRegime: name must be a non-empty string");
  }
  if (declaredRegimes[name]) {
    throw new AgentPostureChainError("agent-posture-chain/duplicate-regime",
      "declareRegime: '" + name + "' already declared");
  }
  declaredRegimes[name] = true;
}

function _isSubset(targetSet, sourceSet) {
  if (!Array.isArray(targetSet) || !Array.isArray(sourceSet)) return false;
  if (sourceSet.length === 0) return true;     // empty source ⊆ any target
  var targetIdx = Object.create(null);
  for (var i = 0; i < targetSet.length; i += 1) targetIdx[targetSet[i]] = true;
  for (var j = 0; j < sourceSet.length; j += 1) {
    if (!targetIdx[sourceSet[j]]) return false;
  }
  return true;
}

function _union() {
  var seen = Object.create(null);
  var out = [];
  for (var a = 0; a < arguments.length; a += 1) {
    var set = arguments[a];
    if (!Array.isArray(set)) continue;
    for (var i = 0; i < set.length; i += 1) {
      if (!seen[set[i]]) {
        seen[set[i]] = true;
        out.push(set[i]);
      }
    }
  }
  return out;
}

function _canDelegate(sourceSet, targetSet, method, auditImpl) {
  if (_isSubset(targetSet, sourceSet)) return true;
  agentAudit.safeAudit(auditImpl, "agent.posture_chain.delegate_denied", null, {
    method: method, sourceSet: sourceSet, targetSet: targetSet,
    missing: _missing(targetSet, sourceSet),
  });
  return false;
}

function _missing(targetSet, sourceSet) {
  var idx = Object.create(null);
  if (Array.isArray(targetSet)) for (var i = 0; i < targetSet.length; i += 1) idx[targetSet[i]] = true;
  var out = [];
  if (Array.isArray(sourceSet)) for (var j = 0; j < sourceSet.length; j += 1) {
    if (!idx[sourceSet[j]]) out.push(sourceSet[j]);
  }
  return out;
}

function _appendHop(envelope, hopName) {
  if (!envelope || typeof envelope !== "object") {
    throw new AgentPostureChainError("agent-posture-chain/bad-envelope",
      "appendHop: envelope required");
  }
  if (typeof hopName !== "string" || hopName.length === 0) {
    throw new AgentPostureChainError("agent-posture-chain/bad-hop-name",
      "appendHop: hopName must be a non-empty string");
  }
  var trail = Array.isArray(envelope.chainTrail) ? envelope.chainTrail.slice() : [];
  trail.push(hopName);
  var enteredAt = Array.isArray(envelope.enteredAt) ? envelope.enteredAt.slice() : [];
  enteredAt.push(Date.now());
  var newEnvelope = Object.assign({}, envelope, {
    chainTrail: trail,
    enteredAt:  enteredAt,
    hopCount:   trail.length,
  });
  guardPostureChain.validate(newEnvelope);
  return newEnvelope;
}

function _validate(envelope, agentPostureSet, auditImpl) {
  guardPostureChain.validate(envelope);
  // The source (envelope) carries a postureSet; the target (the agent
  // we're entering) declares its own posture set. Target must be a
  // superset of source — i.e., the agent covers every regime the
  // calling context requires.
  if (Array.isArray(agentPostureSet)) {
    if (!_isSubset(agentPostureSet, envelope.postureSet)) {
      var missing = _missing(agentPostureSet, envelope.postureSet);
      agentAudit.safeAudit(auditImpl, "agent.posture_chain.downgrade_refused", null, {
        sourceSet: envelope.postureSet, targetSet: agentPostureSet, missing: missing,
        chainTrail: envelope.chainTrail,
      });
      throw new AgentPostureChainError("agent-posture-chain/downgrade-refused",
        "validate: agent posture-set " + JSON.stringify(agentPostureSet) +
        " missing regimes required by envelope: " + JSON.stringify(missing));
    }
  }
  return envelope;
}

module.exports = {
  create:                    create,
  BUILTIN_REGIMES:           BUILTIN_REGIMES,
  AgentPostureChainError:    AgentPostureChainError,
  guards: {
    chain: guardPostureChain,
  },
};
