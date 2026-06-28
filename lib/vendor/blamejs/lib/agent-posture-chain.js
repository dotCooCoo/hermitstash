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
var safeJson                = require("./safe-json");
var envelopeMac             = require("./agent-envelope-mac");

var audit                   = lazyRequire(function () { return require("./audit"); });

var AgentPostureChainError = defineClass("AgentPostureChainError", { alwaysPermanent: true });

var BUILTIN_REGIMES = Object.freeze(["hipaa", "pci-dss", "gdpr", "soc2"]);

// Envelope MAC vocabulary. Cross-process envelope
// integrity: an attacker with queue / event-bus write access who
// strips postureSet to [] and re-sends a saga / sub-agent envelope
// can bypass the downgrade refusal in _validate (which only checks
// SHAPE, not authenticity). Defense is a keyed MAC over the canonical
// envelope bytes, computed at appendHop and verified at validate. The
// key derivation + HMAC construction live in the shared
// b.agent.envelopeMac mechanism (one keyed-MAC mechanism for every
// agent boundary); this label domain-separates the posture-chain MAC.
var ENVELOPE_MAC_LABEL = "blamejs.agent.postureChain/v1";
// Hop count cap defends infinite recursion across
// agent delegation. 16 is the spec default; operators can lower via
// opts.maxHopCount but never raise (audit fan-out without a cap is a
// DoS class).
var DEFAULT_MAX_HOP_COUNT = 16;                                                                         // hop count cap

function _envelopeMacBytes(envelope) {
  // Sign every field that downstream consumers verify off the wire,
  // except the `_mac` field itself. Also includes
  // hopCount + chainTrail so a hostile rewriter can't roll back the
  // trail to evade the cap.
  var payload = {
    postureSet: Array.isArray(envelope.postureSet) ? envelope.postureSet.slice().sort() : [],
    chainTrail: Array.isArray(envelope.chainTrail) ? envelope.chainTrail.slice() : [],
    enteredAt:  Array.isArray(envelope.enteredAt)  ? envelope.enteredAt.slice()  : [],
    hopCount:   typeof envelope.hopCount === "number" ? envelope.hopCount : 0,
  };
  return Buffer.from(safeJson.canonical(payload), "utf8");
}

function _signEnvelope(envelope) {
  return envelopeMac.sign(ENVELOPE_MAC_LABEL, _envelopeMacBytes(envelope));
}

function _verifyEnvelopeMac(envelope) {
  return envelopeMac.verify(ENVELOPE_MAC_LABEL, _envelopeMacBytes(envelope), envelope._mac);
}

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
  // allow:numeric-opt-Infinity-intentional — operator opt clamped to [1, DEFAULT_MAX_HOP_COUNT] (the `<= DEFAULT_MAX_HOP_COUNT` upper bound rejects Infinity); bad input falls back to default
  var maxHopCount = typeof opts.maxHopCount === "number" && opts.maxHopCount > 0 &&
                    opts.maxHopCount <= DEFAULT_MAX_HOP_COUNT
                      ? Math.floor(opts.maxHopCount)
                      : DEFAULT_MAX_HOP_COUNT;
  // Escape hatch — only single-process unit tests should opt out of
  // envelope MAC. Production / multi-
  // process / queue-spanning deployments leave the default on; the
  // gate audit-emits when bypassed so the posture is visible.
  var requireMac = opts.requireMac !== false;
  var ctx = {
    audit:        auditImpl,
    maxHopCount:  maxHopCount,
    requireMac:   requireMac,
  };
  return {
    declareRegime: function (name)                          { return _declareRegime(declaredRegimes, name); },
    isSubset:      function (targetSet, sourceSet)          { return _isSubset(targetSet, sourceSet); },
    union:         function ()                              { return _union.apply(null, arguments); },
    canDelegate:   function (sourceSet, targetSet, method)  { return _canDelegate(sourceSet, targetSet, method, auditImpl); },
    appendHop:     function (envelope, hopName)             { return _appendHop(ctx, envelope, hopName); },
    validate:      function (envelope, agentPostureSet)     { return _validate(ctx, envelope, agentPostureSet); },
    sign:          function (envelope)                      { return _signEnvelope(envelope); },
    verify:        function (envelope)                      { return _verifyEnvelopeMac(envelope); },
    REGIMES:       Object.freeze(Object.keys(declaredRegimes)),
    MAX_HOP_COUNT: maxHopCount,
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

function _appendHop(ctx, envelope, hopName) {
  if (!envelope || typeof envelope !== "object") {
    throw new AgentPostureChainError("agent-posture-chain/bad-envelope",
      "appendHop: envelope required");
  }
  if (typeof hopName !== "string" || hopName.length === 0) {
    throw new AgentPostureChainError("agent-posture-chain/bad-hop-name",
      "appendHop: hopName must be a non-empty string");
  }
  var trail = Array.isArray(envelope.chainTrail) ? envelope.chainTrail.slice() : [];
  // Cap enforced BEFORE the push so the hop-cap throw
  // fires consistently regardless of whether the operator inspects
  // trail.length first. Cap is a hard refusal (no truncation) because
  // a silently-dropped hop loses audit provenance for the call.
  if (trail.length >= ctx.maxHopCount) {
    agentAudit.safeAudit(ctx.audit, "agent.posture_chain.hop_cap_refused", null, {
      hopName: hopName, hopCount: trail.length, maxHopCount: ctx.maxHopCount,
      chainTrail: trail,
    });
    throw new AgentPostureChainError("agent-posture-chain/hop-cap-exceeded",
      "appendHop: chain trail has " + trail.length + " hops; cap is " + ctx.maxHopCount +
      " — refusing to extend (operator delegation cycle?)");
  }
  trail.push(hopName);
  var enteredAt = Array.isArray(envelope.enteredAt) ? envelope.enteredAt.slice() : [];
  enteredAt.push(Date.now());
  var newEnvelope = Object.assign({}, envelope, {
    chainTrail: trail,
    enteredAt:  enteredAt,
    hopCount:   trail.length,
  });
  guardPostureChain.validate(newEnvelope);
  // Sign at every hop. Verify-side enforces requireMac.
  // ctx.requireMac=false (test escape hatch) skips
  // the sign so a vault-less test path still works.
  if (ctx.requireMac) {
    try {
      newEnvelope._mac = _signEnvelope(newEnvelope);
    } catch (e) {
      // Vault not initialized at boot — surface the error to the
      // operator. Without the MAC the envelope is unauthenticated and
      // every downstream _validate would refuse it; better to refuse
      // here with a clear message.
      throw new AgentPostureChainError("agent-posture-chain/mac-sign-failed",
        "appendHop: envelope MAC sign failed — " + (e && e.message ? e.message : String(e)) +
        " — operator wires b.vault.init() before agent-posture-chain.appendHop OR " +
        "passes create({ requireMac: false }) for vault-less unit tests");
    }
  }
  return newEnvelope;
}

function _validate(ctx, envelope, agentPostureSet) {
  guardPostureChain.validate(envelope);
  // MAC verification BEFORE any field-based decision so
  // the wire-rewrite attack (postureSet:[] downgrade with valid SHAPE
  // but no integrity binding) is refused. ctx.requireMac=false skips
  // verification and emits an audit so the bypass is visible.
  if (ctx.requireMac) {
    if (typeof envelope._mac !== "string" || envelope._mac.length === 0) {
      agentAudit.safeAudit(ctx.audit, "agent.posture_chain.unauthenticated_envelope", null, {
        chainTrail: envelope.chainTrail, postureSet: envelope.postureSet,
      });
      throw new AgentPostureChainError("agent-posture-chain/missing-mac",
        "validate: envelope is unauthenticated (no _mac field) — refusing under requireMac=true");
    }
    if (!_verifyEnvelopeMac(envelope)) {
      agentAudit.safeAudit(ctx.audit, "agent.posture_chain.mac_verify_failed", null, {
        chainTrail: envelope.chainTrail, postureSet: envelope.postureSet,
      });
      throw new AgentPostureChainError("agent-posture-chain/mac-verify-failed",
        "validate: envelope MAC verification failed — bytes tampered, " +
        "chain trail rewritten, or signed under a different vault keypair");
    }
  } else {
    agentAudit.safeAudit(ctx.audit, "agent.posture_chain.mac_skipped", null, {
      chainTrail: envelope.chainTrail,
    });
  }
  // Hop cap also enforced at validate-time. A hostile
  // envelope might arrive with hopCount > cap if a prior hop's
  // requireMac was off; refuse here regardless.
  if (Array.isArray(envelope.chainTrail) && envelope.chainTrail.length > ctx.maxHopCount) {
    throw new AgentPostureChainError("agent-posture-chain/hop-cap-exceeded",
      "validate: chain trail length " + envelope.chainTrail.length +
      " exceeds cap " + ctx.maxHopCount);
  }
  // The source (envelope) carries a postureSet; the target (the agent
  // we're entering) declares its own posture set. Target must be a
  // superset of source — i.e., the agent covers every regime the
  // calling context requires.
  if (Array.isArray(agentPostureSet)) {
    if (!_isSubset(agentPostureSet, envelope.postureSet)) {
      var missing = _missing(agentPostureSet, envelope.postureSet);
      agentAudit.safeAudit(ctx.audit, "agent.posture_chain.downgrade_refused", null, {
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
  MAX_HOP_COUNT:             DEFAULT_MAX_HOP_COUNT,
  AgentPostureChainError:    AgentPostureChainError,
  guards: {
    chain: guardPostureChain,
  },
  // Test-only — flush the memoized MAC key after a vault reset.
  _resetForTest: function () { envelopeMac._resetForTest(); },
};
