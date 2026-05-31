"use strict";
/**
 * @module     b.guardPostureChain
 * @nav        Guards
 * @title      Guard Posture Chain
 * @order      442
 *
 * @intro
 *   Validates cross-boundary posture-chain envelopes. The envelope
 *   carries the set of compliance regimes the call is operating
 *   under (`postureSet: ["hipaa", "pci-dss"]`), the hop trail
 *   (`chainTrail: ["api-gateway", "mail-agent", "audit"]`), per-hop
 *   timestamps, and hop count. Refuses:
 *
 *     - oversized trail (default hop cap = 16; defends infinite
 *       recursion across agent delegation)
 *     - non-ASCII hop names (operator-greppable in audit logs)
 *     - duplicate hop in trail (recursion guard)
 *     - missing or non-monotonic enteredAt timestamps
 *     - posture set contains non-string entries OR duplicates
 *
 * @card
 *   Validates cross-boundary posture envelopes. Hop trail caps,
 *   ASCII-only hop names, monotonic timestamps, set-shape
 *   posture-regime entries.
 */

var { defineClass } = require("./framework-error");

var GuardPostureChainError = defineClass("GuardPostureChainError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxHops: 16,  maxHopBytes: 64,  maxRegimes: 8  },
  balanced:   { maxHops: 32,  maxHopBytes: 128, maxRegimes: 16 },
  permissive: { maxHops: 128, maxHopBytes: 256, maxRegimes: 64 },
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

/**
 * @primitive b.guardPostureChain.validate
 * @signature b.guardPostureChain.validate(envelope, opts?)
 * @since     0.9.28
 * @status    stable
 * @related   b.agent.postureChain.create
 *
 * Validate a posture-chain envelope. Returns the envelope on success;
 * throws on refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardPostureChain.validate({
 *     postureSet: ["hipaa"],
 *     chainTrail: ["api-gateway", "mail-agent"],
 *     enteredAt:  [1700000000000, 1700000000100],
 *     hopCount:   2,
 *   });
 */
function validate(envelope, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!envelope || typeof envelope !== "object") {
    throw new GuardPostureChainError("posture-chain/bad-input",
      "guardPostureChain.validate: envelope required");
  }
  // postureSet — array of distinct ASCII regime names
  if (!Array.isArray(envelope.postureSet)) {
    throw new GuardPostureChainError("posture-chain/bad-posture-set",
      "guardPostureChain.validate: postureSet must be an array");
  }
  if (envelope.postureSet.length > profile.maxRegimes) {
    throw new GuardPostureChainError("posture-chain/too-many-regimes",
      "guardPostureChain.validate: " + envelope.postureSet.length +
      " regimes exceeds maxRegimes=" + profile.maxRegimes);
  }
  var regSeen = Object.create(null);
  for (var r = 0; r < envelope.postureSet.length; r += 1) {
    var regime = envelope.postureSet[r];
    if (typeof regime !== "string" || regime.length === 0) {
      throw new GuardPostureChainError("posture-chain/bad-regime",
        "guardPostureChain.validate: postureSet[" + r + "] must be a non-empty string");
    }
    if (regSeen[regime]) {
      throw new GuardPostureChainError("posture-chain/duplicate-regime",
        "guardPostureChain.validate: duplicate regime '" + regime + "' in postureSet");
    }
    regSeen[regime] = true;
  }
  // chainTrail — bounded hop list
  if (!Array.isArray(envelope.chainTrail)) {
    throw new GuardPostureChainError("posture-chain/bad-trail",
      "guardPostureChain.validate: chainTrail must be an array");
  }
  if (envelope.chainTrail.length > profile.maxHops) {
    throw new GuardPostureChainError("posture-chain/hop-limit-exceeded",
      "guardPostureChain.validate: " + envelope.chainTrail.length +
      " hops exceeds maxHops=" + profile.maxHops);
  }
  var hopSeen = Object.create(null);
  for (var h = 0; h < envelope.chainTrail.length; h += 1) {
    var hop = envelope.chainTrail[h];
    if (typeof hop !== "string" || hop.length === 0) {
      throw new GuardPostureChainError("posture-chain/bad-hop",
        "guardPostureChain.validate: chainTrail[" + h + "] must be a non-empty string");
    }
    if (Buffer.byteLength(hop, "utf8") > profile.maxHopBytes) {
      throw new GuardPostureChainError("posture-chain/hop-name-too-long",
        "guardPostureChain.validate: chainTrail[" + h + "] exceeds maxHopBytes=" + profile.maxHopBytes);
    }
    for (var hi = 0; hi < hop.length; hi += 1) {
      var hc = hop.charCodeAt(hi);
      if (hc > 0x7F) {                                                                                // ASCII-only
        throw new GuardPostureChainError("posture-chain/non-ascii-hop",
          "guardPostureChain.validate: chainTrail[" + h + "] has non-ASCII codepoint");
      }
      if (hc < 0x20 || hc === 0x7F) {                                                                 // C0/DEL
        throw new GuardPostureChainError("posture-chain/bad-hop-char",
          "guardPostureChain.validate: chainTrail[" + h + "] has forbidden char 0x" + hc.toString(16));
      }
    }
    if (hopSeen[hop]) {
      throw new GuardPostureChainError("posture-chain/duplicate-hop",
        "guardPostureChain.validate: duplicate hop '" + hop + "' in chainTrail");
    }
    hopSeen[hop] = true;
  }
  // enteredAt timestamps (optional but if present must match length + be monotonic)
  if (typeof envelope.enteredAt !== "undefined") {
    if (!Array.isArray(envelope.enteredAt)) {
      throw new GuardPostureChainError("posture-chain/bad-entered-at",
        "guardPostureChain.validate: enteredAt must be an array of timestamps");
    }
    if (envelope.enteredAt.length !== envelope.chainTrail.length) {
      throw new GuardPostureChainError("posture-chain/entered-at-length-mismatch",
        "guardPostureChain.validate: enteredAt length must equal chainTrail length");
    }
    var prevT = -Infinity;
    for (var t = 0; t < envelope.enteredAt.length; t += 1) {
      var ts = envelope.enteredAt[t];
      if (typeof ts !== "number" || !isFinite(ts) || ts < 0) {
        throw new GuardPostureChainError("posture-chain/bad-timestamp",
          "guardPostureChain.validate: enteredAt[" + t + "] must be a finite non-negative number");
      }
      if (ts < prevT) {
        throw new GuardPostureChainError("posture-chain/non-monotonic-timestamps",
          "guardPostureChain.validate: enteredAt[" + t + "] < enteredAt[" + (t - 1) + "]");
      }
      prevT = ts;
    }
  }
  return envelope;
}

/**
 * @primitive b.guardPostureChain.compliancePosture
 * @signature b.guardPostureChain.compliancePosture(posture)
 * @since     0.9.28
 * @status    stable
 *
 * Return the effective profile for a given compliance posture name.
 * Returns `null` for unknown posture names so operator typos surface
 * here instead of silently falling through to the default profile.
 *
 * @example
 *   b.guardPostureChain.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return COMPLIANCE_POSTURES[opts.posture];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardPostureChainError("posture-chain/bad-profile",
      "guardPostureChain: unknown profile '" + p + "'");
  }
  return p;
}

module.exports = {
  validate:                  validate,
  compliancePosture:         compliancePosture,
  PROFILES:                  PROFILES,
  COMPLIANCE_POSTURES:       COMPLIANCE_POSTURES,
  GuardPostureChainError:    GuardPostureChainError,
  NAME:                      "postureChain",
  KIND:                      "posture-chain",
};
