// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.agent._envelopeMac — internal shared keyed-MAC mechanism for
 * authenticating agent cross-process envelopes (`b.agent.postureChain`
 * delegation envelopes, `b.agent.eventBus` wire envelopes, and any
 * future agent boundary that carries security-relevant fields over a
 * shared transport).
 *
 * The threat is uniform across these boundaries: an attacker with write
 * access to the shared transport (queue / pubsub) can forge or tamper an
 * envelope's authority-bearing fields — posture set, tenant id, topic —
 * because schema/shape validation alone proves nothing about
 * authenticity. The defense is a keyed MAC (HMAC-SHA3-512) over the
 * canonical bytes of exactly those fields, keyed off the vault master so
 * an attacker without the vault key cannot forge it and a vault rotation
 * invalidates every in-flight MAC.
 *
 * Each calling domain supplies a stable `label` (domain separation) and
 * the canonical bytes of the fields it protects; the key derivation,
 * HMAC construction, and constant-time comparison live here so there is
 * a single mechanism to audit, not one per agent module.
 *
 * Internal — operator-facing surface is each primitive's envelope
 * sign/verify behaviour; this is the implementation detail.
 */

var nodeCrypto = require("node:crypto");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");
var bCrypto = require("./crypto");

var vault = lazyRequire(function () { return require("./vault"); });

var AgentEnvelopeMacError = defineClass("AgentEnvelopeMacError", { alwaysPermanent: true });

var ENVELOPE_MAC_KEY_BYTES = 32;                                                                        // HMAC-SHA3-512 keyed bytes

// Per-label memoized keys — each domain-separation label derives its own
// sub-key from the vault master so a MAC minted for one boundary can
// never validate on another. Memoization is process-local; a vault
// rotation implies an operator restart (which clears the cache).
var _macKeyCache = Object.create(null);

// Resolve (and memoize) the MAC sub-key for a domain-separation `label`,
// derived from the vault master. Throws when the vault is not
// initialized — there is no key to authenticate with, so callers MUST
// treat that as fail-closed for any cross-tenant / authority decision
// rather than proceeding unauthenticated.
function resolveKey(label) {
  if (typeof label !== "string" || label.length === 0) {
    throw new AgentEnvelopeMacError("agent-envelope-mac/bad-label",
      "resolveKey: label must be a non-empty string");
  }
  if (_macKeyCache[label]) return _macKeyCache[label];
  var v;
  try { v = vault(); } catch (_e) { v = null; }
  if (!v || typeof v.getKeysJson !== "function") {
    throw new AgentEnvelopeMacError("agent-envelope-mac/vault-not-initialized",
      "envelope MAC: vault must be initialized before agent envelopes can be authenticated " +
      "(operator wires b.vault.init() at boot)");
  }
  var keysJson;
  try { keysJson = v.getKeysJson(); }
  catch (e) {
    throw new AgentEnvelopeMacError("agent-envelope-mac/vault-not-initialized",
      "envelope MAC: vault.getKeysJson threw — " + (e && e.message ? e.message : String(e)));
  }
  var rootBytes = Buffer.from(bCrypto.sha3Hash(keysJson), "hex");
  var input = Buffer.concat([
    Buffer.from(label, "utf8"),
    Buffer.from([0x00]),
    rootBytes,
  ]);
  _macKeyCache[label] = bCrypto.kdf(input, ENVELOPE_MAC_KEY_BYTES);
  return _macKeyCache[label];
}

// Compute the base64 HMAC-SHA3-512 of `canonicalBytes` under the
// `label`'s vault-derived sub-key.
function sign(label, canonicalBytes) {
  var key = resolveKey(label);
  return nodeCrypto.createHmac("sha3-512", key).update(canonicalBytes).digest().toString("base64");
}

// Constant-time verify that `mac` (base64) is the correct HMAC for
// `canonicalBytes` under the `label`'s sub-key. Returns false for a
// missing / malformed `mac`; propagates AgentEnvelopeMacError from
// resolveKey when the vault is absent so the caller fails closed rather
// than treating a missing key as a verification pass.
function verify(label, canonicalBytes, mac) {
  if (typeof mac !== "string" || mac.length === 0) return false;
  var expected = sign(label, canonicalBytes);
  return bCrypto.timingSafeEqual(mac, expected);
}

module.exports = {
  resolveKey:             resolveKey,
  sign:                   sign,
  verify:                 verify,
  AgentEnvelopeMacError:  AgentEnvelopeMacError,
  ENVELOPE_MAC_KEY_BYTES: ENVELOPE_MAC_KEY_BYTES,
  // Test-only — flush the memoized per-label MAC keys after a vault reset.
  _resetForTest:          function () { _macKeyCache = Object.create(null); },
};
