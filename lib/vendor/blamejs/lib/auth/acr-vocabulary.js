// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * ACR (Authentication Context Class Reference) vocabulary.
 *
 * The `acr` claim is RFC 9470 §3 + OIDC Core 1.0 §2 + ISO/IEC 29115. It
 * denotes the rigor of the authentication ceremony that backs the
 * current session — operators reason about it the same way they reason
 * about NIST 800-63-4 AAL bands, but ACR carries finer granularity: it
 * also encodes WHICH method achieved the strength.
 *
 * The framework ships a built-in dictionary of well-known ACR values
 * with a strength-rank assigned from the spec authors' intent, but the
 * dictionary is operator-extendable: every ACR your IdP issues should
 * be registered with `register({ value, rank })` so policy decisions
 * can compare what the request carries against what the route requires.
 *
 * Built-in vocabulary (rank ascending):
 *
 *   "0"                     → no authentication (public access)
 *   "1"                     → password / single-factor (OIDC Core)
 *   "loa1" / "low"          → loa1 / iso-29115 LOA-1 (low confidence)
 *   "phr"                   → phishing-resistant single-factor
 *                             (RFC 9470 example value)
 *   "loa2" / "substantial"  → multi-factor, ISO LOA-2
 *   "2"                     → multi-factor (OIDC Core)
 *   "phrh"                  → phishing-resistant + hardware (RFC 9470)
 *   "loa3" / "high"         → multi-factor + phishing-resistant + hw
 *   "loa4"                  → in-person verified, hardware-bound
 *   "urn:mace:incommon:iap:bronze"  → InCommon LoA-1
 *   "urn:mace:incommon:iap:silver"  → InCommon LoA-2
 *   "urn:mace:incommon:iap:gold"    → InCommon LoA-3
 *   "aal1" / "aal2" / "aal3"        → NIST 800-63-4 (cross-walked)
 *   "ial1" / "ial2" / "ial3"        → NIST 800-63A identity (cross-walked)
 *   "fal1" / "fal2" / "fal3"        → NIST 800-63C federation
 *
 * Operators with a private vocabulary register before evaluation:
 *
 *   b.auth.acr.register({ value: "myco:strong", rank: 70 });
 *
 * Ranks are operator-comparable integers in [0, 100]. The framework's
 * built-ins occupy the ranges:
 *
 *   0–9    public / unauthenticated
 *   10–29  single factor
 *   30–49  multi-factor
 *   50–69  phishing-resistant multi-factor
 *   70–89  hardware-bound + phishing-resistant
 *   90–100 in-person identity-proofed + hardware
 *
 * ACR is a STRING value carried in the `acr` JWT claim. Some IdPs emit
 * the value directly; others stuff a JSON-array of ACRs into the
 * `acr_values` parameter and let the policy engine pick. The framework
 * accepts both.
 *
 * AMR (Authentication Methods References) per RFC 8176 is a separate
 * but adjacent vocabulary — it lists WHICH methods were used (e.g.
 * `["pwd", "otp"]` for password+TOTP). The framework's policy engine
 * also evaluates AMR: a route requiring `requiredAmr: ["hwk"]`
 * (hardware-key per RFC 8176) rejects sessions whose AMR lacks `hwk`
 * even when their ACR ranks high enough.
 */

var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

// Core ranks — ascending strength. Operator-extendable via register().
var BUILTIN_RANKS = {
  // Public / unauthenticated
  "0":                                 0,

  // Single factor
  "1":                                 10,
  "loa1":                              10,
  "low":                               10,
  "ial1":                              10,
  "fal1":                              10,
  "aal1":                              10,
  "urn:mace:incommon:iap:bronze":      12,

  // Phishing-resistant single factor (e.g. mTLS)
  "phr":                               25,

  // Multi-factor
  "2":                                 30,
  "loa2":                              30,
  "substantial":                       30,
  "ial2":                              30,
  "fal2":                              30,
  "aal2":                              35,
  "urn:mace:incommon:iap:silver":      32,    // ACR rank, not bytes

  // Phishing-resistant multi-factor (passkey UV)
  "phrh":                              60,    // allow:raw-time-literal — ACR rank value 60; coincidental multiple-of-60, not a duration, C.TIME N/A

  // Hardware-bound + phishing-resistant + multi-factor
  "loa3":                              70,
  "high":                              70,
  "ial3":                              75,
  "fal3":                              75,
  "aal3":                              75,
  "urn:mace:incommon:iap:gold":        80,    // ACR rank, not bytes

  // In-person identity-proofed + hardware-bound
  "loa4":                              95,
};

// AMR catalog per RFC 8176 — used for requiredAmr policy evaluation.
// Each entry maps the canonical RFC 8176 short-form to a category that
// allows operators to evaluate broad classes (e.g. "any phishing-
// resistant method" → `category: "phishing-resistant"`).
var BUILTIN_AMR = {
  "face":   { category: "biometric",          phishingResistant: false },
  "fpt":    { category: "biometric",          phishingResistant: false },
  "geo":    { category: "context",            phishingResistant: false },
  "hwk":    { category: "hardware",           phishingResistant: true  },
  "iris":   { category: "biometric",          phishingResistant: false },
  "kba":    { category: "knowledge",          phishingResistant: false },
  "mca":    { category: "multi-channel",      phishingResistant: false },
  "mfa":    { category: "composite",          phishingResistant: false },
  "otp":    { category: "out-of-band",        phishingResistant: false },
  "pin":    { category: "knowledge",          phishingResistant: false },
  "pop":    { category: "proof-of-possession", phishingResistant: true },
  "pwd":    { category: "knowledge",          phishingResistant: false },
  "rba":    { category: "context",            phishingResistant: false },
  "retina": { category: "biometric",          phishingResistant: false },
  "sc":     { category: "smart-card",         phishingResistant: true  },
  "sms":    { category: "out-of-band",        phishingResistant: false },
  "swk":    { category: "software-key",       phishingResistant: false },
  "tel":    { category: "out-of-band",        phishingResistant: false },
  "user":   { category: "user-presence",      phishingResistant: false },
  "vbm":    { category: "biometric",          phishingResistant: false },
  "wia":    { category: "windows-integrated", phishingResistant: false },
};

// In-process registry — operators may extend (and re-extend) at boot.
var _registry = Object.create(null);
for (var k in BUILTIN_RANKS) {
  if (Object.prototype.hasOwnProperty.call(BUILTIN_RANKS, k)) {
    _registry[k] = BUILTIN_RANKS[k];
  }
}

function register(opts) {
  opts = opts || {};
  validateOpts(opts, ["value", "rank"], "auth.acr.register");
  validateOpts.requireNonEmptyString(opts.value, "register: value",
    AuthError, "auth-step-up/bad-acr");
  if (typeof opts.rank !== "number" || !isFinite(opts.rank)) {
    throw new AuthError("auth-step-up/bad-rank",
      "auth.acr.register: rank must be a finite number — got " +
      JSON.stringify(opts.rank));
  }
  if (opts.rank < 0 || opts.rank > 100) {
    throw new AuthError("auth-step-up/bad-rank",
      "auth.acr.register: rank must be in [0, 100] — got " + opts.rank);
  }
  _registry[opts.value] = opts.rank;
  return { value: opts.value, rank: opts.rank };
}

function rankOf(value) {
  if (typeof value !== "string" || value.length === 0) return -1;
  if (Object.prototype.hasOwnProperty.call(_registry, value)) {
    return _registry[value];
  }
  return -1;
}

function isRegistered(value) {
  return rankOf(value) !== -1;
}

function listRegistered() {
  var out = [];
  for (var k in _registry) {
    if (Object.prototype.hasOwnProperty.call(_registry, k)) {
      out.push({ value: k, rank: _registry[k] });
    }
  }
  out.sort(function (a, b) {
    if (a.rank !== b.rank) return a.rank - b.rank;
    if (a.value < b.value) return -1;
    if (a.value > b.value) return 1;
    return 0;
  });
  return out;
}

function meets(presented, required) {
  if (typeof required !== "string") return true;
  if (typeof presented !== "string") return false;
  var rp = rankOf(presented);
  var rr = rankOf(required);
  if (rr === -1) {
    throw new AuthError("auth-step-up/unknown-acr",
      "auth.acr.meets: required acr is not registered (call b.auth.acr.register first): " +
      JSON.stringify(required));
  }
  if (rp === -1) return false;
  return rp >= rr;
}

function meetsAny(presented, requiredList) {
  if (!Array.isArray(requiredList) || requiredList.length === 0) return true;
  for (var i = 0; i < requiredList.length; i += 1) {
    if (meets(presented, requiredList[i])) return true;
  }
  return false;
}

function _classifyAmr(amrValue) {
  if (typeof amrValue !== "string") return null;
  if (Object.prototype.hasOwnProperty.call(BUILTIN_AMR, amrValue)) {
    return BUILTIN_AMR[amrValue];
  }
  return null;
}

function amrIncludesPhishingResistant(amrList) {
  if (!Array.isArray(amrList)) return false;
  for (var i = 0; i < amrList.length; i += 1) {
    var info = _classifyAmr(amrList[i]);
    if (info && info.phishingResistant) return true;
  }
  return false;
}

function amrSatisfiesRequiredList(presentedAmr, required) {
  if (!Array.isArray(required) || required.length === 0) return true;
  if (!Array.isArray(presentedAmr)) return false;
  var seen = Object.create(null);
  for (var i = 0; i < presentedAmr.length; i += 1) {
    if (typeof presentedAmr[i] === "string") seen[presentedAmr[i]] = true;
  }
  for (var j = 0; j < required.length; j += 1) {
    if (!seen[required[j]]) return false;
  }
  return true;
}

// Reset hook — for tests only. Restores built-in registry.
function _resetForTests() {
  for (var k in _registry) {
    if (Object.prototype.hasOwnProperty.call(_registry, k)) delete _registry[k];
  }
  for (var bk in BUILTIN_RANKS) {
    if (Object.prototype.hasOwnProperty.call(BUILTIN_RANKS, bk)) {
      _registry[bk] = BUILTIN_RANKS[bk];
    }
  }
}

module.exports = {
  register:                       register,
  rankOf:                         rankOf,
  isRegistered:                   isRegistered,
  listRegistered:                 listRegistered,
  meets:                          meets,
  meetsAny:                       meetsAny,
  amrIncludesPhishingResistant:   amrIncludesPhishingResistant,
  amrSatisfiesRequiredList:       amrSatisfiesRequiredList,
  BUILTIN_RANKS:                  BUILTIN_RANKS,
  BUILTIN_AMR:                    BUILTIN_AMR,
  _resetForTests:                 _resetForTests,
};
