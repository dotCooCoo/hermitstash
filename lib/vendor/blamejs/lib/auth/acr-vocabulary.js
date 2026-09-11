// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

var BUILTIN_RANKS = {
  "0":                                 0,

  "1":                                 10,
  "loa1":                              10,
  "low":                               10,
  "ial1":                              10,
  "fal1":                              10,
  "aal1":                              10,
  "urn:mace:incommon:iap:bronze":      12,

  "phr":                               25,

  "2":                                 30,
  "loa2":                              30,
  "substantial":                       30,
  "ial2":                              30,
  "fal2":                              30,
  "aal2":                              35,
  "urn:mace:incommon:iap:silver":      32,

  "phrh":                              60,    // allow:raw-time-literal — ACR rank value 60; coincidental multiple-of-60, not a duration, C.TIME N/A

  "loa3":                              70,
  "high":                              70,
  "ial3":                              75,
  "fal3":                              75,
  "aal3":                              75,
  "urn:mace:incommon:iap:gold":        80,

  "loa4":                              95,
};

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
