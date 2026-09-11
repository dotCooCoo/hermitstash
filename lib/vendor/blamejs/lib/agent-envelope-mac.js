// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");
var bCrypto = require("./crypto");

var vault = lazyRequire(function () { return require("./vault"); });

var AgentEnvelopeMacError = defineClass("AgentEnvelopeMacError", { alwaysPermanent: true });

var ENVELOPE_MAC_KEY_BYTES = 32;

var _macKeyCache = Object.create(null);

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

function sign(label, canonicalBytes) {
  var key = resolveKey(label);
  return nodeCrypto.createHmac("sha3-512", key).update(canonicalBytes).digest().toString("base64");
}

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
  _resetForTest:          function () { _macKeyCache = Object.create(null); },
};
