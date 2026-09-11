// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var lazyRequire     = require("./lazy-require");
var validateOpts    = require("./validate-opts");
var pick            = require("./pick");
var C               = require("./constants");
var { defineClass } = require("./framework-error");
var VaultAadError = defineClass("VaultAadError", { alwaysPermanent: true });

var bCrypto = lazyRequire(function () { return require("./crypto"); });
var vault  = lazyRequire(function () { return require("./vault"); });
var audit  = lazyRequire(function () { return require("./audit"); });

var AAD_PREFIX  = "vault.aad:";
var AAD_VERSION = 1;

function _canonicalize(parts) {
  if (!parts || typeof parts !== "object" || Array.isArray(parts)) {
    throw new VaultAadError("vault-aad/bad-aad",
      "AAD must be a plain object — got " + typeof parts);
  }
  var keys = Object.keys(parts).sort();          // allow:bare-canonicalize-walk — AEAD AAD canonicalization has its own length-prefixed contract
  if (keys.length === 0) {
    throw new VaultAadError("vault-aad/bad-aad",
      "AAD must have at least one field");
  }
  var chunks = [];
  chunks.push(Buffer.from([AAD_VERSION]));
  for (var i = 0; i < keys.length; i += 1) {
    var key = keys[i];
    if (pick.isPoisonedKey(key)) {
      throw new VaultAadError("vault-aad/bad-aad",
        "AAD field name " + JSON.stringify(key) + " is forbidden (poisoned key)");
    }
    if (typeof parts[key] !== "string" && typeof parts[key] !== "number" &&
        typeof parts[key] !== "boolean") {
      throw new VaultAadError("vault-aad/bad-aad",
        "AAD field " + JSON.stringify(key) + " must be string / number / boolean — got " +
        typeof parts[key]);
    }
    var keyBuf = Buffer.from(key, "utf8");
    var valBuf = Buffer.from(String(parts[key]), "utf8");
    var keyLenBuf = Buffer.alloc(2);
    keyLenBuf.writeUInt16BE(keyBuf.length);
    var valLenBuf = Buffer.alloc(4);
    valLenBuf.writeUInt32BE(valBuf.length);
    chunks.push(keyLenBuf, keyBuf, valLenBuf, valBuf);
  }
  return Buffer.concat(chunks);                  // allow:handrolled-buffer-collect-bounded-framing — AAD canonicalization, bounded by length-prefixed field shape
}

function buildColumnAad(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "table", "rowId", "column", "schemaVersion",
  ], "vault.aad.buildColumnAad");
  validateOpts.requireNonEmptyString(opts.table,
    "buildColumnAad: table", VaultAadError, "vault-aad/bad-aad");
  validateOpts.requireNonEmptyString(opts.column,
    "buildColumnAad: column", VaultAadError, "vault-aad/bad-aad");
  if (opts.rowId == null) {
    throw new VaultAadError("vault-aad/bad-aad",
      "buildColumnAad: rowId is required");
  }
  return {
    table:         opts.table,
    rowId:         String(opts.rowId),
    column:        opts.column,
    schemaVersion: opts.schemaVersion != null ? String(opts.schemaVersion) : "1",
  };
}

function buildContextAad(parts) {
  if (!parts || typeof parts !== "object" || Array.isArray(parts)) {
    throw new VaultAadError("vault-aad/bad-aad",
      "buildContextAad: parts must be a plain object");
  }
  var out = {};
  for (var k in parts) {
    if (!Object.prototype.hasOwnProperty.call(parts, k)) continue;
    if (pick.isPoisonedKey(k)) continue;
    if (parts[k] == null) continue;
    out[k] = parts[k];
  }
  if (Object.keys(out).length === 0) {
    throw new VaultAadError("vault-aad/bad-aad",
      "buildContextAad: at least one non-null field required");
  }
  return out;
}

function _deriveKey(aadBytes, rootKeysJson) {
  var keysJson = (typeof rootKeysJson === "string" && rootKeysJson.length > 0)
    ? rootKeysJson
    : vault().getKeysJson();
  var rootHash = bCrypto().sha3Hash(keysJson);
  var prefix   = Buffer.from("vault.aad/v1/", "utf8");
  var rootBuf  = Buffer.from(rootHash, "hex");
  var input    = Buffer.concat([prefix, rootBuf, aadBytes]);
  return bCrypto().kdf(input, C.BYTES.bytes(32));
}

function _seal(plaintext, aadParts, rootKeysJson, suppressAudit) {
  if (plaintext == null) {
    throw new VaultAadError("vault-aad/bad-input",
      "seal: plaintext is required (use null/undefined-stripping at the call site)");
  }
  if (typeof plaintext !== "string") plaintext = String(plaintext);
  if (plaintext.length === 0) {
    throw new VaultAadError("vault-aad/bad-input",
      "seal: plaintext must be non-empty");
  }
  if (plaintext.indexOf(AAD_PREFIX) === 0) {
    throw new VaultAadError("vault-aad/already-sealed",
      "seal: value is already AAD-sealed (refuses to double-seal)");
  }
  var aadBytes = _canonicalize(aadParts);
  var key = _deriveKey(aadBytes, rootKeysJson);
  var ptBuf = Buffer.from(plaintext, "utf8");
  var packed = bCrypto().encryptPacked(ptBuf, key, aadBytes);

  if (!suppressAudit) {
    try {
      audit().safeEmit({
        action:   "vault.aad.sealed",
        outcome:  "success",
        actor:    null,
        metadata: {
          aadKeys: Object.keys(aadParts).sort(),    // allow:bare-canonicalize-walk — audit-emit metadata, not for signing
          bytes:   ptBuf.length,
        },
      });
    } catch (_e) { /* drop-silent */ }
  }

  return AAD_PREFIX + packed.toString("base64");
}

function seal(plaintext, aadParts) {
  return _seal(plaintext, aadParts, undefined, false);
}

function _unseal(value, aadParts, rootKeysJson, suppressAudit) {
  if (value == null || typeof value !== "string") {
    throw new VaultAadError("vault-aad/bad-input",
      "unseal: value must be a non-empty string");
  }
  if (value.indexOf(AAD_PREFIX) !== 0) {
    throw new VaultAadError("vault-aad/not-sealed",
      "unseal: value is not AAD-sealed (missing " + JSON.stringify(AAD_PREFIX) + " prefix)");
  }
  var aadBytes = _canonicalize(aadParts);
  var key = _deriveKey(aadBytes, rootKeysJson);
  var packed;
  try { packed = Buffer.from(value.slice(AAD_PREFIX.length), "base64"); }
  catch (e) {
    throw new VaultAadError("vault-aad/bad-format",
      "unseal: base64 decode failed - " + e.message);
  }
  var pt;
  try { pt = bCrypto().decryptPacked(packed, key, aadBytes); }
  catch (e) {
    if (!suppressAudit) {
      try {
        audit().safeEmit({
          action:   "vault.aad.unseal_failed",
          outcome:  "denied",
          actor:    null,
          metadata: {
            aadKeys: Object.keys(aadParts).sort(),  // allow:bare-canonicalize-walk — audit-emit metadata, not for signing
            reason:  e.message,
          },
        });
      } catch (_e) { /* drop-silent */ }
    }
    throw new VaultAadError("vault-aad/aead-mismatch",
      "unseal: AEAD authentication failed — value may have been tampered, " +
      "copied from a different row, or sealed under different AAD");
  }
  return pt.toString("utf8");
}

function unseal(value, aadParts) {
  return _unseal(value, aadParts, undefined, false);
}

function isAadSealed(value) {
  return typeof value === "string" && value.indexOf(AAD_PREFIX) === 0;
}

function reseal(value, fromAad, toAad) {
  var plaintext = unseal(value, fromAad);
  return seal(plaintext, toAad);
}

function sealRoot(plaintext, aadParts, rootKeysJson) {
  if (typeof rootKeysJson !== "string" || rootKeysJson.length === 0) {
    throw new VaultAadError("vault-aad/bad-root", "sealRoot: rootKeysJson (vault keys JSON) is required");
  }
  return _seal(plaintext, aadParts, rootKeysJson, true);
}

function unsealRoot(value, aadParts, rootKeysJson) {
  if (typeof rootKeysJson !== "string" || rootKeysJson.length === 0) {
    throw new VaultAadError("vault-aad/bad-root", "unsealRoot: rootKeysJson (vault keys JSON) is required");
  }
  return _unseal(value, aadParts, rootKeysJson, true);
}

function resealRoot(value, aadParts, oldRootJson, newRootJson) {
  var plaintext = unsealRoot(value, aadParts, oldRootJson);
  return sealRoot(plaintext, aadParts, newRootJson);
}

module.exports = {
  seal:               seal,
  unseal:             unseal,
  reseal:             reseal,
  sealRoot:           sealRoot,
  unsealRoot:         unsealRoot,
  resealRoot:         resealRoot,
  isAadSealed:        isAadSealed,
  buildColumnAad:     buildColumnAad,
  buildContextAad:    buildContextAad,
  canonicalizeAad:    _canonicalize,
  AAD_PREFIX:         AAD_PREFIX,
  AAD_VERSION:        AAD_VERSION,
  VaultAadError:      VaultAadError,
};
