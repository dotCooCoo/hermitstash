// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.vault.aad — AAD-bound sealed-column primitive.
 *
 * `b.vault.seal(plaintext)` produces a ciphertext that decrypts back
 * to the same plaintext regardless of WHICH row / column / table the
 * value was sealed for. An attacker with write access to the database
 * (or an audit-log replay) can copy a sealed value from a benign row
 * (e.g. their own user record) into a sensitive row (e.g. another
 * user's PII column), and the value decrypts cleanly. Application
 * code that gates on the field's value alone won't notice.
 *
 * AAD-bound sealed columns close that gap. The seal binds to an
 * Additional Authenticated Data tuple (table, rowId, column,
 * schemaVersion) so the AEAD tag fails on any decrypt where the AAD
 * differs — copy-paste, replay, schema-version-rollback all surface
 * as a refused decrypt.
 *
 * Public surface (b.vault.aad.*):
 *
 *   .seal(plaintext, aadParts)
 *     → "vault.aad:<base64>"  (refuses null/undefined)
 *
 *   .unseal(value, aadParts)
 *     → plaintext             (throws on AEAD mismatch)
 *
 *   .buildColumnAad({ table, rowId, column, schemaVersion })
 *     → canonical-form string suitable for seal/unseal
 *
 *   .buildContextAad(parts)
 *     → canonical-form string from arbitrary { field: value } parts;
 *       sorted-keys + length-prefixed encoding so two callers with
 *       the same logical context always produce the same AAD bytes.
 *
 *   .isAadSealed(value) → boolean
 *
 * Per the framework's security-first stance:
 *   - Symmetric key derivation uses SHAKE256 (matching the vault's
 *     KDF) over the vault root key concatenated with the
 *     canonicalized AAD.
 *   - AEAD: XChaCha20-Poly1305 with the AAD threaded into the tag.
 *   - 24-byte nonce, generated fresh per-seal via
 *     b.crypto.generateBytes — collision probability negligible.
 *
 * The vault must be initialized before sealAad / unsealAad — same
 * post-init contract as plain `vault.seal`.
 */

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

// ---- Canonical AAD construction ----
//
// AAD bytes MUST be deterministic for any two calls describing the
// same logical context (same table, same row, same column, same
// schemaVersion). Sorted-keys + length-prefixed encoding gets us
// determinism regardless of the operator's iteration order.

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

// ---- key derivation ----
//
// Per-row symmetric key = SHAKE256("vault.aad/v1/" || rootKey || aadBytes,
// 32 bytes). Constant-domain prefix prevents key collision with other
// uses of the vault root.

function _deriveKey(aadBytes, rootKeysJson) {
  // rootKeysJson lets the vault-key rotation pipeline derive the per-row
  // key under a SPECIFIC vault root (old or new keypair) within one
  // process; when omitted it uses the live singleton. The keys JSON
  // includes the active keypair PEMs — hashing the whole serialized form
  // gives a stable per-vault root secret. Rotating vault keys produces a
  // different root, so prior AAD-sealed values must be re-sealed (the
  // rotation pipeline walks them via sealRoot/unsealRoot/resealRoot).
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

// Operator-side helper: re-seal a value from one AAD context to
// another (used when migrating row IDs, schema version bumps, etc.).
// Authenticates the source AAD before producing the new ciphertext —
// no key material exposed.
function reseal(value, fromAad, toAad) {
  var plaintext = unseal(value, fromAad);
  return seal(plaintext, toAad);
}

// ---- explicit-root variants (vault-key rotation pipeline) ----
//
// The rotation pipeline must decrypt a cell under the OLD vault root and
// re-encrypt it under the NEW root within one process — the live-singleton
// _deriveKey cannot straddle two keypairs. These take the serialized vault
// keys JSON (b.vault.getKeysJson() output) for a specific root; the AAD
// tuple is unchanged, only the root differs. Per-cell audit is suppressed
// (the rotation pipeline has its own progress + verify reporting).

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

// Re-seal a value from the old root to the new root under the SAME AAD
// tuple: authenticate under the old root (throws aead-mismatch if the
// value was not sealed under oldRootJson + aadParts), then re-encrypt
// under the new root. The rotation pipeline composes this per cell.
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
  // canonicalizeAad — the length-prefixed, sorted-keys AAD-bytes
  // encoder. Exported (internal) so a sibling primitive that runs its
  // own AEAD (crypto-field's per-row K_row cells) threads byte-identical
  // AAD into encryptPacked/decryptPacked as this module does for its
  // own seal/unseal — one canonical encoder, no drift.
  canonicalizeAad:    _canonicalize,
  AAD_PREFIX:         AAD_PREFIX,
  AAD_VERSION:        AAD_VERSION,
  VaultAadError:      VaultAadError,
};
