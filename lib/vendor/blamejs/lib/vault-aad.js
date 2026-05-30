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
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
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
  return Buffer.concat(chunks);                  // allow:handrolled-buffer-collect — AAD canonicalization, bounded by length-prefixed field shape
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
    if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
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

function _deriveKey(aadBytes) {
  var keysJson = vault().getKeysJson();
  // The vault keys JSON includes the active keypair PEMs. We hash the
  // whole serialized form to get a stable per-vault root secret —
  // this is a deterministic derivation; rotating vault keys produces
  // a different root and breaks all prior AAD-sealed values (operator
  // intent: rotation = re-seal).
  var rootHash = bCrypto().sha3Hash(keysJson);
  var prefix   = Buffer.from("vault.aad/v1/", "utf8");
  var rootBuf  = Buffer.from(rootHash, "hex");
  var input    = Buffer.concat([prefix, rootBuf, aadBytes]);
  return bCrypto().kdf(input, C.BYTES.bytes(32));
}

function seal(plaintext, aadParts) {
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
  var key = _deriveKey(aadBytes);
  var ptBuf = Buffer.from(plaintext, "utf8");
  var packed = bCrypto().encryptPacked(ptBuf, key, aadBytes);

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

  return AAD_PREFIX + packed.toString("base64");
}

function unseal(value, aadParts) {
  if (value == null || typeof value !== "string") {
    throw new VaultAadError("vault-aad/bad-input",
      "unseal: value must be a non-empty string");
  }
  if (value.indexOf(AAD_PREFIX) !== 0) {
    throw new VaultAadError("vault-aad/not-sealed",
      "unseal: value is not AAD-sealed (missing " + JSON.stringify(AAD_PREFIX) + " prefix)");
  }
  var aadBytes = _canonicalize(aadParts);
  var key = _deriveKey(aadBytes);
  var packed;
  try { packed = Buffer.from(value.slice(AAD_PREFIX.length), "base64"); }
  catch (e) {
    throw new VaultAadError("vault-aad/bad-format",
      "unseal: base64 decode failed - " + e.message);
  }
  var pt;
  try { pt = bCrypto().decryptPacked(packed, key, aadBytes); }
  catch (e) {
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
    throw new VaultAadError("vault-aad/aead-mismatch",
      "unseal: AEAD authentication failed — value may have been tampered, " +
      "copied from a different row, or sealed under different AAD");
  }
  return pt.toString("utf8");
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

module.exports = {
  seal:               seal,
  unseal:             unseal,
  reseal:             reseal,
  isAadSealed:        isAadSealed,
  buildColumnAad:     buildColumnAad,
  buildContextAad:    buildContextAad,
  AAD_PREFIX:         AAD_PREFIX,
  AAD_VERSION:        AAD_VERSION,
  VaultAadError:      VaultAadError,
};
