// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.cryptoField
 * @nav    Crypto
 * @title  Field-Level Crypto
 *
 * @intro
 *   Per-column field-level encryption with AAD-bound envelopes. Apps
 *   declare which columns hold PHI / PCI / personal data via
 *   `b.db.init({ schema })`; the framework then auto-protects those
 *   columns on every write (`sealRow`) and reverses on every read
 *   (`unsealRow`). Sealed values are produced by `b.vault.seal`, which
 *   wraps an XChaCha20-Poly1305 ciphertext under the framework's PQC
 *   envelope (ML-KEM + ECDH hybrid) — every encryption uses a fresh
 *   random nonce, so two seals of the same plaintext never collide.
 *
 *   Per-row key (K_row) derivation is opt-in via `declarePerRowKey`.
 *   Tables that opt in get a fresh K_row per INSERT: the framework
 *   generates a 32-byte CSPRNG row-secret, derives
 *   `K_row = SHAKE256(rowSecret || ":" || table || ":" || rowId || ":"
 *   || info)`, and stores the SECRET (never K_row) AAD-sealed in
 *   `_blamejs_per_row_keys.wrappedKey`. Because the secret is random —
 *   not a function of any on-disk salt — an attacker with full disk
 *   access cannot re-derive K_row once the wrapped secret is gone. The
 *   AAD on the wrap binds (table, rowId, column, schemaVersion):
 *   copying a wrapped secret from one row to another fails Poly1305
 *   verification, so a DB-write attacker cannot move it between rows to
 *   bypass row-scoped erasure. Sealed columns on a keyed row carry the
 *   `vault.row:` prefix and are XChaCha20-Poly1305 ciphertext under
 *   K_row, AEAD-bound to the same (table, rowId, column) tuple. This is
 *   the crypto-shred substrate for `b.subject.eraseHard` /
 *   `b.retention`: destroying the wrapped secret leaves WAL / replica
 *   residual ciphertext mathematically undecryptable — even with the
 *   vault root key — because K_row is gone everywhere it ever lived.
 *
 *   Derived hashes (`derivedHashes`) provide indexed lookup for sealed
 *   columns. The default digest is a keyed MAC
 *   (`hmac-shake256`: SHAKE256 under the vault's per-deployment MAC key) +
 *   a per-field namespace, so an attacker who recovers the salt alone
 *   cannot correlate low-entropy plaintexts across fields or across
 *   deployments. Operators keeping byte-compatibility with an existing
 *   salted index opt out per-table (`derivedHashMode: "salted-sha3"`) or
 *   per-column (`derivedHashes.<col>.mode`). Sealed columns without a
 *   derived hash are unindexable — queries on them silently return zero
 *   rows.
 *
 *   Per-column residency (`declareColumnResidency`) declares EU / US /
 *   global tags; the storage-write gate (`assertColumnResidency`)
 *   refuses writes to a backend whose tag doesn't satisfy the column
 *   under gdpr / dpdp / pipl-cn / uk-gdpr postures.
 *
 *   No mutation of the input row — every operation returns a new
 *   object, suitable for direct insertion into the audit chain.
 *
 * @card
 *   Per-column field-level encryption with AAD-bound envelopes.
 */
var lazyRequire = require("./lazy-require");
var boundedMap = require("./bounded-map");
var vault = require("./vault");
var vaultAad = require("./vault-aad");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var safeJson = require("./safe-json");
var sql = require("./sql");
var { defineClass } = require("./framework-error");
var { sha3Hash, kdf, generateBytes, encryptPacked, decryptPacked, generateToken } = require("./crypto");
var { HASH_PREFIX, VAULT_PREFIX, ROW_PREFIX, TIME } = require("./constants");

var CryptoFieldRateError = defineClass("CryptoFieldRateError", { alwaysPermanent: true });
var CryptoFieldError     = defineClass("CryptoFieldError", { alwaysPermanent: true });

var TYPED_SENTINEL = String.fromCharCode(0) + "bjsv1:";

function _encodeTyped(value) {
  if (typeof value === "string") {
    if (value === "") return TYPED_SENTINEL + "E:";
    return value.indexOf(TYPED_SENTINEL) === 0 ? TYPED_SENTINEL + "S:" + value : value;
  }
  if (Buffer.isBuffer(value)) return TYPED_SENTINEL + "B:" + value.toString("base64");
  if (value instanceof Uint8Array) return TYPED_SENTINEL + "B:" + Buffer.from(value).toString("base64");
  if (typeof value === "object" && value !== null) return TYPED_SENTINEL + "J:" + JSON.stringify(value);
  return String(value);
}

function _decodeTyped(str) {
  if (typeof str !== "string" || str.indexOf(TYPED_SENTINEL) !== 0) return str;
  var body = str.slice(TYPED_SENTINEL.length);
  var tag = body.slice(0, 2);
  var payload = body.slice(2);
  if (tag === "E:") return "";
  if (tag === "B:") return Buffer.from(payload, "base64");
  if (tag === "J:") return safeJson.parse(payload);
  if (tag === "S:") return payload;
  return str;
}

var compliance    = lazyRequire(function () { return require("./compliance"); });
var db            = lazyRequire(function () { return require("./db"); });
var audit         = lazyRequire(function () { return require("./audit"); });

var _activePosture = null;

/**
 * @primitive b.cryptoField.applyPosture
 * @signature b.cryptoField.applyPosture(posture)
 * @since     0.7.27
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.getActivePosture, b.cryptoField.eraseRow
 *
 * Records the active compliance posture so `eraseRow` can cascade into
 * `b.db.vacuumAfterErase({ mode: "full" })` under regimes whose
 * `POSTURE_DEFAULTS` sets `requireVacuumAfterErase: true` (gdpr / dpdp /
 * pipl-cn / lgpd-br / hipaa). Without the vacuum, freed B-tree index
 * pages keep sealed-column ciphertext readable from a forensic disk
 * image — defeating the "right to erasure" the regime guarantees.
 * Returns null when posture is empty/non-string; otherwise returns
 * `{ posture, requireVacuumAfterErase }`.
 *
 * @example
 *   var info = b.cryptoField.applyPosture("gdpr");
 *   info.posture;                   // → "gdpr"
 *   info.requireVacuumAfterErase;   // → true
 *
 *   b.cryptoField.applyPosture("");   // → null (no-op)
 */
function applyPosture(posture) {
  if (typeof posture !== "string" || posture.length === 0) return null;
  _activePosture = posture;
  var requireVacuum = false;
  try {
    requireVacuum = compliance().postureDefault(posture, "requireVacuumAfterErase") === true;
  } catch (_e) { /* compliance not loaded — record posture only */ }
  return { posture: posture, requireVacuumAfterErase: requireVacuum };
}

/**
 * @primitive b.cryptoField.getActivePosture
 * @signature b.cryptoField.getActivePosture()
 * @since     0.7.27
 * @related   b.cryptoField.applyPosture
 *
 * Returns the posture string most recently recorded via `applyPosture`,
 * or null when no posture has been applied. Read-only — does not
 * mutate state. Used by storage backends to gate cross-border writes.
 *
 * @example
 *   b.cryptoField.applyPosture("hipaa");
 *   b.cryptoField.getActivePosture();   // → "hipaa"
 */
function getActivePosture() { return _activePosture; }

var schemas = Object.create(null);

var columnResidency = Object.create(null);
var perRowResidency = Object.create(null);

var perRowKeyTables = Object.create(null);

var SEAL_ENVELOPE_RANK = Object.freeze({
  "plain":       0,
  "aad":         1,
  "per-row-key": 2,
});

// through. allow:hand-rolled-sql — canonical logical-name declaration.
var PER_ROW_KEYS_TABLE = "_blamejs_per_row_keys";   // allow:hand-rolled-sql
var PER_ROW_KEYS_COLUMN = "wrappedKey";
var PER_ROW_KEYS_SCHEMA_VERSION = "1";

var _PER_ROW_SQL_OPTS = { dialect: "sqlite", quoteName: true };
function _perRowKeysTableName() {
  return PER_ROW_KEYS_TABLE;
}

function _wrappedKeyAad(rowId) {
  return vaultAad.buildColumnAad({
    table:         PER_ROW_KEYS_TABLE,
    rowId:         rowId,
    column:        PER_ROW_KEYS_COLUMN,
    schemaVersion: PER_ROW_KEYS_SCHEMA_VERSION,
  });
}

function _rowCellAad(schema, table, column, rowId) {
  return vaultAad.buildColumnAad({
    table:         table,
    rowId:         rowId,
    column:        column,
    schemaVersion: (schema && schema.schemaVersion) || "1",
  });
}

function _aadBytes(parts) {
  return vaultAad.canonicalizeAad(parts);
}

/**
 * @primitive b.cryptoField.isRowSealed
 * @signature b.cryptoField.isRowSealed(value)
 * @since     0.14.25
 * @related   b.cryptoField.sealRow, b.cryptoField.unsealRow
 *
 * Returns `true` when `value` is a string carrying the per-row-key
 * sealed-cell prefix (`vault.row:`), `false` otherwise. The row-keyed
 * sibling of `b.vault.aad.isAadSealed` — the read path uses it to route
 * a cell to its K_row decrypt instead of the vault-root unseal.
 *
 * @example
 *   b.cryptoField.isRowSealed("vault.row:AAAA");   // → true
 *   b.cryptoField.isRowSealed("vault:AAAA");        // → false
 *   b.cryptoField.isRowSealed(null);                // → false
 */
function isRowSealed(value) {
  return typeof value === "string" && value.indexOf(ROW_PREFIX) === 0;
}

/**
 * @primitive b.cryptoField.registerTable
 * @signature b.cryptoField.registerTable(name, opts)
 * @since     0.4.0
 * @related   b.cryptoField.getSchema, b.cryptoField.sealRow
 *
 * Registers a table's sealed-column declaration. Called from
 * `b.db.init({ schema })` at boot — operators rarely call directly.
 * Stores the per-table list of sealed fields, the derived-hash specs
 * (mapping `derivedField -> { from, normalize }`), and any per-field
 * hash namespaces. Subsequent `sealRow` / `unsealRow` / `eraseRow`
 * calls dispatch through this registry.
 *
 * Seal-envelope floor: when a compliance posture that declares a
 * `sealEnvelopeFloor` is globally pinned (`b.compliance.set` — today
 * `hipaa` / `pci-dss` require at least an AAD-bound envelope), a table
 * that seals columns under a weaker envelope throws
 * `crypto-field/seal-envelope-below-floor` here at registration so the
 * operator catches the under-protected schema at boot. Unpinned and
 * non-regulated deployments register unchanged.
 *
 * @opts
 *   sealedFields:   string[],              // column names sealed via vault.seal
 *   derivedHashes:  { [hashCol]: { from: string, normalize?: fn } },
 *   hashNamespaces: { [field]: string },   // override default rainbow-defense ns
 *   aad:            boolean,               // when true, route seal/unseal through
 *                                          // b.vault.aad — AEAD-binds the ciphertext
 *                                          // to (table, rowIdField=primary key, column)
 *                                          // so a DB-write attacker can't copy a
 *                                          // sealed value between rows.
 *   rowIdField:     string,                // when aad=true, the column name carrying
 *                                          // the row identity. Default "id". The row
 *                                          // passed to sealRow MUST already have this
 *                                          // column populated; sealRow refuses when
 *                                          // missing (an AAD bound to a placeholder
 *                                          // would silently fail every unseal).
 *   schemaVersion:  string|number,         // when aad=true, the schema version
 *                                          // threaded into AAD. Default "1". Bump
 *                                          // when the column layout changes to
 *                                          // invalidate all prior ciphertext.
 *   allowPlainMigration: boolean,          // default false. On an aad / per-row-key
 *                                          // table the read path refuses a PLAIN
 *                                          // (unbound) vault: cell — a relocatable
 *                                          // envelope an attacker could copy in from
 *                                          // another row defeats the AAD copy-
 *                                          // protection, so it is nulled, not surfaced.
 *                                          // Set true ONLY for the bounded window while
 *                                          // migrating pre-AAD rows up to AAD-bound
 *                                          // ciphertext; clear it once migration ends.
 *
 * @example
 *   b.cryptoField.registerTable("patients", {
 *     sealedFields: ["ssn", "diagnosis"],
 *     derivedHashes: {
 *       ssnHash: { from: "ssn", normalize: function (s) { return String(s).replace(/-/g, ""); } }
 *     }
 *   });
 *   b.cryptoField.getSealedFields("patients");   // → ["ssn", "diagnosis"]
 *
 *   // AAD-bound table (recommended for new schemas).
 *   b.cryptoField.registerTable("idempotency_keys", {
 *     sealedFields: ["headers", "body"],
 *     aad:          true,
 *     rowIdField:   "k",       // primary key column
 *   });
 */
function registerTable(name, opts) {
  var aadOn = opts.aad === true;
  var rowIdField = typeof opts.rowIdField === "string" && opts.rowIdField.length > 0
    ? opts.rowIdField : "id";
  var schemaVersion = opts.schemaVersion != null ? String(opts.schemaVersion) : "1";
  var derivedHashMode = opts.derivedHashMode || "hmac-shake256";
  if (derivedHashMode !== "salted-sha3" && derivedHashMode !== "hmac-shake256") {
    throw new CryptoFieldError("crypto-field/bad-derived-hash-mode",
      "registerTable: derivedHashMode must be 'hmac-shake256' (default) or " +
      "'salted-sha3', got " + JSON.stringify(derivedHashMode));
  }
  var derivedHashes = Object.assign({}, opts.derivedHashes || {});
  for (var col in derivedHashes) {
    if (!Object.prototype.hasOwnProperty.call(derivedHashes, col)) continue;
    var colMode = derivedHashes[col] && derivedHashes[col].mode;
    if (colMode !== undefined && colMode !== "salted-sha3" && colMode !== "hmac-shake256") {
      throw new CryptoFieldError("crypto-field/bad-derived-hash-col-mode",
        "registerTable: derivedHashes." + col + ".mode must be " +
        "'salted-sha3' or 'hmac-shake256', got " + JSON.stringify(colMode));
    }
  }
  var sealedFields = Array.isArray(opts.sealedFields) ? opts.sealedFields.slice() : [];
  if (sealedFields.length > 0) {
    _assertSealEnvelopeFloor(name, aadOn);
  }
  schemas[name] = {
    sealedFields:    sealedFields,
    derivedHashes:   derivedHashes,
    hashNamespaces:  Object.assign({}, opts.hashNamespaces || {}),
    aad:             aadOn,
    rowIdField:      rowIdField,
    schemaVersion:   schemaVersion,
    derivedHashMode: derivedHashMode,
    allowPlainMigration: opts.allowPlainMigration === true,
  };
}

function _assertSealEnvelopeFloor(table, aadOn) {
  var posture;
  var floor;
  try {
    var c = compliance();
    posture = c.current();
    if (typeof posture !== "string" || posture.length === 0) return;
    floor = c.postureDefault(posture, "sealEnvelopeFloor");
  } catch (_e) {
    return;
  }
  if (typeof floor !== "string" || !Object.prototype.hasOwnProperty.call(SEAL_ENVELOPE_RANK, floor)) {
    return;
  }
  var declared = perRowKeyTables[table] ? "per-row-key" : (aadOn ? "aad" : "plain");
  if (SEAL_ENVELOPE_RANK[declared] < SEAL_ENVELOPE_RANK[floor]) {
    throw new CryptoFieldError("crypto-field/seal-envelope-below-floor",
      "registerTable: table '" + table + "' seals columns under the '" +
      declared + "' envelope, but the pinned compliance posture '" +
      posture + "' requires at least '" + floor + "'. " +
      (floor === "aad"
        ? "Pass registerTable({ aad: true, rowIdField: <pk> }) so each " +
          "cell is AEAD-bound to (table, row, column) and cannot be " +
          "relocated between rows"
        : "Call b.cryptoField.declarePerRowKey('" + table + "', ...) " +
          "before registerTable so each row gets a crypto-shred K_row") +
      " (CWE-311 / CWE-326). Unpinned or non-regulated deployments are " +
      "unaffected; this gate fires only under a posture that declares a " +
      "sealEnvelopeFloor.");
  }
}

var DERIVED_HASH_BYTES = 32;

function _computeDerivedHash(spec, tableMode, ns, normalized) {
  var mode = _resolveDerivedHashMode(spec, tableMode);
  if (mode === "hmac-shake256") {
    var macKey = vault.getDerivedHashMacKey();
    return kdf(Buffer.concat([macKey, Buffer.from(ns + normalized, "utf8")]),
      DERIVED_HASH_BYTES).toString("hex");
  }
  return _legacyDerivedHash(ns, normalized);
}

function _resolveDerivedHashMode(spec, tableMode) {
  return (spec && spec.mode) || tableMode || "salted-sha3";
}

function _legacyDerivedHash(ns, normalized) {
  return sha3Hash(vault.getDerivedHashSalt().toString("hex") + ns + normalized);
}

/**
 * @primitive b.cryptoField.computeNamespacedHash
 * @signature b.cryptoField.computeNamespacedHash(ns, value, opts?)
 * @since     0.14.10
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.computeDerived, b.cryptoField.lookupHash
 *
 * Computes a namespaced indexed-lookup digest of `value` for a
 * pseudo-field that is NOT backed by a registered derived-hash column
 * (e.g. the sealed-token FTS index in `b.mailStore.fts`). The caller
 * supplies the full namespace string directly — there is no schema
 * lookup — so the same keyed/salted hash machinery that protects
 * registered derived hashes also covers ad-hoc indexed tokens. This is
 * the canonical entry point: hand-rolling
 * `sha3Hash(vault.getDerivedHashSalt() + ns + value)` at a call site
 * bypasses the keyed-MAC mode (`hmac-shake256` off
 * `vault.getDerivedHashMacKey`) and the per-deployment salt policy.
 *
 * `opts.mode` selects the digest:
 *   - `"salted-sha3"` (default): SHA3-512 over `<salt-hex> + ns + value`
 *     (deterministic per deployment; byte-identical to the legacy
 *     hand-rolled scheme).
 *   - `"hmac-shake256"`: SHAKE256(`<vault MAC key> || ns + value`) — a
 *     keyed MAC so an attacker who recovers the salt alone cannot
 *     correlate two low-entropy plaintexts.
 *
 * `opts.truncateBytes` truncates the hex digest to that many BYTES
 * (the hex string is sliced to `truncateBytes * 2` characters). Throws
 * (config-time / entry-point tier) on an unknown `mode` or a
 * non-positive-integer `truncateBytes` so an operator catches the typo
 * at boot rather than silently indexing under a malformed digest.
 *
 * @opts
 *   mode:          string,   // "salted-sha3" (default) | "hmac-shake256"
 *   truncateBytes: number,   // optional; positive integer byte width to slice to
 *
 * @example
 *   var ns = "bj-mail_messages-body:fts:";
 *   var h = b.cryptoField.computeNamespacedHash(ns, "kubernetes", {
 *     mode: "hmac-shake256", truncateBytes: 8
 *   });
 *   /^[0-9a-f]{16}$/.test(h);   // → true
 *
 *   // Default mode is byte-identical to the legacy salted-sha3 hash.
 *   b.cryptoField.computeNamespacedHash(ns, "kubernetes").length;   // → 128
 */
function computeNamespacedHash(ns, value, opts) {
  opts = opts || {};
  var mode = opts.mode || "salted-sha3";
  if (mode !== "salted-sha3" && mode !== "hmac-shake256") {
    throw new CryptoFieldError("crypto-field/bad-namespaced-hash-mode",
      "computeNamespacedHash: opts.mode must be 'salted-sha3' " +
      "(default) or 'hmac-shake256', got " + JSON.stringify(mode));
  }
  var truncateBytes = opts.truncateBytes;
  numericBounds.requirePositiveFiniteIntIfPresent(truncateBytes,
    "computeNamespacedHash: opts.truncateBytes", CryptoFieldError,
    "crypto-field/bad-truncate-bytes");
  var hex = _computeDerivedHash({ mode: mode }, mode, ns, String(value));
  if (truncateBytes !== undefined) {
    return hex.slice(0, truncateBytes * 2);
  }
  return hex;
}

/**
 * @primitive b.cryptoField.getSchema
 * @signature b.cryptoField.getSchema(table)
 * @since     0.4.0
 * @related   b.cryptoField.registerTable, b.cryptoField.getSealedFields
 *
 * Returns the registered schema record for `table` — `{ sealedFields,
 * derivedHashes, hashNamespaces }` — or null when the table was never
 * registered. Read-only; mutations to the returned object do not
 * affect future calls (the inner arrays/objects are shared, so
 * operators should treat the result as read-only).
 *
 * @example
 *   b.cryptoField.registerTable("patients", { sealedFields: ["ssn"] });
 *   var schema = b.cryptoField.getSchema("patients");
 *   schema.sealedFields;   // → ["ssn"]
 *
 *   b.cryptoField.getSchema("unknown");   // → null
 */
function getSchema(table) {
  return schemas[table] || null;
}

/**
 * @primitive b.cryptoField.getSealedFields
 * @signature b.cryptoField.getSealedFields(table)
 * @since     0.4.0
 * @related   b.cryptoField.getSchema, b.cryptoField.sealRow
 *
 * Returns the array of sealed column names for `table`, or an empty
 * array when the table is unregistered. Convenience accessor used by
 * storage backends to know which columns to wrap in `vault.seal` on
 * write and `vault.unseal` on read.
 *
 * @example
 *   b.cryptoField.registerTable("patients", { sealedFields: ["ssn", "diagnosis"] });
 *   b.cryptoField.getSealedFields("patients");   // → ["ssn", "diagnosis"]
 *   b.cryptoField.getSealedFields("public");     // → []
 */
function getSealedFields(table) {
  var s = schemas[table];
  return s ? s.sealedFields : [];
}

/**
 * @primitive b.cryptoField.clearForTest
 * @signature b.cryptoField.clearForTest()
 * @since     0.4.0
 * @status    experimental
 * @related   b.cryptoField.registerTable
 *
 * Test-only helper. Drops every entry from the per-table schema
 * registry so a test fixture can re-register tables under different
 * sealed-field declarations between cases. Operator code never calls
 * this — production schemas come from `b.db.init({ schema })` once at
 * boot.
 *
 * @example
 *   b.cryptoField.registerTable("patients", { sealedFields: ["ssn"] });
 *   b.cryptoField.clearForTest();
 *   b.cryptoField.getSchema("patients");   // → null
 */
function clearForTest() {
  for (var k in schemas) delete schemas[k];
}

function namespaceFor(table, field, registered) {
  if (registered && registered[field]) return registered[field];
  var fieldUpper = field.toUpperCase();
  if (HASH_PREFIX[fieldUpper]) return HASH_PREFIX[fieldUpper];
  return "bj-" + table + "-" + field + ":";
}

/**
 * @primitive b.cryptoField.computeDerived
 * @signature b.cryptoField.computeDerived(table, sourceField, sourceValue)
 * @since     0.4.0
 * @related   b.cryptoField.lookupHash, b.cryptoField.sealRow
 *
 * Computes the derived hash for a (table, sourceField) pair when the
 * schema declares a derived-hash mirror of that source. Returns
 * `{ field, value }` naming the derived column and its hash, or null
 * when no derived hash is declared. Hashes are SHA3 of
 * `vaultSalt + namespace + normalizedValue`, where the per-deployment
 * vault salt prevents cross-deployment correlation and the per-field
 * namespace prevents cross-field rainbow attacks.
 *
 * @example
 *   b.cryptoField.registerTable("users", {
 *     sealedFields: ["email"],
 *     derivedHashes: { emailHash: { from: "email" } }
 *   });
 *   var d = b.cryptoField.computeDerived("users", "email", "alice@example.com");
 *   d.field;          // → "emailHash"
 *   typeof d.value;   // → "string"
 *
 *   b.cryptoField.computeDerived("users", "email", null);   // → null
 */
function _derivedHashResult(s, table, derivedField, spec, sourceField, value) {
  var ns = namespaceFor(table, sourceField, s.hashNamespaces);
  var normalized = spec.normalize ? spec.normalize(value) : String(value);
  var mode = _resolveDerivedHashMode(spec, s.derivedHashMode);
  var primary = _computeDerivedHash(spec, s.derivedHashMode, ns, normalized);
  var out = { field: derivedField, value: primary };
  if (mode === "hmac-shake256") {
    var legacy = _legacyDerivedHash(ns, normalized);
    if (legacy !== primary) out.legacyValue = legacy;
  }
  return out;
}

function computeDerived(table, sourceField, sourceValue) {
  if (sourceValue === undefined || sourceValue === null) return null;
  var s = schemas[table];
  if (!s || !s.derivedHashes) return null;

  for (var derivedField in s.derivedHashes) {
    var spec = s.derivedHashes[derivedField];
    if (spec.from === sourceField) {
      return _derivedHashResult(s, table, derivedField, spec, sourceField, sourceValue);
    }
  }
  return null;
}

var DEFAULT_RATE_CAP_THRESHOLD  = 10;
var DEFAULT_RATE_CAP_WINDOW_MS  = TIME.minutes(1);
var DEFAULT_RATE_CAP_COOLDOWN_MS = TIME.minutes(5);
var _rateCap = null;
var _rateFailWindows = new Map();
var _rateCooldowns = new Map();

function _defaultRateCapRecord() {
  return {
    threshold:  DEFAULT_RATE_CAP_THRESHOLD,
    windowMs:   DEFAULT_RATE_CAP_WINDOW_MS,
    cooldownMs: DEFAULT_RATE_CAP_COOLDOWN_MS,
    now:        function () { return Date.now(); },
    onAudit:    null,
  };
}
function _installDefaultRateCap() {
  _rateCap = _defaultRateCapRecord();
  _rateFailWindows.clear();
  _rateCooldowns.clear();
}
_installDefaultRateCap();

function _rateKey(actor, table, column) {
  return String(actor) + "\x00" + table + "\x00" + column;
}

/**
 * @primitive b.cryptoField.configureUnsealRateCap
 * @signature b.cryptoField.configureUnsealRateCap(opts)
 * @since     0.14.20
 * @compliance hipaa, gdpr, pci-dss
 * @related   b.cryptoField.unsealRow, b.cryptoField.clearRateCapForTest
 *
 * Tune the per-(actor, table, column) cap on sealed-column unseal
 * FAILURES. The cap is ON BY DEFAULT (default-on, v0.15.0): the framework
 * arms it at module load (threshold 10 / 1-minute window / 5-minute
 * cooldown) so a forged-ciphertext oracle is bounded with no operator
 * action. Once a single tuple accrues `threshold` failures inside
 * `windowMs`, every subsequent `unsealRow` touching that tuple is REFUSED
 * for `cooldownMs` with a `CryptoFieldRateError` and a distinct
 * `system.crypto.unseal_rate_exceeded` audit row, bounding the oracle.
 * Without the cap, an attacker who can write `vault:<crafted>` payloads
 * can hammer the KEM-decapsulation / AEAD-verify oracle indefinitely and
 * only an off-band operator alert rule catches the burst.
 *
 * Pass an opts object to RAISE/lower the thresholds. Pass `null` (or
 * `{ disabled: true }`) to turn the cap off entirely and fall back to
 * audit-only (the pre-v0.15.0 behavior), the documented opt-out for the
 * rare deployment that needs an unbounded read path. Validation is
 * config-time / entry-point tier — bad `threshold` / `windowMs` /
 * `cooldownMs` THROW so an operator catches the typo at boot rather than
 * silently mis-configuring the cap.
 *
 * CWE-307 (excessive-attempt restriction); OWASP ASVS v5 §2.2.1;
 * NIST SP 800-63B §5.2.2.
 *
 * @opts
 *   threshold: number,    // failures within the window before refusal kicks in (positive int)
 *   windowMs:  number,    // sliding-window width in ms (positive int; default 60000)
 *   cooldownMs: number,   // refusal duration once tripped (positive int; default windowMs)
 *   disabled:  boolean,   // pass true to turn the cap off (same as configureUnsealRateCap(null))
 *   now:       function,  // injected clock returning epoch ms; default Date.now (test seam)
 *   onAudit:   function,  // optional sink({ action, outcome, metadata }) for the rate audit (test seam)
 *
 * @example
 *   b.cryptoField.configureUnsealRateCap({ threshold: 5, windowMs: 60000, cooldownMs: 300000 });
 *   // ...after 5 forged-ciphertext unseal failures for one (actor, table, column):
 *   try { b.cryptoField.unsealRow("patients", forgedRow, "actor-42"); }
 *   catch (e) { e.code; }   // → "crypto-field/unseal-rate-exceeded"
 *
 *   b.cryptoField.configureUnsealRateCap(null);   // → disable again
 */
function configureUnsealRateCap(opts) {
  if (opts === null || opts === undefined || opts.disabled === true) {
    _rateCap = null;
    _rateFailWindows.clear();
    _rateCooldowns.clear();
    return null;
  }
  validateOpts(opts, ["threshold", "windowMs", "cooldownMs", "disabled", "now", "onAudit"],
    "cryptoField.configureUnsealRateCap");
  if (opts.threshold === undefined) {
    throw new CryptoFieldRateError("crypto-field/bad-threshold",
      "cryptoField.configureUnsealRateCap: opts.threshold is required and must be a positive finite integer");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["threshold", "windowMs", "cooldownMs"],
    "cryptoField.configureUnsealRateCap", CryptoFieldRateError, "crypto-field/bad-rate-cap-opt");
  validateOpts.optionalFunction(opts.now,
    "cryptoField.configureUnsealRateCap: opts.now", CryptoFieldRateError,
    "crypto-field/bad-now");
  validateOpts.optionalFunction(opts.onAudit,
    "cryptoField.configureUnsealRateCap: opts.onAudit", CryptoFieldRateError,
    "crypto-field/bad-on-audit");

  var windowMs = opts.windowMs === undefined ? TIME.minutes(1) : opts.windowMs;
  _rateCap = {
    threshold:  opts.threshold,
    windowMs:   windowMs,
    cooldownMs: opts.cooldownMs === undefined ? windowMs : opts.cooldownMs,
    now:        typeof opts.now === "function" ? opts.now : function () { return Date.now(); },
    onAudit:    typeof opts.onAudit === "function" ? opts.onAudit : null,
  };
  _rateFailWindows.clear();
  _rateCooldowns.clear();
  return { threshold: _rateCap.threshold, windowMs: _rateCap.windowMs, cooldownMs: _rateCap.cooldownMs };
}

// Emits the distinct rate-exceeded audit. Drop-silent, as a hot-path sink.
function _emitRateAudit(metadata) {
  try {
    if (_rateCap && _rateCap.onAudit) {
      _rateCap.onAudit({ action: "system.crypto.unseal_rate_exceeded", outcome: "denied", metadata: metadata });
      return;
    }
    audit().safeEmit({ action: "system.crypto.unseal_rate_exceeded", outcome: "denied", metadata: metadata });
  } catch (_e) { /* drop-silent — audit best-effort */ }
}

function _rateInCooldown(actor, table, column) {
  if (!_rateCap) return false;
  var key = _rateKey(actor, table, column);
  var until = _rateCooldowns.get(key);
  if (until === undefined) return false;
  if (_rateCap.now() >= until) {
    _rateCooldowns.delete(key);
    _rateFailWindows.delete(key);
    return false;
  }
  return true;
}

function _rateNoteFailure(actor, table, column) {
  if (!_rateCap) return false;
  var nowMs = _rateCap.now();
  var key = _rateKey(actor, table, column);
  var arr = boundedMap.getOrInsert(_rateFailWindows, key, function () { return []; });
  var cutoff = nowMs - _rateCap.windowMs;
  var drop = 0;
  while (drop < arr.length && arr[drop] < cutoff) drop += 1;
  if (drop > 0) arr.splice(0, drop);
  arr.push(nowMs);
  if (arr.length >= _rateCap.threshold) {
    _rateCooldowns.set(key, nowMs + _rateCap.cooldownMs);
    return true;
  }
  return false;
}

/**
 * @primitive b.cryptoField.clearRateCapForTest
 * @signature b.cryptoField.clearRateCapForTest()
 * @since     0.14.20
 * @status    experimental
 * @related   b.cryptoField.configureUnsealRateCap
 *
 * Test-only helper. Restores the secure DEFAULT cap (default-on baseline)
 * and drops every in-flight sliding-window + cooldown entry so a fixture
 * can re-configure the cap between cases from a known-good starting point.
 * Operator code never calls this — production deployments inherit the
 * default cap at boot and tune or disable it via configureUnsealRateCap.
 *
 * @example
 *   b.cryptoField.configureUnsealRateCap({ threshold: 3 });
 *   b.cryptoField.clearRateCapForTest();
 *   // cap is back at the secure default; windows + cooldowns cleared
 */
function clearRateCapForTest() {
  _installDefaultRateCap();
}

/**
 * @primitive b.cryptoField.sealRow
 * @signature b.cryptoField.sealRow(table, row, opts?)
 * @since     0.4.0
 * @compliance hipaa, gdpr, pci-dss
 * @related   b.cryptoField.unsealRow, b.cryptoField.eraseRow, b.vault.seal
 *
 * Returns a copy of `row` with every sealed column wrapped in
 * `vault.seal()` and every derived-hash mirror computed from the
 * pre-seal plaintext. The input row is never mutated. `vault.seal` is
 * idempotent — already-sealed values pass through unchanged so
 * round-trips through the storage layer are safe. Derived hashes are
 * computed BEFORE sealing the source so the indexed lookup column
 * captures the plaintext digest.
 *
 * When `opts.kRow` (a row-scoped key Buffer from
 * `materializePerRowKey`) is supplied — wired automatically by the
 * db-query write boundary for `declarePerRowKey` tables — sealed
 * columns are instead XChaCha20-Poly1305-encrypted under K_row and
 * emitted with the `vault.row:` prefix, AEAD-bound to (table, rowId,
 * column, schemaVersion). The residency-tag column (when the table
 * declares per-row residency) is NEVER K_row-sealed: the write gate
 * and reads must see it in plaintext.
 *
 * @opts
 *   kRow:  Buffer,   // row-scoped key from materializePerRowKey; when present,
 *                    // sealed columns emit vault.row: cells under K_row
 *   rowId: string,   // the row's _id; required when kRow is present (AAD term)
 *
 * @example
 *   b.cryptoField.registerTable("patients", {
 *     sealedFields: ["ssn"],
 *     derivedHashes: { ssnHash: { from: "ssn" } }
 *   });
 *   var row = { id: 1, name: "Alice", ssn: "123-45-6789" };
 *   var sealed = b.cryptoField.sealRow("patients", row);
 *   String(sealed.ssn).startsWith("vault:");   // → true
 *   typeof sealed.ssnHash;                     // → "string"
 *   row.ssn;                                   // → "123-45-6789" (input untouched)
 */
function sealRow(table, row, opts) {
  if (!row) return row;
  var s = schemas[table];
  if (!s) return row;
  var out = Object.assign({}, row);
  opts = opts || {};
  var kRow = Buffer.isBuffer(opts.kRow) ? opts.kRow : null;
  var kRowId = kRow
    ? String(opts.rowId != null ? opts.rowId : (out._id != null ? out._id : ""))
    : null;
  if (kRow && kRowId.length === 0) {
    throw new CryptoFieldError("crypto-field/seal-row-krow-rowid-missing",
      "cryptoField.sealRow: opts.kRow supplied but no rowId (set opts.rowId " +
      "or row._id) — the K_row cell AAD binds (table, rowId, column)");
  }
  var residencySpec = perRowResidency[table];
  var residencyCol = residencySpec ? residencySpec.residencyColumn : null;

  if (s.derivedHashes) {
    for (var derivedField in s.derivedHashes) {
      var spec = s.derivedHashes[derivedField];
      var raw = out[spec.from];
      if (raw === undefined || raw === null) continue;
      var plain;
      if (typeof raw === "string" && raw.startsWith(VAULT_PREFIX)) {
        plain = vault.unseal(raw);
      } else if (typeof raw === "string" && vaultAad.isAadSealed(raw)) {
        plain = vaultAad.unseal(raw, _aadParts(s, table, spec.from, out));
      } else {
        plain = raw;
      }
      var ns = namespaceFor(table, spec.from, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(plain) : String(plain);
      out[derivedField] = _computeDerivedHash(spec, s.derivedHashMode, ns, normalized);
    }
  }

  if (s.aad) {
    var rowId = out[s.rowIdField];
    if (rowId === undefined || rowId === null || String(rowId).length === 0) {
      throw new CryptoFieldError("crypto-field/seal-row-aad-rowid-missing",
        "cryptoField.sealRow: table '" + table +
        "' is AAD-bound (registerTable({aad:true})); the row's identity " +
        "column '" + s.rowIdField + "' must be populated BEFORE sealRow. " +
        "Generate the primary key first (e.g. uuid / sequence INSERT … RETURNING), " +
        "set row." + s.rowIdField + ", then sealRow.");   // allow:hand-rolled-sql — error-message prose, not SQL
    }
  }

  for (var i = 0; i < s.sealedFields.length; i++) {
    var field = s.sealedFields[i];
    if (out[field] === undefined || out[field] === null) continue;
    if (kRow && field === residencyCol) continue;
    if (kRow) {
      if (isRowSealed(out[field])) continue;
      var cellAad = _aadBytes(_rowCellAad(s, table, field, kRowId));
      var plainStr = _encodeTyped(out[field]);
      out[field] = ROW_PREFIX +
        encryptPacked(Buffer.from(plainStr, "utf8"), kRow, cellAad).toString("base64");
    } else if (s.aad) {
      if (typeof out[field] === "string" && vaultAad.isAadSealed(out[field])) {
        continue;
      }
      out[field] = vaultAad.seal(_encodeTyped(out[field]),
        _aadParts(s, table, field, out));
    } else {
      // allow:seal-without-aad-by-design — plain-mode legacy table; operator
      out[field] = vault.seal(_encodeTyped(out[field]));
    }
  }

  return out;
}

function _aadParts(schema, table, column, row) {
  return {
    table:         table,
    rowId:         String(row[schema.rowIdField]),
    column:        column,
    schemaVersion: schema.schemaVersion,
  };
}

/**
 * @primitive b.cryptoField.unsealRow
 * @signature b.cryptoField.unsealRow(table, row, actor?, dbHandle?)
 * @since     0.4.0
 * @compliance hipaa, gdpr, pci-dss
 * @related   b.cryptoField.sealRow, b.vault.unseal, b.cryptoField.configureUnsealRateCap
 *
 * Returns a copy of `row` with every sealed column unwrapped via
 * `vault.unseal()`. Round-trips with `sealRow`. When `vault.unseal`
 * throws (DB-write attacker forging a `vault:<crafted>` payload to
 * force ML-KEM decapsulation on attacker-controlled bytes), the
 * failure is recorded on the audit chain as
 * `system.crypto.unseal_failed` and the field is replaced with null
 * so downstream code sees "no value" instead of crashing the request.
 * The input row is never mutated.
 *
 * `vault.row:`-prefixed cells (per-row-key tables, `declarePerRowKey`)
 * are decrypted under the row's K_row: a `dbHandle` (the db-query layer
 * passes `this._db`) is used to fetch the row's wrapped secret from
 * `_blamejs_per_row_keys`, unwrap it, and derive K_row once per call.
 * When a caller passes no `dbHandle` (e.g. `b.breakGlass.unsealRow`,
 * which reads the row via clusterStorage), the framework's local db is
 * resolved automatically — the wrapped secret always lives in the local
 * `_blamejs_per_row_keys`, so keyed reads work on every path.
 * A missing wrapped row (crypto-shredded by `eraseHard` / `retention`)
 * makes the unwrap throw → the field nulls + `system.crypto.unseal_failed`
 * fires, which is correct: shredded data reads as absent.
 *
 * The unseal-failure rate cap is ON BY DEFAULT (default-on, v0.15.0):
 * repeated forged-ciphertext failures for a single `(actor, table,
 * column)` tuple trip a cooldown (threshold 10 / 1-minute window /
 * 5-minute cooldown out of the box; tune or disable via
 * `configureUnsealRateCap`). Once tripped, this call THROWS
 * `CryptoFieldRateError` and emits a distinct
 * `system.crypto.unseal_rate_exceeded` audit instead of exercising the
 * decryption oracle again (CWE-307). `actor` identifies the caller for
 * that tuple (e.g. session subject / API key id); it defaults to an
 * anonymous bucket when omitted, and is ignored entirely when the cap is
 * disabled (full back-compat for the 2-arg call).
 *
 * @example
 *   b.cryptoField.registerTable("patients", { sealedFields: ["ssn"] });
 *   var sealed = b.cryptoField.sealRow("patients", { id: 1, ssn: "123-45-6789" });
 *   var clear  = b.cryptoField.unsealRow("patients", sealed);
 *   clear.ssn;   // → "123-45-6789"
 */
function unsealRow(table, row, actor, dbHandle) {
  if (!row) return row;
  var s = schemas[table];
  if (!s || s.sealedFields.length === 0) return row;
  var out = Object.assign({}, row);
  var capActor = (actor === undefined || actor === null || String(actor).length === 0)
    ? "_anon" : String(actor);

  var kRowId = out._id != null ? String(out._id) : "";
  var keyedTable = hasPerRowKey(table);
  var _kRowCache;
  function _kRowOnce() {
    if (_kRowCache !== undefined) return _kRowCache;
    _kRowCache = null;
    if (!keyedTable || kRowId.length === 0) return null;
    var spec = perRowKeyTables[table];
    var wrap;
    try {
      var prep = (dbHandle && typeof dbHandle.prepare === "function")
        ? dbHandle.prepare.bind(dbHandle)
        : db().prepare;
      var wrapSelBuilt = sql.select(_perRowKeysTableName(), _PER_ROW_SQL_OPTS)
        .columns(["wrappedKey"])
        .where("tableName", table)
        .where("rowId", kRowId)
        .toSql();
      var wrapStmt = prep(wrapSelBuilt.sql);
      wrap = wrapStmt.get.apply(wrapStmt, wrapSelBuilt.params);
    } catch (_e) {
      return null;
    }
    if (!wrap || wrap.wrappedKey == null) return null;
    _kRowCache = _deriveKRow(_unwrapRowSecret(wrap.wrappedKey, kRowId), table, kRowId, spec);
    return _kRowCache;
  }

  for (var i = 0; i < s.sealedFields.length; i++) {
    var field = s.sealedFields[i];
    if (out[field] === "" && (s.aad || keyedTable)) {
      out[field] = null;
      try {
        audit().safeEmit({
          action:  "system.crypto.unseal_failed",
          outcome: "failure",
          metadata: {
            table: table, field: field, rowId: out[s.rowIdField] || out._id || null,
            shape: (s.aad ? "aad" : "row"),
            reason: "empty-string cell in a sealed AAD/keyed column (envelope downgrade)",
          },
        });
      } catch (_e) { /* drop-silent */ }
      continue;
    }
    if (out[field]) {
      var shape = isRowSealed(out[field]) ? "row" : (s.aad ? "aad" : "plain");
      if (_rateInCooldown(capActor, table, field)) {
        _emitRateAudit({
          table: table, field: field, actor: capActor, shape: shape,
          threshold: _rateCap.threshold, windowMs: _rateCap.windowMs, cooldownMs: _rateCap.cooldownMs,
        });
        throw new CryptoFieldRateError("crypto-field/unseal-rate-exceeded",
          "cryptoField.unsealRow: unseal-failure rate cap tripped for (actor, '" + table +
          "', '" + field + "') — refusing further unseal attempts during cooldown");
      }
      var unsealed;
      try {
        if (typeof out[field] === "string" && isRowSealed(out[field])) {
          var kRow = _kRowOnce();
          if (!kRow) {
            throw new CryptoFieldError("crypto-field/row-key-unavailable",
              "unsealRow: per-row key for '" + table + "' row '" + kRowId +
              "' is unavailable (shredded or never materialized)");
          }
          var cellAad = _aadBytes(_rowCellAad(s, table, field, kRowId));
          unsealed = _decodeTyped(decryptPacked(
            Buffer.from(out[field].slice(ROW_PREFIX.length), "base64"), kRow, cellAad
          ).toString("utf8"));
        } else if (typeof out[field] === "string" && vaultAad.isAadSealed(out[field])) {
          unsealed = _decodeTyped(vaultAad.unseal(out[field],
            _aadParts(s, table, field, out)));
        } else if (typeof out[field] === "string" && out[field].startsWith(VAULT_PREFIX)) {
          if ((s.aad || perRowKeyTables[table]) && !s.allowPlainMigration) {
            throw new CryptoFieldError("crypto-field/aad-downgrade-refused",
              "unsealRow: '" + table + "'.'" + field + "' is AAD-bound but the stored " +
              "cell is a plain (unbound) vault envelope — refusing a relocatable-seal " +
              "downgrade. For a bounded migration window pass registerTable({ " +
              "allowPlainMigration: true }), or for a framework-declared table " +
              "db.init({ allowPlainSealMigration: [\"" + table + "\"] }); rows " +
              "re-seal as bound on their next write, and each read under the " +
              "window records system.crypto_field.plain_cell_accepted so the " +
              "remaining set is visible. Close the window when it reaches zero");
          }
          if (s.aad || perRowKeyTables[table]) {
            audit().safeEmit({
              action:   "system.crypto_field.plain_cell_accepted",
              outcome:  "warning",
              metadata: { table: table, column: field,
                          reason: "pre-AAD row read under allowPlainMigration" },
            });
          }
          unsealed = _decodeTyped(vault.unseal(out[field]));
        } else {
          unsealed = out[field];
        }
      } catch (e) {
        var _shredded = e && e.code === "crypto-field/row-key-unavailable";
        try {
          audit().safeEmit({
            action:   _shredded ? "system.crypto.shredded_read" : "system.crypto.unseal_failed",
            outcome:  _shredded ? "success" : "failure",
            metadata: {
              table:   table,
              field:   field,
              rowId:   out[s.rowIdField] || out._id || null,
              shape:   shape,
              reason:  (e && e.message) || String(e),
            },
          });
        } catch (_e) { /* drop-silent */ }
        if (!_shredded && _rateNoteFailure(capActor, table, field)) {
          _emitRateAudit({
            table: table, field: field, actor: capActor, shape: shape,
            threshold: _rateCap.threshold, windowMs: _rateCap.windowMs, cooldownMs: _rateCap.cooldownMs,
          });
        }
        unsealed = null;
      }
      out[field] = unsealed;
    }
  }

  _upgradeDerivedHashesOnRead(s, table, out, dbHandle);

  return out;
}

function _upgradeDerivedHashesOnRead(s, table, out, dbHandle) {
  if (!s.derivedHashes) return;
  var rowId = out._id != null ? String(out._id) : "";
  var upgrades = null;
  for (var derivedField in s.derivedHashes) {
    if (!Object.prototype.hasOwnProperty.call(s.derivedHashes, derivedField)) continue;
    var spec = s.derivedHashes[derivedField];
    if (_resolveDerivedHashMode(spec, s.derivedHashMode) !== "hmac-shake256") continue;
    var stored = out[derivedField];
    if (typeof stored !== "string" || stored.length === 0) continue;
    var plain = out[spec.from];
    if (plain === undefined || plain === null) continue;
    var ns = namespaceFor(table, spec.from, s.hashNamespaces);
    var normalized = spec.normalize ? spec.normalize(plain) : String(plain);
    var keyed  = _computeDerivedHash(spec, s.derivedHashMode, ns, normalized);
    if (stored === keyed) continue;
    var legacy = _legacyDerivedHash(ns, normalized);
    if (stored !== legacy) continue;
    out[derivedField] = keyed;
    if (!upgrades) upgrades = {};
    upgrades[derivedField] = keyed;
  }
  if (!upgrades) return;
  if (rowId.length === 0) return;
  var handle = (dbHandle && typeof dbHandle.prepare === "function")
    ? dbHandle
    : _resolveLocalDbHandle();
  if (!handle) return;
  try {
    var handleDialect = (handle.dialect === "postgres" || handle.dialect === "mysql" ||
      handle.dialect === "sqlite") ? handle.dialect : "sqlite";
    var updBuilt = sql.update(table, { dialect: handleDialect, quoteName: true })
      .set(upgrades)
      .where("_id", rowId)
      .toSql();
    var stmt = handle.prepare(updBuilt.sql);
    stmt.run.apply(stmt, updBuilt.params);
  } catch (_e) {
    // Best-effort — DB not initialized, read-only handle, or the app table
    // isn't on this handle (cluster mode where the row came from the external
    // backend). The returned row still carries the upgraded hash; the legacy
    // digest stays matchable via lookupHashCandidates until a writable read
    // path re-hashes it.
  }
}

function _resolveLocalDbHandle() {
  try {
    var inst = db();
    return (inst && typeof inst.prepare === "function") ? inst : null;
  } catch (_e) {
    return null;
  }
}

/**
 * @primitive b.cryptoField.eraseRow
 * @signature b.cryptoField.eraseRow(table, row)
 * @since     0.7.10
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.sealRow, b.subject.eraseHard, b.db.vacuumAfterErase
 *
 * Returns a tombstoned copy of `row`: every sealed column NULLed,
 * every derived-hash mirror NULLed, and `__erasedAt` set to a
 * 1-day-bucketed UTC ms timestamp (sub-day timing is intentionally
 * fuzzed to defeat audit-log exfiltration + cross-tenant correlation
 * attacks like "this row was erased 2.3s before that one"). Under
 * regulatory postures whose `POSTURE_DEFAULTS` sets
 * `requireVacuumAfterErase: true` (gdpr / dpdp / pipl-cn / lgpd-br /
 * hipaa), automatically schedules `b.db.vacuumAfterErase({ mode:
 * "full" })` so freed B-tree pages don't linger with sealed-column
 * ciphertext readable from a forensic disk image. The row stays in
 * the table for referential integrity; outright DELETE remains the
 * caller's choice when FKs allow.
 *
 * @example
 *   b.cryptoField.registerTable("patients", {
 *     sealedFields: ["ssn"],
 *     derivedHashes: { ssnHash: { from: "ssn" } }
 *   });
 *   var sealed = b.cryptoField.sealRow("patients", { id: 1, ssn: "123-45-6789" });
 *   var erased = b.cryptoField.eraseRow("patients", sealed);
 *   erased.ssn;        // → null
 *   erased.ssnHash;    // → null
 *   typeof erased.__erasedAt;   // → "number"
 */
function eraseRow(table, row) {
  if (!row) return row;
  var s = schemas[table];
  if (!s) return row;
  var out = Object.assign({}, row);
  for (var i = 0; i < s.sealedFields.length; i++) {
    out[s.sealedFields[i]] = null;
  }
  if (s.derivedHashes) {
    for (var derivedField in s.derivedHashes) {
      out[derivedField] = null;
    }
  }
  var dayMs = TIME.days(1);
  out.__erasedAt = Math.floor(Date.now() / dayMs) * dayMs;

  if (_activePosture) {
    var requireVacuum = false;
    try {
      requireVacuum = compliance().postureDefault(
        _activePosture, "requireVacuumAfterErase") === true;
    } catch (_e) { /* compliance lookup best-effort */ }
    if (requireVacuum) {
      try {
        var dbInst = db();
        if (dbInst && typeof dbInst.vacuumAfterErase === "function") {
          dbInst.vacuumAfterErase({ mode: "full" });
        }
      } catch (_vacErr) {
        try {
          audit().safeEmit({
            action:  "cryptofield.vacuum.skipped",
            outcome: "failure",
            metadata: {
              posture: _activePosture,
              reason:  (_vacErr && _vacErr.message) ? _vacErr.message : String(_vacErr),
            },
          });
        } catch (_ae) { /* audit best-effort */ }
      }
    }
  }
  return out;
}

/**
 * @primitive b.cryptoField.lookupHash
 * @signature b.cryptoField.lookupHash(table, field, value)
 * @since     0.4.0
 * @related   b.cryptoField.computeDerived, b.cryptoField.sealRow
 *
 * Translates a plaintext-keyed lookup (e.g. `where({ email: "..." })`)
 * into the derived-hash form (`where({ emailHash: hash(...) })`).
 * Returns `{ field, value }` naming the derived column and its hash,
 * or null when no derived hash is declared for that source field.
 * Sealed columns without a declared derived hash are unindexable —
 * every encryption uses a fresh random nonce, so the ciphertext alone
 * cannot anchor a query.
 *
 * `value` is the digest under the column's ACTIVE mode (keyed-MAC by
 * default since v0.15.0; salted-sha3 when opted out), so existing callers
 * that emit `where(result.field, result.value)` are unchanged. When the
 * active mode is the keyed MAC, the result ALSO carries `legacyValue` — the
 * byte-form a row written under the pre-v0.15.0 salted-sha3 default would
 * hold. Callers that can issue a match-EITHER query (or that prefer the
 * ready-made candidate list) use `b.cryptoField.lookupHashCandidates`; the
 * upgrade-on-read auto-migrate in `unsealRow` re-hashes any row found via
 * the legacy digest to the keyed-MAC form.
 *
 * @example
 *   b.cryptoField.registerTable("users", {
 *     sealedFields: ["email"],
 *     derivedHashes: { emailHash: { from: "email" } }
 *   });
 *   var lookup = b.cryptoField.lookupHash("users", "email", "alice@example.com");
 *   lookup.field;          // → "emailHash"
 *   typeof lookup.value;   // → "string"
 *
 *   b.cryptoField.lookupHash("users", "name", "Alice");   // → null (no derived hash)
 */
function lookupHash(table, field, value) {
  var s = schemas[table];
  if (!s || !s.derivedHashes) return null;
  for (var derivedField in s.derivedHashes) {
    var spec = s.derivedHashes[derivedField];
    if (spec.from === field) {
      return _derivedHashResult(s, table, derivedField, spec, field, value);
    }
  }
  return null;
}

/**
 * @primitive b.cryptoField.lookupHashCandidates
 * @signature b.cryptoField.lookupHashCandidates(table, field, value)
 * @since     0.15.0
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.lookupHash, b.cryptoField.unsealRow
 *
 * Dual-read sibling of `lookupHash`. Returns `{ field, values }` where
 * `values` is the list of derived-hash digests that should ALL be treated
 * as a match for `value` — the digest under the column's active mode FIRST,
 * plus (when the active mode is the keyed MAC) the pre-v0.15.0 salted-sha3
 * digest a row written under the old default would carry. A caller that can
 * issue an `IN (…)` / `OR` equality over `field` finds both the new
 * keyed-indexed rows and the legacy salted-indexed rows in one query, so the
 * keyed-MAC default flip never silently drops pre-flip rows. Returns null
 * when no derived hash is declared for `field`.
 *
 * Pair it with the upgrade-on-read auto-migrate: `unsealRow` re-hashes any
 * row whose stored derived-hash matches the legacy digest to the keyed-MAC
 * form, so the candidate list shrinks back to a single value as rows are
 * read over time.
 *
 * @example
 *   b.cryptoField.registerTable("users", {
 *     sealedFields:  ["email"],
 *     derivedHashes: { emailHash: { from: "email" } },
 *   });
 *   var c = b.cryptoField.lookupHashCandidates("users", "email", "alice@example.com");
 *   c.field;            // → "emailHash"
 *   c.values.length;    // → 2  (keyed-MAC + legacy salted-sha3)
 *   // → b.db.from("users").where(c.field, "IN", c.values)
 */
function lookupHashCandidates(table, field, value) {
  var r = lookupHash(table, field, value);
  if (!r) return null;
  var values = [r.value];
  if (r.legacyValue && r.legacyValue !== r.value) values.push(r.legacyValue);
  return { field: r.field, values: values };
}

/**
 * @primitive b.cryptoField.declareColumnResidency
 * @signature b.cryptoField.declareColumnResidency(table, opts)
 * @since     0.7.27
 * @compliance gdpr
 * @related   b.cryptoField.assertColumnResidency, b.cryptoField.getColumnResidency
 *
 * Declares per-column data residency for `table`. Real GDPR / DPDP /
 * pipl-cn deployments have row-level mixed residency: a `users.name`
 * column may be globally replicable, but `users.addressLine1` must
 * stay in EU storage. At write time
 * (`b.db.set` / `b.db.from(...).insert` / `.update`), the framework
 * consults this registry; if the storage backend's tag doesn't satisfy
 * the column's tag, the write is refused under gdpr / dpdp / pipl-cn /
 * uk-gdpr postures. Throws on bad input (config-time fail-loud).
 *
 * @opts
 *   columnResidency: { [columnName]: "eu" | "us" | "global" | <tag> },
 *
 * @example
 *   b.cryptoField.declareColumnResidency("users", {
 *     columnResidency: {
 *       name:         "global",
 *       addressLine1: "eu",
 *       addressLine2: "eu"
 *     }
 *   });
 *   var got = b.cryptoField.getColumnResidency("users");
 *   got.addressLine1;   // → "eu"
 */
function declareColumnResidency(table, opts) {
  if (typeof table !== "string" || table.length === 0) {
    throw new CryptoFieldError("crypto-field/residency-table-empty",
      "declareColumnResidency: table must be a non-empty string");
  }
  if (opts === null || opts === undefined || typeof opts !== "object" || Array.isArray(opts)) {
    throw new CryptoFieldError("crypto-field/residency-opts-not-object",
      "declareColumnResidency: opts must be a plain object");
  }
  var map = opts.columnResidency;
  if (!map || typeof map !== "object" || Array.isArray(map)) {
    throw new CryptoFieldError("crypto-field/residency-map-not-object",
      "declareColumnResidency: opts.columnResidency must be an object");
  }
  var entry = Object.create(null);
  for (var col in map) {
    if (!Object.prototype.hasOwnProperty.call(map, col)) continue;
    var tag = map[col];
    if (typeof tag !== "string" || tag.length === 0) {
      throw new CryptoFieldError("crypto-field/residency-tag-empty",
        "declareColumnResidency: column '" + col +
        "' residency tag must be a non-empty string");
    }
    entry[col] = tag;
  }
  columnResidency[table] = entry;
  return { table: table, columnResidency: Object.assign({}, entry) };
}

/**
 * @primitive b.cryptoField.getColumnResidency
 * @signature b.cryptoField.getColumnResidency(table)
 * @since     0.7.27
 * @related   b.cryptoField.declareColumnResidency
 *
 * Returns the residency map declared for `table`, or null when the
 * table has no residency declaration. Read-only — does not mutate
 * state. Storage backends use this to inspect residency at the
 * write boundary.
 *
 * @example
 *   b.cryptoField.declareColumnResidency("users", {
 *     columnResidency: { addressLine1: "eu" }
 *   });
 *   b.cryptoField.getColumnResidency("users");      // → { addressLine1: "eu" }
 *   b.cryptoField.getColumnResidency("unknown");    // → null
 */
function getColumnResidency(table) {
  return columnResidency[table] || null;
}

/**
 * @primitive b.cryptoField.assertColumnResidency
 * @signature b.cryptoField.assertColumnResidency(table, row, args)
 * @since     0.7.27
 * @compliance gdpr
 * @related   b.cryptoField.declareColumnResidency, b.cryptoField.declarePerRowResidency
 *
 * Storage-write gate. Storage backends call this with the proposed
 * row before the SQL hits the wire; refusal under regulated postures
 * surfaces a config-time error rather than a silent cross-border leak.
 * Returns null on pass; returns
 * `{ error, table, column, want, got }` on refusal so the storage
 * backend can wrap it in its own error class. Columns tagged "global"
 * or "unrestricted" pass any backend; columns tagged with a region
 * (e.g. "eu") refuse mismatched backends.
 *
 * @opts
 *   backendTag: string,   // tag of the storage backend ("eu" | "us" | "unrestricted")
 *
 * @example
 *   b.cryptoField.declareColumnResidency("users", {
 *     columnResidency: { addressLine1: "eu" }
 *   });
 *   var refusal = b.cryptoField.assertColumnResidency(
 *     "users",
 *     { id: 1, addressLine1: "10 Rue de Rivoli" },
 *     { backendTag: "us" }
 *   );
 *   refusal.error;    // → "column-residency-mismatch"
 *   refusal.column;   // → "addressLine1"
 *   refusal.want;     // → "eu"
 *   refusal.got;      // → "us"
 *
 *   b.cryptoField.assertColumnResidency(
 *     "users",
 *     { id: 1, addressLine1: "10 Rue de Rivoli" },
 *     { backendTag: "eu" }
 *   );   // → null (pass)
 */
function assertColumnResidency(table, row, args) {
  var entry = columnResidency[table];
  if (!entry || !row || !args) return null;
  var backendTag = args.backendTag || "unrestricted";
  var rowLcIndex = null;
  function _rowVal(c) {
    if (Object.prototype.hasOwnProperty.call(row, c)) return row[c];
    if (rowLcIndex === null) {
      rowLcIndex = {};
      var ks = Object.keys(row);
      for (var i = 0; i < ks.length; i++) {
        var lk = ks[i].toLowerCase();
        if (!Object.prototype.hasOwnProperty.call(rowLcIndex, lk)) rowLcIndex[lk] = row[ks[i]];
      }
    }
    return rowLcIndex[String(c).toLowerCase()];
  }
  for (var col in entry) {
    var want = entry[col];
    var cellVal = _rowVal(col);
    if (cellVal === undefined || cellVal === null) continue;
    if (want === "global" || want === "unrestricted") continue;
    if (backendTag === "unrestricted") continue;
    if (backendTag !== want) {
      return {
        error:   "column-residency-mismatch",
        table:   table,
        column:  col,
        want:    want,
        got:     backendTag,
      };
    }
  }
  return null;
}

/**
 * @primitive b.cryptoField.declarePerRowResidency
 * @signature b.cryptoField.declarePerRowResidency(table, opts)
 * @since     0.14.24
 * @compliance gdpr
 * @related   b.cryptoField.getPerRowResidency, b.cryptoField.declareColumnResidency
 *
 * Declares per-ROW data residency for `table`: one plaintext column on
 * each row carries that row's residency tag, and the write gates
 * refuse a tagged row landing on an incompatible backend. The sibling
 * of `declareColumnResidency` — columns answer "which fields are
 * region-bound", rows answer "which region does THIS record belong
 * to" (an EU user's row next to a US user's row in the same table).
 * Local writes (`b.db.from(...).insertOne` / `.update`) enforce the
 * tag against the deployment's `dataResidency` region set under
 * cross-border regulated postures; external writes
 * (`b.externalDb.query`) take the tag per call via
 * `opts.rowResidencyTag` because raw SQL carries no row object. Rows
 * tagged "global" or "unrestricted" pass any backend. Throws on bad
 * input (config-time fail-loud).
 *
 * @opts
 *   residencyColumn: string,    // plaintext column carrying the row's tag
 *   allowedTags:     string[],  // whitelist of valid tag values ("eu", "us", "global", region names)
 *
 * @example
 *   b.cryptoField.declarePerRowResidency("users", {
 *     residencyColumn: "dataRegion",
 *     allowedTags:     ["eu-west-1", "us-east-1", "global"],
 *   });
 *   var spec = b.cryptoField.getPerRowResidency("users");
 *   spec.residencyColumn;   // → "dataRegion"
 */
function declarePerRowResidency(table, opts) {
  validateOpts.requireNonEmptyString(table, "declarePerRowResidency: table",
    CryptoFieldError, "crypto-field/per-row-residency-table-empty");
  validateOpts.requireObject(opts, "declarePerRowResidency",
    CryptoFieldError, "crypto-field/per-row-residency-opts-not-object");
  validateOpts(opts, ["residencyColumn", "allowedTags"], "cryptoField.declarePerRowResidency");
  validateOpts.requireNonEmptyString(opts.residencyColumn,
    "declarePerRowResidency: opts.residencyColumn",
    CryptoFieldError, "crypto-field/per-row-residency-column-invalid");
  if (!Array.isArray(opts.allowedTags) || opts.allowedTags.length === 0) {
    throw new CryptoFieldError("crypto-field/per-row-residency-tags-invalid",
      "declarePerRowResidency: opts.allowedTags must be a non-empty array of tag strings");
  }
  validateOpts.optionalNonEmptyStringArray(opts.allowedTags,
    "declarePerRowResidency: opts.allowedTags",
    CryptoFieldError, "crypto-field/per-row-residency-tag-empty");
  var sealed = getSealedFields(table);
  if (Array.isArray(sealed) && sealed.indexOf(opts.residencyColumn) !== -1) {
    throw new CryptoFieldError("crypto-field/per-row-residency-sealed-conflict",
      "declarePerRowResidency: residencyColumn '" + opts.residencyColumn +
      "' is a sealed field on table '" + table + "' — the residency tag must " +
      "stay plaintext so the write gate can read it. Choose a non-sealed column");
  }
  perRowResidency[table] = {
    residencyColumn: opts.residencyColumn,
    allowedTags:     opts.allowedTags.slice(),
  };
  return {
    table:           table,
    residencyColumn: opts.residencyColumn,
    allowedTags:     opts.allowedTags.slice(),
  };
}

/**
 * @primitive b.cryptoField.getPerRowResidency
 * @signature b.cryptoField.getPerRowResidency(table)
 * @since     0.14.24
 * @related   b.cryptoField.declarePerRowResidency
 *
 * Returns the per-row residency spec declared for `table`
 * (`{ residencyColumn, allowedTags }`), or null when the table has no
 * declaration. Read-only — storage backends call this at the write
 * boundary to decide whether the row-residency gate applies.
 *
 * @example
 *   b.cryptoField.declarePerRowResidency("users", {
 *     residencyColumn: "dataRegion",
 *     allowedTags:     ["eu-west-1", "global"],
 *   });
 *   b.cryptoField.getPerRowResidency("users").allowedTags;   // → ["eu-west-1", "global"]
 *   b.cryptoField.getPerRowResidency("unknown");             // → null
 */
function getPerRowResidency(table) {
  var spec = perRowResidency[table];
  if (!spec) return null;
  return { residencyColumn: spec.residencyColumn, allowedTags: spec.allowedTags.slice() };
}

/**
 * @primitive b.cryptoField.listPerRowResidency
 * @signature b.cryptoField.listPerRowResidency()
 * @since     0.15.4
 * @related   b.cryptoField.getPerRowResidency, b.cryptoField.declarePerRowResidency
 *
 * Enumerate every table opted into per-row residency. Returns one entry per
 * declared table — `{ table, residencyColumn, allowedTags }` — where
 * `allowedTags` lists the regions that table's rows may be tagged to.
 * Read-only. Consumers that must reason about residency across the whole
 * deployment rather than one table use this: `b.backup.create` enumerates it
 * to surface the per-row cross-border regions a deployment-level region
 * compare is blind to.
 *
 * @example
 *   b.cryptoField.declarePerRowResidency("residents", {
 *     residencyColumn: "region",
 *     allowedTags:     ["eu-west-1", "us-east-1"],
 *   });
 *   b.cryptoField.listPerRowResidency();
 *   // → [ { table: "residents", residencyColumn: "region",
 *   //       allowedTags: ["eu-west-1", "us-east-1"] } ]
 */
function listPerRowResidency() {
  return Object.keys(perRowResidency).map(function (t) {
    return {
      table:           t,
      residencyColumn: perRowResidency[t].residencyColumn,
      allowedTags:     perRowResidency[t].allowedTags.slice(),
    };
  });
}

/**
 * @primitive b.cryptoField.declarePerRowKey
 * @signature b.cryptoField.declarePerRowKey(table, opts)
 * @since     0.7.27
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.materializePerRowKey, b.cryptoField.destroyPerRowKey, b.subject.eraseHard
 *
 * Opts a table into per-row keying (K_row crypto-shred substrate).
 * After registration, every INSERT generates a fresh 32-byte CSPRNG
 * row-secret, derives K_row from it, and stores the SECRET (never
 * K_row) AAD-sealed in `_blamejs_per_row_keys (tableName, rowId,
 * wrappedKey)`. AAD on the wrap binds (table, rowId, column,
 * schemaVersion) — a wrapped secret copied to a different row fails
 * Poly1305 verification. `b.subject.eraseHard(subjectId)` /
 * `b.retention` destroy the per-row entries for the subject's rows; WAL
 * / replica residual ciphertext becomes mathematically undecryptable
 * because the random row-secret — the only seed for K_row — is gone
 * everywhere it ever lived. Throws on bad input (config-time
 * fail-loud).
 *
 * @opts
 *   keySize: number,   // bytes; default 32 (XChaCha20-Poly1305 key length); minimum 16
 *   info:    string,   // HKDF info label; default "blamejs-per-row-key:<table>"
 *
 * @example
 *   var spec = b.cryptoField.declarePerRowKey("orders", {
 *     keySize: 32,
 *     info:    "blamejs-per-row-key:orders"
 *   });
 *   spec.keySize;                          // → 32
 *   b.cryptoField.hasPerRowKey("orders");  // → true
 */
function declarePerRowKey(table, opts) {
  if (typeof table !== "string" || table.length === 0) {
    throw new CryptoFieldError("crypto-field/per-row-key-table-empty",
      "declarePerRowKey: table must be a non-empty string");
  }
  opts = opts || {};
  var keySize = opts.keySize === undefined ? 32 : opts.keySize;
  if (typeof keySize !== "number" || !isFinite(keySize) ||
      keySize < 16 || Math.floor(keySize) !== keySize) {
    throw new CryptoFieldError("crypto-field/per-row-key-bad-size",
      "declarePerRowKey: opts.keySize must be an integer >= 16 (bytes)");
  }
  var info = opts.info || ("blamejs-per-row-key:" + table);
  if (typeof info !== "string" || info.length === 0) {
    throw new CryptoFieldError("crypto-field/per-row-key-info-empty",
      "declarePerRowKey: opts.info must be a non-empty string");
  }
  perRowKeyTables[table] = { keySize: keySize, info: info };
  return { table: table, keySize: keySize, info: info };
}

/**
 * @primitive b.cryptoField.hasPerRowKey
 * @signature b.cryptoField.hasPerRowKey(table)
 * @since     0.7.27
 * @related   b.cryptoField.declarePerRowKey
 *
 * Returns `true` when `table` has been registered for per-row keying
 * via `declarePerRowKey`, `false` otherwise. Storage backends gate
 * the K_row materialize/destroy paths through this check.
 *
 * @example
 *   b.cryptoField.hasPerRowKey("orders");   // → false
 *   b.cryptoField.declarePerRowKey("orders", { keySize: 32 });
 *   b.cryptoField.hasPerRowKey("orders");   // → true
 */
function hasPerRowKey(table) {
  return !!perRowKeyTables[table];
}

/**
 * @primitive b.cryptoField.materializePerRowKey
 * @signature b.cryptoField.materializePerRowKey(table, rowId, dbHandle)
 * @since     0.7.27
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.declarePerRowKey, b.cryptoField.destroyPerRowKey
 *
 * Derive-and-store: called by the storage backend on INSERT (the
 * db-query write boundary, gated on `hasPerRowKey`). Generates a fresh
 * 32-byte CSPRNG row-secret, derives
 * `K_row = SHAKE256(rowSecret || ":" || table || ":" || rowId || ":"
 * || info, keySize)`, AAD-seals the SECRET (base64) into
 * `_blamejs_per_row_keys.wrappedKey` via `b.vault.aad.seal`, and
 * returns the unwrapped K_row Buffer for the caller to encrypt sealed
 * columns under the row-scoped key. The secret is random — never a
 * function of any on-disk salt — so destroying the wrapped secret
 * makes K_row unrecoverable even with full disk + vault-root access.
 * Idempotent on UPSERT — if a secret already exists for (table,
 * rowId), unwraps it and re-derives the same K_row. The AAD-bound wrap
 * rejects copy-row attacks: a wrapped secret pasted under a different
 * rowId fails Poly1305 verification at unseal time. `dbHandle` is a
 * b.db handle (`.prepare`); rowId MUST be the row's `_id` (the value
 * `destroyPerRowKey` / `b.subject.eraseHard` delete on).
 *
 * @example
 *   b.cryptoField.declarePerRowKey("orders", { keySize: 32 });
 *   var dbHandle = b.db;   // b.db is the handle — { prepare, transaction, runSql }
 *   var kRow = b.cryptoField.materializePerRowKey("orders", "ord-42", dbHandle);
 *   Buffer.isBuffer(kRow);   // → true
 *   kRow.length;             // → 32
 *
 *   // Idempotent — second call returns the same key.
 *   var kRowAgain = b.cryptoField.materializePerRowKey("orders", "ord-42", dbHandle);
 *   kRow.equals(kRowAgain);  // → true
 */
function materializePerRowKey(table, rowId, dbHandle) {
  var spec = perRowKeyTables[table];
  if (!spec) return null;
  if (!dbHandle || typeof dbHandle.prepare !== "function") {
    throw new CryptoFieldError("crypto-field/materialize-per-row-key-no-db",
      "materializePerRowKey: dbHandle (b.db) is required");
  }
  var ridStr = String(rowId);
  var existingSelBuilt = sql.select(_perRowKeysTableName(), _PER_ROW_SQL_OPTS)
    .columns(["wrappedKey"])
    .where("tableName", table)
    .where("rowId", ridStr)
    .toSql();
  var existingStmt = dbHandle.prepare(existingSelBuilt.sql);
  var existing = existingStmt.get.apply(existingStmt, existingSelBuilt.params);
  if (existing) {
    return _deriveKRow(_unwrapRowSecret(existing.wrappedKey, ridStr), table, ridStr, spec);
  }
  var rowSecret = generateBytes(32);
  var kRow = _deriveKRow(rowSecret, table, ridStr, spec);
  var sealed = vaultAad.seal(rowSecret.toString("base64"), _wrappedKeyAad(ridStr));
  var insBuilt = sql.insert(_perRowKeysTableName(), _PER_ROW_SQL_OPTS)
    .values({
      _id:        generateToken(16),
      tableName:  table,
      rowId:      ridStr,
      wrappedKey: sealed,
      createdAt:  Date.now(),
    })
    .toSql();
  var insStmt = dbHandle.prepare(insBuilt.sql);
  insStmt.run.apply(insStmt, insBuilt.params);
  return kRow;
}

function _deriveKRow(rowSecret, table, rowId, spec) {
  var ikm = Buffer.concat([
    rowSecret,
    Buffer.from(":" + table + ":" + rowId + ":" + spec.info, "utf8"),
  ]);
  return kdf(ikm, spec.keySize);
}

function _unwrapRowSecret(wrapped, rowId) {
  return Buffer.from(vaultAad.unseal(wrapped, _wrappedKeyAad(rowId)), "base64");
}

/**
 * @primitive b.cryptoField.destroyPerRowKey
 * @signature b.cryptoField.destroyPerRowKey(table, rowId, dbHandle)
 * @since     0.7.27
 * @compliance gdpr, hipaa
 * @related   b.cryptoField.materializePerRowKey, b.subject.eraseHard
 *
 * Crypto-shred: drops the row's wrapped row-secret from
 * `_blamejs_per_row_keys`. Called by `b.subject.eraseHard` and
 * `b.retention` for each row mapped to the erased subject. Returns
 * `{ destroyed: <rowsAffected> }`. After destruction, any WAL /
 * replica residual ciphertext for the row is mathematically
 * undecryptable — even with the vault root key — because the random
 * row-secret (the only seed for K_row) is gone everywhere it ever
 * lived. `rowId` MUST be the row's `_id`. No-op when the table is not
 * registered for per-row keying.
 *
 * @example
 *   b.cryptoField.declarePerRowKey("orders", { keySize: 32 });
 *   var dbHandle = b.db;   // b.db is the handle — { prepare, transaction, runSql }
 *   b.cryptoField.materializePerRowKey("orders", "ord-42", dbHandle);
 *
 *   var result = b.cryptoField.destroyPerRowKey("orders", "ord-42", dbHandle);
 *   result.destroyed;   // → 1
 *
 *   // Subsequent destroy is a no-op.
 *   b.cryptoField.destroyPerRowKey("orders", "ord-42", dbHandle).destroyed;   // → 0
 */
function destroyPerRowKey(table, rowId, dbHandle) {
  if (!perRowKeyTables[table]) return { destroyed: 0 };
  if (!dbHandle || typeof dbHandle.prepare !== "function") {
    throw new CryptoFieldError("crypto-field/destroy-per-row-key-no-db",
      "destroyPerRowKey: dbHandle (b.db) is required");
  }
  var delBuilt = sql.delete(_perRowKeysTableName(), _PER_ROW_SQL_OPTS)
    .where("tableName", table)
    .where("rowId", String(rowId))
    .toSql();
  var delStmt = dbHandle.prepare(delBuilt.sql);
  var result = delStmt.run.apply(delStmt, delBuilt.params);
  return { destroyed: (result && result.changes) || 0 };
}

/**
 * @primitive b.cryptoField.clearResidencyForTest
 * @signature b.cryptoField.clearResidencyForTest()
 * @since     0.7.27
 * @status    experimental
 * @related   b.cryptoField.declareColumnResidency, b.cryptoField.declarePerRowKey
 *
 * Test-only helper. Drops every entry from the per-column residency
 * registry, the per-row residency registry, and the per-row-key
 * registry so a test fixture can re-declare them between cases.
 * Operator code never calls this — production declarations come from
 * `b.db.init({ schema })` once at boot.
 *
 * @example
 *   b.cryptoField.declareColumnResidency("users", {
 *     columnResidency: { addressLine1: "eu" }
 *   });
 *   b.cryptoField.clearResidencyForTest();
 *   b.cryptoField.getColumnResidency("users");   // → null
 */
function clearResidencyForTest() {
  for (var t in columnResidency) delete columnResidency[t];
  for (var u in perRowKeyTables) delete perRowKeyTables[u];
  for (var v in perRowResidency) delete perRowResidency[v];
}

module.exports = {
  registerTable:    registerTable,
  getSchema:        getSchema,
  getSealedFields:  getSealedFields,
  sealRow:          sealRow,
  unsealRow:        unsealRow,
  isRowSealed:      isRowSealed,
  configureUnsealRateCap: configureUnsealRateCap,
  clearRateCapForTest:    clearRateCapForTest,
  CryptoFieldRateError:   CryptoFieldRateError,
  _aadParts:        _aadParts,
  sealDoc:          sealRow,
  unsealDoc:        unsealRow,
  eraseRow:         eraseRow,
  applyPosture:     applyPosture,
  getActivePosture: getActivePosture,
  computeDerived:   computeDerived,
  computeNamespacedHash: computeNamespacedHash,
  lookupHash:       lookupHash,
  lookupHashCandidates: lookupHashCandidates,
  clearForTest:     clearForTest,
  declareColumnResidency: declareColumnResidency,
  getColumnResidency:     getColumnResidency,
  assertColumnResidency:  assertColumnResidency,
  declarePerRowResidency: declarePerRowResidency,
  getPerRowResidency:     getPerRowResidency,
  listPerRowResidency:    listPerRowResidency,
  declarePerRowKey:       declarePerRowKey,
  hasPerRowKey:           hasPerRowKey,
  materializePerRowKey:   materializePerRowKey,
  destroyPerRowKey:       destroyPerRowKey,
  clearResidencyForTest:  clearResidencyForTest,
};
