"use strict";
/**
 * Field-level crypto engine.
 *
 * Wraps vault.seal/unseal at the row boundary so apps can declare which
 * columns hold PHI/PCI/personal data and the framework auto-protects them
 * on every write/read. Apps register their schema via db.init({ schema }) —
 * this module then operates on (table, row) pairs.
 *
 * Per-column field types:
 *   - sealedFields:    vault.seal() on write, vault.unseal() on read
 *   - derivedHashes:   computed from a source field on write, indexed lookup
 *                      enabled via where({ derivedField: hashFor(...) })
 *
 * Apps that need a one-way hash field (e.g. an opaque IP block list) build
 * the derived hash themselves with a custom namespace via db.hashFor().
 *
 * No mutation of the input row — every operation returns a new object.
 */
var vault = require("./vault");
var { sha3Hash } = require("./crypto");
var { HASH_PREFIX, VAULT_PREFIX } = require("./constants");

// Per-table registry, populated by db.init()
var schemas = Object.create(null);

function registerTable(name, opts) {
  schemas[name] = {
    sealedFields:   Array.isArray(opts.sealedFields)   ? opts.sealedFields.slice()   : [],
    derivedHashes:  Object.assign({}, opts.derivedHashes || {}),
    hashNamespaces: Object.assign({}, opts.hashNamespaces || {}),
  };
}

function getSchema(table) {
  return schemas[table] || null;
}

function getSealedFields(table) {
  var s = schemas[table];
  return s ? s.sealedFields : [];
}

function clearForTest() {
  for (var k in schemas) delete schemas[k];
}

// ---- Hash helpers ----

// Default hash namespace lookup — falls back to the framework's HASH_PREFIX
// registry, then to a per-table `bj-<table>-<field>:` namespace if neither is
// registered. The namespace prevents rainbow attacks across fields.
function namespaceFor(table, field, registered) {
  if (registered && registered[field]) return registered[field];
  var fieldUpper = field.toUpperCase();
  if (HASH_PREFIX[fieldUpper]) return HASH_PREFIX[fieldUpper];
  return "bj-" + table + "-" + field + ":";
}

function computeDerived(table, sourceField, sourceValue) {
  if (sourceValue === undefined || sourceValue === null) return null;
  var s = schemas[table];
  if (!s || !s.derivedHashes) return null;

  for (var derivedField in s.derivedHashes) {
    var spec = s.derivedHashes[derivedField];
    if (spec.from === sourceField) {
      var ns = namespaceFor(table, sourceField, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(sourceValue) : String(sourceValue);
      return { field: derivedField, value: sha3Hash(ns + normalized) };
    }
  }
  return null;
}

// ---- Row sealing / unsealing ----

function sealRow(table, row) {
  if (!row) return row;
  var s = schemas[table];
  if (!s) return row;
  var out = Object.assign({}, row);

  // Compute derived hashes from plaintext source values BEFORE sealing those
  // sources. If a source value arrives already sealed (e.g. from an internal
  // call passing through), unseal it to get the plaintext for hashing.
  if (s.derivedHashes) {
    for (var derivedField in s.derivedHashes) {
      var spec = s.derivedHashes[derivedField];
      var raw = out[spec.from];
      if (raw === undefined || raw === null) continue;
      var plain = String(raw).startsWith(VAULT_PREFIX) ? vault.unseal(raw) : raw;
      var ns = namespaceFor(table, spec.from, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(plain) : String(plain);
      out[derivedField] = sha3Hash(ns + normalized);
    }
  }

  // Seal fields (vault.seal is idempotent — already-sealed values pass through)
  for (var i = 0; i < s.sealedFields.length; i++) {
    var field = s.sealedFields[i];
    if (out[field] !== undefined && out[field] !== null) {
      out[field] = vault.seal(String(out[field]));
    }
  }

  return out;
}

function unsealRow(table, row) {
  if (!row) return row;
  var s = schemas[table];
  if (!s || s.sealedFields.length === 0) return row;
  var out = Object.assign({}, row);

  for (var i = 0; i < s.sealedFields.length; i++) {
    var field = s.sealedFields[i];
    if (out[field]) {
      var unsealed = vault.unseal(out[field]);
      // If the value wasn't actually sealed, vault.unseal returns the input
      // unchanged — keep the original.
      out[field] = unsealed !== undefined && unsealed !== null ? unsealed : out[field];
    }
  }

  return out;
}

// ---- Erasure (GDPR Art. 17 / "right to be forgotten") ----
//
// eraseRow(table, row) returns a tombstoned copy of the row: every
// sealed column is replaced with NULL, every derived hash column
// (computed from a sealed source) is replaced with NULL, and a
// `__erasedAt` field is added carrying the erasure timestamp. The
// row itself stays in the table (referential integrity), but the
// sealed cleartext is unrecoverable — even with the vault key, NULL
// decrypts to NULL.
//
// Callers that need the row removed entirely should DELETE; eraseRow
// is for the case where downstream FKs / audit references make
// outright deletion infeasible.
function eraseRow(table, row) {
  if (!row) return row;
  var s = schemas[table];
  if (!s) return row;
  var out = Object.assign({}, row);
  // Erase sealed columns — set to null. After this, unsealRow on the
  // erased row returns null for these columns; no key recovers them
  // because there's no ciphertext to decrypt.
  for (var i = 0; i < s.sealedFields.length; i++) {
    out[s.sealedFields[i]] = null;
  }
  // Erase derived hashes — they're indexed lookup mirrors of sealed
  // sources and would otherwise let an attacker reverse the cleartext
  // via dictionary enumeration of the hash.
  if (s.derivedHashes) {
    for (var derivedField in s.derivedHashes) {
      out[derivedField] = null;
    }
  }
  out.__erasedAt = Date.now();
  return out;
}

// ---- Lookup translation ----

// where({ email: 'x' }) → where({ emailHash: hash(...) }).
// If the field is sealed and has no derived hash, lookup is impossible
// (sealed values use random nonces — every encryption is unique). Caller
// is expected to declare a derived hash for every sealed field they want
// to query; otherwise queries on sealed fields silently return zero rows.
function lookupHash(table, field, value) {
  var s = schemas[table];
  if (!s || !s.derivedHashes) return null;
  for (var derivedField in s.derivedHashes) {
    var spec = s.derivedHashes[derivedField];
    if (spec.from === field) {
      var ns = namespaceFor(table, field, s.hashNamespaces);
      var normalized = spec.normalize ? spec.normalize(value) : String(value);
      return { field: derivedField, value: sha3Hash(ns + normalized) };
    }
  }
  return null;
}

module.exports = {
  registerTable:    registerTable,
  getSchema:        getSchema,
  getSealedFields:  getSealedFields,
  sealRow:          sealRow,
  unsealRow:        unsealRow,
  eraseRow:         eraseRow,
  computeDerived:   computeDerived,
  lookupHash:       lookupHash,
  clearForTest:     clearForTest,
};
