/**
 * Field-level crypto schema.
 *
 * Defines how each field in each table is protected:
 *   - "seal"   → vault.seal() on write, vault.unseal() on read
 *   - "hash"   → b.crypto.namespaceHash() on write (one-way, for indexed lookup)
 *   - "argon2" → password hash (handled externally, not auto-processed)
 *   - "raw"    → stored as-is (IDs, timestamps, counters, enums)
 *
 * Derived fields are auto-computed from source fields:
 *   emailHash ← b.crypto.namespaceHash(HASH_PREFIX.EMAIL, email)
 *   shareIdHash ← b.crypto.namespaceHash(HASH_PREFIX.SHARE_ID, shareId)
 *
 * Routes pass PLAINTEXT. This layer seals on write, unseals on read.
 * No route should ever call vault.seal() or b.crypto.namespaceHash() directly for DB fields.
 */
var b = require("./vendor/blamejs");
var vault = require("./vault");
var { HASH_PREFIX, VAULT_PREFIX } = require("./constants");

// Lazy logger — field-crypto loads early (via lib/db.js); a top-level require of
// app/shared/logger risks load-order/circular issues. Resolved at first use.
var _loggerLazy = b.lazyRequire(function () { return require("../app/shared/logger"); });

// AAD schema generation for sealed columns. Bound into every sealed value's
// AEAD tag via b.cryptoField (table, _id, column, schemaVersion). Bump ONLY
// when a column's meaning changes such that an old value must not decrypt into
// it — a bump invalidates every prior AAD-sealed value and REQUIRES a re-seal
// migration in the same release. Routine ALTER TABLE ADD COLUMN does not bump.
var SEAL_SCHEMA_VERSION = "1";

// Recover the plaintext of a sealed-column SOURCE value for derived-hash
// computation. Sources are normally plaintext (routes pass plaintext); the
// sealed branches are defensive for the rare already-sealed passthrough.
function _sourcePlain(table, column, val, rowId) {
  if (typeof val !== "string") return val;
  if (b.vault.aad.isAadSealed(val)) {
    if (rowId == null) return val;
    return b.vault.aad.unseal(val, b.vault.aad.buildColumnAad({
      table: table, rowId: String(rowId), column: column, schemaVersion: SEAL_SCHEMA_VERSION,
    }));
  }
  if (val.indexOf(VAULT_PREFIX) === 0) return vault.unseal(val);
  return val;
}

// Field classification per table
// Fields not listed here are "raw" (stored as-is)
// Fields are sealed (encrypted at rest) or left raw (for SQL query predicates).
// Raw fields are ONLY those needed in WHERE clauses — everything else is sealed.
// Derived fields auto-compute hashed indexes for sealed fields that need lookups.
var FIELD_SCHEMA = {
  users: {
    // raw: _id, status, role, failedLoginAttempts, lockedUntil, createdAt, lastLogin | needed for SQL queries and arithmetic
    seal: ["email", "displayName", "avatar", "googleId", "passwordHash", "authType", "vaultEnabled", "vaultPublicKey", "vaultStealth", "vaultMode", "vaultSeed", "totpLastStep", "totpSecret", "totpEnabled", "totpBackupCodes", "totpAlgorithm"],
    derived: { emailHash: { from: "email", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.EMAIL, String(v).toLowerCase()) : null; } } },
  },
  files: {
    // raw: _id, status, vaultEncrypted, uploadedBy, bundleId, teamId, size, downloads, createdAt, updatedAt, seq, deletedAt | needed for SQL queries, arithmetic, and sync change feed
    seal: ["shareId", "originalName", "relativePath", "storagePath", "mimeType", "uploaderEmail", "uploaderName", "encryptionKey", "bundleShareId", "expiresAt", "vaultEncapsulatedKey", "vaultIv", "vaultBatchId", "vaultBatchName", "checksum"],
    derived: {
      shareIdHash: { from: "shareId", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.SHARE_ID, v) : null; } },
      emailHash: { from: "uploaderEmail", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.EMAIL, String(v).toLowerCase()) : null; } },
      bundleShareIdHash: { from: "bundleShareId", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.SHARE_ID, v) : null; } },
    },
  },
  bundles: {
    // raw: _id, status, ownerId, teamId, createdAt, expectedFiles, receivedFiles, skippedCount, totalSize, downloads | counters used in arithmetic
    // raw: accessMode, bundleType (enums), seq (monotonic counter) | operational fields for sync
    // skippedFiles excluded — it's a JSON array that can't survive String() coercion in vault.seal()
    seal: ["shareId", "uploaderName", "uploaderEmail", "message", "passwordHash", "expiresAt", "finalizeTokenHash", "stashId", "bundleName", "allowedEmails"],
    derived: {
      shareIdHash: { from: "shareId", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.SHARE_ID, v) : null; } },
      emailHash: { from: "uploaderEmail", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.EMAIL, String(v).toLowerCase()) : null; } },
    },
  },
  audit_log: {
    seal: ["action", "targetId", "targetEmail", "performedBy", "performedByEmail", "details", "ip"],
  },
  blocked_ips: {
    hash: ["ip"],
    seal: ["reason", "blockedBy"],
  },
  api_keys: {
    // raw: keyHash (already a hash — sealing double-encrypts), userId (FK lookup)
    seal: ["name", "prefix", "permissions", "lastUsed", "boundStashId", "boundBundleId", "certIssuedAt", "certExpiresAt"],
  },
  webhooks: {
    // raw: active | needed for SQL query (findActive)
    seal: ["url", "events", "secret", "createdBy", "lastTriggered"],
  },
  customer_stash: {
    // raw: maxFileSize, maxFiles, maxBundleSize, defaultExpiry, bundleCount, totalBytes (integers used in arithmetic)
    // raw: accessMode, syncEnabled (enums/flags), maxFileSize, maxFiles, maxBundleSize, defaultExpiry, bundleCount, totalBytes (integers)
    seal: ["slug", "name", "title", "subtitle", "passwordHash", "allowedExtensions", "allowedEmails", "accentColor", "logoUrl", "createdBy", "enabled", "syncBundleId"],
    derived: {
      slugHash: { from: "slug", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.SLUG, v) : null; } },
    },
  },
  credentials: {
    // raw: userId (FK lookup), counter (integer incremented on each auth)
    seal: ["credentialId", "publicKey", "deviceType", "backedUp", "transports"],
  },
  email_sends: {
    // raw: status, createdAt | status/createdAt needed for SQL queries (quota counting)
    seal: ["recipient", "subject", "backend"],
  },
  teams: {
    seal: ["name", "createdBy"],
  },
  team_members: {
    // raw: teamId, userId (FK lookups for team membership queries)
    seal: ["role", "joinedAt"],
  },
  invites: {
    // raw: status, expiresAt | loaded via findAll + JS filter, but status used in cleanup queries
    seal: ["email", "role", "tokenHash", "invitedBy"],
  },
  webhook_deliveries: {
    // raw: webhookId (FK lookup), statusCode, attempts (integers), createdAt (cleanup index)
    seal: ["event", "status", "error"],
  },
  verification_tokens: {
    // raw: token (already a hash), type (enum discriminator), userId (FK cleanup), expiresAt (cleanup)
    seal: [],
  },
  settings: {
    // raw: key | needed for SQL lookup (findOne({ key: envKey }))
    seal: ["value"],
  },
  bundle_access_codes: {
    // raw: bundleShareId (indexed lookup), attempts (counter), status (enum), expiresAt, createdAt
    seal: ["email", "code"],
    derived: {
      emailHash: { from: "email", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.EMAIL, String(v).toLowerCase()) : null; } },
      codeHash: { from: "code", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.ACCESS_CODE, v) : null; } },
    },
  },
  bundle_access_log: {
    // raw: bundleShareId (indexed lookup), accessedAt
    seal: ["email", "ip"],
    derived: {
      emailHash: { from: "email", fn: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.EMAIL, String(v).toLowerCase()) : null; } },
    },
  },
  bundle_access_lockouts: {
    // raw: shareIdHash (already a hash), failures (counter), lastAttempt (timestamp)
    seal: [],
  },
  cert_revocations: {
    // raw: fingerprintHash (already a hash, indexed), revokedAt (timestamp)
    seal: ["cn", "reason"],
  },
  enrollment_codes: {
    // raw: codeHash (indexed for lookup), status, expiresAt, createdAt
    // Everything else sealed — API keys, certs, private keys are highly sensitive
    seal: ["apiKey", "clientCert", "clientKey", "caCert", "stashId", "bundleId", "createdBy", "reissue", "originalKeyId"],
  },
};

// Hash functions for "hash" type fields
var HASH_FNS = {
  blocked_ips: {
    ip: function (v) { return v ? b.crypto.namespaceHash(HASH_PREFIX.BLOCKED_IP, v) : null; },
  },
};

/**
 * Seal a document before DB write.
 * Delegates per-column sealing to b.cryptoField.sealRow, which AEAD-binds each
 * sealed value to its row identity (table, _id, column, schemaVersion) — a
 * DB-write attacker cannot copy a sealed value into another row/column and have
 * it decrypt. Derived hashes and one-way hashes stay HS-computed here (their
 * stored values must remain byte-identical for indexed lookups). rowId is the
 * row's _id: on insert it is on the record, on update it is threaded per-row.
 * Input: plaintext doc. Output: sealed doc ready for DB.
 */
function sealDoc(table, doc, rowId) {
  var schema = FIELD_SCHEMA[table];
  if (!schema) return doc;
  var result = Object.assign({}, doc);
  if (rowId != null) result._id = rowId;

  // Derived hashes — computed HS-side (NOT delegated) so emailHash / shareIdHash
  // / slugHash / ... keep their existing namespace + value and indexed lookups
  // don't break. Source is normally plaintext; _sourcePlain covers the rare
  // already-sealed passthrough.
  if (schema.derived) {
    for (var dk in schema.derived) {
      var def = schema.derived[dk];
      var sourceVal = result[def.from];
      if (sourceVal !== undefined && sourceVal !== null) {
        result[dk] = def.fn(_sourcePlain(table, def.from, sourceVal, result._id));
      }
    }
  }

  // Hide values from sealRow that must NOT be AEAD-sealed, then restore them
  // verbatim. Two cases, both replicating the old vault.seal contract:
  //   1. Falsy ("" / false / 0 / NaN): old vault.seal returned them raw
  //      (`if (!plaintext) return plaintext`). sealRow would seal them — and
  //      b.vault.aad.seal THROWS on empty string + would coerce false→"false"
  //      (truthy). Leave them raw so type/value round-trips unchanged.
  //   2. Already-sealed (legacy "vault:" or "vault.aad:"): b.vault.aad.seal
  //      throws on double-AAD-seal and sealRow does NOT skip a legacy "vault:"
  //      value, so a pre-sealed value (storage encryptionKey, two-factor
  //      totpSecret, settings.value) would be nested-sealed and corrupted.
  //      They stay in their existing scheme until their write path passes
  //      plaintext (lazy migration).
  var passthrough = null;
  if (schema.seal) {
    for (var i = 0; i < schema.seal.length; i++) {
      var field = schema.seal[i];
      var v = result[field];
      if (v === undefined || v === null) continue;   // sealRow skips these; nothing to restore
      if (!v ||
          (typeof v === "string" && (v.indexOf(VAULT_PREFIX) === 0 || b.vault.aad.isAadSealed(v)))) {
        if (!passthrough) passthrough = {};
        passthrough[field] = v;
        delete result[field];
      }
    }
  }

  // Delegate sealing + AAD binding. Tables register {aad:true, rowIdField:"_id"}
  // (registerWithBlamejs) so sealRow binds each sealed column's AEAD tag to the
  // row's _id. sealRow requires result._id for an AAD table.
  result = b.cryptoField.sealRow(table, result);
  if (passthrough) Object.assign(result, passthrough);

  // One-way hash fields (e.g. blocked_ips.ip) — HS-computed.
  if (schema.hash) {
    var hashFns = HASH_FNS[table] || {};
    for (var j = 0; j < schema.hash.length; j++) {
      var hf = schema.hash[j];
      if (result[hf] !== undefined && result[hf] !== null && hashFns[hf]) {
        result[hf] = hashFns[hf](result[hf]);
      }
    }
  }

  return result;
}

/**
 * Unseal a document after DB read.
 * Delegates to b.cryptoField.unsealRow, which dual-reads (AAD-sealed via
 * b.vault.aad, legacy "vault:" via vault.unseal) and FAILS CLOSED on an AEAD
 * mismatch — nulling the field + emitting a system.crypto.unseal_failed audit
 * row rather than returning attacker-crafted ciphertext. Reads always carry the
 * row's _id (the AAD identity); a rowId override is accepted for completeness.
 * Input: sealed doc from DB. Output: plaintext doc.
 */
function unsealDoc(table, doc, rowId) {
  if (!doc) return doc;
  var schema = FIELD_SCHEMA[table];
  if (!schema || !schema.seal || schema.seal.length === 0) return doc;
  if (rowId != null && (doc._id === undefined || doc._id === null)) {
    doc = Object.assign({}, doc, { _id: rowId });
  }
  var out = b.cryptoField.unsealRow(table, doc);

  // unsealRow fails closed to null on an AEAD mismatch (tamper / cross-row or
  // cross-column copy / corruption). Its built-in system.crypto.unseal_failed
  // audit is silenced in the running server (server.js no-ops b.audit at boot),
  // so surface the failure HS-side: a sealed column whose INPUT was sealed but
  // whose OUTPUT is null is a genuine failure (sealed plaintext is never empty —
  // falsy values are stored raw). Log at error severity so operators alert on
  // burst patterns. Do NOT write audit_log here — this runs on the read path
  // inside find() loops; a DB write would risk re-entrancy + amplify an attack.
  for (var i = 0; i < schema.seal.length; i++) {
    var f = schema.seal[i];
    var inV = doc[f];
    if (out[f] == null && inV != null && typeof inV === "string" &&
        (inV.indexOf(VAULT_PREFIX) === 0 || b.vault.aad.isAadSealed(inV))) {
      try {
        _loggerLazy().error("sealed column failed to unseal — possible tamper / cross-row copy / corruption", {
          table: table, column: f, rowId: doc._id || null,
          shape: b.vault.aad.isAadSealed(inV) ? "aad" : "legacy",
        });
      } catch (_e) { /* logging must never break a read */ }
    }
  }
  return out;
}

/**
 * Compute a lookup hash for a field value.
 * Used for query translation: findOne({ email: "x" }) → findOne({ emailHash: hash("x") })
 */
function lookupHash(table, field, value) {
  var schema = FIELD_SCHEMA[table];
  if (!schema || !schema.derived) return null;
  for (var dk in schema.derived) {
    if (schema.derived[dk].from === field) {
      return { key: dk, value: schema.derived[dk].fn(value) };
    }
  }
  // Check hash fields
  var hashFns = HASH_FNS[table] || {};
  if (hashFns[field]) {
    return { key: field, value: hashFns[field](value) };
  }
  return null;
}

/**
 * Get the list of sealed fields for a table.
 */
function getSealedFields(table) {
  var schema = FIELD_SCHEMA[table];
  return schema && schema.seal ? schema.seal : [];
}

// Register every HS table with b.cryptoField so blamejs primitives
// that drive off the framework's schema registry (b.vaultRotate.rotate
// / validateSchemaMatch — which call b.cryptoField.getSchema) can see
// HS's sealed columns. Idempotent — call once at any point before
// invoking those primitives. The actual sealing on each DB op stays
// in this file's sealDoc/unsealDoc.
function registerWithBlamejs() {
  for (var table in FIELD_SCHEMA) {
    var s = FIELD_SCHEMA[table];
    var sealed = Array.isArray(s.seal) ? s.seal : [];
    b.cryptoField.registerTable(table, {
      sealedFields: sealed,
      // AAD-bind each sealed column to its row identity (table, _id, column,
      // schemaVersion). Only meaningful when the table has sealed columns;
      // rowIdField is HS's universal "_id" primary key.
      aad: sealed.length > 0,
      rowIdField: "_id",
      schemaVersion: SEAL_SCHEMA_VERSION,
    });
  }
}

module.exports = { sealDoc, unsealDoc, lookupHash, getSealedFields, FIELD_SCHEMA, registerWithBlamejs };
