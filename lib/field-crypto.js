/**
 * Field-level crypto schema.
 *
 * Defines how each field in each table is protected:
 *   - "seal"   → vault.seal() on write, vault.unseal() on read
 *   - "hash"   → sha3Hash() on write (one-way, for indexed lookup)
 *   - "argon2" → password hash (handled externally, not auto-processed)
 *   - "raw"    → stored as-is (IDs, timestamps, counters, enums)
 *
 * Derived fields are auto-computed from source fields:
 *   emailHash ← sha3Hash(HASH_PREFIX.EMAIL + email)
 *   shareIdHash ← sha3Hash(HASH_PREFIX.SHARE_ID + shareId)
 *
 * Routes pass PLAINTEXT. This layer seals on write, unseals on read.
 * No route should ever call vault.seal() or sha3Hash() directly for DB fields.
 */
var vault = require("./vault");
var { sha3Hash } = require("./crypto");
var { HASH_PREFIX, VAULT_PREFIX } = require("./constants");

// Field classification per table
// Fields not listed here are "raw" (stored as-is)
var FIELD_SCHEMA = {
  users: {
    seal: ["email", "displayName", "avatar", "googleId", "vaultSeed"],
    derived: { emailHash: { from: "email", fn: function (v) { return v ? sha3Hash(HASH_PREFIX.EMAIL + String(v).toLowerCase()) : null; } } },
  },
  files: {
    seal: ["shareId", "originalName", "relativePath", "storagePath", "mimeType", "uploaderEmail", "encryptionKey", "bundleShareId"],
    derived: {
      shareIdHash: { from: "shareId", fn: function (v) { return v ? sha3Hash(HASH_PREFIX.SHARE_ID + v) : null; } },
      emailHash: { from: "uploaderEmail", fn: function (v) { return v ? sha3Hash(HASH_PREFIX.EMAIL + String(v).toLowerCase()) : null; } },
      bundleShareIdHash: { from: "bundleShareId", fn: function (v) { return v ? sha3Hash(HASH_PREFIX.SHARE_ID + v) : null; } },
    },
  },
  bundles: {
    seal: ["shareId", "uploaderName", "uploaderEmail", "message"],
    derived: {
      shareIdHash: { from: "shareId", fn: function (v) { return v ? sha3Hash(HASH_PREFIX.SHARE_ID + v) : null; } },
      emailHash: { from: "uploaderEmail", fn: function (v) { return v ? sha3Hash(HASH_PREFIX.EMAIL + String(v).toLowerCase()) : null; } },
    },
  },
  audit_log: {
    seal: ["action", "targetId", "targetEmail", "performedBy", "performedByEmail", "details", "ip"],
  },
  blocked_ips: {
    hash: ["ip"],
    seal: ["reason"],
  },
  api_keys: {
    seal: ["name", "prefix", "permissions"],
  },
  webhooks: {
    seal: ["url", "events", "secret"],
  },
  credentials: {
    seal: ["credentialId", "publicKey"],
  },
  email_sends: {
    seal: ["recipient", "subject"],
  },
  teams: {
    seal: ["name"],
  },
  settings: {
    seal: ["value"],
  },
};

// Hash functions for "hash" type fields
var HASH_FNS = {
  blocked_ips: {
    ip: function (v) { return v ? sha3Hash(HASH_PREFIX.BLOCKED_IP + v) : null; },
  },
};

/**
 * Seal a document before DB write.
 * Applies vault.seal() to seal fields, hash functions to hash fields,
 * and computes derived fields from their source values.
 * Input: plaintext doc. Output: sealed doc ready for DB.
 */
function sealDoc(table, doc) {
  var schema = FIELD_SCHEMA[table];
  if (!schema) return doc;
  var result = Object.assign({}, doc);

  // Get plaintext values for derived field computation
  // (handles case where route already sealed the value)
  if (schema.derived) {
    for (var dk in schema.derived) {
      var def = schema.derived[dk];
      var sourceVal = result[def.from];
      if (sourceVal !== undefined && sourceVal !== null) {
        // If the source is already sealed, unseal to get plaintext for hashing
        var plainVal = (String(sourceVal).startsWith(VAULT_PREFIX)) ? vault.unseal(sourceVal) : sourceVal;
        result[dk] = def.fn(plainVal);
      }
    }
  }

  // Seal fields (vault.seal() skips already-sealed values)
  if (schema.seal) {
    for (var i = 0; i < schema.seal.length; i++) {
      var field = schema.seal[i];
      if (result[field] !== undefined && result[field] !== null) {
        result[field] = vault.seal(String(result[field]));
      }
    }
  }

  // Hash fields (one-way)
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
 * Applies vault.unseal() to all seal fields.
 * Input: sealed doc from DB. Output: plaintext doc.
 */
function unsealDoc(table, doc) {
  if (!doc) return doc;
  var schema = FIELD_SCHEMA[table];
  if (!schema || !schema.seal) return doc;
  var result = Object.assign({}, doc);

  for (var i = 0; i < schema.seal.length; i++) {
    var field = schema.seal[i];
    if (result[field]) {
      result[field] = vault.unseal(result[field]) || result[field];
    }
  }

  return result;
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

module.exports = { sealDoc, unsealDoc, lookupHash, getSealedFields, FIELD_SCHEMA };
