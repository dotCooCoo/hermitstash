/**
 * How each field of each table is protected: sealed, one-way hashed, an Argon2
 * password hash handled elsewhere, or raw.
 *
 * A derived field is a blind index computed from a sealed source as a keyed MAC
 * — emailHash from email, shareIdHash from shareId, and so on.
 *
 * Routes pass and receive PLAINTEXT. No route should call vault.seal() or
 * compute a blind index for a database field itself.
 */
var b = require("./vendor/blamejs");
var vault = require("./vault");
var { HASH_PREFIX, VAULT_PREFIX } = require("./constants");

// Lazy logger — field-crypto loads early (via lib/db.js); a top-level require of
// app/shared/logger risks load-order/circular issues. Resolved at first use.
var _loggerLazy = b.lazyRequire(function () { return require("../app/shared/logger"); });

// Bound into every sealed value's AEAD tag alongside the table, row and column.
// Bump ONLY when a column's meaning changes such that an old value must not
// decrypt into it — a bump invalidates every AAD-sealed value already stored
// and requires a re-seal migration in the same release. Adding a column is not
// that.
var SEAL_SCHEMA_VERSION = "1";

// Recover the plaintext of a sealed-column SOURCE value for derived-hash
// computation. Sources are normally plaintext (routes pass plaintext); the
// sealed branches are defensive for the rare already-sealed passthrough.
function _sourcePlain(table, column, val, rowId) {
  if (typeof val !== "string") return val;
  if (b.vault.aad.isAadSealed(val)) {
    // An AAD-sealed value can only be unsealed with its rowId. Without one we
    // cannot recover the plaintext, and returning the ciphertext would derive a
    // blind index over ciphertext bytes — silently un-matchable against a lookup
    // that hashes the plaintext. Refuse rather than corrupt the index.
    if (rowId == null) {
      throw new Error("field-crypto: cannot derive an index from an already-sealed " + table + "." + column + " value without its rowId");
    }
    return b.vault.aad.unseal(val, b.vault.aad.buildColumnAad({
      table: table, rowId: String(rowId), column: column, schemaVersion: SEAL_SCHEMA_VERSION,
    }));
  }
  if (val.indexOf(VAULT_PREFIX) === 0) return vault.unseal(val);
  return val;
}

// Anything not listed is raw. A field is left raw ONLY because a WHERE clause
// needs it; everything else is sealed, and a sealed field needing lookups gets
// a derived index.
var FIELD_SCHEMA = {
  users: {
    // raw: _id, status, role, failedLoginAttempts, lockedUntil, createdAt, lastLogin | needed for SQL queries and arithmetic
    // raw: quotaBytes, maxFileSize, maxFiles, maxBundleSize | per-user upload-limit overrides, integers used in arithmetic (like customer_stash's)
    seal: ["email", "pendingEmail", "displayName", "avatar", "googleId", "tailscaleId", "passwordHash", "authType", "vaultEnabled", "vaultPublicKey", "vaultStealth", "vaultMode", "vaultSeed", "totpLastStep", "totpSecret", "totpEnabled", "totpBackupCodes", "totpAlgorithm", "allowedExtensions"],
    derived: {
      emailHash: { from: "email", prefix: HASH_PREFIX.EMAIL, lower: true },
      // Blind index for Sign-in-with-Tailscale lookups. tailscaleId is the stable
      // tailnet login identity (namespaced <login>@<tailnet>); lower:true so the
      // lookup is case-insensitive like email.
      tailscaleIdHash: { from: "tailscaleId", prefix: HASH_PREFIX.TAILSCALE_ID, lower: true },
    },
  },
  files: {
    // raw: _id, status, vaultEncrypted, uploadedBy, bundleId, teamId, size, downloads, createdAt, updatedAt, seq, deletedAt | needed for SQL queries, arithmetic, and sync change feed
    seal: ["shareId", "originalName", "relativePath", "storagePath", "mimeType", "uploaderEmail", "uploaderName", "encryptionKey", "bundleShareId", "expiresAt", "vaultEncapsulatedKey", "vaultIv", "vaultBatchId", "vaultBatchName", "checksum"],
    derived: {
      shareIdHash: { from: "shareId", prefix: HASH_PREFIX.SHARE_ID },
      emailHash: { from: "uploaderEmail", prefix: HASH_PREFIX.EMAIL, lower: true },
      bundleShareIdHash: { from: "bundleShareId", prefix: HASH_PREFIX.SHARE_ID },
    },
  },
  bundles: {
    // skippedFiles carries relative paths, which are content rather than
    // anything queryable, so it seals like allowedEmails — both JSON columns,
    // which _merge unseals before parsing.
    seal: ["shareId", "uploaderName", "uploaderEmail", "message", "passwordHash", "expiresAt", "finalizeTokenHash", "stashId", "bundleName", "allowedEmails", "skippedFiles"],
    derived: {
      shareIdHash: { from: "shareId", prefix: HASH_PREFIX.SHARE_ID },
      emailHash: { from: "uploaderEmail", prefix: HASH_PREFIX.EMAIL, lower: true },
    },
  },
  audit_log: {
    // The chain columns stay raw: verification recomputes rowHash over the
    // stored row and orders by the integer counter, and sealing either would
    // break it. `ip` is sealed, but what it holds depends on AUDIT_IP_FULL —
    // by default a one-way hash, so unsealing yields the hash, not an address.
    seal: ["action", "targetId", "targetEmail", "performedBy", "performedByEmail", "details", "ip", "path", "userAgent"],
  },
  blocked_ips: {
    hash: ["ip"],
    seal: ["reason", "blockedBy"],
  },
  api_keys: {
    // raw: keyHash, certFingerprint (already SHA3 hashes — sealing would break the
    //   hash-equality compare each is looked up / bound by), userId (FK lookup)
    seal: ["name", "prefix", "permissions", "lastUsed", "boundStashId", "boundBundleId", "certIssuedAt", "certExpiresAt"],
  },
  webhooks: {
    // raw: active | needed for SQL query (findActive)
    seal: ["url", "events", "secret", "createdBy", "lastTriggered"],
  },
  customer_stash: {
    // raw: maxFileSize, maxFiles, maxBundleSize, defaultExpiry, bundleCount, totalBytes (integers used in arithmetic)
    // raw: accessMode, syncEnabled (enums/flags), maxFileSize, maxFiles, maxBundleSize, defaultExpiry, bundleCount, totalBytes (integers)
    // raw: teamId (FK — team-scoped stash; uploads inherit it onto bundles + files for team-shared access)
    seal: ["slug", "name", "title", "subtitle", "passwordHash", "allowedExtensions", "allowedEmails", "accentColor", "logoUrl", "createdBy", "enabled", "syncBundleId"],
    derived: {
      slugHash: { from: "slug", prefix: HASH_PREFIX.SLUG },
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
  stash_members: {
    // raw: stashId, userId (FK lookups for stash membership queries)
    seal: ["addedAt"],
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
      emailHash: { from: "email", prefix: HASH_PREFIX.EMAIL, lower: true },
      codeHash: { from: "code", prefix: HASH_PREFIX.ACCESS_CODE },
    },
  },
  bundle_access_log: {
    // raw: bundleShareId (indexed lookup), accessedAt
    seal: ["email", "ip"],
    derived: {
      emailHash: { from: "email", prefix: HASH_PREFIX.EMAIL, lower: true },
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

// A derived column is the indexed lookup key for a sealed source. It is a keyed
// MAC under the vault's per-deployment key, so an attacker holding an
// exfiltrated database, backup or replica cannot recompute the index from a
// guessed plaintext (CWE-916 / CWE-759).
//
// The "hmac-shake256" mode is mandatory. The default salted mode keys off a
// salt stored in plaintext in the data directory, which an exfiltrated database
// carries too — it would not close that gap at all.
//
// Rows written before the key existed carry an unkeyed digest, recomputable
// from the plaintext alone. derivedLegacy reproduces it so lookups match both
// forms until lib/derived-hash-backfill has rewritten those rows.
//
// blocked_ips.ip is deliberately not keyed: it stores no plaintext to re-derive
// from, so it cannot be backfilled, and a blocked address is not the at-rest
// personal data this index exists to protect.
function _normForHash(value, lower) {
  var s = String(value);
  return lower ? s.toLowerCase() : s;
}

function derivedKeyed(prefix, value, lower) {
  return b.cryptoField.computeNamespacedHash(prefix, _normForHash(value, lower), { mode: "hmac-shake256" });
}

function derivedLegacy(prefix, value, lower) {
  return b.crypto.namespaceHash(prefix, _normForHash(value, lower));
}

/**
 * Plaintext document in, sealed document out.
 *
 * Sealing is AEAD-bound to the row's identity, so an attacker with database
 * write access cannot copy a sealed value into another row or column and have
 * it decrypt. The derived and one-way hashes stay computed here, because their
 * stored bytes have to stay identical for the indexed lookups to work.
 */
function sealDoc(table, doc, rowId) {
  var schema = FIELD_SCHEMA[table];
  if (!schema) return doc;
  var result = Object.assign({}, doc);
  if (rowId != null) result._id = rowId;

  // A write always stores the keyed digest; lookupHash is what still resolves
  // the legacy one. A falsy source yields a null index, never a digest.
  if (schema.derived) {
    for (var dk in schema.derived) {
      var def = schema.derived[dk];
      var sourceVal = result[def.from];
      if (sourceVal !== undefined && sourceVal !== null) {
        var plain = _sourcePlain(table, def.from, sourceVal, result._id);
        result[dk] = plain ? derivedKeyed(def.prefix, plain, def.lower) : null;
      }
    }
  }

  // Two kinds of value are withheld from sealRow and restored verbatim.
  //   1. A non-string falsy — false, 0, NaN. A few sealed columns hold one in
  //      practice, and sealing would coerce it to a string and change its type.
  //   2. An already-sealed value. Double-sealing throws, and sealRow does not
  //      skip a legacy envelope, so a pre-sealed column would be nested and
  //      corrupted. Those stay in their existing scheme until their write path
  //      starts passing plaintext.
  //
  // An empty string is deliberately NOT withheld. It seals to a real envelope
  // that round-trips back to "", whereas a bare "" in an AAD-bound column is
  // treated on read as an envelope downgrade and fails closed to null.
  var passthrough = null;
  if (schema.seal) {
    for (var i = 0; i < schema.seal.length; i++) {
      var field = schema.seal[i];
      var v = result[field];
      if (v === undefined || v === null) continue;   // sealRow skips these; nothing to restore
      if ((!v && v !== "") ||
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
 * Sealed document in, plaintext document out.
 *
 * Reads both the AAD-sealed and legacy envelopes, and fails closed on an AEAD
 * mismatch — nulling the field rather than returning attacker-crafted
 * ciphertext.
 */
function unsealDoc(table, doc, rowId) {
  if (!doc) return doc;
  var schema = FIELD_SCHEMA[table];
  if (!schema || !schema.seal || schema.seal.length === 0) return doc;
  if (rowId != null && (doc._id === undefined || doc._id === null)) {
    doc = Object.assign({}, doc, { _id: rowId });
  }
  var out;
  try {
    // The row _id keys the unseal-failure cooldown per row. Without it every
    // call shares one actor, so a single corrupt row trips the cap for every
    // user's reads of that column.
    out = b.cryptoField.unsealRow(table, doc, doc._id != null ? String(doc._id) : undefined);
  } catch (e) {
    // A tripped rate cap throws rather than returning a row, and every read
    // runs through here inside a map with no try/catch around it — so the throw
    // would escape as a 500, letting an attacker who plants a few forged
    // envelopes in one column break every read of it for the cooldown.
    try {
      _loggerLazy().error("sealed-row unseal threw — failing closed", {
        table: table, rowId: doc._id || null, error: e && e.message,
      });
    } catch (_e2) { /* logging must never break a read */ }
    out = Object.assign({}, doc);
    for (var sk = 0; sk < schema.seal.length; sk++) {
      var scol = schema.seal[sk];
      var sval = doc[scol];
      if (typeof sval === "string" && (sval.indexOf(VAULT_PREFIX) === 0 || b.vault.aad.isAadSealed(sval))) {
        out[scol] = null;
      }
    }
    return out;
  }

  // unsealRow's own audit for this is silenced in the running server, so the
  // failure is surfaced here instead. A column whose input was sealed and whose
  // output is null is a genuine failure, because sealed plaintext is never
  // empty — falsy values are stored raw. Logged, never written to audit_log:
  // this runs inside find() loops, where a database write risks re-entrancy and
  // would amplify the attack.
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
  if (!schema) return null;
  if (schema.derived) {
    for (var dk in schema.derived) {
      if (schema.derived[dk].from === field) {
        var def = schema.derived[dk];
        // Matches the write contract, which stores a null index rather than a
        // digest of "" — otherwise every empty-source row collides on a unique
        // index. Returning a digest here would fabricate one no stored row can
        // match, so signal "not a blind-index match" instead.
        if (!value) return null;
        var keyed = derivedKeyed(def.prefix, value, def.lower);
        var legacy = derivedLegacy(def.prefix, value, def.lower);
        // Dual-read: match both the active keyed-MAC digest and the legacy
        // unkeyed digest so rows the boot backfill has not yet rewritten still
        // resolve. `value` is the keyed digest (what new writes store);
        // `candidates` drives the SQL IN (...) match in db._translateQuery.
        return { key: dk, value: keyed, candidates: keyed === legacy ? [keyed] : [keyed, legacy] };
      }
    }
  }
  // One-way "hash" fields (e.g. blocked_ips.ip) are hashed on write, so a
  // findOne({ ip }) must translate the raw value to the same digest or the
  // lookup never matches the stored hash. (Tables with `hash` fields need not
  // have any `derived` fields, so this runs independently of the loop above.)
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
      // Dual-read window: a legacy plain "vault:" cell (written before AAD
      // binding, or before the boot backfill reseals it to "vault.aad:") is
      // still accepted on an AAD-bound column rather than nulled. HS's
      // sealDoc/unsealDoc + the boot backfill migrate those cells up to bound
      // ciphertext; this keeps an upgrading deployment readable until that
      // completes. Clear it once every deployment is confirmed migrated.
      allowPlainMigration: true,
    });
  }
}

module.exports = { sealDoc, unsealDoc, lookupHash, getSealedFields, FIELD_SCHEMA, registerWithBlamejs, derivedKeyed, unsealSource: _sourcePlain };
