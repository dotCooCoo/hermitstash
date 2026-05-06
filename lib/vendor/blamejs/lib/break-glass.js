"use strict";
/**
 * break-glass — column-policy / row-enforcement step-up auth.
 *
 * Operator declares which columns of which tables are GLASS-LOCKED.
 * Reading the encrypted value on any row of a glass-locked column
 * requires the calling operator to:
 *
 *   1. Prove identity with a second factor (TOTP / passkey).
 *   2. Provide an operator-supplied REASON the audit chain captures.
 *   3. Hold a short-lived, scope-bounded GRANT.
 *
 * Each row read under a grant emits a per-row audit event. Default
 * `maxRowsPerGrant: 1` enforces row-by-row auth — each row access is
 * its own discrete authenticated event, compliance-defensible by
 * construction. Operators with batch workflows raise the cap per-table.
 *
 * Spec: memory/specs/blamejs-break-glass-spec.md
 *
 * Ships Model A (policy gate) + TOTP factor + config-time input
 * validation + 14 error codes + audit chain integration. Model B
 * (cryptographic gate via per-row K_row), passkey factor, service-
 * account bypass, and admin tools land in subsequent patches.
 *
 * Public API:
 *
 *   b.breakGlass.init({ now? })             — boot once
 *   b.breakGlass.policy.set(table, opts)
 *   b.breakGlass.policy.get(table)          — null if unset
 *   b.breakGlass.policy.list()
 *   b.breakGlass.policy.delete(table)
 *
 *   b.breakGlass.grant({ req, table, reason, factor, columns? })
 *   b.breakGlass.unsealRow(grant, table, rowId)
 *   b.breakGlass.revoke(grantId, { reason })
 *   b.breakGlass.listActive({ req })
 *
 *   b.breakGlass.BreakGlassError
 */
var audit = require("./audit");
var C = require("./constants");
var cache = require("./cache");
var clusterStorage = require("./cluster-storage");
var { generateBytes, generateToken, kdf, sha3Hash, encryptPacked, decryptPacked } = require("./crypto");
var cryptoField = require("./crypto-field");
var lazyRequire = require("./lazy-require");
var observability = require("./observability");
var requestHelpers = require("./request-helpers");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var safeSql = require("./safe-sql");
var totp = require("./totp");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var vault = lazyRequire(function () { return require("./vault"); });

var lockout = lazyRequire(function () { return require("./auth/lockout"); });
var passkey = lazyRequire(function () { return require("./auth/passkey"); });

// Errors — all 14 codes documented in the spec. `permanent: true`
// means caller's input is bad (config-time / call-site reject);
// `permanent: false` means transient (factor failed, rate-limited)
// — caller may retry.
var BreakGlassError = defineClass("BreakGlassError", { alwaysPermanent: false });

// ---- Defaults (matched to operator-locked decisions) ----

// Symmetric byte counts: 32-byte cell-key (kdf output, XChaCha20 key
// length); 32-byte DEK (AEAD key); 16-byte grant-id randomness (128-bit
// uniqueness for cross-table grant lookups). All routed through C.BYTES
// so the framework's byte math has a single source of truth.
var CELL_KEY_BYTES          = C.BYTES.bytes(32);
var DEK_BYTES               = C.BYTES.bytes(32);
var GRANT_ID_BYTES          = C.BYTES.bytes(16);

var DEFAULT_GRANT_TTL_MS    = C.TIME.minutes(15);
var DEFAULT_MAX_ROWS        = 1;       // operator-locked: row-by-row auth
var DEFAULT_REASON_MIN_LEN  = 12;
var DEFAULT_LOCKED_BEHAVIOR = "throw"; // or "redact"
var DEFAULT_AUDIT_REASON    = "cleartext";
var ALLOWED_FACTORS         = ["totp", "passkey"];
var ALLOWED_REASON_STORAGE  = ["cleartext", "hmac", "both"];

// In-memory policy cache. Cluster-shared via the policies table; the
// cache short-circuits the DB roundtrip on the unsealRow hot path.
// Populated on first access per-table; invalidated on policy.set/delete.
var policyCache = new Map();    // table -> policy
var initialized = false;
// Framework-wide trustProxy setting (set at init). When true, the
// break-glass primitive consults X-Forwarded-For to populate the
// grant row's `ip` field — same trust boundary as middleware.
var _trustProxy = false;

// Factor lockout — wrap auth.lockout so a hostile actor brute-forcing
// TOTP codes against break-glass gets shut out after a few failures.
// Lazy-init on first grant attempt so init() doesn't require the
// cache primitive to be wired before break-glass loads.
var _factorLockout = null;
var _factorLockoutCache = null;
function _ensureFactorLockout() {
  if (_factorLockout) return _factorLockout;
  _factorLockoutCache = cache.create({
    namespace: "breakglass.factor",
    backend:   "memory",
  });
  _factorLockout = lockout().create({
    namespace:   "breakglass.factor",
    cache:       _factorLockoutCache,
    maxAttempts: 5,
    windowMs:    C.TIME.minutes(15),
    audit:       audit,
  });
  return _factorLockout;
}

// ---- Cryptographic mode (Model B) — per-cell encryption with context binding ----
//
// Each policy in cryptographic mode has a per-policy DEK (data
// encryption key) generated at first use. The DEK is vault-sealed so
// it survives restarts. At cell encrypt time, the framework derives a
// per-cell key K_cell = SHAKE256(DEK || table || rowId || column) so
// every (table, rowId, column) triple gets a unique key. Encryption
// uses XChaCha20-Poly1305 with AAD = SHA3-512(table || rowId || column)
// — the AEAD tag itself is bound to the encryption context, so a
// ciphertext from row A literally cannot be decrypted as row B even
// with the same DEK.
//
// THREAT MODEL HONESTY: this provides defense-in-depth via per-cell
// keys + encryption-context binding (cross-cell tampering / accidental
// row-swap fails closed). It does NOT defend against vault-key
// compromise alone — the DEK is still vault-recoverable. True
// second-factor cryptographic gating ships in v0.5.2 with passkey
// integration (the passkey private key lives on the YubiKey, not in
// the framework, so a vault leak alone can't unwrap).

// In-memory DEK cache. Keyed by table name. Cleared on _resetForTest.
var dekCache = new Map();

function _aadFor(table, rowId, column) {
  return sha3Hash(table + "|" + String(rowId) + "|" + column);
}

function _kCell(dek, table, rowId, column) {
  return kdf(Buffer.concat([
    Buffer.isBuffer(dek) ? dek : Buffer.from(dek, "base64"),
    Buffer.from("breakglass.cell|" + table + "|" + String(rowId) + "|" + column, "utf8"),
  ]), CELL_KEY_BYTES);
}

async function _ensureDek(table) {
  if (dekCache.has(table)) return dekCache.get(table);
  // DEK is vault-sealed and stored in the policy row's `dekSealed`
  // column. Generated lazily on first use of cryptographic-mode for
  // the table. Cached in-memory after first read.
  var rows = await clusterStorage.executeAll(
    "SELECT dekSealed FROM _blamejs_break_glass_policies WHERE tableName = ?",
    [table]
  );
  if (!rows || rows.length === 0) {
    throw new BreakGlassError("breakglass/policy-not-set",
      "_ensureDek: no policy for table '" + table + "'", true);
  }
  var sealed = rows[0].dekSealed;
  var dek;
  if (sealed) {
    dek = Buffer.from(vault().unseal(sealed), "base64");
  } else {
    dek = generateBytes(DEK_BYTES);
    var sealedDek = vault().seal(dek.toString("base64"));
    await clusterStorage.execute(
      "UPDATE _blamejs_break_glass_policies SET dekSealed = ? WHERE tableName = ?",
      [sealedDek, table]
    );
  }
  dekCache.set(table, dek);
  return dek;
}

// Encrypt a single cell value with encryption context binding. Operators
// in cryptographic mode use this at write time INSTEAD of letting
// cryptoField.sealRow seal the column.
async function encryptCell(plaintext, ctx) {
  _requireInit();
  if (!ctx || typeof ctx !== "object" ||
      typeof ctx.table !== "string" || ctx.table.length === 0 ||
      ctx.rowId === undefined || ctx.rowId === null ||
      typeof ctx.column !== "string" || ctx.column.length === 0) {
    throw new BreakGlassError("breakglass/bad-cell-ctx",
      "encryptCell: ctx must be { table, rowId, column }");
  }
  var policy = await policyGet(ctx.table);
  if (!policy || !policy.cryptographic) {
    throw new BreakGlassError("breakglass/policy-not-set",
      "encryptCell: table '" + ctx.table + "' is not in cryptographic mode " +
      "(set policy.cryptographic = true to opt in)", true);
  }
  if (policy.columns.indexOf(ctx.column) === -1) {
    throw new BreakGlassError("breakglass/grant-column-mismatch",
      "encryptCell: column '" + ctx.column + "' is not glass-locked on '" + ctx.table + "'", true);
  }
  var dek = await _ensureDek(ctx.table);
  var kCell = _kCell(dek, ctx.table, ctx.rowId, ctx.column);
  var aad = _aadFor(ctx.table, ctx.rowId, ctx.column);
  var pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), "utf8");
  var packed = encryptPacked(pt, kCell, aad);
  return "bgcell:1:" + packed.toString("base64");
}

// Decrypt a cell value. Caller must hold a valid grant covering the
// (table, column) — caller passes through unsealRow which gates this.
// The encryption context (table, rowId, column) is passed both to the
// key derivation AND the AAD; if the caller passes the wrong rowId
// trying to "swap" ciphertexts between rows, decryption fails closed.
async function decryptCell(ciphertext, ctx) {
  _requireInit();
  if (typeof ciphertext !== "string" || ciphertext.indexOf("bgcell:1:") !== 0) {
    throw new BreakGlassError("breakglass/bad-ciphertext",
      "decryptCell: expected 'bgcell:1:<base64>' format");
  }
  if (!ctx || typeof ctx !== "object") {
    throw new BreakGlassError("breakglass/bad-cell-ctx",
      "decryptCell: ctx must be { table, rowId, column }");
  }
  var dek = await _ensureDek(ctx.table);
  var kCell = _kCell(dek, ctx.table, ctx.rowId, ctx.column);
  var aad = _aadFor(ctx.table, ctx.rowId, ctx.column);
  var packed = Buffer.from(ciphertext.slice("bgcell:1:".length), "base64");
  return decryptPacked(packed, kCell, aad).toString("utf8");
}

// ---- Migration support ----
//
// Operator runs `b.breakGlass.migrate(table, opts)` (or the CLI
// equivalent) to convert existing Model-A-sealed rows into Model B
// per-cell-encrypted form. Each row's glass-locked columns are
// unsealed via cryptoField, re-encrypted via encryptCell, and written
// back. The migration is idempotent — a row already in Model B form
// (column starts with "bgcell:") is skipped.

async function migrate(table, opts) {
  _requireInit();
  opts = opts || {};
  validateOpts(opts, ["batchSize", "callerOpts"], "breakGlass.migrate");
  var policy = await policyGet(table);
  if (!policy) {
    throw new BreakGlassError("breakglass/policy-not-set",
      "migrate: no policy for table '" + table + "'", true);
  }
  if (!policy.cryptographic) {
    throw new BreakGlassError("breakglass/bad-policy",
      "migrate: policy must be cryptographic: true to migrate to Model B", true);
  }
  var batchSize = opts.batchSize || 100;
  var totalRows = 0;
  var migratedRows = 0;
  var skippedRows = 0;
  var lastId = "";
  // Iterate via _id-keyset paging so we don't load the whole table into memory.
  while (true) {
    // table is already validated as a safe identifier shape via
    // _validatePolicySet — wrap in "..." per the framework's
    // identifier-quoting convention.
    var qTable = '"' + table + '"';
    var rows = await clusterStorage.executeAll(
      "SELECT * FROM " + qTable + " WHERE _id > ? ORDER BY _id ASC LIMIT ?",
      [lastId, batchSize]
    );
    if (!rows || rows.length === 0) break;
    for (var i = 0; i < rows.length; i++) {
      totalRows++;
      var row = rows[i];
      var unsealed = cryptoField.unsealRow(table, row);
      var anyChanged = false;
      var update = { _id: row._id };
      for (var c = 0; c < policy.columns.length; c++) {
        var col = policy.columns[c];
        var current = unsealed[col];
        if (current == null) continue;
        if (typeof current === "string" && current.indexOf("bgcell:") === 0) {
          continue;  // already migrated
        }
        var encrypted = await encryptCell(current, { table: table, rowId: row._id, column: col });
        update[col] = encrypted;
        anyChanged = true;
      }
      if (anyChanged) {
        // Write Model B ciphertext directly — bypassing cryptoField so
        // the cell ciphertext stays as a literal string, not double-sealed.
        var setCols = Object.keys(update).filter(function (k) { return k !== "_id"; });
        if (setCols.length > 0) {
          // Column names came from the validated policy.columns —
          // also wrap each in "..." for the same identifier-quoting
          // convention.
          var setSql = setCols.map(function (k) { return '"' + k + '" = ?'; }).join(", ");
          var vals = setCols.map(function (k) { return update[k]; });
          vals.push(row._id);
          await clusterStorage.execute(
            "UPDATE " + qTable + " SET " + setSql + " WHERE _id = ?",
            vals
          );
          migratedRows++;
        }
      } else {
        skippedRows++;
      }
      lastId = row._id;
    }
    if (rows.length < batchSize) break;
  }
  audit.safeEmit({
    action:   "breakglass.migrate",
    outcome:  "success",
    actor:    requestHelpers.resolveActorWithOverride(opts.callerOpts),
    metadata: {
      table:        table,
      totalRows:    totalRows,
      migratedRows: migratedRows,
      skippedRows:  skippedRows,
    },
  });
  return { table: table, totalRows: totalRows, migratedRows: migratedRows, skippedRows: skippedRows };
}

// ---- init ----

function init(opts) {
  opts = opts || {};
  validateOpts(opts, ["now", "trustProxy"], "breakGlass.init");
  initialized = true;
  policyCache.clear();
  _factorLockout = null;
  _trustProxy = opts.trustProxy === true || typeof opts.trustProxy === "number"
    ? opts.trustProxy : false;
}

function _resetForTest() {
  initialized = false;
  policyCache.clear();
  dekCache.clear();
  if (_factorLockoutCache && typeof _factorLockoutCache.close === "function") {
    try { _factorLockoutCache.close(); } catch (_e) { /* best-effort */ }
  }
  _factorLockout = null;
  _factorLockoutCache = null;
  _trustProxy = false;
}

function _requireInit() {
  if (!initialized) {
    throw new BreakGlassError("breakglass/not-initialized",
      "b.breakGlass.init() must be called before use");
  }
}

// ---- Policy CRUD ----

function _validatePolicySet(table, opts) {
  if (typeof table !== "string" || table.length === 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: table must be a non-empty string");
  }
  // Identifier safety: the table name flows raw into SQL via interpolation
  // in migrate() / unsealRowAsService(). safeSql.validateIdentifier closes
  // the shape so a malicious / mistyped name with embedded `"` or
  // SQL-keyword shape can't break out of the wrapping quotes.
  // allowReserved: true because every interpolation site quotes the
  // identifier, so reserved-word names work via the SQL standard quoting
  // rule.
  try {
    safeSql.validateIdentifier(table, { allowReserved: true });
  } catch (e) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: table '" + table + "' is not a valid SQL identifier: " +
      ((e && e.message) || String(e)));
  }
  if (!opts || typeof opts !== "object") {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: opts is required");
  }
  validateOpts(opts, [
    "columns", "factors", "cryptographic", "grantTtl", "maxRowsPerGrant",
    "reasonRequired", "reasonMinLength", "pinIp", "sessionPin",
    "onLockedAccess", "requireScope", "serviceAccountBypass",
    "auditReasonStorage",
  ], "breakglass.policy.set");
  if (!Array.isArray(opts.columns) || opts.columns.length === 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: columns must be a non-empty array");
  }
  for (var i = 0; i < opts.columns.length; i++) {
    var colName = opts.columns[i];
    if (typeof colName !== "string" || colName.length === 0) {
      throw new BreakGlassError("breakglass/bad-policy",
        "policy.set: columns[" + i + "] must be a non-empty string");
    }
    // Same identifier-shape check as the table — column names flow into
    // the migrate() UPDATE statement as bare names.
    try {
      safeSql.validateIdentifier(colName, { allowReserved: true });
    } catch (e) {
      throw new BreakGlassError("breakglass/bad-policy",
        "policy.set: columns[" + i + "]='" + colName + "' is not a valid SQL identifier: " +
        ((e && e.message) || String(e)));
    }
  }
  if (!Array.isArray(opts.factors) || opts.factors.length === 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: factors must be a non-empty array");
  }
  for (var j = 0; j < opts.factors.length; j++) {
    if (ALLOWED_FACTORS.indexOf(opts.factors[j]) === -1) {
      throw new BreakGlassError("breakglass/bad-policy",
        "policy.set: factors[" + j + "] '" + opts.factors[j] +
        "' not in v0.5.0 allowed factors [" + ALLOWED_FACTORS.join(",") + "]" +
        " (passkey lands in v0.5.2)");
    }
  }
  // Model B (cryptographic mode) ships in v0.5.1. When enabled,
  // glass-locked columns must be encrypted with `b.breakGlass.encryptCell`
  // at write time (the framework can't auto-encrypt at write because
  // policy-set may post-date existing data; operators run the migration
  // CLI to convert existing rows). At unseal time, the row's
  // glass-locked columns are decrypted via decryptCell with encryption
  // context binding (table, rowId, column).
  validateOpts.optionalBoolean(opts.cryptographic, "policy.set: cryptographic", BreakGlassError, "breakglass/bad-policy");
  var grantTtl = opts.grantTtl != null ? opts.grantTtl : DEFAULT_GRANT_TTL_MS;
  if (typeof grantTtl !== "number" || !isFinite(grantTtl) || grantTtl <= 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: grantTtl must be a positive number of milliseconds");
  }
  var maxRows = opts.maxRowsPerGrant != null ? opts.maxRowsPerGrant : DEFAULT_MAX_ROWS;
  if (!Number.isInteger(maxRows) || maxRows < 1) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: maxRowsPerGrant must be a positive integer (default 1 — row-by-row auth)");
  }
  if (opts.onLockedAccess != null &&
      opts.onLockedAccess !== "throw" && opts.onLockedAccess !== "redact") {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: onLockedAccess must be 'throw' or 'redact'");
  }
  if (opts.auditReasonStorage != null &&
      ALLOWED_REASON_STORAGE.indexOf(opts.auditReasonStorage) === -1) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.set: auditReasonStorage must be one of " + ALLOWED_REASON_STORAGE.join("/"));
  }
  // Service-account bypass: explicit opt-in per table. Operators
  // declare the apiKey ids that may bypass + a required role; the
  // framework requires BOTH to grant the bypass. Without this opt set,
  // there is NO bypass path — every read of a glass-locked column
  // requires a fresh grant.
  var serviceAccountBypass = null;
  if (opts.serviceAccountBypass != null && opts.serviceAccountBypass !== false) {
    var sab = opts.serviceAccountBypass;
    if (!sab || typeof sab !== "object") {
      throw new BreakGlassError("breakglass/bad-policy",
        "policy.set: serviceAccountBypass must be an object { enabled, apiKeyIds, requireRole }");
    }
    if (sab.enabled !== true) {
      throw new BreakGlassError("breakglass/bad-policy",
        "policy.set: serviceAccountBypass.enabled must be true (set serviceAccountBypass: false to disable)");
    }
    if (!Array.isArray(sab.apiKeyIds) || sab.apiKeyIds.length === 0) {
      throw new BreakGlassError("breakglass/bad-policy",
        "policy.set: serviceAccountBypass.apiKeyIds must be a non-empty array of apiKey ids");
    }
    if (typeof sab.requireRole !== "string" || sab.requireRole.length === 0) {
      throw new BreakGlassError("breakglass/bad-policy",
        "policy.set: serviceAccountBypass.requireRole must be a non-empty role / scope string");
    }
    serviceAccountBypass = {
      enabled:     true,
      apiKeyIds:   sab.apiKeyIds.slice(),
      requireRole: sab.requireRole,
    };
  }
  return {
    cryptographic:   opts.cryptographic === true,
    grantTtl:        grantTtl,
    maxRowsPerGrant: maxRows,
    reasonRequired:  opts.reasonRequired !== false,
    reasonMinLength: opts.reasonMinLength != null ? opts.reasonMinLength : DEFAULT_REASON_MIN_LEN,
    pinIp:           opts.pinIp !== false,
    sessionPin:      opts.sessionPin !== false,
    onLockedAccess:  opts.onLockedAccess || DEFAULT_LOCKED_BEHAVIOR,
    requireScope:    opts.requireScope != null ? opts.requireScope : null,
    auditReasonStorage: opts.auditReasonStorage || DEFAULT_AUDIT_REASON,
    serviceAccountBypass: serviceAccountBypass,
  };
}

async function policySet(table, opts, callerOpts) {
  _requireInit();
  var validated = _validatePolicySet(table, opts);
  var policyRow = {
    tableName:                table,
    columnsJson:              JSON.stringify(opts.columns),
    factorsJson:              JSON.stringify(opts.factors),
    cryptographic:            validated.cryptographic ? 1 : 0,
    grantTtlMs:               validated.grantTtl,
    maxRowsPerGrant:          validated.maxRowsPerGrant,
    reasonRequired:           validated.reasonRequired ? 1 : 0,
    reasonMinLength:          validated.reasonMinLength,
    pinIp:                    validated.pinIp ? 1 : 0,
    sessionPin:               validated.sessionPin ? 1 : 0,
    onLockedAccess:           validated.onLockedAccess,
    requireScope:             validated.requireScope,
    serviceAccountBypassJson: validated.serviceAccountBypass
      ? JSON.stringify(validated.serviceAccountBypass)
      : null,
    auditReasonStorage:       validated.auditReasonStorage,
    updatedAt:                Date.now(),
  };
  var sealed = cryptoField.sealRow("_blamejs_break_glass_policies", policyRow);
  // UPSERT — both Postgres and SQLite support ON CONFLICT.
  var keys   = Object.keys(sealed);
  var cols   = keys.join(", ");
  var qs     = keys.map(function () { return "?"; }).join(", ");
  var setSql = keys.filter(function (k) { return k !== "tableName"; })
    .map(function (k) { return k + " = excluded." + k; }).join(", ");
  var sql = "INSERT INTO _blamejs_break_glass_policies (" + cols + ") " +
            "VALUES (" + qs + ") " +
            "ON CONFLICT (tableName) DO UPDATE SET " + setSql;
  await clusterStorage.execute(sql, keys.map(function (k) { return sealed[k]; }));
  policyCache.delete(table);

  audit.safeEmit({
    action:   "breakglass.policy.set",
    outcome:  "success",
    actor:    requestHelpers.resolveActorWithOverride(callerOpts),
    metadata: {
      table:           table,
      columnCount:     opts.columns.length,
      factors:         opts.factors,
      grantTtlMs:      validated.grantTtl,
      maxRowsPerGrant: validated.maxRowsPerGrant,
    },
  });
  observability.event("breakglass.policy.set", { table: table });
  return { applied: true, table: table };
}

async function policyGet(table) {
  _requireInit();
  if (typeof table !== "string" || table.length === 0) return null;
  if (policyCache.has(table)) return policyCache.get(table);
  var rows = await clusterStorage.executeAll(
    "SELECT * FROM _blamejs_break_glass_policies WHERE tableName = ?",
    [table]
  );
  if (!rows || rows.length === 0) {
    policyCache.set(table, null);
    return null;
  }
  var unsealed = cryptoField.unsealRow("_blamejs_break_glass_policies", rows[0]);
  var policy = {
    table:              unsealed.tableName,
    columns:            safeJson.parse(unsealed.columnsJson, { maxBytes: C.BYTES.kib(64) }),
    factors:            safeJson.parse(unsealed.factorsJson, { maxBytes: C.BYTES.kib(8) }),
    cryptographic:      unsealed.cryptographic === 1,
    grantTtl:           Number(unsealed.grantTtlMs),
    maxRowsPerGrant:    Number(unsealed.maxRowsPerGrant),
    reasonRequired:     unsealed.reasonRequired === 1,
    reasonMinLength:    Number(unsealed.reasonMinLength),
    pinIp:              unsealed.pinIp === 1,
    sessionPin:         unsealed.sessionPin === 1,
    onLockedAccess:     unsealed.onLockedAccess,
    requireScope:       unsealed.requireScope,
    serviceAccountBypass: unsealed.serviceAccountBypassJson
      ? safeJson.parse(unsealed.serviceAccountBypassJson, { maxBytes: C.BYTES.kib(8) })
      : null,
    auditReasonStorage: unsealed.auditReasonStorage,
    updatedAt:          Number(unsealed.updatedAt),
  };
  policyCache.set(table, policy);
  return policy;
}

async function policyList() {
  _requireInit();
  var rows = await clusterStorage.executeAll(
    "SELECT tableName FROM _blamejs_break_glass_policies ORDER BY tableName"
  );
  var out = [];
  for (var i = 0; i < (rows || []).length; i++) {
    var p = await policyGet(rows[i].tableName);
    if (p) out.push(p);
  }
  return out;
}

async function policyDelete(table, callerOpts) {
  _requireInit();
  if (typeof table !== "string" || table.length === 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.delete: table must be a non-empty string");
  }
  await clusterStorage.execute(
    "DELETE FROM _blamejs_break_glass_policies WHERE tableName = ?",
    [table]
  );
  policyCache.delete(table);
  audit.safeEmit({
    action:   "breakglass.policy.delete",
    outcome:  "success",
    actor:    requestHelpers.resolveActorWithOverride(callerOpts),
    metadata: { table: table },
  });
  return { deleted: true, table: table };
}

// ---- Grant issuance ----

function _verifyTotpFactor(factor) {
  if (!factor || typeof factor !== "object") return { ok: false };
  if (typeof factor.secret !== "string" || factor.secret.length === 0) return { ok: false };
  if (typeof factor.code !== "string" || factor.code.length === 0)     return { ok: false };
  var verified = totp.verify(factor.secret, factor.code);
  return { ok: verified !== false, step: verified };
}

// Passkey factor — operator presents a WebAuthn assertion plus the
// challenge/origin/RPID + the previously-enrolled credential record.
// Phishing-resistant; the private key lives on the YubiKey, not in
// the framework's vault. v0.5.2 uses passkey for identity verification
// to gate grant issuance; PRF-derived per-policy DEK material (which
// would give true vault-key-alone-doesn't-decrypt defense) is a
// follow-up.
async function _verifyPasskeyFactor(factor) {
  if (!factor || typeof factor !== "object") return { ok: false };
  if (!factor.response || !factor.expectedChallenge ||
      !factor.expectedOrigin || !factor.expectedRPID || !factor.credential) {
    return { ok: false };
  }
  try {
    var result = await passkey().verifyAuthentication({
      response:                factor.response,
      expectedChallenge:       factor.expectedChallenge,
      expectedOrigin:          factor.expectedOrigin,
      expectedRPID:            factor.expectedRPID,
      credential:              factor.credential,
      requireUserVerification: factor.requireUserVerification !== false,
    });
    return { ok: result && result.verified === true };
  } catch (_e) {
    return { ok: false };
  }
}

async function grant(opts) {
  _requireInit();
  if (!opts || typeof opts !== "object") {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "grant: opts is required");
  }
  validateOpts(opts, ["req", "table", "columns", "reason", "factor"], "breakGlass.grant");

  var table = opts.table;
  var policy = await policyGet(table);
  if (!policy) {
    throw new BreakGlassError("breakglass/policy-not-set",
      "no break-glass policy is configured for table '" + table + "'", true);
  }

  // Reason validation
  var reason = typeof opts.reason === "string" ? opts.reason : "";
  if (policy.reasonRequired && reason.length === 0) {
    throw new BreakGlassError("breakglass/missing-reason",
      "grant: reason is required for table '" + table + "'", true);
  }
  if (policy.reasonRequired && reason.length < policy.reasonMinLength) {
    throw new BreakGlassError("breakglass/short-reason",
      "grant: reason must be at least " + policy.reasonMinLength + " characters", true);
  }

  // Column scoping
  var requestedColumns = Array.isArray(opts.columns) && opts.columns.length > 0
    ? opts.columns.slice()
    : policy.columns.slice();
  for (var i = 0; i < requestedColumns.length; i++) {
    if (policy.columns.indexOf(requestedColumns[i]) === -1) {
      throw new BreakGlassError("breakglass/grant-column-mismatch",
        "grant: requested column '" + requestedColumns[i] +
        "' is not glass-locked on table '" + table + "'", true);
    }
  }

  // Actor identity
  var actor = requestHelpers.extractActorContext(opts.req);
  var actorId = actor.userId || (opts.req && opts.req.apiKey && opts.req.apiKey.id) || null;
  if (!actorId) {
    throw new BreakGlassError("breakglass/unauthorized",
      "grant: no authenticated actor on request (req.user.id / req.apiKey.id required)", true);
  }

  // Scope-gate enforcement — when the policy declares requireScope,
  // the actor must carry the named scope (or matching wildcard via
  // b.permissions.match) before the framework will mint a grant.
  // Without this, every TOTP-passing actor could glass-unseal PHI
  // even when the operator explicitly declared `requireScope:
  // "phi:admin"`.
  if (policy.requireScope) {
    var actorScopes = (opts.req && opts.req.user && Array.isArray(opts.req.user.scopes))
      ? opts.req.user.scopes
      : ((opts.req && opts.req.apiKey && Array.isArray(opts.req.apiKey.scopes))
        ? opts.req.apiKey.scopes
        : []);
    var scopeOk = false;
    for (var sci = 0; sci < actorScopes.length; sci += 1) {
      if (actorScopes[sci] === policy.requireScope) { scopeOk = true; break; }
      // Wildcard support: "phi:*" matches "phi:admin" and "phi:read".
      if (typeof actorScopes[sci] === "string" &&
          actorScopes[sci].length > 0 &&
          actorScopes[sci].charAt(actorScopes[sci].length - 1) === "*") {
        var prefix = actorScopes[sci].slice(0, -1);
        if (typeof policy.requireScope === "string" &&
            policy.requireScope.indexOf(prefix) === 0) {
          scopeOk = true; break;
        }
      }
    }
    if (!scopeOk) {
      audit.safeEmit({
        action:   "breakglass.grant.requested",
        outcome:  "denied",
        actor:    actor,
        reason:   "missing-scope",
        metadata: { table: table, requireScope: policy.requireScope },
      });
      throw new BreakGlassError("breakglass/missing-scope",
        "grant: actor does not carry required scope '" + policy.requireScope + "'", true);
    }
  }

  // Factor verification + lockout
  var factorType = opts.factor && opts.factor.type;
  if (!factorType || policy.factors.indexOf(factorType) === -1) {
    throw new BreakGlassError("breakglass/bad-factor",
      "grant: factor.type must be one of [" + policy.factors.join(",") + "]");
  }
  var fl = _ensureFactorLockout();
  var lockKey = actorId;
  var locked = await fl.check(lockKey);
  if (locked && locked.locked) {
    audit.safeEmit({
      action:   "breakglass.grant.requested",
      outcome:  "denied",
      actor:    actor,
      reason:   "factor-rate-limited",
      metadata: { table: table, factorType: factorType, lockUntil: locked.lockedUntil },
    });
    throw new BreakGlassError("breakglass/factor-rate-limited",
      "grant: too many recent factor failures; locked until " +
      new Date(locked.lockedUntil).toISOString());
  }

  var factorOk = false;
  if (factorType === "totp") {
    factorOk = _verifyTotpFactor(opts.factor).ok;
  } else if (factorType === "passkey") {
    factorOk = (await _verifyPasskeyFactor(opts.factor)).ok;
  }

  if (!factorOk) {
    await fl.recordFailure(lockKey, { reason: factorType + "-bad" });
    audit.safeEmit({
      action:   "breakglass.grant.requested",
      outcome:  "denied",
      actor:    actor,
      reason:   "bad-factor",
      metadata: { table: table, factorType: factorType, columns: requestedColumns },
    });
    throw new BreakGlassError("breakglass/bad-factor",
      "grant: " + factorType + " factor verification failed");
  }
  await fl.recordSuccess(lockKey);

  // Build + persist the grant row
  var nowMs    = Date.now();
  var grantId  = "bg-" + generateToken(GRANT_ID_BYTES);
  var sessionId = (opts.req && opts.req.session && opts.req.session.id) || null;
  // Honor the framework-wide trustProxy setting from init() — same
  // boundary as middleware. Without trustProxy, X-Forwarded-For is
  // ignored as attacker-forgeable, and the grant pins to the socket
  // remoteAddress only.
  var ipFromReq = requestHelpers.clientIp(opts.req, { trustProxy: _trustProxy });

  var grantRow = {
    _id:                grantId,
    issuedToActorId:    actorId,
    factorType:         factorType,
    reasonSealed:       reason,
    scopeTable:         table,
    scopeColumnsJson:   JSON.stringify(requestedColumns),
    issuedAt:           nowMs,
    expiresAt:          nowMs + policy.grantTtl,
    maxRowsPerGrant:    policy.maxRowsPerGrant,
    rowsConsumed:       0,
    revokedAt:          null,
    sessionId:          sessionId,
    ip:                 ipFromReq,
    kwGrantHalf:        null,
  };
  var sealed = cryptoField.sealRow("_blamejs_break_glass_grants", grantRow);
  var keys = Object.keys(sealed);
  var cols = keys.join(", ");
  var qs   = keys.map(function () { return "?"; }).join(", ");
  await clusterStorage.execute(
    "INSERT INTO _blamejs_break_glass_grants (" + cols + ") VALUES (" + qs + ")",
    keys.map(function (k) { return sealed[k]; })
  );

  // Audit
  var reasonForAudit = _reasonForAudit(reason, policy.auditReasonStorage);
  audit.safeEmit({
    action:   "breakglass.grant.requested",
    outcome:  "success",
    actor:    actor,
    reason:   reasonForAudit.cleartext,
    metadata: {
      grantId:           grantId,
      table:             table,
      columns:           requestedColumns,
      factorType:        factorType,
      ttlMs:             policy.grantTtl,
      maxRowsPerGrant:   policy.maxRowsPerGrant,
      reasonHmac:        reasonForAudit.hmac,
    },
  });
  observability.event("breakGlass.grant", { table: table });

  return {
    id:             grantId,
    expiresAt:      grantRow.expiresAt,
    rowsRemaining:  policy.maxRowsPerGrant,
    scopeTable:     table,
    scopeColumns:   requestedColumns,
  };
}

function _reasonForAudit(reason, mode) {
  // HMAC variant uses SHA3-512 keyed by a stable framework-wide tag —
  // operators with multiple deployments can correlate via the hash
  // without re-deriving from the same secret. Cleartext is the default
  // (compliance reviewers WANT to read the reason).
  var out = { cleartext: null, hmac: null };
  if (mode === "cleartext" || mode === "both") out.cleartext = reason;
  if (mode === "hmac" || mode === "both") {
    out.hmac = sha3Hash("breakGlass.reason:" + reason);
  }
  return out;
}

// ---- Use a grant ----

async function unsealRow(grantHandle, table, rowId, opts) {
  _requireInit();
  if (!grantHandle || typeof grantHandle !== "object" || typeof grantHandle.id !== "string") {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "unsealRow: grant handle is required (returned from b.breakGlass.grant())");
  }
  // Optional opts.req lets the caller thread the originating request
  // into per-row audit emits so the 5 W's (ip / userAgent / sessionId /
  // requestId / method / route) populate alongside the grant's actor
  // userId. Backward-compatible — calls without opts continue to work
  // and simply audit with userId-only actor.
  opts = opts || {};
  function _actorFor(grantRow) {
    return requestHelpers.extractActorContext(opts.req, {
      userId: grantRow.issuedToActorId,
    });
  }
  if (typeof table !== "string" || table.length === 0) {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "unsealRow: table must be a non-empty string");
  }
  if (rowId === undefined || rowId === null || rowId === "") {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "unsealRow: rowId is required");
  }
  var grantRows = await clusterStorage.executeAll(
    "SELECT * FROM _blamejs_break_glass_grants WHERE _id = ?",
    [grantHandle.id]
  );
  if (!grantRows || grantRows.length === 0) {
    throw new BreakGlassError("breakglass/grant-revoked",
      "unsealRow: grant " + grantHandle.id + " not found (deleted or never issued)", true);
  }
  var sealedGrant = grantRows[0];
  var grantRow = cryptoField.unsealRow("_blamejs_break_glass_grants", sealedGrant);

  // Table mismatch
  if (grantRow.scopeTable !== table) {
    audit.safeEmit({
      action:   "breakglass.unsealrow",
      outcome:  "denied",
      actor:    _actorFor(grantRow),
      reason:   "grant-table-mismatch",
      metadata: { grantId: grantRow._id, expectedTable: grantRow.scopeTable, gotTable: table, rowId: String(rowId) },
    });
    throw new BreakGlassError("breakglass/grant-table-mismatch",
      "unsealRow: grant " + grantHandle.id + " is scoped to '" +
      grantRow.scopeTable + "', not '" + table + "'", true);
  }

  // Revoked
  if (grantRow.revokedAt) {
    throw new BreakGlassError("breakglass/grant-revoked",
      "unsealRow: grant " + grantHandle.id + " was revoked at " +
      new Date(Number(grantRow.revokedAt)).toISOString(), true);
  }

  // Expired
  if (Number(grantRow.expiresAt) <= Date.now()) {
    audit.safeEmit({
      action:   "breakglass.grant.expired",
      outcome:  "success",
      actor:    _actorFor(grantRow),
      metadata: { grantId: grantRow._id, table: table, rowsConsumed: Number(grantRow.rowsConsumed) },
    });
    throw new BreakGlassError("breakglass/grant-expired",
      "unsealRow: grant " + grantHandle.id + " expired at " +
      new Date(Number(grantRow.expiresAt)).toISOString(), true);
  }

  // Exhausted
  if (Number(grantRow.rowsConsumed) >= Number(grantRow.maxRowsPerGrant)) {
    audit.safeEmit({
      action:   "breakglass.grant.exhausted",
      outcome:  "success",
      actor:    _actorFor(grantRow),
      metadata: { grantId: grantRow._id, table: table, rowsConsumed: Number(grantRow.rowsConsumed) },
    });
    throw new BreakGlassError("breakglass/grant-exhausted",
      "unsealRow: grant " + grantHandle.id + " has consumed all " +
      grantRow.maxRowsPerGrant + " allowed rows", true);
  }

  // SELECT-before-increment — fetch the target row FIRST. If the row
  // doesn't exist (operator typo, race with row-deletion, etc.), the
  // grant should not be consumed. Without this ordering, a single
  // typo against `maxRowsPerGrant: 1` (the default) exhausts the
  // grant and forces the operator to re-do the step-up ceremony.
  var rows = await clusterStorage.executeAll(
    "SELECT * FROM " + '"' + table + '"' + " WHERE _id = ?",
    [String(rowId)]
  );
  if (!rows || rows.length === 0) {
    throw new BreakGlassError("breakglass/row-not-found",
      "unsealRow: " + table + "[" + rowId + "] not found", true);
  }

  // Increment rowsConsumed (atomic UPDATE with WHERE rowsConsumed < cap
  // so concurrent unseals can't both pass the runtime check above).
  var updateRes = await clusterStorage.execute(
    "UPDATE _blamejs_break_glass_grants " +
    "SET rowsConsumed = rowsConsumed + 1 " +
    "WHERE _id = ? AND rowsConsumed < maxRowsPerGrant AND " +
    "(revokedAt IS NULL) AND expiresAt > ?",
    [grantHandle.id, Date.now()]
  );
  // executeAll-style result; some backends return rowsAffected, others a count.
  // Re-query to confirm the increment landed and get the post-increment counter.
  var postRows = await clusterStorage.executeAll(
    "SELECT rowsConsumed, revokedAt, expiresAt FROM _blamejs_break_glass_grants WHERE _id = ?",
    [grantHandle.id]
  );
  if (!postRows || postRows.length === 0) {
    throw new BreakGlassError("breakglass/grant-revoked",
      "unsealRow: grant " + grantHandle.id + " disappeared during unseal", true);
  }
  var postRowsConsumed = Number(postRows[0].rowsConsumed);
  // If the UPDATE didn't actually increment (race lost — another unseal
  // exhausted the grant or it was revoked / expired between our check
  // and the UPDATE), refuse this read.
  if (postRowsConsumed === Number(grantRow.rowsConsumed)) {
    throw new BreakGlassError("breakglass/grant-exhausted",
      "unsealRow: grant " + grantHandle.id + " was exhausted by a concurrent read", true);
  }
  void updateRes;
  var policy = await policyGet(table);
  var unsealedRow;
  if (policy && policy.cryptographic) {
    // Snapshot the raw glass-locked column ciphertexts BEFORE
    // cryptoField.unsealRow runs — cryptoField doesn't know about the
    // bgcell: format and would no-op (or error) on it. Then unseal the
    // rest of the row, then decrypt the glass-locked columns via
    // decryptCell with encryption-context binding.
    var rawCipher = {};
    for (var c = 0; c < policy.columns.length; c++) {
      rawCipher[policy.columns[c]] = rows[0][policy.columns[c]];
    }
    var rowMinusLocked = Object.assign({}, rows[0]);
    for (var c2 = 0; c2 < policy.columns.length; c2++) {
      delete rowMinusLocked[policy.columns[c2]];
    }
    unsealedRow = cryptoField.unsealRow(table, rowMinusLocked);
    for (var c3 = 0; c3 < policy.columns.length; c3++) {
      var col = policy.columns[c3];
      if (rawCipher[col] == null) continue;
      try {
        unsealedRow[col] = await decryptCell(rawCipher[col],
          { table: table, rowId: String(rowId), column: col });
      } catch (e) {
        throw new BreakGlassError("breakglass/cell-decrypt-failed",
          "unsealRow: cell decrypt failed for " + table + "[" + rowId +
          "]." + col + " (was the row migrated to Model B?): " +
          ((e && e.message) || String(e)), true);
      }
    }
  } else {
    unsealedRow = cryptoField.unsealRow(table, rows[0]);
  }

  // Per-row audit. The grant's reasonSealed is already cleartext after
  // unsealRow on the grant; pass it into the audit row honoring the
  // policy's auditReasonStorage mode.
  var reasonForAudit = _reasonForAudit(grantRow.reasonSealed || "",
    policy ? policy.auditReasonStorage : DEFAULT_AUDIT_REASON);
  audit.safeEmit({
    action:    "breakglass.unsealrow",
    outcome:   "success",
    actor:     _actorFor(grantRow),
    reason:    reasonForAudit.cleartext,
    metadata:  {
      grantId:        grantRow._id,
      table:          table,
      rowId:          String(rowId),
      columns:        safeJson.parse(grantRow.scopeColumnsJson || "[]", { maxBytes: C.BYTES.kib(64) }),
      rowsRemaining:  Number(grantRow.maxRowsPerGrant) - postRowsConsumed,
      reasonHmac:     reasonForAudit.hmac,
    },
  });
  observability.event("breakglass.unsealrow", { table: table });

  return unsealedRow;
}

// ---- Revoke ----

async function revoke(grantId, opts) {
  _requireInit();
  if (typeof grantId !== "string" || grantId.length === 0) {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "revoke: grantId is required");
  }
  opts = opts || {};
  var nowMs = Date.now();
  await clusterStorage.execute(
    "UPDATE _blamejs_break_glass_grants SET revokedAt = ? " +
    "WHERE _id = ? AND revokedAt IS NULL",
    [nowMs, grantId]
  );
  audit.safeEmit({
    action:   "breakglass.grant.revoked",
    outcome:  "success",
    actor:    requestHelpers.resolveActorWithOverride(opts),
    reason:   typeof opts.reason === "string" ? opts.reason : null,
    metadata: { grantId: grantId },
  });
  return { revoked: true, grantId: grantId };
}

// ---- listActive ----

async function listActive(opts) {
  _requireInit();
  opts = opts || {};
  var actor = requestHelpers.extractActorContext(opts.req);
  var actorId = actor.userId || (opts.req && opts.req.apiKey && opts.req.apiKey.id) || null;
  if (!actorId) return [];
  // Use cryptoField's computeDerived so the hash matches the table's
  // hashNamespace prefix — raw sha3Hash would produce a different value.
  var derived = cryptoField.computeDerived(
    "_blamejs_break_glass_grants", "issuedToActorId", actorId
  );
  if (!derived) return [];
  var nowMs = Date.now();
  var rows = await clusterStorage.executeAll(
    "SELECT * FROM _blamejs_break_glass_grants " +
    "WHERE issuedToActorHash = ? AND (revokedAt IS NULL) AND expiresAt > ? AND rowsConsumed < maxRowsPerGrant " +
    "ORDER BY issuedAt DESC",
    [derived.value, nowMs]
  );
  var out = [];
  for (var i = 0; i < (rows || []).length; i++) {
    var u = cryptoField.unsealRow("_blamejs_break_glass_grants", rows[i]);
    out.push({
      id:             u._id,
      scopeTable:     u.scopeTable,
      scopeColumns:   safeJson.parse(u.scopeColumnsJson || "[]", { maxBytes: C.BYTES.kib(64) }),
      issuedAt:       Number(u.issuedAt),
      expiresAt:      Number(u.expiresAt),
      rowsRemaining:  Number(u.maxRowsPerGrant) - Number(u.rowsConsumed),
      factorType:     u.factorType,
    });
  }
  return out;
}

// ---- Service-account bypass ----
//
// Some legitimate workloads (nightly de-identification, scheduled
// compliance reports) need PHI access without a human at the
// keyboard. The framework refuses to silently bypass — operators
// declare explicit service-account bypasses per-table with an apiKey
// allowlist + required role. Both must match (verified apiKey id is
// in the allowlist AND the apiKey carries the required role/scope)
// before the bypass is granted. Each bypass emits its own distinct
// audit row so post-incident review can distinguish operator-initiated
// from service-initiated reads.

async function unsealRowAsService(req, table, rowId, opts) {
  _requireInit();
  opts = opts || {};
  if (!req || typeof req !== "object") {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "unsealRowAsService: req is required (with verified req.apiKey)");
  }
  if (typeof table !== "string" || table.length === 0) {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "unsealRowAsService: table must be a non-empty string");
  }
  var policy = await policyGet(table);
  if (!policy) {
    throw new BreakGlassError("breakglass/policy-not-set",
      "unsealRowAsService: no break-glass policy for table '" + table + "'", true);
  }
  if (!policy.serviceAccountBypass) {
    throw new BreakGlassError("breakglass/bypass-not-configured",
      "unsealRowAsService: serviceAccountBypass is not configured for '" + table + "'", true);
  }
  var apiKeyOnReq = req.apiKey;
  if (!apiKeyOnReq || typeof apiKeyOnReq.id !== "string") {
    throw new BreakGlassError("breakglass/bypass-no-apikey",
      "unsealRowAsService: req.apiKey.id is required (operator must run b.middleware.requireApiKey before this path)", true);
  }
  if (policy.serviceAccountBypass.apiKeyIds.indexOf(apiKeyOnReq.id) === -1) {
    audit.safeEmit({
      action:   "breakglass.grant.bypass",
      outcome:  "denied",
      actor:    requestHelpers.extractActorContext(req),
      reason:   "apikey-not-in-allowlist",
      metadata: { table: table, rowId: String(rowId), apiKeyId: apiKeyOnReq.id },
    });
    throw new BreakGlassError("breakglass/bypass-unauthorized",
      "unsealRowAsService: apiKey '" + apiKeyOnReq.id +
      "' is not in the bypass allowlist for '" + table + "'", true);
  }
  // Role check — actor must carry policy.serviceAccountBypass.requireRole
  // either as a direct scope or via b.permissions.check resolution.
  var actorScopes = Array.isArray(apiKeyOnReq.scopes) ? apiKeyOnReq.scopes :
                    Array.isArray(apiKeyOnReq.roles)  ? apiKeyOnReq.roles :
                    [];
  var requiredRole = policy.serviceAccountBypass.requireRole;
  var hasRole = actorScopes.indexOf(requiredRole) !== -1;
  if (!hasRole) {
    audit.safeEmit({
      action:   "breakglass.grant.bypass",
      outcome:  "denied",
      actor:    requestHelpers.extractActorContext(req),
      reason:   "missing-role",
      metadata: { table: table, rowId: String(rowId), apiKeyId: apiKeyOnReq.id, requiredRole: requiredRole },
    });
    throw new BreakGlassError("breakglass/bypass-unauthorized",
      "unsealRowAsService: apiKey '" + apiKeyOnReq.id +
      "' lacks required role '" + requiredRole + "'", true);
  }

  // Fetch + unseal the row (Model A or Model B path, same as
  // operator-initiated unsealRow).
  var rows = await clusterStorage.executeAll(
    "SELECT * FROM " + '"' + table + '"' + " WHERE _id = ?",
    [String(rowId)]
  );
  if (!rows || rows.length === 0) {
    throw new BreakGlassError("breakglass/row-not-found",
      "unsealRowAsService: " + table + "[" + rowId + "] not found", true);
  }
  var unsealedRow;
  if (policy.cryptographic) {
    var rawCipher = {};
    for (var c = 0; c < policy.columns.length; c++) rawCipher[policy.columns[c]] = rows[0][policy.columns[c]];
    var rowMinusLocked = Object.assign({}, rows[0]);
    for (var c2 = 0; c2 < policy.columns.length; c2++) delete rowMinusLocked[policy.columns[c2]];
    unsealedRow = cryptoField.unsealRow(table, rowMinusLocked);
    for (var c3 = 0; c3 < policy.columns.length; c3++) {
      var col = policy.columns[c3];
      if (rawCipher[col] == null) continue;
      unsealedRow[col] = await decryptCell(rawCipher[col],
        { table: table, rowId: String(rowId), column: col });
    }
  } else {
    unsealedRow = cryptoField.unsealRow(table, rows[0]);
  }

  audit.safeEmit({
    action:   "breakglass.grant.bypass",
    outcome:  "success",
    actor:    requestHelpers.extractActorContext(req),
    reason:   typeof opts.reason === "string" ? opts.reason : null,
    metadata: {
      table:        table,
      rowId:        String(rowId),
      apiKeyId:     apiKeyOnReq.id,
      requiredRole: requiredRole,
      columns:      policy.columns.slice(),
    },
  });
  observability.event("breakglass.grant.bypass", { table: table });
  return unsealedRow;
}

// ---- Admin tools ----
//
// `listActiveAll` returns every active grant (across all actors) —
// for security-team dashboards and offboarding workflows.
// `revokeAll` mass-revokes grants matching criteria — used by IR
// teams when an account is suspected compromised. Both require
// admin scope (operator wires via opts.requireScope or their own gate).

async function listActiveAll(opts) {
  _requireInit();
  opts = opts || {};
  var nowMs = Date.now();
  var clauses = ["(revokedAt IS NULL)", "expiresAt > ?", "rowsConsumed < maxRowsPerGrant"];
  var params = [nowMs];
  if (opts.table) {
    clauses.push("scopeTable = ?");
    params.push(opts.table);
  }
  if (opts.since) {
    clauses.push("issuedAt >= ?");
    params.push(opts.since);
  }
  var rows = await clusterStorage.executeAll(
    "SELECT * FROM _blamejs_break_glass_grants WHERE " + clauses.join(" AND ") +
    " ORDER BY issuedAt DESC",
    params
  );
  var out = [];
  for (var i = 0; i < (rows || []).length; i++) {
    var u = cryptoField.unsealRow("_blamejs_break_glass_grants", rows[i]);
    out.push({
      id:             u._id,
      issuedToActorId: u.issuedToActorId,
      scopeTable:     u.scopeTable,
      scopeColumns:   safeJson.parse(u.scopeColumnsJson || "[]", { maxBytes: C.BYTES.kib(64) }),
      factorType:     u.factorType,
      issuedAt:       Number(u.issuedAt),
      expiresAt:      Number(u.expiresAt),
      rowsRemaining:  Number(u.maxRowsPerGrant) - Number(u.rowsConsumed),
    });
  }
  audit.safeEmit({
    action:   "breakglass.admin.listactiveall",
    outcome:  "success",
    actor:    requestHelpers.resolveActorWithOverride(opts.callerOpts),
    metadata: { resultCount: out.length, filterTable: opts.table || null },
  });
  return out;
}

async function revokeAll(criteria, opts) {
  _requireInit();
  if (!criteria || typeof criteria !== "object") {
    throw new BreakGlassError("breakglass/bad-revoke-criteria",
      "revokeAll: criteria is required ({ actorId?, table? })");
  }
  if (!criteria.actorId && !criteria.table) {
    throw new BreakGlassError("breakglass/bad-revoke-criteria",
      "revokeAll: at least one of { actorId, table } is required (refusing to mass-revoke without scope)");
  }
  opts = opts || {};
  var clauses = ["revokedAt IS NULL"];
  var params = [];
  if (criteria.actorId) {
    var derived = cryptoField.computeDerived(
      "_blamejs_break_glass_grants", "issuedToActorId", criteria.actorId
    );
    if (derived) {
      clauses.push("issuedToActorHash = ?");
      params.push(derived.value);
    }
  }
  if (criteria.table) {
    clauses.push("scopeTable = ?");
    params.push(criteria.table);
  }
  // Snapshot the to-be-revoked grant ids first so audit captures specifics.
  var ids = await clusterStorage.executeAll(
    "SELECT _id FROM _blamejs_break_glass_grants WHERE " + clauses.join(" AND "),
    params
  );
  var nowMs = Date.now();
  await clusterStorage.execute(
    "UPDATE _blamejs_break_glass_grants SET revokedAt = ? WHERE " + clauses.join(" AND "),
    [nowMs].concat(params)
  );
  audit.safeEmit({
    action:   "breakglass.admin.revokeall",
    outcome:  "success",
    actor:    requestHelpers.resolveActorWithOverride(opts.callerOpts),
    reason:   typeof criteria.reason === "string" ? criteria.reason : null,
    metadata: {
      filterActorId: criteria.actorId || null,
      filterTable:   criteria.table || null,
      revokedCount:  (ids || []).length,
      revokedIds:    (ids || []).map(function (r) { return r._id; }),
    },
  });
  return { revokedCount: (ids || []).length };
}

// ---- Sweep (best-effort cleanup of expired grants) ----

async function _sweepExpired(opts) {
  opts = opts || {};
  var nowMs = Date.now();
  var expired = await clusterStorage.executeAll(
    "SELECT _id, issuedToActorId, scopeTable, rowsConsumed FROM _blamejs_break_glass_grants " +
    "WHERE revokedAt IS NULL AND expiresAt <= ?",
    [nowMs]
  );
  for (var i = 0; i < (expired || []).length; i++) {
    var row = expired[i];
    audit.safeEmit({
      action:   "breakglass.grant.expired",
      outcome:  "success",
      actor:    { userId: row.issuedToActorId },
      metadata: { grantId: row._id, table: row.scopeTable, rowsConsumed: Number(row.rowsConsumed) },
    });
  }
  await clusterStorage.execute(
    "UPDATE _blamejs_break_glass_grants SET revokedAt = ? " +
    "WHERE revokedAt IS NULL AND expiresAt <= ?",
    [nowMs, nowMs]
  );
  return { expired: (expired || []).length };
}

void safeAsync;   // kept import for future grant-async ops in v0.5.1+

module.exports = {
  init:             init,
  policy: {
    set:    policySet,
    get:    policyGet,
    list:   policyList,
    delete: policyDelete,
  },
  grant:            grant,
  unsealRow:        unsealRow,
  revoke:           revoke,
  listActive:       listActive,
  // Cryptographic mode (Model B) — per-cell encryption with context
  // binding. Operators in cryptographic mode call encryptCell at write
  // time; unsealRow auto-routes to decryptCell for glass-locked columns.
  encryptCell:      encryptCell,
  decryptCell:      decryptCell,
  migrate:          migrate,
  // Service-account bypass — operator-declared per-table, gated by
  // (apiKey id in allowlist) AND (apiKey carries required role).
  unsealRowAsService: unsealRowAsService,
  // Admin tools — for security-team dashboards (listActiveAll) and
  // incident-response offboarding (revokeAll). Operators wire their
  // own gate (requireScope or middleware) on the calling routes.
  listActiveAll:    listActiveAll,
  revokeAll:        revokeAll,
  BreakGlassError:  BreakGlassError,

  // Test-only / sweep — operators with active grant volume wire this
  // into a scheduler; the framework doesn't auto-start the timer so
  // boot doesn't depend on anything firing in the background.
  _sweepExpiredForTest: _sweepExpired,
  _resetForTest:        _resetForTest,
};
