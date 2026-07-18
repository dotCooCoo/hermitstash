// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.breakGlass
 * @nav    Identity
 * @title  Break Glass
 *
 * @intro
 *   Column-policy / row-enforcement step-up auth — PHI / PCI columns
 *   require a fresh second-factor grant + operator-supplied reason;
 *   every unseal is audited row-by-row.
 *
 *   The operator declares which columns of which tables are
 *   GLASS-LOCKED. Reading a glass-locked column on any row requires
 *   the caller to (1) prove identity with a fresh second factor (TOTP
 *   or passkey), (2) supply a reason the audit chain captures, and
 *   (3) hold a short-lived scope-bounded grant. Each row read emits a
 *   per-row audit event; the default `maxRowsPerGrant: 1` enforces
 *   row-by-row auth so every PHI / PCI access is its own discrete
 *   authenticated event.
 *
 *   Two crypto models ship side-by-side. Model A — the default — is a
 *   policy gate: glass-locked columns sit in the regular cryptoField
 *   sealed-row pipeline, and break-glass enforces the grant + audit
 *   contract on every read path. Model B (`cryptographic: true` on the
 *   policy) layers per-cell encryption on top: every (table, rowId,
 *   column) triple gets its own key derived `K_cell = SHAKE256(DEK ||
 *   table || rowId || column)`, AEAD-bound to AAD = `SHA3-512(table ||
 *   rowId || column)` so swapping ciphertexts between rows fails
 *   closed. Operators opt into Model B per-policy, then run
 *   `b.breakGlass.migrate(table)` to convert existing rows.
 *
 *   Service-account bypass (`policy.serviceAccountBypass`) is opt-in
 *   per-table — both an apiKey-id allowlist and a required role must
 *   match. Admin tools (`listActiveAll`, `revokeAll`) cover security-
 *   team dashboards and incident-response offboarding.
 *
 * @card
 *   Column-policy / row-enforcement step-up auth — PHI / PCI columns require a fresh second-factor grant + operator-supplied reason; every unseal is audited row-by-row.
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
var sql = require("./sql");
var totp = require("./totp");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var vault = lazyRequire(function () { return require("./vault"); });

var lockout = lazyRequire(function () { return require("./auth/lockout"); });
var passkey = lazyRequire(function () { return require("./auth/passkey"); });
var permissions = lazyRequire(function () { return require("./permissions"); });

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
// Replay-step retention. A TOTP code is only valid inside the verifier's
// drift window (minutes); retaining the highest-accepted step for an hour
// guarantees any in-window replay attempt arrives after the floor is set.
var REPLAY_STEP_TTL_MS      = C.TIME.hours(1);
var DEFAULT_MAX_ROWS        = 1;       // operator-locked: row-by-row auth
var DEFAULT_REASON_MIN_LEN  = 12;
var DEFAULT_LOCKED_BEHAVIOR = "throw"; // or "redact"
var DEFAULT_AUDIT_REASON    = "cleartext";
var ALLOWED_FACTORS         = ["totp", "passkey"];
var ALLOWED_REASON_STORAGE  = ["cleartext", "hmac", "both"];

// cryptoField REGISTRY KEYS for the two break-glass framework tables. These
// are the names db.js's FRAMEWORK_SCHEMA registered the tables under, so
// seal / unseal / computeDerived must key off the byte-identical literal —
// resolving them through frameworkSchema.tableName would diverge the seal-side
// key from the registration under a custom prefix and break decryption. (SQL
// composed via b.sql passes the SAME bare logical name so clusterStorage can
// rewrite the table reference; these constants cover only the cryptoField
// keying.) allow:hand-rolled-sql — cryptoField registry keys, not SQL text.
var POLICIES_TABLE = "_blamejs_break_glass_policies";   // allow:hand-rolled-sql
var GRANTS_TABLE   = "_blamejs_break_glass_grants";     // allow:hand-rolled-sql

// b.sql opts for every statement break-glass dispatches through
// clusterStorage. Thread the ACTIVE backend dialect (clusterStorage.dialect()
// — "sqlite" single-node, "postgres" | "mysql" in cluster mode) so the
// emitted identifier quoting + dialect idioms (ON CONFLICT vs ON DUPLICATE
// KEY) match the backend the SQL dispatches to. Defaulting to "sqlite" works
// on Postgres only by accident (both double-quote identifiers) and emits the
// wrong quoting on MySQL. clusterStorage.execute still rewrites framework
// table names + translates `?` placeholders at dispatch; this controls only
// the builder-side quoting + idiom selection.
//   _sqlOpts()    — framework tables (policies / grants); name resolved bare,
//                   clusterStorage rewrites the prefix.
//   _appSqlOpts() — the operator's glass-locked app table; quoteName so b.sql
//                   quotes the (validated) identifier, and it is NOT
//                   framework-rewritten.
function _sqlOpts()    { return { dialect: clusterStorage.dialect() }; }
function _appSqlOpts() { return { dialect: clusterStorage.dialect(), quoteName: true }; }

// In-memory policy cache. Cluster-shared via the policies table; the
// cache short-circuits the DB roundtrip on the unsealRow hot path.
// Populated on first access per-table; invalidated on policy.set/delete.
var policyCache = new Map();    // table -> policy
var initialized = false;
// Framework-wide client-IP resolver (built at init). The grant row's `ip`
// field is a security control — a grant is pinned to the IP that minted it
// and re-checked on redeem. X-Forwarded-For is forgeable, so the binding is
// meaningful only when resolution is peer-gated: operators declare their
// reverse proxies via init({ trustedProxies }) or own resolution via
// init({ clientIpResolver }). Default resolves the socket address only.
var _ipResolver = requestHelpers.trustedClientIp();

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
// second-factor cryptographic gating uses passkey integration (the
// passkey private key lives on the YubiKey, not in the framework, so a
// vault leak alone can't unwrap).

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
  // The policy table is external-only; its LOGICAL name IS the
  // `_blamejs_`-prefixed name (self-mapped in LOCAL_TO_EXTERNAL), passed
  // bare to b.sql so clusterStorage rewrites + placeholderizes.
  var dekReadBuilt = sql.select("_blamejs_break_glass_policies", _sqlOpts())   // allow:hand-rolled-sql
    .columns(["dekSealed"])
    .where("tableName", table)
    .toSql();
  var rows = await clusterStorage.executeAll(dekReadBuilt.sql, dekReadBuilt.params);
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
    var dekUpdBuilt = sql.update("_blamejs_break_glass_policies", _sqlOpts())   // allow:hand-rolled-sql
      .set({ dekSealed: sealedDek })
      .where("tableName", table)
      .toSql();
    await clusterStorage.execute(dekUpdBuilt.sql, dekUpdBuilt.params);
  }
  dekCache.set(table, dek);
  return dek;
}

/**
 * @primitive b.breakGlass.encryptCell
 * @signature b.breakGlass.encryptCell(plaintext, ctx)
 * @since     0.5.1
 * @status    stable
 * @related   b.breakGlass.decryptCell, b.breakGlass.migrate, b.breakGlass.policy.set
 *
 * Encrypt a single glass-locked cell value with encryption-context
 * binding. Operators running a policy in `cryptographic: true` mode
 * call this at write time INSTEAD of letting `cryptoField.sealRow`
 * seal the column. The framework derives a per-cell key from the
 * policy's vault-sealed DEK plus `(table, rowId, column)`, encrypts
 * with XChaCha20-Poly1305, and sets AAD to `SHA3-512(table || rowId
 * || column)` so a ciphertext literally cannot be decrypted under a
 * different row identifier even with the same DEK.
 *
 * Returns a string of the form `bgcell:1:<base64>` ready to write
 * back to the column. Throws `breakglass/policy-not-set` when the
 * table has no policy or the policy isn't in cryptographic mode, and
 * `breakglass/grant-column-mismatch` when the column isn't glass-
 * locked on the policy.
 *
 * @example
 *   await b.breakGlass.policy.set("patients", {
 *     columns:       ["ssn"],
 *     factors:       ["totp"],
 *     cryptographic: true,
 *   });
 *   var sealed = await b.breakGlass.encryptCell("123-45-6789", {
 *     table:  "patients",
 *     rowId:  "patient-001",
 *     column: "ssn",
 *   });
 *   // → "bgcell:1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
 */
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

/**
 * @primitive b.breakGlass.decryptCell
 * @signature b.breakGlass.decryptCell(ciphertext, ctx)
 * @since     0.5.1
 * @status    stable
 * @related   b.breakGlass.encryptCell, b.breakGlass.unsealRow
 *
 * Decrypt a Model-B `bgcell:1:<base64>` cell value. Internal — the
 * caller must already hold a valid grant covering the (table,
 * column); operator-facing reads route through `b.breakGlass.unsealRow`
 * which gates this call. The encryption context (`table, rowId,
 * column`) is fed into BOTH the per-cell key derivation AND the AEAD
 * AAD, so a caller passing the wrong `rowId` trying to swap
 * ciphertexts between rows fails closed at the AEAD verify step.
 *
 * @example
 *   // unsealRow routes here automatically for cryptographic-mode
 *   // policies; calling decryptCell directly is rare and only for
 *   // operator tooling that's already enforced its own grant gate.
 *   var plaintext = await b.breakGlass.decryptCell(sealed, {
 *     table:  "patients",
 *     rowId:  "patient-001",
 *     column: "ssn",
 *   });
 *   // → "123-45-6789"
 */
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

/**
 * @primitive b.breakGlass.migrate
 * @signature b.breakGlass.migrate(table, opts)
 * @since     0.5.1
 * @status    stable
 * @related   b.breakGlass.encryptCell, b.breakGlass.policy.set
 *
 * One-shot migration that converts every existing row of a glass-
 * locked table from Model A (cryptoField.sealRow only) into Model B
 * per-cell ciphertext. Iterates via `_id`-keyset paging so memory
 * stays bounded; rows already in Model B (column starts with
 * `bgcell:`) are skipped, making the migration idempotent and safe
 * to re-run after a partial failure.
 *
 * Emits a `breakglass.migrate` audit event on completion with totals
 * and skipped counts. Refuses to run when the policy isn't in
 * cryptographic mode — operator must `policy.set({ cryptographic:
 * true })` first.
 *
 * @opts
 *   batchSize:   number,   // _id-keyset page size (default 100)
 *   callerOpts:  object,   // forwarded to audit actor resolution
 *
 * @example
 *   await b.breakGlass.policy.set("patients", {
 *     columns:       ["ssn", "dob"],
 *     factors:       ["totp"],
 *     cryptographic: true,
 *   });
 *   var summary = await b.breakGlass.migrate("patients", { batchSize: 250 });
 *   // → { table: "patients", totalRows: 1200, migratedRows: 1198, skippedRows: 2 }
 */
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
    // `table` is an operator app table (already validated as a safe
    // identifier via _validatePolicySet). quoteName:true makes b.sql quote
    // the name (reserved-word / case-sensitive safe); it is NOT a framework
    // table, so clusterStorage's resolveTables leaves it untouched.
    var pageBuilt = sql.select(table, _appSqlOpts())
      .whereOp("_id", ">", lastId)
      .orderBy("_id", "asc")
      .limit(batchSize)
      .toSql();
    var rows = await clusterStorage.executeAll(pageBuilt.sql, pageBuilt.params);
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
          // Column names came from the validated policy.columns. b.sql
          // quotes every SET target + binds every value; the operator app
          // table is quoted (quoteName) and not framework-rewritten.
          var setMap = {};
          for (var sc = 0; sc < setCols.length; sc++) setMap[setCols[sc]] = update[setCols[sc]];
          var updBuilt = sql.update(table, _appSqlOpts())
            .set(setMap)
            .where("_id", row._id)
            .toSql();
          await clusterStorage.execute(updBuilt.sql, updBuilt.params);
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

/**
 * @primitive b.breakGlass.init
 * @signature b.breakGlass.init(opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.breakGlass.policy.set, b.breakGlass.grant
 *
 * One-shot boot wiring. Clears the in-memory policy cache, resets the
 * factor-lockout counter, and records how the grant row's `ip` field is
 * resolved. That IP is a security binding — the grant pins to it at mint
 * and re-checks it on redeem — so resolution is peer-gated: declare your
 * reverse proxies via `trustedProxies` (CIDRs; X-Forwarded-For honored
 * only from a trusted peer) or own resolution via `clientIpResolver`. A
 * bare `trustProxy` is refused — a forgeable pin is no pin. Operators call
 * this once at boot, before any policy / grant / unseal call — every other
 * primitive throws `breakglass/not-initialized` until init has run.
 *
 * @opts
 *   trustedProxies:   string|string[],          // CIDRs of your reverse proxies — peer-gates X-Forwarded-For
 *   clientIpResolver: function(req): string|null,  // own grant-IP resolution
 *
 * @example
 *   b.breakGlass.init({ trustedProxies: ["10.0.0.0/8"] });
 *   // → undefined  (init returns nothing; throws on bad opts)
 */
function init(opts) {
  opts = opts || {};
  validateOpts(opts, ["trustProxy", "trustedProxies", "clientIpResolver"], "breakGlass.init");
  var resolver;
  try {
    resolver = requestHelpers.trustedClientIp({
      trustedProxies:   opts.trustedProxies,
      clientIpResolver: opts.clientIpResolver,
    });
  } catch (e) {
    throw new BreakGlassError("breakglass/bad-opt", e.message);
  }
  if ((opts.trustProxy === true || typeof opts.trustProxy === "number") && !resolver.peerGated) {
    throw new BreakGlassError("breakglass/bad-opt",
      "trustProxy is spoofable — a grant pinned to a forgeable X-Forwarded-For is no " +
      "pin at all. Declare your reverse proxies via trustedProxies: [\"10.0.0.0/8\", …] " +
      "or supply clientIpResolver(req).");
  }
  initialized = true;
  policyCache.clear();
  _factorLockout = null;
  _ipResolver = resolver;
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
  _ipResolver = requestHelpers.trustedClientIp();
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
        "' not in allowed factors [" + ALLOWED_FACTORS.join(",") + "]");
    }
  }
  // Model B (cryptographic mode). When enabled,
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

/**
 * @primitive b.breakGlass.policy.set
 * @signature b.breakGlass.policy.set(table, opts, callerOpts)
 * @since     0.5.0
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.breakGlass.policy.get, b.breakGlass.policy.delete, b.breakGlass.grant
 *
 * Declare the column-policy that gates step-up auth on the named
 * table. The listed columns become GLASS-LOCKED — every read of one of
 * those columns on any row requires the caller to hold a fresh
 * second-factor grant whose scope covers the column. Stored
 * cluster-wide in `_blamejs_break_glass_policies` (sealed via
 * cryptoField) so every node honors the same gate. Re-runs UPSERT;
 * the policy cache flushes for the table.
 *
 * @opts
 *   columns:              Array<string>,        // glass-locked column names (required, ≥1)
 *   factors:              Array<string>,        // allowed second factors: "totp" / "passkey"
 *   cryptographic:        boolean,              // opt into Model B per-cell encryption (default false)
 *   grantTtl:             number,               // grant lifetime in ms (default 15 minutes)
 *   maxRowsPerGrant:      number,               // rows a grant may unseal (default 1 — row-by-row)
 *   reasonRequired:       boolean,              // require operator reason on grant (default true)
 *   reasonMinLength:      number,               // minimum reason length in chars (default 12)
 *   pinIp:                boolean,              // bind grant to issuing IP (default true)
 *   sessionPin:           boolean,              // bind grant to issuing session (default true)
 *   onLockedAccess:       string,               // "throw" | "redact" on unauthorized read (default "throw")
 *   requireScope:         string,               // actor scope required before grant mints (e.g. "phi:admin")
 *   serviceAccountBypass: object,               // { enabled, apiKeyIds, requireRole } — opt-in machine bypass
 *   auditReasonStorage:   string,               // "cleartext" | "hmac" | "both" (default "cleartext")
 *
 * @example
 *   await b.breakGlass.policy.set("patients", {
 *     columns:         ["ssn", "dob"],
 *     factors:         ["totp"],
 *     grantTtl:        600000,
 *     maxRowsPerGrant: 1,
 *     requireScope:    "phi:admin",
 *   });
 *   // → { applied: true, table: "patients" }
 */
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
  var sealed = cryptoField.sealRow(POLICIES_TABLE, policyRow);
  // UPSERT via b.sql ON CONFLICT(tableName) DO UPDATE (Postgres + SQLite).
  // BARE logical framework table — clusterStorage rewrites + placeholderizes;
  // b.sql quotes every column + binds every sealed value. The conflict key
  // (tableName) is excluded from the DO UPDATE set.
  var keys   = Object.keys(sealed);
  var setCols = keys.filter(function (k) { return k !== "tableName"; });
  var policyBuilt = sql.upsert("_blamejs_break_glass_policies", _sqlOpts())   // allow:hand-rolled-sql
    .columns(keys)
    .values(sealed)
    .onConflict(["tableName"])
    .doUpdateFromExcluded(setCols)
    .toSql();
  await clusterStorage.execute(policyBuilt.sql, policyBuilt.params);
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

/**
 * @primitive b.breakGlass.policy.get
 * @signature b.breakGlass.policy.get(table)
 * @since     0.5.0
 * @status    stable
 * @related   b.breakGlass.policy.set, b.breakGlass.policy.list
 *
 * Read the current break-glass policy for `table` from the cluster-
 * shared policies table, with an in-process cache that short-circuits
 * the DB roundtrip on the unsealRow hot path. Returns `null` when the
 * table has no policy declared (a non-glass-locked table). The cache
 * invalidates on `policy.set` / `policy.delete`.
 *
 * @example
 *   var policy = await b.breakGlass.policy.get("patients");
 *   // → { table: "patients", columns: ["ssn", "dob"], factors: ["totp"], ... }
 *
 *   var none = await b.breakGlass.policy.get("posts");
 *   // → null
 */
async function policyGet(table) {
  _requireInit();
  if (typeof table !== "string" || table.length === 0) return null;
  if (policyCache.has(table)) return policyCache.get(table);
  var getBuilt = sql.select("_blamejs_break_glass_policies", _sqlOpts())   // allow:hand-rolled-sql
    .where("tableName", table)
    .toSql();
  var rows = await clusterStorage.executeAll(getBuilt.sql, getBuilt.params);
  if (!rows || rows.length === 0) {
    policyCache.set(table, null);
    return null;
  }
  var unsealed = cryptoField.unsealRow(POLICIES_TABLE, rows[0]);
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

/**
 * @primitive b.breakGlass.policy.list
 * @signature b.breakGlass.policy.list()
 * @since     0.5.0
 * @status    stable
 * @related   b.breakGlass.policy.get, b.breakGlass.policy.set
 *
 * Enumerate every glass-locked table the cluster knows about. Used by
 * compliance dashboards (which tables hold PHI / PCI?) and migration
 * tooling that needs to walk the full set. Returns hydrated policy
 * objects in `tableName` order — no abbreviated row form.
 *
 * @example
 *   var policies = await b.breakGlass.policy.list();
 *   // → [{ table: "patients", columns: ["ssn", "dob"], ... }, { table: "cards", ... }]
 *   policies.length;
 *   // → 2
 */
async function policyList() {
  _requireInit();
  var listBuilt = sql.select("_blamejs_break_glass_policies", _sqlOpts())   // allow:hand-rolled-sql
    .columns(["tableName"])
    .orderBy("tableName", "asc")
    .toSql();
  var rows = await clusterStorage.executeAll(listBuilt.sql, listBuilt.params);
  var out = [];
  for (var i = 0; i < (rows || []).length; i++) {
    var p = await policyGet(rows[i].tableName);
    if (p) out.push(p);
  }
  return out;
}

/**
 * @primitive b.breakGlass.policy.delete
 * @signature b.breakGlass.policy.delete(table, callerOpts)
 * @since     0.5.0
 * @status    stable
 * @related   b.breakGlass.policy.set
 *
 * Remove the break-glass policy for `table`. Subsequent reads of the
 * previously glass-locked columns no longer require a grant — operators
 * call this only when a column genuinely stops being PHI / PCI (rare;
 * almost always the operator wants `policy.set` with a revised column
 * list instead). Emits a `breakglass.policy.delete` audit event.
 *
 * @example
 *   await b.breakGlass.policy.delete("legacy_patients");
 *   // → { deleted: true, table: "legacy_patients" }
 */
async function policyDelete(table, callerOpts) {
  _requireInit();
  if (typeof table !== "string" || table.length === 0) {
    throw new BreakGlassError("breakglass/bad-policy",
      "policy.delete: table must be a non-empty string");
  }
  var delBuilt = sql.delete("_blamejs_break_glass_policies", _sqlOpts())   // allow:hand-rolled-sql
    .where("tableName", table)
    .toSql();
  await clusterStorage.execute(delBuilt.sql, delBuilt.params);
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
  // factor.now threads a deterministic test clock into totp.verify. The
  // replay floor is NOT applied here: acceptance reserves the matched step
  // atomically in _reserveTotpStep, so two concurrent grants presenting the
  // same in-window code cannot both pass (a read-then-commit floor races —
  // both reads observe the old floor before either commits). totp.verify
  // returns the step the code matches (a fixed value for a given code within
  // the drift window) or false; the reserve then floors replays of that step.
  var vopts = {};
  if (typeof factor.now === "number") vopts.now = factor.now;
  var verified = totp.verify(factor.secret, factor.code, vopts);
  return { ok: verified !== false, step: verified };
}

// Replay-step cache key. Keyed by BOTH the actorId AND a non-reversible
// fingerprint of the TOTP secret. Keying on actorId alone would falsely
// reject a legitimate second grant when two distinct credentials accept a
// code at the same TOTP step (the step number is a wall-clock counter, not
// per-credential) — the secret fingerprint disambiguates them. The secret
// never reaches the cache in any reversible form.
function _replayStepKey(actorId, secret) {
  return "totp-step:" + actorId + ":" + sha3Hash(secret);
}

// Atomically reserve the accepted TOTP step for (actorId, secret): advance
// the stored replay floor to `step` only when `step` is strictly above the
// current floor, and report whether THIS caller won the reservation. The
// compare-and-advance is one atomic cache update, so two concurrent grant()
// calls presenting the same in-window code cannot both pass — the first wins
// and raises the floor to `step`, the second observes step <= floor and is
// refused. (A separate read-then-commit sequence let both reads see the old
// floor before either committed, so both verified — the replay this closes.)
// The TTL outlives the verify drift window many times over so a replayed code
// stays floored until it expires.
//
// Fails CLOSED (returns false) on a cache fault: a grant cannot proceed
// without a working factor cache regardless — the lockout check at the top of
// grant() already gates on the same cache — so refusing here can only reject,
// never loosen replay protection.
async function _reserveTotpStep(actorId, secret, step) {
  _ensureFactorLockout();
  if (typeof step !== "number") return false;
  var won = false;
  try {
    await _factorLockoutCache.update(_replayStepKey(actorId, secret), function (prior) {
      if (typeof prior === "number" && step <= prior) { won = false; return { value: prior }; }
      won = true;
      return { value: step };
    }, { ttlMs: REPLAY_STEP_TTL_MS });
  } catch (_e) { return false; }
  return won;
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

/**
 * @primitive b.breakGlass.grant
 * @signature b.breakGlass.grant(opts)
 * @since     0.5.0
 * @status    stable
 * @compliance hipaa, pci-dss, soc2
 * @related   b.breakGlass.unsealRow, b.breakGlass.revoke, b.breakGlass.policy.set
 *
 * Mint a short-lived, scope-bounded break-glass grant. The framework
 * verifies the operator's second factor (TOTP code or passkey
 * assertion), records the operator-supplied reason into the audit
 * chain, and issues a grant whose scope covers the named columns of
 * the named table for `policy.grantTtl` ms or `policy.maxRowsPerGrant`
 * row reads — whichever ends first. Failures emit a denied-grant audit
 * row; repeated factor failures trigger the lockout primitive.
 *
 * @opts
 *   req:      object,        // the active request (carries actor identity, ip, session)
 *   table:    string,        // glass-locked table the grant scopes to
 *   columns:  Array<string>, // optional subset of policy.columns (default = full policy)
 *   reason:   string,        // operator-supplied reason (length-gated by policy.reasonMinLength)
 *   factor:   object,        // { type: "totp", secret, code } or { type: "passkey", response, ... }
 *
 * @example
 *   var handle = await b.breakGlass.grant({
 *     req:     req,
 *     table:   "patients",
 *     columns: ["ssn"],
 *     reason:  "ER admit verifying identity for patient-001",
 *     factor:  { type: "totp", secret: req.user.totpSecret, code: "123456" },
 *   });
 *   // → { id: "bg-...", expiresAt: 1735000000000, rowsRemaining: 1, scopeTable: "patients", scopeColumns: ["ssn"] }
 */
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
      // Segment-aware scope match via the canonical b.permissions.match: an
      // exact scope, or a wildcard whose "*" occupies a WHOLE colon segment
      // ("phi:*" → "phi:admin"), satisfies the requirement. A raw string prefix
      // ("phi:admin".indexOf("phi:a") === 0) wrongly let a partial-segment
      // scope ("phi:a*") glass-unseal a different value.
      if (typeof actorScopes[sci] === "string" &&
          permissions().match(actorScopes[sci], policy.requireScope)) {
        scopeOk = true; break;
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
  var totpSecret = null;
  if (factorType === "totp") {
    totpSecret = opts.factor && opts.factor.secret;
    // Verify the code, then atomically reserve the step it matched as the act
    // of acceptance. The reserve advances the per-(actor,secret) replay floor
    // in one compare-and-set, so a code already redeemed inside the drift
    // window — including by a concurrent grant for the same credential — is
    // refused. (A read-then-commit floor raced: both grants read the old
    // floor before either committed, so both passed.)
    var totpResult = _verifyTotpFactor(opts.factor);
    if (totpResult.ok && typeof totpResult.step === "number" &&
        typeof totpSecret === "string" && totpSecret.length > 0) {
      factorOk = await _reserveTotpStep(actorId, totpSecret, totpResult.step);
    }
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
  // Peer-gated client-IP resolution from init() (trustedProxies /
  // clientIpResolver). Without it, X-Forwarded-For is ignored as
  // attacker-forgeable and the grant pins to the socket remoteAddress only.
  var ipFromReq = _ipResolver.resolve(opts.req);

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
  var sealed = cryptoField.sealRow(GRANTS_TABLE, grantRow);
  // BARE logical framework table — clusterStorage rewrites + placeholderizes;
  // b.sql quotes every column + binds every sealed value.
  var grantInsBuilt = sql.insert("_blamejs_break_glass_grants", _sqlOpts())   // allow:hand-rolled-sql
    .values(sealed)
    .toSql();
  await clusterStorage.execute(grantInsBuilt.sql, grantInsBuilt.params);

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

// Enforce the grant's IP / session bindings at redemption. policy.set
// documents pinIp / sessionPin as default-ON, and grant() captures
// grantRow.ip / grantRow.sessionId at mint time — but without this gate
// the bindings are stored-and-never-enforced (a grant minted from IP-A
// would redeem from IP-B). Called BEFORE the SELECT-then-increment so a
// mismatch does not consume a grant.
//
// FAIL-CLOSED: when a pin is requested but the binding was captured null
// (e.g. an Express-shaped req whose IP requestHelpers.clientIp couldn't
// read at mint time), the redemption is REFUSED rather than silently
// skipped — a `grantRow.ip != null` short-circuit would defeat the pin
// for exactly the requests whose binding capture failed.
function _enforceGrantPins(policy, grantRow, redeemReq, actorFor) {
  if (!policy) return;
  if (policy.pinIp) {
    if (grantRow.ip == null) {
      audit.safeEmit({
        action:   "breakglass.unsealrow",
        outcome:  "denied",
        actor:    actorFor(grantRow),
        reason:   "grant-ip-binding-missing",
        metadata: { grantId: grantRow._id, table: grantRow.scopeTable },
      });
      throw new BreakGlassError("breakglass/grant-ip-mismatch",
        "unsealRow: grant " + grantRow._id + " has pinIp on but no IP was " +
        "captured at mint (fail-closed) — re-mint from a request whose client " +
        "IP the framework can resolve", true);
    }
    var redeemIp = _ipResolver.resolve(redeemReq);
    if (redeemIp !== grantRow.ip) {
      audit.safeEmit({
        action:   "breakglass.unsealrow",
        outcome:  "denied",
        actor:    actorFor(grantRow),
        reason:   "grant-ip-mismatch",
        metadata: { grantId: grantRow._id, table: grantRow.scopeTable },
      });
      throw new BreakGlassError("breakglass/grant-ip-mismatch",
        "unsealRow: grant " + grantRow._id + " is pinned to its issuing IP " +
        "and this redemption arrived from a different address", true);
    }
  }
  if (policy.sessionPin) {
    if (grantRow.sessionId == null) {
      audit.safeEmit({
        action:   "breakglass.unsealrow",
        outcome:  "denied",
        actor:    actorFor(grantRow),
        reason:   "grant-session-binding-missing",
        metadata: { grantId: grantRow._id, table: grantRow.scopeTable },
      });
      throw new BreakGlassError("breakglass/grant-session-mismatch",
        "unsealRow: grant " + grantRow._id + " has sessionPin on but no " +
        "session id was captured at mint (fail-closed) — re-mint from a " +
        "request carrying req.session.id", true);
    }
    var redeemSession = (redeemReq && redeemReq.session && redeemReq.session.id) || null;
    if (redeemSession !== grantRow.sessionId) {
      audit.safeEmit({
        action:   "breakglass.unsealrow",
        outcome:  "denied",
        actor:    actorFor(grantRow),
        reason:   "grant-session-mismatch",
        metadata: { grantId: grantRow._id, table: grantRow.scopeTable },
      });
      throw new BreakGlassError("breakglass/grant-session-mismatch",
        "unsealRow: grant " + grantRow._id + " is pinned to its issuing " +
        "session and this redemption arrived from a different session", true);
    }
  }
}

// ---- Use a grant ----

/**
 * @primitive b.breakGlass.unsealRow
 * @signature b.breakGlass.unsealRow(grantHandle, table, rowId, opts)
 * @since     0.5.0
 * @status    stable
 * @compliance hipaa, pci-dss, soc2
 * @related   b.breakGlass.grant, b.breakGlass.decryptCell, b.breakGlass.revoke
 *
 * Read one row's glass-locked columns under an active grant. The
 * framework validates the grant (not revoked, not expired, not
 * exhausted, scope matches the table), atomically increments
 * `rowsConsumed`, fetches and unseals the row, and emits a per-row
 * `breakglass.unsealrow` audit event carrying the reason + actor +
 * remaining rows. For Model B (cryptographic) policies, glass-locked
 * columns route through `decryptCell` with encryption-context binding
 * — a swapped ciphertext from another row fails closed at AEAD verify.
 *
 * @opts
 *   req: object,   // optional originating request — populates ip / userAgent / sessionId / requestId on the audit row
 *
 * @example
 *   var row = await b.breakGlass.unsealRow(handle, "patients", "patient-001", { req: req });
 *   // → { _id: "patient-001", name: "Alice", ssn: "123-45-6789", dob: "1980-04-12", ... }
 */
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
  var grantReadBuilt = sql.select("_blamejs_break_glass_grants", _sqlOpts())   // allow:hand-rolled-sql
    .where("_id", grantHandle.id)
    .toSql();
  var grantRows = await clusterStorage.executeAll(grantReadBuilt.sql, grantReadBuilt.params);
  if (!grantRows || grantRows.length === 0) {
    throw new BreakGlassError("breakglass/grant-revoked",
      "unsealRow: grant " + grantHandle.id + " not found (deleted or never issued)", true);
  }
  var sealedGrant = grantRows[0];
  var grantRow = cryptoField.unsealRow(GRANTS_TABLE, sealedGrant);

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

  // IP / session pin enforcement — BEFORE the SELECT-then-increment so a
  // pin mismatch does not consume the grant. Fail-closed when a requested
  // pin's binding was captured null (see _enforceGrantPins). The policy is
  // fetched once here and reused for the Model-A/B unseal dispatch below.
  var policy = await policyGet(table);
  _enforceGrantPins(policy, grantRow, opts.req, _actorFor);

  // SELECT-before-increment — fetch the target row FIRST. If the row
  // doesn't exist (operator typo, race with row-deletion, etc.), the
  // grant should not be consumed. Without this ordering, a single
  // typo against `maxRowsPerGrant: 1` (the default) exhausts the
  // grant and forces the operator to re-do the step-up ceremony.
  // Operator app table (validated identifier) — quoteName quotes it; it is
  // not framework-rewritten.
  var rowReadBuilt = sql.select(table, _appSqlOpts())
    .where("_id", String(rowId))
    .toSql();
  var rows = await clusterStorage.executeAll(rowReadBuilt.sql, rowReadBuilt.params);
  if (!rows || rows.length === 0) {
    throw new BreakGlassError("breakglass/row-not-found",
      "unsealRow: " + table + "[" + rowId + "] not found", true);
  }

  // Increment rowsConsumed (atomic UPDATE with WHERE rowsConsumed < cap so
  // concurrent unseals can't both pass the runtime check above). The
  // rowsConsumed+1 RHS + the rowsConsumed<maxRowsPerGrant column comparison
  // are guarded raw fragments (b.guardSql + placeholder/literal scan). The
  // identifier quoting in those raw fragments is dialect-aware (backticks on
  // MySQL, double-quotes on PG/SQLite) so the column references resolve as
  // identifiers, not string literals, on the active backend.
  var incDialect = clusterStorage.dialect();
  var incBuilt = sql.update("_blamejs_break_glass_grants", _sqlOpts())   // allow:hand-rolled-sql
    .setRaw("rowsConsumed", safeSql.quoteIdentifier("rowsConsumed", incDialect) + " + 1", [])
    .where("_id", grantHandle.id)
    .whereRaw(safeSql.quoteIdentifier("rowsConsumed", incDialect) + " < " +
      safeSql.quoteIdentifier("maxRowsPerGrant", incDialect), [])
    .whereNull("revokedAt")
    .whereOp("expiresAt", ">", Date.now())
    .toSql();
  var updateRes = await clusterStorage.execute(incBuilt.sql, incBuilt.params);
  // The atomic compare-and-increment IS the claim, and the count of rows it
  // CHANGED is the only per-caller signal for whether THIS caller won the
  // slot. `execute` returns rowCount = the rows the UPDATE modified
  // (info.changes on local sqlite; the driver's affected-row count in cluster
  // mode), so rowCount >= 1 means this caller's compare-and-increment landed
  // and rowCount === 0 means it lost — the grant was exhausted / revoked /
  // expired concurrently between the runtime checks above and this UPDATE.
  //
  // Do NOT infer the claim from a re-read of rowsConsumed against this
  // caller's stale pre-value: a concurrent WINNER's increment is visible to
  // the LOSER's re-read, so `post !== pre` is true for the loser too and both
  // proceed — a double-claim that reads two rows under a maxRowsPerGrant:1
  // grant, defeating row-by-row auth. The affected-row count is unambiguous.
  if (!updateRes || Number(updateRes.rowCount) < 1) {
    throw new BreakGlassError("breakglass/grant-exhausted",
      "unsealRow: grant " + grantHandle.id + " was exhausted by a concurrent read", true);
  }
  // Re-query for the post-increment counter — used ONLY for the audit's
  // rowsRemaining hint below, no longer for the claim decision.
  var postReadBuilt = sql.select("_blamejs_break_glass_grants", _sqlOpts())   // allow:hand-rolled-sql
    .columns(["rowsConsumed", "revokedAt", "expiresAt"])
    .where("_id", grantHandle.id)
    .toSql();
  var postRows = await clusterStorage.executeAll(postReadBuilt.sql, postReadBuilt.params);
  if (!postRows || postRows.length === 0) {
    throw new BreakGlassError("breakglass/grant-revoked",
      "unsealRow: grant " + grantHandle.id + " disappeared during unseal", true);
  }
  var postRowsConsumed = Number(postRows[0].rowsConsumed);
  // policy was fetched above for the pin enforcement; reuse it for the
  // Model-A vs Model-B (cryptographic) unseal dispatch.
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

/**
 * @primitive b.breakGlass.revoke
 * @signature b.breakGlass.revoke(grantId, opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.breakGlass.grant, b.breakGlass.revokeAll
 *
 * Mark a single grant revoked. Subsequent `unsealRow` calls against the
 * grant id throw `breakglass/grant-revoked`. Idempotent — already-
 * revoked grants stay at their original `revokedAt` timestamp because
 * the UPDATE clause is gated on `revokedAt IS NULL`.
 *
 * @opts
 *   reason:     string,   // operator note recorded into the audit row
 *   callerOpts: object,   // forwarded to audit actor resolution
 *
 * @example
 *   await b.breakGlass.revoke("bg-abc123", { reason: "operator finished read; releasing" });
 *   // → { revoked: true, grantId: "bg-abc123" }
 */
async function revoke(grantId, opts) {
  _requireInit();
  if (typeof grantId !== "string" || grantId.length === 0) {
    throw new BreakGlassError("breakglass/bad-grant-opts",
      "revoke: grantId is required");
  }
  opts = opts || {};
  var nowMs = Date.now();
  // revokedAt IS NULL keeps the revoke idempotent (already-revoked grants
  // keep their original timestamp).
  var revBuilt = sql.update("_blamejs_break_glass_grants", _sqlOpts())   // allow:hand-rolled-sql
    .set({ revokedAt: nowMs })
    .where("_id", grantId)
    .whereNull("revokedAt")
    .toSql();
  await clusterStorage.execute(revBuilt.sql, revBuilt.params);
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

/**
 * @primitive b.breakGlass.listActive
 * @signature b.breakGlass.listActive(opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.breakGlass.listActiveAll, b.breakGlass.revoke
 *
 * Enumerate the active (not revoked, not expired, rows remaining)
 * grants the caller currently holds. Lookup is keyed via cryptoField's
 * `computeDerived` so the actor's id never appears in cleartext on the
 * grants table — the framework hashes via the table's namespaced
 * derivation. Unauthenticated callers (no actorId on `req`) get an
 * empty array.
 *
 * @opts
 *   req: object,   // request carrying the actor identity (req.user.id or req.apiKey.id)
 *
 * @example
 *   var grants = await b.breakGlass.listActive({ req: req });
 *   // → [{ id: "bg-...", scopeTable: "patients", scopeColumns: ["ssn"], expiresAt: ..., rowsRemaining: 1, factorType: "totp" }]
 */
async function listActive(opts) {
  _requireInit();
  opts = opts || {};
  var actor = requestHelpers.extractActorContext(opts.req);
  var actorId = actor.userId || (opts.req && opts.req.apiKey && opts.req.apiKey.id) || null;
  if (!actorId) return [];
  // Use cryptoField's computeDerived so the hash matches the table's
  // hashNamespace prefix — raw sha3Hash would produce a different value.
  var derived = cryptoField.computeDerived(
    GRANTS_TABLE, "issuedToActorId", actorId
  );
  if (!derived) return [];
  var nowMs = Date.now();
  // rowsConsumed < maxRowsPerGrant is a column-to-column comparison (guarded
  // raw fragment); every other predicate is structured.
  var laDialect = clusterStorage.dialect();
  var laBuilt = sql.select("_blamejs_break_glass_grants", _sqlOpts())   // allow:hand-rolled-sql
    .where("issuedToActorHash", derived.value)
    .whereNull("revokedAt")
    .whereOp("expiresAt", ">", nowMs)
    .whereRaw(safeSql.quoteIdentifier("rowsConsumed", laDialect) + " < " +
      safeSql.quoteIdentifier("maxRowsPerGrant", laDialect), [])
    .orderBy("issuedAt", "desc")
    .toSql();
  var rows = await clusterStorage.executeAll(laBuilt.sql, laBuilt.params);
  var out = [];
  for (var i = 0; i < (rows || []).length; i++) {
    var u = cryptoField.unsealRow(GRANTS_TABLE, rows[i]);
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

/**
 * @primitive b.breakGlass.unsealRowAsService
 * @signature b.breakGlass.unsealRowAsService(req, table, rowId, opts)
 * @since     0.5.0
 * @status    stable
 * @compliance hipaa, pci-dss, soc2
 * @related   b.breakGlass.policy.set, b.breakGlass.unsealRow
 *
 * Machine-account read of a glass-locked row. Bypass is gated by the
 * policy's `serviceAccountBypass` block — both the verified `req.apiKey.id`
 * must be on the operator-declared allowlist AND the apiKey must
 * carry the operator-declared role. Both checks must pass; either
 * failure emits a denied bypass audit row and throws
 * `breakglass/bypass-unauthorized`. Each successful bypass emits a
 * distinct `breakglass.grant.bypass` audit row so post-incident review
 * separates operator-initiated reads from scheduled-job reads.
 *
 * This path is service-to-service: it consumes NO grant row, so the
 * `pinIp` / `sessionPin` grant bindings enforced by `unsealRow` do not
 * apply here. A grant that was minted with those pins is not redeemable
 * through this surface — the bypass is gated solely by the
 * `serviceAccountBypass` allowlist + required-role check.
 *
 * @opts
 *   reason: string,   // operator-supplied reason recorded into the audit row
 *
 * @example
 *   var row = await b.breakGlass.unsealRowAsService(req, "patients", "patient-001", {
 *     reason: "nightly de-identification job",
 *   });
 *   // → { _id: "patient-001", name: "Alice", ssn: "123-45-6789", ... }
 */
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
  // operator-initiated unsealRow). Operator app table — quoteName quotes it;
  // it is not framework-rewritten.
  var svcRowBuilt = sql.select(table, _appSqlOpts())
    .where("_id", String(rowId))
    .toSql();
  var rows = await clusterStorage.executeAll(svcRowBuilt.sql, svcRowBuilt.params);
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

/**
 * @primitive b.breakGlass.listActiveAll
 * @signature b.breakGlass.listActiveAll(opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.breakGlass.listActive, b.breakGlass.revokeAll
 *
 * Admin variant of `listActive` — returns every active grant across
 * every actor. Used by security-team dashboards and offboarding
 * workflows; operators wire their own gate (`requireScope` or a
 * middleware) on the calling route so non-admins can't enumerate the
 * full grant pool. Each call emits a `breakglass.admin.listactiveall`
 * audit row.
 *
 * @opts
 *   table:      string,   // optional filter — only grants scoped to this table
 *   since:      number,   // optional issuedAt floor (ms epoch)
 *   callerOpts: object,   // forwarded to audit actor resolution
 *
 * @example
 *   var all = await b.breakGlass.listActiveAll({ table: "patients" });
 *   // → [{ id: "bg-...", issuedToActorId: "user-42", scopeTable: "patients", ... }]
 */
async function listActiveAll(opts) {
  _requireInit();
  opts = opts || {};
  var nowMs = Date.now();
  // rowsConsumed < maxRowsPerGrant is a column-to-column comparison (guarded
  // raw fragment); the rest are structured predicates.
  var laaDialect = clusterStorage.dialect();
  var laaQb = sql.select("_blamejs_break_glass_grants", _sqlOpts())   // allow:hand-rolled-sql
    .whereNull("revokedAt")
    .whereOp("expiresAt", ">", nowMs)
    .whereRaw(safeSql.quoteIdentifier("rowsConsumed", laaDialect) + " < " +
      safeSql.quoteIdentifier("maxRowsPerGrant", laaDialect), []);
  if (opts.table) laaQb.where("scopeTable", opts.table);
  if (opts.since) laaQb.whereOp("issuedAt", ">=", opts.since);
  laaQb.orderBy("issuedAt", "desc");
  var laaBuilt = laaQb.toSql();
  var rows = await clusterStorage.executeAll(laaBuilt.sql, laaBuilt.params);
  var out = [];
  for (var i = 0; i < (rows || []).length; i++) {
    var u = cryptoField.unsealRow(GRANTS_TABLE, rows[i]);
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

/**
 * @primitive b.breakGlass.revokeAll
 * @signature b.breakGlass.revokeAll(criteria, opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.breakGlass.revoke, b.breakGlass.listActiveAll
 *
 * Mass-revoke grants matching a scope predicate. Refuses to run with
 * empty criteria — IR teams must name at least one of `actorId` or
 * `table` so the framework never silently revokes every grant in the
 * cluster. The to-be-revoked grant ids are snapshotted into the audit
 * row before the UPDATE, so post-incident timelines have the exact
 * list. Common shape: revoke every active grant held by a suspected-
 * compromised account.
 *
 * @opts
 *   callerOpts: object,   // forwarded to audit actor resolution
 *
 * @example
 *   var result = await b.breakGlass.revokeAll(
 *     { actorId: "user-42", reason: "account compromise — IR-2026-0042" },
 *     { callerOpts: { actor: { userId: "soc-on-call" } } }
 *   );
 *   // → { revokedCount: 3 }
 */
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
  // The SELECT (snapshot ids) and UPDATE (apply revoke) share one predicate
  // set; applyRevokeCriteria replays it onto either builder so the WHERE can
  // never drift between the two.
  var derived = criteria.actorId
    ? cryptoField.computeDerived(GRANTS_TABLE, "issuedToActorId", criteria.actorId)
    : null;
  function applyRevokeCriteria(qb) {
    qb.whereNull("revokedAt");
    if (criteria.actorId && derived) qb.where("issuedToActorHash", derived.value);
    if (criteria.table) qb.where("scopeTable", criteria.table);
    return qb;
  }
  // Snapshot the to-be-revoked grant ids first so audit captures specifics.
  var idSelBuilt = applyRevokeCriteria(
    sql.select("_blamejs_break_glass_grants", _sqlOpts()).columns(["_id"])   // allow:hand-rolled-sql
  ).toSql();
  var ids = await clusterStorage.executeAll(idSelBuilt.sql, idSelBuilt.params);
  var nowMs = Date.now();
  var revAllBuilt = applyRevokeCriteria(
    sql.update("_blamejs_break_glass_grants", _sqlOpts()).set({ revokedAt: nowMs })   // allow:hand-rolled-sql
  ).toSql();
  await clusterStorage.execute(revAllBuilt.sql, revAllBuilt.params);
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
  var expiredBuilt = sql.select("_blamejs_break_glass_grants", _sqlOpts())   // allow:hand-rolled-sql
    .columns(["_id", "issuedToActorId", "scopeTable", "rowsConsumed"])
    .whereNull("revokedAt")
    .whereOp("expiresAt", "<=", nowMs)
    .toSql();
  var expired = await clusterStorage.executeAll(expiredBuilt.sql, expiredBuilt.params);
  for (var i = 0; i < (expired || []).length; i++) {
    var row = expired[i];
    audit.safeEmit({
      action:   "breakglass.grant.expired",
      outcome:  "success",
      actor:    { userId: row.issuedToActorId },
      metadata: { grantId: row._id, table: row.scopeTable, rowsConsumed: Number(row.rowsConsumed) },
    });
  }
  var sweepUpdBuilt = sql.update("_blamejs_break_glass_grants", _sqlOpts())   // allow:hand-rolled-sql
    .set({ revokedAt: nowMs })
    .whereNull("revokedAt")
    .whereOp("expiresAt", "<=", nowMs)
    .toSql();
  await clusterStorage.execute(sweepUpdBuilt.sql, sweepUpdBuilt.params);
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
