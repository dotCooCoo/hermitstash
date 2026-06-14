"use strict";
/**
 * @module     b.middleware.idempotencyKey
 * @nav        Middleware
 * @title      Idempotency-Key
 * @order      400
 *
 * @intro
 *   draft-ietf-httpapi-idempotency-key middleware — replay-safe POST /
 *   PUT / PATCH / DELETE handling for retry-capable clients. A client
 *   sends `Idempotency-Key: <opaque>` on a mutating request; the
 *   middleware:
 *
 *     1. Looks up the key in the operator-supplied `store`. A hit
 *        replays the cached `{ statusCode, headers, body }` without
 *        invoking the handler (idempotent replay).
 *     2. Compares the inbound request fingerprint (method + path +
 *        body hash) against the cached fingerprint. A mismatch is a
 *        client-side mistake — same key, different request — and
 *        refuses with 422 + RFC 9457 Problem Details
 *        `idempotency/key-reuse-mismatch` per the draft §4.3.
 *     3. On miss, attaches a capture wrapper to `res.end` so the
 *        handler's response is intercepted, persisted, and replayed
 *        on every subsequent retry within `ttlMs`.
 *
 *   `Idempotency-Key` is OPTIONAL — clients that don't send it skip
 *   the cache and the middleware is a no-op. Idempotency is a
 *   client-asserted contract; the server promises "if you send the
 *   same key + same body, you get the same answer." Operators
 *   wanting strict idempotency on a particular route compose with
 *   `requireIdempotencyKey: true` to refuse missing headers with
 *   `400 idempotency/missing-key`.
 *
 *   Store interface is operator-supplied so cluster deployments can
 *   plug their distributed store (Redis, SQLite-cluster, etc.). The
 *   first-party `memoryStore` is included for single-instance
 *   testing — it accepts `{ ttlMs }` and exposes `_resetForTest()`.
 *
 * @card
 *   draft-ietf-httpapi-idempotency-key middleware — replay-safe POST/PUT/PATCH/DELETE handling for retry-capable clients with operator-supplied distributed store.
 */

var nodeCrypto    = require("node:crypto");
var lazyRequire   = require("../lazy-require");
var numericBounds = require("../numeric-bounds");
var validateOpts  = require("../validate-opts");
var safeBuffer    = require("../safe-buffer");
var safeJson      = require("../safe-json");
var safeSql       = require("../safe-sql");
var sql           = require("../sql");
var bCrypto       = require("../crypto");
var cryptoField   = require("../crypto-field");
var vault         = require("../vault");
var { defineClass } = require("../framework-error");

var audit          = lazyRequire(function () { return require("../audit"); });
var problemDetails = lazyRequire(function () { return require("../problem-details"); });
var C              = require("../constants");

var IdempotencyError = defineClass("IdempotencyError", { alwaysPermanent: true });

// Default applicable methods per draft-ietf-httpapi-idempotency-key §3:
// GET / HEAD / OPTIONS are inherently idempotent (RFC 9110 §9.2.2) so
// the middleware skips them by default. DELETE is included because
// the draft endorses it as the canonical "idempotent but not safe"
// retry surface.
var DEFAULT_METHODS = Object.freeze(["POST", "PUT", "PATCH", "DELETE"]);

// Idempotency-Key shape per the draft §2 — ASCII printable, no
// control chars, length 1..255 (typical client implementations cap
// at 36 for UUID + a few extra for vendor prefixes; 255 is the
// upper bound that still fits a single HTTP header line).
var KEY_RE = /^[\x21-\x7E]+$/;                                                                     // printable ASCII codepoint range
var KEY_MAX_LEN = 255;                                                                             // draft §2 upper bound

/**
 * @primitive b.middleware.idempotencyKey.memoryStore
 * @signature b.middleware.idempotencyKey.memoryStore(opts?)
 * @since     0.8.84
 * @status    stable
 * @related   b.middleware.idempotencyKey
 *
 * First-party in-memory store for `idempotencyKey` middleware.
 * Single-instance only — cluster deployments compose against a
 * distributed store (Redis / SQLite-cluster) matching the
 * three-method interface: `get(key) → record | null`,
 * `set(key, value, ttlMs)`, `delete(key)`. TTL is enforced lazily
 * at read time; the store's resident size is operator-supplied via
 * `opts.maxEntries` (default 10000) — when the cap is hit, the
 * oldest entry is evicted (FIFO; the recorded request was
 * idempotent anyway so re-running is correct, not just safe).
 *
 * @opts
 *   maxEntries: number, // default 10000 — FIFO eviction on overflow
 *
 * @example
 *   var store = b.middleware.idempotencyKey.memoryStore({ maxEntries: 5000 });
 *   var mw = b.middleware.idempotencyKey({ store: store, ttlMs: C.TIME.hours(24) });
 *   app.use(mw);
 */
function memoryStore(opts) {
  opts = opts || {};
  numericBounds.requirePositiveFiniteIntIfPresent(
    opts.maxEntries, "memoryStore.maxEntries", IdempotencyError, "idempotency/bad-max-entries");
  var maxEntries = opts.maxEntries !== undefined ? opts.maxEntries : 10000;                       // default in-memory cap, not bytes
  var data = new Map();
  return {
    get: function (key) {
      var rec = data.get(key);
      if (!rec) return null;
      if (rec.expiresAt < Date.now()) {
        data.delete(key);
        return null;
      }
      return rec.value;
    },
    set: function (key, value, ttlMs) {
      if (data.size >= maxEntries) {
        var oldest = data.keys().next().value;
        data.delete(oldest);
      }
      data.set(key, { value: value, expiresAt: Date.now() + ttlMs });
    },
    delete: function (key) {
      data.delete(key);
    },
    _resetForTest: function () {
      data.clear();
    },
    _size: function () { return data.size; },
  };
}

// Operator-supplied table name is validated via b.safeSql.validateIdentifier
// — single source of truth for the framework's SQL-identifier shape
// (ASCII identifier chars only, 63-char cap, no reserved words). Direct
// interpolation is safe once the validator throws on bad input.

/**
 * @primitive b.middleware.idempotencyKey.dbStore
 * @signature b.middleware.idempotencyKey.dbStore(opts)
 * @since     0.9.14
 * @status    stable
 * @related   b.middleware.idempotencyKey, b.middleware.idempotencyKey.memoryStore, b.db, b.cryptoField
 *
 * Persistent-backed store for `idempotencyKey` middleware. Implements
 * the same three-method interface as `memoryStore` (`get` / `set` /
 * `delete`) but stores records in a SQLite-shaped database — the
 * framework's internal `b.db`, an operator-supplied better-sqlite3
 * instance, or any object exposing `prepare(sql) → { run, get, all }`.
 *
 * Use `dbStore` instead of `memoryStore` when:
 *
 *   - multiple processes share the request-handling fleet (forks
 *     behind a load balancer, multi-instance K8s deployment) and a
 *     retry can land on a different process than the original;
 *   - the daemon may restart between the original request and the
 *     retry (graceful rolling deploy, OOM kill, planned reboot) —
 *     `memoryStore` is volatile, `dbStore` survives the restart;
 *   - audit / compliance review needs to walk historic
 *     idempotency cache decisions queryable with
 *     `SELECT k, status_code, expires_at FROM <tableName>` —
 *     non-sealed columns are forensic-queryable without unsealing.
 *
 * **Defense-in-depth defaults — every option below ships on by default:**
 *
 *   - `hashKeys: true` (since 0.9.15) — operator-supplied keys are
 *     sha3-512 namespace-hashed via
 *     `b.crypto.namespaceHash("idempotency-key", key)` before
 *     insert/lookup. The `k` column carries the hash, not the raw key.
 *     Operator keys often carry PII (order numbers, emails, vendor
 *     prefixes); the DB never sees them.
 *   - `seal: true` (since 0.9.15) — `headers` and `body` columns are
 *     sealed via `b.cryptoField.sealRow` (vault-managed key, AEAD
 *     envelope) so a DB dump leaks neither cached response bodies nor
 *     headers. Requires `b.vault.init(...)` to have run; falls back to
 *     plain-text with a one-shot audit warning when vault isn't ready,
 *     so test-fixture / boot-script callers still work.
 *   - `aad: true` (since 0.9.58) — sealed columns are bound
 *     via Additional Authenticated Data to (table, k, column,
 *     schemaVersion) so a DB-write attacker can't copy a sealed
 *     header/body cell from one row to another (which previously
 *     decrypted cleanly under plain `vault.seal`). Existing v0.9.15-
 *     v0.9.57 dbStore tables continue to read because unsealRow auto-
 *     detects the envelope shape; lazy re-seal on next `set()` upgrades
 *     each row to AAD form. Operators wanting a one-shot migration
 *     call `b.middleware.idempotencyKey.resealMigrate(store)`.
 *   - `fingerprintSeal: true` (since 0.9.58) — the request
 *     `fingerprint` column carries an HMAC under a vault-derived
 *     secret instead of a bare SHA3-256 of method+path+body. The
 *     compare path is constant-time so the column doubles as a
 *     mismatch oracle without offline-brute-force exposure.
 *   - `bodyFingerprintFallback: "deny"` (since 0.9.58) —
 *     when neither `bodyFingerprint` nor `req._rawBody`/`req.body` is
 *     populated for a body-bearing method, the middleware previously
 *     silently degraded the fingerprint to method+path. Set to
 *     `"deny"` (the new default) and the middleware refuses the
 *     request with HTTP 400 `idempotency/missing-body-fingerprint`
 *     instead. Operators with a documented "no body" use case set
 *     `bodyFingerprintFallback: "method-path-only"` to restore the
 *     pre-0.9.58 behavior — the audit chain still emits
 *     `idempotency.empty_body_fingerprint` so the misorder is visible.
 *
 * Lazily-expired: `get(key)` returns `null` for any row whose
 * `expires_at` has passed. The cleanup is scoped by the observed
 * `expires_at` so a concurrent upsert from a sibling process isn't
 * clobbered.
 *
 * **Schema (v0.9.15, split columns):**
 *
 * ```
 *   k             TEXT PRIMARY KEY   -- hashed key when hashKeys=true
 *   fingerprint   TEXT NOT NULL      -- request method+path+body digest
 *   status_code   INTEGER NOT NULL   -- forensic-queryable
 *   headers       TEXT NOT NULL      -- JSON, sealed when seal=true
 *   body          TEXT NOT NULL      -- base64, sealed when seal=true
 *   expires_at    INTEGER NOT NULL
 * ```
 *
 * **Migration note**: v0.9.14 used a single `v` JSON envelope column.
 * Operators with a v0.9.14 table must `DROP TABLE <tableName>;` (or
 * pick a fresh `tableName`) before upgrading — `CREATE TABLE IF NOT
 * EXISTS` won't migrate column layout. Pre-v1 the framework breaks
 * across patch versions for security correctness.
 *
 * @opts
 *   db:         object,   // required — sqlite-shaped: { prepare(sql) → { run, get, all } }
 *   tableName?: string,   // default "blamejs_idempotency_keys"; validated via b.safeSql.validateIdentifier
 *   init?:      boolean,  // default true — run CREATE TABLE IF NOT EXISTS at construction
 *   hashKeys?:  boolean,  // default true — store sha3-512 namespace-hash of the key, not the raw key
 *   seal?:      boolean,  // default true — seal headers + body via b.cryptoField when vault is ready
 *   aad?:       boolean,  // default true — AAD-bind seal to (table,k,column) so a DB-write attacker can't cross-row swap
 *   fingerprintSeal?: boolean, // default true — HMAC fingerprint under a vault-derived secret instead of bare sha3-256
 *
 * @example
 *   // single-process daemon, framework's internal sqlite, both defaults on:
 *   var b = require("blamejs");
 *   await b.vault.init({ dataDir: "/var/lib/myapp" });
 *   await b.db.init({ dataDir: "/var/lib/myapp", schema: [] });
 *   var store = b.middleware.idempotencyKey.dbStore({ db: b.db });
 *   var mw = b.middleware.idempotencyKey({
 *     store: store,
 *     ttlMs: b.constants.TIME.hours(24),
 *   });
 *   app.use(mw);
 */
function dbStore(opts) {
  opts = opts || {};
  if (!opts.db || typeof opts.db !== "object" || typeof opts.db.prepare !== "function") {
    throw new IdempotencyError("idempotency/bad-db",
      "dbStore: opts.db must be a sqlite-shaped database with a `prepare(sql)` method", true);
  }
  var tableNameRaw = opts.tableName !== undefined ? opts.tableName : "blamejs_idempotency_keys";
  // Validate the operator-supplied table name up front so a bad
  // identifier fails at construction with the stable
  // idempotency/bad-table-name code (b.sql would otherwise raise its own
  // SqlBuilderError deeper in the first build). b.sql then quotes the
  // name by construction in every statement it emits for this store
  // (quoteName:true — this is a direct sqlite handle, not a
  // clusterStorage rewrite target, so the name is quoted, not left bare).
  try { safeSql.validateIdentifier(tableNameRaw, { allowReserved: true }); }
  catch (sqlErr) {
    throw new IdempotencyError("idempotency/bad-table-name",
      "dbStore: opts.tableName is not a valid SQL identifier: " +
      (sqlErr && sqlErr.message ? sqlErr.message : String(sqlErr)), true);
  }
  // b.sql opts for every statement this store builds against the local
  // sqlite handle: sqlite dialect (native `?` placeholders, double-quoted
  // identifiers) + quoteName so the operator table name is emitted quoted.
  var sqlOpts = { dialect: "sqlite", quoteName: true };
  var doInit   = opts.init     !== false;
  var hashKeys = opts.hashKeys !== false;
  var sealReq  = opts.seal     !== false;
  // AAD-bind sealing to (table, k, column) by default.
  // Forms a defense-in-depth pair with seal: cross-row swap fails
  // Poly1305 even when the attacker controls the DB layer.
  var aadOn    = opts.aad      !== false;
  // HMAC the fingerprint under a vault-derived secret by
  // default. Bare SHA3-256 of method+path+body is offline-brute-
  // forceable for any DB-dump attacker; HMAC under a vault secret
  // forces them to break the vault first.
  var fpSealOn = opts.fingerprintSeal !== false;
  var db = opts.db;

  // Probe vault readiness with a sentinel seal. If vault.init() hasn't
  // run (test fixture / boot-script / operator simply hasn't wired the
  // posture yet) sealing falls back to plaintext for the lifetime of
  // this dbStore instance and a single audit warning emits so the
  // posture gap is visible in the chain.
  var sealEnabled = false;
  if (sealReq) {
    try {
      // allow:seal-without-aad — vault-readiness probe; throwaway
      // sentinel value, not row-bound data
      vault.seal("__idempotency_seal_probe__");
      sealEnabled = true;
    } catch (_vaultErr) {
      _emitAudit("idempotency.seal_skipped_no_vault",
        { tableName: tableNameRaw,
          reason: "vault.init() has not run; sealing falls back to plaintext" },
        "warning");
    }
  }

  // Register the table with cryptoField. registerTable is idempotent
  // — subsequent dbStore() calls with the same tableName re-declare
  // the same sealedFields and no-op. When aad is on,
  // (table, k, column) is threaded into the AEAD AAD so a DB-write
  // attacker can't copy a sealed value between rows.
  if (sealEnabled) {
    cryptoField.registerTable(tableNameRaw, {
      sealedFields: ["headers", "body"],
      aad:          aadOn,
      rowIdField:   "k",
      schemaVersion: "1",
    });
  }

  // Derive a per-vault HMAC secret for fingerprint sealing. Seed off the
  // SEALED per-deployment MAC key (vault.getDerivedHashMacKey, sealed at
  // rest under the vault root) — NOT getDerivedHashSalt, which sits in
  // PLAINTEXT on disk. With the salt-derived seed an attacker who read
  // the disk could recompute the HMAC key and forge / correlate request
  // fingerprints; the sealed MAC key closes that (the vault root is the
  // trust root, so the secret is unrecoverable without it). Lazy: only
  // derived when fpSealOn is enabled AND the vault is ready, so test
  // fixtures that haven't initialized the vault still construct a
  // dbStore (the fingerprint then falls back to bare sha3-256 with a
  // single audit warning).
  var fpHmacSecret = null;
  if (fpSealOn) {
    try {
      // The MAC key is per-deployment + sealed, so the same dbStore
      // instance across hosts converges on the same HMAC key while disk
      // access alone cannot recover it. The table name domain-separates
      // the fingerprint secret from other consumers of the MAC key.
      var fpDeriveInput = Buffer.concat([
        vault.getDerivedHashMacKey(),
        Buffer.from("idempotency.fingerprint:" + tableNameRaw, "utf8"),
      ]);
      fpHmacSecret = bCrypto.kdf(fpDeriveInput, C.BYTES.bytes(32));
    } catch (_fpErr) {
      _emitAudit("idempotency.fingerprint_seal_skipped_no_vault",
        { tableName: tableNameRaw,
          reason: "vault.getDerivedHashMacKey() unavailable; fingerprint falls back to plain sha3-256" },
        "warning");
      fpHmacSecret = null;
    }
  }

  if (doInit) {
    db.prepare(sql.createTable(tableNameRaw, [
      { name: "k",           type: "text", primaryKey: true },
      { name: "fingerprint", type: "text", notNull: true },
      { name: "status_code", type: "int",  notNull: true },
      { name: "headers",     type: "text", notNull: true },
      { name: "body",        type: "text", notNull: true },
      { name: "expires_at",  type: "int",  notNull: true },
    ], sqlOpts).sql).run();
    db.prepare(sql.createIndex(tableNameRaw + "_expires_idx", tableNameRaw,
      ["expires_at"], sqlOpts).sql).run();
  }

  // Prepared statements, composed once through b.sql and reused per call.
  // b.sql binds concrete values into a params array; for a reusable
  // prepared statement we keep only the emitted SQL text (its `?`
  // placeholders) and bind fresh values at run time, so a build-time
  // sentinel value is just a placeholder slot. status_code + expires_at
  // stay non-sealed so audit/forensic SELECTs don't have to unseal-
  // everything. The `k` column is selected even when not strictly needed
  // for read because cryptoField.unsealRow uses it as the rowId in AAD
  // when the table is AAD-bound.
  var _slot = 0;   // sentinel bind value; the prepared statement rebinds at call time
  var stmtGet = db.prepare(sql.select(tableNameRaw, sqlOpts)
    .columns(["k", "fingerprint", "status_code", "headers", "body", "expires_at"])
    .where("k", _slot)
    .toSql().sql);
  var stmtUpsert = db.prepare(sql.upsert(tableNameRaw, sqlOpts)
    .columns(["k", "fingerprint", "status_code", "headers", "body", "expires_at"])
    .values({ k: _slot, fingerprint: _slot, status_code: _slot,
              headers: _slot, body: _slot, expires_at: _slot })
    .onConflict(["k"])
    .doUpdateFromExcluded(["fingerprint", "status_code", "headers", "body", "expires_at"])
    .toSql().sql);
  var stmtDeleteStale = db.prepare(sql.delete(tableNameRaw, sqlOpts)
    .where("k", _slot)
    .where("expires_at", "<=", _slot)
    .toSql().sql);
  var stmtDelete = db.prepare(sql.delete(tableNameRaw, sqlOpts)
    .where("k", _slot)
    .toSql().sql);

  function _k(rawKey) {
    if (!hashKeys) return rawKey;
    return bCrypto.namespaceHash("idempotency-key", rawKey);
  }

  // Emit / compare HMAC-shape fingerprints. The store
  // round-trips the column as plain text (no transformation per-get);
  // sealing happens at MINT time (when the middleware builds the
  // fingerprint and hands it to set()). The store's responsibility is
  // pass-through. The middleware's `_fingerprintRequest` consults
  // `store.fingerprintMode` to know whether to HMAC.

  return {
    get: function (rawKey) {
      var row = stmtGet.get(_k(rawKey));
      if (!row) return null;
      if (row.expires_at < Date.now()) {
        stmtDeleteStale.run(_k(rawKey), row.expires_at);
        return null;
      }
      var liveRow = row;
      if (sealEnabled) {
        try { liveRow = cryptoField.unsealRow(tableNameRaw, row); }
        catch (_unsealErr) {
          // Decryption failure used to delete the row,
          // which let an attacker probe key presence via a "tamper +
          // observe subsequent SELECT" oracle. The fix: emit audit,
          // return null, do NOT delete. TTL sweeps stale rows out
          // bounded by ttlMs; an out-of-band sweeper handles the
          // corrupt-but-not-yet-expired case.
          _emitAudit("idempotency.unseal_failed",
            { tableName: tableNameRaw,
              keyHash:   _hashKey(rawKey),
              reason:    String(_unsealErr && _unsealErr.message || _unsealErr) },
            "warning");
          return null;
        }
      }
      var headersObj;
      try {
        // Route through C.BYTES.mib(4); raw `4 * 1024 * 1024`
        // was a drift smell flagged by codebase-patterns. 4 MiB ceiling
        // unchanged.
        headersObj = safeJson.parse(liveRow.headers, { maxBytes: C.BYTES.mib(4) });
      } catch (_jsonErr) {
        // Parse failure has two distinct causes:
        //   1. Genuine corruption (truncated row, encoding mishap) — drop.
        //   2. The row was sealed by a sibling process (vault: prefix
        //      present) but THIS process has sealEnabled=false (vault
        //      not initialized OR opts.seal=false). The row is valid
        //      cross-process state we just can't read locally;
        //      DELETING it would clobber another process's cache and
        //      turn a hit into a miss with potential side-effect re-
        //      execution. Treat as miss + LEAVE the row in place.
        var lookedSealed = typeof liveRow.headers === "string" &&
          (liveRow.headers.indexOf("vault:") === 0 ||
           liveRow.headers.indexOf("vault.aad:") === 0);
        if (!lookedSealed) {
          stmtDeleteStale.run(_k(rawKey), row.expires_at);
        }
        return null;
      }
      return {
        fingerprint: liveRow.fingerprint,
        statusCode:  liveRow.status_code,
        headers:     headersObj,
        body:        liveRow.body,
      };
    },
    set: function (rawKey, value, ttlMs) {
      var rowOut = {
        k:           _k(rawKey),
        fingerprint: value.fingerprint,
        status_code: value.statusCode,
        headers:     JSON.stringify(value.headers || {}),
        body:        value.body || "",
        expires_at:  Date.now() + ttlMs,
      };
      if (sealEnabled) {
        rowOut = cryptoField.sealRow(tableNameRaw, rowOut);
      }
      stmtUpsert.run(
        rowOut.k, rowOut.fingerprint, rowOut.status_code,
        rowOut.headers, rowOut.body, rowOut.expires_at);
    },
    delete: function (rawKey) {
      stmtDelete.run(_k(rawKey));
    },
    // The middleware consults this hook to HMAC the
    // method+path+body digest under a vault-derived secret before
    // insert + compare. Returns null when fpSeal is disabled OR the
    // vault wasn't ready at construction; the middleware then falls
    // back to bare sha3-256.
    fingerprintHmac: function (preimageBytes) {
      if (!fpSealOn || !fpHmacSecret) return null;
      return nodeCrypto.createHmac("sha3-256", fpHmacSecret)
        .update(preimageBytes).digest("hex");
    },
    // Operator helper: walk the table and reseal every row
    // under the AAD form. Existing v0.9.15-v0.9.57 rows continue to
    // read on a per-row basis (unsealRow auto-detects shape), but
    // operators wanting an explicit migration step call this once.
    // Idempotent; rows already AAD-sealed pass through unchanged.
    resealMigrate: function () {
      if (!sealEnabled || !aadOn) {
        return { migrated: 0, skipped: 0, reason: "aad-or-seal-disabled" };
      }
      var migrated = 0;
      var skipped = 0;
      var rows = db.prepare(sql.select(tableNameRaw, sqlOpts)
        .columns(["k", "fingerprint", "status_code", "headers", "body", "expires_at"])
        .toSql().sql).all();
      for (var i = 0; i < rows.length; i += 1) {
        var r = rows[i];
        // If headers/body already start with vault.aad: this row is
        // already migrated.
        var alreadyAad = typeof r.headers === "string" &&
          r.headers.indexOf("vault.aad:") === 0 &&
          typeof r.body === "string" &&
          r.body.indexOf("vault.aad:") === 0;
        if (alreadyAad) { skipped += 1; continue; }
        var unsealed;
        try { unsealed = cryptoField.unsealRow(tableNameRaw, r); }
        catch (_e) { skipped += 1; continue; }
        var resealed = cryptoField.sealRow(tableNameRaw, unsealed);
        stmtUpsert.run(
          resealed.k, resealed.fingerprint, resealed.status_code,
          resealed.headers, resealed.body, resealed.expires_at);
        migrated += 1;
      }
      _emitAudit("idempotency.reseal_migrate_complete",
        { tableName: tableNameRaw, migrated: migrated, skipped: skipped });
      return { migrated: migrated, skipped: skipped, reason: null };
    },
    _tableName:   tableNameRaw,
    _hashKeys:    hashKeys,
    _sealEnabled: sealEnabled,
    _aadOn:       aadOn,
    _fpSealOn:    fpSealOn && fpHmacSecret !== null,
  };
}

function _validateStore(store, where) {
  if (!store || typeof store !== "object") {
    throw new IdempotencyError("idempotency/bad-store",
      where + ": store must be an object", true);
  }
  if (typeof store.get !== "function" ||
      typeof store.set !== "function" ||
      typeof store.delete !== "function") {
    throw new IdempotencyError("idempotency/bad-store",
      where + ": store must implement { get, set, delete }", true);
  }
}

function _fingerprintRequest(req, bodyBytes, store) {
  // Fingerprint preimage = method + path + body. Per the draft §4.3,
  // a key+body mismatch is a client-side mistake; our preimage covers
  // method + path so a client reusing a key across different
  // endpoints is also caught. When the store exposes a
  // `fingerprintHmac` hook (dbStore with fingerprintSeal:true + vault
  // ready), the preimage is HMAC'd under a vault-derived secret so a
  // DB dump leaks neither the preimage nor a brute-forceable digest.
  // The middleware then compares the HMAC'd column directly; both
  // sides of the compare use the same secret so the equality is
  // exact, no key-recovery is performed on the dump side.
  var preimage = Buffer.concat([
    Buffer.from((req.method || "GET") + "\n", "utf8"),
    Buffer.from((req.url || "/") + "\n", "utf8"),
    bodyBytes && bodyBytes.length > 0 ? bodyBytes : Buffer.alloc(0),
  ]);
  if (store && typeof store.fingerprintHmac === "function") {
    var hmacOut = store.fingerprintHmac(preimage);
    if (hmacOut !== null) return hmacOut;
  }
  return nodeCrypto.createHash("sha3-256").update(preimage).digest("hex");
}

function _emitAudit(action, metadata, outcome) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome || "success",
      metadata: metadata,
    });
  } catch (_e) { /* best-effort */ }
}

/**
 * @primitive b.middleware.idempotencyKey
 * @signature b.middleware.idempotencyKey(opts)
 * @since     0.8.84
 * @status    stable
 * @related   b.middleware.idempotencyKey.memoryStore, b.problemDetails
 *
 * Build the Idempotency-Key middleware. Returns a connect-style
 * `(req, res, next) => void` handler.
 *
 *   - When `req.method` is not in `opts.methods` (default POST / PUT /
 *     PATCH / DELETE), the middleware is a pass-through.
 *   - When the request lacks an `Idempotency-Key` header and
 *     `opts.requireIdempotencyKey === true`, refuses with HTTP 400 +
 *     `application/problem+json` body
 *     `idempotency/missing-key`.
 *   - When the key is present but malformed (control chars, length
 *     out of range), refuses with HTTP 400 +
 *     `idempotency/bad-key`.
 *   - When the store has a hit AND the cached fingerprint matches the
 *     inbound request fingerprint, replays the cached
 *     `{ statusCode, headers, body }` and DOES NOT call `next()`.
 *   - When the store has a hit AND the fingerprint differs, refuses
 *     with HTTP 422 + `idempotency/key-reuse-mismatch`.
 *   - On a miss, wraps `res.end` to capture the handler's response
 *     and persist `{ fingerprint, statusCode, headers, body }` to
 *     the store with `ttlMs` (default 24h) after the handler
 *     finishes. The wrapper does NOT capture 5xx server-error
 *     responses — replaying a transient infrastructure failure is
 *     not idempotent.
 *
 * Per the draft §4.4, a concurrent-retry from the same client (two
 * requests with the same key arriving in quick succession before
 * the first has written to the store) is allowed to handler-execute
 * twice and either response is acceptable; the framework does not
 * lock the key. Operators wanting strict at-most-once execution
 * implement a distributed-lock layer in their store's `set()`
 * method (the interface is opaque to the middleware).
 *
 * @opts
 *   store:                 object,   // required — get/set/delete interface
 *   ttlMs:                 number,   // default: 24h
 *   methods:               string[], // default: ["POST","PUT","PATCH","DELETE"]
 *   headerName:            string,   // default: "idempotency-key"
 *   requireIdempotencyKey: boolean,  // default: false — refuse missing-key
 *   bodyFingerprint:       function, // (req) => Buffer|string|object|null — operator-supplied body extractor
 *   maxBodyBytes:          number,   // default: 1 MiB — replay-cache body cap
 *   bodyFingerprintFallback: string, // default "deny" — when neither
 *                                    // bodyFingerprint nor req._rawBody / req.body is
 *                                    // available for POST/PUT/PATCH, refuse with HTTP 400
 *                                    // idempotency/missing-body-fingerprint instead of
 *                                    // silently degrading the fingerprint to method+path.
 *                                    // Set to "method-path-only" to restore the pre-0.9.58
 *                                    // behavior (the audit chain still logs
 *                                    // idempotency.empty_body_fingerprint so the
 *                                    // misorder is visible in operator review).
 *
 * **Mount order — idempotency MUST run AFTER body-parser.** The hook
 * (and the default `req._rawBody||req.body` lookup) reads request
 * state at the moment the idempotency middleware runs; if it runs
 * before body-parser, `req.body` is still unset and the fingerprint
 * silently degrades to method+path only — which fails the §4.3
 * "same key, different body" guarantee. `b.middleware.composePipeline`
 * places bodyParser=20 / idempotency=30 by default so the canonical
 * order is correct; operators wiring middleware manually must mount
 * idempotency AFTER bodyParser. The runtime emits
 * `idempotency.empty_body_fingerprint` audit (warning) whenever a
 * body-bearing request reaches the middleware with no body data,
 * so the misordering is detectable from audit logs.
 *
 * @example
 *   var store = b.middleware.idempotencyKey.memoryStore({ maxEntries: 10000 });
 *   var mw = b.middleware.idempotencyKey({
 *     store:     store,
 *     ttlMs:     C.TIME.hours(24),
 *     methods:   ["POST", "PUT", "PATCH"],
 *     // Optional: provide a body-fingerprint extractor that pulls
 *     // from the parsed body shape. The extractor only runs against
 *     // state populated by upstream middleware; mount idempotency
 *     // AFTER bodyParser (composePipeline does this by default).
 *     bodyFingerprint: function (req) { return req.body || null; },
 *   });
 *   app.use(mw);
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new IdempotencyError("idempotency/bad-opts",
      "idempotencyKey: opts must be a non-null object", true);
  }
  _validateStore(opts.store, "idempotencyKey");
  numericBounds.requirePositiveFiniteIntIfPresent(
    opts.ttlMs, "idempotencyKey.ttlMs", IdempotencyError, "idempotency/bad-ttl");
  var ttlMs = opts.ttlMs !== undefined ? opts.ttlMs : C.TIME.hours(24);
  var methods = Array.isArray(opts.methods) && opts.methods.length > 0
    ? opts.methods.map(function (m) { return String(m).toUpperCase(); })
    : DEFAULT_METHODS.slice();
  var headerName = typeof opts.headerName === "string" && opts.headerName.length > 0
    ? opts.headerName.toLowerCase()
    : "idempotency-key";
  var requireKey = opts.requireIdempotencyKey === true;
  // Operator-supplied body-fingerprint extractor. When provided,
  // the middleware calls this instead of the inline
  // `req._rawBody || req.body` lookup. Lets operators mount
  // body-parser BEFORE the idempotency middleware and surface the
  // parsed body shape (req.body is the typical post-parser
  // attachment point); the inline lookup runs BEFORE body-parser
  // by default, so the fingerprint silently degrades to
  // method+path-only when body-parser mounts after. With this
  // hook the middleware reads the body shape the operator
  // canonically attached, regardless of mount order.
  var bodyFingerprintFn = validateOpts.optionalFunction(
    opts.bodyFingerprint, "idempotencyKey.bodyFingerprint",
    IdempotencyError, "idempotency/bad-body-fingerprint"
  ) || null;
  // Default "deny" refuses body-bearing requests that
  // arrive with neither req._rawBody / req.body NOR an operator-
  // supplied bodyFingerprint hook. The silent-degrade-to-method+path
  // path was a §4.3 violation (same key + different body returned
  // false replays); the runtime now refuses with HTTP 400 instead.
  // Operators with a documented "method-path-only" use case opt in.
  var bodyFpFallback = "deny";
  if (opts.bodyFingerprintFallback !== undefined) {
    if (opts.bodyFingerprintFallback !== "deny" &&
        opts.bodyFingerprintFallback !== "method-path-only") {
      throw new IdempotencyError("idempotency/bad-body-fingerprint-fallback",
        "idempotencyKey: opts.bodyFingerprintFallback must be \"deny\" or \"method-path-only\", got " +
        JSON.stringify(opts.bodyFingerprintFallback), true);
    }
    bodyFpFallback = opts.bodyFingerprintFallback;
  }

  // Per-response collector cap. Idempotency replay only makes sense
  // for response bodies that fit in memory; the cap is operator-
  // tunable via opts.maxBodyBytes (default 1 MiB).
  numericBounds.requirePositiveFiniteIntIfPresent(
    opts.maxBodyBytes, "idempotencyKey.maxBodyBytes", IdempotencyError, "idempotency/bad-max-body");
  var maxBodyBytes = opts.maxBodyBytes !== undefined ? opts.maxBodyBytes : C.BYTES.mib(1);

  return function idempotencyMiddleware(req, res, next) {
    var method = (req.method || "GET").toUpperCase();
    if (methods.indexOf(method) === -1) return next();

    var key = req.headers && req.headers[headerName];
    if (Array.isArray(key)) key = key[0];

    if (!key || typeof key !== "string" || key.length === 0) {
      if (!requireKey) return next();
      var missing = problemDetails().create({
        type:   problemDetails().getBase() + "/idempotency/missing-key",
        title:  "Idempotency-Key header required",
        status: 400,                                                                               // HTTP status 400 Bad Request
        detail: "This endpoint requires an Idempotency-Key header (draft-ietf-httpapi-idempotency-key).",
      });
      _emitAudit("idempotency.missing_key", { method: method, path: req.url }, "denied");
      return problemDetails().respond(res, missing);
    }

    if (key.length > KEY_MAX_LEN || !KEY_RE.test(key)) {
      var bad = problemDetails().create({
        type:   problemDetails().getBase() + "/idempotency/bad-key",
        title:  "Idempotency-Key malformed",
        status: 400,                                                                               // HTTP status 400
        detail: "Idempotency-Key must be ASCII printable, length 1.." + KEY_MAX_LEN + " (draft §2).",
      });
      _emitAudit("idempotency.bad_key", { method: method, keyLen: key.length }, "denied");
      return problemDetails().respond(res, bad);
    }

    var bodyBytes;
    if (bodyFingerprintFn) {
      // Operator-supplied hook — called after body-parser so req.body
      // is populated. Hook returns Buffer / string / null.
      try {
        var fpVal = bodyFingerprintFn(req);
        if (fpVal === null || fpVal === undefined) {
          bodyBytes = null;
        } else if (Buffer.isBuffer(fpVal)) {
          bodyBytes = fpVal;
        } else if (typeof fpVal === "string") {
          bodyBytes = Buffer.from(fpVal, "utf8");
        } else {
          // Object / array — JSON-stringify so the hash is stable.
          bodyBytes = Buffer.from(JSON.stringify(fpVal), "utf8");
        }
      } catch (e) {
        _emitAudit("idempotency.body_fingerprint_failed",
          { error: String(e && e.message || e) }, "warning");
        bodyBytes = null;
      }
    } else {
      bodyBytes = req._rawBody || req.body || null;
      if (bodyBytes && typeof bodyBytes === "object" && !Buffer.isBuffer(bodyBytes)) {
        // Buffer-ize a non-buffer body (already-parsed JSON, etc.) so the
        // hash is stable. JSON.stringify with sorted keys would be more
        // robust but the operator-attached body shape is whatever the
        // upstream parser produced; canonicalization is operator-side.
        try {
          bodyBytes = Buffer.from(JSON.stringify(bodyBytes), "utf8");
        } catch (_e) {
          bodyBytes = null;
        }
      }
    }

    // Misordered-mount detector — body-bearing method reached us
    // with neither a parsed body nor a raw-body buffer. Most likely
    // body-parser hasn't run yet, which used to silently degrade the
    // fingerprint to method+path; v0.9.58 makes that
    // case refuse with HTTP 400 by default. The audit emit fires in
    // both fallback modes so operator review surfaces the
    // misconfiguration regardless of the chosen fallback.
    if (!bodyBytes && (method === "POST" || method === "PUT" || method === "PATCH")) {
      _emitAudit("idempotency.empty_body_fingerprint",
        {
          method:          method,
          path:            req.url,
          hasRawBody:      Boolean(req._rawBody),
          hasParsedBody:   req.body !== undefined && req.body !== null,
          hasFingerprintHook: Boolean(bodyFingerprintFn),
          fallback:        bodyFpFallback,
        },
        bodyFpFallback === "deny" ? "denied" : "warning");
      if (bodyFpFallback === "deny") {
        var missingBody = problemDetails().create({
          type:   problemDetails().getBase() + "/idempotency/missing-body-fingerprint",
          title:  "Idempotency body fingerprint unavailable",
          status: 400,                                                                               // HTTP status 400 Bad Request
          detail: "The idempotency middleware could not derive a body fingerprint for this " +
                  "request. Mount body-parser BEFORE the idempotency middleware, OR provide an " +
                  "opts.bodyFingerprint(req) hook. To restore the pre-0.9.58 method+path-only " +
                  "behavior, set opts.bodyFingerprintFallback=\"method-path-only\".",
        });
        return problemDetails().respond(res, missingBody);
      }
    }

    var fingerprint = _fingerprintRequest(req, bodyBytes, opts.store);

    var cached = null;
    try { cached = opts.store.get(key); }
    catch (_storeErr) {
      // Store-read failure — emit audit + treat as miss. Idempotency is
      // a best-effort optimization; the handler runs anyway.
      _emitAudit("idempotency.store_read_failed",
        { key: _redactKey(key), error: String(_storeErr.message || _storeErr) }, "warning");
      cached = null;
    }

    if (cached) {
      if (cached.fingerprint !== fingerprint) {
        // §4.3 — same key, different request body. Client mistake.
        var mismatch = problemDetails().create({
          type:   problemDetails().getBase() + "/idempotency/key-reuse-mismatch",
          title:  "Idempotency-Key reused with different request",
          status: 422,                                                                             // HTTP status 422 Unprocessable Content (RFC 9110)
          detail: "The Idempotency-Key matches a prior request but the request body/method/path differs (draft §4.3).",
        });
        _emitAudit("idempotency.key_reuse_mismatch",
          { method: method, path: req.url, keyHash: _hashKey(key) }, "denied");
        return problemDetails().respond(res, mismatch);
      }
      // Replay. The cached body is a base64 string of the original
      // bytes; restore Buffer + write through the response.
      var rawBody;
      try { rawBody = Buffer.from(cached.body || "", "base64"); }
      catch (_decodeErr) { rawBody = Buffer.alloc(0); }
      res.statusCode = cached.statusCode;
      var headerKeys = Object.keys(cached.headers || {});
      for (var i = 0; i < headerKeys.length; i += 1) {
        try { res.setHeader(headerKeys[i], cached.headers[headerKeys[i]]); }
        catch (_hdrErr) { /* operator-restricted header — skip */ }
      }
      _emitAudit("idempotency.replay",
        { method: method, path: req.url, statusCode: cached.statusCode, keyHash: _hashKey(key) });
      res.end(rawBody);
      return;
    }

    // Miss — capture the handler's response. The bounded collector
    // refuses bodies > maxBodyBytes at push() time (operator can
    // tune via opts.maxBodyBytes; default 1 MiB). When the cap is
    // hit, we abandon the capture + emit audit + DO NOT cache;
    // operators wanting larger replay windows raise the cap.
    var origEnd   = res.end.bind(res);
    var origWrite = res.write.bind(res);
    var collector = safeBuffer.boundedChunkCollector({
      maxBytes:    maxBodyBytes,
      errorClass:  IdempotencyError,
      sizeCode:    "idempotency/body-too-large",
      sizeMessage: "idempotency: response body exceeded maxBodyBytes (cap=" + maxBodyBytes + "); not cached.",
    });
    var captured = false;
    var oversized = false;
    function _pushChunk(chunk, encoding) {
      if (oversized || !chunk) return;
      try { collector.push(_toBuffer(chunk, encoding)); }
      catch (_capErr) {
        oversized = true;
        _emitAudit("idempotency.body_too_large",
          { method: method, path: req.url, cap: maxBodyBytes, keyHash: _hashKey(key) }, "warning");
      }
    }
    res.write = function (chunk, encoding) {
      _pushChunk(chunk, encoding);
      return origWrite(chunk, encoding);
    };
    res.end = function (chunk, encoding) {
      if (!captured) {
        captured = true;
        _pushChunk(chunk, encoding);
        var status = res.statusCode || 200;                                                        // default HTTP status 200
        // Only persist 2xx-4xx responses; 5xx is transient infra
        // failure that should be retried fresh, not replayed.
        if (!oversized && status >= 200 && status < 500) {                                         // HTTP status class boundaries
          var headerMap = {};
          try {
            var allHeaders = typeof res.getHeaders === "function" ? res.getHeaders() : {};
            var hk = Object.keys(allHeaders);
            for (var j = 0; j < hk.length; j += 1) {
              if (hk[j] === "set-cookie") continue;   // Set-Cookie is per-request and unsafe to replay
              headerMap[hk[j]] = allHeaders[hk[j]];
            }
          } catch (_e) { /* ignore */ }
          var combined = collector.result();
          try {
            opts.store.set(key, {
              fingerprint: fingerprint,
              statusCode:  status,
              headers:     headerMap,
              body:        combined.toString("base64"),
            }, ttlMs);
            _emitAudit("idempotency.cache_store",
              { method: method, path: req.url, statusCode: status, keyHash: _hashKey(key), bodyBytes: combined.length });
          } catch (storeErr) {
            _emitAudit("idempotency.store_write_failed",
              { key: _redactKey(key), error: String(storeErr.message || storeErr) }, "warning");
          }
        } else if (!oversized) {
          _emitAudit("idempotency.skip_5xx",
            { method: method, path: req.url, statusCode: status, keyHash: _hashKey(key) });
        }
      }
      return origEnd(chunk, encoding);
    };
    next();
  };
}

function _toBuffer(chunk, encoding) {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (typeof chunk === "string") return Buffer.from(chunk, encoding || "utf8");
  return Buffer.from(String(chunk));
}

function _hashKey(key) {
  // Hash before logging — operator's audit chain shouldn't carry raw
  // idempotency keys (clients sometimes inadvertently put PII / order
  // numbers in them).
  return nodeCrypto.createHash("sha3-256").update(key, "utf8").digest("hex").slice(0, 16);         // log-truncation length, not bytes
}

function _redactKey(key) {
  if (typeof key !== "string") return "<non-string>";
  if (key.length <= 8) return "<short:" + key.length + ">";                                        // log-redaction length threshold
  return key.slice(0, 4) + "..." + key.slice(-2) + " (len=" + key.length + ")";                    // log-redaction prefix/suffix lengths
}

/**
 * @primitive b.middleware.idempotencyKey.resealMigrate
 * @signature b.middleware.idempotencyKey.resealMigrate(store)
 * @since     0.9.58
 * @related   b.middleware.idempotencyKey.dbStore
 *
 * One-shot operator helper that walks a dbStore's table and reseals
 * every row under the AAD-bound envelope shape introduced in v0.9.58.
 * Existing v0.9.15-v0.9.57 rows continue to read on a
 * per-row basis (unsealRow auto-detects shape) so a deploy without
 * this call is correct, but operators who want to upgrade in bulk
 * call this once after upgrading.
 *
 * Returns `{ migrated, skipped, reason }`. `migrated` counts rows
 * rewritten with AAD-bound ciphertext; `skipped` counts rows already
 * AAD-shaped or that failed unseal under the current key (those rows
 * stay in place and surface via the standard
 * `idempotency.unseal_failed` audit on next read). `reason` is null
 * on success; populated when the store doesn't support migration
 * (in-memory store, custom operator-supplied store, etc.).
 *
 * @example
 *   var store = b.middleware.idempotencyKey.dbStore({ db: myDb });
 *   var info  = b.middleware.idempotencyKey.resealMigrate(store);
 *   logger.info("idempotency migration", info);
 */
function resealMigrate(store) {
  if (!store || typeof store.resealMigrate !== "function") {
    return { migrated: 0, skipped: 0, reason: "store-does-not-support-reseal" };
  }
  return store.resealMigrate();
}

module.exports = create;
module.exports.create     = create;
module.exports.memoryStore = memoryStore;
module.exports.dbStore     = dbStore;
module.exports.resealMigrate = resealMigrate;
module.exports.DEFAULT_METHODS = DEFAULT_METHODS;
module.exports.IdempotencyError = IdempotencyError;
