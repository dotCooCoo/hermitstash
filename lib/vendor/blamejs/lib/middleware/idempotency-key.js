// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var requestHelpers = require("../request-helpers");
var safeJson      = require("../safe-json");
var safeSql       = require("../safe-sql");
var sql           = require("../sql");
var bCrypto       = require("../crypto");
var cryptoField   = require("../crypto-field");
var vault         = require("../vault");
var { defineClass } = require("../framework-error");

var auditEmit      = require("../audit-emit");
var problemDetails = lazyRequire(function () { return require("../problem-details"); });
var C              = require("../constants");

var IdempotencyError = defineClass("IdempotencyError", { alwaysPermanent: true });

var DEFAULT_METHODS = Object.freeze(["POST", "PUT", "PATCH", "DELETE"]);

var KEY_RE = /^[\x21-\x7E]+$/;
var KEY_MAX_LEN = 255;

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
  var maxEntries = opts.maxEntries !== undefined ? opts.maxEntries : 10000;
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
  try { safeSql.validateIdentifier(tableNameRaw, { allowReserved: true }); }
  catch (sqlErr) {
    throw new IdempotencyError("idempotency/bad-table-name",
      "dbStore: opts.tableName is not a valid SQL identifier: " +
      (sqlErr && sqlErr.message ? sqlErr.message : String(sqlErr)), true);
  }
  var sqlOpts = { dialect: "sqlite", quoteName: true };
  var doInit   = opts.init     !== false;
  var hashKeys = opts.hashKeys !== false;
  var sealReq  = opts.seal     !== false;
  var aadOn    = opts.aad      !== false;
  var fpSealOn = opts.fingerprintSeal !== false;
  var db = opts.db;

  var sealEnabled = false;
  if (sealReq) {
    try {
      // allow:seal-without-aad-by-design — vault-readiness probe; throwaway
      vault.seal("__idempotency_seal_probe__");
      sealEnabled = true;
    } catch (_vaultErr) {
      _emitAudit("idempotency.seal_skipped_no_vault",
        { tableName: tableNameRaw,
          reason: "vault.init() has not run; sealing falls back to plaintext" },
        "warning");
    }
  }

  if (sealEnabled) {
    cryptoField.registerTable(tableNameRaw, {
      sealedFields: ["headers", "body"],
      aad:          aadOn,
      rowIdField:   "k",
      schemaVersion: "1",
    });
  }

  var fpHmacSecret = null;
  if (fpSealOn) {
    try {
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

  var _slot = 0;
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
        headersObj = safeJson.parse(liveRow.headers, { maxBytes: C.BYTES.mib(4) });
      } catch (_jsonErr) {
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
    fingerprintHmac: function (preimageBytes) {
      if (!fpSealOn || !fpHmacSecret) return null;
      return nodeCrypto.createHmac("sha3-256", fpHmacSecret)
        .update(preimageBytes).digest("hex");
    },
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
  validateOpts.requireMethods(store, ["get", "set", "delete"],
    where + ": store", IdempotencyError, "idempotency/bad-store", true);
}

function _defaultScope(req) {
  var actor = requestHelpers.extractActorContext(req);
  return actor && typeof actor.userId === "string" && actor.userId ? actor.userId : "anon";
}

function _fingerprintRequest(req, bodyBytes, store) {
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

var _emitAudit = auditEmit.emit;

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
  var bodyFingerprintFn = validateOpts.optionalFunction(
    opts.bodyFingerprint, "idempotencyKey.bodyFingerprint",
    IdempotencyError, "idempotency/bad-body-fingerprint"
  ) || null;
  var scopeFn = validateOpts.optionalFunction(
    opts.scopeFn, "idempotencyKey.scopeFn",
    IdempotencyError, "idempotency/bad-scope-fn") || _defaultScope;
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
        status: C.HTTP.STATUS.BAD_REQUEST,
        detail: "This endpoint requires an Idempotency-Key header (draft-ietf-httpapi-idempotency-key).",
      });
      _emitAudit("idempotency.missing_key", { method: method, path: req.url }, "denied");
      return problemDetails().respond(res, missing);
    }

    if (key.length > KEY_MAX_LEN || !KEY_RE.test(key)) {
      var bad = problemDetails().create({
        type:   problemDetails().getBase() + "/idempotency/bad-key",
        title:  "Idempotency-Key malformed",
        status: C.HTTP.STATUS.BAD_REQUEST,
        detail: "Idempotency-Key must be ASCII printable, length 1.." + KEY_MAX_LEN + " (draft §2).",
      });
      _emitAudit("idempotency.bad_key", { method: method, keyLen: key.length }, "denied");
      return problemDetails().respond(res, bad);
    }

    var scope = String(scopeFn(req) || "anon");
    var scopedKey = scope.length + ":" + scope + ":" + key;

    var bodyBytes;
    if (bodyFingerprintFn) {
      try {
        var fpVal = bodyFingerprintFn(req);
        if (fpVal === null || fpVal === undefined) {
          bodyBytes = null;
        } else if (Buffer.isBuffer(fpVal)) {
          bodyBytes = fpVal;
        } else if (typeof fpVal === "string") {
          bodyBytes = Buffer.from(fpVal, "utf8");
        } else {
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
        try {
          bodyBytes = Buffer.from(JSON.stringify(bodyBytes), "utf8");
        } catch (_e) {
          bodyBytes = null;
        }
      }
    }

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
          status: C.HTTP.STATUS.BAD_REQUEST,
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
    try { cached = opts.store.get(scopedKey); }
    catch (_storeErr) {
      _emitAudit("idempotency.store_read_failed",
        { key: _redactKey(key), error: String(_storeErr.message || _storeErr) }, "warning");
      cached = null;
    }

    if (cached) {
      if (cached.fingerprint !== fingerprint) {
        var mismatch = problemDetails().create({
          type:   problemDetails().getBase() + "/idempotency/key-reuse-mismatch",
          title:  "Idempotency-Key reused with different request",
          status: C.HTTP.STATUS.UNPROCESSABLE_CONTENT,
          detail: "The Idempotency-Key matches a prior request but the request body/method/path differs (draft §4.3).",
        });
        _emitAudit("idempotency.key_reuse_mismatch",
          { method: method, path: req.url, keyHash: _hashKey(key) }, "denied");
        return problemDetails().respond(res, mismatch);
      }
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
        var status = res.statusCode || C.HTTP.STATUS.OK;
        if (!oversized &&
            (C.HTTP.success(status) || C.HTTP.redirect(status) || C.HTTP.clientError(status))) {
          var headerMap = {};
          try {
            var allHeaders = typeof res.getHeaders === "function" ? res.getHeaders() : {};
            var hk = Object.keys(allHeaders);
            for (var j = 0; j < hk.length; j += 1) {
              if (hk[j] === "set-cookie") continue;
              headerMap[hk[j]] = allHeaders[hk[j]];
            }
          } catch (_e) { /* ignore */ }
          var combined = collector.result();
          try {
            opts.store.set(scopedKey, {
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
  return nodeCrypto.createHash("sha3-256").update(key, "utf8").digest("hex").slice(0, 16);
}

function _redactKey(key) {
  if (typeof key !== "string") return "<non-string>";
  if (key.length <= 8) return "<short:" + key.length + ">";
  return key.slice(0, 4) + "..." + key.slice(-2) + " (len=" + key.length + ")";
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
