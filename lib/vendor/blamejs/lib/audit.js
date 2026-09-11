// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.audit
 * @featured true
 * @nav    Observability
 * @title  Audit
 *
 * @intro
 *   Tamper-evident, append-only record of every privileged action — the
 *   forensic surface every compliance posture (HIPAA / PCI-DSS / SOC 2 /
 *   GDPR / SOX / DORA) bottoms out on. The `audit_log` table is baked
 *   into db.js's schema runner so apps cannot opt out; the chain is
 *   verified at boot and a break refuses-to-boot.
 *
 *   Hash chain: every row carries `prevHash` + `rowHash` computed over
 *   the SEALED form of the row plus a nonce. Verification recomputes
 *   directly from disk without unsealing — auditors can confirm
 *   integrity without holding the vault key. Periodic SLH-DSA-SHAKE-256f
 *   checkpoints (post-quantum signatures over the chain tip) anchor the
 *   chain to off-line evidence; tampering that recomputes hashes still
 *   fails checkpoint verification.
 *
 *   Namespaces: framework owns `auth.*` / `system.*` / `audit.*` /
 *   `consent.*` / `subject.*`; apps call `registerNamespace("orders")`
 *   at boot before emitting `orders.created`. Unregistered namespaces
 *   are rejected so typos don't become silent unobservable events.
 *
 *   Action shape — the 5W form: WHO (`actor.userId` / sessionId / ip /
 *   userAgent), WHAT (`action` = "namespace.verb[.qualifier]"), WHEN
 *   (`recordedAt` ms epoch + monotonic counter), WHERE (`resource.kind`
 *   / id), HOW (`outcome` ∈ {success, warning, failure, denied} + `reason` +
 *   `metadata`).
 *
 *   Two emit paths:
 *     - `record(event)` — async, throws on bad input, awaits the chain
 *       append. Use when the caller needs durability before continuing.
 *     - `emit(event)` / `safeEmit(event)` — synchronous fire-and-forget;
 *       events buffer in an AsyncHandler and drain serially through
 *       record(). `safeEmit` is drop-silent on malformed input by
 *       design: it runs in request hot paths where throwing would crash
 *       the request that triggered the audit attempt.
 *
 *   Reserved metadata keys: `traceId` (cross-request correlation,
 *   `beginTrace()` mints), `parentEventId`, `before` / `after` (state
 *   diff for change events), `evidenceRef` (pointer to signed PDF /
 *   ticket).
 *
 * @card
 *   Tamper-evident, append-only record of every privileged action — the forensic surface every compliance posture (HIPAA / PCI-DSS / SOC 2 / GDPR / SOX / DORA) bottoms out on.
 */
var auditChain = require("./audit-chain");
var auditSign = require("./audit-sign");
var chainWriter = require("./chain-writer");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var { generateToken } = require("./crypto");
var cryptoField = require("./crypto-field");
var frameworkSchema = require("./framework-schema");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var dbRoleContext = require("./db-role-context");
var handlers = require("./handlers");
var { boot } = require("./log");
var redact = require("./redact");
var safeAsync = require("./safe-async");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var observability = require("./observability");
var { AuditChainOriginError, AuditSegregationError, ClusterError } = require("./framework-error");

var log = boot("audit");

var EXTERNAL_STORE_TIMEOUT_MS = C.TIME.seconds(30);

// Shadow failures are drop-silent — hot-path observability sinks
var _externalStore = null;

var _externalStoreMode = "shadow";

var FRAMEWORK_SQL_TIMEOUT_MS = C.TIME.seconds(30);

function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

async function _readLastCheckpointCounter() {
  var built = sql.select("audit_checkpoints", _sqlOpts())
    .columns(["atMonotonicCounter"])
    .orderBy("atMonotonicCounter", "desc")
    .limit(1)
    .toSql();
  return await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeOne(built.sql, built.params);
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readLastCheckpoint" }
  );
}

async function _readAllCheckpointsAsc() {
  var built = sql.select("audit_checkpoints", _sqlOpts())
    .orderBy("atMonotonicCounter", "asc")
    .toSql();
  return await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeAll(built.sql, built.params);
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readAllCheckpoints" }
  );
}

async function _readAuditRowHashAtCounter(counter) {
  var built = sql.select("audit_log", _sqlOpts())
    .columns(["rowHash"])
    .where("monotonicCounter", counter)
    .toSql();
  return await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeOne(built.sql, built.params);
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readRowHashAtCounter" }
  );
}

var _CHECKPOINT_COLS = [
  "_id", "createdAt", "atMonotonicCounter", "atRowHash",
  "signature", "publicKeyFingerprint", "fencingToken",
];

async function _insertCheckpoint(values) {
  var rowObj = {};
  for (var i = 0; i < _CHECKPOINT_COLS.length; i++) rowObj[_CHECKPOINT_COLS[i]] = values[i];
  var built = sql.insert("audit_checkpoints", _sqlOpts())
    .columns(_CHECKPOINT_COLS)
    .values(rowObj)
    .toSql();
  return await safeAsync.withTimeout(
    clusterStorage.execute(built.sql, built.params),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.insertCheckpoint" }
  );
}

var _DUP_COUNTER_REFS = ["atmonotoniccounter", "chkpt_counter"];
var _DUP_UNIQUE_SIGNALS = [
  "unique constraint failed", "sqlite_constraint", "duplicate key",
  "23505", "duplicate entry", "er_dup_entry", "1062",
];
function _errorTextContainsAny(text, needles) {
  for (var i = 0; i < needles.length; i++) {
    if (text.indexOf(needles[i]) !== -1) return true;
  }
  return false;
}
function _isDuplicateCheckpointCounter(e) {
  if (!e) return false;
  var parts = [e.message, e.detail, e.constraint, e.sqlMessage, e.table, e.code, e.errno];
  var text = "";
  for (var i = 0; i < parts.length; i++) {
    if (parts[i] != null) text += " " + String(parts[i]);
  }
  if (typeof e.toString === "function") text += " " + e.toString();
  text = text.toLowerCase();
  return _errorTextContainsAny(text, _DUP_COUNTER_REFS) &&
         _errorTextContainsAny(text, _DUP_UNIQUE_SIGNALS);
}

async function _upsertAuditTip(counter, rowHash, signedAt, fencingToken) {
  var fence = await clusterStorage.fencedUpsert({
    table:      "_blamejs_audit_tip",   // allow:hand-rolled-sql — bare logical key
    keyColumns: ["scope"],
    label:      "audit.upsertAuditTip",
    timeoutMs:  FRAMEWORK_SQL_TIMEOUT_MS,
    values: {
      scope:              "audit",
      atMonotonicCounter: counter,
      rowHash:            rowHash,
      signedAt:           signedAt,
      fencingToken:       fencingToken,
    },
  });
  if (fence.fenced) {
    throw new ClusterError(
      "audit/fenced-out",
      "audit-tip update rejected: incoming fencingToken=" + fencingToken +
      " is below the stored token (this leader has been fenced out " +
      "by a higher-token successor)",
      true
    );
  }
}

var FRAMEWORK_NAMESPACES = [
  "auth", "system", "audit", "consent", "subject",
  "apikey",
  "app",
  "backup",
  "breakglass",
  "cache",
  "compliance",
  "config",
  "csrf",
  "db",
  "dkim",
  "dora",
  "dsa",
  "dsr",
  "dual",
  "mail",
  "mtls",
  "network",
  "notify",
  "objectstore",
  "openapi",
  "asyncapi",
  "vault",
  "wsclient",
  "inbox",
  "flag",
  "permissions",
  "pipl",
  "pqcagent",
  "privacy",
  "restore",
  "retention",
  "scheduler",
  "seeders",
  "webhook",
  "sse",
  "mcp",
  "graphqlfederation",
  "aiinput",
  "aioutput",
  "aiprompt",
  "a2a",
  "darkpatterns",
  "budr",
  "seccyber",
  "iabtcf",
  "fapi2",
  "contentcredentials",
  "aipref",
  "fdx",
  "tcpa10dlc",
  "iabmspa",
  "vendor",
  "honeytoken",
  "csp",
  "resourceaccesslock",
  "process",
  "keychain",
  "fda21cfr11",
  "ddl",
  "migrations",
  "dlp",
  "session",
  "sandbox",
  "safeurl",
  "http",
  "cryptofield",
  "acme",
  "cert",
  "tls",
  "workerpool",
  "jwt",
  "dr",
  "guardfilename",
  "legalhold",
  "networkheartbeat",
  "router",
  "http2",
  "tenant",
  "httpclient",
  "mailmdn",
  "mailarf",
  "mailbimi",
  "localdb",
  "dataact",
  "idempotency",
  "aibom",
  "aicontentdetect",
  "sdnotify",
  "bootgates",
  "metrics",
  "jose",
  "ai",
  "breach",
  "cra",
  "gdpr",
  "incident",
  "middleware",
  "nis2",
];
var registeredNamespaces = new Set(FRAMEWORK_NAMESPACES);

var HASHABLE_COLS = [
  "_id", "recordedAt", "monotonicCounter",
  "actorUserId", "actorUserIdHash",
  "actorIp",
  "actorUserAgent", "actorSessionId",
  "action", "resourceKind",
  "resourceId", "resourceIdHash",
  "outcome", "reason", "metadata", "requestId",
];

// Lazy db ref — avoids circular require (db -> audit -> db on init paths).
var db = lazyRequire(function () { return require("./db"); });

var _purgeAnchorPolicy = {
  resolvePublicKey: undefined,
  allowUnsigned:    false,
  allowUnchecked:   false,
};

async function _resolveChainOrigin() {
  var anchor;
  var built = sql.select("_blamejs_audit_purge_anchor", _sqlOpts())   // allow:hand-rolled-sql
    .where("scope", "audit")
    .toSql();
  anchor = await clusterStorage.executeOne(built.sql, built.params);
  if (!anchor) return null;

  var verdict = auditChain.verifyPurgeAnchor(anchor, {
    resolvePublicKey: _purgeAnchorPolicy.resolvePublicKey,
    allowUnsigned:    _purgeAnchorPolicy.allowUnsigned,
  });
  if (verdict.status === "valid" ||
      (verdict.status === "unsigned" && verdict.accepted) ||
      (verdict.status === "unchecked" && _purgeAnchorPolicy.allowUnchecked)) {
    return { hash: verdict.hash, counter: verdict.counter };
  }
  throw new AuditChainOriginError(
    "audit/purge-anchor-not-verified",
    "audit_log carries a purge anchor that cannot be believed — " + verdict.reason +
    ". Refusing to append: the anchor says which rows may be missing, and a row " +
    "written without it would be linked to nothing and skipped by verification."
  );
}

var _chainWriter = chainWriter.create({
  table:           "audit_log",
  hashableColumns: HASHABLE_COLS,
  resolveOrigin:   _resolveChainOrigin,
  columnsForInsert: [
    "_id", "recordedAt", "monotonicCounter",
    "actorUserId", "actorUserIdHash",
    "actorIp",
    "actorUserAgent", "actorSessionId",
    "action", "resourceKind",
    "resourceId", "resourceIdHash",
    "outcome", "reason", "metadata", "requestId",
    "prevHash", "rowHash", "nonce", "fencingToken",
  ],
});

/**
 * @primitive b.audit.registerNamespace
 * @signature b.audit.registerNamespace(name)
 * @since     0.1.0
 * @related   b.audit.record, b.audit.safeEmit
 *
 * Register an action namespace at app bootstrap so `record()` / `emit()`
 * accept events under it. Names must match `[a-z][a-z0-9_]*`. Calling
 * twice is a no-op. Framework namespaces (auth / system / audit /
 * consent / subject + every per-primitive namespace) are pre-registered.
 *
 * @example
 *   b.audit.registerNamespace("orders");
 *   b.audit.safeEmit({
 *     action:  "orders.shipped",
 *     actor:   { userId: "u-42" },
 *     outcome: "success",
 *   });
 */
function registerNamespace(name) {
  if (typeof name !== "string" || !/^[a-z][a-z0-9_]*$/.test(name)) {
    throw new Error("audit namespace must match [a-z][a-z0-9_]* — got: " + name);
  }
  if (FRAMEWORK_NAMESPACES.indexOf(name) !== -1) return;
  registeredNamespaces.add(name);
}

function _validateAction(action) {
  if (typeof action !== "string" || !/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(action)) {
    throw new Error(
      "audit action must be 'namespace.verb[.qualifier...]' (lowercase, dot-separated) — got: " + action
    );
  }
  var ns = action.split(".")[0];
  if (!registeredNamespaces.has(ns)) {
    throw new Error(
      "audit namespace '" + ns + "' is not registered. " +
      "Call audit.registerNamespace('" + ns + "') at app bootstrap before recording '" + action + "'."
    );
  }
}

/**
 * @primitive b.audit.record
 * @signature b.audit.record(event)
 * @since     0.1.0
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.audit.safeEmit, b.audit.emit, b.audit.flush
 *
 * Append one event to the audit chain and await durability. Throws on a
 * bad action shape, an unregistered namespace, or an outcome outside
 * {success, warning, failure, denied}. The chain-writer serializes the actual
 * INSERT under a mutex so concurrent record() calls produce a strictly
 * monotonic counter and a valid prevHash → rowHash chain.
 *
 * Use record() when the caller must know the row landed before
 * continuing (consent grants, break-glass unseals, change-control
 * approvals). For request hot paths where best-effort is acceptable,
 * prefer safeEmit().
 *
 * @opts
 *   actor:     { userId, ip, userAgent, sessionId },
 *   action:    "namespace.verb[.qualifier]",
 *   resource:  { kind, id },
 *   outcome:   "success" | "warning" | "failure" | "denied",   // warning = a partial result
 *   reason:    string,
 *   metadata:  object,             // serialized to JSON
 *   requestId: string,
 *
 * @example
 *   await b.audit.record({
 *     actor:    { userId: "u-42", ip: "10.0.0.1" },
 *     action:   "consent.granted",
 *     resource: { kind: "purpose", id: "marketing" },
 *     outcome:  "success",
 *     metadata: { traceId: b.audit.beginTrace() },
 *   });
 */
async function record(event) {
  if (!event || typeof event !== "object") {
    throw new Error("audit.record requires an event object");
  }
  _validateAction(event.action);
  if (!event.outcome || OUTCOME_VALUES.indexOf(event.outcome) === -1) {
    throw new Error("audit.record outcome must be one of " + OUTCOME_VALUES.join(", "));
  }

  return observability.tap("audit.record",
    { action: event.action, outcome: event.outcome },
    async function () {
      var actor    = event.actor    || {};
      var resource = event.resource || {};
      var logical = {
        actorUserId:       actor.userId    || null,
        actorIp:           actor.ip        || null,
        actorUserAgent:    actor.userAgent || null,
        actorSessionId:    actor.sessionId || null,
        action:            event.action,
        resourceKind:      resource.kind   || null,
        resourceId:        resource.id     || null,
        outcome:           event.outcome,
        reason:            event.reason    || null,
        metadata:          event.metadata ? JSON.stringify(event.metadata) : null,
        requestId:         event.requestId || null,
      };
      // catches it drop-silent so the request that emitted can't be crashed.
      if (_externalStore && _externalStoreMode === "redirect" &&
          typeof _externalStore.record === "function") {
        await safeAsync.withTimeout(
          Promise.resolve().then(function () { return _externalStore.record(logical); }),
          EXTERNAL_STORE_TIMEOUT_MS,
          { name: "audit.redirectRecord" }
        );
        return logical;
      }
      var appended = await _chainWriter.append(logical);
      // Mirrors the row to the immutable external store. Drop-silent.
      if (_externalStore && typeof _externalStore.record === "function") {
        try {
          await safeAsync.withTimeout(
            Promise.resolve().then(function () { return _externalStore.record(appended); }),
            EXTERNAL_STORE_TIMEOUT_MS,
            { name: "audit.shadowRecord" }
          );
        } catch (e) {
          var isTimeout = e && (e.code === "ETIMEDOUT" || /timeout/i.test(e.message || ""));
          try {
            observability.event(isTimeout ? "audit.shadow_timeout" : "audit.shadow_failed", {
              action:           appended.action,
              monotonicCounter: appended.monotonicCounter,
              error:            (e && e.message) || String(e),
              timeoutMs:        isTimeout ? EXTERNAL_STORE_TIMEOUT_MS : undefined,
            });
          } catch (_obs) { /* drop-silent — observability is itself hot-path */ }
        }
      }
      return appended;
    }
  );
}

/**
 * @primitive b.audit.useStore
 * @signature b.audit.useStore({ record })
 * @since     0.11.4
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.audit.record, b.audit.safeEmit
 *
 * Register an operator-supplied shadow store for every audit chain
 * append. The framework's tamper-evident chain remains authoritative
 * (HIPAA §164.312(b) / PCI-DSS Req 10 / SOX-404 / ISO 27001 A.12.4.1
 * posture preserved); the operator's `record(row)` async function is
 * called AFTER each successful framework chain.append with the FULL
 * appended row — `{ _id, recordedAt, monotonicCounter, prevHash,
 * rowHash, action, outcome, actorUserId, ..., metadata }` — so
 * external consumers see identical hashes for cross-store
 * reconciliation.
 *
 * Typical use: replicate audit records to an immutable external
 * destination (AWS QLDB / Azure Confidential Ledger / Google Cloud
 * Audit Logs / an in-house WORM appliance / a SIEM forwarder).
 * Operators in regulated industries often need their audit trail in
 * a destination outside the application's own database for
 * separation-of-duties (PCI-DSS Req 10.5.3) or independent retention
 * (HIPAA §164.312(b) / SEC 17a-4 WORM).
 *
 * Failure posture: if the operator's `record` throws / rejects /
 * times out (30s hard cap — a stalled network call MUST NOT block
 * the audit critical path), the shadow failure is surfaced via
 * `b.observability` as either `audit.shadow_failed` (throw/reject)
 * or `audit.shadow_timeout` (cap exceeded) with `{ action,
 * monotonicCounter, error, timeoutMs }` metadata, and the framework
 * chain append still succeeds (the row is durable in the framework's
 * own table; the shadow is a best-effort archival). Hot-path
 * observability sinks emit drop-silent — an unreachable / hanging
 * shadow MUST NOT crash or stall the request path that triggered
 * the audit attempt.
 *
 * Call this once at boot, BEFORE the first `b.audit.record` /
 * `b.audit.emit` / `b.audit.safeEmit`. Switching stores on a running
 * app strands every prior audit row in the previous shadow store —
 * the framework chain has them, but the new shadow doesn't unless
 * the operator backfills.
 *
 * Pass `null` (or `{ record: null }`) to unregister and revert to
 * chain-only mode.
 *
 * Redirect mode — `useStore({ record, replaceChain: true })`: a
 * consumer that owns its own database + audit layer and does NOT use
 * `b.db` has no chain to shadow. In shadow mode every `record()` /
 * `emit()` / `safeEmit()` still tries the `b.db` chain append first,
 * which throws `db/not-initialized` on every emit (or silently drops
 * from the emit handler). With `replaceChain: true` the shaped audit
 * event is handed STRAIGHT to `record(event)` and the `b.db` chain
 * append is skipped, so framework audit events (an SMTP insecure-TLS
 * escape-hatch, mTLS negotiation at boot) land in the consumer's own
 * tamper-evident log instead of erroring. In redirect mode the
 * consumer store is authoritative: `record()`'s 30s timeout bounds a
 * stalled callback, but a genuine store failure PROPAGATES to the
 * caller (record() is the await-durability surface), while the
 * `emit()` / `safeEmit()` handler-flush path drop-silent-catches it.
 * The event passed to `record` is the shaped logical event
 * (`{ action, outcome, actorUserId, actorIp, resourceKind, resourceId,
 * reason, metadata, requestId, ... }`) — no framework `_id` /
 * `monotonicCounter` / `prevHash` / `rowHash`, since there is no
 * framework chain to hash against.
 *
 * @opts
 *   record:        async function (row),  // operator's persistence callback
 *   replaceChain:  boolean,               // default: false (shadow). true → redirect (skip the b.db chain)
 *
 * @example
 *   var b = require("@blamejs/core");
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "plaintext" });
 *   await b.db.init({ dataDir: "/var/lib/blamejs" });
 *   b.audit.useStore({
 *     record: async function (row) {
 *       // Replicate to AWS QLDB / Azure Confidential Ledger / etc.
 *       await externalLedger.append({
 *         id:               row._id,
 *         recordedAt:       row.recordedAt,
 *         monotonicCounter: row.monotonicCounter,
 *         prevHash:         row.prevHash,
 *         rowHash:          row.rowHash,
 *         action:           row.action,
 *         outcome:          row.outcome,
 *         metadata:         row.metadata,
 *       });
 *     },
 *   });
 *   // Every b.audit.* append now also lands in externalLedger.
 */
function useStore(store) {
  if (store === null || store === undefined) {
    _externalStore = null;
    _externalStoreMode = "shadow";
    return;
  }
  if (typeof store !== "object") {
    throw new Error("audit.useStore: store must be an object with a record(row) function, or null to unregister");
  }
  if (store.record === null || store.record === undefined) {
    _externalStore = null;
    _externalStoreMode = "shadow";
    return;
  }
  if (typeof store.record !== "function") {
    throw new Error("audit.useStore: store.record must be an async function (row) => void");
  }
  if (store.replaceChain !== undefined && typeof store.replaceChain !== "boolean") {
    throw new Error("audit.useStore: store.replaceChain must be a boolean (true routes events to record() and skips the b.db chain)");
  }
  _externalStore = store;
  _externalStoreMode = store.replaceChain === true ? "redirect" : "shadow";
}

/**
 * @primitive b.audit.query
 * @signature b.audit.query(criteria)
 * @since     0.1.0
 * @compliance pci-dss, soc2
 * @related   b.audit.verify, b.audit.verifyCheckpoints
 *
 * Read audit rows matching the criteria, returning unsealed rows for
 * the auditor's view. Every call self-logs an `audit.read` event before
 * returning (PCI DSS 10.2.3) so exfiltration attempts are forensically
 * visible; the self-log is suppressed per-invocation only for a query
 * whose own criteria targets `action: "audit.read"`, so concurrent reads
 * each record their own `audit.read`. Plain-field criteria translate into
 * derived-hash equality where the column is sealed.
 *
 * @opts
 *   from:         number | Date | string,   // recordedAt >=
 *   to:           number | Date | string,   // recordedAt <=
 *   actorUserId:  string,
 *   resourceId:   string,
 *   action:       string,
 *   resourceKind: string,
 *   outcome:      "success" | "warning" | "failure" | "denied",
 *   limit:        number,
 *   offset:       number,
 *
 * @example
 *   var rows = await b.audit.query({
 *     action: "consent.granted",
 *     from:   Date.now() - 86400000,
 *     limit:  100,
 *   });
 *   rows.length;   // → 42
 */
async function query(criteria) {
  criteria = criteria || {};
  if (criteria.action !== "audit.read") {
    await record({
      actor:    criteria.actor || {},
      action:   "audit.read",
      outcome:  "success",
      metadata: {
        criteria: _redactCriteria(criteria),
        traceId:  criteria.traceId || null,
      },
    });
  }

  /* c8 ignore next 3 -- cluster-mode topology (configured externalDb backend); single-node query() always takes the else path. Cluster read is exercised in test/integration/audit-stack-{postgres,mysql}. */
  if (cluster.isClusterMode()) {
    return await _queryCluster(criteria);
  }

  var q = db().from("audit_log");

  if (criteria.from)            q = q.where("recordedAt", ">=", _toMs(criteria.from));
  if (criteria.to)              q = q.where("recordedAt", "<=", _toMs(criteria.to));
  if (criteria.actorUserId)     q = q.where({ actorUserId: criteria.actorUserId });
  if (criteria.resourceId)      q = q.where({ resourceId: criteria.resourceId });
  if (criteria.action)          q = q.where({ action: criteria.action });
  if (criteria.resourceKind)    q = q.where({ resourceKind: criteria.resourceKind });
  if (criteria.outcome)         q = q.where({ outcome: criteria.outcome });

  q.orderBy("monotonicCounter", criteria.order === "desc" ? "desc" : "asc");
  if (criteria.limit  != null)  q.limit(criteria.limit);
  if (criteria.offset != null)  q.offset(criteria.offset);

  return q.all();
}

async function _queryCluster(criteria) {
  var qb = sql.select("audit_log", _sqlOpts());
  if (criteria.from) qb.whereOp("recordedAt", ">=", _toMs(criteria.from));
  if (criteria.to)   qb.whereOp("recordedAt", "<=", _toMs(criteria.to));
  if (criteria.actorUserId) {
    var auh = cryptoField.lookupHash("audit_log", "actorUserId", criteria.actorUserId);
    if (auh) {
      var auv = [auh.value];
      if (auh.legacyValue != null && auh.legacyValue !== auh.value) auv.push(auh.legacyValue);
      qb.whereIn(auh.field, auv);
    }
  }
  if (criteria.resourceId) {
    var rh = cryptoField.lookupHash("audit_log", "resourceId", criteria.resourceId);
    if (rh) {
      var rhv = [rh.value];
      if (rh.legacyValue != null && rh.legacyValue !== rh.value) rhv.push(rh.legacyValue);
      qb.whereIn(rh.field, rhv);
    }
  }
  if (criteria.action)       qb.where("action", criteria.action);
  if (criteria.resourceKind) qb.where("resourceKind", criteria.resourceKind);
  if (criteria.outcome)      qb.where("outcome", criteria.outcome);

  qb.orderBy("monotonicCounter", criteria.order === "desc" ? "desc" : "asc");
  if (criteria.limit  != null) qb.limit(criteria.limit);
  if (criteria.offset != null) qb.offset(criteria.offset);

  var built = qb.toSql();
  var rows = await clusterStorage.executeAll(built.sql, built.params);
  return rows.map(function (row) { return cryptoField.unsealRow("audit_log", row); });
}

function _redactCriteria(c) {
  return {
    from:          c.from || null,
    to:            c.to   || null,
    action:        c.action || null,
    resourceKind:  c.resourceKind || null,
    outcome:       c.outcome || null,
    hasUserFilter: !!c.actorUserId,
    hasResourceFilter: !!c.resourceId,
    limit:         c.limit  != null ? c.limit  : null,
    offset:        c.offset != null ? c.offset : null,
  };
}

var TRACE_ID_BYTES = C.BYTES.bytes(16);
/**
 * @primitive b.audit.beginTrace
 * @signature b.audit.beginTrace()
 * @since     0.1.0
 * @related   b.audit.record, b.audit.query
 *
 * Mint a fresh 32-hex-char trace id apps thread through linked events
 * via `metadata.traceId`. Width matches the W3C traceparent trace-id
 * format (16 random bytes hex-encoded), so the id is interoperable with
 * OpenTelemetry / W3C Trace Context propagation.
 *
 * @example
 *   var traceId = b.audit.beginTrace();
 *   await b.audit.record({
 *     action:   "subject.export.requested",
 *     outcome:  "success",
 *     metadata: { traceId: traceId },
 *   });
 *   await b.audit.record({
 *     action:   "subject.export.delivered",
 *     outcome:  "success",
 *     metadata: { traceId: traceId, parentEventId: "..." },
 *   });
 */
function beginTrace() {
  return generateToken(TRACE_ID_BYTES);
}

var CHECKPOINT_FORMAT = "blamejs-audit-checkpoint-v1";
function _checkpointPayload(atMonotonicCounter, atRowHash, createdAt) {
  return Buffer.from(
    CHECKPOINT_FORMAT + "\n" +
    String(atMonotonicCounter) + "\n" +
    atRowHash + "\n" +
    String(createdAt),
    "utf8"
  );
}

/**
 * @primitive b.audit.checkpoint
 * @signature b.audit.checkpoint(opts)
 * @since     0.4.0
 * @compliance soc2, pci-dss, sox-404
 * @related   b.audit.verifyCheckpoints, b.audit.verify
 *
 * Anchor the current chain tip with a fresh post-quantum signature (the
 * configured `b.auditSign` algorithm — SLH-DSA-SHAKE-256f by default,
 * ML-DSA-87 / ML-DSA-65 optional). Inserts a row into `audit_checkpoints`
 * and updates the
 * boot-time rollback-detection sidecar (single-node) or the cluster
 * audit-tip row (cluster mode, fencing-token guarded). Cluster mode
 * requires the caller hold leader status — `cluster.requireLeader()`
 * throws otherwise.
 *
 * Returns the inserted checkpoint row, or `null` when the chain is
 * empty / `skipIfUnchanged` and the tip hasn't advanced.
 *
 * @opts
 *   skipIfUnchanged: boolean,   // null-return when tip didn't move
 *
 * @example
 *   var ckpt = await b.audit.checkpoint({ skipIfUnchanged: true });
 *   if (ckpt) {
 *     console.log("anchored at counter", ckpt.atMonotonicCounter);
 *   }
 */
function _dbGenerationOrNull() {
  try { return db()._dbGeneration(); }
  catch (_e) { return null; }
}

async function checkpoint(opts) {
  var dbGenAtEntry = _dbGenerationOrNull();
  try {
    return await _checkpointOnDatabase(opts, dbGenAtEntry);
  } catch (e) {
    if (_dbGenerationOrNull() !== dbGenAtEntry) return null;
    throw e;
  }
}

async function _checkpointOnDatabase(opts, dbGenAtEntry) {
  cluster.requireLeader();
  opts = opts || {};

  var tipReadBuilt = sql.select("audit_log", _sqlOpts())
    .columns(["_id", "monotonicCounter", "rowHash"])
    .orderBy("monotonicCounter", "desc")
    .limit(1)
    .toSql();
  var tip = await _chainWriter.withChainLock(null, function () {
    return safeAsync.withTimeout(
      safeAsync.asyncRetry(function () {
        return clusterStorage.executeOne(tipReadBuilt.sql, tipReadBuilt.params);
      }),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: "audit.checkpoint.readTip" }
    );
  });

  if (!tip) return null;

  if (opts.skipIfUnchanged) {
    var lastCkpt = await _readLastCheckpointCounter();
    if (lastCkpt && Number(lastCkpt.atMonotonicCounter) >= Number(tip.monotonicCounter)) {
      return null;
    }
  }

  var createdAt = Date.now();
  var counter = Number(tip.monotonicCounter);
  var payload = _checkpointPayload(counter, tip.rowHash, createdAt);
  var signature = auditSign.sign(payload);
  var pubFp = auditSign.getPublicKeyFingerprint();

  if (_dbGenerationOrNull() !== dbGenAtEntry) return null;

  var ckptId = generateToken(TRACE_ID_BYTES);
  var fencingToken = cluster.fencingToken();
  try {
    await _insertCheckpoint(
      [ckptId, createdAt, counter, tip.rowHash, signature, pubFp, fencingToken]
    );
  } catch (e) {
    if (_isDuplicateCheckpointCounter(e)) {
      /* c8 ignore next 3 -- cluster-only fence: single-node dup-anchor is idempotent and returns null below; the cluster fencing-token step-down is exercised in test/integration/audit-stack-{postgres,mysql}. */
      if (cluster.isClusterMode()) {
        await _upsertAuditTip(counter, tip.rowHash, String(createdAt), fencingToken);
      }
      return null;
    }
    throw e;
  }

  /* c8 ignore next 2 -- cluster-mode audit-tip upsert; single-node takes the else (durable-tip sidecar) branch below. Cluster path exercised in test/integration/audit-stack-{postgres,mysql}. */
  if (cluster.isClusterMode()) {
    await _upsertAuditTip(counter, tip.rowHash, String(createdAt), fencingToken);
  } else {
    var rowsFlushed = false;
    try { db().flushToDisk(); rowsFlushed = true; }
    catch (_e) { /* flush failed - do not advance the tip ahead of the rows */ }
    if (rowsFlushed) {
      try {
        db()._writeAuditTip({
          atMonotonicCounter:  counter,
          atRowHash:           tip.rowHash,
          anchoredAt:          createdAt,
          checkpointId:        ckptId,
          publicKeyFingerprint: pubFp,
          version:             1,
        });
      } catch (_e) { /* best effort */ }
    }
  }

  return {
    _id:                ckptId,
    createdAt:          createdAt,
    atMonotonicCounter: counter,
    atRowHash:          tip.rowHash,
    publicKeyFingerprint: pubFp,
  };
}

/**
 * @primitive b.audit.verifyCheckpoints
 * @signature b.audit.verifyCheckpoints()
 * @since     0.4.0
 * @compliance soc2, pci-dss, sox-404
 * @related   b.audit.checkpoint, b.audit.verify
 *
 * Walk every checkpoint and verify (a) the public-key fingerprint
 * matches the current signing key, (b) the post-quantum signature over
 * the payload still verifies, (c) the audit_log row at the anchored counter
 * still has the recorded rowHash. Catches tampering that recomputed
 * chain hashes after holding the vault key, because the off-chain
 * signature anchor is unforgeable without the signing key.
 *
 * Returns `{ ok: true, checkpointsVerified }` on success, or
 * `{ ok: false, checkpointsVerified, breakAt, checkpointId, reason }`
 * at the first break.
 *
 * @example
 *   var result = await b.audit.verifyCheckpoints();
 *   if (!result.ok) {
 *     throw new Error("audit checkpoint break at " + result.breakAt +
 *       ": " + result.reason);
 *   }
 *   result.checkpointsVerified;   // → 17
 */
async function verifyCheckpoints() {
  var rows = await _readAllCheckpointsAsc();

  if (rows.length === 0) return { ok: true, checkpointsVerified: 0 };

  for (var i = 0; i < rows.length; i++) {
    var c = rows[i];
    var pub = auditSign.getPublicKeyByFingerprint(c.publicKeyFingerprint);
    if (!pub) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "no audit-signing key on record for this checkpoint's fingerprint (key rotated without history?)",
        actual:              c.publicKeyFingerprint,
      };
    }
    var payload = _checkpointPayload(Number(c.atMonotonicCounter), c.atRowHash, Number(c.createdAt));
    /* c8 ignore next -- the isBuffer arm is pg/mysql-only (those drivers return a Buffer for the signature BLOB); node:sqlite single-node returns a Uint8Array, so the Buffer.from arm is the one taken here. */
    var sigBuf = Buffer.isBuffer(c.signature) ? c.signature : Buffer.from(c.signature);
    if (!auditSign.verify(payload, sigBuf, pub)) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "post-quantum signature failed",
      };
    }
    var anchored = await _readAuditRowHashAtCounter(c.atMonotonicCounter);
    if (!anchored) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "anchored audit_log row missing (counter=" + c.atMonotonicCounter + ")",
      };
    }
    if (anchored.rowHash !== c.atRowHash) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "anchored rowHash mismatch — audit_log was tampered with",
        expected:            c.atRowHash,
        actual:              anchored.rowHash,
      };
    }
  }
  return { ok: true, checkpointsVerified: rows.length };
}

function _toMs(value) {
  if (typeof value === "number") return value;
  if (value instanceof Date)     return value.getTime();
  if (typeof value === "string") {
    var ms = Date.parse(value);
    if (isNaN(ms)) throw new Error("invalid date: " + value);
    return ms;
  }
  throw new Error("invalid date value");
}

/**
 * @primitive b.audit.verify
 * @signature b.audit.verify(opts)
 * @since     0.1.0
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.audit.verifyCheckpoints, b.audit.query
 *
 * Walk every audit_log row in monotonic order and recompute each
 * `rowHash` against the canonicalized columns + nonce, confirming each
 * row's `prevHash` matches the previous row's `rowHash`. Catches any
 * insert / delete / mutation between checkpoints. Runs at boot in
 * `db.init()`; operators also call it from a periodic job.
 *
 * Returns `{ ok: true, rowsVerified }` on a clean chain, or
 * `{ ok: false, rowsVerified, breakAt, reason }` at the first break.
 *
 * @opts
 *   from:  number,   // start counter (incremental verify after a known-good checkpoint)
 *   to:    number,   // end counter
 *
 * @example
 *   var result = await b.audit.verify();
 *   if (!result.ok) {
 *     console.error("audit chain break at row", result.breakAt);
 *     process.exit(1);
 *   }
 */
async function verify(opts) {
  return await auditChain.verifyChain(
    function (sql, params) {
      return safeAsync.withTimeout(
        safeAsync.asyncRetry(function () {
          /* c8 ignore next -- auditChain.verifyChain always invokes this reader with a params array from the sql builder; the `|| []` is a defensive fallback that is never taken. */
          return clusterStorage.executeAll(sql, params || []);
        }),
        FRAMEWORK_SQL_TIMEOUT_MS,
        { name: "audit.verifyChain" }
      );
    },
    "audit_log",
    opts
  );
}

function _resetForTest() {
  registeredNamespaces = new Set(FRAMEWORK_NAMESPACES);
  _externalStore = null;
  _externalStoreMode = "shadow";
  _purgeAnchorPolicy = {
    resolvePublicKey: undefined,
    allowUnsigned:    false,
    allowUnchecked:   false,
  };
  db.reset();
  _chainWriter._resetForTest();
  if (_auditHandler) {
    try { _auditHandler.shutdownSync("audit._resetForTest"); }
    /* c8 ignore next -- shutdownSync only splices the buffer + cancels a timer; it has no input-driven throw path, so this defensive catch never runs. */
    catch (e) { log.debug("reset-handler-shutdown-failed: " + (e && e.message || e)); }
    _auditHandler = null;
  }
}

var _auditHandler = null;

function _ensureHandler() {
  if (_auditHandler) return _auditHandler;
  _auditHandler = handlers.create({
    name:  "audit",
    flush: async function (batch, ctx) {
      var droppedThisBatch = 0;
      var firstDropAction = null;
      var firstDropMessage = null;
      for (var i = 0; i < batch.length; i++) {
        /* c8 ignore next -- mid-drain shutdown early-exit: fires only when the handler is shut down (test reset) while a batch is in flight, a timing race not deterministically forceable from the public API. */
        if (ctx && ctx.isShutdown && ctx.isShutdown()) return;
        try { await record(batch[i]); }
        catch (e) {
          droppedThisBatch += 1;
          if (firstDropAction === null) {
            firstDropAction = (batch[i] && batch[i].action) || null;
            /* c8 ignore next -- record() only ever rejects with an Error carrying a non-empty message, so the String(e) fallback (and the `e` falsy short-circuit) is unreachable. */
            firstDropMessage = (e && e.message) ? e.message : String(e);
          }
        }
      }
      if (droppedThisBatch > 0) {
        observability.safeEvent("system.audit.chain_write_dropped",
          droppedThisBatch, {
            batchSize:        batch.length,
            firstDropAction:  firstDropAction,
            firstDropMessage: firstDropMessage,
          });
      }
    },
  });
  return _auditHandler;
}

/**
 * @primitive b.audit.emit
 * @signature b.audit.emit(event)
 * @since     0.1.0
 * @related   b.audit.safeEmit, b.audit.record, b.audit.flush
 *
 * Synchronous fire-and-forget emit — events buffer in an AsyncHandler
 * and drain serially through `record()`. Returns immediately; never
 * returns a Promise. Unlike `safeEmit()`, emit() does NOT normalize
 * outcome / action and does NOT redact metadata — callers pass already-
 * shaped events. Most call sites should prefer `safeEmit` instead;
 * `emit` is the lower-level surface the framework's own bound-actor
 * wrapper uses.
 *
 * @example
 *   b.audit.emit({
 *     actor:    { userId: "u-42" },
 *     action:   "system.config.reloaded",
 *     outcome:  "success",
 *     metadata: { source: "SIGHUP" },
 *   });
 */
function emit(event) {
  _ensureHandler().emit(event);
}

// Outcome normalization — drop-silent on a strict `outcome` mismatch
var OUTCOME_VALUES = ["success", "warning", "failure", "denied"];

var OUTCOME_NORMALIZE = {
  ok:        "success",
  okay:      "success",
  pass:      "success",
  passed:    "success",
  success:   "success",
  succeeded: "success",
  duplicate: "success",
  skip:      "success",
  skipped:   "success",
  warn:      "warning",
  warning:   "warning",
  info:      "warning",
  late:      "warning",
  fail:      "failure",
  failed:    "failure",
  failure:   "failure",
  err:       "failure",
  error:     "failure",
  denied:    "denied",
  refused:   "denied",
  deny:      "denied",
};

// drop-silent by contract and throwing would lose the row entirely -- so it
function _normalizeOutcome(o) {
  if (o === undefined || o === null || o === "") return "success";
  if (typeof o !== "string") return "failure";
  var n = Object.prototype.hasOwnProperty.call(OUTCOME_NORMALIZE, o.toLowerCase())
    ? OUTCOME_NORMALIZE[o.toLowerCase()]
    : null;
  return n || "failure";
}

(function () {
  var keys = Object.keys(OUTCOME_NORMALIZE);
  for (var i = 0; i < keys.length; i += 1) {
    if (OUTCOME_VALUES.indexOf(OUTCOME_NORMALIZE[keys[i]]) === -1) {
      throw new Error("audit: OUTCOME_NORMALIZE." + keys[i] + " maps to '" +
        OUTCOME_NORMALIZE[keys[i]] + "', which is not in the outcome vocabulary");
    }
  }
})();

function _normalizeAction(action) {
  /* c8 ignore next -- only caller is safeEmit(), which returns early unless event.action is a string, so action is always a string here. */
  if (typeof action !== "string") return action;
  return action.replace(/-/g, "_");
}

// Drop-silent on malformed input by design.
/**
 * @primitive b.audit.safeEmit
 * @signature b.audit.safeEmit(event)
 * @since     0.1.0
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.audit.emit, b.audit.record, b.audit.flush
 *
 * Hot-path-safe fire-and-forget audit emit. Drop-silent on malformed
 * input by design — safeEmit runs from request middleware, log-stream
 * hooks, and finalizers where throwing on a missing `action` would
 * crash the request that triggered the audit attempt. Operators who
 * need durability guarantees call `record()` and await it.
 *
 * Built-in normalization: action segments with hyphens become
 * underscores ("biometric-id" → "biometric_id"); outcome aliases
 * collapse to {success, failure, denied} ("ok" → "success", "error" →
 * "failure", "refused" → "denied"). Actor / reason / metadata pass
 * through `b.redact.redact()` so connection strings, JWTs, PEM blocks,
 * AWS keys, and SSNs are scrubbed before they reach the chain.
 *
 * @opts
 *   actor:     { userId, ip, userAgent, sessionId },
 *   action:    "namespace.verb[.qualifier]",
 *   resource:  { kind, id },
 *   outcome:   string,            // normalized
 *   reason:    string,            // redacted
 *   metadata:  object,            // redacted
 *   requestId: string,
 *
 * @example
 *   b.audit.safeEmit({
 *     actor:    { userId: req.user && req.user.id },
 *     action:   "auth.login",
 *     outcome:  "success",
 *     metadata: { traceId: req.traceId, ua: req.headers["user-agent"] },
 *   });
 */
function safeEmit(event) {
  if (!event || typeof event !== "object") return;
  if (typeof event.action !== "string") return;
  try {
    var actor = event.actor || {};
    var reason = event.reason || null;
    var metadata = event.metadata || null;
    try {
      actor = redact.redact(actor);
      if (reason !== null) reason = redact.redact(reason);
      if (metadata !== null) metadata = redact.redact(metadata);
    } catch (_e) { /* fall through with original values */ }
    // rejection to escape — but this is a drop-silent sink on the request
    var emitted = _ensureHandler().emit({
      actor:     actor,
      action:    _normalizeAction(event.action),
      resource:  event.resource || null,
      outcome:   _normalizeOutcome(event.outcome),
      reason:    reason,
      metadata:  metadata,
      requestId: event.requestId || null,
    });
    // Passing no onError is the drop-silent contract.
    safeAsync.containRejection(emitted);
  } catch (_e) { /* audit best-effort — never break the caller */ }
}

/**
 * @primitive b.audit.namespaced
 * @signature b.audit.namespaced(prefix, opts?)
 * @since     0.15.13
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.audit.safeEmit, b.audit.emit, b.observability.namespaced
 *
 * Build a drop-silent emitter bound to one action namespace — the shape every
 * framework primitive hand-rolled as a private `_emitAudit(action, outcome,
 * metadata)` closure (or inline) (`if (!on) return; try { safeEmit({ action:
 * "ns." + action, outcome, metadata }); } catch {}`). The returned function
 * prefixes `action` with `prefix + "."`, fills `metadata` with `{}` when
 * omitted, and routes through `safeEmit` (so the same redaction + outcome
 * normalization applies).
 *
 * Every caller drives the SAME 4-argument emitter `(action, outcome, metadata,
 * extra?)`: `extra` is an object whose fields are merged onto the event, which
 * carries the only per-emit variations seen across the framework — `actor`
 * (constant `{ type: "system" }` for an unattended worker, or a per-request
 * `ctx.actor`) and `resource`. So a hand-rolled emitter with extra event fields
 * is never an exception — pass them through `extra`. `opts` is the gate flag for
 * the common case OR `{ audit, sink }`, where `sink` emits to an
 * operator-supplied audit object instead of the framework chain (the emitter is
 * a no-op if that sink has no `safeEmit`, matching the hand-rolled sink guard).
 *
 * A falsy `prefix` (`null` / `""`) builds the no-namespace variant: `action`
 * passes through verbatim (no `prefix + "."`). This serves the primitives whose
 * audit actions are already fully-qualified at the call site (`emitAudit(
 * "system.outbox.started", …)`) — the same gated drop-silent passthrough,
 * without re-homing the qualifier.
 *
 * @opts
 *   audit:  boolean,   // false disables the emitter (default on); passing a bare boolean === { audit }
 *   sink:   object,    // alternate audit target with a .safeEmit(event) (defaults to b.audit)
 *
 * @example
 *   var emitAudit = b.audit.namespaced("gdpr.ropa", opts.audit);
 *   emitAudit("activity_added", "success", { activityId: id });
 *   // → safeEmit({ action: "gdpr.ropa.activity_added", outcome: "success",
 *   //             metadata: { activityId: id } })
 *
 *   var emitGate = b.audit.namespaced("guardSql.gate");
 *   emitGate("refused", "denied", { route: r }, { actor: ctx.actor });  // per-call actor
 */
function namespaced(prefix, opts) {
  var cfg = (opts && typeof opts === "object") ? opts : { audit: opts };
  var on = cfg.audit !== false;
  return function (action, outcome, metadata, extra) {
    if (!on) return;
    var sink = cfg.sink || module.exports;
    if (!sink || typeof sink.safeEmit !== "function") return;
    var evt = { action: prefix ? prefix + "." + action : action, outcome: outcome, metadata: metadata || {} };
    if (extra) { for (var k in extra) { if (Object.prototype.hasOwnProperty.call(extra, k)) evt[k] = extra[k]; } }
    try { sink.safeEmit(evt); } catch (_e) { /* drop-silent — audit is best-effort */ }
  };
}

/**
 * @primitive b.audit.flush
 * @signature b.audit.flush()
 * @since     0.1.0
 * @related   b.audit.emit, b.audit.safeEmit
 *
 * Drain the AsyncHandler buffer — every queued `emit()` / `safeEmit()`
 * lands in the audit chain before the returned Promise resolves. Tests,
 * graceful shutdown, and any code that needs to read audit_log
 * immediately after emitting awaits flush().
 *
 * @example
 *   b.audit.safeEmit({ action: "system.shutdown.requested", outcome: "success" });
 *   await b.audit.flush();
 *   var rows = await b.audit.query({ action: "system.shutdown.requested" });
 *   rows.length;   // → 1
 */
async function flush() {
  if (!_auditHandler) return;
  await _auditHandler.drain();
}

function _checkActorBinding(actorId, eventActorId, opts) {
  /* c8 ignore next -- only callers are bindActor()'s bound wrappers, and bindActor() throws unless actorId is a non-empty string, so actorId is always truthy here. */
  if (!actorId) return true;
  if (!eventActorId) {
    return { ok: false, reason: "event missing actor.userId — refused under bound emit" };
  }
  if (eventActorId !== actorId) {
    return { ok: false,
      reason: "actor mismatch: bound='" + actorId + "', event='" + eventActorId + "'" };
  }
  if (opts && typeof opts.roleEquivalent === "function") {
    var role = dbRoleContext.getRole();
    if (role && !opts.roleEquivalent(actorId, role)) {
      return { ok: false,
        reason: "db-role mismatch: bound actor '" + actorId +
          "' is not equivalent to SQL role '" + role + "'" };
    }
  }
  return { ok: true };
}

/**
 * @primitive b.audit.bindActor
 * @signature b.audit.bindActor(actorId, opts)
 * @since     0.7.0
 * @compliance sox-404, soc2
 * @related   b.audit.assertSegregation, b.audit.generateActorBindingTriggerSql
 *
 * Wrap `safeEmit` / `record` so any event whose `actor.userId` doesn't
 * match the bound id is refused (and an `audit.actor_binding.violation`
 * event is recorded under the bound actor). When `opts.roleEquivalent`
 * is provided and the caller is inside a `db-role-context.runWithRole`
 * scope, the SQL-bound role and bound actor must agree per the
 * operator-supplied mapping.
 *
 * Pair with `generateActorBindingTriggerSql()` for SQL-side enforcement
 * — application-layer binding catches typos; the trigger catches
 * privileged callers bypassing the framework.
 *
 * @opts
 *   roleEquivalent: function (actorId, sqlRole) -> boolean,
 *
 * @example
 *   var bound = b.audit.bindActor("u-42");
 *   bound.safeEmit({
 *     actor:   { userId: "u-42" },
 *     action:  "orders.shipped",
 *     outcome: "success",
 *   });
 *   bound.safeEmit({
 *     actor:   { userId: "u-other" },
 *     action:  "orders.shipped",
 *     outcome: "success",
 *   });
 *   // → drops + records "audit.actor_binding.violation" under u-42
 */
function bindActor(actorId, opts) {
  if (typeof actorId !== "string" || actorId.length === 0) {
    throw new AuditSegregationError("audit/bind-actor-missing",
      "audit.bindActor: actorId must be a non-empty string");
  }
  opts = opts || {};
  function _violationEmit(eventAction, reason) {
    try {
      _ensureHandler().emit({
        action:   "audit.actor_binding.violation",
        outcome:  "denied",
        actor:    { userId: actorId },
        metadata: { attemptedAction: eventAction, reason: reason },
      });
    /* c8 ignore next -- handlers' emit() never throws (it routes bad input to onError/dead-letter internally) and the violation event carries no throwing accessors, so this defensive catch never runs. */
    } catch (_e) { /* drop-silent — never break the caller */ }
  }
  function boundSafeEmit(event) {
    var rv = _checkActorBinding(actorId,
      event && event.actor && event.actor.userId, opts);
    if (rv !== true && !rv.ok) {
      _violationEmit(event && event.action, rv.reason);
      return;
    }
    safeEmit(event);
  }
  async function boundRecord(event) {
    var rv = _checkActorBinding(actorId,
      event && event.actor && event.actor.userId, opts);
    if (rv !== true && !rv.ok) {
      _violationEmit(event && event.action, rv.reason);
      throw new AuditSegregationError("audit/actor-binding-violation",
        "audit.bindActor.record: " + rv.reason);
    }
    return await record(event);
  }
  return {
    actorId:   actorId,
    safeEmit:  boundSafeEmit,
    record:    boundRecord,
  };
}

/**
 * @primitive b.audit.generateActorBindingTriggerSql
 * @signature b.audit.generateActorBindingTriggerSql(opts)
 * @since     0.7.0
 * @compliance sox-404, soc2
 * @related   b.audit.bindActor, b.audit.assertSegregation
 *
 * Emit Postgres trigger DDL that refuses INSERTs into the audit_log
 * table whose stored `actorUserId` column doesn't match the SQL
 * session's `current_user`. Operators apply the returned `up` script
 * via `b.externalDb.migrate` under sox-404 / soc2 posture so a
 * privileged caller (operator script, migration runner) can't write
 * audit rows under a different actor identity.
 *
 * Returns `{ up, down, functionName, triggerName }` for migration
 * runner symmetry.
 *
 * @opts
 *   column:         string,             // default "actorUserId"
 *   tableName:      string,             // default "_blamejs_audit_log"
 *   roleMappingFn:  string,             // SQL fn name mapping actor → role
 *   allowRoles:     string[],           // roles that bypass the check
 *
 * @example
 *   var ddl = b.audit.generateActorBindingTriggerSql({
 *     allowRoles: ["blamejs_service"],
 *   });
 *   await db.query(ddl.up);
 */
function generateActorBindingTriggerSql(opts) {
  opts = opts || {};
  var columnRaw    = opts.column || "actorUserId";
  var tableNameRaw = opts.tableName || frameworkSchema.tableName("audit_log");
  var allowRoles   = Array.isArray(opts.allowRoles) ? opts.allowRoles : [];
  var fnNameRaw    = "_blamejs_audit_actor_binding_check";   // allow:hand-rolled-sql
  var trigNameRaw  = "_blamejs_audit_actor_binding_trig";    // allow:hand-rolled-sql
  var qColumn   = safeSql.quoteIdentifier(columnRaw, "postgres", { allowReserved: true });
  var qTable    = safeSql.quoteIdentifier(tableNameRaw, "postgres", { allowReserved: true });
  var qFn       = safeSql.quoteIdentifier(fnNameRaw, "postgres", { allowReserved: true });
  var qTrig     = safeSql.quoteIdentifier(trigNameRaw, "postgres", { allowReserved: true });
  var qRoleMapFn = opts.roleMappingFn
    ? safeSql.quoteIdentifier(opts.roleMappingFn, "postgres", { allowReserved: true })
    : null;
  var allowList = allowRoles.length === 0 ? "" :
    "  IF current_user IN (" +
    allowRoles.map(function (r) { return "'" + r.replace(/'/g, "''") + "'"; }).join(", ") +
    ") THEN RETURN NEW; END IF;\n";
  var roleMatch = qRoleMapFn
    ? "  IF " + qRoleMapFn + "(NEW." + qColumn + ") IS DISTINCT FROM current_user THEN\n"
    : "  IF NEW." + qColumn + " IS DISTINCT FROM current_user THEN\n";
  // honored. allow:hand-rolled-sql — this is migration-script generation,
  var up =
    "CREATE OR REPLACE FUNCTION " + qFn + "() RETURNS trigger AS $$\n" +   // allow:hand-rolled-sql
    "BEGIN\n" +
    allowList +
    roleMatch +
    "    RAISE EXCEPTION 'segregation-of-duties violation: actor=% does not match current_user=%', NEW." + qColumn + ", current_user\n" +
    "      USING ERRCODE = 'P0001';\n" +
    "  END IF;\n" +
    "  RETURN NEW;\n" +
    "END;\n" +
    "$$ LANGUAGE plpgsql;\n" +
    "DROP TRIGGER IF EXISTS " + qTrig + " ON " + qTable + ";\n" +          // allow:hand-rolled-sql
    "CREATE TRIGGER " + qTrig + "\n" +                                     // allow:hand-rolled-sql
    "  BEFORE INSERT ON " + qTable + "\n" +
    "  FOR EACH ROW EXECUTE FUNCTION " + qFn + "();\n";
  var down =
    "DROP TRIGGER IF EXISTS " + qTrig + " ON " + qTable + ";\n" +          // allow:hand-rolled-sql
    "DROP FUNCTION IF EXISTS " + qFn + "();\n";
  return { up: up, down: down, functionName: fnNameRaw, triggerName: trigNameRaw };
}

/**
 * @primitive b.audit.assertSegregation
 * @signature b.audit.assertSegregation(opts)
 * @since     0.7.0
 * @compliance sox-404, soc2
 * @related   b.audit.generateActorBindingTriggerSql, b.audit.bindActor
 *
 * Boot-time check that confirms the actor-binding trigger function and
 * trigger row exist in the externalDb's `pg_proc` / `pg_trigger`
 * catalogs. Throws `AuditSegregationError` with the missing artifacts
 * named when either is absent — operators wire this into the
 * sox-404 / soc2 boot sequence so a forgotten migration refuses-to-boot
 * instead of silently shipping without enforcement.
 *
 * @opts
 *   db:            { query(sql, params) -> { rows } },   // required
 *   functionName:  string,
 *   triggerName:   string,
 *
 * @example
 *   await b.audit.assertSegregation({ db: externalDb });
 *   // throws if the trigger DDL hasn't been applied
 */
async function assertSegregation(opts) {
  opts = opts || {};
  var externalDb = opts.db || null;
  if (!externalDb || typeof externalDb.query !== "function") {
    throw new AuditSegregationError("audit/segregation-no-db",
      "audit.assertSegregation: opts.db with a query() method is required");
  }
  var fnName = opts.functionName || "_blamejs_audit_actor_binding_check";    // allow:hand-rolled-sql
  var trigName = opts.triggerName || "_blamejs_audit_actor_binding_trig";    // allow:hand-rolled-sql
  var fnRes = await externalDb.query(
    "SELECT 1 FROM pg_proc WHERE proname = $1 LIMIT 1", [fnName]             // allow:hand-rolled-sql
  );
  var fnPresent = !!(fnRes && fnRes.rows && fnRes.rows.length > 0);
  var trigRes = await externalDb.query(
    "SELECT 1 FROM pg_trigger WHERE tgname = $1 LIMIT 1", [trigName]         // allow:hand-rolled-sql
  );
  var trigPresent = !!(trigRes && trigRes.rows && trigRes.rows.length > 0);
  var missing = [];
  if (!fnPresent) missing.push("function:" + fnName);
  if (!trigPresent) missing.push("trigger:" + trigName);
  var ok = missing.length === 0;
  if (!ok) {
    safeEmit({
      action: "audit.actor_binding.violation",
      outcome: "denied",
      metadata: {
        reason: "boot-time segregation check failed",
        missing: missing,
      },
    });
    throw new AuditSegregationError("audit/segregation-not-installed",
      "audit.assertSegregation: SQL-side actor-binding trigger missing — " +
      "apply the DDL from audit.generateActorBindingTriggerSql() under sox-404 / soc2 posture. " +
      "Missing: " + missing.join(", "));
  }
  return { ok: ok, missing: missing };
}

var _activePosture = null;
/**
 * @primitive b.audit.applyPosture
 * @signature b.audit.applyPosture(posture)
 * @since     0.7.27
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.audit.activePosture, b.compliance
 *
 * Cascade hook called by `b.compliance.set(posture)` to record the
 * active regulatory regime. The chain itself is posture-agnostic —
 * every posture audits with the same SLH-DSA-SHAKE-256f signing key —
 * but downstream tooling (forensic export, SIEM correlation) reads the
 * stored posture to filter / route. Returns `{ posture }` on accept,
 * `null` on a non-string / empty argument.
 *
 * @example
 *   b.audit.applyPosture("hipaa");
 *   b.audit.activePosture();   // → "hipaa"
 */
function applyPosture(posture) {
  if (typeof posture !== "string" || posture.length === 0) return null;
  _activePosture = posture;
  return { posture: posture };
}
/**
 * @primitive b.audit.activePosture
 * @signature b.audit.activePosture()
 * @since     0.7.27
 * @related   b.audit.applyPosture
 *
 * Return the posture string most recently passed to `applyPosture()`,
 * or `null` if none has been set. Read-only accessor for downstream
 * tooling that tags audit-derived artifacts with the regime.
 *
 * @example
 *   b.audit.applyPosture("pci-dss");
 *   b.audit.activePosture();   // → "pci-dss"
 */
function activePosture() { return _activePosture; }

module.exports = {
  withChainLock:        function (fn) { return _chainWriter.withChainLock(null, fn); },
  getPurgeAnchorPolicy: function () { return _purgeAnchorPolicy; },
  setPurgeAnchorPolicy: function (policy) {
    _purgeAnchorPolicy = {
      resolvePublicKey: policy && policy.resolvePublicKey,
      allowUnsigned:    !!(policy && policy.allowUnsigned),
      allowUnchecked:   !!(policy && policy.allowUnchecked),
    };
    return _purgeAnchorPolicy;
  },
  invalidateChainOrigin: function () { _chainWriter.invalidateOrigin(null); },
  registerNamespace:    registerNamespace,
  record:               record,
  useStore:             useStore,
  emit:                 emit,
  safeEmit:             safeEmit,
  namespaced:           namespaced,
  applyPosture:         applyPosture,
  activePosture:        activePosture,
  bindActor:            bindActor,
  assertSegregation:    assertSegregation,
  generateActorBindingTriggerSql: generateActorBindingTriggerSql,
  flush:                flush,
  query:                query,
  verify:               verify,
  beginTrace:           beginTrace,
  checkpoint:           checkpoint,
  verifyCheckpoints:    verifyCheckpoints,
  CHECKPOINT_FORMAT:    CHECKPOINT_FORMAT,
  FRAMEWORK_NAMESPACES: FRAMEWORK_NAMESPACES,
  _resetForTest:        _resetForTest,
  _isDuplicateCheckpointCounter: _isDuplicateCheckpointCounter,
};
