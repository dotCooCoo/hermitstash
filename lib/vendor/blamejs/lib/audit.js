"use strict";
/**
 * Audit log — tamper-evident, append-only record of every privileged action.
 *
 * audit_log table is baked into db.js's schema runner — apps cannot opt out.
 * Every row is hash-chained (lib/audit-chain.js); the chain is verified at
 * boot in db.init(); a chain break refuses-to-boot per the compliance stance.
 *
 * Action namespaces:
 *   - Framework owns: 'auth.*', 'system.*', 'audit.*', 'consent.*', 'subject.*'
 *   - Apps register their own via audit.registerNamespace('orders'), then
 *     can record 'orders.created', 'orders.shipped', etc.
 *   - Unregistered namespaces are rejected — prevents typos becoming silent
 *     unobservable events.
 *
 * Hash chain:
 *   - rowHash is computed over the *sealed* form of the row + the nonce.
 *     The sealed form is what's stored on disk; verification recomputes
 *     directly from disk without unsealing anything (faster + lets auditors
 *     verify integrity even without the vault key).
 *
 * Public API:
 *   audit.registerNamespace(name)
 *   audit.record({ actor, action, resource, outcome, reason, metadata, requestId }) → row
 *   audit.query(criteria) → rows  [auto-self-logs an 'audit.read' event before returning]
 *   audit.verify(opts?) → { ok, rowsVerified, breakAt? }
 *   audit.beginTrace() → traceId (32 hex chars)
 *
 * Conventions for `metadata` (apps SHOULD follow these keys for cross-app
 * tooling and RoPA correlation; framework's own subject.* events do):
 *   traceId        — cross-request correlation; same value across linked events
 *   parentEventId  — immediate parent event in the causation chain
 *   before         — state before a change (object), for change events
 *   after          — state after the change
 *   evidenceRef    — pointer to evidence (signed PDF hash, ticket URL, etc.)
 *   App-defined keys are also welcome; don't shadow these reserved ones.
 */
var auditChain = require("./audit-chain");
var auditSign = require("./audit-sign");
var chainWriter = require("./chain-writer");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var { generateToken } = require("./crypto");
var cryptoField = require("./crypto-field");
var handlers = require("./handlers");
var { boot } = require("./log");
var redact = require("./redact");
var safeAsync = require("./safe-async");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var observability = require("./observability");
var { ClusterError } = require("./framework-error");

var log = boot("audit");

// Per-operation timeout for framework-state SQL. A misbehaving
// external-db driver hanging on a query shouldn't hang audit forever.
// 30s is generous for genuinely slow networks while still bounding
// the worst case.
var FRAMEWORK_SQL_TIMEOUT_MS = C.TIME.seconds(30);

// ---- Resilience-wrapped SQL operations (audit-specific reads) ----
// Chain APPEND lives in chain-writer (race-safe via mutex, retry, timeout).
// The wrappers below cover audit-specific reads/writes that aren't part
// of the chain append: checkpoint queries, verifyCheckpoints reads,
// audit-tip cluster-row updates.

async function _readLastCheckpointCounter() {
  return await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeOne(
        "SELECT atMonotonicCounter FROM audit_checkpoints " +
        "ORDER BY atMonotonicCounter DESC LIMIT 1"
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readLastCheckpoint" }
  );
}

async function _readAllAuditRowsAsc() {
  return await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeAll(
        'SELECT * FROM "audit_log" ORDER BY monotonicCounter ASC'
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readAllRowsAsc" }
  );
}

async function _readAllCheckpointsAsc() {
  return await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeAll(
        "SELECT * FROM audit_checkpoints ORDER BY atMonotonicCounter ASC"
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readAllCheckpoints" }
  );
}

async function _readAuditRowHashAtCounter(counter) {
  return await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeOne(
        "SELECT rowHash FROM audit_log WHERE monotonicCounter = ?",
        [counter]
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readRowHashAtCounter" }
  );
}

async function _insertAuditRow(allCols, values) {
  // No retry — non-idempotent. Timeout only.
  var placeholders = allCols.map(function () { return "?"; }).join(", ");
  var quoted = allCols.map(function (c) { return '"' + c + '"'; }).join(", ");
  return await safeAsync.withTimeout(
    clusterStorage.execute(
      "INSERT INTO audit_log (" + quoted + ") VALUES (" + placeholders + ")",
      values
    ),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.insertRow" }
  );
}

async function _insertCheckpoint(values) {
  return await safeAsync.withTimeout(
    clusterStorage.execute(
      "INSERT INTO audit_checkpoints (_id, createdAt, atMonotonicCounter, atRowHash, signature, publicKeyFingerprint, fencingToken) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?)",
      values
    ),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.insertCheckpoint" }
  );
}

async function _upsertAuditTip(counter, rowHash, signedAt, fencingToken) {
  // Cluster-mode only. Single atomic INSERT … ON CONFLICT … DO UPDATE
  // … WHERE … RETURNING. The WHERE clause is the canonical
  // fencing-token guard from blamejs-cluster-spec.md — it enforces
  // monotonic-non-decreasing fencingToken at the database level so a
  // partitioned old leader cannot overwrite the tip even if its
  // application-layer cluster.requireLeader() gate somehow allowed
  // the call through.
  //
  // Update accepted iff the row's stored fencingToken <= incoming one
  // (same-token re-write is fine; a strictly-lower token is fenced
  // out). On rejection RETURNING produces 0 rows — we surface that
  // as ClusterError(code='FENCED_OUT', permanent=true) so the
  // dispatching node knows it's been superseded and should step down
  // rather than retry.
  var result = await safeAsync.withTimeout(
    clusterStorage.execute(
      "INSERT INTO _blamejs_audit_tip " +
      "  (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) " +
      "VALUES ('audit', ?, ?, ?, ?) " +
      "ON CONFLICT (scope) DO UPDATE SET " +
      "  atMonotonicCounter = EXCLUDED.atMonotonicCounter, " +
      "  rowHash            = EXCLUDED.rowHash, " +
      "  signedAt           = EXCLUDED.signedAt, " +
      "  fencingToken       = EXCLUDED.fencingToken " +
      "WHERE _blamejs_audit_tip.fencingToken <= EXCLUDED.fencingToken " +
      "RETURNING fencingToken",
      [counter, rowHash, signedAt, fencingToken]
    ),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.upsertAuditTip" }
  );
  if (!result.rows || result.rows.length === 0) {
    throw new ClusterError(
      "FENCED_OUT",
      "audit-tip update rejected: incoming fencingToken=" + fencingToken +
      " is below the stored token (this leader has been fenced out " +
      "by a higher-token successor)",
      true
    );
  }
}

// Every namespace any framework primitive emits on must be listed here.
// A primitive that adds a new namespace adds it here in the same patch.
// Smoke walks lib/ at boot-time-equivalent (layer-0-primitives/audit-framework-namespaces.test.js)
// and fails if any emitted namespace is missing from this list.
//
// Why this list and not auto-registration via registerNamespace() at
// each primitive's create(): namespace registration must be effective
// the first time ANY primitive emits, regardless of which primitive
// the operator initialized first. Operators wiring just b.scheduler
// without ever calling b.apiKey.create() still trip the apikey verify
// path (e.g. through middleware they didn't write); the action-name
// validation needs to know about apikey at boot, not at first call.
var FRAMEWORK_NAMESPACES = [
  // Generic buckets
  "auth", "system", "audit", "consent", "subject",
  // Per-primitive namespaces — keep alphabetical
  "apikey",     // b.apiKey
  "backup",     // b.backup
  "breakglass", // b.breakGlass — column-policy / row-enforcement step-up auth (audit namespace lowercased per the validator's `namespace.verb` rule, same convention as b.apiKey → apikey.*)
  "cache",      // b.cache
  "compliance", // b.compliance (compliance.posture.set / cleared)
  "config",     // b.configDrift (config.baseline.captured / config.drift.detected / config.baseline.tamper / config.baseline.unreadable)
  "csrf",       // b.middleware.csrfProtect (csrf.bad_cookie_value)
  // (system.crypto.hybrid_disabled rides under "system" so no separate namespace)
  "db",         // b.db / b.middleware.dbRoleFor / b.externalDb.runAs
                //   (role-switching, RLS-shaped events)
  "dkim",       // b.mail.dkim (DKIM-Signature generation events)
  "dora",       // b.dora (DORA Article 17: dora.incident.classified / reported / draftFinal)
  "dsr",        // b.dsr (Data Subject Rights workflow: dsr.ticket.* / dsr.source.*)
  "dual",       // b.dualControl (dual.grant.requested / approved / denied / consumed / expired / self_approval_denied)
  "mail",       // b.mail (b.mail-bounce uses "system.mail.*")
  "mtls",       // b.mtlsCa engine algorithm-selection audit (mtls.engine.algorithm_selected)
  "network",    // b.middleware.networkAllowlist (network.gate.denied)
  "notify",     // b.notify
  "objectstore", // b.objectStore.bucketOps (objectstore.bucket.* / objectstore.object.*)
  "openapi",    // b.openapi (openapi.document.built / openapi.document.served)
  "asyncapi",   // b.asyncapi (asyncapi.document.built)
  "vault",      // b.vault.aad (vault.aad.sealed / vault.aad.unseal_failed)
  "wsclient",   // b.wsClient (wsclient.connected / closed / error)
  "inbox",      // b.inbox (inbox.received / handled / handle_failed / swept)
  "flag",       // b.flag (flag.evaluated / flag.evaluation.error / flag.cache.bust)
  "permissions", // b.permissions
  "restore",    // b.restore
  "retention",  // b.retention (retention.rule.declared / sweep.started / row.processed / sweep.completed / sweep.failed)
  "scheduler",  // b.scheduler (lifecycle: scheduler.start / scheduler.stop;
                //              tick/task events use "system.scheduler.*")
  "seeders",    // b.seeders
  "webhook",    // b.webhook
];
var registeredNamespaces = new Set(FRAMEWORK_NAMESPACES);

// All hashable columns of audit_log (everything in the table except the chain
// bookkeeping itself). This list MUST match what's actually written by INSERT
// and what's read back by verify; the canonicalizer needs the same key set
// at both ends or the hash will mismatch on missing-vs-null keys.
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

// Chain-writer instance owns the race-safe chain append: counter primer,
// chain mutex, prev-tip read, hash compute, INSERT. Per the framework
// rule that repeated tasks become primitives, the audit_log and
// consent_log chains both consume chain-writer.
var _chainWriter = chainWriter.create({
  table:           "audit_log",
  hashableColumns: HASHABLE_COLS,
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

// ---- Public API ----

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

async function record(event) {
  if (!event || typeof event !== "object") {
    throw new Error("audit.record requires an event object");
  }
  _validateAction(event.action);
  if (!event.outcome || ["success", "failure", "denied"].indexOf(event.outcome) === -1) {
    throw new Error("audit.record outcome must be 'success', 'failure', or 'denied'");
  }

  return observability.tap("audit.record",
    { action: event.action, outcome: event.outcome },
    async function () {
      // Build the audit-specific logical row; chain-writer handles _id /
      // recordedAt / monotonicCounter / sealing / null-fill / hashing /
      // insert / fencing-token / chain mutex / counter primer.
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
      return _chainWriter.append(logical);
    }
  );
}

// ---- Query ----
//
// Plain-field criteria translate into derived-hash equality where the column
// is sealed. Returns unsealed rows for the auditor's view.
//
// Self-logging (PCI DSS 10.2.3): every read of audit_log is itself recorded
// as an 'audit.read' event before the query runs, so an exfiltration attempt
// is forensically visible. The recursion guard (_selfLogging flag) prevents
// the audit.read recording from triggering its own self-log; queries
// SPECIFICALLY filtering for action='audit.read' don't auto-log either
// (otherwise legitimate audit auditing produces a Russell-set spiral).
var _selfLogging = false;

async function query(criteria) {
  criteria = criteria || {};
  if (!_selfLogging && criteria.action !== "audit.read") {
    _selfLogging = true;
    try {
      await record({
        actor:    criteria.actor || {},
        action:   "audit.read",
        outcome:  "success",
        metadata: {
          criteria: _redactCriteria(criteria),
          traceId:  criteria.traceId || null,
        },
      });
    } finally {
      _selfLogging = false;
    }
  }

  // In single-node mode the query builder gives us field-crypto unsealing
  // for free. In cluster mode we read raw rows from external-db and
  // unseal manually.
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

  q.orderBy("monotonicCounter", "asc");
  if (criteria.limit  != null)  q.limit(criteria.limit);
  if (criteria.offset != null)  q.offset(criteria.offset);

  return q.all();
}

async function _queryCluster(criteria) {
  var conds = [];
  var params = [];
  if (criteria.from) {
    conds.push("recordedAt >= ?");
    params.push(_toMs(criteria.from));
  }
  if (criteria.to) {
    conds.push("recordedAt <= ?");
    params.push(_toMs(criteria.to));
  }
  if (criteria.actorUserId) {
    var auh = cryptoField.lookupHash("audit_log", "actorUserId", criteria.actorUserId);
    if (auh) { conds.push(auh.field + " = ?"); params.push(auh.value); }
  }
  if (criteria.resourceId) {
    var rh = cryptoField.lookupHash("audit_log", "resourceId", criteria.resourceId);
    if (rh) { conds.push(rh.field + " = ?"); params.push(rh.value); }
  }
  if (criteria.action)        { conds.push("action = ?");        params.push(criteria.action); }
  if (criteria.resourceKind)  { conds.push("resourceKind = ?");  params.push(criteria.resourceKind); }
  if (criteria.outcome)       { conds.push("outcome = ?");       params.push(criteria.outcome); }

  var sql = "SELECT * FROM audit_log";
  if (conds.length > 0) sql += " WHERE " + conds.join(" AND ");
  sql += " ORDER BY monotonicCounter ASC";
  if (criteria.limit != null)  { sql += " LIMIT ?";  params.push(criteria.limit); }
  if (criteria.offset != null) { sql += " OFFSET ?"; params.push(criteria.offset); }

  var rows = await clusterStorage.executeAll(sql, params);
  return rows.map(function (row) { return cryptoField.unsealRow("audit_log", row); });
}

// Audit-readable summary of the criteria without storing raw subject IDs
// in plaintext anywhere outside the sealed columns of audit_log itself.
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

// Generate a fresh trace id apps can thread through their request handlers
// and pass into audit.record() / consent.grant() / etc. via the metadata
// field. Width matches the W3C traceparent trace-id format (16 random
// bytes hex-encoded → 32 chars). Routed through C.BYTES so the byte
// count has a single source of truth.
var TRACE_ID_BYTES = C.BYTES.bytes(16);
function beginTrace() {
  return generateToken(TRACE_ID_BYTES);
}

// ---- Checkpoints (tamper-proof external anchor) ----

// Build the canonical bytes that get signed for a checkpoint at a given
// chain tip. Keep this format stable across the framework's lifetime —
// changing it invalidates every prior checkpoint signature.
var CHECKPOINT_FORMAT = "blamejs-audit-checkpoint-v1";
function _checkpointPayload(atMonotonicCounter, atRowHash, createdAt) {
  // Use a fixed multi-line layout. Avoids JSON serializer quirks; portable
  // to any verifier reading the same column triple from the DB.
  return Buffer.from(
    CHECKPOINT_FORMAT + "\n" +
    String(atMonotonicCounter) + "\n" +
    atRowHash + "\n" +
    String(createdAt),
    "utf8"
  );
}

// Anchor the current chain tip with a fresh ML-DSA-87 signature. Inserts
// a row into audit_checkpoints. Updates <dataDir>/audit.tip for boot-time
// rollback detection.
//
// opts:
//   skipIfUnchanged: bool — return null without inserting if the chain tip
//                           hasn't advanced since the most recent checkpoint
async function checkpoint(opts) {
  cluster.requireLeader();
  opts = opts || {};

  var tip = await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeOne(
        "SELECT _id, monotonicCounter, rowHash FROM audit_log " +
        "ORDER BY monotonicCounter DESC LIMIT 1"
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.checkpoint.readTip" }
  );

  if (!tip) return null; // empty audit log; nothing to anchor

  if (opts.skipIfUnchanged) {
    var lastCkpt = await _readLastCheckpointCounter();
    if (lastCkpt && Number(lastCkpt.atMonotonicCounter) >= Number(tip.monotonicCounter)) {
      return null; // already anchored at this tip
    }
  }

  var createdAt = Date.now();
  var counter = Number(tip.monotonicCounter);
  var payload = _checkpointPayload(counter, tip.rowHash, createdAt);
  var signature = auditSign.sign(payload);
  var pubFp = auditSign.getPublicKeyFingerprint();

  var ckptId = generateToken(TRACE_ID_BYTES);
  var fencingToken = cluster.fencingToken();
  await _insertCheckpoint(
    [ckptId, createdAt, counter, tip.rowHash, signature, pubFp, fencingToken]
  );

  // Update rollback-detection sidecar (single-node) or audit-tip row
  // (cluster mode).
  //
  // Single-node sidecar is best-effort — a sidecar write failure must
  // not block checkpointing because the chain itself is already
  // committed.
  //
  // Cluster-mode audit-tip is NOT best-effort: the upsert's WHERE
  // clause is the fencing-token guard, and a FENCED_OUT response
  // means the local node has been superseded by a newer leader. The
  // checkpoint row was already inserted at this point but propagating
  // the error up makes the leadership-loss visible to the caller — it
  // also means the caller can audit the leader-lost transition and
  // step down. Other audit-tip errors (network blip, transient DB)
  // also surface so the operator can react.
  if (cluster.isClusterMode()) {
    await _upsertAuditTip(counter, tip.rowHash, String(createdAt), fencingToken);
  } else {
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

  return {
    _id:                ckptId,
    createdAt:          createdAt,
    atMonotonicCounter: counter,
    atRowHash:          tip.rowHash,
    publicKeyFingerprint: pubFp,
  };
}

// Walk every checkpoint, verify its signature against the current public
// key (or one matching the row's stored fingerprint). Also confirms the
// audit_log row at atMonotonicCounter still has the recorded rowHash.
//
// Returns { ok, checkpointsVerified, breakAt? }.
async function verifyCheckpoints() {
  var rows = await _readAllCheckpointsAsc();

  if (rows.length === 0) return { ok: true, checkpointsVerified: 0 };

  var currentFp = auditSign.getPublicKeyFingerprint();
  var currentPub = auditSign.getPublicKey();

  for (var i = 0; i < rows.length; i++) {
    var c = rows[i];
    // Public key check: only the current key is accepted — there is no
    // key-history table, so any rotation requires re-signing existing
    // checkpoints. A fingerprint mismatch fails verification.
    if (c.publicKeyFingerprint !== currentFp) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "public key fingerprint mismatch (key rotated without history?)",
        expected:            currentFp,
        actual:              c.publicKeyFingerprint,
      };
    }
    var payload = _checkpointPayload(Number(c.atMonotonicCounter), c.atRowHash, Number(c.createdAt));
    var sigBuf = Buffer.isBuffer(c.signature) ? c.signature : Buffer.from(c.signature);
    if (!auditSign.verify(payload, sigBuf, currentPub)) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "ML-DSA-87 signature failed",
      };
    }
    // Also confirm the audit row at atMonotonicCounter still matches the
    // anchored rowHash. If someone tampered with audit_log AND recomputed
    // hashes (requiring vault key), this catches them via the off-chain
    // signature anchor.
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

// ---- Verify ----

async function verify(opts) {
  // verifyChain just needs an executeAll; route through the same
  // resilience-wrapped reader the rest of audit uses.
  return await auditChain.verifyChain(
    function (sql, params) {
      return safeAsync.withTimeout(
        safeAsync.asyncRetry(function () {
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

// ---- Test helpers ----

function _resetForTest() {
  registeredNamespaces = new Set(FRAMEWORK_NAMESPACES);
  db.reset();
  _chainWriter._resetForTest();
  // Drop pending buffered emits and cancel the age-flush timer on the
  // old handler before dereferencing it. Without this, the old
  // handler's setTimeout (scheduled when emits buffer below maxBatch)
  // fires AFTER the next test's db.init has opened a fresh database —
  // the buffered items then drain through chain-writer into the wrong
  // tmpDir's audit_log, breaking chain verify on the next-next test.
  // shutdownSync is the explicit "drop, don't drain" path because
  // draining to a stale or changing backing store is exactly the bug.
  // The handler's flush also checks ctx.isShutdown() between items, so
  // an in-flight drain that's mid-batch when reset fires bails out
  // instead of writing the rest of the batch to the new database.
  if (_auditHandler) {
    try { _auditHandler.shutdownSync("audit._resetForTest"); }
    catch (e) { log.debug("reset-handler-shutdown-failed: " + (e && e.message || e)); }
    _auditHandler = null;
  }
}

// ---- Handler-backed emit + flush ----
//
// emit() is the call-site API for fire-and-forget audit emission from
// middleware / log-stream / external-db hooks / queue / storage / subject.
// It is SYNCHRONOUS, NEVER throws, and NEVER returns a Promise — request-
// path code can call it without await and without try/catch.
//
// Internally events queue in an AsyncHandler. flush() drains the queue
// to the audit chain (single writer in-process, serialized via the
// chain mutex). Tests, shutdown, and any code that needs audit-row
// durability before reading audit_log calls await audit.flush().
//
// Why this beats fire-and-forget Promises:
//   - No leaked Promises across test/shutdown boundaries
//   - Errors go through a single onError hook (visible to operators)
//   - Recursive emits during flush land in the buffer for the next
//     drain cycle — no infinite loop in cluster-mode dispatchers
//   - Tests have a deterministic "audit is durable now" point
var _auditHandler = null;

function _ensureHandler() {
  if (_auditHandler) return _auditHandler;
  _auditHandler = handlers.create({
    name:  "audit",
    flush: async function (batch, ctx) {
      // Drain by serially writing each event through record(). The chain
      // mutex inside record() further serializes vs concurrent direct
      // record() callers.
      //
      // Between items, check the handler's shutdown probe — if a test
      // (or operator) reset audit while this batch was in flight, the
      // remaining items would otherwise drain through the chain-writer
      // into a database that no longer represents the chain those
      // items were emitted against. Early-exit drops them; the
      // alternative is silent corruption of the next chain.
      var droppedThisBatch = 0;
      for (var i = 0; i < batch.length; i++) {
        if (ctx && ctx.isShutdown && ctx.isShutdown()) return;
        try { await record(batch[i]); }
        catch (e) {
          droppedThisBatch += 1;
          // Per-item failure shouldn't drop the whole batch; log and
          // continue. The handler's onError gets called for batch-
          // wide failures only.
          log.error("flush dropped event: " +
            (e && e.message ? e.message : String(e)) +
            " (action=" + (batch[i] && batch[i].action) + ")");
        }
      }
      // Surface chain-write integrity failures via observability so
      // operators alerting on rate-drop see something. The audit
      // chain itself can't carry the signal — the chain is what's
      // broken — so observability is the only sink left.
      if (droppedThisBatch > 0) {
        observability.safeEvent("system.audit.chain_write_dropped",
          droppedThisBatch, { batchSize: batch.length });
      }
    },
  });
  return _auditHandler;
}

function emit(event) {
  _ensureHandler().emit(event);
}

// Outcome normalization — drop-silent on a strict `outcome` mismatch
// dropped a class of audit rows across the framework (every
// non-{success, failure, denied} outcome from b.flag / b.outbox /
// b.inbox / b.session / b.db / b.config-drift / b.compliance-aiAct
// landed in the handler's catch-and-log path instead of the chain).
// safeEmit owns the normalization; record() stays strict so direct
// callers see the typo loudly.
var OUTCOME_NORMALIZE = {
  ok:        "success",
  okay:      "success",
  pass:      "success",
  passed:    "success",
  success:   "success",
  succeeded: "success",
  warn:      "success",
  warning:   "success",
  duplicate: "success",
  skip:      "success",
  skipped:   "success",
  fail:      "failure",
  failed:    "failure",
  failure:   "failure",
  err:       "failure",
  error:     "failure",
  denied:    "denied",
  refused:   "denied",
  deny:      "denied",
};

function _normalizeOutcome(o) {
  if (typeof o !== "string") return "success";
  var n = OUTCOME_NORMALIZE[o.toLowerCase()];
  return n || "success";
}

// Hyphens in action segments fall outside the underscore-only
// regex enforced by record(). Replace at the segment boundary so
// "compliance.aiact.biometric-id-categorisation" lands as
// "compliance.aiact.biometric_id_categorisation" and reaches the
// chain instead of dropping. The action namespace prefix (the part
// before the first dot) is left strict — namespaces are
// operator-registered and should be plain identifiers.
function _normalizeAction(action) {
  if (typeof action !== "string") return action;
  return action.replace(/-/g, "_");
}

// safeEmit — fire-and-forget audit emit with safe defaults + try/catch.
//
// Most modules wrap emit() in their own _emit helper that fills in
// `actor: {}`, `outcome: "success"`, etc. and catches the throw so an
// audit outage doesn't crash the request handler. This is that helper,
// hoisted out so each module can stop redefining it.
//
// Drop-silent on malformed input by design. safeEmit is called from
// request hot paths where throwing on a
// missing `action` would mean a malformed audit attempt crashes the
// request that triggered it — strictly worse than the missing audit
// row. Operators who need a hard guarantee the event landed should call
// record() and await it with their own error handling. The audit chain
// itself is verified at boot, so a silently dropped row shows up in the
// next chain integrity sweep.
function safeEmit(event) {
  if (!event || typeof event !== "object") return;
  if (typeof event.action !== "string") return;  // can't emit without an action
  try {
    // Scrub credentials before they hit the audit handler. Operators
    // who pass `metadata: { reason: e.message }` from a caught error
    // can land DB connection strings, bearer tokens, and JWT compact-
    // serialization fixtures in audit rows; redact.redact() catches the
    // common shapes (sensitive field names + value-shape detectors:
    // credit-card / JWT / PEM / AWS key / SSN / connection string) and
    // replaces them with markers. Same pass also applies to actor +
    // reason so the entire event surface is consistent. Drop-silent on
    // redact failure — never break the caller's audit attempt.
    var actor = event.actor || {};
    var reason = event.reason || null;
    var metadata = event.metadata || null;
    try {
      actor = redact.redact(actor);
      if (reason !== null) reason = redact.redact(reason);
      if (metadata !== null) metadata = redact.redact(metadata);
    } catch (_e) { /* fall through with original values */ }
    _ensureHandler().emit({
      actor:     actor,
      action:    _normalizeAction(event.action),
      resource:  event.resource || null,
      outcome:   _normalizeOutcome(event.outcome),
      reason:    reason,
      metadata:  metadata,
      requestId: event.requestId || null,
    });
  } catch (_e) { /* audit best-effort — never break the caller */ }
}

async function flush() {
  if (!_auditHandler) return;
  await _auditHandler.drain();
}

module.exports = {
  registerNamespace:    registerNamespace,
  record:               record,
  emit:                 emit,
  safeEmit:             safeEmit,
  flush:                flush,
  query:                query,
  verify:               verify,
  beginTrace:           beginTrace,
  checkpoint:           checkpoint,
  verifyCheckpoints:    verifyCheckpoints,
  CHECKPOINT_FORMAT:    CHECKPOINT_FORMAT,
  FRAMEWORK_NAMESPACES: FRAMEWORK_NAMESPACES,
  _resetForTest:        _resetForTest,
};
