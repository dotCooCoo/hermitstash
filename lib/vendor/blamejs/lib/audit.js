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
 *   / id), HOW (`outcome` ∈ {success, failure, denied} + `reason` +
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
var dbRoleContext = require("./db-role-context");
var handlers = require("./handlers");
var { boot } = require("./log");
var redact = require("./redact");
var safeAsync = require("./safe-async");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var observability = require("./observability");
var { AuditSegregationError, ClusterError } = require("./framework-error");

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
  "pqcagent",   // b.pqcAgent (pqcagent.operator_group.accepted)
  "restore",    // b.restore
  "retention",  // b.retention (retention.rule.declared / sweep.started / row.processed / sweep.completed / sweep.failed)
  "scheduler",  // b.scheduler (lifecycle: scheduler.start / scheduler.stop;
                //              tick/task events use "system.scheduler.*")
  "seeders",    // b.seeders
  "webhook",    // b.webhook
  "sse",        // b.sse (sse.channel_opened / closed / injection_refused)
  "mcp",        // b.mcp.serverGuard (mcp.auth.* / mcp.tool.* / mcp.resource.* / mcp.register.* / mcp.envelope.*)
  "graphqlfederation", // b.graphqlFederation.guardSdl (sdl-refused / sdl-allowed)
  "aiinput",    // b.ai.input.classify (aiInput.classify)
  "a2a",        // b.a2a (a2a.card_signed / verified / rejected)
  "darkpatterns", // b.darkPatterns (darkPatterns.attest / cancel-blocked)
  "budr",       // b.budr (budr.declared)
  "seccyber",   // b.secCyber (seccyber.eight_k_artifact)
  "iabtcf",     // b.iabTcf (iabtcf.refused / iabtcf.accepted)
  "fapi2",      // b.fapi2 (fapi2.posture_asserted)
  "contentcredentials", // b.contentCredentials (contentcredentials.signed / verified)
  "aipref",     // b.aiPref (aipref.paid_crawl_refused)
  "fdx",        // b.fdx (fdx.bound / fdx.consent_receipt_issued)
  "tcpa10dlc",  // b.tcpa10dlc (tcpa10dlc.consent_recorded / consent_revoked)
  "iabmspa",    // b.iabMspa (iabmspa.processing_refused)
  "vendor",     // b.configDrift.verifyVendorIntegrity (vendor.integrity.verified / tampered)
  "honeytoken", // b.honeytoken (honeytoken.issued / tripped)
  "csp",        // b.middleware.cspReport (csp.violation)
  "resourceaccesslock", // b.resourceAccessLock (resourceaccesslock.mode_changed / refused)
  "process",    // b.processSpawn (process.spawn / process.spawn.failed)
  "keychain",   // b.keychain (keychain.stored / keychain.retrieved / keychain.removed)
  "fda21cfr11", // b.fda21cfr11 (signature.created / verified / gxp.assert_failed / audit.refused / posture.installed)
  "ddl",        // b.ddlChangeControl (ddl.change.proposed / approved / rejected / applied / apply_refused)
  "migrations", // b.migrations + b.externalDb.migrate (migrations.history.appended / verified / tampered)
  "dlp",        // b.redact.installOutboundDlp (dlp.outbound.refused / redacted / scanned / installed)
  "session",    // b.sessionDeviceBinding (session.device.bound / drift / refused)
  "sandbox",    // b.sandbox (sandbox.run / sandbox.run.refused — operator-supplied transform isolation)
  "safeurl",    // b.safeUrl.parse (safeurl.idn_homograph.refused — UTS #39 mixed-script host-label refusal)
  "http",       // b.middleware.bodyParser (http.chunked.malformed.refused — RFC 9112 §7.1 chunked-decode failure with Connection: close) // allow:raw-byte-literal — RFC number in prose
  "cryptofield", // b.cryptoField.eraseRow (cryptofield.vacuum.skipped — F-RTBF-2 vacuum-after-erase signal when DB not initialized at erase time)
  "acme",       // b.acme (acme.account.registered / order.* / cert.issued / cert.renewed / cert.renew.skipped — RFC 8555 + RFC 9773 ARI workflow)
  "tls",        // b.router 0-RTT posture (tls.0rtt.refused / tls.0rtt.replayed) — RFC 8446 §8 anti-replay surface // allow:raw-byte-literal — RFC number in prose
  "workerpool", // b.workerPool (workerpool.created / terminated / task.completed / task.failed / task.timeout / spawn.failed — generic worker_threads pool)
  "jwt",        // b.auth.jwt-external (jwt.jwe.refused — RFC 7516 5-segment JWE refusal)
  "dr",         // b.drRunbook (dr.runbook.emitted)
  "guardfilename", // b.guardFilename (guardfilename.sanitize.stripped)
  "legalhold",  // b.legalHold (legalhold.placed / released / place_rejected / release_rejected)
  "networkheartbeat", // b.network.heartbeat.passive (networkheartbeat.passive.timeout)
  "router",     // b.router (router.redirect.cross_origin.refused / allowed)
  "http2",      // b.router h2 GOAWAY tracker (http2.window_update.refused — CVE-2026-21714)
  "tenant",     // b.tenantQuota (tenant.quota.exceeded / tenant.budget.exceeded / tenant.crossover)
  "httpclient", // b.httpClient.cache (httpclient.cache.hit / .miss / .stale / .revalidated / .evicted — RFC 9111 outbound HTTP cache)
  "mailmdn",    // b.mailMdn (mailmdn.generated / mailmdn.suppressed — RFC 3798/8098 Message Disposition Notification)
  "mailarf",    // b.mailArf (mailarf.parsed / mailarf.malformed — RFC 5965 abuse-feedback ingestion)
  "mailbimi",   // b.mail.bimi (mail.bimi.vmc.fetched / verified — RFC 9091 VMC chain validation)
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
 * {success, failure, denied}. The chain-writer serializes the actual
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
 *   outcome:   "success" | "failure" | "denied",
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
 * visible; recursion is guarded so the self-log doesn't trigger its own
 * self-log. Plain-field criteria translate into derived-hash equality
 * where the column is sealed.
 *
 * @opts
 *   from:         number | Date | string,   // recordedAt >=
 *   to:           number | Date | string,   // recordedAt <=
 *   actorUserId:  string,
 *   resourceId:   string,
 *   action:       string,
 *   resourceKind: string,
 *   outcome:      "success" | "failure" | "denied",
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
/**
 * @primitive b.audit.checkpoint
 * @signature b.audit.checkpoint(opts)
 * @since     0.4.0
 * @compliance soc2, pci-dss, sox-404
 * @related   b.audit.verifyCheckpoints, b.audit.verify
 *
 * Anchor the current chain tip with a fresh ML-DSA-87 (post-quantum)
 * signature. Inserts a row into `audit_checkpoints` and updates the
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
/**
 * @primitive b.audit.verifyCheckpoints
 * @signature b.audit.verifyCheckpoints()
 * @since     0.4.0
 * @compliance soc2, pci-dss, sox-404
 * @related   b.audit.checkpoint, b.audit.verify
 *
 * Walk every checkpoint and verify (a) the public-key fingerprint
 * matches the current signing key, (b) the ML-DSA-87 signature over the
 * payload still verifies, (c) the audit_log row at the anchored counter
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

// ---- SOX §404 / SOC 2 CC1.3 — actor-binding + segregation of duties ----
//
// Anyone with write access to the audit_log table can INSERT a row
// claiming any actor identity. The framework already records actor
// from the request context, but a privileged caller (operator script,
// migration runner, anyone with the externalDb credentials) can claim
// a different actor.
//
// bindActor(actorId, opts) returns a wrapper around audit.safeEmit /
// audit.record that refuses any event whose actor.userId mismatches
// the bound identity OR the SQL-bound role (when db-role-context is
// active).
//
// SQL-side enforcement lives in lib/cluster-storage.js's framework-
// schema generator — see generateActorBindingTriggerSql() below for
// the Postgres trigger DDL. Operators apply that DDL in a migration
// when they boot under sox-404 / soc2 / pci-dss posture so a non-
// framework writer can't INSERT rows under a different role.
function _checkActorBinding(actorId, eventActorId, opts) {
  if (!actorId) return true;     // unbound — no enforcement
  if (!eventActorId) {
    return { ok: false, reason: "event missing actor.userId — refused under bound emit" };
  }
  if (eventActorId !== actorId) {
    return { ok: false,
      reason: "actor mismatch: bound='" + actorId + "', event='" + eventActorId + "'" };
  }
  // db-role-context check — when the caller is inside a runWithRole
  // scope, the SQL-bound role and the bound actor must agree (subject
  // to the operator-supplied `roleEquivalent` mapping).
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
      // Surface via the un-bound _ensureHandler so the violation row
      // lands in the chain regardless of bind state.
      _ensureHandler().emit({
        action:   "audit.actor_binding.violation",
        outcome:  "denied",
        actor:    { userId: actorId },
        metadata: { attemptedAction: eventAction, reason: reason },
      });
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

// Trigger-SQL generator — operators apply the returned DDL via
// b.externalDb.migrate so the database itself refuses INSERTs into
// _blamejs_audit_log where the row's stored actor mismatches the
// SQL session's current_user.
//
// opts.column — defaults to "actorUserId"; operators with a separate
//   role mapping table pass an explicit column name.
// opts.roleMappingFn — Postgres function name that maps the row's
//   actorUserId to the expected SQL role; defaults to identity match
//   (current_user must equal the actorUserId).
// opts.tableName — defaults to "_blamejs_audit_log".
// opts.allowRoles — array of roles allowed to insert ANY actor (e.g.
//   the framework's own service account); skipped checks for those
//   roles.
//
// Returns { up: ddl, down: ddl } so the migration runner can install +
// uninstall.
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
  var column = opts.column || "actorUserId";
  var tableName = opts.tableName || "_blamejs_audit_log";
  var allowRoles = Array.isArray(opts.allowRoles) ? opts.allowRoles : [];
  var fnName = "_blamejs_audit_actor_binding_check";
  var trigName = "_blamejs_audit_actor_binding_trig";
  var allowList = allowRoles.length === 0 ? "" :
    "  IF current_user IN (" +
    allowRoles.map(function (r) { return "'" + r.replace(/'/g, "''") + "'"; }).join(", ") +
    ") THEN RETURN NEW; END IF;\n";
  var roleMatch = opts.roleMappingFn
    ? "  IF " + opts.roleMappingFn + "(NEW.\"" + column + "\") IS DISTINCT FROM current_user THEN\n"
    : "  IF NEW.\"" + column + "\" IS DISTINCT FROM current_user THEN\n";
  var up =
    "CREATE OR REPLACE FUNCTION " + fnName + "() RETURNS trigger AS $$\n" +
    "BEGIN\n" +
    allowList +
    roleMatch +
    "    RAISE EXCEPTION 'segregation-of-duties violation: actor=% does not match current_user=%', NEW.\"" + column + "\", current_user\n" +
    "      USING ERRCODE = 'P0001';\n" +
    "  END IF;\n" +
    "  RETURN NEW;\n" +
    "END;\n" +
    "$$ LANGUAGE plpgsql;\n" +
    "DROP TRIGGER IF EXISTS " + trigName + " ON " + tableName + ";\n" +
    "CREATE TRIGGER " + trigName + "\n" +
    "  BEFORE INSERT ON " + tableName + "\n" +
    "  FOR EACH ROW EXECUTE FUNCTION " + fnName + "();\n";
  var down =
    "DROP TRIGGER IF EXISTS " + trigName + " ON " + tableName + ";\n" +
    "DROP FUNCTION IF EXISTS " + fnName + "();\n";
  return { up: up, down: down, functionName: fnName, triggerName: trigName };
}

// Boot-time check operators wire under sox-404 / soc2 posture. Verifies
// the trigger function + trigger row are present in the externalDb
// information_schema. Returns { ok, missing? } so the caller decides
// whether to refuse boot.
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
  var db = opts.db || null;
  if (!db || typeof db.query !== "function") {
    throw new AuditSegregationError("audit/segregation-no-db",
      "audit.assertSegregation: opts.db with a query() method is required");
  }
  var fnName = opts.functionName || "_blamejs_audit_actor_binding_check";
  var trigName = opts.triggerName || "_blamejs_audit_actor_binding_trig";
  var fnRes = await db.query(
    "SELECT 1 FROM pg_proc WHERE proname = $1 LIMIT 1", [fnName]
  );
  var fnPresent = !!(fnRes && fnRes.rows && fnRes.rows.length > 0);
  var trigRes = await db.query(
    "SELECT 1 FROM pg_trigger WHERE tgname = $1 LIMIT 1", [trigName]
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

// applyPosture — F-POSTURE-1 cascade hook. b.compliance.set(posture)
// calls this to record the active posture so audit emissions can
// surface the regulatory regime in metadata where downstream tooling
// (forensic export, SIEM correlation) needs it. The chain itself is
// posture-agnostic (every posture audits with the same SLH-DSA-SHAKE-
// 256f signing key); this hook captures the posture name so query()
// callers that filter by-posture have a stable column to look at.
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
 * tooling that wants to tag audit-derived artifacts with the regime.
 *
 * @example
 *   b.audit.applyPosture("pci-dss");
 *   b.audit.activePosture();   // → "pci-dss"
 */
function activePosture() { return _activePosture; }

module.exports = {
  registerNamespace:    registerNamespace,
  record:               record,
  emit:                 emit,
  safeEmit:             safeEmit,
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
};
