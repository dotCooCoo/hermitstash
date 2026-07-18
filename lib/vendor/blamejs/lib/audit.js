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
var { AuditSegregationError, ClusterError } = require("./framework-error");

var log = boot("audit");

// External shadow-store callbacks are bounded by the same hot-path
// timeout the framework's own SQL paths use. A stalled operator
// network call that neither resolves nor rejects MUST NOT block the
// audit critical path — b.audit.record() must return, emit/safeEmit
// drains must not stall behind it. On timeout the shadow record is
// dropped (audit.shadow_timeout observability event) and the
// framework chain row remains committed — audit emission MUST NOT
// crash or stall the request that triggered it.
var EXTERNAL_STORE_TIMEOUT_MS = C.TIME.seconds(30);

// External shadow store registered via `b.audit.useStore({ record })`.
// When set, every successful framework chain.append also fires
// `_externalStore.record(rowResult)` so operators can replicate audit
// records to an immutable external destination (AWS QLDB, Azure
// Confidential Ledger, Google Cloud Audit Logs, an in-house WORM
// appliance, a SIEM, etc.) WITHOUT giving up the framework's tamper-
// evident chain integrity. The framework's chain remains authoritative;
// the operator's record receives the fully-formed row (logical fields +
// `_id` + `recordedAt` + `monotonicCounter` + `prevHash` + `rowHash`).
//
// Shadow failures are drop-silent — hot-path observability sinks
// must not crash the path that emitted them. An audit-shadow
// failure surfaces via `b.observability` as `audit.shadow_failed`;
// the framework chain row still committed and downstream
// verifyChain still works against the framework store.
var _externalStore = null;

// Per-operation timeout for framework-state SQL. A misbehaving
// external-db driver hanging on a query shouldn't hang audit forever.
// 30s is generous for genuinely slow networks while still bounding
// the worst case.
var FRAMEWORK_SQL_TIMEOUT_MS = C.TIME.seconds(30);

// b.sql opts for every framework-table statement: thread the ACTIVE backend
// dialect (clusterStorage.dialect() — "sqlite" single-node, "postgres" |
// "mysql" in cluster mode) so the emitted identifier quoting + dialect
// idioms (ON CONFLICT vs ON DUPLICATE KEY) match the backend the SQL
// dispatches to. Defaulting to "sqlite" works on Postgres only by accident
// (both double-quote identifiers) and emits the wrong quoting on MySQL.
// clusterStorage.execute still rewrites table names + translates `?`
// placeholders at dispatch; this controls only the builder-side quoting +
// idiom selection.
function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

// ---- Resilience-wrapped SQL operations (audit-specific reads) ----
// Chain APPEND lives in chain-writer (race-safe via mutex, retry, timeout).
// The wrappers below cover audit-specific reads/writes that aren't part
// of the chain append: checkpoint queries, verifyCheckpoints reads,
// audit-tip cluster-row updates.

// Framework-state reads compose b.sql with BARE logical table names —
// clusterStorage rewrites the framework names to their configured-prefix
// form and placeholderizes per dialect; b.sql quotes the camelCase columns
// and runs the output validator.
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

async function _readAllAuditRowsAsc() {
  var built = sql.select("audit_log", _sqlOpts())
    .orderBy("monotonicCounter", "asc")
    .toSql();
  return await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeAll(built.sql, built.params);
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readAllRowsAsc" }
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

async function _insertAuditRow(allCols, values) {
  // No retry — non-idempotent. Timeout only. Map each column to its
  // positional value and bind as a row object (the unambiguous b.sql form;
  // a flat value array whose first element is a Buffer would be misread as
  // an array-of-rows). BARE logical table name → clusterStorage rewrites.
  var rowObj = {};
  for (var i = 0; i < allCols.length; i++) rowObj[allCols[i]] = values[i];
  var built = sql.insert("audit_log", _sqlOpts())
    .columns(allCols)
    .values(rowObj)
    .toSql();
  return await safeAsync.withTimeout(
    clusterStorage.execute(built.sql, built.params),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.insertRow" }
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

// A concurrent anchor of the SAME tip loses the race to INSERT the
// atMonotonicCounter (UNIQUE): two anchors of one tip sign the identical
// payload, so the collision means the counter is ALREADY anchored, not a
// corruption. Recognize it BACKEND-AGNOSTICALLY so the loser returns null like
// the skipIfUnchanged "already anchored" path instead of throwing. Each driver
// surfaces the violation differently: SQLite names the column in the message
// (`... audit_checkpoints.atMonotonicCounter`); Postgres carries the unique
// INDEX name (idx_chkpt_counter) in `constraint`/`detail` with SQLSTATE 23505;
// MySQL reports the key name in `sqlMessage` with errno 1062. Gather every such
// field, and require BOTH a reference to the counter column OR its unique index
// AND a uniqueness signal, so no unrelated error is ever swallowed (anything
// unrecognized rethrows — fail-closed).
// Tokens that name the counter column (sqlite) or its unique index (pg/mysql).
var _DUP_COUNTER_REFS = ["atmonotoniccounter", "chkpt_counter"];
// A uniqueness-violation signal on any backend: sqlite message/code, postgres
// text/SQLSTATE 23505, mysql text/code-name/errno 1062.
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
  // Single atomic INSERT … ON CONFLICT(scope) DO UPDATE … WHERE … RETURNING
  // via b.sql. BARE logical table name (`_blamejs_audit_tip`) — clusterStorage
  // rewrites it (and the same bare name inside the conflictWhere fence) to
  // the configured prefix and placeholderizes. The fenced WHERE enforces the
  // monotonic-non-decreasing fencingToken at the DB level; on rejection
  // RETURNING produces 0 rows.
  // The audit-tip is external-only; its LOGICAL name IS the
  // `_blamejs_`-prefixed name (self-mapped in LOCAL_TO_EXTERNAL), passed
  // bare to b.sql so clusterStorage rewrites it (and the same bare name
  // inside the guarded fence) to the configured prefix.
  //
  // The fence `<table>.<fencingToken> <= EXCLUDED.<fencingToken>` references
  // both the EXISTING row (table-qualified) and the PROPOSED row (EXCLUDED on
  // Postgres/SQLite, VALUES() on MySQL ON DUPLICATE KEY UPDATE), and the
  // identifier quoting differs per dialect — so the raw fragment is built
  // dialect-aware: safeSql.quoteQualified for the table-qualified existing
  // column (backticks on MySQL, double-quotes on PG/SQLite), and the
  // proposed-row reference spelled per dialect (the EXCLUDED keyword has no
  // MySQL equivalent — ON DUPLICATE KEY UPDATE uses VALUES(col)). guardColumn
  // tells the MySQL upsert renderer that the fence protects `fencingToken`,
  // so the IF(<fence>, …, col) wrap on the other SET targets evaluates
  // against the fencingToken column's PRE-update value (the IF-eval-order
  // hazard) and the guard column is assigned last.
  var dialect = clusterStorage.dialect();
  var fenceExisting = safeSql.quoteQualified(["_blamejs_audit_tip", "fencingToken"], dialect);   // allow:hand-rolled-sql
  var fenceProposed = dialect === "mysql"
    ? "VALUES(" + safeSql.quoteIdentifier("fencingToken", "mysql") + ")"
    : "EXCLUDED." + safeSql.quoteIdentifier("fencingToken", dialect);
  var tipFence = fenceExisting + " <= " + fenceProposed;
  var tipBuilt = sql.upsert("_blamejs_audit_tip", { dialect: dialect })   // allow:hand-rolled-sql
    .columns(["scope", "atMonotonicCounter", "rowHash", "signedAt", "fencingToken"])
    .values({
      scope:              "audit",
      atMonotonicCounter: counter,
      rowHash:            rowHash,
      signedAt:           signedAt,
      fencingToken:       fencingToken,
    })
    .onConflict(["scope"])
    .doUpdateFromExcluded(["atMonotonicCounter", "rowHash", "signedAt", "fencingToken"])
    .conflictWhere(tipFence, [], { guardColumn: "fencingToken" })
    .returning(["fencingToken"])
    .toSql();
  var fenced;
  if (dialect === "mysql") {
    // MySQL ON DUPLICATE KEY UPDATE has no WHERE + no RETURNING — the fence
    // becomes an IF(<guard>, VALUES(col), col) per SET target, so a fenced-out
    // (strictly-lower) token leaves every column at its stored value and the
    // statement still "succeeds". Detection therefore can't read RETURNING
    // rows: run the upsert, then read the stored fencingToken back (the b.sql
    // builder hands us the keyed readback SELECT) and compare. If the stored
    // token is ABOVE our incoming one, a higher-token successor won and we
    // were fenced out.
    await safeAsync.withTimeout(
      clusterStorage.execute(tipBuilt.sql, tipBuilt.params),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: "audit.upsertAuditTip" }
    );
    var back = await safeAsync.withTimeout(
      clusterStorage.executeOne(tipBuilt.readbackSql.sql, tipBuilt.readbackSql.params),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: "audit.upsertAuditTip.readback" }
    );
    fenced = !back || Number(back.fencingToken) > Number(fencingToken);
  } else {
    var result = await safeAsync.withTimeout(
      clusterStorage.execute(tipBuilt.sql, tipBuilt.params),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: "audit.upsertAuditTip" }
    );
    fenced = !result.rows || result.rows.length === 0;
  }
  if (fenced) {
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
  "app",        // b.createApp (app.middleware.disabled — a security-default middleware was opted out at construction)
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
  "dsa",        // b.dsa (EU Digital Services Act: dsa.notice.recorded / dsa.sor.recorded / dsa.transparency_report.generated)
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
  "pipl",       // b.pipl (China PIPL cross-border: pipl.transfer.assessed / pipl.security_assessment.recorded)
  "pqcagent",   // b.pqcAgent (pqcagent.operator_group.accepted)
  "privacy",    // b.privacy (privacy.vendor_review.recorded)
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
  "aioutput",   // b.ai.output.sanitize / redact (aioutput.sanitize / aioutput.redact)
  "aiprompt",   // b.ai.prompt.template (aiprompt.template — stripped-threat warning)
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
  "http",       // b.middleware.bodyParser (http.chunked.malformed.refused — RFC 9112 §7.1 chunked-decode failure with Connection: close) // RFC number in prose
  "cryptofield", // b.cryptoField.eraseRow (cryptofield.vacuum.skipped — vacuum-after-erase signal when DB not initialized at erase time)
  "acme",       // b.acme (acme.account.registered / order.* / cert.issued / cert.renewed / cert.renew.skipped — RFC 8555 + RFC 9773 ARI workflow)
  "cert",       // b.cert (cert.account.generated / cert.issued / cert.renewed / cert.renew-failed / cert.challenge-cleanup — turnkey cert-manager lifecycle)
  "tls",        // b.router 0-RTT posture (tls.0rtt.refused / tls.0rtt.replayed) — RFC 8446 §8 anti-replay surface // RFC number in prose
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
  "localdb",    // b.localDb.thin (localdb.thin.opened / recovered / closed — desktop-daemon SQLite wrapper)
  "dataact",    // b.dataAct (EU Data Act 2023/2854 — product_declared / user_access / share_with_third_party / share_refused / switch_request)
  "idempotency", // b.middleware.idempotencyKey (idempotency.missing_key / bad_key / replay / key_reuse_mismatch / cache_store / store_read_failed / store_write_failed / skip_5xx / body_too_large — draft-ietf-httpapi-idempotency-key)
  "aibom",            // b.ai.modelManifest (aibom.signed / aibom.verified — CycloneDX 1.6 ML-BOM)
  "aicontentdetect",  // b.ai.aiContentDetect (aicontentdetect.report — AB-853 / EU AI Act Art. 50 inbound provenance)
  "sdnotify",         // b.sdNotify (sdnotify.send / sdnotify.send.skipped — systemd Type=notify)
  "bootgates",        // b.bootGates (bootgates.passed / bootgates.failed / bootgates.onfail_threw — boot-invariant runner)
  "metrics",          // b.metrics.snapshot.shadowRegistry (metrics.shadow.cardinality_dropped — namespaced metrics export)
  "jose",             // b.jose.jwe.experimental (jose.jwe.experimental.encrypt / .decrypt — ML-KEM-JWE pre-IANA)
  "ai",               // b.ai.adverseDecision (ai.adverse_decision.* — FCRA adverse-action decisioning)
  "breach",           // b.breachDeadline (breach.report.* — breach-notification deadline clock)
  "cra",              // b.craReport (cra.report.* — EU Cyber Resilience Act conformity)
  "gdpr",             // b.gdprRopa (gdpr.ropa.* — GDPR Art. 30 Records of Processing Activities)
  "incident",         // b.incidentReport (incident.report.* — incident lifecycle)
  "middleware",       // b.middleware.ageGate / dailyByteQuota (middleware.age_gate.* / middleware.daily_byte_quota.*)
  "nis2",             // b.nis2Report (nis2.report.* — NIS2 Directive incident reporting)
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
      var appended = await _chainWriter.append(logical);
      // Operator-registered shadow store: replicate the fully-formed
      // row to an immutable external destination. Drop-silent on
      // failure — the framework chain is authoritative and already
      // committed; the shadow is a best-effort archival, and an
      // unreachable destination must not crash the audit caller.
      // The operator's record receives the SAME object the framework
      // returns to its caller, so external consumers see identical
      // hashes / counters / ids for cross-store reconciliation.
      if (_externalStore && typeof _externalStore.record === "function") {
        // Bound the operator-supplied callback so a stalled network
        // call can't hang the audit critical path. Timeout, throw,
        // and resolve paths all converge on the framework chain row
        // staying durable — the shadow is best-effort archival.
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
 * @opts
 *   record:  async function (row),       // operator's persistence callback
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
    return;
  }
  if (typeof store !== "object") {
    throw new Error("audit.useStore: store must be an object with a record(row) function, or null to unregister");
  }
  // `{ record: null }` unregisters explicitly (mirrors the null arg path).
  if (store.record === null || store.record === undefined) {
    _externalStore = null;
    return;
  }
  if (typeof store.record !== "function") {
    throw new Error("audit.useStore: store.record must be an async function (row) => void");
  }
  _externalStore = store;
}

// ---- Query ----
//
// Plain-field criteria translate into derived-hash equality where the column
// is sealed. Returns unsealed rows for the auditor's view.
//
// Self-logging (PCI DSS 10.2.3): every read of audit_log is itself recorded
// as an 'audit.read' event before the query runs, so an exfiltration attempt
// is forensically visible. The self-log goes through record() (which never
// re-enters query()), so the only re-entrancy to suppress is a query whose
// own criteria filters for action='audit.read' — those don't auto-log
// (otherwise legitimate audit-of-audits produces a Russell-set spiral, and
// the self-read itself would log a read). That suppression is decided PER
// INVOCATION from the call's own criteria.action, never from shared mutable
// state: a prior design used a module-global `_selfLogging` boolean toggled
// across record()'s await (chain mutex + SQL yield), so a CONCURRENT
// query() racing a mid-flight self-log observed the flag set and silently
// skipped emitting its own audit.read — under-logging reads exactly when
// load is highest. b.audit.query is reachable from concurrent request
// handlers, so the guard MUST be invocation-local.

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
  // Suppress the self-log ONLY for a query whose own criteria targets
  // action='audit.read' (the self-read's shape + audit-of-audits). This is
  // derived from THIS call's criteria — no shared flag — so concurrent
  // reads each emit their own audit.read instead of one racing read
  // swallowing another's self-log.
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

  // order: "asc" (default, chronological) | "desc" (newest-first). A capped
  // query (limit set) returns the FIRST `limit` rows in this order — so a
  // consumer that wants the most RECENT events under a cap (e.g. the daily
  // review) must pass order:"desc", else `limit` keeps the OLDEST and drops the
  // newest events in the window.
  q.orderBy("monotonicCounter", criteria.order === "desc" ? "desc" : "asc");
  if (criteria.limit  != null)  q.limit(criteria.limit);
  if (criteria.offset != null)  q.offset(criteria.offset);

  return q.all();
}

async function _queryCluster(criteria) {
  // Compose the criteria onto a b.sql SELECT with a BARE logical table name
  // (clusterStorage rewrites + placeholderizes). Sealed-field criteria
  // translate to the derived-hash column via cryptoField.lookupHash exactly
  // as before; b.sql quotes every identifier and binds every value.
  var qb = sql.select("audit_log", _sqlOpts());
  if (criteria.from) qb.whereOp("recordedAt", ">=", _toMs(criteria.from));
  if (criteria.to)   qb.whereOp("recordedAt", "<=", _toMs(criteria.to));
  if (criteria.actorUserId) {
    var auh = cryptoField.lookupHash("audit_log", "actorUserId", criteria.actorUserId);
    if (auh) {
      // Dual-read across the keyed-MAC flip so an actor query still returns
      // audit rows written under the legacy salted-sha3 actor digest.
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

// Anchor the current chain tip with a fresh post-quantum signature (the
// configured b.auditSign algorithm — SLH-DSA-SHAKE-256f by default).
// Inserts a row into audit_checkpoints. Updates <dataDir>/audit.tip for
// boot-time rollback detection.
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
async function checkpoint(opts) {
  cluster.requireLeader();
  opts = opts || {};

  // Bind this checkpoint to the database it reads the tip from. checkpoint()
  // spans async boundaries (tip read → sign → insert); a fire-and-forget call
  // launched by db.close() can have its insert resume AFTER the database it
  // read closed and a fresh one opened, anchoring the old tip into the wrong
  // database. Capture the live db generation now and re-check before the write.
  var dbGenAtEntry = db()._dbGeneration();

  var tipReadBuilt = sql.select("audit_log", _sqlOpts())
    .columns(["_id", "monotonicCounter", "rowHash"])
    .orderBy("monotonicCounter", "desc")
    .limit(1)
    .toSql();
  var tip = await safeAsync.withTimeout(
    safeAsync.asyncRetry(function () {
      return clusterStorage.executeOne(tipReadBuilt.sql, tipReadBuilt.params);
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

  // Fail closed if the database changed under us between the tip read and here
  // (e.g. a close()-launched checkpoint resuming after a fresh db opened). The
  // tip we signed belongs to a database that is gone; anchoring it into the
  // current one would forge a checkpoint. Write nothing.
  if (db()._dbGeneration() !== dbGenAtEntry) return null;

  var ckptId = generateToken(TRACE_ID_BYTES);
  var fencingToken = cluster.fencingToken();
  try {
    await _insertCheckpoint(
      [ckptId, createdAt, counter, tip.rowHash, signature, pubFp, fencingToken]
    );
  } catch (e) {
    // Lost the INSERT race to another anchor of this same tip counter: the
    // counter is already anchored (both anchors sign the identical payload).
    // In SINGLE-NODE mode that is purely idempotent — return null like the
    // skipIfUnchanged "already anchored" path and let the winner own the
    // sidecar write below. In CLUSTER mode the duplicate can instead mean a
    // NEWER LEADER anchored this tip while we still hold an OLDER fencingToken,
    // so we must NOT silently swallow it: run the audit-tip fence first, whose
    // fencing-token WHERE guard throws FENCED_OUT when a higher token has been
    // stored — surfacing the leadership-loss step-down instead of a benign
    // null. If the fence passes (a same-node concurrent race), it is idempotent.
    // Any non-duplicate error rethrows.
    if (_isDuplicateCheckpointCounter(e)) {
      if (cluster.isClusterMode()) {
        await _upsertAuditTip(counter, tip.rowHash, String(createdAt), fencingToken);
      }
      return null;
    }
    throw e;
  }

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
    // Flush the anchored rows to durable db.enc BEFORE advancing the durable
    // tip sidecar. Otherwise a crash between this checkpoint and the next
    // encrypt leaves the tip referencing a counter not yet on durable disk;
    // on reboot the rollback detector reads the tip ahead of the restored
    // db.enc and FALSELY refuses boot as a rollback/deletion, even though the
    // chain is intact and only unflushed rows were lost in a normal crash.
    // Rows-before-tip is the correct durability ordering. flushToDisk is a
    // no-op outside encrypted-at-rest mode (the live file is already durable).
    // The tip advances ONLY if the flush succeeded, so the durable tip can
    // never get ahead of the durable rows.
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
    // Resolve the public key the checkpoint was signed under: the current
    // key, or a rotated-out key from the unsealed public-key history. A
    // rotation archives the prior public key, so a checkpoint anchored
    // before the rotation still verifies (no re-signing required). A
    // fingerprint with no recorded key is the genuine break (key rotated
    // away with no history, or a forged fingerprint).
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
  _externalStore = null;
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
      var firstDropAction = null;
      var firstDropMessage = null;
      for (var i = 0; i < batch.length; i++) {
        if (ctx && ctx.isShutdown && ctx.isShutdown()) return;
        try { await record(batch[i]); }
        catch (e) {
          droppedThisBatch += 1;
          // Per-item failure shouldn't drop the whole batch; the
          // signal flows through observability.safeEvent below. The
          // prior per-drop log.error was noise: boot-phase
          // audit.emit() racing db.init() fires dozens of these
          // during normal startup, and operator dashboards
          // alert-routing on the "error" level read it as a real
          // failure. The aggregate observability metric is the
          // documented signal channel; capture the first drop's
          // action + message in its metadata so operators alerting
          // on `system.audit.chain_write_dropped` get a
          // representative sample without per-line log spam.
          if (firstDropAction === null) {
            firstDropAction = (batch[i] && batch[i].action) || null;
            firstDropMessage = (e && e.message) ? e.message : String(e);
          }
        }
      }
      // Surface chain-write integrity failures via observability so
      // operators alerting on rate-drop see something. The audit
      // chain itself can't carry the signal — the chain is what's
      // broken — so observability is the only sink left.
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
  // Back-compat: a bare boolean/undefined is the gate; an object carries the
  // gate plus the sink axis.
  var cfg = (opts && typeof opts === "object") ? opts : { audit: opts };
  var on = cfg.audit !== false;
  return function (action, outcome, metadata, extra) {
    if (!on) return;
    // module.exports.safeEmit (late-bound) so a test that stubs b.audit.safeEmit
    // still observes the emit; cfg.sink routes to an operator-supplied audit
    // object (no-op if it lacks safeEmit, matching the hand-rolled sink guard).
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
  var columnRaw    = opts.column || "actorUserId";
  // Default resolves through frameworkSchema.tableName so the configurable
  // framework-table prefix flows into the operator-applied trigger DDL.
  var tableNameRaw = opts.tableName || frameworkSchema.tableName("audit_log");
  var allowRoles   = Array.isArray(opts.allowRoles) ? opts.allowRoles : [];
  // Trigger function + trigger object NAMES (not framework tables — they have
  // no LOCAL_TO_EXTERNAL mapping and carry no prefix). assertSegregation
  // looks them up under these exact names.
  var fnNameRaw    = "_blamejs_audit_actor_binding_check";   // allow:hand-rolled-sql
  var trigNameRaw  = "_blamejs_audit_actor_binding_trig";    // allow:hand-rolled-sql
  // Quote-and-validate every identifier through safeSql.quoteIdentifier
  // so operator-supplied opts.column / opts.tableName / opts.roleMappingFn
  // can't reach raw concatenation. PostgreSQL + SQLite both use the
  // double-quote dialect.
  var qColumn   = safeSql.quoteIdentifier(columnRaw, "postgres");
  var qTable    = safeSql.quoteIdentifier(tableNameRaw, "postgres");
  var qFn       = safeSql.quoteIdentifier(fnNameRaw, "postgres");
  var qTrig     = safeSql.quoteIdentifier(trigNameRaw, "postgres");
  var qRoleMapFn = opts.roleMappingFn
    ? safeSql.quoteIdentifier(opts.roleMappingFn, "postgres")
    : null;
  var allowList = allowRoles.length === 0 ? "" :
    "  IF current_user IN (" +
    allowRoles.map(function (r) { return "'" + r.replace(/'/g, "''") + "'"; }).join(", ") +
    ") THEN RETURN NEW; END IF;\n";
  var roleMatch = qRoleMapFn
    ? "  IF " + qRoleMapFn + "(NEW." + qColumn + ") IS DISTINCT FROM current_user THEN\n"
    : "  IF NEW." + qColumn + " IS DISTINCT FROM current_user THEN\n";
  // Operator-applied plpgsql trigger DDL — a CREATE FUNCTION body + RAISE
  // EXCEPTION + CREATE/DROP TRIGGER, none of which b.sql's verb builders
  // model. Every identifier is quoted through safeSql.quoteIdentifier above;
  // the table name resolves via frameworkSchema.tableName, so the prefix is
  // honored. allow:hand-rolled-sql — this is migration-script generation,
  // not a framework-state DML path.
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
  // Trigger / function object NAMES (not framework tables — they have no
  // LOCAL_TO_EXTERNAL mapping and carry no prefix). They must match the
  // names generateActorBindingTriggerSql emits.
  var fnName = opts.functionName || "_blamejs_audit_actor_binding_check";    // allow:hand-rolled-sql
  var trigName = opts.triggerName || "_blamejs_audit_actor_binding_trig";    // allow:hand-rolled-sql
  // Operator-DB system-catalog introspection (Postgres pg_proc / pg_trigger,
  // $N-native, against the operator-supplied db.query) — not a framework
  // table, so b.sql's verb builders don't apply.
  var fnRes = await db.query(
    "SELECT 1 FROM pg_proc WHERE proname = $1 LIMIT 1", [fnName]             // allow:hand-rolled-sql
  );
  var fnPresent = !!(fnRes && fnRes.rows && fnRes.rows.length > 0);
  var trigRes = await db.query(
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

// applyPosture — cascade hook. b.compliance.set(posture)
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
  _isDuplicateCheckpointCounter: _isDuplicateCheckpointCounter,   // test seam: cross-backend dup-counter recognition
};
