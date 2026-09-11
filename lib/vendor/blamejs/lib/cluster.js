// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.cluster
 * @featured true
 * @nav    Production
 * @title  Cluster
 *
 * @intro
 *   Opt-in active/active leader election with fencing-tokenized writes.
 *   An external database is required: the framework's default provider
 *   stores the leader-election row, the per-chain tip rows, and the
 *   shared vault-key fingerprint in the same backend so every node sees
 *   one source of truth. When `b.cluster.init` is never called, the
 *   local process behaves as a permanent single leader: `isLeader()`
 *   always returns true, `fencingToken()` returns 0, no heartbeat runs,
 *   no DB is touched. Single-node deployments pay zero overhead.
 *
 *   When init IS called, the framework starts a heartbeat that renews
 *   the leader lease via the configured provider. On lease loss (network
 *   partition, takeover, lease expiry) the node transitions to follower
 *   and write-side framework primitives throw `NotLeaderError`. The
 *   audit + consent chains carry a fencing token alongside every row so
 *   a stale leader cannot silently extend the chain after losing its
 *   lease — the audit-tip CHECK constraint refuses the stale token at
 *   the database layer. The application-level `requireLeader()` gate is
 *   an early-rejection optimization; the DB constraint is canonical.
 *
 *   Threat model:
 *     - Two leaders writing simultaneously — prevented by fencing
 *       tokens carried into the audit-tip row.
 *     - Follower receiving a write — rejected at the framework boundary
 *       via NotLeaderError. Operators front the cluster with a load
 *       balancer that routes write paths to the current leader; the
 *       discovery handler exposes which node holds the lease.
 *     - External-db unreachable — heartbeat fails; after `leaseTtl` no
 *       leader exists and writes fail closed. When the DB recovers,
 *       election resumes.
 *     - Vault-key drift — every node fingerprints its vault keys on
 *       boot and compares against a canonical fingerprint stored in
 *       the cluster-state row. A node holding a different key refuses
 *       to participate, preventing silent sealed-column corruption.
 *
 * @card
 *   Opt-in active/active leader election with fencing-tokenized writes.
 */
var C = require("./constants");
var clusterProviderDb = require("./cluster-provider-db");
var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var { boot } = require("./log");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var { FrameworkError, ClusterError } = require("./framework-error");

// The external-DB schema quotes every column identifier, so Postgres
// stores them case-preserving. The boot-time chain-tip + vault-key-
// consistency statements compose through b.sql, which quotes every
// identifier by construction (double-quote on Postgres / SQLite, backtick
// on MySQL) so an unquoted fold-to-lowercase reference can't miss the
// column.

// Lazy: vault → db → cluster forms a load-time chain, and external-db is
// loaded before its init has run; both are safe to call once cluster
// reaches runtime, but eager require here would deadlock the load order.
var externalDb = lazyRequire(function () { return require("./external-db"); });
var vault = lazyRequire(function () { return require("./vault"); });
// b.sql builder + the `?`->`$N` placeholderizer + the framework-table
// name resolver. clusterStorage requires cluster, so these are lazy to
// stay clear of the load cycle; resolved at runtime when the boot-time
// rollback / vault-key-consistency checks run.
var sql = lazyRequire(function () { return require("./sql"); });
var clusterStorage = lazyRequire(function () { return require("./cluster-storage"); });
var frameworkSchema = lazyRequire(function () { return require("./framework-schema"); });

function _bDialect() {
  return configuredDialect === "mysql" ? "mysql"
       : configuredDialect === "sqlite" ? "sqlite" : "postgres";
}

function _runClusterQuery(builder) {
  var built = builder.toSql();
  return externalDb().query(
    clusterStorage().placeholderize(built.sql, configuredDialect),
    built.params,
    { backend: configuredExternalDbBackend }
  );
}

function _isMissingTableError(e) {
  if (!e) return false;
  if (clusterStorage().missingRelationCode(e)) return true;
  var msg = e.message || "";
  return /no such table|does not exist|doesn't exist|relation .* does not exist/i.test(msg);
}

var DEFAULT_LEASE_TTL    = C.TIME.seconds(30);
var DEFAULT_HEARTBEAT    = C.TIME.seconds(10);
var MIN_LEASE_TTL        = C.TIME.seconds(10);
var MIN_HEARTBEAT        = C.TIME.seconds(1);

var initialized      = false;
var terminated       = false;
var nodeId           = null;
var role             = null;
var provider         = null;
var lease            = null;
var heartbeatTimer   = null;
var heartbeatMs      = null;
var leaseTtlMs       = null;
var transitionHandlers = [];
var configuredExternalDbBackend = null;
var configuredDialect            = null;
var configuredEndpoint          = null;
var configuredAcceptRotation     = false;
var configuredExpectedVaultKeyFp = null;

var log = boot("cluster");

class NotLeaderError extends FrameworkError {
  constructor(message) {
    super(message || "not leader: write rejected by cluster gate", "cluster/not-leader");
    this.name = "NotLeaderError";
    this.statusCode = 503;
    this.isClusterError = true;
    this.isNotLeaderError = true;
  }
}

var _err = ClusterError.factory;

function _emitTransition(kind, detail) {
  var event = Object.assign({ kind: kind, nodeId: nodeId, at: Date.now() }, detail || {});
  for (var i = 0; i < transitionHandlers.length; i++) {
    try { transitionHandlers[i](event); }
    catch (e) { log.error("transition handler threw: " + e.message); }
  }
}

/**
 * @primitive b.cluster.init
 * @signature b.cluster.init(opts)
 * @since     0.4.0
 * @status    stable
 * @compliance soc2, dora
 * @related   b.cluster.shutdown, b.cluster.requireLeader, b.cluster.currentLeader
 *
 * One-time cluster bootstrap. Configures the leader-election provider,
 * validates the operator-supplied endpoint, runs boot-time rollback
 * detection on the audit + consent chains, fingerprints this node's
 * vault keys against the canonical cluster-state row, then starts the
 * heartbeat that acquires and renews the leader lease. Throws on
 * second invocation, on missing nodeId, on a leaseTtl below 10s, on a
 * heartbeat that doesn't fit comfortably inside the lease, on a role
 * outside `leader` / `follower`, and on a chain or vault-key mismatch
 * that would let this node corrupt cluster state.
 *
 * After a vault-key rotation (`b.vault.rotate`) the public-key
 * fingerprint changes, so the canonical cluster-state row no longer
 * matches and every node would otherwise refuse boot with
 * `cluster/vault-key-drift`. Pass `acceptVaultKeyRotation: true` to declare the
 * change legitimate: the node advances the canonical fingerprint and
 * bumps a rotation epoch instead of refusing. `expectedVaultKeyFp`
 * narrows the acceptance to a single blessed fingerprint so a typo'd /
 * stale key file is still caught. The strict cross-node drift refusal
 * stays in force whenever the rotation is NOT declared.
 *
 * @opts
 *   nodeId:             string,            // required; stable identity
 *   role:               "leader"|"follower",
 *   leaseTtl:           number,            // ms; default 30000, min 10000
 *   heartbeatInterval:  number,            // ms; default 10000, min 1000
 *   endpoint:           string,            // routable URL of THIS node
 *   allowedProtocols:   number,            // safeUrl.ALLOW_HTTP_TLS by default
 *   provider:           object,            // custom election provider
 *   externalDbBackend:  string,            // name of a backend registered via
 *                                          // b.externalDb.init({ backends });
 *                                          // required when no custom provider
 *   dialect:            "postgres"|"sqlite"|"mysql",
 *   acceptVaultKeyRotation: boolean,        // adopt a rotated vault-key
 *                                          // fingerprint instead of
 *                                          // refusing boot on mismatch
 *   expectedVaultKeyFp: string,            // optional; bless ONLY this
 *                                          // post-rotation fingerprint
 *   onTransition:       function (event),
 *
 * @example
 *   await b.cluster.init({
 *     nodeId:            "api-01",
 *     role:              "leader",
 *     leaseTtl:          30000,
 *     heartbeatInterval: 10000,
 *     endpoint:          "https://api-01.example.internal:8443",
 *     externalDbBackend: "primary",   // a backend name from externalDb.init
 *     dialect:           "postgres",
 *     onTransition:      function (event) {
 *       // event.kind ∈ { "lease-acquired", "lease-lost", "lease-released" }
 *       console.log("cluster transition:", event.kind, event.fencingToken);
 *     },
 *   });
 *   // → undefined (heartbeat now running)
 */
async function init(opts) {
  if (initialized) {
    throw _err("cluster/already-initialized", "cluster.init() called twice", true);
  }
  opts = opts || {};
  if (!opts.nodeId) {
    throw _err("cluster/invalid-config", "cluster.init({ nodeId }) is required", true);
  }
  nodeId = String(opts.nodeId);

  leaseTtlMs = opts.leaseTtl != null ? Number(opts.leaseTtl) : DEFAULT_LEASE_TTL;
  if (leaseTtlMs < MIN_LEASE_TTL) {
    throw _err("cluster/invalid-ttl",
      "leaseTtl must be >= " + MIN_LEASE_TTL + "ms (got " + leaseTtlMs + ")",
      true);
  }
  heartbeatMs = opts.heartbeatInterval != null
    ? Number(opts.heartbeatInterval)
    : DEFAULT_HEARTBEAT;
  if (heartbeatMs < MIN_HEARTBEAT) {
    throw _err("cluster/invalid-heartbeat",
      "heartbeatInterval must be >= " + MIN_HEARTBEAT + "ms (got " + heartbeatMs + ")",
      true);
  }
  if (heartbeatMs >= leaseTtlMs) {
    throw _err("cluster/invalid-heartbeat",
      "heartbeatInterval must be < leaseTtl (got heartbeat=" + heartbeatMs +
      ", leaseTtl=" + leaseTtlMs + "); recommend ~1/3 of leaseTtl",
      true);
  }

  role = (opts.role || "leader").toLowerCase();
  if (role !== "leader" && role !== "follower") {
    throw _err("cluster/invalid-role", "role must be 'leader' or 'follower'", true);
  }

  if (opts.endpoint != null) {
    try {
      safeUrl.parse(opts.endpoint, {
        allowedProtocols: opts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
        errorClass:       ClusterError,
      });
    } catch (e) {
      throw _err("cluster/invalid-endpoint",
        "cluster.init({ endpoint }) rejected: " + e.message, true);
    }
    configuredEndpoint = String(opts.endpoint);
  } else {
    configuredEndpoint = null;
  }

  validateOpts.optionalBoolean(opts.acceptVaultKeyRotation,
    "cluster.init({ acceptVaultKeyRotation })", ClusterError, "cluster/invalid-config");
  configuredAcceptRotation = opts.acceptVaultKeyRotation === true;
  if (opts.expectedVaultKeyFp !== undefined) {
    if (typeof opts.expectedVaultKeyFp !== "string" ||
        !/^[0-9a-f]{128}$/.test(opts.expectedVaultKeyFp)) {
      throw _err("cluster/invalid-config",
        "cluster.init({ expectedVaultKeyFp }) must be a 128-char " +
        "lowercase-hex SHA3-512 fingerprint (b.vault rotation output)", true);
    }
    if (!configuredAcceptRotation) {
      throw _err("cluster/invalid-config",
        "cluster.init({ expectedVaultKeyFp }) requires " +
        "acceptVaultKeyRotation: true — blessing a fingerprint without " +
        "enabling adoption has no effect", true);
    }
    configuredExpectedVaultKeyFp = opts.expectedVaultKeyFp;
  } else {
    configuredExpectedVaultKeyFp = null;
  }

  if (typeof opts.onTransition === "function") {
    transitionHandlers.push(opts.onTransition);
  }

  if (opts.provider) {
    provider = opts.provider;
    configuredExternalDbBackend = opts.externalDbBackend || null;
    configuredDialect = (opts.dialect || "postgres").toLowerCase();
  } else {
    if (!opts.externalDbBackend) {
      throw _err("cluster/invalid-config",
        "cluster.init requires either { provider } or { externalDbBackend }", true);
    }
    provider = clusterProviderDb.create({
      externalDbBackend: opts.externalDbBackend,
      dialect:           opts.dialect,
    });
    configuredExternalDbBackend = opts.externalDbBackend;
    configuredDialect = (opts.dialect || "postgres").toLowerCase();
  }

  if (typeof provider.ensureSchema === "function") {
    await provider.ensureSchema();
  }

  initialized = true;
  log("initialized as nodeId='" + nodeId + "', role='" + role + "'");

  if (role === "leader") {
    await _tryAcquire();
  }

  if (configuredExternalDbBackend) {
    await _checkChainTipRollback("audit",
      frameworkSchema().tableName("audit_log"),                                   // allow:hand-rolled-sql — logical-name reference
      frameworkSchema().tableName("_blamejs_audit_tip"));                         // allow:hand-rolled-sql — logical-name reference
    await _checkChainTipRollback("consent",
      frameworkSchema().tableName("consent_log"),                                 // allow:hand-rolled-sql — logical-name reference
      frameworkSchema().tableName("_blamejs_consent_tip"));                       // allow:hand-rolled-sql — logical-name reference
    await _checkVaultKeyConsistency();
  }

  heartbeatTimer = safeAsync.repeating(_heartbeat, heartbeatMs, { name: "cluster-heartbeat" });
}

async function _checkChainTipRollback(chainName, logTable, tipTable) {
  var tipRows;
  try {
    tipRows = await _runClusterQuery(sql().select(tipTable, { dialect: _bDialect() })
      .columns(["atMonotonicCounter", "rowHash"]).where("scope", chainName));
  } catch (e) {
    if (_isMissingTableError(e)) {
      log(chainName + "-tip table not present — skipping rollback check (cluster gates-only mode)");
      return;
    }
    throw e;
  }
  if (!tipRows.rows || tipRows.rows.length === 0) {
    log("no " + chainName + "-tip row — skipping rollback check (first cluster boot or operator-cleared)");
    return;
  }
  var tip = tipRows.rows[0];
  var tipCounter = Number(tip.atMonotonicCounter);
  var tipHash = tip.rowHash;

  var currentRows = await _runClusterQuery(sql().select(logTable, { dialect: _bDialect() })
    .max("monotonicCounter", "m"));
  var currentMax = (currentRows.rows && currentRows.rows[0] && currentRows.rows[0].m)
    ? Number(currentRows.rows[0].m)
    : 0;

  if (currentMax < tipCounter) {
    throw _err("cluster/rollback-detected",
      "FATAL: cluster-mode " + chainName + "-log rollback detected. " +
      chainName + "-tip counter: " + tipCounter +
      "; current external-db max: " + currentMax +
      ". Either external-db was restored from an older snapshot, or " +
      logTable + " rows have been deleted. Investigate before continuing.",
      true);
  }

  if (tipHash) {
    var hashRows = await _runClusterQuery(sql().select(logTable, { dialect: _bDialect() })
      .columns(["rowHash"]).where("monotonicCounter", tipCounter));
    if (hashRows.rows && hashRows.rows.length > 0) {
      var rowAtTip = hashRows.rows[0].rowHash;
      if (rowAtTip !== tipHash) {
        throw _err("cluster/rollback-detected",
          "FATAL: cluster-mode " + chainName + "-log rollback detected (row-hash mismatch). " +
          chainName + "-tip counter: " + tipCounter +
          "; " + chainName + "-tip rowHash: " + tipHash +
          "; current row rowHash: " + rowAtTip +
          ". The row at the recorded tip counter has a different hash — " +
          "indicates row substitution at the chain head. Investigate before continuing.",
          true);
      }
    }
  }
  log("cluster " + chainName + "-tip rollback check ok (tip counter " + tipCounter +
    ", current " + currentMax + ")");
}

function _vaultKeyFingerprint() {
  var keysJson;
  try {
    keysJson = vault().getKeysJson();
  } catch (e) {
    if (/vault.init\(\) must be awaited/.test((e && e.message) || "")) {
      return null;
    }
    throw e;
  }
  var keys = safeJson.parse(keysJson);
  if (!keys || !keys.publicKey || !keys.ecPublicKey) return null;
  return bCrypto.sha3Hash("blamejs/cluster-state/v1\n" +
                         keys.publicKey + "\n" +
                         keys.ecPublicKey);
}

async function _ensureRotationEpochColumn() {
  var stateTable = frameworkSchema().tableName("_blamejs_cluster_state");           // allow:hand-rolled-sql — logical-name reference
  try {
    var alter = sql().alterTable(stateTable,
      { addColumn: { name: "rotationEpoch", type: "BIGINT" } },
      { dialect: _bDialect() }).sql;
    await externalDb().query(clusterStorage().placeholderize(alter, configuredDialect), [],
      { backend: configuredExternalDbBackend });
  } catch (_e) { /* column already exists (or table absent — caught upstream) */ }
}

async function _checkVaultKeyConsistency() {
  var localFp = _vaultKeyFingerprint();
  if (localFp === null) {
    log("vault not initialized — skipping vault-key consistency check (cluster gates-only mode)");
    return;
  }
  var nowMs = Date.now();
  var stateTable = frameworkSchema().tableName("_blamejs_cluster_state");           // allow:hand-rolled-sql — logical-name reference

  try {
    await _runClusterQuery(sql().upsert(stateTable, { dialect: _bDialect() })
      .values({ scope: "state", vaultKeyFp: localFp, recordedAt: nowMs, recordedByNode: nodeId })
      .onConflict(["scope"]).doNothing());
  } catch (e) {
    if (_isMissingTableError(e)) {
      log("cluster-state table not present — skipping vault-key consistency check (custom provider)");
      return;
    }
    throw e;
  }

  await _ensureRotationEpochColumn();

  var rows = await _runClusterQuery(sql().select(stateTable, { dialect: _bDialect() })
    .columns(["vaultKeyFp", "recordedByNode", "recordedAt", "rotationEpoch"])
    .where("scope", "state"));
  if (!rows.rows || rows.rows.length === 0) {
    throw _err("cluster/cluster-state-missing",
      "FATAL: cluster-state row missing immediately after INSERT — " +
      "external-db may not be honoring writes. Refusing boot.",
      true);
  }
  var canonical = rows.rows[0];
  var fpPrefix = C.BYTES.bytes(16);
  if (canonical.vaultKeyFp !== localFp) {
    if (!configuredAcceptRotation) {
      throw _err("cluster/vault-key-drift",
        "FATAL: vault-key drift detected. " +
        "local node: " + nodeId +
        "; local fingerprint: " + localFp.slice(0, fpPrefix) + "…" +
        "; canonical recorded by: " + canonical.recordedByNode +
        "; canonical fingerprint: " + canonical.vaultKeyFp.slice(0, fpPrefix) + "…" +
        ". This node holds a DIFFERENT vault key than the rest of the " +
        "cluster. Sealed-column writes from this node would be unreadable " +
        "by the others (and vice versa). If the key changed via " +
        "b.vault.rotate, re-init with acceptVaultKeyRotation: true to " +
        "advance the cluster's recorded fingerprint; otherwise restore the " +
        "same vault key file before booting this node into the cluster.",
        true);
    }
    if (configuredExpectedVaultKeyFp && configuredExpectedVaultKeyFp !== localFp) {
      throw _err("cluster/vault-key-rotation-mismatch",
        "FATAL: acceptVaultKeyRotation is set but this node's vault-key " +
        "fingerprint does not match the blessed expectedVaultKeyFp. " +
        "local node: " + nodeId +
        "; local fingerprint: " + localFp.slice(0, fpPrefix) + "…" +
        "; expected fingerprint: " + configuredExpectedVaultKeyFp.slice(0, fpPrefix) + "…" +
        ". This node is NOT holding the rotated key the operator approved. " +
        "Restore the post-rotation vault key file (or correct " +
        "expectedVaultKeyFp) before booting this node into the cluster.",
        true);
    }
    var priorEpoch = (canonical.rotationEpoch != null) ? Number(canonical.rotationEpoch) : 0;
    if (!isFinite(priorEpoch) || priorEpoch < 0) priorEpoch = 0;
    var nextEpoch = priorEpoch + 1;
    await _runClusterQuery(sql().update(stateTable, { dialect: _bDialect() })
      .set({
        vaultKeyFp: localFp, recordedAt: nowMs,
        recordedByNode: nodeId, rotationEpoch: nextEpoch,
      })
      .where("scope", "state").where("vaultKeyFp", canonical.vaultKeyFp));
    var after = await _runClusterQuery(sql().select(stateTable, { dialect: _bDialect() })
      .columns(["vaultKeyFp", "recordedByNode", "rotationEpoch"])
      .where("scope", "state"));
    var post = (after.rows && after.rows[0]) || canonical;
    if (post.vaultKeyFp !== localFp) {
      throw _err("cluster/vault-key-drift",
        "FATAL: vault-key drift detected after rotation-accept. " +
        "local node: " + nodeId +
        "; local fingerprint: " + localFp.slice(0, fpPrefix) + "…" +
        "; canonical fingerprint: " + post.vaultKeyFp.slice(0, fpPrefix) + "…" +
        ". A concurrent node advanced the cluster to a DIFFERENT key than " +
        "this node holds — the declared rotation does not cover this " +
        "fingerprint. Restore the agreed post-rotation vault key file.",
        true);
    }
    log("cluster vault-key rotation accepted (fingerprint " +
      localFp.slice(0, fpPrefix) + "… epoch " +
      (post.rotationEpoch != null ? Number(post.rotationEpoch) : nextEpoch) +
      ", recorded by " + post.recordedByNode + ")");
    return;
  }
  log("cluster vault-key consistency ok (fingerprint " +
    localFp.slice(0, fpPrefix) + "… recorded by " + canonical.recordedByNode +
    (canonical.rotationEpoch != null ? ", epoch " + Number(canonical.rotationEpoch) : "") + ")");
}

async function _tryAcquire() {
  if (role !== "leader") return;
  try {
    var got = await provider.acquireLease(nodeId, leaseTtlMs, {
      endpoint: configuredEndpoint,
    });
    if (got) {
      var wasLeader = !!lease;
      lease = got;
      if (!wasLeader) {
        log("acquired lease — fencingToken=" + lease.fencingToken);
        _emitTransition("lease-acquired", { fencingToken: lease.fencingToken });
      }
    }
  } catch (e) {
    log.error("acquire failed: " + e.message);
  }
}

async function _heartbeat() {
  if (!initialized) return;
  if (!lease) {
    var jitterMs = Math.floor(Math.random() * (heartbeatMs * 0.4));            // allow:math-random-noncrypto-jitter-sampling — heartbeat jitter, not security-bearing
    if (jitterMs > 0) {
      await safeAsync.sleep(jitterMs);
    }
    if (!initialized) return;
    await _tryAcquire();
    return;
  }
  try {
    lease = await provider.renewLease(lease, { endpoint: configuredEndpoint });
  } catch (e) {
    if (e.code === "cluster-provider-db/lease-lost") {
      log.error("lease lost: " + e.message);
      var lostToken = lease ? lease.fencingToken : null;
      lease = null;
      _emitTransition("lease-lost", { fencingToken: lostToken });
    } else {
      log.error("renew failed transiently: " + e.message);
    }
  }
}

/**
 * @primitive b.cluster.isLeader
 * @signature b.cluster.isLeader()
 * @since     0.4.0
 * @status    stable
 * @related   b.cluster.requireLeader, b.cluster.fencingToken, b.cluster.currentLeader
 *
 * Synchronous leader check. Returns `true` when this node currently
 * holds a non-expired lease, OR when `b.cluster.init` was never called
 * (single-node permanent-leader fallback). Returns `false` after a
 * graceful `shutdown()`, after lease loss, or while a follower is
 * waiting for its first lease. Cheap; safe to call on every request to
 * branch leader-only work (scheduled jobs, cache warmers, write-side
 * sweeps).
 *
 * @example
 *   if (b.cluster.isLeader()) {
 *     // Run scheduled tick on the leader only.
 *     await runHourlyRollup();
 *   }
 *   // → undefined
 */
function isLeader() {
  if (terminated) return false;
  if (!initialized) return true;
  return !!lease && Date.now() < lease.expiresAt;
}

/**
 * @primitive b.cluster.isClusterMode
 * @signature b.cluster.isClusterMode()
 * @since     0.4.0
 * @status    stable
 * @related   b.cluster.init, b.cluster.externalDbBackend
 *
 * Returns `true` when `b.cluster.init` has been called AND an
 * externalDbBackend is wired — i.e. framework state (audit, consent,
 * fencing-tokenized writes) should route to the shared external DB.
 * Returns `false` in single-node fallback or when a custom provider
 * was supplied without an externalDbBackend; in that case the operator
 * owns write-dispatch.
 *
 * @example
 *   if (b.cluster.isClusterMode()) {
 *     console.log("framework state lives on", b.cluster.externalDbBackend());
 *   }
 *   // → undefined
 */
function isClusterMode() {
  return initialized && !!configuredExternalDbBackend;
}

/**
 * @primitive b.cluster.externalDbBackend
 * @signature b.cluster.externalDbBackend()
 * @since     0.4.0
 * @status    stable
 * @related   b.cluster.init, b.cluster.dialect, b.cluster.isClusterMode
 *
 * Returns the externalDb backend handle wired at init, or `null` in
 * single-node fallback / when a custom provider was supplied without
 * one. Internal write-dispatch code (audit, consent, fencing-tokenized
 * primitives) calls this to route framework state to the shared
 * backend; operator code rarely needs it directly.
 *
 * @example
 *   var backend = b.cluster.externalDbBackend();
 *   if (backend) {
 *     // Framework state lands on the shared cluster DB.
 *   }
 *   // → undefined
 */
function externalDbBackend() {
  return configuredExternalDbBackend;
}

/**
 * @primitive b.cluster.dialect
 * @signature b.cluster.dialect()
 * @since     0.4.0
 * @status    stable
 * @related   b.cluster.externalDbBackend, b.cluster.init
 *
 * Returns the SQL dialect string wired at init — `"postgres"`,
 * `"sqlite"`, or `"mysql"`. Used by write-dispatch code that emits raw
 * placeholder syntax (`$1` vs `?`) against the shared backend.
 *
 * @example
 *   var ph = b.cluster.dialect() === "postgres" ? "$1" : "?";
 *   // → undefined
 */
function dialect() {
  return configuredDialect;
}

/**
 * @primitive b.cluster.currentNodeId
 * @signature b.cluster.currentNodeId()
 * @since     0.4.0
 * @status    stable
 * @related   b.cluster.endpoint, b.cluster.currentLeader
 *
 * Returns this node's configured nodeId, or `"single-node-local"` in
 * the permanent-leader fallback when init was never called. Stable
 * across the lifetime of the process — operators use it to tag audit
 * metadata and observability events with the node identity.
 *
 * @example
 *   b.audit.safeEmit({
 *     action:   "system.bootstrapped",
 *     actor:    { systemNode: b.cluster.currentNodeId() },
 *     outcome:  "success",
 *   });
 *   // → undefined
 */
function currentNodeId() {
  return initialized ? nodeId : "single-node-local";
}

/**
 * @primitive b.cluster.endpoint
 * @signature b.cluster.endpoint()
 * @since     0.7.30
 * @status    stable
 * @related   b.cluster.discoveryHandler, b.cluster.currentLeader
 *
 * This node's routable endpoint URL — the value supplied as
 * `opts.endpoint` to `b.cluster.init`. Returns `null` when not
 * configured or in single-node fallback. External observers wanting
 * to learn the leader's URL should call `discoveryHandler()` /
 * `currentLeader()` instead; this getter is for the local node's own
 * self-identity.
 *
 * @example
 *   var here = b.cluster.endpoint();
 *   // → "https://api-01.example.internal:8443"
 */
function endpoint() {
  return configuredEndpoint;
}

/**
 * @primitive b.cluster.fencingToken
 * @signature b.cluster.fencingToken()
 * @since     0.4.0
 * @status    stable
 * @compliance soc2
 * @related   b.cluster.isLeader, b.cluster.currentLeader
 *
 * Current monotonic fencing token for this node's lease. Increments
 * with every successful acquisition; a stale leader's token is
 * strictly less than the new leader's, and the audit-tip CHECK
 * constraint refuses inserts carrying a stale token. Returns `0` when
 * no lease is held (follower, between leases, single-node fallback).
 *
 * @example
 *   var token = b.cluster.fencingToken();
 *   // → 42
 */
function fencingToken() {
  if (!initialized) return 0;
  return lease ? lease.fencingToken : 0;
}

/**
 * @primitive b.cluster.requireLeader
 * @signature b.cluster.requireLeader()
 * @since     0.4.0
 * @status    stable
 * @related   b.cluster.isLeader, b.cluster.currentLeader
 *
 * Throws `NotLeaderError` (statusCode 503) when this node is not the
 * current leader. Use at the top of write-side handlers so a follower
 * receiving a misrouted request rejects fast instead of producing a
 * downstream fencing-token rejection. Single-node deployments where
 * init was never called short-circuit through `isLeader() === true`
 * and never throw.
 *
 * @example
 *   try {
 *     b.cluster.requireLeader();
 *     await runHourlyRollup();
 *   } catch (e) {
 *     if (e.isNotLeaderError) {
 *       // Operator's load balancer should retry on the leader.
 *       res.writeHead(503).end();
 *       return;
 *     }
 *     throw e;
 *   }
 *   // → undefined
 */
function requireLeader() {
  if (!isLeader()) {
    throw new NotLeaderError(
      "node '" + currentNodeId() + "' is not currently leader" +
      (initialized ? "" : " (cluster not initialized)")
    );
  }
}

/**
 * @primitive b.cluster.currentLeader
 * @signature b.cluster.currentLeader()
 * @since     0.4.0
 * @status    stable
 * @related   b.cluster.discoveryHandler, b.cluster.endpoint, b.cluster.isLeader
 *
 * Async snapshot of the cluster's current leader. Returns
 * `{ nodeId, leaseExpiresAt, fencingToken, endpoint }` when a leader
 * holds a non-expired lease, or `null` when no node currently holds
 * the lease (election in progress, DB unreachable, lease expired).
 * In single-node fallback, returns the synthetic
 * `{ nodeId: "single-node-local", leaseExpiresAt: Infinity, ... }`
 * record so callers don't need a second branch.
 *
 * @example
 *   var leader = await b.cluster.currentLeader();
 *   if (leader && leader.endpoint) {
 *     console.log("forward write to", leader.endpoint);
 *   }
 *   // → undefined
 */
async function currentLeader() {
  if (!initialized) {
    return {
      nodeId:         "single-node-local",
      leaseExpiresAt: Infinity,
      fencingToken:   0,
      endpoint:       null,
    };
  }
  return await provider.currentLeader();
}

/**
 * @primitive b.cluster.discoveryHandler
 * @signature b.cluster.discoveryHandler()
 * @since     0.7.30
 * @status    stable
 * @related   b.cluster.currentLeader, b.cluster.endpoint
 *
 * Returns an HTTP `(req, res)` handler suitable for mounting on any
 * route (e.g. `/cluster/leader`). Replies 200 JSON with
 * `{ leader, self }` when a leader holds the lease, 503 JSON with
 * `{ leader: null, self }` when no leader exists or the DB is
 * unreachable. Method-agnostic; emits `Cache-Control: no-store` so
 * caching proxies don't pin a stale leader during a takeover. No auth
 * — intended for infrastructure inside the trust boundary (load
 * balancers, healthchecks, dashboards). Operators exposing the
 * endpoint externally should layer auth via their own middleware.
 *
 * @example
 *   var leaderProbe = b.cluster.discoveryHandler();
 *   server.on("request", function (req, res) {
 *     if (req.url === "/cluster/leader") return leaderProbe(req, res);
 *     // ... rest of routing
 *   });
 *   // → undefined
 */
function discoveryHandler() {
  return async function (req, res) {
    var selfInfo = {
      nodeId:   currentNodeId(),
      endpoint: configuredEndpoint,
      isLeader: isLeader(),
    };
    var body;
    var status;
    try {
      var leader = await currentLeader();
      if (leader && leader.nodeId && leader.nodeId !== "single-node-local") {
        body = { leader: leader, self: selfInfo };
        status = 200;
      } else if (leader && leader.nodeId === "single-node-local") {
        body = { leader: leader, self: selfInfo };
        status = 200;
      } else {
        body = { leader: null, self: selfInfo };
        status = 503;
      }
    } catch (_e) {
      body = { leader: null, self: selfInfo, error: "leader lookup unavailable" };
      status = 503;
    }
    var json = JSON.stringify(body);
    res.writeHead(status, {
      "Content-Type":   "application/json; charset=utf-8",
      "Content-Length": Buffer.byteLength(json),
      "Cache-Control":  "no-store",
    });
    res.end(json);
  };
}

/**
 * @primitive b.cluster.onTransition
 * @signature b.cluster.onTransition(handler)
 * @since     0.4.0
 * @status    stable
 * @related   b.cluster.init, b.cluster.shutdown
 *
 * Register a callback fired on every cluster role transition. Event
 * shape: `{ kind, nodeId, at, fencingToken? }` where `kind` is one of
 * `"lease-acquired"`, `"lease-lost"`, `"lease-released"`. Multiple
 * handlers can be registered; each runs in registration order and
 * a throwing handler is logged but doesn't break the chain. Throws
 * synchronously when `handler` is not a function.
 *
 * @example
 *   b.cluster.onTransition(function (event) {
 *     b.audit.safeEmit({
 *       action:   "system.cluster_transition",
 *       actor:    { systemNode: event.nodeId },
 *       outcome:  "success",
 *       metadata: { kind: event.kind, fencingToken: event.fencingToken },
 *     });
 *   });
 *   // → undefined
 */
function onTransition(handler) {
  if (typeof handler !== "function") {
    throw _err("cluster/invalid-handler", "onTransition expects a function", true);
  }
  transitionHandlers.push(handler);
}

/**
 * @primitive b.cluster.shutdown
 * @signature b.cluster.shutdown()
 * @since     0.4.0
 * @status    stable
 * @related   b.cluster.init, b.cluster.onTransition
 *
 * Graceful cluster exit. Stops the heartbeat, releases the lease via
 * the provider so the next election round can fire immediately
 * (instead of waiting for `leaseTtl` to expire), emits a
 * `lease-released` transition, and resets internal state. Idempotent
 * when init was never called. After shutdown, `isLeader()` returns
 * `false` permanently for this process; a fresh `init()` is required
 * to participate again. Wire into the framework's appShutdown hook so
 * SIGTERM frees the lease before the new replica boots.
 *
 * @example
 *   process.on("SIGTERM", async function () {
 *     await b.cluster.shutdown();
 *     process.exit(0);
 *   });
 *   // → undefined
 */
async function shutdown() {
  if (!initialized) return;
  if (heartbeatTimer) {
    heartbeatTimer.stop();
    heartbeatTimer = null;
  }
  if (lease) {
    try {
      await provider.releaseLease(lease);
      _emitTransition("lease-released", { fencingToken: lease.fencingToken });
      log("lease released on shutdown");
    } catch (e) {
      log.error("release on shutdown failed: " + e.message);
    }
    lease = null;
  }
  initialized = false;
  terminated = true;
  provider = null;
  role = null;
  leaseTtlMs = null;
  heartbeatMs = null;
  configuredExternalDbBackend = null;
  configuredDialect = null;
  configuredEndpoint = null;
  configuredAcceptRotation = false;
  configuredExpectedVaultKeyFp = null;
  transitionHandlers = [];
}

function _resetForTest() {
  if (heartbeatTimer) heartbeatTimer.stop();
  heartbeatTimer = null;
  initialized = false;
  terminated = false;
  nodeId = null;
  role = null;
  provider = null;
  lease = null;
  leaseTtlMs = null;
  heartbeatMs = null;
  configuredExternalDbBackend = null;
  configuredDialect = null;
  configuredEndpoint = null;
  configuredAcceptRotation = false;
  configuredExpectedVaultKeyFp = null;
  transitionHandlers = [];
}

async function _heartbeatNowForTest() {
  await _heartbeat();
}

module.exports = {
  init:                init,
  isLeader:            isLeader,
  isClusterMode:       isClusterMode,
  externalDbBackend:   externalDbBackend,
  dialect:             dialect,
  currentNodeId:       currentNodeId,
  endpoint:            endpoint,
  fencingToken:        fencingToken,
  requireLeader:       requireLeader,
  currentLeader:       currentLeader,
  discoveryHandler:    discoveryHandler,
  onTransition:        onTransition,
  shutdown:            shutdown,
  NotLeaderError:      NotLeaderError,
  _resetForTest:       _resetForTest,
  _heartbeatNowForTest: _heartbeatNowForTest,
};
