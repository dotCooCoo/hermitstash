"use strict";
/**
 * Cluster coordination — leader election + fencing tokens.
 *
 * Opt-in via `b.cluster.init(...)`. When init is never called, the
 * local process behaves as a permanent single leader: `isLeader()`
 * always returns true, `fencingToken()` returns 0, no heartbeat thread
 * runs, no DB is touched. Single-node deployments pay zero overhead.
 *
 * When init IS called, the framework starts a heartbeat that renews
 * the leader lease via the configured provider. On lease loss (network
 * partition, takeover, lease expiry) the node transitions to follower
 * and write-side framework primitives throw `NotLeaderError`.
 *
 * Threat model:
 *   - Two leaders writing simultaneously: prevented by fencing tokens.
 *     Every leader-only DB write includes the current token; a
 *     CHECK constraint on the audit-tip row rejects a stale token.
 *     The application-layer `requireLeader()` gate is just an early
 *     rejection optimisation; the DB constraint is the canonical guard.
 *   - Follower receiving a write: rejected at the framework boundary.
 *     Operators front the cluster with a load balancer that routes
 *     write paths to the current leader.
 *   - External-db unreachable: heartbeat fails; after `leaseTtl` no
 *     leader exists and writes fail closed. When the DB recovers,
 *     election resumes.
 *
 * Public API:
 *   await cluster.init(opts)             one-time bootstrap
 *   cluster.isLeader()                   sync; true on leader (or single-node)
 *   cluster.currentNodeId()              sync; configured nodeId
 *   cluster.endpoint()                   sync; this node's routable URL
 *                                        (operator-supplied at init), or
 *                                        null if unconfigured. Stored in
 *                                        the leader-election row so
 *                                        external observers can resolve
 *                                        "where is the current leader?"
 *   cluster.fencingToken()               sync; current monotonic token
 *   cluster.requireLeader()              sync; throws NotLeaderError
 *   cluster.currentLeader()              async; { nodeId, leaseExpiresAt,
 *                                                 fencingToken,
 *                                                 endpoint } | null
 *   cluster.discoveryHandler()           returns an HTTP request handler
 *                                        (req, res) → JSON. Mount on any
 *                                        route to expose the current
 *                                        leader for service-mesh / LB
 *                                        consumption. 200 with leader,
 *                                        503 with `{ leader: null }`
 *                                        when no leader.
 *   cluster.onTransition(fn)             register transition handler
 *   await cluster.shutdown()             releases lease, stops heartbeat
 */
var C = require("./constants");
var clusterProviderDb = require("./cluster-provider-db");
var crypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var { boot } = require("./log");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var safeSql = require("./safe-sql");
var safeUrl = require("./safe-url");
var { FrameworkError, ClusterError } = require("./framework-error");

// Lazy: vault → db → cluster forms a load-time chain, and external-db is
// loaded before its init has run; both are safe to call once cluster
// reaches runtime, but eager require here would deadlock the load order.
var externalDb = lazyRequire(function () { return require("./external-db"); });
var vault = lazyRequire(function () { return require("./vault"); });

var DEFAULT_LEASE_TTL    = C.TIME.seconds(30);
var DEFAULT_HEARTBEAT    = C.TIME.seconds(10);
var MIN_LEASE_TTL        = C.TIME.seconds(5);
var MIN_HEARTBEAT        = C.TIME.seconds(1);

var initialized      = false;
var terminated       = false;           // set true by shutdown() so the
                                        // permanent-leader fallback isn't
                                        // re-engaged after a graceful exit
var nodeId           = null;
var role             = null;            // 'leader' | 'follower'
var provider         = null;
var lease            = null;            // current lease (if leader)
var heartbeatTimer   = null;
var heartbeatMs      = null;
var leaseTtlMs       = null;
var transitionHandlers = [];
// Backend coordinates for write-dispatch code in audit/consent/etc.
// These are set when cluster.init is called with `externalDbBackend`
// (the default DB-row provider path); operators using a custom
// provider can set them via init opts directly.
var configuredExternalDbBackend = null;
var configuredDialect            = null;
// Operator-supplied routable endpoint for THIS node, used by external
// load balancers / service meshes to learn where to send write traffic.
// Stored in the leader-election row on every acquire/renew so any node
// (or external observer) can resolve "where is the current leader?"
// via cluster.currentLeader() / cluster.discoveryHandler().
var configuredEndpoint          = null;

var log = boot("cluster");

class NotLeaderError extends FrameworkError {
  constructor(message) {
    super(message || "not leader: write rejected by cluster gate", "NOT_LEADER");
    this.name = "NotLeaderError";
    this.statusCode = 503;            // operator's load balancer should retry on the leader
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

// ---- init ----

async function init(opts) {
  if (initialized) {
    throw _err("ALREADY_INITIALIZED", "cluster.init() called twice", true);
  }
  opts = opts || {};
  if (!opts.nodeId) {
    throw _err("INVALID_CONFIG", "cluster.init({ nodeId }) is required", true);
  }
  nodeId = String(opts.nodeId);

  leaseTtlMs = opts.leaseTtl != null ? Number(opts.leaseTtl) : DEFAULT_LEASE_TTL;
  if (leaseTtlMs < MIN_LEASE_TTL) {
    throw _err("INVALID_TTL",
      "leaseTtl must be >= " + MIN_LEASE_TTL + "ms (got " + leaseTtlMs + ")",
      true);
  }
  heartbeatMs = opts.heartbeatInterval != null
    ? Number(opts.heartbeatInterval)
    : DEFAULT_HEARTBEAT;
  if (heartbeatMs < MIN_HEARTBEAT) {
    throw _err("INVALID_HEARTBEAT",
      "heartbeatInterval must be >= " + MIN_HEARTBEAT + "ms (got " + heartbeatMs + ")",
      true);
  }
  if (heartbeatMs >= leaseTtlMs) {
    throw _err("INVALID_HEARTBEAT",
      "heartbeatInterval must be < leaseTtl (got heartbeat=" + heartbeatMs +
      ", leaseTtl=" + leaseTtlMs + "); recommend ~1/3 of leaseTtl",
      true);
  }

  role = (opts.role || "leader").toLowerCase();
  if (role !== "leader" && role !== "follower") {
    throw _err("INVALID_ROLE", "role must be 'leader' or 'follower'", true);
  }

  // Optional endpoint. If provided, validate scheme + shape via url-safe
  // — HTTPS-only by default since this is the URL external services use
  // to reach the leader. Operators with internal cleartext clusters opt
  // in via opts.allowedProtocols (safeUrl.ALLOW_HTTP_ALL).
  if (opts.endpoint != null) {
    try {
      safeUrl.parse(opts.endpoint, {
        allowedProtocols: opts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
        errorClass:       ClusterError,
      });
    } catch (e) {
      // Re-throw with a config-shaped error so operators see the cluster.init
      // boundary, not a bare url-safe trace.
      throw _err("INVALID_ENDPOINT",
        "cluster.init({ endpoint }) rejected: " + e.message, true);
    }
    configuredEndpoint = String(opts.endpoint);
  } else {
    configuredEndpoint = null;
  }

  if (typeof opts.onTransition === "function") {
    transitionHandlers.push(opts.onTransition);
  }

  // Provider: either operator-supplied, or build the default DB-row
  // provider against an externalDb backend.
  if (opts.provider) {
    provider = opts.provider;
    // Operator-custom provider: they may still be writing framework
    // state to an externalDb backend, in which case they pass these
    // separately so write-dispatch code knows where to go.
    configuredExternalDbBackend = opts.externalDbBackend || null;
    configuredDialect = (opts.dialect || "postgres").toLowerCase();
  } else {
    if (!opts.externalDbBackend) {
      throw _err("INVALID_CONFIG",
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

  // Initial acquisition attempt (only if role === 'leader')
  if (role === "leader") {
    await _tryAcquire();
  }

  // Boot-time rollback detection on the audit + consent chains. Runs
  // regardless of role — every node should refuse to participate in a
  // cluster whose shared chains have been rolled back (a follower
  // would face the same chain integrity failure if it later took
  // over). Skipped when configuredExternalDbBackend is unset, which
  // means a custom provider is in use without externalDb-resident
  // framework state — the operator owns rollback detection in that
  // case.
  if (configuredExternalDbBackend) {
    await _checkChainTipRollback("audit",   "_blamejs_audit_log",   "_blamejs_audit_tip");
    await _checkChainTipRollback("consent", "_blamejs_consent_log", "_blamejs_consent_tip");
    // Vault-key consistency: every node in a cluster must hold the
    // SAME vault key. A node booting with a different key would seal
    // new writes under a key the rest of the cluster can't unseal,
    // and (on takeover) be unable to unseal the rest of the cluster's
    // sealed columns — silent corruption. Compare a fingerprint of
    // this node's vault keys against the canonical one stored at
    // first cluster boot; refuse to participate on mismatch.
    await _checkVaultKeyConsistency();
  }

  // Start heartbeat
  heartbeatTimer = safeAsync.repeating(_heartbeat, heartbeatMs, { name: "cluster-heartbeat" });
}

// Cluster-mode equivalent of db.js's single-node audit.tip-sidecar
// rollback check. Reads the persistent _blamejs_audit_tip row and
// compares to the current chain head in _blamejs_audit_log:
//
//   - No tip row: first cluster boot or operator-cleared. Skip
//     silently (matches the single-node sidecar-missing path).
//   - Tip recorded a counter > current MAX: chain was truncated /
//     restored from older snapshot. FATAL — refuse boot.
//   - Tip recorded a hash that doesn't match the row at that
//     counter: the row at that counter was substituted (different
//     hash for same counter). FATAL — refuse boot.
//
// process.exit(1) is the framework's convention for boot-time
// integrity failures (audit chain, checkpoints, single-node
// rollback). Cluster mode keeps the same posture so operators see
// a single boot-time failure mode regardless of deployment shape.
// Generalized boot-time rollback check used by both audit and consent
// chains. chainName is the human-readable label included in log
// output ("audit" / "consent"). logTable is the chain table
// (_blamejs_audit_log / _blamejs_consent_log). tipTable is the
// single-row coordination table that records the latest counter +
// rowHash + fencingToken (_blamejs_audit_tip / _blamejs_consent_tip).
//
// Surfaces three outcomes:
//   - tip table missing → operator running cluster gates-only mode
//     (cluster wired for leader election but framework state still
//     lives in per-node SQLite without `frameworkSchema.ensureSchema`);
//     skip silently.
//   - no tip row → first cluster boot or operator-cleared; skip.
//   - currentMax < tipCounter, or tip rowHash != row-at-counter
//     hash → FATAL via process.exit(1). Same posture as the
//     single-node audit.tip sidecar rollback check.
async function _checkChainTipRollback(chainName, logTable, tipTable) {
  // Both tables are framework-internal constants from the call sites
  // (`_blamejs_audit_log`, `_blamejs_consent_log`, etc.). Validate +
  // quote per the framework's identifier-quoting convention so a
  // future rename can't silently break the query.
  safeSql.validateIdentifier(logTable, { allowReserved: true });
  safeSql.validateIdentifier(tipTable, { allowReserved: true });
  var qLogTable = safeSql.quoteIdentifier(logTable);
  var qTipTable = safeSql.quoteIdentifier(tipTable);

  var tipRows;
  try {
    tipRows = await externalDb().query(
      "SELECT atMonotonicCounter, rowHash FROM " + qTipTable +
      " WHERE scope = " + (configuredDialect === "postgres" ? "$1" : "?"),
      [chainName],
      { backend: configuredExternalDbBackend }
    );
  } catch (e) {
    var msg = (e && e.message) || "";
    if (/no such table|does not exist|relation .* does not exist/i.test(msg)) {
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

  var currentRows = await externalDb().query(
    "SELECT MAX(monotonicCounter) AS m FROM " + qLogTable,
    [],
    { backend: configuredExternalDbBackend }
  );
  var currentMax = (currentRows.rows && currentRows.rows[0] && currentRows.rows[0].m)
    ? Number(currentRows.rows[0].m)
    : 0;

  if (currentMax < tipCounter) {
    throw _err("ROLLBACK_DETECTED",
      "FATAL: cluster-mode " + chainName + "-log rollback detected. " +
      chainName + "-tip counter: " + tipCounter +
      "; current external-db max: " + currentMax +
      ". Either external-db was restored from an older snapshot, or " +
      logTable + " rows have been deleted. Investigate before continuing.",
      true);
  }

  if (tipHash) {
    var hashRows = await externalDb().query(
      "SELECT rowHash FROM " + qLogTable + " WHERE monotonicCounter = " +
      (configuredDialect === "postgres" ? "$1" : "?"),
      [tipCounter],
      { backend: configuredExternalDbBackend }
    );
    if (hashRows.rows && hashRows.rows.length > 0) {
      var rowAtTip = hashRows.rows[0].rowHash;
      if (rowAtTip !== tipHash) {
        throw _err("ROLLBACK_DETECTED",
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

// Compute a deterministic fingerprint of THIS node's vault keys.
// SHA3-512 of the concatenated public keys (PQC + classical halves of
// the hybrid encryption keypair). One-way: nothing about the private
// key material is recoverable from the fingerprint, so it's safe to
// store in the coordination table that all cluster nodes can read.
//
// Returns null if vault.init() hasn't been called — cluster gates-only
// mode (no sealed-column work) doesn't need this check, same defensive
// posture as the audit-tip rollback check skipping when there's no
// audit-tip table.
function _vaultKeyFingerprint() {
  var keysJson;
  try {
    keysJson = vault().getKeysJson();
  } catch (e) {
    // vault.init() not called — gates-only mode. Skip silently.
    if (/vault.init\(\) must be awaited/.test((e && e.message) || "")) {
      return null;
    }
    throw e;
  }
  // vault.getKeysJson() returns the keys serialized as JSON (the same
  // format vault writes to disk). Parse to extract the public halves;
  // we never touch privateKey/ecPrivateKey here.
  var keys = safeJson.parse(keysJson);
  if (!keys || !keys.publicKey || !keys.ecPublicKey) return null;
  // Domain-separation prefix so this fingerprint can't be confused
  // with a hash of the same bytes computed elsewhere in the framework.
  return crypto.sha3Hash("blamejs/cluster-state/v1\n" +
                         keys.publicKey + "\n" +
                         keys.ecPublicKey);
}

async function _checkVaultKeyConsistency() {
  var localFp = _vaultKeyFingerprint();
  if (localFp === null) {
    log("vault not initialized — skipping vault-key consistency check (cluster gates-only mode)");
    return;
  }
  var nowMs = Date.now();
  var ph = configuredDialect === "postgres";

  // First boot: try to record THIS node's fingerprint. ON CONFLICT DO
  // NOTHING means the FIRST node to boot wins; subsequent nodes
  // observe whatever's already there. Every node then SELECTs and
  // compares — any mismatch (including ours after a losing race)
  // surfaces the drift.
  try {
    await externalDb().query(
      "INSERT INTO _blamejs_cluster_state " +
      "  (scope, vaultKeyFp, recordedAt, recordedByNode) " +
      "VALUES ('state', " +
      (ph ? "$1, $2, $3" : "?, ?, ?") + ") " +
      "ON CONFLICT (scope) DO NOTHING",
      [localFp, nowMs, nodeId],
      { backend: configuredExternalDbBackend }
    );
  } catch (e) {
    // Table missing → the cluster-provider-db ensureSchema didn't run
    // (custom provider that doesn't create _blamejs_cluster_state).
    // Skip silently — same defensive posture as the audit-tip check.
    var msg = (e && e.message) || "";
    if (/no such table|does not exist|relation .* does not exist/i.test(msg)) {
      log("cluster-state table not present — skipping vault-key consistency check (custom provider)");
      return;
    }
    throw e;
  }

  // Read whatever fingerprint is canonical (ours if first boot,
  // someone else's if we lost the race or are joining an existing cluster).
  var rows = await externalDb().query(
    "SELECT vaultKeyFp, recordedByNode, recordedAt FROM _blamejs_cluster_state " +
    "WHERE scope = 'state'",
    [],
    { backend: configuredExternalDbBackend }
  );
  if (!rows.rows || rows.rows.length === 0) {
    // Should never happen — we just INSERTed. Surface as fatal so the
    // condition isn't silently ignored.
    throw _err("CLUSTER_STATE_MISSING",
      "FATAL: cluster-state row missing immediately after INSERT — " +
      "external-db may not be honoring writes. Refusing boot.",
      true);
  }
  var canonical = rows.rows[0];
  if (canonical.vaultKeyFp !== localFp) {
    var fpPrefix = C.BYTES.bytes(16);
    throw _err("VAULT_KEY_DRIFT",
      "FATAL: vault-key drift detected. " +
      "local node: " + nodeId +
      "; local fingerprint: " + localFp.slice(0, fpPrefix) + "…" +
      "; canonical recorded by: " + canonical.recordedByNode +
      "; canonical fingerprint: " + canonical.vaultKeyFp.slice(0, fpPrefix) + "…" +
      ". This node holds a DIFFERENT vault key than the rest of the " +
      "cluster. Sealed-column writes from this node would be unreadable " +
      "by the others (and vice versa). Restore the same vault key file " +
      "before booting this node into the cluster.",
      true);
  }
  log("cluster vault-key consistency ok (fingerprint " +
    localFp.slice(0, C.BYTES.bytes(16)) + "… recorded by " + canonical.recordedByNode + ")");
}

async function _tryAcquire() {
  if (role !== "leader") return;        // pinned-follower role: never claim
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
    // Not currently leader — try to acquire (lease may have expired
    // on the previous holder).
    await _tryAcquire();
    return;
  }
  // We hold a lease — renew it. Re-supply the configured endpoint so a
  // hot-reload of the operator's config (e.g. node moves to a new
  // routable URL after a restart) eventually reaches the discovery row.
  try {
    lease = await provider.renewLease(lease, { endpoint: configuredEndpoint });
  } catch (e) {
    if (e.code === "LEASE_LOST") {
      log.error("lease lost: " + e.message);
      var lostToken = lease ? lease.fencingToken : null;
      lease = null;
      _emitTransition("lease-lost", { fencingToken: lostToken });
      // Attempt to re-acquire on the next heartbeat naturally.
    } else {
      // Transient error — retry on next heartbeat. If it persists past
      // leaseTtl another node will steal, and we'll detect via LEASE_LOST.
      log.error("renew failed transiently: " + e.message);
    }
  }
}

// ---- public sync surface ----

function isLeader() {
  if (terminated) return false;         // post-shutdown: never leader
  if (!initialized) return true;        // never-initialized: permanent leader
  return !!lease && Date.now() < lease.expiresAt;
}

// Has cluster.init been called with a real configuration? Used by
// write-dispatch code (audit, consent, …) to decide whether framework
// state should go to local SQLite or external-db.
function isClusterMode() {
  return initialized && !!configuredExternalDbBackend;
}

function externalDbBackend() {
  return configuredExternalDbBackend;
}

function dialect() {
  return configuredDialect;
}

function currentNodeId() {
  return initialized ? nodeId : "single-node-local";
}

// This node's routable endpoint (operator-configured at cluster.init).
// Returns null when not configured or in single-node fallback. External
// observers should call discoveryHandler() / currentLeader() instead —
// this getter is for the local node's own self-identity.
function endpoint() {
  return configuredEndpoint;
}

function fencingToken() {
  if (!initialized) return 0;
  return lease ? lease.fencingToken : 0;
}

function requireLeader() {
  if (!isLeader()) {
    throw new NotLeaderError(
      "node '" + currentNodeId() + "' is not currently leader" +
      (initialized ? "" : " (cluster not initialized)")
    );
  }
}

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

// HTTP request handler — replies with the current cluster leader for
// service-mesh / load-balancer discovery. Operators mount this at
// whatever route they want (`/cluster/leader`, `/health/leader`, etc.).
//
//   200 application/json — leader present
//     { leader: { nodeId, endpoint, fencingToken, leaseExpiresAt },
//       self:   { nodeId, endpoint, isLeader } }
//
//   503 application/json — no leader (no row, expired lease, DB
//   unreachable, single-node not initialized with cluster mode)
//     { leader: null, self: { nodeId, endpoint, isLeader } }
//
// No auth — this endpoint is intended to be called by infrastructure
// inside the trust boundary (LB, healthcheck, dashboard). Operators
// who expose it externally should layer auth via their own middleware.
//
// Handler is method-agnostic so it works behind any HTTP probe shape
// (GET, HEAD, etc.). Cache-Control: no-store to avoid stale-leader
// responses pinned by a caching proxy during a takeover.
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
        // Permanent-leader fallback (cluster.init never called). Reply
        // 200 — the operator's app is healthy and the "leader" is this
        // process. Useful so the discovery endpoint is never a false
        // negative in single-node deployments.
        body = { leader: leader, self: selfInfo };
        status = 200;
      } else {
        body = { leader: null, self: selfInfo };
        status = 503;
      }
    } catch (e) {
      body = { leader: null, self: selfInfo, error: e.message };
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

function onTransition(handler) {
  if (typeof handler !== "function") {
    throw _err("INVALID_HANDLER", "onTransition expects a function", true);
  }
  transitionHandlers.push(handler);
}

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
  transitionHandlers = [];
  // nodeId is preserved post-shutdown so audit metadata still reflects
  // who this process was; cleared only by _resetForTest.
}

// ---- test helpers — not part of public contract ----

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
  transitionHandlers = [];
}

async function _heartbeatNowForTest() {
  // Drive one heartbeat synchronously without waiting for the timer —
  // lets tests deterministically observe lease state transitions.
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
