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
 *   an early-rejection optimisation; the DB constraint is canonical.
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

// b.sql speaks postgres | sqlite | mysql; the cluster's configuredDialect
// is one of those (validated at init). Used so the boot-time chain-tip /
// vault-key-consistency statements emit the right identifier quoting.
function _bDialect() {
  return configuredDialect === "mysql" ? "mysql"
       : configuredDialect === "sqlite" ? "sqlite" : "postgres";
}

// Emit a b.sql builder + run it against the configured external-DB
// backend. b.sql emits `?` placeholders; the externalDb driver receives
// the SQL verbatim, so translate to `$N` for Postgres (passthrough for
// SQLite / MySQL).
function _runClusterQuery(builder) {
  var built = builder.toSql();
  return externalDb().query(
    clusterStorage().placeholderize(built.sql, configuredDialect),
    built.params,
    { backend: configuredExternalDbBackend }
  );
}

// "The framework-internal table this check needs does not exist yet" —
// the signal that a gates-only cluster (leader election wired, but
// framework state still resident in per-node SQLite without
// frameworkSchema.ensureSchema) should SKIP the boot-time rollback /
// vault-key-consistency check instead of FATAL-refusing boot. Each
// backend phrases the missing-relation fault differently, and not all
// drivers carry a stable structured code, so this matches BOTH the
// driver phrasing AND the portable code/SQLSTATE when present:
//
//   - SQLite:    "no such table: X"
//   - Postgres:  "relation "X" does not exist"  (SQLSTATE 42P01)
//   - MySQL:     "Table 'db.X' doesn't exist"   (errno 1146, SQLSTATE 42S02)
//
// The earlier message-only test recognized the SQLite/Postgres phrasing
// ("no such table" / "does not exist") but NOT MySQL's "doesn't exist"
// (the apostrophe-contracted form), so a gates-only MySQL cluster boot
// mis-fired the skip and surfaced ER_NO_SUCH_TABLE instead of completing.
function _isMissingTableError(e) {
  if (!e) return false;
  // Structured code / SQLSTATE first — driver-stable, locale-independent.
  // mysql2-shape: e.errno === 1146 / e.code === "ER_NO_SUCH_TABLE";
  // the docker-exec shim + ANSI drivers surface SQLSTATE 42S02 (MySQL) /
  // 42P01 (Postgres) on e.code / e.sqlState.
  var code     = (e.code != null) ? String(e.code) : "";
  var sqlState = (e.sqlState != null) ? String(e.sqlState) : "";
  if (e.errno === 1146) return true;
  if (code === "ER_NO_SUCH_TABLE" || code === "42S02" || code === "42P01" ||
      sqlState === "42S02" || sqlState === "42P01") {
    return true;
  }
  // Driver phrasing fallback. "doesn't exist" (MySQL apostrophe form) is
  // covered alongside "does not exist" (Postgres) and "no such table"
  // (SQLite). The MySQL message embeds the table name in quotes, so the
  // bare "doesn't exist" substring is the portable anchor.
  var msg = e.message || "";
  return /no such table|does not exist|doesn't exist|relation .* does not exist/i.test(msg);
}

var DEFAULT_LEASE_TTL    = C.TIME.seconds(30);
var DEFAULT_HEARTBEAT    = C.TIME.seconds(10);
// MIN_LEASE_TTL bumped from 5s → 10s. With 5s leases + 1s heartbeats,
// a network glitch + GC pause can leave the old leader believing it
// still holds the lease (4s remaining on its clock) while a new
// leader has already acquired. Old-leader writes during that window
// only land on framework state with a fencingToken WHERE clause
// (audit-tip CHECK catches it); operator-supplied writes through
// b.externalDb.transaction outside the audit chain DON'T carry the
// clause and can be accepted by both leaders. 10s leaves more room
// for the framework's audit-tip fencing to catch the split-brain
// before consequential writes reach durable state.
var MIN_LEASE_TTL        = C.TIME.seconds(10);
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
// Operator declaration that this node's vault keypair legitimately
// changed via a key rotation (b.vault.rotate). When set, a fingerprint
// that differs from the canonical cluster-state row is ADOPTED (the row
// advances to the new fingerprint + bumps the rotation epoch) instead
// of FATAL-refusing boot. Unset (the default) keeps the strict
// drift-refusal posture for the UNexpected mismatch. See
// _checkVaultKeyConsistency for the consistency model.
var configuredAcceptRotation     = false;
var configuredExpectedVaultKeyFp = null;

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
 * `VAULT_KEY_DRIFT`. Pass `acceptVaultKeyRotation: true` to declare the
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
 *   externalDbBackend:  object,            // required when no custom provider
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
 *     externalDbBackend: b.externalDb.backend("primary"),
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

  // Vault-key rotation acceptance (config-time tier: THROW on bad
  // input). acceptVaultKeyRotation is a boolean declaration; an
  // expectedVaultKeyFp without it is a misconfiguration (the operator
  // blessed a fingerprint but never enabled adoption).
  validateOpts.optionalBoolean(opts.acceptVaultKeyRotation,
    "cluster.init({ acceptVaultKeyRotation })", ClusterError, "INVALID_CONFIG");
  configuredAcceptRotation = opts.acceptVaultKeyRotation === true;
  if (opts.expectedVaultKeyFp !== undefined) {
    if (typeof opts.expectedVaultKeyFp !== "string" ||
        !/^[0-9a-f]{128}$/.test(opts.expectedVaultKeyFp)) {
      throw _err("INVALID_CONFIG",
        "cluster.init({ expectedVaultKeyFp }) must be a 128-char " +
        "lowercase-hex SHA3-512 fingerprint (b.vault rotation output)", true);
    }
    if (!configuredAcceptRotation) {
      throw _err("INVALID_CONFIG",
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
    // Resolve the chain + tip table names through frameworkSchema so the
    // configurable framework-table prefix is honored (the names are
    // `_blamejs_`-prefixed and self-mapped, so the resolve is a no-op under
    // the default prefix).
    await _checkChainTipRollback("audit",
      frameworkSchema().tableName("audit_log"),                                   // allow:hand-rolled-sql — logical-name reference
      frameworkSchema().tableName("_blamejs_audit_tip"));                         // allow:hand-rolled-sql — logical-name reference
    await _checkChainTipRollback("consent",
      frameworkSchema().tableName("consent_log"),                                 // allow:hand-rolled-sql — logical-name reference
      frameworkSchema().tableName("_blamejs_consent_tip"));                       // allow:hand-rolled-sql — logical-name reference
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
  // Both tables are framework-internal constants resolved at the call
  // sites through frameworkSchema. b.sql quotes every identifier by
  // construction; the dialect-final SQL is placeholderized to `$N` for
  // Postgres (passthrough for SQLite).
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
    throw _err("ROLLBACK_DETECTED",
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
  return bCrypto.sha3Hash("blamejs/cluster-state/v1\n" +
                         keys.publicKey + "\n" +
                         keys.ecPublicKey);
}

// Idempotent migration for the rotationEpoch column. cluster-provider-db
// ensureSchema creates _blamejs_cluster_state without it (the column was
// added when rotation-epoch acceptance landed); ADD COLUMN here keeps the
// path version-agnostic the same way the provider migrates the leader
// row's `endpoint` column. The only expected failure is "column already
// exists," which is swallowed. SQLite / MySQL don't take a DEFAULT on a
// non-constant, so the column is nullable and treated as epoch 0 when
// absent on legacy rows.
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

// Consistency model (CWE-345 binding-integrity for sealed columns):
//
//   Every node fingerprints its vault PUBLIC keys (SHA3-512, one-way) and
//   the cluster agrees on ONE canonical fingerprint stored in
//   _blamejs_cluster_state. A node holding a different key seals new
//   writes the rest of the cluster can't unseal — silent corruption — so
//   an UNDECLARED mismatch fails closed (FATAL: VAULT_KEY_DRIFT).
//
//   A vault-key rotation (b.vault.rotate, lib/vault/rotate.js) legitimately
//   changes the public-key fingerprint on EVERY node. The rotation only
//   re-seals the local dataDir; it does not touch the external coordination
//   row, so the canonical fingerprint goes stale and every node would
//   refuse boot. acceptVaultKeyRotation: true is the operator's signed-off
//   declaration "this change is a rotation, not drift": the booting node
//   ADVANCES the canonical row to its own fingerprint and bumps a
//   monotonic rotationEpoch. expectedVaultKeyFp narrows the adoption to a
//   single blessed fingerprint so a stale / wrong key file is still
//   refused. The strict refusal is unchanged when no rotation is declared,
//   which is exactly the cross-node drift case the check defends.
//
//   The epoch is observability + a future-replay guard, not an auth
//   boundary — the auth boundary is the operator's deliberate opt
//   (acceptVaultKeyRotation) plus the optional fingerprint allowlist. A
//   forged row can only ever cost a single declared boot, and a genuinely
//   different key would still fail every sealed read.
async function _checkVaultKeyConsistency() {
  var localFp = _vaultKeyFingerprint();
  if (localFp === null) {
    log("vault not initialized — skipping vault-key consistency check (cluster gates-only mode)");
    return;
  }
  var nowMs = Date.now();
  var stateTable = frameworkSchema().tableName("_blamejs_cluster_state");           // allow:hand-rolled-sql — logical-name reference

  // First boot: try to record THIS node's fingerprint. ON CONFLICT DO
  // NOTHING means the FIRST node to boot wins; subsequent nodes
  // observe whatever's already there. Every node then SELECTs and
  // compares — any mismatch (including ours after a losing race)
  // surfaces the drift. The scope value binds like any other param; b.sql
  // folds DO NOTHING to the MySQL `scope = scope` no-op automatically.
  try {
    await _runClusterQuery(sql().upsert(stateTable, { dialect: _bDialect() })
      .values({ scope: "state", vaultKeyFp: localFp, recordedAt: nowMs, recordedByNode: nodeId })
      .onConflict(["scope"]).doNothing());
  } catch (e) {
    // Table missing → the cluster-provider-db ensureSchema didn't run
    // (custom provider that doesn't create _blamejs_cluster_state).
    // Skip silently — same defensive posture as the audit-tip check.
    if (_isMissingTableError(e)) {
      log("cluster-state table not present — skipping vault-key consistency check (custom provider)");
      return;
    }
    throw e;
  }

  // Bring the rotationEpoch column into existence (idempotent). The INSERT
  // above already proved the table is present, so a real ALTER failure
  // here is "column exists" and is swallowed.
  await _ensureRotationEpochColumn();

  // Read whatever fingerprint is canonical (ours if first boot,
  // someone else's if we lost the race or are joining an existing cluster).
  var rows = await _runClusterQuery(sql().select(stateTable, { dialect: _bDialect() })
    .columns(["vaultKeyFp", "recordedByNode", "recordedAt", "rotationEpoch"])
    .where("scope", "state"));
  if (!rows.rows || rows.rows.length === 0) {
    // Should never happen — we just INSERTed. Surface as fatal so the
    // condition isn't silently ignored.
    throw _err("CLUSTER_STATE_MISSING",
      "FATAL: cluster-state row missing immediately after INSERT — " +
      "external-db may not be honoring writes. Refusing boot.",
      true);
  }
  var canonical = rows.rows[0];
  var fpPrefix = C.BYTES.bytes(16);
  if (canonical.vaultKeyFp !== localFp) {
    // Mismatch. Two readings: a legitimate vault-key rotation the
    // operator has declared, or genuine cross-node drift. Without the
    // declaration, always fail closed — sealed-column corruption is the
    // worse outcome.
    if (!configuredAcceptRotation) {
      throw _err("VAULT_KEY_DRIFT",
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
    // Rotation declared. If the operator blessed a specific fingerprint,
    // the LOCAL key must match it — this rejects a stale / wrong key file
    // that happens to differ from canonical for the wrong reason.
    if (configuredExpectedVaultKeyFp && configuredExpectedVaultKeyFp !== localFp) {
      throw _err("VAULT_KEY_ROTATION_MISMATCH",
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
    // Adopt: advance the canonical row to the new fingerprint and bump
    // the monotonic rotation epoch. The UPDATE is gated on the OLD
    // fingerprint so two nodes adopting concurrently converge on a single
    // advance (the loser's WHERE matches nothing and it re-reads the
    // already-advanced row below).
    var priorEpoch = (canonical.rotationEpoch != null) ? Number(canonical.rotationEpoch) : 0;
    if (!isFinite(priorEpoch) || priorEpoch < 0) priorEpoch = 0;
    var nextEpoch = priorEpoch + 1;
    await _runClusterQuery(sql().update(stateTable, { dialect: _bDialect() })
      .set({
        vaultKeyFp: localFp, recordedAt: nowMs,
        recordedByNode: nodeId, rotationEpoch: nextEpoch,
      })
      .where("scope", "state").where("vaultKeyFp", canonical.vaultKeyFp));
    // Re-read so the post-adopt state reflects whoever actually won the
    // advance (this node, or a peer that adopted the SAME rotated key a
    // beat earlier). A surviving mismatch here means the row now carries a
    // fingerprint that is neither the old one nor ours — a real drift that
    // the rotation declaration does not cover, so fail closed.
    var after = await _runClusterQuery(sql().select(stateTable, { dialect: _bDialect() })
      .columns(["vaultKeyFp", "recordedByNode", "rotationEpoch"])
      .where("scope", "state"));
    var post = (after.rows && after.rows[0]) || canonical;
    if (post.vaultKeyFp !== localFp) {
      throw _err("VAULT_KEY_DRIFT",
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
  // ±20% per-tick jitter on followers — without it, N followers
  // polling on a deterministic cadence all fire _tryAcquire at the
  // same wall-clock instant on lease expiry, producing thundering-
  // herd INSERT/UPDATE pressure on the leader-election row at
  // exactly the worst time. Leader-renewal path doesn't jitter
  // (a missed renewal hands the lease to a follower; the timing
  // budget is in `leaseTtl - heartbeatMs`, not in the jitter
  // window).
  if (!lease) {
    var jitterMs = Math.floor(Math.random() * (heartbeatMs * 0.4));            // allow:math-random-noncrypto-jitter-sampling — heartbeat jitter, not security-bearing
    if (jitterMs > 0) {
      await safeAsync.sleep(jitterMs);
    }
    if (!initialized) return;
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
  if (terminated) return false;         // post-shutdown: never leader
  if (!initialized) return true;        // never-initialized: permanent leader
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
// Has cluster.init been called with a real configuration? Used by
// write-dispatch code (audit, consent, …) to decide whether framework
// state should go to local SQLite or external-db.
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
    } catch (_e) {
      // Generic client-facing reason — the caught error's message (a DB error
      // detail / DSN / host:port) is not echoed to the client (CWE-209).
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
    throw _err("INVALID_HANDLER", "onTransition expects a function", true);
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
  configuredAcceptRotation = false;
  configuredExpectedVaultKeyFp = null;
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
