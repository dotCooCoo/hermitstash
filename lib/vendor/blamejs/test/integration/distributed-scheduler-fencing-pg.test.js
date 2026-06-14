"use strict";
/**
 * Live distributed-correctness proof against a REAL Postgres backend —
 * not the single-process fakes the smoke tests use. Two things the
 * framework advertises only hold if a real database enforces them:
 *
 *   1. EXACTLY-ONCE (b.scheduler, cluster mode): every fire INSERTs a
 *      row into _blamejs_scheduler_ticks keyed on the composite tickKey
 *      `name:scheduledAtUnix` with `ON CONFLICT (tickKey) DO NOTHING`.
 *      When two nodes race the SAME nominal tick, the PRIMARY KEY makes
 *      exactly one INSERT land — the loser's INSERT affects 0 rows and
 *      the scheduler skips its fire. The dedup is the DB's unique
 *      constraint, so this is only a real proof against a real DB.
 *
 *   2. FENCING (b.cluster fencing token): a stale leader holding a lower
 *      fencing token must be refused at the database layer when it
 *      attempts a fenced write after a newer leader took over. The
 *      canonical fenced write is the audit-tip upsert
 *      (`... ON CONFLICT (scope) DO UPDATE ... WHERE
 *      _blamejs_audit_tip.fencingToken <= EXCLUDED.fencingToken
 *      RETURNING fencingToken`, lib/audit.js _upsertAuditTip): the WHERE
 *      clause is the monotonic-non-decreasing guard. cluster-provider-
 *      mysql.test.js proves the lease-fencing-token issuance on MySQL;
 *      this extends both the issuance AND the tip CHECK to Postgres and
 *      ties the stale token to a real refused fenced operation.
 *
 * The "driver" is a docker-exec psql shim — a persistent
 *   docker exec -i blamejs-test-postgres psql -U blamejs -d blamejs_test ...
 * subprocess per client (SQL fed over stdin, never argv — no shell
 * parsing of SQL). It removes any npm pg-driver dep while exercising the
 * framework's real Postgres SQL: the scheduler tick-claim, the cluster-
 * provider-db lease/fencing-token SQL, and the audit-tip fencing guard.
 *
 * RUN: node scripts/test-integration.js --skip-service-check distributed-scheduler-fencing-pg
 *
 * STATUS: the EXACTLY-ONCE proof passes live; the FENCING proof exposes a
 * live bug in lib/cluster-provider-db.js. Postgres folds unquoted column
 * identifiers to lower case, so a real driver returns the leader row's
 * columns as `nodeid` / `leaseid` / `fencingtoken` / `expiresat`, but the
 * provider reads `row.nodeId` / `row.leaseId` / ... (camelCase). Every such
 * read resolves to `undefined`: acquireLease's `row.nodeId !== nodeId` guard
 * is always true so it returns null (the leader can never acquire), and
 * currentLeader reports a phantom leader with `nodeId: undefined` and a NaN
 * lease expiry. The columns are unaffected on MySQL (it preserves alias
 * case), which is why cluster-provider-mysql.test.js passes. The fix is to
 * double-quote the identifiers in the _blamejs_leader DDL and in every
 * SELECT / RETURNING in lib/cluster-provider-db.js (or normalize row keys
 * case-insensitively before the camelCase reads). This test asserts the
 * CORRECT contract so it fails until that is fixed.
 */

var spawn        = require("node:child_process").spawn;
var execFileSync = require("node:child_process").execFileSync;
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var CONTAINER = "blamejs-test-postgres";

// ---- one-shot psql (setup / teardown / out-of-band assertions) ----
// Shell-free SQL: the statement travels on stdin, never in argv.
function _psql(sql) {
  var prelude = "\\pset fieldsep '\\t'\n";
  var out = execFileSync(
    "docker",
    ["exec", "-i", CONTAINER, "sh", "-c",
     "psql -U blamejs -d blamejs_test -qtA -P null=__BJNULL__ 2>&1"],
    { input: prelude + sql + "\n", stdio: ["pipe", "pipe", "pipe"] }
  ).toString("utf8");
  if (/^ERROR:/m.test(out)) {
    throw new Error("psql setup failed for [" + sql + "]:\n" + out);
  }
  return out;
}

// ---- persistent-session docker-exec psql driver ----
// Each client is a long-lived psql subprocess. Statements are written to
// its stdin terminated by an `\echo <sentinel>`; the driver reads merged
// stdout until the sentinel line, then parses the block. SQLSTATE-coded
// ERROR lines throw an Error carrying `.code`.
var PSQL_ARGS = "psql -U blamejs -d blamejs_test -A " +
                "-v ON_ERROR_STOP=0 -P null=__BJNULL__ 2>&1";
var NULL_SENTINEL = "__BJNULL__";
var _seq = 0;

function _makeDockerPgDriver() {
  return {
    connect: function () {
      return new Promise(function (resolve, reject) {
        var child = spawn(
          "docker",
          ["exec", "-i", CONTAINER, "sh", "-c",
           PSQL_ARGS + " ; echo __BLAMEJS_PSQL_EXIT__"],
          { stdio: ["pipe", "pipe", "pipe"] }
        );
        var client = {
          child:   child,
          buf:     "",
          pending: null,
          closed:  false,
          exitErr: null,
        };
        child.on("error", function (e) {
          client.exitErr = e;
          if (client.pending) { var p = client.pending; client.pending = null; p.reject(e); }
        });
        child.on("close", function () {
          client.closed = true;
          if (client.pending) {
            var p = client.pending; client.pending = null;
            p.reject(new Error("psql session closed mid-statement"));
          }
        });
        child.stdout.on("data", function (chunk) {
          client.buf += chunk.toString("utf8");
          _drain(client);
        });
        var primeSentinel = "__BJ_PRIME__";
        client.pending = {
          sentinel: primeSentinel,
          resolve:  function () { resolve(client); },
          reject:   reject,
        };
        client.child.stdin.write(
          "\\pset fieldsep '\\t'\n\\pset footer off\n\\set VERBOSITY verbose\n" +
          "\\echo " + primeSentinel + "\n");
      });
    },

    query: function (client, sql, params) {
      params = params || [];
      var bound = _bindParams(sql, params);
      var sentinel = "__BJ_EOR_" + (++_seq) + "__";
      return new Promise(function (resolve, reject) {
        if (client.closed) { reject(new Error("psql session is closed")); return; }
        client.pending = { sentinel: sentinel, resolve: resolve, reject: reject };
        client.child.stdin.write(bound + "\n;\n\\echo " + sentinel + "\n");
      });
    },

    close: function (client) {
      return new Promise(function (resolve) {
        if (client.closed) { resolve(); return; }
        try { client.child.stdin.end("\\q\n"); } catch (_e) { /* best effort */ }
        var done = false;
        client.child.on("close", function () { if (!done) { done = true; resolve(); } });
        setTimeout(function () {
          if (done) return;
          done = true;
          try { client.child.kill("SIGKILL"); } catch (_e) {}
          resolve();
        }, 2000);
      });
    },

    dialect: "postgres",
  };
}

function _drain(client) {
  if (!client.pending) return;
  var sentinel = client.pending.sentinel;
  var marker = "\n" + sentinel + "\n";
  var idx = client.buf.indexOf(marker);
  var startAtZero = client.buf.indexOf(sentinel + "\n") === 0;
  var block;
  if (idx !== -1) {
    block = client.buf.slice(0, idx);
    client.buf = client.buf.slice(idx + marker.length);
  } else if (startAtZero) {
    block = "";
    client.buf = client.buf.slice((sentinel + "\n").length);
  } else {
    return;
  }
  var p = client.pending;
  client.pending = null;
  var parsed;
  try {
    parsed = _parseBlock(block);
  } catch (e) {
    return p.reject(e);
  }
  if (parsed.error) return p.reject(parsed.error);
  p.resolve({ rows: parsed.rows, rowCount: parsed.rowCount });
}

// Substitute Postgres $1/$2 placeholders with quoted literals. Every test
// value is operator-controlled (ids / nodeIds / tokens / numbers / null).
function _bindParams(sql, params) {
  return sql.replace(/\$(\d+)/g, function (_m, n) {
    var i = Number(n) - 1;
    if (i < 0 || i >= params.length) {
      throw new Error("placeholder $" + n + " has no matching param");
    }
    var v = params[i];
    if (v === null || v === undefined) return "NULL";
    if (typeof v === "number") return String(v);
    if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
    return "'" + String(v).replace(/'/g, "''") + "'";
  });
}

var _CMD_TAG_RE = /^(INSERT|UPDATE|DELETE|MERGE|SELECT|COPY|MOVE)\b(?:\s+\d+)*\s*$/;
var _CTRL_TAG_RE = /^(BEGIN|COMMIT|ROLLBACK|SET|RESET|SAVEPOINT|RELEASE|START|CREATE|DROP|ALTER|GRANT|REVOKE|TRUNCATE|COMMENT|DO|CALL|VACUUM|ANALYZE|EXPLAIN|TABLE|SHOW|DISCARD)\b/;

function _parseBlock(block) {
  var lines = block.split(/\r?\n/);
  while (lines.length && lines[lines.length - 1] === "") lines.pop();

  for (var i = 0; i < lines.length; i++) {
    var em = /^ERROR:\s+([0-9A-Za-z]{5}):\s*(.*)$/.exec(lines[i]);
    if (em) {
      var err = new Error("Postgres " + em[1] + ": " + em[2]);
      err.code = em[1];
      return { error: err };
    }
  }

  var affected = null;
  var dataLines = [];
  for (var j = 0; j < lines.length; j++) {
    var ln = lines[j];
    if (/^(NOTICE|WARNING|DETAIL|HINT|LINE|LOCATION|CONTEXT|STATEMENT):/.test(ln)) continue;
    var tm = _CMD_TAG_RE.exec(ln);
    if (tm) {
      var nums = ln.trim().split(/\s+/).slice(1).map(Number);
      if (nums.length) affected = nums[nums.length - 1];
      continue;
    }
    if (_CTRL_TAG_RE.test(ln) && ln.indexOf("\t") === -1) continue;
    dataLines.push(ln);
  }

  var rows = [];
  if (dataLines.length >= 1) {
    var headers = dataLines[0].split("\t");
    for (var k = 1; k < dataLines.length; k++) {
      var cells = dataLines[k].split("\t");
      var row = {};
      for (var c = 0; c < headers.length; c++) {
        var cell = cells[c];
        row[headers[c]] = (cell === NULL_SENTINEL || cell === undefined) ? null : cell;
      }
      rows.push(row);
    }
  }
  var rowCount = (affected !== null) ? affected : rows.length;
  return { rows: rows, rowCount: rowCount, error: null };
}

// _blamejs_scheduler_ticks DDL (mirrors framework-schema _schedulerTicksDDL
// for the postgres dialect). The scheduler INSERTs through cluster-storage
// against this table when cluster mode is wired.
// Columns are double-quoted so Postgres preserves the camelCase exactly as
// framework-schema._schedulerTicksDDL emits them (quote-by-construction via
// safeSql.quoteIdentifier). The b.sql tick-claim INSERT quotes its columns,
// so an unquoted DDL here would create lowercased columns the quoted INSERT
// cannot find.
var SCHED_TICKS_DDL =
  "CREATE TABLE IF NOT EXISTS _blamejs_scheduler_ticks (" +
  '  "tickKey"         TEXT PRIMARY KEY,' +
  '  "name"            TEXT NOT NULL,' +
  '  "scheduledAtUnix" BIGINT NOT NULL,' +
  '  "claimedAtUnix"   BIGINT NOT NULL,' +
  '  "claimedBy"       TEXT' +
  ")";

// _blamejs_audit_tip DDL (mirrors framework-schema _auditTipDDL for the
// postgres dialect) — the single-row coordination table whose
// fencingToken-monotonic WHERE clause is the canonical DB-layer fence.
var AUDIT_TIP_DDL =
  "CREATE TABLE IF NOT EXISTS _blamejs_audit_tip (" +
  '  "scope"                TEXT PRIMARY KEY,' +
  '  "atMonotonicCounter"   BIGINT NOT NULL,' +
  '  "rowHash"              TEXT,' +
  '  "signedAt"             TEXT,' +
  '  "fencingToken"         BIGINT NOT NULL DEFAULT 0,' +
  "  CHECK (\"scope\" = 'audit')" +
  ")";

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  // ---- fresh schema ----
  _psql([
    "DROP TABLE IF EXISTS _blamejs_scheduler_ticks;",
    "DROP TABLE IF EXISTS _blamejs_audit_tip;",
    "DROP TABLE IF EXISTS _blamejs_leader;",
    "DROP TABLE IF EXISTS _blamejs_cluster_state;",
  ].join("\n"));

  var driver = _makeDockerPgDriver();
  b.cluster._resetForTest();
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "postgres",
      },
    },
  });

  try {
    await _proveExactlyOnce();
    await _proveFencing();
  } finally {
    // Best-effort teardown: shut cluster + externalDb, drop tables.
    try { await b.cluster.shutdown(); } catch (_e) {}
    b.cluster._resetForTest();
    try { await b.externalDb.shutdown(); } catch (_e) {}
    _psql([
      "DROP TABLE IF EXISTS _blamejs_scheduler_ticks;",
      "DROP TABLE IF EXISTS _blamejs_audit_tip;",
      "DROP TABLE IF EXISTS _blamejs_leader;",
      "DROP TABLE IF EXISTS _blamejs_cluster_state;",
    ].join("\n"));
  }
}

// ======================================================================
// 1. EXACTLY-ONCE — two racing nodes claim the SAME scheduled tick; the
//    real PRIMARY KEY on tickKey lets exactly one win, the loser is
//    rejected by the unique constraint (not by a hand-inserted row), and
//    the job fires ONCE.
// ======================================================================
async function _proveExactlyOnce() {
  _psql(SCHED_TICKS_DDL);

  // Wire cluster.init against the real PG provider so cluster.isClusterMode()
  // is true: the scheduler's tick-claim INSERT then routes through
  // clusterStorage → externalDb → real Postgres. The provider's
  // ensureSchema creates _blamejs_leader; we created the ticks table above.
  //
  // NOTE: the scheduler instances below use their OWN cluster views for the
  // leader gate, so this proof does not depend on cluster.isLeader() — it
  // depends only on isClusterMode() routing framework state to PG, which is
  // true regardless of lease state. (cluster.isLeader() is in fact false
  // here on Postgres — see the FENCING section for that bug.)
  await b.cluster.init({
    nodeId:            "sched-node",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
    externalDbBackend: "ops",
    dialect:           "postgres",
  });
  check("exactly-once: cluster is in cluster mode (state routes to PG)",
        b.cluster.isClusterMode() === true);

  // Two scheduler instances modelling two cluster nodes that both believe
  // they're leader (the split-brain window the tick-claim defends). Each
  // declares the SAME task name + same interval so a shared nominal
  // scheduled time produces the SAME tickKey on both. We drive _fireOnce
  // on both for the SAME nominal tick by pinning each task's nextRun to a
  // shared instant before firing.
  var firedByA = 0;
  var firedByB = 0;

  var clusterAView = {
    isLeader:      function () { return true; },
    currentNodeId: function () { return "node-A"; },
  };
  var clusterBView = {
    isLeader:      function () { return true; },
    currentNodeId: function () { return "node-B"; },
  };

  var schedA = b.scheduler.create({ cluster: clusterAView, audit: false });
  var schedB = b.scheduler.create({ cluster: clusterBView, audit: false });

  var taskA = schedA.schedule({
    name: "rollup", every: b.constants.TIME.minutes(1),
    run: async function () { firedByA++; },
  });
  var taskB = schedB.schedule({
    name: "rollup", every: b.constants.TIME.minutes(1),
    run: async function () { firedByB++; },
  });

  // Pin both tasks to the SAME nominal scheduled instant so both compute
  // the identical tickKey ("rollup:<sharedNominal>"). _fireOnce reads
  // task.nextRun as the nominal run for the tick.
  var sharedNominal = Date.now() + b.constants.TIME.minutes(1);
  taskA.nextRun = sharedNominal;
  taskB.nextRun = sharedNominal;

  // Fire BOTH for the same tick concurrently. The two clusterStorage
  // INSERTs hit the real PG PRIMARY KEY at once; exactly one lands.
  schedA._fireOnce("rollup");
  schedB._fireOnce("rollup");

  // Wait until the tick-claim race has resolved on BOTH instances: the
  // winner's fires===1 and the loser's tickClaimLost===1. Polling on the
  // observable counters avoids a fixed sleep.
  await helpers.waitUntil(function () {
    var a = schedA.list()[0];
    var bb = schedB.list()[0];
    var aResolved = (a.fires === 1) || (a.tickClaimLost === 1);
    var bResolved = (bb.fires === 1) || (bb.tickClaimLost === 1);
    return aResolved && bResolved;
  }, { timeoutMs: 15000, label: "exactly-once: both nodes' tick-claim race resolved" });

  var aState = schedA.list()[0];
  var bState = schedB.list()[0];

  // Exactly one of the two nodes won the claim.
  var winners = aState.fires + bState.fires;
  var losers = aState.tickClaimLost + bState.tickClaimLost;
  check("exactly-once: exactly ONE node won the tick-claim (fires totals 1)",
        winners === 1);
  check("exactly-once: exactly ONE node lost (tickClaimLost totals 1)",
        losers === 1);

  // The run-side effect fired exactly once across both nodes — the
  // real proof the job did not double-execute.
  check("exactly-once: the job's run() executed exactly ONCE across both nodes",
        (firedByA + firedByB) === 1);

  // The DB holds exactly one tick row for the shared tickKey — the
  // PRIMARY KEY collapsed the racing INSERTs to one.
  var tickRows = _psql(
    "SELECT count(*) AS n FROM _blamejs_scheduler_ticks " +
    "WHERE \"tickKey\" = 'rollup:" + sharedNominal + "';");
  check("exactly-once: real PG holds exactly ONE tick row for the shared key",
        /^1$/m.test(tickRows.trim()));

  // The surviving row's claimedBy is the winner's nodeId — confirms the
  // winner is the one whose INSERT actually landed, not a coincidence.
  var winnerNode = _psql(
    "SELECT \"claimedBy\" FROM _blamejs_scheduler_ticks " +
    "WHERE \"tickKey\" = 'rollup:" + sharedNominal + "';").trim();
  var expectedWinner = aState.fires === 1 ? "node-A" : "node-B";
  check("exactly-once: surviving tick row's claimedBy is the node that fired",
        winnerNode === expectedWinner);

  // Control: a SECOND distinct nominal tick is independently claimable —
  // proves the dedup is per-tickKey, not a one-shot table lock.
  var secondNominal = sharedNominal + b.constants.TIME.minutes(1);
  taskA.nextRun = secondNominal;
  schedA._fireOnce("rollup");
  await helpers.waitUntil(function () {
    return schedA.list()[0].fires === 2;
  }, { timeoutMs: 15000, label: "exactly-once: a second distinct tick is claimable" });
  check("exactly-once: a distinct second tick fires (per-tickKey dedup, not a table lock)",
        firedByA === 2 || (firedByA + firedByB) === 2);

  await schedA.stop();
  await schedB.stop();

  // Tear down cluster wiring so the fencing section starts from a clean
  // single source of truth (it re-uses _blamejs_leader through two
  // direct provider instances, not cluster.init).
  await b.cluster.shutdown();
  b.cluster._resetForTest();
}

// ======================================================================
// 2. FENCING — extend the MySQL lease-fencing pattern to Postgres AND
//    tie a stale fencing token to a real refused fenced write.
//
//    Two cluster-provider-db instances on the real PG _blamejs_leader
//    row. Node-A acquires (token 1); a takeover by Node-B after A's lease
//    expires bumps the token to 2. The canonical fenced operation — the
//    audit-tip upsert with `WHERE stored.fencingToken <= EXCLUDED` — is
//    issued by Node-B (token 2) and lands. Then the STALE Node-A (token
//    1) attempts the same fenced upsert: the real PG WHERE clause REFUSES
//    it (RETURNING 0 rows). The stale write does not land; the tip still
//    carries Node-B's token-2 row.
// ======================================================================
async function _proveFencing() {
  _psql(AUDIT_TIP_DDL);
  // Fresh leader table for an isolated fencing sequence. The prior
  // _proveExactlyOnce acquired+released leadership (correctly leaving a
  // released row at fencingToken 1), and the fencing token is monotonic
  // across leadership changes BY DESIGN — so without a reset, A's first
  // acquire here would correctly bump to 2. Drop the row so this proof
  // asserts the 1 -> 2 progression from a clean origin.
  _psql("DROP TABLE IF EXISTS _blamejs_leader;");

  var providerFactory = require("../../lib/cluster-provider-db");
  var pA = providerFactory.create({ externalDbBackend: "ops", dialect: "postgres" });
  var pB = providerFactory.create({ externalDbBackend: "ops", dialect: "postgres" });

  await pA.ensureSchema();
  check("fencing: ensureSchema runs against real postgres", true);

  // Node-A acquires the lease — first acquire issues fencing token 1.
  var leaseA = await pA.acquireLease("node-A", b.constants.TIME.seconds(30));
  check("fencing (PG): A acquired the lease",        leaseA !== null);
  check("fencing (PG): A's fencingToken = 1",        leaseA.fencingToken === 1);
  check("fencing (PG): A is the leader nodeId",      leaseA.nodeId === "node-A");

  // While A holds a live lease, B is blocked by the real ON CONFLICT
  // WHERE expiresAt < now() guard.
  var leaseBblocked = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
  check("fencing (PG): B blocked while A holds a live lease", leaseBblocked === null);

  // A performs a FENCED write at token 1 — the audit-tip upsert. First
  // write: no prior tip row, so the INSERT lands and RETURNING is non-empty.
  var aTipOk = await _fencedAuditTipUpsert(1, "node-A-row-hash-1", leaseA.fencingToken);
  check("fencing (PG): A's fenced audit-tip write at token 1 landed", aTipOk === true);
  var tipAfterA = _psql(
    "SELECT \"fencingToken\", \"rowHash\" FROM _blamejs_audit_tip WHERE \"scope\" = 'audit';");
  check("fencing (PG): tip row reflects A's token-1 write",
        /\b1\b/.test(tipAfterA) && /node-A-row-hash-1/.test(tipAfterA));

  // A's lease expires; B takes over. Use a short TTL on a fresh acquire so
  // the takeover bumps the fencing token to 2 via the real
  // `fencingToken + 1` ON CONFLICT path. (A releases first so B's takeover
  // is deterministic rather than waiting on wall-clock expiry of the 30s
  // lease above.)
  await pA.releaseLease(leaseA);
  var leaseB = await helpers.waitUntil(async function () {
    return await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
  }, { timeoutMs: 15000, label: "fencing (PG): B takes over after A releases" });
  check("fencing (PG): B took over the lease",       leaseB !== null);
  check("fencing (PG): takeover bumped fencingToken to 2",
        leaseB.fencingToken === 2);
  check("fencing (PG): leader is now node-B",        leaseB.nodeId === "node-B");

  // B (the NEW leader, token 2) performs a fenced write — accepted because
  // 2 >= stored 1.
  var bTipOk = await _fencedAuditTipUpsert(2, "node-B-row-hash-2", leaseB.fencingToken);
  check("fencing (PG): B's fenced audit-tip write at token 2 landed (2 >= 1)",
        bTipOk === true);
  var tipAfterB = _psql(
    "SELECT \"fencingToken\", \"rowHash\" FROM _blamejs_audit_tip WHERE \"scope\" = 'audit';");
  check("fencing (PG): tip row now carries B's token-2 write",
        /\b2\b/.test(tipAfterB) && /node-B-row-hash-2/.test(tipAfterB));

  // The STALE leader A (still holding token 1) attempts a fenced write.
  // The real PG `WHERE _blamejs_audit_tip.fencingToken <= EXCLUDED`
  // clause refuses it: stored token is 2, incoming is 1, 2 <= 1 is false,
  // 0 rows affected → fenced out. This is the split-brain old-leader
  // write the fencing token exists to stop.
  var staleAccepted = await _fencedAuditTipUpsert(99, "node-A-STALE-row-hash", leaseA.fencingToken);
  check("fencing (PG): STALE A's fenced write at token 1 was REFUSED by the DB",
        staleAccepted === false);

  // The stale write did NOT land — the tip still carries B's token-2 row,
  // not A's stale hash/counter. This is the real side-effect assertion:
  // the partitioned old leader could not corrupt the chain head.
  var tipAfterStale = _psql(
    "SELECT \"atMonotonicCounter\", \"fencingToken\", \"rowHash\" FROM _blamejs_audit_tip " +
    "WHERE \"scope\" = 'audit';");
  check("fencing (PG): stale write did NOT overwrite the tip (token still 2)",
        /\b2\b/.test(tipAfterStale));
  check("fencing (PG): tip rowHash is still B's, NOT A's stale hash",
        /node-B-row-hash-2/.test(tipAfterStale) &&
        !/node-A-STALE-row-hash/.test(tipAfterStale));
  check("fencing (PG): tip counter is B's (2), not A's stale (99)",
        /^2\b/.test(tipAfterStale.trim()) || /\b2\t/.test(tipAfterStale));

  // Same-token rewrite is permitted (the guard is <=, not <): B re-writes
  // at token 2 with a new counter — confirms the guard fences only
  // STRICTLY-lower tokens, matching _upsertAuditTip's documented contract.
  var bRewriteOk = await _fencedAuditTipUpsert(3, "node-B-row-hash-3", leaseB.fencingToken);
  check("fencing (PG): same-token (2) re-write is accepted (guard is <=, not <)",
        bRewriteOk === true);
  var tipAfterRewrite = _psql(
    "SELECT \"atMonotonicCounter\", \"rowHash\" FROM _blamejs_audit_tip WHERE \"scope\" = 'audit';");
  check("fencing (PG): same-token re-write advanced the counter to 3",
        /^3\b/.test(tipAfterRewrite.trim()) || /\b3\t/.test(tipAfterRewrite) ||
        /node-B-row-hash-3/.test(tipAfterRewrite));

  await pB.releaseLease(leaseB);
}

// Issue the canonical fenced audit-tip upsert against the real PG backend,
// byte-for-byte the SQL shape from lib/audit.js _upsertAuditTip (with $N
// placeholders for the postgres dialect). Returns true if the write landed
// (RETURNING produced a row), false if the DB fenced it out (0 rows).
async function _fencedAuditTipUpsert(counter, rowHash, fencingToken) {
  var result = await b.externalDb.query(
    "INSERT INTO _blamejs_audit_tip " +
    "  (\"scope\", \"atMonotonicCounter\", \"rowHash\", \"signedAt\", \"fencingToken\") " +
    "VALUES ('audit', $1, $2, $3, $4) " +
    "ON CONFLICT (\"scope\") DO UPDATE SET " +
    "  \"atMonotonicCounter\" = EXCLUDED.\"atMonotonicCounter\", " +
    "  \"rowHash\"            = EXCLUDED.\"rowHash\", " +
    "  \"signedAt\"           = EXCLUDED.\"signedAt\", " +
    "  \"fencingToken\"       = EXCLUDED.\"fencingToken\" " +
    "WHERE _blamejs_audit_tip.\"fencingToken\" <= EXCLUDED.\"fencingToken\" " +
    "RETURNING \"fencingToken\"",
    [counter, rowHash, String(Date.now()), fencingToken],
    { backend: "ops" }
  );
  return !!(result.rows && result.rows.length > 0);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
