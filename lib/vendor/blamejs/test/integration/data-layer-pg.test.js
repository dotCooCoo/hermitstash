"use strict";
/**
 * Live data-layer test against the docker Postgres container. Drives the
 * cluster-mode SQL path of the framework's session / cache / nonce /
 * rate-limit primitives end-to-end on a real Postgres server — the path
 * advertised for cluster deployments but which smoke only ever exercises
 * against local SQLite.
 *
 * In cluster mode every one of these primitives composes its SQL through
 * b.sql and dispatches via b.clusterStorage -> b.externalDb -> the
 * operator's Postgres. This test proves:
 *
 *   - b.session         create / verify / touch / rotate / destroy /
 *                       destroyAllForUser / count / purgeExpired, with the
 *                       at-rest sealing (userId/data sealed, userIdHash
 *                       derived) round-tripping through real Postgres.
 *   - b.cache (cluster) get / set (tx upsert + tag) / CAS update /
 *                       invalidateTag (whereLike prefix) / clear / has /
 *                       size / getTags.
 *   - b.nonceStore (cluster) checkAndInsert (ON CONFLICT DO NOTHING atomic
 *                       first-seen) + replay rejection + purgeExpired.
 *   - b.middleware.rateLimit (cluster) take() = ON CONFLICT increment with
 *                       a CASE conflict action + RETURNING + the BIGINT
 *                       count coercing back to a JS number (frameworkSchema
 *                       COLUMN_TYPES) so count<=limit comparisons are
 *                       numeric, not string.
 *
 * The "driver" is a persistent docker-exec psql shim (SQL fed over stdin,
 * never argv) modelled on external-db-postgres.test.js. It faithfully
 * reproduces a real node-postgres driver where it matters: BIGINT comes
 * back as a STRING (clusterStorage.execute then coerces it through
 * frameworkSchema.coerceRows), so a counter compared as a string would be
 * caught. The framework tables are created with
 * frameworkSchema.ensureSchema (real DDL, quoted camelCase columns).
 *
 * RUN: node scripts/test-integration.js --skip-service-check data-layer-pg
 */
var spawn        = require("node:child_process").spawn;
var execFileSync = require("node:child_process").execFileSync;
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var CONTAINER     = "blamejs-test-postgres";
var NULL_SENTINEL = "__BJNULL__";

// Soft assertion: records pass/fail without throwing so every section's
// findings are collected even when an earlier check fails (one real bug in
// one primitive shouldn't hide whether the others work on Postgres). All
// findings are replayed through the hard `check` at the end of run() so the
// file still FAILS when any contract is unmet.
var _findings = [];
function softCheck(label, condition) {
  _findings.push({ label: label, ok: !!condition });
  console.log((condition ? "  ok   " : "  FAIL ") + label);
}
var PSQL_ARGS = "psql -U blamejs -d blamejs_test -A " +
                "-v ON_ERROR_STOP=0 -P null=__BJNULL__ 2>&1";

// ---- one-shot psql (setup / teardown / out-of-band assertions) ----
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

// ---- persistent-session docker-exec psql driver (faithful to pg) ----
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
        var client = { child: child, buf: "", pending: null, closed: false };
        child.on("error", function (e) {
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
  try { parsed = _parseBlock(block); }
  catch (e) { return p.reject(e); }
  if (parsed.error) return p.reject(parsed.error);
  p.resolve({ rows: parsed.rows, rowCount: parsed.rowCount });
}

// Inline params: NULL / numbers raw / booleans / single-quote-escaped.
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

  // dataLines carry a header row first (column names AS POSTGRES REPORTS
  // THEM — quoted DDL preserves the camelCase), then data rows. Every cell
  // stays a STRING — exactly the shape node-postgres returns for BIGINT
  // (int8) columns, so clusterStorage's coerceRows is what must turn the
  // framework's int columns back into JS numbers.
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

// Every framework table frameworkSchema.ensureSchema creates — dropped in
// setup AND teardown so the run starts clean and leaves the shared test
// database clean for sibling Postgres tests (which create their own
// tables). The primitives under test only touch sessions / cache /
// cache_tags / nonces / rate-limit counters, but ensureSchema materializes
// the whole framework surface, so all of it is swept.
var FRAMEWORK_TABLES = [
  "_blamejs_sessions", "_blamejs_cache", "_blamejs_cache_tags",
  "_blamejs_api_encrypt_nonces", "_blamejs_rate_limit_counters",
  "_blamejs_audit_log", "_blamejs_consent_log", "_blamejs_audit_checkpoints",
  "_blamejs_audit_tip", "_blamejs_consent_tip", "_blamejs_audit_purge_anchor",
  "_blamejs_scheduler_ticks", "_blamejs_pubsub_messages", "_blamejs_api_keys",
  "_blamejs_jobs", "_blamejs_seeders", "_blamejs_seeders_lock",
  "_blamejs_break_glass_policies", "_blamejs_break_glass_grants",
  // cluster.init's default DB-row leader-election provider creates these.
  "_blamejs_leader", "_blamejs_cluster_state",
];

var rateLimitModule = require("../../lib/middleware/rate-limit");

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  // Drop our framework tables so the run starts clean.
  _psql(FRAMEWORK_TABLES.map(function (t) {
    return "DROP TABLE IF EXISTS " + t + " CASCADE;";
  }).join("\n"));

  // Full-framework bring-up (vault + db + cryptoField). db.init registers
  // the _blamejs_sessions sealedFields (userId, data) + derived userIdHash,
  // which b.session uses to seal/derive regardless of which backend the SQL
  // routes to. The local SQLite db it opens is unused once cluster mode is
  // active (session SQL dispatches to Postgres) but the cryptoField
  // registry it populates is exactly what session needs.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-datalayer-pg-"));
  await helpers.setupTestDb(tmpDir);

  var driver = _makeDockerPgDriver();
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "postgres",
      },
    },
  });

  // Create the framework tables on real Postgres via the real DDL builder.
  await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "postgres" });

  // Cluster mode: the framework's session/cache/nonce/rate-limit SQL now
  // routes through clusterStorage -> externalDb -> Postgres. cluster.init
  // runs a boot-time rollback check against the (empty) audit/consent tips
  // ensureSchema just created; with no tip row it skips cleanly.
  await b.cluster.init({
    nodeId:            "pg-data-node",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
    externalDbBackend: "ops",
    dialect:           "postgres",
    // This node's vault keypair is freshly minted in tmpDir; accept it as
    // the canonical cluster vault key rather than refusing on first boot.
    acceptVaultKeyRotation: true,
  });
  softCheck("cluster is in cluster mode (state routes to Postgres)",
        b.cluster.isClusterMode() === true);
  softCheck("cluster reports leadership on real Postgres", b.cluster.isLeader() === true);

  try {
    await _section("session", _testSession);
    await _section("cache", _testCacheCluster);
    await _section("nonce", _testNonceCluster);
    await _section("rate-limit", _testRateLimitCluster);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    b.cluster._resetForTest();
    try { await b.externalDb.shutdown(); } catch (_e) {}
    try { await helpers.teardownTestDb(tmpDir); } catch (_e) {}
    _psql(FRAMEWORK_TABLES.map(function (t) {
      return "DROP TABLE IF EXISTS " + t + " CASCADE;";
    }).join("\n"));
  }

  // Replay every recorded finding through the hard `check` so the file
  // FAILS (and the runner reports it) when any contract is unmet. All
  // findings have already been printed above.
  var failures = _findings.filter(function (f) { return !f.ok; });
  console.log("");
  console.log("[data-layer-pg] " + (_findings.length - failures.length) + "/" +
    _findings.length + " checks ok; " + failures.length + " failing");
  for (var i = 0; i < _findings.length; i++) {
    check(_findings[i].label, _findings[i].ok);
  }
}

// Run one primitive's section; a thrown driver error becomes a single
// FAILED finding so an unexpected error in one section doesn't hide the
// others' results.
async function _section(label, fn) {
  try {
    await fn();
  } catch (e) {
    softCheck(label + "(pg): section completed without an unexpected error " +
      "— DETAIL: " + (((e && e.message) || String(e)).split(/\r?\n/)[0]), false);
  }
}

// ======================================================================
// b.session full lifecycle on real Postgres (sealed at rest).
// ======================================================================
async function _testSession() {
  // create -> returns a sealed-cookie token; the DB row keys on sha3(sid),
  // userId+data sealed, userIdHash derived.
  var created = await b.session.create({
    userId: "user-42",
    data:   { roles: ["admin"], theme: "dark" },
    ttlMs:  b.constants.TIME.hours(8),
  });
  softCheck("session(pg): create returns a sealed token + expiry",
        created && typeof created.token === "string" &&
        created.token.indexOf("vault:") === 0 && typeof created.expiresAt === "number");

  // The row physically landed on Postgres; userId is NOT plaintext.
  var rawRows = _psql('SELECT "userId", "userIdHash" FROM _blamejs_sessions;');
  softCheck("session(pg): a session row physically landed on Postgres",
        rawRows.trim().length > 0);
  softCheck("session(pg): userId is sealed at rest (NOT the plaintext 'user-42')",
        rawRows.indexOf("user-42") === -1);

  // verify -> unseal round-trips userId + data through Postgres.
  var info = await b.session.verify(created.token);
  softCheck("session(pg): verify unseals userId from the Postgres row",
        info && info.userId === "user-42");
  softCheck("session(pg): verify unseals the data payload",
        info && info.data && info.data.roles && info.data.roles[0] === "admin" &&
        info.data.theme === "dark");
  softCheck("session(pg): verify coerces createdAt/expiresAt to JS numbers " +
        "(BIGINT-as-string would break the timeout math)",
        typeof info.createdAt === "number" && typeof info.expiresAt === "number" &&
        info.expiresAt > info.createdAt);

  // count -> the live session is counted (BIGINT count coerced to number).
  var liveCount = await b.session.count();
  softCheck("session(pg): count() returns the one live session as a JS number",
        typeof liveCount === "number" && liveCount === 1);

  // touch with extendBy -> bumps lastActivity + expiresAt; affectedRows>0.
  var touched = await b.session.touch(created.token, { extendBy: b.constants.TIME.hours(12) });
  softCheck("session(pg): touch() updated the live row (returned true)", touched === true);
  var afterTouch = await b.session.verify(created.token);
  softCheck("session(pg): touch extended expiresAt past the original",
        afterTouch && afterTouch.expiresAt >= created.expiresAt);

  // rotate -> new sid swapped atomically; old token no longer verifies.
  var rotated = await b.session.rotate(created.token, { reason: "mfa" });
  softCheck("session(pg): rotate returns a fresh sealed token",
        rotated && typeof rotated.token === "string" && rotated.token !== created.token);
  softCheck("session(pg): the OLD token no longer verifies after rotate",
        (await b.session.verify(created.token)) === null);
  var rotatedInfo = await b.session.verify(rotated.token);
  softCheck("session(pg): the NEW token verifies with the same userId",
        rotatedInfo && rotatedInfo.userId === "user-42");

  // updateData -> writes the sealed data column without rotating the sid.
  // The SELECT-then-UPDATE both dialect-thread through _sessionSqlOpts(); the
  // data column round-trips through the sealed Postgres TEXT column.
  var updated = await b.session.updateData(rotated.token, { roles: ["admin"], step: "mfa-done" });
  softCheck("session(pg): updateData wrote the sealed data column (returned true)",
        updated === true);
  var afterUpdate = await b.session.verify(rotated.token);
  softCheck("session(pg): updateData payload round-trips through the sealed Postgres column",
        afterUpdate && afterUpdate.data && afterUpdate.data.step === "mfa-done");

  // destroyAllForUser -> deletes via the derived userIdHash; count drops.
  var revoked = await b.session.destroyAllForUser("user-42");
  softCheck("session(pg): destroyAllForUser deleted the session via userIdHash",
        revoked === 1);
  softCheck("session(pg): the session no longer verifies after revoke-all",
        (await b.session.verify(rotated.token)) === null);
  softCheck("session(pg): count() is 0 after revoke-all", (await b.session.count()) === 0);

  // destroy single + purgeExpired side-effects.
  var s2 = await b.session.create({ userId: "user-99", ttlMs: b.constants.TIME.hours(1) });
  softCheck("session(pg): destroy(token) returns true for a live session",
        (await b.session.destroy(s2.token)) === true);
  softCheck("session(pg): destroy is idempotent (second destroy returns false)",
        (await b.session.destroy(s2.token)) === false);

  // Insert an already-expired session directly so purgeExpired has work.
  var expiredSidRow = await b.session.create({ userId: "user-exp", ttlMs: b.constants.TIME.hours(1) });
  void expiredSidRow;
  _psql('UPDATE _blamejs_sessions SET "expiresAt" = 1 WHERE "expiresAt" > 1;');
  var purged = await b.session.purgeExpired();
  softCheck("session(pg): purgeExpired removed the expired row(s) (>=1)", purged >= 1);
  softCheck("session(pg): count() is 0 after purge", (await b.session.count()) === 0);
}

// ======================================================================
// b.cache cluster backend on real Postgres.
// ======================================================================
async function _testCacheCluster() {
  var cache = b.cache.create({ backend: "cluster", namespace: "pgns", ttlMs: b.constants.TIME.minutes(5) });

  await cache.set("k1", { hello: "world", n: 42 });
  var got = await cache.get("k1");
  softCheck("cache(pg): set + get JSON round-trips on real Postgres",
        got && got.hello === "world" && got.n === 42);

  var rowDirect = _psql("SELECT \"valueJson\" FROM _blamejs_cache WHERE \"cacheKey\" = 'pgns:k1';");
  softCheck("cache(pg): row physically present under the composite key",
        /"hello"/.test(rowDirect));

  softCheck("cache(pg): has() returns true for a live key", (await cache.has("k1")) === true);
  softCheck("cache(pg): del() removes the key", (await cache.del("k1")) === true);
  softCheck("cache(pg): get() after del is undefined", (await cache.get("k1")) === undefined);

  // tags + invalidateTag (whereLike prefix scoping).
  await cache.set("a", "1", { tags: ["grp-x"] });
  await cache.set("bk", "2", { tags: ["grp-x", "grp-y"] });
  await cache.set("ck", "3", { tags: ["grp-y"] });
  var tagsA = await cache.getTags("a");
  softCheck("cache(pg): getTags returns the tags written for a key",
        Array.isArray(tagsA) && tagsA.indexOf("grp-x") !== -1);

  var purged = await cache.invalidateTag("grp-x");
  softCheck("cache(pg): invalidateTag purged the grp-x keys (>=2)", purged >= 2);
  softCheck("cache(pg): invalidateTag dropped a + bk",
        (await cache.get("a")) === undefined && (await cache.get("bk")) === undefined);
  softCheck("cache(pg): invalidateTag preserved grp-y-only key ck",
        (await cache.get("ck")) === "3");

  // atomic update (CAS) increment.
  await cache.update("counter", function (n) { return { value: (n || 0) + 1 }; });
  await cache.update("counter", function (n) { return { value: (n || 0) + 1 }; });
  softCheck("cache(pg): atomic update() increments through transaction+CAS",
        (await cache.get("counter")) === 2);

  // size() counts only live namespaced rows.
  var sz = await cache.size();
  softCheck("cache(pg): size() counts live namespaced rows as a number",
        typeof sz === "number" && sz >= 1);

  var cleared = await cache.clear();
  softCheck("cache(pg): clear() wiped the namespace (>=1)", cleared >= 1);
  softCheck("cache(pg): get after clear is undefined", (await cache.get("ck")) === undefined);

  await cache.close();
}

// ======================================================================
// b.nonceStore cluster backend on real Postgres.
// ======================================================================
async function _testNonceCluster() {
  var store = b.nonceStore.create({ backend: "cluster" });
  var future = Date.now() + b.constants.TIME.minutes(10);

  softCheck("nonce(pg): first checkAndInsert returns true (unseen)",
        (await store.checkAndInsert("nonce-aaa", future)) === true);
  var n1 = _psql("SELECT count(*) AS n FROM _blamejs_api_encrypt_nonces WHERE \"nonceHash\" = 'nonce-aaa';");
  softCheck("nonce(pg): the nonce row physically landed", /\b1\b/.test(n1.trim()));

  softCheck("nonce(pg): replay of the same nonce returns false (ON CONFLICT DO NOTHING)",
        (await store.checkAndInsert("nonce-aaa", future)) === false);
  softCheck("nonce(pg): a distinct nonce is accepted",
        (await store.checkAndInsert("nonce-bbb", future)) === true);

  await store.checkAndInsert("nonce-expired", Date.now() - 1000);
  var purged = await store.purgeExpired();
  softCheck("nonce(pg): purgeExpired removed the expired nonce (>=1)", purged >= 1);
  softCheck("nonce(pg): a live nonce still rejects replay after purge",
        (await store.checkAndInsert("nonce-aaa", future)) === false);

  store.close();
}

// ======================================================================
// b.middleware.rateLimit cluster backend on real Postgres.
//   take() = ON CONFLICT increment with a CASE conflict action +
//   RETURNING; the returned BIGINT count must coerce to a JS number so
//   count<=limit is a numeric comparison (a string "10" <= 3 would be a
//   silent always-allow).
// ======================================================================
async function _testRateLimitCluster() {
  var backend = rateLimitModule._clusterBackend({
    backend: "cluster", limit: 3, windowMs: b.constants.TIME.minutes(1),
  });

  var v1 = await backend.take("ratekey-1", 1);
  softCheck("rate-limit(pg): first take() is allowed against real Postgres",
        v1 && v1.allowed === true);
  softCheck("rate-limit(pg): the take() verdict count math is numeric " +
        "(remaining is a finite number, not NaN from a string compare)",
        typeof v1.remaining === "number" && isFinite(v1.remaining) && v1.remaining === 2);

  var rowAfter1 = _psql("SELECT \"count\" FROM _blamejs_rate_limit_counters WHERE \"key\" = 'ratekey-1';");
  softCheck("rate-limit(pg): counter row landed with count=1", /\b1\b/.test(rowAfter1.trim()));

  var v2 = await backend.take("ratekey-1", 1);
  var v3 = await backend.take("ratekey-1", 1);
  var v4 = await backend.take("ratekey-1", 1);
  softCheck("rate-limit(pg): 2nd + 3rd allowed, 4th over the limit refused",
        v2.allowed === true && v3.allowed === true && v4.allowed === false);
  softCheck("rate-limit(pg): the over-limit verdict carries a positive retryAfter",
        typeof v4.retryAfter === "number" && v4.retryAfter > 0);
  var rowAfter4 = _psql("SELECT \"count\" FROM _blamejs_rate_limit_counters WHERE \"key\" = 'ratekey-1';");
  softCheck("rate-limit(pg): counter incremented monotonically to 4",
        /\b4\b/.test(rowAfter4.trim()));

  // A window advance resets the count (the CASE conflict action's
  // window-rollover branch). Force a stale window then take() again.
  _psql("UPDATE _blamejs_rate_limit_counters SET \"windowStart\" = 0 WHERE \"key\" = 'ratekey-1';");
  var vReset = await backend.take("ratekey-1", 1);
  softCheck("rate-limit(pg): a fresh window resets the count (CASE rollover) — allowed again",
        vReset.allowed === true);
  var rowAfterReset = _psql("SELECT \"count\" FROM _blamejs_rate_limit_counters WHERE \"key\" = 'ratekey-1';");
  softCheck("rate-limit(pg): count reset to 1 on window advance",
        /\b1\b/.test(rowAfterReset.trim()));

  // A distinct key is tracked independently.
  var other = await backend.take("ratekey-2", 1);
  softCheck("rate-limit(pg): a distinct key is counted independently",
        other.allowed === true && other.remaining === 2);

  if (typeof backend.close === "function") backend.close();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
