// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live Postgres proof that the b.sql data-layer migration of the five
 * privacy/identity modules emits SQL that actually RUNS against a real
 * Postgres server — not just sqlite host smoke. These modules build their
 * statements with b.sql and either dispatch through b.clusterStorage (the
 * external-db path — api-key registry, consent fenced tip) or run the
 * same b.sql builders at { dialect: "postgres" } against the operator's
 * external DB. This test drives BOTH shapes end-to-end on the docker
 * Postgres container.
 *
 *   - api-key:    issue / verify (lastUsedAt touch) / rotate (graceful +
 *                 hard cutover) / revoke / whereGroup-OR purge — driven
 *                 through the REAL b.apiKey.create() registry in cluster
 *                 mode so the module's own clusterStorage dispatch + the
 *                 BIGINT->JS-number coercion run against live Postgres.
 *   - consent:    the fenced tip upsert (_upsertConsentTip shape) — INSERT
 *                 ... ON CONFLICT(scope) DO UPDATE ... WHERE
 *                 _blamejs_consent_tip."fencingToken" <= EXCLUDED... RETURNING.
 *                 The fence MUST reject a lower fencing token (0 rows) and
 *                 accept a higher one (1 row) on the real planner.
 *   - legal-hold: place INSERT / release DELETE / whereLike("action",
 *                 "legalhold.", "prefix") history prefix-match with ESCAPE.
 *   - subject:    the INSERT-OR-REPLACE upsert (_markErased shape) + the
 *                 restrict INSERT/DELETE presence pattern.
 *   - retention:  hard delete / soft-delete UPDATE / erase NULL-set /
 *                 cascade DELETE / the whereGroup-OR candidate WHERE.
 *
 * The driver is a persistent docker-exec psql shim faithful to a real
 * node-postgres driver's coercions (BIGINT/int8 -> JS string, so the
 * framework's clusterStorage.coerceRows must turn it back into a number;
 * a real NULL distinguished from empty string). SQL travels on stdin,
 * never argv (no shell parse of SQL). Tables are namespaced + DROP/
 * recreated in setup/teardown so concurrent integration tests don't
 * collide.
 */

var spawn        = require("node:child_process").spawn;
var execFileSync = require("node:child_process").execFileSync;
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var cryptoField = require("../../lib/crypto-field");
var b = require("../../");

var CONTAINER = "blamejs-test-postgres";
var NULL_SENTINEL = "__BJNULL__";
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

// Inline params: numbers raw, null -> NULL, everything else single-quote
// escaped. Every test value is operator-controlled.
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
var _CTRL_TAG_RE = /^(BEGIN|COMMIT|ROLLBACK|SET|RESET|SAVEPOINT|RELEASE|START|CREATE|DROP|ALTER|GRANT|REVOKE|TRUNCATE|COMMENT|DO|CALL|VACUUM|ANALYZE|EXPLAIN|TABLE|SHOW|DISCARD|REINDEX)\b/;

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
        if (cell === NULL_SENTINEL || cell === undefined) { row[headers[c]] = null; continue; }
        // STRING by default — matches node-postgres int8-as-string default.
        // The framework's clusterStorage.coerceRows turns the int columns
        // back into JS numbers; leaving them strings here is the real-pg shape.
        row[headers[c]] = cell;
      }
      rows.push(row);
    }
  }
  var rowCount = (affected !== null) ? affected : rows.length;
  return { rows: rows, rowCount: rowCount, error: null };
}

// Reset the framework-state singletons each backend run touches.
function _resetState() {
  try { b.cluster._resetForTest(); } catch (_e) {}
  try { b.consent._resetForTest(); } catch (_e) {}
  try { b.externalDb._resetForTest(); } catch (_e) {}
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  // Namespaced tables — distinct names + the framework's own prefixed
  // names this test owns. DROP first so a prior crash can't poison us.
  var DROP_ALL = [
    "_blamejs_api_keys", "_blamejs_consent_tip",
    "_blamejs_leader", "_blamejs_cluster_state",
    "dl_pg_hold", "dl_pg_erasures", "dl_pg_restrictions",
    "dl_pg_audit", "dl_pg_orders", "dl_pg_order_lines",
  ].map(function (t) { return "DROP TABLE IF EXISTS " + t + " CASCADE;"; }).join("\n");
  _psql(DROP_ALL);

  _resetState();

  // Init the framework vault (plaintext mode for the test) + register the
  // api-key registry's cryptoField schema so sealRow seals ownerId/scopes/
  // metadata and derives ownerIdHash — exactly what db.js's FRAMEWORK_SCHEMA
  // wires for the local path. Without it the issued row's NOT-NULL
  // ownerIdHash is null and the live INSERT rejects.
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dl-pg-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  cryptoField.registerTable("_blamejs_api_keys", {
    sealedFields:  ["ownerId", "scopes", "metadata"],
    derivedHashes: { ownerIdHash: { from: "ownerId" } },
  });

  var driver = _makeDockerPgDriver();
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "postgres",
      },
    },
  });

  // Direct backend query helper. b.sql emits `?` placeholders; the external-db
  // query path does NOT translate them (that is clusterStorage's job on the
  // cluster dispatch). For statements we run straight against the backend
  // (the local-builder shapes — legal-hold / subject / retention — and the
  // raw DDL), placeholderize `?`->`$N` for Postgres exactly as clusterStorage
  // would, so the live driver binds correctly.
  var clusterStorage = require("../../lib/cluster-storage");
  function _q(built) {
    return b.externalDb.query(
      clusterStorage.placeholderize(built.sql, "postgres"), built.params, { backend: "ops" });
  }

  // ====================================================================
  // api-key — drive the REAL b.apiKey.create() registry in CLUSTER mode
  // so issue/verify/rotate/revoke/purge dispatch through the module's
  // clusterStorage path to live Postgres. Coercion (BIGINT->number) is
  // exercised by verify()/getById reading createdAt/expiresAt back.
  // ====================================================================
  // Create the _blamejs_api_keys table on the real server via b.sql DDL
  // at the postgres dialect (the framework ships this schema for cluster
  // mode; ensureSchema would also create it, but building it directly
  // proves the b.sql createTable shape runs on Postgres too).
  var apiKeysDdl = b.sql.createTable("_blamejs_api_keys", [
    { name: "id",                  type: "text", primaryKey: true },
    { name: "namespace",           type: "text", notNull: true },
    { name: "ownerId",             type: "text", notNull: true },
    { name: "ownerIdHash",         type: "text", notNull: true },
    { name: "secretHash",          type: "text", notNull: true },
    { name: "secondarySecretHash", type: "text" },
    { name: "secondaryExpiresAt",  type: "int" },
    { name: "scopes",              type: "text" },
    { name: "metadata",            type: "text" },
    { name: "createdAt",           type: "int", notNull: true },
    { name: "expiresAt",           type: "int" },
    { name: "revokedAt",           type: "int" },
    { name: "lastUsedAt",          type: "int" },
    { name: "prefix",              type: "text", notNull: true },
  ], { dialect: "postgres", quoteName: true });
  // Run DDL through the external-db query path (DDL goes direct on the backend).
  await _q(apiKeysDdl);
  check("api-key: b.sql createTable DDL ran on real Postgres", true);

  // Cluster mode so b.apiKey.create() dispatches to external-db "ops".
  await b.cluster.init({
    nodeId: "dl-pg-node", role: "leader",
    externalDbBackend: "ops", dialect: "postgres",
  });
  check("api-key: cluster.init leader on real Postgres", b.cluster.isLeader() === true);

  var keys = b.apiKey.create({ namespace: "live", prefix: "bk" });

  var nowMs = Date.now();
  var issued = await keys.issue({
    ownerId:   "owner-1",
    scopes:    ["read:x", "write:y"],
    metadata:  { name: "device A" },
    expiresAt: nowMs + b.constants.TIME.days(30),
  });
  check("api-key: issue returns a composed key", typeof issued.key === "string" && issued.key.indexOf("bk_live_") === 0);
  var idHex = issued.id;

  // Row physically present on the server.
  var apiRowCount = _psql("SELECT count(*) AS n FROM _blamejs_api_keys WHERE namespace = 'live';");
  check("api-key: issued row is physically in _blamejs_api_keys on Postgres", /\b1\b/.test(apiRowCount.trim()));

  // verify() — drives SELECT + the trackLastUsedAt UPDATE; the returned
  // record's numeric columns must come back as JS numbers (coercion).
  var rec = await keys.verify(issued.key);
  check("api-key: verify() succeeds against live Postgres", rec !== null && rec.id === idHex);
  // The BIGINT round-trip: createdAt/expiresAt were written as int columns;
  // node-postgres returns them as decimal STRINGS, and the framework's
  // coerceRows + _scrubRecord must hand back the exact JS numbers issue()
  // wrote. Assert against issue()'s own returned values (the registry's
  // internal clock, not the test's nowMs which can differ by a few ms).
  check("api-key: verify() coerces createdAt BIGINT -> the exact JS number issued",
        typeof rec.createdAt === "number" && rec.createdAt === issued.createdAt);
  check("api-key: verify() coerces expiresAt BIGINT -> the exact JS number issued",
        typeof rec.expiresAt === "number" && rec.expiresAt === issued.expiresAt &&
        rec.expiresAt === nowMs + b.constants.TIME.days(30));

  // lastUsedAt UPDATE took effect on the server (was NULL at issue).
  var luRow = _psql('SELECT "lastUsedAt" FROM _blamejs_api_keys WHERE namespace = \'live\';');
  check("api-key: trackLastUsedAt UPDATE persisted a non-null lastUsedAt",
        !new RegExp("\\b" + NULL_SENTINEL + "\\b").test(luRow.trim()) && /\d{6,}/.test(luRow.trim()));

  // rotate() graceful — moves secret into the secondary slot with a TTL.
  var rotated = await keys.rotate(idHex, { graceful: true });
  check("api-key: graceful rotate returns a new key + secondaryExpiresAt",
        typeof rotated.key === "string" && typeof rotated.secondaryExpiresAt === "number");
  // The OLD key still verifies via the secondary slot.
  var oldStillWorks = await keys.verify(issued.key);
  check("api-key: old secret verifies via the secondary slot after graceful rotate",
        oldStillWorks !== null && oldStillWorks.usedSecondary === true);
  // The NEW key verifies via the primary slot.
  var newWorks = await keys.verify(rotated.key);
  check("api-key: new secret verifies via the primary slot",
        newWorks !== null && newWorks.usedSecondary === false);
  // secondaryExpiresAt physically set on the server (int column).
  var secRow = _psql('SELECT "secondaryExpiresAt" FROM _blamejs_api_keys WHERE namespace = \'live\';');
  check("api-key: graceful rotate persisted secondaryExpiresAt on Postgres",
        /\d{6,}/.test(secRow.trim()));

  // rotate() hard cutover — clears the secondary slot; the old key dies.
  var cutover = await keys.rotate(idHex, {});
  check("api-key: hard-cutover rotate returns a key with no grace",
        cutover.secondaryExpiresAt === null);
  var oldDead = await keys.verify(issued.key);
  check("api-key: after hard cutover the original secret no longer verifies", oldDead === null);
  var cutoverWorks = await keys.verify(cutover.key);
  check("api-key: the cutover key verifies via primary", cutoverWorks !== null);
  var secCleared = _psql('SELECT "secondarySecretHash" FROM _blamejs_api_keys WHERE namespace = \'live\';');
  check("api-key: hard cutover NULLed secondarySecretHash on Postgres",
        new RegExp("\\b" + NULL_SENTINEL + "\\b").test(secCleared.trim()));

  // Issue a few more keys for the whereGroup-OR purge predicate. Expired
  // + revoked keys past the threshold should purge; a fresh key stays.
  var oldExpired = await keys.issue({ ownerId: "owner-2", expiresAt: 1 });               // long expired
  var freshKey   = await keys.issue({ ownerId: "owner-3", expiresAt: nowMs + b.constants.TIME.days(365) });
  var toRevoke   = await keys.issue({ ownerId: "owner-4" });
  await keys.revoke(toRevoke.id);
  // Backdate the revoked key's revokedAt below the purge threshold so the
  // OR-group predicate selects it. purgeAfterMs default is 90d. ownerId is
  // a SEALED column, so key the UPDATE on the non-sealed composite `id`
  // ("<namespace>:<idHex>"), not the plaintext ownerId (which never matches
  // the sealed blob on disk).
  _psql('UPDATE _blamejs_api_keys SET "revokedAt" = 1 WHERE "id" = \'live:' + toRevoke.id + '\';');

  var beforePurge = Number(_psql("SELECT count(*) AS n FROM _blamejs_api_keys;").trim());
  var purged = await keys.purgeExpired();
  // The OR predicate matches owner-2 (expiresAt=1 < threshold) AND owner-4
  // (revokedAt=1 < threshold) — exactly 2 rows.
  check("api-key: whereGroup-OR purge removed the expired + old-revoked keys on Postgres",
        purged >= 2);
  var afterPurge = Number(_psql("SELECT count(*) AS n FROM _blamejs_api_keys;").trim());
  check("api-key: purge physically deleted rows (count dropped)", afterPurge < beforePurge);
  // The fresh, non-expired, non-revoked key must survive the OR-predicate.
  var freshSurvives = await keys.verify(freshKey.key);
  check("api-key: the fresh non-expired key survived the purge predicate", freshSurvives !== null);
  void oldExpired;

  // listForOwner — exercises the OR group (expiresAt IS NULL OR >= now) on
  // the live planner.
  var owned = await keys.listForOwner("owner-3");
  check("api-key: listForOwner returns the fresh key for owner-3 on Postgres",
        owned.length === 1 && owned[0].id === freshKey.id);

  // ====================================================================
  // consent — the fenced tip upsert. The fence is the security-critical
  // shape: a lower fencingToken must be REJECTED (RETURNING 0 rows), a
  // higher one ACCEPTED (1 row). Run the EXACT _upsertConsentTip SQL
  // through the external-db path so the real Postgres planner evaluates
  // the WHERE _blamejs_consent_tip."fencingToken" <= EXCLUDED... fence.
  // ====================================================================
  var consentTipDdl = b.sql.createTable("_blamejs_consent_tip", [
    { name: "scope",              type: "text", primaryKey: true },
    { name: "atMonotonicCounter", type: "int", notNull: true },
    { name: "rowHash",            type: "text" },
    { name: "signedAt",           type: "text" },
    { name: "fencingToken",       type: "int", notNull: true },
  ], { dialect: "postgres", quoteName: true });
  await _q(consentTipDdl);

  var safeSql = require("../../lib/safe-sql");
  function _tipUpsertSql(counter, rowHash, signedAt, fencingToken) {
    var tipFence = "_blamejs_consent_tip." + safeSql.quoteIdentifier("fencingToken") +
      " <= EXCLUDED." + safeSql.quoteIdentifier("fencingToken");
    return b.sql.upsert("_blamejs_consent_tip", { dialect: "postgres" })
      .columns(["scope", "atMonotonicCounter", "rowHash", "signedAt", "fencingToken"])
      .values({ scope: "consent", atMonotonicCounter: counter, rowHash: rowHash, signedAt: signedAt, fencingToken: fencingToken })
      .onConflict(["scope"])
      .doUpdateFromExcluded(["atMonotonicCounter", "rowHash", "signedAt", "fencingToken"])
      .conflictWhere(tipFence, [])
      .returning(["fencingToken"])
      .toSql();
  }
  async function _runTip(counter, rowHash, signedAt, fencingToken) {
    var built = _tipUpsertSql(counter, rowHash, signedAt, fencingToken);
    return await _q(built);
  }

  // First insert at token 1 — RETURNING yields the row (the initial INSERT).
  var t1 = await _runTip(1, "hash-1", "1700000000001", 1);
  check("consent-tip: initial upsert RETURNING produced 1 row on Postgres", t1.rows.length === 1);

  // Higher token (2) — fence passes, tip advances, RETURNING 1 row.
  var t2 = await _runTip(2, "hash-2", "1700000000002", 2);
  check("consent-tip: higher fencingToken accepted (RETURNING 1 row)", t2.rows.length === 1);
  var tipState = _psql('SELECT "atMonotonicCounter", "fencingToken" FROM _blamejs_consent_tip WHERE scope = \'consent\';');
  check("consent-tip: tip advanced to counter 2 / token 2 on the server",
        /\b2\t2\b/.test(tipState.trim()) || /2\s+2/.test(tipState.trim()));

  // LOWER token (1) — the FENCE must reject: WHERE stored <= EXCLUDED is
  // false (2 <= 1 false) -> DO UPDATE skipped -> RETURNING 0 rows. This is
  // the partitioned-old-leader defense; consent.js throws FENCED_OUT on 0.
  var t3 = await _runTip(99, "hash-evil", "1700000000099", 1);
  check("consent-tip: FENCE rejects a lower fencingToken (RETURNING 0 rows) on Postgres",
        t3.rows.length === 0);
  var tipUnchanged = _psql('SELECT "atMonotonicCounter", "rowHash" FROM _blamejs_consent_tip WHERE scope = \'consent\';');
  check("consent-tip: a fenced-out write did NOT overwrite the tip (still hash-2/counter-2)",
        /hash-2/.test(tipUnchanged.trim()) && !/hash-evil/.test(tipUnchanged.trim()));

  // Equal token (2) — fence is <= so an equal token is accepted (idempotent
  // re-write of the same leader's tip), RETURNING 1 row.
  var t4 = await _runTip(3, "hash-3", "1700000000003", 2);
  check("consent-tip: equal fencingToken accepted by <= fence (RETURNING 1 row)", t4.rows.length === 1);

  // Prove the framework reads this back coerced: fencingToken is an int
  // column -> coerceRows turns the RETURNING string into a JS number. Read
  // through clusterStorage.execute (the real consent-verify path) which
  // placeholderizes + coerces in cluster mode.
  var tipReadBuilt = b.sql.select("_blamejs_consent_tip", { dialect: "postgres", quoteName: true })
    .columns(["atMonotonicCounter", "fencingToken"])
    .where("scope", "consent")
    .toSql();
  var tipRead = await clusterStorage.execute(tipReadBuilt.sql, tipReadBuilt.params);
  check("consent-tip: clusterStorage.execute coerces fencingToken -> JS number reading back",
        tipRead.rows.length === 1 && typeof tipRead.rows[0].fencingToken === "number" &&
        tipRead.rows[0].fencingToken === 2);

  // Prove the fence is dialect-threaded from the MODULE: rebuild the exact
  // upsert the way consent._upsertConsentTip does for the ACTIVE dialect
  // (clusterStorage.dialect() === "postgres" here) — guardColumn + the
  // EXCLUDED fence — and run it through clusterStorage.execute (the module's
  // own dispatch path). A lower token must still be fenced out (RETURNING 0
  // rows) on the real planner, identical to what the module emits at runtime.
  function _moduleTipUpsert(counter, rowHash, signedAt, fencingToken) {
    var d = clusterStorage.dialect();
    var qf = safeSql.quoteIdentifier("fencingToken", d);
    var fence = d === "mysql"
      ? "_blamejs_consent_tip." + qf + " <= VALUES(" + qf + ")"
      : "_blamejs_consent_tip." + qf + " <= EXCLUDED." + qf;
    return b.sql.upsert("_blamejs_consent_tip", { dialect: d })
      .columns(["scope", "atMonotonicCounter", "rowHash", "signedAt", "fencingToken"])
      .values({ scope: "consent", atMonotonicCounter: counter, rowHash: rowHash, signedAt: signedAt, fencingToken: fencingToken })
      .onConflict(["scope"])
      .doUpdateFromExcluded(["atMonotonicCounter", "rowHash", "signedAt", "fencingToken"])
      .conflictWhere(fence, [], { guardColumn: "fencingToken" })
      .returning(["fencingToken"])
      .toSql();
  }
  var modLower = _moduleTipUpsert(99, "hash-evil-mod", "1700000000099", 1);
  var modLowerRes = await clusterStorage.execute(modLower.sql, modLower.params);
  check("consent-tip: the module-shaped (clusterStorage.dialect()) fence rejects a lower token on Postgres",
        modLowerRes.rows.length === 0);
  var modHigher = _moduleTipUpsert(5, "hash-5-mod", "1700000000005", 5);
  var modHigherRes = await clusterStorage.execute(modHigher.sql, modHigher.params);
  check("consent-tip: the module-shaped fence accepts a higher token (RETURNING 1 row) on Postgres",
        modHigherRes.rows.length === 1);
  var modTipState = _psql('SELECT "rowHash", "fencingToken" FROM _blamejs_consent_tip WHERE scope = \'consent\';');
  check("consent-tip: the module-shaped advance landed hash-5-mod / token 5 on the server",
        /hash-5-mod/.test(modTipState.trim()) && !/hash-evil-mod/.test(modTipState.trim()));

  // Tear down cluster mode before the local-builder shapes (legal-hold /
  // subject / retention) which we drive directly on the backend.
  await b.cluster.shutdown();
  _resetState();
  b.externalDb.init({
    backends: { ops: { connect: driver.connect, query: driver.query, close: driver.close, dialect: "postgres" } },
  });

  // ====================================================================
  // legal-hold — place INSERT / release DELETE / whereLike prefix history.
  // legal-hold's builders run against a local b.db handle in production,
  // but the b.sql shapes must still be valid Postgres. Build them at the
  // postgres dialect and run on the live server.
  // ====================================================================
  var holdDdl = b.sql.createTable("dl_pg_hold", [
    { name: "subjectIdHash", type: "text", primaryKey: true },
    { name: "placedAt",      type: "int",  notNull: true },
    { name: "placedBy",      type: "text" },
    { name: "reason",        type: "text", notNull: true },
    { name: "custodian",     type: "text" },
    { name: "citation",      type: "text" },
    { name: "retainUntil",   type: "int" },
  ], { dialect: "postgres", quoteName: true });
  await _q(holdDdl);

  // place(): the SELECT existence check + the INSERT.
  var hash = b.crypto.sha3Hash("bj-legal-hold:subject-42");
  var placeIns = b.sql.insert("dl_pg_hold", { dialect: "postgres", quoteName: true })
    .values({ subjectIdHash: hash, placedAt: nowMs, placedBy: "legal@x", reason: "SEC subpoena", custodian: "c@x", citation: "SEC-Rule-17a-4", retainUntil: null })
    .toSql();
  await _q(placeIns);
  var holdSelBuilt = b.sql.select("dl_pg_hold", { dialect: "postgres", quoteName: true })
    .columns(["placedAt"]).where("subjectIdHash", hash).toSql();
  var holdSel = await _q(holdSelBuilt);
  check("legal-hold: place INSERT + existence SELECT round-trip on Postgres",
        holdSel.rows.length === 1 && Number(holdSel.rows[0].placedAt) === nowMs);

  // release(): the DELETE keyed on subjectIdHash.
  var holdDel = b.sql.delete("dl_pg_hold", { dialect: "postgres", quoteName: true })
    .where("subjectIdHash", hash).toSql();
  var holdDelRes = await _q(holdDel);
  check("legal-hold: release DELETE affected 1 row on Postgres", holdDelRes.rowCount === 1);
  var holdGone = _psql("SELECT count(*) AS n FROM dl_pg_hold;");
  check("legal-hold: hold physically removed after release", /\b0\b/.test(holdGone.trim()));

  // history(): whereLike("action", "legalhold.", "prefix") — the ESCAPE '~'
  // prefix match. Seed an audit-shaped table and prove the LIKE selects
  // exactly the legalhold.* rows, not a row whose action merely contains it.
  var auditDdl = b.sql.createTable("dl_pg_audit", [
    { name: "recordedAt",   type: "int", notNull: true },
    { name: "action",       type: "text", notNull: true },
    { name: "metadata",     type: "text" },
    { name: "outcome",      type: "text" },
    { name: "resourceKind", type: "text" },
  ], { dialect: "postgres", quoteName: true });
  await _q(auditDdl);
  var seedRows = [
    [1, "legalhold.placed",   '{"subjectId":"subject-42"}', "success", "legal-hold"],
    [2, "legalhold.released", '{"subjectId":"subject-42"}', "success", "legal-hold"],
    [3, "auth.legalhold.x",   '{"subjectId":"subject-42"}', "success", "legal-hold"],  // NOT a prefix match
    [4, "consent.granted",    '{"subjectId":"subject-42"}', "success", "consent"],
  ];
  for (var sr = 0; sr < seedRows.length; sr++) {
    var ins = b.sql.insert("dl_pg_audit", { dialect: "postgres", quoteName: true })
      .values({ recordedAt: seedRows[sr][0], action: seedRows[sr][1], metadata: seedRows[sr][2], outcome: seedRows[sr][3], resourceKind: seedRows[sr][4] })
      .toSql();
    await _q(ins);
  }
  var histBuilt = b.sql.select("dl_pg_audit", { dialect: "postgres", quoteName: true })
    .columns(["recordedAt", "action"])
    .whereLike("action", "legalhold.", "prefix")
    .where("resourceKind", "legal-hold")
    .orderBy("recordedAt", "asc")
    .toSql();
  var hist = await _q(histBuilt);
  check("legal-hold: whereLike prefix selects exactly the legalhold.* rows on Postgres",
        hist.rows.length === 2 &&
        hist.rows[0].action === "legalhold.placed" &&
        hist.rows[1].action === "legalhold.released");
  check("legal-hold: prefix LIKE did NOT match the mid-string 'auth.legalhold.x'",
        hist.rows.every(function (r) { return r.action.indexOf("legalhold.") === 0; }));

  // whereLike ESCAPE: a literal underscore/percent in the term stays
  // literal. Seed an action with a literal "%" and prove a prefix term
  // containing "%" matches ONLY the literal, not a wildcard expansion.
  var wlIns = b.sql.insert("dl_pg_audit", { dialect: "postgres", quoteName: true })
    .values({ recordedAt: 5, action: "legalhold.100%done", metadata: null, outcome: "success", resourceKind: "legal-hold" })
    .toSql();
  await _q(wlIns);
  var escBuilt = b.sql.select("dl_pg_audit", { dialect: "postgres", quoteName: true })
    .columns(["action"]).whereLike("action", "legalhold.100%", "prefix").toSql();
  var esc = await _q(escBuilt);
  check("legal-hold: whereLike escapes a literal % in the term (matches only the literal row)",
        esc.rows.length === 1 && esc.rows[0].action === "legalhold.100%done");

  // ====================================================================
  // subject — the INSERT-OR-REPLACE upsert (_markErased) + restrict
  // INSERT/DELETE presence pattern.
  // ====================================================================
  var erasuresDdl = b.sql.createTable("dl_pg_erasures", [
    { name: "subjectIdHash", type: "text", primaryKey: true },
    { name: "erasedAt",      type: "int", notNull: true },
  ], { dialect: "postgres", quoteName: true });
  await _q(erasuresDdl);

  function _markErasedSql(subjectHash, erasedAt) {
    return b.sql.upsert("dl_pg_erasures", { dialect: "postgres", quoteName: true })
      .values({ subjectIdHash: subjectHash, erasedAt: erasedAt })
      .onConflict(["subjectIdHash"])
      .doUpdateFromExcluded(["erasedAt"])
      .toSql();
  }
  var shash = b.crypto.sha3Hash("bj-subject:user-99");
  var me1 = _markErasedSql(shash, 1700000000000);
  await _q(me1);
  // Re-erase the same subject — INSERT-OR-REPLACE refreshes the timestamp
  // (ON CONFLICT DO UPDATE), NOT a duplicate-key error.
  var me2 = _markErasedSql(shash, 1700000009999);
  var me2res = await _q(me2);
  void me2res;
  var erasureState = _psql('SELECT count(*) AS c, max("erasedAt") AS m FROM dl_pg_erasures;');
  check("subject: INSERT-OR-REPLACE upsert kept ONE row (no dup-key) on Postgres",
        /^1\t/.test(erasureState.trim()) || /\b1\b/.test(erasureState.split("\t")[0]));
  check("subject: INSERT-OR-REPLACE refreshed erasedAt to the newest value",
        /1700000009999/.test(erasureState.trim()));

  // restrict() presence pattern: INSERT when absent, DELETE to lift.
  var restrictDdl = b.sql.createTable("dl_pg_restrictions", [
    { name: "subjectIdHash", type: "text", primaryKey: true },
    { name: "since",         type: "int", notNull: true },
    { name: "reason",        type: "text" },
  ], { dialect: "postgres", quoteName: true });
  await _q(restrictDdl);
  var rIns = b.sql.insert("dl_pg_restrictions", { dialect: "postgres", quoteName: true })
    .values({ subjectIdHash: shash, since: nowMs, reason: "art-18 hold" }).toSql();
  await _q(rIns);
  var rPresBuilt = b.sql.select("dl_pg_restrictions", { dialect: "postgres", quoteName: true })
    .columns(["subjectIdHash"]).where("subjectIdHash", shash).limit(1).toSql();
  var rPres = await _q(rPresBuilt);
  check("subject: restrict INSERT + presence SELECT round-trip on Postgres", rPres.rows.length === 1);
  var rDel = b.sql.delete("dl_pg_restrictions", { dialect: "postgres", quoteName: true })
    .where("subjectIdHash", shash).toSql();
  var rDelRes = await _q(rDel);
  check("subject: restrict DELETE (lift) affected 1 row on Postgres", rDelRes.rowCount === 1);

  // ====================================================================
  // retention — hard delete / soft-delete UPDATE / erase NULL-set /
  // cascade DELETE / the candidate whereGroup-OR WHERE.
  // ====================================================================
  // __erasedAt is declared TEXT — retention's _candidateBase compares it
  // with `__erasedAt = ''` (the empty-string sentinel), so the operator's
  // erasure-marker column is a string column. (A numeric __erasedAt would
  // make `= ''` reject on Postgres with 22P02 — a known cross-dialect
  // footgun, but retention runs against the local SQLite db handle in
  // production, never an external DB, and SQLite is loosely typed.)
  var ordersDdl = b.sql.createTable("dl_pg_orders", [
    { name: "_id",        type: "text", primaryKey: true },
    { name: "createdAt",  type: "int", notNull: true },
    { name: "secretCol",  type: "text" },
    { name: "secretColHash", type: "text" },
    { name: "softAt",     type: "int" },
    { name: "__erasedAt", type: "text" },
  ], { dialect: "postgres", quoteName: true });
  await _q(ordersDdl);
  var linesDdl = b.sql.createTable("dl_pg_order_lines", [
    { name: "_id",     type: "text", primaryKey: true },
    { name: "orderId", type: "text", notNull: true },
  ], { dialect: "postgres", quoteName: true });
  await _q(linesDdl);

  var oldAt = nowMs - b.constants.TIME.days(400);
  for (var oi = 1; oi <= 4; oi++) {
    var oid = "o-" + oi;
    var oins = b.sql.insert("dl_pg_orders", { dialect: "postgres", quoteName: true })
      .values({ _id: oid, createdAt: oldAt, secretCol: "secret-" + oi, secretColHash: "h-" + oi, softAt: null, __erasedAt: null })
      .toSql();
    await _q(oins);
    var lins = b.sql.insert("dl_pg_order_lines", { dialect: "postgres", quoteName: true })
      .values({ _id: "l-" + oi, orderId: oid }).toSql();
    await _q(lins);
  }

  // The candidate WHERE: age <= cutoff AND (softAt IS NULL) AND
  // (__erasedAt IS NULL OR __erasedAt = '') — retention's _candidateBase +
  // whereGroup. It must select all 4 aged rows on the real planner.
  var cutoff = nowMs - b.constants.TIME.days(365);
  var candBuilt = b.sql.select("dl_pg_orders", { dialect: "postgres", quoteName: true })
    .where("createdAt", "<=", cutoff)
    .whereNull("softAt")
    .whereGroup(function (g) { g.whereNull("__erasedAt").orWhereOp("__erasedAt", "=", ""); })
    .limit(500)
    .toSql();
  var cand = await _q(candBuilt);
  check("retention: candidate whereGroup-OR WHERE selects the 4 aged rows on Postgres",
        cand.rowCount === 4);

  // soft-delete UPDATE on o-1.
  var softBuilt = b.sql.update("dl_pg_orders", { dialect: "postgres", quoteName: true })
    .set("softAt", nowMs).where("_id", "o-1").toSql();
  var softRes = await _q(softBuilt);
  check("retention: soft-delete UPDATE set softAt on Postgres", softRes.rowCount === 1);

  // erase NULL-set on o-2 (NULL the sealed col + its derived hash).
  var eraseBuilt = b.sql.update("dl_pg_orders", { dialect: "postgres", quoteName: true })
    .set({ secretCol: null, secretColHash: null }).where("_id", "o-2").toSql();
  await _q(eraseBuilt);
  var erasedCheck = _psql('SELECT "secretCol", "secretColHash" FROM dl_pg_orders WHERE _id = \'o-2\';');
  check("retention: erase NULL-set wiped the sealed col + derived hash on Postgres",
        new RegExp(NULL_SENTINEL + "\\t" + NULL_SENTINEL).test(erasedCheck.trim()));

  // hard delete on o-3 + cascade DELETE its order_lines.
  var hardBuilt = b.sql.delete("dl_pg_orders", { dialect: "postgres", quoteName: true })
    .where("_id", "o-3").toSql();
  var hardRes = await _q(hardBuilt);
  check("retention: hard delete removed o-3 on Postgres", hardRes.rowCount === 1);
  var cascBuilt = b.sql.delete("dl_pg_order_lines", { dialect: "postgres", quoteName: true })
    .where("orderId", "o-3").toSql();
  var cascRes = await _q(cascBuilt);
  check("retention: cascade DELETE removed o-3's order_lines on Postgres", cascRes.rowCount === 1);
  var lineLeft = _psql("SELECT count(*) AS n FROM dl_pg_order_lines WHERE \"orderId\" = 'o-3';");
  check("retention: no orphan order_lines remain for the cascaded parent", /\b0\b/.test(lineLeft.trim()));

  // dry-run cascade count via .count("*","n") — the COUNT shape b.sql emits.
  var cntBuilt = b.sql.select("dl_pg_order_lines", { dialect: "postgres", quoteName: true })
    .count("*", "n").where("orderId", "o-4").toSql();
  var cnt = await _q(cntBuilt);
  check("retention: cascade dry-run COUNT(*) returns 1 for o-4's lines on Postgres",
        cnt.rows.length === 1 && Number(cnt.rows[0].n) === 1);

  // ---- teardown ----
  await b.externalDb.shutdown();
  _resetState();
  _psql(DROP_ALL);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
