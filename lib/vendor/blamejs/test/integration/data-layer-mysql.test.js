"use strict";
/**
 * Live data-layer test against the docker MySQL container. Proves the
 * dialect-threading foundation end-to-end on a real MySQL server: the
 * canonical resolver `b.clusterStorage.dialect()` returns `"mysql"` in
 * cluster mode, and every cluster-routed data-layer backend that threads
 * that dialect into its `b.sql` calls runs against real MySQL with
 * backtick-quoted identifiers and the MySQL `ON DUPLICATE KEY UPDATE`
 * upsert form (not Postgres `ON CONFLICT` / double-quotes):
 *
 *   - b.cache (backend: "cluster")     — _blamejs_cache + _blamejs_cache_tags
 *   - b.session                        — _blamejs_sessions, sealed at rest
 *   - b.nonceStore (backend: "cluster")— _blamejs_api_encrypt_nonces
 *   - b.middleware.rateLimit (cluster) — _blamejs_rate_limit_counters
 *
 * The "driver" is a docker-exec mysql shim (batch mode, one statement per
 * exec) modelled on cluster-provider-mysql.test.js. Each primitive routes
 * its SQL through b.clusterStorage -> b.externalDb -> this driver -> real
 * MySQL, so a dialect bug in the emitted SQL surfaces as a real MySQL ERROR,
 * not a test artifact. size() / count() are asserted to return a JS number
 * (the COUNT(*)/BIGINT-as-string coercion) on the real backend.
 *
 * The rate-limit take() is the headline: its per-column window-rollover
 * conflict action is a CASE that reads the proposed row (VALUES(`col`)) and
 * the existing row (`table`.`col`) — both spelled with the MySQL tokens, so
 * the Postgres EXCLUDED form would be a hard ERROR here. b.sql also folds the
 * RETURNING into a readback SELECT (MySQL upsert has no RETURNING); the
 * backend runs that readback and coerces the BIGINT count back to a number.
 *
 * Cluster mode is wired via a no-op custom provider plus externalDbBackend,
 * so isClusterMode() is true and each backend's clusterStorage.execute()
 * calls dispatch to MySQL. The framework tables are created here by hand
 * with the exact column shape frameworkSchema's MySQL DDL builder emits
 * (camelCase, backtick-quoted, VARCHAR key columns, BIGINT ms-epoch);
 * frameworkSchema.ensureSchema's own MySQL DDL is proven directly in
 * framework-schema-mysql.test.js. b.session seals userId/data via the
 * cryptoField registry that helpers.setupTestDb populates.
 *
 * RUN: node scripts/test-integration.js --skip-service-check data-layer-mysql
 */
var execFileSync = require("node:child_process").execFileSync;
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var CONTAINER = "blamejs-test-mysql";
var DB_NAME   = "blamejs_test";

var rateLimitModule = require("../../lib/middleware/rate-limit");

// Soft assertion: records a pass/fail without throwing, so every section's
// finding is collected even when an earlier one failed. The recorded
// results are replayed through the hard `check` at the end of run() so the
// file still FAILS (and the runner reports it) when any assertion is false,
// while ALL findings are printed first.
var _findings = [];
function softCheck(label, condition) {
  _findings.push({ label: label, ok: !!condition });
  console.log((condition ? "  ok   " : "  FAIL ") + label);
}

// ---- docker-exec mysql driver ----
//
// Batch mode (--batch --raw) emits TAB-separated rows with a header line;
// NULL renders as the literal "NULL". One statement per exec (the driver
// is stateless between calls, fine for the cluster-storage dispatch
// shape). Affected-row count for a DML statement is recovered with a
// trailing `SELECT ROW_COUNT()` in the SAME exec so the same connection's
// session state is read — matching what a real mysql2 driver surfaces as
// rowCount.
function _execMysql(sqlText) {
  var out;
  try {
    out = execFileSync("docker",
      ["exec", "-i", CONTAINER,
       "mysql", "-uroot", "-pblamejs_test_root", "--batch", "--raw", DB_NAME, "-e", sqlText],
      { stdio: ["pipe", "pipe", "pipe"], maxBuffer: 16 * 1024 * 1024 }
    ).toString("utf8");
  } catch (e) {
    var err = new Error(e.stderr ? e.stderr.toString("utf8") : (e.message || String(e)));
    err.cause = e;
    throw err;
  }
  return out;
}

function _parseBatch(out) {
  var lines = out.split(/\r?\n/).filter(function (l) { return l.length > 0; });
  if (lines.length < 1) return { rows: [], headers: [] };
  var headers = lines[0].split("\t");
  var rows = [];
  for (var i = 1; i < lines.length; i++) {
    var cells = lines[i].split("\t");
    var row = {};
    for (var j = 0; j < headers.length; j++) {
      var v = cells[j];
      row[headers[j]] = (v === "NULL" || v === undefined) ? null : v;
    }
    rows.push(row);
  }
  return { rows: rows, headers: headers };
}

// Substitute `?` placeholders with quoted literals. Every test value is
// operator-controlled (keys / numbers / JSON strings / null). MySQL is fed
// `?` (clusterStorage.placeholderize is passthrough for mysql), so this is
// the shim's bind protocol.
function _bindParams(sqlText, params) {
  var i = 0;
  return sqlText.replace(/\?/g, function () {
    if (i >= params.length) throw new Error("placeholder/param count mismatch");
    var p = params[i++];
    if (p === null || p === undefined) return "NULL";
    if (typeof p === "number") return String(p);
    if (typeof p === "boolean") return p ? "1" : "0";
    if (Buffer.isBuffer(p)) return "x'" + p.toString("hex") + "'";
    return "'" + String(p).replace(/\\/g, "\\\\").replace(/'/g, "''") + "'";
  });
}

function _makeDockerMysqlDriver() {
  return {
    connect: async function () { return { id: 1 }; },
    query: async function (_client, sqlText, params) {
      params = params || [];
      var bound = _bindParams(sqlText, params);
      var t = bound.trim();
      if (/^(SELECT|SHOW|WITH)/i.test(t)) {
        var sel = _parseBatch(_execMysql(bound));
        return { rows: sel.rows, rowCount: sel.rows.length };
      }
      // DML / DDL: run it, then read ROW_COUNT() on the SAME connection
      // (one exec) so the affected-row count is faithful.
      var combined = _execMysql(bound + ";\nSELECT ROW_COUNT() AS `__rc`;");
      var rc = _parseBatch(combined);
      var n = (rc.rows[0] && rc.rows[0].__rc != null) ? Number(rc.rows[0].__rc) : 0;
      // MySQL ROW_COUNT() returns -1 for statements that don't affect rows
      // (e.g. CREATE). Clamp to 0 for those.
      if (!Number.isFinite(n) || n < 0) n = 0;
      return { rows: [], rowCount: n };
    },
    close: async function () { /* no-op */ },
  };
}

// No-op cluster provider — we only need isClusterMode() true + a dialect.
// The framework's leader gate is not under test here (cache/nonce/
// rate-limit cluster backends don't gate on isLeader()).
function _noopProvider() {
  return {
    ensureSchema:  async function () { /* tables created by hand below */ },
    acquireLease:  async function () { return { nodeId: "n", leaseId: "l", fencingToken: 1, expiresAt: Date.now() + 60000 }; },
    renewLease:    async function (lease) { return lease; },
    releaseLease:  async function () {},
    currentLeader: async function () { return null; },
  };
}

// ---- framework table DDL for MySQL (matches framework-schema._*DDL
// column shapes; ensureSchema is Postgres/SQLite-only so MySQL is by
// hand). Identifiers backtick-quoted, camelCase preserved. ----
var MYSQL_DDL = [
  // _blamejs_cache. VARCHAR lengths kept index-safe under utf8mb4
  // (4 bytes/char) so the PRIMARY KEY / composite key stay under MySQL's
  // 3072-byte index limit.
  "DROP TABLE IF EXISTS `_blamejs_cache`",
  "CREATE TABLE `_blamejs_cache` (" +
    "`cacheKey` VARCHAR(191) PRIMARY KEY, " +
    "`valueJson` LONGTEXT NOT NULL, " +
    "`expiresAt` BIGINT NOT NULL, " +
    "`updatedAt` BIGINT NOT NULL)",
  // _blamejs_cache_tags
  "DROP TABLE IF EXISTS `_blamejs_cache_tags`",
  "CREATE TABLE `_blamejs_cache_tags` (" +
    "`cacheKey` VARCHAR(191) NOT NULL, " +
    "`tag` VARCHAR(191) NOT NULL, " +
    "PRIMARY KEY (`cacheKey`, `tag`))",
  // Minimal audit/consent tip tables so cluster.init's boot-time rollback
  // check finds "no tip row" and skips cleanly (it reads these).
  "DROP TABLE IF EXISTS `_blamejs_audit_tip`",
  "CREATE TABLE `_blamejs_audit_tip` (" +
    "`scope` VARCHAR(64) PRIMARY KEY, " +
    "`atMonotonicCounter` BIGINT NOT NULL DEFAULT 0, " +
    "`rowHash` TEXT)",
  "DROP TABLE IF EXISTS `_blamejs_consent_tip`",
  "CREATE TABLE `_blamejs_consent_tip` (" +
    "`scope` VARCHAR(64) PRIMARY KEY, " +
    "`atMonotonicCounter` BIGINT NOT NULL DEFAULT 0, " +
    "`rowHash` TEXT)",
  "DROP TABLE IF EXISTS `_blamejs_audit_log`",
  "CREATE TABLE `_blamejs_audit_log` (" +
    "`monotonicCounter` BIGINT, `rowHash` TEXT)",
  "DROP TABLE IF EXISTS `_blamejs_consent_log`",
  "CREATE TABLE `_blamejs_consent_log` (" +
    "`monotonicCounter` BIGINT, `rowHash` TEXT)",
  // _blamejs_sessions — mirrors framework-schema._sessionsDDL("mysql"):
  // VARCHAR key columns (index-safe under utf8mb4), BIGINT ms-epoch
  // timestamps. userId/data hold the vault-sealed ciphertext at rest.
  "DROP TABLE IF EXISTS `_blamejs_sessions`",
  "CREATE TABLE `_blamejs_sessions` (" +
    "`sidHash` VARCHAR(191) PRIMARY KEY, " +
    "`userId` TEXT NOT NULL, " +
    "`userIdHash` VARCHAR(191) NOT NULL, " +
    "`data` TEXT, " +
    "`createdAt` BIGINT NOT NULL, " +
    "`expiresAt` BIGINT NOT NULL, " +
    "`lastActivity` BIGINT NOT NULL)",
  // _blamejs_session_valid_from — per-subject not-before invalidation. Mirrors
  // framework-schema._sessionValidFromDDL("mysql"): VARCHAR key, BIGINT epochs.
  "DROP TABLE IF EXISTS `_blamejs_session_valid_from`",
  "CREATE TABLE `_blamejs_session_valid_from` (" +
    "`subjectHash` VARCHAR(191) PRIMARY KEY, " +
    "`validFromEpoch` BIGINT NOT NULL, " +
    "`updatedAt` BIGINT NOT NULL)",
  // _blamejs_api_encrypt_nonces — replay-protection store. nonceHash is the
  // PRIMARY KEY, so the ON DUPLICATE KEY UPDATE no-op fold makes the first
  // insert win (affectedRows=1) and a replay no-op (affectedRows=0).
  "DROP TABLE IF EXISTS `_blamejs_api_encrypt_nonces`",
  "CREATE TABLE `_blamejs_api_encrypt_nonces` (" +
    "`nonceHash` VARCHAR(191) PRIMARY KEY, " +
    "`expireAt` BIGINT NOT NULL)",
  // _blamejs_rate_limit_counters — fixed-window counter. The PRIMARY KEY on
  // `key` is what take()'s ON DUPLICATE KEY UPDATE CASE-rollover keys on.
  "DROP TABLE IF EXISTS `_blamejs_rate_limit_counters`",
  "CREATE TABLE `_blamejs_rate_limit_counters` (" +
    "`key` VARCHAR(191) PRIMARY KEY, " +
    "`windowStart` BIGINT NOT NULL, " +
    "`count` BIGINT NOT NULL DEFAULT 0)",
  // _blamejs_cluster_state — cluster.init's _checkVaultKeyConsistency records
  // + reads this node's vault-key fingerprint here (the MySQL `ON DUPLICATE
  // KEY UPDATE scope = scope` DO-NOTHING fold). The no-op provider doesn't
  // create it, so it is created by hand; rotationEpoch is materialized up
  // front so the runtime's idempotent ALTER is a no-op. Mirrors
  // cluster-provider-db's _blamejs_cluster_state column shape.
  "DROP TABLE IF EXISTS `_blamejs_cluster_state`",
  "CREATE TABLE `_blamejs_cluster_state` (" +
    "`scope` VARCHAR(64) PRIMARY KEY, " +
    "`vaultKeyFp` TEXT NOT NULL, " +
    "`recordedAt` BIGINT NOT NULL, " +
    "`recordedByNode` TEXT NOT NULL, " +
    "`rotationEpoch` BIGINT NOT NULL DEFAULT 0)",
];

var DROP_ALL = [
  "_blamejs_cache", "_blamejs_cache_tags", "_blamejs_audit_tip",
  "_blamejs_consent_tip", "_blamejs_audit_log", "_blamejs_consent_log",
  "_blamejs_sessions", "_blamejs_session_valid_from", "_blamejs_api_encrypt_nonces",
  "_blamejs_rate_limit_counters", "_blamejs_cluster_state",
].map(function (t) { return "DROP TABLE IF EXISTS `" + t + "`"; });

function _ddl(stmts) {
  for (var i = 0; i < stmts.length; i++) _execMysql(stmts[i]);
}

// Out-of-band assertion helper: run a SELECT directly and return parsed rows.
function _selectDirect(sqlText) {
  return _parseBatch(_execMysql(sqlText)).rows;
}

async function run() {
  var mysqlSvc = await services.requireService("mysql");
  if (!mysqlSvc.ok) throw new Error("mysql unreachable: " + mysqlSvc.reason);

  _ddl(MYSQL_DDL);

  // Full-framework bring-up (vault + db + cryptoField). db.init registers the
  // _blamejs_sessions sealedFields (userId, data) + derived userIdHash, which
  // b.session uses to seal/derive regardless of which backend the SQL routes
  // to. The local SQLite db it opens is unused once cluster mode is active
  // (session SQL dispatches to MySQL) but the cryptoField registry it
  // populates is exactly what b.session's sealing needs.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-datalayer-mysql-"));
  await helpers.setupTestDb(tmpDir);

  var driver = _makeDockerMysqlDriver();
  b.cluster._resetForTest();
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "mysql",
      },
    },
  });

  await b.cluster.init({
    nodeId:            "mysql-data-node",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
    provider:          _noopProvider(),
    externalDbBackend: "ops",
    dialect:           "mysql",
  });
  softCheck("cluster is in cluster mode (state routes to MySQL)",
        b.cluster.isClusterMode() === true);
  softCheck("cluster dialect is mysql", b.cluster.dialect() === "mysql");

  // Each backend threads clusterStorage.dialect() into every b.sql call (via
  // its per-file _*SqlOpts()), so its SQL emits MySQL-shaped identifiers + the
  // ON DUPLICATE KEY UPDATE upsert against the real server. A dialect bug
  // surfaces as a real MySQL ERROR rather than a test artifact.
  try {
    await _section("cache", _testCacheCluster);
    await _section("session", _testSession);
    await _section("nonce", _testNonceCluster);
    await _section("rate-limit", _testRateLimitCluster);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    b.cluster._resetForTest();
    try { await b.externalDb.shutdown(); } catch (_e) {}
    try { await helpers.teardownTestDb(tmpDir); } catch (_e) {}
    _ddl(DROP_ALL);
  }

  // Replay every recorded finding through the hard `check` so the file
  // FAILS (and the runner reports it) when any assertion is false. All
  // findings have already been printed above, so the failure message
  // names the first unmet contract while the full picture is visible.
  var failures = _findings.filter(function (f) { return !f.ok; });
  console.log("");
  console.log("[data-layer-mysql] " + (_findings.length - failures.length) + "/" +
    _findings.length + " checks ok; " + failures.length + " failing");
  for (var i = 0; i < _findings.length; i++) {
    check(_findings[i].label, _findings[i].ok);
  }
}

// Run one primitive's section; a thrown driver error becomes a single
// FAILED check carrying the first line of the MySQL error so each
// primitive's dialect bug is reported independently.
async function _section(label, fn) {
  try {
    await fn();
  } catch (e) {
    var first = ((e && e.message) || String(e)).split(/\r?\n/)
      .filter(function (l) { return /ERROR \d+|error in your SQL|EXCLUDED|"/.test(l); })[0] ||
      ((e && e.message) || String(e)).split(/\r?\n/)[0];
    softCheck(label + "(mysql): cluster SQL executes against real MySQL " +
          "(emitted with the MySQL dialect — backtick identifiers, no Postgres EXCLUDED) " +
          "— DETAIL: " + first, false);
  }
}

// ======================================================================
// b.cache cluster backend on real MySQL.
//   get / set (tx upsert + tag rewrite) / del / has / size / clear /
//   invalidateTag (whereLike prefix) / getTags / CAS update.
// ======================================================================
async function _testCacheCluster() {
  var cache = b.cache.create({ backend: "cluster", namespace: "mysqlns", ttlMs: b.constants.TIME.minutes(5) });

  // set + get round-trip through the real _blamejs_cache UPSERT.
  await cache.set("k1", { hello: "world", n: 42 });
  var got = await cache.get("k1");
  softCheck("cache(mysql): set + get JSON round-trips on real MySQL",
        got && got.hello === "world" && got.n === 42);

  // The row physically lands keyed on "<namespace>:<key>".
  var rowDirect = _selectDirect(
    "SELECT `valueJson` FROM `_blamejs_cache` WHERE `cacheKey` = 'mysqlns:k1';");
  softCheck("cache(mysql): row physically present under composite key",
        rowDirect.length === 1 && /"hello"/.test(rowDirect[0].valueJson));

  // has / del.
  softCheck("cache(mysql): has returns true for a live key", (await cache.has("k1")) === true);
  softCheck("cache(mysql): del removes the key", (await cache.del("k1")) === true);
  softCheck("cache(mysql): get after del is undefined", (await cache.get("k1")) === undefined);

  // tags: set with tags -> tag rows written in the same transaction.
  await cache.set("a", "1", { tags: ["grp-x"] });
  await cache.set("bk", "2", { tags: ["grp-x", "grp-y"] });
  await cache.set("ck", "3", { tags: ["grp-y"] });
  var tagsA = await cache.getTags("a");
  softCheck("cache(mysql): getTags returns the tags written for a key",
        Array.isArray(tagsA) && tagsA.indexOf("grp-x") !== -1);

  // invalidateTag uses whereLike(cacheKey, prefix) + tag match. Drops every
  // key carrying grp-x, scoped to this namespace; leaves grp-y-only keys.
  var purged = await cache.invalidateTag("grp-x");
  softCheck("cache(mysql): invalidateTag purged the grp-x keys (count >= 2)", purged >= 2);
  softCheck("cache(mysql): invalidateTag dropped a + bk",
        (await cache.get("a")) === undefined && (await cache.get("bk")) === undefined);
  softCheck("cache(mysql): invalidateTag preserved grp-y-only key ck",
        (await cache.get("ck")) === "3");

  // Tag junction rows for the purged keys are gone (no orphans).
  var orphanTags = _selectDirect(
    "SELECT COUNT(*) AS `n` FROM `_blamejs_cache_tags` WHERE `cacheKey` = 'mysqlns:a';");
  softCheck("cache(mysql): purged key's tag junction rows removed",
        orphanTags.length === 1 && Number(orphanTags[0].n) === 0);

  // size() counts only live, namespace-scoped rows (whereLike prefix).
  var sz = await cache.size();
  softCheck("cache(mysql): size() counts live namespaced rows (ck remains)", sz >= 1);

  // CAS update (atomic RMW) — counter increment via the transaction +
  // compare-and-set path on real MySQL.
  await cache.update("counter", function (n) { return { value: (n || 0) + 1 }; });
  await cache.update("counter", function (n) { return { value: (n || 0) + 1 }; });
  var counterVal = await cache.get("counter");
  softCheck("cache(mysql): atomic update() increments through CAS on MySQL",
        counterVal === 2);

  // clear() — namespace-scoped wipe via whereLike prefix.
  var cleared = await cache.clear();
  softCheck("cache(mysql): clear() wiped the namespace", cleared >= 1);
  softCheck("cache(mysql): get after clear is undefined", (await cache.get("ck")) === undefined);

  // Cross-namespace isolation: a second instance's key is untouched by the
  // first's clear()/invalidateTag (prefix LIKE scoping is real on MySQL).
  var other = b.cache.create({ backend: "cluster", namespace: "othermysql", ttlMs: b.constants.TIME.minutes(5) });
  await other.set("shared", "other-value", { tags: ["grp-x"] });
  await cache.set("shared", "first-value", { tags: ["grp-x"] });
  await cache.invalidateTag("grp-x");
  softCheck("cache(mysql): invalidateTag is namespace-scoped (other ns survives)",
        (await other.get("shared")) === "other-value");
  await other.clear();
  await other.close();
  await cache.close();
}

// ======================================================================
// b.session full lifecycle on real MySQL (sealed at rest).
//   create / verify / count / touch / rotate / destroyAllForUser /
//   destroy / purgeExpired — every statement dialect-threaded to MySQL
//   (backtick identifiers), userId/data sealed via cryptoField.
// ======================================================================
async function _testSession() {
  var created = await b.session.create({
    userId: "user-42",
    data:   { roles: ["admin"], theme: "dark" },
    ttlMs:  b.constants.TIME.hours(8),
  });
  softCheck("session(mysql): create returns a sealed token + expiry",
        created && typeof created.token === "string" &&
        created.token.indexOf("vault:") === 0 && typeof created.expiresAt === "number");

  // The row physically landed on MySQL; userId is NOT plaintext.
  var rawRows = _selectDirect("SELECT `userId`, `userIdHash` FROM `_blamejs_sessions`;");
  softCheck("session(mysql): a session row physically landed on MySQL",
        rawRows.length === 1);
  softCheck("session(mysql): userId is sealed at rest (NOT the plaintext 'user-42')",
        rawRows.length === 1 && String(rawRows[0].userId).indexOf("user-42") === -1);

  // verify -> unseal round-trips userId + data through MySQL.
  var info = await b.session.verify(created.token);
  softCheck("session(mysql): verify unseals userId from the MySQL row",
        info && info.userId === "user-42");
  softCheck("session(mysql): verify unseals the data payload",
        info && info.data && info.data.roles && info.data.roles[0] === "admin" &&
        info.data.theme === "dark");
  softCheck("session(mysql): verify coerces createdAt/expiresAt to JS numbers " +
        "(BIGINT-as-string would break the timeout math)",
        info && typeof info.createdAt === "number" && typeof info.expiresAt === "number" &&
        info.expiresAt > info.createdAt);

  // count -> the live session is counted (COUNT(*) BIGINT coerced to number).
  var liveCount = await b.session.count();
  softCheck("session(mysql): count() returns the one live session as a JS number",
        typeof liveCount === "number" && liveCount === 1);

  // touch with extendBy -> bumps lastActivity + expiresAt; affectedRows>0.
  var touched = await b.session.touch(created.token, { extendBy: b.constants.TIME.hours(12) });
  softCheck("session(mysql): touch() updated the live row (returned true)", touched === true);
  var afterTouch = await b.session.verify(created.token);
  softCheck("session(mysql): touch extended expiresAt past the original",
        afterTouch && afterTouch.expiresAt >= created.expiresAt);

  // rotate -> new sid swapped atomically; old token no longer verifies.
  var rotated = await b.session.rotate(created.token, { reason: "mfa" });
  softCheck("session(mysql): rotate returns a fresh sealed token",
        rotated && typeof rotated.token === "string" && rotated.token !== created.token);
  softCheck("session(mysql): the OLD token no longer verifies after rotate",
        (await b.session.verify(created.token)) === null);
  var rotatedInfo = await b.session.verify(rotated.token);
  softCheck("session(mysql): the NEW token verifies with the same userId",
        rotatedInfo && rotatedInfo.userId === "user-42");

  // updateData -> writes the sealed data column without rotating the sid.
  var updated = await b.session.updateData(rotated.token, { roles: ["admin"], step: "mfa-done" });
  softCheck("session(mysql): updateData wrote the sealed data column (returned true)",
        updated === true);
  var afterUpdate = await b.session.verify(rotated.token);
  softCheck("session(mysql): updateData payload round-trips through the sealed MySQL column",
        afterUpdate && afterUpdate.data && afterUpdate.data.step === "mfa-done");

  // destroyAllForUser -> deletes via the derived userIdHash; count drops.
  var revoked = await b.session.destroyAllForUser("user-42");
  softCheck("session(mysql): destroyAllForUser deleted the session via userIdHash",
        revoked === 1);
  softCheck("session(mysql): the session no longer verifies after revoke-all",
        (await b.session.verify(rotated.token)) === null);
  softCheck("session(mysql): count() is 0 after revoke-all", (await b.session.count()) === 0);

  // destroy single + idempotency.
  var s2 = await b.session.create({ userId: "user-99", ttlMs: b.constants.TIME.hours(1) });
  softCheck("session(mysql): destroy(token) returns true for a live session",
        (await b.session.destroy(s2.token)) === true);
  softCheck("session(mysql): destroy is idempotent (second destroy returns false)",
        (await b.session.destroy(s2.token)) === false);

  // purgeExpired side-effect: age a row directly, then sweep.
  await b.session.create({ userId: "user-exp", ttlMs: b.constants.TIME.hours(1) });
  _execMysql("UPDATE `_blamejs_sessions` SET `expiresAt` = 1 WHERE `expiresAt` > 1;");
  var purged = await b.session.purgeExpired();
  softCheck("session(mysql): purgeExpired removed the expired row(s) (>=1)", purged >= 1);
  softCheck("session(mysql): count() is 0 after purge", (await b.session.count()) === 0);
}

// ======================================================================
// b.nonceStore cluster backend on real MySQL.
//   checkAndInsert (ON DUPLICATE KEY UPDATE no-op fold = atomic
//   first-seen) + replay rejection + purgeExpired. The MySQL no-op fold
//   returns affectedRows=1 for a fresh insert (won) and 0 for a duplicate
//   (replay), which is the wire signal checkAndInsert reads.
// ======================================================================
async function _testNonceCluster() {
  var store = b.nonceStore.create({ backend: "cluster" });
  var future = Date.now() + b.constants.TIME.minutes(10);

  softCheck("nonce(mysql): first checkAndInsert returns true (unseen)",
        (await store.checkAndInsert("nonce-aaa", future)) === true);
  var n1 = _selectDirect(
    "SELECT COUNT(*) AS `n` FROM `_blamejs_api_encrypt_nonces` WHERE `nonceHash` = 'nonce-aaa';");
  softCheck("nonce(mysql): the nonce row physically landed",
        n1.length === 1 && Number(n1[0].n) === 1);

  softCheck("nonce(mysql): replay of the same nonce returns false (DUPLICATE-KEY no-op fold)",
        (await store.checkAndInsert("nonce-aaa", future)) === false);
  softCheck("nonce(mysql): a distinct nonce is accepted",
        (await store.checkAndInsert("nonce-bbb", future)) === true);

  await store.checkAndInsert("nonce-expired", Date.now() - 1000);
  var purged = await store.purgeExpired();
  softCheck("nonce(mysql): purgeExpired removed the expired nonce (>=1)", purged >= 1);
  softCheck("nonce(mysql): a live nonce still rejects replay after purge",
        (await store.checkAndInsert("nonce-aaa", future)) === false);

  store.close();
}

// ======================================================================
// b.middleware.rateLimit cluster backend on real MySQL.
//   take() = ON DUPLICATE KEY UPDATE with a per-column CASE conflict
//   action (proposed row = VALUES(`col`), existing row = `table`.`col`)
//   + a readback SELECT (MySQL has no RETURNING). The returned BIGINT
//   count must coerce to a JS number so count<=limit is numeric.
// ======================================================================
async function _testRateLimitCluster() {
  var backend = rateLimitModule._clusterBackend({
    backend: "cluster", limit: 3, windowMs: b.constants.TIME.minutes(1),
  });

  var v1 = await backend.take("ratekey-1", 1);
  softCheck("rate-limit(mysql): first take() is allowed against real MySQL",
        v1 && v1.allowed === true);
  softCheck("rate-limit(mysql): the take() verdict count math is numeric " +
        "(remaining is a finite number, not NaN from a string compare)",
        typeof v1.remaining === "number" && isFinite(v1.remaining) && v1.remaining === 2);

  var rowAfter1 = _selectDirect(
    "SELECT `count` FROM `_blamejs_rate_limit_counters` WHERE `key` = 'ratekey-1';");
  softCheck("rate-limit(mysql): counter row landed with count=1",
        rowAfter1.length === 1 && Number(rowAfter1[0].count) === 1);

  var v2 = await backend.take("ratekey-1", 1);
  var v3 = await backend.take("ratekey-1", 1);
  var v4 = await backend.take("ratekey-1", 1);
  softCheck("rate-limit(mysql): 2nd + 3rd allowed, 4th over the limit refused",
        v2.allowed === true && v3.allowed === true && v4.allowed === false);
  softCheck("rate-limit(mysql): the over-limit verdict carries a positive retryAfter",
        typeof v4.retryAfter === "number" && v4.retryAfter > 0);
  var rowAfter4 = _selectDirect(
    "SELECT `count` FROM `_blamejs_rate_limit_counters` WHERE `key` = 'ratekey-1';");
  softCheck("rate-limit(mysql): counter incremented monotonically to 4 (same-window CASE branch)",
        rowAfter4.length === 1 && Number(rowAfter4[0].count) === 4);

  // A window advance resets the count (the CASE conflict action's
  // window-rollover branch). Force a stale window then take() again.
  _execMysql("UPDATE `_blamejs_rate_limit_counters` SET `windowStart` = 0 WHERE `key` = 'ratekey-1';");
  var vReset = await backend.take("ratekey-1", 1);
  softCheck("rate-limit(mysql): a fresh window resets the count (CASE rollover) — allowed again",
        vReset.allowed === true);
  var rowAfterReset = _selectDirect(
    "SELECT `count` FROM `_blamejs_rate_limit_counters` WHERE `key` = 'ratekey-1';");
  softCheck("rate-limit(mysql): count reset to 1 on window advance (proposed-window CASE branch)",
        rowAfterReset.length === 1 && Number(rowAfterReset[0].count) === 1);

  // A distinct key is tracked independently.
  var other = await backend.take("ratekey-2", 1);
  softCheck("rate-limit(mysql): a distinct key is counted independently",
        other.allowed === true && other.remaining === 2);

  // reset(key) deletes the counter row.
  await backend.reset("ratekey-1");
  var afterReset = _selectDirect(
    "SELECT COUNT(*) AS `n` FROM `_blamejs_rate_limit_counters` WHERE `key` = 'ratekey-1';");
  softCheck("rate-limit(mysql): reset(key) deleted the counter row",
        afterReset.length === 1 && Number(afterReset[0].n) === 0);

  if (typeof backend.close === "function") backend.close();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
