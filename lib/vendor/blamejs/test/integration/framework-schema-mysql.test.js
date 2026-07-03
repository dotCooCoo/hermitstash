// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live test of b.frameworkSchema.ensureSchema against the docker MySQL
 * container. ensureSchema materializes the framework's external-DB surface
 * (audit / consent / checkpoints / tips / scheduler / rate-limit / pubsub /
 * api-key / session / job / cache / seeder / break-glass tables + their
 * indexes + the append-only WORM triggers). It was Postgres/SQLite-only
 * until the MySQL DDL branch landed; this file proves the MySQL branch
 * creates EVERY framework table on a real server AND that a row inserts +
 * reads back through each, with the dialect-specific shapes exercised:
 *
 *   - BIGINT for ms-epoch counters/timestamps (a 32-bit INT overflows
 *     Date.now()).
 *   - LONGBLOB for the binary nonce / signature columns.
 *   - VARCHAR(191) for every TEXT column in a PRIMARY KEY or index (MySQL
 *     refuses unbounded TEXT/BLOB in a key — the bug #97 surfaced).
 *   - BIGINT AUTO_INCREMENT PRIMARY KEY for the pubsub id.
 *   - the WORM triggers (SIGNAL SQLSTATE '45000') block DELETE/UPDATE on
 *     the append-only tables.
 *
 * The driver is the externalDb-shaped persistent docker-exec mysql client
 * b.externalDb.init wraps; ensureSchema dispatches its DDL through it. A
 * dedicated database (bjfs_test) keeps the run isolated.
 *
 * RUN: node scripts/test-integration.js --skip-service-check framework-schema-mysql
 */
var execFileSync = require("node:child_process").execFileSync;
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var CONTAINER = "blamejs-test-mysql";
var DB_NAME   = "bjfs_test";
// ANSI_QUOTES is NOT set: the framework's MySQL DDL emits backtick-quoted
// identifiers, which parse in either sql_mode — this proves the backtick
// path, not a double-quote-via-ANSI_QUOTES workaround.
var _results = [];
function soft(label, cond) {
  _results.push({ label: label, ok: !!cond });
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  return !!cond;
}

// ---- one-shot docker-exec mysql ----
// SQL on stdin (never argv). Each call is a fresh connection — faithful to
// a pooled driver where each acquire is a clean session. stderr captured so
// a MySQL error surfaces with its 4-digit code.
function _mysqlExec(sql, opts) {
  opts = opts || {};
  var dbArgs = opts.noDb ? [] : [DB_NAME];
  var args = ["exec", "-i", CONTAINER, "mysql", "-uroot", "-pblamejs_test_root",
              "--batch", "--raw"].concat(dbArgs);
  try {
    var out = execFileSync("docker", args,
      { input: sql + "\n", stdio: ["pipe", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
    return { ok: true, out: out.toString("utf8") };
  } catch (e) {
    var stderr = e.stderr ? e.stderr.toString("utf8") : "";
    return { ok: false, out: (e.stdout ? e.stdout.toString("utf8") : ""), err: stderr || (e.message || String(e)) };
  }
}

// One-shot for setup / out-of-band assertions; throws on error.
function _mysql(sql, opts) {
  var r = _mysqlExec(sql, opts);
  if (!r.ok) throw new Error("mysql setup failed for [" + sql.slice(0, 120) + "]: " + _clean(r.err));
  return r.out;
}

function _clean(s) {
  return String(s || "").split(/\r?\n/)
    .filter(function (l) { return l && l.indexOf("World-writable") === -1 && l.indexOf("Using a password") === -1; })
    .join(" ").slice(0, 220);
}

// externalDb-shaped driver over the one-shot exec. connect/close are no-ops
// (each query opens its own connection); query inlines `$N` / `?` params and
// returns { rows, rowCount }.
function _makeDockerMysqlDriver() {
  return {
    connect: function () { return Promise.resolve({}); },
    query:   function (_client, sql, params) {
      var r = _mysqlExec(_bindParams(sql, params || []));
      if (!r.ok) {
        var em = /ERROR\s+(\d+)[^:]*:\s*(.*)/.exec(r.err);
        var err = new Error("MySQL " + (em ? em[1] + ": " + em[2] : _clean(r.err)));
        if (em) err.code = em[1];
        return Promise.reject(err);
      }
      return Promise.resolve({ rows: _parseRows(r.out), rowCount: 0 });
    },
    close:   function () { return Promise.resolve(); },
    dialect: "mysql",
  };
}

function _parseRows(out) {
  var lines = out.split(/\r?\n/).filter(function (l) {
    return l.length > 0 && l.indexOf("World-writable") === -1 && l.indexOf("Using a password") === -1;
  });
  if (lines.length === 0) return [];
  var headers = lines[0].split("\t");
  var rows = [];
  for (var i = 1; i < lines.length; i++) {
    var cells = lines[i].split("\t");
    var row = {};
    for (var c = 0; c < headers.length; c++) {
      var cell = cells[c];
      row[headers[c]] = (cell === "NULL" || cell === undefined) ? null : cell;
    }
    rows.push(row);
  }
  return rows;
}

function _bindParams(sql, params) {
  var i = 0;
  return sql.replace(/\$(\d+)|\?/g, function (m) {
    var idx = m.charAt(0) === "$" ? Number(m.slice(1)) - 1 : i++;
    var v = params[idx];
    if (v === null || v === undefined) return "NULL";
    if (Buffer.isBuffer(v)) return "0x" + (v.length ? v.toString("hex") : "00");
    if (typeof v === "number") return String(v);
    if (typeof v === "boolean") return v ? "1" : "0";
    return "'" + String(v).replace(/\\/g, "\\\\").replace(/'/g, "''") + "'";
  });
}

// Every framework table ensureSchema creates, with a minimal valid row to
// insert + read back so the per-table column shapes (BIGINT / LONGBLOB /
// VARCHAR-key) are exercised end-to-end. Buffers exercise LONGBLOB; large
// ms-epoch numbers exercise BIGINT (a 32-bit INT would overflow).
var BIG_MS = 1893456000000;   // 2030-01-01, well beyond 32-bit INT range
var NONCE  = Buffer.from("0123456789abcdef0123456789abcdef", "hex");
var FRAMEWORK_TABLES = [
  "_blamejs_audit_log", "_blamejs_consent_log", "_blamejs_audit_checkpoints",
  "_blamejs_audit_tip", "_blamejs_consent_tip", "_blamejs_audit_purge_anchor",
  "_blamejs_scheduler_ticks", "_blamejs_rate_limit_counters",
  "_blamejs_pubsub_messages", "_blamejs_api_encrypt_nonces", "_blamejs_api_keys",
  "_blamejs_sessions", "_blamejs_session_valid_from", "_blamejs_jobs",
  "_blamejs_cache", "_blamejs_cache_tags",
  "_blamejs_seeders", "_blamejs_seeders_lock", "_blamejs_break_glass_policies",
  "_blamejs_break_glass_grants",
];

async function run() {
  var mysqlSvc = await services.requireService("mysql");
  if (!mysqlSvc.ok) throw new Error("mysql unreachable: " + mysqlSvc.reason);

  _mysql("CREATE DATABASE IF NOT EXISTS " + DB_NAME + ";", { noDb: true });
  _mysql(FRAMEWORK_TABLES.map(function (t) { return "DROP TABLE IF EXISTS `" + t + "`;"; }).join("\n"));

  var driver = _makeDockerMysqlDriver();
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      ops: { connect: driver.connect, query: driver.query, close: driver.close, dialect: "mysql" },
    },
  });

  try {
    // ---- ensureSchema creates EVERY framework table on real MySQL ----
    var report = await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "mysql" });
    soft("ensureSchema(mysql) returned the created-table report",
         report && Array.isArray(report.tables) && report.tables.length === FRAMEWORK_TABLES.length);

    var present = _mysql(
      "SELECT count(*) AS n FROM information_schema.tables WHERE table_schema='" + DB_NAME +
      "' AND table_name LIKE '_blamejs_%';");
    var createdCount = Number((_parseRows(present)[0] || {}).n);
    soft("ensureSchema(mysql) materialized all " + FRAMEWORK_TABLES.length +
         " framework tables on the server (got " + createdCount + ")",
         createdCount === FRAMEWORK_TABLES.length);

    // Confirm a representative key column is VARCHAR (NOT TEXT) — the bug
    // #97 fix (MySQL refuses TEXT in a key). audit_log._id is the PK.
    var colType = _mysql(
      "SELECT DATA_TYPE AS dt FROM information_schema.columns WHERE table_schema='" + DB_NAME +
      "' AND table_name='_blamejs_audit_log' AND column_name='_id';");
    soft("ensureSchema(mysql): a PRIMARY-KEY TEXT column is VARCHAR, not TEXT (key-length fix)",
         /varchar/i.test((_parseRows(colType)[0] || {}).dt || ""));
    // ms-epoch column is BIGINT (not a 32-bit INT).
    var intType = _mysql(
      "SELECT DATA_TYPE AS dt FROM information_schema.columns WHERE table_schema='" + DB_NAME +
      "' AND table_name='_blamejs_audit_log' AND column_name='recordedAt';");
    soft("ensureSchema(mysql): a ms-epoch column is BIGINT (no 32-bit overflow)",
         /bigint/i.test((_parseRows(intType)[0] || {}).dt || ""));

    // ---- insert + read a row through each table ----
    await _roundTripAuditLog();
    await _roundTripConsentLog();
    await _roundTripCheckpoints();
    await _roundTripSingleRow("_blamejs_audit_tip", { scope: "audit", atMonotonicCounter: 1, rowHash: "h", signedAt: "now", fencingToken: 0 }, "scope", "audit");
    await _roundTripSingleRow("_blamejs_consent_tip", { scope: "consent", atMonotonicCounter: 1, rowHash: "h", signedAt: "now", fencingToken: 0 }, "scope", "consent");
    await _roundTripSingleRow("_blamejs_audit_purge_anchor", { scope: "audit", lastPurgedCounter: 1, lastPurgedRowHash: "h", archiveBundleId: "b1", purgedAt: BIG_MS }, "scope", "audit");
    await _roundTripSingleRow("_blamejs_scheduler_ticks", { tickKey: "job:1", name: "job", scheduledAtUnix: BIG_MS, claimedAtUnix: BIG_MS, claimedBy: "node-1" }, "tickKey", "job:1");
    await _roundTripSingleRow("_blamejs_rate_limit_counters", { key: "ip:1.2.3.4", windowStart: BIG_MS, count: 7 }, "key", "ip:1.2.3.4");
    await _roundTripPubsub();
    await _roundTripSingleRow("_blamejs_api_encrypt_nonces", { nonceHash: "nh-1", expireAt: BIG_MS }, "nonceHash", "nh-1");
    await _roundTripApiKeys();
    await _roundTripSessions();
    await _roundTripJobs();
    await _roundTripSingleRow("_blamejs_cache", { cacheKey: "ns:k1", valueJson: "{\"a\":1}", expiresAt: BIG_MS, updatedAt: BIG_MS }, "cacheKey", "ns:k1");
    await _roundTripSingleRow("_blamejs_cache_tags", { cacheKey: "ns:k1", tag: "t1" }, "cacheKey", "ns:k1");
    await _roundTripSingleRow("_blamejs_seeders", { env: "dev", name: "0001-seed", description: "d", appliedAt: "now", rerunnable: 0 }, "name", "0001-seed");
    await _roundTripSingleRow("_blamejs_seeders_lock", { scope: "lock", lockedAt: BIG_MS, lockedBy: "node-1" }, "scope", "lock");
    await _roundTripBreakGlassPolicies();
    await _roundTripBreakGlassGrants();

    // ---- WORM trigger blocks DELETE/UPDATE on an append-only table ----
    await _wormBlocks();
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    b.externalDb._resetForTest();
    _mysql(FRAMEWORK_TABLES.map(function (t) { return "DROP TABLE IF EXISTS `" + t + "`;"; }).join("\n"));
  }

  var failed = _results.filter(function (r) { return !r.ok; });
  console.log("\n[framework-schema-mysql] " + (_results.length - failed.length) + "/" +
    _results.length + " checks passed");
  if (failed.length) failed.forEach(function (r) { console.log("  - " + r.label); });
  for (var i = 0; i < _results.length; i++) check(_results[i].label, _results[i].ok);
}

// Insert a row via externalDb then read it back; assert the key column
// round-trips. Generic single-PK helper.
async function _roundTripSingleRow(table, row, keyCol, keyVal) {
  var cols = Object.keys(row);
  var placeholders = cols.map(function () { return "?"; }).join(", ");
  var quotedCols = cols.map(function (c) { return "`" + c + "`"; }).join(", ");
  var params = cols.map(function (c) { return row[c]; });
  await b.externalDb.query(
    "INSERT INTO `" + table + "` (" + quotedCols + ") VALUES (" + placeholders + ")",
    params, { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query(
    "SELECT `" + keyCol + "` AS k FROM `" + table + "` WHERE `" + keyCol + "` = ?",
    [keyVal], { backend: "ops" });
  soft(table + ": insert + read a row round-trips through real MySQL",
       res && res.rows && res.rows.length === 1 && res.rows[0].k === keyVal);
}

async function _roundTripAuditLog() {
  await b.externalDb.query(
    "INSERT INTO `_blamejs_audit_log` (`_id`,`recordedAt`,`monotonicCounter`,`action`,`outcome`,`prevHash`,`rowHash`,`nonce`,`fencingToken`) " +
    "VALUES (?,?,?,?,?,?,?,?,?)",
    ["a-1", BIG_MS, 1, "login", "success", "p0", "r1", NONCE, 0],
    { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query(
    "SELECT `_id` AS k, `recordedAt` AS ts FROM `_blamejs_audit_log` WHERE `_id` = ?",
    ["a-1"], { backend: "ops" });
  var row = res && res.rows && res.rows[0];
  soft("_blamejs_audit_log: row round-trips (LONGBLOB nonce + BIGINT recordedAt)",
       row && row.k === "a-1" && String(row.ts) === String(BIG_MS));
}

async function _roundTripConsentLog() {
  await b.externalDb.query(
    "INSERT INTO `_blamejs_consent_log` (`_id`,`recordedAt`,`monotonicCounter`,`subjectId`,`subjectIdHash`,`purpose`,`lawfulBasis`,`action`,`channel`,`prevHash`,`rowHash`,`nonce`,`fencingToken`) " +
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
    ["c-1", BIG_MS, 1, "subj", "subjHash", "marketing", "consent", "grant", "web", "p0", "r1", NONCE, 0],
    { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query("SELECT `_id` AS k FROM `_blamejs_consent_log` WHERE `_id` = ?", ["c-1"], { backend: "ops" });
  soft("_blamejs_consent_log: row round-trips", res && res.rows && res.rows[0] && res.rows[0].k === "c-1");
}

async function _roundTripCheckpoints() {
  await b.externalDb.query(
    "INSERT INTO `_blamejs_audit_checkpoints` (`_id`,`createdAt`,`atMonotonicCounter`,`atRowHash`,`signature`,`publicKeyFingerprint`,`fencingToken`) VALUES (?,?,?,?,?,?,?)",
    ["chk-1", BIG_MS, 5, "r5", NONCE, "fp-1", 0],
    { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query("SELECT `_id` AS k FROM `_blamejs_audit_checkpoints` WHERE `_id` = ?", ["chk-1"], { backend: "ops" });
  soft("_blamejs_audit_checkpoints: row round-trips (LONGBLOB signature)", res && res.rows && res.rows[0] && res.rows[0].k === "chk-1");
}

async function _roundTripPubsub() {
  // id is BIGINT AUTO_INCREMENT — omit it so the engine assigns one.
  await b.externalDb.query(
    "INSERT INTO `_blamejs_pubsub_messages` (`topic`,`payload`,`publishedAt`,`publishedBy`) VALUES (?,?,?,?)",
    ["chan", "{\"x\":1}", BIG_MS, "node-1"], { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query("SELECT `id` AS id FROM `_blamejs_pubsub_messages` WHERE `topic` = ?", ["chan"], { backend: "ops" });
  soft("_blamejs_pubsub_messages: AUTO_INCREMENT id assigned + row round-trips",
       res && res.rows && res.rows[0] && Number(res.rows[0].id) >= 1);
}

async function _roundTripApiKeys() {
  await b.externalDb.query(
    "INSERT INTO `_blamejs_api_keys` (`id`,`namespace`,`ownerId`,`ownerIdHash`,`secretHash`,`createdAt`,`prefix`) VALUES (?,?,?,?,?,?,?)",
    ["ns:idhex", "ns", "owner", "ownerHash", "secretHash", BIG_MS, "pfx"],
    { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query("SELECT `id` AS k FROM `_blamejs_api_keys` WHERE `id` = ?", ["ns:idhex"], { backend: "ops" });
  soft("_blamejs_api_keys: row round-trips", res && res.rows && res.rows[0] && res.rows[0].k === "ns:idhex");
}

async function _roundTripSessions() {
  await b.externalDb.query(
    "INSERT INTO `_blamejs_sessions` (`sidHash`,`userId`,`userIdHash`,`createdAt`,`expiresAt`,`lastActivity`) VALUES (?,?,?,?,?,?)",
    ["sid-1", "uid-sealed", "uidHash", BIG_MS, BIG_MS, BIG_MS],
    { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query("SELECT `sidHash` AS k FROM `_blamejs_sessions` WHERE `sidHash` = ?", ["sid-1"], { backend: "ops" });
  soft("_blamejs_sessions: row round-trips", res && res.rows && res.rows[0] && res.rows[0].k === "sid-1");
}

async function _roundTripJobs() {
  await b.externalDb.query(
    "INSERT INTO `_blamejs_jobs` (`_id`,`queueName`,`status`,`enqueuedAt`,`availableAt`) VALUES (?,?,?,?,?)",
    ["job-1", "q1", "pending", BIG_MS, BIG_MS],
    { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query("SELECT `_id` AS k FROM `_blamejs_jobs` WHERE `_id` = ?", ["job-1"], { backend: "ops" });
  soft("_blamejs_jobs: row round-trips", res && res.rows && res.rows[0] && res.rows[0].k === "job-1");
}

async function _roundTripBreakGlassPolicies() {
  await b.externalDb.query(
    "INSERT INTO `_blamejs_break_glass_policies` (`tableName`,`columnsJson`,`factorsJson`,`grantTtlMs`,`updatedAt`) VALUES (?,?,?,?,?)",
    ["secret_table", "[\"ssn\"]", "[\"webauthn\"]", BIG_MS, BIG_MS],
    { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query("SELECT `tableName` AS k FROM `_blamejs_break_glass_policies` WHERE `tableName` = ?", ["secret_table"], { backend: "ops" });
  soft("_blamejs_break_glass_policies: row round-trips", res && res.rows && res.rows[0] && res.rows[0].k === "secret_table");
}

async function _roundTripBreakGlassGrants() {
  await b.externalDb.query(
    "INSERT INTO `_blamejs_break_glass_grants` (`_id`,`issuedToActorId`,`issuedToActorHash`,`factorType`,`scopeTable`,`scopeColumnsJson`,`issuedAt`,`expiresAt`,`maxRowsPerGrant`) VALUES (?,?,?,?,?,?,?,?,?)",
    ["grant-1", "actor", "actorHash", "webauthn", "secret_table", "[\"ssn\"]", BIG_MS, BIG_MS, 1],
    { backend: "ops", rowResidencyTag: "unrestricted" });
  var res = await b.externalDb.query("SELECT `_id` AS k FROM `_blamejs_break_glass_grants` WHERE `_id` = ?", ["grant-1"], { backend: "ops" });
  soft("_blamejs_break_glass_grants: row round-trips", res && res.rows && res.rows[0] && res.rows[0].k === "grant-1");
}

// The append-only WORM triggers must block DELETE + UPDATE on the audit
// tables. ensureSchema installs them via SIGNAL SQLSTATE '45000'.
async function _wormBlocks() {
  var delBlocked = false;
  try {
    await b.externalDb.query("DELETE FROM `_blamejs_audit_log` WHERE `_id` = ?", ["a-1"], { backend: "ops" });
  } catch (_e) { delBlocked = true; }
  soft("_blamejs_audit_log: WORM trigger blocks DELETE (append-only)", delBlocked);

  var updBlocked = false;
  try {
    await b.externalDb.query("UPDATE `_blamejs_audit_log` SET `action` = ? WHERE `_id` = ?", ["tampered", "a-1"], { backend: "ops" });
  } catch (_e) { updBlocked = true; }
  soft("_blamejs_audit_log: WORM trigger blocks UPDATE (append-only)", updBlocked);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
