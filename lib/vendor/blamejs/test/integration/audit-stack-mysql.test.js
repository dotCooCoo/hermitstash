// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live MySQL coverage for the b.sql data layer of:
 *
 *   lib/audit.js        — record() → chain-writer, checkpoint(),
 *                         _upsertAuditTip() fencing-token guard (the MySQL
 *                         ON DUPLICATE KEY UPDATE + IF-fold + readback path),
 *                         verify(), verifyCheckpoints()
 *   lib/audit-tools.js  — exportSlice / verifyBundle reading the live MySQL
 *                         audit_log + the purge-anchor UPSERT
 *   lib/chain-writer.js — _insertRow / counter primer / tip read on MySQL
 *   lib/break-glass.js  — policy.set/get/list (ON DUPLICATE KEY UPSERT) +
 *                         grant + unsealRow consume (the backtick-quoted
 *                         rowsConsumed increment), routed to live MySQL
 *   lib/crypto-field.js — a K_row (vault.row:) sealed cell stored as TEXT in
 *                         MySQL and read back + derived-hash dual-read
 *
 * Each of these files threads { dialect: clusterStorage.dialect() } into
 * every framework-table b.sql call, so in cluster mode against a MySQL
 * backend the emitted SQL is backtick-quoted with ON DUPLICATE KEY UPDATE —
 * what MySQL accepts. Defaulting to "sqlite" emitted double-quoted
 * identifiers (string literals on MySQL) + ON CONFLICT (a syntax error),
 * which is what this file proves is no longer the case.
 *
 * The driver is a docker-exec mysql shim (per-statement, like the
 * data-layer-cluster-mysql file). None of the five files under test use
 * clusterStorage.transaction, so the per-statement driver is sufficient.
 *
 * RUN: node scripts/test-integration.js --skip-service-check audit-stack-mysql
 */

var execFileSync = require("node:child_process").execFileSync;
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");

var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var setupTestDb    = require("../helpers/db").setupTestDb;
var teardownTestDb = require("../helpers/db").teardownTestDb;
var b = require("../../");

var CONTAINER = "blamejs-test-mysql";
var DB_NAME   = "blamejs_audit_mysql_test";

// ---- one-shot mysql (setup / teardown / out-of-band assertions) ----
function _mysqlRoot(sql, dbName) {
  var args = ["exec", "-i", CONTAINER, "mysql", "-uroot", "-pblamejs_test_root", "--batch", "--raw"];
  if (dbName) args.push(dbName);
  args.push("-e", sql);
  return execFileSync("docker", args, { stdio: ["pipe", "pipe", "pipe"] }).toString("utf8");
}

// --batch output: tab-separated, header row, "NULL" sentinel. Every cell is
// text (BIGINT included) — coerceRow's job on the framework readback.
function _parseBatch(out) {
  var lines = out.split(/\r?\n/).filter(function (l) { return l.length > 0; });
  if (lines.length < 1) return { rows: [] };
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
  return { rows: rows };
}

function _countMysql(table, whereClause) {
  var sql = "SELECT count(*) AS n FROM " + table + (whereClause ? " WHERE " + whereClause : "");
  var parsed = _parseBatch(_mysqlRoot(sql, DB_NAME));
  return parsed.rows[0] ? Number(parsed.rows[0].n) : 0;
}

function _scalar(sql) {
  var parsed = _parseBatch(_mysqlRoot(sql, DB_NAME));
  if (!parsed.rows[0]) return null;
  var k = Object.keys(parsed.rows[0])[0];
  return parsed.rows[0][k];
}

// ---- docker-exec mysql driver (faithful to a text-protocol driver) ----
// SQL is piped over STDIN, NOT passed as an `-e` argument: a sealed cell can
// push a single INSERT past the OS command-line length limit (ENAMETOOLONG),
// whereas a real protocol driver streams it. STDIN keeps the shim faithful at
// any statement size.
function _exec(sql) {
  try {
    return execFileSync("docker",
      ["exec", "-i", CONTAINER, "mysql", "-uroot", "-pblamejs_test_root",
       "--batch", "--raw", DB_NAME],
      { input: sql + "\n", stdio: ["pipe", "pipe", "pipe"] }).toString("utf8");
  } catch (e) {
    var msg = e.stderr ? e.stderr.toString("utf8") : (e.message || String(e));
    var errLine = (msg.split(/\r?\n/).filter(function (l) { return /ERROR \d+/.test(l); })[0]) || msg.trim();
    var err = new Error(errLine.trim());
    var m = /ERROR (\d+) \(([0-9A-Za-z]{5})\)/.exec(msg);
    if (m) { err.errno = Number(m[1]); err.code = m[2]; err.sqlState = m[2]; }
    throw err;
  }
}

function _bindParams(sql, params) {
  var i = 0;
  return sql.replace(/\?/g, function () {
    if (i >= params.length) throw new Error("placeholder/param count mismatch");
    var p = params[i++];
    if (p === null || p === undefined) return "NULL";
    if (Buffer.isBuffer(p)) return "x'" + p.toString("hex") + "'";   // BLOB literal (nonce / signature)
    if (typeof p === "number") return String(p);
    if (typeof p === "boolean") return p ? "1" : "0";
    return "'" + String(p).replace(/\\/g, "\\\\").replace(/'/g, "''") + "'";
  });
}

// A real mysql2 driver parses the binary protocol, so a BLOB comes back as a
// Buffer and a TEXT cell carrying embedded newlines / tabs round-trips
// intact. The docker-exec `--batch --raw` shim emits cells verbatim into a
// TSV, so (a) binary BLOBs (nonce / signature) corrupt the stream and (b) a
// sealed `vault:` text cell containing literal newlines shatters one row
// across several TSV lines — column misalignment that breaks the chain-hash
// recompute. Emulate the live driver faithfully: for a `SELECT * FROM
// <framework table>`, expand the star to an explicit projection that
// HEX()-encodes EVERY column (so no cell can contain a tab or newline), then
// decode each cell by type — blob columns to Buffers, everything else to a
// UTF-8 string (coerceRows then turns BIGINT strings into numbers). Keeps the
// test honest (bytes in == bytes out, like mysql2) without touching any
// framework SQL.
// Per-column metadata: { name, kind } where kind is "blob" | "text" |
// "numeric". HEX() of a NUMERIC column returns the hex of the integer value
// (HEX(255) -> "FF"), NOT the hex of its ASCII digits — so numeric columns
// must NOT be HEX-wrapped (they carry no tabs/newlines and round-trip as
// plain text the framework's coerceRows turns back into numbers). Only
// text/blob columns get HEX-encoded (they may carry sealed bytes / embedded
// newlines that would shatter the TSV).
var _COLMETA_CACHE = {};   // table -> [{ name, kind }]
function _columnMeta(table) {
  if (_COLMETA_CACHE[table] !== undefined) return _COLMETA_CACHE[table];
  var out = _mysqlRoot(
    "SELECT column_name, data_type FROM information_schema.columns " +
    "WHERE table_schema = '" + DB_NAME + "' AND table_name = '" + table + "' " +
    "ORDER BY ordinal_position", DB_NAME);
  var meta = _parseBatch(out).rows.map(function (r) {
    var name = r.column_name || r.COLUMN_NAME;
    var dt = (r.data_type || r.DATA_TYPE || "").toLowerCase();
    var kind;
    if (/(longblob|mediumblob|tinyblob|blob|varbinary|binary)/.test(dt)) kind = "blob";
    else if (/(int|decimal|numeric|float|double|bit|year)/.test(dt))     kind = "numeric";
    else kind = "text";
    return { name: name, kind: kind };
  });
  _COLMETA_CACHE[table] = meta;
  return meta;
}

function _makeDockerMysqlDriver() {
  return {
    connect: async function () { return { id: 1 }; },
    query: async function (_client, sql, params) {
      params = params || [];
      var bound = _bindParams(sql, params);
      var t = bound.trim();
      if (/^(CREATE|ALTER|INSERT|UPDATE|DELETE|DROP|REPLACE|TRUNCATE)\b/i.test(t)) {
        var stmt = bound.replace(/;\s*$/, "");
        var ar = _exec(stmt + "; SELECT ROW_COUNT() AS n");
        var parsed = _parseBatch(ar);
        var n = parsed.rows[0] ? Number(parsed.rows[0].n) : 0;
        if (!isFinite(n) || n < 0) n = 0;
        return { rows: [], affectedRows: n, rowCount: n };
      }
      // Newline/binary-safe SELECT *: HEX-encode every column so the TSV can
      // never be shattered by an embedded tab/newline (sealed vault: cells),
      // then decode by type. Only the `SELECT * FROM <table>` shape needs it;
      // explicit-projection framework reads never project a blob/multiline
      // cell.
      var meta = null;
      var starMatch = /^SELECT \* FROM `?([A-Za-z0-9_]+)`?\b/i.exec(bound);
      if (starMatch) {
        meta = _columnMeta(starMatch[1]);
        if (meta.length > 0) {
          var proj = meta.map(function (m) {
            // Numeric columns pass through raw (HEX of a number is the hex of
            // its value, not its digits); text/blob get HEX-encoded so binary
            // / embedded newlines survive the TSV.
            return m.kind === "numeric"
              ? "`" + m.name + "`"
              : "HEX(`" + m.name + "`) AS `" + m.name + "`";
          }).join(", ");
          bound = bound.replace(/^SELECT \*/i, "SELECT " + proj);
        } else {
          meta = null;
        }
      }
      var parsedSel = _parseBatch(_exec(bound));
      if (meta) {
        var byName = {};
        for (var mi = 0; mi < meta.length; mi++) byName[meta[mi].name] = meta[mi];
        for (var i = 0; i < parsedSel.rows.length; i++) {
          var row = parsedSel.rows[i];
          for (var k in row) {
            if (!Object.prototype.hasOwnProperty.call(row, k)) continue;
            var cell = row[k];
            if (cell === null || cell === undefined) continue;
            var m = byName[k];
            if (!m || m.kind === "numeric") continue;   // numeric passes through (coerceRows handles it)
            var buf = Buffer.from(String(cell), "hex");
            row[k] = m.kind === "blob" ? buf : buf.toString("utf8");
          }
        }
      }
      return { rows: parsedSel.rows, rowCount: parsedSel.rows.length };
    },
    close: async function () { /* no-op */ },
    dialect: "mysql",
  };
}

// Framework + app tables this test owns. Dropped at setup + teardown so a
// re-run is clean and other live tests don't collide.
var OWNED_TABLES = [
  "_blamejs_audit_log", "_blamejs_consent_log", "_blamejs_audit_checkpoints",
  "_blamejs_audit_tip", "_blamejs_consent_tip", "_blamejs_audit_purge_anchor",
  "_blamejs_break_glass_policies", "_blamejs_break_glass_grants",
  "_blamejs_leader", "_blamejs_cluster_state",
  "patients", "krow_demo",
];

function _dropOwned() {
  for (var i = 0; i < OWNED_TABLES.length; i++) {
    try { _mysqlRoot("DROP TABLE IF EXISTS `" + OWNED_TABLES[i] + "`", DB_NAME); } catch (_e) {}
  }
}

async function run() {
  var svc = await services.requireService("mysql");
  if (!svc.ok) throw new Error("mysql unreachable: " + svc.reason);

  _mysqlRoot("CREATE DATABASE IF NOT EXISTS " + DB_NAME);
  _dropOwned();

  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-my-"));
  var driver = _makeDockerMysqlDriver();

  try {
    // Boot the framework: vault + local SQLite + cryptoField schema
    // registration for the framework tables. The glass-locked "patients"
    // app table is sealed for the break-glass + crypto-field sections.
    await setupTestDb(tmpDir, [
      {
        name: "patients",
        columns: {
          _id: "TEXT PRIMARY KEY", mrn: "TEXT", ssn: "TEXT",
          residency: "TEXT", notes: "TEXT",
        },
        sealedFields: ["ssn", "notes"],
      },
    ]);

    // External MySQL backend + cluster mode. ensureSchema now emits MySQL DDL
    // (backtick identifiers, BIGINT, ON DUPLICATE KEY); cluster.init flips
    // clusterStorage to route framework SQL to the external MySQL backend.
    b.externalDb.init({
      backends: {
        ops: {
          connect: driver.connect, query: driver.query, close: driver.close,
          dialect: "mysql",
        },
      },
    });
    await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "mysql" });
    check("ensureSchema created the framework tables on real MySQL (audit + break-glass)",
      _countMysql("information_schema.tables",
        "table_schema = '" + DB_NAME + "' AND table_name = '_blamejs_break_glass_grants'") === 1);

    await b.cluster.init({
      nodeId:            "audit-stack-my",
      role:              "leader",
      externalDbBackend: "ops",
      dialect:           "mysql",
    });
    check("cluster.init acquired leadership on real MySQL (gates every chain append)",
      b.cluster.isLeader() === true);
    check("framework is in cluster mode → framework SQL routes to external MySQL",
      b.clusterStorage.dialect() === "mysql" &&
      b.clusterStorage.tableName("audit_log") === "_blamejs_audit_log");

    await _testAuditRecordAndChain();
    await _testCheckpointAndFence();
    await _testCoercionFidelity();
    await _testAuditToolsBundle(tmpDir);
    await _testBreakGlass();
    await _testCryptoFieldKRowRoundTrip();
    await _testDerivedHashDualRead();
    await _testTamperDetection();

  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    try { await teardownTestDb(tmpDir); } catch (_e) {}
    _dropOwned();
  }
}

// ====================================================================
// 1. audit.record() → chain-writer._insertRow on real MySQL. The whole
//    primitive: counter primer (MAX), tip read, seal, computeRowHash,
//    backtick-quoted INSERT, then verify(). A correct chain verifies ok:true.
// ====================================================================
async function _testAuditRecordAndChain() {
  var events = [
    { action: "system.boot", outcome: "success" },
    { action: "auth.login.success", outcome: "success", actor: { userId: "u-1", ip: "10.0.0.7" } },
    { action: "consent.granted", outcome: "success",
      actor: { userId: "u-2" }, resource: { kind: "purpose", id: "marketing" },
      metadata: { region: "eu" } },
    { action: "system.shutdown", outcome: "success" },
  ];
  var appended = [];
  for (var i = 0; i < events.length; i++) appended.push(await b.audit.record(events[i]));
  check("audit.record returned a monotonic counter per row (1..4) on MySQL",
    appended[0].monotonicCounter === 1 && appended[3].monotonicCounter === 4);
  check("audit.record landed 4 rows in _blamejs_audit_log on real MySQL",
    _countMysql("`_blamejs_audit_log`", null) === 4);

  var v = await b.audit.verify({});
  check("audit.verify walks the live MySQL chain and returns ok:true", v.ok === true);
  check("audit.verify counted every stored row (rowsVerified === 4)",
    v.ok === true && v.rowsVerified === 4);
  if (!v.ok) check("AUDIT-VERIFY DETAIL (mysql): '" + v.reason + "' at row " + v.breakAt, false);

  // Counter primer: a fresh in-process chain-writer must read MAX from MySQL
  // and continue at 5, not restart at 1.
  b.audit._resetForTest();
  var more = await b.audit.record({ action: "system.boot", outcome: "success" });
  check("counter primer read MAX(monotonicCounter) from live MySQL (continued at 5)",
    more.monotonicCounter === 5);
  check("5 audit rows present after primer-continued append on MySQL",
    _countMysql("`_blamejs_audit_log`", null) === 5);
}

// ====================================================================
// 2. audit.checkpoint() → _insertCheckpoint + _upsertAuditTip on MySQL.
//    The tip UPSERT is the MySQL ON DUPLICATE KEY UPDATE + IF(<fence>,…)
//    fold; FENCED_OUT detection reads the stored token back (no RETURNING on
//    MySQL). A strictly-lower incoming token must be FENCED_OUT.
// ====================================================================
async function _testCheckpointAndFence() {
  var ck = await b.audit.checkpoint({});
  check("audit.checkpoint anchored the live MySQL chain tip (counter 5)",
    ck && ck.atMonotonicCounter === 5);
  check("checkpoint row landed in _blamejs_audit_checkpoints on MySQL",
    _countMysql("`_blamejs_audit_checkpoints`", null) === 1);

  check("_upsertAuditTip wrote the single audit-tip row on MySQL",
    _countMysql("`_blamejs_audit_tip`", "`scope` = 'audit'") === 1);
  check("audit-tip atMonotonicCounter matches the chain tip (5) on MySQL",
    Number(_scalar("SELECT `atMonotonicCounter` FROM `_blamejs_audit_tip` WHERE `scope` = 'audit'")) === 5);

  var vc = await b.audit.verifyCheckpoints();
  check("audit.verifyCheckpoints returns ok:true against the live MySQL checkpoint",
    vc.ok === true && vc.checkpointsVerified === 1);
  if (!vc.ok) check("VERIFY-CHECKPOINTS DETAIL (mysql): '" + vc.reason + "'", false);

  // Fencing guard. Raise the stored token directly to a high value, then a
  // second checkpoint at the leader's (lower) fencing token must be
  // FENCED_OUT — the MySQL IF-fold keeps the stored token, and the readback
  // detection surfaces the FENCED_OUT.
  var storedTok = Number(_scalar("SELECT `fencingToken` FROM `_blamejs_audit_tip` WHERE `scope`='audit'"));
  var highTok = storedTok + 1000000;
  _mysqlRoot("UPDATE `_blamejs_audit_tip` SET `fencingToken` = " + highTok + " WHERE `scope`='audit'", DB_NAME);
  // Append a row so checkpoint has a new tip to anchor, then attempt the
  // checkpoint — its _upsertAuditTip carries the leader's lower token.
  await b.audit.record({ action: "system.boot", outcome: "success" });
  var fencedErr = null;
  try { await b.audit.checkpoint({}); } catch (e) { fencedErr = e; }
  check("checkpoint at a lower fencing token is FENCED_OUT on MySQL (IF-fold + readback)",
    fencedErr !== null && /FENCED_OUT/.test((fencedErr.code || "") + (fencedErr.message || "")));
  check("the stored fencingToken stayed at the higher value (lower token did not overwrite)",
    Number(_scalar("SELECT `fencingToken` FROM `_blamejs_audit_tip` WHERE `scope`='audit'")) === highTok);

  // Restore the leader's token so subsequent sections can checkpoint again.
  _mysqlRoot("UPDATE `_blamejs_audit_tip` SET `fencingToken` = " + storedTok + " WHERE `scope`='audit'", DB_NAME);
}

// ====================================================================
// 3. Coercion fidelity: read an audit row back THROUGH clusterStorage and
//    assert the normalized JS shape — MySQL --batch hands BIGINT as text,
//    coerceRows must turn the framework int columns into JS numbers.
// ====================================================================
async function _testCoercionFidelity() {
  var built = require("../../lib/sql").select("audit_log", { dialect: b.clusterStorage.dialect() })
    .orderBy("monotonicCounter", "asc").limit(1).toSql();
  var rows = await b.clusterStorage.executeAll(built.sql, built.params);
  check("clusterStorage.executeAll read an audit row back from live MySQL", rows.length === 1);
  var row = rows[0];
  check("coercion (mysql): monotonicCounter is a JS number === 1",
    typeof row.monotonicCounter === "number" && row.monotonicCounter === 1);
  check("coercion (mysql): recordedAt BIGINT coerced to a JS number",
    typeof row.recordedAt === "number");
  check("coercion (mysql): rowHash stays a string under the camelCase key",
    typeof row.rowHash === "string" && row.rowHash.length > 0);
}

// ====================================================================
// 4. audit-tools exportSlice → verifyBundle over the live MySQL audit_log
//    via the default clusterStorage readers, then the purge-anchor UPSERT.
// ====================================================================
async function _testAuditToolsBundle(tmpDir) {
  var pass = Buffer.from("audit-bundle-passphrase-not-secret-1234567890", "utf8");
  var nRows = _countMysql("`_blamejs_audit_log`", null);

  var exDir = path.join(tmpDir, "export-bundle-my");
  var ex = await b.auditTools.exportSlice({ out: exDir, passphrase: pass });
  check("audit-tools.exportSlice read the live MySQL chain + wrote a bundle",
    ex.rowCount === nRows);

  var exVerify = await b.auditTools.verifyBundle({ in: exDir, passphrase: pass });
  check("audit-tools.verifyBundle round-trips the exported live-MySQL slice (ok:true)",
    exVerify.ok === true && exVerify.rowsVerified === nRows);
  if (!exVerify.ok) check("EXPORT-VERIFY DETAIL (mysql): '" + exVerify.reason + "'", false);

  // The purge-anchor UPSERT (the external-DB piece of purge's default apply)
  // through b.sql + clusterStorage must land on MySQL (ON DUPLICATE KEY).
  await b.clusterStorage.execute(
    "INSERT INTO `_blamejs_audit_purge_anchor` " +
    "(`scope`,`lastPurgedCounter`,`lastPurgedRowHash`,`archiveBundleId`,`purgedAt`) " +
    "VALUES ('audit', ?, ?, ?, ?) " +
    "ON DUPLICATE KEY UPDATE `lastPurgedCounter`=VALUES(`lastPurgedCounter`), " +
    "`lastPurgedRowHash`=VALUES(`lastPurgedRowHash`), " +
    "`archiveBundleId`=VALUES(`archiveBundleId`), `purgedAt`=VALUES(`purgedAt`)",
    [3, "anchor-hash", "bundle-1", Date.now()]);
  var anchor = await b.clusterStorage.executeOne(
    "SELECT `lastPurgedCounter`, `lastPurgedRowHash` FROM `_blamejs_audit_purge_anchor` WHERE `scope` = ?",
    ["audit"]);
  check("purge anchor UPSERT through clusterStorage landed on MySQL + coerced counter BIGINT→number",
    anchor && anchor.lastPurgedCounter === 3 && anchor.lastPurgedRowHash === "anchor-hash");
  _mysqlRoot("DELETE FROM `_blamejs_audit_purge_anchor` WHERE `scope`='audit'", DB_NAME);
}

// ====================================================================
// 5. break-glass policy + grant + unsealRow consume — the whole flow on
//    live MySQL: policy UPSERT (sealed, ON DUPLICATE KEY), policy.get/list,
//    grant (TOTP verify → sealed grant INSERT with the derived hash NOT
//    NULL), then unsealRow (grant fetch + backtick-quoted rowsConsumed++
//    increment + glass-locked column unseal of a real MySQL-stored row).
// ====================================================================
async function _testBreakGlass() {
  b.breakGlass.init({ trustProxy: false });

  _mysqlRoot("CREATE TABLE IF NOT EXISTS `patients` (" +
    "`_id` VARCHAR(64) PRIMARY KEY, `mrn` TEXT, `ssn` TEXT, " +
    "`residency` TEXT, `notes` TEXT)", DB_NAME);

  var patient = b.cryptoField.sealRow("patients", {
    _id: "patient-001", mrn: "MRN-1", ssn: "123-45-6789",
    residency: "eu", notes: "high blood pressure",
  });
  await b.clusterStorage.execute(
    "INSERT INTO `patients` (`_id`,`mrn`,`ssn`,`residency`,`notes`) VALUES (?,?,?,?,?)",
    [patient._id, patient.mrn, patient.ssn, patient.residency, patient.notes]);
  check("break-glass (mysql): glass-locked ssn is stored SEALED (vault:-prefixed)",
    /vault[:.]/.test(String(_scalar("SELECT `ssn` FROM `patients` WHERE `_id`='patient-001'"))));

  var setRes = await b.breakGlass.policy.set("patients", {
    columns: ["ssn", "notes"], factors: ["totp"],
    grantTtl: b.constants.TIME.minutes(15), maxRowsPerGrant: 1,
    reasonMinLength: 12, pinIp: false, sessionPin: false,
  });
  check("break-glass (mysql): policy.set UPSERT landed on MySQL", setRes.applied === true);
  check("break-glass (mysql): one policy row physically present",
    _countMysql("`_blamejs_break_glass_policies`", null) === 1);

  var got = await b.breakGlass.policy.get("patients");
  check("break-glass (mysql): policy.get reads + unseals the MySQL policy row",
    got && got.table === "patients" && got.columns.length === 2 && got.columns.indexOf("ssn") !== -1);
  check("break-glass (mysql): policy numeric fields coerced (grantTtl is a number)",
    typeof got.grantTtl === "number" && got.grantTtl > 0);

  var listed = await b.breakGlass.policy.list();
  check("break-glass (mysql): policy.list enumerates the glass-locked table",
    listed.length === 1 && listed[0].table === "patients");

  var totpSecret = b.auth.totp.generateSecret();
  var nowMs = Date.now();
  var code = b.auth.totp.generate(totpSecret, { now: nowMs });
  var req = {
    user: { id: "dr-house", scopes: [] }, socket: { remoteAddress: "127.0.0.1" },
    headers: { "user-agent": "test-agent" }, method: "POST", url: "/admin/break-glass",
  };
  var handle = await b.breakGlass.grant({
    req: req, table: "patients", columns: ["ssn"],
    reason: "ER admit verifying identity for patient-001",
    factor: { type: "totp", secret: totpSecret, code: code, now: nowMs },
  });
  check("break-glass (mysql): grant minted after live TOTP verify",
    handle && typeof handle.id === "string" && handle.id.indexOf("bg-") === 0);
  check("break-glass (mysql): grant row physically landed",
    _countMysql("`_blamejs_break_glass_grants`", null) === 1);
  check("break-glass (mysql): issuedToActorHash NOT-NULL derived column populated",
    String(_scalar("SELECT `issuedToActorHash` FROM `_blamejs_break_glass_grants` LIMIT 1") || "").length > 0);

  var unsealed = await b.breakGlass.unsealRow(handle, "patients", "patient-001");
  check("break-glass (mysql): unsealRow returned the decrypted glass-locked ssn",
    unsealed && unsealed.ssn === "123-45-6789");
  check("break-glass (mysql): atomic rowsConsumed++ persisted (backtick whereRaw fence)",
    Number(_scalar("SELECT `rowsConsumed` FROM `_blamejs_break_glass_grants` LIMIT 1")) === 1);

  var exhaustedErr = null;
  try { await b.breakGlass.unsealRow(handle, "patients", "patient-001"); }
  catch (e) { exhaustedErr = e; }
  check("break-glass (mysql): second unseal refused — grant exhausted (row-by-row auth)",
    exhaustedErr && /exhausted/i.test((exhaustedErr.code || "") + (exhaustedErr.message || "")));

  // listActive / listActiveAll exercise the same backtick whereRaw fence.
  var active = await b.breakGlass.listActiveAll({ table: "patients" });
  check("break-glass (mysql): listActiveAll runs the backtick rowsConsumed<max fence (grant now exhausted → 0)",
    Array.isArray(active) && active.length === 0);
}

// ====================================================================
// 6. crypto-field K_row (vault.row:) sealed cell stored on MySQL + read
//    back, proving the typed codec survives a real TEXT round-trip. The
//    wrapped row-secret lives in the LOCAL per-row-keys registry; the
//    sealed CELL is what lands on MySQL.
// ====================================================================
async function _testCryptoFieldKRowRoundTrip() {
  b.cryptoField.declarePerRowKey("krow_demo", { keySize: 32 });
  b.cryptoField.registerTable("krow_demo", { sealedFields: ["secret", "blobCol", "objCol"] });

  var rowId = "krow-row-1";
  var kRow = b.cryptoField.materializePerRowKey("krow_demo", rowId, b.db);
  check("crypto-field (mysql): materializePerRowKey produced a 32-byte K_row",
    Buffer.isBuffer(kRow) && kRow.length === 32);

  var origBuf = Buffer.from([0, 1, 2, 250, 251, 255]);
  var origObj = { kind: "phi", level: 9 };
  var sealed = b.cryptoField.sealRow("krow_demo",
    { _id: rowId, secret: "top-secret-string", blobCol: origBuf, objCol: origObj },
    { kRow: kRow, rowId: rowId });
  check("crypto-field (mysql): sealRow under K_row emitted vault.row: cells",
    b.cryptoField.isRowSealed(sealed.secret) && b.cryptoField.isRowSealed(sealed.blobCol) &&
    b.cryptoField.isRowSealed(sealed.objCol));

  _mysqlRoot("CREATE TABLE IF NOT EXISTS `krow_demo` (" +
    "`_id` VARCHAR(64) PRIMARY KEY, `secret` TEXT, `blobCol` TEXT, `objCol` TEXT)", DB_NAME);
  await b.clusterStorage.execute(
    "INSERT INTO `krow_demo` (`_id`,`secret`,`blobCol`,`objCol`) VALUES (?,?,?,?)",
    [rowId, sealed.secret, sealed.blobCol, sealed.objCol]);

  var stored = await b.clusterStorage.executeOne(
    "SELECT `_id`,`secret`,`blobCol`,`objCol` FROM `krow_demo` WHERE `_id` = ?", [rowId]);
  check("crypto-field (mysql): vault.row: cells survived the MySQL TEXT round-trip intact",
    stored.secret === sealed.secret && stored.blobCol === sealed.blobCol && stored.objCol === sealed.objCol);

  // Unseal under K_row (the read path resolves the wrapped secret from the
  // LOCAL per-row-keys registry) — typed codec restores original types.
  var unsealed = b.cryptoField.unsealRow("krow_demo", stored, "svc", b.db);
  check("crypto-field (mysql): K_row unseal restored the string value",
    unsealed.secret === "top-secret-string");
  check("crypto-field (mysql): K_row unseal restored the Buffer value byte-for-byte",
    Buffer.isBuffer(unsealed.blobCol) && unsealed.blobCol.equals(origBuf));
  check("crypto-field (mysql): K_row unseal restored the object value",
    unsealed.objCol && unsealed.objCol.kind === "phi" && unsealed.objCol.level === 9);
}

// ====================================================================
// 7. crypto-field derived-hash dual-read on a row stored in MySQL. A row
//    whose derived-hash column holds the LEGACY salted-sha3 digest is found
//    via lookupHashCandidates' legacy member; reading it back through the
//    framework leaves the keyed-MAC value the active lookup uses.
// ====================================================================
async function _testDerivedHashDualRead() {
  b.cryptoField.registerTable("dh_my", {
    sealedFields:  ["email"],
    derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
  });
  var email = "Carol@Example.com";
  var lk = b.cryptoField.lookupHash("dh_my", "email", email);
  check("derived-hash (mysql): active lookup is the keyed MAC (64 hex)", lk.value.length === 64);
  check("derived-hash (mysql): legacyValue surfaced (128 hex)",
    typeof lk.legacyValue === "string" && lk.legacyValue.length === 128);
  var cands = b.cryptoField.lookupHashCandidates("dh_my", "email", email);
  check("derived-hash (mysql): candidates carry BOTH digests (match-either)",
    cands.values.length === 2 && cands.values.indexOf(lk.value) !== -1 &&
    cands.values.indexOf(lk.legacyValue) !== -1);

  // Forge a legacy-indexed row on MySQL.
  _mysqlRoot("CREATE TABLE IF NOT EXISTS `dh_my` (" +
    "`_id` VARCHAR(64) PRIMARY KEY, `email` TEXT, `emailHash` TEXT)", DB_NAME);
  var sealed = b.cryptoField.sealRow("dh_my", { _id: "c-legacy", email: email });
  sealed.emailHash = lk.legacyValue;
  await b.clusterStorage.execute(
    "INSERT INTO `dh_my` (`_id`,`email`,`emailHash`) VALUES (?,?,?)",
    [sealed._id, sealed.email, sealed.emailHash]);
  var foundLegacy = await b.clusterStorage.executeOne(
    "SELECT `_id` FROM `dh_my` WHERE `emailHash` = ?", [lk.legacyValue]);
  check("derived-hash (mysql): legacy-indexed row found via the legacy candidate hash",
    foundLegacy && foundLegacy._id === "c-legacy");
  _mysqlRoot("DROP TABLE IF EXISTS `dh_my`", DB_NAME);
  b.cryptoField.clearForTest();
  // Re-register the framework tables clearForTest dropped so later teardown
  // (which seals/unseals through cryptoField) still has its schema.
  // (setupTestDb registered them via db.init's FRAMEWORK_SCHEMA; clearForTest
  // wiped the whole registry, so a fresh db.init-equivalent isn't available
  // here — but teardown only closes the db, no further seal calls, so this is
  // safe. Left as a note for maintainers.)
}

// ====================================================================
// 8. Tamper detection on the live chain — mutate a hashed column, confirm
//    verify reports ok:false. Meaningful only because the clean chain
//    verified ok:true.
// ====================================================================
async function _testTamperDetection() {
  // Drop the append-only WORM triggers (the privileged-DB-write attacker the
  // chain defends against), mutate a hashed column, confirm verify catches it.
  // Trigger names follow the framework's `no_update_<table>` / `no_delete_<table>`
  // convention; drop both so the tampering UPDATE can land.
  try { _mysqlRoot("DROP TRIGGER IF EXISTS `no_update__blamejs_audit_log`", DB_NAME); } catch (_e) {}
  try { _mysqlRoot("DROP TRIGGER IF EXISTS `no_delete__blamejs_audit_log`", DB_NAME); } catch (_e) {}
  _mysqlRoot("UPDATE `_blamejs_audit_log` SET `action` = 'auth.login.tampered' " +
    "WHERE `monotonicCounter` = 2", DB_NAME);
  var v = await b.audit.verify({});
  check("audit.verify returns ok:false after a hashed column is tampered on MySQL", v.ok === false);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
