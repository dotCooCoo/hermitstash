// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live MySQL proof that the b.sql data-layer migration of the six
 * privacy/identity/production modules (consent / api-key / legal-hold /
 * subject / retention / scheduler) emits valid MySQL — backtick
 * identifiers, `ON DUPLICATE KEY UPDATE` upserts, the IF()-based fence
 * rewrite the builder synthesizes for MySQL (which has no `WHERE` on
 * upsert and no `RETURNING`), and the unsigned/BIGINT coercion at the
 * driver boundary.
 *
 * MySQL is NOT a framework cluster backend (frameworkSchema /
 * clusterStorage support postgres + sqlite only — see
 * audit-chain-external-db.test.js). So api-key / consent never dispatch
 * to MySQL in production; the framework table shapes here are exercised
 * as b.sql operator-app-schema targets — proving the SAME builders that
 * back the migrated modules emit MySQL that runs. The headline MySQL-
 * specific surface:
 *
 *   - consent fenced tip: the builder rewrites `conflictWhere(fence)` +
 *     `RETURNING` into per-column `IF(stored.fencingToken <=
 *     VALUES(fencingToken), VALUES(col), col)` (no WHERE / no RETURNING
 *     on MySQL). This test proves the IF-fence actually PRESERVES the old
 *     tip on a lower fencing token against a real MySQL server (the
 *     security property), and documents that the RETURNING-0-rows
 *     fenced-out signal consent.js depends on does NOT exist on MySQL.
 *   - api-key:    issue/verify/rotate/revoke/purge SQL shapes (INSERT /
 *                 SELECT / the lastUsedAt UPDATE / graceful+cutover
 *                 rotate UPDATE / the whereGroup-OR purge SELECT+DELETE)
 *                 + BIGINT-as-string -> JS-number coercion via the
 *                 framework's coerceRows on the real MySQL readback.
 *   - legal-hold: place INSERT / release DELETE / whereLike prefix history.
 *   - subject:    the INSERT-OR-REPLACE upsert + restrict INSERT/DELETE.
 *   - retention:  hard / soft / erase NULL-set / cascade DELETE / candidate.
 *   - scheduler:  the tick-claim upsert `onConflict(tickKey).doNothing()`
 *                 — on MySQL this folds to `ON DUPLICATE KEY UPDATE
 *                 tickKey = tickKey`, so a duplicate tickKey (the split-
 *                 brain replay) affects 0 rows = the loser skips, exactly
 *                 the dedup signal `_fireOnce` reads — plus the prune
 *                 DELETE and the BIGINT-as-string -> JS-number coercion of
 *                 the claimed-at readback.
 *
 * Distinct from data-layer-mysql.test.js (cache / nonce / rate-limit
 * cluster backends). Driver: a minimal docker-exec `mysql -e` shim (no
 * shell parse of SQL beyond the -e arg). `?` placeholders bound inline
 * (operator-controlled values only). Tables namespaced + DROP/recreated.
 *
 * RUN: node scripts/test-integration.js --skip-service-check data-layer-mysql-privacy
 */

var execFileSync = require("node:child_process").execFileSync;
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var cryptoField = require("../../lib/crypto-field");
var b = require("../../");

var CONTAINER = "blamejs-test-mysql";
var DB_NAME   = "blamejs_test";

function _mysql(sql) {
  var out;
  try {
    out = execFileSync("docker",
      ["exec", "-i", CONTAINER, "mysql", "-uroot", "-pblamejs_test_root",
       "--batch", "--raw", DB_NAME, "-e", sql],
      { stdio: ["pipe", "pipe", "pipe"], maxBuffer: 16 * 1024 * 1024 }
    ).toString("utf8");
  } catch (e) {
    var err = new Error(e.stderr ? e.stderr.toString("utf8") : (e.message || String(e)));
    err.cause = e;
    throw err;
  }
  return out;
}

// Inline `?` binding. Values are operator-controlled (ids / hashes /
// numbers / null). MySQL: backslash IS a string escape by default, so
// escape both backslash and single-quote.
function _bindParams(sql, params) {
  var i = 0;
  return sql.replace(/\?/g, function () {
    if (i >= params.length) throw new Error("placeholder/param count mismatch");
    var p = params[i++];
    if (p === null || p === undefined) return "NULL";
    if (typeof p === "number") return String(p);
    if (typeof p === "boolean") return p ? "1" : "0";
    if (Buffer.isBuffer(p)) return "x'" + p.toString("hex") + "'";
    return "'" + String(p).replace(/\\/g, "\\\\").replace(/'/g, "''") + "'";
  });
}

// Parse a --batch tab-separated result block. NULL prints as the literal
// "NULL"; numeric columns come back as STRINGS (faithful to a real driver
// returning BIGINT as a JS string), so the framework's coerceRows must
// turn them back to numbers.
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

// A MySQL external-db driver: every query() shells `mysql -e`. Writes
// report ROW_COUNT() (read on the SAME exec/connection so the count is
// faithful); reads return parsed rows.
function _makeDockerMysqlDriver() {
  return {
    connect: async function () { return { id: 1 }; },
    query: async function (_client, sql, params) {
      params = params || [];
      var bound = _bindParams(sql, params);
      var t = bound.trim();
      if (/^(SELECT|SHOW|WITH)/i.test(t)) {
        var sel = _parseBatch(_mysql(bound));
        return { rows: sel.rows, rowCount: sel.rows.length };
      }
      var combined = _mysql(bound + ";\nSELECT ROW_COUNT() AS `__rc`;");
      var rc = _parseBatch(combined);
      var n = (rc.rows[0] && rc.rows[0].__rc != null) ? Number(rc.rows[0].__rc) : 0;
      if (!Number.isFinite(n) || n < 0) n = 0;   // CREATE/etc return -1
      return { rows: [], rowCount: n };
    },
    close: async function () { /* no-op */ },
    dialect: "mysql",
  };
}

function _resetState() {
  try { b.cluster._resetForTest(); } catch (_e) {}
  try { b.consent._resetForTest(); } catch (_e) {}
  try { b.externalDb._resetForTest(); } catch (_e) {}
}

async function run() {
  var mysqlSvc = await services.requireService("mysql");
  if (!mysqlSvc.ok) throw new Error("mysql unreachable: " + mysqlSvc.reason);

  var TABLES = [
    "dl_myp_api_keys", "dl_myp_consent_tip",
    "dl_myp_hold", "dl_myp_erasures", "dl_myp_restrictions",
    "dl_myp_audit", "dl_myp_orders", "dl_myp_order_lines",
    "dl_myp_sched_ticks",
  ];
  _mysql(TABLES.map(function (t) { return "DROP TABLE IF EXISTS `" + t + "`;"; }).join(" "));

  _resetState();

  // Vault + api-key cryptoField schema, so sealRow seals ownerId/scopes/
  // metadata and derives ownerIdHash (db.js FRAMEWORK_SCHEMA wires this
  // for the local path).
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dl-myp-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  cryptoField.registerTable("dl_myp_api_keys", {
    sealedFields:  ["ownerId", "scopes", "metadata"],
    derivedHashes: { ownerIdHash: { from: "ownerId" } },
  });

  var driver = _makeDockerMysqlDriver();
  b.externalDb.init({
    backends: { ops: { connect: driver.connect, query: driver.query, close: driver.close, dialect: "mysql" } },
  });

  // b.sql emits `?`; MySQL keeps `?` (placeholderize is passthrough for
  // mysql), so the driver binds inline — no translation needed.
  function _q(built) {
    return b.externalDb.query(built.sql, built.params, { backend: "ops" });
  }

  var nowMs = Date.now();

  // ====================================================================
  // api-key SQL shapes on MySQL. The api-key registry's clusterStorage
  // dispatch only targets postgres/sqlite, so here we drive the SAME
  // b.sql shapes the module emits (built at { dialect: "mysql" }) directly
  // against MySQL — proving the migrated statements are valid MySQL and
  // the coercion round-trips. We hand-seal the row with cryptoField the
  // same way issue() does.
  // ====================================================================
  var apiKeysDdl = b.sql.createTable("dl_myp_api_keys", [
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
  ], { dialect: "mysql", quoteName: true });
  // MySQL needs a key length on a TEXT PRIMARY KEY. Patch the emitted DDL
  // so `id` is a bounded VARCHAR PK (operator-app-schema concern, not a
  // framework-shape concern — the framework only ships pg/sqlite DDL).
  _mysql(apiKeysDdl.sql.replace("`id` TEXT PRIMARY KEY", "`id` VARCHAR(190) PRIMARY KEY"));
  check("api-key: b.sql createTable DDL (MySQL backticks) ran on real MySQL", true);

  var COLS = ["id", "namespace", "ownerId", "ownerIdHash", "secretHash",
    "secondarySecretHash", "secondaryExpiresAt", "scopes", "metadata",
    "createdAt", "expiresAt", "revokedAt", "lastUsedAt", "prefix"];

  function _sealApiRow(plain) {
    var sealed = cryptoField.sealRow("dl_myp_api_keys", plain);
    for (var i = 0; i < COLS.length; i++) if (!(COLS[i] in sealed)) sealed[COLS[i]] = null;
    return sealed;
  }
  function _insApiRow(plain) {
    var sealed = _sealApiRow(plain);
    var insertRow = {};
    for (var ci = 0; ci < COLS.length; ci++) insertRow[COLS[ci]] = sealed[COLS[ci]];
    return _q(b.sql.insert("dl_myp_api_keys", { dialect: "mysql", quoteName: true }).columns(COLS).values(insertRow).toSql());
  }
  var credentialHash = require("../../lib/credential-hash");
  var bCrypto = require("../../lib/crypto");
  var frameworkSchema = require("../../lib/framework-schema");

  var idHex = bCrypto.generateToken(8);
  var compositeId = "live:" + idHex;
  var secretEnvelope = await credentialHash.hash(bCrypto.generateToken(16), { algo: "shake256" });
  await _insApiRow({
    id: compositeId, namespace: "live", ownerId: "owner-1",
    secretHash: secretEnvelope, secondarySecretHash: null, secondaryExpiresAt: null,
    scopes: JSON.stringify(["read:x"]), metadata: JSON.stringify({ name: "dev" }),
    createdAt: nowMs, expiresAt: nowMs + b.constants.TIME.days(30),
    revokedAt: null, lastUsedAt: null, prefix: "bk",
  });
  // ownerIdHash must be a real non-null derived hash (sealRow populated it).
  var ownerHashRow = _parseBatch(_mysql("SELECT ownerIdHash FROM dl_myp_api_keys WHERE id = '" + compositeId + "';"));
  check("api-key: sealRow populated a non-null derived ownerIdHash on MySQL",
        ownerHashRow.rows.length === 1 && !!ownerHashRow.rows[0].ownerIdHash);

  // SELECT-back + coercion: read the row through coerceRows so
  // createdAt/expiresAt (TEXT-from-MySQL) become JS numbers.
  var apiSel = await _q(b.sql.select("dl_myp_api_keys", { dialect: "mysql", quoteName: true })
    .columns(COLS).where("id", compositeId).toSql());
  check("api-key: SELECT round-trips the row on MySQL", apiSel.rows.length === 1);
  var coercedApi = frameworkSchema.coerceRows(apiSel.rows);
  check("api-key: coerceRows turns createdAt BIGINT-string -> JS number on MySQL",
        typeof coercedApi[0].createdAt === "number" && coercedApi[0].createdAt === nowMs);
  check("api-key: coerceRows turns expiresAt BIGINT-string -> JS number on MySQL",
        typeof coercedApi[0].expiresAt === "number" &&
        coercedApi[0].expiresAt === nowMs + b.constants.TIME.days(30));

  // lastUsedAt UPDATE (verify's trackLastUsedAt touch).
  var luRes = await _q(b.sql.update("dl_myp_api_keys", { dialect: "mysql", quoteName: true })
    .set({ lastUsedAt: nowMs }).where("id", compositeId).toSql());
  check("api-key: lastUsedAt UPDATE affected 1 row on MySQL", luRes.rowCount === 1);

  // graceful rotate UPDATE — move secret to secondary slot with TTL.
  var newHash = await credentialHash.hash(bCrypto.generateToken(16), { algo: "shake256" });
  await _q(b.sql.update("dl_myp_api_keys", { dialect: "mysql", quoteName: true })
    .set({ secretHash: newHash, secondarySecretHash: secretEnvelope, secondaryExpiresAt: nowMs + b.constants.TIME.days(7) })
    .where("id", compositeId).toSql());
  var graceRow = _parseBatch(_mysql("SELECT secondaryExpiresAt FROM dl_myp_api_keys WHERE id = '" + compositeId + "';"));
  check("api-key: graceful rotate UPDATE persisted secondaryExpiresAt on MySQL",
        graceRow.rows.length === 1 && /\d{6,}/.test(String(graceRow.rows[0].secondaryExpiresAt)));

  // hard cutover UPDATE — clear the secondary slot.
  await _q(b.sql.update("dl_myp_api_keys", { dialect: "mysql", quoteName: true })
    .set({ secretHash: newHash, secondarySecretHash: null, secondaryExpiresAt: null })
    .where("id", compositeId).toSql());
  var cutRow = _parseBatch(_mysql("SELECT secondarySecretHash FROM dl_myp_api_keys WHERE id = '" + compositeId + "';"));
  check("api-key: hard cutover NULLed secondarySecretHash on MySQL",
        cutRow.rows.length === 1 && cutRow.rows[0].secondarySecretHash === null);

  // revoke UPDATE (set revokedAt where revokedAt IS NULL).
  var revRes = await _q(b.sql.update("dl_myp_api_keys", { dialect: "mysql", quoteName: true })
    .set({ revokedAt: nowMs }).where("id", compositeId).whereNull("revokedAt").toSql());
  check("api-key: revoke UPDATE (set where revokedAt IS NULL) affected 1 row on MySQL",
        revRes.rowCount === 1);

  // Seed an expired + a fresh key for the whereGroup-OR purge predicate.
  await _insApiRow({
    id: "live:purge-0", namespace: "live", ownerId: "owner-p0",
    secretHash: await credentialHash.hash(bCrypto.generateToken(16), { algo: "shake256" }),
    secondarySecretHash: null, secondaryExpiresAt: null, scopes: null, metadata: null,
    createdAt: nowMs, expiresAt: 1, revokedAt: null, lastUsedAt: null, prefix: "bk",   // expired
  });
  await _insApiRow({
    id: "live:purge-1", namespace: "live", ownerId: "owner-p1",
    secretHash: await credentialHash.hash(bCrypto.generateToken(16), { algo: "shake256" }),
    secondarySecretHash: null, secondaryExpiresAt: null, scopes: null, metadata: null,
    createdAt: nowMs, expiresAt: nowMs + b.constants.TIME.days(365), revokedAt: null, lastUsedAt: null, prefix: "bk",   // fresh
  });
  var threshold = nowMs - b.constants.TIME.days(90);
  function _purgeWhere(qb) {
    return qb.where("namespace", "live").whereGroup(function (g) {
      g.whereGroup(function (a) { a.whereNotNull("revokedAt").where("revokedAt", "<", threshold); })
       .orWhereGroup(function (b2) { b2.whereNotNull("expiresAt").where("expiresAt", "<", threshold); });
    });
  }
  var purgeSel = await _q(_purgeWhere(b.sql.select("dl_myp_api_keys", { dialect: "mysql", quoteName: true }).columns(["id"])).toSql());
  // owner-1 (revokedAt=now, NOT < threshold), purge-0 (expiresAt=1 < threshold) → exactly 1.
  check("api-key: whereGroup-OR purge SELECT found the 1 expired key on MySQL",
        purgeSel.rows.length === 1 && purgeSel.rows[0].id === "live:purge-0");
  var purgeDel = await _q(_purgeWhere(b.sql.delete("dl_myp_api_keys", { dialect: "mysql", quoteName: true })).toSql());
  check("api-key: whereGroup-OR purge DELETE removed exactly 1 row on MySQL", purgeDel.rowCount === 1);

  // ====================================================================
  // consent fenced tip on MySQL — the headline MySQL-specific surface.
  // The builder rewrites conflictWhere(fence) + RETURNING into per-column
  // IF(stored.fencingToken <= VALUES(fencingToken), VALUES(col), col).
  // Prove the IF-fence PRESERVES the old tip when a lower fencing token
  // arrives, and document that the RETURNING 0-rows fenced-out signal
  // consent.js uses does NOT exist here.
  // ====================================================================
  var consentTipDdl = b.sql.createTable("dl_myp_consent_tip", [
    { name: "scope",              type: "text", primaryKey: true },
    { name: "atMonotonicCounter", type: "int", notNull: true },
    { name: "rowHash",            type: "text" },
    { name: "signedAt",           type: "text" },
    { name: "fencingToken",       type: "int", notNull: true },
  ], { dialect: "mysql", quoteName: true });
  _mysql(consentTipDdl.sql.replace("`scope` TEXT PRIMARY KEY", "`scope` VARCHAR(64) PRIMARY KEY"));

  var safeSql = require("../../lib/safe-sql");
  function _tipUpsert(counter, rowHash, signedAt, fencingToken) {
    var tipFence = "dl_myp_consent_tip." + safeSql.quoteIdentifier("fencingToken", "mysql") +
      " <= VALUES(" + safeSql.quoteIdentifier("fencingToken", "mysql") + ")";
    return b.sql.upsert("dl_myp_consent_tip", { dialect: "mysql", quoteName: true })
      .columns(["scope", "atMonotonicCounter", "rowHash", "signedAt", "fencingToken"])
      .values({ scope: "consent", atMonotonicCounter: counter, rowHash: rowHash, signedAt: signedAt, fencingToken: fencingToken })
      .onConflict(["scope"])
      .doUpdateFromExcluded(["atMonotonicCounter", "rowHash", "signedAt", "fencingToken"])
      .conflictWhere(tipFence, [])
      .toSql();
  }
  // Confirm the builder produced the MySQL IF()-fence rewrite (no WHERE,
  // no RETURNING — MySQL upsert has neither).
  var tipSqlText = _tipUpsert(1, "h", "s", 1).sql;
  check("consent-tip: builder rewrote the fence into MySQL IF() conditional updates",
        /ON DUPLICATE KEY UPDATE/.test(tipSqlText) &&
        /IF\(dl_myp_consent_tip\.`fencingToken` <= VALUES\(`fencingToken`\)/.test(tipSqlText) &&
        !/RETURNING/.test(tipSqlText));

  await _q(_tipUpsert(1, "hash-1", "1700000000001", 1));   // initial
  await _q(_tipUpsert(2, "hash-2", "1700000000002", 2));   // higher token — advances
  var tipAfterHigher = _parseBatch(_mysql("SELECT atMonotonicCounter, rowHash, fencingToken FROM dl_myp_consent_tip WHERE scope='consent';"));
  check("consent-tip: higher fencingToken advanced the tip to counter 2 on MySQL",
        tipAfterHigher.rows[0].atMonotonicCounter === "2" && tipAfterHigher.rows[0].rowHash === "hash-2");

  // LOWER token (1) with a would-be newer counter/hash — the IF-fence must
  // keep the OLD values (stored token 2 <= incoming 1 is FALSE).
  await _q(_tipUpsert(99, "hash-evil", "1700000000099", 1));
  var tipAfterFence = _parseBatch(_mysql("SELECT atMonotonicCounter, rowHash, fencingToken FROM dl_myp_consent_tip WHERE scope='consent';"));
  check("consent-tip: MySQL IF-fence PRESERVED the tip against a lower fencing token " +
        "(no hash-evil, still counter 2)",
        tipAfterFence.rows[0].rowHash === "hash-2" &&
        tipAfterFence.rows[0].atMonotonicCounter === "2" &&
        tipAfterFence.rows[0].fencingToken === "2");

  // EQUAL token (2) — the <= fence accepts; the tip advances.
  await _q(_tipUpsert(3, "hash-3", "1700000000003", 2));
  var tipAfterEqual = _parseBatch(_mysql("SELECT atMonotonicCounter, rowHash FROM dl_myp_consent_tip WHERE scope='consent';"));
  check("consent-tip: equal fencingToken accepted by the <= IF-fence on MySQL (advanced to hash-3)",
        tipAfterEqual.rows[0].rowHash === "hash-3" && tipAfterEqual.rows[0].atMonotonicCounter === "3");

  // ====================================================================
  // legal-hold — place INSERT / release DELETE / whereLike prefix history.
  // ====================================================================
  var holdDdl = b.sql.createTable("dl_myp_hold", [
    { name: "subjectIdHash", type: "text", primaryKey: true },
    { name: "placedAt",      type: "int",  notNull: true },
    { name: "placedBy",      type: "text" },
    { name: "reason",        type: "text", notNull: true },
    { name: "custodian",     type: "text" },
    { name: "citation",      type: "text" },
    { name: "retainUntil",   type: "int" },
  ], { dialect: "mysql", quoteName: true });
  _mysql(holdDdl.sql.replace("`subjectIdHash` TEXT PRIMARY KEY", "`subjectIdHash` VARCHAR(190) PRIMARY KEY"));
  var hash = b.crypto.sha3Hash("bj-legal-hold:subject-42");
  await _q(b.sql.insert("dl_myp_hold", { dialect: "mysql", quoteName: true })
    .values({ subjectIdHash: hash, placedAt: nowMs, placedBy: "legal@x", reason: "SEC subpoena", custodian: "c@x", citation: "SEC-Rule-17a-4", retainUntil: null })
    .toSql());
  var holdSel = await _q(b.sql.select("dl_myp_hold", { dialect: "mysql", quoteName: true }).columns(["placedAt"]).where("subjectIdHash", hash).toSql());
  check("legal-hold: place INSERT + existence SELECT round-trip on MySQL",
        holdSel.rows.length === 1 && Number(holdSel.rows[0].placedAt) === nowMs);
  var holdDel = await _q(b.sql.delete("dl_myp_hold", { dialect: "mysql", quoteName: true }).where("subjectIdHash", hash).toSql());
  check("legal-hold: release DELETE affected 1 row on MySQL", holdDel.rowCount === 1);

  var auditDdl = b.sql.createTable("dl_myp_audit", [
    { name: "recordedAt",   type: "int", notNull: true },
    { name: "action",       type: "text", notNull: true },
    { name: "metadata",     type: "text" },
    { name: "outcome",      type: "text" },
    { name: "resourceKind", type: "text" },
  ], { dialect: "mysql", quoteName: true });
  _mysql(auditDdl.sql);
  var seedRows = [
    [1, "legalhold.placed",   "{}", "success", "legal-hold"],
    [2, "legalhold.released", "{}", "success", "legal-hold"],
    [3, "auth.legalhold.x",   "{}", "success", "legal-hold"],   // NOT a prefix match
    [4, "legalhold.100%done", "{}", "success", "legal-hold"],   // literal % — must stay literal
  ];
  for (var sr = 0; sr < seedRows.length; sr++) {
    await _q(b.sql.insert("dl_myp_audit", { dialect: "mysql", quoteName: true })
      .values({ recordedAt: seedRows[sr][0], action: seedRows[sr][1], metadata: seedRows[sr][2], outcome: seedRows[sr][3], resourceKind: seedRows[sr][4] })
      .toSql());
  }
  var hist = await _q(b.sql.select("dl_myp_audit", { dialect: "mysql", quoteName: true })
    .columns(["recordedAt", "action"])
    .whereLike("action", "legalhold.", "prefix")
    .where("resourceKind", "legal-hold")
    .orderBy("recordedAt", "asc")
    .toSql());
  check("legal-hold: whereLike prefix selects exactly the legalhold.* rows on MySQL " +
        "(placed/released/100%done, NOT auth.legalhold.x)",
        hist.rows.length === 3 &&
        hist.rows.every(function (r) { return r.action.indexOf("legalhold.") === 0; }));
  var esc = await _q(b.sql.select("dl_myp_audit", { dialect: "mysql", quoteName: true })
    .columns(["action"]).whereLike("action", "legalhold.100%", "prefix").toSql());
  check("legal-hold: whereLike escapes a literal % in the term on MySQL (matches only the literal row)",
        esc.rows.length === 1 && esc.rows[0].action === "legalhold.100%done");

  // ====================================================================
  // subject — INSERT-OR-REPLACE upsert (_markErased) + restrict INSERT/DELETE.
  // ====================================================================
  var erasuresDdl = b.sql.createTable("dl_myp_erasures", [
    { name: "subjectIdHash", type: "text", primaryKey: true },
    { name: "erasedAt",      type: "int", notNull: true },
  ], { dialect: "mysql", quoteName: true });
  _mysql(erasuresDdl.sql.replace("`subjectIdHash` TEXT PRIMARY KEY", "`subjectIdHash` VARCHAR(190) PRIMARY KEY"));
  function _markErased(subjectHash, erasedAt) {
    return b.sql.upsert("dl_myp_erasures", { dialect: "mysql", quoteName: true })
      .values({ subjectIdHash: subjectHash, erasedAt: erasedAt })
      .onConflict(["subjectIdHash"])
      .doUpdateFromExcluded(["erasedAt"])
      .toSql();
  }
  var shash = b.crypto.sha3Hash("bj-subject:user-99");
  await _q(_markErased(shash, 1700000000000));
  await _q(_markErased(shash, 1700000009999));   // re-erase refreshes timestamp, no dup-key
  var erasureState = _parseBatch(_mysql("SELECT COUNT(*) AS c, MAX(erasedAt) AS m FROM dl_myp_erasures;"));
  check("subject: INSERT-OR-REPLACE upsert kept ONE row (no dup-key) on MySQL",
        erasureState.rows[0].c === "1");
  check("subject: INSERT-OR-REPLACE refreshed erasedAt to the newest value on MySQL",
        erasureState.rows[0].m === "1700000009999");

  var restrictDdl = b.sql.createTable("dl_myp_restrictions", [
    { name: "subjectIdHash", type: "text", primaryKey: true },
    { name: "since",         type: "int", notNull: true },
    { name: "reason",        type: "text" },
  ], { dialect: "mysql", quoteName: true });
  _mysql(restrictDdl.sql.replace("`subjectIdHash` TEXT PRIMARY KEY", "`subjectIdHash` VARCHAR(190) PRIMARY KEY"));
  await _q(b.sql.insert("dl_myp_restrictions", { dialect: "mysql", quoteName: true })
    .values({ subjectIdHash: shash, since: nowMs, reason: "art-18 hold" }).toSql());
  var rPres = await _q(b.sql.select("dl_myp_restrictions", { dialect: "mysql", quoteName: true })
    .columns(["subjectIdHash"]).where("subjectIdHash", shash).limit(1).toSql());
  check("subject: restrict INSERT + presence SELECT round-trip on MySQL", rPres.rows.length === 1);
  var rDel = await _q(b.sql.delete("dl_myp_restrictions", { dialect: "mysql", quoteName: true })
    .where("subjectIdHash", shash).toSql());
  check("subject: restrict DELETE (lift) affected 1 row on MySQL", rDel.rowCount === 1);

  // ====================================================================
  // retention — hard / soft / erase NULL-set / cascade / candidate WHERE.
  // __erasedAt is TEXT (the `= ''` sentinel column shape).
  // ====================================================================
  var ordersDdl = b.sql.createTable("dl_myp_orders", [
    { name: "_id",        type: "text", primaryKey: true },
    { name: "createdAt",  type: "int", notNull: true },
    { name: "secretCol",  type: "text" },
    { name: "secretColHash", type: "text" },
    { name: "softAt",     type: "int" },
    { name: "__erasedAt", type: "text" },
  ], { dialect: "mysql", quoteName: true });
  _mysql(ordersDdl.sql.replace("`_id` TEXT PRIMARY KEY", "`_id` VARCHAR(190) PRIMARY KEY"));
  var linesDdl = b.sql.createTable("dl_myp_order_lines", [
    { name: "_id",     type: "text", primaryKey: true },
    { name: "orderId", type: "text", notNull: true },
  ], { dialect: "mysql", quoteName: true });
  _mysql(linesDdl.sql.replace("`_id` TEXT PRIMARY KEY", "`_id` VARCHAR(190) PRIMARY KEY"));

  var oldAt = nowMs - b.constants.TIME.days(400);
  for (var oi = 1; oi <= 4; oi++) {
    var oid = "o-" + oi;
    await _q(b.sql.insert("dl_myp_orders", { dialect: "mysql", quoteName: true })
      .values({ _id: oid, createdAt: oldAt, secretCol: "secret-" + oi, secretColHash: "h-" + oi, softAt: null, __erasedAt: null })
      .toSql());
    await _q(b.sql.insert("dl_myp_order_lines", { dialect: "mysql", quoteName: true })
      .values({ _id: "l-" + oi, orderId: oid }).toSql());
  }
  var cutoff = nowMs - b.constants.TIME.days(365);
  var cand = await _q(b.sql.select("dl_myp_orders", { dialect: "mysql", quoteName: true })
    .where("createdAt", "<=", cutoff)
    .whereNull("softAt")
    .whereGroup(function (g) { g.whereNull("__erasedAt").orWhereOp("__erasedAt", "=", ""); })
    .limit(500)
    .toSql());
  check("retention: candidate whereGroup-OR WHERE selects the 4 aged rows on MySQL",
        cand.rows.length === 4);
  var softRes = await _q(b.sql.update("dl_myp_orders", { dialect: "mysql", quoteName: true })
    .set("softAt", nowMs).where("_id", "o-1").toSql());
  check("retention: soft-delete UPDATE set softAt on MySQL", softRes.rowCount === 1);
  await _q(b.sql.update("dl_myp_orders", { dialect: "mysql", quoteName: true })
    .set({ secretCol: null, secretColHash: null }).where("_id", "o-2").toSql());
  var erasedRow = _parseBatch(_mysql("SELECT secretCol, secretColHash FROM dl_myp_orders WHERE _id = 'o-2';"));
  check("retention: erase NULL-set wiped the sealed col + derived hash on MySQL",
        erasedRow.rows[0].secretCol === null && erasedRow.rows[0].secretColHash === null);
  var hardRes = await _q(b.sql.delete("dl_myp_orders", { dialect: "mysql", quoteName: true }).where("_id", "o-3").toSql());
  check("retention: hard delete removed o-3 on MySQL", hardRes.rowCount === 1);
  var cascRes = await _q(b.sql.delete("dl_myp_order_lines", { dialect: "mysql", quoteName: true }).where("orderId", "o-3").toSql());
  check("retention: cascade DELETE removed o-3's order_lines on MySQL", cascRes.rowCount === 1);
  var cnt = await _q(b.sql.select("dl_myp_order_lines", { dialect: "mysql", quoteName: true })
    .count("*", "n").where("orderId", "o-4").toSql());
  check("retention: cascade dry-run COUNT(*) returns 1 for o-4's lines on MySQL",
        cnt.rows.length === 1 && Number(cnt.rows[0].n) === 1);

  // ====================================================================
  // scheduler — the cluster tick-claim. _fireOnce builds
  //   sql.upsert("_blamejs_scheduler_ticks", { dialect })
  //     .columns([tickKey, name, scheduledAtUnix, claimedAtUnix, claimedBy])
  //     .values({...}).onConflict(["tickKey"]).doNothing()
  // and reads result.rowCount: a fresh tickKey wins (rowCount 1 = fire),
  // a duplicate tickKey loses (rowCount 0 = skip, task.tickClaimLost++).
  // On MySQL doNothing() folds to `ON DUPLICATE KEY UPDATE tickKey =
  // tickKey`, so the PRIMARY KEY on `tickKey` makes the first INSERT land
  // (ROW_COUNT 1) and the split-brain replay a no-op (ROW_COUNT 0) — the
  // dedup is the DB's unique constraint, the security property a real
  // server must enforce. The prune is delete().where("scheduledAtUnix",
  // "<", threshold). claimedAtUnix is a BIGINT read back + coerced.
  // ====================================================================
  var schedTicksDdl = b.sql.createTable("dl_myp_sched_ticks", [
    { name: "tickKey",         type: "text", primaryKey: true },
    { name: "name",            type: "text", notNull: true },
    { name: "scheduledAtUnix", type: "int",  notNull: true },
    { name: "claimedAtUnix",   type: "int",  notNull: true },
    { name: "claimedBy",       type: "text" },
  ], { dialect: "mysql", quoteName: true });
  _mysql(schedTicksDdl.sql.replace("`tickKey` TEXT PRIMARY KEY", "`tickKey` VARCHAR(190) PRIMARY KEY"));

  var SCHED_COLS = ["tickKey", "name", "scheduledAtUnix", "claimedAtUnix", "claimedBy"];
  function _claimTick(tickKey, name, scheduledAtUnix, claimedAtUnix, claimedBy) {
    return b.sql.upsert("dl_myp_sched_ticks", { dialect: "mysql", quoteName: true })
      .columns(SCHED_COLS)
      .values({
        tickKey:         tickKey,
        name:            name,
        scheduledAtUnix: scheduledAtUnix,
        claimedAtUnix:   claimedAtUnix,
        claimedBy:       claimedBy,
      })
      .onConflict(["tickKey"])
      .doNothing()
      .toSql();
  }
  // Confirm the builder emitted the MySQL no-op fold (no ON CONFLICT, no
  // RETURNING — the doNothing() rewrite to `ON DUPLICATE KEY UPDATE
  // tickKey = tickKey`).
  var claimSqlText = _claimTick("rollup:1", "rollup", 1, 2, "node-A").sql;
  check("scheduler: doNothing() emitted the MySQL ON DUPLICATE KEY UPDATE no-op fold",
        /ON DUPLICATE KEY UPDATE `tickKey` = `tickKey`/.test(claimSqlText) &&
        !/ON CONFLICT/.test(claimSqlText) && !/RETURNING/.test(claimSqlText));

  var nominal = nowMs + b.constants.TIME.minutes(1);
  var tickKey = "rollup:" + nominal;
  // node-A claims the tick first — fresh tickKey, ROW_COUNT 1 (won).
  var claimA = await _q(_claimTick(tickKey, "rollup", nominal, nowMs, "node-A"));
  check("scheduler: first tick-claim INSERT won (rowCount 1 = the leader fires) on MySQL",
        claimA.rowCount === 1);
  // node-B races the SAME nominal tick (split-brain) — duplicate tickKey,
  // the DUPLICATE-KEY no-op fold affects 0 rows (lost the claim, skips).
  var claimB = await _q(_claimTick(tickKey, "rollup", nominal, nowMs + 5, "node-B"));
  check("scheduler: racing tick-claim on the SAME tickKey lost (rowCount 0 = loser skips) on MySQL",
        claimB.rowCount === 0);
  // The DB holds exactly one tick row for the shared key — the PRIMARY KEY
  // collapsed the racing INSERTs to one. claimedBy is still node-A's (the
  // no-op fold left the winner's row untouched).
  var tickRow = _parseBatch(_mysql(
    "SELECT claimedBy, claimedAtUnix FROM dl_myp_sched_ticks WHERE tickKey = '" + tickKey + "';"));
  check("scheduler: real MySQL holds exactly ONE tick row for the shared key, claimedBy=node-A",
        tickRow.rows.length === 1 && tickRow.rows[0].claimedBy === "node-A");
  // claimedAtUnix is a BIGINT column — coerceRows turns the string the
  // driver returns back into a JS number (the same path the readback uses).
  var coercedTick = frameworkSchema.coerceRows(tickRow.rows);
  check("scheduler: coerceRows turns claimedAtUnix BIGINT-string -> JS number on MySQL",
        typeof coercedTick[0].claimedAtUnix === "number" && coercedTick[0].claimedAtUnix === nowMs);

  // A DISTINCT nominal tick is independently claimable (per-tickKey dedup,
  // not a one-shot table lock).
  var nominal2 = nominal + b.constants.TIME.minutes(1);
  var claim2 = await _q(_claimTick("rollup:" + nominal2, "rollup", nominal2, nowMs + 9, "node-A"));
  check("scheduler: a distinct second tick is independently claimable (rowCount 1) on MySQL",
        claim2.rowCount === 1);

  // pruneTickClaims: delete().where("scheduledAtUnix", "<", threshold).
  // Seed an old tick + keep the two fresh ones; prune below a cutoff and
  // assert only the aged row is removed.
  await _q(_claimTick("rollup:" + (nominal - b.constants.TIME.days(30)), "rollup",
    nominal - b.constants.TIME.days(30), nowMs, "node-A"));
  var pruneThreshold = nominal - b.constants.TIME.days(7);
  var pruneDel = await _q(b.sql.delete("dl_myp_sched_ticks", { dialect: "mysql", quoteName: true })
    .where("scheduledAtUnix", "<", pruneThreshold)
    .toSql());
  check("scheduler: pruneTickClaims DELETE removed exactly the aged tick row on MySQL",
        pruneDel.rowCount === 1);
  var remaining = _parseBatch(_mysql("SELECT COUNT(*) AS n FROM dl_myp_sched_ticks;"));
  check("scheduler: prune left the two un-aged tick rows intact on MySQL",
        Number(remaining.rows[0].n) === 2);

  // ---- teardown ----
  await b.externalDb.shutdown();
  _resetState();
  _mysql(TABLES.map(function (t) { return "DROP TABLE IF EXISTS `" + t + "`;"; }).join(" "));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
