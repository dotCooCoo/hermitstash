// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live test of b.dsr.dbTicketStore against the docker MySQL container.
 *
 * Same intent as dsr-cluster-pg.test.js: the ticket store composes every
 * statement through b.sql (`?` placeholders + double-quoted identifiers)
 * and drives an operator-supplied b.db-shaped handle ({ runSql,
 * prepare }); layer-0 only ever runs it on node:sqlite. Here the SAME
 * store runs over a docker-exec mysql shim shaped like that handle, so
 * every statement the store emits PREPARES and RUNS on real MySQL:
 *
 *   - insert + get: the sealed-at-rest row (payload / subject_* AEAD-
 *     sealed, bound to the ticket id) physically lands on MySQL with the
 *     derived subject_email_hash / subject_id_hash lookup columns
 *     populated, and get() unseals the round-trip.
 *   - list({ subject }): an indexable subject key (email / subjectId)
 *     matches ONLY its own tickets via the dual-hash whereIn.
 *   - FAIL-CLOSED subject filter: a subject with NO indexable key
 *     (phone-only, or empty) matches ZERO tickets — never the whole
 *     table. The same predicate guards a DESTRUCTIVE path: the
 *     erasure-completion purge lists the subject's tickets and DELETES
 *     them, so a fail-open filter here would delete every OTHER
 *     subject's tickets too.
 *   - erasure-completion purge: completing an erasure removes exactly
 *     the subject's own prior tickets (the erasure ticket itself and
 *     other subjects' tickets survive), and an erasure whose subject has
 *     no indexable key purges NOTHING.
 *   - purgeExpired: the terminal-status whereIn sweep removes only the
 *     ticket whose retentionUntil has passed.
 *
 * Handle-boundary notes (operator-adapter concerns, mirroring
 * db-layer-mysql.test.js):
 *   - b.sql emits double-quoted identifiers; MySQL's default sql_mode
 *     reads those as STRING literals, so every statement batch is
 *     prefixed with `SET SESSION sql_mode=...,ANSI_QUOTES` (each
 *     docker-exec is a fresh connection).
 *   - `?` placeholders fold into the SQL as quoted literals at the
 *     handle boundary (the mysql CLI has no bind protocol).
 *   - run() reports { changes } from ROW_COUNT() issued in the SAME
 *     mysql invocation as the write (ROW_COUNT is connection-scoped).
 *   - the store's schema probe is `PRAGMA table_info(...)` (a
 *     SQLite-ism); the handle answers it from information_schema.columns.
 *   - MySQL has no CREATE INDEX IF NOT EXISTS; the handle strips the
 *     clause and swallows a duplicate-key-name error (1061) so the
 *     store's idempotent index DDL stays idempotent.
 *   - the physical table is operator-provisioned: VARCHAR key/indexed
 *     columns (MySQL refuses an unbounded TEXT column in a key, error
 *     1170), BIGINT ms-epoch columns (MySQL INTEGER is 32-bit), LONGTEXT
 *     payload. The store's own CREATE TABLE IF NOT EXISTS then no-ops
 *     against the existing table.
 *
 * RUN: node scripts/test-integration.js --skip-service-check dsr-cluster-mysql
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
var TABLE     = "bjdsr_my_tickets";
// ANSI_QUOTES makes MySQL honor the b.sql double-quoted identifiers;
// without it every "col" parses as a string literal. Prefixed to every
// statement batch since each docker-exec is a fresh connection.
var SQLMODE = "SET SESSION sql_mode=CONCAT(@@sql_mode,',ANSI_QUOTES');\n";

// Soft assertion: records pass/fail without throwing so every section's
// findings are collected even when an earlier check fails. All findings
// are replayed through the hard `check` at the end of run() so the file
// still FAILS when any contract is unmet.
var _findings = [];
function softCheck(label, condition) {
  _findings.push({ label: label, ok: !!condition });
  console.log((condition ? "  ok   " : "  FAIL ") + label);
}

// ---- shared synchronous docker-exec mysql ----
// SQL travels on stdin (never argv). --batch gives TAB-separated,
// header-bearing output; --raw disables escaping so a value round-trips
// byte-faithfully. stderr is captured so a SQL error surfaces with its
// message.
function _mysqlRaw(sql) {
  var args = ["exec", "-i", CONTAINER, "mysql", "-uroot", "-pblamejs_test_root",
              "--batch", "--raw", DB_NAME];
  try {
    var out = execFileSync("docker", args,
      { input: SQLMODE + sql + "\n",
        stdio: ["pipe", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
    return { ok: true, out: out.toString("utf8") };
  } catch (e) {
    var stderr = e.stderr ? e.stderr.toString("utf8") : "";
    return { ok: false, out: (e.stdout ? e.stdout.toString("utf8") : ""), err: stderr || (e.message || String(e)) };
  }
}

// One-shot for setup / teardown / out-of-band assertions; throws on error.
function _mysql(sql) {
  var r = _mysqlRaw(sql);
  if (!r.ok) throw new Error("mysql setup failed for [" + sql.slice(0, 120) + "]: " + _clean(r.err));
  return r.out;
}

function _clean(s) {
  return String(s || "").split(/\r?\n/)
    .filter(function (l) { return l && l.indexOf("[Warning] Using a password") === -1; })
    .join(" ").slice(0, 220);
}

// Inline `?` binding. Every value the store binds is operator-controlled
// (ids / sealed cells / hashes / numbers / null). MySQL treats backslash
// as a string escape by default, so escape both backslash and quote.
function _bindQ(sql, params) {
  params = params || [];
  var i = 0;
  return sql.replace(/\?/g, function () {
    if (i >= params.length) throw new Error("placeholder/param count mismatch in: " + sql);
    var v = params[i++];
    if (v === null || v === undefined) return "NULL";
    if (typeof v === "number") return String(v);
    if (typeof v === "boolean") return v ? "1" : "0";
    return "'" + String(v).replace(/\\/g, "\\\\").replace(/'/g, "''") + "'";
  });
}

// Parse a --batch block: header row first, then data rows. NULL prints as
// the literal "NULL".
function _parseSelect(out) {
  var lines = out.split(/\r?\n/).filter(function (l) { return l.length > 0; });
  if (lines.length === 0) return [];
  var headers = lines[0].split("\t");
  var rows = [];
  for (var i = 1; i < lines.length; i++) {
    var cells = lines[i].split("\t");
    var row = {};
    for (var c = 0; c < headers.length; c++) {
      var v = cells[c];
      row[headers[c]] = (v === "NULL" || v === undefined) ? null : v;
    }
    rows.push(row);
  }
  return rows;
}

function _isWrite(sql) {
  return /^\s*(INSERT|UPDATE|DELETE|REPLACE|MERGE)\b/i.test(sql);
}

// Out-of-band raw read (bypasses the store's unseal) for at-rest asserts.
function _selectDirect(sqlText) {
  return _parseSelect(_mysql(sqlText));
}

// ---- b.db-shaped handle ({ runSql, prepare }) over real MySQL ----
function _makeMysqlDbHandle() {
  return {
    prepare: function (sql) {
      // The store's schema reconcile probes columns with the SQLite
      // `PRAGMA table_info(...)`; a MySQL operator adapter answers the
      // same question from information_schema.columns (one row per
      // column, named `name` like the PRAGMA's output).
      var pragma = /^PRAGMA\s+table_info\(\s*"?([A-Za-z0-9_]+)"?\s*\)\s*$/i.exec(sql);
      if (pragma) {
        sql = "SELECT column_name AS name FROM information_schema.columns " +
              "WHERE table_schema = '" + DB_NAME + "' AND table_name = '" + pragma[1] + "'";
      }
      return {
        get: function () {
          var params = Array.prototype.slice.call(arguments);
          var r = _mysqlRaw(_bindQ(sql, params));
          if (!r.ok) throw new Error("MySQL error: " + _clean(r.err));
          var rows = _parseSelect(r.out);
          return rows.length ? rows[0] : undefined;
        },
        all: function () {
          var params = Array.prototype.slice.call(arguments);
          var r = _mysqlRaw(_bindQ(sql, params));
          if (!r.ok) throw new Error("MySQL error: " + _clean(r.err));
          return _parseSelect(r.out);
        },
        run: function () {
          var params = Array.prototype.slice.call(arguments);
          var bound = _bindQ(sql, params);
          // ROW_COUNT() in the SAME connection/batch as the write reports
          // affectedRows (it is connection-scoped).
          var r = _mysqlRaw(bound + ";\nSELECT ROW_COUNT() AS rc;");
          if (!r.ok) throw new Error("MySQL error: " + _clean(r.err));
          var changes = 0;
          if (_isWrite(sql)) {
            var rows = _parseSelect(r.out);
            var last = rows.length ? rows[rows.length - 1] : null;
            if (last && last.rc !== undefined && last.rc !== null) changes = Number(last.rc);
          }
          return { changes: changes, lastInsertRowid: 0 };
        },
      };
    },
    runSql: function (sql) {
      var t = sql;
      // The physical table is operator-provisioned (VARCHAR key columns),
      // so the store's convenience CREATE TABLE IF NOT EXISTS is a no-op;
      // patch its TEXT PRIMARY KEY anyway so the statement would stay
      // valid on MySQL even against an absent table (error 1170 refuses
      // an unbounded TEXT key).
      t = t.replace("id TEXT PRIMARY KEY", "id VARCHAR(190) PRIMARY KEY");
      // MySQL has no CREATE INDEX IF NOT EXISTS: strip the clause and
      // swallow the duplicate-key-name error (1061) so the store's
      // idempotent index DDL stays idempotent.
      var isIdempotentIndex = /^CREATE INDEX IF NOT EXISTS\b/i.test(t);
      if (isIdempotentIndex) t = t.replace(/^CREATE INDEX IF NOT EXISTS\b/i, "CREATE INDEX");
      var r = _mysqlRaw(t);
      if (!r.ok) {
        if (isIdempotentIndex && /Duplicate key name|error 1061/i.test(r.err)) return "";
        throw new Error("MySQL error: " + _clean(r.err));
      }
      return r.out;
    },
  };
}

function _dropAll() {
  _mysql('DROP TABLE IF EXISTS "' + TABLE + '";');
}

// Operator-provisioned physical table: the canonical dbTicketStore column
// set, with VARCHAR key/indexed columns (MySQL cannot key or index an
// unbounded TEXT column), BIGINT ms-epoch columns (MySQL INTEGER is
// 32-bit and cannot hold a Date.now() value; the store's convenience DDL
// sizes INTEGER for SQLite where it is 64-bit), and a LONGTEXT payload.
// The store's own CREATE TABLE IF NOT EXISTS no-ops against this table
// and its column reconcile finds every column present.
function _provision() {
  _mysql('CREATE TABLE "' + TABLE + '" (' +
    '"id" VARCHAR(190) PRIMARY KEY, ' +
    '"type" VARCHAR(64) NOT NULL, ' +
    '"status" VARCHAR(64) NOT NULL, ' +
    '"subject_id" TEXT, ' +
    '"subject_email" TEXT, ' +
    '"subject_phone" TEXT, ' +
    '"subject_email_hash" VARCHAR(190), ' +
    '"subject_id_hash" VARCHAR(190), ' +
    '"submitted_at" BIGINT NOT NULL, ' +
    '"deadline_at" BIGINT NOT NULL, ' +
    '"processed_at" BIGINT, ' +
    '"verification_level" VARCHAR(64), ' +
    '"posture" VARCHAR(64), ' +
    '"payload" LONGTEXT NOT NULL);');
}

// Run one stage; a thrown error becomes a single FAILED finding so an
// unexpected MySQL error in one stage doesn't hide the others.
async function _section(label, fn) {
  try {
    await fn();
  } catch (e) {
    softCheck(label + "(mysql): stage completed without an unexpected error " +
      "— DETAIL: " + (((e && e.message) || String(e)).split(/\r?\n/)[0]), false);
  }
}

async function run() {
  var mysqlSvc = await services.requireService("mysql");
  if (!mysqlSvc.ok) throw new Error("mysql unreachable: " + mysqlSvc.reason);

  _dropAll();
  _provision();

  // Vault + local-db bring-up: the store seals subject PII + payload via
  // b.cryptoField only when a vault is initialized, and that sealed mode
  // is exactly what the dual-hash lookup + fail-closed filter guard.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dsr-mysql-"));
  await helpers.setupTestDb(tmpDir);

  var handle = _makeMysqlDbHandle();

  var SUBJECTS = {
    "alice@example.com": { subjectId: "u-alice", email: "alice@example.com", phone: "+15550001111" },
    "bob@example.com":   { subjectId: "u-bob",   email: "bob@example.com",   phone: "+15550002222" },
  };

  var store, dsr;
  var t1, t2, tb, erasure, ghostErasure;

  try {
    // Constructing the store runs its ensureSchema against real MySQL
    // (CREATE TABLE IF NOT EXISTS no-op, information_schema column probe,
    // the emulated idempotent CREATE INDEX on the hash + status columns).
    store = b.dsr.dbTicketStore({ db: handle, table: TABLE });
    softCheck("store(mysql): dbTicketStore construction ran ensureSchema on real MySQL", true);

    dsr = b.dsr.create({
      ticketStore: store,
      posture:     "gdpr",
      identityResolver: async function (input) {
        if (input && input.email && SUBJECTS[input.email]) return SUBJECTS[input.email];
        if (input && input.phone === "+15550003333") {
          // A subject the operator can only identify by phone — no email,
          // no subjectId, so the ticket store has NO indexable key for it.
          return { phone: "+15550003333" };
        }
        return null;
      },
      sources: [{
        name:  "users",
        query: async function () { return [{ id: 1 }]; },
        erase: async function () { return { deletedIds: [1] }; },
      }],
    });

    await _section("sealed-insert", async function () {
      t1 = await dsr.submit({
        type:    "access",
        subject: { email: "alice@example.com" },
        reason:  "export request one",
      });
      var raw = _selectDirect(
        'SELECT "subject_email", "subject_phone", "subject_email_hash", ' +
        '"subject_id_hash", "payload" FROM "' + TABLE + "\" WHERE \"id\" = '" + t1.id + "';");
      softCheck("sealed-insert(mysql): the ticket row physically landed on MySQL",
            raw.length === 1);
      softCheck("sealed-insert(mysql): subject_email is sealed at rest (not plaintext)",
            raw.length === 1 && typeof raw[0].subject_email === "string" &&
            raw[0].subject_email.indexOf("alice@example.com") === -1);
      softCheck("sealed-insert(mysql): payload is sealed at rest (no plaintext email leak)",
            raw.length === 1 && typeof raw[0].payload === "string" &&
            raw[0].payload.indexOf("alice@example.com") === -1);
      softCheck("sealed-insert(mysql): derived subject_email_hash populated for lookup",
            raw.length === 1 && typeof raw[0].subject_email_hash === "string" &&
            raw[0].subject_email_hash.length > 0);
      softCheck("sealed-insert(mysql): derived subject_id_hash populated for lookup",
            raw.length === 1 && typeof raw[0].subject_id_hash === "string" &&
            raw[0].subject_id_hash.length > 0);

      var got = await store.get(t1.id);
      softCheck("sealed-insert(mysql): get() unseals the payload back to cleartext",
            got !== null && got.subject && got.subject.email === "alice@example.com" &&
            got.type === "access" && got.status === "pending");
      softCheck("sealed-insert(mysql): get() of an unknown id returns null",
            (await store.get("DSR-0000000-NOPE")) === null);
    });

    await _section("list-by-subject", async function () {
      t2 = await dsr.submit({
        type:    "access",
        subject: { email: "alice@example.com" },
        reason:  "export request two",
      });
      tb = await dsr.submit({
        type:    "access",
        subject: { email: "bob@example.com" },
        reason:  "bob export",
      });

      var aliceList = await store.list({ subject: { email: "alice@example.com" } });
      var aliceIds = aliceList.map(function (t) { return t.id; }).sort();
      softCheck("list(mysql): alice's email matches exactly her two tickets via the " +
            "dual-hash whereIn (not bob's)",
            aliceList.length === 2 &&
            JSON.stringify(aliceIds) === JSON.stringify([t1.id, t2.id].sort()));

      var bobList = await store.list({ subject: { subjectId: "u-bob" } });
      softCheck("list(mysql): bob's subjectId matches exactly his ticket via subject_id_hash",
            bobList.length === 1 && bobList[0].id === tb.id);
    });

    await _section("fail-closed-filter", async function () {
      var all = await store.list({});
      softCheck("fail-closed(mysql): baseline — a no-subject list sees every ticket (3)",
            all.length === 3);

      // Alice's phone IS on her tickets' sealed payloads, but phone is not
      // an indexable subject key — the filter must produce a
      // matches-nothing predicate, NOT degrade to a full-table scan.
      var phoneOnly = await store.list({ subject: { phone: "+15550001111" } });
      softCheck("fail-closed(mysql): a phone-only subject matches ZERO tickets on real " +
            "MySQL (never all " + all.length + ")",
            phoneOnly.length === 0);

      var emptySubject = await store.list({ subject: {} });
      softCheck("fail-closed(mysql): an empty subject matches ZERO tickets (never all)",
            emptySubject.length === 0);
    });

    await _section("erasure-purge", async function () {
      erasure = await dsr.submit({
        type:              "erasure",
        subject:           { email: "alice@example.com" },
        reason:            "right to erasure",
        verificationLevel: "secondary",
      });
      var processed = await dsr.process(erasure.id,
        { actor: "compliance@example.com", verificationLevel: "secondary" });
      softCheck("erasure(mysql): the erasure ticket completed on real MySQL",
            processed && processed.status === "completed");

      softCheck("erasure(mysql): alice's prior ticket one was purged",
            (await store.get(t1.id)) === null);
      softCheck("erasure(mysql): alice's prior ticket two was purged",
            (await store.get(t2.id)) === null);
      softCheck("erasure(mysql): the erasure ticket itself survives (audit/receipt trail)",
            (await store.get(erasure.id)) !== null);
      softCheck("erasure(mysql): bob's ticket is untouched by alice's erasure purge",
            (await store.get(tb.id)) !== null);
    });

    await _section("erasure-no-key-purges-nothing", async function () {
      // The DESTRUCTIVE fail-closed proof: an erasure whose subject has NO
      // indexable key must purge NOTHING. A fail-open subject filter would
      // list every row here and delete every other subject's tickets.
      ghostErasure = await dsr.submit({
        type:              "erasure",
        subject:           { phone: "+15550003333" },
        reason:            "erasure for a subject with no indexable key",
        verificationLevel: "secondary",
      });
      var done = await dsr.process(ghostErasure.id, { verificationLevel: "secondary" });
      softCheck("erasure-no-key(mysql): the no-indexable-key erasure still completes",
            done && done.status === "completed");
      softCheck("erasure-no-key(mysql): bob's ticket SURVIVES the no-key purge " +
            "(a fail-open filter would have deleted it)",
            (await store.get(tb.id)) !== null);
      softCheck("erasure-no-key(mysql): alice's completed erasure ticket SURVIVES the no-key purge",
            (await store.get(erasure.id)) !== null);
      softCheck("erasure-no-key(mysql): the no-key erasure ticket itself survives",
            (await store.get(ghostErasure.id)) !== null);
    });

    await _section("purge-expired", async function () {
      var now = Date.now();
      await store.insert({
        id:                "DSR-0000000-RETIRED1",
        type:              "access",
        status:            "completed",
        subject:           { subjectId: "u-old", email: "old@example.com" },
        submittedAt:       now - b.constants.TIME.days(60),
        deadlineAt:        now - b.constants.TIME.days(30),
        processedAt:       now - b.constants.TIME.days(45),
        verificationLevel: "primary",
        posture:           "gdpr",
        retentionUntil:    now - b.constants.TIME.days(1),
      });
      var purged = await store.purgeExpired();
      softCheck("purge-expired(mysql): the aged terminal ticket was purged (exactly 1)",
            purged === 1);
      softCheck("purge-expired(mysql): the aged ticket row is gone",
            (await store.get("DSR-0000000-RETIRED1")) === null);
      softCheck("purge-expired(mysql): a completed ticket inside its retention floor survives",
            (await store.get(erasure.id)) !== null);
    });
  } finally {
    try { await helpers.teardownTestDb(tmpDir); } catch (_e) {}
    _dropAll();
  }

  // Replay every recorded finding through the hard `check` so the file
  // FAILS (and the runner reports it) when any contract is unmet.
  var failures = _findings.filter(function (f) { return !f.ok; });
  console.log("");
  console.log("[dsr-cluster-mysql] " + (_findings.length - failures.length) + "/" +
    _findings.length + " checks ok; " + failures.length + " failing");
  for (var i = 0; i < _findings.length; i++) {
    check(_findings[i].label, _findings[i].ok);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
