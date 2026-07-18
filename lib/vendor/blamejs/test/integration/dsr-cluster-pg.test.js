// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live test of b.dsr.dbTicketStore against the docker Postgres container.
 *
 * The ticket store composes every statement through b.sql (`?`
 * placeholders + double-quoted identifiers) and drives an operator-
 * supplied b.db-shaped handle ({ runSql, prepare }); layer-0 only ever
 * runs it on node:sqlite. This test wires the SAME store over a
 * docker-exec psql shim shaped like that handle, so every statement the
 * store emits PREPARES and RUNS on real Postgres:
 *
 *   - insert + get: the sealed-at-rest row (payload / subject_* AEAD-
 *     sealed, bound to the ticket id) physically lands on Postgres with
 *     the derived subject_email_hash / subject_id_hash lookup columns
 *     populated, and get() unseals the round-trip.
 *   - list({ subject }): an indexable subject key (email / subjectId)
 *     matches ONLY its own tickets via the dual-hash whereIn (active
 *     keyed-MAC + legacy digest candidates).
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
 * db-layer-postgres.test.js):
 *   - `?` placeholders fold into the SQL as quoted literals at the
 *     handle boundary (psql has no bind protocol over stdin; every value
 *     is operator-controlled).
 *   - Postgres honors the double-quoted identifiers b.sql emits.
 *   - the store's schema probe is `PRAGMA table_info(...)` (a
 *     SQLite-ism); the handle answers it from information_schema.columns,
 *     as a real operator adapter over Postgres must.
 *   - the physical table is operator-provisioned with BIGINT ms-epoch
 *     columns: the store's convenience DDL types epochs as INTEGER,
 *     which is 64-bit on SQLite but 32 bits on Postgres. The store's own
 *     CREATE TABLE IF NOT EXISTS then no-ops against the existing table.
 *
 * RUN: node scripts/test-integration.js --skip-service-check dsr-cluster-pg
 */

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
var TABLE         = "bjdsr_pg_tickets";

// Soft assertion: records pass/fail without throwing so every section's
// findings are collected even when an earlier check fails. All findings
// are replayed through the hard `check` at the end of run() so the file
// still FAILS when any contract is unmet.
var _findings = [];
function softCheck(label, condition) {
  _findings.push({ label: label, ok: !!condition });
  console.log((condition ? "  ok   " : "  FAIL ") + label);
}

// ---- shared synchronous docker-exec psql ----
// Field separator is a literal TAB embedded in the -P argument (built in
// Node where the byte is exact); -P flags print no confirmation line.
// 2>&1 merges the ERROR lines psql writes to stderr (ON_ERROR_STOP=0 ->
// exit 0, errors only on stderr).
var TAB = "\t";
var _PSQL_BASE =
  "psql -U blamejs -d blamejs_test -v ON_ERROR_STOP=0 " +
  "-P footer=off -P null=" + NULL_SENTINEL + " -P 'fieldsep=" + TAB + "'";

function _psqlRaw(sql) {
  return execFileSync(
    "docker",
    ["exec", "-i", CONTAINER, "sh", "-c", _PSQL_BASE + " -At 2>&1"],
    { input: sql + "\n", stdio: ["pipe", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 }
  ).toString("utf8");
}

// One-shot for setup / teardown; throws on any SQL error.
function _psql(sql) {
  var out = _psqlRaw(sql);
  if (/^ERROR:/m.test(out)) {
    throw new Error("psql setup failed for [" + sql + "]:\n" + out);
  }
  return out;
}

// Header-bearing variant (-A keeps the column-name row) for reads.
function _psqlHeader(sql) {
  return execFileSync(
    "docker",
    ["exec", "-i", CONTAINER, "sh", "-c", _PSQL_BASE + " -A 2>&1"],
    { input: sql + "\n", stdio: ["pipe", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 }
  ).toString("utf8");
}

// Inline `?` binding. Every value the store binds is operator-controlled
// (ids / sealed cells / hashes / numbers / null).
function _bindQ(sql, params) {
  params = params || [];
  var i = 0;
  return sql.replace(/\?/g, function () {
    if (i >= params.length) {
      throw new Error("placeholder/param count mismatch in: " + sql);
    }
    var v = params[i++];
    if (v === null || v === undefined) return "NULL";
    if (typeof v === "number") return String(v);
    if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
    return "'" + String(v).replace(/'/g, "''") + "'";
  });
}

var _CMD_TAG_RE = /^(INSERT|UPDATE|DELETE|MERGE|SELECT|COPY|MOVE)\b(?:\s+\d+)*\s*$/;

function _parseError(out) {
  var lines = out.split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var em = /^ERROR:\s+([0-9A-Za-z]{5}):\s*(.*)$/.exec(lines[i]) ||
             /^ERROR:\s+(.*)$/.exec(lines[i]);
    if (em) {
      var err = new Error("Postgres error: " + lines[i]);
      if (em.length === 3) err.code = em[1];
      return err;
    }
  }
  return null;
}

function _rowsFromHeaderBlock(out) {
  var err = _parseError(out);
  if (err) throw err;
  var lines = out.split(/\r?\n/);
  var data = [];
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i];
    if (ln === "") continue;
    if (_CMD_TAG_RE.test(ln) && ln.indexOf("\t") === -1) continue;
    if (/^(BEGIN|COMMIT|ROLLBACK|SET|CREATE|DROP|ALTER)\b/.test(ln) &&
        ln.indexOf("\t") === -1) continue;
    data.push(ln);
  }
  if (data.length === 0) return [];
  var headers = data[0].split("\t");
  var rows = [];
  for (var r = 1; r < data.length; r++) {
    var cells = data[r].split("\t");
    var row = {};
    for (var c = 0; c < headers.length; c++) {
      var cell = cells[c];
      row[headers[c]] = (cell === NULL_SENTINEL || cell === undefined) ? null : cell;
    }
    rows.push(row);
  }
  return rows;
}

function _affectedFromBlock(out) {
  var err = _parseError(out);
  if (err) throw err;
  var lines = out.split(/\r?\n/);
  var affected = 0;
  for (var i = 0; i < lines.length; i++) {
    if (_CMD_TAG_RE.test(lines[i])) {
      var nums = lines[i].trim().split(/\s+/).slice(1).map(Number);
      if (nums.length) affected = nums[nums.length - 1];
    }
  }
  return affected;
}

function _isWrite(sql) {
  return /^\s*(INSERT|UPDATE|DELETE|REPLACE|MERGE)\b/i.test(sql);
}

// Out-of-band raw read (bypasses the store's unseal) for at-rest asserts.
function _selectDirect(sqlText) {
  return _rowsFromHeaderBlock(_psqlHeader(sqlText));
}

// ---- b.db-shaped handle ({ runSql, prepare }) over real Postgres ----
function _makePgDbHandle() {
  return {
    prepare: function (sql) {
      // The store's schema reconcile probes columns with the SQLite
      // `PRAGMA table_info(...)`; a Postgres operator adapter answers the
      // same question from information_schema.columns (one row per
      // column, named `name` like the PRAGMA's output).
      var pragma = /^PRAGMA\s+table_info\(\s*"?([A-Za-z0-9_]+)"?\s*\)\s*$/i.exec(sql);
      if (pragma) {
        sql = "SELECT column_name AS name FROM information_schema.columns " +
              "WHERE table_schema = 'public' AND table_name = '" + pragma[1] + "'";
      }
      return {
        get: function () {
          var params = Array.prototype.slice.call(arguments);
          var rows = _rowsFromHeaderBlock(_psqlHeader(_bindQ(sql, params)));
          return rows.length ? rows[0] : undefined;
        },
        all: function () {
          var params = Array.prototype.slice.call(arguments);
          return _rowsFromHeaderBlock(_psqlHeader(_bindQ(sql, params)));
        },
        run: function () {
          var params = Array.prototype.slice.call(arguments);
          var out = _psqlRaw(_bindQ(sql, params));
          var changes = _isWrite(sql) ? _affectedFromBlock(out) : (function () {
            var e = _parseError(out); if (e) throw e; return 0;
          })();
          return { changes: changes, lastInsertRowid: 0 };
        },
      };
    },
    runSql: function (sql) {
      var out = _psqlRaw(sql);
      var e = _parseError(out);
      if (e) throw e;
      return out;
    },
  };
}

function _dropAll() {
  _psql('DROP TABLE IF EXISTS "' + TABLE + '" CASCADE;');
}

// Operator-provisioned physical table: the canonical dbTicketStore column
// set, with the ms-epoch columns typed BIGINT (Postgres INTEGER is 32-bit
// and cannot hold a Date.now() value; the store's convenience DDL sizes
// INTEGER for SQLite where it is 64-bit). The store's own CREATE TABLE IF
// NOT EXISTS no-ops against this table and its column reconcile finds
// every column present.
function _provision() {
  _psql('CREATE TABLE "' + TABLE + '" (' +
    '"id" TEXT PRIMARY KEY, ' +
    '"type" TEXT NOT NULL, ' +
    '"status" TEXT NOT NULL, ' +
    '"subject_id" TEXT, ' +
    '"subject_email" TEXT, ' +
    '"subject_phone" TEXT, ' +
    '"subject_email_hash" TEXT, ' +
    '"subject_id_hash" TEXT, ' +
    '"submitted_at" BIGINT NOT NULL, ' +
    '"deadline_at" BIGINT NOT NULL, ' +
    '"processed_at" BIGINT, ' +
    '"verification_level" TEXT, ' +
    '"posture" TEXT, ' +
    '"payload" TEXT NOT NULL);');
}

// Run one stage; a thrown error becomes a single FAILED finding so an
// unexpected Postgres error in one stage doesn't hide the others.
async function _section(label, fn) {
  try {
    await fn();
  } catch (e) {
    softCheck(label + "(pg): stage completed without an unexpected error " +
      "— DETAIL: " + (((e && e.message) || String(e)).split(/\r?\n/)[0]), false);
  }
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  _dropAll();
  _provision();

  // Vault + local-db bring-up: the store seals subject PII + payload via
  // b.cryptoField only when a vault is initialized, and that sealed mode
  // is exactly what the dual-hash lookup + fail-closed filter guard.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dsr-pg-"));
  await helpers.setupTestDb(tmpDir);

  var handle = _makePgDbHandle();

  var SUBJECTS = {
    "alice@example.com": { subjectId: "u-alice", email: "alice@example.com", phone: "+15550001111" },
    "bob@example.com":   { subjectId: "u-bob",   email: "bob@example.com",   phone: "+15550002222" },
  };

  var store, dsr;
  var t1, t2, tb, erasure, ghostErasure;

  try {
    // Constructing the store runs its ensureSchema against real Postgres
    // (CREATE TABLE IF NOT EXISTS no-op, information_schema column probe,
    // CREATE INDEX IF NOT EXISTS on the hash + status columns).
    store = b.dsr.dbTicketStore({ db: handle, table: TABLE });
    softCheck("store(pg): dbTicketStore construction ran ensureSchema on real Postgres", true);

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
      softCheck("sealed-insert(pg): the ticket row physically landed on Postgres",
            raw.length === 1);
      softCheck("sealed-insert(pg): subject_email is sealed at rest (not plaintext)",
            raw.length === 1 && typeof raw[0].subject_email === "string" &&
            raw[0].subject_email.indexOf("alice@example.com") === -1);
      softCheck("sealed-insert(pg): payload is sealed at rest (no plaintext email leak)",
            raw.length === 1 && typeof raw[0].payload === "string" &&
            raw[0].payload.indexOf("alice@example.com") === -1);
      softCheck("sealed-insert(pg): derived subject_email_hash populated for lookup",
            raw.length === 1 && typeof raw[0].subject_email_hash === "string" &&
            raw[0].subject_email_hash.length > 0);
      softCheck("sealed-insert(pg): derived subject_id_hash populated for lookup",
            raw.length === 1 && typeof raw[0].subject_id_hash === "string" &&
            raw[0].subject_id_hash.length > 0);

      var got = await store.get(t1.id);
      softCheck("sealed-insert(pg): get() unseals the payload back to cleartext",
            got !== null && got.subject && got.subject.email === "alice@example.com" &&
            got.type === "access" && got.status === "pending");
      softCheck("sealed-insert(pg): get() of an unknown id returns null",
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
      softCheck("list(pg): alice's email matches exactly her two tickets via the " +
            "dual-hash whereIn (not bob's)",
            aliceList.length === 2 &&
            JSON.stringify(aliceIds) === JSON.stringify([t1.id, t2.id].sort()));

      var bobList = await store.list({ subject: { subjectId: "u-bob" } });
      softCheck("list(pg): bob's subjectId matches exactly his ticket via subject_id_hash",
            bobList.length === 1 && bobList[0].id === tb.id);
    });

    await _section("fail-closed-filter", async function () {
      var all = await store.list({});
      softCheck("fail-closed(pg): baseline — a no-subject list sees every ticket (3)",
            all.length === 3);

      // Alice's phone IS on her tickets' sealed payloads, but phone is not
      // an indexable subject key — the filter must produce a
      // matches-nothing predicate, NOT degrade to a full-table scan.
      var phoneOnly = await store.list({ subject: { phone: "+15550001111" } });
      softCheck("fail-closed(pg): a phone-only subject matches ZERO tickets on real " +
            "Postgres (never all " + all.length + ")",
            phoneOnly.length === 0);

      var emptySubject = await store.list({ subject: {} });
      softCheck("fail-closed(pg): an empty subject matches ZERO tickets (never all)",
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
      softCheck("erasure(pg): the erasure ticket completed on real Postgres",
            processed && processed.status === "completed");

      softCheck("erasure(pg): alice's prior ticket one was purged",
            (await store.get(t1.id)) === null);
      softCheck("erasure(pg): alice's prior ticket two was purged",
            (await store.get(t2.id)) === null);
      softCheck("erasure(pg): the erasure ticket itself survives (audit/receipt trail)",
            (await store.get(erasure.id)) !== null);
      softCheck("erasure(pg): bob's ticket is untouched by alice's erasure purge",
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
      softCheck("erasure-no-key(pg): the no-indexable-key erasure still completes",
            done && done.status === "completed");
      softCheck("erasure-no-key(pg): bob's ticket SURVIVES the no-key purge " +
            "(a fail-open filter would have deleted it)",
            (await store.get(tb.id)) !== null);
      softCheck("erasure-no-key(pg): alice's completed erasure ticket SURVIVES the no-key purge",
            (await store.get(erasure.id)) !== null);
      softCheck("erasure-no-key(pg): the no-key erasure ticket itself survives",
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
      softCheck("purge-expired(pg): the aged terminal ticket was purged (exactly 1)",
            purged === 1);
      softCheck("purge-expired(pg): the aged ticket row is gone",
            (await store.get("DSR-0000000-RETIRED1")) === null);
      softCheck("purge-expired(pg): a completed ticket inside its retention floor survives",
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
  console.log("[dsr-cluster-pg] " + (_findings.length - failures.length) + "/" +
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
