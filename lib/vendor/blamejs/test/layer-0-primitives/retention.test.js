// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.retention — canonical per-primitive coverage.
 *
 * Drives the retention controller through its real consumer path
 * (b.retention.create → declare → run / runAll / preview / list) plus
 * the standalone posture helpers (complianceFloor / applyPosture /
 * activePosture). Focuses on the error / adversarial / defensive /
 * option-default branches: rule-shape rejection, the identifier SQLi
 * gate, legal-hold skip (per-row field + subject registry), multi-stage
 * routing, soft-delete-without-field, custom-action errors, cascade
 * fan-out, the keyset-pagination cursor, the __erasedAt fallback query,
 * sweep failure, and the per-rule concurrency lock.
 */

var fs = require("fs");
var path = require("path");
var os = require("os");
var helpers  = require("../helpers");
var dbHelper = require("../helpers/db");
var b     = helpers.b;
var check = helpers.check;

var DAYS90 = b.constants.TIME.days(90);
var LONG_AGO = function () { return Date.now() - b.constants.TIME.days(400); };

// Create an operator app table (unique name per test) with the columns the
// candidate query expects. __erasedAt present unless withoutErasedAt.
function _seedTable(table, n, opts) {
  opts = opts || {};
  var cols = ["\"_id\" TEXT PRIMARY KEY", "\"createdAt\" INTEGER", "\"payload\" TEXT"];
  if (!opts.withoutErasedAt) cols.push("\"__erasedAt\" INTEGER");
  if (opts.holdCol) cols.push("\"" + opts.holdCol + "\" INTEGER");
  if (opts.subjectCol) cols.push("\"" + opts.subjectCol + "\" TEXT");
  if (opts.softCol) cols.push("\"" + opts.softCol + "\" INTEGER");
  b.db.prepare("CREATE TABLE \"" + table + "\" (" + cols.join(", ") + ")").run();
  var colNames = ["\"_id\"", "\"createdAt\"", "\"payload\""];
  if (opts.holdCol)    colNames.push("\"" + opts.holdCol + "\"");
  if (opts.subjectCol) colNames.push("\"" + opts.subjectCol + "\"");
  var qs = colNames.map(function () { return "?"; }).join(", ");
  for (var i = 0; i < n; i++) {
    var vals = ["r-" + i, LONG_AGO(), "secret-" + i];
    if (opts.holdCol)    vals.push(opts.hold ? 1 : null);
    if (opts.subjectCol) vals.push(opts.subject || ("subj-" + i));
    b.db.prepare("INSERT INTO \"" + table + "\" (" + colNames.join(", ") + ") VALUES (" + qs + ")").run.apply(null, vals);
  }
}

function _expectThrow(label, fn, matcher) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  // Match against BOTH the framework-error code and the message text so a
  // matcher can pin either surface.
  var msg = threw ? ((threw.code || "") + " " + (threw.message || String(threw))) : "";
  check(label, threw !== null && (!matcher || matcher.test(msg)));
}

// ---------------------------------------------------------------------------
// Happy path — establishes the real consumer path works end-to-end.
// ---------------------------------------------------------------------------
async function testHappyEraseSweep() {
  b.cryptoField.registerTable("ret_happy", { sealedFields: ["payload"], rowIdField: "_id" });
  _seedTable("ret_happy", 3);
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "happy", table: "ret_happy", ageField: "createdAt", ttlMs: DAYS90, action: "erase" });
  var summary = await ret.run("happy");
  check("happy erase scanned 3", summary.scanned === 3);
  check("happy erase processed 3", summary.processed === 3);
  check("happy erase action label", summary.action === "erase");
  var nulled = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_happy\" WHERE \"payload\" IS NULL").get();
  check("happy erase NULLed the sealed payload", nulled.n === 3);
  var listed = ret.list();
  check("list() surfaces the declared rule", listed.length === 1 && listed[0].name === "happy");
  check("list() reports default batchSize 500", listed[0].batchSize === 500);
}

// ---------------------------------------------------------------------------
// Audit-on path — exercises _emit + the auditInstance branch of create().
// ---------------------------------------------------------------------------
async function testAuditOnEmits() {
  b.cryptoField.registerTable("ret_audit", { sealedFields: ["payload"], rowIdField: "_id" });
  _seedTable("ret_audit", 1);
  // audit: an instance → auditInstance = the passed object (not the lazy singleton).
  var ret = b.retention.create({ db: b.db, audit: b.audit });
  ret.declare({ name: "audit-on", table: "ret_audit", ageField: "createdAt", ttlMs: DAYS90, action: "erase" });
  var summary = await ret.run("audit-on");
  check("audit-on sweep still processes the row", summary.processed === 1);
  // audit: true → auditOn true but auditInstance null (lazy audit() sink).
  var ret2 = b.retention.create({ db: b.db, audit: true });
  ret2.declare({ name: "audit-true", table: "ret_audit", ageField: "createdAt", ttlMs: DAYS90, action: "erase" });
  var s2 = await ret2.run("audit-true");
  check("audit:true controller runs without throwing", !!s2);
}

// ---------------------------------------------------------------------------
// delete action + keyset-pagination cursor across multiple batches.
// ---------------------------------------------------------------------------
async function testDeleteActionMultiBatch() {
  _seedTable("ret_del", 5);   // not registered for sealing — plain delete
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "del", table: "ret_del", ageField: "createdAt", ttlMs: DAYS90, action: "delete", batchSize: 2 });
  var summary = await ret.run("del");
  check("delete multi-batch scanned every row once", summary.scanned === 5);
  check("delete multi-batch processed every row", summary.processed === 5);
  var left = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_del\"").get();
  check("delete removed every past-TTL row", left.n === 0);
}

// ---------------------------------------------------------------------------
// soft-delete action — writes softDeleteField; candidate query whereNull it.
// ---------------------------------------------------------------------------
async function testSoftDeleteAction() {
  _seedTable("ret_soft", 3, { softCol: "deletedAt" });
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "soft", table: "ret_soft", ageField: "createdAt", ttlMs: DAYS90,
    action: "soft-delete", softDeleteField: "deletedAt" });
  // dry-run first: would-soft-delete without stamping the column.
  var pv = await ret.run("soft", { dryRun: true });
  check("soft-delete dry-run would-process without stamping", pv.processed === 3);
  var unstamped = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_soft\" WHERE \"deletedAt\" IS NULL").get();
  check("soft-delete dry-run stamped nothing", unstamped.n === 3);
  var summary = await ret.run("soft");
  check("soft-delete processed every row", summary.processed === 3);
  var stamped = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_soft\" WHERE \"deletedAt\" IS NOT NULL").get();
  check("soft-delete stamped the timestamp column", stamped.n === 3);
  // A second sweep skips the already-soft-deleted rows (whereNull excludes them).
  var again = await ret.run("soft");
  check("second soft-delete sweep scans nothing (already stamped)", again.scanned === 0);
}

// soft-delete action declared WITHOUT softDeleteField → per-row throw, captured
// into summary.errors (the run loop's defensive per-row catch + warning outcome).
async function testSoftDeleteMissingField() {
  _seedTable("ret_soft_bad", 2);
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "soft-bad", table: "ret_soft_bad", ageField: "createdAt", ttlMs: DAYS90,
    action: "soft-delete" });   // no softDeleteField
  var summary = await ret.run("soft-bad");
  check("soft-delete-without-field records a per-row error", summary.errors.length === 2);
  check("soft-delete-without-field processed nothing", summary.processed === 0);
  check("soft-delete-without-field error names the missing field",
        /softDeleteField/.test(summary.errors[0].reason || ""));
}

// ---------------------------------------------------------------------------
// custom function action — real path, dry-run path, error path, list label.
// ---------------------------------------------------------------------------
async function testCustomActionFn() {
  _seedTable("ret_custom", 2);
  var seen = [];
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "custom", table: "ret_custom", ageField: "createdAt", ttlMs: DAYS90,
    action: function (row) { seen.push(row._id); return { customAction: 1, id: row._id }; } });
  var summary = await ret.run("custom");
  check("custom action processed every row", summary.processed === 2);
  check("custom action invoked once per row", seen.length === 2);
  check("custom rule reports action 'custom'", summary.action === "custom");
  check("list() reports <custom> for a function action",
        ret.list()[0].action === "<custom>");
  // dry-run: the function must NOT be invoked (wouldCustomAction shape).
  seen.length = 0;
  var preview = await ret.run("custom", { dryRun: true });
  check("custom dry-run would-process without invoking the fn",
        preview.processed === 2 && seen.length === 0);

  // A custom action returning nothing → the { customAction: 1 } default shape.
  _seedTable("ret_custom_void", 1);
  var ret0 = b.retention.create({ db: b.db, audit: false });
  ret0.declare({ name: "custom-void", table: "ret_custom_void", ageField: "createdAt", ttlMs: DAYS90,
    action: function () { /* returns undefined */ } });
  var s0 = await ret0.run("custom-void");
  check("custom action returning nothing still counts as processed", s0.processed === 1);

  // A throwing custom action lands in summary.errors, not an unhandled reject.
  _seedTable("ret_custom_err", 2);
  var ret2 = b.retention.create({ db: b.db, audit: false });
  ret2.declare({ name: "custom-err", table: "ret_custom_err", ageField: "createdAt", ttlMs: DAYS90,
    action: function () { throw new Error("boom-in-custom"); } });
  var s2 = await ret2.run("custom-err");
  check("throwing custom action captured per-row (not fatal)", s2.errors.length === 2);
  check("throwing custom action surfaces the reason", /boom-in-custom/.test(s2.errors[0].reason || ""));

  // An error carrying an empty message → the per-row reason falls back to
  // String(e) rather than storing "".
  _seedTable("ret_custom_empty", 1);
  var ret3 = b.retention.create({ db: b.db, audit: false });
  ret3.declare({ name: "custom-empty", table: "ret_custom_empty", ageField: "createdAt", ttlMs: DAYS90,
    action: function () { throw new Error(""); } });
  var s3 = await ret3.run("custom-empty");
  check("empty-message error still records a non-empty per-row reason",
        s3.errors.length === 1 && typeof s3.errors[0].reason === "string" && s3.errors[0].reason.length > 0);
}

// ---------------------------------------------------------------------------
// cascade fan-out — real DELETE + dry-run COUNT of child rows.
// ---------------------------------------------------------------------------
async function testCascade() {
  _seedTable("ret_parent", 2);
  b.db.prepare("CREATE TABLE \"ret_child\" (\"_id\" TEXT PRIMARY KEY, \"parentId\" TEXT)").run();
  b.db.prepare("INSERT INTO \"ret_child\" (\"_id\", \"parentId\") VALUES ('c-0','r-0')").run();
  b.db.prepare("INSERT INTO \"ret_child\" (\"_id\", \"parentId\") VALUES ('c-1','r-0')").run();
  b.db.prepare("INSERT INTO \"ret_child\" (\"_id\", \"parentId\") VALUES ('c-2','r-1')").run();
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "casc", table: "ret_parent", ageField: "createdAt", ttlMs: DAYS90,
    action: "delete", cascade: [{ table: "ret_child", foreignKey: "parentId" }] });

  // dry-run first: counts children, deletes nothing.
  var preview = await ret.run("casc", { dryRun: true });
  check("cascade dry-run scanned the parents", preview.scanned === 2);
  var childPre = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_child\"").get();
  check("cascade dry-run left every child row intact", childPre.n === 3);

  // real run: deletes parents + cascades to children.
  var summary = await ret.run("casc");
  check("cascade real run processed the parents", summary.processed === 2);
  var childPost = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_child\"").get();
  check("cascade real run fanned the delete into children", childPost.n === 0);

  // erase action + cascade — the erase path also fans the FK edge out.
  b.cryptoField.registerTable("ret_ec_parent", { sealedFields: ["payload"], rowIdField: "_id" });
  _seedTable("ret_ec_parent", 2);
  b.db.prepare("CREATE TABLE \"ret_ec_child\" (\"_id\" TEXT PRIMARY KEY, \"pid\" TEXT)").run();
  b.db.prepare("INSERT INTO \"ret_ec_child\" (\"_id\", \"pid\") VALUES ('ec-0','r-0')").run();
  b.db.prepare("INSERT INTO \"ret_ec_child\" (\"_id\", \"pid\") VALUES ('ec-1','r-1')").run();
  var retE = b.retention.create({ db: b.db, audit: false });
  retE.declare({ name: "ec", table: "ret_ec_parent", ageField: "createdAt", ttlMs: DAYS90,
    action: "erase", cascade: [{ table: "ret_ec_child", foreignKey: "pid" }] });
  var eSummary = await retE.run("ec");
  check("erase+cascade processed the parents", eSummary.processed === 2);
  var ecChild = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_ec_child\"").get();
  check("erase+cascade fanned the delete into children", ecChild.n === 0);
  var ecParent = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_ec_parent\" WHERE \"payload\" IS NULL").get();
  check("erase+cascade NULLed the parent sealed column", ecParent.n === 2);
}

// ---------------------------------------------------------------------------
// erase with derived-hash columns — NULLs the sealed field AND its hash sibling.
// ---------------------------------------------------------------------------
async function testEraseWithDerivedHash() {
  b.cryptoField.registerTable("ret_dh", {
    sealedFields:  ["email"],
    rowIdField:    "_id",
    derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
  });
  b.db.prepare("CREATE TABLE \"ret_dh\" (\"_id\" TEXT PRIMARY KEY, \"createdAt\" INTEGER, " +
    "\"email\" TEXT, \"emailHash\" TEXT, \"__erasedAt\" INTEGER)").run();
  var longAgo = LONG_AGO();
  for (var i = 0; i < 2; i++) {
    b.db.prepare("INSERT INTO \"ret_dh\" (\"_id\",\"createdAt\",\"email\",\"emailHash\",\"__erasedAt\") VALUES (?,?,?,?,NULL)")
      .run("d-" + i, longAgo, "user" + i + "@x.test", "hash-" + i);
  }
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "dh", table: "ret_dh", ageField: "createdAt", ttlMs: DAYS90, action: "erase" });
  var summary = await ret.run("dh");
  check("derived-hash erase processed every row", summary.processed === 2);
  var nulled = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_dh\" WHERE \"email\" IS NULL AND \"emailHash\" IS NULL").get();
  check("derived-hash erase NULLed both the sealed field and its hash sibling", nulled.n === 2);
}

// ---------------------------------------------------------------------------
// multi-stage routing — earliest-cutoff selection + warn stage + stageBreakdown.
// ---------------------------------------------------------------------------
async function testMultiStage() {
  // Rows aged ~400d. Stages: warn at 90d, delete at 300d. Both crossed → the
  // most-aggressive due stage (delete) wins.
  _seedTable("ret_stage", 2);
  var ret = b.retention.create({ db: b.db, audit: false });
  // ttlMs deliberately larger than the smallest stage atMs so the run() cutoff
  // computation walks the stages and picks the earliest stage threshold.
  ret.declare({ name: "stage", table: "ret_stage", ageField: "createdAt", ttlMs: b.constants.TIME.days(400),
    action: "delete",
    stages: [ { atMs: b.constants.TIME.days(90), action: "warn" },
              { atMs: b.constants.TIME.days(300), action: "delete" } ] });
  var summary = await ret.run("stage");
  check("multi-stage scanned the candidate rows", summary.scanned === 2);
  check("multi-stage routed to the most-aggressive due stage (delete)",
        summary.stageBreakdown.delete === 2);
  var left = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_stage\"").get();
  check("multi-stage delete removed the rows", left.n === 0);

  // warn-only: a young row that crossed only the warn stage → warned, no write.
  b.db.prepare("CREATE TABLE \"ret_warn\" (\"_id\" TEXT PRIMARY KEY, \"createdAt\" INTEGER, \"payload\" TEXT, \"__erasedAt\" INTEGER)").run();
  var midAge = Date.now() - b.constants.TIME.days(120);   // past warn(90) but before delete(300)
  b.db.prepare("INSERT INTO \"ret_warn\" (\"_id\",\"createdAt\",\"payload\",\"__erasedAt\") VALUES ('w-0',?, 'p', NULL)").run(midAge);
  var ret2 = b.retention.create({ db: b.db, audit: false });
  ret2.declare({ name: "warn", table: "ret_warn", ageField: "createdAt", ttlMs: DAYS90,
    action: "delete",
    stages: [ { atMs: b.constants.TIME.days(90), action: "warn" },
              { atMs: b.constants.TIME.days(300), action: "delete" } ] });
  var s2 = await ret2.run("warn");
  check("warn stage marks the row warned (no delete)", s2.stageBreakdown.warn === 1);
  var stillHere = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_warn\"").get();
  check("warn stage left the row in place", stillHere.n === 1);
}

// ---------------------------------------------------------------------------
// legal-hold — per-row field skip.
// ---------------------------------------------------------------------------
async function testLegalHoldPerRowField() {
  _seedTable("ret_hold", 3, { holdCol: "onHold", hold: true });
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "hold", table: "ret_hold", ageField: "createdAt", ttlMs: DAYS90,
    action: "delete", legalHoldField: "onHold" });
  var summary = await ret.run("hold");
  check("per-row legal hold honoured on every row", summary.legalHoldsHonored === 3);
  check("per-row legal hold processed nothing", summary.processed === 0);
  var intact = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_hold\"").get();
  check("per-row legal hold left every row intact", intact.n === 3);
}

// legal-hold — subject-level registry consult (b.legalHold singleton).
async function testLegalHoldSubjectRegistry() {
  _seedTable("ret_subj", 2, { subjectCol: "userId", subject: "held-user" });
  var holds = b.legalHold.create({ db: b.db, audit: false });
  try {
    var placed = holds.place("held-user", { reason: "SEC subpoena 24-cv-01933", citation: "SEC-Rule-17a-4" });
    check("legal-hold placed on the subject", placed && placed.placed === true);
    check("registry reports the subject held", holds.isHeld("held-user") === true);
    var ret = b.retention.create({ db: b.db, audit: false });
    ret.declare({ name: "subj", table: "ret_subj", ageField: "createdAt", ttlMs: DAYS90,
      action: "delete", subjectField: "userId" });
    var summary = await ret.run("subj");
    check("subject-registry hold honoured on every row", summary.legalHoldsHonored === 2);
    check("subject-registry hold processed nothing", summary.processed === 0);
    var intact = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_subj\"").get();
    check("subject-registry hold left every row intact", intact.n === 2);
  } finally {
    // Don't leak the process-global singleton into sibling suite files.
    if (b.legalHold && typeof b.legalHold._resetForTest === "function") b.legalHold._resetForTest();
  }
}

// ---------------------------------------------------------------------------
// erase on a table with no sealed columns → falls back to hard delete.
// ---------------------------------------------------------------------------
async function testEraseFallbackToDelete() {
  _seedTable("ret_nosealed", 2);   // not registered → getSealedFields === []
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "nosealed", table: "ret_nosealed", ageField: "createdAt", ttlMs: DAYS90, action: "erase" });
  var summary = await ret.run("nosealed");
  check("erase-with-no-sealed-columns processed the rows", summary.processed === 2);
  var left = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_nosealed\"").get();
  check("erase-with-no-sealed-columns fell back to a hard delete", left.n === 0);
}

// ---------------------------------------------------------------------------
// candidate-query fallback when the table has no __erasedAt column.
// ---------------------------------------------------------------------------
async function testNoErasedAtColumnFallback() {
  _seedTable("ret_noerased", 3, { withoutErasedAt: true });
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "noerased", table: "ret_noerased", ageField: "createdAt", ttlMs: DAYS90, action: "delete" });
  var summary = await ret.run("noerased");
  check("no-__erasedAt table falls back to the plain candidate query", summary.scanned === 3);
  check("no-__erasedAt table still processes rows", summary.processed === 3);
}

// ---------------------------------------------------------------------------
// preview() — dry-run convenience wrapper, no concurrency-lock consumption.
// ---------------------------------------------------------------------------
async function testPreview() {
  b.cryptoField.registerTable("ret_preview", { sealedFields: ["payload"], rowIdField: "_id" });
  _seedTable("ret_preview", 2);
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "prev", table: "ret_preview", ageField: "createdAt", ttlMs: DAYS90, action: "erase" });
  var preview = await ret.preview("prev");
  check("preview reports would-process count", preview.processed === 2 && preview.dryRun === true);
  var intact = b.db.prepare("SELECT COUNT(*) AS n FROM \"ret_preview\" WHERE \"payload\" IS NOT NULL").get();
  check("preview mutated nothing", intact.n === 2);
}

// ---------------------------------------------------------------------------
// concurrency lock — an in-flight sweep is not re-entered.
// ---------------------------------------------------------------------------
async function testConcurrencyLock() {
  _seedTable("ret_lock", 1);
  var release;
  var gate = new Promise(function (res) { release = res; });
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "lock", table: "ret_lock", ageField: "createdAt", ttlMs: DAYS90,
    action: async function () { await gate; return { customAction: 1 }; } });
  var p1 = ret.run("lock");                    // suspends inside the custom action with running[name]=true
  var r2 = await ret.run("lock");              // sees the lock → skipped
  check("concurrent sweep is skipped", r2.skipped === true);
  check("concurrent sweep names the reason", r2.reason === "concurrent-sweep-in-progress");
  release();
  var r1 = await p1;
  check("the in-flight sweep completes after release", r1.processed === 1);
  // The lock is cleared afterwards — a follow-up sweep runs normally.
  var r3 = await ret.run("lock");
  check("lock released after completion (follow-up sweep runs)", r3.skipped !== true);
}

// ---------------------------------------------------------------------------
// runAll — success + the per-rule failure branch (rule on a missing table).
// ---------------------------------------------------------------------------
async function testRunAll() {
  _seedTable("ret_all", 2);
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "all-ok", table: "ret_all", ageField: "createdAt", ttlMs: DAYS90, action: "delete" });
  // A valid identifier that names a table that does not exist → SWEEP_FAILED,
  // caught by runAll into a { name, error } entry rather than aborting the batch.
  ret.declare({ name: "all-ghost", table: "ghost_table_absent", ageField: "createdAt", ttlMs: DAYS90, action: "delete" });
  var summaries = await ret.runAll();
  check("runAll returns one summary per rule", summaries.length === 2);
  var ok = summaries.filter(function (s) { return s.name === "all-ok"; })[0];
  var ghost = summaries.filter(function (s) { return s.name === "all-ghost"; })[0];
  check("runAll ran the healthy rule", ok && ok.processed === 2);
  check("runAll captured the failing rule as an error entry", ghost && typeof ghost.error === "string");
}

// run() on a rule that fails mid-sweep throws SWEEP_FAILED.
async function testSweepFailedThrows() {
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "boom", table: "another_absent_table", ageField: "createdAt", ttlMs: DAYS90, action: "delete" });
  var threw = null;
  try { await ret.run("boom"); } catch (e) { threw = e; }
  check("sweep against a missing table throws SWEEP_FAILED",
        threw !== null && /SWEEP_FAILED|sweep failed/.test((threw && (threw.code || threw.message)) || ""));
  // The lock is released even on failure — a retry is not permanently blocked.
  var threw2 = null;
  try { await ret.run("boom"); } catch (e) { threw2 = e; }
  check("failed sweep released the lock (retry reaches the same failure, not a skip)",
        threw2 !== null && !(threw2 && threw2.skipped));
}

// ---------------------------------------------------------------------------
// create() / run() entry-point guards.
// ---------------------------------------------------------------------------
function testCreateBadOpt() {
  _expectThrow("create() with no arguments throws BAD_OPT",
    function () { b.retention.create(); }, /db is required|BAD_OPT/);
  _expectThrow("create() with no db throws BAD_OPT",
    function () { b.retention.create({ audit: false }); }, /db is required|BAD_OPT/);
  _expectThrow("create() with a db lacking .prepare throws BAD_OPT",
    function () { b.retention.create({ db: {}, audit: false }); }, /db is required|BAD_OPT/);
}

async function testNoSuchRule() {
  var ret = b.retention.create({ db: b.db, audit: false });
  var threw = null;
  try { await ret.run("never-declared"); } catch (e) { threw = e; }
  check("run() on an undeclared rule throws NO_SUCH_RULE",
        threw !== null && /NO_SUCH_RULE|not declared/.test((threw && (threw.code || threw.message)) || ""));
}

function testDuplicateRule() {
  var ret = b.retention.create({ db: b.db, audit: false });
  ret.declare({ name: "dup", table: "ret_dup", ageField: "createdAt", ttlMs: DAYS90, action: "delete" });
  _expectThrow("declaring the same rule name twice throws DUPLICATE_RULE",
    function () { ret.declare({ name: "dup", table: "ret_dup", ageField: "createdAt", ttlMs: DAYS90, action: "delete" }); },
    /DUPLICATE_RULE|already declared/);
}

// ---------------------------------------------------------------------------
// _handleDialect — operator handle advertising a dialect (fn / string / throw).
// ---------------------------------------------------------------------------
function testHandleDialect() {
  function wrap(dialect) {
    return { prepare: function () { return b.db.prepare.apply(b.db, arguments); }, dialect: dialect };
  }
  // All resolve to "sqlite" so the emitted SQL still runs against the real handle.
  check("dialect() returning a string is threaded through",
        !!b.retention.create({ db: wrap(function () { return "sqlite"; }), audit: false }));
  check("dialect() returning a non-string falls back to sqlite",
        !!b.retention.create({ db: wrap(function () { return 123; }), audit: false }));
  check("dialect() throwing falls back to sqlite",
        !!b.retention.create({ db: wrap(function () { throw new Error("no dialect"); }), audit: false }));
  check("dialect as a string property is honoured",
        !!b.retention.create({ db: { prepare: b.db.prepare.bind(b.db), dialect: "sqlite" }, audit: false }));
}

// ---------------------------------------------------------------------------
// _validateRule — the full rejection battery (config-time throws).
// ---------------------------------------------------------------------------
function testRuleValidation() {
  var ret = b.retention.create({ db: b.db, audit: false });
  function bad(label, rule, matcher) {
    _expectThrow(label, function () { ret.declare(rule); }, matcher || /BAD_RULE/);
  }
  bad("non-object rule rejected", null, /rule must be an object|BAD_RULE/);
  bad("non-object rule (string) rejected", "nope", /rule must be an object|BAD_RULE/);
  bad("missing name rejected", { table: "t", ageField: "createdAt", ttlMs: 1, action: "delete" }, /rule\.name/);
  bad("empty name rejected", { name: "", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete" }, /rule\.name/);
  bad("missing table rejected", { name: "n", ageField: "createdAt", ttlMs: 1, action: "delete" }, /rule\.table/);
  bad("SQLi table identifier rejected",
      { name: "n", table: "users\"; DROP TABLE audit_log;--", ageField: "createdAt", ttlMs: 1, action: "delete" },
      /safe SQL identifier/);
  bad("missing ageField rejected", { name: "n", table: "t", ttlMs: 1, action: "delete" }, /rule\.ageField/);
  bad("SQLi ageField identifier rejected",
      { name: "n", table: "t", ageField: "a b", ttlMs: 1, action: "delete" }, /safe SQL identifier/);
  bad("zero ttlMs rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 0, action: "delete" }, /ttlMs/);
  bad("negative ttlMs rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: -5, action: "delete" }, /ttlMs/);
  bad("non-finite ttlMs rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: Infinity, action: "delete" }, /ttlMs/);
  bad("non-number ttlMs rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: "90d", action: "delete" }, /ttlMs/);
  bad("non-string/non-fn action rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: 5 }, /rule\.action/);
  bad("unknown action string rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "shred" }, /erase|delete|soft-delete/);
  bad("zero batchSize rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", batchSize: 0 }, /batchSize/);
  bad("non-int batchSize rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", batchSize: 2.5 }, /batchSize/);
  bad("empty softDeleteField rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", softDeleteField: "" }, /softDeleteField/);
  bad("non-string softDeleteField rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", softDeleteField: 7 }, /softDeleteField/);
  bad("SQLi softDeleteField rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", softDeleteField: "a;b" }, /safe SQL identifier/);
  bad("empty legalHoldField rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", legalHoldField: "" }, /legalHoldField/);
  bad("SQLi legalHoldField rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", legalHoldField: "x y" }, /safe SQL identifier/);
  bad("empty subjectField rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", subjectField: "" }, /subjectField/);
  bad("SQLi subjectField rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", subjectField: "u-d" }, /safe SQL identifier/);
  bad("non-array cascade rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", cascade: {} }, /cascade/);
  bad("empty cascade rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", cascade: [] }, /cascade/);
  bad("malformed cascade entry rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", cascade: [{ table: "c" }] }, /cascade/);
  bad("SQLi cascade table rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", cascade: [{ table: "c;x", foreignKey: "fk" }] }, /safe SQL identifier/);
  bad("SQLi cascade fk rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", cascade: [{ table: "c", foreignKey: "f k" }] }, /safe SQL identifier/);
  bad("non-array stages rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", stages: {} }, /stages/);
  bad("empty stages rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", stages: [] }, /stages/);
  bad("bad stage atMs rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", stages: [{ atMs: 0, action: "warn" }] }, /atMs/);
  bad("bad stage action type rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", stages: [{ atMs: 5, action: 9 }] }, /stages\[0\]\.action/);
  bad("unknown stage action string rejected", { name: "n", table: "t", ageField: "createdAt", ttlMs: 1, action: "delete", stages: [{ atMs: 5, action: "purge" }] }, /erase|delete|soft-delete|warn/);
}

// ---------------------------------------------------------------------------
// Posture helpers — complianceFloor / applyPosture / activePosture.
// ---------------------------------------------------------------------------
function testPostureHelpers() {
  var r = b.retention;
  var prior = r.activePosture();
  try {
    // Known floors.
    check("complianceFloor(hipaa) returns the 6-year floor",
          r.complianceFloor("hipaa") === b.constants.TIME.days(365 * 6));
    check("complianceFloor candidate > floor keeps candidate",
          r.complianceFloor("pci-dss", b.constants.TIME.days(400)) === b.constants.TIME.days(400));
    check("complianceFloor candidate <= 0 falls back to floor",
          r.complianceFloor("sox", 0) === b.constants.TIME.days(365 * 7));
    // Unknown posture / bad posture type.
    _expectThrow("complianceFloor(unknown) throws unknown-posture",
      function () { r.complianceFloor("not-a-posture", 1000); }, /unknown-posture/);

    // applyPosture records active state; complianceFloor inherits it.
    r.applyPosture(null);
    check("applyPosture(null) clears the active posture", r.activePosture() === null);
    _expectThrow("complianceFloor with no active posture + omitted arg throws",
      function () { r.complianceFloor(b.constants.TIME.days(30)); }, /bad-posture|posture must be a string/);

    var applied = r.applyPosture("hipaa");
    check("applyPosture(known) returns { posture, floorMs }",
          applied && applied.posture === "hipaa" && applied.floorMs === b.constants.TIME.days(365 * 6));
    check("activePosture reflects the applied posture", r.activePosture() === "hipaa");
    check("complianceFloor(numeric-only) inherits the active posture",
          r.complianceFloor(b.constants.TIME.days(30)) === b.constants.TIME.days(365 * 6));

    // A posture string with no retention floor → floorMs null (no throw here;
    // applyPosture records whatever the operator pins).
    var noFloor = r.applyPosture("gdpr");
    check("applyPosture(posture with no floor) reports floorMs null",
          noFloor && noFloor.posture === "gdpr" && noFloor.floorMs === null);
  } finally {
    if (typeof prior === "string") r.applyPosture(prior); else r.applyPosture(null);
  }
}

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-retention-"));
  await dbHelper.setupTestDb(tmpDir);
  try {
    await testHappyEraseSweep();
    await testAuditOnEmits();
    await testDeleteActionMultiBatch();
    await testSoftDeleteAction();
    await testSoftDeleteMissingField();
    await testCustomActionFn();
    await testCascade();
    await testEraseWithDerivedHash();
    await testMultiStage();
    await testLegalHoldPerRowField();
    await testLegalHoldSubjectRegistry();
    await testEraseFallbackToDelete();
    await testNoErasedAtColumnFallback();
    await testPreview();
    await testConcurrencyLock();
    await testRunAll();
    await testSweepFailedThrows();
    testCreateBadOpt();
    await testNoSuchRule();
    testDuplicateRule();
    testHandleDialect();
    testRuleValidation();
    testPostureHelpers();
  } finally {
    await dbHelper.teardownTestDb(tmpDir);
  }
  console.log("OK — retention (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; console.error(err && err.stack || err); });
}
