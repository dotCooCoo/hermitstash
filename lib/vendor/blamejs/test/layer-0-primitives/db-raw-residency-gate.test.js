"use strict";
/**
 * b.db.runSql / b.db.prepare(...).run(...) — local per-row residency gate on
 * the RAW execution path. _assertLocalResidency is wired only at the
 * structured builder boundary (insertOne/updateOne). The raw paths
 * b.db.runSql (execRaw) and b.db.prepare(sql).run(...) write a cross-border
 * row straight to disk with NO residency check under a regulated posture.
 * RED today: builder refuses (control), raw paths do not.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = helpers.fs;
var os   = helpers.os;
var path = helpers.path;

var SCHEMA = [{
  name: "residents",
  columns: { _id: "TEXT PRIMARY KEY", name: "TEXT", dataRegion: "TEXT" },
}];

async function initDb(tmpDir) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  helpers.setTestPassphraseEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init({
    dataDir:       tmpDir,
    tmpDir:        path.join(tmpDir, "tmpfs"),
    schema:        SCHEMA,
    dataResidency: { region: "eu-west-1" },
  });
}

function codeOf(fn) {
  try { fn(); } catch (e) { return (e && e.code) || (e && e.message) || "threw"; }
  return null;
}

async function run() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-raw-resid-"));
  await initDb(tmp);
  b.cryptoField.clearResidencyForTest();
  try {
    b.cryptoField.declarePerRowResidency("residents", {
      residencyColumn: "dataRegion",
      allowedTags:     ["eu-west-1", "us-east-1", "global"],
    });
    b.compliance.set("gdpr");

    // CONTROL: the structured builder path refuses the cross-border tag.
    check("control: db.from() builder refuses the cross-border tag",
      codeOf(function () {
        b.db.from("residents").insertOne({ _id: "ctl", name: "x", dataRegion: "us-east-1" });
      }) === "db-query/row-residency-local-mismatch");

    // RAW PATH 1: b.db.runSql (execRaw). RED today — no refusal.
    var runSqlRefusedCode = codeOf(function () {
      b.db.runSql(
        "INSERT INTO \"residents\" (_id, name, dataRegion) VALUES ('raw-1', 'x', 'us-east-1')");
    });
    check("b.db.runSql cross-border write is refused (residency gate fires on the raw path)",
      runSqlRefusedCode === "db-query/row-residency-local-mismatch");
    check("b.db.runSql cross-border row did not persist (no us-east-1 row landed)",
      b.db.from("residents").where({ _id: "raw-1" }).first() === null);

    // RAW PATH 2: b.db.prepare(sql).run(...) — the seeders' consumer path.
    var prepareRefusedCode = codeOf(function () {
      b.db.prepare(
        "INSERT INTO \"residents\" (_id, name, dataRegion) VALUES (?, ?, ?)")
        .run("raw-2", "x", "us-east-1");
    });
    check("b.db.prepare().run() cross-border write is refused (residency gate fires)",
      prepareRefusedCode === "db-query/row-residency-local-mismatch");
    check("b.db.prepare().run() cross-border row did not persist",
      b.db.from("residents").where({ _id: "raw-2" }).first() === null);

    // An in-region raw write still succeeds (no over-rejection).
    b.db.runSql(
      "INSERT INTO \"residents\" (_id, name, dataRegion) VALUES ('raw-eu', 'y', 'eu-west-1')");
    check("an in-region raw write still persists (gate does not over-reject)",
      (b.db.from("residents").where({ _id: "raw-eu" }).first() || {}).dataRegion === "eu-west-1");

    // RAW PATH 3: a SCHEMA-QUALIFIED table name must resolve to the table and
    // still gate. SQLite accepts INSERT INTO main.residents; capturing only the
    // "main" qualifier would skip the gate for the real target table.
    var qualifiedRefusedCode = codeOf(function () {
      b.db.runSql(
        "INSERT INTO main.residents (_id, name, dataRegion) VALUES ('raw-q', 'x', 'us-east-1')");
    });
    check("qualified-name raw write is refused (main.residents resolves to residents)",
      qualifiedRefusedCode === "db-query/row-residency-local-mismatch");
    check("qualified-name cross-border row did not persist",
      b.db.from("residents").where({ _id: "raw-q" }).first() === null);

    // RAW PATH 4: an UPDATE whose SET value contains the word WHERE inside a
    // quoted string must be parsed quote-aware, so the residency-column
    // assignment after it is still seen and gated.
    var quotedWhereRefusedCode = codeOf(function () {
      b.db.runSql(
        "UPDATE residents SET name='x WHERE y', dataRegion='us-east-1' WHERE _id='raw-eu'");
    });
    check("update with a quoted WHERE in a SET value is parsed quote-aware + refused",
      quotedWhereRefusedCode === "db-query/row-residency-local-mismatch");
    check("the quoted-WHERE update did not move the row cross-border",
      (b.db.from("residents").where({ _id: "raw-eu" }).first() || {}).dataRegion === "eu-west-1");

    // RAW PATH 5: a LEADING SQL COMMENT must not hide the write keyword from the
    // ^-anchored gate. A "/* hint */ INSERT ..." or "-- hint\nUPDATE ..." that
    // the gate fails to recognize as a write skips residency enforcement
    // entirely — a cross-border-write bypass. Strip leading comments before the
    // write-detection so the gate still fires.
    var blockCommentRefusedCode = codeOf(function () {
      b.db.runSql(
        "/* region hint */ INSERT INTO residents (_id, name, dataRegion) VALUES ('raw-bc', 'x', 'us-east-1')");
    });
    check("leading block-comment write is recognized + refused (no comment bypass)",
      blockCommentRefusedCode === "db-query/row-residency-local-mismatch");
    check("leading block-comment cross-border row did not persist",
      b.db.from("residents").where({ _id: "raw-bc" }).first() === null);

    var lineCommentRefusedCode = codeOf(function () {
      b.db.runSql(
        "-- region hint\nUPDATE residents SET dataRegion='us-east-1' WHERE _id='raw-eu'");
    });
    check("leading line-comment write is recognized + refused (no comment bypass)",
      lineCommentRefusedCode === "db-query/row-residency-local-mismatch");
    check("the leading line-comment update did not move the row cross-border",
      (b.db.from("residents").where({ _id: "raw-eu" }).first() || {}).dataRegion === "eu-west-1");

    // Stacked comment + whitespace before the keyword is also stripped.
    var stackedRefusedCode = codeOf(function () {
      b.db.runSql(
        "/* a */  -- b\n  /* c */ INSERT INTO residents (_id, name, dataRegion) VALUES ('raw-st', 'x', 'us-east-1')");
    });
    check("stacked leading comments are stripped + the write is refused",
      stackedRefusedCode === "db-query/row-residency-local-mismatch");

    // An in-region leading-comment write still persists (no over-rejection).
    b.db.runSql(
      "/* in-region */ INSERT INTO residents (_id, name, dataRegion) VALUES ('raw-bc-ok', 'z', 'eu-west-1')");
    check("in-region leading-comment write still persists (gate does not over-reject)",
      (b.db.from("residents").where({ _id: "raw-bc-ok" }).first() || {}).dataRegion === "eu-west-1");

    // RAW PATH 6: a writable-CTE write hides its effective verb behind a `WITH`
    // prefix, so the ^-anchored write-keyword detector misses it — node:sqlite
    // executes `WITH c AS (...) INSERT INTO residents ...` / `WITH ... UPDATE
    // residents SET ...` and would persist a cross-border row UNGATED. The gate
    // now recognizes the residency-table write target behind the CTE prefix and
    // FAILS CLOSED (can't parse a CTE body) — directing the operator to the
    // structured builder. (Sibling of RAW PATH 5.)
    var cteInsertCode = codeOf(function () {
      b.db.runSql(
        "WITH src AS (SELECT 'us-east-1' AS r) INSERT INTO residents (_id, name, dataRegion) SELECT 'cte-i', 'x', r FROM src");
    });
    check("writable-CTE INSERT to a residency table is refused (no CTE-prefix bypass)",
      cteInsertCode === "db-query/row-residency-raw-unparseable");
    check("writable-CTE INSERT cross-border row did not persist",
      b.db.from("residents").where({ _id: "cte-i" }).first() === null);

    var cteUpdateCode = codeOf(function () {
      b.db.prepare(
        "WITH RECURSIVE t AS (SELECT 1) UPDATE residents SET dataRegion = 'us-east-1' WHERE _id = 'raw-eu'").run();
    });
    check("WITH RECURSIVE UPDATE to a residency table is refused (no CTE-prefix bypass)",
      cteUpdateCode === "db-query/row-residency-raw-unparseable");
    check("the writable-CTE update did not move the row cross-border",
      (b.db.from("residents").where({ _id: "raw-eu" }).first() || {}).dataRegion === "eu-west-1");

    // A read-only CTE (WITH ... SELECT) is NOT a write → not gated (no over-reject).
    var cteReadErr = codeOf(function () {
      b.db.runSql("WITH c AS (SELECT _id FROM residents WHERE dataRegion = 'eu-west-1') SELECT _id FROM c");
    });
    check("read-only WITH...SELECT is not gated (no residency error)", cteReadErr === null);

    // A writable-CTE write to a NON-residency table is not over-rejected.
    b.db.runSql("CREATE TABLE IF NOT EXISTS notes (_id TEXT PRIMARY KEY, body TEXT)");
    b.db.runSql("WITH s AS (SELECT 'hi' AS b) INSERT INTO notes (_id, body) SELECT 'n1', b FROM s");
    check("writable-CTE write to a NON-residency table still persists (no over-reject)",
      (b.db.from("notes").where({ _id: "n1" }).first() || {}).body === "hi");
  } finally {
    b.compliance.clear();
    b.cryptoField.clearResidencyForTest();
    b.db.close();
    fs.rmSync(tmp, { recursive: true, force: true });
    b.audit._resetForTest();
    b.db._resetForTest();
    b.vault._resetForTest();
    b.cluster._resetForTest();
  }
  console.log("OK — db raw-path residency gate tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
