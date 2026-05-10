"use strict";
/**
 * b.localDb.thin — lightweight node:sqlite wrapper for desktop daemons.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;

async function run() {
  // ---- _validateOpts ----
  var threw;
  try { b.localDb.thin(); } catch (e) { threw = e; }
  check("localDb.thin: missing opts throws",
    threw && threw.code === "localdb-thin/bad-opts" &&
    threw instanceof b.frameworkError.LocalDbThinError);

  threw = null;
  try { b.localDb.thin({ schemaSql: "CREATE TABLE x(id INTEGER)" }); } catch (e) { threw = e; }
  check("localDb.thin: missing file throws",
    threw && threw.code === "localdb-thin/bad-file");

  threw = null;
  try { b.localDb.thin({ file: "x.db" }); } catch (e) { threw = e; }
  check("localDb.thin: missing schemaSql throws",
    threw && threw.code === "localdb-thin/bad-schema-sql");

  threw = null;
  try { b.localDb.thin({ file: "x.db", schemaSql: "S", recovery: "wat" }); } catch (e) { threw = e; }
  check("localDb.thin: bad recovery throws",
    threw && threw.code === "localdb-thin/bad-recovery");

  threw = null;
  try { b.localDb.thin({ file: "x.db", schemaSql: "S", pragmas: [] }); } catch (e) { threw = e; }
  check("localDb.thin: array pragmas throws",
    threw && threw.code === "localdb-thin/bad-pragmas");

  // ---- happy path: open / schema / prepare-cache / run / query / close ----
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-localdb-"));
  var dbPath = path.join(tmpDir, "thin.db");
  try {
    var handle = b.localDb.thin({
      file:      dbPath,
      schemaSql: "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);",
      audit:     false,
    });
    check("localDb.thin: returns operator surface",
      typeof handle.prepare === "function" &&
      typeof handle.run === "function" &&
      typeof handle.query === "function" &&
      typeof handle.close === "function" &&
      handle.file === dbPath);

    handle.run("INSERT INTO notes (body) VALUES (?)", "alpha");
    handle.run("INSERT INTO notes (body) VALUES (?)", "beta");
    var rows = handle.query("SELECT body FROM notes ORDER BY id");
    check("localDb.thin: run + query round-trip",
      rows.length === 2 && rows[0].body === "alpha" && rows[1].body === "beta");

    // Prepared-statement cache: same SQL string returns same prepared
    // handle on second prepare().
    var s1 = handle.prepare("SELECT 1 AS v");
    var s2 = handle.prepare("SELECT 1 AS v");
    check("localDb.thin: prepare cache returns same handle", s1 === s2);

    // WAL mode is enforced.
    var modeRow = handle.db.prepare("PRAGMA journal_mode").get();
    check("localDb.thin: PRAGMA journal_mode=WAL",
      modeRow && String(modeRow.journal_mode).toLowerCase() === "wal");

    handle.close();

    // After close, prepare/run/query must throw.
    threw = null;
    try { handle.run("SELECT 1"); } catch (e) { threw = e; }
    check("localDb.thin: post-close run throws",
      threw && threw.code === "localdb-thin/closed");

    // Idempotent close.
    handle.close();
    check("localDb.thin: close() idempotent", true);

    // ---- recovery: refuse vs rename-and-recreate ----
    // Corrupt the file in place.
    fs.writeFileSync(dbPath, "this-is-not-a-sqlite-file");
    threw = null;
    try {
      b.localDb.thin({
        file:      dbPath,
        schemaSql: "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY);",
        audit:     false,
      });
    } catch (e) { threw = e; }
    check("localDb.thin: refuse on corrupt (default) throws",
      threw && threw.code === "localdb-thin/corrupt");

    // Now with rename-and-recreate it must auto-recover.
    var recovered = b.localDb.thin({
      file:      dbPath,
      schemaSql: "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);",
      recovery:  "rename-and-recreate",
      audit:     false,
    });
    check("localDb.thin: rename-and-recreate recovers",
      recovered.recovered === true && typeof recovered.recoveredTo === "string");

    // The renamed-aside file exists on disk.
    check("localDb.thin: corrupt file is renamed aside",
      fs.existsSync(recovered.recoveredTo));

    // The fresh DB is usable.
    recovered.run("INSERT INTO notes (body) VALUES (?)", "fresh");
    var freshRows = recovered.query("SELECT body FROM notes");
    check("localDb.thin: fresh DB usable after recovery",
      freshRows.length === 1 && freshRows[0].body === "fresh");

    recovered.close();

    // ---- pragma allowlist: bad name rejected ----
    threw = null;
    try {
      b.localDb.thin({
        file:      path.join(tmpDir, "p.db"),
        schemaSql: "CREATE TABLE x(id INTEGER);",
        pragmas:   { "drop-table": "ON" },
        audit:     false,
      });
    } catch (e) { threw = e; }
    check("localDb.thin: bad pragma name rejected",
      threw && threw.code === "localdb-thin/bad-pragma-name");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }

  check("localDb.LocalDbThinError class registered",
    typeof b.localDb.LocalDbThinError === "function" &&
    b.localDb.LocalDbThinError === b.frameworkError.LocalDbThinError);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[local-db-thin] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
