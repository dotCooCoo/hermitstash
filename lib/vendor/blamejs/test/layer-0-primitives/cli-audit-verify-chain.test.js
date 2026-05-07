"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var sqlite = require("node:sqlite");
var helpers = require("../helpers");
var check = helpers.check;
var cli = require("../../lib/cli");

function _tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

function _captureCtx() {
  var stdout = [];
  var stderr = [];
  return {
    stdout: { write: function (s) { stdout.push(String(s)); } },
    stderr: { write: function (s) { stderr.push(String(s)); } },
    env:    {},
    cwd:    process.cwd(),
    out:    function () { return stdout.join(""); },
    err:    function () { return stderr.join(""); },
  };
}

function _createAuditTable(dbPath, tableName) {
  var db = new sqlite.DatabaseSync(dbPath);
  // Minimal columns verifyChain reads from `SELECT *` on an empty table.
  // The empty-rows path returns ok=true without inspecting the columns,
  // so this is enough for the CLI surface tests.
  db.prepare("CREATE TABLE " + tableName + " (" +
    " _id INTEGER PRIMARY KEY," +
    " monotonicCounter INTEGER," +
    " prevHash TEXT," +
    " rowHash  TEXT," +
    " nonce    BLOB" +
    ")").run();
  db.close();
}

async function run() {
  // ---- empty audit_log: chain trivially verifies ----
  var dir = _tmpDir("blamejs-cli-verify-chain");
  var dbPath = path.join(dir, "blamejs.db");
  _createAuditTable(dbPath, "audit_log");

  var ctx1 = _captureCtx();
  var c1 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath], ctx1);
  check("verify-chain: exits 0 on empty audit_log", c1 === 0);
  check("verify-chain: announces rowsVerified=0",
        /rowsVerified=0/.test(ctx1.out()));
  check("verify-chain: announces table=audit_log",
        /table=audit_log/.test(ctx1.out()));

  // ---- arg validation ----
  var ctx2 = _captureCtx();
  var c2 = await cli.main(["audit", "verify-chain"], ctx2);
  check("verify-chain: missing --db returns 2",
        c2 === 2 && /--db/.test(ctx2.err()));

  var ctx3 = _captureCtx();
  var c3 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath, "--max-rows", "0"], ctx3);
  check("verify-chain: --max-rows=0 returns 2",
        c3 === 2 && /max-rows/.test(ctx3.err()));

  var ctx4 = _captureCtx();
  var c4 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath, "--max-rows", "abc"], ctx4);
  check("verify-chain: --max-rows non-numeric returns 2",
        c4 === 2 && /max-rows/.test(ctx4.err()));

  // ---- bad db path ----
  var ctx5 = _captureCtx();
  var c5 = await cli.main(
    ["audit", "verify-chain", "--db",
     path.join(dir, "no-such-dir", "missing.db")], ctx5);
  check("verify-chain: bad db path returns 1",
        c5 === 1 && /cannot open db/.test(ctx5.err()));

  // ---- custom --table ----
  var dbPath2 = path.join(dir, "alt.db");
  _createAuditTable(dbPath2, "audit_consent");
  var ctx6 = _captureCtx();
  var c6 = await cli.main(
    ["audit", "verify-chain", "--db", dbPath2, "--table", "audit_consent"], ctx6);
  check("verify-chain: --table picks alternate audit table",
        c6 === 0 && /table=audit_consent/.test(ctx6.out()));

  // ---- cleanup ----
  fs.rmSync(dir, { recursive: true, force: true });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
