// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Coverage for lib/cli.js branches not exercised by the per-command
// cli-*.test.js files or test/00-primitives.js:
//   - the `seed` subcommand (arg validation + a local-sqlite status run)
//   - `dev --grace-ms` numeric validation
//   - `api-snapshot` operator-supplied `--module` (capture + compare
//     failure paths)
//   - top-level `--help` / `-h` routing + unknown help topic fall-through
// Everything drives the public b.cli.main(argv, ctx) surface with a
// captured-output ctx; nothing here needs a live network/db backend
// (the sqlite handle is a local temp file, same shape the existing
// cli-audit-verify-chain / migrate tests use).

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var cli = require("../../lib/cli");

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

function _tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

async function run() {
  var dir = _tmpDir("blamejs-cli-coverage");
  try {
    // =====================================================================
    // seed — arg validation
    // =====================================================================

    // bare `seed` (no subcommand) → usage on stderr, exit 2
    var cBare = _captureCtx();
    var rcBare = await cli.main(["seed"], cBare);
    check("seed: bare → exit 2",                rcBare === 2);
    check("seed: bare → usage on stderr",       /Usage: blamejs seed/.test(cBare.err()));

    // `seed help` → usage on stdout, exit 0
    var cHelp = _captureCtx();
    var rcHelp = await cli.main(["seed", "help"], cHelp);
    check("seed help: exit 0",                  rcHelp === 0);
    check("seed help: usage on stdout",         /Usage: blamejs seed/.test(cHelp.out()));
    check("seed help: lists run + status",      /\brun\b/.test(cHelp.out()) && /\bstatus\b/.test(cHelp.out()));

    // `help seed` (top-level help dispatch → SEED_USAGE)
    var cTopHelpSeed = _captureCtx();
    var rcTopHelpSeed = await cli.main(["help", "seed"], cTopHelpSeed);
    check("help seed: exit 0",                  rcTopHelpSeed === 0);
    check("help seed: prints SEED_USAGE",       /Usage: blamejs seed/.test(cTopHelpSeed.out()));

    // unknown subcommand → exit 2 + usage
    var cUnk = _captureCtx();
    var rcUnk = await cli.main(["seed", "frobnicate"], cUnk);
    check("seed unknown sub: exit 2",           rcUnk === 2);
    check("seed unknown sub: names the sub",    /unknown subcommand 'frobnicate'/.test(cUnk.err()));

    // run without --db → exit 2
    var cNoDb = _captureCtx();
    var rcNoDb = await cli.main(["seed", "run"], cNoDb);
    check("seed run: missing --db → exit 2",    rcNoDb === 2);
    check("seed run: missing --db message",     /--db <path> is required/.test(cNoDb.err()));

    // --db present but bare (boolean flag, no value) → treated as missing
    var cDbBool = _captureCtx();
    var rcDbBool = await cli.main(["seed", "run", "--db"], cDbBool);
    check("seed run: --db with no value → exit 2", rcDbBool === 2);
    check("seed run: --db no value message",       /--db <path> is required/.test(cDbBool.err()));

    // --db present, --env missing → exit 2
    var dbPath = path.join(dir, "seed.db");
    var cNoEnv = _captureCtx();
    var rcNoEnv = await cli.main(["seed", "status", "--db", dbPath], cNoEnv);
    check("seed status: missing --env → exit 2", rcNoEnv === 2);
    check("seed status: missing --env message",  /--env <name> is required/.test(cNoEnv.err()));

    // bad db path (parent dir doesn't exist) → cannot open db, exit 1
    var cBadDb = _captureCtx();
    var rcBadDb = await cli.main(
      ["seed", "status", "--db", path.join(dir, "no-such-dir", "x.db"), "--env", "dev"],
      cBadDb);
    check("seed status: unopenable db → exit 1", rcBadDb === 1);
    check("seed status: cannot-open message",    /cannot open db/.test(cBadDb.err()));

    // =====================================================================
    // seed — status happy path against a local sqlite file + empty dir
    // =====================================================================
    var seedersDir = path.join(dir, "seeders-empty");
    var cStatus = _captureCtx();
    var rcStatus = await cli.main(
      ["seed", "status", "--db", dbPath, "--env", "dev", "--dir", seedersDir],
      cStatus);
    check("seed status: empty dir → exit 0",     rcStatus === 0);
    check("seed status: prints env line",        /env: dev/.test(cStatus.out()));
    check("seed status: 0 applied of 0 total",   /applied: 0 \/ 0/.test(cStatus.out()));
    check("seed status: 0 pending",              /pending: 0/.test(cStatus.out()));

    // =====================================================================
    // dev — --grace-ms numeric validation (returns before spawning a child)
    // =====================================================================
    var cGraceNeg = _captureCtx();
    var rcGraceNeg = await cli.main(
      ["dev", "--command", "node", "--grace-ms", "-5"], cGraceNeg);
    check("dev --grace-ms negative → exit 2",    rcGraceNeg === 2);
    check("dev --grace-ms negative message",     /--grace-ms must be a non-negative number/.test(cGraceNeg.err()));

    var cGraceNaN = _captureCtx();
    var rcGraceNaN = await cli.main(
      ["dev", "--command", "node", "--grace-ms", "not-a-number"], cGraceNaN);
    check("dev --grace-ms non-numeric → exit 2", rcGraceNaN === 2);
    check("dev --grace-ms non-numeric message",  /--grace-ms must be a non-negative number/.test(cGraceNaN.err()));

    // missing --command still exits 2 (guards the `dev` entry independent
    // of the grace-ms path above)
    var cDevNoCmd = _captureCtx();
    var rcDevNoCmd = await cli.main(["dev"], cDevNoCmd);
    check("dev: missing --command → exit 2",     rcDevNoCmd === 2);
    check("dev: missing --command message",      /--command <cmd> is required/.test(cDevNoCmd.err()));

    // =====================================================================
    // dev — --ignore pattern refusal takes the standard exit-2 + stderr
    // path, never rejects main(). An over-length pattern, a ReDoS-shape
    // pattern guardRegex refuses, and a pattern RegExp() can't compile are
    // all operator-input validation failures: they must return exit 2 like
    // every other dev validation, not reject the awaited promise (which the
    // bin shim would surface as a stack-trace + exit 1).
    // =====================================================================
    async function _devIgnore(pattern) {
      var c = _captureCtx();
      var rejected = false;
      var rc;
      try {
        rc = await cli.main(["dev", "--command", "node", "--ignore", pattern], c);
      } catch (_e) {
        rejected = true;
      }
      return { rc: rc, rejected: rejected, err: c.err() };
    }

    var igLong = await _devIgnore("a".repeat(300));
    check("dev --ignore over-length → never rejects main()", igLong.rejected === false);
    check("dev --ignore over-length → exit 2",               igLong.rc === 2);
    check("dev --ignore over-length message",                /exceeds max length/.test(igLong.err));

    var igReDoS = await _devIgnore("(a+)+$");
    check("dev --ignore ReDoS-shape → never rejects main()", igReDoS.rejected === false);
    check("dev --ignore ReDoS-shape → exit 2",               igReDoS.rc === 2);
    check("dev --ignore ReDoS-shape message",                /refused by guardRegex/.test(igReDoS.err));

    var igBadRe = await _devIgnore("(");
    check("dev --ignore uncompilable → never rejects main()", igBadRe.rejected === false);
    check("dev --ignore uncompilable → exit 2",               igBadRe.rc === 2);
    check("dev --ignore uncompilable message",                /--ignore pattern/.test(igBadRe.err));

    // =====================================================================
    // api-snapshot — operator-supplied --module
    // =====================================================================

    // capture from a non-existent module → cannot load, exit 1
    var cModBad = _captureCtx();
    var rcModBad = await cli.main(
      ["api-snapshot", "capture", "--module", path.join(dir, "no-module.js")], cModBad);
    check("api-snapshot capture bad --module → exit 1", rcModBad === 1);
    check("api-snapshot capture bad --module message",
          /cannot load module/.test(cModBad.err()));

    // capture from a valid operator module → wrote snapshot, exit 0
    var customMod = path.join(dir, "custom-mod.js");
    fs.writeFileSync(customMod,
      "module.exports = { version: \"9.9.9\", greet: function greet() {} };");
    var customSnap = path.join(dir, "custom-snap.json");
    var cModOk = _captureCtx();
    var rcModOk = await cli.main(
      ["api-snapshot", "capture", "--file", customSnap, "--module", customMod], cModOk);
    check("api-snapshot capture custom --module → exit 0", rcModOk === 0);
    check("api-snapshot capture custom --module wrote file", fs.existsSync(customSnap));
    check("api-snapshot capture custom --module reports version",
          /frameworkVersion 9\.9\.9/.test(cModOk.out()));

    // compare where the saved snapshot reads fine but capturing the CURRENT
    // surface fails (bad --module) → "cannot capture current surface", exit 1
    var cCmpBad = _captureCtx();
    var rcCmpBad = await cli.main(
      ["api-snapshot", "compare", "--file", customSnap, "--module", path.join(dir, "gone.js")],
      cCmpBad);
    check("api-snapshot compare uncapturable current → exit 1", rcCmpBad === 1);
    check("api-snapshot compare uncapturable current message",
          /cannot capture current surface/.test(cCmpBad.err()));

    // =====================================================================
    // top-level dispatch — help routing edges
    // =====================================================================

    // `<cmd> --help` synthesizes `help <cmd>` → that command's usage
    var cMigHelp = _captureCtx();
    var rcMigHelp = await cli.main(["migrate", "--help"], cMigHelp);
    check("migrate --help → exit 0",             rcMigHelp === 0);
    check("migrate --help prints migrate usage", /Usage: blamejs migrate/.test(cMigHelp.out()));

    // `-h` short flag takes the same route
    var cMigH = _captureCtx();
    var rcMigH = await cli.main(["migrate", "-h"], cMigH);
    check("migrate -h → exit 0",                 rcMigH === 0);
    check("migrate -h prints migrate usage",     /Usage: blamejs migrate/.test(cMigH.out()));

    // `help <unknown-topic>` falls through to the top-level usage
    var cBogus = _captureCtx();
    var rcBogus = await cli.main(["help", "totally-bogus-topic"], cBogus);
    check("help unknown-topic → exit 0",         rcBogus === 0);
    check("help unknown-topic prints top usage", /blamejs <command>/.test(cBogus.out()));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
