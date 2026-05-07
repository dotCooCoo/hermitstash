"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var cli = require("../../lib/cli");

function _tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

function _captureCtx() {
  var stdout = [], stderr = [];
  return {
    stdout: { write: function (s) { stdout.push(String(s)); } },
    stderr: { write: function (s) { stderr.push(String(s)); } },
    env:    Object.assign({}, process.env),
    cwd:    process.cwd(),
    out:    function () { return stdout.join(""); },
    err:    function () { return stderr.join(""); },
  };
}

async function run() {
  // ---- help ----
  var ctxHelp = _captureCtx();
  var rcHelp = await cli.main(["security", "--help"], ctxHelp);
  check("help: exit 0",                       rcHelp === 0);
  check("help: lists assert subcommand",      /assert/.test(ctxHelp.out()));

  // ---- assert without --data-dir ----
  var ctxNoDir = _captureCtx();
  var rcNoDir = await cli.main(["security", "assert"], ctxNoDir);
  check("assert without --data-dir: exit 2",  rcNoDir === 2);

  // ---- assert against a plaintext-vault dir: vault posture fails ----
  // Skip NTP / dbAtRest / auditSigning so the only failing assertion
  // is vault-mismatch — keeps the test independent of process.env
  // state that other tests in the suite may set.
  var dataDir = _tmpDir("blamejs-cli-security");
  var ctxFail = _captureCtx();
  var rcFail = await cli.main(
    ["security", "assert", "--data-dir", dataDir, "--vault-mode", "plaintext",
     "--no-audit-signing", "--no-db-at-rest", "--no-ntp-strict"], ctxFail);
  check("assert plaintext vault: exit 1",     rcFail === 1);
  check("assert plaintext vault: FAIL summary printed",
        /FAIL:\s+1 assertion/.test(ctxFail.out()));
  check("assert plaintext vault: vault failure code printed",
        /security\/vault-mismatch/.test(ctxFail.out()));

  // ---- unknown subcommand ----
  var ctxBad = _captureCtx();
  var rcBad = await cli.main(["security", "audit"], ctxBad);
  check("unknown subcommand → exit 2",       rcBad === 2);

  // ---- cleanup ----
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) {}
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cli-security] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
