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
  // ---- help via the long --help flag ----
  var ctxHelp = _captureCtx();
  var rcHelp = await cli.main(["erase", "--help"], ctxHelp);
  check("help: exit 0",                            rcHelp === 0);
  check("help: mentions GDPR Art. 17",             /GDPR Art\. 17/.test(ctxHelp.out()));

  // ---- arg validation: --confirm required ----
  var dataDir = _tmpDir("blamejs-cli-erase");
  var ctxNoConfirm = _captureCtx();
  var rcNoConfirm = await cli.main(
    ["erase", "--data-dir", dataDir, "--table", "users", "--row-id", "u-1",
     "--vault-mode", "plaintext"], ctxNoConfirm);
  check("erase without --confirm: exit 2",         rcNoConfirm === 2);
  check("erase without --confirm: error mentions confirm",
        /--confirm/.test(ctxNoConfirm.err()));

  // ---- arg validation: --table required ----
  var ctxNoTable = _captureCtx();
  var rcNoTable = await cli.main(
    ["erase", "--data-dir", dataDir, "--row-id", "u-1", "--confirm",
     "--vault-mode", "plaintext"], ctxNoTable);
  check("erase without --table: exit 2",           rcNoTable === 2);

  // ---- arg validation: --row-id required ----
  var ctxNoRow = _captureCtx();
  var rcNoRow = await cli.main(
    ["erase", "--data-dir", dataDir, "--table", "users", "--confirm",
     "--vault-mode", "plaintext"], ctxNoRow);
  check("erase without --row-id: exit 2",          rcNoRow === 2);

  // ---- arg validation: bad --table identifier rejected ----
  var ctxBadTable = _captureCtx();
  var rcBadTable = await cli.main(
    ["erase", "--data-dir", dataDir, "--table", "users; DROP",
     "--row-id", "u-1", "--confirm", "--vault-mode", "plaintext"], ctxBadTable);
  check("erase bad --table identifier: non-zero exit", rcBadTable !== 0);

  // ---- cleanup ----
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) {}
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cli-erase] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
