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
  var rcHelp = await cli.main(["retention", "--help"], ctxHelp);
  check("help: exit 0",                              rcHelp === 0);
  check("help: lists preview + run subcommands",     /preview/.test(ctxHelp.out()) && /\brun\b/.test(ctxHelp.out()));

  // ---- arg validation ----
  var dataDir = _tmpDir("blamejs-cli-retention");
  var ctxNoTable = _captureCtx();
  var rcNoTable = await cli.main(
    ["retention", "preview", "--data-dir", dataDir, "--age-field", "createdAt",
     "--ttl-ms", "1000", "--vault-mode", "plaintext"], ctxNoTable);
  check("preview without --table: exit 2",           rcNoTable === 2);

  var ctxNoAge = _captureCtx();
  var rcNoAge = await cli.main(
    ["retention", "preview", "--data-dir", dataDir, "--table", "users",
     "--ttl-ms", "1000", "--vault-mode", "plaintext"], ctxNoAge);
  check("preview without --age-field: exit 2",       rcNoAge === 2);

  var ctxBadTtl = _captureCtx();
  var rcBadTtl = await cli.main(
    ["retention", "preview", "--data-dir", dataDir, "--table", "users",
     "--age-field", "createdAt", "--ttl-ms", "-100", "--vault-mode", "plaintext"], ctxBadTtl);
  check("preview with negative --ttl-ms: exit 2",    rcBadTtl === 2);

  var ctxBadAction = _captureCtx();
  var rcBadAction = await cli.main(
    ["retention", "preview", "--data-dir", dataDir, "--table", "users",
     "--age-field", "createdAt", "--ttl-ms", "1000", "--action", "shred",
     "--vault-mode", "plaintext"], ctxBadAction);
  check("preview with invalid --action: exit 2",     rcBadAction === 2);

  var ctxSoftNoField = _captureCtx();
  var rcSoftNoField = await cli.main(
    ["retention", "preview", "--data-dir", dataDir, "--table", "users",
     "--age-field", "createdAt", "--ttl-ms", "1000", "--action", "soft-delete",
     "--vault-mode", "plaintext"], ctxSoftNoField);
  check("preview soft-delete without --soft-delete-field: exit 2",
        rcSoftNoField === 2);

  // ---- unknown subcommand ----
  var ctxBad = _captureCtx();
  var rcBad = await cli.main(["retention", "list"], ctxBad);
  check("unknown subcommand → exit 2",              rcBad === 2);

  // ---- cleanup ----
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) {}
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cli-retention] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
