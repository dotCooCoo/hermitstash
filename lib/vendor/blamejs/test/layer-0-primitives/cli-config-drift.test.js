// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
  var rcHelp = await cli.main(["config-drift", "--help"], ctxHelp);
  check("help: exit 0",                              rcHelp === 0);
  check("help: lists inspect + verify subcommands", /inspect/.test(ctxHelp.out()) && /verify/.test(ctxHelp.out()));

  // ---- inspect / verify against an empty data dir (no sidecar) ----
  var dataDir = _tmpDir("blamejs-cli-config-drift");
  var ctxNone = _captureCtx();
  var rcNone = await cli.main(
    ["config-drift", "inspect", "--data-dir", dataDir, "--vault-mode", "plaintext"], ctxNone);
  check("inspect no sidecar: exit 0",                rcNone === 0);
  check("inspect no sidecar: reports absence",       /no sidecar present/.test(ctxNone.out()));

  var ctxVerifyNone = _captureCtx();
  var rcVerifyNone = await cli.main(
    ["config-drift", "verify", "--data-dir", dataDir, "--vault-mode", "plaintext"], ctxVerifyNone);
  check("verify no sidecar: exit 1",                 rcVerifyNone === 1);

  // ---- unknown subcommand ----
  var ctxBad = _captureCtx();
  var rcBad = await cli.main(["config-drift", "scan"], ctxBad);
  check("unknown subcommand → exit 2",              rcBad === 2);

  // ---- missing --data-dir ----
  var ctxNoDir = _captureCtx();
  var rcNoDir = await cli.main(["config-drift", "inspect"], ctxNoDir);
  check("inspect without --data-dir: exit 2",        rcNoDir === 2);

  // ---- cleanup ----
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) {}
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cli-config-drift] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
