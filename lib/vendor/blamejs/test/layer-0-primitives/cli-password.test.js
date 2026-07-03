// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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

async function run() {
  // ---- help ----
  var ctxHelp = _captureCtx();
  var rcHelp = await cli.main(["password", "--help"], ctxHelp);
  check("help: exit 0",                       rcHelp === 0);
  check("help: lists check + profiles",       /check/.test(ctxHelp.out()) && /pci-4\.0/.test(ctxHelp.out()));

  // ---- check: rejects common password ----
  var ctxBad = _captureCtx();
  var rcBad = await cli.main(["password", "check", "--plaintext", "password"], ctxBad);
  check("check 'password': exit 1",           rcBad === 1);
  check("check 'password': REJECTED + code",  /REJECTED:\s+policy\/forbidden-common/.test(ctxBad.out()));

  // ---- check: too-short rejected ----
  var ctxShort = _captureCtx();
  var rcShort = await cli.main(["password", "check", "--plaintext", "abc"], ctxShort);
  check("check 'abc': exit 1",                rcShort === 1);
  check("check 'abc': too-short code",        /policy\/too-short/.test(ctxShort.out()));

  // ---- check: respects --min-length override ----
  var ctxMin = _captureCtx();
  var rcMin = await cli.main(
    ["password", "check", "--plaintext", "0123456789ab", "--min-length", "16"], ctxMin);
  check("check with --min-length 16: exit 1", rcMin === 1);
  check("check with --min-length 16: too-short code", /policy\/too-short/.test(ctxMin.out()));

  // ---- check: passes a strong unique password ----
  var ctxOk = _captureCtx();
  var rcOk = await cli.main(
    ["password", "check", "--plaintext", "horse-staple-correct-battery-9281!"], ctxOk);
  check("check strong: exit 0",               rcOk === 0);
  check("check strong: prints 'ok'",          /\bok\b/.test(ctxOk.out()));

  // ---- check: context substring rejection ----
  var ctxCtx = _captureCtx();
  var rcCtx = await cli.main(
    ["password", "check", "--plaintext", "alice-loves-cats-9281!", "--username", "alice"], ctxCtx);
  check("check with context.username match: exit 1", rcCtx === 1);
  check("check with context.username match: contains-context code",
        /policy\/contains-context/.test(ctxCtx.out()));

  // ---- check: --json output is valid JSON ----
  var ctxJson = _captureCtx();
  var rcJson = await cli.main(
    ["password", "check", "--plaintext", "password", "--json"], ctxJson);
  check("check --json: exit 1",               rcJson === 1);
  var parsed = null;
  try { parsed = JSON.parse(ctxJson.out().trim()); }
  catch (_e) { /* leave null */ }
  check("check --json: valid JSON",           parsed !== null && parsed.ok === false);
  check("check --json: includes code",        parsed && /policy\/forbidden-common/.test(parsed.code));

  // ---- check: --profile pci-4.0 enforces 12-char minimum ----
  var ctxPci = _captureCtx();
  var rcPci = await cli.main(
    ["password", "check", "--plaintext", "Sh0rt-pass!", "--profile", "pci-4.0"], ctxPci);
  check("check pci-4.0 short: exit 1",        rcPci === 1);
  check("check pci-4.0 short: too-short",     /policy\/too-short/.test(ctxPci.out()));

  // ---- check: missing --plaintext returns 2 ----
  var ctxMissing = _captureCtx();
  var rcMissing = await cli.main(["password", "check"], ctxMissing);
  check("check missing --plaintext → exit 2", rcMissing === 2);

  // ---- unknown subcommand ----
  var ctxUnk = _captureCtx();
  var rcUnk = await cli.main(["password", "audit"], ctxUnk);
  check("unknown subcommand → exit 2",        rcUnk === 2);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cli-password] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
