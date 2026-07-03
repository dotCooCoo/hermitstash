// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = require("../../");

function _captureCtx(env) {
  var stdout = [];
  var stderr = [];
  return {
    stdout: { write: function (s) { stdout.push(String(s)); } },
    stderr: { write: function (s) { stderr.push(String(s)); } },
    env:    env || {},
    cwd:    process.cwd(),
    out:    function () { return stdout.join(""); },
    err:    function () { return stderr.join(""); },
  };
}

function run() {
  // ---- makeReporter contract ----
  var ctx = _captureCtx();
  var report = b.cliHelpers.makeReporter(ctx, "blamejs my-tool issue");

  check("ok(message): writes to stdout, returns 0",
        report.ok("done") === 0 && /^done\n$/.test(ctx.out()));

  ctx = _captureCtx();
  report = b.cliHelpers.makeReporter(ctx, "blamejs my-tool issue");
  check("ok(undefined): returns 0, writes nothing",
        report.ok() === 0 && ctx.out() === "");

  ctx = _captureCtx();
  report = b.cliHelpers.makeReporter(ctx, "blamejs my-tool issue");
  check("error(message): writes prefix + message to stderr, returns 1",
        report.error("kaboom") === 1 &&
        /^blamejs my-tool issue: kaboom\n$/.test(ctx.err()));

  ctx = _captureCtx();
  report = b.cliHelpers.makeReporter(ctx, "blamejs my-tool issue");
  check("error(message, 2): returns custom exit code",
        report.error("missing arg", 2) === 2);

  ctx = _captureCtx();
  report = b.cliHelpers.makeReporter(ctx, "blamejs my-tool issue");
  check("usage(USAGE): writes to stderr, returns 2",
        report.usage("Usage: blamejs my-tool ...") === 2 &&
        /^Usage: blamejs my-tool \.\.\.\n$/.test(ctx.err()));

  ctx = _captureCtx();
  report = b.cliHelpers.makeReporter(ctx, "blamejs my-tool issue");
  check("helpStdout(USAGE): writes to stdout, returns 0",
        report.helpStdout("Usage: ...") === 0 && /^Usage: \.\.\.\n$/.test(ctx.out()));

  // ---- makeReporter validation ----
  var threwOnNoCtx = null;
  try { b.cliHelpers.makeReporter(null, "x"); }
  catch (e) { threwOnNoCtx = e; }
  check("makeReporter: throws when ctx is missing",
        !!threwOnNoCtx && /ctx is required/.test(threwOnNoCtx.message));

  var threwOnNoPrefix = null;
  try { b.cliHelpers.makeReporter({}, ""); }
  catch (e) { threwOnNoPrefix = e; }
  check("makeReporter: throws when prefix is empty",
        !!threwOnNoPrefix && /prefix is required/.test(threwOnNoPrefix.message));

  // ---- resolvePassphrase ----
  var fromFlag = b.cliHelpers.resolvePassphrase(
    { flags: { passphrase: "from-flag" } },
    _captureCtx({ MY_PP: "from-env" }),
    { flag: "passphrase", envVar: "MY_PP" });
  check("resolvePassphrase: --flag wins",
        Buffer.isBuffer(fromFlag) && fromFlag.toString("utf8") === "from-flag");

  var fromEnv = b.cliHelpers.resolvePassphrase(
    { flags: {} },
    _captureCtx({ MY_PP: "from-env" }),
    { flag: "passphrase", envVar: "MY_PP" });
  check("resolvePassphrase: env-var fallback",
        Buffer.isBuffer(fromEnv) && fromEnv.toString("utf8") === "from-env");

  var nullPp = b.cliHelpers.resolvePassphrase(
    { flags: {} },
    _captureCtx({}),
    { flag: "passphrase", envVar: "MY_PP" });
  check("resolvePassphrase: returns null when neither source set",
        nullPp === null);

  var threwOnUnknownKey = null;
  try {
    b.cliHelpers.resolvePassphrase(
      { flags: {} }, _captureCtx({}),
      { flag: "p", envVar: "E", typo: true });
  } catch (e) { threwOnUnknownKey = e; }
  check("resolvePassphrase: validateOpts catches typo'd key",
        !!threwOnUnknownKey && /unknown option 'typo'/.test(threwOnUnknownKey.message));

  var threwOnNoFlag = null;
  try {
    b.cliHelpers.resolvePassphrase({ flags: {} }, _captureCtx({}), { flag: "" });
  } catch (e) { threwOnNoFlag = e; }
  check("resolvePassphrase: throws when opts.flag missing",
        !!threwOnNoFlag && /opts\.flag is required/.test(threwOnNoFlag.message));

  // ---- bootApp validation (without actually booting; that's covered by
  //      cli-vault, cli-backup, cli-api-key tests) ----
  var threwBootUnknownKey = null;
  return b.cliHelpers.bootApp({ dataDir: "/tmp/x", typo: true }).then(
    function () { /* should not resolve */ },
    function (e) { threwBootUnknownKey = e; }
  ).then(function () {
    check("bootApp: validateOpts catches typo'd key at boot",
          !!threwBootUnknownKey && /unknown option 'typo'/.test(threwBootUnknownKey.message));

    var threwBootBadMode = null;
    return b.cliHelpers.bootApp({ dataDir: "/tmp/x", vaultMode: "yolo" }).then(
      function () {},
      function (e) { threwBootBadMode = e; }
    ).then(function () {
      check("bootApp: vaultMode must be 'wrapped' or 'plaintext'",
            !!threwBootBadMode && /vaultMode must be/.test(threwBootBadMode.message));

      var threwBootNoPP = null;
      return b.cliHelpers.bootApp({
        dataDir: "/tmp/x", vaultMode: "wrapped", env: {},
      }).then(
        function () {},
        function (e) { threwBootNoPP = e; }
      ).then(function () {
        check("bootApp: wrapped mode demands BLAMEJS_VAULT_PASSPHRASE",
              !!threwBootNoPP && /BLAMEJS_VAULT_PASSPHRASE/.test(threwBootNoPP.message));
      });
    });
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
