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
  var dataDir = _tmpDir("blamejs-cli-mtls");
  var base = ["--data-dir", dataDir, "--vault-mode", "plaintext"];

  // ---- arg validation up front ----
  var ctxA = _captureCtx();
  var cA = await cli.main(["mtls"], ctxA);
  check("no subcommand: usage on stderr, returns 2",
        cA === 2 && /Usage: blamejs mtls/.test(ctxA.err()));

  var ctxB = _captureCtx();
  var cB = await cli.main(["mtls", "frobnicate"], ctxB);
  check("unknown subcommand: returns 2",
        cB === 2 && /unknown subcommand/.test(ctxB.err()));

  var ctxC = _captureCtx();
  var cC = await cli.main(["help", "mtls"], ctxC);
  check("help mtls: prints MTLS_USAGE",
        cC === 0 && /Usage: blamejs mtls/.test(ctxC.out()));

  var ctxD = _captureCtx();
  var cD = await cli.main(["mtls", "status"], ctxD);
  check("status without --data-dir: returns 2",
        cD === 2 && /--data-dir/.test(ctxD.err()));

  // ---- status against a fresh data-dir (no CA on disk) ----
  var ctx1 = _captureCtx();
  var c1 = await cli.main(["mtls", "status"].concat(base), ctx1);
  check("status (no CA): returns 0",                 c1 === 0);
  check("status (no CA): announces 'CA exists: no'", /CA exists:\s+no/.test(ctx1.out()));
  check("status (no CA): hints at init",             /run 'blamejs mtls init'/.test(ctx1.out()));

  // ---- show-cert against a fresh data-dir errors clearly ----
  var ctx2 = _captureCtx();
  var c2 = await cli.main(["mtls", "show-cert"].concat(base), ctx2);
  check("show-cert (no CA): non-zero",                c2 !== 0);
  check("show-cert (no CA): points at the missing path",
        /no CA on disk/.test(ctx2.err()));

  // ---- init: bundled engine generates a real CA ----
  var ctx3 = _captureCtx();
  var c3 = await cli.main(["mtls", "init"].concat(base), ctx3);
  check("init: returns 0",                            c3 === 0);
  check("init: announces ca-cert path",                /ca-cert:/.test(ctx3.out()));
  check("init: announces ca-key path",                 /ca-key:/.test(ctx3.out()));
  check("init: ca.crt written to data-dir",
        fs.existsSync(path.join(dataDir, "ca.crt")));

  // ---- issue: --subject required ----
  var ctx4 = _captureCtx();
  var c4 = await cli.main(["mtls", "issue"].concat(base), ctx4);
  check("issue without --subject: returns 2",
        c4 === 2 && /--subject/.test(ctx4.err()));

  // ---- issue: bundled engine signs a leaf cert ----
  var ctx5 = _captureCtx();
  var c5 = await cli.main(["mtls", "issue"].concat(base).concat(["--subject", "client-1"]), ctx5);
  check("issue with --subject: returns 0",            c5 === 0);
  check("issue: prints leaf certificate PEM",          /BEGIN CERTIFICATE/.test(ctx5.out()));
  check("issue: prints leaf private key PEM",          /BEGIN PRIVATE KEY/.test(ctx5.out()));

  // ---- issue-p12 demands both --subject and --password ----
  var ctx6 = _captureCtx();
  var c6 = await cli.main(["mtls", "issue-p12"].concat(base).concat(["--subject", "x"]), ctx6);
  check("issue-p12 without --password: returns 2",
        c6 === 2 && /--password/.test(ctx6.err()));

  // ---- issue-p12: bundled engine packages a P12 ----
  var p12Out = path.join(dataDir, "client.p12");
  var ctx6b = _captureCtx();
  var c6b = await cli.main(
    ["mtls", "issue-p12"].concat(base).concat([
      "--subject", "client-2",
      "--password", "p12-passphrase-xyz",
      "--out", p12Out,
    ]), ctx6b);
  check("issue-p12 with --subject + --password + --out: returns 0", c6b === 0);
  check("issue-p12: writes the bundle to --out",                    fs.existsSync(p12Out));
  if (fs.existsSync(p12Out)) {
    var p12Buf = fs.readFileSync(p12Out);
    check("issue-p12: file is a non-trivial ASN.1 SEQUENCE",
          p12Buf.length > 1000 && p12Buf[0] === 0x30);
  }

  // ---- bad --vault-mode ----
  var ctx7 = _captureCtx();
  var c7 = await cli.main(["mtls", "status", "--data-dir", dataDir, "--vault-mode", "yolo"], ctx7);
  check("bad --vault-mode: returns 2",
        c7 === 2 && /--vault-mode/.test(ctx7.err()));

  // ---- bad --sealed-mode ----
  var ctx8 = _captureCtx();
  var c8 = await cli.main(["mtls", "status"].concat(base).concat(["--sealed-mode", "yolo"]), ctx8);
  check("bad --sealed-mode: returns 2",
        c8 === 2 && /--sealed-mode/.test(ctx8.err()));

  fs.rmSync(dataDir, { recursive: true, force: true });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
