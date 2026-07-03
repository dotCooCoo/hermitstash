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
  var dataDir = _tmpDir("blamejs-cli-apikey");

  // Common base flags for every issue/list/verify/revoke against this
  // CLI-bootstrapped data dir. plaintext vault keeps the test
  // self-contained (no BLAMEJS_VAULT_PASSPHRASE setup); the CLI will
  // generate the keypair on first boot.
  var base = ["--data-dir", dataDir, "--vault-mode", "plaintext", "--namespace", "api"];

  // ---- arg validation up front ----
  var ctxA = _captureCtx();
  var cA = await cli.main(["api-key"], ctxA);
  check("no subcommand: usage on stderr, returns 2",
        cA === 2 && /Usage: blamejs api-key/.test(ctxA.err()));

  var ctxB = _captureCtx();
  var cB = await cli.main(["api-key", "frobnicate"], ctxB);
  check("unknown subcommand: returns 2",
        cB === 2 && /unknown subcommand/.test(ctxB.err()));

  var ctxC = _captureCtx();
  var cC = await cli.main(["help", "api-key"], ctxC);
  check("help api-key: prints API_KEY_USAGE",
        cC === 0 && /Usage: blamejs api-key/.test(ctxC.out()));

  var ctxD = _captureCtx();
  var cD = await cli.main(["api-key", "issue"], ctxD);
  check("issue without --data-dir: returns 2",
        cD === 2 && /--data-dir/.test(ctxD.err()));

  // ---- issue ----
  var ctx1 = _captureCtx();
  var c1 = await cli.main(
    ["api-key", "issue"].concat(base).concat([
      "--owner-id", "alice", "--scopes", "users:read,users:write",
    ]),
    ctx1);
  check("issue: returns 0",                      c1 === 0);
  check("issue: prints id line",                 /^id:\s+[a-f0-9]+/m.test(ctx1.out()));
  check("issue: prints key line with bk_ prefix", /^key:\s+bk_api_[a-f0-9]+_[a-f0-9]+/m.test(ctx1.out()));
  check("issue: prints scopes line",             /^scopes:\s+users:read, users:write/m.test(ctx1.out()));
  check("issue: warns plaintext-once",            /shown ONCE/.test(ctx1.out()));

  // Pull id + key out of the issue stdout for downstream subtests.
  var idMatch  = ctx1.out().match(/^id:\s+([a-f0-9]+)/m);
  var keyMatch = ctx1.out().match(/^key:\s+(bk_api_[a-f0-9]+_[a-f0-9]+)/m);
  var aliceId  = idMatch  ? idMatch[1]  : null;
  var aliceKey = keyMatch ? keyMatch[1] : null;
  check("issue: parsable id captured",  !!aliceId);
  check("issue: parsable key captured", !!aliceKey);
  // revoke takes the bare idHex (matches what `list` prints in the
  // first column).

  // ---- issue with --expires-ms (the flag must actually set the expiry;
  // it was a silent no-op when the CLI passed the wrong opt key) ----
  var futureMs = 4102444800000;   // 2100-01-01T00:00:00Z, absolute unix ms
  var ctxE = _captureCtx();
  var cE = await cli.main(
    ["api-key", "issue"].concat(base).concat([
      "--owner-id", "carol", "--scopes", "users:read", "--expires-ms", String(futureMs),
    ]), ctxE);
  check("issue --expires-ms: returns 0", cE === 0);
  check("issue --expires-ms: prints the expiry line (flag is not a no-op)",
        /^expires:\s+2100-01-01T00:00:00/m.test(ctxE.out()));

  // ---- issue (missing --scopes) ----
  var ctx2 = _captureCtx();
  var c2 = await cli.main(
    ["api-key", "issue"].concat(base).concat(["--owner-id", "bob"]),
    ctx2);
  check("issue without --scopes: returns 2",
        c2 === 2 && /--scopes/.test(ctx2.err()));

  // ---- list ----
  var ctx3 = _captureCtx();
  var c3 = await cli.main(
    ["api-key", "list"].concat(base).concat(["--owner-id", "alice"]),
    ctx3);
  check("list: returns 0",                       c3 === 0);
  check("list: shows alice + 1 active key",       /owner: alice \(1 active keys\)/.test(ctx3.out()));
  check("list: shows the issued id",              ctx3.out().indexOf(aliceId) !== -1);
  check("list: shows the scopes",                 /scopes=\[users:read,users:write\]/.test(ctx3.out()));

  // ---- verify (correct token) ----
  var ctx4 = _captureCtx();
  var c4 = await cli.main(
    ["api-key", "verify"].concat(base).concat(["--token", aliceKey]),
    ctx4);
  check("verify: returns 0 with valid token",    c4 === 0);
  check("verify: surfaces ownerId",               /^ownerId:\s+alice/m.test(ctx4.out()));

  // ---- verify (garbage token) ----
  var ctx5 = _captureCtx();
  var c5 = await cli.main(
    ["api-key", "verify"].concat(base).concat(["--token", "not-a-real-token"]),
    ctx5);
  check("verify: rejects garbage with non-zero",  c5 !== 0);
  check("verify: announces rejected on stderr",    /rejected:/.test(ctx5.err()));

  // ---- revoke ----
  var ctx6 = _captureCtx();
  var c6 = await cli.main(
    ["api-key", "revoke"].concat(base).concat(["--id", aliceId]),
    ctx6);
  check("revoke: returns 0",                     c6 === 0);
  check("revoke: announces the id revoked",      ctx6.out().indexOf(aliceId) !== -1);

  // ---- verify after revoke ----
  var ctx7 = _captureCtx();
  var c7 = await cli.main(
    ["api-key", "verify"].concat(base).concat(["--token", aliceKey]),
    ctx7);
  check("verify: rejects revoked token",          c7 !== 0);

  // ---- revoke (missing --id) ----
  var ctx8 = _captureCtx();
  var c8 = await cli.main(
    ["api-key", "revoke"].concat(base),
    ctx8);
  check("revoke without --id: returns 2",
        c8 === 2 && /--id/.test(ctx8.err()));

  fs.rmSync(dataDir, { recursive: true, force: true });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
