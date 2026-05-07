"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var cli = require("../../lib/cli");
var vault = require("../../lib/vault");

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

async function _bootPlaintextVault(dataDir) {
  // vault.init has process-level state; reset between subtests so each
  // call against a fresh dataDir generates a fresh vault.key.
  if (typeof vault._resetForTest === "function") vault._resetForTest();
  await vault.init({ dataDir: dataDir, mode: "plaintext" });
  if (typeof vault._resetForTest === "function") vault._resetForTest();
}

async function run() {
  // ---- status: empty dir ----
  var d1 = _tmpDir("blamejs-cli-vault-status");
  fs.mkdirSync(path.join(d1, "data"));
  var ctx1 = _captureCtx();
  var code1 = await cli.main(["vault", "status", "--data-dir", path.join(d1, "data")], ctx1);
  check("status: returns 0 on empty data dir", code1 === 0);
  check("status: reports plaintext absent",
        /vault\.key \(plaintext\):\s+absent/.test(ctx1.out()));
  check("status: reports sealed absent",
        /vault\.key\.sealed \(wrapped\):\s+absent/.test(ctx1.out()));
  fs.rmSync(d1, { recursive: true, force: true });

  // ---- seal round-trip ----
  var d2 = _tmpDir("blamejs-cli-vault-seal");
  var dd2 = path.join(d2, "data");
  fs.mkdirSync(dd2);
  await _bootPlaintextVault(dd2);
  check("plaintext vault.key written by init",
        fs.existsSync(path.join(dd2, "vault.key")));
  var ctx2 = _captureCtx();
  var code2 = await cli.main(
    ["vault", "seal", "--data-dir", dd2, "--passphrase", "test-pass-1"], ctx2);
  check("seal: returns 0",                code2 === 0);
  check("seal: announces sealedPath",     /sealed:\s/.test(ctx2.out()));
  check("seal: removes plaintext file",   !fs.existsSync(path.join(dd2, "vault.key")));
  check("seal: writes sealed file",        fs.existsSync(path.join(dd2, "vault.key.sealed")));

  // ---- unseal ----
  var ctx3 = _captureCtx();
  var code3 = await cli.main(
    ["vault", "unseal", "--data-dir", dd2, "--passphrase", "test-pass-1"], ctx3);
  check("unseal: returns 0",              code3 === 0);
  check("unseal: writes plaintext back",   fs.existsSync(path.join(dd2, "vault.key")));
  check("unseal: WARNING about plaintext", /WARNING:/.test(ctx3.out()));

  // ---- unseal with wrong passphrase fails ----
  fs.unlinkSync(path.join(dd2, "vault.key"));
  var ctx4 = _captureCtx();
  var code4 = await cli.main(
    ["vault", "unseal", "--data-dir", dd2, "--passphrase", "wrong-pass"], ctx4);
  check("unseal: wrong passphrase exits non-zero", code4 !== 0);
  check("unseal: wrong passphrase doesn't write plaintext",
        !fs.existsSync(path.join(dd2, "vault.key")));
  fs.rmSync(d2, { recursive: true, force: true });

  // ---- rotate ----
  var d3 = _tmpDir("blamejs-cli-vault-rotate");
  var dd3 = path.join(d3, "data");
  fs.mkdirSync(dd3);
  await _bootPlaintextVault(dd3);
  await cli.main(["vault", "seal", "--data-dir", dd3, "--passphrase", "old"], _captureCtx());
  var ctx5 = _captureCtx();
  var code5 = await cli.main(
    ["vault", "rotate", "--data-dir", dd3, "--passphrase", "old", "--new-passphrase", "new"], ctx5);
  check("rotate: returns 0",              code5 === 0);
  check("rotate: announces rotated path", /rotated:\s/.test(ctx5.out()));
  // Old passphrase no longer works.
  var ctx6 = _captureCtx();
  var code6 = await cli.main(
    ["vault", "unseal", "--data-dir", dd3, "--passphrase", "old"], ctx6);
  check("rotate: old passphrase rejected after rotate", code6 !== 0);
  // New passphrase works.
  var ctx7 = _captureCtx();
  var code7 = await cli.main(
    ["vault", "unseal", "--data-dir", dd3, "--passphrase", "new"], ctx7);
  check("rotate: new passphrase succeeds", code7 === 0);
  fs.rmSync(d3, { recursive: true, force: true });

  // ---- env-var fallback ----
  var d4 = _tmpDir("blamejs-cli-vault-env");
  var dd4 = path.join(d4, "data");
  fs.mkdirSync(dd4);
  await _bootPlaintextVault(dd4);
  var ctx8 = _captureCtx();
  ctx8.env = { BLAMEJS_VAULT_PASSPHRASE: "from-env" };
  var code8 = await cli.main(["vault", "seal", "--data-dir", dd4], ctx8);
  check("seal: passphrase resolved from BLAMEJS_VAULT_PASSPHRASE", code8 === 0);
  check("seal: env-var path produced sealed file",
        fs.existsSync(path.join(dd4, "vault.key.sealed")));
  fs.rmSync(d4, { recursive: true, force: true });

  // ---- arg validation ----
  var ctx9 = _captureCtx();
  var code9 = await cli.main(["vault"], ctx9);
  check("no subcommand: prints USAGE on stderr, returns 2",
        code9 === 2 && /Usage: blamejs vault/.test(ctx9.err()));

  var ctxA = _captureCtx();
  var codeA = await cli.main(["vault", "frobnicate"], ctxA);
  check("unknown subcommand: rejects with 2",
        codeA === 2 && /unknown subcommand/.test(ctxA.err()));

  var ctxB = _captureCtx();
  var codeB = await cli.main(["help", "vault"], ctxB);
  check("help vault: prints VAULT_USAGE",
        codeB === 0 && /Usage: blamejs vault/.test(ctxB.out()));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
