"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var cli = require("../../lib/cli");
var b = require("../../");

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

async function _buildFixtureBundle(passphrase) {
  var dataDir = _tmpDir("blamejs-cli-restore-data");
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  fs.writeFileSync(path.join(dataDir, "hello.txt"), "world\n");

  var bundleRoot = _tmpDir("blamejs-cli-restore-bundles");
  var storage = b.backup.localStorage({ root: bundleRoot });
  var backup = b.backup.create({
    dataDir:       dataDir,
    storage:       storage,
    passphrase:    Buffer.from(passphrase, "utf8"),
    files:         [{ relativePath: "hello.txt", kind: "plaintext" }],
    vaultKeyJson:  b.vault.getKeysJson(),
  });
  var result = await backup.run();
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  return {
    dataDir:    dataDir,
    bundleRoot: bundleRoot,
    bundleId:   result.bundleId,
    bundleDir:  path.join(bundleRoot, result.bundleId),
  };
}

async function run() {
  var fx = await _buildFixtureBundle("the-fixture-passphrase");

  // ---- list ----
  var ctx1 = _captureCtx();
  var c1 = await cli.main(["restore", "list", "--storage-root", fx.bundleRoot], ctx1);
  check("list: returns 0",                       c1 === 0);
  check("list: enumerates the fixture bundle",   ctx1.out().indexOf(fx.bundleId) !== -1);

  // ---- inspect (--bundle <dir>) ----
  var ctx2 = _captureCtx();
  var c2 = await cli.main(["restore", "inspect", "--bundle", fx.bundleDir], ctx2);
  check("inspect: returns 0",                    c2 === 0);
  check("inspect: reports manifest version",     /^manifest:\s+v/m.test(ctx2.out()));
  check("inspect: reports file count",           /^files:\s+1/m.test(ctx2.out()));

  // ---- inspect (--storage-root + --bundle-id) ----
  var ctx3 = _captureCtx();
  var c3 = await cli.main(
    ["restore", "inspect", "--storage-root", fx.bundleRoot, "--bundle-id", fx.bundleId],
    ctx3);
  check("inspect: alternative selector form",    c3 === 0 && /files:/.test(ctx3.out()));

  // ---- apply: live restore into a fresh data dir ----
  var liveDataDir = path.join(_tmpDir("blamejs-cli-restore-live"), "data");
  fs.mkdirSync(liveDataDir, { recursive: true });
  fs.writeFileSync(path.join(liveDataDir, "old.txt"), "discard-me\n");
  var ctx4 = _captureCtx();
  var c4 = await cli.main(
    ["restore", "apply",
     "--data-dir",   liveDataDir,
     "--bundle",     fx.bundleDir,
     "--passphrase", "the-fixture-passphrase"], ctx4);
  check("apply: returns 0",                      c4 === 0);
  check("apply: restored file landed",           fs.existsSync(path.join(liveDataDir, "hello.txt")));
  check("apply: restored bytes round-trip",
        fs.readFileSync(path.join(liveDataDir, "hello.txt"), "utf8") === "world\n");
  check("apply: pre-restore content preserved in rollback",
        !fs.existsSync(path.join(liveDataDir, "old.txt")));

  // ---- list-rollbacks ----
  var ctx5 = _captureCtx();
  var c5 = await cli.main(
    ["restore", "list-rollbacks", "--data-dir", liveDataDir], ctx5);
  check("list-rollbacks: returns 0",             c5 === 0);
  check("list-rollbacks: enumerates one point",  /rollback points at .* 1/.test(ctx5.out()) ||
                                                 ctx5.out().indexOf("rollback") !== -1);

  // ---- rollback ----
  var ctx6 = _captureCtx();
  var c6 = await cli.main(
    ["restore", "rollback", "--data-dir", liveDataDir], ctx6);
  check("rollback: returns 0",                   c6 === 0);
  check("rollback: pre-restore file restored",   fs.existsSync(path.join(liveDataDir, "old.txt")));
  check("rollback: bundle file gone",            !fs.existsSync(path.join(liveDataDir, "hello.txt")));

  // ---- env-var passphrase fallback ----
  var liveDataDir2 = path.join(_tmpDir("blamejs-cli-restore-live2"), "data");
  fs.mkdirSync(liveDataDir2, { recursive: true });
  var ctx7 = _captureCtx();
  ctx7.env = { BLAMEJS_BACKUP_PASSPHRASE: "the-fixture-passphrase" };
  var c7 = await cli.main(
    ["restore", "apply",
     "--data-dir", liveDataDir2,
     "--bundle",   fx.bundleDir], ctx7);
  check("apply: passphrase from BLAMEJS_BACKUP_PASSPHRASE", c7 === 0);

  // ---- arg validation ----
  var ctx8 = _captureCtx();
  var c8 = await cli.main(["restore"], ctx8);
  check("no subcommand: usage on stderr, returns 2",
        c8 === 2 && /Usage: blamejs restore/.test(ctx8.err()));

  var ctx9 = _captureCtx();
  var c9 = await cli.main(["restore", "frobnicate"], ctx9);
  check("unknown subcommand: returns 2",
        c9 === 2 && /unknown subcommand/.test(ctx9.err()));

  var ctx10 = _captureCtx();
  var c10 = await cli.main(["restore", "apply", "--data-dir", "/tmp/x", "--bundle", fx.bundleDir], ctx10);
  check("apply: missing passphrase returns 2",
        c10 === 2 && /passphrase/i.test(ctx10.err()));

  var ctx11 = _captureCtx();
  var c11 = await cli.main(["restore", "inspect"], ctx11);
  check("inspect: missing bundle selector returns 2",
        c11 === 2 && /bundle/i.test(ctx11.err()));

  var ctx12 = _captureCtx();
  var c12 = await cli.main(["help", "restore"], ctx12);
  check("help restore: prints RESTORE_USAGE",
        c12 === 0 && /Usage: blamejs restore/.test(ctx12.out()));

  // ---- cleanup ----
  fs.rmSync(fx.dataDir,    { recursive: true, force: true });
  fs.rmSync(fx.bundleRoot, { recursive: true, force: true });
  fs.rmSync(liveDataDir,   { recursive: true, force: true });
  fs.rmSync(liveDataDir2,  { recursive: true, force: true });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
