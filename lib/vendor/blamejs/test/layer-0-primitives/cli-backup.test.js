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
  // Minimal in-process bundle build so the CLI tests have a real
  // bundleDir to read against. Storage backend is a memory-backed
  // adapter that writes the bundle to disk under bundleRoot.
  var dataDir = _tmpDir("blamejs-cli-backup-data");
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  fs.writeFileSync(path.join(dataDir, "hello.txt"), "world\n");

  var bundleRoot = _tmpDir("blamejs-cli-backup-bundles");
  var bundles = {};
  var storage = {
    listBundles: function () { return Object.keys(bundles); },
    hasBundle:   function (id) { return !!bundles[id]; },
    writeBundle: async function (id, srcDir) {
      var dst = path.join(bundleRoot, id);
      fs.cpSync(srcDir, dst, { recursive: true });
      bundles[id] = dst;
    },
    readBundle:   async function (id, dstDir) { fs.cpSync(bundles[id], dstDir, { recursive: true }); },
    deleteBundle: async function (id) { fs.rmSync(bundles[id], { recursive: true, force: true }); delete bundles[id]; },
  };
  var backup = b.backup.create({
    dataDir:       dataDir,
    storage:       storage,
    passphrase:    Buffer.from(passphrase, "utf8"),
    files:         [{ relativePath: "hello.txt", kind: "plaintext" }],
    vaultKeyJson:  b.vault.getKeysJson(),
  });
  var result = await backup.run();
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  return { dataDir: dataDir, bundleRoot: bundleRoot, bundleDir: path.join(bundleRoot, result.bundleId) };
}

async function run() {
  var fx = await _buildFixtureBundle("the-fixture-passphrase");

  // ---- inspect (no passphrase) ----
  var ctx1 = _captureCtx();
  var c1 = await cli.main(["backup", "inspect", "--bundle", fx.bundleDir], ctx1);
  check("inspect: returns 0",                  c1 === 0);
  check("inspect: prints file count",          /^files:\s+1/m.test(ctx1.out()));
  check("inspect: prints kinds histogram",     /plaintext: 1/.test(ctx1.out()));
  check("inspect: no passphrase needed",        !/passphrase/i.test(ctx1.err()));

  // ---- verify (correct passphrase) ----
  var ctx2 = _captureCtx();
  var c2 = await cli.main(
    ["backup", "verify", "--bundle", fx.bundleDir, "--passphrase", "the-fixture-passphrase"], ctx2);
  check("verify: returns 0 with correct passphrase", c2 === 0);
  check("verify: announces file count",        /verified:\s+1/.test(ctx2.out()));

  // ---- verify (wrong passphrase) ----
  var ctx3 = _captureCtx();
  var c3 = await cli.main(
    ["backup", "verify", "--bundle", fx.bundleDir, "--passphrase", "wrong"], ctx3);
  check("verify: non-zero exit on wrong passphrase", c3 !== 0);
  check("verify: useful error message",        /passphrase rejected/i.test(ctx3.err()));

  // ---- extract ----
  var stagingDir = path.join(_tmpDir("blamejs-cli-backup-staging"), "fresh");
  // _tmpDir creates a directory that already exists; pass a fresh subpath
  // since restore-bundle.extract refuses to merge into an existing dir.
  var ctx4 = _captureCtx();
  var c4 = await cli.main(
    ["backup", "extract", "--bundle", fx.bundleDir, "--to", stagingDir,
     "--passphrase", "the-fixture-passphrase"], ctx4);
  check("extract: returns 0",                  c4 === 0);
  check("extract: writes the file",             fs.existsSync(path.join(stagingDir, "hello.txt")));
  check("extract: roundtrips bytes",
        fs.readFileSync(path.join(stagingDir, "hello.txt"), "utf8") === "world\n");

  // ---- env-var passphrase fallback ----
  var ctx5 = _captureCtx();
  ctx5.env = { BLAMEJS_BACKUP_PASSPHRASE: "the-fixture-passphrase" };
  var c5 = await cli.main(["backup", "verify", "--bundle", fx.bundleDir], ctx5);
  check("verify: passphrase from BLAMEJS_BACKUP_PASSPHRASE", c5 === 0);

  // ---- arg validation ----
  var ctx6 = _captureCtx();
  var c6 = await cli.main(["backup"], ctx6);
  check("no subcommand: usage on stderr, returns 2",
        c6 === 2 && /Usage: blamejs backup/.test(ctx6.err()));

  var ctx7 = _captureCtx();
  var c7 = await cli.main(["backup", "frobnicate"], ctx7);
  check("unknown subcommand: returns 2",
        c7 === 2 && /unknown subcommand/.test(ctx7.err()));

  var ctx8 = _captureCtx();
  var c8 = await cli.main(["help", "backup"], ctx8);
  check("help backup: prints BACKUP_USAGE",
        c8 === 0 && /Usage: blamejs backup/.test(ctx8.out()));

  // ---- cleanup ----
  fs.rmSync(fx.dataDir,    { recursive: true, force: true });
  fs.rmSync(fx.bundleRoot, { recursive: true, force: true });
  fs.rmSync(stagingDir,    { recursive: true, force: true });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
