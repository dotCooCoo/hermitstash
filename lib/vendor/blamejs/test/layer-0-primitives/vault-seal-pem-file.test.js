"use strict";

var fs = require("fs");
var os = require("os");
var path = require("path");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var BOOT_TIMEOUT_MS = 5000;
var POLL_INTERVAL_MS = 50;        // fast for tests; production default is 2s

async function setupVault() {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-spf-vault-"));
  await b.vault.init({
    dataDir:    dataDir,
    mode:       "plaintext",
    bootTimeoutMs: BOOT_TIMEOUT_MS,
  });
  return { dataDir: dataDir };
}

function teardownVault(ctx) {
  try { b.vault._resetForTest(); } catch (_e) { /* ignore */ }
  try { fs.rmSync(ctx.dataDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
}

async function _waitForGen(watcher, target, timeoutMs) {
  var deadline = Date.now() + (timeoutMs || 5000);
  while (Date.now() < deadline) {
    if (watcher.generation >= target) return true;
    await new Promise(function (r) { setTimeout(r, 25); });
  }
  return false;
}

async function testInitialSeal() {
  var ctx = await setupVault();
  var src = path.join(ctx.dataDir, "privkey.pem");
  var dest = path.join(ctx.dataDir, "privkey.sealed");
  var pem = "-----BEGIN PRIVATE KEY-----\nFAKEKEYBYTES\n-----END PRIVATE KEY-----\n";
  fs.writeFileSync(src, pem);
  var watcher;
  try {
    watcher = b.vault.sealPemFile({
      source:       src,
      destination:  dest,
      pollInterval: POLL_INTERVAL_MS,
      audit:        false,
    });
    check("sealPemFile: initial seal completes", watcher.generation === 1);
    check("sealPemFile: destination exists",     fs.existsSync(dest));
    check("sealPemFile: destination has sealed prefix",
          fs.readFileSync(dest, "utf8").indexOf("vault:") === 0);
    var unsealed = b.vault.unseal(fs.readFileSync(dest, "utf8")).toString("utf8");
    check("sealPemFile: unseal round-trips to source PEM", unsealed === pem);
    check("sealPemFile: lastError is null on success", watcher.lastError === null);
    check("sealPemFile: marker removed after success",
          !fs.existsSync(dest + ".rewriting"));
  } finally {
    if (watcher) watcher.stop();
    teardownVault(ctx);
  }
}

async function testAutoResealOnSourceChange() {
  var ctx = await setupVault();
  var src = path.join(ctx.dataDir, "privkey.pem");
  var dest = path.join(ctx.dataDir, "privkey.sealed");
  fs.writeFileSync(src, "PEM-V1\n");
  var watcher;
  try {
    watcher = b.vault.sealPemFile({
      source:       src,
      destination:  dest,
      pollInterval: POLL_INTERVAL_MS,
      audit:        false,
    });
    check("sealPemFile auto: initial seal at gen 1", watcher.generation === 1);

    // Simulate ACME renewal — write a different PEM. Bump mtime to
    // ensure fs.watchFile sees the change even on coarse-resolution
    // filesystems where two writes within the same poll window can
    // collide on mtime.
    fs.writeFileSync(src, "PEM-V2-renewed\n");
    var future = new Date(Date.now() + 5000);
    fs.utimesSync(src, future, future);

    var sawV2 = await _waitForGen(watcher, 2, 5000);
    check("sealPemFile auto: gen incremented after source change", sawV2);

    var unsealed2 = b.vault.unseal(fs.readFileSync(dest, "utf8")).toString("utf8");
    check("sealPemFile auto: destination reflects new source bytes",
          unsealed2 === "PEM-V2-renewed\n");
  } finally {
    if (watcher) watcher.stop();
    teardownVault(ctx);
  }
}

async function testRecoveryFromMarker() {
  // Operator scenario: process crashed mid-reseal — marker remains on
  // disk. Next start() detects it and re-runs the seal idempotently.
  var ctx = await setupVault();
  var src = path.join(ctx.dataDir, "privkey.pem");
  var dest = path.join(ctx.dataDir, "privkey.sealed");
  fs.writeFileSync(src, "RECOVER-PEM\n");
  // Pre-seed the marker as if from a prior crashed reseal.
  fs.writeFileSync(dest + ".rewriting", String(Date.now()));
  var watcher;
  try {
    watcher = b.vault.sealPemFile({
      source:       src,
      destination:  dest,
      pollInterval: POLL_INTERVAL_MS,
      audit:        false,
    });
    check("sealPemFile recovery: gen advanced past 0", watcher.generation >= 1);
    check("sealPemFile recovery: marker removed after recovery seal",
          !fs.existsSync(dest + ".rewriting"));
    check("sealPemFile recovery: destination reflects current source",
          b.vault.unseal(fs.readFileSync(dest, "utf8")).toString("utf8") === "RECOVER-PEM\n");
  } finally {
    if (watcher) watcher.stop();
    teardownVault(ctx);
  }
}

async function testRefuseSamePathSealing() {
  var ctx = await setupVault();
  var src = path.join(ctx.dataDir, "shared.pem");
  fs.writeFileSync(src, "PEM\n");
  var threw = false;
  try {
    b.vault.sealPemFile({
      source:      src,
      destination: src,
      audit:       false,
    });
  } catch (e) {
    threw = e && e.code === "seal-pem-file/same-path";
  }
  check("sealPemFile: refuses identical source/destination paths", threw);
  teardownVault(ctx);
}

async function testForceReseal() {
  // Operator-driven forceReseal triggers a reseal even without a
  // source mtime change.
  var ctx = await setupVault();
  var src = path.join(ctx.dataDir, "privkey.pem");
  var dest = path.join(ctx.dataDir, "privkey.sealed");
  fs.writeFileSync(src, "FORCE-PEM\n");
  var watcher;
  try {
    watcher = b.vault.sealPemFile({
      source:       src,
      destination:  dest,
      pollInterval: POLL_INTERVAL_MS * 100,  // long poll — force the manual path
      audit:        false,
    });
    var initialGen = watcher.generation;
    watcher.forceReseal();
    // forceReseal is synchronous in the test environment (vault.seal
    // is sync); generation should advance immediately.
    check("sealPemFile force: generation advanced after forceReseal",
          watcher.generation === initialGen + 1);
  } finally {
    if (watcher) watcher.stop();
    teardownVault(ctx);
  }
}

async function testStopHaltsWatcher() {
  var ctx = await setupVault();
  var src = path.join(ctx.dataDir, "privkey.pem");
  var dest = path.join(ctx.dataDir, "privkey.sealed");
  fs.writeFileSync(src, "STOP-PEM\n");
  var watcher;
  try {
    watcher = b.vault.sealPemFile({
      source:       src,
      destination:  dest,
      pollInterval: POLL_INTERVAL_MS,
      audit:        false,
    });
    check("sealPemFile stop: watching=true after start",  watcher.watching === true);
    watcher.stop();
    check("sealPemFile stop: watching=false after stop",  watcher.watching === false);
  } finally {
    teardownVault(ctx);
  }
}

async function run() {
  await testInitialSeal();
  await testAutoResealOnSourceChange();
  await testRecoveryFromMarker();
  await testRefuseSamePathSealing();
  await testForceReseal();
  await testStopHaltsWatcher();
}

module.exports = { run: run };

if (require.main === module) {
  var fsLog = require("fs");
  var pathLog = require("path");
  var OUT = pathLog.join(__dirname, "..", "..", ".test-output");
  try { fsLog.mkdirSync(OUT, { recursive: true }); } catch (_e) { /* best-effort */ }
  var LOG_PATH = pathLog.join(OUT, "vault-seal-pem-file.log");
  try { fsLog.unlinkSync(LOG_PATH); } catch (_e) { /* fresh */ }
  var _logFd = fsLog.openSync(LOG_PATH, "w");
  function _logWrite(chunk) {
    try {
      var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      fsLog.writeSync(_logFd, buf, 0, buf.length, null);
    } catch (_e) { /* best-effort */ }
  }
  var origStdout = process.stdout.write.bind(process.stdout);
  var origStderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = function (c, e, cb) { _logWrite(c); return origStdout(c, e, cb); };
  process.stderr.write = function (c, e, cb) { _logWrite(c); return origStderr(c, e, cb); };
  process.on("exit", function () { try { fsLog.closeSync(_logFd); } catch (_e) { /* best-effort */ } });
  console.log("output: " + LOG_PATH);
  run().then(
    function () { console.log("OK — vault.sealPemFile tests"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
