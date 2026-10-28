/**
 * lib/server-lease.js: the lease the server and the offline vault tools hold
 * on the data directory, and the checks in scripts/lib/server-liveness.js and
 * server.js that read it.
 */
var { describe, it, after, afterEach } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var os = require("os");
var { spawnSync } = require("child_process");

var REPO_ROOT = path.resolve(__dirname, "..", "..");
var C = require(path.join(REPO_ROOT, "lib", "constants"));
var serverLease = require(path.join(REPO_ROOT, "lib", "server-lease"));

var testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "server-lease-"));
var seq = 0;
function leasePath() { return path.join(testRoot, "lease-" + (seq++)); }
function freshDataDir(name) {
  var d = path.join(testRoot, name + "-" + (seq++));
  fs.mkdirSync(d);
  return d;
}
function writeLease(dataDir, fields) {
  fs.writeFileSync(path.join(dataDir, C.DATA_DIR_INTERNAL.SERVER_LEASE), JSON.stringify(Object.assign({
    kind: "server", pid: 99, hostname: "server-container", token: "t", startedAt: "x",
    heartbeatAt: new Date().toISOString(),
  }, fields)));
}

after(function () { fs.rmSync(testRoot, { recursive: true, force: true }); });
afterEach(function () { serverLease.release(); });

describe("server-lease", function () {
  it("acquire writes a fresh server lease naming this process, and release deletes it", function () {
    var p = leasePath();
    serverLease.acquire({ path: p });
    var lease = serverLease.read(p);
    assert.strictEqual(lease.kind, "server");
    assert.strictEqual(lease.pid, process.pid);
    assert.strictEqual(lease.hostname, os.hostname());
    assert.strictEqual(lease.fresh, true);
    assert.ok(serverLease.isMine(lease));
    assert.ok(lease.ageMs >= 0 && lease.ageMs < serverLease.STALE_MS);
    if (process.platform !== "win32") {
      assert.strictEqual(fs.statSync(p).mode & 0o077, 0, "the lease is owner-only");
    }
    serverLease.release();
    assert.strictEqual(serverLease.read(p), null);
  });

  it("records a tool lease with the tool's name", function () {
    var p = leasePath();
    serverLease.acquire({ path: p, kind: "tool", name: "vault-key-rotate.js" });
    var lease = serverLease.read(p);
    assert.strictEqual(lease.kind, "tool");
    assert.strictEqual(lease.name, "vault-key-rotate.js");
    assert.match(serverLease.describe(lease), /^vault-key-rotate\.js \(pid \d+ on /);
  });

  it("refreshes the heartbeat on its interval", async function () {
    var p = leasePath();
    serverLease.acquire({ path: p, heartbeatMs: 20 });
    var first = serverLease.read(p).heartbeatAt;
    var deadline = Date.now() + C.TIME.seconds(5);
    while (serverLease.read(p).heartbeatAt === first && Date.now() < deadline) {
      await new Promise(setImmediate);
    }
    assert.notStrictEqual(serverLease.read(p).heartbeatAt, first, "a heartbeat rewrote the lease");
  });

  it("keeps the heartbeat going while the main thread is blocked", async function () {
    var p = leasePath();
    serverLease.acquire({ path: p, heartbeatMs: 20 });
    var first = serverLease.read(p).heartbeatAt;
    // block the event loop the way a large synchronous copy does
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 400);
    assert.notStrictEqual(serverLease.read(p).heartbeatAt, first, "the worker refreshed the lease during the block");
  });

  it("does not write a heartbeat while another process holds the lease lock", async function () {
    var p = leasePath();
    serverLease.acquire({ path: p, heartbeatMs: 20 });
    fs.mkdirSync(p + ".lock");
    var during = serverLease.read(p).heartbeatAt;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300);
    assert.strictEqual(serverLease.read(p).heartbeatAt, during, "no write while the lock is held");
    fs.rmdirSync(p + ".lock");
    // Generous: under a loaded full-suite run the worker thread can be starved.
    var deadline = Date.now() + C.TIME.seconds(15);
    while (serverLease.read(p).heartbeatAt === during && Date.now() < deadline) {
      await new Promise(setImmediate);
    }
    assert.notStrictEqual(serverLease.read(p).heartbeatAt, during, "heartbeats resume once the lock is free");
  });

  it("refuses a fresh lease held by another process, and lets a server replace a server lease", function () {
    var p = leasePath();
    fs.writeFileSync(p, JSON.stringify({ kind: "tool", name: "vault-key-rotate.js", pid: 5, hostname: "h", token: "tool",
      startedAt: "x", heartbeatAt: new Date().toISOString() }));
    assert.throws(function () { serverLease.acquire({ path: p }); },
      function (e) { return e.code === "server-lease/held" && e.lease.token === "tool"; });
    assert.throws(function () { serverLease.acquire({ path: p, kind: "tool" }); }, /vault-key-rotate\.js \(pid 5/);
    assert.strictEqual(serverLease.read(p).token, "tool", "the refused caller leaves the lease alone");

    fs.writeFileSync(p, JSON.stringify({ kind: "server", pid: 6, hostname: "h", token: "old-server",
      startedAt: "x", heartbeatAt: new Date().toISOString() }));
    assert.throws(function () { serverLease.acquire({ path: p, kind: "tool" }); }, /a HermitStash server \(pid 6/);
    serverLease.acquire({ path: p });
    assert.ok(serverLease.isMine(serverLease.read(p)), "a starting server replaces a server lease");
  });

  it("a running server writes its lease again after a second server took it and exited", async function () {
    var dataDir = freshDataDir("second-server");
    var p = path.join(dataDir, C.DATA_DIR_INTERNAL.SERVER_LEASE);
    serverLease.acquire({ path: p, heartbeatMs: 20 });
    var mine = serverLease.read(p).token;
    var r = spawnSync("node", ["-e",
      "var l=require(" + JSON.stringify(path.join(REPO_ROOT, "lib", "server-lease")) + ");l.acquire();" +
      "console.log('TOOK ' + l.isMine(l.read()));process.exit(1);"],
    { env: Object.assign({}, process.env, { HERMITSTASH_DATA_DIR: dataDir }), encoding: "utf8" });
    assert.match(r.stdout, /TOOK true/, r.stderr);
    var afterExit = serverLease.read(p);
    assert.ok(afterExit && afterExit.fresh, "the second server left a fresh lease when it exited");
    var deadline = Date.now() + C.TIME.seconds(5);
    while (!(serverLease.read(p) && serverLease.read(p).token === mine) && Date.now() < deadline) {
      await new Promise(setImmediate);
    }
    var back = serverLease.read(p);
    assert.ok(back && back.token === mine && back.fresh, "the first server's lease is back");
  });

  it("a running server's heartbeat replaces a tool lease written over it", async function () {
    var p = leasePath();
    serverLease.acquire({ path: p, heartbeatMs: 20 });
    var mine = serverLease.read(p).token;
    fs.writeFileSync(p, JSON.stringify({ kind: "tool", name: "x", pid: 1, hostname: "h", token: "tool",
      startedAt: "x", heartbeatAt: new Date().toISOString() }));
    var deadline = Date.now() + C.TIME.seconds(5);
    while (serverLease.read(p).token !== mine && Date.now() < deadline) {
      await new Promise(setImmediate);
    }
    assert.strictEqual(serverLease.read(p).token, mine);
  });

  it("lets exactly one of two processes that start together take the lease", function () {
    var dataDir = freshDataDir("race");
    // Both processes wait for the same wall-clock moment, then try at once. The
    // winner holds the lease well past the moment, so a loser that started
    // late under load still finds it held.
    var startAt = Date.now() + C.TIME.seconds(4);
    var holdUntil = startAt + C.TIME.seconds(4);
    var script = "var l=require(" + JSON.stringify(path.join(REPO_ROOT, "lib", "server-lease")) + ");" +
      "while(Date.now()<" + startAt + "){}" +
      "try{l.acquire({kind:'tool',name:'racer'});console.log('WON');" +
      "var left=" + holdUntil + "-Date.now();if(left>0)Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,left);}" +
      "catch(e){console.log(e.code==='server-lease/held'?'REFUSED':'ERROR '+e.message);}";
    var env = Object.assign({}, process.env, { HERMITSTASH_DATA_DIR: dataDir });
    var { spawn } = require("child_process");
    function run() {
      return new Promise(function (resolve) {
        var out = "";
        var c = spawn("node", ["-e", script], { env: env });
        c.stdout.on("data", function (d) { out += d; });
        c.on("exit", function () { resolve(out.trim()); });
      });
    }
    return Promise.all([run(), run()]).then(function (outs) {
      assert.deepStrictEqual(outs.slice().sort(), ["REFUSED", "WON"], JSON.stringify(outs));
    });
  });

  it("removes a lock directory left behind by a process that died holding it", function () {
    var p = leasePath();
    fs.mkdirSync(p + ".lock");
    var old = new Date(Date.now() - C.TIME.minutes(1));
    fs.utimesSync(p + ".lock", old, old);
    serverLease.acquire({ path: p });
    assert.ok(serverLease.isMine(serverLease.read(p)));
    assert.ok(!fs.existsSync(p + ".lock"));
  });

  it("release leaves a lease another process wrote in its place", function () {
    var p = leasePath();
    serverLease.acquire({ path: p });
    var other = { pid: 1, hostname: "h", token: "someone-else", startedAt: "x", heartbeatAt: new Date().toISOString() };
    fs.writeFileSync(p, JSON.stringify(other));
    serverLease.release();
    assert.strictEqual(serverLease.read(p).token, "someone-else");
  });

  it("reports a lease past STALE_MS as stale", function () {
    var p = leasePath();
    fs.writeFileSync(p, JSON.stringify({ kind: "server", pid: 7, hostname: "h", token: "t", startedAt: "x",
      heartbeatAt: new Date(Date.now() - serverLease.STALE_MS - C.TIME.seconds(1)).toISOString() }));
    var lease = serverLease.read(p);
    assert.strictEqual(lease.fresh, false);
    assert.strictEqual(lease.pid, 7);
    assert.strictEqual(serverLease.secondsUntilStale(lease), 0);
  });

  it("treats a lease it cannot parse as a fresh tool lease", function () {
    var p = leasePath();
    fs.writeFileSync(p, "not json");
    assert.deepStrictEqual(serverLease.read(p), { unreadable: true, kind: "tool", fresh: true, ageMs: null });
    fs.writeFileSync(p, JSON.stringify({ heartbeatAt: "not a date" }));
    assert.strictEqual(serverLease.read(p).unreadable, true);
  });

  it("returns null when there is no lease", function () {
    assert.strictEqual(serverLease.read(path.join(testRoot, "absent")), null);
  });

  it("deletes the lease on exit after the exit handlers registered before releaseAfterExistingExitHandlers", function () {
    var dataDir = freshDataDir("exit-order");
    var leaseFile = path.join(dataDir, C.DATA_DIR_INTERNAL.SERVER_LEASE);
    var r = spawnSync("node", ["-e",
      "var fs=require('fs');var l=require(" + JSON.stringify(path.join(REPO_ROOT, "lib", "server-lease")) + ");" +
      "l.acquire();" +
      "process.on('exit',function(){console.log('LEASE_DURING_LATER_HANDLER='+fs.existsSync(" + JSON.stringify(leaseFile) + "));});" +
      "l.releaseAfterExistingExitHandlers();"],
    { env: Object.assign({}, process.env, { HERMITSTASH_DATA_DIR: dataDir }), encoding: "utf8" });
    assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /LEASE_DURING_LATER_HANDLER=true/, "a handler registered before the move still sees the lease");
    assert.ok(!fs.existsSync(leaseFile), "the lease is gone after exit");
  });
});

describe("server-liveness with a lease", function () {
  function runGuard(dataDir, claim) {
    var fn = claim ? "claimDataDir({}, 'test-tool.js')" : "assertServerNotRunning({})";
    return spawnSync("node", ["-e",
      "var g=require(" + JSON.stringify(path.join(REPO_ROOT, "scripts", "lib", "server-liveness")) + ");" +
      "g." + fn + ".then(function(){var l=require(" + JSON.stringify(path.join(REPO_ROOT, "lib", "server-lease")) + ").read();" +
      "console.log('NOT_RUNNING ' + JSON.stringify(l && {kind:l.kind,name:l.name}));});"],
    { env: Object.assign({}, process.env, { HERMITSTASH_DATA_DIR: dataDir, PORT: "18995", INTERNAL_TLS_PORT: "18996" }),
      encoding: "utf8" });
  }

  it("refuses while a server lease is fresh, whatever ports the caller probes", function () {
    var dataDir = freshDataDir("guard-server");
    writeLease(dataDir, {});
    var r = runGuard(dataDir, true);
    assert.strictEqual(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /a HermitStash server \(pid 99 on server-container, last refreshed \d+s ago\) holds /);
    assert.match(r.stderr, /expires in \d+s/);
  });

  it("refuses while another tool holds the lease", function () {
    var dataDir = freshDataDir("guard-tool");
    writeLease(dataDir, { kind: "tool", name: "vault-key-rotate.js" });
    var r = runGuard(dataDir, true);
    assert.strictEqual(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /vault-key-rotate\.js \(pid 99 on server-container/);
    assert.match(r.stderr, /Stop that tool first/);
  });

  it("claimDataDir takes a tool lease when the lease is stale and nothing answers on the ports", function () {
    var dataDir = freshDataDir("guard-stale");
    writeLease(dataDir, { heartbeatAt: new Date(Date.now() - C.TIME.minutes(10)).toISOString() });
    var r = runGuard(dataDir, true);
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /NOT_RUNNING \{"kind":"tool","name":"test-tool\.js"\}/);
    assert.ok(!fs.existsSync(path.join(dataDir, C.DATA_DIR_INTERNAL.SERVER_LEASE)), "released at exit");
  });
});

describe("server.js with a tool lease", function () {
  it("refuses to start while a tool holds a fresh lease, and leaves the lease in place", function () {
    var dataDir = freshDataDir("boot-tool");
    writeLease(dataDir, { kind: "tool", name: "vault-key-rotate.js", token: "tool-token" });
    var r = spawnSync("node", [path.join(REPO_ROOT, "server.js")], {
      cwd: REPO_ROOT,
      env: Object.assign({}, process.env, { HERMITSTASH_DATA_DIR: dataDir, PORT: "18993", INTERNAL_TLS_PORT: "18994" }),
      encoding: "utf8", timeout: 30000,
    });
    assert.strictEqual(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /FATAL: vault-key-rotate\.js \(pid 99 on server-container, .*\) is using the data directory/);
    assert.strictEqual(serverLease.read(path.join(dataDir, C.DATA_DIR_INTERNAL.SERVER_LEASE)).token, "tool-token");
  });
});
