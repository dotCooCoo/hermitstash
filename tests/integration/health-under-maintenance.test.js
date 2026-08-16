"use strict";

/**
 * Maintenance mode must not tell the orchestrator the process has died.
 *
 * Every shipped deployment polls /health and treats anything other than 200 as
 * a dead container: the Dockerfile and docker-compose health checks exit
 * non-zero on it, and deploy/kubernetes.yml wires the same path to the
 * liveness, readiness AND startup probes. The maintenance gate answered it with
 * the 503 maintenance page, so switching maintenance on made Kubernetes kill
 * and restart the pod — repeatedly, for as long as the operator left it on,
 * which is exactly when they wanted the deployment left alone.
 *
 * Maintenance withholds the site from people. It is not a claim that the
 * process stopped, and this pins the difference.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var http = require("node:http");
var { spawn } = require("node:child_process");

var net = require("node:net");

var projectRoot = path.join(__dirname, "..", "..");
var PORT, dir, child;

// A port the OS hands out, not one picked by hand. A fixed number collides with
// a concurrent run — and worse, an unrelated HermitStash already listening on it
// would answer every assertion here happily, so the suite would pass while
// testing nothing at all.
function freePort() {
  return new Promise(function (resolve, reject) {
    var srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", function () {
      var p = srv.address().port;
      srv.close(function () { resolve(p); });
    });
  });
}

function get(p) {
  return new Promise(function (resolve) {
    var req = http.get({ host: "127.0.0.1", port: PORT, path: p, timeout: 5000 }, function (res) {
      var body = "";
      res.on("data", function (c) { body += c; });
      res.on("end", function () { resolve({ status: res.statusCode, body: body }); });
    });
    req.on("error", function (e) { resolve({ status: 0, body: String(e.message) }); });
    req.on("timeout", function () { req.destroy(); resolve({ status: 0, body: "timeout" }); });
  });
}

before(async function () {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-maint-"));
  PORT = await freePort();
  child = spawn(process.execPath, ["server.js"], {
    cwd: projectRoot,
    env: Object.assign({}, process.env, {
      HERMITSTASH_DATA_DIR: dir,
      HERMITSTASH_DB_PATH: path.join(dir, "t.db"),
      HERMITSTASH_ALLOW_DISK_DB: "true",
      PORT: String(PORT),
      MAINTENANCE_MODE: "true",
      SETUP_COMPLETE: "true",
    }),
    stdio: ["ignore", "pipe", "pipe"],
  });
  // Wait on the server's own ready signal rather than a sleep: it logs
  // "HermitStash is running" from inside the listen callback, so the event is
  // exactly the condition, and a dead child rejects immediately instead of
  // burning the timeout. It also settles whose server answered — a stray
  // instance on the port would otherwise satisfy every assertion below without
  // this test having exercised anything.
  // The upper bound is an AbortSignal rather than a setTimeout: nothing here
  // sleeps for a fixed duration, so the wait ends the moment the server is
  // ready or the child dies, and the ceiling only exists to turn a hang into a
  // readable failure.
  await new Promise(function (resolve, reject) {
    var seen = "";
    var deadline = AbortSignal.timeout(40000);
    deadline.addEventListener("abort", function () {
      reject(new Error("the server never reported ready on port " + PORT + "\n" + seen.slice(-600)));
    });

    function watch(chunk) {
      seen += chunk.toString();
      if (seen.indexOf("HermitStash is running") !== -1) resolve();
    }
    child.stdout.on("data", watch);
    child.stderr.on("data", watch);
    child.once("exit", function (code) {
      reject(new Error("the server exited during startup with code " + code + "\n" + seen.slice(-600)));
    });
  });
});

after(function () {
  if (child) { try { child.kill(); } catch (_e) { /* best effort */ } }
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

describe("the health endpoint during maintenance", function () {
  it("answers 200 so the container is not restarted", function () {
    return get("/health").then(function (res) {
      assert.equal(res.status, 200,
        "the Dockerfile, compose and kubernetes probes all read this as liveness: " + res.body.slice(0, 200));
    });
  });

  it("still reports status ok, which is what the probes test", function () {
    return get("/health").then(function (res) {
      var body = JSON.parse(res.body);
      assert.equal(body.status, "ok", "probes and dashboards read this field");
    });
  });

  it("says maintenance is on, so the state is still visible", function () {
    // The point is not to hide maintenance — only to stop reporting it as death.
    return get("/health").then(function (res) {
      assert.equal(JSON.parse(res.body).maintenance, true,
        "a human or dashboard must still be able to tell: " + res.body.slice(0, 200));
    });
  });

  it("and maintenance is genuinely on — the site itself is withheld", function () {
    // Without this the test above could pass on a server that simply is not in
    // maintenance mode, and prove nothing.
    return get("/drop").then(function (res) {
      assert.notEqual(res.status, 200,
        "the ordinary site must be withheld, or this suite is not testing maintenance mode");
    });
  });
});
