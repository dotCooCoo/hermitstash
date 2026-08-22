// Maintenance mode withholds the site from people. It does not tell the
// orchestrator the process has died.
//
// This is the half of the Umbrel deployment profile that needs a server: the
// compose file wires a HEALTHCHECK at /health, and so do the Dockerfile and the
// kubernetes manifest, where it drives the liveness, readiness AND startup
// probes. Answering the maintenance page there made the orchestrator restart
// the container for exactly as long as the operator left maintenance on —
// which is precisely when they wanted it left alone.
//
// The guard is exercised two ways on purpose. Through the server, because the
// mounted position is part of the behaviour — a guard mounted after the routes
// withholds nothing. And directly, because /health is declared in the entry
// point rather than in a route module, so no harness-built app serves it and an
// end-to-end assertion would be testing the harness's route list instead of the
// exemption.

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () {
  await testServer.start({ env: { MAINTENANCE_MODE: "true" } });
  client = new TestClient(testServer.baseUrl());
});

after(function () { return testServer.stop(); });

// Drive the middleware itself and report what it did.
function verdictFor(pathname, user) {
  var maintenance = require("../../middleware/maintenance");
  var req = { pathname: pathname, method: "GET", headers: {}, user: user || null };
  var out = { status: null, ended: false };
  var res = {
    statusCode: 200,
    setHeader: function () {},
    getHeader: function () {},
    writeHead: function (s) { out.status = s; return res; },
    end: function () { out.ended = true; },
  };
  var passed = false;
  maintenance(req, res, function () { passed = true; });
  return { passed: passed, status: out.status };
}

describe("maintenance mode — the liveness probe is not a visitor", function () {

  it("does not withhold /health", function () {
    // The exemption an orchestrator restarts the container over.
    assert.strictEqual(verdictFor("/health").passed, true);
  });

  it("withholds an ordinary page", function () {
    var v = verdictFor("/");
    assert.strictEqual(v.passed, false, "a visitor must not reach the site");
  });

  it("lets an admin through, and the sign-in flow that makes one", function () {
    // Withholding these would lock the operator out of the surface they turned
    // maintenance on to work with.
    assert.strictEqual(verdictFor("/auth/login").passed, true);
    assert.strictEqual(verdictFor("/admin/settings").passed, true);
    assert.strictEqual(verdictFor("/", { role: "admin" }).passed, true);
  });

  it("lets through the assets those pages render with", function () {
    ["/css/app.css", "/js/api.js", "/img/logo.svg"].forEach(function (p) {
      assert.strictEqual(verdictFor(p).passed, true, p);
    });
  });
});

describe("maintenance mode — mounted where it can actually withhold", function () {

  it("withholds a real request to an ordinary page", async function () {
    // Through the server, so the mount position is covered too: this guard sat
    // in the entry point where no harness-built app mounted it, which is how
    // the exemption above went untested in the first place.
    var res = await client.get("/");
    assert.strictEqual(res.status, 503);
  });

  it("does not withhold a real request to the sign-in page", async function () {
    var res = await client.get("/auth/login");
    assert.notStrictEqual(res.status, 503);
  });
});
