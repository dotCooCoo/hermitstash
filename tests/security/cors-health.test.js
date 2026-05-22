/**
 * Regression test for the v1.11.13 production bug — the global CORS
 * middleware was rejecting cross-origin GET /health probes from a
 * configured gateway origin because the allowlist wasn't extended,
 * which silently broke the PQC entry page's transitive "can the
 * browser reach the app over PQC TLS" check.
 *
 * Locks in: /health goes through the global cors middleware (no bespoke
 * per-endpoint allowlist), and an operator-listed origin actually
 * receives Access-Control-Allow-Origin in the response.
 */
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const http = require("http");

var b = require("../../lib/vendor/blamejs");

var server;
var port;

function rawGet(pathStr, origin) {
  return new Promise(function (resolve, reject) {
    var headers = {};
    if (origin) headers.Origin = origin;
    var req = http.request({
      hostname: "127.0.0.1", port: port, path: pathStr, method: "GET", headers: headers,
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          text: Buffer.concat(chunks).toString(),
        });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

before(function () {
  // Build a router that mirrors the production /health code path:
  // b.middleware.cors with the same options middleware/cors.js passes,
  // then the /health handler from server-main.js.
  var Router = b.router.Router;
  var app = new Router();
  app.use(b.middleware.cors({
    origins:       ["https://hermitstash.com"],
    siteOrigin:    "http://127.0.0.1",
    credentials:   true,
    refuseUnknown: true,
  }));
  app.get("/health", function (req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() }));
  });
  return new Promise(function (resolve) {
    server = app.listen(0, function () {
      port = server.address().port;
      resolve();
    });
  });
});

after(function () {
  return new Promise(function (resolve) {
    if (!server) return resolve();
    server.close(function () { resolve(); });
    if (typeof server.closeAllConnections === "function") server.closeAllConnections();
  });
});

describe("CORS on /health (gateway-domain probe)", function () {
  it("same-origin request (no Origin header) → 200", async function () {
    var r = await rawGet("/health", null);
    assert.strictEqual(r.status, 200, "expected 200 for same-origin /health");
    var body = JSON.parse(r.text);
    assert.strictEqual(body.status, "ok");
  });

  it("listed gateway origin → 200 with matching Access-Control-Allow-Origin", async function () {
    var r = await rawGet("/health", "https://hermitstash.com");
    assert.strictEqual(r.status, 200, "expected 200 for allowed cross-origin /health");
    assert.strictEqual(
      r.headers["access-control-allow-origin"],
      "https://hermitstash.com",
      "ACAO must echo the request Origin when listed"
    );
    var body = JSON.parse(r.text);
    assert.strictEqual(body.status, "ok");
  });

  it("unlisted origin → refused with no ACAO header", async function () {
    var r = await rawGet("/health", "https://evil.example.com");
    assert.notStrictEqual(r.status, 200, "unlisted origin must not pass through to handler");
    assert.strictEqual(
      r.headers["access-control-allow-origin"],
      undefined,
      "ACAO must be absent for unlisted origins"
    );
  });
});
