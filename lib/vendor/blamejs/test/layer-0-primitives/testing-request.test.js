// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.testing.request — supertest-style chainable HTTP test helper.
 */

var http  = require("node:http");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// b.testing.request drives the harness server with a default-agent http.request
// (keep-alive) and closes the fixture server fire-and-forget. The kept-alive
// client socket and the server's accept socket finalize their destroy on a
// later event-loop turn, past the forked worker's grace window. Destroy the
// global-agent socket pool, then poll until every TCP handle has drained so
// none outlives run().
async function _drainTcpHandles() {
  http.globalAgent.destroy();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "testing-request: TCP handle drain after globalAgent.destroy" });
}

async function run() {
  try {
    await _runTests();
  } finally {
    await _drainTcpHandles();
  }
}

async function _runTests() {
  // ---- Surface ----
  check("b.testing.request is fn",  typeof b.testing.request === "function");

  // ---- bare (req, res) handler ----
  var listener = function (req, res) {
    if (req.url === "/echo") {
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ method: req.method, body: Buffer.concat(chunks).toString("utf8") }));
      });
      return;
    }
    if (req.url === "/headers") {
      res.writeHead(200, { "X-Custom": req.headers["x-custom"] || "" });
      res.end("ok");
      return;
    }
    if (req.url === "/four") { res.writeHead(404); res.end(); return; }
    if (req.url === "/five") { res.writeHead(500); res.end(); return; }
    res.writeHead(200);
    res.end("default");
  };

  // ---- GET ----
  var r1 = await b.testing.request(listener).get("/").expect(200);
  check("GET /: status 200",        r1.status === 200);
  check("GET /: body buffer",       Buffer.isBuffer(r1.body));
  check("GET /: text decoded",      r1.text === "default");

  // ---- POST + body + content-type auto ----
  var r2 = await b.testing.request(listener)
    .post("/echo")
    .send({ name: "alpha" });
  check("POST /echo: status 200",        r2.status === 200);
  check("POST /echo: parsed JSON",       r2.json && r2.json.method === "POST");
  check("POST /echo: body round-trip",   r2.json.body === '{"name":"alpha"}');

  // ---- set headers (object + key/value) ----
  var r3 = await b.testing.request(listener)
    .get("/headers")
    .set("X-Custom", "v1");
  check("set(k,v): header forwarded",     r3.headers["x-custom"] === "v1");

  var r4 = await b.testing.request(listener)
    .get("/headers")
    .set({ "X-Custom": "v2", "X-Other": "y" });
  check("set(obj): headers forwarded",    r4.headers["x-custom"] === "v2");

  // ---- expect(status) success / failure ----
  var threw = null;
  try { await b.testing.request(listener).get("/four").expect(200); }
  catch (e) { threw = e; }
  check("expect: status mismatch rejects",   threw && /expect\(200\) got status 404/.test(threw.message));

  // 404 with explicit expect 404 → resolves
  var r5 = await b.testing.request(listener).get("/four").expect(404);
  check("expect: matching status resolves",  r5.status === 404);

  // ---- expect(fn) custom assertion ----
  var custom = await b.testing.request(listener)
    .get("/")
    .expect(function (res) {
      if (res.text !== "default") throw new Error("body mismatch");
    });
  check("expect(fn): custom assertion runs", custom.text === "default");

  // ---- send raw string ----
  var r6 = await b.testing.request(listener)
    .post("/echo")
    .set("Content-Type", "text/plain")
    .send("raw text");
  check("send(string): raw body",        r6.json.body === "raw text");

  // ---- b.router target ----
  var router = new b.router.Router();
  router.get("/router-test", function (req, res) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("from router");
  });
  var r7 = await b.testing.request(router).get("/router-test");
  check("router target: status 200",      r7.status === 200);
  check("router target: body",            r7.text === "from router");

  // ---- error path: bad target ----
  threw = null;
  try { b.testing.request(42); } catch (e) { threw = e; }
  check("bad target: throws",             threw && /must be a b\.router/.test(threw.message));

  // ---- HEAD / DELETE / PATCH / PUT ----
  var rh = await b.testing.request(listener).head("/");
  check("HEAD: status 200",               rh.status === 200);
  var rd = await b.testing.request(listener).delete("/");
  check("DELETE: status 200",             rd.status === 200);
  var rp = await b.testing.request(listener).patch("/");
  check("PATCH: status 200",              rp.status === 200);
  var ru = await b.testing.request(listener).put("/");
  check("PUT: status 200",                ru.status === 200);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
