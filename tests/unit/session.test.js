const { describe, it, before } = require("node:test");
const assert = require("node:assert");
var http = require("http");

var { Router } = require("../../lib/vendor/blamejs").router;
var { sessionMiddleware } = require("../../lib/session");
var vault = require("../../lib/vault");

describe("session (ML-KEM-768 encrypted cookies)", function () {
  before(async function () {
    // b.session.create (v0.9.45+) calls b.vault.getDerivedHashSalt for
    // the userIdHash derived hash. Without an explicit vault.init the
    // sync seal/unseal path leaves b.vault.paths null and the salt
    // lookup throws — every test middleware would silently catch and
    // emit a req-session-undefined response.
    await vault.init();
  });


  it("sets an hs_sid cookie on first request", function (_, done) {
    var app = new Router();
    app.use(sessionMiddleware);
    app.get("/t", function (req, res) { res.json({ ok: true }); });
    var server = app.listen(0, function () {
      http.get("http://localhost:" + server.address().port + "/t", function (res) {
        var cookies = res.headers["set-cookie"];
        assert.ok(cookies, "should set cookies");
        assert.ok(cookies.some(function (c) { return c.startsWith("hs_sid="); }), "should set hs_sid cookie");
        server.close(done);
      });
    });
  });

  it("cookie value is ML-KEM-768 encrypted (large, no dot separator)", function (_, done) {
    var app = new Router();
    app.use(sessionMiddleware);
    app.get("/t", function (req, res) { res.json({ ok: true }); });
    var server = app.listen(0, function () {
      http.get("http://localhost:" + server.address().port + "/t", function (res) {
        var cookie = res.headers["set-cookie"][0];
        var value = cookie.split("hs_sid=")[1].split(";")[0];
        var decoded = decodeURIComponent(value);
        // ML-KEM-768 ciphertext is much larger than old HMAC format
        assert.ok(decoded.length > 500, "cookie should be large (ML-KEM ciphertext), got length: " + decoded.length);
        // Should NOT have the old sid.hmac dot format
        assert.ok(!decoded.includes(".") || decoded.length > 200, "should not be old HMAC format");
        server.close(done);
      });
    });
  });

  it("persists session data across requests with same cookie", function (_, done) {
    var app = new Router();
    app.use(sessionMiddleware);
    app.get("/set", function (req, res) { req.session.val = 42; res.json({ set: true }); });
    app.get("/get", function (req, res) { res.json({ val: req.session.val }); });
    var server = app.listen(0, function () {
      var port = server.address().port;
      http.get("http://localhost:" + port + "/set", function (res1) {
        var cookie = res1.headers["set-cookie"][0].split(";")[0];
        http.get({ hostname: "localhost", port: port, path: "/get", headers: { cookie: cookie } }, function (res2) {
          var chunks = [];
          res2.on("data", function (c) { chunks.push(c); });
          res2.on("end", function () {
            var body = JSON.parse(Buffer.concat(chunks).toString());
            assert.strictEqual(body.val, 42);
            server.close(done);
          });
        });
      });
    });
  });

  it("rejects tampered cookies", function (_, done) {
    var app = new Router();
    app.use(sessionMiddleware);
    app.get("/set", function (req, res) { req.session.secret = "hidden"; res.json({}); });
    app.get("/get", function (req, res) { res.json({ secret: req.session.secret || null }); });
    var server = app.listen(0, function () {
      var port = server.address().port;
      http.get("http://localhost:" + port + "/set", function () {
        http.get({ hostname: "localhost", port: port, path: "/get", headers: { cookie: "hs_sid=tampered_garbage_data_here" } }, function (res) {
          var chunks = [];
          res.on("data", function (c) { chunks.push(c); });
          res.on("end", function () {
            var body = JSON.parse(Buffer.concat(chunks).toString());
            assert.strictEqual(body.secret, null, "tampered cookie should not access session");
            server.close(done);
          });
        });
      });
    });
  });

  it("rejects old HMAC-format cookies", function (_, done) {
    var app = new Router();
    app.use(sessionMiddleware);
    app.get("/set", function (req, res) { req.session.data = "test"; res.json({}); });
    app.get("/get", function (req, res) { res.json({ data: req.session.data || null }); });
    var server = app.listen(0, function () {
      var port = server.address().port;
      http.get("http://localhost:" + port + "/set", function () {
        // Old format: sid.hmac_signature
        http.get({ hostname: "localhost", port: port, path: "/get", headers: { cookie: "hs_sid=abc123def456.fakesignature" } }, function (res) {
          var chunks = [];
          res.on("data", function (c) { chunks.push(c); });
          res.on("end", function () {
            var body = JSON.parse(Buffer.concat(chunks).toString());
            assert.strictEqual(body.data, null, "old HMAC format should be rejected");
            server.close(done);
          });
        });
      });
    });
  });

  it("session rotation creates new cookie", function (_, done) {
    var app = new Router();
    app.use(sessionMiddleware);
    app.get("/login", async function (req, res) {
      req.session.user = "alice";
      await req.regenerateSession();
      res.json({ user: req.session.user });
    });
    var server = app.listen(0, function () {
      var port = server.address().port;
      http.get("http://localhost:" + port + "/login", function (res) {
        var cookies = res.headers["set-cookie"];
        assert.ok(cookies && cookies.length > 0, "should set new cookie after rotation");
        var chunks = [];
        res.on("data", function (c) { chunks.push(c); });
        res.on("end", function () {
          var body = JSON.parse(Buffer.concat(chunks).toString());
          assert.strictEqual(body.user, "alice", "session data preserved after rotation");
          server.close(done);
        });
      });
    });
  });
});
