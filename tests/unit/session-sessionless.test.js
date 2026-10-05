require("../helpers/isolate-db");
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var http = require("http");

// lib/session.js opens its store when it is required. Each test file uses its
// own store name.
process.env.HERMITSTASH_SESSION_DB = "test-session-sessionless-"
  + require("crypto").randomBytes(4).toString("hex") + ".db";

var b = require("../../lib/vendor/blamejs");
var { Router } = b.router;
var { sessionMiddleware } = require("../../lib/session");
var attachUser = require("../../middleware/attach-user");
var apiAuth = require("../../middleware/api-auth");
var legacyApiEncrypt = require("../../middleware/api-encrypt");
var { csrfMiddleware } = require("../../app/security/csrf-policy");
var vault = require("../../lib/vault");

var MACHINE_PATHS = ["/health", "/sitemap.xml", "/manifest.json", "/.well-known/blamejs-pubkey"];
var BEARER = "Bearer hs_" + b.crypto.generateToken(24);

// The middleware runs in the order server-main.js mounts it. The handlers are
// stand-ins that answer without reading the session.
function buildApp() {
  var app = new Router();
  app.use(sessionMiddleware);
  app.use(attachUser);
  app.use(apiAuth);
  app.use(function legacyApiEncryptCarve(req, res, next) {
    if (req.pathname === "/.well-known/blamejs-pubkey") return next();
    return legacyApiEncrypt(req, res, next);
  });
  app.use(csrfMiddleware);
  MACHINE_PATHS.forEach(function (p) {
    app.get(p, function (req, res) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
  });
  app.get("/page", function (req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ csrf: req.csrfToken || null }));
  });
  app.post("/form", function (req, res) { res.writeHead(200); res.end("ok"); });
  app.post("/sign-in", async function (req, res) {
    await req.regenerateSession({ userId: "user-sessionless-test" });
    res.writeHead(200);
    res.end("ok");
  });
  return app;
}

var server;
var port;

before(async function () {
  await vault.init();
  server = buildApp().listen(0, "127.0.0.1");
  await new Promise(function (resolve) { server.on("listening", resolve); });
  port = server.address().port;
});

after(function () { server.close(); });

function send(method, p, headers, body) {
  return new Promise(function (resolve, reject) {
    var h = Object.assign({}, headers || {});
    if (body) h["content-length"] = Buffer.byteLength(body);
    var req = http.request({ hostname: "127.0.0.1", port: port, method: method, path: p, headers: h }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function sessionCookie(res) {
  var hit = (res.headers["set-cookie"] || []).filter(function (c) { return c.indexOf("hs_sid=") === 0; })[0];
  return hit ? hit.split(";")[0] : null;
}

describe("a request that needs no session stores none", function () {
  it("a cookie-less GET of each machine path stores no session and sets no cookie", async function () {
    for (var i = 0; i < MACHINE_PATHS.length; i++) {
      var before = await b.session.count();
      var res = await send("GET", MACHINE_PATHS[i]);
      assert.strictEqual(res.status, 200, MACHINE_PATHS[i]);
      assert.strictEqual(sessionCookie(res), null, MACHINE_PATHS[i] + " set a session cookie");
      assert.strictEqual(await b.session.count(), before, MACHINE_PATHS[i] + " stored a session");
    }
  });

  it("cookie-less HEAD and OPTIONS requests store no session", async function () {
    var before = await b.session.count();
    var responses = [
      await send("HEAD", "/health"),
      await send("HEAD", "/page"),
      await send("OPTIONS", "/page"),
    ];
    responses.forEach(function (res) { assert.strictEqual(sessionCookie(res), null); });
    assert.strictEqual(await b.session.count(), before);
  });

  it("a cookie-less request with a bearer credential stores no session", async function () {
    var before = await b.session.count();
    var res = await send("GET", "/page", { authorization: BEARER });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(sessionCookie(res), null);
    assert.strictEqual(await b.session.count(), before);
  });

  it("a bearer request that signs in stores the new session and sends its cookie", async function () {
    var before = await b.session.count();
    var res = await send("POST", "/sign-in", { authorization: BEARER, "content-type": "application/json" }, "{}");
    assert.strictEqual(res.status, 200);
    assert.ok(sessionCookie(res), "req.regenerateSession must set the session cookie");
    assert.strictEqual(await b.session.count(), before + 1);
  });
});

describe("a request that needs a session still gets one", function () {
  it("a cookie-less page request stores a session and sets its cookie", async function () {
    var before = await b.session.count();
    var res = await send("GET", "/page");
    assert.ok(sessionCookie(res));
    assert.strictEqual(await b.session.count(), before + 1);
  });

  it("accepts the CSRF token issued with that session and refuses a wrong one", async function () {
    var page = await send("GET", "/page");
    var cookie = sessionCookie(page);
    var token = JSON.parse(page.body).csrf;
    var form = { "content-type": "application/x-www-form-urlencoded" };
    var accepted = await send("POST", "/form", Object.assign({ cookie: cookie, "x-csrf-token": token }, form), "a=1");
    var wrong = await send("POST", "/form", Object.assign({ cookie: cookie, "x-csrf-token": "wrong" }, form), "a=1");
    var noCookie = await send("POST", "/form", Object.assign({ "x-csrf-token": token }, form), "a=1");
    assert.strictEqual(accepted.status, 200);
    assert.strictEqual(wrong.status, 403);
    assert.strictEqual(noCookie.status, 403);
  });

  it("a machine path requested with a session cookie keeps that session", async function () {
    var cookie = sessionCookie(await send("GET", "/page"));
    var before = await b.session.count();
    var res = await send("GET", "/health", { cookie: cookie });
    assert.strictEqual(sessionCookie(res), cookie);
    assert.strictEqual(await b.session.count(), before);
  });
});
