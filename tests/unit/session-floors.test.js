require("../helpers/isolate-db");
var { describe, it, before, after, mock } = require("node:test");
var assert = require("node:assert");
var http = require("http");

// lib/session.js opens its store when it is required. Each test file uses its
// own store name.
process.env.HERMITSTASH_SESSION_DB = "test-session-floors-"
  + require("crypto").randomBytes(4).toString("hex") + ".db";

var b = require("../../lib/vendor/blamejs");
var TIME = b.constants.TIME;

// lib/session.js reads this when it is required. The framework's own default
// is 12 hours.
process.env.SESSION_ABSOLUTE_TIMEOUT_MS = String(TIME.hours(24));

var { Router } = b.router;
var { sessionMiddleware } = require("../../lib/session");
var config = require("../../lib/config");
var vault = require("../../lib/vault");

var FLOORS_OFF = { idleTimeoutMs: 0, absoluteTimeoutMs: 0 };
var server;
var port;

before(async function () {
  await vault.init();
  var app = new Router();
  app.use(sessionMiddleware);
  app.get("/t", function (req, res) { res.writeHead(200); res.end("ok"); });
  app.get("/auth/session-check", function (req, res) {
    req._skipActivityUpdate = true;
    res.writeHead(200);
    res.end("ok");
  });
  server = app.listen(0, "127.0.0.1");
  await new Promise(function (resolve) { server.on("listening", resolve); });
  port = server.address().port;
});

after(function () { server.close(); });

function get(p, cookie) {
  return new Promise(function (resolve, reject) {
    var headers = cookie ? { cookie: cookie } : {};
    var req = http.get({ hostname: "127.0.0.1", port: port, path: p, headers: headers }, function (res) {
      res.resume();
      res.on("end", function () { resolve(res); });
    });
    req.on("error", reject);
  });
}

function sessionCookie(res) {
  var hit = (res.headers["set-cookie"] || []).filter(function (c) { return c.indexOf("hs_sid=") === 0; })[0];
  return hit ? hit.split(";")[0] : null;
}

function tokenOf(cookie) { return decodeURIComponent(cookie.slice("hs_sid=".length)); }

// openAt sends a cookie-less request with the clock set offsetMs from now, so
// the session it opens has that creation and activity time.
async function openAt(offsetMs) {
  var realNow = Date.now();
  var clock = mock.method(Date, "now", function () { return realNow + offsetMs; });
  try {
    return sessionCookie(await get("/t"));
  } finally {
    clock.mock.restore();
  }
}

// inUseSince opens a session offsetMs from now and records activity on it now.
async function inUseSince(offsetMs) {
  var cookie = await openAt(offsetMs);
  await b.session.touch(tokenOf(cookie), { extendBy: TIME.days(7), idleTimeoutMs: 0, absoluteTimeoutMs: 0 });
  return cookie;
}

describe("saving a session applies the configured timeouts", function () {
  it("keeps a session still in use 13 hours after it was created", async function () {
    var cookie = await inUseSince(-TIME.hours(13));
    var res = await get("/t", cookie);
    assert.strictEqual(sessionCookie(res), cookie, "the request must be served on the same session");
    assert.ok(await b.session.verify(tokenOf(cookie), FLOORS_OFF), "the session must still be stored");
  });

  it("refuses a session created 25 hours ago even though it is still in use", async function () {
    var cookie = await inUseSince(-TIME.hours(25));
    var res = await get("/t", cookie);
    assert.ok(sessionCookie(res), "the response must carry a session cookie");
    assert.notStrictEqual(sessionCookie(res), cookie, "the server must issue a new session");
  });

  it("honors an idle timeout longer than 30 minutes", async function () {
    var saved = config.sessionIdleTimeout;
    config.sessionIdleTimeout = TIME.hours(2);
    try {
      var cookie = await openAt(-TIME.minutes(45));
      var res = await get("/t", cookie);
      assert.strictEqual(sessionCookie(res), cookie);
      assert.ok(await b.session.verify(tokenOf(cookie), FLOORS_OFF));
    } finally {
      config.sessionIdleTimeout = saved;
    }
  });

  it("leaves the idle clock alone on a request that sets _skipActivityUpdate", async function () {
    var cookie = await openAt(-TIME.minutes(10));
    var before = (await b.session.verify(tokenOf(cookie), FLOORS_OFF)).lastActivity;
    await get("/auth/session-check", cookie);
    var after = (await b.session.verify(tokenOf(cookie), FLOORS_OFF)).lastActivity;
    assert.strictEqual(after, before);
  });

  it("moves the idle clock on an ordinary request", async function () {
    var cookie = await openAt(-TIME.minutes(10));
    var before = (await b.session.verify(tokenOf(cookie), FLOORS_OFF)).lastActivity;
    await get("/t", cookie);
    var after = (await b.session.verify(tokenOf(cookie), FLOORS_OFF)).lastActivity;
    assert.ok(after > before, "lastActivity " + before + " -> " + after);
  });
});
