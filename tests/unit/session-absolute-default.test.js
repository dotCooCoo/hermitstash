require("../helpers/isolate-db");
var { describe, it, before, after, mock } = require("node:test");
var assert = require("node:assert");
var http = require("http");

// lib/session.js opens its store when it is required. Each test file uses its
// own store name.
process.env.HERMITSTASH_SESSION_DB = "test-session-absolute-default-"
  + require("crypto").randomBytes(4).toString("hex") + ".db";
// lib/session.js reads this when it is required. These cases cover the default.
delete process.env.SESSION_ABSOLUTE_TIMEOUT_MS;

var b = require("../../lib/vendor/blamejs");
var TIME = b.constants.TIME;
var { Router } = b.router;
var { sessionMiddleware } = require("../../lib/session");
var vault = require("../../lib/vault");

var server;
var port;

before(async function () {
  await vault.init();
  var app = new Router();
  app.use(sessionMiddleware);
  app.get("/t", function (req, res) { res.writeHead(200); res.end("ok"); });
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

// inUseSince opens a session with the clock set offsetMs from now, then records
// activity on it now.
async function inUseSince(offsetMs) {
  var realNow = Date.now();
  var clock = mock.method(Date, "now", function () { return realNow + offsetMs; });
  var cookie;
  try {
    cookie = sessionCookie(await get("/t"));
  } finally {
    clock.mock.restore();
  }
  var token = decodeURIComponent(cookie.slice("hs_sid=".length));
  await b.session.touch(token, { extendBy: TIME.days(7), idleTimeoutMs: 0, absoluteTimeoutMs: 0 });
  return cookie;
}

describe("without SESSION_ABSOLUTE_TIMEOUT_MS a session lasts at most 12 hours", function () {
  it("refuses a session created 13 hours ago even though it is still in use", async function () {
    var cookie = await inUseSince(-TIME.hours(13));
    var res = await get("/t", cookie);
    assert.ok(sessionCookie(res), "the response must carry a session cookie");
    assert.notStrictEqual(sessionCookie(res), cookie, "the server must issue a new session");
  });

  it("keeps a session created 11 hours ago that is still in use", async function () {
    var cookie = await inUseSince(-TIME.hours(11));
    var res = await get("/t", cookie);
    assert.strictEqual(sessionCookie(res), cookie);
  });
});
