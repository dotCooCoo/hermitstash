"use strict";
/**
 * b.middleware.bearerAuth — Bearer-token middleware.
 *
 * Covers: surface; missing-Authorization passes through (so cookie
 * paths can take over); invalid Bearer rejects with 401 + WWW-
 * Authenticate; verifier-returned-null rejects 401; verifier-throws
 * rejects 401 with operator-classifiable code; valid token attaches
 * req.user.
 */

var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _bodyReq  = helpers._bodyReq;
var _bodyRes  = helpers._bodyRes;

function _runMiddleware(mw, req, res) {
  return new Promise(function (resolve) {
    var settled = false;
    mw(req, res, function () {
      if (settled) return;
      settled = true;
      resolve({ next: true, status: res._endedStatus, user: req.user });
    });
    res.on("finish", function () {
      if (settled) return;
      settled = true;
      resolve({ next: false, status: res._endedStatus, user: req.user });
    });
    setTimeout(function () {
      if (settled) return;
      settled = true;
      resolve({ next: false, status: res._endedStatus, timeout: true });
    }, 1500);                                                                    // allow:raw-byte-literal — test safety timeout ms
  });
}

function testBearerSurface() {
  check("middleware.bearerAuth exposed",
        typeof b.middleware.bearerAuth === "function");
  var threw = null;
  try { b.middleware.bearerAuth({}); } catch (e) { threw = e; }
  check("bearerAuth without verify → throws",
        threw && /missing-verify/.test(threw.code || threw.message || ""));
}

async function testBearerMissingHeaderPassesThrough() {
  var mw = b.middleware.bearerAuth({ verify: async function () { return null; } });
  var req = _bodyReq("GET", {}, "");
  var res = _bodyRes();
  var rv = await _runMiddleware(mw, req, res);
  check("no Authorization header → next() (cookie path can take over)",
        rv.next === true);
}

async function testBearerInvalidTokenRejected() {
  var mw = b.middleware.bearerAuth({ verify: async function () { return null; } });
  var req = _bodyReq("GET", { authorization: "Bearer bogus" }, "");
  var res = _bodyRes();
  var rv = await _runMiddleware(mw, req, res);
  check("invalid Bearer token → 401",
        rv.next === false && rv.status === 401);
  check("invalid Bearer → WWW-Authenticate header set",
        typeof res._headers["WWW-Authenticate"] === "string" &&
        res._headers["WWW-Authenticate"].indexOf("Bearer") === 0);
}

async function testBearerVerifyThrowsRejected() {
  var mw = b.middleware.bearerAuth({
    verify: async function () { throw Object.assign(new Error("expired"), { code: "auth-bearer/expired" }); },
  });
  var req = _bodyReq("GET", { authorization: "Bearer x" }, "");
  var res = _bodyRes();
  var rv = await _runMiddleware(mw, req, res);
  check("verifier throws → 401 with invalid_token challenge",
        rv.next === false && rv.status === 401 &&
        /invalid_token/.test(res._headers["WWW-Authenticate"] || ""));
}

async function testBearerValidAttachesUser() {
  var mw = b.middleware.bearerAuth({
    verify: async function (token) {
      return token === "good" ? { id: "u1", scopes: ["read"] } : null;
    },
  });
  var req = _bodyReq("GET", { authorization: "Bearer good" }, "");
  var res = _bodyRes();
  var rv = await _runMiddleware(mw, req, res);
  check("valid Bearer → next() and req.user attached",
        rv.next === true && rv.user && rv.user.id === "u1");
}

async function run() {
  testBearerSurface();
  await testBearerMissingHeaderPassesThrough();
  await testBearerInvalidTokenRejected();
  await testBearerVerifyThrowsRejected();
  await testBearerValidAttachesUser();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
