// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.router — request-body schema validation must run even when no body was
 * parsed. A route declaring `spec.body` is asserting the body is part of the
 * contract; skipping the check when `req.body === undefined` (no body sent /
 * bodyParser absent / empty POST) silently admits a request that omits a
 * required body straight to the handler. Mirrors the always-run params/query
 * checks.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var s       = b.safeSchema;

function _req(method, url) {
  return { method: method, url: url, headers: { host: "localhost" } };
}

function _res() {
  var res = {
    statusCode:    0,
    headersSent:   false,
    writableEnded: false,
    _body:         "",
    writeHead: function (status, headers) {
      res.statusCode = status;
      res._headers = headers || {};
      res.headersSent = true;
    },
    end: function (chunk) {
      if (chunk !== undefined) res._body += chunk;
      res.writableEnded = true;
    },
  };
  return res;
}

async function testMissingRequiredBodyRejected() {
  var r = b.router.create();
  var handlerRan = false;
  r.post("/items", { body: s.object({ name: s.string() }) }, function (req, res) {
    handlerRan = true;
    res.writeHead(200); res.end("created");
  });

  // No body was parsed onto the request (req.body === undefined).
  var res = _res();
  await r.handle(_req("POST", "/items"), res);
  check("missing required body → 400", res.statusCode === 400);
  check("missing required body → handler did not run", handlerRan === false);
  check("missing required body → validation error names the body location",
    /"where":"body"/.test(res._body));
}

async function testValidBodyAccepted() {
  var r = b.router.create();
  var seen = null;
  r.post("/items", { body: s.object({ name: s.string() }) }, function (req, res) {
    seen = req.body;
    res.writeHead(200); res.end("created");
  });

  var req = _req("POST", "/items");
  req.body = { name: "widget" };
  var res = _res();
  await r.handle(req, res);
  check("valid body → 200", res.statusCode === 200);
  check("valid body → handler sees parsed body", seen && seen.name === "widget");
}

async function testOptionalBodyAbsentAccepted() {
  // An explicitly-optional body schema must still pass when no body is sent —
  // the fix validates, it does not require a body unconditionally.
  var r = b.router.create();
  var handlerRan = false;
  r.post("/items", { body: s.object({ name: s.string() }).optional() }, function (req, res) {
    handlerRan = true;
    res.writeHead(200); res.end("ok");
  });

  var res = _res();
  await r.handle(_req("POST", "/items"), res);
  check("optional body absent → 200", res.statusCode === 200 && handlerRan === true);
}

async function run() {
  await testMissingRequiredBodyRejected();
  await testValidBodyAccepted();
  await testOptionalBodyAbsentAccepted();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK router-body-validation — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}
