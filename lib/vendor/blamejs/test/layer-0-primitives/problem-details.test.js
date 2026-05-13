"use strict";
/**
 * b.problemDetails — RFC 9457 Problem Details for HTTP APIs.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("problemDetails.create is fn",  typeof b.problemDetails.create === "function");
  check("problemDetails.respond is fn", typeof b.problemDetails.respond === "function");
  check("problemDetails.fromError is fn", typeof b.problemDetails.fromError === "function");
  check("problemDetails.validate is fn", typeof b.problemDetails.validate === "function");
  check("problemDetails.setBase is fn", typeof b.problemDetails.setBase === "function");
  check("RESERVED_FIELDS exposed",      Array.isArray(b.problemDetails.RESERVED_FIELDS));
  check("ProblemDetailsError exposed",  typeof b.problemDetails.ProblemDetailsError === "function");
}

function testCreateDefaults() {
  var p = b.problemDetails.create({});
  check("create() defaults type to about:blank", p.type === "about:blank");
  check("create() returns frozen", Object.isFrozen(p));
}

function testCreateFullShape() {
  var p = b.problemDetails.create({
    type:     "https://example.com/problems/out-of-credit",
    title:    "Out of credit",
    status:   403,
    detail:   "Balance 30, costs 50",
    instance: "/account/12345",
    balance:  30,
    accounts: ["/a", "/b"],
  });
  check("create() preserves type",     p.type === "https://example.com/problems/out-of-credit");
  check("create() preserves title",    p.title === "Out of credit");
  check("create() preserves status",   p.status === 403);
  check("create() preserves detail",   p.detail === "Balance 30, costs 50");
  check("create() preserves instance", p.instance === "/account/12345");
  check("create() preserves extension balance", p.balance === 30);
  check("create() preserves extension accounts", Array.isArray(p.accounts) && p.accounts.length === 2);
}

function testCreateRefusesBadShape() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("create({}) bad type non-string", function () { b.problemDetails.create({ type: 5 }); }, "problem-details/bad-type");
  expectCode("create({}) bad title empty",     function () { b.problemDetails.create({ title: "" }); }, "problem-details/bad-title");
  expectCode("create({}) bad status too low",  function () { b.problemDetails.create({ status: 99 }); }, "problem-details/bad-status");
  expectCode("create({}) bad status too high", function () { b.problemDetails.create({ status: 600 }); }, "problem-details/bad-status");
  expectCode("create({}) bad status non-int",  function () { b.problemDetails.create({ status: 200.5 }); }, "problem-details/bad-status");
  expectCode("create({}) bad detail non-str",  function () { b.problemDetails.create({ detail: 5 }); }, "problem-details/bad-detail");
  expectCode("create({}) bad instance empty",  function () { b.problemDetails.create({ instance: "" }); }, "problem-details/bad-instance");
  expectCode("create(null) refused",           function () { b.problemDetails.create(null); }, "problem-details/bad-opts");
  expectCode("create([]) refused",             function () { b.problemDetails.create([]); }, "problem-details/bad-opts");
  // Proto-pollution shape via JSON.parse — Object.keys sees __proto__ as a real key in this case.
  expectCode("create(__proto__ from JSON.parse) refused",
             function () { b.problemDetails.create(JSON.parse('{"__proto__":{"x":1}}')); },
             "problem-details/reserved-extension");
}

function testFromError() {
  b.problemDetails._resetForTest();
  var err = new (b.frameworkError.ComplianceError)("compliance/unknown-posture", "bad posture", true);
  var p = b.problemDetails.fromError(err);
  check("fromError: type prefixed with default base",
        /^https:\/\/blamejs\.com\/problems\/compliance\/unknown-posture$/.test(p.type));
  check("fromError: title humanized",
        p.title.indexOf("Compliance") !== -1 && p.title.indexOf("Error") !== -1);
  check("fromError: detail uses message",
        p.detail === "bad posture");
  check("fromError: status defaults to 500",
        p.status === 500);
  // override
  var p2 = b.problemDetails.fromError(err, { status: 400, title: "Bad Request", instance: "/audit/123" });
  check("fromError: opt overrides status/title/instance",
        p2.status === 400 && p2.title === "Bad Request" && p2.instance === "/audit/123");
}

function testFromErrorWithStatusCode() {
  var err = new (b.frameworkError.ObjectStoreError)("object-store/upstream", "S3 said no", false, 503);
  var p = b.problemDetails.fromError(err);
  check("fromError: err.statusCode propagates",  p.status === 503);
}

function testSetBase() {
  b.problemDetails._resetForTest();
  check("getBase: default", b.problemDetails.getBase() === "https://blamejs.com/problems");
  b.problemDetails.setBase("https://api.example.com/problems/");
  check("setBase: trailing slash stripped", b.problemDetails.getBase() === "https://api.example.com/problems");
  var err = new Error("foo");
  err.code = "ns/test";
  var p = b.problemDetails.fromError(err);
  check("setBase: fromError uses new base",
        p.type === "https://api.example.com/problems/ns/test");
  var threw = null;
  try { b.problemDetails.setBase("ftp://example.com"); }
  catch (e) { threw = e; }
  check("setBase: refuses non-http(s)", threw && /problem-details\/bad-base/.test(threw.code || ""));
  b.problemDetails._resetForTest();
}

function testRespond() {
  var headers = {};
  var statusCode = null;
  var body = null;
  var fakeRes = {
    setHeader: function (k, v) { headers[k.toLowerCase()] = v; },
    end:       function (b2) { body = b2; },
    statusCode: 0,
  };
  Object.defineProperty(fakeRes, "statusCode", {
    get: function () { return statusCode; },
    set: function (v) { statusCode = v; },
  });
  var p = b.problemDetails.create({
    type: "https://blamejs.com/problems/test", title: "t", status: 422, detail: "d",
  });
  b.problemDetails.respond(fakeRes, p);
  check("respond: sets statusCode",        statusCode === 422);
  check("respond: sets problem+json type", headers["content-type"] === "application/problem+json");
  check("respond: sets Cache-Control no-store", headers["cache-control"] === "no-store");
  check("respond: writes JSON body",       JSON.parse(body).status === 422);
}

function testValidate() {
  var ok = b.problemDetails.validate({ type: "x", title: "t", status: 400, detail: "d" });
  check("validate: returns doc on success", ok && ok.status === 400);
  function expectCode(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("problem-details/bad-inbound") !== -1);
  }
  expectCode("validate: refuses null",            function () { b.problemDetails.validate(null); });
  expectCode("validate: refuses non-obj",         function () { b.problemDetails.validate("x"); });
  expectCode("validate: refuses array",           function () { b.problemDetails.validate([]); });
  expectCode("validate: refuses bad status",      function () { b.problemDetails.validate({ status: 99 }); });
  expectCode("validate: refuses bad type",        function () { b.problemDetails.validate({ type: 5 }); });
}

async function run() {
  testSurface();
  testCreateDefaults();
  testCreateFullShape();
  testCreateRefusesBadShape();
  testFromError();
  testFromErrorWithStatusCode();
  testSetBase();
  testRespond();
  testValidate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
