"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("namespace",  typeof b.mail.server.jmap === "object");
  check("create fn",  typeof b.mail.server.jmap.create === "function");
  check("error class", typeof b.mail.server.jmap.MailServerJmapError === "function");
}

function testBadOptsRefused() {
  function expectThrow(label, opts, codeMatch) {
    var threw = null;
    try { b.mail.server.jmap.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses missing mailStore",
    { methods: {}, accountsFor: function () {} },
    "mail-server-jmap/no-mail-store");
  expectThrow("refuses missing methods",
    { mailStore: {}, accountsFor: function () {} },
    "mail-server-jmap/no-methods");
  expectThrow("refuses methods as array",
    { mailStore: {}, methods: [], accountsFor: function () {} },
    "mail-server-jmap/no-methods");
  expectThrow("refuses missing accountsFor",
    { mailStore: {}, methods: {} },
    "mail-server-jmap/no-accounts-for");
}

async function testDispatchHappyPath() {
  var calls = [];
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: { "core": "A1" }, accounts: { A1: { name: "x" } } }; },
    methods: {
      "Core/echo": async function (actor, args) {
        calls.push({ actor: actor, args: args });
        return { hi: args.hi };
      },
    },
  });
  var rv = await jmap.dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 42 }, "c0"]],
  });
  check("response has methodResponses",
    Array.isArray(rv.methodResponses) && rv.methodResponses.length === 1);
  check("response echoes clientId",
    rv.methodResponses[0][2] === "c0");
  check("response carries result",
    rv.methodResponses[0][1].hi === 42);
  check("sessionState included",
    typeof rv.sessionState === "string" && rv.sessionState.length > 0);
  check("handler received actor", calls[0].actor.id === "actor1");
}

async function testBackRefResolution() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: {
      "First/get":  async function () { return { list: [{ id: "x1" }, { id: "x2" }] }; },
      "Second/use": async function (actor, args) { return { received: args }; },
    },
  });
  var rv = await jmap.dispatch({ id: "a" }, {
    using:       [],
    methodCalls: [
      ["First/get",  {}, "c0"],
      ["Second/use", { "#fromFirst": { resultOf: "c0", name: "First/get", path: "/list/0/id" } }, "c1"],
    ],
  });
  // The back-reference `#fromFirst` resolves to "x1" — the resolved
  // arg under key "fromFirst" should be "x1".
  check("backref resolved to nested value",
    rv.methodResponses[1][1].received.fromFirst === "x1");
}

async function testBadBackRefRefused() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: {
      "First/get": async function () { return { list: [] }; },
      "Second/x":  async function () { return {}; },
    },
  });
  // Back-ref points at a non-existent path
  var rv = await jmap.dispatch({ id: "a" }, {
    using:       [],
    methodCalls: [
      ["First/get", {}, "c0"],
      ["Second/x",  { "#bad": { resultOf: "c0", name: "First/get", path: "/list/99/id" } }, "c1"],
    ],
  });
  check("second call surfaces invalidResultReference",
    rv.methodResponses[1][0] === "error" &&
    rv.methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");
}

async function testUnknownMethod() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: {},
  });
  var rv = await jmap.dispatch({ id: "a" }, {
    using:       [],
    methodCalls: [["Mailbox/get", { accountId: "A1" }, "c0"]],
  });
  check("unknownMethod returned for unwired method",
    rv.methodResponses[0][0] === "error" &&
    rv.methodResponses[0][1].type === "urn:ietf:params:jmap:error:unknownMethod");
}

async function testMethodThrewMaskedAsServerFail() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: {
      "Boom/now": async function () { throw new Error("internal stack-trace SHOULD NOT LEAK"); },
    },
  });
  var rv = await jmap.dispatch({ id: "a" }, {
    using:       [],
    methodCalls: [["Boom/now", {}, "c0"]],
  });
  check("method throw masked as serverFail",
    rv.methodResponses[0][0] === "error" &&
    rv.methodResponses[0][1].type === "urn:ietf:params:jmap:error:serverFail");
  check("internal stack trace not leaked in description",
    !/internal stack-trace/.test(rv.methodResponses[0][1].description));
}

async function testNoActorRefused() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: {},
  });
  var rv = await jmap.dispatch(null, {
    using:       [],
    methodCalls: [["X", {}, "c0"]],
  });
  check("no-actor → forbidden",
    rv.type === "urn:ietf:params:jmap:error:forbidden");
}

async function run() {
  testSurface();
  testBadOptsRefused();
  await testDispatchHappyPath();
  await testBackRefResolution();
  await testBadBackRefRefused();
  await testUnknownMethod();
  await testMethodThrewMaskedAsServerFail();
  await testNoActorRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap] OK"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
