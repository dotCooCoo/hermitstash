// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var nodeHttp = require("node:http");

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

// ---- Cross-tenant accountId gate (RFC 8620 §3.6.1 accountNotFound) ----
//
// accountsFor(actor) is the authorization source; a method call / blob op
// that names an accountId outside the actor's enumerated set is rejected
// with `accountNotFound` BEFORE the operator handler runs, so a tenant
// can't read/write another tenant's account.

async function testDispatchForeignAccountRefused() {
  var reached = false;
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    // Actor A is enumerated for A1 only.
    accountsFor: async function () { return { primaryAccounts: { core: "A1" }, accounts: { A1: { name: "tenant-a" } } }; },
    methods: {
      "Mailbox/get": async function () { reached = true; return { list: [] }; },
    },
  });
  // Tenant A references tenant B's accountId (B9).
  var rv = await jmap.dispatch({ id: "actor-a", tenantId: "tenant-a" }, {
    using:       [],
    methodCalls: [["Mailbox/get", { accountId: "B9" }, "c0"]],
  });
  check("foreign accountId → accountNotFound",
    rv.methodResponses[0][0] === "error" &&
    rv.methodResponses[0][1].type === "urn:ietf:params:jmap:error:accountNotFound");
  check("foreign accountId → method handler NOT reached", reached === false);
  check("response echoes clientId on the gate error",
    rv.methodResponses[0][2] === "c0");
}

async function testDispatchOwnAccountAllowed() {
  var reached = false;
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: { core: "A1" }, accounts: { A1: { name: "tenant-a" } } }; },
    methods: {
      "Mailbox/get": async function (actor, args) { reached = true; return { accountId: args.accountId, list: [] }; },
    },
  });
  var rv = await jmap.dispatch({ id: "actor-a" }, {
    using:       [],
    methodCalls: [["Mailbox/get", { accountId: "A1" }, "c0"]],
  });
  check("own accountId → handler reached", reached === true);
  check("own accountId → no error", rv.methodResponses[0][0] === "Mailbox/get");
}

async function testDispatchForeignFromAccountRefused() {
  // A /copy method (RFC 8620 §5.4) names TWO accounts: the destination
  // `accountId` and the SOURCE `fromAccountId` (read from). The cross-tenant
  // gate must validate BOTH — checking only the destination let a tenant name
  // a foreign source account and copy (read) another tenant's data.
  var reached = false;
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    // Actor A is enumerated for A1 only.
    accountsFor: async function () { return { primaryAccounts: { core: "A1" }, accounts: { A1: { name: "tenant-a" } } }; },
    methods: {
      "Email/copy": async function () { reached = true; return { created: {} }; },
    },
  });
  // Destination A1 is the actor's own, but the SOURCE B9 belongs to tenant B.
  var rv = await jmap.dispatch({ id: "actor-a", tenantId: "tenant-a" }, {
    using:       [],
    methodCalls: [["Email/copy", { fromAccountId: "B9", accountId: "A1", create: {} }, "c0"]],
  });
  check("Email/copy foreign fromAccountId → accountNotFound",
    rv.methodResponses[0][0] === "error" &&
    rv.methodResponses[0][1].type === "urn:ietf:params:jmap:error:accountNotFound");
  check("Email/copy foreign fromAccountId → handler NOT reached", reached === false);
}

async function testDispatchOwnFromAccountAllowed() {
  // Both the source and destination accounts are the actor's own → allowed.
  var reached = false;
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () {
      return { primaryAccounts: { core: "A1" }, accounts: { A1: { name: "tenant-a" }, A2: { name: "tenant-a-2" } } };
    },
    methods: {
      "Email/copy": async function () { reached = true; return { created: {} }; },
    },
  });
  var rv = await jmap.dispatch({ id: "actor-a" }, {
    using:       [],
    methodCalls: [["Email/copy", { fromAccountId: "A1", accountId: "A2", create: {} }, "c0"]],
  });
  check("Email/copy own source+dest accounts → handler reached", reached === true);
  check("Email/copy own source+dest accounts → no gate error",
    rv.methodResponses[0][0] === "Email/copy");
}

async function testDispatchAccountAgnosticMethodAllowed() {
  // A call with no accountId (account-agnostic) passes the gate unchanged.
  var reached = false;
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: {
      "Core/echo": async function (actor, args) { reached = true; return { hi: args.hi }; },
    },
  });
  var rv = await jmap.dispatch({ id: "actor-a" }, {
    using:       [],
    methodCalls: [["Core/echo", { hi: 7 }, "c0"]],
  });
  check("account-agnostic method → handler reached", reached === true);
  check("account-agnostic method → result returned", rv.methodResponses[0][1].hi === 7);
}

async function testUploadForeignAccountRefused() {
  var backendHit = false;
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      uploadBlob: function () { backendHit = true; return Promise.resolve({ blobId: "x" }); },
    },
    accountsFor: async function () { return { accounts: { A1: { name: "tenant-a" } } }; },
    methods: {},
  });
  // Upload targeting tenant B's accountId (B9).
  var mr = _makeUploadReqRes("/jmap/upload/B9", "text/plain", [Buffer.from("hi")]);
  jmap.uploadHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  await new Promise(function (r) { setImmediate(r); });
  check("upload foreign accountId → 404",            mr.res._status() === 404);
  check("upload foreign accountId → accountNotFound", /jmap:error:accountNotFound/.test(mr.res._buf()));
  check("upload foreign accountId → backend NOT hit", backendHit === false);
}

async function testDownloadForeignAccountRefused() {
  var backendHit = false;
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob: function () { backendHit = true; return Promise.resolve({ bytes: Buffer.from("x"), type: "text/plain" }); },
    },
    accountsFor: async function () { return { accounts: { A1: { name: "tenant-a" } } }; },
    methods: {},
  });
  // Download targeting tenant B's accountId (B9).
  var mr = _makeUploadReqRes("/jmap/download/B9/blob_42/note.txt", null, []);
  jmap.downloadHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  await new Promise(function (r) { setImmediate(r); });
  check("download foreign accountId → 404",            mr.res._status() === 404);
  check("download foreign accountId → accountNotFound", /jmap:error:accountNotFound/.test(mr.res._buf()));
  check("download foreign accountId → backend NOT hit", backendHit === false);
}

// ---- v0.11.29 — JMAP Push (EventSource SSE per RFC 8620 §7.3) ----

function _makeMockReqRes(url) {
  var resBuf = "";
  var resHeaders = {};
  var statusCode = 200;
  var listeners = {};
  var ended = false;
  var req = {
    url:     url,
    user:    { id: "u1" },
    on:      function (ev, fn) { listeners[ev] = listeners[ev] || []; listeners[ev].push(fn); },
    _fire:   function (ev) { (listeners[ev] || []).forEach(function (fn) { try { fn(); } catch (_e) {} }); },
  };
  var res = {
    get statusCode() { return statusCode; },
    set statusCode(v) { statusCode = v; },
    setHeader: function (k, v) { resHeaders[k.toLowerCase()] = v; },
    write:    function (chunk) { resBuf += chunk; },
    end:      function (chunk) { if (chunk) resBuf += chunk; ended = true; },
    _buf:     function () { return resBuf; },
    _headers: function () { return resHeaders; },
    _status:  function () { return statusCode; },
    _ended:   function () { return ended; },
  };
  return { req: req, res: res };
}

function testEventSourceHandlerExists() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  check("eventSourceHandler exposed", typeof jmap.eventSourceHandler === "function");
}

function testEventSourceRefusesUnauthenticated() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, subscribePush: function () { return Promise.resolve(); } },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeMockReqRes("/jmap/eventsource");
  mr.req.user = null;
  jmap.eventSourceHandler(mr.req, mr.res);
  check("unauthenticated → 401",         mr.res._status() === 401);
  check("401 carries forbidden type",    /jmap:error:forbidden/.test(mr.res._buf()));
}

function testEventSourceRefusesWithoutBackend() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },                                                       // no subscribePush
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeMockReqRes("/jmap/eventsource");
  jmap.eventSourceHandler(mr.req, mr.res);
  check("no backend → 503",              mr.res._status() === 503);
  check("503 carries serverUnavailable", /jmap:error:serverUnavailable/.test(mr.res._buf()));
}

async function testEventSourceStreamHeadersAndConnect() {
  var subscribeCalls = [];
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, types, emitFn) {
        subscribeCalls.push({ actor: actor, types: types, emitFn: emitFn });
        return Promise.resolve(function () { /* unsub */ });
      },
    },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeMockReqRes("/jmap/eventsource?types=Email,Mailbox&closeafter=no&ping=60");
  jmap.eventSourceHandler(mr.req, mr.res);
  // Wait for the subscribePush promise chain to settle.
  await new Promise(function (r) { setImmediate(r); });
  var h = mr.res._headers();
  check("Content-Type text/event-stream", /^text\/event-stream/.test(h["content-type"] || ""));
  check("Cache-Control no-cache",          h["cache-control"] === "no-cache");
  check("Connection keep-alive",           h["connection"] === "keep-alive");
  check("X-Accel-Buffering no",            h["x-accel-buffering"] === "no");
  check("buffer carries retry hint",       /retry: 5000/.test(mr.res._buf()));
  check("buffer carries connected comment", /: connected/.test(mr.res._buf()));
  check("subscribePush called once",       subscribeCalls.length === 1);
  check("subscribePush received types",
        subscribeCalls[0].types && subscribeCalls[0].types[0] === "Email" &&
        subscribeCalls[0].types[1] === "Mailbox");
  mr.req._fire("close");
}

async function testEventSourceWildcardTypes() {
  var subscribed = null;
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, types) { subscribed = types; return Promise.resolve(); },
    },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeMockReqRes("/jmap/eventsource?types=*");
  jmap.eventSourceHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(r); });
  check("types=* → backend gets null (wildcard)", subscribed === null);
  mr.req._fire("close");
}

async function testEventSourceStateChangeAndCloseAfter() {
  var emitFn = null;
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, types, fn) {
        emitFn = fn;
        return Promise.resolve();
      },
    },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeMockReqRes("/jmap/eventsource?closeafter=state");
  jmap.eventSourceHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(r); });
  // Push a StateChange — handler MUST emit `event: state` and close.
  emitFn({ kind: "StateChange", changed: { "A1": { Email: "abc" } } });
  check("state event emitted",
        /event: state/.test(mr.res._buf()) && /"@type":"StateChange"/.test(mr.res._buf()));
  check("closeafter=state closes stream",  mr.res._ended() === true);
}

async function testEventSourcePingZeroDisables() {
  // Codex P1 — RFC 8620 §7.3: `ping=0` is the explicit opt-out for
  // the keepalive event channel. Server MUST NOT clamp it to the
  // default and start emitting ping frames.
  var emitFn = null;
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, types, fn) { emitFn = fn; return Promise.resolve(); },
    },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeMockReqRes("/jmap/eventsource?ping=0");
  jmap.eventSourceHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(r); });
  // Backend got subscribed but no setInterval should have fired.
  // We can't easily fake-clock here without a heavier harness, so
  // assert structurally: the handler is alive (emit-fn is set) AND
  // the response buffer carries the initial `: connected` comment
  // but NO ping events.
  check("ping=0 → subscribePush still called",   typeof emitFn === "function");
  check("ping=0 → connected comment present",    /: connected/.test(mr.res._buf()));
  check("ping=0 → no event: ping in initial buffer", !/event: ping/.test(mr.res._buf()));
  mr.req._fire("close");
}

function testEventSourceBadCloseAfter() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, subscribePush: function () { return Promise.resolve(); } },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeMockReqRes("/jmap/eventsource?closeafter=banana");
  jmap.eventSourceHandler(mr.req, mr.res);
  check("invalid closeafter → 400",      mr.res._status() === 400);
  check("400 cites invalidArguments",    /jmap:error:invalidArguments/.test(mr.res._buf()));
}

// ---- v0.11.30 — JMAP blob upload + download (RFC 8620 §6) ----

function _makeUploadReqRes(url, contentType, bodyChunks) {
  var resBuf = "";
  var resHeaders = {};
  var statusCode = 200;
  var listeners = {};
  var ended = false;
  var req = {
    url:     url,
    user:    { id: "u1" },
    headers: { "content-type": contentType || "application/octet-stream" },
    on:      function (ev, fn) { listeners[ev] = listeners[ev] || []; listeners[ev].push(fn); },
    destroy: function () { (listeners["error"] || []).forEach(function (fn) { try { fn(new Error("destroyed")); } catch (_e) {} }); },
    _fire:   function (ev, arg) { (listeners[ev] || []).forEach(function (fn) { try { fn(arg); } catch (_e) {} }); },
  };
  var res = {
    get statusCode() { return statusCode; },
    set statusCode(v) { statusCode = v; },
    setHeader: function (k, v) { resHeaders[k.toLowerCase()] = v; },
    write:    function (chunk) { resBuf += chunk; },
    end:      function (chunk) { if (chunk) resBuf += chunk; ended = true; },
    _buf:     function () { return resBuf; },
    _headers: function () { return resHeaders; },
    _status:  function () { return statusCode; },
    _ended:   function () { return ended; },
  };
  // Schedule the body chunks to be delivered after the handler installs its listeners.
  setImmediate(function () {
    (bodyChunks || []).forEach(function (chunk) { req._fire("data", chunk); });
    req._fire("end");
  });
  return { req: req, res: res };
}

async function testUploadHandlerHappyPath() {
  var uploads = [];
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      uploadBlob: function (actor, accountId, type, bytes) {
        uploads.push({ actor: actor, accountId: accountId, type: type, size: bytes.length });
        return Promise.resolve({ blobId: "blob_42", type: type, size: bytes.length });
      },
    },
    accountsFor: async function () { return { accounts: { A1: { name: "x" } } }; },
    methods: {},
  });
  var body = Buffer.from("Hello, blob world.");
  var mr = _makeUploadReqRes("/jmap/upload/A1", "text/plain", [body]);
  jmap.uploadHandler(mr.req, mr.res);
  // Wait for setImmediate + handler resolution.
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  await new Promise(function (r) { setImmediate(r); });
  check("upload → 201 Created",                    mr.res._status() === 201);
  check("upload → JSON body with blobId",
        /"blobId":"blob_42"/.test(mr.res._buf()));
  check("upload → accountId echoed",               /"accountId":"A1"/.test(mr.res._buf()));
  check("upload → backend called once",            uploads.length === 1);
  check("upload → bytes forwarded byte-equal",     uploads[0].size === body.length);
  check("upload → content-type forwarded",         uploads[0].type === "text/plain");
}

async function testUploadHandlerOversizeRefused() {
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      uploadBlob: function () { return Promise.resolve({ blobId: "x" }); },
    },
    accountsFor: async function () { return {}; },
    methods: {},
    maxBlobBytes: 64,                                                                                  // allow:raw-byte-literal — tight test cap
  });
  var bigBody = Buffer.alloc(200, 0x41);                                                                // allow:raw-byte-literal — 'A' fill
  var mr = _makeUploadReqRes("/jmap/upload/A1", "application/octet-stream", [bigBody]);
  jmap.uploadHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  check("upload oversize → 413",                   mr.res._status() === 413);
  check("upload oversize → limit:maxSizeUpload",   /"limit":"maxSizeUpload"/.test(mr.res._buf()));
}

function testUploadHandlerRefusesUnauth() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, uploadBlob: function () { return Promise.resolve({ blobId: "x" }); } },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeUploadReqRes("/jmap/upload/A1", "text/plain", [Buffer.from("x")]);
  mr.req.user = null;
  jmap.uploadHandler(mr.req, mr.res);
  check("upload unauth → 401",                     mr.res._status() === 401);
  check("upload unauth → forbidden type",          /jmap:error:forbidden/.test(mr.res._buf()));
}

function testUploadHandlerWithoutBackend() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },                                                       // no uploadBlob
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeUploadReqRes("/jmap/upload/A1", "text/plain", [Buffer.from("x")]);
  jmap.uploadHandler(mr.req, mr.res);
  check("upload no-backend → 503",                 mr.res._status() === 503);
  check("upload no-backend → serverUnavailable",   /jmap:error:serverUnavailable/.test(mr.res._buf()));
}

function testUploadHandlerRefusesBadAccountId() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, uploadBlob: function () { return Promise.resolve({ blobId: "x" }); } },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  // accountId with disallowed chars (path traversal shape).
  var mr = _makeUploadReqRes("/jmap/upload/..%2Fevil", "text/plain", []);
  jmap.uploadHandler(mr.req, mr.res);
  check("upload bad accountId → 400",              mr.res._status() === 400);
  check("upload bad accountId → invalidArguments", /jmap:error:invalidArguments/.test(mr.res._buf()));
}

async function testDownloadHandlerHappyPath() {
  var calls = [];
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob: function (actor, accountId, blobId) {
        calls.push({ accountId: accountId, blobId: blobId });
        return Promise.resolve({ bytes: Buffer.from("hello blob"), type: "text/plain" });
      },
    },
    accountsFor: async function () { return { accounts: { A1: { name: "x" } } }; },
    methods: {},
  });
  var mr = _makeUploadReqRes("/jmap/download/A1/blob_42/note.txt", null, []);
  jmap.downloadHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  check("download → 200",                          mr.res._status() === 200);
  check("download → content-type from backend",    mr.res._headers()["content-type"] === "text/plain");
  check("download → body bytes match",             /hello blob/.test(mr.res._buf()));
  check("download → backend got accountId+blobId",
        calls[0].accountId === "A1" && calls[0].blobId === "blob_42");
  check("download → Content-Disposition attachment",
        /attachment; filename="note\.txt"/.test(mr.res._headers()["content-disposition"] || ""));
}

async function testDownloadHandlerMalformedUrl() {
  // Codex P2 — A URL like `/jmap/download/A1/B1` (missing the `name`
  // segment) MUST refuse with 400 invalidArguments, not silently
  // remap (accountId="download", blobId="A1", name="B1").
  var calls = [];
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob: function (_a, accountId, blobId) {
        calls.push({ accountId: accountId, blobId: blobId });
        return Promise.resolve({ bytes: Buffer.from("x"), type: "text/plain" });
      },
    },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeUploadReqRes("/jmap/download/A1/B1", null, []);
  jmap.downloadHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  check("download missing name → 400",         mr.res._status() === 400);
  check("download malformed → invalidArguments", /jmap:error:invalidArguments/.test(mr.res._buf()));
  check("download malformed → backend not called", calls.length === 0);
}

async function testJmapIdAcceptsFullLength() {
  // Codex P1 — JMAP Id is up to 255 octets. Upload + download MUST
  // accept the full spec length, not refuse at 64.
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      uploadBlob: function () { return Promise.resolve({ blobId: "B" }); },
      downloadBlob: function () { return Promise.resolve({ bytes: Buffer.from("x"), type: "text/plain" }); },
    },
    // The full-length accountId is enumerated for the actor so the gate
    // permits it; this test exercises the JMAP Id length cap, not authz.
    accountsFor: async function () {
      var id = "A".repeat(200);                                                                       // allow:raw-byte-literal — 200 chars, under RFC 8620 §1.2 255 cap
      var accts = {}; accts[id] = { name: "x" };
      return { accounts: accts };
    },
    methods: {},
  });
  var longId = "A".repeat(200);                                                                       // allow:raw-byte-literal — 200 chars, under RFC 8620 §1.2 255 cap
  var mrUp = _makeUploadReqRes("/jmap/upload/" + longId, "text/plain", [Buffer.from("hi")]);
  jmap.uploadHandler(mrUp.req, mrUp.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  check("upload accepts 200-char accountId",   mrUp.res._status() === 201);
  var mrDn = _makeUploadReqRes("/jmap/download/" + longId + "/blob_42/note.txt", null, []);
  jmap.downloadHandler(mrDn.req, mrDn.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  check("download accepts 200-char accountId", mrDn.res._status() === 200);
  // 256+ chars still refuse.
  var tooLongId = "A".repeat(256);                                                                    // allow:raw-byte-literal — 256 chars, just over the cap
  var mrTooLong = _makeUploadReqRes("/jmap/upload/" + tooLongId, "text/plain", [Buffer.from("hi")]);
  jmap.uploadHandler(mrTooLong.req, mrTooLong.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  check("upload refuses 256+ accountId",       mrTooLong.res._status() === 400);
}

async function testDownloadHandlerNotFound() {
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob: function () { return Promise.resolve(null); },
    },
    accountsFor: async function () { return { accounts: { A1: { name: "x" } } }; },
    methods: {},
  });
  var mr = _makeUploadReqRes("/jmap/download/A1/missing/note.txt", null, []);
  jmap.downloadHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  check("download missing → 404",                  mr.res._status() === 404);
  check("download missing → blob-not-found (not account gate)",
        /Blob not found/.test(mr.res._buf()));
}

function testDownloadHandlerRefusesUnauth() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, downloadBlob: function () {} },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeUploadReqRes("/jmap/download/A1/blob/note.txt", null, []);
  mr.req.user = null;
  jmap.downloadHandler(mr.req, mr.res);
  check("download unauth → 401",                   mr.res._status() === 401);
}

function testDownloadHandlerWithoutBackend() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeUploadReqRes("/jmap/download/A1/blob/note.txt", null, []);
  jmap.downloadHandler(mr.req, mr.res);
  check("download no-backend → 503",               mr.res._status() === 503);
}

// ---- v0.11.34 — JMAP WebSocket transport (RFC 8887) ----

function testWebSocketHandlerExposed() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  check("webSocketHandler exposed", typeof jmap.webSocketHandler === "function");
}

function testWebSocketHandlerRefusesUnauthenticated() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, subscribePush: function () { return Promise.resolve(); } },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  // Mock socket — record what's written.
  var writes = "";
  var destroyed = false;
  var sock = {
    write: function (b) { writes += b; },
    destroy: function () { destroyed = true; },
    on: function () {},
    once: function () {},
  };
  var req = { user: null, url: "/jmap/ws", headers: {} };
  jmap.webSocketHandler(req, sock, Buffer.alloc(0));
  check("unauth → 401 written",                /^HTTP\/1\.1 401/.test(writes));
  check("unauth → socket destroyed",            destroyed === true);
}

// ---- Handlers driven over REAL localhost connections ----
//
// JMAP is HTTP-mounted (RFC 8620), so the Express-style handlers
// (apiHandler / sessionHandler / discoveryHandler / eventSourceHandler /
// uploadHandler / downloadHandler) are mounted on a real node:http server
// and driven with genuine HTTP requests + a real WebSocket client
// (b.wsClient) for the RFC 8887 webSocketHandler — exercising the
// wrong-state / malformed / backend-failure / resource-limit / cross-tenant
// refusals over the wire.

// ---- global handle tracking (WS clients + upgrade sockets + servers) ----
var _httpServers = [];
var _wsClients   = [];
var _wsSockets   = [];

function _actorFrom(req, cfg) {
  if (cfg.noActor) return null;
  var h = req.headers["x-actor"];
  if (h === "none")   return null;
  if (h === "idonly") return { id: "uid-9" };
  if (h === "empty")  return {};
  return cfg.actor || { id: "u1", username: "alice" };
}

// Mount every JMAP handler on a real node:http server. Body-consuming
// apiHandler reads the request body first (simulating b.middleware.bodyParser);
// the streaming upload/download/eventsource handlers own their own req stream.
function _startHttp(jmap, cfg) {
  cfg = cfg || {};
  var server = nodeHttp.createServer(function (req, res) {
    req.user = _actorFrom(req, cfg);
    if (cfg.params) req.params = cfg.params;
    var path = String(req.url || "").split("?")[0];
    if (cfg.forceDownload) { jmap.downloadHandler(req, res); return; }
    if (cfg.forceUpload)   { jmap.uploadHandler(req, res); return; }
    if (path === "/jmap/session")      { jmap.sessionHandler(req, res); return; }
    if (path === "/.well-known/jmap")  { jmap.discoveryHandler(req, res); return; }
    if (path === "/jmap/eventsource")  { jmap.eventSourceHandler(req, res); return; }
    if (path.indexOf("/jmap/upload/") === 0)   { jmap.uploadHandler(req, res); return; }
    if (path.indexOf("/jmap/download/") === 0) { jmap.downloadHandler(req, res); return; }
    if (path === "/jmap/api") {
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        var raw = Buffer.concat(chunks).toString("utf8");
        // Leave req.body UNDEFINED on an empty body so the "body missing"
        // branch is reachable; otherwise hand apiHandler the parsed object.
        if (raw.length > 0) { try { req.body = JSON.parse(raw); } catch (_e) { req.body = raw; } }
        jmap.apiHandler(req, res);
      });
      return;
    }
    res.statusCode = 404; res.end();
  });
  server.on("upgrade", function (req, socket, head) {
    _wsSockets.push(socket);
    req.user = _actorFrom(req, cfg);
    jmap.webSocketHandler(req, socket, head);
  });
  _httpServers.push(server);
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { resolve({ server: server, port: server.address().port }); });
  });
}

function _stop(server) {
  return new Promise(function (resolve) { try { server.close(function () { resolve(); }); } catch (_e) { resolve(); } });
}

// One HTTP request → { status, headers, body(string) }. agent:false so each
// request uses a fresh socket that closes (no keep-alive handle leak).
function _req(port, opts) {
  opts = opts || {};
  return new Promise(function (resolve, reject) {
    var r = nodeHttp.request({
      host: "127.0.0.1", port: port, method: opts.method || "GET",
      path: opts.path, headers: opts.headers || {}, agent: false,
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    r.on("error", reject);
    if (opts.body != null) r.write(opts.body);
    r.end();
  });
}

// Tolerant request — resolves { refused:true } if the socket resets (the
// oversize-upload responder writes 413 then destroys the request stream, a
// respond-then-reset race). Either a 413 read OR a reset proves refusal.
function _reqSafe(port, opts) {
  return _req(port, opts).then(
    function (r) { return r; },
    function (_e) { return { refused: true, status: 0, headers: {}, body: "" }; }
  );
}

// Open an SSE / streaming response; resolve on the response head so we can
// read status + a live-growing buffer, then abort.
function _openSse(port, path, headers) {
  return new Promise(function (resolve, reject) {
    var r = nodeHttp.request({
      host: "127.0.0.1", port: port, method: "GET", path: path, headers: headers || {}, agent: false,
    }, function (res) {
      var buf = ""; var closed = false;
      res.on("data",  function (c) { buf += c.toString("utf8"); });
      res.on("end",   function () { closed = true; });
      res.on("close", function () { closed = true; });
      res.on("error", function () { closed = true; });
      resolve({
        status: res.statusCode, headers: res.headers,
        read: function () { return buf; },
        isClosed: function () { return closed; },
        abort: function () { try { r.destroy(); } catch (_e) { /* best-effort */ } },
      });
    });
    r.on("error", reject);
    r.end();
  });
}

function _wsConnect(port, opts) {
  var client = b.wsClient.connect("ws://127.0.0.1:" + port + "/jmap/ws",
    Object.assign({ subprotocols: ["jmap"], reconnect: false, audit: false, allowInternal: true }, opts || {}));
  _wsClients.push(client);
  return client;
}

var DEFAULT_ACCOUNTS = async function () {
  return { primaryAccounts: { core: "A1" }, accounts: { A1: { name: "tenant-a" } } };
};

// ==========================================================================
// 1. sessionHandler (RFC 8620 §2)
// ==========================================================================
async function testSessionHandler() {
  // 1a. default caps inject the websocket transport (no operator ws cap)
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    var r = await _req(s.port, { path: "/jmap/session" });
    check("session → 200", r.status === 200);
    check("session content-type json", /application\/json/.test(r.headers["content-type"] || ""));
    var sess = JSON.parse(r.body);
    check("session advertises default websocket cap",
      sess.capabilities["urn:ietf:params:jmap:websocket"] &&
      sess.capabilities["urn:ietf:params:jmap:websocket"].url === "/jmap/ws");
    check("session core cap present", !!sess.capabilities["urn:ietf:params:jmap:core"]);
    check("session accounts echoed", sess.accounts.A1 && sess.accounts.A1.name === "tenant-a");
    check("session primaryAccounts echoed", sess.primaryAccounts.core === "A1");
    check("session apiUrl default", sess.apiUrl === "/jmap/api");
    check("session username from actor.username", sess.username === "alice");
    check("session state present", typeof sess.state === "string" && sess.state.length > 0);

    // 1b. username falls back to actor.id, then "unknown"
    var rId = await _req(s.port, { path: "/jmap/session", headers: { "x-actor": "idonly" } });
    check("session username falls back to actor.id", JSON.parse(rId.body).username === "uid-9");
    var rEmpty = await _req(s.port, { path: "/jmap/session", headers: { "x-actor": "empty" } });
    check("session username falls back to 'unknown'", JSON.parse(rEmpty.body).username === "unknown");

    // 1c. unauthenticated → 401 forbidden
    var rNo = await _req(s.port, { path: "/jmap/session", headers: { "x-actor": "none" } });
    check("session unauth → 401", rNo.status === 401);
    check("session unauth → forbidden type", /jmap:error:forbidden/.test(rNo.body));
  } finally { await _stop(s.server); }

  // 1d. operator-supplied websocket cap → NOT overwritten + urlEndpointResolution set
  var jmapWs = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: {},
    serverCapabilities: { "urn:ietf:params:jmap:websocket": { url: "/operator/ws", supportsPush: false } },
  });
  var sWs = await _startHttp(jmapWs, {});
  try {
    var rw = await _req(sWs.port, { path: "/jmap/session" });
    var sessw = JSON.parse(rw.body);
    check("session keeps operator websocket cap",
      sessw.capabilities["urn:ietf:params:jmap:websocket"].url === "/operator/ws");
    check("session urlEndpointResolution present when operator ws cap set",
      sessw.urlEndpointResolution && sessw.urlEndpointResolution.useEndpoint === "/jmap/ws");
  } finally { await _stop(sWs.server); }

  // 1e. accountsFor returns null → defaults; and accountsFor rejects → 500
  var jmapNull = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return null; },
    methods: {},
  });
  var sNull = await _startHttp(jmapNull, {});
  try {
    var rn = await _req(sNull.port, { path: "/jmap/session" });
    check("session accountInfo null → 200 with empty accounts",
      rn.status === 200 && JSON.stringify(JSON.parse(rn.body).accounts) === "{}");
  } finally { await _stop(sNull.server); }

  var jmapThrow = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { throw new Error("accountsFor boom"); },
    methods: {},
  });
  var sThrow = await _startHttp(jmapThrow, {});
  try {
    var rt = await _req(sThrow.port, { path: "/jmap/session" });
    check("session accountsFor throw → 500", rt.status === 500);
    check("session accountsFor throw → serverFail", /jmap:error:serverFail/.test(rt.body));
  } finally { await _stop(sThrow.server); }
}

// ==========================================================================
// 2. discoveryHandler (RFC 8620 §2.2) — 302 redirect
// ==========================================================================
async function testDiscoveryHandler() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    var r = await _req(s.port, { path: "/.well-known/jmap" });
    check("discovery → 302", r.status === 302);
    check("discovery → Location /jmap/session", r.headers["location"] === "/jmap/session");
  } finally { await _stop(s.server); }

  var jmapCustom = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
    sessionUrl: "/custom/session",
  });
  var sc = await _startHttp(jmapCustom, {});
  try {
    var rc = await _req(sc.port, { path: "/.well-known/jmap" });
    check("discovery custom sessionUrl honored", rc.headers["location"] === "/custom/session");
  } finally { await _stop(sc.server); }
}

// ==========================================================================
// 3. apiHandler (RFC 8620 §3.3) over HTTP — refusal / error status mapping
// ==========================================================================
async function testApiHandler() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: {
      "Core/echo": async function (actor, args) { return { hi: args.hi }; },
      "Op/err":    async function () { return { type: "urn:ietf:params:jmap:error:invalidArguments", description: "operator says no" }; },
    },
  });
  var s = await _startHttp(jmap, {});
  try {
    // 3a. body missing (bodyParser not run) → 400
    var rNoBody = await _req(s.port, { method: "POST", path: "/jmap/api" });
    check("api missing body → 400", rNoBody.status === 400);
    check("api missing body → invalidArguments", /request body missing/.test(rNoBody.body));

    // 3b. happy 200
    var rOk = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [["Core/echo", { hi: 7 }, "c0"]] }),
    });
    check("api happy → 200", rOk.status === 200);
    var okBody = JSON.parse(rOk.body);
    check("api happy → result echoed", okBody.methodResponses[0][1].hi === 7);
    check("api happy → sessionState", typeof okBody.sessionState === "string");

    // 3c. guard refusal (no `using`) → 400 invalidArguments
    var rBad = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ methodCalls: [["Core/echo", {}, "c0"]] }),
    });
    check("api guard-refusal → 400", rBad.status === 400);
    check("api guard-refusal → invalidArguments", /jmap:error:invalidArguments/.test(rBad.body));

    // 3d. no actor → forbidden mapped to 401
    var rForbidden = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json", "x-actor": "none" },
      body: JSON.stringify({ using: [], methodCalls: [["Core/echo", {}, "c0"]] }),
    });
    check("api no-actor → 401", rForbidden.status === 401);
    check("api no-actor → forbidden", /jmap:error:forbidden/.test(rForbidden.body));

    // 3e. operator-emitted error shape → preserved (200, error inside)
    var rOpErr = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [["Op/err", {}, "c0"]] }),
    });
    check("api operator-error-shape → 200", rOpErr.status === 200);
    var opErrBody = JSON.parse(rOpErr.body);
    check("api operator-error-shape preserved",
      opErrBody.methodResponses[0][0] === "error" &&
      opErrBody.methodResponses[0][1].type === "urn:ietf:params:jmap:error:invalidArguments");
  } finally { await _stop(s.server); }

  // 3f. accountsFor throws inside dispatch → serverFail refusal (mapped 400)
  var jmapAcctThrow = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { throw new Error("acct boom"); },
    methods: { "Core/echo": async function () { return {}; } },
  });
  var sat = await _startHttp(jmapAcctThrow, {});
  try {
    var rat = await _req(sat.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [["Core/echo", {}, "c0"]] }),
    });
    check("api accountsFor-throw → 400 (serverFail refusal)", rat.status === 400);
    check("api accountsFor-throw → serverFail", /jmap:error:serverFail/.test(rat.body));
    check("api accountsFor-throw → account authorization unavailable",
      /account authorization unavailable/.test(rat.body));
  } finally { await _stop(sat.server); }
}

// ==========================================================================
// 4. Back-reference resolution + JSON-Pointer edge cases (RFC 8620 §3.7 /
//    RFC 6901) — driven through apiHandler over HTTP
// ==========================================================================
async function testBackRefsAndPointer() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: {
      "First/get":  async function () {
        return { list: [{ id: "x1" }, { id: "x2" }], name: "n", s: "str", "a/b": "slash", "c~d": "tilde" };
      },
      "Second/use": async function (actor, args) { return { received: args }; },
    },
  });
  var s = await _startHttp(jmap, {});
  try {
    // 4a. pointer edges that SUCCEED (whole result / array-* / escapes / nested)
    var rv = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", {
          "#whole": { resultOf: "c0", name: "First/get", path: "" },
          "#arr":   { resultOf: "c0", name: "First/get", path: "/list/*" },
          "#first": { resultOf: "c0", name: "First/get", path: "/list/0/id" },
          "#sl":    { resultOf: "c0", name: "First/get", path: "/a~1b" },
          "#ti":    { resultOf: "c0", name: "First/get", path: "/c~0d" },
        }, "c1"],
      ] }),
    });
    var got = JSON.parse(rv.body).methodResponses[1][1].received;
    check("backref path='' resolves whole result", got.whole && got.whole.name === "n");
    check("backref path='/list/*' resolves array", Array.isArray(got.arr) && got.arr.length === 2);
    check("backref path='/list/0/id' resolves scalar", got.first === "x1");
    check("backref ~1 escape → '/'", got.sl === "slash");
    check("backref ~0 escape → '~'", got.ti === "tilde");

    // 4b. pointer into a NON-object (string) → undefined → invalidResultReference
    var rNon = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#x": { resultOf: "c0", name: "First/get", path: "/s/foo" } }, "c1"],
      ] }),
    });
    check("backref into non-object → invalidResultReference",
      JSON.parse(rNon.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4c. malformed back-ref value (missing `path`) → invalidResultReference
    var rMissing = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#bad": { resultOf: "c0", name: "First/get" } }, "c1"],
      ] }),
    });
    check("backref missing path → invalidResultReference",
      JSON.parse(rMissing.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4d. back-ref value is an ARRAY (not the { resultOf, name, path } object)
    var rArr = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#bad": [1, 2, 3] }, "c1"],
      ] }),
    });
    check("backref value-is-array → invalidResultReference",
      JSON.parse(rArr.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4e. back-ref name mismatch (prior clientId produced a different method)
    var rName = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#bad": { resultOf: "c0", name: "Other/get", path: "/list/0/id" } }, "c1"],
      ] }),
    });
    check("backref name-mismatch → invalidResultReference",
      JSON.parse(rName.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4e2. back-ref array index is non-numeric → undefined → invalidResultReference
    var rNaN = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [
        ["First/get", {}, "c0"],
        ["Second/use", { "#bad": { resultOf: "c0", name: "First/get", path: "/list/notanum/id" } }, "c1"],
      ] }),
    });
    check("backref non-numeric array index → invalidResultReference",
      JSON.parse(rNaN.body).methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");

    // 4f. unknown method → unknownMethod
    var rUnknown = await _req(s.port, {
      method: "POST", path: "/jmap/api", headers: { "content-type": "application/json" },
      body: JSON.stringify({ using: [], methodCalls: [["Nope/nope", {}, "c0"]] }),
    });
    check("unknown method → unknownMethod",
      JSON.parse(rUnknown.body).methodResponses[0][1].type === "urn:ietf:params:jmap:error:unknownMethod");
  } finally { await _stop(s.server); }
}

// ==========================================================================
// 5. uploadHandler (RFC 8620 §6.1) over HTTP
// ==========================================================================
async function testUploadHandler() {
  // 5a. happy 201 + meta defaults (uploadBlob returns no type/size → defaults)
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      uploadBlob: function (actor, accountId, type, bytes) { return Promise.resolve({ blobId: "blob_1" }); },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    var rOk = await _req(s.port, {
      method: "POST", path: "/jmap/upload/A1", headers: { "content-type": "text/plain" }, body: "hello",
    });
    check("upload happy → 201", rOk.status === 201);
    var meta = JSON.parse(rOk.body);
    check("upload meta type defaults to content-type", meta.type === "text/plain");
    check("upload meta size defaults to byte length", meta.size === 5);
    check("upload echoes accountId", meta.accountId === "A1");

    // 5b. default content-type when no header
    var rNoCt = await _req(s.port, { method: "POST", path: "/jmap/upload/A1", body: "x" });
    check("upload no content-type → octet-stream default", JSON.parse(rNoCt.body).type === "application/octet-stream");

    // 5c. malformed accountId (path-traversal shape) → 400
    var rBadId = await _req(s.port, { method: "POST", path: "/jmap/upload/..%2Fevil", body: "x" });
    check("upload bad accountId → 400", rBadId.status === 400);
    check("upload bad accountId → invalidArguments", /jmap:error:invalidArguments/.test(rBadId.body));

    // 5d. over-long URL (> 8 KiB) → segments empty → 400
    var longSeg = "a"; for (var i = 0; i < 14; i += 1) longSeg += longSeg;   // ~16 KiB
    var rLong = await _req(s.port, { method: "POST", path: "/jmap/upload/" + longSeg.slice(0, 8300), body: "x" });
    check("upload over-long URL → 400", rLong.status === 400);
    check("upload over-long URL → cap message", /exceeds the/.test(rLong.body));

    // 5e. foreign accountId → 404 accountNotFound
    var rForeign = await _req(s.port, { method: "POST", path: "/jmap/upload/B9", body: "x" });
    check("upload foreign accountId → 404", rForeign.status === 404);
    check("upload foreign accountId → accountNotFound", /jmap:error:accountNotFound/.test(rForeign.body));

    // 5f. unauthenticated → 401
    var rUnauth = await _req(s.port, { method: "POST", path: "/jmap/upload/A1", headers: { "x-actor": "none" }, body: "x" });
    check("upload unauth → 401", rUnauth.status === 401);
  } finally { await _stop(s.server); }

  // 5g. no uploadBlob backend → 503
  var jmapNoBackend = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sNb = await _startHttp(jmapNoBackend, {});
  try {
    var rNb = await _req(sNb.port, { method: "POST", path: "/jmap/upload/A1", body: "x" });
    check("upload no-backend → 503", rNb.status === 503);
    check("upload no-backend → serverUnavailable", /jmap:error:serverUnavailable/.test(rNb.body));
  } finally { await _stop(sNb.server); }

  // 5h. oversize body → refused (413 branch runs server-side; client sees 413 or reset)
  var jmapCap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, uploadBlob: function () { return Promise.resolve({ blobId: "x" }); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {}, maxBlobBytes: b.constants.BYTES.bytes(16),
  });
  var sCap = await _startHttp(jmapCap, {});
  try {
    var rOver = await _reqSafe(sCap.port, { method: "POST", path: "/jmap/upload/A1", body: Buffer.alloc(64, 0x41) });
    check("upload oversize → not accepted (refused)", rOver.status !== 201);
    check("upload oversize → 413 or connection reset",
      rOver.status === 413 || rOver.refused === true);
  } finally { await _stop(sCap.server); }

  // 5i. uploadBlob returns bad meta (no blobId) → 500 serverFail
  var jmapBadMeta = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, uploadBlob: function () { return Promise.resolve({}); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sBad = await _startHttp(jmapBadMeta, {});
  try {
    var rBadMeta = await _req(sBad.port, { method: "POST", path: "/jmap/upload/A1", body: "x" });
    check("upload bad-meta → 500", rBadMeta.status === 500);
    check("upload bad-meta → serverFail", /jmap:error:serverFail/.test(rBadMeta.body));
  } finally { await _stop(sBad.server); }

  // 5j. uploadBlob throws → 500 serverFail
  var jmapThrow = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, uploadBlob: function () { return Promise.reject(new Error("upload boom")); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sTh = await _startHttp(jmapThrow, {});
  try {
    var rTh = await _req(sTh.port, { method: "POST", path: "/jmap/upload/A1", body: "x" });
    check("upload backend-throw → 500", rTh.status === 500);
    check("upload backend-throw → serverFail", /jmap:error:serverFail/.test(rTh.body));
  } finally { await _stop(sTh.server); }

  // 5k. router-supplied req.params.accountId path is honored
  var uploadedAcct = null;
  var jmapParams = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      uploadBlob: function (actor, accountId) { uploadedAcct = accountId; return Promise.resolve({ blobId: "x" }); },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sParam = await _startHttp(jmapParams, { forceUpload: true, params: { accountId: "A1" } });
  try {
    var rp = await _req(sParam.port, { method: "POST", path: "/anything/here", body: "x" });
    check("upload router-supplied params.accountId honored → 201", rp.status === 201 && uploadedAcct === "A1");
  } finally { await _stop(sParam.server); }
}

// ==========================================================================
// 6. downloadHandler (RFC 8620 §6.2) over HTTP
// ==========================================================================
async function testDownloadHandler() {
  // 6a. happy 5-seg path (+ Content-Disposition) and raw-Buffer / accept branch
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob: function (actor, accountId, blobId) {
        if (blobId === "rawbuf") return Promise.resolve(Buffer.from("rawbytes"));
        if (blobId === "notbuf") return Promise.resolve({ bytes: "not-a-buffer" });
        if (blobId === "missing") return Promise.resolve(null);
        if (blobId === "boom") return Promise.reject(new Error("download boom"));
        return Promise.resolve({ bytes: Buffer.from("hello blob"), type: "text/plain" });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    var rOk = await _req(s.port, { path: "/jmap/download/A1/blob_1/note.txt" });
    check("download happy → 200", rOk.status === 200);
    check("download content-type from backend", (rOk.headers["content-type"] || "") === "text/plain");
    check("download body bytes", rOk.body === "hello blob");
    check("download Content-Disposition attachment",
      /attachment; filename="note\.txt"/.test(rOk.headers["content-disposition"] || ""));

    // 6b. invalid filename segment → no Content-Disposition
    var rNoDisp = await _req(s.port, { path: "/jmap/download/A1/blob_1/no,te" });
    check("download invalid filename → no disposition", !rNoDisp.headers["content-disposition"]);

    // 6c. raw Buffer result + ?accept type
    var rRaw = await _req(s.port, { path: "/jmap/download/A1/rawbuf/f.bin?accept=application/x-test" });
    check("download raw Buffer + accept → 200", rRaw.status === 200);
    check("download raw Buffer uses accept type", (rRaw.headers["content-type"] || "") === "application/x-test");
    check("download raw Buffer body", rRaw.body === "rawbytes");

    // 6d. malformed %-encoded accept is drop-silent (still 200 octet-stream)
    var rBadAccept = await _req(s.port, { path: "/jmap/download/A1/rawbuf/f.bin?accept=%zz" });
    check("download malformed accept drop-silent → 200", rBadAccept.status === 200);
    check("download malformed accept → octet-stream default",
      (rBadAccept.headers["content-type"] || "") === "application/octet-stream");

    // 6e. non-Buffer backend body → 500
    var rNotBuf = await _req(s.port, { path: "/jmap/download/A1/notbuf/f.bin" });
    check("download non-Buffer body → 500", rNotBuf.status === 500);
    check("download non-Buffer → serverFail", /non-Buffer body/.test(rNotBuf.body));

    // 6f. null backend result → 404 blob-not-found
    var rMissing = await _req(s.port, { path: "/jmap/download/A1/missing/f.bin" });
    check("download null result → 404", rMissing.status === 404);
    check("download null result → Blob not found", /Blob not found/.test(rMissing.body));

    // 6g. backend throws → 500
    var rBoom = await _req(s.port, { path: "/jmap/download/A1/boom/f.bin" });
    check("download backend-throw → 500", rBoom.status === 500);
    check("download backend-throw → serverFail", /jmap:error:serverFail/.test(rBoom.body));

    // 6h. malformed accountId segment → 400
    var rBadAcct = await _req(s.port, { path: "/jmap/download/..%2Fx/blob_1/f.bin" });
    check("download malformed accountId → 400", rBadAcct.status === 400);
    check("download malformed accountId → invalidArguments", /malformed accountId/.test(rBadAcct.body));

    // 6i. malformed blobId segment → 400
    var rBadBlob = await _req(s.port, { path: "/jmap/download/A1/..%2Fx/f.bin" });
    check("download malformed blobId → 400", rBadBlob.status === 400);
    check("download malformed blobId → invalidArguments", /malformed blobId/.test(rBadBlob.body));

    // 6j. missing name segment (only 4 real segments → not 3, not 5+) → 400
    var rShort = await _req(s.port, { path: "/jmap/download/A1/blob_1" });
    check("download missing name segment → 400", rShort.status === 400);

    // 6k. over-long URL → 400
    var lp = "a"; for (var i = 0; i < 14; i += 1) lp += lp;
    var rLong = await _req(s.port, { path: "/jmap/download/A1/blob_1/" + lp.slice(0, 8300) });
    check("download over-long URL → 400", rLong.status === 400);
    check("download over-long URL → cap message", /exceeds the/.test(rLong.body));

    // 6l. foreign accountId → 404 accountNotFound
    var rForeign = await _req(s.port, { path: "/jmap/download/B9/blob_1/f.bin" });
    check("download foreign accountId → 404", rForeign.status === 404);
    check("download foreign accountId → accountNotFound", /jmap:error:accountNotFound/.test(rForeign.body));

    // 6m. unauthenticated → 401
    var rUnauth = await _req(s.port, { path: "/jmap/download/A1/blob_1/f.bin", headers: { "x-actor": "none" } });
    check("download unauth → 401", rUnauth.status === 401);
  } finally { await _stop(s.server); }

  // 6n. no downloadBlob backend → 503
  var jmapNb = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sNb = await _startHttp(jmapNb, {});
  try {
    var rNb = await _req(sNb.port, { path: "/jmap/download/A1/blob_1/f.bin" });
    check("download no-backend → 503", rNb.status === 503);
  } finally { await _stop(sNb.server); }

  // 6o. router-stripped 3-segment path ({accountId}/{blobId}/{name})
  var strippedCall = null;
  var jmapStrip = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob: function (actor, accountId, blobId) {
        strippedCall = { accountId: accountId, blobId: blobId };
        return Promise.resolve({ bytes: Buffer.from("s"), type: "text/plain" });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sStrip = await _startHttp(jmapStrip, { forceDownload: true });
  try {
    var rStrip = await _req(sStrip.port, { path: "/A1/blob_9/note.txt" });
    check("download router-stripped 3-seg → 200", rStrip.status === 200);
    check("download router-stripped mapped segments",
      strippedCall && strippedCall.accountId === "A1" && strippedCall.blobId === "blob_9");
  } finally { await _stop(sStrip.server); }
}

// ==========================================================================
// 7. eventSourceHandler (RFC 8620 §7.3, SSE) over HTTP
// ==========================================================================
async function testEventSource() {
  // 7a. no subscribePush backend → 503
  var jmapNb = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sNb = await _startHttp(jmapNb, {});
  try {
    var rNb = await _req(sNb.port, { path: "/jmap/eventsource" });
    check("eventsource no-backend → 503", rNb.status === 503);
    check("eventsource no-backend → serverUnavailable", /jmap:error:serverUnavailable/.test(rNb.body));

    // 7b. unauth → 401
    var rUn = await _req(sNb.port, { path: "/jmap/eventsource", headers: { "x-actor": "none" } });
    check("eventsource unauth → 401", rUn.status === 401);
  } finally { await _stop(sNb.server); }

  // 7c. invalid closeafter → 400 (subscribePush present so we pass the 503 gate)
  var jmapBadCa = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, subscribePush: function () { return Promise.resolve(); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sCa = await _startHttp(jmapBadCa, {});
  try {
    var rCa = await _req(sCa.port, { path: "/jmap/eventsource?closeafter=banana" });
    check("eventsource bad closeafter → 400", rCa.status === 400);
    check("eventsource bad closeafter → invalidArguments", /jmap:error:invalidArguments/.test(rCa.body));
  } finally { await _stop(sCa.server); }

  // 7d. full SSE stream: headers + connected + StateChange emit + unsubscribe
  var captured = {};
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, types, emitFn) {
        captured.types = types; captured.emit = emitFn;
        return Promise.resolve(function () { captured.unsub = true; });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    // ping=1000 exercises the >900 clamp; %zz key exercises decode drop-silent;
    // `flag` (no '=') exercises the eq===-1 branch.
    var sse = await _openSse(s.port, "/jmap/eventsource?types=Email,Mailbox&ping=1000&%zz=bad&flag");
    check("eventsource → 200", sse.status === 200);
    check("eventsource content-type event-stream", /text\/event-stream/.test(sse.headers["content-type"] || ""));
    check("eventsource cache-control no-cache", sse.headers["cache-control"] === "no-cache");
    check("eventsource X-Accel-Buffering no", sse.headers["x-accel-buffering"] === "no");
    await helpers.waitUntil(function () { return typeof captured.emit === "function"; },
      { timeoutMs: 5000, label: "eventsource: subscribePush emitFn captured" });
    check("eventsource connected comment present", /: connected/.test(sse.read()));
    check("eventsource types forwarded", captured.types && captured.types[0] === "Email");
    // push a StateChange over the real stream
    captured.emit({ kind: "StateChange", changed: { A1: { Email: "s1" } } });
    await helpers.waitUntil(function () { return /event: state/.test(sse.read()); },
      { timeoutMs: 5000, label: "eventsource: state event delivered" });
    check("eventsource StateChange delivered",
      /event: state/.test(sse.read()) && /"@type":"StateChange"/.test(sse.read()));
    // non-StateChange event is ignored (no crash)
    captured.emit({ kind: "Other" });
    captured.emit(null);
    // abort → req 'close' → cleanup → unsubscribe invoked
    sse.abort();
    await helpers.waitUntil(function () { return captured.unsub === true; },
      { timeoutMs: 5000, label: "eventsource: unsubscribe after client close" });
    check("eventsource unsubscribe called on client close", captured.unsub === true);
  } finally { await _stop(s.server); }

  // 7e. closeafter=state → stream closes after first StateChange
  var cap2 = {};
  var jmap2 = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, types, emitFn) { cap2.emit = emitFn; return Promise.resolve(); },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s2 = await _startHttp(jmap2, {});
  try {
    var sse2 = await _openSse(s2.port, "/jmap/eventsource?closeafter=state&ping=0");
    await helpers.waitUntil(function () { return typeof cap2.emit === "function"; },
      { timeoutMs: 5000, label: "eventsource closeafter: emitFn captured" });
    cap2.emit({ kind: "StateChange", changed: { A1: { Email: "s2" } } });
    await helpers.waitUntil(function () { return sse2.isClosed(); },
      { timeoutMs: 5000, label: "eventsource closeafter=state: stream closed" });
    check("eventsource closeafter=state → closed after event",
      sse2.isClosed() && /event: state/.test(sse2.read()));
  } finally { await _stop(s2.server); }

  // 7f. subscribePush rejects → handler cleans up (stream closes)
  var jmap3 = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function () { return Promise.reject(new Error("subscribe boom")); },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s3 = await _startHttp(jmap3, {});
  try {
    var sse3 = await _openSse(s3.port, "/jmap/eventsource");
    check("eventsource subscribe-reject: 200 headers already sent", sse3.status === 200);
    await helpers.waitUntil(function () { return sse3.isClosed(); },
      { timeoutMs: 5000, label: "eventsource subscribe-reject: stream cleaned up" });
    check("eventsource subscribe-reject → stream closed", sse3.isClosed());
  } finally { await _stop(s3.server); }
}

// ==========================================================================
// 8. webSocketHandler (RFC 8887) over a REAL b.wsClient connection
// ==========================================================================
function _wsWait(client, until, label) {
  return helpers.waitUntil(until, { timeoutMs: 5000, label: label });
}

async function testWebSocket() {
  var captured = {};
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, dataTypes, emitFn) {
        captured.emit = emitFn; return Promise.resolve(function () { captured.unsub = true; });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: { "Core/echo": async function (actor, args) { return { hi: args.hi }; } },
  });
  var s = await _startHttp(jmap, {});
  try {
    var client = _wsConnect(s.port);
    var msgs = [];
    var errSeen = null;
    client.on("message", function (d) { msgs.push(typeof d === "string" ? d : d.toString("utf8")); });
    client.on("error", function (e) { errSeen = e; });
    await _wsWait(client, function () { return client.readyState === "open"; }, "ws: open");
    check("ws negotiated jmap subprotocol", client.subprotocol === "jmap");

    // 8a. valid Request → Response
    client.send(JSON.stringify({ "@type": "Request", id: "r1", using: [], methodCalls: [["Core/echo", { hi: 9 }, "c0"]] }));
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: response received");
    var resp = JSON.parse(msgs[0]);
    check("ws Request → Response @type", resp["@type"] === "Response");
    check("ws Response echoes requestId", resp.requestId === "r1");
    check("ws Response carries methodResponses", resp.methodResponses[0][1].hi === 9);

    // 8b. binary frame → RequestError notJSON
    msgs.length = 0;
    client.send(Buffer.from([0x00, 0x01, 0x02]));
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: binary refused");
    check("ws binary frame → RequestError notJSON",
      JSON.parse(msgs[0])["@type"] === "RequestError" && /notJSON/.test(msgs[0]));

    // 8c. non-JSON text frame → RequestError notJSON
    msgs.length = 0;
    client.send("this is not json {");
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: bad json refused");
    check("ws non-JSON text → RequestError notJSON",
      JSON.parse(msgs[0])["@type"] === "RequestError" && /not valid JSON/.test(msgs[0]));

    // 8d. Request that fails envelope validation → RequestError (not empty Response)
    msgs.length = 0;
    client.send(JSON.stringify({ "@type": "Request", id: "r2", using: [], methodCalls: [] }));
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: invalid request refused");
    check("ws invalid Request → RequestError",
      JSON.parse(msgs[0])["@type"] === "RequestError");
    check("ws invalid Request → requestId echoed", JSON.parse(msgs[0]).requestId === "r2");

    // 8e. unknown @type → RequestError unknownDataType
    msgs.length = 0;
    client.send(JSON.stringify({ "@type": "Bogus", id: "r3" }));
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: unknown type refused");
    check("ws unknown @type → unknownDataType",
      /unknownDataType/.test(msgs[0]) && JSON.parse(msgs[0]).requestId === "r3");

    // 8f. WebSocketPushEnable → StateChange push; duplicate enable is a no-op
    client.send(JSON.stringify({ "@type": "WebSocketPushEnable", dataTypes: ["Email"] }));
    await _wsWait(client, function () { return typeof captured.emit === "function"; }, "ws: push enabled");
    client.send(JSON.stringify({ "@type": "WebSocketPushEnable" }));   // duplicate no-op
    msgs.length = 0;
    captured.emit({ kind: "StateChange", changed: { A1: { Email: "sc" } } });
    captured.emit(null);           // guard: !event
    captured.emit({ kind: "Nope" }); // non-StateChange ignored
    await _wsWait(client, function () { return msgs.length >= 1; }, "ws: statechange pushed");
    check("ws StateChange pushed", JSON.parse(msgs[0])["@type"] === "StateChange");

    // 8g. WebSocketPushDisable → unsubscribe invoked
    client.send(JSON.stringify({ "@type": "WebSocketPushDisable" }));
    await _wsWait(client, function () { return captured.unsub === true; }, "ws: push disabled/unsub");
    check("ws PushDisable → unsubscribe called", captured.unsub === true);

    check("ws no client error over the exchange", errSeen === null);
    client.close(1000, "bye");
    await _wsWait(client, function () { return client.readyState === "closed"; }, "ws: closed");
  } finally { await _stop(s.server); }

  // 8h. WebSocketPushEnable with no subscribePush backend → serverUnavailable
  var jmapNoPush = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sNp = await _startHttp(jmapNoPush, {});
  try {
    var c2 = _wsConnect(sNp.port);
    var m2 = [];
    c2.on("message", function (d) { m2.push(typeof d === "string" ? d : d.toString("utf8")); });
    c2.on("error", function () {});
    await _wsWait(c2, function () { return c2.readyState === "open"; }, "ws(no-push): open");
    c2.send(JSON.stringify({ "@type": "WebSocketPushEnable" }));
    await _wsWait(c2, function () { return m2.length >= 1; }, "ws(no-push): serverUnavailable");
    check("ws PushEnable no-backend → serverUnavailable", /serverUnavailable/.test(m2[0]));
    c2.close(1000, "bye");
  } finally { await _stop(sNp.server); }

  // 8i. WebSocketPushEnable whose subscribePush REJECTS → serverFail + rollback
  var jmapReject = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, subscribePush: function () { return Promise.reject(new Error("sub reject")); } },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sRj = await _startHttp(jmapReject, {});
  try {
    var c3 = _wsConnect(sRj.port);
    var m3 = [];
    c3.on("message", function (d) { m3.push(typeof d === "string" ? d : d.toString("utf8")); });
    c3.on("error", function () {});
    await _wsWait(c3, function () { return c3.readyState === "open"; }, "ws(reject): open");
    c3.send(JSON.stringify({ "@type": "WebSocketPushEnable" }));
    await _wsWait(c3, function () { return m3.length >= 1; }, "ws(reject): serverFail");
    check("ws PushEnable subscribe-reject → serverFail",
      JSON.parse(m3[0])["@type"] === "RequestError" && /serverFail/.test(m3[0]));
    c3.close(1000, "bye");
  } finally { await _stop(sRj.server); }

  // 8j. unauthenticated upgrade → 401 handshake refusal (client sees error)
  var jmapUn = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var sUn = await _startHttp(jmapUn, { noActor: true });
  try {
    var c4 = _wsConnect(sUn.port);
    var err4 = null; var closed4 = false;
    c4.on("error", function (e) { err4 = e; });
    c4.on("close", function () { closed4 = true; });
    await _wsWait(c4, function () { return err4 !== null || closed4; }, "ws(unauth): handshake refused");
    check("ws unauth handshake → client error/close", err4 !== null || closed4);
  } finally { await _stop(sUn.server); }
}

// ---- teardown: force every WS client + socket down, wait for TCP drain ----
async function _drainTcpHandles() {
  _wsClients.forEach(function (c) {
    try { c.cancelReconnect(); } catch (_e) { /* best-effort */ }
    try { c.close(); } catch (_e) { /* best-effort */ }
    try { c._teardown(b.wsClient.CLOSE_NORMAL, "", false); } catch (_e) { /* best-effort */ }
  });
  _wsSockets.forEach(function (sock) {
    try { if (sock && !sock.destroyed) sock.destroy(); } catch (_e) { /* best-effort */ }
  });
  await Promise.all(_httpServers.map(function (srv) {
    return new Promise(function (res) {
      try { if (typeof srv.closeAllConnections === "function") srv.closeAllConnections(); } catch (_e) { /* best-effort */ }
      try { srv.close(function () { res(); }); } catch (_e) { res(); }
    });
  }));
  _wsClients = []; _wsSockets = []; _httpServers = [];
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "mail-server-jmap: TCP handle drain after run" });
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
  // Cross-tenant accountId gate (RFC 8620 §3.6.1 accountNotFound)
  await testDispatchForeignAccountRefused();
  await testDispatchForeignFromAccountRefused();
  await testDispatchOwnFromAccountAllowed();
  await testDispatchOwnAccountAllowed();
  await testDispatchAccountAgnosticMethodAllowed();
  await testDispatchArrayArgsRecursion();
  await testDispatchMethodEntryNonFunctionSkipped();
  await testDispatchAccountGateEdges();
  await testDispatchBackRefMissingObjectKey();
  await testUploadForeignAccountRefused();
  await testDownloadForeignAccountRefused();
  // v0.11.29 — JMAP Push (EventSource SSE per RFC 8620 §7.3)
  testEventSourceHandlerExists();
  testEventSourceRefusesUnauthenticated();
  testEventSourceRefusesWithoutBackend();
  await testEventSourceStreamHeadersAndConnect();
  await testEventSourceWildcardTypes();
  await testEventSourceStateChangeAndCloseAfter();
  await testEventSourcePingZeroDisables();
  testEventSourceBadCloseAfter();
  await testEventSourceSendThrowCleansUp();
  await testEventSourceSubscribeAfterClose();
  await testEventSourcePingTickEmits();
  // v0.11.30 — blob upload + download
  await testUploadHandlerHappyPath();
  await testUploadHandlerOversizeRefused();
  testUploadHandlerRefusesUnauth();
  testUploadHandlerWithoutBackend();
  testUploadHandlerRefusesBadAccountId();
  await testUploadHandlerReqError();
  await testDownloadHandlerHappyPath();
  await testDownloadHandlerNotFound();
  testDownloadHandlerRefusesUnauth();
  testDownloadHandlerWithoutBackend();
  await testDownloadHandlerMalformedUrl();
  await testJmapIdAcceptsFullLength();
  // v0.11.34 — JMAP WebSocket transport (RFC 8887)
  testWebSocketHandlerExposed();
  testWebSocketHandlerRefusesUnauthenticated();
  // v0.11.38 — EmailSubmission/set reference handler
  await testEmailSubmissionSetHappyPath();
  await testEmailSubmissionSetForbiddenMailFrom();
  await testEmailSubmissionSetEmailNotFound();
  await testEmailSubmissionSetNoRecipients();
  await testEmailSubmissionSetTooManyRecipients();
  await testEmailSubmissionSetInvalidRecipient();
  await testEmailSubmissionSetIdentityNotFound();
  await testEmailSubmissionSetUpdateOnlyHonorsUndoStatus();
  await testEmailSubmissionSetUpdateCannotUnsendWithoutOnCancel();
  await testEmailSubmissionSetDestroy();
  testEmailSubmissionSetRefusesBadOpts();
  await testEmailSubmissionSetBadMaxRecipients();
  await testEmailSubmissionSetMissingAccountId();
  await testEmailSubmissionSetCreateValidationErrors();
  await testEmailSubmissionSetUpdatePatchNotObject();
  await testEmailSubmissionSetUpdateOnCancelOutcomes();
  await testEmailSubmissionSetDestroyEdges();
  await testEmailSubmissionSetDeliveryStatusVariants();
  await testEmailSubmissionSetCreateDeliverThrows();
  await testEmailSubmissionSetOnCreatedThrows();
  await testEmailSubmissionSetIdentitiesReturnsNull();
  // Handlers driven over real localhost HTTP + WebSocket connections
  var wtt = helpers.withTestTimeout;
  try {
    await wtt("session handler",   testSessionHandler);
    await wtt("discovery handler", testDiscoveryHandler);
    await wtt("api handler",       testApiHandler);
    await wtt("backrefs+pointer",  testBackRefsAndPointer);
    await wtt("upload handler",    testUploadHandler);
    await wtt("download handler",  testDownloadHandler);
    await wtt("event source",      testEventSource);
    await wtt("web socket",        testWebSocket);
    await wtt("download router params", testDownloadRouterSuppliedParams);
    await wtt("ws non-jmap subprotocol", testWebSocketNonJmapSubprotocol);
    await wtt("ws push lifecycle edges", testWebSocketPushLifecycleEdges);
  } finally {
    await _drainTcpHandles();
  }
}

function _makeESHandler(overrides) {
  var deliveries = [];
  var fakeDeliver = async function (env) {
    deliveries.push(env);
    return {
      delivered: env.to.map(function (r) { return { recipient: r, smtpReply: "250 ok" }; }),
      deferred:  [],
      failed:    [],
    };
  };
  var base = {
    deliver:     fakeDeliver,
    lookupEmail: async function (id) {
      return id === "missing" ? null : Buffer.from("From: ops@x.com\r\n\r\nbody");
    },
    identities: function () {
      return [{ id: "I1", email: "ops@example.com" }];
    },
  };
  var merged = Object.assign({}, base);
  if (overrides) Object.keys(overrides).forEach(function (k) { merged[k] = overrides[k]; });
  return { handler: b.mail.server.jmap.emailSubmissionSetHandler(merged), deliveries: deliveries };
}

async function testEmailSubmissionSetHappyPath() {
  var onCreatedHits = [];
  var es = _makeESHandler({
    onCreated: async function (id, sub, accId) { onCreatedHits.push({ id: id, accId: accId }); },
  });
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: {
      identityId: "I1",
      emailId:    "E1",
      envelope: { mailFrom: { email: "ops@example.com" },
                  rcptTo:   [{ email: "alice@example.com" }] },
    } },
  }, {});
  check("EmailSubmission/set happy: created not null",  rv.created !== null);
  check("EmailSubmission/set happy: c1 has id",         typeof rv.created.c1.id === "string");
  check("EmailSubmission/set happy: undoStatus final",  rv.created.c1.undoStatus === "final");
  check("EmailSubmission/set happy: deliveryStatus alice delivered",
    rv.created.c1.deliveryStatus["alice@example.com"].delivered === "yes");
  check("EmailSubmission/set happy: onCreated fired",   onCreatedHits.length === 1);
  check("EmailSubmission/set happy: deliver invoked with rcpt",
    es.deliveries.length === 1 && es.deliveries[0].to[0] === "alice@example.com");
  check("EmailSubmission/set happy: newState is opaque string", typeof rv.newState === "string" && rv.newState.length > 0);
}

async function testEmailSubmissionSetForbiddenMailFrom() {
  var es = _makeESHandler();
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: {
      identityId: "I1", emailId: "E1",
      envelope: { mailFrom: { email: "spoof@x.com" },
                  rcptTo:   [{ email: "alice@example.com" }] },
    } },
  }, {});
  check("forbiddenMailFrom returned", rv.notCreated && rv.notCreated.c1.type === "forbiddenMailFrom");
  check("no deliver invocation on forbidden", es.deliveries.length === 0);
}

async function testEmailSubmissionSetEmailNotFound() {
  var es = _makeESHandler();
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: {
      identityId: "I1", emailId: "missing",
      envelope: { mailFrom: { email: "ops@example.com" },
                  rcptTo:   [{ email: "alice@example.com" }] },
    } },
  }, {});
  check("emailNotFound returned", rv.notCreated && rv.notCreated.c1.type === "emailNotFound");
}

async function testEmailSubmissionSetNoRecipients() {
  var es = _makeESHandler();
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: {
      identityId: "I1", emailId: "E1",
      envelope: { mailFrom: { email: "ops@example.com" }, rcptTo: [] },
    } },
  }, {});
  check("noRecipients returned", rv.notCreated && rv.notCreated.c1.type === "noRecipients");
}

async function testEmailSubmissionSetTooManyRecipients() {
  var es = _makeESHandler({ maxRecipients: 2 });
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: {
      identityId: "I1", emailId: "E1",
      envelope: { mailFrom: { email: "ops@example.com" },
                  rcptTo:   [{ email: "a@x" }, { email: "b@x" }, { email: "c@x" }] },
    } },
  }, {});
  check("tooManyRecipients returned", rv.notCreated && rv.notCreated.c1.type === "tooManyRecipients");
}

async function testEmailSubmissionSetInvalidRecipient() {
  var es = _makeESHandler();
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: {
      identityId: "I1", emailId: "E1",
      envelope: { mailFrom: { email: "ops@example.com" },
                  rcptTo:   [{ email: "no-at-sign" }] },
    } },
  }, {});
  check("invalidRecipients returned", rv.notCreated && rv.notCreated.c1.type === "invalidRecipients");
}

async function testEmailSubmissionSetIdentityNotFound() {
  var es = _makeESHandler();
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: {
      identityId: "I-unknown", emailId: "E1",
      envelope: { mailFrom: { email: "ops@example.com" },
                  rcptTo:   [{ email: "a@x.com" }] },
    } },
  }, {});
  check("identityNotFound returned", rv.notCreated && rv.notCreated.c1.type === "identityNotFound");
}

async function testEmailSubmissionSetUpdateOnlyHonorsUndoStatus() {
  var es = _makeESHandler();
  var rv = await es.handler({}, {
    accountId: "A1",
    update: { S1: { identityId: "I2" } },
  }, {});
  check("invalidProperties on non-undoStatus update",
    rv.notUpdated && rv.notUpdated.S1.type === "invalidProperties" &&
    rv.notUpdated.S1.properties.indexOf("identityId") !== -1);

  var rv2 = await es.handler({}, {
    accountId: "A1",
    update: { S1: { undoStatus: "pending" } },
  }, {});
  check("non-canceled undoStatus refused",
    rv2.notUpdated && rv2.notUpdated.S1.type === "invalidProperties");
}

async function testEmailSubmissionSetUpdateCannotUnsendWithoutOnCancel() {
  var es = _makeESHandler();
  var rv = await es.handler({}, {
    accountId: "A1",
    update: { S1: { undoStatus: "canceled" } },
  }, {});
  check("cannotUnsend without onCancel", rv.notUpdated && rv.notUpdated.S1.type === "cannotUnsend");

  var cancelCalls = [];
  var es2 = _makeESHandler({
    onCancel: async function (subId, accId) { cancelCalls.push({ subId: subId, accId: accId }); return true; },
  });
  var rv2 = await es2.handler({}, {
    accountId: "A1",
    update: { S1: { undoStatus: "canceled" } },
  }, {});
  check("onCancel honored", rv2.updated && rv2.updated.S1 === null);
  check("onCancel called with subId", cancelCalls.length === 1 && cancelCalls[0].subId === "S1");
}

async function testEmailSubmissionSetDestroy() {
  var destroyed = [];
  var es = _makeESHandler({
    onDestroyed: async function (id, accId) { destroyed.push({ id: id, accId: accId }); },
  });
  var rv = await es.handler({}, {
    accountId: "A1",
    destroy: ["S1", "S2"],
  }, {});
  check("destroy returns array", Array.isArray(rv.destroyed) && rv.destroyed.length === 2);
  check("onDestroyed called per id",  destroyed.length === 2);
}

function testEmailSubmissionSetRefusesBadOpts() {
  function expectThrow(label, opts, codeMatch) {
    var threw = null;
    try { b.mail.server.jmap.emailSubmissionSetHandler(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses missing deliver",
    { lookupEmail: function () {}, identities: function () {} },
    "mail-server-jmap/no-deliver");
  expectThrow("refuses missing lookupEmail",
    { deliver: function () {}, identities: function () {} },
    "mail-server-jmap/no-lookup-email");
  expectThrow("refuses missing identities",
    { deliver: function () {}, lookupEmail: function () {} },
    "mail-server-jmap/no-identities");
}

// ==========================================================================
// Dispatch-level branches: array-arg recursion, non-fn method skip, account
// gate edge shapes, JSON-Pointer missing-key (RFC 8620 §3.6.1 / §3.7)
// ==========================================================================
async function testDispatchArrayArgsRecursion() {
  // Array-valued args force _resolveBackRefs down its Array.isArray branch,
  // recursing element-by-element (including nested objects/arrays).
  var received = null;
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: { "Bulk/set": async function (actor, args) { received = args; return { ok: true }; } },
  });
  var rv = await jmap.dispatch({ id: "a" }, {
    using: [], methodCalls: [["Bulk/set", { ids: ["x1", "x2", { nested: ["deep"] }] }, "c0"]],
  });
  check("array-valued args resolved intact through recursion",
    received && Array.isArray(received.ids) && received.ids[0] === "x1" &&
    received.ids[2] && received.ids[2].nested[0] === "deep");
  check("array-args method → non-error response", rv.methodResponses[0][0] === "Bulk/set");
}

async function testDispatchMethodEntryNonFunctionSkipped() {
  // A methods map entry whose value is not a function is skipped at registry
  // build time — it never registers, so a call to it is unknownMethod.
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: { "Good/x": async function () { return { ok: 1 }; }, "Bad/y": 12345 },
  });
  var rv = await jmap.dispatch({ id: "a" }, {
    using: [], methodCalls: [["Good/x", {}, "c0"], ["Bad/y", {}, "c1"]],
  });
  check("non-function method entry skipped (Good/x dispatches)",
    rv.methodResponses[0][0] === "Good/x" && rv.methodResponses[0][1].ok === 1);
  check("non-function method entry unregistered → unknownMethod",
    rv.methodResponses[1][0] === "error" &&
    rv.methodResponses[1][1].type === "urn:ietf:params:jmap:error:unknownMethod");
}

async function testDispatchAccountGateEdges() {
  // accountsFor returns null → empty permitted set → any named accountId is
  // rejected fail-closed (_permittedAccountIds info/accounts fallbacks).
  var jmapNull = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return null; },
    methods: { "Mailbox/get": async function () { return { list: [] }; } },
  });
  var rvNull = await jmapNull.dispatch({ id: "a" }, {
    using: [], methodCalls: [["Mailbox/get", { accountId: "A1" }, "c0"]],
  });
  check("accountsFor null → accountNotFound (fail-closed)",
    rvNull.methodResponses[0][1].type === "urn:ietf:params:jmap:error:accountNotFound");

  var reached = { nullId: false };
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: { A1: { name: "x" } } }; },
    methods: { "Mailbox/get": async function (actor, args) { reached.nullId = true; return { got: args.accountId }; } },
  });
  // accountId:null → the gate skips a null-valued *AccountId key (method runs).
  var rvNullAcc = await jmap.dispatch({ id: "a" }, {
    using: [], methodCalls: [["Mailbox/get", { accountId: null }, "c0"]],
  });
  check("accountId:null skips gate → method runs",
    reached.nullId === true && rvNullAcc.methodResponses[0][0] === "Mailbox/get");
  // non-string accountId (number) → denied with deniedAccountId coerced to null.
  var rvNum = await jmap.dispatch({ id: "a" }, {
    using: [], methodCalls: [["Mailbox/get", { accountId: 999 }, "c0"]],
  });
  check("non-string accountId → accountNotFound (denied)",
    rvNum.methodResponses[0][1].type === "urn:ietf:params:jmap:error:accountNotFound");
}

async function testDispatchBackRefMissingObjectKey() {
  // JSON-Pointer walk into an object that lacks the final segment → undefined
  // → invalidResultReference (the hasOwnProperty guard, not the array guard).
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: {
      "First/get":  async function () { return { list: [{ id: "x1" }] }; },
      "Second/use": async function (actor, args) { return { received: args }; },
    },
  });
  var rv = await jmap.dispatch({ id: "a" }, {
    using: [], methodCalls: [
      ["First/get", {}, "c0"],
      ["Second/use", { "#miss": { resultOf: "c0", name: "First/get", path: "/list/0/nope" } }, "c1"],
    ],
  });
  check("back-ref to missing object key → invalidResultReference",
    rv.methodResponses[1][1].type === "urn:ietf:params:jmap:error:invalidResultReference");
}

// ==========================================================================
// eventSourceHandler internal branches driven through a mock req/res:
// _send write-throw cleanup, subscribe-resolves-after-close, ping keepalive
// ==========================================================================
async function testEventSourceSendThrowCleansUp() {
  // A res.write that throws while emitting a `state` frame drives _send's
  // catch → _cleanup (the socket-torn-down path).
  var emitFn = null;
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (actor, types, fn) { emitFn = fn; return Promise.resolve(function () {}); },
    },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var status = 200; var ended = false; var listeners = {};
  var req = {
    url: "/jmap/eventsource?ping=0", user: { id: "u1" },
    on: function (ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); },
    _fire: function (ev) { (listeners[ev] || []).forEach(function (fn) { try { fn(); } catch (_e) { /* ignore */ } }); },
  };
  var res = {
    get statusCode() { return status; }, set statusCode(v) { status = v; },
    setHeader: function () {},
    write: function (chunk) { if (String(chunk).indexOf("event: state") === 0) throw new Error("socket gone"); },
    end: function () { ended = true; },
  };
  jmap.eventSourceHandler(req, res);
  await helpers.waitUntil(function () { return typeof emitFn === "function"; },
    { timeoutMs: 5000, label: "es-send-throw: subscribePush resolved" });
  emitFn({ kind: "StateChange", changed: { A1: { Email: "s" } } });
  check("SSE _send write-throw triggers cleanup (res.end called)", ended === true);
}

async function testEventSourceSubscribeAfterClose() {
  // Client disconnects (req 'close' → _cleanup, closed=true) BEFORE
  // subscribePush resolves → the late-resolving handle is unsubscribed.
  var resolveSub = null; var unsubCalled = false;
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function () { return new Promise(function (r) { resolveSub = r; }); },
    },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeMockReqRes("/jmap/eventsource?ping=0");
  jmap.eventSourceHandler(mr.req, mr.res);
  await helpers.waitUntil(function () { return typeof resolveSub === "function"; },
    { timeoutMs: 5000, label: "es-after-close: subscribePush invoked" });
  mr.req._fire("close");
  resolveSub(function () { unsubCalled = true; });
  await helpers.waitUntil(function () { return unsubCalled === true; },
    { timeoutMs: 5000, label: "es-after-close: late unsubscribe invoked" });
  check("SSE subscribe resolves after close → unsubscribe invoked", unsubCalled === true);
}

async function testEventSourcePingTickEmits() {
  // ping=5 is the RFC 8620 §7.3 floor; the keepalive interval fires an
  // `event: ping` frame carrying the negotiated interval. Genuine timer
  // latency (5 s min) — polled via waitUntil.
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function () { return Promise.resolve(function () {}); },
    },
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeMockReqRes("/jmap/eventsource?ping=5");
  jmap.eventSourceHandler(mr.req, mr.res);
  try {
    await helpers.waitUntil(function () { return /event: ping/.test(mr.res._buf()); },
      { timeoutMs: 8000, label: "es-ping: keepalive ping frame emitted" });
    check("SSE ping keepalive frame emitted with interval",
      /event: ping/.test(mr.res._buf()) && /"interval":5/.test(mr.res._buf()));
  } finally {
    mr.req._fire("close");   // clears the ping interval
  }
}

// ==========================================================================
// uploadHandler req 'error' event → 400 abort
// ==========================================================================
async function testUploadHandlerReqError() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {}, uploadBlob: function () { return Promise.resolve({ blobId: "x" }); } },
    accountsFor: async function () { return { accounts: { A1: { name: "x" } } }; },
    methods: {},
  });
  var status = 200; var ended = false; var listeners = {};
  var req = {
    url: "/jmap/upload/A1", user: { id: "u1" }, headers: { "content-type": "text/plain" },
    on: function (ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); },
    _fire: function (ev, a) { (listeners[ev] || []).forEach(function (fn) { try { fn(a); } catch (_e) { /* ignore */ } }); },
  };
  var res = {
    get statusCode() { return status; }, set statusCode(v) { status = v; },
    setHeader: function () {}, write: function () {}, end: function () { ended = true; },
  };
  jmap.uploadHandler(req, res);
  req._fire("error", new Error("socket error mid-upload"));
  check("upload req 'error' → 400", status === 400);
  check("upload req 'error' → response ended", ended === true);
}

// ==========================================================================
// downloadHandler router-supplied req.params path (RFC 8620 §6.2)
// ==========================================================================
async function testDownloadRouterSuppliedParams() {
  var call = null;
  var jmap = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      downloadBlob: function (a, accountId, blobId) {
        call = { accountId: accountId, blobId: blobId };
        return Promise.resolve({ bytes: Buffer.from("rp"), type: "text/plain" });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, { forceDownload: true, params: { accountId: "A1", blobId: "blob_7", name: "n.txt" } });
  try {
    var r = await _req(s.port, { path: "/whatever/the/router/mounted" });
    check("download router-supplied params → 200", r.status === 200);
    check("download router-supplied maps params to backend",
      call && call.accountId === "A1" && call.blobId === "blob_7");
  } finally { await _stop(s.server); }
}

// ==========================================================================
// webSocketHandler: non-jmap subprotocol refusal (RFC 8887 §3.1)
// ==========================================================================
async function testWebSocketNonJmapSubprotocol() {
  var jmap = b.mail.server.jmap.create({
    mailStore: { appendMessage: function () {} }, accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s = await _startHttp(jmap, {});
  try {
    var client = _wsConnect(s.port, { subprotocols: ["not-jmap"] });
    var closed = false; var errSeen = null;
    client.on("close", function () { closed = true; });
    client.on("error", function (e) { errSeen = e; });
    await _wsWait(client, function () { return closed || errSeen !== null; },
      "ws non-jmap: server refused the connection");
    check("ws non-jmap subprotocol → server refused (closed/errored)", closed || errSeen !== null);
    check("ws non-jmap → never negotiated jmap", client.subprotocol !== "jmap");
  } finally { await _stop(s.server); }
}

// ==========================================================================
// webSocketHandler push lifecycle edges: late-cleanup when disabled during
// subscribe setup; unsubscribe on connection close (RFC 8887 §5)
// ==========================================================================
async function testWebSocketPushLifecycleEdges() {
  // (a) PushEnable, PushDisable, THEN subscribePush resolves → the deferred
  //     handle is torn down by the late-cleanup path (!pushEnabled).
  var cap = {};
  var jmapLate = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function () {
        cap.enableCalls = (cap.enableCalls || 0) + 1;
        return new Promise(function (r) { cap.resolveSub = r; });
      },
    },
    accountsFor: DEFAULT_ACCOUNTS,
    methods: { "Core/echo": async function (a, args) { return { hi: args.hi }; } },
  });
  var s = await _startHttp(jmapLate, {});
  try {
    var client = _wsConnect(s.port);
    var msgs = [];
    client.on("message", function (d) { msgs.push(typeof d === "string" ? d : d.toString("utf8")); });
    client.on("error", function () {});
    await _wsWait(client, function () { return client.readyState === "open"; }, "ws-late: open");
    client.send(JSON.stringify({ "@type": "WebSocketPushEnable" }));
    await _wsWait(client, function () { return typeof cap.resolveSub === "function"; }, "ws-late: subscribePush called");
    client.send(JSON.stringify({ "@type": "WebSocketPushDisable" }));
    // A Request AFTER the Disable: receiving its Response proves the Disable
    // was processed in-order (pushEnabled=false) before we resolve the setup.
    client.send(JSON.stringify({ "@type": "Request", id: "q1", using: [], methodCalls: [["Core/echo", { hi: 1 }, "c0"]] }));
    await _wsWait(client, function () { return msgs.some(function (m) { return /"requestId":"q1"/.test(m); }); },
      "ws-late: post-disable response received");
    cap.resolveSub(function () { cap.unsub = true; });
    await _wsWait(client, function () { return cap.unsub === true; }, "ws-late: deferred unsubscribe ran");
    check("ws push late-cleanup unsubscribes a handle that resolved after disable", cap.unsub === true);
    client.close(1000, "bye");
    await _wsWait(client, function () { return client.readyState === "closed"; }, "ws-late: closed");
  } finally { await _stop(s.server); }

  // (b) PushEnable resolves (pushUnsubscribe set), THEN the connection closes
  //     → conn 'close' runs the active unsubscribe.
  var cap2 = {};
  var jmapClose = b.mail.server.jmap.create({
    mailStore: {
      appendMessage: function () {},
      subscribePush: function (a, dt, emitFn) { cap2.emit = emitFn; return Promise.resolve(function () { cap2.unsub = true; }); },
    },
    accountsFor: DEFAULT_ACCOUNTS, methods: {},
  });
  var s2 = await _startHttp(jmapClose, {});
  try {
    var c2 = _wsConnect(s2.port);
    c2.on("error", function () {});
    await _wsWait(c2, function () { return c2.readyState === "open"; }, "ws-close: open");
    c2.send(JSON.stringify({ "@type": "WebSocketPushEnable" }));
    await _wsWait(c2, function () { return typeof cap2.emit === "function"; }, "ws-close: push enabled");
    cap2.emit(null);                       // guard: falsy event ignored
    cap2.emit({ kind: "StateChange" });    // no `changed` → default {} fallback
    cap2.emit({ kind: "Nope" });           // non-StateChange ignored
    c2.close(1000, "bye");
    await _wsWait(c2, function () { return cap2.unsub === true; }, "ws-close: unsub on conn close");
    check("ws push conn-close unsubscribes the active subscription", cap2.unsub === true);
  } finally { await _stop(s2.server); }
}

// ==========================================================================
// emailSubmissionSetHandler — option-default + create/update/destroy branches
// (RFC 8621 §7.5)
// ==========================================================================
function testEmailSubmissionSetBadMaxRecipients() {
  function expectThrow(label, maxRecipients) {
    var threw = null;
    try {
      b.mail.server.jmap.emailSubmissionSetHandler({
        deliver: function () {}, lookupEmail: function () {}, identities: function () {},
        maxRecipients: maxRecipients,
      });
    } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-jmap/bad-max-recipients") !== -1);
  }
  expectThrow("negative maxRecipients rejected", -5);
  expectThrow("non-number maxRecipients rejected", "lots");
  expectThrow("non-finite maxRecipients rejected", Infinity);
}

async function testEmailSubmissionSetMissingAccountId() {
  var es = _makeESHandler();
  var threw = null;
  try { await es.handler({}, {}, {}); } catch (e) { threw = e; }
  check("EmailSubmission/set missing accountId → invalidArguments throw",
    threw && (threw.code || "").indexOf("invalidArguments") !== -1);
  var threw2 = null;
  try { await es.handler({}, null, {}); } catch (e) { threw2 = e; }
  check("EmailSubmission/set null args → invalidArguments throw",
    threw2 && (threw2.code || "").indexOf("invalidArguments") !== -1);
}

async function testEmailSubmissionSetCreateValidationErrors() {
  var es = _makeESHandler();
  async function notCreated(sub) {
    var rv = await es.handler({}, { accountId: "A1", create: { c1: sub } }, {});
    return rv.notCreated && rv.notCreated.c1;
  }
  var eNull = await notCreated(null);
  check("create sub null → invalidArguments", eNull && eNull.type === "invalidArguments");
  var eArr = await notCreated([1, 2]);
  check("create sub array → invalidArguments", eArr && eArr.type === "invalidArguments");
  var eNoId = await notCreated({ emailId: "E1", envelope: {} });
  check("create no identityId → invalidProperties(identityId)",
    eNoId && eNoId.type === "invalidProperties" && eNoId.properties.indexOf("identityId") !== -1);
  var eNoEmail = await notCreated({ identityId: "I1", envelope: {} });
  check("create no emailId → invalidProperties(emailId)",
    eNoEmail && eNoEmail.type === "invalidProperties" && eNoEmail.properties.indexOf("emailId") !== -1);
  var eNoEnv = await notCreated({ identityId: "I1", emailId: "E1" });
  check("create no envelope → invalidProperties(envelope)",
    eNoEnv && eNoEnv.type === "invalidProperties" && eNoEnv.properties.indexOf("envelope") !== -1);
  var eNoMailFrom = await notCreated({ identityId: "I1", emailId: "E1", envelope: { rcptTo: [{ email: "a@x.com" }] } });
  check("create no mailFrom.email → invalidProperties(envelope/mailFrom)",
    eNoMailFrom && eNoMailFrom.type === "invalidProperties" &&
    eNoMailFrom.properties.indexOf("envelope/mailFrom") !== -1);
}

async function testEmailSubmissionSetUpdatePatchNotObject() {
  var es = _makeESHandler();
  var rv = await es.handler({}, { accountId: "A1", update: { S1: "notanobject", S2: [1, 2] } }, {});
  check("update patch string → invalidPatch", rv.notUpdated && rv.notUpdated.S1.type === "invalidPatch");
  check("update patch array → invalidPatch", rv.notUpdated && rv.notUpdated.S2.type === "invalidPatch");
}

async function testEmailSubmissionSetUpdateOnCancelOutcomes() {
  var esFalse = _makeESHandler({ onCancel: async function () { return false; } });
  var rvF = await esFalse.handler({}, { accountId: "A1", update: { S1: { undoStatus: "canceled" } } }, {});
  check("onCancel false → cannotUnsend", rvF.notUpdated && rvF.notUpdated.S1.type === "cannotUnsend");

  var esThrow = _makeESHandler({ onCancel: async function () { throw new Error("cancel boom"); } });
  var rvT = await esThrow.handler({}, { accountId: "A1", update: { S1: { undoStatus: "canceled" } } }, {});
  check("onCancel throws (plain Error) → notUpdated serverFail shape",
    rvT.notUpdated && rvT.notUpdated.S1.type === "serverFail");
}

async function testEmailSubmissionSetDestroyEdges() {
  var esNoOp = _makeESHandler();   // no onDestroyed configured
  var rv = await esNoOp.handler({}, { accountId: "A1", destroy: [123, "", "S3"] }, {});
  check("destroy non-string id → notDestroyed invalidArguments",
    rv.notDestroyed && rv.notDestroyed["123"] && rv.notDestroyed["123"].type === "invalidArguments");
  check("destroy empty id → notDestroyed invalidArguments",
    rv.notDestroyed && rv.notDestroyed[""] && rv.notDestroyed[""].type === "invalidArguments");
  check("destroy valid id with no onDestroyed → noop accepted",
    Array.isArray(rv.destroyed) && rv.destroyed.indexOf("S3") !== -1);

  var esThrow = _makeESHandler({ onDestroyed: async function () { throw new Error("destroy boom"); } });
  var rvT = await esThrow.handler({}, { accountId: "A1", destroy: ["S9"] }, {});
  check("onDestroyed throws → notDestroyed serverFail",
    rvT.notDestroyed && rvT.notDestroyed.S9 && rvT.notDestroyed.S9.type === "serverFail");
}

async function testEmailSubmissionSetDeliveryStatusVariants() {
  // deferred + failed + smtpReply-default fallbacks across all three loops.
  var es = _makeESHandler({
    deliver: async function () {
      return {
        delivered: [{ recipient: "d@x.com" }],   // no smtpReply → "250 Accepted"
        deferred:  [{ recipient: "q@x.com" }],   // no smtpReply → "451 ..."
        failed:    [{ recipient: "f@x.com" }],   // no smtpReply → "550 ..."
      };
    },
  });
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: { identityId: "I1", emailId: "E1",
      envelope: { mailFrom: { email: "ops@example.com" },
        rcptTo: [{ email: "d@x.com" }, { email: "q@x.com" }, { email: "f@x.com" }] } } },
  }, {});
  var ds = rv.created.c1.deliveryStatus;
  check("delivered → yes + default 250 smtpReply", ds["d@x.com"].delivered === "yes" && /^250/.test(ds["d@x.com"].smtpReply));
  check("deferred → queued + default 451 smtpReply", ds["q@x.com"].delivered === "queued" && /^451/.test(ds["q@x.com"].smtpReply));
  check("failed → no + default 550 smtpReply", ds["f@x.com"].delivered === "no" && /^550/.test(ds["f@x.com"].smtpReply));

  // deliver returns {} → every deliveryStatus loop's source array falls back
  // to [] (empty deliveryStatus).
  var esEmpty = _makeESHandler({ deliver: async function () { return {}; } });
  var rvE = await esEmpty.handler({}, {
    accountId: "A1",
    create: { c1: { identityId: "I1", emailId: "E1",
      envelope: { mailFrom: { email: "ops@example.com" }, rcptTo: [{ email: "a@x.com" }] } } },
  }, {});
  check("empty deliver result → empty deliveryStatus",
    rvE.created.c1.deliveryStatus && Object.keys(rvE.created.c1.deliveryStatus).length === 0);
}

async function testEmailSubmissionSetCreateDeliverThrows() {
  // deliver throwing a plain Error (no _jmapType) surfaces as serverFail via
  // the create-loop catch + _jmapErrorShape fallback.
  var es = _makeESHandler({ deliver: async function () { throw new Error("mta down"); } });
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: { identityId: "I1", emailId: "E1",
      envelope: { mailFrom: { email: "ops@example.com" }, rcptTo: [{ email: "a@x.com" }] } } },
  }, {});
  check("deliver throws plain Error → notCreated serverFail",
    rv.notCreated && rv.notCreated.c1 && rv.notCreated.c1.type === "serverFail");
}

async function testEmailSubmissionSetOnCreatedThrows() {
  // onCreated is an operator persistence side-effect — a throw there is
  // drop-silent and the create still succeeds.
  var es = _makeESHandler({ onCreated: async function () { throw new Error("persist boom"); } });
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: { identityId: "I1", emailId: "E1",
      envelope: { mailFrom: { email: "ops@example.com" }, rcptTo: [{ email: "a@x.com" }] } } },
  }, {});
  check("onCreated throw is drop-silent → create still succeeds",
    rv.created && rv.created.c1 && typeof rv.created.c1.id === "string");
}

async function testEmailSubmissionSetIdentitiesReturnsNull() {
  // identities() returning null falls back to an empty list → identityNotFound.
  var es = _makeESHandler({ identities: function () { return null; } });
  var rv = await es.handler({}, {
    accountId: "A1",
    create: { c1: { identityId: "I1", emailId: "E1",
      envelope: { mailFrom: { email: "ops@example.com" }, rcptTo: [{ email: "a@x.com" }] } } },
  }, {});
  check("identities()→null → identityNotFound (empty-list fallback)",
    rv.notCreated && rv.notCreated.c1 && rv.notCreated.c1.type === "identityNotFound");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap] OK"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
