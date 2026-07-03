// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
  // v0.11.30 — blob upload + download
  await testUploadHandlerHappyPath();
  await testUploadHandlerOversizeRefused();
  testUploadHandlerRefusesUnauth();
  testUploadHandlerWithoutBackend();
  testUploadHandlerRefusesBadAccountId();
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

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap] OK"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
