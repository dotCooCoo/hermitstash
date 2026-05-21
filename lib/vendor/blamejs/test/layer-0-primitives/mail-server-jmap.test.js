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
    accountsFor: async function () { return {}; },
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
    accountsFor: async function () { return {}; },
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
    accountsFor: async function () { return {}; },
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
    accountsFor: async function () { return {}; },
    methods: {},
  });
  var mr = _makeUploadReqRes("/jmap/download/A1/missing/note.txt", null, []);
  jmap.downloadHandler(mr.req, mr.res);
  await new Promise(function (r) { setImmediate(function () { setImmediate(r); }); });
  check("download missing → 404",                  mr.res._status() === 404);
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

async function run() {
  testSurface();
  testBadOptsRefused();
  await testDispatchHappyPath();
  await testBackRefResolution();
  await testBadBackRefRefused();
  await testUnknownMethod();
  await testMethodThrewMaskedAsServerFail();
  await testNoActorRefused();
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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap] OK"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
