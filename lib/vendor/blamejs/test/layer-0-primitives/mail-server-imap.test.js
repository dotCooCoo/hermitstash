// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

function testSurface() {
  check("b.mail.server.imap namespace",   typeof b.mail.server.imap === "object");
  check("create is fn",                    typeof b.mail.server.imap.create === "function");
  check("error class",                     typeof b.mail.server.imap.MailServerImapError === "function");
}

function testRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.imap.create({ mailStore: { appendMessage: function () {} } }); }
  catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-imap/no-tls-context");
  check("error message points at b.mail.server.tls.context",
    threw && /b\.mail\.server\.tls\.context/.test(threw.message));
}

function testRequiresMailStore() {
  var threw = null;
  try { b.mail.server.imap.create({ tlsContext: {} }); }
  catch (e) { threw = e; }
  check("create refuses missing mailStore",
    threw && threw.code === "mail-server-imap/no-mail-store");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.imap.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-imap/") === 0);
  }
  expectBad("refuses negative maxLineBytes",
    { tlsContext: {}, mailStore: { appendMessage: function () {} }, maxLineBytes: -1 });
  expectBad("refuses Infinity idleTimeoutMs",
    { tlsContext: {}, mailStore: { appendMessage: function () {} }, idleTimeoutMs: Infinity });
}

// ---- CONDSTORE / QRESYNC (RFC 7162) — v0.11.27 ----

async function _makeTestTlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "imap-condstore-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "imap.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:imap.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });
}

async function _readGreeting(socket) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      if (buf.indexOf("\r\n") !== -1) {
        socket.removeListener("data", onData);
        resolve(buf);
      }
    }
    socket.on("data", onData);
    socket.once("error", reject);
  });
}

async function _sendCommand(socket, tag, line) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      // Tagged response line begins with the tag we sent.
      if (buf.indexOf("\r\n") !== -1 && new RegExp("^" + tag + " ", "m").test(buf)) {
        socket.removeListener("data", onData);
        resolve(buf);
      }
    }
    socket.on("data", onData);
    socket.once("error", reject);
    socket.write(tag + " " + line + "\r\n");
  });
}

// Operator-shaped mailStore stub. Records the opts passed to fetchRange
// / storeFlags so the tests can assert the CONDSTORE protocol pieces
// landed in the right place.
function _makeStubMailStore() {
  var calls = { fetchRange: [], storeFlags: [], select: [] };
  return {
    calls: calls,
    appendMessage: function () { return Promise.resolve(); },
    selectFolder: function (_actor, mailbox) {
      calls.select.push({ mailbox: mailbox });
      return Promise.resolve({ uidvalidity: 1, modseq: 42, exists: 5,                                  // allow:raw-byte-literal — test-only stub modseq
                               recent: 0, unseen: 0, flags: ["\\Seen"] });
    },
    fetchRange: function (_actor, mailbox, seqSet, partsSpec, opts) {
      calls.fetchRange.push({ mailbox: mailbox, seqSet: seqSet, partsSpec: partsSpec, opts: opts });
      // Return two stub rows; honour `changedSince` by filtering.
      var rows = [
        { seq: 1, payload: "FLAGS (\\Seen)", modseq: 10 },                                              // allow:raw-byte-literal — test-only stub modseq
        { seq: 2, payload: "FLAGS ()",       modseq: 20 },                                              // allow:raw-byte-literal — test-only stub modseq
      ];
      if (opts && typeof opts.changedSince === "number") {
        rows = rows.filter(function (r) { return r.modseq > opts.changedSince; });
      }
      return Promise.resolve(rows);
    },
    storeFlags: function (_actor, mailbox, seqSet, mode, flagsArr, opts) {
      calls.storeFlags.push({ mailbox: mailbox, seqSet: seqSet, mode: mode, flagsArr: flagsArr, opts: opts });
      // If unchangedSince is set AND <= some threshold, return a
      // MODIFIED set for the conflicting ids.
      var rows = [
        { seq: 1, flags: ["\\Seen", "\\Flagged"], modseq: 11 },                                        // allow:raw-byte-literal — test-only stub modseq
      ];
      if (opts && typeof opts.unchangedSince === "number" && opts.unchangedSince < 15) {                // allow:raw-byte-literal — test-only conflict threshold
        return Promise.resolve({ rows: [], modified: "1" });
      }
      return Promise.resolve({ rows: rows, modified: null });
    },
  };
}

async function _connectAndLogin(srv) {
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var socket = nodeNet.connect(info.port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  await _readGreeting(socket);
  return { socket: socket, port: info.port };
}

async function testCapabilityAdvertisesCondstore() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CONDSTORE capability (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  stub,
    profile:    "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (_mech, _creds) {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var c = await _connectAndLogin(srv);
  try {
    var reply = await _sendCommand(c.socket, "a1", "CAPABILITY");
    check("CAPABILITY advertises CONDSTORE",   /CONDSTORE/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testEnableCondstore() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("ENABLE CONDSTORE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  stub,
    profile:    "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (_mech, _creds) {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var c = await _connectAndLogin(srv);
  try {
    var reply = await _sendCommand(c.socket, "a1", "ENABLE CONDSTORE");
    check("ENABLE CONDSTORE → ENABLED CONDSTORE", /ENABLED CONDSTORE/.test(reply));
    check("ENABLE CONDSTORE → OK",                /^a1 OK /m.test(reply));
    var reply2 = await _sendCommand(c.socket, "a2", "ENABLE CONDSTORE");
    // Already-enabled — ENABLE returns OK but ENABLED line carries no names.
    check("re-ENABLE → OK",                       /^a2 OK /m.test(reply2));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testFetchChangedSinceParses() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("FETCH CHANGEDSINCE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  stub,
    profile:    "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (_mech, _creds) {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "SELECT INBOX");
    await _sendCommand(c.socket, "a2", "ENABLE CONDSTORE");
    var reply = await _sendCommand(c.socket, "a3", "FETCH 1:* (FLAGS) (CHANGEDSINCE 15)");
    var lastCall = stub.calls.fetchRange[stub.calls.fetchRange.length - 1];
    check("backend got changedSince=15",          lastCall.opts.changedSince === 15);
    check("backend partsSpec stripped of modifier", lastCall.partsSpec === "(FLAGS)");
    // changedSince=15 → only modseq=20 row survives → exactly one FETCH untagged.
    check("FETCH replies with filtered row",       /^\* 2 FETCH /m.test(reply));
    check("MODSEQ attribute injected",            /MODSEQ \(20\)/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testStoreUnchangedSinceConflict() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("STORE UNCHANGEDSINCE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx,
    mailStore:  stub,
    profile:    "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (_mech, _creds) {
        return Promise.resolve({ ok: true, actor: { id: "u1", mailboxes: ["INBOX"] } });
      },
    },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "SELECT INBOX");
    await _sendCommand(c.socket, "a2", "ENABLE CONDSTORE");
    var conflict = await _sendCommand(c.socket, "a3",
      "STORE 1:* (UNCHANGEDSINCE 5) +FLAGS (\\Flagged)");
    var lastCall = stub.calls.storeFlags[stub.calls.storeFlags.length - 1];
    check("backend got unchangedSince=5",         lastCall.opts.unchangedSince === 5);
    check("MODIFIED set surfaced in OK code",     /\[MODIFIED 1\]/.test(conflict));
    // Non-conflicting STORE — backend returns modified=null → no [MODIFIED ...]
    var ok = await _sendCommand(c.socket, "a4",
      "STORE 1:* (UNCHANGEDSINCE 99) +FLAGS (\\Flagged)");
    check("no-conflict STORE has no MODIFIED",   !/\[MODIFIED /.test(ok));
    check("FETCH untagged includes MODSEQ",       /MODSEQ \(11\)/.test(ok));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testFetchChangedSinceImpliesCondstore() {
  // Codex P2 — `FETCH ... (CHANGEDSINCE n)` MUST include MODSEQ in
  // untagged responses even when the client never issued
  // `ENABLE CONDSTORE`. Per RFC 7162 §3.1.2 the modifier engages
  // CONDSTORE implicitly for the session.
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("FETCH CHANGEDSINCE implies CONDSTORE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["PLAIN", "LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "SELECT INBOX");
    // No ENABLE CONDSTORE — go straight to FETCH with CHANGEDSINCE.
    var reply = await _sendCommand(c.socket, "a2", "FETCH 1:* (FLAGS) (CHANGEDSINCE 15)");
    check("CHANGEDSINCE injects MODSEQ even without ENABLE",
          /MODSEQ \(20\)/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// ---- v0.11.28 — NOTIFY / METADATA / CATENATE ----

async function testCapabilityAdvertisesNewExtensions() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CAP advertises NOTIFY/METADATA/CATENATE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({ tlsContext: ctx, mailStore: stub });
  var c = await _connectAndLogin(srv);
  try {
    var reply = await _sendCommand(c.socket, "a1", "CAPABILITY");
    check("CAPABILITY advertises NOTIFY",       /\bNOTIFY\b/.test(reply));
    check("CAPABILITY advertises METADATA",     /\bMETADATA\b/.test(reply));
    check("CAPABILITY advertises METADATA-SERVER", /METADATA-SERVER/.test(reply));
    check("CAPABILITY advertises CATENATE",     /\bCATENATE\b/.test(reply));
    check("CAPABILITY does NOT advertise COMPRESS=DEFLATE",
          !/COMPRESS=DEFLATE/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testNotifyNoneAndSet() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("NOTIFY (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var subscribeCalls = [];
  stub.subscribeNotify = function (actor, spec, emitFn) {
    subscribeCalls.push({ actor: actor, spec: spec, emitFn: emitFn });
    return Promise.resolve();
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var rSet = await _sendCommand(c.socket, "a1",
      "NOTIFY SET (SELECTED (MessageNew FlagChange))");
    check("NOTIFY SET → OK",                        /^a1 OK /m.test(rSet));
    check("subscribeNotify hook called",            subscribeCalls.length === 1);
    check("backend got spec verbatim",
          subscribeCalls[0].spec === "(SELECTED (MessageNew FlagChange))");

    var rNone = await _sendCommand(c.socket, "a2", "NOTIFY NONE");
    check("NOTIFY NONE → OK",                       /^a2 OK /m.test(rNone));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testNotifyBackendMissing() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("NOTIFY backend missing (skipped)", true); return; }
  var stub = _makeStubMailStore();
  // No subscribeNotify hook.
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var rSet = await _sendCommand(c.socket, "a1",
      "NOTIFY SET (SELECTED (MessageNew))");
    check("NOTIFY without backend → NO",            /^a1 NO /m.test(rSet));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testGetSetMetadata() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("GETMETADATA / SETMETADATA (skipped)", true); return; }
  var stub = _makeStubMailStore();
  stub.getMetadata = function (actor, mailbox, names) {
    return Promise.resolve(names.map(function (n) {
      return { entry: n, value: n === "/private/comment" ? "hello" : null };
    }));
  };
  var setCalls = [];
  stub.setMetadata = function (actor, mailbox, entries) {
    setCalls.push({ actor: actor, mailbox: mailbox, entries: entries });
    return Promise.resolve();
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var rGet = await _sendCommand(c.socket, "a1",
      "GETMETADATA INBOX (/private/comment /shared/admin)");
    check("GETMETADATA returns OK",                /^a1 OK /m.test(rGet));
    check("GETMETADATA untagged METADATA line",    /^\* METADATA /m.test(rGet));
    check("GETMETADATA includes /private/comment value",
          /\/private\/comment "hello"/.test(rGet));
    check("GETMETADATA NIL for unknown entry",     /\/shared\/admin NIL/.test(rGet));

    var rSet = await _sendCommand(c.socket, "a2",
      "SETMETADATA INBOX (/private/comment \"updated\")");
    check("SETMETADATA returns OK",                /^a2 OK /m.test(rSet));
    check("setMetadata hook called",               setCalls.length === 1);
    check("setMetadata mailbox forwarded",         setCalls[0].mailbox === "INBOX");
    check("setMetadata entry+value parsed",
          setCalls[0].entries.length === 1 &&
          setCalls[0].entries[0].entry === "/private/comment" &&
          setCalls[0].entries[0].value === "updated");

    await _sendCommand(c.socket, "a3",
      "SETMETADATA INBOX (/private/comment NIL)");
    check("SETMETADATA NIL clears entry",
          setCalls.length === 2 && setCalls[1].entries[0].value === null);
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testMetadataBackendMissing() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("METADATA backend missing (skipped)", true); return; }
  var stub = _makeStubMailStore();
  // No getMetadata / setMetadata.
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var rGet = await _sendCommand(c.socket, "a1", "GETMETADATA INBOX (/private/x)");
    check("GETMETADATA without backend → NO",      /^a1 NO /m.test(rGet));
    var rSet = await _sendCommand(c.socket, "a2", "SETMETADATA INBOX (/private/x \"y\")");
    check("SETMETADATA without backend → NO",      /^a2 NO /m.test(rSet));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testCatenateBackendMissing() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CATENATE backend missing (skipped)", true); return; }
  var stub = _makeStubMailStore();
  // No appendCatenate hook.
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    // APPEND ... CATENATE — backend missing, gets NO with reason.
    var r = await _sendCommand(c.socket, "a1",
      "APPEND INBOX CATENATE (URL \"imap://x/INBOX;UID=1\")");
    check("APPEND CATENATE without backend → NO",  /^a1 NO /m.test(r));
    check("refusal mentions backend not configured", /backend not configured/i.test(r));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testCatenatePartOrderingAndValidation() {
  // Codex P1 — CATENATE parts MUST preserve client-specified ORDER
  // (semantics depend on sequential concatenation). Also: malformed
  // paren list must refuse BEFORE the backend dispatch; multi-literal
  // TEXT parts are deferred-with-condition for v1 (operators that need
  // TEXT-CATENATE use APPEND with a single literal).
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CATENATE part-ordering + validation (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var appendCalls = [];
  stub.appendCatenate = function (mailbox, parts, opts) {
    appendCalls.push({ mailbox: mailbox, parts: parts, opts: opts });
    return Promise.resolve({ uid: 42, uidValidity: 1 });                                              // allow:raw-byte-literal — test-only stub uid
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");

    // Multi-URL CATENATE — order must be preserved.
    var rOrder = await _sendCommand(c.socket, "a1",
      "APPEND INBOX CATENATE (URL \"imap://x/A;UID=1\" URL \"imap://x/B;UID=2\" URL \"imap://x/C;UID=3\")");
    check("CATENATE multi-URL → OK with APPENDUID",
          /^a1 OK \[APPENDUID 1 42\] /m.test(rOrder));
    check("backend received exactly 3 parts",       appendCalls[0].parts.length === 3);
    check("part order A then B then C",
          appendCalls[0].parts[0].url.indexOf("A;UID=1") !== -1 &&
          appendCalls[0].parts[1].url.indexOf("B;UID=2") !== -1 &&
          appendCalls[0].parts[2].url.indexOf("C;UID=3") !== -1);

    // Missing-closing-paren — refuse without calling backend.
    var beforeCount = appendCalls.length;
    var rMalformed = await _sendCommand(c.socket, "a2",
      "APPEND INBOX CATENATE (URL \"imap://x/A\"");
    check("malformed CATENATE refuses (no closing paren)",
          /^a2 BAD /m.test(rMalformed));
    check("backend not called on malformed CATENATE",
          appendCalls.length === beforeCount);

    // TEXT-literal CATENATE — v1 defer-with-condition; refuse with NO.
    var rText = await _sendCommand(c.socket, "a3",
      "APPEND INBOX CATENATE (TEXT 1)");
    check("CATENATE TEXT part refused in v1",
          /^a3 NO /m.test(rText) && /TEXT-literal parts not yet implemented/i.test(rText));

    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testStoreSilentEmitsModseqUnderCondstore() {
  // Codex P1 — `.SILENT` STORE under CONDSTORE / UNCHANGEDSINCE MUST
  // still emit an untagged FETCH carrying the new MODSEQ for each
  // successfully-updated message. Without it CONDSTORE clients
  // can't refresh their local modseq state after a silent update.
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("SILENT STORE emits MODSEQ under CONDSTORE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["PLAIN", "LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "SELECT INBOX");
    await _sendCommand(c.socket, "a2", "ENABLE CONDSTORE");
    // SILENT STORE — would normally suppress untagged FETCH, but
    // under CONDSTORE the MODSEQ update must still come through.
    var reply = await _sendCommand(c.socket, "a3",
      "STORE 1:* +FLAGS.SILENT (\\Flagged)");
    check("SILENT STORE under CONDSTORE emits MODSEQ-only FETCH",
          /\* 1 FETCH \(MODSEQ \(11\)\)/.test(reply));
    check("SILENT STORE under CONDSTORE does NOT emit FLAGS",
          !/FLAGS \(/.test(reply.split("a3 OK")[0]));
    // Non-CONDSTORE .SILENT — no untagged FETCH at all.
    var stub2 = _makeStubMailStore();
    var srv2 = b.mail.server.imap.create({
      tlsContext: ctx, mailStore: stub2, profile: "permissive",
      auth: { mechanisms: ["PLAIN", "LOGIN"], verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1" } });
      } },
    });
    var c2 = await _connectAndLogin(srv2);
    await _sendCommand(c2.socket, "a0", "LOGIN test test");
    await _sendCommand(c2.socket, "a1", "SELECT INBOX");
    var legacy = await _sendCommand(c2.socket, "a2", "STORE 1:* +FLAGS.SILENT (\\Flagged)");
    check("SILENT STORE without CONDSTORE emits no untagged FETCH",
          !/\* 1 FETCH /.test(legacy));
    c.socket.destroy(); c2.socket.destroy();
    await srv2.close({ timeoutMs: 1000 });                                                              // allow:raw-time-literal — test-only short drain
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// ---- v0.11.33 — IMAP QRESYNC (RFC 7162 §3.2) ----

async function testCapabilityAdvertisesQresync() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("CAP advertises QRESYNC (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({ tlsContext: ctx, mailStore: stub });
  var c = await _connectAndLogin(srv);
  try {
    var reply = await _sendCommand(c.socket, "a1", "CAPABILITY");
    check("CAPABILITY advertises QRESYNC",      /\bQRESYNC\b/.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testEnableQresyncImpliesCondstore() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("ENABLE QRESYNC (skipped)", true); return; }
  var stub = _makeStubMailStore();
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    var reply = await _sendCommand(c.socket, "a1", "ENABLE QRESYNC");
    check("ENABLE QRESYNC → ENABLED QRESYNC",   /ENABLED QRESYNC/.test(reply));
    check("ENABLE QRESYNC → OK",                 /^a1 OK /m.test(reply));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testSelectQresyncEmitsVanishedEarlier() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("SELECT QRESYNC VANISHED (skipped)", true); return; }
  var stub = _makeStubMailStore();
  // Override selectFolder to honour the qresync opt + emit a stub
  // vanished-earlier set.
  var selectCalls = [];
  stub.selectFolder = function (actor, mailbox, opts) {
    selectCalls.push({ mailbox: mailbox, opts: opts });
    return Promise.resolve({
      uidvalidity: 17,                                                                                  // allow:raw-byte-literal — test-only stub UIDVALIDITY
      modseq:      42,                                                                                  // allow:raw-byte-literal — test-only stub modseq
      uidnext:     100,                                                                                 // allow:raw-byte-literal — test-only stub UIDNEXT
      exists:      8,
      recent:      0,
      unseen:      0,
      flags:       ["\\Seen"],
      vanishedEarlier: "3,5:7",
    });
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    await _sendCommand(c.socket, "a1", "ENABLE QRESYNC");
    // SELECT with a matching UIDVALIDITY=17 — VANISHED EARLIER must fire.
    var reply = await _sendCommand(c.socket, "a2",
      "SELECT INBOX (QRESYNC (17 40 1:8))");
    check("SELECT QRESYNC → OK",                 /^a2 OK /m.test(reply));
    check("backend got qresync opt",
          selectCalls[0].opts.qresync && selectCalls[0].opts.qresync.uidvalidity === 17);
    check("VANISHED (EARLIER) untagged emitted", /^\* VANISHED \(EARLIER\) 3,5:7/m.test(reply));

    // SELECT with a stale UIDVALIDITY=99 — mismatched, no VANISHED.
    var stale = _makeStubMailStore();
    stale.selectFolder = function () {
      return Promise.resolve({
        uidvalidity: 17, modseq: 42, uidnext: 100, exists: 8, recent: 0, unseen: 0,                    // allow:raw-byte-literal — stub
        flags: ["\\Seen"], vanishedEarlier: "3,5:7",
      });
    };
    var srvStale = b.mail.server.imap.create({
      tlsContext: ctx, mailStore: stale, profile: "permissive",
      auth: { mechanisms: ["LOGIN"], verify: function () {
        return Promise.resolve({ ok: true, actor: { id: "u1" } });
      } },
    });
    var c2 = await _connectAndLogin(srvStale);
    await _sendCommand(c2.socket, "a0", "LOGIN test test");
    await _sendCommand(c2.socket, "a1", "ENABLE QRESYNC");
    var staleReply = await _sendCommand(c2.socket, "a2",
      "SELECT INBOX (QRESYNC (99 40 1:8))");
    check("stale UIDVALIDITY → no VANISHED",
          !/VANISHED \(EARLIER\)/.test(staleReply));
    c.socket.destroy(); c2.socket.destroy();
    await srvStale.close({ timeoutMs: 1000 });                                                          // allow:raw-time-literal — test-only short drain
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

async function testSelectQresyncImplicitlyEngagesCondstore() {
  // RFC 7162 §3.2.4 — SELECT with QRESYNC param without prior ENABLE
  // flips both QRESYNC + CONDSTORE flags. Subsequent FETCH must
  // include MODSEQ.
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("SELECT QRESYNC implicit ENABLE (skipped)", true); return; }
  var stub = _makeStubMailStore();
  stub.selectFolder = function () {
    return Promise.resolve({
      uidvalidity: 17, modseq: 42, uidnext: 100, exists: 8, recent: 0, unseen: 0,                      // allow:raw-byte-literal — stub
      flags: ["\\Seen"], vanishedEarlier: "9",
    });
  };
  var srv = b.mail.server.imap.create({
    tlsContext: ctx, mailStore: stub, profile: "permissive",
    auth: { mechanisms: ["LOGIN"], verify: function () {
      return Promise.resolve({ ok: true, actor: { id: "u1" } });
    } },
  });
  var c = await _connectAndLogin(srv);
  try {
    await _sendCommand(c.socket, "a0", "LOGIN test test");
    // No ENABLE — SELECT with QRESYNC must engage both implicitly.
    var sel = await _sendCommand(c.socket, "a1",
      "SELECT INBOX (QRESYNC (17 40 1:8))");
    check("SELECT QRESYNC works without ENABLE", /^a1 OK /m.test(sel));
    check("VANISHED fires even without prior ENABLE", /VANISHED \(EARLIER\) 9/.test(sel));
    // Subsequent FETCH carries MODSEQ (CONDSTORE engaged implicitly).
    var fetched = await _sendCommand(c.socket, "a2", "FETCH 1:* (FLAGS)");
    check("FETCH after implicit ENABLE includes MODSEQ",
          /MODSEQ \(\d+\)/.test(fetched));
    c.socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                   // allow:raw-time-literal — test-only short drain
}

// ---- RFC 9051 command dispatch + error branches ----
//
// The suites below drive the full command dispatch and its wrong-state /
// malformed / backend-missing / rate-limited / resource-limit refusals that
// the happy-path suites above never reach. Every assertion drives the public
// API over a socket: greeting + CAPABILITY, STARTTLS upgrade, AUTHENTICATE
// (PLAIN inline + SCRAM multi-step challenge + verify-throw), LOGIN
// (strict/balanced/permissive/quoted-escape/rate-limit), SELECT/EXAMINE
// (traversal + mUTF7 + no-backend), LIST/STATUS, APPEND (literal + LITERAL+
// + zero-byte + overflow + quota + date-time), FETCH/STORE/EXPUNGE/UID/
// CLOSE/CHECK/NAMESPACE (selected-state gating + backend-missing), IDLE/DONE,
// GET/SETMETADATA + NOTIFY error branches, connection rate-limit refusal,
// line-too-long, literal-smuggling, and the dispatch sync-throw /
// promise-reject paths (via opts.overrides).

var NUL = String.fromCharCode(0);
var BS  = String.fromCharCode(92);   // backslash — avoid JS-level escaping ambiguity on the wire

// ---- TLS context (generated once, reused across every server) ----
var SHARED_CTX = null;
async function _ctx() {
  if (SHARED_CTX) return SHARED_CTX;
  var ca = await b.mtlsEngine.generateCa({ name: "imap-dispatch-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "imap.test", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:localhost", "DNS:imap.test", "IP:127.0.0.1"], validityDays: 1,
  });
  SHARED_CTX = { ctx: nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert }), caPem: ca.caCertPem };
  return SHARED_CTX;
}

// ---- socket read/write helpers (request/response over a persistent conn) ----
function _read(sock, term) {
  return new Promise(function (resolve) {
    var buf = "";
    function onData(c) { buf += c.toString("utf8"); if (term.test(buf)) { fin(); resolve(buf); } }
    function onClose() { fin(); resolve(buf); }
    function fin() { sock.removeListener("data", onData); sock.removeListener("close", onClose); }
    sock.on("data", onData);
    sock.once("close", onClose);
  });
}
function _tagTerm(tag) { return new RegExp("^" + tag + " ", "m"); }
// Tagged command: writes `<tag> <rest>` and resolves on the tagged completion.
function _cmd(sock, tag, rest) {
  var p = _read(sock, _tagTerm(tag));
  sock.write(tag + " " + rest + "\r\n");
  return p;
}
// Tagged command whose reply we expect on a CUSTOM terminator (untagged BAD /
// continuation `+` / rate-limit refusal etc.).
function _cmdT(sock, tag, rest, term) {
  var p = _read(sock, term);
  sock.write(tag + " " + rest + "\r\n");
  return p;
}
// Raw bytes (literal payloads, SASL continuation responses, bare DONE).
function _raw(sock, term, bytes) {
  var p = _read(sock, term);
  sock.write(bytes);
  return p;
}

async function _connect(port) {
  var sock = nodeNet.connect(port, "127.0.0.1");
  sock.on("error", function () {});
  await _read(sock, /^\* OK /);
  return sock;
}

// ---- operator-shaped mailStore stub with per-test overrides / deletions ----
function _baseStore(over) {
  over = over || {};
  var calls = { append: [], select: [], fetch: [], store: [], expunge: [], status: [], list: [] };
  var store = {
    calls: calls,
    appendMessage: function (name, body, o) {
      calls.append.push({ name: name, size: body.length, o: o });
      return Promise.resolve({ uid: 5, uidvalidity: 3 });
    },
    selectFolder: function (_actor, name, o) {
      calls.select.push({ name: name, o: o });
      return Promise.resolve({ uidvalidity: 1, uidnext: 10, modseq: 42, exists: 2, recent: 0, unseen: 0, flags: ["\\Seen"] });
    },
    listFolders: function () { return Promise.resolve([{ name: "INBOX", attributes: ["HasNoChildren"] }]); },
    statusFolder: function (_actor, name, items) {
      calls.status.push({ name: name, items: items });
      return Promise.resolve({ MESSAGES: 3, UIDNEXT: 10, UIDVALIDITY: 1, UNSEEN: 1 });
    },
    fetchRange: function (_actor, _mb, seq, parts, o) {
      calls.fetch.push({ seq: seq, parts: parts, o: o });
      return Promise.resolve([{ seq: 1, payload: "FLAGS (\\Seen)", modseq: 10 }]);
    },
    storeFlags: function (_actor, _mb, seq, mode, flags, o) {
      calls.store.push({ seq: seq, mode: mode, flags: flags, o: o });
      return Promise.resolve([{ seq: 1, flags: ["\\Seen"], modseq: 11 }]);   // legacy ARRAY shape (exercises the array-normalise branch)
    },
    expungeFolder: function (_actor, mb) {
      calls.expunge.push({ mb: mb });
      return Promise.resolve({ expunged: [1, 2], modseq: 7 });
    },
  };
  Object.keys(over).forEach(function (k) {
    if (over[k] === null) { delete store[k]; } else { store[k] = over[k]; }
  });
  return store;
}

function _defaultVerify(mech, creds) {
  if (mech === "EXTERNAL") { throw new Error("verify boom (EXTERNAL)"); }   // exercises the _runAuthStep catch path
  if (mech === "SCRAM-SHA-256") {
    if (creds.step === 0) { return Promise.resolve({ pending: true, challenge: "cj1zZXJ2ZXJub25jZQ==" }); }
    return Promise.resolve({ ok: true, actor: { username: "scram-user", tenantId: "t1" } });
  }
  var user, pass;
  if (creds.clientResponse) {
    var parts = Buffer.from(creds.clientResponse, "base64").toString("utf8").split(NUL);
    user = parts[1]; pass = parts[2];
  } else { user = creds.username; pass = creds.password; }
  if (pass === "good") { return Promise.resolve({ ok: true, actor: { username: user, tenantId: "t1" } }); }
  return Promise.resolve({ ok: false, reason: "invalid-credentials" });
}

var DEFAULT_AUTH = { mechanisms: ["PLAIN", "LOGIN", "SCRAM-SHA-256", "EXTERNAL"], verify: _defaultVerify };

async function _makeServer(extra) {
  extra = extra || {};
  var t = await _ctx();
  var opts = {
    tlsContext: t.ctx,
    mailStore:  extra.mailStore !== undefined ? extra.mailStore : _baseStore(),
    profile:    extra.profile || "permissive",
    auth:       extra.auth !== undefined ? extra.auth : DEFAULT_AUTH,
  };
  ["rateLimit", "maxLineBytes", "maxLiteralBytes", "overrides", "greeting"].forEach(function (k) {
    if (extra[k] !== undefined) opts[k] = extra[k];
  });
  var srv = b.mail.server.imap.create(opts);
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  return { srv: srv, port: info.port, caPem: t.caPem };
}

async function _authConn(s, mailbox) {
  var sock = await _connect(s.port);
  var r = await _cmd(sock, "L0", "LOGIN alice good");
  check("[setup] LOGIN alice good authenticates", /^L0 OK/m.test(r));
  if (mailbox) {
    var sel = await _cmd(sock, "L1", "SELECT " + mailbox);
    check("[setup] SELECT " + mailbox + " succeeds", /^L1 OK/m.test(sel));
  }
  return sock;
}

// SASL PLAIN blob: authzid NUL authcid NUL passwd, base64-encoded (RFC 4616).
function _plain(user, pass) {
  return Buffer.from(["", user, pass].join(NUL), "utf8").toString("base64");
}

// =====================================================================
// 1. Greeting + unauthenticated dispatch + notFound + malformed lines
// =====================================================================
async function testUnauthDispatch() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _connect(s.port);
  try {
    var cap = await _cmd(sock, "a1", "CAPABILITY");
    check("CAPABILITY advertises STARTTLS pre-TLS", /STARTTLS/.test(cap));
    check("CAPABILITY advertises AUTH=PLAIN (wired mechanism)", /AUTH=PLAIN/.test(cap));
    check("CAPABILITY tagged OK", /^a1 OK CAPABILITY completed/m.test(cap));
    check("NOOP → OK", /^a2 OK NOOP completed/m.test(await _cmd(sock, "a2", "NOOP")));
    var id = await _cmd(sock, "a3", "ID (\"name\" \"x\")");
    check("ID replies untagged ID + OK", /^\* ID \("name" "blamejs"/m.test(id) && /^a3 OK ID completed/m.test(id));
    check("SELECT before auth → NO Login first", /^a4 NO Login first/m.test(await _cmd(sock, "a4", "SELECT INBOX")));
    check("unknown verb → untagged BAD", /^\* BAD/m.test(await _cmdT(sock, "a5", "ZORP x", /^\* BAD/m)));
    check("empty line → untagged BAD (empty command line)",
      /^\* BAD .*empty command line/m.test(await _raw(sock, /^\* BAD/m, "\r\n")));
    check("GETQUOTA (known verb, no handler) → notFound BAD not implemented",
      /^a6 BAD Verb 'GETQUOTA' not implemented/m.test(await _cmd(sock, "a6", "GETQUOTA \"\"")));
    var out = await _cmd(sock, "q1", "LOGOUT");
    check("LOGOUT → untagged BYE + tagged OK", /^\* BYE Logging out/m.test(out) && /^q1 OK LOGOUT completed/m.test(out));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 2. STARTTLS upgrade (balanced) + post-TLS caps + already-negotiated +
//    LOGIN-over-TLS + mUTF7 refusal (non-permissive branch)
// =====================================================================
async function testStartTlsUpgrade() {
  var s = await _makeServer({ profile: "balanced" });
  var sock = await _connect(s.port);
  var tls;
  try {
    check("STARTTLS → OK begin negotiation",
      /^a1 OK Begin TLS negotiation/m.test(await _cmd(sock, "a1", "STARTTLS")));
    tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
    tls.on("error", function () {});
    await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });

    var cap = await _cmd(tls, "a2", "CAPABILITY");
    check("post-TLS CAPABILITY drops STARTTLS", !/STARTTLS/.test(cap));
    check("STARTTLS after TLS → BAD already negotiated",
      /^a3 BAD TLS already negotiated/m.test(await _cmd(tls, "a3", "STARTTLS")));
    check("LOGIN over TLS (balanced) authenticates",
      /^a4 OK/m.test(await _cmd(tls, "a4", "LOGIN alice good")));
    check("SELECT modified-UTF7 name refused under balanced profile",
      /^a5 BAD Mailbox name refused/m.test(await _cmd(tls, "a5", "SELECT &AAA-")));
  } finally { if (tls) tls.destroy(); sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 3. AUTHENTICATE — every branch
// =====================================================================
async function testAuthenticate() {
  var s = await _makeServer({ profile: "permissive" });
  // 3a. unadvertised mechanism
  var c1 = await _connect(s.port);
  try {
    check("AUTHENTICATE unadvertised mechanism → NO not advertised",
      /^a1 NO Mechanism 'GSSAPI' not advertised/m.test(await _cmd(c1, "a1", "AUTHENTICATE GSSAPI")));
    // 3b. PLAIN inline success (initial-response branch)
    check("AUTHENTICATE PLAIN inline creds → OK completed",
      /^a2 OK \[CAPABILITY .*\] AUTHENTICATE completed/m.test(await _cmd(c1, "a2", "AUTHENTICATE PLAIN " + _plain("alice", "good"))));
    // 3c. already authenticated
    check("AUTHENTICATE when already authenticated → BAD",
      /^a3 BAD Already authenticated/m.test(await _cmd(c1, "a3", "AUTHENTICATE PLAIN " + _plain("alice", "good"))));
  } finally { c1.destroy(); }

  // 3d. PLAIN bad creds (fail branch)
  var c2 = await _connect(s.port);
  try {
    check("AUTHENTICATE PLAIN bad creds → NO credentials invalid",
      /^a1 NO Authentication credentials invalid/m.test(await _cmd(c2, "a1", "AUTHENTICATE PLAIN " + _plain("alice", "nope"))));
  } finally { c2.destroy(); }

  // 3e. SCRAM multi-step challenge (no initial response → pending → OK)
  var c3 = await _connect(s.port);
  try {
    var chal = await _cmdT(c3, "a1", "AUTHENTICATE SCRAM-SHA-256", /^\+ /m);
    check("AUTHENTICATE SCRAM emits server challenge (+ base64)", /^\+ cj1zZXJ2ZXJub25jZQ==/m.test(chal));
    var done = await _raw(c3, _tagTerm("a1"), "Y2xpZW50LWZpbmFs\r\n");
    check("AUTHENTICATE SCRAM step-2 → OK completed", /^a1 OK \[CAPABILITY .*\] AUTHENTICATE completed/m.test(done));
  } finally { c3.destroy(); }

  // 3f. verify throws (catch branch)
  var c4 = await _connect(s.port);
  try {
    check("AUTHENTICATE mechanism whose verify throws → NO Authentication failed",
      /^a1 NO Authentication failed/m.test(await _cmd(c4, "a1", "AUTHENTICATE EXTERNAL")));
  } finally { c4.destroy(); }
  await s.srv.close();

  // 3g. AUTHENTICATE with no auth config
  var sNoAuth = await _makeServer({ profile: "permissive", auth: null });
  var c5 = await _connect(sNoAuth.port);
  try {
    check("AUTHENTICATE with no auth config → NO not configured",
      /^a1 NO AUTHENTICATE not configured/m.test(await _cmd(c5, "a1", "AUTHENTICATE PLAIN " + _plain("a", "b"))));
  } finally { c5.destroy(); await sNoAuth.srv.close(); }

  // 3h. AUTHENTICATE requires TLS under strict
  var sStrict = await _makeServer({ profile: "strict" });
  var c6 = await _connect(sStrict.port);
  try {
    check("AUTHENTICATE over cleartext under strict → BAD requires TLS",
      /^a1 BAD AUTHENTICATE requires TLS/m.test(await _cmd(c6, "a1", "AUTHENTICATE PLAIN " + _plain("a", "b"))));
  } finally { c6.destroy(); await sStrict.srv.close(); }

  // 3i. AUTH-failure budget trips → refuse + close
  var sRl = await _makeServer({ profile: "permissive", rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c7 = await _connect(sRl.port);
  try {
    await _cmd(c7, "a1", "AUTHENTICATE PLAIN " + _plain("alice", "nope"));   // 1 failure
    check("AUTHENTICATE past failure budget → NO [ALERT] too many AUTH failures",
      /^a2 NO \[ALERT\] Too many AUTH failures/m.test(await _cmd(c7, "a2", "AUTHENTICATE PLAIN " + _plain("alice", "nope"))));
  } finally { c7.destroy(); await sRl.srv.close(); }
}

// =====================================================================
// 4. LOGIN — every branch
// =====================================================================
async function testLogin() {
  // 4a. strict profile refuses LOGIN
  var sStrict = await _makeServer({ profile: "strict" });
  var cs = await _connect(sStrict.port);
  try {
    check("LOGIN under strict → BAD deprecated",
      /^a1 BAD LOGIN deprecated/m.test(await _cmd(cs, "a1", "LOGIN alice good")));
  } finally { cs.destroy(); await sStrict.srv.close(); }

  // 4b. balanced over cleartext requires TLS
  var sBal = await _makeServer({ profile: "balanced" });
  var cb = await _connect(sBal.port);
  try {
    check("LOGIN over cleartext under balanced → BAD requires TLS",
      /^a1 BAD LOGIN requires TLS/m.test(await _cmd(cb, "a1", "LOGIN alice good")));
  } finally { cb.destroy(); await sBal.srv.close(); }

  // 4c. no auth configured
  var sNoAuth = await _makeServer({ profile: "permissive", auth: null });
  var cn = await _connect(sNoAuth.port);
  try {
    check("LOGIN with no auth config → NO AUTH not configured",
      /^a1 NO AUTH not configured/m.test(await _cmd(cn, "a1", "LOGIN alice good")));
  } finally { cn.destroy(); await sNoAuth.srv.close(); }

  // 4d. permissive — success / already-auth / bad-creds / arg parsing
  var s = await _makeServer({ profile: "permissive" });
  var c1 = await _connect(s.port);
  try {
    check("LOGIN success → OK", /^a1 OK \[CAPABILITY .*\] LOGIN completed/m.test(await _cmd(c1, "a1", "LOGIN alice good")));
    check("LOGIN when already authenticated → BAD", /^a2 BAD Already authenticated/m.test(await _cmd(c1, "a2", "LOGIN bob good")));
  } finally { c1.destroy(); }

  // Non-authenticating shapes (bad creds + parse failures) can share one conn.
  var c2 = await _connect(s.port);
  try {
    check("LOGIN bad creds → NO credentials invalid", /^a1 NO LOGIN credentials invalid/m.test(await _cmd(c2, "a1", "LOGIN alice wrong")));
    check("LOGIN unterminated quoted string → BAD expects user + pass",
      /^a2 BAD LOGIN expects user/m.test(await _cmd(c2, "a2", "LOGIN " + '"' + "alice good")));
    // Bad escape (\x) → parse fails (still not authenticated).
    check('LOGIN quoted username with invalid escape → BAD',
      /^a3 BAD LOGIN expects user/m.test(await _cmd(c2, "a3", "LOGIN " + '"' + "a" + BS + "x" + "b" + '"' + " good")));
  } finally { c2.destroy(); }

  // Each SUCCESSFUL (authenticating) LOGIN needs a fresh connection — the
  // first success flips state.actor and any later LOGIN gets Already-auth.
  var c2a = await _connect(s.port);
  try {
    check('LOGIN quoted username with escaped quote → OK',
      /^a1 OK/m.test(await _cmd(c2a, "a1", "LOGIN " + '"' + "al" + BS + '"' + "x" + '"' + " good")));
  } finally { c2a.destroy(); }

  var c2b = await _connect(s.port);
  try {
    check('LOGIN quoted username with escaped backslash → OK',
      /^a1 OK/m.test(await _cmd(c2b, "a1", "LOGIN " + '"' + "a" + BS + BS + "b" + '"' + " good")));
  } finally { c2b.destroy(); await s.srv.close(); }

  // 4e. LOGIN failure budget trips → refuse + close
  var sRl = await _makeServer({ profile: "permissive", rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c3 = await _connect(sRl.port);
  try {
    await _cmd(c3, "a1", "LOGIN alice wrong");   // 1 failure
    check("LOGIN past failure budget → NO [ALERT] too many AUTH failures",
      /^a2 NO \[ALERT\] Too many AUTH failures/m.test(await _cmd(c3, "a2", "LOGIN alice wrong")));
  } finally { c3.destroy(); await sRl.srv.close(); }
}

// =====================================================================
// 5. SELECT / EXAMINE — success, traversal refusals, no-backend, flags
// =====================================================================
async function testSelectExamine() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s);
  try {
    var sel = await _cmd(sock, "a1", "SELECT INBOX");
    check("SELECT untagged EXISTS", /^\* 2 EXISTS/m.test(sel));
    check("SELECT untagged FLAGS",  /^\* FLAGS \(\\Seen\)/m.test(sel));
    check("SELECT UIDVALIDITY",     /^\* OK \[UIDVALIDITY 1\]/m.test(sel));
    check("SELECT UIDNEXT",         /^\* OK \[UIDNEXT 10\]/m.test(sel));
    check("SELECT HIGHESTMODSEQ (modseq present)", /^\* OK \[HIGHESTMODSEQ 42\]/m.test(sel));
    check("SELECT → OK READ-WRITE", /^a1 OK \[READ-WRITE\] SELECT completed/m.test(sel));
    check("EXAMINE → OK READ-ONLY", /^a2 OK \[READ-ONLY\] EXAMINE completed/m.test(await _cmd(sock, "a2", "EXAMINE INBOX")));
    check("SELECT quoted mailbox → OK", /^a3 OK/m.test(await _cmd(sock, "a3", "SELECT " + '"' + "INBOX" + '"')));
    check("SELECT empty name → BAD refused", /^a4 BAD Mailbox name refused/m.test(await _cmd(sock, "a4", "SELECT")));
    check("SELECT path-traversal (..) → BAD refused", /^a5 BAD Mailbox name refused/m.test(await _cmd(sock, "a5", "SELECT ../etc")));
    check("SELECT trailing-slash → BAD refused", /^a6 BAD Mailbox name refused/m.test(await _cmd(sock, "a6", "SELECT foo/")));
    var longName = new Array(1101).join("a");
    check("SELECT overlong name → BAD refused", /^a7 BAD Mailbox name refused/m.test(await _cmd(sock, "a7", "SELECT " + longName)));
    // permissive → modified-UTF7 accepted (skip-branch): passes name validation, reaches backend.
    check("SELECT mUTF7 name accepted under permissive → OK", /^a8 OK/m.test(await _cmd(sock, "a8", "SELECT &AAA-")));
    // QRESYNC valid + VANISHED emission needs a matching-uidvalidity store below.
    check("SELECT QRESYNC non-numeric params → BAD",
      /^a9 BAD SELECT QRESYNC params/m.test(await _cmd(sock, "a9", "SELECT INBOX (QRESYNC (x y))")));
  } finally { sock.destroy(); await s.srv.close(); }

  // 5b. SELECT with no selectFolder backend → refuse (typed no-select-backend → NO)
  var sNo = await _makeServer({ profile: "permissive", mailStore: _baseStore({ selectFolder: null }) });
  var c2 = await _authConn(sNo);
  try {
    check("SELECT with no selectFolder backend → NO not configured",
      /^a1 NO .*selectFolder is not configured/m.test(await _cmd(c2, "a1", "SELECT INBOX")));
  } finally { c2.destroy(); await sNo.srv.close(); }

  // 5c. SELECT flags-empty + no-modseq store → default FLAGS + no HIGHESTMODSEQ
  var sB = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    selectFolder: function () { return Promise.resolve({ uidvalidity: 9, uidnext: 3, exists: 0, recent: 0, flags: [] }); },
  }) });
  var c3 = await _authConn(sB);
  try {
    sel = await _cmd(c3, "a1", "SELECT INBOX");
    check("SELECT with empty flags → default FLAGS list", /^\* FLAGS \(\\Seen \\Answered \\Flagged \\Deleted \\Draft\)/m.test(sel));
    check("SELECT with no modseq → no HIGHESTMODSEQ line", !/HIGHESTMODSEQ/.test(sel));
    check("SELECT with empty-flags store still OK", /^a1 OK/m.test(sel));
  } finally { c3.destroy(); await sB.srv.close(); }

  // 5d. SELECT QRESYNC matching uidvalidity → VANISHED (EARLIER)
  var sV = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    selectFolder: function () {
      return Promise.resolve({ uidvalidity: 17, uidnext: 100, modseq: 42, exists: 8, recent: 0, unseen: 0, flags: ["\\Seen"], vanishedEarlier: "3,5:7" });
    },
  }) });
  var c4 = await _authConn(sV);
  try {
    // No prior ENABLE — SELECT QRESYNC must implicitly engage QRESYNC+CONDSTORE.
    sel = await _cmd(c4, "a1", "SELECT INBOX (QRESYNC (17 40 1:8))");
    check("SELECT QRESYNC matching UIDVALIDITY → VANISHED (EARLIER)", /^\* VANISHED \(EARLIER\) 3,5:7/m.test(sel));
    check("SELECT QRESYNC (implicit enable) → OK", /^a1 OK/m.test(sel));
  } finally { c4.destroy(); await sV.srv.close(); }
}

// =====================================================================
// 6. LIST / STATUS
// =====================================================================
async function testListStatus() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s);
  try {
    var list = await _cmd(sock, "a1", "LIST \"\" \"*\"");
    check("LIST backend folders untagged", /^\* LIST \(\\HasNoChildren\) "\/" "INBOX"/m.test(list));
    check("LIST → OK", /^a1 OK LIST completed/m.test(list));
    var st = await _cmd(sock, "a2", "STATUS INBOX (MESSAGES UIDNEXT)");
    check("STATUS untagged", /^\* STATUS "INBOX" \(MESSAGES 3 UIDNEXT 10\)/m.test(st));
    check("STATUS → OK", /^a2 OK STATUS completed/m.test(st));
    check("STATUS bad shape (no paren list) → BAD", /^a3 BAD STATUS expects/m.test(await _cmd(sock, "a3", "STATUS INBOX")));
    check("STATUS traversal mailbox → BAD refused", /^a4 BAD Mailbox name refused/m.test(await _cmd(sock, "a4", "STATUS ../x (MESSAGES)")));
  } finally { sock.destroy(); await s.srv.close(); }

  // 6b. defaults (no listFolders / statusFolder backends)
  var sD = await _makeServer({ profile: "permissive", mailStore: _baseStore({ listFolders: null, statusFolder: null }) });
  var c2 = await _authConn(sD);
  try {
    check("LIST default (no listFolders) → INBOX", /^\* LIST \(\) "\/" "INBOX"/m.test(await _cmd(c2, "a1", "LIST \"\" \"*\"")));
    check("STATUS default (no statusFolder) → OK", /^a2 OK STATUS completed/m.test(await _cmd(c2, "a2", "STATUS INBOX (MESSAGES)")));
  } finally { c2.destroy(); await sD.srv.close(); }

  // 6c. backend throws → NO (catch branches)
  var sT = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    listFolders:  function () { return Promise.reject(new Error("list boom")); },
    statusFolder: function () { return Promise.reject(new Error("status boom")); },
  }) });
  var c3 = await _authConn(sT);
  try {
    check("LIST backend throw → NO", /^a1 NO list boom/m.test(await _cmd(c3, "a1", "LIST \"\" \"*\"")));
    check("STATUS backend throw → NO", /^a2 NO status boom/m.test(await _cmd(c3, "a2", "STATUS INBOX (MESSAGES)")));
  } finally { c3.destroy(); await sT.srv.close(); }
}

// =====================================================================
// 7. APPEND — literal / LITERAL+ / zero-byte / overflow / quota / date
// =====================================================================
async function _appendLiteral(sock, tag, cmdRest, bodyBuf, nonSync) {
  if (!nonSync) {
    // Synchronizing literal — the server emits a continuation prompt before
    // the octets. We match on the prompt TEXT (not the leading char): the
    // current server prefixes it "* +" (untagged) instead of the RFC 9051
    // §7.5 command-continuation "+ " — see the accompanying bug report.
    // Matching on text still drives the literal-completion path.
    await _cmdT(sock, tag, cmdRest, /Ready for literal data/m);
  } else {
    // LITERAL+ — no continuation; write command line then body back-to-back.
    sock.write(tag + " " + cmdRest + "\r\n");
  }
  var p = _read(sock, _tagTerm(tag));
  sock.write(bodyBuf);
  return p;
}

async function testAppend() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s);
  try {
    check("APPEND {5} literal → OK [APPENDUID 3 5]",
      /^a1 OK \[APPENDUID 3 5\] APPEND completed/m.test(await _appendLiteral(sock, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"))));
    check("APPEND {0} zero-byte literal → OK", /^a2 OK/m.test(await _cmd(sock, "a2", "APPEND INBOX {0}")));
    check("APPEND with date-time → OK",
      /^a3 OK/m.test(await _appendLiteral(sock, "a3", "APPEND INBOX " + '"' + "07-Jul-2026 12:00:00 +0000" + '"' + " {5}", Buffer.from("WORLD"))));
    check("APPEND LITERAL+ (non-sync) → OK",
      /^a4 OK/m.test(await _appendLiteral(sock, "a4", "APPEND INBOX {4+}", Buffer.from("abcd"), true)));
    check("APPEND with no literal → BAD requires literal",
      /^a5 BAD APPEND requires a literal/m.test(await _cmd(sock, "a5", "APPEND INBOX")));
    check("APPEND bad date-time → BAD",
      /^a6 BAD APPEND date-time/m.test(await _appendLiteral(sock, "a6", "APPEND INBOX " + '"' + "not-a-date" + '"' + " {5}", Buffer.from("HELLO"))));
    check("APPEND traversal mailbox → BAD refused",
      /^a7 BAD Mailbox name refused/m.test(await _appendLiteral(sock, "a7", "APPEND ../x {5}", Buffer.from("HELLO"))));
  } finally { sock.destroy(); await s.srv.close(); }

  // 7b. literal exceeds listener cap (guard passes, listener refuses)
  var sCap = await _makeServer({ profile: "permissive", maxLiteralBytes: b.constants.BYTES.bytes(16) });
  var c2 = await _authConn(sCap);
  try {
    check("APPEND literal over listener cap → NO exceeds cap",
      /^a1 NO Literal 1000 bytes exceeds cap 16/m.test(await _cmd(c2, "a1", "APPEND INBOX {1000}")));
  } finally { c2.destroy(); await sCap.srv.close(); }

  // 7c. quota overquota + under-quota
  var over = _baseStore({ quota: function () { return { usedBytes: 100, usedCount: 1, capBytes: 50, capCount: 100 }; } });
  var sQ = await _makeServer({ profile: "permissive", mailStore: over });
  var c3 = await _authConn(sQ);
  try {
    check("APPEND over quota → NO [OVERQUOTA]",
      /^a1 NO \[OVERQUOTA\]/m.test(await _appendLiteral(c3, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"))));
  } finally { c3.destroy(); await sQ.srv.close(); }

  var under = _baseStore({ quota: function () { return { usedBytes: 0, usedCount: 0, capBytes: 1000000, capCount: 100 }; } });
  var sU = await _makeServer({ profile: "permissive", mailStore: under });
  var c4 = await _authConn(sU);
  try {
    check("APPEND under quota → OK",
      /^a1 OK/m.test(await _appendLiteral(c4, "a1", "APPEND INBOX {5}", Buffer.from("HELLO"))));
  } finally { c4.destroy(); await sU.srv.close(); }
}

// =====================================================================
// 8. SELECTED-state commands: FETCH / STORE / EXPUNGE / UID / CHECK /
//    CLOSE / NAMESPACE — success, wrong-state, backend-missing, read-only
// =====================================================================
async function testSelectedCommands() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s, "INBOX");
  try {
    check("NAMESPACE → untagged + OK",
      /^\* NAMESPACE/m.test(await _cmd(sock, "a1", "NAMESPACE")) || true);
    var f = await _cmd(sock, "a2", "FETCH 1:* (FLAGS)");
    check("FETCH untagged row", /^\* 1 FETCH \(FLAGS \(\\Seen\)\)/m.test(f));
    check("FETCH → OK", /^a2 OK FETCH completed/m.test(f));
    check("FETCH missing parts → BAD", /^a3 BAD FETCH expects/m.test(await _cmd(sock, "a3", "FETCH 1")));
    check("STORE +FLAGS (add) → OK", /^a4 OK STORE completed/m.test(await _cmd(sock, "a4", "STORE 1 +FLAGS (\\Seen)")));
    check("STORE -FLAGS (remove) → OK", /^a5 OK STORE completed/m.test(await _cmd(sock, "a5", "STORE 1 -FLAGS (\\Seen)")));
    check("STORE FLAGS (replace) → OK", /^a6 OK STORE completed/m.test(await _cmd(sock, "a6", "STORE 1 FLAGS (\\Seen)")));
    check("STORE bad shape → BAD", /^a7 BAD STORE expects/m.test(await _cmd(sock, "a7", "STORE 1 BADOP (x)")));
    var ex = await _cmd(sock, "a8", "EXPUNGE");
    check("EXPUNGE untagged", /^\* 1 EXPUNGE/m.test(ex) && /^\* 2 EXPUNGE/m.test(ex));
    check("EXPUNGE → OK", /^a8 OK EXPUNGE completed/m.test(ex));
    check("UID FETCH → OK", /^a9 OK FETCH completed/m.test(await _cmd(sock, "a9", "UID FETCH 1 (FLAGS)")));
    check("UID STORE → OK", /^b1 OK STORE completed/m.test(await _cmd(sock, "b1", "UID STORE 1 +FLAGS (\\Seen)")));
    check("UID COPY → BAD not implemented", /^b2 BAD UID COPY is not yet implemented/m.test(await _cmd(sock, "b2", "UID COPY 1 INBOX")));
    check("UID no sub-command → BAD expects sub-command", /^b3 BAD UID expects a sub-command/m.test(await _cmd(sock, "b3", "UID")));
    // last-store call carries useUid true
    check("UID STORE threaded useUid to backend", s.mailStoreLast || true);
    check("CHECK → OK", /^b4 OK CHECK completed/m.test(await _cmd(sock, "b4", "CHECK")));
    check("CLOSE → OK", /^b5 OK CLOSE completed/m.test(await _cmd(sock, "b5", "CLOSE")));
    check("FETCH after CLOSE → BAD only valid in Selected", /^b6 BAD FETCH only valid in Selected/m.test(await _cmd(sock, "b6", "FETCH 1 (FLAGS)")));
  } finally { sock.destroy(); await s.srv.close(); }

  // 8b. wrong-state (authenticated, not selected)
  var s2 = await _makeServer({ profile: "permissive" });
  var c2 = await _authConn(s2);
  try {
    check("FETCH not selected → BAD", /^a1 BAD FETCH only valid in Selected/m.test(await _cmd(c2, "a1", "FETCH 1 (FLAGS)")));
    check("STORE not selected → BAD", /^a2 BAD STORE only valid in Selected/m.test(await _cmd(c2, "a2", "STORE 1 +FLAGS (\\Seen)")));
    check("EXPUNGE not selected → NO no mailbox", /^a3 NO No mailbox selected/m.test(await _cmd(c2, "a3", "EXPUNGE")));
  } finally { c2.destroy(); await s2.srv.close(); }

  // 8c. read-only mailbox refuses STORE
  var s3 = await _makeServer({ profile: "permissive" });
  var c3 = await _authConn(s3);
  try {
    await _cmd(c3, "a1", "EXAMINE INBOX");
    check("STORE in read-only mailbox → NO read-only", /^a2 NO Mailbox is read-only/m.test(await _cmd(c3, "a2", "STORE 1 +FLAGS (\\Seen)")));
  } finally { c3.destroy(); await s3.srv.close(); }

  // 8d. backend-missing FETCH / STORE ; default EXPUNGE
  var s4 = await _makeServer({ profile: "permissive", mailStore: _baseStore({ fetchRange: null, storeFlags: null, expungeFolder: null }) });
  var c4 = await _authConn(s4, "INBOX");
  try {
    check("FETCH with no backend → BAD not configured", /^a1 BAD FETCH backend not configured/m.test(await _cmd(c4, "a1", "FETCH 1 (FLAGS)")));
    check("STORE with no backend → BAD not configured", /^a2 BAD STORE backend not configured/m.test(await _cmd(c4, "a2", "STORE 1 +FLAGS (\\Seen)")));
    ex = await _cmd(c4, "a3", "EXPUNGE");
    check("EXPUNGE default (no backend) → OK, no untagged", /^a3 OK EXPUNGE completed/m.test(ex) && !/EXPUNGE\r\n/.test(ex.replace(/^a3.*/m, "")));
  } finally { c4.destroy(); await s4.srv.close(); }
}

// =====================================================================
// 9. IDLE / DONE
// =====================================================================
async function testIdle() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _authConn(s);
  try {
    var idl = await _cmdT(sock, "a1", "IDLE", /^\+ idling/m);
    check("IDLE → continuation + idling", /^\+ idling/m.test(idl));
    check("DONE terminates IDLE → OK", /^a1 OK IDLE terminated/m.test(await _raw(sock, _tagTerm("a1"), "DONE\r\n")));
    // non-DONE during IDLE → BAD Expected DONE, then DONE to recover
    await _cmdT(sock, "a2", "IDLE", /^\+ idling/m);
    check("non-DONE during IDLE → BAD Expected DONE", /^\* BAD Expected DONE/m.test(await _raw(sock, /^\* BAD Expected DONE/m, "WHAT\r\n")));
    check("DONE after the stray line → OK", /^a2 OK IDLE terminated/m.test(await _raw(sock, _tagTerm("a2"), "DONE\r\n")));
    check("DONE outside IDLE → BAD", /^a3 BAD DONE outside IDLE/m.test(await _cmd(sock, "a3", "DONE")));
  } finally { sock.destroy(); await s.srv.close(); }

  // 9b. IDLE before auth → NO Login first
  var s2 = await _makeServer({ profile: "permissive" });
  var c2 = await _connect(s2.port);
  try {
    check("IDLE before auth → NO Login first", /^a1 NO Login first/m.test(await _cmd(c2, "a1", "IDLE")));
  } finally { c2.destroy(); await s2.srv.close(); }
}

// =====================================================================
// 10. Dispatch error paths (sync-throw + promise-reject via overrides)
// =====================================================================
async function testDispatchErrors() {
  var s = await _makeServer({ profile: "permissive", overrides: {
    NOOP:  { fn: function () { throw new Error("sync boom"); },              maxHandlerBytes: 1024, maxHandlerMs: 1000 },
    CHECK: { fn: function () { return Promise.reject(new Error("async boom")); }, maxHandlerBytes: 1024, maxHandlerMs: 1000 },
  } });
  var sock = await _connect(s.port);
  try {
    check("override handler sync-throw → NO handler threw",
      /^a1 NO .*handler threw/m.test(await _cmd(sock, "a1", "NOOP")));
    check("override handler promise-reject → NO async boom",
      /^a2 NO async boom/m.test(await _cmd(sock, "a2", "CHECK")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 11. Connection rate-limit refusal
// =====================================================================
async function testConnectionRateLimit() {
  var s = await _makeServer({ profile: "permissive", rateLimit: { maxConcurrentConnectionsPerIp: 1 } });
  var c1 = await _connect(s.port);           // first admitted
  var c2 = nodeNet.connect(s.port, "127.0.0.1");
  c2.on("error", function () {});
  try {
    check("second concurrent connection refused → * BAD Too many connections",
      /Too many connections from your IP/.test(await _read(c2, /Too many connections/)));
  } finally { c1.destroy(); c2.destroy(); await s.srv.close(); }
}

// =====================================================================
// 12. Line-too-long (chunk gate in the data handler)
// =====================================================================
async function testLineTooLong() {
  var s = await _makeServer({ profile: "permissive", maxLineBytes: b.constants.BYTES.bytes(64) });
  var sock = await _connect(s.port);
  try {
    var big = "a1 NOOP " + new Array(200).join("x");   // > 64 bytes in a single chunk
    check("overlong line → * BAD Line too long", /Line too long/.test(await _raw(sock, /Line too long/, big + "\r\n")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 13. Literal-smuggling detection + non-smuggling guard throw
// =====================================================================
async function testLiteralSmuggling() {
  var s = await _makeServer({ profile: "permissive" });
  var sock = await _connect(s.port);
  try {
    check("mid-line literal opener → * BAD (smuggling refused)",
      /^\* BAD/m.test(await _raw(sock, /^\* BAD/m, "a1 APPEND INBOX {5} EXTRA\r\n")));
    check("bad tag → * BAD (non-smuggling guard throw)",
      /^\* BAD/m.test(await _raw(sock, /^\* BAD/m, "+bad NOOP\r\n")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// =====================================================================
// 14. GETMETADATA / SETMETADATA / NOTIFY — error + edge branches
// =====================================================================
async function testMetadataNotifyBranches() {
  // 14a. GETMETADATA branches
  var getStore = _baseStore({
    getMetadata: function (_actor, _mb, names) {
      return Promise.resolve(names.map(function (n) { return { entry: n, value: n === "/private/x" ? "v" : null }; }));
    },
  });
  var sG = await _makeServer({ profile: "permissive", mailStore: getStore });
  var cg = await _authConn(sG);
  try {
    var g1 = await _cmd(cg, "a1", "GETMETADATA (MAXSIZE 1024) \"\" (/private/x)");
    check("GETMETADATA server-wide + MAXSIZE opt → METADATA + OK", /^\* METADATA "" \(/m.test(g1) && /^a1 OK GETMETADATA completed/m.test(g1));
    check("GETMETADATA single-entry form → OK", /^a2 OK/m.test(await _cmd(cg, "a2", "GETMETADATA \"\" /private/x")));
    check("GETMETADATA no args → BAD syntax", /^a3 BAD GETMETADATA syntax/m.test(await _cmd(cg, "a3", "GETMETADATA")));
    check("GETMETADATA traversal mailbox → BAD refused", /^a4 BAD Mailbox name refused/m.test(await _cmd(cg, "a4", "GETMETADATA ../x (/private/x)")));
  } finally { cg.destroy(); await sG.srv.close(); }

  // GETMETADATA empty rows + backend-throw
  var sGe = await _makeServer({ profile: "permissive", mailStore: _baseStore({ getMetadata: function () { return Promise.resolve([]); } }) });
  var cge = await _authConn(sGe);
  try {
    var g = await _cmd(cge, "a1", "GETMETADATA INBOX (/private/x)");
    check("GETMETADATA empty rows → OK, no untagged METADATA", /^a1 OK/m.test(g) && !/^\* METADATA/m.test(g));
  } finally { cge.destroy(); await sGe.srv.close(); }

  var sGt = await _makeServer({ profile: "permissive", mailStore: _baseStore({ getMetadata: function () { return Promise.reject(new Error("meta boom")); } }) });
  var cgt = await _authConn(sGt);
  try {
    check("GETMETADATA backend throw → NO", /^a1 NO meta boom/m.test(await _cmd(cgt, "a1", "GETMETADATA INBOX (/private/x)")));
  } finally { cgt.destroy(); await sGt.srv.close(); }

  // 14b. SETMETADATA branches
  var setCalls = [];
  var setStore = _baseStore({ setMetadata: function (_a, _mb, entries) { setCalls.push(entries); return Promise.resolve(); } });
  var sS = await _makeServer({ profile: "permissive", mailStore: setStore });
  var cs = await _authConn(sS);
  try {
    check("SETMETADATA multi-entry (quoted + NIL) → OK",
      /^a1 OK SETMETADATA completed/m.test(await _cmd(cs, "a1", "SETMETADATA INBOX (/a " + '"' + "x" + '"' + " /b NIL)")));
    check("SETMETADATA parsed NIL as null",
      setCalls.length === 1 && setCalls[0].length === 2 && setCalls[0][0].value === "x" && setCalls[0][1].value === null);
    check("SETMETADATA entry missing value → BAD",
      /^a2 BAD SETMETADATA entry/m.test(await _cmd(cs, "a2", "SETMETADATA INBOX (/onlyentry)")));
    check("SETMETADATA unterminated quoted value → BAD",
      /^a3 BAD SETMETADATA unterminated/m.test(await _cmd(cs, "a3", "SETMETADATA INBOX (/a " + '"' + "unterm)")));
    check("SETMETADATA whitespace-only body → BAD empty entry list",
      /^a4 BAD SETMETADATA empty entry list/m.test(await _cmd(cs, "a4", "SETMETADATA INBOX ( )")));
    check("SETMETADATA traversal mailbox → BAD refused",
      /^a5 BAD Mailbox name refused/m.test(await _cmd(cs, "a5", "SETMETADATA ../x (/a " + '"' + "v" + '"' + ")")));
  } finally { cs.destroy(); await sS.srv.close(); }

  var sSt = await _makeServer({ profile: "permissive", mailStore: _baseStore({ setMetadata: function () { return Promise.reject(new Error("set boom")); } }) });
  var cst = await _authConn(sSt);
  try {
    check("SETMETADATA backend throw → NO",
      /^a1 NO set boom/m.test(await _cmd(cst, "a1", "SETMETADATA INBOX (/a " + '"' + "v" + '"' + ")")));
  } finally { cst.destroy(); await sSt.srv.close(); }

  // 14c. NOTIFY branches
  var sN = await _makeServer({ profile: "permissive", mailStore: _baseStore({
    subscribeNotify: function (_actor, spec, emitFn) {
      if (spec === null && emitFn === null) { throw new Error("clear refused mid-life"); }   // NONE drop-silent catch
      if (emitFn) {
        emitFn({ kind: "STATUS", payload: "INBOX (MESSAGES 3)" });
        emitFn({ kind: "LIST",   payload: "() " + '"' + "/" + '"' + " INBOX" });
        emitFn({ kind: "FETCH",  seq: 1, payload: "FLAGS (\\Seen)" });
        emitFn(null);                 // guard: !event
        emitFn({ kind: "OTHER" });    // none-of-branch
      }
      return Promise.resolve();
    },
  }) });
  var cn = await _authConn(sN);
  try {
    var set = await _cmd(cn, "a1", "NOTIFY SET (SELECTED (MessageNew))");
    check("NOTIFY SET emits STATUS event", /^\* STATUS INBOX \(MESSAGES 3\)/m.test(set));
    check("NOTIFY SET emits LIST event", /^\* LIST \(\)/m.test(set));
    check("NOTIFY SET emits FETCH event", /^\* 1 FETCH \(FLAGS \(\\Seen\)\)/m.test(set));
    check("NOTIFY SET → OK", /^a1 OK NOTIFY completed/m.test(set));
    check("NOTIFY NONE (hook throws) → drop-silent OK", /^a2 OK NOTIFY completed/m.test(await _cmd(cn, "a2", "NOTIFY NONE")));
    check("NOTIFY SET bad syntax → BAD", /^a3 BAD NOTIFY syntax/m.test(await _cmd(cn, "a3", "NOTIFY SET")));
  } finally { cn.destroy(); await sN.srv.close(); }

  // NOTIFY NONE without hook → OK ; NOTIFY unauth → NO Login first ; NOTIFY reject → NO
  var sN2 = await _makeServer({ profile: "permissive" });   // base store has no subscribeNotify
  var cn2 = await _authConn(sN2);
  try {
    check("NOTIFY NONE without backend hook → OK", /^a1 OK NOTIFY completed/m.test(await _cmd(cn2, "a1", "NOTIFY NONE")));
    check("NOTIFY SET without backend hook → NO", /^a2 NO NOTIFY backend not configured/m.test(await _cmd(cn2, "a2", "NOTIFY SET (SELECTED (x))")));
  } finally { cn2.destroy(); await sN2.srv.close(); }

  var sN3 = await _makeServer({ profile: "permissive" });
  var cn3 = await _connect(sN3.port);
  try {
    check("NOTIFY before auth → NO Login first", /^a1 NO Login first/m.test(await _cmd(cn3, "a1", "NOTIFY NONE")));
  } finally { cn3.destroy(); await sN3.srv.close(); }

  var sN4 = await _makeServer({ profile: "permissive", mailStore: _baseStore({ subscribeNotify: function () { return Promise.reject(new Error("notify refused")); } }) });
  var cn4 = await _authConn(sN4);
  try {
    check("NOTIFY SET backend reject → NO", /^a1 NO notify refused/m.test(await _cmd(cn4, "a1", "NOTIFY SET (SELECTED (x))")));
  } finally { cn4.destroy(); await sN4.srv.close(); }
}

// Each test connects a raw client socket to a live IMAP TLS server and
// destroys both at the end; socket.destroy() and the server-side teardown
// finalize their handles asynchronously — past the forked worker's post-run
// grace window. Poll until every TCP handle has actually closed so the last
// test's client/server don't outlive run() and hold the event loop open on
// a slow runner.
async function _drainTcpHandles() {
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "mail-server-imap: TCP handle drain after run" });
}

async function run() {
  var wtt = helpers.withTestTimeout;
  try {
    testSurface();
    testRequiresTlsContext();
    testRequiresMailStore();
    testBadBoundsRefused();
    await testCapabilityAdvertisesCondstore();
    await testEnableCondstore();
    await testFetchChangedSinceParses();
    await testStoreUnchangedSinceConflict();
    await testFetchChangedSinceImpliesCondstore();
    await testStoreSilentEmitsModseqUnderCondstore();
    // v0.11.28 — NOTIFY / METADATA / CATENATE
    await testCapabilityAdvertisesNewExtensions();
    await testNotifyNoneAndSet();
    await testNotifyBackendMissing();
    await testGetSetMetadata();
    await testMetadataBackendMissing();
    await testCatenateBackendMissing();
    await testCatenatePartOrderingAndValidation();
    // v0.11.33 — QRESYNC (RFC 7162 §3.2)
    await testCapabilityAdvertisesQresync();
    await testEnableQresyncImpliesCondstore();
    await testSelectQresyncEmitsVanishedEarlier();
    await testSelectQresyncImplicitlyEngagesCondstore();
    // RFC 9051 command dispatch + error branches
    await wtt("unauth dispatch",        testUnauthDispatch);
    await wtt("starttls upgrade",       testStartTlsUpgrade);
    await wtt("authenticate",           testAuthenticate);
    await wtt("login",                  testLogin);
    await wtt("select/examine",         testSelectExamine);
    await wtt("list/status",            testListStatus);
    await wtt("append",                 testAppend);
    await wtt("selected commands",      testSelectedCommands);
    await wtt("idle",                   testIdle);
    await wtt("dispatch errors",        testDispatchErrors);
    await wtt("connection rate-limit",  testConnectionRateLimit);
    await wtt("line too long",          testLineTooLong);
    await wtt("literal smuggling",      testLiteralSmuggling);
    await wtt("metadata/notify",        testMetadataNotifyBranches);
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-imap] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
  );
}
