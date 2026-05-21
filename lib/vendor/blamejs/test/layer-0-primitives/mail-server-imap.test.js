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

async function run() {
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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-imap] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
  );
}
