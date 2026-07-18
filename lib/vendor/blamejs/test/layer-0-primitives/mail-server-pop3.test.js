// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.pop3 — create() opts validation plus command-handler and
 * error-branch behavior driven over a real localhost listener (plaintext
 * AUTHORIZATION path + STLS->TLS upgrade + authenticated TRANSACTION path):
 * the RFC 1939 / RFC 2595 command dispatch (CAPA/STLS/USER/PASS/STAT/LIST/
 * RETR/TOP/UIDL/DELE/RSET/NOOP/QUIT) and its wrong-state / malformed /
 * not-found refusals. Every socket assertion drives the public API.
 *
 * Run standalone: `node test/layer-0-primitives/mail-server-pop3.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

var NUL = String.fromCharCode(0);

function testSurface() {
  check("namespace",    typeof b.mail.server.pop3 === "object");
  check("create fn",    typeof b.mail.server.pop3.create === "function");
  check("error class",  typeof b.mail.server.pop3.MailServerPop3Error === "function");
}

function _stubMailStore() {
  return {
    openPop3Drop:    async function () { return { dropId: "drop-1", count: 0, totalBytes: 0 }; },
    commitPop3Drop:  async function () { return { deleted: 0 }; },
    listMessages:    async function () { return []; },
    getMessage:      async function () { return null; },
    markDelete:      async function () { return; },
  };
}

function testRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.pop3.create({ mailStore: _stubMailStore() }); }
  catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-pop3/no-tls-context");
  check("error message points at b.mail.server.tls.context",
    threw && /b\.mail\.server\.tls\.context/.test(threw.message));
}

function testRequiresMailStore() {
  var threw = null;
  try { b.mail.server.pop3.create({ tlsContext: {} }); }
  catch (e) { threw = e; }
  check("create refuses missing mailStore",
    threw && threw.code === "mail-server-pop3/no-mail-store");
}

function testRequiresMailStoreOpenPop3Drop() {
  var threw = null;
  try { b.mail.server.pop3.create({ tlsContext: {}, mailStore: {} }); }
  catch (e) { threw = e; }
  check("create refuses mailStore without openPop3Drop",
    threw && threw.code === "mail-server-pop3/no-mail-store");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.pop3.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-pop3/") === 0);
  }
  expectBad("refuses negative maxLineBytes",
    { tlsContext: {}, mailStore: _stubMailStore(), maxLineBytes: -1 });
  expectBad("refuses Infinity idleTimeoutMs",
    { tlsContext: {}, mailStore: _stubMailStore(), idleTimeoutMs: Infinity });
}

function _readReply(socket, multiline) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      var done = multiline ? (/\r\n\.\r\n$/.test(buf) || /^-ERR/.test(buf)) : /\r\n$/.test(buf);
      if (done) { socket.removeListener("data", onData); socket.removeListener("error", onErr); resolve(buf); }
    }
    function onErr(e) { socket.removeListener("data", onData); reject(e); }
    socket.on("data", onData);
    socket.once("error", onErr);
  });
}
function _send(socket, line, multiline) {
  var p = _readReply(socket, multiline);
  socket.write(line + "\r\n");
  return p;
}

async function _makeTestTlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "pop3-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "pop3.test", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1"], validityDays: 1,
  });
  return { ctx: nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert }), caPem: ca.caCertPem };
}

function _stubStore() {
  var msgs = [
    { msgNum: 1, size: 14, uid: "uid-1", bytes: Buffer.from("Subject: a\r\n\r\nhi") },
    { msgNum: 2, size: 5,  uid: "uid-2", bytes: Buffer.from("world") },
  ];
  return {
    openPop3Drop:   async function () { return { dropId: "drop-1", count: msgs.length, totalBytes: 19 }; },
    commitPop3Drop: async function () { return { deleted: 0 }; },
    listMessages:   async function () { return msgs.map(function (m) { return { msgNum: m.msgNum, size: m.size, uid: m.uid, uidl: m.uid }; }); },
    getMessage:     async function (actor, dropId, n) { var f = msgs.find(function (m) { return m.msgNum === n; }); return f ? { size: f.size, rawBytes: f.bytes } : null; },
    markDelete:     async function () { return; },
  };
}

async function _makeServer(extra) {
  var tls = await _makeTestTlsContext();
  var opts = {
    tlsContext: tls.ctx,
    mailStore:  _stubStore(),
    auth: { verify: async function (mech, creds) {
      // PASS gives parsed username/password; AUTH gives a raw base64 SASL blob
      // in clientResponse (authzid NUL authcid NUL passwd) for us to decode.
      var username = creds.username, password = creds.password;
      if (creds.clientResponse) {
        var parts = Buffer.from(creds.clientResponse, "base64").toString("utf8").split(NUL);
        username = parts[1]; password = parts[2];
      }
      return password === "good"
        ? { ok: true, actor: { username: username, tenantId: "t1" } }
        : { ok: false };
    } },
  };
  if (extra) { Object.keys(extra).forEach(function (k) { opts[k] = extra[k]; }); }
  var srv = b.mail.server.pop3.create(opts);
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  return { srv: srv, port: info.port, caPem: tls.caPem };
}

// ---- plaintext AUTHORIZATION path: dispatch + wrong-state + malformed ----
async function testPlaintextDispatch() {
  var s = await _makeServer();
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  try {
    check("greeting is +OK", /^\+OK/.test(await _readReply(sock)));
    check("CAPA lists STLS", /STLS/.test(await _send(sock, "CAPA", true)));
    check("RETR before auth refused", /^-ERR/.test(await _send(sock, "RETR 1")));
    check("STAT before auth refused", /^-ERR/.test(await _send(sock, "STAT")));
    check("USER over cleartext refused (RFC 2595)", /^-ERR/.test(await _send(sock, "USER alice")));
    check("unknown verb refused", /^-ERR/.test(await _send(sock, "FLOOP")));
    check("NOOP ok", /^\+OK/.test(await _send(sock, "NOOP")));
    check("empty line refused", /^-ERR/.test(await _send(sock, "")));
    check("QUIT in authorization ok", /^\+OK/.test(await _send(sock, "QUIT")));
  } finally { sock.destroy(); await s.srv.close(); }
}

// ---- STLS->TLS upgrade + authenticated TRANSACTION path ----
async function testAuthenticatedTransaction() {
  var s = await _makeServer();
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock); // greeting
  check("STLS begins negotiation", /^\+OK/.test(await _send(sock, "STLS")));
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    check("USER accepted over TLS", /^\+OK/.test(await _send(tls, "USER alice")));
    check("PASS with bad creds refused", /^-ERR/.test(await _send(tls, "PASS wrong")));
    check("USER re-issued after failure", /^\+OK/.test(await _send(tls, "USER alice")));
    check("PASS with good creds authenticates", /^\+OK/.test(await _send(tls, "PASS good")));
    check("USER after auth refused (already authenticated)", /^-ERR/.test(await _send(tls, "USER bob")));
    check("STAT returns count+size", /^\+OK 2 /.test(await _send(tls, "STAT")));
    check("LIST all is multiline", /\r\n\.\r\n$/.test(await _send(tls, "LIST", true)));
    check("LIST single ok", /^\+OK 1 /.test(await _send(tls, "LIST 1")));
    check("LIST out-of-range refused", /^-ERR/.test(await _send(tls, "LIST 99")));
    check("RETR existing returns body", /octets/.test(await _send(tls, "RETR 1", true)));
    check("RETR missing refused", /^-ERR/.test(await _send(tls, "RETR 99")));
    check("RETR non-numeric refused", /^-ERR/.test(await _send(tls, "RETR abc")));
    check("TOP existing ok", /^\+OK/.test(await _send(tls, "TOP 1 0", true)));
    check("TOP missing refused", /^-ERR/.test(await _send(tls, "TOP 99 0")));
    check("UIDL all is multiline", /\r\n\.\r\n$/.test(await _send(tls, "UIDL", true)));
    check("UIDL single ok", /^\+OK 1 /.test(await _send(tls, "UIDL 1")));
    check("DELE marks message", /^\+OK/.test(await _send(tls, "DELE 1")));
    check("NOOP in transaction ok", /^\+OK/.test(await _send(tls, "NOOP")));
    check("RSET clears delete marks", /^\+OK/.test(await _send(tls, "RSET")));
    check("STLS after TLS refused", /^-ERR/.test(await _send(tls, "STLS")));
    check("QUIT commits + closes", /^\+OK/.test(await _send(tls, "QUIT")));
  } finally { tls.destroy(); sock.destroy(); await s.srv.close(); }
}

// ---- AUTH PLAIN mechanism over TLS ----
async function testAuthPlainMechanism() {
  var s = await _makeServer();
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  await _readReply(sock);
  await _send(sock, "STLS");
  var tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  try {
    // SASL PLAIN (RFC 4616): authzid NUL authcid NUL passwd, base64-encoded.
    var sasl = ["", "alice", "good"].join(NUL);
    var authArg = Buffer.from(sasl, "utf8").toString("base64");
    check("AUTH PLAIN with inline creds authenticates", /^\+OK/.test(await _send(tls, "AUTH PLAIN " + authArg)));
    check("STAT after AUTH ok", /^\+OK/.test(await _send(tls, "STAT")));
  } finally { tls.destroy(); sock.destroy(); await s.srv.close(); }
}

// ---- error / enumeration / malformed-argument branches ----
async function testEdgeCases() {
  var s = await _makeServer({ maxLineBytes: b.constants.BYTES.bytes(64) });
  var sock = nodeNet.connect(s.port, "127.0.0.1");
  sock.on("error", function () {});
  try {
    await _readReply(sock); // greeting
    check("AUTH with no mechanism enumerates (RFC 5034)", /^\+OK/.test(await _send(sock, "AUTH", true)));
    check("AUTH PLAIN over cleartext refused (RFC 2595)", /^-ERR/.test(await _send(sock, "AUTH PLAIN")));
    check("PASS without prior USER refused", /^-ERR/.test(await _send(sock, "PASS secret")));
    check("APOP handled (refused under strict / no shared secret)", /^-ERR/.test(await _send(sock, "APOP alice deadbeef")));
    check("DELE in authorization refused", /^-ERR/.test(await _send(sock, "DELE 1")));
    // Overlong line: exceeds the 64-byte cap -> -ERR + close.
    var longArg = "USER " + new Array(200).join("a");
    var reply = await _send(sock, longArg);
    check("overlong line refused", /^-ERR/.test(reply));
  } finally { sock.destroy(); await s.srv.close(); }
}

// ---- raw byte-stream connection collector -------------------------------
// A single accumulator over the socket lets pipelined / async-window /
// server-initiated-close scenarios be asserted with helpers.waitUntil
// (poll, never a bare setTimeout) without interleaving multiple `data`
// readers on the same socket.
function _conn(port) {
  var sock = nodeNet.connect(port, "127.0.0.1");
  var acc = "";
  var closed = false;
  sock.on("data", function (chunk) { acc += chunk.toString("utf8"); });
  sock.on("error", function () {});
  sock.on("close", function () { closed = true; });
  return {
    sock:     sock,
    text:     function () { return acc; },
    isClosed: function () { return closed; },
    send:     function (line) { try { sock.write(line + "\r\n"); } catch (_e) { /* socket down */ } },
    writeRaw: function (buf)  { try { sock.write(buf); } catch (_e) { /* socket down */ } },
    waitFor:  function (re, label) {
      return helpers.waitUntil(function () { return re.test(acc); },
        { timeoutMs: 5000, label: "pop3 reply: " + (label || String(re)) });
    },
    waitClosed: function (label) {
      return helpers.waitUntil(function () { return closed; },
        { timeoutMs: 5000, label: "pop3 close: " + (label || "connection") });
    },
    destroy: function () { try { sock.destroy(); } catch (_e) { /* idempotent */ } },
  };
}

// Drive one command sequence on a fresh connection and assert the reply.
async function _driveOnce(port, lines, expectRe, label) {
  var c = _conn(port);
  try {
    await c.waitFor(/ready\r\n/, label + " greeting");
    lines.forEach(function (ln) { c.send(ln); });
    await c.waitFor(expectRe, label);
    check(label, expectRe.test(c.text()));
  } finally { c.destroy(); }
}

// One authenticator that covers every mechanism the listener drives:
// PASS (username/password), AUTH PLAIN (base64 authzid NUL authcid NUL
// passwd via clientResponse), and APOP (username + digest). A `boom`
// credential makes verify throw (exercises the .catch branch); `good`
// authenticates; anything else fails closed.
function _fullVerify() {
  return async function (mech, creds) {
    if (mech === "APOP") {
      if (creds.digest === "boom") throw new Error("apop-verify-boom");
      return creds.digest === "good"
        ? { ok: true, actor: { username: creds.username, tenantId: "t1" } }
        : { ok: false };
    }
    var username = creds.username, password = creds.password;
    if (creds.clientResponse) {
      var parts = Buffer.from(creds.clientResponse, "base64").toString("utf8").split(NUL);
      username = parts[1]; password = parts[2];
    }
    if (password === "boom") throw new Error("pass-verify-boom");
    return password === "good"
      ? { ok: true, actor: { username: username, tenantId: "t1" } }
      : { ok: false };
  };
}

// Permissive listener with the full authenticator — the profile that
// exercises the USER/PASS/APOP/AUTH transaction path over plaintext
// (permissive opts out of the cleartext-auth refusal) so the deep
// error/verify branches are reachable without a TLS handshake per case.
async function _makeFullServer(extra) {
  var merged = { profile: "permissive", auth: { verify: _fullVerify(), mechanisms: ["PLAIN"] } };
  if (extra) { Object.keys(extra).forEach(function (k) { merged[k] = extra[k]; }); }
  return _makeServer(merged);
}

function _saslBlob(user, pass) {
  return Buffer.from(["", user, pass].join(NUL), "utf8").toString("base64");
}

// ---- create()-time tenant-scope validation ----
function testTenantScopeCreateValidation() {
  var e1 = null;
  try { b.mail.server.pop3.create({ tlsContext: {}, mailStore: _stubMailStore(), tenantScope: {} }); }
  catch (e) { e1 = e; }
  check("tenantScope without .check refused at create",
    e1 && e1.code === "mail-server-pop3/bad-tenant-scope");
  var e2 = null;
  try { b.mail.server.pop3.create({ tlsContext: {}, mailStore: _stubMailStore(), tenantScope: { check: function () {} } }); }
  catch (e) { e2 = e; }
  check("tenantScope without agentTenantId refused at create",
    e2 && e2.code === "mail-server-pop3/no-agent-tenant-id");
}

// ---- cross-tenant AUTH refusal (and same-tenant accept) ----
async function testTenantScopeEnforcement() {
  var s1 = await _makeFullServer({
    tenantScope:   { check: function () { var e = new Error("wrong tenant"); e.code = "agent-tenant/cross-tenant"; throw e; } },
    agentTenantId: "agent-1",
  });
  try {
    await _driveOnce(s1.port, ["USER alice", "PASS good"], /cross-tenant/, "cross-tenant auth refused");
  } finally { await s1.srv.close(); }

  var s2 = await _makeFullServer({
    tenantScope:   { check: function () { /* same tenant — accept */ } },
    agentTenantId: "agent-1",
  });
  try {
    await _driveOnce(s2.port, ["USER alice", "PASS good"], /Logged in/, "same-tenant auth accepted");
  } finally { await s2.srv.close(); }
}

// ---- CAPA advertises wired SASL mechanisms (uppercased) ----
async function testCapaAdvertisesSasl() {
  var s = await _makeServer({ auth: { verify: _fullVerify(), mechanisms: ["plain", "login"] } });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("CAPA");
    await c.waitFor(/\r\n\.\r\n/, "capa terminator");
    check("CAPA advertises wired SASL mechanisms uppercased", /SASL PLAIN LOGIN\r\n/.test(c.text()));
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- idle timeout closes an authorization-state connection ----
async function testIdleTimeoutClosesConnection() {
  await helpers.withTestTimeout("pop3 idle timeout", async function () {
    var s = await _makeServer({ idleTimeoutMs: 300 });
    var c = _conn(s.port);
    try {
      await c.waitFor(/ready\r\n/, "greeting");
      await c.waitFor(/-ERR Idle timeout/, "idle timeout -ERR");
      check("idle connection receives -ERR Idle timeout", /-ERR Idle timeout/.test(c.text()));
      await c.waitClosed("idle timeout close");
      check("idle connection is closed by the listener", c.isClosed());
    } finally { c.destroy(); await s.srv.close(); }
  }, { timeoutMs: 8000 });
}

// ---- server survives a peer RST (socket error handler) ----
async function testSocketErrorSurvived() {
  var s = await _makeServer();
  var c1 = _conn(s.port);
  try {
    await c1.waitFor(/ready\r\n/, "greeting");
    // Abort with an RST so the server-side socket emits 'error'
    // (ECONNRESET) rather than a clean FIN — exercises the socket
    // error handler; the listener must stay up.
    if (typeof c1.sock.resetAndDestroy === "function") c1.sock.resetAndDestroy();
    else c1.sock.destroy(new Error("reset"));
    var c2 = _conn(s.port);
    try {
      await c2.waitFor(/ready\r\n/, "post-reset greeting");
      check("listener survives a peer RST and still serves new connections",
        /ready/.test(c2.text()));
    } finally { c2.destroy(); }
  } finally { c1.destroy(); await s.srv.close(); }
}

// ---- overlong line with no CRLF is refused + closed ----
async function testLineTooLongNoCrlf() {
  var s = await _makeServer({ maxLineBytes: b.constants.BYTES.bytes(64) });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    // 99 bytes, no CRLF — buffer exceeds the 64-byte cap before a line
    // terminator arrives → -ERR + close (distinct from the guard's
    // line-too-long, which needs a terminated line).
    c.writeRaw(Buffer.from(new Array(100).join("A"), "utf8"));
    await c.waitFor(/-ERR Line too long/, "unterminated overlong line");
    check("unterminated overlong line refused", /-ERR Line too long \(cap 64\)/.test(c.text()));
    await c.waitClosed("overlong line close");
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- STLS / AUTH / APOP refused once in TRANSACTION state ----
async function testPostAuthWrongState() {
  var s = await _makeFullServer();
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Logged in/, "authenticated");
    c.send("STLS");
    await c.waitFor(/STLS only valid in AUTHORIZATION/, "STLS wrong-state");
    c.send("AUTH PLAIN " + _saslBlob("alice", "good"));
    await c.waitFor(/AUTH only valid in AUTHORIZATION/, "AUTH wrong-state");
    c.send("APOP alice deadbeef");
    await c.waitFor(/APOP only valid in AUTHORIZATION/, "APOP wrong-state");
    check("STLS refused in TRANSACTION (RFC 2595 §4)", /STLS only valid in AUTHORIZATION/.test(c.text()));
    check("AUTH refused in TRANSACTION", /AUTH only valid in AUTHORIZATION/.test(c.text()));
    check("APOP refused in TRANSACTION", /APOP only valid in AUTHORIZATION/.test(c.text()));
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- STLS handshake failure (onError) closes the connection ----
async function testStlsHandshakeFailureClosed() {
  await helpers.withTestTimeout("pop3 stls handshake failure", async function () {
    var s = await _makeServer();
    var c = _conn(s.port);
    try {
      await c.waitFor(/ready\r\n/, "greeting");
      c.send("STLS");
      await c.waitFor(/Begin TLS negotiation/, "stls ack");
      // Feed non-TLS bytes where a ClientHello is expected → the server
      // TLS socket errors → onError → tls_handshake_failed + close.
      c.writeRaw(Buffer.from("this-is-not-a-tls-clienthello-record\r\n\r\n", "utf8"));
      await c.waitClosed("stls handshake failure close");
      check("failed STLS handshake closes the connection", c.isClosed());
    } finally { c.destroy(); await s.srv.close(); }
  }, { timeoutMs: 8000 });
}

// ---- post-handshake idle timeout (STLS onTimeout) ----
async function testTlsIdleTimeoutClosed() {
  await helpers.withTestTimeout("pop3 tls idle timeout", async function () {
    var s = await _makeServer({ idleTimeoutMs: 400 });
    var sock = nodeNet.connect(s.port, "127.0.0.1");
    sock.on("error", function () {});
    var tls = null;
    try {
      await _readReply(sock);                 // greeting
      await _send(sock, "STLS");              // +OK Begin TLS negotiation
      tls = nodeTls.connect({ socket: sock, ca: s.caPem, servername: "localhost" });
      tls.on("error", function () {});
      await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
      // The idle timer is armed only after a successful handshake; go
      // idle so the post-handshake timer fires onTimeout(tlsSocket).
      var got = "";
      var tlsClosed = false;
      tls.on("data", function (ch) { got += ch.toString("utf8"); });
      tls.on("close", function () { tlsClosed = true; });
      await helpers.waitUntil(function () { return /-ERR Idle timeout/.test(got) || tlsClosed; },
        { timeoutMs: 6000, label: "post-handshake idle timeout" });
      check("post-handshake idle fires onTimeout and closes",
        /-ERR Idle timeout/.test(got) || tlsClosed);
    } finally {
      if (tls) tls.destroy();
      sock.destroy();
      await s.srv.close();
    }
  }, { timeoutMs: 9000 });
}

// ---- USER arriving in the auth window (actor set, drop pending) ----
async function testUserDuringAuthWindowRefused() {
  await helpers.withTestTimeout("pop3 user-during-auth-window", async function () {
    var releaseOpen = null;
    var openGate = new Promise(function (res) { releaseOpen = res; });
    var openCalled = false;
    var store = _stubStore();
    store.openPop3Drop = async function () {
      openCalled = true; await openGate;
      return { dropId: "drop-1", count: 0, totalBytes: 0 };
    };
    var s = await _makeFullServer({ mailStore: store });
    var c = _conn(s.port);
    try {
      await c.waitFor(/ready\r\n/, "greeting");
      c.send("USER alice");
      await c.waitFor(/Send password/, "user ack");
      c.send("PASS good");
      // state.actor is set synchronously before openPop3Drop is awaited;
      // wait until the drop-open is in flight (stage still authorization).
      await helpers.waitUntil(function () { return openCalled; },
        { timeoutMs: 5000, label: "openPop3Drop invoked" });
      c.send("USER bob");
      await c.waitFor(/Already authenticated/, "USER during auth-window");
      check("USER during the pending-drop window is refused as already-authenticated",
        /Already authenticated/.test(c.text()));
      releaseOpen();
      await c.waitFor(/Logged in/, "auth completes after gate release");
    } finally {
      if (releaseOpen) releaseOpen();
      c.destroy(); await s.srv.close();
    }
  }, { timeoutMs: 9000 });
}

// ---- USER / APOP refused over cleartext under balanced ----
async function testClearttextRefusedBalanced() {
  var s = await _makeServer({ profile: "balanced" });
  try {
    // balanced lets USER/APOP past the wire-protocol guard pre-TLS, but
    // the listener's defense-in-depth refuses the cleartext credential.
    await _driveOnce(s.port, ["USER alice"], /USER refused over cleartext/, "USER over cleartext refused (balanced)");
    await _driveOnce(s.port, ["APOP alice deadbeef"], /APOP refused over cleartext/, "APOP over cleartext refused (balanced)");
  } finally { await s.srv.close(); }
}

// ---- listener with no authenticator wired ----
async function testNoAuthConfigured() {
  var s = await _makeServer({ profile: "permissive", auth: null });
  try {
    await _driveOnce(s.port, ["USER alice", "PASS secret"], /AUTH not configured on this listener/, "PASS with no authConfig");
    await _driveOnce(s.port, ["APOP alice deadbeef"], /AUTH not configured/, "APOP with no authConfig");
    await _driveOnce(s.port, ["AUTH PLAIN " + _saslBlob("alice", "good")], /AUTH not configured/, "AUTH with no authConfig");
  } finally { await s.srv.close(); }
}

// ---- PASS branches: no prior USER, verify-throw, auth-failure budget ----
async function testPassBranches() {
  var s1 = await _makeFullServer();
  try {
    await _driveOnce(s1.port, ["PASS secret"], /PASS only valid after USER/, "PASS before USER refused");
  } finally { await s1.srv.close(); }

  var s2 = await _makeFullServer();
  try {
    await _driveOnce(s2.port, ["USER alice", "PASS boom"], /Authentication failed/, "PASS verify-throw refused");
  } finally { await s2.srv.close(); }

  var s3 = await _makeFullServer({ rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c = _conn(s3.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS wrong");
    await c.waitFor(/Authentication failed/, "first PASS failure");
    c.send("USER alice"); c.send("PASS wrong");
    await c.waitFor(/Too many AUTH failures/, "PASS budget exhausted");
    check("PASS past the auth-failure budget is refused + closed", /Too many AUTH failures/.test(c.text()));
    await c.waitClosed("PASS rate-limit close");
  } finally { c.destroy(); await s3.srv.close(); }
}

// ---- APOP verify branches under permissive ----
async function testApopMechanism() {
  var s = await _makeFullServer();
  try {
    await _driveOnce(s.port, ["APOP alice good"], /Logged in/, "APOP success authenticates");
    await _driveOnce(s.port, ["APOP alice nope"], /Authentication failed/, "APOP bad digest refused");
    await _driveOnce(s.port, ["APOP alice boom"], /Authentication failed/, "APOP verify-throw refused");
  } finally { await s.srv.close(); }

  var s2 = await _makeFullServer({ rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c = _conn(s2.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("APOP alice nope");
    await c.waitFor(/Authentication failed/, "first APOP failure");
    c.send("APOP alice nope");
    await c.waitFor(/Too many AUTH failures/, "APOP budget exhausted");
    check("APOP past the auth-failure budget is refused + closed", /Too many AUTH failures/.test(c.text()));
    await c.waitClosed("APOP rate-limit close");
  } finally { c.destroy(); await s2.srv.close(); }
}

// ---- AUTH verify branches under permissive ----
async function testAuthMechanismBranches() {
  var s1 = await _makeFullServer();
  try {
    await _driveOnce(s1.port, ["AUTH PLAIN " + _saslBlob("alice", "wrong")], /Authentication failed/, "AUTH PLAIN bad creds refused");
  } finally { await s1.srv.close(); }

  var s2 = await _makeFullServer();
  try {
    await _driveOnce(s2.port, ["AUTH PLAIN " + _saslBlob("alice", "boom")], /Authentication failed/, "AUTH PLAIN verify-throw refused");
  } finally { await s2.srv.close(); }

  var s3 = await _makeFullServer({ rateLimit: { authFailuresPerIpPer15Min: 1 } });
  var c = _conn(s3.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("AUTH PLAIN " + _saslBlob("alice", "wrong"));
    await c.waitFor(/Authentication failed/, "first AUTH failure");
    c.send("AUTH PLAIN " + _saslBlob("alice", "wrong"));
    await c.waitFor(/Too many AUTH failures/, "AUTH budget exhausted");
    check("AUTH past the auth-failure budget is refused + closed", /Too many AUTH failures/.test(c.text()));
    await c.waitClosed("AUTH rate-limit close");
  } finally { c.destroy(); await s3.srv.close(); }
}

// ---- backend openPop3Drop rejection surfaces -ERR ----
async function testOpenDropRejects() {
  var store = _stubStore();
  store.openPop3Drop = async function () { throw new Error("drop-locked"); };
  var s = await _makeFullServer({ mailStore: store });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Cannot open drop/, "open-drop rejection");
    check("openPop3Drop rejection surfaces -ERR Cannot open drop",
      /Cannot open drop: drop-locked/.test(c.text()));
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- UPDATE-state commit rejection surfaces -ERR + close ----
async function testQuitCommitFails() {
  var store = _stubStore();
  store.commitPop3Drop = async function () { throw new Error("commit-broke"); };
  var s = await _makeFullServer({ mailStore: store });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Logged in/, "authenticated");
    c.send("QUIT");
    await c.waitFor(/Commit failed/, "commit rejection");
    check("QUIT commit rejection surfaces -ERR Commit failed",
      /Commit failed: commit-broke/.test(c.text()));
    await c.waitClosed("commit-fail close");
  } finally { c.destroy(); await s.srv.close(); }
}

// ---- RSET routes through mailStore.resetPop3Drop when present ----
async function testRsetInvokesResetPop3Drop() {
  var resetCalled = false;
  var store = _stubStore();
  store.resetPop3Drop = async function () { resetCalled = true; };
  var s = await _makeFullServer({ mailStore: store });
  var c = _conn(s.port);
  try {
    await c.waitFor(/ready\r\n/, "greeting");
    c.send("USER alice"); c.send("PASS good");
    await c.waitFor(/Logged in/, "authenticated");
    c.send("RSET");
    await c.waitFor(/delete marks cleared/, "rset ok");
    await helpers.waitUntil(function () { return resetCalled; },
      { timeoutMs: 5000, label: "resetPop3Drop invoked" });
    check("RSET routes through mailStore.resetPop3Drop when present", resetCalled);
  } finally { c.destroy(); await s.srv.close(); }
}

async function run() {
  testSurface();
  testRequiresTlsContext();
  testRequiresMailStore();
  testRequiresMailStoreOpenPop3Drop();
  testBadBoundsRefused();
  testTenantScopeCreateValidation();
  await testPlaintextDispatch();
  await testAuthenticatedTransaction();
  await testAuthPlainMechanism();
  await testEdgeCases();
  await testTenantScopeEnforcement();
  await testCapaAdvertisesSasl();
  await testIdleTimeoutClosesConnection();
  await testSocketErrorSurvived();
  await testLineTooLongNoCrlf();
  await testPostAuthWrongState();
  await testStlsHandshakeFailureClosed();
  await testTlsIdleTimeoutClosed();
  await testUserDuringAuthWindowRefused();
  await testClearttextRefusedBalanced();
  await testNoAuthConfigured();
  await testPassBranches();
  await testApopMechanism();
  await testAuthMechanismBranches();
  await testOpenDropRejects();
  await testQuitCommitFails();
  await testRsetInvokesResetPop3Drop();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[mail-server-pop3] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); });
}
