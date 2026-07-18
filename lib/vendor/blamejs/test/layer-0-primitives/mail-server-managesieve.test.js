// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.managesieve — create() opts validation plus command-handler
 * and error-branch tests driven over a real localhost listener (RFC 5804):
 * the wire-protocol dispatch (CAPABILITY / NOOP / STARTTLS / LOGOUT /
 * AUTHENTICATE / HAVESPACE / PUTSCRIPT / LISTSCRIPTS / SETACTIVE / GETSCRIPT /
 * DELETESCRIPT / RENAMESCRIPT) plus its wrong-state / malformed / not-found /
 * backend-failure / rate-limit / idle-timeout branches. Every wire assertion
 * drives the public API over a socket; the STARTTLS upgrade trusts the test
 * CA via `ca:` (never rejectUnauthorized:false).
 *
 * Run standalone: node test/layer-0-primitives/mail-server-managesieve.test.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var mailServerManageSieve = require("../../lib/mail-server-managesieve");

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

function _stubMailStore() {
  return {
    sieveScripts: {
      put:       async function () { return; },
      list:      async function () { return []; },
      get:       async function () { return null; },
      setActive: async function () { return; },
      delete:    async function () { return; },
      rename:    async function () { return; },
      haveSpace: async function () { return { ok: true }; },
    },
  };
}

function testSurface() {
  check("namespace",   typeof mailServerManageSieve === "object");
  check("create fn",   typeof mailServerManageSieve.create === "function");
  check("error class",
    typeof mailServerManageSieve.MailServerManageSieveError === "function");
}

function testRequiresTlsContext() {
  var threw = null;
  try {
    mailServerManageSieve.create({ mailStore: _stubMailStore() });
  } catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-managesieve/no-tls-context");
  check("error message points at b.mail.server.tls.context",
    threw && /b\.mail\.server\.tls\.context/.test(threw.message));
  check("error message names allowPlaintext opt-in",
    threw && /allowPlaintext/.test(threw.message));
}

function testAllowPlaintextOpt() {
  // Explicit allowPlaintext + no tlsContext is accepted (operator
  // opted into plaintext mode + audit emits warning at boot).
  var rv = null;
  try {
    rv = mailServerManageSieve.create({
      mailStore:      _stubMailStore(),
      allowPlaintext: true,
    });
  } catch (e) { rv = e; }
  check("create accepts allowPlaintext=true with no tlsContext",
    rv && typeof rv.listen === "function" && typeof rv.close === "function");
}

function testRequiresMailStore() {
  var threw = null;
  try { mailServerManageSieve.create({ tlsContext: {} }); }
  catch (e) { threw = e; }
  check("create refuses missing mailStore",
    threw && threw.code === "mail-server-managesieve/no-mail-store");
}

function testRequiresMailStoreSieveScripts() {
  var threw = null;
  try { mailServerManageSieve.create({ tlsContext: {}, mailStore: {} }); }
  catch (e) { threw = e; }
  check("create refuses mailStore without sieveScripts",
    threw && threw.code === "mail-server-managesieve/no-mail-store");

  // sieveScripts present but missing the `put` method.
  var threw2 = null;
  try {
    mailServerManageSieve.create({
      tlsContext: {},
      mailStore: { sieveScripts: { list: function () {} } },
    });
  } catch (e) { threw2 = e; }
  check("create refuses sieveScripts without put method",
    threw2 && threw2.code === "mail-server-managesieve/no-mail-store");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { mailServerManageSieve.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-managesieve/") === 0);
  }
  expectBad("refuses negative maxLineBytes",
    { tlsContext: {}, mailStore: _stubMailStore(), maxLineBytes: -1 });
  expectBad("refuses Infinity idleTimeoutMs",
    { tlsContext: {}, mailStore: _stubMailStore(), idleTimeoutMs: Infinity });
  expectBad("refuses NaN maxLineBytes",
    { tlsContext: {}, mailStore: _stubMailStore(), maxLineBytes: NaN });
}

function testRefusesNonObjectOpts() {
  var threw = null;
  try { mailServerManageSieve.create(null); } catch (e) { threw = e; }
  check("create refuses null opts",
    threw && (threw.code || "").indexOf("mail-server-managesieve/") === 0);
}

function testHandleSurface() {
  var handle = mailServerManageSieve.create({
    tlsContext: {},
    mailStore:  _stubMailStore(),
  });
  check("handle.listen is a function",  typeof handle.listen === "function");
  check("handle.close is a function",   typeof handle.close === "function");
}

var NUL = String.fromCharCode(0);

// ---- socket read helpers -------------------------------------------------

// A ManageSieve response block ends with a line beginning OK / NO / BYE
// (RFC 5804 §1.2). Data lines (capability tuples, LISTSCRIPTS entries,
// GETSCRIPT literals) begin with `"` or `{`, so the terminal line is
// unambiguous for the fixtures this suite drives.
function _isTerminal(buf) {
  return /(?:^|\r\n)(?:OK|NO|BYE)(?: [^\r\n]*)?\r\n$/.test(buf);
}
function _read(sock) {
  return new Promise(function (resolve) {
    var buf = "";
    function onData(chunk) { buf += chunk.toString("utf8"); if (_isTerminal(buf)) done(); }
    function onClose() { done(); }
    function done() {
      sock.removeListener("data", onData);
      sock.removeListener("close", onClose);
      sock.removeListener("error", onClose);
      resolve(buf);
    }
    sock.on("data", onData);
    sock.once("close", onClose);
    sock.once("error", onClose);
  });
}
// Attach the reader BEFORE writing so no response bytes are missed.
function _cmd(sock, line) {
  var p = _read(sock);
  sock.write(line + "\r\n");
  return p;
}
function _connect(port) {
  var sock = nodeNet.connect(port, "127.0.0.1");
  sock.on("error", function () {});
  return sock;
}
function _b64(s) { return Buffer.from(s, "utf8").toString("base64"); }

// ---- TLS + store fixtures ------------------------------------------------

async function _makeTestTlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "managesieve-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "managesieve.test", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1"], validityDays: 1,
  });
  return { ctx: nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert }), caPem: ca.caCertPem };
}

// A SASL verify that decodes a base64 PLAIN blob (authzid NUL authcid NUL
// passwd) and accepts passwd === "good"; EXTERNAL always succeeds; a
// username of "throw" makes verify reject (exercises the catch path).
function _verify(mech, creds) {
  if (mech === "EXTERNAL") return { ok: true, actor: { username: "ext", tenantId: "t-ext" } };
  var cr = creds.clientResponse;
  if (!cr) return { ok: false };
  var parts = Buffer.from(cr, "base64").toString("utf8").split(NUL);
  if (parts[1] === "throw") throw new Error("verify blew up");
  return parts[2] === "good"
    ? { ok: true, actor: { username: parts[1], tenantId: "t1" } }
    : { ok: false };
}

function _richStore() {
  var listCall = 0;
  return { sieveScripts: {
    put:       async function () { return; },
    list:      async function () {
      listCall += 1;
      // First call returns an array (with an ACTIVE entry + a name that
      // needs quote-escaping); second call returns a non-array to exercise
      // the `Array.isArray(...) ? ... : []` defensive branch.
      return listCall === 1
        ? [{ name: 'a"b', active: true }, { name: "two", active: false }]
        : null;
    },
    get:       async function (actor, name) {
      if (name === "exists") return { body: "keep;\r\n" };   // already CRLF-terminated
      if (name === "nocrlf") return { body: "keep;" };        // server must append CRLF
      return null;                                             // NONEXISTENT
    },
    setActive: async function () { return; },
    delete:    async function () { return; },
    rename:    async function () { return; },
    haveSpace: async function (actor, name) {
      if (name === "full")     return { ok: false, reason: "over quota" };
      if (name === "noreason") return { ok: false };                          // reason-less → "no space" fallback
      return { ok: true };
    },
  } };
}

function _rejectStore() {
  function boom() { return Promise.reject(new Error("backend down")); }
  return { sieveScripts: {
    put: boom, list: boom, get: boom, setActive: boom, delete: boom, rename: boom, haveSpace: boom,
  } };
}

var VALID_SIEVE   = 'require ["fileinto"];\r\nkeep;\r\n';
var INVALID_SIEVE = 'require ["nope-cap"];\r\nkeep;\r\n';   // unknown capability → safeSieve rejects

// ==========================================================================
// 0. create() guard rails (drive the throw branches directly)
// ==========================================================================
function testCreateValidation() {
  function caught(fn) { try { fn(); return null; } catch (e) { return e; } }
  var e1 = caught(function () { b.mail.server.managesieve.create({ mailStore: _richStore() }); });
  check("create refuses missing tlsContext",   e1 && e1.code === "mail-server-managesieve/no-tls-context");
  var e2 = caught(function () { b.mail.server.managesieve.create({ allowPlaintext: true }); });
  check("create refuses missing mailStore",    e2 && e2.code === "mail-server-managesieve/no-mail-store");
}

// ==========================================================================
// 1. plaintext, no auth: dispatch + wrong-state + malformed + not-found
// ==========================================================================
async function testPlaintextNoAuth() {
  var srv = b.mail.server.managesieve.create({
    allowPlaintext: true, profile: "permissive", mailStore: _richStore(),
    // no auth config → SASL "" advertised, AUTHENTICATE refused as not-configured
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    var greeting = await _read(sock);
    check("greeting emits capability banner", /"IMPLEMENTATION" "blamejs"/.test(greeting));
    check("greeting ends with OK ready",      /OK "blamejs ManageSieve ready"/.test(greeting));
    check("no-auth advertises empty SASL",     /"SASL" ""/.test(greeting));
    check("plaintext listener omits STARTTLS", !/"STARTTLS"/.test(greeting));

    check("CAPABILITY re-emits banner + OK",  /OK "Capability completed"/.test(await _cmd(sock, "CAPABILITY")));
    check("NOOP → OK",                        /OK "NOOP completed"/.test(await _cmd(sock, "NOOP")));
    check("NOOP with tag echoes TAG",         /OK \(TAG "hi"\) "NOOP completed"/.test(await _cmd(sock, 'NOOP "hi"')));
    check("STARTTLS unavailable w/o context", /NO "STARTTLS unavailable/.test(await _cmd(sock, "STARTTLS")));
    check("AUTHENTICATE not configured",      /NO "AUTHENTICATE not configured/.test(await _cmd(sock, 'AUTHENTICATE "EXTERNAL"')));
    check("HAVESPACE before auth refused",    /NO "AUTHENTICATE first"/.test(await _cmd(sock, 'HAVESPACE "s" 100')));
    check("PUTSCRIPT before auth refused",    /NO "AUTHENTICATE first"/.test(await _cmd(sock, 'PUTSCRIPT "s" {5+}')));
    check("unknown verb refused (guard)",     /NO "[^"]*unknown verb/.test(await _cmd(sock, "FLOOP")));
    check("empty command line refused",       /NO "[^"]*empty command line/.test(await _cmd(sock, "")));
    check("LOGOUT → OK + close",              /OK "Logout completed"/.test(await _cmd(sock, "LOGOUT")));
  } finally { sock.destroy(); await srv.close(); }
}

// ==========================================================================
// 2. STARTTLS upgrade + AUTHENTICATE state machine over TLS (strict)
// ==========================================================================
async function testStartTlsAndAuth() {
  var tls = await _makeTestTlsContext();
  var srv = b.mail.server.managesieve.create({
    tlsContext: tls.ctx, profile: "strict", mailStore: _richStore(),
    auth: { mechanisms: ["PLAIN", "EXTERNAL"], verify: async function (m, c) { return _verify(m, c); } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  var tsock = null;
  try {
    var greeting = await _read(sock);
    check("strict+TLS advertises STARTTLS",   /"STARTTLS"/.test(greeting));
    check("advertises configured SASL mechs",  /"SASL" "PLAIN EXTERNAL"/.test(greeting));

    check("PLAIN pre-TLS refused (cleartext)", /NO "[^"]*cleartext/.test(await _cmd(sock, 'AUTHENTICATE "PLAIN"')));
    check("STARTTLS → begin negotiation",      /OK "Begin TLS negotiation now"/.test(await _cmd(sock, "STARTTLS")));

    tsock = nodeTls.connect({ socket: sock, ca: tls.caPem, servername: "localhost" });
    tsock.on("error", function () {});
    await new Promise(function (r, j) { tsock.once("secureConnect", r); tsock.once("error", j); });

    check("post-TLS re-emits caps + success",  /OK "TLS negotiation successful"/.test(await _read(tsock)));
    check("STARTTLS again refused (already)",   /NO "STARTTLS already negotiated"/.test(await _cmd(tsock, "STARTTLS")));
    check("mechanism not advertised refused",   /NO "Mechanism 'SCRAM-SHA-256' not advertised"/.test(await _cmd(tsock, 'AUTHENTICATE "SCRAM-SHA-256"')));
    check("PLAIN w/o initial-response fails",    /NO "Authentication failed"/.test(await _cmd(tsock, 'AUTHENTICATE "PLAIN"')));

    // Synchronizing literal IR (bad creds) — server sends a bare OK
    // continuation, then we stream the IR in two chunks to exercise the
    // partial-literal drain branch.
    var badIr = Buffer.from(_b64(NUL + "alice" + NUL + "bad"), "utf8");
    var pCont = _read(tsock);
    tsock.write('AUTHENTICATE "PLAIN" {' + badIr.length + '}\r\n');
    check("sync literal → OK continuation",     /^OK\r\n$/.test(await pCont));
    var pAuth = _read(tsock);
    tsock.write(badIr.subarray(0, 3));
    await helpers.passiveObserve(40, "managesieve: auth-IR partial drain");
    tsock.write(badIr.subarray(3));
    check("bad creds → Authentication failed",  /NO "Authentication failed"/.test(await pAuth));

    // Non-synchronizing literal IR (LITERAL+, good creds) → success.
    var goodIr = Buffer.from(_b64(NUL + "alice" + NUL + "good"), "utf8");
    var pOk = _read(tsock);
    tsock.write('AUTHENTICATE "PLAIN" {' + goodIr.length + '+}\r\n');
    tsock.write(goodIr);
    check("LITERAL+ good creds authenticates",  /OK "Authenticated"/.test(await pOk));

    check("AUTHENTICATE after auth refused",    /NO "[^"]*NOT-AUTHENTICATED"/.test(await _cmd(tsock, 'AUTHENTICATE "PLAIN"')));
    check("HAVESPACE over TLS → Have space",     /OK "Have space"/.test(await _cmd(tsock, 'HAVESPACE "s" 100')));
    check("post-auth CAPABILITY omits STARTTLS", !/"STARTTLS"/.test(await _cmd(tsock, "CAPABILITY")));
    check("LOGOUT over TLS → OK",                /OK "Logout completed"/.test(await _cmd(tsock, "LOGOUT")));
  } finally { if (tsock) tsock.destroy(); sock.destroy(); await srv.close(); }
}

// ==========================================================================
// 2b. STARTTLS handshake failure → starttls_handshake_failed + close
// ==========================================================================
async function testStartTlsHandshakeFailure() {
  var tls = await _makeTestTlsContext();
  var srv = b.mail.server.managesieve.create({
    tlsContext: tls.ctx, profile: "strict", mailStore: _richStore(),
    auth: { mechanisms: ["PLAIN"], verify: async function (m, c) { return _verify(m, c); } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    await _read(sock); // greeting
    check("STARTTLS → begin negotiation",       /OK "Begin TLS negotiation now"/.test(await _cmd(sock, "STARTTLS")));
    var closed = false;
    sock.once("close", function () { closed = true; });
    // Feed bytes that are not a valid TLS ClientHello → the server's
    // TLSSocket handshake errors → onError → close.
    sock.write(Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]));
    await helpers.waitUntil(function () { return closed; },
      { timeoutMs: 5000, label: "managesieve: STARTTLS handshake-failure closes connection" });
    check("handshake failure tears down socket", closed === true);
  } finally { sock.destroy(); await srv.close(); }
}

// ==========================================================================
// 3. authenticated command handlers (happy + variants) over plaintext
// ==========================================================================
async function testAuthenticatedHandlers() {
  var srv = b.mail.server.managesieve.create({
    allowPlaintext: true, profile: "permissive", mailStore: _richStore(),
    auth: { mechanisms: ["EXTERNAL"], verify: async function (m, c) { return _verify(m, c); } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    await _read(sock); // greeting
    check("EXTERNAL (no IR) authenticates",     /OK "Authenticated"/.test(await _cmd(sock, 'AUTHENTICATE "EXTERNAL"')));

    check("HAVESPACE ok:true → Have space",      /OK "Have space"/.test(await _cmd(sock, 'HAVESPACE "s" 100')));
    check("HAVESPACE ok:false → QUOTA/MAXSIZE",  /NO "\(QUOTA\/MAXSIZE\) over quota"/.test(await _cmd(sock, 'HAVESPACE "full" 100')));
    check("HAVESPACE reason-less → no space",    /NO "\(QUOTA\/MAXSIZE\) no space"/.test(await _cmd(sock, 'HAVESPACE "noreason" 100')));

    // PUTSCRIPT via synchronizing literal, body streamed in two chunks
    // (partial-literal drain branch), valid script → accepted.
    var body = Buffer.from(VALID_SIEVE, "utf8");
    var pCont = _read(sock);
    sock.write('PUTSCRIPT "v" {' + body.length + '}\r\n');
    check("PUTSCRIPT sync → OK continuation",    /^OK\r\n$/.test(await pCont));
    var pPut = _read(sock);
    sock.write(body.subarray(0, 6));
    await helpers.passiveObserve(40, "managesieve: putscript partial drain");
    sock.write(body.subarray(6));
    check("PUTSCRIPT valid script accepted",     /OK "PUTSCRIPT completed"/.test(await pPut));

    // PUTSCRIPT via LITERAL+ with an invalid script → refused.
    var bad = Buffer.from(INVALID_SIEVE, "utf8");
    var pBad = _read(sock);
    sock.write('PUTSCRIPT "bad" {' + bad.length + '+}\r\n');
    sock.write(bad);
    check("PUTSCRIPT invalid script refused",    /NO "Script validation failed/.test(await pBad));

    var listReply = await _cmd(sock, "LISTSCRIPTS");
    check("LISTSCRIPTS lists + ACTIVE flag",     /"a\\"b" ACTIVE\r\n"two"\r\nOK "LISTSCRIPTS completed"/.test(listReply));
    check("LISTSCRIPTS non-array → OK count-0",  /OK "LISTSCRIPTS completed"/.test(await _cmd(sock, "LISTSCRIPTS")));

    check("SETACTIVE name → OK",                 /OK "SETACTIVE completed"/.test(await _cmd(sock, 'SETACTIVE "s"')));
    check("SETACTIVE empty (deactivate) → OK",   /OK "SETACTIVE completed"/.test(await _cmd(sock, 'SETACTIVE ""')));

    var g1 = await _cmd(sock, 'GETSCRIPT "exists"');
    check("GETSCRIPT returns literal + body",    /\{7\}\r\nkeep;\r\nOK "GETSCRIPT completed"/.test(g1));
    var g2 = await _cmd(sock, 'GETSCRIPT "nocrlf"');
    check("GETSCRIPT appends CRLF when absent",  /\{5\}\r\nkeep;\r\nOK "GETSCRIPT completed"/.test(g2));
    check("GETSCRIPT missing → NONEXISTENT",     /NO "\(NONEXISTENT\) Script not found"/.test(await _cmd(sock, 'GETSCRIPT "missing"')));

    check("DELETESCRIPT → OK",                   /OK "DELETESCRIPT completed"/.test(await _cmd(sock, 'DELETESCRIPT "s"')));
    check("RENAMESCRIPT → OK",                   /OK "RENAMESCRIPT completed"/.test(await _cmd(sock, 'RENAMESCRIPT "a" "bb"')));
    check("NOOP authenticated → OK",             /OK "NOOP completed"/.test(await _cmd(sock, "NOOP")));
    check("STARTTLS post-auth → pre-AUTH only",  /NO "STARTTLS only valid pre-AUTH/.test(await _cmd(sock, "STARTTLS")));
    check("LOGOUT → OK",                         /OK "Logout completed"/.test(await _cmd(sock, "LOGOUT")));
  } finally { sock.destroy(); await srv.close(); }
}

// ==========================================================================
// 4. backend-failure branches — every handler's .catch → NO
// ==========================================================================
async function testBackendFailures() {
  var srv = b.mail.server.managesieve.create({
    allowPlaintext: true, profile: "permissive", mailStore: _rejectStore(),
    auth: { mechanisms: ["EXTERNAL"], verify: async function (m, c) { return _verify(m, c); } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    await _read(sock);
    await _cmd(sock, 'AUTHENTICATE "EXTERNAL"');
    check("HAVESPACE backend reject → NO",       /NO "backend down"/.test(await _cmd(sock, 'HAVESPACE "s" 100')));

    var body = Buffer.from(VALID_SIEVE, "utf8");
    var pPut = _read(sock);
    sock.write('PUTSCRIPT "v" {' + body.length + '+}\r\n');
    sock.write(body);
    check("PUTSCRIPT put reject → NO",           /NO "backend down"/.test(await pPut));

    check("LISTSCRIPTS backend reject → NO",     /NO "backend down"/.test(await _cmd(sock, "LISTSCRIPTS")));
    check("SETACTIVE backend reject → NO",       /NO "backend down"/.test(await _cmd(sock, 'SETACTIVE "s"')));
    check("GETSCRIPT backend reject → NO",       /NO "backend down"/.test(await _cmd(sock, 'GETSCRIPT "s"')));
    check("DELETESCRIPT backend reject → NO",    /NO "backend down"/.test(await _cmd(sock, 'DELETESCRIPT "s"')));
    check("RENAMESCRIPT backend reject → NO",    /NO "backend down"/.test(await _cmd(sock, 'RENAMESCRIPT "a" "bb"')));
  } finally { sock.destroy(); await srv.close(); }
}

// ==========================================================================
// 5. AUTH failure branch + verify-throw catch + AUTH-failure rate limit
// ==========================================================================
async function testAuthFailureRateLimit() {
  var srv = b.mail.server.managesieve.create({
    allowPlaintext: true, profile: "permissive", mailStore: _richStore(),
    rateLimit: { authFailuresPerIpPer15Min: 2 },
    auth: { mechanisms: ["PLAIN"], verify: async function (m, c) { return _verify(m, c); } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    await _read(sock);
    async function authPlain(blob) {
      var ir = Buffer.from(_b64(blob), "utf8");
      var p = _read(sock);
      sock.write('AUTHENTICATE "PLAIN" {' + ir.length + '+}\r\n');
      sock.write(ir);
      return p;
    }
    check("bad creds → verify-fail branch",      /NO "Authentication failed"/.test(await authPlain(NUL + "u" + NUL + "bad")));
    check("verify throw → catch → failed",       /NO "Authentication failed"/.test(await authPlain(NUL + "throw" + NUL + "x")));
    check("AUTH-failure budget exhausted → NO",  /NO "Too many AUTH failures from your IP"/.test(await authPlain(NUL + "u" + NUL + "bad")));
  } finally { sock.destroy(); await srv.close(); }
}

// ==========================================================================
// 6. per-IP concurrent-connection rate limit (admitConnection refusal)
// ==========================================================================
async function testConnectionRateLimit() {
  var srv = b.mail.server.managesieve.create({
    allowPlaintext: true, profile: "permissive", mailStore: _richStore(),
    rateLimit: { maxConcurrentConnectionsPerIp: 1 },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var first = _connect(info.port);
  var second = null;
  try {
    await _read(first); // holds the single concurrent slot open
    second = _connect(info.port);
    check("2nd concurrent connection refused",   /NO "Too many connections from your IP"/.test(await _read(second)));
  } finally { first.destroy(); if (second) second.destroy(); await srv.close(); }
}

// ==========================================================================
// 7. line-too-long (no CRLF, exceeds cap) → NO + close
// ==========================================================================
async function testLineTooLong() {
  var srv = b.mail.server.managesieve.create({
    allowPlaintext: true, profile: "permissive", mailStore: _richStore(),
    maxLineBytes: b.constants.BYTES.bytes(64),
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    await _read(sock);
    var p = _read(sock);
    sock.write(new Array(200).join("A"));   // 199 bytes, no CRLF → exceeds 64-byte cap
    check("overlong line (no CRLF) → NO",         /NO "Line too long/.test(await p));
  } finally { sock.destroy(); await srv.close(); }
}

// ==========================================================================
// 8. idle timeout → BYE + close
// ==========================================================================
async function testIdleTimeout() {
  var srv = b.mail.server.managesieve.create({
    // profile omitted → exercises the `opts.profile || "strict"` default
    allowPlaintext: true, mailStore: _richStore(),
    idleTimeoutMs: b.constants.TIME.seconds(0.3),
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    await _read(sock);                        // greeting
    check("idle timeout emits BYE",               /BYE "Idle timeout"/.test(await _read(sock)));
  } finally { sock.destroy(); await srv.close(); }
}

// ==========================================================================
// 9. handler faults — sync throw (handler_threw) + async reject
//    (handler_rejected) via operator overrides
// ==========================================================================
async function testHandlerFaults() {
  var budget = { maxHandlerBytes: b.constants.BYTES.kib(8), maxHandlerMs: b.constants.TIME.seconds(5) };
  var srv = b.mail.server.managesieve.create({
    allowPlaintext: true, profile: "permissive", mailStore: _richStore(),
    overrides: {
      NOOP:       { fn: function () { throw new Error("sync boom"); },
                    maxHandlerBytes: budget.maxHandlerBytes, maxHandlerMs: budget.maxHandlerMs },
      CAPABILITY: { fn: function () { return Promise.reject(new Error("async boom")); },
                    maxHandlerBytes: budget.maxHandlerBytes, maxHandlerMs: budget.maxHandlerMs },
    },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = _connect(info.port);
  try {
    await _read(sock);
    check("handler sync-throw → Internal error",  /NO "Internal error"/.test(await _cmd(sock, "NOOP")));
    check("handler async-reject → Internal error",/NO "Internal error"/.test(await _cmd(sock, "CAPABILITY")));
  } finally { sock.destroy(); await srv.close(); }
}

async function run() {
  testSurface();
  testRequiresTlsContext();
  testAllowPlaintextOpt();
  testRequiresMailStore();
  testRequiresMailStoreSieveScripts();
  testBadBoundsRefused();
  testRefusesNonObjectOpts();
  testHandleSurface();
  testCreateValidation();
  await testPlaintextNoAuth();
  await testStartTlsAndAuth();
  await testStartTlsHandshakeFailure();
  await testAuthenticatedHandlers();
  await testBackendFailures();
  await testAuthFailureRateLimit();
  await testConnectionRateLimit();
  await testLineTooLong();
  await testIdleTimeout();
  await testHandlerFaults();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-managesieve] OK — " + helpers.getChecks() + " checks"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
  );
}
