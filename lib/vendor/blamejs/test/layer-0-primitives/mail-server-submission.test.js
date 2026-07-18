// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.submission — outbound SMTP submission listener.
 *
 * Tests cover opts validation, AUTH-required posture under strict
 * profile, AUTH-needs-TLS gate (RFC 4954 §4), identity-binding,
 * and the multi-step verify hook contract. Error / defensive /
 * adversarial branches are also driven over a real localhost listener:
 * wrong-state and malformed-command refusals, AUTH failure modes and
 * per-IP rate-limits, tenant scoping, STARTTLS / implicit-TLS postures,
 * DKIM-required modes, recipient policy, size and line limits, DATA
 * smuggling refusals, idle-timeout, and close() drain.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

async function _makeTestTlsContext() {
  var ca = await b.mtlsEngine.generateCa({ name: "submission-bdat-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "submission.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:submission.test", "DNS:localhost", "IP:127.0.0.1"],
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

async function _sendCommand(socket, line) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      if (buf.indexOf("\r\n") !== -1) {
        var lines = buf.split("\r\n").filter(Boolean);
        var last = lines[lines.length - 1];
        if (/^\d{3} /.test(last)) {
          socket.removeListener("data", onData);
          resolve(buf);
        }
      }
    }
    socket.on("data", onData);
    socket.once("error", reject);
    socket.write(line + "\r\n");
  });
}

// Send the BDAT command line + the payload bytes in one go (the byte
// stream after the CRLF is consumed verbatim per RFC 3030).
async function _sendBdat(socket, payload, isLast) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      var lines = buf.split("\r\n").filter(Boolean);
      var last = lines[lines.length - 1];
      if (/^\d{3} /.test(last)) {
        socket.removeListener("data", onData);
        resolve(buf);
      }
    }
    socket.on("data", onData);
    socket.once("error", reject);
    var payloadBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
    socket.write("BDAT " + payloadBuf.length + (isLast ? " LAST" : "") + "\r\n");
    socket.write(payloadBuf);
  });
}

function testSurface() {
  check("submission.create is fn",
    typeof b.mail.server.submission.create === "function");
  check("MailServerSubmissionError is fn",
    typeof b.mail.server.submission.MailServerSubmissionError === "function");
}

function testCreateRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.submission.create({}); } catch (e) { threw = e; }
  check("submission.create refuses missing tlsContext",
    threw && threw.code === "mail-server-submission/no-tls-context");
}

function testStrictProfileRequiresAuthConfig() {
  var threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      // no auth config — strict default refuses
    });
  } catch (e) { threw = e; }
  check("strict profile refuses missing auth config",
    threw && threw.code === "mail-server-submission/no-auth");
}

function testPermissiveAllowsNoAuth() {
  var threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      profile:    "permissive",
    });
  } catch (e) { threw = e; }
  check("permissive accepts no auth (operator-acknowledged legacy)",
    threw === null);
}

function testBadAuthShapeRefused() {
  var threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      auth:       { mechanisms: [], verify: function () {} },
    });
  } catch (e) { threw = e; }
  check("empty mechanisms refused",
    threw && threw.code === "mail-server-submission/bad-auth");

  threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      auth:       { mechanisms: ["PLAIN"], verify: "not-a-fn" },
    });
  } catch (e) { threw = e; }
  check("non-function verify refused",
    threw && threw.code === "mail-server-submission/bad-auth");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.submission.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-submission/") === 0);
  }
  expectBad("negative maxLineBytes refused",
    { tlsContext: {}, profile: "permissive", maxLineBytes: -1 });
  expectBad("non-finite idleTimeoutMs refused",
    { tlsContext: {}, profile: "permissive", idleTimeoutMs: Infinity });
}

async function _makePermissiveServer() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { return null; }
  var handoffs = [];
  var agent = {
    handoff: function (env) {
      handoffs.push(env);
      return Promise.resolve({ messageId: "<test@bdat>" });
    },
  };
  var srv = b.mail.server.submission.create({
    tlsContext: ctx,
    profile:    "permissive",
    agent:      agent,
  });
  return { srv: srv, handoffs: handoffs };
}

async function testEhloAdvertisesChunking() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT CHUNKING advertised (skipped — no TLS ctx)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    var ehlo = await _sendCommand(socket, "EHLO client.example.com");
    check("EHLO advertises CHUNKING",          /250.CHUNKING/.test(ehlo));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatSingleLastChunk() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT single LAST chunk (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<sender@example.com>");
    await _sendCommand(socket, "RCPT TO:<recipient@example.com>");
    var body = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: BDAT test\r\n\r\nHello BDAT.";
    var reply = await _sendBdat(socket, body, true);
    check("BDAT LAST replies 250",             /^250 /m.test(reply));
    check("BDAT handed off to agent",          bundle.handoffs.length === 1);
    check("BDAT body bytes match exactly",
          bundle.handoffs[0] && bundle.handoffs[0].body.toString("utf8") === body);
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatMultipleChunksThenLast() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT multiple chunks (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    var part1 = "From: a@x\r\nTo: b@x\r\nSubject: Multi-chunk\r\n\r\n";
    var part2 = "First chunk of body.\r\n";
    var part3 = "Second chunk concludes.";
    var r1 = await _sendBdat(socket, part1, false);
    check("first BDAT chunk replies 250",       /^250 /m.test(r1));
    var r2 = await _sendBdat(socket, part2, false);
    check("second BDAT chunk replies 250",      /^250 /m.test(r2));
    var r3 = await _sendBdat(socket, part3, true);
    check("BDAT LAST replies 250",              /^250 /m.test(r3));
    check("agent received concatenated body",
          bundle.handoffs[0].body.toString("utf8") === part1 + part2 + part3);
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatZeroByteLast() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT zero-byte LAST (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    var body = "From: a@x\r\nTo: b@x\r\nSubject: Body in chunk 1 only\r\n\r\nAll bytes here.";
    await _sendBdat(socket, body, false);
    var r = await _sendCommand(socket, "BDAT 0 LAST");
    check("zero-byte BDAT LAST replies 250",    /^250 /m.test(r));
    check("agent received chunk-1 body intact", bundle.handoffs[0].body.toString("utf8") === body);
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatOutsideTransaction() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT outside transaction (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    var r = await _sendCommand(socket, "BDAT 5 LAST");
    check("BDAT before MAIL FROM → 503",       /^503 /m.test(r));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatBadArgs() {
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT bad args (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    // guardSmtpCommand pre-validates BDAT shape → 500 5.5.2 (syntax)
    // before our handler returns 501 5.5.4. Either is a refusal.
    var r1 = await _sendCommand(socket, "BDAT");
    check("BDAT missing size refused",         /^5\d\d /m.test(r1));
    var r2 = await _sendCommand(socket, "BDAT abc");
    check("BDAT non-integer size refused",     /^5\d\d /m.test(r2));
    var r3 = await _sendCommand(socket, "BDAT 10 NOTLAST");
    check("BDAT invalid 3rd arg refused",      /^5\d\d /m.test(r3));
    var r4 = await _sendCommand(socket, "BDAT -5 LAST");
    check("BDAT negative size refused",        /^5\d\d /m.test(r4));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatBinaryBytesPreserved() {
  // Codex P1 — BDAT payloads can be 8-bit / binary (BINARYMIME, MIME
  // attachments). The line-buffer drain MUST NOT round-trip bytes
  // through UTF-8 — invalid sequences get replaced with U+FFFD and
  // the body corrupts. Send a payload containing every non-CR/LF
  // byte value 0x00..0xFF and assert byte-for-byte equality.
  var bundle = await _makePermissiveServer();
  if (!bundle) { check("BDAT binary bytes preserved (skipped)", true); return; }
  var srv = bundle.srv;
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    // RFC 822-shaped header + binary body (every byte except CR/LF
    // in the body slot). Header MUST end with CRLF CRLF; the binary
    // section starts after.
    var header = Buffer.from(
      "From: a@example.com\r\nTo: b@example.com\r\nSubject: bin\r\n" +
      "Content-Type: application/octet-stream\r\n\r\n", "utf8");
    var binBytes = [];
    for (var i = 0; i < 256; i += 1) {
      // Skip 0x0A/0x0D — bare CR/LF inside a BDAT header section
      // would still be invalid SMTP, but for the body any byte is
      // legal under BINARYMIME.
      binBytes.push(i);
    }
    var body = Buffer.concat([header, Buffer.from(binBytes)]);
    var reply = await _sendBdat(socket, body, true);
    check("BDAT LAST with binary body → 250",   /^250 /m.test(reply));
    check("agent received body length",        bundle.handoffs[0] && bundle.handoffs[0].body.length === body.length);
    // Byte-for-byte equality
    var same = bundle.handoffs[0].body.equals(body);
    check("agent received body byte-equal",    same === true);
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

async function testBdatOversizeRefused() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("BDAT oversize (skipped)", true); return; }
  // Tight 1 KiB cap so the test runs fast.
  var srv = b.mail.server.submission.create({
    tlsContext:      ctx,
    profile:         "permissive",
    maxMessageBytes: 1024,                                                                             // allow:raw-byte-literal — tight test cap to exercise size refusal
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO client.example.com");
    await _sendCommand(socket, "MAIL FROM:<a@example.com>");
    await _sendCommand(socket, "RCPT TO:<b@example.com>");
    var r = await _sendCommand(socket, "BDAT 99999 LAST");
    check("BDAT exceeds cap → 552",            /^552 /m.test(r));
    socket.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                                  // allow:raw-time-literal — test-only short drain
}

var NUL = String.fromCharCode(0);
var LF  = String.fromCharCode(10);
var CR  = String.fromCharCode(13);

// ---- socket plumbing ----

function _readReply(socket) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      // A complete SMTP reply always ends with CRLF; only then is its
      // final line the terminal "NNN <text>" (a multiline reply's earlier
      // lines are "NNN-<text>"). Requiring the trailing CRLF prevents
      // resolving on a chunk boundary that happens to split mid-reply.
      if (!/\r\n$/.test(buf)) return;
      var lines = buf.split("\r\n").filter(Boolean);
      var last = lines[lines.length - 1];
      if (last && /^\d{3} /.test(last)) {
        socket.removeListener("data", onData);
        socket.removeListener("error", onErr);
        resolve(buf);
      }
    }
    function onErr(e) {
      socket.removeListener("data", onData);
      reject(e);
    }
    socket.on("data", onData);
    socket.once("error", onErr);
  });
}

function _send(socket, line) {
  var p = _readReply(socket);
  socket.write(line + "\r\n");
  return p;
}

// Write raw bytes and read the next reply (for DATA-body payloads).
function _writeRaw(socket, bytes) {
  var p = _readReply(socket);
  socket.write(bytes);
  return p;
}

// DATA command → 354 → dot-terminated body → final reply.
async function _dataDot(socket, body) {
  await _send(socket, "DATA");
  return _writeRaw(socket, body + "\r\n.\r\n");
}

async function _makeTestTlsContextWithCa() {
  var ca = await b.mtlsEngine.generateCa({ name: "submission-wire-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "submission.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:submission.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return {
    ctx:   nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert }),
    caPem: ca.caCertPem,
  };
}

// Build + listen a submission server sharing the test TLS context.
async function _mk(tls, extra) {
  var handoffs = [];
  var opts = { tlsContext: tls.ctx };
  if (extra) { Object.keys(extra).forEach(function (k) { opts[k] = extra[k]; }); }
  var srv = b.mail.server.submission.create(opts);
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  return { srv: srv, port: info.port, caPem: tls.caPem, handoffs: handoffs };
}

function _agentCapturing(handoffs, mode) {
  return {
    handoff: function (env) {
      handoffs.push(env);
      if (mode === "reject") return Promise.reject(new Error("upstream down"));
      return Promise.resolve({ messageId: "<accepted@test>" });
    },
  };
}

function _connect(port) {
  var socket = nodeNet.connect(port, "127.0.0.1");
  socket.on("error", function () { /* swallow ECONNRESET on close */ });
  return new Promise(function (resolve, reject) {
    socket.once("connect", function () { resolve(socket); });
    socket.once("error", reject);
  });
}

async function _tlsUpgrade(rawSocket, caPem) {
  var tls = nodeTls.connect({ socket: rawSocket, ca: caPem, servername: "localhost" });
  tls.on("error", function () {});
  await new Promise(function (r, j) { tls.once("secureConnect", r); tls.once("error", j); });
  return tls;
}

// SASL PLAIN blob (authzid NUL authcid NUL passwd), base64.
function _saslPlain(user, pass) {
  return Buffer.from(["", user, pass].join(NUL), "utf8").toString("base64");
}

// ---- create() defensive branches ----

function testCreateValidation(tls) {
  function expect(label, opts, code) {
    var threw = null;
    try { b.mail.server.submission.create(opts); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  // Non-object opts.
  var threwObj = null;
  try { b.mail.server.submission.create(null); } catch (e) { threwObj = e; }
  check("null opts refused", threwObj && (threwObj.code || "").indexOf("mail-server-submission/") === 0);

  // Missing tlsContext.
  var threwTls = null;
  try { b.mail.server.submission.create({ profile: "permissive" }); } catch (e) { threwTls = e; }
  check("missing tlsContext refused", threwTls && threwTls.code === "mail-server-submission/no-tls-context");
  // Strict profile requires auth.
  expect("strict profile without auth refused",
    { tlsContext: tls.ctx }, "mail-server-submission/no-auth");
  // Bad auth.verify + bad mechanisms.
  expect("non-function auth.verify refused",
    { tlsContext: tls.ctx, auth: { verify: "nope" } }, "mail-server-submission/bad-auth");
  expect("empty auth.mechanisms refused",
    { tlsContext: tls.ctx, auth: { verify: function () {}, mechanisms: [] } }, "mail-server-submission/bad-auth");
  // Bad numeric bound.
  var threwBound = null;
  try { b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive", maxLineBytes: -1 }); } catch (e) { threwBound = e; }
  check("negative maxLineBytes refused", threwBound && (threwBound.code || "").indexOf("mail-server-submission/") === 0);

  expect("bad tenantScope (no check fn) refused",
    { tlsContext: tls.ctx, profile: "permissive", tenantScope: {}, agentTenantId: "t1" },
    "mail-server-submission/bad-tenant-scope");
  expect("tenantScope without agentTenantId refused",
    { tlsContext: tls.ctx, profile: "permissive", tenantScope: { check: function () {} } },
    "mail-server-submission/no-agent-tenant-id");
  expect("bad dkimRequireMode refused",
    { tlsContext: tls.ctx, profile: "permissive", dkimRequireMode: "sometimes" },
    "mail-server-submission/bad-dkim-require-mode");

  // guardDomain:false + guardDomain object both accepted at create.
  var okA = null, okB = null;
  try { b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive", guardDomain: false }); } catch (e) { okA = e; }
  try { b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive", guardDomain: { profile: "strict" } }); } catch (e) { okB = e; }
  check("guardDomain:false accepted", okA === null);
  check("guardDomain object accepted", okB === null);
}

async function testCloseBeforeListen(tls) {
  var srv = b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive" });
  var threw = null;
  try { await srv.close(); } catch (e) { threw = e; }
  check("close() before listen() is a no-op", threw === null);
  check("connectionCount is 0 before listen", srv.connectionCount() === 0);
  check("_portForTest is null before listen", srv._portForTest() === null);
}

async function testDoubleListen(tls) {
  var srv = b.mail.server.submission.create({ tlsContext: tls.ctx, profile: "permissive" });
  await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    check("_portForTest returns a bound port", typeof srv._portForTest() === "number" && srv._portForTest() > 0);
    var threw = null;
    try { await srv.listen({ port: 0, address: "127.0.0.1" }); } catch (e) { threw = e; }
    check("double listen() refused (already-listening)",
      threw && (threw.code || "").indexOf("mail-server-submission/") === 0);
  } finally { await srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- permissive dispatch + wrong-state + malformed refusals ----

async function testPermissiveDispatch(tls) {
  var s = await _mk(tls, { profile: "permissive" });
  var sock = await _connect(s.port);
  try {
    check("greeting is 220", /^220 /.test(await _readReply(sock)));

    // Wrong-state before EHLO.
    check("MAIL before EHLO → 503",  /^503 /.test(await _send(sock, "MAIL FROM:<a@example.com>")));
    check("RCPT before MAIL → 503",  /^503 /.test(await _send(sock, "RCPT TO:<b@example.com>")));
    check("DATA before RCPT → 503",  /^503 /.test(await _send(sock, "DATA")));
    check("BDAT before MAIL → 503",  /^5\d\d /.test(await _send(sock, "BDAT 3 LAST")));

    // HELO single-line reply branch.
    check("HELO replies single 250", /^250 /.test(await _send(sock, "HELO client.example.com")));
    // EHLO multiline with STARTTLS advertised (plaintext port).
    var ehlo = await _send(sock, "EHLO client.example.com");
    check("EHLO advertises PIPELINING", /250[ -]PIPELINING/.test(ehlo));
    check("EHLO advertises STARTTLS (plaintext port)", /250[ -]STARTTLS/.test(ehlo));
    check("EHLO advertises CHUNKING", /250[ -]CHUNKING/.test(ehlo));

    // Simple verbs.
    check("NOOP → 250", /^250 /.test(await _send(sock, "NOOP")));
    check("VRFY → 502", /^502 /.test(await _send(sock, "VRFY alice")));
    check("EXPN → 502", /^502 /.test(await _send(sock, "EXPN list")));
    // Unknown verb passes guardSmtpCommand under permissive → switch default 500.
    check("unknown verb → 500", /^500 /.test(await _send(sock, "FLOOP arg")));
    // HELP is a guardSmtpCommand-known verb with no submission handler →
    // reaches the switch default (500 Unknown command).
    check("HELP → 500 (no handler)", /^500 /.test(await _send(sock, "HELP")));

    // Control-char / NUL / bare-LF / bare-CR refusals (guardSmtpCommand → 500).
    check("bare-LF in command → 500", /^500 /.test(await _writeRaw(sock, "NOOP" + LF + "X\r\n")));
    check("bare-CR in command → 500", /^500 /.test(await _writeRaw(sock, "NOOP" + CR + "X\r\n")));
    check("NUL in command → 500",     /^500 /.test(await _writeRaw(sock, "NOOP" + NUL + "X\r\n")));

    // RSET resets, QUIT closes.
    check("RSET → 250", /^250 /.test(await _send(sock, "RSET")));
    check("QUIT → 221", /^221 /.test(await _send(sock, "QUIT")));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- domain hardening refusals (HELO / MAIL FROM / RCPT TO) ----

async function testDomainRefusals(tls) {
  var s = await _mk(tls, { profile: "permissive", guardDomain: { profile: "strict" } });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    // Bare-IPv4 domain refused (CVE-2021-22931 class) at HELO.
    check("EHLO bare-IP domain → 501", /^501 /.test(await _send(sock, "EHLO 10.0.0.1")));
    // Valid EHLO to advance.
    check("EHLO valid domain → 250", /^250[ -]/.test(await _send(sock, "EHLO client.example.com")));
    // MAIL FROM with bare-IP domain refused.
    check("MAIL FROM bare-IP domain → 501", /^501 /.test(await _send(sock, "MAIL FROM:<a@10.0.0.1>")));
    // Valid MAIL FROM.
    check("MAIL FROM valid → 250", /^250 /.test(await _send(sock, "MAIL FROM:<a@example.com>")));
    // RCPT TO with bare-IP domain refused.
    check("RCPT TO bare-IP domain → 501", /^501 /.test(await _send(sock, "RCPT TO:<b@127.0.0.1>")));
    check("RCPT TO valid → 250", /^250 /.test(await _send(sock, "RCPT TO:<b@example.com>")));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- DATA path (audit-only + agent handoff success + agent reject) ----

async function testDataPaths(tls) {
  // Audit-only (no agent), permissive.
  var s1 = await _mk(tls, { profile: "permissive" });
  var sock = await _connect(s1.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");
    var body = "From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nHello.";
    check("DATA audit-only → 250", /^250 /.test(await _dataDot(sock, body)));
  } finally { sock.destroy(); await s1.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Agent handoff resolves → outbound_routed 250.
  var h2 = [];
  var s2 = await _mk(tls, { profile: "permissive", agent: _agentCapturing(h2, "accept") });
  var sock2 = await _connect(s2.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    await _send(sock2, "MAIL FROM:<a@example.com>");
    await _send(sock2, "RCPT TO:<b@example.com>");
    var reply = await _dataDot(sock2, "From: a@example.com\r\n\r\nbody");
    check("agent handoff accepted → 250 with id", /^250 .*accepted/.test(reply));
    check("agent received one handoff", h2.length === 1);
    check("handoff direction outbound", h2[0] && h2[0].direction === "outbound");
  } finally { sock2.destroy(); await s2.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Agent handoff resolves without a messageId → 250 without id suffix.
  var hEmpty = [];
  var sEmpty = await _mk(tls, {
    profile: "permissive",
    agent: { handoff: function (env) { hEmpty.push(env); return Promise.resolve({}); } },
  });
  var sockE = await _connect(sEmpty.port);
  try {
    await _readReply(sockE);
    await _send(sockE, "EHLO client.example.com");
    await _send(sockE, "MAIL FROM:<a@example.com>");
    await _send(sockE, "RCPT TO:<b@example.com>");
    check("agent ack without messageId → 250", /^250 /.test(await _dataDot(sockE, "From: a@example.com\r\n\r\nx")));
  } finally { sockE.destroy(); await sEmpty.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Agent handoff rejects → 451.
  var h3 = [];
  var s3 = await _mk(tls, { profile: "permissive", agent: _agentCapturing(h3, "reject") });
  var sock3 = await _connect(s3.port);
  try {
    await _readReply(sock3);
    await _send(sock3, "EHLO client.example.com");
    await _send(sock3, "MAIL FROM:<a@example.com>");
    await _send(sock3, "RCPT TO:<b@example.com>");
    check("agent handoff rejected → 451", /^451 /.test(await _dataDot(sock3, "From: a@example.com\r\n\r\nx")));
  } finally { sock3.destroy(); await s3.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- BDAT extra branches (0-not-last ack, cumulative cap, DATA-before-RCPT) ----

async function testBdatBranches(tls) {
  var h = [];
  var s = await _mk(tls, { profile: "permissive", agent: _agentCapturing(h, "accept") });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    // BDAT with zero recipients → 503.
    check("BDAT with no rcpts → 503", /^503 /.test(await _send(sock, "BDAT 3 LAST")));
    await _send(sock, "RCPT TO:<b@example.com>");
    // Zero-byte non-last chunk → 250 "0 octets received".
    check("BDAT 0 (not last) → 250 0 octets", /^250 .*0 octets/.test(await _send(sock, "BDAT 0")));
    // A real chunk then LAST.
    var part = "From: a@example.com\r\n\r\npayload";
    var pbuf = Buffer.from(part, "utf8");
    var r = _readReply(sock);
    sock.write("BDAT " + pbuf.length + " LAST\r\n");
    sock.write(pbuf);
    check("BDAT LAST finalizes → 250", /^250 /.test(await r));
    await helpers.waitUntil(function () { return h.length >= 1; },
      { timeoutMs: 5000, label: "submission BDAT: agent handoff received after BDAT LAST" });
    check("agent got BDAT body", h.length === 1 && h[0].body.toString("utf8") === part);
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- cleartext AUTH accepted + identity binding (strict) ----

async function testCleartextAuthAndIdentity(tls) {
  var s = await _mk(tls, {
    profile:         "permissive",
    identityBinding: "strict",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        var user = parts[1];
        if (user === "empty") return Promise.resolve({ ok: true, actor: { id: "empty@example.com" } });
        // "solo" carries a single-mailbox STRING (not the array form).
        if (user === "solo") return Promise.resolve({ ok: true, actor: { id: "solo@example.com", mailbox: "solo@example.com" } });
        return Promise.resolve({ ok: true, actor: { id: user + "@example.com", mailboxes: ["ok@example.com"] } });
      },
    },
  });

  // Actor with a mailbox set.
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    check("cleartext AUTH PLAIN accepted → 235",
      /^235 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("ok", "pw"))));
    check("AUTH again after success → 503",
      /^503 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("ok", "pw"))));
    // Identity binding: not in set → 553.
    check("MAIL FROM not in actor set → 553",
      /^553 /.test(await _send(sock, "MAIL FROM:<evil@example.com>")));
    check("RSET → 250", /^250 /.test(await _send(sock, "RSET")));
    // In set → 250.
    check("MAIL FROM in actor set → 250",
      /^250 /.test(await _send(sock, "MAIL FROM:<ok@example.com>")));
  } finally { sock.destroy(); }

  // Actor with NO mailboxes → every MAIL FROM refused.
  var sock2 = await _connect(s.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    await _send(sock2, "AUTH PLAIN " + _saslPlain("empty", "pw"));
    check("MAIL FROM with no-mailbox actor → 553",
      /^553 /.test(await _send(sock2, "MAIL FROM:<whatever@example.com>")));
  } finally { sock2.destroy(); }

  // Actor whose mailbox set is the single-string form.
  var sock3 = await _connect(s.port);
  try {
    await _readReply(sock3);
    await _send(sock3, "EHLO client.example.com");
    await _send(sock3, "AUTH PLAIN " + _saslPlain("solo", "pw"));
    check("MAIL FROM matching string-mailbox actor → 250",
      /^250 /.test(await _send(sock3, "MAIL FROM:<solo@example.com>")));
  } finally { sock3.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- AUTH failures: mech-not-advertised, verify-fail, verify-throw, multi-step ----

async function testAuthFailuresAndMultiStep(tls) {
  var s = await _mk(tls, {
    profile: "permissive",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (mech, creds) {
        if (mech === "LOGIN") {
          if (creds.step === 0) return Promise.resolve({ pending: true, challenge: Buffer.from("Username:", "utf8").toString("base64") });
          return Promise.resolve({ ok: true, actor: { id: "u@example.com" } });
        }
        if (mech === "PLAIN") {
          var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
          if (parts[2] === "boom") return Promise.reject(new Error("backend exploded"));
          if (parts[2] === "good") return Promise.resolve({ ok: true, actor: { id: parts[1] } });
          return Promise.resolve({ ok: false, reason: "bad-password" });
        }
        return Promise.resolve({ ok: false });
      },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    // Mechanism not advertised → 535.
    check("AUTH unadvertised mech → 535", /^535 /.test(await _send(sock, "AUTH CRAM-MD5 abcd")));
    // verify returns { ok:false } → 535.
    check("AUTH verify-fail → 535", /^535 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "nope"))));
    // verify throws → 535.
    check("AUTH verify-throw → 535", /^535 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "boom"))));
    // Multi-step LOGIN: 334 challenge then 235.
    check("AUTH LOGIN issues 334 challenge", /^334 /.test(await _send(sock, "AUTH LOGIN")));
    check("AUTH LOGIN completes → 235",
      /^235 /.test(await _send(sock, Buffer.from("user", "utf8").toString("base64"))));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- AUTH-failure per-IP rate-limit (421 + close) ----

async function testAuthRateLimit(tls) {
  var s = await _mk(tls, {
    profile:   "permissive",
    rateLimit: { authFailuresPerIpPer15Min: 1 },
    auth: {
      mechanisms: ["PLAIN"],
      verify: function () { return Promise.resolve({ ok: false, reason: "always-fail" }); },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    check("first AUTH fails → 535", /^535 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "x"))));
    // Second attempt trips the per-IP budget → 421 + close.
    check("AUTH over budget → 421", /^421 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "y"))));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- cross-tenant refusal ----

async function testCrossTenant(tls) {
  var tenantScope = {
    check: function (actor, tid) {
      if (!actor || actor.tenantId !== tid) {
        var e = new Error("cross-tenant"); e.code = "tenant/mismatch"; throw e;
      }
    },
  };
  var s = await _mk(tls, {
    profile:       "permissive",
    tenantScope:   tenantScope,
    agentTenantId: "t1",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        return Promise.resolve({ ok: true, actor: { id: parts[1], tenantId: parts[1] === "right" ? "t1" : "t2" } });
      },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    check("wrong tenant → 535 cross-tenant",
      /^535 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("wrong", "x"))));
  } finally { sock.destroy(); }

  var sock2 = await _connect(s.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    check("right tenant → 235",
      /^235 /.test(await _send(sock2, "AUTH PLAIN " + _saslPlain("right", "x"))));
  } finally { sock2.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- strict profile: pre-TLS refusals, STARTTLS upgrade, DKIM-required ----

async function testStrictProfileStartTls(tls) {
  var s = await _mk(tls, {
    profile: "strict",
    auth: {
      mechanisms: ["PLAIN", "LOGIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        return Promise.resolve({ ok: true, actor: { id: (parts[1] || "u") + "@example.com", mailboxes: ["ok@example.com"] } });
      },
    },
  });
  var raw = await _connect(s.port);
  try {
    await _readReply(raw);
    var ehlo = await _send(raw, "EHLO client.example.com");
    check("strict EHLO advertises STARTTLS", /250[ -]STARTTLS/.test(ehlo));
    check("strict EHLO hides AUTH pre-TLS",   !/AUTH /.test(ehlo));
    check("AUTH before STARTTLS → 538", /^538 /.test(await _send(raw, "AUTH PLAIN " + _saslPlain("ok", "x"))));
    check("MAIL before STARTTLS → 530", /^530 /.test(await _send(raw, "MAIL FROM:<ok@example.com>")));
    check("STARTTLS → 220", /^220 /.test(await _send(raw, "STARTTLS")));

    var tsock = await _tlsUpgrade(raw, s.caPem);
    var ehlo2 = await _send(tsock, "EHLO client.example.com");
    check("post-TLS EHLO advertises AUTH", /AUTH /.test(ehlo2));
    check("post-TLS EHLO hides STARTTLS",  !/250[ -]STARTTLS/.test(ehlo2));
    check("STARTTLS after upgrade → 503",  /^503 /.test(await _send(tsock, "STARTTLS")));
    // Over TLS but not yet authenticated → strict profile still requires AUTH.
    check("MAIL over TLS pre-AUTH (strict) → 530", /^530 /.test(await _send(tsock, "MAIL FROM:<ok@example.com>")));
    check("AUTH over TLS succeeds → 235",  /^235 /.test(await _send(tsock, "AUTH PLAIN " + _saslPlain("ok", "x"))));
    // Identity binding (strict default): not-in-set 553, then in-set OK.
    check("MAIL not-in-set over TLS → 553", /^553 /.test(await _send(tsock, "MAIL FROM:<evil@example.com>")));
    await _send(tsock, "RSET");
    check("MAIL in-set over TLS → 250",     /^250 /.test(await _send(tsock, "MAIL FROM:<ok@example.com>")));
    check("RCPT over TLS → 250",            /^250 /.test(await _send(tsock, "RCPT TO:<b@example.com>")));
    // strict requireDkim default true + no DKIM-Signature → 550.
    check("DATA without DKIM (strict) → 550", /^550 /.test(await _dataDot(tsock, "From: ok@example.com\r\n\r\nno dkim here")));
    tsock.destroy();
  } finally { raw.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- implicit-TLS ----

async function testImplicitTls(tls) {
  var s = await _mk(tls, { profile: "permissive", implicitTls: true });
  var raw = await _connect(s.port);
  var tsock = null;
  try {
    tsock = await _tlsUpgrade(raw, s.caPem);
    check("implicit-TLS greeting is 220", /^220 /.test(await _readReply(tsock)));
    var ehlo = await _send(tsock, "EHLO client.example.com");
    check("implicit-TLS EHLO hides STARTTLS", !/250[ -]STARTTLS/.test(ehlo));
    // On implicit-TLS, state.tls is already true, so STARTTLS is refused as
    // "already active" (503) — the RFC 8314 502 branch is unreachable here.
    // Either way STARTTLS is correctly refused.
    check("STARTTLS on implicit-TLS refused (5xx)", /^5\d\d /.test(await _send(tsock, "STARTTLS")));
    check("MAIL FROM over implicit-TLS → 250", /^250 /.test(await _send(tsock, "MAIL FROM:<a@example.com>")));
    check("RCPT over implicit-TLS → 250", /^250 /.test(await _send(tsock, "RCPT TO:<b@example.com>")));
    check("DATA over implicit-TLS → 250", /^250 /.test(await _dataDot(tsock, "From: a@example.com\r\n\r\nx")));
  } finally { if (tsock) tsock.destroy(); raw.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- DKIM-required modes (any / self / mismatch / no header block) ----

async function _dkimTxn(port, body) {
  var sock = await _connect(port);
  await _readReply(sock);
  await _send(sock, "EHLO client.example.com");
  await _send(sock, "MAIL FROM:<a@example.com>");
  await _send(sock, "RCPT TO:<b@example.com>");
  var reply = await _dataDot(sock, body);
  sock.destroy();
  return reply;
}

async function testDkimModes(tls) {
  // any: present → ok, absent → 550.
  var sAny = await _mk(tls, { profile: "permissive", requireDkim: true, dkimRequireMode: "any" });
  try {
    check("dkim any: signature present → 250",
      /^250 /.test(await _dkimTxn(sAny.port, "DKIM-Signature: v=1; d=example.com; b=zzz\r\nFrom: a@example.com\r\n\r\nbody")));
    check("dkim any: no signature → 550",
      /^550 /.test(await _dkimTxn(sAny.port, "From: a@example.com\r\n\r\nbody")));
    // header block with no blank line (headerEnd === -1) still finds the sig.
    check("dkim any: no header/body split still finds sig → 250",
      /^250 /.test(await _dkimTxn(sAny.port, "DKIM-Signature: v=1; d=example.com; b=zzz")));
    // Folded DKIM-Signature (continuation line begins with SP) is unfolded.
    check("dkim any: folded signature accepted → 250",
      /^250 /.test(await _dkimTxn(sAny.port, "DKIM-Signature: v=1;\r\n d=example.com;\r\n b=zzz\r\nFrom: a@example.com\r\n\r\nbody")));
  } finally { await sAny.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // self: d= must match envelope-sender domain (no auth → falls back to MAIL FROM domain).
  var sSelf = await _mk(tls, { profile: "permissive", requireDkim: true, dkimRequireMode: "self" });
  try {
    check("dkim self: matching d= → 250",
      /^250 /.test(await _dkimTxn(sSelf.port, "DKIM-Signature: v=1; d=example.com; b=zzz\r\nFrom: a@example.com\r\n\r\nbody")));
    check("dkim self: mismatched d= → 550",
      /^550 /.test(await _dkimTxn(sSelf.port, "DKIM-Signature: v=1; d=other.org; b=zzz\r\nFrom: a@example.com\r\n\r\nbody")));
  } finally { await sSelf.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // off: requireDkim forced false → DATA without sig accepted.
  var sOff = await _mk(tls, { profile: "permissive", requireDkim: true, dkimRequireMode: "off" });
  try {
    check("dkim off: no signature accepted → 250",
      /^250 /.test(await _dkimTxn(sOff.port, "From: a@example.com\r\n\r\nbody")));
  } finally { await sOff.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- recipientPolicy accept / refuse / throw + rcpt cap ----

async function testRecipientPolicy(tls) {
  var s = await _mk(tls, {
    profile:            "permissive",
    maxRcptsPerMessage: 2,
    recipientPolicy: function (ctx) {
      if (ctx.rcptTo.indexOf("throw@") === 0) return Promise.reject(new Error("policy engine down"));
      if (ctx.rcptTo.indexOf("deny@") === 0) return Promise.resolve({ ok: false, reason: "on deny list" });
      return Promise.resolve({ ok: true });
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    check("recipientPolicy accept → 250", /^250 /.test(await _send(sock, "RCPT TO:<ok@example.com>")));
    check("recipientPolicy refuse → 550", /^550 /.test(await _send(sock, "RCPT TO:<deny@example.com>")));
    check("recipientPolicy throw → 451",  /^451 /.test(await _send(sock, "RCPT TO:<throw@example.com>")));
    // Second accepted recipient reaches the cap (2); a third → 452.
    check("second accepted rcpt → 250", /^250 /.test(await _send(sock, "RCPT TO:<ok2@example.com>")));
    check("rcpt over cap → 452",        /^452 /.test(await _send(sock, "RCPT TO:<ok3@example.com>")));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- concurrent-connection rate-limit ----

async function testConnRateLimit(tls) {
  var s = await _mk(tls, { profile: "permissive", rateLimit: { maxConcurrentConnectionsPerIp: 1 } });
  var first = await _connect(s.port);
  try {
    check("first connection greeted 220", /^220 /.test(await _readReply(first)));
    var second = await _connect(s.port);
    check("second connection from same IP → 421", /^421 /.test(await _readReply(second)));
    second.destroy();
  } finally { first.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- line-too-long, body-too-large, DATA smuggling, SIZE-exceeds ----

async function testLimitsAndSmuggling(tls) {
  // Line too long: cap is maxLineBytes*4.
  var sLine = await _mk(tls, { profile: "permissive", maxLineBytes: b.constants.BYTES.bytes(16) });
  var lsock = await _connect(sLine.port);
  try {
    await _readReply(lsock);
    var longLine = "NOOP " + new Array(200).join("A"); // ~204 bytes > 16*4
    check("overlong command line → 500", /^500 /.test(await _send(lsock, longLine)));
  } finally { lsock.destroy(); await sLine.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Body too large + SIZE-declared refusal + smuggling, tight maxMessageBytes.
  var sBody = await _mk(tls, { profile: "permissive", maxMessageBytes: b.constants.BYTES.kib(1) });
  var bsock = await _connect(sBody.port);
  try {
    await _readReply(bsock);
    await _send(bsock, "EHLO client.example.com");
    // SIZE param exceeds fixed maximum → 552.
    check("MAIL FROM SIZE over max → 552",
      /^552 /.test(await _send(bsock, "MAIL FROM:<a@example.com> SIZE=999999")));
    await _send(bsock, "MAIL FROM:<a@example.com>");
    await _send(bsock, "RCPT TO:<b@example.com>");
    // Over-cap DATA body → 552.
    var big = new Array(2100).join("A"); // ~2099 bytes > 1 KiB
    check("DATA body over max → 552", /^552 /.test(await _dataDot(bsock, big)));
  } finally { bsock.destroy(); await sBody.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // DATA-body bare-LF-dot smuggling → 554.
  var sSm = await _mk(tls, { profile: "permissive" });
  var ssock = await _connect(sSm.port);
  try {
    await _readReply(ssock);
    await _send(ssock, "EHLO client.example.com");
    await _send(ssock, "MAIL FROM:<a@example.com>");
    await _send(ssock, "RCPT TO:<b@example.com>");
    await _send(ssock, "DATA");
    // bare-LF dot line — CVE-2023-51764 smuggling shape.
    check("DATA bare-LF-dot smuggling → 554",
      /^554 /.test(await _writeRaw(ssock, "evil body" + LF + "." + LF + "injected")));
  } finally { ssock.destroy(); await sSm.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- AUTH not configured (permissive, no auth) ----

async function testAuthNotConfigured(tls) {
  var s = await _mk(tls, { profile: "permissive" });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    check("AUTH with no authenticator → 502", /^502 /.test(await _send(sock, "AUTH PLAIN " + _saslPlain("u", "p"))));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- idle timeout ----

async function testIdleTimeout(tls) {
  var s = await _mk(tls, { profile: "permissive", idleTimeoutMs: b.constants.TIME.seconds(1) });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock); // greeting
    // No further traffic → server should fire the idle-timeout 421.
    var reply = await _readReply(sock);
    check("idle timeout → 421", /^421 /.test(reply));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- close() drain writes 421 to live sockets ----

async function testCloseDrain(tls) {
  var s = await _mk(tls, { profile: "permissive" });
  var sock = await _connect(s.port);
  await _readReply(sock);
  check("connectionCount is 1 with a live socket", s.srv.connectionCount() >= 1);
  var got421 = false;
  sock.on("data", function (c) { if (/421 /.test(c.toString("utf8"))) got421 = true; });
  var closing = s.srv.close({ timeoutMs: b.constants.TIME.seconds(5) });
  // Let the drain write its 421, then release the socket so close resolves fast.
  await helpers.waitUntil(function () { return got421; }, {
    timeoutMs: b.constants.TIME.seconds(3),
    label:     "close-drain: 421 shutdown notice delivered",
  });
  sock.destroy();
  await closing;
  check("close() drained live socket with 421", got421 === true);
  check("connectionCount is 0 after close", s.srv.connectionCount() === 0);
}

// ---- BDAT: non-final chunk ack, tail re-feed, empty-LAST, cumulative cap ----

async function testBdatMore(tls) {
  var h = [];
  var s = await _mk(tls, { profile: "permissive", agent: _agentCapturing(h, "accept") });

  // Non-final non-zero chunk → "N octets received", then finalize.
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");
    var r1 = _readReply(sock);
    sock.write("BDAT 5\r\n");
    sock.write("abcde");
    check("BDAT non-final chunk → 250 N octets", /^250 .*octets/.test(await r1));
    // Tail re-feed: BDAT chunk + trailing command in one segment.
    var r2 = _readReply(sock);
    sock.write("BDAT 3\r\nxyzNOOP\r\n");
    check("BDAT chunk with pipelined tail → 250", /^250 /.test(await r2));
    // Zero-byte LAST after real chunks → finalizes the accumulated body.
    check("BDAT 0 LAST after chunks → 250", /^250 /.test(await _send(sock, "BDAT 0 LAST")));
    await helpers.waitUntil(function () { return h.length >= 1; },
      { timeoutMs: 5000, label: "submission BDAT: agent handoff received after BDAT 0 LAST" });
    check("agent received accumulated BDAT body", h.length === 1 && h[0].body.toString("utf8") === "abcdexyz");
  } finally { sock.destroy(); }

  // BDAT 0 LAST as the only chunk → empty body finalized.
  var sock2 = await _connect(s.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    await _send(sock2, "MAIL FROM:<a@example.com>");
    await _send(sock2, "RCPT TO:<b@example.com>");
    check("BDAT 0 LAST empty message → 250", /^250 /.test(await _send(sock2, "BDAT 0 LAST")));
  } finally { sock2.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }

  // Cumulative-size cap up-front refusal.
  var sCap = await _mk(tls, { profile: "permissive", maxMessageBytes: b.constants.BYTES.kib(1) });
  var sock3 = await _connect(sCap.port);
  try {
    await _readReply(sock3);
    await _send(sock3, "EHLO client.example.com");
    await _send(sock3, "MAIL FROM:<a@example.com>");
    await _send(sock3, "RCPT TO:<b@example.com>");
    check("BDAT cumulative over cap → 552", /^552 /.test(await _send(sock3, "BDAT 99999 LAST")));
  } finally { sock3.destroy(); await sCap.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- PIPELINING: RCPT verdict still in-flight when DATA / BDAT arrives ----

async function testPipeliningRace(tls) {
  var s = await _mk(tls, {
    profile: "permissive",
    // Async accept: the verdict resolves on a microtask AFTER the pipelined
    // DATA / BDAT line is dispatched in the same ingest pass.
    recipientPolicy: function () { return Promise.resolve({ ok: true }); },
  });

  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "MAIL FROM:<a@example.com>");
    await _send(sock, "RCPT TO:<committed@example.com>"); // one committed recipient
    // Pipeline a second RCPT (verdict pending) + DATA in one segment.
    var r = _readReply(sock);
    sock.write("RCPT TO:<pending@example.com>\r\nDATA\r\n");
    check("DATA while RCPT verdict pending → 451", /^451 /.test(await r));
  } finally { sock.destroy(); }

  var sock2 = await _connect(s.port);
  try {
    await _readReply(sock2);
    await _send(sock2, "EHLO client.example.com");
    await _send(sock2, "MAIL FROM:<a@example.com>");
    await _send(sock2, "RCPT TO:<committed@example.com>");
    var r2 = _readReply(sock2);
    sock2.write("RCPT TO:<pending@example.com>\r\nBDAT 5 LAST\r\n");
    check("BDAT while RCPT verdict pending → 451", /^451 /.test(await r2));
  } finally { sock2.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

// ---- DKIM self mode with an authenticated actor (id-domain fallback) +
//      d-less signature + folded signature ----

async function testDkimSelfActor(tls) {
  var s = await _mk(tls, {
    profile:         "permissive",
    identityBinding: "permissive",         // allow MAIL FROM without a mailbox set
    requireDkim:     true,
    dkimRequireMode: "self",
    auth: {
      mechanisms: ["PLAIN"],
      verify: function (mech, creds) {
        var parts = Buffer.from(creds.clientResponse || "", "base64").toString("utf8").split(NUL);
        // actor with an id carrying the domain but NO explicit .domain field
        // → _actorDomain falls back to the id's @-domain.
        return Promise.resolve({ ok: true, actor: { id: parts[1] + "@example.com" } });
      },
    },
  });
  var sock = await _connect(s.port);
  try {
    await _readReply(sock);
    await _send(sock, "EHLO client.example.com");
    await _send(sock, "AUTH PLAIN " + _saslPlain("u", "x"));
    await _send(sock, "MAIL FROM:<u@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");
    // d= matches the actor-id domain → accepted.
    check("dkim self (actor id-domain) matching d= → 250",
      /^250 /.test(await _dataDot(sock, "DKIM-Signature: v=1; d=example.com; b=z\r\nFrom: u@example.com\r\n\r\nx")));
    await _send(sock, "MAIL FROM:<u@example.com>");
    await _send(sock, "RCPT TO:<b@example.com>");
    // Signature present but no d= tag → no match → 550.
    check("dkim self signature without d= → 550",
      /^550 /.test(await _dataDot(sock, "DKIM-Signature: v=1; b=z\r\nFrom: u@example.com\r\n\r\nx")));
  } finally { sock.destroy(); await s.srv.close({ timeoutMs: b.constants.TIME.seconds(2) }); }
}

async function run() {
  testSurface();
  testCreateRequiresTlsContext();
  testStrictProfileRequiresAuthConfig();
  testPermissiveAllowsNoAuth();
  testBadAuthShapeRefused();
  testBadBoundsRefused();
  await testEhloAdvertisesChunking();
  await testBdatSingleLastChunk();
  await testBdatMultipleChunksThenLast();
  await testBdatZeroByteLast();
  await testBdatOutsideTransaction();
  await testBdatBadArgs();
  await testBdatBinaryBytesPreserved();
  await testBdatOversizeRefused();

  var tls;
  try { tls = await _makeTestTlsContextWithCa(); }
  catch (_e) { check("mail-server-submission error branches skipped (no TLS ctx)", true); return; }

  testCreateValidation(tls);
  await testCloseBeforeListen(tls);
  await testDoubleListen(tls);
  await testPermissiveDispatch(tls);
  await testDomainRefusals(tls);
  await testDataPaths(tls);
  await testBdatBranches(tls);
  await testBdatMore(tls);
  await testPipeliningRace(tls);
  await testDkimSelfActor(tls);
  await testCleartextAuthAndIdentity(tls);
  await testAuthFailuresAndMultiStep(tls);
  await testAuthRateLimit(tls);
  await testCrossTenant(tls);
  await testStrictProfileStartTls(tls);
  await testImplicitTls(tls);
  await testDkimModes(tls);
  await testRecipientPolicy(tls);
  await testConnRateLimit(tls);
  await testLimitsAndSmuggling(tls);
  await testAuthNotConfigured(tls);
  await testIdleTimeout(tls);
  await testCloseDrain(tls);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-submission] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
  );
}
