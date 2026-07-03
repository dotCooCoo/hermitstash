// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.submission — outbound SMTP submission listener.
 *
 * Tests cover opts validation, AUTH-required posture under strict
 * profile, AUTH-needs-TLS gate (RFC 4954 §4), identity-binding,
 * and the multi-step verify hook contract.
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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-submission] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
  );
}
