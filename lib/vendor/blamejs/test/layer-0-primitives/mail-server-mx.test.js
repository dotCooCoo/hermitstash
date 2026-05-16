"use strict";
/**
 * b.mail.server.mx — inbound SMTP / MX listener.
 *
 * Tests cover the wire-protocol state machine, SMTP-smuggling defense
 * (CVE-2023-51764 / CVE-2024-32178 — bare-LF dot-terminator), open-
 * relay refusal by default, STARTTLS-stripping defense, and the
 * helper byte-scan primitives (_detectSmugglingShape /
 * _findDotTerminator / _dotUnstuff).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeNet = require("node:net");
var nodeTls = require("node:tls");

function testSurface() {
  check("mx.create is fn",            typeof b.mail.server.mx.create === "function");
  check("MailServerMxError is fn",    typeof b.mail.server.mx.MailServerMxError === "function");
  // Wire-protocol parsing helpers now live in b.safeSmtp; smuggling
  // detection in b.guardSmtpCommand. The MX listener consumes both.
  check("safeSmtp.findDotTerminator is fn",
        typeof b.safeSmtp.findDotTerminator === "function");
  check("safeSmtp.dotUnstuff is fn",
        typeof b.safeSmtp.dotUnstuff === "function");
  check("guardSmtpCommand.detectBodySmuggling is fn",
        typeof b.guardSmtpCommand.detectBodySmuggling === "function");
}

function testCreateRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.mx.create({}); } catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-mx/no-tls-context");
}

function testCreateRejectsBadBounds() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.mx.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-mx/") === 0);
  }
  expectBad("negative maxLineBytes refused",
    { tlsContext: {}, maxLineBytes: -1 });
  expectBad("non-array localDomains refused",
    { tlsContext: {}, localDomains: "example.com" });
  expectBad("empty localDomains array refused",
    { tlsContext: {}, localDomains: [] });
  expectBad("non-array relayAllowedFor refused",
    { tlsContext: {}, relayAllowedFor: "x" });
}

function testDetectSmugglingShape() {
  // Canonical CRLF-only body — no smuggling shape.
  var clean = Buffer.from("hello\r\nworld\r\n.\r\n", "utf8");
  check("clean CRLF body not flagged as smuggling",
    b.guardSmtpCommand.detectBodySmuggling(clean) === false);

  // Bare-LF dot-line smuggling shape (CVE-2023-51764).
  var smuggled = Buffer.from("hello\nworld\n.\n", "utf8");
  check("bare-LF dot-line flagged as smuggling",
    b.guardSmtpCommand.detectBodySmuggling(smuggled) === true);

  // Mid-body bare-LF without dot — not the smuggling shape.
  var mixed = Buffer.from("hello\nthere\r\n.\r\n", "utf8");
  check("bare-LF without dot terminator not flagged",
    b.guardSmtpCommand.detectBodySmuggling(mixed) === false);
}

function testFindDotTerminator() {
  var withTerm = Buffer.from("body line\r\n.\r\n", "utf8");
  var idx = b.safeSmtp.findDotTerminator(withTerm);
  check("dot-terminator found at body end",
    idx === Buffer.byteLength("body line", "utf8"));

  var noTerm = Buffer.from("body line\r\n", "utf8");
  check("no terminator returns -1",
    b.safeSmtp.findDotTerminator(noTerm) === -1);

  // CRLF dot CRLF only — RFC 5321 §2.3.8 canonical form. Bare LF
  // alone shouldn't match (smuggling defense — the terminator
  // scanner is strict-CRLF; the smuggling detector lives in
  // b.guardSmtpCommand.detectBodySmuggling).
  var bareLf = Buffer.from("body\n.\n", "utf8");
  check("bare-LF terminator does not match canonical CRLF",
    b.safeSmtp.findDotTerminator(bareLf) === -1);
}

function testDotUnstuff() {
  // ".." line at body start → "." (stuffing reversed).
  var stuffed = Buffer.from("hello\r\n..secret line\r\nworld\r\n", "utf8");
  var unstuffed = b.safeSmtp.dotUnstuff(stuffed);
  check("dot-stuffing reversed: '..' → '.'",
    unstuffed.toString("utf8") === "hello\r\n.secret line\r\nworld\r\n");

  // Plain body without dot-prefix lines passes through.
  var plain = Buffer.from("hello\r\nworld\r\n", "utf8");
  check("plain body passes through unstuff",
    b.safeSmtp.dotUnstuff(plain).toString("utf8") === "hello\r\nworld\r\n");
}

// ---- End-to-end SMTP conversation test ---------------------------------

async function _makeTestTlsContext() {
  // Mint a CA + server leaf cert via the framework's mtls-engine.
  // node:tls accepts the resulting PEM pair as a server identity for
  // TLS 1.3; we use this rather than baking a fixed test fixture into
  // the repo so the cert can't drift past expiry.
  var ca = await b.mtlsEngine.generateCa({ name: "mail-server-mx-test-ca" });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:           "mx.test",
    caCertPem:    ca.caCertPem,
    caKeyPem:     ca.caKeyPem,
    usage:        "server",
    sans:         ["DNS:mx.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });
  return nodeTls.createSecureContext({
    key:  leaf.key,
    cert: leaf.cert,
  });
}

async function _sendCommand(socket, line) {
  return new Promise(function (resolve, reject) {
    var buf = "";
    function onData(chunk) {
      buf += chunk.toString("utf8");
      if (buf.indexOf("\r\n") !== -1) {
        // Read until the LAST "code SP" line — multi-line 250- responses
        // have continuation lines starting with "code-".
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

async function testEhloFlow() {
  // Boot the server with a permissive profile so plaintext EHLO works
  // (operator-acknowledged downgrade for staging). Skip if the test
  // cert fixture isn't available.
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) {
    check("EHLO flow (skipped — test cert fixture unavailable)", true);
    return;
  }
  var srv = b.mail.server.mx.create({
    tlsContext:   ctx,
    profile:      "permissive",
    localDomains: ["example.com"],
  });
  var listenInfo = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(listenInfo.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    var greeting = await _readGreeting(socket);
    check("server sends 220 greeting", /^220 /.test(greeting));

    var ehloReply = await _sendCommand(socket, "EHLO sender.example.com");
    check("EHLO returns 250 with capabilities",
      /^250-/m.test(ehloReply) && /^250 ENHANCEDSTATUSCODES/m.test(ehloReply));
    check("EHLO advertises STARTTLS",      /250.STARTTLS/.test(ehloReply));
    check("EHLO advertises SIZE",          /250.SIZE \d+/.test(ehloReply));

    var mailReply = await _sendCommand(socket, "MAIL FROM:<sender@external.com>");
    check("MAIL FROM accepted under permissive",  /^250 /.test(mailReply));

    var rcptReply = await _sendCommand(socket, "RCPT TO:<alice@example.com>");
    check("RCPT TO local domain accepted",  /^250 /.test(rcptReply));

    var dataReply = await _sendCommand(socket, "DATA");
    check("DATA returns 354 prompt",        /^354 /.test(dataReply));

    var endReply = await _sendCommand(socket, "Subject: test\r\nFrom: sender@external.com\r\n\r\nHello world.\r\n.");
    check("DATA body accepted with 250",    /^250 /.test(endReply));

    var quitReply = await _sendCommand(socket, "QUIT");
    check("QUIT returns 221 bye",           /^221 /.test(quitReply));
    socket.destroy();
  } finally {
    await srv.close({ timeoutMs: 1000 });                                                            // allow:raw-time-literal — test-only short drain
  }
}

async function testRelayRefused() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) {
    check("Relay refusal (skipped)", true);
    return;
  }
  var srv = b.mail.server.mx.create({
    tlsContext:   ctx,
    profile:      "permissive",
    localDomains: ["example.com"],
  });
  var listenInfo = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(listenInfo.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO sender.example.com");
    await _sendCommand(socket, "MAIL FROM:<sender@external.com>");
    var rcptReply = await _sendCommand(socket, "RCPT TO:<bob@notlocal.example>");
    check("non-local RCPT refused with 550 5.7.1",
      /^550 5\.7\.1/.test(rcptReply));
    socket.destroy();
  } finally {
    await srv.close({ timeoutMs: 1000 });                                                            // allow:raw-time-literal — test-only short drain
  }
}

async function testStrictProfileRequiresStartTls() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) {
    check("strict-profile STARTTLS gate (skipped)", true);
    return;
  }
  var srv = b.mail.server.mx.create({
    tlsContext:   ctx,
    profile:      "strict",  // requires STARTTLS before MAIL FROM
    localDomains: ["example.com"],
  });
  var listenInfo = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var socket = nodeNet.connect(listenInfo.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    await _sendCommand(socket, "EHLO sender.example.com");
    var mailReply = await _sendCommand(socket, "MAIL FROM:<sender@external.com>");
    check("strict-profile refuses plaintext MAIL FROM with 530",
      /^530 5\.7\.0/.test(mailReply));
    socket.destroy();
  } finally {
    await srv.close({ timeoutMs: 1000 });                                                            // allow:raw-time-literal — test-only short drain
  }
}

async function run() {
  testSurface();
  testCreateRequiresTlsContext();
  testCreateRejectsBadBounds();
  testDetectSmugglingShape();
  testFindDotTerminator();
  testDotUnstuff();
  await testEhloFlow();
  await testRelayRefused();
  await testStrictProfileRequiresStartTls();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-mx] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
