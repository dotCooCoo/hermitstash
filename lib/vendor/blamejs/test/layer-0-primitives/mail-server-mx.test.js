// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.server.mx — inbound SMTP / MX listener.
 *
 * Tests cover the wire-protocol state machine, SMTP-smuggling defense
 * (CVE-2023-51764 / -51765 / -51766 — bare-LF dot-terminator), open-
 * relay refusal by default, STARTTLS-stripping defense, and the
 * helper byte-scan primitives (_detectSmugglingShape /
 * _findDotTerminator / _dotUnstuff).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeNet  = require("node:net");
var nodeTls  = require("node:tls");
// The exact audit module auditEmit resolves via require("./audit") — patch
// its safeEmit to capture the drop-silent events the listener emits (there
// is no test helper for global-audit capture; restore in finally).
var auditMod = require("../../lib/audit");

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
          socket.removeListener("error", onError);
          resolve(buf);
        }
      }
    }
    // Detach on settle — a long transaction issues a dozen commands on
    // one socket, and never-fired once("error") handlers accumulate
    // past the MaxListeners warning threshold.
    function onError(e) { socket.removeListener("data", onData); reject(e); }
    socket.on("data", onData);
    socket.once("error", onError);
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
        socket.removeListener("error", onError);
        resolve(buf);
      }
    }
    function onError(e) { socket.removeListener("data", onData); reject(e); }
    socket.on("data", onData);
    socket.once("error", onError);
  });
}

// Passive accumulator for unsolicited server replies (idle-timeout 421,
// shutdown 421) — the caller polls the buffer via helpers.waitUntil rather
// than issuing a command. Swallows post-close socket errors (ECONNRESET
// when the server destroys the connection) so they don't reject the run.
function _collect(socket) {
  var buf = "";
  socket.on("data", function (chunk) { buf += chunk.toString("utf8"); });
  socket.on("error", function () { /* connection torn down by server; ignore */ });
  return { text: function () { return buf; } };
}

// Capture the drop-silent audit events the listener emits while `fn`'s
// window is open. Patches the exact module object auditEmit resolves and
// restores it unconditionally, so no global-audit state leaks to the
// smoke harness.
function _withAuditCapture(fn) {
  var events = [];
  var orig = auditMod.safeEmit;
  auditMod.safeEmit = function (evt) {
    events.push(evt);
    return orig.call(auditMod, evt);
  };
  return Promise.resolve()
    .then(function () { return fn(events); })
    .finally(function () { auditMod.safeEmit = orig; });
}

// Connect + read the 220 greeting, returning the live socket.
async function _connectTo(info) {
  var socket = nodeNet.connect(info.port, "127.0.0.1");
  await new Promise(function (r) { socket.once("connect", r); });
  await _readGreeting(socket);
  return socket;
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

// Connection-level gates (helo / rbl / greylist) wired into the live
// state machine. Each gate is an operator-supplied object; we drive the
// real wire protocol with mock gates and assert the SMTP verdict.
async function testConnectionGates() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) {
    check("connection gates (skipped — test cert fixture unavailable)", true);
    return;
  }

  async function _connect(srv) {
    var info = await srv.listen({ port: 0, address: "127.0.0.1" });
    var socket = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { socket.once("connect", r); });
    await _readGreeting(socket);
    return socket;
  }

  // ---- greylist defer → 450 tempfail at RCPT ----
  var greySrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    greylist: { check: async function () { return { action: "defer", reason: "first-seen" }; } },
  });
  var grerr = null, greySock;
  try {
    greySock = await _connect(greySrv);
    await _sendCommand(greySock, "EHLO sender.example.com");
    await _sendCommand(greySock, "MAIL FROM:<s@external.com>");
    var greyRcpt = await _sendCommand(greySock, "RCPT TO:<alice@example.com>");
    check("greylist defer → 450 tempfail", /^450 4\.7\.1/.test(greyRcpt));
    greySock.destroy();
  } catch (e) { grerr = e; } finally { await greySrv.close({ timeoutMs: 1000 }); }   // allow:raw-time-literal — test-only short drain
  check("greylist gate ran without error", grerr === null);

  // ---- RBL listed → 554 at RCPT ----
  var rblSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    rbl: { query: async function () {
      return { listed: [{ zone: "zen.spamhaus.org" }], allowed: [], neutral: [], errors: [] };
    } },
  });
  try {
    var rblSock = await _connect(rblSrv);
    await _sendCommand(rblSock, "EHLO sender.example.com");
    await _sendCommand(rblSock, "MAIL FROM:<s@external.com>");
    var rblRcpt = await _sendCommand(rblSock, "RCPT TO:<alice@example.com>");
    check("RBL-listed IP → 554 at RCPT", /^554 5\.7\.1/.test(rblRcpt));
    rblSock.destroy();
  } finally { await rblSrv.close({ timeoutMs: 1000 }); }                              // allow:raw-time-literal — test-only short drain

  // ---- helo hard-reject → 550 at EHLO ----
  var heloSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    helo: { evaluate: async function () { return { action: "reject-shape" }; } },
  });
  try {
    var heloSock = await _connect(heloSrv);
    // A syntactically-valid domain (passes guardDomain) so the refusal
    // comes from the helo GATE (reject-shape), not domain hardening.
    var heloReply = await _sendCommand(heloSock, "EHLO sender.example.com");
    check("helo hard-reject → 550 at EHLO", /^550 5\.7\.1/.test(heloReply));
    heloSock.destroy();
  } finally { await heloSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // ---- gates that accept → normal flow (gate ran + passed) ----
  var passSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    helo:     { evaluate: async function () { return { action: "accept" }; } },
    rbl:      { query:    async function () { return { listed: [], allowed: [], neutral: [], errors: [] }; } },
    greylist: { check:    async function () { return { action: "accept", reason: "known" }; } },
  });
  try {
    var passSock = await _connect(passSrv);
    await _sendCommand(passSock, "EHLO sender.example.com");
    await _sendCommand(passSock, "MAIL FROM:<s@external.com>");
    var passRcpt = await _sendCommand(passSock, "RCPT TO:<alice@example.com>");
    check("accepting gates → RCPT 250", /^250 /.test(passRcpt));
    passSock.destroy();
  } finally { await passSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // ---- async-serial pump: pipelined commands (RFC 2920) keep ordering
  // even though the greylist gate awaits between RCPTs. Send EHLO + MAIL
  // + RCPT in a single write; the deferred RCPT must still answer 450
  // and replies must arrive in order. ----
  var slowCount = 0;
  var pipeSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    greylist: { check: async function () {
      slowCount += 1;
      await helpers.waitUntil(function () { return true; }, { timeoutMs: 100, label: "gate async yield" });
      return { action: "defer", reason: "first-seen" };
    } },
  });
  try {
    var pipeInfo = await pipeSrv.listen({ port: 0, address: "127.0.0.1" });
    var pipeSock = nodeNet.connect(pipeInfo.port, "127.0.0.1");
    await new Promise(function (r) { pipeSock.once("connect", r); });
    await _readGreeting(pipeSock);
    // Pipeline EHLO + MAIL + RCPT in one TCP write.
    var combined = await new Promise(function (resolve, reject) {
      var buf = "";
      function onData(chunk) {
        buf += chunk.toString("utf8");
        if (/^450 /m.test(buf)) { pipeSock.removeListener("data", onData); resolve(buf); }
      }
      pipeSock.on("data", onData);
      pipeSock.once("error", reject);
      pipeSock.write("EHLO sender.example.com\r\nMAIL FROM:<s@external.com>\r\nRCPT TO:<alice@example.com>\r\n");
    });
    var idx250ehlo = combined.indexOf("250");
    var idx450 = combined.indexOf("450");
    check("pipelined commands answered in order (250… before 450)",
      idx250ehlo !== -1 && idx450 !== -1 && idx250ehlo < idx450);
    check("greylist gate ran exactly once for the pipelined RCPT", slowCount === 1);
    pipeSock.destroy();
  } finally { await pipeSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain
}

// Gates must run + serialize on the POST-STARTTLS path too — the default
// strict/balanced profiles require STARTTLS before MAIL, so that's where
// the gates actually fire. Mint a CA so the client can trust the upgraded
// connection (no rejectUnauthorized bypass), do a real STARTTLS handshake,
// and assert the greylist gate produces 450 over TLS.
async function testGateOverStartTls() {
  var ca, leaf;
  try {
    ca = await b.mtlsEngine.generateCa({ name: "mx-starttls-test-ca" });
    leaf = await b.mtlsEngine.signClientCert({
      cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
      usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1"], validityDays: 1,
    });
  } catch (_e) {
    check("gate over STARTTLS (skipped — cert fixture unavailable)", true);
    return;
  }
  var ctx = nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "strict", localDomains: ["example.com"],
    greylist: { check: async function () { return { action: "defer", reason: "first-seen" }; } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var plain, tlsSock;
  try {
    plain = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { plain.once("connect", r); });
    await _readGreeting(plain);
    await _sendCommand(plain, "EHLO sender.example.com");
    var stReply = await _sendCommand(plain, "STARTTLS");
    check("STARTTLS → 220 ready", /^220 /.test(stReply));
    tlsSock = nodeTls.connect({ socket: plain, ca: [ca.caCertPem], servername: "localhost" });
    await new Promise(function (r, j) {
      tlsSock.once("secureConnect", r); tlsSock.once("error", j);
    });
    await _sendCommand(tlsSock, "EHLO sender.example.com");   // re-issue per RFC 3207 §4.2
    await _sendCommand(tlsSock, "MAIL FROM:<s@external.com>");
    var rcpt = await _sendCommand(tlsSock, "RCPT TO:<alice@example.com>");
    check("greylist gate runs on the post-STARTTLS serialized pump → 450",
      /^450 4\.7\.1/.test(rcpt));
    tlsSock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// DATA-phase SPF/DKIM/DMARC gate (opts.guardEnvelope → b.mail.inbound
// .verify). Drives full SMTP transactions against a mocked DNS: the
// policy-reject path answers 550 5.7.1 before the agent handoff, the
// aligned path delivers with the verdict on the handoff ctx + the
// RFC 8601 Authentication-Results header prepended, quarantine
// delivers annotated, monitor mode never refuses, and DNS temperror
// defers (451) or accepts per onTemperror.
async function testGuardEnvelopeGate() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("guardEnvelope gate (skipped — test cert fixture unavailable)", true); return; }
  var records = {
    "external.com/TXT":         [["v=spf1 ip4:127.0.0.1 -all"]],
    "_dmarc.external.com/TXT":  [["v=DMARC1; p=reject"]],
    "spoof.example/TXT":        [["v=spf1 -all"]],
    "_dmarc.spoof.example/TXT": [["v=DMARC1; p=reject"]],
    "spoofq.example/TXT":        [["v=spf1 -all"]],
    "_dmarc.spoofq.example/TXT": [["v=DMARC1; p=quarantine"]],
  };
  var dnsLookup = async function (host, type) {
    if (records[host + "/" + type]) return records[host + "/" + type];
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  async function _transact(socket, mailFrom, body) {
    await _sendCommand(socket, "MAIL FROM:<" + mailFrom + ">");
    await _sendCommand(socket, "RCPT TO:<alice@example.com>");
    await _sendCommand(socket, "DATA");
    return _sendCommand(socket, body + "\r\n.");
  }

  // Boot-time validation of the gate config.
  var eBad = null;
  try {
    b.mail.server.mx.create({ tlsContext: ctx, guardEnvelope: "yes" });
  } catch (e) { eBad = e; }
  check("guardEnvelope: non-boolean/object config refused at boot", eBad !== null);
  var eMode = null;
  try {
    b.mail.server.mx.create({ tlsContext: ctx, guardEnvelope: { mode: "loud" } });
  } catch (e) { eMode = e; }
  check("guardEnvelope: unknown mode refused at boot", eMode !== null);
  // DKIM verifier ranges are mirrored at boot — a config the verifier
  // would refuse per-message must fail startup, not break live SMTP.
  var eSigs = null;
  try {
    b.mail.server.mx.create({ tlsContext: ctx, guardEnvelope: { maxSignatures: 100 } });
  } catch (e) { eSigs = e; }
  check("guardEnvelope: maxSignatures above the DKIM verifier ceiling refused at boot",
        eSigs !== null && /bad-bound/.test(eSigs.code || ""));
  var eSkew = null;
  try {
    b.mail.server.mx.create({ tlsContext: ctx,
      guardEnvelope: { clockSkewMs: b.mail.dkim.DKIM_CLOCK_SKEW_MS_MAX + 1 } });
  } catch (e) { eSkew = e; }
  check("guardEnvelope: clockSkewMs above the DKIM verifier ceiling refused at boot",
        eSkew !== null && /bad-bound/.test(eSkew.code || ""));

  // ---- enforce mode ----
  var handoffs = [];
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "enforce", dnsLookup: dnsLookup },
    agent: { handoff: async function (h) { handoffs.push(h); return { messageId: "m" + handoffs.length }; } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var sock = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { sock.once("connect", r); });
    await _readGreeting(sock);
    await _sendCommand(sock, "EHLO sender.example.com");

    // Policy reject: SPF fail against p=reject → refused at the wire
    // with the RFC 7372 multiple-authentication-checks-failed code.
    var rej = await _transact(sock, "ceo@spoof.example",
      "From: ceo@spoof.example\r\nSubject: urgent\r\n\r\npay this invoice\r\n");
    check("guardEnvelope enforce: DMARC p=reject + SPF fail → 550 5.7.26 (RFC 7372)", /^550 5\.7\.26/.test(rej));
    check("guardEnvelope enforce: refused message never reaches the agent", handoffs.length === 0);

    // Multi-From spoofing shape → refused.
    var multi = await _transact(sock, "s@external.com",
      "From: s@external.com\r\nFrom: ceo@spoof.example\r\nSubject: x\r\n\r\nbody\r\n");
    check("guardEnvelope enforce: duplicated From → 550 5.7.1 (RFC 7489 §6.6.1)",
      /^550 5\.7\.1/.test(multi) && handoffs.length === 0);

    // Aligned pass: delivered with verdict + A-R header. The message
    // arrives with a FORGED Authentication-Results header claiming
    // this receiver's authserv-id — RFC 8601 §5 requires it stripped
    // before the computed one is prepended.
    var ok = await _transact(sock, "s@external.com",
      "Authentication-Results: example.com;\r\n  dkim=pass header.d=forged.example\r\n" +
      "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n");
    check("guardEnvelope enforce: aligned SPF pass → 250 accepted", /^250 /.test(ok));
    check("guardEnvelope: handoff carries the auth verdict",
      handoffs.length === 1 && handoffs[0].auth &&
      handoffs[0].auth.action === "accept" &&
      handoffs[0].auth.spf.result === "pass" &&
      handoffs[0].auth.dmarc.result === "pass" &&
      handoffs[0].auth.quarantine === false);
    var delivered = handoffs.length === 1 ? handoffs[0].body.toString("utf8") : "";
    check("guardEnvelope: A-R header prepended with the localDomains authserv-id",
      delivered.indexOf("Authentication-Results: example.com") === 0 &&
      /spf=pass/.test(delivered) && /dmarc=pass/.test(delivered));
    check("guardEnvelope: forged same-authserv-id A-R header stripped (RFC 8601 §5)",
      delivered.indexOf("forged.example") === -1 &&
      delivered.split("Authentication-Results: example.com").length === 2);
    check("guardEnvelope: original message preserved after the A-R header",
      delivered.indexOf("Subject: hi") !== -1 && delivered.indexOf("hello") !== -1);

    // Quarantine policy: delivered, annotated for the downstream agent.
    var q = await _transact(sock, "news@spoofq.example",
      "From: news@spoofq.example\r\nSubject: promo\r\n\r\ndeal\r\n");
    check("guardEnvelope enforce: p=quarantine → 250 delivered annotated",
      /^250 /.test(q) && handoffs.length === 2 &&
      handoffs[1].auth.quarantine === true &&
      handoffs[1].auth.action === "quarantine");
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                  // allow:raw-time-literal — test-only short drain

  // ---- monitor mode: same spoof, never refused ----
  var monHandoffs = [];
  var monSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "monitor", dnsLookup: dnsLookup },
    agent: { handoff: async function (h) { monHandoffs.push(h); return {}; } },
  });
  var monInfo = await monSrv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var monSock = nodeNet.connect(monInfo.port, "127.0.0.1");
    await new Promise(function (r) { monSock.once("connect", r); });
    await _readGreeting(monSock);
    await _sendCommand(monSock, "EHLO sender.example.com");
    var monRej = await _transact(monSock, "ceo@spoof.example",
      "From: ceo@spoof.example\r\nSubject: urgent\r\n\r\npay\r\n");
    check("guardEnvelope monitor: policy-reject message still delivered",
      /^250 /.test(monRej) && monHandoffs.length === 1 &&
      monHandoffs[0].auth.action === "reject" &&
      monHandoffs[0].auth.mode === "monitor");
    monSock.destroy();
  } finally { await monSrv.close({ timeoutMs: 1000 }); }                               // allow:raw-time-literal — test-only short drain

  // ---- DNS temperror: defer (default) vs accept ----
  var servfail = async function () { throw new Error("SERVFAIL"); };
  var deferSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "enforce", dnsLookup: servfail },
  });
  var deferInfo = await deferSrv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var dSock = nodeNet.connect(deferInfo.port, "127.0.0.1");
    await new Promise(function (r) { dSock.once("connect", r); });
    await _readGreeting(dSock);
    await _sendCommand(dSock, "EHLO sender.example.com");
    var deferred = await _transact(dSock, "s@external.com",
      "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n");
    check("guardEnvelope: DNS temperror defers with 451 4.7.0 (sender retries)",
      /^451 4\.7\.0/.test(deferred));
    dSock.destroy();
  } finally { await deferSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // ---- pipeline wall-clock timeout: a hanging resolver cannot pin
  // the connection slot — the race defers on the temperror path ----
  var hangForever = function () { return new Promise(function () {}); };
  var timeoutSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "enforce", dnsLookup: hangForever, timeoutMs: 250 },        // allow:raw-time-literal — test-only short budget
  });
  var timeoutInfo = await timeoutSrv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var tSock = nodeNet.connect(timeoutInfo.port, "127.0.0.1");
    await new Promise(function (r) { tSock.once("connect", r); });
    await _readGreeting(tSock);
    await _sendCommand(tSock, "EHLO sender.example.com");
    var timedOut = await _transact(tSock, "s@external.com",
      "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n");
    check("guardEnvelope: hanging resolver hits timeoutMs → 451 4.7.0",
      /^451 4\.7\.0/.test(timedOut));
    tSock.destroy();
  } finally { await timeoutSrv.close({ timeoutMs: 1000 }); }                           // allow:raw-time-literal — test-only short drain

  var acceptSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardEnvelope: { mode: "enforce", onTemperror: "accept", dnsLookup: servfail },
  });
  var acceptInfo = await acceptSrv.listen({ port: 0, address: "127.0.0.1" });
  try {
    var aSock = nodeNet.connect(acceptInfo.port, "127.0.0.1");
    await new Promise(function (r) { aSock.once("connect", r); });
    await _readGreeting(aSock);
    await _sendCommand(aSock, "EHLO sender.example.com");
    var accepted = await _transact(aSock, "s@external.com",
      "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n");
    check("guardEnvelope: onTemperror accept admits when DNS is down",
      /^250 /.test(accepted));
    aSock.destroy();
  } finally { await acceptSrv.close({ timeoutMs: 1000 }); }                            // allow:raw-time-literal — test-only short drain
}

// ---- Boot-time validation of the guardEnvelope config object -----------
// The gate's tunables are validated at create() so an operator typo fails
// startup rather than turning every live DATA into an envelope_error.
function testGuardEnvelopeBootValidation() {
  function expectThrow(label, opts) {
    var threw = null;
    try { b.mail.server.mx.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-mx/") === 0);
  }
  expectThrow("guardEnvelope.onTemperror invalid → throw",
    { tlsContext: {}, guardEnvelope: { onTemperror: "maybe" } });
  expectThrow("guardEnvelope.authservId non-string → throw",
    { tlsContext: {}, guardEnvelope: { authservId: 123 } });
  expectThrow("guardEnvelope.authservId empty string → throw",
    { tlsContext: {}, guardEnvelope: { authservId: "" } });
  expectThrow("guardEnvelope.dnsLookup non-function → throw",
    { tlsContext: {}, guardEnvelope: { dnsLookup: "not-a-fn" } });

  // A fully-specified gate config (explicit authservId + onTemperror
  // accept + dnsLookup fn) constructs cleanly — exercises the accept
  // branches the reject cases above skip.
  var okServer = null;
  try {
    okServer = b.mail.server.mx.create({
      tlsContext: {}, profile: "permissive",
      guardEnvelope: {
        mode:        "monitor",
        onTemperror: "accept",
        authservId:  "custom.mx.example",
        dnsLookup:   async function () { return []; },
      },
    });
  } catch (_e) { okServer = null; }
  check("guardEnvelope full valid config constructs", okServer !== null &&
    typeof okServer.listen === "function");

  // `guardEnvelope: true` shorthand — mode defaults to the profile-derived
  // posture (permissive → monitor, otherwise enforce).
  var trueMonitor = null, trueEnforce = null;
  try {
    trueMonitor = b.mail.server.mx.create({
      tlsContext: {}, profile: "permissive", guardEnvelope: true });
  } catch (_e) { trueMonitor = null; }
  try {
    trueEnforce = b.mail.server.mx.create({ tlsContext: {}, guardEnvelope: true });
  } catch (_e) { trueEnforce = null; }
  check("guardEnvelope:true under permissive constructs (monitor default)",
    trueMonitor !== null);
  check("guardEnvelope:true under default profile constructs (enforce default)",
    trueEnforce !== null);
}

// ---- guardDomain opt: false (disable) and object (profile override) ----
function testGuardDomainBootOptions() {
  var offServer = null;
  try {
    offServer = b.mail.server.mx.create({ tlsContext: {}, guardDomain: false });
  } catch (_e) { offServer = null; }
  check("guardDomain:false constructs (hardening disabled)", offServer !== null);

  var objServer = null;
  try {
    objServer = b.mail.server.mx.create({
      tlsContext: {}, guardDomain: { profile: "balanced" },
    });
  } catch (_e) { objServer = null; }
  check("guardDomain object with profile override constructs", objServer !== null);

  // guardDomain object WITHOUT its own profile falls back to the server
  // profile.
  var objDefault = null;
  try {
    objDefault = b.mail.server.mx.create({ tlsContext: {}, guardDomain: {} });
  } catch (_e) { objDefault = null; }
  check("guardDomain object without profile falls back to server profile",
    objDefault !== null);

  // An operator localDomains entry that guardDomain itself rejects (a
  // special-use domain) must fail startup, not silently weaken the gate.
  var badLocal = null;
  try {
    b.mail.server.mx.create({ tlsContext: {}, localDomains: ["foo.local"] });
  } catch (e) { badLocal = e; }
  check("localDomains rejected by guardDomain → bad-local-domain at boot",
    badLocal !== null && /bad-local-domain/.test(badLocal.code || ""));
}

// ---- Command dispatch: NOOP / RSET / VRFY / EXPN / unknown / HELO / EHLO-no-arg
async function testCommandDispatch() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("command dispatch (skipped — cert fixture unavailable)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    check("NOOP → 250", /^250 /.test(await _sendCommand(sock, "NOOP")));
    check("RSET → 250", /^250 /.test(await _sendCommand(sock, "RSET")));
    check("VRFY → 502 not implemented",
      /^502 5\.5\.1/.test(await _sendCommand(sock, "VRFY alice")));
    check("EXPN → 502 not implemented",
      /^502 5\.5\.1/.test(await _sendCommand(sock, "EXPN staff")));
    check("unknown verb → 500",
      /^500 5\.5\.2/.test(await _sendCommand(sock, "HELP")));
    check("HELO (not EHLO) → single-line 250",
      /^250 /.test(await _sendCommand(sock, "HELO relay.example.com")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- Sequence + syntax errors: out-of-order commands and malformed args -
async function testSequenceAndSyntaxErrors() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("sequence/syntax errors (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var s1, s2;
  try {
    // MAIL FROM before any EHLO → 503 bad sequence.
    s1 = await _connectTo(info);
    check("MAIL FROM before EHLO → 503",
      /^503 5\.5\.1/.test(await _sendCommand(s1, "MAIL FROM:<a@external.com>")));
    s1.destroy();

    // Fresh connection: EHLO, then RCPT before MAIL, DATA before RCPT,
    // and malformed MAIL / RCPT the shape-guard passes but the listener's
    // stricter address regex rejects (501).
    s2 = await _connectTo(info);
    await _sendCommand(s2, "EHLO sender.example.com");
    check("RCPT before MAIL → 503",
      /^503 5\.5\.1/.test(await _sendCommand(s2, "RCPT TO:<a@example.com>")));
    check("DATA before RCPT → 503",
      /^503 5\.5\.1/.test(await _sendCommand(s2, "DATA")));
    check("malformed MAIL FROM (trailing junk) → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s2, "MAIL FROM:<a@external.com>extra")));
    // Land a good MAIL so the next RCPT reaches the address parse.
    await _sendCommand(s2, "MAIL FROM:<a@external.com>");
    check("malformed RCPT TO (trailing junk) → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s2, "RCPT TO:<a@example.com>extra")));
    s2.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- Domain hardening refuses HELO / MAIL FROM / RCPT TO bad domains ----
// bare-IPv4-as-domain (CVE-2021-22931 class) + special-use domain (RFC 6761).
async function testDomainRefusals() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("domain refusals (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var s1, s2;
  try {
    // HELO with a bare IPv4 (not an address literal) → guardDomain refuses.
    s1 = await _connectTo(info);
    check("HELO bare-IPv4 domain → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s1, "HELO 1.2.3.4")));
    s1.destroy();

    s2 = await _connectTo(info);
    await _sendCommand(s2, "EHLO sender.example.com");
    check("MAIL FROM bare-IPv4 domain → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s2, "MAIL FROM:<x@1.2.3.4>")));
    await _sendCommand(s2, "MAIL FROM:<s@external.com>");
    check("RCPT TO special-use domain → 501",
      /^501 5\.5\.4/.test(await _sendCommand(s2, "RCPT TO:<x@foo.local>")));
    s2.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- Resource caps: SIZE=, per-message size, recipient count, line length
async function testResourceLimits() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("resource limits (skipped)", true); return; }

  // Small per-message cap: declared SIZE= over the cap refused at MAIL
  // FROM (552), and a DATA body over the cap refused mid-stream (552).
  var capSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    maxMessageBytes: 64,
  });
  var capInfo = await capSrv.listen({ port: 0, address: "127.0.0.1" });
  var capSock;
  try {
    capSock = await _connectTo(capInfo);
    await _sendCommand(capSock, "EHLO sender.example.com");
    check("MAIL FROM SIZE= over maxMessageBytes → 552",
      /^552 5\.3\.4/.test(await _sendCommand(capSock, "MAIL FROM:<s@external.com> SIZE=100000")));
    await _sendCommand(capSock, "MAIL FROM:<s@external.com>");
    await _sendCommand(capSock, "RCPT TO:<alice@example.com>");
    await _sendCommand(capSock, "DATA");
    var big = "";
    for (var i = 0; i < 200; i += 1) big += "A";
    check("DATA body over maxMessageBytes → 552 mid-stream",
      /^552 5\.3\.4/.test(await _sendCommand(capSock, big)));
    capSock.destroy();
  } finally { await capSrv.close({ timeoutMs: 1000 }); }                              // allow:raw-time-literal — test-only short drain

  // Per-message recipient cap (default maxMessageBytes so SIZE overrun
  // has room). maxRcptsPerMessage:1 → the second RCPT is refused 452.
  var rcptSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    maxRcptsPerMessage: 1,
  });
  var rcptInfo = await rcptSrv.listen({ port: 0, address: "127.0.0.1" });
  var rcptSock;
  try {
    rcptSock = await _connectTo(rcptInfo);
    await _sendCommand(rcptSock, "EHLO sender.example.com");
    await _sendCommand(rcptSock, "MAIL FROM:<s@external.com>");
    await _sendCommand(rcptSock, "RCPT TO:<alice@example.com>");
    check("second RCPT past maxRcptsPerMessage → 452",
      /^452 4\.5\.3/.test(await _sendCommand(rcptSock, "RCPT TO:<bob@example.com>")));
    rcptSock.destroy();
  } finally { await rcptSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // Declared SIZE= reconciled against the actual DATA byte count (RFC 1870
  // §6.3): a body larger than the declared SIZE is refused after DATA.
  var overrunSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var overrunInfo = await overrunSrv.listen({ port: 0, address: "127.0.0.1" });
  var overrunSock;
  try {
    overrunSock = await _connectTo(overrunInfo);
    await _sendCommand(overrunSock, "EHLO sender.example.com");
    await _sendCommand(overrunSock, "MAIL FROM:<s@external.com> SIZE=10");
    await _sendCommand(overrunSock, "RCPT TO:<alice@example.com>");
    await _sendCommand(overrunSock, "DATA");
    check("DATA body over declared SIZE= → 552 (RFC 1870 §6.3)",
      /^552 5\.3\.4/.test(await _sendCommand(overrunSock,
        "From: s@external.com\r\nSubject: overrun\r\n\r\nthis body is far larger than ten bytes\r\n.")));
    overrunSock.destroy();
  } finally { await overrunSrv.close({ timeoutMs: 1000 }); }                          // allow:raw-time-literal — test-only short drain

  // Per-command line cap: a command line past the hard byte ceiling is
  // refused 500 and the connection is dropped.
  var lineSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    maxLineBytes: 64,
  });
  var lineInfo = await lineSrv.listen({ port: 0, address: "127.0.0.1" });
  var lineSock;
  try {
    lineSock = await _connectTo(lineInfo);
    var overlong = "";
    for (var j = 0; j < 400; j += 1) overlong += "A";
    check("over-long command line → 500 5.5.6 + close",
      /^500 5\.5\.6/.test(await _sendCommand(lineSock, overlong)));
    lineSock.destroy();
  } finally { await lineSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain
}

// ---- Per-IP RCPT-failure cap: repeated failed recipients trip a 421 + close
// (the mailbox-enumeration backstop — RFC 5321 §3.5). A low cap makes the
// backoff deterministic.
async function testRcptFailureRateLimit() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("RCPT-failure rate limit (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    rateLimit: { rcptFailuresPerIpPerMinute: 2 },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    await _sendCommand(sock, "EHLO sender.example.com");
    await _sendCommand(sock, "MAIL FROM:<s@external.com>");
    // Two relay-denied recipients spend the failure budget.
    check("first relay-denied RCPT → 550",
      /^550 5\.7\.1/.test(await _sendCommand(sock, "RCPT TO:<a@notlocal.example>")));
    check("second relay-denied RCPT → 550",
      /^550 5\.7\.1/.test(await _sendCommand(sock, "RCPT TO:<b@notlocal.example>")));
    // The next RCPT trips the per-IP failure cap → 421 + connection close.
    check("RCPT past the per-IP failure cap → 421 + close",
      /^421 4\.7\.0/.test(await _sendCommand(sock, "RCPT TO:<c@notlocal.example>")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- SMTP-smuggling wire paths: bare-LF / bare-CR / NUL command lines and
// a bare-LF dot-terminator in the DATA body. Captures the smtp_smuggling
// _detected audit to prove the NUL-injection path is audited (regression:
// the code guard emits is `guard-smtp-command/nul`, not `nul-byte`).
async function testWireSmuggling() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("wire smuggling (skipped)", true); return; }

  // strict profile refuses bare LF (permissive tolerates it), so the
  // smuggling-detected audit fires for bare LF / bare CR / NUL here.
  var strictSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "strict", localDomains: ["example.com"],
  });
  var strictInfo = await strictSrv.listen({ port: 0, address: "127.0.0.1" });
  var cmdSock;
  await _withAuditCapture(async function (events) {
    try {
      cmdSock = await _connectTo(strictInfo);
      check("bare-LF in command line → 500",
        /^500 5\.5\.2/.test(await _sendCommand(cmdSock, "EHLO x\ny")));
      check("bare-CR in command line → 500",
        /^500 5\.5\.2/.test(await _sendCommand(cmdSock, "EHLO x\rY")));
      check("NUL byte in command line → 500",
        /^500 5\.5\.2/.test(await _sendCommand(cmdSock, ("EHL" + String.fromCharCode(0) + "O example.com"))));
      cmdSock.destroy();
    } finally { if (cmdSock) cmdSock.destroy(); }

    function smug(code) {
      return events.filter(function (e) {
        return e && e.action === "mail.server.mx.smtp_smuggling_detected" &&
          e.metadata && e.metadata.code === code;
      }).length;
    }
    check("bare-LF command emits smtp_smuggling_detected audit",
      smug("guard-smtp-command/bare-lf") >= 1);
    check("bare-CR command emits smtp_smuggling_detected audit",
      smug("guard-smtp-command/bare-cr") >= 1);
    check("NUL-byte command emits smtp_smuggling_detected audit (code /nul)",
      smug("guard-smtp-command/nul") >= 1);
  });
  await strictSrv.close({ timeoutMs: 1000 });                                          // allow:raw-time-literal — test-only short drain

  // DATA-body bare-LF dot terminator (the CVE-2023-51764 smuggling shape)
  // is refused 554 mid-body under any profile.
  var bodySrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var bodyInfo = await bodySrv.listen({ port: 0, address: "127.0.0.1" });
  var bodySock;
  try {
    bodySock = await _connectTo(bodyInfo);
    await _sendCommand(bodySock, "EHLO sender.example.com");
    await _sendCommand(bodySock, "MAIL FROM:<s@external.com>");
    await _sendCommand(bodySock, "RCPT TO:<alice@example.com>");
    await _sendCommand(bodySock, "DATA");
    check("bare-LF dot-terminator in DATA body → 554 (SMTP smuggling)",
      /^554 5\.7\.0/.test(await _sendCommand(bodySock, "smuggled\n.\n")));
    bodySock.destroy();
  } finally { await bodySrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain
}

// ---- Operator-explicit relay allowlist admits non-local recipients ------
async function testRelayAllowed() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("relay allowlist (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    relayAllowedFor: [{ cidr: "0.0.0.0/0", scope: "all" }],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    await _sendCommand(sock, "EHLO sender.example.com");
    await _sendCommand(sock, "MAIL FROM:<s@external.com>");
    check("non-local RCPT admitted when relayAllowedFor is set → 250",
      /^250 /.test(await _sendCommand(sock, "RCPT TO:<bob@notlocal.example>")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- relayAllowedFor enforces the entry CIDR against the peer address ---
// A peer OUTSIDE every allowlisted range must be relay-refused; only a peer
// INSIDE a range is admitted. Regression guard for the open-relay class where
// a non-empty relayAllowedFor admitted every peer regardless of source
// address (the entry `cidr` was ignored).
async function testRelayCidrEnforced() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("relay CIDR enforcement (skipped)", true); return; }

  // (a) Peer 127.0.0.1 is OUTSIDE 10.0.0.0/8 → relay refused with 550.
  var denySrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    relayAllowedFor: [{ cidr: "10.0.0.0/8", scope: "internal" }],
  });
  var denyInfo = await denySrv.listen({ port: 0, address: "127.0.0.1" });
  var denySock;
  try {
    denySock = await _connectTo(denyInfo);
    await _sendCommand(denySock, "EHLO sender.example.com");
    await _sendCommand(denySock, "MAIL FROM:<attacker@evil.com>");
    check("out-of-CIDR peer relay-refused → 550 (no open relay)",
      /^550 5\.7\.1/.test(await _sendCommand(denySock, "RCPT TO:<victim@notlocal.example>")));
    denySock.destroy();
  } finally { await denySrv.close({ timeoutMs: 1000 }); }                              // allow:raw-time-literal — test-only short drain

  // (b) Peer 127.0.0.1 is INSIDE 127.0.0.0/8 → relay admitted with 250.
  var allowSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    relayAllowedFor: [{ cidr: "127.0.0.0/8", scope: "loopback" }],
  });
  var allowInfo = await allowSrv.listen({ port: 0, address: "127.0.0.1" });
  var allowSock;
  try {
    allowSock = await _connectTo(allowInfo);
    await _sendCommand(allowSock, "EHLO sender.example.com");
    await _sendCommand(allowSock, "MAIL FROM:<s@external.com>");
    check("in-CIDR peer relay admitted → 250",
      /^250 /.test(await _sendCommand(allowSock, "RCPT TO:<bob@notlocal.example>")));
    allowSock.destroy();
  } finally { await allowSrv.close({ timeoutMs: 1000 }); }                             // allow:raw-time-literal — test-only short drain

  // (b2) IPv4-mapped fold the relay gate relies on. An IPv4 client on the
  // common dual-stack `::` listener is reported by Node as ::ffff:a.b.c.d;
  // cidrContains refuses a cross-family compare, so the gate folds the mapped
  // peer via ssrfGuard.canonicalizeHost before matching (otherwise every IPv4
  // client on a `::` listener would be denied against a documented IPv4 CIDR).
  // Asserted at the composed-primitive level — deterministic and hang-free,
  // where an end-to-end `::` bind + IPv4 dialog is runtime/dual-stack dependent.
  check("relay fold: a mapped peer canonicalizes to its IPv4 dotted form",
    b.ssrfGuard.canonicalizeHost("::ffff:127.0.0.1") === "127.0.0.1");
  check("relay fold: the raw mixed-family compare does NOT match (fold is required)",
    b.ssrfGuard.cidrContains("127.0.0.0/8", "::ffff:127.0.0.1") === false);
  check("relay fold: the folded IPv4 peer matches the IPv4 relay CIDR",
    b.ssrfGuard.cidrContains("127.0.0.0/8", b.ssrfGuard.canonicalizeHost("::ffff:127.0.0.1")) === true);
  check("relay fold: an out-of-CIDR mapped peer stays refused after folding (no fail-open)",
    b.ssrfGuard.cidrContains("127.0.0.0/8", b.ssrfGuard.canonicalizeHost("::ffff:10.9.9.9")) === false);

  // (c) Config-time: a malformed / mask-less relay CIDR is refused at boot.
  function bootRejects(label, entry) {
    var threw = null;
    try {
      b.mail.server.mx.create({
        tlsContext: {}, relayAllowedFor: [entry],
      });
    } catch (e) { threw = e; }
    check(label, threw && threw.code === "mail-server-mx/bad-relay-cidr");
  }
  bootRejects("malformed relay CIDR refused at boot", { cidr: "not-a-cidr", scope: "x" });
  bootRejects("mask-less relay CIDR refused at boot", { cidr: "203.0.113.5", scope: "x" });
  bootRejects("out-of-range prefix refused at boot", { cidr: "10.0.0.0/40", scope: "x" });
  bootRejects("non-object relay entry refused at boot", "10.0.0.0/8");

  // (c2) A dotted IPv4-mapped IPv6 relay CIDR (::ffff:10.0.0.0/104) is a valid
  // spelling that cidrContains accepts; the config validation folds it to the
  // plain IPv4 CIDR (10.0.0.0/8) so it is accepted at boot (rather than refused
  // as bad-relay-cidr) and then matches BOTH a genuine IPv4 peer and a mapped
  // peer via the gate's peer fold — not just the mapped form.
  function bootAccepts(label, entry) {
    var ok = true;
    try { b.mail.server.mx.create({ tlsContext: {}, relayAllowedFor: [entry] }); }
    catch (_e) { ok = false; }
    check(label, ok);
  }
  bootAccepts("dotted IPv4-mapped relay CIDR accepted at boot (folded to IPv4)",
    { cidr: "::ffff:10.0.0.0/104", scope: "internal" });
  bootAccepts("hex-group IPv4-mapped relay CIDR accepted at boot",
    { cidr: "::ffff:0a00:0/104", scope: "internal" });
  check("the ::ffff:10.0.0.0/104 fold (10.0.0.0/8) matches a genuine IPv4 peer",
    b.ssrfGuard.cidrContains("10.0.0.0/8", "10.2.3.4") === true);
  check("the ::ffff:10.0.0.0/104 fold (10.0.0.0/8) matches an IPv4-mapped peer",
    b.ssrfGuard.cidrContains("10.0.0.0/8", b.ssrfGuard.canonicalizeHost("::ffff:10.2.3.4")) === true);
}

// ---- Agent handoff failure surfaces a 451 transient error ---------------
async function testAgentHandoffFailure() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("agent handoff failure (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    agent: { handoff: async function () { throw new Error("mail store unavailable"); } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    await _sendCommand(sock, "EHLO sender.example.com");
    await _sendCommand(sock, "MAIL FROM:<s@external.com>");
    await _sendCommand(sock, "RCPT TO:<alice@example.com>");
    await _sendCommand(sock, "DATA");
    check("agent handoff rejection → 451 local delivery error",
      /^451 4\.3\.0/.test(await _sendCommand(sock,
        "From: s@external.com\r\nSubject: hi\r\n\r\nhello\r\n.")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- A gate that throws is caught by the pump → 421 + connection close --
async function testGateThrows() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("gate throws (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    helo: { evaluate: async function () { throw new Error("gate backend down"); } },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    check("throwing helo gate → 421 server error",
      /^421 4\.3\.0/.test(await _sendCommand(sock, "EHLO sender.example.com")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- Idle-timeout fires a 421 and closes the plaintext connection -------
async function testIdleTimeout() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("idle timeout (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    idleTimeoutMs: 300,                                                                // allow:raw-time-literal — test-only short idle window
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    var col = _collect(sock);
    // Send nothing — the idle timer fires the transient 421.
    await helpers.waitUntil(function () { return /^421 4\.4\.2/m.test(col.text()); },
      { timeoutMs: 5000, label: "mx idle timeout: 421 4.4.2 delivered" });
    check("idle connection → 421 4.4.2 + close", /^421 4\.4\.2/m.test(col.text()));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- close() drains, then force-destroys a lingering connection ---------
async function testCloseDestroysLingering() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("close-drain destroy (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock = await _connectTo(info);
  _collect(sock);   // swallow the shutdown 421 + reset without rejecting
  await _sendCommand(sock, "EHLO sender.example.com");
  check("one live connection tracked before close", srv.connectionCount() === 1);
  // Hold the client socket open; close() writes the shutdown 421, waits
  // out the short drain, then force-destroys the lingering connection.
  await srv.close({ timeoutMs: 200 });                                                 // allow:raw-time-literal — test-only short drain window
  check("close() force-destroys lingering connection → count 0",
    srv.connectionCount() === 0);
  sock.destroy();
}

// ---- TLS error/lifecycle paths: STARTTLS-when-already-active (503),
// a non-TLS ClientHello after the STARTTLS 220 (handshake failure), and
// the post-STARTTLS idle timeout. Mints one CA and reuses it. ------------
async function testTlsErrorPaths() {
  var ca, leaf;
  try {
    ca = await b.mtlsEngine.generateCa({ name: "mx-tls-errpaths-ca" });
    leaf = await b.mtlsEngine.signClientCert({
      cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
      usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1"], validityDays: 1,
    });
  } catch (_e) { check("TLS error paths (skipped — cert fixture unavailable)", true); return; }
  var ctx = nodeTls.createSecureContext({ key: leaf.key, cert: leaf.cert });

  // ---- STARTTLS issued a second time over the negotiated TLS → 503 ----
  var dupSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var dupInfo = await dupSrv.listen({ port: 0, address: "127.0.0.1" });
  var dupPlain, dupTls;
  try {
    dupPlain = await _connectTo(dupInfo);
    await _sendCommand(dupPlain, "EHLO sender.example.com");
    check("STARTTLS → 220 ready", /^220 /.test(await _sendCommand(dupPlain, "STARTTLS")));
    dupTls = nodeTls.connect({ socket: dupPlain, ca: [ca.caCertPem], servername: "localhost" });
    await new Promise(function (r, j) { dupTls.once("secureConnect", r); dupTls.once("error", j); });
    await _sendCommand(dupTls, "EHLO sender.example.com");
    check("STARTTLS when TLS already active → 503",
      /^503 5\.5\.1/.test(await _sendCommand(dupTls, "STARTTLS")));
    dupTls.destroy();
  } finally { await dupSrv.close({ timeoutMs: 1000 }); }                               // allow:raw-time-literal — test-only short drain

  // ---- Non-TLS bytes after the STARTTLS 220 → handshake failure/close --
  var hsSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var hsInfo = await hsSrv.listen({ port: 0, address: "127.0.0.1" });
  var hsSock;
  try {
    hsSock = await _connectTo(hsInfo);
    await _sendCommand(hsSock, "EHLO sender.example.com");
    await _sendCommand(hsSock, "STARTTLS");
    var closed = false;
    hsSock.on("close", function () { closed = true; });
    hsSock.on("error", function () { /* reset on failed handshake */ });
    // Garbage where the TLS ClientHello should be — the server's TLS
    // wrap errors and tears the connection down.
    hsSock.write("this is definitely not a tls client hello\r\n");
    await helpers.waitUntil(function () { return closed; },
      { timeoutMs: 5000, label: "mx STARTTLS: non-TLS bytes close the connection" });
    check("non-TLS bytes after STARTTLS 220 → connection closed", closed === true);
    hsSock.destroy();
  } finally { await hsSrv.close({ timeoutMs: 1000 }); }                                // allow:raw-time-literal — test-only short drain

  // ---- Post-STARTTLS idle timeout fires 421 over the TLS socket -------
  var idleSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    idleTimeoutMs: 600,                                                                // allow:raw-time-literal — room for handshake, then idle
  });
  var idleInfo = await idleSrv.listen({ port: 0, address: "127.0.0.1" });
  var idlePlain, idleTls;
  try {
    idlePlain = await _connectTo(idleInfo);
    await _sendCommand(idlePlain, "EHLO sender.example.com");
    await _sendCommand(idlePlain, "STARTTLS");
    idleTls = nodeTls.connect({ socket: idlePlain, ca: [ca.caCertPem], servername: "localhost" });
    await new Promise(function (r, j) { idleTls.once("secureConnect", r); idleTls.once("error", j); });
    await _sendCommand(idleTls, "EHLO sender.example.com");
    var tlsCol = _collect(idleTls);
    await helpers.waitUntil(function () { return /^421 4\.4\.2/m.test(tlsCol.text()); },
      { timeoutMs: 5000, label: "mx TLS idle timeout: 421 4.4.2 over TLS" });
    check("post-STARTTLS idle → 421 4.4.2 over TLS", /^421 4\.4\.2/m.test(tlsCol.text()));
    idleTls.destroy();
  } finally { await idleSrv.close({ timeoutMs: 1000 }); }                              // allow:raw-time-literal — test-only short drain
}

// ---- Address-literal HELO / null reverse-path skip domain hardening -----
// RFC 5321 §4.1.3 address literals (`[1.2.3.4]`) and the §4.5.5 empty
// reverse path (`<>`) are legitimate non-domain forms; the guardDomain
// hardening is skipped for them rather than refusing.
async function testAddressLiteralAndNullSender() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("address-literal / null sender (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var sock;
  try {
    sock = await _connectTo(info);
    check("EHLO address literal [127.0.0.1] accepted (hardening skipped)",
      /^250[ -]/.test(await _sendCommand(sock, "EHLO [127.0.0.1]")));
    check("MAIL FROM:<> null reverse path accepted (bounce path)",
      /^250 /.test(await _sendCommand(sock, "MAIL FROM:<>")));
    check("RCPT after null sender still accepted → 250",
      /^250 /.test(await _sendCommand(sock, "RCPT TO:<alice@example.com>")));
    // RCPT TO address literal skips domain hardening (RFC 5321 §4.1.3);
    // the non-local literal is then relay-refused.
    check("RCPT TO address literal skips hardening, then relay-refused → 550",
      /^550 5\.7\.1/.test(await _sendCommand(sock, "RCPT TO:<x@[127.0.0.1]>")));
    sock.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain

  // guardDomain disabled → the HELO/EHLO hardening branch is skipped
  // entirely (operator closed-network opt-out).
  var offSrv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    guardDomain: false,
  });
  var offInfo = await offSrv.listen({ port: 0, address: "127.0.0.1" });
  var offSock;
  try {
    offSock = await _connectTo(offInfo);
    check("EHLO with guardDomain disabled accepted (no hardening) → 250",
      /^250[ -]/.test(await _sendCommand(offSock, "EHLO sender.example.com")));
    offSock.destroy();
  } finally { await offSrv.close({ timeoutMs: 1000 }); }                               // allow:raw-time-literal — test-only short drain
}

// ---- Per-IP concurrent-connection cap refuses the excess connection ----
async function testConnectionRateLimit() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("connection rate limit (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
    rateLimit: { maxConcurrentConnectionsPerIp: 1 },
  });
  var info = await srv.listen({ port: 0, address: "127.0.0.1" });
  var first, second;
  try {
    first = await _connectTo(info);   // admitted; held open to occupy the single slot
    second = nodeNet.connect(info.port, "127.0.0.1");
    await new Promise(function (r) { second.once("connect", r); });
    var reply = await _readGreeting(second);   // first line is the refusal, not a 220
    check("excess concurrent connection refused with 421 4.7.0",
      /^421 4\.7\.0/.test(reply));
    first.destroy();
    second.destroy();
  } finally { await srv.close({ timeoutMs: 1000 }); }                                 // allow:raw-time-literal — test-only short drain
}

// ---- close() is idempotent: no-arg close drains, second close is a no-op
async function testCloseIdempotent() {
  var ctx;
  try { ctx = await _makeTestTlsContext(); }
  catch (_e) { check("close idempotency (skipped)", true); return; }
  var srv = b.mail.server.mx.create({
    tlsContext: ctx, profile: "permissive", localDomains: ["example.com"],
  });
  await srv.listen({ port: 0, address: "127.0.0.1" });
  var firstErr = null;
  try { await srv.close(); } catch (e) { firstErr = e; }   // no opts → default drain timeout
  check("close() with no options resolves", firstErr === null);
  var secondErr = null;
  try { await srv.close(); } catch (e) { secondErr = e; }  // already closed → early return
  check("second close() is a no-op", secondErr === null);
}

async function run() {
  testSurface();
  testCreateRequiresTlsContext();
  testCreateRejectsBadBounds();
  testGuardEnvelopeBootValidation();
  testGuardDomainBootOptions();
  testDetectSmugglingShape();
  testFindDotTerminator();
  testDotUnstuff();
  await testEhloFlow();
  await testRelayRefused();
  await testStrictProfileRequiresStartTls();
  await testConnectionGates();
  await testGateOverStartTls();
  await testGuardEnvelopeGate();
  await testCommandDispatch();
  await testSequenceAndSyntaxErrors();
  await testDomainRefusals();
  await testAddressLiteralAndNullSender();
  await testResourceLimits();
  await testRcptFailureRateLimit();
  await testConnectionRateLimit();
  await testWireSmuggling();
  await testRelayAllowed();
  await testRelayCidrEnforced();
  await testAgentHandoffFailure();
  await testGateThrows();
  await testIdleTimeout();
  await testCloseDestroysLingering();
  await testCloseIdempotent();
  await testTlsErrorPaths();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-mx] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
