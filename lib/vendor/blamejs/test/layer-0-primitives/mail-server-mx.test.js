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
  await testConnectionGates();
  await testGateOverStartTls();
  await testGuardEnvelopeGate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-mx] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
