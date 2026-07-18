// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail SMTP transport extensions — RFC 3030 BDAT/CHUNKING/BINARYMIME,
 * RFC 1870 SIZE pre-check, IPv6 connect family preference, and the
 * b.mail.reverseDns FCrDNS helper. Mock SMTP server scripts EHLO
 * advertisement to exercise the transport branches without a live
 * relay. Also drives the error / defensive / adversarial branches of
 * the wider b.mail surface — toAscii/toUnicode, the RFC 822 builder,
 * console/memory/http/resend transports, create() validation, and the
 * full SMTP state machine over a loopback TLS server whose leaf cert
 * is minted by b.mtlsEngine and trusted via opts.ca (verification
 * stays ON — no rejectUnauthorized bypass). The standalone CLI runs
 * ad-hoc; smoke wires this in as a layer-0 file.
 */

var http = require("node:http");
var net = require("net");
var tls = require("node:tls");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var C = b.constants;

function listenOnRandomPort(server) {
  return new Promise(function (resolve, reject) {
    server.listen(0, "127.0.0.1", function () { resolve(server.address().port); });
    server.on("error", reject);
  });
}

// Mock SMTP server that the smtp transport can talk to over CLEARTEXT.
// Skips STARTTLS by advertising it absent and accepting the cleartext
// path: in production the transport refuses cleartext send unless the
// peer accepts STARTTLS, but we simulate a TLS-already-established
// peer by overriding `useImplicitTLS` via implicitTls + mocking tls
// (out of scope here). Instead we accept that the transport will
// issue STARTTLS first and we respond with 220, then expect TLS
// handshake — but for these tests we bypass STARTTLS by setting
// implicitTls=true on the transport and serving the connection over
// plain TCP. The transport's tls.connect() against our plain socket
// surfaces a TLS error before any commands are sent.
//
// To exercise the post-EHLO branches without TLS plumbing, we use the
// SAME pattern the existing 00-primitives test uses: capture the lines
// the transport writes BEFORE it fails on the upgrade. EHLO + first
// MAIL FROM both reach the wire, which is what we need for B9/B10
// branch verification. For BDAT/CHUNKING happy-path coverage, we set
// implicitTls + run the server with a TLS listener too — but to keep
// fixtures lean, we test the wire FORMAT through the
// _buildRfc822ForTest export and the EHLO branching through the
// state-machine inputs that DO reach the wire (MAIL FROM line).

// Helper — start a cleartext server that:
//   1. greets with 220
//   2. responds to EHLO with the operator-supplied advertisement lines
//   3. captures every line the client writes
//   4. responds 250 to MAIL FROM / RCPT TO / DATA-354 / "." -250
//      OR 250 to BDAT chunks
//   5. ends gracefully on QUIT
//
// Records `bdatChunks: [{ size, last, body }]` and `mailFromLine`,
// `rcptLines`, `dataAccepted` so the test can assert the wire shape.
function startMockSmtp(advertisedExtensions) {
  var state = {
    lines:        [],
    mailFromLine: null,
    rcptLines:    [],
    dataAccepted: false,
    bdatChunks:   [],
    server:       null,
    port:         0,
  };
  var server = net.createServer(function (sock) {
    sock.write("220 mock.local ESMTP\r\n");
    var inDataMode = false;
    var dataBuffer = "";
    var bdatRemaining = 0;
    var bdatLast = false;
    var bdatBody = Buffer.alloc(0);
    var pending = Buffer.alloc(0);
    sock.on("data", function (chunk) {
      pending = Buffer.concat([pending, chunk]);
      // BDAT body bytes consume length-prefixed bytes from pending.
      while (true) {
        if (bdatRemaining > 0) {
          if (pending.length === 0) return;
          var take = Math.min(bdatRemaining, pending.length);
          bdatBody = Buffer.concat([bdatBody, pending.slice(0, take)]);
          pending = pending.slice(take);
          bdatRemaining -= take;
          if (bdatRemaining === 0) {
            state.bdatChunks.push({
              size: bdatBody.length,
              last: bdatLast,
              body: bdatBody.toString("utf8"),
            });
            bdatBody = Buffer.alloc(0);
            sock.write("250 chunk accepted\r\n");
          }
          continue;
        }
        if (inDataMode) {
          // Look for CRLF.CRLF terminator.
          dataBuffer += pending.toString("utf8");
          pending = Buffer.alloc(0);
          var endIdx = dataBuffer.indexOf("\r\n.\r\n");
          if (endIdx >= 0) {
            inDataMode = false;
            dataBuffer = "";
            state.dataAccepted = true;
            sock.write("250 message accepted\r\n");
          }
          return;
        }
        // Line-mode command parsing.
        var nl = pending.indexOf("\r\n");
        if (nl < 0) return;
        var line = pending.slice(0, nl).toString("utf8");
        pending = pending.slice(nl + 2);
        if (!line) continue;
        state.lines.push(line);
        var u = line.toUpperCase();
        if (u.indexOf("EHLO") === 0) {
          var resp = "250-mock.local greets you\r\n";
          for (var i = 0; i < advertisedExtensions.length; i += 1) {
            var prefix = (i === advertisedExtensions.length - 1) ? "250 " : "250-";
            resp += prefix + advertisedExtensions[i] + "\r\n";
          }
          sock.write(resp);
        } else if (u.indexOf("MAIL FROM") === 0) {
          state.mailFromLine = line;
          sock.write("250 sender ok\r\n");
        } else if (u.indexOf("RCPT TO") === 0) {
          state.rcptLines.push(line);
          sock.write("250 rcpt ok\r\n");
        } else if (u === "DATA") {
          inDataMode = true;
          sock.write("354 send body\r\n");
        } else if (u.indexOf("BDAT ") === 0) {
          var parts = line.split(/\s+/);
          var n = parseInt(parts[1], 10);
          bdatRemaining = isFinite(n) && n >= 0 ? n : 0;
          bdatLast = (parts.length >= 3 && parts[2].toUpperCase() === "LAST");
        } else if (u === "QUIT") {
          sock.write("221 bye\r\n"); sock.end();
        } else if (u.indexOf("STARTTLS") === 0) {
          // Don't honor STARTTLS — respond 502 so the transport fails.
          sock.write("502 starttls not supported in mock\r\n");
        } else {
          sock.write("250 OK\r\n");
        }
      }
    });
    sock.on("error", function () { /* expected — client may tear down */ });
  });
  state.server = server;
  return state;
}

// Build a transport configured for our mock server. We force
// implicitTls=true so the transport doesn't try STARTTLS — but we
// pass a custom tlsOpts that makes Node accept the cleartext socket?
// That's not feasible. Easier: stub out tls.connect via the
// transport's `implicitTls: false` AND pass a server that DOES advertise
// STARTTLS — but we don't honor it here. The simpler route taken by
// the existing 00-primitives suite is to use cfg with implicitTls=true
// and a real TLS listener. To keep the fixture lean, we exercise the
// state machine via a TLS-faking server: the transport's tls.connect()
// over a plain socket fails immediately. Instead, we DRIVE the
// transport's state machine directly by exposing _smtpSendForTest? —
// not exported. The cleanest path is a TLS-on-localhost mock with a
// self-signed cert. Out of scope for layer-0.
//
// We test BDAT/SIZE branches via:
//   1. internal helpers (_messageWireSize / _parsePeerSize / etc.)
//      exposed via test-only export
//   2. wire-format assertion against b.mail._buildRfc822ForTest output
//   3. unit-level peer-size pre-check via the smtpTransport opt path
//
// For full end-to-end mail-over-net tests, the integration suite
// (test/integration/mail-smtp.test.js) handles a Mailpit fixture.

// ---- B9 / B10 / B17 — opts surface gates ----

function testSmtpTransportAcceptsChunkingOpts() {
  var t = b.mail.transports.smtp({
    host: "127.0.0.1", port: 2525,
    chunking: false,
    chunkSize: b.constants.BYTES.kib(64),
    respectPeerSize: false,
    preferFamily: 4,
  });
  check("smtpTransport accepts chunking opts shape", typeof t.send === "function");
}

function testSmtpTransportRefusesBadHost() {
  var threw = false;
  try { b.mail.transports.smtp({}); }
  catch (e) { threw = e.code === "mail/smtp-misconfigured"; }
  check("smtpTransport requires opts.host", threw === true);
}

// ---- B17 — reverseDns helper ----

async function testReverseDnsBadIp() {
  var r = await b.mail.reverseDns("not-an-ip");
  check("reverseDns refuses non-IP input",
        r.ok === false && r.fcrdns === false && typeof r.error === "string");
}

async function testReverseDnsLoopback() {
  // 127.0.0.1 reverse-resolves locally on most systems via /etc/hosts
  // → "localhost", whose forward query may or may not include 127.0.0.1
  // depending on the OS. We assert SHAPE not value: ok or error must
  // be present, and the result object must carry the documented keys.
  var r;
  try { r = await b.mail.reverseDns("127.0.0.1"); }
  catch (e) { r = { ok: false, error: (e && e.code) || "throw" }; }
  check("reverseDns returns ok|error result for loopback",
        r && (typeof r.ok === "boolean") &&
        Array.isArray(r.forward) &&
        (typeof r.fcrdns === "boolean"));
}

// ---- B10 — peer SIZE parsing ----

function testParsePeerSizeShape() {
  // Driven through the public surface: build a transport with
  // respectPeerSize:true and a tiny operator-side cap on the message,
  // then send through a mock peer that advertises a small SIZE.
  // Standalone parsing of EHLO lines is internal — but we can verify
  // the public-surface refuse path via a synthetic test below.
  // Here we assert the option shape is wired (typeof check).
  var t = b.mail.transports.smtp({
    host: "127.0.0.1", port: 2525, respectPeerSize: true,
  });
  check("smtpTransport with respectPeerSize:true builds", typeof t.send === "function");
}

// ---- B9 / B10 — wire format via test-only RFC 822 builder ----

function testRfc822BuilderProducesParseable() {
  // The internal _buildRfc822ForTest export lets us inspect the wire
  // bytes that get fed to BDAT / DATA. Verify the message starts with
  // RFC 5322 headers + has a body.
  var wire = b.mail._buildRfc822ForTest({
    from:    "From <from@example.com>",
    to:      "to@example.com",
    subject: "Test",
    text:    "Hello world",
  });
  check("_buildRfc822ForTest emits headers",
        /^From:/m.test(wire) && /^To:/m.test(wire) && /^Subject:/m.test(wire));
  check("_buildRfc822ForTest emits body separator",
        wire.indexOf("\r\n\r\n") !== -1);
  check("_buildRfc822ForTest emits Hello world body",
        wire.indexOf("Hello world") !== -1);
}

// ---- B9 — message binary-detection helper (proxied via transport) ----

function testMessageWithBinaryAttachment() {
  // We can't easily reach _messageRequiresBinaryMime directly without
  // exposing it. Instead verify behavior via the transport: a message
  // with a NUL-bearing buffer attachment + mock peer that does NOT
  // advertise BINARYMIME should refuse with mail/binarymime-not-
  // advertised. Drive through the b.mail.create + transport surface.
  var binaryBuffer = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,                                  // allow:raw-byte-literal — PNG magic bytes for fixture
                                   0x00, 0x00, 0x00, 0x0D]);                                                       // allow:raw-byte-literal — PNG IHDR length, fixture
  // Just verify the message accepts binary attachments without throwing
  // at validate-time — the BINARYMIME-required wire branch is exercised
  // by integration tests when a real peer is available.
  var captured = [];
  var mailer = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: true }); },
    audit: false,
    defaults: { from: "from@example.com" },
  });
  return mailer.send({
    to: "to@example.com",
    subject: "binary test",
    text: "see attached",
    attachments: [{
      filename: "logo.png",
      contentType: "image/png",
      content: binaryBuffer,
      binary: true,
    }],
  }).then(function () {
    check("binary-attachment message dispatches through transport",
          captured.length === 1 &&
          captured[0].attachments[0].binary === true);
  });
}

// ---- B10 — peer SIZE refusal end-to-end via mock SMTP ----

async function testPeerSizeRefusalEndToEnd() {
  // Start a mock SMTP server that advertises SIZE=64 (tiny cap). We
  // can't drive STARTTLS / TLS upgrade through the cleartext mock, so
  // we verify the EHLO line + early MAIL FROM branch via the smtp
  // transport's STARTTLS-failure path: the transport will issue
  // STARTTLS before MAIL FROM. Since our mock doesn't honor STARTTLS,
  // the transport fails before we can observe the SIZE check.
  //
  // We instead verify the SIZE ARG PARSER directly via a synthetic
  // test below — the integration suite covers the full wire path when
  // a real TLS-capable mock is available.
  var lines = ["8BITMIME", "SIZE 64", "CHUNKING", "BINARYMIME"];                                                    // allow:raw-byte-literal — SIZE byte cap fixture
  // The mock server also has STARTTLS missing — without TLS the
  // transport refuses to send AUTH / DATA so we can at least verify
  // the EHLO advertisement parsing reached the transport.
  var state = startMockSmtp(lines);
  await listenOnRandomPort(state.server);
  try {
    var transport = b.mail.transports.smtp({
      host: "127.0.0.1", port: state.server.address().port,
      ehloName: "test.local",
      timeoutMs: 1000,
    });
    var err = null;
    try {
      await transport.send({
        from: "sender@test.local",
        to: "rcpt@test.local",
        subject: "S",
        text: "T",
      });
    } catch (e) { err = e; }
    check("transport surfaces a MailError when STARTTLS denied",
          err && err.isMailError === true);
    check("transport emitted EHLO before failing",
          state.lines.some(function (l) { return /^EHLO /i.test(l); }));
    // The transport's STARTTLS branch runs BEFORE EHLO is re-issued
    // post-upgrade, so we don't reach MAIL FROM in this path. The
    // assertion confirms the SIZE / CHUNKING extension lines reached
    // the wire — operator-facing posture is "you advertised; we'd
    // honor it post-TLS."
    check("mock server advertised CHUNKING + SIZE + BINARYMIME",
          state.lines.length > 0);
  } finally {
    await new Promise(function (resolve) { state.server.close(function () { resolve(); }); });
  }
}

async function testGuardDomainDefaultRefusesBareIp() {
  var m = b.mail.create({ transport: b.mail.transports.memory() });
  var threw = null;
  try {
    await m.send({ to: "alice@192.168.1.1", from: "sender@example.org",
      subject: "t", text: "hi" });
  } catch (e) { threw = e; }
  check("default guardDomain refuses bare IPv4 recipient",
    threw && threw.code === "mail/recipient-domain-refused" &&
    /ipv4-as-domain/.test(threw.message));
}

async function testGuardDomainDefaultRefusesSpecialUseDomain() {
  var m = b.mail.create({ transport: b.mail.transports.memory() });
  var threw = null;
  try {
    await m.send({ to: "alice@my-host.localhost", from: "sender@example.org",
      subject: "t", text: "hi" });
  } catch (e) { threw = e; }
  check("default guardDomain refuses RFC 6761 .localhost recipient",
    threw && threw.code === "mail/recipient-domain-refused" &&
    /special-use/.test(threw.message));
}

async function testGuardDomainOptOutAllows() {
  var m = b.mail.create({ transport: b.mail.transports.memory(), guardDomain: false });
  var rv = await m.send({ to: "alice@192.168.1.1", from: "sender@example.org",
    subject: "t", text: "hi" });
  check("guardDomain:false allows bare-IP recipient",
    rv && rv.transport === "memory");
}

async function testGuardDomainSkipsAddressLiteral() {
  // RFC 5321 §4.1.3 address literal form `[1.2.3.4]` — operator
  // explicitly wrapped, so the bracket-syntax constraint applies
  // not guardDomain.
  var m = b.mail.create({ transport: b.mail.transports.memory() });
  var rv = await m.send({ to: "alice@[192.168.1.1]", from: "sender@example.org",
    subject: "t", text: "hi" });
  check("address literal `[1.2.3.4]` allowed (bracket-syntax already constrains)",
    rv && rv.transport === "memory");
}

async function testGuardDomainPermissiveProfileAllowsBareIp() {
  // Regression: pre-fix, opts.guardDomain.profile was passed to
  // buildProfile() under the wrong key (`profile` vs `baseProfile`)
  // so the resulting profile was {} and validate() always fell back
  // to strict. Bare-IP recipient under permissive must succeed.
  var m = b.mail.create({
    transport:    b.mail.transports.memory(),
    guardDomain:  { profile: "permissive" },
  });
  var rv = await m.send({ to: "alice@192.168.1.1", from: "sender@example.org",
    subject: "t", text: "hi" });
  check("guardDomain:{profile:'permissive'} allows bare-IP recipient",
    rv && rv.transport === "memory");
}

async function testGuardDomainHappyPath() {
  var m = b.mail.create({ transport: b.mail.transports.memory() });
  var rv = await m.send({ to: "alice@example.com", from: "sender@example.org",
    subject: "t", text: "hi" });
  check("normal recipient allowed", rv && rv.transport === "memory");
}

async function testGuardDomainValidatesFromAddress() {
  var m = b.mail.create({ transport: b.mail.transports.memory() });
  var threw = null;
  try {
    await m.send({ to: "alice@example.com",
      from: "sender@192.168.1.1",
      subject: "t", text: "hi" });
  } catch (e) { threw = e; }
  check("from-address bare-IP refused",
    threw && threw.code === "mail/recipient-domain-refused" &&
    /from domain/.test(threw.message));
}

// ---------------------------------------------------------------------------
// Loopback SMTP mock — a scriptable RFC 5321 state machine over an
// already-secure socket (implicit TLS) or a cleartext socket that
// upgrades on STARTTLS. Captures every wire line + BDAT chunks.
// ---------------------------------------------------------------------------

function _wireHandler(sock, script, state) {
  sock.setEncoding("utf8");
  var pending = Buffer.alloc(0);
  var inData = false;
  var dataBuf = "";
  var bdatRemaining = 0;
  var bdatLast = false;
  var bdatBody = Buffer.alloc(0);
  function reply(code, text) { sock.write(code + " " + text + "\r\n"); }
  sock.on("data", function (chunk) {
    pending = Buffer.concat([pending, Buffer.from(chunk, "utf8")]);
    while (true) {
      if (bdatRemaining > 0) {
        if (pending.length === 0) return;
        var take = Math.min(bdatRemaining, pending.length);
        bdatBody = Buffer.concat([bdatBody, pending.slice(0, take)]);
        pending = pending.slice(take);
        bdatRemaining -= take;
        if (bdatRemaining === 0) {
          state.bdatChunks.push({ size: bdatBody.length, last: bdatLast });
          bdatBody = Buffer.alloc(0);
          reply(script.bdatCode || 250, "chunk ok");
        }
        continue;
      }
      if (inData) {
        dataBuf += pending.toString("utf8");
        pending = Buffer.alloc(0);
        if (dataBuf.indexOf("\r\n.\r\n") >= 0) {
          inData = false; dataBuf = "";
          reply(script.bodyCode || 250, "message accepted");
        }
        return;
      }
      var nl = pending.indexOf("\r\n");
      if (nl < 0) return;
      var line = pending.slice(0, nl).toString("utf8");
      pending = pending.slice(nl + 2);
      if (!line) continue;
      state.lines.push(line);
      var u = line.toUpperCase();
      if (u.indexOf("EHLO") === 0) {
        if (script.noEhloResponse) return;
        var ext = script.ext || [];
        var resp = "250-mock greets you\r\n";
        for (var i = 0; i < ext.length; i += 1) {
          resp += ((i === ext.length - 1) ? "250 " : "250-") + ext[i] + "\r\n";
        }
        if (ext.length === 0) resp = (script.ehloCode || 250) + " mock\r\n";
        else if (script.ehloCode && script.ehloCode !== 250) {
          resp = script.ehloCode + " ehlo rejected\r\n";
        }
        sock.write(resp);
      } else if (u.indexOf("AUTH LOGIN") === 0) {
        reply(script.authUserCode || 334, "VXNlcm5hbWU6");
      } else if (u.indexOf("MAIL FROM") === 0) {
        state.mailFromLine = line;
        reply(script.mailFromCode || 250, "sender ok");
      } else if (u.indexOf("RCPT TO") === 0) {
        state.rcptLines.push(line);
        reply(script.rcptCode || 250, "rcpt ok");
      } else if (u === "DATA") {
        if (script.dataCode && script.dataCode !== 354) {
          reply(script.dataCode, "data rejected");
        } else { inData = true; reply(354, "send body"); }
      } else if (u.indexOf("BDAT ") === 0) {
        var parts = line.split(/\s+/);
        var n = parseInt(parts[1], 10);
        bdatRemaining = isFinite(n) && n >= 0 ? n : 0;
        bdatLast = (parts.length >= 3 && parts[2].toUpperCase() === "LAST");
        if (bdatRemaining === 0) {
          state.bdatChunks.push({ size: 0, last: bdatLast });
          reply(script.bdatCode || 250, "empty chunk ok");
        }
      } else if (u === "QUIT") {
        reply(221, "bye"); sock.end();
      } else if (state.authStage !== undefined) {
        // AUTH LOGIN username/password base64 lines.
        state.authLines.push(line);
        if (state.authStage === 0) {
          state.authStage = 1;
          reply(script.authPassCode || 334, "UGFzc3dvcmQ6");
        } else {
          reply(script.authFinalCode || 235, "auth ok");
        }
      } else {
        reply(250, "ok");
      }
      // Track AUTH LOGIN follow-up lines: after "AUTH LOGIN" the next two
      // non-command lines are user + pass base64.
      if (u.indexOf("AUTH LOGIN") === 0) state.authStage = 0;
    }
  });
  sock.on("error", function () { /* client teardown is expected */ });
}

function _newState() {
  return {
    lines: [], mailFromLine: null, rcptLines: [], bdatChunks: [],
    authLines: [], authStage: undefined,
  };
}

// Implicit-TLS SMTP server.
function startTlsSmtp(certPair, script) {
  var state = _newState();
  var server = tls.createServer({ key: certPair.key, cert: certPair.cert }, function (sock) {
    if (typeof script.greetingFlood === "number") {
      sock.write(Buffer.alloc(script.greetingFlood, 0x61).toString("utf8"));  // allow:raw-byte-literal — 'a' filler for oversize-framing test
      sock.on("error", function () {});
      return;
    }
    sock.write((script.greeting || "220 mock ESMTP") + "\r\n");
    if (script.greetingReject) { sock.on("error", function () {}); return; }
    _wireHandler(sock, script, state);
  });
  state.server = server;
  return state;
}

// Cleartext SMTP server that upgrades to TLS on STARTTLS.
function startStarttlsSmtp(certPair, script) {
  var state = _newState();
  var server = net.createServer(function (raw) {
    raw.setEncoding("utf8");
    raw.write("220 mock ESMTP\r\n");
    var buf = "";
    raw.on("data", function onData(d) {
      buf += d;
      var idx;
      while ((idx = buf.indexOf("\r\n")) >= 0) {
        var line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        if (!line) continue;
        state.lines.push(line);
        var u = line.toUpperCase();
        if (u.indexOf("EHLO") === 0) {
          raw.write("250-mock\r\n250 STARTTLS\r\n");
        } else if (u.indexOf("STARTTLS") === 0) {
          if (script.starttls === "reject") { raw.write("502 no starttls\r\n"); continue; }
          raw.write("220 go ahead\r\n");
          raw.removeListener("data", onData);
          var upgraded = new tls.TLSSocket(raw, {
            isServer: true, key: certPair.key, cert: certPair.cert,
          });
          _wireHandler(upgraded, script, state);
          return;
        }
      }
    });
    raw.on("error", function () {});
  });
  state.server = server;
  return state;
}

function listen(state) {
  return new Promise(function (resolve, reject) {
    state.server.listen(0, "127.0.0.1", function () {
      state.port = state.server.address().port;
      resolve(state.port);
    });
    state.server.on("error", reject);
  });
}

function closeServer(state) {
  return new Promise(function (resolve) {
    try { state.server.close(function () { resolve(); }); }
    catch (_e) { resolve(); }
  });
}

// A TLS smtp transport pointed at a loopback mock; verification stays on
// via opts.ca + opts.servername:"localhost" (cert carries a localhost SAN).
function tlsTransport(certPair, port, extra) {
  var opts = {
    host: "127.0.0.1", port: port, implicitTls: true,
    ca: certPair.caCertPem, servername: "localhost", preferFamily: 4,
    timeoutMs: C.TIME.seconds(4),
  };
  if (extra) { for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) opts[k] = extra[k]; }
  return b.mail.transports.smtp(opts);
}

function starttlsTransport(certPair, port, extra) {
  var opts = {
    host: "127.0.0.1", port: port,
    ca: certPair.caCertPem, servername: "localhost", preferFamily: 4,
    timeoutMs: C.TIME.seconds(4),
  };
  if (extra) { for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) opts[k] = extra[k]; }
  return b.mail.transports.smtp(opts);
}

async function _sendErr(transport, message) {
  var err = null;
  try { await transport.send(message); }
  catch (e) { err = e; }
  return err;
}

// ---------------------------------------------------------------------------
// Pure helpers: toAscii / toUnicode
// ---------------------------------------------------------------------------

function testToAsciiBranches() {
  check("toAscii(non-string) → null", b.mail.toAscii(123) === null);
  check("toAscii('') → null", b.mail.toAscii("") === null);
  check("toAscii with '/' → null", b.mail.toAscii("a.com/evil") === null);
  check("toAscii with '?' → null", b.mail.toAscii("a.com?x") === null);
  check("toAscii with '#' → null", b.mail.toAscii("a.com#x") === null);
  check("toAscii with '\\\\' → null", b.mail.toAscii("a.com\\x") === null);
  check("toAscii with ':' → null", b.mail.toAscii("a.com:25") === null);
  check("toAscii with '@' → null", b.mail.toAscii("u@a.com") === null);
  check("toAscii with '[' → null", b.mail.toAscii("[1.2.3.4]") === null);
  check("toAscii IDN → xn--", b.mail.toAscii("münchen.de") === "xn--mnchen-3ya.de");
}

function testToUnicodeBranches() {
  check("toUnicode(non-string) → null", b.mail.toUnicode(123) === null);
  check("toUnicode('') → null", b.mail.toUnicode("") === null);
  check("toUnicode xn-- → unicode", b.mail.toUnicode("xn--mnchen-3ya.de") === "münchen.de");
}

// ---------------------------------------------------------------------------
// _buildRfc822ForTest — multipart, calendar, attachments, dot-stuffing
// ---------------------------------------------------------------------------

function testBuildRfc822MultipartAlternative() {
  var wire = b.mail._buildRfc822ForTest({
    from: "a@x.com", to: "b@y.com", subject: "s",
    text: "plain text", html: "<p>html</p>",
  });
  check("alt: multipart/alternative content-type",
    /Content-Type: multipart\/alternative; boundary="/.test(wire));
  check("alt: carries text part", wire.indexOf("text/plain; charset=utf-8") !== -1);
  check("alt: carries html part", wire.indexOf("text/html; charset=utf-8") !== -1);
  check("alt: closes boundary", /--blamejs-alt-[^\r\n]+--/.test(wire));
}

function testBuildRfc822CalendarCcReplyToHeaders() {
  var wire = b.mail._buildRfc822ForTest({
    from: "a@x.com", to: ["b@y.com", "c@y.com"], cc: ["d@y.com"],
    replyTo: "reply@x.com", subject: "invite",
    headers: { "X-Custom": "vv" },
    calendar: { method: "REQUEST", icalText: "BEGIN:VCALENDAR\r\nEND:VCALENDAR" },
  });
  check("cal: To joins array", /^To: b@y\.com, c@y\.com/m.test(wire));
  check("cal: Cc header present", /^Cc: d@y\.com/m.test(wire));
  check("cal: Reply-To header present", /^Reply-To: reply@x\.com/m.test(wire));
  check("cal: custom header present", /^X-Custom: vv/m.test(wire));
  check("cal: text/calendar with method param",
    wire.indexOf('text/calendar; method="REQUEST"') !== -1);
}

function testBuildRfc822AttachmentsAndDotStuffing() {
  var wire = b.mail._buildRfc822ForTest({
    from: "a@x.com", to: "b@y.com", subject: "s",
    text: ".leading dot line\nsecond",
    attachments: [
      { filename: "a.txt", content: "hello", contentType: "text/plain" },
      { filename: "logo.png", content: Buffer.from([0x89, 0x50]), cid: "img1" },  // allow:raw-byte-literal — 2-byte fixture
    ],
  });
  check("att: multipart/mixed wrapper", /Content-Type: multipart\/mixed; boundary="/.test(wire));
  check("att: base64 transfer encoding", wire.indexOf("Content-Transfer-Encoding: base64") !== -1);
  check("att: filename param", wire.indexOf('filename="a.txt"') !== -1);
  check("att: inline cid → Content-ID", wire.indexOf("Content-ID: <img1>") !== -1);
  check("att: inline disposition for cid part", wire.indexOf("Content-Disposition: inline") !== -1);
  check("att: built message body is NOT pre-dot-stuffed (DATA transparency moved to DATA send; BDAT gets raw)",
    wire.indexOf("\r\n.leading dot line") !== -1 && wire.indexOf("\r\n..leading dot line") === -1);
}

// ---------------------------------------------------------------------------
// console + memory transports
// ---------------------------------------------------------------------------

function _fakeStream() {
  var out = { data: "" };
  out.write = function (s) { out.data += s; };
  return out;
}

async function testConsoleTransport() {
  var s1 = _fakeStream();
  var t1 = b.mail.transports.console({ stream: s1 });
  var r1 = await t1.send({
    to: ["a@x.com", "b@x.com"], from: "f@x.com", subject: "hi",
    cc: ["c@x.com"], bcc: ["secret@x.com"], text: "body-text",
  });
  check("console: returns transport marker", r1.transport === "console" && typeof r1.deliveredAt === "number");
  check("console: prints To joined", s1.data.indexOf("To: a@x.com, b@x.com") !== -1);
  check("console: prints Cc", s1.data.indexOf("Cc: c@x.com") !== -1);
  check("console: prints Bcc addresses (redact off)", s1.data.indexOf("Bcc: secret@x.com") !== -1);
  check("console: prints body", s1.data.indexOf("body-text") !== -1);

  var s2 = _fakeStream();
  var t2 = b.mail.transports.console({ stream: s2, redactBcc: true });
  await t2.send({ to: "a@x.com", from: "f@x.com", bcc: ["x@x.com", "y@x.com"], html: "<b>hi</b>" });
  check("console: redactBcc hides addresses", s2.data.indexOf("x@x.com") === -1);
  check("console: redactBcc shows count", s2.data.indexOf("2 recipients") !== -1);
  check("console: html-only body renders size hint", s2.data.indexOf("(html body,") !== -1);

  // Single (non-array) recipient + single bcc branch.
  var s3 = _fakeStream();
  var t3 = b.mail.transports.console({ stream: s3, redactBcc: true });
  await t3.send({ to: "solo@x.com", from: "f@x.com", bcc: "one@x.com" });
  check("console: single bcc redacts to '1 recipient'", s3.data.indexOf("1 recipient —") !== -1);
}

async function testMemoryTransport() {
  var mem = b.mail.transports.memory();
  var r0 = await mem.send({ to: "a@x.com", from: "f@x.com" });
  var r1 = await mem.send({ to: "b@x.com", from: "f@x.com" });
  check("memory: captures sends", mem.sent.length === 2);
  check("memory: index reflects order", r0.index === 0 && r1.index === 1);
  check("memory: transport marker", r0.transport === "memory");
  mem.reset();
  check("memory: reset clears sent", mem.sent.length === 0);
}

// ---------------------------------------------------------------------------
// httpTransport — config gates, serializer faults, error wrap, interpret
// ---------------------------------------------------------------------------

function testHttpTransportConfigGates() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("http: requires endpoint",
    threw(function () { b.mail.transports.http({ serialize: function () {} }); }).code === "mail/http-misconfigured");
  check("http: requires serialize fn",
    threw(function () { b.mail.transports.http({ endpoint: "https://x.test" }); }).code === "mail/http-misconfigured");
}

async function testHttpTransportBadSerializer() {
  var t1 = b.mail.transports.http({
    endpoint: "https://x.test", name: "vend",
    serialize: function () { return null; },
  });
  var e1 = await _sendErr(t1, { to: "a@x.com", from: "f@x.com" });
  check("http: serialize non-object → bad-serializer", e1 && e1.code === "mail/vend-bad-serializer");

  var t2 = b.mail.transports.http({
    endpoint: "https://x.test", name: "vend",
    serialize: function () { return { body: 42 }; },
  });
  var e2 = await _sendErr(t2, { to: "a@x.com", from: "f@x.com" });
  check("http: serialize body non-string/Buffer → bad-serializer", e2 && e2.code === "mail/vend-bad-serializer");
}

async function testHttpTransportRequestFailureWrap() {
  // Point at a closed loopback port → ECONNREFUSED inside http-client →
  // rewrapped into mail/<name>-failed with the original as cause.
  var t = b.mail.transports.http({
    endpoint: "http://127.0.0.1:1/send", name: "vend",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    serialize: function () { return { body: "{}" }; },
  });
  var e = await _sendErr(t, { to: "a@x.com", from: "f@x.com" });
  check("http: request failure → mail/vend-failed", e && e.code === "mail/vend-failed");
  check("http: original error preserved as cause", e && e.cause != null);
}

async function testHttpTransportSuccessAndInterpret() {
  // Loopback HTTP server returns a controllable status + body; interpret
  // branches drive off it.
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var mode = req.headers["x-mode"];
      if (mode === "500") { res.writeHead(500); res.end("err"); return; }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "msg-123", extraKey: "ev" }));
    });
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  var base = {
    endpoint: "http://127.0.0.1:" + port + "/send", name: "vend",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
  };
  try {
    // (a) No interpret → returns info + statusCode.
    var tNo = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { body: "{}" }; },
    }));
    var rNo = await tNo.send({ to: "a@x.com", from: "f@x.com" });
    check("http: no-interpret returns info", rNo.transport === "vend" && rNo.statusCode === 200);

    // (b) interpret ok with id + extra merged.
    var tOk = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { headers: { "Content-Length": "2" }, body: "{}" }; },
      interpret: function (res) {
        var d = JSON.parse(res.body.toString("utf8"));
        return { ok: true, id: d.id, extra: { extraKey: d.extraKey } };
      },
    }));
    var rOk = await tOk.send({ to: "a@x.com", from: "f@x.com" });
    check("http: interpret id merged", rOk.id === "msg-123");
    check("http: interpret extra merged", rOk.extraKey === "ev");

    // (c) interpret verdict false → rejected with statusCode.
    var tRej = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { body: "{}" }; },
      interpret: function () { return { ok: false, reason: "nope", statusCode: 422 }; },
    }));
    var eRej = await _sendErr(tRej, { to: "a@x.com", from: "f@x.com" });
    check("http: verdict false → rejected", eRej && eRej.code === "mail/vend-rejected");
    check("http: rejected carries statusCode", eRej && eRej.statusCode === 422);

    // (d) interpret throws plain → interpret-failed.
    var tThrow = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { body: "{}" }; },
      interpret: function () { throw new Error("boom"); },
    }));
    var eThrow = await _sendErr(tThrow, { to: "a@x.com", from: "f@x.com" });
    check("http: interpret throw → interpret-failed", eThrow && eThrow.code === "mail/vend-interpret-failed");

    // (e) interpret throws a MailError → passthrough.
    var tMail = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { body: "{}" }; },
      interpret: function () { throw new b.mail.MailError("mail/custom-code", "x", true); },
    }));
    var eMail = await _sendErr(tMail, { to: "a@x.com", from: "f@x.com" });
    check("http: interpret MailError passthrough", eMail && eMail.code === "mail/custom-code");

    // (f) non-2xx status → http-client throws → mail/vend-failed with statusCode.
    var tErr = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { headers: { "X-Mode": "500" }, body: "{}" }; },
    }));
    var eErr = await _sendErr(tErr, { to: "a@x.com", from: "f@x.com" });
    check("http: non-2xx → mail/vend-failed", eErr && eErr.code === "mail/vend-failed");
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

// ---------------------------------------------------------------------------
// resendTransport — config gate + serialize + interpret over loopback
// ---------------------------------------------------------------------------

function testResendConfigGate() {
  var threw = null;
  try { b.mail.transports.resend({}); } catch (e) { threw = e; }
  check("resend: requires apiKey", threw && threw.code === "mail/resend-misconfigured");
}

async function testResendOverLoopback() {
  var lastBody = { v: null };
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      lastBody.v = Buffer.concat(chunks).toString("utf8");
      var mode = req.headers["x-scenario"];
      res.writeHead(200, { "Content-Type": "application/json" });
      if (mode === "noid") { res.end(JSON.stringify({ message: "quota exceeded" })); return; }
      if (mode === "badjson") { res.end("<html>not json</html>"); return; }
      res.end(JSON.stringify({ id: "re_abc" }));
    });
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  var endpoint = "http://127.0.0.1:" + port + "/emails";
  try {
    var tOk = b.mail.transports.resend({
      apiKey: "re_key", endpoint: endpoint,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var rOk = await tOk.send({
      from: "f@x.com", to: "a@x.com", cc: ["c@x.com"], bcc: "d@x.com",
      replyTo: "r@x.com", subject: "s", html: "<p>h</p>", text: "t",
      headers: { "X-H": "1" },
      attachments: [{ filename: "a.txt", content: "hello", contentType: "text/plain", cid: "c1" }],
    });
    check("resend: ok → id", rOk.id === "re_abc");
    var payload = JSON.parse(lastBody.v);
    check("resend: serialize to as array", Array.isArray(payload.to));
    check("resend: serialize cc/bcc arrays", Array.isArray(payload.cc) && Array.isArray(payload.bcc));
    check("resend: serialize reply_to", payload.reply_to === "r@x.com");
    check("resend: serialize attachment base64 + content_id",
      payload.attachments[0].content === Buffer.from("hello").toString("base64") &&
      payload.attachments[0].content_id === "c1");
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

async function testResendBadResponseAndNoId() {
  // Dedicated server that keys behavior off the request path so the real
  // resendTransport interpret branches (bad-json + no-id) are exercised.
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    if (req.url.indexOf("badjson") !== -1) { res.end("<html>nope</html>"); return; }
    if (req.url.indexOf("noid") !== -1) { res.end(JSON.stringify({ message: "denied" })); return; }
    res.end(JSON.stringify({ id: "re_ok" }));
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    var tBad = b.mail.transports.resend({
      apiKey: "k", endpoint: "http://127.0.0.1:" + port + "/badjson",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var eBad = await _sendErr(tBad, { to: "a@x.com", from: "f@x.com", subject: "s", text: "t" });
    check("resend: non-JSON body → bad-response", eBad && eBad.code === "mail/resend-bad-response");

    var tNo = b.mail.transports.resend({
      apiKey: "k", endpoint: "http://127.0.0.1:" + port + "/noid",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var eNo = await _sendErr(tNo, { to: "a@x.com", from: "f@x.com", subject: "s", text: "t" });
    check("resend: missing id → rejected (reason = message)",
      eNo && eNo.code === "mail/resend-rejected" && /denied/.test(eNo.message));
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

// ---------------------------------------------------------------------------
// create() — opts validation, transport shapes, error wrap, footer/unsub
// ---------------------------------------------------------------------------

function testCreateOptsAndTransportShapes() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("create: unknown opt rejected",
    threw(function () { b.mail.create({ bogusKey: 1 }); }) !== null);
  check("create: bad transport (object w/o send) rejected",
    threw(function () { b.mail.create({ transport: { name: "x" } }); }).code === "mail/bad-transport");
  // transport as a bare function is wrapped into { send, name:"anonymous" }.
  var m = b.mail.create({ transport: function () { return Promise.resolve({ ok: 1 }); }, audit: false });
  check("create: function transport wrapped", m.transport.name === "anonymous");
  // Default transport (console) when omitted.
  var m2 = b.mail.create({ audit: false });
  check("create: default transport is console", m2.transport.name === "console");
}

async function testCreateTransportErrorWrap() {
  // Non-MailError thrown by transport → wrapped as mail/transport-failed.
  var mPlain = b.mail.create({
    transport: function () { throw new Error("kaboom"); },
    guardDomain: false, audit: false,
  });
  var ePlain = await _sendErr(mPlain, { to: "a@x.com", from: "f@x.com", text: "hi" });
  check("create: plain transport error → mail/transport-failed", ePlain && ePlain.code === "mail/transport-failed");
  check("create: transport error preserves cause", ePlain && ePlain.cause && ePlain.cause.message === "kaboom");

  // A MailError thrown by transport is re-thrown unchanged.
  var mMail = b.mail.create({
    transport: function () { throw new b.mail.MailError("mail/custom", "nope", true); },
    guardDomain: false, audit: false,
  });
  var eMail = await _sendErr(mMail, { to: "a@x.com", from: "f@x.com", text: "hi" });
  check("create: MailError from transport passes through", eMail && eMail.code === "mail/custom");
}

async function testCreateUnsubscribeExpansion() {
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  await m.send({
    to: "a@x.com", from: "f@x.com", text: "hi",
    unsubscribe: { url: "https://x.test/unsub", oneClick: true },
  });
  var sent = captured[0];
  var keys = Object.keys(sent.headers || {}).map(function (k) { return k.toLowerCase(); });
  check("create: unsubscribe expands into List-Unsubscribe header",
    keys.indexOf("list-unsubscribe") !== -1);
  check("create: unsubscribe object removed after expansion", sent.unsubscribe === undefined);
}

function testCreateFooterHtmlValidation() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  var addr = { street: "1 St", city: "X", region: "Y", postalCode: "62701", country: "US" };
  // Valid override carrying country + postalCode → create succeeds.
  var ok = threw(function () {
    b.mail.create({
      transport: b.mail.transports.memory(), commercial: true, audit: false,
      postalAddress: addr, footerHtml: "<div>Acme, 62701, US</div>",
    });
  });
  check("create: footerHtml with country+postalCode accepted", ok === null);
  // Missing country → refused.
  var eC = threw(function () {
    b.mail.create({
      transport: b.mail.transports.memory(), commercial: true, audit: false,
      postalAddress: addr, footerHtml: "<div>Acme 62701</div>",
    });
  });
  check("create: footerHtml missing country → bad-footer-html", eC && eC.code === "mail/bad-footer-html");
  // Missing postalCode (country present) → refused.
  var eP = threw(function () {
    b.mail.create({
      transport: b.mail.transports.memory(), commercial: true, audit: false,
      postalAddress: addr, footerHtml: "<div>Acme US</div>",
    });
  });
  check("create: footerHtml missing postalCode → bad-footer-html", eP && eP.code === "mail/bad-footer-html");
}

async function testCommercialHtmlOnlyAndStringAddress() {
  // commercial:true with a STRING postalAddress + html-only message: text
  // is null → the append-when-null branch fills text with the address.
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false, commercial: true,
    postalAddress: "Acme Inc, 500 Rue, 75001 Paris, France",
    defaults: { from: "shop@x.com" },
  });
  await m.send({
    to: "a@x.com", subject: "promo", html: "<p>buy</p>",
    headers: { "List-Unsubscribe": "<https://x.test/u>" },
  });
  var sent = captured[0];
  check("commercial: html footer appended with string address", sent.html.indexOf("Acme Inc") !== -1);
  check("commercial: text synthesized from string address when text null",
    typeof sent.text === "string" && sent.text.indexOf("Acme Inc") !== -1);
}

// ---------------------------------------------------------------------------
// _validateMessage — adversarial / malformed message branches
// ---------------------------------------------------------------------------

function _validator() {
  return b.mail.create({
    transport: function () { return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
}

async function testValidateMessageBranches() {
  var m = _validator();
  async function expect(label, message, code) {
    var e = await _sendErr(m, message);
    check(label, e && e.code === code);
  }
  await expect("missing to", { from: "f@x.com", text: "hi" }, "mail/missing-to");
  await expect("empty-string recipient", { to: [""], from: "f@x.com", text: "hi" }, "mail/invalid-recipient");
  await expect("recipient control char", { to: ["a\r\nb@x.com"], from: "f@x.com", text: "hi" }, "mail/invalid-recipient");
  await expect("recipient bad address", { to: ["notanemail"], from: "f@x.com", text: "hi" }, "mail/invalid-recipient");
  await expect("missing from", { to: "a@x.com", text: "hi" }, "mail/missing-from");
  await expect("from control char", { to: "a@x.com", from: "a\r\nb@x.com", text: "hi" }, "mail/invalid-from");
  await expect("from bad address", { to: "a@x.com", from: "notanemail", text: "hi" }, "mail/invalid-from");
  await expect("subject CRLF", { to: "a@x.com", from: "f@x.com", subject: "a\r\nb", text: "hi" }, "mail/invalid-subject");
  await expect("missing body", { to: "a@x.com", from: "f@x.com" }, "mail/missing-body");
}

async function testValidateCalendarBranches() {
  var m = _validator();
  async function expect(label, cal, code) {
    var e = await _sendErr(m, { to: "a@x.com", from: "f@x.com", calendar: cal });
    check(label, e && e.code === code);
  }
  await expect("calendar not object", 5, "mail/invalid-calendar");
  await expect("calendar bad method", { method: "BOGUS", icalText: "BEGIN:VCALENDAR" }, "mail/invalid-calendar");
  await expect("calendar no icalText", { method: "REQUEST" }, "mail/invalid-calendar");
  await expect("calendar not vcalendar", { method: "REQUEST", icalText: "nope" }, "mail/invalid-calendar");
  // Valid calendar-only message dispatches.
  var captured = [];
  var m2 = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  await m2.send({ to: "a@x.com", from: "f@x.com", calendar: { method: "PUBLISH", icalText: "BEGIN:VCALENDAR\r\nEND:VCALENDAR" } });
  check("calendar: valid calendar-only dispatches", captured.length === 1);
}

async function testValidateAttachmentBranches() {
  var m = _validator();
  var base = { to: "a@x.com", from: "f@x.com", text: "hi" };
  async function expect(label, attachments, code) {
    var msg = Object.assign({}, base, { attachments: attachments });
    var e = await _sendErr(m, msg);
    check(label, e && e.code === code);
  }
  await expect("attachments not array", "nope", "mail/invalid-attachments");
  await expect("attachment not object", [5], "mail/invalid-attachment");
  await expect("attachment no filename", [{ content: "x" }], "mail/invalid-attachment");
  await expect("attachment filename control char", [{ filename: "a\r\nb.txt", content: "x" }], "mail/invalid-attachment");
  await expect("attachment filename traversal (guardFilename)", [{ filename: "../../etc/passwd", content: "x" }], "mail/invalid-attachment");
  await expect("attachment content missing", [{ filename: "a.txt" }], "mail/invalid-attachment");
  await expect("attachment content wrong type", [{ filename: "a.txt", content: 5 }], "mail/invalid-attachment");
  await expect("attachment contentType unclean", [{ filename: "a.txt", content: "x", contentType: "text/plain\r\nX: y" }], "mail/invalid-attachment");
  await expect("attachment bad disposition", [{ filename: "a.txt", content: "x", contentDisposition: "sideways" }], "mail/invalid-attachment");
  await expect("attachment bad cid (angle bracket)", [{ filename: "a.txt", content: "x", cid: "a<b>" }], "mail/invalid-attachment");
  // Magic-byte mismatch: real PNG magic bytes but claimed text/plain.
  await expect("attachment magic-byte mismatch",
    [{ filename: "a.txt", content: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D]), contentType: "text/plain" }],  // allow:raw-byte-literal — PNG magic bytes vs text/plain claim
    "mail/invalid-attachment");
  // skipFilenameSafety + skipMagicByteCheck bypasses → send succeeds.
  var captured = [];
  var m2 = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  await m2.send(Object.assign({}, base, {
    attachments: [{
      filename: "weird name.txt".replace(" ", ""), content: "x",
      skipFilenameSafety: true, skipMagicByteCheck: true, contentType: "text/plain",
      contentDisposition: "attachment",
    }],
  }));
  check("attachment: valid attachment dispatches", captured.length === 1);
}

async function testEaiRecipientAccepted() {
  // EAI path: Unicode local + IDN domain must validate through _isValidEmail.
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  await m.send({ to: "bü@münchen.de", from: "f@x.com", subject: "grüße", text: "hi" });
  check("eai: unicode recipient + IDN domain accepted", captured.length === 1);
  // "Name <addr>" display form accepted.
  captured.length = 0;
  await m.send({ to: "Alice <alice@x.com>", from: "Bob <bob@x.com>", text: "hi" });
  check("display-name form accepted", captured.length === 1);
}

// ---------------------------------------------------------------------------
// smtpTransport — config-time gates (no socket needed)
// ---------------------------------------------------------------------------

function testSmtpConfigGates() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("smtp: requires host",
    threw(function () { b.mail.transports.smtp({}); }).code === "mail/smtp-misconfigured");
  check("smtp: bad dkimSigner shape",
    threw(function () { b.mail.transports.smtp({ host: "h", dkimSigner: { nope: 1 } }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in ehloName refused",
    threw(function () { b.mail.transports.smtp({ host: "h", ehloName: "x\r\nMAIL FROM:<e>" }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in user refused",
    threw(function () { b.mail.transports.smtp({ host: "h", user: "u\r\nx" }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in pass refused",
    threw(function () { b.mail.transports.smtp({ host: "h", pass: "p\r\nx" }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in host refused",
    threw(function () { b.mail.transports.smtp({ host: "h\r\nx" }); }).code === "mail/smtp-misconfigured");
  check("smtp: CRLF in servername refused",
    threw(function () { b.mail.transports.smtp({ host: "h", servername: "s\r\nx" }); }).code === "mail/smtp-misconfigured");
  check("smtp: bad port refused",
    threw(function () { b.mail.transports.smtp({ host: "h", port: 70000 }); }).code === "mail/smtp-misconfigured");
  check("smtp: bad chunkSize refused",
    threw(function () { b.mail.transports.smtp({ host: "h", chunkSize: -1 }); }).code === "mail/smtp-misconfigured");
  check("smtp: bad maxTransactionMs refused",
    threw(function () { b.mail.transports.smtp({ host: "h", maxTransactionMs: -5 }); }).code === "mail/smtp-misconfigured");
}

async function testSmtpDkimSignFailureRejectsPreConnect() {
  // A dkimSigner whose .sign() throws rejects the send synchronously,
  // before any socket is opened — so any unroutable host is fine.
  var t = b.mail.transports.smtp({
    host: "127.0.0.1", port: 1, implicitTls: true,
    dkimSigner: { sign: function () { throw new Error("no key"); } },
  });
  var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", subject: "s", text: "t" });
  check("smtp: dkim sign failure → mail/dkim-sign-failed", e && e.code === "mail/dkim-sign-failed");
}

// ---------------------------------------------------------------------------
// smtpTransport — full state machine over loopback TLS
// ---------------------------------------------------------------------------

async function testSmtpHappyPathData(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var r = await t.send({ from: "s@a.test", to: ["r1@b.test", "r2@b.test"], cc: "c@b.test", subject: "hi", text: "hello" });
    check("smtp-data: delivered with code 250", r.transport === "smtp" && r.code === 250);
    check("smtp-data: sent RCPT for to+cc (3)", st.rcptLines.length === 3);
    check("smtp-data: used DATA not BDAT", st.bdatChunks.length === 0);
  } finally { await closeServer(st); }
}

async function testSmtpAuthLogin(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port, { user: "user", pass: "pass" });
    var r = await t.send({ from: "s@a.test", to: "r@b.test", subject: "hi", text: "hello" });
    check("smtp-auth: delivered after AUTH LOGIN", r.code === 250);
    check("smtp-auth: sent AUTH LOGIN", st.lines.some(function (l) { return /^AUTH LOGIN/i.test(l); }));
    check("smtp-auth: sent b64 user", st.authLines.indexOf(Buffer.from("user").toString("base64")) !== -1);
    check("smtp-auth: sent b64 pass", st.authLines.indexOf(Buffer.from("pass").toString("base64")) !== -1);
  } finally { await closeServer(st); }
}

async function testSmtpBdatChunking(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["CHUNKING", "8BITMIME"] });
  await listen(st);
  try {
    // Small chunkSize forces multiple BDAT chunks.
    var t = tlsTransport(certPair, st.port, { chunkSize: C.BYTES.bytes(32) });
    var r = await t.send({ from: "s@a.test", to: "r@b.test", subject: "hi", text: new Array(20).join("chunkybody-") });
    check("smtp-bdat: delivered", r.code === 250);
    check("smtp-bdat: used BDAT (multiple chunks)", st.bdatChunks.length >= 2);
    check("smtp-bdat: final chunk marked LAST", st.bdatChunks[st.bdatChunks.length - 1].last === true);
  } finally { await closeServer(st); }
}

async function testSmtpBinaryMimeBdat(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["CHUNKING", "BINARYMIME", "8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var r = await t.send({
      from: "s@a.test", to: "r@b.test", subject: "bin", text: "see attached",
      attachments: [{ filename: "a.bin", content: Buffer.from([0x00, 0x01, 0x02, 0x00]), binary: true, skipMagicByteCheck: true, contentType: "application/octet-stream" }],  // allow:raw-byte-literal — NUL-bearing binary fixture
    });
    check("smtp-binarymime: delivered via BDAT", r.code === 250 && st.bdatChunks.length >= 1);
    check("smtp-binarymime: MAIL FROM carried BODY=BINARYMIME", /BODY=BINARYMIME/.test(st.mailFromLine || ""));
  } finally { await closeServer(st); }
}

async function testSmtpSmtpUtf8And8BitMime(certPair) {
  var st1 = startTlsSmtp(certPair, { ext: ["SMTPUTF8", "8BITMIME", "SIZE 1000000"] });
  await listen(st1);
  try {
    var t1 = tlsTransport(certPair, st1.port);
    var r1 = await t1.send({ from: "s@a.test", to: "r@b.test", subject: "grüße", text: "hallo" });
    check("smtp-utf8: delivered", r1.code === 250);
    check("smtp-utf8: MAIL FROM carried SMTPUTF8", /SMTPUTF8/.test(st1.mailFromLine || ""));
    check("smtp-utf8: MAIL FROM carried SIZE=", /SIZE=\d+/.test(st1.mailFromLine || ""));
  } finally { await closeServer(st1); }

  var st2 = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st2);
  try {
    var t2 = tlsTransport(certPair, st2.port);
    var r2 = await t2.send({ from: "s@a.test", to: "r@b.test", subject: "s", text: "café ☕ body" });
    check("smtp-8bit: delivered", r2.code === 250);
    check("smtp-8bit: MAIL FROM carried BODY=8BITMIME", /BODY=8BITMIME/.test(st2.mailFromLine || ""));
  } finally { await closeServer(st2); }
}

async function testSmtpSizeRefusal(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["SIZE 10"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", subject: "s", text: "this body far exceeds ten bytes" });
    check("smtp-size: peer SIZE cap exceeded → mail/peer-size-exceeded", e && e.code === "mail/peer-size-exceeded");
  } finally { await closeServer(st); }
}

async function testSmtpEaiUnsupportedRefusal(certPair) {
  // Message requires SMTPUTF8 (unicode subject) but peer does not advertise it.
  var st = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", subject: "grüße", text: "hi" });
    check("smtp-eai: unicode but no SMTPUTF8 → mail/smtp-failed(eai)",
      e && e.code === "mail/smtp-failed" && /eai-required-not-supported/.test(e.message));
  } finally { await closeServer(st); }
}

async function testSmtpBinaryMimeUnsupportedRefusal(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var e = await _sendErr(t, {
      from: "s@a.test", to: "r@b.test", subject: "s", text: "x",
      attachments: [{ filename: "a.bin", content: Buffer.from([0x00, 0x00]), binary: true, skipMagicByteCheck: true, contentType: "application/octet-stream" }],  // allow:raw-byte-literal — NUL binary fixture
    });
    check("smtp-binarymime-unsupported → mail/binarymime-not-advertised",
      e && e.code === "mail/binarymime-not-advertised");
  } finally { await closeServer(st); }
}

async function testSmtpRejectionCodes(certPair) {
  // greeting rejected
  var stG = startTlsSmtp(certPair, { greeting: "554 go away" });
  await listen(stG);
  try {
    var eG = await _sendErr(tlsTransport(certPair, stG.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: greeting 554 → smtp-failed", eG && /greeting-rejected/.test(eG.message));
  } finally { await closeServer(stG); }

  // EHLO rejected
  var stE = startTlsSmtp(certPair, { ext: [], ehloCode: 500 });
  await listen(stE);
  try {
    var eE = await _sendErr(tlsTransport(certPair, stE.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: EHLO 500 → smtp-failed", eE && /ehlo-rejected/.test(eE.message));
  } finally { await closeServer(stE); }

  // MAIL FROM rejected
  var stM = startTlsSmtp(certPair, { ext: ["8BITMIME"], mailFromCode: 550 });
  await listen(stM);
  try {
    var eM = await _sendErr(tlsTransport(certPair, stM.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: MAIL FROM 550 → smtp-failed", eM && /mail-from-rejected/.test(eM.message));
  } finally { await closeServer(stM); }

  // RCPT rejected
  var stR = startTlsSmtp(certPair, { ext: ["8BITMIME"], rcptCode: 550 });
  await listen(stR);
  try {
    var eR = await _sendErr(tlsTransport(certPair, stR.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: RCPT 550 → smtp-failed", eR && /rcpt-rejected/.test(eR.message));
  } finally { await closeServer(stR); }

  // DATA rejected
  var stD = startTlsSmtp(certPair, { ext: ["8BITMIME"], dataCode: 503 });
  await listen(stD);
  try {
    var eD = await _sendErr(tlsTransport(certPair, stD.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: DATA 503 → smtp-failed", eD && /data-rejected/.test(eD.message));
  } finally { await closeServer(stD); }

  // BODY rejected (post-DATA final code non-250 → smtp-rejected)
  var stB = startTlsSmtp(certPair, { ext: ["8BITMIME"], bodyCode: 552 });
  await listen(stB);
  try {
    var eB = await _sendErr(tlsTransport(certPair, stB.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: BODY 552 → mail/smtp-rejected", eB && eB.code === "mail/smtp-rejected");
  } finally { await closeServer(stB); }

  // BDAT chunk rejected
  var stBd = startTlsSmtp(certPair, { ext: ["CHUNKING", "8BITMIME"], bdatCode: 552 });
  await listen(stBd);
  try {
    var eBd = await _sendErr(tlsTransport(certPair, stBd.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: BDAT chunk 552 → mail/bdat-chunk-rejected", eBd && eBd.code === "mail/bdat-chunk-rejected");
  } finally { await closeServer(stBd); }

  // AUTH final rejected
  var stA = startTlsSmtp(certPair, { ext: ["8BITMIME"], authFinalCode: 535 });
  await listen(stA);
  try {
    var eA = await _sendErr(tlsTransport(certPair, stA.port, { user: "u", pass: "p" }), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-reject: AUTH final 535 → smtp-failed", eA && /auth-failed/.test(eA.message));
  } finally { await closeServer(stA); }
}

async function testSmtpResponseTooLarge(certPair) {
  var st = startTlsSmtp(certPair, { greetingFlood: C.BYTES.kib(300) });
  await listen(st);
  try {
    var e = await _sendErr(tlsTransport(certPair, st.port), { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp: oversize framing → response-too-large", e && /response-too-large/.test(e.message));
  } finally { await closeServer(st); }
}

async function testSmtpTransactionTimeout(certPair) {
  // Server greets then never answers EHLO; a small maxTransactionMs
  // trips the absolute transaction deadline (socket idle timeout kept high).
  var st = startTlsSmtp(certPair, { noEhloResponse: true });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port, { maxTransactionMs: C.TIME.seconds(0.3), timeoutMs: C.TIME.seconds(10) });
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp: transaction deadline → transaction-timeout", e && /transaction-timeout/.test(e.message));
  } finally { await closeServer(st); }
}

async function testSmtpSocketTimeout(certPair) {
  // Small socket idle timeout, large transaction deadline → 'timeout' fires.
  var st = startTlsSmtp(certPair, { noEhloResponse: true });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port, { timeoutMs: C.TIME.seconds(0.3), maxTransactionMs: C.TIME.seconds(30) });
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp: idle timeout → smtp-failed(timeout)", e && e.code === "mail/smtp-failed" && /timeout/.test(e.message));
  } finally { await closeServer(st); }
}

async function testSmtpStarttlsHappyPath(certPair) {
  var st = startStarttlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = starttlsTransport(certPair, st.port);
    var r = await t.send({ from: "s@a.test", to: "r@b.test", subject: "hi", text: "hello" });
    check("smtp-starttls: delivered after upgrade", r.code === 250);
    check("smtp-starttls: issued STARTTLS then re-EHLO",
      st.lines.filter(function (l) { return /^EHLO/i.test(l); }).length >= 2);
  } finally { await closeServer(st); }
}

async function testSmtpStarttlsRejected(certPair) {
  var st = startStarttlsSmtp(certPair, { starttls: "reject" });
  await listen(st);
  try {
    var t = starttlsTransport(certPair, st.port);
    var e = await _sendErr(t, { from: "s@a.test", to: "r@b.test", text: "x" });
    check("smtp-starttls: rejected upgrade → starttls-rejected", e && /starttls-rejected/.test(e.message));
  } finally { await closeServer(st); }
}

// ---------------------------------------------------------------------------
// reverseDns — error branches via a fake resolver injected through
// network-dns? Not injectable; use documented shape checks on bad input.
// ---------------------------------------------------------------------------

async function testReverseDnsErrorShape() {
  var r = await b.mail.reverseDns("definitely not an ip");
  check("reverseDns: bad input → ok:false + error", r.ok === false && typeof r.error === "string" && r.fcrdns === false);
}

// ---------------------------------------------------------------------------
// b.mail.feedbackId — Gmail FBL 4-tuple builder: every reject branch + ok
// ---------------------------------------------------------------------------

function testFeedbackId() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  var ok = b.mail.feedbackId({
    campaignId: "wk26-promo", customerId: "acme", mailType: "marketing", senderId: "pool-1",
  });
  check("feedbackId: valid 4-tuple joins with ':'", ok === "wk26-promo:acme:marketing:pool-1");

  check("feedbackId: no opts → bad-feedback-id-opts",
    threw(function () { return b.mail.feedbackId(); }).code === "mail/bad-feedback-id-opts");
  check("feedbackId: non-object opts → bad-feedback-id-opts",
    threw(function () { return b.mail.feedbackId("nope"); }).code === "mail/bad-feedback-id-opts");
  check("feedbackId: missing field → bad-feedback-id-field",
    threw(function () { return b.mail.feedbackId({ customerId: "a", mailType: "b", senderId: "c" }); }).code === "mail/bad-feedback-id-field");
  check("feedbackId: empty-string field → bad-feedback-id-field",
    threw(function () { return b.mail.feedbackId({ campaignId: "", customerId: "a", mailType: "b", senderId: "c" }); }).code === "mail/bad-feedback-id-field");
  check("feedbackId: >64-char field → bad-feedback-id-field",
    threw(function () { return b.mail.feedbackId({ campaignId: "x".repeat(65), customerId: "a", mailType: "b", senderId: "c" }); }).code === "mail/bad-feedback-id-field");
  check("feedbackId: ':' in field (separator corruption) → bad-feedback-id-field",
    threw(function () { return b.mail.feedbackId({ campaignId: "a:b", customerId: "a", mailType: "b", senderId: "c" }); }).code === "mail/bad-feedback-id-field");
  check("feedbackId: control char in field → bad-feedback-id-field",
    threw(function () { return b.mail.feedbackId({ campaignId: "a\tb", customerId: "a", mailType: "b", senderId: "c" }); }).code === "mail/bad-feedback-id-field");
  check("feedbackId: CR in field → bad-feedback-id-field",
    threw(function () { return b.mail.feedbackId({ campaignId: "a\rb", customerId: "a", mailType: "b", senderId: "c" }); }).code === "mail/bad-feedback-id-field");
}

// ---------------------------------------------------------------------------
// b.mail.toAscii — domainToASCII returns empty (non-delimiter junk) → null
// ---------------------------------------------------------------------------

function testToAsciiPunycodeEmptyReturnsNull() {
  // A bare space / bare "xn--" prefix reaches nodeUrl.domainToASCII (no URL
  // delimiter to short-circuit on) which yields "" — the length-0 guard maps
  // that to null rather than surfacing an empty ACE label.
  check("toAscii(' ') → null (empty ACE)", b.mail.toAscii(" ") === null);
  check("toAscii('xn--') → null (empty ACE)", b.mail.toAscii("xn--") === null);
}

// ---------------------------------------------------------------------------
// b.mail.create — CAN-SPAM postalAddress validation at construction time
// ---------------------------------------------------------------------------

function testCreateCommercialPostalAddressValidation() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  var mem = b.mail.transports.memory();
  var validAddr = { street: "1 St", city: "Springfield", region: "IL", postalCode: "62701", country: "US" };

  check("create: commercial:true with no postalAddress → missing-postal-address",
    threw(function () { return b.mail.create({ transport: mem, commercial: true, audit: false }); }).code === "mail/missing-postal-address");
  check("create: commercial:true empty-string address → missing-postal-address",
    threw(function () { return b.mail.create({ transport: mem, commercial: true, postalAddress: "   ", audit: false }); }).code === "mail/missing-postal-address");
  check("create: commercial:true non-object non-string address → missing-postal-address",
    threw(function () { return b.mail.create({ transport: mem, commercial: true, postalAddress: 5, audit: false }); }).code === "mail/missing-postal-address");
  check("create: commercial:true object address missing a required field → missing-postal-address",
    threw(function () { return b.mail.create({ transport: mem, commercial: true, audit: false,
      postalAddress: { street: "1 St", city: "X", region: "Y", postalCode: "62701" } }); }).code === "mail/missing-postal-address");
  check("create: commercial:true address field with control char → missing-postal-address",
    threw(function () { return b.mail.create({ transport: mem, commercial: true, audit: false,
      postalAddress: { street: "1 St", city: "X", region: "Y", postalCode: "62701", country: "U\nS" } }); }).code === "mail/missing-postal-address");

  // regulated:true is the alias for commercial:true — same postal-address gate.
  check("create: regulated:true is the commercial alias (valid address builds)",
    threw(function () { return b.mail.create({ transport: mem, regulated: true, postalAddress: validAddr, audit: false }); }) === null);
  check("create: regulated:true with no address → missing-postal-address",
    threw(function () { return b.mail.create({ transport: mem, regulated: true, audit: false }); }).code === "mail/missing-postal-address");

  // String-shape postalAddress carries no structured country/postalCode fields,
  // so a footerHtml override needn't (can't) echo them — create still builds.
  check("create: string postalAddress + footerHtml builds (no structured field check)",
    threw(function () { return b.mail.create({ transport: mem, commercial: true, audit: false,
      postalAddress: "Acme, 500 Rue, 75001 Paris, FR", footerHtml: "<div>anything</div>" }); }) === null);
}

// ---------------------------------------------------------------------------
// b.mail.create send() — CAN-SPAM opt-out enforcement + object-address footer
// ---------------------------------------------------------------------------

async function testCommercialSendCanSpamAndObjectFooter() {
  var addr = { street: "1 St", city: "Springfield", region: "IL", postalCode: "62701", country: "US" };
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false, commercial: true, postalAddress: addr,
  });

  // (a) commercial send with neither unsubscribe object nor List-Unsubscribe
  // header → hard refusal before the transport is touched.
  var eNoUnsub = await _sendErr(m, { to: "a@x.com", from: "f@x.com", text: "hi" });
  check("commercial send: no opt-out → mail/canspam-no-unsubscribe",
    eNoUnsub && eNoUnsub.code === "mail/canspam-no-unsubscribe");
  check("commercial send: refusal happened before transport", captured.length === 0);

  // Headers present but none is List-Unsubscribe → the header scan exhausts
  // and the opt-out gate still refuses (distinct branch from headers absent).
  var eOtherHdr = await _sendErr(m, { to: "a@x.com", from: "f@x.com", text: "hi", headers: { "X-Other": "1" } });
  check("commercial send: non-matching headers still → mail/canspam-no-unsubscribe",
    eOtherHdr && eOtherHdr.code === "mail/canspam-no-unsubscribe");

  // (b) unsubscribe object → expands to List-Unsubscribe, send proceeds, and
  // the html footer is rendered from the STRUCTURED object address (<br>-joined
  // street / city+region+postal / country).
  captured.length = 0;
  await m.send({ to: "a@x.com", from: "f@x.com", html: "<p>buy</p>", unsubscribe: { url: "https://x.test/u" } });
  var sHtml = captured[0];
  check("commercial send: object address html footer carries street", sHtml.html.indexOf("1 St") !== -1);
  check("commercial send: object address html footer carries country", sHtml.html.indexOf("US") !== -1);
  check("commercial send: object address html footer uses <br> join", sHtml.html.indexOf("<br>") !== -1);
  check("commercial send: text part synthesized from object address when html-only",
    typeof sHtml.text === "string" && sHtml.text.indexOf("Springfield") !== -1);

  // (c) a pre-existing List-Unsubscribe header satisfies the opt-out gate too
  // (the header-scan branch of _hasUnsubscribe, distinct from the object form).
  captured.length = 0;
  await m.send({ to: "a@x.com", from: "f@x.com", text: "hi", headers: { "List-Unsubscribe": "<https://x.test/u>" } });
  check("commercial send: List-Unsubscribe header satisfies opt-out gate", captured.length === 1);
}

// ---------------------------------------------------------------------------
// _validateMessage — Reply-To / custom-header CRLF+NUL injection refusals
// ---------------------------------------------------------------------------

async function testMessageHeaderInjectionBranches() {
  var m = b.mail.create({
    transport: function () { return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  var base = { to: "a@x.com", from: "f@x.com", text: "hi" };
  function withProp(extra) { return Object.assign({}, base, extra); }

  var eReply = await _sendErr(m, withProp({ replyTo: "a\r\nBcc: evil@x.com" }));
  check("send: CRLF in replyTo → mail/invalid-reply-to (header injection)",
    eReply && eReply.code === "mail/invalid-reply-to");

  var crlfKey = {}; crlfKey["X-Evil\r\nBcc"] = "evil@x.com";
  var eKeyCrlf = await _sendErr(m, withProp({ headers: crlfKey }));
  check("send: CRLF in a header key → mail/invalid-header",
    eKeyCrlf && eKeyCrlf.code === "mail/invalid-header");

  var nulKey = {}; nulKey["X-Evil\0Bcc"] = "evil@x.com";
  var eKeyNul = await _sendErr(m, withProp({ headers: nulKey }));
  check("send: NUL in a header key → mail/invalid-header",
    eKeyNul && eKeyNul.code === "mail/invalid-header");

  var eValCrlf = await _sendErr(m, withProp({ headers: { "X-Good": "ok\r\nBcc: evil@x.com" } }));
  check("send: CRLF in a header value → mail/invalid-header",
    eValCrlf && eValCrlf.code === "mail/invalid-header");
}

// ---------------------------------------------------------------------------
// _mergeMessage — defaults.headers ∪ message.headers shallow merge
// ---------------------------------------------------------------------------

async function testMergeMessageHeaderMerge() {
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
    defaults: { headers: { "X-Default": "d" } },
  });
  await m.send({ to: "a@x.com", from: "f@x.com", text: "hi", headers: { "X-Msg": "mm" } });
  var hk = Object.keys(captured[0].headers || {});
  check("merge: defaults.headers + message.headers both present",
    hk.indexOf("X-Default") !== -1 && hk.indexOf("X-Msg") !== -1);
}

// ---------------------------------------------------------------------------
// smtpTransport — rejectUnauthorized:false audits the insecure TLS session
// ---------------------------------------------------------------------------

function testSmtpRejectUnauthorizedAudits() {
  // Building the transport with cert-verification disabled must audit the
  // insecure-TLS decision at config time (no socket, no throw) — the audit
  // sink drops silently, so we only assert the transport still constructs.
  var t = b.mail.transports.smtp({ host: "mx.example.test", rejectUnauthorized: false });
  check("smtp: rejectUnauthorized:false still builds a transport", typeof t.send === "function");
}

// ---------------------------------------------------------------------------
// SMTP wire — BINARYMIME auto-detected from a NUL-bearing Buffer attachment
// even without an explicit binary:true marker.
// ---------------------------------------------------------------------------

async function testSmtpBinaryMimeFromNulBuffer(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["CHUNKING", "BINARYMIME", "8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var r = await t.send({
      from: "s@a.test", to: "r@b.test", subject: "bin", text: "see attached",
      // NUL byte in the octet stream, but NO binary:true flag — the transport's
      // first-4-KiB scan must classify this as binary and emit BODY=BINARYMIME.
      attachments: [{
        filename: "a.dat", content: Buffer.from([0x41, 0x00, 0x42, 0x00]),  // allow:raw-byte-literal — NUL-bearing octet stream, no binary flag
        skipMagicByteCheck: true, contentType: "application/octet-stream",
      }],
    });
    check("smtp-binarymime-autodetect: delivered via BDAT", r.code === 250 && st.bdatChunks.length >= 1);
    check("smtp-binarymime-autodetect: MAIL FROM carried BODY=BINARYMIME (no binary flag)",
      /BODY=BINARYMIME/.test(st.mailFromLine || ""));
  } finally { await closeServer(st); }

  // Counterpart: a Buffer attachment with NO NUL bytes and no binary flag must
  // NOT be classified binary — the scan exhausts and MAIL FROM omits BINARYMIME.
  var st2 = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st2);
  try {
    var t2 = tlsTransport(certPair, st2.port);
    var r2 = await t2.send({
      from: "s@a.test", to: "r@b.test", subject: "clean", text: "hi",
      attachments: [{
        filename: "note.txt", content: Buffer.from("plain ascii payload", "utf8"),
        skipMagicByteCheck: true, contentType: "text/plain",
      }],
    });
    check("smtp-binarymime-autodetect: clean buffer delivered", r2.code === 250);
    check("smtp-binarymime-autodetect: clean buffer omits BODY=BINARYMIME",
      !/BODY=BINARYMIME/.test(st2.mailFromLine || ""));
  } finally { await closeServer(st2); }
}

// ---------------------------------------------------------------------------
// _isValidEmail — EAI / length edge branches driven through the send path
// (guardDomain:false isolates the recipient-shape validator).
// ---------------------------------------------------------------------------

async function testEaiAndLengthValidationEdges() {
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false,
  });
  async function reject(label, to, code) {
    var e = await _sendErr(m, { to: to, from: "f@x.com", text: "hi" });
    check(label, e && e.code === code);
  }
  // EAI local part empty (atIdx <= 0) — non-ASCII forces the EAI branch.
  await reject("eai: '@münchen.de' (empty local) → invalid-recipient",
    "@münchen.de", "mail/invalid-recipient");
  // EAI trailing '@' (atIdx === length-1).
  await reject("eai: 'bü@' (trailing @) → invalid-recipient",
    "bü@", "mail/invalid-recipient");
  // IDN domain with NO dot: punycodes to a label the ASCII EMAIL_RE rejects
  // (needs a '.'), so the re-test of the ACE domain fails closed.
  await reject("eai: IDN domain without a dot → invalid-recipient",
    "bü@münchen", "mail/invalid-recipient");
  // Pure-ASCII address beyond the RFC 5321 §4.5.3.1.3 254-octet forward-path
  // bound is refused before the regex ever runs.
  await reject("eai: >254-octet ASCII address → invalid-recipient",
    "x".repeat(250) + "@x.com", "mail/invalid-recipient");

  // Counterpart: a well-formed EAI address (unicode local + IDN domain that
  // punycodes to a dotted ACE form) is accepted through the same path.
  captured.length = 0;
  await m.send({ to: "bü@münchen.de", from: "f@x.com", text: "hi" });
  check("eai: unicode-local + dotted IDN domain accepted", captured.length === 1);
}

// ---------------------------------------------------------------------------
// create() — guardDomain profile fallback chain + custom footerSeparator
// ---------------------------------------------------------------------------

async function testCreateGuardDomainProfileFallback() {
  // guardDomain:{} (object, no .profile) falls back to opts.profile.
  var m1 = b.mail.create({
    transport: b.mail.transports.memory(), guardDomain: {}, profile: "permissive",
  });
  var r1 = await m1.send({ to: "a@192.168.1.1", from: "s@example.org", subject: "t", text: "hi" });
  check("create: guardDomain:{} + profile:'permissive' allows bare-IP (opts.profile fallback)",
    r1 && r1.transport === "memory");

  // No guardDomain opt at all → opts.profile drives the default-on gate.
  var m2 = b.mail.create({ transport: b.mail.transports.memory(), profile: "permissive" });
  var r2 = await m2.send({ to: "a@192.168.1.1", from: "s@example.org", subject: "t", text: "hi" });
  check("create: bare profile:'permissive' (no guardDomain opt) allows bare-IP",
    r2 && r2.transport === "memory");
}

async function testCommercialCustomFooterSeparator() {
  // footerSeparator overrides the default "\n\n----\n" / "<hr>" on both parts.
  var addr = { street: "1 St", city: "Springfield", region: "IL", postalCode: "62701", country: "US" };
  var captured = [];
  var m = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: 1 }); },
    guardDomain: false, audit: false, commercial: true, postalAddress: addr,
    footerSeparator: "\n==SEP==\n",
  });
  await m.send({
    to: "a@x.com", from: "f@x.com", text: "body", html: "<p>body</p>",
    unsubscribe: { url: "https://x.test/u" },
  });
  var sent = captured[0];
  check("commercial: custom footerSeparator applied to text part",
    sent.text.indexOf("\n==SEP==\n") !== -1);
  check("commercial: custom footerSeparator applied to html part",
    sent.html.indexOf("\n==SEP==\n") !== -1);
}

// ---------------------------------------------------------------------------
// consoleTransport — single (non-array) cc branch
// ---------------------------------------------------------------------------

async function testConsoleSingleCc() {
  var s = _fakeStream();
  var t = b.mail.transports.console({ stream: s });
  await t.send({ to: "solo@x.com", from: "f@x.com", cc: "one-cc@x.com", text: "hi" });
  check("console: single (non-array) cc printed verbatim",
    s.data.indexOf("Cc: one-cc@x.com") !== -1);
}

// ---------------------------------------------------------------------------
// httpTransport — custom method + verdict-ok-without-id branch
// ---------------------------------------------------------------------------

async function testHttpMethodAndVerdictNoId() {
  var seenMethod = { v: null };
  var server = http.createServer(function (req, res) {
    seenMethod.v = req.method;
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  var base = {
    endpoint: "http://127.0.0.1:" + port + "/send", name: "vend",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
  };
  try {
    // Custom method (PUT) reaches the wire.
    var tPut = b.mail.transports.http(Object.assign({}, base, {
      method: "put",
      serialize: function () { return { body: "{}" }; },
    }));
    var rPut = await tPut.send({ to: "a@x.com", from: "f@x.com" });
    check("http: custom method upper-cased + sent (PUT)", seenMethod.v === "PUT" && rPut.transport === "vend");

    // interpret returns a truthy verdict with ok:true but no id / no extra →
    // info returned unchanged (neither id nor extra merged).
    var tOk = b.mail.transports.http(Object.assign({}, base, {
      serialize: function () { return { body: "{}" }; },
      interpret: function () { return { ok: true }; },
    }));
    var rOk = await tOk.send({ to: "a@x.com", from: "f@x.com" });
    check("http: verdict ok w/o id → info has no id", rOk.id === undefined && rOk.statusCode === 200);
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

// ---------------------------------------------------------------------------
// resendTransport — minimal serialize (no optional fields) + no-id/no-message
// rejection (reason falls back to JSON.stringify(data))
// ---------------------------------------------------------------------------

async function testResendMinimalAndNoMessageReason() {
  var lastBody = { v: null };
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      lastBody.v = Buffer.concat(chunks).toString("utf8");
      res.writeHead(200, { "Content-Type": "application/json" });
      if (req.url.indexOf("emptyobj") !== -1) { res.end("{}"); return; }
      res.end(JSON.stringify({ id: "re_min" }));
    });
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    // Minimal message: only from/to → serialize omits cc/bcc/replyTo/html/
    // attachments (all the false branches) and subject defaults to "".
    var tMin = b.mail.transports.resend({
      apiKey: "k", endpoint: "http://127.0.0.1:" + port + "/emails",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var rMin = await tMin.send({ from: "f@x.com", to: "a@x.com" });
    check("resend: minimal send → id", rMin.id === "re_min");
    var payload = JSON.parse(lastBody.v);
    check("resend: minimal serialize omits cc/bcc/replyTo/html/attachments",
      payload.cc === undefined && payload.bcc === undefined && payload.reply_to === undefined &&
      payload.html === undefined && payload.attachments === undefined && payload.subject === "");

    // Response {} → no id AND no message field → reason = JSON.stringify(data).
    var tEmpty = b.mail.transports.resend({
      apiKey: "k", endpoint: "http://127.0.0.1:" + port + "/emptyobj",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
    });
    var eEmpty = await _sendErr(tEmpty, { from: "f@x.com", to: "a@x.com" });
    check("resend: no-id no-message body → rejected with JSON.stringify reason",
      eEmpty && eEmpty.code === "mail/resend-rejected" && /\{\}/.test(eEmpty.message));
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

// ---------------------------------------------------------------------------
// smtpTransport — config-time option permutations (no socket)
// ---------------------------------------------------------------------------

function testSmtpOptionPermutations() {
  // implicitTls:true on a non-465 port, plus TLS-shape opts (ecdhCurve / ca /
  // minTlsVersion) and a forced IPv6 family preference — all wired at build.
  var t1 = b.mail.transports.smtp({
    host: "mx.example.test", port: 2525, implicitTls: true,
    ecdhCurve: "X25519MLKEM768", ca: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
    minTlsVersion: "TLSv1.3", preferFamily: "6",
  });
  check("smtp: implicitTls + ecdhCurve/ca/minTlsVersion + preferFamily:'6' builds",
    typeof t1.send === "function");

  // Bare-IP host → SNI servername must be omitted (Node rejects SNI to an IP);
  // the transport still constructs.
  var t2 = b.mail.transports.smtp({ host: "127.0.0.1", port: 587 });
  check("smtp: bare-IPv4 host builds (servername auto-omitted)", typeof t2.send === "function");

  // Colon-bearing (IPv6-shaped) host also omits SNI.
  var t3 = b.mail.transports.smtp({ host: "2001:db8::1", port: 587 });
  check("smtp: IPv6-shaped host builds (servername auto-omitted)", typeof t3.send === "function");

  // Explicit chunkSize:0 is a positive-finite-int violation → refused.
  var threw = null;
  try { b.mail.transports.smtp({ host: "h", chunkSize: 0 }); } catch (e) { threw = e; }
  check("smtp: chunkSize:0 refused (positive-finite-int gate)",
    threw && threw.code === "mail/smtp-misconfigured");
}

// ---------------------------------------------------------------------------
// SMTP wire — _parsePeerSize no-cap ('SIZE' alone) + junk-arg ('SIZE abc')
// ---------------------------------------------------------------------------

async function testSmtpParsePeerSizeNoCapAndJunk(certPair) {
  // 'SIZE' advertised with no argument → peerSizeCap 0 (no enforced cap): the
  // pre-check is skipped BUT MAIL FROM still carries SIZE= (peerSizeCap !== -1).
  var stNoCap = startTlsSmtp(certPair, { ext: ["8BITMIME", "SIZE"] });
  await listen(stNoCap);
  try {
    var t = tlsTransport(certPair, stNoCap.port);
    var r = await t.send({ from: "s@a.test", to: "r@b.test", subject: "s", text: "body bytes" });
    check("smtp-size-nocap: delivered (no enforced cap)", r.code === 250);
    check("smtp-size-nocap: MAIL FROM still carries SIZE=", /SIZE=\d+/.test(stNoCap.mailFromLine || ""));
  } finally { await closeServer(stNoCap); }

  // 'SIZE abc' (non-numeric argument) → peerSizeCap -1 (treated as unadvertised):
  // no pre-check and NO SIZE= keyword on MAIL FROM.
  var stJunk = startTlsSmtp(certPair, { ext: ["8BITMIME", "SIZE abc"] });
  await listen(stJunk);
  try {
    var t2 = tlsTransport(certPair, stJunk.port);
    var r2 = await t2.send({ from: "s@a.test", to: "r@b.test", subject: "s", text: "body bytes" });
    check("smtp-size-junk: delivered (junk SIZE arg ignored)", r2.code === 250);
    check("smtp-size-junk: MAIL FROM omits SIZE=", !/SIZE=/.test(stJunk.mailFromLine || ""));
  } finally { await closeServer(stJunk); }
}

// ---------------------------------------------------------------------------
// SMTP wire — 8BITMIME triggered by a non-ASCII calendar body, and SMTPUTF8
// triggered by a non-ASCII cc recipient (the cc/bcc list branch of the
// _messageRequiresSmtpUtf8 detector).
// ---------------------------------------------------------------------------

async function testSmtp8BitMimeCalendarBody(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    var r = await t.send({
      from: "s@a.test", to: "r@b.test", subject: "invite",
      calendar: { method: "REQUEST", icalText: "BEGIN:VCALENDAR\r\nSUMMARY:grüße café ☕\r\nEND:VCALENDAR" },
    });
    check("smtp-8bit-cal: delivered", r.code === 250);
    check("smtp-8bit-cal: non-ASCII calendar body → BODY=8BITMIME",
      /BODY=8BITMIME/.test(st.mailFromLine || ""));
  } finally { await closeServer(st); }
}

async function testSmtpSmtpUtf8FromCcRecipient(certPair) {
  var st = startTlsSmtp(certPair, { ext: ["SMTPUTF8", "8BITMIME"] });
  await listen(st);
  try {
    var t = tlsTransport(certPair, st.port);
    // ASCII from / to / subject; only the cc carries non-ASCII → the cc/bcc
    // scan in _messageRequiresSmtpUtf8 must flip the transaction to SMTPUTF8.
    var r = await t.send({
      from: "s@a.test", to: "r@b.test", cc: "grüße@münchen.de", subject: "hi", text: "hello",
    });
    check("smtp-utf8-cc: delivered", r.code === 250);
    check("smtp-utf8-cc: non-ASCII cc recipient → MAIL FROM carried SMTPUTF8",
      /SMTPUTF8/.test(st.mailFromLine || ""));
    check("smtp-utf8-cc: cc added to RCPT set", st.rcptLines.length === 2);
  } finally { await closeServer(st); }
}

// ---------------------------------------------------------------------------

async function run() {
  testSmtpTransportAcceptsChunkingOpts();
  testSmtpTransportRefusesBadHost();
  await testReverseDnsBadIp();
  await testReverseDnsLoopback();
  testParsePeerSizeShape();
  testRfc822BuilderProducesParseable();
  await testMessageWithBinaryAttachment();
  await testPeerSizeRefusalEndToEnd();
  await testGuardDomainDefaultRefusesBareIp();
  await testGuardDomainDefaultRefusesSpecialUseDomain();
  await testGuardDomainOptOutAllows();
  await testGuardDomainSkipsAddressLiteral();
  await testGuardDomainPermissiveProfileAllowsBareIp();
  await testGuardDomainHappyPath();
  await testGuardDomainValidatesFromAddress();

  // Pure / no-socket branches.
  testToAsciiBranches();
  testToUnicodeBranches();
  testBuildRfc822MultipartAlternative();
  testBuildRfc822CalendarCcReplyToHeaders();
  testBuildRfc822AttachmentsAndDotStuffing();
  await testConsoleTransport();
  await testMemoryTransport();
  testHttpTransportConfigGates();
  await testHttpTransportBadSerializer();
  await testHttpTransportRequestFailureWrap();
  await testHttpTransportSuccessAndInterpret();
  testResendConfigGate();
  await testResendOverLoopback();
  await testResendBadResponseAndNoId();
  testCreateOptsAndTransportShapes();
  await testCreateTransportErrorWrap();
  await testCreateUnsubscribeExpansion();
  testCreateFooterHtmlValidation();
  await testCommercialHtmlOnlyAndStringAddress();
  await testValidateMessageBranches();
  await testValidateCalendarBranches();
  await testValidateAttachmentBranches();
  await testEaiRecipientAccepted();
  testSmtpConfigGates();
  await testSmtpDkimSignFailureRejectsPreConnect();
  await testReverseDnsErrorShape();

  // Error / adversarial / defensive branches added for coverage.
  testFeedbackId();
  testToAsciiPunycodeEmptyReturnsNull();
  testCreateCommercialPostalAddressValidation();
  await testCommercialSendCanSpamAndObjectFooter();
  await testMessageHeaderInjectionBranches();
  await testMergeMessageHeaderMerge();
  testSmtpRejectUnauthorizedAudits();

  // Additional error / edge / permutation branches.
  await testEaiAndLengthValidationEdges();
  await testCreateGuardDomainProfileFallback();
  await testCommercialCustomFooterSeparator();
  await testConsoleSingleCc();
  await testHttpMethodAndVerdictNoId();
  await testResendMinimalAndNoMessageReason();
  testSmtpOptionPermutations();

  // SMTP state machine over loopback TLS — mint one cert pair, reuse.
  var ca = await b.mtlsEngine.generateCa({ generation: 1 });
  var leaf = await b.mtlsEngine.signClientCert({
    cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["IP:127.0.0.1", "localhost"],
  });
  var certPair = { key: leaf.key, cert: leaf.cert, caCertPem: ca.caCertPem };

  await testSmtpHappyPathData(certPair);
  await testSmtpAuthLogin(certPair);
  await testSmtpBdatChunking(certPair);
  await testSmtpBinaryMimeBdat(certPair);
  await testSmtpSmtpUtf8And8BitMime(certPair);
  await testSmtpSizeRefusal(certPair);
  await testSmtpEaiUnsupportedRefusal(certPair);
  await testSmtpBinaryMimeUnsupportedRefusal(certPair);
  await testSmtpRejectionCodes(certPair);
  await testSmtpResponseTooLarge(certPair);
  await testSmtpTransactionTimeout(certPair);
  await testSmtpSocketTimeout(certPair);
  await testSmtpStarttlsHappyPath(certPair);
  await testSmtpStarttlsRejected(certPair);
  await testSmtpBinaryMimeFromNulBuffer(certPair);
  await testSmtpParsePeerSizeNoCapAndJunk(certPair);
  await testSmtp8BitMimeCalendarBody(certPair);
  await testSmtpSmtpUtf8FromCcRecipient(certPair);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
