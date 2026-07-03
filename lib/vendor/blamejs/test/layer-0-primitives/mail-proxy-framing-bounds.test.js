// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * SMTP client (b.mail.transports.smtp) + proxy CONNECT tunnel
 * (b.network.proxy.agentFor) framing-buffer + wall-clock bounds.
 *
 * Both paths accumulate bytes off a peer socket until a delimiter
 * (CRLF / CRLFCRLF). Without a cap, a peer that streams bytes and never
 * sends the delimiter grows the accumulator without limit (OOM). Without
 * an absolute deadline, a slow-trickle peer resets the per-socket idle
 * timer forever and the operation hangs.
 *
 * These drive the real shipped consumer surface:
 *   - b.mail.transports.smtp(...).send(msg)  against a hostile net.Server
 *   - b.network.proxy.agentFor(url).createConnection(...) against a
 *     hostile CONNECT proxy
 *
 * RED (pre-fix): unbounded `buffer += data` / `Buffer.concat` → the send
 * never settles (the server streams forever); the test times out / OOMs.
 * GREEN (post-fix): the send rejects promptly with a bounded-error code.
 */

var net = require("node:net");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function listen(server) {
  return new Promise(function (resolve, reject) {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", function () {
      resolve(server.address().port);
    });
  });
}

function closeServer(server) {
  return new Promise(function (resolve) {
    try { server.close(function () { resolve(); }); }
    catch (_e) { resolve(); }
  });
}

// ---- (1) SMTP: framing buffer is bounded against a never-CRLF peer ----

async function testSmtpResponseTooLargeBounded() {
  var streamTimer = null;
  // A server that completes the TCP handshake, sends a 220 greeting (so
  // the client moves past connect), then on the first client command
  // streams non-CRLF bytes forever.
  var server = net.createServer(function (sock) {
    // Client destroys mid-blast at the cap; swallow the resulting ECONNRESET.
    sock.on("error", function () { if (streamTimer) { clearInterval(streamTimer); streamTimer = null; } });
    sock.write("220 evil.example ESMTP\r\n");
    sock.on("data", function () {
      // Client just sent EHLO; respond with an unbounded non-CRLF blast.
      var blast = Buffer.alloc(16 * 1024, 0x41); // 16 KiB of 'A', no CRLF
      streamTimer = setInterval(function () {
        if (!sock.writable) { clearInterval(streamTimer); return; }
        try { sock.write(blast); } catch (_e) { clearInterval(streamTimer); }
      }, 1);
    });
  });
  var port = await listen(server);

  var transport = b.mail.transports.smtp({
    host:    "127.0.0.1",
    port:    port,
    timeoutMs: 60000,          // idle timer kept high so it can't mask the cap
  });

  var err = null;
  try {
    await transport.send({
      from: "ops@example.com",
      to:   ["alice@dest.example"],
      subject: "hi",
      text: "body",
    });
  } catch (e) { err = e; }

  if (streamTimer) clearInterval(streamTimer);
  await closeServer(server);

  check("smtp: never-CRLF peer rejects (does not hang/OOM)", err !== null);
  check("smtp: rejects with response-too-large",
    err && typeof err.message === "string" &&
    err.message.indexOf("response-too-large") !== -1);
  check("smtp: error is a MailError", err && err.isMailError === true);
}

// ---- (2) SMTP: absolute transaction deadline fires on a trickle peer ----

async function testSmtpTransactionDeadlineBounded() {
  var trickleTimer = null;
  // A server that greets, then for each command emits a SINGLE
  // continuation byte-pair periodically — never a final response. With a
  // generous idle timeout but a tiny maxTransactionMs the send must still
  // fail on the wall-clock deadline.
  var server = net.createServer(function (sock) {
    // Client destroys at the transaction deadline; swallow the ECONNRESET.
    sock.on("error", function () { if (trickleTimer) { clearInterval(trickleTimer); trickleTimer = null; } });
    sock.write("220 slow.example ESMTP\r\n");
    sock.on("data", function () {
      // Keep the socket "alive" with periodic continuation lines so the
      // idle timer never trips, but never complete the EHLO response.
      if (trickleTimer) return;
      trickleTimer = setInterval(function () {
        if (!sock.writable) { clearInterval(trickleTimer); return; }
        try { sock.write("250-keepalive\r\n"); } catch (_e) { clearInterval(trickleTimer); }
      }, 20);
    });
  });
  var port = await listen(server);

  var transport = b.mail.transports.smtp({
    host:             "127.0.0.1",
    port:             port,
    timeoutMs:        60000,    // idle timer never trips (trickle keeps it warm)
    maxTransactionMs: 300,      // absolute deadline — must fire
  });

  var started = Date.now();
  var err = null;
  try {
    await transport.send({
      from: "ops@example.com",
      to:   ["alice@dest.example"],
      subject: "hi",
      text: "body",
    });
  } catch (e) { err = e; }
  var elapsed = Date.now() - started;

  if (trickleTimer) clearInterval(trickleTimer);
  await closeServer(server);

  check("smtp: trickle peer rejects (does not hang)", err !== null);
  check("smtp: rejects with transaction-timeout",
    err && typeof err.message === "string" &&
    err.message.indexOf("transaction-timeout") !== -1);
  check("smtp: deadline fired near maxTransactionMs (well under idle)", elapsed < 5000);
}

// ---- (3) maxTransactionMs is validated at config time ----

function testMaxTransactionMsValidated() {
  var threw = null;
  try {
    b.mail.transports.smtp({ host: "127.0.0.1", maxTransactionMs: -5 });
  } catch (e) { threw = e; }
  check("smtp: negative maxTransactionMs throws MailError",
    threw && threw.isMailError === true && threw.code === "mail/smtp-misconfigured");
}

// ---- (4) Proxy CONNECT: framing buffer bounded against a never-CRLFCRLF proxy ----

async function testProxyConnectHeadersTooLargeBounded() {
  var streamTimer = null;
  // A fake proxy that accepts the CONNECT, then streams bytes that never
  // contain the CRLFCRLF header terminator.
  var server = net.createServer(function (sock) {
    // Client tears down once the cap trips; swallow the resulting ECONNRESET.
    sock.on("error", function () { if (streamTimer) { clearInterval(streamTimer); streamTimer = null; } });
    sock.on("data", function () {
      if (streamTimer) return;
      var blast = Buffer.alloc(16 * 1024, 0x42); // 16 KiB of 'B', no CRLFCRLF
      streamTimer = setInterval(function () {
        if (!sock.writable) { clearInterval(streamTimer); return; }
        try { sock.write(blast); } catch (_e) { clearInterval(streamTimer); }
      }, 1);
    });
  });
  var port = await listen(server);

  b.network.proxy.set({ http: "http://127.0.0.1:" + port });
  var agent = b.network.proxy.agentFor("http://target.example/");

  var err = null;
  await new Promise(function (resolve) {
    agent.createConnection({ host: "target.example", port: 80 }, function (e, sock) {
      err = e;
      if (sock) { try { sock.destroy(); } catch (_e) { /* ignore */ } }
      resolve();
    });
  });

  if (streamTimer) clearInterval(streamTimer);
  b.network.proxy._resetForTest();
  await closeServer(server);

  check("proxy: never-CRLFCRLF reply rejects (does not hang/OOM)", err !== null);
  check("proxy: rejects with connect-headers-too-large",
    err && err.code === "proxy/connect-headers-too-large");
}

// ---- (5) Proxy CONNECT: ABSOLUTE wall-clock deadline (Codex P2, #362) ----
// A proxy that trickles a byte just inside every idle window but never sends
// CRLFCRLF would reset an idle socket.setTimeout forever and never trip the
// 64 KiB cap. The connect must still fail via an ABSOLUTE deadline. RED when
// the bound is socket.setTimeout (idle): the connect hangs past the deadline.
async function testProxyConnectAbsoluteDeadlineBounded() {
  var trickle = null;
  var server = net.createServer(function (sock) {
    // The client tears the socket down at the deadline; writing to it after
    // emits ECONNRESET on the server side — expected, swallow it so the test
    // process doesn't crash on an unhandled 'error'.
    sock.on("error", function () { if (trickle) { clearInterval(trickle); trickle = null; } });
    sock.on("data", function () {
      if (trickle) return;
      // One byte every 50ms — keeps an idle timer warm, stays far under the
      // 64 KiB header cap, never sends the CRLFCRLF terminator.
      trickle = setInterval(function () {
        if (!sock.writable) { clearInterval(trickle); return; }
        try { sock.write("x"); } catch (_e) { clearInterval(trickle); }
      }, 50);
    });
  });
  var port = await listen(server);

  b.network.proxy._setConnectTimeoutForTest(300);   // small absolute deadline
  b.network.proxy.set({ http: "http://127.0.0.1:" + port });
  var agent = b.network.proxy.agentFor("http://target.example/");

  var started = Date.now();
  var err = null;
  await new Promise(function (resolve) {
    agent.createConnection({ host: "target.example", port: 80 }, function (e, sock) {
      err = e;
      if (sock) { try { sock.destroy(); } catch (_e) { /* ignore */ } }
      resolve();
    });
  });
  var elapsed = Date.now() - started;

  if (trickle) clearInterval(trickle);
  b.network.proxy._resetForTest();
  await closeServer(server);

  check("proxy: trickling CONNECT reply still fails (absolute deadline)", err !== null);
  check("proxy: rejects with connect-timeout", err && err.code === "proxy/connect-timeout");
  check("proxy: bounded by the absolute deadline (~timeout, not held open by trickle)",
    elapsed < 3000);
}

// ---- Run ----

async function run() {
  await testSmtpResponseTooLargeBounded();
  await testSmtpTransactionDeadlineBounded();
  testMaxTransactionMsValidated();
  await testProxyConnectHeadersTooLargeBounded();
  await testProxyConnectAbsoluteDeadlineBounded();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-proxy-framing-bounds] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
