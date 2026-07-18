// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * SVCB / HTTPS RR parsing + DDR / DNR primitive coverage.
 *
 * The DoH / DoT / system-resolver wire round-trips live in the live
 * integration suite (test/integration/network-dns.test.js); this file
 * exercises the pure-parse paths (RFC 9460 §A sample wire formats)
 * and the operator-side DDR / DNR validation surface using fakes so
 * smoke runs offline. It also drives the public b.network.dns surface
 * offline for the config-time throws, malformed-reply and name-decode
 * branches, classifier edge cases, cache / IP-literal lookup paths,
 * and raw-query transport failure branches — using loopback fake TCP
 * responders + closed-port fault injection, never a real external
 * endpoint and never rejectUnauthorized:false.
 */

var net = require("node:net");
var tls = require("node:tls");
var nodeHttps = require("node:https");
var nodeCrypto = require("node:crypto");

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var dnsModule = b.network.dns;

function _resetAll() {
  if (typeof dnsModule._resetForTest === "function") dnsModule._resetForTest();
}

function _throws(fn, expectedCodeSubstr) {
  try { fn(); }
  catch (e) {
    if (!expectedCodeSubstr) return true;
    var hay = (e.code || "") + " " + (e.message || "");
    return hay.indexOf(expectedCodeSubstr) !== -1;
  }
  return false;
}

async function _throwsAsync(fn, expectedCodeSubstr) {
  try { await fn(); return false; }
  catch (e) {
    if (!expectedCodeSubstr) return true;
    var hay = (e.code || "") + " " + (e.message || "");
    return hay.indexOf(expectedCodeSubstr) !== -1;
  }
}

// ---- DNS message construction helpers (test-side) --------------------
// Build a plausible DNS reply for a specific QTYPE so tests can drive
// the full _decodeDnsAnswerRaw → _parseSvcbRdata path without standing
// up a real responder for the parse-correctness checks.

function _encodeQname(name) {
  // root => single 0 byte
  if (name === "" || name === ".") return Buffer.from([0]);
  var parts = name.split(".").filter(Boolean);
  var len = 1;
  for (var i = 0; i < parts.length; i++) len += 1 + parts[i].length;
  var buf = Buffer.alloc(len);
  var off = 0;
  for (var p = 0; p < parts.length; p++) {
    var lab = parts[p];
    buf.writeUInt8(lab.length, off++);
    buf.write(lab, off, "ascii");
    off += lab.length;
  }
  buf.writeUInt8(0, off);
  return buf;
}

function _buildDnsReply(opts) {
  // opts: { qname, qtype, answers: [{ name, type, ttl, rdata }] }
  var qname = _encodeQname(opts.qname);
  var qtypeBuf = Buffer.alloc(4);
  qtypeBuf.writeUInt16BE(opts.qtype, 0);
  qtypeBuf.writeUInt16BE(1, 2); // class IN
  var hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(0xabcd, 0);                                                // id
  hdr.writeUInt16BE(0x8180, 2);                                                // flags: response, RA, NOERROR
  hdr.writeUInt16BE(1, 4);                                                     // QDCOUNT
  hdr.writeUInt16BE(opts.answers.length, 6);                                   // ANCOUNT
  hdr.writeUInt16BE(0, 8);
  hdr.writeUInt16BE(0, 10);
  var parts = [hdr, qname, qtypeBuf];
  for (var a = 0; a < opts.answers.length; a++) {
    var ans = opts.answers[a];
    parts.push(_encodeQname(ans.name || opts.qname));
    var ansHdr = Buffer.alloc(10);
    ansHdr.writeUInt16BE(ans.type, 0);
    ansHdr.writeUInt16BE(1, 2);
    ansHdr.writeUInt32BE(ans.ttl || 60, 4);
    ansHdr.writeUInt16BE(ans.rdata.length, 8);
    parts.push(ansHdr);
    parts.push(ans.rdata);
  }
  return Buffer.concat(parts);
}

function _svcbAliasRdata(target) {
  // RFC 9460 §2.4.2 AliasMode: priority=0, target, no SvcParams.
  var prio = Buffer.alloc(2);
  prio.writeUInt16BE(0, 0);
  return Buffer.concat([prio, _encodeQname(target)]);
}

function _svcbServiceRdata(priority, target, params) {
  // params: [{ key, value (Buffer) }] in ascending key order
  var prio = Buffer.alloc(2);
  prio.writeUInt16BE(priority, 0);
  var pieces = [prio, _encodeQname(target)];
  for (var i = 0; i < params.length; i++) {
    var hdr = Buffer.alloc(4);
    hdr.writeUInt16BE(params[i].key, 0);
    hdr.writeUInt16BE(params[i].value.length, 2);
    pieces.push(hdr);
    pieces.push(params[i].value);
  }
  return Buffer.concat(pieces);
}

function _alpnValueBuf(protos) {
  // alpn SvcParam value: list of length-prefixed char-strings.
  var pieces = [];
  for (var i = 0; i < protos.length; i++) {
    var s = protos[i];
    pieces.push(Buffer.from([s.length]));
    pieces.push(Buffer.from(s, "ascii"));
  }
  return Buffer.concat(pieces);
}

// ---- Standalone TCP fixture servers ----------------------------------
// To exercise the full _systemRawQuery / _dotLookup transport paths we
// stand up a tiny TCP server (and TLS wrapper variant) that speaks the
// 2-byte-length-prefixed DNS framing. The server hands back a
// pre-built reply when a query arrives.

function _startTcpResponder(replyBytes) {
  return new Promise(function (resolve) {
    var srv = net.createServer(function (sock) {
      var got = [];
      var expected = -1;
      sock.on("data", function (chunk) {
        got.push(chunk);
        var all = Buffer.concat(got);
        if (expected === -1 && all.length >= 2) expected = all.readUInt16BE(0);
        if (expected >= 0 && all.length >= expected + 2) {
          var rlen = Buffer.alloc(2);
          rlen.writeUInt16BE(replyBytes.length, 0);
          sock.write(rlen);
          sock.write(replyBytes);
          sock.end();
        }
      });
      sock.on("error", function () { /* fixture best-effort */ });
    });
    srv.unref();
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port });
    });
  });
}

function _genSelfSignedCert() {
  // Deterministic-enough self-signed cert via node:crypto for the DoT
  // fixture. We pin against the leaf via the `ca` option, so the cert
  // chain is just the leaf itself.
  var alg = { type: "ec", namedCurve: "prime256v1" };
  var keys = nodeCrypto.generateKeyPairSync(alg.type, { namedCurve: alg.namedCurve });
  // Fall back if X509 self-sign isn't available; tests using this
  // helper guard against that by checking for the cert before use.
  if (typeof nodeCrypto.X509Certificate !== "function") return null;
  // Generate via spawn of node's built-in --tls-min-v1.3 self-signed?
  // No — we use selfsigned-via-ec.js stub: build a cert object using
  // tls.createSecureContext on raw key pair won't accept a non-cert.
  // Easiest: skip TLS handshake test if we can't generate a cert.
  return { key: keys.privateKey, cert: null };
}

function _startTlsResponder(replyBytes, keyPem, certPem) {
  return new Promise(function (resolve, reject) {
    var srv = tls.createServer({
      key:        keyPem,
      cert:       certPem,
      minVersion: "TLSv1.2",
    }, function (sock) {
      var got = [];
      var expected = -1;
      sock.on("data", function (chunk) {
        got.push(chunk);
        var all = Buffer.concat(got);
        if (expected === -1 && all.length >= 2) expected = all.readUInt16BE(0);
        if (expected >= 0 && all.length >= expected + 2) {
          var rlen = Buffer.alloc(2);
          rlen.writeUInt16BE(replyBytes.length, 0);
          sock.write(rlen);
          sock.write(replyBytes);
          sock.end();
        }
      });
      sock.on("error", function () { /* fixture best-effort */ });
    });
    srv.on("error", reject);
    srv.unref();
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port });
    });
  });
}

// The DNS primitive's system-resolver TCP query (and DoT pool sockets)
// open client sockets; _resetForTest() destroys them, but socket.destroy()
// finalizes the underlying handle asynchronously — past the forked worker's
// post-run grace window. Reset, then poll until the TCP client handle has
// actually closed so it doesn't outlive run() and hold the event loop open.
async function _drainTcpHandles() {
  _resetAll();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "network-dns: TCP handle drain after _resetForTest" });
}

// DnsError carries a terminal-vs-transient signal on err.permanent so a caller
// driving a retry loop re-attempts only the failures a retry can fix. Fails
// CLOSED: network / resolver-availability failures are transient; bad config,
// malformed input, NXDOMAIN-style no-result, and any unknown code are permanent.
function testDnsErrorPermanentClassification() {
  var DnsError = dnsModule.DnsError;
  check("DnsError exported", typeof DnsError === "function");
  // Permanent — config / input / no-answer (retrying cannot fix these).
  check("DnsError dns/bad-host is permanent",        new DnsError("dns/bad-host", "x").permanent === true);
  check("DnsError dns/bad-transport is permanent",   new DnsError("dns/bad-transport", "x").permanent === true);
  check("DnsError dns/unsupported-type is permanent", new DnsError("dns/unsupported-type", "x").permanent === true);
  check("DnsError dns/no-result is permanent",       new DnsError("dns/no-result", "x").permanent === true);
  check("DnsError unknown code is permanent (fail closed)", new DnsError("dns/never-defined", "x").permanent === true);
  // Caller-shape / environment config errors raised before any network work are
  // permanent — a retry cannot make absent config or invalid input valid.
  check("DnsError dns/transport-unavailable is permanent (transport not configured)",
        new DnsError("dns/transport-unavailable", "x").permanent === true);
  check("DnsError dns/dnr-no-resolvers is permanent (empty/invalid resolver list)",
        new DnsError("dns/dnr-no-resolvers", "x").permanent === true);
  check("DnsError dns/setservers-failed is permanent (invalid resolver address)",
        new DnsError("dns/setservers-failed", "x").permanent === true);
  check("DnsError dns/no-system-resolvers is permanent (none configured)",
        new DnsError("dns/no-system-resolvers", "x").permanent === true);
  // Transient — a network round-trip that a retry can plausibly fix.
  check("DnsError dns/lookup-timeout is transient",  new DnsError("dns/lookup-timeout", "x").permanent === false);
  check("DnsError dns/resolve-failed is transient",  new DnsError("dns/resolve-failed", "x").permanent === false);
  check("DnsError dns/dot-failed is transient",      new DnsError("dns/dot-failed", "x").permanent === false);
}

// ---- Compact DNS wire-format builders (test-side) --------------------
// Terser siblings of the builders above, used by the error-branch and
// fault-injection tests; _buildReply additionally takes a flags word so
// tests can force non-NOERROR rcodes (SERVFAIL / NXDOMAIN).
function _qname(name) {
  if (name === "" || name === ".") return Buffer.from([0]);
  var parts = name.split(".").filter(Boolean);
  var len = 1;
  for (var i = 0; i < parts.length; i++) len += 1 + parts[i].length;
  var buf = Buffer.alloc(len);
  var off = 0;
  for (var p = 0; p < parts.length; p++) {
    var lab = parts[p];
    buf.writeUInt8(lab.length, off++);
    buf.write(lab, off, "ascii");
    off += lab.length;
  }
  buf.writeUInt8(0, off);
  return buf;
}

function _buildReply(qname, qtype, answers, flags) {
  var qn = _qname(qname);
  var qtail = Buffer.alloc(4);
  qtail.writeUInt16BE(qtype, 0);
  qtail.writeUInt16BE(1, 2);
  var hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(0xabcd, 0);
  hdr.writeUInt16BE(flags === undefined ? 0x8180 : flags, 2);
  hdr.writeUInt16BE(1, 4);
  hdr.writeUInt16BE(answers.length, 6);
  var parts = [hdr, qn, qtail];
  for (var a = 0; a < answers.length; a++) {
    var ans = answers[a];
    parts.push(_qname(ans.name || qname));
    var ah = Buffer.alloc(10);
    ah.writeUInt16BE(ans.type, 0);
    ah.writeUInt16BE(1, 2);
    ah.writeUInt32BE(ans.ttl || 60, 4);
    ah.writeUInt16BE(ans.rdata.length, 8);
    parts.push(ah, ans.rdata);
  }
  return Buffer.concat(parts);
}

function _svcbRd(priority, target, params) {
  var prio = Buffer.alloc(2);
  prio.writeUInt16BE(priority, 0);
  var pieces = [prio, _qname(target)];
  for (var i = 0; i < params.length; i++) {
    var h = Buffer.alloc(4);
    h.writeUInt16BE(params[i].key, 0);
    h.writeUInt16BE(params[i].value.length, 2);
    pieces.push(h, params[i].value);
  }
  return Buffer.concat(pieces);
}

function _alpn(protos) {
  var pieces = [];
  for (var i = 0; i < protos.length; i++) {
    pieces.push(Buffer.from([protos[i].length]));
    pieces.push(Buffer.from(protos[i], "ascii"));
  }
  return Buffer.concat(pieces);
}

// ---- fault-injection loopback fixtures --------------------------------
// Accepts the TCP connection then immediately tears it down — models an
// upstream that closes before sending any reply.
function _startCloseImmediately() {
  return new Promise(function (resolve) {
    var srv = net.createServer(function (sock) {
      sock.on("error", function () { /* fixture best-effort */ });
      sock.destroy();
    });
    srv.unref();
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port });
    });
  });
}

// A 127.0.0.1 port with nothing listening (bind → capture → close).
function _probeClosedPort() {
  return new Promise(function (resolve) {
    var s = net.createServer();
    s.unref();
    s.listen(0, "127.0.0.1", function () {
      var p = s.address().port;
      s.close(function () { resolve(p); });
    });
  });
}

// Track a server's live raw TCP sockets so teardown can force-close them.
// A plain srv.close() only stops accepting — stalled fixtures (hang mode)
// hold sockets open, which would otherwise outlive run() and trip the TCP
// handle-drain guard. `.close()` destroys every live connection first.
function _trackAndClosable(srv) {
  var conns = new Set();
  srv.on("connection", function (sock) {
    conns.add(sock);
    sock.on("close", function () { conns.delete(sock); });
  });
  return function close() {
    conns.forEach(function (sock) {
      try { sock.destroy(); } catch (_e) { /* best-effort */ }
    });
    try { srv.close(); } catch (_e) { /* best-effort */ }
  };
}

// A loopback TCP responder that reads the framed query then cleanly
// half-closes (FIN) WITHOUT sending a reply — models an upstream that
// hangs up mid-exchange, driving the system-transport close-before-reply
// branch (distinct from an abrupt RST, which surfaces as 'error').
function _startTcpFinNoReply() {
  return new Promise(function (resolve) {
    var srv = net.createServer(function (sock) {
      sock.on("error", function () { /* fixture best-effort */ });
      sock.on("data", function () { sock.end(); });   // FIN after the query, no reply
    });
    srv.unref();
    var close = _trackAndClosable(srv);
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port, close: close });
    });
  });
}

// A loopback TCP responder that accepts the connection, consumes the
// framed query, and NEVER replies — models an upstream that stalls after
// accept so the wall-clock deadline (sock.setTimeout) has to tear it down.
function _startTcpHang() {
  return new Promise(function (resolve) {
    var srv = net.createServer(function (sock) {
      sock.on("data", function () { /* consume, never reply */ });
      sock.on("error", function () { /* fixture best-effort */ });
    });
    srv.unref();
    var close = _trackAndClosable(srv);
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port, close: close });
    });
  });
}

// ---- Real-handshake DoT / DoH fixtures --------------------------------
// The framework's DoT/DoH clients pin minVersion TLSv1.3 + the hybrid-PQC
// group list + a caller-supplied `ca`, and validate the server identity.
// We mint a server leaf through the framework's own mtls engine (SAN
// IP:127.0.0.1 + DNS:localhost) so a genuine TLS 1.3 handshake completes
// against a loopback listener with NO rejectUnauthorized:false anywhere.
// The cert keygen is the expensive part, so mint once and cache.
var _secureCertCache = null;
async function _mintSecureCert() {
  if (_secureCertCache) return _secureCertCache;
  var ca = await b.mtlsEngine.generateCa({ generation: 1 });
  var leaf = await b.mtlsEngine.signClientCert({
    cn:         "localhost",
    caCertPem:  ca.caCertPem,
    caKeyPem:   ca.caKeyPem,
    usage:      "server",
    sans:       ["IP:127.0.0.1", "DNS:localhost"],
  });
  _secureCertCache = { caPem: ca.caCertPem, keyPem: leaf.key, certPem: leaf.cert };
  return _secureCertCache;
}

// DoT (DNS-over-TLS) loopback responder. Speaks the 2-byte-length-prefixed
// TCP DNS framing over TLS 1.3. opts.hang completes the handshake then
// stalls; otherwise it replies once with opts.reply and half-closes.
function _startDotServer(cert, opts) {
  opts = opts || {};
  return new Promise(function (resolve) {
    var srv = tls.createServer({
      key:        cert.keyPem,
      cert:       cert.certPem,
      minVersion: "TLSv1.3",
    }, function (sock) {
      sock.on("error", function () { /* fixture best-effort */ });
      if (opts.hang) return;
      var got = [];
      var expected = -1;
      sock.on("data", function (chunk) {
        got.push(chunk);
        var all = Buffer.concat(got);
        if (expected === -1 && all.length >= 2) expected = all.readUInt16BE(0);
        if (expected >= 0 && all.length >= expected + 2) {
          var rlen = Buffer.alloc(2);
          rlen.writeUInt16BE(opts.reply.length, 0);
          sock.write(rlen);
          sock.write(opts.reply);
          sock.end();
        }
      });
    });
    srv.on("error", function () { /* fixture best-effort */ });
    srv.unref();
    var close = _trackAndClosable(srv);
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port, close: close });
    });
  });
}

// DoH (DNS-over-HTTPS) loopback responder. Drains the request (GET query
// string or POST body) then answers with opts.reply under
// application/dns-message + opts.status (default 200). opts.hang receives
// the request and never responds so the per-request deadline fires.
function _startDohServer(cert, opts) {
  opts = opts || {};
  return new Promise(function (resolve) {
    var srv = nodeHttps.createServer({
      key:        cert.keyPem,
      cert:       cert.certPem,
      minVersion: "TLSv1.3",
    }, function (req, res) {
      req.on("error", function () { /* fixture best-effort */ });
      req.on("data", function () { /* drain POST body */ });
      req.on("end", function () {
        if (opts.hang) return;
        res.writeHead(opts.status || 200, { "content-type": "application/dns-message" });
        res.end(opts.reply || Buffer.alloc(0));
      });
    });
    srv.on("error", function () { /* fixture best-effort */ });
    srv.unref();
    var close = _trackAndClosable(srv);
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port, close: close });
    });
  });
}

// A record rdata (4 octets) + AAAA rdata (16 octets) builders for the
// transport round-trip fixtures.
function _aRdata(a, b2, c, d) { return Buffer.from([a, b2, c, d]); }
function _aaaaRdata() {
  var v6 = Buffer.alloc(16);
  v6[0] = 0x20; v6[1] = 0x01; v6[2] = 0x0d; v6[3] = 0xb8; v6[15] = 0x01;   // 2001:db8::1
  return v6;
}

// A reply whose single answer's owner name is a compression pointer
// (0xc0 0x0c → offset 12, the question name) instead of a fully-written
// name — the wire shape that exercises the name-compression branch of
// _skipDnsName that a literal owner name never reaches.
function _buildReplyCompressedName(qname, qtype, ansType, rdata, flags) {
  var qn = _qname(qname);
  var qtail = Buffer.alloc(4);
  qtail.writeUInt16BE(qtype, 0);
  qtail.writeUInt16BE(1, 2);
  var hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(0xabcd, 0);
  hdr.writeUInt16BE(flags === undefined ? 0x8180 : flags, 2);
  hdr.writeUInt16BE(1, 4);
  hdr.writeUInt16BE(1, 6);
  var ptr = Buffer.from([0xc0, 0x0c]);                                     // pointer → question name at offset 12
  var ah = Buffer.alloc(10);
  ah.writeUInt16BE(ansType, 0);
  ah.writeUInt16BE(1, 2);
  ah.writeUInt32BE(60, 4);
  ah.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([hdr, qn, qtail, ptr, ah, rdata]);
}

function _reset() {
  if (typeof dnsModule._resetForTest === "function") dnsModule._resetForTest();
}

// ======================================================================
// Config setters — throw-on-bad-input + success branches
// ======================================================================
function testSetServers() {
  _reset();
  check("setServers: non-array throws dns/bad-servers",
    _throws(function () { dnsModule.setServers(null); }, "dns/bad-servers"));
  check("setServers: empty array throws dns/bad-servers",
    _throws(function () { dnsModule.setServers([]); }, "dns/bad-servers"));
  check("setServers: non-string element throws dns/bad-server",
    _throws(function () { dnsModule.setServers(["1.2.3.4", 123]); }, "dns/bad-server"));
  check("setServers: empty-string element throws dns/bad-server",
    _throws(function () { dnsModule.setServers(["1.2.3.4", ""]); }, "dns/bad-server"));
  check("setServers: invalid resolver address throws dns/setservers-failed",
    _throws(function () { dnsModule.setServers(["not-an-ip-at-all"]); }, "dns/setservers-failed"));

  _reset();
  dnsModule.setServers(["127.0.0.1", "9.9.9.9"]);
  var got = dnsModule.getServers();
  check("setServers: valid list persists + getServers returns a copy",
    Array.isArray(got) && got.indexOf("127.0.0.1") !== -1 && got.indexOf("9.9.9.9") !== -1);
  got.push("mutation");
  check("getServers: returns a defensive copy (mutation does not leak)",
    dnsModule.getServers().indexOf("mutation") === -1);
  _reset();
  check("getServers: falls back to OS resolvers (array) when unset",
    Array.isArray(dnsModule.getServers()));
}

function testSetResultOrder() {
  _reset();
  check("setResultOrder: bad value throws dns/bad-result-order",
    _throws(function () { dnsModule.setResultOrder("random"); }, "dns/bad-result-order"));
  dnsModule.setResultOrder("ipv4first");
  check("setResultOrder: ipv4first stored", dnsModule._stateForTest().resultOrder === "ipv4first");
  dnsModule.setResultOrder("verbatim");
  check("setResultOrder: verbatim stored", dnsModule._stateForTest().resultOrder === "verbatim");
  dnsModule.setResultOrder("ipv6first");
  check("setResultOrder: ipv6first stored (mapped to verbatim in node)",
    dnsModule._stateForTest().resultOrder === "ipv6first");
  _reset();
}

function testSetFamily() {
  _reset();
  check("setFamily: bad value throws dns/bad-family",
    _throws(function () { dnsModule.setFamily(5); }, "dns/bad-family"));
  dnsModule.setFamily(0);
  check("setFamily: 0 accepted", dnsModule._stateForTest().family === 0);
  dnsModule.setFamily(4);
  check("setFamily: 4 accepted", dnsModule._stateForTest().family === 4);
  dnsModule.setFamily(6);
  check("setFamily: 6 accepted", dnsModule._stateForTest().family === 6);
  _reset();
}

function testSetLookupTimeout() {
  _reset();
  check("setLookupTimeoutMs: non-number throws dns/bad-timeout",
    _throws(function () { dnsModule.setLookupTimeoutMs("5s"); }, "dns/bad-timeout"));
  check("setLookupTimeoutMs: NaN throws dns/bad-timeout",
    _throws(function () { dnsModule.setLookupTimeoutMs(NaN); }, "dns/bad-timeout"));
  check("setLookupTimeoutMs: Infinity throws dns/bad-timeout",
    _throws(function () { dnsModule.setLookupTimeoutMs(Infinity); }, "dns/bad-timeout"));
  check("setLookupTimeoutMs: negative throws dns/bad-timeout",
    _throws(function () { dnsModule.setLookupTimeoutMs(-1); }, "dns/bad-timeout"));
  dnsModule.setLookupTimeoutMs(1234);
  check("setLookupTimeoutMs: valid value stored", dnsModule._stateForTest().lookupTimeoutMs === 1234);
  _reset();
}

function testSetCacheTtl() {
  _reset();
  check("setCacheTtlMs: non-number throws dns/bad-cache-ttl",
    _throws(function () { dnsModule.setCacheTtlMs("nope"); }, "dns/bad-cache-ttl"));
  check("setCacheTtlMs: negative throws dns/bad-cache-ttl",
    _throws(function () { dnsModule.setCacheTtlMs(-5); }, "dns/bad-cache-ttl"));
  check("setCacheTtlMs: bad negativeMs throws dns/bad-cache-ttl",
    _throws(function () { dnsModule.setCacheTtlMs(1000, -1); }, "dns/bad-cache-ttl"));
  dnsModule.setCacheTtlMs(5000, 2500);
  check("setCacheTtlMs: positive ms + negativeMs stored",
    dnsModule._stateForTest().cacheTtlMs === 5000 &&
    dnsModule._stateForTest().cacheNegativeTtlMs === 2500);
  dnsModule.setCacheTtlMs(0);
  check("setCacheTtlMs: 0 disables + clears (cacheTtlMs=0)",
    dnsModule._stateForTest().cacheTtlMs === 0);
  _reset();
}

function testUseDnsOverHttps() {
  _reset();
  dnsModule.useDnsOverHttps({ provider: "cloudflare" });
  check("useDnsOverHttps: provider=cloudflare resolves url",
    dnsModule._stateForTest().doh.url.indexOf("cloudflare-dns.com") !== -1);
  _reset();
  dnsModule.useDnsOverHttps({ provider: "google" });
  check("useDnsOverHttps: provider=google resolves url",
    dnsModule._stateForTest().doh.url.indexOf("dns.google") !== -1);
  _reset();
  dnsModule.useDnsOverHttps({ provider: "quad9" });
  check("useDnsOverHttps: provider=quad9 resolves url",
    dnsModule._stateForTest().doh.url.indexOf("quad9") !== -1);
  _reset();
  check("useDnsOverHttps: unknown provider throws dns/bad-doh-provider",
    _throws(function () { dnsModule.useDnsOverHttps({ provider: "myisp" }); }, "dns/bad-doh-provider"));
  check("useDnsOverHttps: non-https url throws dns/bad-doh-url",
    _throws(function () { dnsModule.useDnsOverHttps({ url: "http://insecure/dns" }); }, "dns/bad-doh-url"));
  check("useDnsOverHttps: bad method throws dns/bad-doh-method",
    _throws(function () { dnsModule.useDnsOverHttps({ url: "https://x/dns", method: "PUT" }); }, "dns/bad-doh-method"));
  check("useDnsOverHttps: bad ca type throws dns/bad-doh-ca",
    _throws(function () { dnsModule.useDnsOverHttps({ url: "https://x/dns", ca: 123 }); }, "dns/bad-doh-ca"));
  check("useDnsOverHttps: unknown opt key throws (validate-opts)",
    _throws(function () { dnsModule.useDnsOverHttps({ url: "https://x/dns", bogus: 1 }); }));
  _reset();
  dnsModule.useDnsOverHttps({ url: "https://doh.example/dns-query", method: "POST" });
  check("useDnsOverHttps: explicit url+method configured",
    dnsModule._stateForTest().doh.url === "https://doh.example/dns-query" &&
    dnsModule._stateForTest().doh.method === "POST");
  _reset();
}

function testUseDnsOverTls() {
  _reset();
  check("useDnsOverTls: missing host throws dns/bad-dot-host",
    _throws(function () { dnsModule.useDnsOverTls({ port: 853 }); }, "dns/bad-dot-host"));
  check("useDnsOverTls: bad port throws dns/bad-dot-port",
    _throws(function () { dnsModule.useDnsOverTls({ host: "1.1.1.1", port: -5 }); }, "dns/bad-dot-port"));
  check("useDnsOverTls: bad ca type throws dns/bad-dot-ca",
    _throws(function () { dnsModule.useDnsOverTls({ host: "1.1.1.1", ca: 42 }); }, "dns/bad-dot-ca"));
  check("useDnsOverTls: unknown opt key throws (validate-opts)",
    _throws(function () { dnsModule.useDnsOverTls({ host: "1.1.1.1", nope: 1 }); }));
  _reset();
  dnsModule.useDnsOverTls({ host: "1.1.1.1" });
  var st = dnsModule._stateForTest();
  check("useDnsOverTls: defaults port 853 + servername=host",
    st.dot.host === "1.1.1.1" && st.dot.port === 853 && st.dot.servername === "1.1.1.1");
  _reset();
}

function testUseSystemResolver() {
  _reset();
  dnsModule.useDnsOverHttps({ url: "https://x/dns" });
  dnsModule.useSystemResolver();
  var st = dnsModule._stateForTest();
  check("useSystemResolver: clears doh/dot + sets systemResolver",
    st.doh === null && st.dot === null && st.systemResolver === true);
  _reset();
}

// ======================================================================
// Classifiers — pure, never throw
// ======================================================================
function testIsNullMx() {
  check("isNullMx: non-array is false", dnsModule.isNullMx(null) === false);
  check("isNullMx: empty array is false", dnsModule.isNullMx([]) === false);
  check("isNullMx: two records is false",
    dnsModule.isNullMx([{ priority: 0, exchange: "." }, { priority: 1, exchange: "mx" }]) === false);
  check("isNullMx: non-object element is false", dnsModule.isNullMx([null]) === false);
  check("isNullMx: non-zero priority is false",
    dnsModule.isNullMx([{ priority: 10, exchange: "." }]) === false);
  check("isNullMx: priority 0 + exchange '' is null-mx (node shape)",
    dnsModule.isNullMx([{ priority: 0, exchange: "" }]) === true);
  check("isNullMx: priority 0 + exchange '.' is null-mx (literal root)",
    dnsModule.isNullMx([{ priority: 0, exchange: "." }]) === true);
  check("isNullMx: real exchange is not null-mx",
    dnsModule.isNullMx([{ priority: 0, exchange: "mail.example.com" }]) === false);
}

function testClassifyDnskeyAlgorithm() {
  check("classifyDnskeyAlgorithm: non-integer returns null",
    dnsModule.classifyDnskeyAlgorithm(1.5) === null);
  check("classifyDnskeyAlgorithm: string returns null",
    dnsModule.classifyDnskeyAlgorithm("13") === null);
  check("classifyDnskeyAlgorithm: NaN returns null",
    dnsModule.classifyDnskeyAlgorithm(NaN) === null);
  var sha1 = dnsModule.classifyDnskeyAlgorithm(5);
  check("classifyDnskeyAlgorithm: 5 RSASHA1 deprecated+known",
    sha1 && sha1.deprecated === true && sha1.known === true && sha1.name === "RSASHA1");
  var ec = dnsModule.classifyDnskeyAlgorithm(13);
  check("classifyDnskeyAlgorithm: 13 ECDSAP256SHA256 current",
    ec && ec.deprecated === false && ec.known === true);
  var reserved = dnsModule.classifyDnskeyAlgorithm(4);
  check("classifyDnskeyAlgorithm: 4 Reserved is deprecated+known",
    reserved && reserved.deprecated === true && reserved.known === true);
  var unassigned = dnsModule.classifyDnskeyAlgorithm(17);
  check("classifyDnskeyAlgorithm: 17 unassigned → known:false",
    unassigned && unassigned.known === false && unassigned.deprecated === false);
  var priv = dnsModule.classifyDnskeyAlgorithm(253);
  check("classifyDnskeyAlgorithm: 253 PRIVATEDNS known+not-deprecated",
    priv && priv.known === true && priv.deprecated === false);
}

function testClassifyDsDigestType() {
  check("classifyDsDigestType: non-integer returns null",
    dnsModule.classifyDsDigestType(2.2) === null);
  var sha1 = dnsModule.classifyDsDigestType(1);
  check("classifyDsDigestType: 1 SHA-1 deprecated+known",
    sha1 && sha1.deprecated === true && sha1.known === true);
  var sha256 = dnsModule.classifyDsDigestType(2);
  check("classifyDsDigestType: 2 SHA-256 current",
    sha256 && sha256.deprecated === false && sha256.known === true);
  var reserved = dnsModule.classifyDsDigestType(0);
  check("classifyDsDigestType: 0 Reserved deprecated+known",
    reserved && reserved.deprecated === true && reserved.known === true);
  var unassigned = dnsModule.classifyDsDigestType(7);
  check("classifyDsDigestType: 7 unassigned → known:false",
    unassigned && unassigned.known === false);
}

// ======================================================================
// SVCB rdata parse — malformed + valid variants (direct call)
// ======================================================================
function _parseAt0(rd) { return dnsModule._parseSvcbRdata(rd, 0, rd.length); }

function testParseSvcbMalformed() {
  var parse = dnsModule._parseSvcbRdata;
  check("parseSvcb: rdlen < 2 throws (truncated before priority)",
    _throws(function () { parse(Buffer.alloc(4), 0, 1); }, "dns/svcb-malformed"));

  // priority(2) + root name(0x00) + 3 dangling bytes → SvcParam header truncated
  var hdrTrunc = Buffer.concat([Buffer.from([0, 1]), Buffer.from([0]), Buffer.from([0, 0, 0])]);
  check("parseSvcb: dangling SvcParam header throws (header truncated)",
    _throws(function () { return _parseAt0(hdrTrunc); }, "dns/svcb-malformed"));

  // key present but paramLen overflows rdata
  var overflow = Buffer.concat([Buffer.from([0, 1]), Buffer.from([0]),
    Buffer.from([0, 1]), Buffer.from([0, 5])]);
  check("parseSvcb: SvcParam value overflow throws",
    _throws(function () { return _parseAt0(overflow); }, "dns/svcb-malformed"));

  check("parseSvcb: mandatory odd length throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 0, value: Buffer.from([0]) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: no-default-alpn with non-zero length throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 2, value: Buffer.from([0]) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: port wrong length throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 3, value: Buffer.from([1]) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: ipv4hint length not multiple of 4 throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 4, value: Buffer.from([1, 2, 3]) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: ipv6hint length not multiple of 16 throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 6, value: Buffer.alloc(15) }]));
    }, "dns/svcb-malformed"));
  check("parseSvcb: alpn char-string overflow throws",
    _throws(function () {
      return _parseAt0(_svcbRd(1, ".", [{ key: 1, value: Buffer.from([5]) }]));
    }, "dns/svcb-malformed"));
}

function testParseSvcbValidVariants() {
  // no-default-alpn (key 2, zero length) → noDefaultAlpn true
  var ndAlpn = _parseAt0(_svcbRd(1, "svc.example.net", [{ key: 2, value: Buffer.alloc(0) }]));
  check("parseSvcb: no-default-alpn (zero length) → noDefaultAlpn true",
    ndAlpn.params.noDefaultAlpn === true);

  // AliasMode with root target "." → target "."
  var rootAlias = _parseAt0(Buffer.concat([Buffer.from([0, 0]), _qname(".")]));
  check("parseSvcb: root target renders as '.'",
    rootAlias.priority === 0 && rootAlias.target === ".");

  // dohpath (key 7) utf8
  var dp = _parseAt0(_svcbRd(2, "svc.example.net",
    [{ key: 7, value: Buffer.from("/dns-query{?dns}", "utf8") }]));
  check("parseSvcb: dohpath decodes utf8", dp.params.dohpath === "/dns-query{?dns}");

  // ech (key 5) opaque buffer
  var ech = _parseAt0(_svcbRd(3, "svc.example.net",
    [{ key: 5, value: Buffer.from([0xfe, 0x0d, 0x00]) }]));
  check("parseSvcb: ech surfaced as opaque buffer",
    Buffer.isBuffer(ech.params.ech) && ech.params.ech.length === 3);
}

// ======================================================================
// _decodeDnsAnswerRaw — adversarial reply framing (direct call)
// ======================================================================
function testDecodeAnswerRaw() {
  var dec = dnsModule._decodeDnsAnswerRaw;
  check("_decodeDnsAnswerRaw: non-buffer throws dns/bad-reply",
    _throws(function () { dec("notabuffer"); }, "dns/bad-reply"));
  check("_decodeDnsAnswerRaw: <12 bytes throws dns/bad-reply",
    _throws(function () { dec(Buffer.alloc(6)); }, "dns/bad-reply"));

  // rcode != 0 (SERVFAIL=2) → dns/no-result
  var servfail = Buffer.alloc(12);
  servfail.writeUInt8(0x02, 3);
  check("_decodeDnsAnswerRaw: non-zero rcode throws dns/no-result",
    _throws(function () { dec(servfail); }, "dns/no-result"));

  // ancount claims 1 but no answer bytes follow the question → record truncated
  var recTrunc = _buildReply("example.com", 1, []);
  recTrunc.writeUInt16BE(1, 6); // lie: ancount = 1
  check("_decodeDnsAnswerRaw: answer record header truncated throws dns/bad-reply",
    _throws(function () { dec(recTrunc); }, "dns/bad-reply"));

  // valid A answer but rdlen lies past buffer end → rdata truncated
  var okReply = _buildReply("example.com", 1,
    [{ name: "example.com", type: 1, rdata: Buffer.from([1, 2, 3, 4]) }]);
  // bump the last answer's rdlen (offset = length-2-4) to overflow
  okReply.writeUInt16BE(0x00ff, okReply.length - 6);
  check("_decodeDnsAnswerRaw: answer rdata truncated throws dns/bad-reply",
    _throws(function () { dec(okReply); }, "dns/bad-reply"));

  // clean decode of a well-formed reply
  var clean = dec(_buildReply("example.com", 1,
    [{ name: "example.com", type: 1, rdata: Buffer.from([9, 9, 9, 9]) }]));
  check("_decodeDnsAnswerRaw: well-formed reply yields one answer + ad=false",
    clean.answers.length === 1 && clean.ad === false);
}

// ======================================================================
// _readDnsName — pointer + termination adversarial branches (direct call)
// ======================================================================
function testReadDnsName() {
  var rd = dnsModule._readDnsName;

  // compression pointer as the very last byte → truncated at pointer
  var ptrTrunc = Buffer.from([0xc0]);
  check("_readDnsName: pointer truncated at last byte throws",
    _throws(function () { rd(ptrTrunc, 0); }, "dns/svcb-malformed"));

  // pointer target beyond buffer length → out of bounds
  var ptrOob = Buffer.from([0xc0, 0x40]); // points to offset 64, buf len 2
  check("_readDnsName: pointer out of bounds throws",
    _throws(function () { rd(ptrOob, 0); }, "dns/svcb-malformed"));

  // labels with no terminating 0 and no pointer → not terminated
  var noTerm = Buffer.from([3, 0x61, 0x62, 0x63]); // "abc" then EOF
  check("_readDnsName: unterminated name throws",
    _throws(function () { rd(noTerm, 0); }, "dns/svcb-malformed"));

  // valid: two labels then root
  var ok = Buffer.concat([_qname("a.bc")]);
  var res = rd(ok, 0);
  check("_readDnsName: valid name decodes labels + nextOff",
    res.name === "a.bc" && res.nextOff === ok.length);

  // valid forward compression pointer: name at 0 = "x" + pointer to a
  // root label sitting later in the buffer.
  var buf = Buffer.alloc(8);
  buf[0] = 1; buf[1] = 0x78;          // label "x"
  buf[2] = 0xc0; buf[3] = 0x05;       // pointer to offset 5
  buf[5] = 0;                         // root at offset 5
  var pres = rd(buf, 0);
  check("_readDnsName: forward pointer resolves + nextOff after pointer",
    pres.name === "x" && pres.nextOff === 4);
}

// ======================================================================
// lookup — IP literal short-circuit + cache + local-form system path
// ======================================================================
async function testLookupIpLiteral() {
  _reset();
  var v4 = await dnsModule.lookup("203.0.113.7");
  check("lookup: IPv4 literal returns {address,family:4} without resolution",
    v4.address === "203.0.113.7" && v4.family === 4);
  var v4all = await dnsModule.lookup("203.0.113.7", { all: true });
  check("lookup: IPv4 literal all:true returns single-element array",
    Array.isArray(v4all) && v4all.length === 1 && v4all[0].family === 4);
  var v6 = await dnsModule.lookup("2001:db8::1");
  check("lookup: IPv6 literal returns family 6", v6.family === 6);
  _reset();
}

async function testLookupLocalFormAndCache() {
  _reset();
  dnsModule.setCacheTtlMs(60000);
  dnsModule.setLookupTimeoutMs(4000);
  var first = await dnsModule.lookup("localhost");
  check("lookup: localhost resolves via system path (loopback)",
    typeof first.address === "string" && (first.family === 4 || first.family === 6));
  var second = await dnsModule.lookup("localhost");
  check("lookup: second localhost lookup returns same address (positive cache hit)",
    first.address === second.address);
  var allForm = await dnsModule.lookup("localhost", { all: true });
  check("lookup: all:true from cache returns array", Array.isArray(allForm));
  dnsModule.clearCache();
  var third = await dnsModule.lookup("localhost");
  check("lookup: resolves again after clearCache", typeof third.address === "string");
  _reset();
}

async function testLookupNegativeCache() {
  _reset();
  dnsModule.useSystemResolver();
  dnsModule.setCacheTtlMs(60000, 60000);
  dnsModule.setLookupTimeoutMs(4000);
  var e1 = null;
  try { await dnsModule.lookup("no-such-host-zzz.invalid"); }
  catch (e) { e1 = e; }
  if (e1) {
    var e2 = null;
    try { await dnsModule.lookup("no-such-host-zzz.invalid"); }
    catch (e) { e2 = e; }
    check("lookup: negative cache re-throws the SAME error instance (cache hit)",
      e2 !== null && e2 === e1);
  } else {
    check("lookup: negative-cache path (host unexpectedly resolved; skipped)", true);
  }
  _reset();
}

async function testLookupOrderingBranches() {
  // Drive _orderAddrs ipv6first + ipv4first sort branches through the
  // local-form system path (localhost may return >=1 address).
  _reset();
  dnsModule.setResultOrder("ipv6first");
  dnsModule.setLookupTimeoutMs(4000);
  var a = await dnsModule.lookup("localhost", { all: true });
  check("lookup: ipv6first ordering path returns array", Array.isArray(a) && a.length >= 1);
  _reset();
  dnsModule.setResultOrder("ipv4first");
  dnsModule.setLookupTimeoutMs(4000);
  var c = await dnsModule.lookup("localhost", { all: true });
  check("lookup: ipv4first ordering path returns array", Array.isArray(c) && c.length >= 1);
  _reset();
}

async function testLookupDohDotNoResult() {
  // DoH configured but pointed at a closed port: _dualStack catches both
  // family failures → normalized empty → dns/no-result.
  _reset();
  var closed = await _probeClosedPort();
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + closed + "/dns-query" });
  dnsModule.setLookupTimeoutMs(1500);
  check("lookup(DoH, dead upstream): both families fail → dns/no-result",
    await _throwsAsync(function () { return dnsModule.lookup("public.example.com"); }, "dns/no-result"));
  _reset();

  // DoT configured at a closed port: handshake failure per family → empty → no-result.
  var closed2 = await _probeClosedPort();
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: closed2, servername: "localhost" });
  dnsModule.setLookupTimeoutMs(1500);
  check("lookup(DoT, dead upstream): handshake fails → dns/no-result",
    await _throwsAsync(function () { return dnsModule.lookup("public.example.com"); }, "dns/no-result"));
  await _drainTcpHandles();
}

// ======================================================================
// resolve / _resolveProtocol — IP literal, wrong-family, transport errors
// ======================================================================
async function testResolveProtocol() {
  _reset();
  check("resolve4: bad host throws dns/bad-host",
    await _throwsAsync(function () { return dnsModule.resolve4(""); }, "dns/bad-host"));
  var r4 = await dnsModule.resolve4("198.51.100.9");
  check("resolve4: IPv4 literal short-circuits to [literal]",
    Array.isArray(r4) && r4[0] === "198.51.100.9");
  check("resolve4: IPv6 literal is wrong family",
    await _throwsAsync(function () { return dnsModule.resolve4("2001:db8::5"); }, "dns/wrong-family"));
  var r6 = await dnsModule.resolve6("2001:db8::5");
  check("resolve6: IPv6 literal short-circuits", Array.isArray(r6) && r6[0] === "2001:db8::5");
  check("resolve6: IPv4 literal is wrong family",
    await _throwsAsync(function () { return dnsModule.resolve6("198.51.100.9"); }, "dns/wrong-family"));
  var r6a = await dnsModule.resolveAaaa("2001:db8::9");
  check("resolveAaaa: IPv6 literal short-circuits", Array.isArray(r6a) && r6a[0] === "2001:db8::9");
  _reset();
}

async function testResolveTransportErrors() {
  _reset();
  var closed = await _probeClosedPort();
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + closed + "/dns-query" });
  dnsModule.setLookupTimeoutMs(1500);
  check("resolve4(auto DoH, dead upstream): surfaces DnsError",
    await _throwsAsync(function () { return dnsModule.resolve4("public.example.com"); }));
  _reset();

  var closed2 = await _probeClosedPort();
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: closed2, servername: "localhost" });
  dnsModule.setLookupTimeoutMs(1500);
  check("resolve4(auto DoT, dead upstream): surfaces DnsError",
    await _throwsAsync(function () { return dnsModule.resolve4("public.example.com"); }));
  await _drainTcpHandles();
}

async function testResolveDispatch() {
  _reset();
  // lowercase type is uppercased; A dispatch via IP literal (offline).
  var a = await dnsModule.resolve("192.0.2.10", "a");
  check("resolve: lowercase 'a' dispatches to A + short-circuits literal",
    Array.isArray(a) && a[0] === "192.0.2.10");
  var aaaa = await dnsModule.resolve("2001:db8::7", "aaaa");
  check("resolve: 'aaaa' dispatches to AAAA literal",
    Array.isArray(aaaa) && aaaa[0] === "2001:db8::7");
  check("resolve: unsupported type throws dns/unsupported-type",
    await _throwsAsync(function () { return dnsModule.resolve("example.com", "TXT"); }, "dns/unsupported-type"));

  // HTTPS dispatch → queryHttps, exercised via a system TCP responder.
  var reply = _buildReply("example.com", 65, [{
    name: "example.com", type: 65,
    rdata: _svcbRd(1, "svc.example.net", [{ key: 1, value: _alpn(["h2"]) }]),
  }]);
  var fix = await _startTcpResponder(reply);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + fix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  var https = await dnsModule.resolve("example.com", "HTTPS", { transport: "system" });
  check("resolve: 'HTTPS' dispatches to queryHttps (system transport)",
    Array.isArray(https) && https.length === 1 && https[0].params.alpn[0] === "h2");
  fix.srv.close();
  await _drainTcpHandles();
}

// ======================================================================
// resolveSecure — validation branches + DoH error path
// ======================================================================
async function testResolveSecure() {
  _reset();
  dnsModule.useSystemResolver();
  check("resolveSecure: no DoH transport throws dns/secure-requires-doh",
    await _throwsAsync(function () { return dnsModule.resolveSecure("example.com"); }, "dns/secure-requires-doh"));
  _reset();
  dnsModule.useDnsOverHttps({ url: "https://x.example/dns-query" });
  check("resolveSecure: empty host throws dns/bad-host",
    await _throwsAsync(function () { return dnsModule.resolveSecure(""); }, "dns/bad-host"));
  check("resolveSecure: >253 char host throws dns/bad-host",
    await _throwsAsync(function () {
      return dnsModule.resolveSecure(("a".repeat(60) + ".").repeat(5) + "example.com");
    }, "dns/bad-host"));
  check("resolveSecure: oversize label throws dns/bad-host",
    await _throwsAsync(function () {
      return dnsModule.resolveSecure("a".repeat(64) + ".example.com");
    }, "dns/bad-host"));
  check("resolveSecure: non-LDH label (underscore) throws dns/bad-host",
    await _throwsAsync(function () {
      return dnsModule.resolveSecure("bad_label.example.com");
    }, "dns/bad-host"));
  check("resolveSecure: unsupported type throws dns/secure-unsupported-type",
    await _throwsAsync(function () {
      return dnsModule.resolveSecure("example.com", "TXT");
    }, "dns/secure-unsupported-type"));
  _reset();

  // Valid host + type but dead DoH upstream → DoH error path executes.
  var closed = await _probeClosedPort();
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + closed + "/dns-query" });
  dnsModule.setLookupTimeoutMs(1500);
  check("resolveSecure: valid A query against dead upstream surfaces DnsError",
    await _throwsAsync(function () { return dnsModule.resolveSecure("example.com", "A"); }));
  check("resolveSecure: valid AAAA query against dead upstream surfaces DnsError",
    await _throwsAsync(function () { return dnsModule.resolveSecure("example.com", "AAAA"); }));
  await _drainTcpHandles();
}

// ======================================================================
// reverse — input validation
// ======================================================================
async function testReverse() {
  _reset();
  check("reverse: non-string throws dns/bad-ip",
    await _throwsAsync(function () { return dnsModule.reverse(12345); }, "dns/bad-ip"));
  check("reverse: empty string throws dns/bad-ip",
    await _throwsAsync(function () { return dnsModule.reverse(""); }, "dns/bad-ip"));
  check("reverse: non-IP string throws dns/bad-ip",
    await _throwsAsync(function () { return dnsModule.reverse("definitely-not-an-ip"); }, "dns/bad-ip"));
  _reset();
}

// ======================================================================
// nodeLookup — callback adapter (offline via IP literal + local form)
// ======================================================================
function _nodeLookupP(host, options) {
  return new Promise(function (resolve, reject) {
    function cb(err) {
      if (err) return reject(err);
      resolve(Array.prototype.slice.call(arguments, 1));
    }
    if (options === undefined) dnsModule.nodeLookup(host, cb);
    else dnsModule.nodeLookup(host, options, cb);
  });
}

async function testNodeLookup() {
  _reset();
  var single = await _nodeLookupP("192.0.2.55"); // options omitted → function-as-options branch
  check("nodeLookup: options-omitted callback yields (address, family)",
    single[0] === "192.0.2.55" && single[1] === 4);
  var all = await _nodeLookupP("192.0.2.55", { all: true });
  check("nodeLookup: all:true yields an array in first callback arg",
    Array.isArray(all[0]) && all[0][0].address === "192.0.2.55");

  // error path via callback (local-form NXDOMAIN)
  dnsModule.useSystemResolver();
  dnsModule.setLookupTimeoutMs(4000);
  var errored = false;
  try { await _nodeLookupP("no-host-abc-xyz.invalid"); }
  catch (e) { errored = !!e; }
  check("nodeLookup: resolution failure surfaces via callback(err)", errored);
  _reset();
}

// ======================================================================
// _systemRawQuery — transport failure branches (loopback fixtures)
// ======================================================================
async function testSystemRawQueryErrors() {
  // Upstream closes before replying → dns/system-failed.
  _reset();
  var closer = await _startCloseImmediately();
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + closer.port]);
  dnsModule.setLookupTimeoutMs(3000);
  check("querySvcb(system): upstream close-before-reply → dns/system-failed",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { transport: "system" });
    }, "dns/system-failed"));
  closer.srv.close();
  await _drainTcpHandles();

  // Connection refused → dns/system-failed.
  _reset();
  var refused = await _probeClosedPort();
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + refused]);
  dnsModule.setLookupTimeoutMs(3000);
  check("querySvcb(system): connection refused → dns/system-failed",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { transport: "system" });
    }, "dns/system-failed"));
  await _drainTcpHandles();
}

async function testSystemRawQueryV6Bracket() {
  // Exercise the "[ipv6]:port" server-address parsing branch. Best-effort:
  // skips cleanly when the runner lacks IPv6 loopback.
  _reset();
  var port = null;
  try {
    port = await new Promise(function (resolve, reject) {
      var s = net.createServer();
      s.unref();
      s.on("error", reject);
      s.listen(0, "::1", function () {
        var p = s.address().port;
        s.close(function () { resolve(p); });
      });
    });
  } catch (_e) { port = null; }
  if (port === null) {
    check("querySvcb(system): [::1]:port bracket parse (skipped — no IPv6 loopback)", true);
    _reset();
    return;
  }
  dnsModule.useSystemResolver();
  dnsModule.setServers(["[::1]:" + port]);
  dnsModule.setLookupTimeoutMs(2000);
  // Nothing listening on that ::1 port → connect refused → system-failed,
  // but the bracket-parse branch runs on the way there.
  check("querySvcb(system): [::1]:port bracket address parsed (refused → DnsError)",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { transport: "system" });
    }));
  await _drainTcpHandles();
}

// ======================================================================
// discoverEncrypted — mapping + no-transport + alias-skip branches
// ======================================================================
async function testDiscoverEncryptedBranches() {
  // name must be a string.
  _reset();
  check("discoverEncrypted: non-string name throws dns/bad-host",
    await _throwsAsync(function () { return dnsModule.discoverEncrypted({ name: 12345 }); }, "dns/bad-host"));

  // NXDOMAIN (rcode 3) upstream → mapped to dns/ddr-not-discovered.
  _reset();
  var nx = _buildReply("_dns.resolver.arpa", 64, [], 0x8183);
  var nxFix = await _startTcpResponder(nx);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + nxFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  check("discoverEncrypted: NXDOMAIN mapped to dns/ddr-not-discovered",
    await _throwsAsync(function () { return dnsModule.discoverEncrypted(); }, "dns/ddr-not-discovered"));
  nxFix.srv.close();
  await _drainTcpHandles();

  // Only an AliasMode (priority 0) record present → all skipped → not-discovered.
  _reset();
  var aliasOnly = _buildReply("_dns.resolver.arpa", 64, [{
    name: "_dns.resolver.arpa", type: 64, rdata: _svcbRd(0, "alias.example.net", []),
  }]);
  var aliasFix = await _startTcpResponder(aliasOnly);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + aliasFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  check("discoverEncrypted: alias-only records skipped → dns/ddr-not-discovered",
    await _throwsAsync(function () { return dnsModule.discoverEncrypted(); }, "dns/ddr-not-discovered"));
  aliasFix.srv.close();
  await _drainTcpHandles();

  // ServiceMode with an unrecognized alpn (no dot/h2/h3, no dohpath) → skipped.
  _reset();
  var noTransport = _buildReply("_dns.resolver.arpa", 64, [{
    name: "_dns.resolver.arpa", type: 64,
    rdata: _svcbRd(1, "svc.example.net", [{ key: 1, value: _alpn(["ftp"]) }]),
  }]);
  var ntFix = await _startTcpResponder(noTransport);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + ntFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  check("discoverEncrypted: no recognized transport → dns/ddr-not-discovered",
    await _throwsAsync(function () { return dnsModule.discoverEncrypted(); }, "dns/ddr-not-discovered"));
  ntFix.srv.close();
  await _drainTcpHandles();

  // insecureSystemResolverOnly:false → transport auto (system here) still works.
  _reset();
  var good = _buildReply("_dns.resolver.arpa", 64, [{
    name: "_dns.resolver.arpa", type: 64,
    rdata: _svcbRd(1, "doh.example.net", [
      { key: 1, value: _alpn(["h2"]) },
      { key: 7, value: Buffer.from("/dns-query", "utf8") },
    ]),
  }]);
  var goodFix = await _startTcpResponder(good);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + goodFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  var res = await dnsModule.discoverEncrypted({ insecureSystemResolverOnly: false });
  check("discoverEncrypted: insecureSystemResolverOnly:false auto transport returns a DoH descriptor",
    Array.isArray(res) && res.length === 1 && res[0].transport === "doh" && res[0].dohpath === "/dns-query");
  goodFix.srv.close();
  await _drainTcpHandles();
}

// ======================================================================
// useDesignatedResolvers — config-loop fallback branches
// ======================================================================
function testDesignatedResolversFallback() {
  // First entry passes pre-loop validation (https url) but fails to
  // configure (invalid method rejected by useDnsOverHttps) → caught,
  // second valid entry wins (active=1).
  _reset();
  var r = dnsModule.useDesignatedResolvers([
    { transport: "doh", url: "https://primary.example.net/dns-query", method: "PUT" },
    { transport: "doh", url: "https://secondary.example.net/dns-query" },
  ]);
  check("useDesignatedResolvers: first entry fails to configure → second wins (active=1)",
    r.active === 1 && r.count === 2 &&
    dnsModule._stateForTest().doh.url.indexOf("secondary") !== -1);
  _reset();

  // Every entry fails to configure → dns/dnr-no-resolvers with last error.
  check("useDesignatedResolvers: all entries fail → dns/dnr-no-resolvers",
    _throws(function () {
      dnsModule.useDesignatedResolvers([
        { transport: "doh", url: "https://only.example.net/dns-query", method: "PATCH" },
      ]);
    }, "dns/dnr-no-resolvers"));
  _reset();

  // A dot entry that passes host validation but fails port validation in
  // useDnsOverTls → caught → dnr-no-resolvers.
  check("useDesignatedResolvers: dot entry bad port → dnr-no-resolvers",
    _throws(function () {
      dnsModule.useDesignatedResolvers([
        { transport: "dot", host: "dot.example.net", port: -9 },
      ]);
    }, "dns/dnr-no-resolvers"));
  _reset();
}

// ======================================================================
// DoT success paths — real TLS 1.3 handshake against a loopback responder
// (A / AAAA decode via _decodeDnsAnswer, _dotLookup, _dotRawQuery, the
// lookup + _resolveProtocol DoT branches)
// ======================================================================
async function testDotSecureTransport() {
  var cert = await _mintSecureCert();

  // ---- A-record lookup over DoT ----
  _reset();
  var aReply = _buildReply("secure.example.com", 1, [
    { name: "secure.example.com", type: 1, rdata: _aRdata(203, 0, 113, 5) },
  ]);
  var dotA = await _startDotServer(cert, { reply: aReply });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: dotA.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var a = await dnsModule.lookup("secure.example.com", { family: 4 });
    check("lookup(DoT): A record resolves via real TLS 1.3 handshake",
      a.address === "203.0.113.5" && a.family === 4);
  } finally { dotA.close(); await _drainTcpHandles(); }

  // ---- AAAA-record resolve6 over DoT (_resolveProtocol DoT branch) ----
  _reset();
  var aaaaReply = _buildReply("v6.example.com", 28, [
    { name: "v6.example.com", type: 28, rdata: _aaaaRdata() },
  ]);
  var dotAAAA = await _startDotServer(cert, { reply: aaaaReply });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: dotAAAA.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var r6 = await dnsModule.resolve6("v6.example.com");
    check("resolve6(DoT): AAAA record decodes to an IPv6 string",
      Array.isArray(r6) && r6.length === 1 && r6[0].indexOf("2001:") === 0);
  } finally { dotAAAA.close(); await _drainTcpHandles(); }

  // ---- SVCB query over DoT (_dotRawQuery raw path) ----
  _reset();
  var svcbReply = _buildReply("svc.example.com", 64, [
    { name: "svc.example.com", type: 64,
      rdata: _svcbRd(1, "target.example.net", [{ key: 1, value: _alpn(["h2"]) }]) },
  ]);
  var dotSvcb = await _startDotServer(cert, { reply: svcbReply });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: dotSvcb.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var svcb = await dnsModule.querySvcb("svc.example.com", { transport: "dot" });
    check("querySvcb(DoT): SVCB record parses over the TLS transport",
      Array.isArray(svcb) && svcb.length === 1 && svcb[0].params.alpn[0] === "h2");
  } finally { dotSvcb.close(); await _drainTcpHandles(); }
}

// ======================================================================
// DoH success paths — real HTTPS round-trip against a loopback responder
// (_dohLookup GET + POST, _dohLookupSecure AD bit, _dohRawQuery, non-200)
// ======================================================================
async function testDohSecureTransport() {
  var cert = await _mintSecureCert();
  var aReply = _buildReply("doh.example.com", 1, [
    { name: "doh.example.com", type: 1, rdata: _aRdata(198, 51, 100, 9) },
  ]);

  // ---- A lookup + resolve4 over DoH (GET) ----
  _reset();
  var dohA = await _startDohServer(cert, { reply: aReply });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + dohA.port + "/dns-query", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var a = await dnsModule.lookup("doh.example.com", { family: 4 });
    check("lookup(DoH GET): A record resolves over real HTTPS", a.address === "198.51.100.9");
    var r4 = await dnsModule.resolve4("doh.example.com");
    check("resolve4(DoH): A record via _resolveProtocol DoH branch",
      Array.isArray(r4) && r4[0] === "198.51.100.9");
  } finally { dohA.close(); await _drainTcpHandles(); }

  // ---- POST method (usePost branch: content-type/length + req.write) ----
  _reset();
  var dohP = await _startDohServer(cert, { reply: aReply });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + dohP.port + "/dns-query", method: "POST", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var ap = await dnsModule.lookup("doh.example.com", { family: 4 });
    check("lookup(DoH POST): A record resolves via POST body", ap.address === "198.51.100.9");
  } finally { dohP.close(); await _drainTcpHandles(); }

  // ---- resolveSecure over DoH with the AD bit set (_dohLookupSecure) ----
  _reset();
  var adReply = _buildReply("secure.example.com", 1, [
    { name: "secure.example.com", type: 1, rdata: _aRdata(203, 0, 113, 1) },
  ]);
  adReply.writeUInt16BE(0x81a0, 2);   // flags: response + RA + AD bit (0x20 in byte 3)
  var dohSec = await _startDohServer(cert, { reply: adReply });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + dohSec.port + "/dns-query", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var sec = await dnsModule.resolveSecure("secure.example.com", "A");
    check("resolveSecure(DoH): returns { rrs, ad } with the AD bit surfaced",
      sec && Array.isArray(sec.rrs) && sec.rrs[0] === "203.0.113.1" && sec.ad === true);
  } finally { dohSec.close(); await _drainTcpHandles(); }

  // ---- SVCB over DoH (_dohRawQuery raw path) ----
  _reset();
  var svcbReply = _buildReply("svc.example.com", 64, [
    { name: "svc.example.com", type: 64,
      rdata: _svcbRd(1, "t.example.net", [{ key: 1, value: _alpn(["h3"]) }]) },
  ]);
  var dohSvcb = await _startDohServer(cert, { reply: svcbReply });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + dohSvcb.port + "/dns-query", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var svcb = await dnsModule.querySvcb("svc.example.com", { transport: "doh" });
    check("querySvcb(DoH): SVCB record parses over HTTPS",
      Array.isArray(svcb) && svcb.length === 1 && svcb[0].params.alpn[0] === "h3");
  } finally { dohSvcb.close(); await _drainTcpHandles(); }

  // ---- DoH non-200 status → dns/doh-http ----
  _reset();
  var doh500 = await _startDohServer(cert, { reply: Buffer.alloc(0), status: 500 });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + doh500.port + "/dns-query", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    check("querySvcb(DoH 500): non-200 response surfaces dns/doh-http",
      await _throwsAsync(function () {
        return dnsModule.querySvcb("svc.example.com", { transport: "doh" });
      }, "dns/doh-http"));
  } finally { doh500.close(); await _drainTcpHandles(); }
}

// ======================================================================
// Secure-transport wall-clock deadlines — a stalled upstream must be torn
// down (_armRequestTimeout for DoH, _dotConnect sock.setTimeout for DoT,
// and the shared _withTimeout deadline)
// ======================================================================
async function testSecureTransportTimeouts() {
  var cert = await _mintSecureCert();

  // ---- DoH request accepted then stalled → dns/lookup-timeout ----
  _reset();
  var dohHang = await _startDohServer(cert, { hang: true });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + dohHang.port + "/dns-query", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(700);
  try {
    check("querySvcb(DoH stalled): request deadline surfaces dns/lookup-timeout",
      await _throwsAsync(function () {
        return dnsModule.querySvcb("svc.example.com", { transport: "doh" });
      }, "dns/lookup-timeout"));
    // The promise-level deadline can win the race with the socket-level
    // req.setTimeout; give the request-teardown callback a window to fire
    // before the fixture is destroyed (verifies no lingering handle).
    await helpers.passiveObserve(400, "network-dns: DoH request-teardown grace");
  } finally { dohHang.close(); await _drainTcpHandles(); }

  // ---- DoT handshake completes, query stalls → socket deadline tears down ----
  _reset();
  var dotHang = await _startDotServer(cert, { hang: true });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: dotHang.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(700);
  try {
    check("resolve4(DoT stalled): idle socket deadline surfaces a DnsError",
      await _throwsAsync(function () { return dnsModule.resolve4("hang.example.com"); }));
    await helpers.passiveObserve(400, "network-dns: DoT socket-teardown grace");
  } finally { dotHang.close(); await _drainTcpHandles(); }
}

// ======================================================================
// Remaining defensive / adversarial / option-default branches reachable
// wholly in-process (local-form normalization, env transport override,
// LDH label rejection, DNR entry shape, DDR non-NXDOMAIN rethrow, raw name
// decode limits, transport-unavailable + no-resolvers guards, system
// timeout, native-error wraps)
// ======================================================================
async function testLocalFormTrailingDot() {
  _reset();
  dnsModule.setLookupTimeoutMs(4000);
  try {
    var ld = await dnsModule.lookup("localhost.");
    check("lookup: fully-qualified 'localhost.' strips the root dot → system path",
      typeof ld.address === "string" && (ld.family === 4 || ld.family === 6));
    // explicit family over the system resolver → sets nodeOpts.family
    var ld4 = await dnsModule.lookup("localhost", { family: 4 });
    check("lookup(system, family:4): pins the address family on the OS resolver",
      ld4.family === 4);
  } finally { _reset(); }
}

async function testEnsureSecureDefaultEnvOverride() {
  var saved = process.env.BLAMEJS_DNS_TRANSPORT;
  try {
    // BLAMEJS_DNS_TRANSPORT=system → the default resolver is the OS resolver.
    process.env.BLAMEJS_DNS_TRANSPORT = "system";
    _reset();
    dnsModule.setLookupTimeoutMs(4000);
    await dnsModule.lookup("localhost");
    check("lookup: BLAMEJS_DNS_TRANSPORT=system arms the system resolver default",
      dnsModule._stateForTest().systemResolver === true);

    // BLAMEJS_DNS_TRANSPORT=dot → default DoT config is armed; a local-form
    // host short-circuits to the system path so no external connection runs.
    process.env.BLAMEJS_DNS_TRANSPORT = "dot";
    _reset();
    dnsModule.setLookupTimeoutMs(4000);
    await dnsModule.lookup("localhost");
    var dotState = dnsModule._stateForTest().dot;
    check("lookup: BLAMEJS_DNS_TRANSPORT=dot arms the default DoT config (port 853)",
      dotState && dotState.host === "1.1.1.1" && dotState.port === 853);
  } finally {
    if (saved === undefined) delete process.env.BLAMEJS_DNS_TRANSPORT;
    else process.env.BLAMEJS_DNS_TRANSPORT = saved;
    _reset();
  }
}

async function testValidateLdhLabelReject() {
  _reset();
  check("querySvcb: label with a non-LDH character throws dns/bad-host",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("bad!char.example.com", { transport: "system" });
    }, "dns/bad-host"));
  _reset();
}

function testDesignatedResolversNonObjectEntry() {
  _reset();
  check("useDesignatedResolvers: non-object entry throws dns/dnr-malformed",
    _throws(function () { dnsModule.useDesignatedResolvers([42]); }, "dns/dnr-malformed"));
  _reset();
}

async function testDiscoverEncryptedRethrow() {
  // A transport failure that is NOT rcode/NXDOMAIN must be rethrown as-is
  // (only a genuine no-result maps to dns/ddr-not-discovered).
  _reset();
  var refused = await _probeClosedPort();
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + refused]);
  dnsModule.setLookupTimeoutMs(2500);
  try {
    check("discoverEncrypted: connection failure (not NXDOMAIN) is rethrown unchanged",
      await _throwsAsync(function () { return dnsModule.discoverEncrypted(); }, "dns/system-failed"));
  } finally { await _drainTcpHandles(); }
}

function testReadDnsNameLimits() {
  var rdn = dnsModule._readDnsName;
  // Label length runs past the end of the message.
  check("_readDnsName: label length exceeding the message throws dns/svcb-malformed",
    _throws(function () { return rdn(Buffer.from([5, 0x61]), 0); }, "dns/svcb-malformed"));
  // A run of single-byte labels with no terminator, longer than the
  // 256-hop compression-loop cap → hits the iteration guard before the
  // not-terminated guard.
  var longLabels = Buffer.alloc(600);
  for (var i = 0; i < 600; i += 2) { longLabels[i] = 1; longLabels[i + 1] = 0x61; }
  check("_readDnsName: label walk beyond the 256-hop cap throws dns/svcb-malformed",
    _throws(function () { return rdn(longLabels, 0); }, "dns/svcb-malformed"));
}

async function testRawQueryTransportUnavailable() {
  // System-only config, then a forced doh/dot transport with no matching
  // config → _rawQuery raises dns/transport-unavailable (permanent).
  _reset();
  dnsModule.useSystemResolver();
  check("querySvcb(transport:doh) under system-only config → dns/transport-unavailable",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { transport: "doh" });
    }, "dns/transport-unavailable"));
  check("querySvcb(transport:dot) under system-only config → dns/transport-unavailable",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { transport: "dot" });
    }, "dns/transport-unavailable"));
  _reset();
}

async function testSystemRawQueryNoServers() {
  // Force getServers() to report zero configured resolvers.
  _reset();
  dnsModule.useSystemResolver();
  dnsModule._stateForTest().servers = [];
  try {
    check("querySvcb(system): zero configured resolvers → dns/no-system-resolvers",
      await _throwsAsync(function () {
        return dnsModule.querySvcb("example.com", { transport: "system" });
      }, "dns/no-system-resolvers"));
  } finally { _reset(); }
}

async function testSystemRawQueryTimeout() {
  // Upstream accepts the TCP connection then stalls → sock.setTimeout
  // wall-clock deadline settles the query with dns/lookup-timeout.
  _reset();
  var hang = await _startTcpHang();
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + hang.port]);
  dnsModule.setLookupTimeoutMs(700);
  try {
    check("querySvcb(system): upstream accepts then stalls → dns/lookup-timeout",
      await _throwsAsync(function () {
        return dnsModule.querySvcb("example.com", { transport: "system" });
      }, "dns/lookup-timeout"));
    // The socket-level sock.setTimeout deadline can fire a hair after the
    // promise-level _withTimeout; let it settle before the fixture teardown.
    await helpers.passiveObserve(250, "network-dns: system socket-teardown grace");
  } finally { hang.close(); await _drainTcpHandles(); }
}

async function testNativeErrorWraps() {
  // resolve4 over the system resolver with an unparseable host → c-ares
  // rejects with a native EBADNAME (no network); the framework wraps it as
  // dns/resolve-failed via the non-DnsError branch.
  _reset();
  dnsModule.useSystemResolver();
  dnsModule.setLookupTimeoutMs(5000);
  check("resolve4(system): native c-ares error wraps as dns/resolve-failed",
    await _throwsAsync(function () {
      return dnsModule.resolve4("bad host with spaces");
    }, "dns/resolve-failed"));
  _reset();

  // reverse of a reserved IP → native ENOTFOUND (no network); wrapped as
  // dns/reverse-failed via the non-DnsError branch.
  dnsModule.useSystemResolver();
  dnsModule.setLookupTimeoutMs(5000);
  check("reverse: native c-ares error wraps as dns/reverse-failed (IPv4)",
    await _throwsAsync(function () { return dnsModule.reverse("0.0.0.0"); }, "dns/reverse-failed"));
  // An IPv6 literal exercises the family-6 branch of the reverse-requested
  // observability event.
  check("reverse: IPv6 literal native error wraps as dns/reverse-failed",
    await _throwsAsync(function () { return dnsModule.reverse("::"); }, "dns/reverse-failed"));
  _reset();
}

// ======================================================================
// DoT decode + adversarial-reply + auto-transport branches (real TLS)
// ======================================================================
async function testDotDecodeAndErrorBranches() {
  var cert = await _mintSecureCert();

  // ---- answer owner name via compression pointer (_skipDnsName pointer) ----
  _reset();
  var comp = _buildReplyCompressedName("comp.example.com", 1, 1, _aRdata(192, 0, 2, 7));
  var s1 = await _startDotServer(cert, { reply: comp });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: s1.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var a = await dnsModule.lookup("comp.example.com", { family: 4 });
    check("lookup(DoT): compressed answer name decodes (name-compression branch)",
      a.address === "192.0.2.7");
  } finally { s1.close(); await _drainTcpHandles(); }

  // ---- SERVFAIL rcode over DoT → decode raises dns/no-result ----
  _reset();
  var servfail = _buildReply("sf.example.com", 1,
    [{ name: "sf.example.com", type: 1, rdata: _aRdata(1, 2, 3, 4) }], 0x8182);   // rcode 2 = SERVFAIL
  var s2 = await _startDotServer(cert, { reply: servfail });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: s2.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    check("resolve4(DoT): SERVFAIL rcode surfaces a DnsError (decode reject path)",
      await _throwsAsync(function () { return dnsModule.resolve4("sf.example.com"); }));
  } finally { s2.close(); await _drainTcpHandles(); }

  // ---- truncated rdata over DoT → decode raises dns/bad-reply ----
  _reset();
  var trunc = _buildReply("tr.example.com", 1,
    [{ name: "tr.example.com", type: 1, rdata: _aRdata(9, 9, 9, 9) }]);
  trunc.writeUInt16BE(0x00ff, trunc.length - 6);                                  // rdlen lies past buffer end
  var s3 = await _startDotServer(cert, { reply: trunc });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: s3.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    check("resolve4(DoT): truncated rdata surfaces a DnsError (decode reject path)",
      await _throwsAsync(function () { return dnsModule.resolve4("tr.example.com"); }));
  } finally { s3.close(); await _drainTcpHandles(); }

  // ---- querySvcb with NO opts → auto-selects the configured DoT transport ----
  _reset();
  var svcbReply = _buildReply("auto.example.com", 64, [{ name: "auto.example.com", type: 64,
    rdata: _svcbRd(1, "t.example.net", [{ key: 1, value: _alpn(["h2"]) }]) }]);
  var s5 = await _startDotServer(cert, { reply: svcbReply });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: s5.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var svcb = await dnsModule.querySvcb("auto.example.com");                     // no opts → _rawQuery auto-selects DoT
    check("querySvcb(auto): no transport opt auto-selects the configured DoT",
      Array.isArray(svcb) && svcb.length === 1 && svcb[0].params.alpn[0] === "h2");
  } finally { s5.close(); await _drainTcpHandles(); }

  // ---- SVCB reply carrying a non-matching answer type → skipped ----
  _reset();
  var mixed = _buildReply("mix.example.com", 64, [
    { name: "mix.example.com", type: 1,  rdata: _aRdata(10, 0, 0, 1) },          // A record — must be skipped
    { name: "mix.example.com", type: 64, rdata: _svcbRd(1, "t.example.net", [{ key: 1, value: _alpn(["h3"]) }]) },
  ]);
  var s6 = await _startDotServer(cert, { reply: mixed });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: s6.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var mr = await dnsModule.querySvcb("mix.example.com", { transport: "dot" });
    check("querySvcb(DoT): a non-SVCB answer record is filtered out",
      Array.isArray(mr) && mr.length === 1 && mr[0].params.alpn[0] === "h3");
  } finally { s6.close(); await _drainTcpHandles(); }

  // ---- reply shorter than a DNS header → decode rejects (buf < 12) ----
  _reset();
  var s7 = await _startDotServer(cert, { reply: Buffer.alloc(6) });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: s7.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    check("resolve4(DoT): sub-header reply surfaces a DnsError (buf<12 guard)",
      await _throwsAsync(function () { return dnsModule.resolve4("short.example.com"); }));
  } finally { s7.close(); await _drainTcpHandles(); }

  // ---- ancount lies (claims an answer, none present) → record-header truncated ----
  _reset();
  var lie = _buildReply("lie.example.com", 1, []);
  lie.writeUInt16BE(1, 6);                                                          // ANCOUNT = 1, but no answer bytes
  var s8 = await _startDotServer(cert, { reply: lie });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: s8.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    check("resolve4(DoT): lying ANCOUNT surfaces a DnsError (record-header guard)",
      await _throwsAsync(function () { return dnsModule.resolve4("lie.example.com"); }));
  } finally { s8.close(); await _drainTcpHandles(); }

  // ---- NOERROR reply with zero answers → resolve raises dns/no-result ----
  _reset();
  var empty = _buildReply("empty.example.com", 1, []);                              // ANCOUNT 0, NOERROR
  var s9 = await _startDotServer(cert, { reply: empty });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: s9.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    check("resolve6(DoT): NOERROR with no matching answers → dns/no-result",
      await _throwsAsync(function () { return dnsModule.resolve6("empty.example.com"); }, "dns/no-result"));
  } finally { s9.close(); await _drainTcpHandles(); }
}

// ======================================================================
// DoH GET-with-query, POST-secure/raw, non-200 for lookup + resolveSecure,
// and family-0 dual-stack ordering (real HTTPS)
// ======================================================================
async function testDohDecodeAndErrorBranches() {
  var cert = await _mintSecureCert();
  var aReply = _buildReply("doh2.example.com", 1,
    [{ name: "doh2.example.com", type: 1, rdata: _aRdata(198, 51, 100, 42) }]);

  // ---- DoH url already carrying a query string → getUrl joins with '&' ----
  _reset();
  var qsrv = await _startDohServer(cert, { reply: aReply });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + qsrv.port + "/dns-query?ns=1", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var a = await dnsModule.lookup("doh2.example.com", { family: 4 });
    check("lookup(DoH, url with existing query): appends the dns param with '&'",
      a.address === "198.51.100.42");
  } finally { qsrv.close(); await _drainTcpHandles(); }

  // ---- resolveSecure over DoH via POST + '?'-url (usePost + '&' branches) ----
  _reset();
  var adReply = _buildReply("sec.example.com", 1,
    [{ name: "sec.example.com", type: 1, rdata: _aRdata(203, 0, 113, 9) }]);
  adReply.writeUInt16BE(0x81a0, 2);                                               // AD bit set
  var psec = await _startDohServer(cert, { reply: adReply });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + psec.port + "/dns-query?p=1", method: "POST", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var sec = await dnsModule.resolveSecure("sec.example.com", "A");
    check("resolveSecure(DoH POST, ?-url): decodes via POST body over the '&' getUrl branch",
      sec && Array.isArray(sec.rrs) && sec.rrs[0] === "203.0.113.9" && sec.ad === true);
  } finally { psec.close(); await _drainTcpHandles(); }

  // ---- querySvcb over DoH via POST + auto transport (raw usePost branch) ----
  _reset();
  var svcbReply = _buildReply("praw.example.com", 64, [{ name: "praw.example.com", type: 64,
    rdata: _svcbRd(1, "t.example.net", [{ key: 1, value: _alpn(["h2"]) }]) }]);
  var praw = await _startDohServer(cert, { reply: svcbReply });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + praw.port + "/dns-query?p=1", method: "POST", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var svcb = await dnsModule.querySvcb("praw.example.com");                     // no transport → auto DoH, POST body
    check("querySvcb(DoH POST, auto transport): raw query round-trips via POST body",
      Array.isArray(svcb) && svcb.length === 1 && svcb[0].params.alpn[0] === "h2");
  } finally { praw.close(); await _drainTcpHandles(); }

  // ---- non-200 for lookup (_dohLookup) + resolveSecure (_dohLookupSecure) ----
  _reset();
  var e500 = await _startDohServer(cert, { reply: Buffer.alloc(0), status: 500 });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + e500.port + "/dns-query", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    check("lookup(DoH 500, family:4): _dohLookup non-200 surfaces dns/doh-http",
      await _throwsAsync(function () {
        return dnsModule.lookup("x.example.com", { family: 4 });
      }, "dns/doh-http"));
    check("resolveSecure(DoH 500): _dohLookupSecure non-200 surfaces dns/doh-http",
      await _throwsAsync(function () {
        return dnsModule.resolveSecure("x.example.com", "A");
      }, "dns/doh-http"));
  } finally { e500.close(); await _drainTcpHandles(); }

  // ---- family-0 dual-stack over DoH with ipv6first ordering ----
  _reset();
  var dsrv = await _startDohServer(cert, { reply: aReply });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + dsrv.port + "/dns-query", ca: cert.caPem });
  dnsModule.setResultOrder("ipv6first");
  dnsModule.setLookupTimeoutMs(5000);
  try {
    var all = await dnsModule.lookup("doh2.example.com", { all: true });          // family 0 → _dualStack both families
    check("lookup(DoH, family 0, ipv6first): dual-stack returns the A answer",
      Array.isArray(all) && all.length >= 1 && all[0].address === "198.51.100.42");
  } finally { dsrv.close(); await _drainTcpHandles(); }
}

async function testResolveTypeAndNodeLookupBranches() {
  // resolve(): a non-string type is rejected as a typed DnsError (not a
  // raw TypeError from .toUpperCase()).
  _reset();
  check("resolve: non-string type throws dns/unsupported-type",
    await _throwsAsync(function () { return dnsModule.resolve("192.0.2.1", 123); }, "dns/unsupported-type"));
  // Omitted type defaults to 'A' (the `type || "A"` branch) and short-circuits
  // on the IP literal offline.
  var a = await dnsModule.resolve("192.0.2.1");
  check("resolve: omitted type defaults to A + short-circuits the IP literal",
    Array.isArray(a) && a[0] === "192.0.2.1");
  _reset();

  // nodeLookup(): explicit null options falls back to {} (the `options || {}`
  // branch); an explicit family flows through to lookup().
  var nullOpts = await _nodeLookupP("192.0.2.60", null);
  check("nodeLookup: explicit null options defaults to {} → (address, family)",
    nullOpts[0] === "192.0.2.60" && nullOpts[1] === 4);
  var famOpts = await _nodeLookupP("192.0.2.61", { family: 4 });
  check("nodeLookup: explicit family flows through to lookup()",
    famOpts[0] === "192.0.2.61" && famOpts[1] === 4);
  _reset();
}

// ======================================================================
// Additional transport branches: DoH malformed-200 decode-in-end-handler,
// DoT-raw handshake failure, system close-before-reply, no-arg config
// throws, and the deadline-disabled (ms=0) path
// ======================================================================
async function testMoreTransportBranches() {
  var cert = await _mintSecureCert();

  // ---- config setters with NO opts → default {} then required-field throw ----
  _reset();
  check("useDnsOverHttps(): no opts defaults to {} then throws dns/bad-doh-url",
    _throws(function () { dnsModule.useDnsOverHttps(); }, "dns/bad-doh-url"));
  check("useDnsOverTls(): no opts defaults to {} then throws dns/bad-dot-host",
    _throws(function () { dnsModule.useDnsOverTls(); }, "dns/bad-dot-host"));
  _reset();

  // ---- DoH 200 with a malformed body → decode throws inside the end handler ----
  // Drives the catch(e){reject(e)} arm of _dohLookup / _dohLookupSecure /
  // _dohRawQuery (a 200 response whose body fails to decode).
  _reset();
  var badBody = _buildReply("bad.example.com", 1,
    [{ name: "bad.example.com", type: 1, rdata: _aRdata(9, 9, 9, 9) }]);
  badBody.writeUInt16BE(0x00ff, badBody.length - 6);                              // rdlen lies past end
  var mErr = await _startDohServer(cert, { reply: badBody });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + mErr.port + "/dns-query", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(5000);
  try {
    check("resolve4(DoH): malformed 200 body surfaces a DnsError (_dohLookup end-handler)",
      await _throwsAsync(function () { return dnsModule.resolve4("bad.example.com"); }));
    check("resolveSecure(DoH): malformed 200 body surfaces a DnsError (_dohLookupSecure)",
      await _throwsAsync(function () { return dnsModule.resolveSecure("bad.example.com", "A"); }));
    check("querySvcb(DoH): malformed 200 body surfaces a DnsError (_dohRawQuery)",
      await _throwsAsync(function () { return dnsModule.querySvcb("bad.example.com", { transport: "doh" }); }));
  } finally { mErr.close(); await _drainTcpHandles(); }

  // ---- querySvcb(DoT) against a closed port → _dotRawQuery handshake failure ----
  _reset();
  var closed = await _probeClosedPort();
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: closed, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(2000);
  try {
    check("querySvcb(DoT, dead upstream): raw-query handshake failure surfaces a DnsError",
      await _throwsAsync(function () { return dnsModule.querySvcb("svc.example.com", { transport: "dot" }); }));
  } finally { await _drainTcpHandles(); }

  // ---- system transport: upstream FINs after the query, no reply ----
  _reset();
  var fin = await _startTcpFinNoReply();
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + fin.port]);
  dnsModule.setLookupTimeoutMs(5000);
  try {
    check("querySvcb(system): upstream closes before replying → dns/system-failed",
      await _throwsAsync(function () {
        return dnsModule.querySvcb("example.com", { transport: "system" });
      }, "dns/system-failed"));
  } finally { fin.close(); await _drainTcpHandles(); }

  // ---- deadline disabled (lookupTimeoutMs === 0) over a healthy DoH upstream ----
  // Exercises the ms<=0 short-circuits in _withTimeout + _armRequestTimeout.
  _reset();
  var okReply = _buildReply("ok.example.com", 1,
    [{ name: "ok.example.com", type: 1, rdata: _aRdata(192, 0, 2, 200) }]);
  var okSrv = await _startDohServer(cert, { reply: okReply });
  dnsModule.useDnsOverHttps({ url: "https://127.0.0.1:" + okSrv.port + "/dns-query", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(0);
  try {
    var a = await dnsModule.lookup("ok.example.com", { family: 4 });
    check("lookup(DoH, timeout disabled): resolves without arming a deadline",
      a.address === "192.0.2.200");
  } finally { okSrv.close(); await _drainTcpHandles(); }

  // ---- deadline disabled over a healthy DoT upstream (_dotConnect skips setTimeout) ----
  _reset();
  var okDot = await _startDotServer(cert, { reply: okReply });
  dnsModule.useDnsOverTls({ host: "127.0.0.1", port: okDot.port, servername: "localhost", ca: cert.caPem });
  dnsModule.setLookupTimeoutMs(0);
  try {
    var d = await dnsModule.resolve4("ok.example.com");
    check("resolve4(DoT, timeout disabled): resolves without arming a socket deadline",
      Array.isArray(d) && d[0] === "192.0.2.200");
  } finally { okDot.close(); await _drainTcpHandles(); }
}

async function run() {
  try { await _runTests(); }
  finally { await _drainTcpHandles(); }
}

async function _runTests() {
  _resetAll();

  testDnsErrorPermanentClassification();

  // ============================================================
  // Item B4 — SVCB / HTTPS rdata parsing
  // ============================================================

  var parseSvcb = dnsModule._parseSvcbRdata;

  // ---- AliasMode (priority=0) ----
  var aliasRd = _svcbAliasRdata("foo.example.com");
  var aliasMsg = Buffer.alloc(2 + aliasRd.length);
  aliasRd.copy(aliasMsg, 2);
  var aliasParsed = parseSvcb(aliasMsg, 2, aliasRd.length);
  check("SVCB AliasMode: priority is 0",
    aliasParsed.priority === 0);
  check("SVCB AliasMode: target carries owner-relative name",
    aliasParsed.target === "foo.example.com");
  check("SVCB AliasMode: params object is empty",
    Object.keys(aliasParsed.params).length === 0);

  // ---- ServiceMode with alpn + port + ipv4hint (RFC 9460 §A example) ----
  var alpnVal = _alpnValueBuf(["h2", "h3"]);
  var portVal = Buffer.from([0x01, 0xbb]);                                     // 443
  var ipv4Val = Buffer.from([192, 0, 2, 1, 198, 51, 100, 7]);                  // 192.0.2.1, 198.51.100.7
  var serviceRd = _svcbServiceRdata(1, "svc.example.net", [
    { key: 1, value: alpnVal },                                                // alpn
    { key: 3, value: portVal },                                                // port
    { key: 4, value: ipv4Val },                                                // ipv4hint
  ]);
  var serviceMsg = Buffer.alloc(2 + serviceRd.length);
  serviceRd.copy(serviceMsg, 2);
  var serviceParsed = parseSvcb(serviceMsg, 2, serviceRd.length);
  check("SVCB ServiceMode: priority preserved",
    serviceParsed.priority === 1);
  check("SVCB ServiceMode: target preserved",
    serviceParsed.target === "svc.example.net");
  check("SVCB ServiceMode: alpn list parses h2 + h3",
    Array.isArray(serviceParsed.params.alpn) &&
    serviceParsed.params.alpn[0] === "h2" &&
    serviceParsed.params.alpn[1] === "h3");
  check("SVCB ServiceMode: port parses to 443",
    serviceParsed.params.port === 443);
  check("SVCB ServiceMode: ipv4hint parses both addresses",
    Array.isArray(serviceParsed.params.ipv4hint) &&
    serviceParsed.params.ipv4hint[0] === "192.0.2.1" &&
    serviceParsed.params.ipv4hint[1] === "198.51.100.7");

  // ---- ServiceMode with ipv6hint + dohpath ----
  var v6Bytes = Buffer.alloc(16);
  v6Bytes[0] = 0x20; v6Bytes[1] = 0x01; v6Bytes[2] = 0x0d; v6Bytes[3] = 0xb8;
  v6Bytes[15] = 0x01;
  var dohpathVal = Buffer.from("/dns-query{?dns}", "utf8");
  var v6Rd = _svcbServiceRdata(2, "svc.example.net", [
    { key: 6, value: v6Bytes },                                                // ipv6hint
    { key: 7, value: dohpathVal },                                             // dohpath
  ]);
  var v6Msg = Buffer.alloc(2 + v6Rd.length);
  v6Rd.copy(v6Msg, 2);
  var v6Parsed = parseSvcb(v6Msg, 2, v6Rd.length);
  check("SVCB ServiceMode: ipv6hint parses single address",
    Array.isArray(v6Parsed.params.ipv6hint) &&
    v6Parsed.params.ipv6hint.length === 1);
  check("SVCB ServiceMode: dohpath parses",
    v6Parsed.params.dohpath === "/dns-query{?dns}");

  // ---- ServiceMode with mandatory + ech ----
  var mandVal = Buffer.from([0x00, 0x01, 0x00, 0x04]);                         // mandatory keys: alpn, ipv4hint
  var echVal = Buffer.from([0xfe, 0x0d, 0x00, 0x10, 0xab, 0xcd]);              // opaque ECHConfigList bytes
  var ipv4Val2 = Buffer.from([10, 0, 0, 1]);
  var mandRd = _svcbServiceRdata(3, "svc.example.net", [
    { key: 0, value: mandVal },                                                // mandatory
    { key: 1, value: _alpnValueBuf(["h2"]) },                                  // alpn
    { key: 4, value: ipv4Val2 },                                               // ipv4hint
    { key: 5, value: echVal },                                                 // ech
  ]);
  var mandMsg = Buffer.alloc(2 + mandRd.length);
  mandRd.copy(mandMsg, 2);
  var mandParsed = parseSvcb(mandMsg, 2, mandRd.length);
  check("SVCB ServiceMode: mandatory list parses to numeric keys",
    Array.isArray(mandParsed.params.mandatory) &&
    mandParsed.params.mandatory[0] === 1 &&
    mandParsed.params.mandatory[1] === 4);
  check("SVCB ServiceMode: ech surfaced as opaque Buffer",
    Buffer.isBuffer(mandParsed.params.ech) &&
    mandParsed.params.ech.length === echVal.length);

  // ---- Malformed: ascending-key violation ----
  var badOrderRd = _svcbServiceRdata(1, "svc.example.net", [
    { key: 4, value: Buffer.from([10, 0, 0, 1]) },
    { key: 1, value: _alpnValueBuf(["h2"]) },                                  // out of order!
  ]);
  var badOrderMsg = Buffer.alloc(2 + badOrderRd.length);
  badOrderRd.copy(badOrderMsg, 2);
  check("SVCB malformed: ascending-key violation throws dns/svcb-malformed",
    _throws(function () { parseSvcb(badOrderMsg, 2, badOrderRd.length); }, "dns/svcb-malformed"));

  // ---- Malformed: port SvcParam wrong length ----
  var badPortRd = _svcbServiceRdata(1, "svc.example.net", [
    { key: 3, value: Buffer.from([0x01]) },                                    // 1 byte, must be 2
  ]);
  var badPortMsg = Buffer.alloc(2 + badPortRd.length);
  badPortRd.copy(badPortMsg, 2);
  check("SVCB malformed: port wrong length throws dns/svcb-malformed",
    _throws(function () { parseSvcb(badPortMsg, 2, badPortRd.length); }, "dns/svcb-malformed"));

  // ---- Unknown SvcParamKey surfaces under params.unknown ----
  var unkRd = _svcbServiceRdata(1, "svc.example.net", [
    { key: 1, value: _alpnValueBuf(["h2"]) },
    { key: 99, value: Buffer.from([0xde, 0xad, 0xbe, 0xef]) },                 // unknown key
  ]);
  var unkMsg = Buffer.alloc(2 + unkRd.length);
  unkRd.copy(unkMsg, 2);
  var unkParsed = parseSvcb(unkMsg, 2, unkRd.length);
  check("SVCB unknown SvcParamKey: surfaces under params.unknown",
    unkParsed.params.unknown && Buffer.isBuffer(unkParsed.params.unknown[99]) &&
    unkParsed.params.unknown[99].length === 4);

  // ---- SVCB query: end-to-end via system-resolver fixture (TCP responder) ----
  _resetAll();
  var serviceReply = _buildDnsReply({
    qname:   "example.com",
    qtype:   64,
    answers: [{
      name:  "example.com",
      type:  64,
      ttl:   60,
      rdata: _svcbServiceRdata(1, "svc.example.net", [
        { key: 1, value: _alpnValueBuf(["h2"]) },
        { key: 3, value: Buffer.from([0x01, 0xbb]) },
      ]),
    }],
  });
  var tcpFixture = await _startTcpResponder(serviceReply);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + tcpFixture.port]);
  dnsModule.setLookupTimeoutMs(5000);
  var svcbResults = await dnsModule.querySvcb("example.com", { transport: "system" });
  check("querySvcb (system transport): returns parsed records",
    Array.isArray(svcbResults) && svcbResults.length === 1 &&
    svcbResults[0].priority === 1 &&
    svcbResults[0].target === "svc.example.net" &&
    svcbResults[0].params.alpn[0] === "h2" &&
    svcbResults[0].params.port === 443);
  tcpFixture.srv.close();
  _resetAll();

  // ---- queryHttps: same path, different QTYPE (65) ----
  var httpsReply = _buildDnsReply({
    qname:   "example.com",
    qtype:   65,
    answers: [{
      name:  "example.com",
      type:  65,
      ttl:   60,
      rdata: _svcbServiceRdata(1, ".", [
        { key: 1, value: _alpnValueBuf(["h3", "h2"]) },
      ]),
    }],
  });
  var httpsFix = await _startTcpResponder(httpsReply);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + httpsFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  var httpsResults = await dnsModule.queryHttps("example.com", { transport: "system" });
  check("queryHttps: returns parsed h3+h2 record",
    Array.isArray(httpsResults) && httpsResults.length === 1 &&
    httpsResults[0].params.alpn[0] === "h3" &&
    httpsResults[0].params.alpn[1] === "h2");
  httpsFix.srv.close();
  _resetAll();

  // ---- querySvcb: input validation ----
  check("querySvcb: bad transport throws dns/bad-transport",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { transport: "carrier-pigeon" });
    }, "dns/bad-transport"));
  check("querySvcb: empty host throws dns/bad-host",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("", { transport: "system" });
    }, "dns/bad-host"));
  check("querySvcb: oversize label throws dns/bad-host",
    await _throwsAsync(function () {
      var oversize = "a".repeat(64) + ".example.com";
      return dnsModule.querySvcb(oversize, { transport: "system" });
    }, "dns/bad-host"));
  check("querySvcb: unknown opt key throws (validate-opts)",
    await _throwsAsync(function () {
      return dnsModule.querySvcb("example.com", { trnsport: "system" });
    }));

  // ============================================================
  // Item B13 — DoT alternate transport via resolve(name, type, opts)
  // ============================================================

  // ---- DoT: handshake-failed surfaces dns/dot-handshake-failed ----
  // Connect to a port where nothing listens with a long timeout — the
  // socket error routes through the entry.ready promise and surfaces
  // as the new error code.
  _resetAll();
  // Pick a port that's almost certainly unused. We do a quick binding
  // test to find one — bind a server, capture the port, close it, and
  // immediately point the framework at it.
  var probe = await new Promise(function (resolveP) {
    var s = net.createServer();
    s.unref();
    s.listen(0, "127.0.0.1", function () {
      var p = s.address().port;
      s.close(function () { resolveP(p); });
    });
  });
  dnsModule.useDnsOverTls({
    host:       "127.0.0.1",
    port:       probe,
    servername: "localhost",
  });
  dnsModule.setLookupTimeoutMs(2000);
  check("DoT: handshake to closed port surfaces DnsError",
    await _throwsAsync(function () { return dnsModule.resolve4("example.com"); }));
  _resetAll();

  // ---- resolve(name, type, opts): generic resolver dispatch ----
  // resolve("…", "SVCB") routes through querySvcb. Use the TCP fixture
  // (which our raw-system-query path DOES use) to confirm dispatch.
  var aReply = _buildDnsReply({
    qname:   "example.com",
    qtype:   64,
    answers: [{
      name:  "example.com",
      type:  64,
      ttl:   60,
      rdata: _svcbAliasRdata("svc.example.net"),
    }],
  });
  var aFix = await _startTcpResponder(aReply);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + aFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  var aResolved = await dnsModule.resolve("example.com", "SVCB", { transport: "system" });
  check("resolve(name, 'SVCB'): dispatches to querySvcb",
    Array.isArray(aResolved) && aResolved.length === 1 && aResolved[0].priority === 0);
  aFix.srv.close();
  _resetAll();

  check("resolve: unsupported type throws",
    await _throwsAsync(function () {
      return dnsModule.resolve("example.com", "TXT");
    }, "dns/unsupported-type"));

  // ---- resolve: explicit transport mismatch (doh requested, not configured) ----
  _resetAll();
  check("resolve4: transport='doh' without useDnsOverHttps throws transport-unavailable",
    await _throwsAsync(function () {
      return dnsModule.resolve4("example.com", { transport: "doh" });
    }, "dns/transport-unavailable"));
  check("resolve4: transport='dot' without useDnsOverTls throws transport-unavailable",
    await _throwsAsync(function () {
      return dnsModule.resolve4("example.com", { transport: "dot" });
    }, "dns/transport-unavailable"));
  check("resolve4: bad transport throws bad-transport",
    await _throwsAsync(function () {
      return dnsModule.resolve4("example.com", { transport: "smoke-signal" });
    }, "dns/bad-transport"));
  _resetAll();

  // ============================================================
  // Item B14 — DDR (Discovery of Designated Resolvers)
  // ============================================================

  // ---- discoverEncrypted: empty result throws dns/ddr-not-discovered ----
  var emptyReply = _buildDnsReply({
    qname:   "_dns.resolver.arpa",
    qtype:   64,
    answers: [],
  });
  var emptyFix = await _startTcpResponder(emptyReply);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + emptyFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  check("discoverEncrypted: empty SVCB set throws dns/ddr-not-discovered",
    await _throwsAsync(function () { return dnsModule.discoverEncrypted(); }, "dns/ddr-not-discovered"));
  emptyFix.srv.close();
  _resetAll();

  // ---- discoverEncrypted: returns DoT + DoH descriptors ----
  // The server publishes two ServiceMode records:
  //   #1 — alpn=dot, port=853
  //   #2 — alpn=h2, dohpath=/dns-query
  var ddrReply = _buildDnsReply({
    qname:   "_dns.resolver.arpa",
    qtype:   64,
    answers: [{
      name:  "_dns.resolver.arpa",
      type:  64,
      ttl:   60,
      rdata: _svcbServiceRdata(1, "doh.example.net", [
        { key: 1, value: _alpnValueBuf(["dot"]) },
        { key: 3, value: Buffer.from([0x03, 0x55]) },                          // 853
      ]),
    }, {
      name:  "_dns.resolver.arpa",
      type:  64,
      ttl:   60,
      rdata: _svcbServiceRdata(2, "doh.example.net", [
        { key: 1, value: _alpnValueBuf(["h2"]) },
        { key: 7, value: Buffer.from("/dns-query", "utf8") },
      ]),
    }],
  });
  var ddrFix = await _startTcpResponder(ddrReply);
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + ddrFix.port]);
  dnsModule.setLookupTimeoutMs(5000);
  var resolvers = await dnsModule.discoverEncrypted();
  check("discoverEncrypted: returns 2 resolver descriptors sorted by priority",
    Array.isArray(resolvers) && resolvers.length === 2 &&
    resolvers[0].priority === 1 && resolvers[1].priority === 2);
  check("discoverEncrypted: first resolver is DoT on port 853",
    resolvers[0].transport === "dot" && resolvers[0].port === 853 &&
    resolvers[0].target === "doh.example.net");
  check("discoverEncrypted: second resolver is DoH with dohpath",
    resolvers[1].transport === "doh" && resolvers[1].dohpath === "/dns-query");
  ddrFix.srv.close();
  _resetAll();

  // ---- discoverEncrypted: bad opt rejected ----
  check("discoverEncrypted: unknown opt key throws (validate-opts)",
    await _throwsAsync(function () {
      return dnsModule.discoverEncrypted({ wrongKey: true });
    }));

  // ============================================================
  // Item B14 — DNR (Discovery of Network-designated Resolvers)
  // ============================================================

  _resetAll();

  // ---- useDesignatedResolvers: empty list throws dns/dnr-no-resolvers ----
  check("useDesignatedResolvers: empty list throws dns/dnr-no-resolvers",
    _throws(function () { dnsModule.useDesignatedResolvers([]); }, "dns/dnr-no-resolvers"));
  check("useDesignatedResolvers: non-array throws dns/dnr-no-resolvers",
    _throws(function () { dnsModule.useDesignatedResolvers(null); }, "dns/dnr-no-resolvers"));

  // ---- useDesignatedResolvers: missing required fields ----
  check("useDesignatedResolvers: doh entry without https url throws dns/dnr-malformed",
    _throws(function () {
      dnsModule.useDesignatedResolvers([{ transport: "doh", url: "http://insecure" }]);
    }, "dns/dnr-malformed"));
  check("useDesignatedResolvers: dot entry without host throws dns/dnr-malformed",
    _throws(function () {
      dnsModule.useDesignatedResolvers([{ transport: "dot" }]);
    }, "dns/dnr-malformed"));
  check("useDesignatedResolvers: unknown transport throws dns/dnr-malformed",
    _throws(function () {
      dnsModule.useDesignatedResolvers([{ transport: "udp" }]);
    }, "dns/dnr-malformed"));

  // ---- useDesignatedResolvers: doh entry configures STATE.doh ----
  var dohRes = dnsModule.useDesignatedResolvers([
    { transport: "doh", url: "https://doh.example.net/dns-query" },
  ]);
  var stateAfterDoh = dnsModule._stateForTest();
  check("useDesignatedResolvers: doh entry configures STATE.doh",
    stateAfterDoh.doh && stateAfterDoh.doh.url === "https://doh.example.net/dns-query");
  check("useDesignatedResolvers: returns active index + count",
    dohRes.active === 0 && dohRes.count === 1);
  _resetAll();

  // ---- useDesignatedResolvers: dot entry configures STATE.dot ----
  dnsModule.useDesignatedResolvers([
    { transport: "dot", host: "1.1.1.1", port: 853, servername: "one.one.one.one" },
  ]);
  var stateAfterDot = dnsModule._stateForTest();
  check("useDesignatedResolvers: dot entry configures STATE.dot",
    stateAfterDot.dot && stateAfterDot.dot.host === "1.1.1.1" &&
    stateAfterDot.dot.port === 853);
  var designated = dnsModule._designatedResolversForTest();
  check("useDesignatedResolvers: persists list for inspection",
    Array.isArray(designated) && designated.length === 1);
  _resetAll();

  // ---- useDesignatedResolvers: tries entries in order, second wins after first fails ----
  // First entry has a malformed url that will be rejected; second is valid.
  // Wrap the call so the first throws then-catches internally and we
  // assert the second (index 1) configures.
  // The framework rejects the malformed url at validation time, so we
  // need an entry that PASSES initial config validation but the
  // *second* succeeds. Use the path where validate succeeds for all
  // and the first one configures (active === 0). For the negative
  // path, an entry with a bad url throws dns/dnr-malformed at the
  // pre-loop validation pass, so the loop never runs. Validate that
  // by passing two valid entries — first succeeds, second is unused.
  var multi = dnsModule.useDesignatedResolvers([
    { transport: "doh", url: "https://primary.example.net/dns-query" },
    { transport: "doh", url: "https://secondary.example.net/dns-query" },
  ]);
  check("useDesignatedResolvers: first valid entry wins active=0",
    multi.active === 0 && multi.count === 2);
  _resetAll();

  // ============================================================
  // _readDnsName robustness — pointer loops + reserved labels
  // ============================================================

  var rd = dnsModule._readDnsName;

  // Pointer loop: byte 12 → pointer back to 12.
  var loopBuf = Buffer.alloc(20);
  loopBuf[12] = 0xc0;
  loopBuf[13] = 12;
  check("_readDnsName: self-referential pointer throws dns/svcb-malformed",
    _throws(function () { rd(loopBuf, 12); }, "dns/svcb-malformed"));

  // Reserved label type bits (0x80) — RFC 1035 reserves label types 01 / 10.
  var reservedBuf = Buffer.alloc(20);
  reservedBuf[12] = 0x80;
  check("_readDnsName: reserved label type throws dns/svcb-malformed",
    _throws(function () { rd(reservedBuf, 12); }, "dns/svcb-malformed"));

  // ============================================================
  // Public-surface error / defensive / adversarial branches —
  // config setters, classifiers, parse + decode faults, lookup
  // cache paths, and transport fault injection
  // ============================================================

  // sync config + classifier + parse branches
  testSetServers();
  testSetResultOrder();
  testSetFamily();
  testSetLookupTimeout();
  testSetCacheTtl();
  testUseDnsOverHttps();
  testUseDnsOverTls();
  testUseSystemResolver();
  testIsNullMx();
  testClassifyDnskeyAlgorithm();
  testClassifyDsDigestType();
  testParseSvcbMalformed();
  testParseSvcbValidVariants();
  testDecodeAnswerRaw();
  testReadDnsName();
  testDesignatedResolversFallback();

  // async / transport branches
  await testLookupIpLiteral();
  await testLookupLocalFormAndCache();
  await testLookupNegativeCache();
  await testLookupOrderingBranches();
  await testLookupDohDotNoResult();
  await testResolveProtocol();
  await testResolveTransportErrors();
  await testResolveDispatch();
  await testResolveSecure();
  await testReverse();
  await testNodeLookup();
  await testSystemRawQueryErrors();
  await testSystemRawQueryV6Bracket();
  await testDiscoverEncryptedBranches();

  // real-handshake DoT / DoH transport round-trips + deadlines
  await testDotSecureTransport();
  await testDohSecureTransport();
  await testDotDecodeAndErrorBranches();
  await testDohDecodeAndErrorBranches();
  await testSecureTransportTimeouts();

  // remaining in-process defensive / adversarial / option-default branches
  await testLocalFormTrailingDot();
  await testEnsureSecureDefaultEnvOverride();
  await testValidateLdhLabelReject();
  testDesignatedResolversNonObjectEntry();
  await testDiscoverEncryptedRethrow();
  testReadDnsNameLimits();
  await testRawQueryTransportUnavailable();
  await testSystemRawQueryNoServers();
  await testSystemRawQueryTimeout();
  await testNativeErrorWraps();
  await testResolveTypeAndNodeLookupBranches();
  await testMoreTransportBranches();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network-dns] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
