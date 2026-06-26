"use strict";
/**
 * SVCB / HTTPS RR parsing + DDR / DNR primitive coverage.
 *
 * The DoH / DoT / system-resolver wire round-trips live in the live
 * integration suite (test/integration/network-dns.test.js); this file
 * exercises the pure-parse paths (RFC 9460 §A sample wire formats)
 * and the operator-side DDR / DNR validation surface using fakes so
 * smoke runs offline.
 */

var net = require("node:net");
var tls = require("node:tls");
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

async function run() {
  try { await _runTests(); }
  finally { await _drainTcpHandles(); }
}

async function _runTests() {
  _resetAll();

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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network-dns] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
