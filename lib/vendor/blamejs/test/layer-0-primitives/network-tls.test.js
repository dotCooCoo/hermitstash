// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.tls — ECH (Encrypted Client Hello) ECHConfigList parser
 * + RFC 9525 strict PKIX server-identity verifier.
 *
 * The ECH path synthesises a draft-ietf-tls-esni-22 ECHConfigList byte
 * string (the value of an SVCB/HTTPS `ech=` SvcParam per RFC 9460
 * paragraph 7.4.2) and asserts the parser returns the documented shape;
 * malformed framing raises `tls/ech-config-malformed`. We do not open
 * a TLS socket here — the test exercises the parsing + opt-shape only,
 * so smoke remains laptop-runnable.
 *
 * The PKIX path synthesises Node-shaped peer-cert objects (subject /
 * subjectaltname) and asserts: SAN-required when present, CN-fallback
 * refusal, wildcard depth limits, partial-wildcard refusal, IP-SAN
 * matching, and IPv6 canonicalization byte-equality.
 *
 * The sections after the PKIX tests drive the CA trust store, PQC
 * key-share surface, OCSP parse/build/evaluate error paths,
 * Certificate-Transparency SCT + Merkle-proof verifiers, the expiry /
 * pinset-drift monitors, and the SNICallback wrapper through every
 * wrong-state, malformed-input, and fault-injected branch reachable
 * without opening a real socket — certificates are synthesised as DER
 * via lib/asn1-der (shape-only; X509Certificate parses subject / issuer
 * / validity / fingerprint / serial off the structure without verifying
 * the signature) so the whole suite stays laptop-runnable.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodeOs     = require("node:os");
var nodePath   = require("node:path");
var nodeTls    = require("node:tls");
var nodeNet    = require("node:net");
var asn1       = require("../../lib/asn1-der");
var auditMod   = require("../../lib/audit");

var nt = b.network.tls;
var C  = b.constants;

// ---- ECHConfigList synthesis -------------------------------------
//
// Build a single ECHConfig at draft-22 version 0xfe0d:
//
//   key_config = uint8 config_id || uint16 kem_id ||
//                opaque<u16> public_key ||
//                vector<u16> [HpkeSymmetricCipherSuite]
//   maximum_name_length = uint8
//   public_name = opaque<u8>
//   extensions = vector<u16> [Extension]
//
// then wrap into an ECHConfigList: uint16 outer_length || ECHConfig[]
function _writeU8(buf, off, v)  { buf[off] = v & 0xff;        return off + 1; }
function _writeU16(buf, off, v) { buf.writeUInt16BE(v & 0xffff, off); return off + 2; }
function _writeBytes(buf, off, src) { src.copy(buf, off); return off + src.length; }

function _buildEchConfigDraft22(opts) {
  opts = opts || {};
  var configId = opts.configId === undefined ? 0x07 : opts.configId;
  var kemId    = opts.kemId    === undefined ? 0x0020 : opts.kemId;  // X25519 HKDF-SHA256
  var pubKey   = opts.publicKey || Buffer.alloc(32, 0xab);           // X25519 32 bytes
  var suites   = opts.cipherSuites || [
    { kdfId: 0x0001, aeadId: 0x0001 },  // HKDF-SHA256, AES-128-GCM
    { kdfId: 0x0001, aeadId: 0x0003 },  // HKDF-SHA256, ChaCha20-Poly1305
  ];
  var maxNameLen = opts.maximumNameLength === undefined ? 64 : opts.maximumNameLength;
  var publicName = Buffer.from(opts.publicName || "public.example.com", "ascii");
  var extensions = opts.extensions || [];

  // serialize cipher_suites
  var suitesBody = Buffer.alloc(suites.length * 4);
  var sp = 0;
  for (var si = 0; si < suites.length; si += 1) {
    sp = _writeU16(suitesBody, sp, suites[si].kdfId);
    sp = _writeU16(suitesBody, sp, suites[si].aeadId);
  }

  // serialize extensions
  var extBodies = [];
  for (var ei = 0; ei < extensions.length; ei += 1) {
    var hdr = Buffer.alloc(4);
    _writeU16(hdr, 0, extensions[ei].type);
    _writeU16(hdr, 2, extensions[ei].data.length);
    extBodies.push(hdr, extensions[ei].data);
  }
  var extJoined = Buffer.concat(extBodies);

  // assemble contents: key_config + max_name + public_name + extensions
  var contents = Buffer.alloc(
    1 +                                // config_id
    2 +                                // kem_id
    2 + pubKey.length +                // u16-prefixed public_key
    2 + suitesBody.length +            // u16-prefixed cipher_suites
    1 +                                // max_name_length
    1 + publicName.length +            // u8-prefixed public_name
    2 + extJoined.length               // u16-prefixed extensions
  );
  var p = 0;
  p = _writeU8(contents, p, configId);
  p = _writeU16(contents, p, kemId);
  p = _writeU16(contents, p, pubKey.length);
  p = _writeBytes(contents, p, pubKey);
  p = _writeU16(contents, p, suitesBody.length);
  p = _writeBytes(contents, p, suitesBody);
  p = _writeU8(contents, p, maxNameLen);
  p = _writeU8(contents, p, publicName.length);
  p = _writeBytes(contents, p, publicName);
  p = _writeU16(contents, p, extJoined.length);
  _writeBytes(contents, p, extJoined);

  // wrap as ECHConfig: uint16 version || uint16 length || contents
  var cfgHdr = Buffer.alloc(4);
  _writeU16(cfgHdr, 0, opts.version === undefined ? 0xfe0d : opts.version);
  _writeU16(cfgHdr, 2, contents.length);
  var cfg = Buffer.concat([cfgHdr, contents]);

  // wrap list: uint16 outer_length || ECHConfig
  var listHdr = Buffer.alloc(2);
  _writeU16(listHdr, 0, cfg.length);
  return Buffer.concat([listHdr, cfg]);
}

function testEchSurface() {
  check("network.tls.parseEchConfigList is a function",
        typeof b.network.tls.parseEchConfigList === "function");
  check("network.tls.connectWithEch is a function",
        typeof b.network.tls.connectWithEch === "function");
  check("NetworkTlsError is a class",
        typeof b.network.tls.NetworkTlsError === "function");
}

function testEchParseDraft22() {
  var raw = _buildEchConfigDraft22({});
  var parsed = b.network.tls.parseEchConfigList(raw);
  check("parsed.rawLength matches input length",
        parsed.rawLength === raw.length);
  check("one ECHConfig produced",
        Array.isArray(parsed.configs) && parsed.configs.length === 1);
  var c = parsed.configs[0];
  check("version is 0xfe0d", c.version === 0xfe0d);
  check("keyConfig.configId roundtrip", c.keyConfig.configId === 0x07);
  check("keyConfig.kemId X25519", c.keyConfig.kemId === 0x0020);
  check("keyConfig.publicKey is 32-byte Buffer",
        Buffer.isBuffer(c.keyConfig.publicKey) && c.keyConfig.publicKey.length === 32);
  check("two cipher suites",
        Array.isArray(c.keyConfig.cipherSuites) && c.keyConfig.cipherSuites.length === 2);
  check("first suite kdf+aead",
        c.keyConfig.cipherSuites[0].kdfId === 0x0001 &&
        c.keyConfig.cipherSuites[0].aeadId === 0x0001);
  check("publicName roundtrip",
        c.publicName === "public.example.com");
  check("maximumNameLength roundtrip",
        c.maximumNameLength === 64);
  check("extensions empty array",
        Array.isArray(c.extensions) && c.extensions.length === 0);
}

function testEchParseAcceptsBase64() {
  var raw = _buildEchConfigDraft22({});
  var b64 = raw.toString("base64");
  var parsed = b.network.tls.parseEchConfigList(b64);
  check("base64 input parses",
        parsed.configs.length === 1 && parsed.configs[0].version === 0xfe0d);
  var threw = false;
  try { b.network.tls.parseEchConfigList("not base64!!!"); }
  catch (e) { threw = e.code === "tls/ech-config-malformed"; }
  check("non-base64 string rejects with ech-config-malformed", threw);
}

function testEchMalformedFraming() {
  // Outer length lies — declares 100 bytes but only 4 follow.
  var bad1 = Buffer.from([0x00, 0x64, 0xfe, 0x0d]);
  var threw1 = false;
  try { b.network.tls.parseEchConfigList(bad1); }
  catch (e) { threw1 = e.code === "tls/ech-config-malformed"; }
  check("outer length mismatch raises ech-config-malformed", threw1);

  // Inner cipher_suites length is 5 — not a multiple of 4.
  var bogusSuites = Buffer.alloc(5, 0x00);
  var raw = _buildEchConfigDraft22({});
  // Locate suites prefix: outer(2) + cfgHdr(4) + configId(1) + kemId(2)
  // + pkLenPrefix(2) + pk(32) = 43; suite-len uint16 starts at 43.
  // Stomp suite-len to 5 bytes so it fails the %4 check.
  raw[43] = 0x00; raw[44] = 0x05;
  // Truncate the buffer to fit the new suite-len (otherwise the
  // contents-end check fires first).
  var truncated = Buffer.concat([raw.slice(0, 45), bogusSuites,
                                 Buffer.alloc(0)]);
  // Re-frame outer + inner length so the malformed-suites check fires
  // before contents-overflow.
  var newInnerLen = truncated.length - 6;  // minus outer(2) + cfgHdr(4)
  truncated.writeUInt16BE(truncated.length - 2, 0);
  truncated.writeUInt16BE(newInnerLen, 4);
  var threw2 = false;
  try { b.network.tls.parseEchConfigList(truncated); }
  catch (e) { threw2 = e.code === "tls/ech-config-malformed"; }
  check("cipher_suites length not multiple of 4 raises ech-config-malformed", threw2);

  // Empty buffer
  var threw3 = false;
  try { b.network.tls.parseEchConfigList(Buffer.alloc(0)); }
  catch (e) { threw3 = e.code === "tls/ech-config-malformed"; }
  check("empty Buffer rejects with ech-config-malformed", threw3);
}

function testEchUnknownVersion() {
  // Future version — parser surfaces raw `body` so the caller can
  // forward it to a Node build that supports it.
  var unknownVer = _buildEchConfigDraft22({ version: 0xfe99 });
  var parsed = b.network.tls.parseEchConfigList(unknownVer);
  check("unknown version present in output",
        parsed.configs.length === 1 && parsed.configs[0].version === 0xfe99);
  check("unknown-version body is a Buffer",
        Buffer.isBuffer(parsed.configs[0].body));
  check("unknown-version body length matches inner length",
        parsed.configs[0].body.length === parsed.configs[0].length);
  check("unknown-version has no keyConfig",
        parsed.configs[0].keyConfig === undefined);
}

function testEchConnectWithEchOptShape() {
  // Verify the option-validation tier: bad shapes throw at config-time
  // with NetworkTlsError. We never actually open a socket.
  var threw1 = false;
  try { b.network.tls.connectWithEch(); }
  catch (e) { threw1 = e instanceof b.network.tls.NetworkTlsError; }
  check("connectWithEch with no opts refuses", threw1);

  var threw2 = false;
  try { b.network.tls.connectWithEch({ host: "" }); }
  catch (e) { threw2 = e instanceof b.network.tls.NetworkTlsError; }
  check("connectWithEch with empty host refuses", threw2);

  var threw3 = false;
  try { b.network.tls.connectWithEch({ host: "x", port: 99999 }); }
  catch (e) { threw3 = e instanceof b.network.tls.NetworkTlsError; }
  check("connectWithEch with out-of-range port refuses", threw3);

  var threw4 = false;
  try { b.network.tls.connectWithEch({ host: "x", ipFamily: 5 }); }
  catch (e) { threw4 = e instanceof b.network.tls.NetworkTlsError; }
  check("connectWithEch with bad ipFamily refuses", threw4);

  var threw5 = false;
  try { b.network.tls.connectWithEch({ host: "x", timeoutMs: -1 }); }
  catch (e) { threw5 = e instanceof b.network.tls.NetworkTlsError; }
  check("connectWithEch with negative timeoutMs refuses", threw5);

  var threw6 = false;
  try { b.network.tls.connectWithEch({ host: "x", echOverride: 12345 }); }
  catch (e) { threw6 = e instanceof b.network.tls.NetworkTlsError; }
  check("connectWithEch with bad-shape echOverride refuses", threw6);

  var threw7 = false;
  try { b.network.tls.connectWithEch({ host: "x", unknownKey: true }); }
  catch (e) { threw7 = e && /unknown option/.test(e.message); }
  check("connectWithEch with unknown opts key refuses via validateOpts", threw7);
}

function testEchConnectWithBadOverrideEchConfig() {
  // echOverride accepted but malformed -> rejects via parseEchConfigList.
  return b.network.tls.connectWithEch({
    host:        "127.0.0.1",
    port:        1,
    echOverride: Buffer.from([0xff, 0xff, 0xff, 0xff]),  // outer length lies
  }).then(function () {
    check("connectWithEch with malformed echOverride should reject", false);
  }).catch(function (e) {
    check("connectWithEch with malformed echOverride rejects ech-config-malformed",
          e && e.code === "tls/ech-config-malformed");
  });
}

// connectWithEch driven against LOCAL servers so the _doConnect success /
// timeout / error handlers (and the echOverride branch) run offline — the
// SVCB/DNS default path is exercised separately; these cover the connect tail.
async function testConnectWithEchAgainstLocalServer() {
  var echCfg = _buildEchConfigDraft22({});

  // Success: echOverride validates, _doConnect connects to a real local
  // TLS 1.3 server, secureConnect fires, the promise resolves the socket.
  // servername must be a hostname (Node forbids an IP ServerName); ECH
  // gracefully degrades on a non-ECH server, so the handshake still
  // completes whether or not this Node build attaches the `ech` option.
  var server = await _startTlsServer();
  try {
    var sock = await nt.connectWithEch({
      host: "127.0.0.1", port: server.port, servername: "localhost",
      echOverride: echCfg, rejectUnauthorized: false, timeoutMs: 5000,
    });
    check("connectWithEch resolves a secured socket via echOverride + local server",
          !!(sock && sock.encrypted === true));
    try { sock.destroy(); } catch (_e) { /* best-effort */ }
  } finally {
    server.close();
  }

  // Error: connect to a port with no listener -> socket 'error' -> reject.
  var closed = await _startTlsServer();
  var deadPort = closed.port;
  closed.close();
  var connErr = null;
  try {
    await nt.connectWithEch({
      host: "127.0.0.1", port: deadPort, servername: "localhost",
      echOverride: echCfg, rejectUnauthorized: false, timeoutMs: 5000,
    });
  } catch (e) { connErr = e; }
  check("connectWithEch rejects when the peer is unreachable (error handler)",
        connErr !== null);

  // Timeout: a plain TCP server that accepts but never speaks TLS, with a
  // tiny timeoutMs -> the handshake stalls -> reject tls/ech-timeout.
  var tcpSrv = nodeNet.createServer(function (s) { s.on("error", function () { /* peer reset */ }); });
  tcpSrv.on("error", function () { /* accept best-effort */ });
  tcpSrv.unref();
  await new Promise(function (res) { tcpSrv.listen(0, "127.0.0.1", res); });
  var stallPort = tcpSrv.address().port;
  var toErr = null;
  try {
    await nt.connectWithEch({
      host: "127.0.0.1", port: stallPort, servername: "localhost",
      echOverride: echCfg, rejectUnauthorized: false, timeoutMs: 40,
    });
  } catch (e) { toErr = e; }
  check("connectWithEch times out when the handshake stalls (tls/ech-timeout)",
        !!(toErr && toErr.code === "tls/ech-timeout"));
  try { tcpSrv.close(); } catch (_e) { /* best-effort */ }
}

// ---- RFC 9525 PKIX strict identity verification ------------------

function _cert(subjectAltname, subjectCN) {
  return {
    subject:        subjectCN === undefined ? {} : { CN: subjectCN },
    subjectaltname: subjectAltname,
  };
}

function testPkixSurface() {
  check("network.tls.checkServerIdentity9525 is a function",
        typeof b.network.tls.checkServerIdentity9525 === "function");
}

function testPkixQuotedSanNoBypass() {
  // Node renders a SAN value containing separators as a JSON-quoted string
  // (CVE-2021-44531/44532). A naive split(",") would break `DNS:"x,
  // DNS:victim.com, y"` — a SINGLE dNSName whose value is the whole quoted
  // blob — into pieces and extract a clean `DNS:victim.com` the cert never
  // asserts. The strict RFC 9525 verifier must be at least as strict as the
  // Node function it replaces: REJECT, never accept the smuggled name.
  var tls  = require("node:tls");
  var host = "victim.com";
  var cert = _cert('DNS:"x, DNS:victim.com, y"', "attacker");
  var bjsErr  = b.network.tls.checkServerIdentity9525(host, cert);
  var nodeErr = tls.checkServerIdentity(host, cert);
  check("quoted-blob SAN does not smuggle a hostname (rejects, matching Node)",
        !!bjsErr && !!nodeErr);

  // Decoded control whitespace in a quoted dNSName must NOT be trimmed away:
  // a quoted value that is a newline-escape then victim.com decodes to a
  // leading LF + victim.com; a trim would reduce it to a bare victim.com that
  // matches a name the certificate never asserts. The value is preserved
  // verbatim, so it fails the exact match — as it does in Node. (Node may
  // throw ERR_TLS_CERT_ALTNAME_FORMAT; either way it does not ACCEPT.)
  function _nodeAccepts(h, c) { try { return tls.checkServerIdentity(h, c) === undefined; } catch (_e) { return false; } }
  var leadCtl = _cert('DNS:"\\u000avictim.com"', "attacker");
  check("leading control-char in quoted SAN is not trimmed into a match",
        b.network.tls.checkServerIdentity9525("victim.com", leadCtl) !== undefined &&
        _nodeAccepts("victim.com", leadCtl) === false);
  var trailCtl = _cert('DNS:"victim.com\\u000a"', "attacker");
  check("trailing control-char in quoted SAN is not trimmed into a match",
        b.network.tls.checkServerIdentity9525("victim.com", trailCtl) !== undefined &&
        _nodeAccepts("victim.com", trailCtl) === false);

  // Same class on the IP path: a smuggled quoted IP value with a control char
  // must not normalize (via a trim) into a clean IP that matches.
  var ipCtl = _cert('IP Address:"198.51.100.1\\u000a"', "attacker");
  check("control-char in quoted IP SAN does not match a clean IP",
        b.network.tls.checkServerIdentity9525("198.51.100.1", ipCtl) !== undefined);
  // Legitimate IP + bracketed IPv6 still match (no trim was needed for those).
  check("legit IPv4 SAN still matches",
        b.network.tls.checkServerIdentity9525("198.51.100.1",
          _cert("IP Address:198.51.100.1")) === undefined);
  // The genuine (whole-blob) dNSName is still matchable exactly.
  var okErr = b.network.tls.checkServerIdentity9525("x, DNS:victim.com, y", cert);
  check("the actual quoted dNSName value matches exactly", okErr === undefined);
  // Legitimate unquoted multi-SAN + wildcard + IP remain accepted (parity).
  check("legit multi-DNS still accepted",
        b.network.tls.checkServerIdentity9525("b.example.com",
          _cert("DNS:a.example.com, DNS:b.example.com")) === undefined);
  check("legit wildcard still accepted",
        b.network.tls.checkServerIdentity9525("foo.example.com",
          _cert("DNS:*.example.com")) === undefined);
}

function testPkixSanRequiredWhenAbsent() {
  // SAN missing entirely + no CN -> tls/pkix-san-required.
  var err = b.network.tls.checkServerIdentity9525("foo.example.com",
    _cert(undefined));
  check("missing SAN refuses with tls/pkix-san-required",
        err && err.code === "tls/pkix-san-required");
}

function testPkixCnFallbackRefused() {
  // Legacy CN-only cert (no SAN, but has CN) -> distinct CN-fallback code,
  // emitted by the exported drop-in itself (RFC 9525 §6.4.4; matches the
  // @primitive doc which promises operators can grep the distinct shape).
  var err = b.network.tls.checkServerIdentity9525("foo.example.com",
    _cert(undefined, "foo.example.com"));
  check("CN-only cert refuses with tls/pkix-cn-fallback-refused",
        err && err.code === "tls/pkix-cn-fallback-refused");
  // No SAN AND no CN still falls through to the generic san-required code.
  var sanErr = b.network.tls.checkServerIdentity9525("foo.example.com",
    _cert(undefined));
  check("no-SAN no-CN cert still refuses with tls/pkix-san-required",
        sanErr && sanErr.code === "tls/pkix-san-required");
  // The internal _checkServerIdentityStrict surfaces the same code:
  var strictErr = b.network.tls._checkServerIdentityStrict("foo.example.com",
    _cert(undefined, "foo.example.com"));
  check("internal strict combiner surfaces tls/pkix-cn-fallback-refused",
        strictErr && strictErr.code === "tls/pkix-cn-fallback-refused");
}

function testPkixDnsExactMatch() {
  var ok = b.network.tls.checkServerIdentity9525("foo.example.com",
    _cert("DNS:foo.example.com"));
  check("exact dNSName match returns undefined", ok === undefined);

  var err = b.network.tls.checkServerIdentity9525("bar.example.com",
    _cert("DNS:foo.example.com"));
  check("non-matching dNSName returns mismatch error",
        err && err.code === "tls/pkix-hostname-mismatch");
}

function testPkixDnsCaseInsensitive() {
  var ok = b.network.tls.checkServerIdentity9525("FOO.example.com",
    _cert("DNS:foo.example.com"));
  check("ASCII case-insensitive match",
        ok === undefined);
}

function testPkixWildcardOneLabelOnly() {
  var ok = b.network.tls.checkServerIdentity9525("foo.example.com",
    _cert("DNS:*.example.com"));
  check("wildcard matches one-deep subdomain", ok === undefined);

  // Wildcard MUST NOT match deeper subdomains.
  var err1 = b.network.tls.checkServerIdentity9525("foo.bar.example.com",
    _cert("DNS:*.example.com"));
  check("wildcard refuses deeper subdomain (RFC 9525 paragraph 6.4.3)",
        err1 && err1.code === "tls/pkix-hostname-mismatch");

  // Wildcard MUST NOT match the apex.
  var err2 = b.network.tls.checkServerIdentity9525("example.com",
    _cert("DNS:*.example.com"));
  check("wildcard refuses apex match",
        err2 && err2.code === "tls/pkix-hostname-mismatch");
}

function testPkixWildcardPartialRefused() {
  // Partial wildcards (`f*o.example.com`) refuse.
  var err1 = b.network.tls.checkServerIdentity9525("foo.example.com",
    _cert("DNS:f*o.example.com"));
  check("partial-wildcard refuses",
        err1 && err1.code === "tls/pkix-hostname-mismatch");

  // Middle-position wildcards (`foo.*.example.com`) refuse.
  var err2 = b.network.tls.checkServerIdentity9525("foo.bar.example.com",
    _cert("DNS:foo.*.example.com"));
  check("middle-position wildcard refuses",
        err2 && err2.code === "tls/pkix-hostname-mismatch");
}

function testPkixWildcardTooBroadRefused() {
  // `*.tld` is too broad — at least 3 labels are required.
  var err = b.network.tls.checkServerIdentity9525("anything.com",
    _cert("DNS:*.com"));
  check("wildcard `*.tld` refuses (too broad)",
        err && err.code === "tls/pkix-hostname-mismatch");
}

function testPkixIpSanIpv4() {
  var ok = b.network.tls.checkServerIdentity9525("198.51.100.1",
    _cert("IP Address:198.51.100.1"));
  check("IPv4 literal matches iPAddress SAN", ok === undefined);

  var err = b.network.tls.checkServerIdentity9525("198.51.100.1",
    _cert("DNS:198.51.100.1"));
  check("IPv4 literal does NOT match dNSName SAN (RFC 9525 paragraph 6.5)",
        err && err.code === "tls/pkix-hostname-mismatch");

  var mismatchErr = b.network.tls.checkServerIdentity9525("198.51.100.2",
    _cert("IP Address:198.51.100.1"));
  check("IPv4 mismatch refuses",
        mismatchErr && mismatchErr.code === "tls/pkix-hostname-mismatch");
}

function testPkixIpSanIpv6Canonicalization() {
  // Same address, different textual forms -> all match.
  var ok1 = b.network.tls.checkServerIdentity9525("2001:db8::1",
    _cert("IP Address:2001:DB8:0000:0000:0000:0000:0000:0001"));
  check("IPv6 expanded form matches abbreviated", ok1 === undefined);

  var ok2 = b.network.tls.checkServerIdentity9525("2001:DB8::1",
    _cert("IP Address:2001:db8::1"));
  check("IPv6 case-insensitive match", ok2 === undefined);

  var err = b.network.tls.checkServerIdentity9525("2001:db8::2",
    _cert("IP Address:2001:db8::1"));
  check("IPv6 mismatch refuses",
        err && err.code === "tls/pkix-hostname-mismatch");
}

function testPkixIpSanCrossFamilyRefuses() {
  var err1 = b.network.tls.checkServerIdentity9525("198.51.100.1",
    _cert("IP Address:2001:db8::c633:6401"));
  check("IPv4 host vs IPv6 SAN refuses",
        err1 && err1.code === "tls/pkix-hostname-mismatch");

  var err2 = b.network.tls.checkServerIdentity9525("2001:db8::1",
    _cert("IP Address:198.51.100.1"));
  check("IPv6 host vs IPv4 SAN refuses",
        err2 && err2.code === "tls/pkix-hostname-mismatch");
}

function testPkixSanWithMultipleEntries() {
  // First entry mismatches, third matches -> matches.
  var ok = b.network.tls.checkServerIdentity9525("api.example.com",
    _cert("DNS:www.example.com, DNS:cdn.example.com, DNS:api.example.com"));
  check("multi-entry SAN matches third entry", ok === undefined);

  // None match.
  var err = b.network.tls.checkServerIdentity9525("zzz.example.com",
    _cert("DNS:www.example.com, DNS:cdn.example.com, DNS:api.example.com"));
  check("multi-entry SAN refuses on no match",
        err && err.code === "tls/pkix-hostname-mismatch");
}

function testPkixHostShape() {
  var err = b.network.tls.checkServerIdentity9525("",
    _cert("DNS:foo.example.com"));
  check("empty host refuses",
        err && err.code === "tls/pkix-hostname-mismatch");

  var err2 = b.network.tls.checkServerIdentity9525("internaĺ.example.com",
    _cert("DNS:internal.example.com"));
  check("non-ASCII host refuses (caller pre-converts to A-label)",
        err2 && err2.code === "tls/pkix-hostname-mismatch");
}

// v0.15.12 (#143) — an outbound TLS connection that honors rejectUnauthorized:
// false (operator opt-in to disable peer-cert validation) must emit an audit +
// observability event so the degraded posture is observable. Capture the event
// through the real operator tap (observability.setTap) — observability has no
// `emit`, so the emit must land on the safeEvent → tap path that an operator
// actually wires (the live connect path is covered in the integration suite
// alongside tls.classical_downgrade).
function testInsecureTlsAudit() {
  var nt = b.network.tls;
  check("auditInsecureTls is exported", typeof nt.auditInsecureTls === "function");

  var observability = require("../../lib/observability");
  var captured = [];
  observability.setTap(function (name, value, labels) { captured.push({ name: name, labels: labels }); });
  try {
    nt.auditInsecureTls({ host: "peer.example", port: 8443, source: "network.tls.connectWithEch" });
  } finally {
    observability.setTap(null);
  }
  var ev = captured.filter(function (c) { return c.name === "tls.insecure_skip_verify"; });
  check("auditInsecureTls emits tls.insecure_skip_verify", ev.length >= 1);
  check("audit event carries host/port/source",
        ev.length >= 1 && ev[0].labels.host === "peer.example" &&
        ev[0].labels.port === 8443 && ev[0].labels.source === "network.tls.connectWithEch");

  var threw = false;
  try { nt.auditInsecureTls(null); } catch (_e) { threw = true; }
  check("auditInsecureTls is drop-silent on bad input (never throws into a connect)", threw === false);
}

// NetworkTlsError carries a terminal-vs-transient signal on err.permanent;
// TlsTrustError is always permanent (a trust-verification failure must never be
// silently retried). Fails CLOSED: only the network-layer ECH failures are
// transient; bad options, malformed config, PKIX validation, and unknown codes
// are permanent.
function testNetworkTlsErrorPermanentClassification() {
  var NetworkTlsError = b.network.tls.NetworkTlsError;
  var TlsTrustError   = b.network.tls.TlsTrustError;
  // NetworkTlsError — permanent (config / validation, retry cannot fix).
  check("NetworkTlsError bad-tls-options is permanent",
        new NetworkTlsError("network-tls/bad-tls-options", "x").permanent === true);
  check("NetworkTlsError pkix-hostname-mismatch is permanent",
        new NetworkTlsError("tls/pkix-hostname-mismatch", "x").permanent === true);
  check("NetworkTlsError ech-config-malformed is permanent",
        new NetworkTlsError("tls/ech-config-malformed", "x").permanent === true);
  check("NetworkTlsError unknown code is permanent (fail closed)",
        new NetworkTlsError("tls/never-defined", "x").permanent === true);
  // NetworkTlsError — transient (network-layer ECH failure, a retry may succeed).
  check("NetworkTlsError ech-connect-failed is transient",
        new NetworkTlsError("tls/ech-connect-failed", "x").permanent === false);
  check("NetworkTlsError ech-timeout is transient",
        new NetworkTlsError("tls/ech-timeout", "x").permanent === false);
  check("NetworkTlsError ech-dns-unavailable is transient",
        new NetworkTlsError("tls/ech-dns-unavailable", "x").permanent === false);
  // TlsTrustError — ALWAYS permanent (trust failures, incl. a network failure
  // during the trust check, must not auto-retry past a trust decision).
  check("TlsTrustError ocsp-not-good is permanent",
        new TlsTrustError("tls/ocsp-not-good", "x").permanent === true);
  check("TlsTrustError connect-failed during trust is still permanent",
        new TlsTrustError("tls/connect-failed", "x").permanent === true);
}

var OID_TLS_FEATURE = "1.3.6.1.5.5.7.1.24";
var OID_CT_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2";
var OID_OCSP_NONCE  = "1.3.6.1.5.5.7.48.1.2";

// ---- synthetic-cert builders --------------------------------------

function _synthCert(opts) {
  opts = opts || {};
  var serial     = opts.serial     || Buffer.from([0x12, 0x34]);
  var cn         = opts.cn         || "Test CA";
  var keyBytes   = opts.keyBytes   || Buffer.from("k-bytes-aaaaaaaaaaaaaaaaaaaaaaaa");
  var notBefore  = opts.notBefore  || "260101000000Z";
  var notAfter   = opts.notAfter   || "270101000000Z";
  var algId    = asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.1.1"), asn1.writeNull()]);
  var cnrdn    = asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeNode(0x0c, Buffer.from(cn, "ascii"))]);
  var name     = asn1.writeSequence([asn1.writeNode(0x31, cnrdn)]);
  var validity = asn1.writeSequence([
    asn1.writeNode(0x17, Buffer.from(notBefore, "ascii")),
    asn1.writeNode(0x17, Buffer.from(notAfter, "ascii")),
  ]);
  var spki     = asn1.writeSequence([algId,
    asn1.writeNode(0x03, Buffer.concat([Buffer.from([0]), keyBytes]))]);
  var version  = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var tbsKids  = [version, asn1.writeInteger(serial), algId, name, validity, name, spki];
  if (opts.exts && opts.exts.length) {
    tbsKids.push(asn1.writeContextExplicit(3, asn1.writeSequence(opts.exts)));
  }
  var tbs = asn1.writeSequence(tbsKids);
  return asn1.writeSequence([tbs, algId, asn1.writeNode(0x03, Buffer.from([0, 0, 0, 0]))]);
}

function _toPem(der) {
  return "-----BEGIN CERTIFICATE-----\n" +
    der.toString("base64").replace(/(.{64})/g, "$1\n") +
    "\n-----END CERTIFICATE-----\n";
}

// Build a REAL, handshake-valid self-signed EC leaf cert (P-256) so a
// localhost tls.createServer can complete a TLS handshake. Unlike
// _synthCert (fake [0,0,0,0] signature, shape-only for X509 field
// parsing), this embeds the true SPKI and an ECDSA-SHA256 signature over
// the tbsCertificate, so a client that connects with
// rejectUnauthorized:false completes 'secureConnect'. Serial defaults to
// _SERIAL so a _buildOcsp staple (default serial _SERIAL) binds to the
// connected peer's serialNumber in ocsp.requireGood.
function _makeRealSelfSignedCert(serial) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var spkiDer = kp.publicKey.export({ type: "spki", format: "der" });
  var sigAlgId = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]);  // ecdsa-with-SHA256
  var cnrdn = asn1.writeSequence([asn1.writeOid("2.5.4.3"),
    asn1.writeNode(0x0c, Buffer.from("localhost", "ascii"))]);
  var name  = asn1.writeSequence([asn1.writeNode(0x31, cnrdn)]);
  var validity = asn1.writeSequence([
    asn1.writeNode(0x17, Buffer.from("250101000000Z", "ascii")),
    asn1.writeNode(0x17, Buffer.from("350101000000Z", "ascii")),
  ]);
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var tbs = asn1.writeSequence([version, asn1.writeInteger(serial || _SERIAL),
    sigAlgId, name, validity, name, spkiDer]);
  var sig = nodeCrypto.sign("sha256", tbs, kp.privateKey);
  var certDer = asn1.writeSequence([tbs, sigAlgId, asn1.writeBitString(sig)]);
  return {
    certPem: _toPem(certDer),
    keyPem:  kp.privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

// Start a localhost TLS server presenting the real self-signed cert. When
// `staple` is a Buffer, the server answers the client's requestOCSP with
// it via the 'OCSPRequest' event. Returns { srv, port, close }.
function _startTlsServer(staple) {
  return new Promise(function (resolve) {
    var m = _makeRealSelfSignedCert(_SERIAL);
    var srv = nodeTls.createServer(
      { key: m.keyPem, cert: m.certPem, minVersion: "TLSv1.2" },
      function (sock) { sock.on("error", function () { /* peer reset */ }); });
    if (Buffer.isBuffer(staple)) {
      srv.on("OCSPRequest", function (_cert, _issuer, cb) { cb(null, staple); });
    }
    srv.on("error", function () { /* listen/accept best-effort */ });
    srv.unref();
    srv.listen(0, "127.0.0.1", function () {
      resolve({
        srv:   srv,
        port:  srv.address().port,
        close: function () { try { srv.close(); } catch (_e) { /* best-effort */ } },
      });
    });
  });
}

function _mustStapleExt() {
  return asn1.writeSequence([
    asn1.writeOid(OID_TLS_FEATURE),
    asn1.writeOctetString(asn1.writeSequence([asn1.writeInteger(Buffer.from([5]))])),
  ]);
}

function _buildSctBytes(opts) {
  opts = opts || {};
  var logId = opts.logId || Buffer.alloc(32, 0xaa);
  var ts = Buffer.alloc(8); ts.writeBigUInt64BE(BigInt(opts.timestamp || 1700000000000));
  var extVec = Buffer.from([0x00, 0x00]);
  var sig = opts.sig || Buffer.from("sigbytes!");
  var sigLen = Buffer.alloc(2); sigLen.writeUInt16BE(sig.length);
  return Buffer.concat([
    Buffer.from([opts.version === undefined ? 0 : opts.version]),
    logId, ts, extVec,
    Buffer.from([opts.hashAlgo === undefined ? 4 : opts.hashAlgo,
                 opts.sigAlgo === undefined ? 3 : opts.sigAlgo]),
    sigLen, sig,
  ]);
}

function _sctListRaw(sctBytesArr, opts) {
  opts = opts || {};
  var parts = [];
  for (var i = 0; i < sctBytesArr.length; i += 1) {
    var l = Buffer.alloc(2); l.writeUInt16BE(sctBytesArr[i].length);
    parts.push(l, sctBytesArr[i]);
  }
  var body = Buffer.concat(parts);
  var outer = Buffer.alloc(2);
  outer.writeUInt16BE(opts.lieOuterLen === undefined ? body.length : opts.lieOuterLen);
  return Buffer.concat([outer, body]);
}

function _sctExt(sctListRaw) {
  return asn1.writeSequence([
    asn1.writeOid(OID_CT_SCT_LIST),
    asn1.writeOctetString(asn1.writeOctetString(sctListRaw)),
  ]);
}

// Build a signed BasicOCSPResponse over a single (serial, issuer) CertID.
function _buildOcsp(o) {
  o = o || {};
  var serial    = o.serial || Buffer.from([0x12, 0x34, 0x56, 0x78]);
  var issuerDer = o.issuerDer;
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var issuerPem = kp.publicKey.export({ type: "spki", format: "pem" });
  var req = nt.ocsp.buildRequest({
    leafCertDer:   _synthCert({ serial: serial, cn: "Leaf", keyBytes: Buffer.from("leaf-key-bytes-aaaaaaaaaaaaaaaa") }),
    issuerCertDer: issuerDer,
    nonce:         false,
  });
  var reqTop  = asn1.readNode(req.requestDer);
  var reqTbs  = asn1.readSequence(reqTop.value)[0];
  var reqList = asn1.readSequence(reqTbs.value)[0];
  var reqOne  = asn1.readSequence(reqList.value)[0];
  var certId  = asn1.readSequence(reqOne.value)[0];

  var certStatus;
  if (o.status === "revoked") {
    certStatus = asn1.writeContextImplicit(1, asn1.writeNode(0x18, Buffer.from("20250101000000Z")));
  } else if (o.status === "unknown") {
    certStatus = asn1.writeContextImplicit(2, Buffer.alloc(0));
  } else {
    certStatus = asn1.writeContextImplicit(0, Buffer.alloc(0));
  }
  var timeTag = o.timeTag === undefined ? 0x18 : o.timeTag;
  var thisU = asn1.writeNode(timeTag, Buffer.from(o.thisUpdate || "20250615000000Z"));
  var srKids = [certId.raw, certStatus, thisU];
  if (o.nextUpdate !== null) {
    srKids.push(asn1.writeContextExplicit(0, asn1.writeNode(0x18,
      Buffer.from(o.nextUpdate || "20991231000000Z"))));
  }
  var singleResponse = asn1.writeSequence(srKids);
  var responderId = asn1.writeContextExplicit(2, asn1.writeOctetString(Buffer.alloc(20, 0xcc)));
  var producedAt  = asn1.writeNode(0x18, Buffer.from("20250615000000Z"));
  var responses   = asn1.writeSequence([singleResponse]);
  var rdKids = [responderId, producedAt, responses];
  if (o.nonce) {
    var nonceExt = asn1.writeSequence([
      asn1.writeOid(OID_OCSP_NONCE),
      asn1.writeOctetString(asn1.writeOctetString(o.nonce)),
    ]);
    rdKids.push(asn1.writeContextExplicit(1, asn1.writeSequence([nonceExt])));
  }
  var tbs = asn1.writeSequence(rdKids);
  var sig = o.badSig
    ? Buffer.alloc(70, 0x00)
    : nodeCrypto.sign("sha256", tbs, kp.privateKey);
  var sigAlg = asn1.writeSequence([asn1.writeOid(o.sigAlgOid || "1.2.840.10045.4.3.2")]);
  var basic  = asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(sig)]);
  var rbInner = asn1.writeSequence([asn1.writeOid("1.3.6.1.5.5.7.48.1.1"), asn1.writeOctetString(basic)]);
  var der = asn1.writeSequence([
    asn1.writeNode(0x0a, Buffer.from([0])),
    asn1.writeContextExplicit(0, rbInner),
  ]);
  return { der: der, issuerPem: issuerPem };
}

function _ctLeafHash(signedEntryDer, ts) {
  var tsBuf = Buffer.alloc(8); tsBuf.writeBigUInt64BE(BigInt(Math.floor(ts)));
  var lenBuf = Buffer.alloc(3); lenBuf.writeUIntBE(signedEntryDer.length, 0, 3);
  var leafBytes = Buffer.concat([
    Buffer.from([0]), Buffer.from([0]), tsBuf, Buffer.from([0, 0]),
    lenBuf, signedEntryDer, Buffer.from([0, 0]),
  ]);
  return nodeCrypto.createHash("sha256")
    .update(Buffer.concat([Buffer.from([0]), leafBytes])).digest();
}
function _ctInner(left, right) {
  return nodeCrypto.createHash("sha256")
    .update(Buffer.concat([Buffer.from([1]), left, right])).digest();
}

var _SERIAL = Buffer.from([0x12, 0x34, 0x56, 0x78]);
var _NOW    = Date.parse("2025-06-15T00:00:01Z");

// =====================================================================
// CA trust store
// =====================================================================

function testAddCaShapes() {
  nt._resetForTest();
  var der = _synthCert({ cn: "Alpha CA" });
  var added = nt.addCa(_toPem(der), { label: "alpha" });
  check("addCa(string PEM) returns one meta", Array.isArray(added) && added.length === 1);
  check("addCa meta carries subject", added[0].subject === "CN=Alpha CA");

  // Buffer input
  var addedBuf = nt.addCa(Buffer.from(_toPem(_synthCert({ cn: "Beta CA" })), "utf8"), { label: "beta" });
  check("addCa(Buffer PEM) works", addedBuf.length === 1 && addedBuf[0].subject === "CN=Beta CA");

  // Bundle with two CERTIFICATE blocks -> two metas.
  var bundle = _toPem(_synthCert({ cn: "Gamma CA", serial: Buffer.from([0x0a]) })) +
               _toPem(_synthCert({ cn: "Delta CA", serial: Buffer.from([0x0b]) }));
  var addedBundle = nt.addCaBundle(bundle, { label: "bundle" });
  check("addCaBundle with two blocks returns two metas", addedBundle.length === 2);

  check("getTrustStore reflects all four", nt.getTrustStore().length === 4);
  check("getCaPems returns four PEMs", nt.getCaPems().length === 4);
  var store = nt.getTrustStore();
  check("getTrustStore entry exposes fingerprint256 + label",
        typeof store[0].fingerprint256 === "string" && store[0].label === "alpha");
  nt._resetForTest();
}

function testAddCaRejections() {
  nt._resetForTest();
  // Non-string non-Buffer -> tls/bad-ca via _normalizePem.
  var e1 = null;
  try { nt.addCa(12345); } catch (e) { e1 = e; }
  check("addCa(number) throws tls/bad-ca", e1 && e1.code === "tls/bad-ca");

  // Path-like string that is not a readable path -> tls/empty-pem.
  var e2 = null;
  try { nt.addCa("/no/such/path/to/ca.pem"); } catch (e) { e2 = e; }
  check("addCa(nonexistent path) throws tls/empty-pem", e2 && e2.code === "tls/empty-pem");

  // Has a BEGIN marker (not path-like) but no CERTIFICATE block -> empty-pem.
  var e3 = null;
  try { nt.addCa("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"); }
  catch (e) { e3 = e; }
  check("addCa(non-CERTIFICATE PEM) throws tls/empty-pem", e3 && e3.code === "tls/empty-pem");

  // CERTIFICATE block with unparseable body -> tls/bad-ca-pem.
  var e4 = null;
  try { nt.addCa("-----BEGIN CERTIFICATE-----\nnot valid base64 @@@\n-----END CERTIFICATE-----"); }
  catch (e) { e4 = e; }
  check("addCa(garbage CERTIFICATE body) throws tls/bad-ca-pem", e4 && e4.code === "tls/bad-ca-pem");

  // Unknown opt key -> validateOpts.
  var e5 = null;
  try { nt.addCa(_toPem(_synthCert({})), { nope: true }); } catch (e) { e5 = e; }
  check("addCa unknown opt throws via validateOpts", e5 && /unknown option/.test(e5.message));
  nt._resetForTest();
}

function testAddCaFromFileAndDir() {
  nt._resetForTest();
  var dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamejs-tls-ca-"));
  try {
    var file = nodePath.join(dir, "single.pem");
    nodeFs.writeFileSync(file, _toPem(_synthCert({ cn: "File CA" })));
    var addedFile = nt.addCa(file, { label: "from-file" });
    check("addCa(file path) reads + parses PEM", addedFile.length === 1 && addedFile[0].subject === "CN=File CA");

    // Directory of certs (only .pem/.crt/.cer are read, sorted).
    var certDir = nodePath.join(dir, "bundle");
    nodeFs.mkdirSync(certDir);
    nodeFs.writeFileSync(nodePath.join(certDir, "a.pem"), _toPem(_synthCert({ cn: "Dir A", serial: Buffer.from([0x21]) })));
    nodeFs.writeFileSync(nodePath.join(certDir, "b.crt"), _toPem(_synthCert({ cn: "Dir B", serial: Buffer.from([0x22]) })));
    nodeFs.writeFileSync(nodePath.join(certDir, "ignore.txt"), "not a cert");
    var addedDir = nt.addCa(certDir, { label: "from-dir" });
    check("addCa(directory) reads only .pem/.crt/.cer", addedDir.length === 2);
  } finally {
    nodeFs.rmSync(dir, { recursive: true, force: true });
    nt._resetForTest();
  }
}

function testRemoveCa() {
  nt._resetForTest();
  var added = nt.addCa(_toPem(_synthCert({ cn: "Rm CA" })), { label: "rm" });
  var fp = added[0].fingerprint256;

  var eBad = null;
  try { nt.removeCa(""); } catch (e) { eBad = e; }
  check("removeCa('') throws tls/bad-fingerprint", eBad && eBad.code === "tls/bad-fingerprint");
  var eBad2 = null;
  try { nt.removeCa(12345); } catch (e) { eBad2 = e; }
  check("removeCa(non-string) throws tls/bad-fingerprint", eBad2 && eBad2.code === "tls/bad-fingerprint");

  check("removeCa(unknown fp) returns 0", nt.removeCa("AA:BB:CC") === 0);
  // Lower-case + match on real fingerprint.
  check("removeCa(known fp, case-insensitive) returns 1", nt.removeCa(fp.toLowerCase()) === 1);
  check("store empty after remove", nt.getTrustStore().length === 0);
  nt._resetForTest();
}

function testRemoveCaByLabel() {
  nt._resetForTest();
  nt.addCa(_toPem(_synthCert({ cn: "L1" })), { label: "keep" });
  nt.addCa(_toPem(_synthCert({ cn: "L2", serial: Buffer.from([0x31]) })), { label: "drop" });
  nt.addCa(_toPem(_synthCert({ cn: "L3", serial: Buffer.from([0x32]) })), { label: "drop" });

  var eBad = null;
  try { nt.removeCaByLabel(""); } catch (e) { eBad = e; }
  check("removeCaByLabel('') throws tls/bad-label", eBad && eBad.code === "tls/bad-label");

  check("removeCaByLabel(unknown) returns 0", nt.removeCaByLabel("nope") === 0);
  check("removeCaByLabel('drop') removes both", nt.removeCaByLabel("drop", { audit: false }) === 2);
  check("one entry survives", nt.getTrustStore().length === 1);
  nt._resetForTest();
}

function testClearAll() {
  nt._resetForTest();
  check("clearAll on empty store returns 0", nt.clearAll() === 0);
  nt.addCa(_toPem(_synthCert({ cn: "C1" })), {});
  nt.addCa(_toPem(_synthCert({ cn: "C2", serial: Buffer.from([0x41]) })), {});
  check("clearAll returns removed count", nt.clearAll({ audit: false }) === 2);
  check("store empty after clearAll", nt.getTrustStore().length === 0);
  nt._resetForTest();
}

function testPurgeExpired() {
  nt._resetForTest();
  nt.addCa(_toPem(_synthCert({ cn: "Fresh", notAfter: "270101000000Z" })), { label: "fresh" });
  nt.addCa(_toPem(_synthCert({ cn: "Expired", serial: Buffer.from([0x51]), notBefore: "190101000000Z", notAfter: "200101000000Z" })), { label: "expired" });
  var removed = nt.purgeExpired({ audit: false });
  check("purgeExpired removes the expired cert only", removed === 1);
  var store = nt.getTrustStore();
  check("only the fresh cert survives purge", store.length === 1 && store[0].label === "fresh");
  check("purgeExpired again returns 0 (nothing left to purge)", nt.purgeExpired() === 0);
  nt._resetForTest();
}

function testExpiringSoon() {
  nt._resetForTest();
  var eBad = null;
  try { nt.expiringSoon(-1); } catch (e) { eBad = e; }
  check("expiringSoon(negative) throws tls/bad-window", eBad && eBad.code === "tls/bad-window");
  var eInf = null;
  try { nt.expiringSoon(Infinity); } catch (e) { eInf = e; }
  check("expiringSoon(Infinity) throws tls/bad-window", eInf && eInf.code === "tls/bad-window");

  nt.addCa(_toPem(_synthCert({ cn: "Soon", notAfter: "270101000000Z" })), { label: "soon" });
  var big = nt.expiringSoon(C.TIME.days(3650));
  check("expiringSoon with wide window lists the cert", big.length === 1 && big[0].label === "soon");
  var none = nt.expiringSoon(0);
  check("expiringSoon(0) lists nothing not-yet-past", none.length === 0);
  nt._resetForTest();
}

function testSystemTrustAndApplyToContext() {
  nt._resetForTest();
  check("isSystemTrustEnabled false by default", nt.isSystemTrustEnabled() === false);
  nt.useSystemTrust(true);
  check("useSystemTrust(true) enables", nt.isSystemTrustEnabled() === true);

  nt.addCa(_toPem(_synthCert({ cn: "Ctx CA" })), {});
  var ctx = nt.applyToContext({ base: { rejectUnauthorized: true } });
  check("applyToContext preserves base keys", ctx.rejectUnauthorized === true);
  check("applyToContext sets ca array", Array.isArray(ctx.ca) && ctx.ca.length >= 1);
  check("applyToContext sets groups from key shares",
        typeof ctx.groups === "string" && ctx.groups.indexOf("X25519MLKEM768") === 0);
  check("systemTrust folds in root certificates",
        ctx.ca.length > 1 || nodeTlsHasNoRoots());

  // Operator-supplied groups override is preserved.
  var ctx2 = nt.applyToContext({ base: { groups: "X25519" } });
  check("applyToContext keeps operator groups override", ctx2.groups === "X25519");

  nt.useSystemTrust(false);
  check("useSystemTrust(false) disables", nt.isSystemTrustEnabled() === false);

  var eBad = null;
  try { nt.applyToContext({ nope: 1 }); } catch (e) { eBad = e; }
  check("applyToContext unknown opt throws via validateOpts", eBad && /unknown option/.test(eBad.message));
  nt._resetForTest();
}
function nodeTlsHasNoRoots() {
  return !Array.isArray(nodeTls.rootCertificates);
}

function testBaselineDrift() {
  nt._resetForTest();
  check("detectBaselineDrift null before capture", nt.detectBaselineDrift() === null);
  nt.captureBaselineFingerprints();
  var drift0 = nt.detectBaselineDrift();
  check("no drift right after capture", drift0 && drift0.drifted === false);

  var added = nt.addCa(_toPem(_synthCert({ cn: "Drift CA" })), {});
  var drift1 = nt.detectBaselineDrift();
  check("adding a CA registers as drift (added)",
        drift1 && drift1.drifted === true && drift1.added.indexOf(added[0].fingerprint256) !== -1);

  nt.captureBaselineFingerprints();
  nt.removeCa(added[0].fingerprint256);
  var drift2 = nt.detectBaselineDrift();
  check("removing a CA registers as drift (removed)",
        drift2 && drift2.drifted === true && drift2.removed.length === 1);
  nt._resetForTest();
}

// =====================================================================
// expiry / pinset-drift monitors
// =====================================================================

function testMonitorValidation() {
  var e1 = null;
  try { nt.expiryMonitor({ intervalMs: 0, windowMs: 1000 }); } catch (e) { e1 = e; }
  check("expiryMonitor bad intervalMs throws tls/bad-interval", e1 && e1.code === "tls/bad-interval");
  var e2 = null;
  try { nt.expiryMonitor({ intervalMs: 1000, windowMs: -1 }); } catch (e) { e2 = e; }
  check("expiryMonitor bad windowMs throws tls/bad-window", e2 && e2.code === "tls/bad-window");
  var e3 = null;
  try { nt.pinsetDriftMonitor({ intervalMs: Infinity }); } catch (e) { e3 = e; }
  check("pinsetDriftMonitor bad intervalMs throws tls/bad-interval", e3 && e3.code === "tls/bad-interval");
}

async function testExpiryMonitorTick() {
  nt._resetForTest();
  nt.addCa(_toPem(_synthCert({ cn: "Mon CA", notAfter: "270101000000Z" })), { label: "mon" });
  var seen = 0;
  var lastRows = null;
  var mon = nt.expiryMonitor({
    intervalMs: 15,
    windowMs:   C.TIME.days(3650),
    onExpiring: function (rows) { seen += 1; lastRows = rows; },
  });
  try {
    await helpers.waitUntil(function () { return seen >= 1; },
      { timeoutMs: 5000, label: "expiryMonitor: onExpiring fired" });
    check("expiryMonitor tick invoked onExpiring", seen >= 1);
    check("onExpiring received the expiring row", lastRows && lastRows.length === 1 && lastRows[0].label === "mon");
  } finally {
    mon.stop();
    mon.stop();  // idempotent second stop is a no-op
    nt._resetForTest();
  }
}

async function testPinsetDriftMonitorTick() {
  nt._resetForTest();
  nt.captureBaselineFingerprints();               // baseline = [] (empty store)
  nt.addCa(_toPem(_synthCert({ cn: "Drift Mon CA" })), {});  // now drifts vs baseline
  var seen = 0;
  var lastDrift = null;
  var mon = nt.pinsetDriftMonitor({
    intervalMs: 15,
    onDrift:    function (d) { seen += 1; lastDrift = d; },
  });
  try {
    await helpers.waitUntil(function () { return seen >= 1; },
      { timeoutMs: 5000, label: "pinsetDriftMonitor: onDrift fired" });
    check("pinsetDriftMonitor tick invoked onDrift", seen >= 1);
    check("onDrift reports the added fingerprint", lastDrift && lastDrift.added.length === 1);
  } finally {
    mon.stop();
    nt._resetForTest();
  }
}

// =====================================================================
// PQC key shares
// =====================================================================

function testPqcKeyShares() {
  nt._resetForTest();
  var def = nt.pqc.getKeyShares();
  check("getKeyShares returns default list", Array.isArray(def) && def[0] === "X25519MLKEM768");

  var afterSet = nt.pqc.setKeyShares(["X25519MLKEM768", "X25519"]);
  check("setKeyShares narrows the list", afterSet.length === 2 && afterSet[1] === "X25519");

  var eArr = null;
  try { nt.pqc.setKeyShares("X25519"); } catch (e) { eArr = e; }
  check("setKeyShares(non-array) throws tls/bad-key-shares", eArr && eArr.code === "tls/bad-key-shares");
  var eEmpty = null;
  try { nt.pqc.setKeyShares([]); } catch (e) { eEmpty = e; }
  check("setKeyShares([]) throws tls/bad-key-shares", eEmpty && eEmpty.code === "tls/bad-key-shares");
  var eEntry = null;
  try { nt.pqc.setKeyShares([""]); } catch (e) { eEntry = e; }
  check("setKeyShares(empty entry) throws tls/bad-key-share", eEntry && eEntry.code === "tls/bad-key-share");
  var eColon = null;
  try { nt.pqc.setKeyShares(["X25519:X25519"]); } catch (e) { eColon = e; }
  check("setKeyShares(entry with ':') throws tls/bad-key-share", eColon && eColon.code === "tls/bad-key-share");
  var eLong = null;
  try { nt.pqc.setKeyShares([new Array(66).join("a")]); } catch (e) { eLong = e; }
  check("setKeyShares(>64-char entry) throws tls/bad-key-share", eLong && eLong.code === "tls/bad-key-share");
  var eNum = null;
  try { nt.pqc.setKeyShares([123]); } catch (e) { eNum = e; }
  check("setKeyShares(non-string entry) throws tls/bad-key-share", eNum && eNum.code === "tls/bad-key-share");

  var reset = nt.pqc.resetKeyShares();
  check("resetKeyShares restores default", reset.length === 4 && reset[0] === "X25519MLKEM768");

  // preferredGroups alias surface.
  nt.preferredGroups.set(["X25519"]);
  check("preferredGroups.get reflects set", nt.preferredGroups.get()[0] === "X25519");
  nt.preferredGroups.reset();
  check("preferredGroups.reset restores default", nt.preferredGroups.get().length === 4);
  check("preferredGroups.DEFAULT is the frozen default", nt.preferredGroups.DEFAULT[0] === "X25519MLKEM768");
  check("pqc.DEFAULT_KEY_SHARES exposed", nt.pqc.DEFAULT_KEY_SHARES[0] === "X25519MLKEM768");
  nt._resetForTest();
}

// =====================================================================
// OCSP — parse / build / evaluate
// =====================================================================

function testOcspParseShapeErrors() {
  var cases = [
    { der: Buffer.from([0x30, 0x00]), label: "empty SEQUENCE (no responseStatus)" },
    // successful (0) but no responseBytes.
    { der: asn1.writeSequence([asn1.writeNode(0x0a, Buffer.from([0]))]), label: "successful missing responseBytes" },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var threw = null;
    try { nt.ocsp.parseResponse(cases[i].der); } catch (e) { threw = e; }
    check("parseResponse rejects " + cases[i].label + " with ocsp-bad-shape",
          threw && /ocsp-bad-shape/.test(threw.code || ""));
  }
  // Unknown responseStatus int -> "unknown:<n>".
  var rv = nt.ocsp.parseResponse(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x09]));
  check("parseResponse maps unknown status int to 'unknown:9'", rv.status === "unknown:9");
}

function testOcspParseUnsupportedResponseType() {
  // successful + responseBytes whose responseType OID is not id-pkix-ocsp-basic.
  var rbInner = asn1.writeSequence([asn1.writeOid("1.2.3.4"), asn1.writeOctetString(Buffer.from([0x30, 0x00]))]);
  var der = asn1.writeSequence([asn1.writeNode(0x0a, Buffer.from([0])), asn1.writeContextExplicit(0, rbInner)]);
  var threw = null;
  try { nt.ocsp.parseResponse(der); } catch (e) { threw = e; }
  check("parseResponse rejects non-basic responseType",
        threw && threw.code === "tls/ocsp-unsupported-response-type");
}

function testOcspParseBadTime() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "T CA", keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });
  var fx = _buildOcsp({ issuerDer: issuer, status: "good", thisUpdate: "2025Z" });  // too short for either time form
  var threw = null;
  try { nt.ocsp.parseResponse(fx.der); } catch (e) { threw = e; }
  check("parseResponse rejects malformed time with ocsp-bad-time",
        threw && threw.code === "tls/ocsp-bad-time");
}

function testOcspParseUtcTimeYear() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "U CA", keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });
  // UTCTime (0x17) YY>=50 -> 19xx.
  var fx = _buildOcsp({ issuerDer: issuer, status: "good", timeTag: 0x17, thisUpdate: "750101000000Z", nextUpdate: null });
  var parsed = nt.ocsp.parseResponse(fx.der);
  var ms = parsed.basic.responses[0].thisUpdate;
  check("parseResponse UTCTime YY>=50 maps to 19xx",
        ms === Date.UTC(1975, 0, 1, 0, 0, 0));
}

function testOcspEvaluateBranches() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "Eval CA", keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });

  var good = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL });
  var okRv = nt.ocsp.evaluate(good.der, { issuerPem: good.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW });
  check("evaluate good response ok=true", okRv.ok === true && okRv.certStatus === "good");

  // Missing serialHex -> fail closed.
  var noSer = nt.ocsp.evaluate(good.der, { issuerPem: good.issuerPem, now: _NOW });
  check("evaluate without serialHex fails closed", noSer.ok === false && noSer.signatureValid === true);

  // Serial not present.
  var notFound = nt.ocsp.evaluate(good.der, { issuerPem: good.issuerPem, serialHex: "deadbeef", now: _NOW });
  check("evaluate serial-not-found fails closed", notFound.ok === false &&
        /no entry for the requested cert serial/.test((notFound.errors || []).join(" ")));

  // Revoked.
  var rev = _buildOcsp({ issuerDer: issuer, status: "revoked", serial: _SERIAL });
  var revRv = nt.ocsp.evaluate(rev.der, { issuerPem: rev.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW });
  check("evaluate revoked -> ok=false certStatus=revoked", revRv.ok === false && revRv.certStatus === "revoked");

  // Unknown certStatus.
  var unk = _buildOcsp({ issuerDer: issuer, status: "unknown", serial: _SERIAL });
  var unkRv = nt.ocsp.evaluate(unk.der, { issuerPem: unk.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW });
  check("evaluate unknown certStatus -> ok=false", unkRv.ok === false && unkRv.certStatus === "unknown");

  // Bad signature -> signatureValid false.
  var bad = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL, badSig: true });
  var badRv = nt.ocsp.evaluate(bad.der, { issuerPem: bad.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW });
  check("evaluate bad signature -> ok=false signatureValid=false", badRv.ok === false && badRv.signatureValid === false);

  // Unsupported signature algorithm OID.
  var badAlg = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL, sigAlgOid: "1.2.3.999" });
  var badAlgRv = nt.ocsp.evaluate(badAlg.der, { issuerPem: badAlg.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW });
  check("evaluate unsupported sig-alg -> ok=false signatureValid=false", badAlgRv.ok === false && badAlgRv.signatureValid === false);

  // thisUpdate in the future.
  var fut = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL, thisUpdate: "20990101000000Z" });
  var futRv = nt.ocsp.evaluate(fut.der, { issuerPem: fut.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW });
  check("evaluate future thisUpdate -> ok=false", futRv.ok === false && /future/.test((futRv.errors || []).join(" ")));

  // Past nextUpdate.
  var past = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL, thisUpdate: "20200101000000Z", nextUpdate: "20200201000000Z" });
  var pastRv = nt.ocsp.evaluate(past.der, { issuerPem: past.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW });
  check("evaluate past nextUpdate -> ok=false", pastRv.ok === false && /past nextUpdate/.test((pastRv.errors || []).join(" ")));

  // Non-finite clockSkew falls back to default (does not disable the window).
  var futSkew = nt.ocsp.evaluate(fut.der, { issuerPem: fut.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW, clockSkewMs: Infinity });
  check("evaluate non-finite clockSkew does not disable future-check", futSkew.ok === false);
}

function testOcspEvaluateNonce() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "Nonce CA", keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });
  var nonce = Buffer.from("0123456789abcdef");
  var fx = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL, nonce: nonce });

  var match = nt.ocsp.evaluate(fx.der, { issuerPem: fx.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW, expectedNonce: nonce });
  check("evaluate nonce match -> ok=true nonce=matched", match.ok === true && match.nonce === "matched");

  var mismatch = nt.ocsp.evaluate(fx.der, { issuerPem: fx.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW, expectedNonce: Buffer.from("ffffffffffffffff") });
  check("evaluate nonce mismatch -> ok=false", mismatch.ok === false && /nonce mismatch/.test((mismatch.errors || []).join(" ")));

  // expectedNonce not a Buffer -> shape error.
  var badShape = nt.ocsp.evaluate(fx.der, { issuerPem: fx.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW, expectedNonce: "hex" });
  check("evaluate expectedNonce non-Buffer -> ok=false", badShape.ok === false && /must be a Buffer/.test((badShape.errors || []).join(" ")));

  // Present but not checked (no expectedNonce).
  var present = nt.ocsp.evaluate(fx.der, { issuerPem: fx.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW });
  check("evaluate nonce present-not-checked", present.nonce === "present-not-checked");

  // expectedNonce supplied but response carries none.
  var noNonceFx = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL });
  var missing = nt.ocsp.evaluate(noNonceFx.der, { issuerPem: noNonceFx.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW, expectedNonce: nonce });
  check("evaluate expected nonce but response has none -> ok=false", missing.ok === false && /missing nonce/.test((missing.errors || []).join(" ")));
}

function testOcspEvaluateIssuerBindShapeErrors() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "Bind CA", keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });
  var fx = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL });
  // issuerCertDer not a Buffer -> shape error.
  var rv = nt.ocsp.evaluate(fx.der, { issuerPem: fx.issuerPem, serialHex: _SERIAL.toString("hex"), now: _NOW, issuerCertDer: "not-a-buffer" });
  check("evaluate issuerCertDer non-Buffer -> ok=false", rv.ok === false && /must be a Buffer/.test((rv.errors || []).join(" ")));
}

function testOcspBuildRequest() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "Req CA", keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });
  var leaf = _synthCert({ serial: _SERIAL, cn: "Leaf", keyBytes: Buffer.from("leaf-key-bytes-aaaaaaaaaaaaaaaa") });

  var withNonce = nt.ocsp.buildRequest({ leafCertDer: leaf, issuerCertDer: issuer });
  check("buildRequest default nonce is 16 bytes", Buffer.isBuffer(withNonce.nonce) && withNonce.nonce.length === 16);
  check("buildRequest returns a DER buffer", Buffer.isBuffer(withNonce.requestDer) && withNonce.requestDer.length > 0);

  var noNonce = nt.ocsp.buildRequest({ leafCertDer: leaf, issuerCertDer: issuer, nonce: false });
  check("buildRequest nonce:false -> nonce null", noNonce.nonce === null);

  var custom = nt.ocsp.buildRequest({ leafCertDer: leaf, issuerCertDer: issuer, nonceLen: 32 });
  check("buildRequest nonceLen:32 honored", custom.nonce.length === 32);

  var e1 = null;
  try { nt.ocsp.buildRequest({ leafCertDer: "x", issuerCertDer: issuer }); } catch (e) { e1 = e; }
  check("buildRequest bad leafCertDer throws ocsp-bad-input", e1 && e1.code === "tls/ocsp-bad-input");
  var e2 = null;
  try { nt.ocsp.buildRequest({ leafCertDer: leaf, issuerCertDer: 42 }); } catch (e) { e2 = e; }
  check("buildRequest bad issuerCertDer throws ocsp-bad-input", e2 && e2.code === "tls/ocsp-bad-input");
  var e3 = null;
  try { nt.ocsp.buildRequest({ leafCertDer: leaf, issuerCertDer: issuer, nonceLen: 99 }); } catch (e) { e3 = e; }
  check("buildRequest out-of-range nonceLen throws ocsp-bad-nonce-len", e3 && e3.code === "tls/ocsp-bad-nonce-len");
}

async function testOcspFetchGuards() {
  var e1 = null;
  try { await nt.ocsp.fetch({ leafPem: 123 }); } catch (e) { e1 = e; }
  check("ocsp.fetch bad input throws ocsp-bad-input", e1 && e1.code === "tls/ocsp-bad-input");

  var e2 = null;
  try { await nt.ocsp.fetch({ leafPem: "not a cert", issuerPem: "also not a cert" }); } catch (e) { e2 = e; }
  check("ocsp.fetch unparseable PEM throws ocsp-bad-cert", e2 && e2.code === "tls/ocsp-bad-cert");

  // Valid certs with no AIA responder URL -> ocsp-no-responder.
  var leafPem = _toPem(_synthCert({ cn: "Fetch Leaf", serial: _SERIAL }));
  var issuerPem = _toPem(_synthCert({ cn: "Fetch CA", serial: Buffer.from([0x01]) }));
  var e3 = null;
  try { await nt.ocsp.fetch({ leafPem: leafPem, issuerPem: issuerPem }); } catch (e) { e3 = e; }
  check("ocsp.fetch with no responder URL throws ocsp-no-responder", e3 && e3.code === "tls/ocsp-no-responder");
}

async function testOcspRequireGoodEmpty() {
  var e1 = null;
  try { await nt.ocsp.requireGood({}); } catch (e) { e1 = e; }
  check("requireGood without issuerPem throws ocsp-missing-issuer", e1 && e1.code === "tls/ocsp-missing-issuer");
}

function testOcspMustStaple() {
  var e1 = null;
  try { nt.ocsp.inspectMustStaple("not a buffer"); } catch (e) { e1 = e; }
  check("inspectMustStaple bad input throws ocsp-bad-input", e1 && e1.code === "tls/ocsp-bad-input");

  var msCert = _synthCert({ cn: "MS CA", exts: [_mustStapleExt()] });
  var ms = nt.ocsp.inspectMustStaple(msCert);
  check("inspectMustStaple detects must-staple", ms.mustStaple === true && ms.features.indexOf(5) !== -1);

  var plainCert = _synthCert({ cn: "Plain CA" });
  check("inspectMustStaple on plain cert -> mustStaple false", nt.ocsp.inspectMustStaple(plainCert).mustStaple === false);

  // requireMustStaple predicate.
  var predicate = nt.ocsp.requireMustStaple();
  check("requireMustStaple missing peer cert.raw -> error",
        predicate(null, {}) instanceof nt.TlsTrustError);
  var msViolation = predicate({ raw: msCert }, { ocspBytes: Buffer.alloc(0) });
  check("must-staple cert w/o staple -> ocsp-must-staple-violated",
        msViolation && msViolation.code === "tls/ocsp-must-staple-violated");
  var msOk = predicate({ raw: msCert }, { ocspBytes: Buffer.from([0x30, 0x00]) });
  check("must-staple cert with a staple -> null (permitted)", msOk === null);
  var plainOk = predicate({ raw: plainCert }, {});
  check("non-must-staple cert -> null under default policy", plainOk === null);

  var strict = nt.ocsp.requireMustStaple({ enforceUnconditional: true });
  var strictViolation = strict({ raw: plainCert }, {});
  check("enforceUnconditional refuses plain cert w/o staple",
        strictViolation && strictViolation.code === "tls/ocsp-staple-required");
}

// =====================================================================
// Certificate Transparency
// =====================================================================

function testCtInspectAndParse() {
  var e1 = null;
  try { nt.ct.inspect("not a buffer"); } catch (e) { e1 = e; }
  check("ct.inspect bad input throws ct-bad-input", e1 && e1.code === "tls/ct-bad-input");

  var plain = _synthCert({ cn: "No SCT" });
  check("ct.inspect no-SCT cert -> hasSctExtension false", nt.ct.inspect(plain).hasSctExtension === false);

  var sct = _buildSctBytes({});
  var withSct = _synthCert({ cn: "SCT CA", exts: [_sctExt(_sctListRaw([sct]))] });
  var inspected = nt.ct.inspect(withSct);
  check("ct.inspect SCT cert -> hasSctExtension true", inspected.hasSctExtension === true);

  var e2 = null;
  try { nt.ct.parseScts("nope"); } catch (e) { e2 = e; }
  check("ct.parseScts bad input throws ct-bad-input", e2 && e2.code === "tls/ct-bad-input");
  check("ct.parseScts no-SCT cert -> []", nt.ct.parseScts(plain).length === 0);
  var parsed = nt.ct.parseScts(withSct);
  check("ct.parseScts returns one SCT with hashAlgo/sigAlgo",
        parsed.length === 1 && parsed[0].hashAlgo === 4 && parsed[0].sigAlgo === 3);
}

function testCtVerifyScts() {
  var e1 = null;
  try { nt.ct.verifyScts("nope"); } catch (e) { e1 = e; }
  check("verifyScts bad input throws ct-bad-input", e1 && e1.code === "tls/ct-bad-input");

  var plain = _synthCert({ cn: "No SCT" });
  check("verifyScts no-SCT cert -> reason no-sct-extension", nt.ct.verifyScts(plain).reason === "no-sct-extension");

  // Cert with an SCT + issuer but no log keys -> insufficient-verified, per-sct
  // log-key-missing. (An issuer_key_hash is required to pass the precert gate.)
  var kh = Buffer.alloc(32, 0xcd);
  var sct = _buildSctBytes({});
  var withSct = _synthCert({ cn: "SCT CA", exts: [_sctExt(_sctListRaw([sct]))] });
  var rv = nt.ct.verifyScts(withSct, { issuerKeyHash: kh });
  check("verifyScts with no log keys -> ok false insufficient-verified",
        rv.ok === false && rv.reason === "insufficient-verified" && rv.scts[0].reason === "log-key-missing");
  // Without the issuing CA the embedded (precert_entry) SCT cannot be verified.
  var noIssuer = nt.ct.verifyScts(withSct, {});
  check("verifyScts with an SCT but no issuer -> issuer-key-required",
        noIssuer.ok === false && noIssuer.reason === "issuer-key-required");

  // Parse-error: lie about the outer SCT-list length.
  var badList = _sctListRaw([sct], { lieOuterLen: 9999 });
  var badCert = _synthCert({ cn: "Bad SCT", exts: [_sctExt(badList)] });
  var badRv = nt.ct.verifyScts(badCert, {});
  check("verifyScts with malformed SCT list -> reason parse-error", badRv.reason === "parse-error");

  // requireScts predicate (issuer supplied so the precert gate is satisfied).
  var predicate = nt.ct.requireScts({ issuerKeyHash: kh });
  check("requireScts missing peer cert.raw -> error", predicate(null) instanceof nt.TlsTrustError);
  var noExt = predicate({ raw: plain });
  check("requireScts no-SCT cert -> tls/ct-no-sct-extension", noExt && noExt.code === "tls/ct-no-sct-extension");
  var insuff = predicate({ raw: withSct });
  check("requireScts insufficient -> tls/ct-insufficient-verified", insuff && insuff.code === "tls/ct-insufficient-verified");
}

function testCtVerifyInclusion() {
  var signedEntry = Buffer.from("fake-signed-entry-der-bytes");
  var ts = 1700000000000;
  var leafHash = _ctLeafHash(signedEntry, ts);

  // Trivial single-leaf tree: computedRoot === leafHash.
  var trivial = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1, rootHash: leafHash },
  });
  check("verifyInclusion trivial tree valid", trivial.valid === true);

  // 2-leaf tree, leafIndex 0.
  var sib = Buffer.alloc(32, 0x11);
  var root2 = _ctInner(leafHash, sib);
  var two = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [sib],
    sthFromLog: { treeSize: 2, rootHash: root2.toString("hex") },
  });
  check("verifyInclusion 2-leaf leafIndex0 valid (hex rootHash)", two.valid === true);

  // Root mismatch.
  var mismatch = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1, rootHash: Buffer.alloc(32, 0x00) },
  });
  check("verifyInclusion root mismatch -> valid false root-mismatch", mismatch.valid === false && mismatch.reason === "root-mismatch");

  // Shape errors.
  var errCases = [
    [undefined, "missing-opts"],
    [{}, "missing-sct"],
    [{ sct: {} }, "missing-leaf-certificate"],
    [{ sct: {}, leafCertificate: Buffer.from("x") }, "missing-sth"],
    [{ sct: {}, leafCertificate: Buffer.from("x"), sthFromLog: {}, leafIndex: -1 }, "bad-leaf-index"],
    [{ sct: {}, leafCertificate: Buffer.from("x"), sthFromLog: {}, leafIndex: 0, auditPath: "no" }, "bad-audit-path"],
  ];
  for (var i = 0; i < errCases.length; i += 1) {
    var r = nt.ct.verifyInclusion(errCases[i][0]);
    check("verifyInclusion reason=" + errCases[i][1], r.valid === false && r.reason === errCases[i][1]);
  }

  // Bad SCT timestamp.
  var badTs = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: "nope", signedEntryDer: signedEntry },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1, rootHash: leafHash },
  });
  check("verifyInclusion bad timestamp -> bad-sct-timestamp", badTs.reason === "bad-sct-timestamp");

  // Bad STH root length.
  var badRoot = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1, rootHash: Buffer.alloc(4) },
  });
  check("verifyInclusion bad-sth-root (short buffer)", badRoot.reason === "bad-sth-root");

  // Precert-entry leaf: an issuer makes verifyInclusion hash a precert_entry
  // (issuer_key_hash || tbs, entry_type 1), a different leaf than the x509
  // form. Build the RFC 9162 §4.6 precert leaf hash BY HAND and assert a
  // single-leaf tree's computed root equals it — and that the no-issuer x509
  // leaf does NOT match, proving the issuer binds the leaf.
  var incCert = _synthCert({ cn: "IncPrecert", exts: [_sctExt(_sctListRaw([_buildSctBytes({})]))] });
  var incTbs = nt._stripSctExtensionFromCert(incCert);
  var incKh = Buffer.alloc(32, 0xcd);
  var tsB = Buffer.alloc(8); tsB.writeBigUInt64BE(BigInt(ts));
  var tbsLen = Buffer.alloc(3); tbsLen.writeUIntBE(incTbs.length, 0, 3);
  var precertLeaf = Buffer.concat([
    Buffer.from([0, 0]), tsB, Buffer.from([0, 1]),   // version, leaf_type, ts, entry_type=precert_entry
    incKh, tbsLen, incTbs, Buffer.from([0, 0]),        // issuer_key_hash || uint24(tbs) || tbs || extensions
  ]);
  var precertLeafHash = nodeCrypto.createHash("sha256")
    .update(Buffer.concat([Buffer.from([0]), precertLeaf])).digest();
  var incValid = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: ts }, leafCertificate: incCert,
    leafIndex: 0, auditPath: [], issuerKeyHash: incKh,
    sthFromLog: { treeSize: 1, rootHash: precertLeafHash },
  });
  check("verifyInclusion precert-entry leaf (issuer) valid against the hand-built precert leaf hash",
        incValid.valid === true);
  var incX509 = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: ts }, leafCertificate: incCert,
    leafIndex: 0, auditPath: [], sthFromLog: { treeSize: 1, rootHash: precertLeafHash },
  });
  check("verifyInclusion x509 leaf (no issuer) does not match the precert root (issuer binds the leaf)",
        incX509.valid === false && incX509.reason === "root-mismatch");
}

function testCtVerifyConsistency() {
  var X = Buffer.alloc(32, 0x22);
  var same = nt.ct.verifyConsistency({ firstSize: 1, secondSize: 1, proof: [], firstRoot: X, secondRoot: X });
  check("verifyConsistency m=n=1 valid", same.valid === true);

  var sib = Buffer.alloc(32, 0x33);
  var second = _ctInner(X, sib);
  var grow = nt.ct.verifyConsistency({ firstSize: 1, secondSize: 2, proof: [sib], firstRoot: X, secondRoot: second });
  check("verifyConsistency m=1 n=2 valid", grow.valid === true);

  var mismatch = nt.ct.verifyConsistency({ firstSize: 1, secondSize: 1, proof: [], firstRoot: X, secondRoot: Buffer.alloc(32, 0x99) });
  check("verifyConsistency root mismatch -> valid false", mismatch.valid === false && mismatch.reason === "root-mismatch");

  // Empty proof but first tree not a complete subtree -> walk-failed.
  var incomplete = nt.ct.verifyConsistency({ firstSize: 3, secondSize: 4, proof: [], firstRoot: X, secondRoot: X });
  check("verifyConsistency incomplete-subtree empty proof -> walk-failed", incomplete.valid === false && incomplete.reason === "consistency-walk-failed");

  // Shape errors.
  check("verifyConsistency missing-opts", nt.ct.verifyConsistency(undefined).reason === "missing-opts");
  check("verifyConsistency bad-first-root", nt.ct.verifyConsistency({ firstRoot: Buffer.alloc(4), secondRoot: X }).reason === "bad-first-root");
  check("verifyConsistency bad-second-root", nt.ct.verifyConsistency({ firstRoot: X, secondRoot: Buffer.alloc(4) }).reason === "bad-second-root");
  check("verifyConsistency bad sizes -> walk-failed",
        nt.ct.verifyConsistency({ firstSize: 0, secondSize: 1, proof: [], firstRoot: X, secondRoot: X }).reason === "consistency-walk-failed");
}

// =====================================================================
// parseEchConfigList extra framing branches
// =====================================================================

function testEchExtraFraming() {
  // Single-byte buffer -> too short for outer prefix.
  var e1 = null;
  try { nt.parseEchConfigList(Buffer.from([0x00])); } catch (e) { e1 = e; }
  check("parseEchConfigList 1-byte buffer -> ech-config-malformed", e1 && e1.code === "tls/ech-config-malformed");

  // Truncated ECHConfig header.
  var e2 = null;
  try { nt.parseEchConfigList(Buffer.from([0x00, 0x02, 0xfe, 0x0d])); } catch (e) { e2 = e; }
  check("parseEchConfigList truncated config header -> ech-config-malformed", e2 && e2.code === "tls/ech-config-malformed");

  // Declared config length overflows list.
  var e3 = null;
  try { nt.parseEchConfigList(Buffer.from([0x00, 0x04, 0xfe, 0x0d, 0x00, 0xff])); } catch (e) { e3 = e; }
  check("parseEchConfigList config length overflow -> ech-config-malformed", e3 && e3.code === "tls/ech-config-malformed");
}

// =====================================================================
// wrapSNICallback
// =====================================================================

function testWrapSniCallback() {
  check("wrapSNICallback(non-function) returns arg unchanged", nt.wrapSNICallback(42) === 42);

  // Operator callback that throws synchronously -> wrapper surfaces via cb(err, null).
  var wrapped = nt.wrapSNICallback(function () { throw new Error("boom in SNI"); });
  var cbErr = "unset";
  var cbCtx = "unset";
  wrapped("evil.example.com", function (err, ctx) { cbErr = err; cbCtx = ctx; });
  check("throwing SNICallback surfaces the error to cb", cbErr instanceof Error && /boom in SNI/.test(cbErr.message));
  check("throwing SNICallback passes null ctx", cbCtx === null);

  // Normal callback passes through untouched.
  var okWrapped = nt.wrapSNICallback(function (servername, cb) { cb(null, { servername: servername }); });
  var okCtx = null;
  okWrapped("good.example.com", function (_err, ctx) { okCtx = ctx; });
  check("non-throwing SNICallback passes through", okCtx && okCtx.servername === "good.example.com");

  // Callback that throws AFTER already invoking cb (double-invoke) is swallowed.
  var didNotThrow = true;
  try {
    var dbl = nt.wrapSNICallback(function (servername, cb) { cb(null, null); throw new Error("late throw"); });
    dbl("x", function () {});
  } catch (_e) { didNotThrow = false; }
  check("SNICallback throwing after cb() does not escape the wrapper", didNotThrow === true);
}

// =====================================================================
// buildOptions — TLS request-options builder (PQC groups + TLSv1.3 floor)
// =====================================================================

function testBuildOptionsBranches() {
  nt._resetForTest();

  // Defaults: TLSv1.3 floor + framework PQC group list; groups mirrors ecdhCurve.
  var def = nt.buildOptions();
  check("buildOptions default minVersion is TLSv1.3", def.minVersion === "TLSv1.3");
  check("buildOptions default ecdhCurve leads with the hybrid group",
        def.ecdhCurve.indexOf("X25519MLKEM768") === 0 && def.groups === def.ecdhCurve);

  // opts must be a plain object — an array refuses at the config-time tier.
  var eArr = null;
  try { nt.buildOptions([1, 2]); } catch (e) { eArr = e; }
  check("buildOptions on an array refuses bad-tls-options",
        eArr && eArr.code === "network-tls/bad-tls-options");

  // minVersion is locked to TLSv1.3.
  var eMin = null;
  try { nt.buildOptions({ minVersion: "TLSv1.2" }); } catch (e) { eMin = e; }
  check("buildOptions minVersion!=TLSv1.3 refuses", eMin && eMin.code === "network-tls/bad-tls-options");

  // Narrowing the group list (array + string ecdhCurve + string groups) is accepted.
  check("buildOptions narrows groups[] to a subset",
        nt.buildOptions({ groups: ["X25519MLKEM768"] }).groups === "X25519MLKEM768");
  check("buildOptions narrows ecdhCurve string to a subset",
        nt.buildOptions({ ecdhCurve: "X25519MLKEM768:X25519" }).ecdhCurve === "X25519MLKEM768:X25519");
  check("buildOptions accepts a groups string",
        nt.buildOptions({ groups: "X25519" }).groups === "X25519");

  // Widening to a group outside the framework preferred list refuses.
  var eWide = null;
  try { nt.buildOptions({ groups: ["kyber-nonsense"] }); } catch (e) { eWide = e; }
  check("buildOptions widening to a non-preferred group refuses",
        eWide && eWide.code === "network-tls/bad-tls-options");

  // Empty group list refuses.
  var eEmpty = null;
  try { nt.buildOptions({ groups: [] }); } catch (e) { eEmpty = e; }
  check("buildOptions empty groups[] refuses", eEmpty && eEmpty.code === "network-tls/bad-tls-options");

  // An empty-string entry inside the group list refuses.
  var eBadEntry = null;
  try { nt.buildOptions({ groups: [""] }); } catch (e) { eBadEntry = e; }
  check("buildOptions empty-string group entry refuses", eBadEntry && eBadEntry.code === "network-tls/bad-tls-options");

  // groups that is neither string nor array (but defined) refuses.
  var eShape = null;
  try { nt.buildOptions({ groups: 123 }); } catch (e) { eShape = e; }
  check("buildOptions non-string non-array groups refuses", eShape && eShape.code === "network-tls/bad-tls-options");

  // ca normalization: string passes through; Buffer → utf8; array joins with \n.
  var pem1 = "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----";
  var pem2 = "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----";
  check("buildOptions ca string passes through", nt.buildOptions({ ca: pem1 }).ca === pem1);
  check("buildOptions ca Buffer normalizes to utf8",
        nt.buildOptions({ ca: Buffer.from(pem1, "utf8") }).ca === pem1);
  check("buildOptions ca array joins with newline",
        nt.buildOptions({ ca: [pem1, Buffer.from(pem2, "utf8")] }).ca === pem1 + "\n" + pem2);
  check("buildOptions ca null → undefined", nt.buildOptions({ ca: null }).ca === undefined);

  // ca of a wrong scalar type, and a wrong-typed array entry, both refuse.
  var eCa1 = null;
  try { nt.buildOptions({ ca: 42 }); } catch (e) { eCa1 = e; }
  check("buildOptions ca number refuses", eCa1 && eCa1.code === "network-tls/bad-tls-options");
  var eCa2 = null;
  try { nt.buildOptions({ ca: [pem1, 7] }); } catch (e) { eCa2 = e; }
  check("buildOptions ca array wrong-typed entry refuses", eCa2 && eCa2.code === "network-tls/bad-tls-options");

  // cert / key pass-through + shape guards.
  check("buildOptions cert string passes through", nt.buildOptions({ cert: pem1 }).cert === pem1);
  check("buildOptions key Buffer passes through",
        Buffer.isBuffer(nt.buildOptions({ key: Buffer.from(pem2) }).key));
  var eCert = null;
  try { nt.buildOptions({ cert: 5 }); } catch (e) { eCert = e; }
  check("buildOptions non-string non-Buffer cert refuses", eCert && eCert.code === "network-tls/bad-tls-options");
  var eKey = null;
  try { nt.buildOptions({ key: {} }); } catch (e) { eKey = e; }
  check("buildOptions bad-shape key refuses", eKey && eKey.code === "network-tls/bad-tls-options");

  // sni maps to servername; empty sni refuses.
  check("buildOptions sni maps to servername",
        nt.buildOptions({ sni: "internal.example.com" }).servername === "internal.example.com");
  var eSni = null;
  try { nt.buildOptions({ sni: "" }); } catch (e) { eSni = e; }
  check("buildOptions empty sni refuses", eSni && eSni.code === "network-tls/bad-tls-options");

  // An operator-narrowed key-share set is honored as the preferred list.
  nt.pqc.setKeyShares(["X25519"]);
  check("buildOptions uses the operator-narrowed key-share set",
        nt.buildOptions().groups === "X25519");
  nt._resetForTest();
}

// =====================================================================
// OCSP over a real localhost TLS handshake — connect / requireStapled /
// requireGood drive the _connectAndCheckOcsp socket path end-to-end.
// =====================================================================

async function testOcspConnectRealPaths() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "RG CA",
    keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });

  // 1. connect, server does not staple → resolves with ocspBytes null.
  var s1 = await _startTlsServer(undefined);
  try {
    var r1 = await nt.ocsp.connect({ host: "127.0.0.1", port: s1.port,
      rejectUnauthorized: false, servername: "localhost" });
    check("ocsp.connect no-staple resolves with peerCert and ocspBytes null",
          r1 && r1.ocspBytes === null && r1.peerCert && !!r1.peerCert.serialNumber);
  } finally { s1.close(); }

  // 2. requireStapled, no staple → refuses (TlsTrustError).
  var s2 = await _startTlsServer(undefined);
  var e2 = null;
  try {
    await nt.ocsp.requireStapled({ host: "127.0.0.1", port: s2.port,
      rejectUnauthorized: false, servername: "localhost" });
  } catch (e) { e2 = e; } finally { s2.close(); }
  check("ocsp.requireStapled with no staple refuses", e2 instanceof nt.TlsTrustError);

  // 3. requireStapled with a non-empty staple → resolves carrying the bytes.
  var s3 = await _startTlsServer(Buffer.from([0x30, 0x00]));
  try {
    var r3 = await nt.ocsp.requireStapled({ host: "127.0.0.1", port: s3.port,
      rejectUnauthorized: false, servername: "localhost" });
    check("ocsp.requireStapled with a staple resolves ocspBytes",
          Buffer.isBuffer(r3.ocspBytes) && r3.ocspBytes.length === 2);
  } finally { s3.close(); }

  // 4. connect to a closed port → the socket 'error' handler rejects.
  var e4 = null;
  try {
    await nt.ocsp.connect({ host: "127.0.0.1", port: 1,
      rejectUnauthorized: false, servername: "localhost" });
  } catch (e) { e4 = e; }
  check("ocsp.connect to a closed port rejects", e4 !== null);

  // 5. requireGood — staple binds a DIFFERENT serial → evaluation fails,
  //    requireGood throws tls/ocsp-not-good.
  var badFx = _buildOcsp({ issuerDer: issuer, status: "good", serial: Buffer.from([0x99, 0x99]) });
  var s5 = await _startTlsServer(badFx.der);
  var e5 = null;
  try {
    await nt.ocsp.requireGood({ host: "127.0.0.1", port: s5.port,
      rejectUnauthorized: false, servername: "localhost", issuerPem: badFx.issuerPem });
  } catch (e) { e5 = e; } finally { s5.close(); }
  check("ocsp.requireGood with a wrong-serial staple throws ocsp-not-good",
        e5 && e5.code === "tls/ocsp-not-good");

  // 6. requireGood — staple binds the peer serial (_SERIAL), good + fresh →
  //    resolves with a passing evaluation.
  var goodFx = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL });
  var s6 = await _startTlsServer(goodFx.der);
  try {
    var r6 = await nt.ocsp.requireGood({ host: "127.0.0.1", port: s6.port,
      rejectUnauthorized: false, servername: "localhost", issuerPem: goodFx.issuerPem });
    check("ocsp.requireGood with a good staple resolves ok",
          r6 && r6.ocspEvaluation && r6.ocspEvaluation.ok === true);
  } finally { s6.close(); }
}

// =====================================================================
// OCSP issuer/leaf cert-shape errors (buildRequest DER walk) + evaluate
// deep issuer-binding (RFC 6960 §4.1.1) branches.
// =====================================================================

function testOcspCertShapeErrors() {
  var leaf   = _synthCert({ serial: _SERIAL, cn: "Leaf",
    keyBytes: Buffer.from("leaf-key-bytes-aaaaaaaaaaaaaaaa") });
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "Shape CA",
    keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });

  // issuerCertDer is a Buffer but not a SEQUENCE (an OCTET STRING).
  var e1 = null;
  try { nt.ocsp.buildRequest({ leafCertDer: leaf, issuerCertDer: Buffer.from([0x04, 0x01, 0x00]) }); }
  catch (e) { e1 = e; }
  check("buildRequest non-SEQUENCE issuer cert throws ocsp-bad-issuer-cert",
        e1 && e1.code === "tls/ocsp-bad-issuer-cert");

  // issuer cert is a SEQUENCE whose tbs lacks the SPKI field.
  var shortTbs = asn1.writeSequence([asn1.writeSequence([asn1.writeInteger(Buffer.from([1]))])]);
  var e2 = null;
  try { nt.ocsp.buildRequest({ leafCertDer: leaf, issuerCertDer: shortTbs }); }
  catch (e) { e2 = e; }
  check("buildRequest issuer cert lacking SPKI throws ocsp-bad-issuer-cert",
        e2 && e2.code === "tls/ocsp-bad-issuer-cert");

  // leafCertDer is a Buffer but not a SEQUENCE (issuer walk succeeds first).
  var e3 = null;
  try { nt.ocsp.buildRequest({ leafCertDer: Buffer.from([0x04, 0x01, 0x00]), issuerCertDer: issuer }); }
  catch (e) { e3 = e; }
  check("buildRequest non-SEQUENCE leaf cert throws ocsp-bad-leaf-cert",
        e3 && e3.code === "tls/ocsp-bad-leaf-cert");
}

function testOcspEvaluateDeepBinding() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "DeepBind CA",
    keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });
  var other  = _synthCert({ serial: Buffer.from([0x02]), cn: "Other CA",
    keyBytes: Buffer.from("other-ca-key-bytes-bbbbbbbbbbbb") });
  var fx = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL });
  var serialHex = _SERIAL.toString("hex");

  // Unparseable issuer public key PEM → verify throws, caught → ok:false.
  var badKey = nt.ocsp.evaluate(fx.der, {
    issuerPem: "-----BEGIN PUBLIC KEY-----\nbm90LWEta2V5\n-----END PUBLIC KEY-----\n",
    serialHex: serialHex, now: _NOW });
  check("evaluate with an unparseable issuer key -> ok false",
        badKey.ok === false && /issuer public key parse failed/.test((badKey.errors || []).join(" ")));

  // issuerCertDer MATCHES the CertID issuer → the §4.1.1 name/key bind passes.
  var bound = nt.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: serialHex, now: _NOW, issuerCertDer: issuer });
  check("evaluate with a matching issuerCertDer binds and stays ok",
        bound.ok === true && bound.certStatus === "good");

  // issuerCertDer is a DIFFERENT issuer → name/key hash mismatch, fail closed.
  var wrong = nt.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: serialHex, now: _NOW, issuerCertDer: other });
  check("evaluate with a wrong issuerCertDer -> ok false (wrong-issuer bind)",
        wrong.ok === false && /issuerNameHash|issuerKeyHash/.test((wrong.errors || []).join(" ")));
}

// =====================================================================
// CT SCT verification — per-SCT failure branches with a present log key.
// =====================================================================

function testCtVerifyMoreScts() {
  var ecPub = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .publicKey.export({ type: "spki", format: "pem" });
  // The SCT log_id must be SHA-256(log key SPKI) so the verifier's log-id
  // binding passes and these per-SCT failure branches are reached.
  var logId = nodeCrypto.createHash("sha256")
    .update(nodeCrypto.createPublicKey(ecPub).export({ type: "spki", format: "der" })).digest();
  var logHex = logId.toString("hex");
  var kh = Buffer.alloc(32, 0xcd);   // issuer_key_hash — get past the precert gate
  function _logKeys(pem) { var m = {}; m[logHex] = pem; return m; }
  function _opts(pem) { return { logKeys: _logKeys(pem), minScts: 1, issuerKeyHash: kh }; }

  // Unsupported SCT hash algorithm (not sha256/384/512) with a present key.
  var badHash = _buildSctBytes({ logId: logId, hashAlgo: 99 });
  var badHashCert = _synthCert({ cn: "BadHash", exts: [_sctExt(_sctListRaw([badHash]))] });
  var r1 = nt.ct.verifyScts(badHashCert, _opts(ecPub));
  check("verifyScts unsupported SCT hash algo -> per-sct unsupported-hash-algo",
        r1.scts[0].reason === "unsupported-hash-algo");

  // Log key present but unparseable.
  var okSct  = _buildSctBytes({ logId: logId });
  var okCert = _synthCert({ cn: "OkSct", exts: [_sctExt(_sctListRaw([okSct]))] });
  var r2 = nt.ct.verifyScts(okCert, _opts("not a pem"));
  check("verifyScts unparseable log key -> log-key-parse-failed",
        r2.scts[0].reason === "log-key-parse-failed");

  // SCT claims RSA (sigAlgo 1) but the registered log key is EC → mismatch.
  var rsaClaim = _buildSctBytes({ logId: logId, sigAlgo: 1 });
  var rsaCert  = _synthCert({ cn: "RsaClaim", exts: [_sctExt(_sctListRaw([rsaClaim]))] });
  var r3 = nt.ct.verifyScts(rsaCert, _opts(ecPub));
  check("verifyScts SCT-algo vs log-key-type mismatch -> log-key-algo-mismatch",
        r3.scts[0].reason === "log-key-algo-mismatch");

  // Valid EC key + matching algo but a garbage signature → not verified
  // (verify returns false, or throws and is caught) → insufficient.
  var r4 = nt.ct.verifyScts(okCert, _opts(ecPub));
  check("verifyScts good key but bad signature -> not verified, insufficient",
        r4.ok === false && r4.scts[0].verified === false);
}

// =====================================================================
// checkServerIdentity9525 — remaining refuse branches.
// =====================================================================

function testPkixMoreBranches() {
  // cert argument not an object → hostname-mismatch (peer cert object missing).
  var e1 = nt.checkServerIdentity9525("foo.example.com", null);
  check("checkServerIdentity9525 null cert -> hostname-mismatch",
        e1 && e1.code === "tls/pkix-hostname-mismatch");

  // Empty host string → hostname-mismatch.
  var e2 = nt.checkServerIdentity9525("", _cert("DNS:foo.example.com"));
  check("checkServerIdentity9525 empty host -> hostname-mismatch",
        e2 && e2.code === "tls/pkix-hostname-mismatch");

  // Non-ASCII (U-label) host is refused — operators pre-convert via punycode.
  var e3 = nt.checkServerIdentity9525("héllo.example.com", _cert("DNS:xn--hllo-bpa.example.com"));
  check("checkServerIdentity9525 non-ASCII host refuses",
        e3 && e3.code === "tls/pkix-hostname-mismatch");

  // DNS host but the cert SAN carries only iPAddress entries → mismatch.
  var e4 = nt.checkServerIdentity9525("foo.example.com", _cert("IP Address:198.51.100.7"));
  check("checkServerIdentity9525 DNS host vs IP-only SAN -> mismatch",
        e4 && e4.code === "tls/pkix-hostname-mismatch");

  // A SAN entry without a "kind:value" colon is skipped; a following DNS
  // entry still matches.
  check("checkServerIdentity9525 skips colon-less SAN entries",
        nt.checkServerIdentity9525("foo.example.com",
          _cert("bare-entry, DNS:foo.example.com")) === undefined);

  // The short "IP" SAN kind (not only "IP Address") is honored for IP hosts.
  check("checkServerIdentity9525 honors the short IP: SAN kind",
        nt.checkServerIdentity9525("198.51.100.9", _cert("IP:198.51.100.9")) === undefined);

  // A malformed iPAddress SAN cannot match a valid IP host.
  var e5 = nt.checkServerIdentity9525("2001:db8::1", _cert("IP Address:2001:db8::xyz"));
  check("checkServerIdentity9525 malformed IPv6 SAN -> mismatch",
        e5 && e5.code === "tls/pkix-hostname-mismatch");
}

// =====================================================================
// connectWithEch — real localhost handshake, error + timeout branches.
// =====================================================================

async function testConnectWithEchRealConnect() {
  var validEch = _buildEchConfigDraft22({});

  // alpn wrong shape → config-time throw.
  var eAlpn = null;
  try { nt.connectWithEch({ host: "127.0.0.1", alpn: "h2" }); } catch (e) { eAlpn = e; }
  check("connectWithEch non-array alpn refuses",
        eAlpn instanceof nt.NetworkTlsError && eAlpn.code === "tls/ech-bad-opts");

  // Real connect over a localhost TLS server with an operator echOverride +
  // rejectUnauthorized:false → drives _doConnect, the insecure-TLS audit,
  // and the ECH attach/degrade branch to secureConnect.
  var s1 = await _startTlsServer(undefined);
  try {
    var sock = await nt.connectWithEch({
      host: "127.0.0.1", port: s1.port, servername: "localhost",
      alpn: ["h2"], echOverride: validEch, rejectUnauthorized: false,
    });
    check("connectWithEch resolves a secured socket over localhost",
          sock && sock.encrypted === true);
    try { sock.destroy(); } catch (_e) { /* best-effort */ }
  } finally { s1.close(); }

  // Error path — connect to a closed port rejects.
  var eDead = null;
  try {
    await nt.connectWithEch({ host: "127.0.0.1", port: 1, servername: "localhost",
      echOverride: validEch, rejectUnauthorized: false, timeoutMs: C.TIME.seconds(5) });
  } catch (e) { eDead = e; }
  check("connectWithEch to a closed port rejects", eDead !== null);

  // Timeout path — a plain TCP server that accepts but never speaks TLS.
  var hung = await new Promise(function (resolve) {
    var srv = nodeNet.createServer(function (sock) { sock.on("error", function () {}); });
    srv.on("error", function () {});
    srv.unref();
    srv.listen(0, "127.0.0.1", function () { resolve({ srv: srv, port: srv.address().port }); });
  });
  var eTo = null;
  try {
    await nt.connectWithEch({ host: "127.0.0.1", port: hung.port, servername: "localhost",
      echOverride: validEch, rejectUnauthorized: false, timeoutMs: 150 });
  } catch (e) { eTo = e; } finally { try { hung.srv.close(); } catch (_e) { /* best-effort */ } }
  check("connectWithEch handshake timeout rejects tls/ech-timeout",
        eTo && eTo.code === "tls/ech-timeout");
}

// =====================================================================
// CT SCT-list / single-SCT parse rejections (ct.parseScts throws) +
// verifyInclusion strip + optional-consistency-proof branches.
// =====================================================================

function testCtParseSctErrors() {
  // parseScts propagates a malformed outer length (verifyScts would swallow
  // it as reason:"parse-error"; the raw parse surface throws).
  var badOuter = _synthCert({ cn: "BadOuter",
    exts: [_sctExt(_sctListRaw([_buildSctBytes({})], { lieOuterLen: 9999 }))] });
  var e1 = null;
  try { nt.ct.parseScts(badOuter); } catch (e) { e1 = e; }
  check("ct.parseScts malformed outer length throws ct-bad-list",
        e1 && e1.code === "tls/ct-bad-list");

  // A single SCT shorter than the minimum v1 layout.
  var shortSct = _synthCert({ cn: "ShortSct",
    exts: [_sctExt(_sctListRaw([Buffer.alloc(10)]))] });
  var e2 = null;
  try { nt.ct.parseScts(shortSct); } catch (e) { e2 = e; }
  check("ct.parseScts too-short SCT throws ct-sct-too-short",
        e2 && e2.code === "tls/ct-sct-too-short");

  // An SCT with a non-zero (unsupported) version byte.
  var badVer = _synthCert({ cn: "BadVer",
    exts: [_sctExt(_sctListRaw([_buildSctBytes({ version: 1 })]))] });
  var e3 = null;
  try { nt.ct.parseScts(badVer); } catch (e) { e3 = e; }
  check("ct.parseScts non-v1 SCT throws ct-sct-bad-version",
        e3 && e3.code === "tls/ct-sct-bad-version");
}

// ocsp.fetch composes buildRequest + httpClient; a transport rejection
// (the framework's https-only outbound allowlist refuses the responder URL)
// surfaces as tls/ocsp-fetch-failed. Drives the buildRequest + request +
// catch path without a live responder.
async function testOcspFetchRequestPath() {
  var leafPem   = _toPem(_synthCert({ cn: "FetchReq Leaf", serial: _SERIAL }));
  var issuerPem = _toPem(_synthCert({ cn: "FetchReq CA", serial: Buffer.from([0x01]) }));
  var e1 = null;
  try {
    await nt.ocsp.fetch({ leafPem: leafPem, issuerPem: issuerPem,
      responderUrl: "http://127.0.0.1:1/ocsp", nonce: false });
  } catch (e) { e1 = e; }
  check("ocsp.fetch responder transport failure throws ocsp-fetch-failed",
        e1 && e1.code === "tls/ocsp-fetch-failed");
}

function testCtInclusionExtra() {
  var signedEntry = Buffer.from("fake-signed-entry-der-bytes");
  var ts = 1700000000000;
  var leafHash = _ctLeafHash(signedEntry, ts);

  // sct without signedEntryDer -> verifyInclusion strips the SCT extension
  // from the supplied leaf cert to derive the signed entry itself.
  var sctCert = _synthCert({ cn: "InclLeaf",
    exts: [_sctExt(_sctListRaw([_buildSctBytes({})]))] });
  var stripPath = nt.ct.verifyInclusion({
    sct:             { logIdHex: "aa", timestamp: ts },  // no signedEntryDer
    leafCertificate: sctCert, leafIndex: 0, auditPath: [],
    sthFromLog:      { treeSize: 1, rootHash: Buffer.alloc(32, 0x00) },
  });
  check("verifyInclusion derives the signed entry by stripping the SCT ext",
        stripPath.valid === false && stripPath.reason === "root-mismatch");

  // Inclusion reconciles, but the optional consistency proof does not.
  var incl = nt.ct.verifyInclusion({
    sct:             { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [],
    sthFromLog:      { treeSize: 1, rootHash: leafHash },
    consistency:     { firstSize: 1, firstRoot: Buffer.alloc(32, 0x55), proof: [] },
  });
  check("verifyInclusion with a non-reconciling consistency proof fails closed",
        incl.valid === false &&
        (incl.reason === "consistency-mismatch" || incl.reason === "consistency-walk-failed"));
}

// The SCT + TLS-Feature cert-extension extractors are deliberately tolerant
// of malformed ASN.1 — they return "no extension" rather than throwing so a
// broken peer cert can't crash the CT / must-staple checks.
function testSctAndTlsFeatureTolerance() {
  var malformed = [
    Buffer.from([0x30, 0x82, 0x01, 0x00]),                                     // SEQUENCE, long-form len, no content
    Buffer.from([0x04, 0x01, 0x00]),                                           // OCTET STRING (top not SEQUENCE)
    Buffer.from([0x30, 0x00]),                                                 // empty SEQUENCE (no children)
    asn1.writeSequence([asn1.writeInteger(Buffer.from([1]))]),                 // tbs is INTEGER, not SEQUENCE
    asn1.writeSequence([asn1.writeSequence([asn1.writeInteger(Buffer.from([1]))])]),  // tbs SEQUENCE, no [3] extensions
    asn1.writeSequence([asn1.writeSequence([                                   // [3] wrapping a non-SEQUENCE
      asn1.writeContextExplicit(3, asn1.writeInteger(Buffer.from([1]))),
    ])]),
  ];
  var tolerated = true;
  for (var i = 0; i < malformed.length; i += 1) {
    try {
      if (nt.ct.parseScts(malformed[i]).length !== 0) tolerated = false;
      if (nt.ocsp.inspectMustStaple(malformed[i]).mustStaple !== false) tolerated = false;
    } catch (_e) { tolerated = false; }
  }
  check("SCT + TLS-Feature extractors tolerate malformed cert buffers", tolerated);
  check("ct.inspect on a non-cert buffer -> hasSctExtension false",
        nt.ct.inspect(Buffer.from([0x30, 0x00])).hasSctExtension === false);
}

// RFC 9162 §2.1.3/§2.1.4 Merkle inclusion + consistency walks — multi-level
// audit paths (siblings supplied as opaque 32-byte hashes; the expected root
// is recomputed with the same inner-hash the module uses).
function testCtMerklePaths() {
  var ts = 1700000000000;
  var signedEntry = Buffer.from("merkle-leaf-entry");
  var h1 = _ctLeafHash(signedEntry, ts);
  var s0 = Buffer.alloc(32, 0x11);
  var s1 = Buffer.alloc(32, 0x22);

  // 4-leaf tree, leafIndex 1 (left child then combined on the right).
  var root4 = _ctInner(_ctInner(s0, h1), s1);
  check("verifyInclusion 4-leaf index1 climbs the audit path",
        nt.ct.verifyInclusion({
          sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
          leafCertificate: Buffer.from("x"), leafIndex: 1, auditPath: [s0, s1],
          sthFromLog: { treeSize: 4, rootHash: root4 },
        }).valid === true);

  // 3-leaf tree, right-most leaf (the fn===sn branch).
  var root3 = _ctInner(s0, h1);
  check("verifyInclusion 3-leaf right-most leaf (fn===sn)",
        nt.ct.verifyInclusion({
          sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
          leafCertificate: Buffer.from("x"), leafIndex: 2, auditPath: [s0],
          sthFromLog: { treeSize: 3, rootHash: root3 },
        }).valid === true);

  // Audit path exhausted before the root.
  check("verifyInclusion exhausted audit path -> inclusion-walk-failed",
        nt.ct.verifyInclusion({
          sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
          leafCertificate: Buffer.from("x"), leafIndex: 1, auditPath: [],
          sthFromLog: { treeSize: 4, rootHash: root4 },
        }).reason === "inclusion-walk-failed");

  // Audit path entry that is not a 32-byte hash.
  check("verifyInclusion non-32-byte audit entry -> inclusion-walk-failed",
        nt.ct.verifyInclusion({
          sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
          leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [Buffer.alloc(4)],
          sthFromLog: { treeSize: 2, rootHash: Buffer.alloc(32, 0x00) },
        }).reason === "inclusion-walk-failed");

  // Audit path with trailing entries beyond the root.
  check("verifyInclusion trailing audit entries -> inclusion-walk-failed",
        nt.ct.verifyInclusion({
          sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
          leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [s0, s1],
          sthFromLog: { treeSize: 2, rootHash: Buffer.alloc(32, 0x00) },
        }).reason === "inclusion-walk-failed");

  // Consistency m=2 → n=4 (the odd-index skip loop runs; first tree complete).
  var firstHash = Buffer.alloc(32, 0x33);
  var c0 = Buffer.alloc(32, 0x44);
  check("verifyConsistency m=2 n=4 valid",
        nt.ct.verifyConsistency({ firstSize: 2, secondSize: 4, proof: [c0],
          firstRoot: firstHash, secondRoot: _ctInner(firstHash, c0) }).valid === true);

  // Consistency m=3 → n=4 (first tree NOT a complete subtree; proof shifted).
  var p0 = Buffer.alloc(32, 0x55), p1 = Buffer.alloc(32, 0x66), p2 = Buffer.alloc(32, 0x77);
  check("verifyConsistency m=3 n=4 incomplete-subtree valid",
        nt.ct.verifyConsistency({ firstSize: 3, secondSize: 4, proof: [p0, p1, p2],
          firstRoot: Buffer.alloc(32, 0x88),
          secondRoot: _ctInner(p2, _ctInner(p0, p1)) }).valid === true);
}

// =====================================================================
// Trust-store audit-emit paths + no-argument config-time guards
//
// The CA-store tests above pass { audit: false } to keep the emit side
// quiet, so the DEFAULT-audit emit branch of removeCaByLabel / clearAll /
// purgeExpired never runs, and the no-argument `opts || {}` defaulting of
// applyToContext / the monitors is never taken. Drive those here through
// the real consumer surface.
// =====================================================================

function testTrustStoreAuditEmitAndGuards() {
  nt._resetForTest();

  // removeCaByLabel WITHOUT { audit: false } — the emit branch runs.
  nt.addCa(_toPem(_synthCert({ cn: "AE1" })), { label: "ae" });
  nt.addCa(_toPem(_synthCert({ cn: "AE2", serial: Buffer.from([0x61]) })), { label: "ae" });
  check("removeCaByLabel default-audit removes both", nt.removeCaByLabel("ae") === 2);

  // clearAll WITHOUT { audit: false } — the emit branch runs.
  nt.addCa(_toPem(_synthCert({ cn: "AE3", serial: Buffer.from([0x62]) })), {});
  check("clearAll default-audit clears the store", nt.clearAll() === 1);

  // purgeExpired WITHOUT { audit: false } with a genuinely-expired cert.
  nt.addCa(_toPem(_synthCert({ cn: "Fresh AE", notAfter: "270101000000Z" })), { label: "fresh" });
  nt.addCa(_toPem(_synthCert({ cn: "Old AE", serial: Buffer.from([0x63]),
    notBefore: "190101000000Z", notAfter: "200101000000Z" })), { label: "old" });
  check("purgeExpired default-audit drops the expired cert", nt.purgeExpired() === 1);

  // applyToContext() with NO argument — opts || {} and opts.base || {}
  // both default; PQC groups are still folded in.
  var ctx = nt.applyToContext();
  check("applyToContext() no-arg returns an object", ctx !== null && typeof ctx === "object");
  check("applyToContext() no-arg still sets PQC groups",
        typeof ctx.groups === "string" && ctx.groups.indexOf("X25519MLKEM768") === 0);

  // No-argument monitors default their opts, then throw on the missing
  // intervalMs at the config-time tier.
  var eExp = null;
  try { nt.expiryMonitor(); } catch (e) { eExp = e; }
  check("expiryMonitor() no-arg throws tls/bad-interval", eExp && eExp.code === "tls/bad-interval");
  var eDrift = null;
  try { nt.pinsetDriftMonitor(); } catch (e) { eDrift = e; }
  check("pinsetDriftMonitor() no-arg throws tls/bad-interval", eDrift && eDrift.code === "tls/bad-interval");

  nt._resetForTest();
}

// _isPathLike short-circuits: a string that is too long (> 1 KiB) or that
// carries a CRLF is NOT treated as a filesystem path, so addCa parses it as
// PEM and it fails as empty rather than being stat()'d as a path.
function testCertPathLikeRejections() {
  nt._resetForTest();
  var big = new Array(1600).join("a");   // ~1599 bytes > 1 KiB, no PEM marker
  var eBig = null;
  try { nt.addCa(big); } catch (e) { eBig = e; }
  check("addCa(>1KiB non-PEM string) is not path-like -> tls/empty-pem",
        eBig && eBig.code === "tls/empty-pem");

  var eCrlf = null;
  try { nt.addCa("some\r\ntext"); } catch (e) { eCrlf = e; }
  check("addCa(CRLF non-PEM string) is not path-like -> tls/empty-pem",
        eCrlf && eCrlf.code === "tls/empty-pem");
  nt._resetForTest();
}

// RFC 9525 wildcard label-walk branches not reached by the happy-path
// wildcard tests: an embedded '*' in a non-left-most label, a mismatched
// non-left-most label under a valid left-most wildcard, and an empty
// left-most host label.
function testPkixWildcardLabelWalk() {
  var e1 = b.network.tls.checkServerIdentity9525("a.example.com",
    _cert("DNS:*.exa*ple.com"));
  check("wildcard left label + embedded '*' in a later label refuses",
        e1 && e1.code === "tls/pkix-hostname-mismatch");

  var e2 = b.network.tls.checkServerIdentity9525("foo.example.net",
    _cert("DNS:*.example.com"));
  check("wildcard match with a mismatched later label refuses",
        e2 && e2.code === "tls/pkix-hostname-mismatch");

  var e3 = b.network.tls.checkServerIdentity9525(".example.com",
    _cert("DNS:*.example.com"));
  check("wildcard refuses an empty left-most host label",
        e3 && e3.code === "tls/pkix-hostname-mismatch");
}

// _refuseCnFallback second operand (subjectaltname.length === 0) + the
// _checkServerIdentityStrict delegation-to-9525 tail on a clean SAN.
function testStrictCombinerAndEmptySanCn() {
  var errEmpty = b.network.tls.checkServerIdentity9525("x.example.com",
    { subject: { CN: "x.example.com" }, subjectaltname: "" });
  check("empty-string SAN + CN refuses with tls/pkix-cn-fallback-refused",
        errEmpty && errEmpty.code === "tls/pkix-cn-fallback-refused");

  var ok = b.network.tls._checkServerIdentityStrict("foo.example.com",
    _cert("DNS:foo.example.com"));
  check("strict combiner delegates to the 9525 verifier on a clean SAN", ok === undefined);
}

// wrapSNICallback audit-metadata fallbacks: a NON-string servername maps to
// null and a thrown NON-Error value maps through String(err).
function testWrapSniCallbackNonStringServername() {
  // A NON-Error throw value (no .message field) drives reason -> String(err);
  // a NON-string servername drives servername -> null.
  var thrown = { note: "no-message-field" };
  var wrapped = nt.wrapSNICallback(function () { throw thrown; });
  var cbErr = "unset";
  wrapped(12345, function (err) { cbErr = err; });
  check("throwing SNICallback with non-string servername surfaces the raw throw",
        cbErr === thrown);
}

// =====================================================================
// Monitor tick branches — the "nothing expiring" / "no drift" / no-callback
// / throwing-callback / baseline-uncaptured paths the happy-path monitor
// tests don't reach. Driven through the real timer (safeAsync.repeating);
// audit emissions captured through the documented b.audit.safeEmit test
// seam and restored in a finally.
// =====================================================================

function _captureAudit(bucket) {
  var orig = auditMod.safeEmit;
  auditMod.safeEmit = function (evt) { bucket.push(evt); };
  return function restore() { auditMod.safeEmit = orig; };
}

async function testExpiryMonitorOkTick() {
  nt._resetForTest();
  // Fresh cert + a tiny window -> every tick reports "ok" (nothing expiring).
  nt.addCa(_toPem(_synthCert({ cn: "OK Mon", notAfter: "270101000000Z" })), { label: "ok" });
  var events = [];
  var restore = _captureAudit(events);
  var mon = nt.expiryMonitor({ intervalMs: 15, windowMs: 1 });
  try {
    await helpers.waitUntil(function () {
      return events.some(function (e) {
        return e.action === "network.tls.ca.expiry_check" && e.outcome === "ok";
      });
    }, { timeoutMs: 5000, label: "expiryMonitor: ok tick emitted" });
    check("expiryMonitor emits an 'ok' expiry_check when nothing is expiring", true);
  } finally {
    mon.stop();
    restore();
    nt._resetForTest();
  }
}

async function testExpiryMonitorNoCallbackWarnTick() {
  nt._resetForTest();
  // Two certs inside a wide window, NO onExpiring -> the warn path runs
  // (emit + earliest-validTo reduce over multiple rows) and the onExpiring
  // dispatch takes its "no callback" side.
  nt.addCa(_toPem(_synthCert({ cn: "W1", notAfter: "270101000000Z" })), { label: "w1" });
  nt.addCa(_toPem(_synthCert({ cn: "W2", serial: Buffer.from([0x71]),
    notAfter: "280101000000Z" })), { label: "w2" });
  var events = [];
  var restore = _captureAudit(events);
  var mon = nt.expiryMonitor({ intervalMs: 15, windowMs: C.TIME.days(3650) });
  try {
    await helpers.waitUntil(function () {
      return events.some(function (e) { return e.action === "network.tls.ca.expiring"; });
    }, { timeoutMs: 5000, label: "expiryMonitor: warn tick with no callback" });
    var ev = events.filter(function (e) { return e.action === "network.tls.ca.expiring"; })[0];
    check("expiryMonitor warn tick reports both expiring certs", ev.metadata.count === 2);
  } finally {
    mon.stop();
    restore();
    nt._resetForTest();
  }
}

async function testExpiryMonitorThrowingCallback() {
  nt._resetForTest();
  nt.addCa(_toPem(_synthCert({ cn: "T Mon", notAfter: "270101000000Z" })), { label: "t" });
  var called = 0;
  var mon = nt.expiryMonitor({
    intervalMs: 15,
    windowMs:   C.TIME.days(3650),
    onExpiring: function () { called += 1; throw new Error("operator hook boom"); },
  });
  try {
    await helpers.waitUntil(function () { return called >= 1; },
      { timeoutMs: 5000, label: "expiryMonitor: throwing onExpiring invoked" });
    check("expiryMonitor swallows a throwing onExpiring (never escapes the tick)", called >= 1);
  } finally {
    mon.stop();
    nt._resetForTest();
  }
}

async function testPinsetDriftMonitorOkTick() {
  nt._resetForTest();
  nt.addCa(_toPem(_synthCert({ cn: "Stable CA" })), {});
  nt.captureBaselineFingerprints();   // baseline == current -> no drift
  var events = [];
  var restore = _captureAudit(events);
  var mon = nt.pinsetDriftMonitor({ intervalMs: 15 });
  try {
    await helpers.waitUntil(function () {
      return events.some(function (e) {
        return e.action === "network.tls.pinset.drift_check" && e.outcome === "ok";
      });
    }, { timeoutMs: 5000, label: "pinsetDriftMonitor: ok tick" });
    check("pinsetDriftMonitor emits an 'ok' drift_check when the pinset is stable", true);
  } finally {
    mon.stop();
    restore();
    nt._resetForTest();
  }
}

async function testPinsetDriftMonitorNoCallback() {
  nt._resetForTest();
  nt.captureBaselineFingerprints();   // baseline == [] (empty store)
  nt.addCa(_toPem(_synthCert({ cn: "Drift NoCb CA" })), {});   // now drifts
  var events = [];
  var restore = _captureAudit(events);
  var mon = nt.pinsetDriftMonitor({ intervalMs: 15 });   // NO onDrift
  try {
    await helpers.waitUntil(function () {
      return events.some(function (e) { return e.action === "network.tls.pinset.drifted"; });
    }, { timeoutMs: 5000, label: "pinsetDriftMonitor: drifted tick, no callback" });
    check("pinsetDriftMonitor drift tick runs with no onDrift callback", true);
  } finally {
    mon.stop();
    restore();
    nt._resetForTest();
  }
}

async function testPinsetDriftMonitorThrowingCallback() {
  nt._resetForTest();
  nt.captureBaselineFingerprints();
  nt.addCa(_toPem(_synthCert({ cn: "Drift Throw CA" })), {});
  var called = 0;
  var mon = nt.pinsetDriftMonitor({
    intervalMs: 15,
    onDrift:    function () { called += 1; throw new Error("drift hook boom"); },
  });
  try {
    await helpers.waitUntil(function () { return called >= 1; },
      { timeoutMs: 5000, label: "pinsetDriftMonitor: throwing onDrift invoked" });
    check("pinsetDriftMonitor swallows a throwing onDrift", called >= 1);
  } finally {
    mon.stop();
    nt._resetForTest();
  }
}

async function testPinsetDriftMonitorNoBaseline() {
  nt._resetForTest();
  nt.addCa(_toPem(_synthCert({ cn: "No Baseline CA" })), {});
  // No captureBaselineFingerprints() -> detectBaselineDrift() returns null,
  // so every tick early-returns and nothing is emitted.
  var events = [];
  var restore = _captureAudit(events);
  var mon = nt.pinsetDriftMonitor({ intervalMs: 15 });
  try {
    await helpers.passiveObserve(300, "pinsetDriftMonitor: no baseline -> silent");
    check("pinsetDriftMonitor with no captured baseline emits nothing",
          events.filter(function (e) {
            return /^network\.tls\.pinset/.test(e.action || "");
          }).length === 0);
  } finally {
    mon.stop();
    restore();
    nt._resetForTest();
  }
}

// =====================================================================
// Branch-coverage extension — crafted-input paths for the OCSP DER
// parser, the CT SCT-list / cert-extension extractors, the ECHConfig
// framing reader, connectWithEch config guards, and the RFC 9525
// hostname/IP helper edges. Every case drives the exported consumer
// surface (nt.ocsp.* / nt.ct.* / nt.parseEchConfigList / nt.connectWith
// Ech / nt.checkServerIdentity9525) with a hand-built malformed or edge
// input and asserts the documented refusal `.code` or the preserved
// parse result — never a validation bypass.
// =====================================================================

var _OID_BASIC_OCSP = "1.3.6.1.5.5.7.48.1.1";

function _u64be(n) { var b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }

// parseOcspResponse shape guards — a malformed OCSPResponse DER must
// refuse with the exact tls/ocsp-bad-* code, never silently parse.
function testOcspParseShapeGuardsMore() {
  // non-Buffer + empty Buffer -> ocsp-bad-input.
  var e0a = null;
  try { nt.ocsp.parseResponse(42); } catch (e) { e0a = e; }
  check("parseResponse(non-Buffer) throws ocsp-bad-input", e0a && e0a.code === "tls/ocsp-bad-input");
  var e0b = null;
  try { nt.ocsp.parseResponse(Buffer.alloc(0)); } catch (e) { e0b = e; }
  check("parseResponse(empty Buffer) throws ocsp-bad-input", e0b && e0b.code === "tls/ocsp-bad-input");

  // top node not a SEQUENCE (an OCTET STRING) -> ocsp-bad-shape.
  var e1 = null;
  try { nt.ocsp.parseResponse(Buffer.from([0x04, 0x01, 0x00])); } catch (e) { e1 = e; }
  check("parseResponse(non-SEQUENCE top) throws ocsp-bad-shape", e1 && e1.code === "tls/ocsp-bad-shape");

  // successful + responseBytes [0] wrapping a non-SEQUENCE -> ocsp-bad-shape.
  var derRbNotSeq = asn1.writeSequence([
    asn1.writeNode(0x0a, Buffer.from([0])),
    asn1.writeContextExplicit(0, asn1.writeNode(0x04, Buffer.from([1, 2]))),
  ]);
  var e2 = null;
  try { nt.ocsp.parseResponse(derRbNotSeq); } catch (e) { e2 = e; }
  check("parseResponse(responseBytes not SEQUENCE) throws ocsp-bad-shape", e2 && e2.code === "tls/ocsp-bad-shape");

  // responseBytes SEQUENCE with < 2 children -> ocsp-bad-shape.
  var derRbShort = asn1.writeSequence([
    asn1.writeNode(0x0a, Buffer.from([0])),
    asn1.writeContextExplicit(0, asn1.writeSequence([asn1.writeOid("1.2.3")])),
  ]);
  var e3 = null;
  try { nt.ocsp.parseResponse(derRbShort); } catch (e) { e3 = e; }
  check("parseResponse(responseBytes < 2 children) throws ocsp-bad-shape", e3 && e3.code === "tls/ocsp-bad-shape");

  // BasicOCSPResponse OCTET STRING wrapping a non-SEQUENCE -> ocsp-bad-shape.
  var derBasicNotSeq = asn1.writeSequence([
    asn1.writeNode(0x0a, Buffer.from([0])),
    asn1.writeContextExplicit(0, asn1.writeSequence([
      asn1.writeOid(_OID_BASIC_OCSP),
      asn1.writeOctetString(asn1.writeInteger(Buffer.from([1]))),
    ])),
  ]);
  var e4 = null;
  try { nt.ocsp.parseResponse(derBasicNotSeq); } catch (e) { e4 = e; }
  check("parseResponse(BasicOCSPResponse not SEQUENCE) throws ocsp-bad-shape", e4 && e4.code === "tls/ocsp-bad-shape");

  // BasicOCSPResponse SEQUENCE with < 3 children -> ocsp-bad-shape.
  var derBasicShort = asn1.writeSequence([
    asn1.writeNode(0x0a, Buffer.from([0])),
    asn1.writeContextExplicit(0, asn1.writeSequence([
      asn1.writeOid(_OID_BASIC_OCSP),
      asn1.writeOctetString(asn1.writeSequence([
        asn1.writeInteger(Buffer.from([1])),
        asn1.writeInteger(Buffer.from([2])),
      ])),
    ])),
  ]);
  var e5 = null;
  try { nt.ocsp.parseResponse(derBasicShort); } catch (e) { e5 = e; }
  check("parseResponse(BasicOCSPResponse < 3 children) throws ocsp-bad-shape", e5 && e5.code === "tls/ocsp-bad-shape");
}

// buildRequest issuer-cert DER-walk shape guards.
function testOcspBuildRequestIssuerShapes() {
  var leaf = _synthCert({ serial: _SERIAL, cn: "Leaf",
    keyBytes: Buffer.from("leaf-key-bytes-aaaaaaaaaaaaaaaa") });

  // issuer cert SEQUENCE with zero children -> ocsp-bad-issuer-cert.
  var e1 = null;
  try { nt.ocsp.buildRequest({ leafCertDer: leaf, issuerCertDer: asn1.writeSequence([]) }); }
  catch (e) { e1 = e; }
  check("buildRequest(issuer SEQUENCE, no children) throws ocsp-bad-issuer-cert",
        e1 && e1.code === "tls/ocsp-bad-issuer-cert");

  // issuer tbsCertificate not a SEQUENCE -> ocsp-bad-issuer-cert.
  var e2 = null;
  try { nt.ocsp.buildRequest({ leafCertDer: leaf,
    issuerCertDer: asn1.writeSequence([asn1.writeInteger(Buffer.from([1]))]) }); }
  catch (e) { e2 = e; }
  check("buildRequest(issuer tbs not SEQUENCE) throws ocsp-bad-issuer-cert",
        e2 && e2.code === "tls/ocsp-bad-issuer-cert");

  // Full-shaped tbs whose SPKI field is a SEQUENCE with < 2 children
  // (no subjectPublicKey BIT STRING) -> ocsp-bad-issuer-cert.
  var algId = asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.1.1"), asn1.writeNull()]);
  var cnrdn = asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeNode(0x0c, Buffer.from("SPKI CA", "ascii"))]);
  var name  = asn1.writeSequence([asn1.writeNode(0x31, cnrdn)]);
  var validity = asn1.writeSequence([
    asn1.writeNode(0x17, Buffer.from("260101000000Z", "ascii")),
    asn1.writeNode(0x17, Buffer.from("270101000000Z", "ascii")),
  ]);
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var badSpki = asn1.writeSequence([algId]);   // 1 child — missing BIT STRING
  var tbsBadSpki = asn1.writeSequence([version, asn1.writeInteger(Buffer.from([1])),
    algId, name, validity, name, badSpki]);
  var certBadSpki = asn1.writeSequence([tbsBadSpki, algId, asn1.writeNode(0x03, Buffer.from([0, 0, 0, 0]))]);
  var e3 = null;
  try { nt.ocsp.buildRequest({ leafCertDer: leaf, issuerCertDer: certBadSpki }); }
  catch (e) { e3 = e; }
  check("buildRequest(issuer SPKI < 2 children) throws ocsp-bad-issuer-cert",
        e3 && e3.code === "tls/ocsp-bad-issuer-cert");
}

// ocsp.fetch / requireGood no-argument config guards (opts || {} default).
async function testOcspNoArgGuards() {
  var e1 = null;
  try { await nt.ocsp.fetch(); } catch (e) { e1 = e; }
  check("ocsp.fetch() no-arg throws ocsp-bad-input", e1 && e1.code === "tls/ocsp-bad-input");

  var e2 = null;
  try { await nt.ocsp.requireGood(); } catch (e) { e2 = e; }
  check("ocsp.requireGood() no-arg throws ocsp-missing-issuer", e2 && e2.code === "tls/ocsp-missing-issuer");
}

// removeCa with an explicit { audit: false } drives the opts.audit !== false
// arm of the emit gate (the default-audit arm is covered elsewhere).
function testRemoveCaAuditArm() {
  nt._resetForTest();
  var added = nt.addCa(_toPem(_synthCert({ cn: "RmA CA" })), { label: "rma" });
  check("removeCa({audit:false}) still removes", nt.removeCa(added[0].fingerprint256, { audit: false }) === 1);
  nt._resetForTest();
}

// CT SCT-extension extractor edge branches: non-SCT / empty / non-SEQUENCE
// extensions are skipped, and a genuine SCT is still located; a malformed
// SCT-extension inner (not a second OCTET STRING) refuses with ct-bad-extension.
function testCtSctExtractorEdges() {
  var goodSct = _sctExt(_sctListRaw([_buildSctBytes({})]));

  // A non-SCT extension (must-staple) preceding the SCT ext -> OID mismatch
  // continue, then the SCT is found.
  var mixed = _synthCert({ cn: "MixSct", exts: [_mustStapleExt(), goodSct] });
  check("parseScts skips a non-SCT extension then finds the SCT",
        nt.ct.parseScts(mixed).length === 1);

  // A non-SEQUENCE extension entry is skipped.
  var withInt = _synthCert({ cn: "IntExt",
    exts: [asn1.writeNode(0x02, Buffer.from([1])), goodSct] });
  check("parseScts skips a non-SEQUENCE extension entry then finds the SCT",
        nt.ct.parseScts(withInt).length === 1);

  // An empty-SEQUENCE extension entry is skipped.
  var withEmpty = _synthCert({ cn: "EmptyExt", exts: [asn1.writeSequence([]), goodSct] });
  check("parseScts skips an empty-SEQUENCE extension entry then finds the SCT",
        nt.ct.parseScts(withEmpty).length === 1);

  // SCT extension whose extnValue does NOT wrap a second OCTET STRING
  // (wraps a SEQUENCE instead) -> fails closed to no SCT, never throws (a
  // hostile peer controls this cert; parseScts/verifyScts must not throw).
  var badInner = asn1.writeSequence([
    asn1.writeOid(OID_CT_SCT_LIST),
    asn1.writeOctetString(asn1.writeSequence([asn1.writeInteger(Buffer.from([1]))])),
  ]);
  var badInnerCert = _synthCert({ cn: "BadInner", exts: [badInner] });
  var e1 = null, parsed1;
  try { parsed1 = nt.ct.parseScts(badInnerCert); } catch (e) { e1 = e; }
  check("parseScts(SCT extnValue not wrapping OCTET STRING) fails closed to [] (no throw)",
        e1 === null && Array.isArray(parsed1) && parsed1.length === 0);
}

// TLS-Feature (must-staple) extractor edge branches through inspectMustStaple.
function testTlsFeatureExtractorEdges() {
  var feat = _mustStapleExt();

  // Non-SEQUENCE + empty-SEQUENCE + OID-unreadable + OID-mismatch extensions
  // are all skipped before the real TLS-Feature ext is located.
  var noisy = _synthCert({ cn: "NoisyFeat", exts: [
    asn1.writeNode(0x02, Buffer.from([1])),                // non-SEQUENCE -> skip
    asn1.writeSequence([]),                                // empty -> skip
    asn1.writeSequence([asn1.writeNode(0x02, Buffer.from([1])), asn1.writeNull()]), // first child not OID -> skip
    _sctExt(_sctListRaw([_buildSctBytes({})])),            // OID mismatch -> skip
    feat,
  ] });
  var msNoisy = nt.ocsp.inspectMustStaple(noisy);
  check("inspectMustStaple skips noisy extensions and still detects must-staple",
        msNoisy.mustStaple === true && msNoisy.features.indexOf(5) !== -1);

  // TLS-Feature extnValue wrapping a non-SEQUENCE -> treated as no feature.
  var featNotSeq = asn1.writeSequence([
    asn1.writeOid(OID_TLS_FEATURE),
    asn1.writeOctetString(asn1.writeNode(0x02, Buffer.from([1]))),
  ]);
  var certNotSeq = _synthCert({ cn: "FeatNotSeq", exts: [featNotSeq] });
  check("inspectMustStaple(TLS-Feature not SEQUENCE) -> mustStaple false",
        nt.ocsp.inspectMustStaple(certNotSeq).mustStaple === false);

  // TLS-Feature SEQUENCE-OF with a NON-integer entry: the non-integer is
  // ignored, the integer 5 still flags must-staple.
  var featMixed = asn1.writeSequence([
    asn1.writeOid(OID_TLS_FEATURE),
    asn1.writeOctetString(asn1.writeSequence([
      asn1.writeNull(),                          // non-integer -> ignored
      asn1.writeInteger(Buffer.from([5])),       // status_request -> must-staple
    ])),
  ]);
  var certMixed = _synthCert({ cn: "FeatMixed", exts: [featMixed] });
  var msMixed = nt.ocsp.inspectMustStaple(certMixed);
  check("inspectMustStaple ignores non-integer TLS-Feature entries but keeps the 5",
        msMixed.mustStaple === true && msMixed.features.length === 1 && msMixed.features[0] === 5);
}

// SCT-list / single-SCT low-level parse rejections through ct.parseScts.
function testCtSctBytesParseErrors() {
  // Outer SCT list shorter than its 2-byte length prefix.
  var listShort = asn1.writeSequence([
    asn1.writeOid(OID_CT_SCT_LIST),
    asn1.writeOctetString(asn1.writeOctetString(Buffer.from([0x00]))),
  ]);
  var e1 = null;
  try { nt.ct.parseScts(_synthCert({ cn: "ListShort", exts: [listShort] })); } catch (e) { e1 = e; }
  check("parseScts(SCT list < outer prefix) throws ct-bad-list", e1 && e1.code === "tls/ct-bad-list");

  // A single SCT whose declared length runs past the list buffer.
  var overrunBody = Buffer.concat([Buffer.from([0x00, 0x40]), Buffer.alloc(5, 0x00)]);
  var overrunList = Buffer.concat([Buffer.from([0x00, overrunBody.length]), overrunBody]);
  var overrunExt = asn1.writeSequence([
    asn1.writeOid(OID_CT_SCT_LIST),
    asn1.writeOctetString(asn1.writeOctetString(overrunList)),
  ]);
  var e2 = null;
  try { nt.ct.parseScts(_synthCert({ cn: "Overrun", exts: [overrunExt] })); } catch (e) { e2 = e; }
  check("parseScts(SCT declared length past buffer) throws ct-bad-list", e2 && e2.code === "tls/ct-bad-list");

  // A 47-byte SCT whose ct_extensions length consumes the DigitallySigned
  // header -> truncated before DigitallySigned.
  var sctTruncExt = Buffer.concat([
    Buffer.from([0]), Buffer.alloc(32, 0xaa), _u64be(1),
    Buffer.from([0x00, 0x04]), Buffer.alloc(4, 0x00),
  ]);
  var e3 = null;
  try { nt.ct.parseScts(_synthCert({ cn: "SctTruncExt",
    exts: [_sctExt(_sctListRaw([sctTruncExt]))] })); } catch (e) { e3 = e; }
  check("parseScts(SCT ext len eats DigitallySigned) throws ct-sct-truncated",
        e3 && e3.code === "tls/ct-sct-truncated");

  // An SCT whose declared signature length does not match the remaining bytes.
  var sctBadSigLen = Buffer.concat([
    Buffer.from([0]), Buffer.alloc(32, 0xaa), _u64be(1),
    Buffer.from([0x00, 0x00]),   // ct_extensions len 0
    Buffer.from([0x04, 0x03]),   // hash+sig algo
    Buffer.from([0x00, 0x05]),   // sig length 5 ...
    Buffer.from([0x01, 0x02, 0x03]),  // ... but only 3 bytes follow
  ]);
  var e4 = null;
  try { nt.ct.parseScts(_synthCert({ cn: "SctBadSigLen",
    exts: [_sctExt(_sctListRaw([sctBadSigLen]))] })); } catch (e) { e4 = e; }
  check("parseScts(SCT sig length mismatch) throws ct-sct-truncated",
        e4 && e4.code === "tls/ct-sct-truncated");
}

// ECHConfig internal reader overflow / truncation branches. Every framing
// violation must refuse with tls/ech-config-malformed.
function testEchInternalReaderFraming() {
  function _throws(raw, label) {
    var e = null;
    try { nt.parseEchConfigList(raw); } catch (err) { e = err; }
    check("parseEchConfigList " + label + " -> ech-config-malformed",
          e && e.code === "tls/ech-config-malformed");
  }

  // draft-22 config, declared body length 0 -> _echReadU8(config_id) overflows.
  _throws(Buffer.from([0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00]), "u8 read past body");

  // draft-22 config, body 1 byte -> _echReadU16(kem_id) overflows.
  _throws(Buffer.from([0x00, 0x05, 0xfe, 0x0d, 0x00, 0x01, 0x07]), "u16 read past body");

  // draft-22 config whose public_key opaque<u16> length overflows the buffer.
  _throws(Buffer.from([0x00, 0x09, 0xfe, 0x0d, 0x00, 0x05, 0x07, 0x00, 0x20, 0xff, 0xff]),
          "opaque<u16> public_key overflow");

  // Stomp the cipher_suites length prefix of a VALID config to a large
  // multiple of 4 so it overflows the config body.
  var valid1 = _buildEchConfigDraft22({});
  valid1[43] = 0xff; valid1[44] = 0xfc;   // suites-len prefix at offset 43
  _throws(valid1, "cipher_suites vector overflows body");

  // Stomp the public_name u8 length prefix so it overflows.
  var valid2 = _buildEchConfigDraft22({});
  valid2[54] = 0xff;   // public_name length byte at offset 54
  _throws(valid2, "u8-prefixed public_name overflow");

  // Stomp the extensions u16 length prefix so it no longer consumes the body.
  var valid3 = _buildEchConfigDraft22({});
  valid3[73] = 0x00; valid3[74] = 0x02;   // ext-len prefix at offset 73
  _throws(valid3, "extensions vector does not consume body");
}

// ECHConfig with a real extension exercises the extensions parse loop and
// preserves the extension type + data verbatim.
function testEchExtensionsLoop() {
  var raw = _buildEchConfigDraft22({
    extensions: [{ type: 0x1234, data: Buffer.from([0xaa, 0xbb, 0xcc]) }],
  });
  var parsed = nt.parseEchConfigList(raw);
  var exts = parsed.configs[0].extensions;
  check("parseEchConfigList reads a present extension",
        Array.isArray(exts) && exts.length === 1 && exts[0].type === 0x1234);
  check("parseEchConfigList preserves the extension data bytes verbatim",
        Buffer.isBuffer(exts[0].data) && exts[0].data.equals(Buffer.from([0xaa, 0xbb, 0xcc])));
}

// connectWithEch config-time guards + the echOverride base64-string branch
// over a real localhost handshake (drives the string arm + ipFamily/ca/
// checkServerIdentity connectOpts assignments + servername-defaults-to-host).
async function testConnectWithEchConfigAndStringOverride() {
  // opts as an array refuses at the plain-object guard.
  var eArr = null;
  try { nt.connectWithEch([1, 2]); } catch (e) { eArr = e; }
  check("connectWithEch(array) refuses ech-bad-opts",
        eArr instanceof nt.NetworkTlsError && eArr.code === "tls/ech-bad-opts");

  var validEch = _buildEchConfigDraft22({});
  var s1 = await _startTlsServer(undefined);
  try {
    // ipFamily + ca + checkServerIdentity connectOpts assignments all set,
    // echOverride passed as a BASE64 STRING (drives the string-decode arm).
    var sock = await nt.connectWithEch({
      host: "127.0.0.1", port: s1.port, servername: "localhost", ipFamily: 4,
      ca: _toPem(_synthCert({ cn: "Unused CA" })),
      checkServerIdentity: function () { return undefined; },
      echOverride: validEch.toString("base64"),
      rejectUnauthorized: false,
    });
    check("connectWithEch with a base64 echOverride + ipFamily/ca/checkServerIdentity secures",
          sock && sock.encrypted === true);
    try { sock.destroy(); } catch (_e) { /* best-effort */ }
  } finally { s1.close(); }
}

// RFC 9525 helper edges: empty DNS-SAN value, trailing-dot host, malformed
// quoted SAN (fail closed), bracketed IPv6 SAN, and the ::-prefix / ::-suffix
// IPv6 forms.
function testPkixHelperEdges() {
  // Empty dNSName value cannot match; refuses.
  var e1 = nt.checkServerIdentity9525("foo.example.com", _cert("DNS:"));
  check("empty dNSName SAN value refuses", e1 && e1.code === "tls/pkix-hostname-mismatch");

  // Trailing-dot (absolute FQDN) host normalizes and matches.
  check("trailing-dot host normalizes to match the SAN",
        nt.checkServerIdentity9525("foo.example.com.", _cert("DNS:foo.example.com")) === undefined);

  // Malformed quoted SAN -> parser fails closed -> refuses (never smuggles a name).
  var e2 = nt.checkServerIdentity9525("victim.com", _cert('DNS:"unterminated'));
  check("malformed quoted SAN fails closed (refuses)", e2 && e2.code === "tls/pkix-hostname-mismatch");

  // Bracketed IPv6 SAN value canonicalizes and matches the bare IPv6 host.
  check("bracketed IPv6 SAN matches the bare IPv6 host",
        nt.checkServerIdentity9525("2001:db8::1", _cert("IP Address:[2001:db8::1]")) === undefined);

  // ::-prefix (empty left) and ::-suffix (empty right) IPv6 forms both match.
  check("IPv6 ::-prefix host matches its SAN",
        nt.checkServerIdentity9525("::1", _cert("IP Address:::1")) === undefined);
  check("IPv6 ::-suffix host matches its SAN",
        nt.checkServerIdentity9525("2001:db8::", _cert("IP Address:2001:db8::")) === undefined);
}

// CT Merkle verifier optional-shape branches: bigint SCT timestamp, the
// sha256RootHash STH alias, hex-string roots (inclusion consistency +
// standalone verifyConsistency), and omitted (undefined) proofs.
function testCtVerifierOptionalShapes() {
  var signedEntry = Buffer.from("optional-shape-entry");
  var ts = 1700000000000;
  var leafHash = _ctLeafHash(signedEntry, ts);

  // bigint timestamp + sha256RootHash alias (no rootHash) -> valid.
  var okBig = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: BigInt(ts), signedEntryDer: signedEntry },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1, sha256RootHash: leafHash },
  });
  check("verifyInclusion bigint timestamp + sha256RootHash alias valid", okBig.valid === true);

  // Optional consistency proof with a hex-string firstRoot + omitted proof
  // (proof || []): the first tree is a complete subtree, so an empty proof
  // reconciles for firstSize 1.
  var incl = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1, rootHash: leafHash },
    consistency: { firstSize: 1, firstRoot: leafHash.toString("hex") },  // proof omitted
  });
  check("verifyInclusion hex-string consistency firstRoot + omitted proof reconciles",
        incl.valid === true && incl.consistency && incl.consistency.ok === true);

  // Standalone verifyConsistency with hex-string roots + omitted proof.
  var X = Buffer.alloc(32, 0x22);
  var sameHex = nt.ct.verifyConsistency({
    firstSize: 1, secondSize: 1,
    firstRoot: X.toString("hex"), secondRoot: X.toString("hex"),  // proof omitted
  });
  check("verifyConsistency hex-string roots + omitted proof valid", sameHex.valid === true);

  // requireScts() with no argument defaults its opts.
  check("ct.requireScts() no-arg returns a predicate function",
        typeof nt.ct.requireScts() === "function");
}

var _OID_RSA_SHA256   = "1.2.840.113549.1.1.11";
var _OID_RSA_SHA384   = "1.2.840.113549.1.1.12";
var _OID_RSA_SHA512   = "1.2.840.113549.1.1.13";
var _OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
var _OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4";

// evaluate: the signatureAlgorithm-OID → node-hash mapping arms + the
// no-opts guard + the finite-clockSkew arm.
function testOcspEvaluateMoreBranches() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "EvalMore CA",
    keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });
  var serialHex = _SERIAL.toString("hex");

  // Each recognized signatureAlgorithm OID maps to a node hash and the
  // response still parses as "successful" (the signature verifies or fails
  // to verify against the EC issuer key, but the OID-mapping arm executes).
  [_OID_RSA_SHA256, _OID_RSA_SHA384, _OID_RSA_SHA512,
   _OID_ECDSA_SHA384, _OID_ECDSA_SHA512].forEach(function (oid) {
    var fx = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL, sigAlgOid: oid });
    var rv = nt.ocsp.evaluate(fx.der, { issuerPem: fx.issuerPem, serialHex: serialHex, now: _NOW });
    check("evaluate maps signatureAlgorithm OID " + oid + " to a hash (status successful)",
          rv && rv.status === "successful" && typeof rv.signatureValid === "boolean");
  });

  // evaluate with NO opts defaults opts and refuses on the missing issuer.
  var eNoOpts = null;
  try { nt.ocsp.evaluate(Buffer.from([0x30, 0x00])); } catch (e) { eNoOpts = e; }
  check("evaluate() no-opts throws ocsp-missing-issuer", eNoOpts && eNoOpts.code === "tls/ocsp-missing-issuer");

  // A finite clockSkewMs is honored (the freshness window still passes for a
  // fresh good response).
  var good = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL });
  var rvSkew = nt.ocsp.evaluate(good.der, { issuerPem: good.issuerPem, serialHex: serialHex,
    now: _NOW, clockSkewMs: C.TIME.minutes(1) });
  check("evaluate honors a finite clockSkewMs", rvSkew.ok === true && rvSkew.certStatus === "good");
}

// buildRequest with no argument defaults opts and refuses on the missing
// leaf cert.
function testOcspBuildRequestNoArg() {
  var e1 = null;
  try { nt.ocsp.buildRequest(); } catch (e) { e1 = e; }
  check("ocsp.buildRequest() no-arg throws ocsp-bad-input", e1 && e1.code === "tls/ocsp-bad-input");
}

// CT extractor "extensions present but the target extension is absent"
// tail branches: parseScts returns [] and inspectMustStaple returns false
// after walking a cert whose only extension is the OTHER kind.
function testCtExtractorNoMatchTails() {
  var onlyMustStaple = _synthCert({ cn: "OnlyMS", exts: [_mustStapleExt()] });
  check("parseScts on a cert whose only ext is must-staple returns []",
        nt.ct.parseScts(onlyMustStaple).length === 0);

  var onlySct = _synthCert({ cn: "OnlySCT", exts: [_sctExt(_sctListRaw([_buildSctBytes({})]))] });
  check("inspectMustStaple on a cert whose only ext is an SCT list -> mustStaple false",
        nt.ocsp.inspectMustStaple(onlySct).mustStaple === false);
}

// verifyInclusion strip-the-SCT-extension failure branches: a leaf cert that
// is not a SEQUENCE / whose tbs is not a SEQUENCE refuses with strip-failed
// (never silently proceeds).
function testCtVerifyInclusionStripFailures() {
  var sct = { logIdHex: "aa", timestamp: 1700000000000 };  // no signedEntryDer -> strip
  var notSeq = nt.ct.verifyInclusion({
    sct: sct, leafCertificate: Buffer.from([0x04, 0x01, 0x00]), leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1, rootHash: Buffer.alloc(32, 0x00) },
  });
  check("verifyInclusion leaf not a SEQUENCE -> strip-failed", notSeq.reason === "strip-failed");

  var badTbs = nt.ct.verifyInclusion({
    sct: sct, leafCertificate: asn1.writeSequence([asn1.writeInteger(Buffer.from([1]))]),
    leafIndex: 0, auditPath: [], sthFromLog: { treeSize: 1, rootHash: Buffer.alloc(32, 0x00) },
  });
  check("verifyInclusion leaf tbs not a SEQUENCE -> strip-failed", badTbs.reason === "strip-failed");
}

// verifyScts strip walk over a cert carrying BOTH an SCT ext and a non-SCT
// ext (must-staple): the strip keeps the non-SCT ext + drops the SCT ext,
// and the SCT hash-algo → node-hash mapping runs for sha384 / sha512 SCTs.
function testCtVerifyStripAndHashAlgos() {
  var ecPub = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .publicKey.export({ type: "spki", format: "pem" });
  var logHex = "aa".repeat(32);
  var kh = Buffer.alloc(32, 0xcd);   // issuer_key_hash — get past the precert gate
  function _opts() { var m = {}; m[logHex] = ecPub; return { logKeys: m, minScts: 1, issuerKeyHash: kh }; }

  // Mixed extensions drive the strip loop's keep-non-SCT / drop-SCT branches.
  var mixed = _synthCert({ cn: "StripMix",
    exts: [_mustStapleExt(), _sctExt(_sctListRaw([_buildSctBytes({})]))] });
  var rvMixed = nt.ct.verifyScts(mixed, _opts());
  check("verifyScts strips the SCT ext while keeping a must-staple ext (walk runs)",
        rvMixed.totalScts === 1 && Array.isArray(rvMixed.scts) && rvMixed.scts.length === 1);
  // Directly assert the strip output: the kept (must-staple) extension OID
  // survives and the SCT-list extension OID is gone — the signed-entry TBS is
  // wrong if either is mishandled, and counting SCTs cannot see that.
  var strippedMix = nt._stripSctExtensionFromCert(mixed);
  var sctOidDer = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]);
  var poisonOidDer = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x03]);
  var tlsFeatOidDer = asn1.writeOid(OID_TLS_FEATURE);
  check("strip keeps the non-SCT (must-staple) extension OID in the TBS",
        strippedMix.indexOf(tlsFeatOidDer) !== -1);
  check("strip drops the SCT-list extension OID from the TBS",
        strippedMix.indexOf(sctOidDer) === -1);
  // RFC 6962 §3.2: the signed tbs_certificate is reconstructed from the final
  // cert "by extracting the TBSCertificate ... and deleting the SCT extension"
  // — it is "without ... the poison extension". The reconstruction must NOT
  // re-insert the precert poison OID (1.3.6.1.4.1.11129.2.4.3); doing so would
  // differ from what the log signed and break every real embedded SCT.
  check("strip does not re-insert the precert poison OID (RFC 6962 §3.2 delete-only)",
        strippedMix.indexOf(poisonOidDer) === -1);

  // SCTs declaring sha384 / sha512 exercise the hash-algo → node-hash arms.
  var sct384 = _synthCert({ cn: "Sct384",
    exts: [_sctExt(_sctListRaw([_buildSctBytes({ hashAlgo: 5 })]))] });
  check("verifyScts maps SCT hashAlgo 5 (sha384) — per-sct result present",
        nt.ct.verifyScts(sct384, _opts()).scts.length === 1);
  var sct512 = _synthCert({ cn: "Sct512",
    exts: [_sctExt(_sctListRaw([_buildSctBytes({ hashAlgo: 6 })]))] });
  check("verifyScts maps SCT hashAlgo 6 (sha512) — per-sct result present",
        nt.ct.verifyScts(sct512, _opts()).scts.length === 1);
}

// CT Merkle proof guards reachable only through the public verifiers with
// out-of-range sizes / short or malformed proofs.
function testCtMerkleGuardsMore() {
  var X = Buffer.alloc(32, 0x22);

  // Non-integer treeSize surfaces as inclusion-walk-failed (the path's
  // tree-size guard throws and is caught).
  var badTree = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: 1700000000000, signedEntryDer: Buffer.from("x") },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1.5, rootHash: Buffer.alloc(32, 0x00) },
  });
  check("verifyInclusion non-integer treeSize -> inclusion-walk-failed",
        badTree.reason === "inclusion-walk-failed");

  // verifyConsistency with n < m -> walk-failed (bad-second-size throw caught).
  check("verifyConsistency secondSize < firstSize -> consistency-walk-failed",
        nt.ct.verifyConsistency({ firstSize: 2, secondSize: 1, proof: [],
          firstRoot: X, secondRoot: X }).reason === "consistency-walk-failed");

  // verifyConsistency with a non-32-byte proof entry -> walk-failed
  // (bad-consistency-entry throw caught).
  check("verifyConsistency non-32-byte proof entry -> consistency-walk-failed",
        nt.ct.verifyConsistency({ firstSize: 2, secondSize: 4, proof: [Buffer.alloc(4, 1)],
          firstRoot: X, secondRoot: X }).reason === "consistency-walk-failed");

  // verifyConsistency with a proof too short to reach the second root ->
  // walk-failed (consistency-short throw caught).
  check("verifyConsistency proof exhausted before second root -> consistency-walk-failed",
        nt.ct.verifyConsistency({ firstSize: 3, secondSize: 16, proof: [Buffer.alloc(32, 1)],
          firstRoot: X, secondRoot: X }).reason === "consistency-walk-failed");

  // verifyInclusion whose optional consistency proof has a bad firstSize
  // -> the consistency path throws and is caught as consistency-walk-failed.
  var signedEntry = Buffer.from("guard-entry");
  var ts = 1700000000000;
  var leafHash = _ctLeafHash(signedEntry, ts);
  var inclBadConsist = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: ts, signedEntryDer: signedEntry },
    leafCertificate: Buffer.from("x"), leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1, rootHash: leafHash },
    consistency: { firstSize: 0, firstRoot: X, proof: [] },
  });
  check("verifyInclusion optional consistency bad firstSize -> consistency-walk-failed",
        inclBadConsist.reason === "consistency-walk-failed");
}

// requireGood over a real localhost handshake, binding the response CertID to
// the issuer cert DER (RFC 6960 §4.1.1) so the issuerCertDer-present arm runs
// and the good evaluation is preserved (asserts ACCEPT of a correctly-bound
// good staple — not a bypass).
async function testOcspRequireGoodWithIssuerBinding() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "RGBind CA",
    keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });
  var goodFx = _buildOcsp({ issuerDer: issuer, status: "good", serial: _SERIAL });
  var s = await _startTlsServer(goodFx.der);
  try {
    var r = await nt.ocsp.requireGood({ host: "127.0.0.1", port: s.port,
      rejectUnauthorized: false, servername: "localhost",
      issuerPem: goodFx.issuerPem, issuerCertDer: issuer });
    check("requireGood with a matching issuerCertDer binds and stays good",
          r && r.ocspEvaluation && r.ocspEvaluation.ok === true &&
          r.ocspEvaluation.certStatus === "good");
  } finally { s.close(); }
}

// evaluate parse-error + non-successful-status early returns, plus the
// all-zero serial normalization fallback.
function testOcspEvaluateParseAndStatusBranches() {
  var issuer = _synthCert({ serial: Buffer.from([0x01]), cn: "PS CA",
    keyBytes: Buffer.from("real-ca-key-bytes-aaaaaaaaaaaaaa") });

  // Unparseable OCSP DER with an issuerPem present -> parse-error (caught).
  var pe = nt.ocsp.evaluate(Buffer.from([0x04, 0x01, 0x00]), { issuerPem: issuer && "x", serialHex: "01" });
  check("evaluate(unparseable DER) -> status parse-error", pe.ok === false && pe.status === "parse-error");

  // responseStatus != successful (tryLater) -> early non-successful return.
  var tryLater = asn1.writeSequence([asn1.writeNode(0x0a, Buffer.from([3]))]);
  var ts = nt.ocsp.evaluate(tryLater, { issuerPem: "x", serialHex: "01" });
  check("evaluate(responseStatus tryLater) -> ok false status tryLater",
        ts.ok === false && ts.status === "tryLater");

  // All-zero serial normalizes to "0" on both sides and still binds.
  var zeroFx = _buildOcsp({ issuerDer: issuer, status: "good", serial: Buffer.from([0x00]) });
  var zeroRv = nt.ocsp.evaluate(zeroFx.der, { issuerPem: zeroFx.issuerPem, serialHex: "00", now: _NOW });
  check("evaluate all-zero serial normalizes and binds good",
        zeroRv.ok === true && zeroRv.certStatus === "good");
}

// strip-failed when the leaf cert carries NO extensions at all (the strip
// walk finds no [3] extensions wrapper), plus the DER long-form length
// encoder for a kept extension larger than 127 bytes.
function testCtStripNoExtAndLongLength() {
  // No extensions -> strip refuses -> verifyInclusion reports strip-failed.
  var noExtCert = _synthCert({ cn: "NoExtStrip" });
  var rv = nt.ct.verifyInclusion({
    sct: { logIdHex: "aa", timestamp: 1700000000000 },  // no signedEntryDer -> strip
    leafCertificate: noExtCert, leafIndex: 0, auditPath: [],
    sthFromLog: { treeSize: 1, rootHash: Buffer.alloc(32, 0x00) },
  });
  check("verifyInclusion leaf with no extensions -> strip-failed", rv.reason === "strip-failed");

  // A kept (non-SCT) extension larger than 127 bytes exercises the DER
  // long-form length encoder during the strip re-encode.
  var ecPub = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .publicKey.export({ type: "spki", format: "pem" });
  var logHex = "aa".repeat(32); var keys = {}; keys[logHex] = ecPub;
  var bigExt = asn1.writeSequence([
    asn1.writeOid("1.2.3.4"),
    asn1.writeOctetString(Buffer.alloc(200, 0x5a)),
  ]);
  var bigCert = _synthCert({ cn: "BigExtStrip",
    exts: [bigExt, _sctExt(_sctListRaw([_buildSctBytes({})]))] });
  var rvBig = nt.ct.verifyScts(bigCert,
    { logKeys: keys, minScts: 1, issuerKeyHash: Buffer.alloc(32, 0xcd) });
  check("verifyScts strip re-encodes a >127-byte kept extension (long-form length)",
        rvBig.totalScts === 1);
}

// =====================================================================

// Regression: verifyScts's RFC 6962 log-key algorithm cross-check must read the
// SCT's `sigAlgo` field (the name _parseSct emits). Reading a wrong field name
// made the value always undefined → every SCT failed the algo gate with
// "log-key-algo-mismatch" and nodeCrypto.verify was never reached, so CT SCT
// signature verification could never succeed (fail-closed but non-functional).
function testCtVerifySctAlgoGateReadsSigAlgoField() {
  var ecKp  = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var rsaKp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var ecPem  = ecKp.publicKey.export({ type: "spki", format: "pem" });
  var rsaPem = rsaKp.publicKey.export({ type: "spki", format: "pem" });
  // A precomputed issuer_key_hash so verifyScts gets past its issuer gate and
  // reaches the per-SCT algorithm cross-check (an embedded SCT is a
  // precert_entry, which the verifier cannot process without the issuer).
  var issuerKp  = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var issuerSpkiDer = issuerKp.publicKey.export({ type: "spki", format: "der" });
  var issuerKh  = nodeCrypto.createHash("sha256").update(issuerSpkiDer).digest();
  // The SCT log_id is the SHA-256 of the log key's SPKI (RFC 6962 §3.2); the
  // verifier now enforces that binding, so tests must use the real log_id.
  function logIdFor(pem) {
    return nodeCrypto.createHash("sha256")
      .update(nodeCrypto.createPublicKey(pem).export({ type: "spki", format: "der" })).digest();
  }
  function reasonFor(sigAlgo, pem) {
    var logId = logIdFor(pem);
    var sct   = _buildSctBytes({ logId: logId, sigAlgo: sigAlgo, hashAlgo: 4 });
    var cert  = _synthCert({ cn: "SCT Algo", exts: [_sctExt(_sctListRaw([sct]))] });
    var logKeys = {}; logKeys[logId.toString("hex")] = pem;
    var rv = nt.ct.verifyScts(cert, { logKeys: logKeys, minScts: 1, issuerKeyHash: issuerKh });
    return rv.scts[0] ? rv.scts[0].reason : "no-sct";
  }
  // Matching algo pairs must PASS the gate (reach signature verification, whose
  // reason is anything but the algo mismatch) — RED on the wrong-field bug.
  check("verifyScts: an ecdsa SCT + EC log key passes the algo gate (reaches verify)",
        reasonFor(3, ecPem) !== "log-key-algo-mismatch");
  check("verifyScts: an rsa SCT + RSA log key passes the algo gate (reaches verify)",
        reasonFor(1, rsaPem) !== "log-key-algo-mismatch");
  // A GENUINE mismatch (ecdsa SCT against an RSA log key) must still be refused
  // at the gate — proves the fix reads the field, not that it disabled the gate.
  check("verifyScts: an ecdsa SCT against an RSA log key is still refused (log-key-algo-mismatch)",
        reasonFor(3, rsaPem) === "log-key-algo-mismatch");

  // Passing the algo gate is necessary but not sufficient: the signature must
  // actually verify. An embedded SCT is a precert_entry (RFC 6962 §3.2), so
  // the log signed
  //   version || sig_type(0) || timestamp || entry_type(1=precert_entry) ||
  //   issuer_key_hash(32) || uint24(tbs) || tbs || uint16(0)
  // where issuer_key_hash = SHA-256(issuer SubjectPublicKeyInfo). Build that
  // input BY HAND (independent of the verifier's own helper, so this cannot
  // pass by self-consistency), sign it with the log key, embed the SCT, and
  // assert it verifies — RED while verifyScts built an x509_entry over just
  // the stripped TBS (no issuer binding), which no real embedded SCT matches.
  function rfcPrecertSignedEntry(tbs, keyHash, timestamp) {
    var head = Buffer.alloc(12);
    head[0] = 0;                                   // sct_version v1
    head[1] = 0;                                   // signature_type certificate_timestamp
    head.writeBigUInt64BE(BigInt(timestamp), 2);
    head.writeUInt16BE(1, 10);                     // entry_type precert_entry
    var tbsLen = Buffer.alloc(3); tbsLen.writeUIntBE(tbs.length, 0, 3);
    return Buffer.concat([head, keyHash, tbsLen, tbs, Buffer.from([0x00, 0x00])]);
  }
  function verifyGenuine(sigAlgo, kp, pem, keyHash, verifyOpts, label, hashAlgo, nodeAlgo) {
    hashAlgo = hashAlgo === undefined ? 4 : hashAlgo;   // default SCT HashAlgorithm sha256
    nodeAlgo = nodeAlgo || "sha256";
    var logId = logIdFor(pem);   // SCT log_id must be SHA-256(log key SPKI)
    var ts    = 1700000000000;
    var placeholder = _synthCert({ cn: "SCT Genuine",
      exts: [_sctExt(_sctListRaw([_buildSctBytes(
        { logId: logId, sigAlgo: sigAlgo, hashAlgo: hashAlgo, timestamp: ts,
          sig: Buffer.alloc(64, 0x01) })]))] });
    var stripped = nt._stripSctExtensionFromCert(placeholder);
    var signedEntry = rfcPrecertSignedEntry(stripped, keyHash, ts);
    // Sign with the SCT's declared hash — a mis-mapped hashAlgo→node-hash arm
    // (e.g. sha512 treated as sha256) would recompute a different digest and
    // fail this verify, so each hash arm is genuinely exercised.
    var realSig = nodeCrypto.sign(nodeAlgo, signedEntry, kp.privateKey);
    var finalSct = _buildSctBytes(
      { logId: logId, sigAlgo: sigAlgo, hashAlgo: hashAlgo, timestamp: ts, sig: realSig });
    var cert = _synthCert({ cn: "SCT Genuine",
      exts: [_sctExt(_sctListRaw([finalSct]))] });
    var logKeys = {}; logKeys[logId.toString("hex")] = pem;
    var opts = Object.assign({ logKeys: logKeys, minScts: 1 }, verifyOpts);
    var rv = nt.ct.verifyScts(cert, opts);
    check("verifyScts: a genuinely signed " + label + " SCT verifies (scts[0].verified true)",
          !!(rv.scts[0] && rv.scts[0].verified === true));
    check("verifyScts: a genuinely signed " + label + " SCT flips rv.ok true (>= minScts verified)",
          rv.ok === true && rv.verifiedCount >= 1);
    // The production helper must emit the exact RFC-6962 precert bytes we
    // signed by hand — asserts the helper itself is RFC-correct, not merely
    // self-consistent.
    var helperEntry = nt._buildSctSignedEntry(stripped,
      { version: 0, timestamp: ts, extensions: Buffer.alloc(0) }, keyHash);
    check("verifyScts: _buildSctSignedEntry emits the RFC 6962 precert_entry bytes (" + label + ")",
          Buffer.compare(helperEntry, signedEntry) === 0);
    return cert;
  }
  // issuer supplied as the precomputed 32-byte hash (EC + RSA log keys).
  var ecCert = verifyGenuine(3, ecKp, ecPem, issuerKh, { issuerKeyHash: issuerKh }, "ecdsa");
  verifyGenuine(1, rsaKp, rsaPem, issuerKh, { issuerKeyHash: issuerKh }, "rsa");
  // sha384 / sha512 SCTs genuinely verify — exercises the hashAlgo 5/6 →
  // node-hash mapping with a real signature, not just a per-sct-result count.
  verifyGenuine(3, ecKp, ecPem, issuerKh, { issuerKeyHash: issuerKh }, "ecdsa-sha384", 5, "sha384");
  verifyGenuine(3, ecKp, ecPem, issuerKh, { issuerKeyHash: issuerKh }, "ecdsa-sha512", 6, "sha512");

  // Missing the issuing CA fails closed (embedded SCTs cannot verify without
  // it) rather than silently accepting or throwing.
  var ecLogId = logIdFor(ecPem);
  var logKeysEc = {}; logKeysEc[ecLogId.toString("hex")] = ecPem;
  var rvNoIssuer = nt.ct.verifyScts(ecCert, { logKeys: logKeysEc, minScts: 1 });
  check("verifyScts: without the issuing CA it fails closed (issuer-key-required)",
        rvNoIssuer.ok === false && rvNoIssuer.reason === "issuer-key-required");

  // A WRONG issuer key hash changes the signed input, so the same signature
  // no longer verifies — proves issuer_key_hash is actually bound. (The log
  // key still matches the SCT log_id, so this fails at the signature, not the
  // log-id binding.)
  var rvWrongIssuer = nt.ct.verifyScts(ecCert,
    { logKeys: logKeysEc, minScts: 1, issuerKeyHash: Buffer.alloc(32, 0xff) });
  check("verifyScts: a wrong issuer_key_hash makes the genuine SCT fail (binds the issuer)",
        rvWrongIssuer.ok === false && !!rvWrongIssuer.scts[0] &&
        rvWrongIssuer.scts[0].verified === false &&
        rvWrongIssuer.scts[0].reason === undefined);

  // A log key that does NOT hash to the SCT's log_id is rejected before its
  // signature is checked — the log_id is a commitment to the log's key, so a
  // misconfigured map cannot let another key impersonate an approved log.
  var otherEcPem = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .publicKey.export({ type: "spki", format: "pem" });
  var lkMismatch = {}; lkMismatch[ecLogId.toString("hex")] = otherEcPem;
  var rvBind = nt.ct.verifyScts(ecCert,
    { logKeys: lkMismatch, minScts: 1, issuerKeyHash: issuerKh });
  check("verifyScts: a key not hashing to the SCT log_id is refused (log-id-key-mismatch)",
        rvBind.ok === false && !!rvBind.scts[0] &&
        rvBind.scts[0].reason === "log-id-key-mismatch");

  // The issuerCertDer convenience path (SPKI extracted from a real issuer
  // cert) must resolve to the same hash and verify.
  var realIssuer = _makeRealSelfSignedCert(Buffer.from([0x77]));
  var realIssuerDer = Buffer.from(realIssuer.certPem
    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, ""), "base64");
  var realIssuerKh = nodeCrypto.createHash("sha256").update(
    new nodeCrypto.X509Certificate(realIssuerDer).publicKey
      .export({ type: "spki", format: "der" })).digest();
  verifyGenuine(3, ecKp, ecPem, realIssuerKh, { issuerCertDer: realIssuerDer }, "ecdsa+issuerCertDer");

  // requireScts derives the issuer from the peer chain (peerCert.issuer-
  // Certificate.raw) when the operator does not pass one.
  var logKeysReq = {}; logKeysReq[ecLogId.toString("hex")] = ecPem;
  var reqCert = verifyGenuine(3, ecKp, ecPem, realIssuerKh, { issuerCertDer: realIssuerDer }, "ecdsa+req");
  var gate = nt.ct.requireScts({ logKeys: logKeysReq, minScts: 1 });
  var gateErr = gate({ raw: reqCert, issuerCertificate: { raw: realIssuerDer } });
  check("requireScts: derives the issuer from the peer chain and admits a genuine SCT",
        gateErr === null);
}

// verifyScts hardening: distinct-log counting (Chrome CT diversity), a
// fail-closed extension walk over a hostile cert, minScts input validation,
// and RFC 6962 §5.2 future-timestamp refusal.
function testCtVerifyHardening() {
  var ecKp   = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var ecPem  = ecKp.publicKey.export({ type: "spki", format: "pem" });
  var logId  = nodeCrypto.createHash("sha256")
    .update(ecKp.publicKey.export({ type: "spki", format: "der" })).digest();
  var issuerKh = nodeCrypto.createHash("sha256").update(
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
      .publicKey.export({ type: "spki", format: "der" })).digest();
  var ts = 1700000000000;
  var logKeys = {}; logKeys[logId.toString("hex")] = ecPem;
  var opts = { logKeys: logKeys, issuerKeyHash: issuerKh };

  // Sign a genuine precert_entry SCT over a fixed stripped TBS (the strip is
  // independent of the SCT list, so a placeholder cert yields the same TBS).
  var placeholder = _synthCert({ cn: "Dup", exts: [_sctExt(_sctListRaw(
    [_buildSctBytes({ logId: logId, timestamp: ts, sig: Buffer.alloc(64, 0x01) })]))] });
  var strippedTbs = nt._stripSctExtensionFromCert(placeholder);
  var head = Buffer.alloc(12); head.writeBigUInt64BE(BigInt(ts), 2); head.writeUInt16BE(1, 10);
  var tbsLen = Buffer.alloc(3); tbsLen.writeUIntBE(strippedTbs.length, 0, 3);
  var signedEntry = Buffer.concat([head, issuerKh, tbsLen, strippedTbs, Buffer.from([0, 0])]);
  var genuineSct = _buildSctBytes({ logId: logId, sigAlgo: 3, hashAlgo: 4, timestamp: ts,
    sig: nodeCrypto.sign("sha256", signedEntry, ecKp.privateKey) });

  // #1 — the SAME genuine SCT embedded twice is one distinct log, so it cannot
  // satisfy a minScts:2 (diversity) policy, but does satisfy minScts:1.
  var dupCert = _synthCert({ cn: "Dup", exts: [_sctExt(_sctListRaw([genuineSct, genuineSct]))] });
  var rvDup2 = nt.ct.verifyScts(dupCert, Object.assign({ minScts: 2 }, opts));
  check("verifyScts: duplicate SCTs from one log do not satisfy minScts:2 (log diversity)",
        rvDup2.ok === false && rvDup2.verifiedCount === 1 && rvDup2.totalScts === 2);
  var rvDup1 = nt.ct.verifyScts(dupCert, Object.assign({ minScts: 1 }, opts));
  check("verifyScts: those same SCTs verify as one distinct log at minScts:1",
        rvDup1.ok === true && rvDup1.verifiedCount === 1);

  // #2 — a hostile cert whose extension is not (OID, ..., OCTET STRING) must
  // NOT throw out of verifyScts; it fails closed to no-sct-extension.
  var badExtCert = _synthCert({ cn: "BadExt", exts: [asn1.writeSequence(
    [asn1.writeInteger(Buffer.from([1])), asn1.writeOctetString(Buffer.from([2]))])] });
  var threwExt = false, rvBadExt;
  try { rvBadExt = nt.ct.verifyScts(badExtCert, opts); } catch (_e) { threwExt = true; }
  check("verifyScts: a malformed extension does not throw (fails closed)",
        threwExt === false && rvBadExt.reason === "no-sct-extension");
  // An SCT-OID extension whose value is not a nested OCTET STRING also fails closed.
  var badSctCert = _synthCert({ cn: "BadSct", exts: [asn1.writeSequence(
    [asn1.writeOid(OID_CT_SCT_LIST), asn1.writeOctetString(asn1.writeInteger(Buffer.from([9])))])] });
  check("verifyScts: an SCT ext not wrapping a nested OCTET STRING fails closed",
        nt.ct.verifyScts(badSctCert, opts).reason === "no-sct-extension");

  // #3 — minScts must be a positive integer; a 0/negative policy would accept
  // unverified certs, so it throws at the entry point.
  var threwZero = false;
  try { nt.ct.verifyScts(dupCert, Object.assign({ minScts: 0 }, opts)); }
  catch (e) { threwZero = e && e.code === "tls/ct-bad-input"; }
  check("verifyScts: minScts:0 throws tls/ct-bad-input (no fail-open policy)", threwZero === true);
  var threwNeg = false;
  try { nt.ct.verifyScts(dupCert, Object.assign({ minScts: -1 }, opts)); } catch (_e) { threwNeg = true; }
  check("verifyScts: a negative minScts throws", threwNeg === true);

  // #4 — an SCT timestamped in the future (relative to opts.now) is refused
  // (RFC 6962 §5.2); a past-dated one is not refused on timestamp grounds.
  var futSct = _buildSctBytes({ logId: logId, timestamp: 2000000000000 });   // ~2033
  var futCert = _synthCert({ cn: "Fut", exts: [_sctExt(_sctListRaw([futSct]))] });
  var rvFut = nt.ct.verifyScts(futCert, Object.assign({ now: 1700000000000 }, opts));
  check("verifyScts: a future-dated SCT is refused (timestamp-in-future)",
        rvFut.ok === false && !!rvFut.scts[0] && rvFut.scts[0].reason === "timestamp-in-future");
  var rvPast = nt.ct.verifyScts(dupCert, Object.assign({ now: 1700000000001, minScts: 1 }, opts));
  check("verifyScts: a past-dated SCT is not refused on timestamp grounds (reaches verification)",
        !!rvPast.scts[0] && rvPast.scts[0].reason !== "timestamp-in-future");
  // A non-finite clockSkewMs must not fail open — it falls back to the default
  // skew, so the future SCT is still refused.
  var rvNanSkew = nt.ct.verifyScts(futCert,
    Object.assign({ now: 1700000000000, clockSkewMs: NaN }, opts));
  check("verifyScts: a NaN clockSkewMs does not fail open (future SCT still refused)",
        rvNanSkew.ok === false && rvNanSkew.scts[0].reason === "timestamp-in-future");
}

async function run() {
  testNetworkTlsErrorPermanentClassification();
  testInsecureTlsAudit();
  testEchSurface();
  testEchParseDraft22();
  testEchParseAcceptsBase64();
  testEchMalformedFraming();
  testEchUnknownVersion();
  testEchConnectWithEchOptShape();
  await testEchConnectWithBadOverrideEchConfig();
  await testConnectWithEchAgainstLocalServer();
  testPkixSurface();
  testPkixSanRequiredWhenAbsent();
  testPkixCnFallbackRefused();
  testPkixDnsExactMatch();
  testPkixDnsCaseInsensitive();
  testPkixWildcardOneLabelOnly();
  testPkixWildcardPartialRefused();
  testPkixWildcardTooBroadRefused();
  testPkixIpSanIpv4();
  testPkixIpSanIpv6Canonicalization();
  testPkixIpSanCrossFamilyRefuses();
  testPkixSanWithMultipleEntries();
  testPkixQuotedSanNoBypass();
  testPkixHostShape();

  nt._resetForTest();
  try {
    // CA store
    testAddCaShapes();
    testAddCaRejections();
    testAddCaFromFileAndDir();
    testRemoveCa();
    testRemoveCaByLabel();
    testClearAll();
    testPurgeExpired();
    testExpiringSoon();
    testSystemTrustAndApplyToContext();
    testBaselineDrift();
    // monitors
    testMonitorValidation();
    await testExpiryMonitorTick();
    await testPinsetDriftMonitorTick();
    // trust-store audit-emit + no-arg guards, cert path-like rejection,
    // PKIX wildcard-walk / strict-combiner, SNI metadata fallbacks
    testTrustStoreAuditEmitAndGuards();
    testCertPathLikeRejections();
    testPkixWildcardLabelWalk();
    testStrictCombinerAndEmptySanCn();
    testWrapSniCallbackNonStringServername();
    // monitor tick branches (ok / no-callback / throwing-callback / no-baseline)
    await testExpiryMonitorOkTick();
    await testExpiryMonitorNoCallbackWarnTick();
    await testExpiryMonitorThrowingCallback();
    await testPinsetDriftMonitorOkTick();
    await testPinsetDriftMonitorNoCallback();
    await testPinsetDriftMonitorThrowingCallback();
    await testPinsetDriftMonitorNoBaseline();
    // PQC
    testPqcKeyShares();
    // buildOptions
    testBuildOptionsBranches();
    // OCSP
    testOcspParseShapeErrors();
    testOcspParseUnsupportedResponseType();
    testOcspParseBadTime();
    testOcspParseUtcTimeYear();
    testOcspEvaluateBranches();
    testOcspEvaluateNonce();
    testOcspEvaluateIssuerBindShapeErrors();
    testOcspBuildRequest();
    testOcspCertShapeErrors();
    testOcspEvaluateDeepBinding();
    await testOcspFetchGuards();
    await testOcspFetchRequestPath();
    await testOcspRequireGoodEmpty();
    await testOcspConnectRealPaths();
    testOcspMustStaple();
    // CT
    testCtInspectAndParse();
    testCtVerifyScts();
    testCtVerifySctAlgoGateReadsSigAlgoField();
    testCtVerifyHardening();
    testCtVerifyMoreScts();
    testCtParseSctErrors();
    testSctAndTlsFeatureTolerance();
    testCtVerifyInclusion();
    testCtInclusionExtra();
    testCtMerklePaths();
    testCtVerifyConsistency();
    // ECH extra framing + real connect
    testEchExtraFraming();
    await testConnectWithEchRealConnect();
    // PKIX extra branches
    testPkixMoreBranches();
    // SNI
    testWrapSniCallback();
    // Branch-coverage extension — crafted OCSP/CT/ECH/PKIX edge inputs
    testOcspParseShapeGuardsMore();
    testOcspBuildRequestIssuerShapes();
    await testOcspNoArgGuards();
    testRemoveCaAuditArm();
    testCtSctExtractorEdges();
    testTlsFeatureExtractorEdges();
    testCtSctBytesParseErrors();
    testEchInternalReaderFraming();
    testEchExtensionsLoop();
    await testConnectWithEchConfigAndStringOverride();
    testPkixHelperEdges();
    testCtVerifierOptionalShapes();
    testOcspEvaluateMoreBranches();
    testOcspBuildRequestNoArg();
    testCtExtractorNoMatchTails();
    testCtVerifyInclusionStripFailures();
    testCtVerifyStripAndHashAlgos();
    testCtMerkleGuardsMore();
    await testOcspRequireGoodWithIssuerBinding();
    testOcspEvaluateParseAndStatusBranches();
    testCtStripNoExtAndLongLength();
  } finally {
    nt._resetForTest();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
