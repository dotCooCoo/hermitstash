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
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

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
  testPkixHostShape();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
