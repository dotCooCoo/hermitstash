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

  // Cert with an SCT but no log keys -> insufficient-verified, per-sct log-key-missing.
  var sct = _buildSctBytes({});
  var withSct = _synthCert({ cn: "SCT CA", exts: [_sctExt(_sctListRaw([sct]))] });
  var rv = nt.ct.verifyScts(withSct, {});
  check("verifyScts with no log keys -> ok false insufficient-verified",
        rv.ok === false && rv.reason === "insufficient-verified" && rv.scts[0].reason === "log-key-missing");

  // Parse-error: lie about the outer SCT-list length.
  var badList = _sctListRaw([sct], { lieOuterLen: 9999 });
  var badCert = _synthCert({ cn: "Bad SCT", exts: [_sctExt(badList)] });
  var badRv = nt.ct.verifyScts(badCert, {});
  check("verifyScts with malformed SCT list -> reason parse-error", badRv.reason === "parse-error");

  // requireScts predicate.
  var predicate = nt.ct.requireScts({});
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
  var logHex = "aa".repeat(32);
  function _logKeys(pem) { var m = {}; m[logHex] = pem; return m; }

  // Unsupported SCT hash algorithm (not sha256/384/512) with a present key.
  var badHash = _buildSctBytes({ hashAlgo: 99 });
  var badHashCert = _synthCert({ cn: "BadHash", exts: [_sctExt(_sctListRaw([badHash]))] });
  var r1 = nt.ct.verifyScts(badHashCert, { logKeys: _logKeys(ecPub), minScts: 1 });
  check("verifyScts unsupported SCT hash algo -> per-sct unsupported-hash-algo",
        r1.scts[0].reason === "unsupported-hash-algo");

  // Log key present but unparseable.
  var okSct  = _buildSctBytes({});
  var okCert = _synthCert({ cn: "OkSct", exts: [_sctExt(_sctListRaw([okSct]))] });
  var r2 = nt.ct.verifyScts(okCert, { logKeys: _logKeys("not a pem"), minScts: 1 });
  check("verifyScts unparseable log key -> log-key-parse-failed",
        r2.scts[0].reason === "log-key-parse-failed");

  // SCT claims RSA (sigAlgo 1) but the registered log key is EC → mismatch.
  var rsaClaim = _buildSctBytes({ sigAlgo: 1 });
  var rsaCert  = _synthCert({ cn: "RsaClaim", exts: [_sctExt(_sctListRaw([rsaClaim]))] });
  var r3 = nt.ct.verifyScts(rsaCert, { logKeys: _logKeys(ecPub), minScts: 1 });
  check("verifyScts SCT-algo vs log-key-type mismatch -> log-key-algo-mismatch",
        r3.scts[0].reason === "log-key-algo-mismatch");

  // Valid EC key + matching algo but a garbage signature → not verified
  // (verify returns false, or throws and is caught) → insufficient.
  var r4 = nt.ct.verifyScts(okCert, { logKeys: _logKeys(ecPub), minScts: 1 });
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
  } finally {
    nt._resetForTest();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
