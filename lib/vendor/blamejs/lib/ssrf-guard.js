// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.ssrfGuard
 * @nav    HTTP
 * @title  SSRF Guard
 *
 * @intro
 *   Outbound-URL Server-Side-Request-Forgery defense. Every URL the
 *   framework dials on behalf of an operator (b.httpClient, webhook
 *   delivery, OAuth discovery, OIDC JWKS fetch, image-by-URL upload)
 *   routes through the gate. The gate refuses private (RFC 1918 +
 *   RFC 4193 ULA), loopback (127/8 + ::1), link-local
 *   (169.254/16 + fe80::/10), reserved / documentation / CGNAT,
 *   IPv4-mapped / 6to4 / NAT64 / discard-prefix wrappers, and the
 *   cloud-metadata IPs (169.254.169.254 AWS/GCP/Azure/OpenStack/DO,
 *   169.254.170.2 AWS ECS task role, fd00:ec2::254 IPv6 IMDS).
 *
 *   DNS rebinding is closed by resolving the hostname once during
 *   classification AND returning the validated IP set in the result.
 *   b.httpClient pins the actual TCP connect to those exact addresses
 *   via a custom `lookup` callback — a hostile DNS server cannot flip
 *   the answer between guard-check and connect. Redirect chains are
 *   re-validated end-to-end by b.httpClient (each Location header
 *   passes through `checkUrl` before the next hop is dialed), and
 *   `createAllowlist` builds operator-specific egress allowlists that
 *   compose on top of the framework's hard-coded ban list.
 *
 *   Cloud-metadata IPs are blocked unconditionally — `allowInternal`
 *   does NOT override this class because metadata endpoints leak
 *   instance credentials. Operators with a legitimate need for the
 *   metadata service do it through their cloud SDK with explicit IAM,
 *   never through the framework's outbound HTTP.
 *
 * @card
 *   Outbound-URL Server-Side-Request-Forgery defense.
 */

var dns = require("node:dns").promises;
var net = require("node:net");

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");

var { FrameworkError } = require("./framework-error");

var networkDns = lazyRequire(function () { return require("./network-dns"); });

// IP address bit-widths (RFC 791 §3.1 IPv4, RFC 4291 §2.5 IPv6) and
// CIDR prefix arithmetic constants. The numerals in this file are
// bit-counts in IP-address space, not byte sizes; routed through
// C.BYTES.bytes (a value-passthrough) so every numeric literal in the
// codebase has a single source of truth for "what shape is this number".
var IPV4_BITS     = C.BYTES.bytes(32);
var IPV6_BITS     = C.BYTES.bytes(128);
var BITS_PER_BYTE = C.BYTES.bytes(8);
var IPV6_BYTES    = C.BYTES.bytes(16);     // 128 bits / 8 bits-per-byte
var IPV6_GROUPS   = C.BYTES.bytes(8);      // hex groups
var HEX_RADIX     = C.BYTES.bytes(16);     // parseInt / toString radix

/**
 * @primitive b.ssrfGuard.SsrfError
 * @signature b.ssrfGuard.SsrfError
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.checkUrl, b.ssrfGuard.createAllowlist
 *
 * Error class thrown by every `b.ssrfGuard` primitive on a refused
 * URL or refused address. Extends `FrameworkError`. Carries a stable
 * `.code` (e.g. `ssrf-guard/blocked-cloud-metadata`,
 * `ssrf-guard/blocked-private`, `ssrf-guard/not-on-allowlist`) plus
 * the offending `.url` / `.ip` / `.category` for the audit log. Is
 * marked `.permanent = true` so retry layers do not loop on it.
 *
 * @example
 *   var b = require("blamejs");
 *   try {
 *     await b.ssrfGuard.checkUrl("http://169.254.169.254/latest/meta-data/");
 *   } catch (e) {
 *     e instanceof b.ssrfGuard.SsrfError;   // → true
 *     e.code;                               // → "ssrf-guard/blocked-cloud-metadata"
 *     e.category;                           // → "cloud-metadata"
 *   }
 */
class SsrfError extends FrameworkError {
  constructor(message, code, ctx) {
    super(message, code);
    this.name = "SsrfError";
    this.permanent = true;
    this.isSsrfError = true;
    if (ctx) {
      this.url = ctx.url || null;
      this.ip = ctx.ip || null;
      this.category = ctx.category || null;
    }
  }
}

// ---- IPv4 ranges (as numeric prefix tables for fast match) ----
// Each entry: [networkInt, prefixLen]
var IPV4_PRIVATE = [
  [_ipv4ToInt("10.0.0.0"),     C.BYTES.bytes(8)],
  [_ipv4ToInt("172.16.0.0"),  C.BYTES.bytes(12)],
  [_ipv4ToInt("192.168.0.0"), C.BYTES.bytes(16)],
];
var IPV4_LOOPBACK = [
  [_ipv4ToInt("127.0.0.0"), C.BYTES.bytes(8)],
];
var IPV4_LINK_LOCAL = [
  [_ipv4ToInt("169.254.0.0"), C.BYTES.bytes(16)],
];
var IPV4_RESERVED = [
  [_ipv4ToInt("0.0.0.0"),         C.BYTES.bytes(8)],   // "this network"
  [_ipv4ToInt("100.64.0.0"),     C.BYTES.bytes(10)],   // CGNAT (RFC 6598)
  [_ipv4ToInt("192.0.0.0"),      C.BYTES.bytes(24)],   // IETF protocol assignments
  [_ipv4ToInt("192.0.2.0"),      C.BYTES.bytes(24)],   // TEST-NET-1
  [_ipv4ToInt("198.18.0.0"),     C.BYTES.bytes(15)],   // network benchmark
  [_ipv4ToInt("198.51.100.0"),   C.BYTES.bytes(24)],   // TEST-NET-2
  [_ipv4ToInt("203.0.113.0"),    C.BYTES.bytes(24)],   // TEST-NET-3
  [_ipv4ToInt("224.0.0.0"),       C.BYTES.bytes(4)],   // multicast
  [_ipv4ToInt("240.0.0.0"),       C.BYTES.bytes(4)],   // reserved + 255.255.255.255
];

// ---- IPv6 ranges (as 16-byte prefix tables) ----
var IPV6_LOOPBACK_BYTES   = _ipv6ToBytes("::1");
var IPV6_UNSPECIFIED_BYTES = _ipv6ToBytes("::");
var IPV6_PRIVATE_PREFIX   = _ipv6ToBytes("fc00::");
var IPV6_LINK_LOCAL_PREFIX = _ipv6ToBytes("fe80::");
var IPV6_DOC_PREFIX       = _ipv6ToBytes("2001:db8::");      // documentation
// IPv4-mapped IPv6 (::ffff:0:0 with C.BYTES.bytes(96)-bit prefix)
var IPV6_V4_MAPPED_PREFIX = _ipv6ToBytes("::ffff:0:0");
// Multicast ff00::/8 — RFC 4291 §2.7. Refused for outbound HTTP same as
// IPv4 multicast 224/4 — there's no legitimate fetch from a multicast
// destination on a production gateway.
var IPV6_MULTICAST_PREFIX = _ipv6ToBytes("ff00::");
// NAT64 well-known prefix 64:ff9b::/96 — RFC 6052. Translates to IPv4
// embedded in the lower 32 bits; the framework refuses since the
// underlying v4 address is what gets contacted and might be private.
// (Operators with NAT64 deployments flip allowInternal.)
var IPV6_NAT64_PREFIX     = _ipv6ToBytes("64:ff9b::");
// 6to4 2002::/16 — RFC 3056. Carries an embedded IPv4 in bytes 2-5;
// hostile use is to tunnel through to a v4 destination the v4 guard
// would have refused. Refused.
var IPV6_6TO4_PREFIX      = _ipv6ToBytes("2002::");
// Discard prefix 100::/64 — RFC 6666. Dropped by routers; fetching
// from it is operationally meaningless and a likely sign of mis-config
// or attempted exfil to a sinkhole.
var IPV6_DISCARD_PREFIX   = _ipv6ToBytes("100::");

// ---- Cloud metadata addresses (matched on CANONICAL bytes, not string) ----
// The documentation strings below are the human-readable canonical forms.
// Matching is byte-canonical (see _isCloudMetadataAddr): an IPv6 address has
// many textual representations (compressed `::`, fully-expanded
// `fd00:ec2:0:0:0:0:0:254`, mixed-case) that all decode to the same 16 bytes.
// A string-equality membership test matched only ONE spelling, so a hostile
// (or merely DoH-decoded — network-dns.js emits the expanded form) answer of
// `fd00:ec2:0:0:0:0:0:254` slipped past as "private" and rode the documented
// `allowInternal:true` waiver straight into the IMDS credential endpoint.
var CLOUD_METADATA_IPS = [
  "169.254.169.254",       // AWS, GCP, Azure, OpenStack, DO
  "169.254.170.2",         // AWS ECS task role
  "fd00:ec2::254",         // AWS IMDS over IPv6
];
// Canonical byte forms of the metadata IPs — v4 as a 4-byte Buffer, v6 as a
// 16-byte Buffer. Built once at load via the same parsers classify() uses,
// so every textual representation that decodes to these bytes is caught.
var CLOUD_METADATA_BYTES = CLOUD_METADATA_IPS.map(function (ip) {
  var fam = net.isIP(ip);
  return fam === 4 ? _ipv4ToBytes(ip) : _ipv6ToBytes(ip);
});

// ---- Helpers ----

function _ipv4ToInt(ip) {
  var parts = ip.split(".");
  if (parts.length !== 4) return NaN;
  var nums = [0, 0, 0, 0];
  for (var i = 0; i < 4; i += 1) {
    var s = parts[i];
    // Strict octet validation: each segment must be 1-3 ASCII digits
    // representing 0-255. The previous `parts[i] | 0` coerced
    // anything non-numeric to 0 silently — exposed via cidrContains
    // (network-allowlist) where a typo'd CIDR could collapse to
    // 0.0.0.0/16 with no signal.
    if (typeof s !== "string" || s.length === 0 || s.length > 3) return NaN;
    if (!/^\d{1,3}$/.test(s)) return NaN;
    var n = parseInt(s, 10);
    if (n < 0 || n > 255) return NaN;
    nums[i] = n;
  }
  return ((nums[0] << 24) >>> 0) +
         (nums[1] << 16) +
         (nums[2] << 8) +
          nums[3];
}

function _ipv4ToBytes(ip) {
  // Canonical 4-byte form of an IPv4 address. Returns null on malformed
  // input so a metadata-membership test never matches garbage.
  var n = _ipv4ToInt(ip);
  if (!Number.isFinite(n)) return null;
  return Buffer.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function _ipv6ToBytes(ip) {
  // Node's net.isIPv6 returns 6 for valid IPv6; we then expand
  // shorthand via manual parsing. node:net doesn't export an
  // ipv6-to-bytes helper, but the URL constructor + Buffer dance
  // is reliable for canonicalizing.
  var groups = _expandIpv6(ip);
  var out = Buffer.alloc(IPV6_BYTES);
  for (var i = 0; i < IPV6_GROUPS; i++) {
    var v = parseInt(groups[i], HEX_RADIX) || 0;
    out[i * 2] = (v >> 8) & 0xff;
    out[i * 2 + 1] = v & 0xff;
  }
  return out;
}

function _expandIpv6(ip) {
  // Handle "::" zero-elision + IPv4-mapped suffix ("::ffff:1.2.3.4").
  var lower = ip.toLowerCase();
  // IPv4-mapped: convert trailing dotted-quad to two hex groups
  var dot = lower.lastIndexOf(":");
  if (dot !== -1 && lower.indexOf(".", dot) !== -1) {
    var v4 = lower.slice(dot + 1);
    var ipv4Int = _ipv4ToInt(v4);
    var hi = (ipv4Int >>> 16) & 0xffff;
    var lo = ipv4Int & 0xffff;
    lower = lower.slice(0, dot + 1) + hi.toString(HEX_RADIX) + ":" + lo.toString(HEX_RADIX);
  }
  var doubleColon = lower.indexOf("::");
  var leftStr, rightStr;
  if (doubleColon === -1) {
    leftStr  = lower;
    rightStr = "";
  } else {
    leftStr  = lower.slice(0, doubleColon);
    rightStr = lower.slice(doubleColon + 2);
  }
  var left  = leftStr.length  ? leftStr.split(":")  : [];
  var right = rightStr.length ? rightStr.split(":") : [];
  var missing = IPV6_GROUPS - left.length - right.length;
  var fill = [];
  for (var i = 0; i < missing; i++) fill.push("0");
  return left.concat(fill).concat(right);
}

function _ipv6BytesToString(bytes) {
  // RFC 5952 §4 canonical textual form from 16 canonical bytes: lower-hex,
  // no leading zeros per group, the LONGEST run of two-or-more zero groups
  // compressed to "::" (leftmost run on a length tie — §4.2.3), and the
  // shortened-but-not-IPv4-dotted form (the framework keeps IPv4-mapped as
  // pure hex so every mapped spelling collapses to one string). Driven off
  // the same 16-byte buffer classify() matches on, so the emitted string and
  // the security verdict can never disagree about which address this is.
  var groups = [];
  for (var i = 0; i < IPV6_GROUPS; i++) {
    groups.push(((bytes[i * 2] << 8) | bytes[i * 2 + 1]) & 0xffff);
  }
  var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (var g = 0; g < IPV6_GROUPS; g++) {
    if (groups[g] === 0) {
      if (curStart === -1) { curStart = g; curLen = 1; } else { curLen += 1; }
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  // A single zero group is NOT compressed (RFC 5952 §4.2.2).
  if (bestLen < 2) bestStart = -1;
  var parts = [];
  for (var k = 0; k < IPV6_GROUPS; k++) {
    if (bestStart !== -1 && k === bestStart) {
      parts.push("");
      k += bestLen - 1;
      // A run reaching the final group needs a trailing empty part so the
      // join yields the "::"-terminated form (e.g. fe80:: not fe80:).
      if (k === IPV6_GROUPS - 1) parts.push("");
      continue;
    }
    parts.push(groups[k].toString(HEX_RADIX));
  }
  var out = parts.join(":");
  // A run starting at group 0 needs a leading empty part ("::1", "::").
  if (bestStart === 0) out = ":" + out;
  return out;
}

/**
 * @primitive b.ssrfGuard.canonicalizeHost
 * @signature b.ssrfGuard.canonicalizeHost(host)
 * @since     0.15.6
 * @status    stable
 * @related   b.ssrfGuard.classify, b.safeUrl.canonicalize
 *
 * Canonicalize a bare host string to its single comparable form for
 * host allowlists, dedup keys, and SSRF pre-checks. A `net.isIP`-valid
 * IP literal collapses to one canonical string: a dotted-quad IPv4
 * stays dotted-quad; IPv6 in any zero-compression / mixed-case /
 * IPv4-mapped spelling (`[0:0:0:0:0:ffff:7f00:1]`, `::FFFF:7F00:1`)
 * becomes the RFC 5952 lower-hex compressed form. The IP bytes are
 * parsed by the SAME routines `classify` matches on, so the canonical
 * string and the SSRF verdict can never disagree about which address a
 * host is.
 *
 * The numeric-base IPv4 decode (octal `0177.0.0.1`, hex `0x7f000001`,
 * single-integer `2130706433`, shorthand `127.1`) is the WHATWG URL
 * parser's job — `b.safeUrl.canonicalize` runs that FIRST and hands this
 * primitive the already-decoded dotted-quad. This is the IP-byte + case
 * layer, not the base decoder.
 *
 * A DNS name (not an IP literal) is lowercased and any trailing dot is
 * stripped — `Example.COM.` → `example.com`. IDN A-label / U-label
 * normalization is NOT done here (the WHATWG URL parser owns that via
 * `b.safeUrl.canonicalize`).
 * `[...]`-bracketed IPv6 input is accepted (brackets stripped); the
 * returned IPv6 string is UNbracketed (the URL layer re-adds brackets).
 *
 * @example
 *   var b = require("blamejs");
 *   b.ssrfGuard.canonicalizeHost("[0:0:0:0:0:0:0:1]");    // → "::1"
 *   b.ssrfGuard.canonicalizeHost("::FFFF:7F00:1");        // → "::ffff:7f00:1"
 *   b.ssrfGuard.canonicalizeHost("Example.COM.");         // → "example.com"
 */
function canonicalizeHost(host) {
  if (typeof host !== "string" || host.length === 0) return host;
  var bare = host.replace(/^\[|\]$/g, "");
  var family = net.isIP(bare);
  if (family === 4) {
    var v4 = _ipv4ToBytes(bare);
    if (v4) return v4[0] + "." + v4[1] + "." + v4[2] + "." + v4[3];
    return bare.toLowerCase();
  }
  if (family === 6) {
    var v6bytes = _ipv6ToBytes(bare);
    // An IPv4-mapped IPv6 address (::ffff:a.b.c.d, the ::ffff:0:0/96 block) IS
    // the IPv4 address a.b.c.d for routing / access control — classify() already
    // re-classifies it by the embedded v4, and a dual-stack peer arriving on
    // ::ffff:1.2.3.4 reaches the same host as 1.2.3.4. Fold it to the dotted
    // IPv4 form so a dual-stack peer and an operator's IPv4 allowlist entry
    // canonicalize equal. ONLY the IPv4-mapped block (::ffff:0:0/96) folds,
    // because classify(::ffff:x) === classify(x) — its classify branch returns
    // the embedded-v4 verdict with no reserved fallback, so folding can't change
    // an SSRF verdict. NAT64 (64:ff9b::/96) and 6to4 (2002::/16) are NOT folded:
    // classify treats a NAT64 literal as `classify(v4) || "reserved"`, so a
    // public NAT64 address classifies as "reserved" while its embedded v4 is
    // null — folding would flip a blocked verdict to an allowed public IPv4.
    // classify still reaches the embedded v4 for the deny side; the canonical
    // form keeps NAT64 / 6to4 as IPv6 so canonicalize-then-classify agrees with
    // classify alone.
    if (_ipv6PrefixMatch(IPV6_V4_MAPPED_PREFIX, C.BYTES.bytes(96), v6bytes)) {
      return v6bytes[12] + "." + v6bytes[13] + "." + v6bytes[14] + "." + v6bytes[15];
    }
    return _ipv6BytesToString(v6bytes);
  }
  // Not an IP literal — DNS name. Lowercase + strip ALL trailing dots: a
  // hostname's trailing-dot count is not significant for identity (the root
  // label is empty), so host / host. / host.. must collapse to one form or a
  // trailing-dot count bypasses a host allow/deny comparison.
  var name = bare.toLowerCase().replace(/\.+$/, "");
  return name;
}

function _cidrIpv4Match(cidr, ip) {
  var slash = cidr.indexOf("/");
  if (slash === -1) return false;
  var network = _ipv4ToInt(cidr.slice(0, slash));
  var prefix = parseInt(cidr.slice(slash + 1), 10);
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > IPV4_BITS) return false;
  var ipInt = _ipv4ToInt(ip);
  if (prefix === 0) return true;
  var mask = (0xffffffff << (IPV4_BITS - prefix)) >>> 0;
  return (ipInt & mask) === (network & mask);
}

function _cidrIpv6Match(cidr, ip) {
  var slash = cidr.indexOf("/");
  if (slash === -1) return false;
  var network = _ipv6ToBytes(cidr.slice(0, slash));
  var prefix = parseInt(cidr.slice(slash + 1), 10);
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > IPV6_BITS) return false;
  var bytes = _ipv6ToBytes(ip);
  var fullBytes = Math.floor(prefix / BITS_PER_BYTE);
  var remainingBits = prefix % BITS_PER_BYTE;
  for (var i = 0; i < fullBytes; i++) {
    if (bytes[i] !== network[i]) return false;
  }
  if (remainingBits > 0) {
    var mask = (0xff << (BITS_PER_BYTE - remainingBits)) & 0xff;
    if ((bytes[fullBytes] & mask) !== (network[fullBytes] & mask)) return false;
  }
  return true;
}

function _ipv4PrefixMatch(prefixTable, ipInt) {
  for (var i = 0; i < prefixTable.length; i++) {
    var net4 = prefixTable[i][0];
    var prefix = prefixTable[i][1];
    var mask = prefix === 0 ? 0 : (0xffffffff << (IPV4_BITS - prefix)) >>> 0;
    if ((ipInt & mask) === (net4 & mask)) return true;
  }
  return false;
}

function _ipv6PrefixMatch(prefixBytes, prefixLen, ipBytes) {
  var fullBytes = Math.floor(prefixLen / BITS_PER_BYTE);
  var remainingBits = prefixLen % BITS_PER_BYTE;
  for (var i = 0; i < fullBytes; i++) {
    if (ipBytes[i] !== prefixBytes[i]) return false;
  }
  if (remainingBits > 0) {
    var mask = (0xff << (BITS_PER_BYTE - remainingBits)) & 0xff;
    if ((ipBytes[fullBytes] & mask) !== (prefixBytes[fullBytes] & mask)) return false;
  }
  return true;
}

// ---- Public classification API ----

/**
 * @primitive b.ssrfGuard.classify
 * @signature b.ssrfGuard.classify(ip)
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.checkUrl, b.ssrfGuard.cidrContains
 *
 * Synchronous IP-string classifier. Returns one of `"loopback"`,
 * `"link-local"`, `"private"`, `"reserved"`, `"cloud-metadata"`, or
 * `null` when the address is a routable public IP (or not a valid IP
 * at all — non-string / malformed input returns `null` rather than
 * throwing). Recognizes IPv4-mapped (`::ffff:a.b.c.d`), 6to4
 * (`2002::/16`), and NAT64 (`64:ff9b::/96`) v6 wrappers and reclassifies
 * the embedded v4 address — a 6to4-wrapped private IP returns
 * `"private"`, never `null`.
 *
 * @example
 *   var b = require("blamejs");
 *   b.ssrfGuard.classify("169.254.169.254");   // → "cloud-metadata"
 *   b.ssrfGuard.classify("10.0.0.1");          // → "private"
 *   b.ssrfGuard.classify("127.0.0.1");         // → "loopback"
 *   b.ssrfGuard.classify("8.8.8.8");           // → null
 *   b.ssrfGuard.classify("::ffff:10.0.0.1");   // → "private"
 */
function classify(ip) {
  if (typeof ip !== "string") return null;
  var family = net.isIP(ip);
  if (family === 0) return null;

  // Cloud-metadata IPs are matched on their canonical byte form so every
  // textual spelling (compressed `::`, fully-expanded zero-runs, mixed
  // case) is caught — a string-equality test matched one spelling only.
  if (_isCloudMetadataAddr(ip, family)) return "cloud-metadata";

  if (family === 4) {
    var ipInt = _ipv4ToInt(ip);
    if (_ipv4PrefixMatch(IPV4_LOOPBACK,    ipInt)) return "loopback";
    if (_ipv4PrefixMatch(IPV4_LINK_LOCAL,  ipInt)) return "link-local";
    if (_ipv4PrefixMatch(IPV4_PRIVATE,     ipInt)) return "private";
    if (_ipv4PrefixMatch(IPV4_RESERVED,    ipInt)) return "reserved";
    return null;
  }

  // IPv6
  var bytes = _ipv6ToBytes(ip);
  if (_bufEqual(bytes, IPV6_LOOPBACK_BYTES))      return "loopback";
  if (_bufEqual(bytes, IPV6_UNSPECIFIED_BYTES))   return "reserved";
  if (_ipv6PrefixMatch(IPV6_LINK_LOCAL_PREFIX, C.BYTES.bytes(10), bytes))  return "link-local";
  if (_ipv6PrefixMatch(IPV6_PRIVATE_PREFIX,     7, bytes))  return "private";
  if (_ipv6PrefixMatch(IPV6_DOC_PREFIX,        C.BYTES.bytes(32), bytes))  return "reserved";
  if (_ipv6PrefixMatch(IPV6_MULTICAST_PREFIX,   C.BYTES.bytes(8), bytes))  return "reserved";
  if (_ipv6PrefixMatch(IPV6_DISCARD_PREFIX,    C.BYTES.bytes(64), bytes))  return "reserved";
  // 6to4 prefix embeds a v4 address in bytes 2–5; classify the
  // embedded v4 so a 6to4-wrapped private/metadata address is refused
  // for the same reason its v4 form would be.
  if (_ipv6PrefixMatch(IPV6_6TO4_PREFIX, C.BYTES.bytes(16), bytes)) {
    var v4From6to4 = bytes[2] + "." + bytes[3] + "." + bytes[4] + "." + bytes[5];
    return classify(v4From6to4) || "reserved";
  }
  // NAT64 well-known prefix embeds v4 in the lower bytes.
  if (_ipv6PrefixMatch(IPV6_NAT64_PREFIX, C.BYTES.bytes(96), bytes)) {
    var v4FromNat64 = bytes[12] + "." + bytes[13] + "." + bytes[14] + "." + bytes[15];
    return classify(v4FromNat64) || "reserved";
  }
  // IPv4-mapped addresses (::ffff:a.b.c.d): re-classify the v4 portion.
  if (_ipv6PrefixMatch(IPV6_V4_MAPPED_PREFIX, C.BYTES.bytes(96), bytes)) {
    var mappedV4 = bytes[12] + "." + bytes[13] + "." + bytes[14] + "." + bytes[15];
    return classify(mappedV4);
  }
  return null;
}

// Canonical-bytes membership test for the cloud-metadata IP set. An IP
// matches iff its parsed bytes equal one of CLOUD_METADATA_BYTES, regardless
// of textual representation. This is the unconditional metadata gate — it
// must NOT be string-based, because IPv6 has many spellings of the same
// address (the DoH resolver in network-dns.js, for instance, emits the
// fully-expanded `fd00:ec2:0:0:0:0:0:254` rather than the compressed form).
function _isCloudMetadataAddr(ip, family) {
  var fam = typeof family === "number" ? family : net.isIP(ip);
  if (fam === 0) return false;
  var bytes = fam === 4 ? _ipv4ToBytes(ip) : _ipv6ToBytes(ip);
  if (!bytes) return false;
  for (var i = 0; i < CLOUD_METADATA_BYTES.length; i++) {
    var ref = CLOUD_METADATA_BYTES[i];
    if (ref && ref.length === bytes.length && _bufEqual(bytes, ref)) return true;
  }
  return false;
}

function _bufEqual(a, b) {
  // Compares Buffer-like byte arrays for equality. The buffers here
  // are IP addresses, not secrets, so the comparison doesn't need
  // constant-time semantics — Buffer.compare uses native memcmp.
  return Buffer.compare(a, b) === 0;
}

/**
 * @primitive b.ssrfGuard.cidrContains
 * @signature b.ssrfGuard.cidrContains(cidr, ip)
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.classify, b.ssrfGuard.createAllowlist
 *
 * Returns `true` if `ip` falls inside the CIDR block `cidr`, else
 * `false`. Both arguments must be the same address family (v4-in-v4
 * or v6-in-v6 — mixed families return `false`). Used internally by
 * `checkUrl` to evaluate the operator's `allowInternal` exception
 * list and exposed publicly so operator code can drive the same
 * range arithmetic for routing / allowlist UI.
 *
 * @example
 *   var b = require("blamejs");
 *   b.ssrfGuard.cidrContains("10.0.0.0/8",   "10.1.2.3");      // → true
 *   b.ssrfGuard.cidrContains("10.0.0.0/8",   "11.0.0.1");      // → false
 *   b.ssrfGuard.cidrContains("fd00::/8",     "fd12:3456::1");  // → true
 *   b.ssrfGuard.cidrContains("10.0.0.0/8",   "::1");           // → false (mixed family)
 */
function cidrContains(cidr, ip) {
  if (typeof cidr !== "string" || typeof ip !== "string") return false;
  var slash = cidr.indexOf("/");
  if (slash === -1) return false;
  var network = cidr.slice(0, slash);
  var nFamily = net.isIP(network);
  var iFamily = net.isIP(ip);
  if (nFamily === 0 || iFamily === 0 || nFamily !== iFamily) return false;
  return nFamily === 4 ? _cidrIpv4Match(cidr, ip) : _cidrIpv6Match(cidr, ip);
}

// ---- URL check (DNS-resolving) ----

/**
 * @primitive b.ssrfGuard.checkUrl
 * @signature b.ssrfGuard.checkUrl(url, opts?)
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.classify, b.ssrfGuard.createAllowlist, b.httpClient.request
 *
 * Async DNS-resolving URL gate — the canonical pre-flight before
 * any outbound fetch / webhook delivery / OAuth discovery. Resolves
 * the hostname (via `b.network.dns` when available so DoH overrides
 * apply, else native `dns.lookup`), classifies every returned address,
 * and throws `SsrfError` on the first refused class. Cloud-metadata
 * IPs throw unconditionally; other classes can be overridden by
 * `allowInternal: true` (allow every private class) or
 * `allowInternal: ["10.0.0.0/8", ...]` (allow specific CIDRs only).
 *
 * Returns `{ url, ips }` on success — `ips` is the resolved address
 * list, suitable for passing to `https.request({ lookup })` so the
 * subsequent TCP connect pins to the validated set and a hostile DNS
 * server cannot rebind between guard-check and connect.
 *
 * @opts
 *   allowInternal: boolean | string[],   // override private-range refusal
 *                                        //   (cloud-metadata is NEVER overridable)
 *   errorClass:    Function,             // subclass of SsrfError to throw
 *   dnsLookup:     Function,             // override DNS resolver (testing / fixtures)
 *
 * @example
 *   // assertSafe before fetch — refuse private / metadata / loopback
 *   var b = require("blamejs");
 *   var result = await b.ssrfGuard.checkUrl("https://api.partner.example.com/v1/x");
 *   result.ips[0].address;   // → "203.0.113.42"
 *
 *   // Pin TCP connect to the validated IP set (defeats DNS rebinding):
 *   var validatedIps = result.ips;
 *   var lookup = function (host, opts, cb) { cb(null, validatedIps[0].address, validatedIps[0].family); };
 *
 * @example
 *   // Allow an internal mesh CIDR for one specific call:
 *   var b = require("blamejs");
 *   await b.ssrfGuard.checkUrl("http://10.0.5.42:8080/health", {
 *     allowInternal: ["10.0.0.0/8"],
 *   });
 *   // → { url: parsedUrl, ips: [{ address: "10.0.5.42", family: 4 }] }
 *
 * @example
 *   // Cloud-metadata IPs are blocked unconditionally (allowInternal does NOT override):
 *   var b = require("blamejs");
 *   try {
 *     await b.ssrfGuard.checkUrl("http://169.254.169.254/latest/meta-data/iam/", {
 *       allowInternal: true,
 *     });
 *   } catch (e) {
 *     e.code;       // → "ssrf-guard/blocked-cloud-metadata"
 *     e.category;   // → "cloud-metadata"
 *   }
 */
async function checkUrl(url, opts) {
  opts = opts || {};
  validateOpts(opts, ["allowInternal", "errorClass", "dnsLookup"], "ssrfGuard.checkUrl");

  var ErrorClass = opts.errorClass || SsrfError;
  var allowInternal = opts.allowInternal === true ? true :
                      Array.isArray(opts.allowInternal) ? opts.allowInternal :
                      false;

  var parsed = url instanceof URL ? url : safeUrl.parse(String(url), {
    allowedProtocols: safeUrl.ALLOW_HTTP_ALL,
    errorClass: ErrorClass,
  });
  if (!parsed.hostname) {
    throw new ErrorClass("URL '" + parsed.toString() + "' has no hostname",
      "ssrf-guard/no-hostname", { url: parsed.toString() });
  }

  // Strip IPv6 brackets — net.isIP doesn't accept "[::1]" form, only "::1"
  var hostForCheck = parsed.hostname.replace(/^\[|\]$/g, "");

  var ips;
  if (net.isIP(hostForCheck)) {
    ips = [{ address: hostForCheck, family: net.isIP(hostForCheck) }];
  } else {
    var lookup = opts.dnsLookup || function (host) {
      try {
        var nd = networkDns();
        if (nd && typeof nd.lookup === "function") {
          return nd.lookup(host, { all: true });
        }
      } catch (_e) { /* fall through to native */ }
      return dns.lookup(host, { all: true });
    };
    ips = await lookup(hostForCheck);
    if (!Array.isArray(ips)) ips = [ips];
  }

  for (var i = 0; i < ips.length; i++) {
    var addr = ips[i].address;
    var category = classify(addr);
    if (!category) continue;

    // Cloud-metadata IPs are NEVER allowed — they leak instance
    // credentials (AWS IMDS, GCP metadata, Azure IMDS) and a blanket
    // allowInternal bypass would let any compromised request exfiltrate
    // them. Operators with a legitimate need to talk to the metadata
    // service do it through the cloud SDK with explicit IAM, never
    // through the framework's outbound HTTP. Same hard-deny applies
    // to allowInternal=[cidr-list]: the list grants exception for
    // private ranges, not for the metadata IP that happens to fall
    // inside link-local.
    if (category === "cloud-metadata") {
      throw new ErrorClass(
        "URL '" + parsed.toString() + "' resolves to " + addr +
        " (cloud-metadata) — blocked unconditionally; allowInternal does NOT override " +
        "this class because metadata IPs leak instance credentials",
        "ssrf-guard/blocked-cloud-metadata",
        { url: parsed.toString(), ip: addr, category: category }
      );
    }

    if (allowInternal === true) continue;
    if (Array.isArray(allowInternal) && allowInternal.some(function (cidr) {
      return cidrContains(cidr, addr);
    })) continue;

    throw new ErrorClass(
      "URL '" + parsed.toString() + "' resolves to " + addr +
      " in the " + category + " range — pass allowInternal:true to override",
      "ssrf-guard/blocked-" + category,
      { url: parsed.toString(), ip: addr, category: category }
    );
  }
  return { url: parsed, ips: ips };
}

/**
 * @primitive b.ssrfGuard.createAllowlist
 * @signature b.ssrfGuard.createAllowlist(opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.checkUrl, b.ssrfGuard.cidrContains
 *
 * Build a contextual per-call egress allowlist composing on top of
 * `ssrfGuard`. Operators describe an allowed host / CIDR set plus an
 * optional denylist; the returned `{ assert(url) }` either resolves
 * to the validated IP set (delegating to `checkUrl` with
 * `allowInternal: true` because the explicit allowlist supersedes
 * the private-range refusal) or throws `SsrfError`. Distinct from
 * `checkUrl`'s hard-coded ban list — use `createAllowlist` when the
 * deployment has SPECIFIC outbound targets and everything else
 * should be refused.
 *
 * Throws at construction time if `allow` is empty (an empty
 * allowlist would refuse every URL — almost certainly a config typo).
 *
 * @opts
 *   allow: string[],   // required; entries are exact hostnames OR CIDR blocks
 *   deny:  string[],   // optional; checked AFTER allow — denylist wins
 *
 * @example
 *   // Allow-list a single partner domain — refuse everything else:
 *   var b = require("blamejs");
 *   var egress = b.ssrfGuard.createAllowlist({
 *     allow: ["api.partner.example.com", "203.0.113.0/24"],
 *     deny:  ["evil.partner.example.com"],
 *   });
 *   await egress.assert("https://api.partner.example.com/v1/x");
 *   // → { url: parsedUrl, ips: [{ address: "203.0.113.10", family: 4 }] }
 *
 * @example
 *   // Custom blocklist for cloud-metadata IPs at the allowlist layer
 *   // (defense-in-depth; checkUrl already refuses these unconditionally):
 *   var b = require("blamejs");
 *   var egress = b.ssrfGuard.createAllowlist({
 *     allow: ["10.0.0.0/8"],
 *     deny:  ["169.254.169.254", "169.254.170.2"],
 *   });
 *   try {
 *     await egress.assert("http://169.254.169.254/latest/");
 *   } catch (e) {
 *     e.code;   // → "ssrf-guard/blocked-cloud-metadata"
 *   }
 */
function createAllowlist(opts) {
  opts = opts || {};
  var allowList = Array.isArray(opts.allow) ? opts.allow.slice() : [];
  var denyList  = Array.isArray(opts.deny)  ? opts.deny.slice()  : [];
  if (allowList.length === 0) {
    throw new SsrfError(
      "network.allowlist.create requires at least one entry in `allow`",
      "ssrf-guard/empty-allowlist", {});
  }
  function _matches(list, hostOrIp) {
    // Canonicalize BOTH the URL host and each non-CIDR operator entry before
    // comparing: the URL parser already lowercases the host (and strips a
    // trailing dot), so a mixed-case or trailing-dot operator entry compared
    // raw silently failed to match — letting a denylisted host through.
    var canonHost = canonicalizeHost(hostOrIp);
    for (var i = 0; i < list.length; i++) {
      var entry = list[i];
      if (entry.indexOf("/") !== -1) {
        try { if (cidrContains(entry, hostOrIp)) return true; } catch (_e) { /* ignore */ }
      } else if (canonicalizeHost(entry) === canonHost) {
        return true;
      }
    }
    return false;
  }
  async function assertUrl(url) {
    var parsed;
    try { parsed = new URL(url); }                                                 // allow:raw-new-url-parse-only — local URL parse for hostname extraction
    catch (_e) {
      throw new SsrfError("invalid URL", "ssrf-guard/bad-url", { url: url });
    }
    var host = parsed.hostname;
    if (!_matches(allowList, host)) {
      throw new SsrfError(
        "URL host '" + host + "' not on the operator allowlist",
        "ssrf-guard/not-on-allowlist", { url: url, host: host });
    }
    if (_matches(denyList, host)) {
      throw new SsrfError(
        "URL host '" + host + "' on the operator denylist",
        "ssrf-guard/on-denylist", { url: url, host: host });
    }
    return checkUrl(parsed.toString(), { allowInternal: true });
  }
  return { assert: assertUrl };
}

/**
 * @primitive b.ssrfGuard.isPrivate
 * @signature b.ssrfGuard.isPrivate(ip)
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.classify
 *
 * Returns `true` if `ip` is in an RFC 1918 IPv4 private range
 * (10/8, 172.16/12, 192.168/16) or RFC 4193 IPv6 ULA (fc00::/7).
 * Convenience wrapper over `classify(ip) === "private"`.
 *
 * @example
 *   var b = require("blamejs");
 *   b.ssrfGuard.isPrivate("10.0.0.1");        // → true
 *   b.ssrfGuard.isPrivate("8.8.8.8");         // → false
 *   b.ssrfGuard.isPrivate("fd12:3456::1");    // → true
 */
function isPrivate(ip)       { return classify(ip) === "private"; }

/**
 * @primitive b.ssrfGuard.isLoopback
 * @signature b.ssrfGuard.isLoopback(ip)
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.classify
 *
 * Returns `true` if `ip` is in 127/8 (IPv4 loopback) or `::1`
 * (IPv6 loopback). Convenience wrapper over
 * `classify(ip) === "loopback"`.
 *
 * @example
 *   var b = require("blamejs");
 *   b.ssrfGuard.isLoopback("127.0.0.1");   // → true
 *   b.ssrfGuard.isLoopback("::1");         // → true
 *   b.ssrfGuard.isLoopback("8.8.8.8");     // → false
 */
function isLoopback(ip)      { return classify(ip) === "loopback"; }

/**
 * @primitive b.ssrfGuard.isLinkLocal
 * @signature b.ssrfGuard.isLinkLocal(ip)
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.classify, b.ssrfGuard.isCloudMetadata
 *
 * Returns `true` if `ip` is in 169.254/16 (IPv4 link-local) or
 * fe80::/10 (IPv6 link-local). Note that the cloud-metadata IPs
 * (169.254.169.254 / 169.254.170.2) classify as `"cloud-metadata"`,
 * NOT `"link-local"` — use `isCloudMetadata` if that distinction
 * matters.
 *
 * @example
 *   var b = require("blamejs");
 *   b.ssrfGuard.isLinkLocal("169.254.0.1");        // → true
 *   b.ssrfGuard.isLinkLocal("169.254.169.254");    // → false (it's cloud-metadata)
 *   b.ssrfGuard.isLinkLocal("fe80::1");            // → true
 */
function isLinkLocal(ip)     { return classify(ip) === "link-local"; }

/**
 * @primitive b.ssrfGuard.isCloudMetadata
 * @signature b.ssrfGuard.isCloudMetadata(ip)
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.classify, b.ssrfGuard.checkUrl
 *
 * Returns `true` if `ip` is one of the cloud-metadata service
 * addresses (169.254.169.254 AWS/GCP/Azure/OpenStack/DO,
 * 169.254.170.2 AWS ECS task role, fd00:ec2::254 IPv6 IMDS).
 * These IPs leak instance credentials and `checkUrl` refuses them
 * unconditionally — `allowInternal` does NOT override.
 *
 * @example
 *   var b = require("blamejs");
 *   b.ssrfGuard.isCloudMetadata("169.254.169.254");   // → true
 *   b.ssrfGuard.isCloudMetadata("169.254.170.2");     // → true
 *   b.ssrfGuard.isCloudMetadata("fd00:ec2::254");     // → true
 *   b.ssrfGuard.isCloudMetadata("169.254.0.1");       // → false (link-local but not metadata)
 */
function isCloudMetadata(ip) { return classify(ip) === "cloud-metadata"; }

/**
 * @primitive b.ssrfGuard.isReserved
 * @signature b.ssrfGuard.isReserved(ip)
 * @since     0.7.0
 * @status    stable
 * @related   b.ssrfGuard.classify
 *
 * Returns `true` if `ip` is in an IETF-reserved range — 0/8 ("this
 * network"), 100.64/10 (CGNAT, RFC 6598), 192.0.0/24 (IETF protocol
 * assignments), TEST-NET-1/2/3 (192.0.2/24, 198.51.100/24, 203.0.113/24),
 * 198.18/15 (network benchmark), 224/4 (multicast), 240/4 (reserved +
 * 255.255.255.255), 2001:db8::/32 (IPv6 documentation), ff00::/8 (IPv6
 * multicast), or 100::/64 (IPv6 discard prefix).
 *
 * @example
 *   var b = require("blamejs");
 *   b.ssrfGuard.isReserved("192.0.2.1");      // → true (TEST-NET-1)
 *   b.ssrfGuard.isReserved("100.64.0.1");     // → true (CGNAT)
 *   b.ssrfGuard.isReserved("224.0.0.1");      // → true (multicast)
 *   b.ssrfGuard.isReserved("8.8.8.8");        // → false
 */
function isReserved(ip)      { return classify(ip) === "reserved"; }

/**
 * @primitive b.ssrfGuard.checkUrlTextual
 * @signature b.ssrfGuard.checkUrlTextual(url, opts?)
 * @since     0.11.1
 * @status    stable
 * @related   b.ssrfGuard.checkUrl
 *
 * Text-only SSRF check for paths where the DNS lookup is
 * intentionally deferred to a downstream resolver (e.g. an outbound
 * HTTP proxy resolving hostnames in its own network context, or a
 * pinned-IP transport that already knows the destination address).
 * The hostname is checked verbatim against the cloud-metadata IP list
 * — those addresses (`169.254.169.254`, `169.254.170.2`,
 * `fd00:ec2::254`) are NEVER overridable, even when
 * `allowInternal: true` and a proxy is configured. Operators short-
 * circuiting the DNS-resolution portion of `checkUrl` MUST still call
 * this primitive so the unconditional metadata-IP block applies at
 * the textual layer.
 *
 * Returns `{ ips: null, host }` on accept. Throws `SsrfError` with
 * `code: "ssrf-guard/blocked-cloud-metadata"` when the hostname is
 * an IP literal matching a known cloud-metadata IP.
 *
 * @opts
 *   errorClass?: typeof FrameworkError,    // operator-supplied error class for typed refusal
 *
 * @example
 *   b.ssrfGuard.checkUrlTextual("http://intranet-app/api");
 *   // → { ips: null, host: "intranet-app" }
 *
 *   try { b.ssrfGuard.checkUrlTextual("http://169.254.169.254/x"); }
 *   catch (e) { e.code; }
 *   // → "ssrf-guard/blocked-cloud-metadata"
 */
function checkUrlTextual(url, opts) {
  opts = opts || {};
  var ErrorClass = opts.errorClass || SsrfError;
  var parsed = url instanceof URL ? url : safeUrl.parse(String(url), {
    allowedProtocols: safeUrl.ALLOW_HTTP_ALL,
    errorClass: ErrorClass,
  });
  if (!parsed.hostname) {
    throw new ErrorClass("URL '" + parsed.toString() + "' has no hostname",
      "ssrf-guard/no-hostname", { url: parsed.toString() });
  }
  var host = parsed.hostname.replace(/^\[|\]$/g, "");
  // If the textual hostname IS an IP literal AND matches a cloud-
  // metadata IP, refuse — even with `allowInternal: true` and a proxy.
  // Metadata IPs leak instance credentials (AWS IMDS, GCP, Azure) and
  // are not a configuration knob. Matched on canonical bytes so a
  // non-canonical IPv6 spelling (compressed / expanded / mixed-case)
  // can't slip the textual gate the way it slipped classify().
  var hostFamily = net.isIP(host);
  if (hostFamily !== 0 && _isCloudMetadataAddr(host, hostFamily)) {
    throw new ErrorClass(
      "URL '" + parsed.toString() + "' resolves to cloud-metadata IP " + host +
      " — refused unconditionally (not overridable via allowInternal + proxy)",
      "ssrf-guard/blocked-cloud-metadata",
      { url: parsed.toString(), ip: host, category: "cloud-metadata" });
  }
  return { ips: null, host: host };
}

module.exports = {
  classify:         classify,
  canonicalizeHost: canonicalizeHost,
  cidrContains:     cidrContains,
  checkUrl:         checkUrl,
  checkUrlTextual:  checkUrlTextual,
  createAllowlist:  createAllowlist,
  isPrivate:        isPrivate,
  isLoopback:       isLoopback,
  isLinkLocal:      isLinkLocal,
  isCloudMetadata:  isCloudMetadata,
  isReserved:       isReserved,
  SsrfError:        SsrfError,
};
