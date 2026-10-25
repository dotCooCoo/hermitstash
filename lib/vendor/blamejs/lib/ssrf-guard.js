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
var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");

var { FrameworkError } = require("./framework-error");
var frameworkError = require("./framework-error");

var networkDns = lazyRequire(function () { return require("./network-dns"); });

var IPV4_BITS     = C.BYTES.bytes(32);
var IPV6_BITS     = C.BYTES.bytes(128);
var IPV4_MAPPED_PREFIX_BITS = C.BYTES.bytes(96);
var BITS_PER_BYTE = C.BYTES.bytes(8);
var IPV6_BYTES    = C.BYTES.bytes(16);
var IPV6_GROUPS   = C.BYTES.bytes(8);
var HEX_RADIX     = C.BYTES.bytes(16);

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

frameworkError.messageFirstFactory(SsrfError);

function _refuse(ErrorClass, code, message, ctx) {
  if (ErrorClass && typeof ErrorClass.factory === "function") {
    return ErrorClass.factory(code, message, ctx);
  }
  return new ErrorClass(message, code, ctx);
}

function _cidrHolds(addr) {
  return function (cidr) { return cidrContains(cidr, addr); };
}

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
  [_ipv4ToInt("0.0.0.0"),         C.BYTES.bytes(8)],
  [_ipv4ToInt("100.64.0.0"),     C.BYTES.bytes(10)],
  [_ipv4ToInt("192.0.0.0"),      C.BYTES.bytes(24)],
  [_ipv4ToInt("192.0.2.0"),      C.BYTES.bytes(24)],
  [_ipv4ToInt("198.18.0.0"),     C.BYTES.bytes(15)],
  [_ipv4ToInt("198.51.100.0"),   C.BYTES.bytes(24)],
  [_ipv4ToInt("203.0.113.0"),    C.BYTES.bytes(24)],
  [_ipv4ToInt("224.0.0.0"),       C.BYTES.bytes(4)],
  [_ipv4ToInt("240.0.0.0"),       C.BYTES.bytes(4)],
];

var IPV6_LOOPBACK_BYTES   = _ipv6ToBytes("::1");
var IPV6_UNSPECIFIED_BYTES = _ipv6ToBytes("::");
var IPV6_PRIVATE_PREFIX   = _ipv6ToBytes("fc00::");
var IPV6_LINK_LOCAL_PREFIX = _ipv6ToBytes("fe80::");
var IPV6_DOC_PREFIX       = _ipv6ToBytes("2001:db8::");
var IPV6_V4_MAPPED_PREFIX = _ipv6ToBytes("::ffff:0:0");
var IPV6_MULTICAST_PREFIX = _ipv6ToBytes("ff00::");
var IPV6_NAT64_PREFIX     = _ipv6ToBytes("64:ff9b::");
var IPV6_6TO4_PREFIX      = _ipv6ToBytes("2002::");
var IPV6_DISCARD_PREFIX   = _ipv6ToBytes("100::");

var CLOUD_METADATA_IPS = [
  "169.254.169.254",
  "169.254.170.2",
  "fd00:ec2::254",
];
var CLOUD_METADATA_BYTES = CLOUD_METADATA_IPS.map(function (ip) {
  var fam = net.isIP(ip);
  return fam === 4 ? _ipv4ToBytes(ip) : _ipv6ToBytes(ip);
});

function _ipv4ToInt(ip) {
  var parts = ip.split(".");
  if (parts.length !== 4) return NaN;
  var nums = [0, 0, 0, 0];
  for (var i = 0; i < 4; i += 1) {
    var s = parts[i];
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
  var n = _ipv4ToInt(ip);
  if (!Number.isFinite(n)) return null;
  return Buffer.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function _ipv6ToBytes(ip) {
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
  var zone = ip.indexOf("%");
  var lower = (zone === -1 ? ip : ip.slice(0, zone)).toLowerCase();
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
  if (bestLen < 2) bestStart = -1;
  var parts = [];
  for (var k = 0; k < IPV6_GROUPS; k++) {
    if (bestStart !== -1 && k === bestStart) {
      parts.push("");
      k += bestLen - 1;
      if (k === IPV6_GROUPS - 1) parts.push("");
      continue;
    }
    parts.push(groups[k].toString(HEX_RADIX));
  }
  var out = parts.join(":");
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
 * stays dotted-quad; IPv6 in any zero-compression or mixed-case
 * spelling becomes the RFC 5952 lower-hex compressed form; and an
 * IPv4-mapped spelling (`[0:0:0:0:0:ffff:7f00:1]`, `::FFFF:7F00:1`)
 * folds to the dotted quad it names, so it compares equal to the same
 * address written as IPv4. The IP bytes are
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
 * An IPv6 zone id (`fe80::1%eth0`, `::ffff:10.0.0.1%eth0`) is not part of
 * the returned string, and the address is read from the text before the `%`.
 *
 * @example
 *   var b = require("blamejs");
 *   b.ssrfGuard.canonicalizeHost("[0:0:0:0:0:0:0:1]");    // → "::1"
 *   b.ssrfGuard.canonicalizeHost("::FFFF:7F00:1");        // → "127.0.0.1"
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
    if (_ipv6PrefixMatch(IPV6_V4_MAPPED_PREFIX, C.BYTES.bytes(96), v6bytes)) {
      return v6bytes[12] + "." + v6bytes[13] + "." + v6bytes[14] + "." + v6bytes[15];
    }
    return _ipv6BytesToString(v6bytes);
  }
  var name = codepointClass.trimTrailingChars(bare.toLowerCase(), ".");
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

  if (_isCloudMetadataAddr(ip, family)) return "cloud-metadata";

  if (family === 4) {
    var ipInt = _ipv4ToInt(ip);
    if (_ipv4PrefixMatch(IPV4_LOOPBACK,    ipInt)) return "loopback";
    if (_ipv4PrefixMatch(IPV4_LINK_LOCAL,  ipInt)) return "link-local";
    if (_ipv4PrefixMatch(IPV4_PRIVATE,     ipInt)) return "private";
    if (_ipv4PrefixMatch(IPV4_RESERVED,    ipInt)) return "reserved";
    return null;
  }

  var bytes = _ipv6ToBytes(ip);
  if (_bufEqual(bytes, IPV6_LOOPBACK_BYTES))      return "loopback";
  if (_bufEqual(bytes, IPV6_UNSPECIFIED_BYTES))   return "reserved";
  if (_ipv6PrefixMatch(IPV6_LINK_LOCAL_PREFIX, C.BYTES.bytes(10), bytes))  return "link-local";
  if (_ipv6PrefixMatch(IPV6_PRIVATE_PREFIX,     7, bytes))  return "private";
  if (_ipv6PrefixMatch(IPV6_DOC_PREFIX,        C.BYTES.bytes(32), bytes))  return "reserved";
  if (_ipv6PrefixMatch(IPV6_MULTICAST_PREFIX,   C.BYTES.bytes(8), bytes))  return "reserved";
  if (_ipv6PrefixMatch(IPV6_DISCARD_PREFIX,    C.BYTES.bytes(64), bytes))  return "reserved";
  var wrappedV4 = _wrappedIpv4(bytes);
  if (wrappedV4 !== null) return classify(wrappedV4) || "reserved";
  if (_ipv6PrefixMatch(IPV6_V4_MAPPED_PREFIX, C.BYTES.bytes(96), bytes)) {
    var mappedV4 = bytes[12] + "." + bytes[13] + "." + bytes[14] + "." + bytes[15];
    return classify(mappedV4);
  }
  return null;
}

function _wrappedIpv4(bytes) {
  if (_ipv6PrefixMatch(IPV6_6TO4_PREFIX, C.BYTES.bytes(16), bytes)) {
    return bytes[2] + "." + bytes[3] + "." + bytes[4] + "." + bytes[5];
  }
  if (_ipv6PrefixMatch(IPV6_NAT64_PREFIX, C.BYTES.bytes(96), bytes)) {
    return bytes[12] + "." + bytes[13] + "." + bytes[14] + "." + bytes[15];
  }
  return null;
}

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
 * An `allowInternal` CIDR is compared with the canonical address, so
 * `10.0.0.0/8` waives `::ffff:10.0.0.1` and `::ffff:10.0.0.0/104` waives
 * `10.0.0.1`.
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
    throw _refuse(ErrorClass, "ssrf-guard/no-hostname",
      "URL '" + parsed.toString() + "' has no hostname",
      { url: parsed.toString() });
  }

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

    if (category === "cloud-metadata") {
      throw _refuse(ErrorClass, "ssrf-guard/blocked-cloud-metadata",
        "URL '" + parsed.toString() + "' resolves to " + addr +
        " (cloud-metadata) — blocked unconditionally; allowInternal does NOT override " +
        "this class because metadata IPs leak instance credentials",
        { url: parsed.toString(), ip: addr, category: category }
      );
    }

    if (allowInternal === true) continue;
    if (Array.isArray(allowInternal) &&
        allowInternal.map(_canonicalListEntry).some(_cidrHolds(canonicalizeHost(addr)))) continue;

    throw _refuse(ErrorClass, "ssrf-guard/blocked-" + category,
      "URL '" + parsed.toString() + "' resolves to " + addr +
      " in the " + category + " range — pass allowInternal:true to override",
      { url: parsed.toString(), ip: addr, category: category }
    );
  }
  return { url: parsed, ips: ips };
}

function _canonicalListEntry(entry) {
  if (typeof entry !== "string") return entry;
  var slash = entry.indexOf("/");
  if (slash === -1) return canonicalizeHost(entry);
  var network = entry.slice(0, slash);
  var prefixText = entry.slice(slash + 1);
  var prefix = Number(prefixText);
  if (net.isIP(network) !== 6 || !Number.isInteger(prefix) || String(prefix) !== prefixText) return entry;
  if (prefix < IPV4_MAPPED_PREFIX_BITS || prefix > IPV6_BITS) return entry;
  var bytes = _ipv6ToBytes(network);
  if (!_ipv6PrefixMatch(IPV6_V4_MAPPED_PREFIX, IPV4_MAPPED_PREFIX_BITS, bytes)) return entry;
  return bytes[12] + "." + bytes[13] + "." + bytes[14] + "." + bytes[15] + "/" +
    (prefix - IPV4_MAPPED_PREFIX_BITS);
}

function _listEntryProblem(entry) {
  if (typeof entry !== "string" || entry.length === 0) return "is not a non-empty string";
  var slash = entry.indexOf("/");
  if (slash !== -1) {
    var network = entry.slice(0, slash);
    var prefixText = entry.slice(slash + 1);
    var family = net.isIP(network);
    if (family === 0) return "has a CIDR network that is not an IP address";
    if (!codepointClass.isRunOf(prefixText, codepointClass.ASCII_DIGITS, 1) ||
        (prefixText.length > 1 && prefixText.charAt(0) === "0")) {
      return "has a CIDR prefix that is not a decimal integer";
    }
    if (Number(prefixText) > (family === 4 ? IPV4_BITS : IPV6_BITS)) {
      return "has a CIDR prefix longer than the address";
    }
    return null;
  }
  var bracketed = entry.charAt(0) === "[" && entry.charAt(entry.length - 1) === "]";
  var bare = bracketed ? entry.slice(1, -1) : entry;
  var literalFamily = net.isIP(bare);
  if (literalFamily !== 0) return bracketed && literalFamily !== 6 ? "brackets an IPv4 address" : null;
  var parsedHost;
  try { parsedHost = new URL("http://" + entry + "/").hostname; }                 // allow:raw-new-url-parse-only — the entry is compared with how a URL host parses, never dialed
  catch (_e) { return "is not a host name a URL can carry"; }
  if (canonicalizeHost(parsedHost) !== canonicalizeHost(entry)) {
    return "is read by the URL parser as the host '" + parsedHost + "'";
  }
  return null;
}

function _checkedList(value, field) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new SsrfError("ssrfGuard.createAllowlist: `" + field + "` must be an array of strings",
      "ssrf-guard/bad-entry", {});
  }
  for (var i = 0; i < value.length; i++) {
    var problem = _listEntryProblem(value[i]);
    if (problem !== null) {
      throw new SsrfError("ssrfGuard.createAllowlist: `" + field + "[" + i + "]` (" +
        JSON.stringify(value[i]) + ") " + problem, "ssrf-guard/bad-entry", {});
    }
  }
  return value.map(_canonicalListEntry);
}

function _hostSpellings(canonHost, everySpelling) {
  var forms = [canonHost];
  if (!everySpelling || typeof canonHost !== "string") return forms;
  var family = net.isIP(canonHost);
  var v4 = family === 4 ? canonHost : null;
  if (family === 6) {
    v4 = _wrappedIpv4(_ipv6ToBytes(canonHost));
    if (v4 !== null) forms.push(v4);
  }
  if (v4 !== null) forms.push("::ffff:" + v4);
  return forms;
}

function _listMatches(list, hostOrIp, everySpelling) {
  var forms = _hostSpellings(canonicalizeHost(hostOrIp), everySpelling);
  for (var i = 0; i < list.length; i++) {
    var entry = list[i];
    var isCidr = entry.indexOf("/") !== -1;
    for (var f = 0; f < forms.length; f++) {
      if (isCidr) {
        if (cidrContains(entry, forms[f])) return true;
      } else if (entry === forms[f]) {
        return true;
      }
    }
  }
  return false;
}

function _carriedAddress(ip) {
  var canon = canonicalizeHost(ip);
  if (net.isIP(canon) !== 6) return canon;
  var v4 = _wrappedIpv4(_ipv6ToBytes(canon));
  return v4 !== null ? v4 : canon;
}

function _sameAddress(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (net.isIP(canonicalizeHost(a)) === 0 || net.isIP(canonicalizeHost(b)) === 0) return a === b;
  return _zoneOf(a) === _zoneOf(b) && canonicalizeHost(a) === canonicalizeHost(b);
}

function _zoneOf(ip) {
  var zone = ip.indexOf("%");
  if (zone === -1) return "";
  var end = ip.charAt(ip.length - 1) === "]" ? ip.length - 1 : ip.length;
  return ip.slice(zone + 1, end);
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
 * Throws `ssrf-guard/empty-allowlist` at construction time when `allow` is
 * empty. Throws `ssrf-guard/bad-entry` at construction time when
 * `allow` or `deny` is not an array, or when an entry is not a non-empty
 * string, is a CIDR whose network is not an IP address or whose prefix is
 * not a decimal integer from 0 to 32 (IPv4) or 128 (IPv6), or is a host
 * name the URL parser reads as a different host (`api.example.com:443`,
 * `10.0.0`, `010.0.0.1`, a Unicode name not written as `xn--`).
 *
 * Hosts and entries are compared in their canonical form: an IPv4-mapped
 * host (`[::ffff:10.0.0.1]`) is compared as the IPv4 address, and an
 * IPv4-mapped CIDR with a prefix of 96 or more (`::ffff:10.0.0.0/104`) as
 * the IPv4 CIDR it covers. A `deny` entry also matches an IPv4 host through
 * its `::ffff:` form, and a 6to4 (`2002::/16`) or NAT64 (`64:ff9b::/96`)
 * host through the IPv4 address it carries. An IPv6 `deny` CIDR that
 * contains `::ffff:0:0/96`, such as `::/0` or the reserved `::/8`, therefore
 * denies every IPv4 host. An `allow` entry matches only the canonical form.
 *
 * `deny` entries are checked against the URL host and then against every
 * address `checkUrl` resolves it to, so `deny: ["127.0.0.0/8", "::1/128"]`
 * refuses an allowed host name that resolves to loopback. That refusal is
 * `ssrf-guard/on-denylist` with the address in `err.ip`.
 *
 * @opts
 *   allow: string[],   // required; entries are exact hostnames OR CIDR blocks
 *   deny:  string[],   // optional; checked AFTER allow — denylist wins
 *
 * @example
 *   // requires: outbound DNS — assert() resolves the host before allowing it
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
 *     allow: ["10.0.0.0/8", "169.254.0.0/16"],
 *     deny:  ["169.254.169.254", "169.254.170.2"],
 *   });
 *   try {
 *     await egress.assert("http://169.254.169.254/latest/");
 *   } catch (e) {
 *     e.code;   // → "ssrf-guard/on-denylist"
 *   }
 */
function createAllowlist(opts) {
  opts = opts || {};
  validateOpts(opts, ["allow", "deny"], "ssrfGuard.createAllowlist");
  var allowList = _checkedList(opts.allow, "allow");
  var denyList  = _checkedList(opts.deny, "deny");
  if (allowList.length === 0) {
    throw new SsrfError(
      "network.allowlist.create requires at least one entry in `allow`",
      "ssrf-guard/empty-allowlist", {});
  }
  async function assertUrl(url) {
    var parsed;
    try { parsed = new URL(url); }                                                 // allow:raw-new-url-parse-only — local URL parse for hostname extraction
    catch (_e) {
      throw new SsrfError("invalid URL", "ssrf-guard/bad-url", { url: url });
    }
    var host = parsed.hostname;   // allow:url-hostname-not-dialed (compared with the lists and named in the refusal)
    if (!_listMatches(allowList, host, false)) {
      throw new SsrfError(
        "URL host '" + host + "' not on the operator allowlist",
        "ssrf-guard/not-on-allowlist", { url: url, host: host });
    }
    if (_listMatches(denyList, host, true)) {
      throw new SsrfError(
        "URL host '" + host + "' on the operator denylist",
        "ssrf-guard/on-denylist", { url: url, host: host });
    }
    var result = await checkUrl(parsed.toString(), { allowInternal: true });
    for (var r = 0; r < result.ips.length; r++) {
      var address = result.ips[r] && result.ips[r].address;
      if (typeof address === "string" && _listMatches(denyList, address, true)) {
        throw new SsrfError(
          "URL host '" + host + "' resolves to " + address + ", which is on the operator denylist",
          "ssrf-guard/on-denylist", { url: url, host: host, ip: address });
      }
    }
    return result;
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
 * @primitive b.ssrfGuard.isLoopbackHost
 * @signature b.ssrfGuard.isLoopbackHost(host)
 * @since     0.17.13
 * @status    stable
 * @related   b.ssrfGuard.isExactLoopbackName, b.ssrfGuard.isLoopback, b.ssrfGuard.canonicalizeHost
 *
 * Hostname-aware loopback test. Unlike `isLoopback` (IP literals only) this
 * canonicalizes `host` (strips `[]` brackets + trailing dots, folds an
 * IPv4-mapped IPv6, lowercases) and returns `true` for a loopback IP literal
 * OR the RFC 6761 §6.3 reserved names `localhost` and any `*.localhost`. Pure
 * name-shape — never resolves DNS.
 *
 * @example
 *   b.ssrfGuard.isLoopbackHost("localhost");     // → true
 *   b.ssrfGuard.isLoopbackHost("[::1]");          // → true
 *   b.ssrfGuard.isLoopbackHost("app.localhost");  // → true
 *   b.ssrfGuard.isLoopbackHost("example.com");    // → false
 */
function isLoopbackHost(host) {
  if (typeof host !== "string" || host.length === 0) return false;
  var canon = canonicalizeHost(host);
  if (net.isIP(canon)) return classify(canon) === "loopback";
  return canon === "localhost" || /\.localhost$/.test(canon);
}

/**
 * @primitive b.ssrfGuard.isExactLoopbackName
 * @signature b.ssrfGuard.isExactLoopbackName(host)
 * @since     0.17.13
 * @status    stable
 * @related   b.ssrfGuard.isLoopbackHost
 *
 * Like `isLoopbackHost` but WITHOUT the `*.localhost` subdomain reservation —
 * accepts only the exact `localhost` name or a loopback IP literal. For the
 * OAuth/OIDC cleartext-redirect loopback exception (RFC 9700 §4.1.1), which
 * must not widen to a `*.localhost` name an attacker could register in a resolver.
 *
 * @example
 *   b.ssrfGuard.isExactLoopbackName("localhost");     // → true
 *   b.ssrfGuard.isExactLoopbackName("127.0.0.1");     // → true
 *   b.ssrfGuard.isExactLoopbackName("app.localhost"); // → false
 */
function isExactLoopbackName(host) {
  if (typeof host !== "string" || host.length === 0) return false;
  var canon = canonicalizeHost(host);
  if (net.isIP(canon)) return classify(canon) === "loopback";
  return canon === "localhost";
}

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
 * an IP literal matching a known cloud-metadata IP, and
 * `code: "ssrf-guard/no-hostname"` for a URL that parses but carries no
 * hostname, which leaves nothing to screen.
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
    throw _refuse(ErrorClass, "ssrf-guard/no-hostname",
      "URL '" + parsed.toString() + "' has no hostname",
      { url: parsed.toString() });
  }
  var host = parsed.hostname.replace(/^\[|\]$/g, "");
  var hostFamily = net.isIP(host);
  if (hostFamily !== 0 && _isCloudMetadataAddr(host, hostFamily)) {
    throw _refuse(ErrorClass, "ssrf-guard/blocked-cloud-metadata",
      "URL '" + parsed.toString() + "' resolves to cloud-metadata IP " + host +
      " — refused unconditionally (not overridable via allowInternal + proxy)",
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
  isLoopbackHost:   isLoopbackHost,
  isExactLoopbackName: isExactLoopbackName,
  isLinkLocal:      isLinkLocal,
  isCloudMetadata:  isCloudMetadata,
  isReserved:       isReserved,
  SsrfError:        SsrfError,
  _canonicalListEntry: _canonicalListEntry,
  _listEntryProblem:   _listEntryProblem,
  _listMatches:        _listMatches,
  _sameAddress:        _sameAddress,
  _carriedAddress:     _carriedAddress,
};
