"use strict";
/**
 * ssrf-guard — outbound URL gate against private / loopback / link-local /
 * cloud-metadata / reserved IP ranges.
 *
 * Wired as default-on in b.httpClient.request. Operators with internal
 * mesh calls opt out per call:
 *
 *   b.httpClient.request({ url: "http://internal.svc", allowInternal: true });
 *   b.httpClient.request({ url: "http://10.0.5.1",     allowInternal: ["10.0.0.0/8"] });
 *
 * Standalone use:
 *
 *   var ssrf = b.ssrfGuard;
 *   await ssrf.checkUrl("https://example.com");          // throws SsrfError on hit
 *   ssrf.classify("169.254.169.254");                    // → "cloud-metadata"
 *   ssrf.cidrContains("10.0.0.0/8", "10.1.2.3");        // → true
 *
 * What's blocked by default:
 *   - IPv4 private  (RFC 1918): 10/8, 172.16/12, 192.168/16
 *   - IPv4 loopback:            127/8
 *   - IPv4 link-local:          169.254/16
 *   - IPv4 reserved/broadcast:  0/8, 100.64/10 (CGNAT), 224/4 (multicast),
 *                               240/4, 255.255.255.255
 *   - IPv4 documentation/test:  192.0.2/24, 198.51.100/24, 203.0.113/24, 198.18/15
 *   - IPv6 loopback:            ::1
 *   - IPv6 ULA (private):       fc00::/7
 *   - IPv6 link-local:          fe80::/10
 *   - Cloud metadata IPs:       169.254.169.254 (AWS/GCP/Azure),
 *                               169.254.170.2 (AWS ECS task role),
 *                               fd00:ec2::254
 *
 * Hostnames are resolved via dns.lookup before classification, so a
 * malicious hostname pointing at a private IP fails the guard.
 *
 * The validated IPs are returned in the result and `b.httpClient` pins
 * the actual TCP connect to those exact addresses (via a custom
 * `lookup` callback passed to https / http2 connect). A hostile DNS
 * server cannot rebind between guard-check and connect to redirect
 * traffic at a private / metadata address.
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

// ---- Cloud metadata addresses (string-equality, exact match) ----
var CLOUD_METADATA_IPS = [
  "169.254.169.254",       // AWS, GCP, Azure, OpenStack, DO
  "169.254.170.2",         // AWS ECS task role
  "fd00:ec2::254",         // AWS IMDS over IPv6
];

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

function classify(ip) {
  if (typeof ip !== "string") return null;
  var family = net.isIP(ip);
  if (family === 0) return null;

  if (CLOUD_METADATA_IPS.indexOf(ip) !== -1) return "cloud-metadata";

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

function _bufEqual(a, b) {
  // Compares Buffer-like byte arrays for equality. The buffers here
  // are IP addresses, not secrets, so the comparison doesn't need
  // constant-time semantics — Buffer.compare uses native memcmp.
  return Buffer.compare(a, b) === 0;
}

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

// b.network.allowlist — contextual per-call egress allowlist composing
// on ssrfGuard. Operators describe an allowed CIDR set + denylist;
// the resulting `assert(url)` either resolves to the validated IP set
// or throws SsrfError. Distinct from `ssrfGuard.checkUrl` (which uses
// the framework's hard-coded private/cloud-metadata ban list) — this
// is for cases where the operator's deployment has SPECIFIC outbound
// targets and everything else should be refused.
//
//   var egress = b.network.allowlist.create({
//     allow: ["api.partner.example.com", "192.0.2.0/24"],
//     deny:  ["api.partner.example.com/admin"],
//   });
//   await egress.assert("https://api.partner.example.com/v1/x");
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
    for (var i = 0; i < list.length; i++) {
      var entry = list[i];
      if (entry === hostOrIp) return true;
      if (entry.indexOf("/") !== -1) {
        try { if (cidrContains(entry, hostOrIp)) return true; } catch (_e) { /* ignore */ }
      }
    }
    return false;
  }
  async function assertUrl(url) {
    var parsed;
    try { parsed = new URL(url); }                                                 // allow:raw-new-url — local URL parse for hostname extraction
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

module.exports = {
  classify:        classify,
  cidrContains:    cidrContains,
  checkUrl:        checkUrl,
  createAllowlist: createAllowlist,
  isPrivate:       function (ip) { return classify(ip) === "private"; },
  isLoopback:      function (ip) { return classify(ip) === "loopback"; },
  isLinkLocal:     function (ip) { return classify(ip) === "link-local"; },
  isCloudMetadata: function (ip) { return classify(ip) === "cloud-metadata"; },
  isReserved:      function (ip) { return classify(ip) === "reserved"; },
  SsrfError:       SsrfError,
};
