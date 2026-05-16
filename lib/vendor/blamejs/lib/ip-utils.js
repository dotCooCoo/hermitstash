"use strict";
/**
 * lib/ip-utils.js — internal IP-address helpers shared across
 * `b.mail.auth` (SPF / DMARC IP-in-CIDR), `b.mail.rbl` (RFC 5782
 * reverse-DNS), `b.mail.greylist` (RFC 6647 CIDR fingerprint).
 *
 * Not exposed on the operator-facing `b` surface; internal compose
 * point so the three consumers don't drift on IPv6 parsing.
 *
 * RFC 4291 §2.2 IPv6 text form: 8 groups of 1-4 hex characters
 * separated by `:`; one `::` allowed to compress a contiguous run
 * of zero groups; IPv4-mapped form `::ffff:1.2.3.4` per RFC 5952 §5
 * + dual-stack `::a.b.c.d` per RFC 4291 §2.5.5.2.
 */

/**
 * Expand an IPv6 address to its full 32-hex-character form. Returns
 * `null` on parse failure (invalid hex group, group count != 8,
 * multiple `::`, group > 0xffff).
 *
 *   expandIpv6Hex("2001:db8::1")       → "20010db8000000000000000000000001"
 *   expandIpv6Hex("::ffff:192.0.2.1")  → "00000000000000000000ffffc0000201"
 *   expandIpv6Hex("::1")               → "00000000000000000000000000000001"
 *   expandIpv6Hex("bad")               → null
 */
function expandIpv6Hex(ip) {
  if (typeof ip !== "string") return null;
  // RFC 4291 §2.5.5.2 IPv4-mapped / dual-stack: accept ".d.d.d.d" tail.
  var dual = ip.match(/^(.*?):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);                                    // allow:regex-no-length-cap — dotted-quad has fixed shape; LHS bounded by IPv6 group cap below
  if (dual) {
    var v4 = dual[2].split(".").map(Number);
    if (v4.some(function (o) { return !(o >= 0 && o <= 255); })) return null;                            // allow:raw-byte-literal — IPv4 octet range
    var hi = (v4[0] << 8) | v4[1];                                                                       // allow:raw-byte-literal — 16-bit group pack
    var lo = (v4[2] << 8) | v4[3];                                                                       // allow:raw-byte-literal — 16-bit group pack
    ip = dual[1] + ":" + hi.toString(16) + ":" + lo.toString(16);
  }
  var dblColon = ip.split("::");
  if (dblColon.length > 2) return null;
  var leftGroups  = dblColon[0] === "" ? [] : dblColon[0].split(":");
  var rightGroups = dblColon.length === 2 ? (dblColon[1] === "" ? [] : dblColon[1].split(":")) : [];
  if (dblColon.length === 1 && leftGroups.length !== 8) return null;                                      // allow:raw-byte-literal — RFC 4291 IPv6 group count
  var fillCount = 8 - leftGroups.length - rightGroups.length;                                             // allow:raw-byte-literal — RFC 4291 IPv6 group count
  if (fillCount < 0) return null;
  var fill = [];
  for (var f = 0; f < fillCount; f += 1) fill.push("0");
  var groups = leftGroups.concat(fill).concat(rightGroups);
  if (groups.length !== 8) return null;                                                                   // allow:raw-byte-literal — RFC 4291 IPv6 group count
  var hex = "";
  for (var i = 0; i < 8; i += 1) {                                                                        // allow:raw-byte-literal — RFC 4291 IPv6 group count
    var g = groups[i];
    if (g.length === 0 || g.length > 4) return null;                                                      // allow:raw-byte-literal — RFC 4291 IPv6 hex-group max length
    for (var hc = 0; hc < g.length; hc += 1) {
      var cp = g.charCodeAt(hc);
      var isDigit    = cp >= 0x30 && cp <= 0x39;                                                          // allow:raw-byte-literal — ASCII '0'..'9'
      var isLowerHex = cp >= 0x61 && cp <= 0x66;                                                          // allow:raw-byte-literal — ASCII 'a'..'f'
      var isUpperHex = cp >= 0x41 && cp <= 0x46;                                                          // allow:raw-byte-literal — ASCII 'A'..'F'
      if (!isDigit && !isLowerHex && !isUpperHex) return null;
    }
    hex += g.toLowerCase().padStart(4, "0");                                                              // allow:raw-byte-literal — 4 hex chars per IPv6 group
  }
  return hex;
}

/**
 * Expand IPv6 to an 8-element array of 16-bit unsigned integers.
 * Used by `b.mail.auth` SPF / DMARC IP-in-CIDR evaluation which
 * does bitwise group-level math.
 *
 *   expandIpv6Groups("::1")   → [0,0,0,0,0,0,0,1]
 *   expandIpv6Groups("bad")   → null
 */
function expandIpv6Groups(ip) {
  var hex = expandIpv6Hex(ip);
  if (hex === null) return null;
  var groups = new Array(8);                                                                              // allow:raw-byte-literal — RFC 4291 IPv6 group count
  for (var i = 0; i < 8; i += 1) {                                                                        // allow:raw-byte-literal — RFC 4291 IPv6 group count
    groups[i] = parseInt(hex.slice(i * 4, i * 4 + 4), 16);                                                // allow:raw-byte-literal — 4 hex chars per IPv6 group
  }
  return groups;
}

// Loose IPv4 textual-form check — for primitives that need to
// classify a string as "looks like dotted-quad IPv4" but don't need
// the strict per-octet bound check (callers that DO need octet
// bounds use the strict form in `mail-rbl.js` etc.). Shared so
// `lib/mail.js`, `lib/mail-helo.js`, and `lib/redis-client.js`
// don't drift on the same shape.
//
//   isIPv4Shape("1.2.3.4")     → true
//   isIPv4Shape("999.0.0.0")   → true (shape only; octets unbounded)
//   isIPv4Shape("not-an-ip")   → false
//   isIPv4Shape("1.2.3")       → false
var IPV4_SHAPE_RE = /^\d+\.\d+\.\d+\.\d+$/;                                                              // allow:regex-no-length-cap — anchored + literal-dot shape; caller bounds length
function isIPv4Shape(s) {
  return typeof s === "string" && IPV4_SHAPE_RE.test(s);
}

module.exports = {
  expandIpv6Hex:    expandIpv6Hex,
  expandIpv6Groups: expandIpv6Groups,
  isIPv4Shape:      isIPv4Shape,
};
