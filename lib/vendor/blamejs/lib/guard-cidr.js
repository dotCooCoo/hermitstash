"use strict";
/**
 * @module b.guardCidr
 * @nav    Guards
 * @title  Guard Cidr
 *
 * @intro
 *   CIDR identifier-safety primitive (KIND="identifier"). Validates
 *   user-supplied CIDR notation strings (IPv4 + IPv6) destined for
 *   network allowlists, ACLs, security-group rules, and tenant-
 *   boundary configuration. Consumes `ctx.identifier` (or
 *   `ctx.cidr`).
 *
 *   Shape and prefix-bound enforcement: every CIDR splits into
 *   `address/mask`. IPv4 must be strict dotted-decimal (no leading
 *   zeros — octal-form `0177.0.0.1` is refused at the parser; that
 *   class is owned by `b.guardDomain`). IPv4 mask is `[0-32]`; IPv6
 *   mask is `[0-128]`; out-of-range and non-numeric masks refuse.
 *   IPv6 supports `::` zero-group compression with the standard
 *   "at most one `::`" rule.
 *
 *   Reserved-block awareness: IPv4 ranges per RFC 1918 (private 10/8,
 *   172.16/12, 192.168/16), loopback 127/8, link-local 169.254/16,
 *   multicast 224/4, reserved class-E 240/4, documentation 192.0.2/24,
 *   198.51.100/24, 203.0.113/24, benchmarking 198.18/15, and CGNAT
 *   100.64/10. IPv6 ranges: loopback `::1`, unspecified `::/128`,
 *   ULA `fc00::/7`, link-local `fe80::/10`, multicast `ff00::/8`,
 *   IPv4-mapped `::ffff:0:0/96`, documentation `2001:db8::/32`,
 *   teredo `2001::/32`, deprecated 6to4 `2002::/16`. IPv4-mapped IPv6
 *   trips dual-stack allowlist confusion (CVE-2021-22931 class) and
 *   refuses under strict.
 *
 *   Network-address alignment: `10.0.0.1/24` has host bits set under
 *   a /24 mask when the canonical network is `10.0.0.0/24`. Common
 *   typo class — refused under strict, audited under balanced.
 *   BIDI / control / null-byte / zero-width are universal-refuse at
 *   every profile (codepoint-class catalog).
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`.
 *
 * @card
 *   CIDR identifier-safety primitive (KIND="identifier").
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var safeBuffer = require("./safe-buffer");
var { GuardCidrError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardCidrError.factory;

var IPV4_OCTET_MAX = 255;                                                        // allow:raw-byte-literal — RFC 791 octet ceiling
var IPV4_MASK_MAX  = 32;                                                         // allow:raw-byte-literal — IPv4 prefix ceiling
var IPV6_MASK_MAX  = 128;                                                        // allow:raw-byte-literal — IPv6 prefix ceiling
var IPV4_OCTETS    = 4;                                                          // allow:raw-byte-literal — IPv4 dotted-quad count
var IPV6_GROUPS    = 8;                                                          // allow:raw-byte-literal — IPv6 16-bit group count

// ---- IPv4 reserved ranges (CIDR network, /mask) ----
//
// Each entry: [networkAsUint32, maskBits, label].
function _ipv4ToUint32(o) { return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]; }   // allow:raw-byte-literal — IPv4 octet shifts
var IPV4_RESERVED = Object.freeze([
  { net: _ipv4ToUint32([10, 0, 0, 0]),       prefix: 8,  label: "rfc1918-private-10" },          // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([172, 16, 0, 0]),     prefix: 12, label: "rfc1918-private-172.16" },      // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([192, 168, 0, 0]),    prefix: 16, label: "rfc1918-private-192.168" },     // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([127, 0, 0, 0]),      prefix: 8,  label: "loopback" },                    // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([169, 254, 0, 0]),    prefix: 16, label: "link-local" },                  // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([224, 0, 0, 0]),      prefix: 4,  label: "multicast" },                   // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([240, 0, 0, 0]),      prefix: 4,  label: "reserved-class-e" },            // allow:raw-byte-literal — IPv4 octets allow:raw-time-literal — 240 is an IPv4 octet not seconds
  { net: _ipv4ToUint32([192, 0, 2, 0]),      prefix: 24, label: "documentation-test-net-1" },    // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([198, 51, 100, 0]),   prefix: 24, label: "documentation-test-net-2" },    // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([203, 0, 113, 0]),    prefix: 24, label: "documentation-test-net-3" },    // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([198, 18, 0, 0]),     prefix: 15, label: "benchmarking" },                // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([100, 64, 0, 0]),     prefix: 10, label: "cgnat" },                       // allow:raw-byte-literal — IPv4 octets
  { net: _ipv4ToUint32([0, 0, 0, 0]),        prefix: 8,  label: "this-network" },                // allow:raw-byte-literal — IPv4 octets
]);

// ---- IPv6 reserved prefixes ----
//
// Stored as a normalized "first 32 hex chars (no colons)" prefix-byte
// string. Match by string-prefix on the first ceil(prefix/4) hex chars.
var IPV6_RESERVED = Object.freeze([
  { prefix: 128, hexPrefix: "00000000000000000000000000000001", label: "loopback" },             // allow:raw-byte-literal — IPv6 hex form
  { prefix: 128, hexPrefix: "00000000000000000000000000000000", label: "unspecified" },          // allow:raw-byte-literal — IPv6 hex form
  { prefix: 7,   hexPrefix: "fc",                                 label: "ula" },                // allow:raw-byte-literal — IPv6 hex form
  { prefix: 10,  hexPrefix: "fe8",                                label: "link-local" },         // allow:raw-byte-literal — IPv6 hex form
  { prefix: 8,   hexPrefix: "ff",                                 label: "multicast" },          // allow:raw-byte-literal — IPv6 hex form
  { prefix: 96,  hexPrefix: "00000000000000000000ffff",           label: "ipv4-mapped" },        // allow:raw-byte-literal — IPv6 hex form
  { prefix: 32,  hexPrefix: "20010db8",                           label: "documentation" },      // allow:raw-byte-literal — IPv6 hex form
  { prefix: 32,  hexPrefix: "20010000",                           label: "teredo" },             // allow:raw-byte-literal — IPv6 hex form
  { prefix: 16,  hexPrefix: "2002",                               label: "deprecated-6to4" },    // allow:raw-byte-literal — IPv6 hex form
]);

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    networkAlignmentPolicy:    "reject",
    reservedRangesPolicy:      "reject",
    ipv4MappedIpv6Policy:      "reject",
    requireMaskPolicy:         "reject-bare-ip",                                 // bare ip/no mask refused
    family:                    "either",                                         // "either" | "ipv4-only" | "ipv6-only"
    maxBytes:                  C.BYTES.bytes(64),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    networkAlignmentPolicy:    "audit",
    reservedRangesPolicy:      "audit",
    ipv4MappedIpv6Policy:      "audit",
    requireMaskPolicy:         "audit-bare-ip",                                  // bare ip → audit; treat as host-only prefix
    family:                    "either",
    maxBytes:                  C.BYTES.bytes(64),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:               "reject",                                          // BIDI refused at every profile
    controlPolicy:             "reject",                                          // controls refused at every profile
    nullBytePolicy:            "reject",                                          // null refused at every profile
    zeroWidthPolicy:           "reject",                                          // zero-width refused at every profile
    networkAlignmentPolicy:    "audit",
    reservedRangesPolicy:      "allow",
    ipv4MappedIpv6Policy:      "allow",
    requireMaskPolicy:         "allow-bare-ip",
    family:                    "either",
    maxBytes:                  C.BYTES.bytes(64),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(64),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardCidrError,
    errCodePrefix:      "cidr",
  });
}

// ---- Parsers ----

function _parseIpv4(s) {
  // Strict dotted-decimal — every octet is 0-255 with no leading zeros
  // (octal/hex/long forms refused — see guard-domain for that class).
  var parts = s.split(".");
  if (parts.length !== IPV4_OCTETS) return null;
  var octets = [];
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i];
    if (!/^[0-9]+$/.test(p)) return null;
    if (p.length > 1 && p.charAt(0) === "0") return null;                        // leading-zero octal/forms refused
    var n = parseInt(p, 10);                                                     // allow:raw-byte-literal — base-10 radix
    if (n > IPV4_OCTET_MAX) return null;
    octets.push(n);
  }
  return octets;
}

function _parseIpv6(s) {
  // IPv6 — supports `::` zero-group compression. Returns 8 hex groups
  // expanded to 4-char-each lowercase string, or null on malformation.
  if (s.indexOf(":::") !== -1) return null;
  var doubleColons = s.split("::");
  if (doubleColons.length > 2) return null;

  function _parseGroups(seg) {
    if (seg === "") return [];
    var parts = seg.split(":");
    var out = [];
    for (var i = 0; i < parts.length; i += 1) {
      var p = parts[i];
      if (!safeBuffer.IPV6_HEXTET_RE.test(p)) return null;
      out.push(p.toLowerCase());
    }
    return out;
  }

  var groups;
  if (doubleColons.length === 1) {
    // No `::` — must be exactly 8 groups.
    groups = _parseGroups(doubleColons[0]);
    if (!groups || groups.length !== IPV6_GROUPS) return null;
  } else {
    var left  = _parseGroups(doubleColons[0]);
    var right = _parseGroups(doubleColons[1]);
    if (left === null || right === null) return null;
    var pad = IPV6_GROUPS - left.length - right.length;
    if (pad < 0) return null;
    var zeros = [];
    for (var z = 0; z < pad; z += 1) zeros.push("0000");                         // allow:raw-byte-literal — IPv6 zero group
    groups = left.concat(zeros).concat(right);
    if (groups.length !== IPV6_GROUPS) return null;
  }
  // Pad each group to 4 chars.
  for (var g = 0; g < groups.length; g += 1) {
    while (groups[g].length < 4) groups[g] = "0" + groups[g];                    // allow:raw-byte-literal — IPv6 group width
  }
  return groups;
}

function _hostBitsSetIpv4(octets, prefix) {
  if (prefix === IPV4_MASK_MAX) return false;
  var addr = _ipv4ToUint32(octets);
  var hostMask = prefix === 0 ? 0xFFFFFFFF : ((1 << (IPV4_MASK_MAX - prefix)) - 1) >>> 0;
  return (addr & hostMask) !== 0;
}

function _hostBitsSetIpv6(groups, prefix) {
  if (prefix === IPV6_MASK_MAX) return false;
  // Walk groups from most-significant; once we cross the prefix
  // boundary, every remaining bit must be zero.
  var bitIdx = 0;
  for (var i = 0; i < groups.length; i += 1) {
    var grp = parseInt(groups[i], 16);                                           // allow:raw-byte-literal — base-16 radix
    for (var b = 15; b >= 0; b -= 1) {                                           // allow:raw-byte-literal — bits per group
      if (bitIdx >= prefix) {
        if ((grp >> b) & 1) return true;
      }
      bitIdx += 1;
    }
  }
  return false;
}

function _ipv4InReservedRange(octets, prefix) {
  var addr = _ipv4ToUint32(octets);
  var hits = [];
  for (var i = 0; i < IPV4_RESERVED.length; i += 1) {
    var r = IPV4_RESERVED[i];
    if (prefix < r.prefix) continue;                                             // user range broader than reserved → not contained
    var mask = r.prefix === 0 ? 0 : (0xFFFFFFFF << (IPV4_MASK_MAX - r.prefix)) >>> 0;
    // JS `&` is signed int32 — `>>> 0` reinterprets back to uint32 so
    // addresses with the high bit set compare correctly.
    if (((addr & mask) >>> 0) === r.net) hits.push(r.label);
  }
  return hits;
}

function _ipv6InReservedRange(groups, prefix) {
  var hex = groups.join("");
  var hits = [];
  for (var i = 0; i < IPV6_RESERVED.length; i += 1) {
    var r = IPV6_RESERVED[i];
    if (prefix < r.prefix) continue;
    if (hex.startsWith(r.hexPrefix)) hits.push(r.label);
  }
  return hits;
}

// ---- Detection ----

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "cidr.bad-input",
              snippet: "cidr is not a string" }];
  }
  if (input.length === 0) {
    return [{ kind: "empty", severity: "high",
              ruleId: "cidr.empty",
              snippet: "cidr is empty" }];
  }
  if (Buffer.byteLength(input, "utf8") > opts.maxBytes) {
    return [{ kind: "cidr-cap", severity: "high",
              ruleId: "cidr.cidr-cap",
              snippet: "cidr input exceeds maxBytes " + opts.maxBytes }];
  }

  var charThreats = codepointClass.detectCharThreats(input, opts, "cidr");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

  // Split address from mask.
  var slashAt = input.indexOf("/");
  var addrPart = slashAt === -1 ? input : input.slice(0, slashAt);
  var maskPart = slashAt === -1 ? null   : input.slice(slashAt + 1);

  var hasMask = maskPart !== null;
  if (!hasMask) {
    if (opts.requireMaskPolicy === "reject-bare-ip") {
      issues.push({
        kind: "bare-ip", severity: "high",
        ruleId: "cidr.bare-ip",
        snippet: "input has no `/mask` — bare IP refused at strict; " +
                 "use /32 (IPv4) or /128 (IPv6) for a single host",
      });
      return issues;
    } else if (opts.requireMaskPolicy === "audit-bare-ip") {
      issues.push({
        kind: "bare-ip", severity: "warn",
        ruleId: "cidr.bare-ip",
        snippet: "input has no `/mask` — treating as /32 or /128 host",
      });
    }
  }

  // Determine address family.
  var ipv4Octets = _parseIpv4(addrPart);
  var ipv6Groups = ipv4Octets ? null : _parseIpv6(addrPart);

  if (!ipv4Octets && !ipv6Groups) {
    issues.push({
      kind: "address-shape", severity: "high",
      ruleId: "cidr.address-shape",
      snippet: "address `" + addrPart + "` is not a valid IPv4 dotted-" +
               "decimal or IPv6 hex-group form",
    });
    return issues;
  }

  var family = ipv4Octets ? "ipv4" : "ipv6";

  // Family-restriction enforcement.
  if (opts.family === "ipv4-only" && family !== "ipv4") {
    issues.push({
      kind: "family-mismatch", severity: "high",
      ruleId: "cidr.family-mismatch",
      snippet: "address is " + family + " but family policy is `ipv4-only`",
    });
  }
  if (opts.family === "ipv6-only" && family !== "ipv6") {
    issues.push({
      kind: "family-mismatch", severity: "high",
      ruleId: "cidr.family-mismatch",
      snippet: "address is " + family + " but family policy is `ipv6-only`",
    });
  }

  // Mask validation.
  var maskMax = family === "ipv4" ? IPV4_MASK_MAX : IPV6_MASK_MAX;
  var prefix = hasMask ? -1 : maskMax;
  if (hasMask) {
    if (!/^[0-9]+$/.test(maskPart)) {
      issues.push({
        kind: "mask-shape", severity: "high",
        ruleId: "cidr.mask-shape",
        snippet: "mask `" + maskPart + "` is not a non-negative integer",
      });
      return issues;
    }
    prefix = parseInt(maskPart, 10);                                             // allow:raw-byte-literal — base-10 radix
    if (prefix > maskMax) {
      issues.push({
        kind: "mask-cap", severity: "high",
        ruleId: "cidr.mask-cap",
        snippet: "mask /" + prefix + " exceeds " + family + " maximum /" +
                 maskMax,
      });
      return issues;
    }
  }

  // Network-address alignment — host bits must be zero unless the
  // mask is /32 or /128 (single host).
  var misaligned;
  if (family === "ipv4") misaligned = _hostBitsSetIpv4(ipv4Octets, prefix);
  else                   misaligned = _hostBitsSetIpv6(ipv6Groups, prefix);
  if (misaligned && opts.networkAlignmentPolicy !== "allow") {
    issues.push({
      kind: "network-misaligned",
      severity: opts.networkAlignmentPolicy === "reject" ? "high" : "warn",
      ruleId: "cidr.network-misaligned",
      snippet: "host bits set in `" + addrPart + "/" + prefix + "` — " +
               "network address would be different; common typo class",
    });
  }

  // Reserved-range membership.
  var reserved = family === "ipv4"
    ? _ipv4InReservedRange(ipv4Octets, prefix)
    : _ipv6InReservedRange(ipv6Groups, prefix);
  if (reserved.length > 0 && opts.reservedRangesPolicy !== "allow") {
    issues.push({
      kind: "reserved-range",
      severity: opts.reservedRangesPolicy === "reject" ? "high" : "warn",
      ruleId: "cidr.reserved-range",
      snippet: "cidr falls inside reserved range(s): " + reserved.join(", "),
    });
  }

  // IPv4-mapped IPv6 confusion check.
  if (family === "ipv6" &&
      reserved.indexOf("ipv4-mapped") !== -1 &&
      opts.ipv4MappedIpv6Policy !== "allow") {
    issues.push({
      kind: "ipv4-mapped-ipv6",
      severity: opts.ipv4MappedIpv6Policy === "reject" ? "high" : "warn",
      ruleId: "cidr.ipv4-mapped-ipv6",
      snippet: "address is IPv4-mapped IPv6 (`::ffff:0:0/96`) — dual-" +
               "stack allowlist confusion class (CVE-2021-22931 IPv6 " +
               "variant)",
    });
  }

  return issues;
}

/**
 * @primitive  b.guardCidr.validate
 * @signature  b.guardCidr.validate(input, opts?)
 * @since      0.7.41
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardCidr.sanitize, b.guardCidr.gate
 *
 * Inspect a CIDR notation string and return `{ ok, issues, summary }`.
 * Each issue carries `{ kind, severity, ruleId, snippet }` with
 * severity in `"warn"|"high"|"critical"`. Detected: malformed address
 * shape, octet-out-of-range, mask-out-of-range, network-address
 * misalignment, reserved-range membership, IPv4-mapped-IPv6
 * confusion, family mismatch, bare IP without `/mask`, BIDI / control
 * / null-byte / zero-width codepoints. Pure inspection — never
 * mutates input or throws.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliance: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   family:     "either"|"ipv4-only"|"ipv6-only",
 *   networkAlignmentPolicy: "reject"|"audit"|"allow",
 *   reservedRangesPolicy:   "reject"|"audit"|"allow",
 *   ipv4MappedIpv6Policy:   "reject"|"audit"|"allow",
 *   requireMaskPolicy:      "reject-bare-ip"|"audit-bare-ip"|"allow-bare-ip",
 *   maxBytes:   number,    // CIDR string byte cap (default 64)
 *
 * @example
 *   var rv = b.guardCidr.validate("10.0.0.0/8", { profile: "strict" });
 *   rv.ok;                                             // → false
 *   rv.issues.some(function (i) { return i.kind === "reserved-range"; });   // → true
 *
 *   var clean = b.guardCidr.validate("8.8.8.0/24", { profile: "strict" });
 *   clean.ok;                                          // → true
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes"],
    "guardCidr.validate", GuardCidrError, "cidr.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 ruleId: "cidr.bad-input",
                 snippet: "cidr is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

/**
 * @primitive  b.guardCidr.sanitize
 * @signature  b.guardCidr.sanitize(input, opts?)
 * @since      0.7.41
 * @status     stable
 * @related    b.guardCidr.validate, b.guardCidr.gate
 *
 * Normalize a CIDR string when no critical/high issues fire. Throws
 * `GuardCidrError` on any high/critical refusal (reserved-range,
 * misalignment under strict, BIDI / null-byte / control bytes).
 * Safe transforms applied otherwise: lowercase IPv6 hex groups,
 * preserve mask form. IPv4 is returned unchanged (no canonical
 * casing).
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliance: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *
 * @example
 *   var safe = b.guardCidr.sanitize("2001:DB8::/32", { profile: "permissive" });
 *   safe;                                              // → "2001:db8::/32"
 *
 *   var v4 = b.guardCidr.sanitize("8.8.8.0/24", { profile: "strict" });
 *   v4;                                                // → "8.8.8.0/24"
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("cidr.bad-input", "sanitize requires string input");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "cidr.refused",
        "guardCidr.sanitize: " + issues[i].snippet);
    }
  }
  // Normalize: lowercase IPv6 groups + canonical mask form.
  var slashAt = input.indexOf("/");
  var addr = slashAt === -1 ? input : input.slice(0, slashAt);
  var mask = slashAt === -1 ? null  : input.slice(slashAt + 1);
  if (_parseIpv4(addr)) return mask === null ? addr : addr + "/" + mask;
  return mask === null ? addr.toLowerCase() : addr.toLowerCase() + "/" + mask;
}

/**
 * @primitive  b.guardCidr.gate
 * @signature  b.guardCidr.gate(opts?)
 * @since      0.7.41
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardCidr.validate, b.guardCidr.sanitize
 *
 * Build a `b.gateContract` gate that consumes `ctx.identifier` (or
 * `ctx.cidr`) and dispatches `serve` (no input or clean) →
 * `audit-only` (warn-only issues) → `refuse` (any critical or high
 * issue). No `sanitize` action — CIDR sanitization is caller-driven
 * via `b.guardCidr.sanitize`; an allowlist gate that silently rewrote
 * the operator's network range would be its own bug class.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliance: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,    // gate identity for audit / observability
 *   family:     "either"|"ipv4-only"|"ipv6-only",
 *
 * @example
 *   var cidrGate = b.guardCidr.gate({ profile: "strict", family: "ipv4-only" });
 *   var verdict = await cidrGate.check({ identifier: "10.0.0.0/8" });
 *   verdict.action;                                    // → "refuse"
 */
function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardCidr:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var identifier = ctx && (ctx.identifier || ctx.cidr || "");
      if (!identifier) return { ok: true, action: "serve" };
      var rv = validate(identifier, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical";
      });
      var hasHigh = rv.issues.some(function (i) {
        return i.severity === "high";
      });
      if (!hasCritical && !hasHigh) {
        return { ok: true, action: "audit-only", issues: rv.issues };
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

/**
 * @primitive  b.guardCidr.buildProfile
 * @signature  b.guardCidr.buildProfile(opts)
 * @since      0.7.41
 * @status     stable
 * @related    b.guardCidr.gate, b.guardCidr.compliancePosture
 *
 * Compose a derived profile from one or more named bases plus inline
 * overrides. `opts.extends` is a profile name (`"strict"` /
 * `"balanced"` / `"permissive"`) or an array of names; later entries
 * shadow earlier ones. Inline `opts` keys win last.
 *
 * @opts
 *   extends: string|string[],   // base profile name(s) to compose
 *
 * @example
 *   var custom = b.guardCidr.buildProfile({
 *     extends: "balanced",
 *     reservedRangesPolicy: "reject",
 *   });
 *   custom.reservedRangesPolicy;                       // → "reject"
 *   custom.bidiPolicy;                                 // → "reject"
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardCidr.compliancePosture
 * @signature  b.guardCidr.compliancePosture(name)
 * @since      0.7.41
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardCidr.gate, b.guardCidr.buildProfile
 *
 * Look up a compliance-posture overlay by name (`"hipaa"` /
 * `"pci-dss"` / `"gdpr"` / `"soc2"`). Returns a shallow clone of the
 * posture object — the caller may mutate freely. Throws
 * `GuardCidrError("cidr.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardCidr.compliancePosture("hipaa");
 *   posture.reservedRangesPolicy;                      // → "reject"
 *   posture.forensicSnippetBytes;                      // → 128
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "cidr");
}

var _cidrRulePacks = gateContract.makeRulePackLoader(GuardCidrError, "cidr");
/**
 * @primitive  b.guardCidr.loadRulePack
 * @signature  b.guardCidr.loadRulePack(pack)
 * @since      0.7.41
 * @status     stable
 * @related    b.guardCidr.gate
 *
 * Register an operator-supplied rule pack with the guard-cidr
 * registry. The pack is identified by `pack.id` (non-empty string)
 * and stored for later inspection / dispatch by gates that opt in
 * via `opts.rulePackId`. Returns the pack object unchanged on
 * success; throws `GuardCidrError("cidr.bad-opt")` when `pack` is
 * missing or `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardCidr.loadRulePack({
 *     id: "tenant-private-only",
 *     rules: [
 *       { id: "external-allowlisted", severity: "high",
 *         detect: function (cidr) { return cidr.indexOf("10.") !== 0; },
 *         reason: "tenant policy: only 10.0.0.0/8 ranges permitted" },
 *     ],
 *   });
 *   pack.id;                                           // → "tenant-private-only"
 */
var loadRulePack = _cidrRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "cidr",
  KIND:                "identifier",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "identifier",
    benignBytes:       Buffer.from("8.8.8.0/24", "utf8"),
    hostileBytes:      Buffer.from("10.0.0.0/8", "utf8"),
    benignIdentifier:  "8.8.8.0/24",
    // Hostile: RFC 1918 private range — refused at strict.
    hostileIdentifier: "10.0.0.0/8",
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardCidrError:      GuardCidrError,
};
