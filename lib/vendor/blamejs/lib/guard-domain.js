// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardDomain
 * @nav    Guards
 * @title  Guard Domain
 *
 * @intro
 *   Domain-name identifier-safety primitive (KIND="identifier").
 *   Validates user-supplied DNS names destined for allowlists,
 *   redirect targets, webhook endpoints, email-domain extraction,
 *   and CORS origin checks. Consumes `ctx.identifier` (or
 *   `ctx.domain`).
 *
 *   IDN homograph defense: mixed-script confusables (RFC 5891-5894
 *   IDNA2008, UTS #39) — Cyrillic / Greek / Cherokee letters mixed
 *   with Latin in a single label spoof trusted domains. Strict
 *   refuses; balanced/permissive audit. The script-allowlist is
 *   operator-tunable via `opts.allowedScripts`. Punycode A-labels
 *   (`xn--`) audit by default at balanced; bare `xn--` always
 *   refuses.
 *
 *   Label-length caps per RFC 1035 §2.3.4: 63 octets per label, 253
 *   octets per FQDN. UTF-8 byte counting (not codepoint count) — the
 *   wire-form bound is what DNS resolvers enforce. RFC 952 / 1123
 *   LDH grammar enforced for ASCII labels; double-hyphen at positions
 *   3-4 without `xn--` prefix audits.
 *
 *   TLD allowlist + public-suffix awareness: RFC 6761 special-use
 *   suffixes (`.localhost` / `.local` / `.invalid` / `.test` /
 *   `.onion` / `.alt` / `.home.arpa` / `.internal`) refuse under
 *   strict — letting these through as user-input webhook targets
 *   routes traffic to loopback / mDNS / Tor / LAN. IPv4-as-domain
 *   (dotted-decimal, octal, hex, long-decimal) and IPv6 bracket
 *   literals refuse (CVE-2021-22931 DNS-rebinding class).
 *   Single-label / TLD-only refuses under strict (search-domain
 *   suffix on misconfigured stubs).
 *
 *   Public-suffix and full UTS #46 ToASCII / ToUnicode round-trip
 *   ship behind operator-supplied callbacks (`opts.publicSuffixList`,
 *   `opts.idnToAscii`) — defer-with-condition until an operator
 *   surfaces a cookie-scope or email-domain canonicalization use case
 *   that needs framework-vendored tables.
 *
 *   BIDI / control / null-byte / zero-width are universal-refuse at
 *   every profile (CVE-2021-42574 Trojan Source class). DGA heuristic
 *   (Shannon entropy >= 3.8 bits/char on labels >= 12 chars) audits
 *   under balanced, refuses under strict.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`.
 *
 * @card
 *   Domain-name identifier-safety primitive (KIND="identifier").
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var ipUtils = require("./ip-utils");
var C = require("./constants");
var { GuardDomainError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardDomainError.factory;

// ---- RFC 1035 §2.3.4 length caps ----

var LIMIT_LABEL_OCTETS = 63;                                                     // RFC 1035 §2.3.4
var LIMIT_DOMAIN_OCTETS = 253;                                                   // RFC 1035 §2.3.4 (255 wire minus length prefixes)

// ---- Label shapes (character walks over explicit codepoint tables) ----

function _isAsciiLetter(cc) {
  return (cc >= 0x41 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A);
}
function _isAsciiDigit(cc) { return cc >= 0x30 && cc <= 0x39; }
function _isHexDigit(cc) {
  return _isAsciiDigit(cc) || (cc >= 0x41 && cc <= 0x46) || (cc >= 0x61 && cc <= 0x66);
}
function _isLdhChar(cc) {
  return _isAsciiLetter(cc) || _isAsciiDigit(cc) || cc === 0x2D;   // "-"
}

// An LDH label — letters, digits and hyphens, beginning and ending with a
// letter or a digit. Length is checked separately.
function _isLdhLabel(s) {
  if (s.length === 0) return false;
  if (!_isAsciiLetter(s.charCodeAt(0)) && !_isAsciiDigit(s.charCodeAt(0))) return false;
  var last = s.charCodeAt(s.length - 1);
  if (!_isAsciiLetter(last) && !_isAsciiDigit(last)) return false;
  for (var i = 1; i < s.length - 1; i += 1) {
    if (!_isLdhChar(s.charCodeAt(i))) return false;
  }
  return true;
}

// A service-prefix label per RFC 8552 — `_dmarc`, `_acme-challenge`. An
// underscore, then an LDH label.
function _isServiceLabel(s) {
  return s.charAt(0) === "_" && _isLdhLabel(s.slice(1));
}

// The punycode A-label prefix, and the malformed form that is the prefix and
// nothing else.
function _hasPunycodePrefix(s) {
  return s.length >= 4 && s.slice(0, 4).toLowerCase() === "xn--";
}
function _isBarePunycodePrefix(s) {
  return s.length === 4 && _hasPunycodePrefix(s);
}

// Is every character of `s` a digit?
function _isAllDigits(s) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i += 1) {
    if (!_isAsciiDigit(s.charCodeAt(i))) return false;
  }
  return true;
}

// One numeric segment of a permissive IPv4 spelling: decimal (which covers the
// octal form, since a leading zero is still a digit run) or `0x`-prefixed hex.
function _isIpv4NumericSegment(s) {
  if (_isAllDigits(s)) return true;
  if (s.length < 3) return false;
  if (s.charAt(0) !== "0") return false;
  var x = s.charCodeAt(1);
  if (x !== 0x78 && x !== 0x58) return false;                      // "x" / "X"
  for (var i = 2; i < s.length; i += 1) {
    if (!_isHexDigit(s.charCodeAt(i))) return false;
  }
  return true;
}

// Minimum digits before a bare decimal run counts as an IPv4 address rather
// than a port-shaped number.
var LONG_DECIMAL_IPV4_DIGITS = 8;

// Looser IPv4 detection — every dot-segment is a numeric form (decimal, octal
// with a leading zero, or hex with an `0x` prefix), or the whole input is a
// long-decimal / long-hex with no dots. Catches the parser-permissive forms
// `0177.0.0.1` (octal), `0xC0.0xA8.0x01.0x01` (hex), `3232235777`
// (long-decimal) and `0xC0A80101` (long-hex).
//
// Detection requires at least one digit AND that every dot-segment is a
// number, so a purely alphabetic `a.b` does not read as IPv4 even though its
// characters overlap the hex alphabet.
function _looksLikeIpv4Permissive(s) {
  var hasDigit = false;
  for (var d = 0; d < s.length; d += 1) {
    if (_isAsciiDigit(s.charCodeAt(d))) { hasDigit = true; break; }
  }
  if (!hasDigit) return false;
  if (_isIpv4NumericSegment(s)) {
    // No dots: a long-hex form counts immediately; a bare decimal run has to
    // be long enough not to be a port number.
    return _isAllDigits(s) ? s.length >= LONG_DECIMAL_IPV4_DIGITS : true;
  }
  if (s.indexOf(".") === -1) return false;
  var parts = s.split(".");
  if (parts.length !== 4) return false;
  for (var i = 0; i < parts.length; i += 1) {
    if (!_isIpv4NumericSegment(parts[i])) return false;
  }
  return true;
}

// An IPv6 bracket literal: `[`, a run of hex digits, colons and dots, `]`.
function _isIpv6BracketLiteral(s) {
  if (s.length < 3) return false;
  if (s.charAt(0) !== "[" || s.charAt(s.length - 1) !== "]") return false;
  for (var i = 1; i < s.length - 1; i += 1) {
    var cc = s.charCodeAt(i);
    if (!_isHexDigit(cc) && cc !== 0x3A && cc !== 0x2E) return false;   // ":" "."
  }
  return true;
}

// IDN script-range tables for mixed-script confusable detection live
// in codepoint-class — every guard-* family member + safe-url shares
// the same catalog so adding a script is a single edit.
var _detectMixedScripts = codepointClass.detectMixedScripts;

// RFC 6761 special-use domains + IETF reserved. Lowercase, no trailing
// dot. Match by suffix — `_acme-challenge.app.localhost` → `.localhost`.
//
// Excluded deliberately: `example.com` / `example.net` / `example.org`.
// Those are documentation-reserved but legitimately appear in test
// fixtures and SSO redirect-URI examples; refusing them at strict
// trips operators on benign inputs. A future `documentation-reserved`
// posture can flag them as warn-only when operators ask.
var SPECIAL_USE_DOMAINS = Object.freeze([
  "localhost",
  "local",            // RFC 6762 mDNS
  "invalid",
  "test",
  "onion",            // RFC 7686
  "alt",              // RFC 9476
  "home.arpa",        // RFC 8375
  "internal",         // ICANN reserved 2024
]);

function _matchesSpecialUse(name) {
  // The whole trailing run of dots, not just the root label's one: a resolver
  // that tolerates `localhost..` resolves it as `localhost`, and stripping a
  // single dot leaves `localhost.` which matches nothing in the table.
  var lower = codepointClass.trimChars(name.toLowerCase(), ".", { leading: false });
  for (var i = 0; i < SPECIAL_USE_DOMAINS.length; i += 1) {
    var su = SPECIAL_USE_DOMAINS[i];
    if (lower === su || lower.endsWith("." + su)) return su;
  }
  return null;
}

// Shannon entropy in bits per character over a-z0-9 alphabet, used as
// a DGA heuristic. Returns 0 for trivial inputs.
function _shannonEntropy(s) {
  if (!s || s.length < 2) return 0;
  var counts = Object.create(null);
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charAt(i).toLowerCase();
    counts[c] = (counts[c] || 0) + 1;
  }
  var len = s.length;
  var h = 0;
  var keys = Object.keys(counts);
  for (var k = 0; k < keys.length; k += 1) {
    var p = counts[keys[k]] / len;
    h -= p * Math.log2(p);
  }
  return h;
}

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    ldhPolicy:            "reject",
    underscorePolicy:     "reject",                                              // strict refuses service labels too
    punycodePolicy:       "reject",
    mixedScriptPolicy:    "reject",
    specialUsePolicy:     "reject",
    ipLiteralPolicy:      "reject",
    wildcardPolicy:       "reject",
    singleLabelPolicy:    "reject",
    trailingDotPolicy:    "normalize",
    dgaPolicy:            "reject",
    allowedScripts:       ["latin"],
    dgaEntropyThreshold:  3.8,                                                   // Shannon entropy bits/char threshold (DGA heuristic)
    dgaMinLabelLen:       12,                                                    // DGA heuristic floor
    maxLabelOctets:       LIMIT_LABEL_OCTETS,
    maxDomainOctets:      LIMIT_DOMAIN_OCTETS,
    maxBytes:             C.BYTES.bytes(2048),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    ldhPolicy:            "reject",
    underscorePolicy:     "reject",
    punycodePolicy:       "audit",
    mixedScriptPolicy:    "reject",
    specialUsePolicy:     "reject",
    ipLiteralPolicy:      "reject",
    wildcardPolicy:       "reject",
    singleLabelPolicy:    "reject",
    trailingDotPolicy:    "normalize",
    dgaPolicy:            "audit",
    allowedScripts:       ["latin", "cyrillic", "greek", "han", "hiragana",
                           "katakana", "hangul"],
    dgaEntropyThreshold:  3.8,                                                   // Shannon entropy bits/char threshold (DGA heuristic)
    dgaMinLabelLen:       12,                                                    // DGA heuristic floor
    maxLabelOctets:       LIMIT_LABEL_OCTETS,
    maxDomainOctets:      LIMIT_DOMAIN_OCTETS,
    maxBytes:             C.BYTES.bytes(2048),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    ldhPolicy:            "audit",
    underscorePolicy:     "allow",                                               // service labels permitted in permissive
    punycodePolicy:       "allow",
    mixedScriptPolicy:    "audit",
    specialUsePolicy:     "audit",
    ipLiteralPolicy:      "allow",
    wildcardPolicy:       "reject",                                              // wildcard refused at every profile — never user-input
    singleLabelPolicy:    "audit",
    trailingDotPolicy:    "normalize",
    dgaPolicy:            "allow",
    allowedScripts:       null,
    dgaEntropyThreshold:  3.8,                                                   // Shannon entropy bits/char threshold (DGA heuristic)
    dgaMinLabelLen:       12,                                                    // DGA heuristic floor
    maxLabelOctets:       LIMIT_LABEL_OCTETS,
    maxDomainOctets:      LIMIT_DOMAIN_OCTETS,
    maxBytes:             C.BYTES.bytes(2048),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
});

// ---- Detection ----

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "domain", emptyMode: "skip", cap: { bytes: opts.maxDomainOctets, snippet: function (byteLen, max) { return "domain " + byteLen + " octets exceeds " + max + " (RFC 1035 §2.3.4)"; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  // Trailing-dot — FQDN distinguisher. Normalize for downstream checks
  // but record as audit if operator wants to know.
  var hadTrailingDot = input.charAt(input.length - 1) === ".";
  var name = hadTrailingDot ? input.slice(0, -1) : input;

  // Empty string after trim.
  if (name.length === 0) {
    issues.push({
      kind: "empty", severity: "high",
      ruleId: "domain.empty",
      snippet: "domain is empty",
    });
    return issues;
  }

  // Bracketed IPv6 literal.
  if (_isIpv6BracketLiteral(name)) {
    if (opts.ipLiteralPolicy !== "allow") {
      issues.push({
        kind: "ipv6-literal",
        severity: opts.ipLiteralPolicy === "reject" ? "high" : "warn",
        ruleId: "domain.ipv6-literal",
        snippet: "input is an IPv6 bracket literal — bypasses DNS-name " +
                 "validation; pass through opts.allowIp if intended",
      });
    }
    return issues;
  }

  // IPv4 detection — strict dotted-decimal AND loose (octal/hex/long).
  if (ipUtils.isIPv4(name) || _looksLikeIpv4Permissive(name)) {
    if (opts.ipLiteralPolicy !== "allow") {
      issues.push({
        kind: "ipv4-as-domain",
        severity: opts.ipLiteralPolicy === "reject" ? "high" : "warn",
        ruleId: "domain.ipv4-as-domain",
        snippet: "input parses as IPv4 (CVE-2021-22931 class) — " +
                 "DNS-rebinding risk against allowlist matchers",
      });
      // Don't continue to label parsing — IPv4-shaped strings would
      // collide with single-label / LDH errors and confuse the operator.
      return issues;
    }
  }

  // RFC 6761 special-use suffix.
  var su = _matchesSpecialUse(name);
  if (su && opts.specialUsePolicy !== "allow") {
    issues.push({
      kind: "special-use",
      severity: opts.specialUsePolicy === "reject" ? "high" : "warn",
      ruleId: "domain.special-use",
      snippet: "domain matches RFC 6761 / IETF reserved suffix `." + su + "` " +
               "— would route to loopback / mDNS / Tor / LAN",
    });
  }

  // Label split + per-label structural checks.
  var labels = name.split(".");

  // Single-label / TLD-only.
  if (labels.length < 2) {
    if (opts.singleLabelPolicy !== "allow") {
      issues.push({
        kind: "single-label",
        severity: opts.singleLabelPolicy === "reject" ? "high" : "warn",
        ruleId: "domain.single-label",
        snippet: "single-label / TLD-only domain — risks search-domain " +
                 "suffixing on misconfigured stub resolvers",
      });
    }
  }

  for (var li = 0; li < labels.length; li += 1) {
    var label = labels[li];

    // Empty label (e.g. `foo..bar` or leading `.foo`).
    if (label.length === 0) {
      issues.push({
        kind: "empty-label", severity: "high",
        ruleId: "domain.empty-label",
        snippet: "label " + (li + 1) + " is empty (consecutive or " +
                 "leading dots)",
      });
      continue;
    }

    var labelBytes = Buffer.byteLength(label, "utf8");
    if (labelBytes > opts.maxLabelOctets) {
      issues.push({
        kind: "label-cap", severity: "high",
        ruleId: "domain.label-cap",
        snippet: "label " + (li + 1) + " is " + labelBytes +
                 " octets, exceeds " + opts.maxLabelOctets +
                 " (RFC 1035 §2.3.4)",
      });
      continue;                                                                  // label-cap masks downstream rule failures
    }

    // Wildcard `*`.
    if (label === "*") {
      if (opts.wildcardPolicy !== "allow") {
        issues.push({
          kind: "wildcard", severity: "high",
          ruleId: "domain.wildcard",
          snippet: "wildcard label `*` — valid in TLS SAN / DNS RR but " +
                   "never in a user-input identifier",
        });
      }
      continue;
    }

    // Service-prefix label (RFC 8552). Underscore allowed only if
    // operator opts in.
    if (label.charAt(0) === "_") {
      if (_isServiceLabel(label)) {
        if (opts.underscorePolicy !== "allow") {
          issues.push({
            kind: "underscore-label",
            severity: opts.underscorePolicy === "reject" ? "high" : "warn",
            ruleId: "domain.underscore-label",
            snippet: "label " + (li + 1) + " starts with `_` (RFC 8552 " +
                     "service label) — never valid as a hostname",
          });
        }
      } else {
        issues.push({
          kind: "underscore-malformed", severity: "high",
          ruleId: "domain.underscore-malformed",
          snippet: "label " + (li + 1) + " starts with `_` but doesn't " +
                   "match the service-label grammar",
        });
      }
      continue;
    }

    // Punycode A-label.
    if (_hasPunycodePrefix(label)) {
      if (_isBarePunycodePrefix(label)) {
        issues.push({
          kind: "punycode-bare", severity: "high",
          ruleId: "domain.punycode-bare",
          snippet: "label " + (li + 1) + " is bare `xn--` with no " +
                   "Punycode payload",
        });
        continue;
      }
      if (opts.punycodePolicy !== "allow") {
        issues.push({
          kind: "punycode-label",
          severity: opts.punycodePolicy === "reject" ? "high" : "warn",
          ruleId: "domain.punycode-label",
          snippet: "label " + (li + 1) + " is an IDN A-label (`xn--`) — " +
                   "homograph-spoofing class without round-trip validation",
        });
      }
      // ASCII LDH check still applies.
      if (!_isLdhLabel(label) && opts.ldhPolicy !== "allow") {
        issues.push({
          kind: "ldh-violation", severity: "high",
          ruleId: "domain.ldh-violation",
          snippet: "label " + (li + 1) + " (Punycode form) violates LDH " +
                   "rule (RFC 952 / 1123 §2.1)",
        });
      }
      continue;
    }

    // ASCII LDH or Unicode label.
    var allAscii = true;
    for (var ai = 0; ai < label.length; ai += 1) {
      if (label.charCodeAt(ai) > 0x7F) { allAscii = false; break; }              // ASCII boundary codepoint
    }

    if (allAscii) {
      if (!_isLdhLabel(label) && opts.ldhPolicy !== "allow") {
        issues.push({
          kind: "ldh-violation",
          severity: opts.ldhPolicy === "reject" ? "high" : "warn",
          ruleId: "domain.ldh-violation",
          snippet: "label " + (li + 1) + " " + JSON.stringify(label) +
                   " violates LDH rule (RFC 952 / 1123 §2.1)",
        });
      }
      // Position-3-4 double-hyphen check excluding the `xn--` prefix.
      if (label.length >= 4 && label.charAt(2) === "-" &&
          label.charAt(3) === "-" && !_hasPunycodePrefix(label)) {
        issues.push({
          kind: "double-hyphen", severity: "warn",
          ruleId: "domain.double-hyphen",
          snippet: "label " + (li + 1) + " has `--` at positions 3-4 " +
                   "without the `xn--` IDN prefix",
        });
      }
    } else {
      // Unicode label — flag mixed-script confusables and strict-LDH
      // operators that didn't opt into IDN.
      if (opts.punycodePolicy !== "allow") {
        // Operator wants Punycode-only; reject raw Unicode labels.
        issues.push({
          kind: "raw-unicode-label",
          severity: opts.punycodePolicy === "reject" ? "high" : "warn",
          ruleId: "domain.raw-unicode-label",
          snippet: "label " + (li + 1) + " contains raw Unicode " +
                   "(non-ASCII) — IDN labels must be Punycode-encoded " +
                   "(`xn--…`) for transport-safe comparison",
        });
      }
      var mixed = _detectMixedScripts(label, opts.allowedScripts);
      if (mixed && opts.mixedScriptPolicy !== "allow") {
        issues.push({
          kind: "mixed-script",
          severity: opts.mixedScriptPolicy === "reject" ? "critical" : "high",
          ruleId: "domain.mixed-script",
          snippet: "label " + (li + 1) + " mixes scripts (" +
                   mixed.join(", ") + ") — IDN homograph spoofing class",
        });
      }
    }

    // DGA entropy heuristic — high-entropy long single label is C2-shape.
    if (label.length >= opts.dgaMinLabelLen && opts.dgaPolicy !== "allow") {
      var h = _shannonEntropy(label);
      if (h >= opts.dgaEntropyThreshold) {
        issues.push({
          kind: "dga-entropy",
          severity: opts.dgaPolicy === "reject" ? "high" : "warn",
          ruleId: "domain.dga-entropy",
          snippet: "label " + (li + 1) + " has Shannon entropy " +
                   h.toFixed(2) + " bits/char (>= " +
                   opts.dgaEntropyThreshold + ") — C2 / DGA shape",
        });
      }
    }
  }

  // Trailing-dot audit signal (after structural checks, before return).
  if (hadTrailingDot && opts.trailingDotPolicy === "audit") {
    issues.push({
      kind: "trailing-dot", severity: "warn",
      ruleId: "domain.trailing-dot",
      snippet: "input had trailing dot (FQDN-marker) — normalize/strip " +
               "before allowlist comparison",
    });
  }

  return issues;
}

/**
 * @primitive  b.guardDomain.validate
 * @signature  b.guardDomain.validate(input, opts?)
 * @since      0.7.41
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardDomain.sanitize, b.guardDomain.gate
 *
 * Inspect a domain-name string and return `{ ok, issues }`.
 * Each issue carries `{ kind, severity, ruleId, snippet }` with
 * severity in `"warn"|"high"|"critical"`. Detected: domain/label
 * length cap (RFC 1035 §2.3.4), LDH violation, IDN A-label
 * malformation, mixed-script homograph, special-use suffix (RFC
 * 6761), IPv4-as-domain (every parser-permissive form), IPv6
 * bracket-literal, single-label / TLD-only, wildcard label,
 * underscore label, trailing dot, DGA-shape entropy, BIDI / control
 * / null-byte / zero-width codepoints. Pure inspection.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ldhPolicy:           "reject"|"audit"|"allow",
 *   punycodePolicy:      "reject"|"audit"|"allow",
 *   mixedScriptPolicy:   "reject"|"audit"|"allow",
 *   specialUsePolicy:    "reject"|"audit"|"allow",
 *   ipLiteralPolicy:     "reject"|"audit"|"allow",
 *   wildcardPolicy:      "reject"|"audit"|"allow",
 *   singleLabelPolicy:   "reject"|"audit"|"allow",
 *   underscorePolicy:    "reject"|"audit"|"allow",
 *   dgaPolicy:           "reject"|"audit"|"allow",
 *   trailingDotPolicy:   "normalize"|"audit"|"reject",
 *   allowedScripts:      string[]|null,
 *   dgaEntropyThreshold: number,
 *   dgaMinLabelLen:      number,
 *   maxLabelOctets:      number,    // default 63 (RFC 1035 §2.3.4)
 *   maxDomainOctets:     number,    // default 253 (RFC 1035 §2.3.4)
 *   maxBytes:            number,    // total input byte cap
 *
 * @example
 *   var rv = b.guardDomain.validate("192.168.1.1", { profile: "strict" });
 *   rv.ok;                                             // → false
 *   rv.issues.some(function (i) { return i.kind === "ipv4-as-domain"; });   // → true
 *
 *   var ok = b.guardDomain.validate("example.com", { profile: "strict" });
 *   ok.ok;                                             // → true
 */
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues) below — `validate(input, opts) = aggregateIssues(detect(
// input, resolveOpts(opts)))`, with the length/byte caps declared via
// `intOpts`. The @primitive block above documents the resulting public ABI.

/**
 * @primitive  b.guardDomain.sanitize
 * @signature  b.guardDomain.sanitize(input, opts?)
 * @since      0.7.41
 * @status     stable
 * @related    b.guardDomain.validate, b.guardDomain.gate
 *
 * Normalize a domain-name string when no critical/high issues fire.
 * Throws `GuardDomainError` on any high/critical refusal (homograph
 * mix, IPv4-as-domain, special-use suffix, BIDI, malformed Punycode).
 * Safe transforms applied otherwise: ASCII lowercasing, trailing-dot
 * strip. Refuses to canonicalize Unicode labels — operators wanting
 * IDN ToASCII supply `opts.idnToAscii` so the framework doesn't
 * silently rewrite a label the operator's allowlist would treat as
 * different.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *
 * @example
 *   var safe = b.guardDomain.sanitize("Example.Com.", { profile: "balanced" });
 *   safe;                                              // → "example.com"
 */
// _sanitizeTransform — the guard-specific normalize applied by defineGuard's
// generated sanitize AFTER resolve → detect → throw-on-refusal. Input is an
// already-validated string at this point (a non-string refuses upstream).
function _sanitizeTransform(input) {
  // Safe transforms: lowercase ASCII, strip trailing dot.
  var out = input.toLowerCase();
  if (out.charAt(out.length - 1) === ".") out = out.slice(0, -1);
  return out;
}

// gate / buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below; their wiki sections render from the
// single-sourced @abiTemplate (defineGuard) blocks in gate-contract.js,
// instantiated per guard by the page generator.

// Hostile: dotted-decimal IPv4 (CVE-2021-22931 class) — every profile
// refuses (allowlist-bypass via DNS rebinding).
var INTEGRATION_FIXTURES = gateContract.identifierFixtures("example.com", "192.168.1.1");

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize). The gate is the factory default — the
// standard serve -> audit-only -> refuse chain — reading ctx.identifier ||
// ctx.domain via ctxFields. No sanitize action: an allowlist gate never
// rewrites the operator's stored allowlist key.
module.exports = gateContract.defineGuard({
  name:        "domain",
  kind:        "identifier",
  errorClass:  GuardDomainError,
  profiles:    PROFILES,
  base:        256,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:           _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:          ["maxLabelOctets", "maxDomainOctets", "maxBytes", "dgaMinLabelLen"],
  ctxFields:   ["identifier", "domain"],
  extra: {
    // The label-shape walks, exposed so the test can compare each against the
    // pattern it replaced. Reaching them through `validate` alone would test
    // the policy layer on top rather than the shape decision itself.
    _shapesForTest: {
      isLdhLabel:             _isLdhLabel,
      isServiceLabel:         _isServiceLabel,
      hasPunycodePrefix:      _hasPunycodePrefix,
      isBarePunycodePrefix:   _isBarePunycodePrefix,
      isIpv6BracketLiteral:   _isIpv6BracketLiteral,
      looksLikeIpv4Permissive: _looksLikeIpv4Permissive,
    },
  },
});
