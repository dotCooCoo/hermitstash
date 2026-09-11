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

var nodeUrl = require("node:url");
var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var ipUtils = require("./ip-utils");
var C = require("./constants");
var { GuardDomainError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var LIMIT_LABEL_OCTETS = 63;
var LIMIT_DOMAIN_OCTETS = 253;

var _isAsciiLetter = codepointClass.isAsciiLetter;
var _isAsciiDigit  = codepointClass.isAsciiDigit;

function _isHexDigit(cc) {
  return _isAsciiDigit(cc) || (cc >= 0x41 && cc <= 0x46) || (cc >= 0x61 && cc <= 0x66);
}
function _isLdhChar(cc) {
  return codepointClass.isAsciiAlnum(cc) || cc === 0x2D;
}

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

function _isServiceLabel(s) {
  return s.charAt(0) === "_" && _isLdhLabel(s.slice(1));
}

function _hasPunycodePrefix(s) {
  return s.length >= 4 && s.slice(0, 4).toLowerCase() === "xn--";
}
function _isBarePunycodePrefix(s) {
  return s.length === 4 && _hasPunycodePrefix(s);
}

var IDNA_LABEL_SEPARATORS = ".。．｡";

function _normalizeIdnaSeparators(s) {
  var out = "";
  for (var i = 0; i < s.length; i += 1) {
    var ch = s.charAt(i);
    out += IDNA_LABEL_SEPARATORS.indexOf(ch) === -1 ? ch : ".";
  }
  return out;
}

function _aceLabelCarriesPayload(label) {
  if (!_hasPunycodePrefix(label)) return true;
  if (label.length <= 4) return false;
  var decoded;
  try { decoded = nodeUrl.domainToUnicode(label); }
  catch (_e) { return false; }
  if (decoded === "") return false;
  return decoded.toLowerCase() !== label.toLowerCase();
}

/**
 * @primitive  b.guardDomain.aceLabelsCarryPayload
 * @signature  b.guardDomain.aceLabelsCarryPayload(asciiDomain)
 * @since      0.20.0
 * @status     stable
 * @related    b.guardDomain.validate, b.mail.toAscii, b.publicSuffix.canonicalDomain
 *
 * Report whether every `xn--` label in an already-ASCII domain carries a
 * Punycode payload that decodes. `xn--`, `xn--a` and `xn--zz` do not and
 * return `false`; a well-formed A-label such as `xn--mnchen-3ya` returns
 * `true`, as does a name with no `xn--` label at all.
 *
 * `url.domainToASCII()` maps a name, it does not validate one, and its
 * answer for a payload-less ACE label differs by Node version: 24.21.0
 * returns the label unchanged where 26 returns the empty string. A caller
 * testing only for the empty string accepts `xn--` on one runtime and
 * refuses it on the other. This is the framework's own answer and does not
 * move with the runtime.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.guardDomain.aceLabelsCarryPayload("xn--mnchen-3ya.de");   // → true
 *   b.guardDomain.aceLabelsCarryPayload("xn--.de");             // → false
 */
function aceLabelsCarryPayload(asciiDomain) {
  if (typeof asciiDomain !== "string" || asciiDomain.length === 0) return false;
  var labels = _normalizeIdnaSeparators(asciiDomain).split(".");
  for (var i = 0; i < labels.length; i += 1) {
    if (!_aceLabelCarriesPayload(labels[i])) return false;
  }
  return true;
}

function _isAllDigits(s) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i += 1) {
    if (!_isAsciiDigit(s.charCodeAt(i))) return false;
  }
  return true;
}

function _isIpv4NumericSegment(s) {
  if (_isAllDigits(s)) return true;
  if (s.length < 3) return false;
  if (s.charAt(0) !== "0") return false;
  var x = s.charCodeAt(1);
  if (x !== 0x78 && x !== 0x58) return false;
  for (var i = 2; i < s.length; i += 1) {
    if (!_isHexDigit(s.charCodeAt(i))) return false;
  }
  return true;
}

var LONG_DECIMAL_IPV4_DIGITS = 8;

function _looksLikeIpv4Permissive(s) {
  var hasDigit = false;
  for (var d = 0; d < s.length; d += 1) {
    if (_isAsciiDigit(s.charCodeAt(d))) { hasDigit = true; break; }
  }
  if (!hasDigit) return false;
  if (_isIpv4NumericSegment(s)) {
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

function _isIpv6BracketLiteral(s) {
  if (s.length < 3) return false;
  if (s.charAt(0) !== "[" || s.charAt(s.length - 1) !== "]") return false;
  for (var i = 1; i < s.length - 1; i += 1) {
    var cc = s.charCodeAt(i);
    if (!_isHexDigit(cc) && cc !== 0x3A && cc !== 0x2E) return false;
  }
  return true;
}

var _detectMixedScripts = codepointClass.detectMixedScripts;

var SPECIAL_USE_DOMAINS = Object.freeze([
  "localhost",
  "local",
  "invalid",
  "test",
  "onion",
  "alt",
  "home.arpa",
  "internal",
]);

function _matchesSpecialUse(name) {
  var lower = codepointClass.trimChars(name.toLowerCase(), ".", { leading: false });
  for (var i = 0; i < SPECIAL_USE_DOMAINS.length; i += 1) {
    var su = SPECIAL_USE_DOMAINS[i];
    if (lower === su || lower.endsWith("." + su)) return su;
  }
  return null;
}

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

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    ldhPolicy:            "reject",
    underscorePolicy:     "reject",
    punycodePolicy:       "reject",
    mixedScriptPolicy:    "reject",
    specialUsePolicy:     "reject",
    ipLiteralPolicy:      "reject",
    wildcardPolicy:       "reject",
    singleLabelPolicy:    "reject",
    trailingDotPolicy:    "normalize",
    dgaPolicy:            "reject",
    allowedScripts:       ["latin"],
    dgaEntropyThreshold:  3.8,
    dgaMinLabelLen:       12,
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
    dgaEntropyThreshold:  3.8,
    dgaMinLabelLen:       12,
    maxLabelOctets:       LIMIT_LABEL_OCTETS,
    maxDomainOctets:      LIMIT_DOMAIN_OCTETS,
    maxBytes:             C.BYTES.bytes(2048),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    ldhPolicy:            "audit",
    underscorePolicy:     "allow",
    punycodePolicy:       "allow",
    mixedScriptPolicy:    "audit",
    specialUsePolicy:     "audit",
    ipLiteralPolicy:      "allow",
    wildcardPolicy:       "reject",
    singleLabelPolicy:    "audit",
    trailingDotPolicy:    "normalize",
    dgaPolicy:            "allow",
    allowedScripts:       null,
    dgaEntropyThreshold:  3.8,
    dgaMinLabelLen:       12,
    maxLabelOctets:       LIMIT_LABEL_OCTETS,
    maxDomainOctets:      LIMIT_DOMAIN_OCTETS,
    maxBytes:             C.BYTES.bytes(2048),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
});

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "domain", emptyMode: "skip", cap: { bytes: opts.maxDomainOctets, snippet: function (byteLen, max) { return "domain " + byteLen + " octets exceeds " + max + " (RFC 1035 §2.3.4)"; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  var normalized = _normalizeIdnaSeparators(input);
  var hadTrailingDot = normalized.charAt(normalized.length - 1) === ".";
  var name = hadTrailingDot ? normalized.slice(0, -1) : normalized;

  if (name.length === 0) {
    issues.push({
      kind: "empty", severity: "high",
      ruleId: "domain.empty",
      snippet: "domain is empty",
    });
    return issues;
  }

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

  if (ipUtils.isIPv4(name) || _looksLikeIpv4Permissive(name)) {
    if (opts.ipLiteralPolicy !== "allow") {
      issues.push({
        kind: "ipv4-as-domain",
        severity: opts.ipLiteralPolicy === "reject" ? "high" : "warn",
        ruleId: "domain.ipv4-as-domain",
        snippet: "input parses as IPv4 (CVE-2021-22931 class) — " +
                 "DNS-rebinding risk against allowlist matchers",
      });
      return issues;
    }
  }

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

  var labels = name.split(".");

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
      continue;
    }

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
      if (!_aceLabelCarriesPayload(label)) {
        issues.push({
          kind: "punycode-undecodable", severity: "high",
          ruleId: "domain.punycode-undecodable",
          snippet: "label " + (li + 1) + " carries an `xn--` payload that " +
                   "decodes to nothing",
        });
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

    var allAscii = true;
    for (var ai = 0; ai < label.length; ai += 1) {
      if (label.charCodeAt(ai) > 0x7F) { allAscii = false; break; }
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
      if (opts.punycodePolicy !== "allow") {
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
function _sanitizeTransform(input) {
  var out = _normalizeIdnaSeparators(input).toLowerCase();
  if (out.charAt(out.length - 1) === ".") out = out.slice(0, -1);
  return out;
}

var INTEGRATION_FIXTURES = gateContract.identifierFixtures("example.com", "192.168.1.1");

var POLICY_ENUM = gateContract.policyVocabulary([
  "ldhPolicy", "punycodePolicy", "mixedScriptPolicy", "specialUsePolicy",
  "ipLiteralPolicy", "wildcardPolicy", "singleLabelPolicy", "underscorePolicy",
  "dgaPolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow, {
  trailingDotPolicy: ["normalize", "audit", "reject"],
});

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
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
    aceLabelsCarryPayload: aceLabelsCarryPayload,
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
