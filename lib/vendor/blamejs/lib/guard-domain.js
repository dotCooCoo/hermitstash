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
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardDomainError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardDomainError.factory;

// ---- RFC 1035 §2.3.4 length caps ----

var LIMIT_LABEL_OCTETS = 63;                                                     // allow:raw-byte-literal — RFC 1035 §2.3.4
var LIMIT_DOMAIN_OCTETS = 253;                                                   // allow:raw-byte-literal — RFC 1035 §2.3.4 (255 wire minus length prefixes)

// ---- Static patterns (built from explicit codepoint tables) ----

// LDH label — letters / digits / hyphens, with leading-and-trailing
// hyphen rejection enforced separately. Length checked separately.
var LDH_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;

// Service-prefix label per RFC 8552 — `_dmarc`, `_acme-challenge`, …
var SERVICE_LABEL_RE = /^_[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;

// Punycode A-label prefix.
var PUNYCODE_LABEL_RE = /^xn--/i;

// Bare `xn--` with no payload after — malformed A-label.
var BARE_XN_RE = /^xn--$/i;

// Wildcard label — `*` alone in any label position.
var WILDCARD_LABEL_RE = /^\*$/;

// IPv4 decimal-dotted form.
var IPV4_DOTTED_RE = /^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;

// Looser IPv4 detection — every dot-segment is a numeric form
// (decimal, octal with leading 0, or hex with 0x prefix), or the whole
// input is a long-decimal / long-hex (no dots). Catches the parser-
// permissive forms `0177.0.0.1` (octal), `0xC0.0xA8.0x01.0x01` (hex),
// `3232235777` (long-decimal), `0xC0A80101` (long-hex).
//
// Detection requires at least one digit AND that every dot-segment is a
// number, so labels like `a.b` (purely alphabetic) don't false-positive
// as IPv4 even though their codepoints overlap the hex alphabet.
var IPV4_NUMERIC_SEGMENT_RE = /^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/;
function _looksLikeIpv4Permissive(s) {
  if (!/[0-9]/.test(s)) return false;
  if (IPV4_NUMERIC_SEGMENT_RE.test(s)) {
    // Long-decimal / long-hex without dots, e.g. `3232235777`.
    return s.length > 0 && !/^[0-9]+$/.test(s) ? true :
           // Pure long-decimal — at least 8 digits to count as IPv4
           // representation, otherwise it's a port-shaped number.
           s.length >= 8;                                                        // allow:raw-byte-literal — minimum digits to recognize long-decimal IPv4
  }
  if (s.indexOf(".") === -1) return false;
  var parts = s.split(".");
  if (parts.length !== 4) return false;
  for (var i = 0; i < parts.length; i += 1) {
    if (!IPV4_NUMERIC_SEGMENT_RE.test(parts[i])) return false;
  }
  return true;
}

// IPv6 bracket-literal.
var IPV6_BRACKET_RE = /^\[[0-9a-fA-F:.]+\]$/;

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
  var lower = name.toLowerCase().replace(/\.$/, "");
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
    bidiPolicy:           "reject",
    controlPolicy:        "reject",
    nullBytePolicy:       "reject",
    zeroWidthPolicy:      "reject",
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
    dgaEntropyThreshold:  3.8,                                                   // allow:raw-byte-literal — Shannon entropy bits/char threshold (DGA heuristic)
    dgaMinLabelLen:       12,                                                    // allow:raw-byte-literal — DGA heuristic floor
    maxLabelOctets:       LIMIT_LABEL_OCTETS,
    maxDomainOctets:      LIMIT_DOMAIN_OCTETS,
    maxBytes:             C.BYTES.bytes(2048),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:           "reject",
    controlPolicy:        "reject",
    nullBytePolicy:       "reject",
    zeroWidthPolicy:      "reject",
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
    dgaEntropyThreshold:  3.8,                                                   // allow:raw-byte-literal — Shannon entropy bits/char threshold (DGA heuristic)
    dgaMinLabelLen:       12,                                                    // allow:raw-byte-literal — DGA heuristic floor
    maxLabelOctets:       LIMIT_LABEL_OCTETS,
    maxDomainOctets:      LIMIT_DOMAIN_OCTETS,
    maxBytes:             C.BYTES.bytes(2048),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:           "reject",                                              // BIDI refused at every profile — universal forgery
    controlPolicy:        "reject",                                              // control bytes refused at every profile
    nullBytePolicy:       "reject",                                              // null refused at every profile
    zeroWidthPolicy:      "reject",                                              // zero-width refused at every profile — invisible label-segmentation
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
    dgaEntropyThreshold:  3.8,                                                   // allow:raw-byte-literal — Shannon entropy bits/char threshold (DGA heuristic)
    dgaMinLabelLen:       12,                                                    // allow:raw-byte-literal — DGA heuristic floor
    maxLabelOctets:       LIMIT_LABEL_OCTETS,
    maxDomainOctets:      LIMIT_DOMAIN_OCTETS,
    maxBytes:             C.BYTES.bytes(2048),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardDomainError,
    errCodePrefix:      "domain",
  });
}

// ---- Detection ----

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "domain.bad-input",
              snippet: "domain is not a string" }];
  }

  // Total-length cap (UTF-8 byte count, not codepoint count, per RFC 1035).
  var byteLen = Buffer.byteLength(input, "utf8");
  if (byteLen > opts.maxDomainOctets) {
    issues.push({
      kind: "domain-cap", severity: "high",
      ruleId: "domain.domain-cap",
      snippet: "domain " + byteLen + " octets exceeds " +
               opts.maxDomainOctets + " (RFC 1035 §2.3.4)",
    });
    return issues;                                                               // size cap is structural — abort further checks
  }

  // Codepoint-class threats (BIDI / control / null / zero-width). These
  // are universal-refuse — running them first lets the more specific
  // structural checks operate on a sanitized-or-refused input.
  var charThreats = codepointClass.detectCharThreats(input, opts, "domain");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

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
  if (IPV6_BRACKET_RE.test(name)) {
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
  if (IPV4_DOTTED_RE.test(name) || _looksLikeIpv4Permissive(name)) {
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
    if (WILDCARD_LABEL_RE.test(label)) {                                         // allow:regex-no-length-cap — label bounded by maxLabelOctets above
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
      if (SERVICE_LABEL_RE.test(label)) {                                        // allow:regex-no-length-cap — label bounded by maxLabelOctets above
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
    if (PUNYCODE_LABEL_RE.test(label)) {                                         // allow:regex-no-length-cap — label bounded by maxLabelOctets above
      if (BARE_XN_RE.test(label)) {                                              // allow:regex-no-length-cap — label bounded by maxLabelOctets above
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
      if (!LDH_LABEL_RE.test(label) && opts.ldhPolicy !== "allow") {             // allow:regex-no-length-cap — label bounded by maxLabelOctets above
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
      if (label.charCodeAt(ai) > 0x7F) { allAscii = false; break; }              // allow:raw-byte-literal — ASCII boundary codepoint
    }

    if (allAscii) {
      if (!LDH_LABEL_RE.test(label) && opts.ldhPolicy !== "allow") {             // allow:regex-no-length-cap — label bounded by maxLabelOctets above
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
          label.charAt(3) === "-" && !PUNYCODE_LABEL_RE.test(label)) {
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
 * Inspect a domain-name string and return `{ ok, issues, summary }`.
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
 *   compliance: "hipaa"|"pci-dss"|"gdpr"|"soc2",
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
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLabelOctets", "maxDomainOctets", "maxBytes", "dgaMinLabelLen"],
    "guardDomain.validate", GuardDomainError, "domain.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 ruleId: "domain.bad-input",
                 snippet: "domain is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

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
 *   compliance: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *
 * @example
 *   var safe = b.guardDomain.sanitize("Example.Com.", { profile: "balanced" });
 *   safe;                                              // → "example.com"
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("domain.bad-input", "sanitize requires string input");
  }
  // Critical refuses can't be repaired.
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "domain.refused",
        "guardDomain.sanitize: " + issues[i].snippet);
    }
  }
  // Safe transforms: lowercase ASCII, strip trailing dot.
  var out = input.toLowerCase();
  if (out.charAt(out.length - 1) === ".") out = out.slice(0, -1);
  return out;
}

/**
 * @primitive  b.guardDomain.gate
 * @signature  b.guardDomain.gate(opts?)
 * @since      0.7.41
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardDomain.validate, b.guardDomain.sanitize
 *
 * Build a `b.gateContract` gate that consumes `ctx.identifier` (or
 * `ctx.domain`) and dispatches `serve` (no input or clean) →
 * `audit-only` (warn-only issues) → `refuse` (any critical or high
 * issue). No `sanitize` action — domain canonicalization is
 * caller-driven via `b.guardDomain.sanitize` so an allowlist gate
 * never silently rewrites the operator's stored allowlist key.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliance: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,    // gate identity for audit / observability
 *
 * @example
 *   var domGate = b.guardDomain.gate({ profile: "strict" });
 *   var verdict = await domGate.check({ identifier: "myhost.localhost" });
 *   verdict.action;                                    // → "refuse"
 */
function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardDomain:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      // Identifier-shape ctx — operator passes via ctx.identifier or
      // ctx.domain.
      var identifier = ctx && (ctx.identifier || ctx.domain || "");
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
 * @primitive  b.guardDomain.buildProfile
 * @signature  b.guardDomain.buildProfile(opts)
 * @since      0.7.41
 * @status     stable
 * @related    b.guardDomain.gate, b.guardDomain.compliancePosture
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
 *   var custom = b.guardDomain.buildProfile({
 *     extends: "balanced",
 *     allowedScripts: ["latin"],
 *     punycodePolicy: "reject",
 *   });
 *   custom.punycodePolicy;                             // → "reject"
 *   custom.bidiPolicy;                                 // → "reject"
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardDomain.compliancePosture
 * @signature  b.guardDomain.compliancePosture(name)
 * @since      0.7.41
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardDomain.gate, b.guardDomain.buildProfile
 *
 * Look up a compliance-posture overlay by name (`"hipaa"` /
 * `"pci-dss"` / `"gdpr"` / `"soc2"`). Returns a shallow clone of the
 * posture object — the caller may mutate freely. Throws
 * `GuardDomainError("domain.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardDomain.compliancePosture("hipaa");
 *   posture.specialUsePolicy;                          // → "reject"
 *   posture.forensicSnippetBytes;                      // → 256
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "domain");
}

var _domainRulePacks = gateContract.makeRulePackLoader(GuardDomainError, "domain");
/**
 * @primitive  b.guardDomain.loadRulePack
 * @signature  b.guardDomain.loadRulePack(pack)
 * @since      0.7.41
 * @status     stable
 * @related    b.guardDomain.gate
 *
 * Register an operator-supplied rule pack with the guard-domain
 * registry. The pack is identified by `pack.id` (non-empty string)
 * and stored for later inspection / dispatch by gates that opt in
 * via `opts.rulePackId`. Returns the pack object unchanged on
 * success; throws `GuardDomainError("domain.bad-opt")` when `pack`
 * is missing or `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardDomain.loadRulePack({
 *     id: "tenant-corp-only",
 *     rules: [
 *       { id: "tenant-suffix", severity: "high",
 *         detect: function (d) { return !/\.example\.com$/i.test(d); },
 *         reason: "tenant policy: only example.com suffixes permitted" },
 *     ],
 *   });
 *   pack.id;                                           // → "tenant-corp-only"
 */
var loadRulePack = _domainRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "domain",
  KIND:                "identifier",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:        "identifier",
    benignBytes: Buffer.from("example.com", "utf8"),
    // Hostile: dotted-decimal IPv4 (CVE-2021-22931 class) — every
    // profile refuses (allowlist-bypass via DNS rebinding).
    hostileBytes: Buffer.from("192.168.1.1", "utf8"),
    benignIdentifier:  "example.com",
    hostileIdentifier: "192.168.1.1",
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
  GuardDomainError:    GuardDomainError,
};
