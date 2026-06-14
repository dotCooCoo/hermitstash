"use strict";
/**
 * @module b.guardEmail
 * @nav    Guards
 * @title  Guard Email
 *
 * @intro
 *   RFC 822 / 5322 single-address validator + RFC 5322 message gate
 *   with header-injection defense, domain-side IDN / Punycode
 *   handling, mixed-script confusable detection, label length caps,
 *   IP-literal denial, and sub-address handling.
 *
 *   Two entry shapes:
 *     - `validateAddress(addr, opts)` — single mailbox (RFC 5321
 *       atext@DNS-domain). Caps RFC 5321 §4.5.3.1 local-part 64 /
 *       domain 255 / address 320. Flags multi-`@`, IP literals,
 *       Punycode, mixed-script confusables, and codepoint-class
 *       threats (BIDI / control / null / zero-width).
 *
 *   Scope of Unicode handling: the DOMAIN side recognizes IDN /
 *   Punycode (`xn--`) labels and mixed-script confusables, gated by
 *   `allowedScripts` (RFC 5890 / RFC 5891). The LOCAL part is
 *   ASCII atext only (RFC 5321 §4.1.2 / RFC 5322 §3.2.3) — a unicode
 *   mailbox (RFC 6531 SMTPUTF8 / EAI) is NOT accepted and surfaces as
 *   an `address-syntax` issue. This is deliberate: a unicode
 *   local-part widens the homograph / confusable attack surface
 *   beyond the domain (where registry IDN policy and Punycode
 *   normalization apply) into the unregulated mailbox name, where no
 *   equivalent normalization authority exists. RFC 6531 local-part
 *   acceptance re-opens behind an explicit `allowUnicodeLocalPart`
 *   opt-in when operator demand for genuine EAI mailboxes lands;
 *   until then the conservative ASCII contract holds by default.
 *     - `validateMessage(rfc822, opts)` — full RFC 5322 message.
 *       Splits header section, unfolds folded headers, walks every
 *       single-line header for embedded CR/LF, drives address checks
 *       on `From` / `To` / `Cc` / `Bcc` / `Reply-To` / `Sender` /
 *       `Return-Path`, and scans the message body for SMTP-smuggling
 *       (bare-CR / bare-LF / `\r?\n.\r?\nMAIL FROM:` class —
 *       CVE-2023-51764 / 51765 / 51766) plus RFC 5322 §2.1.1 line cap.
 *
 *   Profiles ship in pairs:
 *     - `strict` / `balanced` / `permissive` — operator scope.
 *     - `hipaa` / `pci-dss` / `gdpr` / `soc2` — compliance posture.
 *
 *   Header injection, SMTP smuggling, multi-`@`, and null-byte are
 *   `reject` at every profile — universally exploitable, no
 *   sanitization is safe.
 *
 * @card
 *   RFC 822 / 5322 single-address validator + RFC 5322 message gate with header-injection defense, domain-side IDN / Punycode and mixed-script confusable detection (ASCII-only local-part), label length caps, IP-literal denial, and sub-address handling.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardEmailError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardEmailError.factory;

// ---- RFC 5321 / 5322 limits ----

var LIMIT_LOCAL_PART = 64;                                                       // RFC 5321 §4.5.3.1.1
var LIMIT_DOMAIN     = 255;                                                      // RFC 5321 §4.5.3.1.2
var LIMIT_ADDRESS    = 320;                                                      // RFC 5321 sum (64 + 1 + 255)
var LIMIT_LINE       = 998;                                                      // RFC 5322 §2.1.1 maximum line length

// ---- Source-level threat detectors ----

// Bare CR or bare LF outside CRLF pair — SMTP smuggling vector class.
// Detection MUST scan the full message bytes; a bare LF in the body
// can let an attacker smuggle a follow-on `\r\n.\r\n` sequence past
// the upstream MTA's end-of-data check.
function _scanBareLineEndings(input) {
  var bareCr = false;
  var bareLf = false;
  for (var i = 0; i < input.length; i += 1) {
    var c = input.charCodeAt(i);
    if (c === 13) {                                                              // CR
      var next = i + 1 < input.length ? input.charCodeAt(i + 1) : -1;
      if (next !== 10) bareCr = true;                                            // LF
    } else if (c === 10) {                                                       // LF
      var prev = i > 0 ? input.charCodeAt(i - 1) : -1;
      if (prev !== 13) bareLf = true;                                            // CR
    }
    if (bareCr && bareLf) break;
  }
  return { bareCr: bareCr, bareLf: bareLf };
}

// Smuggled SMTP verbs after a bare line ending — the canonical
// SEC Consult / smtpsmuggling.com pattern.
var SMUGGLED_VERB_RE = /(?:\r(?!\n)|(?<!\r)\n)\.?\s*(?:MAIL FROM|RCPT TO|DATA|EHLO|HELO|RSET|QUIT)\b/i;

// CRLF in any single-line header value — header injection.
function _hasCrlfInHeaderValue(value) {
  for (var i = 0; i < value.length; i += 1) {
    var c = value.charCodeAt(i);
    if (c === 13 || c === 10) return true;                                       // CR or LF in header value
  }
  return false;
}

// Strict address regex — RFC 5321 plus a small, conservative subset of
// 5322 atext. Domains MUST be DNS-shaped (label syntax).
//
// allow:dynamic-regex — built once at module load from the static
// atext class; no runtime input.
// Local-part regex is permissive on length so the explicit cap check
// can produce a useful local-part-cap issue (instead of failing the
// regex first and surfacing address-syntax). RFC 5321 cap is enforced
// downstream via opts.maxLocalPartBytes.
//
// The local-part class is ASCII atext only — the printable-ASCII set
// of RFC 5321 §4.1.2 / RFC 5322 §3.2.3. A unicode (non-ASCII)
// local-part per RFC 6531 (SMTPUTF8 / EAI) is intentionally NOT
// matched: it fails this regex and surfaces as an `address-syntax`
// issue. Domain-side Unicode is handled separately (Punycode + mixed-
// script detection, gated by allowedScripts). Keeping the local-part
// ASCII avoids extending homograph / confusable exposure into the
// mailbox name, which has no registry-level normalization authority.
var _LOCAL = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+";
var _LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
var _DOMAIN = "(?:" + _LABEL + "(?:\\." + _LABEL + ")+)";
// allow:dynamic-regex — built once at module load from the static
// _LOCAL + _DOMAIN literal strings; no runtime input.
var ADDRESS_RE = new RegExp("^(" + _LOCAL + ")@(" + _DOMAIN + ")$");

// IP-literal (square-bracketed IPv4 / IPv6). Allowed-or-refused via opt.
var IP_LITERAL_RE = /^[^@]+@\[[^\]]+\]$/;

// Comment syntax in address — `(comment)` per RFC 5322. Most receivers
// reject; we flag.
var ADDRESS_COMMENT_RE = /[()]/;

// Punycode prefix on a domain label.
var PUNYCODE_LABEL_RE = /(?:^|\.)xn--/i;

// Mixed-script detection — flag any domain with characters from more
// than one of: Latin / Cyrillic / Greek / Armenian / Cherokee. The
// catalog is conservative; operators with legitimate non-Latin domains
// register the script via `allowedScripts: ["latin", "cyrillic"]`.
//
// Codepoints from Unicode 15.1 official script ranges (via codepoint-
// class.js conventions — keep numeric, no literal characters).
var SCRIPT_RANGES = {
  latin:    [[0x0041, 0x005a], [0x0061, 0x007a],
             [0x00c0, 0x024f], [0x1e00, 0x1eff]],                                // Unicode script ranges
  cyrillic: [[0x0400, 0x04ff], [0x0500, 0x052f]],                                // Unicode Cyrillic + Cyrillic Supplement
  greek:    [[0x0370, 0x03ff], [0x1f00, 0x1fff]],                                // Unicode Greek + Greek Extended
  armenian: [[0x0530, 0x058f]],                                                  // Unicode Armenian
  cherokee: [[0x13a0, 0x13ff], [0xab70, 0xabbf]],                                // Unicode Cherokee + Cherokee Supplement
};

function _scriptFor(cp) {
  var keys = Object.keys(SCRIPT_RANGES);
  for (var i = 0; i < keys.length; i += 1) {
    var ranges = SCRIPT_RANGES[keys[i]];
    for (var j = 0; j < ranges.length; j += 1) {
      if (cp >= ranges[j][0] && cp <= ranges[j][1]) return keys[i];
    }
  }
  return null;                                                                   // unknown script — not a confusable
}

function _detectMixedScripts(domain, allowedScripts) {
  var seen = {};
  for (var i = 0; i < domain.length; i += 1) {
    var script = _scriptFor(domain.charCodeAt(i));
    if (script === null) continue;
    seen[script] = true;
  }
  var scripts = Object.keys(seen);
  if (scripts.length <= 1) return null;
  var disallowed = [];
  for (var k = 0; k < scripts.length; k += 1) {
    if (!allowedScripts || allowedScripts.indexOf(scripts[k]) === -1) {
      disallowed.push(scripts[k]);
    }
  }
  return scripts.length > 1 && disallowed.length > 0 ? scripts : null;
}

// Header fields the spec treats as single-line (no folded CR/LF).
var SINGLE_LINE_HEADERS = ["from", "to", "cc", "bcc", "reply-to", "sender",
                           "subject", "message-id", "in-reply-to", "references",
                           "date", "return-path"];

// Display-name + envelope split.
var DISPLAY_PHRASE_ANGLE_RE = /^\s*(.*?)\s*<\s*([^>]+)\s*>\s*$/;

function _parseAddressLine(line) {
  // Returns { display, envelope } — display may be empty.
  var m = line.match(DISPLAY_PHRASE_ANGLE_RE);
  if (m) return { display: m[1].replace(/^"|"$/g, ""), envelope: m[2] };
  return { display: "", envelope: line.trim() };
}

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    crlfHeaderInjectionPolicy:    "reject",
    smtpSmugglingPolicy:          "reject",
    bareCrPolicy:                 "reject",
    bareLfPolicy:                 "reject",
    multiAtPolicy:                "reject",
    ipLiteralPolicy:              "reject",
    addressCommentPolicy:         "reject",
    punycodePolicy:               "reject",                                      // strict refuses Punycode — operators with legit IDN traffic opt up
    mixedScriptPolicy:            "reject",
    displayNameSpoofPolicy:       "reject",
    bomPolicy:                    "reject",
    bidiPolicy:                   "reject",
    controlPolicy:                "reject",
    nullBytePolicy:               "reject",
    zeroWidthPolicy:              "reject",
    allowedScripts:               ["latin"],
    maxLocalPartBytes:            LIMIT_LOCAL_PART,
    maxDomainBytes:               LIMIT_DOMAIN,
    maxAddressBytes:              LIMIT_ADDRESS,
    maxHeaderLineBytes:           LIMIT_LINE,
    maxHeaders:                   128,                                           // header count cap
    maxBytes:                     C.BYTES.mib(8),
  },
  "balanced": {
    crlfHeaderInjectionPolicy:    "reject",
    smtpSmugglingPolicy:          "reject",
    bareCrPolicy:                 "audit",
    bareLfPolicy:                 "audit",
    multiAtPolicy:                "reject",
    ipLiteralPolicy:              "audit",
    addressCommentPolicy:         "audit",
    punycodePolicy:               "audit",
    mixedScriptPolicy:            "reject",
    displayNameSpoofPolicy:       "audit",
    bomPolicy:                    "strip",
    bidiPolicy:                   "strip",
    controlPolicy:                "strip",
    nullBytePolicy:               "strip",
    zeroWidthPolicy:              "strip",
    allowedScripts:               ["latin", "cyrillic", "greek"],
    maxLocalPartBytes:            LIMIT_LOCAL_PART,
    maxDomainBytes:               LIMIT_DOMAIN,
    maxAddressBytes:              LIMIT_ADDRESS,
    maxHeaderLineBytes:           LIMIT_LINE,
    maxHeaders:                   512,                                           // header count cap
    maxBytes:                     C.BYTES.mib(32),
  },
  "permissive": {
    crlfHeaderInjectionPolicy:    "reject",                                      // header injection refused at every profile — universal smuggling vector
    smtpSmugglingPolicy:          "reject",                                      // SMTP smuggling refused at every profile — universal vector
    bareCrPolicy:                 "audit",
    bareLfPolicy:                 "audit",
    multiAtPolicy:                "reject",                                      // multi-@ refused at every profile — RFC 5322 violates
    ipLiteralPolicy:              "allow",
    addressCommentPolicy:         "audit",
    punycodePolicy:               "audit",
    mixedScriptPolicy:            "audit",
    displayNameSpoofPolicy:       "audit",
    bomPolicy:                    "audit",
    bidiPolicy:                   "audit",
    controlPolicy:                "strip",
    nullBytePolicy:               "reject",                                      // null bytes refused at every profile
    zeroWidthPolicy:              "audit",
    allowedScripts:               null,                                          // permissive — allow every Unicode script
    maxLocalPartBytes:            LIMIT_LOCAL_PART,
    maxDomainBytes:               LIMIT_DOMAIN,
    maxAddressBytes:              LIMIT_ADDRESS,
    maxHeaderLineBytes:           LIMIT_LINE,
    maxHeaders:                   2048,                                          // header count cap
    maxBytes:                     C.BYTES.mib(128),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode:          "enforce",
  maxRuntimeMs:  C.TIME.seconds(10),
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "gdpr": Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "soc2": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardEmailError,
    errCodePrefix:      "email",
  });
}

// ---- Address validation ----

function _detectAddressIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              snippet: "address is not a string" }];
  }

  // Total-address length cap.
  if (input.length > opts.maxAddressBytes) {
    issues.push({
      kind: "address-cap", severity: "high", ruleId: "email.address-cap",
      snippet: "address " + input.length + " bytes exceeds maxAddressBytes " +
               opts.maxAddressBytes,
    });
  }

  // Multi-@ check — count any unquoted @ outside square brackets.
  var atCount = 0;
  var inQuote = false;
  var inBrack = false;
  for (var i = 0; i < input.length; i += 1) {
    var c = input.charAt(i);
    if (c === '"') inQuote = !inQuote;
    else if (c === "[" && !inQuote) inBrack = true;
    else if (c === "]" && !inQuote) inBrack = false;
    else if (c === "@" && !inQuote && !inBrack) atCount += 1;
  }
  if (atCount !== 1 && opts.multiAtPolicy !== "allow") {
    issues.push({
      kind: "multi-at", severity: "critical",
      ruleId: "email.multi-at",
      snippet: "address has " + atCount + " '@' characters; expected exactly 1",
    });
    return issues;                                                               // can't continue without one envelope split
  }

  // Comment syntax — `(comment)` per RFC 5322; most receivers reject.
  if (opts.addressCommentPolicy !== "allow" && ADDRESS_COMMENT_RE.test(input)) { // allow:regex-no-length-cap — input bounded by maxAddressBytes
    issues.push({
      kind: "address-comment",
      severity: opts.addressCommentPolicy === "reject" ? "high" : "warn",
      ruleId: "email.address-comment",
      snippet: "address contains '(' or ')' — RFC 5322 comment syntax, " +
               "smuggling-prone vs RFC 5321 receivers",
    });
  }

  // IP-literal check.
  if (IP_LITERAL_RE.test(input)) {                                               // allow:regex-no-length-cap — input bounded by maxAddressBytes
    if (opts.ipLiteralPolicy !== "allow") {
      issues.push({
        kind: "ip-literal",
        severity: opts.ipLiteralPolicy === "reject" ? "high" : "warn",
        ruleId: "email.ip-literal",
        snippet: "address uses IP literal `[...]` — bypasses DNS / DMARC alignment",
      });
    }
  } else {
    // Length-aware cap checks BEFORE syntax-regex. The regex enforces
    // RFC 5321 label-length (63) and atext shape; oversized inputs would
    // fail the regex first and bury the more useful cap diagnosis.
    var atIdx = input.lastIndexOf("@");
    var localPart = atIdx === -1 ? input : input.slice(0, atIdx);
    var domain = atIdx === -1 ? "" : input.slice(atIdx + 1);

    if (localPart.length > opts.maxLocalPartBytes) {
      issues.push({
        kind: "local-part-cap", severity: "high",
        ruleId: "email.local-part-cap",
        snippet: "local-part " + localPart.length + " bytes exceeds " +
                 opts.maxLocalPartBytes + " (RFC 5321 §4.5.3.1.1)",
      });
    }
    if (domain.length > opts.maxDomainBytes) {
      issues.push({
        kind: "domain-cap", severity: "high",
        ruleId: "email.domain-cap",
        snippet: "domain " + domain.length + " bytes exceeds " +
                 opts.maxDomainBytes + " (RFC 5321 §4.5.3.1.2)",
      });
    }

    // Punycode / IDN — flag operator's choice. Runs against the lexed
    // domain so non-ASCII codepoints (which fail the strict ASCII regex)
    // still surface this issue.
    if (opts.punycodePolicy !== "allow" && PUNYCODE_LABEL_RE.test(domain)) {     // allow:regex-no-length-cap — domain bounded by maxDomainBytes
      issues.push({
        kind: "punycode-domain",
        severity: opts.punycodePolicy === "reject" ? "high" : "warn",
        ruleId: "email.punycode-domain",
        snippet: "domain uses IDN/Punycode (`xn--` label) — may be " +
                 "homograph-spoofing",
      });
    }

    // Mixed-script confusable detection in domain. Runs on the lexed
    // domain (post-@ split) so non-ASCII codepoints surface here even
    // when they fail the strict ASCII syntax regex below.
    var mixed = _detectMixedScripts(domain, opts.allowedScripts);
    if (mixed && opts.mixedScriptPolicy !== "allow") {
      issues.push({
        kind: "mixed-script-domain",
        severity: opts.mixedScriptPolicy === "reject" ? "critical" : "high",
        ruleId: "email.mixed-script-domain",
        snippet: "domain mixes scripts (" + mixed.join(", ") + ") — " +
                 "IDN homograph spoofing class",
      });
    }

    // If we found a cap issue, skip the strict-ASCII regex (over-cap
    // input fails it anyway and the cap diagnosis is more actionable).
    var hasCap = issues.some(function (i) {
      return i.kind === "local-part-cap" || i.kind === "domain-cap";
    });
    if (!hasCap) {
      var match = input.match(ADDRESS_RE);                                       // allow:regex-no-length-cap — input bounded by maxAddressBytes
      if (!match) {
        // The strict regex caught a non-ASCII or shape issue. If we've
        // already surfaced a punycode / mixed-script issue (the actual
        // semantic threat), don't pile on with address-syntax — the
        // operator gets the real diagnosis.
        var hasIdnIssue = issues.some(function (i) {
          return i.kind === "punycode-domain" || i.kind === "mixed-script-domain";
        });
        if (!hasIdnIssue) {
          issues.push({
            kind: "address-syntax", severity: "high",
            ruleId: "email.address-syntax",
            snippet: "address does not match RFC 5321 atext@DNS-domain shape",
          });
        }
      }
    }
  }

  // Codepoint-class threats inside the address.
  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "email"));

  return issues;
}

/**
 * @primitive b.guardEmail.validateAddress
 * @signature b.guardEmail.validateAddress(input, opts)
 * @since     0.7.17
 * @status    stable
 * @related   b.guardEmail.validateMessage, b.guardEmail.gate, b.guardEmail.sanitize
 *
 * Validate a single email address against RFC 5321 atext@DNS-domain
 * shape with the active profile's policies. Returns `{ ok, issues }`;
 * `issues[]` carries `kind` / `severity` / `ruleId` / `snippet` for
 * every detector that fired. Never throws on input — bad shapes
 * surface as `bad-input` issues so the caller can route on them.
 *
 * Detectors run in order: total-address cap, multi-`@` count,
 * RFC 5322 comment syntax, IP literal `[...]`, local-part / domain
 * caps, Punycode (`xn--`) labels, mixed-script confusables (Latin /
 * Cyrillic / Greek / Armenian / Cherokee), strict-ASCII regex shape,
 * and codepoint-class threats (BIDI / null / control / zero-width).
 *
 * The local-part is validated as ASCII atext only (RFC 5321 §4.1.2 /
 * RFC 5322 §3.2.3). A unicode local-part (RFC 6531 SMTPUTF8 / EAI)
 * is rejected as an `address-syntax` issue — keeping the mailbox name
 * ASCII bounds homograph / confusable exposure to the domain side,
 * where Punycode normalization and `allowedScripts` gating apply.
 * RFC 6531 local-part acceptance re-opens behind a future explicit
 * `allowUnicodeLocalPart` opt-in on operator demand. Domain-side
 * IDN / Punycode and mixed-script handling are already supported.
 *
 * @opts
 *   profile:                 "strict" | "balanced" | "permissive",
 *   compliancePosture:       "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   multiAtPolicy:           "reject" | "audit" | "allow",
 *   ipLiteralPolicy:         "reject" | "audit" | "allow",
 *   addressCommentPolicy:    "reject" | "audit" | "allow",
 *   punycodePolicy:          "reject" | "audit" | "allow",
 *   mixedScriptPolicy:       "reject" | "audit" | "allow",
 *   allowedScripts:          string[] | null,
 *   maxLocalPartBytes:       number,
 *   maxDomainBytes:          number,
 *   maxAddressBytes:         number,
 *
 * @example
 *   var guardEmail = require("./lib/guard-email");
 *   var rv = guardEmail.validateAddress("alice@example.com",
 *     { profile: "strict" });
 *   rv.ok;                  // → true
 *   rv.issues.length;       // → 0
 *
 *   var bad = guardEmail.validateAddress("user@[10.0.0.1]",
 *     { profile: "strict" });
 *   bad.ok;                 // → false
 *   bad.issues[0].kind;     // → "ip-literal"
 */
function validateAddress(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLocalPartBytes", "maxDomainBytes", "maxAddressBytes",
     "maxHeaderLineBytes", "maxHeaders", "maxBytes"],
    "guardEmail.validateAddress", GuardEmailError, "email.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "address is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectAddressIssues(input, opts));
}

// ---- Message validation (full RFC 822 / 5322) ----

function _detectMessageIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              snippet: "input is not a string" }];
  }
  if (input.length > opts.maxBytes) {
    return [{ kind: "too-large", severity: "high",
              ruleId: "email.too-large",
              snippet: "input " + input.length +
                       " bytes exceeds maxBytes " + opts.maxBytes }];
  }

  // BOM at start of message — header-injection prelude.
  if (opts.bomPolicy !== "allow") {
    if (input.charCodeAt(0) === 0xfeff) {                                        // Unicode BOM
      issues.push({
        kind: "bom",
        severity: opts.bomPolicy === "reject" ? "high" : "warn",
        ruleId: "email.bom",
        snippet: "message starts with BOM (U+FEFF) — header-parser confusion",
      });
    }
  }

  // SMTP smuggling — bare CR / bare LF + smuggled-verb scan.
  var bare = _scanBareLineEndings(input);
  if (bare.bareCr && opts.bareCrPolicy !== "allow") {
    issues.push({
      kind: "bare-cr",
      severity: opts.bareCrPolicy === "reject" ? "critical" : "warn",
      ruleId: "email.bare-cr",
      snippet: "message contains bare CR (not part of CRLF) — SMTP " +
               "smuggling vector class (CVE-2023-51764)",
    });
  }
  if (bare.bareLf && opts.bareLfPolicy !== "allow") {
    issues.push({
      kind: "bare-lf",
      severity: opts.bareLfPolicy === "reject" ? "critical" : "warn",
      ruleId: "email.bare-lf",
      snippet: "message contains bare LF (not part of CRLF) — SMTP " +
               "smuggling vector class (CVE-2023-51765 / CVE-2023-51766)",
    });
  }
  if (opts.smtpSmugglingPolicy !== "allow" && SMUGGLED_VERB_RE.test(input)) {    // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "smtp-smuggling", severity: "critical",
      ruleId: "email.smtp-smuggling",
      snippet: "embedded SMTP verb after bare CR/LF — smuggling vector " +
               "(SEC Consult / smtpsmuggling.com class)",
    });
  }

  // Split header section from body.
  var headerEnd = input.indexOf("\r\n\r\n");
  if (headerEnd === -1) headerEnd = input.indexOf("\n\n");
  var headerSection = headerEnd === -1 ? input : input.slice(0, headerEnd);

  // Per-line cap + count cap.
  var lines = headerSection.split(/\r?\n/);
  if (lines.length > opts.maxHeaders) {
    issues.push({
      kind: "header-count-cap", severity: "high",
      ruleId: "email.header-count-cap",
      snippet: "header count " + lines.length + " exceeds maxHeaders " +
               opts.maxHeaders,
    });
  }
  for (var li = 0; li < lines.length; li += 1) {
    if (lines[li].length > opts.maxHeaderLineBytes) {
      issues.push({
        kind: "header-line-cap", severity: "high",
        ruleId: "email.header-line-cap",
        snippet: "header line " + (li + 1) + " is " + lines[li].length +
                 " bytes (RFC 5322 §2.1.1 limit " + opts.maxHeaderLineBytes + ")",
      });
      break;
    }
  }

  // Walk single-line headers checking for embedded CRLF + display-name
  // spoofing.
  var unfolded = _unfoldHeaders(lines);
  for (var hi = 0; hi < unfolded.length; hi += 1) {
    var entry = unfolded[hi];
    var name = entry.name.toLowerCase();
    if (SINGLE_LINE_HEADERS.indexOf(name) === -1) continue;

    // CRLF in single-line header value.
    if (opts.crlfHeaderInjectionPolicy !== "allow" &&
        _hasCrlfInHeaderValue(entry.value)) {
      issues.push({
        kind: "crlf-header-injection", severity: "critical",
        ruleId: "email.crlf-header-injection",
        snippet: "header `" + entry.name + "` contains CR/LF — header " +
                 "injection vector (smuggle From/Bcc/body)",
      });
    }

    // Address-bearing headers — run address checks on each address.
    if (name === "from" || name === "to" || name === "cc" ||
        name === "bcc" || name === "reply-to" || name === "sender" ||
        name === "return-path") {
      var addrIssues = _checkAddressHeaderValue(entry.value, opts, entry.name);
      for (var ai = 0; ai < addrIssues.length; ai += 1) {
        issues.push(addrIssues[ai]);
      }
    }
  }

  // Codepoint-class threats in the full message.
  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "email"));

  return issues;
}

function _unfoldHeaders(lines) {
  var out = [];
  var current = null;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line === "") { current = null; continue; }
    if (current && (line.charAt(0) === " " || line.charAt(0) === "\t")) {
      current.value += " " + line.replace(/^\s+/, "");
      continue;
    }
    var colonAt = line.indexOf(":");
    if (colonAt === -1) { current = null; continue; }
    current = {
      name:  line.slice(0, colonAt).trim(),
      value: line.slice(colonAt + 1).replace(/^\s+/, ""),
    };
    out.push(current);
  }
  return out;
}

function _splitAddressList(value) {
  // Split on commas outside angle brackets and quoted strings.
  var parts = [];
  var depth = 0;
  var inQuote = false;
  var start = 0;
  for (var i = 0; i < value.length; i += 1) {
    var c = value.charAt(i);
    if (c === '"' && (i === 0 || value.charAt(i - 1) !== "\\")) inQuote = !inQuote;
    else if (!inQuote && c === "<") depth += 1;
    else if (!inQuote && c === ">") depth -= 1;
    else if (!inQuote && depth === 0 && c === ",") {
      parts.push(value.slice(start, i).trim());
      start = i + 1;
    }
  }
  if (start < value.length) parts.push(value.slice(start).trim());
  return parts.filter(function (s) { return s.length > 0; });
}

function _checkAddressHeaderValue(value, opts, headerName) {
  var issues = [];
  var parts = _splitAddressList(value);
  for (var p = 0; p < parts.length; p += 1) {
    var parsed = _parseAddressLine(parts[p]);
    var addrIssues = _detectAddressIssues(parsed.envelope, opts);
    for (var k = 0; k < addrIssues.length; k += 1) {
      var iss = Object.assign({}, addrIssues[k], {
        snippet: headerName + ": " + addrIssues[k].snippet,
      });
      issues.push(iss);
    }
    // Display-name spoofing: display contains an `@` that does NOT match
    // the envelope domain.
    if (parsed.display && parsed.display.indexOf("@") !== -1 &&
        opts.displayNameSpoofPolicy !== "allow") {
      var atIdx = parsed.envelope.lastIndexOf("@");
      var envDomain = atIdx === -1 ? "" : parsed.envelope.slice(atIdx + 1);
      var displayHasDomain = parsed.display.toLowerCase().indexOf(envDomain.toLowerCase()) !== -1;
      if (!displayHasDomain) {
        issues.push({
          kind: "display-name-spoof",
          severity: opts.displayNameSpoofPolicy === "reject" ? "critical" : "high",
          ruleId: "email.display-name-spoof",
          snippet: headerName + ": display name `" +
                   parsed.display.slice(0, 64) + "` includes an @-address that " + // snippet truncation
                   "doesn't match the envelope domain `" + envDomain + "`",
        });
      }
    }
  }
  return issues;
}

/**
 * @primitive b.guardEmail.validateMessage
 * @signature b.guardEmail.validateMessage(input, opts)
 * @since     0.7.17
 * @status    stable
 * @related   b.guardEmail.validateAddress, b.guardEmail.gate, b.guardEmail.sanitize
 *
 * Validate a complete RFC 5322 message (headers + body) against the
 * active profile. Splits the header section, unfolds folded
 * continuation lines, walks every single-line header for embedded
 * CR/LF (header-injection class), and runs `validateAddress` on each
 * envelope under address-bearing headers (`From` / `To` / `Cc` /
 * `Bcc` / `Reply-To` / `Sender` / `Return-Path`). Body is scanned
 * for SMTP-smuggling vectors (bare CR / bare LF / smuggled
 * `MAIL FROM:` after a bare line ending — CVE-2023-51764 / 51765 /
 * 51766 class). Caps RFC 5322 §2.1.1 998-byte line, configurable
 * header count, and total `maxBytes`.
 *
 * @opts
 *   profile:                       "strict" | "balanced" | "permissive",
 *   compliancePosture:             "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   crlfHeaderInjectionPolicy:     "reject" | "audit" | "allow",
 *   smtpSmugglingPolicy:           "reject" | "audit" | "allow",
 *   bareCrPolicy:                  "reject" | "audit" | "allow",
 *   bareLfPolicy:                  "reject" | "audit" | "allow",
 *   displayNameSpoofPolicy:        "reject" | "audit" | "allow",
 *   bomPolicy:                     "reject" | "audit" | "strip" | "allow",
 *   maxHeaderLineBytes:            number,
 *   maxHeaders:                    number,
 *   maxBytes:                      number,
 *
 * @example
 *   var guardEmail = require("./lib/guard-email");
 *   var msg = "From: alice@example.com\r\n" +
 *             "To: bob@example.com\r\n" +
 *             "Subject: hello\r\n" +
 *             "Date: Mon, 5 May 2026 10:00:00 +0000\r\n\r\n" +
 *             "Hello.\r\n";
 *   var rv = guardEmail.validateMessage(msg, { profile: "strict" });
 *   rv.ok;                  // → true
 *
 *   // Header injection: a CRLF inside the From value forges a Bcc.
 *   var bad = "From: alice@example.com\r\nBcc: leak@evil\r\n" +
 *             "To: bob@example.com\r\nSubject: hi\r\n\r\nbody\r\n";
 *   var injected = guardEmail.validateMessage(bad, { profile: "strict" });
 *   injected.ok;            // → true (well-formed; injected-line is its own header)
 */
function validateMessage(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLocalPartBytes", "maxDomainBytes", "maxAddressBytes",
     "maxHeaderLineBytes", "maxHeaders", "maxBytes"],
    "guardEmail.validateMessage", GuardEmailError, "email.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "input is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectMessageIssues(input, opts));
}

/**
 * @primitive b.guardEmail.validate
 * @signature b.guardEmail.validate(input, opts)
 * @since     0.7.17
 * @status    stable
 * @related   b.guardEmail.validateAddress, b.guardEmail.validateMessage
 *
 * Auto-routing entry: a string with no newline AND no `:` is treated
 * as a single address (delegates to `validateAddress`); otherwise the
 * input is treated as a full RFC 5322 message (delegates to
 * `validateMessage`). Operators who want a fixed shape — never the
 * heuristic — call the specific entry directly.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var guardEmail = require("./lib/guard-email");
 *   guardEmail.validate("alice@example.com",
 *     { profile: "strict" }).ok;          // → true
 *
 *   var msg = "From: a@example.com\r\nTo: b@example.com\r\n" +
 *             "Subject: x\r\nDate: Mon, 5 May 2026 10:00:00 +0000\r\n\r\nhi\r\n";
 *   guardEmail.validate(msg,
 *     { profile: "strict" }).ok;          // → true
 */
function validate(input, opts) {
  if (typeof input === "string" && input.indexOf("\n") === -1 &&
      input.indexOf(":") === -1) {
    return validateAddress(input, opts);
  }
  return validateMessage(input, opts);
}

/**
 * @primitive b.guardEmail.sanitize
 * @signature b.guardEmail.sanitize(input, opts)
 * @since     0.7.17
 * @status    stable
 * @related   b.guardEmail.validate, b.guardEmail.gate
 *
 * Best-effort sanitize for email content. THROWS on critical-severity
 * issues (SMTP smuggling / CRLF header injection / multi-`@` /
 * mixed-script confusable / null byte) — these have no safe
 * sanitization. Lower-severity codepoint-class threats (BIDI / zero-
 * width / control / BOM) are stripped per the active profile. Never
 * silently drops a smuggling vector: the caller either gets
 * sanitized text or a thrown `GuardEmailError`.
 *
 * @opts
 *   profile:               "strict" | "balanced" | "permissive",
 *   compliancePosture:     "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   bidiPolicy:            "reject" | "audit" | "strip" | "allow",
 *   controlPolicy:         "reject" | "audit" | "strip" | "allow",
 *   zeroWidthPolicy:       "reject" | "audit" | "strip" | "allow",
 *
 * @example
 *   var guardEmail = require("./lib/guard-email");
 *   // CRLF in the From value is a header-injection vector — sanitize
 *   // refuses rather than silently dropping the bytes.
 *   var hostile = "From: alice@example.com\rBcc: leak@evil\r\n" +
 *                 "To: bob@example.com\r\nSubject: hi\r\n\r\nbody\r\n";
 *   var threw = false;
 *   try { guardEmail.sanitize(hostile, { profile: "strict" }); }
 *   catch (e) { threw = (e.code || "").indexOf("email.") === 0; }
 *   threw;                      // → true
 *
 *   // Benign input with a stray BIDI override is stripped under balanced.
 *   var clean = guardEmail.sanitize("hello world",
 *     { profile: "balanced" });
 *   clean;                      // → "hello world"
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("email.bad-input", "sanitize requires string input");
  }
  // Critical shapes have no safe sanitization in email — throw on
  // smuggling / CRLF injection / multi-@ / mixed-script.
  var issues = _detectMessageIssues(input, opts);
  gateContract.throwOnRefusalSeverity(issues,
    { errorClass: GuardEmailError, codePrefix: "email", severities: ["critical"] });
  return codepointClass.applyCharStripPolicies(input, opts);
}

/**
 * @primitive b.guardEmail.gate
 * @signature b.guardEmail.gate(opts)
 * @since     0.7.17
 * @status    stable
 * @related   b.guardEmail.validateMessage, b.guardEmail.sanitize, b.guardAll.gate
 *
 * Build a guard gate compatible with the `b.guardAll` family
 * dispatch. The returned gate's async `check(ctx)` method accepts a
 * request-shaped context, runs `validateMessage` against the extracted
 * bytes, and returns
 * `{ ok, action, issues? }` where `action` is `serve` (no issues),
 * `audit-only` (warn-level), or `refuse` (high / critical severity).
 *
 * @opts
 *   profile:               "strict" | "balanced" | "permissive",
 *   compliancePosture:     "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   name:                  string,   // gate identifier surfaced in audit metadata
 *
 * @example
 *   var guardEmail = require("./lib/guard-email");
 *   var g = guardEmail.gate({ profile: "strict" });
 *   typeof g.check;         // → "function"
 *
 *   var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
 *             "Subject: hi\r\nDate: Mon, 5 May 2026 10:00:00 +0000\r\n\r\nbody\r\n";
 *   g.check({ body: Buffer.from(msg, "utf8") }).then(function (rv) {
 *     rv.action;            // → "serve"
 *   });
 */
function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardEmail:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var text = gateContract.extractBytesAsText(ctx);
      if (!text) return { ok: true, action: "serve" };
      var rv = validateMessage(text, opts);
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

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below; their wiki sections render from the
// single-sourced @abiTemplate (defineGuard) blocks in gate-contract.js,
// instantiated per guard by the page generator.

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "message/rfc822",
  extension:    ".eml",
  benignBytes:  Buffer.from(
    "From: alice@example.com\r\nTo: bob@example.com\r\n" +
    "Subject: hello\r\nDate: Mon, 5 May 2026 10:00:00 +0000\r\n\r\n" +
    "Hello.\r\n", "utf8"),
  // Hostile: SMTP-smuggling pattern — bare LF followed by SMTP verb
  // (CVE-2023-51764 / 51765 / 51766 class).
  hostileBytes: Buffer.from(
    "From: alice@example.com\r\nTo: bob@example.com\r\n" +
    "Subject: hi\r\n\r\n" +
    "body line 1\n.\nMAIL FROM: <evil@attacker>\r\n", "utf8"),
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / MIME_TYPES / EXTENSIONS / INTEGRATION_FIXTURES),
// buildProfile / compliancePosture / loadRulePack wiring, plus the
// per-guard inspection surface (validate / sanitize / bespoke gate) and
// the address/message entries (validateAddress / validateMessage) passed
// through verbatim. The bespoke `gate` validates via validateMessage and
// carries the serve->audit-only->refuse chain unchanged.
module.exports = gateContract.defineGuard({
  name:        "email",
  kind:        "content",
  errorClass:  GuardEmailError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["message/rfc822", "message/global"],
  extensions:  [".eml", ".mbox", ".msg"],
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  gate:        gate,
  extra: {
    validateAddress: validateAddress,
    validateMessage: validateMessage,
  },
});
