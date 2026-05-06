"use strict";
/**
 * guard-email — Email content-safety primitive (b.guardEmail).
 *
 * Threat catalog grounded in current research:
 *   - SMTP smuggling (CVE-2023-51764 Postfix; CVE-2023-51765 Sendmail;
 *     CVE-2023-51766 Exim; CVE-2026-32178 .NET System.Net.Mail) —
 *     embedded SMTP verbs after bare-CR / bare-LF / dot-stuffing
 *     manipulation lets an attacker inject a second message in the
 *     same SMTP session with a forged envelope.
 *   - CRLF header injection — `\r\n` inside any header field value
 *     splits the header section and lets the attacker forge `From:`,
 *     `Bcc:`, or smuggle a body.
 *   - IDN homograph spoofing — mixed-script Unicode in the domain part
 *     (Cyrillic а / Greek α / Armenian / Cherokee letters that look
 *     like Latin lowercase). Most filters miss confusables.
 *   - Display-name spoofing — `"support@apple.com" <attacker@evil>` —
 *     the rendered name impersonates a trusted address while the
 *     envelope routes elsewhere.
 *   - Bare IP literal addresses — `user@[1.2.3.4]` / `user@[IPv6:...]`.
 *   - Comment syntax in addresses — `(comment)` per RFC 5322 — most
 *     receivers reject; senders that accept it are a smuggling vector.
 *   - RFC 5321 / 5322 length caps — local-part 64; domain 255; total
 *     address 320; per-line 998.
 *   - Multiple @ characters / multiple addresses in a single field.
 *   - Bidi / null / control / zero-width chars in addresses + headers.
 *   - BOM injection at the start of a header.
 *
 *   var rv = b.guardEmail.validateAddress(addr, { profile: "strict" });
 *   var rv = b.guardEmail.validateMessage(rfc822, { profile: "strict" });
 *   var safe = b.guardEmail.sanitize(input, { profile: "balanced" });
 *   var g = b.guardEmail.gate({ profile: "strict" });
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

var LIMIT_LOCAL_PART = 64;                                                       // allow:raw-byte-literal — RFC 5321 §4.5.3.1.1
var LIMIT_DOMAIN     = 255;                                                      // allow:raw-byte-literal — RFC 5321 §4.5.3.1.2
var LIMIT_ADDRESS    = 320;                                                      // allow:raw-byte-literal — RFC 5321 sum (64 + 1 + 255)
var LIMIT_LINE       = 998;                                                      // allow:raw-byte-literal — RFC 5322 §2.1.1 maximum line length

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
    if (c === 13) {                                                              // allow:raw-byte-literal — CR
      var next = i + 1 < input.length ? input.charCodeAt(i + 1) : -1;
      if (next !== 10) bareCr = true;                                            // allow:raw-byte-literal — LF
    } else if (c === 10) {                                                       // allow:raw-byte-literal — LF
      var prev = i > 0 ? input.charCodeAt(i - 1) : -1;
      if (prev !== 13) bareLf = true;                                            // allow:raw-byte-literal — CR
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
    if (c === 13 || c === 10) return true;                                       // allow:raw-byte-literal — CR or LF in header value
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
             [0x00c0, 0x024f], [0x1e00, 0x1eff]],                                // allow:raw-byte-literal — Unicode script ranges
  cyrillic: [[0x0400, 0x04ff], [0x0500, 0x052f]],                                // allow:raw-byte-literal — Unicode Cyrillic + Cyrillic Supplement
  greek:    [[0x0370, 0x03ff], [0x1f00, 0x1fff]],                                // allow:raw-byte-literal — Unicode Greek + Greek Extended
  armenian: [[0x0530, 0x058f]],                                                  // allow:raw-byte-literal — Unicode Armenian
  cherokee: [[0x13a0, 0x13ff], [0xab70, 0xabbf]],                                // allow:raw-byte-literal — Unicode Cherokee + Cherokee Supplement
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
    maxHeaders:                   128,                                           // allow:raw-byte-literal — header count cap
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
    maxHeaders:                   512,                                           // allow:raw-byte-literal — header count cap
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
    maxHeaders:                   2048,                                          // allow:raw-byte-literal — header count cap
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
    if (input.charCodeAt(0) === 0xfeff) {                                        // allow:raw-byte-literal — Unicode BOM
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
                   parsed.display.slice(0, 64) + "` includes an @-address that " + // allow:raw-byte-literal — snippet truncation
                   "doesn't match the envelope domain `" + envDomain + "`",
        });
      }
    }
  }
  return issues;
}

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

// validate(input, opts) — auto-detect single address vs full message.
function validate(input, opts) {
  if (typeof input === "string" && input.indexOf("\n") === -1 &&
      input.indexOf(":") === -1) {
    return validateAddress(input, opts);
  }
  return validateMessage(input, opts);
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("email.bad-input", "sanitize requires string input");
  }
  // Critical shapes have no safe sanitization in email — throw on
  // smuggling / CRLF injection / multi-@ / mixed-script.
  var issues = _detectMessageIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical") {
      throw _err(issues[i].ruleId || "email.refused",
        "guardEmail.sanitize: " + issues[i].snippet);
    }
  }
  return codepointClass.applyCharStripPolicies(input, opts);
}

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

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "email");
}

var _emailRulePacks = gateContract.makeRulePackLoader(GuardEmailError, "email");
var loadRulePack = _emailRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "email",
  KIND:                "content",
  MIME_TYPES:          Object.freeze(["message/rfc822", "message/global"]),
  EXTENSIONS:          Object.freeze([".eml", ".mbox", ".msg"]),
  INTEGRATION_FIXTURES: Object.freeze({
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
  }),
  // ---- primitive surface ----
  validate:            validate,
  validateAddress:     validateAddress,
  validateMessage:     validateMessage,
  sanitize:            sanitize,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardEmailError:     GuardEmailError,
};
