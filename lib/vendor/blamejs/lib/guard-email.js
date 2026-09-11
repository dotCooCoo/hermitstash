// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var mimeParse = require("./mime-parse");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardEmailError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardEmailError.factory;

var LIMIT_LOCAL_PART = 64;
var LIMIT_DOMAIN     = 255;
var LIMIT_ADDRESS    = 320;
var LIMIT_LINE       = 998;

function _scanBareLineEndings(input) {
  var bareCr = false;
  var bareLf = false;
  for (var i = 0; i < input.length; i += 1) {
    var c = input.charCodeAt(i);
    if (c === 13) {
      var next = i + 1 < input.length ? input.charCodeAt(i + 1) : -1;
      if (next !== 10) bareCr = true;
    } else if (c === 10) {
      var prev = i > 0 ? input.charCodeAt(i - 1) : -1;
      if (prev !== 13) bareLf = true;
    }
    if (bareCr && bareLf) break;
  }
  return { bareCr: bareCr, bareLf: bareLf };
}

var SMTP_VERBS = ["MAIL FROM", "RCPT TO", "DATA", "EHLO", "HELO", "RSET", "QUIT"];

function _smtpVerbAt(text, at) {
  for (var v = 0; v < SMTP_VERBS.length; v += 1) {
    var verb = SMTP_VERBS[v];
    if (!codepointClass.containsFolded(text.slice(at, at + verb.length), verb)) continue;
    var after = text.charCodeAt(at + verb.length);
    if (isNaN(after) || !_isWordChar(after)) return true;
  }
  return false;
}

var _isWordChar = codepointClass.isIdentifierChar;

var _splitLines = codepointClass.splitLines;

function _hasSmuggledVerb(text) {
  var len = text.length;
  var afterOne = len;
  var afterTwo = len;
  for (var i = len - 1; i >= 0; i -= 1) {
    var cc = text.charCodeAt(i);
    var bare = (cc === 0x0D && text.charCodeAt(i + 1) !== 0x0A) ||
               (cc === 0x0A && text.charCodeAt(i - 1) !== 0x0D);
    if (bare && _smtpVerbAt(text, text.charCodeAt(i + 1) === 0x2E ? afterTwo : afterOne)) {
      return true;
    }
    afterTwo = afterOne;
    if (!codepointClass.inRanges(cc, codepointClass.WHITESPACE_RANGES)) afterOne = i;
  }
  return false;
}

function _hasCrlfInHeaderValue(value) {
  for (var i = 0; i < value.length; i += 1) {
    var c = value.charCodeAt(i);
    if (c === 13 || c === 10) return true;
  }
  return false;
}

var ATEXT_PUNCTUATION = "!#$%&'*+/=?^_`{|}~.-";
var MAX_DNS_LABEL_LENGTH = 63;

var _isAlnum = codepointClass.isAsciiAlnum;

function _isAtextRun(s) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i += 1) {
    var cc = s.charCodeAt(i);
    if (_isAlnum(cc)) continue;
    if (ATEXT_PUNCTUATION.indexOf(String.fromCharCode(cc)) === -1) return false;
  }
  return true;
}

function _isDnsLabel(s) {
  if (s.length === 0 || s.length > MAX_DNS_LABEL_LENGTH) return false;
  if (!_isAlnum(s.charCodeAt(0))) return false;
  if (!_isAlnum(s.charCodeAt(s.length - 1))) return false;
  for (var i = 1; i < s.length - 1; i += 1) {
    var cc = s.charCodeAt(i);
    if (!_isAlnum(cc) && cc !== 0x2D) return false;
  }
  return true;
}

function _isDnsDomain(s) {
  if (s.indexOf(".") === -1) return false;
  var labels = s.split(".");
  if (labels.length < 2) return false;
  for (var i = 0; i < labels.length; i += 1) {
    if (!_isDnsLabel(labels[i])) return false;
  }
  return true;
}

function _isStrictAddress(s) {
  var at = s.indexOf("@");
  if (at === -1 || at !== s.lastIndexOf("@")) return false;
  return _isAtextRun(s.slice(0, at)) && _isDnsDomain(s.slice(at + 1));
}

function _isIpLiteralAddress(s) {
  var at = s.indexOf("@");
  if (at <= 0) return false;
  if (s.slice(0, at).indexOf("@") !== -1) return false;
  if (s.charAt(at + 1) !== "[") return false;
  if (s.charAt(s.length - 1) !== "]") return false;
  var inner = s.slice(at + 2, s.length - 1);
  return inner.length > 0 && inner.indexOf("]") === -1;
}

function _hasPunycodeLabel(domain) {
  var labels = domain.split(".");
  for (var i = 0; i < labels.length; i += 1) {
    if (labels[i].length >= 4 && labels[i].slice(0, 4).toLowerCase() === "xn--") {
      return true;
    }
  }
  return false;
}

var SCRIPT_RANGES = {
  latin:    [[0x0041, 0x005a], [0x0061, 0x007a],
             [0x00c0, 0x024f], [0x1e00, 0x1eff]],
  cyrillic: [[0x0400, 0x04ff], [0x0500, 0x052f]],
  greek:    [[0x0370, 0x03ff], [0x1f00, 0x1fff]],
  armenian: [[0x0530, 0x058f]],
  cherokee: [[0x13a0, 0x13ff], [0xab70, 0xabbf]],
};

function _scriptFor(cp) {
  var keys = Object.keys(SCRIPT_RANGES);
  for (var i = 0; i < keys.length; i += 1) {
    var ranges = SCRIPT_RANGES[keys[i]];
    for (var j = 0; j < ranges.length; j += 1) {
      if (cp >= ranges[j][0] && cp <= ranges[j][1]) return keys[i];
    }
  }
  return null;
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

var SINGLE_LINE_HEADERS = ["from", "to", "cc", "bcc", "reply-to", "sender",
                           "subject", "message-id", "in-reply-to", "references",
                           "date", "return-path"];

function _parseAddressLine(line) {
  var end = line.length;
  var ws = codepointClass.WHITESPACE_RANGES;
  while (end > 0 && codepointClass.inRanges(line.charCodeAt(end - 1), ws)) end -= 1;
  if (end === 0 || line.charAt(end - 1) !== ">") {
    return { display: "", envelope: line.trim() };
  }
  var gt = end - 1;

  var lastGtBefore = line.lastIndexOf(">", gt - 1);
  var lt = line.indexOf("<", lastGtBefore + 1);
  if (lt === -1 || lt > gt) return { display: "", envelope: line.trim() };

  var inner = line.slice(lt + 1, gt);
  var envelope = codepointClass.trimRanges(inner, ws, { trailing: false });
  if (envelope.length === 0) {
    if (inner.length === 0) return { display: "", envelope: line.trim() };
    envelope = inner.slice(inner.length - 1);
  }

  var head = line.slice(0, lt);
  var display = codepointClass.trimRanges(head, ws);
  if (codepointClass.firstInRanges(display, LINE_TERMINATOR_RANGES) !== -1) {
    return { display: "", envelope: line.trim() };
  }
  return { display: _stripOuterQuotes(display), envelope: envelope };
}

var LINE_TERMINATOR_RANGES = [0x000A, 0x000D, 0x2028, 0x2029];

var PROFILES = Object.freeze({
  "strict": {
    crlfHeaderInjectionPolicy:    "reject",
    smtpSmugglingPolicy:          "reject",
    bareCrPolicy:                 "reject",
    bareLfPolicy:                 "reject",
    multiAtPolicy:                "reject",
    ipLiteralPolicy:              "reject",
    addressCommentPolicy:         "reject",
    punycodePolicy:               "reject",
    mixedScriptPolicy:            "reject",
    displayNameSpoofPolicy:       "reject",
    bomPolicy:                    "reject",
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    allowedScripts:               ["latin"],
    maxLocalPartBytes:            LIMIT_LOCAL_PART,
    maxDomainBytes:               LIMIT_DOMAIN,
    maxAddressBytes:              LIMIT_ADDRESS,
    maxHeaderLineBytes:           LIMIT_LINE,
    maxHeaders:                   128,
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
    bidiPolicy:                   "reject",
    controlPolicy:                "strip",
    nullBytePolicy:               "reject",
    zeroWidthPolicy:              "strip",
    allowedScripts:               ["latin", "cyrillic", "greek"],
    maxLocalPartBytes:            LIMIT_LOCAL_PART,
    maxDomainBytes:               LIMIT_DOMAIN,
    maxAddressBytes:              LIMIT_ADDRESS,
    maxHeaderLineBytes:           LIMIT_LINE,
    maxHeaders:                   512,
    maxBytes:                     C.BYTES.mib(32),
  },
  "permissive": {
    crlfHeaderInjectionPolicy:    "reject",
    smtpSmugglingPolicy:          "reject",
    bareCrPolicy:                 "audit",
    bareLfPolicy:                 "audit",
    multiAtPolicy:                "reject",
    ipLiteralPolicy:              "allow",
    addressCommentPolicy:         "audit",
    punycodePolicy:               "audit",
    mixedScriptPolicy:            "audit",
    displayNameSpoofPolicy:       "audit",
    bomPolicy:                    "audit",
    bidiPolicy:                   "audit",
    controlPolicy:                "strip",
    nullBytePolicy:               "reject",
    zeroWidthPolicy:              "audit",
    allowedScripts:               null,
    maxLocalPartBytes:            LIMIT_LOCAL_PART,
    maxDomainBytes:               LIMIT_DOMAIN,
    maxAddressBytes:              LIMIT_ADDRESS,
    maxHeaderLineBytes:           LIMIT_LINE,
    maxHeaders:                   2048,
    maxBytes:                     C.BYTES.mib(128),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs:  C.TIME.seconds(10),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

function _stripOuterQuotes(s) {
  var out = s;
  if (out.charAt(0) === "\"") out = out.slice(1);
  if (out.length > 0 && out.charAt(out.length - 1) === "\"") out = out.slice(0, -1);
  return out;
}

function _resolveOpts(opts) {
  return module.exports.resolveOpts(opts);
}

function _detectAddressIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              snippet: "address is not a string" }];
  }

  var addressBytes = Buffer.byteLength(input, "utf8");
  if (addressBytes > opts.maxAddressBytes) {
    issues.push({
      kind: "address-cap", severity: "high", ruleId: "email.address-cap",
      snippet: "address " + addressBytes + " bytes exceeds maxAddressBytes " +
               opts.maxAddressBytes,
    });
  }

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
    return issues;
  }

  if (opts.addressCommentPolicy !== "allow" &&
      codepointClass.indexOfAny(input, "()") !== -1) {
    issues.push({
      kind: "address-comment",
      severity: opts.addressCommentPolicy === "reject" ? "high" : "warn",
      ruleId: "email.address-comment",
      snippet: "address contains '(' or ')' — RFC 5322 comment syntax, " +
               "smuggling-prone vs RFC 5321 receivers",
    });
  }

  if (_isIpLiteralAddress(input)) {
    if (opts.ipLiteralPolicy !== "allow") {
      issues.push({
        kind: "ip-literal",
        severity: opts.ipLiteralPolicy === "reject" ? "high" : "warn",
        ruleId: "email.ip-literal",
        snippet: "address uses IP literal `[...]` — bypasses DNS / DMARC alignment",
      });
    }
  } else {
    var atIdx = input.lastIndexOf("@");
    var localPart = atIdx === -1 ? input : input.slice(0, atIdx);
    var domain = atIdx === -1 ? "" : input.slice(atIdx + 1);

    var localPartBytes = Buffer.byteLength(localPart, "utf8");
    if (localPartBytes > opts.maxLocalPartBytes) {
      issues.push({
        kind: "local-part-cap", severity: "high",
        ruleId: "email.local-part-cap",
        snippet: "local-part " + localPartBytes + " bytes exceeds " +
                 opts.maxLocalPartBytes + " (RFC 5321 §4.5.3.1.1)",
      });
    }
    var domainBytes = Buffer.byteLength(domain, "utf8");
    if (domainBytes > opts.maxDomainBytes) {
      issues.push({
        kind: "domain-cap", severity: "high",
        ruleId: "email.domain-cap",
        snippet: "domain " + domainBytes + " bytes exceeds " +
                 opts.maxDomainBytes + " (RFC 5321 §4.5.3.1.2)",
      });
    }

    if (opts.punycodePolicy !== "allow" && _hasPunycodeLabel(domain)) {
      issues.push({
        kind: "punycode-domain",
        severity: opts.punycodePolicy === "reject" ? "high" : "warn",
        ruleId: "email.punycode-domain",
        snippet: "domain uses IDN/Punycode (`xn--` label) — may be " +
                 "homograph-spoofing",
      });
    }

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

    var hasCap = issues.some(function (i) {
      return i.kind === "local-part-cap" || i.kind === "domain-cap";
    });
    if (!hasCap) {
      if (!_isStrictAddress(input)) {
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
    "guardEmail.validateAddress", GuardEmailError, "email/bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "address is not a string" }],
    };
  }
  return gateContract.runIssueValidator(input, opts, _detectAddressIssues, "raw");
}

function _detectMessageIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "email", noun: "input", emptyMode: "skip", scanCodepoints: false, cap: { bytes: opts.maxBytes, kind: "too-large", snippet: function (byteLen, max) { return "input " + byteLen + " bytes exceeds maxBytes " + max; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  if (opts.bomPolicy !== "allow") {
    if (input.charCodeAt(0) === 0xfeff) {
      issues.push({
        kind: "bom",
        severity: opts.bomPolicy === "reject" ? "high" : "warn",
        ruleId: "email.bom",
        snippet: "message starts with BOM (U+FEFF) — header-parser confusion",
      });
    }
  }

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
  if (opts.smtpSmugglingPolicy !== "allow" && _hasSmuggledVerb(input)) {
    issues.push({
      kind: "smtp-smuggling", severity: "critical",
      ruleId: "email.smtp-smuggling",
      snippet: "embedded SMTP verb after bare CR/LF — smuggling vector " +
               "(SEC Consult / smtpsmuggling.com class)",
    });
  }

  var headerEnd = input.indexOf("\r\n\r\n");
  if (headerEnd === -1) headerEnd = input.indexOf("\n\n");
  var headerSection = headerEnd === -1 ? input : input.slice(0, headerEnd);

  var lines = _splitLines(headerSection);
  if (lines.length > opts.maxHeaders) {
    issues.push({
      kind: "header-count-cap", severity: "high",
      ruleId: "email.header-count-cap",
      snippet: "header count " + lines.length + " exceeds maxHeaders " +
               opts.maxHeaders,
    });
  }
  for (var li = 0; li < lines.length; li += 1) {
    var lineBytes = Buffer.byteLength(lines[li], "utf8");
    if (lineBytes > opts.maxHeaderLineBytes) {
      issues.push({
        kind: "header-line-cap", severity: "high",
        ruleId: "email.header-line-cap",
        snippet: "header line " + (li + 1) + " is " + lineBytes +
                 " bytes (RFC 5322 §2.1.1 limit " + opts.maxHeaderLineBytes + ")",
      });
      break;
    }
  }

  var unfolded = _unfoldHeaders(lines);
  for (var hi = 0; hi < unfolded.length; hi += 1) {
    var entry = unfolded[hi];
    var name = entry.name.toLowerCase();
    if (SINGLE_LINE_HEADERS.indexOf(name) === -1) continue;

    if (opts.crlfHeaderInjectionPolicy !== "allow" &&
        _hasCrlfInHeaderValue(entry.value)) {
      issues.push({
        kind: "crlf-header-injection", severity: "critical",
        ruleId: "email.crlf-header-injection",
        snippet: "header `" + entry.name + "` contains CR/LF — header " +
                 "injection vector (smuggle From/Bcc/body)",
      });
    }

    if (name === "from" || name === "to" || name === "cc" ||
        name === "bcc" || name === "reply-to" || name === "sender" ||
        name === "return-path") {
      var addrIssues = _checkAddressHeaderValue(entry.value, opts, entry.name);
      for (var ai = 0; ai < addrIssues.length; ai += 1) {
        issues.push(addrIssues[ai]);
      }
    }
  }

  if (opts.crlfHeaderInjectionPolicy !== "allow") {
    var block = mimeParse.classifyHeaderBlock(input);
    for (var mi = 0; mi < block.malformed.length; mi += 1) {
      issues.push({
        kind: "malformed-header-line", severity: "high",
        ruleId: "email.malformed-header-line",
        snippet: "header-section line " + (block.malformed[mi].lineIndex + 1) +
                 " is neither a header field nor a folding continuation — " +
                 "malformed message / header-injection signal",
      });
    }
  }

  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "email"));

  return issues;
}

function _trimLeadingWhitespace(s) {
  return codepointClass.trimRanges(s, codepointClass.WHITESPACE_RANGES,
                                   { trailing: false });
}

function _unfoldHeaders(lines) {
  var out = [];
  var current = null;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line === "") { current = null; continue; }
    if (current && (line.charAt(0) === " " || line.charAt(0) === "\t")) {
      current.value += " " + _trimLeadingWhitespace(line);
      continue;
    }
    var colonAt = line.indexOf(":");
    if (colonAt === -1) { current = null; continue; }
    current = {
      name:  line.slice(0, colonAt).trim(),
      value: _trimLeadingWhitespace(line.slice(colonAt + 1)),
    };
    out.push(current);
  }
  return out;
}

function _splitAddressList(value) {
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
                   parsed.display.slice(0, 64) + "` includes an @-address that " +
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
    "guardEmail.validateMessage", GuardEmailError, "email/bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "input is not a string" }],
    };
  }
  return gateContract.runIssueValidator(input, opts, _detectMessageIssues, "raw");
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
    throw _err("email/bad-input", "sanitize requires string input");
  }
  var issues = _detectMessageIssues(input, opts);
  gateContract.throwOnRefusedDisposition(issues, {
    dispositionFor: _gateDispositionFor,
    opts:           opts,
    errorClass:     GuardEmailError,
    codePrefix:     "email",
    severities:     ["critical"],
  });
  codepointClass.assertWithinMaxBytes(input, opts, _err, "email");
  codepointClass.assertNoCharThreats(input, opts, _err, "email");
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
function _gateDispositionFor(issue, opts) {
  return gateContract.charThreatDisposition(issue, opts);
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildContentGate({
    name:     opts.name || "guardEmail:" + (opts.profile || "default"),
    opts:     opts,
    validate: validateMessage,
    dispositionFor:   _gateDispositionFor,
    produceSanitized: function (text, o) { return sanitize(text, o); },
  });
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "message/rfc822",
  extension:    ".eml",
  benignBytes:  Buffer.from(
    "From: alice@example.com\r\nTo: bob@example.com\r\n" +
    "Subject: hello\r\nDate: Mon, 5 May 2026 10:00:00 +0000\r\n\r\n" +
    "Hello.\r\n", "utf8"),
  hostileBytes: Buffer.from(
    "From: alice@example.com\r\nTo: bob@example.com\r\n" +
    "Subject: hi\r\n\r\n" +
    "body line 1\n.\nMAIL FROM: <evil@attacker>\r\n", "utf8"),
});

var POLICY_ENUM = gateContract.policyVocabulary([
  "multiAtPolicy", "ipLiteralPolicy", "punycodePolicy", "mixedScriptPolicy",
  "addressCommentPolicy", "crlfHeaderInjectionPolicy", "bareCrPolicy",
  "bareLfPolicy", "smtpSmugglingPolicy", "displayNameSpoofPolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow, {
  bomPolicy: gateContract.POLICY_VALUES.rejectStripAuditAllow,
});

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "email",
  kind:        "content",
  charRepair:  true,
  errorClass:  GuardEmailError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["message/rfc822", "message/global"],
  extensions:  [".eml", ".mbox", ".msg"],
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  intOpts:     ["maxBytes", "maxLocalPartBytes", "maxDomainBytes",
                "maxAddressBytes", "maxHeaderLineBytes", "maxHeaders"],
  gate:        gate,
  extra: {
    validateAddress: validateAddress,
    validateMessage: validateMessage,
    _shapesForTest: {
      isStrictAddress:    _isStrictAddress,
      isIpLiteralAddress: _isIpLiteralAddress,
      hasPunycodeLabel:   _hasPunycodeLabel,
      hasSmuggledVerb:    _hasSmuggledVerb,
      parseAddressLine:   _parseAddressLine,
      splitLines:         _splitLines,
    },
  },
});
