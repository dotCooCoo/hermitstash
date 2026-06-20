"use strict";
/**
 * b.mail.spf + b.mail.dmarc + b.mail.arc — inbound mail authentication
 * verification family. Counterpart to the existing outbound DKIM
 * signer in lib/mail-dkim.js.
 *
 * Operators receiving mail (incoming webhooks, customer-support
 * inboxes, mailing-list ingestion, .eml uploads) need this to evaluate
 * sender authenticity and decide on accept / quarantine / reject.
 *
 * Surface:
 *   b.mail.spf.verify({ ip, mailFrom, helo, dnsLookup }) → result
 *   b.mail.dmarc.evaluate({ from, spf, dkim, dnsLookup })  → result
 *   b.mail.arc.verify(rfc822, opts)                        → chain status
 *
 * SPF (RFC 7208) — ip4 / ip6 / a / mx / include / exists / all /
 *   redirect= mechanisms, with macro-string expansion (§7).
 *   Mechanism limit: 10 DNS lookups per RFC 7208 §4.6.4 (with the
 *   void-lookup sub-limit at 2). The `a` and `mx` arms honor RFC
 *   §5.3 / §5.4 dual-cidr-length syntax (`a:foo.com/24//64`). The
 *   `exists` mechanism (§5.7) and include / redirect targets honor
 *   §7 macro expansion (`%{i}` / `%{s}` / `%{l}` / `%{d}` / `%{o}` /
 *   `%{h}` / `%{v}` / `%{p}` plus the digit / `r` / delimiter
 *   transformers); the §4.6.4 lookup + void ceilings still bound the
 *   macro-driven exists / a / mx queries.
 *
 *   Deferred mechanism (carries an explicit Re-open condition in the
 *   dispatch arm in this file):
 *     - ptr:    "strongly discouraged" by §5.5; re-opens when an
 *               operator surfaces a legitimate ptr-only sender.
 *
 * DMARC (RFC 7489) — TXT record at _dmarc.<domain>; alignment check
 *   between From-header domain and DKIM-d / SPF-from-domain;
 *   policy resolution (none / quarantine / reject) per the published
 *   record. The org-domain extraction uses an operator-supplied
 *   `dnsLookup` callback (the framework doesn't ship the Public Suffix
 *   List).
 *
 * ARC (RFC 8617) — chain-of-custody verification. The framework parses
 *   the existing chain headers, recomputes the per-hop signatures, and
 *   reports validity by composing `lib/mail-dkim.js` (which carries
 *   the actual signature-verification surface).
 */

var zlib = require("node:zlib");
var net = require("node:net");
var nodeCrypto = require("node:crypto");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var structuredFields = require("./structured-fields");
var markupEscape = require("./markup-escape").markupEscape;
var bCrypto = require("./crypto");
var C = require("./constants");
var dkim = require("./mail-dkim");
var mimeParse = require("./mime-parse");
var safeXml = require("./parsers/safe-xml");
var ipUtils = require("./ip-utils");
var publicSuffix = require("./public-suffix");
var networkDnsResolver = lazyRequire(function () { return require("./network-dns-resolver"); });
var { MailAuthError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

// SPF DNS-lookup ceiling per RFC 7208 §4.6.4. Operators with high-
// fan-out include chains hit this; the verify path returns "permerror"
// when crossed, matching mainstream MTAs.
var SPF_DNS_LOOKUP_LIMIT = 10;

// RFC 7208 §4.6.4 — "void lookup" cap. A void lookup is a successful
// DNS query whose answer is empty (NXDOMAIN, no-data response, or
// zero records returned). The SPF spec caps void lookups at 2; beyond
// that the policy MUST permerror. Attackers chain misconfigured
// `include:`s pointing at non-existent domains to amplify recursive
// resolver work without tripping the 10-lookup ceiling.
var SPF_VOID_LOOKUP_LIMIT = 2;                                                   // RFC 7208 §4.6.4 void-lookup ceiling

// RFC 7208 §3.3 — each SPF TXT record MUST NOT exceed 450 bytes when
// concatenated across multi-string TXT chunks. The spec lifts a
// receiver MUST-refuse on >450-byte records to bound parse work.
var SPF_RECORD_MAX_BYTES = 450;                                                  // RFC 7208 §3.3 record ceiling

// SPF redirect= modifier (RFC 7208 §6.1) recursion cap. The modifier
// re-evaluates against a different domain; a chain of redirect= cycles
// MUST terminate. We bound at the same depth as the lookup ceiling
// minus current count (the redirect itself counts as one lookup); the
// hard cap below is an additional belt-and-braces against malformed
// upstream policies that would otherwise spin until the lookup cap
// alone tripped.
var SPF_REDIRECT_DEPTH_LIMIT = 10;                                               // same shape as RFC 7208 §4.6.4 lookup ceiling

// Shared safe-DNS TXT/A/AAAA/MX/PTR lookup. Operator-supplied
// `dnsLookup(qname, type)` is honored for every type when present:
//   TXT  → [[ "v=spf1 ...", ... ], ...]   (array of TXT-string-arrays)
//   A    → [ "192.0.2.1", ... ]           (flat IPv4 string array)
//   AAAA → [ "2001:db8::1", ... ]         (flat IPv6 string array)
//   MX   → [ { exchange, preference }, ...]  (or [ "mx1.example.", ... ]
//                                             when operator omits preference)
//   PTR  → [ "host.example.", ... ]       (flat PTR-name array)
// When no operator callback is supplied, requests route through
// `b.network.dns.resolver` (DoH by default per v0.7.23). CVE-2008-1447
// (Kaminsky) + CVE-2022-3204 (NRDelegationAttack) class — the encrypted
// DoH transport plus b.safeDns parse caps defend transport and parse-
// side. Earlier shape fell back to `node:dns.promises.resolveTxt`
// directly, which sent plaintext UDP/53 to whatever the system
// resolver was — every downstream finding inherited that exposure.
var _defaultResolver = null;
function _getDefaultResolver() {
  if (_defaultResolver) return _defaultResolver;
  _defaultResolver = networkDnsResolver().create();
  return _defaultResolver;
}

// TXT resolution reuses the shared reshape in networkDnsResolver.resolveTxt,
// passing this module's own resolver so TXT shares the resolver (and cache)
// used for A / MX / PTR below.
async function _safeResolveTxt(qname, operatorLookup) {
  return networkDnsResolver().resolveTxt(qname, operatorLookup, _getDefaultResolver());
}

async function _safeResolveA(qname, family /* 4|6 */, operatorLookup) {
  // Pre-v0.11.3 the operatorLookup parameter wasn't threaded here, so
  // the documented `dnsLookup` shape for A/AAAA was unhonored — SPF a/
  // mx mechanism tests had no operator-mockable path. The function
  // signature now matches the docstring contract above. Operator
  // returns a flat string array of IP literals.
  if (operatorLookup) {
    var resp = await operatorLookup(qname, family === 6 ? "AAAA" : "A");
    if (!Array.isArray(resp) || resp.length === 0) {
      var aerr = new Error("no " + (family === 6 ? "AAAA" : "A") + " records for " + qname);
      aerr.code = "ENODATA";
      throw aerr;
    }
    return resp.map(function (x) { return String(x); });
  }
  var r = await _getDefaultResolver().query(qname, family === 6 ? "AAAA" : "A");
  var out = [];
  for (var i = 0; i < r.rrs.length; i += 1) {
    var rr = r.rrs[i];
    var wantType = family === 6 ? 28 : 1;                                        // IANA DNS qtype AAAA / A
    if (rr && rr.type === wantType) out.push(rr.decoded);
  }
  if (out.length === 0) {
    var err = new Error("no " + (family === 6 ? "AAAA" : "A") + " records for " + qname);
    err.code = "ENODATA";
    throw err;
  }
  return out;
}

// RFC 1035 §3.3.9 MX record: { preference, exchange }. Returns array of
// exchange hostnames sorted by preference (lowest first). Operator-
// supplied dnsLookup callback may return either:
//   - [ { exchange, preference }, ... ]  — full shape (preferred)
//   - [ "mx1.example.", ... ]            — exchanges only (preference
//                                           treated as 0 → first-served)
async function _safeResolveMx(qname, operatorLookup) {
  if (operatorLookup) {
    var resp = await operatorLookup(qname, "MX");
    if (!Array.isArray(resp) || resp.length === 0) {
      var merr = new Error("no MX records for " + qname);
      merr.code = "ENODATA";
      throw merr;
    }
    var normalized = resp.map(function (entry) {
      if (typeof entry === "string") return { exchange: entry.replace(/\.$/, ""), preference: 0 };
      var ex = entry && entry.exchange;
      var pref = (entry && typeof entry.preference === "number") ? entry.preference : 0;
      return { exchange: String(ex || "").replace(/\.$/, ""), preference: pref };
    }).filter(function (e) { return e.exchange.length > 0; });
    normalized.sort(function (a, b) { return a.preference - b.preference; });
    return normalized.map(function (e) { return e.exchange; });
  }
  var r = await _getDefaultResolver().query(qname, "MX");
  var entries = [];
  for (var i = 0; i < r.rrs.length; i += 1) {
    var rr = r.rrs[i];
    if (rr && rr.type === 15) {                                                  // IANA DNS qtype MX
      var d = rr.decoded || {};
      if (d.exchange) {
        entries.push({ exchange: String(d.exchange).replace(/\.$/, ""),
                       preference: typeof d.preference === "number" ? d.preference : 0 });
      }
    }
  }
  if (entries.length === 0) {
    var err = new Error("no MX records for " + qname);
    err.code = "ENODATA";
    throw err;
  }
  entries.sort(function (a, b) { return a.preference - b.preference; });
  return entries.map(function (e) { return e.exchange; });
}

async function _safeReverse(ip) {
  // PTR query against the reverse-arpa name. IPv4: a.b.c.d.in-addr.arpa
  // (reversed octets); IPv6: nibble-reversed under ip6.arpa.
  var qname = _ipToReverseArpa(ip);
  if (qname === null) {
    var err = new Error("invalid IP literal: " + ip);
    err.code = "ENOTFOUND";
    throw err;
  }
  var r = await _getDefaultResolver().query(qname, "PTR");
  var out = [];
  for (var i = 0; i < r.rrs.length; i += 1) {
    var rr = r.rrs[i];
    if (rr && rr.type === 12) {                                                  // IANA DNS qtype PTR
      // Strip trailing dot if present (PTR rdata is FQDN with root dot).
      var name = String(rr.decoded || "").replace(/\.$/, "");
      if (name.length > 0) out.push(name);
    }
  }
  if (out.length === 0) {
    var e2 = new Error("no PTR records for " + ip);
    e2.code = "ENODATA";
    throw e2;
  }
  return out;
}

function _ipToReverseArpa(ip) {
  if (typeof ip !== "string") return null;
  if (net.isIPv4(ip)) {
    var p = ip.split(".");
    if (p.length !== 4) return null;                                             // IPv4 octet count
    return p[3] + "." + p[2] + "." + p[1] + "." + p[0] + ".in-addr.arpa";
  }
  if (net.isIPv6(ip)) {
    var groups = ipUtils.expandIpv6Groups(ip);
    if (!groups) return null;
    var hex = "";
    for (var i = 0; i < groups.length; i += 1) {
      var s = groups[i].toString(16);                                            // hex radix
      while (s.length < 4) s = "0" + s;                                          // IPv6 group nibble count
      hex += s;
    }
    var rev = hex.split("").reverse().join(".");
    return rev + ".ip6.arpa";
  }
  return null;
}

// ---- Helpers ----

function _ipv4ToInt(ip) {
  var parts = ip.split(".");
  if (parts.length !== 4) return null;                                           // IPv4 octet count
  var n = 0;
  for (var i = 0; i < 4; i += 1) {                                               // IPv4 octet count
    var p = parseInt(parts[i], 10);
    if (!isFinite(p) || p < 0 || p > 255) return null;                           // IPv4 octet range
    n = (n * 256) + p;                                                           // IPv4 octet base
  }
  return n;
}

// Expand an IPv6 string (which may carry `::` shorthand) into 8 16-bit
// groups. Returns null on malformed input.
function _ipv6Expand(ip) {
  // Compose the shared lib/ip-utils helper so the same IPv6 parse
  // path is shared across mail-auth / mail-rbl / mail-greylist.
  return ipUtils.expandIpv6Groups(ip);
}

function _ipv6InCidr(ip, cidr) {
  var slash = cidr.indexOf("/");
  var net = slash === -1 ? cidr : cidr.slice(0, slash);
  var mask = slash === -1 ? 128 : parseInt(cidr.slice(slash + 1), 10);                        // IPv6 max prefix
  if (!isFinite(mask) || mask < 0 || mask > 128) return false;                                // IPv6 max prefix
  var ipGroups  = _ipv6Expand(ip);
  var netGroups = _ipv6Expand(net);
  if (!ipGroups || !netGroups) return false;
  if (mask === 0) return true;
  // Compare group-by-group up to the prefix boundary.
  var fullGroups = Math.floor(mask / 16);                                                     // bits per group
  var remainBits = mask - fullGroups * 16;                                                    // bits per group
  for (var g = 0; g < fullGroups; g += 1) {
    if (ipGroups[g] !== netGroups[g]) return false;
  }
  if (remainBits > 0 && fullGroups < 8) {                                                     // IPv6 group count
    var groupMask = (0xffff << (16 - remainBits)) & 0xffff;                                   // bits per group
    if ((ipGroups[fullGroups] & groupMask) !== (netGroups[fullGroups] & groupMask)) return false;
  }
  return true;
}

function _ipv4InCidr(ip, cidr) {
  var slash = cidr.indexOf("/");
  var net = slash === -1 ? cidr : cidr.slice(0, slash);
  var mask = slash === -1 ? 32 : parseInt(cidr.slice(slash + 1), 10);             // IPv4 max prefix
  if (mask < 0 || mask > 32) return false;                                       // IPv4 max prefix
  var ipInt = _ipv4ToInt(ip);
  var netInt = _ipv4ToInt(net);
  if (ipInt === null || netInt === null) return false;
  if (mask === 0) return true;
  var bits = 32 - mask;                                                          // IPv4 max prefix
  // Use BigInt to avoid 32-bit signed-int wrap.
  var maskInt = (BigInt("0xFFFFFFFF") << BigInt(bits)) & BigInt("0xFFFFFFFF");
  return (BigInt(ipInt) & maskInt) === (BigInt(netInt) & maskInt);
}

// ---- SPF macro-string expansion (RFC 7208 §7) ----
//
// A macro-string is `*( macro-expand / macro-literal )`. A macro-expand
// is `"%{" macro-letter transformers *delimiter "}"` (RFC 7208 §7.1).
// The legacy `%%`, `%_`, `%-` escapes expand to "%", " ", "%20".
//
// Macro letters (RFC 7208 §7.2):
//   s = <sender>          (the MAIL FROM / HELO identity, localpart@domain)
//   l = local-part of <sender>
//   o = domain of <sender>
//   d = <domain>          (the SPF record's current domain)
//   i = <ip>              (dotted-decimal for IPv4; nibble-dotted-hex for IPv6)
//   p = the validated domain name of <ip> (PTR — discouraged §5.5; "unknown"
//       absent a validated name; the framework returns "unknown" rather
//       than performing the discouraged reverse-lookup)
//   v = "in-addr" for IPv4, "ip6" for IPv6
//   h = HELO/EHLO domain
//   c / r / t = SMTP-time-only macros (exp= text); not valid in a
//       checked macro-string, so we expand them to empty in mechanism
//       context per §7.3's split between "macro-string" and the
//       exp-only letters.
//
// Transformers (RFC 7208 §7.1): an optional digit count limits the
// number of right-hand parts kept after a split; an optional `r`
// reverses the parts; an optional delimiter set (any of `.-+,/_=`)
// replaces "." as the split delimiter. After transforms, the parts are
// re-joined with ".".
//
// Length bound: the expanded macro-string is capped so a hostile policy
// can't inflate a DNS qname past the RFC 1035 §3.1 255-octet ceiling
// (the resulting name is used as a DNS query). RFC 7208 §7.1 mandates a
// 253-octet limit on the constructed domain-name; we cap the assembled
// string the same way.
var SPF_MACRO_MAX_EXPANDED_BYTES = 253;                                          // RFC 1035 §3.1 / RFC 7208 §7.1 name ceiling
var SPF_MACRO_DELIMS = ".-+,/_=";                                                // RFC 7208 §7.1 delimiter set

// IPv6 nibble-dotted form for the `i` macro (RFC 7208 §7.3): each of the
// 32 hex nibbles becomes its own "."-separated part. e.g.
// 2001:db8::1 → "2.0.0.1.0.d.b.8.0.…0.0.0.1".
function _ipv6Nibbles(ip) {
  var groups = ipUtils.expandIpv6Groups(ip);
  if (!groups) return null;
  var nibbles = [];
  for (var i = 0; i < groups.length; i += 1) {
    var s = groups[i].toString(16);                                              // hex radix
    while (s.length < 4) s = "0" + s;                                            // IPv6 group nibble count
    for (var j = 0; j < 4; j += 1) nibbles.push(s.charAt(j));                    // IPv6 group nibble count
  }
  return nibbles;
}

// Resolve a single macro letter to its base string value (pre-transform).
// `vars` carries { ip, isIpv6, sender, localPart, senderDomain, domain,
// helo }. Letters not meaningful in mechanism context expand to "".
function _spfMacroValue(letter, vars) {
  var lower = letter.toLowerCase();
  switch (lower) {
    case "s": return vars.sender || "";
    case "l": return vars.localPart || "";
    case "o": return vars.senderDomain || "";
    case "d": return vars.domain || "";
    case "h": return vars.helo || "";
    case "v": return vars.isIpv6 ? "ip6" : "in-addr";
    case "i":
      if (vars.isIpv6) {
        var nib = _ipv6Nibbles(vars.ip);
        return nib ? nib.join(".") : "";
      }
      return vars.ip || "";
    // RFC 7208 §5.5 — `p` (validated domain name) is "strongly
    // discouraged"; resolving it requires the reverse-DNS path the
    // framework intentionally does not perform here. Expand to the
    // RFC-mandated sentinel so an `exists:%{p}...` policy degrades to a
    // deterministic miss rather than a forged match.
    case "p": return "unknown";
    // c / r / t are exp-text-only macros (RFC 7208 §7.3); empty in
    // mechanism context.
    default:  return "";
  }
}

// Split `value` on the active delimiter chars, optionally reverse, keep
// the rightmost `digits` parts, re-join with ".". RFC 7208 §7.1.
function _spfApplyTransform(value, digits, reverse, delims) {
  if (value.length === 0) return "";
  // Build a character class from the (validated) delimiter set. Each
  // delim char is one of `.-+,/_=` — all regex-safe except none need
  // escaping inside a class except `-` which we place last; the set is
  // a fixed allowlist so no untrusted metacharacter reaches the class.
  var splitParts;
  if (delims === ".") {
    splitParts = value.split(".");
  } else {
    var out = [];
    var cur = "";
    for (var ci = 0; ci < value.length; ci += 1) {
      var ch = value.charAt(ci);
      if (delims.indexOf(ch) !== -1) { out.push(cur); cur = ""; }
      else cur += ch;
    }
    out.push(cur);
    splitParts = out;
  }
  if (reverse) splitParts = splitParts.slice().reverse();
  if (digits !== null && digits > 0 && digits < splitParts.length) {
    splitParts = splitParts.slice(splitParts.length - digits);
  }
  return splitParts.join(".");
}

// Expand an SPF macro-string (RFC 7208 §7.1). `vars` is the macro
// variable bag. Throws MailAuthError on malformed `%` syntax (a bare
// `%` not followed by `{`, `%`, `_`, or `-` is a syntax error per
// §7.1 — receivers MUST permerror, mirrored by the caller catching the
// throw). The expanded result is byte-capped (§7.1 / RFC 1035 §3.1).
//
// The scanner is a single linear left-to-right pass (no backtracking
// regex over untrusted input): each `%{...}` token is matched by an
// index walk to the closing `}`, bounding work at O(n) in the macro
// length.
function _spfExpandMacros(macroString, vars) {
  if (typeof macroString !== "string" || macroString.indexOf("%") === -1) {
    return macroString;
  }
  var out = "";
  var n = macroString.length;
  var i = 0;
  while (i < n) {
    var ch = macroString.charAt(i);
    if (ch !== "%") { out += ch; i += 1; continue; }
    // ch === "%": peek the next char.
    if (i + 1 >= n) {
      throw new MailAuthError("mail-auth/spf-macro-bad-syntax",
        "SPF macro-string ends with a bare '%' (RFC 7208 §7.1)");
    }
    var next = macroString.charAt(i + 1);
    if (next === "%") { out += "%"; i += 2; continue; }
    if (next === "_") { out += " "; i += 2; continue; }
    if (next === "-") { out += "%20"; i += 2; continue; }
    if (next !== "{") {
      throw new MailAuthError("mail-auth/spf-macro-bad-syntax",
        "SPF macro escape '%" + next + "' is invalid (RFC 7208 §7.1 allows %%, %_, %-, %{...})");
    }
    // next === "{": find the closing "}".
    var close = macroString.indexOf("}", i + 2);
    if (close === -1) {
      throw new MailAuthError("mail-auth/spf-macro-bad-syntax",
        "SPF macro '%{' has no closing '}' (RFC 7208 §7.1)");
    }
    var body = macroString.slice(i + 2, close);
    // body = macro-letter [ digits ] [ "r" ] *delimiter   (RFC 7208 §7.1)
    if (body.length === 0) {
      throw new MailAuthError("mail-auth/spf-macro-bad-syntax",
        "SPF macro '%{}' is empty (RFC 7208 §7.1)");
    }
    var letter = body.charAt(0);
    if (!/^[slodiphcrtv]$/i.test(letter)) {
      throw new MailAuthError("mail-auth/spf-macro-bad-syntax",
        "SPF macro letter " + JSON.stringify(letter) + " is not a valid macro-letter (RFC 7208 §7.2)");
    }
    var rest = body.slice(1);
    var digits = null;
    var di = 0;
    while (di < rest.length && rest.charAt(di) >= "0" && rest.charAt(di) <= "9") di += 1;
    if (di > 0) {
      digits = parseInt(rest.slice(0, di), 10);
      if (!isFinite(digits) || digits < 1) {
        throw new MailAuthError("mail-auth/spf-macro-bad-syntax",
          "SPF macro transformer digit count must be >= 1 (RFC 7208 §7.1): " + JSON.stringify(body));
      }
    }
    rest = rest.slice(di);
    var reverse = false;
    if (rest.length > 0 && (rest.charAt(0) === "r" || rest.charAt(0) === "R")) {
      reverse = true;
      rest = rest.slice(1);
    }
    // Remaining chars are the optional delimiter set; each MUST be one
    // of the RFC 7208 §7.1 delimiters. Anything else is malformed.
    var delims = "";
    for (var ri = 0; ri < rest.length; ri += 1) {
      var dch = rest.charAt(ri);
      if (SPF_MACRO_DELIMS.indexOf(dch) === -1) {
        throw new MailAuthError("mail-auth/spf-macro-bad-syntax",
          "SPF macro delimiter " + JSON.stringify(dch) + " is not in the RFC 7208 §7.1 set " +
          JSON.stringify(SPF_MACRO_DELIMS));
      }
      if (delims.indexOf(dch) === -1) delims += dch;
    }
    if (delims.length === 0) delims = ".";
    var base = _spfMacroValue(letter, vars);
    out += _spfApplyTransform(base, digits, reverse, delims);
    i = close + 1;
  }
  if (out.length > SPF_MACRO_MAX_EXPANDED_BYTES) {
    // RFC 7208 §7.1 — the constructed domain-name is left-truncated to
    // fit the 253-octet ceiling: leading labels are discarded until the
    // remainder fits. This keeps the trailing (more-significant) labels
    // the policy author intends as the lookup target.
    while (out.length > SPF_MACRO_MAX_EXPANDED_BYTES) {
      var dot = out.indexOf(".");
      if (dot === -1) { out = out.slice(out.length - SPF_MACRO_MAX_EXPANDED_BYTES); break; }
      out = out.slice(dot + 1);
    }
  }
  return out;
}

// Parse an SPF record into mechanisms.
function _parseSpfRecord(text) {
  var trimmed = text.trim();
  if (trimmed.indexOf("v=spf1") !== 0) {
    throw new MailAuthError("mail-auth/spf-bad-version",
      "SPF record must start with 'v=spf1', got " +
        JSON.stringify(trimmed.slice(0, C.BYTES.bytes(32))));
  }
  var parts = trimmed.split(/\s+/);
  var mechanisms = [];
  var modifiers  = [];
  for (var i = 1; i < parts.length; i += 1) {
    var p = parts[i];
    if (p.length === 0) continue;
    // RFC 7208 §4.6 distinguishes mechanisms (with optional qualifier
    // prefix) from modifiers (name=value, no qualifier; e.g.
    // `redirect=` and `exp=`). Pre-v0.8.32 the framework treated
    // `redirect=` like a mechanism, surfacing a permerror under the
    // generic "out of scope" arm. Handle modifiers separately:
    // redirect= triggers re-evaluation against the target domain;
    // exp= is operator-facing only (we record it).
    var eqAt = p.indexOf("=");
    if (eqAt !== -1 && /^[a-z]+$/i.test(p.slice(0, eqAt))) {
      modifiers.push({ name: p.slice(0, eqAt).toLowerCase(), value: p.slice(eqAt + 1) });
      continue;
    }
    var qualifier = "+";
    if (p.charAt(0) === "+" || p.charAt(0) === "-" ||
        p.charAt(0) === "~" || p.charAt(0) === "?") {
      qualifier = p.charAt(0);
      p = p.slice(1);
    }
    var colonAt = p.indexOf(":");
    var slashAt = p.indexOf("/");
    var sep = (colonAt !== -1 && (slashAt === -1 || colonAt < slashAt))
              ? colonAt : slashAt;
    var mech = sep === -1 ? p : p.slice(0, sep);
    var arg  = sep === -1 ? null : p.slice(sep + 1);
    // `raw` preserves the full mechanism+arg token after qualifier-
    // strip. The a/mx dispatch arm reparses this directly because
    // RFC 7208 §5.3/§5.4 allow `dual-cidr-length` after the optional
    // domain-spec (e.g. `a:example.com/24//64`); the simple `arg`
    // field above splits on the first separator and loses the
    // information about whether that separator was `:` or `/`.
    mechanisms.push({ qualifier: qualifier, mechanism: mech.toLowerCase(), arg: arg, raw: p });
  }
  // Surface modifiers via a non-enumerable property so callers that
  // don't expect them don't see them in JSON-serialized records but
  // _spfEvaluateDomain can react.
  Object.defineProperty(mechanisms, "modifiers", { value: modifiers });
  return mechanisms;
}

// Fetch the SPF TXT record for a domain. Returns:
//   { kind: "found",    record: "<text>" }  — exactly one v=spf1 record
//   { kind: "none" }                          — zero v=spf1 records
//   { kind: "permerror", reason: "<msg>" }    — multiple v=spf1 records
//                                              (RFC 7208 §4.5 — domain
//                                              MUST publish at most one)
async function _fetchSpfRecord(domain, dnsLookup) {
  var records;
  try {
    records = await _safeResolveTxt(domain, dnsLookup);
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return { kind: "none" };
    throw new MailAuthError("mail-auth/spf-lookup-failed",
      "SPF TXT lookup for " + domain + " failed: " +
      ((e && e.message) || String(e)));
  }
  if (!Array.isArray(records)) return { kind: "none" };
  var matches = [];
  for (var i = 0; i < records.length; i += 1) {
    var rec = Array.isArray(records[i]) ? records[i].join("") : records[i];
    if (typeof rec === "string" && rec.indexOf("v=spf1") === 0) matches.push(rec);
  }
  if (matches.length === 0) return { kind: "none" };
  if (matches.length > 1) {
    return { kind: "permerror",
             reason: "domain " + domain + " publishes " + matches.length +
                     " v=spf1 records; RFC 7208 §4.5 requires at most one" };
  }
  // RFC 7208 §3.3 — the SPF record (concatenated across multi-string
  // TXT chunks) MUST NOT exceed 450 bytes. Receivers MUST refuse
  // larger records (permerror) so a malformed-large policy can't
  // amplify parser work.
  if (matches[0].length > SPF_RECORD_MAX_BYTES) {
    return { kind: "permerror",
             reason: "domain " + domain + " SPF record is " + matches[0].length +
                     " bytes; RFC 7208 §3.3 caps at " + SPF_RECORD_MAX_BYTES };
  }
  return { kind: "found", record: matches[0] };
}

// RFC 7208 §5.3 / §5.4 — `a [ ":" domain-spec ] [ dual-cidr-length ]`
// and `mx [ ":" domain-spec ] [ dual-cidr-length ]`. dual-cidr-length
// is `[ "/" ip4-cidr ] [ "//" ip6-cidr ]`. Returns the parsed target
// domain plus per-family prefix lengths (32 / 128 when omitted).
//
// `raw` is the post-qualifier token (e.g. "a", "a:foo.com", "a/24",
// "a//64", "a:foo.com/24//64"). Throws MailAuthError on bad cidr.
function _parseADualCidr(raw, mech, defaultDomain) {
  var rest   = raw.slice(mech.length);
  var domain = defaultDomain;
  var v4Mask = 32;                                                                 // IPv4 max prefix
  var v6Mask = 128;                                                                // IPv6 max prefix

  if (rest.charAt(0) === ":") {
    rest = rest.slice(1);
    var slashAt = rest.indexOf("/");
    if (slashAt === -1) { domain = rest; rest = ""; }
    else { domain = rest.slice(0, slashAt); rest = rest.slice(slashAt); }
  }

  if (rest.length > 0) {
    // rest is now "" | "/v4" | "//v6" | "/v4//v6".
    var dblSlash = rest.indexOf("//");
    var v4Part = "";
    var v6Part = "";
    if (dblSlash !== -1) {
      v4Part = rest.slice(0, dblSlash);                                            // "" or "/24"
      v6Part = rest.slice(dblSlash + 2);                                           // "64"
    } else {
      v4Part = rest;                                                               // "/24"
    }
    if (v4Part.length > 0) {
      if (v4Part.charAt(0) !== "/") {
        throw new MailAuthError("mail-auth/spf-bad-cidr",
          "SPF " + mech + " dual-cidr malformed: " + JSON.stringify(raw));
      }
      var v4Str = v4Part.slice(1);
      // RFC 7208 §5.3 / §5.4 — `ip4-cidr-length = "/" 1*DIGIT`. An
      // empty digit segment (`a/`, `mx/`) is malformed grammar; the
      // receiver MUST permerror. Pre-fix this silently kept the
      // default /32 and would authorize the connecting IP under any
      // A record of the target, which can over-authorize senders
      // publishing `v=spf1 a/ -all` (would match every IP in the
      // /32 of every A record).
      if (v4Str.length === 0) {
        throw new MailAuthError("mail-auth/spf-bad-cidr",
          "SPF " + mech + " v4 cidr-length is empty (RFC 7208 §5.3/§5.4 grammar requires 1*DIGIT): " +
          JSON.stringify(raw));
      }
      var v4n = parseInt(v4Str, 10);
      if (!isFinite(v4n) || v4n < 0 || v4n > 32 || String(v4n) !== v4Str) {         // IPv4 max prefix
        throw new MailAuthError("mail-auth/spf-bad-cidr",
          "SPF " + mech + " v4 cidr-length invalid: " + JSON.stringify(raw));
      }
      v4Mask = v4n;
    }
    // RFC 7208 §5.3 / §5.4 — `ip6-cidr-length = "/" 1*DIGIT` (after
    // the "//" separator). When the `//` separator IS present (i.e.
    // the raw token contained `//`) the digit segment MUST be 1*DIGIT.
    // Empty (`a//`, `a/24//`, `mx//`) is malformed grammar; permerror.
    if (dblSlash !== -1) {
      if (v6Part.length === 0) {
        throw new MailAuthError("mail-auth/spf-bad-cidr",
          "SPF " + mech + " v6 cidr-length is empty (RFC 7208 §5.3/§5.4 grammar requires 1*DIGIT): " +
          JSON.stringify(raw));
      }
      var v6n = parseInt(v6Part, 10);
      if (!isFinite(v6n) || v6n < 0 || v6n > 128 || String(v6n) !== v6Part) {       // IPv6 max prefix
        throw new MailAuthError("mail-auth/spf-bad-cidr",
          "SPF " + mech + " v6 cidr-length invalid: " + JSON.stringify(raw));
      }
      v6Mask = v6n;
    }
  }

  if (!domain || domain.length === 0) {
    throw new MailAuthError("mail-auth/spf-bad-cidr",
      "SPF " + mech + " has no target domain (current-domain unavailable)");
  }
  return { domain: domain.toLowerCase(), v4Mask: v4Mask, v6Mask: v6Mask };
}

// RFC 7208 §5.3 / §5.4 — `a` and `mx` mechanism evaluation. Both
// resolve the target domain (or the current SPF-evaluating domain when
// arg omitted) to a set of IP addresses; the connecting IP matches if
// it falls inside any of those addresses under the parsed cidr prefix.
//
// Lookup accounting per §4.6.4:
//   - `a`: the outer evaluator has already counted this as one DNS-
//          touching mechanism. The single A/AAAA query is THAT one
//          lookup; no additional increment here.
//   - `mx`: the outer evaluator has counted the MX query itself.
//          EACH MX hostname's A/AAAA expansion adds an additional
//          lookup; total expansion is capped at 10 MX hostnames per
//          §4.6.4 (the explicit "MX limit"). Crossing the global
//          10-lookup ceiling at any expansion step permerrors.
//
// Returns one of:
//   { match: true }                       — connecting IP matched
//   { match: false }                      — no IP matched / record absent
//   { error: "temperror", reason: "..." } — transient DNS failure
//   { error: "permerror", reason: "..." } — over-limit / bad CIDR / bad MX count
async function _spfMatchAMx(mech, raw, ip, isIpv6, defaultDomain, dnsLookup, lookups, macroVars) {
  var parsed;
  try { parsed = _parseADualCidr(raw, mech, defaultDomain); }
  catch (e) { return { error: "permerror", reason: e.message }; }

  // RFC 7208 §5.3 / §5.4 — the domain-spec after `a:` / `mx:` is a
  // macro-string (§7). Expand it before resolving so policies like
  // `a:%{i}._ah.example.com` evaluate correctly. The default-domain
  // case (`a` / `mx` with no `:domain`) carries no `%` and passes
  // through untouched.
  if (macroVars && parsed.domain.indexOf("%") !== -1) {
    try { parsed.domain = _spfExpandMacros(parsed.domain, macroVars).toLowerCase(); }
    catch (e) { return { error: "permerror", reason: e.message }; }
    if (!parsed.domain || parsed.domain.length === 0) {
      return { error: "permerror",
               reason: "SPF " + mech + ": domain-spec expanded to empty (RFC 7208 §7)" };
    }
  }

  var mask = isIpv6 ? parsed.v6Mask : parsed.v4Mask;
  var family = isIpv6 ? 6 : 4;                                                     // IP family marker

  var targetIps = [];
  if (mech === "a") {
    try { targetIps = await _safeResolveA(parsed.domain, family, dnsLookup); }
    catch (e) {
      var code = e && e.code;
      if (code === "ENOTFOUND" || code === "ENODATA") return { match: false };
      return { error: "temperror",
               reason: "SPF a:" + parsed.domain + " lookup failed: " +
                       ((e && e.message) || String(e)) };
    }
  } else {                                                                          // mech === "mx"
    var mxHosts;
    try { mxHosts = await _safeResolveMx(parsed.domain, dnsLookup); }
    catch (e) {
      var mcode = e && e.code;
      if (mcode === "ENOTFOUND" || mcode === "ENODATA") return { match: false };
      return { error: "temperror",
               reason: "SPF mx:" + parsed.domain + " MX lookup failed: " +
                       ((e && e.message) || String(e)) };
    }
    // RFC 7208 §4.6.4 — the MX expansion is capped at 10 hostnames.
    // Crossing this is a permerror; receivers MUST NOT silently
    // truncate, since a misconfigured sender publishing 20 MX hosts
    // would otherwise have only the first 10 contribute to authz.
    if (mxHosts.length > 10) {                                                      // RFC 7208 §4.6.4 MX limit
      return { error: "permerror",
               reason: "SPF mx:" + parsed.domain + " resolved " + mxHosts.length +
                       " MX hosts (RFC 7208 §4.6.4 caps at 10)" };
    }
    for (var mi = 0; mi < mxHosts.length; mi += 1) {
      lookups.count += 1;
      if (lookups.count > lookups.limit) {
        return { error: "permerror",
                 reason: "DNS lookup limit exceeded (RFC 7208 §4.6.4) during mx:" +
                         parsed.domain + " expansion" };
      }
      try {
        var hostIps = await _safeResolveA(mxHosts[mi], family, dnsLookup);
        for (var hi = 0; hi < hostIps.length; hi += 1) targetIps.push(hostIps[hi]);
      } catch (e) {
        var hcode = e && e.code;
        if (hcode === "ENOTFOUND" || hcode === "ENODATA") {
          // Void lookup — counts toward §4.6.4 ceiling for the MX
          // expansion (the MX hostname has no A/AAAA in the relevant
          // family). Some hosts are v4-only and won't have AAAA; we
          // skip the host but charge the void slot.
          lookups.void = (lookups.void || 0) + 1;
          if (lookups.void > SPF_VOID_LOOKUP_LIMIT) {
            return { error: "permerror",
                     reason: "SPF void-lookup limit exceeded (RFC 7208 §4.6.4) during mx expansion" };
          }
          continue;
        }
        return { error: "temperror",
                 reason: "SPF mx host " + mxHosts[mi] + " A/AAAA lookup failed: " +
                         ((e && e.message) || String(e)) };
      }
    }
  }

  for (var ti = 0; ti < targetIps.length; ti += 1) {
    var cidr = targetIps[ti] + "/" + mask;
    if (isIpv6) { if (_ipv6InCidr(ip, cidr)) return { match: true }; }
    else        { if (_ipv4InCidr(ip, cidr)) return { match: true }; }
  }
  return { match: false };
}

// SPF verify — recursive include resolution + ip4 / ip6 / a / mx /
// include / exists / all / redirect=, with RFC 7208 §7 macro expansion.
// The `ptr` mechanism remains deferred (see the dispatch arm for the
// Re-open condition + operator escape hatch via b.mail.iprev.verify).
async function spfVerify(opts) {
  opts = opts || {};
  validateOpts(opts, ["ip", "mailFrom", "helo", "dnsLookup"], "mail.spf.verify");
  if (typeof opts.ip !== "string") {
    throw new MailAuthError("mail-auth/spf-bad-ip",
      "spf.verify: ip must be a string");
  }
  var domain = opts.mailFrom
    ? String(opts.mailFrom).split("@")[1]
    : opts.helo;
  if (typeof domain !== "string" || domain.length === 0) {
    throw new MailAuthError("mail-auth/spf-bad-domain",
      "spf.verify: mailFrom or helo is required");
  }

  var lookups = { count: 0, limit: SPF_DNS_LOOKUP_LIMIT, void: 0 };
  // RFC 7208 §7 macro variable bag. `<sender>` is the MAIL FROM identity
  // when present, else `postmaster@<helo>` per §4.3 (the localpart
  // defaults to "postmaster" when the reverse-path is empty / HELO is
  // the checked identity). `<domain>` (%{d}) tracks the SPF record's
  // current domain and is rebound at each include/redirect re-entry.
  var senderIdentity = opts.mailFrom
    ? String(opts.mailFrom)
    : ("postmaster@" + String(opts.helo || domain));
  var senderLocal = senderIdentity.indexOf("@") !== -1
    ? senderIdentity.slice(0, senderIdentity.indexOf("@"))
    : "postmaster";
  var senderDomain = senderIdentity.indexOf("@") !== -1
    ? senderIdentity.slice(senderIdentity.indexOf("@") + 1)
    : String(opts.helo || domain);
  var macroVars = {
    ip:           opts.ip,
    isIpv6:       opts.ip.indexOf(":") !== -1,
    sender:       senderIdentity,
    localPart:    senderLocal,
    senderDomain: senderDomain,
    domain:       domain.toLowerCase(),
    helo:         typeof opts.helo === "string" ? opts.helo : "",
  };
  // RFC 7208 §4.6.4 — the initial query for the sender domain's SPF
  // record itself does NOT count toward the 10-lookup limit. Only
  // include / a / mx / ptr / exists / redirect mechanisms count.
  // Pre-v0.8.17 this was off-by-one — senders at the spec ceiling
  // got false permerror.
  var result = await _spfEvaluateDomain(domain.toLowerCase(), opts.ip,
                                          opts.dnsLookup, lookups,
                                          { isInitial: true, macroVars: macroVars });
  return {
    result: result.verdict,                                                      // pass | fail | softfail | neutral | none | temperror | permerror
    domain: domain,
    explanation: result.explanation,
    lookupCount: lookups.count,
  };
}

async function _spfEvaluateDomain(domain, ip, dnsLookup, lookups, ctx) {
  ctx = ctx || {};
  if (lookups.count > lookups.limit) {
    return { verdict: "permerror", explanation: "DNS lookup limit exceeded (RFC 7208 §4.6.4)" };
  }
  // RFC 7208 §4.6.4 — void-lookup ceiling. Each successful query that
  // returns 0 records (NXDOMAIN, no-data) counts. Beyond 2, permerror.
  if ((lookups.void || 0) > SPF_VOID_LOOKUP_LIMIT) {
    return { verdict: "permerror",
             explanation: "SPF void-lookup limit exceeded (RFC 7208 §4.6.4)" };
  }
  // RFC 7208 §6.1 — redirect= recursion bound. Per-evaluation
  // re-entries via redirect MUST terminate. The lookup limit also
  // catches pathological chains; this bound is the belt-and-braces.
  if ((ctx.redirectDepth || 0) > SPF_REDIRECT_DEPTH_LIMIT) {
    return { verdict: "permerror",
             explanation: "SPF redirect= recursion limit exceeded (RFC 7208 §6.1)" };
  }
  // Initial query for the sender's SPF record doesn't count (RFC 7208
  // §4.6.4); only include / a / mx / ptr / exists / redirect do.
  if (!ctx.isInitial) lookups.count += 1;

  var fetched;
  try { fetched = await _fetchSpfRecord(domain, dnsLookup); }
  catch (e) {
    return { verdict: "temperror", explanation: e.message };
  }
  if (fetched.kind === "permerror") {
    return { verdict: "permerror", explanation: fetched.reason };
  }
  if (fetched.kind === "none") {
    // Void lookup — count toward §4.6.4 ceiling. Initial query
    // doesn't count as a "lookup" but DOES count as void if the
    // sender has no SPF (mirrors the spec's intent: a misconfigured
    // sender that publishes no record still consumes a slot).
    lookups.void = (lookups.void || 0) + 1;
    return { verdict: "none", explanation: "no SPF record at " + domain };
  }

  var mechanisms;
  try { mechanisms = _parseSpfRecord(fetched.record); }
  catch (e) {
    return { verdict: "permerror", explanation: e.message };
  }

  // RFC 7208 §7.2 — `%{d}` is the SPF record's CURRENT domain, which is
  // rebound at each include / redirect re-entry. Clone the inherited
  // macro bag with `domain` pinned to the domain we're evaluating now.
  var baseMacroVars = ctx.macroVars || {};
  var macroVars = Object.assign({}, baseMacroVars, { domain: domain });

  var isIpv6 = ip.indexOf(":") !== -1;
  for (var i = 0; i < mechanisms.length; i += 1) {
    var m = mechanisms[i];
    var match = false;
    if (m.mechanism === "all") match = true;
    else if (!isIpv6 && (m.mechanism === "ip4" || m.mechanism === "ipv4")) {
      if (m.arg && _ipv4InCidr(ip, m.arg)) match = true;
    } else if (isIpv6 && (m.mechanism === "ip6" || m.mechanism === "ipv6")) {
      if (m.arg && _ipv6InCidr(ip, m.arg)) match = true;
    } else if (m.mechanism === "include") {
      if (!m.arg) continue;
      // RFC 7208 §7 — the include target may itself be a macro-string
      // (e.g. `include:%{d}.spf.example.net`). Expand against the
      // current macro bag before recursing.
      var includeTarget;
      try { includeTarget = _spfExpandMacros(m.arg, macroVars); }
      catch (e) { return { verdict: "permerror", explanation: e.message }; }
      var inner = await _spfEvaluateDomain(includeTarget.toLowerCase(), ip,
                                           dnsLookup, lookups,
                                           { macroVars: macroVars });
      if (inner.verdict === "pass") match = true;
      else if (inner.verdict === "permerror" || inner.verdict === "temperror") {
        return inner;
      }
      // RFC 7208 §5.2 — when the included domain has no SPF record at
      // all, the include itself MUST permerror (the included policy is
      // missing, the operator's intent is unverifiable). Without this
      // check `include:gone-domain.example` silently authorizes whatever
      // mechanism follows, including `+all`.
      else if (inner.verdict === "none") {
        return { verdict: "permerror",
                 explanation: "include:" + m.arg + " has no SPF record (RFC 7208 §5.2)" };
      }
    } else if (m.mechanism === "a" || m.mechanism === "mx") {
      // RFC 7208 §5.3 / §5.4. The mechanism itself counts as one DNS
      // lookup per §4.6.4 (already incremented by the outer loop's
      // `lookups.count += 1` for non-initial domains; ip4/ip6/all are
      // overcounted as a result, but only by mechanisms whose lookup
      // budget the spec doesn't care about — they're not DNS-touching).
      // The `a` / `mx` arms additionally expand per RFC §4.6.4 (each
      // MX hostname adds another lookup); the helper handles that
      // accounting.
      lookups.count += 1;
      if (lookups.count > lookups.limit) {
        return { verdict: "permerror",
                 explanation: "DNS lookup limit exceeded (RFC 7208 §4.6.4) at " +
                              m.mechanism };
      }
      var amRes = await _spfMatchAMx(m.mechanism, m.raw, ip, isIpv6,
                                      domain, dnsLookup, lookups, macroVars);
      if (amRes.error === "permerror") {
        return { verdict: "permerror", explanation: amRes.reason };
      }
      if (amRes.error === "temperror") {
        return { verdict: "temperror", explanation: amRes.reason };
      }
      if (amRes.match) match = true;
    } else if (m.mechanism === "exists") {
      // RFC 7208 §5.7 — `exists:<domain-spec>`. The domain-spec is
      // macro-expanded (§7) and an A query is performed; the mechanism
      // matches when ANY A record exists (the address is irrelevant —
      // existence alone is the signal, so an AAAA-only target does NOT
      // match per the spec's "A query" wording). Published policies use
      // it for per-IP / per-recipient lookups like
      // `exists:%{ir}.%{v}._spf.example.com`.
      if (!m.arg) continue;
      var existsTarget;
      try { existsTarget = _spfExpandMacros(m.arg, macroVars); }
      catch (e) { return { verdict: "permerror", explanation: e.message }; }
      if (!existsTarget || existsTarget.length === 0) {
        return { verdict: "permerror",
                 explanation: "SPF exists: expanded to an empty domain (RFC 7208 §5.7)" };
      }
      // §4.6.4 — the exists A query counts as one DNS-touching lookup.
      lookups.count += 1;
      if (lookups.count > lookups.limit) {
        return { verdict: "permerror",
                 explanation: "DNS lookup limit exceeded (RFC 7208 §4.6.4) at exists:" +
                              existsTarget };
      }
      var existsHit = false;
      try {
        var existsIps = await _safeResolveA(existsTarget.toLowerCase(), 4, dnsLookup);
        existsHit = Array.isArray(existsIps) && existsIps.length > 0;
      } catch (e) {
        var ecode = e && e.code;
        if (ecode === "ENOTFOUND" || ecode === "ENODATA") {
          // Void lookup — RFC 7208 §4.6.4 ceiling. A non-existent target
          // is a miss, not an error, but charges the void slot so a
          // chain of exists: misses can't amplify resolver work.
          lookups.void = (lookups.void || 0) + 1;
          if (lookups.void > SPF_VOID_LOOKUP_LIMIT) {
            return { verdict: "permerror",
                     explanation: "SPF void-lookup limit exceeded (RFC 7208 §4.6.4) during exists: evaluation" };
          }
          existsHit = false;
        } else {
          return { verdict: "temperror",
                   explanation: "SPF exists:" + existsTarget + " lookup failed: " +
                                ((e && e.message) || String(e)) };
        }
      }
      if (existsHit) match = true;
    } else if (m.mechanism === "ptr") {
      // RFC 7208 §5.5 — `ptr` is "strongly discouraged": it ties the
      // sender's authorization to whoever controls the connecting IP's
      // PTR zone and doubles DNS load (reverse + forward-confirm per
      // query). A small minority of legacy senders still publish
      // `+ptr -all` as their only stance.
      //
      // Re-open condition: an operator surfaces a legitimate sender
      // whose ONLY SPF stance is `ptr` and needs the framework to
      // evaluate it rather than the MTA already doing iprev.
      //
      // Operator escape hatch today: wire `b.mail.iprev.verify(ip)` and
      // treat fcrdns=true the same as an SPF pass for that domain.
      return {
        verdict: "permerror",
        explanation: "SPF mechanism 'ptr' is not implemented (RFC 7208 §5.5 — strongly " +
                     "discouraged); use b.mail.iprev.verify for forward-confirmed reverse DNS",
      };
    }
    if (match) {
      var qualifier = m.qualifier;
      var verdict = qualifier === "+" ? "pass" :
                    qualifier === "-" ? "fail" :
                    qualifier === "~" ? "softfail" :
                    qualifier === "?" ? "neutral" : "neutral";
      return { verdict: verdict, explanation: "matched " + m.mechanism +
               (m.arg ? ":" + m.arg : "") };
    }
  }

  // RFC 7208 §6.1 — `redirect=<domain>` modifier: when no mechanism
  // matched, fall through to the target domain's policy. The redirect
  // is ignored if an `all` mechanism is present (since `all` matches
  // unconditionally, the redirect is unreachable by construction).
  // Pre-this-patch the redirect= modifier was silently dropped — a
  // domain whose only policy was `v=spf1 redirect=_spf.example.com`
  // returned "neutral" instead of the redirected verdict, leaving
  // every legitimate sender unauthenticated.
  var mods = mechanisms.modifiers || [];
  for (var rmi = 0; rmi < mods.length; rmi += 1) {
    if (mods[rmi].name === "redirect" && mods[rmi].value) {
      // Redirect counts as one DNS-mechanism per §4.6.4. RFC 7208 §7 —
      // the redirect target may be a macro-string; expand it first.
      var redirectTarget;
      try { redirectTarget = _spfExpandMacros(mods[rmi].value, macroVars); }
      catch (e) { return { verdict: "permerror", explanation: e.message }; }
      var redirected = await _spfEvaluateDomain(
        redirectTarget.toLowerCase(), ip, dnsLookup, lookups,
        { redirectDepth: (ctx.redirectDepth || 0) + 1, macroVars: macroVars });
      // RFC 7208 §6.1 — if the redirect target has no SPF record,
      // permerror (the operator's intent is unverifiable).
      if (redirected.verdict === "none") {
        return { verdict: "permerror",
                 explanation: "redirect=" + mods[rmi].value +
                              " has no SPF record (RFC 7208 §6.1)" };
      }
      return redirected;
    }
  }

  return { verdict: "neutral", explanation: "no mechanism matched" };
}

// ---- DMARC (RFC 7489) ----

async function _fetchDmarcRecord(domain, dnsLookup) {
  var qname = "_dmarc." + domain.toLowerCase();
  var records = await networkDnsResolver().safeResolveTxt(qname, {
    dnsLookup:    dnsLookup,
    errorFactory: function (code, msg) { return new MailAuthError(code, msg); },
    code:         "mail-auth/dmarc-lookup-failed",
  });
  if (!Array.isArray(records)) return null;
  var matches = [];
  for (var i = 0; i < records.length; i += 1) {
    var rec = Array.isArray(records[i]) ? records[i].join("") : records[i];
    if (typeof rec === "string" && rec.indexOf("v=DMARC1") === 0) matches.push(rec);
  }
  if (matches.length === 0) return null;
  // RFC 7489 §6.6.3 — when multiple v=DMARC1 records are published,
  // the receiver MUST treat the domain as having no DMARC record.
  if (matches.length > 1) return null;
  return matches[0];
}

// RFC 7489 base policy keys + DMARCbis (draft-ietf-dmarc-dmarcbis)
// extensions:
//   np=<none|quarantine|reject>  policy for non-existent subdomains
//   psd=<y|n|u>                  applies-at-public-suffix-domain (TLD
//                                operator publishes a DMARC record on
//                                the suffix itself)
// Validation tier: parse is config-time (operator-supplied DNS bytes);
// throw on malformed v= / unrecognized np= or psd= values rather than
// silently dropping — operators with a typo'd record otherwise see the
// fallback policy applied without warning.
var DMARCBIS_VALID_NP = { none: 1, quarantine: 1, reject: 1 };
var DMARCBIS_VALID_PSD = { y: 1, n: 1, u: 1 };

function _parseDmarcRecord(text) {
  var policy = { v: null, p: null, sp: null, np: null, psd: null,
                 pct: 100, adkim: "r", aspf: "r" };                              // RFC 7489 default pct
  // RFC 7489 §6.4 DMARC tag-list grammar: `tag-spec *( ";" tag-spec )`,
  // tag-value carries NO quoted-string — the naive split is correct.
  var pairs = structuredFields.parseTagList(text);
  for (var i = 0; i < pairs.length; i += 1) {
    var key = pairs[i][0];
    var val = pairs[i][1];
    if (key === "v")     policy.v = val;
    else if (key === "p")     policy.p = val.toLowerCase();
    else if (key === "sp")    policy.sp = val.toLowerCase();
    else if (key === "pct")   policy.pct = parseInt(val, 10);
    else if (key === "adkim") policy.adkim = val.toLowerCase();
    else if (key === "aspf")  policy.aspf = val.toLowerCase();
    else if (key === "np") {
      var npVal = val.toLowerCase();
      if (!DMARCBIS_VALID_NP[npVal]) {
        throw new MailAuthError("mail-auth/dmarcbis-bad-tag",
          "DMARC np= must be one of none|quarantine|reject, got " + JSON.stringify(val));
      }
      policy.np = npVal;
    }
    else if (key === "psd") {
      var psdVal = val.toLowerCase();
      if (!DMARCBIS_VALID_PSD[psdVal]) {
        throw new MailAuthError("mail-auth/dmarcbis-bad-tag",
          "DMARC psd= must be one of y|n|u, got " + JSON.stringify(val));
      }
      policy.psd = psdVal;
    }
  }
  if (policy.v !== "DMARC1") {
    throw new MailAuthError("mail-auth/dmarc-bad-version",
      "DMARC record version must be DMARC1, got " + JSON.stringify(policy.v));
  }
  return policy;
}

function _alignmentCheck(fromDomain, authDomain, mode) {
  if (!fromDomain || !authDomain) return false;
  var f = fromDomain.toLowerCase();
  var a = authDomain.toLowerCase();
  if (mode === "s") return f === a;                                              // strict
  // RFC 7489 §3.1.1 + DMARCbis §4.4 — relaxed alignment compares the
  // organizational domain (the public-suffix-tail registered name).
  // Earlier shape did a naive `endsWith` text-suffix check which over-
  // approximated alignment: `evil-bank.com` and `bank.com` looked
  // aligned even though they're separately registered. PSL lookup
  // closes the gap.
  if (f === a) return true;
  var fOrg = null;
  var aOrg = null;
  try { fOrg = publicSuffix.organizationalDomain(f); } catch (_e) { fOrg = null; }
  try { aOrg = publicSuffix.organizationalDomain(a); } catch (_e) { aOrg = null; }
  if (fOrg && aOrg && fOrg === aOrg) return true;
  return false;
}

async function dmarcEvaluate(opts) {
  opts = opts || {};
  validateOpts(opts, ["from", "spf", "dkim", "dnsLookup", "domainExists",
                       "pctSampleKey"],
               "mail.dmarc.evaluate");
  if (typeof opts.from !== "string") {
    throw new MailAuthError("mail-auth/dmarc-bad-from",
      "dmarc.evaluate: opts.from must be the From-header email address");
  }
  var fromDomain = opts.from.split("@")[1];
  if (!fromDomain) {
    throw new MailAuthError("mail-auth/dmarc-bad-from",
      "dmarc.evaluate: opts.from is missing the @domain part");
  }
  fromDomain = fromDomain.toLowerCase();

  // DMARCbis (draft-ietf-dmarc-dmarcbis) replaces the legacy "drop one
  // label" org-domain heuristic with a proper Public Suffix List lookup.
  // organizationalDomain returns null when the input IS a public suffix
  // (e.g. "co.uk") OR when no PSL match resolves; either way, the
  // org-domain walk below short-circuits.
  var orgDomain = null;
  try { orgDomain = publicSuffix.organizationalDomain(fromDomain); }
  catch (_e) { orgDomain = null; }

  var policy = null;
  var policyOriginDomain = null;
  var orgDomainPolicyApplied = false;
  var psdPolicyApplied = false;
  try {
    var rec = await _fetchDmarcRecord(fromDomain, opts.dnsLookup);
    if (rec) {
      policy = _parseDmarcRecord(rec);
      policyOriginDomain = fromDomain;
    } else if (orgDomain && orgDomain !== fromDomain) {
      // RFC 7489 §6.6.3 + DMARCbis §4.6 — fall through to organizational
      // domain. When the org-domain record sets sp= it applies to this
      // subdomain; otherwise p= is the operative policy.
      var orgRec = await _fetchDmarcRecord(orgDomain, opts.dnsLookup);
      if (orgRec) {
        var orgPolicy = _parseDmarcRecord(orgRec);
        orgPolicy.p = orgPolicy.sp || orgPolicy.p;
        policy = orgPolicy;
        policyOriginDomain = orgDomain;
        orgDomainPolicyApplied = true;
      }
    }

    // DMARCbis §4.7 — when the org-domain record carries `psd=y`, OR
    // the published record sits at the public suffix itself (TLD
    // operator), the receiver continues lookup at the public suffix
    // for downstream DSP cooperation. We honor the `psd=y` opt-in by
    // surfacing the tag so operators can route on it; the explicit
    // suffix walk below covers the suffix-record case.
    if (!policy) {
      var suffix = null;
      try { suffix = publicSuffix.publicSuffix(fromDomain); }
      catch (_e) { suffix = null; }
      if (suffix && suffix !== fromDomain && suffix !== orgDomain) {
        var psdRec = await _fetchDmarcRecord(suffix, opts.dnsLookup);
        if (psdRec) {
          var psdPolicy = _parseDmarcRecord(psdRec);
          if (psdPolicy.psd === "y") {
            psdPolicy.p = psdPolicy.sp || psdPolicy.p;
            policy = psdPolicy;
            policyOriginDomain = suffix;
            psdPolicyApplied = true;
          }
        }
      }
    }
  } catch (e) {
    return { result: "temperror", explanation: e.message,
             policy: null, alignment: { spf: false, dkim: false },
             orgDomain: orgDomain };
  }
  if (!policy) {
    return { result: "none", explanation: "no DMARC record at _dmarc." + fromDomain,
             policy: null, alignment: { spf: false, dkim: false },
             orgDomain: orgDomain };
  }

  // DMARCbis §4.8 — non-existent subdomain (NXDOMAIN on MX/A/AAAA for
  // the message-from domain) gets the np= policy when published. The
  // operator wires the existence check via opts.domainExists; absent
  // that callback we conservatively treat the domain as existing
  // (the np= path is opt-in observability, not a downgrade gate).
  var npApplied = false;
  if (typeof policy.np === "string" && typeof opts.domainExists === "function" &&
      orgDomainPolicyApplied) {
    var exists = true;
    try { exists = await opts.domainExists(fromDomain); }
    catch (_e) { exists = true; }
    if (exists === false) {
      policy = Object.assign({}, policy, { p: policy.np });
      npApplied = true;
    }
  }

  var spfDomain = (opts.spf && opts.spf.domain) || null;
  var dkimResults = Array.isArray(opts.dkim) ? opts.dkim : (opts.dkim ? [opts.dkim] : []);

  var spfAligned = opts.spf && opts.spf.result === "pass" &&
                   _alignmentCheck(fromDomain, spfDomain, policy.aspf);
  var dkimAligned = false;
  for (var i = 0; i < dkimResults.length; i += 1) {
    var d = dkimResults[i];
    if (d && d.result === "pass" &&
        _alignmentCheck(fromDomain, d.d || d.domain, policy.adkim)) {
      dkimAligned = true;
      break;
    }
  }

  var pass = spfAligned || dkimAligned;
  // RFC 7489 §6.6.4 — pct= MUST be consulted when the disposition is
  // not "deliver". When pct is < 100 the receiver applies the policy
  // to that fraction of failing messages and the rest gets the next-
  // less-strict disposition (reject → quarantine; quarantine → none).
  //
  // Sampling determinism: a single message MUST receive the same
  // sampled/not-sampled verdict across retries. `Math.random()` re-
  // rolls per-call so the receiver's first attempt could deliver
  // (sampled=true → quarantine→none) while a retry rejected — leading
  // to inconsistent disposition for the same SMTP envelope. Derive
  // the sample roll from a stable per-message key (operator-supplied
  // `pctSampleKey` — typically the Message-ID + From-domain + a
  // receiver-side secret) hashed via SHAKE256, mapped to [0,100). When
  // the operator doesn't supply a key we fall back to a per-call
  // crypto.randomInt — still cryptographically uniform, just not
  // retry-stable. The fallback is the framework's hardening floor
  // (replaces Math.random); retry-stability requires the operator to
  // wire a key.
  var pctRaw = parseInt(policy.pct, 10);                                                       // pct percentage, not bytes
  var pct = isFinite(pctRaw) && pctRaw >= 0 && pctRaw <= 100 ? pctRaw : 100;                    // pct percentage, not bytes
  var sampleRoll;
  if (typeof opts.pctSampleKey === "string" && opts.pctSampleKey.length > 0) {
    // Deterministic per-message sample roll. SHAKE256 → first 4 bytes
    // → uint32 → modulo 100. 4 bytes is far in excess of the
    // information needed for 0..99 and uniform mapping is fine.
    var hash = nodeCrypto.createHash("shake256", { outputLength: 4 })
                          .update(String(opts.pctSampleKey)).digest();
    var u32 = (hash[0] << 24 >>> 0) + (hash[1] << 16) + (hash[2] << 8) + hash[3];               // uint32 bit assembly
    sampleRoll = u32 % 100;                                                                     // pct sample roll
  } else {
    sampleRoll = bCrypto.randomInt(0, 100);                                                     // pct sample roll
  }
  var sampled = !pass && pct < 100 && sampleRoll >= pct;
  var recommendedAction = pass ? "deliver" :
                          sampled
                            ? (policy.p === "reject" ? "quarantine" :
                               policy.p === "quarantine" ? "none" : "deliver")
                            : (policy.p === "reject"     ? "reject" :
                               policy.p === "quarantine" ? "quarantine" :
                               "deliver");

  return {
    result:     pass ? "pass" : "fail",
    policy:     policy,
    policyOriginDomain:    policyOriginDomain,
    orgDomain:             orgDomain,
    orgDomainPolicyApplied: orgDomainPolicyApplied,
    psdPolicyApplied:      psdPolicyApplied,
    npPolicyApplied:       npApplied,
    alignment:  { spf: spfAligned, dkim: dkimAligned },
    recommendedAction: recommendedAction,
    explanation: pass
      ? "aligned via " + (spfAligned ? "spf" : "dkim")
      : "no aligned authentication; policy=" + policy.p,
  };
}

// ---- ARC (RFC 8617) — full per-hop verification ----
//
// Each hop carries three headers — ARC-Authentication-Results (AAR),
// ARC-Message-Signature (AMS), ARC-Seal (AS). AMS verifies the
// message body + selected headers (DKIM-shaped signature). AS signs
// the chain-of-custody (all prior AAR/AMS/AS headers + own AAR/AMS
// with empty b=). Verification follows §5.1.1 (AMS) + §5.1.2 (AS).

function _splitHeaders(rfc822) {
  var sep = rfc822.indexOf("\r\n\r\n");
  if (sep === -1) sep = rfc822.indexOf("\n\n");
  if (sep === -1) {
    throw new MailAuthError("mail-auth/arc-no-body",
      "ARC: message has no header/body separator");
  }
  return rfc822.slice(0, sep);
}

function _parseHeaderLines(headerSection) {
  // Unfold multi-line headers (lines starting with whitespace).
  var lines = headerSection.split(/\r?\n/);
  var unfolded = [];
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0) continue;
    if ((line.charAt(0) === " " || line.charAt(0) === "\t") && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += " " + line.replace(/^\s+/, "");
    } else {
      unfolded.push(line);
    }
  }
  return unfolded;
}

// RFC 8617 §5.1.2 caps the chain at 50 sets to bound verifier work and
// limit how far an attacker can push junk headers.
var ARC_MAX_HOPS = 50;                                                           // RFC 8617 §5.1.2 chain ceiling

async function arcVerify(rfc822, opts) {
  if (typeof rfc822 !== "string" || rfc822.length === 0) {
    throw new MailAuthError("mail-auth/arc-bad-input",
      "arc.verify: rfc822 must be a non-empty string");
  }
  opts = opts || {};
  var headers = _parseHeaderLines(_splitHeaders(rfc822));
  var hops = [];
  var seenSlot = {};                                                             // {`<instance>:<name>`: true} — duplicate detection

  // 1. Index ARC headers by instance number. Refuse duplicates: a single
  //    hop has exactly one ARC-Seal / ARC-Message-Signature /
  //    ARC-Authentication-Results. A second copy at the same instance is
  //    a malformed chain (per RFC 8617 §5.1 implicit, and a known
  //    injection vector — a forwarder that re-signs with a duplicate
  //    instance would silently overwrite the original signer).
  var duplicate = false;
  var maxInstanceSeen = 0;
  // RFC 8617 §5.2 — verifier MUST process the chain starting with the
  // highest-instance set, then walk down. Each hop prepends its three
  // headers (AS, AMS, AAR) to the message, so the source order from
  // top to bottom is: i=N (AS, AMS, AAR), i=N-1 (...), ..., i=1.
  // A chain whose source order doesn't decrease has been re-shuffled
  // by an intermediary that didn't follow §5.1, or is forged. Track
  // per-header-set first-appearance order and enforce strictly-
  // decreasing instances.
  var orderTrail = [];                       // [{ inst, name, idx }]
  for (var i = 0; i < headers.length; i += 1) {
    var line = headers[i];
    var khv = structuredFields.parseKeyValuePiece(line, ":");
    if (khv.value === null) continue;
    var name = khv.key;
    var value = khv.value.trim();
    if (name !== "arc-seal" && name !== "arc-message-signature" &&
        name !== "arc-authentication-results") continue;
    // ARC hop instance per RFC 8617 §4.2.1 — bounded to 3 digits; the
    // spec doesn't define a hard ceiling but operational use never
    // exceeds 50 hops, and a 999-hop limit prevents pathological
    // header values from chewing the verifier.
    var iMatch = value.match(/(?:^|[;,\s])i=(\d{1,3})\b/);
    var inst = iMatch ? parseInt(iMatch[1], 10) : null;
    if (inst === null || !isFinite(inst) || inst < 1) continue;
    if (inst > maxInstanceSeen) maxInstanceSeen = inst;
    var slotKey = inst + ":" + name;
    if (seenSlot[slotKey]) { duplicate = true; continue; }
    seenSlot[slotKey] = true;
    if (!hops[inst - 1]) hops[inst - 1] = { instance: inst };
    hops[inst - 1][name] = value;
    orderTrail.push({ inst: inst, name: name, idx: i });
  }

  // Source-order enforcement (RFC 8617 §5.1 + §5.2): the first AS for
  // a given hop must appear before its AMS, which must appear before
  // its AAR (within a single set). Across sets, hop instances MUST
  // strictly decrease top-to-bottom. Use the first-appearance index
  // per hop to validate the cross-set ordering; an out-of-order chain
  // is treated as a structural failure rather than risking a permissive
  // verdict.
  var orderFail = null;
  if (orderTrail.length > 0) {
    // Per-hop first-appearance: which i= instance owns each contiguous
    // run? Walk top to bottom and confirm the instance numbers, when
    // they change, only EVER decrease.
    var prevInst = null;
    for (var oi = 0; oi < orderTrail.length; oi += 1) {
      var cur = orderTrail[oi].inst;
      if (prevInst !== null && cur > prevInst) {
        orderFail = "header-order-ascending-i=" + cur + "-after-i=" + prevInst;
        break;
      }
      prevInst = cur;
    }
  }

  if (hops.length === 0) {
    return { chainStatus: "none", hopCount: 0, hops: [] };
  }

  if (duplicate) {
    return {
      chainStatus: "fail",
      reason:      "duplicate-instance",
      hopCount:    hops.filter(Boolean).length,
      hops: hops.filter(Boolean).map(function (h) {
        return { instance: h.instance,
                 hasSeal: !!h["arc-seal"],
                 hasMessageSignature: !!h["arc-message-signature"],
                 hasAuthenticationResults: !!h["arc-authentication-results"],
                 amsResult: "skipped", asResult: "skipped" };
      }),
    };
  }

  if (orderFail) {
    return {
      chainStatus: "fail",
      reason:      "header-order-violation: " + orderFail,
      hopCount:    hops.filter(Boolean).length,
      hops: hops.filter(Boolean).map(function (h) {
        return { instance: h.instance,
                 hasSeal: !!h["arc-seal"],
                 hasMessageSignature: !!h["arc-message-signature"],
                 hasAuthenticationResults: !!h["arc-authentication-results"],
                 amsResult: "skipped", asResult: "skipped" };
      }),
    };
  }

  if (maxInstanceSeen > ARC_MAX_HOPS) {
    return {
      chainStatus: "fail",
      reason:      "too-many-hops",
      hopCount:    maxInstanceSeen,
      hops:        [],
    };
  }

  // 2. Structural check — every hop must carry all three headers AND
  //    the chain must start at i=1 with no gaps. RFC 8617 §5.1 requires
  //    instances to form a contiguous 1..N sequence. Indexed loop (not
  //    .some) because sparse arrays skip empty slots in callbacks —
  //    a non-contiguous chain ([hop1, , hop3]) would silently pass.
  var structuralFail = false;
  for (var sci = 0; sci < hops.length; sci += 1) {
    var sch = hops[sci];
    if (!sch || !sch["arc-seal"] || !sch["arc-message-signature"] ||
        !sch["arc-authentication-results"]) {
      structuralFail = true;
      break;
    }
  }
  if (structuralFail) {
    return {
      chainStatus: "fail",
      reason:      "incomplete-or-non-contiguous",
      hopCount:    hops.filter(Boolean).length,
      hops: hops.filter(Boolean).map(function (h) {
        return { instance: h.instance,
                 hasSeal: !!h["arc-seal"],
                 hasMessageSignature: !!h["arc-message-signature"],
                 hasAuthenticationResults: !!h["arc-authentication-results"],
                 amsResult: "skipped", asResult: "skipped" };
      }),
    };
  }

  // 3. Per-hop AMS + AS verification.
  var perHop = [];
  var anyFail = false;
  // RFC 8617 §5.2 — operator-tunable clock skew on t= (signing
  // timestamp) and x= (expiration) tags. Default 5 min.
  var arcClockSkewMs = typeof opts.clockSkewMs === "number" && opts.clockSkewMs >= 0           // allow:numeric-opt-Infinity — operator-supplied skew, default 5 min
    ? opts.clockSkewMs : C.TIME.minutes(5);
  var nowSec = Math.floor(Date.now() / 1000);                                                  // Unix epoch seconds divisor

  for (var hopIdx = 0; hopIdx < hops.length; hopIdx += 1) {
    var hop = hops[hopIdx];

    // RFC 8617 §5.2 — verifier MUST reject AMS or AS with t= timestamp
    // in the future or x= expiration in the past (with operator skew
    // tolerance). Pre-v0.8.17 the verifier parsed t= but never
    // enforced it.
    var amsTags = _parseArcTagList(hop["arc-message-signature"]);
    var asTags  = _parseArcTagList(hop["arc-seal"]);
    var amsT = amsTags.t ? parseInt(amsTags.t, 10) : null;
    var amsX = amsTags.x ? parseInt(amsTags.x, 10) : null;
    var asT  = asTags.t  ? parseInt(asTags.t, 10)  : null;
    var asX  = asTags.x  ? parseInt(asTags.x, 10)  : null;
    var skewSec = Math.floor(arcClockSkewMs / 1000);                                          // sec divisor
    var timeFault = null;
    if (amsT && isFinite(amsT) && amsT - skewSec > nowSec) timeFault = "ams-t-future";
    if (amsX && isFinite(amsX) && amsX + skewSec < nowSec) timeFault = "ams-x-expired";
    if (asT  && isFinite(asT)  && asT  - skewSec > nowSec) timeFault = "as-t-future";
    if (asX  && isFinite(asX)  && asX  + skewSec < nowSec) timeFault = "as-x-expired";

    // AMS — RFC 8617 §5.1.1. Same shape as a DKIM-Signature; reuses
    // the DKIM verifier by injecting a temporary message that has
    // the AMS as the signing header.
    var amsResult = timeFault
      ? { result: "fail", errors: ["ams: " + timeFault + " (RFC 8617 §5.2)"] }
      : await _verifyArc(rfc822, hop, hops, "ams", opts.dnsLookup, dkim);

    // AS — RFC 8617 §5.1.2. Signs the catenation of all prior
    // ARC-{AAR,AMS,AS} headers plus current AAR + AMS, then the AS
    // itself with empty b=.
    var asResult = timeFault
      ? { result: "fail", errors: ["as: " + timeFault + " (RFC 8617 §5.2)"] }
      : await _verifyArc(rfc822, hop, hops, "as", opts.dnsLookup, dkim);

    perHop.push({
      instance:                 hop.instance,
      hasSeal:                  true,
      hasMessageSignature:      true,
      hasAuthenticationResults: true,
      amsResult:                amsResult.result,
      asResult:                 asResult.result,
      amsErrors:                amsResult.errors,
      asErrors:                 asResult.errors,
    });
    if (amsResult.result !== "pass" || asResult.result !== "pass") anyFail = true;
  }

  // 4. Chain Validation per RFC 8617 §5.2.
  //
  //    Per-hop cv= self-attestation rules:
  //      i=1   — cv=none REQUIRED (no upstream chain to validate)
  //      i>=2  — cv=pass or cv=fail; cv=none is invalid at i>=2
  //
  //    Once any hop's AS reports cv=fail, the chain is permanently
  //    broken — downstream cv=pass claims after an upstream cv=fail
  //    are malformed (a hop can't claim the chain validates when it
  //    knows an earlier hop saw it fail).
  var perHopCv = [];
  var hopRuleViolation = null;
  var sawFail = false;
  for (var hi = 0; hi < hops.length; hi += 1) {
    var as = hops[hi]["arc-seal"];
    var hopCvMatch = as.match(/(?:^|[;,\s])cv=(none|pass|fail)/);
    var hopCv = hopCvMatch ? hopCvMatch[1] : null;
    perHopCv.push(hopCv);
    if (hopCv === null) {
      hopRuleViolation = "missing-cv-at-i=" + (hi + 1);
      break;
    }
    if (hi === 0 && hopCv !== "none") {
      hopRuleViolation = "i=1-cv-must-be-none-got-" + hopCv;
      break;
    }
    if (hi >= 1 && hopCv === "none") {
      hopRuleViolation = "i=" + (hi + 1) + "-cv=none-invalid-after-hop-1";
      break;
    }
    if (hopCv === "fail") sawFail = true;
    if (hopCv === "pass" && sawFail) {
      hopRuleViolation = "i=" + (hi + 1) + "-cv=pass-after-upstream-fail";
      break;
    }
  }

  var lastCv = perHopCv[perHopCv.length - 1];
  var chainStatus;
  var reasonOut = null;
  if (hopRuleViolation) {
    chainStatus = "fail";
    reasonOut = hopRuleViolation;
  } else if (anyFail) {
    chainStatus = "fail";
    reasonOut = "signature-verification-failed";
  } else if (lastCv === "fail") {
    chainStatus = "fail";
    reasonOut = "last-as-cv=fail";
  } else if (hops.length === 1 && lastCv === "none") {
    chainStatus = "pass";
  } else if (hops.length > 1 && lastCv === "pass") {
    chainStatus = "pass";
  } else {
    chainStatus = "fail";
    reasonOut = "unexpected-cv-state";
  }

  var out = {
    chainStatus: chainStatus,
    hopCount:    hops.length,
    cv:          lastCv,
    perHopCv:    perHopCv,
    hops:        perHop,
  };
  if (reasonOut) out.reason = reasonOut;
  return out;
}

// Verify a single AMS or AS within the chain by reconstructing the
// signed string per RFC 8617 + invoking node:crypto.verify with the
// public key fetched from the AMS's d= + s= TXT record.
async function _verifyArc(rfc822, hop, allHops, kind, dnsLookup, dkim) {
  var sigHeaderName = kind === "ams" ? "arc-message-signature" : "arc-seal";
  var sigValue = hop[sigHeaderName];
  var tags = _parseArcTagList(sigValue);
  if (!tags.d || !tags.s || !tags.b || !tags.a) {
    return { result: "permerror", errors: [kind + ": missing required tag(s) d/s/b/a"] };
  }
  if (tags.a !== "rsa-sha256" && tags.a !== "ed25519-sha256") {
    return { result: "permerror", errors: [kind + ": unsupported alg '" + tags.a + "'"] };
  }

  // Fetch the signing public key from <s>._domainkey.<d>.
  var keyTags;
  try {
    var qname = tags.s + "._domainkey." + tags.d;
    var records = await _safeResolveTxt(qname, dnsLookup);
    keyTags = _parseDkimKeyRecord(records);
  } catch (e) {
    var verdict = (e && (e.code === "ENOTFOUND" || e.code === "ENODATA"))
                  ? "permerror" : "temperror";
    return { result: verdict, errors: [kind + ": key lookup failed: " +
             ((e && e.message) || String(e))] };
  }
  if (!keyTags || !keyTags.p) {
    return { result: "permerror", errors: [kind + ": key record missing p="] };
  }

  // Reconstruct the canonical signed string.
  var canonicalized;
  if (kind === "ams") {
    // AMS signs the body + selected headers, identical to DKIM-Sig.
    // Reuse the DKIM verifier by passing a synthetic message where
    // the AMS header is renamed to DKIM-Signature.
    return await _verifyAmsViaDkim(rfc822, hop, sigValue, tags, dkim, dnsLookup);
  }

  // AS signs the catenation of every prior AAR/AMS/AS plus current
  // AAR/AMS, then the AS itself with empty b= per RFC 8617 §5.1.2.
  canonicalized = "";
  for (var prior = 0; prior < hop.instance; prior += 1) {
    var p = allHops[prior];
    if (!p) continue;
    canonicalized += _canonRelaxedHeader("ARC-Authentication-Results", p["arc-authentication-results"]);
    canonicalized += _canonRelaxedHeader("ARC-Message-Signature",      p["arc-message-signature"]);
    if (p.instance !== hop.instance) {
      // Prior AS gets included whole.
      canonicalized += _canonRelaxedHeader("ARC-Seal", p["arc-seal"]);
    }
  }
  // Current AS with b= emptied. RFC 8617 §5.1.2: canonicalization
  // includes the AS header with `b=` value stripped + no trailing CRLF.
  var asUnsigned = sigValue.replace(/(\bb=)[^;]*/i, "$1");
  canonicalized += _canonRelaxedHeader("ARC-Seal", asUnsigned).replace(/\r\n$/, "");

  // Verify the AS signature.
  return _runVerify(canonicalized, tags.b, tags.a, keyTags.p, "as");
}

async function _verifyAmsViaDkim(rfc822, hop, sigValue, tags, dkim, dnsLookup) {
  // Build a synthetic rfc822 where the ARC-Message-Signature is renamed
  // to DKIM-Signature so the existing DKIM verifier handles AMS
  // verification (the cryptographic shape is identical).
  var renamedHeader = "DKIM-Signature: " + sigValue;
  var sep = rfc822.indexOf("\r\n\r\n");
  if (sep === -1) sep = rfc822.indexOf("\n\n");
  var headerEnd = sep === -1 ? rfc822.length : sep;
  // Strip every other ARC-* header so the DKIM verifier doesn't see
  // them, AND replace the AMS itself with DKIM-Signature for this hop.
  var headerLines = _parseHeaderLines(rfc822.slice(0, headerEnd));
  var rebuilt = [];
  for (var i = 0; i < headerLines.length; i += 1) {
    var line = headerLines[i];
    var khv = structuredFields.parseKeyValuePiece(line, ":");
    if (khv.value === null) { rebuilt.push(line); continue; }
    var name = khv.key;
    if (name === "arc-message-signature" ||
        name === "arc-seal" ||
        name === "dkim-signature") {
      continue;
    }
    if (name === "arc-authentication-results") {
      // RFC 8617 §5.1.1 — keep only the CURRENT hop's AAR (signer
      // canonicalizes it via h=). Pre-v0.8.17 stripped every AAR
      // unconditionally, breaking verification on chains that
      // included AAR in h= (Microsoft + Google interop).
      var instMatch = /\bi\s*=\s*(\d+)/.exec(khv.value);
      if (!instMatch || parseInt(instMatch[1], 10) !== hop.instance) continue;
    }
    rebuilt.push(line);
  }
  rebuilt.unshift(renamedHeader);
  var synthetic = rebuilt.join("\r\n") + (sep === -1 ? "" :
    rfc822.slice(headerEnd));
  var rv = await dkim.verify(synthetic, { dnsLookup: dnsLookup });
  if (!Array.isArray(rv) || rv.length === 0) {
    return { result: "permerror", errors: ["ams: dkim verifier returned no results"] };
  }
  return { result: rv[0].result, errors: rv[0].errors || [] };
}

function _parseArcTagList(value) {
  // RFC 8617 §4 ARC tag-list grammar (same as DKIM's): `tag-spec *( ";"
  // tag-spec )`, tag-value contains no DQUOTE, FWS inside a value ignored.
  var pairs = structuredFields.parseTagList(value, { stripValueWs: true });
  var tags = {};
  for (var i = 0; i < pairs.length; i += 1) tags[pairs[i][0]] = pairs[i][1];
  return tags;
}

function _parseDkimKeyRecord(records) {
  var joined = "";
  if (Array.isArray(records)) {
    for (var i = 0; i < records.length; i += 1) {
      var rec = records[i];
      joined = Array.isArray(rec) ? rec.join("") : String(rec);
      if (joined.indexOf("v=DKIM1") === 0 || joined.indexOf("p=") !== -1) break;
    }
  } else {
    joined = String(records || "");
  }
  return _parseArcTagList(joined);
}

function _canonRelaxedHeader(name, value) {
  // RFC 6376 §3.4.2 relaxed header canon — shared with the DKIM signer/verifier
  // so the DMARC/ARC paths reach a byte-identical canon (RFC 8617 §5.1.1).
  return dkim.canonHeaderRelaxed(name, value);
}

function _pemFromB64KeyMaterial(b64) {
  var pem = "-----BEGIN PUBLIC KEY-----\n";
  for (var i = 0; i < b64.length; i += 64) {                                     // PEM wrap width
    pem += b64.slice(i, i + 64) + "\n";                                          // PEM wrap width
  }
  pem += "-----END PUBLIC KEY-----\n";
  return pem;
}

function _runVerify(signedString, sigB64, algorithm, keyB64, label) {
  var nodeCrypto = require("node:crypto");
  var pem = _pemFromB64KeyMaterial(keyB64);
  var keyObj;
  try { keyObj = nodeCrypto.createPublicKey(pem); }
  catch (e) {
    return { result: "permerror",
             errors: [label + ": key parse failed: " + ((e && e.message) || String(e))] };
  }
  var nodeAlgo = algorithm === "rsa-sha256" ? "sha256" : null;
  var sigBuf = Buffer.from(sigB64, "base64");
  var verified;
  try {
    verified = nodeCrypto.verify(nodeAlgo, Buffer.from(signedString, "utf8"), keyObj, sigBuf);
  } catch (e) {
    return { result: "permerror",
             errors: [label + ": verify threw: " + ((e && e.message) || String(e))] };
  }
  return verified
    ? { result: "pass", errors: [] }
    : { result: "fail", errors: [label + ": signature verification failed"] };
}

void C; // C is imported for future TIME constants in policy fetchers.

// ---- ARC receiver-side trust evaluation (RFC 8617 §6) ----
//
// arc.verify confirms the cryptographic chain validates; arc.evaluate
// is the operator-side trust decision: given a passing chain, did any
// hop in the chain belong to a sealer the operator trusts? The trust
// list is operator policy — typically the operator's own domain plus
// upstream relays the operator has agreed to honor (mailing list
// operators, MX-vendor middleware).
//
//   var rv = await b.mail.arc.evaluate(rfc822, {
//     trustedSealers: ["example.com", "mailgun.net"],
//   });
//   // → { chainStatus: "pass", trusted: true, trustedHop: 2,
//   //    trustedDomain: "mailgun.net" }

async function arcEvaluate(rfc822, opts) {
  if (typeof rfc822 !== "string" || rfc822.length === 0) {
    throw new MailAuthError("mail-auth/arc-bad-input",
      "arc.evaluate: rfc822 must be a non-empty string");
  }
  opts = opts || {};
  if (!Array.isArray(opts.trustedSealers)) {
    throw new MailAuthError("mail-auth/arc-bad-trusted-sealers",
      "arc.evaluate: opts.trustedSealers must be an array of domain strings");
  }
  var trusted = {};
  for (var ti = 0; ti < opts.trustedSealers.length; ti += 1) {
    var d = opts.trustedSealers[ti];
    if (typeof d !== "string" || d.length === 0) {
      throw new MailAuthError("mail-auth/arc-trust-eval-failed",
        "arc.evaluate: trustedSealers[" + ti + "] must be a non-empty domain string");
    }
    trusted[d.toLowerCase()] = true;
  }

  var verdict = await arcVerify(rfc822, opts);
  var out = {
    chainStatus:    verdict.chainStatus,
    hopCount:       verdict.hopCount,
    trusted:        false,
    trustedHop:     null,
    trustedDomain:  null,
    // RFC 8617 §6 trust evaluation extension surface (B6).
    //   trust:        "trusted" | "unverified" | "failed"
    //   trustedHops:  [{ instance, domain }] of every trusted sealer
    //                 in the validated chain
    //   finalAr:      verbatim AAR from the most-recent hop (the
    //                 receiver's view of upstream auth results)
    //   breakAt:      first instance whose AMS or AS failed, or null
    //                 when every hop verified
    trust:          verdict.chainStatus === "pass" ? "unverified" : "failed",
    trustedHops:    [],
    finalAr:        null,
    breakAt:        null,
  };
  if (verdict.reason) out.reason = verdict.reason;

  // Re-extract per-hop d= (signing domain on AS) AND the AAR text from
  // the original headers — the verify-result shape doesn't carry
  // them. One pass over the header section.
  var headers = _parseHeaderLines(_splitHeaders(rfc822));
  var hopDomains = {};
  var hopAr = {};
  for (var hi = 0; hi < headers.length; hi += 1) {
    var line = headers[hi];
    var khv = structuredFields.parseKeyValuePiece(line, ":");
    if (khv.value === null) continue;
    var name = khv.key;
    var value = khv.value.trim();
    if (name === "arc-seal") {
      var iMatch = value.match(/(?:^|[;,\s])i=(\d+)/);                            // allow:regex-no-length-cap — header bounded by RFC 5322 998
      var dMatch = value.match(/(?:^|[;,\s])d=([^\s;]+)/);                        // allow:regex-no-length-cap — header bounded by RFC 5322 998
      if (iMatch && dMatch) hopDomains[parseInt(iMatch[1], 10)] = dMatch[1].toLowerCase();
    } else if (name === "arc-authentication-results") {
      var arIMatch = value.match(/\bi\s*=\s*(\d+)/);                              // allow:regex-no-length-cap — header bounded by RFC 5322 998
      if (arIMatch) hopAr[parseInt(arIMatch[1], 10)] = value;
    }
  }

  // finalAr — the most-recent hop's AAR. Always populated when the
  // chain has at least one hop (regardless of pass/fail), so the
  // operator can surface upstream auth context even on a broken chain.
  if (verdict.hopCount > 0) {
    out.finalAr = hopAr[verdict.hopCount] || null;
  }

  // breakAt — first instance whose AMS or AS failed.
  if (Array.isArray(verdict.hops)) {
    for (var bi = 0; bi < verdict.hops.length; bi += 1) {
      var bhop = verdict.hops[bi];
      if (!bhop) continue;
      if (bhop.amsResult !== "pass" || bhop.asResult !== "pass") {
        out.breakAt = bhop.instance;
        break;
      }
    }
  }

  if (verdict.chainStatus !== "pass" || !Array.isArray(verdict.hops)) return out;

  // Walk hops most-recent-first so we attribute the primary trust
  // decision to the deepest (closest-to-receiver) trusted sealer, but
  // also collect EVERY trusted hop so the operator can audit the
  // full custody chain.
  for (var ri2 = verdict.hops.length - 1; ri2 >= 0; ri2 -= 1) {
    var hop = verdict.hops[ri2];
    if (!hop || hop.amsResult !== "pass" || hop.asResult !== "pass") continue;
    var domain = hopDomains[hop.instance];
    if (domain && trusted[domain]) {
      out.trustedHops.push({ instance: hop.instance, domain: domain });
      if (!out.trusted) {
        out.trusted = true;
        out.trustedHop = hop.instance;
        out.trustedDomain = domain;
      }
    }
  }
  out.trust = out.trusted ? "trusted" : "unverified";
  return out;
}

// ---- Authentication-Results header (RFC 8601) builder ----
//
// Build the A-R header value the receiving MTA prepends to the message
// before delivery. Operators consume per-method results from
// b.mail.spf.verify / b.mail.dmarc.evaluate / b.mail.arc.verify (or
// .evaluate) and pass them to .emit; the framework formats the RFC
// 8601-conformant header string.
//
//   var hdr = b.mail.authResults.emit({
//     authservId: "mx.example.com",
//     results: [
//       { method: "spf",   result: "pass", smtpMailfrom: "user@sender.example" },
//       { method: "dkim",  result: "pass", domain: "sender.example" },
//       { method: "dmarc", result: "pass", from: "user@sender.example" },
//       { method: "arc",   result: "pass" },
//     ],
//   });
//   // → "Authentication-Results: mx.example.com;\r\n  spf=pass smtp.mailfrom=user@sender.example;\r\n  dkim=pass header.d=sender.example;\r\n  dmarc=pass header.from=user@sender.example;\r\n  arc=pass"

// RFC 8601 §2.7 — result vocabulary is METHOD-SPECIFIC, not a flat
// allowlist. The flat AR_VALID_RESULTS table previously accepted
// `hardfail` for DKIM (only valid for DMARC §2.7.4) and `temperror` /
// `permerror` for methods that don't recognize them. Per-method maps
// match the spec sections cited.
var AR_RESULTS_BY_METHOD = {
  // §2.7.1 — auth
  auth:           { pass: 1, fail: 1, none: 1, permerror: 1, temperror: 1 },
  // §2.7.2 — domainkeys (legacy; vocabulary kept narrow)
  domainkeys:     { pass: 1, fail: 1, neutral: 1, none: 1, permerror: 1, temperror: 1, policy: 1 },
  // §2.7.3 — DKIM
  dkim:           { pass: 1, fail: 1, neutral: 1, none: 1, permerror: 1, temperror: 1, policy: 1 },
  "dkim-adsp":    { pass: 1, fail: 1, discard: 1, nxdomain: 1, none: 1, permerror: 1, temperror: 1 },
  // §2.7.4 — SPF (uses softfail; not hardfail)
  spf:            { pass: 1, fail: 1, softfail: 1, neutral: 1, none: 1, permerror: 1, temperror: 1, policy: 1 },
  "sender-id":    { pass: 1, fail: 1, softfail: 1, neutral: 1, none: 1, permerror: 1, temperror: 1, policy: 1 },
  // §2.7.5 — IPRev
  iprev:          { pass: 1, fail: 1, permerror: 1, temperror: 1 },
  // §2.7.6 — DMARC (this is the ONE place hardfail is valid in some drafts; keep it)
  dmarc:          { pass: 1, fail: 1, none: 1, permerror: 1, temperror: 1, hardfail: 1, bestguesspass: 1 },
  // RFC 8617 §4.1 — ARC
  arc:            { pass: 1, fail: 1, none: 1 },
  // RFC 8616 — DANE
  dane:           { pass: 1, fail: 1, none: 1, permerror: 1, temperror: 1 },
  // VBR + DNSWL + S/MIME — vocabulary kept conservative
  smime:          { pass: 1, fail: 1, neutral: 1, none: 1, permerror: 1, temperror: 1, policy: 1 },
  vbr:            { pass: 1, fail: 1, none: 1, permerror: 1, temperror: 1 },
  dnswl:          { pass: 1, none: 1, temperror: 1 },
  "x-original-authentication-results": { pass: 1, fail: 1, neutral: 1, none: 1, softfail: 1, hardfail: 1, policy: 1, permerror: 1, temperror: 1, bestguesspass: 1, discard: 1, nxdomain: 1 },
};
var AR_VALID_METHODS = Object.keys(AR_RESULTS_BY_METHOD).reduce(function (acc, m) {
  acc[m] = 1; return acc;
}, {});

function authResultsEmit(opts) {
  validateOpts.requireObject(opts, "authResults.emit", MailAuthError, "mail-auth/ar-bad-input");
  validateOpts(opts, ["authservId", "results", "version", "fold"], "authResults.emit");
  validateOpts.requireNonEmptyString(opts.authservId,
    "authResults.emit: authservId", MailAuthError, "mail-auth/ar-bad-authserv-id");
  if (/[\r\n\0]/.test(opts.authservId)) {
    throw new MailAuthError("mail-auth/ar-bad-authserv-id",
      "authResults.emit: authservId contains forbidden control characters");
  }
  if (!Array.isArray(opts.results)) {
    throw new MailAuthError("mail-auth/ar-bad-results",
      "authResults.emit: results must be an array");
  }

  var version = (opts.version === undefined || opts.version === null)
    ? "1" : String(opts.version);
  var head = opts.authservId + (version === "1" ? "" : " " + version);

  if (opts.results.length === 0) {
    // RFC 8601 §2.2 — when no methods evaluated, emit `none`.
    return "Authentication-Results: " + head + "; none";
  }

  var clauses = [];
  for (var i = 0; i < opts.results.length; i += 1) {
    var r = opts.results[i];
    if (!r || typeof r !== "object") {
      throw new MailAuthError("mail-auth/ar-bad-result-entry",
        "authResults.emit: results[" + i + "] must be an object");
    }
    var method = String(r.method || "").toLowerCase();
    var result = String(r.result || "").toLowerCase();
    if (!AR_VALID_METHODS[method]) {
      throw new MailAuthError("mail-auth/ar-bad-method",
        "authResults.emit: unknown method '" + r.method + "'");
    }
    var methodResults = AR_RESULTS_BY_METHOD[method];
    if (!methodResults || !methodResults[result]) {
      throw new MailAuthError("mail-auth/ar-bad-result",
        "authResults.emit: result '" + r.result + "' is not in the RFC 8601 §2.7 vocabulary for method '" + method + "'");
    }
    var clause = method + "=" + result;
    if (r.reason && typeof r.reason === "string" && !/[\r\n\0;]/.test(r.reason)) {
      // RFC 8601 §2.2 — quoted-string allows backslash-escaped DQUOTE
      // (`\"`). Pre-v0.8.32 the framework collapsed `"` to `'` which
      // is lossy. Use the spec-correct escape so the receiver can
      // round-trip the original reason.
      clause += ' reason="' + r.reason.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
    }
    // Method-specific properties (ptype.property=value triples per
    // RFC 8601 §2.3). Operators pass them as flat object keys.
    var props = {
      smtpMailfrom: "smtp.mailfrom",
      smtpHelo:     "smtp.helo",
      domain:       "header.d",
      selector:     "header.s",
      from:         "header.from",
      iprev:        "policy.iprev",
      ip:           "policy.ip",
      tls:          "policy.tls",
    };
    var propKeys = Object.keys(props);
    for (var pk = 0; pk < propKeys.length; pk += 1) {
      var k = propKeys[pk];
      var rv = r[k];
      if (typeof rv !== "string" || rv.length === 0) continue;
      // pvalue ABNF per RFC 8601 §2.3:
      //   pvalue = [CFWS] ((value / dot-atom-text) [CFWS]) /
      //            (local-part "@" domain) [CFWS]
      // For framework emit we require the printable-ASCII subset of
      // dot-atom-text + local-part-at-domain shapes; CRLF / NUL /
      // semicolon / SP / HTAB / quoting metacharacters are refused
      // (operator-supplied value is structured, not free-form).
      if (!/^[A-Za-z0-9._@\-:[\]]+$/.test(rv)) continue;                            // allow:regex-no-length-cap — bounded by header line cap
      clause += " " + props[k] + "=" + rv;
    }
    clauses.push(clause);
  }

  var fold = opts.fold !== false;
  var sep = fold ? ";\r\n  " : "; ";
  return "Authentication-Results: " + head + ";\r\n  " + clauses.join(sep);
}

// ---- Inbound message-authentication pipeline (RFC 7489 §6.6) ----
//
// One call runs the receiver-side authentication set on a message as it
// arrives: SPF (RFC 7208) on the envelope identity, DKIM (RFC 6376) on
// the message bytes, DMARC (RFC 7489 / DMARCbis) policy + alignment on
// the From-header domain, and — when an authserv-id is supplied — the
// RFC 8601 Authentication-Results header the receiver prepends before
// delivery. b.mail.server.mx composes this at DATA time via its
// guardEnvelope opt; operators running their own listeners (or doing
// post-delivery verification in an agent) call it directly:
//
//   var v = await b.mail.inbound.verify({
//     ip:         "203.0.113.5",
//     helo:       "mail.sender.example",
//     mailFrom:   "bounce@sender.example",
//     message:    rfc5322Bytes,                  // string or Buffer
//     authservId: "mx.example.com",
//   });
//   // → { spf, dkim, from, dmarc, authResults }
//   if (v.dmarc.recommendedAction === "reject") { /* refuse 550 5.7.1 */ }
//
// From-header discipline (RFC 7489 §6.6.1): DMARC evaluates exactly one
// author domain. A message with zero From fields, several From fields,
// or several author addresses in one field is the header-duplication
// spoofing shape — an attacker pairs an aligned-but-hidden From with the
// one the mail client displays (the CVE-2024-7208 / CVE-2024-7209
// hosted-relay spoofing class rides on exactly this ambiguity). Those
// messages return `dmarc.result: "permerror"` with
// `recommendedAction: "reject"` instead of picking one of the Froms.

// RFC 5322 §2.1 — the header block ends at the first empty line. SMTP
// wire format is CRLF; bare-LF input is accepted defensively for
// operator-fed strings that lost CRs in their own tooling.
function _splitHeaderBlock(message) {
  var idx = message.indexOf("\r\n\r\n");
  if (idx !== -1) return { headers: message.slice(0, idx), body: message.slice(idx + 4) };
  idx = message.indexOf("\n\n");
  if (idx !== -1) return { headers: message.slice(0, idx), body: message.slice(idx + 2) };
  return { headers: message, body: "" };
}

// Quote-aware single pass over a From field value (RFC 5322 phrase
// quoting): counts angle-addr pairs that contain an `@` (a `<` inside
// a quoted-string is display-name text — `"John <Jr.> Smith" <u@d>`
// is one author, not two) and top-level commas (address-list
// separators; a comma inside a quoted display-name like
// `"Doe, John" <j@d>` does not count). Records the content of the
// last @-bearing angle-addr for extraction.
function _countFromAuthors(value) {
  var inQuote = false, inAngle = false, escaped = false;
  var angleAddrs = 0, topCommas = 0, angleStart = -1;
  var lastAddr = null;
  for (var i = 0; i < value.length; i += 1) {
    var ch = value.charAt(i);
    if (escaped) { escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (ch === "\"" && !inAngle) { inQuote = !inQuote; continue; }
    if (inQuote) continue;
    if (ch === "<" && !inAngle) { inAngle = true; angleStart = i; continue; }
    if (ch === ">" && inAngle) {
      inAngle = false;
      var inner = value.slice(angleStart + 1, i).trim();
      if (inner.indexOf("@") !== -1) { angleAddrs += 1; lastAddr = inner; }
      continue;
    }
    if (ch === "," && !inAngle) topCommas += 1;
  }
  return { angleAddrs: angleAddrs, topCommas: topCommas, lastAddr: lastAddr };
}

// Unfold (RFC 5322 §2.2.3), collect every From: field, and extract the
// author address. `count` is the number of From fields, widened by
// multiple-author detection inside a single field: several @-bearing
// angle-addrs, or a bare address-list separated by top-level commas
// (RFC 7489 §6.6.1 — a multi-author From is the header-duplication
// spoofing shape and must not have "one" author picked from it).
function _extractFromHeaders(headerBlock) {
  var unfolded = structuredFields.unfoldHeaderContinuations(headerBlock);
  var lines = unfolded.split(/\r?\n/);
  var fromValues = [];
  for (var i = 0; i < lines.length; i += 1) {
    var m = /^From[ \t]*:(.*)$/i.exec(lines[i]);
    if (m) fromValues.push(m[1].trim());
  }
  if (fromValues.length === 0) return { count: 0, address: null, domain: null };
  var count = fromValues.length;
  var value = fromValues[0];
  var authors = _countFromAuthors(value);
  if (count === 1) {
    if (authors.angleAddrs > 1) count = authors.angleAddrs;
    else if (authors.topCommas > 0) count = authors.topCommas + 1;
  }
  var address;
  if (authors.angleAddrs >= 1) {
    // count > 1 is refused by the caller before the address is used;
    // for the single-author case this is that author's angle-addr.
    address = authors.lastAddr;
  } else {
    // Bare addr-spec form. An RFC 5322 addr-spec cannot contain
    // whitespace or commas — their presence means an address list or
    // display-name soup; extracting "the" domain from it would pick
    // one of several authors (the §6.6.1 forbidden move), so the
    // field is treated as unparsable instead.
    address = value.trim();
    if (/[\s,]/.test(address)) address = null;
  }
  var at = address ? address.lastIndexOf("@") : -1;
  var domain = (at > 0 && address && at < address.length - 1)
    ? address.slice(at + 1).toLowerCase()
    : null;
  return { count: count, address: address || null, domain: domain };
}

async function inboundVerify(opts) {
  validateOpts.requireObject(opts, "inbound.verify", MailAuthError, "mail-auth/inbound-bad-input");
  validateOpts(opts, ["ip", "helo", "mailFrom", "message", "dnsLookup", "domainExists",
                       "maxSignatures", "clockSkewMs", "minRsaBits", "authservId"],
               "mail.inbound.verify");
  validateOpts.requireNonEmptyString(opts.ip, "inbound.verify: ip",
    MailAuthError, "mail-auth/inbound-bad-ip");
  if (opts.authservId !== undefined && opts.authservId !== null) {
    validateOpts.requireNonEmptyString(opts.authservId, "inbound.verify: authservId",
      MailAuthError, "mail-auth/inbound-bad-authserv-id");
  }
  var message = opts.message;
  if (Buffer.isBuffer(message)) {
    // DKIM canonicalization re-encodes the string form as UTF-8
    // (lib/mail-dkim.js hashes Buffer.from(canonicalized, "utf8")), so
    // the byte→string decode must be utf8 for valid-UTF-8 content to
    // round-trip exactly. Non-UTF-8 8-bit content cannot survive any
    // decode + utf8 re-encode; such messages verify as DKIM fail and
    // DMARC falls back to the SPF identity (RFC 7489 §4.2 — one
    // aligned authenticator is sufficient to pass).
    message = message.toString("utf8");
  }
  if (typeof message !== "string" || message.length === 0) {
    throw new MailAuthError("mail-auth/inbound-bad-message",
      "inbound.verify: message must be a non-empty string or Buffer (the full RFC 5322 message)");
  }
  var mailFrom = (typeof opts.mailFrom === "string" && opts.mailFrom.length > 0) ? opts.mailFrom : null;
  var helo     = (typeof opts.helo === "string" && opts.helo.length > 0) ? opts.helo : null;

  // SPF — envelope identity: MAIL FROM, falling back to HELO for the
  // null reverse-path (RFC 7208 §2.4). DNS failures surface as the
  // RFC's temperror result, not as throws.
  var spf;
  if (mailFrom || helo) {
    spf = await spfVerify({
      ip:        opts.ip,
      mailFrom:  mailFrom || undefined,
      helo:      helo || undefined,
      dnsLookup: opts.dnsLookup,
    });
  } else {
    spf = { result: "none", domain: null,
            explanation: "no MAIL FROM or HELO identity supplied", lookupCount: 0 };
  }

  // DKIM — every signature on the message (bounded by maxSignatures;
  // a signature-less message verifies as a single `none` entry).
  var dkimVerifyOpts = { dnsLookup: opts.dnsLookup };
  if (opts.clockSkewMs !== undefined) dkimVerifyOpts.clockSkewMs = opts.clockSkewMs;
  if (opts.maxSignatures !== undefined) dkimVerifyOpts.maxSignatures = opts.maxSignatures;
  if (opts.minRsaBits !== undefined) dkimVerifyOpts.minRsaBits = opts.minRsaBits;
  var dkimResults = await dkim.verify(message, dkimVerifyOpts);

  // From header + DMARC policy/alignment.
  var from = _extractFromHeaders(_splitHeaderBlock(message).headers);
  var dmarc;
  if (from.count === 1 && from.address && from.domain) {
    dmarc = await dmarcEvaluate({
      from:         from.address,
      spf:          spf,
      dkim:         dkimResults,
      dnsLookup:    opts.dnsLookup,
      domainExists: opts.domainExists,
    });
    // RFC 7489 §6.6.2 — a fail verdict computed while an authenticator
    // returned temperror is not final: the very lookup that failed
    // transiently could have produced the aligned pass. Surface
    // temperror so the caller defers (the sender retries) instead of
    // permanently refusing a legitimate sender during a DNS blip. A
    // pass verdict stands — one aligned authenticator is sufficient
    // regardless of the other's transient failure.
    if (dmarc.result === "fail" &&
        (spf.result === "temperror" ||
         dkimResults.some(function (d) { return d.result === "temperror"; }))) {
      dmarc.result            = "temperror";
      dmarc.recommendedAction = null;
      dmarc.explanation       = (dmarc.explanation ? dmarc.explanation + "; " : "") +
        "fail computed while an authenticator returned temperror — transient, retry";
    }
  } else {
    dmarc = {
      result:            "permerror",
      recommendedAction: "reject",
      policy:            null,
      alignment:         { spf: false, dkim: false },
      orgDomain:         null,
      explanation: from.count === 0
        ? "message has no From header (RFC 7489 §6.6.1)"
        : (from.count > 1
            ? "message carries " + from.count + " From authors (RFC 7489 §6.6.1 — multi-From spoofing shape)"
            : "From header has no parsable author domain"),
    };
  }

  // RFC 8601 Authentication-Results — only when the caller identifies
  // itself (the authserv-id is the receiver's own name; there is no
  // sensible default the framework could invent).
  var authResults = null;
  if (opts.authservId) {
    var arResults = [];
    var spfEntry = { method: "spf", result: spf.result };
    if (mailFrom) spfEntry.smtpMailfrom = mailFrom;
    else if (helo) spfEntry.smtpHelo = helo;
    arResults.push(spfEntry);
    for (var di = 0; di < dkimResults.length; di += 1) {
      var d = dkimResults[di];
      var dkimEntry = { method: "dkim", result: d.result };
      if (typeof d.d === "string" && d.d.length > 0) dkimEntry.domain = d.d;
      if (typeof d.s === "string" && d.s.length > 0) dkimEntry.selector = d.s;
      arResults.push(dkimEntry);
    }
    var dmarcEntry = { method: "dmarc", result: dmarc.result };
    if (from.address) dmarcEntry.from = from.address;
    arResults.push(dmarcEntry);
    authResults = authResultsEmit({ authservId: opts.authservId, results: arResults });
  }

  return { spf: spf, dkim: dkimResults, from: from, dmarc: dmarc, authResults: authResults };
}

// ---- DMARC aggregate (RUA) report parser (RFC 7489 §7.2 / draft-ietf-dmarc-aggregate-reporting) ----
//
// MTAs that publish a DMARC `rua=` policy receive aggregate reports
// from peers — XML attached to a multipart/report mail body, often
// gzip-compressed. This primitive accepts the report bytes (raw XML,
// gzipped XML, or a parsed object) and returns a structured shape
// with the metadata, published policy, and per-record evaluation
// results.
//
//   var rv = b.mail.dmarc.parseAggregateReport(xmlBytes);
//   // → {
//   //     reportMetadata: { orgName, email, reportId, dateRange },
//   //     policyPublished: { domain, adkim, aspf, p, sp, pct, ... },
//   //     records: [{ sourceIp, count, dispositions, identifiers, authResults }]
//   //   }

var DMARC_RUA_MAX_REPORT_BYTES = C.BYTES.mib(8);
var DMARC_RUA_MAX_RECORDS_PER_REPORT = 10000;

function _arrayOf(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function dmarcParseAggregateReport(input, opts) {
  opts = opts || {};
  var bytes;
  if (Buffer.isBuffer(input)) bytes = input;
  else if (typeof input === "string") bytes = Buffer.from(input, "utf8");
  else if (input && typeof input === "object" && input.feedback) {
    // operator already pre-parsed via safeXml; skip the parse step.
    return _shapeAggregateReport(input);
  }
  else {
    throw new MailAuthError("mail-auth/dmarc-rua-bad-input",
      "dmarc.parseAggregateReport: input must be a Buffer, string, or pre-parsed object");
  }
  if (bytes.length > DMARC_RUA_MAX_REPORT_BYTES) {
    throw new MailAuthError("mail-auth/dmarc-rua-too-large",
      "dmarc.parseAggregateReport: report exceeds " + DMARC_RUA_MAX_REPORT_BYTES + " bytes");
  }

  // Auto-detect gzip via magic 0x1f 0x8b (RFC 1952). DMARC RUA reports
  // are commonly zip- or gzip-compressed; the gzip magic check covers
  // the bulk of real-world reports. ZIP archives need operator-side
  // unzip first (the framework doesn't ship a ZIP primitive yet).
  var contentType = (opts.contentType || "").toLowerCase();
  var looksGzip = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
  if (contentType.indexOf("gzip") !== -1 || looksGzip) {
    try { bytes = zlib.gunzipSync(bytes, { maxOutputLength: DMARC_RUA_MAX_REPORT_BYTES }); }
    catch (e) {
      // Distinguish "decompressed bytes exceed cap" (gunzip bomb /
      // amplification — operator should rate-limit the source) from
      // "stream is malformed" (operator-level diagnostic) so audit/
      // alert wiring can react differently. Node surfaces the bomb
      // case with ERR_BUFFER_TOO_LARGE / "Output length exceeded the
      // limit" / the explicit `maxOutputLength` code. Defends the
      // decompression-amplification class (CWE-409 / CVE-2025-0725).
      var msg = (e && e.message) || String(e);
      var isBomb = (e && (e.code === "ERR_BUFFER_TOO_LARGE" ||
                          e.code === "ERR_OUT_OF_RANGE")) ||
                   /output length|max(?:imum)?\s+output|exceeds?/i.test(msg);
      if (isBomb) {
        throw new MailAuthError("mail-auth/dmarc-rua-gunzip-bomb",
          "dmarc.parseAggregateReport: gunzip output exceeded " +
          DMARC_RUA_MAX_REPORT_BYTES + " bytes (decompression amplification — refused)");
      }
      throw new MailAuthError("mail-auth/dmarc-rua-gunzip-failed",
        "dmarc.parseAggregateReport: gunzip failed: " + msg);
    }
  }

  var parsed;
  try { parsed = safeXml.parse(bytes.toString("utf8"), { maxBytes: DMARC_RUA_MAX_REPORT_BYTES }); }
  catch (e) {
    throw new MailAuthError("mail-auth/dmarc-rua-bad-xml",
      "dmarc.parseAggregateReport: XML parse failed: " + ((e && e.message) || String(e)));
  }
  return _shapeAggregateReport(parsed);
}

function _shapeAggregateReport(parsed) {
  if (!parsed || typeof parsed !== "object" || !parsed.feedback) {
    throw new MailAuthError("mail-auth/dmarc-rua-no-feedback",
      "dmarc.parseAggregateReport: report root must be <feedback>");
  }
  var feedback = parsed.feedback;
  var rmRaw = feedback.report_metadata || {};
  var ppRaw = feedback.policy_published || {};
  var records = _arrayOf(feedback.record);
  if (records.length > DMARC_RUA_MAX_RECORDS_PER_REPORT) {
    throw new MailAuthError("mail-auth/dmarc-rua-too-many-records",
      "dmarc.parseAggregateReport: report has " + records.length +
      " records (cap " + DMARC_RUA_MAX_RECORDS_PER_REPORT + ")");
  }

  var dateRange = rmRaw.date_range || {};
  var beginSec = parseInt(dateRange.begin, 10);
  var endSec = parseInt(dateRange.end, 10);

  var shaped = {
    reportMetadata: {
      orgName:    rmRaw.org_name || null,
      email:      rmRaw.email || null,
      reportId:   rmRaw.report_id || null,
      extraContact: rmRaw.extra_contact_info || null,
      dateRange: {
        begin: isFinite(beginSec) ? beginSec : null,
        end:   isFinite(endSec)   ? endSec   : null,
      },
    },
    policyPublished: {
      domain: ppRaw.domain || null,
      adkim:  ppRaw.adkim  || null,
      aspf:   ppRaw.aspf   || null,
      p:      ppRaw.p      || null,
      sp:     ppRaw.sp     || null,
      pct:    ppRaw.pct === undefined ? null : parseInt(ppRaw.pct, 10),
      fo:     ppRaw.fo     || null,
    },
    records: records.map(function (rec) {
      var row = rec.row || {};
      var pe = row.policy_evaluated || {};
      var ids = rec.identifiers || {};
      var ar = rec.auth_results || {};
      var dkimResults = _arrayOf(ar.dkim).map(function (d) {
        return {
          domain:   d.domain   || null,
          selector: d.selector || null,
          result:   d.result   || null,
          humanResult: d.human_result || null,
        };
      });
      var spfResults = _arrayOf(ar.spf).map(function (s) {
        return {
          domain: s.domain || null,
          result: s.result || null,
          scope:  s.scope  || null,
        };
      });
      var reasons = _arrayOf(pe.reason).map(function (r) {
        return { type: r.type || null, comment: r.comment || null };
      });
      var count = parseInt(row.count, 10);
      return {
        sourceIp: row.source_ip || null,
        count:    isFinite(count) ? count : null,
        dispositions: {
          disposition: pe.disposition || null,
          dkim:        pe.dkim        || null,
          spf:         pe.spf         || null,
          reasons:     reasons,
        },
        identifiers: {
          headerFrom:   ids.header_from   || null,
          envelopeFrom: ids.envelope_from || null,
          envelopeTo:   ids.envelope_to   || null,
        },
        authResults: {
          dkim: dkimResults,
          spf:  spfResults,
        },
      };
    }),
  };

  // Convenience aggregates — most operators want the totals up front.
  var totalCount = 0;
  var passCount = 0;
  var failCount = 0;
  for (var i = 0; i < shaped.records.length; i += 1) {
    var r = shaped.records[i];
    if (typeof r.count === "number") totalCount += r.count;
    var dispDkim = r.dispositions.dkim;
    var dispSpf  = r.dispositions.spf;
    if (dispDkim === "pass" || dispSpf === "pass") {
      if (typeof r.count === "number") passCount += r.count;
    } else {
      if (typeof r.count === "number") failCount += r.count;
    }
  }
  shaped.totals = {
    messages:      totalCount,
    aligned:       passCount,
    notAligned:    failCount,
  };
  return shaped;
}

// ---- DMARC aggregate (RUA) report builder/serializer (RFC 7489 Appendix C) ----
//
// The inverse of dmarcParseAggregateReport: an MTA acting as the
// REPORTING side (it received mail under another domain's DMARC policy
// and now owes that domain an aggregate report) serializes its
// observation rows into the RFC 7489 Appendix C `<feedback>` XML.
//
// The builder accepts the SAME shaped object dmarcParseAggregateReport
// returns (reportMetadata / policyPublished / records[...]), so a parsed
// report round-trips back to identical structure. Operators may also
// hand-assemble the shape directly.
//
//   var xml = b.mail.dmarc.buildAggregateReport({
//     reportMetadata: { orgName, email, reportId, dateRange: { begin, end } },
//     policyPublished: { domain, adkim, aspf, p, sp, pct },
//     records: [{ sourceIp, count,
//                 dispositions: { disposition, dkim, spf, reasons },
//                 identifiers:  { headerFrom, envelopeFrom, envelopeTo },
//                 authResults:  { dkim: [...], spf: [...] } }],
//   });
//   // → "<?xml version=\"1.0\" ...?>\n<feedback>...</feedback>"
//
// Validation tier: config-time/entry-point — the report shape is
// operator-assembled structured data, so a malformed shape (missing
// reportMetadata / policyPublished / non-array records) THROWS so the
// operator catches the mistake before the report is mailed to a peer.
//
// XML safety: every emitted text node and the (rare) attribute-free
// element bodies are escaped through _xmlEscapeText, which neutralizes
// `& < > " '`. Source IPs, domains, and identifiers can carry
// attacker-influenced bytes (a spoofed envelope-from observed in the
// wild); escaping prevents a crafted observation from injecting markup
// into the report a peer will parse.

// RFC 7489 Appendix C — the report is plain-element XML (no attributes
// in the schema), so only the five XML text-content metacharacters need
// neutralizing. Numeric / enum fields are coerced and range-checked
// before they reach here, but escaping is applied uniformly so a future
// caller can't bypass it.
function _xmlEscapeText(value) {
  return markupEscape(value, { apos: "&apos;" });
}

// Emit `<tag>escaped-text</tag>` when value is non-null/defined; emit
// nothing when the field is absent (RFC 7489 Appendix C marks many
// child elements optional — omitting is correct, emitting an empty
// element changes the parsed shape).
function _xmlLeaf(tag, value) {
  if (value === undefined || value === null || value === "") return "";
  return "<" + tag + ">" + _xmlEscapeText(value) + "</" + tag + ">";
}

// Integer leaf — coerce, refuse non-finite (a NaN count would serialize
// as the string "NaN" and corrupt the peer's parse).
function _xmlIntLeaf(tag, value) {
  if (value === undefined || value === null) return "";
  var n = typeof value === "number" ? value : parseInt(value, 10);
  if (!isFinite(n)) {
    throw new MailAuthError("mail-auth/dmarc-rua-build-bad-int",
      "dmarc.buildAggregateReport: " + tag + " must be a finite integer, got " + JSON.stringify(value));
  }
  return "<" + tag + ">" + String(Math.trunc(n)) + "</" + tag + ">";
}

function _buildAuthResultsXml(authResults) {
  var ar = authResults || {};
  var parts = [];
  var dkimRows = Array.isArray(ar.dkim) ? ar.dkim : [];
  for (var i = 0; i < dkimRows.length; i += 1) {
    var d = dkimRows[i] || {};
    parts.push(
      "<dkim>" +
      _xmlLeaf("domain", d.domain) +
      _xmlLeaf("selector", d.selector) +
      _xmlLeaf("result", d.result) +
      _xmlLeaf("human_result", d.humanResult) +
      "</dkim>");
  }
  var spfRows = Array.isArray(ar.spf) ? ar.spf : [];
  for (var j = 0; j < spfRows.length; j += 1) {
    var s = spfRows[j] || {};
    parts.push(
      "<spf>" +
      _xmlLeaf("domain", s.domain) +
      _xmlLeaf("scope", s.scope) +
      _xmlLeaf("result", s.result) +
      "</spf>");
  }
  return "<auth_results>" + parts.join("") + "</auth_results>";
}

function dmarcBuildAggregateReport(report, opts) {
  opts = opts || {};
  if (!report || typeof report !== "object") {
    throw new MailAuthError("mail-auth/dmarc-rua-build-bad-input",
      "dmarc.buildAggregateReport: report must be an object");
  }
  var rm = report.reportMetadata;
  var pp = report.policyPublished;
  if (!rm || typeof rm !== "object") {
    throw new MailAuthError("mail-auth/dmarc-rua-build-bad-input",
      "dmarc.buildAggregateReport: report.reportMetadata is required (RFC 7489 Appendix C)");
  }
  if (!pp || typeof pp !== "object") {
    throw new MailAuthError("mail-auth/dmarc-rua-build-bad-input",
      "dmarc.buildAggregateReport: report.policyPublished is required (RFC 7489 Appendix C)");
  }
  var records = report.records;
  if (!Array.isArray(records)) {
    throw new MailAuthError("mail-auth/dmarc-rua-build-bad-input",
      "dmarc.buildAggregateReport: report.records must be an array");
  }
  if (records.length > DMARC_RUA_MAX_RECORDS_PER_REPORT) {
    throw new MailAuthError("mail-auth/dmarc-rua-build-too-many-records",
      "dmarc.buildAggregateReport: " + records.length + " records exceeds cap " +
      DMARC_RUA_MAX_RECORDS_PER_REPORT);
  }

  // report_metadata (RFC 7489 Appendix C). date_range is two epoch
  // seconds; org_name + report_id are mandatory per the schema.
  var dateRange = rm.dateRange || {};
  var metaXml =
    "<report_metadata>" +
    _xmlLeaf("org_name", rm.orgName) +
    _xmlLeaf("email", rm.email) +
    _xmlLeaf("extra_contact_info", rm.extraContact) +
    _xmlLeaf("report_id", rm.reportId) +
    "<date_range>" +
    _xmlIntLeaf("begin", dateRange.begin) +
    _xmlIntLeaf("end", dateRange.end) +
    "</date_range>" +
    "</report_metadata>";

  // policy_published (RFC 7489 Appendix C).
  var policyXml =
    "<policy_published>" +
    _xmlLeaf("domain", pp.domain) +
    _xmlLeaf("adkim", pp.adkim) +
    _xmlLeaf("aspf", pp.aspf) +
    _xmlLeaf("p", pp.p) +
    _xmlLeaf("sp", pp.sp) +
    (pp.pct === undefined || pp.pct === null ? "" : _xmlIntLeaf("pct", pp.pct)) +
    _xmlLeaf("fo", pp.fo) +
    "</policy_published>";

  // record[] rows. Each row: source_ip + count + policy_evaluated +
  // identifiers + auth_results.
  var recordXml = "";
  for (var i = 0; i < records.length; i += 1) {
    var rec = records[i] || {};
    var disp = rec.dispositions || {};
    var ids = rec.identifiers || {};
    var reasonRows = Array.isArray(disp.reasons) ? disp.reasons : [];
    var reasonXml = "";
    for (var ri = 0; ri < reasonRows.length; ri += 1) {
      var rs = reasonRows[ri] || {};
      reasonXml +=
        "<reason>" +
        _xmlLeaf("type", rs.type) +
        _xmlLeaf("comment", rs.comment) +
        "</reason>";
    }
    recordXml +=
      "<record>" +
      "<row>" +
      _xmlLeaf("source_ip", rec.sourceIp) +
      _xmlIntLeaf("count", rec.count) +
      "<policy_evaluated>" +
      _xmlLeaf("disposition", disp.disposition) +
      _xmlLeaf("dkim", disp.dkim) +
      _xmlLeaf("spf", disp.spf) +
      reasonXml +
      "</policy_evaluated>" +
      "</row>" +
      "<identifiers>" +
      _xmlLeaf("envelope_to", ids.envelopeTo) +
      _xmlLeaf("envelope_from", ids.envelopeFrom) +
      _xmlLeaf("header_from", ids.headerFrom) +
      "</identifiers>" +
      _buildAuthResultsXml(rec.authResults) +
      "</record>";
  }

  // RFC 7489 §7.2.1.1 — report-format version is "1.0" (the `version`
  // element under <feedback>). Emit the XML declaration + a single
  // <feedback> root so the output round-trips through safeXml.parse.
  var version = _xmlLeaf("version", opts.version || "1.0");
  var doc =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
    "<feedback>" +
    version +
    metaXml +
    policyXml +
    recordXml +
    "</feedback>";

  // Optional gzip per the same transport convention the parser accepts
  // (RFC 1952). Default is raw XML; operators opt into compression for
  // the mail attachment. Back-compat: default behavior is unchanged
  // (raw string out) — gzip is strictly opt-in.
  if (opts.gzip === true) {
    return zlib.gzipSync(Buffer.from(doc, "utf8"));
  }
  return doc;
}

// ---- iprev (RFC 8601 §3) — Forward-Confirmed Reverse DNS verifier ----
//
// The receiving SMTP server reverse-resolves the connecting peer's IP
// to a PTR name, forward-resolves the PTR name to an A or AAAA set,
// and confirms the original IP appears in the forward set. Spoofed
// PTR records (attacker controls the rDNS zone but not the forward
// zone) fail this check and SHOULD be reflected in the
// Authentication-Results header so downstream policies can react.
//
// Surface:
//   await b.mail.iprev.verify(ip)
//   → { result: "pass"|"fail"|"permerror"|"temperror",
//       ptr, forward, fcrdns, ip }
//
// Returns "permerror" on bad-shape input (not an IP literal); returns
// "temperror" on ENODATA / ENOTFOUND / lookup failure (the receiver
// retries on transient DNS faults). Pure-DNS — no operator state.

// RFC 8601 §3 — PTR result shape. The PTR rdata is an FQDN (1*labels).
// Reject answers that aren't shaped as a DNS name: non-strings,
// empty strings, strings containing chars outside DNS LDH+dot, or
// labels exceeding 63 octets. An attacker who controls a reverse
// zone could publish a PTR whose rdata is arbitrary bytes (e.g.
// `<script>...`) that downstream consumers (audit / Authentication-
// Results emission) might fail to escape. Pre-filter at the iprev
// boundary so only well-shaped names reach downstream.
function _isValidPtrName(name) {
  if (typeof name !== "string") return false;
  var trimmed = name.replace(/\.$/, "");
  if (trimmed.length === 0 || trimmed.length > 253) return false;                // RFC 1035 hostname cap
  // Labels: 1..63 octets, LDH (letter / digit / hyphen) + leading
  // alphanum (RFC 1035 §2.3.1). Permissive: PTR rdata can in practice
  // contain underscores (mail-server idiom) — allow underscore in
  // labels too. Reject anything else.
  var labels = trimmed.split(".");
  for (var i = 0; i < labels.length; i += 1) {
    var lab = labels[i];
    if (lab.length === 0 || lab.length > 63) return false;                       // RFC 1035 label cap
    if (!/^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/.test(lab)) return false;
  }
  return true;
}

async function iprevVerify(ip) {
  if (typeof ip !== "string" || ip.length === 0) {
    return { result: "permerror", ip: ip || null,
             ptr: null, forward: [], fcrdns: false,
             explanation: "ip must be a non-empty string" };
  }
  if (!net.isIP(ip)) {
    return { result: "permerror", ip: ip,
             ptr: null, forward: [], fcrdns: false,
             explanation: "ip is not a valid IPv4 / IPv6 literal" };
  }

  var ptrs;
  try { ptrs = await _safeReverse(ip); }
  catch (e) {
    var rcode = e && e.code;
    if (rcode === "ENOTFOUND" || rcode === "ENODATA") {
      return { result: "fail", ip: ip,
               ptr: null, forward: [], fcrdns: false,
               explanation: "no PTR record for " + ip };
    }
    return { result: "temperror", ip: ip,
             ptr: null, forward: [], fcrdns: false,
             explanation: "PTR lookup failed: " + ((e && e.message) || String(e)) };
  }
  if (!Array.isArray(ptrs) || ptrs.length === 0) {
    return { result: "fail", ip: ip,
             ptr: null, forward: [], fcrdns: false,
             explanation: "PTR returned empty answer set" };
  }

  // RFC 8601 §3 — when multiple PTRs exist the receiver picks ONE
  // and continues. We pick the first (matches mainstream MTA
  // behavior) and stash the rest for operator visibility on the
  // out-of-band metadata. Validate the PTR's shape FIRST — a PTR
  // with arbitrary bytes shouldn't reach downstream consumers.
  var ptr = String(ptrs[0]).replace(/\.$/, "");
  if (!_isValidPtrName(ptr)) {
    return { result: "permerror", ip: ip,
             ptr: ptr, forward: [], fcrdns: false,
             explanation: "PTR record is not a valid DNS name shape (RFC 8601 §3)" };
  }
  var isV6 = net.isIPv6(ip);
  var forwardAddrs;
  try {
    forwardAddrs = await _safeResolveA(ptr, isV6 ? 6 : 4);
  } catch (e) {
    var fcode = e && e.code;
    if (fcode === "ENOTFOUND" || fcode === "ENODATA") {
      return { result: "fail", ip: ip,
               ptr: ptr, forward: [], fcrdns: false,
               explanation: "no forward record for PTR " + ptr };
    }
    if (fcode === "ETIMEOUT" || fcode === "ESERVFAIL") {
      return { result: "temperror", ip: ip,
               ptr: ptr, forward: [], fcrdns: false,
               explanation: "forward lookup transient failure: " + fcode };
    }
    // Anything else — propagate as temperror; Node DNS surfaces some
    // non-RFC error codes via the platform resolver. Permerror only
    // for definitive negative answers above.
    throw new MailAuthError("mail-auth/iprev-temperror",
      "iprev.verify: forward lookup of " + ptr + " threw: " +
      ((e && e.message) || String(e)));
  }
  var forward = Array.isArray(forwardAddrs) ? forwardAddrs.slice() : [];
  var ipLc = ip.toLowerCase();
  var fcrdns = false;
  for (var i = 0; i < forward.length; i += 1) {
    if (String(forward[i]).toLowerCase() === ipLc) { fcrdns = true; break; }
  }
  return {
    result:      fcrdns ? "pass" : "fail",
    ip:          ip,
    ptr:         ptr,
    forward:     forward,
    fcrdns:      fcrdns,
    explanation: fcrdns
      ? "PTR " + ptr + " forward-resolves to " + ip
      : "PTR " + ptr + " does not forward-resolve to " + ip,
  };
}

// ---- DMARC forensic (RUF) failure-report parser (RFC 6591 + RFC 7489 §7.3) ----
//
// A domain publishing a DMARC `ruf=` policy receives per-message
// failure reports when an authentication check fails. RFC 7489 §7.3
// specifies the Authentication Failure Reporting Format (AFRF) of
// RFC 6591 for these: a multipart/report (report-type=feedback-report)
// carrying a `message/feedback-report` part whose header block adds the
// DMARC-specific fields (Auth-Failure, Delivery-Result, Identity-
// Alignment, DKIM-*/SPF-* result fields) on top of the RFC 5965 base
// fields, plus a third part (message/rfc822 or text/rfc822-headers)
// with the reported message (in full or headers-only).
//
// Composes the shared lib/mime-parse.js substrate (the same MIME walker
// the RFC 5965 ARF ingest in lib/mail-arf.js uses) for the
// multipart/report bisection + message/feedback-report extraction, then
// shapes the full RFC 6591 §3.1 forensic field set (which the abuse-
// report profile does not model) plus the reported message's headers.
//
//   var rv = b.mail.dmarc.parseForensicReport(rawMessageBytes);
//   if (!rv.ok) { /* rv.error.code / rv.error.message */ }
//   else        { /* rv.report.feedbackType / .authFailure / … */ }
//
// Validation tier: DEFENSIVE READER. The input is hostile-by-default
// (a per-message failure report arrives at an operator endpoint from an
// arbitrary reporting peer). The parser RETURNS a typed error object on
// any malformed / over-cap / wrong-shape input — it does NOT throw in
// the hot path, so a crafted report can't crash the request that
// ingested it. Bytes + part-count + reported-header counts are bounded
// (CWE-400 resource-exhaustion class) like the sibling aggregate-report
// parser.
//
//   { ok: true,  report: { … } }
//   { ok: false, error: { code: "<slug>", message: "<reason>" } }

// RFC 6591 §3.2 — the report is small in practice; cap at 8 MiB to match
// the sibling DMARC aggregate-report ceiling so operators have one
// mental model for "what fits".
var DMARC_RUF_MAX_REPORT_BYTES = C.BYTES.mib(8);

// RFC 2046 §5.1 — a multipart/report failure report has a handful of
// parts (text/plain + message/feedback-report + the reported message);
// bound the part count so a hostile report with thousands of empty
// boundary delimiters can't force unbounded walk work.
var DMARC_RUF_MAX_PARTS = 64;                                                    // resource-exhaustion bound (CWE-400)

// RFC 6591 §3.1 — required forensic fields. Feedback-Type and Auth-
// Failure are the two that make an auth-failure report a DMARC forensic
// report (RFC 7489 §7.3). User-Agent / Version are advisory in practice.
var DMARC_RUF_REQUIRED_FIELDS = ["feedback-type", "auth-failure"];

// RFC 6591 §3.1 — Auth-Failure registry values. Unknown values pass
// through (the IANA "Authentication Failure" registry grows); this set
// documents the launch vocabulary so operators can route on it.
var DMARC_RUF_AUTH_FAILURE_TYPES = Object.freeze({
  adsp:       1,                                                                 // RFC 6591 §3.1 (historic ADSP)
  "bodyhash": 1,                                                                 // DKIM body-hash mismatch
  dkim:       1,                                                                 // DKIM signature failure
  dmarc:      1,                                                                 // RFC 7489 §7.3 — DMARC evaluation failure
  revoked:    1,                                                                 // signing key revoked
  signature:  1,                                                                 // DKIM signature syntactically invalid
  spf:        1,                                                                 // SPF check failure
});
void DMARC_RUF_AUTH_FAILURE_TYPES;

// RFC 6591 §3.2 — the reported message's header section can be large but
// is bounded; cap the number of reported headers we normalize so a
// crafted report can't force unbounded work. The full reported message
// text is still surfaced verbatim under `reportedMessage` (bounded by
// the overall byte cap), but the parsed `reportedHeaders` list is
// header-count-capped.
var DMARC_RUF_MAX_REPORTED_HEADERS = 256;                                       // resource-exhaustion bound (CWE-400)

function _rufError(code, message) {
  return { ok: false, error: { code: code, message: message } };
}

// Parse the reported message's headers (RFC 6591 §3.2 — the third part
// of the report carries the message that failed authentication, in full
// or headers-only). Returns an own-keys-only map (null-prototype) of
// header-name → value (last-wins for duplicate single-valued lookups;
// the full ordered list is also returned) so a header named
// `__proto__` / `constructor` in a hostile report can't pollute the
// prototype chain (prototype-pollution class).
function _parseReportedHeaders(reportedMessage) {
  var ordered = [];
  var map = Object.create(null);
  if (typeof reportedMessage !== "string" || reportedMessage.length === 0) {
    return { headers: ordered, map: map, truncated: false };
  }
  var split;
  try { split = mimeParse.splitHeadersAndBody(reportedMessage); }
  catch (_e) { return { headers: ordered, map: map, truncated: false }; }
  var hdrs = Array.isArray(split.headers) ? split.headers : [];
  var truncated = false;
  for (var i = 0; i < hdrs.length; i += 1) {
    if (ordered.length >= DMARC_RUF_MAX_REPORTED_HEADERS) { truncated = true; break; }
    var h = hdrs[i];
    if (!h || typeof h.name !== "string") continue;
    var name = h.name;
    var value = typeof h.value === "string" ? h.value : "";
    ordered.push({ name: name, value: value });
    // Own-key assignment on a null-prototype object: a reported header
    // named __proto__ / constructor / prototype is stored as data, not
    // walked up the chain.
    map[name.toLowerCase()] = value;
  }
  return { headers: ordered, map: map, truncated: truncated };
}

// Reassemble a MIME part's headers + body so a reported message that
// ships as text/rfc822-headers (no separate body) still round-trips its
// header bytes (RFC 6591 §3.2 permits headers-only).
function _reassembleRufPart(part) {
  var hdrs = "";
  var ph = Array.isArray(part.headers) ? part.headers : [];
  for (var i = 0; i < ph.length; i += 1) {
    hdrs += ph[i].name + ": " + ph[i].value + "\r\n";
  }
  return hdrs + "\r\n" + (part.body || "");
}

function dmarcParseForensicReport(input, opts) {
  opts = opts || {};

  // ---- Coerce + byte-cap (defensive: typed error, never throw) ----
  var asString;
  if (typeof input === "string") asString = input;
  else if (Buffer.isBuffer(input)) asString = input.toString("utf8");
  else {
    return _rufError("mail-auth/dmarc-ruf-bad-input",
      "dmarc.parseForensicReport: input must be a string or Buffer");
  }
  var maxBytes = (typeof opts.maxBytes === "number" && isFinite(opts.maxBytes) && opts.maxBytes > 0)
    ? opts.maxBytes
    : DMARC_RUF_MAX_REPORT_BYTES;
  if (safeBuffer.byteLengthOf(asString) > maxBytes) {
    return _rufError("mail-auth/dmarc-ruf-too-large",
      "dmarc.parseForensicReport: report exceeds " + maxBytes + " bytes (got " + safeBuffer.byteLengthOf(asString) + ")");
  }

  // ---- Bisect top-level headers / body; require multipart/report ----
  var top;
  try { top = mimeParse.splitHeadersAndBody(asString); }
  catch (e) {
    return _rufError("mail-auth/dmarc-ruf-bad-report",
      "dmarc.parseForensicReport: header/body split failed: " + ((e && e.message) || String(e)));
  }
  var ct = mimeParse.parseContentType(mimeParse.findHeader(top.headers, "Content-Type") || "");
  if (ct.type !== "multipart/report") {
    return _rufError("mail-auth/dmarc-ruf-bad-report",
      "dmarc.parseForensicReport: top-level Content-Type must be multipart/report (got '" + ct.type + "')");
  }
  // RFC 6591 §2 / RFC 5965 §2 — report-type=feedback-report. Tolerate an
  // omitted report-type (shipping reporters sometimes drop it); refuse a
  // mismatched value.
  if (ct.params["report-type"] && ct.params["report-type"].toLowerCase() !== "feedback-report") {
    return _rufError("mail-auth/dmarc-ruf-bad-report",
      "dmarc.parseForensicReport: report-type must be feedback-report (got '" +
      ct.params["report-type"] + "')");
  }
  if (!ct.params.boundary) {
    return _rufError("mail-auth/dmarc-ruf-bad-report",
      "dmarc.parseForensicReport: multipart/report Content-Type lacks boundary parameter");
  }

  // ---- Walk the parts; find message/feedback-report + reported msg ----
  var parts = mimeParse.splitMimeParts(top.body, ct.params.boundary);
  if (parts.length === 0) {
    return _rufError("mail-auth/dmarc-ruf-bad-report",
      "dmarc.parseForensicReport: multipart/report body contains no parts");
  }
  if (parts.length > DMARC_RUF_MAX_PARTS) {
    return _rufError("mail-auth/dmarc-ruf-too-many-parts",
      "dmarc.parseForensicReport: report has " + parts.length + " parts (cap " +
      DMARC_RUF_MAX_PARTS + ")");
  }

  var feedbackPart = null;
  var reportedPart = null;
  for (var pi = 0; pi < parts.length; pi += 1) {
    var split;
    try { split = mimeParse.splitHeadersAndBody(parts[pi]); }
    catch (_e) { continue; }
    var partCt = mimeParse.parseContentType(
      mimeParse.findHeader(split.headers, "Content-Type") || "");
    if (partCt.type === "message/feedback-report" && !feedbackPart) {
      feedbackPart = split;
    } else if ((partCt.type === "message/rfc822" ||
                partCt.type === "text/rfc822-headers") && !reportedPart) {
      reportedPart = split;
    }
  }
  if (!feedbackPart) {
    return _rufError("mail-auth/dmarc-ruf-no-feedback-report",
      "dmarc.parseForensicReport: missing message/feedback-report subpart (RFC 6591 §3)");
  }

  // ---- Parse the feedback-report header block (RFC 6591 §3.1) ----
  // Field names are stored own-key on a null-prototype map so a hostile
  // field named __proto__ / constructor can't pollute the prototype.
  var fields;
  try { fields = mimeParse.parseHeaderBlock(feedbackPart.body); }
  catch (e) {
    return _rufError("mail-auth/dmarc-ruf-bad-report",
      "dmarc.parseForensicReport: feedback-report field parse failed: " + ((e && e.message) || String(e)));
  }
  var fieldMap = Object.create(null);
  var rcptToList = [];
  for (var fi = 0; fi < fields.length; fi += 1) {
    var f = fields[fi];
    if (!f || typeof f.name !== "string") continue;
    var lc = f.name.toLowerCase();
    var val = typeof f.value === "string" ? f.value : "";
    fieldMap[lc] = val;
    if (lc === "original-rcpt-to") rcptToList.push(val);
  }
  function _field(name) {
    return Object.prototype.hasOwnProperty.call(fieldMap, name) ? fieldMap[name] : null;
  }

  // ---- Required fields (RFC 6591 §3.1 / RFC 7489 §7.3) ----
  for (var ri = 0; ri < DMARC_RUF_REQUIRED_FIELDS.length; ri += 1) {
    var req = DMARC_RUF_REQUIRED_FIELDS[ri];
    var rv = _field(req);
    if (typeof rv !== "string" || rv.length === 0) {
      if (req === "auth-failure") {
        return _rufError("mail-auth/dmarc-ruf-missing-auth-failure",
          "dmarc.parseForensicReport: required field 'Auth-Failure' is missing (RFC 6591 §3.1)");
      }
      return _rufError("mail-auth/dmarc-ruf-missing-field",
        "dmarc.parseForensicReport: required field '" + req + "' is missing (RFC 6591 §3.1)");
    }
  }

  // RFC 7489 §7.3 — a DMARC forensic report carries Feedback-Type:
  // auth-failure (the AFRF profile of RFC 6591). A report whose Feedback-
  // Type is another ARF class (e.g. plain "abuse") is a valid feedback
  // report but NOT a DMARC forensic report; surface the mismatch rather
  // than mislabeling it. Field values are case-insensitive tokens.
  var feedbackType = String(_field("feedback-type")).toLowerCase();
  if (feedbackType !== "auth-failure") {
    return _rufError("mail-auth/dmarc-ruf-not-auth-failure",
      "dmarc.parseForensicReport: Feedback-Type must be 'auth-failure' for a " +
      "DMARC forensic report (RFC 7489 §7.3 / RFC 6591), got " +
      JSON.stringify(_field("feedback-type")));
  }

  // ---- RFC 6591 §3.2 reported message ----
  var reportedMessage = null;
  if (reportedPart) {
    reportedMessage = (reportedPart.body && reportedPart.body.length > 0)
      ? reportedPart.body
      : _reassembleRufPart(reportedPart);
  }
  var reported = _parseReportedHeaders(reportedMessage);

  // ---- Normalize Arrival-Date / Incidents (RFC 5965 §3.1) ----
  var arrivalRaw = _field("arrival-date") || _field("received-date") || null;
  var arrivalIso = null;
  if (arrivalRaw) {
    var d = new Date(arrivalRaw);
    if (!isNaN(d.getTime())) arrivalIso = d.toISOString();
  }
  var incidentsRaw = _field("incidents");
  var incidents = null;
  if (typeof incidentsRaw === "string") {
    var inc = parseInt(incidentsRaw, 10);
    if (isFinite(inc) && inc >= 0) incidents = inc;
  }

  // Surface unmodeled fields under extraFields for operator visibility
  // (vendor X-* tags). Own-key copy off the null-prototype fieldMap onto
  // a null-prototype target so a field named __proto__ / constructor in a
  // hostile report is stored as data, not as a prototype mutation.
  var KNOWN = Object.create(null);
  ["feedback-type", "user-agent", "version", "auth-failure",
   "delivery-result", "identity-alignment", "dkim-domain",
   "dkim-identity", "dkim-selector", "dkim-canonicalized-header",
   "dkim-canonicalized-body", "spf-dns", "original-mail-from",
   "original-rcpt-to", "arrival-date", "received-date",
   "reported-domain", "source-ip", "authentication-results",
   "reported-uri", "incidents", "original-envelope-id"
  ].forEach(function (k) { KNOWN[k] = 1; });
  var extraFields = Object.create(null);
  Object.keys(fieldMap).forEach(function (k) {
    if (!Object.prototype.hasOwnProperty.call(KNOWN, k)) extraFields[k] = fieldMap[k];
  });

  var report = {
    // ---- RFC 5965 base fields ----
    feedbackType:          _field("feedback-type"),
    userAgent:             _field("user-agent"),
    version:               _field("version") || "1",
    arrivalDate:           arrivalIso || arrivalRaw,
    reportedDomain:        _field("reported-domain"),
    sourceIp:              _field("source-ip"),
    originalFrom:          _field("original-mail-from"),
    originalRcptTo:        rcptToList,
    originalEnvelopeId:    _field("original-envelope-id"),
    authenticationResults: _field("authentication-results"),
    incidents:             incidents,
    reportedUri:           _field("reported-uri"),

    // ---- RFC 6591 §3.1 / RFC 7489 §7.3 forensic-specific fields ----
    authFailure:           _field("auth-failure"),                              // RFC 6591 §3.1 — "dkim" | "spf" | "dmarc" | "bodyhash" | …
    deliveryResult:        _field("delivery-result"),                           // RFC 6591 §3.1 — "delivered" | "spam" | "policy" | "reject" | "other"
    identityAlignment:     _field("identity-alignment"),                        // RFC 7489 §7.3 — "none" | "spf" | "dkim" | "dkim spf"
    dkim: {
      domain:              _field("dkim-domain"),                               // RFC 6591 §3.1
      identity:            _field("dkim-identity"),
      selector:            _field("dkim-selector"),
      canonicalizedHeader: _field("dkim-canonicalized-header"),
      canonicalizedBody:   _field("dkim-canonicalized-body"),
    },
    spf: {
      dns:                 _field("spf-dns"),                                    // RFC 6591 §3.1 — the SPF DNS record at evaluation time
    },

    // ---- RFC 6591 §3.2 reported message ----
    reportedMessage:       reportedMessage,
    reportedHeaders:       reported.headers,                                    // [ { name, value }, … ] — order preserved
    reportedHeaderMap:     reported.map,                                        // null-prototype lower-cased-name → value
    reportedHeadersTruncated: reported.truncated,                               // true when the §3.2 header cap clipped the list

    // ---- operator-visible passthrough for unmodeled fields ----
    extraFields:           extraFields,
  };

  return { ok: true, report: report };
}

module.exports = {
  spf: Object.freeze({
    verify:        spfVerify,
    parseRecord:   _parseSpfRecord,
  }),
  dmarc: Object.freeze({
    evaluate:                 dmarcEvaluate,
    parseRecord:              _parseDmarcRecord,
    parseAggregateReport:     dmarcParseAggregateReport,
    buildAggregateReport:     dmarcBuildAggregateReport,
    parseForensicReport:      dmarcParseForensicReport,
  }),
  arc: Object.freeze({
    verify:        arcVerify,
    evaluate:      arcEvaluate,
    sign:          require("./mail-arc-sign").sign,           // allow:inline-require — re-export from sibling module
    ALLOWED_CV:    require("./mail-arc-sign").ALLOWED_CV,     // allow:inline-require — re-export from sibling module
  }),
  iprev: Object.freeze({
    verify:        iprevVerify,
  }),
  authResults: Object.freeze({
    emit:          authResultsEmit,
  }),
  inbound: Object.freeze({
    verify:        inboundVerify,
  }),
  MailAuthError: MailAuthError,
  SPF_DNS_LOOKUP_LIMIT: SPF_DNS_LOOKUP_LIMIT,
};
