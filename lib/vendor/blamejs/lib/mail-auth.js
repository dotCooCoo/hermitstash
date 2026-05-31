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
 * SPF (RFC 7208) — ip4 / ip6 / a / mx / include / all / redirect=
 *   mechanisms.
 *   Mechanism limit: 10 DNS lookups per RFC 7208 §4.6.4 (with the
 *   void-lookup sub-limit at 2). The `a` and `mx` arms honor RFC
 *   §5.3 / §5.4 dual-cidr-length syntax (`a:foo.com/24//64`).
 *
 *   Deferred mechanisms (each carries an explicit Re-open condition
 *   in the dispatch arm in this file):
 *     - exists: requires macro-string expansion (§7) to be useful;
 *               re-opens when macros land OR an operator surfaces a
 *               real macro-less `exists:` policy.
 *     - ptr:    "strongly discouraged" by §5.5; re-opens when an
 *               operator surfaces a legitimate ptr-only sender.
 *     - macro-string expansion (§7) itself — separate slice tracked
 *               under blamejs-roadmap.md.
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
var validateOpts = require("./validate-opts");
var bCrypto = require("./crypto");
var C = require("./constants");
var dkim = require("./mail-dkim");
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

async function _safeResolveTxt(qname, operatorLookup) {
  if (operatorLookup) return operatorLookup(qname, "TXT");
  var r = await _getDefaultResolver().queryTxt(qname);
  var out = [];
  for (var i = 0; i < r.rrs.length; i += 1) {
    var rr = r.rrs[i];
    if (rr && rr.type === 16) {                                                  // IANA DNS qtype TXT
      out.push(Array.isArray(rr.decoded) ? rr.decoded : [String(rr.decoded)]);
    }
  }
  if (out.length === 0) {
    var err = new Error("no TXT records for " + qname);
    err.code = "ENODATA";
    throw err;
  }
  return out;
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
async function _spfMatchAMx(mech, raw, ip, isIpv6, defaultDomain, dnsLookup, lookups) {
  var parsed;
  try { parsed = _parseADualCidr(raw, mech, defaultDomain); }
  catch (e) { return { error: "permerror", reason: e.message }; }

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
// include / all / redirect=. The `exists` and `ptr` mechanisms +
// macro-string expansion remain deferred (see the mechanism dispatch
// arm for the Re-open condition + operator escape hatch).
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
  // RFC 7208 §4.6.4 — the initial query for the sender domain's SPF
  // record itself does NOT count toward the 10-lookup limit. Only
  // include / a / mx / ptr / exists / redirect mechanisms count.
  // Pre-v0.8.17 this was off-by-one — senders at the spec ceiling
  // got false permerror.
  var result = await _spfEvaluateDomain(domain.toLowerCase(), opts.ip,
                                          opts.dnsLookup, lookups,
                                          { isInitial: true });
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
      var inner = await _spfEvaluateDomain(m.arg.toLowerCase(), ip, dnsLookup, lookups);
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
                                      domain, dnsLookup, lookups);
      if (amRes.error === "permerror") {
        return { verdict: "permerror", explanation: amRes.reason };
      }
      if (amRes.error === "temperror") {
        return { verdict: "temperror", explanation: amRes.reason };
      }
      if (amRes.match) match = true;
    } else if (m.mechanism === "exists" || m.mechanism === "ptr") {
      // RFC 7208 §5.7 (exists) + §5.5 (ptr) — deferred from v0.11.3.
      //
      // exists: requires macro-string expansion (RFC 7208 §7) to be
      //   useful in practice; almost every published `exists:` policy
      //   uses macros like `exists:%{l}.%{d}._spf.example.com` to do
      //   per-recipient or per-IP lookups. A non-macro `exists:` is
      //   technically valid but vanishingly rare in published policies.
      //
      // ptr:    RFC 7208 §5.5 explicitly says "use of this mechanism
      //   is strongly discouraged" — the receiver does reverse-DNS +
      //   forward-confirm per query, doubling DNS load and tying the
      //   sender's authz to whoever controls their PTR zone. Despite
      //   this discouragement, a small minority of legacy senders
      //   still publish `+ptr -all` policies as their only SPF stance.
      //
      // Re-open conditions:
      //   - exists: macro-string expansion lands in the framework (a
      //     standalone slice; tracked under blamejs-roadmap.md), OR an
      //     operator surfaces a real `exists:` policy without macros
      //     and asks for the simple A-existence form.
      //   - ptr:    an operator surfaces a legitimate sender whose
      //     ONLY SPF stance is `ptr` and needs the framework to
      //     evaluate it (rather than the operator's MTA already doing
      //     iprev via `b.mail.auth.iprev`).
      //
      // Operator escape hatch today:
      //   - exists: senders almost universally have a non-`exists:`
      //     mechanism alongside; the framework returns "permerror"
      //     here, surfacing the gap, but legitimate mail flow that
      //     ALSO carries a passing ip4/ip6/include path is unaffected.
      //   - ptr: operators evaluating a ptr-only sender wire
      //     `b.mail.auth.iprev(ip)` and treat fcrdns=true the same as
      //     SPF pass for that domain.
      return {
        verdict: "permerror",
        explanation: "SPF mechanism '" + m.mechanism + "' is not yet implemented (RFC 7208 §" +
                     (m.mechanism === "exists" ? "5.7 + §7 macros" : "5.5") +
                     "); senders typically publish ip4 / ip6 / a / mx / include alongside",
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
      // Redirect counts as one DNS-mechanism per §4.6.4.
      var redirected = await _spfEvaluateDomain(
        mods[rmi].value.toLowerCase(), ip, dnsLookup, lookups,
        { redirectDepth: (ctx.redirectDepth || 0) + 1 });
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
  var records;
  try {
    records = await _safeResolveTxt(qname, dnsLookup);
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return null;
    throw new MailAuthError("mail-auth/dmarc-lookup-failed",
      "DMARC TXT lookup for " + qname + " failed: " +
      ((e && e.message) || String(e)));
  }
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
  var pairs = text.split(";");                                                              // allow:bare-split-on-quoted-header — RFC 7489 §6.4 DMARC tag-list grammar: `tag-spec *( ";" tag-spec )` with tag-value = 0*( tval *( WSP / FWS ) ); NO quoted-string allowed
  for (var i = 0; i < pairs.length; i += 1) {
    var kv = pairs[i].trim();
    if (kv.length === 0) continue;
    var eq = kv.indexOf("=");
    if (eq === -1) continue;
    var key = kv.slice(0, eq).trim().toLowerCase();
    var val = kv.slice(eq + 1).trim();
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
    var colonAt = line.indexOf(":");
    if (colonAt === -1) continue;
    var name = line.slice(0, colonAt).trim().toLowerCase();
    var value = line.slice(colonAt + 1).trim();
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
    var colonAt = line.indexOf(":");
    if (colonAt === -1) { rebuilt.push(line); continue; }
    var name = line.slice(0, colonAt).trim().toLowerCase();
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
      var instMatch = /\bi\s*=\s*(\d+)/.exec(line.slice(colonAt + 1));
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
  var tags = {};
  var parts = String(value).split(";");                                                          // allow:bare-split-on-quoted-header — RFC 8617 §4 ARC tag-list grammar (same as the DKIM RFC's): `tag-spec *( ";" tag-spec )`, tag-value contains no DQUOTE

  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    var eq = p.indexOf("=");
    if (eq === -1) continue;
    tags[p.slice(0, eq).trim().toLowerCase()] = p.slice(eq + 1).trim().replace(/\s+/g, "");
  }
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
  // RFC 6376 §3.4.2 — relaxed header canon: lowercase name, unfold,
  // collapse internal WSP runs, strip trailing WSP.
  var unfolded = String(value).replace(/\r?\n[ \t]+/g, " ");
  var trimmed = unfolded.replace(/[ \t]+/g, " ").replace(/^[ \t]+|[ \t]+$/g, "");
  return name.toLowerCase() + ":" + trimmed + "\r\n";
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
    var colonAt = line.indexOf(":");
    if (colonAt === -1) continue;
    var name = line.slice(0, colonAt).trim().toLowerCase();
    var value = line.slice(colonAt + 1).trim();
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

module.exports = {
  spf: Object.freeze({
    verify:        spfVerify,
    parseRecord:   _parseSpfRecord,
  }),
  dmarc: Object.freeze({
    evaluate:                 dmarcEvaluate,
    parseRecord:              _parseDmarcRecord,
    parseAggregateReport:     dmarcParseAggregateReport,
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
  MailAuthError: MailAuthError,
  SPF_DNS_LOOKUP_LIMIT: SPF_DNS_LOOKUP_LIMIT,
};
