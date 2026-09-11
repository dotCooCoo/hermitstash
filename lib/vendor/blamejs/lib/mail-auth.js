// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var zlib = require("node:zlib");
var net = require("node:net");
var nodeCrypto = require("node:crypto");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var structuredFields = require("./structured-fields");
var markupEscape = require("./markup-escape").markupEscape;
var safeDecompress = require("./safe-decompress").safeDecompress;
var bCrypto = require("./crypto");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var dkim = require("./mail-dkim");
var ARC_AMS_REUSE = require("./mail-arc-reuse-token");
var mimeParse = require("./mime-parse");
var safeXml = require("./parsers/safe-xml");
var ipUtils = require("./ip-utils");
var publicSuffix = require("./public-suffix");
var networkDnsResolver = lazyRequire(function () { return require("./network-dns-resolver"); });
var { MailAuthError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var SPF_DNS_LOOKUP_LIMIT = 10;

var SPF_VOID_LOOKUP_LIMIT = 2;

var SPF_RECORD_MAX_BYTES = 450;

var SPF_REDIRECT_DEPTH_LIMIT = 10;

var _defaultResolver = null;
function _getDefaultResolver() {
  if (_defaultResolver) return _defaultResolver;
  _defaultResolver = networkDnsResolver().create();
  return _defaultResolver;
}

async function _safeResolveTxt(qname, operatorLookup) {
  return networkDnsResolver().resolveTxt(qname, operatorLookup, _getDefaultResolver());
}

async function _safeResolveA(qname, family , operatorLookup) {
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
    var wantType = family === 6 ? 28 : 1;
    if (rr && rr.type === wantType) out.push(rr.decoded);
  }
  if (out.length === 0) {
    var err = new Error("no " + (family === 6 ? "AAAA" : "A") + " records for " + qname);
    err.code = "ENODATA";
    throw err;
  }
  return out;
}

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
    if (rr && rr.type === 15) {
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

async function _safeReverse(ip, operatorLookup) {
  var qname = _ipToReverseArpa(ip);
  if (qname === null) {
    var err = new Error("invalid IP literal: " + ip);
    err.code = "ENOTFOUND";
    throw err;
  }
  if (operatorLookup) {
    var resp = await operatorLookup(qname, "PTR");
    if (!Array.isArray(resp) || resp.length === 0) {
      var perr = new Error("no PTR records for " + ip);
      perr.code = "ENODATA";
      throw perr;
    }
    var names = [];
    for (var pi = 0; pi < resp.length; pi += 1) {
      var nm = String(resp[pi]).replace(/\.$/, "");
      if (nm.length > 0) names.push(nm);
    }
    if (names.length === 0) {
      var perr2 = new Error("no PTR records for " + ip);
      perr2.code = "ENODATA";
      throw perr2;
    }
    return names;
  }
  var r = await _getDefaultResolver().query(qname, "PTR");
  var out = [];
  for (var i = 0; i < r.rrs.length; i += 1) {
    var rr = r.rrs[i];
    if (rr && rr.type === 12) {
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
    if (p.length !== 4) return null;
    return p[3] + "." + p[2] + "." + p[1] + "." + p[0] + ".in-addr.arpa";
  }
  if (net.isIPv6(ip)) {
    var groups = ipUtils.expandIpv6Groups(ip);
    if (!groups) return null;
    var hex = "";
    for (var i = 0; i < groups.length; i += 1) {
      var s = groups[i].toString(16);
      while (s.length < 4) s = "0" + s;
      hex += s;
    }
    var rev = hex.split("").reverse().join(".");
    return rev + ".ip6.arpa";
  }
  return null;
}

function _ipv4ToInt(ip) {
  var parts = ip.split(".");
  if (parts.length !== 4) return null;
  var n = 0;
  for (var i = 0; i < 4; i += 1) {
    var p = parseInt(parts[i], 10);
    if (!isFinite(p) || p < 0 || p > 255) return null;
    n = (n * 256) + p;
  }
  return n;
}

function _ipv6Expand(ip) {
  return ipUtils.expandIpv6Groups(ip);
}

function _ipv6InCidr(ip, cidr) {
  var slash = cidr.indexOf("/");
  var networkAddr = slash === -1 ? cidr : cidr.slice(0, slash);
  var mask = slash === -1 ? 128 : parseInt(cidr.slice(slash + 1), 10);
  if (!isFinite(mask) || mask < 0 || mask > 128) return false;
  var ipGroups  = _ipv6Expand(ip);
  var netGroups = _ipv6Expand(networkAddr);
  if (!ipGroups || !netGroups) return false;
  if (mask === 0) return true;
  var fullGroups = Math.floor(mask / 16);
  var remainBits = mask - fullGroups * 16;
  for (var g = 0; g < fullGroups; g += 1) {
    if (ipGroups[g] !== netGroups[g]) return false;
  }
  if (remainBits > 0 && fullGroups < 8) {
    var groupMask = (0xffff << (16 - remainBits)) & 0xffff;
    if ((ipGroups[fullGroups] & groupMask) !== (netGroups[fullGroups] & groupMask)) return false;
  }
  return true;
}

function _ipv4InCidr(ip, cidr) {
  var slash = cidr.indexOf("/");
  var networkAddr = slash === -1 ? cidr : cidr.slice(0, slash);
  var mask = slash === -1 ? 32 : parseInt(cidr.slice(slash + 1), 10);
  if (!isFinite(mask) || mask < 0 || mask > 32) return false;
  var ipInt = _ipv4ToInt(ip);
  var netInt = _ipv4ToInt(networkAddr);
  if (ipInt === null || netInt === null) return false;
  if (mask === 0) return true;
  var bits = 32 - mask;
  var maskInt = (BigInt("0xFFFFFFFF") << BigInt(bits)) & BigInt("0xFFFFFFFF");
  return (BigInt(ipInt) & maskInt) === (BigInt(netInt) & maskInt);
}

var SPF_MACRO_MAX_EXPANDED_BYTES = 253;
var SPF_MACRO_DELIMS = ".-+,/_=";

function _ipv6Nibbles(ip) {
  var groups = ipUtils.expandIpv6Groups(ip);
  if (!groups) return null;
  var nibbles = [];
  for (var i = 0; i < groups.length; i += 1) {
    var s = groups[i].toString(16);
    while (s.length < 4) s = "0" + s;
    for (var j = 0; j < 4; j += 1) nibbles.push(s.charAt(j));
  }
  return nibbles;
}

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
    case "p": return "unknown";
    default:  return "";
  }
}

function _spfApplyTransform(value, digits, reverse, delims) {
  if (value.length === 0) return "";
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
    var close = macroString.indexOf("}", i + 2);
    if (close === -1) {
      throw new MailAuthError("mail-auth/spf-macro-bad-syntax",
        "SPF macro '%{' has no closing '}' (RFC 7208 §7.1)");
    }
    var body = macroString.slice(i + 2, close);
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
    while (out.length > SPF_MACRO_MAX_EXPANDED_BYTES) {
      var dot = out.indexOf(".");
      if (dot === -1) { out = out.slice(out.length - SPF_MACRO_MAX_EXPANDED_BYTES); break; }
      out = out.slice(dot + 1);
    }
  }
  return out;
}

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
    mechanisms.push({ qualifier: qualifier, mechanism: mech.toLowerCase(), arg: arg, raw: p });
  }
  Object.defineProperty(mechanisms, "modifiers", { value: modifiers });
  return mechanisms;
}

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
  if (matches[0].length > SPF_RECORD_MAX_BYTES) {
    return { kind: "permerror",
             reason: "domain " + domain + " SPF record is " + matches[0].length +
                     " bytes; RFC 7208 §3.3 caps at " + SPF_RECORD_MAX_BYTES };
  }
  return { kind: "found", record: matches[0] };
}

function _parseADualCidr(raw, mech, defaultDomain) {
  var rest   = raw.slice(mech.length);
  var domain = defaultDomain;
  var v4Mask = 32;
  var v6Mask = 128;

  if (rest.charAt(0) === ":") {
    rest = rest.slice(1);
    var slashAt = rest.indexOf("/");
    if (slashAt === -1) { domain = rest; rest = ""; }
    else { domain = rest.slice(0, slashAt); rest = rest.slice(slashAt); }
  }

  if (rest.length > 0) {
    var dblSlash = rest.indexOf("//");
    var v4Part = "";
    var v6Part = "";
    if (dblSlash !== -1) {
      v4Part = rest.slice(0, dblSlash);
      v6Part = rest.slice(dblSlash + 2);
    } else {
      v4Part = rest;
    }
    if (v4Part.length > 0) {
      if (v4Part.charAt(0) !== "/") {
        throw new MailAuthError("mail-auth/spf-bad-cidr",
          "SPF " + mech + " dual-cidr malformed: " + JSON.stringify(raw));
      }
      var v4Str = v4Part.slice(1);
      if (v4Str.length === 0) {
        throw new MailAuthError("mail-auth/spf-bad-cidr",
          "SPF " + mech + " v4 cidr-length is empty (RFC 7208 §5.3/§5.4 grammar requires 1*DIGIT): " +
          JSON.stringify(raw));
      }
      var v4n = parseInt(v4Str, 10);
      if (!isFinite(v4n) || v4n < 0 || v4n > 32 || String(v4n) !== v4Str) {
        throw new MailAuthError("mail-auth/spf-bad-cidr",
          "SPF " + mech + " v4 cidr-length invalid: " + JSON.stringify(raw));
      }
      v4Mask = v4n;
    }
    if (dblSlash !== -1) {
      if (v6Part.length === 0) {
        throw new MailAuthError("mail-auth/spf-bad-cidr",
          "SPF " + mech + " v6 cidr-length is empty (RFC 7208 §5.3/§5.4 grammar requires 1*DIGIT): " +
          JSON.stringify(raw));
      }
      var v6n = parseInt(v6Part, 10);
      if (!isFinite(v6n) || v6n < 0 || v6n > 128 || String(v6n) !== v6Part) {
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

async function _spfMatchAMx(mech, raw, ip, isIpv6, defaultDomain, dnsLookup, lookups, macroVars) {
  var parsed;
  try { parsed = _parseADualCidr(raw, mech, defaultDomain); }
  catch (e) { return { error: "permerror", reason: e.message }; }

  if (macroVars && parsed.domain.indexOf("%") !== -1) {
    try { parsed.domain = _spfExpandMacros(parsed.domain, macroVars).toLowerCase(); }
    catch (e) { return { error: "permerror", reason: e.message }; }
    if (!parsed.domain || parsed.domain.length === 0) {
      return { error: "permerror",
               reason: "SPF " + mech + ": domain-spec expanded to empty (RFC 7208 §7)" };
    }
  }

  var mask = isIpv6 ? parsed.v6Mask : parsed.v4Mask;
  var family = isIpv6 ? 6 : 4;

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
  } else {
    var mxHosts;
    try { mxHosts = await _safeResolveMx(parsed.domain, dnsLookup); }
    catch (e) {
      var mcode = e && e.code;
      if (mcode === "ENOTFOUND" || mcode === "ENODATA") return { match: false };
      return { error: "temperror",
               reason: "SPF mx:" + parsed.domain + " MX lookup failed: " +
                       ((e && e.message) || String(e)) };
    }
    if (mxHosts.length > 10) {
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

async function spfVerify(opts) {
  opts = opts || {};
  validateOpts(opts, ["ip", "mailFrom", "helo", "dnsLookup"], "mail.spf.verify");
  if (typeof opts.ip !== "string") {
    throw new MailAuthError("mail-auth/spf-bad-ip",
      "spf.verify: ip must be a string");
  }
  var mailFromStr = opts.mailFrom ? String(opts.mailFrom) : "";
  if (mailFromStr && mailFromStr.indexOf("@") !== mailFromStr.lastIndexOf("@")) {
    return { result: "permerror", domain: null,
             explanation: "mailFrom has more than one '@' (not a valid addr-spec)",
             lookupCount: 0 };
  }
  var domain = opts.mailFrom
    ? mailFromStr.split("@")[1]
    : opts.helo;
  if (typeof domain !== "string" || domain.length === 0) {
    throw new MailAuthError("mail-auth/spf-bad-domain",
      "spf.verify: mailFrom or helo is required");
  }

  var lookups = { count: 0, limit: SPF_DNS_LOOKUP_LIMIT, void: 0 };
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
  var result = await _spfEvaluateDomain(domain.toLowerCase(), opts.ip,
                                          opts.dnsLookup, lookups,
                                          { isInitial: true, macroVars: macroVars });
  return {
    result: result.verdict,
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
  if ((lookups.void || 0) > SPF_VOID_LOOKUP_LIMIT) {
    return { verdict: "permerror",
             explanation: "SPF void-lookup limit exceeded (RFC 7208 §4.6.4)" };
  }
  if ((ctx.redirectDepth || 0) > SPF_REDIRECT_DEPTH_LIMIT) {
    return { verdict: "permerror",
             explanation: "SPF redirect= recursion limit exceeded (RFC 7208 §6.1)" };
  }
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
    lookups.void = (lookups.void || 0) + 1;
    return { verdict: "none", explanation: "no SPF record at " + domain };
  }

  var mechanisms;
  try { mechanisms = _parseSpfRecord(fetched.record); }
  catch (e) {
    return { verdict: "permerror", explanation: e.message };
  }

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
      else if (inner.verdict === "none") {
        return { verdict: "permerror",
                 explanation: "include:" + m.arg + " has no SPF record (RFC 7208 §5.2)" };
      }
    } else if (m.mechanism === "a" || m.mechanism === "mx") {
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
      if (!m.arg) continue;
      var existsTarget;
      try { existsTarget = _spfExpandMacros(m.arg, macroVars); }
      catch (e) { return { verdict: "permerror", explanation: e.message }; }
      if (!existsTarget || existsTarget.length === 0) {
        return { verdict: "permerror",
                 explanation: "SPF exists: expanded to an empty domain (RFC 7208 §5.7)" };
      }
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

  var mods = mechanisms.modifiers || [];
  for (var rmi = 0; rmi < mods.length; rmi += 1) {
    if (mods[rmi].name === "redirect" && mods[rmi].value) {
      var redirectTarget;
      try { redirectTarget = _spfExpandMacros(mods[rmi].value, macroVars); }
      catch (e) { return { verdict: "permerror", explanation: e.message }; }
      var redirected = await _spfEvaluateDomain(
        redirectTarget.toLowerCase(), ip, dnsLookup, lookups,
        { redirectDepth: (ctx.redirectDepth || 0) + 1, macroVars: macroVars });
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
  if (matches.length > 1) return null;
  return matches[0];
}

var DMARC_MAX_QNAME_OCTETS = 253;
var DMARC_TREE_WALK_MAX_LABELS = 8;
var DMARC_TREE_WALK_LABEL_FLOOR = 7;

function _dmarcAuthorDomainLabels(domain) {
  var d = publicSuffix.canonicalDomain(String(domain));
  if (!d) return null;
  return d.split(".");
}

function _dmarcTreeWalkTargets(domain) {
  var labels = _dmarcAuthorDomainLabels(domain);
  if (labels === null || labels.length === 0) return [];
  var targets = [labels.join(".")];
  var rest = labels.length >= DMARC_TREE_WALK_MAX_LABELS
    ? labels.slice(labels.length - DMARC_TREE_WALK_LABEL_FLOOR)
    : labels.slice(1);
  while (rest.length > 0) {
    targets.push(rest.join("."));
    rest = rest.slice(1);
  }
  return targets;
}

async function _dmarcTreeWalk(domain, dnsLookup) {
  var targets = _dmarcTreeWalkTargets(domain);
  var found = [];
  var transient = false;
  var start = targets.length > 0 ? targets[0] : null;
  var skipped = false;
  var unreadBelowClosestRecord = false;
  var queried = 0;
  for (var i = 0; i < targets.length; i += 1) {
    var raw;
    var parsed;
    if (("_dmarc." + targets[i]).length > DMARC_MAX_QNAME_OCTETS) continue;
    try {
      queried += 1;
      raw = await _fetchDmarcRecord(targets[i], dnsLookup);
      if (!raw) continue;
      parsed = _parseDmarcRecord(raw);
    } catch (e) {
      if (i === 0) throw e;
      if (_isPermanentDmarcError(e)) {
        if (found.length > 0) continue;
        throw e;
      }
      transient = true;
      skipped = true;
      if (found.length === 0) unreadBelowClosestRecord = true;
      continue;
    }
    found.push({ domain: targets[i], policy: parsed, labels: targets[i].split(".").length });
    if (parsed.psd === "n" || parsed.psd === "y") break;
  }
  return { found: found, transient: transient, start: start, skipped: skipped,
           queried: queried, unreadBelowClosestRecord: unreadBelowClosestRecord };
}

function _isPermanentDmarcError(e) {
  return !!(e && typeof e.code === "string" &&
    (e.code === "mail-auth/dmarc-bad-version" ||
     e.code === "mail-auth/dmarcbis-bad-tag" ||
     e.code === "mail-auth/dmarc-missing-policy"));
}

function _dmarcRecordAt(found, domain) {
  return found.filter(function (r) { return r.domain === domain; })[0] || null;
}

function _dmarcOrganizationalDomain(found, startDomain) {
  var i;
  for (i = 0; i < found.length; i += 1) {
    if (found[i].policy.psd === "n") return { domain: found[i].domain, via: "psd-n" };
  }
  for (i = 0; i < found.length; i += 1) {
    if (found[i].policy.psd !== "y") continue;
    if (found[i].domain === startDomain) {
      return { domain: startDomain, via: "psd-y-self" };
    }
    var below = _labelBelow(startDomain, found[i].domain);
    if (below) return { domain: below, via: "psd-y" };
  }
  var fewest = null;
  for (i = 0; i < found.length; i += 1) {
    if (fewest === null || found[i].labels < fewest.labels) fewest = found[i];
  }
  return fewest ? { domain: fewest.domain, via: "fewest-labels" } : null;
}

function _labelBelow(startDomain, ancestor) {
  var start = String(startDomain).toLowerCase().split(".");
  var anc = String(ancestor).toLowerCase().split(".");
  if (anc.length >= start.length) return null;
  if (start.slice(start.length - anc.length).join(".") !== anc.join(".")) return null;
  return start.slice(start.length - anc.length - 1).join(".");
}

var DMARC_VALID_P = { none: 1, quarantine: 1, reject: 1 };
var DMARCBIS_VALID_NP = { none: 1, quarantine: 1, reject: 1 };
var DMARCBIS_VALID_PSD = { y: 1, n: 1, u: 1 };

function _parseDmarcRecord(text) {
  var policy = { v: null, p: null, sp: null, np: null, psd: null,
                 pct: 100, adkim: "r", aspf: "r" };
  var pairs = structuredFields.parseTagList(text);
  for (var i = 0; i < pairs.length; i += 1) {
    var key = pairs[i][0];
    var val = pairs[i][1];
    if (key === "v")     policy.v = val;
    else if (key === "p") {
      var pVal = val.toLowerCase();
      if (!Object.prototype.hasOwnProperty.call(DMARC_VALID_P, pVal)) {
        throw new MailAuthError("mail-auth/dmarcbis-bad-tag",
          "DMARC p= must be one of none|quarantine|reject, got " + JSON.stringify(val));
      }
      policy.p = pVal;
    }
    else if (key === "sp") {
      var spVal = val.toLowerCase();
      if (!Object.prototype.hasOwnProperty.call(DMARC_VALID_P, spVal)) {
        throw new MailAuthError("mail-auth/dmarcbis-bad-tag",
          "DMARC sp= must be one of none|quarantine|reject, got " + JSON.stringify(val));
      }
      policy.sp = spVal;
    }
    else if (key === "pct")   policy.pct = parseInt(val, 10);
    else if (key === "adkim") policy.adkim = val.toLowerCase();
    else if (key === "aspf")  policy.aspf = val.toLowerCase();
    else if (key === "np") {
      var npVal = val.toLowerCase();
      if (!Object.prototype.hasOwnProperty.call(DMARCBIS_VALID_NP, npVal)) {
        throw new MailAuthError("mail-auth/dmarcbis-bad-tag",
          "DMARC np= must be one of none|quarantine|reject, got " + JSON.stringify(val));
      }
      policy.np = npVal;
    }
    else if (key === "psd") {
      var psdVal = val.toLowerCase();
      if (!Object.prototype.hasOwnProperty.call(DMARCBIS_VALID_PSD, psdVal)) {
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
  if (policy.p === null) {
    throw new MailAuthError("mail-auth/dmarc-missing-policy",
      "DMARC record has no required p= tag (RFC 9989 §4.7)");
  }
  return policy;
}

function _alignmentCheck(fromDomain, authDomain, mode, boundary) {
  if (!fromDomain || !authDomain) return false;
  var f = publicSuffix.canonicalDomain(fromDomain);
  var a = publicSuffix.canonicalDomain(authDomain);
  if (!f || !a) return false;
  if (mode === "s") return f === a;
  if (f === a) return true;
  if (boundary) {
    var b = publicSuffix.canonicalDomain(boundary);
    if (!b) return false;
    return _isAtOrUnder(f, b) && _isAtOrUnder(a, b);
  }
  var fOrg = null;
  var aOrg = null;
  try { fOrg = publicSuffix.organizationalDomain(f); } catch (_e) { fOrg = null; }
  try { aOrg = publicSuffix.organizationalDomain(a); } catch (_e) { aOrg = null; }
  if (fOrg && aOrg && fOrg === aOrg) return true;
  return false;
}

function _isAtOrUnder(domain, ancestor) {
  if (domain === ancestor) return true;
  var d = String(domain).split(".");
  var a = String(ancestor).split(".");
  if (d.length <= a.length) return false;
  return d.slice(d.length - a.length).join(".") === a.join(".");
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
  if (opts.from.indexOf("@") !== opts.from.lastIndexOf("@")) {
    throw new MailAuthError("mail-auth/dmarc-bad-from",
      "dmarc.evaluate: opts.from has more than one '@' (not a valid addr-spec)");
  }
  var fromDomain = opts.from.split("@")[1];
  if (!fromDomain) {
    throw new MailAuthError("mail-auth/dmarc-bad-from",
      "dmarc.evaluate: opts.from is missing the @domain part");
  }
  fromDomain = fromDomain.toLowerCase();
  if (_dmarcAuthorDomainLabels(fromDomain) === null) {
    throw new MailAuthError("mail-auth/dmarc-bad-from",
      "dmarc.evaluate: the From domain has an empty label (not a valid domain name)");
  }

  var orgDomain = null;
  try { orgDomain = publicSuffix.organizationalDomain(fromDomain); }
  catch (_e) { orgDomain = null; }

  var policy = null;
  var policyOriginDomain = null;
  var orgDomainPolicyApplied = false;
  var psdPolicyApplied = false;
  var alignmentBoundary = null;
  var walkSkipped = false;
  var alignmentExactOnly = false;
  try {
    var walk = await _dmarcTreeWalk(fromDomain, opts.dnsLookup);
    var found = walk.found;
    var atStart = _dmarcRecordAt(found, walk.start);
    walkSkipped = walk.skipped === true;
    if (walk.unreadBelowClosestRecord) {
      throw new MailAuthError("mail-auth/dmarc-lookup-failed",
        "DMARC tree walk could not complete for " + fromDomain +
        " — a name below the record that would apply did not resolve");
    }
    var selected = _dmarcOrganizationalDomain(found, walk.start);
    if (selected && (selected.via === "psd-n" || selected.via === "psd-y")) {
      alignmentBoundary = selected.domain;
    }
    if (selected && selected.via === "psd-y-self") alignmentExactOnly = true;

    if (atStart) {
      policy = atStart.policy;
      policyOriginDomain = atStart.domain;
    } else if (found.length > 0) {
      var chosen = found[0];
      chosen.policy.p = chosen.policy.sp || chosen.policy.p;
      policy = chosen.policy;
      policyOriginDomain = chosen.domain;
      if (chosen.policy.psd === "y") psdPolicyApplied = true;
      else orgDomainPolicyApplied = true;
    }
  } catch (e) {
    var permanent = _isPermanentDmarcError(e);
    return { result: permanent ? "permerror" : "temperror", explanation: e.message,
             policy: null, alignment: { spf: false, dkim: false },
             orgDomain: orgDomain };
  }
  if (!policy) {
    return { result: "none",
             explanation: "no DMARC record at any of the " + walk.queried +
                          " name(s) queried from _dmarc." + walk.start + " upward",
             policy: null, alignment: { spf: false, dkim: false },
             orgDomain: orgDomain };
  }

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

  var relaxedUnavailable = walkSkipped || alignmentExactOnly;
  var alignSpf = relaxedUnavailable ? "s" : policy.aspf;
  var alignDkim = relaxedUnavailable ? "s" : policy.adkim;

  var spfAligned = opts.spf && opts.spf.result === "pass" &&
                   _alignmentCheck(fromDomain, spfDomain, alignSpf, alignmentBoundary);
  var dkimAligned = false;
  for (var i = 0; i < dkimResults.length; i += 1) {
    var d = dkimResults[i];
    if (d && d.result === "pass" &&
        _alignmentCheck(fromDomain, d.d || d.domain, alignDkim, alignmentBoundary)) {
      dkimAligned = true;
      break;
    }
  }

  var pass = spfAligned || dkimAligned;
  var pctRaw = parseInt(policy.pct, 10);
  var pct = isFinite(pctRaw) && pctRaw >= 0 && pctRaw <= 100 ? pctRaw : 100;
  var sampleRoll;
  if (typeof opts.pctSampleKey === "string" && opts.pctSampleKey.length > 0) {
    var hash = nodeCrypto.createHash("shake256", { outputLength: 4 })
                          .update(String(opts.pctSampleKey)).digest();
    var u32 = (hash[0] << 24 >>> 0) + (hash[1] << 16) + (hash[2] << 8) + hash[3];
    sampleRoll = u32 % 100;
  } else {
    sampleRoll = bCrypto.randomInt(0, 100);
  }
  var sampled = !pass && pct < 100 && sampleRoll >= pct;
  var recommendedAction;
  if (pass) {
    recommendedAction = "deliver";
  } else if (policy.p === "none") {
    recommendedAction = "deliver";
  } else if (sampled) {
    recommendedAction = policy.p === "reject" ? "quarantine" : "none";
  } else {
    recommendedAction = policy.p === "reject" ? "reject" : "quarantine";
  }

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

var ARC_MAX_HOPS = 50;

function _arcInstanceOf(value) {
  var m = String(value).match(/(?:^|[;,\s])i=(\d{1,3})\b/);
  if (!m) return null;
  var inst = parseInt(m[1], 10);
  return (isFinite(inst) && inst >= 1) ? inst : null;
}

async function arcVerify(rfc822, opts) {
  if ((!Buffer.isBuffer(rfc822) && typeof rfc822 !== "string") || rfc822.length === 0) {
    throw new MailAuthError("mail-auth/arc-bad-input",
      "arc.verify: rfc822 must be a non-empty Buffer or string");
  }
  rfc822 = dkim._toWire(rfc822);
  opts = opts || {};
  rfc822 = rfc822.replace(/\r?\n/g, "\r\n");
  var headers = _parseHeaderLines(_splitHeaders(rfc822));
  var hops = [];
  var seenSlot = {};

  var duplicate = false;
  var maxInstanceSeen = 0;
  var orderTrail = [];
  for (var i = 0; i < headers.length; i += 1) {
    var line = headers[i];
    var khv = structuredFields.parseKeyValuePiece(line, ":");
    if (khv.value === null) continue;
    var name = khv.key;
    var value = khv.value.trim();
    if (name !== "arc-seal" && name !== "arc-message-signature" &&
        name !== "arc-authentication-results") continue;
    var inst = _arcInstanceOf(value);
    if (inst === null) continue;
    if (inst > maxInstanceSeen) maxInstanceSeen = inst;
    var slotKey = inst + ":" + name;
    if (seenSlot[slotKey]) { duplicate = true; continue; }
    seenSlot[slotKey] = true;
    if (!hops[inst - 1]) hops[inst - 1] = { instance: inst };
    hops[inst - 1][name] = value;
    orderTrail.push({ inst: inst, name: name, idx: i });
  }

  var orderFail = null;
  if (orderTrail.length > 0) {
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

  var perHop = [];
  var anyFail = false;
  var anyHardFail = false;
  var arcClockSkewMs = numericBounds.isNonNegativeFiniteInt(opts.clockSkewMs)
    ? opts.clockSkewMs : C.TIME.minutes(5);
  var nowSec = Math.floor(Date.now() / 1000);

  for (var hopIdx = 0; hopIdx < hops.length; hopIdx += 1) {
    var hop = hops[hopIdx];

    var amsTags = _parseArcTagList(hop["arc-message-signature"]);
    var asTags  = _parseArcTagList(hop["arc-seal"]);
    var amsT = amsTags.t ? parseInt(amsTags.t, 10) : null;
    var amsX = amsTags.x ? parseInt(amsTags.x, 10) : null;
    var asT  = asTags.t  ? parseInt(asTags.t, 10)  : null;
    var asX  = asTags.x  ? parseInt(asTags.x, 10)  : null;
    var skewSec = Math.floor(arcClockSkewMs / 1000);
    var timeFault = null;
    if (amsTags.t && (!isFinite(amsT) || amsT - skewSec > nowSec)) timeFault = isFinite(amsT) ? "ams-t-future" : "ams-t-unparseable";
    if (amsTags.x && (!isFinite(amsX) || amsX + skewSec < nowSec)) timeFault = isFinite(amsX) ? "ams-x-expired" : "ams-x-unparseable";
    if (asTags.t  && (!isFinite(asT)  || asT  - skewSec > nowSec)) timeFault = isFinite(asT)  ? "as-t-future"  : "as-t-unparseable";
    if (asTags.x  && (!isFinite(asX)  || asX  + skewSec < nowSec)) timeFault = isFinite(asX)  ? "as-x-expired" : "as-x-unparseable";

    var amsResult = timeFault
      ? { result: "fail", errors: ["ams: " + timeFault + " (RFC 8617 §5.2)"] }
      : await _verifyArc(rfc822, hop, hops, "ams", opts.dnsLookup, dkim);

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
    if (amsResult.result !== "pass" || asResult.result !== "pass") {
      anyFail = true;
      if ((amsResult.result !== "pass" && amsResult.result !== "temperror") ||
          (asResult.result  !== "pass" && asResult.result  !== "temperror")) {
        anyHardFail = true;
      }
    }
  }

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
  var transientOut = false;
  if (hopRuleViolation) {
    chainStatus = "fail";
    reasonOut = hopRuleViolation;
  } else if (anyFail) {
    chainStatus = "fail";
    var lastSeal = perHop.length ? perHop[perHop.length - 1].asResult : null;
    var terminalCv = lastCv === "fail" && lastSeal === "pass";
    reasonOut = terminalCv ? "last-as-cv=fail"
      : (anyHardFail ? "signature-verification-failed" : "key-lookup-unavailable");
    transientOut = !terminalCv && !anyHardFail;
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
  if (transientOut) out.transient = true;
  return out;
}

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

  var canonicalized;
  if (kind === "ams") {
    return await _verifyAmsViaDkim(rfc822, hop, sigValue, tags, dkim, dnsLookup);
  }

  canonicalized = "";
  for (var prior = 0; prior < hop.instance; prior += 1) {
    var p = allHops[prior];
    if (!p) continue;
    canonicalized += _canonRelaxedHeader("ARC-Authentication-Results", p["arc-authentication-results"]);
    canonicalized += _canonRelaxedHeader("ARC-Message-Signature",      p["arc-message-signature"]);
    if (p.instance !== hop.instance) {
      canonicalized += _canonRelaxedHeader("ARC-Seal", p["arc-seal"]);
    }
  }
  var asUnsigned = dkim._stripBTagValue(sigValue);
  canonicalized += _canonRelaxedHeader("ARC-Seal", asUnsigned).replace(/\r\n$/, "");

  var asKFamily   = keyTags.k !== undefined ? String(keyTags.k).toLowerCase() : "rsa";
  var asSigFamily = String(tags.a || "").toLowerCase().split("-")[0];
  if (asKFamily !== asSigFamily) {
    return { result: "permerror",
      errors: [kind + ": key k=" + asKFamily + " does not match seal a=" + tags.a + " (RFC 6376 §3.6.1)"] };
  }

  return _runVerify(canonicalized, tags.b, tags.a, keyTags.p, "as");
}

async function _verifyAmsViaDkim(rfc822, hop, sigValue, tags, dkim, dnsLookup) {
  var renamedHeader = "DKIM-Signature: " + sigValue;
  var sep = rfc822.indexOf("\r\n\r\n");
  if (sep === -1) sep = rfc822.indexOf("\n\n");
  var headerEnd = sep === -1 ? rfc822.length : sep;
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
      var aarInst = _arcInstanceOf(khv.value);
      if (aarInst === null || aarInst !== hop.instance) continue;
    }
    rebuilt.push(line);
  }
  rebuilt.unshift(renamedHeader);
  var synthetic = rebuilt.join("\r\n") + (sep === -1 ? "" :
    rfc822.slice(headerEnd));
  var verifyOpts = { dnsLookup: dnsLookup };
  verifyOpts[ARC_AMS_REUSE] = true;
  var rv = await dkim.verify(dkim._wireBytes(synthetic), verifyOpts);
  if (!Array.isArray(rv) || rv.length === 0) {
    return { result: "permerror", errors: ["ams: dkim verifier returned no results"] };
  }
  return { result: rv[0].result, errors: rv[0].errors || [] };
}

function _parseArcTagList(value) {
  var pairs = structuredFields.parseTagList(value,
    { stripValueWs: true, lowerKey: false });
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
  return dkim.canonHeaderRelaxed(name, value);
}

var ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function _pemFromB64KeyMaterial(b64) {
  var raw = null;
  try { raw = Buffer.from(b64, "base64"); } catch (_e) { raw = null; }
  if (raw && raw.length === 32) {
    b64 = Buffer.concat([ED25519_SPKI_PREFIX, raw]).toString("base64");
  }
  var pem = "-----BEGIN PUBLIC KEY-----\n";
  for (var i = 0; i < b64.length; i += 64) {
    pem += b64.slice(i, i + 64) + "\n";
  }
  pem += "-----END PUBLIC KEY-----\n";
  return pem;
}

function _runVerify(signedString, sigB64, algorithm, keyB64, label) {
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
    verified = nodeCrypto.verify(nodeAlgo, Buffer.from(signedString, "latin1"), keyObj, sigBuf);
  } catch (e) {
    return { result: "permerror",
             errors: [label + ": verify threw: " + ((e && e.message) || String(e))] };
  }
  return verified
    ? { result: "pass", errors: [] }
    : { result: "fail", errors: [label + ": signature verification failed"] };
}

void C;

async function arcEvaluate(rfc822, opts) {
  if ((!Buffer.isBuffer(rfc822) && typeof rfc822 !== "string") || rfc822.length === 0) {
    throw new MailAuthError("mail-auth/arc-bad-input",
      "arc.evaluate: rfc822 must be a non-empty Buffer or string");
  }
  rfc822 = dkim._toWire(rfc822);
  var rfc822Octets = dkim._wireBytes(rfc822);
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

  var verdict = await arcVerify(rfc822Octets, opts);
  var out = {
    chainStatus:    verdict.chainStatus,
    hopCount:       verdict.hopCount,
    trusted:        false,
    trustedHop:     null,
    trustedDomain:  null,
    trust:          verdict.chainStatus === "pass" ? "unverified" : "failed",
    trustedHops:    [],
    finalAr:        null,
    breakAt:        null,
  };
  if (verdict.reason) out.reason = verdict.reason;
  if (verdict.transient) out.transient = true;

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
      var sealInst = _arcInstanceOf(value);
      var dMatch = value.match(/(?:^|[;,\s])d=([^\s;]+)/);                        // allow:regex-no-length-cap — header bounded by RFC 5322 998
      if (sealInst !== null && dMatch) hopDomains[sealInst] = dMatch[1].toLowerCase();
    } else if (name === "arc-authentication-results") {
      var arInst = _arcInstanceOf(value);
      if (arInst !== null) hopAr[arInst] = value;
    }
  }

  if (verdict.hopCount > 0) {
    out.finalAr = hopAr[verdict.hopCount] || null;
  }

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

var AR_RESULTS_BY_METHOD = {
  auth:           { pass: 1, fail: 1, none: 1, permerror: 1, temperror: 1 },
  domainkeys:     { pass: 1, fail: 1, neutral: 1, none: 1, permerror: 1, temperror: 1, policy: 1 },
  dkim:           { pass: 1, fail: 1, neutral: 1, none: 1, permerror: 1, temperror: 1, policy: 1 },
  "dkim-adsp":    { pass: 1, fail: 1, discard: 1, nxdomain: 1, none: 1, permerror: 1, temperror: 1 },
  spf:            { pass: 1, fail: 1, softfail: 1, neutral: 1, none: 1, permerror: 1, temperror: 1, policy: 1 },
  "sender-id":    { pass: 1, fail: 1, softfail: 1, neutral: 1, none: 1, permerror: 1, temperror: 1, policy: 1 },
  iprev:          { pass: 1, fail: 1, permerror: 1, temperror: 1 },
  dmarc:          { pass: 1, fail: 1, none: 1, permerror: 1, temperror: 1, hardfail: 1, bestguesspass: 1 },
  arc:            { pass: 1, fail: 1, none: 1 },
  dane:           { pass: 1, fail: 1, none: 1, permerror: 1, temperror: 1 },
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
  if (/[\r\n\0]/.test(version)) {
    throw new MailAuthError("mail-auth/ar-bad-version",
      "authResults.emit: version contains forbidden control characters");
  }
  var head = opts.authservId + (version === "1" ? "" : " " + version);

  if (opts.results.length === 0) {
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
    if (!Object.prototype.hasOwnProperty.call(AR_VALID_METHODS, method)) {
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
      clause += " reason=" + safeBuffer.quoteString(r.reason);
    }
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
      if (!/^[A-Za-z0-9._@\-:[\]]+$/.test(rv)) continue;                            // allow:regex-no-length-cap — bounded by header line cap
      clause += " " + props[k] + "=" + rv;
    }
    clauses.push(clause);
  }

  var fold = opts.fold !== false;
  var sep = fold ? ";\r\n  " : "; ";
  return "Authentication-Results: " + head + ";\r\n  " + clauses.join(sep);
}

function _splitHeaderBlock(message) {
  var idx = message.indexOf("\r\n\r\n");
  if (idx !== -1) return { headers: message.slice(0, idx), body: message.slice(idx + 4) };
  idx = message.indexOf("\n\n");
  if (idx !== -1) return { headers: message.slice(0, idx), body: message.slice(idx + 2) };
  return { headers: message, body: "" };
}

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
    address = authors.lastAddr;
  } else {
    address = value.trim();
    if (/[\s,;:<>]/.test(address)) address = null;
  }
  if (address && address.indexOf("@") !== address.lastIndexOf("@")) address = null;
  var at = address ? address.lastIndexOf("@") : -1;
  var domain = (at > 0 && address && at < address.length - 1)
    ? address.slice(at + 1).toLowerCase()
    : null;
  if (domain && !_isValidFromHostname(domain)) domain = null;
  return { count: count, address: address || null, domain: domain };
}

var _FROM_HOSTNAME_RE =
  /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
function _isValidFromHostname(host) {
  return typeof host === "string" && host.length <= 253 && _FROM_HOSTNAME_RE.test(host);
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
    message = message.toString("latin1");
  }
  if (typeof message !== "string" || message.length === 0) {
    throw new MailAuthError("mail-auth/inbound-bad-message",
      "inbound.verify: message must be a non-empty string or Buffer (the full RFC 5322 message)");
  }
  message = message.replace(/\r?\n/g, "\r\n");
  if (message.indexOf("\r\n\r\n") === -1) message += "\r\n\r\n";
  var mailFrom = (typeof opts.mailFrom === "string" && opts.mailFrom.length > 0) ? opts.mailFrom : null;
  var helo     = (typeof opts.helo === "string" && opts.helo.length > 0) ? opts.helo : null;

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

  var dkimVerifyOpts = { dnsLookup: opts.dnsLookup };
  if (opts.clockSkewMs !== undefined) dkimVerifyOpts.clockSkewMs = opts.clockSkewMs;
  if (opts.maxSignatures !== undefined) dkimVerifyOpts.maxSignatures = opts.maxSignatures;
  if (opts.minRsaBits !== undefined) dkimVerifyOpts.minRsaBits = opts.minRsaBits;
  var messageOctets = dkim._wireBytes(message);
  var dkimResults = await dkim.verify(messageOctets, dkimVerifyOpts);

  var arcResult;
  try {
    arcResult = await arcVerify(messageOctets, { dnsLookup: opts.dnsLookup });
  } catch (e) {
    arcResult = { chainStatus: "fail", hopCount: 0, hops: [],
                  reason: "arc-verify-error: " + ((e && e.message) || String(e)) };
  }

  var headerOctets = _splitHeaderBlock(message).headers;
  var from = _extractFromHeaders(Buffer.from(headerOctets, "latin1").toString("utf8"));
  var dmarc;
  if (from.count === 1 && from.address && from.domain) {
    dmarc = await dmarcEvaluate({
      from:         from.address,
      spf:          spf,
      dkim:         dkimResults,
      dnsLookup:    opts.dnsLookup,
      domainExists: opts.domainExists,
    });
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
        ? "message has no From header (RFC 9989 §5.3.1)"
        : (from.count > 1
            ? "message carries " + from.count + " From authors (RFC 9989 §5.3.1 — multi-From spoofing shape)"
            : "From header has no parsable author domain"),
    };
  }

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
    arResults.push({ method: "arc", result: arcResult.chainStatus });
    authResults = authResultsEmit({ authservId: opts.authservId, results: arResults });
  }

  return { spf: spf, dkim: dkimResults, from: from, dmarc: dmarc,
           arc: arcResult, authResults: authResults };
}

var DMARC_RUA_MAX_REPORT_BYTES = C.BYTES.mib(8);
var DMARC_RUA_MAX_EXPANSION_RATIO = 300;
var DMARC_RUA_MAX_ELEMENTS_PER_RECORD = 32;
var DMARC_RUA_REPORT_HEADER_ELEMENTS  = 64;
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

  var contentType = (opts.contentType || "").toLowerCase();
  var looksGzip = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
  var looksZip  = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b &&
                  bytes[2] === 0x03 && bytes[3] === 0x04;
  if (looksZip || (contentType.indexOf("zip") !== -1 && !looksGzip &&
                   contentType.indexOf("gzip") === -1)) {
    throw new MailAuthError("mail-auth/dmarc-rua-zip-not-unpacked",
      "dmarc.parseAggregateReport: input is a ZIP archive — read the report " +
      "entry out of it with b.archive.read.zip and pass the XML bytes here");
  }
  if (contentType.indexOf("gzip") !== -1 || looksGzip) {
    try {
      bytes = safeDecompress(bytes, {
        algorithm:          "gzip",
        maxOutputBytes:     DMARC_RUA_MAX_REPORT_BYTES,
        maxCompressedBytes: DMARC_RUA_MAX_REPORT_BYTES,
        maxRatio:           DMARC_RUA_MAX_EXPANSION_RATIO,
        ctx:                "dmarc.parseAggregateReport",
      });
    }
    catch (e) {
      var msg = (e && e.message) || String(e);
      var isBomb = e && (e.code === "safe-decompress/ratio-exceeded" ||
                         e.code === "safe-decompress/output-cap-exceeded");
      if (isBomb) {
        throw new MailAuthError("mail-auth/dmarc-rua-gunzip-bomb",
          "dmarc.parseAggregateReport: gunzip output exceeded " +
          DMARC_RUA_MAX_REPORT_BYTES + " bytes or " +
          DMARC_RUA_MAX_EXPANSION_RATIO + ":1 expansion " +
          "(decompression amplification — refused)");
      }
      throw new MailAuthError("mail-auth/dmarc-rua-gunzip-failed",
        "dmarc.parseAggregateReport: gunzip failed: " + msg);
    }
  }

  var parsed;
  try {
    parsed = safeXml.parse(bytes.toString("utf8"), {
      maxBytes:    DMARC_RUA_MAX_REPORT_BYTES,
      maxElements: DMARC_RUA_MAX_RECORDS_PER_REPORT * DMARC_RUA_MAX_ELEMENTS_PER_RECORD +
                   DMARC_RUA_REPORT_HEADER_ELEMENTS,
    });
  }
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

function _xmlEscapeText(value) {
  return markupEscape(value, { apos: "&apos;" });
}

function _xmlLeaf(tag, value) {
  if (value === undefined || value === null || value === "") return "";
  return "<" + tag + ">" + _xmlEscapeText(value) + "</" + tag + ">";
}

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
      "dmarc.buildAggregateReport: report.reportMetadata is required (RFC 9990 Appendix A)");
  }
  if (!pp || typeof pp !== "object") {
    throw new MailAuthError("mail-auth/dmarc-rua-build-bad-input",
      "dmarc.buildAggregateReport: report.policyPublished is required (RFC 9990 Appendix A)");
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

  var version = _xmlLeaf("version", opts.version || "1.0");
  var doc =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
    "<feedback>" +
    version +
    metaXml +
    policyXml +
    recordXml +
    "</feedback>";

  if (opts.gzip === true) {
    return zlib.gzipSync(Buffer.from(doc, "utf8"));
  }
  return doc;
}

function _isValidPtrName(name) {
  if (typeof name !== "string") return false;
  var trimmed = name.replace(/\.$/, "");
  if (trimmed.length === 0 || trimmed.length > 253) return false;
  var labels = trimmed.split(".");
  for (var i = 0; i < labels.length; i += 1) {
    var lab = labels[i];
    if (lab.length === 0 || lab.length > 63) return false;
    if (!/^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/.test(lab)) return false;
  }
  return true;
}

async function iprevVerify(ip, opts) {
  opts = opts || {};
  validateOpts(opts, ["dnsLookup"], "mail.iprev.verify");
  var dnsLookup = opts.dnsLookup;
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
  try { ptrs = await _safeReverse(ip, dnsLookup); }
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

  var ptr = String(ptrs[0]).replace(/\.$/, "");
  if (!_isValidPtrName(ptr)) {
    return { result: "permerror", ip: ip,
             ptr: ptr, forward: [], fcrdns: false,
             explanation: "PTR record is not a valid DNS name shape (RFC 8601 §3)" };
  }
  var isV6 = net.isIPv6(ip);
  var forwardAddrs;
  try {
    forwardAddrs = await _safeResolveA(ptr, isV6 ? 6 : 4, dnsLookup);
  } catch (e) {
    var fcode = e && e.code;
    if (fcode === "ENOTFOUND" || fcode === "ENODATA") {
      return { result: "fail", ip: ip,
               ptr: ptr, forward: [], fcrdns: false,
               explanation: "no forward record for PTR " + ptr };
    }
    return { result: "temperror", ip: ip,
             ptr: ptr, forward: [], fcrdns: false,
             explanation: "forward lookup of " + ptr + " transient failure: " +
                          (fcode || (e && e.message) || String(e)) };
  }
  var forward = Array.isArray(forwardAddrs) ? forwardAddrs.slice() : [];
  var ipCanon = isV6 ? ipUtils.expandIpv6Hex(ip) : ip.toLowerCase();
  var fcrdns = false;
  for (var i = 0; i < forward.length; i += 1) {
    var fwdStr = String(forward[i]);
    var fwdCanon = isV6 ? ipUtils.expandIpv6Hex(fwdStr) : fwdStr.toLowerCase();
    if (ipCanon && fwdCanon && fwdCanon === ipCanon) { fcrdns = true; break; }
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

var DMARC_RUF_MAX_REPORT_BYTES = C.BYTES.mib(8);

var DMARC_RUF_MAX_PARTS = 64;

var DMARC_RUF_REQUIRED_FIELDS = ["feedback-type", "auth-failure"];

var DMARC_RUF_AUTH_FAILURE_TYPES = Object.freeze({
  adsp:       1,
  "bodyhash": 1,
  dkim:       1,
  dmarc:      1,
  revoked:    1,
  signature:  1,
  spf:        1,
});
void DMARC_RUF_AUTH_FAILURE_TYPES;

var DMARC_RUF_MAX_REPORTED_HEADERS = 256;

function _rufError(code, message) {
  return { ok: false, error: { code: code, message: message } };
}

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
    map[name.toLowerCase()] = value;
  }
  return { headers: ordered, map: map, truncated: truncated };
}

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
  if (ct.params["report-type"] && ct.params["report-type"].toLowerCase() !== "feedback-report") {
    return _rufError("mail-auth/dmarc-ruf-bad-report",
      "dmarc.parseForensicReport: report-type must be feedback-report (got '" +
      ct.params["report-type"] + "')");
  }
  if (!ct.params.boundary) {
    return _rufError("mail-auth/dmarc-ruf-bad-report",
      "dmarc.parseForensicReport: multipart/report Content-Type lacks boundary parameter");
  }

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

  var feedbackType = String(_field("feedback-type")).toLowerCase();
  if (feedbackType !== "auth-failure") {
    return _rufError("mail-auth/dmarc-ruf-not-auth-failure",
      "dmarc.parseForensicReport: Feedback-Type must be 'auth-failure' for a " +
      "DMARC forensic report (RFC 9991 / RFC 6591), got " +
      JSON.stringify(_field("feedback-type")));
  }

  var reportedMessage = null;
  if (reportedPart) {
    reportedMessage = (reportedPart.body && reportedPart.body.length > 0)
      ? reportedPart.body
      : _reassembleRufPart(reportedPart);
  }
  var reported = _parseReportedHeaders(reportedMessage);

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

    authFailure:           _field("auth-failure"),
    deliveryResult:        _field("delivery-result"),
    identityAlignment:     _field("identity-alignment"),
    dkim: {
      domain:              _field("dkim-domain"),
      identity:            _field("dkim-identity"),
      selector:            _field("dkim-selector"),
      canonicalizedHeader: _field("dkim-canonicalized-header"),
      canonicalizedBody:   _field("dkim-canonicalized-body"),
    },
    spf: {
      dns:                 _field("spf-dns"),
    },

    reportedMessage:       reportedMessage,
    reportedHeaders:       reported.headers,
    reportedHeaderMap:     reported.map,
    reportedHeadersTruncated: reported.truncated,

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
