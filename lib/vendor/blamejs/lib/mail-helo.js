"use strict";
/**
 * @module     b.mail.helo
 * @nav        Mail
 * @title      Mail HELO
 * @order      550
 *
 * @intro
 *   RFC 5321 §4.1.1.1 HELO / EHLO hostname validation primitive +
 *   forward-confirmed-reverse-DNS (FCrDNS, RFC 8601 §2.7.6) verifier.
 *   Composes `b.network.dns.resolver` (v0.9.31) for the rDNS + forward
 *   lookup pair; pairs with `b.guardSmtpCommand` (v0.9.32) which gates
 *   the command-line SHAPE — this primitive evaluates the SEMANTIC
 *   identity claim.
 *
 *   The MX listener (v0.9.36) calls `b.mail.helo.evaluate({ ip,
 *   claimedName, resolver })` at the EHLO boundary and feeds the
 *   verdict into the per-connection policy decision (reject /
 *   greylist-anyway / score-tag for downstream SpamAssassin / accept).
 *
 *   ## Shape gate (RFC 5321 §4.1.1.1 + §4.1.2)
 *
 *   - **Domain form**: LDH labels per RFC 5321 §2.3.5, FQDN with at
 *     least one `.` (operator can demand multi-label via profile).
 *     Bare hostname (no dots) refused under `strict`; localhost-class
 *     claims (`localhost`, `localdomain`) always refused regardless
 *     of profile.
 *   - **Address-literal**: `[1.2.3.4]` IPv4 or `[IPv6:2001:db8::1]`
 *     IPv6 per RFC 5321 §4.1.3 — accepted when matches the connection
 *     IP, refused otherwise (RFC 5321 §4.1.1.1 implies the literal
 *     should be the actual host).
 *   - **Empty / too-long**: refused under all profiles.
 *
 *   ## FCrDNS check (RFC 8601 §2.7.6 / RFC 1912 §2.1)
 *
 *   With `resolver` provided, `evaluate()` issues:
 *
 *     1. PTR for `<connection-ip>.in-addr.arpa` (IPv4) or `.ip6.arpa`
 *        (IPv6) — reverse name.
 *     2. A / AAAA for each PTR result — forward name.
 *     3. Match: at least one forward IP must equal the connection IP
 *        (the FCrDNS contract).
 *
 *   The returned verdict carries the rDNS name(s) + the per-name
 *   forward-match outcome so operator audit pipelines see exactly why
 *   FCrDNS passed or failed.
 *
 *   ## "Generic rDNS" heuristic (operator-configurable)
 *
 *   Many spam sources have FCrDNS-valid rDNS that's CLEARLY a consumer
 *   ISP dynamic pool (`pool-xx-xx.dialup.example.com`,
 *   `dsl-1234.foo.example.net`, etc.). Operators opt-in via
 *   `{ genericRdnsPatterns: [<regex>...] }` and the verdict flags
 *   genericRdns: true. Pre-shipped pattern list lives in
 *   `b.mail.helo.GENERIC_RDNS_PATTERNS` for the common
 *   consumer-ISP shapes; operator extends per-deployment.
 *
 *   ## Verdict shape
 *
 *   ```js
 *   {
 *     action:        "accept" | "reject-shape" | "soft-fail-fcrdns" |
 *                    "match-self-refused" | "literal-mismatch",
 *     shape:         "domain" | "address-literal-v4" |
 *                    "address-literal-v6" | "bare-host" | "invalid",
 *     fcrdns:        {
 *       checked:     boolean,
 *       passed:      boolean,
 *       rdnsNames:   string[],
 *       forwardIps:  string[],
 *       matchedIp:   string | null,
 *     } | null,
 *     genericRdns:   boolean,
 *     reason:        string,
 *   }
 *   ```
 *
 *   ## CVE / threat model
 *
 *   - **HELO spoofing** — RFC 5321 §4.1.1.1 doesn't require HELO
 *     accuracy, but a peer claiming `our-mx-cluster.example.com`
 *     when its FCrDNS resolves elsewhere is suspect. Operator's
 *     `selfNames` list blocks the self-claim spoof.
 *   - **Botnet residential-IP class** — generic-rDNS detection +
 *     RBL composition catches consumer-ISP dynamic-pool sources
 *     before they reach the DATA phase.
 *   - **DNS poisoning of PTR** — composed via `b.network.dns.resolver`,
 *     so PTR queries inherit the resolver's `safeDns` caps, AD-bit
 *     surface, and CVE coverage (CVE-2008-1447 / 2022-3204 /
 *     2023-50387 / 50868 / 2024-1737).
 *
 *   ## When NOT to enforce FCrDNS strict
 *
 *   IPv6 PTR records are spotty across consumer ISPs; FCrDNS-strict
 *   on IPv6 traffic over-rejects. Operator opts to
 *   `{ fcrdnsRequiredFor: ["v4"] }` under `balanced` profile when
 *   they need to accept v6 senders without PTR records (common with
 *   legitimate cloud / VPS providers that don't auto-publish rDNS).
 *
 * @card
 *   RFC 5321 §4.1.1.1 HELO/EHLO validation + RFC 8601 §2.7.6 FCrDNS check. Composes b.network.dns.resolver for PTR + forward lookups. Verdict carries shape + FCrDNS pass/fail + generic-rDNS flag for MX listener policy. Operator-configurable selfNames, genericRdnsPatterns, fcrdnsRequiredFor.
 */

var { defineClass }    = require("./framework-error");
var lazyRequire        = require("./lazy-require");
var ipUtils            = require("./ip-utils");

var audit              = lazyRequire(function () { return require("./audit"); });

var MailHeloError = defineClass("MailHeloError", { alwaysPermanent: true });

// RFC 5321 §2.3.5 LDH label: alphanumeric + hyphen (not leading or
// trailing); §2.3.5 domain: dot-joined LDH labels; total ≤ 255 octets
// per RFC 1035 §2.3.4.
var LDH_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;                                      // allow:regex-no-length-cap — anchored + per-label repeat cap matches RFC 5321 §2.3.5
var ADDR_LIT_V4_RE = /^\[((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\]$/;  // allow:regex-no-length-cap — anchored + per-octet repeat cap
var ADDR_LIT_V6_RE = /^\[IPv6:([0-9a-fA-F:.]+)\]$/;                                                       // allow:regex-no-length-cap — IPv6 textual bounded by overall maxBytes

var DEFAULT_MAX_BYTES = 255;                                                                              // allow:raw-byte-literal — RFC 1035 §2.3.4 cap
var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  // Strict: FQDN (≥1 dot), no localhost, no bare-host, FCrDNS strict
  // for IPv4 + IPv6.
  strict: {
    maxBytes:           DEFAULT_MAX_BYTES,
    requireFqdn:        true,
    refuseBareHost:     true,
    fcrdnsRequiredFor:  ["v4", "v6"],
  },
  // Balanced: FQDN required, FCrDNS strict for v4 only (consumer IPv6
  // PTR records are spotty).
  balanced: {
    maxBytes:           DEFAULT_MAX_BYTES,
    requireFqdn:        true,
    refuseBareHost:     true,
    fcrdnsRequiredFor:  ["v4"],
  },
  // Permissive: shape only; no FCrDNS gate.
  permissive: {
    maxBytes:           DEFAULT_MAX_BYTES,
    requireFqdn:        false,
    refuseBareHost:     false,
    fcrdnsRequiredFor:  [],
  },
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

// Operator-extensible default list of generic-rDNS patterns the
// framework ships. Each is a RegExp — case-insensitive — designed
// to catch the obvious consumer-ISP dynamic-pool naming shapes.
// The framework's value-add is the gate primitive, not curating a
// world-class generic-rDNS list; operators extend per deployment.
var GENERIC_RDNS_PATTERNS = Object.freeze([
  /dynamic/i,                                                                                            // allow:regex-no-length-cap — case-insensitive partial; input length already capped
  /\bdial-?up\b/i,                                                                                       // allow:regex-no-length-cap
  /\bdsl\b/i,                                                                                            // allow:regex-no-length-cap
  /\bcable\b/i,                                                                                          // allow:regex-no-length-cap
  /\bpool[-_]/i,                                                                                         // allow:regex-no-length-cap
  /\bppp[0-9]/i,                                                                                         // allow:regex-no-length-cap
  /\bbroadband\b/i,                                                                                      // allow:regex-no-length-cap
  /\b[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}\b/,                                                     // allow:regex-no-length-cap — IPv4-in-name shape (no anchor on purpose; runs over capped input)
]);

// Localhost-class claims always refused regardless of profile.
var LOCALHOST_REFUSED = Object.freeze({
  "localhost":              true,
  "localhost.localdomain":  true,
  "localdomain":            true,
});

/**
 * @primitive b.mail.helo.evaluate
 * @signature b.mail.helo.evaluate(ctx, opts?)
 * @since     0.9.35
 * @status    stable
 * @related   b.guardSmtpCommand.validate, b.network.dns.resolver.create
 *
 * Evaluate a peer's HELO / EHLO identity claim. Returns a verdict
 * shape the MX listener consumes to drive accept / reject /
 * score-tag policy.
 *
 * @opts
 *   profile:               "strict" | "balanced" | "permissive",
 *   posture:               "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   selfNames:             string[],            // operator's MX hostnames; claim of these by a peer refused
 *   genericRdnsPatterns:   RegExp[],            // additional patterns layered onto built-ins
 *   fcrdnsRequiredFor:     ("v4" | "v6")[],     // overrides profile's FCrDNS list
 *   audit:                 b.audit namespace,
 *
 * @example
 *   var resolver = b.network.dns.resolver.create();
 *   var v = await b.mail.helo.evaluate({
 *     ip:          "203.0.113.42",
 *     claimedName: "mail.example.com",
 *     resolver:    resolver,
 *   }, { profile: "strict" });
 *   if (v.action === "reject-shape") return reply(550, v.reason);
 */
async function evaluate(ctx, opts) {
  opts = opts || {};
  var profile = opts.profile || (opts.posture && COMPLIANCE_POSTURES[opts.posture]) || DEFAULT_PROFILE;
  if (!PROFILES[profile]) {
    throw new MailHeloError("mail-helo/bad-profile",
      "evaluate: unknown profile '" + profile + "'");
  }
  var caps = PROFILES[profile];
  var fcrdnsRequiredFor = Array.isArray(opts.fcrdnsRequiredFor) ? opts.fcrdnsRequiredFor : caps.fcrdnsRequiredFor;
  var selfNames = (opts.selfNames || []).map(function (n) { return String(n).toLowerCase(); });
  var auditImpl = opts.audit || audit();

  if (!ctx || typeof ctx !== "object") {
    throw new MailHeloError("mail-helo/bad-input",
      "evaluate: ctx must be a plain object");
  }
  if (typeof ctx.claimedName !== "string" || ctx.claimedName.length === 0) {
    throw new MailHeloError("mail-helo/bad-input",
      "evaluate: ctx.claimedName must be a non-empty string");
  }
  if (typeof ctx.ip !== "string" || ctx.ip.length === 0) {
    throw new MailHeloError("mail-helo/bad-input",
      "evaluate: ctx.ip must be a non-empty string");
  }

  var claimed = ctx.claimedName.trim();
  if (Buffer.byteLength(claimed, "utf8") > caps.maxBytes) {
    return _emit(auditImpl, "reject-shape", {
      shape:  "invalid",
      reason: "claimedName exceeds " + caps.maxBytes + " bytes (RFC 1035 §2.3.4)",
    });
  }

  // Classify shape: address-literal vs domain vs invalid.
  var v4Lit = claimed.match(ADDR_LIT_V4_RE);
  var v6Lit = claimed.match(ADDR_LIT_V6_RE);
  if (v4Lit) {
    if (v4Lit[1] !== ctx.ip) {
      return _emit(auditImpl, "literal-mismatch", {
        shape:  "address-literal-v4",
        reason: "address-literal '" + v4Lit[1] + "' does not match connection IP '" + ctx.ip + "' (RFC 5321 §4.1.1.1)",
      });
    }
    return _emit(auditImpl, "accept", {
      shape:  "address-literal-v4",
      reason: "address-literal matches connection IP",
    });
  }
  if (v6Lit) {
    // Both sides expanded to canonical form for compare.
    var claimedHex = ipUtils.expandIpv6Hex(v6Lit[1]);
    var ipHex      = ipUtils.expandIpv6Hex(ctx.ip);
    if (!claimedHex || !ipHex || claimedHex !== ipHex) {
      return _emit(auditImpl, "literal-mismatch", {
        shape:  "address-literal-v6",
        reason: "IPv6 address-literal '" + v6Lit[1] + "' does not match connection IP '" + ctx.ip + "' (RFC 5321 §4.1.3)",
      });
    }
    return _emit(auditImpl, "accept", {
      shape:  "address-literal-v6",
      reason: "IPv6 address-literal matches connection IP",
    });
  }

  // Not an address-literal; must be a domain.
  var lower = claimed.toLowerCase();
  if (LOCALHOST_REFUSED[lower]) {
    return _emit(auditImpl, "reject-shape", {
      shape:  "invalid",
      reason: "localhost-class claim '" + lower + "' refused (RFC 6761 §6.3 reserved name)",
    });
  }
  if (selfNames.indexOf(lower) !== -1) {
    return _emit(auditImpl, "match-self-refused", {
      shape:  "domain",
      reason: "peer claims our own MX hostname '" + lower + "' (HELO-self spoofing)",
    });
  }

  var labels = claimed.split(".");
  var isFqdn = labels.length >= 2 && labels.every(function (l) { return l.length > 0; });
  if (!isFqdn && caps.requireFqdn) {
    return _emit(auditImpl, "reject-shape", {
      shape:  "bare-host",
      reason: "claimedName not FQDN (no '.'); RFC 5321 §4.1.1.1 requires primary host name",
    });
  }
  if (labels.length === 1 && caps.refuseBareHost) {
    return _emit(auditImpl, "reject-shape", {
      shape:  "bare-host",
      reason: "bare host '" + claimed + "' refused; FQDN required",
    });
  }
  for (var i = 0; i < labels.length; i += 1) {
    var l = labels[i];
    if (l.length === 0) {
      return _emit(auditImpl, "reject-shape", {
        shape:  "invalid",
        reason: "empty label (consecutive dots)",
      });
    }
    if (!LDH_LABEL_RE.test(l)) {                                                                         // allow:regex-no-length-cap — claimed already capped at maxBytes; label length-bounded by LDH_LABEL_RE's repeat cap
      return _emit(auditImpl, "reject-shape", {
        shape:  "invalid",
        reason: "label '" + l + "' not LDH-shaped (RFC 5321 §2.3.5)",
      });
    }
  }

  // Shape OK — run FCrDNS if resolver provided and profile requires.
  var ipKind = ipUtils.expandIpv6Hex(ctx.ip) ? "v6" : "v4";
  var needFcrdns = ctx.resolver && fcrdnsRequiredFor.indexOf(ipKind) !== -1;
  if (!needFcrdns) {
    var generic = _checkGenericRdns(opts.genericRdnsPatterns, [claimed]);
    var rv = {
      action:      "accept",
      shape:       "domain",
      fcrdns:      null,
      genericRdns: generic,
      reason:      "shape passed; FCrDNS skipped (no resolver or " + ipKind + " not in fcrdnsRequiredFor)",
    };
    _emitAudit(auditImpl, "mail.helo.accept", rv);
    return rv;
  }

  var fcrdnsResult = await _runFcrdns(ctx.ip, ctx.resolver);
  var rv2 = {
    action:      fcrdnsResult.passed ? "accept" : "soft-fail-fcrdns",
    shape:       "domain",
    fcrdns:      fcrdnsResult,
    genericRdns: _checkGenericRdns(opts.genericRdnsPatterns, fcrdnsResult.rdnsNames.concat([claimed])),
    reason:      fcrdnsResult.passed
      ? "FCrDNS verified (rDNS → forward → match connection IP)"
      : "FCrDNS failed (rDNS resolved but forward did not match connection IP)",
  };
  _emitAudit(auditImpl, fcrdnsResult.passed ? "mail.helo.accept" : "mail.helo.fcrdns_failed", rv2);
  return rv2;
}

async function _runFcrdns(ip, resolver) {
  var result = {
    checked:    true,
    passed:     false,
    rdnsNames:  [],
    forwardIps: [],
    matchedIp:  null,
  };
  var rev = _reverseName(ip);
  if (!rev) {
    return result;                                                                                      // unparseable IP — caller already rejected
  }
  try {
    var ptr = await resolver.queryPtr(rev);
    if (ptr && ptr.rrs) {
      result.rdnsNames = ptr.rrs.map(function (r) { return r.decoded; }).filter(Boolean);
    }
  } catch (_e) { /* NXDOMAIN or upstream — leave empty so passed stays false */ }

  for (var i = 0; i < result.rdnsNames.length; i += 1) {
    var name = result.rdnsNames[i];
    try {
      var isV6 = ipUtils.expandIpv6Hex(ip) !== null;
      var fwd = isV6 ? await resolver.queryAaaa(name) : await resolver.queryA(name);
      if (fwd && fwd.rrs) {
        for (var j = 0; j < fwd.rrs.length; j += 1) {
          var fip = fwd.rrs[j].decoded;
          if (fip) {
            result.forwardIps.push(fip);
            if (_ipEqual(fip, ip)) {
              result.passed   = true;
              result.matchedIp = fip;
            }
          }
        }
      }
    } catch (_e) { /* per-name fwd failure is non-fatal; check the next */ }
  }
  return result;
}

function _reverseName(ip) {
  if (typeof ip !== "string") return null;
  // Reuse the RFC 5782 reverse-name construction on mail-rbl —
  // appended to in-addr.arpa or ip6.arpa for the PTR query name.
  if (ipUtils.isIPv4Shape(ip)) {
    return ip.split(".").reverse().join(".") + ".in-addr.arpa";
  }
  var hex = ipUtils.expandIpv6Hex(ip);
  if (!hex) return null;
  var rev = "";
  for (var i = hex.length - 1; i >= 0; i -= 1) {
    rev += hex[i];
    if (i > 0) rev += ".";
  }
  return rev + ".ip6.arpa";
}

function _ipEqual(a, b) {
  if (a === b) return true;
  var ha = ipUtils.expandIpv6Hex(a);
  var hb = ipUtils.expandIpv6Hex(b);
  if (ha && hb) return ha === hb;
  return false;
}

function _checkGenericRdns(extraPatterns, names) {
  var patterns = GENERIC_RDNS_PATTERNS.slice();
  if (Array.isArray(extraPatterns)) {
    for (var p = 0; p < extraPatterns.length; p += 1) {
      if (extraPatterns[p] instanceof RegExp) patterns.push(extraPatterns[p]);
    }
  }
  for (var n = 0; n < names.length; n += 1) {
    if (typeof names[n] !== "string") continue;
    for (var q = 0; q < patterns.length; q += 1) {
      if (patterns[q].test(names[n])) return true;
    }
  }
  return false;
}

function _emit(auditImpl, action, partial) {
  var rv = Object.assign({
    action:      action,
    fcrdns:      null,
    genericRdns: false,
  }, partial);
  _emitAudit(auditImpl, "mail.helo." + action, rv);
  return rv;
}

function _emitAudit(auditImpl, action, metadata) {
  try {
    if (auditImpl && typeof auditImpl.safeEmit === "function") {
      auditImpl.safeEmit({
        action:   action,
        outcome:  "success",
        metadata: metadata,
      });
    }
  } catch (_e) { /* drop-silent — audit emit failure must not block MX accept loop */ }
}

/**
 * @primitive b.mail.helo.compliancePosture
 * @signature b.mail.helo.compliancePosture(posture)
 * @since     0.9.35
 * @status    stable
 *
 * Return the effective profile name for a compliance posture, or
 * `null` for unknown posture names.
 *
 * @example
 *   b.mail.helo.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

module.exports = {
  evaluate:                evaluate,
  compliancePosture:       compliancePosture,
  PROFILES:                PROFILES,
  COMPLIANCE_POSTURES:     COMPLIANCE_POSTURES,
  GENERIC_RDNS_PATTERNS:   GENERIC_RDNS_PATTERNS,
  MailHeloError:           MailHeloError,
  _reverseName:            _reverseName,
};
