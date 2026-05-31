"use strict";
/**
 * @module     b.mail.rbl
 * @nav        Mail
 * @title      Mail RBL
 * @order      540
 *
 * @intro
 *   RFC 5782 DNS-based blocklist (DNSBL) + allowlist (DNSWL) query
 *   primitive. Composes `b.network.dns.resolver` for the underlying
 *   DNS queries and surfaces a structured `{ listed, allowed,
 *   neutral, errors }` shape for the MX listener (v0.9.34) and
 *   submission listener (v0.9.35) to consume per-connection.
 *
 *   ## Query construction
 *
 *   - **IPv4** — octets reversed, blocklist domain suffixed. RFC 5782
 *     §2.1: address `192.0.2.99` against `bl.spamcop.net` becomes the
 *     query name `99.2.0.192.bl.spamcop.net`.
 *   - **IPv6** — nibble-reversed across all 128 bits (32 hex nibbles),
 *     blocklist domain suffixed. RFC 5782 §2.4: address
 *     `2001:db8::1` against `ugly.example.com` becomes
 *     `1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ugly.example.com`.
 *   - **Domain blocklists** (Spamhaus DBL / SURBL — RFC 5782 §3) —
 *     query the domain directly against the list zone, no reverse.
 *
 *   ## A-record semantics (RFC 5782 §2.1)
 *
 *   The A-record return is a SEMANTIC code, not a routable address.
 *   Convention is `127.0.0.x`:
 *     - `127.0.0.2` — listed (generic).
 *     - `127.0.0.4+` — operator-specific sub-list (Spamhaus uses
 *       `127.0.0.4` SBL, `127.0.0.5` XBL, etc.).
 *     - `127.255.255.252+` — RFC 5782 §5 test addresses.
 *   The primitive exposes the raw bytes so operator's MX policy can
 *   inspect the sub-list code.
 *
 *   ## TXT-record reason (RFC 5782 §2.2)
 *
 *   Many DNSBLs publish a TXT record alongside the A — short prose
 *   describing why the IP is listed (often with a URL for delisting).
 *   The primitive fetches it lazily — operator opts in via
 *   `{ withReason: true }` per-query when they want to render the
 *   reason back to the peer via SMTP 550 message.
 *
 *   ## DNSWL allowlists
 *
 *   `b.mail.rbl.create({ ..., allowlists: [...] })` — operator wires
 *   any list as DNSBL (refuse on listed) OR DNSWL (allow on listed).
 *   Same query shape; the verdict semantics differ. RFC 5782 §3.2
 *   notes TXT records on DNSWLs are operationally less useful since
 *   SMTP can't advise the peer WHY they were accepted, but the field
 *   is surfaced for audit visibility regardless.
 *
 *   ## CVE / threat model
 *
 *   - **Blocklist-cache amplification** — each list query goes through
 *     `b.network.dns.resolver` so cache + TTL + serve-stale already
 *     defend against amplification + flood from a single hostile peer.
 *   - **DoS-by-query** — operator-configurable per-connection
 *     concurrent-query cap (default 8) and per-IP query timeout
 *     (default 5s); a slow / unresponsive list can't stall the MX
 *     listener.
 *   - **DNS-poisoning** — every response parses through `b.safeDns`
 *     (bounded RR counts, bounded TXT length) via the resolver, so
 *     a poisoned upstream response can't smuggle oversized rdata.
 *
 *   ## Why it exists
 *
 *   The MX listener (v0.9.34) needs RBL queries on every accepted
 *   connection for SPF / IP-reputation evaluation; the submission
 *   listener checks operator's own submission-rate / spam-source
 *   lists. Without this primitive each consumer rolls its own
 *   reverse-IP construction + A-record sub-code interpretation, and
 *   the per-list query timeout / cap is operator-specific instead of
 *   framework-shared.
 *
 * @card
 *   RFC 5782 DNSBL + DNSWL query primitive. Composes b.network.dns.resolver;
 *   reverses IPv4 octets + IPv6 nibbles; surfaces A-record return code
 *   and optional TXT reason. Operator-configurable list set + concurrent-
 *   query cap + per-list timeout.
 */

var C                  = require("./constants");
var { defineClass }    = require("./framework-error");
var lazyRequire        = require("./lazy-require");
var ipUtils            = require("./ip-utils");

var audit              = lazyRequire(function () { return require("./audit"); });

var MailRblError = defineClass("MailRblError", { alwaysPermanent: true });

var IPV4_RE       = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;  // allow:regex-no-length-cap — anchored + per-octet repeat-cap
var IPV6_HEX_RE   = /^[0-9a-fA-F:]+$/;                                                                    // allow:regex-no-length-cap — checked by length cap below
var IPV6_MAX_LEN  = 39;                                                                                   // max IPv6 textual length (8 groups × 4 hex + 7 colons)

var DEFAULT_TIMEOUT_MS    = C.TIME.seconds(5);
var DEFAULT_CONCURRENCY   = 8;                                                                           // concurrent-query cap, not bytes
var DEFAULT_PROFILE       = "strict";

var PROFILES = Object.freeze({
  strict:     { maxConcurrent: 8, perListTimeoutMs: C.TIME.seconds(5), maxListsPerQuery: 16 },           // list-count cap
  balanced:   { maxConcurrent: 16, perListTimeoutMs: C.TIME.seconds(10), maxListsPerQuery: 32 },         // list-count cap
  permissive: { maxConcurrent: 32, perListTimeoutMs: C.TIME.seconds(20), maxListsPerQuery: 64 },         // list-count cap
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

/**
 * @primitive b.mail.rbl.create
 * @signature b.mail.rbl.create(opts)
 * @since     0.9.33
 * @status    stable
 * @related   b.network.dns.resolver.create, b.safeDns.parseResponse
 *
 * Build an RBL query instance. Returns an object with
 * `.query(ip, opts) → Promise<verdict>` and
 * `.queryDomain(domain, opts) → Promise<verdict>` methods.
 *
 * @opts
 *   resolver:    b.network.dns.resolver.create() instance, required
 *   blocklists:  Array<string> — DNS zones (e.g. "bl.spamcop.net")
 *   allowlists:  Array<string> — DNSWL zones (e.g. "list.dnswl.org")
 *   profile:     "strict" | "balanced" | "permissive"
 *   posture:     "hipaa" | "pci-dss" | "gdpr" | "soc2"
 *   withReason:  boolean — default false; fetch TXT record per A hit
 *   audit:       b.audit namespace
 *
 * @example
 *   var rbl = b.mail.rbl.create({
 *     resolver:   b.network.dns.resolver.create(),
 *     blocklists: ["zen.spamhaus.org", "bl.spamcop.net"],
 *   });
 *   var verdict = await rbl.query("192.0.2.99", { withReason: true });
 *   if (verdict.listed.length) refuseConnection(verdict.listed[0].reason);
 */
function create(opts) {
  opts = opts || {};
  if (!opts.resolver || typeof opts.resolver.query !== "function") {
    throw new MailRblError("mail-rbl/bad-resolver",
      "create: opts.resolver must be a b.network.dns.resolver.create() instance");
  }
  var profile = opts.profile || (opts.posture && COMPLIANCE_POSTURES[opts.posture]) || DEFAULT_PROFILE;
  if (!PROFILES[profile]) {
    throw new MailRblError("mail-rbl/bad-profile",
      "create: unknown profile '" + profile + "'");
  }
  var caps = PROFILES[profile];
  var blocklists = Array.isArray(opts.blocklists) ? opts.blocklists.slice() : [];
  var allowlists = Array.isArray(opts.allowlists) ? opts.allowlists.slice() : [];
  var withReason = opts.withReason === true;
  var auditImpl  = opts.audit || audit();
  if (blocklists.length + allowlists.length === 0) {
    throw new MailRblError("mail-rbl/no-lists",
      "create: must configure at least one blocklist or allowlist");
  }
  if (blocklists.length + allowlists.length > caps.maxListsPerQuery) {
    throw new MailRblError("mail-rbl/too-many-lists",
      "create: " + (blocklists.length + allowlists.length) +
      " lists configured; profile cap is " + caps.maxListsPerQuery);
  }
  _validateZoneNames(blocklists.concat(allowlists));

  async function query(ip, qopts) {
    qopts = qopts || {};
    if (typeof ip !== "string" || ip.length === 0) {
      throw new MailRblError("mail-rbl/bad-input",
        "query: ip must be a non-empty string");
    }
    var reverse = reverseIp(ip);
    return _walkLists(reverse, qopts);
  }

  async function queryDomain(domain, qopts) {
    qopts = qopts || {};
    if (typeof domain !== "string" || domain.length === 0) {
      throw new MailRblError("mail-rbl/bad-input",
        "queryDomain: domain must be a non-empty string");
    }
    if (domain.indexOf(".") === -1) {
      throw new MailRblError("mail-rbl/bad-input",
        "queryDomain: domain must contain at least one label separator");
    }
    return _walkLists(domain, qopts);
  }

  async function _walkLists(prefix, qopts) {
    var perQueryReason = qopts.withReason !== undefined ? qopts.withReason === true : withReason;
    var allLists = blocklists.map(function (z) { return { zone: z, kind: "block" }; })
      .concat(allowlists.map(function (z) { return { zone: z, kind: "allow" }; }));

    var verdict = { listed: [], allowed: [], neutral: [], errors: [] };
    var inFlight = 0;
    var idx = 0;

    return new Promise(function (resolve) {
      function _emit() {
        // Schedule up to maxConcurrent at any time.
        while (inFlight < caps.maxConcurrent && idx < allLists.length) {
          var entry = allLists[idx];
          idx += 1;
          inFlight += 1;
          _checkList(prefix, entry, perQueryReason, caps).then(function (rv) {
            inFlight -= 1;
            if (rv.error) {
              verdict.errors.push({ list: rv.list, message: rv.error });
            } else if (rv.listed) {
              if (rv.kind === "allow") verdict.allowed.push(rv);
              else                      verdict.listed.push(rv);
            } else {
              verdict.neutral.push({ list: rv.list });
            }
            if (idx >= allLists.length && inFlight === 0) resolve(verdict);
            else _emit();
          });
        }
        if (idx >= allLists.length && inFlight === 0) resolve(verdict);
      }
      _emit();
    });
  }

  return {
    query:                 query,
    queryDomain:           queryDomain,
    blocklists:            blocklists,
    allowlists:            allowlists,
    profile:               profile,
    MailRblError:          MailRblError,
  };

  async function _checkList(prefix, entry, perQueryReason, capsArg) {
    var name = prefix + "." + entry.zone;
    var rv = { list: entry.zone, kind: entry.kind, listed: false };
    try {
      var aResp = await _withTimeout(opts.resolver.queryA(name), capsArg.perListTimeoutMs);
      if (aResp && aResp.rrs && aResp.rrs.length > 0) {
        rv.listed     = true;
        rv.returnCode = aResp.rrs[0].decoded;
        if (perQueryReason) {
          try {
            var txtResp = await _withTimeout(opts.resolver.queryTxt(name), capsArg.perListTimeoutMs);
            if (txtResp && txtResp.rrs && txtResp.rrs.length > 0) {
              rv.reason = (txtResp.rrs[0].decoded || []).join("");
            }
          } catch (_e) { /* TXT failure is non-fatal; A bit already set the verdict */ }
        }
        _emitAudit(auditImpl, "mail.rbl." + entry.kind + "_listed", {
          list: entry.zone, returnCode: rv.returnCode,
        });
      }
    } catch (e) {
      // NXDOMAIN is the expected "not listed" response, not an error
      // condition. RFC 5782 §2.1.1 — absence of any A record means
      // "not in list". Resolver surfaces this as resolver/nxdomain-or-
      // error which we treat as the neutral verdict.
      if (e && e.code === "resolver/nxdomain-or-error") {
        // Neutral — not listed; not an error.
        return rv;
      }
      rv.error = (e && e.message) || String(e);
    }
    return rv;
  }
}

/**
 * @primitive b.mail.rbl.reverseIp
 * @signature b.mail.rbl.reverseIp(ip)
 * @since     0.9.33
 * @status    stable
 *
 * Build the reverse-DNS query name for an IPv4 or IPv6 address per
 * RFC 5782 §2.1 / §2.4. Pure-functional helper exposed for operator
 * tests and the `b.mail.dnsbl` extension primitive.
 *
 * @example
 *   b.mail.rbl.reverseIp("192.0.2.99");   // → "99.2.0.192"
 *   b.mail.rbl.reverseIp("2001:db8::1");  // → "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
 */
function reverseIp(ip) {
  if (typeof ip !== "string" || ip.length === 0) {
    throw new MailRblError("mail-rbl/bad-input",
      "reverseIp: ip must be a non-empty string");
  }
  // IPv4 first.
  if (IPV4_RE.test(ip)) {
    return ip.split(".").reverse().join(".");
  }
  // IPv6 — accept canonical / compressed forms. Expand and nibble-reverse.
  if (ip.length > IPV6_MAX_LEN || !IPV6_HEX_RE.test(ip)) {
    throw new MailRblError("mail-rbl/bad-input",
      "reverseIp: '" + ip + "' is not a valid IPv4 or IPv6 address");
  }
  var expanded = ipUtils.expandIpv6Hex(ip);
  if (!expanded) {
    throw new MailRblError("mail-rbl/bad-input",
      "reverseIp: '" + ip + "' is not a parseable IPv6 address");
  }
  // expanded is 32 hex chars (128 bits / 4 = 32 nibbles); reverse + dot-join.
  var rev = [];
  for (var i = expanded.length - 1; i >= 0; i -= 1) rev.push(expanded[i]);
  return rev.join(".");
}

/**
 * @primitive b.mail.rbl.compliancePosture
 * @signature b.mail.rbl.compliancePosture(posture)
 * @since     0.9.33
 * @status    stable
 *
 * Return the effective profile name for a compliance posture, or
 * `null` for unknown posture names.
 *
 * @example
 *   b.mail.rbl.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _validateZoneNames(zones) {
  for (var i = 0; i < zones.length; i += 1) {
    var z = zones[i];
    if (typeof z !== "string" || z.length === 0 || z.length > 253) {                                     // RFC 1035 §2.3.4 total name cap
      throw new MailRblError("mail-rbl/bad-zone",
        "list zone '" + z + "' must be a non-empty string under 253 bytes");
    }
    if (z.indexOf("..") !== -1 || z.charAt(0) === "." || z.charAt(z.length - 1) === ".") {
      throw new MailRblError("mail-rbl/bad-zone",
        "list zone '" + z + "' has malformed dots");
    }
    // ASCII label-shape — DNSBL zones are always ASCII (IDN punycode
    // if non-ASCII upstream).
    for (var c = 0; c < z.length; c += 1) {
      var cc = z.charCodeAt(c);
      if (cc < 0x20 || cc === 0x7f || cc > 0x7e) {                                                       // RFC 1035 ASCII zone-name shape
        throw new MailRblError("mail-rbl/bad-zone",
          "list zone '" + z + "' contains non-ASCII or control chars");
      }
    }
  }
}

function _withTimeout(promise, timeoutMs) {
  return new Promise(function (resolve, reject) {
    var done = false;
    var t = setTimeout(function () {
      if (done) return;
      done = true;
      reject(new MailRblError("mail-rbl/timeout",
        "list query exceeded " + timeoutMs + "ms"));
    }, timeoutMs);
    promise.then(function (v) {
      if (done) return;
      done = true;
      clearTimeout(t);
      resolve(v);
    }, function (e) {
      if (done) return;
      done = true;
      clearTimeout(t);
      reject(e);
    });
  });
}

function _emitAudit(auditImpl, action, metadata) {
  try {
    if (auditImpl && typeof auditImpl.safeEmit === "function") {
      auditImpl.safeEmit({ action: action, outcome: "success", metadata: metadata });
    }
  } catch (_e) { /* drop-silent — audit failures don't break query path */ }
}

void DEFAULT_TIMEOUT_MS;                                                                                  // referenced indirectly via PROFILES.strict.perListTimeoutMs
void DEFAULT_CONCURRENCY;                                                                                 // referenced indirectly via PROFILES.strict.maxConcurrent

module.exports = {
  create:                  create,
  reverseIp:               reverseIp,
  compliancePosture:       compliancePosture,
  PROFILES:                PROFILES,
  COMPLIANCE_POSTURES:     COMPLIANCE_POSTURES,
  MailRblError:            MailRblError,
};
