/**
 * Client-IP extraction, peer-gated.
 *
 * A forwarded address is honoured only for hops whose own address falls inside
 * the trusted-proxy set, walking right to left and stopping at the first that
 * does not — so a direct caller cannot forge an upstream address to slip a
 * blocklist or a rate-limit key.
 *
 * That set is loopback, which covers the ordinary container and reverse-proxy
 * deployments, plus whatever TRUST_PROXY names; a bare address there becomes a
 * /32 or /128. Every caller goes through getIp(), so the trust policy has one
 * home.
 */
"use strict";

var b = require("./vendor/blamejs");

// Loopback proxies trusted by default. An IPv4-mapped ::ffff:127.0.0.1 peer is
// matched by 127.0.0.1/32, so no separate mapped-loopback entry is needed.
// Operator CIDRs from TRUST_PROXY are appended to this set.
var DEFAULT_TRUSTED_CIDRS = ["127.0.0.1/32", "::1/128"];

// Lazy config require to avoid a load-cycle during startup (config → vault →
// log paths can pull client-ip via audit).
// allow:inline-require — require sits inside b.lazyRequire's loader; the outer
// is the framework primitive, the inner is the deferred load.
var configLazy = b.lazyRequire(function () {
  try { return require("./config"); } catch (_e) { return null; } // allow:inline-require — deferred load wrapped by b.lazyRequire; config-not-yet-loaded at boot falls back to loopback-only
});

// trustedClientIp requires CIDR form. A bare IP is a /32 (IPv4) or /128 (IPv6);
// a value already carrying a prefix is passed through unchanged.
function _toCidr(entry) {
  if (entry.indexOf("/") !== -1) return entry;
  return entry + (entry.indexOf(":") !== -1 ? "/128" : "/32");
}

// Spelled out rather than taken from a profile, because the shipped profiles
// are built for outbound filtering and refuse the private ranges that are the
// entire point here — a trusted proxy sits on the LAN, and an admin fence names
// the internal network. So reserved ranges are allowed, a bare address is
// allowed and normalised to a full mask, and a host-bit-bearing form like
// 10.0.0.1/8 is allowed because both consumers mask identically and refusing it
// would break a working deployment.
//
// The codepoint policies come from the framework's frozen floor rather than
// being re-spelled: a copy is how one drifts when the floor gains a class.
var CIDR_OPTS = Object.assign({}, b.gateContract.CHAR_THREATS_REJECT_ALL, {
  reservedRangesPolicy: "allow", networkAlignmentPolicy: "allow", requireMaskPolicy: "allow",
});

/**
 * Split an operator CIDR list into the entries that are usable and the ones
 * that are not, without throwing. Returns { valid, invalid }.
 *
 * Neither caller could do this itself. Handing the whole list to the resolver
 * throws on the first bad entry, so one typo discarded every other entry and
 * dropped the deployment to loopback. Probing each entry against the SSRF
 * guard answers false on garbage rather than throwing, so nothing was ever
 * rejected and a malformed entry simply never matched.
 */
function parseCidrList(value) {
  var out = { valid: [], invalid: [] };
  if (!value) return out;
  String(value).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (entry) {
    var cidr = _toCidr(entry);
    var verdict;
    try { verdict = b.guardCidr.validate(cidr, CIDR_OPTS); }
    catch (e) { out.invalid.push({ entry: entry, reason: e.message }); return; }
    if (verdict && verdict.ok) { out.valid.push(cidr); return; }
    var issues = (verdict && verdict.issues) || [];
    out.invalid.push({ entry: entry, reason: issues.length ? issues[0].snippet : "not a valid CIDR" });
  });
  return out;
}


// Keyed on the raw setting, so a hot reload rebuilds and an unchanged value
// costs nothing. getIp runs on essentially every request, so neither the
// per-entry validation nor the rejection notice belongs in that path — the
// notice would otherwise be written once per call rather than once per change.
// The raw value is also what keeps an edit visible when it changes only WHICH
// entry is malformed and leaves the surviving list identical.
var _cachedKey = null;
var _cachedResolver = null;
var _cachedProtocol = null;
function _resolver() {
  var cfg = configLazy();
  var raw = (cfg && cfg.trustProxy) ? String(cfg.trustProxy) : "";
  if (raw !== _cachedKey) {
    var parsed = parseCidrList(raw);
    // One bad entry is dropped and the rest kept. Discarding the whole list
    // leaves every client behind a proxy resolving to the proxy's own address:
    // per-IP limits and blocks collapse onto one bucket, and the admin fence,
    // reading the same address, admits anyone the moment the allowlist covers
    // the proxy's network. Loud, but never thrown — a bad value pushed to a
    // running server must not stop it serving.
    parsed.invalid.forEach(function (bad) {
      // allow:console-direct — load-cycle-sensitive module (config is lazy-required
      // to avoid config → vault → audit → client-ip); no logger available here.
      console.error("[client-ip] TRUST_PROXY entry ignored: " + JSON.stringify(bad.entry) + " — " + bad.reason);
    });
    var list = DEFAULT_TRUSTED_CIDRS.concat(parsed.valid);
    // Both resolvers are built from the SAME list. Who we believe about the
    // caller's address and who we believe about the caller's scheme is one
    // trust decision, and splitting it is how the two drift: a proxy trusted
    // for X-Forwarded-For but not X-Forwarded-Proto would put the real client
    // in the audit log while the Secure cookie flag read the wrong scheme.
    try {
      _cachedResolver = b.requestHelpers.trustedClientIp({ trustedProxies: list });
      _cachedProtocol = b.requestHelpers.trustedProtocol({ trustedProxies: list });
    } catch (_e) {
      // Every entry in `list` was validated above, so this should be
      // unreachable; keep the loopback-only fallback so an unforeseen
      // disagreement between the two still leaves a resolver to serve with.
      _cachedResolver = b.requestHelpers.trustedClientIp({ trustedProxies: DEFAULT_TRUSTED_CIDRS });
      _cachedProtocol = b.requestHelpers.trustedProtocol({ trustedProxies: DEFAULT_TRUSTED_CIDRS });
    }
    _cachedKey = raw;
  }
  return _cachedResolver;
}

// One representation, so the blocklist, the rate-limit key and the audit log
// all key off the same string: an RFC 5952 IPv6 form, with an IPv4-mapped
// address folded and brackets stripped. Lowercasing alone left a compressed
// address and its expanded form as distinct strings, which is both a blocklist
// evasion and a rate-limit collision. A non-IP value passes through unchanged.
function canonicalize(ip) {
  if (typeof ip !== "string" || !ip) return ip;
  return b.ssrfGuard.canonicalizeHost(ip);
}

function getIp(req) {
  if (!req) return null;
  return canonicalize(_resolver().resolve(req));
}

// Did this request arrive over TLS? Peer-gated through the same trusted-proxy
// list as getIp, so X-Forwarded-Proto counts only from a declared proxy and a
// direct caller cannot claim "https" by sending the header.
//
// This is the Secure-cookie decision. Deriving it from a configured origin
// instead reads the scheme the operator NAMED rather than the one the browser
// USED, which is wrong the moment the app answers on more than one — an HTTPS
// origin then marks the cookie Secure for a plain-HTTP visitor, whose browser
// discards it, and every following request arrives unauthenticated.
function isSecureRequest(req) {
  if (!req) return false;
  _resolver();                       // populate the cache pair
  return _cachedProtocol.resolve(req) === "https";
}

// Rate-limit / lockout bucket key for the trustProxy-gated client IP.
// b.requestHelpers.ipKey keeps IPv4 EXACT (per-host) but collapses IPv6 to its
// routing-significant /64 — an IPv6 end-site is allocated a whole /64 (RFC 6177
// / RFC 4291 §2.5.4) and freely rotates the low 64 bits, so keying on the full
// /128 would let one site mint an unlimited number of buckets and evade every
// per-IP throttle. Both the rate-limit keyFn AND every loginLimiter.reset()
// site derive their key through this ONE helper so they can never diverge (a
// reset on the full /128 would otherwise leave the /64's counter intact).
//
// ipKey returns "" for an unparseable input; we keep the historical
// `|| "unknown"` fallback so a degenerate request doesn't key every such client
// into the same "" bucket. The audit actor (clientIp.getIp) stays the FULL
// resolved IP — only this rate-limit/quota KEY is bucketed.
function rateKey(req) {
  var ip = getIp(req);
  return (ip && b.requestHelpers.ipKey(ip, { ipv6Bits: 64 })) || "unknown"; // allow:raw-byte-literal — IPv6 routing prefix length (RFC 4291 §2.5.4), not a byte size
}

module.exports = {
  getIp: getIp, canonicalize: canonicalize, rateKey: rateKey, parseCidrList: parseCidrList,
  isSecureRequest: isSecureRequest,
};
