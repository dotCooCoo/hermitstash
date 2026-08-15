/**
 * HermitStash-aware client-IP extraction.
 *
 * b.requestHelpers.trustedClientIp resolves the real client IP behind a
 * reverse proxy with a peer-gated, right-to-left walk: X-Forwarded-For is
 * honored only for the hops whose address falls in the trusted-proxy CIDR
 * set, stopping at the first hop that isn't — so a direct caller can't forge
 * an upstream address to walk the blocklist or evade a rate-limit key.
 *
 * The trusted set is the loopback proxies (127.0.0.1 / ::1, covering the
 * Docker / nginx-front-end deployments) plus any CIDRs the operator adds via
 * the TRUST_PROXY config (a bare IP is treated as a /32 or /128). Single
 * helper so the trust policy lives in one place; callers go through getIp().
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

// What counts as a well-formed operator CIDR. Named explicitly rather than taken
// from a profile, because the defaults are built for outbound-request filtering
// and refuse the private ranges that are the entire point of both callers here —
// a trusted proxy sits on the LAN, and an admin fence names the internal network.
//
//   reservedRanges     allow — 10/8, 192.168/16 and loopback are the normal answer
//   networkAlignment   allow — 10.0.0.1/8 is a common way of writing 10.0.0.0/8,
//                              and both consumers mask the host bits identically,
//                              so it already behaves as the operator intends;
//                              refusing it would break a working deployment
//   requireMask        allow — a bare IP is normalised to /32 or /128 above
//
// The codepoint policies stay at reject: a direction-changing or zero-width
// character in a config value is not a CIDR anyone meant to write.
var CIDR_OPTS = {
  reservedRangesPolicy: "allow", networkAlignmentPolicy: "allow", requireMaskPolicy: "allow",
  bidiPolicy: "reject", controlPolicy: "reject", nullBytePolicy: "reject", zeroWidthPolicy: "reject",
};

/**
 * Parse a comma-separated operator CIDR list into the entries that are usable
 * and the ones that are not, without throwing.
 *
 * Both callers previously took an entry's word for it. The trust list handed the
 * whole thing to trustedClientIp, which throws on the first bad entry — so ONE
 * typo discarded every other entry and dropped the deployment to loopback-only.
 * The admin fence probed each entry with ssrfGuard.cidrContains inside a
 * try/catch, but that helper answers false on garbage rather than throwing, so
 * the check never rejected anything and a malformed entry simply never matched.
 *
 * Returns { valid: [cidr], invalid: [{ entry, reason }] }.
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


// Cache the resolver on the RAW TRUST_PROXY value, so a hot-reloaded setting
// rebuilds it and an unchanged one costs nothing. getIp runs on essentially
// every request — through authentication, rate limiting and the audit trail —
// so both halves of the work below have to stay out of that path: validating
// each entry is real work to repeat per request, and the rejection notice
// would otherwise be written once per call rather than once per change.
//
// Keying on the raw value rather than the parsed result also keeps an edit
// visible when it only changes WHICH entry is malformed, which leaves the
// surviving list identical.
var _cachedKey = null;
var _cachedResolver = null;
function _resolver() {
  var cfg = configLazy();
  var raw = (cfg && cfg.trustProxy) ? String(cfg.trustProxy) : "";
  if (raw !== _cachedKey) {
    var parsed = parseCidrList(raw);
    // A bad entry is dropped on its own and the rest are kept. Discarding the
    // whole list instead is what made this worth changing: behind a reverse
    // proxy with no trusted-proxy entry surviving, every client resolves to the
    // proxy's own address — per-IP rate limits and IP blocks all collapse onto
    // one bucket, and the admin network fence, which reads the same resolved
    // address, admits any caller the moment the operator's allowlist covers the
    // proxy's network.
    //
    // Loud rather than silent, and never thrown: a bad value pushed to a running
    // server must not stop it serving.
    parsed.invalid.forEach(function (bad) {
      // allow:console-direct — load-cycle-sensitive module (config is lazy-required
      // to avoid config → vault → audit → client-ip); no logger available here.
      console.error("[client-ip] TRUST_PROXY entry ignored: " + JSON.stringify(bad.entry) + " — " + bad.reason);
    });
    var list = DEFAULT_TRUSTED_CIDRS.concat(parsed.valid);
    try {
      _cachedResolver = b.requestHelpers.trustedClientIp({ trustedProxies: list });
    } catch (_e) {
      // Every entry in `list` was validated above, so this should be
      // unreachable; keep the loopback-only fallback so an unforeseen
      // disagreement between the two still leaves a resolver to serve with.
      _cachedResolver = b.requestHelpers.trustedClientIp({ trustedProxies: DEFAULT_TRUSTED_CIDRS });
    }
    _cachedKey = raw;
  }
  return _cachedResolver;
}

// Canonicalize an address to a single representation so the blocklist, the
// rate-limit key, and the audit log all key off the same string.
// b.ssrfGuard.canonicalizeHost produces a byte-canonical (RFC 5952) IPv6 form,
// folds an IPv4-mapped IPv6 (::ffff:1.2.3.4 → 1.2.3.4) and strips brackets. The
// previous lowercase+regex left a ::-compressed address and its fully-expanded
// form as DISTINCT strings, so a block / rate-limit key on one didn't match the
// other (blocklist evasion + rate-limit key collision). A non-IP audit value
// passes through unchanged.
function canonicalize(ip) {
  if (typeof ip !== "string" || !ip) return ip;
  return b.ssrfGuard.canonicalizeHost(ip);
}

function getIp(req) {
  if (!req) return null;
  return canonicalize(_resolver().resolve(req));
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
};
