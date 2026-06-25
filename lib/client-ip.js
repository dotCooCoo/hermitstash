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

function _trustedProxies() {
  var cfg = configLazy();
  var extra = (cfg && cfg.trustProxy)
    ? String(cfg.trustProxy).split(",").map(function (s) { return s.trim(); }).filter(Boolean).map(_toCidr)
    : [];
  return DEFAULT_TRUSTED_CIDRS.concat(extra);
}

// Cache the resolver keyed on the trusted-proxy set so a hot-reloaded
// TRUST_PROXY rebuilds it without re-validating CIDRs on every request. A
// malformed operator CIDR falls back to loopback-only — fail-safe: never throw
// per request, never silently widen trust.
var _cachedKey = null;
var _cachedResolver = null;
function _resolver() {
  var list = _trustedProxies();
  var key = list.join(",");
  if (key !== _cachedKey) {
    try {
      _cachedResolver = b.requestHelpers.trustedClientIp({ trustedProxies: list });
    } catch (_e) {
      _cachedResolver = b.requestHelpers.trustedClientIp({ trustedProxies: DEFAULT_TRUSTED_CIDRS });
    }
    _cachedKey = key;
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

module.exports = { getIp: getIp, canonicalize: canonicalize };
