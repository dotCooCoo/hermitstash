/**
 * Tailscale integration glue.
 *
 * HermitStash-specific layer over two general blamejs primitives:
 *   - b.requestHelpers.trustedIdentityHeaders — peer-gated identity family
 *   - b.localHttp                             — SSRF-safe LocalAPI client
 *
 * Sign-in-with-Tailscale identity arrives as the `tailscale serve` header family
 * (Tailscale-User-Login / -Name / -Profile-Pic / App-Capabilities). Serve injects
 * these and strips any client-supplied copies; we ALSO peer-gate the family to the
 * loopback serve proxy and strip forged copies from every other peer, so a client
 * that reaches the port directly can never impersonate a tailnet user. This is why
 * the app MUST bind loopback-only when Tailscale is enabled — the serve proxy is
 * then the only peer that can deliver the family.
 * Ref: https://tailscale.com/docs/features/tailscale-serve
 *
 * Identity is only read when tailscale.enabled AND tailscale.ssoEnabled. Under
 * Funnel a public visitor carries NO identity header, so "no header" always means
 * unauthenticated (never "internal/trusted") — the caller falls back to the other
 * HermitStash sign-in methods.
 */
var b = require("./vendor/blamejs");
var C = require("./constants");
var config = require("./config");

var _log = b.lazyRequire(function () { return require("../app/shared/logger"); });

// The `tailscale serve` identity header family. Field name → header name.
var SERVE_HEADERS = {
  login:      "Tailscale-User-Login",
  name:       "Tailscale-User-Name",
  profilePic: "Tailscale-User-Profile-Pic",
  caps:       "Tailscale-App-Capabilities",
};
var _FAMILY_LOWER = Object.keys(SERVE_HEADERS).map(function (k) { return SERVE_HEADERS[k].toLowerCase(); });

// LOOPBACK ONLY. Serve proxies from the loopback interface; with the mandatory
// loopback bind this peer-gate means only the in-host serve proxy can deliver the
// family — a LAN or tailnet peer reaching the port directly is never trusted.
var LOOPBACK_CIDRS = ["127.0.0.0/8", "::1/128"];

var DISPLAY_NAME_MAX = 200;

// ---- peer-gated identity extractor (built once, reset on config reload) ----
var _identityGate = null;
function identityGate() {
  if (!_identityGate) {
    _identityGate = b.requestHelpers.trustedIdentityHeaders({
      trustedProxies: LOOPBACK_CIDRS,
      headers: SERVE_HEADERS,
      as: "tailscaleIdentity",
    });
  }
  return _identityGate;
}

function _stripFamily(req) {
  if (req && req.headers) {
    for (var i = 0; i < _FAMILY_LOWER.length; i++) delete req.headers[_FAMILY_LOWER[i]];
  }
}

/**
 * Connect middleware — register globally BEFORE the route chain so
 * req.tailscaleIdentity is the trusted raw family (or null) and any forged copy
 * is stripped before any handler reads it. 3-arg middleware signature.
 */
function middleware(req, res, next) {
  if (!config.tailscale.enabled) {
    // Defense in depth: with the feature off, never let a client-supplied
    // Tailscale-* header survive to be read as identity by anything downstream.
    _stripFamily(req);
    req.tailscaleIdentity = null;
    return next();
  }
  return identityGate().middleware(req, res, next);
}

// ---- identity normalization ----

// Strip control chars and cap length. The display name is cosmetic (the login is
// the authenticating identity); Tailscale sends it UTF-8, so a best-effort clean
// is sufficient. Values arrive raw per the primitive's contract.
function _cleanText(v) {
  if (typeof v !== "string") return "";
  var s = v.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  return s.length > DISPLAY_NAME_MAX ? s.slice(0, DISPLAY_NAME_MAX) : s;
}

// The App-Capabilities header is documented JSON: an object mapping capability
// name (URL-style, e.g. "example.com/cap/hermitstash") → array of rule objects.
// The grant gate only needs the set of capability KEYS the user holds. Anything
// that isn't the documented object shape yields no capabilities (fail-closed).
function parseCaps(v) {
  if (!v || typeof v !== "string") return [];
  var obj = b.safeJson.parseOrDefault(v, null);
  if (obj && typeof obj === "object" && !Array.isArray(obj)) return Object.keys(obj);
  return [];
}

/**
 * Resolve the tailnet identity from a request, or null when there is none
 * (Funnel/public, feature off, or SSO off). null ALWAYS means "not a tailnet
 * user" — never "trusted internal".
 *
 * Resolves the peer-gated family DIRECTLY via the gate (which performs the
 * loopback peer check itself), so the auth decision is authoritative on its own
 * and does not depend on `middleware` having run first for this request. When the
 * middleware did run on a non-loopback peer it already stripped the forged family,
 * so this re-resolves to null identically — the two agree by construction.
 */
function identityFrom(req) {
  if (!config.tailscale.enabled || !config.tailscale.ssoEnabled) return null;
  var r = identityGate().resolve(req);
  if (!r || !r.trusted) return null;
  var raw = r.identity;
  if (!raw || typeof raw !== "object") return null;
  var login = String(raw.login || "").trim().toLowerCase();
  if (!login) return null;
  return {
    login: login,
    displayName: _cleanText(raw.name) || login,
    // Remote, attacker-influenced URL — surfaced for client-side rendering only,
    // never server-fetched (that would be an SSRF vector).
    profilePicUrl: _cleanText(raw.profilePic),
    caps: parseCaps(raw.caps),
  };
}

/**
 * Stable, namespaced identity used as the sealed users.tailscaleId (and its blind
 * index). The tailnet login is already IdP-scoped (alice@example.com, alice@github)
 * and lives in its own column/namespace, so it never collides with an email row.
 */
function tailscaleId(login) { return String(login || "").trim().toLowerCase(); }

/**
 * Admin-gated auto-provisioning decision for a tailnet identity with no existing
 * account. A user is provisionable ONLY when they carry the required capability
 * grant OR their login is on the allowlist. With BOTH unset, no tailnet user is
 * auto-provisioned (SSO signs in existing accounts only).
 * Returns { allowed, via }.
 */
function provisioningDecision(identity) {
  var grant = String(config.tailscale.ssoRequiredGrant || "").trim();
  var allow = config.tailscale.ssoAllowlist || [];
  if (grant && identity && Array.isArray(identity.caps) && identity.caps.indexOf(grant) !== -1) {
    return { allowed: true, via: "grant" };
  }
  if (allow.length && identity && allow.indexOf(identity.login) !== -1) {
    return { allowed: true, via: "allowlist" };
  }
  return { allowed: false, via: null };
}

// ---- LocalAPI (b.localHttp over the tailscaled unix socket / named pipe) ----
// Used for node status → MagicDNS hostname auto-config, and WhoIs in the
// direct-bind topology (HS bound on the tailnet IP rather than behind serve).
var _client = null;
var _clientSock = null;
function localApi() {
  var sp = config.tailscale.socketPath;
  if (_client && _clientSock === sp) return _client;
  _client = b.localHttp.create({
    socketPath: sp,
    hostHeader: "local-tailscaled.sock",
    timeoutMs: C.TIME.seconds(3),
    maxResponseBytes: C.BYTES.mib(1),
  });
  _clientSock = sp;
  return _client;
}

async function status() {
  var r = await localApi().get("/localapi/v0/status");
  if (r.statusCode !== 200) throw new Error("tailscale LocalAPI status: HTTP " + r.statusCode);
  return r.json();
}

/**
 * This node's MagicDNS name (trailing dot stripped), or null when unavailable.
 * e.g. "hs.tailnet-name.ts.net".
 */
async function magicDnsName() {
  var st = await status();
  var self = st && st.Self;
  var dns = self && self.DNSName;
  if (!dns || typeof dns !== "string") return null;
  return dns.replace(/\.$/, "").toLowerCase() || null;
}

/**
 * Spoof-proof identity of a tailnet peer by its "ip:port", for the direct-bind
 * topology (peer is the real tailnet IP). Under serve the peer is loopback and the
 * header family is the identity source instead. Returns a normalized identity or null.
 */
async function whois(remoteAddr) {
  if (!remoteAddr || typeof remoteAddr !== "string") return null;
  var r = await localApi().get("/localapi/v0/whois?addr=" + encodeURIComponent(remoteAddr));
  if (r.statusCode !== 200) return null;
  var data = r.json() || {};
  var up = data.UserProfile || {};
  var login = String(up.LoginName || "").trim().toLowerCase();
  if (!login) return null;
  var caps = data.CapMap && typeof data.CapMap === "object" ? Object.keys(data.CapMap) : [];
  return {
    login: login,
    displayName: _cleanText(up.DisplayName) || login,
    profilePicUrl: _cleanText(up.ProfilePicURL),
    caps: caps,
  };
}

/**
 * Best-effort tailnet hostname auto-config. When Tailscale is enabled, auto-config
 * is on, and the operator has NOT set an explicit origin, derive the WebAuthn RP
 * origin + rpId (and thus the share-URL base) from this node's MagicDNS name so a
 * fresh serve deployment works with zero origin configuration. NEVER overrides an
 * operator-set RP_ORIGIN. Mutates the live config object; logs + leaves defaults on
 * any failure (e.g. tailscaled not yet reachable). Returns the applied origin or null.
 */
async function applyHostnameAutoConfig() {
  if (!config.tailscale.enabled || !config.tailscale.hostnameAutoConfig) return null;
  // Respect any operator-set origin: an explicit env var, or any non-localhost
  // value already resolved from env/DB. Only fill in when it's still a localhost
  // default (so we key off "operator configured something" rather than a brittle
  // exact-default string compare).
  if (b.safeEnv.readVar("RP_ORIGIN")) return null;
  if (config.rpOrigin && !/^https?:\/\/localhost(:|\/|$)/i.test(config.rpOrigin)) return null;
  var name;
  try { name = await magicDnsName(); }
  catch (e) { _log().warn("[tailscale] hostname auto-config: LocalAPI status unavailable", { error: e && e.message }); return null; }
  if (!name) return null;
  var origin = "https://" + name;
  config.rpOrigin = origin;
  config.rpId = name;
  _log().info("[tailscale] hostname auto-config applied", { rpOrigin: origin, rpId: name });
  return origin;
}

// Rebuild cached client + gate on config hot-reload (socket path / enable change).
config.onReset(function () { _client = null; _clientSock = null; _identityGate = null; });

module.exports = {
  SERVE_HEADERS: SERVE_HEADERS,
  middleware: middleware,
  identityFrom: identityFrom,
  parseCaps: parseCaps,
  tailscaleId: tailscaleId,
  provisioningDecision: provisioningDecision,
  status: status,
  magicDnsName: magicDnsName,
  whois: whois,
  applyHostnameAutoConfig: applyHostnameAutoConfig,
};
