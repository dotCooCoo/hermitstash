/**
 * Validation for the OpenID Connect settings. It depends on nothing but the
 * framework, so lib/config.js can call it when an admin saves settings and
 * app/bootstrap/startup-checks.js can call it at boot.
 */
var net = require("node:net");
var b = require("./vendor/blamejs");

var GROUPS_CLAIM_SEGMENT_RE = /^[A-Za-z0-9_:\-\/]+$/;
var MAX_GROUPS_CLAIM_LEN = 100;
var MAX_SCOPE_LEN = 200;
var SCOPE_TOKEN_RE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
var FORBIDDEN_PATH_SEGMENTS = Object.freeze({ "__proto__": true, "constructor": true, "prototype": true });

// Address blocks an OIDC_ALLOW_INTERNAL range must fall inside: private
// (RFC 1918, RFC 4193), shared address space (RFC 6598, used by Tailscale),
// loopback and link-local.
var INTERNAL_BLOCKS = Object.freeze([
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
  "127.0.0.0/8", "169.254.0.0/16",
  "fc00::/7", "fe80::/10", "::1/128",
]);
var _internalBlockList = null;

function _inInternalBlock(addr, prefix) {
  var family = net.isIP(addr) === 4 ? "ipv4" : "ipv6";
  if (!_internalBlockList) {
    _internalBlockList = INTERNAL_BLOCKS.map(function (cidr) {
      var slash = cidr.lastIndexOf("/");
      var base = cidr.slice(0, slash);
      var bits = parseInt(cidr.slice(slash + 1), 10);
      var fam = net.isIP(base) === 4 ? "ipv4" : "ipv6";
      var list = new net.BlockList();
      list.addSubnet(base, bits, fam);
      return { list: list, prefix: bits, family: fam };
    });
  }
  for (var i = 0; i < _internalBlockList.length; i++) {
    var blk = _internalBlockList[i];
    if (blk.family === family && prefix >= blk.prefix && blk.list.check(addr, family)) return true;
  }
  return false;
}

/**
 * Parse the OIDC_ALLOW_INTERNAL list. Returns { cidrs, error }. Every entry
 * must be an IP address with a prefix length, and the whole range must lie
 * inside a private, shared (100.64.0.0/10), loopback or link-local block.
 */
function parseInternalCidrs(list) {
  var out = [];
  var items = Array.isArray(list) ? list : [];
  for (var i = 0; i < items.length; i++) {
    var entry = String(items[i] || "").trim();
    if (!entry) continue;
    var slash = entry.lastIndexOf("/");
    if (slash === -1) return { cidrs: [], error: "OIDC_ALLOW_INTERNAL entry '" + entry + "' needs a prefix length, for example 10.0.0.5/32" };
    var addr = entry.slice(0, slash);
    var prefixText = entry.slice(slash + 1);
    var family = net.isIP(addr);
    if (!family || !/^[0-9]{1,3}$/.test(prefixText)) {
      return { cidrs: [], error: "OIDC_ALLOW_INTERNAL entry '" + entry + "' is not an IP address range" };
    }
    var prefix = parseInt(prefixText, 10);
    var maxPrefix = family === 4 ? 32 : 128; // allow:raw-byte-literal — address width in bits
    if (prefix < 1 || prefix > maxPrefix) {
      return { cidrs: [], error: "OIDC_ALLOW_INTERNAL entry '" + entry + "' needs a prefix length between 1 and " + maxPrefix };
    }
    if (!_inInternalBlock(addr, prefix)) {
      return { cidrs: [], error: "OIDC_ALLOW_INTERNAL entry '" + entry + "' is not inside a private, shared (100.64.0.0/10), loopback or link-local range" };
    }
    out.push(addr + "/" + prefix);
  }
  return { cidrs: out, error: null };
}

function _inRanges(host, cidrs) {
  var family = net.isIP(host);
  if (!family || !cidrs.length) return false;
  var list = new net.BlockList();
  for (var i = 0; i < cidrs.length; i++) {
    var slash = cidrs[i].lastIndexOf("/");
    var addr = cidrs[i].slice(0, slash);
    list.addSubnet(addr, parseInt(cidrs[i].slice(slash + 1), 10), net.isIP(addr) === 4 ? "ipv4" : "ipv6");
  }
  return list.check(host, family === 4 ? "ipv4" : "ipv6");
}

function bareHost(hostname) {
  var h = String(hostname || "");
  if (h.charAt(0) === "[" && h.charAt(h.length - 1) === "]") h = h.slice(1, -1);
  return h;
}

/**
 * Decide how the issuer may be reached. An https issuer is always allowed. An
 * http issuer is allowed only when its host is an IP address inside one of the
 * OIDC_ALLOW_INTERNAL ranges. Returns { http, host, error }.
 */
function issuerPolicy(issuer, cidrs) {
  var u;
  try { u = b.safeUrl.parse(String(issuer || ""), { allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL }); }
  catch (_e) { return { http: false, host: null, error: "OIDC_ISSUER is not a valid URL" }; }
  var host = bareHost(u.hostname);
  if (u.protocol === "https:") return { http: false, host: host, error: null };
  if (u.protocol !== "http:") return { http: false, host: host, error: "OIDC_ISSUER must use https" };
  if (!_inRanges(host, cidrs || [])) {
    return { http: true, host: host, error: "OIDC_ISSUER must use https unless its host is an IP address inside an OIDC_ALLOW_INTERNAL range" };
  }
  return { http: true, host: host, error: null };
}

function groupsClaimError(path) {
  if (!path) return null;
  var shapeErr = "OIDC_GROUPS_CLAIM must be a claim name or a dotted path such as realm_access.roles";
  if (path.length > MAX_GROUPS_CLAIM_LEN) return shapeErr;
  var segs = path.split(".");
  for (var i = 0; i < segs.length; i++) {
    if (!GROUPS_CLAIM_SEGMENT_RE.test(segs[i])) return shapeErr; // allow:regex-no-length-cap — the whole path is capped at MAX_GROUPS_CLAIM_LEN above
    if (FORBIDDEN_PATH_SEGMENTS[segs[i]]) return "OIDC_GROUPS_CLAIM may not contain the segment '" + segs[i] + "'";
  }
  return null;
}

function scopesError(scopes) {
  for (var i = 0; i < scopes.length; i++) {
    if (scopes[i].length > MAX_SCOPE_LEN || !SCOPE_TOKEN_RE.test(scopes[i])) return "OIDC_SCOPES entry '" + scopes[i] + "' is not a valid scope";
  }
  return null;
}

/**
 * Validate an OIDC settings object shaped like config.oidc. Returns an error
 * string, or null when the settings are usable. The address ranges, the groups
 * claim and the scopes are checked even while OIDC is disabled, so a bad value
 * cannot be saved now and switched on later.
 */
function validateOidcConfig(o) {
  o = o || {};
  var parsed = parseInternalCidrs(o.allowInternal);
  if (parsed.error) return parsed.error;
  var claimErr = groupsClaimError(o.groupsClaim || "");
  if (claimErr) return claimErr;
  var scopeErr = scopesError(Array.isArray(o.scopes) ? o.scopes : []);
  if (scopeErr) return scopeErr;
  if (!o.enabled) return null;
  if (!o.issuer) return "OIDC_ISSUER is required when OpenID Connect is enabled";
  if (!o.clientID) return "OIDC_CLIENT_ID is required when OpenID Connect is enabled";
  var pol = issuerPolicy(o.issuer, parsed.cidrs);
  if (pol.error) return pol.error;
  var allowlist = Array.isArray(o.allowlist) ? o.allowlist : [];
  if (o.autoProvision && allowlist.length === 0 && !o.requiredGroup) {
    return "OIDC_AUTO_PROVISION needs OIDC_ALLOWLIST or OIDC_REQUIRED_GROUP. Without either, every user of the identity provider would get an account";
  }
  return null;
}

module.exports = {
  parseInternalCidrs: parseInternalCidrs,
  issuerPolicy: issuerPolicy,
  bareHost: bareHost,
  groupsClaimError: groupsClaimError,
  validateOidcConfig: validateOidcConfig,
  FORBIDDEN_PATH_SEGMENTS: FORBIDDEN_PATH_SEGMENTS,
};
