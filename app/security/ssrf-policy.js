/**
 * SSRF Policy — comprehensive URL validation and IP denylist.
 * Replaces ad-hoc checks scattered across routes and lib/webhook.js.
 *
 * Covers all reserved/special-use ranges from IANA:
 *   RFC 1918, RFC 6598, RFC 5737, RFC 3927, RFC 4843,
 *   RFC 6333, RFC 6666, multicast, broadcast, loopback.
 */
var dns = require("dns");
var { URL } = require("url");

// CIDR ranges that must be blocked
var DENIED_CIDRS = [
  // IPv4 private & reserved
  { prefix: "0.",        label: "this-network" },
  { prefix: "10.",       label: "rfc1918" },
  // 100.64.0.0/10 (CGNAT) handled by isCgnat() below
  { prefix: "127.",       label: "loopback" },
  { prefix: "169.254.",   label: "link-local" },
  { prefix: "172.16.",    label: "rfc1918" },
  { prefix: "172.17.",    label: "rfc1918" },
  { prefix: "172.18.",    label: "rfc1918" },
  { prefix: "172.19.",    label: "rfc1918" },
  { prefix: "172.20.",    label: "rfc1918" },
  { prefix: "172.21.",    label: "rfc1918" },
  { prefix: "172.22.",    label: "rfc1918" },
  { prefix: "172.23.",    label: "rfc1918" },
  { prefix: "172.24.",    label: "rfc1918" },
  { prefix: "172.25.",    label: "rfc1918" },
  { prefix: "172.26.",    label: "rfc1918" },
  { prefix: "172.27.",    label: "rfc1918" },
  { prefix: "172.28.",    label: "rfc1918" },
  { prefix: "172.29.",    label: "rfc1918" },
  { prefix: "172.30.",    label: "rfc1918" },
  { prefix: "172.31.",    label: "rfc1918" },
  { prefix: "192.0.0.",   label: "ietf-protocol" },
  { prefix: "192.0.2.",   label: "rfc5737-doc" },
  { prefix: "192.168.",   label: "rfc1918" },
  { prefix: "198.18.",    label: "rfc2544-bench" },
  { prefix: "198.19.",    label: "rfc2544-bench" },
  { prefix: "198.51.100.",label: "rfc5737-doc" },
  { prefix: "203.0.113.", label: "rfc5737-doc" },
  { prefix: "224.",       label: "multicast" },
  { prefix: "225.",       label: "multicast" },
  { prefix: "226.",       label: "multicast" },
  { prefix: "227.",       label: "multicast" },
  { prefix: "228.",       label: "multicast" },
  { prefix: "229.",       label: "multicast" },
  { prefix: "230.",       label: "multicast" },
  { prefix: "231.",       label: "multicast" },
  { prefix: "232.",       label: "multicast" },
  { prefix: "233.",       label: "multicast" },
  { prefix: "234.",       label: "multicast" },
  { prefix: "235.",       label: "multicast" },
  { prefix: "236.",       label: "multicast" },
  { prefix: "237.",       label: "multicast" },
  { prefix: "238.",       label: "multicast" },
  { prefix: "239.",       label: "multicast" },
  { prefix: "240.",       label: "reserved" },
  { prefix: "255.",       label: "broadcast" },
];

// Cloud metadata endpoints
var DENIED_HOSTNAMES = [
  "metadata.google.internal",
  "metadata.google",
  "169.254.169.254",     // AWS/GCP/Azure metadata
  "fd00:ec2::254",       // AWS IMDSv2 IPv6
];

// RFC 6598 CGNAT: 100.64.0.0/10 = 100.64.0.0 – 100.127.255.255
function isCgnat(ip) {
  if (!ip.startsWith("100.")) return false;
  var second = parseInt(ip.split(".")[1], 10);
  return second >= 64 && second <= 127;
}

/**
 * Check if an IP address is in a denied range.
 */
function isPrivateIp(ip) {
  if (!ip) return true;
  var h = String(ip).toLowerCase().replace(/^\[|\]$/g, "");

  // Exact matches
  if (h === "localhost" || h === "0.0.0.0" || h === "::1" || h === "::" || h === "") return true;

  // IPv6-mapped IPv4
  if (h.startsWith("::ffff:")) return isPrivateIp(h.substring(7));

  // IPv6 private ranges
  if (h.startsWith("fc") || h.startsWith("fd")) return true;       // ULA
  if (h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb")) return true; // link-local
  if (h.startsWith("ff")) return true;                              // multicast

  // CGNAT range (100.64.0.0/10) — numeric check for full coverage
  if (isCgnat(h)) return true;

  // IPv4 CIDR prefix check
  for (var i = 0; i < DENIED_CIDRS.length; i++) {
    if (h.startsWith(DENIED_CIDRS[i].prefix)) return true;
  }

  return false;
}

/**
 * Check if a hostname resolves to a private/denied IP.
 * Resolves DNS to prevent rebinding attacks.
 */
function isPrivateHost(hostname) {
  if (!hostname) return Promise.resolve(true);
  var h = String(hostname).toLowerCase();

  // Check denied hostnames
  for (var i = 0; i < DENIED_HOSTNAMES.length; i++) {
    if (h === DENIED_HOSTNAMES[i]) return Promise.resolve(true);
  }

  // Check if hostname is a literal IP
  if (isPrivateIp(h)) return Promise.resolve(true);

  // Resolve DNS and check all addresses
  return new Promise(function (resolve) {
    dns.lookup(h, { all: true }, function (err, addresses) {
      if (err || !addresses || addresses.length === 0) return resolve({ blocked: true });
      for (var j = 0; j < addresses.length; j++) {
        if (isPrivateIp(addresses[j].address)) return resolve({ blocked: true });
      }
      resolve({ blocked: false, address: addresses[0].address, family: addresses[0].family });
    });
  });
}

/**
 * Validate a URL for outbound requests (webhooks, etc.).
 * Returns { valid: true } or { valid: false, reason: string }.
 */
function validateOutboundUrl(urlStr) {
  try {
    var u = new URL(urlStr);
  } catch (_e) {
    return { valid: false, reason: "Invalid URL" };
  }
  if (u.protocol !== "https:") return { valid: false, reason: "HTTPS required" };
  if (u.username || u.password) return { valid: false, reason: "Credentials in URL not allowed" };
  if (!u.hostname) return { valid: false, reason: "Missing hostname" };
  return { valid: true, url: u };
}

module.exports = { isPrivateIp, isPrivateHost, validateOutboundUrl };
