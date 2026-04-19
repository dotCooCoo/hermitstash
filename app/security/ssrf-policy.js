/**
 * SSRF Policy — comprehensive URL validation and IP denylist.
 * Replaces ad-hoc checks scattered across routes and lib/webhook.js.
 *
 * Covers all reserved/special-use ranges from IANA:
 *   RFC 1918, RFC 6598 (CGNAT), RFC 5737 (doc), RFC 3927 (link-local),
 *   RFC 2544 (benchmarking), RFC 5771 (multicast), RFC 6890 (reserved),
 *   IPv6 ULA (RFC 4193), IPv6 link-local, IPv6 multicast, loopback.
 *
 * Uses Node's built-in net.BlockList for proper CIDR matching. The earlier
 * implementation used string-prefix checks ("240.", etc.) which missed
 * 241.0.0.0 through 254.255.255.255 — 14 /8 ranges inside the reserved
 * 240.0.0.0/4 allocation. A hostname resolving to e.g. 250.1.2.3 previously
 * passed through as public; this version blocks the whole /4.
 */
var dns = require("dns");
var net = require("net");
var { URL } = require("url");

var blockList = new net.BlockList();

// IPv4 reserved / private / special-use ranges
blockList.addAddress("0.0.0.0", "ipv4");
blockList.addSubnet("10.0.0.0", 8, "ipv4");              // RFC 1918
blockList.addSubnet("100.64.0.0", 10, "ipv4");           // RFC 6598 CGNAT
blockList.addSubnet("127.0.0.0", 8, "ipv4");             // loopback
blockList.addSubnet("169.254.0.0", 16, "ipv4");          // link-local
blockList.addSubnet("172.16.0.0", 12, "ipv4");           // RFC 1918
blockList.addSubnet("192.0.0.0", 24, "ipv4");            // IETF protocol assignments
blockList.addSubnet("192.0.2.0", 24, "ipv4");            // RFC 5737 doc TEST-NET-1
blockList.addSubnet("192.168.0.0", 16, "ipv4");          // RFC 1918
blockList.addSubnet("198.18.0.0", 15, "ipv4");           // RFC 2544 benchmarking (198.18+198.19)
blockList.addSubnet("198.51.100.0", 24, "ipv4");         // RFC 5737 doc TEST-NET-2
blockList.addSubnet("203.0.113.0", 24, "ipv4");          // RFC 5737 doc TEST-NET-3
blockList.addSubnet("224.0.0.0", 4, "ipv4");             // multicast (224.0.0.0 – 239.255.255.255)
blockList.addSubnet("240.0.0.0", 4, "ipv4");             // reserved + broadcast (240.0.0.0 – 255.255.255.255)

// IPv6 reserved / private / special-use ranges
blockList.addAddress("::1", "ipv6");                     // loopback
blockList.addAddress("::", "ipv6");                      // unspecified
blockList.addSubnet("fc00::", 7, "ipv6");                // ULA (RFC 4193) — fc00::/7 covers fc + fd
blockList.addSubnet("fe80::", 10, "ipv6");               // link-local (RFC 4291)
blockList.addSubnet("ff00::", 8, "ipv6");                // multicast (RFC 4291)
blockList.addSubnet("2001:db8::", 32, "ipv6");           // RFC 3849 documentation
blockList.addSubnet("64:ff9b::", 96, "ipv6");            // RFC 6052 well-known prefix
blockList.addSubnet("100::", 64, "ipv6");                // RFC 6666 discard prefix
blockList.addSubnet("2002::", 16, "ipv6");               // 6to4 (RFC 3056)

// Hostnames that must always be blocked (cloud metadata endpoints).
// The IP addresses behind these are in link-local / ULA ranges which
// blockList already catches, but denying by name prevents DNS-level
// tricks where a public name resolves to the metadata IP.
var DENIED_HOSTNAMES = [
  "metadata.google.internal",
  "metadata.google",
  "metadata",
  "169.254.169.254",     // AWS/GCP/Azure metadata (also caught by link-local /16)
  "fd00:ec2::254",       // AWS IMDSv2 IPv6 (also caught by ULA /7)
];

/**
 * Check if an IP literal falls in a reserved/private range.
 */
function isPrivateIp(ip) {
  if (!ip) return true;
  var h = String(ip).toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h === "") return true;
  // IPv6-mapped IPv4 → delegate to the IPv4 path
  if (h.startsWith("::ffff:")) return isPrivateIp(h.substring(7));

  if (net.isIPv4(h)) return blockList.check(h, "ipv4");
  if (net.isIPv6(h)) return blockList.check(h, "ipv6");
  // Not a valid IP literal — treat as blocked to be safe.
  return true;
}

/**
 * Resolve a hostname and block if any resolved address is private.
 * Prevents DNS-rebinding to internal addresses.
 */
function isPrivateHost(hostname) {
  if (!hostname) return Promise.resolve({ blocked: true });
  var h = String(hostname).toLowerCase();

  for (var i = 0; i < DENIED_HOSTNAMES.length; i++) {
    if (h === DENIED_HOSTNAMES[i]) return Promise.resolve({ blocked: true });
  }

  // Literal IP — check directly, no DNS required.
  if (net.isIP(h)) return Promise.resolve({ blocked: isPrivateIp(h) });

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
 * Returns { valid: true, url } or { valid: false, reason }.
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
