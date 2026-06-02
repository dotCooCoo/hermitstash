/**
 * SSRF policy — outbound URL validation + private-address denial.
 *
 * IP classification is delegated to b.ssrfGuard. It refuses every
 * reserved / non-routable class: RFC 1918 private, RFC 6598 CGNAT,
 * loopback, link-local, the RFC 5737 documentation nets, RFC 2544
 * benchmarking, multicast, and the reserved 240/4 block; IPv6 ULA,
 * link-local, multicast, documentation, and discard prefixes; and the
 * NAT64, 6to4, and IPv4-mapped wrappers — each reclassified to its
 * embedded IPv4 address so a wrapped private or metadata target is
 * refused for the same reason its bare form would be. Cloud-metadata
 * IPs (AWS/GCP/Azure 169.254.169.254, the AWS ECS task-role
 * 169.254.170.2, and the IMDS-over-IPv6 fd00:ec2::254) are refused as
 * their own class.
 *
 * Hostnames are resolved and refused if ANY resolved address classifies
 * as non-public, which defeats DNS-rebinding to an internal target. The
 * resolved address is returned so the caller can pin its TCP connect to
 * the validated IP (TOCTOU defence against a rebind between check and
 * connect).
 */
var dns = require("node:dns");
var net = require("node:net");
var b = require("../../lib/vendor/blamejs");

// Hostnames that must always be blocked (cloud metadata endpoints). The
// IPs behind these are already caught by b.ssrfGuard.classify, but denying
// by name as well stops a DNS trick where a public name resolves to a
// metadata IP only at connect time.
var DENIED_HOSTNAMES = [
  "metadata.google.internal",
  "metadata.google",
  "metadata",
  "169.254.169.254",
  "fd00:ec2::254",
];

/**
 * Check if an IP literal falls in a reserved / private / metadata range.
 * Non-IP input is treated as blocked (fail-closed) so a malformed or
 * unresolved value can never pass through as public.
 */
function isPrivateIp(ip) {
  if (!ip) return true;
  var h = String(ip).toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (h === "localhost" || h === "") return true;
  if (net.isIP(h) === 0) return true;        // not a valid IP literal → blocked
  return b.ssrfGuard.classify(h) !== null;   // any non-public class → blocked
}

/**
 * Resolve a hostname and block if any resolved address is private.
 * Prevents DNS-rebinding to internal addresses. Returns
 * { blocked, address?, family? }; on a clean result, address/family pin
 * the validated IP for the caller's connect (TOCTOU defence).
 */
function isPrivateHost(hostname) {
  if (!hostname) return Promise.resolve({ blocked: true });
  var h = String(hostname).toLowerCase().replace(/\.+$/, "");

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
 *
 * b.safeUrl.parse with ALLOW_HTTP_TLS pre-frozen ["https:"] enforces the
 * HTTPS-only constraint at parse time. parse also bounds the input
 * length (8 KiB default), refuses NUL/CR/LF in the input, and runs the
 * URL through Node's WHATWG parser — same bytes the runtime would
 * dispatch on, no double-parse drift.
 */
function validateOutboundUrl(urlStr) {
  var u;
  try {
    u = b.safeUrl.parse(urlStr, { allowedProtocols: b.safeUrl.ALLOW_HTTP_TLS });
  } catch (_e) {
    return { valid: false, reason: "Invalid URL" };
  }
  if (u.username || u.password) return { valid: false, reason: "Credentials in URL not allowed" };
  if (!u.hostname) return { valid: false, reason: "Missing hostname" };
  return { valid: true, url: u };
}

module.exports = { isPrivateIp, isPrivateHost, validateOutboundUrl };
