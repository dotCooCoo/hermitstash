/**
 * Admin network fence — opt-in CIDR allowlist on the /admin surface.
 *
 * An ADDITIVE network-layer gate that sits ON TOP OF requireAdmin auth:
 * requireAdmin stops unauthorized USERS, the fence stops the route being
 * REACHABLE from outside the operator's admin network at all, which is what
 * defends a leaked credential. Created ONLY when ADMIN_ALLOWED_CIDRS is
 * non-empty, so the default deployment mounts nothing and /admin behaves
 * exactly as before. A miss is answered 404, not 403, so a probe cannot tell
 * the fence exists.
 *
 * The client IP comes from HS's peer-gated reader, and that is the whole
 * reason this is not b.middleware.networkAllowlist. clientIp.getIp honours
 * X-Forwarded-For ONLY when the socket peer is a configured trusted proxy, and
 * canonicalizes ::ffff: IPv4-mapped IPv6. The framework primitive resolves the
 * client IP itself without that peer gate, so an X-Forwarded-For header on a
 * request arriving off-proxy could name an in-range source and pass — and a
 * dual-stack listener could false-deny an in-range operator on a ::ffff:
 * address. Composing getIp closes both.
 */
var b = require("../../lib/vendor/blamejs");
var clientIp = require("../../lib/client-ip");
var audit = require("../../lib/audit");

/**
 * Validate the operator's CIDR list and return the usable entries.
 *
 * Throws on a malformed entry rather than dropping it. A typo'd fence is an
 * operator emergency: silently discarding the bad entry removes part of the
 * allowlist with no indication, and the deployment keeps running while the
 * fence it is trusting has a hole. parseCidrList also supplies the /32 a bare
 * address needs — written without one it matched nothing at all, not even
 * itself.
 */
function compile(entries) {
  var list = Array.isArray(entries) ? entries : [entries];
  var fence = clientIp.parseCidrList(list.join(","));
  if (fence.invalid.length > 0) {
    throw new Error("ADMIN_ALLOWED_CIDRS contains a malformed entry: "
      + fence.invalid.map(function (bad) {
        return JSON.stringify(bad.entry) + " (" + bad.reason + ")";
      }).join("; "));
  }
  return fence.valid;
}

/**
 * Is this request in the admin surface the fence covers?
 *
 * Boundary-aware on purpose: /administer and /admin-tools are separate routes
 * and a bare prefix test would fence them too.
 */
function isAdminPath(pathname) {
  return pathname === "/admin" || pathname.indexOf("/admin/") === 0;
}

/**
 * Build the fence middleware over a validated CIDR list.
 */
function create(entries) {
  var cidrs = compile(entries);

  return function adminNetworkFence(req, res, next) {
    // Decide on the router's canonical, once-decoded req.pathname — never the
    // raw req.url, whose percent-escapes the gate and the downstream route
    // matcher would resolve differently (a gate-vs-resolver split). The router
    // always sets req.pathname before middleware; if it is ever absent, fail
    // CLOSED by treating the request as admin-scoped so the fence still applies.
    var pathname = typeof req.pathname === "string" ? req.pathname : "/admin";
    if (!isAdminPath(pathname)) return next();

    var ip = clientIp.getIp(req);
    var allowed = !!ip && cidrs.some(function (cidr) {
      try { return b.ssrfGuard.cidrContains(cidr, ip); } catch (_e) { return false; }
    });
    if (allowed) return next();

    audit.log(audit.ACTIONS.ADMIN_FENCE_DENIED, {
      req: req,
      details: "Admin request from a non-allowlisted network was refused: " + pathname,
    });
    res.statusCode = 404;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Not Found");
  };
}

module.exports = { create: create, compile: compile, isAdminPath: isAdminPath };
