// Maintenance mode — withholds the site from people while an operator works.
//
// It lives here rather than inline in the entry point so it can be exercised
// directly, the same reason app/security/admin-fence.js does. Mounted inline it
// could only be reached by booting the whole server, and the test harness
// builds its own middleware chain — so the behaviour below had no coverage at
// all, which is how the health-check case reached operators.
//
// /health is exempt, and that exemption is the point. Every shipped deployment
// polls it and reads anything but 200 as a dead process: the Dockerfile and
// compose health checks exit non-zero, and the kubernetes manifest wires it to
// the liveness, readiness AND startup probes. Answering the maintenance page
// there had the orchestrator restart the container for as long as maintenance
// was left on — precisely when the operator wanted it left alone. Maintenance
// withholds the site; it does not claim the process has stopped.
"use strict";

var config = require("../lib/config");
var C = require("../lib/constants");
var { sendHtml } = require("../lib/template");

// Prefixes a visitor still needs while the site is withheld: the sign-in flow
// so an admin can authenticate into the exemption below, the admin surface
// itself, and the assets both of those render with.
var ALLOWED_PREFIXES = ["/auth", "/admin", "/css", "/js", "/img"];

function isAllowedPath(pathname) {
  if (!pathname) return false;
  for (var i = 0; i < ALLOWED_PREFIXES.length; i++) {
    if (pathname.indexOf(ALLOWED_PREFIXES[i]) === 0) return true;
  }
  return false;
}

module.exports = function maintenance(req, res, next) {
  if (!config.maintenanceMode) return next();
  if (req.pathname === "/health") return next();
  if (req.user && req.user.role === "admin") return next();
  if (isAllowedPath(req.pathname)) return next();

  sendHtml(res, "maintenance", {
    brand: { siteName: config.siteName, logo: config.customLogo || C.paths.logo },
    assets: { css: C.paths.css + "?v=" + C.cssVersion },
  }, 503);
};

module.exports.ALLOWED_PREFIXES = ALLOWED_PREFIXES;
