/**
 * CORS middleware — thin wrapper around b.middleware.cors.
 *
 * Reads config.corsOrigins (array of origin strings) at build time.
 * Wildcard "*" entries are filtered out — blamejs requires an explicit
 * allowlist (the wildcard + credentials combo is a spec violation anyway).
 * The wrapper rebuilds on config hot-reload via config.onReset.
 */
var b = require("../lib/vendor/blamejs");
var config = require("../lib/config");
var originPolicy = require("../app/security/origin-policy");

function build() {
  var origins = (config.corsOrigins || []).filter(function (o) {
    return typeof o === "string" && o !== "*" && o.length > 0;
  });
  return b.middleware.cors({
    origins:       origins,
    siteOrigin:    originPolicy.getOrigin(),
    credentials:   true,
    refuseUnknown: true,
  });
}

var current = build();
config.onReset(function () { current = build(); });

module.exports = function (req, res, next) {
  // /health runs its own narrower CORS (rpOrigin + HEALTH_CORS_ORIGINS) so
  // the gateway at hermitstash.com can probe app.hermitstash.com without
  // appearing on the global CORS_ORIGINS allowlist. Bypass the global
  // refuseUnknown check for that one path only.
  if (req.pathname === "/health") return next();
  return current(req, res, next);
};
