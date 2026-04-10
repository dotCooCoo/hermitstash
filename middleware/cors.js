/**
 * CORS middleware — cross-origin resource sharing for API consumers.
 * Only active when CORS_ORIGINS is configured in admin settings.
 */
var config = require("../lib/config");

module.exports = function cors(req, res, next) {
  var origins = config.corsOrigins || [];
  if (origins.length === 0) return next();

  var origin = req.headers.origin || "";
  if (!origin) return next();

  var allowed = origins.indexOf(origin) !== -1 || origins.indexOf("*") !== -1;
  if (!allowed) return next();

  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");

  // Preflight
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
    res.setHeader("Access-Control-Max-Age", "86400");
    res.writeHead(204);
    return res.end();
  }

  next();
};
