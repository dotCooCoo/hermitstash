/**
 * Security response headers — applied to every response.
 */
var config = require("../lib/config");

module.exports = function securityHeaders(req, res, next) {
  var origWriteHead = res.writeHead.bind(res);
  res.writeHead = function (code) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("X-XSS-Protection", "0");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    // HSTS for HTTPS deployments
    if (config.rpOrigin && config.rpOrigin.startsWith("https")) {
      res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    if (!res.getHeader("Content-Security-Policy")) {
      res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'");
    }
    // Prevent caching of authenticated/dynamic pages
    var isStatic = req.pathname && /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|webp)$/.test(req.pathname);
    if (!isStatic) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
      res.setHeader("Vary", "Cookie");
      // nginx-specific: override proxy_cache even if nginx.conf enables it
      res.setHeader("X-Accel-Expires", "0");
      res.setHeader("Surrogate-Control", "no-store");
    }
    return origWriteHead.apply(res, arguments);
  };
  next();
};
