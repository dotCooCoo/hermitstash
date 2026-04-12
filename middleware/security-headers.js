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
      // Build analytics CSP domains from auto-detection or manual override
      var analyticsDomains = "";
      if (config.analyticsCspDomains) {
        // Manual override — admin-specified domains
        analyticsDomains = " " + config.analyticsCspDomains.split(",").map(function (d) { return d.trim(); }).filter(Boolean).join(" ");
      } else if (config.analyticsScript) {
        // Auto-detect: extract domains from src="" and https:// URLs in the script tag
        var srcMatches = config.analyticsScript.match(/(?:src|href)=["']https?:\/\/([^"'\s\/]+)/gi) || [];
        var urlMatches = config.analyticsScript.match(/https?:\/\/([^"'\s\/\)]+)/gi) || [];
        var domains = new Set();
        srcMatches.concat(urlMatches).forEach(function (m) {
          try { var host = m.replace(/^.*?https?:\/\//i, "").split(/[/"'\s]/)[0]; if (host && host.includes(".")) domains.add("https://" + host); } catch (_e) {}
        });
        if (domains.size > 0) analyticsDomains = " " + Array.from(domains).join(" ");
      }
      var scriptSrc = "script-src 'self' 'unsafe-inline'" + analyticsDomains;
      var connectSrc = "connect-src 'self'" + analyticsDomains;
      res.setHeader("Content-Security-Policy", "default-src 'self'; " + scriptSrc + "; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data: https:; " + connectSrc + "; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
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
