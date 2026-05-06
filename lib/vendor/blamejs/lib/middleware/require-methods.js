"use strict";
/**
 * require-methods middleware — refuses HTTP methods outside an
 * operator-supplied allowlist.
 *
 * Defense against unexpected verb routing. Many CVE-class bugs trace
 * to a route handler that was wired for GET but accidentally also
 * accepts arbitrary verbs (PROPFIND, OPTIONS, custom). Mounting
 * `requireMethods(["GET", "POST"])` on the route blocks anything
 * outside the allowlist before the handler sees the request.
 *
 *   router.use(b.middleware.requireMethods(["GET", "POST"]));
 *
 * Refusal returns 405 with `Allow:` listing the allowed methods, per
 * RFC 9110 §15.5.6.
 */

var lazyRequire = require("../lazy-require");
var { defineClass } = require("../framework-error");

var RequireMethodsError = defineClass("RequireMethodsError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });

function create(allowed, opts) {
  if (!Array.isArray(allowed) || allowed.length === 0) {
    throw new RequireMethodsError("require-methods/no-allowlist",
      "middleware.requireMethods: first argument must be a non-empty array of HTTP methods");
  }
  var normalized = [];
  for (var i = 0; i < allowed.length; i += 1) {
    if (typeof allowed[i] !== "string" || allowed[i].length === 0) {
      throw new RequireMethodsError("require-methods/bad-method",
        "middleware.requireMethods: method[" + i + "] must be a non-empty string");
    }
    if (/[\r\n\0\s,;]/.test(allowed[i])) {
      throw new RequireMethodsError("require-methods/bad-method",
        "middleware.requireMethods: method[" + i + "] contains forbidden whitespace / separator characters");
    }
    normalized.push(allowed[i].toUpperCase());
  }
  var allowHeader = normalized.join(", ");
  opts = opts || {};
  var auditOn = opts.audit !== false;

  return function requireMethodsMiddleware(req, res, next) {
    var m = (req.method || "").toUpperCase();
    if (normalized.indexOf(m) !== -1) return next();
    if (!res.headersSent) {
      var body = "Method Not Allowed";
      res.writeHead(405, {                                                       // allow:raw-byte-literal — HTTP 405 status
        "Allow":          allowHeader,
        "Content-Type":   "text/plain; charset=utf-8",
        "Content-Length": Buffer.byteLength(body),
      });
      res.end(body);
    }
    if (auditOn) {
      try {
        observability().safeEvent("middleware.requireMethods.denied", 1, {
          method: m, route: req.url,
        });
      } catch (_e) { /* drop-silent */ }
    }
  };
}

module.exports = {
  create: create,
};
