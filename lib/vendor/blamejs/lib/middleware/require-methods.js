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
var denyResponse = require("./deny-response").denyResponse;
var { defineClass } = require("../framework-error");

var RequireMethodsError = defineClass("RequireMethodsError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });

/**
 * @primitive b.middleware.requireMethods
 * @signature b.middleware.requireMethods(allowed, opts)
 * @since     0.1.0
 * @related   b.middleware.requireContentType
 *
 * Refuses HTTP methods outside the operator-supplied allowlist.
 * Defends against unexpected verb routing — many CVE-class bugs
 * trace to a route wired for GET that accidentally accepts arbitrary
 * verbs (PROPFIND, OPTIONS, custom). Refuses with HTTP 405 +
 * `Allow:` header listing the allowed methods per RFC 9110 §15.5.6.
 * Throws at create-time on empty / non-array allowlist or methods
 * containing whitespace/separator characters.
 *
 * @opts
 *   {
 *     audit:          boolean,   // default true
 *     onDeny:         function(req, res, info): void,  // own the 405; info = { status, reason, method, allowed }
 *     problemDetails: boolean,   // default false — emit RFC 9457 application/problem+json instead of text/plain
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use("/api",
 *     b.middleware.requireMethods(["GET", "POST"]),
 *     function (req, res) { res.end("ok"); }
 *   );
 */
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
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;

  return function requireMethodsMiddleware(req, res, next) {
    var m = (req.method || "").toUpperCase();
    if (normalized.indexOf(m) !== -1) return next();
    if (!res.headersSent) {
      denyResponse(req, res, {
        onDeny:        onDeny,
        problem:       problemMode,
        status:        405,
        info:          { status: 405, reason: "method-not-allowed", method: m, allowed: normalized },
        problemCode:   "method-not-allowed",
        problemTitle:  "Method Not Allowed",
        problemDetail: "The " + m + " method is not allowed on this resource.",
        headers:       { "Allow": allowHeader },
        contentType:   "text/plain; charset=utf-8",
        body:          "Method Not Allowed",
      });
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
