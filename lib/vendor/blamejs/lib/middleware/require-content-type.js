"use strict";
/**
 * require-content-type middleware — refuses requests with a body
 * (POST/PUT/PATCH) whose `Content-Type` header isn't in the
 * operator-supplied allowlist.
 *
 * Defense against MIME-type confusion: a route that processes JSON
 * shouldn't accept `application/x-www-form-urlencoded` even if the
 * body parses (and vice versa). The middleware refuses with 415
 * before the body parser runs, per RFC 9110 §15.5.16.
 *
 *   router.use(b.middleware.requireContentType(["application/json"]));
 *
 * GET / HEAD / DELETE / OPTIONS without a body bypass the check by
 * default. Operators wanting to enforce content-type on idempotent
 * verbs that DO carry bodies (rare DELETE-with-body shapes) pass
 * `methods` to override.
 */

var lazyRequire = require("../lazy-require");
var { defineClass } = require("../framework-error");

var RequireContentTypeError = defineClass("RequireContentTypeError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });

var DEFAULT_BODY_METHODS = ["POST", "PUT", "PATCH"];

function _normalizeAllowed(types) {
  if (!Array.isArray(types) || types.length === 0) return null;
  var out = [];
  for (var i = 0; i < types.length; i += 1) {
    var t = types[i];
    if (typeof t !== "string" || t.length === 0) return null;
    var bare = t.split(";")[0].trim().toLowerCase();
    if (bare.length === 0) return null;
    out.push(bare);
  }
  return out;
}

/**
 * @primitive b.middleware.requireContentType
 * @signature b.middleware.requireContentType(allowed, opts)
 * @since     0.1.0
 * @related   b.middleware.requireMethods, b.middleware.bodyParser
 *
 * Refuses requests with a body (POST/PUT/PATCH by default) whose
 * `Content-Type` header isn't in the operator-supplied allowlist.
 * Defends against MIME-type confusion: a route that processes JSON
 * shouldn't accept `application/x-www-form-urlencoded` even if the
 * body parses, and vice versa. Refuses with HTTP 415 + `Accept:`
 * listing the allowed types per RFC 9110 §15.5.16, BEFORE the
 * body parser runs. Idempotent verbs (GET / HEAD / DELETE /
 * OPTIONS) bypass by default; operators with rare DELETE-with-body
 * shapes pass `methods` to override. Throws on empty / non-array
 * allowlist.
 *
 * @opts
 *   {
 *     methods: string[],   // override default ["POST", "PUT", "PATCH"]
 *     audit:   boolean,    // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.post("/api/echo",
 *     b.middleware.requireContentType(["application/json"]),
 *     b.middleware.bodyParser({ json: { limit: 1024 } }),
 *     function (req, res) { res.end(JSON.stringify(req.body)); }
 *   );
 */
function create(allowed, opts) {
  var normalized = _normalizeAllowed(allowed);
  if (!normalized) {
    throw new RequireContentTypeError("require-content-type/no-allowlist",
      "middleware.requireContentType: first argument must be a non-empty array of content-type strings");
  }
  opts = opts || {};
  var methods = Array.isArray(opts.methods) && opts.methods.length > 0
                  ? opts.methods.map(function (m) { return m.toUpperCase(); })
                  : DEFAULT_BODY_METHODS.slice();
  var auditOn = opts.audit !== false;

  return function requireContentTypeMiddleware(req, res, next) {
    var m = (req.method || "").toUpperCase();
    if (methods.indexOf(m) === -1) return next();
    var ct = req.headers && req.headers["content-type"];
    var bare = (typeof ct === "string" ? ct.split(";")[0].trim().toLowerCase() : "");
    if (bare.length > 0 && normalized.indexOf(bare) !== -1) return next();
    if (!res.headersSent) {
      var body = "Unsupported Media Type";
      res.writeHead(415, {                                                       // allow:raw-byte-literal — HTTP 415 status
        "Accept":         normalized.join(", "),
        "Content-Type":   "text/plain; charset=utf-8",
        "Content-Length": Buffer.byteLength(body),
      });
      res.end(body);
    }
    if (auditOn) {
      try {
        observability().safeEvent("middleware.requireContentType.denied", 1, {
          method: m, contentType: bare || "<absent>", route: req.url,
        });
      } catch (_e) { /* drop-silent */ }
    }
  };
}

module.exports = {
  create: create,
};
