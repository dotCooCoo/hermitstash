"use strict";
/**
 * assetlinks middleware — emits Digital Asset Links at
 * `/.well-known/assetlinks.json` per Google's Digital Asset Links
 * spec (used by Trusted Web Activity / Android App Links / Smart
 * Lock for Passwords / Web Authentication for Android, etc.).
 *
 *   var al = b.middleware.assetlinks({
 *     statements: [
 *       {
 *         relation: ["delegate_permission/common.handle_all_urls"],
 *         target: {
 *           namespace:        "android_app",
 *           package_name:     "com.example.app",
 *           sha256_cert_fingerprints: ["AB:CD:..."],
 *         },
 *       },
 *     ],
 *   });
 *   router.use(al);
 *
 * The framework JSON-serializes the statements array once at
 * create() and serves with `Content-Type: application/json` per
 * Google's spec. Operators with multiple linked apps include
 * multiple statement entries.
 */

var lazyRequire = require("../lazy-require");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var AssetlinksError = defineClass("AssetlinksError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });

function create(opts) {
  validateOpts.requireObject(opts, "middleware.assetlinks", AssetlinksError);
  validateOpts(opts, ["statements", "audit"], "middleware.assetlinks");

  if (!Array.isArray(opts.statements) || opts.statements.length === 0) {
    throw new AssetlinksError("assetlinks/no-statements",
      "middleware.assetlinks: opts.statements must be a non-empty array of statement objects");
  }
  for (var i = 0; i < opts.statements.length; i += 1) {
    var stmt = opts.statements[i];
    if (!stmt || typeof stmt !== "object" || Array.isArray(stmt)) {
      throw new AssetlinksError("assetlinks/bad-statement",
        "middleware.assetlinks: statements[" + i + "] must be a plain object");
    }
    if (!Array.isArray(stmt.relation) || stmt.relation.length === 0) {
      throw new AssetlinksError("assetlinks/bad-statement",
        "middleware.assetlinks: statements[" + i + "].relation must be a non-empty array");
    }
    if (!stmt.target || typeof stmt.target !== "object") {
      throw new AssetlinksError("assetlinks/bad-statement",
        "middleware.assetlinks: statements[" + i + "].target must be an object");
    }
  }

  var body = safeJson.stringify(opts.statements, { space: 2 });
  var bodyBuf = Buffer.from(body, "utf8");
  var auditOn = opts.audit !== false;

  return function assetlinksMiddleware(req, res, next) {
    var url = req.url || "";
    var qIdx = url.indexOf("?");
    var path = qIdx === -1 ? url : url.slice(0, qIdx);
    if (path !== "/.well-known/assetlinks.json") return next();
    if (req.method !== "GET" && req.method !== "HEAD") {
      var bodyMsg = "Method Not Allowed";
      res.writeHead(405, {                                                       // allow:raw-byte-literal — HTTP 405 status
        "Allow":          "GET, HEAD",
        "Content-Type":   "text/plain; charset=utf-8",
        "Content-Length": Buffer.byteLength(bodyMsg),
      });
      res.end(bodyMsg);
      return;
    }
    res.writeHead(200, {                                                         // allow:raw-byte-literal — HTTP 200 status
      "Content-Type":     "application/json; charset=utf-8",
      "Content-Length":   bodyBuf.length,
      "Cache-Control":    "public, max-age=86400",
      "X-Content-Type-Options": "nosniff",
    });
    if (req.method === "HEAD") { res.end(); return; }
    res.end(bodyBuf);
    if (auditOn) {
      try { observability().safeEvent("middleware.assetlinks.served", 1, {}); }
      catch (_e) { /* obs best-effort */ }
    }
  };
}

module.exports = {
  create: create,
};
