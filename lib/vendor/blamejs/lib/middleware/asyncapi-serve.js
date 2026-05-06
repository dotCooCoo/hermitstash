"use strict";
/**
 * asyncapi-serve middleware — expose an AsyncAPI 3.0 document at a
 * mount point.
 *
 *   var aapi = b.asyncapi.create({ ... });
 *   ...add channels / operations / schemas / security...
 *
 *   router.use(b.middleware.asyncapiServe({
 *     document:      aapi,
 *     pathJson:      "/asyncapi.json",
 *     pathYaml:      "/asyncapi.yaml",
 *     pretty:        true,
 *     accessControl: "public",
 *   }));
 *
 * Behaviour matches openapiServe: GET / HEAD only, SHA3-512 ETag with
 * conditional 304, configurable CORS gate, falls through on other
 * paths / methods.
 */

var nodeCrypto    = require("crypto");
var validateOpts  = require("../validate-opts");
var lazyRequire   = require("../lazy-require");
var { defineClass } = require("../framework-error");
var AsyncApiError = defineClass("AsyncApiError", { alwaysPermanent: true });

var openapiYaml   = lazyRequire(function () { return require("../openapi-yaml"); });
var audit         = lazyRequire(function () { return require("../audit"); });

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "document", "pathJson", "pathYaml", "pretty",
    "cacheControl", "accessControl", "audit",
  ], "middleware.asyncapiServe");
  if (!opts.document || typeof opts.document.toJson !== "function") {
    throw new AsyncApiError("asyncapi/bad-document",
      "asyncapiServe: document must be a builder created via b.asyncapi.create()");
  }
  var pathJson      = opts.pathJson || "/asyncapi.json";
  var pathYaml      = opts.pathYaml || "/asyncapi.yaml";
  var pretty        = opts.pretty === true ? 2 : 0;
  var cacheControl  = (typeof opts.cacheControl === "string" && opts.cacheControl.length > 0)
    ? opts.cacheControl : "public, max-age=300";
  var accessControl = opts.accessControl || "public";
  var auditOn       = opts.audit !== false;

  if (typeof pathJson !== "string" || pathJson.charAt(0) !== "/") {
    throw new AsyncApiError("asyncapi/bad-path",
      "asyncapiServe: pathJson must start with '/'");
  }
  if (typeof pathYaml !== "string" || pathYaml.charAt(0) !== "/") {
    throw new AsyncApiError("asyncapi/bad-path",
      "asyncapiServe: pathYaml must start with '/'");
  }

  var cachedJsonStr  = null;
  var cachedYamlStr  = null;
  var cachedJsonEtag = null;
  var cachedYamlEtag = null;

  function _rebuild() {
    var doc = opts.document.toJson();
    cachedJsonStr  = JSON.stringify(doc, null, pretty);
    cachedYamlStr  = openapiYaml().toYaml(doc);
    cachedJsonEtag = '"' + nodeCrypto.createHash("sha3-512").update(cachedJsonStr).digest("base64url").slice(0, 24) + '"';
    cachedYamlEtag = '"' + nodeCrypto.createHash("sha3-512").update(cachedYamlStr).digest("base64url").slice(0, 24) + '"';
  }
  _rebuild();

  function _writeBody(req, res, body, etag, contentType) {
    var requestEtag = (req.headers && req.headers["if-none-match"]) || null;
    if (requestEtag && requestEtag === etag) {
      res.writeHead(304, { "ETag": etag, "Cache-Control": cacheControl });           // allow:raw-byte-literal — HTTP 304
      res.end();
      return;
    }
    var headers = {
      "Content-Type":   contentType,
      "Content-Length": Buffer.byteLength(body),
      "Cache-Control":  cacheControl,
      "ETag":           etag,
    };
    if (accessControl === "public") {
      headers["Access-Control-Allow-Origin"] = "*";
    }
    res.writeHead(200, headers);                                                     // allow:raw-byte-literal — HTTP 200
    res.end(body);
  }

  var mw = function (req, res, next) {
    if (typeof res.writeHead !== "function") return next();
    var method = (req.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") return next();
    var pathname = req.pathname;
    if (typeof pathname !== "string") {
      var url = req.url || "";
      var qIdx = url.indexOf("?");
      pathname = qIdx === -1 ? url : url.slice(0, qIdx);
    }
    if (pathname === pathJson) {
      _writeBody(req, res, cachedJsonStr, cachedJsonEtag, "application/json; charset=utf-8");
      if (auditOn) {
        try {
          audit().safeEmit({
            action:   "asyncapi.document.served",
            outcome:  "success",
            actor:    null,
            metadata: { format: "json", path: pathname, bytes: cachedJsonStr.length },
          });
        } catch (_e) { /* drop-silent */ }
      }
      return;
    }
    if (pathname === pathYaml) {
      _writeBody(req, res, cachedYamlStr, cachedYamlEtag, "application/yaml; charset=utf-8");
      if (auditOn) {
        try {
          audit().safeEmit({
            action:   "asyncapi.document.served",
            outcome:  "success",
            actor:    null,
            metadata: { format: "yaml", path: pathname, bytes: cachedYamlStr.length },
          });
        } catch (_e) { /* drop-silent */ }
      }
      return;
    }
    return next();
  };
  mw.forceRebuild = _rebuild;
  return mw;
}

module.exports = { create: create };
