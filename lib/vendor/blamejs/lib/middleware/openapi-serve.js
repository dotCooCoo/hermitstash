// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C             = require("../constants");
var nodeCrypto    = require("node:crypto");
var validateOpts  = require("../validate-opts");
var lazyRequire   = require("../lazy-require");
var safeUrl       = require("../safe-url");
var { defineClass } = require("../framework-error");
var OpenApiError = defineClass("OpenApiError", { alwaysPermanent: true });

function _canonicalAllowOrigin(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new OpenApiError("openapi/bad-access-control",
      label + ": accessControl.allowOrigin must be a non-empty origin string " +
      "(e.g. \"https://docs.example.com\")");
  }
  var parsed;
  try {
    parsed = safeUrl.parse(value, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
  } catch (e) {
    throw new OpenApiError("openapi/bad-access-control",
      label + ": accessControl.allowOrigin '" + value + "' is not a valid " +
      "http(s) origin: " + ((e && e.message) || String(e)));
  }
  var path = parsed.pathname || "";
  if ((path !== "" && path !== "/") || parsed.search || parsed.hash) {
    throw new OpenApiError("openapi/bad-access-control",
      label + ": accessControl.allowOrigin must be a bare origin " +
      "(scheme://host[:port]) with no path / query / fragment; got '" + value + "'");
  }
  var port = parsed.port;
  return parsed.protocol + "//" + parsed.hostname.toLowerCase() + (port ? ":" + port : "");
}

var openapiYaml   = lazyRequire(function () { return require("../openapi-yaml"); });
var audit         = lazyRequire(function () { return require("../audit"); });

/**
 * @primitive b.middleware.openapiServe
 * @signature b.middleware.openapiServe(opts)
 * @since     0.1.0
 * @related   b.middleware.asyncapiServe, b.openapi.create
 *
 * Serves an OpenAPI 3.1 document built via `b.openapi.create` at a
 * configurable JSON + YAML mount point. GET/HEAD only; everything
 * else falls through. SHA3-512 ETag enables conditional 304. With
 * `accessControl: "public"` (default) emits
 * `Access-Control-Allow-Origin: *` so external doc tooling can
 * fetch; `same-origin` omits the CORS header for internal-only docs;
 * `{ allowOrigin: "https://docs.example.com" }` echoes one validated
 * origin with `Vary: Origin`.
 *
 * @opts
 *   {
 *     document:      object,    // builder from b.openapi.create()
 *     pathJson:      string,    // default "/openapi.json"
 *     pathYaml:      string,    // default "/openapi.yaml"
 *     pretty:        boolean,
 *     cacheControl:  string,    // default "public, max-age=300"
 *     accessControl: "public"|"same-origin"|{ allowOrigin: string },
 *     audit:         boolean,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   var doc = b.openapi.create({ info: { title: "api", version: "1.0.0" } });
 *   app.use(b.middleware.openapiServe({
 *     document:     doc,
 *     pretty:       true,
 *     cacheControl: "public, max-age=300",
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "document", "pathJson", "pathYaml", "pretty",
    "cacheControl", "accessControl", "audit",
  ], "middleware.openapiServe");
  if (!opts.document || typeof opts.document.toJson !== "function") {
    throw new OpenApiError("openapi/bad-document",
      "openapiServe: document must be a builder created via b.openapi.create()");
  }
  var pathJson      = opts.pathJson || "/openapi.json";
  var pathYaml      = opts.pathYaml || "/openapi.yaml";
  var pretty        = opts.pretty === true ? 2 : 0;
  var cacheControl  = (typeof opts.cacheControl === "string" && opts.cacheControl.length > 0)
    ? opts.cacheControl : "public, max-age=300";
  var accessControl = opts.accessControl || "public";
  var allowOriginHeader = null;
  if (accessControl === "public") {
    allowOriginHeader = "*";
  } else if (accessControl && typeof accessControl === "object" &&
             typeof accessControl.allowOrigin === "string") {
    allowOriginHeader = _canonicalAllowOrigin(accessControl.allowOrigin, "openapiServe");
  }
  var auditOn       = opts.audit !== false;

  if (typeof pathJson !== "string" || pathJson.charAt(0) !== "/") {
    throw new OpenApiError("openapi/bad-path",
      "openapiServe: pathJson must start with '/' - got " + JSON.stringify(pathJson));
  }
  if (typeof pathYaml !== "string" || pathYaml.charAt(0) !== "/") {
    throw new OpenApiError("openapi/bad-path",
      "openapiServe: pathYaml must start with '/' - got " + JSON.stringify(pathYaml));
  }

  var cachedDoc       = null;
  var cachedJsonStr   = null;
  var cachedYamlStr   = null;
  var cachedJsonEtag  = null;
  var cachedYamlEtag  = null;

  function _rebuild() {
    cachedDoc      = opts.document.toJson();
    cachedJsonStr  = JSON.stringify(cachedDoc, null, pretty);
    cachedYamlStr  = openapiYaml().toYaml(cachedDoc);
    cachedJsonEtag = '"' + nodeCrypto.createHash("sha3-512").update(cachedJsonStr).digest("base64url").slice(0, 24) + '"';
    cachedYamlEtag = '"' + nodeCrypto.createHash("sha3-512").update(cachedYamlStr).digest("base64url").slice(0, 24) + '"';
  }
  _rebuild();

  function _writeBody(req, res, body, etag, contentType) {
    var requestEtag = (req.headers && req.headers["if-none-match"]) || null;
    if (requestEtag && requestEtag === etag) {
      res.writeHead(C.HTTP.STATUS.NOT_MODIFIED, { "ETag": etag, "Cache-Control": cacheControl });
      res.end();
      return;
    }
    var headers = {
      "Content-Type":   contentType,
      "Content-Length": Buffer.byteLength(body),
      "Cache-Control":  cacheControl,
      "ETag":           etag,
    };
    if (allowOriginHeader !== null) {
      headers["Access-Control-Allow-Origin"] = allowOriginHeader;
      if (allowOriginHeader !== "*") headers["Vary"] = "Origin";
    }
    res.writeHead(C.HTTP.STATUS.OK, headers);
    if ((req.method || "GET").toUpperCase() === "HEAD") { res.end(); return; }
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
            action:  "openapi.document.served",
            outcome: "success",
            actor:   null,
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
            action:  "openapi.document.served",
            outcome: "success",
            actor:   null,
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
