// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var nodeCrypto    = require("node:crypto");
var validateOpts  = require("../validate-opts");
var lazyRequire   = require("../lazy-require");
var safeUrl       = require("../safe-url");
var { defineClass } = require("../framework-error");
var AsyncApiError = defineClass("AsyncApiError", { alwaysPermanent: true });

// Validate an operator-supplied accessControl.allowOrigin and return the
// canonical `scheme://host[:port]` string for the Access-Control-Allow-
// Origin response header. CORS (Fetch Standard §3.2.1) requires a single
// concrete origin with no path / query / fragment; the empty-string and
// "*" wildcard forms are spelled separately ("same-origin" / "public").
// Parsing through safeUrl rejects header-injection bytes (CR/LF) and
// userinfo, and confirms the value is a real http(s) origin. Throws so
// the operator catches a typo'd allowOrigin at boot.
function _canonicalAllowOrigin(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new AsyncApiError("asyncapi/bad-access-control",
      label + ": accessControl.allowOrigin must be a non-empty origin string " +
      "(e.g. \"https://docs.example.com\")");
  }
  var parsed;
  try {
    parsed = safeUrl.parse(value, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL });
  } catch (e) {
    throw new AsyncApiError("asyncapi/bad-access-control",
      label + ": accessControl.allowOrigin '" + value + "' is not a valid " +
      "http(s) origin: " + ((e && e.message) || String(e)));
  }
  var path = parsed.pathname || "";
  if ((path !== "" && path !== "/") || parsed.search || parsed.hash) {
    throw new AsyncApiError("asyncapi/bad-access-control",
      label + ": accessControl.allowOrigin must be a bare origin " +
      "(scheme://host[:port]) with no path / query / fragment; got '" + value + "'");
  }
  var port = parsed.port;
  return parsed.protocol + "//" + parsed.hostname.toLowerCase() + (port ? ":" + port : "");
}

var openapiYaml   = lazyRequire(function () { return require("../openapi-yaml"); });
var audit         = lazyRequire(function () { return require("../audit"); });

/**
 * @primitive b.middleware.asyncapiServe
 * @signature b.middleware.asyncapiServe(opts)
 * @since     0.1.0
 * @related   b.middleware.openapiServe, b.asyncapi.create
 *
 * Serves an AsyncAPI 3.0 document built via `b.asyncapi.create` at
 * configurable JSON + YAML mount points. Matches `openapiServe`
 * behaviour: GET/HEAD only, SHA3-512 ETag with conditional 304,
 * operator-controlled CORS gate, falls through on unmatched paths
 * or methods. `accessControl: "public"` (default) emits
 * `Access-Control-Allow-Origin: *`; `same-origin` omits the header;
 * `{ allowOrigin: "https://docs.example.com" }` echoes one validated
 * origin with `Vary: Origin`. Use to publish channel + operation +
 * message + schema specs for event-driven APIs (Kafka, AMQP, MQTT,
 * WebSocket).
 *
 * @opts
 *   {
 *     document:      object,    // builder from b.asyncapi.create()
 *     pathJson:      string,    // default "/asyncapi.json"
 *     pathYaml:      string,    // default "/asyncapi.yaml"
 *     pretty:        boolean,   // default false → minified
 *     cacheControl:  string,    // default "public, max-age=300"
 *     accessControl: "public"|"same-origin"|{ allowOrigin: string },
 *     audit:         boolean,   // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   var aapi = b.asyncapi.create({ info: { title: "events", version: "1.0.0" } });
 *   app.use(b.middleware.asyncapiServe({
 *     document:      aapi,
 *     pathJson:      "/asyncapi.json",
 *     pathYaml:      "/asyncapi.yaml",
 *     accessControl: "public",
 *   }));
 */
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
  // Resolve the Access-Control-Allow-Origin value once at config time.
  // "public" → "*"; an { allowOrigin } object → the canonical origin
  // (validated, throws on a bad value); "same-origin" / anything else →
  // null (no CORS header emitted).
  var allowOriginHeader = null;
  if (accessControl === "public") {
    allowOriginHeader = "*";
  } else if (accessControl && typeof accessControl === "object" &&
             typeof accessControl.allowOrigin === "string") {
    allowOriginHeader = _canonicalAllowOrigin(accessControl.allowOrigin, "asyncapiServe");
  }
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
      res.writeHead(304, { "ETag": etag, "Cache-Control": cacheControl });           // HTTP 304
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
      // A specific (non-"*") origin makes the response vary by Origin;
      // advertise it so shared caches don't serve one operator's allowed
      // origin to another's request (Fetch Standard §3.2.1).
      if (allowOriginHeader !== "*") headers["Vary"] = "Origin";
    }
    res.writeHead(200, headers);                                                     // HTTP 200
    // HEAD carries the GET headers (incl. Content-Length) with no body
    // (RFC 9110 §9.3.2).
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
