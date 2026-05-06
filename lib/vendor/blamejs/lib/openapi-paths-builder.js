"use strict";
/**
 * OpenAPI 3.1 — paths / operations builder.
 *
 * Internal to lib/openapi.js. Holds the per-path operation table
 * (method to operationObject) and produces the final `paths` map used
 * by the document builder.
 *
 * Path keys MUST start with `/` per OpenAPI 3.1 §4.8. Path templates
 * use `{name}` placeholders that bind to declared `parameters` of
 * `in: path`. The builder validates that every `{name}` placeholder
 * has a matching declared parameter at build-time.
 *
 * Operation methods accepted: get / put / post / delete / options /
 * head / patch / trace (RFC 9110 + OpenAPI 3.1 §4.8.5).
 */

var validateOpts = require("./validate-opts");
var schemaWalk   = require("./openapi-schema-walk");
var { defineClass } = require("./framework-error");
var OpenApiError = defineClass("OpenApiError", { alwaysPermanent: true });

var VALID_METHODS = ["get", "put", "post", "delete",
                     "options", "head", "patch", "trace"];

// Path-template parameter extraction — each `{name}` is a path param.
function _extractPathParams(pathTemplate) {
  var out = [];
  var pattern = /\{([a-zA-Z_][a-zA-Z0-9_-]*)\}/g;
  var matched = pattern.exec(pathTemplate);
  while (matched !== null) {
    out.push(matched[1]);
    matched = pattern.exec(pathTemplate);
  }
  return out;
}

function PathsBuilder() {
  this._paths = {};
}

PathsBuilder.prototype.add = function (method, urlPattern, opts) {
  opts = opts || {};
  if (typeof method !== "string" || VALID_METHODS.indexOf(method.toLowerCase()) === -1) {
    throw new OpenApiError("openapi/bad-method",
      "paths.add: method must be one of " + VALID_METHODS.join(", ") +
      " - got " + JSON.stringify(method));
  }
  validateOpts.requireNonEmptyString(urlPattern, "paths.add: urlPattern",
    OpenApiError, "openapi/bad-path");
  if (urlPattern.charAt(0) !== "/") {
    throw new OpenApiError("openapi/bad-path",
      "paths.add: urlPattern must start with '/' - got " +
      JSON.stringify(urlPattern));
  }
  validateOpts(opts, [
    "summary", "description", "operationId", "tags",
    "parameters", "requestBody", "responses",
    "security", "deprecated", "servers", "externalDocs",
  ], "paths.add");

  var op = {};
  if (typeof opts.summary === "string")     op.summary = opts.summary;
  if (typeof opts.description === "string") op.description = opts.description;
  if (typeof opts.operationId === "string") op.operationId = opts.operationId;
  if (Array.isArray(opts.tags) && opts.tags.length > 0) {
    op.tags = opts.tags.map(function (t) {
      if (typeof t !== "string" || t.length === 0) {
        throw new OpenApiError("openapi/bad-tag",
          "paths.add: tags must be non-empty strings");
      }
      return t;
    });
  }

  // Parameters
  var declaredPathParams = Object.create(null);
  if (Array.isArray(opts.parameters)) {
    op.parameters = [];
    for (var i = 0; i < opts.parameters.length; i += 1) {
      var p = _normaliseParameter(opts.parameters[i], "paths.add: parameters[" + i + "]");
      op.parameters.push(p);
      if (p.in === "path") declaredPathParams[p.name] = true;
    }
  }
  // Verify every {placeholder} in path is declared.
  var placeholders = _extractPathParams(urlPattern);
  for (var j = 0; j < placeholders.length; j += 1) {
    if (!declaredPathParams[placeholders[j]]) {
      throw new OpenApiError("openapi/missing-path-param",
        "paths.add: path template " + JSON.stringify(urlPattern) +
        " references {" + placeholders[j] +
        "} but no parameter with in=path name=" + JSON.stringify(placeholders[j]) +
        " was declared");
    }
  }

  // Request body
  if (opts.requestBody) {
    op.requestBody = _normaliseRequestBody(opts.requestBody, "paths.add: requestBody");
  }

  // Responses (required)
  if (!opts.responses || typeof opts.responses !== "object") {
    throw new OpenApiError("openapi/missing-responses",
      "paths.add: responses object is required (per OpenAPI 3.1 §4.8.5)");
  }
  op.responses = _normaliseResponses(opts.responses, "paths.add: responses");

  if (Array.isArray(opts.security)) op.security = opts.security.slice();
  if (opts.deprecated === true)     op.deprecated = true;
  if (Array.isArray(opts.servers))  op.servers = opts.servers.slice();
  if (opts.externalDocs)            op.externalDocs = opts.externalDocs;

  if (!this._paths[urlPattern]) this._paths[urlPattern] = {};
  if (this._paths[urlPattern][method.toLowerCase()]) {
    throw new OpenApiError("openapi/duplicate-operation",
      "paths.add: duplicate operation " + method.toUpperCase() + " " + urlPattern);
  }
  this._paths[urlPattern][method.toLowerCase()] = op;
  return op;
};

function _normaliseParameter(input, label) {
  if (!input || typeof input !== "object") {
    throw new OpenApiError("openapi/bad-parameter",
      label + ": parameter must be an object");
  }
  validateOpts.requireNonEmptyString(input.name, label + ": name",
    OpenApiError, "openapi/bad-parameter");
  var validIn = ["path", "query", "header", "cookie"];
  if (validIn.indexOf(input.in) === -1) {
    throw new OpenApiError("openapi/bad-parameter",
      label + ": in must be one of " + validIn.join(", ") +
      " - got " + JSON.stringify(input.in));
  }
  if (input.in === "path" && input.required !== true) {
    throw new OpenApiError("openapi/bad-parameter",
      label + ": path parameter " + JSON.stringify(input.name) +
      " must have required=true (per OpenAPI 3.1 §4.8.10)");
  }
  var p = {
    name: input.name,
    in:   input.in,
  };
  if (typeof input.description === "string") p.description = input.description;
  if (input.required === true) p.required = true;
  if (input.deprecated === true) p.deprecated = true;
  if (input.allowEmptyValue === true) p.allowEmptyValue = true;
  if (input.schema != null) {
    p.schema = schemaWalk.walk(input.schema);
  }
  if (input.example != null) p.example = input.example;
  return p;
}

function _normaliseRequestBody(input, label) {
  if (!input || typeof input !== "object") {
    throw new OpenApiError("openapi/bad-request-body",
      label + ": requestBody must be an object");
  }
  if (!input.content || typeof input.content !== "object") {
    throw new OpenApiError("openapi/bad-request-body",
      label + ": content map required (e.g. { 'application/json': { schema: ... } })");
  }
  var out = { content: {} };
  if (typeof input.description === "string") out.description = input.description;
  if (input.required === true) out.required = true;
  for (var ct in input.content) {
    if (!Object.prototype.hasOwnProperty.call(input.content, ct)) continue;
    var entry = input.content[ct];
    if (!entry || typeof entry !== "object") {
      throw new OpenApiError("openapi/bad-request-body",
        label + ": content[" + JSON.stringify(ct) + "] must be an object");
    }
    var ce = {};
    if (entry.schema != null) ce.schema = schemaWalk.walk(entry.schema);
    if (entry.example != null) ce.example = entry.example;
    if (entry.examples != null) ce.examples = entry.examples;
    if (entry.encoding != null) ce.encoding = entry.encoding;
    out.content[ct] = ce;
  }
  return out;
}

function _normaliseResponses(input, label) {
  var out = {};
  var statusKeys = Object.keys(input);
  if (statusKeys.length === 0) {
    throw new OpenApiError("openapi/missing-responses",
      label + ": at least one response required");
  }
  for (var i = 0; i < statusKeys.length; i += 1) {
    var status = statusKeys[i];
    var resp = input[status];
    if (!resp || typeof resp !== "object") {
      throw new OpenApiError("openapi/bad-response",
        label + "[" + status + "]: response must be an object");
    }
    var r = {};
    if (typeof resp.description === "string") {
      r.description = resp.description;
    } else {
      throw new OpenApiError("openapi/missing-response-description",
        label + "[" + status + "]: description is required (per OpenAPI 3.1 §4.8.16)");
    }
    if (resp.headers != null) r.headers = resp.headers;
    if (resp.content != null) {
      r.content = {};
      for (var ct in resp.content) {
        if (!Object.prototype.hasOwnProperty.call(resp.content, ct)) continue;
        var entry = resp.content[ct];
        if (!entry || typeof entry !== "object") continue;
        var ce = {};
        if (entry.schema != null) ce.schema = schemaWalk.walk(entry.schema);
        if (entry.example != null) ce.example = entry.example;
        if (entry.examples != null) ce.examples = entry.examples;
        r.content[ct] = ce;
      }
    }
    if (resp.links != null) r.links = resp.links;
    out[status] = r;
  }
  return out;
}

PathsBuilder.prototype.toMap = function () {
  var sorted = Object.keys(this._paths).sort();
  var out = {};
  for (var i = 0; i < sorted.length; i += 1) {
    var pathKey = sorted[i];
    var pathItem = this._paths[pathKey];
    var ordered = {};
    for (var j = 0; j < VALID_METHODS.length; j += 1) {
      var method = VALID_METHODS[j];
      if (pathItem[method]) ordered[method] = pathItem[method];
    }
    out[pathKey] = ordered;
  }
  return out;
};

module.exports = {
  PathsBuilder:        PathsBuilder,
  VALID_METHODS:       VALID_METHODS,
  _extractPathParams:  _extractPathParams,
  OpenApiError:        OpenApiError,
};
