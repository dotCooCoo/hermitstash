// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * OpenAPI 3.1 / 3.2 — paths / operations + webhooks builder.
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
 *
 * `WebhooksBuilder` shares the same Operation Object normalisation but
 * keys by a free-form webhook NAME (not a URL pattern): the top-level
 * `webhooks` field is a map of named Path Item Objects describing
 * out-of-band requests the API initiates (OpenAPI 3.2 §4.8.2, "Fixed
 * Fields" — `webhooks`; carried forward unchanged from 3.1.0 §4.1).
 * Webhook keys are not URL templates, so the `/`-prefix and
 * path-template-placeholder checks are intentionally not applied.
 */

var validateOpts = require("./validate-opts");
var schemaWalk   = require("./openapi-schema-walk");
var pick         = require("./pick");
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
  // null-proto so a urlPattern keyed into _paths (operator-supplied API path)
  // can never reach Object.prototype — a "__proto__" / "constructor" path lands
  // as an own property, not a prototype mutation (prototype-polluting-assignment).
  this._paths = Object.create(null);
}

// _buildOperation — normalise a single Operation Object from operator
// opts. Shared by PathsBuilder.add and WebhooksBuilder.add. `label` is
// the caller-facing prefix used in error messages. `declaredPathParams`
// (out-param object) records every in=path parameter so the caller can
// verify path-template placeholders against it; webhooks have no URL
// template so the caller simply ignores it.
function _buildOperation(method, opts, label, declaredPathParams) {
  if (typeof method !== "string" || VALID_METHODS.indexOf(method.toLowerCase()) === -1) {
    throw new OpenApiError("openapi/bad-method",
      label + ": method must be one of " + VALID_METHODS.join(", ") +
      " - got " + JSON.stringify(method));
  }
  validateOpts(opts, [
    "summary", "description", "operationId", "tags",
    "parameters", "requestBody", "responses",
    "security", "deprecated", "servers", "externalDocs",
  ], label);

  var op = {};
  if (typeof opts.summary === "string")     op.summary = opts.summary;
  if (typeof opts.description === "string") op.description = opts.description;
  if (typeof opts.operationId === "string") op.operationId = opts.operationId;
  if (Array.isArray(opts.tags) && opts.tags.length > 0) {
    op.tags = opts.tags.map(function (t) {
      if (typeof t !== "string" || t.length === 0) {
        throw new OpenApiError("openapi/bad-tag",
          label + ": tags must be non-empty strings");
      }
      return t;
    });
  }

  // Parameters
  if (Array.isArray(opts.parameters)) {
    op.parameters = [];
    for (var i = 0; i < opts.parameters.length; i += 1) {
      var p = _normaliseParameter(opts.parameters[i], label + ": parameters[" + i + "]");
      op.parameters.push(p);
      if (p.in === "path") declaredPathParams[p.name] = true;
    }
  }

  // Request body
  if (opts.requestBody) {
    op.requestBody = _normaliseRequestBody(opts.requestBody, label + ": requestBody");
  }

  // Responses (required)
  if (!opts.responses || typeof opts.responses !== "object") {
    throw new OpenApiError("openapi/missing-responses",
      label + ": responses object is required (per OpenAPI 3.1 §4.8.5)");
  }
  op.responses = _normaliseResponses(opts.responses, label + ": responses");

  if (Array.isArray(opts.security)) op.security = opts.security.slice();
  if (opts.deprecated === true)     op.deprecated = true;
  if (Array.isArray(opts.servers))  op.servers = opts.servers.slice();
  if (opts.externalDocs)            op.externalDocs = opts.externalDocs;
  return op;
}

PathsBuilder.prototype.add = function (method, urlPattern, opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(urlPattern, "paths.add: urlPattern",
    OpenApiError, "openapi/bad-path");
  if (urlPattern.charAt(0) !== "/") {
    throw new OpenApiError("openapi/bad-path",
      "paths.add: urlPattern must start with '/' - got " +
      JSON.stringify(urlPattern));
  }

  var declaredPathParams = Object.create(null);
  var op = _buildOperation(method, opts, "paths.add", declaredPathParams);

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

  if (!this._paths[urlPattern]) this._paths[urlPattern] = Object.create(null);
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

// WebhooksBuilder — the top-level `webhooks` field is a map of named
// Path Item Objects describing requests the API initiates out-of-band
// (OpenAPI 3.2 §4.8.2 Fixed Fields → `webhooks`; unchanged from
// 3.1.0 §4.1). Keys are free-form webhook names (e.g. "newPet"), NOT
// URL templates — no `/`-prefix and no path-template-placeholder
// validation. Each named entry holds the same Operation Objects as a
// regular path item.
function WebhooksBuilder() {
  // Null-prototype map so a free-form webhook name that collides with an
  // Object.prototype member (__proto__ / constructor / prototype) becomes
  // an own property instead of mutating the prototype (CWE-1321).
  this._webhooks = Object.create(null);
}

WebhooksBuilder.prototype.add = function (name, method, opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(name, "webhook.add: name",
    OpenApiError, "openapi/bad-webhook");
  if (pick.isPoisonedKey(name)) {
    throw new OpenApiError("openapi/bad-webhook",
      "webhook.add: name must not be a reserved object key (" + JSON.stringify(name) + ")");
  }
  var declaredPathParams = Object.create(null);
  var op = _buildOperation(method, opts, "webhook.add", declaredPathParams);
  if (!this._webhooks[name]) this._webhooks[name] = {};
  if (this._webhooks[name][method.toLowerCase()]) {
    throw new OpenApiError("openapi/duplicate-operation",
      "webhook.add: duplicate operation " + method.toUpperCase() +
      " on webhook " + JSON.stringify(name));
  }
  this._webhooks[name][method.toLowerCase()] = op;
  return op;
};

WebhooksBuilder.prototype.count = function () {
  return Object.keys(this._webhooks).length;
};

WebhooksBuilder.prototype.toMap = function () {
  var sorted = Object.keys(this._webhooks).sort();
  var out = {};
  for (var i = 0; i < sorted.length; i += 1) {
    var name = sorted[i];
    var item = this._webhooks[name];
    var ordered = {};
    for (var j = 0; j < VALID_METHODS.length; j += 1) {
      var method = VALID_METHODS[j];
      if (item[method]) ordered[method] = item[method];
    }
    out[name] = ordered;
  }
  return out;
};

module.exports = {
  PathsBuilder:        PathsBuilder,
  WebhooksBuilder:     WebhooksBuilder,
  VALID_METHODS:       VALID_METHODS,
  _extractPathParams:  _extractPathParams,
  OpenApiError:        OpenApiError,
};
