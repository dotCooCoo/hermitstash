"use strict";
/**
 * b.openapi — OpenAPI 3.1 schema-document builder.
 *
 * Operators describe their public HTTP surface as an OpenAPI 3.1
 * document the framework can serve at /openapi.json (or any path of
 * their choice) for downstream tooling: API consumers, Postman, code-
 * generators, contract-testing rigs.
 *
 * The builder is FRAMEWORK-FACING: it produces a valid OpenAPI 3.1
 * document, but the operator's hand-written contract is the source of
 * truth — it does NOT auto-walk b.router routes (operators frequently
 * want a smaller / different surface published than what the router
 * exposes internally). Future patch may add `fromRouter()` once the
 * route-shape is stable.
 *
 * Public surface:
 *
 *   b.openapi.create({ info, servers, externalDocs, tags })
 *     -> builder
 *
 *   builder.path(method, urlPattern, opts)            // add operation
 *   builder.schema(name, schema)                       // reusable component schema
 *   builder.response(name, response)                   // reusable response
 *   builder.parameter(name, parameter)                 // reusable parameter
 *   builder.security.add(name, scheme)                 // add security scheme
 *   builder.security.require(requirement)              // doc-level security
 *   builder.tag({ name, description })                 // tag group
 *   builder.server({ url, description, variables })    // server URL
 *
 *   builder.toJson()        -> OpenAPI 3.1 JSON document
 *   builder.toYaml()        -> YAML serialisation (if vendored YAML present)
 *   builder.middleware(opts) -> request-time middleware that serves the doc
 *
 *   b.openapi.security.{bearer,basic,apiKey,oauth2,openIdConnect,mtls,dpop}
 *     -> security-scheme builders (delegated from openapi-security.js)
 *
 *   b.openapi.schemaWalk(input)
 *     -> safeSchema -> JSON Schema utility (delegated)
 */

var validateOpts          = require("./validate-opts");
var lazyRequire           = require("./lazy-require");
var schemaWalk            = require("./openapi-schema-walk");
var pathsBuilderMod       = require("./openapi-paths-builder");
var openapiSecurity       = require("./openapi-security");
var openapiYaml           = require("./openapi-yaml");
var { defineClass }       = require("./framework-error");
var audit                 = lazyRequire(function () { return require("./audit"); });

var OpenApiError = defineClass("OpenApiError", { alwaysPermanent: true });

var OPENAPI_VERSION = "3.1.0";

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "info", "servers", "externalDocs", "tags", "security",
  ], "openapi.create");
  if (!opts.info || typeof opts.info !== "object") {
    throw new OpenApiError("openapi/bad-info",
      "openapi.create: info object is required (title + version)");
  }
  validateOpts.requireNonEmptyString(opts.info.title,
    "openapi.create: info.title", OpenApiError, "openapi/bad-info");
  validateOpts.requireNonEmptyString(opts.info.version,
    "openapi.create: info.version", OpenApiError, "openapi/bad-info");

  var paths       = new pathsBuilderMod.PathsBuilder();
  var components  = {
    schemas:         {},
    responses:       {},
    parameters:      {},
    securitySchemes: {},
    requestBodies:   {},
    headers:         {},
    examples:        {},
  };
  var docTags       = Array.isArray(opts.tags) ? opts.tags.slice() : [];
  var docServers    = Array.isArray(opts.servers) ? opts.servers.slice() : [];
  var docSecurity   = Array.isArray(opts.security) ? opts.security.slice() : [];
  var externalDocs  = opts.externalDocs || null;

  function _validateServerEntry(entry, label) {
    if (!entry || typeof entry !== "object") {
      throw new OpenApiError("openapi/bad-server",
        label + ": server must be an object");
    }
    validateOpts.requireNonEmptyString(entry.url,
      label + ": url", OpenApiError, "openapi/bad-server");
  }
  for (var s = 0; s < docServers.length; s += 1) {
    _validateServerEntry(docServers[s], "openapi.create: servers[" + s + "]");
  }

  var builder = {
    info:         Object.assign({}, opts.info),

    path: function (method, urlPattern, pathOpts) {
      paths.add(method, urlPattern, pathOpts || {});
      return builder;
    },

    schema: function (name, schemaSpec) {
      validateOpts.requireNonEmptyString(name, "schema: name",
        OpenApiError, "openapi/bad-component");
      if (Object.prototype.hasOwnProperty.call(components.schemas, name)) {
        throw new OpenApiError("openapi/duplicate-component",
          "schema: component schemas." + name + " already registered");
      }
      components.schemas[name] = schemaWalk.walk(schemaSpec);
      return builder;
    },

    response: function (name, responseSpec) {
      validateOpts.requireNonEmptyString(name, "response: name",
        OpenApiError, "openapi/bad-component");
      if (!responseSpec || typeof responseSpec !== "object") {
        throw new OpenApiError("openapi/bad-response",
          "response: responseSpec must be an object");
      }
      if (typeof responseSpec.description !== "string") {
        throw new OpenApiError("openapi/missing-response-description",
          "response: description is required");
      }
      components.responses[name] = responseSpec;
      return builder;
    },

    parameter: function (name, paramSpec) {
      validateOpts.requireNonEmptyString(name, "parameter: name",
        OpenApiError, "openapi/bad-component");
      if (!paramSpec || typeof paramSpec !== "object") {
        throw new OpenApiError("openapi/bad-parameter",
          "parameter: paramSpec must be an object");
      }
      var p = Object.assign({}, paramSpec);
      if (p.schema != null) p.schema = schemaWalk.walk(p.schema);
      components.parameters[name] = p;
      return builder;
    },

    requestBody: function (name, bodySpec) {
      validateOpts.requireNonEmptyString(name, "requestBody: name",
        OpenApiError, "openapi/bad-component");
      if (!bodySpec || typeof bodySpec !== "object") {
        throw new OpenApiError("openapi/bad-request-body",
          "requestBody: bodySpec must be an object");
      }
      components.requestBodies[name] = bodySpec;
      return builder;
    },

    header: function (name, headerSpec) {
      validateOpts.requireNonEmptyString(name, "header: name",
        OpenApiError, "openapi/bad-component");
      components.headers[name] = headerSpec;
      return builder;
    },

    example: function (name, exampleSpec) {
      validateOpts.requireNonEmptyString(name, "example: name",
        OpenApiError, "openapi/bad-component");
      components.examples[name] = exampleSpec;
      return builder;
    },

    security: {
      add: function (name, scheme) {
        validateOpts.requireNonEmptyString(name, "security.add: name",
          OpenApiError, "openapi/bad-security");
        if (!scheme || typeof scheme !== "object" || typeof scheme.type !== "string") {
          throw new OpenApiError("openapi/bad-security",
            "security.add: scheme must be a securityScheme object with a type");
        }
        components.securitySchemes[name] = scheme;
        return builder;
      },
      require: function (requirement) {
        if (!requirement || typeof requirement !== "object") {
          throw new OpenApiError("openapi/bad-security",
            "security.require: requirement must be an object like { schemeName: ['scope'] }");
        }
        docSecurity.push(requirement);
        return builder;
      },
    },

    tag: function (tagSpec) {
      if (!tagSpec || typeof tagSpec !== "object" ||
          typeof tagSpec.name !== "string" || tagSpec.name.length === 0) {
        throw new OpenApiError("openapi/bad-tag",
          "tag: tagSpec.name is required");
      }
      docTags.push(tagSpec);
      return builder;
    },

    server: function (serverSpec) {
      _validateServerEntry(serverSpec, "server");
      docServers.push(serverSpec);
      return builder;
    },

    toJson: function () {
      var doc = {
        openapi: OPENAPI_VERSION,
        info:    builder.info,
      };
      if (docServers.length > 0)  doc.servers = docServers.slice();
      doc.paths = paths.toMap();
      var anyComponent = false;
      var componentsOut = {};
      var keys = ["schemas", "responses", "parameters", "requestBodies",
                  "headers", "examples", "securitySchemes"];
      for (var k = 0; k < keys.length; k += 1) {
        var key = keys[k];
        if (Object.keys(components[key]).length > 0) {
          componentsOut[key] = components[key];
          anyComponent = true;
        }
      }
      if (anyComponent) doc.components = componentsOut;
      if (docSecurity.length > 0) doc.security = docSecurity.slice();
      if (docTags.length > 0)     doc.tags     = docTags.slice();
      if (externalDocs)           doc.externalDocs = externalDocs;
      // Validate security references — every requirement key must be a
      // registered security scheme.
      for (var r = 0; r < docSecurity.length; r += 1) {
        for (var schemeName in docSecurity[r]) {
          if (!Object.prototype.hasOwnProperty.call(docSecurity[r], schemeName)) continue;
          if (!components.securitySchemes[schemeName]) {
            throw new OpenApiError("openapi/dangling-security",
              "toJson: doc-level security references undefined scheme " +
              JSON.stringify(schemeName));
          }
        }
      }
      // Same check on per-operation security.
      for (var pathKey in doc.paths) {
        if (!Object.prototype.hasOwnProperty.call(doc.paths, pathKey)) continue;
        var pathItem = doc.paths[pathKey];
        for (var methodKey in pathItem) {
          if (!Object.prototype.hasOwnProperty.call(pathItem, methodKey)) continue;
          var op = pathItem[methodKey];
          if (Array.isArray(op.security)) {
            for (var os = 0; os < op.security.length; os += 1) {
              for (var sn in op.security[os]) {
                if (!Object.prototype.hasOwnProperty.call(op.security[os], sn)) continue;
                if (!components.securitySchemes[sn]) {
                  throw new OpenApiError("openapi/dangling-security",
                    "toJson: " + methodKey.toUpperCase() + " " + pathKey +
                    " references undefined security scheme " + JSON.stringify(sn));
                }
              }
            }
          }
        }
      }
      try {
        audit().safeEmit({
          action:   "openapi.document.built",
          outcome:  "success",
          actor:    null,
          metadata: {
            title:           builder.info.title,
            version:         builder.info.version,
            pathCount:       Object.keys(doc.paths).length,
            schemaCount:     Object.keys(components.schemas).length,
            securityCount:   Object.keys(components.securitySchemes).length,
          },
        });
      } catch (_e) { /* drop-silent */ }
      return doc;
    },

    toJsonString: function (indent) {
      return JSON.stringify(builder.toJson(), null, indent || 2);
    },

    toYaml: function () {
      return openapiYaml.toYaml(builder.toJson());
    },

    middleware: function (mwOpts) {
      mwOpts = mwOpts || {};
      validateOpts(mwOpts, ["pretty", "cacheControl"], "openapi.builder.middleware");
      var pretty = mwOpts.pretty === true ? 2 : 0;
      var cacheControl = (typeof mwOpts.cacheControl === "string" && mwOpts.cacheControl.length > 0)
        ? mwOpts.cacheControl
        : "public, max-age=300";
      // Memoize the JSON between calls; re-build if the operator
      // calls forceRebuild().
      var cached = null;
      var cachedString = null;
      function _rebuild() {
        cached = builder.toJson();
        cachedString = JSON.stringify(cached, null, pretty);
      }
      _rebuild();
      var mw = function (req, res, next) {
        if (typeof res.writeHead !== "function") return next();
        var body = cachedString;
        res.writeHead(200, {                                                                                  // allow:raw-byte-literal — HTTP 200 status
          "Content-Type":   "application/json; charset=utf-8",
          "Content-Length": Buffer.byteLength(body),
          "Cache-Control":  cacheControl,
        });
        res.end(body);
      };
      mw.forceRebuild = _rebuild;
      return mw;
    },
  };

  return builder;
}

// Parse + validate an external OpenAPI 3.1 JSON document. Operators
// hand a doc that arrived from a downstream integration (consumer
// hand-edited, contract-test fixture, third-party publish) and want
// the framework's gate to enforce the same shape rules `toJson` does
// on builder output.
//
// Returns `{ doc, errors[] }`. `doc` is the parsed object (whether
// valid or not, so the operator can inspect what they got);
// `errors` is an array of strings — empty on a valid document.
//
// Throws (config-time entry-point) on invalid JSON / wrong type.
function parse(jsonStringOrObject) {
  var doc;
  if (typeof jsonStringOrObject === "string") {
    try { doc = JSON.parse(jsonStringOrObject); }                                       // allow:bare-json-parse — operator-supplied OpenAPI doc; size-bounded by caller
    catch (e) {
      throw new OpenApiError("openapi/bad-json",
        "openapi.parse: invalid JSON — " + e.message);
    }
  } else if (jsonStringOrObject != null && typeof jsonStringOrObject === "object") {
    doc = jsonStringOrObject;
  } else {
    throw new OpenApiError("openapi/bad-input",
      "openapi.parse: input must be a JSON string or a plain object");
  }
  var errors = [];
  if (typeof doc.openapi !== "string") {
    errors.push("missing or non-string `openapi` version field (must be 3.1.x)");
  } else if (doc.openapi.indexOf("3.1") !== 0) {
    errors.push("`openapi` version must be 3.1.x — got " + JSON.stringify(doc.openapi));
  }
  if (!doc.info || typeof doc.info !== "object") {
    errors.push("missing or non-object `info`");
  } else {
    if (typeof doc.info.title !== "string" || doc.info.title.length === 0) {
      errors.push("info.title must be a non-empty string");
    }
    if (typeof doc.info.version !== "string" || doc.info.version.length === 0) {
      errors.push("info.version must be a non-empty string");
    }
  }
  if (doc.paths != null && typeof doc.paths !== "object") {
    errors.push("`paths` must be an object when present");
  } else if (doc.paths) {
    for (var pathKey in doc.paths) {
      if (!Object.prototype.hasOwnProperty.call(doc.paths, pathKey)) continue;
      if (pathKey.charAt(0) !== "/") {
        errors.push("path " + JSON.stringify(pathKey) + " must start with '/'");
      }
      var pathItem = doc.paths[pathKey];
      if (!pathItem || typeof pathItem !== "object") {
        errors.push("paths[" + JSON.stringify(pathKey) + "] must be an object");
        continue;
      }
      var validMethods = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];
      for (var methodKey in pathItem) {
        if (!Object.prototype.hasOwnProperty.call(pathItem, methodKey)) continue;
        if (validMethods.indexOf(methodKey) === -1) continue;       // allow non-method fields like 'parameters', 'summary', '$ref'
        var op = pathItem[methodKey];
        if (!op || typeof op !== "object") {
          errors.push(methodKey.toUpperCase() + " " + pathKey + ": operation must be an object");
          continue;
        }
        if (!op.responses || typeof op.responses !== "object" ||
            Object.keys(op.responses).length === 0) {
          errors.push(methodKey.toUpperCase() + " " + pathKey +
                      ": responses object required (per OpenAPI 3.1 §4.8.5)");
        } else {
          for (var statusKey in op.responses) {
            if (!Object.prototype.hasOwnProperty.call(op.responses, statusKey)) continue;
            var resp = op.responses[statusKey];
            if (!resp || typeof resp !== "object") {
              errors.push(methodKey.toUpperCase() + " " + pathKey +
                          " response " + statusKey + ": must be an object");
              continue;
            }
            if (resp["$ref"]) continue;       // $ref short-circuit
            if (typeof resp.description !== "string" || resp.description.length === 0) {
              errors.push(methodKey.toUpperCase() + " " + pathKey +
                          " response " + statusKey +
                          ": description is required (per OpenAPI 3.1 §4.8.16)");
            }
          }
        }
        if (Array.isArray(op.parameters)) {
          for (var pi = 0; pi < op.parameters.length; pi += 1) {
            var p = op.parameters[pi];
            if (!p || typeof p !== "object") continue;
            if (p["$ref"]) continue;
            if (p.in === "path" && p.required !== true) {
              errors.push(methodKey.toUpperCase() + " " + pathKey +
                          " parameters[" + pi + "]: path parameter " +
                          JSON.stringify(p.name) + " must have required=true");
            }
          }
        }
      }
    }
  }
  // Dangling security references — every requirement key must resolve
  // to a registered security scheme.
  var securitySchemes = (doc.components && doc.components.securitySchemes) || {};
  if (Array.isArray(doc.security)) {
    for (var s = 0; s < doc.security.length; s += 1) {
      for (var schemeName in doc.security[s]) {
        if (!Object.prototype.hasOwnProperty.call(doc.security[s], schemeName)) continue;
        if (!securitySchemes[schemeName]) {
          errors.push("doc-level security references undefined scheme " +
                      JSON.stringify(schemeName));
        }
      }
    }
  }
  return { doc: doc, errors: errors, valid: errors.length === 0 };
}

module.exports = {
  create:      create,
  parse:       parse,
  schemaWalk:  schemaWalk.walk,
  security:    openapiSecurity,
  toYaml:      openapiYaml.toYaml,
  VERSION:     OPENAPI_VERSION,
  OpenApiError: OpenApiError,
};
