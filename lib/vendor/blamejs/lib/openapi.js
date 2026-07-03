// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.openapi
 * @nav    Other
 * @title  Openapi
 *
 * @intro
 *   OpenAPI 3.1 / 3.2 emitter from declarative route declarations +
 *   schemas (composable with `b.safeSchema`); JSON / YAML output.
 *   Operators describe their public HTTP surface as an OpenAPI document
 *   the framework serves at `/openapi.json` (or any path) for
 *   downstream tooling: API consumers, Postman, code-generators,
 *   contract-test rigs.
 *
 *   The builder is FRAMEWORK-FACING: it produces a valid OpenAPI
 *   document, but the operator's hand-written contract is the source
 *   of truth — it does NOT auto-walk `b.router` routes (operators
 *   frequently want a smaller / different surface published than what
 *   the router exposes internally).
 *
 *   `3.1.0` is the default emitted version. Pass
 *   `create({ openapi: "3.2.0", ... })` to opt into OpenAPI 3.2; both
 *   3.1.x and 3.2.x parse and emit. The 3.2 additions wired here are
 *   the top-level `webhooks` map (named out-of-band Path Item Objects
 *   the API initiates — OpenAPI 3.2 §4.8.2) and the `jsonSchemaDialect`
 *   field (declares the default JSON Schema dialect for the document —
 *   OpenAPI 3.2 §4.8.1).
 *
 *   The builder fluent surface is `path()` / `webhook()` / `schema()` /
 *   `response()` / `parameter()` / `requestBody()` / `header()` /
 *   `example()` / `security.add()` / `security.require()` / `tag()` /
 *   `server()`, each returning the builder for chaining. Terminal calls
 *   are `toJson()` (JSON document with referential integrity checked
 *   — every security-scheme reference must resolve), `toJsonString()`,
 *   `toYaml()`, and `middleware(opts)` which mounts the cached
 *   document at request-time. Security-scheme builders for bearer /
 *   basic / apiKey / oauth2 / openIdConnect / mtls / dpop live on
 *   `b.openapi.security`.
 *
 * @card
 *   OpenAPI 3.1 / 3.2 emitter from declarative route declarations + schemas (composable with `b.safeSchema`); JSON / YAML output.
 */

var validateOpts          = require("./validate-opts");
var lazyRequire           = require("./lazy-require");
var schemaWalk            = require("./openapi-schema-walk");
var pathsBuilderMod       = require("./openapi-paths-builder");
var openapiSecurity       = require("./openapi-security");
var openapiYaml           = require("./openapi-yaml");
var safeJson              = require("./safe-json");
var C                     = require("./constants");
var { defineClass }       = require("./framework-error");
var audit                 = lazyRequire(function () { return require("./audit"); });

var OpenApiError = defineClass("OpenApiError", { alwaysPermanent: true });

// Default emitted version. `create({ openapi: "3.2.0" })` opts into 3.2.
// Both 3.1.x and 3.2.x are accepted by create() and parse() (OpenAPI
// 3.2 is a backward-compatible superset of 3.1).
var OPENAPI_VERSION       = "3.1.0";
var SUPPORTED_MAJOR_MINOR = ["3.1", "3.2"];

// _resolveVersion — validate an operator-supplied `opts.openapi` version
// string against the accepted major.minor set and return it; default to
// OPENAPI_VERSION when omitted. THROWS on an unsupported version
// (config-time / entry-point tier — operator catches the typo at boot).
function _resolveVersion(version, label) {
  if (version === undefined || version === null) return OPENAPI_VERSION;
  if (typeof version !== "string" || version.length === 0) {
    throw new OpenApiError("openapi/bad-version",
      label + ": openapi must be a version string (e.g. \"3.1.0\" or \"3.2.0\")");
  }
  for (var i = 0; i < SUPPORTED_MAJOR_MINOR.length; i += 1) {
    if (version.indexOf(SUPPORTED_MAJOR_MINOR[i] + ".") === 0 ||
        version === SUPPORTED_MAJOR_MINOR[i]) {
      return version;
    }
  }
  throw new OpenApiError("openapi/bad-version",
    label + ": openapi version must be one of " +
    SUPPORTED_MAJOR_MINOR.map(function (v) { return v + ".x"; }).join(" / ") +
    " — got " + JSON.stringify(version));
}

/**
 * @primitive b.openapi.create
 * @signature b.openapi.create(opts)
 * @since     0.6.30
 * @related   b.openapi.parse, b.asyncapi.create, b.safeSchema
 *
 * Build a fluent OpenAPI 3.1 / 3.2 document builder. `opts.info` is
 * required (`title` + `version`). Returns a chainable builder; terminal
 * calls are `toJson()`, `toJsonString(indent)`, `toYaml()`, and
 * `middleware(opts)`. `toJson()` cross-checks every doc-level and
 * per-operation security requirement against
 * `components.securitySchemes` and throws
 * `OpenApiError("openapi/dangling-security")` on a missing scheme.
 *
 * `3.1.0` is emitted by default. Pass `openapi: "3.2.0"` to opt into
 * OpenAPI 3.2; an unsupported version (e.g. `"4.0.0"`) throws
 * `OpenApiError("openapi/bad-version")`. `webhook(name, method, opts)`
 * registers a top-level webhook (OpenAPI 3.2 §4.8.2) and
 * `jsonSchemaDialect` declares the document's default JSON Schema
 * dialect (OpenAPI 3.2 §4.8.1) — both valid in 3.1.x and 3.2.x.
 *
 * @opts
 *   info:              { title, version, description?, contact?, license? },   // REQUIRED — title + version are non-empty strings
 *   openapi:           string,        // emitted version — "3.1.x" (default) or "3.2.x"
 *   jsonSchemaDialect: string,        // default JSON Schema dialect URI for the document
 *   servers:           array,         // [{ url, description?, variables? }, ...]
 *   externalDocs:      { url, description? },
 *   tags:              array,         // [{ name, description? }, ...] — seed; builder.tag() appends more
 *   security:          array,         // doc-level security requirements [{ schemeName: ["scope"] }, ...]
 *
 * @example
 *   var doc = b.openapi.create({
 *     openapi: "3.2.0",
 *     info:    { title: "Acme API", version: "1.0.0" },
 *     servers: [{ url: "https://api.acme.example.com" }],
 *   });
 *   doc.security.add("bearerAuth", b.openapi.security.bearer({ bearerFormat: "JWT" }));
 *   doc.path("get", "/users/{id}", {
 *     summary:    "Fetch a user",
 *     parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
 *     responses:  { "200": { description: "ok" }, "404": { description: "not found" } },
 *     security:   [{ bearerAuth: [] }],
 *   });
 *   doc.webhook("newPet", "post", {
 *     requestBody: { content: { "application/json": { schema: { type: "object" } } } },
 *     responses:   { "200": { description: "ack" } },
 *   });
 *   var json = doc.toJson();
 *   json.openapi;           // → "3.2.0"
 *   json.webhooks.newPet.post.responses["200"].description;   // → "ack"
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "info", "openapi", "jsonSchemaDialect",
    "servers", "externalDocs", "tags", "security",
  ], "openapi.create");
  if (!opts.info || typeof opts.info !== "object") {
    throw new OpenApiError("openapi/bad-info",
      "openapi.create: info object is required (title + version)");
  }
  validateOpts.requireNonEmptyString(opts.info.title,
    "openapi.create: info.title", OpenApiError, "openapi/bad-info");
  validateOpts.requireNonEmptyString(opts.info.version,
    "openapi.create: info.version", OpenApiError, "openapi/bad-info");

  var openapiVersion    = _resolveVersion(opts.openapi, "openapi.create");
  var jsonSchemaDialect = validateOpts.optionalNonEmptyString(
    opts.jsonSchemaDialect, "openapi.create: jsonSchemaDialect",
    OpenApiError, "openapi/bad-json-schema-dialect");

  var paths       = new pathsBuilderMod.PathsBuilder();
  var webhooks    = new pathsBuilderMod.WebhooksBuilder();
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

  // _checkOperationSecurity — every per-operation security requirement
  // key must resolve to a registered security scheme. `labelPrefix`
  // distinguishes path operations ("") from webhook operations
  // ("webhook ") in the error message.
  function _checkOperationSecurity(itemMap, labelPrefix) {
    for (var itemKey in itemMap) {
      if (!Object.prototype.hasOwnProperty.call(itemMap, itemKey)) continue;
      var item = itemMap[itemKey];
      for (var methodKey in item) {
        if (!Object.prototype.hasOwnProperty.call(item, methodKey)) continue;
        var op = item[methodKey];
        if (!Array.isArray(op.security)) continue;
        for (var os = 0; os < op.security.length; os += 1) {
          for (var sn in op.security[os]) {
            if (!Object.prototype.hasOwnProperty.call(op.security[os], sn)) continue;
            if (!components.securitySchemes[sn]) {
              throw new OpenApiError("openapi/dangling-security",
                "toJson: " + labelPrefix + methodKey.toUpperCase() + " " + itemKey +
                " references undefined security scheme " + JSON.stringify(sn));
            }
          }
        }
      }
    }
  }

  var builder = {
    info:         Object.assign({}, opts.info),

    path: function (method, urlPattern, pathOpts) {
      paths.add(method, urlPattern, pathOpts || {});
      return builder;
    },

    webhook: function (name, method, webhookOpts) {
      webhooks.add(name, method, webhookOpts || {});
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
        openapi: openapiVersion,
        info:    builder.info,
      };
      if (jsonSchemaDialect) doc.jsonSchemaDialect = jsonSchemaDialect;
      if (docServers.length > 0)  doc.servers = docServers.slice();
      doc.paths = paths.toMap();
      if (webhooks.count() > 0) doc.webhooks = webhooks.toMap();
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
      // Same check on per-operation security — for both `paths` and
      // `webhooks` operations (webhook operations carry `security` too).
      _checkOperationSecurity(doc.paths, "");
      if (doc.webhooks) _checkOperationSecurity(doc.webhooks, "webhook ");
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
        res.writeHead(200, {                                                                                  // HTTP 200 status
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

var PARSE_METHODS = ["get", "put", "post", "delete",
                     "options", "head", "patch", "trace"];

// _validateItemOperations — validate the Operation Objects inside a
// single Path Item (used for both `paths` entries and `webhooks`
// entries). `label` is the operator-facing prefix (a path key like
// "/x" or a webhook label like "webhook newPet"). Pushes shape errors
// into `errors`; non-method fields (parameters / summary / $ref) are
// skipped exactly as the paths loop did before this was extracted.
function _validateItemOperations(item, label, errors, securitySchemes) {
  for (var methodKey in item) {
    if (!Object.prototype.hasOwnProperty.call(item, methodKey)) continue;
    if (PARSE_METHODS.indexOf(methodKey) === -1) continue;     // allow non-method fields like 'parameters', 'summary', '$ref'
    var op = item[methodKey];
    if (!op || typeof op !== "object") {
      errors.push(methodKey.toUpperCase() + " " + label + ": operation must be an object");
      continue;
    }
    if (!op.responses || typeof op.responses !== "object" ||
        Object.keys(op.responses).length === 0) {
      errors.push(methodKey.toUpperCase() + " " + label +
                  ": responses object required (per OpenAPI 3.1 §4.8.5)");
    } else {
      for (var statusKey in op.responses) {
        if (!Object.prototype.hasOwnProperty.call(op.responses, statusKey)) continue;
        var resp = op.responses[statusKey];
        if (!resp || typeof resp !== "object") {
          errors.push(methodKey.toUpperCase() + " " + label +
                      " response " + statusKey + ": must be an object");
          continue;
        }
        if (resp["$ref"]) continue;       // $ref short-circuit
        if (typeof resp.description !== "string" || resp.description.length === 0) {
          errors.push(methodKey.toUpperCase() + " " + label +
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
          errors.push(methodKey.toUpperCase() + " " + label +
                      " parameters[" + pi + "]: path parameter " +
                      JSON.stringify(p.name) + " must have required=true");
        }
      }
    }
    // Operation-level security requirement keys must resolve to a
    // registered scheme — the builder's toJson() enforces this, so parse()
    // must too, for both path and webhook operations.
    if (securitySchemes && Array.isArray(op.security)) {
      for (var rqi = 0; rqi < op.security.length; rqi += 1) {
        var req = op.security[rqi];
        if (!req || typeof req !== "object") continue;
        for (var schemeKey in req) {
          if (!Object.prototype.hasOwnProperty.call(req, schemeKey)) continue;
          if (!securitySchemes[schemeKey]) {
            errors.push(methodKey.toUpperCase() + " " + label +
                        ": security references undefined scheme " +
                        JSON.stringify(schemeKey));
          }
        }
      }
    }
  }
}

/**
 * @primitive b.openapi.parse
 * @signature b.openapi.parse(jsonStringOrObject)
 * @since     0.6.30
 * @related   b.openapi.create
 *
 * Parse + validate an external OpenAPI 3.1 / 3.2 document. Operators
 * hand a doc that arrived from a downstream integration (consumer hand-
 * edited, contract-test fixture, third-party publish) and want the
 * framework's gate to enforce the same shape rules `toJson()`
 * enforces on builder output. Throws on invalid JSON or non-object
 * input; otherwise returns `{ doc, errors, valid }`. `errors` is an
 * array of strings — empty on a valid document. The `openapi` version
 * must be `3.1.x` or `3.2.x`. Path keys must start with `/`, every
 * operation must declare `responses` with a `description`, path
 * parameters must carry `required: true`, and doc-level security must
 * reference declared schemes. Top-level `webhooks` (OpenAPI 3.2
 * §4.8.2) are validated with the same operation rules but free-form
 * names instead of `/`-prefixed URL keys; `jsonSchemaDialect` (OpenAPI
 * 3.2 §4.8.1) must be a string when present.
 *
 * @example
 *   var result = b.openapi.parse('{"openapi":"3.2.0","info":{"title":"x","version":"1.0.0"}}');
 *   result.valid;       // → true
 *   result.errors;      // → []
 *
 *   var bad = b.openapi.parse({ openapi: "3.1.0", info: { title: "x", version: "1.0.0" }, paths: { "users": {} } });
 *   bad.valid;          // → false
 *   bad.errors[0];      // → 'path "users" must start with \'/\''
 */
function parse(jsonStringOrObject) {
  // A JSON string is parsed through safeJson (proto-pollution-key strip + depth
  // / size caps — a raw JSON.parse here kept a "__proto__" member and was
  // unbounded on an operator-supplied document); a pre-built object passes
  // through. The 16 MiB cap is generous for any real OpenAPI document.
  var doc = safeJson.parseStringOrObject(jsonStringOrObject, {
    maxBytes:   C.BYTES.mib(16),
    errorClass: OpenApiError,
    jsonCode:   "openapi/bad-json",
    inputCode:  "openapi/bad-input",
    label:      "openapi.parse",
  });
  var errors = [];
  if (typeof doc.openapi !== "string") {
    errors.push("missing or non-string `openapi` version field (must be 3.1.x or 3.2.x)");
  } else if (doc.openapi.indexOf("3.1") !== 0 && doc.openapi.indexOf("3.2") !== 0) {
    errors.push("`openapi` version must be 3.1.x or 3.2.x — got " + JSON.stringify(doc.openapi));
  }
  if (doc.jsonSchemaDialect != null && typeof doc.jsonSchemaDialect !== "string") {
    errors.push("`jsonSchemaDialect` must be a string when present (per OpenAPI 3.2 §4.8.1)");
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
  // Resolved once so operation-level security requirements on both paths
  // and webhooks can be checked against it during shape validation.
  var securitySchemes = (doc.components && doc.components.securitySchemes) || {};
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
      _validateItemOperations(pathItem, pathKey, errors, securitySchemes);
    }
  }
  // Webhooks — same operation rules as paths, but keys are free-form
  // webhook names (not `/`-prefixed URL templates), per OpenAPI 3.2
  // §4.8.2.
  if (doc.webhooks != null && typeof doc.webhooks !== "object") {
    errors.push("`webhooks` must be an object when present");
  } else if (doc.webhooks) {
    for (var webhookKey in doc.webhooks) {
      if (!Object.prototype.hasOwnProperty.call(doc.webhooks, webhookKey)) continue;
      var webhookItem = doc.webhooks[webhookKey];
      if (!webhookItem || typeof webhookItem !== "object") {
        errors.push("webhooks[" + JSON.stringify(webhookKey) + "] must be an object");
        continue;
      }
      _validateItemOperations(webhookItem, "webhook " + webhookKey, errors, securitySchemes);
    }
  }
  // Dangling security references — every requirement key must resolve
  // to a registered security scheme.
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
