"use strict";
/**
 * @module b.asyncapi
 * @nav    Other
 * @title  Asyncapi
 *
 * @intro
 *   AsyncAPI 3.0 emitter for pubsub / WebSocket / SSE channels;
 *   complements `b.openapi`. Operators describe their pubsub /
 *   websocket / kafka / mqtt surfaces as a single document the
 *   framework serves at `/asyncapi.json` (or `.yaml`) for downstream
 *   tooling.
 *
 *   The builder is FRAMEWORK-FACING: it produces a valid AsyncAPI 3.0
 *   document, but the operator's hand-written contract is the source
 *   of truth — it does NOT auto-walk `b.pubsub` topics or
 *   `b.websocketChannels` subscriptions (operators frequently want a
 *   smaller / different surface published than what is in-process).
 *
 *   Builder fluent surface: `channel(id, opts)` registers a channel,
 *   `operation(id, opts)` registers a send/receive operation that
 *   `$ref`s an already-registered channel (operations referencing
 *   undeclared channels throw `asyncapi/dangling-channel`),
 *   `schema()` / `message()` / `parameter()` / `correlationId()` /
 *   `security.add()` / `security.require()` / `tag()` / `server()`
 *   register components. Terminal calls are `toJson()` /
 *   `toJsonString(indent)` / `toYaml()`. Typed binding builders for
 *   websockets / kafka / amqp / mqtt / http live on
 *   `b.asyncapi.bindings`; reusable trait builders on
 *   `b.asyncapi.traits`.
 *
 * @card
 *   AsyncAPI 3.0 emitter for pubsub / WebSocket / SSE channels; complements `b.openapi`.
 */

var validateOpts        = require("./validate-opts");
var lazyRequire         = require("./lazy-require");
var schemaWalk          = require("./openapi-schema-walk");
var openapiSecurity     = require("./openapi-security");
var openapiYaml         = require("./openapi-yaml");
var bindingsMod         = require("./asyncapi-bindings");
var traitsMod           = require("./asyncapi-traits");
var safeJson            = require("./safe-json");
var C                   = require("./constants");
var { defineClass }     = require("./framework-error");
var AsyncApiError = defineClass("AsyncApiError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });

var ASYNCAPI_VERSION = "3.0.0";

var VALID_OPERATION_ACTIONS = ["send", "receive"];

/**
 * @primitive b.asyncapi.create
 * @signature b.asyncapi.create(opts)
 * @since     0.6.30
 * @related   b.asyncapi.parse, b.openapi.create
 *
 * Build a fluent AsyncAPI 3.0 document builder. `opts.info` is
 * required (`title` + `version`). `opts.servers` is a map keyed by
 * server id, each entry carrying `host` + `protocol`. Returns a
 * chainable builder; terminal calls are `toJson()`,
 * `toJsonString(indent)`, and `toYaml()`. `toJson()` cross-checks
 * every doc-level and per-operation security requirement against
 * `components.securitySchemes` and throws
 * `AsyncApiError("asyncapi/dangling-security")` on a missing scheme.
 *
 * @opts
 *   info:               { title, version, description?, contact?, license? },   // REQUIRED — title + version are non-empty strings
 *   servers:            { serverId: { host, protocol, description?, ... } },    // map keyed by id; each entry needs host + protocol
 *   defaultContentType: string,                  // defaults to "application/json"
 *   security:           array,                   // doc-level security requirements [{ schemeName: ["scope"] }, ...]
 *   externalDocs:       { url, description? },
 *   tags:               array,                   // [{ name, description? }, ...] — seed; builder.tag() appends more
 *   id:                 string,                  // optional document identifier (e.g. "urn:com:acme:events")
 *
 * @example
 *   var aapi = b.asyncapi.create({
 *     info:    { title: "Acme Events", version: "1.0.0" },
 *     servers: { production: { host: "broker.acme.example.com:9092", protocol: "kafka" } },
 *   });
 *   aapi.channel("orders.created", {
 *     address:  "orders.created",
 *     messages: { OrderCreated: { payload: { type: "object", properties: { id: { type: "string" } }, required: ["id"] }, contentType: "application/json" } },
 *     bindings: { kafka: b.asyncapi.bindings.kafka({ topic: "orders.created", partitions: 4 }) },
 *   });
 *   aapi.operation("publishOrderCreated", {
 *     action:  "send",
 *     channel: "orders.created",
 *     summary: "Publish an order-created event",
 *   });
 *   var doc = aapi.toJson();
 *   doc.asyncapi;                                    // → "3.0.0"
 *   doc.operations.publishOrderCreated.action;       // → "send"
 *   doc.operations.publishOrderCreated.channel.$ref; // → "#/channels/orders.created"
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "info", "servers", "defaultContentType", "security",
    "externalDocs", "tags", "id",
  ], "asyncapi.create");
  if (!opts.info || typeof opts.info !== "object") {
    throw new AsyncApiError("asyncapi/bad-info",
      "create: info object is required (title + version)");
  }
  validateOpts.requireNonEmptyString(opts.info.title,
    "create: info.title", AsyncApiError, "asyncapi/bad-info");
  validateOpts.requireNonEmptyString(opts.info.version,
    "create: info.version", AsyncApiError, "asyncapi/bad-info");

  var info = Object.assign({}, opts.info);
  var servers   = _validateServers(opts.servers);
  var channels  = {};
  var operations = {};
  var components = {
    schemas:         {},
    messages:        {},
    parameters:      {},
    securitySchemes: {},
    serverVariables: {},
    correlationIds:  {},
    operationTraits: {},
    messageTraits:   {},
    replies:         {},
    replyAddresses:  {},
  };
  var docTags     = Array.isArray(opts.tags) ? opts.tags.slice() : [];
  var docSecurity = Array.isArray(opts.security) ? opts.security.slice() : [];
  var defaultContentType = (typeof opts.defaultContentType === "string" && opts.defaultContentType.length > 0)
    ? opts.defaultContentType : "application/json";
  var externalDocs = opts.externalDocs || null;
  var docId        = opts.id || null;

  function _addChannel(channelId, channelOpts) {
    validateOpts.requireNonEmptyString(channelId, "channel: channelId",
      AsyncApiError, "asyncapi/bad-channel");
    if (Object.prototype.hasOwnProperty.call(channels, channelId)) {
      throw new AsyncApiError("asyncapi/duplicate-channel",
        "channel: " + channelId + " already registered");
    }
    channelOpts = channelOpts || {};
    validateOpts(channelOpts, [
      "address", "messages", "title", "summary", "description",
      "servers", "parameters", "tags", "bindings", "externalDocs",
    ], "channel");
    var ch = {};
    if (channelOpts.address)     ch.address = channelOpts.address;
    if (channelOpts.title)       ch.title = channelOpts.title;
    if (channelOpts.summary)     ch.summary = channelOpts.summary;
    if (channelOpts.description) ch.description = channelOpts.description;
    if (Array.isArray(channelOpts.servers)) ch.servers = channelOpts.servers.slice();
    if (channelOpts.bindings)    ch.bindings = channelOpts.bindings;
    if (channelOpts.externalDocs) ch.externalDocs = channelOpts.externalDocs;
    if (Array.isArray(channelOpts.tags)) ch.tags = channelOpts.tags.slice();
    if (channelOpts.parameters && typeof channelOpts.parameters === "object") {
      ch.parameters = {};
      for (var pn in channelOpts.parameters) {
        if (!Object.prototype.hasOwnProperty.call(channelOpts.parameters, pn)) continue;
        ch.parameters[pn] = channelOpts.parameters[pn];
      }
    }
    if (channelOpts.messages && typeof channelOpts.messages === "object") {
      ch.messages = {};
      for (var mn in channelOpts.messages) {
        if (!Object.prototype.hasOwnProperty.call(channelOpts.messages, mn)) continue;
        ch.messages[mn] = _normaliseMessage(channelOpts.messages[mn],
          "channel " + channelId + ".messages." + mn);
      }
    }
    channels[channelId] = ch;
    return ch;
  }

  function _addOperation(operationId, opOpts) {
    validateOpts.requireNonEmptyString(operationId, "operation: operationId",
      AsyncApiError, "asyncapi/bad-operation");
    if (Object.prototype.hasOwnProperty.call(operations, operationId)) {
      throw new AsyncApiError("asyncapi/duplicate-operation",
        "operation: " + operationId + " already registered");
    }
    opOpts = opOpts || {};
    validateOpts(opOpts, [
      "action", "channel", "messages", "summary", "description",
      "tags", "bindings", "security", "externalDocs", "reply",
    ], "operation");
    if (VALID_OPERATION_ACTIONS.indexOf(opOpts.action) === -1) {
      throw new AsyncApiError("asyncapi/bad-operation",
        "operation: action must be 'send' or 'receive' - got " +
        JSON.stringify(opOpts.action));
    }
    validateOpts.requireNonEmptyString(opOpts.channel, "operation: channel",
      AsyncApiError, "asyncapi/bad-operation");
    if (!Object.prototype.hasOwnProperty.call(channels, opOpts.channel)) {
      throw new AsyncApiError("asyncapi/dangling-channel",
        "operation " + operationId + ": channel " + JSON.stringify(opOpts.channel) +
        " is not registered (declare it via builder.channel() first)");
    }
    var op = {
      action:  opOpts.action,
      channel: { "$ref": "#/channels/" + opOpts.channel },
    };
    if (opOpts.summary)      op.summary = opOpts.summary;
    if (opOpts.description)  op.description = opOpts.description;
    if (Array.isArray(opOpts.tags)) op.tags = opOpts.tags.slice();
    if (opOpts.bindings)     op.bindings = opOpts.bindings;
    if (Array.isArray(opOpts.security)) op.security = opOpts.security.slice();
    if (opOpts.externalDocs) op.externalDocs = opOpts.externalDocs;
    if (opOpts.reply)        op.reply = opOpts.reply;
    if (Array.isArray(opOpts.messages) && opOpts.messages.length > 0) {
      op.messages = opOpts.messages.map(function (m, idx) {
        if (typeof m === "string") {
          return { "$ref": "#/channels/" + opOpts.channel + "/messages/" + m };
        }
        if (m && typeof m === "object" && typeof m["$ref"] === "string") {
          return { "$ref": m["$ref"] };
        }
        throw new AsyncApiError("asyncapi/bad-operation",
          "operation " + operationId + ".messages[" + idx +
          "]: must be a message name string or an object with $ref");
      });
    }
    operations[operationId] = op;
    return op;
  }

  function _normaliseMessage(input, label) {
    if (!input || typeof input !== "object") {
      throw new AsyncApiError("asyncapi/bad-message",
        label + ": message must be an object");
    }
    var m = {};
    if (input.name)         m.name = input.name;
    if (input.title)        m.title = input.title;
    if (input.summary)      m.summary = input.summary;
    if (input.description)  m.description = input.description;
    if (input.contentType)  m.contentType = input.contentType;
    if (input.headers != null) m.headers = schemaWalk.walk(input.headers);
    if (input.payload != null) m.payload = schemaWalk.walk(input.payload);
    if (input.correlationId) m.correlationId = input.correlationId;
    if (input.bindings)     m.bindings = input.bindings;
    if (input.tags)         m.tags = input.tags;
    if (Array.isArray(input.examples)) m.examples = input.examples.slice();
    if (input.traits)       m.traits = input.traits;
    if (input.externalDocs) m.externalDocs = input.externalDocs;
    return m;
  }

  return {
    info: info,
    asyncapi: ASYNCAPI_VERSION,

    channel: function (id, channelOpts) { _addChannel(id, channelOpts); return this; },
    operation: function (id, opOpts)    { _addOperation(id, opOpts); return this; },

    schema: function (name, schemaSpec) {
      validateOpts.requireNonEmptyString(name, "schema: name",
        AsyncApiError, "asyncapi/bad-component");
      if (Object.prototype.hasOwnProperty.call(components.schemas, name)) {
        throw new AsyncApiError("asyncapi/duplicate-component",
          "schema: components.schemas." + name + " already registered");
      }
      components.schemas[name] = schemaWalk.walk(schemaSpec);
      return this;
    },

    message: function (name, messageSpec) {
      validateOpts.requireNonEmptyString(name, "message: name",
        AsyncApiError, "asyncapi/bad-component");
      components.messages[name] = _normaliseMessage(messageSpec, "message: " + name);
      return this;
    },

    parameter: function (name, paramSpec) {
      validateOpts.requireNonEmptyString(name, "parameter: name",
        AsyncApiError, "asyncapi/bad-component");
      components.parameters[name] = paramSpec;
      return this;
    },

    correlationId: function (name, idSpec) {
      validateOpts.requireNonEmptyString(name, "correlationId: name",
        AsyncApiError, "asyncapi/bad-component");
      if (!idSpec || typeof idSpec !== "object" || typeof idSpec.location !== "string") {
        throw new AsyncApiError("asyncapi/bad-correlation-id",
          "correlationId: spec must be { location: 'runtime expression', description? }");
      }
      components.correlationIds[name] = idSpec;
      return this;
    },

    security: {
      add: function (name, scheme) {
        validateOpts.requireNonEmptyString(name, "security.add: name",
          AsyncApiError, "asyncapi/bad-security");
        if (!scheme || typeof scheme !== "object" || typeof scheme.type !== "string") {
          throw new AsyncApiError("asyncapi/bad-security",
            "security.add: scheme must be a securityScheme object with a type");
        }
        components.securitySchemes[name] = scheme;
        return this;
      },
      require: function (requirement) {
        if (!requirement || typeof requirement !== "object") {
          throw new AsyncApiError("asyncapi/bad-security",
            "security.require: requirement must be an object like { schemeName: ['scope'] }");
        }
        docSecurity.push(requirement);
        return this;
      },
    },

    tag: function (tagSpec) {
      if (!tagSpec || typeof tagSpec !== "object" ||
          typeof tagSpec.name !== "string" || tagSpec.name.length === 0) {
        throw new AsyncApiError("asyncapi/bad-tag",
          "tag: tagSpec.name is required");
      }
      docTags.push(tagSpec);
      return this;
    },

    server: function (serverId, serverSpec) {
      validateOpts.requireNonEmptyString(serverId, "server: serverId",
        AsyncApiError, "asyncapi/bad-server");
      _validateServerEntry(serverSpec, "server " + serverId);
      servers[serverId] = Object.assign({}, serverSpec);
      return this;
    },

    toJson: function () {
      var doc = {
        asyncapi: ASYNCAPI_VERSION,
        info:     info,
      };
      if (docId) doc.id = docId;
      if (defaultContentType) doc.defaultContentType = defaultContentType;
      if (Object.keys(servers).length > 0) doc.servers = servers;

      doc.channels   = channels;
      doc.operations = operations;

      var anyComponent = false;
      var componentsOut = {};
      var keys = ["schemas", "messages", "parameters", "securitySchemes",
                  "serverVariables", "correlationIds", "operationTraits",
                  "messageTraits", "replies", "replyAddresses"];
      for (var k = 0; k < keys.length; k += 1) {
        var key = keys[k];
        if (Object.keys(components[key]).length > 0) {
          componentsOut[key] = components[key];
          anyComponent = true;
        }
      }
      if (anyComponent) doc.components = componentsOut;

      // Validate doc-level security references.
      for (var r = 0; r < docSecurity.length; r += 1) {
        for (var schemeName in docSecurity[r]) {
          if (!Object.prototype.hasOwnProperty.call(docSecurity[r], schemeName)) continue;
          if (!components.securitySchemes[schemeName]) {
            throw new AsyncApiError("asyncapi/dangling-security",
              "toJson: doc-level security references undefined scheme " +
              JSON.stringify(schemeName));
          }
        }
      }
      // Operation-level security
      for (var opId in operations) {
        if (!Object.prototype.hasOwnProperty.call(operations, opId)) continue;
        var opSec = operations[opId].security;
        if (Array.isArray(opSec)) {
          for (var os = 0; os < opSec.length; os += 1) {
            for (var sn in opSec[os]) {
              if (!Object.prototype.hasOwnProperty.call(opSec[os], sn)) continue;
              if (!components.securitySchemes[sn]) {
                throw new AsyncApiError("asyncapi/dangling-security",
                  "toJson: operation " + opId + " references undefined security scheme " +
                  JSON.stringify(sn));
              }
            }
          }
        }
      }

      if (docSecurity.length > 0) doc.security = docSecurity.slice();
      if (docTags.length > 0)     doc.tags = docTags.slice();
      if (externalDocs)           doc.externalDocs = externalDocs;

      try {
        audit().safeEmit({
          action:   "asyncapi.document.built",
          outcome:  "success",
          actor:    null,
          metadata: {
            title:       info.title,
            version:     info.version,
            channelCount:   Object.keys(channels).length,
            operationCount: Object.keys(operations).length,
            schemaCount:    Object.keys(components.schemas).length,
            messageCount:   Object.keys(components.messages).length,
          },
        });
      } catch (_e) { /* drop-silent */ }

      return doc;
    },

    toJsonString: function (indent) {
      return JSON.stringify(this.toJson(), null, indent || 2);
    },

    toYaml: function () {
      return openapiYaml.toYaml(this.toJson());
    },
  };
}

function _validateServers(input) {
  if (input == null) return {};
  if (typeof input !== "object" || Array.isArray(input)) {
    throw new AsyncApiError("asyncapi/bad-server",
      "create: servers must be a map { serverId: spec, ... }");
  }
  var out = {};
  for (var key in input) {
    if (!Object.prototype.hasOwnProperty.call(input, key)) continue;
    _validateServerEntry(input[key], "create: servers." + key);
    out[key] = Object.assign({}, input[key]);
  }
  return out;
}

function _validateServerEntry(entry, label) {
  if (!entry || typeof entry !== "object") {
    throw new AsyncApiError("asyncapi/bad-server",
      label + ": server must be an object");
  }
  validateOpts.requireNonEmptyString(entry.host,
    label + ": host", AsyncApiError, "asyncapi/bad-server");
  validateOpts.requireNonEmptyString(entry.protocol,
    label + ": protocol", AsyncApiError, "asyncapi/bad-server");
}

/**
 * @primitive b.asyncapi.parse
 * @signature b.asyncapi.parse(jsonStringOrObject)
 * @since     0.6.30
 * @related   b.asyncapi.create, b.openapi.parse
 *
 * Parse + validate an external AsyncAPI 3.0 document. Throws on
 * invalid JSON or non-object input; otherwise returns
 * `{ doc, errors, valid }`. `errors` is an array of strings — empty
 * on a valid document. Operations must declare `action: "send" |
 * "receive"` and a `channel.$ref` resolving to a declared channel;
 * server entries need both `host` and `protocol`; doc-level security
 * must reference declared schemes.
 *
 * @example
 *   var result = b.asyncapi.parse('{"asyncapi":"3.0.0","info":{"title":"x","version":"1.0.0"}}');
 *   result.valid;       // → true
 *   result.errors;      // → []
 *
 *   var bad = b.asyncapi.parse({
 *     asyncapi: "3.0.0",
 *     info:     { title: "x", version: "1.0.0" },
 *     channels: {},
 *     operations: { pub: { action: "send", channel: { $ref: "#/channels/missing" } } },
 *   });
 *   bad.valid;          // → false
 *   bad.errors[0];      // → 'operations.pub.channel: $ref "#/channels/missing" does not resolve to a declared channel'
 */
function parse(jsonStringOrObject) {
  // A JSON string is parsed through safeJson (proto-pollution-key strip + depth
  // / size caps — a raw JSON.parse here kept a "__proto__" member and was
  // unbounded on an operator-supplied document); a pre-built object passes
  // through. The 16 MiB cap is generous for any real AsyncAPI document.
  var doc = safeJson.parseStringOrObject(jsonStringOrObject, {
    maxBytes:   C.BYTES.mib(16),
    errorClass: AsyncApiError,
    jsonCode:   "asyncapi/bad-json",
    inputCode:  "asyncapi/bad-input",
    label:      "asyncapi.parse",
  });
  var errors = [];
  if (typeof doc.asyncapi !== "string") {
    errors.push("missing or non-string `asyncapi` version field (must be 3.0.x)");
  } else if (doc.asyncapi.indexOf("3.0") !== 0) {
    errors.push("`asyncapi` version must be 3.0.x — got " + JSON.stringify(doc.asyncapi));
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
  // Channels must be an object when present.
  if (doc.channels != null && typeof doc.channels !== "object") {
    errors.push("`channels` must be an object when present");
  }
  // Operations must reference declared channels.
  var channels = doc.channels || {};
  if (doc.operations && typeof doc.operations === "object") {
    for (var opId in doc.operations) {
      if (!Object.prototype.hasOwnProperty.call(doc.operations, opId)) continue;
      var op = doc.operations[opId];
      if (!op || typeof op !== "object") {
        errors.push("operations." + opId + ": must be an object");
        continue;
      }
      if (op.action !== "send" && op.action !== "receive") {
        errors.push("operations." + opId + ".action must be 'send' or 'receive' — got " +
                    JSON.stringify(op.action));
      }
      var channelRef = op.channel;
      if (channelRef && typeof channelRef === "object" && typeof channelRef["$ref"] === "string") {
        var refMatch = channelRef["$ref"].match(/^#\/channels\/(.+)$/);
        if (refMatch && !Object.prototype.hasOwnProperty.call(channels, refMatch[1])) {
          errors.push("operations." + opId + ".channel: $ref " +
                      JSON.stringify(channelRef["$ref"]) +
                      " does not resolve to a declared channel");
        }
      } else {
        errors.push("operations." + opId + ".channel: must be a $ref to #/channels/<id>");
      }
    }
  }
  // Server entries must carry host + protocol when present.
  if (doc.servers && typeof doc.servers === "object") {
    for (var sid in doc.servers) {
      if (!Object.prototype.hasOwnProperty.call(doc.servers, sid)) continue;
      var entry = doc.servers[sid];
      if (!entry || typeof entry !== "object") {
        errors.push("servers." + sid + ": must be an object");
        continue;
      }
      if (typeof entry.host !== "string" || entry.host.length === 0) {
        errors.push("servers." + sid + ".host must be a non-empty string");
      }
      if (typeof entry.protocol !== "string" || entry.protocol.length === 0) {
        errors.push("servers." + sid + ".protocol must be a non-empty string");
      }
    }
  }
  // Dangling doc-level security references.
  var schemes = (doc.components && doc.components.securitySchemes) || {};
  if (Array.isArray(doc.security)) {
    for (var s = 0; s < doc.security.length; s += 1) {
      for (var sn in doc.security[s]) {
        if (!Object.prototype.hasOwnProperty.call(doc.security[s], sn)) continue;
        if (!schemes[sn]) {
          errors.push("doc-level security references undefined scheme " + JSON.stringify(sn));
        }
      }
    }
  }
  return { doc: doc, errors: errors, valid: errors.length === 0 };
}

module.exports = {
  create:     create,
  parse:      parse,
  bindings:   bindingsMod,
  traits:     traitsMod,
  schemaWalk: schemaWalk.walk,
  security:   openapiSecurity,
  toYaml:     openapiYaml.toYaml,
  VERSION:    ASYNCAPI_VERSION,
  AsyncApiError: AsyncApiError,
};
