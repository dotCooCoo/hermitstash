"use strict";
/**
 * AsyncAPI 3.0 protocol bindings.
 *
 * AsyncAPI describes asynchronous APIs (pubsub, websockets, kafka,
 * mqtt, amqp, redis-streams, ...) and bindings carry per-protocol
 * configuration that the spec body does not describe in a protocol-
 * neutral way.
 *
 * The framework ships first-class binding builders for the four
 * protocols its primitives speak:
 *
 *   .websockets({ method, query, headers })   — RFC 6455 / RFC 7692
 *   .kafka({ topic, partitions, replicas, ... })
 *   .amqp({ exchange, queue, ... })
 *   .mqtt({ qos, retain, ... })
 *
 * Operators with other protocols (NATS, Redis Streams, AWS SNS, ...)
 * pass plain JSON binding objects; the AsyncAPI builder accepts them
 * unchanged.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var AsyncApiError = defineClass("AsyncApiError", { alwaysPermanent: true });

function websockets(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "method", "query", "headers", "bindingVersion",
  ], "asyncapi.bindings.websockets");
  if (opts.method != null) {
    var validMethods = ["GET", "POST"];
    if (validMethods.indexOf(opts.method) === -1) {
      throw new AsyncApiError("asyncapi/bad-binding",
        "websockets: method must be GET or POST - got " + JSON.stringify(opts.method));
    }
  }
  var out = {};
  if (opts.method)  out.method  = opts.method;
  if (opts.query)   out.query   = opts.query;
  if (opts.headers) out.headers = opts.headers;
  out.bindingVersion = opts.bindingVersion || "0.1.0";
  return out;
}

function kafka(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "topic", "partitions", "replicas", "topicConfiguration",
    "bindingVersion", "groupId", "clientId", "schemaRegistryUrl",
    "schemaRegistryVendor", "schemaIdLocation", "schemaIdPayloadEncoding",
    "schemaLookupStrategy", "key",
  ], "asyncapi.bindings.kafka");
  if (opts.topic != null) {
    validateOpts.requireNonEmptyString(opts.topic,
      "kafka: topic", AsyncApiError, "asyncapi/bad-binding");
  }
  if (opts.partitions != null &&
      (typeof opts.partitions !== "number" || opts.partitions <= 0)) {
    throw new AsyncApiError("asyncapi/bad-binding",
      "kafka: partitions must be a positive number");
  }
  if (opts.replicas != null &&
      (typeof opts.replicas !== "number" || opts.replicas <= 0)) {
    throw new AsyncApiError("asyncapi/bad-binding",
      "kafka: replicas must be a positive number");
  }
  var out = {};
  if (opts.topic)       out.topic = opts.topic;
  if (opts.partitions)  out.partitions = opts.partitions;
  if (opts.replicas)    out.replicas = opts.replicas;
  if (opts.topicConfiguration)    out.topicConfiguration = opts.topicConfiguration;
  if (opts.groupId)     out.groupId = opts.groupId;
  if (opts.clientId)    out.clientId = opts.clientId;
  if (opts.schemaRegistryUrl)     out.schemaRegistryUrl = opts.schemaRegistryUrl;
  if (opts.schemaRegistryVendor)  out.schemaRegistryVendor = opts.schemaRegistryVendor;
  if (opts.schemaIdLocation)      out.schemaIdLocation = opts.schemaIdLocation;
  if (opts.schemaIdPayloadEncoding) out.schemaIdPayloadEncoding = opts.schemaIdPayloadEncoding;
  if (opts.schemaLookupStrategy)  out.schemaLookupStrategy = opts.schemaLookupStrategy;
  if (opts.key)         out.key = opts.key;
  out.bindingVersion = opts.bindingVersion || "0.5.0";
  return out;
}

function amqp(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "is", "exchange", "queue", "deliveryMode",
    "mandatory", "bcc", "replyTo", "timestamp", "ack", "bindingVersion",
  ], "asyncapi.bindings.amqp");
  if (opts.is != null && opts.is !== "queue" && opts.is !== "routingKey") {
    throw new AsyncApiError("asyncapi/bad-binding",
      "amqp: is must be 'queue' or 'routingKey' - got " + JSON.stringify(opts.is));
  }
  var out = {};
  if (opts.is)        out.is = opts.is;
  if (opts.exchange)  out.exchange = opts.exchange;
  if (opts.queue)     out.queue = opts.queue;
  if (opts.deliveryMode != null) out.deliveryMode = opts.deliveryMode;
  if (opts.mandatory === true)   out.mandatory = true;
  if (Array.isArray(opts.bcc))   out.bcc = opts.bcc.slice();
  if (opts.replyTo)  out.replyTo = opts.replyTo;
  if (opts.timestamp === true)   out.timestamp = true;
  if (opts.ack === true)         out.ack = true;
  out.bindingVersion = opts.bindingVersion || "0.3.0";
  return out;
}

function mqtt(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "qos", "retain", "messageExpiryInterval", "topic",
    "bindingVersion",
  ], "asyncapi.bindings.mqtt");
  if (opts.qos != null) {
    if (typeof opts.qos !== "number" || opts.qos < 0 || opts.qos > 2 ||
        Math.floor(opts.qos) !== opts.qos) {
      throw new AsyncApiError("asyncapi/bad-binding",
        "mqtt: qos must be 0, 1, or 2 - got " + JSON.stringify(opts.qos));
    }
  }
  var out = {};
  if (typeof opts.qos === "number")        out.qos = opts.qos;
  if (opts.retain === true)                out.retain = true;
  if (typeof opts.messageExpiryInterval === "number") {
    out.messageExpiryInterval = opts.messageExpiryInterval;
  }
  if (opts.topic)        out.topic = opts.topic;
  out.bindingVersion = opts.bindingVersion || "0.2.0";
  return out;
}

function http(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "type", "method", "query", "statusCode", "headers", "bindingVersion",
  ], "asyncapi.bindings.http");
  if (opts.type != null && opts.type !== "request" && opts.type !== "response") {
    throw new AsyncApiError("asyncapi/bad-binding",
      "http: type must be 'request' or 'response' - got " + JSON.stringify(opts.type));
  }
  var out = {};
  if (opts.type)         out.type = opts.type;
  if (opts.method)       out.method = opts.method;
  if (opts.query)        out.query = opts.query;
  if (opts.statusCode != null) out.statusCode = opts.statusCode;
  if (opts.headers)      out.headers = opts.headers;
  out.bindingVersion = opts.bindingVersion || "0.3.0";
  return out;
}

module.exports = {
  websockets:    websockets,
  kafka:         kafka,
  amqp:          amqp,
  mqtt:          mqtt,
  http:          http,
  AsyncApiError: AsyncApiError,
};
