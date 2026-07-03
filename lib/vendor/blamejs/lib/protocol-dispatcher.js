// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * protocol-dispatcher — pluggable protocol resolver with deferred-protocol
 * surfacing.
 *
 * Three framework modules ship a "pick a backend by protocol name" surface:
 *   - lib/queue.js                 (local, deferred: redis/sqs/amqp/nats)
 *   - lib/log-stream.js            (local + webhook + otlp + cloudwatch + syslog)
 *   - lib/object-store/index.js    (local + http-put + sigv4 + gcs + azure-blob)
 *
 * Each previously copied a ~30-line dispatch block: validate config has a
 * protocol, look up DEFERRED_PROTOCOLS for a clear "not yet implemented"
 * error, look up PROTOCOLS for the real implementation, throw on unknown.
 * This primitive owns that lookup + error shape so callers focus on
 * post-resolve logic (retry+breaker wrapping, classification, etc.).
 *
 * Public API:
 *
 *   var dispatcher = protocolDispatcher.create({
 *     name:             "queue",                // appears in error messages
 *     errorClass:       QueueError,             // thrown on unknown/deferred/missing
 *     protocols:        { local: localProto },  // protocol-name → module
 *     deferred:         { redis: { description: "Redis Streams" } },
 *     fallbackProtocol: "local",                // hinted in deferred-error
 *   });
 *
 *   var proto = dispatcher.resolve(cfg.protocol);
 *   //   throws errorClass when:
 *   //     - cfg.protocol is undefined / empty                  → MISSING_PROTOCOL
 *   //     - cfg.protocol matches a deferred-protocol entry      → PROTOCOL_NOT_IMPLEMENTED
 *   //     - cfg.protocol is neither implemented nor deferred    → UNKNOWN_PROTOCOL
 *   //   returns the protocol module (caller invokes proto.create(cfg) etc.)
 *
 *   dispatcher.protocols  // → ["local"]
 *   dispatcher.deferred   // → ["redis"]
 *
 * Why resolve-only (not build): the post-resolve flow differs per module
 * (retry+breaker for queue+object-store, batched dispatch for log-stream,
 * classification routing for object-store). A one-size-fits-all builder
 * would either miss those concerns or expose them as a sprawling opts
 * surface. Resolve-only keeps the primitive small and the post-resolve
 * code where it belongs.
 *
 * Error surface: every throw carries the dispatcher's `name` so an
 * operator with multiple dispatchers (queue + log-stream) reading the
 * error message knows which one rejected the protocol.
 */
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

// Default error class — operators / test fixtures that don't want to
// supply their own get this generic shape with the same code namespace.
var ProtocolDispatcherError = defineClass("ProtocolDispatcherError", { withStatusCode: true });

// Throw at create-time on bad input so operators catch typos at app
// boot, not first request.
function _validateConfig(opts) {
  if (!opts || typeof opts !== "object") {
    throw new ProtocolDispatcherError("protocol-dispatcher/bad-opts",
      "protocolDispatcher.create: opts is required");
  }
  validateOpts.requireNonEmptyString(opts.name, "protocolDispatcher.create: opts.name", ProtocolDispatcherError, "protocol-dispatcher/bad-name");
  if (!opts.protocols || typeof opts.protocols !== "object" || Array.isArray(opts.protocols)) {
    throw new ProtocolDispatcherError("protocol-dispatcher/bad-protocols",
      "protocolDispatcher.create: opts.protocols (object) is required");
  }
  // Each protocol value should look like a module with .create — operators
  // wiring a typo'd reference get a clearer error than "undefined is not
  // a function" when resolve() hits it.
  var pkeys = Object.keys(opts.protocols);
  for (var i = 0; i < pkeys.length; i++) {
    var p = opts.protocols[pkeys[i]];
    if (!p || typeof p !== "object" || typeof p.create !== "function") {
      throw new ProtocolDispatcherError("protocol-dispatcher/bad-protocol-entry",
        "protocolDispatcher.create: opts.protocols['" + pkeys[i] +
        "'] must be an object with a .create function (got " +
        (p === null ? "null" : typeof p) + ")");
    }
  }
  if (opts.deferred !== undefined && opts.deferred !== null) {
    if (typeof opts.deferred !== "object" || Array.isArray(opts.deferred)) {
      throw new ProtocolDispatcherError("protocol-dispatcher/bad-deferred",
        "protocolDispatcher.create: opts.deferred must be an object (or omitted)");
    }
  }
  if (opts.fallbackProtocol !== undefined && opts.fallbackProtocol !== null) {
    if (typeof opts.fallbackProtocol !== "string" || opts.fallbackProtocol.length === 0) {
      throw new ProtocolDispatcherError("protocol-dispatcher/bad-fallback",
        "protocolDispatcher.create: opts.fallbackProtocol must be a non-empty string (or omitted)");
    }
  }
  if (opts.errorClass !== undefined && opts.errorClass !== null) {
    if (typeof opts.errorClass !== "function") {
      throw new ProtocolDispatcherError("protocol-dispatcher/bad-error-class",
        "protocolDispatcher.create: opts.errorClass must be a constructor (or omitted)");
    }
  }
}

function create(opts) {
  _validateConfig(opts);
  var name             = opts.name;
  var protocols        = Object.assign({}, opts.protocols);
  var deferred         = Object.assign({}, opts.deferred || {});
  var fallbackProtocol = opts.fallbackProtocol || null;
  var ErrorClass       = opts.errorClass || ProtocolDispatcherError;

  function _err(code, message) {
    // ErrorClass is expected to be a defineClass-built class with
    // (code, message, permanent[, statusCode]) signature. Pass
    // permanent=true since protocol mismatches are config errors, not
    // transient failures.
    return new ErrorClass(code, message, true);
  }

  function resolve(protocol) {
    if (typeof protocol !== "string" || protocol.length === 0) {
      throw _err("MISSING_PROTOCOL",
        name + " backend requires { protocol }");
    }
    if (Object.prototype.hasOwnProperty.call(deferred, protocol)) {
      var d = deferred[protocol];
      var msg = name + " protocol '" + protocol + "' is not yet implemented";
      if (d && d.description) msg += " (" + d.description + ")";
      if (d && d.since)       msg += "; deferred to " + d.since;
      if (fallbackProtocol)   msg += ". Use protocol: '" + fallbackProtocol + "' for now.";
      throw _err("PROTOCOL_NOT_IMPLEMENTED", msg);
    }
    if (!Object.prototype.hasOwnProperty.call(protocols, protocol)) {
      // Diagnostic listing only — sorted protocol-name list for the
      // operator-facing error message; not a canonicalization-for-hash
      // walk, so the bare keys-then-sort is correct here.
      var protoKeys = Object.keys(protocols);
      protoKeys.sort();
      var known = protoKeys.join(", ");
      throw _err("UNKNOWN_PROTOCOL",
        "unknown " + name + " protocol: '" + protocol +
        "' (known: " + (known || "[none]") + ")");
    }
    return protocols[protocol];
  }

  // Same diagnostic-only sort for the dispatcher's introspection
  // surface — operators read these to confirm wiring at boot.
  var protocolNames = Object.keys(protocols);
  protocolNames.sort();
  var deferredNames = Object.keys(deferred);
  deferredNames.sort();

  return {
    name:      name,
    resolve:   resolve,
    protocols: protocolNames,
    deferred:  deferredNames,
  };
}

module.exports = {
  create:                    create,
  ProtocolDispatcherError:   ProtocolDispatcherError,
};
