// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var ProtocolDispatcherError = defineClass("ProtocolDispatcherError", { withStatusCode: true });

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
    return new ErrorClass(code, message, true);
  }

  function resolve(protocol) {
    if (typeof protocol !== "string" || protocol.length === 0) {
      throw _err("protocol-dispatcher/missing-protocol",
        name + " backend requires { protocol }");
    }
    if (Object.prototype.hasOwnProperty.call(deferred, protocol)) {
      var d = deferred[protocol];
      var msg = name + " protocol '" + protocol + "' is not yet implemented";
      if (d && d.description) msg += " (" + d.description + ")";
      if (d && d.since)       msg += "; deferred to " + d.since;
      if (fallbackProtocol)   msg += ". Use protocol: '" + fallbackProtocol + "' for now.";
      throw _err("protocol-dispatcher/protocol-not-implemented", msg);
    }
    if (!Object.prototype.hasOwnProperty.call(protocols, protocol)) {
      var protoKeys = Object.keys(protocols);
      protoKeys.sort();
      var known = protoKeys.join(", ");
      throw _err("protocol-dispatcher/unknown-protocol",
        "unknown " + name + " protocol: '" + protocol +
        "' (known: " + (known || "[none]") + ")");
    }
    return protocols[protocol];
  }

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
