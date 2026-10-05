// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.protocolDispatcher
 * @nav    Primitives
 * @title  Protocol Dispatcher
 * @slug   protocol-dispatcher
 *
 * @intro
 *   The table a primitive with several wire protocols looks its backend up
 *   in. A caller names a protocol, and the dispatcher answers the module
 *   that speaks it, or refuses with a message naming the ones it knows.
 *
 *   It separates three cases a hand-written lookup tends to merge. A name
 *   nobody registered is unknown, and the refusal lists what is known so a
 *   typo is visible. A name registered as deferred is one this version does
 *   not speak yet, and its refusal says so and points at the protocol to use
 *   instead, rather than reading as a typo. A missing name is neither, and
 *   says the option is required.
 *
 *   Every name is checked when the dispatcher is built, so a backend
 *   registered without a <code>create</code> function is caught at
 *   construction rather than on the first request that asks for it.
 *
 * @card
 *   Look a wire protocol's backend up by name, refusing an unknown one with
 *   the list of known names and a deferred one with what to use instead.
 *   Backends are validated when the table is built.
 */

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

/**
 * @primitive b.protocolDispatcher.create
 * @signature b.protocolDispatcher.create(opts)
 * @since     0.2.18
 * @status    stable
 * @related   b.frameworkError.defineClass
 *
 * Build the table and answer the handle to read it. The handle carries
 * `name`, `resolve(protocol)`, and `protocols` and `deferred` as sorted
 * arrays of the names in each.
 *
 * `resolve` answers the registered backend, and throws otherwise:
 * `protocol-dispatcher/missing-protocol` when nothing was named,
 * `protocol-dispatcher/protocol-not-implemented` for a deferred name, and
 * `protocol-dispatcher/unknown-protocol` for anything else, with the known
 * names listed. `errorClass` makes those throws the owning primitive's own
 * error type, so a caller catches one class rather than two.
 *
 * Validation is config-time, and each refusal carries its own code: an `opts`
 * that is not an object throws `protocol-dispatcher/bad-opts`, a missing or
 * empty `name` throws `protocol-dispatcher/bad-name`, a `protocols` that is not
 * an object throws `protocol-dispatcher/bad-protocols`, an entry within it that
 * is not an object with a `create` function throws
 * `protocol-dispatcher/bad-protocol-entry`, a `deferred` that is not an object
 * throws `protocol-dispatcher/bad-deferred`, a `fallbackProtocol` that is not a
 * non-empty string throws `protocol-dispatcher/bad-fallback`, and an
 * `errorClass` that is not a constructor throws
 * `protocol-dispatcher/bad-error-class`.
 *
 * @opts
 *   name:             string,  // what the primitive is called in messages; required
 *   protocols:        object,  // { <name>: module-with-create }; required
 *   deferred:         object,  // { <name>: { description?, since? } } — known but unimplemented
 *   fallbackProtocol: string,  // named in a deferred refusal as the one to use
 *   errorClass:       function,// FrameworkError subclass the refusals are built from
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var dispatch = b.protocolDispatcher.create({
 *     name:      "objectStore",
 *     protocols: { s3: require("./s3"), azure: require("./azure") },
 *     deferred:  { gcs: { description: "Google Cloud Storage", since: "0.9.0" } },
 *     fallbackProtocol: "s3",
 *   });
 *   dispatch.protocols;          // → ["azure", "s3"]
 *   dispatch.resolve("s3");      // → the s3 module
 *   dispatch.resolve("gcs");     // throws protocol-dispatcher/protocol-not-implemented
 */
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
