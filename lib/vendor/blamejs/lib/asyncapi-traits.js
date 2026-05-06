"use strict";
/**
 * AsyncAPI 3.0 traits — reusable fragments that operations and
 * messages can inherit via the `traits` array. Operators define a
 * trait once (e.g. "every kafka publish carries a tracing-header
 * envelope") and apply it to every relevant operation.
 *
 * AsyncAPI's trait-merge semantics: each trait is merged into the
 * parent in declaration order, with later traits overriding earlier
 * ones; the parent (operation / message) overrides any trait. This
 * module ships a `applyTraits(parent, traits)` helper that performs
 * the merge in-process so operators can compose traits without
 * relying on consumer tooling to do it.
 *
 *   var docTrait = b.asyncapi.traits.operation({
 *     bindings: { kafka: { groupId: "consumers-prod" } },
 *     tags:     [{ name: "kafka" }],
 *   });
 *
 *   var op = b.asyncapi.traits.applyOperation(
 *     { action: "send", channel: "events" },
 *     [docTrait],
 *   );
 *
 * The framework's primary use of this module is as a building block —
 * operators can also pass `traits: [...]` arrays directly into
 * `builder.operation(...)` / `builder.message(...)` without using
 * these helpers, but applyTraits gives a side-channel for reuse.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var AsyncApiError = defineClass("AsyncApiError", { alwaysPermanent: true });

var OPERATION_TRAIT_KEYS = [
  "title", "summary", "description", "security", "tags",
  "bindings", "externalDocs",
];

var MESSAGE_TRAIT_KEYS = [
  "headers", "correlationId", "schemaFormat", "contentType",
  "name", "title", "summary", "description", "tags",
  "bindings", "externalDocs", "examples", "traits",
];

function operation(spec) {
  if (!spec || typeof spec !== "object") {
    throw new AsyncApiError("asyncapi/bad-trait",
      "traits.operation: spec must be an object");
  }
  validateOpts(spec, OPERATION_TRAIT_KEYS, "traits.operation");
  return Object.freeze(_clone(spec));
}

function message(spec) {
  if (!spec || typeof spec !== "object") {
    throw new AsyncApiError("asyncapi/bad-trait",
      "traits.message: spec must be an object");
  }
  validateOpts(spec, MESSAGE_TRAIT_KEYS, "traits.message");
  return Object.freeze(_clone(spec));
}

function applyOperation(parent, traits) {
  return _apply(parent, traits, OPERATION_TRAIT_KEYS, "traits.applyOperation");
}

function applyMessage(parent, traits) {
  return _apply(parent, traits, MESSAGE_TRAIT_KEYS, "traits.applyMessage");
}

function _apply(parent, traits, keys, label) {
  if (!parent || typeof parent !== "object") {
    throw new AsyncApiError("asyncapi/bad-apply",
      label + ": parent must be an object");
  }
  if (traits == null) return _clone(parent);
  if (!Array.isArray(traits)) {
    throw new AsyncApiError("asyncapi/bad-apply",
      label + ": traits must be an array");
  }
  var merged = {};
  for (var i = 0; i < traits.length; i += 1) {
    var trait = traits[i];
    if (!trait || typeof trait !== "object") continue;
    for (var k = 0; k < keys.length; k += 1) {
      var key = keys[k];
      if (Object.prototype.hasOwnProperty.call(trait, key)) {
        merged[key] = _mergeKey(key, merged[key], trait[key]);
      }
    }
  }
  // Parent overrides traits.
  for (var pk in parent) {
    if (!Object.prototype.hasOwnProperty.call(parent, pk)) continue;
    merged[pk] = _mergeKey(pk, merged[pk], parent[pk]);
  }
  return merged;
}

function _mergeKey(key, base, overlay) {
  if (overlay == null) return base;
  if (base == null) return _clone(overlay);
  // Arrays merge by concatenation (`tags`, `examples`).
  if (Array.isArray(base) && Array.isArray(overlay)) {
    return base.concat(overlay);
  }
  // Objects merge shallow (`bindings`, `headers`).
  if (typeof base === "object" && typeof overlay === "object" &&
      !Array.isArray(base) && !Array.isArray(overlay)) {
    var out = {};
    for (var k1 in base) {
      if (Object.prototype.hasOwnProperty.call(base, k1)) out[k1] = base[k1];
    }
    for (var k2 in overlay) {
      if (Object.prototype.hasOwnProperty.call(overlay, k2)) out[k2] = overlay[k2];
    }
    return out;
  }
  return overlay;        // scalar overrides
}

function _clone(value) {
  if (value == null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(_clone);
  var out = {};
  for (var k in value) {
    if (Object.prototype.hasOwnProperty.call(value, k)) {
      out[k] = _clone(value[k]);
    }
  }
  return out;
}

module.exports = {
  operation:        operation,
  message:          message,
  applyOperation:   applyOperation,
  applyMessage:     applyMessage,
  OPERATION_TRAIT_KEYS: OPERATION_TRAIT_KEYS,
  MESSAGE_TRAIT_KEYS:   MESSAGE_TRAIT_KEYS,
  AsyncApiError:    AsyncApiError,
};
