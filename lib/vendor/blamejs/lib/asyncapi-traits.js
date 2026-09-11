// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
  for (var pk in parent) {
    if (!Object.prototype.hasOwnProperty.call(parent, pk)) continue;
    merged[pk] = _mergeKey(pk, merged[pk], parent[pk]);
  }
  return merged;
}

function _mergeKey(key, base, overlay) {
  if (overlay == null) return base;
  if (base == null) return _clone(overlay);
  if (Array.isArray(base) && Array.isArray(overlay)) {
    return base.concat(overlay);
  }
  if (typeof base === "object" && typeof overlay === "object" &&
      !Array.isArray(base) && !Array.isArray(overlay)) {
    var out = {};
    validateOpts.assignOwnEnumerable(out, base);
    validateOpts.assignOwnEnumerable(out, overlay);
    return out;
  }
  return overlay;
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
