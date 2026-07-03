// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.hal
 * @nav    HTTP
 * @title  HAL hypermedia
 * @order  173
 *
 * @intro
 *   HAL (Hypertext Application Language, IETF draft-kelly-json-hal-08).
 *   Wraps resources with `_links` + `_embedded` so clients discover
 *   navigation + nested resources without out-of-band routing. The
 *   spec is small; the framework's helper is correspondingly small.
 *
 *   Content-Type: `application/hal+json`
 *
 *   Reserved properties:
 *     - `_links`     — { rel: linkObject | linkObject[] } per RFC 8288
 *     - `_embedded`  — { rel: resource | resource[] }
 *     - `_templates` — HAL-FORMS extension (operator-supplied)
 *
 * @card
 *   HAL (draft-kelly-json-hal) + HAL-FORMS hypermedia response builder. Content-Type negotiation + _links/_embedded structure helpers per RFC 8288.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var HalError = defineClass("HalError", { alwaysPermanent: true });

var CONTENT_TYPE = "application/hal+json";

/**
 * @primitive b.hal.resource
 * @signature b.hal.resource(payload, opts?)
 * @since     0.10.16
 * @status    stable
 *
 * Build a HAL resource. `payload` is the operator's domain object;
 * `opts.links` is a map of `{ rel: href | linkObject | linkObject[] }`;
 * `opts.embedded` is a map of `{ rel: resource | resource[] }`.
 *
 * @opts
 *   links:    { [rel]: string | LinkObject | LinkObject[] },
 *   embedded: { [rel]: object | object[] },
 *   templates: { [name]: HalFormTemplate },     // HAL-FORMS extension
 *
 * @example
 *   var r = b.hal.resource(
 *     { title: "Hello", body: "World" },
 *     { links: { self: "/articles/1",
 *                next: { href: "/articles/2", title: "Next article" } } }
 *   );
 */
function resource(payload, opts) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new HalError("hal/bad-payload",
      "resource: payload must be a non-array object");
  }
  opts = opts || {};
  validateOpts(opts, ["links", "embedded", "templates"], "hal.resource");
  // Build resource by shallow-clone (don't mutate operator input).
  var out = {};
  var keys = Object.keys(payload);
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    if (k === "_links" || k === "_embedded" || k === "_templates") {
      // Operator-supplied reserved keys in payload override opts —
      // refuse to avoid ambiguity.
      throw new HalError("hal/reserved-key",
        "resource: payload must not contain reserved key '" + k + "' (use opts." +
        (k === "_templates" ? "templates" : k.slice(1)) + ")");
    }
    out[k] = payload[k];
  }
  if (opts.links) {
    if (typeof opts.links !== "object" || Array.isArray(opts.links)) {
      throw new HalError("hal/bad-links", "resource: opts.links must be a non-array object");
    }
    out._links = _normaliseLinks(opts.links);
  }
  if (opts.embedded) {
    if (typeof opts.embedded !== "object" || Array.isArray(opts.embedded)) {
      throw new HalError("hal/bad-embedded", "resource: opts.embedded must be a non-array object");
    }
    out._embedded = opts.embedded;
  }
  if (opts.templates) {
    if (typeof opts.templates !== "object" || Array.isArray(opts.templates)) {
      throw new HalError("hal/bad-templates", "resource: opts.templates must be a non-array object");
    }
    out._templates = opts.templates;
  }
  return out;
}

function _normaliseLinks(links) {
  var out = {};
  var keys = Object.keys(links);
  for (var i = 0; i < keys.length; i += 1) {
    var rel = keys[i];
    var val = links[rel];
    if (typeof val === "string") {
      out[rel] = { href: val };
    } else if (Array.isArray(val)) {
      out[rel] = val.map(function (v, idx) {
        if (typeof v === "string") return { href: v };
        if (v && typeof v === "object" && typeof v.href === "string") return v;
        throw new HalError("hal/bad-link",
          "_links." + rel + "[" + idx + "] must be a string or LinkObject");
      });
    } else if (val && typeof val === "object" && typeof val.href === "string") {
      out[rel] = val;
    } else {
      throw new HalError("hal/bad-link",
        "_links." + rel + " must be a string, LinkObject, or LinkObject[]");
    }
  }
  return out;
}

module.exports = {
  resource:      resource,
  CONTENT_TYPE:  CONTENT_TYPE,
  HalError:      HalError,
};
