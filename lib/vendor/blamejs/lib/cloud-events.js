"use strict";
/**
 * CloudEvents 1.0 envelope (cloudevents.io/spec/v1.0).
 *
 * A vendor-neutral event-format spec adopted by AWS EventBridge,
 * Knative, Azure Event Grid, Google Eventarc, Datadog, and the
 * CNCF event ecosystem. Operators wrap outbound events from
 * webhook / pubsub / queue boundaries to interop with these
 * consumers without each consumer having to learn a bespoke shape.
 *
 *   var ce = b.cloudEvents.wrap({
 *     source: "/services/orders",
 *     type:   "com.example.order.created",
 *     subject: "order/o-1234",
 *     data:    { id: "o-1234", total: 4250 },
 *   });
 *   // → {
 *   //     specversion: "1.0",
 *   //     id:          "<auto-uuid-v4>",
 *   //     source:      "/services/orders",
 *   //     type:        "com.example.order.created",
 *   //     time:        "2026-05-06T...",
 *   //     subject:     "order/o-1234",
 *   //     datacontenttype: "application/json",
 *   //     data:        { id: "o-1234", total: 4250 },
 *   //   }
 *
 *   var ce = b.cloudEvents.parse(envelope);   // throws on shape violation
 *
 * Spec compliance — REQUIRED attributes (CloudEvents §3.1):
 *   id, source, specversion, type
 *
 * OPTIONAL attributes:
 *   datacontenttype, dataschema, subject, time, data, data_base64
 *
 * Operator-defined extension attributes are passed through unchanged
 * if they conform to the spec's naming rules (lowercase ASCII letters
 * + digits, length 1–20).
 */

var nodeCrypto = require("crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var CloudEventsError = defineClass("CloudEventsError", { alwaysPermanent: true });

var SPECVERSION = "1.0";

// CloudEvents §3.1 — required string attributes.
var REQUIRED_ATTRS = ["id", "source", "specversion", "type"];

// CloudEvents §3.1 — known optional attributes (other strings get
// passed through as extension attributes if they conform to the
// naming rules).
var KNOWN_OPTIONAL_ATTRS = {
  datacontenttype: 1,
  dataschema:      1,
  subject:         1,
  time:            1,
  data:            1,
  data_base64:     1,
};

// CloudEvents §3.1 attribute naming — lowercase letters + digits,
// length 1-20.
var EXT_ATTR_NAME_RE = /^[a-z0-9]{1,20}$/;

function _isoNow() { return new Date().toISOString(); }

function _genId() {
  // RFC 4122 v4 UUID — 16 random bytes with version + variant bits.
  return nodeCrypto.randomUUID();
}

// ---- wrap ----

function wrap(opts) {
  validateOpts.requireObject(opts, "cloudEvents.wrap", CloudEventsError);
  validateOpts.requireNonEmptyString(opts.source,
    "cloudEvents.wrap: source", CloudEventsError, "cloud-events/bad-source");
  validateOpts.requireNonEmptyString(opts.type,
    "cloudEvents.wrap: type", CloudEventsError, "cloud-events/bad-type");
  validateOpts.optionalNonEmptyString(opts.id,
    "cloudEvents.wrap: id", CloudEventsError, "cloud-events/bad-id");
  validateOpts.optionalNonEmptyString(opts.subject,
    "cloudEvents.wrap: subject", CloudEventsError, "cloud-events/bad-subject");
  validateOpts.optionalNonEmptyString(opts.time,
    "cloudEvents.wrap: time", CloudEventsError, "cloud-events/bad-time");
  validateOpts.optionalNonEmptyString(opts.datacontenttype,
    "cloudEvents.wrap: datacontenttype", CloudEventsError, "cloud-events/bad-datacontenttype");
  validateOpts.optionalNonEmptyString(opts.dataschema,
    "cloudEvents.wrap: dataschema", CloudEventsError, "cloud-events/bad-dataschema");

  var out = {
    specversion: SPECVERSION,
    id:          opts.id || _genId(),
    source:      opts.source,
    type:        opts.type,
    time:        opts.time || _isoNow(),
  };
  if (opts.subject !== undefined && opts.subject !== null) out.subject = opts.subject;
  if (opts.dataschema !== undefined && opts.dataschema !== null) out.dataschema = opts.dataschema;

  // data — choose JSON vs binary based on Buffer-ness; auto-set
  // datacontenttype when caller doesn't supply one.
  if (opts.data !== undefined) {
    if (Buffer.isBuffer(opts.data)) {
      out.data_base64 = opts.data.toString("base64");
      out.datacontenttype = opts.datacontenttype || "application/octet-stream";
    } else {
      out.data = opts.data;
      out.datacontenttype = opts.datacontenttype || "application/json";
    }
  } else if (opts.datacontenttype) {
    out.datacontenttype = opts.datacontenttype;
  }

  // Extension attributes — operator-defined, must conform to the
  // §3.1 naming rules (lowercase ASCII alnum, 1-20 chars).
  if (opts.extensions !== undefined && opts.extensions !== null) {
    validateOpts.optionalPlainObject(opts.extensions,
      "cloudEvents.wrap: extensions", CloudEventsError, "cloud-events/bad-extensions");
    var extKeys = Object.keys(opts.extensions);
    for (var i = 0; i < extKeys.length; i += 1) {
      var k = extKeys[i];
      // bound BEFORE regex test — k.length > 0 && k.length <= 20
      if (typeof k !== "string" || k.length === 0 || k.length > 20 || !EXT_ATTR_NAME_RE.test(k)) {
        throw new CloudEventsError("cloud-events/bad-extension-name",
          "cloudEvents.wrap: extension '" + k + "' must match [a-z0-9]{1,20}");
      }
      if (REQUIRED_ATTRS.indexOf(k) !== -1 || KNOWN_OPTIONAL_ATTRS[k]) {
        throw new CloudEventsError("cloud-events/extension-conflicts-with-spec",
          "cloudEvents.wrap: extension '" + k + "' conflicts with a spec attribute");
      }
      out[k] = opts.extensions[k];
    }
  }
  return out;
}

// ---- parse ----

function parse(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new CloudEventsError("cloud-events/bad-envelope",
      "cloudEvents.parse: envelope must be a plain object");
  }
  for (var i = 0; i < REQUIRED_ATTRS.length; i += 1) {
    var k = REQUIRED_ATTRS[i];
    if (typeof envelope[k] !== "string" || envelope[k].length === 0) {
      throw new CloudEventsError("cloud-events/missing-required",
        "cloudEvents.parse: required attribute '" + k + "' missing or empty (CloudEvents §3.1)");
    }
  }
  if (envelope.specversion !== SPECVERSION) {
    throw new CloudEventsError("cloud-events/unsupported-specversion",
      "cloudEvents.parse: specversion='" + envelope.specversion +
      "' is not supported (this primitive implements CloudEvents 1.0)");
  }
  if (envelope.data !== undefined && envelope.data_base64 !== undefined) {
    throw new CloudEventsError("cloud-events/data-conflict",
      "cloudEvents.parse: envelope has both 'data' and 'data_base64' (CloudEvents §3.1.1)");
  }

  // Decode binary data if the envelope used base64 mode.
  var decodedData = envelope.data;
  if (envelope.data_base64 !== undefined) {
    if (typeof envelope.data_base64 !== "string") {
      throw new CloudEventsError("cloud-events/bad-data-base64",
        "cloudEvents.parse: data_base64 must be a string");
    }
    try { decodedData = Buffer.from(envelope.data_base64, "base64"); }
    catch (e) {
      throw new CloudEventsError("cloud-events/bad-data-base64",
        "cloudEvents.parse: data_base64 decode failed: " + ((e && e.message) || String(e)));
    }
  }

  // Surface extension attributes separately so consumers can route on
  // operator-defined fields without grepping the envelope.
  var extensions = {};
  var keys = Object.keys(envelope);
  for (var j = 0; j < keys.length; j += 1) {
    var key = keys[j];
    if (REQUIRED_ATTRS.indexOf(key) !== -1) continue;
    if (KNOWN_OPTIONAL_ATTRS[key]) continue;
    extensions[key] = envelope[key];
  }

  return {
    specversion:     envelope.specversion,
    id:              envelope.id,
    source:          envelope.source,
    type:            envelope.type,
    time:            envelope.time || null,
    subject:         envelope.subject || null,
    datacontenttype: envelope.datacontenttype || null,
    dataschema:      envelope.dataschema || null,
    data:            decodedData,
    extensions:      extensions,
  };
}

module.exports = {
  wrap:             wrap,
  parse:            parse,
  SPECVERSION:      SPECVERSION,
  REQUIRED_ATTRS:   REQUIRED_ATTRS,
  CloudEventsError: CloudEventsError,
};
