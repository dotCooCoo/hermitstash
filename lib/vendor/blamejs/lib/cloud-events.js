"use strict";
/**
 * @module b.cloudEvents
 * @nav    Communication
 * @title  CloudEvents
 *
 * @intro
 *   Produce and consume webhook / pubsub / queue payloads in the
 *   framework-neutral CNCF CloudEvents v1.0 schema
 *   (cloudevents.io/spec/v1.0). The spec is adopted by AWS
 *   EventBridge, Azure Event Grid, Google Eventarc, Knative, Datadog,
 *   and the wider CNCF ecosystem — wrapping outbound events at
 *   `b.webhook` / `b.pubsub` / `b.queue` boundaries lets operators
 *   interop with these consumers without each consumer learning a
 *   bespoke shape.
 *
 *   `wrap` produces a structured-mode envelope from operator-supplied
 *   `source` / `type` / `subject` / `data` (and optional `extensions`),
 *   auto-filling `id` (UUID v4) and `time` (ISO 8601). Buffer payloads
 *   are routed to the `data_base64` field with a default
 *   `application/octet-stream` content-type; non-Buffer payloads land
 *   in `data` with `application/json`. `parse` validates a received
 *   envelope against the §3.1 required-attribute set, refuses unknown
 *   `specversion` values and the illegal `data` + `data_base64`
 *   simultaneous form, decodes base64-mode payloads back to a Buffer,
 *   and surfaces operator-defined extension attributes separately so
 *   consumers can route on them without grepping the envelope.
 *
 *   Extension-attribute names follow the §3.1 naming rules
 *   (lowercase ASCII alnum, 1..20 chars). Names that collide with a
 *   spec attribute are refused.
 *
 * @card
 *   Produce and consume webhook / pubsub / queue payloads in the framework-neutral CNCF CloudEvents v1.0 schema (cloudevents.io/spec/v1.0).
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

/**
 * @primitive b.cloudEvents.wrap
 * @signature b.cloudEvents.wrap(opts)
 * @since     0.7.45
 * @status    stable
 * @related   b.cloudEvents.parse, b.webhook.signer, b.pubsub.create
 *
 * Produces a CloudEvents v1.0 structured-mode envelope from
 * `opts.source` + `opts.type` (the only required inputs). `id` is
 * auto-filled with a UUID v4 when absent; `time` is auto-filled with
 * the current ISO 8601 timestamp. Buffer `data` is base64-encoded
 * into `data_base64` with `application/octet-stream`; non-Buffer
 * `data` lands in the `data` attribute with `application/json`.
 * Extension keys must match `[a-z0-9]{1,20}` and must not collide
 * with a spec attribute — both refusals throw `CloudEventsError` at
 * config time.
 *
 * @opts
 *   {
 *     source:           string,         // required; URI-reference per §3.1
 *     type:             string,         // required; reverse-DNS recommended
 *     id?:              string,         // default UUID v4
 *     time?:            string,         // default new Date().toISOString()
 *     subject?:         string,
 *     datacontenttype?: string,         // auto: application/json | application/octet-stream
 *     dataschema?:      string,         // URI of payload schema
 *     data?:            object|Buffer,  // Buffer routes to data_base64
 *     extensions?:      object          // keys [a-z0-9]{1,20}, no spec collisions
 *   }
 *
 * @example
 *   var b = require("blamejs").create();
 *   var ce = b.cloudEvents.wrap({
 *     source:  "/services/orders",
 *     type:    "com.example.order.created",
 *     subject: "order/o-1234",
 *     data:    { id: "o-1234", total: 4250 }
 *   });
 *   ce.specversion;
 *   // → "1.0"
 */
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

/**
 * @primitive b.cloudEvents.parse
 * @signature b.cloudEvents.parse(envelope)
 * @since     0.7.45
 * @status    stable
 * @related   b.cloudEvents.wrap, b.webhook.verifier
 *
 * Validates a received CloudEvents v1.0 envelope and returns a
 * normalized record `{ specversion, id, source, type, time, subject,
 * datacontenttype, dataschema, data, extensions }`. Throws
 * `CloudEventsError` for missing required attributes (§3.1),
 * unsupported `specversion`, the illegal simultaneous `data` +
 * `data_base64` form (§3.1.1), and base64-decoding failures.
 * Buffer-mode payloads (`data_base64`) are decoded back to a
 * `Buffer`; operator-defined extension attributes are surfaced under
 * `.extensions` so routing can branch on them without scanning the
 * envelope.
 *
 * @example
 *   var b = require("blamejs").create();
 *   var record = b.cloudEvents.parse({
 *     specversion: "1.0",
 *     id:          "evt-1",
 *     source:      "/services/orders",
 *     type:        "com.example.order.created",
 *     data:        { id: "o-1234", total: 4250 }
 *   });
 *   record.type;
 *   // → "com.example.order.created"
 */
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
