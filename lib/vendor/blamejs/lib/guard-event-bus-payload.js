"use strict";
/**
 * @module     b.guardEventBusPayload
 * @nav        Guards
 * @title      Guard Event Bus Payload
 * @order      439
 *
 * @intro
 *   Payload-shape validator for `b.agent.eventBus` events. Bus owners
 *   declare a schema per topic (flat key→type map); operators
 *   publishing events validate against the schema before pubsub
 *   dispatch; subscribers re-validate at delivery in case the payload
 *   was tampered in-flight.
 *
 *   Per-topic schema is a flat object:
 *
 *     ```js
 *     bus.registerTopic("mail.scan.malware-detected", {
 *       schema: {
 *         source:       "string",
 *         confidence:   "number",
 *         detectedAt:   "isoDateTime",
 *         sampleId:     "string",
 *       },
 *       ...
 *     });
 *     ```
 *
 *   Types: `string` / `number` / `boolean` / `integer` / `isoDateTime`
 *   / `array` / `object`. Optional fields suffix-marked with `?`
 *   (e.g. `"reason?": "string"`).
 *
 *   Payload byte cap (default 64 KiB) — events are metadata, NOT bulk
 *   data; publishers move bulk data through `b.objectStore` /
 *   `b.mailStore` and reference IDs in events.
 *
 * @card
 *   Validates `b.agent.eventBus` event payloads against per-topic
 *   schemas. Bounded byte cap, flat-shape type checks.
 */

var { defineClass } = require("./framework-error");

var GuardEventBusPayloadError = defineClass("GuardEventBusPayloadError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxBytes: 65536 },                                                                    // 64 KiB metadata cap
  balanced:   { maxBytes: 262144 },                                                                   // 256 KiB
  permissive: { maxBytes: 1048576 },                                                                  // 1 MiB
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

var ISO_DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/;        // allow:regex-no-length-cap — value length-bounded by maxBytes payload cap

/**
 * @primitive b.guardEventBusPayload.validate
 * @signature b.guardEventBusPayload.validate(payload, schema, opts?)
 * @since     0.9.25
 * @status    stable
 * @related   b.agent.eventBus.create
 *
 * Validate an event payload against its declared schema. Returns
 * the payload on success; throws on type mismatch / missing required
 * field / oversize.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardEventBusPayload.validate(
 *     { source: "1.2.3.4", confidence: 0.95 },
 *     { source: "string", confidence: "number" }
 *   );
 */
function validate(payload, schema, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new GuardEventBusPayloadError("event-bus-payload/bad-input",
      "guardEventBusPayload.validate: payload must be a plain object");
  }
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    throw new GuardEventBusPayloadError("event-bus-payload/bad-schema",
      "guardEventBusPayload.validate: schema must be a plain object");
  }
  var serialized;
  try { serialized = JSON.stringify(payload); }
  catch (e) {
    throw new GuardEventBusPayloadError("event-bus-payload/unserializable",
      "guardEventBusPayload.validate: payload not JSON-serializable: " +
      (e && e.message ? e.message : String(e)));
  }
  if (Buffer.byteLength(serialized, "utf8") > profile.maxBytes) {
    throw new GuardEventBusPayloadError("event-bus-payload/oversize",
      "guardEventBusPayload.validate: " + Buffer.byteLength(serialized, "utf8") +
      " bytes exceeds maxBytes=" + profile.maxBytes +
      " (events are metadata; reference bulk data via objectStore IDs)");
  }
  // Walk schema; check each field's type + presence.
  var schemaKeys = Object.keys(schema);
  for (var i = 0; i < schemaKeys.length; i += 1) {
    var key = schemaKeys[i];
    var optional = key.charAt(key.length - 1) === "?";
    var fieldName = optional ? key.slice(0, -1) : key;
    var expectedType = schema[key];
    var actual = payload[fieldName];
    if (typeof actual === "undefined" || actual === null) {
      if (!optional) {
        throw new GuardEventBusPayloadError("event-bus-payload/missing-field",
          "guardEventBusPayload.validate: required field '" + fieldName + "' missing");
      }
      continue;
    }
    _checkType(actual, expectedType, fieldName);
  }
  // Reject unknown keys — schema must be exhaustive.
  var payloadKeys = Object.keys(payload);
  for (var p = 0; p < payloadKeys.length; p += 1) {
    var pk = payloadKeys[p];
    if (!Object.prototype.hasOwnProperty.call(schema, pk) &&
        !Object.prototype.hasOwnProperty.call(schema, pk + "?")) {
      throw new GuardEventBusPayloadError("event-bus-payload/unknown-field",
        "guardEventBusPayload.validate: unknown field '" + pk + "' not in schema");
    }
  }
  return payload;
}

/**
 * @primitive b.guardEventBusPayload.compliancePosture
 * @signature b.guardEventBusPayload.compliancePosture(posture)
 * @since     0.9.25
 * @status    stable
 *
 * Return the effective profile for a given compliance posture name.
 * Returns `null` for unknown posture names so operator typos surface
 * here instead of silently falling through to the default profile.
 *
 * @example
 *   b.guardEventBusPayload.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _checkType(value, type, fieldName) {
  if (type === "string" && typeof value !== "string") {
    throw new GuardEventBusPayloadError("event-bus-payload/type-mismatch",
      "field '" + fieldName + "' expected string, got " + typeof value);
  }
  if (type === "number" && (typeof value !== "number" || !isFinite(value))) {
    throw new GuardEventBusPayloadError("event-bus-payload/type-mismatch",
      "field '" + fieldName + "' expected finite number, got " +
      (typeof value === "number" ? "non-finite number" : typeof value));
  }
  if (type === "boolean" && typeof value !== "boolean") {
    throw new GuardEventBusPayloadError("event-bus-payload/type-mismatch",
      "field '" + fieldName + "' expected boolean, got " + typeof value);
  }
  if (type === "integer" && !Number.isInteger(value)) {
    throw new GuardEventBusPayloadError("event-bus-payload/type-mismatch",
      "field '" + fieldName + "' expected integer");
  }
  if (type === "isoDateTime") {
    // Length-bound the value before regex test so a hostile input can't
    // burn regex-engine CPU. RFC 3339 ISO-8601 dateTime is bounded by
    // ~40 chars even with fractional seconds + numeric offset; cap at 64
    // for safety. The payload-level maxBytes cap also bounds the field.
    if (typeof value !== "string" || value.length > 64 || !ISO_DATETIME_RE.test(value)) {             // ISO-8601 dateTime max length
      throw new GuardEventBusPayloadError("event-bus-payload/type-mismatch",
        "field '" + fieldName + "' expected ISO-8601 dateTime string");
    }
  }
  if (type === "array" && !Array.isArray(value)) {
    throw new GuardEventBusPayloadError("event-bus-payload/type-mismatch",
      "field '" + fieldName + "' expected array");
  }
  if (type === "object") {
    // Plain object check: rule out null first (typeof null === "object"
    // pre-ES6 quirk), then array, then any non-object type.
    if (value === null || Array.isArray(value) || typeof value !== "object") {
      throw new GuardEventBusPayloadError("event-bus-payload/type-mismatch",
        "field '" + fieldName + "' expected plain object");
    }
  }
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return COMPLIANCE_POSTURES[opts.posture];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardEventBusPayloadError("event-bus-payload/bad-profile",
      "guardEventBusPayload: unknown profile '" + p + "'");
  }
  return p;
}

module.exports = {
  validate:                    validate,
  compliancePosture:           compliancePosture,
  PROFILES:                    PROFILES,
  COMPLIANCE_POSTURES:         COMPLIANCE_POSTURES,
  GuardEventBusPayloadError:   GuardEventBusPayloadError,
  NAME:                        "eventBusPayload",
  KIND:                        "event-bus-payload",
};
