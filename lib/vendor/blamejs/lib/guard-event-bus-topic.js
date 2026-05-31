"use strict";
/**
 * @module     b.guardEventBusTopic
 * @nav        Guards
 * @title      Guard Event Bus Topic
 * @order      438
 *
 * @intro
 *   Topic name validator for `b.agent.eventBus.registerTopic` /
 *   `publish` / `subscribe`. Refuses:
 *
 *     - dot-count < 3 (operators must use `<domain>.<source>.<event>`
 *       shape so topic names are greppable + namespace-prefixed —
 *       `mail.scan.malware-detected` not `malware`)
 *     - non-ASCII (NFC + ASCII-only — operator-greppable across
 *       audit logs + JMAP wire + cross-process)
 *     - oversized (default 128 bytes — events are metadata, not bulk
 *       data; long names defeat the greppability rationale)
 *     - reserved `framework.*` prefix from operator code
 *     - path-traversal shapes (`..` / `/` / `\` / NUL / C0)
 *
 * @card
 *   Validates `b.agent.eventBus` topic names. Dot-count, ASCII,
 *   reserved-prefix, path-traversal refusal.
 */

var { defineClass } = require("./framework-error");

var GuardEventBusTopicError = defineClass("GuardEventBusTopicError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxBytes: 128, minDots: 2 },
  balanced:   { maxBytes: 256, minDots: 2 },
  permissive: { maxBytes: 512, minDots: 1 },
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

var RESERVED_PREFIXES = Object.freeze(["framework.", "FRAMEWORK."]);

/**
 * @primitive b.guardEventBusTopic.validate
 * @signature b.guardEventBusTopic.validate(name, opts?)
 * @since     0.9.25
 * @status    stable
 * @related   b.agent.eventBus.create
 *
 * Validate an event-bus topic name. Returns the name on success;
 * throws `GuardEventBusTopicError` on refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardEventBusTopic.validate("mail.scan.malware-detected");
 */
function validate(name, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (typeof name !== "string" || name.length === 0) {
    throw new GuardEventBusTopicError("event-bus-topic/bad-input",
      "guardEventBusTopic.validate: name must be a non-empty string");
  }
  if (Buffer.byteLength(name, "utf8") > profile.maxBytes) {
    throw new GuardEventBusTopicError("event-bus-topic/oversize",
      "guardEventBusTopic.validate: name exceeds maxBytes=" + profile.maxBytes);
  }
  // Dot-count check — `<domain>.<source>.<event>` shape.
  var dots = 0;
  for (var d = 0; d < name.length; d += 1) if (name.charCodeAt(d) === 0x2E) dots += 1;                // '.' codepoint
  if (dots < profile.minDots) {
    throw new GuardEventBusTopicError("event-bus-topic/insufficient-dots",
      "guardEventBusTopic.validate: name '" + name + "' has " + dots +
      " dots; minimum " + profile.minDots + " required (use <domain>.<source>.<event> shape)");
  }
  // Reserved prefix refusal.
  for (var r = 0; r < RESERVED_PREFIXES.length; r += 1) {
    if (name.indexOf(RESERVED_PREFIXES[r]) === 0) {
      throw new GuardEventBusTopicError("event-bus-topic/reserved-prefix",
        "guardEventBusTopic.validate: name '" + name + "' uses reserved prefix '" +
        RESERVED_PREFIXES[r] + "'");
    }
  }
  // Path-traversal refusal.
  if (name.indexOf("..") >= 0) {
    throw new GuardEventBusTopicError("event-bus-topic/path-traversal",
      "guardEventBusTopic.validate: name contains '..'");
  }
  // C0 / DEL / slash / non-ASCII refusal.
  for (var i = 0; i < name.length; i += 1) {
    var c = name.charCodeAt(i);
    if (c > 0x7F) {                                                                                   // ASCII-only cap
      throw new GuardEventBusTopicError("event-bus-topic/non-ascii",
        "guardEventBusTopic.validate: name contains non-ASCII codepoint at offset " + i);
    }
    if (c < 0x20 || c === 0x7F || c === 0x2F || c === 0x5C) {                                         // C0/DEL/slash/backslash
      throw new GuardEventBusTopicError("event-bus-topic/bad-char",
        "guardEventBusTopic.validate: forbidden char 0x" + c.toString(16) + " at offset " + i);
    }
  }
  return name;
}

/**
 * @primitive b.guardEventBusTopic.compliancePosture
 * @signature b.guardEventBusTopic.compliancePosture(posture)
 * @since     0.9.25
 * @status    stable
 *
 * Return the effective profile for a given compliance posture name.
 * Returns `null` for unknown posture names so operator typos surface
 * here instead of silently falling through to the default profile.
 *
 * @example
 *   b.guardEventBusTopic.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return COMPLIANCE_POSTURES[opts.posture];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardEventBusTopicError("event-bus-topic/bad-profile",
      "guardEventBusTopic: unknown profile '" + p + "'");
  }
  return p;
}

module.exports = {
  validate:                  validate,
  compliancePosture:         compliancePosture,
  PROFILES:                  PROFILES,
  COMPLIANCE_POSTURES:       COMPLIANCE_POSTURES,
  RESERVED_PREFIXES:         RESERVED_PREFIXES,
  GuardEventBusTopicError:   GuardEventBusTopicError,
  NAME:                      "eventBusTopic",
  KIND:                      "event-bus-topic",
};
