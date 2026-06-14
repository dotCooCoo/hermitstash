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
var gateContract = require("./gate-contract");

var GuardEventBusTopicError = defineClass("GuardEventBusTopicError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxBytes: 128, minDots: 2 },
  balanced:   { maxBytes: 256, minDots: 2 },
  permissive: { maxBytes: 512, minDots: 1 },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

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

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardEventBusTopicError,
  codePrefix: "event-bus-topic",
});

module.exports = gateContract.defineParser({
  name:       "event-bus-topic",
  entry:      validate,
  errorClass: GuardEventBusTopicError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    RESERVED_PREFIXES: RESERVED_PREFIXES,
    NAME:              "eventBusTopic",
    KIND:              "event-bus-topic",
  },
});
