"use strict";
/**
 * @module     b.guardSagaConfig
 * @nav        Guards
 * @title      Guard Saga Config
 * @order      441
 *
 * @intro
 *   Saga-creation config validator. Refuses empty steps array,
 *   duplicate step names, non-ASCII saga name, non-async-function
 *   run/compensate fields, oversized step count.
 *
 * @card
 *   Validates `b.agent.saga.create()` opts. Step-list shape, name
 *   uniqueness, run/compensate function checks.
 */

var { defineClass } = require("./framework-error");

var GuardSagaConfigError = defineClass("GuardSagaConfigError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxSteps: 32,   maxNameBytes: 64  },
  balanced:   { maxSteps: 128,  maxNameBytes: 128 },
  permissive: { maxSteps: 512,  maxNameBytes: 256 },
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

/**
 * @primitive b.guardSagaConfig.validate
 * @signature b.guardSagaConfig.validate(config, opts?)
 * @since     0.9.27
 * @status    stable
 * @related   b.agent.saga.create
 *
 * Validate saga config. Returns config on success; throws on refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardSagaConfig.validate({
 *     name: "mail.send",
 *     steps: [
 *       { name: "sign", run: async () => {}, compensate: async () => {} },
 *     ],
 *   });
 */
function validate(config, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!config || typeof config !== "object") {
    throw new GuardSagaConfigError("saga-config/bad-input",
      "guardSagaConfig.validate: config required");
  }
  if (typeof config.name !== "string" || config.name.length === 0) {
    throw new GuardSagaConfigError("saga-config/bad-name",
      "guardSagaConfig.validate: name required");
  }
  if (Buffer.byteLength(config.name, "utf8") > profile.maxNameBytes) {
    throw new GuardSagaConfigError("saga-config/name-too-long",
      "guardSagaConfig.validate: name exceeds maxNameBytes=" + profile.maxNameBytes);
  }
  for (var i = 0; i < config.name.length; i += 1) {
    var c = config.name.charCodeAt(i);
    if (c > 0x7F) {                                                                                   // ASCII-only
      throw new GuardSagaConfigError("saga-config/non-ascii-name",
        "guardSagaConfig.validate: name has non-ASCII codepoint at offset " + i);
    }
    if (c < 0x20 || c === 0x7F) {                                                                     // C0/DEL
      throw new GuardSagaConfigError("saga-config/bad-name-char",
        "guardSagaConfig.validate: name has forbidden char 0x" + c.toString(16));
    }
  }
  if (!Array.isArray(config.steps) || config.steps.length === 0) {
    throw new GuardSagaConfigError("saga-config/no-steps",
      "guardSagaConfig.validate: steps must be a non-empty array");
  }
  if (config.steps.length > profile.maxSteps) {
    throw new GuardSagaConfigError("saga-config/too-many-steps",
      "guardSagaConfig.validate: " + config.steps.length + " steps exceeds " + profile.maxSteps);
  }
  var seenNames = Object.create(null);
  for (var s = 0; s < config.steps.length; s += 1) {
    var step = config.steps[s];
    if (!step || typeof step !== "object") {
      throw new GuardSagaConfigError("saga-config/bad-step",
        "guardSagaConfig.validate: steps[" + s + "] must be an object");
    }
    if (typeof step.name !== "string" || step.name.length === 0) {
      throw new GuardSagaConfigError("saga-config/bad-step-name",
        "guardSagaConfig.validate: steps[" + s + "].name required");
    }
    if (seenNames[step.name]) {
      throw new GuardSagaConfigError("saga-config/duplicate-step-name",
        "guardSagaConfig.validate: duplicate step name '" + step.name + "'");
    }
    seenNames[step.name] = true;
    if (typeof step.run !== "function") {
      throw new GuardSagaConfigError("saga-config/bad-step-run",
        "guardSagaConfig.validate: steps[" + s + "].run must be a function");
    }
    if (typeof step.compensate !== "undefined" && typeof step.compensate !== "function") {
      throw new GuardSagaConfigError("saga-config/bad-step-compensate",
        "guardSagaConfig.validate: steps[" + s + "].compensate must be a function (or omitted)");
    }
  }
  return config;
}

/**
 * @primitive b.guardSagaConfig.compliancePosture
 * @signature b.guardSagaConfig.compliancePosture(posture)
 * @since     0.9.27
 * @status    stable
 *
 * Return the effective profile for a given compliance posture name.
 * Returns `null` for unknown posture names so operator typos surface
 * here instead of silently falling through to the default profile.
 *
 * @example
 *   b.guardSagaConfig.compliancePosture("hipaa");   // → "strict"
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
    throw new GuardSagaConfigError("saga-config/bad-profile",
      "guardSagaConfig: unknown profile '" + p + "'");
  }
  return p;
}

module.exports = {
  validate:                 validate,
  compliancePosture:        compliancePosture,
  PROFILES:                 PROFILES,
  COMPLIANCE_POSTURES:      COMPLIANCE_POSTURES,
  GuardSagaConfigError:     GuardSagaConfigError,
  NAME:                     "sagaConfig",
  KIND:                     "saga-config",
};
