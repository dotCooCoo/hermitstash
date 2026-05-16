"use strict";
/**
 * @module     b.guardTenantId
 * @nav        Guards
 * @title      Guard Tenant Id
 * @order      440
 *
 * @intro
 *   Tenant-id shape validator. Tenant ids surface in audit log lines,
 *   sealed registry rows, derived-key context labels, and routing
 *   keys — they have to be ASCII-greppable across the whole framework
 *   stack. Refuses:
 *
 *     - non-ASCII (NFC + ASCII-only)
 *     - path-traversal shapes (`..` / `/` / `\` / NUL / C0 / DEL)
 *     - oversized (default 64 bytes)
 *     - reserved `ROOT` / `FRAMEWORK` / `*` / empty
 *     - leading `.` (hidden-folder shape)
 *
 * @card
 *   Validates tenant-id strings. ASCII-only, bounded, no path-
 *   traversal, no reserved names.
 */

var { defineClass } = require("./framework-error");

var GuardTenantIdError = defineClass("GuardTenantIdError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxBytes: 64  },                                                                      // allow:raw-byte-literal
  balanced:   { maxBytes: 128 },                                                                      // allow:raw-byte-literal
  permissive: { maxBytes: 512 },                                                                      // allow:raw-byte-literal
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

var RESERVED = Object.freeze({ "ROOT": true, "FRAMEWORK": true, "*": true });

/**
 * @primitive b.guardTenantId.validate
 * @signature b.guardTenantId.validate(tenantId, opts?)
 * @since     0.9.26
 * @status    stable
 * @related   b.agent.tenant.create
 *
 * Validate a tenant-id string. Returns the id on success; throws
 * `GuardTenantIdError` on refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardTenantId.validate("acme-clinic");
 */
function validate(tenantId, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (typeof tenantId !== "string" || tenantId.length === 0) {
    throw new GuardTenantIdError("tenant-id/bad-input",
      "guardTenantId.validate: tenantId must be a non-empty string");
  }
  if (Buffer.byteLength(tenantId, "utf8") > profile.maxBytes) {
    throw new GuardTenantIdError("tenant-id/oversize",
      "guardTenantId.validate: tenantId exceeds maxBytes=" + profile.maxBytes);
  }
  if (RESERVED[tenantId]) {
    throw new GuardTenantIdError("tenant-id/reserved",
      "guardTenantId.validate: tenantId '" + tenantId + "' is framework-reserved");
  }
  if (tenantId.charAt(0) === ".") {
    throw new GuardTenantIdError("tenant-id/hidden",
      "guardTenantId.validate: tenantId cannot start with '.'");
  }
  if (tenantId.indexOf("..") >= 0) {
    throw new GuardTenantIdError("tenant-id/path-traversal",
      "guardTenantId.validate: tenantId contains '..'");
  }
  for (var i = 0; i < tenantId.length; i += 1) {
    var c = tenantId.charCodeAt(i);
    if (c > 0x7F) {                                                                                   // allow:raw-byte-literal — ASCII-only cap
      throw new GuardTenantIdError("tenant-id/non-ascii",
        "guardTenantId.validate: non-ASCII codepoint at offset " + i);
    }
    if (c < 0x20 || c === 0x7F || c === 0x2F || c === 0x5C) {                                         // allow:raw-byte-literal — C0/DEL/slash/backslash
      throw new GuardTenantIdError("tenant-id/bad-char",
        "guardTenantId.validate: forbidden char 0x" + c.toString(16) + " at offset " + i);
    }
  }
  return tenantId;
}

/**
 * @primitive b.guardTenantId.compliancePosture
 * @signature b.guardTenantId.compliancePosture(posture)
 * @since     0.9.26
 * @status    stable
 *
 * Return the effective profile for a given compliance posture name.
 * Returns `null` for unknown posture names so operator typos surface
 * here instead of silently falling through to the default profile.
 *
 * @example
 *   b.guardTenantId.compliancePosture("hipaa");   // → "strict"
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
    throw new GuardTenantIdError("tenant-id/bad-profile",
      "guardTenantId: unknown profile '" + p + "'");
  }
  return p;
}

module.exports = {
  validate:               validate,
  compliancePosture:      compliancePosture,
  PROFILES:               PROFILES,
  COMPLIANCE_POSTURES:    COMPLIANCE_POSTURES,
  RESERVED:               RESERVED,
  GuardTenantIdError:     GuardTenantIdError,
  NAME:                   "tenantId",
  KIND:                   "tenant-id",
};
