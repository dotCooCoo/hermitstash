/**
 * Admin request validators — input normalization for admin routes.
 * Validates settings updates, user management actions, and export parameters.
 */
var { validateEmail } = require("../../shared/validate");

// Roles the admin can assign via invite or role toggle
var VALID_ROLES = ["user", "admin"];

// Export types available from the admin panel
var VALID_EXPORT_TYPES = ["users", "files"];

/**
 * Validate a settings update payload.
 * Sanitizes and validates each field against the settings schema.
 * Returns { error } or { settings }.
 */
function validateSettingsInput(body) {
  if (!body || typeof body !== "object") return { error: "Settings object required." };

  var keys = Object.keys(body);
  if (keys.length === 0) return { error: "No settings provided." };
  if (keys.length > 100) return { error: "Too many settings." };

  // String-value length guard (raw, before sanitization)
  for (var i = 0; i < keys.length; i++) {
    var val = body[keys[i]];
    if (typeof val === "string" && val.length > 10000) {
      return { error: "Value too long for key: " + keys[i] };
    }
  }

  // Per-field sanitization and validation via settings-schema
  var schema = require("../../../lib/settings-schema");
  var cleaned = {};
  var errors = [];
  for (var j = 0; j < keys.length; j++) {
    var key = keys[j];
    // Skip masked sensitive values (handled by config.updateSettings)
    if (/^\u2022+$/.test(body[key])) { cleaned[key] = body[key]; continue; }
    var result = schema.sanitizeAndValidate(key, body[key]);
    if (result.error) {
      errors.push(key + ": " + result.error);
    } else {
      cleaned[key] = result.value;
    }
  }

  if (errors.length > 0) return { error: errors.join("; ") };

  // Cross-field guard: refuse a save that enables backups without a
  // passphrase being configured. This catches the scenario where an
  // operator checks "Enable Backup" and saves without entering a
  // passphrase — the scheduled job would then silently no-op every
  // tick. The check is permissive: passes if EITHER (a) the new save
  // includes a non-empty passphrase, OR (b) the masked-bullets value
  // is being sent back (preserving an existing passphrase), OR
  // (c) backup.passphraseHash is already set in the running config
  // (passphrase was previously saved). Bug discovered 2026-04-22.
  if (cleaned.backupEnabled === true || cleaned.backupEnabled === "true") {
    var pwIncoming = cleaned.backupPassphrase;
    var pwIsMaskBullets = typeof pwIncoming === "string" && /^•+$/.test(pwIncoming);
    var pwIsNewValue = typeof pwIncoming === "string" && pwIncoming.length > 0 && !pwIsMaskBullets;
    if (!pwIsMaskBullets && !pwIsNewValue) {
      var config = require("../../../lib/config");
      var hasExisting = !!(config.backup && config.backup.passphraseHash);
      if (!hasExisting) {
        return { error: "Backup is enabled but no passphrase has been set. Enter a passphrase before saving." };
      }
    }
  }

  return { settings: cleaned };
}

/**
 * Validate an invite-user payload.
 * Returns { error } or { email, role }.
 */
function validateInviteInput(body) {
  if (!body) return { error: "Request body required." };

  var emailResult = validateEmail(body.email);
  if (!emailResult.valid) return { error: emailResult.reason };

  var role = String(body.role || "user").toLowerCase();
  if (VALID_ROLES.indexOf(role) === -1) {
    return { error: "Invalid role. Must be one of: " + VALID_ROLES.join(", ") };
  }

  return { email: emailResult.email, role: role };
}

/**
 * Validate a role-change request (toggle between user and admin).
 * Only verifies the target user ID is present.
 * Returns { error } or { userId }.
 */
function validateRoleChangeInput(userId) {
  if (!userId || typeof userId !== "string") return { error: "User ID required." };
  if (userId.length > 64) return { error: "Invalid user ID." };
  return { userId: userId };
}

/**
 * Validate a suspend/unsuspend request.
 * Returns { error } or { userId }.
 */
function validateSuspendInput(userId) {
  if (!userId || typeof userId !== "string") return { error: "User ID required." };
  if (userId.length > 64) return { error: "Invalid user ID." };
  return { userId: userId };
}

/**
 * Validate a user-delete request.
 * Returns { error } or { userId }.
 */
function validateDeleteUserInput(userId) {
  if (!userId || typeof userId !== "string") return { error: "User ID required." };
  if (userId.length > 64) return { error: "Invalid user ID." };
  return { userId: userId };
}

/**
 * Validate export parameters (type, optional filters).
 * Returns { error } or { type }.
 */
function validateExportParams(type) {
  if (!type || typeof type !== "string") return { error: "Export type required." };
  var normalized = type.toLowerCase();
  if (VALID_EXPORT_TYPES.indexOf(normalized) === -1) {
    return { error: "Invalid export type. Must be one of: " + VALID_EXPORT_TYPES.join(", ") };
  }
  return { type: normalized };
}

/**
 * Validate pagination query parameters shared across admin API endpoints.
 * Returns { page, limit } with safe defaults and bounds.
 */
function validatePaginationParams(query) {
  query = query || {};
  var page = Math.max(1, parseInt(query.page, 10) || 1);
  var limit = Math.max(1, Math.min(200, parseInt(query.limit, 10) || 25));
  return { page: page, limit: limit };
}

/**
 * Validate an IP blocklist entry.
 * Returns { error } or { ip, reason }.
 */
function validateBlocklistInput(body) {
  if (!body) return { error: "Request body required." };
  var ip = String(body.ip || "").trim();
  if (!ip || ip.length > 45) return { error: "Valid IP required." };

  // Basic format check — IPv4 or IPv6 (simple patterns, no nested quantifiers)
  var isIpv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
  var isIpv6 = /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(":");
  if (!isIpv4 && !isIpv6) return { error: "Invalid IP format." };

  var reason = String(body.reason || "").slice(0, 500);
  return { ip: ip, reason: reason };
}

/**
 * Validate a database purge confirmation.
 * Returns { error } or { confirmed: true }.
 */
function validatePurgeConfirmation(body) {
  if (!body) return { error: "Request body required." };
  if (body.confirm !== "PURGE") return { error: "Type PURGE to confirm." };
  return { confirmed: true };
}

module.exports = {
  validateSettingsInput: validateSettingsInput,
  validateInviteInput: validateInviteInput,
  validateRoleChangeInput: validateRoleChangeInput,
  validateSuspendInput: validateSuspendInput,
  validateDeleteUserInput: validateDeleteUserInput,
  validateExportParams: validateExportParams,
  validatePaginationParams: validatePaginationParams,
  validateBlocklistInput: validateBlocklistInput,
  validatePurgeConfirmation: validatePurgeConfirmation,
};
