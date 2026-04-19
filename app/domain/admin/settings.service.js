/**
 * Settings Service — business logic for admin settings management.
 * Wraps config.getSettings / config.updateSettings with audit-friendly return values.
 */
var config = require("../../../lib/config");
var { ValidationError } = require("../../shared/errors");

/**
 * Get all settings with sensitive values masked.
 * Returns a plain object suitable for JSON response.
 */
function getAllSettings() {
  return config.getSettings();
}

/**
 * Update settings from an admin-submitted changes object.
 * Delegates validation and auth-lockout prevention to config.updateSettings.
 *
 * Returns { updated: string[], restart: boolean, warnings: string[] }.
 * Throws Error if the update would lock out all auth methods.
 */
function updateSettings(changes) {
  if (!changes || typeof changes !== "object") {
    throw new ValidationError("Settings object required.");
  }

  // Strip any keys that are empty strings to avoid clearing values unintentionally.
  // Intentional clears (e.g. removing a custom logo) pass an explicit empty string
  // from the admin UI, so the caller should include those consciously.
  var result = config.updateSettings(changes);

  return {
    updated: result.updated || [],
    restart: !!result.restart,
    warnings: result.warnings || [],
  };
}

/**
 * Build a summary string for audit logging after a settings change.
 */
function buildAuditDetails(result) {
  var msg = "changed: " + result.updated.join(", ");
  if (result.restart) msg += " (restart needed)";
  return msg;
}

module.exports = {
  getAllSettings: getAllSettings,
  updateSettings: updateSettings,
  buildAuditDetails: buildAuditDetails,
};
