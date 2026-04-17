/**
 * Settings schema — type definitions, sanitization, and validation for all admin-changeable settings.
 *
 * Every setting in config.js settingsMap has a corresponding schema entry here.
 * The schema is used on SAVE (reject bad data at the gate) and on LOAD (defensive fallback).
 *
 * Types: string, number, boolean, url, hostname, enum, list, credential, path, css, multiline
 */

// ---- Sanitization helpers ----

// Strip ASCII control characters (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F) but preserve LF (0x0A) and CR (0x0D) for multiline
var CONTROL_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F]/g;

function stripControls(s) {
  return typeof s === "string" ? s.replace(CONTROL_RE, "") : String(s || "");
}

function sanitizeString(v) {
  return stripControls(String(v || "")).trim();
}

function sanitizeMultiline(v) {
  return stripControls(String(v || "")).trim();
}

// ---- Validation helpers ----

function isValidUrl(v) {
  if (!v) return true; // empty = disabled
  try { var u = new URL(v); return u.protocol === "http:" || u.protocol === "https:"; } catch (_e) { return false; }
}

function isValidHostname(v) {
  if (!v) return true;
  return /^[a-z0-9][a-z0-9.\-]{0,252}$/.test(v) && !/\s/.test(v);
}

function isValidCssColor(v) {
  if (!v) return true;
  return /^#[0-9a-fA-F]{3,8}$/.test(v) || /^[a-zA-Z]+$/.test(v);
}

function isValidCssFont(v) {
  if (!v) return true;
  return !/<|{|;|url\s*\(/.test(v);
}

function isValidPath(v) {
  if (!v) return true;
  return !/\x00/.test(v) && !/\.\./.test(v);
}

// ---- Schema definition ----

var SCHEMA = {
  // Free-text strings
  siteName:           { type: "string", maxLen: 200 },
  customLogo:         { type: "path", maxLen: 500 },
  dropTitle:          { type: "string", maxLen: 500 },
  dropSubtitle:       { type: "string", maxLen: 1000 },
  heroTitle:          { type: "string", maxLen: 500 },
  heroSubtitle:       { type: "string", maxLen: 1000 },
  announcementBanner: { type: "string", maxLen: 1000 },
  privacyPolicy:      { type: "multiline", maxLen: 5000 },
  termsOfService:     { type: "multiline", maxLen: 5000 },
  cookiePolicy:       { type: "multiline", maxLen: 5000 },
  analyticsScript:    { type: "multiline", maxLen: 5000 },
  analyticsCspDomains:{ type: "list", maxLen: 2000 },
  rpName:             { type: "string", maxLen: 200 },
  rpId:               { type: "hostname", maxLen: 253 },

  // Booleans
  landingEnabled:     { type: "boolean" },
  showMaintainerSupport: { type: "boolean" },
  maintenanceMode:    { type: "boolean" },
  localAuth:          { type: "boolean" },
  registrationOpen:   { type: "boolean" },
  publicUpload:       { type: "boolean" },
  emailVerification:  { type: "boolean" },
  passkeyEnabled:     { type: "boolean" },
  s3DirectDownloads:  { type: "boolean" },
  backupEnabled:      { type: "boolean" },
  setupComplete:      { type: "boolean" },

  // Numbers with ranges
  port:               { type: "number", min: 1, max: 65535 },
  sessionIdleTimeout: { type: "number", min: 60000, max: 86400000 },
  maxFileSize:        { type: "number", min: 0, max: 10737418240 },
  uploadTimeout:      { type: "number", min: 10000, max: 3600000 },
  uploadConcurrency:  { type: "number", min: 1, max: 100 },
  uploadRetries:      { type: "number", min: 0, max: 10 },
  fileExpiryDays:     { type: "number", min: 0, max: 36500 },
  storageQuotaBytes:  { type: "number", min: 0 },
  perUserQuotaBytes:  { type: "number", min: 0 },
  publicMaxFiles:     { type: "number", min: 1, max: 100000 },
  publicMaxBundleSize:{ type: "number", min: 0, max: 10737418240 },
  publicIpQuotaBytes: { type: "number", min: 0 },
  smtpPort:           { type: "number", min: 1, max: 65535 },
  resendQuotaDaily:   { type: "number", min: 0, max: 100000 },
  resendQuotaMonthly: { type: "number", min: 0, max: 1000000 },
  backupSchedule:     { type: "number", min: 3600000, max: 604800000 },
  backupRetention:    { type: "number", min: 1, max: 365 },
  s3PresignExpiry:    { type: "number", min: 60, max: 604800 },

  // URLs
  rpOrigin:           { type: "url", maxLen: 500 },
  googleCallbackURL:  { type: "url", maxLen: 500 },
  s3Endpoint:         { type: "url", maxLen: 500 },
  backupS3Endpoint:   { type: "url", maxLen: 500 },

  // Enums
  storageBackend:     { type: "enum", values: ["local", "s3"] },
  emailBackend:       { type: "enum", values: ["smtp", "resend", "smtp+resend"] },
  backupScope:        { type: "enum", values: ["db", "full"] },
  emailTemplateMode:  { type: "enum", values: ["text", "html"] },

  // Hostnames / identifiers
  s3Bucket:           { type: "hostname", maxLen: 63 },
  s3Region:           { type: "hostname", maxLen: 63 },
  backupS3Bucket:     { type: "hostname", maxLen: 63 },
  backupS3Region:     { type: "hostname", maxLen: 63 },
  smtpHost:           { type: "hostname", maxLen: 253 },
  googleClientID:     { type: "string", maxLen: 500 },

  // Credentials (trim only, no format check — providers vary)
  sessionSecret:      { type: "credential", maxLen: 500 },
  googleClientSecret: { type: "credential", maxLen: 500 },
  s3AccessKey:        { type: "credential", maxLen: 500 },
  s3SecretKey:        { type: "credential", maxLen: 500 },
  smtpUser:           { type: "credential", maxLen: 500 },
  smtpPass:           { type: "credential", maxLen: 500 },
  smtpFrom:           { type: "string", maxLen: 500 },
  resendApiKey:       { type: "credential", maxLen: 500 },
  backupS3AccessKey:  { type: "credential", maxLen: 500 },
  backupS3SecretKey:  { type: "credential", maxLen: 500 },
  backupPassphrase:   { type: "credential", maxLen: 500 },
  backupPassphraseHash: { type: "raw" }, // pre-computed hash, no sanitization

  // Comma-separated lists
  allowedDomains:     { type: "list", maxLen: 5000 },
  adminEmails:        { type: "list", maxLen: 5000 },
  allowedExtensions:  { type: "list", maxLen: 5000 },
  corsOrigins:        { type: "list", maxLen: 5000 },
  healthCorsOrigins:  { type: "list", maxLen: 5000 },

  // Paths
  uploadDir:          { type: "path", maxLen: 500 },

  // CSS / theme
  themeAccentColor:   { type: "css-color", maxLen: 50 },
  themeBgColor:       { type: "css-color", maxLen: 50 },
  themeFont:          { type: "css-font", maxLen: 200 },

  // Email templates
  emailTemplateSubject: { type: "string", maxLen: 500 },
  emailTemplateHeader:  { type: "multiline", maxLen: 5000 },
  emailTemplateFooter:  { type: "multiline", maxLen: 5000 },

  // Misc
  trustProxy:         { type: "string", maxLen: 200 },
};

// ---- Public API ----

/**
 * Sanitize a setting value by type. Always returns a clean string.
 * Applied on both save and load paths.
 */
function sanitize(key, value) {
  var schema = SCHEMA[key];
  if (!schema) return sanitizeString(value);

  switch (schema.type) {
    case "raw": return String(value || "");
    case "multiline": return sanitizeMultiline(value);
    case "hostname": return sanitizeString(value).toLowerCase();
    case "enum": return sanitizeString(value).toLowerCase();
    default: return sanitizeString(value);
  }
}

/**
 * Validate a setting value (after sanitization).
 * Returns { valid: true } or { valid: false, error: "reason" }.
 */
function validate(key, value) {
  var schema = SCHEMA[key];
  if (!schema) return { valid: true };

  // Max length check (all types)
  if (schema.maxLen && value.length > schema.maxLen) {
    return { valid: false, error: "exceeds max length of " + schema.maxLen };
  }

  switch (schema.type) {
    case "number": {
      if (value === "" || value === "0") return { valid: true };
      var n = parseInt(value, 10);
      if (isNaN(n)) return { valid: false, error: "must be a number" };
      if (schema.min !== undefined && n < schema.min) return { valid: false, error: "minimum is " + schema.min };
      if (schema.max !== undefined && n > schema.max) return { valid: false, error: "maximum is " + schema.max };
      return { valid: true };
    }
    case "boolean": {
      if (value === "" || value === "true" || value === "false") return { valid: true };
      return { valid: false, error: "must be true or false" };
    }
    case "url": {
      if (!isValidUrl(value)) return { valid: false, error: "invalid URL" };
      return { valid: true };
    }
    case "hostname": {
      if (!isValidHostname(value)) return { valid: false, error: "invalid hostname" };
      return { valid: true };
    }
    case "enum": {
      if (value === "") return { valid: true };
      if (schema.values.indexOf(value) === -1) return { valid: false, error: "must be one of: " + schema.values.join(", ") };
      return { valid: true };
    }
    case "path": {
      if (!isValidPath(value)) return { valid: false, error: "invalid path (no .. or null bytes)" };
      return { valid: true };
    }
    case "css-color": {
      if (!isValidCssColor(value)) return { valid: false, error: "invalid color (use #hex or color name)" };
      return { valid: true };
    }
    case "css-font": {
      if (!isValidCssFont(value)) return { valid: false, error: "font name cannot contain <, {, ;, or url()" };
      return { valid: true };
    }
    default:
      return { valid: true };
  }
}

/**
 * Sanitize and validate a setting. Returns { value, error }.
 * If error is set, the value should be rejected.
 */
function sanitizeAndValidate(key, value) {
  var cleaned = sanitize(key, value);
  var result = validate(key, cleaned);
  if (!result.valid) return { value: cleaned, error: result.error };
  return { value: cleaned, error: null };
}

module.exports = { sanitize: sanitize, validate: validate, sanitizeAndValidate: sanitizeAndValidate, stripControls: stripControls, SCHEMA: SCHEMA };
