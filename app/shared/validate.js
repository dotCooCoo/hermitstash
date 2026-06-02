/**
 * Shared validation utilities — centralized email, URL, and input validation.
 * All auth/profile/admin/invite flows should use these.
 */

// Simple email check — no nested quantifiers to avoid ReDoS
var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Validate an email address.
 * Returns { valid: true, email: normalized } or { valid: false, reason: string }.
 */
function validateEmail(email) {
  if (!email || typeof email !== "string") return { valid: false, reason: "Email is required." };
  // Refuse control bytes on the RAW value before trim(): an addr-spec
  // permits none, and checking the trimmed value would let edge C0/DEL
  // bytes slip past the format regex.
  for (var ci = 0; ci < email.length; ci++) {
    var cc = email.charCodeAt(ci);
    if (cc < 32 || cc === 127) return { valid: false, reason: "Invalid email format." };
  }
  var trimmed = email.trim().toLowerCase();
  if (trimmed.length === 0) return { valid: false, reason: "Email is required." };
  if (trimmed.length > 254) return { valid: false, reason: "Email too long." };
  if (!EMAIL_RE.test(trimmed)) return { valid: false, reason: "Invalid email format." };
  // Check for consecutive dots, leading/trailing dots in local part
  var local = trimmed.split("@")[0];
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
    return { valid: false, reason: "Invalid email format." };
  }
  return { valid: true, email: trimmed };
}

/**
 * Validate a password.
 */
function validatePassword(password) {
  if (!password || typeof password !== "string") return { valid: false, reason: "Password is required." };
  if (password.length < 8) return { valid: false, reason: "Password must be at least 8 characters." };
  if (password.length > 256) return { valid: false, reason: "Password too long." };
  return { valid: true };
}

/**
 * Validate a display name.
 */
function validateDisplayName(name) {
  if (!name || typeof name !== "string") return { valid: false, reason: "Name is required." };
  var trimmed = name.trim().slice(0, 100);
  if (trimmed.length === 0) return { valid: false, reason: "Name is required." };
  return { valid: true, name: trimmed };
}

/**
 * Validate a bearer token format.
 */
function validateBearerToken(token) {
  if (!token || typeof token !== "string") return false;
  if (token.length < 16 || token.length > 512) return false;
  return /^[a-zA-Z0-9._\-]+$/.test(token);
}

module.exports = { validateEmail, validatePassword, validateDisplayName, validateBearerToken };
