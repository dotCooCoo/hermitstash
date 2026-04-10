/**
 * Auth request validators — input normalization for auth routes.
 */
var { validateEmail, validatePassword, validateDisplayName } = require("../../shared/validate");

/**
 * Validate login request body.
 */
function validateLoginInput(body) {
  if (!body) return { error: "Request body required." };
  var email = String(body.email || "");
  var password = String(body.password || "");
  if (!email || !password) return { error: "Email and password required." };
  return { email: email, password: password };
}

/**
 * Validate registration request body.
 */
function validateRegisterInput(body) {
  if (!body) return { error: "Request body required." };
  var nameResult = validateDisplayName(body.displayName);
  if (!nameResult.valid) return { error: nameResult.reason };
  var emailResult = validateEmail(body.email);
  if (!emailResult.valid) return { error: emailResult.reason };
  var pwResult = validatePassword(body.password);
  if (!pwResult.valid) return { error: pwResult.reason };
  return { displayName: nameResult.name, email: emailResult.email, password: String(body.password) };
}

module.exports = { validateLoginInput, validateRegisterInput };
