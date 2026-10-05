/**
 * Auth request validators — input normalization for auth routes.
 */
var b = require("../../../lib/vendor/blamejs");
var { validateEmail, validatePassword, validateDisplayName, EMAIL_MAX_LENGTH } = require("../../shared/validate");

/**
 * Validate login request body.
 * Returns { error } when the email or the password is missing. An email longer
 * than EMAIL_MAX_LENGTH characters, or one that contains a control character,
 * comes back as email null with its length in emailLength. No account holds
 * such an address, and the login route answers it the way it answers an
 * unknown account.
 */
function validateLoginInput(body) {
  if (!body) return { error: "Request body required." };
  var email = String(body.email || "");
  var password = String(body.password || "");
  if (!email || !password) return { error: "Email and password required." };
  if (email.length > EMAIL_MAX_LENGTH ||
      b.codepointClass.firstControlCharOffset(email, { forbidTab: true }) !== -1) {
    return { email: null, emailLength: email.length, password: password };
  }
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
