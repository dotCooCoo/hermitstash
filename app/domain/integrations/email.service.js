/**
 * Email Service — thin wrapper over lib/email for the service layer.
 * Future: add queue-based sending, retry logic, template rendering.
 */
var email = require("../../../lib/email");

module.exports = {
  sendVerificationEmail: email.sendVerificationEmail,
  sendInviteEmail: email.sendInviteEmail,
  sendUploaderConfirmation: email.sendUploaderConfirmation,
  sendAdminNotification: email.sendAdminNotification,
  sendPasswordResetEmail: email.sendPasswordResetEmail,
};
