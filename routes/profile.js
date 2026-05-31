var b = require("../lib/vendor/blamejs");
var rateLimit = require("../lib/rate-limit");
var audit = require("../lib/audit");
var C = require("../lib/constants");
var config = require("../lib/config");
var logger = require("../app/shared/logger");
var usersRepo = require("../app/data/repositories/users.repo");
var { isAdmin } = require("../app/shared/authz");
var filesRepo = require("../app/data/repositories/files.repo");
var credentialsRepo = require("../app/data/repositories/credentials.repo");
;
var { validateEmail, validatePassword } = require("../app/shared/validate");
var requireAuth = require("../middleware/require-auth");
var { send } = require("../middleware/send");
var sessionService = require("../app/domain/auth/session.service");
var { AppError, ValidationError, AuthenticationError } = require("../app/shared/errors");

module.exports = function (app) {
  // Profile page
  app.get("/profile", (req, res) => {
    if (!requireAuth(req, res)) return;
    send(res, "profile", { user: req.user, passkeyEnabled: config.passkeyEnabled });
  });

  // Update display name
  app.post("/profile/update", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      var displayName = String(body.displayName || "").slice(0, 100);
      if (!displayName) throw new ValidationError("Display name is required.");
      usersRepo.update(req.user._id, { $set: { displayName: displayName } });
      audit.log(audit.ACTIONS.DISPLAY_NAME_CHANGED, { targetId: req.user._id, targetEmail: req.user.email, details: "new name: " + displayName, req: req });
      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Profile update error", { error: e.message || String(e) });
      throw new AppError("Failed to update profile.", 500);
    }
  });

  // Change password (local auth only)
  app.post("/profile/password", rateLimit.guard({ scope: "password-change", max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!config.localAuth) throw new ValidationError("Password authentication is disabled.");
    try {
      var body = (await b.parsers.json(req)) || {};
      var currentPassword = String(body.currentPassword || "");
      var newPassword = String(body.newPassword || "");
      if (!currentPassword || !newPassword) throw new ValidationError("Current and new password are required.");
      var pwCheck = validatePassword(newPassword);
      if (!pwCheck.valid) throw new ValidationError(pwCheck.reason);
      if (req.user.authType !== "local") throw new ValidationError("Password change only available for local accounts.");

      var valid = await b.auth.password.verify(req.user.passwordHash, currentPassword);
      if (!valid) throw new AuthenticationError("Current password is incorrect.");

      var passwordHash = await b.auth.password.hash(newPassword);
      usersRepo.update(req.user._id, { $set: { passwordHash: passwordHash } });

      // Invalidate all other sessions for this user, then re-establish current
      await sessionService.revokeUser(req.user._id);
      await sessionService.loginUser(req, req.user._id);

      audit.log(audit.ACTIONS.PASSWORD_CHANGED, { targetId: req.user._id, targetEmail: req.user.email, req: req });

      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Password change error", { error: e.message || String(e) });
      throw new AppError("Failed to change password.", 500);
    }
  });

  // Change email (requires password re-authentication)
  app.post("/profile/email", rateLimit.guard({ scope: "email-change", max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      var password = String(body.password || "");
      var emailCheck = validateEmail(body.newEmail);
      if (!emailCheck.valid) throw new ValidationError(emailCheck.reason);
      var newEmail = emailCheck.email;
      if (!password) throw new ValidationError("Current password required.");
      if (req.user.authType !== "local") throw new ValidationError("Email change only available for local accounts.");

      var valid = await b.auth.password.verify(req.user.passwordHash, password);
      if (!valid) throw new AuthenticationError("Password is incorrect.");

      // Check for duplicate
      var existing = usersRepo.findByEmail(newEmail);
      if (existing && existing._id !== req.user._id) throw new ValidationError("Email already in use.");

      var oldEmail = req.user.email;
      usersRepo.update(req.user._id, { $set: { email: newEmail } });

      audit.log(audit.ACTIONS.EMAIL_CHANGED, { targetId: req.user._id, targetEmail: newEmail, details: "old: " + oldEmail, req: req });
      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Email change error", { error: e.message || String(e) });
      throw new AppError("Failed to change email.", 500);
    }
  });

  // Delete own account
  app.post("/profile/delete", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      if (body.confirm !== "DELETE") throw new ValidationError("Type DELETE to confirm.");

      if (isAdmin(req.user)) {
        var adminCount = usersRepo.count({ role: "admin" });
        if (adminCount <= 1) throw new ValidationError("Cannot delete the last admin account.");
      }

      var userFiles = filesRepo.findAll({ uploadedBy: req.user._id });
      var count = userFiles.length;
      for (var f of userFiles) {
        filesRepo.update(f._id, { $set: { uploadedBy: "deleted", uploaderName: req.user.displayName + " (deleted)" } });
      }

      usersRepo.remove(req.user._id);
      credentialsRepo.removeByUser(req.user._id);
      await sessionService.revokeUser(req.user._id);
      await sessionService.logoutUser(req);

      audit.log(audit.ACTIONS.ACCOUNT_SELF_DELETED, { targetId: req.user._id, targetEmail: req.user.email, details: "filesReassigned: " + count, req: req });

      res.json({ success: true, redirect: "/" });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Account delete error", { error: e.message || String(e) });
      throw new AppError("Failed to delete account.", 500);
    }
  });
};
