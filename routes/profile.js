var b = require("../lib/vendor/blamejs");
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
      if (!displayName) return res.status(400).json({ error: "Display name is required." });
      usersRepo.update(req.user._id, { $set: { displayName: displayName } });
      audit.log(audit.ACTIONS.DISPLAY_NAME_CHANGED, { targetId: req.user._id, targetEmail: req.user.email, details: "new name: " + displayName, req: req });
      res.json({ success: true });
    } catch (e) {
      logger.error("Profile update error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to update profile." });
    }
  });

  // Change password (local auth only)
  app.post("/profile/password", b.middleware.rateLimit({ scope: "password-change", max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!config.localAuth) return res.status(400).json({ error: "Password authentication is disabled." });
    try {
      var body = (await b.parsers.json(req)) || {};
      var currentPassword = String(body.currentPassword || "");
      var newPassword = String(body.newPassword || "");
      if (!currentPassword || !newPassword) return res.status(400).json({ error: "Current and new password are required." });
      var pwCheck = validatePassword(newPassword);
      if (!pwCheck.valid) return res.status(400).json({ error: pwCheck.reason });
      if (req.user.authType !== "local") return res.status(400).json({ error: "Password change only available for local accounts." });

      var valid = await b.auth.password.verify(req.user.passwordHash, currentPassword);
      if (!valid) return res.status(401).json({ error: "Current password is incorrect." });

      var passwordHash = await b.auth.password.hash(newPassword);
      usersRepo.update(req.user._id, { $set: { passwordHash: passwordHash } });

      // Invalidate all other sessions for this user, then re-establish current
      await sessionService.revokeUser(req.user._id);
      await sessionService.loginUser(req, req.user._id);

      audit.log(audit.ACTIONS.PASSWORD_CHANGED, { targetId: req.user._id, targetEmail: req.user.email, req: req });

      res.json({ success: true });
    } catch (e) {
      logger.error("Password change error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to change password." });
    }
  });

  // Change email (requires password re-authentication)
  app.post("/profile/email", b.middleware.rateLimit({ scope: "email-change", max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      var password = String(body.password || "");
      var emailCheck = validateEmail(body.newEmail);
      if (!emailCheck.valid) return res.status(400).json({ error: emailCheck.reason });
      var newEmail = emailCheck.email;
      if (!password) return res.status(400).json({ error: "Current password required." });
      if (req.user.authType !== "local") return res.status(400).json({ error: "Email change only available for local accounts." });

      var valid = await b.auth.password.verify(req.user.passwordHash, password);
      if (!valid) return res.status(401).json({ error: "Password is incorrect." });

      // Check for duplicate
      var existing = usersRepo.findByEmail(newEmail);
      if (existing && existing._id !== req.user._id) return res.status(400).json({ error: "Email already in use." });

      var oldEmail = req.user.email;
      usersRepo.update(req.user._id, { $set: { email: newEmail } });

      audit.log(audit.ACTIONS.EMAIL_CHANGED, { targetId: req.user._id, targetEmail: newEmail, details: "old: " + oldEmail, req: req });
      res.json({ success: true });
    } catch (e) {
      logger.error("Email change error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to change email." });
    }
  });

  // Delete own account
  app.post("/profile/delete", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = (await b.parsers.json(req)) || {};
      if (body.confirm !== "DELETE") return res.status(400).json({ error: "Type DELETE to confirm." });

      if (isAdmin(req.user)) {
        var adminCount = usersRepo.count({ role: "admin" });
        if (adminCount <= 1) return res.status(400).json({ error: "Cannot delete the last admin account." });
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
      logger.error("Account delete error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to delete account." });
    }
  });
};
