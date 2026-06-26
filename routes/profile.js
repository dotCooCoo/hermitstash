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
var { validateEmail, validatePassword } = require("../app/shared/validate");
var requireAuth = require("../middleware/require-auth");
var { send, host } = require("../middleware/send");
var sessionService = require("../app/domain/auth/session.service");
var verificationRoutes = require("./verification");
var emailService = require("../lib/email");
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
  app.post("/profile/password", rateLimit.guard({ max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async (req, res) => {
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
  app.post("/profile/email", rateLimit.guard({ max: 5, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" }), async (req, res) => {
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

      var oldEmail = req.user.email;
      if (newEmail === oldEmail) throw new ValidationError("New email matches the current one.");

      // Reject a change to an address already tied to another account.
      var existing = usersRepo.findByEmail(newEmail);
      if (existing && existing._id !== req.user._id) throw new ValidationError("Email already in use.");

      // Reject a change to an address with outstanding anonymous public uploads.
      // Repointing an account at such an address must not be able to silently arm a
      // future ownership claim of those uploads (see routes/dashboard.js); ownership
      // of a stranger's anonymous uploads is never conferred by an email edit.
      var pendingClaims = filesRepo.findAll({ uploaderEmail: newEmail, uploadedBy: "public" });
      if (pendingClaims.length > 0) {
        throw new ValidationError("That address has pending anonymous uploads and can't be claimed by changing your email.");
      }

      // Proof-of-control: when email verification is operative, STAGE the new
      // address in pendingEmail and require a verification round-trip before it
      // takes effect. The account's live email (and login identity) stays the OLD,
      // already-verified address until the holder proves control of the new one by
      // following the link mailed to it — so a mistyped change can never lock the
      // holder out, and an unverified address never becomes the account email (so it
      // can never arm an ownership claim, see routes/dashboard.js). Confirming the
      // token (/auth/verify/:token) commits pendingEmail -> email. The session and
      // old email remain valid throughout; no demotion, no forced logout.
      if (config.emailVerification) {
        usersRepo.update(req.user._id, { $set: { pendingEmail: newEmail } });

        var rawToken = verificationRoutes.createVerificationToken(req.user._id);
        var verifyUrl = host(req) + "/auth/verify/" + rawToken;
        try {
          await emailService.sendVerificationEmail({ to: newEmail, displayName: req.user.displayName, verifyUrl: verifyUrl });
        } catch (emailErr) {
          logger.error("Email change verification send failed", { error: emailErr.message || String(emailErr) });
        }

        audit.log(audit.ACTIONS.EMAIL_CHANGED, { targetId: req.user._id, targetEmail: newEmail, details: "old: " + oldEmail + ", staged pending verification of the new address", req: req });
        audit.log(audit.ACTIONS.EMAIL_VERIFICATION_SENT, { targetId: req.user._id, targetEmail: newEmail, req: req });
        return res.json({ success: true, pending: true, message: "A confirmation link was sent to " + newEmail + ". Your email changes once you confirm it; your current address stays in effect until then." });
      }

      // Verification disabled: parity with registration's active path — a direct
      // write is acceptable because no verified-email signal exists in this mode, so
      // the address can never arm an ownership claim regardless.
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
