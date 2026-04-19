var config = require("../lib/config");
var C = require("../lib/constants");
var logger = require("../app/shared/logger");
var usersRepo = require("../app/data/repositories/users.repo");
var verificationTokensRepo = require("../app/data/repositories/verificationTokens.repo");
var { sha3Hash, generateToken, hashPassword } = require("../lib/crypto");
var { sendPasswordResetEmail } = require("../lib/email");
var { validateEmail, validatePassword } = require("../app/shared/validate");
var audit = require("../lib/audit");
var rateLimit = require("../lib/rate-limit");
var { send, host } = require("../middleware/send");
var { parseJson } = require("../lib/multipart");
var sessionService = require("../app/domain/auth/session.service");

module.exports = function (app) {
  // GET /auth/forgot-password — show the forgot password form
  app.get("/auth/forgot-password", function (req, res) {
    if (!config.localAuth) {
      return send(res, "error", { user: null, title: "Disabled", message: "Password reset is not available." }, 403);
    }
    if (req.user) return res.redirect("/dashboard");
    send(res, "forgot-password", { user: null });
  });

  // POST /auth/forgot-password — rate limited, generate reset token, send email
  app.post("/auth/forgot-password", rateLimit.middleware("password-reset", 5, C.TIME.FIFTEEN_MIN), async function (req, res) {
    if (!config.localAuth) return res.status(403).json({ error: "Disabled." });

    try {
      var body = await parseJson(req);
      var emailCheck = validateEmail(body.email);
      if (!emailCheck.valid) {
        // Always return success to avoid email enumeration
        return res.json({ success: true });
      }

      var user = usersRepo.findByEmail(emailCheck.email);

      // Always return success — don't reveal if email exists
      if (!user || user.authType !== "local" || !user.passwordHash) {
        audit.log(audit.ACTIONS.PASSWORD_RESET_REQUESTED, { details: "No matching local account", req: req });
        return res.json({ success: true });
      }

      // Block reset for suspended users silently
      if (user.status === "suspended") {
        audit.log(audit.ACTIONS.PASSWORD_RESET_REQUESTED, { targetId: user._id, targetEmail: user.email, details: "Suspended account", req: req });
        return res.json({ success: true });
      }

      // Clean up any existing password_reset tokens for this user
      verificationTokensRepo.remove({ userId: user._id, type: "password_reset" });

      // Generate and store hashed token
      var rawToken = generateToken();
      var tokenHash = sha3Hash(rawToken);
      var expiresAt = new Date(Date.now() + C.TIME.ONE_HOUR).toISOString(); // 1 hour

      verificationTokensRepo.create({
        userId: user._id,
        token: tokenHash,
        type: "password_reset",
        expiresAt: expiresAt,
        createdAt: new Date().toISOString(),
      });

      // Send reset email
      var resetUrl = host(req) + "/auth/reset-password/" + rawToken;
      await sendPasswordResetEmail({ to: user.email, resetUrl: resetUrl });

      audit.log(audit.ACTIONS.PASSWORD_RESET_REQUESTED, { targetId: user._id, targetEmail: user.email, details: "Reset email sent", req: req });
      res.json({ success: true });
    } catch (e) {
      logger.error("Password reset request error", { error: e.message || String(e) });
      res.json({ success: true }); // Don't leak errors
    }
  });

  // GET /auth/reset-password/:token — validate token and show reset form
  app.get("/auth/reset-password/:token", function (req, res) {
    if (!config.localAuth) {
      return send(res, "error", { user: null, title: "Disabled", message: "Password reset is not available." }, 403);
    }

    var rawToken = req.params.token;
    if (!rawToken || rawToken.length !== 64) {
      return send(res, "error", { user: null, title: "Invalid Link", message: "This password reset link is invalid." }, 400);
    }

    var tokenHash = sha3Hash(rawToken);
    var record = verificationTokensRepo.findOne({ token: tokenHash, type: "password_reset" });

    if (!record) {
      audit.log(audit.ACTIONS.PASSWORD_RESET_FAILED, { details: "Invalid token", req: req });
      return send(res, "error", { user: null, title: "Invalid Link", message: "This password reset link is invalid or has already been used." }, 400);
    }

    if (new Date(record.expiresAt) < new Date()) {
      verificationTokensRepo.remove(record._id);
      audit.log(audit.ACTIONS.PASSWORD_RESET_FAILED, { details: "Expired token", targetId: record.userId, req: req });
      return send(res, "error", { user: null, title: "Link Expired", message: "This password reset link has expired. Please request a new one." }, 400);
    }

    send(res, "reset-password", { user: null, token: rawToken });
  });

  // POST /auth/reset-password/:token — validate token, update password, clear sessions
  app.post("/auth/reset-password/:token", rateLimit.middleware("password-reset-submit", 10, C.TIME.FIFTEEN_MIN), async function (req, res) {
    if (!config.localAuth) return res.status(403).json({ error: "Disabled." });

    try {
      var rawToken = req.params.token;
      if (!rawToken || rawToken.length !== 64) {
        return res.status(400).json({ error: "Invalid reset link." });
      }

      var body = await parseJson(req);
      var password = String(body.password || "");

      // Password confirmation is a client-side UX check (catch typos before
      // submission). Validating it server-side adds no security — an attacker
      // bypassing the form would simply submit matching values. The reset-
      // password view enforces the match before POSTing.
      var pwCheck = validatePassword(password);
      if (!pwCheck.valid) {
        return res.status(400).json({ error: pwCheck.reason });
      }

      var tokenHash = sha3Hash(rawToken);
      var record = verificationTokensRepo.findOne({ token: tokenHash, type: "password_reset" });

      if (!record) {
        audit.log(audit.ACTIONS.PASSWORD_RESET_FAILED, { details: "Invalid token on submit", req: req });
        return res.status(400).json({ error: "Invalid or expired reset link. Please request a new one." });
      }

      if (new Date(record.expiresAt) < new Date()) {
        verificationTokensRepo.remove(record._id);
        audit.log(audit.ACTIONS.PASSWORD_RESET_FAILED, { details: "Expired token on submit", targetId: record.userId, req: req });
        return res.status(400).json({ error: "Reset link has expired. Please request a new one." });
      }

      var user = usersRepo.findById(record.userId);
      if (!user) {
        verificationTokensRepo.remove(record._id);
        return res.status(400).json({ error: "Account not found." });
      }

      // Hash new password and update user
      var newHash = await hashPassword(password);
      usersRepo.update(user._id, { $set: {
        passwordHash: newHash,
        failedLoginAttempts: 0,
        lockedUntil: null,
      } });

      // Delete the used token and any other reset tokens for this user
      verificationTokensRepo.remove({ userId: user._id, type: "password_reset" });

      // Clear all sessions for this user (force re-login everywhere)
      sessionService.revokeUser(user._id);

      audit.log(audit.ACTIONS.PASSWORD_RESET_SUCCESS, { targetId: user._id, targetEmail: user.email, req: req });
      res.json({ success: true, redirect: "/auth/login" });
    } catch (e) {
      logger.error("Password reset error", { error: e.message || String(e) });
      res.status(500).json({ error: "Password reset failed. Please try again." });
    }
  });
};
