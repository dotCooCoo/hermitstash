var config = require("../lib/config");
var C = require("../lib/constants");
var logger = require("../app/shared/logger");
var usersRepo = require("../app/data/repositories/users.repo");
var verificationTokensRepo = require("../app/data/repositories/verificationTokens.repo");
var { sha3Hash, generateToken } = require("../lib/crypto");
var { sendVerificationEmail } = require("../lib/email");
var audit = require("../lib/audit");
var { send, host } = require("../middleware/send");
var sessionService = require("../app/domain/auth/session.service");
var { validateEmail } = require("../app/shared/validate");
var rateLimit = require("../lib/rate-limit");
var { parseJson } = require("../lib/multipart");

function createVerificationToken(userId) {
  // Clean up any existing tokens for this user
  verificationTokensRepo.remove({ userId: userId });

  var rawToken = generateToken();
  var tokenHash = sha3Hash(rawToken);
  var expiresAt = new Date(Date.now() + C.TIME.ONE_DAY).toISOString(); // 24 hours

  verificationTokensRepo.create({
    userId: userId,
    token: tokenHash,
    type: "email",
    expiresAt: expiresAt,
    createdAt: new Date().toISOString(),
  });

  return rawToken;
}

module.exports = function (app) {
  // Verify email — GET shows confirmation page, POST consumes the token
  app.get("/auth/verify/:token", async (req, res) => {
    try {
      var rawToken = req.params.token;
      var tokenHash = sha3Hash(rawToken);
      var record = verificationTokensRepo.findOne({ token: tokenHash, type: "email" });

      if (!record) {
        audit.log(audit.ACTIONS.EMAIL_VERIFICATION_FAILED, { details: "Invalid token", req: req });
        return send(res, "error", { user: null, title: "Invalid Link", message: "This verification link is invalid or has already been used." }, 400);
      }

      if (new Date(record.expiresAt) < new Date()) {
        verificationTokensRepo.remove(record._id);
        audit.log(audit.ACTIONS.EMAIL_VERIFICATION_FAILED, { details: "Expired token", targetId: record.userId, req: req });
        return send(res, "error", { user: null, title: "Link Expired", message: "This verification link has expired. Please request a new one." }, 400);
      }

      // Show a confirmation page with an auto-submitting form
      var csrfToken = req.csrfToken || "";
      var html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Verify Email</title></head><body>'
        + '<form id="v" method="POST" action="/auth/verify/' + encodeURIComponent(rawToken) + '">'
        + '<input type="hidden" name="_csrf" value="' + csrfToken + '">'
        + '<noscript><button type="submit">Click to verify your email</button></noscript>'
        + '</form>'
        + '<script>document.getElementById("v").submit();</script>'
        + '</body></html>';
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
    } catch (e) {
      logger.error("Verification error", { error: e.message || String(e) });
      send(res, "error", { user: null, title: "Error", message: "Verification failed. Please try again." }, 500);
    }
  });

  // Verify email — POST consumes the token and logs in the user
  app.post("/auth/verify/:token", async (req, res) => {
    try {
      var rawToken = req.params.token;
      var tokenHash = sha3Hash(rawToken);
      var record = verificationTokensRepo.findOne({ token: tokenHash, type: "email" });

      if (!record) {
        audit.log(audit.ACTIONS.EMAIL_VERIFICATION_FAILED, { details: "Invalid token", req: req });
        return send(res, "error", { user: null, title: "Invalid Link", message: "This verification link is invalid or has already been used." }, 400);
      }

      if (new Date(record.expiresAt) < new Date()) {
        verificationTokensRepo.remove(record._id);
        audit.log(audit.ACTIONS.EMAIL_VERIFICATION_FAILED, { details: "Expired token", targetId: record.userId, req: req });
        return send(res, "error", { user: null, title: "Link Expired", message: "This verification link has expired. Please request a new one." }, 400);
      }

      var user = usersRepo.findById(record.userId);
      if (!user) {
        verificationTokensRepo.remove(record._id);
        return send(res, "error", { user: null, title: "Error", message: "Account not found." }, 404);
      }

      // Activate the user
      usersRepo.update(user._id, { $set: { status: "active" } });
      verificationTokensRepo.remove(record._id);

      audit.log(audit.ACTIONS.EMAIL_VERIFIED, { targetId: user._id, targetEmail: user.email, req: req });

      // Auto-login after verification
      sessionService.loginUser(req, user._id);

      send(res, "error", { user: user, title: "Email Verified", message: "Your email has been verified. Welcome to " + config.siteName + "!" }, 200);
    } catch (e) {
      logger.error("Verification error", { error: e.message || String(e) });
      send(res, "error", { user: null, title: "Error", message: "Verification failed. Please try again." }, 500);
    }
  });

  // Resend verification email (rate limited to prevent email quota abuse)
  app.post("/auth/resend-verification", rateLimit.middleware("resend-verify", 3, C.TIME.FIVE_MIN), async (req, res) => {
    try {
      var body = await parseJson(req);
      var emailCheck = validateEmail(body.email);
      if (!emailCheck.valid) return res.status(400).json({ error: emailCheck.reason });
      var email = emailCheck.email;

      var user = usersRepo.findByEmail(email);
      if (!user || user.status !== "pending") {
        // Don't reveal whether account exists
        return res.json({ success: true, message: "If an account with that email exists and needs verification, a new link has been sent." });
      }

      var rawToken = createVerificationToken(user._id);
      var verifyUrl = host(null) + "/auth/verify/" + rawToken;
      try {
        await sendVerificationEmail({ to: user.email, displayName: user.displayName, verifyUrl: verifyUrl });
      } catch (emailErr) {
        logger.error("Email send failed", { error: emailErr.message });
      }

      audit.log(audit.ACTIONS.EMAIL_VERIFICATION_RESENT, { targetId: user._id, targetEmail: user.email, req: req });
      res.json({ success: true, message: "If an account with that email exists and needs verification, a new link has been sent." });
    } catch (e) {
      logger.error("Resend verification error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to resend verification." });
    }
  });

  // Pending verification page
  app.get("/auth/pending", (req, res) => {
    send(res, "verify-pending", { user: null });
  });
};

module.exports.createVerificationToken = createVerificationToken;
