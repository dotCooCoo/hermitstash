var config = require("../lib/config");
var C = require("../lib/constants");
var logger = require("../app/shared/logger");
var vault = require("../lib/vault");
var rateLimit = require("../lib/rate-limit");
var { sha3Hash } = require("../lib/crypto");
var usersRepo = require("../app/data/repositories/users.repo");
var { parseJson } = require("../lib/multipart");
var totp = require("../lib/totp");
var requireAuth = require("../middleware/require-auth");
var audit = require("../lib/audit");
var sessionService = require("../app/domain/auth/session.service");

module.exports = function (app) {
  // Start 2FA setup — generate secret, return URI for QR code
  app.post("/2fa/setup", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var secret = totp.generateSecret();
      // Store provisionally in session until verified
      req.session.pendingTotpSecret = secret;
      var uri = totp.getUri(secret, req.user.email, config.siteName);
      res.json({ secret: secret, uri: uri });
    } catch (e) {
      logger.error("2FA setup error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to set up 2FA." });
    }
  });

  // Confirm 2FA setup — verify code, save secret + backup codes
  app.post("/2fa/confirm", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = await parseJson(req);
      var code = String(body.code || "");
      var secret = req.session.pendingTotpSecret;
      if (!secret) return res.status(400).json({ error: "No pending 2FA setup. Start again." });

      if (!totp.verify(secret, code)) {
        return res.status(400).json({ error: "Invalid code. Try again." });
      }

      // Generate backup codes
      var backupCodes = totp.generateBackupCodes();
      var hashedCodes = backupCodes.map(function (c) { return sha3Hash(c); });

      // Save to user (vault-sealed secret, hashed backup codes)
      usersRepo.update(req.user._id, {
        $set: {
          totpSecret: vault.seal(secret),
          totpEnabled: "true",
          totpBackupCodes: JSON.stringify(hashedCodes),
        },
      });

      delete req.session.pendingTotpSecret;
      audit.log(audit.ACTIONS.TOTP_ENABLED, { targetId: req.user._id, targetEmail: req.user.email, req: req });

      // Return backup codes (shown once, never again)
      res.json({ success: true, backupCodes: backupCodes });
    } catch (e) {
      logger.error("2FA confirm error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to confirm 2FA." });
    }
  });

  // Disable 2FA
  app.post("/2fa/disable", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = await parseJson(req);
      var code = String(body.code || "");

      // Require a valid code to disable
      var user = usersRepo.findById(req.user._id);
      var secret = user.totpSecret ? vault.unseal(user.totpSecret) : null;
      if (!secret) return res.status(400).json({ error: "2FA is not enabled." });

      if (!totp.verify(secret, code)) {
        return res.status(400).json({ error: "Invalid code." });
      }

      usersRepo.update(req.user._id, {
        $set: { totpSecret: null, totpEnabled: null, totpBackupCodes: null },
      });

      audit.log(audit.ACTIONS.TOTP_DISABLED, { targetId: req.user._id, targetEmail: req.user.email, req: req });
      res.json({ success: true });
    } catch (e) {
      logger.error("2FA disable error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to disable 2FA." });
    }
  });

  // Verify 2FA during login (called after password success)
  app.post("/2fa/verify", rateLimit.middleware("2fa", 5, C.TIME.FIVE_MIN), async (req, res) => {
    try {
      var body = await parseJson(req);
      var code = String(body.code || "");
      var userId = req.session.pendingTotpUserId;
      var pendingExpires = req.session.pendingTotpExpires || 0;

      if (!userId) return res.status(400).json({ error: "No pending 2FA verification." });
      if (Date.now() > pendingExpires) {
        delete req.session.pendingTotpUserId;
        delete req.session.pendingTotpExpires;
        return res.status(400).json({ error: "2FA session expired. Please log in again." });
      }

      var user = usersRepo.findById(userId);
      if (!user) return res.status(400).json({ error: "User not found." });
      if (user.status === "suspended") {
        delete req.session.pendingTotpUserId;
        return res.status(403).json({ error: "Account suspended." });
      }

      var secret = user.totpSecret ? vault.unseal(user.totpSecret) : null;
      if (!secret) return res.status(400).json({ error: "2FA not configured." });

      // Try TOTP code first (with replay prevention)
      var lastStep = user.totpLastStep ? parseInt(user.totpLastStep, 10) : 0;
      var matchedStep = totp.verify(secret, code, lastStep);
      if (matchedStep) {
        sessionService.complete2fa(req);
        usersRepo.update(user._id, { $set: { lastLogin: new Date().toISOString(), totpLastStep: String(matchedStep) } });
        audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, details: "2FA verified via TOTP", req: req });
        return res.json({ success: true, redirect: "/dashboard" });
      }

      // Try backup code
      var backupCodes = [];
      try { backupCodes = Array.isArray(user.totpBackupCodes) ? user.totpBackupCodes : JSON.parse(user.totpBackupCodes || "[]"); } catch (_e) {}
      var codeHash = sha3Hash(code);
      var idx = backupCodes.indexOf(codeHash);

      if (idx !== -1) {
        // Consume the backup code (single-use)
        backupCodes.splice(idx, 1);
        usersRepo.update(user._id, { $set: { totpBackupCodes: JSON.stringify(backupCodes) } });

        sessionService.complete2fa(req);
        usersRepo.update(user._id, { $set: { lastLogin: new Date().toISOString() } });
        audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, details: "2FA verified via backup code (" + backupCodes.length + " remaining)", req: req });
        return res.json({ success: true, redirect: "/dashboard" });
      }

      audit.log(audit.ACTIONS.TOTP_FAILED, { targetId: user._id, details: "Invalid 2FA code", req: req });
      res.status(401).json({ error: "Invalid 2FA code." });
    } catch (e) {
      logger.error("2FA verify error", { error: e.message || String(e) });
      res.status(500).json({ error: "2FA verification failed." });
    }
  });

  // Check 2FA status
  app.get("/2fa/status", (req, res) => {
    if (!requireAuth(req, res)) return;
    var user = usersRepo.findById(req.user._id);
    var backupCount = 0;
    try { var codes = Array.isArray(user.totpBackupCodes) ? user.totpBackupCodes : JSON.parse(user.totpBackupCodes || "[]"); backupCount = codes.length; } catch (_e) { /* malformed backupCodes — report 0 remaining */ }
    res.json({ enabled: user.totpEnabled === "true", backupCodesRemaining: backupCount });
  });
};
