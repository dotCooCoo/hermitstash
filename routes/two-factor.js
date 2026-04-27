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
var { send } = require("../middleware/send");

// Stored algorithm is null/undefined for users enrolled before v1.9.11 (always
// SHA-1 in that era). Anything else is the explicit string ("SHA512" today).
function algorithmFor(user) {
  return user && user.totpAlgorithm ? user.totpAlgorithm : "SHA1";
}

function isLegacyAlgorithm(alg) {
  return alg !== totp.DEFAULT_ALGORITHM;
}

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

      // New enrollments are always SHA-512 — no legacy path through /2fa/setup.
      if (!totp.verify(secret, code, 0, totp.DEFAULT_ALGORITHM)) {
        return res.status(400).json({ error: "Invalid code. Try again." });
      }

      // Generate backup codes
      var backupCodes = totp.generateBackupCodes();
      var hashedCodes = backupCodes.map(function (c) { return sha3Hash(c); });

      // Save to user (vault-sealed secret, hashed backup codes, explicit algorithm)
      usersRepo.update(req.user._id, {
        $set: {
          totpSecret: vault.seal(secret),
          totpEnabled: "true",
          totpBackupCodes: JSON.stringify(hashedCodes),
          totpAlgorithm: totp.DEFAULT_ALGORITHM,
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

      if (!totp.verify(secret, code, 0, algorithmFor(user))) {
        return res.status(400).json({ error: "Invalid code." });
      }

      usersRepo.update(req.user._id, {
        $set: { totpSecret: null, totpEnabled: null, totpBackupCodes: null, totpAlgorithm: null },
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

      // Try TOTP code first (with replay prevention). Dispatch on the stored
      // algorithm so legacy SHA-1 secrets still verify; mark them for forced
      // re-enrollment so they roll forward on first use after upgrade.
      var alg = algorithmFor(user);
      var lastStep = user.totpLastStep ? parseInt(user.totpLastStep, 10) : 0;
      var matchedStep = totp.verify(secret, code, lastStep, alg);
      if (matchedStep) {
        sessionService.complete2fa(req);
        if (isLegacyAlgorithm(alg)) req.session.requiresTotpReEnroll = "true";
        usersRepo.update(user._id, { $set: { lastLogin: new Date().toISOString(), totpLastStep: String(matchedStep) } });
        audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, details: "2FA verified via TOTP (" + alg + ")", req: req });
        return res.json({ success: true, redirect: isLegacyAlgorithm(alg) ? "/2fa/re-enroll" : "/dashboard" });
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
        if (isLegacyAlgorithm(alg)) req.session.requiresTotpReEnroll = "true";
        usersRepo.update(user._id, { $set: { lastLogin: new Date().toISOString() } });
        audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, details: "2FA verified via backup code (" + backupCodes.length + " remaining, alg=" + alg + ")", req: req });
        return res.json({ success: true, redirect: isLegacyAlgorithm(alg) ? "/2fa/re-enroll" : "/dashboard" });
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
    res.json({ enabled: user.totpEnabled === "true", backupCodesRemaining: backupCount, algorithm: algorithmFor(user) });
  });

  // ---- Forced re-enrollment (legacy SHA-1 → SHA-512 migration) ----
  //
  // Eligibility: user must be fully logged in AND have a legacy algorithm
  // stored. The session flag req.session.requiresTotpReEnroll is set during
  // /2fa/verify when a legacy code succeeds; the re-enroll endpoints accept
  // either signal (flag OR stored legacy algorithm) so an admin who clears
  // the flag can still re-pair manually.

  function eligibleForReEnroll(req) {
    if (!req.user) return false;
    if (req.session && req.session.requiresTotpReEnroll === "true") return true;
    var fresh = usersRepo.findById(req.user._id);
    return fresh && fresh.totpEnabled === "true" && isLegacyAlgorithm(algorithmFor(fresh));
  }

  // Render the re-enroll page (no QR rendering yet — manual entry of the
  // otpauth URI into the authenticator app's "manual entry" mode).
  app.get("/2fa/re-enroll", (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!eligibleForReEnroll(req)) return res.redirect("/dashboard");
    send(res, "re-enroll", { user: req.user });
  });

  // Begin re-enrollment: generate a fresh SHA-512 secret + URI; stash in
  // session as pending until the user proves possession by entering a code.
  app.post("/2fa/re-enroll/start", async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!eligibleForReEnroll(req)) return res.status(403).json({ error: "Re-enrollment not required for this account." });
    try {
      var secret = totp.generateSecret(totp.DEFAULT_ALGORITHM);
      req.session.pendingReEnrollSecret = secret;
      var uri = totp.getUri(secret, req.user.email, config.siteName, totp.DEFAULT_ALGORITHM);
      res.json({ secret: secret, uri: uri, algorithm: totp.DEFAULT_ALGORITHM });
    } catch (e) {
      logger.error("2FA re-enroll start error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to start re-enrollment." });
    }
  });

  // Confirm re-enrollment: verify the new code against the pending SHA-512
  // secret, then atomically replace the stored secret + algorithm + backup
  // codes and clear the session flag.
  app.post("/2fa/re-enroll/confirm", async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!eligibleForReEnroll(req)) return res.status(403).json({ error: "Re-enrollment not required for this account." });
    try {
      var body = await parseJson(req);
      var code = String(body.code || "");
      var secret = req.session.pendingReEnrollSecret;
      if (!secret) return res.status(400).json({ error: "No pending re-enrollment. Start again." });

      if (!totp.verify(secret, code, 0, totp.DEFAULT_ALGORITHM)) {
        return res.status(400).json({ error: "Invalid code. Try again." });
      }

      var backupCodes = totp.generateBackupCodes();
      var hashedCodes = backupCodes.map(function (c) { return sha3Hash(c); });

      usersRepo.update(req.user._id, {
        $set: {
          totpSecret: vault.seal(secret),
          totpEnabled: "true",
          totpBackupCodes: JSON.stringify(hashedCodes),
          totpAlgorithm: totp.DEFAULT_ALGORITHM,
          totpLastStep: null,
        },
      });

      delete req.session.pendingReEnrollSecret;
      delete req.session.requiresTotpReEnroll;
      audit.log(audit.ACTIONS.TOTP_ENABLED, { targetId: req.user._id, targetEmail: req.user.email, details: "Re-enrolled to " + totp.DEFAULT_ALGORITHM, req: req });

      res.json({ success: true, backupCodes: backupCodes });
    } catch (e) {
      logger.error("2FA re-enroll confirm error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to confirm re-enrollment." });
    }
  });
};
