var config = require("../lib/config");
var logger = require("../app/shared/logger");
var rateLimit = require("../lib/rate-limit");
var usersRepo = require("../app/data/repositories/users.repo");
var credentialsRepo = require("../app/data/repositories/credentials.repo");
var { parseJson } = require("../lib/multipart");
var audit = require("../lib/audit");
var requireAuth = require("../middleware/require-auth");
var sessionService = require("../app/domain/auth/session.service");

// Lazy-load ESM module
var _webauthn = null;
async function webauthn() {
  if (!_webauthn) _webauthn = require("../lib/vendor/simplewebauthn-server.cjs");
  return _webauthn;
}

module.exports = function (app) {
  // ---- Registration (add passkey to existing account) ----

  // Generate registration options
  app.post("/passkey/register/options", async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!config.passkeyEnabled) return res.status(403).json({ error: "Passkeys are disabled." });

    try {
      var wa = await webauthn();
      var userCreds = credentialsRepo.findByUser(req.user._id);
      var excludeCredentials = userCreds.map(function (c) {
        var transports = c.transports;
        if (typeof transports === "string") { try { transports = JSON.parse(transports); } catch (_e) { transports = undefined; } }
        // credentialId stored as base64, WebAuthn needs base64url
        var idB64url = Buffer.from(c.credentialId, "base64").toString("base64url");
        return { id: idB64url, transports: transports || undefined };
      });

      var options = await wa.generateRegistrationOptions({
        rpName: config.rpName,
        rpID: config.rpId,
        userName: req.user.email,
        userDisplayName: req.user.displayName || req.user.email,
        attestationType: "none",
        excludeCredentials: excludeCredentials,
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
          // No authenticatorAttachment — allows both platform (Touch ID, Windows Hello)
          // and cross-platform (LastPass, 1Password, Bitwarden, YubiKey) authenticators
        },
      });

      // Hint browsers to show all authenticator types including password managers
      options.hints = ["client-device", "hybrid"];

      // Store challenge in session
      req.session.passkeyChallenge = options.challenge;
      res.json(options);
    } catch (e) {
      logger.error("Passkey register options error", { error: e.message || String(e), stack: e.stack });
      res.status(500).json({ error: "Failed to generate passkey options." });
    }
  });

  // Verify registration response
  app.post("/passkey/register/verify", async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!config.passkeyEnabled) return res.status(403).json({ error: "Passkeys are disabled." });

    try {
      var wa = await webauthn();
      var body = await parseJson(req);
      var expectedChallenge = req.session.passkeyChallenge;
      delete req.session.passkeyChallenge;

      if (!expectedChallenge) return res.status(400).json({ error: "No pending passkey challenge." });

      var verification = await wa.verifyRegistrationResponse({
        response: body,
        expectedChallenge: expectedChallenge,
        expectedOrigin: config.rpOrigin,
        expectedRPID: config.rpId,
      });

      if (!verification.verified || !verification.registrationInfo) {
        return res.status(400).json({ error: "Passkey verification failed." });
      }

      var info = verification.registrationInfo;

      credentialsRepo.create({
        userId: req.user._id,
        credentialId: Buffer.from(info.credential.id, "base64url").toString("base64"),
        publicKey: Buffer.from(info.credential.publicKey).toString("base64"),
        counter: info.credential.counter,
        deviceType: info.credentialDeviceType || "unknown",
        backedUp: info.credentialBackedUp ? 1 : 0,
        transports: body.response && body.response.transports ? JSON.stringify(body.response.transports) : null,
        createdAt: new Date().toISOString(),
      });

      audit.log(audit.ACTIONS.PASSKEY_REGISTERED, { targetId: req.user._id, targetEmail: req.user.email, details: "deviceType: " + (info.credentialDeviceType || "unknown"), req: req });
      res.json({ verified: true });
    } catch (e) {
      logger.error("Passkey register verify error", { error: e.message || String(e) });
      res.status(500).json({ error: "Passkey registration failed." });
    }
  });

  // ---- Authentication (login with passkey) ----

  // Generate authentication options
  app.post("/passkey/login/options", async (req, res) => {
    if (!config.passkeyEnabled) return res.status(403).json({ error: "Passkeys are disabled." });

    try {
      var wa = await webauthn();
      var options = await wa.generateAuthenticationOptions({
        rpID: config.rpId,
        userVerification: "preferred",
      });

      // Hint browsers to show all authenticator types including password managers
      options.hints = ["client-device", "hybrid"];

      // Store challenge in session for verification
      req.session.passkeyChallenge = options.challenge;
      res.json(options);
    } catch (e) {
      logger.error("Passkey login options error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to generate login options." });
    }
  });

  // Verify authentication response
  app.post("/passkey/login/verify", rateLimit.middleware("passkey-login", 10, 60000), async (req, res) => {
    if (!config.passkeyEnabled) return res.status(403).json({ error: "Passkeys are disabled." });

    try {
      var wa = await webauthn();
      var body = await parseJson(req);
      var expectedChallenge = req.session.passkeyChallenge;
      delete req.session.passkeyChallenge;

      if (!expectedChallenge) return res.status(400).json({ error: "No pending passkey challenge." });

      // Find the credential by trying all stored credentials
      var incomingCredId = body.id; // base64url encoded
      var allCreds = credentialsRepo.findAll({});
      var matchedCred = null;

      for (var i = 0; i < allCreds.length; i++) {
        var row = allCreds[i];
        var storedB64url = Buffer.from(row.credentialId, "base64").toString("base64url");
        if (storedB64url === incomingCredId) {
          matchedCred = row;
          break;
        }
      }

      if (!matchedCred) {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, { details: "Unknown credential", req: req });
        return res.status(401).json({ error: "Unknown passkey." });
      }

      var user = usersRepo.findById(matchedCred.userId);
      if (!user) {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, { details: "User not found for credential", req: req });
        return res.status(401).json({ error: "Account not found." });
      }

      if (user.status === "suspended") {
        return res.status(403).json({ error: "Account suspended." });
      }
      if (user.status === "pending") {
        return res.status(403).json({ error: "Please verify your email first.", pending: true, email: user.email });
      }

      var verification = await wa.verifyAuthenticationResponse({
        response: body,
        expectedChallenge: expectedChallenge,
        expectedOrigin: config.rpOrigin,
        expectedRPID: config.rpId,
        credential: {
          id: incomingCredId,
          publicKey: Buffer.from(matchedCred.publicKey, "base64"),
          counter: matchedCred.counter || 0,
          transports: (function() { try { return typeof matchedCred.transports === "string" ? JSON.parse(matchedCred.transports) : (matchedCred.transports || []); } catch(_e) { return []; } })(),
        },
      });

      if (!verification.verified) {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, { targetId: user._id, targetEmail: user.email, details: "Verification failed", req: req });
        return res.status(401).json({ error: "Passkey verification failed." });
      }

      // Update counter
      var newCounter = verification.authenticationInfo.newCounter;
      credentialsRepo.update(matchedCred._id, { $set: { counter: newCounter } });

      // Login
      usersRepo.update(user._id, { $set: { lastLogin: new Date().toISOString() } });
      sessionService.loginUser(req, user._id);
      audit.log(audit.ACTIONS.PASSKEY_LOGIN_SUCCESS, { targetId: user._id, targetEmail: user.email, details: "authType: passkey", req: req });
      res.json({ verified: true, redirect: "/dashboard" });
    } catch (e) {
      logger.error("Passkey login verify error", { error: e.message || String(e) });
      res.status(500).json({ error: "Passkey login failed." });
    }
  });

  // ---- Passkey management ----

  // List user's passkeys (safe info only)
  app.get("/passkey/list", (req, res) => {
    if (!requireAuth(req, res)) return;
    var creds = credentialsRepo.findByUser(req.user._id);
    var safe = creds.map(function (c) {
      return { _id: c._id, deviceType: c.deviceType || "unknown", backedUp: !!c.backedUp, createdAt: c.createdAt };
    });
    res.json({ passkeys: safe, passkeyEnabled: config.passkeyEnabled });
  });

  // Remove a passkey
  app.post("/passkey/remove", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = await parseJson(req);
      var credId = body.credentialId;
      if (!credId) return res.status(400).json({ error: "Credential ID required." });

      var cred = credentialsRepo.findOne({ _id: credId });
      if (!cred || cred.userId !== req.user._id) {
        return res.status(404).json({ error: "Passkey not found." });
      }

      // Don't allow removing last passkey if user has no other login method
      var remaining = credentialsRepo.findByUser(req.user._id);
      if (remaining.length <= 1) {
        var hasPassword = !!req.user.passwordHash;
        var hasGoogle = req.user.authType === "google" || !!req.user.googleId;
        if (!hasPassword && !hasGoogle) {
          return res.status(400).json({ error: "Cannot remove your only passkey. Add a password or link Google first." });
        }
        // Warn if vault is enabled — removing the only passkey makes vault unrecoverable
        var vaultEnabled = req.user.vaultEnabled === "true";
        if (vaultEnabled) {
          // Allow removal but the client should confirm (check body.confirmVaultRisk)
          if (!body.confirmVaultRisk) {
            return res.status(400).json({ error: "This passkey is used for your vault. Removing it will make vault files unrecoverable. Send confirmVaultRisk: true to proceed.", requiresConfirmation: true });
          }
        }
      }

      credentialsRepo.remove({ _id: credId });
      audit.log(audit.ACTIONS.PASSKEY_REMOVED, { targetId: req.user._id, targetEmail: req.user.email, req: req });
      res.json({ success: true });
    } catch (e) {
      logger.error("Passkey remove error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to remove passkey." });
    }
  });
};
