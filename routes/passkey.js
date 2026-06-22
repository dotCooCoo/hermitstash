var b = require("../lib/vendor/blamejs");
var config = require("../lib/config");
var C = require("../lib/constants");
var logger = require("../app/shared/logger");
var usersRepo = require("../app/data/repositories/users.repo");
var credentialsRepo = require("../app/data/repositories/credentials.repo");
var audit = require("../lib/audit");
var requireAuth = require("../middleware/require-auth");
var sessionService = require("../app/domain/auth/session.service");
var rateLimit = require("../lib/rate-limit");
var { AppError, ValidationError, AuthenticationError, ForbiddenError, NotFoundError } = require("../app/shared/errors");

module.exports = function (app) {
  // ---- Registration (add passkey to existing account) ----

  // Generate registration options
  app.post("/passkey/register/options", async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!config.passkeyEnabled) throw new ForbiddenError("Passkeys are disabled.");

    try {
      var userCreds = credentialsRepo.findByUser(req.user._id);
      var excludeCredentials = userCreds.map(function (c) {
        var transports = c.transports;
        if (typeof transports === "string") { transports = b.safeJson.parseOrDefault(transports, undefined); }
        // credentialId stored as base64, WebAuthn needs base64url
        var idB64url = Buffer.from(c.credentialId, "base64").toString("base64url");
        return { id: idB64url, transports: transports || undefined };
      });

      // b.auth.passkey.startRegistration sets options.hints to
      // ["client-device", "hybrid"] by default — same value HS used to
      // assign manually. authenticatorAttachment is intentionally
      // unset so both platform (Touch ID, Windows Hello) and cross-
      // platform (LastPass, 1Password, Bitwarden, YubiKey) work.
      var options = await b.auth.passkey.startRegistration({
        rpName: config.rpName,
        rpId: config.rpId,
        userName: req.user.email,
        userDisplayName: req.user.displayName || req.user.email,
        attestationType: "none",
        excludeCredentials: excludeCredentials,
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
        },
      });

      // Store challenge in session
      req.session.passkeyChallenge = options.challenge;
      res.json(options);
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Passkey register options error", { error: e.message || String(e), stack: e.stack });
      throw new AppError("Failed to generate passkey options.", 500);
    }
  });

  // Verify registration response
  app.post("/passkey/register/verify", async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!config.passkeyEnabled) throw new ForbiddenError("Passkeys are disabled.");

    try {
      var body = (await b.parsers.json(req)) || {};
      var expectedChallenge = req.session.passkeyChallenge;
      delete req.session.passkeyChallenge;

      if (!expectedChallenge) throw new ValidationError("No pending passkey challenge.");

      var verification = await b.auth.passkey.verifyRegistration({
        response: body,
        expectedChallenge: expectedChallenge,
        expectedOrigin: config.rpOrigin,
        expectedRPID: config.rpId,
        requireUserVerification: false,
      });

      if (!verification.verified || !verification.registrationInfo) {
        throw new ValidationError("Passkey verification failed.");
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
      if (e.isAppError) throw e;
      logger.error("Passkey register verify error", { error: e.message || String(e) });
      throw new AppError("Passkey registration failed.", 500);
    }
  });

  // ---- Authentication (login with passkey) ----

  // Generate authentication options
  app.post("/passkey/login/options", async (req, res) => {
    if (!config.passkeyEnabled) throw new ForbiddenError("Passkeys are disabled.");

    try {
      // b.auth.passkey.startAuthentication sets options.hints to
      // ["client-device", "hybrid"] by default.
      var options = await b.auth.passkey.startAuthentication({
        rpId: config.rpId,
        userVerification: "preferred",
      });

      // Store challenge in session for verification
      req.session.passkeyChallenge = options.challenge;
      res.json(options);
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Passkey login options error", { error: e.message || String(e) });
      throw new AppError("Failed to generate login options.", 500);
    }
  });

  // Verify authentication response
  app.post("/passkey/login/verify", rateLimit.guard({ max: 10, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), async (req, res) => {
    if (!config.passkeyEnabled) throw new ForbiddenError("Passkeys are disabled.");

    try {
      var body = (await b.parsers.json(req)) || {};
      var expectedChallenge = req.session.passkeyChallenge;
      delete req.session.passkeyChallenge;

      if (!expectedChallenge) throw new ValidationError("No pending passkey challenge.");

      // Find the credential by trying all stored credentials
      var incomingCredId = body.id; // base64url encoded
      var allCreds = credentialsRepo.find({});
      var matchedCred = null;

      for (var i = 0; i < allCreds.length; i++) {
        var row = allCreds[i];
        var storedB64url = Buffer.from(row.credentialId, "base64").toString("base64url");
        // Constant-time compare so verification timing can't enumerate which
        // credential IDs exist (=== short-circuits on the first differing byte).
        if (b.crypto.timingSafeEqual(storedB64url, String(incomingCredId || ""))) {
          matchedCred = row;
          break;
        }
      }

      if (!matchedCred) {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, { details: "Unknown credential", req: req });
        throw new AuthenticationError("Unknown passkey.");
      }

      var user = usersRepo.findById(matchedCred.userId);
      if (!user) {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, { details: "User not found for credential", req: req });
        throw new AuthenticationError("Account not found.");
      }

      if (user.status === "suspended") {
        throw new ForbiddenError("Account suspended.");
      }
      if (user.status === "pending") {
        throw new ForbiddenError("Please verify your email first.").withExtras({ pending: true, email: user.email });
      }

      // counter passed verbatim — the wrapper refuses undefined / null
      // explicitly (audit-2026-05-11 clone-detection bypass fix) so a
      // legacy row with a dropped counter column surfaces as a refusal
      // instead of silently coercing to 0.
      var verification = await b.auth.passkey.verifyAuthentication({
        response: body,
        expectedChallenge: expectedChallenge,
        expectedOrigin: config.rpOrigin,
        expectedRPID: config.rpId,
        credential: {
          id: incomingCredId,
          publicKey: Buffer.from(matchedCred.publicKey, "base64"),
          // Pass the stored counter verbatim. The wrapper refuses undefined / null
          // explicitly (clone-detection-bypass defense), so a legacy row with a
          // dropped counter fails closed (login refused) instead of silently
          // coercing to 0 and disabling clone detection for that credential.
          counter: matchedCred.counter,
          transports: typeof matchedCred.transports === "string"
            ? b.safeJson.parseOrDefault(matchedCred.transports, [])
            : (matchedCred.transports || []),
        },
        requireUserVerification: false,
      });

      if (!verification.verified) {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, { targetId: user._id, targetEmail: user.email, details: "Verification failed", req: req });
        throw new AuthenticationError("Passkey verification failed.");
      }

      // Update counter
      var newCounter = verification.authenticationInfo.newCounter;
      credentialsRepo.update(matchedCred._id, { $set: { counter: newCounter } });

      // Login
      usersRepo.update(user._id, { $set: { lastLogin: new Date().toISOString() } });
      await sessionService.loginUser(req, user._id);
      audit.log(audit.ACTIONS.PASSKEY_LOGIN_SUCCESS, { targetId: user._id, targetEmail: user.email, details: "authType: passkey", req: req });
      res.json({ verified: true, redirect: "/dashboard" });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Passkey login verify error", { error: e.message || String(e) });
      throw new AppError("Passkey login failed.", 500);
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
      var body = (await b.parsers.json(req)) || {};
      var credId = body.credentialId;
      if (!credId) throw new ValidationError("Credential ID required.");

      var cred = credentialsRepo.findOne({ _id: credId });
      if (!cred || cred.userId !== req.user._id) {
        throw new NotFoundError("Passkey not found.");
      }

      // Don't allow removing last passkey if user has no other login method
      var remaining = credentialsRepo.findByUser(req.user._id);
      if (remaining.length <= 1) {
        var hasPassword = !!req.user.passwordHash;
        var hasGoogle = req.user.authType === "google" || !!req.user.googleId;
        if (!hasPassword && !hasGoogle) {
          throw new ValidationError("Cannot remove your only passkey. Add a password or link Google first.");
        }
        // Warn if vault is enabled — removing the only passkey makes vault unrecoverable
        var vaultEnabled = req.user.vaultEnabled === "true";
        if (vaultEnabled) {
          // Allow removal but the client should confirm (check body.confirmVaultRisk)
          if (!body.confirmVaultRisk) {
            throw new ValidationError("This passkey is used for your vault. Removing it will make vault files unrecoverable. Send confirmVaultRisk: true to proceed.").withExtras({ requiresConfirmation: true });
          }
        }
      }

      credentialsRepo.remove({ _id: credId });
      audit.log(audit.ACTIONS.PASSKEY_REMOVED, { targetId: req.user._id, targetEmail: req.user.email, req: req });
      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Passkey remove error", { error: e.message || String(e) });
      throw new AppError("Failed to remove passkey.", 500);
    }
  });
};
