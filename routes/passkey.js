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
var replayNonce = require("../lib/replay-nonce");
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
  app.post("/passkey/login/options", rateLimit.guard({ max: 30, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), async (req, res) => {
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

      // Atomically claim this challenge. The in-memory `delete` above is persisted
      // only at res.end via the deferred session flush (last-writer-wins), so two
      // concurrent requests both read the same challenge and both pass the check.
      // The challenge is the natural single-use token; claiming it here closes the
      // TOCTOU window the same way the 2FA path does for the TOTP step.
      if (!(await replayNonce.claimOnce("passkey:chal:" + b.crypto.sha3Hash(expectedChallenge), C.TIME.minutes(2)))) {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, { details: "Passkey challenge replay rejected (concurrent)", req: req });
        throw new AuthenticationError("Passkey challenge already used.");
      }

      // Find the credential by trying all stored credentials
      var incomingCredId = body.id; // base64url encoded
      var allCreds = credentialsRepo.find({});
      var matchedCred = null;

      for (var i = 0; i < allCreds.length; i++) {
        var row = allCreds[i];
        var storedB64url = Buffer.from(row.credentialId, "base64").toString("base64url");
        // Constant-time compare so verification timing can't enumerate which
        // credential IDs exist (=== short-circuits on the first differing byte),
        // and EVERY row is compared for the same reason. Returning at the first
        // hit made the total time report the match's position in the table,
        // which is registration order — the enumeration signal this compare
        // exists to deny, reintroduced one line below it. The first match still
        // wins; the guard sits after the comparison, not in place of it.
        if (b.crypto.timingSafeEqual(storedB64url, String(incomingCredId || "")) && !matchedCred) {
          matchedCred = row;
        }
      }

      // Account state (suspended / pending) MUST NOT be consulted before a
      // cryptographically-verified assertion: doing so leaks account state — and
      // credential existence — to a caller who knows a credentialId but holds no
      // private key (a distinct "Account suspended" / "Unknown passkey" response
      // is a status/enumeration oracle). Verify possession FIRST; whether the
      // credential is unknown, its user is missing, or the assertion fails to
      // verify, return one indistinguishable failure. Only AFTER verification do
      // we apply the suspended / pending gate.
      var user = matchedCred ? usersRepo.findById(matchedCred.userId) : null;

      var verification = null;
      if (matchedCred && user) {
        try {
          // counter passed verbatim — the wrapper refuses undefined / null
          // explicitly (clone-detection-bypass defense) so a legacy row with a
          // dropped counter column fails closed (login refused) instead of
          // silently coercing to 0 and disabling clone detection. Such a refusal
          // throws; it is caught here and folded into the uniform failure below.
          verification = await b.auth.passkey.verifyAuthentication({
            response: body,
            expectedChallenge: expectedChallenge,
            expectedOrigin: config.rpOrigin,
            expectedRPID: config.rpId,
            credential: {
              id: incomingCredId,
              publicKey: Buffer.from(matchedCred.publicKey, "base64"),
              counter: matchedCred.counter,
              transports: typeof matchedCred.transports === "string"
                ? b.safeJson.parseOrDefault(matchedCred.transports, [])
                : (matchedCred.transports || []),
            },
            requireUserVerification: false,
          });
        } catch (verifyErr) {
          // A malformed / unverifiable assertion (or the counter fail-closed
          // refusal above) is an authentication failure, not a 500 — treat it as
          // an unverified result so it joins the uniform failure path.
          logger.error("Passkey verifyAuthentication rejected", { error: verifyErr && (verifyErr.message || String(verifyErr)) });
          verification = null;
        }
      }

      if (!verification || !verification.verified) {
        // Uniform failure — one identical status + message whether the
        // credential was unknown, its user was missing, or the assertion did not
        // verify. The audit detail differs (server-side only) but the
        // caller-visible response never distinguishes the three, closing both
        // the credential-existence and account-state oracles.
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, {
          targetId: user ? user._id : undefined,
          targetEmail: user ? user.email : undefined,
          details: !matchedCred ? "Unknown credential" : (!user ? "User not found for credential" : "Verification failed"),
          req: req,
        });
        throw new AuthenticationError("Unknown passkey.");
      }

      // Cryptographic proof of possession established — now it is safe to reveal
      // account state to the verified owner.
      if (user.status === "suspended") {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_FAILED, { targetId: user._id, targetEmail: user.email, details: "Account suspended", req: req });
        throw new ForbiddenError("Account suspended.");
      }
      if (user.status === "pending") {
        throw new ForbiddenError("Please verify your email first.").withExtras({ pending: true, email: user.email });
      }

      // Update counter
      var newCounter = verification.authenticationInfo.newCounter;
      credentialsRepo.update(matchedCred._id, { $set: { counter: newCounter } });

      // Route through the shared login chokepoint so a totpEnabled account is
      // held in the pending-2FA state rather than receiving a full session.
      // Passkeys are verified with requireUserVerification:false, so the
      // assertion proves possession only — the second factor the owner enabled
      // must still be entered, exactly as on the local-password and Google
      // paths. The browser redirects a requires2fa response to /2fa.
      var outcome = await sessionService.completeLogin(req, user._id);
      if (outcome.requires2fa) {
        audit.log(audit.ACTIONS.PASSKEY_LOGIN_SUCCESS, { targetId: user._id, targetEmail: user.email, details: "authType: passkey, 2FA pending", req: req });
        return res.json({ requires2fa: true });
      }
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
