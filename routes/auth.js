var clientIp = require("../lib/client-ip");
var b = require("../lib/vendor/blamejs");
var rateLimit = require("../lib/rate-limit");
var config = require("../lib/config");
var C = require("../lib/constants");
var logger = require("../app/shared/logger");
var usersRepo = require("../app/data/repositories/users.repo");
var oidc = require("../lib/oidc");
var emailService = require("../app/domain/integrations/email.service");
var { send, host } = require("../middleware/send");
var { emitError } = require("../middleware/respond-error");
var audit = require("../lib/audit");
var authService = require("../app/domain/auth/auth.service");
var sessionService = require("../app/domain/auth/session.service");
var tailscale = require("../lib/tailscale");
var { validateLoginInput, validateRegisterInput } = require("../app/http/validators/auth.validator");
var { createVerificationToken } = require("./verification");
var { validateToken } = require("../app/security/csrf-policy");
var { AppError, ValidationError, AuthenticationError, ForbiddenError } = require("../app/shared/errors");

module.exports = function (app) {
  // Google sign-in runs on lib/oidc: PKCE, state, nonce and a verified
  // id_token. The pending state lives in req.session.oauthState, is single-use
  // and expires after 5 minutes.
  app.get("/auth/google", async (req, res) => {
    if (!config.google.clientID) {
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "Google OAuth not configured (no Client ID)", req: req });
      return send(res, "error", { title: "Not Configured", message: "Google OAuth is not set up. Add a Client ID in Admin Settings.", user: null }, 500);
    }
    try {
      oidc.redirectToProvider(res, await oidc.startLogin("google", req));
    } catch (err) {
      var reason = oidc.auditReason(err);
      logger.error("Google sign-in could not start", { reason: reason });
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "Google sign-in could not start: " + reason, req: req });
      send(res, "error", { title: "Sign-in Unavailable", message: "Google sign-in could not be started. The server log has the reason.", user: null }, 502);
    }
  });

  app.get("/auth/google/callback", rateLimit.guard({ max: 10, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), async (req, res) => {
    try {
      var identity = await oidc.completeLogin("google", req);
      if (!identity.email) {
        var unverified = new Error("Google email not verified");
        unverified.oidcReason = "email-not-verified";
        throw unverified;
      }
      // googleId is the id_token sub, the same value the userinfo endpoint
      // reported as `sub` before, so existing accounts keep matching.
      var profile = { googleId: identity.sub, email: identity.email, displayName: identity.displayName, avatar: identity.avatar };

      var result = authService.resolveGoogleUser(profile, config.allowedDomains);
      var user = result.user;

      if (result.isNew) {
        audit.log(audit.ACTIONS.USER_REGISTERED, { targetId: user._id, targetEmail: user.email, details: "authType: google, role: " + user.role, req: req });
      }

      // Route through the shared login chokepoint so the 2FA gate is
      // enforced here exactly as on the local-password path — a totpEnabled
      // account reachable via SSO must complete TOTP, not receive a full
      // session. The callback is a browser navigation, so a pending-2FA
      // outcome is a redirect (not a JSON body).
      var outcome = await sessionService.completeLogin(req, user._id);
      if (outcome.requires2fa) {
        return res.redirect("/2fa");
      }
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, targetEmail: user.email, details: "authType: google", req: req });
      res.redirect("/dashboard");
    } catch (err) {
      // The reason is a fixed string (lib/oidc auditReason) or the message of a
      // refusal raised by the auth service. A provider response body never
      // reaches the log.
      var reason = err && err.oidcReason ? oidc.auditReason(err) : (err && err.isAppError ? String(err.message).slice(0, 120) : "callback failed");
      logger.error("Google sign-in failed", { reason: reason });
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "Google callback error: " + reason, req: req });
      res.redirect("/auth/failed");
    }
  });

  // Generic OpenID Connect sign-in (Keycloak, Authentik, Authelia and other
  // conforming providers). Like the Google callback, these are GET
  // navigations from the provider; state, PKCE and the nonce bind the
  // callback to the browser that started the login.
  app.get("/auth/oidc", rateLimit.guard({ max: 30, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), async (req, res) => {
    if (!oidc.isEnabled()) {
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "OpenID Connect not configured", req: req });
      return send(res, "error", { title: "Not Configured", message: "Single sign-on is not set up. Configure OpenID Connect in Admin Settings.", user: null }, 500);
    }
    try {
      oidc.redirectToProvider(res, await oidc.startLogin("oidc", req));
    } catch (err) {
      var reason = oidc.auditReason(err);
      logger.error("OpenID Connect sign-in could not start", { reason: reason });
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "OpenID Connect sign-in could not start: " + reason, req: req });
      send(res, "error", { title: "Sign-in Unavailable", message: "Single sign-on could not be started. The server log has the reason.", user: null }, 502);
    }
  });

  app.get("/auth/oidc/callback", rateLimit.guard({ max: 10, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), async (req, res) => {
    var identity = null;
    try {
      if (!oidc.isEnabled()) {
        var off = new Error("OpenID Connect not configured");
        off.oidcReason = "not-configured";
        throw off;
      }
      var policy = config.oidc;
      identity = await oidc.completeLogin("oidc", req, { needGroups: !!(policy.requiredGroup || policy.adminGroup) });
      var result = authService.resolveOidcUser(identity, {
        allowedDomains: config.allowedDomains,
        autoProvision: policy.autoProvision,
        allowlist: policy.allowlist,
        requiredGroup: policy.requiredGroup,
        adminGroup: policy.adminGroup,
      });
      var user = result.user;
      if (result.isNew) {
        audit.log(audit.ACTIONS.USER_REGISTERED, { targetId: user._id, targetEmail: user.email, details: "authType: oidc, role: " + user.role, req: req });
      }
      if (result.linked) {
        audit.log(audit.ACTIONS.OIDC_ACCOUNT_LINKED, { targetId: user._id, targetEmail: user.email, details: "Linked to an OpenID Connect identity by verified email (account authType: " + (user.authType || "unknown") + ")", req: req });
      }
      if (result.roleChange) {
        audit.log(audit.ACTIONS.USER_ROLE_CHANGED, { targetId: user._id, targetEmail: user.email, details: result.roleChange.from + " -> " + result.roleChange.to + " (OpenID Connect admin group)", req: req });
      }
      if (result.roleSyncRefused) {
        audit.log(audit.ACTIONS.OIDC_ROLE_SYNC_REFUSED, { targetId: user._id, targetEmail: user.email, details: "Not in the admin group, but kept as admin because it is the last active admin", req: req });
      }
      // A demotion ends the account's other sessions. This request's session
      // is replaced by the login below.
      if (result.revokeSessions) await sessionService.revokeUser(user._id);

      var outcome = await sessionService.completeLogin(req, user._id);
      if (outcome.requires2fa) return res.redirect("/2fa");
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, targetEmail: user.email, details: "authType: oidc", req: req });
      res.redirect("/dashboard");
    } catch (err) {
      var reason = oidc.auditReason(err);
      if (err && err.oidcReason === "provision-denied") {
        audit.log(audit.ACTIONS.OIDC_PROVISION_DENIED, { targetEmail: identity && identity.email ? identity.email : undefined, details: "No account and provisioning did not allow one", req: req });
      } else if (err && err.oidcReason === "group-denied") {
        audit.log(audit.ACTIONS.OIDC_GROUP_DENIED, { targetId: err.revokeUserId || undefined, targetEmail: identity && identity.email ? identity.email : undefined, details: "Required group missing", req: req });
      }
      // A refusal of an account bound to this identity (required group or
      // domain no longer satisfied) also ends its existing sessions.
      if (err && err.revokeUserId) {
        try { await sessionService.revokeUser(err.revokeUserId); }
        catch (revokeErr) { logger.error("OpenID Connect: session revocation failed", { error: revokeErr && revokeErr.code ? revokeErr.code : "unknown" }); }
      }
      logger.error("OpenID Connect sign-in failed", { reason: reason });
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "OpenID Connect callback error: " + reason, req: req });
      res.redirect("/auth/failed");
    }
  });

  // Sign in with Tailscale. Like the Google callback, the identity arrives from
  // outside the credential form — here as the peer-gated `tailscale serve` header
  // family (set + forged-copies-stripped by tailscale.middleware). It is a GET
  // (a link, not a form) and CSRF-exempt because login-CSRF has no leverage: the
  // identity is the visitor's OWN tailnet identity, bound by tailscaled/serve and
  // never attacker-forgeable, so it can only ever sign a user into their own
  // account. Under Funnel a public visitor carries no identity header, so the
  // request fails closed to /auth/failed and the visitor uses another method.
  app.get("/auth/tailscale", rateLimit.guard({ max: 20, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), async (req, res) => {
    try {
      if (!config.tailscale.enabled || !config.tailscale.ssoEnabled) {
        audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "Tailscale sign-in not enabled", req: req });
        return res.redirect("/auth/login");
      }
      var identity = tailscale.identityFrom(req);
      if (!identity) {
        audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "Tailscale sign-in: no tailnet identity on request (direct client / Funnel)", req: req });
        return res.redirect("/auth/failed");
      }
      var result = authService.resolveTailscaleUser(identity);
      var user = result.user;
      if (result.isNew) {
        audit.log(audit.ACTIONS.USER_REGISTERED, { targetId: user._id, targetEmail: user.email, details: "authType: tailscale, role: " + user.role, req: req });
      }
      // Shared login chokepoint — the same one the Google callback + local login
      // use, so an enabled TOTP is enforced on the Tailscale path too.
      var outcome = await sessionService.completeLogin(req, user._id);
      if (outcome.requires2fa) return res.redirect("/2fa");
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, targetEmail: user.email, details: "authType: tailscale", req: req });
      res.redirect("/dashboard");
    } catch (err) {
      // Gate-closed / cross-provider / suspended (ForbiddenError) and any other
      // failure land on the generic failure page; the specific reason is audited.
      logger.error("Tailscale auth error", { error: err.message || String(err) });
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "Tailscale sign-in error: " + (err.message || String(err)), req: req });
      res.redirect("/auth/failed");
    }
  });

  // Login page — always accessible (shows available auth methods)
  app.get("/auth/login", (req, res) => {
    if (req.user) return res.redirect("/dashboard");
    var tailscaleAuth = !!(config.tailscale.enabled && config.tailscale.ssoEnabled);
    // Must have at least one auth method enabled
    var oidcAuth = oidc.isEnabled();
    var hasAnyAuth = config.localAuth || config.passkeyEnabled || !!config.google.clientID || tailscaleAuth || oidcAuth;
    if (!hasAnyAuth) return send(res, "error", { title: "No Auth Methods", message: "No authentication methods are configured. Contact the administrator.", user: null }, 503);
    send(res, "login", { user: null, error: null, localAuth: config.localAuth, googleAuth: !!config.google.clientID, oidcAuth: oidcAuth, oidcButtonLabel: config.oidc.buttonLabel || "Sign in with SSO", tailscaleAuth: tailscaleAuth, registrationOpen: config.registrationOpen && config.localAuth, passkeyEnabled: config.passkeyEnabled });
  });

  var loginLimiter = rateLimit.guard({ max: 15, windowMs: C.TIME.minutes(5), algorithm: "fixed-window" });
  app.post("/auth/login", loginLimiter, async (req, res) => {
    if (!config.localAuth) throw new ForbiddenError("Disabled.");
    try {
      var body = (await b.parsers.json(req)) || {};
      var input = validateLoginInput(body);
      if (input.error) throw new ValidationError(input.error);

      // Account lockout check (pre-service, needs DB lookup for timing).
      // Parse once and fail CLOSED on a present-but-unparseable lockedUntil:
      // `new Date(bad).getTime() > Date.now()` is `NaN > now` = false, which would
      // silently lift an active lockout. A corrupt value keeps the account locked
      // (the safe direction); the duration falls back to the standard 30-minute
      // window since the real remaining time can't be computed.
      // input.email is null for an address no account can hold, so the lookup
      // is skipped and the attempt takes the unknown-account path.
      var existing = input.email ? usersRepo.findByEmail(input.email) : null;
      var lockedUntilMs = existing && existing.lockedUntil ? Date.parse(existing.lockedUntil) : 0;
      var isLocked = !!(existing && existing.lockedUntil && (!Number.isFinite(lockedUntilMs) || lockedUntilMs > Date.now()));

      // A locked existing account must be indistinguishable, at the client
      // boundary, from a non-existent or wrong-password account: same uniform 401
      // body, no remaining-minutes countdown, no auth-type tell. Otherwise the
      // distinct "temporarily locked" 403 is an attacker-triggerable existence +
      // local-auth-method oracle (lock a target via 10 wrong guesses, then read
      // the divergent response). The lock is still fully enforced — a locked
      // account never logs in even with the correct password — and the detailed
      // reason is kept in the server-side audit log. Timing is equalized by
      // running the same Argon2id verify path (authenticateLocal) before
      // collapsing to the uniform error, rather than short-circuiting.
      function lockedReject() {
        var lockMinutes = Number.isFinite(lockedUntilMs) ? Math.ceil((lockedUntilMs - Date.now()) / C.TIME.minutes(1)) : 30;
        audit.log(audit.ACTIONS.LOGIN_FAILED_BAD_PASSWORD, { targetId: existing._id, targetEmail: input.email, details: "Account locked (" + lockMinutes + " min remaining)", req: req });
        var err = new AuthenticationError("Invalid email or password.");
        err._locked = true; // already audited — the catch must not re-process it
        return err;
      }

      var user;
      try {
        user = await authService.authenticateLocal(input.email, input.password);
        // Correct credentials but the account is locked: do NOT establish a
        // session — collapse to the uniform 401.
        if (isLocked) throw lockedReject();
      } catch (err) {
        // A refused password check (503) did not test the password. It is
        // rethrown unchanged, ahead of the lock and failed-attempt handling
        // below, for locked and unlocked accounts alike.
        if (err.code === "SERVICE_UNAVAILABLE") throw err;
        // Any failure on a locked account (wrong password, pending, suspended)
        // also collapses to the uniform 401 without incrementing the counter or
        // revealing the lock — a locked account never has its state mutated by a
        // guess and never surfaces a distinguisher. Audit exactly once.
        if (isLocked) throw err._locked ? err : lockedReject();
        if (err.isAppError) {
          // Track failed attempts for lockout (only if the user exists AND has a
          // local password — a passwordless OAuth/passkey account can't be
          // brute-forced here, so counting attempts only lets an attacker lock /
          // pollute its state).
          if (err.statusCode === 401 && existing && !err.noPassword) {
            // Atomic increment — a read-modify-write would let concurrent failed
            // attempts each read the same pre-write counter and slip past the
            // lockout threshold (TOCTOU bypass).
            var attempts = usersRepo.incrementFailedAttempts(existing._id) || 0;
            if (attempts >= 10) {
              // Engage the lock AND reset the counter to 0 in the same write so
              // the post-expiry window starts fresh. Without the reset, the DB
              // keeps the saturated count (e.g. 10); once the 30-minute window
              // lapses the gate at :99 reads only lockedUntil and lets the next
              // request through, but a single wrong password then increments
              // 10→11 and immediately re-locks for another 30 minutes — locking
              // the account indefinitely. The atomic incrementFailedAttempts
              // (single SQL UPDATE) above still guards the pre-lock TOCTOU path.
              usersRepo.update(existing._id, { $set: { lockedUntil: new Date(Date.now() + C.TIME.minutes(30)).toISOString(), failedLoginAttempts: 0 } });
              audit.log(audit.ACTIONS.LOGIN_FAILED_BAD_PASSWORD, { targetId: existing._id, targetEmail: input.email, details: "Account locked after " + attempts + " failed attempts (30 min)", req: req });
            } else {
              audit.log(audit.ACTIONS.LOGIN_FAILED_BAD_PASSWORD, { targetId: existing._id, targetEmail: input.email, details: "Invalid password (attempt " + attempts + "/10)", req: req });
            }
          } else if (err.statusCode === 401) {
            audit.log(audit.ACTIONS.LOGIN_FAILED_NO_ACCOUNT, input.email
              ? { targetEmail: input.email, details: "No account found", req: req }
              : { details: "Unusable email (" + input.emailLength + " characters)", req: req });
          } else if (err.statusCode === 403 && err.pending) {
            err.extras = { pending: true, email: err.email };
          } else if (err.statusCode === 403) {
            audit.log(audit.ACTIONS.LOGIN_FAILED_BAD_PASSWORD, { targetId: existing ? existing._id : undefined, targetEmail: input.email, details: "Suspended account (local)", req: req });
          }
          throw err;
        }
        throw err;
      }

      // Successful login — reset lockout counters
      usersRepo.update(user._id, { $set: { failedLoginAttempts: 0, lockedUntil: null } });
      // Reset through the SAME key transform the limiter's keyFn uses
      // (clientIp.rateKey collapses IPv6 to /64). Resetting on the full /128
      // would clear the wrong bucket and leave an IPv6 client's counter intact.
      loginLimiter.reset(clientIp.rateKey(req));

      // Route through the shared login chokepoint — the same one the Google
      // callback uses — so the 2FA gate lives in exactly one place and a new
      // login entry can't establish a full session past an enabled TOTP.
      var outcome = await sessionService.completeLogin(req, user._id);
      if (outcome.requires2fa) {
        return res.json({ requires2fa: true });
      }
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, targetEmail: user.email, details: "authType: local", req: req });
      var redirect = (!config.setupComplete && user.role === "admin") ? "/admin/setup" : "/dashboard";
      res.json({ success: true, redirect: redirect });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Login error", { error: e.message || String(e) });
      throw new AppError("Login failed.", 500);
    }
  });

  // Local register
  app.get("/auth/register", (req, res) => {
    if (!config.localAuth || !config.registrationOpen) return send(res, "error", { title: "Disabled", message: "Registration is closed.", user: null }, 403);
    if (req.user) return res.redirect("/dashboard");
    send(res, "register", { user: null, error: null, googleAuth: !!config.google.clientID, oidcAuth: oidc.isEnabled(), oidcButtonLabel: config.oidc.buttonLabel || "Sign in with SSO" });
  });

  app.post("/auth/register", rateLimit.guard({ max: 10, windowMs: C.TIME.minutes(15), algorithm: "fixed-window" }), async (req, res) => {
    if (!config.localAuth || !config.registrationOpen) throw new ForbiddenError("Registration is closed.");
    try {
      var body = (await b.parsers.json(req)) || {};
      var input = validateRegisterInput(body);
      if (input.error) throw new ValidationError(input.error);

      var result = await authService.registerLocal(input.displayName, input.email, input.password, { emailVerification: config.emailVerification });

      var user = result.user;
      audit.log(audit.ACTIONS.USER_REGISTERED, { targetId: user._id, targetEmail: user.email, details: "authType: local, role: " + user.role + ", claimed: " + result.claimed + ", verified: " + !result.needsVerification, req: req });

      if (result.needsVerification) {
        var rawToken = createVerificationToken(user._id);
        var verifyUrl = host(req) + "/auth/verify/" + rawToken;
        emailService.sendVerificationEmail({ to: user.email, displayName: user.displayName, verifyUrl: verifyUrl });
        audit.log(audit.ACTIONS.EMAIL_VERIFICATION_SENT, { targetId: user._id, targetEmail: user.email, req: req });
        return res.json({ success: true, redirect: "/auth/pending?email=" + encodeURIComponent(user.email), pending: true });
      }

      await sessionService.loginUser(req, user._id);
      res.json({ success: true, redirect: "/dashboard", claimed: result.claimed });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Register error", { error: e.message || String(e) });
      throw new AppError("Registration failed.", 500);
    }
  });

  app.get("/auth/failed", (req, res) => {
    audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "OAuth failed or domain not authorized", req: req });
    // RFC 9110 §15.5.2: 401 responses MUST carry a WWW-Authenticate challenge.
    // FormBased is not a registered scheme — browsers ignore it — but its
    // presence satisfies the MUST so compliance scanners don't flag the page.
    res.setHeader("WWW-Authenticate", 'FormBased realm="HermitStash"');
    send(res, "error", { title: "Login Failed", message: "Could not sign you in. Your email domain may not be authorized.", user: null }, 401);
  });

  // Lightweight session check for client-side heartbeat (no side effects)
  // Must NOT reset lastActivity — otherwise idle timeout never triggers
  app.get("/auth/session-check", (req, res) => {
    req._skipActivityUpdate = true;
    res.json({ authenticated: !!(req.user && req.user._id) });
  });

  app.post("/auth/logout", (req, res) => {
    // Parse form body for CSRF token. Bounded at 2 KB — more than enough for a
    // CSRF token; anything larger is malicious. The collector caps total bytes
    // at push() time; on overflow we destroy the request and short-circuit via
    // an `aborted` flag so destroy-in-flight data events don't keep pushing.
    var collector = b.safeBuffer.boundedChunkCollector({ maxBytes: 2048 });
    var aborted = false;
    req.on("data", function (c) {
      if (aborted) return;
      try {
        collector.push(c);
      } catch (_e) {
        aborted = true;
        try { req.destroy(); } catch (_e2) { /* request may already be destroyed — oversize body aborted */ }
      }
    });
    req.on("end", async function () {
      if (aborted) return;
      var body = collector.result().toString("utf8");
      var params = Object.fromEntries(new URLSearchParams(body));
      if (!req.session || !validateToken(req.session, req, params)) {
        emitError(req, res, { status: 403, code: "FORBIDDEN", detail: "CSRF validation failed." });
        return;
      }
      audit.log(audit.ACTIONS.LOGOUT, { req: req });
      // Pass res for the secure self-logout: destroys the storage row AND
      // emits W3C Clear-Site-Data + an expired hs_sid cookie so the
      // browser wipes its client-side state. The token logoutUser revokes
      // is req.sessionId — the live cookie this request carried.
      await sessionService.logoutUser(req, res);
      res.redirect("/");
    });
  });
};
