var clientIp = require("../lib/client-ip");
var b = require("../lib/vendor/blamejs");
var rateLimit = require("../lib/rate-limit");
var config = require("../lib/config");
var C = require("../lib/constants");
var logger = require("../app/shared/logger");
var usersRepo = require("../app/data/repositories/users.repo");
var { getAuthUrl, exchangeCode, generateState } = require("../lib/google-auth");
var emailService = require("../app/domain/integrations/email.service");
var { send, host } = require("../middleware/send");
var { emitError } = require("../middleware/respond-error");
var audit = require("../lib/audit");
var authService = require("../app/domain/auth/auth.service");
var sessionService = require("../app/domain/auth/session.service");
var { validateLoginInput, validateRegisterInput } = require("../app/http/validators/auth.validator");
var { createVerificationToken } = require("./verification");
var { validateToken } = require("../app/security/csrf-policy");
var { AppError, ValidationError, AuthenticationError, ForbiddenError } = require("../app/shared/errors");

module.exports = function (app) {
  // Google OAuth
  app.get("/auth/google", (req, res) => {
    if (!config.google.clientID) {
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "Google OAuth not configured (no Client ID)", req: req });
      return send(res, "error", { title: "Not Configured", message: "Google OAuth is not set up. Add a Client ID in Admin Settings.", user: null }, 500);
    }
    var state = generateState();
    // Bind a creation timestamp so a captured state can't be replayed across a
    // long-lived session window (state is single-use and expires in 5 minutes).
    req.session.oauthState = { value: state, ts: Date.now() };
    var url = getAuthUrl(state, req);
    res.redirect(url);
  });

  app.get("/auth/google/callback", rateLimit.guard({ max: 10, windowMs: C.TIME.minutes(1), algorithm: "fixed-window" }), async (req, res) => {
    try {
      var code = req.query.code;
      if (!code) {
        logger.error("Google callback: no code", { error: "Missing code parameter" });
        return res.redirect("/auth/failed");
      }

      // Verify state to prevent CSRF: constant-time value match + freshness.
      var st = req.session.oauthState;
      var stateOk = !!st && !!req.query.state &&
        b.crypto.timingSafeEqual(String(req.query.state), String(st.value || ""));
      var fresh = !!st && (Date.now() - (st.ts || 0)) <= C.TIME.minutes(5);
      if (!stateOk || !fresh) {
        delete req.session.oauthState;
        audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "OAuth state mismatch or expired (CSRF protection)", req: req });
        return res.redirect("/auth/failed");
      }
      delete req.session.oauthState;

      var profile = await exchangeCode(code, req);

      var result = authService.resolveGoogleUser(profile, config.allowedDomains);
      var user = result.user;

      if (result.isNew) {
        audit.log(audit.ACTIONS.USER_REGISTERED, { targetId: user._id, targetEmail: user.email, details: "authType: google, role: " + user.role, req: req });
      }

      await sessionService.loginUser(req, user._id);
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, targetEmail: user.email, details: "authType: google", req: req });
      res.redirect("/dashboard");
    } catch (err) {
      logger.error("Auth error", { error: err.message || String(err) });
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "Google callback error: " + (err.message || String(err)), req: req });
      res.redirect("/auth/failed");
    }
  });

  // Login page — always accessible (shows available auth methods)
  app.get("/auth/login", (req, res) => {
    if (req.user) return res.redirect("/dashboard");
    // Must have at least one auth method enabled
    var hasAnyAuth = config.localAuth || config.passkeyEnabled || !!config.google.clientID;
    if (!hasAnyAuth) return send(res, "error", { title: "No Auth Methods", message: "No authentication methods are configured. Contact the administrator.", user: null }, 503);
    send(res, "login", { user: null, error: null, localAuth: config.localAuth, googleAuth: !!config.google.clientID, registrationOpen: config.registrationOpen && config.localAuth, passkeyEnabled: config.passkeyEnabled });
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
      var existing = usersRepo.findByEmail(input.email);
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
            audit.log(audit.ACTIONS.LOGIN_FAILED_NO_ACCOUNT, { targetEmail: input.email, details: "No account found", req: req });
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

      // Check if 2FA is required
      if (authService.requires2fa(user._id)) {
        await sessionService.start2faPending(req, user._id);
        return res.json({ requires2fa: true });
      }

      authService.touchLogin(user._id);
      await sessionService.loginUser(req, user._id);
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
    send(res, "register", { user: null, error: null, googleAuth: !!config.google.clientID });
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
    // RFC 7235 §3.1: 401 responses MUST carry a WWW-Authenticate challenge.
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
      // emits RFC 9527 Clear-Site-Data + an expired hs_sid cookie so the
      // browser wipes its client-side state. The token logoutUser revokes
      // is req.sessionId — the live cookie this request carried.
      await sessionService.logoutUser(req, res);
      res.redirect("/");
    });
  });
};
