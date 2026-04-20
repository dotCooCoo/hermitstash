var config = require("../lib/config");
var C = require("../lib/constants");
var logger = require("../app/shared/logger");
var usersRepo = require("../app/data/repositories/users.repo");
var { parseJson } = require("../lib/multipart");
var { getAuthUrl, exchangeCode, generateState } = require("../lib/google-auth");
var emailService = require("../app/domain/integrations/email.service");
var { send, host } = require("../middleware/send");
var audit = require("../lib/audit");
var rateLimit = require("../lib/rate-limit");
var authService = require("../app/domain/auth/auth.service");
var sessionService = require("../app/domain/auth/session.service");
var { validateLoginInput, validateRegisterInput } = require("../app/http/validators/auth.validator");
var { createVerificationToken } = require("./verification");
var { validateToken } = require("../app/security/csrf-policy");

module.exports = function (app) {
  // Google OAuth
  app.get("/auth/google", (req, res) => {
    if (!config.google.clientID) {
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "Google OAuth not configured (no Client ID)", req: req });
      return send(res, "error", { title: "Not Configured", message: "Google OAuth is not set up. Add a Client ID in Admin Settings.", user: null }, 500);
    }
    var state = generateState();
    req.session.oauthState = state;
    var url = getAuthUrl(state, req);
    res.redirect(url);
  });

  app.get("/auth/google/callback", rateLimit.middleware("google-callback", 10, C.TIME.ONE_MIN), async (req, res) => {
    try {
      var code = req.query.code;
      if (!code) {
        logger.error("Google callback: no code", { error: "Missing code parameter" });
        return res.redirect("/auth/failed");
      }

      // Verify state to prevent CSRF
      if (!req.query.state || req.query.state !== req.session.oauthState) {
        delete req.session.oauthState;
        audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, { details: "OAuth state mismatch (CSRF protection)", req: req });
        return res.redirect("/auth/failed");
      }
      delete req.session.oauthState;

      var profile = await exchangeCode(code, req);

      var result = authService.resolveGoogleUser(profile, config.allowedDomains);
      var user = result.user;

      if (result.isNew) {
        audit.log(audit.ACTIONS.USER_REGISTERED, { targetId: user._id, targetEmail: user.email, details: "authType: google, role: " + user.role, req: req });
      }

      sessionService.loginUser(req, user._id);
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

  app.post("/auth/login", rateLimit.middleware("login", 15, C.TIME.FIVE_MIN), async (req, res) => {
    if (!config.localAuth) return res.status(403).json({ error: "Disabled." });
    try {
      var body = await parseJson(req);
      var input = validateLoginInput(body);
      if (input.error) return res.status(400).json({ error: input.error });

      // Account lockout check (pre-service, needs DB lookup for timing)
      var existing = usersRepo.findByEmail(input.email);
      if (existing && existing.lockedUntil && new Date(existing.lockedUntil).getTime() > Date.now()) {
        var lockMinutes = Math.ceil((new Date(existing.lockedUntil).getTime() - Date.now()) / C.TIME.ONE_MIN);
        audit.log(audit.ACTIONS.LOGIN_FAILED_BAD_PASSWORD, { targetId: existing._id, targetEmail: input.email, details: "Account locked (" + lockMinutes + " min remaining)", req: req });
        return res.status(403).json({ error: "Account temporarily locked. Try again in " + lockMinutes + " minutes." });
      }

      var user;
      try {
        user = await authService.authenticateLocal(input.email, input.password);
      } catch (err) {
        if (err.isAppError) {
          // Track failed attempts for lockout (only if user exists)
          if (err.statusCode === 401 && existing) {
            var attempts = (parseInt(existing.failedLoginAttempts, 10) || 0) + 1;
            var lockUpdate = { failedLoginAttempts: attempts };
            if (attempts >= 10) {
              lockUpdate.lockedUntil = new Date(Date.now() + C.TIME.THIRTY_MIN).toISOString();
              audit.log(audit.ACTIONS.LOGIN_FAILED_BAD_PASSWORD, { targetId: existing._id, targetEmail: input.email, details: "Account locked after " + attempts + " failed attempts (30 min)", req: req });
            } else {
              audit.log(audit.ACTIONS.LOGIN_FAILED_BAD_PASSWORD, { targetId: existing._id, targetEmail: input.email, details: "Invalid password (attempt " + attempts + "/10)", req: req });
            }
            usersRepo.update(existing._id, { $set: lockUpdate });
          } else if (err.statusCode === 401) {
            audit.log(audit.ACTIONS.LOGIN_FAILED_NO_ACCOUNT, { targetEmail: input.email, details: "No account found", req: req });
          } else if (err.statusCode === 403 && err.pending) {
            return res.status(403).json({ error: err.message, pending: true, email: err.email });
          } else if (err.statusCode === 403) {
            audit.log(audit.ACTIONS.LOGIN_FAILED_BAD_PASSWORD, { targetId: existing ? existing._id : undefined, targetEmail: input.email, details: "Suspended account (local)", req: req });
          }
          return res.status(err.statusCode).json({ error: err.message });
        }
        throw err;
      }

      // Successful login — reset lockout counters
      usersRepo.update(user._id, { $set: { failedLoginAttempts: 0, lockedUntil: null } });
      rateLimit.reset("login", rateLimit.getIp(req));

      // Check if 2FA is required
      if (authService.requires2fa(user._id)) {
        sessionService.start2faPending(req, user._id);
        return res.json({ requires2fa: true });
      }

      authService.touchLogin(user._id);
      sessionService.loginUser(req, user._id);
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, { targetId: user._id, targetEmail: user.email, details: "authType: local", req: req });
      var redirect = (!config.setupComplete && user.role === "admin") ? "/admin/setup" : "/dashboard";
      res.json({ success: true, redirect: redirect });
    } catch (e) {
      logger.error("Login error", { error: e.message || String(e) });
      res.status(500).json({ error: "Login failed." });
    }
  });

  // Local register
  app.get("/auth/register", (req, res) => {
    if (!config.localAuth || !config.registrationOpen) return send(res, "error", { title: "Disabled", message: "Registration is closed.", user: null }, 403);
    if (req.user) return res.redirect("/dashboard");
    send(res, "register", { user: null, error: null, googleAuth: !!config.google.clientID });
  });

  app.post("/auth/register", rateLimit.middleware("register", 10, C.TIME.FIFTEEN_MIN), async (req, res) => {
    if (!config.localAuth || !config.registrationOpen) return res.status(403).json({ error: "Registration is closed." });
    try {
      var body = await parseJson(req);
      var input = validateRegisterInput(body);
      if (input.error) return res.status(400).json({ error: input.error });

      var result;
      try {
        result = await authService.registerLocal(input.displayName, input.email, input.password, { emailVerification: config.emailVerification });
      } catch (err) {
        if (err.isAppError) return res.status(err.statusCode).json({ error: err.message });
        throw err;
      }

      var user = result.user;
      audit.log(audit.ACTIONS.USER_REGISTERED, { targetId: user._id, targetEmail: user.email, details: "authType: local, role: " + user.role + ", claimed: " + result.claimed + ", verified: " + !result.needsVerification, req: req });

      if (result.needsVerification) {
        var rawToken = createVerificationToken(user._id);
        var verifyUrl = host(req) + "/auth/verify/" + rawToken;
        emailService.sendVerificationEmail({ to: user.email, displayName: user.displayName, verifyUrl: verifyUrl });
        audit.log(audit.ACTIONS.EMAIL_VERIFICATION_SENT, { targetId: user._id, targetEmail: user.email, req: req });
        return res.json({ success: true, redirect: "/auth/pending?email=" + encodeURIComponent(user.email), pending: true });
      }

      sessionService.loginUser(req, user._id);
      res.json({ success: true, redirect: "/dashboard", claimed: result.claimed });
    } catch (e) {
      logger.error("Register error", { error: e.message || String(e) });
      res.status(500).json({ error: "Registration failed." });
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
    // CSRF token; anything larger is malicious. Use a running counter instead
    // of Buffer.concat per chunk (that was O(n²)), and short-circuit via an
    // `aborted` flag so destroy-in-flight data events don't keep pushing.
    var chunks = [];
    var total = 0;
    var aborted = false;
    req.on("data", function (c) {
      if (aborted) return;
      total += c.length;
      if (total > 2048) {
        aborted = true;
        try { req.destroy(); } catch (_e) { /* request may already be destroyed — oversize body aborted */ }
        return;
      }
      chunks.push(c);
    });
    req.on("end", function () {
      if (aborted) return;
      var body = Buffer.concat(chunks).toString("utf8");
      var params = Object.fromEntries(new URLSearchParams(body));
      if (!req.session || !validateToken(req.session, req, params)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "CSRF validation failed." }));
      }
      audit.log(audit.ACTIONS.LOGOUT, { req: req });
      sessionService.logoutUser(req);
      res.redirect("/");
    });
  });
};
