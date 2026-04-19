var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var config = require("../lib/config");
var C = require("../lib/constants");
var rateLimit = require("../lib/rate-limit");
var filesRepo = require("../app/data/repositories/files.repo");
var invitesRepo = require("../app/data/repositories/invites.repo");
var { parseJson } = require("../lib/multipart");
var { hashPassword, sha3Hash, generateToken, timingSafeEqual } = require("../lib/crypto");
var { sendInviteEmail } = require("../lib/email");
var { clearSessionsForUser } = require("../lib/session");
var { validatePassword } = require("../app/shared/validate");
var sessionService = require("../app/domain/auth/session.service");
var requireAdmin = require("../middleware/require-admin");
var { send, host } = require("../middleware/send");
var { validateInviteInput, validateRoleChangeInput, validateSuspendInput, validateDeleteUserInput, validatePaginationParams } = require("../app/http/validators/admin.validator");
var usersRepo = require("../app/data/repositories/users.repo");

module.exports = function (app) {
  // Admin user management page
  app.get("/admin/users", (req, res) => {
    if (!requireAdmin(req, res)) return;
    send(res, "admin-users", { user: req.user });
  });

  // Paginated, searchable, filterable user list (JSON)
  // Search ?q= is rate-limited separately because each request unseals up to
  // USER_SEARCH_SCAN_LIMIT user records — repeating it cheaply is a DoS lever
  // even against admin users.
  app.get("/admin/users/api", rateLimit.middleware("admin-user-search", 60, C.TIME.ONE_MIN), (req, res) => {
    if (!requireAdmin(req, res)) return;
    var q = req.query.q || "";
    var role = req.query.role || "";
    var authType = req.query.authType || "";
    var status = req.query.status || "";
    var pag = validatePaginationParams(req.query);
    var page = pag.page;
    var limit = pag.limit;
    var sort = req.query.sort || "createdAt";
    var dir = req.query.dir || "desc";

    var filterQuery = {};
    if (role) filterQuery.role = role;
    if (authType) filterQuery.authType = authType;
    if (status) filterQuery.status = status;

    var opts = { limit: limit, offset: (page - 1) * limit, orderBy: sort, orderDir: dir };
    var result;

    // Encrypted fields can't be searched via SQL LIKE — fetch a bounded window
    // and filter in JS. 500 rows is plenty for any realistic directory
    // (admins who need cross-corpus search should use an external directory)
    // and bounds the per-request unseal cost.
    var USER_SEARCH_SCAN_LIMIT = 500;
    if (q) {
      result = usersRepo.findPaginated(filterQuery, { limit: USER_SEARCH_SCAN_LIMIT, offset: 0, orderBy: sort, orderDir: dir });
      var qLower = q.toLowerCase();
      result.data = result.data.filter(function (u) {
        return (u.email || "").toLowerCase().includes(qLower) || (u.displayName || "").toLowerCase().includes(qLower);
      });
      result.total = result.data.length;
      result.data = result.data.slice((page - 1) * limit, page * limit);
    } else {
      result = usersRepo.findPaginated(filterQuery, opts);
    }

    var pages = Math.ceil(result.total / limit) || 1;
    var list = result.data.map(function (u) {
      var obj = Object.assign({}, u);
      delete obj.passwordHash;
      delete obj.totpSecret;
      delete obj.totpBackupCodes;
      delete obj.vaultSeed;
      delete obj.vaultPublicKey;
      obj.fileCount = filesRepo.count({ uploadedBy: u._id });
      return obj;
    });

    res.json({ users: list, total: result.total, page: page, pages: pages, limit: limit });
  });

  // List pending invites (JSON)
  app.get("/admin/users/invites/api", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var all = invitesRepo.findAll({});
    var pending = all.filter(function (i) { return i.status === "pending"; });
    var list = pending.map(function (i) {
      return {
        _id: i._id,
        email: i.email,
        role: i.role,
        status: i.status,
        createdAt: i.createdAt,
        expiresAt: i.expiresAt,
        expired: i.expiresAt < new Date().toISOString(),
      };
    });
    res.json({ invites: list });
  });

  // Invite user via email
  app.post("/admin/users/invite", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var check = validateInviteInput(body);
      if (check.error) return res.status(400).json({ error: check.error });
      var email = check.email;
      var role = check.role;
      if (usersRepo.findByEmail(email)) return res.status(400).json({ error: "Email already registered." });

      // Check for existing pending invite
      var existing = invitesRepo.findAll({}).filter(function (i) { return i.email === email && i.status === "pending"; });
      if (existing.length > 0) return res.status(400).json({ error: "Invite already sent to this email." });

      var token = generateToken(32);
      invitesRepo.create({
        email: email,
        role: role === "admin" ? "admin" : "user",
        tokenHash: sha3Hash(token),
        invitedBy: req.user._id,
        status: "pending",
        expiresAt: new Date(Date.now() + 2 * C.TIME.ONE_DAY).toISOString(),
        createdAt: new Date().toISOString(),
      });

      var inviteUrl = host(req) + "/auth/invite/" + token;
      var sent = false;
      try {
        sent = await sendInviteEmail({ to: email, inviteUrl: inviteUrl, inviterName: req.user.displayName || req.user.email, role: role });
      } catch (emailErr) {
        logger.error("Email send failed", { error: emailErr.message });
      }
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { targetEmail: email, details: "User invited as " + role + ", emailSent: " + sent, req: req });
      res.json({ success: true, emailSent: sent });
    } catch (e) {
      logger.error("Invite error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to send invite." });
    }
  });

  // Resend invite email
  app.post("/admin/users/invite/resend", async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var email = String(body.email || "").trim().toLowerCase();
      if (!email) return res.status(400).json({ error: "Email is required." });

      var pending = invitesRepo.findAll({}).filter(function (i) { return i.email === email && i.status === "pending"; });
      if (!pending.length) return res.status(404).json({ error: "No pending invite for this email." });

      var invite = pending[0];
      var token;

      // If expired, generate a new token and extend expiry
      if (invite.expiresAt < new Date().toISOString()) {
        token = generateToken(32);
        invitesRepo.update(invite._id, {
          $set: {
            tokenHash: sha3Hash(token),
            expiresAt: new Date(Date.now() + 2 * C.TIME.ONE_DAY).toISOString(),
          },
        });
      } else {
        // Still valid — we cannot recover the original token from the hash,
        // so generate a fresh token and update the hash
        token = generateToken(32);
        invitesRepo.update(invite._id, {
          $set: { tokenHash: sha3Hash(token) },
        });
      }

      var inviteUrl = host(req) + "/auth/invite/" + token;
      var sent = await sendInviteEmail({ to: email, inviteUrl: inviteUrl, inviterName: req.user.displayName || req.user.email, role: invite.role });
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { targetEmail: email, details: "Invite resent (new token issued; any prior link invalidated), emailSent: " + sent, req: req });
      res.json({ success: true, emailSent: sent });
    } catch (e) {
      logger.error("Invite resend error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to resend invite." });
    }
  });

  // Accept invite — show setup form
  app.get("/auth/invite/:token", (req, res) => {
    var tokenHash = sha3Hash(req.params.token);
    var invite = invitesRepo.findAll({}).filter(function (i) { return i.tokenHash && i.tokenHash.length === tokenHash.length && timingSafeEqual(i.tokenHash, tokenHash) && i.status === "pending"; })[0];
    if (!invite) return send(res, "error", { title: "Invalid Invite", message: "This invite link is invalid or has already been used.", user: null }, 404);
    if (invite.expiresAt < new Date().toISOString()) return send(res, "error", { title: "Invite Expired", message: "This invite has expired. Please ask your admin for a new one.", user: null }, 410);
    send(res, "invite-accept", { email: invite.email, token: req.params.token, user: null, localAuth: config.localAuth, passkeyEnabled: config.passkeyEnabled, googleAuth: !!config.google.clientID });
  });

  // Accept invite — process form
  app.post("/auth/invite/accept", rateLimit.middleware("invite-accept", 10, C.TIME.FIFTEEN_MIN), async (req, res) => {
    try {
      var body = await parseJson(req);
      var token = String(body.token || "");
      var displayName = String(body.displayName || "").slice(0, 100);
      var password = String(body.password || "");
      if (!token || !displayName) return res.status(400).json({ error: "Name is required." });

      // When localAuth is off, never accept a password — force passwordless account
      if (!config.localAuth) {
        password = "";
      }
      if (config.localAuth) {
        var pwCheck = validatePassword(password);
        if (!pwCheck.valid) return res.status(400).json({ error: pwCheck.reason });
      }

      var tokenHash = sha3Hash(token);
      var invite = invitesRepo.findAll({}).filter(function (i) { return i.tokenHash && i.tokenHash.length === tokenHash.length && timingSafeEqual(i.tokenHash, tokenHash) && i.status === "pending"; })[0];
      if (!invite) return res.status(400).json({ error: "Invalid or expired invite." });
      if (invite.expiresAt < new Date().toISOString()) return res.status(400).json({ error: "Invite expired." });
      if (usersRepo.findByEmail(invite.email)) return res.status(400).json({ error: "Account already exists." });

      var passwordHash = password ? await hashPassword(password) : null;
      var newUser = usersRepo.create({
        email: invite.email,
        displayName: displayName,
        passwordHash: passwordHash,
        authType: password ? "local" : "invite",
        role: invite.role,
        status: "active",
        createdAt: new Date().toISOString(),
      });

      invitesRepo.update(invite._id, { $set: { status: "accepted" } });
      audit.log(audit.ACTIONS.USER_REGISTERED, { targetId: newUser._id, targetEmail: invite.email, details: "via invite, role: " + invite.role });

      // Auto-login
      sessionService.loginUser(req, newUser._id);
      res.json({ success: true, redirect: "/dashboard" });
    } catch (e) {
      logger.error("Accept invite error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to create account." });
    }
  });

  // Toggle user role
  app.post("/admin/users/:id/role", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var check = validateRoleChangeInput(req.params.id);
    if (check.error) return res.status(400).json({ error: check.error });
    var target = usersRepo.findById(check.userId);
    if (!target) return res.status(404).json({ error: "Not found." });

    if (target.role === "admin") {
      var adminCount = usersRepo.count({ role: "admin", status: "active" });
      if (adminCount <= 1) {
        return res.status(400).json({ error: "Cannot remove the last admin." });
      }
    }

    var oldRole = target.role;
    var newRole = target.role === "admin" ? "user" : "admin";
    usersRepo.update(target._id, { $set: { role: newRole } });

    audit.log(audit.ACTIONS.USER_ROLE_CHANGED, { targetId: target._id, targetEmail: target.email, details: oldRole + " -> " + newRole, req: req });

    res.json({ success: true, newRole: newRole });
  });

  // Suspend user
  app.post("/admin/users/:id/suspend", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var check = validateSuspendInput(req.params.id);
    if (check.error) return res.status(400).json({ error: check.error });
    var target = usersRepo.findById(check.userId);
    if (!target) return res.status(404).json({ error: "Not found." });

    if (target.role === "admin") {
      var adminCount = usersRepo.count({ role: "admin", status: "active" });
      if (adminCount <= 1) {
        return res.status(400).json({ error: "Cannot suspend the last admin." });
      }
    }

    usersRepo.update(target._id, { $set: { status: "suspended" } });
    clearSessionsForUser(target._id);

    audit.log(audit.ACTIONS.USER_SUSPENDED, { targetId: target._id, targetEmail: target.email, req: req });

    res.json({ success: true });
  });

  // Unsuspend user
  app.post("/admin/users/:id/unsuspend", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var target = usersRepo.findById(req.params.id);
    if (!target) return res.status(404).json({ error: "Not found." });

    usersRepo.update(target._id, { $set: { status: "active" } });

    audit.log(audit.ACTIONS.USER_UNSUSPENDED, { targetId: target._id, targetEmail: target.email, req: req });

    res.json({ success: true });
  });

  // Delete user and reassign files
  app.post("/admin/users/:id/delete", (req, res) => {
    if (!requireAdmin(req, res)) return;
    var check = validateDeleteUserInput(req.params.id);
    if (check.error) return res.status(400).json({ error: check.error });
    var target = usersRepo.findById(check.userId);
    if (!target) return res.status(404).json({ error: "Not found." });

    if (target.role === "admin") {
      var adminCount = usersRepo.count({ role: "admin", status: "active" });
      if (adminCount <= 1) {
        return res.status(400).json({ error: "Cannot delete the last admin." });
      }
    }

    var result = usersRepo.deleteUser(target._id, "deleted");
    clearSessionsForUser(target._id);

    var reassigned = result ? result.filesReassigned : 0;
    audit.log(audit.ACTIONS.USER_DELETED, { targetId: target._id, targetEmail: target.email, details: "filesReassigned: " + reassigned, req: req });

    res.json({ success: true, filesReassigned: reassigned });
  });
};
