"use strict";
// Admin auth + page editor routes.
// Uses b.auth.password (Argon2id), b.session, b.permissions to gate
// /admin, b.audit.safeEmit for every page edit, b.cache (invalidated on
// save), b.slug for title→slug coercion, and b.middleware.csrf for
// form-POST protection.
//
// Single-admin model: one admin seeded from WIKI_ADMIN_EMAIL +
// WIKI_ADMIN_PASSWORD at first boot. Apps wanting a larger editor
// surface swap b.auth.password for whatever auth surface they need;
// the route shapes here stay the same.

var b = require("@blamejs/core");
var nav = require("../lib/nav");

function _layoutData(req, ctx) {
  var pathname = (req.url || "/").split("?")[0];
  return {
    cspNonce:    (req.res && req.res.locals && req.res.locals.cspNonce) || "",
    locale:      req.locale || "en",
    dir:         req.dir ? req.dir() : "ltr",
    user:        req.user || null,
    csrfToken:   req.csrfToken || "",
    searchQuery: "",
    title:       "",
    assets:      (ctx && ctx.assets) || {},
    nav:          nav.NAV_GROUPS,
    currentGroup: nav.groupForPath(pathname),
    currentPath:  pathname,
  };
}

function register(router, ctx) {
  var db = ctx.db;
  var template = ctx.template;
  var audit = ctx.audit;
  var pageCache = ctx.pageCache;
  var perms = ctx.perms;
  var passwordAuth = ctx.passwordAuth;
  var session = ctx.session;
  var notify = ctx.notify;
  var apiKeys = ctx.apiKeys;
  var loginLockout = ctx.loginLockout;
  var trustProxy = ctx.trustProxy;

  // Resolve the cookie Secure attribute through the framework's
  // trust-proxy-aware protocol detector. With trustProxy:false (the
  // default), x-forwarded-proto is ignored and only req.socket.encrypted
  // counts — preventing an attacker from spoofing https with a header
  // injection. Operators behind a real TLS terminator opt in via
  // WIKI_TRUST_PROXY=1 in build-app.js.
  function _secureCookieFlag(req) {
    return b.requestHelpers.requestProtocol(req, { trustProxy: trustProxy }) === "https"
      ? "; Secure" : "";
  }

  // ---- Login form ----
  router.get("/login", function (req, res) {
    if (req.user) return b.render.redirect(res, "/admin");
    var data = Object.assign(_layoutData(req, ctx), { title: "Sign in", error: null });
    b.render.htmlString(res, template.render("login", data));
  });

  // ---- Login submit ----
  router.post("/login", async function (req, res) {
    var body = req.body || {};
    var email = String(body.email || "").trim().toLowerCase();
    var password = String(body.password || "");
    var data = Object.assign(_layoutData(req, ctx), { title: "Sign in" });

    function _showError(msg, opts) {
      var status = (opts && opts.status) || 401;
      data.error = msg;
      return b.render.htmlString(res, template.render("login", data),
        { status: status });
    }

    if (!email || !password) {
      return _showError("Email and password are required.", { status: 400 });
    }

    // Pre-check the lockout BEFORE the Argon2 verify — a locked-out
    // attacker shouldn't get to keep burning ~250ms of CPU per try.
    // Lockout state is keyed on the submitted email so an attacker
    // probing many users can't lock the legitimate user out by
    // hammering a different account.
    var lockState = await loginLockout.check(email);
    if (lockState.locked) {
      var retryAfterMs = Math.max(0, lockState.lockedUntil - Date.now());
      res.setHeader("Retry-After", Math.ceil(retryAfterMs / b.constants.TIME.seconds(1)).toString());
      return _showError("Too many failed attempts. Try again later.", { status: 429 });
    }

    // Look up admin row. Single-admin shape — table has at most one row.
    var row = db.prepare(
      "SELECT id, email, passwordHash FROM admin_users WHERE email = ? LIMIT 1"
    ).get(email);
    if (!row) {
      await loginLockout.recordFailure(email, { req: req });
      audit.safeEmit({
        action:   "wiki.login.failure",
        outcome:  "failure",
        actor:    b.requestHelpers.extractActorContext(req),
        reason:   "no-such-user",
      });
      return _showError("Invalid credentials.");
    }
    // b.auth.password.verify(stored, plain) — argument order matters
    var ok = await passwordAuth.verify(row.passwordHash, password);
    if (!ok) {
      await loginLockout.recordFailure(email, { req: req });
      audit.safeEmit({
        action:   "wiki.login.failure",
        outcome:  "failure",
        actor:    b.requestHelpers.extractActorContext(req, { userId: row.id }),
        reason:   "bad-password",
      });
      return _showError("Invalid credentials.");
    }
    // Successful auth clears the failure counter and any pending
    // lockout for this email.
    await loginLockout.recordSuccess(email, { req: req });
    // Build a session bound to this admin. session.create returns
    // { token, expiresAt } — the cookie value is the token, max-age
    // mirrors expiresAt. The scope stored on the session is the actual
    // scope the role grants (wiki:admin), not the role name — perms
    // checks compare scope strings, so the role/scope split must be
    // honored or the comparison only works by string-coincidence.
    var sess = await session.create({ userId: row.id, data: { email: row.email, scopes: ["wiki:admin"] } });
    var maxAge = Math.max(0, Math.floor((sess.expiresAt - Date.now()) / b.constants.TIME.seconds(1)));
    res.setHeader("Set-Cookie",
      "wiki_sid=" + sess.token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + maxAge + _secureCookieFlag(req));
    audit.safeEmit({
      action:   "wiki.login.success",
      outcome:  "success",
      actor:    b.requestHelpers.extractActorContext(req, { userId: row.id }),
    });
    b.render.redirect(res, "/admin");
  });

  // ---- Logout ----
  router.post("/logout", async function (req, res) {
    if (req.session && req.session.id) {
      await session.destroy(req.session.id);
    }
    res.setHeader("Set-Cookie",
      "wiki_sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + _secureCookieFlag(req));
    audit.safeEmit({
      action:   "wiki.logout",
      outcome:  "success",
      actor:    b.requestHelpers.extractActorContext(req),
    });
    b.render.redirect(res, "/");
  });

  // ---- Admin gate ----
  // perms.require(scope) returns a 3-arg middleware that emits a
  // 401/403 if the actor lacks the scope. The scope string here must
  // match what gets stored on the session (see login above).
  var requireAdmin = perms.require("wiki:admin");

  router.get("/admin", requireAdmin, function (req, res) {
    var pages = db.prepare(
      "SELECT groupName, slug, title, updatedAt, updatedBy " +
      "FROM pages ORDER BY groupName, slug"
    ).all().map(function (r) {
      return Object.assign(r, { updatedAtIso: new Date(r.updatedAt).toISOString() });
    });
    var data = Object.assign(_layoutData(req, ctx), {
      title: "Admin",
      pages: pages,
    });
    b.render.htmlString(res, template.render("admin/dashboard", data));
  });

  // GET /admin/edit  → new page
  // GET /admin/edit/:group/:slug → edit existing
  router.get("/admin/edit", requireAdmin, function (req, res) {
    var data = Object.assign(_layoutData(req, ctx), {
      title:     "New page",
      isNew:     true,
      groupName: "",
      slug:      "",
      titleField: "",
      body:      "",
      error:     null,
    });
    // Template var collision — use `titleField` for the form's title
    // input; `title` stays the page-meta title in the layout (already
    // set by Object.assign earlier, so no re-assignment needed here).
    data.titleField = "";
    b.render.htmlString(res, template.render("admin/edit", data));
  });

  router.get("/admin/edit/:group/:slug", requireAdmin, function (req, res) {
    var row = db.prepare(
      "SELECT groupName, slug, title, body FROM pages WHERE groupName = ? AND slug = ?"
    ).get(req.params.group, req.params.slug);
    if (!row) return b.render.htmlString(res, "Not found", { status: 404 });
    var data = Object.assign(_layoutData(req, ctx), {
      title:     "Edit " + row.title,
      isNew:     false,
      groupName: row.groupName,
      slug:      row.slug,
      titleField: row.title,
      body:      row.body,
      error:     null,
    });
    b.render.htmlString(res, template.render("admin/edit", data));
  });

  // ---- Save (create or update) ----
  router.post("/admin/save", requireAdmin, async function (req, res) {
    var body = req.body || {};
    // b.slug normalizes user-typed input into URL-safe shapes — same
    // transform across this app and any operator code building slugs.
    // Fallback "page" / "untitled" prevents an empty input from ever
    // hitting the DB (b.slug returns "" on whitespace-only input).
    var groupName = b.slug(String(body.groupName || ""), { fallback: "" });
    var slug = b.slug(String(body.slug || ""), { fallback: "" });
    var title = String(body.title || "").trim();
    var content = String(body.body || "");
    // Re-render the edit form with the operator's submitted values + an
    // error banner. Used for any validation failure so the user doesn't
    // lose what they just typed.
    function _rerenderEdit(errMsg, opts) {
      var status = (opts && opts.status) || 400;
      var data = Object.assign(_layoutData(req, ctx), {
        title:      groupName && slug ? "Edit " + groupName + "/" + slug : "New page",
        isNew:      !(groupName && slug),
        groupName:  groupName,
        slug:       slug,
        titleField: title,
        body:       content,
        error:      errMsg,
      });
      return b.render.htmlString(res, template.render("admin/edit", data), { status: status });
    }

    if (!groupName || !slug || !title) {
      return _rerenderEdit("Group, slug, and title are all required.", { status: 400 });
    }
    // Reject malformed HTML at the operator boundary so a forgotten
    // `</div>` doesn't ship and silently break the rendered page (the
    // wiki renders body raw — `{{{ body }}}` — by design, so the
    // browser's tag-recovery would otherwise swallow surrounding
    // layout into the unclosed element).
    var htmlProblem = b.htmlBalance.check(content);
    if (htmlProblem) {
      audit.safeEmit({
        action:   "wiki.page.edited",
        outcome:  "failure",
        actor:    b.requestHelpers.extractActorContext(req),
        resource: { kind: "wiki.page", id: groupName + "/" + slug },
        reason:   htmlProblem.code,
        metadata: { message: htmlProblem.message },
      });
      return _rerenderEdit(
        "Invalid HTML — " + htmlProblem.message +
          ". Fix the issue and save again; your text is preserved below.",
        { status: 400 }
      );
    }
    var now = Date.now();
    var userId = req.user ? req.user.userId : "unknown";
    db.prepare(
      "INSERT INTO pages (groupName, slug, title, body, updatedAt, updatedBy) " +
      "VALUES (?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT (groupName, slug) DO UPDATE SET " +
      "  title = excluded.title, body = excluded.body, " +
      "  updatedAt = excluded.updatedAt, updatedBy = excluded.updatedBy"
    ).run(groupName, slug, title, content, now, userId);

    // Invalidate the page cache for this key so readers see the edit.
    await pageCache.del(groupName + "/" + slug);

    audit.safeEmit({
      action:   "wiki.page.edited",
      outcome:  "success",
      actor:    b.requestHelpers.extractActorContext(req),
      resource: { kind: "wiki.page", id: groupName + "/" + slug },
      metadata: { title: title, byteLength: content.length },
    });

    // Notify on every page edit. The 'log' channel always fires (dev
    // visibility); the 'webhook' channel fires when WIKI_WEBHOOK_URL
    // + WIKI_WEBHOOK_SECRET are configured. b.notify dispatches via
    // sendBatch — one channel down (e.g. webhook receiver 5xx) does
    // NOT fail the other.
    var notifyMessage = {
      event:     "wiki.page.edited",
      group:     groupName,
      slug:      slug,
      title:     title,
      byteLength: content.length,
      editedAt:  now,
      editedBy:  userId,
    };
    var inputs = [{ channel: "log", message: notifyMessage, req: req }];
    if (notify.channels().indexOf("webhook") !== -1) {
      inputs.push({ channel: "webhook", message: notifyMessage, req: req });
    }
    // sendBatch is fire-and-forget at the route level — we don't block
    // the redirect on outbound webhook delivery. b.retry inside notify
    // handles transient failures; permanent ones audit.
    notify.sendBatch(inputs).catch(function () { /* notify is best-effort */ });

    b.render.redirect(res, "/" + groupName + "/" + slug);
  });

  // ---- API keys (content-management) ----
  router.get("/admin/api-keys", requireAdmin, async function (req, res) {
    if (!req.user || !req.user.userId) {
      return b.render.htmlString(res, "Unauthorized", { status: 401 });
    }
    var keys = await apiKeys.listForOwner(req.user.userId, { req: req });
    var data = Object.assign(_layoutData(req, ctx), {
      title:  "API Keys",
      keys:   keys,
      issued: null,
    });
    b.render.htmlString(res, template.render("admin/api-keys", data));
  });

  router.post("/admin/api-keys/issue", requireAdmin, async function (req, res) {
    if (!req.user || !req.user.userId) {
      return b.render.htmlString(res, "Unauthorized", { status: 401 });
    }
    var body = req.body || {};
    var label = String(body.label || "").trim() || null;
    var scopes = String(body.scopes || "").split(",")
      .map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length > 0; });
    // Default issued API keys to wiki:admin so the operator gets a usable
    // key out of the form. Adjust scopes via the form's text field; the
    // perms primitive enforces the chosen scope at the route boundary.
    if (scopes.length === 0) scopes = ["wiki:admin"];
    var issued = await apiKeys.issue({
      ownerId:  req.user.userId,
      scopes:   scopes,
      metadata: { label: label },
      req:      req,
    });
    // The plaintext secret is shown ONCE; subsequent listings only
    // surface the prefix + id.
    var keys = await apiKeys.listForOwner(req.user.userId, { req: req });
    var data = Object.assign(_layoutData(req, ctx), {
      title:  "API Keys",
      keys:   keys,
      issued: { id: issued.id, key: issued.key, scopes: scopes.join(", ") },
    });
    b.render.htmlString(res, template.render("admin/api-keys", data));
  });

  router.post("/admin/api-keys/revoke", requireAdmin, async function (req, res) {
    var body = req.body || {};
    var id = String(body.id || "").trim();
    if (!/^wiki:[a-f0-9]+$/.test(id)) {
      return b.render.htmlString(res, "Bad request", { status: 400 });
    }
    await apiKeys.revoke(id, { req: req });
    b.render.redirect(res, "/admin/api-keys");
  });
}

module.exports = { register: register };
