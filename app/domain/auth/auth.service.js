/**
 * Auth Service — business logic for authentication and user registration.
 * Routes handle HTTP; this handles identity resolution and account creation.
 */
var b = require("../../../lib/vendor/blamejs");
var config = require("../../../lib/config");
var tailscale = require("../../../lib/tailscale");
var passwordGate = require("../../../lib/password-gate");
var usersRepo = require("../../data/repositories/users.repo");
var filesRepo = require("../../data/repositories/files.repo");
var { validateEmail, validatePassword, validateDisplayName } = require("../../shared/validate");
var { ValidationError, AuthenticationError, ForbiddenError, ConflictError } = require("../../shared/errors");

// Is this account's email address proven to be controlled by the account holder?
// An anonymous public upload is reassigned to an account ONLY when this is true —
// email equality alone is never proof of email ownership. Proof exists only when
// email verification is operative (an account passes a token round-trip to its
// address) AND the account has cleared that round-trip (status "active", i.e. not
// "pending"). With verification disabled there is no proof-of-control signal at
// all, so the equality auto-claim must not fire — an explicit, audited claim is a
// separate action, never an equality grant.
function emailIsVerified(user) {
  return !!(user && config.emailVerification && user.status === "active");
}

// Lazily-cached dummy Argon2id hash (default params, so its verify cost matches a
// real one). Verifying against it on the non-existent / passwordless login paths
// keeps the response time constant, denying an attacker a timing oracle for which
// emails have an active local password.
var _dummyHashPromise = null;
function dummyPasswordHash() {
  if (!_dummyHashPromise) {
    var pending = passwordGate.hash(b.crypto.generateToken(16));
    _dummyHashPromise = pending;
    // A refused or failed hash is removed from the cache, and the next caller
    // starts a new one.
    pending.catch(function () {
      if (_dummyHashPromise === pending) _dummyHashPromise = null;
    });
  }
  return _dummyHashPromise;
}

/**
 * Register a new local user.
 * Returns the created user record.
 */
async function registerLocal(displayName, email, password, opts) {
  var nameResult = validateDisplayName(displayName);
  if (!nameResult.valid) throw new ValidationError(nameResult.reason);
  var emailResult = validateEmail(email);
  if (!emailResult.valid) throw new ValidationError(emailResult.reason);
  var pwResult = validatePassword(password);
  if (!pwResult.valid) throw new ValidationError(pwResult.reason);

  var existing = usersRepo.findByEmail(emailResult.email);
  if (existing) throw new ConflictError("Email already registered.");

  var passwordHash = await passwordGate.hash(password);
  var isAdmin = usersRepo.count({}) === 0;
  var needsVerification = opts && opts.emailVerification && !isAdmin;

  var user = usersRepo.create({
    email: emailResult.email,
    displayName: nameResult.name,
    passwordHash: passwordHash,
    authType: "local",
    role: isAdmin ? "admin" : "user",
    status: needsVerification ? "pending" : "active",
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
  });

  // Reassign anonymous public uploads made with this email — but ONLY once the
  // account's email is proven (verification operative + account active). A brand-new
  // account is either "pending" (verification on, address not yet proven) or has no
  // proof signal at all (verification off), so this never fires at registration: a
  // verified account's uploads are claimed later, on its first authenticated visit
  // (see routes/dashboard.js), gated by the same emailIsVerified() check.
  var claimed = [];
  if (emailIsVerified(user)) {
    claimed = filesRepo.findAll({ uploaderEmail: user.email, uploadedBy: "public" });
    for (var f of claimed) {
      filesRepo.update(f._id, { $set: { uploadedBy: user._id } });
    }
  }

  return { user: user, claimed: claimed.length, needsVerification: needsVerification };
}

/**
 * Authenticate a local user by email and password.
 * Returns the user or throws. An empty or null email finds no account, so it
 * takes the unknown-account branch below, dummy verify included.
 */
async function authenticateLocal(email, password) {
  if (!password) throw new ValidationError("Email and password required.");

  var user = email ? usersRepo.findByEmail(email) : null;
  if (!user) {
    // Constant-cost verify so a non-existent account costs the same as a wrong
    // password on a real one — no account-existence timing oracle.
    await passwordGate.verify(await dummyPasswordHash(), password);
    throw new AuthenticationError("Invalid email or password.");
  }
  if (!user.passwordHash) {
    // Passwordless account (Google-OAuth / passkey-only): equalize timing, and
    // mark the error so the caller skips failed-attempt lockout — locking a
    // password that does not exist is a pure DoS / state-pollution vector, not a
    // brute-force defense.
    await passwordGate.verify(await dummyPasswordHash(), password);
    var noPwErr = new AuthenticationError("Invalid email or password.");
    noPwErr.noPassword = true;
    throw noPwErr;
  }
  // Verify the password BEFORE any account-status gate. Throwing pending/suspended
  // first skipped the Argon2id cost (a status-by-timing oracle) and revealed an
  // account's status to anyone holding only its email. Now the same verify cost is
  // paid on every existing-account branch, and only a caller who proves the
  // password learns pending/suspended state.
  var valid = await passwordGate.verify(user.passwordHash, password);
  if (!valid) throw new AuthenticationError("Invalid email or password.");

  if (user.status === "pending") {
    var err = new ForbiddenError("Please verify your email before signing in.");
    err.pending = true;
    err.email = user.email;
    throw err;
  }
  if (user.status === "suspended") throw new ForbiddenError("Account suspended.");

  return user;
}

/**
 * Resolve a Google OAuth profile to an existing or new user.
 * Returns { user, isNew }.
 */
function resolveGoogleUser(profile, allowedDomains) {
  if (!profile || !profile.email) throw new ValidationError("Google returned no email.");

  // The IdP userinfo email is untrusted input that never passes validateEmail
  // (which is applied only on the local-registration path). An addr-spec has
  // exactly one "@" (RFC 5322 §3.4.1); a multi-@ address like
  // x@allowed.com@evil.com would satisfy an allowedDomains gate on the wrong
  // segment while the real mailbox lives elsewhere (CWE-290). Validate the
  // whole address first, then derive the domain from the FINAL "@".
  var addrCheck = b.guardEmail.validateAddress(profile.email);
  if (!addrCheck.ok) throw new ForbiddenError("Malformed email.");
  var domain = profile.email.slice(profile.email.lastIndexOf("@") + 1);
  if (allowedDomains && allowedDomains.length > 0 && !allowedDomains.includes(domain)) {
    throw new ForbiddenError("Domain not allowed: " + domain);
  }

  // Email is the authoritative lookup key. (A prior googleId fallback here was
  // unreachable: it only ran when the email lookup found nothing, yet required a
  // row whose email equalled profile.email — which the email lookup would already
  // have matched — while also doing a full-table scan. Re-linking a changed email
  // to a stable googleId, if ever wanted, must be an explicit googleId-only lookup.)
  var user = usersRepo.findByEmail(profile.email);

  // Bind a returning user to the stable OIDC subject (googleId), not the email
  // alone. A verified email can move between two distinct Google identities over
  // time — a Workspace admin reassigns a departed employee's address to a new hire,
  // or a consumer account is deleted and the address later recreated — so a match
  // on email with a DIFFERENT googleId is an identity change, not the same person
  // (CWE-290). And a local password account must not be assumable through Google
  // just because the addresses coincide (cross-provider takeover, CWE-287). Refuse
  // both. googleId is the sealed OIDC sub, read back as plaintext here.
  if (user && user.googleId &&
      !b.crypto.timingSafeEqual(Buffer.from(String(user.googleId)), Buffer.from(String(profile.googleId || "")))) {
    throw new ForbiddenError("Google account does not match the linked identity.");
  }
  if (user && user.authType && user.authType !== "google") {
    throw new ForbiddenError("This account uses a different sign-in method.");
  }

  // Enforce allowedDomains on returning users too. user.email is a persisted,
  // previously-validated address; derive from the FINAL "@" for consistency
  // with the fresh-profile path above.
  if (user && allowedDomains && allowedDomains.length > 0) {
    var stored = user.email || "";
    var userDomain = stored.indexOf("@") === -1 ? "" : stored.slice(stored.lastIndexOf("@") + 1);
    if (!allowedDomains.includes(userDomain)) {
      throw new ForbiddenError("Domain no longer allowed: " + userDomain);
    }
  }

  if (user && user.status === "suspended") throw new ForbiddenError("Account suspended.");

  if (!user) {
    var isAdmin = usersRepo.count({}) === 0;
    user = usersRepo.create({
      googleId: profile.googleId,
      email: profile.email,
      displayName: profile.displayName,
      avatar: profile.avatar,
      authType: "google",
      role: isAdmin ? "admin" : "user",
      status: "active",
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
    });
    return { user: user, isNew: true };
  }

  usersRepo.update(user._id, { $set: { lastLogin: new Date().toISOString() } });
  return { user: user, isNew: false };
}

function _oidcRefusal(reason, message, revokeUserId) {
  var err = new ForbiddenError(message);
  err.oidcReason = reason;
  if (revokeUserId) err.revokeUserId = revokeUserId;
  return err;
}

function _domainOf(email) {
  var e = String(email || "");
  return e.indexOf("@") === -1 ? "" : e.slice(e.lastIndexOf("@") + 1);
}

function _timingSafeStrEq(a, b2) {
  return b.crypto.timingSafeEqual(Buffer.from(String(a)), Buffer.from(String(b2)));
}

/**
 * Resolve a verified OpenID Connect identity (lib/oidc completeLogin) to an
 * account.
 *
 * `identity` is { issuer, sub, email, displayName, avatar, groups }. `email`
 * is null unless the provider verified it, and `groups` is null when the
 * provider did not supply them. `policy` is config.oidc plus
 * `allowedDomains`.
 *
 * Lookup order:
 *   1. The account bound to "<issuer>|<sub>".
 *   2. Otherwise the account holding the verified email, which is then linked
 *      to this subject. An account already bound to another subject is
 *      refused, as is a suspended or pending one.
 *   3. Otherwise a new account, when provisioning allows it.
 *
 * Every login re-checks allowedDomains and the required group. When the admin
 * group is set and the provider supplied groups, the role of a linked account
 * follows group membership, except that the last active admin is never
 * demoted.
 *
 * Returns { user, isNew, linked, roleChange: { from, to } | null,
 * roleSyncRefused, revokeSessions }. A refusal throws ForbiddenError carrying
 * `oidcReason`; one that should also end the account's existing sessions
 * carries `revokeUserId`.
 */
function resolveOidcUser(identity, policy) {
  if (!identity || typeof identity.sub !== "string" || !identity.sub || typeof identity.issuer !== "string" || !identity.issuer) {
    throw _oidcRefusal("no-identity", "The identity provider returned no subject.");
  }
  policy = policy || {};
  var subject = identity.issuer + "|" + identity.sub;
  var groups = Array.isArray(identity.groups) ? identity.groups : null;
  var allowedDomains = Array.isArray(policy.allowedDomains) ? policy.allowedDomains : [];
  var requiredGroup = policy.requiredGroup || "";
  var adminGroup = policy.adminGroup || "";
  var hasGroup = function (g) { return !!(groups && g && groups.indexOf(g) !== -1); };

  var user = usersRepo.findByOidcSubject(subject);
  var linked = false;

  if (!user && identity.email) {
    var byEmail = usersRepo.findByEmail(identity.email);
    if (byEmail) {
      // A verified email can move between two identities at the provider (an
      // address reassigned to a new employee, or a deleted account recreated).
      // An account already bound to a different subject is not taken over.
      if (byEmail.oidcSubject && !_timingSafeStrEq(byEmail.oidcSubject, subject)) {
        throw _oidcRefusal("subject-mismatch", "This account is linked to a different single sign-on identity.");
      }
      // A pending account has not proven control of its address, so it may
      // belong to someone who registered the address first.
      if (byEmail.status === "pending") {
        throw _oidcRefusal("account-pending", "This account has not verified its email address.");
      }
      user = byEmail;
      linked = true;
    }
  }

  if (user) {
    if (user.status === "suspended") throw _oidcRefusal("account-suspended", "Account suspended.");
    if (allowedDomains.length > 0) {
      // The stored address and, when the provider sends one, its current
      // verified address must both be in an allowed domain.
      var domain = _domainOf(user.email);
      var idpDomain = identity.email ? _domainOf(identity.email) : domain;
      if (!domain || allowedDomains.indexOf(domain) === -1 ||
          !idpDomain || allowedDomains.indexOf(idpDomain) === -1) {
        throw _oidcRefusal("domain-not-allowed", "Your email domain is not allowed.", linked ? null : user._id);
      }
    }
    if (requiredGroup && !hasGroup(requiredGroup)) {
      throw _oidcRefusal("group-denied", "Your account is not in the group required to sign in.", linked ? null : user._id);
    }

    var set = {};
    if (linked) set.oidcSubject = subject;
    if (user.authType === "oidc") {
      if (identity.displayName) set.displayName = identity.displayName;
      set.avatar = identity.avatar || "";
    }

    var roleChange = null;
    var roleSyncRefused = false;
    var revokeSessions = false;
    if (adminGroup && groups !== null) {
      var wantAdmin = hasGroup(adminGroup);
      if (wantAdmin && user.role !== "admin") {
        set.role = "admin";
        roleChange = { from: user.role || "user", to: "admin" };
      } else if (!wantAdmin && user.role === "admin") {
        var activeAdmins = usersRepo.count({ role: "admin", status: "active" });
        if (activeAdmins <= 1) {
          roleSyncRefused = true;
        } else {
          set.role = "user";
          roleChange = { from: "admin", to: "user" };
          revokeSessions = true;
        }
      }
    }
    if (Object.keys(set).length > 0) usersRepo.update(user._id, { $set: set });
    var fresh = usersRepo.findById(user._id) || user;
    return { user: fresh, isNew: false, linked: linked, roleChange: roleChange, roleSyncRefused: roleSyncRefused, revokeSessions: revokeSessions };
  }

  // No account: provisioning.
  if (!identity.email) {
    throw _oidcRefusal("no-verified-email", "The identity provider did not supply a verified email address.");
  }
  if (allowedDomains.length > 0 && allowedDomains.indexOf(_domainOf(identity.email)) === -1) {
    throw _oidcRefusal("domain-not-allowed", "Your email domain is not allowed.");
  }
  if (requiredGroup && !hasGroup(requiredGroup)) {
    throw _oidcRefusal("group-denied", "Your account is not in the group required to sign in.");
  }
  var allowlist = Array.isArray(policy.allowlist) ? policy.allowlist : [];
  var permitted = !!policy.autoProvision &&
    ((allowlist.length > 0 && allowlist.indexOf(identity.email) !== -1) || (!!requiredGroup && hasGroup(requiredGroup)));
  if (!permitted) {
    throw _oidcRefusal("provision-denied", "No account exists for this identity. Ask an administrator for access.");
  }

  var created = usersRepo.create({
    email: identity.email,
    displayName: identity.displayName || identity.email.split("@")[0],
    avatar: identity.avatar || "",
    authType: "oidc",
    oidcSubject: subject,
    role: adminGroup && hasGroup(adminGroup) ? "admin" : "user",
    status: "active",
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
  });

  // Two callbacks for the same subject can both reach this point. Whichever
  // row was created first is kept and the other is removed.
  var rows = usersRepo.findAllByOidcSubject(subject);
  if (rows.length > 1) {
    rows.sort(function (x, y) {
      var cx = String(x.createdAt || ""), cy = String(y.createdAt || "");
      if (cx !== cy) return cx < cy ? -1 : 1;
      return String(x._id) < String(y._id) ? -1 : 1;
    });
    if (rows[0]._id !== created._id) {
      usersRepo.remove(created._id);
      return { user: rows[0], isNew: false, linked: false, roleChange: null, roleSyncRefused: false, revokeSessions: false };
    }
  }
  return { user: created, isNew: true, linked: false, roleChange: null, roleSyncRefused: false, revokeSessions: false };
}

/**
 * Resolve a Sign-in-with-Tailscale identity to an existing or new user.
 * `identity` is the normalized, already-peer-gated tailnet identity from
 * lib/tailscale (login/displayName/profilePicUrl/caps) — the trust boundary is
 * the caller's; this layer only maps identity → account.
 * Returns { user, isNew }.
 */
function resolveTailscaleUser(identity) {
  if (!identity || !identity.login) throw new ValidationError("Tailscale returned no identity.");
  var tsId = tailscale.tailscaleId(identity.login);

  // Returning user: bound to the stable tailnet login (sealed tailscaleId, looked
  // up via its blind index) — a distinct namespace from email, so a tailnet login
  // that coincides with some account's email address never cross-matches.
  var user = usersRepo.findByTailscaleId(tsId);
  if (user) {
    // A row carrying this tailscaleId must be a Tailscale account. Refuse if it
    // somehow uses another method (defensive against a cross-provider takeover).
    if (user.authType && user.authType !== "tailscale") {
      throw new ForbiddenError("This account uses a different sign-in method.");
    }
    if (user.status === "suspended") throw new ForbiddenError("Account suspended.");
    usersRepo.update(user._id, { $set: { lastLogin: new Date().toISOString() } });
    return { user: user, isNew: false };
  }

  // No existing Tailscale account → admin-gated auto-provisioning. Create ONLY
  // when the identity carries the required capability grant or is on the
  // allowlist; otherwise refuse (never silently create an account for any tailnet
  // member).
  var decision = tailscale.provisioningDecision(identity);
  if (!decision.allowed) {
    throw new ForbiddenError("Your tailnet account is not permitted to sign in here. Ask an administrator to grant access.");
  }

  // Populate email only when the tailnet login is a real address AND no other
  // account already owns it — never silently merge with or take over an existing
  // local/Google account that shares the address (CWE-287). A non-email login
  // (e.g. alice@github) provisions with no email; tailscaleId carries identity.
  var emailToStore = null;
  var addrCheck = b.guardEmail.validateAddress(identity.login);
  if (addrCheck && addrCheck.ok) {
    if (usersRepo.findByEmail(identity.login)) {
      throw new ForbiddenError("An account with this email already exists. Sign in with its existing method.");
    }
    emailToStore = identity.login;
  }

  var isAdmin = usersRepo.count({}) === 0;
  var doc = {
    tailscaleId: tsId,
    displayName: identity.displayName || identity.login,
    authType: "tailscale",
    role: isAdmin ? "admin" : "user",
    status: "active",
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
  };
  if (emailToStore) doc.email = emailToStore;
  if (identity.profilePicUrl) doc.avatar = identity.profilePicUrl;

  var created = usersRepo.create(doc);
  return { user: created, isNew: true };
}

/**
 * Check if a user has 2FA enabled.
 */
function requires2fa(userId) {
  var user = usersRepo.findById(userId);
  return user && user.totpEnabled === "true";
}

/**
 * Update last login timestamp.
 */
function touchLogin(userId) {
  usersRepo.update(userId, { $set: { lastLogin: new Date().toISOString() } });
}

module.exports = { registerLocal, authenticateLocal, resolveGoogleUser, resolveOidcUser, resolveTailscaleUser, requires2fa, touchLogin, emailIsVerified };
