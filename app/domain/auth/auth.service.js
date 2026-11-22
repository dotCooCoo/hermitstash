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
var credentialsRepo = require("../../data/repositories/credentials.repo");
var { validateEmail, validatePassword, validateDisplayName } = require("../../shared/validate");
var { ValidationError, AuthenticationError, ForbiddenError, ConflictError } = require("../../shared/errors");

// Each account records how its email address was confirmed, in
// emailConfirmedVia and emailConfirmedAt:
//   "verification"  an emailed verification link for this address was followed;
//   "invite"        an emailed invite was accepted;
//   "google"        Google sign-in with this verified address;
//   "oidc"          OpenID Connect sign-in with this verified address;
//   "legacy"        no recorded proof (accounts from before 1.16.2, and any
//                   account whose address changed without proof);
//   null            pending accounts and accounts created from an email the
//                   provider did not verify.

// May anonymous public uploads made with this account's address be reassigned
// to it? Email equality alone is never proof. A recorded confirmation is; a
// "legacy" account qualifies only while email verification is on and the
// account is active, as before 1.16.2. An unconfirmed account never does.
function emailIsVerified(user) {
  if (!user || user.status !== "active" || !user.emailConfirmedVia || !user.emailConfirmedAt) return false;
  if (user.emailConfirmedVia === "legacy") return !!config.emailVerification;
  return true;
}

// May an OpenID Connect identity with this verified address be linked to the
// account automatically? Only a recorded confirmation counts; "legacy" never does.
function emailConfirmedForLinking(user) {
  return !!(user && user.emailConfirmedAt && user.emailConfirmedVia && user.emailConfirmedVia !== "legacy");
}

// The $set fields that record a confirmation by `via`.
function confirmationFields(via) {
  return { emailConfirmedAt: new Date().toISOString(), emailConfirmedVia: via };
}

/**
 * The ways `user` can sign in right now: "password", "passkey", "google",
 * "oidc" and "tailscale". A method counts only while it is enabled.
 */
function signInMethods(user) {
  var out = [];
  if (!user) return out;
  if (user.passwordHash && config.localAuth) out.push("password");
  if (config.passkeyEnabled && credentialsRepo.findByUser(user._id).length > 0) out.push("passkey");
  if (user.googleId && config.google && config.google.clientID) out.push("google");
  var o = config.oidc;
  if (user.oidcSubject && o && o.enabled && o.issuer && o.clientID) out.push("oidc");
  if (user.tailscaleId && config.tailscale && config.tailscale.enabled && config.tailscale.ssoEnabled) out.push("tailscale");
  return out;
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

  // Reassign anonymous public uploads made with this email only when
  // emailIsVerified() accepts the account. A pending account is unconfirmed and
  // never claims here; its uploads are claimed on its first authenticated visit
  // after verification (see routes/dashboard.js) by the same check.
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
    user = usersRepo.create(Object.assign({
      googleId: profile.googleId,
      email: profile.email,
      displayName: profile.displayName,
      avatar: profile.avatar,
      authType: "google",
      role: isAdmin ? "admin" : "user",
      status: "active",
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
    }, confirmationFields("google")));
    return { user: user, isNew: true };
  }

  var gset = { lastLogin: new Date().toISOString() };
  if (!emailConfirmedForLinking(user)) Object.assign(gset, confirmationFields("google"));
  usersRepo.update(user._id, { $set: gset });
  return { user: usersRepo.findById(user._id) || user, isNew: false };
}

// Shown when an OpenID Connect sign-in matches an account by email but may
// not be linked to it automatically.
var LINK_REFUSED_MESSAGE = "An account with this email address already exists. If it is yours, sign in to it with the method you already use and link single sign-on from your profile page. If you did not create it, ask an administrator.";
var UNVERIFIED_REFUSED_MESSAGE = "Your identity provider did not confirm your email address. Ask an administrator for access.";
var GROUPS_UNAVAILABLE_MESSAGE = "Your identity provider did not send your group membership, so your access could not be checked.";
var GROUP_DENIED_MESSAGE = "Your account is not in the group required to sign in.";
var DOMAIN_MESSAGE = "Your email domain is not allowed.";

// `revokeUserId` asks the caller to end the account's sessions; `accountId`
// names the existing account the refusal concerns, for the audit log.
function _oidcRefusal(reason, message, revokeUserId, accountId) {
  var err = new ForbiddenError(message);
  err.oidcReason = reason;
  if (revokeUserId) err.revokeUserId = revokeUserId;
  if (accountId) err.accountId = accountId;
  return err;
}

function _isUniqueViolation(e) {
  return !!(e && (e.errcode === 2067 || /UNIQUE constraint/i.test(String(e.message || "")))); // allow:raw-byte-literal: SQLITE_CONSTRAINT_UNIQUE result code
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
 * `identity` is { issuer, sub, email, unverifiedEmail, unverifiedExternal,
 * displayName, avatar, groups }. `email` is null unless the provider verified
 * it, `unverifiedEmail` is an address the provider did not mark as verified,
 * and `groups` is null when the groups could not be read. `policy` is
 * config.oidc plus `allowedDomains`.
 *
 * Lookup order:
 *   1. The account bound to "<issuer>|<sub>".
 *   2. Otherwise the account holding the verified email, which is then linked
 *      to this subject. It is refused when it is bound to another subject,
 *      pending, blocked by an earlier unlink, or has no recorded confirmation
 *      of its address. An unverified email is never used for this lookup.
 *   3. Otherwise a new account, when provisioning allows it. An unverified
 *      email (with policy.trustUnverifiedEmail) creates an account only for a
 *      member of the required group, never for a guest account, and never
 *      when an account already holds the address.
 *
 * Every login re-checks allowedDomains and the required group. Groups that
 * could not be read refuse the sign-in without ending sessions. When the
 * admin group is set and the provider supplied groups, the role of a linked
 * account follows group membership, except that the last active admin is
 * never demoted; when the groups could not be read, an admin is refused and
 * keeps the role.
 *
 * Returns { user, isNew, linked, roleChange: { from, to } | null,
 * roleSyncRefused, revokeSessions }. A refusal throws ForbiddenError carrying
 * `oidcReason` and, when it concerns an existing account, `accountId`. Only a
 * group or domain refusal of an already bound account carries `revokeUserId`,
 * which asks the caller to end that account's sessions.
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

  var verified = identity.email || null;
  var unverified = (!verified && policy.trustUnverifiedEmail && identity.unverifiedEmail) ? identity.unverifiedEmail : null;

  var user = usersRepo.findByOidcSubject(subject);
  var linked = false;

  if (!user && verified) {
    var byEmail = usersRepo.findByEmail(verified);
    if (byEmail) {
      // A verified email can move between two identities at the provider (an
      // address reassigned to a new employee, or a deleted account recreated).
      // An account already bound to a different subject is not taken over.
      if (byEmail.oidcSubject && !_timingSafeStrEq(byEmail.oidcSubject, subject)) {
        throw _oidcRefusal("subject-mismatch", "An account with this email address is linked to a different single sign-on identity.", null, byEmail._id);
      }
      // A pending account has not proven control of its address, so it may
      // belong to someone who registered the address first.
      if (byEmail.status === "pending") {
        throw _oidcRefusal("account-pending", "This account has not verified its email address.", null, byEmail._id);
      }
      // After an unlink, the account is linked again only from its profile page.
      if (byEmail.oidcAutoLinkBlockedAt) {
        throw _oidcRefusal("auto-link-blocked", LINK_REFUSED_MESSAGE, null, byEmail._id);
      }
      // An account whose holder never proved control of the address may have
      // been registered by someone else in advance; linking it would hand the
      // provider identity to that person's password or passkey.
      if (!emailConfirmedForLinking(byEmail)) {
        throw _oidcRefusal("email-unconfirmed", LINK_REFUSED_MESSAGE, null, byEmail._id);
      }
      user = byEmail;
      linked = true;
    }
  }

  if (user) {
    if (user.status === "suspended") throw _oidcRefusal("account-suspended", "This account is suspended.", null, user._id);
    // A guest identity is refused under OIDC_TRUST_UNVERIFIED_EMAIL on every
    // sign-in, including one bound to an account earlier.
    if (policy.trustUnverifiedEmail && !verified && identity.unverifiedExternal) {
      throw _oidcRefusal("unverified-email-external", UNVERIFIED_REFUSED_MESSAGE, null, user._id);
    }
    if (allowedDomains.length > 0) {
      // The stored address and, when the provider sends one, its current
      // address must both be in an allowed domain.
      var domain = _domainOf(user.email);
      var idpEmail = verified || unverified;
      var idpDomain = idpEmail ? _domainOf(idpEmail) : domain;
      if (!domain || allowedDomains.indexOf(domain) === -1 ||
          !idpDomain || allowedDomains.indexOf(idpDomain) === -1) {
        throw _oidcRefusal("domain-not-allowed", DOMAIN_MESSAGE, linked ? null : user._id, user._id);
      }
    }
    _checkRequiredGroup(requiredGroup, groups, user, linked);
    // An admin whose groups could not be read cannot be checked against the
    // admin group, so the sign-in is refused and the role is left alone.
    if (adminGroup && groups === null && user.role === "admin") {
      throw _oidcRefusal("groups-unavailable", GROUPS_UNAVAILABLE_MESSAGE, null, user._id);
    }

    var set = {};
    if (linked) {
      set.oidcSubject = subject;
      set.oidcLabel = verified;
    } else if (verified || unverified) {
      set.oidcLabel = verified || unverified;
    }
    if (verified && user.email && verified === String(user.email).toLowerCase() && !emailConfirmedForLinking(user)) {
      Object.assign(set, confirmationFields("oidc"));
    }
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
  var provEmail = verified || unverified;
  if (!provEmail) {
    throw _oidcRefusal("no-verified-email", "Your identity provider did not supply a verified email address.");
  }
  if (allowedDomains.length > 0 && allowedDomains.indexOf(_domainOf(provEmail)) === -1) {
    throw _oidcRefusal("domain-not-allowed", DOMAIN_MESSAGE);
  }
  _checkRequiredGroup(requiredGroup, groups, null, false);
  var permitted;
  if (unverified) {
    // Checked after the domain and group, so a person outside the group
    // cannot learn which addresses hold an account.
    if (!requiredGroup) throw _oidcRefusal("unverified-email-needs-group", UNVERIFIED_REFUSED_MESSAGE);
    if (identity.unverifiedExternal) throw _oidcRefusal("unverified-email-external", UNVERIFIED_REFUSED_MESSAGE);
    var holder = usersRepo.findByEmail(unverified);
    if (holder) throw _oidcRefusal("email-in-use-unverified", UNVERIFIED_REFUSED_MESSAGE, null, holder._id);
    // The allowlist is not consulted: an unverified address is not proof
    // that the person is the one the allowlist names.
    permitted = !!policy.autoProvision && hasGroup(requiredGroup);
  } else {
    var allowlist = Array.isArray(policy.allowlist) ? policy.allowlist : [];
    permitted = !!policy.autoProvision &&
      ((allowlist.length > 0 && allowlist.indexOf(verified) !== -1) || (!!requiredGroup && hasGroup(requiredGroup)));
  }
  if (!permitted) {
    throw _oidcRefusal("provision-denied", "No account exists for this identity. Ask an administrator for access.");
  }

  var now = new Date().toISOString();
  var created;
  try {
    created = usersRepo.create({
      email: provEmail,
      displayName: identity.displayName || provEmail.split("@")[0],
      avatar: identity.avatar || "",
      authType: "oidc",
      oidcSubject: subject,
      oidcLabel: provEmail,
      role: adminGroup && hasGroup(adminGroup) ? "admin" : "user",
      status: "active",
      createdAt: now,
      lastLogin: now,
      emailConfirmedVia: verified ? "oidc" : null,
      emailConfirmedAt: verified ? now : null,
    });
  } catch (e) {
    // Another account took the address between the check and the insert.
    if (_isUniqueViolation(e)) {
      if (unverified) throw _oidcRefusal("email-in-use-unverified", UNVERIFIED_REFUSED_MESSAGE);
      throw _oidcRefusal("provision-denied", "No account exists for this identity. Ask an administrator for access.");
    }
    throw e;
  }

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

// The required-group check shared by sign-in, provisioning and explicit
// linking. Groups that could not be read refuse without ending sessions; a
// group list without the group refuses, and for an already bound account
// (`user` given and not `linked`) also ends its sessions.
function _checkRequiredGroup(requiredGroup, groups, user, linked) {
  if (!requiredGroup) return;
  if (groups === null) {
    throw _oidcRefusal("groups-unavailable", GROUPS_UNAVAILABLE_MESSAGE, null, user ? user._id : null);
  }
  if (groups.indexOf(requiredGroup) === -1) {
    throw _oidcRefusal("group-denied", GROUP_DENIED_MESSAGE, (user && !linked) ? user._id : null, user ? user._id : null);
  }
}

/**
 * Link a verified OpenID Connect identity to a signed-in account, from the
 * profile page. `user` is the account, re-read by the caller; `identity` and
 * `policy` are as for resolveOidcUser.
 *
 * Refused (ForbiddenError with `oidcReason`, never ending sessions) when the
 * account is not active, the identity is linked to another account, the
 * account is linked to another identity, the provider's verified email
 * belongs to another account, or allowedDomains or the required group is not
 * satisfied. The role is not changed.
 *
 * Returns { alreadyLinked, emailMatched }.
 */
function linkOidcIdentity(user, identity, policy) {
  if (!identity || typeof identity.sub !== "string" || !identity.sub || typeof identity.issuer !== "string" || !identity.issuer) {
    throw _oidcRefusal("no-identity", "The identity provider returned no subject.");
  }
  policy = policy || {};
  if (!user || user.status !== "active") {
    throw _oidcRefusal("account-not-active", "This account cannot be linked.", null, user ? user._id : null);
  }
  var subject = identity.issuer + "|" + identity.sub;
  var verified = identity.email || null;
  var unverified = (!verified && policy.trustUnverifiedEmail && identity.unverifiedEmail) ? identity.unverifiedEmail : null;
  var emailMatched = !!(verified && user.email && verified === String(user.email).toLowerCase());

  var holder = usersRepo.findByOidcSubject(subject);
  if (holder) {
    if (holder._id !== user._id) {
      throw _oidcRefusal("link-subject-in-use", "That single sign-on identity is already linked to another account.", null, user._id);
    }
    return { alreadyLinked: true, emailMatched: emailMatched };
  }
  if (user.oidcSubject && !_timingSafeStrEq(user.oidcSubject, subject)) {
    throw _oidcRefusal("link-other-subject", "This account is linked to a different single sign-on identity.", null, user._id);
  }
  if (policy.trustUnverifiedEmail && !verified && identity.unverifiedExternal) {
    throw _oidcRefusal("unverified-email-external", UNVERIFIED_REFUSED_MESSAGE, null, user._id);
  }
  // The provider's address, verified or not, must not belong to another
  // account, so the stored label never names another account's address.
  var providerEmail = verified || unverified;
  if (providerEmail) {
    var byEmail = usersRepo.findByEmail(providerEmail);
    if (byEmail && byEmail._id !== user._id) {
      throw _oidcRefusal("link-email-other-account", "The email address of that single sign-on identity belongs to another account.", null, user._id);
    }
  }
  var allowedDomains = Array.isArray(policy.allowedDomains) ? policy.allowedDomains : [];
  if (allowedDomains.length > 0) {
    var domain = _domainOf(user.email);
    var idpEmail = verified || unverified;
    if (!domain || allowedDomains.indexOf(domain) === -1 ||
        (idpEmail && allowedDomains.indexOf(_domainOf(idpEmail)) === -1)) {
      throw _oidcRefusal("domain-not-allowed", DOMAIN_MESSAGE, null, user._id);
    }
  }
  var groups = Array.isArray(identity.groups) ? identity.groups : null;
  if (policy.requiredGroup) {
    if (groups === null) throw _oidcRefusal("groups-unavailable", GROUPS_UNAVAILABLE_MESSAGE, null, user._id);
    if (groups.indexOf(policy.requiredGroup) === -1) throw _oidcRefusal("group-denied", GROUP_DENIED_MESSAGE, null, user._id);
  }

  usersRepo.setOidcSubject(user._id, subject, identity.email || identity.unverifiedEmail || null);
  if (emailMatched && !emailConfirmedForLinking(user)) {
    usersRepo.update(user._id, { $set: confirmationFields("oidc") });
  }

  // Two link callbacks for the same subject can both reach this point. The
  // binding is removed again and this request is refused.
  if (usersRepo.findAllByOidcSubject(subject).length > 1) {
    usersRepo.clearOidcSubject(user._id);
    throw _oidcRefusal("link-subject-in-use", "That single sign-on identity is already linked to another account.", null, user._id);
  }
  return { alreadyLinked: false, emailMatched: emailMatched };
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

module.exports = {
  registerLocal, authenticateLocal, resolveGoogleUser, resolveOidcUser, linkOidcIdentity, resolveTailscaleUser,
  requires2fa, touchLogin, emailIsVerified, emailConfirmedForLinking, confirmationFields, signInMethods,
};
