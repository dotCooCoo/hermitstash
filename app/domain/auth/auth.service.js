/**
 * Auth Service — business logic for authentication and user registration.
 * Routes handle HTTP; this handles identity resolution and account creation.
 */
var b = require("../../../lib/vendor/blamejs");
var config = require("../../../lib/config");
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
  if (!_dummyHashPromise) _dummyHashPromise = b.auth.password.hash(b.crypto.generateToken(16));
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

  var passwordHash = await b.auth.password.hash(password);
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
 * Returns the user or throws.
 */
async function authenticateLocal(email, password) {
  if (!email || !password) throw new ValidationError("Email and password required.");

  var user = usersRepo.findByEmail(email);
  if (!user) {
    // Constant-cost verify so a non-existent account costs the same as a wrong
    // password on a real one — no account-existence timing oracle.
    await b.auth.password.verify(await dummyPasswordHash(), password);
    throw new AuthenticationError("Invalid email or password.");
  }
  if (!user.passwordHash) {
    // Passwordless account (Google-OAuth / passkey-only): equalize timing, and
    // mark the error so the caller skips failed-attempt lockout — locking a
    // password that does not exist is a pure DoS / state-pollution vector, not a
    // brute-force defense.
    await b.auth.password.verify(await dummyPasswordHash(), password);
    var noPwErr = new AuthenticationError("Invalid email or password.");
    noPwErr.noPassword = true;
    throw noPwErr;
  }
  // Verify the password BEFORE any account-status gate. Throwing pending/suspended
  // first skipped the Argon2id cost (a status-by-timing oracle) and revealed an
  // account's status to anyone holding only its email. Now the same verify cost is
  // paid on every existing-account branch, and only a caller who proves the
  // password learns pending/suspended state.
  var valid = await b.auth.password.verify(user.passwordHash, password);
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

module.exports = { registerLocal, authenticateLocal, resolveGoogleUser, requires2fa, touchLogin, emailIsVerified };
