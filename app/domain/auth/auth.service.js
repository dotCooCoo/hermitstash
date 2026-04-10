/**
 * Auth Service — business logic for authentication and user registration.
 * Routes handle HTTP; this handles identity resolution and account creation.
 */
var usersRepo = require("../../data/repositories/users.repo");
var filesRepo = require("../../data/repositories/files.repo");
var { hashPassword, verifyPassword } = require("../../../lib/crypto");
var { validateEmail, validatePassword, validateDisplayName } = require("../../shared/validate");
var { ValidationError, AuthenticationError, ForbiddenError, ConflictError } = require("../../shared/errors");

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

  var passwordHash = await hashPassword(password);
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

  // Claim public uploads made with this email
  var claimed = filesRepo.findAll({ uploaderEmail: emailResult.email, uploadedBy: "public" });
  for (var f of claimed) {
    filesRepo.update(f._id, { $set: { uploadedBy: user._id } });
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
  if (!user) throw new AuthenticationError("Invalid email or password.");
  if (!user.passwordHash) throw new AuthenticationError("Invalid email or password.");
  if (user.status === "pending") {
    var err = new ForbiddenError("Please verify your email before signing in.");
    err.pending = true;
    err.email = user.email;
    throw err;
  }
  if (user.status === "suspended") throw new ForbiddenError("Account suspended.");

  var valid = await verifyPassword(password, user.passwordHash);
  if (!valid) throw new AuthenticationError("Invalid email or password.");

  return user;
}

/**
 * Resolve a Google OAuth profile to an existing or new user.
 * Returns { user, isNew }.
 */
function resolveGoogleUser(profile, allowedDomains) {
  if (!profile || !profile.email) throw new ValidationError("Google returned no email.");

  var domain = profile.email.split("@")[1];
  if (allowedDomains && allowedDomains.length > 0 && !allowedDomains.includes(domain)) {
    throw new ForbiddenError("Domain not allowed: " + domain);
  }

  // Look up by email first
  var user = usersRepo.findByEmail(profile.email);

  // Fallback: googleId match (requires email match too)
  if (!user) {
    var allUsers = usersRepo.findAll({});
    for (var i = 0; i < allUsers.length; i++) {
      if (allUsers[i].googleId === profile.googleId && allUsers[i].email === profile.email) {
        user = allUsers[i];
        break;
      }
    }
  }

  // Enforce allowedDomains on returning users too
  if (user && allowedDomains && allowedDomains.length > 0) {
    var userDomain = (user.email || "").split("@")[1];
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

module.exports = { registerLocal, authenticateLocal, resolveGoogleUser, requires2fa, touchLogin };
