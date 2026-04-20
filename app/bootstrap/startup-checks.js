/**
 * Startup invariant checks — enforces secure configuration on boot.
 * Prints warnings for non-critical issues, exits on critical ones.
 *
 * Call this after config is loaded but before routes are registered.
 */
var fs = require("fs");
var config = require("../../lib/config");
var { PATHS } = require("../../lib/constants");

function run() {
  var warnings = [];
  var errors = [];

  // ---- Critical: vault key must exist and be readable ----
  var dataDir = PATHS.DATA_DIR;
  var vaultKeyPath = PATHS.VAULT_KEY;
  if (fs.existsSync(vaultKeyPath)) {
    try {
      var keyData = JSON.parse(fs.readFileSync(vaultKeyPath, "utf8"));
      // Hybrid format (ML-KEM-1024 + P-384) — matches lib/vault.js loadKeys().
      if (!keyData.ecPublicKey || !keyData.ecPrivateKey) {
        errors.push("Vault key file exists but is not in the ML-KEM-1024 + P-384 hybrid format. Run the migration tool.");
      }
    } catch (e) {
      errors.push("Vault key file is corrupted: " + e.message);
    }
  }
  // No vault key on first run is OK — it will be generated

  // ---- Critical: default admin credentials ----
  var { users } = require("../../lib/db");
  var adminUser = users.findOne({ email: "admin@hermitstash.com" });
  if (adminUser && config.setupComplete) {
    errors.push("Default admin email (admin@hermitstash.com) still in use after setup. Change it in admin settings.");
  }

  // ---- Warning: session secret ----
  if (config.sessionSecret === "change-me-please") {
    warnings.push("Session secret is the default value. Change it in admin settings.");
  }

  // ---- Warning: no canonical origin ----
  if (!config.rpOrigin) {
    warnings.push("No rpOrigin configured. Generated URLs will use localhost. Set the RP Origin in admin settings for production.");
  }

  // ---- Warning: public upload without authentication ----
  if (config.publicUpload && !config.localAuth && !config.passkeyEnabled && !config.google.clientID) {
    warnings.push("Public uploads enabled but no authentication method configured. Anyone can upload without accountability.");
  }

  // ---- Warning: HTTPS not configured ----
  if (config.rpOrigin && !config.rpOrigin.startsWith("https://") && !config.rpOrigin.includes("localhost")) {
    warnings.push("rpOrigin is not HTTPS. Session cookies may not be secure. Use HTTPS in production.");
  }

  // ---- Warning: weak Argon2 parameters ----
  if (process.env.ARGON2_FAST === "1") {
    warnings.push("ARGON2_FAST=1 is set — password hashing uses dangerously weak parameters (1MB, 1 iteration). DO NOT use in production. Passwords are trivially crackable with these settings.");
  }

  // ---- Info: enforce mTLS is on ----
  // Operators who've enabled this intentionally know what it does, but a loud
  // boot-time confirmation helps when the mode is unexpectedly on (e.g., a
  // teammate toggled it, or the DB setting survived a restore).
  if (process.env.ENFORCE_MTLS_STRICT === "true") {
    warnings.push("ENFORCE_MTLS_STRICT=true — TLS handshake rejects non-mTLS clients at the network layer. Set ENFORCE_MTLS_STRICT=false to exit this mode.");
  } else if (config.enforceMtls) {
    warnings.push("Enforce mTLS is ON (soft) — non-mTLS browser connections will be dropped at the app layer. Escape hatch: set ENFORCE_MTLS_STRICT=false and restart.");
  }

  // ---- Info: CA regen flag — surface a post-restart notice ----
  // The /admin/api/mtls-ca/regenerate endpoint writes this flag immediately
  // before exiting. On restart we log the summary (admins can redistribute
  // browser certs and, if any, notify offline sync clients to re-enroll).
  // The flag is consumed and deleted to prevent repeated warnings.
  try {
    var regenFlagPath = require("path").join(PATHS.DATA_DIR, "ca-regen-flag.json");
    if (fs.existsSync(regenFlagPath)) {
      var flagData = JSON.parse(fs.readFileSync(regenFlagPath, "utf8"));
      var s = flagData.summary || {};
      warnings.push("mTLS CA was regenerated at " + flagData.at + " (v" + s.caGenerationBefore + " → v" + s.caGenerationAfter + "). Acked: " + (s.syncClientsAcked || 0) + "/" + (s.syncClientsConnected || 0) + " live sync clients. " + (s.syncClientsOffline || 0) + " offline clients need re-enrollment. " + (s.browserCertsRevoked || 0) + " browser cert(s) invalidated — admins must re-download.");
      try { fs.unlinkSync(regenFlagPath); } catch (_e) { /* flag file may have been removed by a concurrent boot */ }
    }
  } catch (_e) { /* flag corrupted or unreadable — non-fatal */ }

  // ---- Warning: mTLS CA is a legacy generation ----
  // When the algorithm envelope in lib/mtls-ca.js is bumped (CA_GENERATION),
  // any CA issued by a previous version becomes "legacy". The CA still works,
  // but regenerating it picks up the newer signature/KDF/cipher primitives.
  // The admin Danger Zone exposes a one-click regeneration flow.
  try {
    var mtlsCa = require("../../lib/mtls-ca");
    var caStatus = mtlsCa.getCaStatus();
    if (caStatus.exists && caStatus.isLegacy) {
      warnings.push("mTLS CA is a legacy generation (v" + caStatus.generation + " → current v" + caStatus.current + "). Regenerate via Admin → General → Danger Zone to pick up the upgraded algorithm envelope. All existing client certificates will be re-issued to active sync clients; offline clients will need to re-enroll.");
    }
  } catch (_e) { /* mtls-ca not loaded — non-fatal */ }

  // ---- Warning: email features enabled without a working backend ----
  // Admin endpoints (invite create/resend, /admin/users/:id/resend-verification,
  // /admin/users/:id/password-reset-link) already surface the URL when email
  // fails, so the feature still works out-of-band. But user-driven flows
  // (self-serve password reset, new-user verification from /auth/register)
  // silently fail for anti-enumeration — worth flagging loudly at boot.
  var emailCfg = config.email || {};
  var hasSmtp = !!(emailCfg.host && emailCfg.user);
  var hasResend = !!emailCfg.resendApiKey;
  var emailConfigured = hasSmtp || hasResend;
  var emailActive = emailCfg.enabled !== false && emailConfigured;
  if (!emailActive) {
    var reason = emailCfg.enabled === false ? "EMAIL_ENABLED=false" : "no email backend configured (SMTP_HOST/SMTP_USER or RESEND_API_KEY)";
    if (config.emailVerification && config.localAuth && config.registrationOpen) {
      warnings.push("EMAIL_VERIFICATION=true but email is not active (" + reason + "). New registrations will stall on /auth/pending. Admins can resend + hand-deliver verification links via Admin → Users → Verify.");
    }
    if (config.localAuth) {
      warnings.push("Email is not active (" + reason + ") — self-serve password reset will silently fail. Admins can generate reset links manually via Admin → Users → Reset link.");
    }
  }

  // ---- Warning: invalid env var values ----
  // Validates every env var in settingsMap against its settings-schema type
  // (number, boolean, url, hostname, enum, timezone, etc.). Catches typos
  // like PORT=abc, MAX_FILE_SIZE=xyz, BACKUP_TIMEZONE=America/Foobar — values
  // that previously fell back to defaults silently are now surfaced loudly.
  try {
    var envWarnings = config.validateEnvVars();
    for (var ew = 0; ew < envWarnings.length; ew++) {
      warnings.push(envWarnings[ew]);
    }
  } catch (_e) { /* settings-schema not loaded yet — non-fatal */ }

  // ---- Warning: data directory permissions ----
  if (fs.existsSync(dataDir)) {
    try {
      var stat = fs.statSync(dataDir);
      // Check if group/other readable (Unix only)
      if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
        warnings.push("data/ directory has loose permissions (" + (stat.mode & 0o777).toString(8) + "). Consider chmod 700.");
      }
    } catch (_e) { /* platform probe — stat/mode not available on this OS */ }
  }

  // ---- Print results ----
  if (warnings.length > 0) {
    console.log("\n  Startup warnings:");
    for (var i = 0; i < warnings.length; i++) {
      console.log("  ⚠ " + warnings[i]);
    }
  }

  if (errors.length > 0) {
    console.error("\n  FATAL startup errors:");
    for (var j = 0; j < errors.length; j++) {
      console.error("  ✖ " + errors[j]);
    }
    console.error("\n  Fix these issues and restart.\n");
    process.exit(1);
  }

  return { warnings: warnings, errors: errors };
}

module.exports = { run };
