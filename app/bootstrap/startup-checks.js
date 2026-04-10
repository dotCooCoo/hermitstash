/**
 * Startup invariant checks — enforces secure configuration on boot.
 * Prints warnings for non-critical issues, exits on critical ones.
 *
 * Call this after config is loaded but before routes are registered.
 */
var fs = require("fs");
var path = require("path");
var config = require("../../lib/config");

function run() {
  var warnings = [];
  var errors = [];

  // ---- Critical: vault key must exist and be readable ----
  var vaultKeyPath = path.join(__dirname, "..", "..", "data", "vault.key");
  if (fs.existsSync(vaultKeyPath)) {
    try {
      var keyData = JSON.parse(fs.readFileSync(vaultKeyPath, "utf8"));
      if (!keyData.publicKey || !keyData.privateKey) {
        errors.push("Vault key file exists but is missing publicKey or privateKey.");
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

  // ---- Warning: data directory permissions ----
  var dataDir = path.join(__dirname, "..", "..", "data");
  if (fs.existsSync(dataDir)) {
    try {
      var stat = fs.statSync(dataDir);
      // Check if group/other readable (Unix only)
      if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
        warnings.push("data/ directory has loose permissions (" + (stat.mode & 0o777).toString(8) + "). Consider chmod 700.");
      }
    } catch (_e) {}
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
