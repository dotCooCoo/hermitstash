"use strict";
/**
 * blamejs wiki/docs reference app — production entry.
 *
 * All framework wiring lives in lib/build-app.js so the e2e suite can
 * boot the same configuration in-process. This file is the env-var
 * + signal-handler shim around buildApp.
 *
 * Env vars:
 *   WIKI_DATA_DIR                       directory for vault key + sqlite db (default ./data)
 *   WIKI_PORT                           HTTP port (default 3008)
 *   WIKI_BIND                           bind address (default 0.0.0.0)
 *   WIKI_SITE_URL                       canonical public URL of this deploy
 *                                       (default https://blamejs.com) — used for
 *                                       canonical links, Open Graph, sitemap.xml,
 *                                       and robots.txt
 *   WIKI_ADMIN_EMAIL                    admin user email (default admin@blamejs.com)
 *   WIKI_ADMIN_PASSWORD                 admin password — required ≥ 8 chars; a random
 *                                       dev password is generated and printed if unset
 *   WIKI_WEBHOOK_URL                    optional outbound page-edit webhook URL
 *   WIKI_WEBHOOK_SECRET                 HMAC-SHA3-512 signing key for the webhook
 *
 *   Production posture (auto-detected from passphrase env vars; explicit
 *   overrides take precedence):
 *
 *   BLAMEJS_VAULT_PASSPHRASE            sets vault to wrapped + DB to encrypted-at-rest
 *   BLAMEJS_AUDIT_SIGNING_PASSPHRASE    sets audit-sign key to wrapped
 *   WIKI_VAULT_MODE                     "wrapped" | "plaintext" (override)
 *   WIKI_DB_AT_REST                     "encrypted" | "plain" (override)
 *   WIKI_AUDIT_SIGNING_MODE             "wrapped" | "plaintext" (override)
 *
 *   Security hardening (read directly by lib/build-app.js):
 *
 *   WIKI_ADMIN_TRUSTED_PROXIES          comma-separated reverse-proxy CIDRs. When set,
 *                                       peer-gates x-forwarded-for (the /admin fence)
 *                                       and x-forwarded-proto (cookie Secure flag) — the
 *                                       headers are honoured ONLY from a trusted peer, so
 *                                       a direct caller can't forge an IP or claim https.
 *   WIKI_ADMIN_ALLOWED_CIDRS            comma-separated CIDR list. When set, mounts
 *                                       b.middleware.networkAllowlist as the in-process
 *                                       CIDR fence on /admin paths. Empty = no fence.
 *   WIKI_ADMIN_DENIED_CIDRS             comma-separated CIDR list of explicit denies
 *                                       (deny-then-allow precedence). Empty = no
 *                                       deny rules.
 *   WIKI_REQUIRE_PROD_ASSERTS           "1" / "true" — at boot, run
 *                                       b.security.assertProduction(...) and refuse
 *                                       to boot when production posture is incomplete.
 */

var path = require("node:path");
var b = require("@blamejs/core");
var { buildApp } = require("./lib/build-app");

var log = b.log.create({ base: { service: "wiki" } });

var DATA_DIR       = b.safeEnv.readVar("WIKI_DATA_DIR")     || path.join(__dirname, "data");
var PORT           = b.safeEnv.readVar("WIKI_PORT", { type: "number", default: b.constants.BYTES.bytes(3008) });
var SITE_URL       = (b.safeEnv.readVar("WIKI_SITE_URL")    || "https://blamejs.com").replace(/\/+$/, "");
// Default bind: 0.0.0.0 so a containerized wiki accepts connections
// from the Docker port-forward and reverse proxies on the same host
// network. Operators with a stricter posture (e.g. listening only on
// localhost behind a same-host reverse proxy) set WIKI_BIND=127.0.0.1.
var BIND           = b.safeEnv.readVar("WIKI_BIND")          || "0.0.0.0";
var ADMIN_EMAIL    = b.safeEnv.readVar("WIKI_ADMIN_EMAIL")   || "admin@blamejs.com";
var ADMIN_PASSWORD = b.safeEnv.readVar("WIKI_ADMIN_PASSWORD") || null;
var WEBHOOK_URL    = b.safeEnv.readVar("WIKI_WEBHOOK_URL")   || null;
var WEBHOOK_SECRET = b.safeEnv.readVar("WIKI_WEBHOOK_SECRET") || null;

var MIN_ADMIN_PASSWORD_LEN = b.constants.BYTES.bytes(8);
var GENERATED_PASSWORD_BYTES = b.constants.BYTES.bytes(18);

function _resolveAdminPassword() {
  if (ADMIN_PASSWORD && ADMIN_PASSWORD.length >= MIN_ADMIN_PASSWORD_LEN) return ADMIN_PASSWORD;
  var generated = b.crypto.generateBytes(GENERATED_PASSWORD_BYTES).toString("base64url");
  log.warn("WIKI_ADMIN_PASSWORD not set; using generated dev password", {
    email:    ADMIN_EMAIL,
    password: generated,
    note:     "set WIKI_ADMIN_PASSWORD in env for stable production credentials",
  });
  return generated;
}

// Single termination point. Routes through log.fatal first so the boot
// or shutdown failure shows up as a structured event before the
// process winds down.
function _terminate(code, reason, err) {
  if (err) log.error(reason, { err: (err && err.stack) || String(err), exitCode: code });
  else if (reason) log.info(reason, { exitCode: code });
  process.exit(code); // allow:process-exit — wiki app entrypoint terminator
}

(async function main() {
  var built = await buildApp({
    dataDir:       DATA_DIR,
    port:          PORT,
    adminEmail:    ADMIN_EMAIL,
    adminPassword: _resolveAdminPassword(),
    webhookUrl:    WEBHOOK_URL,
    webhookSecret: WEBHOOK_SECRET,
    siteUrl:       SITE_URL,
  });

  // Start the scheduler (timer-based; refs the event loop until shutdown)
  built.scheduler.start();

  var info = await built.app.listen({ port: PORT, host: BIND });
  // Display URL: 0.0.0.0 isn't a connectable address — show localhost
  // for human readability while the actual bind is on all interfaces.
  var displayHost = BIND === "0.0.0.0" ? "localhost" : BIND;
  log.info("listening", {
    url:        "http://" + displayHost + ":" + info.port,
    bind:       BIND,
    port:       info.port,
    adminEmail: ADMIN_EMAIL,
    webhookUrl: WEBHOOK_URL || null,
  });

  function _shutdown() {
    log.info("shutting down");
    built.scheduler.stop().catch(function () {});
    built.app.shutdown().then(
      function ()  { _terminate(0, "shutdown complete"); },
      function (e) { _terminate(1, "shutdown error", e); }
    );
  }
  process.once("SIGINT",  _shutdown);
  process.once("SIGTERM", _shutdown);
})().catch(function (e) {
  _terminate(1, "fatal boot error", e);
});
