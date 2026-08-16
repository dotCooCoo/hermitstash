"use strict";

/**
 * What boot says about the configuration it found.
 *
 * These warnings are the only notice an operator gets that public uploads are
 * open to anyone, that password reset will fail silently, or that password
 * hashing is running at test strength. They are produced from config and the
 * environment and returned, so they can be driven directly rather than scraped
 * out of a booted server's stderr.
 *
 * The HTTPS check is the one with teeth: it suppresses its warning for a
 * loopback origin, and the suppression has to survive a hostname that merely
 * begins with "localhost".
 */

var os = require("node:os");
var path = require("node:path");
var fs = require("node:fs");
var { spawnSync } = require("node:child_process");

// Point DATA_DIR at a scratch directory BEFORE anything reads constants, so the
// CA-regeneration flag cases below write to a temp file rather than the real
// data directory — the check consumes and deletes that file, and doing it for
// real would eat a genuine pending notice.
var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-startup-checks-"));
process.env.HERMITSTASH_DATA_DIR = dataDir;

var { projectRoot: root } = require("../helpers/test-env");

var { describe, it, before, after, afterEach } = require("node:test");
var assert = require("node:assert");

var config = require("../../lib/config");
var vault = require("../../lib/vault");
var startupChecks = require("../../app/bootstrap/startup-checks");

var FLAG = path.join(dataDir, "ca-regen-flag.json");

// Apply a patch over config, run the checks, put config back. Console output is
// swallowed: run() prints the warnings it returns, and the assertions read the
// return value.
function runWith(patch, envPatch) {
  var savedConfig = {};
  var savedEnv = {};
  Object.keys(patch || {}).forEach(function (k) {
    savedConfig[k] = config[k];
    config[k] = patch[k];
  });
  Object.keys(envPatch || {}).forEach(function (k) {
    savedEnv[k] = process.env[k];
    if (envPatch[k] === undefined) delete process.env[k];
    else process.env[k] = envPatch[k];
  });

  var origLog = console.log;
  var origErr = console.error;
  console.log = function () {};
  console.error = function () {};
  try {
    return startupChecks.run();
  } finally {
    console.log = origLog;
    console.error = origErr;
    Object.keys(savedConfig).forEach(function (k) { config[k] = savedConfig[k]; });
    Object.keys(savedEnv).forEach(function (k) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    });
  }
}

function said(result, pattern) {
  return result.warnings.some(function (w) { return pattern.test(w); });
}

// A configuration that trips none of the warnings, so each test turns on
// exactly the one it is about.
function quiet(extra) {
  return Object.assign({
    rpOrigin: "https://stash.example.com",
    sessionSecret: "a-real-secret",
    publicUpload: false,
    localAuth: false,
    passkeyEnabled: true,
    google: { clientID: "" },
    enforceMtls: false,
    emailVerification: false,
    registrationOpen: false,
    setupComplete: false,
    email: { enabled: true, host: "smtp.example.com", user: "postmaster", resendApiKey: "" },
  }, extra || {});
}

var QUIET_ENV = { ARGON2_FAST: undefined, ENFORCE_MTLS_STRICT: undefined };

describe("startup checks", function () {
  // The default-admin check reads users by email, which is a sealed column —
  // its blind index needs the vault MAC key.
  before(async function () { await vault.init(); });

  after(function () {
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  });
  afterEach(function () {
    try { fs.unlinkSync(FLAG); } catch (_e) { /* most cases never write it */ }
  });

  it("says nothing when the configuration is sound", function () {
    var out = runWith(quiet(), QUIET_ENV);
    assert.deepEqual(out.errors, []);
    assert.deepEqual(out.warnings, [], "a sound configuration should be silent: " + out.warnings.join(" | "));
  });

  describe("the canonical origin", function () {
    it("warns when none is set", function () {
      var out = runWith(quiet({ rpOrigin: "" }), QUIET_ENV);
      assert.ok(said(out, /No rpOrigin configured/), out.warnings.join(" | "));
    });

    it("warns when it is not HTTPS", function () {
      var out = runWith(quiet({ rpOrigin: "http://stash.example.com" }), QUIET_ENV);
      assert.ok(said(out, /rpOrigin is not HTTPS/), out.warnings.join(" | "));
    });

    it("stays quiet for a loopback origin, which does not need TLS", function () {
      var out = runWith(quiet({ rpOrigin: "http://localhost:3000" }), QUIET_ENV);
      assert.ok(!said(out, /not HTTPS/), out.warnings.join(" | "));
    });

    it("stays quiet for 127.0.0.1 as well", function () {
      var out = runWith(quiet({ rpOrigin: "http://127.0.0.1:3000" }), QUIET_ENV);
      assert.ok(!said(out, /not HTTPS/), out.warnings.join(" | "));
    });

    it("still warns for a host that merely STARTS with localhost", function () {
      // The reason this is a parse plus a loopback classification rather than a
      // substring test: localhost.evil.com resolves wherever its owner points
      // it, and suppressing the warning for it hides a plaintext origin.
      var out = runWith(quiet({ rpOrigin: "http://localhost.evil.com" }), QUIET_ENV);
      assert.ok(said(out, /rpOrigin is not HTTPS/),
        "localhost.evil.com is not loopback: " + out.warnings.join(" | "));
    });

    it("warns when the origin cannot be parsed at all", function () {
      var out = runWith(quiet({ rpOrigin: "http://[not a host]:::" }), QUIET_ENV);
      assert.ok(said(out, /rpOrigin is not HTTPS/),
        "an unparseable origin must not be treated as loopback: " + out.warnings.join(" | "));
    });
  });

  describe("authentication and uploads", function () {
    it("warns when public upload is on with no way to identify anyone", function () {
      var out = runWith(quiet({ publicUpload: true, localAuth: false, passkeyEnabled: false, google: { clientID: "" } }), QUIET_ENV);
      assert.ok(said(out, /no authentication method configured/), out.warnings.join(" | "));
    });

    it("stays quiet when public upload is paired with local accounts", function () {
      var out = runWith(quiet({ publicUpload: true, localAuth: true }), QUIET_ENV);
      assert.ok(!said(out, /no authentication method configured/), out.warnings.join(" | "));
    });

    it("counts a Google client as an authentication method", function () {
      var out = runWith(quiet({ publicUpload: true, passkeyEnabled: false, google: { clientID: "abc.apps.googleusercontent.com" } }), QUIET_ENV);
      assert.ok(!said(out, /no authentication method configured/), out.warnings.join(" | "));
    });

    it("warns about the default session secret", function () {
      var out = runWith(quiet({ sessionSecret: "change-me-please" }), QUIET_ENV);
      assert.ok(said(out, /Session secret is the default/), out.warnings.join(" | "));
    });
  });

  describe("password hashing strength", function () {
    it("warns loudly when the fast Argon2 parameters are in force", function () {
      var out = runWith(quiet(), { ARGON2_FAST: "1", ENFORCE_MTLS_STRICT: undefined });
      assert.ok(said(out, /ARGON2_FAST=1 is set/), out.warnings.join(" | "));
      assert.ok(said(out, /DO NOT use in production/), "the warning has to be unmissable");
    });
  });

  describe("mutual TLS", function () {
    it("reports the network-layer mode and how to leave it", function () {
      var out = runWith(quiet(), { ENFORCE_MTLS_STRICT: "true", ARGON2_FAST: undefined });
      assert.ok(said(out, /ENFORCE_MTLS_STRICT=true/), out.warnings.join(" | "));
      assert.ok(said(out, /ENFORCE_MTLS_STRICT=false/), "an escape hatch has to be stated");
    });

    it("reports the app-layer mode separately", function () {
      var out = runWith(quiet({ enforceMtls: true }), QUIET_ENV);
      assert.ok(said(out, /Enforce mTLS is ON \(soft\)/), out.warnings.join(" | "));
    });

    it("prefers the network-layer message when both are on", function () {
      var out = runWith(quiet({ enforceMtls: true }), { ENFORCE_MTLS_STRICT: "true", ARGON2_FAST: undefined });
      assert.ok(said(out, /ENFORCE_MTLS_STRICT=true/), out.warnings.join(" | "));
      assert.ok(!said(out, /soft/), "one mTLS message, not two: " + out.warnings.join(" | "));
    });
  });

  describe("the CA-regeneration notice", function () {
    // The exact fields routes/admin.js writes into the flag. Naming one the
    // writer does not set is how this notice came to report a number nobody
    // produced, so the shape here is copied from the producer rather than from
    // the message that reads it.
    function realSummary(over) {
      return Object.assign({
        caGenerationBefore: 3, caGenerationAfter: 4,
        syncCertsTotal: 3, syncClientsConnected: 3, syncClientsAcked: 2,
        syncClientsOffline: 1, browserCertsUnaffected: 5, restartInMs: 0,
      }, over || {});
    }

    it("reports a pending regeneration and consumes the flag", function () {
      fs.writeFileSync(FLAG, JSON.stringify({ at: "2026-08-16T10:00:00Z", summary: realSummary() }));
      var out = runWith(quiet(), QUIET_ENV);
      assert.ok(said(out, /mTLS CA was regenerated at 2026-08-16T10:00:00Z \(v3 → v4\)/), out.warnings.join(" | "));
      assert.ok(said(out, /2\/3 live sync clients/), out.warnings.join(" | "));
      assert.ok(said(out, /1 offline clients need re-enrollment/), out.warnings.join(" | "));
      assert.equal(fs.existsSync(FLAG), false, "the flag is consumed so the notice does not repeat");
    });

    it("does not tell admins to re-download browser certificates", function () {
      // A sync-CA regeneration does not touch them — they are issued by the
      // separate browser CA (routes/admin.js says so at the commit). The notice
      // said they were invalidated, which was true only before the split.
      fs.writeFileSync(FLAG, JSON.stringify({ at: "2026-08-16T10:00:00Z", summary: realSummary() }));
      var out = runWith(quiet(), QUIET_ENV);
      assert.ok(said(out, /Browser certificates are unaffected/), out.warnings.join(" | "));
      assert.ok(!said(out, /invalidated|re-download/), out.warnings.join(" | "));
    });

    it("does not repeat the notice on the next boot", function () {
      fs.writeFileSync(FLAG, JSON.stringify({ at: "2026-08-16T10:00:00Z", summary: realSummary() }));
      var first = runWith(quiet(), QUIET_ENV);
      assert.ok(said(first, /mTLS CA was regenerated/), "the first boot reports it");
      var second = runWith(quiet(), QUIET_ENV);
      assert.ok(!said(second, /mTLS CA was regenerated/), second.warnings.join(" | "));
    });

    it("does not print a notice made of undefined when the summary is missing", function () {
      // Valid JSON carrying a timestamp but no generations. Requiring only `at`
      // let this through and rendered "v undefined → v undefined".
      fs.writeFileSync(FLAG, JSON.stringify({ at: "2026-08-16T10:00:00Z", summary: {} }));
      var out = runWith(quiet(), QUIET_ENV);
      assert.ok(!said(out, /undefined/), out.warnings.join(" | "));
      assert.ok(said(out, /could not be read/), "and it is reported as unreadable: " + out.warnings.join(" | "));
    });

    it("does not print a notice made of undefined when the flag is corrupt", function () {
      // parseOrDefault answers {} for anything unparseable, so every field
      // interpolated into the notice is undefined. An operator reading
      // "regenerated at undefined (vundefined -> vundefined)" learns nothing and
      // cannot tell it apart from a real regeneration they should act on.
      fs.writeFileSync(FLAG, "{ this is not json");
      var out = runWith(quiet(), QUIET_ENV);
      assert.ok(!said(out, /undefined/),
        "a corrupt flag must not produce a notice full of undefined: " + out.warnings.join(" | "));
      assert.ok(!said(out, /re-download/),
        "and must not resurrect the browser-certificate instruction the valid path just dropped: " + out.warnings.join(" | "));
      assert.equal(fs.existsSync(FLAG), false, "and the unreadable flag is still cleared");
    });

    it("does not print a notice when the flag is valid JSON but empty", function () {
      fs.writeFileSync(FLAG, "{}");
      var out = runWith(quiet(), QUIET_ENV);
      assert.ok(!said(out, /undefined/), out.warnings.join(" | "));
    });
  });

  describe("data directory permissions", function () {
    // Windows has no group/other mode bits, and the check says so itself, so
    // this runs where the branch exists. mkdtemp already gives 0700, which is
    // why the sound-configuration case above stays silent on Linux too.
    var unixOnly = { skip: process.platform === "win32" ? "POSIX mode bits only" : false };

    it("warns when the data directory is readable by anyone", unixOnly, function () {
      fs.chmodSync(dataDir, 0o777);
      try {
        var out = runWith(quiet(), QUIET_ENV);
        assert.ok(said(out, /data\/ directory has loose permissions \(777\)/), out.warnings.join(" | "));
        assert.ok(said(out, /chmod 700/), "and names the fix");
      } finally {
        fs.chmodSync(dataDir, 0o700);
      }
    });

    it("stays quiet at 0700", unixOnly, function () {
      fs.chmodSync(dataDir, 0o700);
      var out = runWith(quiet(), QUIET_ENV);
      assert.ok(!said(out, /loose permissions/), out.warnings.join(" | "));
    });
  });

  describe("environment variable values", function () {
    it("passes through a value the settings schema rejects", function () {
      // These used to fall back to a default in silence, so an operator who
      // typed the value wrong got the default's behaviour and no clue why.
      var out = runWith(quiet(), { PORT: "definitely-not-a-port", ARGON2_FAST: undefined, ENFORCE_MTLS_STRICT: undefined });
      assert.ok(said(out, /PORT='definitely-not-a-port' is invalid/), out.warnings.join(" | "));
      assert.ok(said(out, /Using default/), "and says what happens instead");
    });

    it("says nothing about a value the schema accepts", function () {
      var out = runWith(quiet(), { PORT: "8443", ARGON2_FAST: undefined, ENFORCE_MTLS_STRICT: undefined });
      assert.ok(!said(out, /PORT=/), out.warnings.join(" | "));
    });
  });

  describe("the default admin account", function () {
    // This is the one check that is fatal, and it ends the process — so it runs
    // in a child. The account is found by querying a SEALED column in plaintext,
    // which the database layer answers from the blind index; a test that seeded
    // the row any other way would pass while the real check found nothing.
    it("refuses to finish booting while the default admin address is still in use", function () {
      var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hs-default-admin-"));
      var email = "admin@hermitstash.com";
      var script = [
        "var vault = require(" + JSON.stringify(path.join(root, "lib", "vault")) + ");",
        "vault.init().then(function () {",
        "  var { hashEmail } = require(" + JSON.stringify(path.join(root, "lib", "crypto")) + ");",
        "  var { users } = require(" + JSON.stringify(path.join(root, "lib", "db")) + ");",
        "  users.insert({",
        "    email: vault.seal(" + JSON.stringify(email) + "),",
        "    emailHash: hashEmail(" + JSON.stringify(email) + "),",
        "    displayName: vault.seal('Default Admin'),",
        "    authType: 'local', role: 'admin', status: 'active',",
        "    createdAt: new Date().toISOString(),",
        "  });",
        "  require(" + JSON.stringify(path.join(root, "lib", "config")) + ").setupComplete = true;",
        "  require(" + JSON.stringify(path.join(root, "app", "bootstrap", "startup-checks")) + ").run();",
        "  process.stdout.write('BOOT-CONTINUED');",
        "});",
      ].join("\n");

      var res = spawnSync(process.execPath, ["-e", script], {
        cwd: root,
        encoding: "utf8",
        env: Object.assign({}, process.env, {
          HERMITSTASH_DATA_DIR: tmp,
          HERMITSTASH_DB_PATH: path.join(tmp, "default-admin.db"),
          HERMITSTASH_SESSION_DB: "default-admin-session.db",
          HERMITSTASH_ALLOW_DISK_DB: "true",
        }),
      });
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* best effort */ }

      var said_ = String(res.stderr || "") + String(res.stdout || "");
      assert.ok(String(res.stdout || "").indexOf("BOOT-CONTINUED") === -1,
        "boot must not continue past a fatal check: " + said_.slice(0, 400));
      assert.equal(res.status, 1, "a fatal startup error exits 1: " + said_.slice(0, 400));
      assert.match(said_, /FATAL startup errors/);
      assert.match(said_, /Default admin email \(admin@hermitstash\.com\) still in use/);
      assert.match(said_, /Fix these issues and restart/);
    });
  });

  describe("email delivery", function () {
    it("warns that self-serve password reset will fail when no backend is set", function () {
      var out = runWith(quiet({ localAuth: true, email: { enabled: true, host: "", user: "", resendApiKey: "" } }), QUIET_ENV);
      assert.ok(said(out, /self-serve password reset will silently fail/), out.warnings.join(" | "));
      assert.ok(said(out, /no email backend configured/), "the reason has to name the setting");
    });

    it("names the disabling switch when email is turned off explicitly", function () {
      var out = runWith(quiet({ localAuth: true, email: { enabled: false, host: "smtp.example.com", user: "postmaster", resendApiKey: "" } }), QUIET_ENV);
      assert.ok(said(out, /EMAIL_ENABLED=false/), out.warnings.join(" | "));
    });

    it("accepts an API-key backend as configured", function () {
      var out = runWith(quiet({ localAuth: true, email: { enabled: true, host: "", user: "", resendApiKey: "re_test_key" } }), QUIET_ENV);
      assert.ok(!said(out, /password reset will silently fail/), out.warnings.join(" | "));
    });

    it("warns that registrations will stall when verification needs email it does not have", function () {
      var out = runWith(quiet({
        localAuth: true, emailVerification: true, registrationOpen: true,
        email: { enabled: true, host: "", user: "", resendApiKey: "" },
      }), QUIET_ENV);
      assert.ok(said(out, /New registrations will stall/), out.warnings.join(" | "));
    });

    it("stays quiet about registrations when registration is closed", function () {
      var out = runWith(quiet({
        localAuth: true, emailVerification: true, registrationOpen: false,
        email: { enabled: true, host: "", user: "", resendApiKey: "" },
      }), QUIET_ENV);
      assert.ok(!said(out, /New registrations will stall/), out.warnings.join(" | "));
    });

    it("needs both a host and a user before SMTP counts as configured", function () {
      var out = runWith(quiet({ localAuth: true, email: { enabled: true, host: "smtp.example.com", user: "", resendApiKey: "" } }), QUIET_ENV);
      assert.ok(said(out, /password reset will silently fail/),
        "a host with no user is not a usable backend: " + out.warnings.join(" | "));
    });
  });
});
