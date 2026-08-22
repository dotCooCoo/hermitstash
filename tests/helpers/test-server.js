/**
 * Starts a HermitStash server on a random port with an isolated test database.
 * Mounts ALL routes and middleware including api-encrypt.
 *
 * b.testHarness.start (v0.9.43+) owns the env-var set + restore-on-stop
 * lifecycle. Pre-harness this file did `process.env.X = "..."` directly and
 * never reset on stop() — a real env-leak across sibling test processes
 * under `--test-concurrency`. The harness's stop() restores the pre-start
 * values (and removes keys that didn't exist before), so a sibling test
 * starting after our stop() sees a clean process.env.
 *
 * initVault is FALSE: HS's lib/vault.init wraps b.vault.init with
 * HS-specific rotation-recovery + sealed-file mode-mismatch checks +
 * BLAMEJS_VAULT_PASSPHRASE_* env-mirror. b.testHarness's `initVault: true`
 * path calls b.vault.init directly — skipping HS's wrapper. The
 * harness still does its other work (dataDir + env management + ref-
 * counting hooks) and HS's vault.init() runs explicitly below.
 */
const path = require("path");
const fs = require("fs");
const os = require("os");
const b = require("../../lib/vendor/blamejs");

const projectRoot = path.join(__dirname, "..", "..");
const testId = b.crypto.generateToken(4);

// Scratch lives in the OS temp directory, not under the repo.
//
// It used to be data/test-<id> and uploads/test-<id>, and the teardown could not
// reliably remove them: on Windows a file-syncing agent holds the directory
// handle, so every file inside deletes and the rmdir itself raises EPERM. The
// result was 9,097 abandoned directories in data/ — each holding a vault
// keypair and a ~400 KB database — sitting beside the live database and the
// real vault keys, and being replicated to cloud storage.
//
// Nothing depended on the location: consumers read testUploadDir and testDbPath
// from this module. tests/test-server-e2e.js already did it this way.
const testRoot = path.join(os.tmpdir(), "hermitstash-test-" + testId);
const testDataDir = path.join(testRoot, "data");
const testUploadDir = path.join(testRoot, "uploads");
const testDbPath = path.join(testDataDir, "test.db");

let server = null;
let port = 0;
let harness = null;

const ENV_OVERRIDES = {
  PORT: "0",
  UPLOAD_DIR: testUploadDir,
  SESSION_SECRET: "test-secret-" + testId,
  HERMITSTASH_SESSION_DB: "test-session-" + testId + ".db",
  // A bare filename, not a path — lib/session.js joins it onto /dev/shm where
  // that exists and onto the data directory where it does not, so the unique
  // name alone kept the session database inside the repo.
  //
  // Pointed at this run's own data directory rather than the shared temp root:
  // lib/db.js sweeps its working directory at load and deletes every other
  // hermitstash-*.db in it, so a shared directory has concurrent test processes
  // deleting each other's databases.
  HERMITSTASH_TMPDIR: testDataDir,
  LOCAL_AUTH: "true",
  REGISTRATION_OPEN: "true",
  PUBLIC_UPLOAD: "true",
  STORAGE_BACKEND: "local",
  GOOGLE_CLIENT_ID: "",
  SMTP_HOST: "",
  EMAIL_VERIFICATION: "false",
  PASSKEY_ENABLED: "true",
  RP_ID: "localhost",
  RP_ORIGIN: "http://localhost",
  HERMITSTASH_DB_PATH: testDbPath,
  // Pin HERMITSTASH_DATA_DIR per-test so concurrent vault.key.sealed
  // creators don't trip sibling tests with the mode-mismatch refusal.
  HERMITSTASH_DATA_DIR: testDataDir,
};

function clearCache() {
  var keys = Object.keys(require.cache);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].includes("hermitstash") && !keys[i].includes("node_modules") && !keys[i].includes("test")) {
      delete require.cache[keys[i]];
    }
  }
}

var allRoutes = [
  "auth", "dashboard", "files", "drop", "bundles", "admin", "users",
  "profile", "audit", "apikeys", "webhooks", "verification", "passkey",
  "two-factor", "teams", "vault", "password-reset", "stash",
];

function resetAllRateLimits() {
  var rateLimit = require(path.join(projectRoot, "lib", "rate-limit"));
  // Every guarded route limits through b.middleware.rateLimit; resetAll()
  // drops all keys across all limiter instances, so one call flushes login,
  // register, upload, 2FA, and every other guarded route between cases.
  rateLimit.resetAllInstances();
}

async function start(opts) {
  opts = opts || {};
  fs.mkdirSync(testUploadDir, { recursive: true });

  // b.testHarness owns dataDir creation + env-var set/restore + vault
  // ref-counting. We pass the dataDir explicitly (no mkdtemp) so the
  // module-level exports stay stable; harness still does cleanup +
  // env restoration on stop().
  harness = await b.testHarness.start({
    dataDir:   testDataDir,
    initVault: false,
    env:       Object.assign({}, ENV_OVERRIDES, opts.env || {}),
  });

  clearCache();

  // lib/session.js's b.session backend requires b.vault to be
  // initialized before any seal call. Production wires this through
  // server.js's `await vault.init()`; the test harness calls HS's
  // wrapper here (which composes b.vault.init internally) so the
  // HS-specific rotation-recovery + sealed-file mode-mismatch checks
  // run before the rest of the boot sequence.
  var vault = require(path.join(projectRoot, "lib", "vault"));
  await vault.init();

  await _continueStart(opts);
}

function _continueStart(opts) {
  return new Promise(function (resolve) {
    // Require lib/rate-limit so resetAllRateLimits() can flush every
    // b.middleware.rateLimit instance between cases. The routes below
    // construct their own limiters as they load; the framework owns the
    // registry resetAllInstances() clears.
    require(path.join(projectRoot, "lib", "rate-limit"));
    var { Router, serveStatic } = b.router;
    var { sessionMiddleware } = require(path.join(projectRoot, "lib", "session"));
    var attachUser = require(path.join(projectRoot, "middleware", "attach-user"));
    var apiEncryptKeypair = require(path.join(projectRoot, "lib", "api-encrypt-keypair"));
    var legacyApiEncrypt = require(path.join(projectRoot, "middleware", "api-encrypt"));

    var app = new Router();
    app.use(require(path.join(projectRoot, "middleware", "security-headers")));
    app.use(serveStatic(path.join(projectRoot, "public")));
    app.use(require(path.join(projectRoot, "middleware", "ip-check")));
    app.use(sessionMiddleware);
    app.use(attachUser);
    app.use(require(path.join(projectRoot, "middleware", "api-auth")));

    // ---- blamejs per-session apiEncrypt protocol ----
    //
    // MUST mirror server-main.js's wiring exactly. When tests install
    // only the legacy api-encrypt middleware, any defect that lives in
    // the blamejs gating / body-parser / apiEncrypt chain surfaces only
    // in production. The browser-upload regression class — cookie-auth
    // /drop/init rejected with "encrypted-payload-required" because
    // blamejs intercepted the path before legacy could handle it — is
    // exactly what this divergence can hide. Keep this block byte-
    // aligned with server-main.js — when the production wiring
    // changes, this block changes too.
    var blamejsKeypair = apiEncryptKeypair.loadOrGenerate();
    var blamejsApiEncrypt = b.middleware.apiEncrypt({
      keypair:     blamejsKeypair,
      keying:      "per-session",
      exemptPaths: ["/.well-known/blamejs-pubkey"],
    });
    var blamejsBodyParser = b.middleware.bodyParser({
      json:       { limit: b.constants.BYTES.mib(2) },
      urlencoded: false,
      text:       false,
      raw:        false,
      multipart:  false,
    });
    function isBlamejsApiEncryptPath(req) {
      var p = req.pathname || "";
      if (p === "/.well-known/blamejs-pubkey") return true;
      if (!req.apiKey) return false;
      if (p === "/drop/init") return req.method === "POST";
      if (p.indexOf("/drop/finalize/") === 0) return req.method === "POST";
      if (p === "/sync/rename") return req.method === "POST";
      return false;
    }
    app.use(function legacyApiEncryptCarve(req, res, next) {
      if (isBlamejsApiEncryptPath(req)) return next();
      legacyApiEncrypt(req, res, next);
    });
    app.use(function blamejsBodyParserGate(req, res, next) {
      if (!isBlamejsApiEncryptPath(req)) return next();
      if (req.method !== "POST" && req.method !== "PUT" && req.method !== "PATCH") return next();
      return blamejsBodyParser(req, res, next);
    });
    app.use(function blamejsApiEncryptGate(req, res, next) {
      if (!isBlamejsApiEncryptPath(req)) return next();
      return blamejsApiEncrypt(req, res, next);
    });
    app.get("/.well-known/blamejs-pubkey", blamejsApiEncrypt.publishPublicKey());

    // CSRF middleware must mirror production — it generates req.session._csrf
    // which routes (e.g. /auth/logout) validate against. Without this, form
    // POST routes that expect CSRF validation would always 403 in tests.
    app.use(require(path.join(projectRoot, "app", "security", "csrf-policy")).csrfMiddleware);

    // Same position server-main.js mounts it, and a no-op unless the run turns
    // maintenance on. It was missing here, which is why the /health exemption
    // — the one an orchestrator restarts the container over — had no coverage.
    app.use(require(path.join(projectRoot, "middleware", "maintenance")));

    var routes = opts.routes || allRoutes;
    for (var i = 0; i < routes.length; i++) {
      require(path.join(projectRoot, "routes", routes[i]))(app);
    }

    // Centralized error handler — mirrors server-main.js so thrown AppError
    // subclasses become RFC 9457 problem-details instead of the router's
    // bare 500 fallback. Without this, any route that throws to the boundary
    // reaches the test client as text/plain "Internal Server Error".
    app.onError(require(path.join(projectRoot, "middleware", "error-handler")));

    // Initialize the transaction helper — needed by service modules that
    // wrap multi-step DB operations (teams.deleteTeam, etc.). Mirrors
    // server-main.js:90 (txHelper.init). Safe to call redundantly.
    try {
      var txHelper = require(path.join(projectRoot, "app", "data", "db", "transaction"));
      var dbMod = require(path.join(projectRoot, "lib", "db"));
      txHelper.init(dbMod.getDb());
    } catch (_e) { /* best effort — tests that don't use transactions will still work */ }

    server = app.listen(0, function () {
      port = server.address().port;
      resetAllRateLimits();
      resolve();
    });
  });
}

async function stop() {
  if (server) {
    await new Promise(function (resolve) {
      server.close(function () { resolve(); });
      // Force-close keep-alive connections so the process exits promptly
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
    });
    server = null;
  }
  try { fs.rmSync(testUploadDir, { recursive: true, force: true }); } catch {}

  // Close the database before the harness removes the directory holding it.
  //
  // Windows refuses to delete a file another handle has open, so harness.stop()
  // was failing on the still-open test.db and swallowing it — silently, and only
  // here: Linux unlinks an open file happily, so CI never showed it. Each run
  // left behind a directory with a vault keypair and a ~400 KB database, and on
  // a development machine data/ sits inside a synced folder. 9,097 of them had
  // collected.
  //
  // Suppress the exit-time re-encrypt first: it exists to persist the live
  // database at shutdown, and there is nothing here worth persisting — the
  // directory is about to be deleted.
  try {
    var dbMod = require(path.join(projectRoot, "lib", "db"));
    if (typeof dbMod.suppressExitEncrypt === "function") dbMod.suppressExitEncrypt();
    var handle = typeof dbMod.getDb === "function" ? dbMod.getDb() : null;
    if (handle && typeof handle.close === "function") handle.close();
  } catch (_e) { /* best effort — a failure here only restores the old littering */ }

  // The session store is a SECOND database, living in this same directory now
  // that HERMITSTASH_TMPDIR points here, and it holds the directory just as
  // firmly as the first one.
  try {
    var sessionMod = require(path.join(projectRoot, "lib", "session"));
    if (typeof sessionMod.closeStore === "function") sessionMod.closeStore();
  } catch (_e) { /* best effort */ }

  if (harness) {
    // harness.stop() restores env and releases the vault. It does NOT remove
    // this directory, and the comment here used to say it did: the harness
    // removes a dataDir only when it created one itself (`weCreatedDataDir`),
    // and this one is supplied by us. That is the right call on its part — it
    // does not delete a directory an operator handed it — so removing ours is
    // ours to do.
    // Reentrant: marked stopped internally, additional calls are no-ops.
    await harness.stop();
    harness = null;
  }
  // Remove the whole scratch root. In the OS temp directory this succeeds; if a
  // watcher ever holds the directory itself, the files still go and what is left
  // is an empty shell the operating system will sweep.
  try { fs.rmSync(testRoot, { recursive: true, force: true }); } catch {}
}

function baseUrl() {
  return "http://localhost:" + port;
}

module.exports = {
  start,
  stop,
  baseUrl,
  clearCache,
  resetAllRateLimits,
  projectRoot,
  testDataDir,
  testDbPath,
  testUploadDir,
};
