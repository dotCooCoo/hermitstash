"use strict";
/**
 * @module     b.testHarness
 * @nav        DX
 * @title      Test Harness
 * @order      820
 *
 * @intro
 *   Isolated-boot helper for framework-consumer test suites. Replaces
 *   the per-project pattern of:
 *
 *     - mkdtemp a fresh data directory
 *     - set `MYAPP_DATA_DIR` / `MYAPP_DB_PATH` env vars so the app's
 *       boot path reads the test paths instead of production
 *     - init `b.vault` in plaintext mode against the test dataDir so
 *       primitives that compose vault don't try to read a real key
 *     - tear down: close vault, remove the temp directory, restore
 *       env vars
 *
 *   That pattern lands as ~50-100 lines in every framework consumer's
 *   `tests/helpers/test-server.js`. This primitive owns it once.
 *
 *   ## Lifecycle
 *
 *   ```js
 *   var h = await b.testHarness.start({
 *     envPrefix:   "MYAPP",            // optional — env vars prefixed with this
 *     env:         { LOG_LEVEL: "error" },  // optional — additional env vars to set
 *     initVault:   true,               // optional — init b.vault in plaintext mode
 *     resetCaches: true,               // optional — call framework _resetForTest() hooks
 *   });
 *   // h.dataDir   — operator-supplied or framework-generated mkdtemp path
 *   // h.dbPath    — `<dataDir>/db.sqlite` unless operator overrides
 *   // h.vaultDir  — `<dataDir>/vault`
 *
 *   // ... operator's app boot reads process.env.MYAPP_DATA_DIR etc.
 *
 *   await h.stop();   // teardown: close vault, remove dataDir, restore env
 *   ```
 *
 *   ## Concurrent test isolation
 *
 *   Tests using `SMOKE_PARALLEL=N` against the framework boot N processes
 *   in parallel — each one running this primitive gets its own
 *   `mkdtemp`-generated dataDir (collision-free) and its own env-var
 *   override scope (process-local). The harness does NOT use
 *   shared state; multiple `start()` calls in the same process create
 *   parallel handles.
 *
 *   ## What the harness does NOT own
 *
 *   - **The operator's HTTP server**. Consumers boot their own
 *     `app.listen(port)`. The harness only sets up paths + env +
 *     vault + cache-reset. The pattern in HS's
 *     `tests/helpers/test-server.js` mounts an Express app onto the
 *     harness's prepared paths.
 *   - **Per-request authentication state**. The harness doesn't
 *     mint session cookies / JWTs; tests that need that compose
 *     `b.session.create({ store: ... })` against the harness's
 *     paths.
 *   - **Audit replay tracking**. The harness emits no audit; the
 *     framework primitives the operator boots emit their own.
 *
 *   ## When to use this vs the existing `_resetForTest()` hooks
 *
 *   Framework primitives (vault, audit, db, …) expose
 *   `_resetForTest()` so a single test can scrub in-memory state
 *   without process-restart. The harness composes those resets +
 *   adds filesystem isolation. Use the harness when your test
 *   needs WRITE access to a fresh dataDir (file uploads, sealed
 *   db, audit-chain on disk); use the bare `_resetForTest()` hooks
 *   when in-memory state is enough.
 *
 * @card
 *   Isolated-boot helper for framework-consumer test suites. Owns the mkdtemp + env-vars + vault.init + teardown pattern that every consumer reinvents in their tests/helpers/test-server.js.
 */

var nodeFs   = require("node:fs");
var os       = require("node:os");
var nodePath = require("node:path");
var bCrypto      = require("./crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var lazyRequire     = require("./lazy-require");

var vault = lazyRequire(function () { return require("./vault"); });

var TestHarnessError = defineClass("TestHarnessError", { alwaysPermanent: true });

// Reference count of harnesses with initVault=true currently alive.
// vault state is process-global + idempotent across init() calls, so
// concurrent harnesses share a single initialized vault. The last
// harness to stop() releases the vault via _resetForTest; earlier
// stops decrement without tearing down so the still-running peers
// keep working.
var _vaultRefCount = 0;

/**
 * @primitive b.testHarness.start
 * @signature b.testHarness.start(opts?)
 * @since     0.9.43
 * @status    stable
 * @related   b.vault.init
 *
 * Boot an isolated test harness. Returns a promise resolving to a
 * handle exposing `dataDir`, `dbPath`, `vaultDir`, `env` (the env-var
 * overrides set), and an async `stop()` that tears the harness down
 * (releases vault, removes the temp directory, restores env). Always
 * `await` the call — vault.init is async, and unawaited failures
 * become unhandled rejections.
 *
 * Concurrent harnesses with `initVault: true` share the
 * process-global vault state via reference counting; stopping one
 * harness leaves vault initialized for the remaining peers. The
 * last `stop()` releases vault.
 *
 * @opts
 *   dataDir:     string,    // optional — pre-existing dir to use; harness mkdtemps if absent
 *   dbPath:      string,    // optional — defaults to `<dataDir>/db.sqlite`
 *   vaultDir:    string,    // optional — defaults to `<dataDir>/vault`
 *   envPrefix:   string,    // optional — env vars `<PREFIX>_DATA_DIR` / `_DB_PATH` / `_VAULT_DIR`; default no prefix
 *   env:         object,    // optional — additional env-var overrides; restored on stop()
 *   initVault:   boolean,   // optional — boot b.vault in plaintext mode against vaultDir; default true
 *   keepOnStop:  boolean,   // optional — leave dataDir in place after stop(); default false (rm -rf)
 *
 * @example
 *   var h = await b.testHarness.start({ envPrefix: "MYAPP", initVault: true });
 *   try {
 *     // ... operator's app boot reads process.env.MYAPP_DATA_DIR etc.
 *     // ... run tests ...
 *   } finally {
 *     await h.stop();
 *   }
 */
async function start(opts) {
  opts = opts || {};
  validateOpts.optionalNonEmptyString(opts.dataDir, "start.dataDir",
    TestHarnessError, "test-harness/bad-input");
  if (opts.envPrefix !== undefined && (typeof opts.envPrefix !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(opts.envPrefix))) {  // allow:regex-no-length-cap — env-var prefix shape
    throw new TestHarnessError("test-harness/bad-input",
      "start: opts.envPrefix must be uppercase ASCII identifier (A-Z, 0-9, _)");
  }
  if (opts.env !== undefined && (opts.env === null || typeof opts.env !== "object" || Array.isArray(opts.env))) {
    throw new TestHarnessError("test-harness/bad-input",
      "start: opts.env must be a plain object if provided");
  }

  // Resolve / create dataDir.
  var dataDir;
  var weCreatedDataDir = false;
  if (opts.dataDir) {
    dataDir = nodePath.resolve(opts.dataDir);
    nodeFs.mkdirSync(dataDir, { recursive: true });
  } else {
    // mkdtemp uses os.tmpdir + cryptographic suffix; collision-free
    // even under SMOKE_PARALLEL=64 fan-out. Prefix surfaces the
    // process owner for grep-on-leak diagnosis.
    var prefix = nodePath.join(os.tmpdir(),
      "blamejs-harness-" + bCrypto.generateToken(4) + "-");                                              // allow:raw-byte-literal — 4-byte token (8 hex) suffix
    dataDir = nodeFs.mkdtempSync(prefix);
    weCreatedDataDir = true;
  }

  var dbPath   = opts.dbPath   || nodePath.join(dataDir, "db.sqlite");
  var vaultDir = opts.vaultDir || nodePath.join(dataDir, "vault");
  nodeFs.mkdirSync(vaultDir, { recursive: true });

  // Capture + set env vars. We restore on stop() — values absent
  // pre-start are unset; values present are restored to their prior
  // value. The harness is process-local; concurrent harnesses share
  // process.env so the operator's envPrefix should be unique per
  // harness (or omitted, in which case no env vars are set).
  var envBackup = {};
  function _setEnv(key, value) {
    // First-write-wins on the backup so multiple writes to the same
    // key (e.g. envPrefix + opts.env naming the same var) restore the
    // ORIGINAL pre-harness value on stop(), not a harness-written
    // intermediate. Object.prototype.hasOwnProperty.call guards
    // against the `__proto__` / `constructor` key class.
    if (!Object.prototype.hasOwnProperty.call(envBackup, key)) {
      envBackup[key] = Object.prototype.hasOwnProperty.call(process.env, key)
        ? process.env[key] : null;
    }
    process.env[key] = value;
  }
  if (opts.envPrefix) {
    _setEnv(opts.envPrefix + "_DATA_DIR", dataDir);
    _setEnv(opts.envPrefix + "_DB_PATH",  dbPath);
    _setEnv(opts.envPrefix + "_VAULT_DIR", vaultDir);
  }
  if (opts.env) {
    for (var k in opts.env) {
      if (Object.prototype.hasOwnProperty.call(opts.env, k)) {
        _setEnv(k, String(opts.env[k]));
      }
    }
  }

  // Optional vault init. Default ON for the typical case where the
  // operator's primitives compose vault. Operator opts out via
  // `initVault: false` for tests that exercise vault.init themselves.
  var initVault = opts.initVault !== false;
  var ownsVaultRef = false;
  if (initVault) {
    try {
      // vault.init is async; awaiting it ensures failures surface as
      // a thrown TestHarnessError from start() (not an unhandled
      // promise rejection after start() returns).
      await vault().init({ dataDir: vaultDir, mode: "plaintext" });
      _vaultRefCount += 1;
      ownsVaultRef = true;
    } catch (e) {
      // Reset env + remove dataDir before re-throwing so the test
      // doesn't leak a half-initialized state.
      _restoreEnv(envBackup);
      if (weCreatedDataDir && !opts.keepOnStop) {
        try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); }
        catch (_e) { /* best-effort cleanup */ }
      }
      throw new TestHarnessError("test-harness/vault-init-failed",
        "start: vault.init failed: " + (e && e.message || String(e)));
    }
  }

  var stopped = false;
  async function stop() {
    if (stopped) return;
    stopped = true;

    // Vault teardown — _resetForTest is the framework convention for
    // primitive scrub. Reference-counted so concurrent harnesses
    // sharing the process-global vault don't tear it out from under
    // each other; only the LAST owning harness's stop() resets.
    if (initVault && ownsVaultRef) {
      ownsVaultRef = false;
      _vaultRefCount = Math.max(0, _vaultRefCount - 1);
      if (_vaultRefCount === 0) {
        try {
          var v = vault();
          if (typeof v._resetForTest === "function") v._resetForTest();
        } catch (_e) { /* best-effort */ }
      }
    }

    _restoreEnv(envBackup);

    if (weCreatedDataDir && !opts.keepOnStop) {
      try { nodeFs.rmSync(dataDir, { recursive: true, force: true }); }
      catch (_e) { /* best-effort — operator can inspect on leak */ }
    }
  }

  return {
    dataDir:   dataDir,
    dbPath:    dbPath,
    vaultDir:  vaultDir,
    envPrefix: opts.envPrefix || null,
    initVault: initVault,
    stop:      stop,
    TestHarnessError: TestHarnessError,
  };
}

function _restoreEnv(backup) {
  for (var k in backup) {
    if (!Object.prototype.hasOwnProperty.call(backup, k)) continue;
    if (backup[k] === null) delete process.env[k];
    else                    process.env[k] = backup[k];
  }
}

module.exports = {
  start:              start,
  TestHarnessError:   TestHarnessError,
};
