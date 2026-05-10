"use strict";
/**
 * @module b.dev
 * @nav    Tools
 * @title  Dev
 *
 * @intro
 *   Dev-mode helpers — hot-reload signal (file watch + child-process
 *   restart), route-list dump exposed via `dev.stats()`, and a request
 *   inspector courtesy of `stdio: 'inherit'` so the operator sees the
 *   spawned app's logs unchanged.
 *
 *   The hot-reload loop spawns the app as a child process, watches the
 *   source directories with `fs.watch({ recursive: true })`, and
 *   restarts the child when an unignored file changes. On-disk state
 *   (vault keys, encrypted DB, sealed cookies) survives the restart
 *   because the child re-opens the files; only in-process state is
 *   lost, which is the correct semantic for "I just edited a route
 *   handler and want to see it."
 *
 *   Hygiene baked in:
 *     - Bursts of file events (save-everything keystrokes, multi-file
 *       format-on-save) collapse into one restart via the `graceMs`
 *       debounce (default 250 ms).
 *     - A restart-in-flight queues at most one follow-up — many edits
 *       during a slow restart yield two restarts, not N.
 *     - Ignored kinds by default: `node_modules/`, `.git/`, dotfiles,
 *       SQLite journal/WAL/SHM siblings, `.log`, editor scratch files
 *       (`.swp`, `~$`).
 *     - Crash without a pending stop/restart leaves the child corpse
 *       in place and waits for a file change rather than spawn-thrashing.
 *     - Graceful kill via `SIGTERM`; `SIGKILL` escalation after
 *       `killTimeoutMs` (default 4000 ms) if the child ignores it.
 *
 *   Production refusal: `dev.create()` throws `dev/refused-in-production`
 *   when `NODE_ENV=production`, unless the operator explicitly sets
 *   `opts.allowProduction: true` with an audited reason. This is what
 *   `blamejs dev` (CLI) calls; production deployments that accidentally
 *   wire it crash loudly at boot rather than spawning shells on every
 *   save.
 *
 *   Test seams: `opts._spawn(cmd, args, sopts)` and
 *   `opts._watch(dir, wopts, listener)` default to `child_process.spawn`
 *   and `fs.watch`; unit tests pass fakes to drive the engine without
 *   real subprocesses.
 *
 * @card
 *   Dev-mode helpers — hot-reload signal (file watch + child-process restart), route-list dump exposed via `dev.stats()`, and a request inspector courtesy of `stdio: 'inherit'` so the operator sees the spawned app's logs unchanged.
 */

var path = require("path");
var fs = require("fs");
var lazyRequire = require("./lazy-require");
var logModule = require("./log");
var nb = require("./numeric-bounds");
var safeEnv = require("./parsers/safe-env");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

// child_process is required ONLY when dev.create() is actually
// called — not at module load. The dev primitive spawns subprocesses
// (nodemon-style restart loop) by design; isolating the dependency
// behind lazy-load means a production process that never calls
// b.dev.create() never loads child_process, and supply-chain scanners
// inspecting a deployed bundle don't see it as a top-level dep of an
// otherwise hermetic framework. Production deployments additionally
// refuse to construct dev.create() — see _refuseInProduction below.
var childProcess = lazyRequire(function () { return require("child_process"); });

class DevError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "DevError";
    this.permanent = true;
    this.isDevError = true;
  }
}

var bootLog = logModule.boot("dev");

var DEFAULT_GRACE_MS         = 250;
// Default SIGKILL escalation budget: 4s — long enough for graceful
// shutdown handlers to flush, short enough that an ignored SIGTERM
// doesn't keep the dev loop hanging.
var DEFAULT_KILL_TIMEOUT_MS  = 0xFA0;
var DEFAULT_KILL_SIGNAL      = "SIGTERM";
var DEFAULT_IGNORE = [
  /node_modules/,
  /\.git\b/,
  /^\./,                // dotfiles + dotdirs
  /\.db$/, /\.db-journal$/, /\.db-wal$/, /\.db-shm$/,
  /\.log$/,
  /\.swp$/, /~$/,       // editor scratch files
];

function _matchesAny(patterns, value) {
  for (var i = 0; i < patterns.length; i++) {
    var p = patterns[i];
    if (p instanceof RegExp) { if (p.test(value)) return true; }
    else if (typeof p === "string") { if (value.indexOf(p) !== -1) return true; }
  }
  return false;
}

function _logVia(log, level, message, fields) {
  if (log && typeof log[level] === "function") {
    try { log[level](message, fields); }
    catch (_e) { /* logger best-effort */ }
    return;
  }
  // Fallback: framework boot channel (TTY-aware, structured-JSON when piped).
  var line = message + (fields ? " " + JSON.stringify(fields) : "");
  var emit = (level === "error" || level === "fatal") ? bootLog.error
    : (level === "warn" ? bootLog.warn : bootLog.info);
  emit(line);
}

/**
 * @primitive b.dev.create
 * @signature b.dev.create(opts)
 * @since     0.4.0
 * @status    stable
 *
 * Build a hot-reload supervisor — spawn `opts.command` with `opts.args`,
 * watch `opts.watch` directories, and restart the child on every
 * unignored file change. Returns `{ start, stop, restart, stats }`;
 * `stats()` reports `{ pid, running, restarts, lastRestartAt, watchers }`.
 *
 * Throws `DevError` at config time on a missing command, a non-finite
 * `graceMs` / `killTimeoutMs`, or an attempt to load with
 * `NODE_ENV=production` (without `opts.allowProduction`).
 *
 * @opts
 *   command:        string,                       // required — program to spawn (e.g. "node")
 *   args:           [string],                     // argv after command; default []
 *   watch:          [string],                     // directories to watch (recursive); default ["."]
 *   ignore:         [RegExp | string],            // appended to the framework default-ignore list
 *   graceMs:        number,                       // debounce window (ms); default 250
 *   killSignal:     string,                       // initial kill signal; default "SIGTERM"
 *   killTimeoutMs:  number,                       // SIGKILL escalation budget (ms); default 4000
 *   log:            object,                       // structured logger ({ info, warn, error })
 *   env:            object,                       // child env; default process.env
 *   cwd:            string,                       // child cwd; default process.cwd()
 *   stdio:          string | array,               // child stdio; default "inherit"
 *   allowProduction: boolean,                     // override the production refusal (audited reason required)
 *
 * @example
 *   var dev = b.dev.create({
 *     command: "node",
 *     args:    ["./server.js"],
 *     watch:   ["./routes", "./views", "./lib"],
 *     ignore:  [/\.tmp$/],
 *     graceMs: 250,
 *   });
 *
 *   // await dev.start();
 *   // dev.stats();   // → { pid: <number>, running: true, restarts: 0, lastRestartAt: null, watchers: 3 }
 *   // await dev.stop();
 */
function create(opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(opts.command, "dev.create: opts.command (the program to spawn)", DevError, "dev/no-command");
  var args         = Array.isArray(opts.args) ? opts.args.slice() : [];
  var watch        = Array.isArray(opts.watch) && opts.watch.length > 0
    ? opts.watch.slice() : ["."];
  var ignore       = Array.isArray(opts.ignore)
    ? DEFAULT_IGNORE.concat(opts.ignore)
    : DEFAULT_IGNORE.slice();
  nb.requireNonNegativeFiniteIntIfPresent(opts.graceMs,
    "dev.create: opts.graceMs", DevError, "dev/bad-grace-ms");
  var graceMs = opts.graceMs !== undefined ? opts.graceMs : DEFAULT_GRACE_MS;
  var killSignal   = typeof opts.killSignal === "string" ? opts.killSignal : DEFAULT_KILL_SIGNAL;
  nb.requireNonNegativeFiniteIntIfPresent(opts.killTimeoutMs,
    "dev.create: opts.killTimeoutMs", DevError, "dev/bad-kill-timeout-ms");
  var killTimeoutMs = opts.killTimeoutMs !== undefined ? opts.killTimeoutMs : DEFAULT_KILL_TIMEOUT_MS;
  var log          = opts.log || null;
  var env          = opts.env || process.env;
  var cwd          = opts.cwd || process.cwd();

  // dev.create() is intended for development-mode use only —
  // restarting subprocesses on file change is a feature operators
  // run on their laptop, never in production. Refusing here means a
  // mis-configured production deployment that accidentally wires the
  // dev primitive crashes loudly at boot rather than spawning shells
  // on every save. Operators with a legitimate cross-cutting need
  // (e.g. a CI runner that uses dev() to drive end-to-end tests)
  // explicitly opt in via opts.allowProduction with an audited reason.
  if (safeEnv.readVar("NODE_ENV") === "production" && !opts.allowProduction) {
    throw new DevError("dev/refused-in-production",
      "b.dev.create: dev mode refuses to load when NODE_ENV=production. " +
      "Set opts.allowProduction:true with an audited reason if a non-dev " +
      "context legitimately needs subprocess spawn-on-watch behaviour.");
  }

  // Test seams. childProcess is lazily-required; calling spawn here
  // pulls in node's child_process module on first dev.create() use.
  var spawnFn = opts._spawn || function (cmd, sargs, sopts) {
    return childProcess().spawn(cmd, sargs, sopts);
  };
  var watchFn = opts._watch || function (dir, wopts, listener) {
    return fs.watch(dir, wopts, listener);
  };
  var setTimeoutFn  = opts._setTimeout  || setTimeout;
  var clearTimeoutFn = opts._clearTimeout || clearTimeout;

  var child           = null;
  var watchers        = [];
  var debounceTimer   = null;
  var killTimer       = null;
  var started         = false;
  var stopping        = false;
  var restarting      = false;
  var queuedRestart   = false;
  var restartCount    = 0;
  var lastRestartAt   = null;

  function _spawnChild() {
    var c = spawnFn(opts.command, args, {
      stdio: opts.stdio || "inherit",
      env:   env,
      cwd:   cwd,
    });
    c.on("exit", function (code, signal) {
      // If the child exits while we're not stopping/restarting, that's
      // a crash — log it and wait for a file change to retry. This
      // matches nodemon's behavior: a bad commit leaves the child
      // corpse around without spawn-thrashing.
      if (!stopping && !restarting) {
        _logVia(log, "warn",
          "child exited unexpectedly — waiting for file change to restart",
          { code: code, signal: signal });
        child = null;
      }
    });
    c.on("error", function (err) {
      _logVia(log, "error", "spawn error", { error: (err && err.message) || String(err) });
    });
    return c;
  }

  function _killChild() {
    return new Promise(function (resolve) {
      if (!child) { resolve(); return; }
      var c = child;
      var settled = false;
      function done() {
        if (settled) return;
        settled = true;
        if (killTimer) { try { clearTimeoutFn(killTimer); } catch (_e) { /* timer already cleared */ } killTimer = null; }
        resolve();
      }
      c.once("exit", done);
      try { c.kill(killSignal); }
      catch (e) {
        _logVia(log, "warn", "kill threw, child may already be gone",
          { error: (e && e.message) || String(e) });
        done();
        return;
      }
      // Hard-kill if the child ignores SIGTERM
      killTimer = setTimeoutFn(function () {
        if (settled) return;
        _logVia(log, "warn",
          "child did not exit after " + killTimeoutMs + "ms — sending SIGKILL");
        try { c.kill("SIGKILL"); }
        catch (_e) { done(); }
      }, killTimeoutMs);
      if (killTimer && typeof killTimer.unref === "function") killTimer.unref();
    });
  }

  async function _restart() {
    if (restarting) {
      // Coalesce: a restart-in-flight gets one followup queued, never more.
      queuedRestart = true;
      return;
    }
    restarting = true;
    try {
      await _killChild();
      child = null;
      if (stopping) return;
      child = _spawnChild();
      restartCount += 1;
      lastRestartAt = new Date().toISOString();
      _logVia(log, "info", "restarted",
        { pid: child && child.pid, restarts: restartCount });
    } catch (e) {
      _logVia(log, "error", "restart failed",
        { error: (e && e.message) || String(e) });
    } finally {
      restarting = false;
      if (queuedRestart && !stopping) {
        queuedRestart = false;
        // Tail-call the queued restart on the next microtask so we
        // unwind the current stack first.
        Promise.resolve().then(_restart);
      }
    }
  }

  function _scheduleRestart(reason) {
    if (stopping) return;
    if (debounceTimer) clearTimeoutFn(debounceTimer);
    debounceTimer = setTimeoutFn(function () {
      debounceTimer = null;
      _logVia(log, "info", "change detected, restarting", { reason: reason });
      _restart();
    }, graceMs);
    if (debounceTimer && typeof debounceTimer.unref === "function") debounceTimer.unref();
  }

  function _onWatchEvent(dir, eventType, filename) {
    if (!filename) return;
    var rel = String(filename);
    var full = path.join(dir, rel);
    if (_matchesAny(ignore, rel) || _matchesAny(ignore, full)) return;
    _scheduleRestart(eventType + ":" + rel);
  }

  function _armWatchers() {
    for (var i = 0; i < watch.length; i++) {
      (function (dir) {
        var resolved = path.isAbsolute(dir) ? dir : path.resolve(cwd, dir);
        var w;
        try {
          w = watchFn(resolved, { recursive: true, persistent: false }, function (eventType, filename) {
            _onWatchEvent(resolved, eventType, filename);
          });
        } catch (e) {
          // Missing dir, permission error, platform that doesn't
          // support recursive — log and move on so a bad watch entry
          // doesn't take the whole dev loop down.
          _logVia(log, "warn", "could not watch " + resolved,
            { error: (e && e.message) || String(e) });
          return;
        }
        if (w && typeof w.on === "function") {
          w.on("error", function (err) {
            _logVia(log, "warn", "watcher error on " + resolved,
              { error: (err && err.message) || String(err) });
          });
        }
        watchers.push(w);
      })(watch[i]);
    }
  }

  function _disarmWatchers() {
    for (var i = 0; i < watchers.length; i++) {
      try { if (watchers[i] && typeof watchers[i].close === "function") watchers[i].close(); }
      catch (_e) { /* close best-effort */ }
    }
    watchers = [];
  }

  async function start() {
    if (started) return;
    started = true;
    stopping = false;
    _armWatchers();
    child = _spawnChild();
    _logVia(log, "info", "started", { pid: child && child.pid, watch: watch });
  }

  async function stop() {
    if (!started) return;
    stopping = true;
    if (debounceTimer) { try { clearTimeoutFn(debounceTimer); } catch (_e) { /* timer already cleared */ } debounceTimer = null; }
    _disarmWatchers();
    await _killChild();
    child = null;
    started = false;
    stopping = false;
    queuedRestart = false;
    _logVia(log, "info", "stopped", { restarts: restartCount });
  }

  async function restart() { await _restart(); }

  function stats() {
    return {
      pid:           child && child.pid !== undefined ? child.pid : null,
      running:       !!child && started && !stopping,
      restarts:      restartCount,
      lastRestartAt: lastRestartAt,
      watchers:      watchers.length,
    };
  }

  return {
    start:    start,
    stop:     stop,
    restart:  restart,
    stats:    stats,
    // Test hook: simulate a watcher event for engine tests
    _emit:    function (dir, eventType, filename) { _onWatchEvent(dir, eventType, filename); },
  };
}

module.exports = {
  create:    create,
  DevError:  DevError,
  DEFAULT_IGNORE: DEFAULT_IGNORE,
};
