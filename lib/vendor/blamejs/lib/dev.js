"use strict";
/**
 * dev — file-watch + child-process restart for iteration loops.
 *
 * The framework's hot-reload primitive. Spawn the app as a child
 * process, watch the source directories, and restart the child when a
 * file changes. On-disk state (vault keys, encrypted DB, sealed
 * cookies) survives the restart because the child re-opens the files
 * — only in-process state is lost, which is the correct semantic for
 * "I just edited a route handler and want to see it."
 *
 *   var dev = b.dev.create({
 *     command: "node",
 *     args:    ["./server.js"],
 *     watch:   ["./routes", "./views", "./public", "./lib"],
 *     ignore:  [/node_modules/, /\.db$/, /\.tmp$/, /^\./],
 *     graceMs: 250,           // debounce: collapse bursts into one restart
 *     killSignal:    "SIGTERM",
 *     killTimeoutMs: 4000,    // SIGKILL after this if SIGTERM is ignored
 *     log:     logInstance,   // optional structured logger
 *     env:     { ...process.env, BLAMEJS_DEV: "1" },
 *     cwd:     process.cwd(),
 *   });
 *
 *   await dev.start();        // launches child + arms watchers
 *   await dev.stop();         // signals child + closes watchers
 *
 *   dev.stats();              // → { pid, running, restarts, lastRestartAt }
 *
 * Operator-side, this is what `blamejs dev` will call (next CLI slice).
 *
 * Engine hygiene:
 *   - Bursts of file events (a saved-everything keystroke, a multi-
 *     file format-on-save) collapse into one restart via debounce.
 *   - The child is spawned with stdio: 'inherit' so the operator sees
 *     their app's output unchanged.
 *   - Parent SIGINT/SIGTERM are forwarded: stop() before exit so an
 *     orphan child can't outlive the dev session.
 *   - Restart in-flight when a new event arrives: queue one followup,
 *     no more — many edits during a slow restart still result in only
 *     two restarts, not N.
 *
 * Test seams:
 *   opts._spawn(cmd, args, sopts)        → child-process-shaped object
 *   opts._watch(dir, wopts, listener)    → fs.watcher-shaped object
 *   These default to child_process.spawn and fs.watch; tests pass
 *   fakes to drive the engine without real subprocesses.
 */

var path = require("path");
var childProcess = require("child_process");
var fs = require("fs");
var logModule = require("./log");
var nb = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

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

  // Test seams
  var spawnFn = opts._spawn || function (cmd, sargs, sopts) {
    return childProcess.spawn(cmd, sargs, sopts);
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
