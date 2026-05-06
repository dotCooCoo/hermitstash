"use strict";
/**
 * log — structured JSON application logger with request-id correlation.
 *
 * Distinct concern from lib/logger.js: logger.js is the framework's
 * own boot/operational chatter to console with `[blamejs:<name>] `
 * prefix (humans watching `npm start`). lib/log.js is the app-level
 * structured logger meant to be ingested by a log aggregator.
 *
 * Each line is one JSON object on a single line, terminated with `\n`.
 * Levels: debug (0) < info (1) < warn (2) < error (3) < fatal (4).
 * Default routing: debug / info / warn → stdout; error / fatal → stderr.
 * Multi-sink config (`sinks: [...]`) takes full control of routing.
 *
 *   var log = b.log.create({
 *     level:   "info",            // env LOG_LEVEL > opts.level > "info"
 *     base:    { service: "myapp", version: "1.2.3" },
 *     redact:  true,              // run extras through lib/redact
 *   });
 *
 *   // Multi-sink: each sink gets every line at-or-above its own level.
 *   // Default (no `sinks` opt) splits info-and-below to stdout and
 *   // warn-and-up to stderr — same as before.
 *   var log = b.log.create({
 *     level: "debug",
 *     sinks: [
 *       { stream: process.stdout,                              level: "info"  },
 *       { stream: fs.createWriteStream("./logs/debug.log"),    level: "debug" },
 *       { stream: fs.createWriteStream("./logs/errors.log"),   level: "error" },
 *     ],
 *   });
 *   // sinks: [...] is mutually exclusive with destination/errorDestination.
 *
 *   log.info("user logged in", { userId: "u-1" });
 *   log.error("payment failed", { orderId, err: e.message });
 *
 *   // Child with bound context
 *   var authLog = log.bind({ component: "auth" });
 *   authLog.info("password verified", { userId: "u-1" });
 *
 *   // Request correlation via AsyncLocalStorage (Node async context)
 *   await log.runWithRequestId("req-abc", async function () {
 *     log.info("inside request");   // → ..., "requestId": "req-abc"
 *   });
 *
 *   // Router middleware that allocates a requestId and binds it for
 *   // the entire request async chain
 *   r.use(log.middleware());
 *
 * Field merge order (last wins):
 *   1. base context from create()
 *   2. bound context from bind() (each ancestor up the chain)
 *   3. requestId from ALS (if set)
 *   4. extra arg from .info(msg, extra)
 *   5. core fields: timestamp, level, message
 *
 * Core fields cannot be overwritten by extras — log.info("hi", { level: "X" })
 * keeps level: "info" in the emitted line, with an _overwriteAttempt
 * flag if the operator tried to clobber.
 */

var { AsyncLocalStorage } = require("node:async_hooks");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var redact = require("./redact");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

// Lazy resolves to break load-order cycles:
//   - parsers/safe-env requires log (boot logger for env-read errors).
//     log can't require safe-env at top because safe-env's top-level
//     `var log = boot("env")` would see log's exports half-built.
//   - crypto requires constants + framework-error + vendor; it does NOT
//     require log, so a top-of-file require would technically work, but
//     keeping crypto lazy keeps log loadable from anywhere without
//     pulling the whole crypto bundle into the framework's earliest
//     boot path (request-id middleware needs only generateToken).
var safeEnv = lazyRequire(function () { return require("./parsers/safe-env"); });
var crypto  = lazyRequire(function () { return require("./crypto"); });

// Request-id correlation token — 8 bytes hex-encoded (16 chars). Short
// enough to read in a log line, long enough to keep collisions far below
// audible-noise even at 1M req/s sustained. Routed through C.BYTES so
// the file's byte arithmetic has a single source of truth.
var REQUEST_ID_BYTES = C.BYTES.bytes(8);

var LEVELS = { debug: 0, info: 1, warn: 2, error: 3, fatal: 4 };
var LEVEL_NAMES = Object.keys(LEVELS);

class LogError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "LogError";
    this.permanent = true;
    this.isLogError = true;
  }
}

// Single ALS shared across all log instances so request-id propagates
// regardless of which instance emitted the line. Keyed map so
// operators can attach more than just requestId (e.g. tenantId).
var _als = new AsyncLocalStorage();

function _getStore() { return _als.getStore() || null; }

function _normalizeDestination(d, fallback) {
  if (d === "stdout") return process.stdout;
  if (d === "stderr") return process.stderr;
  if (d && typeof d.write === "function") return d;
  if (typeof d === "function") return { write: d };
  if (d === undefined || d === null) return fallback;
  throw new LogError("log/bad-destination",
    "destination must be 'stdout', 'stderr', a stream with .write, or a function");
}

function _normalizeLevel(level) {
  if (typeof level === "number") {
    if (level < 0 || level > 4 || !Number.isFinite(level)) {
      throw new LogError("log/bad-level", "numeric level must be 0-4");
    }
    return level;
  }
  if (typeof level === "string") {
    if (LEVELS[level] === undefined) {
      throw new LogError("log/bad-level",
        "level must be one of " + LEVEL_NAMES.join(", "));
    }
    return LEVELS[level];
  }
  throw new LogError("log/bad-level", "level must be a string or number");
}

var _CORE_FIELDS = ["timestamp", "level", "message", "requestId"];

function _mergeExtras(into, extras, redactExtras) {
  if (!extras || typeof extras !== "object") return false;
  var src = redactExtras ? redact.redact(extras) : extras;
  var keys = Object.keys(src);
  var clobberAttempt = false;
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (_CORE_FIELDS.indexOf(k) !== -1) {
      // Operator tried to overwrite a core field — preserve the core
      // value but flag it so misconfig surfaces in the line.
      clobberAttempt = true;
      continue;
    }
    into[k] = src[k];
  }
  return clobberAttempt;
}

function _resolveSinks(opts) {
  // Three input shapes — pick exactly one:
  //   (a) opts.sinks: [{ stream, level }, ...]
  //   (b) opts.destination + opts.errorDestination (legacy two-sink split)
  //   (c) neither — defaults to stdout for info-and-below, stderr for warn-and-up
  if (Array.isArray(opts.sinks)) {
    if (opts.destination !== undefined || opts.errorDestination !== undefined) {
      throw new LogError("log/conflicting-sinks",
        "log.create: pass either { sinks: [...] } OR { destination, errorDestination }, not both");
    }
    if (opts.sinks.length === 0) {
      throw new LogError("log/no-sinks",
        "log.create: sinks: [] would silently drop every line — pass at least one sink");
    }
    return opts.sinks.map(function (s, i) {
      if (!s || typeof s !== "object") {
        throw new LogError("log/bad-sink", "sinks[" + i + "]: expected object with { stream, level? }");
      }
      var allowed = ["stream", "level"];
      var keys = Object.keys(s);
      for (var j = 0; j < keys.length; j++) {
        if (allowed.indexOf(keys[j]) === -1) {
          throw new LogError("log/bad-sink",
            "sinks[" + i + "]: unknown key '" + keys[j] + "' (allowed: " + allowed.join(", ") + ")");
        }
      }
      var stream = _normalizeDestination(s.stream, null);
      if (!stream) {
        throw new LogError("log/bad-sink", "sinks[" + i + "]: stream is required");
      }
      // Per-sink level: missing → no filter beyond the global; present → must be valid.
      var minLevel = (s.level === undefined) ? null : _normalizeLevel(s.level);
      return { stream: stream, minLevel: minLevel };
    });
  }
  // Legacy / default — synthesize the two-sink split.
  var stdoutDest = _normalizeDestination(opts.destination, process.stdout);
  var stderrDest = _normalizeDestination(opts.errorDestination, process.stderr);
  return [
    // Order matters for emit fan-out: stdout sink catches debug-info-warn;
    // stderr catches error-and-up. Existing behavior — same boundary.
    { stream: stdoutDest, minLevel: null, _maxLevelExclusive: LEVELS.error },
    { stream: stderrDest, minLevel: LEVELS.error },
  ];
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "level", "destination", "errorDestination", "sinks",
    "format", "redact", "base", "clock",
  ], "b.log");

  // Resolve initial level: env > opts > default
  // safeEnv enforces the size cap + missing/empty handling; LEVELS lookup
  // gates an unrecognised value (silently falls through to opts/default
  // rather than throwing — bad LOG_LEVEL on the env should not crash boot).
  var envLevel = safeEnv().readVar("LOG_LEVEL");
  var level;
  if (envLevel && LEVELS[envLevel] !== undefined) {
    level = LEVELS[envLevel];
  } else if (opts.level !== undefined) {
    level = _normalizeLevel(opts.level);
  } else {
    level = LEVELS.info;
  }

  var sinks = _resolveSinks(opts);

  var format    = opts.format || "json"; // reserved for future formats
  if (format !== "json") {
    throw new LogError("log/bad-format",
      "only 'json' format is supported (got '" + format + "')");
  }
  var redactOn  = opts.redact !== false;
  var base      = opts.base ? Object.assign({}, opts.base) : {};

  // Clock injection lets tests pin timestamps deterministically.
  var clock = typeof opts.clock === "function" ? opts.clock : function () { return new Date(); };

  function _emit(levelName, message, extras, boundChain) {
    if (LEVELS[levelName] < level) return;

    var entry = {};
    entry.timestamp = clock().toISOString();
    entry.level     = levelName;
    entry.message   = typeof message === "string" ? message : String(message);

    // Merge base, then each ancestor's bound context (root → leaf)
    Object.assign(entry, base);
    if (boundChain) {
      for (var i = 0; i < boundChain.length; i++) Object.assign(entry, boundChain[i]);
    }

    // Request id from ALS — overrides only if not already set by base/bound
    var store = _getStore();
    if (store && store.requestId && entry.requestId === undefined) {
      entry.requestId = store.requestId;
    }
    // Merge any other ALS-bound fields (operator may have set tenantId etc.)
    if (store && store._extra) {
      var ekeys = Object.keys(store._extra);
      for (var j = 0; j < ekeys.length; j++) {
        var ek = ekeys[j];
        if (entry[ek] === undefined) entry[ek] = store._extra[ek];
      }
    }

    // Re-stamp core fields — entries from base/bound context cannot
    // overwrite timestamp/level/message
    entry.timestamp = clock().toISOString();
    entry.level     = levelName;
    entry.message   = typeof message === "string" ? message : String(message);

    var clobbered = _mergeExtras(entry, extras, redactOn);
    if (clobbered) entry._overwriteAttempt = true;

    var line;
    try { line = JSON.stringify(entry) + "\n"; }
    catch (_e) {
      // Circular ref or non-serializable extra — emit a fallback line.
      line = JSON.stringify({
        timestamp: entry.timestamp,
        level:     levelName,
        message:   entry.message,
        _logError: "extras not serializable",
      }) + "\n";
    }
    // Trojan-Source defense (CVE-2021-42574). JSON.stringify does NOT
    // escape Unicode bidi / format controls, so a hostile log message
    // containing U+202E (RIGHT-TO-LEFT OVERRIDE) survives into TTY /
    // syslog / file sinks where it can re-order the visible line —
    // forging which fields appear under which keys when the operator
    // reads the log. Escape the entire bidi/format-control set to
    // `\uXXXX` literals on the wire.
    line = _escapeBidiControls(line);

    var lvlNum = LEVELS[levelName];
    for (var s = 0; s < sinks.length; s++) {
      var sink = sinks[s];
      if (sink.minLevel !== null && lvlNum < sink.minLevel) continue;
      // Legacy default-sinks split uses an exclusive upper bound so the
      // stdout sink catches only info-and-below (warn+ goes to stderr).
      if (sink._maxLevelExclusive !== undefined && lvlNum >= sink._maxLevelExclusive) continue;
      try { sink.stream.write(line); }
      catch (_e) { /* sink write best-effort — never throw out of a log call */ }
    }
  }

  function _makeInstance(boundChain) {
    function child(extra) {
      if (!extra || typeof extra !== "object") {
        throw new LogError("log/bad-bind", "bind(extra) requires an object");
      }
      // Preserve frozen ancestor chain; append a copy so callers can
      // mutate their original without affecting the bound logger.
      var nextChain = boundChain.concat([Object.assign({}, extra)]);
      return _makeInstance(nextChain);
    }

    function level_in(name)  { return LEVELS[name] !== undefined && LEVELS[name] >= level; }
    function setLevel(l)     { level = _normalizeLevel(l); }
    function getLevel()      { return LEVEL_NAMES[level]; }

    function debug(msg, extra) { _emit("debug", msg, extra, boundChain); }
    function info(msg, extra)  { _emit("info",  msg, extra, boundChain); }
    function warn(msg, extra)  { _emit("warn",  msg, extra, boundChain); }
    function error(msg, extra) { _emit("error", msg, extra, boundChain); }
    function fatal(msg, extra) { _emit("fatal", msg, extra, boundChain); }

    function runWithRequestId(id, fn) {
      var store = { requestId: id || null, _extra: {} };
      return _als.run(store, fn);
    }
    function runWithContext(ctx, fn) {
      var existing = _getStore();
      var rid = (ctx && ctx.requestId) || (existing && existing.requestId) || null;
      var extra = Object.assign({},
        existing && existing._extra ? existing._extra : {},
        ctx || {});
      delete extra.requestId;
      return _als.run({ requestId: rid, _extra: extra }, fn);
    }
    function getRequestId() {
      var s = _getStore();
      return s ? s.requestId : null;
    }

    function middleware(mwOpts) {
      mwOpts = mwOpts || {};
      var headerName = (mwOpts.headerName || "x-request-id").toLowerCase();
      var setOnRes   = mwOpts.setHeader !== false;
      var generate   = typeof mwOpts.generate === "function"
        ? mwOpts.generate
        : function () {
          // 16 random hex chars — short, sufficient correlation entropy.
          // Routes through the framework token primitive so the entropy
          // source matches the rest of the codebase.
          return crypto().generateToken(REQUEST_ID_BYTES);
        };
      return function logRequestIdMiddleware(req, res, next) {
        var inbound = req.headers && req.headers[headerName];
        var id = (typeof inbound === "string" && inbound.length > 0 && inbound.length <= 200)
          ? inbound
          : generate();
        // Strip CRLF defensively before reflecting back into a header
        id = safeBuffer.stripCrlf(String(id));
        req.id = id;
        if (setOnRes && typeof res.setHeader === "function") {
          try { res.setHeader("X-Request-Id", id); } catch (_e) { /* header may be locked */ }
        }
        runWithRequestId(id, function () { next(); });
      };
    }

    return {
      debug:            debug,
      info:             info,
      warn:             warn,
      error:            error,
      fatal:            fatal,
      bind:             child,
      setLevel:         setLevel,
      getLevel:         getLevel,
      isLevelEnabled:   level_in,
      runWithRequestId: runWithRequestId,
      runWithContext:   runWithContext,
      getRequestId:     getRequestId,
      middleware:       middleware,
    };
  }

  return _makeInstance([]);
}

// ---- Boot logger ----
//
// Framework-internal modules emit human-readable startup chatter
// during boot ("[blamejs:db] ready", "[blamejs:vault] WARNING: …"),
// distinct from the structured app-level logger above. The boot
// channel is TTY-aware:
//
//   - stdout is a TTY     → "[blamejs:<name>] <message>" line
//   - stdout is piped     → JSON line { timestamp, level, message,
//                                       component: <name>, boot: true }
//
// This keeps `npm start` readable for humans while letting log
// aggregators ingest boot chatter as structured records.
//
// Returned object is a callable (info path) plus .info / .warn /
// .error / .prefix members so calls like `log("ready")` and
// `log.warn("…")` both work.
function boot(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw new LogError("log/bad-name", "log.boot(name) requires a non-empty name");
  }
  var prefix = "[blamejs:" + name + "] ";

  function _emit(levelName, msg) {
    // Route through console.{log,error} (not process.{stdout,stderr}.write)
    // so test runners that capture console output behave as operators
    // expect — same rationale as the original lib/logger.js.
    var sink = (LEVELS[levelName] >= LEVELS.warn) ? console.error : console.log;
    var stream = (LEVELS[levelName] >= LEVELS.warn) ? process.stderr : process.stdout;
    var isTty = !!(stream && stream.isTTY);
    if (isTty) {
      sink(prefix + String(msg));
      return;
    }
    var entry = {
      timestamp: new Date().toISOString(),
      level:     levelName,
      message:   String(msg),
      component: name,
      boot:      true,
    };
    sink(JSON.stringify(entry));
  }

  function debug(msg, fields) {
    // Boot-time debug entries route through console.log unless LOG_LEVEL
    // suppresses them. fields (when present) get JSON-appended so
    // operators see the structured context.
    if (LEVELS.debug < _bootMinLevel()) return;
    var rendered = msg;
    if (fields !== undefined) {
      try { rendered = msg + " " + JSON.stringify(fields); }
      catch (_e) { rendered = msg; }
    }
    _emit("debug", rendered);
  }
  function info(msg)  { _emit("info",  msg); }
  function warn(msg)  { _emit("warn",  msg); }
  function error(msg) { _emit("error", msg); }

  // The returned function is the info path so `log(msg)` matches the
  // existing call shape across the codebase.
  info.debug = debug;
  info.info  = info;
  info.warn  = warn;
  info.error = error;
  info.prefix = prefix;
  return info;
}

// makeViaOrFallback — closure factory for operator-log routing. Used by
// bundler / dev / error-page / pqc-gate (and similar primitives) that
// accept opts.log but must keep emitting through a per-module fallback
// when the operator didn't pass one. Replaces the per-file
// `function _logVia(log, level, message, fields) { if (log && typeof
// log[level] === "function") { try { log[level](message, fields); }
// catch ... } return; } ... fallback;` boilerplate.
//
//   var _logVia = log.makeViaOrFallback(opts.log, log.boot("bundler"));
//   _logVia("error", "build-failed", { reason: "..." });
//
// The operator log call is best-effort: a misbehaving log[level] swallows
// internally rather than crash the caller. Fallback is invoked only when
// the operator log is absent or doesn't expose the requested level.
function makeViaOrFallback(operatorLog, fallbackLog) {
  return function (level, message, fields) {
    if (operatorLog && typeof operatorLog[level] === "function") {
      try { operatorLog[level](message, fields); }
      catch (_e) { /* operator log best-effort */ }
      return;
    }
    var line = message + (fields ? " " + JSON.stringify(fields) : "");
    var fb = (level === "error" || level === "fatal") ? fallbackLog.error
           : (level === "warn") ? fallbackLog.warn
           : fallbackLog.info;
    if (typeof fb === "function") fb(line);
  };
}

// Boot-time minimum level (debug suppressed unless explicitly enabled).
// Uses raw process.env per the documented load-cycle exception: log.js
// Trojan-Source defense (CVE-2021-42574). Replace Unicode bidi /
// format-control characters with their `\uXXXX` literal escape so a
// hostile log message can't re-order the visible line in a TTY /
// syslog reader. Set covers:
//   U+061C — Arabic Letter Mark
//   U+200E/U+200F — LRM/RLM
//   U+202A-U+202E — LRE/RLE/PDF/LRO/RLO
//   U+2066-U+2069 — LRI/RLI/FSI/PDI
var _BIDI_CONTROL_RE = /[؜‎‏‪‫‬‭‮⁦⁧⁨⁩]/g;

function _escapeBidiControls(s) {
  if (typeof s !== "string" || s.length === 0) return s;
  return s.replace(_BIDI_CONTROL_RE, function (ch) {
    var code = ch.charCodeAt(0).toString(16);                                      // allow:raw-byte-literal — Unicode hex radix
    while (code.length < 4) code = "0" + code;
    return "\\u" + code;
  });
}

// runs before safeEnv on the boot path; safeEnv requires log, so log
// can't go through safeEnv to read its own level.
function _bootMinLevel() {
  // allow:raw-process-env — see header comment above
  var raw = process.env.BLAMEJS_BOOT_LOG_LEVEL || process.env.LOG_LEVEL || "info";
  return LEVELS[raw] != null ? LEVELS[raw] : LEVELS.info;
}

module.exports = {
  create:           create,
  boot:             boot,
  makeViaOrFallback: makeViaOrFallback,
  LEVELS:           LEVELS,
  LogError:         LogError,
  // Module-level helpers for code paths that don't have a logger
  // instance handy but still need to read ALS state.
  getRequestId:     function () { var s = _getStore(); return s ? s.requestId : null; },
  runWithRequestId: function (id, fn) { return _als.run({ requestId: id || null, _extra: {} }, fn); },
};
