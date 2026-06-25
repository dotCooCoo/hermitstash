"use strict";
/**
 * @module b.log
 * @featured true
 * @nav    Observability
 * @title  Log
 *
 * @intro
 *   Structured JSON application logger meant to be ingested by a log
 *   aggregator. Each emitted line is a single JSON object terminated
 *   with `\n`; the log level is encoded as the string field `level`,
 *   not as console color. Distinct from `b.log.boot` — that path is
 *   framework-internal startup chatter to the TTY (humans watching
 *   `npm start`); `create()` is what apps wire into their request
 *   lifecycle.
 *
 *   Levels: debug (0) < info (1) < warn (2) < error (3) < fatal (4).
 *   Default routing: debug / info / warn → stdout; error / fatal →
 *   stderr. Multi-sink config (`sinks: [...]`) takes full control of
 *   routing — each sink gets every line at-or-above its own per-sink
 *   level, useful when the operator wants debug to a file but warn+
 *   to stderr.
 *
 *   Redact-aware: `extras` passed to `.info(msg, extras)` flow through
 *   `b.redact` by default, so password / token / cardNumber-shaped
 *   keys never reach the log line. Operators opt out with
 *   `redact: false` only when the logger sits behind a downstream
 *   redactor.
 *
 *   Request correlation rides on Node's AsyncLocalStorage. The
 *   middleware allocates a `requestId` (or honors an inbound
 *   `X-Request-Id` header) and binds it for the entire async chain;
 *   every `log.info` inside the request automatically picks up the
 *   id without the caller threading it explicitly. OpenTelemetry
 *   trace correlation rides the same channel — `runWithContext`
 *   merges arbitrary fields (tenantId, traceId) into the bound store.
 *
 *   Child loggers via `log.bind({ component: "auth" })` carry the
 *   bound fields into every emitted line; chains compose, so an
 *   auth-handler logger can bind its own `userId` on top.
 *
 *   Field merge order (last wins): base context → bound chain → ALS
 *   store → caller's extras → core fields (timestamp / level /
 *   message). Extras that try to clobber a core field are dropped
 *   and the line carries `_overwriteAttempt: true` so misconfig is
 *   visible.
 *
 *   Trojan-Source defense (CVE-2021-42574) is baked in: Unicode
 *   bidi / format controls in messages are escaped to `\uXXXX`
 *   literals before they reach the wire so a hostile message can't
 *   re-order the visible line in a TTY / syslog reader.
 *
 * @card
 *   Structured JSON application logger meant to be ingested by a log aggregator.
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
var bCrypto = lazyRequire(function () { return require("./crypto"); });

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
    if (!Object.prototype.hasOwnProperty.call(LEVELS, level)) {
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

/**
 * @primitive b.log.create
 * @signature b.log.create(opts)
 * @since     0.1.70
 * @status    stable
 * @related   b.log.boot, b.log.makeViaOrFallback, b.redact.redact
 *
 * Build a structured JSON logger instance. Returns an object with
 * `.debug` / `.info` / `.warn` / `.error` / `.fatal` emitters, plus
 * `.bind(extra)` for child loggers, `.middleware()` for router-side
 * request-id binding, `.runWithRequestId(id, fn)` /
 * `.runWithContext(ctx, fn)` for ad-hoc AsyncLocalStorage scopes,
 * and `.setLevel` / `.getLevel` / `.isLevelEnabled` for runtime
 * level control. Level resolution is `LOG_LEVEL` env > `opts.level`
 * > `"info"`.
 *
 * @opts
 *   level:            "info",                      // string or 0-4
 *   base:             { service: "myapp" },        // merged into every line
 *   redact:           true,                        // run extras through b.redact
 *   sinks: [
 *     { stream: process.stdout, level: "info" },
 *     { stream: fs.createWriteStream("./errors.log"), level: "error" },
 *   ],
 *   destination:      process.stdout,              // legacy single-sink
 *   errorDestination: process.stderr,              // legacy two-sink split
 *   format:           "json",
 *   clock:            function () { return new Date(); }, // test seam
 *
 * @example
 *   var log = b.log.create({
 *     level: "info",
 *     base:  { service: "myapp", version: "1.2.3" },
 *   });
 *   log.info("user logged in", { userId: "u-1" });
 *   var authLog = log.bind({ component: "auth" });
 *   authLog.warn("rate-limited", { ip: "203.0.113.7" });
 *   // → {"timestamp":"...","level":"info","message":"user logged in",
 *   //    "service":"myapp","version":"1.2.3","userId":"u-1"}
 */
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
    function enterRequestId(id) {
      _als.enterWith({ requestId: id || null, _extra: {} });
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
      // Read and write the SAME header. The raw form keeps the operator's
      // casing (or the canonical "X-Request-Id" default) for the response;
      // the lowercased form matches Node's request-header keys for the read.
      var rawHeaderName = (typeof mwOpts.headerName === "string" && mwOpts.headerName.length > 0)
        ? mwOpts.headerName : "X-Request-Id";
      var headerName = rawHeaderName.toLowerCase();
      var setOnRes   = mwOpts.setHeader !== false;
      var generate   = typeof mwOpts.generate === "function"
        ? mwOpts.generate
        : function () {
          // 16 random hex chars — short, sufficient correlation entropy.
          // Routes through the framework token primitive so the entropy
          // source matches the rest of the codebase.
          return bCrypto().generateToken(REQUEST_ID_BYTES);
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
          try { res.setHeader(rawHeaderName, id); } catch (_e) { /* header may be locked */ }
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
      enterRequestId:   enterRequestId,
      runWithContext:   runWithContext,
      getRequestId:     getRequestId,
      middleware:       middleware,
    };
  }

  return _makeInstance([]);
}

/**
 * @primitive b.log.boot
 * @signature b.log.boot(name)
 * @since     0.7.0
 * @status    stable
 * @related   b.log.create, b.log.makeViaOrFallback
 *
 * Framework-internal boot logger for human-readable startup chatter
 * (`[blamejs:db] ready`, `[blamejs:vault] WARNING: ...`). TTY-aware:
 * when stdout is a terminal it emits a prefixed line; when stdout is
 * piped it emits a one-line JSON object so log aggregators can ingest
 * boot chatter as structured records. The returned value is a
 * callable (info path) plus `.debug` / `.info` / `.warn` / `.error` /
 * `.prefix` members so `log("ready")` and `log.warn("...")` both
 * work.
 *
 * @example
 *   var log = b.log.boot("db");
 *   log("ready");
 *   log.warn("connection slow");
 *   // → "[blamejs:db] ready"   (TTY)
 *   // → {"timestamp":"...","level":"info","message":"ready",
 *   //    "component":"db","boot":true}  (piped)
 */
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
      // Raw human-readable line — escape BOTH the C0/newline (line-forging)
      // and bidi (re-ordering) control classes the create() path neutralizes,
      // so a hostile boot message can't inject lines or re-order the visible
      // line on a TTY / syslog reader (CWE-117 / Trojan-Source CVE-2021-42574).
      sink(_escapeBidiControls(_escapeC0Controls(prefix + String(msg))));
      return;
    }
    var entry = {
      timestamp: new Date().toISOString(),
      level:     levelName,
      message:   String(msg),
      component: name,
      boot:      true,
    };
    // JSON.stringify already escapes C0/newlines; bidi/format controls survive
    // raw into a piped aggregator, so apply the same bidi escape create() uses.
    sink(_escapeBidiControls(JSON.stringify(entry)));
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

/**
 * @primitive b.log.makeViaOrFallback
 * @signature b.log.makeViaOrFallback(operatorLog, fallbackLog)
 * @since     0.7.30
 * @status    stable
 * @related   b.log.create, b.log.boot
 *
 * Closure factory for operator-log routing. Used by primitives
 * (bundler, dev server, error-page renderer, pqc-gate, ...) that
 * accept `opts.log` but must keep emitting through a per-module
 * fallback when the operator didn't pass one. The operator log call
 * is best-effort — a misbehaving `log[level]` is swallowed rather
 * than crashing the caller. Fallback fires only when the operator
 * log is absent or doesn't expose the requested level.
 *
 * @example
 *   var fallback = b.log.boot("bundler");
 *   var via = b.log.makeViaOrFallback(null, fallback);
 *   via("error", "build-failed", { reason: "missing entrypoint" });
 *   // → "[blamejs:bundler] build-failed {\"reason\":\"missing entrypoint\"}"
 */
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
    var code = ch.charCodeAt(0).toString(16);                                      // Unicode hex radix
    while (code.length < 4) code = "0" + code;
    return "\\u" + code;
  });
}

// C0 control chars (incl. CR / LF / TAB) + DEL — escaped to `\uXXXX` so a
// hostile message can't forge extra log lines on a raw (non-JSON) TTY sink
// (log-injection, CWE-117). The create() path gets this for free from
// JSON.stringify; the boot() TTY branch writes raw text and needs it
// explicitly. Pairs with _escapeBidiControls (which only covers the bidi set).
var _C0_CONTROL_RE = /[\u0000-\u001f\u007f]/g;   // eslint-disable-line no-control-regex -- the C0/DEL set is what we escape

function _escapeC0Controls(s) {
  if (typeof s !== "string" || s.length === 0) return s;
  return s.replace(_C0_CONTROL_RE, function (ch) {
    var code = ch.charCodeAt(0).toString(16);
    while (code.length < 4) code = "0" + code;
    return "\\u" + code;
  });
}

// runs before safeEnv on the boot path; safeEnv requires log, so log
// can't go through safeEnv to read its own level.
function _bootMinLevel() {
  // allow:raw-process-env — see header comment above
  var raw = process.env.BLAMEJS_BOOT_LOG_LEVEL || process.env.LOG_LEVEL || "info";
  return Object.prototype.hasOwnProperty.call(LEVELS, raw) ? LEVELS[raw] : LEVELS.info;
}

/**
 * @primitive b.log.getRequestId
 * @signature b.log.getRequestId()
 * @since     0.1.70
 * @status    stable
 * @related   b.log.runWithRequestId, b.log.create
 *
 * Read the current AsyncLocalStorage-bound request id, or `null`
 * when called outside a `runWithRequestId` / middleware-wrapped
 * scope. The module-level helper exists for code paths that don't
 * have a logger instance handy but still need to read the
 * request-correlation token (e.g. an external SDK callback that
 * must include the id in a remote span).
 *
 * @example
 *   await b.log.runWithRequestId("req-abc", async function () {
 *     var id = b.log.getRequestId();
 *     // → "req-abc"
 *   });
 */
function getRequestId() {
  var s = _getStore();
  return s ? s.requestId : null;
}

/**
 * @primitive b.log.runWithRequestId
 * @signature b.log.runWithRequestId(id, fn)
 * @since     0.1.70
 * @status    stable
 * @related   b.log.getRequestId, b.log.create
 *
 * Run `fn` inside an AsyncLocalStorage scope where
 * `b.log.getRequestId()` returns `id`. Every `b.log.create`-built
 * logger inside the scope automatically picks up the id on each
 * emitted line. Returns whatever `fn` returns (including a Promise);
 * the binding propagates through `await` boundaries via Node's
 * async-context plumbing.
 *
 * @example
 *   var result = await b.log.runWithRequestId("req-abc", async function () {
 *     return b.log.getRequestId();
 *   });
 *   // → "req-abc"
 */
function runWithRequestId(id, fn) {
  return _als.run({ requestId: id || null, _extra: {} }, fn);
}

/**
 * @primitive b.log.enterRequestId
 * @signature b.log.enterRequestId(id)
 * @since     0.15.21
 * @status    stable
 * @related   b.log.runWithRequestId, b.log.getRequestId
 *
 * Bind `id` into the AsyncLocalStorage scope for the REMAINDER of the
 * current async execution — without nesting a callback. Where
 * `runWithRequestId(id, fn)` wraps a function (and the binding closes when
 * `fn` returns), this uses `AsyncLocalStorage.enterWith` so the id survives a
 * dispatch model that hands control back to its caller before the awaited
 * work runs — a boolean-`next` middleware chain (`b.router`), where the route
 * handler executes after the middleware returns. Call it once per request,
 * inside the per-request async context, so each request stays isolated. The
 * companion to `b.middleware.requestId({ asyncContext: true })`, which calls
 * it for you.
 *
 * @example
 *   // inside a per-request middleware, before next():
 *   b.log.enterRequestId(req.requestId);
 *   // any awaited handler downstream now sees b.log.getRequestId() === req.requestId
 */
function enterRequestId(id) {
  _als.enterWith({ requestId: id || null, _extra: {} });
}

module.exports = {
  create:            create,
  boot:              boot,
  makeViaOrFallback: makeViaOrFallback,
  LEVELS:            LEVELS,
  LogError:          LogError,
  // Module-level helpers for code paths that don't have a logger
  // instance handy but still need to read ALS state.
  getRequestId:      getRequestId,
  runWithRequestId:  runWithRequestId,
  enterRequestId:    enterRequestId,
};
