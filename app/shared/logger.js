/**
 * Structured JSON logger.
 *
 * Levels: debug < info < warn < error < fatal
 * Output: JSON lines to stdout (debug/info/warn) or stderr (error/fatal).
 * Request correlation via AsyncLocalStorage — request-id middleware enters a
 * storage context for each request, and every log line written during that
 * async chain picks up the requestId automatically. Previously used a
 * module-global, which was overwritten whenever concurrent requests ran
 * through the middleware, producing wrong correlation IDs under load.
 *
 * Respects LOG_LEVEL env var (default: "info").
 */

var { AsyncLocalStorage } = require("node:async_hooks");

var LEVELS = { debug: 0, info: 1, warn: 2, error: 3, fatal: 4 };
var _minLevel = LEVELS[process.env.LOG_LEVEL] !== undefined ? LEVELS[process.env.LOG_LEVEL] : LEVELS.info;

var _als = new AsyncLocalStorage();

/**
 * Run a function with a given requestId bound to the async context.
 * All logger calls during fn (and in any awaited continuations) will
 * include requestId automatically.
 */
function runWithRequestId(id, fn) {
  return _als.run({ requestId: id || null }, fn);
}

/**
 * Read the requestId bound to the current async context, or null.
 */
function getRequestId() {
  var store = _als.getStore();
  return store ? store.requestId : null;
}

function write(level, message, extra) {
  if (LEVELS[level] === undefined || LEVELS[level] < _minLevel) return;

  var entry = {
    timestamp: new Date().toISOString(),
    level: level,
    message: message,
  };

  var rid = getRequestId();
  if (rid) entry.requestId = rid;

  // Merge extra data — flatten one level for readability
  if (extra && typeof extra === "object") {
    var keys = Object.keys(extra);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      // Don't overwrite core fields
      if (k !== "timestamp" && k !== "level" && k !== "message" && k !== "requestId") {
        entry[k] = extra[k];
      }
    }
  }

  var line = JSON.stringify(entry) + "\n";

  if (level === "error" || level === "fatal") {
    process.stderr.write(line);
  } else {
    process.stdout.write(line);
  }
}

module.exports = {
  debug: function (msg, extra) { write("debug", msg, extra); },
  info: function (msg, extra) { write("info", msg, extra); },
  warn: function (msg, extra) { write("warn", msg, extra); },
  error: function (msg, extra) { write("error", msg, extra); },
  fatal: function (msg, extra) { write("fatal", msg, extra); },
  runWithRequestId: runWithRequestId,
  getRequestId: getRequestId,
};
