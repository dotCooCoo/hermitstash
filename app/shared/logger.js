/**
 * Structured JSON logger.
 *
 * Levels: debug < info < warn < error < fatal
 * Output: JSON lines to stdout (debug/info/warn) or stderr (error/fatal).
 * Request correlation via setRequestId() — typically called by request-id middleware.
 *
 * Respects LOG_LEVEL env var (default: "info").
 */

var LEVELS = { debug: 0, info: 1, warn: 2, error: 3, fatal: 4 };
var _minLevel = LEVELS[process.env.LOG_LEVEL] !== undefined ? LEVELS[process.env.LOG_LEVEL] : LEVELS.info;

// Per-request context — set once per request, cleared automatically
var _requestId = null;

function setRequestId(id) {
  _requestId = id || null;
}

function getRequestId() {
  return _requestId;
}

function write(level, message, extra) {
  if (LEVELS[level] === undefined || LEVELS[level] < _minLevel) return;

  var entry = {
    timestamp: new Date().toISOString(),
    level: level,
    message: message,
  };

  if (_requestId) entry.requestId = _requestId;

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
  setRequestId: setRequestId,
  getRequestId: getRequestId,
};
