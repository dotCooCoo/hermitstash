/**
 * Structured JSON logger — wraps b.log.create().
 *
 * Levels: debug < info < warn < error < fatal
 * Output: JSON lines to stdout (debug/info/warn) or stderr (error/fatal).
 * runWithRequestId(id, fn) adds the request ID to every line written inside fn.
 * The request-id middleware calls it for the composed security pipeline, and
 * middleware/error-handler.js calls it for the lines it writes.
 *
 * LOG_LEVEL sets the level (default "info"). It is resolved here and passed to
 * b.log.create().
 *
 * The second argument flows through b.redact, so password / token / key-shaped
 * fields are scrubbed before they reach the log line. Message text is
 * bidi-escaped (Trojan-Source defense) by the framework.
 *
 * Share IDs, password-reset, verification and invite tokens, and record _ids
 * are all b.crypto.generateToken(32) values: 64 hexadecimal characters. Before
 * a line is written, each such value in the message or in a string field is
 * replaced by [redacted], and a string field whose name contains "share" is
 * replaced whole. A field whose name ends in "Id" or "_id", such as bundleId,
 * holds a record identifier and is written unchanged. A Uint8Array or Buffer is
 * passed to b.redact as it is, and b.redact masks it.
 *
 * module.exports keeps the same shape the hand-rolled logger had
 * (debug/info/warn/error/fatal + runWithRequestId/getRequestId) so every
 * importer is untouched by the swap. requestPath and redactTokens are exported
 * for log fields, audit details and SIEM events.
 */

var nodeUtil = require("node:util");
var b = require("../../lib/vendor/blamejs");

var VALID_LEVELS = { debug: 1, info: 1, warn: 1, error: 1, fatal: 1 };
// allow:raw-process-env — the logger initializes before the config layer is built
var level = VALID_LEVELS[process.env.LOG_LEVEL] ? process.env.LOG_LEVEL : "info";

var logger = b.log.create({
  destination: process.stdout,
  errorDestination: process.stderr,
  level: level,
});

var REDACTED = "[redacted]";
// 64 hexadecimal characters with no hexadecimal character directly before or
// after them.
var TOKEN_IN_TEXT_RE = /(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])/g;
// A whole path segment of 32 or more letters, digits, "-" or "_".
var TOKEN_SEGMENT_RE = /^[A-Za-z0-9_-]{32,}$/;
var SHARE_FIELD_RE = /share/i;
var ID_FIELD_RE = /(?:Id|_id)$/;
var MAX_FIELD_DEPTH = 4;

/**
 * The request path to write in a log line, an audit detail or a SIEM event.
 * After the router has matched a route, this is the route pattern, for example
 * /b/:shareId/download. Before that, it is the request path with each segment
 * of 32 or more letters, digits, "-" or "_" replaced by :token and each
 * 64-character hexadecimal value replaced by [redacted]. The query string is
 * never included. Returns "/" when the request cannot be read.
 */
function requestPath(req) {
  try {
    if (req && typeof req.routePattern === "string" && req.routePattern.length > 0) {
      return req.routePattern;
    }
    // resolveRoute returns req.url without its query string when no route matched.
    var raw = (req && typeof req.pathname === "string") ? req.pathname : b.requestHelpers.resolveRoute(req);
    var masked = String(raw).split("/").map(function (segment) {
      return TOKEN_SEGMENT_RE.test(segment) ? ":token" : segment;
    }).join("/");
    return redactTokens(masked) || "/";
  } catch (_e) {
    return "/";
  }
}

/**
 * Returns text with each 64-character hexadecimal value replaced by
 * [redacted]. Storage keys, scratch directories and error messages carry share
 * IDs that way, for example bundles/<id>/<time>-<id>.pdf. A SHA3-512 checksum
 * has 128 characters and is left as it is.
 */
function redactTokens(text) {
  if (typeof text !== "string" || text.length === 0) return text;
  return text.replace(TOKEN_IN_TEXT_RE, REDACTED);
}

function _safeField(key, value, depth) {
  if (typeof value === "string") {
    if (key !== null && SHARE_FIELD_RE.test(key)) return REDACTED;
    if (key !== null && ID_FIELD_RE.test(key)) return value;
    return redactTokens(value);
  }
  if (!value || typeof value !== "object") return value;
  if (nodeUtil.types.isUint8Array(value)) return value;
  if (depth >= MAX_FIELD_DEPTH) return REDACTED;
  if (Array.isArray(value)) {
    return value.map(function (item) { return _safeField(null, item, depth + 1); });
  }
  var out = {};
  Object.keys(value).forEach(function (k) { out[k] = _safeField(k, value[k], depth + 1); });
  return out;
}

function _write(method, msg, extra) {
  return method(typeof msg === "string" ? redactTokens(msg) : msg, _safeField(null, extra, 0));
}

module.exports = {
  debug: function (msg, extra) { return _write(logger.debug, msg, extra); },
  info: function (msg, extra) { return _write(logger.info, msg, extra); },
  warn: function (msg, extra) { return _write(logger.warn, msg, extra); },
  error: function (msg, extra) { return _write(logger.error, msg, extra); },
  fatal: function (msg, extra) { return _write(logger.fatal, msg, extra); },
  runWithRequestId: function (id, fn) { return logger.runWithRequestId(id, fn); },
  getRequestId: function () { return logger.getRequestId(); },
  requestPath: requestPath,
  redactTokens: redactTokens,
};
