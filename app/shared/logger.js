/**
 * Structured JSON logger — wraps b.log.create().
 *
 * Levels: debug < info < warn < error < fatal
 * Output: JSON lines to stdout (debug/info/warn) or stderr (error/fatal).
 * Request correlation via AsyncLocalStorage — the request-id middleware enters
 * a storage context for each request (runWithRequestId), and every log line
 * written during that async chain picks up the requestId automatically.
 *
 * Respects LOG_LEVEL env var (default: "info"). b.log.create() does not read
 * the environment itself, so the level is resolved here and passed through,
 * preserving the same operator knob the previous hand-rolled logger exposed.
 *
 * The second argument flows through b.redact, so password / token / key-shaped
 * fields are scrubbed before they reach the log line. Message text is
 * bidi-escaped (Trojan-Source defense) by the framework.
 *
 * module.exports keeps the same shape the hand-rolled logger had
 * (debug/info/warn/error/fatal + runWithRequestId/getRequestId) so every
 * importer is untouched by the swap.
 */

var b = require("../../lib/vendor/blamejs");

var VALID_LEVELS = { debug: 1, info: 1, warn: 1, error: 1, fatal: 1 };
// allow:raw-process-env — the logger initializes before the config layer is built
var level = VALID_LEVELS[process.env.LOG_LEVEL] ? process.env.LOG_LEVEL : "info";

var logger = b.log.create({
  destination: process.stdout,
  errorDestination: process.stderr,
  level: level,
});

module.exports = {
  debug: function (msg, extra) { return logger.debug(msg, extra); },
  info: function (msg, extra) { return logger.info(msg, extra); },
  warn: function (msg, extra) { return logger.warn(msg, extra); },
  error: function (msg, extra) { return logger.error(msg, extra); },
  fatal: function (msg, extra) { return logger.fatal(msg, extra); },
  runWithRequestId: function (id, fn) { return logger.runWithRequestId(id, fn); },
  getRequestId: function () { return logger.getRequestId(); },
};
