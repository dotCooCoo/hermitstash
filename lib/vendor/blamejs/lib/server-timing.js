"use strict";
/**
 * @module     b.serverTiming
 * @nav        HTTP
 * @title      Server-Timing
 * @order      315
 *
 * @intro
 *   W3C Server-Timing response header builder. Lets the server
 *   describe per-request timing metrics (database query duration,
 *   downstream HTTP call latency, encryption time) so the browser's
 *   Performance API exposes them to client-side telemetry.
 *
 *   The header is a comma-separated list of `name; dur=<ms>; desc=<text>`
 *   entries. Builder primitives are immutable per-request collectors
 *   that operators populate over the lifetime of the request and
 *   serialize at response-write time.
 *
 *   `b.serverTiming.create()` returns a per-request collector:
 *
 *     var timing = b.serverTiming.create();
 *     timing.mark("db.query", 12.5, "user fetch");
 *     timing.mark("encrypt",  3.1);
 *     res.setHeader("Server-Timing", timing.toHeader());
 *     // → "db.query; dur=12.5; desc=\"user fetch\", encrypt; dur=3.1"
 *
 *   Use `timing.measure(name, fn)` to time an async operation
 *   inline:
 *
 *     var rows = await timing.measure("db.query", function () {
 *       return db.query("SELECT ...");
 *     });
 *
 * @card
 *   W3C Server-Timing response header builder — per-request timing-metric collector that surfaces server-side latency in the browser's Performance API.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var ServerTimingError = defineClass("ServerTimingError", { alwaysPermanent: true });

// W3C Server-Timing §3 — metric-name is token shape (RFC 7230). Cap
// at 128 chars for sanity; operator-supplied desc is sf-string.
var METRIC_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/;                                       // allow:raw-byte-literal — RFC 7230 token shape + length cap

function _quoteDesc(s) {
  return "\"" + String(s).replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + "\"";
}

/**
 * @primitive b.serverTiming.create
 * @signature b.serverTiming.create()
 * @since     0.8.86
 * @status    stable
 * @related   b.serverTiming.entry
 *
 * Return a per-request collector with `mark` / `measure` / `toHeader`
 * methods. The collector is mutable + scoped to a single request;
 * operators discard or stringify at response-write time. Throws
 * `server-timing/bad-name` for non-token metric names and
 * `server-timing/bad-duration` for non-finite negative duration.
 *
 * @example
 *   var timing = b.serverTiming.create();
 *   timing.mark("cache.lookup", 0.3);
 *   var data = await timing.measure("db.query", function () { return db.query("..."); });
 *   res.setHeader("Server-Timing", timing.toHeader());
 */
function create() {
  var entries = [];

  function mark(name, durationMs, description) {
    validateOpts.requireNonEmptyString(
      name, "serverTiming.mark.name", ServerTimingError, "server-timing/bad-name");
    if (name.length > 128 || !METRIC_NAME_RE.test(name)) {                                         // allow:raw-byte-literal — metric-name length cap, not bytes
      throw new ServerTimingError("server-timing/bad-name",
        "metric name '" + name + "' must match RFC 7230 token + <= 128 chars");
    }
    if (durationMs !== undefined && durationMs !== null) {
      if (typeof durationMs !== "number" || !isFinite(durationMs) || durationMs < 0) {
        throw new ServerTimingError("server-timing/bad-duration",
          "duration must be a non-negative finite number when provided");
      }
    }
    if (description !== undefined && description !== null) {
      if (typeof description !== "string") {
        throw new ServerTimingError("server-timing/bad-description",
          "description must be a string when provided");
      }
    }
    entries.push({
      name: name,
      dur:  typeof durationMs === "number" ? durationMs : null,
      desc: typeof description === "string" ? description : null,
    });
    return entries[entries.length - 1];
  }

  async function measure(name, fn) {
    if (typeof fn !== "function") {
      throw new ServerTimingError("server-timing/bad-fn",
        "measure: fn must be a function", true);
    }
    var start = _now();
    try {
      var result = await fn();
      mark(name, _now() - start);
      return result;
    } catch (err) {
      mark(name, _now() - start, "error");
      throw err;
    }
  }

  function toHeader() {
    if (entries.length === 0) return "";
    return entries.map(function (e) {
      var parts = [e.name];
      if (e.dur !== null) parts.push("dur=" + _formatDur(e.dur));
      if (e.desc !== null) parts.push("desc=" + _quoteDesc(e.desc));
      return parts.join("; ");
    }).join(", ");
  }

  function snapshot() {
    return entries.map(function (e) { return Object.assign({}, e); });
  }

  return { mark: mark, measure: measure, toHeader: toHeader, snapshot: snapshot };
}

/**
 * @primitive b.serverTiming.entry
 * @signature b.serverTiming.entry(name, durationMs?, description?)
 * @since     0.8.86
 * @status    stable
 * @related   b.serverTiming.create
 *
 * Format a single Server-Timing entry without building a collector.
 * Useful when the operator wants a one-shot header value without
 * threading a collector through the request scope.
 *
 * @example
 *   res.setHeader("Server-Timing", b.serverTiming.entry("db.query", 12.5));
 *   // → "db.query; dur=12.5"
 */
function entryString(name, durationMs, description) {
  var c = create();
  c.mark(name, durationMs, description);
  return c.toHeader();
}

function _now() {
  // Prefer process.hrtime when available (sub-ms precision); fall back
  // to Date.now in environments without it.
  if (typeof process !== "undefined" && typeof process.hrtime === "function" &&
      typeof process.hrtime.bigint === "function") {
    return Number(process.hrtime.bigint() / 1000n) / 1000;                                         // allow:raw-byte-literal — hrtime ns→ms scale, not bytes
  }
  return Date.now();
}

function _formatDur(ms) {
  // W3C spec says dur is a number; emit at most 3 decimal places.
  if (Number.isInteger(ms)) return String(ms);
  return ms.toFixed(3).replace(/\.?0+$/, "");
}

module.exports = {
  create:            create,
  entry:             entryString,
  ServerTimingError: ServerTimingError,
};
