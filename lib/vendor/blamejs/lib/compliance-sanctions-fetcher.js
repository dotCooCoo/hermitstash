"use strict";
/**
 * b.compliance.sanctions.fetcher — periodic sanctions-list refresh
 * helper.
 *
 * The framework intentionally does NOT vendor the sanctions list (it
 * changes daily and has legal-distribution implications). Operators
 * fetch from the canonical source on a schedule + reload the screener.
 * This module wraps the schedule + comparison + reload-trigger logic
 * so operators write one fetch callback instead of orchestrating it.
 *
 *   var fetcher = b.compliance.sanctions.fetcher.create({
 *     screener:        sdnScreener,                // from sanctions.create
 *     intervalMs:      C.TIME.hours(24),
 *     fetch:           async function () {
 *       // Operator-supplied: hits treasury.gov, parses CSV, returns
 *       // canonical entry array.
 *       var rows = await downloadSdnCsv();
 *       return rows.map(b.compliance.sanctions.parseOfacCsvRow);
 *     },
 *     onRefreshed:     function (diff) {
 *       log.info("SDN list refreshed", diff);
 *     },
 *     onError:         function (err) {
 *       pagerDuty.alert("SDN list fetch failed", err);
 *     },
 *   });
 *   fetcher.start();
 *   ...
 *   await fetcher.shutdown();
 *
 * Behavior:
 *   - On each tick, run fetch(); if it returns a non-empty array,
 *     swap the screener's index via screener.reload(entries).
 *   - If fetch() throws or returns empty, skip the swap and emit an
 *     audit event; the screener keeps the previous index. Operators
 *     can configure onError for paging.
 *   - Initial run is opt-in via opts.fetchOnStart (default true);
 *     operators that prefer to seed the screener from a cached file
 *     at boot pass false.
 *
 * Audit emissions:
 *   compliance.sanctions.refresh.started   — every tick
 *   compliance.sanctions.refresh.completed — successful refresh + diff
 *   compliance.sanctions.refresh.skipped   — tick returned empty
 *   compliance.sanctions.refresh.failed    — fetch threw
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var SanctionsFetcherError = defineClass("SanctionsFetcherError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

function create(opts) {
  validateOpts.requireObject(opts, "compliance.sanctions.fetcher", SanctionsFetcherError);
  validateOpts(opts, [
    "screener", "intervalMs", "fetch",
    "onRefreshed", "onError",
    "fetchOnStart", "audit",
  ], "compliance.sanctions.fetcher.create");

  validateOpts.shape(opts, {
    screener: function (value) {
      if (!value || typeof value.reload !== "function") {
        throw new SanctionsFetcherError("sanctions-fetcher/bad-screener",
          "fetcher.create: screener must be a sanctions.create() instance");
      }
    },
    fetch: function (value) {
      if (typeof value !== "function") {
        throw new SanctionsFetcherError("sanctions-fetcher/bad-fetch",
          "fetcher.create: fetch must be an async function returning entry[]");
      }
    },
    intervalMs:   "optional-positive-finite",
    onRefreshed:  "optional-function",
    onError:      "optional-function",
    fetchOnStart: "optional-boolean",
    audit:        "optional-boolean",
  }, "fetcher.create", SanctionsFetcherError, "sanctions-fetcher/bad-opts");

  var intervalMs   = opts.intervalMs   || C.TIME.hours(24);
  var fetchOnStart = opts.fetchOnStart !== false;
  var auditOn      = opts.audit !== false;
  var screener     = opts.screener;
  var fetchFn      = opts.fetch;

  var handle  = null;
  var stopping = false;
  var lastSuccess = null;
  var lastError = null;
  var refreshCount = 0;
  var failureCount = 0;

  var _emitAudit = audit().namespaced(null, { audit: auditOn });

  var _emitMetric = observability().namespaced("compliance.sanctions.fetcher");

  async function _tick() {
    if (stopping) return;
    _emitAudit("compliance.sanctions.refresh.started", "success", {
      algorithm: screener.algorithm,
    });
    var entries;
    try {
      entries = await fetchFn();
    } catch (e) {
      failureCount += 1;
      lastError = (e && e.message) || String(e);
      _emitAudit("compliance.sanctions.refresh.failed", "failure", {
        error: lastError, algorithm: screener.algorithm,
      });
      _emitMetric("failed", 1);
      if (typeof opts.onError === "function") {
        try { opts.onError(e); } catch (_e2) { /* operator hook */ }
      }
      return;
    }
    if (!Array.isArray(entries) || entries.length === 0) {
      _emitAudit("compliance.sanctions.refresh.skipped", "success", {
        reason: "fetch-returned-empty", algorithm: screener.algorithm,
      });
      _emitMetric("skipped", 1);
      return;
    }
    var diff;
    try { diff = screener.reload(entries); }
    catch (e) {
      failureCount += 1;
      lastError = (e && e.message) || String(e);
      _emitAudit("compliance.sanctions.refresh.failed", "failure", {
        error: lastError, phase: "reload", algorithm: screener.algorithm,
      });
      _emitMetric("failed", 1);
      if (typeof opts.onError === "function") {
        try { opts.onError(e); } catch (_e2) { /* operator hook */ }
      }
      return;
    }
    refreshCount += 1;
    lastSuccess = Date.now();
    _emitAudit("compliance.sanctions.refresh.completed", "success", {
      algorithm: screener.algorithm,
      added:     diff.addedIds.length,
      removed:   diff.removedIds.length,
      newSize:   diff.newSize,
    });
    _emitMetric("completed", 1);
    if (typeof opts.onRefreshed === "function") {
      try { opts.onRefreshed(diff); } catch (_e2) { /* operator hook */ }
    }
  }

  function start() {
    if (handle) return;
    stopping = false;
    if (fetchOnStart) {
      // Fire-and-forget; the periodic ticker handles the rest.
      _tick().catch(function () { /* drop-silent — see _tick */ });
    }
    handle = safeAsync.repeating(function () {
      _tick().catch(function () { /* drop-silent */ });
    }, intervalMs, { name: "sanctions-fetcher" });
  }

  async function shutdown() {
    stopping = true;
    if (handle) { handle.stop(); handle = null; }
  }

  function stats() {
    return {
      lastSuccess:  lastSuccess,
      lastError:    lastError,
      refreshCount: refreshCount,
      failureCount: failureCount,
      running:      handle !== null,
    };
  }

  return {
    start:      start,
    shutdown:   shutdown,
    stats:      stats,
    // Test hook
    _tickOnce:  _tick,
  };
}

module.exports = {
  create:                  create,
  SanctionsFetcherError:   SanctionsFetcherError,
};
