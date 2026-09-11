// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.middleware.composePipeline
 * @nav        Middleware
 * @title      Compose Pipeline
 * @order      550
 *
 * @intro
 *   Order-aware middleware composer. Replaces the per-project pattern
 *   of N separate `app.use(mw)` calls — where mount order silently
 *   matters (apiEncrypt must precede body-parser; body-parser must
 *   precede idempotency-key + csrf; csrf must precede require-auth) —
 *   with a single declarative pipeline that documents the order +
 *   detects conflicts at registration time.
 *
 *   ## What this primitive owns
 *
 *   - **Single mount point**: one `app.use(pipeline)` instead of N.
 *   - **Order documented in code**: the entry array IS the order;
 *     reading the registration tells the reviewer the canonical
 *     order without grepping `app.use` calls.
 *   - **Conflict detection at registration**: duplicate names refused;
 *     duplicate explicit positions refused; non-monotonic positions
 *     refused (a later entry with a smaller position is a
 *     mis-registration).
 *   - **Canonical-position warnings**: when an entry's `name` matches
 *     a known framework primitive's recommended position
 *     (`apiEncrypt` → 10, `bodyParser` → 20, `csrf` → 30,
 *     `idempotency` → 30, `rateLimit` → 40, `requireAuth` → 50,
 *     `handler` → 60, `errorHandler` → 90), the composer emits an
 *     `system.middleware.compose.canonical_mismatch` audit at warning when
 *     the operator-supplied order deviates. Refusal is opt-in via
 *     `opts.strict: true`; default is warn-and-continue so operators
 *     with intentional non-canonical ordering aren't blocked.
 *
 *   ## What this primitive does NOT own
 *
 *   - **The middlewares themselves** — the composer is a sequencer,
 *     not a registry. Each middleware retains its own
 *     `b.middleware.X(opts)` factory + behavior.
 *   - **Async-context propagation** — async middleware works (the
 *     composer awaits the previous `next()` via Promise wrap), but
 *     primitives that need `AsyncLocalStorage` should attach it at
 *     the middleware itself, not the composer.
 *   - **Error handling** — the composer dispatches through `next(err)`
 *     in the standard way; operators register a tail error-handler
 *     (`name: "errorHandler"`) for the canonical position 90 slot.
 *
 *   ## Audit
 *
 *   Each composed pipeline is registered at boot time with a unique
 *   `pipelineId` (sha3-512 of the sorted entry names) and emits a
 *   `system.middleware.compose.pipeline_built` audit with the entry list
 *   and canonical-mismatch flags. Per-request dispatch is NOT
 *   audited (would blow up the audit pipeline volume) — composers
 *   that need per-request observability compose `b.observability`
 *   inside their own middleware.
 *
 * @card
 *   Order-aware middleware composer. Single mount point replacing N app.use calls, with conflict detection at registration + canonical-position warnings for framework middlewares. Operator's pipeline order documented in code; the entry array IS the order.
 */

var bCrypto         = require("../crypto");
var { defineClass } = require("../framework-error");
var lazyRequire     = require("../lazy-require");
var validateOpts    = require("../validate-opts");

var audit = lazyRequire(function () { return require("../audit"); });

var ComposePipelineError = defineClass("ComposePipelineError", { alwaysPermanent: true });

var CANONICAL_POSITIONS = Object.freeze({
  requestId:     5,
  apiEncrypt:    10,
  bodyParser:    20,
  cspNonce:      22,
  securityHeaders: 25,
  csrf:          30,
  idempotency:   30,
  fetchMetadata: 32,
  rateLimit:     40,
  botGuard:      42,
  requireAuth:   50,
  attachUser:    52,
  handler:       60,                                                                                      // allow:raw-time-literal — pipeline position bucket; coincidental multiple-of-60, C.TIME N/A
  errorHandler:  90,
});

/**
 * @primitive b.middleware.composePipeline
 * @signature b.middleware.composePipeline(entries, opts?)
 * @since     0.9.43
 * @status    stable
 * @related   b.middleware.requestId, b.middleware.requireAuth, b.middleware.idempotencyKey
 *
 * Compose an ordered middleware pipeline into a single Express-shaped
 * middleware. Each `entries[i]` is `{ name: string, mw: function,
 * position?: number }`. Returns the composed `(req, res, next) =>
 * void` middleware. Throws at registration time on duplicate names,
 * duplicate positions, non-monotonic positions, or (with strict)
 * canonical-position mismatches.
 *
 * @opts
 *   strict:  boolean,    // refuse on canonical-position mismatch (default false: warn-and-continue)
 *   name:    string,     // optional pipeline name for audit
 *
 * @example
 *   var pipeline = b.middleware.composePipeline([
 *     { name: "apiEncrypt", mw: apiEncryptMw },
 *     { name: "bodyParser", mw: bodyParserMw },
 *     { name: "csrf",       mw: csrfMw },
 *     { name: "idempotency", mw: idempotencyMw, position: 35 },
 *     { name: "requireAuth", mw: requireAuthMw },
 *   ]);
 *   app.use(pipeline);
 */
function composePipeline(entries, opts) {
  opts = opts || {};
  validateOpts.optionalBoolean(opts.strict, "composePipeline.strict",
    ComposePipelineError, "compose-pipeline/bad-strict");

  if (!Array.isArray(entries)) {
    throw new ComposePipelineError("compose-pipeline/bad-entries",
      "composePipeline: entries must be an array of { name, mw, position? } objects");
  }
  if (entries.length === 0) {
    throw new ComposePipelineError("compose-pipeline/bad-entries",
      "composePipeline: entries must contain at least one middleware");
  }

  var seenNames     = Object.create(null);
  var seenPositions = Object.create(null);
  var canonicalMismatches = [];
  var resolved = [];

  for (var i = 0; i < entries.length; i += 1) {
    var e = entries[i];
    if (!e || typeof e !== "object") {
      throw new ComposePipelineError("compose-pipeline/bad-entry",
        "composePipeline: entry at index " + i + " must be an object");
    }
    if (typeof e.name !== "string" || e.name.length === 0 || e.name.length > 64) {
      throw new ComposePipelineError("compose-pipeline/bad-entry",
        "composePipeline: entries[" + i + "].name must be a non-empty string ≤ 64 bytes");
    }
    if (typeof e.mw !== "function") {
      throw new ComposePipelineError("compose-pipeline/bad-entry",
        "composePipeline: entries[" + i + "].mw must be a function (got " + typeof e.mw + ")");
    }
    if (seenNames[e.name]) {
      throw new ComposePipelineError("compose-pipeline/duplicate-name",
        "composePipeline: duplicate entry name '" + e.name + "' at index " + i);
    }
    seenNames[e.name] = true;

    var position;
    if (e.position !== undefined) {
      if (typeof e.position !== "number" || !Number.isFinite(e.position) || e.position < 0) {
        throw new ComposePipelineError("compose-pipeline/bad-position",
          "composePipeline: entries[" + i + "].position must be a non-negative finite number");
      }
      position = e.position;
    } else if (Object.prototype.hasOwnProperty.call(CANONICAL_POSITIONS, e.name)) {
      position = CANONICAL_POSITIONS[e.name];
    } else {
      position = (i + 1) * 100;
    }

    if (Object.prototype.hasOwnProperty.call(seenPositions, position)) {
      var prevName = seenPositions[position];
      var bothExplicit = entries[_findIndex(resolved, prevName)] &&
                          entries[_findIndex(resolved, prevName)].position !== undefined &&
                          e.position !== undefined;
      if (bothExplicit) {
        throw new ComposePipelineError("compose-pipeline/duplicate-position",
          "composePipeline: entries[" + i + "].position=" + position +
          " collides with '" + prevName + "'; supply explicit distinct positions to disambiguate");
      }
    }
    seenPositions[position] = e.name;

    if (resolved.length > 0 && position < resolved[resolved.length - 1].position) {
      throw new ComposePipelineError("compose-pipeline/non-monotonic",
        "composePipeline: entries[" + i + "] ('" + e.name + "', position=" + position +
        ") declared before entries with higher position; entries must be in non-decreasing position order");
    }

    if (Object.prototype.hasOwnProperty.call(CANONICAL_POSITIONS, e.name) &&
        e.position !== undefined && e.position !== CANONICAL_POSITIONS[e.name]) {
      canonicalMismatches.push({
        name:              e.name,
        suppliedPosition:  e.position,
        canonicalPosition: CANONICAL_POSITIONS[e.name],
      });
    }

    resolved.push({ name: e.name, mw: e.mw, position: position });
  }

  if (canonicalMismatches.length > 0) {
    if (opts.strict === true) {
      throw new ComposePipelineError("compose-pipeline/canonical-mismatch",
        "composePipeline: strict=true; " + canonicalMismatches.length +
        " canonical-position mismatch(es): " +
        canonicalMismatches.map(function (m) {
          return m.name + " supplied=" + m.suppliedPosition + " canonical=" + m.canonicalPosition;
        }).join(", "));
    }
    _emitAudit("system.middleware.compose.canonical_mismatch", {
      pipelineName: opts.name || null,
      mismatches:   canonicalMismatches,
    });
  }

  var pipelineId = bCrypto.namespaceHash("system.middleware.compose.pipeline",
    resolved.map(function (r) { return r.name; }).join("\0"));

  _emitAudit("system.middleware.compose.pipeline_built", {
    pipelineId:   pipelineId,
    pipelineName: opts.name || null,
    entryCount:   resolved.length,
    entries:      resolved.map(function (r) { return { name: r.name, position: r.position }; }),
  });

  return function composedPipeline(req, res, finalNext) {
    return new Promise(function (resolve, reject) {
      var idx = 0;
      var finished = false;
      function _finishOnce(err) {
        if (finished) return;
        finished = true;
        try { finalNext(err); }
        catch (finalErr) { return reject(finalErr); }
        resolve();
      }
      function _resolveOnce() {
        if (finished) return;
        finished = true;
        resolve();
      }
      if (res && typeof res.once === "function") {
        res.once("finish", _resolveOnce);
        res.once("close", _resolveOnce);
      }
      async function dispatch(err) {
        if (finished) return;
        if (idx >= resolved.length) return _finishOnce(err);
        var entry = resolved[idx];
        idx += 1;
        var isErrorHandler = entry.mw.length === 4;
        if (err && !isErrorHandler) return dispatch(err);
        if (!err && isErrorHandler) return dispatch();
        var advanced = false;
        function _next(passErr) {
          advanced = true;
          return dispatch(passErr);
        }
        try {
          if (err) {
            await entry.mw(err, req, res, _next);
            if (!advanced) _resolveOnce();
          } else {
            await entry.mw(req, res, _next);
            if (!advanced && _responseEnded(res)) _resolveOnce();
          }
        } catch (syncErr) {
          dispatch(syncErr).catch(reject);
        }
      }
      dispatch().catch(reject);
    });
  };
}

function _responseEnded(res) {
  return !!(res && (res.writableEnded || res.finished || res.headersSent));
}

composePipeline.CANONICAL_POSITIONS = CANONICAL_POSITIONS;
composePipeline.ComposePipelineError = ComposePipelineError;

function _emitAudit(action, metadata) {
  try {
    if (audit && typeof audit().safeEmit === "function") {
      audit().safeEmit({ action: action, outcome: "success", metadata: metadata });
    }
  } catch (_e) { /* drop-silent — audit failure must not break pipeline registration */ }
}

function _findIndex(arr, name) {
  for (var i = 0; i < arr.length; i += 1) {
    if (arr[i].name === name) return i;
  }
  return -1;
}

module.exports = composePipeline;
