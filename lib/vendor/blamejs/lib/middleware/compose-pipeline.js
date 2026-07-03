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

// Canonical positions for framework middlewares. The composer
// surfaces mismatches as warnings; refusal is opt-in via
// `opts.strict: true`. Operators with intentional non-canonical
// ordering aren't blocked.
//
// Position groupings (relative — exact numbers can drift, the
// classes are what matter):
//   < 10  : request-id, connection-tracking (must be earliest)
//   10-19 : api-encrypt (must decrypt before any read)
//   20-29 : body-parser (must precede idempotency, csrf, validation)
//   30-39 : csrf, idempotency, header policy (need body parsed)
//   40-49 : rate-limit, bot-guard (after auth context if any)
//   50-59 : require-auth, ACL (after body + csrf)
//   60-89 : application handlers
//   >= 90 : error-handler (must be last; trailing catch)
var CANONICAL_POSITIONS = Object.freeze({
  requestId:     5,                                                                                       // canonical position bucket
  apiEncrypt:    10,                                                                                      // canonical position bucket
  bodyParser:    20,                                                                                      // canonical position bucket
  cspNonce:      22,                                                                                      // canonical position bucket
  securityHeaders: 25,                                                                                    // canonical position bucket
  csrf:          30,                                                                                      // canonical position bucket
  idempotency:   30,                                                                                      // canonical position bucket (same as csrf)
  fetchMetadata: 32,                                                                                      // canonical position bucket
  rateLimit:     40,                                                                                      // canonical position bucket
  botGuard:      42,                                                                                      // canonical position bucket
  requireAuth:   50,                                                                                      // canonical position bucket
  attachUser:    52,                                                                                      // canonical position bucket
  handler:       60,                                                                                      // allow:raw-time-literal — pipeline position bucket; coincidental multiple-of-60, C.TIME N/A
  errorHandler:  90,                                                                                      // canonical position bucket
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
    if (typeof e.name !== "string" || e.name.length === 0 || e.name.length > 64) {                       // middleware-name cap
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
      // Operator-supplied name matches a canonical framework
      // middleware — use the canonical position by default. Operator
      // can still override by passing an explicit position.
      position = CANONICAL_POSITIONS[e.name];
    } else {
      // Operator-defined middleware without explicit position —
      // synthesize a position from the array index times 100 so
      // operators that don't care about explicit ordering get a
      // natural sequential flow. Use 100 so canonical positions
      // (5..90) can interleave without colliding when an operator
      // mixes named + unnamed entries.
      position = (i + 1) * 100;                                                                          // index→position scale; canonical-pos ceiling is 90
    }

    if (Object.prototype.hasOwnProperty.call(seenPositions, position)) {
      // Same explicit position from two entries — refuse (would make
      // dispatch order undefined). Two canonical entries CAN land at
      // the same position (csrf + idempotency are both 30); allowed
      // only when operator didn't supply an explicit position for
      // either. Surface this via a less-severe error code so
      // operators with intentional ties can override with explicit
      // distinct positions.
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

  // Composed middleware — sequentially invokes each entry's mw via
  // next() chaining. Standard Express idiom: each mw receives
  // (req, res, next) and either calls next() to continue or
  // next(err) to bail out to the error-handler.
  //
  // composedPipeline returns a Promise that resolves AFTER `finalNext`
  // has been called by the chain. The framework router awaits this
  // promise; without it, async middleware (bodyParser / apiEncrypt
  // reading the request stream) leave the router with `next` still
  // false when composedPipeline returns synchronously, and the
  // router exits the request before the chain has actually advanced.
  //
  // Middleware do NOT await next() — that's the Express contract.
  // So we can't rely on `await entry.mw(...)` to wait for the rest
  // of the chain. Instead, the outer Promise resolves only when the
  // chain reaches its end via finalNext, regardless of how many
  // hops of async middleware have happened along the way.
  //
  // When a middleware calls `next(err)`, the chain skips non-error
  // middleware (3-arg) and dispatches the error to the first 4-arg
  // entry (`(err, req, res, next)` — Express's error-handler shape).
  // If no error-handler entry is found, `finalNext(err)` carries the
  // error up to the framework router.
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
      // A middleware (or error handler) that ENDS THE RESPONSE without calling
      // next has halted the chain: it handled the request itself. Settle the
      // outer promise so the awaiting router is released — a never-settled
      // promise pins its req/res closure forever — but do NOT call finalNext:
      // the router's next-flag stays false, so it won't run the route handler
      // on top of an already-sent response.
      function _resolveOnce() {
        if (finished) return;
        finished = true;
        resolve();
      }
      // Settle when the response actually finishes. This is response-driven,
      // not return-driven: a callback-style middleware that calls next() LATER
      // (from a timer, stream, or legacy callback) returns before next() runs,
      // so we must NOT treat a bare return as a halt — only an ended response.
      // The synchronous _responseEnded() check below covers a middleware that
      // ended the response inline (and a mock res without an event emitter);
      // this listener covers one that ends it from a deferred callback.
      if (res && typeof res.once === "function") {
        res.once("finish", _resolveOnce);
        res.once("close", _resolveOnce);
      }
      async function dispatch(err) {
        if (finished) return;
        if (idx >= resolved.length) return _finishOnce(err);
        var entry = resolved[idx];
        idx += 1;
        // 4-arg entries are error handlers (Express convention).
        // Regular entries run on the success path; error entries on
        // the error path. Skip entries that don't match the current
        // path until one matches OR the chain ends.
        var isErrorHandler = entry.mw.length === 4;
        if (err && !isErrorHandler) return dispatch(err);
        if (!err && isErrorHandler) return dispatch();
        // Track whether the middleware called its next() argument.
        // If a 4-arg error handler runs to completion without calling
        // next, the error is considered handled and the chain ends
        // cleanly (Express convention). Same applies to a 3-arg
        // middleware that doesn't call next — the chain stops, but
        // we don't invoke finalNext to avoid the router proceeding
        // to the route handler after a middleware decided to halt.
        var advanced = false;
        function _next(passErr) {
          advanced = true;
          return dispatch(passErr);
        }
        try {
          if (err) {
            // Error handler: (err, req, res, next). Express convention — a
            // 4-arg handler that returns without calling next has HANDLED the
            // error, so the chain ends cleanly; settle (without finalNext).
            await entry.mw(err, req, res, _next);
            if (!advanced) _resolveOnce();
          } else {
            // Regular middleware: (req, res, next). Settle only if it ENDED the
            // response (a halt). A bare return without next is NOT treated as a
            // halt — it may be a callback-style middleware that calls next()
            // later (timer/stream); the finish/close listener covers a deferred
            // response end, and a deferred next() continues the chain.
            await entry.mw(req, res, _next);
            if (!advanced && _responseEnded(res)) _resolveOnce();
          }
        } catch (syncErr) {
          // Synchronous throw OR rejected promise — route through
          // the error path so a downstream error-handler can format
          // the response.
          dispatch(syncErr).catch(reject);
        }
      }
      dispatch().catch(reject);
    });
  };
}

// True once the response has been committed/ended — the reliable "this
// middleware handled the request" signal (vs. the function merely returning,
// which a callback-style middleware does before its deferred next()).
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
