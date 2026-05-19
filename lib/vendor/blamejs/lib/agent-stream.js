"use strict";
/**
 * @module     b.agent.stream
 * @nav        Agent
 * @title      Agent Stream
 * @order      60
 *
 * @intro
 *   Async-iterable variants for agent methods that yield N rows.
 *   Operator wraps a cursor-shaped fetcher with `b.agent.stream.create`;
 *   the resulting object is `AsyncIterable<row>` — built-in
 *   backpressure (each `yield` blocks until the consumer pulls),
 *   automatic cursor close via `try`/`finally` on any exit path
 *   (consumer break, throw, network drop), and drain-marker emit on
 *   orchestrator drain so clients can resume from `lastSeenCursor`
 *   against the new agent post-drain.
 *
 *   ```js
 *   var stream = b.agent.stream.create({
 *     orchestrator: orch,                  // optional — for drain reg
 *     actor:        { id: "u1" },
 *     kind:         "search",
 *     batchSize:    256,
 *     openCursor:   function (cursorOpts) {
 *       return store.openSearchCursor(cursorOpts);     // operator
 *     },
 *     cursorOpts:   { folder: "INBOX", sinceModseq: 0 },
 *   });
 *
 *   for await (var row of stream) {
 *     // row delivered as soon as the cursor yields it.
 *     // Pulling slowly applies backpressure to the store.
 *     if (someCondition) break;            // cursor.close() fires automatically
 *   }
 *   ```
 *
 *   ## Drain-marker semantic
 *
 *   When orchestrator drain fires, in-flight streams emit ONE final
 *   `{ _drainMarker: true, lastSeenCursor: <opaque>, reason: "drain" }`
 *   row and exit cleanly. Clients reconnecting via JMAP-WebSocket /
 *   IMAP NOTIFY pass `lastSeenCursor` back to resume.
 *
 *   ## Cursor contract
 *
 *   Operator-supplied cursor:
 *     `cursor.fetchBatch(batchSize) → { rows, nextCursor, done }`
 *     `cursor.close() → void | Promise<void>`
 *
 *   The framework's `b.mailStore` will gain `openSearchCursor` /
 *   `openFolderCursor` / `openExportCursor` etc. at later mail-stack
 *   slices that compose this primitive.
 *
 * @card
 *   Async-iterable variants for agent methods that yield N rows.
 *   Cursor-backed backpressure; auto-close on exit; drain-marker
 *   emit so clients resume cleanly post-deploy.
 */

var lazyRequire       = require("./lazy-require");
var { defineClass }   = require("./framework-error");
var guardStreamArgs   = require("./guard-stream-args");
var agentAudit        = require("./agent-audit");

var audit             = lazyRequire(function () { return require("./audit"); });

var AgentStreamError = defineClass("AgentStreamError", { alwaysPermanent: true });

var DEFAULT_BATCH_SIZE = 256;                                                                          // allow:raw-byte-literal — cursor batch row count, not bytes

/**
 * @primitive b.agent.stream.create
 * @signature b.agent.stream.create(opts)
 * @since     0.9.24
 * @status    stable
 * @related   b.agent.orchestrator.create
 *
 * Create an async-iterable backed by an operator-supplied cursor.
 * Returns an object that implements `[Symbol.asyncIterator]` — usable
 * with `for await (var row of stream)`. Cursor close + audit emit +
 * orchestrator stream-registry hook are owned by the framework;
 * operator only supplies the `openCursor` factory + `cursorOpts`.
 *
 * @opts
 *   openCursor:    function(cursorOpts) → cursor,   // required
 *   cursorOpts:    object,                           // operator-passed
 *   batchSize:     integer,                           // default 256
 *   orchestrator:  b.agent.orchestrator,              // optional — for drain reg
 *   actor:         { id, ... },                       // optional — audit attribution
 *   kind:          string,                            // "search" / "export" / ...
 *   audit:         b.audit,                           // optional
 *
 * @example
 *   var stream = b.agent.stream.create({
 *     openCursor: function (o) { return store.openSearchCursor(o); },
 *     cursorOpts: { folder: "INBOX" },
 *   });
 *   for await (var row of stream) { process(row); }
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new AgentStreamError("agent-stream/bad-opts", "create: opts required");
  }
  if (typeof opts.openCursor !== "function") {
    throw new AgentStreamError("agent-stream/bad-open-cursor",
      "create: opts.openCursor must be a function");
  }
  guardStreamArgs.validate({
    batchSize:  opts.batchSize,
    kind:       opts.kind,
    cursorOpts: opts.cursorOpts,
  });
  var batchSize = typeof opts.batchSize === "number" ? opts.batchSize : DEFAULT_BATCH_SIZE;
  var orch      = opts.orchestrator || null;
  var auditImpl = opts.audit || audit();
  var actor     = opts.actor || null;
  var kind      = opts.kind  || "stream";

  return {
    [Symbol.asyncIterator]: function () {
      return _makeIterator({
        openCursor: opts.openCursor,
        cursorOpts: opts.cursorOpts,
        batchSize:  batchSize,
        orchestrator: orch,
        audit:      auditImpl,
        actor:      actor,
        kind:       kind,
      });
    },
  };
}

function _makeIterator(ctx) {
  var streamId   = ctx.orchestrator ? ctx.orchestrator.registerStream({ kind: ctx.kind, actor: ctx.actor }) : null;
  var cursor     = null;
  var buffer     = [];
  var done       = false;
  var closed     = false;
  var drained    = false;
  // SUBSTRATE-14 — track the cursor of the LAST row actually yielded
  // to the consumer. The prior shape called cursor.lastSeenCursor()
  // at drain-marker emit, which returned the position of the last
  // FETCHED batch — clients resuming from that cursor SKIPPED every
  // row still in `buffer` that hadn't been yielded yet. Now we record
  // the per-row cursor at yield time so the marker carries the
  // correct resume point.
  var lastYieldedCursor = null;
  _safeAudit(ctx.audit, "agent.stream.opened", ctx.actor, { kind: ctx.kind, streamId: streamId });

  async function _closeOnce(reason) {
    if (closed) return;
    closed = true;
    if (cursor && typeof cursor.close === "function") {
      try { await cursor.close(); } catch (_e) { /* best-effort */ }
    }
    if (streamId && ctx.orchestrator) {
      try { ctx.orchestrator.unregisterStream(streamId); } catch (_e) { /* best-effort */ }
    }
    _safeAudit(ctx.audit, "agent.stream.closed", ctx.actor, {
      kind: ctx.kind, streamId: streamId, reason: reason || "exhausted",
    });
  }

  return {
    next: async function () {
      try {
        if (buffer.length > 0) {
          var row = buffer.shift();
          // SUBSTRATE-14 — record the cursor for this yielded row so a
          // drain that fires BETWEEN buffered yields emits a marker
          // whose lastSeenCursor matches what the client actually
          // received. The cursor extraction shape mirrors the
          // operator's `cursor.lastSeenCursor()` contract: row carries
          // `_cursor` OR the cursor object exposes a per-row helper.
          lastYieldedCursor = _resumeCursorFor(row, lastYieldedCursor);
          return { value: row, done: false };
        }
        if (done) {
          if (!closed) await _closeOnce("exhausted");
          return { value: undefined, done: true };
        }
        // Check orchestrator drain BEFORE fetching the next batch.
        if (ctx.orchestrator && ctx.orchestrator.isDraining && ctx.orchestrator.isDraining()) {
          if (!drained) {
            drained = true;
            var marker = {
              _drainMarker:   true,
              lastSeenCursor: lastYieldedCursor,
              reason:         "drain",
            };
            _safeAudit(ctx.audit, "agent.stream.drain_marker_emitted", ctx.actor, {
              kind: ctx.kind, streamId: streamId,
              bufferedRowsDropped: buffer.length,
              lastSeenCursor: lastYieldedCursor,
            });
            done = true;
            // Discard any buffered rows so the consumer doesn't see
            // post-drain rows after the marker.
            buffer.length = 0;
            return { value: marker, done: false };
          }
          await _closeOnce("drain");
          return { value: undefined, done: true };
        }
        if (!cursor) {
          cursor = await ctx.openCursor(ctx.cursorOpts);
          if (!cursor || typeof cursor.fetchBatch !== "function") {
            throw new AgentStreamError("agent-stream/bad-cursor",
              "openCursor returned non-cursor (missing fetchBatch)");
          }
        }
        var batch = await cursor.fetchBatch(ctx.batchSize);
        if (!batch || typeof batch !== "object") {
          throw new AgentStreamError("agent-stream/bad-batch",
            "cursor.fetchBatch returned non-object");
        }
        var rows = batch.rows || [];
        if (batch.done) done = true;
        if (rows.length === 0) {
          if (!closed) await _closeOnce("exhausted");
          return { value: undefined, done: true };
        }
        // Push all but the first into the buffer; return the first.
        for (var i = 1; i < rows.length; i += 1) buffer.push(rows[i]);
        lastYieldedCursor = _resumeCursorFor(rows[0], lastYieldedCursor);
        return { value: rows[0], done: false };
      } catch (e) {
        // Any error closes the cursor + emits an audit. Re-throw to
        // surface upward.
        await _closeOnce("error");
        throw e;
      }
    },
    return: async function () {
      // Consumer's `break` calls this — close the cursor cleanly.
      await _closeOnce("consumer-break");
      return { value: undefined, done: true };
    },
    throw: async function (err) {
      await _closeOnce("consumer-throw");
      throw err;
    },
  };
}

function _safeAudit(auditImpl, action, actor, metadata) {
  agentAudit.safeAudit(auditImpl, action, actor, metadata);
}

// SUBSTRATE-14 — resolve the resume cursor for a row about to be
// yielded. Operators may attach the cursor per-row (`row._cursor` /
// `row.cursor`) OR rely on the cursor's own per-row tracker
// (`cursor.cursorForRow(row)`) — both shapes supported.
function _resumeCursorFor(row, fallback) {
  if (row && typeof row === "object") {
    if (row._cursor != null) return row._cursor;
    if (row.cursor  != null) return row.cursor;
  }
  return fallback;
}

module.exports = {
  create:            create,
  AgentStreamError:  AgentStreamError,
  guards: {
    args: guardStreamArgs,
  },
};
