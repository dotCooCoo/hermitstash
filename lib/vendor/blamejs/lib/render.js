// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.render
 * @nav    HTTP
 * @title  Render
 *
 * @intro
 *   Server-side HTML / JSON / XML response helpers. Each helper picks
 *   the right Content-Type, sets a sensible Cache-Control + security
 *   header default, and ends the response in one call — replacing the
 *   five-line writeHead / stringify / Content-Length / end ritual that
 *   every route handler otherwise reimplements.
 *
 *   Module-level helpers (`json` / `text` / `htmlString` / `redirect`)
 *   work without a template engine. `create({ engine })` wraps a
 *   `b.template.create` instance and returns the same helpers plus
 *   `html(res, viewName, data?)` for engine-rendered pages. Operators
 *   who never render server-side HTML import only the module-level
 *   helpers and skip the engine wiring entirely.
 *
 *   All helpers fall through silently when `res.writableEnded === true`,
 *   so a late Promise rejection after `res.end` can't corrupt the wire
 *   with a half-written second body. The default `Cache-Control` is
 *   `private, no-cache, must-revalidate` — overridable via
 *   `opts.headers["Cache-Control"]` for CDN-cacheable responses.
 *
 * @card
 *   Server-side HTML / JSON / XML response helpers.
 */

var C            = require("./constants");
var lazyRequire  = require("./lazy-require");
var validateOpts = require("./validate-opts");

// safe-async — lazy because render is required during boot by the router and
// only the streaming helper needs it, so an operator who never streams does
// not pull the async toolkit in at load.
var safeAsync = lazyRequire(function () { return require("./safe-async"); });
// request-helpers — lazy for the same reason, and because it requires render's
// siblings; only the streaming and error paths need it.
var requestHelpers = lazyRequire(function () { return require("./request-helpers"); });

var DEFAULT_CHARSET = "utf-8";

function _alreadyDone(res) {
  return res && res.writableEnded === true;
}

// The status to send. A status that was NOT given takes the default; one that
// was is sent exactly as given, so `writeHead` reports a nonsense value rather
// than this quietly turning it into a 200. `0` and `NaN` are the pair that
// makes the difference: both are falsy, and defaulting them away would answer
// a misconfigured handler with a successful response.
function _statusOr(opts, fallback) {
  if (!opts || opts.status === undefined || opts.status === null) return fallback;
  return opts.status;
}

function _writeResponse(res, status, headers, body) {
  if (_alreadyDone(res)) return;
  // The headers are already on the wire — writeHead would throw
  // ERR_HTTP_HEADERS_SENT and take the caller's error path with it. This is
  // the natural recovery after a streaming failure ("catch, then render a
  // 500"), so it has to fail as an incomplete transfer rather than a crash.
  if (res.headersSent === true && requestHelpers().failAfterHeaders(res)) return;
  if (typeof res.writeHead === "function") {
    res.writeHead(status, headers);
  } else {
    // Plain object response (for tests). Best-effort header set.
    res.statusCode = status;
    if (typeof res.setHeader === "function") {
      for (var k in headers) {
        if (Object.prototype.hasOwnProperty.call(headers, k)) res.setHeader(k, headers[k]);
      }
    }
  }
  if (typeof res.end === "function") res.end(body);
}

function _mergedHeaders(base, extra) {
  if (!extra) return base;
  var out = {};
  validateOpts.assignOwnEnumerable(out, base);
  validateOpts.assignOwnEnumerable(out, extra);
  return out;
}

// `writeHead(status, headers)` merges with what `setHeader` recorded but lets
// its own object win on a name they share, so a default here replaced whatever a
// route had already said — silently, and only for the names the defaults happen
// to carry, so a `Content-Disposition` survived while the `Content-Type` beside
// it did not.
//
// Exactly one default steps aside for that, and only in `stream`. The reason is
// what the header MEANS in each place. `json`, `text` and `htmlString` encode
// the body themselves, so their `Content-Type` describes the bytes they just
// produced — it belongs with `Content-Length`, not with a preference, and
// inheriting an earlier one is how a JSON error body comes to be served as
// `text/html` and a reflected value in it becomes markup. `stream` does not know
// what its bytes are: `application/octet-stream` is a placeholder for an answer
// the caller has, which is exactly the case the route stating `text/csv` was
// giving it.
//
// `Cache-Control` never steps aside either, in any of them. It is a security
// default rather than a formatting one — dynamic responses must revalidate —
// and a default that any earlier `setHeader` in the chain could relax would not
// be a default. `opts.headers` remains the way to say otherwise, deliberately,
// because that says it at the call rather than somewhere up the middleware.
function _defaultContentTypeUnlessStated(res, defaults) {
  if (!res || typeof res.getHeader !== "function") return defaults;
  var stated = res.getHeader("Content-Type");
  // A header set to nothing states nothing. `setHeader` also accepts an ARRAY,
  // and a wrapper that keeps every header that way would have looked like it
  // had said nothing at all.
  if (Array.isArray(stated)) stated = stated.length ? stated[0] : "";
  if (typeof stated === "number") stated = String(stated);
  if (typeof stated !== "string" || stated === "") return defaults;
  var out = {};
  Object.keys(defaults).forEach(function (name) {
    if (name !== "Content-Type") out[name] = defaults[name];
  });
  return out;
}

// Default Cache-Control for dynamic responses. Browsers heuristically
// cache HTML responses without explicit headers, which causes "saved
// changes don't appear" bugs after a POST/redirect. `no-cache` permits
// caching but forces revalidation on every access — server returns 200
// with fresh content (or 304 if unchanged) instead of the browser
// silently serving stale. Operators wanting a public CDN cacheable
// response override via `opts.headers["Cache-Control"]`.
var DEFAULT_DYNAMIC_CACHE_CONTROL = "private, no-cache, must-revalidate";

/**
 * @primitive b.render.json
 * @signature b.render.json(res, body, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.render.text, b.render.htmlString, b.render.create
 *
 * JSON-stringifies `body` and writes it to `res` with Content-Type
 * `application/json; charset=utf-8`, an explicit `Content-Length`,
 * and the dynamic-response Cache-Control. Status defaults to 200;
 * any custom headers in `opts.headers` merge over the defaults so
 * operators can pin a different Cache-Control or add CORS headers
 * without losing Content-Type. The Content-Type it sends is its own:
 * this helper encodes the body, so the type describes the bytes it
 * produced rather than a preference, and a `text/html` left on the
 * response by an earlier `res.setHeader` does not carry over — that
 * is how a JSON error body comes to be parsed as markup. Say it in
 * `opts.headers` to send something else. Returns `undefined` — the
 * response is fully written by the time the call returns.
 *
 * `opts.replacer` is forwarded to `JSON.stringify` (ECMA-262 §25.5.2,
 * the second argument) so handlers can serialize values that have no
 * native JSON form — `BigInt` (which otherwise throws), `Date` in a
 * custom shape, `Map` / `Set`, or a redaction filter over secret-
 * shaped keys — without pre-walking the body. Accepts the same
 * function or property-name array `JSON.stringify` does; a non-
 * function / non-array value is a config typo and throws.
 *
 * @opts
 *   status:   200,                  // numeric HTTP status (200/201/202/4xx/5xx)
 *   headers:  {},                   // merged over defaults; later wins
 *   replacer: function|string[],    // JSON.stringify replacer (BigInt/Date/redaction)
 *
 * @example
 *   b.render.json(res, { ok: true, id: 42 }, { status: 201 });
 *   // → response: 201, application/json, body `{"ok":true,"id":42}`
 *
 *   b.render.json(res, { total: 9007199254740993n }, {
 *     replacer: function (k, v) { return typeof v === "bigint" ? v.toString() : v; },
 *   });
 *   // → body `{"total":"9007199254740993"}`
 */
function json(res, body, opts) {
  opts = opts || {};
  if (opts.replacer !== undefined && opts.replacer !== null &&
      typeof opts.replacer !== "function" && !Array.isArray(opts.replacer)) {
    throw new TypeError("render.json: opts.replacer must be a function or an array of keys");
  }
  var encoded = JSON.stringify(body, opts.replacer);
  var headers = _mergedHeaders({
    "Content-Type":   "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(encoded, "utf8"),
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, _statusOr(opts, C.HTTP.STATUS.OK), headers, encoded);
}

/**
 * @primitive b.render.stream
 * @signature b.render.stream(res, iterable, opts?)
 * @since     0.18.19
 * @status    stable
 * @related   b.render.json, b.safeAsync.writeChunk
 *
 * Write an async (or sync) iterable to a response, one chunk at a time, and
 * end it. For a generated download — a CSV export, an NDJSON dump, a receipt —
 * where the source is a generator over a cursor rather than a `Readable` that
 * could simply be piped.
 *
 * The obvious loop is wrong in three ways that testing does not surface.
 * `res.write()` returning `false` is easy to discard, and a local client
 * drains instantly, so a bounded-memory export becomes unbounded only under a
 * slow client. Always awaiting `'drain'` then hangs forever when the peer has
 * gone, because a closed socket never emits it. And a producer that throws
 * after the first byte cannot be turned into an error page: the status line is
 * already sent, so the handler appends its message to the partial body and the
 * client receives a 200 whose last row reads "Internal Server Error" — a
 * truncated export that every consumer reads as complete.
 *
 * So: back-pressure is awaited, a closed peer stops the loop instead of
 * stalling it, and a mid-stream throw destroys the connection. Destroying ends
 * a chunked response without its terminating chunk, which is the only signal
 * left that says "this transfer is incomplete" once bytes are on the wire. The
 * error is re-thrown either way, so the caller still logs it.
 *
 * A producer that fails BEFORE yielding anything is not a truncated export —
 * nothing was produced. Opening an async generator runs none of its body, so
 * the first value is fetched while the status line is still unsent: a query
 * that fails to run reaches the caller with a response it can still render an
 * error page on, rather than as a download that dies partway. One row is
 * therefore fetched before the headers go out, which is what any implementation
 * must do to know whether the producer can produce at all.
 *
 * That wait belongs to a response THIS call commits. A long-lived stream whose
 * first value is minutes away — an event subscription, a tail — should send its
 * own head first (`res.writeHead(...)`, `res.flushHeaders()`) and then stream
 * into it: with the status line already out there is nothing to hold back, so
 * no value is fetched before the headers and the client sees the connection
 * establish at once.
 *
 * Headers are written from `opts` before the first chunk unless the caller has
 * already sent them. The `application/octet-stream` default steps aside for a
 * Content-Type the route already set with `res.setHeader` — unlike the other
 * helpers this one does not encode the body, so that default is a placeholder
 * for an answer the caller has, and a route serving a CSV had already given it.
 * An explicit `opts.headers` entry still wins over both, and the Cache-Control
 * default does not step aside for anything but that. Nothing is buffered: a
 * chunk is handed to the socket as the producer yields it.
 *
 * Pass a function instead of an iterable to be handed a signal that aborts when
 * the client goes away, the caller aborts, or the stream fails. Cancelling a
 * generator does not reach work it is already waiting on — a generator parked
 * in `await query()` runs its `finally` only once that query returns on its
 * own — so a producer holding a cursor, a connection or a file handle should
 * take the signal and cancel with it.
 *
 * @opts
 *   status:   200,        // numeric HTTP status, sent with the first chunk
 *   headers:  {},         // merged over the dynamic-response defaults
 *   onError:  "destroy",  // "destroy" (default) or "rethrow" to leave the socket alone
 *   signal:   AbortSignal, // stop producing when it aborts
 *
 * @example
 *   await b.render.stream(res, rows(), {
 *     headers: { "Content-Type": "text/csv; charset=utf-8" },
 *   });
 *
 *   async function* rows() {
 *     yield "order_id,total\n";
 *     for await (var r of cursor) yield r.id + "," + r.total + "\n";
 *   }
 *
 *   // Taking the signal lets the query itself be cancelled when the client
 *   // hangs up, instead of running to completion against a closed socket.
 *   await b.render.stream(res, function (signal) { return rows(signal); }, {
 *     headers: { "Content-Type": "text/csv; charset=utf-8" },
 *   });
 */
async function stream(res, iterable, opts) {
  opts = opts || {};
  validateOpts(opts, ["status", "headers", "onError", "signal"], "render.stream");
  if (opts.onError !== undefined && opts.onError !== "destroy" && opts.onError !== "rethrow") {
    throw new TypeError("render.stream: opts.onError must be \"destroy\" or \"rethrow\"");
  }
  if (_alreadyDone(res)) return;

  // Read the caller's headers FIRST, while there is nothing to release. Copying
  // them runs whatever `opts.headers` chooses to run — a getter, a proxy trap —
  // and doing it after the producer was opened left a throw there with no path
  // back to the cleanup, holding the producer's cursor or file handle for the
  // life of the process. Here it is simply a bad argument, and reaches the
  // caller as one.
  var headers = _mergedHeaders(_defaultContentTypeUnlessStated(res, {
    "Content-Type":  "application/octet-stream",
    "Cache-Control": DEFAULT_DYNAMIC_CACHE_CONTROL,
  }), opts.headers);

  // Stopping has to reach the producer, not only the loop. An async generator
  // suspended inside its own `await` does not run its `finally` when `return()`
  // is called: that call queues behind the very pull it is trying to cancel, so
  // a cursor stays open until a query nobody is waiting for finishes on its
  // own. Handing the producer a signal is the only way to reach work already in
  // flight, so a producer that takes one is given this one.
  var stopper = new AbortController();
  var unlink = _linkSignal(opts.signal, stopper);

  // The source is opened before anything is committed. A factory that throws,
  // or an object whose `Symbol.asyncIterator` throws, then reaches the caller's
  // error page normally — with the status line still unsent, rather than as a
  // committed response with no body to follow.
  // "Before the status line goes out" is this primitive's own status line. The
  // CALLER may have sent one already — the documented shape where a route
  // writes its own head and streams into it, which is how SSE is written — and
  // then there is no pre-commit window to fail into: those headers are on the
  // wire and the only honest ending left is an incomplete transfer. Every throw
  // out of the opening sequence goes through here so that a response someone
  // else committed is never left neither ended nor destroyed, which reads to
  // the client as a body that never arrives.
  function failBeforeStreaming(e, openedSource) {
    if (openedSource) _stopProducer(stopper, openedSource, unlink);
    else unlink();
    if (res.headersSent === true && opts.onError !== "rethrow") {
      requestHelpers().failAfterHeaders(res);
    }
    throw e;
  }

  var source;
  try {
    source = _openSource(iterable, stopper.signal);
  } catch (e) {
    failBeforeStreaming(e, null);
  }

  // Opening an async generator does no work — its body does not run until the
  // first pull — so "the source opened" said nothing about whether the producer
  // can produce, which is the source type this primitive is built around. The
  // first value is fetched HERE, while the status line is still unsent, so a
  // query that fails before any row reaches the caller's error page instead of
  // arriving as a download that dies partway. That is the failure most likely
  // to be seen in production, and the only one an error page can explain.
  //
  // A stop that arrives during the first pull is NOT a pre-commit failure: an
  // aborted export is a truncation whether or not a row was ever produced, and
  // it takes the committed path below so the client hears an incomplete
  // transfer rather than a successful empty one.
  // Only where THIS call is the one that will commit. A route that sent its own
  // status line has no pre-commit window to protect, and waiting for a first
  // value there buys nothing while costing everything: an event stream whose
  // first event is minutes away would hold its headers back for minutes, and
  // the client would see a connection that never established. That shape — send
  // the head, flush it, then stream — is also the escape hatch for a long-lived
  // producer that wants its headers out before it has anything to say.
  var closed = _closedSignal(res);
  var stopped = null;                                  // "abort" | "peer" | null
  var pending = null;                                  // the first step, held back
  var willCommitHere = res.headersSent !== true && typeof res.writeHead === "function";
  if (!willCommitHere) pending = null;
  else if (stopper.signal.aborted) stopped = "abort";
  else if (_peerGone(res)) stopped = "peer";
  else {
    try {
      // Until the producer offers something that would actually be WRITTEN, or
      // says it is done. A `null` or `undefined` is skipped by the loop below
      // rather than written, so it is not proof the producer can produce — a
      // source that yields one and then fails would otherwise have committed
      // the response on the strength of a value nobody ever sends.
      for (;;) {
        pending = _requireIteratorResult(
          await _raceStop(Promise.resolve(source.next()), stopper.signal, closed));
        if (pending.done) break;
        // A SYNC iterable may yield a PROMISE, and `for await` resolves it
        // before handing it on — so a rejected one is another failure before
        // any chunk was produced, and it belongs in this window rather than in
        // the loop. Resolved here, the loop sees a settled value and writes it.
        if (!source.isAsync && pending.value && typeof pending.value.then === "function") {
          pending = {
            done: false,
            value: await _raceStop(pending.value, stopper.signal, closed),
          };
        }
        if (pending.value !== null && pending.value !== undefined) break;
      }
    } catch (e) {
      if (e && e.stopKind) stopped = e.stopKind;
      else {
        closed.dispose();
        failBeforeStreaming(e, source);
      }
    }
  }

  if (res.headersSent !== true && typeof res.writeHead === "function") {
    try {
      res.writeHead(_statusOr(opts, C.HTTP.STATUS.OK), headers);
    } catch (e) {
      // A status out of range or a header value Node refuses. The producer is
      // already open by now, so a configuration mistake would otherwise leave
      // its cursor or file handle held for the life of the process. A partial
      // writeHead can also leave the response committed, which is why this
      // takes the same route out as every other failure before the loop.
      closed.dispose();
      failBeforeStreaming(e, source);
    }
  }

  // The status line went out above, so from here the response is committed
  // whether or not a chunk has been written yet. Treating "committed" as "at
  // least one chunk landed" left a producer that failed on its first row with
  // a response that was neither ended nor destroyed — headers and
  // `Transfer-Encoding: chunked` on the wire and nothing to follow, so the
  // client waited forever.
  // Three things can stop this loop and each has to release the producer: the
  // producer failing, the caller aborting, and the peer going away. A
  // `for await` releases the iterator only when IT decides the loop is over,
  // so a pull that never settles — a query that hangs, a page that never
  // arrives — kept the handler, the cursor and the response alive with no way
  // out. The loop owns its own stopping instead.
  try {
    for (;;) {
      if (stopped !== null) break;                     // decided before the commit
      if (stopper.signal.aborted) { stopped = "abort"; break; }
      // The peer is gone: stop pulling rows nobody will read, and do not wait
      // for a drain that never comes.
      if (_peerGone(res)) { stopped = "peer"; break; }
      var step;
      if (pending !== null) { step = pending; pending = null; }   // the pre-commit pull
      else {
        try {
          step = _requireIteratorResult(
            await _raceStop(Promise.resolve(source.next()), stopper.signal, closed));
        } catch (e) {
          if (e && e.stopKind) { stopped = e.stopKind; break; }
          throw e;
        }
      }
      if (step.done) break;
      var chunk = step.value;
      try {
        // A synchronous iterable may still yield promises, and `for await`
        // resolves each one before handing it on. Writing the promise object
        // instead would put "[object Promise]" in the export.
        if (!source.isAsync && chunk && typeof chunk.then === "function") {
          chunk = await _raceStop(chunk, stopper.signal, closed);
        }
        if (chunk === null || chunk === undefined) continue;
        await _raceStop(safeAsync().writeChunk(res, chunk), stopper.signal, closed);
      } catch (e2) {
        if (e2 && e2.stopKind) { stopped = e2.stopKind; break; }
        throw e2;
      }
    }
  } catch (e) {
    _stopProducer(stopper, source, unlink);
    closed.dispose();
    if (opts.onError !== "rethrow") requestHelpers().failAfterHeaders(res);
    throw e;
  }
  // Only stop a producer the loop LEFT early. A `for await` calls `return()` on
  // an early exit and not on normal exhaustion, and producers use it to record
  // exactly that — telling one its completed export was cancelled is a
  // different statement.
  if (stopped !== null) _stopProducer(stopper, source, unlink);
  else unlink();
  closed.dispose();
  // An abort is a truncation too. Ending normally would write the terminating
  // chunk and hand the client four rows of a fifty-row export as a complete,
  // successful 200 — the very outcome this primitive exists to prevent, and
  // the caller would not hear about it either. A signal that was already
  // aborted when the call began takes the same path: an empty export is still
  // a truncated one.
  if (stopped !== null) {
    requestHelpers().failAfterHeaders(res);
    return;
  }
  if (typeof res.end === "function" && !_alreadyDone(res)) res.end();
}

// Open the producer. A function is called with the stop signal, so a producer
// whose work is cancellable can be handed the one thing that reaches work
// already in flight; anything else is used as the iterable it claims to be.
function _openSource(iterable, signal) {
  var it = typeof iterable === "function" ? iterable(signal) : iterable;
  var isAsync = !!(it && typeof it[Symbol.asyncIterator] === "function");
  if (!it || (!isAsync && typeof it[Symbol.iterator] !== "function")) {
    throw new TypeError("render.stream: expected an async or sync iterable of chunks, " +
      "or a function returning one");
  }
  var iterator = isAsync ? it[Symbol.asyncIterator]() : it[Symbol.iterator]();
  // What the method HANDED BACK has to be an iterator, and that is asked here
  // rather than at the first pull. Left until then, a method returning `null`,
  // a number, or an object with no `next` came to light after the status line
  // had gone out — so a malformed producer arrived as a committed response that
  // was then destroyed, instead of as a bad argument the caller could still
  // render an error page for.
  if (!iterator || (typeof iterator !== "object" && typeof iterator !== "function") ||
      typeof iterator.next !== "function") {
    throw new TypeError("render.stream: the iterable's " +
      (isAsync ? "Symbol.asyncIterator" : "Symbol.iterator") +
      " returned something that is not an iterator — it must return an object " +
      "with a next() method");
  }
  return {
    isAsync: isAsync,
    next:    function () { return iterator.next(); },
    "return": function () {
      return typeof iterator["return"] === "function" ? iterator["return"]() : undefined;
    },
  };
}

// The iterator protocol says a step is an object. Treating anything else as "no
// chunk this time" would pull again from a producer that can only answer the
// same way, and spin forever with the response held open; `for await` raises
// here and so does this. Asked of the FIRST step too, which is before the status
// line goes out, so a producer that answers wrongly from the start is a bad
// argument rather than a committed response.
function _requireIteratorResult(step) {
  if (!step || (typeof step !== "object" && typeof step !== "function")) {
    throw new TypeError("render.stream: the producer returned " +
      (step === undefined ? "undefined" : JSON.stringify(step)) +
      " where an iterator result was expected");
  }
  return step;
}

// Stop the producer, signal first. `return()` alone is not enough: on an async
// generator it queues behind the pull it means to cancel, so a generator parked
// in `await query()` does not reach its `finally` — and the cursor, file handle
// or connection it holds stays open — until that query finishes on its own. The
// signal reaches the pending work; `return()` then unwinds the generator.
//
// Neither is awaited. A producer blocked on the same thing that stalled the
// pull would otherwise block the response's own teardown behind it.
function _stopProducer(stopper, source, unlink) {
  unlink();
  try { stopper.abort(); } catch (_a) { /* already aborted */ }
  if (!source) return;
  try {
    var maybe = source["return"]();
    if (maybe && typeof maybe.then === "function") maybe.then(_ignore, _ignore);
  } catch (_e) { /* the producer is entitled to refuse */ }
}

// Forward the caller's abort to the stop signal, and hand back the undo. A
// per-request signal outlives a single export, so the listener is removed when
// the stream is over rather than left to accumulate one per response.
function _linkSignal(signal, stopper) {
  if (!signal) return _ignore;
  if (signal.aborted) {
    stopper.abort();
    return _ignore;
  }
  function onAbort() { stopper.abort(); }
  signal.addEventListener("abort", onAbort, { once: true });
  return function () { signal.removeEventListener("abort", onAbort); };
}

function _ignore() {}

// Take delivery of a promise whose outcome no longer matters, so that a
// rejection nobody is waiting for does not surface as an unhandled one.
function _observe(promise) {
  if (promise && typeof promise.then === "function") promise.then(_ignore, _ignore);
}

// A promise that settles when the response closes, so a pull blocked on the
// next database page does not outlive the client that asked for it. The
// listener is removed either way — a long-lived response would otherwise
// accumulate one per stream.
function _closedSignal(res) {
  var fired = _peerGone(res);
  // A subscriber list rather than a promise. Racing a promise would attach one
  // reaction per chunk to the same unresolved promise, and a settled race
  // cannot detach it — so a long export accumulated a closure for every row it
  // wrote, and the memory it was careful not to spend on buffering went here
  // instead.
  var waiting = [];
  function onClose() {
    fired = true;
    var pending = waiting;
    waiting = [];
    for (var i = 0; i < pending.length; i += 1) pending[i]();
  }
  if (res && typeof res.once === "function") res.once("close", onClose);
  return {
    isClosed: function () { return fired || _peerGone(res); },
    subscribe: function (fn) {
      if (fired) { fn(); return function () {}; }
      waiting.push(fn);
      return function () {
        var at = waiting.indexOf(fn);
        if (at !== -1) waiting.splice(at, 1);
      };
    },
    dispose: function () {
      waiting = [];
      if (res && typeof res.removeListener === "function") res.removeListener("close", onClose);
    },
  };
}

// Settle as soon as the caller aborts or the peer closes, so neither a blocked
// producer nor a wait for `drain` from a peer that stopped reading outlives the
// reason to keep going.
function _raceStop(promise, signal, closed) {
  if (!signal && !closed) return promise;
  // Already stopped before the race could be set up — but the pull is in flight
  // whatever we decide about it. Left unobserved, its later rejection is an
  // unhandled rejection, which by default takes the process down: a producer
  // that cancels itself and then lets its query reject would kill the server.
  if (signal && signal.aborted) {
    _observe(promise);
    return Promise.reject(_stopError("abort"));
  }
  if (closed && closed.isClosed()) {
    _observe(promise);
    return Promise.reject(_stopError("peer"));
  }
  return new Promise(function (resolve, reject) {
    var settled = false;
    var unsubscribe = null;
    function done(fn, v) {
      if (settled) return;
      settled = true;
      if (signal) signal.removeEventListener("abort", onAbort);
      if (unsubscribe) unsubscribe();
      fn(v);
    }
    function onAbort() { done(reject, _stopError("abort")); }
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
    if (closed) unsubscribe = closed.subscribe(function () { done(reject, _stopError("peer")); });
    promise.then(function (v) { done(resolve, v); }, function (e) { done(reject, e); });
  });
}

function _stopError(kind) {
  var err = new Error("render.stream: " + (kind === "abort" ? "aborted" : "the peer closed"));
  err.code = kind === "abort" ? "render/aborted" : "render/peer-closed";
  err.stopKind = kind;
  return err;
}

// A response whose socket has been destroyed or whose peer has hung up. Both
// are reported differently across Node versions and response doubles, so all
// three signals are consulted.
function _peerGone(res) {
  if (!res) return true;
  if (res.destroyed === true || res.writableEnded === true) return true;
  return !!(res.socket && res.socket.destroyed === true);
}

/**
 * @primitive b.render.text
 * @signature b.render.text(res, body, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.render.json, b.render.htmlString
 *
 * Coerces `body` to a string and writes it as `text/plain` with the
 * supplied charset (default `utf-8`). `null` / `undefined` body
 * becomes the empty string rather than the literal text `"null"` —
 * a common gotcha when forwarding a value-or-nothing handler result.
 *
 * @opts
 *   status:  200,
 *   headers: {},
 *   charset: "utf-8",
 *
 * @example
 *   b.render.text(res, "OK");
 *   // → 200, Content-Type "text/plain; charset=utf-8", body "OK"
 */
function text(res, body, opts) {
  opts = opts || {};
  var encoded = body == null ? "" : String(body);
  var charset = opts.charset || DEFAULT_CHARSET;
  var headers = _mergedHeaders({
    "Content-Type":   "text/plain; charset=" + charset,
    "Content-Length": Buffer.byteLength(encoded, charset),
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, _statusOr(opts, C.HTTP.STATUS.OK), headers, encoded);
}

/**
 * @primitive b.render.htmlString
 * @signature b.render.htmlString(res, htmlBody, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.render.json, b.render.create
 *
 * Writes a pre-rendered HTML string with `Content-Type: text/html;
 * charset=<charset>`. Use when an HTML body is already in hand — for
 * engine-bound view rendering, prefer `b.render.create({ engine })`
 * and the returned `html(res, viewName, data)` helper which threads
 * `res.locals` (CSP nonce, request id, current user) into the view.
 *
 * @opts
 *   status:  200,
 *   headers: {},
 *   charset: "utf-8",
 *
 * @example
 *   b.render.htmlString(res, "<h1>Hi</h1>");
 *   // → 200, text/html; charset=utf-8, body "<h1>Hi</h1>"
 */
function htmlString(res, htmlBody, opts) {
  opts = opts || {};
  var encoded = htmlBody == null ? "" : String(htmlBody);
  var charset = opts.charset || DEFAULT_CHARSET;
  var headers = _mergedHeaders({
    "Content-Type":   "text/html; charset=" + charset,
    "Content-Length": Buffer.byteLength(encoded, charset),
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, _statusOr(opts, C.HTTP.STATUS.OK), headers, encoded);
}

/**
 * @primitive b.render.redirect
 * @signature b.render.redirect(res, location, opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeRedirect, b.render.json
 *
 * Sends a 3xx response with the given `Location` header and an empty
 * body. Throws when `location` is empty or when `opts.status` falls
 * outside the 300–399 range. Default status is 302; pass 301 / 303 /
 * 307 / 308 for the other RFC 9110 §15.4 redirect semantics. For
 * untrusted user-supplied destinations, validate first via
 * `b.safeRedirect` before passing the result here.
 *
 * @opts
 *   status:  302,   // 301 / 302 / 303 / 307 / 308
 *   headers: {},
 *
 * @example
 *   b.render.redirect(res, "/login", { status: 303 });
 *   // → 303, Location "/login", empty body
 */
function redirect(res, location, opts) {
  opts = opts || {};
  if (typeof location !== "string" || location.length === 0) {
    throw new Error("render.redirect: location is required");
  }
  var status = _statusOr(opts, C.HTTP.STATUS.FOUND);
  if (!C.HTTP.redirect(status)) {
    throw new Error("render.redirect: status must be 3xx (got " + status + ")");
  }
  var headers = _mergedHeaders({
    "Location":       location,
    "Content-Length": 0,
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, status, headers, "");
}

// ---- Engine-bound instance ----

/**
 * @primitive b.render.create
 * @signature b.render.create(opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.template.create, b.render.htmlString
 *
 * Binds a template engine to a renderer and returns the module-level
 * helpers (`json` / `text` / `htmlString` / `redirect`) plus
 * `html(res, viewName, data?, opts?)`. The `html` helper auto-merges
 * `res.locals` into the template data so request-scoped values
 * (CSP nonce, request id, current user) thread through every render
 * without per-route plumbing. Operator-supplied `data` keys take
 * precedence over locals — explicit beats implicit. Throws when
 * `opts.engine.render` is not a function.
 *
 * @opts
 *   engine: <required>,   // a template engine instance from b.template.create({ viewsDir })
 *
 * @example
 *   // requires: a views directory on disk
 *   var engine = b.template.create({ viewsDir: "/srv/views" });
 *   var r      = b.render.create({ engine: engine });
 *   r.html(res, "home", { user: "ada" });
 *   // → 200, text/html; charset=utf-8, body = engine.render("home", merged-locals)
 */
function create(opts) {
  opts = opts || {};
  if (!opts.engine || typeof opts.engine.render !== "function") {
    throw new Error("render.create({ engine }): engine.render must be a function " +
      "(pass a template engine from b.template.create)");
  }
  var engine = opts.engine;

  function html(res, viewName, data, htmlOpts) {
    htmlOpts = htmlOpts || {};
    // Auto-merge res.locals into template data — the framework's
    // request-scoped surface (cspNonce, requestId, current user, etc.)
    // lands in res.locals via middleware (csp-nonce, attach-user, etc.).
    // Operators no longer have to thread these through every render
    // call. Operator-supplied `data` keys take precedence over locals
    // — explicit > implicit.
    var merged;
    if (res && res.locals && typeof res.locals === "object") {
      merged = {};
      var lk = Object.keys(res.locals);
      for (var li = 0; li < lk.length; li++) merged[lk[li]] = res.locals[lk[li]];
      if (data) {
        var dk = Object.keys(data);
        for (var di = 0; di < dk.length; di++) merged[dk[di]] = data[dk[di]];
      }
    } else {
      merged = data || {};
    }
    var body = engine.render(viewName, merged);
    return htmlString(res, body, htmlOpts);
  }

  return {
    html:        html,
    htmlString:  htmlString,
    json:        json,
    stream:      stream,
    text:        text,
    redirect:    redirect,
    engine:      engine,
  };
}

module.exports = {
  create:      create,
  json:        json,
  stream:      stream,
  text:        text,
  htmlString:  htmlString,
  redirect:    redirect,
};
