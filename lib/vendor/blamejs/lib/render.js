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

function _statusOr(opts, fallback) {
  if (!opts || opts.status === undefined || opts.status === null) return fallback;
  return opts.status;
}

function _writeResponse(res, status, headers, body) {
  if (_alreadyDone(res)) return;
  if (res.headersSent === true && requestHelpers().failAfterHeaders(res)) return;
  if (typeof res.writeHead === "function") {
    res.writeHead(status, headers);
  } else {
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

function _defaultContentTypeUnlessStated(res, defaults) {
  if (!res || typeof res.getHeader !== "function") return defaults;
  var stated = res.getHeader("Content-Type");
  if (Array.isArray(stated)) stated = stated.length ? stated[0] : "";
  if (typeof stated === "number") stated = String(stated);
  if (typeof stated !== "string" || stated === "") return defaults;
  var out = {};
  Object.keys(defaults).forEach(function (name) {
    if (name !== "Content-Type") out[name] = defaults[name];
  });
  return out;
}

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
 * the client goes away, the caller aborts, or the stream fails. Canceling a
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
 *   // Taking the signal lets the query itself be canceled when the client
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

  var headers = _mergedHeaders(_defaultContentTypeUnlessStated(res, {
    "Content-Type":  "application/octet-stream",
    "Cache-Control": DEFAULT_DYNAMIC_CACHE_CONTROL,
  }), opts.headers);

  var stopper = new AbortController();
  var unlink = _linkSignal(opts.signal, stopper);

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

  var closed = _closedSignal(res);
  var stopped = null;
  var pending = null;
  var willCommitHere = res.headersSent !== true && typeof res.writeHead === "function";
  if (!willCommitHere) pending = null;
  else if (stopper.signal.aborted) stopped = "abort";
  else if (_peerGone(res)) stopped = "peer";
  else {
    try {
      for (;;) {
        pending = _requireIteratorResult(
          await _raceStop(Promise.resolve(source.next()), stopper.signal, closed));
        if (pending.done) break;
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
      closed.dispose();
      failBeforeStreaming(e, source);
    }
  }

  try {
    for (;;) {
      if (stopped !== null) break;
      if (stopper.signal.aborted) { stopped = "abort"; break; }
      if (_peerGone(res)) { stopped = "peer"; break; }
      var step;
      if (pending !== null) { step = pending; pending = null; }
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
  if (stopped !== null) _stopProducer(stopper, source, unlink);
  else unlink();
  closed.dispose();
  if (stopped !== null) {
    requestHelpers().failAfterHeaders(res);
    return;
  }
  if (typeof res.end === "function" && !_alreadyDone(res)) res.end();
}

function _openSource(iterable, signal) {
  var it = typeof iterable === "function" ? iterable(signal) : iterable;
  var isAsync = !!(it && typeof it[Symbol.asyncIterator] === "function");
  if (!it || (!isAsync && typeof it[Symbol.iterator] !== "function")) {
    throw new TypeError("render.stream: expected an async or sync iterable of chunks, " +
      "or a function returning one");
  }
  var iterator = isAsync ? it[Symbol.asyncIterator]() : it[Symbol.iterator]();
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

function _requireIteratorResult(step) {
  if (!step || (typeof step !== "object" && typeof step !== "function")) {
    throw new TypeError("render.stream: the producer returned " +
      (step === undefined ? "undefined" : JSON.stringify(step)) +
      " where an iterator result was expected");
  }
  return step;
}

function _stopProducer(stopper, source, unlink) {
  unlink();
  try { stopper.abort(); } catch (_a) { /* already aborted */ }
  if (!source) return;
  try {
    var maybe = source["return"]();
    if (maybe && typeof maybe.then === "function") maybe.then(_ignore, _ignore);
  } catch (_e) { /* the producer is entitled to refuse */ }
}

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

function _observe(promise) {
  if (promise && typeof promise.then === "function") promise.then(_ignore, _ignore);
}

function _closedSignal(res) {
  var fired = _peerGone(res);
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

function _raceStop(promise, signal, closed) {
  if (!signal && !closed) return promise;
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
 * outside the 300 to 399 range. Default status is 302; pass 301 / 303 /
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
