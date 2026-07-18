// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeAsync.withSignal + b.safeAsync.makeDropCallback.
 *
 * withSignal races a Promise against an AbortSignal: when the signal
 * aborts, the wrapper rejects with SafeAsyncError (.code = "async/
 * aborted", .cause = signal.reason) while the underlying Promise keeps
 * running in the background — only the wrapper's resolution is short-
 * circuited. makeDropCallback is the canonical log-stream-sink onDrop
 * wrapper: it invokes onDrop with the framework-canonical
 * { reason, batch, error } payload and, per the drop-silent contract,
 * routes any throw from the operator callback to onError instead of
 * letting it bubble into the request that triggered the drop.
 *
 * All async waits poll via helpers.waitUntil — no fixed setTimeout.
 */

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var waitUntil = helpers.waitUntil;

async function run() {
  // ---- withSignal: a real abort produces the typed rejection ----
  // Drive a genuine AbortController and assert the wrapper rejects with
  // the advertised SafeAsyncError shape. The underlying work is a real
  // framework sleep that flips a flag when it completes, so we can also
  // prove it kept running in the background after the abort.
  var backgroundDone = false;
  var underlying = b.safeAsync.sleep(30).then(function () {
    backgroundDone = true;
    return "underlying-finished";
  });

  var ctrl = new AbortController();
  var wrapped = b.safeAsync.withSignal(underlying, ctrl.signal);
  ctrl.abort(new Error("caller-cancelled"));

  var aborted = null;
  try { await wrapped; }
  catch (e) { aborted = e; }
  check("b.safeAsync.withSignal: aborting the signal rejects the wrapper", aborted !== null);
  check("withSignal: rejection is a SafeAsyncError",
    aborted instanceof b.safeAsync.SafeAsyncError);
  check("withSignal: rejection .code is async/aborted", aborted && aborted.code === "async/aborted");
  check("withSignal: .cause is the signal.reason passed to abort()",
    aborted && aborted.cause instanceof Error && aborted.cause.message === "caller-cancelled");

  // The underlying Promise is NOT cancelled — only the wrapper settled.
  // Poll (never sleep) until the background work reports completion.
  await waitUntil(function () { return backgroundDone; }, {
    timeoutMs: 5000,
    label: "safe-async withSignal: underlying promise continues after wrapper aborts",
  });
  check("withSignal: underlying promise keeps running in the background", backgroundDone === true);

  // ---- withSignal: an already-aborted signal rejects immediately ----
  var pre = new AbortController();
  pre.abort();
  var preAborted = null;
  try { await b.safeAsync.withSignal(Promise.resolve("x"), pre.signal); }
  catch (e) { preAborted = e; }
  check("withSignal: a pre-aborted signal rejects with async/aborted",
    preAborted instanceof b.safeAsync.SafeAsyncError && preAborted.code === "async/aborted");

  // ---- withSignal: no signal / un-aborted signal resolve through ----
  check("withSignal: no signal resolves the underlying value unchanged",
    (await b.safeAsync.withSignal(Promise.resolve("passthru"), undefined)) === "passthru");

  var live = new AbortController();
  check("withSignal: an un-aborted signal resolves the underlying value",
    (await b.safeAsync.withSignal(Promise.resolve("ok"), live.signal)) === "ok");

  // Underlying rejection (signal never aborts) surfaces the ORIGINAL
  // error, not a synthesized async/aborted one.
  var origErr = null;
  var live2 = new AbortController();
  try { await b.safeAsync.withSignal(Promise.reject(new Error("underlying-fail")), live2.signal); }
  catch (e) { origErr = e; }
  check("withSignal: underlying rejection surfaces the original error",
    origErr && origErr.message === "underlying-fail" && origErr.code === undefined);

  // ---- makeDropCallback: canonical payload shape ----
  var dropped = [];
  var emit = b.safeAsync.makeDropCallback(
    function (info) { dropped.push(info); },
    function (e) { dropped.push({ onError: e.message }); }
  );
  emit("buffer-full", [{ id: 1 }], new Error("queue overflow"));
  check("b.safeAsync.makeDropCallback: onDrop receives the canonical { reason, batch, error } payload",
    dropped.length === 1 &&
    dropped[0].reason === "buffer-full" &&
    Array.isArray(dropped[0].batch) && dropped[0].batch[0].id === 1 &&
    dropped[0].error instanceof Error && dropped[0].error.message === "queue overflow");

  // An omitted error argument normalizes to error:null (not undefined).
  emit("flush-timeout", [{ id: 2 }]);
  check("makeDropCallback: omitted error normalizes to error:null",
    dropped.length === 2 && dropped[1].error === null);

  // ---- makeDropCallback: drop-silent contract ----
  // A throwing onDrop must route to onError and NEVER bubble into the
  // caller (the request/flush path that triggered the drop stays alive).
  var onErrCaught = null;
  var emitThrows = b.safeAsync.makeDropCallback(
    function () { throw new Error("onDrop-boom"); },
    function (e) { onErrCaught = e; }
  );
  var bubbled = false;
  try { emitThrows("reason", []); }
  catch (_e) { bubbled = true; }
  check("makeDropCallback: a throwing onDrop does not bubble to the caller", bubbled === false);
  check("makeDropCallback: the throw is routed to onError",
    onErrCaught instanceof Error && onErrCaught.message === "onDrop-boom");

  // A missing / non-function onDrop is a silent no-op — the drop-silent
  // contract holds even when the operator wired nothing.
  var nullThrew = false;
  try { b.safeAsync.makeDropCallback(null, null)("reason", []); }
  catch (_e) { nullThrew = true; }
  check("makeDropCallback: a null onDrop is a silent no-op", nullThrew === false);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
