// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeAsync core coordination primitives: SafeAsyncError, withSignal,
 * withTimeout, sleep, safeAwait, safeInvoke, makeDropCallback, Mutex,
 * Semaphore, Once.
 *
 * withSignal / withTimeout race a Promise against an AbortSignal and/or a
 * wall-clock deadline: on abort the wrapper rejects with SafeAsyncError
 * (.code = "async/aborted", .cause = signal.reason); on timeout with
 * .code = "async/timeout"; the underlying Promise keeps running in the
 * background. sleep is an abortable/unref-able delay. safeAwait is the
 * Go-style [error, value] tuple. safeInvoke / makeDropCallback are the
 * drop-silent operator-callback path (a throwing callback — or a throwing
 * onError — never bubbles into the request that triggered the drop). Mutex
 * and Semaphore serialize / bound async regions with abortable waiters and
 * fail-closed release() guards (release on unheld / idle throws
 * async/bad-release). Once memoizes a single-flight init.
 *
 * All async waits poll via helpers.waitUntil / abort deterministically —
 * no fixed setTimeout budgets that flake under parallel smoke.
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

  // ---- withSignal: a LATE underlying rejection after abort is swallowed ----
  // Aborting settles the wrapper (async/aborted). The underlying promise's
  // then-handlers stay attached; a later rejection must hit the settled-guard
  // and be swallowed — no double-reject, no unhandled-rejection crash.
  var lateCtrl = new AbortController();
  var lateWrapErr = null;
  var lateReject;
  var lateUnderlying = new Promise(function (_res, rej) { lateReject = rej; });
  var lateWrapped = b.safeAsync.withSignal(lateUnderlying, lateCtrl.signal)
    .catch(function (e) { lateWrapErr = e; });
  lateCtrl.abort(new Error("abort-first"));
  await lateWrapped;
  check("withSignal: abort settles the wrapper with async/aborted",
    lateWrapErr instanceof b.safeAsync.SafeAsyncError && lateWrapErr.code === "async/aborted");
  lateReject(new Error("late-underlying"));
  await helpers.passiveObserve(20, "safe-async withSignal: late underlying rejection swallowed post-abort");
  check("withSignal: a late underlying rejection after abort is swallowed by the settled-guard", true);

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

  // ---- SafeAsyncError: default code + explicit code/cause ----
  var defErr = new b.safeAsync.SafeAsyncError("no code given");
  check("SafeAsyncError: default code is async/invalid when none supplied", defErr.code === "async/invalid");
  check("SafeAsyncError: isSafeAsyncError flag is set", defErr.isSafeAsyncError === true);
  var causeErr = new b.safeAsync.SafeAsyncError("with cause", "async/custom", new Error("root-cause"));
  check("SafeAsyncError: explicit code + cause are preserved",
    causeErr.code === "async/custom" &&
    causeErr.cause instanceof Error && causeErr.cause.message === "root-cause");

  // ---- withTimeout: config-time bad-arg (throws async/bad-arg) ----
  function wtRejects(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("withTimeout: rejects " + label,
      threw instanceof b.safeAsync.SafeAsyncError && threw.code === "async/bad-arg" &&
      /positive finite number/.test(threw.message || ""));
  }
  wtRejects("ms=0",        function () { b.safeAsync.withTimeout(Promise.resolve(1), 0); });
  wtRejects("ms negative", function () { b.safeAsync.withTimeout(Promise.resolve(1), -5); });
  wtRejects("ms NaN",      function () { b.safeAsync.withTimeout(Promise.resolve(1), NaN); });
  wtRejects("ms Infinity", function () { b.safeAsync.withTimeout(Promise.resolve(1), Infinity); });
  wtRejects("ms string",   function () { b.safeAsync.withTimeout(Promise.resolve(1), "100"); });

  // Happy path resolves the underlying value before the deadline.
  var wtOk = await b.safeAsync.withTimeout(Promise.resolve("fast"), 1000, { name: "fast-op" });
  check("withTimeout: resolves the underlying value before the deadline", wtOk === "fast");

  // Timeout fires → SafeAsyncError(async/timeout); message carries ms + opts.name.
  var wtTimeout = null;
  try { await b.safeAsync.withTimeout(new Promise(function () {}), 20, { name: "stuck-op" }); }
  catch (e) { wtTimeout = e; }
  check("withTimeout: a hung promise rejects with async/timeout",
    wtTimeout instanceof b.safeAsync.SafeAsyncError && wtTimeout.code === "async/timeout");
  check("withTimeout: timeout message includes the ms budget and the opts.name label",
    wtTimeout && /20ms/.test(wtTimeout.message) && /stuck-op/.test(wtTimeout.message));

  // Already-aborted signal at start → immediate async/aborted (name + cause).
  var wtPre = new AbortController();
  wtPre.abort(new Error("pre-cancel"));
  var wtPreErr = null;
  try { await b.safeAsync.withTimeout(new Promise(function () {}), 1000, { signal: wtPre.signal, name: "pre" }); }
  catch (e) { wtPreErr = e; }
  check("withTimeout: an already-aborted signal rejects immediately with async/aborted",
    wtPreErr instanceof b.safeAsync.SafeAsyncError && wtPreErr.code === "async/aborted");
  check("withTimeout: aborted message includes opts.name and cause is the signal reason",
    wtPreErr && /pre/.test(wtPreErr.message) &&
    wtPreErr.cause instanceof Error && wtPreErr.cause.message === "pre-cancel");

  // Abort while pending → async/aborted with the signal reason as cause.
  var wtCtrl = new AbortController();
  var wtAbortErr = null;
  var wtAbortP = b.safeAsync.withTimeout(new Promise(function () {}), 5000, { signal: wtCtrl.signal, name: "mid" })
    .catch(function (e) { wtAbortErr = e; });
  wtCtrl.abort(new Error("mid-cancel"));
  await wtAbortP;
  check("withTimeout: aborting a pending wrapper rejects with async/aborted",
    wtAbortErr instanceof b.safeAsync.SafeAsyncError && wtAbortErr.code === "async/aborted" &&
    wtAbortErr.cause instanceof Error && wtAbortErr.cause.message === "mid-cancel");

  // Signal present + underlying resolves → resolve path removes the abort listener.
  var wtLive = new AbortController();
  var wtLiveOk = await b.safeAsync.withTimeout(Promise.resolve("ok-with-signal"), 1000, { signal: wtLive.signal });
  check("withTimeout: resolves through with an un-aborted signal present", wtLiveOk === "ok-with-signal");

  // Signal present + underlying rejects → original error surfaces (reject path removes listener).
  var wtLive2 = new AbortController();
  var wtOrig = null;
  try { await b.safeAsync.withTimeout(Promise.reject(new Error("underlying-boom")), 1000, { signal: wtLive2.signal }); }
  catch (e) { wtOrig = e; }
  check("withTimeout: underlying rejection surfaces the original error (signal present, not aborted)",
    wtOrig && wtOrig.message === "underlying-boom" && wtOrig.code === undefined);

  // ---- sleep: bad ms, immediate-resolve, abort, unref ----
  var slBad = null;
  try { await b.safeAsync.sleep("nope"); } catch (e) { slBad = e; }
  check("sleep: non-number ms rejects with async/bad-arg",
    slBad instanceof b.safeAsync.SafeAsyncError && slBad.code === "async/bad-arg");
  var slNaN = null;
  try { await b.safeAsync.sleep(NaN); } catch (e) { slNaN = e; }
  check("sleep: NaN ms rejects with async/bad-arg", slNaN && slNaN.code === "async/bad-arg");
  var slInf = null;
  try { await b.safeAsync.sleep(Infinity); } catch (e) { slInf = e; }
  check("sleep: Infinity ms rejects with async/bad-arg", slInf && slInf.code === "async/bad-arg");

  var slZero = await b.safeAsync.sleep(0);
  check("sleep: ms<=0 resolves immediately", slZero === undefined);
  var slNeg = await b.safeAsync.sleep(-100);
  check("sleep: negative ms resolves immediately", slNeg === undefined);

  var slPre = new AbortController();
  slPre.abort(new Error("sleep-pre"));
  var slPreErr = null;
  try { await b.safeAsync.sleep(1000, { signal: slPre.signal }); } catch (e) { slPreErr = e; }
  check("sleep: pre-aborted signal rejects with async/aborted before start",
    slPreErr instanceof b.safeAsync.SafeAsyncError && slPreErr.code === "async/aborted" &&
    slPreErr.cause instanceof Error && slPreErr.cause.message === "sleep-pre");

  // Resolve with a live (un-aborted) signal present exercises the resolve-path
  // removeEventListener branch; unref:true exercises the timer.unref() branch.
  var slLive = new AbortController();
  var slOk = await b.safeAsync.sleep(15, { signal: slLive.signal });
  check("sleep: resolves after the delay with an un-aborted signal present", slOk === undefined);
  // unref:true means the timer alone can't hold the event loop open, so a
  // bare `await` would let Node exit before it resolves — hold the loop with
  // a ref'd poller (waitUntil) and confirm the unref'd sleep still fires.
  var slUnrefResolved = false;
  b.safeAsync.sleep(15, { unref: true }).then(function () { slUnrefResolved = true; });
  await waitUntil(function () { return slUnrefResolved; }, {
    timeoutMs: 5000,
    label: "safe-async sleep: unref:true timer resolves while the loop is held",
  });
  check("sleep: unref:true still resolves (loop held by a ref'd poller)", slUnrefResolved === true);

  // Abort mid-sleep → async/aborted (cause = signal reason).
  var slCtrl = new AbortController();
  var slAbortErr = null;
  var slAbortP = b.safeAsync.sleep(5000, { signal: slCtrl.signal }).catch(function (e) { slAbortErr = e; });
  slCtrl.abort(new Error("sleep-mid"));
  await slAbortP;
  check("sleep: aborting mid-sleep rejects with async/aborted",
    slAbortErr instanceof b.safeAsync.SafeAsyncError && slAbortErr.code === "async/aborted" &&
    slAbortErr.cause instanceof Error && slAbortErr.cause.message === "sleep-mid");

  // ---- safeAwait: [error, value] tuple, never throws ----
  var saOk = await b.safeAsync.safeAwait(Promise.resolve(99));
  check("safeAwait: resolved promise → [null, value]", saOk[0] === null && saOk[1] === 99);
  var saErr = await b.safeAsync.safeAwait(Promise.reject(new Error("await-fail")));
  check("safeAwait: rejected promise → [error, null]",
    saErr[0] instanceof Error && saErr[0].message === "await-fail" && saErr[1] === null);

  // ---- safeInvoke: happy path, missing callback, nested onError-throws ----
  var siSeen = null;
  b.safeAsync.safeInvoke(function (p) { siSeen = p; }, { k: "v" });
  check("safeInvoke: calls the callback with the payload", siSeen && siSeen.k === "v");
  var siNoop = false;
  try { b.safeAsync.safeInvoke(null, { k: "v" }); siNoop = true; } catch (_e) { siNoop = false; }
  check("safeInvoke: a non-function callback is a silent no-op", siNoop === true);
  // callback throws AND onError throws → nested catch must swallow (never bubbles).
  var siNestedBubbled = false;
  try {
    b.safeAsync.safeInvoke(
      function () { throw new Error("cb-boom"); },
      { k: "v" },
      function () { throw new Error("onError-boom"); }
    );
  } catch (_e) { siNestedBubbled = true; }
  check("safeInvoke: a throwing onError does not bubble (nested catch swallows)", siNestedBubbled === false);

  // ---- Mutex ----
  check("safeAsync.Mutex is a constructor", typeof b.safeAsync.Mutex === "function");
  var mtx = new b.safeAsync.Mutex();
  check("Mutex: not held initially", mtx.isHeld() === false && mtx.pendingCount() === 0);
  await mtx.acquire();
  check("Mutex: held after acquire", mtx.isHeld() === true);
  var mtxSecondGot = false;
  var mtxSecond = mtx.acquire().then(function () { mtxSecondGot = true; });
  check("Mutex: a second acquire while held queues (pendingCount 1)", mtx.pendingCount() === 1);
  mtx.release();                       // hands the lock to the queued waiter
  await mtxSecond;
  check("Mutex: release hands the lock to the queued waiter", mtxSecondGot === true);
  mtx.release();
  check("Mutex: fully released after last release", mtx.isHeld() === false);

  var mtxRelErr = null;
  try { mtx.release(); } catch (e) { mtxRelErr = e; }
  check("Mutex: release on an unheld mutex throws async/bad-release",
    mtxRelErr instanceof b.safeAsync.SafeAsyncError && mtxRelErr.code === "async/bad-release");

  var mtx2 = new b.safeAsync.Mutex();
  await mtx2.acquire();
  var mtxPre = new AbortController();
  mtxPre.abort(new Error("mtx-pre"));
  var mtxPreErr = null;
  try { await mtx2.acquire({ signal: mtxPre.signal }); } catch (e) { mtxPreErr = e; }
  check("Mutex: acquire while held with a pre-aborted signal rejects async/aborted",
    mtxPreErr instanceof b.safeAsync.SafeAsyncError && mtxPreErr.code === "async/aborted" &&
    mtxPreErr.cause instanceof Error && mtxPreErr.cause.message === "mtx-pre");

  // A live signal that aborts WHILE the acquirer waits removes it from the queue.
  var mtxWaitCtrl = new AbortController();
  var mtxWaitErr = null;
  var mtxWaitP = mtx2.acquire({ signal: mtxWaitCtrl.signal }).catch(function (e) { mtxWaitErr = e; });
  check("Mutex: signal-bearing waiter queued before abort", mtx2.pendingCount() === 1);
  mtxWaitCtrl.abort(new Error("mtx-wait-cancel"));
  await mtxWaitP;
  check("Mutex: aborting a queued waiter rejects async/aborted and dequeues it",
    mtxWaitErr instanceof b.safeAsync.SafeAsyncError && mtxWaitErr.code === "async/aborted" &&
    mtx2.pendingCount() === 0);

  // A live signal that never aborts: release hands off and removes its abort listener.
  var mtxSigCtrl = new AbortController();
  var mtxSigGot = false;
  var mtxSigP = mtx2.acquire({ signal: mtxSigCtrl.signal }).then(function () { mtxSigGot = true; });
  check("Mutex: second signal-bearing waiter queued", mtx2.pendingCount() === 1);
  mtx2.release();
  await mtxSigP;
  check("Mutex: release hands off to a signal-bearing waiter (listener removed)", mtxSigGot === true);
  mtx2.release();
  check("Mutex: mtx2 released after handoff drain", mtx2.isHeld() === false);

  var mtx3 = new b.safeAsync.Mutex();
  var reThrew = null;
  try { await mtx3.runExclusive(function () { throw new Error("exclusive-boom"); }); }
  catch (e) { reThrew = e; }
  check("Mutex: runExclusive propagates the fn throw", reThrew && reThrew.message === "exclusive-boom");
  check("Mutex: runExclusive releases the lock on throw (finally)", mtx3.isHeld() === false);
  var reVal = await mtx3.runExclusive(function () { return "exclusive-ok"; });
  check("Mutex: runExclusive returns the fn value and releases", reVal === "exclusive-ok" && mtx3.isHeld() === false);

  // ---- Semaphore ----
  check("safeAsync.Semaphore is a constructor", typeof b.safeAsync.Semaphore === "function");
  function semRejects(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("Semaphore: rejects " + label,
      threw instanceof b.safeAsync.SafeAsyncError && threw.code === "async/bad-arg");
  }
  semRejects("limit 0",        function () { return new b.safeAsync.Semaphore(0); });
  semRejects("limit negative", function () { return new b.safeAsync.Semaphore(-1); });
  semRejects("limit float",    function () { return new b.safeAsync.Semaphore(2.5); });
  semRejects("limit string",   function () { return new b.safeAsync.Semaphore("2"); });

  var sem = new b.safeAsync.Semaphore(2);
  check("Semaphore: inFlight()/pendingCount() start at 0", sem.inFlight() === 0 && sem.pendingCount() === 0);
  await sem.acquire();
  await sem.acquire();
  check("Semaphore: inFlight() reflects held slots", sem.inFlight() === 2 && sem.pendingCount() === 0);
  var semThirdGot = false;
  var semThird = sem.acquire().then(function () { semThirdGot = true; });
  check("Semaphore: over-limit acquire waits (pendingCount 1)", sem.pendingCount() === 1);
  sem.release();                       // hands a slot to the queued waiter
  await semThird;
  check("Semaphore: release hands a slot to the queued waiter", semThirdGot === true);
  sem.release();
  sem.release();
  check("Semaphore: inFlight() back to 0 after draining", sem.inFlight() === 0);

  var semRelErr = null;
  try { sem.release(); } catch (e) { semRelErr = e; }
  check("Semaphore: release on an idle semaphore throws async/bad-release",
    semRelErr instanceof b.safeAsync.SafeAsyncError && semRelErr.code === "async/bad-release");

  var sem1 = new b.safeAsync.Semaphore(1);
  await sem1.acquire();
  var semPre = new AbortController();
  semPre.abort(new Error("sem-pre"));
  var semPreErr = null;
  try { await sem1.acquire({ signal: semPre.signal }); } catch (e) { semPreErr = e; }
  check("Semaphore: at-limit acquire with a pre-aborted signal rejects async/aborted",
    semPreErr instanceof b.safeAsync.SafeAsyncError && semPreErr.code === "async/aborted" &&
    semPreErr.cause instanceof Error && semPreErr.cause.message === "sem-pre");

  var semWaitCtrl = new AbortController();
  var semWaitErr = null;
  var semWaitP = sem1.acquire({ signal: semWaitCtrl.signal }).catch(function (e) { semWaitErr = e; });
  check("Semaphore: signal-bearing waiter queued before abort", sem1.pendingCount() === 1);
  semWaitCtrl.abort(new Error("sem-wait-cancel"));
  await semWaitP;
  check("Semaphore: aborting a queued waiter rejects async/aborted and dequeues it",
    semWaitErr instanceof b.safeAsync.SafeAsyncError && semWaitErr.code === "async/aborted" &&
    sem1.pendingCount() === 0);

  var semSigCtrl = new AbortController();
  var semSigGot = false;
  var semSigP = sem1.acquire({ signal: semSigCtrl.signal }).then(function () { semSigGot = true; });
  check("Semaphore: second signal-bearing waiter queued", sem1.pendingCount() === 1);
  sem1.release();
  await semSigP;
  check("Semaphore: release hands off to a signal-bearing waiter (listener removed)", semSigGot === true);
  sem1.release();
  check("Semaphore: sem1 drained", sem1.inFlight() === 0);

  var sem2 = new b.safeAsync.Semaphore(1);
  var swThrew = null;
  try { await sem2.runWith(function () { throw new Error("runwith-boom"); }); }
  catch (e) { swThrew = e; }
  check("Semaphore: runWith propagates the fn throw", swThrew && swThrew.message === "runwith-boom");
  check("Semaphore: runWith releases on throw (finally)", sem2.inFlight() === 0);
  var swVal = await sem2.runWith(function () { return "runwith-ok"; });
  check("Semaphore: runWith returns the fn value and releases", swVal === "runwith-ok" && sem2.inFlight() === 0);

  // ---- Once ----
  check("safeAsync.Once is a constructor", typeof b.safeAsync.Once === "function");
  var onceBadErr = null;
  try { new b.safeAsync.Once("not-a-fn"); } catch (e) { onceBadErr = e; }
  check("Once: a non-function argument throws async/bad-arg",
    onceBadErr instanceof b.safeAsync.SafeAsyncError && onceBadErr.code === "async/bad-arg");

  var onceCalls = 0;
  var once = new b.safeAsync.Once(function () { onceCalls += 1; return "init-result"; });
  check("Once: hasInvoked() is false before the first invoke", once.hasInvoked() === false);
  var oncePromises = await Promise.all([once.invoke(), once.invoke(), once.invoke()]);
  check("Once: concurrent invokes run the fn exactly once", onceCalls === 1);
  check("Once: every caller receives the same result",
    oncePromises.join(",") === "init-result,init-result,init-result");
  check("Once: hasInvoked() is true after invoke", once.hasInvoked() === true);
  once.reset();
  check("Once: hasInvoked() is false again after reset", once.hasInvoked() === false);
  await once.invoke();
  check("Once: invoke after reset runs the fn again", onceCalls === 2);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
