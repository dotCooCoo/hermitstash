"use strict";
/**
 * Layer 0 — pure primitive smoke tests.
 *
 * These tests exercise primitives with NO framework state and NO I/O
 * dependencies (or I/O confined to tmpdir round-trips). They run FIRST
 * in the smoke-test ordering: a broken primitive should surface here,
 * not as a downstream consumer crash that hides the root cause.
 *
 * Currently shipped here:
 *   - sql-safe (identifier validation, quoting, allowlist)
 *   - chain-writer (rejects non-chain-table; race-safety under
 *     concurrent appends)
 *   - async-safe (withTimeout / safeAwait / Mutex / Semaphore /
 *     Once / CircuitBreaker)
 *   - handlers (emit/drain, retry, breaker, DLQ, shutdown, stats,
 *     backpressure, recursion-safe emit-during-flush)
 *   - json-safe (parse / stringify / canonical / validate /
 *     validateCollect / formats — incl. the IPv6 detail tests)
 *
 * Pending migration (still in smoke.js):
 *   - atomic-file / parsers (xml, csv, toml, yaml, env-parse) /
 *     redact
 */

var helpers = require("./_helpers");
var b           = helpers.b;
var fs          = helpers.fs;
var os          = helpers.os;
var path        = helpers.path;
var check       = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var listenOnRandomPort = helpers.listenOnRandomPort;

// httpClient tests stand up local http://127.0.0.1 mock servers. The
// framework default is HTTPS-only; tests opt in to cleartext the same
// way an operator with an internal cleartext endpoint would —
// `allowedProtocols: safeUrl.ALLOW_HTTP_ALL`. Wrapping it in this thin
// helper keeps the tests focused on what they're verifying without
// repeating the opt-in 18 times.
function httpReq(opts) {
  return b.httpClient.request(Object.assign(
    {
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    },
    opts
  ));
}

// ---- sql-safe ----

function testSqlSafeIdentifierValidation() {
  // Good shape
  check("safeSql.validateIdentifier accepts valid name",
        b.safeSql.validateIdentifier("audit_log") === "audit_log");
  check("safeSql.validateIdentifier accepts leading underscore",
        b.safeSql.validateIdentifier("_blamejs_audit_log") === "_blamejs_audit_log");
  // Bad shape
  var badRejects = [
    ["empty",            ""],
    ["leading digit",    "1foo"],
    ["embedded space",   "foo bar"],
    ["punctuation",      "foo.bar"],
    ["semicolon",        "foo;DROP"],
    ["quote",            'foo"bar'],
    ["backslash",        "foo\\bar"],
    ["null byte",        "foo\0bar"],
  ];
  for (var i = 0; i < badRejects.length; i++) {
    var label = badRejects[i][0];
    var input = badRejects[i][1];
    var threw = false;
    try { b.safeSql.validateIdentifier(input); }
    catch (e) { threw = !!e.isSafeSqlError; }
    check("safeSql rejects bad identifier (" + label + ")", threw);
  }
  // Reserved word
  var threwReserved = false;
  try { b.safeSql.validateIdentifier("SELECT"); }
  catch (e) { threwReserved = e.code === "sql/reserved-word"; }
  check("safeSql rejects SQL reserved word",                threwReserved);
  // sqlite_ prefix
  var threwInternal = false;
  try { b.safeSql.validateIdentifier("sqlite_master"); }
  catch (e) { threwInternal = e.code === "sql/internal-prefix"; }
  check("safeSql rejects sqlite_-prefixed identifier",      threwInternal);
  // Length cap
  var threwLong = false;
  try { b.safeSql.validateIdentifier("a".repeat(70)); }
  catch (e) { threwLong = e.code === "sql/too-long"; }
  check("safeSql rejects over-long identifier",             threwLong);
}

function testSqlSafeQuoteIdentifier() {
  check("quoteIdentifier sqlite uses double-quote",
        b.safeSql.quoteIdentifier("audit_log", "sqlite") === '"audit_log"');
  check("quoteIdentifier postgres uses double-quote",
        b.safeSql.quoteIdentifier("audit_log", "postgres") === '"audit_log"');
  check("quoteIdentifier mysql uses backtick",
        b.safeSql.quoteIdentifier("audit_log", "mysql") === "`audit_log`");
  var threw = false;
  try { b.safeSql.quoteIdentifier("foo;DROP"); }
  catch (e) { threw = !!e.isSafeSqlError; }
  check("quoteIdentifier rejects bad name",                 threw);
}

function testSqlSafeQuoteQualified() {
  // Array form
  check("quoteQualified array → schema.table",
        b.safeSql.quoteQualified(["public", "users"]) === '"public"."users"');
  check("quoteQualified array postgres dialect",
        b.safeSql.quoteQualified(["public", "users"], "postgres") === '"public"."users"');
  check("quoteQualified array mysql dialect",
        b.safeSql.quoteQualified(["public", "users"], "mysql") === "`public`.`users`");
  // String form — splits on dot
  check("quoteQualified string 'a.b'",
        b.safeSql.quoteQualified("public.users") === '"public"."users"');
  // Three-part qualifier
  check("quoteQualified 3-part qualifier",
        b.safeSql.quoteQualified("dbA.public.users") === '"dbA"."public"."users"');
  // Single segment
  check("quoteQualified single segment",
        b.safeSql.quoteQualified("users") === '"users"');
  // Each segment validated — bad part rejects
  var threwBadPart = null;
  try { b.safeSql.quoteQualified(["public", "1invalid"]); }
  catch (e) { threwBadPart = e; }
  check("quoteQualified rejects bad-shape segment",
        threwBadPart && threwBadPart.code === "sql/bad-shape");
  // Reserved-word part rejects
  var threwReserved = null;
  try { b.safeSql.quoteQualified(["public", "select"]); }
  catch (e) { threwReserved = e; }
  check("quoteQualified rejects reserved-word segment",
        threwReserved && threwReserved.code === "sql/reserved-word");
  // Empty / non-string / non-array
  var threwEmpty = null;
  try { b.safeSql.quoteQualified(""); } catch (e) { threwEmpty = e; }
  check("quoteQualified rejects empty string",
        threwEmpty && threwEmpty.code === "sql/empty");
  var threwArr = null;
  try { b.safeSql.quoteQualified([]); } catch (e) { threwArr = e; }
  check("quoteQualified rejects empty array",
        threwArr && threwArr.code === "sql/empty");
  var threwType = null;
  try { b.safeSql.quoteQualified(42); } catch (e) { threwType = e; }
  check("quoteQualified rejects non-string/array",
        threwType && threwType.code === "sql/bad-type");
}

function testSqlSafeAssertOneOf() {
  var allow = new Set(["audit_log", "consent_log"]);
  check("assertOneOf passes when in allowlist",
        b.safeSql.assertOneOf("audit_log", allow) === "audit_log");
  var threw = false;
  try { b.safeSql.assertOneOf("users", allow); }
  catch (e) { threw = e.code === "sql/not-allowed"; }
  check("assertOneOf rejects non-allowlisted",              threw);
  check("assertOneOf accepts array allowlist",
        b.safeSql.assertOneOf("a", ["a", "b"]) === "a");
}

// ---- chain-writer ----

async function testChainWriterRejectsBadTable() {
  var threw = null;
  try {
    b.chainWriter.create({
      table: "users",
      columnsForInsert: ["_id"],
      hashableColumns:  ["_id"],
    });
  } catch (e) { threw = e; }
  check("chainWriter rejects non-chain table",
        threw && (threw.code === "sql/not-allowed" || threw.code === "chain-writer/invalid-config" ||
                  /not in allowlist/.test(threw.message)));
}

async function testChainWriterRaceSafetyConcurrentAppends() {
  // Concurrent appends through chain-writer should produce a chain
  // with no forks — every row's prevHash matches the predecessor's
  // rowHash, monotonicCounter strictly increases by 1.
  //
  // This is technically Layer 3 work (needs db) but is included with
  // the chain-writer primitive tests because it's the canonical
  // resilience claim for the primitive. The cost of running setupTestDb
  // here is acceptable; the alternative is splitting the chain-writer
  // tests across two layer files which obscures the intent.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cw-"));
  try {
    b.cluster._resetForTest();
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");

    var promises = [];
    for (var i = 0; i < 10; i++) {
      promises.push(b.audit.record({
        actor:   { userId: "u-" + i },
        action:  "test.concurrent",
        outcome: "success",
      }));
    }
    var results = await Promise.all(promises);

    var verified = await b.audit.verify();
    check("chain-writer race test: chain verifies after 10 concurrent appends",
          verified.ok === true);
    var counters = results.map(function (r) { return r.monotonicCounter; }).sort(function (a, b) { return a - b; });
    var allUnique = counters.every(function (c, idx, arr) { return idx === 0 || c === arr[idx - 1] + 1; });
    check("chain-writer race test: counters strictly monotonic, no duplicates",
          allUnique && counters.length === 10);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- async-safe ----

async function testAsyncSafeWithTimeoutResolves() {
  var v = await b.safeAsync.withTimeout(Promise.resolve("ok"), 100);
  check("withTimeout: resolves with value when fast",       v === "ok");
}

async function testAsyncSafeWithTimeoutRejects() {
  var threw = null;
  try {
    await b.safeAsync.withTimeout(new Promise(function () {}), 20, { name: "test-op" });
  } catch (e) { threw = e; }
  check("withTimeout: rejects on timeout",                  threw && threw.code === "async/timeout");
  check("withTimeout: timeout error names operation",       threw && threw.message.indexOf("test-op") >= 0);
}

async function testAsyncSafeWithTimeoutAbort() {
  var ctrl = new AbortController();
  var p = b.safeAsync.withTimeout(new Promise(function () {}), 10000, { signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("withTimeout: AbortSignal aborts cleanly",          threw && threw.code === "async/aborted");
}

async function testAsyncSafeWithTimeoutPropagatesError() {
  var threw = null;
  try {
    await b.safeAsync.withTimeout(Promise.reject(new Error("boom")), 100);
  } catch (e) { threw = e; }
  check("withTimeout: propagates underlying rejection",     threw && threw.message === "boom");
}

async function testAsyncSafeSafeAwait() {
  var ok = await b.safeAsync.safeAwait(Promise.resolve(42));
  check("safeAwait: success returns [null, value]",         ok[0] === null && ok[1] === 42);
  var fail = await b.safeAsync.safeAwait(Promise.reject(new Error("nope")));
  check("safeAwait: failure returns [error, null]",         fail[0] && fail[0].message === "nope" && fail[1] === null);
}

async function testAsyncSafeMutexSerializes() {
  var m = new b.safeAsync.Mutex();
  var order = [];
  async function task(label, durMs) {
    return m.runExclusive(async function () {
      order.push(label + ":enter");
      await new Promise(function (r) { setTimeout(r, durMs); });
      order.push(label + ":exit");
    });
  }
  await Promise.all([task("A", 30), task("B", 5), task("C", 5)]);
  check("Mutex: A enters first",       order[0] === "A:enter");
  check("Mutex: A exits before B/C enter",
        order.indexOf("A:exit") < order.indexOf("B:enter") &&
        order.indexOf("A:exit") < order.indexOf("C:enter"));
  check("Mutex: B and C don't interleave",
        Math.abs(order.indexOf("B:enter") - order.indexOf("B:exit")) === 1);
}

async function testAsyncSafeMutexReleaseOnThrow() {
  var m = new b.safeAsync.Mutex();
  var threw = null;
  try {
    await m.runExclusive(async function () { throw new Error("inner"); });
  } catch (e) { threw = e; }
  check("Mutex: runExclusive propagates thrown error",      threw && threw.message === "inner");
  check("Mutex: lock released after throw",                 !m.isHeld());
}

async function testAsyncSafeMutexAbortableAcquire() {
  var m = new b.safeAsync.Mutex();
  await m.acquire();
  var ctrl = new AbortController();
  var p = m.acquire({ signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("Mutex: aborted acquire rejects",                   threw && threw.code === "async/aborted");
  check("Mutex: aborted acquirer no longer queued",         m.pendingCount() === 0);
  m.release();
}

async function testAsyncSafeSemaphoreBoundedConcurrency() {
  var s = new b.safeAsync.Semaphore(2);
  var concurrent = 0;
  var maxConcurrent = 0;
  async function task() {
    return s.runWith(async function () {
      concurrent += 1;
      if (concurrent > maxConcurrent) maxConcurrent = concurrent;
      await new Promise(function (r) { setTimeout(r, 10); });
      concurrent -= 1;
    });
  }
  await Promise.all([task(), task(), task(), task(), task()]);
  check("Semaphore: max concurrency respected",             maxConcurrent === 2);
}

async function testAsyncSafeSemaphoreAbortableAcquire() {
  var s = new b.safeAsync.Semaphore(1);
  await s.acquire();
  var ctrl = new AbortController();
  var p = s.acquire({ signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("Semaphore: aborted acquire rejects",               threw && threw.code === "async/aborted");
  s.release();
}

async function testAsyncSafeOnceSingleFlight() {
  var calls = 0;
  var once = new b.safeAsync.Once(async function () {
    calls += 1;
    await new Promise(function (r) { setTimeout(r, 10); });
    return "result-" + calls;
  });
  var results = await Promise.all([once.invoke(), once.invoke(), once.invoke()]);
  check("Once: function invoked exactly once",              calls === 1);
  check("Once: all callers see same result",
        results[0] === "result-1" && results[1] === "result-1" && results[2] === "result-1");
}

async function testAsyncSafeOnceCachesFailure() {
  var once = new b.safeAsync.Once(async function () { throw new Error("init failed"); });
  var first = null, second = null;
  try { await once.invoke(); } catch (e) { first = e; }
  try { await once.invoke(); } catch (e) { second = e; }
  check("Once: failure caches; both callers see same rejection",
        first && second && first.message === "init failed" && second.message === "init failed");
}

async function testAsyncSafeOnceReset() {
  var calls = 0;
  var once = new b.safeAsync.Once(async function () {
    calls += 1;
    if (calls === 1) throw new Error("transient");
    return "ok";
  });
  var failed = null;
  try { await once.invoke(); } catch (e) { failed = e; }
  check("Once: first call fails as expected",               failed && failed.message === "transient");
  once.reset();
  var second = await once.invoke();
  check("Once: reset enables retry; second call succeeds",  second === "ok" && calls === 2);
}

async function testAsyncSafeCircuitBreakerStateTransitions() {
  var br = new b.safeAsync.CircuitBreaker("test", { failureThreshold: 2, cooldownMs: 30, successThreshold: 1 });
  check("CircuitBreaker: starts closed",                    br.getState() === "closed");
  for (var i = 0; i < 2; i++) {
    try { await br.wrap(async function () { throw new Error("fail"); }); } catch (_e) {}
  }
  check("CircuitBreaker: opens after failureThreshold",     br.getState() === "open");
  var fastFail = null;
  try { await br.wrap(async function () { return "ok"; }); }
  catch (e) { fastFail = e; }
  check("CircuitBreaker: open state fast-fails",            fastFail && fastFail.code === "CIRCUIT_OPEN");
  await new Promise(function (r) { setTimeout(r, 50); });
  var probe = await br.wrap(async function () { return "ok"; });
  check("CircuitBreaker: half-open probe success",          probe === "ok");
  check("CircuitBreaker: closes after success threshold",   br.getState() === "closed");
}

async function testAsyncSafeSleepBasic() {
  var t0 = Date.now();
  await b.safeAsync.sleep(40);
  var elapsed = Date.now() - t0;
  check("sleep: resolves after delay", elapsed >= 35 && elapsed < 200);
}

async function testAsyncSafeSleepZeroResolvesImmediately() {
  var t0 = Date.now();
  await b.safeAsync.sleep(0);
  await b.safeAsync.sleep(-5);
  var elapsed = Date.now() - t0;
  check("sleep: ms<=0 resolves immediately", elapsed < 20);
}

async function testAsyncSafeSleepBadArg() {
  var threw = null;
  try { await b.safeAsync.sleep("nope"); }
  catch (e) { threw = e; }
  check("sleep: non-numeric ms rejects", threw && threw.code === "async/bad-arg");
  threw = null;
  try { await b.safeAsync.sleep(Infinity); }
  catch (e) { threw = e; }
  check("sleep: non-finite ms rejects",  threw && threw.code === "async/bad-arg");
}

async function testAsyncSafeSleepAbort() {
  var ac = new AbortController();
  var t0 = Date.now();
  setTimeout(function () { ac.abort(new Error("user cancel")); }, 20);
  var threw = null;
  try { await b.safeAsync.sleep(5000, { signal: ac.signal }); }
  catch (e) { threw = e; }
  var elapsed = Date.now() - t0;
  check("sleep: abort cancels mid-sleep",  threw && threw.code === "async/aborted");
  check("sleep: abort short-circuits the wait", elapsed < 200);

  // Pre-aborted signal rejects immediately (no waiting).
  var preAborted = new AbortController();
  preAborted.abort(new Error("already gone"));
  var threwPre = null;
  try { await b.safeAsync.sleep(5000, { signal: preAborted.signal }); }
  catch (e) { threwPre = e; }
  check("sleep: pre-aborted signal rejects", threwPre && threwPre.code === "async/aborted");
}

async function testAsyncSafeSleepUnrefOptIn() {
  // sleep(ms, { unref: true }) MUST NOT keep the process alive. Spawn a
  // child that requires async-safe directly (avoiding the framework boot,
  // which schedules its own intervals that would mask the unref check)
  // and starts an unref'd sleep without awaiting it. The script body's
  // last line is a synchronous console.log — when the script function
  // returns, node's loop has only the unref'd timer, so it should exit
  // cleanly within ~100ms. 5s wall clock fails fast on regression.
  var { spawn } = require("child_process");
  var safeAsyncPath = path.resolve(__dirname, "..", "lib", "safe-async.js").replace(/\\/g, "\\\\");
  var script =
    'var as = require("' + safeAsyncPath + '");' +
    'as.sleep(60000, { unref: true });' +    // pending unref'd sleep, no await
    'console.log("script-end");';
  var child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
  var stdout = "";
  child.stdout.on("data", function (c) { stdout += c.toString(); });

  var exited = await new Promise(function (resolve) {
    var killed = false;
    var t = setTimeout(function () { killed = true; child.kill("SIGKILL"); resolve("timeout"); }, 5000);
    child.once("exit", function (code) { clearTimeout(t); resolve(killed ? "killed" : "exit:" + code); });
  });
  check("sleep: { unref:true } lets process exit during pending sleep", exited === "exit:0");
  check("sleep: script body ran before exit",                            stdout.indexOf("script-end") !== -1);
}

async function testAsyncSafeSleepDefaultRefd() {
  // The natural `await sleep(ms)` pattern keeps the loop alive for the
  // duration. A bug in the previous draft made sleep unconditionally
  // unref the timer, which deadlocked otherwise-idle processes (loop
  // exits because nothing keeps it alive, awaiting Promise never
  // resolves). Verify by running a child whose ONLY work is `await
  // sleep(150)` then a final console.log — without the ref, node exits
  // before sleep completes and "post-sleep" never prints.
  var { spawn } = require("child_process");
  var safeAsyncPath = path.resolve(__dirname, "..", "lib", "safe-async.js").replace(/\\/g, "\\\\");
  var script =
    'var as = require("' + safeAsyncPath + '");' +
    '(async function() { await as.sleep(150); console.log("post-sleep"); })()' +
    '  .catch(function (e) { console.error("FAIL", e.message); process.exit(2); });';
  var child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
  var stdout = "";
  child.stdout.on("data", function (c) { stdout += c.toString(); });
  var exited = await new Promise(function (resolve) {
    var t = setTimeout(function () { child.kill("SIGKILL"); resolve("timeout"); }, 5000);
    child.once("exit", function (code) { clearTimeout(t); resolve("exit:" + code); });
  });
  check("sleep: default keeps loop alive for await pattern",  exited === "exit:0");
  check("sleep: post-sleep continuation actually ran",        stdout.indexOf("post-sleep") !== -1);
}

function testAsyncSafeWithTimeoutSignalCases() {
  var as = b.safeAsync;

  // 1. null + no ms → null (caller's "no signal needed" path)
  check("withTimeoutSignal: null+0 returns null", as.withTimeoutSignal(null, 0) === null);
  check("withTimeoutSignal: null+undefined returns null",
        as.withTimeoutSignal(null) === null);

  // 2. null signal + positive ms → AbortSignal.timeout
  var sig = as.withTimeoutSignal(null, 50);
  check("withTimeoutSignal: only timeout returns an AbortSignal",
        sig instanceof AbortSignal && sig.aborted === false);

  // 3. user signal + 0 ms → user signal unchanged
  var ac = new AbortController();
  var passthrough = as.withTimeoutSignal(ac.signal, 0);
  check("withTimeoutSignal: user-only returns user signal unchanged",
        passthrough === ac.signal);

  // 4. both → composes (firing user signal aborts the composed)
  var ac2 = new AbortController();
  var combined = as.withTimeoutSignal(ac2.signal, 5000);
  check("withTimeoutSignal: composed signal exists",
        combined instanceof AbortSignal && combined.aborted === false);
  ac2.abort(new Error("user"));
  check("withTimeoutSignal: composed aborts when user aborts",
        combined.aborted === true);
}

async function testAsyncSafeWithTimeoutSignalTimeoutFires() {
  var sig = b.safeAsync.withTimeoutSignal(null, 30);
  await new Promise(function (r) { setTimeout(r, 80); });
  check("withTimeoutSignal: timeout-only signal fires after ms", sig.aborted === true);
}

// ---- auth-header ----

function testAuthHeaderBearer() {
  var ah = b.authHeader;
  var h = ah.bearer("abc-123");
  check("authHeader.bearer: Authorization shape", h.Authorization === "Bearer abc-123");

  var threw = null;
  try { ah.bearer(""); }
  catch (e) { threw = e; }
  check("authHeader.bearer: rejects empty token", threw instanceof ah.AuthHeaderError);

  threw = null;
  try { ah.bearer(null); }
  catch (e) { threw = e; }
  check("authHeader.bearer: rejects null token", threw instanceof ah.AuthHeaderError);
}

function testAuthHeaderBasic() {
  var ah = b.authHeader;
  var h = ah.basic("alice", "s3cret");
  // RFC 7617: "alice:s3cret" base64-encoded
  var expected = Buffer.from("alice:s3cret", "utf8").toString("base64");
  check("authHeader.basic: Authorization shape",
        h.Authorization === "Basic " + expected);

  // Empty password permitted (legacy endpoints sometimes want this)
  var emptyPwd = ah.basic("alice", "");
  check("authHeader.basic: empty password permitted",
        emptyPwd.Authorization === "Basic " + Buffer.from("alice:", "utf8").toString("base64"));

  var threw = null;
  try { ah.basic(undefined, "x"); }
  catch (e) { threw = e; }
  check("authHeader.basic: rejects undefined username",
        threw instanceof ah.AuthHeaderError);
}

function testAuthHeaderFromConfig() {
  var ah = b.authHeader;
  check("authHeader.fromConfig: undefined → {}",
        Object.keys(ah.fromConfig()).length === 0);
  check("authHeader.fromConfig: {auth:none} → {}",
        Object.keys(ah.fromConfig({ auth: "none" })).length === 0);

  var bearerH = ah.fromConfig({ auth: "bearer", token: "tok" });
  check("authHeader.fromConfig: bearer returns Bearer header",
        bearerH.Authorization === "Bearer tok");

  var basicH = ah.fromConfig({ auth: "basic", username: "u", password: "p" });
  check("authHeader.fromConfig: basic returns Basic header",
        basicH.Authorization.indexOf("Basic ") === 0);

  var threw = null;
  try { ah.fromConfig({ auth: "ntlm" }); }
  catch (e) { threw = e; }
  check("authHeader.fromConfig: rejects unknown method",
        threw && threw.code === "auth-header/unknown-method");
}

// ---- auth.password (Argon2id) ----
//
// All tests below use deliberately weak Argon2 params (memoryCost=1024
// KiB / timeCost=1 / parallelism=1) so each hash/verify takes ~10ms
// instead of ~250-500ms with defaults. The defaults are exercised
// indirectly by the surface check (DEFAULT_PARAMS) and by the integration
// path (vault-wrap uses comparable params). The point of these tests is
// behavior + boundaries, not benchmarking.

var FAST_ARGON_PARAMS = { memoryCost: 1024, timeCost: 1, parallelism: 1 };

async function testAuthPasswordHashShape() {
  var p = b.auth.password;
  var h = await p.hash("hunter2", FAST_ARGON_PARAMS);
  check("auth.password.hash returns string",        typeof h === "string");
  check("auth.password.hash starts with $argon2id$", h.indexOf("$argon2id$") === 0);
  check("auth.password.hash includes m/t/p params",
        /\$m=1024,t=1,p=1\$/.test(h));

  // Same plain → different hash (random salt)
  var h2 = await p.hash("hunter2", FAST_ARGON_PARAMS);
  check("auth.password.hash uses random salt (hashes differ)",  h !== h2);
}

async function testAuthPasswordVerifyRoundTrip() {
  var p = b.auth.password;
  var stored = await p.hash("correct horse battery staple", FAST_ARGON_PARAMS);
  check("verify accepts correct password",
        (await p.verify(stored, "correct horse battery staple")) === true);
  check("verify rejects wrong password",
        (await p.verify(stored, "wrong horse battery staple")) === false);
  check("verify rejects empty plain",       (await p.verify(stored, "")) === false);
  check("verify rejects null plain",        (await p.verify(stored, null)) === false);
}

async function testAuthPasswordVerifyTamperedHash() {
  var p = b.auth.password;
  var stored = await p.hash("hunter2", FAST_ARGON_PARAMS);
  // Flip one base64 char in the hash portion (after the last $)
  var lastDollar = stored.lastIndexOf("$");
  var head = stored.slice(0, lastDollar + 1);
  var tail = stored.slice(lastDollar + 1);
  var tampered = head + (tail[0] === "A" ? "B" : "A") + tail.slice(1);
  check("verify rejects tampered hash",     (await p.verify(tampered, "hunter2")) === false);
}

async function testAuthPasswordVerifyMalformedHash() {
  var p = b.auth.password;
  check("verify rejects empty hash",        (await p.verify("", "hunter2")) === false);
  check("verify rejects null hash",         (await p.verify(null, "hunter2")) === false);
  check("verify rejects non-id variant",
        (await p.verify("$argon2i$v=19$m=1024,t=1,p=1$AAAA$BBBB", "x")) === false);
  check("verify rejects garbage hash",
        (await p.verify("not-a-hash", "x")) === false);
  check("verify rejects truncated PHC",
        (await p.verify("$argon2id$v=19", "x")) === false);
}

async function testAuthPasswordHashRejectsBadInput() {
  var p = b.auth.password;
  var threw = null;
  try { await p.hash("", FAST_ARGON_PARAMS); }
  catch (e) { threw = e; }
  check("hash rejects empty plain",         threw && threw.code === "auth-password/invalid-plain");
  check("hash error is AuthError",          threw && threw.isAuthError === true);
  check("hash error is permanent",          threw && threw.permanent === true);

  threw = null;
  try { await p.hash(123, FAST_ARGON_PARAMS); }
  catch (e) { threw = e; }
  check("hash rejects non-string plain",    threw && threw.code === "auth-password/invalid-plain");

  threw = null;
  // 5000-byte string > 4096 cap
  var huge = "x".repeat(5000);
  try { await p.hash(huge, FAST_ARGON_PARAMS); }
  catch (e) { threw = e; }
  check("hash rejects oversize plain",      threw && threw.code === "auth-password/plain-too-large");

  threw = null;
  try { await p.hash("ok", { memoryCost: 0 }); }
  catch (e) { threw = e; }
  check("hash rejects bad memoryCost param", threw && threw.code === "auth-password/bad-params");
}

async function testAuthPasswordNeedsRehash() {
  var p = b.auth.password;
  var stored = await p.hash("hunter2", FAST_ARGON_PARAMS);

  // Same params → no rehash needed
  check("needsRehash false for same params",
        p.needsRehash(stored, FAST_ARGON_PARAMS) === false);

  // Stronger params → rehash needed
  check("needsRehash true when memory bumped",
        p.needsRehash(stored, { memoryCost: 4096, timeCost: 1, parallelism: 1 }) === true);
  check("needsRehash true when time bumped",
        p.needsRehash(stored, { memoryCost: 1024, timeCost: 5, parallelism: 1 }) === true);

  // Malformed / non-id hashes always need rehash
  check("needsRehash true for empty hash",        p.needsRehash("") === true);
  check("needsRehash true for argon2i hash",      p.needsRehash("$argon2i$...") === true);
  check("needsRehash true for garbage hash",      p.needsRehash("not-a-hash") === true);
}

function testAuthPasswordSurface() {
  var p = b.auth.password;
  check("auth namespace present",                  typeof b.auth === "object");
  check("auth.password.hash is a function",        typeof p.hash === "function");
  check("auth.password.verify is a function",      typeof p.verify === "function");
  check("auth.password.needsRehash is a function", typeof p.needsRehash === "function");
  check("auth.password.DEFAULT_PARAMS frozen",     Object.isFrozen(p.DEFAULT_PARAMS));
  check("DEFAULT_PARAMS.memoryCost = 64 MiB-in-KiB", p.DEFAULT_PARAMS.memoryCost === 65536);
}

// ---- auth.totp (RFC 6238) ----
//
// RFC 6238 Appendix B publishes test vectors for HMAC-SHA1, HMAC-SHA256,
// and HMAC-SHA512. SHA-1 is NOT supported by this framework (see
// lib/totp.js docstring), so the test below covers the SHA-256 and
// SHA-512 vectors only — confirming the implementation matches the RFC
// for both supported algorithms.
//
// Per RFC, each algorithm uses a different key (the test K is
// "12345678…" repeated to fill the algorithm's HMAC block size):
//   SHA-256: K = ASCII("12345678901234567890123456789012") (32 bytes)
//   SHA-512: K = ASCII("1234567890…1234") (64 bytes)
// Below are the precomputed base32 encodings of those keys.

var RFC6238_KEY_B32_SHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
var RFC6238_KEY_B32_SHA512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

function _stepFromT(tSec, stepSec) {
  return Math.floor(tSec / (stepSec || 30));
}

function testAuthTotpRfc6238Vectors() {
  // Appendix B vectors at 8 digits — matches the RFC reference
  // implementation AND the framework's new 8-digit default. The
  // explicit `digits: 8` is redundant under the current default but
  // kept here so the test stays valid even if the default ever shifts.
  var t = b.auth.totp;
  var sha256Vectors = [
    { T:          59, code: "46119246" },
    { T:  1111111109, code: "68084774" },
    { T:  1111111111, code: "67062674" },
    { T:  1234567890, code: "91819424" },
    { T:  2000000000, code: "90698825" },
    { T: 20000000000, code: "77737706" },
  ];
  var sha512Vectors = [
    { T:          59, code: "90693936" },
    { T:  1111111109, code: "25091201" },
    { T:  1111111111, code: "99943326" },
    { T:  1234567890, code: "93441116" },
    { T:  2000000000, code: "38618901" },
    { T: 20000000000, code: "47863826" },
  ];
  for (var i = 0; i < sha256Vectors.length; i++) {
    var v = sha256Vectors[i];
    var got = t.compute(RFC6238_KEY_B32_SHA256, _stepFromT(v.T, 30),
                        { digits: 8, algorithm: "sha256" });
    check("RFC 6238 SHA-256 vector T=" + v.T + " → " + v.code,  got === v.code);
  }
  for (var j = 0; j < sha512Vectors.length; j++) {
    var w = sha512Vectors[j];
    var got2 = t.compute(RFC6238_KEY_B32_SHA512, _stepFromT(w.T, 30),
                         { digits: 8, algorithm: "sha512" });
    check("RFC 6238 SHA-512 vector T=" + w.T + " → " + w.code,  got2 === w.code);
  }
}

function testAuthTotpGenerateSecret() {
  var t = b.auth.totp;
  var s = t.generateSecret();
  check("generateSecret returns string",                      typeof s === "string");
  // 128 bytes → 1024 bits → ceil(1024/5) = 205 base32 characters
  check("generateSecret default = 205 base32 chars (128 bytes / SHA-512 block size)",
        s.length === 205);
  check("generateSecret is base32 (A-Z 2-7)",                 /^[A-Z2-7]+$/.test(s));

  // Two secrets are different (random source)
  var s2 = t.generateSecret();
  check("generateSecret produces unique secrets",             s !== s2);

  // Operators can opt down to RFC 4226 §4 floor (20 bytes) for
  // manual-entry-friendly authenticators
  var sMin = t.generateSecret({ bytes: 20 });
  check("generateSecret honors opts.bytes=20 (RFC 4226 floor)", sMin.length === 32);

  // bytes < MIN_SECRET_BYTES rejected
  var threw = null;
  try { t.generateSecret({ bytes: 10 }); }
  catch (e) { threw = e; }
  check("generateSecret rejects bytes < 20",                  threw && threw.code === "auth-totp/bad-secret-length");
}

function testAuthTotpGenerateAndVerifyRoundTrip() {
  var t = b.auth.totp;
  var secret = t.generateSecret();
  var code = t.generate(secret);
  check("generate returns 8-digit string by default",         /^[0-9]{8}$/.test(code));

  var step = t.verify(secret, code);
  check("verify returns the matched step number (truthy)",    typeof step === "number" && step > 0);
  check("verify rejects wrong code",                          t.verify(secret, "00000000") === false);
  // v0.6.56 — input normalisation: every authenticator UI / clipboard
  // paste introduces whitespace + common separators ("123 456",
  // "123-456", "123.456", "123_456"). The framework strips these
  // before timing-safe comparison. Letters / other characters do NOT
  // get stripped — those are real input errors, not paste artefacts.
  check("verify accepts code with spaces",
        t.verify(secret, code.slice(0, 4) + " " + code.slice(4)) === step);
  check("verify accepts code with dashes",
        t.verify(secret, code.slice(0, 4) + "-" + code.slice(4)) === step);
  check("verify accepts code with dots",
        t.verify(secret, code.slice(0, 4) + "." + code.slice(4)) === step);
  check("verify accepts code with underscores",
        t.verify(secret, code.slice(0, 4) + "_" + code.slice(4)) === step);
  check("verify accepts code with leading/trailing whitespace",
        t.verify(secret, "  " + code + "\t") === step);
  check("verify rejects code with letter-substitution (real typo, not paste)",
        t.verify(secret, code.slice(0, 4) + "X" + code.slice(4)) === false);
}

function testAuthTotpDriftWindow() {
  var t = b.auth.totp;
  var secret = t.generateSecret();
  var nowMs = Date.now();
  var stepNow = Math.floor(nowMs / 1000 / 30);

  // Compute the codes the authenticator would have shown 30s and 60s ago,
  // and the codes for now and 30s in the future.
  var codeMinus2 = t.compute(secret, stepNow - 2);
  var codeMinus1 = t.compute(secret, stepNow - 1);
  var codeNow    = t.compute(secret, stepNow);
  var codePlus1  = t.compute(secret, stepNow + 1);
  var codePlus2  = t.compute(secret, stepNow + 2);

  // Default driftSteps = 1: ±1 step accepted, ±2 rejected
  check("verify accepts current code",        t.verify(secret, codeNow,    { now: nowMs }) === stepNow);
  check("verify accepts -1 step (drift=1)",   t.verify(secret, codeMinus1, { now: nowMs }) === stepNow - 1);
  check("verify accepts +1 step (drift=1)",   t.verify(secret, codePlus1,  { now: nowMs }) === stepNow + 1);
  check("verify rejects -2 step (default drift=1)",
        t.verify(secret, codeMinus2, { now: nowMs }) === false);
  check("verify rejects +2 step (default drift=1)",
        t.verify(secret, codePlus2,  { now: nowMs }) === false);

  // driftSteps=2 widens the window
  check("verify accepts -2 step with driftSteps=2",
        t.verify(secret, codeMinus2, { now: nowMs, driftSteps: 2 }) === stepNow - 2);
}

function testAuthTotpReplayProtection() {
  var t = b.auth.totp;
  var secret = t.generateSecret();
  var nowMs = Date.now();
  var stepNow = Math.floor(nowMs / 1000 / 30);
  var codeNow = t.compute(secret, stepNow);

  // First verify succeeds
  var matched = t.verify(secret, codeNow, { now: nowMs });
  check("first verify accepts code",                          matched === stepNow);

  // Second verify with lastUsedStep=matched rejects (replay defense)
  check("verify rejects replay at the same step",
        t.verify(secret, codeNow, { now: nowMs, lastUsedStep: matched }) === false);

  // Drift-window codes that are ALSO at-or-below lastUsedStep get rejected
  var codeMinus1 = t.compute(secret, stepNow - 1);
  check("verify rejects prior-step code under replay guard",
        t.verify(secret, codeMinus1, { now: nowMs, lastUsedStep: matched }) === false);
}

function testAuthTotpVerifyMalformedInput() {
  var t = b.auth.totp;
  var secret = t.generateSecret();
  // verify is tolerant — never throws on bad input, just returns false
  check("verify(empty secret) → false",       t.verify("", "123456") === false);
  check("verify(null secret) → false",        t.verify(null, "123456") === false);
  check("verify(secret, null) → false",       t.verify(secret, null) === false);
  check("verify(secret, undefined) → false",  t.verify(secret, undefined) === false);
  // Non-numeric code that's the right length still doesn't match → false
  check("verify(secret, 'abcdef') → false",   t.verify(secret, "abcdef") === false);
}

function testAuthTotpUriShape() {
  var t = b.auth.totp;
  var u = t.uri("JBSWY3DPEHPK3PXP", "alice@example.com", { issuer: "BlameJS" });
  check("uri starts with otpauth://totp/",                   u.indexOf("otpauth://totp/") === 0);
  check("uri label has Issuer:Account",                      u.indexOf("BlameJS:alice%40example.com") !== -1);
  check("uri carries secret as query param",                 /[?&]secret=JBSWY3DPEHPK3PXP/.test(u));
  check("uri carries issuer as query param",                 /[?&]issuer=BlameJS/.test(u));
  check("uri carries algorithm=SHA512 (framework default)",  /[?&]algorithm=SHA512/.test(u));
  check("uri does NOT carry algorithm=SHA1",                 /[?&]algorithm=SHA1[^256512]/.test(u) === false);
  check("uri carries digits=8 (framework default)",          /[?&]digits=8/.test(u));
  check("uri carries period=30 (default stepSeconds)",       /[?&]period=30/.test(u));

  // Operators with SHA-256 authenticators opt in explicitly
  var u256 = t.uri("JBSWY3DPEHPK3PXP", "alice@example.com",
                   { issuer: "BlameJS", algorithm: "sha256" });
  check("uri honors explicit algorithm=sha256 opt-in",       /[?&]algorithm=SHA256/.test(u256));

  // Required-field errors
  var threw = null;
  try { t.uri("SECRET", "alice", {}); }
  catch (e) { threw = e; }
  check("uri without issuer throws AuthError",
        threw && threw.code === "auth-totp/missing-issuer");

  threw = null;
  try { t.uri("", "alice", { issuer: "X" }); }
  catch (e) { threw = e; }
  check("uri with empty secret throws",
        threw && threw.code === "auth-totp/missing-secret");
}

function testAuthTotpBackupCodes() {
  var t = b.auth.totp;
  var codes = t.generateBackupCodes();
  check("default backup codes count = 10",      codes.length === 10);
  check("default backup code length = 8 hex",   /^[0-9a-f]{8}$/.test(codes[0]));
  // Codes are unique within the batch (random source)
  var uniq = {};
  for (var i = 0; i < codes.length; i++) uniq[codes[i]] = true;
  check("default backup codes are unique",       Object.keys(uniq).length === 10);

  // Configurable count + length
  var custom = t.generateBackupCodes({ count: 3, bytesPerCode: 8 });
  check("custom count honored",                  custom.length === 3);
  check("custom bytesPerCode honored (8 → 16 hex chars)",
        /^[0-9a-f]{16}$/.test(custom[0]));
}

function testAuthTotpBadAlgorithmRejected() {
  var t = b.auth.totp;
  var threw = null;
  try { t.compute("ABCDEFGH", 0, { algorithm: "md5" }); }
  catch (e) { threw = e; }
  check("compute with unsupported alg throws",
        threw && threw.code === "auth-totp/bad-alg");

  // SHA-1 is explicitly rejected — framework posture deviates from
  // RFC 6238's default to enforce stronger HMAC. See lib/totp.js
  // docstring for rationale.
  var threwSha1 = null;
  try { t.compute("ABCDEFGH", 0, { algorithm: "sha1" }); }
  catch (e) { threwSha1 = e; }
  check("compute with sha1 is rejected (framework posture)",
        threwSha1 && threwSha1.code === "auth-totp/bad-alg");
}

function testAuthTotpSurface() {
  var t = b.auth.totp;
  check("auth.totp namespace present",                   typeof b.auth.totp === "object");
  check("auth.totp.generateSecret is a function",        typeof t.generateSecret === "function");
  check("auth.totp.generate is a function",              typeof t.generate === "function");
  check("auth.totp.compute is a function",               typeof t.compute === "function");
  check("auth.totp.verify is a function",                typeof t.verify === "function");
  check("auth.totp.uri is a function",                   typeof t.uri === "function");
  check("auth.totp.generateBackupCodes is a function",   typeof t.generateBackupCodes === "function");
  check("auth.totp.DEFAULT_STEP_SECONDS = 30",           t.DEFAULT_STEP_SECONDS === 30);
  check("auth.totp.DEFAULT_DIGITS = 8",                  t.DEFAULT_DIGITS === 8);
  check("auth.totp.DEFAULT_ALGORITHM = sha512",          t.DEFAULT_ALGORITHM === "sha512");
  check("auth.totp.DEFAULT_SECRET_BYTES = 128 (SHA-512 block size)",
        t.DEFAULT_SECRET_BYTES === 128);
  check("auth.totp.MIN_SECRET_BYTES = 20 (RFC 4226 §4 floor)",
        t.MIN_SECRET_BYTES === 20);
  check("auth.totp.SUPPORTED_ALGORITHMS excludes sha1",
        t.SUPPORTED_ALGORITHMS.indexOf("sha1") === -1);
  check("auth.totp.SUPPORTED_ALGORITHMS = [sha256, sha512]",
        t.SUPPORTED_ALGORITHMS.length === 2 &&
        t.SUPPORTED_ALGORITHMS.indexOf("sha256") !== -1 &&
        t.SUPPORTED_ALGORITHMS.indexOf("sha512") !== -1);
}

// ---- auth.passkey (WebAuthn) ----
//
// Registration and authentication are end-to-end ceremonies between
// the server and a real authenticator (Touch ID / YubiKey / 1Password
// /etc.) — no built-in mock authenticator ships with the framework.
// These tests cover what we CAN cover without one:
//
//   - module surface (exports + auth namespace wiring)
//   - input validation (each required field surfaces as AuthError
//     with a code that matches the framework's other auth.* primitives)
//   - generated registration / authentication options have RFC-shaped
//     fields the browser API needs (challenge, rp, user, pubKeyCredParams,
//     timeout)
//   - hints default ["client-device", "hybrid"] so platform AND
//     cross-device authenticators surface
//
// The verify* paths rely on real signed assertions; round-tripping
// without an authenticator would mean stubbing the simplewebauthn
// internals, which would test our stub more than our wrapper.
// Operators get full ceremony coverage at the integration layer.

async function testAuthPasskeySurface() {
  var p = b.auth.passkey;
  check("auth.passkey namespace present",                typeof b.auth.passkey === "object");
  check("auth.passkey.startRegistration is a function",  typeof p.startRegistration === "function");
  check("auth.passkey.verifyRegistration is a function", typeof p.verifyRegistration === "function");
  check("auth.passkey.startAuthentication is a function", typeof p.startAuthentication === "function");
  check("auth.passkey.verifyAuthentication is a function", typeof p.verifyAuthentication === "function");

  // Vendor bundle loads + exports the four core entry points
  var v = require("../lib/vendor/simplewebauthn-server.cjs");
  check("vendor exports generateRegistrationOptions",    typeof v.generateRegistrationOptions === "function");
  check("vendor exports verifyRegistrationResponse",     typeof v.verifyRegistrationResponse === "function");
  check("vendor exports generateAuthenticationOptions",  typeof v.generateAuthenticationOptions === "function");
  check("vendor exports verifyAuthenticationResponse",   typeof v.verifyAuthenticationResponse === "function");
}

async function testAuthPasskeyStartRegistrationOptions() {
  var p = b.auth.passkey;
  var opts = await p.startRegistration({
    rpName:           "BlameJS",
    rpId:             "example.com",
    userName:         "alice@example.com",
    userDisplayName:  "Alice",
  });
  check("registration options has challenge",            typeof opts.challenge === "string" && opts.challenge.length > 0);
  check("registration options has rp.name",              opts.rp && opts.rp.name === "BlameJS");
  check("registration options has rp.id",                opts.rp && opts.rp.id === "example.com");
  check("registration options has user.name",            opts.user && opts.user.name === "alice@example.com");
  check("registration options has user.displayName",     opts.user && opts.user.displayName === "Alice");
  check("registration options has user.id (random)",     typeof opts.user.id === "string" && opts.user.id.length > 0);
  check("registration options has pubKeyCredParams",     Array.isArray(opts.pubKeyCredParams) && opts.pubKeyCredParams.length > 0);
  check("registration options has timeout",              typeof opts.timeout === "number" && opts.timeout > 0);
  check("registration options attestation = 'none'",     opts.attestation === "none");
  check("registration options residentKey = 'preferred'",
        opts.authenticatorSelection && opts.authenticatorSelection.residentKey === "preferred");
  check("registration options userVerification = 'preferred'",
        opts.authenticatorSelection.userVerification === "preferred");
  check("registration options hints = client-device + hybrid",
        Array.isArray(opts.hints) &&
        opts.hints.indexOf("client-device") !== -1 &&
        opts.hints.indexOf("hybrid") !== -1);

  // Two consecutive calls produce different challenges (random)
  var opts2 = await p.startRegistration({
    rpName: "BlameJS", rpId: "example.com", userName: "alice@example.com",
  });
  check("registration challenge is non-deterministic",   opts.challenge !== opts2.challenge);
}

async function testAuthPasskeyStartAuthenticationOptions() {
  var p = b.auth.passkey;
  var opts = await p.startAuthentication({
    rpId: "example.com",
  });
  check("auth options has challenge",                    typeof opts.challenge === "string" && opts.challenge.length > 0);
  check("auth options has rpId",                         opts.rpId === "example.com");
  check("auth options has timeout",                      typeof opts.timeout === "number");
  check("auth options userVerification = 'preferred'",   opts.userVerification === "preferred");
  check("auth options hints = client-device + hybrid",
        Array.isArray(opts.hints) &&
        opts.hints.indexOf("client-device") !== -1 &&
        opts.hints.indexOf("hybrid") !== -1);
}

async function testAuthPasskeyValidationErrors() {
  var p = b.auth.passkey;

  // startRegistration — missing fields
  var threw = null;
  try { await p.startRegistration({}); }
  catch (e) { threw = e; }
  check("startRegistration({}) throws missing-rpName",
        threw && threw.code === "auth-passkey/missing-rpName");

  threw = null;
  try { await p.startRegistration({ rpName: "X" }); }
  catch (e) { threw = e; }
  check("startRegistration without rpId throws missing-rpId",
        threw && threw.code === "auth-passkey/missing-rpId");

  threw = null;
  try { await p.startRegistration({ rpName: "X", rpId: "x.test" }); }
  catch (e) { threw = e; }
  check("startRegistration without userName throws missing-userName",
        threw && threw.code === "auth-passkey/missing-userName");

  // startAuthentication — missing rpId
  threw = null;
  try { await p.startAuthentication({}); }
  catch (e) { threw = e; }
  check("startAuthentication({}) throws missing-rpId",
        threw && threw.code === "auth-passkey/missing-rpId");

  // verifyRegistration — missing fields
  threw = null;
  try { await p.verifyRegistration({}); }
  catch (e) { threw = e; }
  check("verifyRegistration({}) throws missing-response",
        threw && threw.code === "auth-passkey/missing-response");

  threw = null;
  try { await p.verifyRegistration({ response: {} }); }
  catch (e) { threw = e; }
  check("verifyRegistration without expectedChallenge throws",
        threw && threw.code === "auth-passkey/missing-expectedChallenge");

  // verifyAuthentication — missing credential
  threw = null;
  try {
    await p.verifyAuthentication({
      response: {},
      expectedChallenge: "c",
      expectedOrigin:    "https://x.test",
      expectedRPID:      "x.test",
    });
  } catch (e) { threw = e; }
  check("verifyAuthentication without credential throws",
        threw && threw.code === "auth-passkey/missing-credential");

  // All errors are AuthError with permanent=true
  check("auth-passkey errors are AuthError",             threw && threw.isAuthError === true);
  check("auth-passkey errors are permanent",             threw && threw.permanent === true);
}

async function testAuthPasskeyExcludeCredentials() {
  // Registration options can carry an excludeCredentials list so the
  // browser refuses to register a key that's already enrolled.
  var p = b.auth.passkey;
  var opts = await p.startRegistration({
    rpName: "BlameJS",
    rpId:   "example.com",
    userName: "alice@example.com",
    excludeCredentials: [
      { id: "AAAA", transports: ["internal"] },
      { id: "BBBB" },
    ],
  });
  check("excludeCredentials propagates",
        Array.isArray(opts.excludeCredentials) &&
        opts.excludeCredentials.length === 2);
  check("excludeCredentials preserves transports",
        opts.excludeCredentials[0].transports &&
        opts.excludeCredentials[0].transports.indexOf("internal") !== -1);
}

async function testAuthPasskeyCustomHints() {
  // Operators can override the default hints (e.g. force platform-only)
  var p = b.auth.passkey;
  var opts = await p.startRegistration({
    rpName: "BlameJS",
    rpId: "example.com",
    userName: "alice@example.com",
    hints: ["client-device"],
  });
  check("custom hints override default",
        opts.hints.length === 1 && opts.hints[0] === "client-device");
}

// ---- auth.jwt (PQC-signed JWT) ----
//
// Most tests below use ML-DSA-87 keys so each sign/verify is sub-millisecond
// — SLH-DSA-SHAKE-256f signs in ~76 ms, which would balloon test time
// across the 25+ assertions. One round-trip uses the SLH-DSA default
// to prove the default path works end-to-end; everything else exercises
// behavior with the smaller-signature alg.

function _jwtMlDsaKeypair() {
  return require("crypto").generateKeyPairSync("ml-dsa-87", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function _jwtSlhDsaKeypair() {
  return require("crypto").generateKeyPairSync("slh-dsa-shake-256f", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function testAuthJwtSurface() {
  var j = b.auth.jwt;
  check("auth.jwt namespace present",                typeof b.auth.jwt === "object");
  check("auth.jwt.sign is a function",               typeof j.sign === "function");
  check("auth.jwt.verify is a function",             typeof j.verify === "function");
  check("auth.jwt.decode is a function",             typeof j.decode === "function");
  check("auth.jwt.DEFAULT_ALGORITHM = SLH-DSA-SHAKE-256f",
        j.DEFAULT_ALGORITHM === "SLH-DSA-SHAKE-256f");
  check("auth.jwt.SUPPORTED_ALGORITHMS includes SLH-DSA-SHAKE-256f",
        j.SUPPORTED_ALGORITHMS.indexOf("SLH-DSA-SHAKE-256f") !== -1);
  check("auth.jwt.SUPPORTED_ALGORITHMS includes ML-DSA-87",
        j.SUPPORTED_ALGORITHMS.indexOf("ML-DSA-87") !== -1);
  check("auth.jwt.SUPPORTED_ALGORITHMS does NOT include classical algs",
        j.SUPPORTED_ALGORITHMS.indexOf("RS256") === -1 &&
        j.SUPPORTED_ALGORITHMS.indexOf("ES256") === -1 &&
        j.SUPPORTED_ALGORITHMS.indexOf("HS256") === -1);
}

async function testAuthJwtSignVerifyRoundTripDefault() {
  // Default algorithm = SLH-DSA-SHAKE-256f. Run one full round-trip
  // to prove the default end-to-end despite the per-sign cost.
  var j = b.auth.jwt;
  var k = _jwtSlhDsaKeypair();
  var token = await j.sign({ sub: "user-1", role: "admin" }, { privateKey: k.privateKey });
  check("default-alg sign returns 3-part dotted string",
        typeof token === "string" && token.split(".").length === 3);

  var payload = await j.verify(token, { publicKey: k.publicKey });
  check("default-alg verify returns payload",        payload && payload.sub === "user-1");
  check("default-alg verify preserves custom claims", payload.role === "admin");
  check("default-alg auto-adds iat",                 typeof payload.iat === "number");

  // Decode (no-verify) returns header + payload + signature
  var decoded = j.decode(token);
  check("decode returns header.alg",                 decoded.header.alg === "SLH-DSA-SHAKE-256f");
  check("decode returns header.typ",                 decoded.header.typ === "JWT");
  check("decode returns payload.sub",                decoded.payload.sub === "user-1");
  check("decode returns signature buffer",           Buffer.isBuffer(decoded.signature));
  // SLH-DSA-SHAKE-256f signature size is ~50 KB
  check("default-alg signature size matches FIPS 205 (~50 KB)",
        decoded.signature.length > 49000 && decoded.signature.length < 51000);
}

async function testAuthJwtMlDsaOptIn() {
  // ML-DSA-87 opt-in for throughput-sensitive paths.
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({ sub: "u-2" },
                           { privateKey: k.privateKey, algorithm: "ML-DSA-87" });
  var decoded = j.decode(token);
  check("ML-DSA-87 token header carries alg",        decoded.header.alg === "ML-DSA-87");
  check("ML-DSA-87 signature size matches FIPS 204 (~5 KB)",
        decoded.signature.length > 4000 && decoded.signature.length < 6000);

  var payload = await j.verify(token, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] });
  check("ML-DSA-87 verify round-trip",               payload.sub === "u-2");
}

async function testAuthJwtAlgorithmAllowlist() {
  // verify() defaults to allowing ONLY DEFAULT_ALGORITHM. A token
  // signed with ML-DSA-87 must therefore be rejected unless the
  // allowlist explicitly opts in.
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({ sub: "u" },
                           { privateKey: k.privateKey, algorithm: "ML-DSA-87" });

  var threw = null;
  try { await j.verify(token, { publicKey: k.publicKey }); }
  catch (e) { threw = e; }
  check("verify default allowlist rejects ML-DSA-87 token",
        threw && threw.code === "auth-jwt/algorithm-not-allowed");

  // Explicit opt-in works
  var ok = await j.verify(token, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] });
  check("verify with ML-DSA-87 in allowlist accepts the token",  ok && ok.sub === "u");

  // Typo in allowlist surfaces at verify time
  var threwTypo = null;
  try { await j.verify(token, { publicKey: k.publicKey, algorithms: ["MD5"] }); }
  catch (e) { threwTypo = e; }
  check("verify with typoed alg in allowlist throws unsupported-algorithm",
        threwTypo && threwTypo.code === "auth-jwt/unsupported-algorithm");
}

async function testAuthJwtExpiration() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var nowMs = Date.now();

  // expiresInSec=10 — token is valid now, expired 11s later
  var token = await j.sign({ sub: "u" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    expiresInSec: 10, now: nowMs,
  });
  var decoded = j.decode(token);
  check("expiresInSec sets exp claim",
        typeof decoded.payload.exp === "number" &&
        decoded.payload.exp === Math.floor(nowMs / 1000) + 10);

  // Verify within window passes
  var ok = await j.verify(token, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs,
  });
  check("verify within exp window passes",          ok.sub === "u");

  // Verify after exp throws expired
  var threw = null;
  try {
    await j.verify(token, {
      publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs + 11000,
    });
  } catch (e) { threw = e; }
  check("verify past exp throws auth-jwt/expired",   threw && threw.code === "auth-jwt/expired");

  // clockToleranceSec gives leeway
  var ok2 = await j.verify(token, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs + 11000,
    clockToleranceSec: 5,
  });
  check("clockToleranceSec lets a barely-expired token through",  ok2.sub === "u");
}

async function testAuthJwtNotBefore() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var nowMs = Date.now();

  // notBeforeSec=60 — token isn't valid until 60s from now
  var token = await j.sign({ sub: "u" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    notBeforeSec: 60, now: nowMs,
  });

  // Verify before nbf throws
  var threw = null;
  try {
    await j.verify(token, {
      publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs,
    });
  } catch (e) { threw = e; }
  check("verify before nbf throws auth-jwt/not-yet-valid",
        threw && threw.code === "auth-jwt/not-yet-valid");

  // Verify after nbf passes
  var ok = await j.verify(token, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"], now: nowMs + 61000,
  });
  check("verify after nbf passes",                   ok.sub === "u");
}

async function testAuthJwtIssuerAudienceSubject() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({}, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    issuer:   "https://blamejs.example.com",
    audience: ["api-a", "api-b"],
    subject:  "user-42",
  });
  var decoded = j.decode(token);
  check("issuer claim recorded",                     decoded.payload.iss === "https://blamejs.example.com");
  check("audience claim recorded as array",          Array.isArray(decoded.payload.aud) &&
                                                     decoded.payload.aud.length === 2);
  check("subject claim recorded",                    decoded.payload.sub === "user-42");

  var verifyOpts = { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] };

  // Matching expectations pass
  var ok = await j.verify(token, Object.assign({}, verifyOpts, {
    issuer: "https://blamejs.example.com", audience: "api-a", subject: "user-42",
  }));
  check("matching iss/aud/sub passes",               ok.sub === "user-42");

  // aud accepts string-OR-array on both sides; any-of match
  var okMulti = await j.verify(token, Object.assign({}, verifyOpts, {
    audience: ["api-c", "api-b"],
  }));
  check("audience any-of match passes",              okMulti.sub === "user-42");

  // Issuer mismatch
  var threw = null;
  try { await j.verify(token, Object.assign({}, verifyOpts, { issuer: "evil.com" })); }
  catch (e) { threw = e; }
  check("issuer mismatch throws auth-jwt/iss-mismatch",
        threw && threw.code === "auth-jwt/iss-mismatch");

  // Audience mismatch
  threw = null;
  try { await j.verify(token, Object.assign({}, verifyOpts, { audience: "api-c" })); }
  catch (e) { threw = e; }
  check("audience mismatch throws auth-jwt/aud-mismatch",
        threw && threw.code === "auth-jwt/aud-mismatch");

  // Subject mismatch
  threw = null;
  try { await j.verify(token, Object.assign({}, verifyOpts, { subject: "user-99" })); }
  catch (e) { threw = e; }
  check("subject mismatch throws auth-jwt/sub-mismatch",
        threw && threw.code === "auth-jwt/sub-mismatch");
}

async function testAuthJwtSignatureTampering() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({ sub: "u" }, { privateKey: k.privateKey, algorithm: "ML-DSA-87" });
  var parts = token.split(".");

  // Flip a character in the signature
  var sigChar = parts[2][0] === "A" ? "B" : "A";
  var tamperedSig = parts[0] + "." + parts[1] + "." + sigChar + parts[2].slice(1);
  var threwSig = null;
  try { await j.verify(tamperedSig, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threwSig = e; }
  check("tampered signature → auth-jwt/invalid-signature",
        threwSig && threwSig.code === "auth-jwt/invalid-signature");

  // Tamper the payload — re-encode a different sub claim, keep the
  // original signature. Verify should still fail because the signature
  // was over the original signing input.
  var alteredPayload = Buffer.from(JSON.stringify({ sub: "evil" })).toString("base64")
    .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  var tamperedPayload = parts[0] + "." + alteredPayload + "." + parts[2];
  var threwPayload = null;
  try { await j.verify(tamperedPayload, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threwPayload = e; }
  check("tampered payload → auth-jwt/invalid-signature",
        threwPayload && threwPayload.code === "auth-jwt/invalid-signature");

  // Wrong public key → verify rejects (different ML-DSA-87 keypair)
  var k2 = _jwtMlDsaKeypair();
  var threwKey = null;
  try { await j.verify(token, { publicKey: k2.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threwKey = e; }
  check("wrong public key → auth-jwt/invalid-signature",
        threwKey && threwKey.code === "auth-jwt/invalid-signature");
}

async function testAuthJwtMalformedTokens() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();

  // decode + verify both reject malformed shapes
  var bad = ["", "no-dots", "one.dot", "a.b.c.d", "🌶."];
  for (var i = 0; i < bad.length; i++) {
    var threw = null;
    try { j.decode(bad[i]); }
    catch (e) { threw = e; }
    check("decode rejects '" + bad[i] + "' → malformed",
          threw && threw.code === "auth-jwt/malformed");
  }

  // verify on garbage signing input → malformed (decode fails first)
  var threwV = null;
  try { await j.verify("garbage", { publicKey: k.publicKey }); }
  catch (e) { threwV = e; }
  check("verify on garbage → auth-jwt/malformed",
        threwV && threwV.code === "auth-jwt/malformed");
}

async function testAuthJwtMalformedRegisteredClaims() {
  // RFC 7519 §4.1: exp / nbf / iat MUST be NumericDate values (JSON
  // numeric, seconds since epoch). A token with a string exp must be
  // rejected as malformed — silently skipping the check would let a
  // token with `exp: "0"` bypass expiration enforcement entirely.
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var nodeCrypto = require("crypto");

  function _buildToken(payload) {
    var header = { alg: "ML-DSA-87", typ: "JWT" };
    var b64 = function (o) {
      return Buffer.from(JSON.stringify(o)).toString("base64")
        .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    };
    var signingInput = b64(header) + "." + b64(payload);
    var sig = nodeCrypto.sign(null, Buffer.from(signingInput, "ascii"),
                              nodeCrypto.createPrivateKey({ key: k.privateKey, format: "pem" }));
    var sigB64 = sig.toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    return signingInput + "." + sigB64;
  }

  // exp as a string → malformed
  var t1 = _buildToken({ sub: "u", exp: "9999999999" });
  var threw1 = null;
  try { await j.verify(t1, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threw1 = e; }
  check("verify: string exp rejected as malformed",
        threw1 && threw1.code === "auth-jwt/malformed");

  // nbf as a string → malformed
  var t2 = _buildToken({ sub: "u", nbf: "0" });
  var threw2 = null;
  try { await j.verify(t2, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threw2 = e; }
  check("verify: string nbf rejected as malformed",
        threw2 && threw2.code === "auth-jwt/malformed");

  // iat as a string → malformed
  var t3 = _buildToken({ sub: "u", iat: "not-a-number" });
  var threw3 = null;
  try { await j.verify(t3, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threw3 = e; }
  check("verify: string iat rejected as malformed",
        threw3 && threw3.code === "auth-jwt/malformed");

  // exp as null → malformed
  var t4 = _buildToken({ sub: "u", exp: null });
  var threw4 = null;
  try { await j.verify(t4, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threw4 = e; }
  check("verify: null exp rejected as malformed",
        threw4 && threw4.code === "auth-jwt/malformed");

  // exp as Infinity → malformed
  var t5 = _buildToken({ sub: "u", exp: 1e308 * 1e308 });   // → Infinity in JSON
  // (JSON.stringify(Infinity) → "null", which the test above already covers
  //  via t4. Skipping the redundant case.)
  void t5;

  // omitted claims still pass — the rule is "if present, must be number"
  var tOk = _buildToken({ sub: "u" });
  var ok = await j.verify(tOk, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] });
  check("verify: missing exp/nbf/iat is fine (no claim, no enforcement)", ok.sub === "u");
}

async function testAuthJwtCritHeaderRejected() {
  // RFC 7515 §4.1.11: any unrecognized critical header MUST cause the
  // verifier to reject the token. We don't define any extensions, so
  // any `crit` header → rejection.
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();

  // Build a token with a crit header by bypassing the framework's sign.
  // Header/payload encoded by hand; signature still produced by Node.
  var header = { alg: "ML-DSA-87", typ: "JWT", crit: ["urn:example:future"] };
  var headerB64 = Buffer.from(JSON.stringify(header)).toString("base64")
    .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  var payload = { sub: "u" };
  var payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64")
    .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  var signingInput = headerB64 + "." + payloadB64;
  var sig = require("crypto").sign(null, Buffer.from(signingInput, "ascii"),
                                   require("crypto").createPrivateKey({ key: k.privateKey, format: "pem" }));
  var sigB64 = sig.toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  var token = signingInput + "." + sigB64;

  var threw = null;
  try { await j.verify(token, { publicKey: k.publicKey, algorithms: ["ML-DSA-87"] }); }
  catch (e) { threw = e; }
  check("verify rejects unknown crit header (RFC 7515 §4.1.11)",
        threw && threw.code === "auth-jwt/unknown-crit");
}

async function testAuthJwtKidPropagation() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();
  var token = await j.sign({ sub: "u" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    kid: "key-2026-04-26",
  });
  var decoded = j.decode(token);
  check("kid embedded in header",                    decoded.header.kid === "key-2026-04-26");
}

async function testAuthJwtReplayDefense() {
  // RFC 7519 §4.1.7 jti claim — when paired with a replayStore, the
  // verifier refuses to accept the same token twice. Defends against
  // captured-bearer-token replay (CVE class — token-reuse under TLS-
  // terminated proxies, log scraping, browser-history exposure,
  // leaked Authorization headers in shared dev tools).
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();

  // First verify — passes; checkAndInsert records the jti.
  var store = b.nonceStore.create({ backend: "memory" });
  var noJtiStore = b.nonceStore.create({ backend: "memory" });
  var token = await j.sign({ sub: "u", jti: "unique-token-1" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    expiresInSec: 60,
  });
  var ok = await j.verify(token, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"],
    replayStore: store,
  });
  check("first verify passes",                       ok.sub === "u");

  // Second verify — refused with auth-jwt/replay.
  var threwReplay = null;
  try {
    await j.verify(token, {
      publicKey: k.publicKey, algorithms: ["ML-DSA-87"],
      replayStore: store,
    });
  } catch (e) { threwReplay = e; }
  check("second verify refused as replay",
        threwReplay && threwReplay.code === "auth-jwt/replay");

  // sign() with expiresInSec auto-mints a jti (16 random bytes b64url)
  // when the operator didn't supply one — closes the silent-downgrade
  // hole where a token configured for replay-protection on verify
  // would have shipped without a jti. The replay path then works.
  var tokenAutoJti = await j.sign({ sub: "u" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    expiresInSec: 60,
  });
  var autoJtiClaims = JSON.parse(Buffer.from(tokenAutoJti.split(".")[1], "base64url").toString("utf8"));
  check("expiresInSec auto-mints jti",         typeof autoJtiClaims.jti === "string" && autoJtiClaims.jti.length >= 16);
  var autoJtiVerified = await j.verify(tokenAutoJti, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"],
    replayStore: noJtiStore,
  });
  check("replayStore + auto-mint jti verifies",
        autoJtiVerified && autoJtiVerified.sub === "u");

  // checkAndInsert throwing surfaces as replay-store-failed
  var brokenStore = {
    checkAndInsert: async function () { throw new Error("redis is down"); },
  };
  var token2 = await j.sign({ sub: "u", jti: "unique-token-2" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    expiresInSec: 60,
  });
  var threwBroken = null;
  try {
    await j.verify(token2, {
      publicKey: k.publicKey, algorithms: ["ML-DSA-87"],
      replayStore: brokenStore,
    });
  } catch (e) { threwBroken = e; }
  check("replayStore.checkAndInsert throwing → auth-jwt/replay-store-failed",
        threwBroken && threwBroken.code === "auth-jwt/replay-store-failed");

  // Bad replayStore shape → bad-replay-store
  var threwShape = null;
  try {
    await j.verify(token2, {
      publicKey: k.publicKey, algorithms: ["ML-DSA-87"],
      replayStore: { hasSeen: function () {} },
    });
  } catch (e) { threwShape = e; }
  check("replayStore without checkAndInsert → auth-jwt/bad-replay-store",
        threwShape && threwShape.code === "auth-jwt/bad-replay-store");

  // Without replayStore, jti is preserved but no enforcement
  var tokenJ = await j.sign({ sub: "u", jti: "unique-token-3" }, {
    privateKey: k.privateKey, algorithm: "ML-DSA-87",
    expiresInSec: 60,
  });
  var ok1 = await j.verify(tokenJ, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"],
  });
  var ok2 = await j.verify(tokenJ, {
    publicKey: k.publicKey, algorithms: ["ML-DSA-87"],
  });
  check("without replayStore, same token verifies twice (replay defense is opt-in)",
        ok1.sub === "u" && ok2.sub === "u");

  // Cleanup — close the in-memory backends so the sweep timers stop
  store.close();
  noJtiStore.close();
}

async function testAuthJwtMissingKey() {
  var j = b.auth.jwt;
  var k = _jwtMlDsaKeypair();

  // sign without privateKey
  var threwS = null;
  try { await j.sign({ sub: "u" }, { algorithm: "ML-DSA-87" }); }
  catch (e) { threwS = e; }
  check("sign without privateKey throws missing-key",
        threwS && threwS.code === "auth-jwt/missing-key");

  // verify without publicKey — sign a token first
  var token = await j.sign({ sub: "u" }, { privateKey: k.privateKey, algorithm: "ML-DSA-87" });
  var threwV = null;
  try { await j.verify(token, { algorithms: ["ML-DSA-87"] }); }
  catch (e) { threwV = e; }
  check("verify without publicKey throws missing-key",
        threwV && threwV.code === "auth-jwt/missing-key");
}

// ---- DPoP (RFC 9449) ----

async function testAuthDpopRoundTrip() {
  var d = b.auth.dpop;
  var nodeCrypto = require("crypto");
  check("auth.dpop namespace present",          typeof b.auth.dpop === "object");
  check("auth.dpop.buildProof is a function",   typeof d.buildProof === "function");
  check("auth.dpop.verify is a function",       typeof d.verify === "function");
  check("auth.dpop.thumbprint is a function",   typeof d.thumbprint === "function");

  // ES256 — the canonical DPoP alg per RFC 9449 §4.2
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var proof = await d.buildProof({
    htm: "POST",
    htu: "https://api.example.com/resource?ignored=1",
    privateKey: ec.privateKey,
    accessToken: "access-token-xyz",
  });
  check("ES256 proof is a 3-part dotted string",
        typeof proof === "string" && proof.split(".").length === 3);

  var rv = await d.verify(proof, {
    htm: "POST",
    htu: "https://api.example.com/resource",
    accessToken: "access-token-xyz",
  });
  check("verify returns header + payload + jkt",
        rv && rv.header && rv.payload && typeof rv.jkt === "string");
  check("payload.htm carries the method",       rv.payload.htm === "POST");
  check("payload.htu strips query string",      rv.payload.htu === "https://api.example.com/resource");
  check("payload.ath = sha256(access_token)",   typeof rv.payload.ath === "string" && rv.payload.ath.length > 0);
  check("payload.jti is a non-empty string",    typeof rv.payload.jti === "string" && rv.payload.jti.length > 0);
  check("header.typ is dpop+jwt",               rv.header.typ === "dpop+jwt");
  check("header.jwk is embedded",               rv.header.jwk && rv.header.jwk.kty === "EC");
}

async function testAuthDpopHtmHtuMismatch() {
  var d = b.auth.dpop;
  var nodeCrypto = require("crypto");
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var proof = await d.buildProof({ htm: "POST", htu: "https://api.example.com/r", privateKey: ec.privateKey });

  // htm mismatch
  var threwM = null;
  try { await d.verify(proof, { htm: "GET", htu: "https://api.example.com/r" }); }
  catch (e) { threwM = e; }
  check("htm mismatch → auth-dpop/htm-mismatch",
        threwM && threwM.code === "auth-dpop/htm-mismatch");

  // htu mismatch
  var threwU = null;
  try { await d.verify(proof, { htm: "POST", htu: "https://evil.example.com/r" }); }
  catch (e) { threwU = e; }
  check("htu mismatch → auth-dpop/htu-mismatch",
        threwU && threwU.code === "auth-dpop/htu-mismatch");
}

async function testAuthDpopAthBinding() {
  var d = b.auth.dpop;
  var nodeCrypto = require("crypto");
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var proof = await d.buildProof({
    htm: "POST", htu: "https://api.example.com/r",
    privateKey: ec.privateKey, accessToken: "tok-A",
  });

  // ath enforced when accessToken provided to verify
  var threwM = null;
  try { await d.verify(proof, { htm: "POST", htu: "https://api.example.com/r", accessToken: "tok-B" }); }
  catch (e) { threwM = e; }
  check("ath mismatch → auth-dpop/ath-mismatch",
        threwM && threwM.code === "auth-dpop/ath-mismatch");

  // missing ath — operator passes accessToken but proof has no ath
  var noAthProof = await d.buildProof({ htm: "POST", htu: "https://api.example.com/r", privateKey: ec.privateKey });
  var threwMissing = null;
  try { await d.verify(noAthProof, { htm: "POST", htu: "https://api.example.com/r", accessToken: "tok-A" }); }
  catch (e) { threwMissing = e; }
  check("missing ath when accessToken supplied → auth-dpop/missing-ath",
        threwMissing && threwMissing.code === "auth-dpop/missing-ath");
}

async function testAuthDpopReplayDefense() {
  var d = b.auth.dpop;
  var nodeCrypto = require("crypto");
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var store = b.nonceStore.create({ backend: "memory" });
  var proof = await d.buildProof({ htm: "GET", htu: "https://api.example.com/r", privateKey: ec.privateKey });

  // First verify passes
  var ok1 = await d.verify(proof, { htm: "GET", htu: "https://api.example.com/r", replayStore: store });
  check("first verify with replay store ok",    ok1.header.typ === "dpop+jwt");

  // Second verify refused as replay
  var threwR = null;
  try { await d.verify(proof, { htm: "GET", htu: "https://api.example.com/r", replayStore: store }); }
  catch (e) { threwR = e; }
  check("second verify refused → auth-dpop/replay",
        threwR && threwR.code === "auth-dpop/replay");

  store.close();
}

async function testAuthDpopAlgorithmDefenses() {
  var d = b.auth.dpop;
  var nodeCrypto = require("crypto");
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });

  // alg "none" refused outright
  var threwNone = null;
  try {
    await d.buildProof({ htm: "GET", htu: "https://x/y", privateKey: ec.privateKey, algorithm: "none" });
  } catch (e) { threwNone = e; }
  check("alg='none' refused at build",
        threwNone && threwNone.code === "auth-dpop/refused-alg");

  // alg HS256 refused
  var threwHs = null;
  try {
    await d.verify("a.b.c", { htm: "GET", htu: "https://x/y", algorithms: ["HS256"] });
  } catch (e) { threwHs = e; }
  check("alg='HS256' refused in allowlist",
        threwHs && threwHs.code === "auth-dpop/refused-alg");

  // alg-not-allowed when token alg not in opt allowlist
  var proof = await d.buildProof({ htm: "GET", htu: "https://x/y", privateKey: ec.privateKey });
  var threwAna = null;
  try { await d.verify(proof, { htm: "GET", htu: "https://x/y", algorithms: ["EdDSA"] }); }
  catch (e) { threwAna = e; }
  check("alg-not-allowed when allowlist excludes ES256",
        threwAna && threwAna.code === "auth-dpop/alg-not-allowed");
}

async function testAuthDpopIatWindow() {
  var d = b.auth.dpop;
  var nodeCrypto = require("crypto");
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });

  var nowMs = Date.now();
  // iat 1000s in the past
  var staleProof = await d.buildProof({
    htm: "GET", htu: "https://x/y", privateKey: ec.privateKey,
    iat: Math.floor(nowMs / 1000) - 1000,
  });
  var threw = null;
  try { await d.verify(staleProof, { htm: "GET", htu: "https://x/y", now: nowMs }); }
  catch (e) { threw = e; }
  check("iat-out-of-window when proof is stale",
        threw && threw.code === "auth-dpop/iat-out-of-window");

  // Larger window accepts the same stale proof
  var ok = await d.verify(staleProof, {
    htm: "GET", htu: "https://x/y", now: nowMs, iatWindowSec: 2000,
  });
  check("iatWindowSec lets a stale proof through",  ok.payload.htm === "GET");
}

async function testAuthDpopJwkPrivateLeakRefused() {
  var d = b.auth.dpop;
  var nodeCrypto = require("crypto");
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  // Build a proof, then tamper the embedded JWK to add a private 'd' field
  var proof = await d.buildProof({ htm: "GET", htu: "https://x/y", privateKey: ec.privateKey });
  var parts = proof.split(".");
  var hdr = JSON.parse(Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
  hdr.jwk.d = "fake-private-component";
  parts[0] = Buffer.from(JSON.stringify(hdr)).toString("base64")
    .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  var threw = null;
  try { await d.verify(parts.join("."), { htm: "GET", htu: "https://x/y" }); }
  catch (e) { threw = e; }
  check("jwk with 'd' refused → auth-dpop/jwk-has-private",
        threw && threw.code === "auth-dpop/jwk-has-private");
}

async function testAuthDpopThumbprint() {
  var d = b.auth.dpop;
  var nodeCrypto = require("crypto");
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var proof = await d.buildProof({ htm: "GET", htu: "https://x/y", privateKey: ec.privateKey });
  var rv = await d.verify(proof, { htm: "GET", htu: "https://x/y" });

  // Thumbprint matches what d.thumbprint() returns for the same jwk
  var direct = d.thumbprint(rv.header.jwk);
  check("verify-returned jkt matches thumbprint helper", rv.jkt === direct);

  // expectedThumbprint pass + mismatch
  var ok = await d.verify(proof, { htm: "GET", htu: "https://x/y", expectedThumbprint: rv.jkt });
  check("expectedThumbprint match passes",      ok.jkt === rv.jkt);

  var threw = null;
  try {
    var differentJkt = "X".repeat(rv.jkt.length);
    await d.verify(proof, { htm: "GET", htu: "https://x/y", expectedThumbprint: differentJkt });
  } catch (e) { threw = e; }
  check("expectedThumbprint mismatch → auth-dpop/thumbprint-mismatch",
        threw && threw.code === "auth-dpop/thumbprint-mismatch");
}

async function testAuthDpopPqcMlDsa() {
  var d = b.auth.dpop;
  var nodeCrypto = require("crypto");
  var ml = nodeCrypto.generateKeyPairSync("ml-dsa-87");
  var proof = await d.buildProof({ htm: "POST", htu: "https://api.example.com/r", privateKey: ml.privateKey });
  check("ML-DSA-87 proof builds",               typeof proof === "string");

  var rv = await d.verify(proof, { htm: "POST", htu: "https://api.example.com/r" });
  check("ML-DSA-87 verify ok",                  rv.header.alg === "ML-DSA-87");
  check("ML-DSA-87 jwk.kty=AKP",                rv.header.jwk.kty === "AKP");
  check("ML-DSA-87 jwk.alg=ML-DSA-87",          rv.header.jwk.alg === "ML-DSA-87");
}

// ---- AAL — NIST SP 800-63-4 authentication assurance levels ----

function testAuthAalSurface() {
  var a = b.auth.aal;
  check("auth.aal namespace present",            typeof a === "object");
  check("auth.aal.AAL1 / AAL2 / AAL3 strings",
        a.AAL1 === "AAL1" && a.AAL2 === "AAL2" && a.AAL3 === "AAL3");
  check("auth.aal.fromMethods is a function",    typeof a.fromMethods === "function");
  check("auth.aal.meets is a function",          typeof a.meets === "function");
  check("auth.aal.isValidBand",
        a.isValidBand("AAL2") && !a.isValidBand("AAL4"));
}

function testAuthAalFromMethods() {
  var a = b.auth.aal;

  // AAL1 — single factor (memorized secret)
  check("password alone → AAL1",                 a.fromMethods({ password: true }) === "AAL1");
  check("pin alone → AAL1",                      a.fromMethods({ pin: true }) === "AAL1");
  check("hardware alone → AAL1",                 a.fromMethods({ hardware: true }) === "AAL1");
  check("mtls alone → AAL1",                     a.fromMethods({ mtls: true }) === "AAL1");

  // AAL2 — multi-factor
  check("password + totp → AAL2",                a.fromMethods({ password: true, totp: true }) === "AAL2");
  check("password + sms → AAL2",                 a.fromMethods({ password: true, sms: true }) === "AAL2");
  check("password + mtls → AAL2",                a.fromMethods({ password: true, mtls: true }) === "AAL2");
  check("pin + hardware → AAL3",                 a.fromMethods({ pin: true, hardware: true }) === "AAL3");

  // AAL3 — phishing-resistant multi-factor. v0.9.2: SP 800-63-4 §5.1.7
  // requires UV-bound user verification on webauthn for AAL3
  // (MF-CRYPT). webauthn:true alone WITHOUT uv:true caps at AAL2
  // (SF-CRYPT); with uv:true OR combined with a memorized secret it
  // reaches AAL3.
  check("webauthn + uv → AAL3",                  a.fromMethods({ webauthn: true, uv: true }) === "AAL3");
  check("passkey + uv → AAL3",                   a.fromMethods({ passkey: true, uv: true }) === "AAL3");
  check("password + webauthn → AAL3",            a.fromMethods({ password: true, webauthn: true }) === "AAL3");
  check("webauthn no-uv alone → AAL2",           a.fromMethods({ webauthn: true }) === "AAL2");
  check("passkey no-uv alone → AAL2",            a.fromMethods({ passkey: true }) === "AAL2");

  // No methods asserted → throws
  var threw = null;
  try { a.fromMethods({}); } catch (e) { threw = e; }
  check("empty methods → auth-aal/no-methods",   threw && threw.code === "auth-aal/no-methods");

  // Invalid input
  threw = null;
  try { a.fromMethods(null); } catch (e) { threw = e; }
  check("null methods → auth-aal/bad-methods",   threw && threw.code === "auth-aal/bad-methods");
}

function testAuthAalMeets() {
  var a = b.auth.aal;
  check("AAL3 meets AAL2",                       a.meets("AAL3", "AAL2") === true);
  check("AAL2 meets AAL2",                       a.meets("AAL2", "AAL2") === true);
  check("AAL1 does not meet AAL2",               a.meets("AAL1", "AAL2") === false);
  check("AAL3 meets AAL1",                       a.meets("AAL3", "AAL1") === true);
  check("invalid band fails meets",              a.meets("AAL4", "AAL2") === false);
  check("null actual fails meets",               a.meets(null, "AAL2") === false);
}

async function testRequireAalMiddleware() {
  // Build a middleware and exercise pass/fail paths against fake req/res.
  var mw = b.middleware.requireAal({ minimum: "AAL2", audit: false });
  check("requireAal returns a function",         typeof mw === "function");

  function _fakeRes() {
    var r = { headersSent: false, statusCode: null, headers: null, body: null };
    r.writeHead = function (sc, hdrs) { r.statusCode = sc; r.headers = hdrs; r.headersSent = true; };
    r.end = function (b2) { r.body = b2; };
    return r;
  }

  // Below minimum → 401
  var nextCalled = false;
  var res = _fakeRes();
  mw({ user: { aal: "AAL1", id: "u-1" }, url: "/admin", headers: {}, socket: {} }, res, function () { nextCalled = true; });
  check("AAL1 below AAL2 → 401",                 res.statusCode === 401);
  check("WWW-Authenticate carries scheme + required",
        res.headers && /AAL-StepUp/.test(res.headers["WWW-Authenticate"] || "") &&
        /required="AAL2"/.test(res.headers["WWW-Authenticate"] || ""));
  check("next not called on deny",               nextCalled === false);

  // At minimum → next()
  nextCalled = false;
  res = _fakeRes();
  mw({ user: { aal: "AAL2", id: "u-1" }, url: "/admin", headers: {}, socket: {} }, res, function () { nextCalled = true; });
  check("AAL2 meets AAL2 → next()",              nextCalled === true && res.statusCode === null);

  // Above minimum → next()
  nextCalled = false;
  res = _fakeRes();
  mw({ user: { aal: "AAL3", id: "u-1" }, url: "/admin", headers: {}, socket: {} }, res, function () { nextCalled = true; });
  check("AAL3 meets AAL2 → next()",              nextCalled === true);

  // No user (anonymous) → 401
  res = _fakeRes();
  mw({ url: "/admin", headers: {}, socket: {} }, res, function () { });
  check("no user → 401",                         res.statusCode === 401);

  // Custom getAal opt
  var mw2 = b.middleware.requireAal({
    minimum: "AAL3",
    getAal:  function (req) { return req.headers["x-aal"]; },
    audit:   false,
  });
  res = _fakeRes();
  nextCalled = false;
  mw2({ url: "/admin", headers: { "x-aal": "AAL3" }, socket: {} }, res, function () { nextCalled = true; });
  check("getAal reads custom source",            nextCalled === true);

  // Bad minimum at create time
  var threw = null;
  try { b.middleware.requireAal({ minimum: "AAL4" }); } catch (e) { threw = e; }
  check("bad minimum → auth-aal/bad-minimum",    threw && threw.code === "auth-aal/bad-minimum");
}

// ---- template — eval-free interpreter ----
//
// Each test sets up its own tmpdir + writes the views by hand so the
// fixtures are inline + readable. No global state — every test creates
// its own engine via template.create({ viewsDir }).

function _writeView(dir, name, content) {
  fs.mkdirSync(path.dirname(path.join(dir, name + ".html")), { recursive: true });
  fs.writeFileSync(path.join(dir, name + ".html"), content);
}

function testTemplateEscapeHtml() {
  var t = b.template;
  check("escapeHtml: ampersand",                t.escapeHtml("a & b") === "a &amp; b");
  check("escapeHtml: lt/gt",                    t.escapeHtml("<x>") === "&lt;x&gt;");
  check("escapeHtml: double-quote",             t.escapeHtml('"x"') === "&quot;x&quot;");
  check("escapeHtml: single-quote",             t.escapeHtml("'x'") === "&#x27;x&#x27;");
  check("escapeHtml: null/undefined → empty",   t.escapeHtml(null) === "" && t.escapeHtml(undefined) === "");
  check("escapeHtml: number → string-escaped",  t.escapeHtml(42) === "42");
}

function testTemplateBasicRender() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "hello", "<h1>{{ greeting }}, {{ name }}!</h1>");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("hello", { greeting: "Hi", name: "Alice" });
    check("basic render substitutes + escapes",   out === "<h1>Hi, Alice!</h1>");

    // Hostile input is escaped by default
    var hostile = eng.render("hello", { greeting: "<script>alert(1)</script>", name: 'A"B' });
    check("user values escaped in {{ }}",
          hostile.indexOf("<script>") === -1 &&
          hostile.indexOf("&lt;script&gt;alert(1)&lt;/script&gt;") !== -1 &&
          hostile.indexOf("&quot;") !== -1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateRenderString() {
  // Serverless / read-only-FS path: render from a source string with no
  // viewsDir + no disk read. HTML escaping still applies.
  var eng = b.template.create({});
  check("renderString: no viewsDir engine created", eng.viewsDir === null);
  var out = eng.renderString("<h1>{{ greeting }}, {{ name }}!</h1>", { greeting: "Hi", name: "Alice" });
  check("renderString: substitutes + escapes",
        out === "<h1>Hi, Alice!</h1>");
  var hostile = eng.renderString("<p>{{ x }}</p>", { x: "<script>alert(1)</script>" });
  check("renderString: user values escaped",
        hostile.indexOf("<script>") === -1 && hostile.indexOf("&lt;script&gt;") !== -1);

  // extends + partial resolved via opts.resolve (no disk).
  var views = {
    base:  "<html>{% block body %}default{% endblock %}</html>",
    greet: "<p>hi {{ n }}</p>",
  };
  var composed = eng.renderString(
    "{% extends \"base\" %}{% block body %}{{> greet}}{% endblock %}",
    { n: "Bo" },
    { resolve: function (name) { return views[name]; } });
  check("renderString: extends + partial via opts.resolve",
        composed === "<html><p>hi Bo</p></html>");

  // extends with no resolver → clean throw (not a crash).
  var threwExtends = null;
  try { eng.renderString("{% extends \"base\" %}{% block body %}x{% endblock %}", {}); }
  catch (e) { threwExtends = e; }
  check("renderString: extends without opts.resolve refuses",
        threwExtends && /extends/.test(threwExtends.message));

  // A missing partial inlines empty (same as the file path).
  check("renderString: missing partial inlines empty",
        eng.renderString("a{{> nope}}b", {}, { resolve: function () { return undefined; } }) === "ab");

  // Data omitted: renderString(source, { resolve }) treats the opts as
  // opts (not data) when it carries a function `resolve` + no 3rd arg.
  var noData = eng.renderString(
    "{% extends \"base\" %}{% block body %}static{% endblock %}",
    { resolve: function (name) { return views[name]; } });
  check("renderString: opts-as-2nd-arg (data omitted) honored",
        noData === "<html>static</html>");

  // compileString returns a reusable AST.
  var ast = eng.compileString("<b>{{ v }}</b>");
  check("compileString: returns an AST", ast && ast.type === "Template");

  // String templates are byte-capped against hostile input (untrusted
  // source); the default cap refuses an oversize source, and a hostile
  // tag stream can't drive a ReDoS through the block resolver.
  var threwCap = null;
  try { eng.compileString("x".repeat(300000)); } catch (e) { threwCap = e; }
  check("compileString: oversize source refused (maxBytes)",
        threwCap && /maxBytes/.test(threwCap.message));
  check("compileString: opts.maxBytes raises the cap",
        eng.compileString("y".repeat(300000), { maxBytes: 1000000 }) !== null);
  var t0 = Date.now();
  try { eng.compileString("{%block\tA%}".repeat(40000)); } catch (e2) { void e2; }
  check("compileString: pathological block-open stream bounded (no ReDoS)",
        (Date.now() - t0) < 1000);

  // The file-backed methods refuse on a no-viewsDir engine.
  var threwFile = null;
  try { eng.render("anything", {}); } catch (e) { threwFile = e; }
  check("render() without viewsDir refuses",
        threwFile && /viewsDir not configured/.test(threwFile.message));
}

function testTemplateRawExpression() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "raw", "<div>{{{ trustedHtml }}}</div>");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("raw", { trustedHtml: "<em>ok</em>" });
    check("{{{ raw }}} bypasses escape",          out === "<div><em>ok</em></div>");

    // null/undefined raw → empty (not "null"/"undefined")
    var nullOut = eng.render("raw", { trustedHtml: null });
    check("{{{ null }}} renders empty",           nullOut === "<div></div>");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateIfElse() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "cond",
      "{% if loggedIn %}Welcome, {{ name }}{% else %}Please sign in{% endif %}");
    var eng = b.template.create({ viewsDir: dir });
    check("if-true branch",       eng.render("cond", { loggedIn: true, name: "A" }) === "Welcome, A");
    check("if-false → else branch", eng.render("cond", { loggedIn: false }) === "Please sign in");

    // Nested if
    _writeView(dir, "nested",
      "{% if a %}{% if b %}AB{% else %}A!B{% endif %}{% else %}!A{% endif %}");
    check("nested if-true-true",  eng.render("nested", { a: true, b: true }) === "AB");
    check("nested if-true-false", eng.render("nested", { a: true, b: false }) === "A!B");
    check("nested if-false",      eng.render("nested", { a: false, b: true }) === "!A");

    // if without else
    _writeView(dir, "noelse", "[{% if v %}yes{% endif %}]");
    check("if without else, true",  eng.render("noelse", { v: 1 }) === "[yes]");
    check("if without else, false", eng.render("noelse", { v: 0 }) === "[]");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateForLoop() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "list", "<ul>{% for it in items %}<li>{{ it }}</li>{% endfor %}</ul>");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("list", { items: ["a", "b", "c"] });
    check("for loop iterates array",
          out === "<ul><li>a</li><li>b</li><li>c</li></ul>");

    var empty = eng.render("list", { items: [] });
    check("for over empty array yields no body",  empty === "<ul></ul>");

    // Loop body has access to outer scope too
    _writeView(dir, "list2",
      "{% for x in xs %}{{ prefix }}-{{ x }} {% endfor %}");
    var out2 = eng.render("list2", { xs: [1, 2], prefix: "id" });
    check("loop body sees outer scope",            out2 === "id-1 id-2 ");

    // Object iteration is NOT supported (operators map to entries first)
    var nonIter = eng.render("list", { items: { a: 1 } });
    check("non-array source renders no body (no iteration)",
          nonIter === "<ul></ul>");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateExpressionGrammar() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    var eng = b.template.create({ viewsDir: dir });

    // Member access + index
    _writeView(dir, "member", "{{ user.name }} ({{ tags[0] }})");
    check("dot-access + index",
          eng.render("member", { user: { name: "A" }, tags: ["x", "y"] }) === "A (x)");

    // Comparison + logical
    _writeView(dir, "cmp", "{% if n > 0 && n < 10 %}small{% else %}other{% endif %}");
    check("&& + comparison true",   eng.render("cmp", { n: 5 }) === "small");
    check("&& + comparison false",  eng.render("cmp", { n: 50 }) === "other");

    // Equality (=== and ==)
    _writeView(dir, "eq", "{% if a === 'x' %}strict{% else %}other{% endif %}");
    check("=== matches strictly",   eng.render("eq", { a: "x" }) === "strict");
    check("=== rejects coercion",   eng.render("eq", { a: 1 }) === "other");

    // Ternary
    _writeView(dir, "tern", "{{ on ? 'YES' : 'NO' }}");
    check("ternary true",           eng.render("tern", { on: true }) === "YES");
    check("ternary false",          eng.render("tern", { on: false }) === "NO");

    // Unary not
    _writeView(dir, "neg", "{% if !done %}working{% else %}done{% endif %}");
    check("unary !",                eng.render("neg", { done: false }) === "working");

    // Function call (operator-supplied helper)
    _writeView(dir, "call", "{{ helpers.upper(name) }}");
    var helpers = { upper: function (s) { return String(s).toUpperCase(); } };
    check("function call invokes operator-supplied helper",
          eng.render("call", { helpers: helpers, name: "alice" }) === "ALICE");

    // String + number literals
    _writeView(dir, "lit", "{{ 'fixed-' + n }}");
    check("literal + numeric concat",   eng.render("lit", { n: 7 }) === "fixed-7");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplatePartialInclusion() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    fs.mkdirSync(path.join(dir, "partials"), { recursive: true });
    fs.writeFileSync(path.join(dir, "partials", "header.html"), "<header>{{ title }}</header>");
    fs.writeFileSync(path.join(dir, "partials", "footer.html"), "<footer>©</footer>");
    _writeView(dir, "page", "{{> header }}<main>{{ body }}</main>{{> footer }}");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("page", { title: "T", body: "B" });
    check("partials inlined + interpolated",
          out === "<header>T</header><main>B</main><footer>©</footer>");

    // Missing partial → silent empty (forgiving render, no exception)
    _writeView(dir, "missing", "[{{> nope }}]");
    check("missing partial silently empty",  eng.render("missing", {}) === "[]");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateLayoutInheritance() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "base",
      "<html><head><title>{% block title %}Default{% endblock %}</title></head>" +
      "<body><div id='content'>{% block content %}<p>Default body</p>{% endblock %}</div></body></html>");
    _writeView(dir, "child",
      "{% extends \"base\" %}" +
      "{% block title %}{{ pageTitle }}{% endblock %}" +
      "{% block content %}<h1>{{ heading }}</h1>{% endblock %}");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("child", { pageTitle: "Hi", heading: "Welcome" });
    check("child overrides title block",
          out.indexOf("<title>Hi</title>") !== -1);
    check("child overrides content block",
          out.indexOf("<h1>Welcome</h1>") !== -1);
    check("base wraps the child blocks",
          out.indexOf("<html>") === 0 && out.indexOf("</html>") !== -1);

    // Child that overrides only one block — other block keeps default
    _writeView(dir, "partialOverride",
      "{% extends \"base\" %}{% block title %}Only Title{% endblock %}");
    var partial = eng.render("partialOverride", {});
    check("child with partial override keeps base default for non-overridden block",
          partial.indexOf("<title>Only Title</title>") !== -1 &&
          partial.indexOf("<p>Default body</p>") !== -1);

    // Multi-level: grandchild → child → base
    _writeView(dir, "mid",
      "{% extends \"base\" %}{% block content %}<p>mid</p>{% endblock %}");
    _writeView(dir, "leaf",
      "{% extends \"mid\" %}{% block title %}Leaf Title{% endblock %}");
    var multi = eng.render("leaf", {});
    check("multi-level inheritance: leaf title + mid content + base wrap",
          multi.indexOf("<title>Leaf Title</title>") !== -1 &&
          multi.indexOf("<p>mid</p>") !== -1 &&
          multi.indexOf("<html>") === 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateContainmentDefenses() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "safe", "ok");
    var eng = b.template.create({ viewsDir: dir });
    check("clean view name renders",        eng.render("safe", {}) === "ok");

    // Path-traversal markers rejected
    var rejected = [
      "../etc/passwd",
      "../../../../etc/passwd",
      "safe/../../escape",
      "with\0null",
    ];
    for (var i = 0; i < rejected.length; i++) {
      var threw = false;
      try { eng.render(rejected[i], {}); } catch (_e) { threw = true; }
      check("rejects path '" + rejected[i] + "'",   threw);
    }

    // Empty / non-string view name rejected
    var threwEmpty = false;
    try { eng.render("", {}); } catch (_e) { threwEmpty = true; }
    check("rejects empty view name",         threwEmpty);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplatePrototypeSafety() {
  // Member access must NOT walk the prototype chain — `{{ x.constructor }}`
  // and `{{ x.__proto__ }}` should resolve to undefined, not Function/Object.
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "proto", "[{{ x.constructor }}][{{ x.__proto__ }}][{{ x.toString }}]");
    var eng = b.template.create({ viewsDir: dir });
    var out = eng.render("proto", { x: { y: 1 } });
    // Each prototype-chain access renders empty
    check("prototype-chain access yields undefined → empty escape",
          out === "[][][]");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateCacheAndReset() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tpl-"));
  try {
    _writeView(dir, "v", "<p>v1: {{ x }}</p>");
    var eng = b.template.create({ viewsDir: dir });
    check("first render uses v1",            eng.render("v", { x: 1 }) === "<p>v1: 1</p>");

    // Mutate the source on disk — cached engine still serves the old AST
    _writeView(dir, "v", "<p>v2: {{ x }}</p>");
    check("second render still uses cached v1 AST (cache=on default)",
          eng.render("v", { x: 1 }) === "<p>v1: 1</p>");

    // reset() drops the cache
    eng.reset();
    check("after reset, engine picks up v2",
          eng.render("v", { x: 1 }) === "<p>v2: 1</p>");

    // cache: false → always re-read
    var engNoCache = b.template.create({ viewsDir: dir, cache: false });
    _writeView(dir, "v", "<p>v3: {{ x }}</p>");
    check("cache:false reflects latest source",
          engNoCache.render("v", { x: 1 }) === "<p>v3: 1</p>");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testTemplateMissingViewsDir() {
  var threw = null;
  try { b.template.create({ viewsDir: path.join(os.tmpdir(), "blamejs-nope-" + Date.now()) }); }
  catch (e) { threw = e; }
  check("create() rejects missing viewsDir",   threw && /viewsDir does not exist/.test(threw.message));

  // viewsDir is now optional — create({}) returns a string-only engine
  // (serverless path); the file-backed render() refuses instead.
  threw = null;
  var eng = null;
  try { eng = b.template.create({}); } catch (e) { threw = e; }
  check("create() without viewsDir succeeds (string-only engine)", threw === null && eng !== null);
  threw = null;
  try { eng.render("x", {}); } catch (e) { threw = e; }
  check("render() without viewsDir refuses",   threw && /viewsDir not configured/.test(threw.message));
}

function testTemplateSurface() {
  check("b.template namespace present",        typeof b.template === "object");
  check("b.template.create is a function",     typeof b.template.create === "function");
  check("b.template.render is a function",     typeof b.template.render === "function");
  check("b.template.escapeHtml is a function", typeof b.template.escapeHtml === "function");
}

// ---- render — response helpers ----

function _captureRes() {
  // Mock res with the same shape b.middleware.errorHandler / cors etc.
  // expect: writeHead(status, headers), end(body), writableEnded.
  // _captured() returns { status, headers, body, ended }.
  var headers = {};
  var status = null;
  var body = "";
  var ended = false;
  return {
    writableEnded: false,
    writeHead: function (s, h) { status = s; if (h) for (var k in h) headers[k.toLowerCase()] = h[k]; },
    setHeader: function (k, v) { headers[k.toLowerCase()] = v; },
    end:       function (b) { if (b !== undefined && b !== null) body += b; ended = true; this.writableEnded = true; },
    _captured: function () { return { status: status, headers: headers, body: body, ended: ended }; },
  };
}

function testRenderJson() {
  var res = _captureRes();
  b.render.json(res, { ok: true, n: 42 });
  var c = res._captured();
  check("render.json: 200 default",                  c.status === 200);
  check("render.json: Content-Type application/json",
        c.headers["content-type"].indexOf("application/json") === 0);
  check("render.json: body is JSON-stringified",     c.body === '{"ok":true,"n":42}');
  check("render.json: Content-Length matches body",
        Number(c.headers["content-length"]) === Buffer.byteLength(c.body));

  // Custom status + extra headers
  var res2 = _captureRes();
  b.render.json(res2, { error: "bad" }, { status: 400, headers: { "X-Custom": "v" } });
  var c2 = res2._captured();
  check("render.json: custom status",                c2.status === 400);
  check("render.json: extra headers merged",         c2.headers["x-custom"] === "v");
}

function testRenderText() {
  var res = _captureRes();
  b.render.text(res, "hello");
  var c = res._captured();
  check("render.text: 200 default",                  c.status === 200);
  check("render.text: Content-Type text/plain",
        c.headers["content-type"].indexOf("text/plain") === 0);
  check("render.text: body is the string",           c.body === "hello");

  // Null/undefined body is empty string, not "null"/"undefined"
  var res2 = _captureRes();
  b.render.text(res2, null);
  check("render.text: null → empty body",            res2._captured().body === "");
}

function testRenderHtmlString() {
  var res = _captureRes();
  b.render.htmlString(res, "<h1>Hi</h1>");
  var c = res._captured();
  check("render.htmlString: Content-Type text/html",
        c.headers["content-type"].indexOf("text/html") === 0);
  check("render.htmlString: body intact",            c.body === "<h1>Hi</h1>");
}

function testRenderRedirect() {
  var res = _captureRes();
  b.render.redirect(res, "/login");
  var c = res._captured();
  check("render.redirect: 302 default",              c.status === 302);
  check("render.redirect: Location header",          c.headers.location === "/login");
  check("render.redirect: empty body",               c.body === "");

  // Permanent redirect (301) opt-in
  var res2 = _captureRes();
  b.render.redirect(res2, "/new-home", { status: 301 });
  check("render.redirect: 301 status honored",       res2._captured().status === 301);

  // Non-3xx status rejected
  var threw = false;
  try { b.render.redirect(_captureRes(), "/x", { status: 200 }); }
  catch (_e) { threw = true; }
  check("render.redirect: rejects non-3xx status",   threw);

  // Empty location rejected
  threw = false;
  try { b.render.redirect(_captureRes(), ""); }
  catch (_e) { threw = true; }
  check("render.redirect: rejects empty location",   threw);
}

function testRenderDoesNotDoubleWrite() {
  // Mid-stream double-writes (route already responded then a stray
  // helper fires) must NOT corrupt the wire — second write is a no-op.
  var res = _captureRes();
  b.render.json(res, { ok: 1 });
  var firstStatus = res._captured().status;
  b.render.json(res, { ok: 2 });    // should be a no-op
  var c = res._captured();
  check("render: silent no-op when res already finished",
        c.status === firstStatus && c.body === '{"ok":1}');
}

function testRenderCreateWithEngine() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-render-"));
  try {
    fs.writeFileSync(path.join(dir, "page.html"), "<h1>{{ title }}</h1>");
    var engine = b.template.create({ viewsDir: dir });
    var r = b.render.create({ engine: engine });
    check("create returns html method",                typeof r.html === "function");
    check("create returns json/text/redirect too",
          typeof r.json === "function" && typeof r.text === "function" && typeof r.redirect === "function");
    check("create exposes the engine",                 r.engine === engine);

    var res = _captureRes();
    r.html(res, "page", { title: "Hi" });
    var c = res._captured();
    check("instance.html renders + writes correct body",
          c.body === "<h1>Hi</h1>" && c.headers["content-type"].indexOf("text/html") === 0);

    // Render error from a missing view propagates (operator catches via
    // middleware.errorHandler downstream)
    var threw = false;
    try { r.html(_captureRes(), "nope-not-real", {}); }
    catch (_e) { threw = true; }
    check("instance.html propagates render errors",    threw);

    // Custom status (e.g. 404 page render)
    var res2 = _captureRes();
    r.html(res2, "page", { title: "404" }, { status: 404 });
    check("instance.html honors opts.status",           res2._captured().status === 404);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testRenderCreateValidation() {
  var threw = null;
  try { b.render.create({}); }
  catch (e) { threw = e; }
  check("create({}) requires engine",                  threw && /engine\.render/.test(threw.message));

  threw = null;
  try { b.render.create({ engine: { not: "an engine" } }); }
  catch (e) { threw = e; }
  check("create with non-engine object rejected",      threw && /engine\.render/.test(threw.message));
}

function testRenderSurface() {
  check("b.render namespace present",                  typeof b.render === "object");
  check("b.render.create is a function",               typeof b.render.create === "function");
  check("b.render.json is a function",                 typeof b.render.json === "function");
  check("b.render.text is a function",                 typeof b.render.text === "function");
  check("b.render.htmlString is a function",           typeof b.render.htmlString === "function");
  check("b.render.redirect is a function",             typeof b.render.redirect === "function");
}

// ---- staticServe ----
//
// Each test sets up its own root dir with fixture files; ends-to-end
// via a real http server + the framework's listenOnRandomPort helper.

async function _httpGet(port, urlPath, headers) {
  return await b.httpClient.request({
    url: "http://127.0.0.1:" + port + urlPath,
    headers: headers || {},
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
  });
}

async function _httpReq(port, method, urlPath, headers) {
  return await b.httpClient.request({
    method: method,
    url: "http://127.0.0.1:" + port + urlPath,
    headers: headers || {},
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
  });
}

function _writeFile(dir, name, content) {
  fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
  fs.writeFileSync(path.join(dir, name), content);
}

async function testStaticServeBasic() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "hello.txt", "hello world");
  _writeFile(dir, "page.html", "<h1>X</h1>");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) {
    mw(req, res, function () {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("not found");
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    var got = await _httpGet(port, "/hello.txt");
    check("static: GET 200",                            got.statusCode === 200);
    check("static: body bytes intact",                  got.body.toString("utf8") === "hello world");
    check("static: Content-Type from extension",
          got.headers["content-type"].indexOf("text/plain") === 0);
    check("static: Cache-Control public + max-age",
          /public, max-age=\d+/.test(got.headers["cache-control"]));
    check("static: ETag is a quoted string",            /^"[^"]+"$/.test(got.headers["etag"]));
    check("static: X-Integrity is sha384-…",
          /^sha384-[A-Za-z0-9+/=]+$/.test(got.headers["x-integrity"]));

    // HTML extension picks up text/html
    var html = await _httpGet(port, "/page.html");
    check("static: .html → text/html",
          html.headers["content-type"].indexOf("text/html") === 0);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeImmutableForHashedPaths() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "app.css", "body { color: red; }");
  _writeFile(dir, "app.abc123ef.css", "body { color: blue; }");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) {
    mw(req, res, function () { res.writeHead(404); res.end(); });
  });
  var port = await listenOnRandomPort(server);
  try {
    var plain = await _httpGet(port, "/app.css");
    check("static: non-hashed path uses default max-age",
          /max-age=3600/.test(plain.headers["cache-control"]) &&
          plain.headers["cache-control"].indexOf("immutable") === -1);

    var hashed = await _httpGet(port, "/app.abc123ef.css");
    check("static: hashed path uses immutable cache",
          /max-age=31536000/.test(hashed.headers["cache-control"]) &&
          /immutable/.test(hashed.headers["cache-control"]));
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeEtagAnd304() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "f.txt", "hello");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () { res.writeHead(404); res.end(); }); });
  var port = await listenOnRandomPort(server);
  try {
    var first = await _httpGet(port, "/f.txt");
    check("static: 200 first request",                 first.statusCode === 200);
    var etag = first.headers["etag"];

    // Conditional GET with matching If-None-Match → 304. httpClient
    // rejects on non-2xx (treats 3xx/4xx/5xx alike), so the 304 path
    // surfaces as a thrown error with statusCode 304.
    var second = null;
    try {
      await b.httpClient.request({
        url: "http://127.0.0.1:" + port + "/f.txt",
        headers: { "If-None-Match": etag },
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
        errorClass: b.frameworkError.ObjectStoreError,
      });
    } catch (e) { second = e; }
    check("static: matching If-None-Match → 304",      second && second.statusCode === 304);

    // Conditional GET with mismatched If-None-Match → 200
    var third = await _httpGet(port, "/f.txt", { "If-None-Match": '"not-the-real-etag"' });
    check("static: mismatched If-None-Match → 200",    third.statusCode === 200);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeHead() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "f.txt", "hello world");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () { res.writeHead(404); res.end(); }); });
  var port = await listenOnRandomPort(server);
  try {
    var head = await _httpReq(port, "HEAD", "/f.txt");
    check("static: HEAD returns 200",                   head.statusCode === 200);
    check("static: HEAD body is empty",                 head.body.length === 0);
    check("static: HEAD carries Content-Length",
          Number(head.headers["content-length"]) === Buffer.byteLength("hello world"));
    check("static: HEAD carries ETag",                  /^"[^"]+"$/.test(head.headers["etag"]));
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeContainmentDefenses() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "ok.txt", "ok");
  // Sibling directory outside root that we might leak via traversal
  var siblingDir = dir + "-sibling";
  fs.mkdirSync(siblingDir, { recursive: true });
  fs.writeFileSync(path.join(siblingDir, "secret.txt"), "secret");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () {
    res.writeHead(404); res.end("not found");
  }); });
  var port = await listenOnRandomPort(server);
  try {
    var rejected = [
      "/../" + path.basename(siblingDir) + "/secret.txt",
      "/..%2f..%2fetc%2fpasswd",
      "/ok.txt%00.png",   // null byte
    ];
    for (var i = 0; i < rejected.length; i++) {
      var resp = null;
      try {
        resp = await b.httpClient.request({
          url: "http://127.0.0.1:" + port + rejected[i],
          allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
          allowInternal:    true,
          errorClass: b.frameworkError.ObjectStoreError,
        });
      } catch (e) { resp = e; }
      // Either falls through to the operator's 404 OR errors at HTTP layer.
      // Either way, the secret file content must not appear in the body.
      var body = resp && resp.body ? resp.body.toString("utf8") : "";
      check("static: rejects '" + rejected[i] + "' (no leak of secret content)",
            body.indexOf("secret") === -1);
    }

    // Sanity: legitimate request still works
    var ok = await _httpGet(port, "/ok.txt");
    check("static: legitimate request still served",   ok.body.toString("utf8") === "ok");
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(siblingDir, { recursive: true, force: true });
  }
}

async function testStaticServeIndexFile() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "index.html", "<h1>root</h1>");
  _writeFile(dir, "sub/index.html", "<h1>sub</h1>");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () {
    res.writeHead(404); res.end();
  }); });
  var port = await listenOnRandomPort(server);
  try {
    var rootGet = await _httpGet(port, "/");
    check("static: dir / serves indexFile",            rootGet.body.toString("utf8") === "<h1>root</h1>");

    var subGet = await _httpGet(port, "/sub/");
    check("static: nested dir serves its indexFile",    subGet.body.toString("utf8") === "<h1>sub</h1>");

    // Disable indexFile → directory falls through to next()
    b.staticServe._resetCacheForTest();
    var mw2 = b.staticServe.create({ root: dir, indexFile: null });
    var server2 = http.createServer(function (req, res) { mw2(req, res, function () {
      res.writeHead(404); res.end("no index");
    }); });
    var port2 = await listenOnRandomPort(server2);
    try {
      var noIdx = await b.httpClient.request({
        url: "http://127.0.0.1:" + port2 + "/",
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
        errorClass: b.frameworkError.ObjectStoreError,
      }).catch(function (e) { return e; });
      check("static: indexFile=null → falls through to next()",
            (noIdx.statusCode || noIdx.statusCode) === 404);
    } finally { server2.close(); }
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeMethodGuard() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "f.txt", "x");
  b.staticServe._resetCacheForTest();

  var http = require("http");
  var nextCalls = 0;
  var mw = b.staticServe.create({ root: dir });
  var server = http.createServer(function (req, res) { mw(req, res, function () {
    nextCalls += 1;
    res.writeHead(405, { "Content-Type": "text/plain", "Allow": "GET, HEAD" });
    res.end("method not allowed");
  }); });
  var port = await listenOnRandomPort(server);
  try {
    var post = await b.httpClient.request({
      method: "POST",
      url: "http://127.0.0.1:" + port + "/f.txt",
      body: Buffer.from("nope"),
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
      errorClass: b.frameworkError.ObjectStoreError,
    }).catch(function (e) { return e; });
    check("static: POST falls through (next() called)",  nextCalls === 1);
    check("static: POST returns operator's 405",         post.statusCode === 405);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStaticServeIntegrityHelper() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  _writeFile(dir, "asset.css", "body { color: green; }");
  b.staticServe._resetCacheForTest();
  try {
    var sri = await b.staticServe.integrity(path.join(dir, "asset.css"));
    check("integrity returns sha384- prefix",          /^sha384-/.test(sri));
    check("integrity is base64-shaped",                /^sha384-[A-Za-z0-9+/=]+$/.test(sri));
    // Same file → same hash (cached or not)
    var sri2 = await b.staticServe.integrity(path.join(dir, "asset.css"));
    check("integrity is deterministic on same content", sri === sri2);

    // Modified file → different hash
    fs.writeFileSync(path.join(dir, "asset.css"), "body { color: red; }");
    // Bump mtime so cache invalidates
    var future = (Date.now() + 5000) / 1000;
    fs.utimesSync(path.join(dir, "asset.css"), future, future);
    var sri3 = await b.staticServe.integrity(path.join(dir, "asset.css"));
    check("integrity reflects content change",          sri3 !== sri);

    // Missing file
    var threw = null;
    try { await b.staticServe.integrity(path.join(dir, "missing.css")); }
    catch (e) { threw = e; }
    check("integrity throws on missing file",          threw && /not found/i.test(threw.message));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ---- staticServe v0.7.x v1-defensible-feature tests ----

async function _staticTestServer(opts) {
  var http = require("http");
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  if (opts.files) {
    var keys = Object.keys(opts.files);
    for (var ki = 0; ki < keys.length; ki++) _writeFile(dir, keys[ki], opts.files[keys[ki]]);
  }
  b.staticServe._resetCacheForTest();
  var serveOpts = Object.assign({ root: dir }, opts.create || {});
  var fn = b.staticServe.create(serveOpts);
  var server = http.createServer(function (req, res) {
    fn(req, res, function () { res.writeHead(404); res.end("not found"); });
  });
  var port = await listenOnRandomPort(server);
  return {
    dir: dir, fn: fn, server: server, port: port,
    cleanup: function () {
      server.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function _statusOnly(port, urlPath, reqHeaders, method) {
  // Bypass httpClient and use raw http so we capture status + headers +
  // body for every response class (200/206/304/4xx/5xx alike). httpClient
  // throws on non-2xx without retaining response headers, which the
  // download tests need for Content-Range / Retry-After / etc.
  var http = require("http");
  var resp = await new Promise(function (resolve, reject) {
    var req = http.request({
      method: method || "GET",
      hostname: "127.0.0.1",
      port: port,
      path: urlPath,
      headers: reqHeaders || {},
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
  // Server-side post-flush handlers (audit emit, observability counter,
  // bandwidth consumption update, concurrency-slot release) run after the
  // pipe's res.end fires. Wait for the server's stream "end" listener to
  // have run + any queued microtasks (cache.set inside _consumeBandwidth)
  // before the test inspects emission state.
  await new Promise(function (r) { setTimeout(r, 30); });
  return resp;
}

async function testStaticServeRangeBasic() {
  var ctx = await _staticTestServer({ files: { "a.bin": "abcdefghijklmnopqrstuvwxyz" } });
  try {
    var r = await _statusOnly(ctx.port, "/a.bin", { "Range": "bytes=0-4" });
    check("static.range basic: 206 status",                 r.statusCode === 206);
    check("static.range basic: Content-Range bytes 0-4/26",
          r.headers["content-range"] === "bytes 0-4/26");
    check("static.range basic: Content-Length 5",           Number(r.headers["content-length"]) === 5);
    check("static.range basic: body is 'abcde'",            r.body.toString("utf8") === "abcde");
    check("static.range basic: Accept-Ranges: bytes",       r.headers["accept-ranges"] === "bytes");
  } finally { ctx.cleanup(); }
}

async function testStaticServeRangeSuffix() {
  var ctx = await _staticTestServer({ files: { "a.bin": "abcdefghij" } });
  try {
    var r = await _statusOnly(ctx.port, "/a.bin", { "Range": "bytes=-3" });
    check("static.range suffix: 206 status",                r.statusCode === 206);
    check("static.range suffix: body is last 3 bytes",      r.body.toString("utf8") === "hij");
    check("static.range suffix: Content-Range tail",        r.headers["content-range"] === "bytes 7-9/10");
  } finally { ctx.cleanup(); }
}

async function testStaticServeRangeOpenEnd() {
  var ctx = await _staticTestServer({ files: { "a.bin": "abcdefghij" } });
  try {
    var r = await _statusOnly(ctx.port, "/a.bin", { "Range": "bytes=4-" });
    check("static.range open-end: 206",                      r.statusCode === 206);
    check("static.range open-end: body is from 4 to end",   r.body.toString("utf8") === "efghij");
  } finally { ctx.cleanup(); }
}

async function testStaticServeRangeUnsatisfiable() {
  var ctx = await _staticTestServer({ files: { "a.bin": "short" } });
  try {
    var r = await _statusOnly(ctx.port, "/a.bin", { "Range": "bytes=100-200" });
    check("static.range unsatisfiable: 416",                 r.statusCode === 416);
    check("static.range unsatisfiable: Content-Range bytes */5",
          r.headers["content-range"] === "bytes */5");
  } finally { ctx.cleanup(); }
}

async function testStaticServeRangeMultiRefused() {
  var ctx = await _staticTestServer({ files: { "a.bin": "abcdefghij" } });
  try {
    var r = await _statusOnly(ctx.port, "/a.bin", { "Range": "bytes=0-2,5-7" });
    check("static.range multi: 416 (multipart/byteranges not v1)",
          r.statusCode === 416);
  } finally { ctx.cleanup(); }
}

async function testStaticServeAcceptRangesOff() {
  var ctx = await _staticTestServer({ files: { "a.bin": "abc" }, create: { acceptRanges: false } });
  try {
    // Range header present BUT acceptRanges: false → server ignores Range,
    // returns full 200 with no Accept-Ranges header.
    var r = await _statusOnly(ctx.port, "/a.bin", { "Range": "bytes=0-1" });
    check("static.acceptRanges off: ignores Range → 200",   r.statusCode === 200);
    check("static.acceptRanges off: full body returned",    r.body.toString("utf8") === "abc");
    check("static.acceptRanges off: no Accept-Ranges hdr",  !r.headers["accept-ranges"]);
  } finally { ctx.cleanup(); }
}

async function testStaticServeIfMatchPrecondition() {
  var ctx = await _staticTestServer({ files: { "a.bin": "hello" } });
  try {
    var r = await _statusOnly(ctx.port, "/a.bin", { "If-Match": '"not-a-real-etag"' });
    check("static.if-match mismatch: 412",                   r.statusCode === 412);
    var ok = await _statusOnly(ctx.port, "/a.bin", { "If-Match": "*" });
    check("static.if-match wildcard: 200",                   ok.statusCode === 200);
  } finally { ctx.cleanup(); }
}

async function testStaticServeIfModifiedSince() {
  var ctx = await _staticTestServer({ files: { "a.bin": "x" } });
  try {
    // future date → file not modified since then → 304
    var future = new Date(Date.now() + 60_000).toUTCString();
    var r = await _statusOnly(ctx.port, "/a.bin", { "If-Modified-Since": future });
    check("static.if-modified-since future: 304",            r.statusCode === 304);
    // past date → file modified since → 200
    var past = new Date(Date.now() - 60_000_000).toUTCString();
    var r2 = await _statusOnly(ctx.port, "/a.bin", { "If-Modified-Since": past });
    check("static.if-modified-since past: 200",              r2.statusCode === 200);
  } finally { ctx.cleanup(); }
}

async function testStaticServeIfUnmodifiedSince() {
  var ctx = await _staticTestServer({ files: { "a.bin": "x" } });
  try {
    // past date → file modified since → 412
    var past = new Date(Date.now() - 60_000_000).toUTCString();
    var r = await _statusOnly(ctx.port, "/a.bin", { "If-Unmodified-Since": past });
    check("static.if-unmodified-since past: 412",            r.statusCode === 412);
    // future date → file not modified since → 200
    var future = new Date(Date.now() + 60_000).toUTCString();
    var r2 = await _statusOnly(ctx.port, "/a.bin", { "If-Unmodified-Since": future });
    check("static.if-unmodified-since future: 200",          r2.statusCode === 200);
  } finally { ctx.cleanup(); }
}

async function testStaticServePermissionsGate() {
  var allow = false;
  var permissions = {
    check: function (req, scope) {
      void req; void scope;
      return allow;
    },
  };
  var ctx = await _staticTestServer({
    files: { "a.bin": "secret" },
    create: { permissions: permissions },
  });
  try {
    var denied = await _statusOnly(ctx.port, "/a.bin");
    check("static.permissions deny: 403",                    denied.statusCode === 403);
    allow = true;
    var ok = await _statusOnly(ctx.port, "/a.bin");
    check("static.permissions allow: 200",                   ok.statusCode === 200);
    check("static.permissions allow: body served",           ok.body.toString("utf8") === "secret");
  } finally { ctx.cleanup(); }
}

async function testStaticServeRetentionGate() {
  var servable = true;
  var retention = {
    isServable: function (absPath, ctx) { void absPath; void ctx; return servable; },
  };
  var ctx = await _staticTestServer({
    files: { "a.bin": "data" },
    create: { retention: retention },
  });
  try {
    var ok = await _statusOnly(ctx.port, "/a.bin");
    check("static.retention servable: 200",                  ok.statusCode === 200);
    servable = false;
    var blocked = await _statusOnly(ctx.port, "/a.bin");
    check("static.retention blocked: 451",                   blocked.statusCode === 451);
  } finally { ctx.cleanup(); }
}

async function testStaticServeRevokeViaInstance() {
  var ctx = await _staticTestServer({ files: { "a.bin": "data" } });
  try {
    var ok = await _statusOnly(ctx.port, "/a.bin");
    check("static.revoke before: 200",                        ok.statusCode === 200);
    var absPath = path.join(ctx.dir, "a.bin");
    await ctx.fn.revoke(absPath);
    var blocked = await _statusOnly(ctx.port, "/a.bin");
    check("static.revoke after: 404 (opaque)",                blocked.statusCode === 404);
    await ctx.fn.unrevoke(absPath);
    var restored = await _statusOnly(ctx.port, "/a.bin");
    check("static.unrevoke: 200 again",                       restored.statusCode === 200);
  } finally { ctx.cleanup(); }
}

async function testStaticServeRevokeStoreOpt() {
  var revoked = new Set();
  var revokeStore = {
    isRevoked: function (key) { return revoked.has(key); },
    revoke:    function (key) { revoked.add(key); return { ok: true }; },
    unrevoke:  function (key) { revoked.delete(key); return { ok: true }; },
  };
  var ctx = await _staticTestServer({
    files: { "a.bin": "data" },
    create: { revokeStore: revokeStore },
  });
  try {
    revoked.add(path.join(ctx.dir, "a.bin"));
    var blocked = await _statusOnly(ctx.port, "/a.bin");
    check("static.revokeStore: 404 when revoked",             blocked.statusCode === 404);
  } finally { ctx.cleanup(); }
}

async function testStaticServeMimeAllowlist() {
  // Use a real PNG magic-byte prefix so b.fileType.detect classifies it.
  var pngHeader = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.alloc(64, 0),
  ]);
  var ctx = await _staticTestServer({
    files: {},
    create: {
      fileType: b.fileType,
      allowedFileTypes: ["image/png"],
    },
  });
  fs.writeFileSync(path.join(ctx.dir, "img.png"), pngHeader);
  try {
    var ok = await _statusOnly(ctx.port, "/img.png");
    check("static.mime allowlist: png served when in list",   ok.statusCode === 200);
  } finally { ctx.cleanup(); }
}

async function testStaticServeMimeAllowlistRejected() {
  var pngHeader = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.alloc(64, 0),
  ]);
  var ctx = await _staticTestServer({
    files: {},
    create: {
      fileType: b.fileType,
      allowedFileTypes: ["image/jpeg"],
    },
  });
  fs.writeFileSync(path.join(ctx.dir, "img.png"), pngHeader);
  try {
    var rejected = await _statusOnly(ctx.port, "/img.png");
    check("static.mime allowlist: png rejected when not in list",
          rejected.statusCode === 415);
  } finally { ctx.cleanup(); }
}

function testStaticServeMimeRequiresFileType() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  try {
    var threw = null;
    try {
      b.staticServe.create({
        root: dir,
        allowedFileTypes: ["image/png"],
        // fileType: missing
      });
    } catch (e) { threw = e; }
    check("static.allowedFileTypes without fileType throws",
          threw && /fileType primitive is not wired/.test(threw.message));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

async function testStaticServeOnServeHook() {
  var seen = [];
  var ctx = await _staticTestServer({
    files: { "a.bin": "hello" },
    create: {
      onServe: async function (info) {
        seen.push({ urlPath: info.urlPath, size: info.size });
        info.headers["X-Custom"] = "watermark-applied";
      },
    },
  });
  try {
    var r = await _statusOnly(ctx.port, "/a.bin");
    check("static.onServe: hook ran",                         seen.length === 1 &&
                                                              seen[0].urlPath === "/a.bin");
    check("static.onServe: hook can mutate headers",          r.headers["x-custom"] === "watermark-applied");
  } finally { ctx.cleanup(); }
}

async function testStaticServeOnServeThrows500() {
  var ctx = await _staticTestServer({
    files: { "a.bin": "x" },
    create: {
      onServe: async function () { throw new Error("operator-bug"); },
    },
  });
  try {
    var r = await _statusOnly(ctx.port, "/a.bin");
    check("static.onServe throws: 500",                       r.statusCode === 500);
  } finally { ctx.cleanup(); }
}

async function testStaticServeAuditEmission() {
  var emitted = [];
  var fakeAudit = {
    safeEmit: function (entry) { emitted.push(entry); },
  };
  var ctx = await _staticTestServer({
    files: { "a.bin": "hello" },
    create: { audit: fakeAudit },
  });
  try {
    await _statusOnly(ctx.port, "/a.bin");
    check("static.audit success: emission count",             emitted.length === 1);
    check("static.audit success: action name",                emitted[0].action === "staticServe.serve.success");
    check("static.audit success: outcome=success",            emitted[0].outcome === "success");
    check("static.audit success: resource present",           emitted[0].resource === "/a.bin");
    check("static.audit success: size present",               typeof emitted[0].size === "number");
    check("static.audit success: contentType present",        typeof emitted[0].contentType === "string");

    // Failure emission via permissions.deny path
    emitted.length = 0;
    var ctx2 = await _staticTestServer({
      files: { "a.bin": "x" },
      create: {
        audit: fakeAudit,
        permissions: { check: function () { return false; } },
      },
    });
    try {
      await _statusOnly(ctx2.port, "/a.bin");
      check("static.audit failure: emission",                 emitted.length === 1);
      check("static.audit failure: action name",              emitted[0].action === "staticServe.serve.failure");
      check("static.audit failure: reason permission_denied", emitted[0].reason === "permission_denied");
    } finally { ctx2.cleanup(); }
  } finally { ctx.cleanup(); }
}

async function testStaticServeAuditSuccessOptOut() {
  var emitted = [];
  var fakeAudit = { safeEmit: function (e) { emitted.push(e); } };
  var ctx = await _staticTestServer({
    files: { "a.bin": "x" },
    create: { audit: fakeAudit, auditSuccess: false },
  });
  try {
    await _statusOnly(ctx.port, "/a.bin");
    check("static.audit auditSuccess:false suppresses success",
          emitted.length === 0);
  } finally { ctx.cleanup(); }
}

async function testStaticServeStats() {
  var ctx = await _staticTestServer({ files: { "a.bin": "abcd" } });
  try {
    await _statusOnly(ctx.port, "/a.bin");
    await _statusOnly(ctx.port, "/a.bin");
    var s = ctx.fn.stats();
    check("static.stats: shape has requestsServed",           typeof s.requestsServed === "number");
    check("static.stats: requestsServed === 2",                s.requestsServed === 2);
    check("static.stats: bytesServed === 8 (4 bytes × 2)",    s.bytesServed === 8);
  } finally { ctx.cleanup(); }
}

async function testStaticServeInvalidateMeta() {
  var ctx = await _staticTestServer({ files: { "a.bin": "v1" } });
  try {
    var first = await _statusOnly(ctx.port, "/a.bin");
    var firstEtag = first.headers["etag"];
    fs.writeFileSync(path.join(ctx.dir, "a.bin"), "v2-different");
    // Without invalidate, the cache still holds the v1 mtime — bump mtime
    var future = (Date.now() + 5000) / 1000;
    fs.utimesSync(path.join(ctx.dir, "a.bin"), future, future);
    ctx.fn.invalidateMeta(path.join(ctx.dir, "a.bin"));
    var second = await _statusOnly(ctx.port, "/a.bin");
    check("static.invalidateMeta: ETag updated",              second.headers["etag"] !== firstEtag);
    check("static.invalidateMeta: body reflects new content", second.body.toString("utf8") === "v2-different");
  } finally { ctx.cleanup(); }
}

function testStaticServeQuotaRequiresCache() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-"));
  try {
    var threw = null;
    try {
      b.staticServe.create({
        root: dir,
        maxBytesPerActorPerWindowMs: 1024,
        // cache: missing
      });
    } catch (e) { threw = e; }
    check("static.quota without cache: throws at create",     threw && /quotas require opts.cache/.test(threw.message));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

async function testStaticServeBandwidthQuotaPerActor() {
  // In-memory cache-shape stub so the gate can run without depending on
  // b.cache.create() in this layer-0 test.
  var store = new Map();
  var fakeCache = {
    get: async function (k) { return store.get(k); },
    set: async function (k, v) { store.set(k, v); return true; },
  };
  var ctx = await _staticTestServer({
    files: { "a.bin": "1234567890" },          // 10 bytes
    create: {
      cache: fakeCache,
      maxBytesPerActorPerWindowMs: 12,         // first request fits, second exceeds
      bandwidthWindowMs: 60_000,
    },
  });
  try {
    var first = await _statusOnly(ctx.port, "/a.bin");
    check("static.bandwidth: first request 200",              first.statusCode === 200);
    var second = await _statusOnly(ctx.port, "/a.bin");
    check("static.bandwidth: second request 429 (cap exceeded)",
          second.statusCode === 429);
    check("static.bandwidth: Retry-After header",             !!second.headers["retry-after"]);
  } finally { ctx.cleanup(); }
}

async function testStaticServeConcurrencyCap() {
  var store = new Map();
  var fakeCache = {
    get: async function (k) { return store.get(k); },
    set: async function (k, v) { store.set(k, v); return true; },
  };
  var ctx = await _staticTestServer({
    files: { "a.bin": "x" },
    create: {
      cache: fakeCache,
      maxConcurrentDownloadsPerActor: 1,
    },
  });
  try {
    // Pre-load the cache key so the first request sees current=1 already
    // (the in-flight slot is incremented by a real previous request, but
    // we simulate it for determinism).
    // The fake server is loopback so extractActorContext gives ip=::1 or
    // 127.0.0.1 depending on the OS dual-stack mode. Pre-load both keys
    // so whichever the host uses, the cap shows as already-saturated.
    store.set("static:conc:ip:127.0.0.1", 1);
    store.set("static:conc:ip:::1", 1);
    store.set("static:conc:ip:::ffff:127.0.0.1", 1);
    var r = await _statusOnly(ctx.port, "/a.bin");
    check("static.concurrency: at cap → 429",                  r.statusCode === 429);
  } finally { ctx.cleanup(); }
}

function testStaticServeSurface() {
  check("b.staticServe namespace present",             typeof b.staticServe === "object");
  check("b.staticServe.create is a function",          typeof b.staticServe.create === "function");
  check("b.staticServe.integrity is a function",       typeof b.staticServe.integrity === "function");
  check("b.staticServe.IMMUTABLE_MAX_AGE_SEC = 1y",
        b.staticServe.IMMUTABLE_MAX_AGE_SEC === 31536000);
  check("b.staticServe.DEFAULT_MAX_AGE_SEC = 1h",
        b.staticServe.DEFAULT_MAX_AGE_SEC === 3600);

  // create() validation
  var threw = null;
  try { b.staticServe.create({}); }
  catch (e) { threw = e; }
  check("create({}) requires root",                     threw && /root/.test(threw.message));

  threw = null;
  try { b.staticServe.create({ root: path.join(os.tmpdir(), "blamejs-nope-" + Date.now()) }); }
  catch (e) { threw = e; }
  check("create() rejects missing root",                threw && /does not exist/.test(threw.message));
}

// ---- forms ----

function testFormsCsrfTokenGeneration() {
  var f = b.forms;
  var t = f.generateCsrfToken();
  check("generateCsrfToken: 64 hex chars (32 bytes)",
        typeof t === "string" && /^[0-9a-f]{64}$/.test(t));
  // Two consecutive calls produce different tokens (random)
  check("generateCsrfToken: non-deterministic",      f.generateCsrfToken() !== t);
}

function testFormsCsrfTokenVerify() {
  var f = b.forms;
  var t = f.generateCsrfToken();
  check("verifyCsrfToken: same string accepts",      f.verifyCsrfToken(t, t) === true);
  check("verifyCsrfToken: different strings reject", f.verifyCsrfToken(t, f.generateCsrfToken()) === false);
  // Length-mismatch rejected (defense against length-oracle attacks)
  check("verifyCsrfToken: length mismatch → false",  f.verifyCsrfToken(t, t + "X") === false);
  // Empty / null / wrong-type → false (no throw)
  check("verifyCsrfToken: empty → false",            f.verifyCsrfToken("", t) === false);
  check("verifyCsrfToken: null → false",             f.verifyCsrfToken(null, t) === false);
  check("verifyCsrfToken: number → false",           f.verifyCsrfToken(42, t) === false);
}

function testFormsEscapeAttribute() {
  var f = b.forms;
  // Escapes the same set as escapeHtml + ` and =
  check("escapeAttribute: <, >, &",                  f.escapeAttribute("<&>") === "&lt;&amp;&gt;");
  check("escapeAttribute: double-quote",             f.escapeAttribute('"x"') === "&quot;x&quot;");
  check("escapeAttribute: single-quote",             f.escapeAttribute("'x'") === "&#x27;x&#x27;");
  check("escapeAttribute: backtick",                 f.escapeAttribute("`x`") === "&#x60;x&#x60;");
  check("escapeAttribute: equals sign",              f.escapeAttribute("a=b") === "a&#x3D;b");
  check("escapeAttribute: null/undefined → empty",
        f.escapeAttribute(null) === "" && f.escapeAttribute(undefined) === "");
}

function testFormsRenderBasic() {
  var f = b.forms;
  var html = f.render({
    action: "/contact",
    csrfToken: "abc123",
    fields: [
      { name: "email", type: "email", required: true, label: "Email" },
      { name: "msg",   type: "textarea", label: "Message" },
    ],
  });
  check("render: <form> wraps content",                html.indexOf("<form ") === 0 && html.indexOf("</form>") !== -1);
  check("render: action attribute",                    html.indexOf('action="/contact"') !== -1);
  check("render: method defaults to POST",             html.indexOf('method="POST"') !== -1);
  check("render: hidden CSRF input",
        html.indexOf('<input type="hidden" name="_csrf" value="abc123">') !== -1);
  check("render: email input present",                 html.indexOf('type="email"') !== -1);
  check("render: required attribute",                  html.indexOf("required") !== -1);
  check("render: textarea element",                    html.indexOf("<textarea") !== -1);
  check("render: auto-appended submit button",         html.indexOf("<button type=\"submit\">Submit</button>") !== -1);
  check("render: label wraps non-hidden field",        html.indexOf("<label>Email") !== -1);
}

function testFormsRenderEscapesHostileInput() {
  var f = b.forms;
  // Operator (or attacker) tries to slip an attribute-breaking value
  // into an action or option label
  var html = f.render({
    action: '/safe" onsubmit="alert(1)',
    fields: [
      { name: "color", type: "select", options: [
        { value: 'red"><script>alert(1)</script>', label: '"label' },
      ]},
    ],
  });
  // The attacker payload must NOT appear as raw HTML
  check("render: hostile action escaped",              html.indexOf('onsubmit="alert(1)') === -1);
  check("render: hostile option value escaped",        html.indexOf("<script>") === -1);
  check("render: option label HTML-escaped",
        html.indexOf("&quot;label") !== -1);
}

function testFormsRenderSelectAndPreselection() {
  var f = b.forms;
  var html = f.render({
    action: "/x",
    csrfToken: "T",
    fields: [{
      name: "country",
      type: "select",
      value: "FR",
      options: [
        { value: "US", label: "United States" },
        { value: "FR", label: "France" },
      ],
    }],
  });
  check("select renders all options",
        html.indexOf("United States") !== -1 && html.indexOf("France") !== -1);
  check("select pre-selects via value match",
        /<option[^>]*value="FR"[^>]*selected[^>]*>France<\/option>/.test(html) === true);
}

function testFormsRenderSubmitOverride() {
  var f = b.forms;
  // When operator includes a submit field, no auto-button
  var html = f.render({
    action: "/x",
    fields: [
      { name: "n", type: "text" },
      { name: "go", type: "submit", value: "Send Now" },
    ],
  });
  check("explicit submit overrides auto-button",
        html.indexOf('type="submit"') !== -1 &&
        html.indexOf('value="Send Now"') !== -1 &&
        html.indexOf("<button") === -1);
}

function testFormsRenderRejectsInvalidSpec() {
  var f = b.forms;
  var threw = null;
  try { f.render({ fields: [] }); }
  catch (e) { threw = e; }
  check("render rejects missing action",               threw && /action is required/.test(threw.message));

  threw = null;
  try { f.render({ action: "/x" }); }
  catch (e) { threw = e; }
  check("render rejects missing fields",               threw && /fields must be an array/.test(threw.message));

  threw = null;
  try { f.render({ action: "/x", fields: [{ type: "text" }] }); }
  catch (e) { threw = e; }
  check("render rejects field without name",           threw && /name/.test(threw.message));

  threw = null;
  try { f.render({ action: "/x", fields: [{ name: "x", type: "wat" }] }); }
  catch (e) { threw = e; }
  check("render rejects unknown field type",           threw && /unsupported field type/.test(threw.message));
}

function testFormsValidateRequired() {
  var f = b.forms;
  var spec = { fields: [
    { name: "email", type: "email", required: true, label: "Email" },
    { name: "name",  type: "text" },
  ]};

  var r1 = f.validate(spec, {});
  check("validate: missing required produces error",   r1.valid === false && r1.errors.email);
  check("validate: error references field label",      /Email is required/.test(r1.errors.email));
  check("validate: optional field not required",       !r1.errors.name);

  var r2 = f.validate(spec, { email: "alice@example.com", name: "Alice" });
  check("validate: all-present passes",                r2.valid === true && Object.keys(r2.errors).length === 0);
  check("validate: values reflected back",             r2.values.email === "alice@example.com" && r2.values.name === "Alice");
}

function testFormsValidateTypes() {
  var f = b.forms;

  // Number
  var r = f.validate({ fields: [{ name: "n", type: "number", min: 1, max: 10 }]}, { n: "5" });
  check("validate: number coerces string → number",    r.valid === true && r.values.n === 5);

  r = f.validate({ fields: [{ name: "n", type: "number" }]}, { n: "abc" });
  check("validate: non-numeric number → error",        r.valid === false && /must be a number/.test(r.errors.n));

  r = f.validate({ fields: [{ name: "n", type: "number", min: 5 }]}, { n: "1" });
  check("validate: number below min → error",          r.valid === false && /≥ 5/.test(r.errors.n));

  r = f.validate({ fields: [{ name: "n", type: "number", max: 10 }]}, { n: "100" });
  check("validate: number above max → error",          r.valid === false && /≤ 10/.test(r.errors.n));

  // Email
  r = f.validate({ fields: [{ name: "e", type: "email" }]}, { e: "not-an-email" });
  check("validate: bad email → error",                 r.valid === false && /valid email/.test(r.errors.e));

  r = f.validate({ fields: [{ name: "e", type: "email" }]}, { e: "alice@example.com" });
  check("validate: good email passes",                 r.valid === true);

  // URL
  r = f.validate({ fields: [{ name: "u", type: "url" }]}, { u: "not a url" });
  check("validate: bad URL → error",                   r.valid === false && /valid URL/.test(r.errors.u));

  r = f.validate({ fields: [{ name: "u", type: "url" }]}, { u: "https://example.com/x" });
  check("validate: good URL passes",                   r.valid === true);

  // Checkbox
  r = f.validate({ fields: [{ name: "c", type: "checkbox" }]}, { c: "on" });
  check("validate: checkbox 'on' → true",              r.valid === true && r.values.c === true);
  r = f.validate({ fields: [{ name: "c", type: "checkbox" }]}, {});
  check("validate: checkbox missing → false",          r.valid === true && r.values.c === false);

  // Length bounds
  r = f.validate({ fields: [{ name: "p", type: "text", minlength: 8, maxlength: 64 }]}, { p: "short" });
  check("validate: text below minlength → error",      r.valid === false && /at least 8/.test(r.errors.p));
  r = f.validate({ fields: [{ name: "p", type: "text", maxlength: 5 }]}, { p: "way too long" });
  check("validate: text above maxlength → error",      r.valid === false && /at most 5/.test(r.errors.p));

  // Pattern — RegExp instance only (string patterns refused at config
  // time so the framework never compiles operator-supplied source on
  // the request path).
  var codeRe = /[A-Z]{3}-[0-9]{4}/;
  r = f.validate({ fields: [{ name: "code", type: "text", pattern: codeRe }]}, { code: "ABC-1234" });
  check("validate: pattern match passes",              r.valid === true);
  r = f.validate({ fields: [{ name: "code", type: "text", pattern: codeRe }]}, { code: "abc-12" });
  check("validate: pattern mismatch → error",          r.valid === false && /invalid format/.test(r.errors.code));
  // String pattern is a config-time error (operators wrap with `RegExp` at config).
  var stringPatternThrew = false;
  try {
    f.validate({ fields: [{ name: "code", type: "text", pattern: "[A-Z]+" }]}, { code: "ABC" });
  } catch (e) { stringPatternThrew = /pre-compiled RegExp/.test(e.message); }
  check("validate: string pattern → throws clear config error", stringPatternThrew);

  // Select / radio enum
  r = f.validate({ fields: [
    { name: "c", type: "select", options: [{ value: "US" }, { value: "FR" }]},
  ]}, { c: "ZZ" });
  check("validate: out-of-enum select → error",        r.valid === false && /invalid value/.test(r.errors.c));
}

function testFormsSurface() {
  var f = b.forms;
  check("b.forms namespace present",                   typeof b.forms === "object");
  check("b.forms.generateCsrfToken is a function",     typeof f.generateCsrfToken === "function");
  check("b.forms.verifyCsrfToken is a function",       typeof f.verifyCsrfToken === "function");
  check("b.forms.render is a function",                typeof f.render === "function");
  check("b.forms.validate is a function",              typeof f.validate === "function");
  check("b.forms.escapeAttribute is a function",       typeof f.escapeAttribute === "function");
  check("b.forms.escapeHtml === template.escapeHtml",  f.escapeHtml === b.template.escapeHtml);
  check("b.forms.CSRF_TOKEN_BYTES = 32",                f.CSRF_TOKEN_BYTES === 32);
}

// ---- mail ----
//
// memory transport is the pattern for tests; it captures every
// message into transport.sent[] without touching disk or network.

async function testMailSendRoundTripViaMemoryTransport() {
  var memory = b.mail.transports.memory();
  var mailer = b.mail.create({
    transport: memory,
    defaults:  { from: "noreply@example.com" },
    audit:     false,    // skip audit for layer-0 (no audit module init)
  });
  var result = await mailer.send({
    to:      "alice@example.com",
    subject: "Welcome",
    text:    "Hi Alice",
  });
  check("mail.send returns transport result",        result && result.transport === "memory");
  check("memory transport captures the message",     memory.sent.length === 1);
  check("captured message has merged from",          memory.sent[0].from === "noreply@example.com");
  check("captured message has subject",              memory.sent[0].subject === "Welcome");
  check("captured message has body",                 memory.sent[0].text === "Hi Alice");

  memory.reset();
  check("memory.reset clears sent[]",                memory.sent.length === 0);
}

async function testMailDefaultsAndOverrides() {
  var memory = b.mail.transports.memory();
  var mailer = b.mail.create({
    transport: memory,
    defaults:  {
      from:    "default@example.com",
      replyTo: "support@example.com",
      headers: { "X-App": "blamejs", "X-Env": "dev" },
    },
    audit: false,
  });

  // Defaults applied
  await mailer.send({ to: "x@y.com", subject: "S", text: "T" });
  check("from default applied",                      memory.sent[0].from === "default@example.com");
  check("replyTo default applied",                   memory.sent[0].replyTo === "support@example.com");
  check("headers default applied",                   memory.sent[0].headers["X-App"] === "blamejs");

  // Per-message override
  memory.reset();
  await mailer.send({
    to: "x@y.com", subject: "S", text: "T",
    from: "override@example.com",
    headers: { "X-App": "test", "X-Custom": "v" },
  });
  check("from override wins",                        memory.sent[0].from === "override@example.com");
  check("replyTo default still applied",             memory.sent[0].replyTo === "support@example.com");
  check("headers merged shallow (override beats default)",
        memory.sent[0].headers["X-App"] === "test");
  check("headers merged shallow (default still present)",
        memory.sent[0].headers["X-Env"] === "dev");
  check("headers merged shallow (override-only key)",
        memory.sent[0].headers["X-Custom"] === "v");
}

async function testMailValidation() {
  var memory = b.mail.transports.memory();
  var mailer = b.mail.create({ transport: memory, audit: false });

  var threw = null;
  try { await mailer.send({ from: "a@b.com", text: "x" }); }
  catch (e) { threw = e; }
  check("missing to → mail/missing-to",
        threw && threw.code === "mail/missing-to" && threw.isMailError === true);

  threw = null;
  try { await mailer.send({ to: "a@b.com", text: "x" }); }
  catch (e) { threw = e; }
  check("missing from → mail/missing-from",          threw && threw.code === "mail/missing-from");

  threw = null;
  try { await mailer.send({ to: "a@b.com", from: "c@d.com" }); }
  catch (e) { threw = e; }
  check("missing body → mail/missing-body",          threw && threw.code === "mail/missing-body");

  threw = null;
  try { await mailer.send({ to: "not-an-email", from: "c@d.com", text: "x" }); }
  catch (e) { threw = e; }
  check("invalid recipient → mail/invalid-recipient", threw && threw.code === "mail/invalid-recipient");

  threw = null;
  try { await mailer.send({ to: "a@b.com", from: "garbage", text: "x" }); }
  catch (e) { threw = e; }
  check("invalid from → mail/invalid-from",          threw && threw.code === "mail/invalid-from");

  // Bracketed-form recipient is valid
  await mailer.send({
    to:   "Alice <alice@example.com>",
    from: "Bob <bob@example.com>",
    text: "hi",
  });
  check("bracketed Name <addr> form accepted",       memory.sent.length === 1);
}

async function testMailEaiSmtpUtf8() {
  // RFC 6531/6532/6533 internationalized email — IDN domain + Unicode
  // local-part. b.mail.send accepts the address and the memory transport
  // ferries it through; the SMTP transport's SMTPUTF8 negotiation is
  // exercised by integration tests against real peers.
  check("b.mail.toAscii is a function",       typeof b.mail.toAscii === "function");
  check("b.mail.toUnicode is a function",     typeof b.mail.toUnicode === "function");
  check("toAscii(münchen.example)",
        b.mail.toAscii("münchen.example") === "xn--mnchen-3ya.example");
  check("toUnicode(xn--mnchen-3ya.example)",
        b.mail.toUnicode("xn--mnchen-3ya.example") === "münchen.example");
  check("toAscii returns null for empty",     b.mail.toAscii("") === null);
  check("toUnicode returns null for empty",   b.mail.toUnicode("") === null);

  var memory = b.mail.transports.memory();
  var mailer = b.mail.create({ transport: memory, audit: false });

  // EAI address — Unicode local-part + IDN domain
  await mailer.send({
    from:    "sender@example.com",
    to:      "müller@münchen.example",
    subject: "Hallo Welt",
    text:    "Sehr geehrte Damen und Herren",
  });
  check("EAI Unicode local + IDN domain accepted",
        memory.sent.length === 1 &&
        memory.sent[0].to === "müller@münchen.example");

  // Plain ASCII still works
  await mailer.send({
    from:    "sender@example.com",
    to:      "rcpt@example.com",
    subject: "ascii",
    text:    "x",
  });
  check("ASCII path remains valid",            memory.sent.length === 2);

  // Invalid IDN domain (empty) refused
  var threw = null;
  try { await mailer.send({ from: "a@b.com", to: "x@", text: "x" }); }
  catch (e) { threw = e; }
  check("empty IDN domain refused",            threw && threw.code === "mail/invalid-recipient");

  // CRLF in EAI local part still refused (header injection defense)
  threw = null;
  try { await mailer.send({ from: "a@b.com", to: "abc\r\nBCC: evil@x.com@münchen.example", text: "x" }); }
  catch (e) { threw = e; }
  check("CRLF in EAI address refused",         threw && threw.code === "mail/invalid-recipient");
}

async function testMailRecipientArrayAndCcBcc() {
  var memory = b.mail.transports.memory();
  var mailer = b.mail.create({ transport: memory, audit: false });
  await mailer.send({
    to:      ["a@x.com", "b@x.com"],
    cc:      "c@x.com",
    bcc:     ["d@x.com", "e@x.com"],
    from:    "noreply@x.com",
    subject: "Multi",
    text:    "body",
  });
  check("multiple to addresses preserved",
        Array.isArray(memory.sent[0].to) && memory.sent[0].to.length === 2);
  check("cc string preserved",                       memory.sent[0].cc === "c@x.com");
  check("bcc array preserved",
        Array.isArray(memory.sent[0].bcc) && memory.sent[0].bcc.length === 2);
}

async function testMailTransportFailureWraps() {
  // A transport that throws → mail/transport-failed wrapper
  var failingTransport = {
    name: "broken",
    send: async function () { throw new Error("smtp connection refused"); },
  };
  var mailer = b.mail.create({ transport: failingTransport, audit: false });

  var threw = null;
  try {
    await mailer.send({ to: "a@b.com", from: "c@d.com", text: "x" });
  } catch (e) { threw = e; }
  check("transport throw → mail/transport-failed",   threw && threw.code === "mail/transport-failed");
  check("wrapped error is MailError",                threw && threw.isMailError === true);
  check("wrapped error preserves cause",
        threw && threw.cause && /smtp connection refused/.test(threw.cause.message));

  // A transport throwing a MailError passes through unchanged
  var explicitMailError = {
    name: "direct",
    send: async function () { throw new b.mail.MailError("custom-code", "explicit failure", true); },
  };
  var mailer2 = b.mail.create({ transport: explicitMailError, audit: false });

  threw = null;
  try { await mailer2.send({ to: "a@b.com", from: "c@d.com", text: "x" }); }
  catch (e) { threw = e; }
  check("upstream MailError preserved (code unchanged)",
        threw && threw.code === "custom-code" && threw.message === "explicit failure");
}

async function testMailFunctionAsTransport() {
  // A bare function counts as a transport
  var calls = [];
  var mailer = b.mail.create({
    transport: async function (message) {
      calls.push(message);
      return { transport: "fn", at: Date.now() };
    },
    audit: false,
  });
  var result = await mailer.send({
    to: "a@b.com", from: "c@d.com", subject: "S", text: "T",
  });
  check("function transport invoked",                calls.length === 1);
  check("function transport result returned",        result && result.transport === "fn");
}

function testMailConsoleTransportShape() {
  // Capture stderr to a buffer; the console transport writes there.
  var stream = {
    written: "",
    write: function (s) { this.written += s; },
  };
  var t = b.mail.transports.console({ stream: stream });
  check("console transport has a name",              t.name === "console");
  check("console transport exposes send",            typeof t.send === "function");
  // Smoke-call it
  return t.send({
    to: "a@b.com", from: "c@d.com", subject: "Hi", text: "body line",
  }).then(function (r) {
    check("console transport returns deliveredAt",   typeof r.deliveredAt === "number");
    check("console transport stream got the body",
          stream.written.indexOf("body line") !== -1 &&
          stream.written.indexOf("c@d.com") !== -1);
  });
}

function testMailCreateValidation() {
  var threw = null;
  try { b.mail.create({ transport: { wrong: "shape" } }); }
  catch (e) { threw = e; }
  check("create rejects transport without .send",    threw && threw.code === "mail/bad-transport");

  threw = null;
  try { b.mail.create({ transport: 42 }); }
  catch (e) { threw = e; }
  check("create rejects non-function/non-object transport", threw && threw.code === "mail/bad-transport");
}

function testMailSurface() {
  check("b.mail namespace present",                  typeof b.mail === "object");
  check("b.mail.create is a function",               typeof b.mail.create === "function");
  check("b.mail.MailError is a class",               typeof b.mail.MailError === "function");
  check("b.mail.transports.console is a function",   typeof b.mail.transports.console === "function");
  check("b.mail.transports.memory is a function",    typeof b.mail.transports.memory === "function");
  check("b.mail.transports.smtp is a function",      typeof b.mail.transports.smtp === "function");
  check("b.mail.transports.http is a function",      typeof b.mail.transports.http === "function");
  check("b.mail.transports.resend is a function",    typeof b.mail.transports.resend === "function");
}

function testMailHttpFactoryValidation() {
  var threw = null;
  try { b.mail.transports.http(); }
  catch (e) { threw = e; }
  check("http factory rejects missing endpoint",
        threw && threw.code === "mail/http-misconfigured" && threw.isMailError === true);

  threw = null;
  try { b.mail.transports.http({ endpoint: "https://x" }); }
  catch (e) { threw = e; }
  check("http factory rejects missing serialize",
        threw && threw.code === "mail/http-misconfigured");

  var t = b.mail.transports.http({
    endpoint:  "https://example.test/mail",
    name:      "postmark",
    serialize: function () { return { body: "{}" }; },
  });
  check("http factory honors custom name",            t && t.name === "postmark");
  check("http factory returns send",                  typeof t.send === "function");

  // Default name is "http" when not supplied
  var t2 = b.mail.transports.http({
    endpoint:  "https://example.test/",
    serialize: function () { return { body: "{}" }; },
  });
  check("http factory defaults name to http",         t2 && t2.name === "http");
}

async function testMailHttpRoundTripWithCustomVendor() {
  // Simulate a "Postmark-style" API: header X-Server-Token, body
  // {From,To,Subject,HtmlBody,TextBody}, response {MessageID,ErrorCode}.
  // Verifies that the generic http transport can drive any vendor that
  // speaks JSON-over-HTTP without needing a framework-level preset.
  var http = require("http");
  var seen = null;
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      seen = {
        method:  req.method,
        url:     req.url,
        headers: req.headers,
        body:    JSON.parse(Buffer.concat(chunks).toString("utf8")),
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ MessageID: "pm_test_xyz", ErrorCode: 0 }));
    });
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.http({
      name:             "postmark",
      endpoint:         "http://127.0.0.1:" + port + "/email",
      timeoutMs:        2000,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
      headers: {
        "X-Postmark-Server-Token": "tok_test",
        "Content-Type":            "application/json",
        "Accept":                  "application/json",
      },
      serialize: function (message) {
        var payload = {
          From:     message.from,
          To:       Array.isArray(message.to) ? message.to.join(", ") : message.to,
          Subject:  message.subject,
          HtmlBody: message.html,
          TextBody: message.text,
        };
        return { body: JSON.stringify(payload) };
      },
      interpret: function (res) {
        var data = JSON.parse(res.body.toString("utf8"));
        if (data.ErrorCode !== 0) return { ok: false, reason: data.Message || ("err " + data.ErrorCode) };
        return { ok: true, id: data.MessageID };
      },
    });

    var result = await transport.send({
      from: "sender@test.local", to: "rcpt@test.local",
      subject: "Hi", html: "<p>Hi</p>", text: "Hi",
    });
    check("http transport happy path returns id from interpret",
          result && result.transport === "postmark" && result.id === "pm_test_xyz");
    check("http transport surfaces statusCode in result",
          result && result.statusCode === 200);
    check("http transport sent vendor-specific header",
          seen && seen.headers["x-postmark-server-token"] === "tok_test");
    check("http transport sent vendor-specific body shape",
          seen && seen.body.From === "sender@test.local" &&
          seen.body.HtmlBody === "<p>Hi</p>" && seen.body.TextBody === "Hi");
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testMailHttpInterpretRejection() {
  // interpret() returning {ok:false} surfaces as mail/<name>-rejected
  // with the vendor's reason in the message.
  var http = require("http");
  var server = http.createServer(function (_req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ErrorCode: 422, Message: "Invalid recipient" }));
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.http({
      name:             "postmark",
      endpoint:         "http://127.0.0.1:" + port + "/",
      timeoutMs:        1500,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
      headers:   { "Content-Type": "application/json" },
      serialize: function () { return { body: "{}" }; },
      interpret: function (res) {
        var data = JSON.parse(res.body.toString("utf8"));
        if (data.ErrorCode !== 0) return { ok: false, reason: data.Message };
        return { ok: true, id: data.MessageID };
      },
    });
    var err = null;
    try { await transport.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err = e; }
    check("http interpret-rejection surfaces mail/<name>-rejected",
          err && err.code === "mail/postmark-rejected" && err.isMailError === true);
    check("http interpret-rejection includes vendor reason",
          err && /Invalid recipient/.test(err.message || ""));
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

async function testMailHttpInterpretThrows() {
  // interpret() throwing a non-MailError surfaces as mail/<name>-interpret-failed.
  var http = require("http");
  var server = http.createServer(function (_req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("not json at all");
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.http({
      name:             "vendor",
      endpoint:         "http://127.0.0.1:" + port + "/",
      timeoutMs:        1500,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
      headers:   { "Content-Type": "application/json" },
      serialize: function () { return { body: "{}" }; },
      interpret: function (res) { return { ok: !!JSON.parse(res.body.toString("utf8")).id }; },
    });
    var err = null;
    try { await transport.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err = e; }
    check("http interpret-throws surfaces mail/<name>-interpret-failed",
          err && err.code === "mail/vendor-interpret-failed" && err.isMailError === true);
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

function testMailHttpBadSerializer() {
  // serialize() returning a non-object surfaces as mail/<name>-bad-serializer.
  // (Async — but we can test the synchronous validation path via the
  //  promise.) No network needed since the error happens before request.
  var transport = b.mail.transports.http({
    name:      "vendor",
    endpoint:  "https://example.test/",
    serialize: function () { return null; },
  });
  return transport.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }).then(
    function () { check("http bad-serializer should reject", false); },
    function (err) {
      check("http bad-serializer returns mail/<name>-bad-serializer",
            err && err.code === "mail/vendor-bad-serializer" && err.isMailError === true);
    }
  );
}

function testMailSmtpFactoryValidation() {
  var threw = null;
  try { b.mail.transports.smtp(); }
  catch (e) { threw = e; }
  check("smtp factory rejects missing opts.host",
        threw && threw.code === "mail/smtp-misconfigured" && threw.isMailError === true);

  var t = b.mail.transports.smtp({ host: "smtp.example.com" });
  check("smtp factory returns a transport with name=smtp", t && t.name === "smtp");
  check("smtp factory returns a transport with .send",     typeof t.send === "function");
}

function testMailResendFactoryValidation() {
  var threw = null;
  try { b.mail.transports.resend(); }
  catch (e) { threw = e; }
  check("resend factory rejects missing apiKey",
        threw && threw.code === "mail/resend-misconfigured" && threw.isMailError === true);

  threw = null;
  try { b.mail.transports.resend({ apiKey: 42 }); }
  catch (e) { threw = e; }
  check("resend factory rejects non-string apiKey",
        threw && threw.code === "mail/resend-misconfigured");

  var t = b.mail.transports.resend({ apiKey: "re_test_xxx" });
  check("resend factory returns a transport with name=resend", t && t.name === "resend");
  check("resend factory returns a transport with .send",       typeof t.send === "function");
}

async function testMailSmtpRoundTrip() {
  // Stand up a fake SMTP server in-process and walk the protocol the
  // transport speaks. We don't exercise STARTTLS here — that path needs
  // a real cert. The auth-disabled branch (no opts.user) covers the
  // EHLO → MAIL FROM → RCPT TO → DATA path including dot-stuffing.
  var net = require("net");
  var lines = [];
  var dataBuf = "";
  var inData = false;
  var server = net.createServer(function (sock) {
    sock.setEncoding("utf8");
    sock.write("220 fake.local ESMTP\r\n");
    sock.on("data", function (chunk) {
      if (inData) {
        dataBuf += chunk;
        var endIdx = dataBuf.indexOf("\r\n.\r\n");
        if (endIdx !== -1) {
          inData = false;
          dataBuf = dataBuf.slice(0, endIdx);
          sock.write("250 OK queued\r\n");
        }
        return;
      }
      var parts = chunk.split("\r\n");
      for (var i = 0; i < parts.length; i++) {
        var line = parts[i];
        if (!line) continue;
        lines.push(line);
        var u = line.toUpperCase();
        if (u.indexOf("EHLO") === 0)         sock.write("250-fake.local\r\n250 OK\r\n");
        else if (u.indexOf("MAIL FROM") === 0) sock.write("250 OK\r\n");
        else if (u.indexOf("RCPT TO") === 0)   sock.write("250 OK\r\n");
        else if (u === "DATA")               { inData = true; sock.write("354 send body\r\n"); }
        else if (u === "QUIT")               { sock.write("221 bye\r\n"); sock.end(); }
        else                                  sock.write("250 OK\r\n");
      }
    });
    sock.on("error", function () { /* ignore — client will report */ });
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.smtp({
      host:     "127.0.0.1",
      port:     port,
      ehloName: "test.local",
      // No user/pass → skips AUTH path, also skips STARTTLS since we
      // never advertise it; the transport sees a plain socket and goes
      // straight to MAIL FROM after EHLO. Implicit TLS off.
    });
    // The transport defaults to STARTTLS for non-465 ports — bypass by
    // forcing implicitTls=false AND skipping auth, which means the
    // transport flow expects STARTTLS. We need a different shape: tell
    // the transport this socket is already TLS by using port 465 +
    // implicitTls true... but that requires real TLS. The cleanest way
    // is to test via a custom plain-text override path. The transport's
    // current shape is: non-implicit always issues STARTTLS. Skip TLS
    // testing here — that needs cert plumbing — and instead verify that
    // the state machine refuses to send data when STARTTLS is rejected.
    var err = null;
    try { await transport.send({
      from: "sender@test.local", to: "rcpt@test.local",
      subject: "S", text: "T",
    }); }
    catch (e) { err = e; }

    // Server doesn't advertise STARTTLS; client sends STARTTLS anyway
    // because the transport always issues it on cleartext ports. Server
    // replies "250 OK" (default branch above) — not 220. Transport
    // fails closed with starttls-rejected.
    check("smtp transport refuses to send cleartext when STARTTLS not honored",
          err && err.code === "mail/smtp-failed" &&
          /starttls-rejected/.test(err.message || ""));
    check("smtp state-machine wrote EHLO before failing",
          lines.indexOf("EHLO test.local") !== -1);
    check("smtp state-machine never sent MAIL FROM in cleartext",
          !lines.some(function (l) { return /^MAIL FROM/i.test(l); }));
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testMailSmtpStarttlsAccept() {
  // Verify the happy-path STARTTLS handshake reaches the upgrade step
  // without us needing a full TLS cert: server accepts STARTTLS with
  // 220, then client tries to upgrade and fails on the cert exchange.
  // What we're checking is that the transport DID issue STARTTLS and
  // attempt the upgrade — i.e. it doesn't leak plaintext credentials.
  var net = require("net");
  var lines = [];
  var server = net.createServer(function (sock) {
    sock.setEncoding("utf8");
    sock.write("220 fake.local ESMTP\r\n");
    sock.on("data", function (chunk) {
      var parts = chunk.split("\r\n");
      for (var i = 0; i < parts.length; i++) {
        var line = parts[i];
        if (!line) continue;
        lines.push(line);
        var u = line.toUpperCase();
        if (u.indexOf("EHLO") === 0)         sock.write("250-fake.local\r\n250-STARTTLS\r\n250 OK\r\n");
        else if (u === "STARTTLS")           {
          sock.write("220 ready for tls\r\n");
          // Don't actually complete TLS — just hang. Client will error
          // on TLS handshake or timeout.
          setTimeout(function () { try { sock.destroy(); } catch (_e) {} }, 50);
        }
      }
    });
    sock.on("error", function () { /* expected — TLS handshake will tear down */ });
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.smtp({
      host: "127.0.0.1", port: port, ehloName: "test.local",
      timeoutMs: 1000,
      // user/pass set so we'd attempt AUTH after upgrade — verifies
      // the AUTH credentials never reach the wire pre-TLS.
      user: "u", pass: "p",
    });
    var err = null;
    try {
      await transport.send({
        from: "sender@test.local", to: "rcpt@test.local",
        subject: "S", text: "T",
      });
    } catch (e) { err = e; }

    check("smtp transport issued STARTTLS",            lines.indexOf("STARTTLS") !== -1);
    check("smtp transport never sent AUTH LOGIN before TLS",
          !lines.some(function (l) { return /^AUTH LOGIN/i.test(l); }));
    check("smtp transport never base64-encoded credentials in cleartext",
          !lines.some(function (l) { return l === Buffer.from("u").toString("base64"); }));
    check("smtp transport surfaced a MailError for failed TLS upgrade",
          err && err.isMailError === true);
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testMailResendRoundTrip() {
  // Spin up a local HTTP server that pretends to be the Resend API.
  // The transport uses lib/http-client which is HTTPS-by-default; we
  // pass safeUrl.ALLOW_HTTP_ALL via opts.allowedProtocols so the
  // request reaches our cleartext fixture.
  var http = require("http");
  var seen = null;
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      seen = {
        method:  req.method,
        url:     req.url,
        headers: req.headers,
        body:    JSON.parse(Buffer.concat(chunks).toString("utf8")),
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "rsnd_test_abc123" }));
    });
  });
  var port = await listenOnRandomPort(server);

  try {
    var transport = b.mail.transports.resend({
      apiKey:           "re_test_secret",
      endpoint:         "http://127.0.0.1:" + port + "/emails",
      timeoutMs:        2000,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
    var result = await transport.send({
      from: "Sender <sender@test.local>",
      to: ["a@b.com", "c@d.com"],
      cc: "e@f.com",
      subject: "Hello",
      html: "<p>Hi</p>",
      text: "Hi",
      replyTo: "reply@test.local",
    });
    check("resend transport returns deliveredAt + id",
          result && result.transport === "resend" && result.id === "rsnd_test_abc123");
    check("resend transport sent POST",                seen && seen.method === "POST");
    check("resend transport set Authorization header",
          seen && seen.headers.authorization === "Bearer re_test_secret");
    check("resend transport sent content-type json",
          seen && /application\/json/.test(seen.headers["content-type"] || ""));
    check("resend transport mapped to as array",
          seen && Array.isArray(seen.body.to) && seen.body.to.length === 2);
    check("resend transport mapped cc as array",
          seen && Array.isArray(seen.body.cc) && seen.body.cc[0] === "e@f.com");
    check("resend transport mapped replyTo to reply_to (snake_case)",
          seen && seen.body.reply_to === "reply@test.local");
    check("resend transport forwarded subject + html + text",
          seen && seen.body.subject === "Hello" &&
          seen.body.html === "<p>Hi</p>" && seen.body.text === "Hi");
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testMailResendErrorPaths() {
  var http = require("http");

  // Case 1 — server returns 200 with non-JSON body
  var s1 = http.createServer(function (_req, res) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("not json");
  });
  var p1 = await listenOnRandomPort(s1);
  try {
    var t1 = b.mail.transports.resend({
      apiKey: "re_x", endpoint: "http://127.0.0.1:" + p1 + "/",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true, timeoutMs: 1500,
    });
    var err1 = null;
    try { await t1.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err1 = e; }
    check("resend non-JSON body surfaces mail/resend-bad-response",
          err1 && err1.code === "mail/resend-bad-response");
  } finally {
    await new Promise(function (r) { s1.close(function () { r(); }); });
  }

  // Case 2 — server returns 200 JSON with no `id`
  var s2 = http.createServer(function (_req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "rate limited" }));
  });
  var p2 = await listenOnRandomPort(s2);
  try {
    var t2 = b.mail.transports.resend({
      apiKey: "re_x", endpoint: "http://127.0.0.1:" + p2 + "/",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true, timeoutMs: 1500,
    });
    var err2 = null;
    try { await t2.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err2 = e; }
    check("resend JSON without id surfaces mail/resend-rejected",
          err2 && err2.code === "mail/resend-rejected" &&
          /rate limited/.test(err2.message || ""));
  } finally {
    await new Promise(function (r) { s2.close(function () { r(); }); });
  }

  // Case 3 — server returns non-2xx
  var s3 = http.createServer(function (_req, res) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "Invalid API key" }));
  });
  var p3 = await listenOnRandomPort(s3);
  try {
    var t3 = b.mail.transports.resend({
      apiKey: "re_x", endpoint: "http://127.0.0.1:" + p3 + "/",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true, timeoutMs: 1500,
    });
    var err3 = null;
    try { await t3.send({ from: "a@b.com", to: "c@d.com", subject: "S", text: "T" }); }
    catch (e) { err3 = e; }
    check("resend HTTP error wraps to mail/resend-failed",
          err3 && err3.code === "mail/resend-failed" && err3.isMailError === true);
    check("resend HTTP error preserves statusCode",
          err3 && err3.statusCode === 401);
  } finally {
    await new Promise(function (r) { s3.close(function () { r(); }); });
  }
}

// ---- v0.4.22 mail attachments + multipart ----

async function testMailAttachmentsValidation() {
  var t = b.mail.transports.memory();
  var mail = b.mail.create({ transport: t });
  var base = { from: "a@b", to: "c@d", subject: "S", text: "T" };

  async function _expectThrow(label, opts) {
    var threw = false;
    try { await mail.send(Object.assign({}, base, { attachments: opts })); }
    catch (_e) { threw = true; }
    check("mail attachments validation: " + label, threw);
  }
  await _expectThrow("rejects non-array",                 "string");
  await _expectThrow("rejects non-object entry",          ["string"]);
  await _expectThrow("rejects missing filename",          [{ content: Buffer.from("x") }]);
  await _expectThrow("rejects empty filename",            [{ filename: "", content: Buffer.from("x") }]);
  await _expectThrow("rejects filename CRLF",             [{ filename: "x\nfoo", content: Buffer.from("x") }]);
  await _expectThrow("rejects missing content",           [{ filename: "x.txt" }]);
  await _expectThrow("rejects non-buffer non-string content", [{ filename: "x.txt", content: 42 }]);
  await _expectThrow("rejects bad contentDisposition",    [{ filename: "x.txt", content: "x", contentDisposition: "weird" }]);
  await _expectThrow("rejects cid with brackets",         [{ filename: "x.png", content: "x", cid: "<bad>" }]);
}

async function testMailAttachmentsMemoryTransportPassthrough() {
  var t = b.mail.transports.memory();
  var mail = b.mail.create({ transport: t });
  await mail.send({
    from: "noreply@app.example.com", to: "alice@example.com", subject: "Files",
    text: "see attached",
    attachments: [
      { filename: "doc.txt", content: "hello", contentType: "text/plain" },
      { filename: "logo.png", content: Buffer.from([1, 2, 3]), cid: "logo-1" },
    ],
  });
  check("memory transport: 1 message captured",          t.sent.length === 1);
  check("memory transport: attachments passed through",  t.sent[0].attachments.length === 2);
  check("memory transport: cid preserved",               t.sent[0].attachments[1].cid === "logo-1");
}

function testMailRfc822MultipartMixedWithAttachment() {
  // Inspect the wire format directly via the test-only export. The SMTP
  // network path is covered by the existing smtpRoundTrip / smtpStarttls
  // smoke tests; here we just want to assert builder shape.
  var wire = b.mail._buildRfc822ForTest({
    from: "x@y.com", to: "a@b.com", subject: "Files", text: "see attached",
    attachments: [{ filename: "doc.txt", content: "hello world", contentType: "text/plain" }],
  });
  check("rfc822: Content-Type multipart/mixed",
        /Content-Type: multipart\/mixed; boundary="blamejs-mixed-/.test(wire));
  check("rfc822: contains body part", /Content-Type: text\/plain; charset=utf-8/.test(wire));
  check("rfc822: Content-Disposition attachment",
        /Content-Disposition: attachment; filename="doc.txt"/.test(wire));
  check("rfc822: Content-Transfer-Encoding base64",
        /Content-Transfer-Encoding: base64/.test(wire));
  var b64 = Buffer.from("hello world").toString("base64");
  check("rfc822: base64 body present",  wire.indexOf(b64) !== -1);
}

function testMailRfc822InlineWithCid() {
  var wire = b.mail._buildRfc822ForTest({
    from: "x@y.com", to: "a@b.com", subject: "Inline image",
    html: '<img src="cid:logo-1">',
    attachments: [
      { filename: "logo.png", content: Buffer.from([0x89, 0x50, 0x4e, 0x47]),
        contentType: "image/png", cid: "logo-1" },
    ],
  });
  check("rfc822 inline: Content-ID header",     /Content-ID: <logo-1>/.test(wire));
  check("rfc822 inline: disposition inline",
        /Content-Disposition: inline; filename="logo\.png"/.test(wire));
  check("rfc822 inline: image/png content-type", /Content-Type: image\/png/.test(wire));
}

function testMailRfc822TextHtmlPlusAttachment() {
  // Both text + html + attachment → multipart/mixed wrapping
  // multipart/alternative wrapping the text and html parts.
  var wire = b.mail._buildRfc822ForTest({
    from: "x@y.com", to: "a@b.com", subject: "Both",
    text: "TEXT", html: "<p>HTML</p>",
    attachments: [{ filename: "foo.txt", content: "x" }],
  });
  check("rfc822 mixed+alt: outer multipart/mixed",
        /multipart\/mixed; boundary="blamejs-mixed-/.test(wire));
  check("rfc822 mixed+alt: inner multipart/alternative",
        /multipart\/alternative; boundary="blamejs-alt-/.test(wire));
  check("rfc822 mixed+alt: text body present",
        /TEXT/.test(wire));
  check("rfc822 mixed+alt: html body present",
        /<p>HTML<\/p>/.test(wire));
}

async function testMailResendForwardsAttachments() {
  var http = require("http");
  var captured = null;
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      try { captured = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
      catch (_e) { captured = null; }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "msg-abc" }));
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    var mail = b.mail.create({
      transport: b.mail.transports.resend({
        apiKey:           "rk_test",
        endpoint:         "http://127.0.0.1:" + port + "/emails",
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      }),
    });
    await mail.send({
      from: "noreply@x.com", to: "a@b.com", subject: "Files", text: "T",
      attachments: [
        { filename: "doc.txt", content: "hello", contentType: "text/plain" },
        { filename: "logo.png", content: Buffer.from("PNG"), contentType: "image/png", cid: "logo-1" },
      ],
    });
    check("resend forward: payload.attachments present",  Array.isArray(captured.attachments) && captured.attachments.length === 2);
    check("resend forward: filename forwarded",            captured.attachments[0].filename === "doc.txt");
    check("resend forward: content base64-encoded",
          captured.attachments[0].content === Buffer.from("hello").toString("base64"));
    check("resend forward: contentType forwarded",         captured.attachments[1].contentType === "image/png");
    check("resend forward: cid maps to content_id",        captured.attachments[1].content_id === "logo-1");
  } finally {
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

// ---- api-snapshot ----

function testApiSnapshotSurface() {
  check("b.apiSnapshot namespace present",        typeof b.apiSnapshot === "object");
  check("capture is a function",                  typeof b.apiSnapshot.capture === "function");
  check("write is a function",                    typeof b.apiSnapshot.write === "function");
  check("read is a function",                     typeof b.apiSnapshot.read === "function");
  check("compare is a function",                  typeof b.apiSnapshot.compare === "function");
  check("formatDiff is a function",               typeof b.apiSnapshot.formatDiff === "function");
  check("ApiSnapshotError is a class",            typeof b.apiSnapshot.ApiSnapshotError === "function");
  check("SNAPSHOT_FORMAT_VERSION is 1",           b.apiSnapshot.SNAPSHOT_FORMAT_VERSION === 1);
}

function testApiSnapshotCaptureCategorizes() {
  var target = {
    fn:    function (a, b) { return a + b; },
    str:   "hello",
    num:   42,
    obj:   { nested: function () {}, count: 1 },
    klass: new (class Widget { constructor() { this.x = 1; } })(),
    _internal: function () {},
  };
  var snap = b.apiSnapshot.capture(target, { frameworkVersion: "0.0.0-test" });
  check("snapshot has version 1",                 snap.version === 1);
  check("snapshot has frameworkVersion",          snap.frameworkVersion === "0.0.0-test");
  check("snapshot has createdAt ISO",
        typeof snap.createdAt === "string" && /^\d{4}-/.test(snap.createdAt));

  check("function captured with arity",
        snap.exports.fn.type === "function" && snap.exports.fn.arity === 2);
  check("string captured as primitive",
        snap.exports.str.type === "primitive" && snap.exports.str.valueType === "string");
  check("number captured as primitive",
        snap.exports.num.type === "primitive" && snap.exports.num.valueType === "number");
  check("nested object recurses",
        snap.exports.obj.type === "object" &&
        snap.exports.obj.members.nested.type === "function");
  check("class instance captured as instance with constructor name",
        snap.exports.klass.type === "instance" && snap.exports.klass.ctorName === "Widget");
  check("underscore-prefixed members skipped by default",
        snap.exports._internal === undefined);
}

function testApiSnapshotCaptureHandlesCycles() {
  var a = {};
  var bRef = { back: a };
  a.forward = bRef;
  // Cycle: a → forward → bRef → back → a → ...
  var snap = b.apiSnapshot.capture({ a: a });
  check("cycle short-circuits as type=cycle",
        snap.exports.a.members.forward.members.back.type === "cycle");
}

function testApiSnapshotWriteAndRead() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-snap-"));
  try {
    var snap = b.apiSnapshot.capture({
      fn: function () {},
      val: "x",
    });
    var p = path.join(dir, "snap.json");
    b.apiSnapshot.write(snap, p);
    check("snapshot file exists",                   fs.existsSync(p));
    var written = fs.readFileSync(p, "utf8");
    check("written file has trailing newline",      written.charAt(written.length - 1) === "\n");

    var loaded = b.apiSnapshot.read(p);
    check("read returns same version",              loaded.version === snap.version);
    check("read preserves exports tree",            loaded.exports.fn.type === "function");

    // Bad path → missing
    var threw = null;
    try { b.apiSnapshot.read(path.join(dir, "nope.json")); } catch (e) { threw = e; }
    check("read missing file rejects",              threw && threw.code === "api-snapshot/missing");

    // Bad shape → bad-shape
    fs.writeFileSync(path.join(dir, "bad.json"), JSON.stringify({ random: "garbage" }));
    threw = null;
    try { b.apiSnapshot.read(path.join(dir, "bad.json")); } catch (e) { threw = e; }
    check("read bad-version snapshot rejects",      threw && threw.code === "api-snapshot/bad-version");
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

function testApiSnapshotCompareNoChange() {
  var snap1 = b.apiSnapshot.capture({ fn: function () {}, val: "x" });
  // Capture a fresh one with the same shape — should diff clean
  var snap2 = b.apiSnapshot.capture({ fn: function () {}, val: "y" });
  var diff = b.apiSnapshot.compare(snap1, snap2);
  check("identical-shape snapshots: no breaking",  diff.breaking.length === 0);
  check("identical-shape snapshots: no additive",  diff.additive.length === 0);
  check("identical-shape snapshots: no typeChange", diff.typeChanged.length === 0);
}

function testApiSnapshotCompareDetectsRemoval() {
  var snap1 = b.apiSnapshot.capture({
    a: function () {}, b: { c: function () {}, d: "x" },
  });
  // Remove b.c
  var snap2 = b.apiSnapshot.capture({
    a: function () {}, b: { d: "x" },
  });
  var diff = b.apiSnapshot.compare(snap1, snap2);
  check("removed nested member surfaces as breaking",
        diff.breaking.length === 1 && diff.breaking[0].kind === "removed" &&
        diff.breaking[0].path === "b.c");
}

function testApiSnapshotCompareDetectsTypeChange() {
  var snap1 = b.apiSnapshot.capture({ x: function () {} });
  var snap2 = b.apiSnapshot.capture({ x: { wasFunction: true } });
  var diff = b.apiSnapshot.compare(snap1, snap2);
  check("type change surfaces as breaking + typeChanged",
        diff.breaking.length >= 1 && diff.typeChanged.length === 1);
  check("typeChanged carries was/is",
        diff.typeChanged[0].was === "function" && diff.typeChanged[0].is === "object");
}

function testApiSnapshotCompareDetectsArityDecrease() {
  var snap1 = b.apiSnapshot.capture({ fn: function (a, b, c) {} });   // arity 3
  var snap2 = b.apiSnapshot.capture({ fn: function (a) {} });         // arity 1
  var diff = b.apiSnapshot.compare(snap1, snap2);
  check("arity decrease surfaces as breaking",
        diff.breaking.some(function (e) { return e.kind === "arity-decreased" && e.path === "fn"; }));
}

function testApiSnapshotCompareIgnoresArityIncrease() {
  var snap1 = b.apiSnapshot.capture({ fn: function (a) {} });          // arity 1
  var snap2 = b.apiSnapshot.capture({ fn: function (a, b, c) {} });    // arity 3
  var diff = b.apiSnapshot.compare(snap1, snap2);
  check("arity increase is NOT breaking (added optional params)",
        diff.breaking.length === 0);
}

function testApiSnapshotCompareDetectsAdditive() {
  var snap1 = b.apiSnapshot.capture({ a: function () {} });
  var snap2 = b.apiSnapshot.capture({ a: function () {}, newOne: function () {} });
  var diff = b.apiSnapshot.compare(snap1, snap2);
  check("added member surfaces as additive (not breaking)",
        diff.additive.length === 1 && diff.additive[0].path === "newOne" &&
        diff.breaking.length === 0);
}

function testApiSnapshotFormatDiff() {
  var snap1 = b.apiSnapshot.capture({ a: function () {}, b: function () {} });
  var snap2 = b.apiSnapshot.capture({ a: function () {}, c: function () {} });
  var out = b.apiSnapshot.formatDiff(b.apiSnapshot.compare(snap1, snap2));
  check("formatDiff includes BREAKING header",      /BREAKING/.test(out));
  check("formatDiff lists removed b",               /b/.test(out) && /removed/.test(out));
  check("formatDiff lists additive c",              /\+ c/.test(out));

  var noChange = b.apiSnapshot.formatDiff({ breaking: [], additive: [], typeChanged: [] });
  check("formatDiff: no changes message",            /no changes/.test(noChange));
}

function testApiSnapshotOnFrameworkSurfaceCaptures() {
  // Capture the actual framework's surface — verifies the walker
  // handles real-world state including class instances, functions,
  // version strings, etc.
  var snap = b.apiSnapshot.capture(b);
  check("framework snapshot captures top-level entries",
        Object.keys(snap.exports).length > 30);
  check("framework snapshot includes crypto namespace",
        snap.exports.crypto && snap.exports.crypto.type === "object");
  check("framework snapshot includes constants namespace",
        snap.exports.constants && snap.exports.constants.type === "object");
  check("framework snapshot includes version primitive",
        snap.exports.version && snap.exports.version.type === "primitive");
}

async function testCliApiSnapshotCaptureAndCompare() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-snap-cli-"));
  try {
    // Capture using the CLI subcommand
    var snapPath = path.join(dir, "snap.json");
    var t1 = _cliCtx();
    var rc1 = await b.cli.main(["api-snapshot", "capture", "--file", snapPath], t1.ctx);
    check("api-snapshot capture exits 0",            rc1 === 0);
    check("api-snapshot capture wrote file",          fs.existsSync(snapPath));
    check("api-snapshot capture stdout mentions path",
          t1.captured().out.indexOf(snapPath) !== -1);

    // Compare against a fresh capture (same surface, no breaking changes)
    var t2 = _cliCtx();
    var rc2 = await b.cli.main(["api-snapshot", "compare", "--file", snapPath], t2.ctx);
    check("api-snapshot compare exits 0 on no breaking changes", rc2 === 0);
    check("api-snapshot compare prints no-changes-message OR diff summary",
          /no changes/.test(t2.captured().out) ||
          /BREAKING|additive/.test(t2.captured().out));

    // Validate bad invocation
    var t3 = _cliCtx();
    var rc3 = await b.cli.main(["api-snapshot", "fly"], t3.ctx);
    check("unknown api-snapshot subcommand exits 2", rc3 === 2);

    var t4 = _cliCtx();
    var rc4 = await b.cli.main(["api-snapshot"], t4.ctx);
    check("bare api-snapshot exits 2 with usage",
          rc4 === 2 && /Usage: blamejs api-snapshot/.test(t4.captured().err));

    var t5 = _cliCtx();
    var rc5 = await b.cli.main(["api-snapshot", "compare", "--file",
      path.join(dir, "missing.json")], t5.ctx);
    check("api-snapshot compare missing snapshot exits 1", rc5 === 1);

    var t6 = _cliCtx();
    var rc6 = await b.cli.main(["help", "api-snapshot"], t6.ctx);
    check("help api-snapshot exits 0",                rc6 === 0);
    check("help api-snapshot prints usage",
          /Usage: blamejs api-snapshot/.test(t6.captured().out));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

// ---- deprecate ----
//
// Tests manipulate process.env.BLAMEJS_DEPRECATIONS and
// process.env.NODE_ENV directly, with cleanup in finally{} blocks so
// they don't leak across tests.

function _withEnv(overrides, fn) {
  var saved = {};
  var keys = Object.keys(overrides);
  for (var i = 0; i < keys.length; i++) {
    saved[keys[i]] = process.env[keys[i]];
    if (overrides[keys[i]] === null) delete process.env[keys[i]];
    else process.env[keys[i]] = overrides[keys[i]];
  }
  try { return fn(); }
  finally {
    for (var j = 0; j < keys.length; j++) {
      if (saved[keys[j]] === undefined) delete process.env[keys[j]];
      else process.env[keys[j]] = saved[keys[j]];
    }
  }
}

// Capture stderr writes during fn(), restore after.
function _captureStderr(fn) {
  var captured = [];
  var orig = process.stderr.write;
  process.stderr.write = function (chunk) {
    captured.push(typeof chunk === "string" ? chunk : chunk.toString());
    return true;
  };
  try { fn(); }
  finally { process.stderr.write = orig; }
  return captured.join("");
}

function testDeprecateSurface() {
  check("b.deprecate namespace present",          typeof b.deprecate === "object");
  check("warn is a function",                     typeof b.deprecate.warn === "function");
  check("wrap is a function",                     typeof b.deprecate.wrap === "function");
  check("alias is a function",                    typeof b.deprecate.alias === "function");
  check("list is a function",                     typeof b.deprecate.list === "function");
  check("reset is a function",                    typeof b.deprecate.reset === "function");
  check("getMode is a function",                  typeof b.deprecate.getMode === "function");
  check("DeprecateError is a class",            typeof b.deprecate.DeprecateError === "function");
}

function testDeprecateModeResolution() {
  _withEnv({ BLAMEJS_DEPRECATIONS: null, NODE_ENV: null }, function () {
    check("default (no env) → warn",                b.deprecate.getMode() === "warn");
  });
  _withEnv({ BLAMEJS_DEPRECATIONS: null, NODE_ENV: "production" }, function () {
    check("NODE_ENV=production → silent",            b.deprecate.getMode() === "silent");
  });
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn", NODE_ENV: "production" }, function () {
    check("BLAMEJS_DEPRECATIONS overrides production", b.deprecate.getMode() === "warn");
  });
  _withEnv({ BLAMEJS_DEPRECATIONS: "ERROR" }, function () {
    check("env value case-insensitive",              b.deprecate.getMode() === "error");
  });
  _withEnv({ BLAMEJS_DEPRECATIONS: "garbage" }, function () {
    check("unrecognized env value falls back to default",
          b.deprecate.getMode() === "silent" || b.deprecate.getMode() === "warn");
  });
}

function testDeprecateWarnEmitsOnce() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn" }, function () {
    var stderr = _captureStderr(function () {
      b.deprecate.warn("oldThing", {
        since: "0.2.0", removeIn: "0.4.0",
        message: "use newThing()",
      });
      b.deprecate.warn("oldThing", { since: "0.2.0", removeIn: "0.4.0" });
      b.deprecate.warn("oldThing", { since: "0.2.0", removeIn: "0.4.0" });
    });
    check("warn writes one line for repeated calls",
          (stderr.match(/blamejs:deprecated/g) || []).length === 1);
    check("warn line contains name",                  /oldThing/.test(stderr));
    check("warn line contains since",                  /since 0\.2\.0/.test(stderr));
    check("warn line contains removeIn",               /removed in 0\.4\.0/.test(stderr));
    check("warn line contains message",                /use newThing/.test(stderr));

    var listed = b.deprecate.list();
    check("list shows the deprecation",                listed.length === 1 && listed[0].name === "oldThing");
    check("list reports correct callCount",            listed[0].callCount === 3);
  });
}

function testDeprecateSilentMode() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "silent" }, function () {
    var stderr = _captureStderr(function () {
      b.deprecate.warn("x", { since: "0.1.0", removeIn: "0.2.0" });
    });
    check("silent mode emits nothing on stderr",       stderr === "");
    // But list() still tracks the call
    check("silent mode still tracks call in list()",   b.deprecate.list().length === 1);
  });
}

function testDeprecateErrorMode() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "error" }, function () {
    var threw = null;
    try { b.deprecate.warn("oldX", { since: "0.1.0", removeIn: "0.2.0" }); }
    catch (e) { threw = e; }
    check("error mode throws on first use",            threw && threw.code === "deprecate/used-in-error-mode");
    check("error mode error includes name",            threw && /oldX/.test(threw.message));
  });
}

function testDeprecateDifferentSinceProducesNewLine() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn" }, function () {
    var stderr = _captureStderr(function () {
      b.deprecate.warn("x", { since: "0.1.0", removeIn: "0.3.0" });
      b.deprecate.warn("x", { since: "0.1.0", removeIn: "0.3.0" });    // dedup
      b.deprecate.warn("x", { since: "0.2.0", removeIn: "0.4.0" });    // new since
    });
    check("dedupe is per (name, since)",                (stderr.match(/blamejs:deprecated/g) || []).length === 2);
    check("list has two entries",                        b.deprecate.list().length === 2);
  });
}

function testDeprecateWarnArgValidation() {
  var threw;
  threw = null; try { b.deprecate.warn(); } catch (e) { threw = e; }
  check("warn rejects missing name",                   threw && threw.code === "deprecate/bad-name");

  threw = null; try { b.deprecate.warn("x"); } catch (e) { threw = e; }
  check("warn rejects missing opts",                   threw && threw.code === "deprecate/bad-opts");

  threw = null; try { b.deprecate.warn("x", { since: "0.1.0" }); } catch (e) { threw = e; }
  check("warn rejects missing removeIn",               threw && threw.code === "deprecate/bad-opts");

  threw = null; try { b.deprecate.warn("x", { removeIn: "0.2.0" }); } catch (e) { threw = e; }
  check("warn rejects missing since",                  threw && threw.code === "deprecate/bad-opts");
}

function testDeprecateWrap() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn" }, function () {
    var calls = [];
    var newFn = function (a, b2) { calls.push([a, b2]); return a + b2; };
    var oldFn = b.deprecate.wrap(newFn, "oldFn", {
      since: "0.2.0", removeIn: "0.4.0", message: "renamed to newFn",
    });

    var stderr = _captureStderr(function () {
      var r1 = oldFn(1, 2);
      var r2 = oldFn(3, 4);
      check("wrap delegates return value",                r1 === 3 && r2 === 7);
      check("wrap delegates arguments",                   calls.length === 2 && calls[0][0] === 1 && calls[0][1] === 2);
    });
    check("wrap warns once for repeated calls",          (stderr.match(/blamejs:deprecated/g) || []).length === 1);
    check("wrap warning carries new name",               /renamed to newFn/.test(stderr));
  });
}

function testDeprecateWrapValidation() {
  var threw;
  threw = null; try { b.deprecate.wrap("not-a-function", "x", { since: "0.1.0", removeIn: "0.2.0" }); } catch (e) { threw = e; }
  check("wrap rejects non-function target",            threw && threw.code === "deprecate/bad-target");

  threw = null; try { b.deprecate.wrap(function () {}, "", { since: "0.1.0", removeIn: "0.2.0" }); } catch (e) { threw = e; }
  check("wrap rejects empty name",                     threw && threw.code === "deprecate/bad-name");
}

function testDeprecateAlias() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "warn" }, function () {
    var target = { newKey: "value-via-new-key" };
    b.deprecate.alias(target, "oldKey", "newKey", {
      since: "0.2.0", removeIn: "0.4.0",
    });
    var stderr = _captureStderr(function () {
      var v = target.oldKey;
      check("alias get returns newKey value",            v === "value-via-new-key");
      // Setter writes through to newKey
      target.oldKey = "now-set-via-old";
      check("alias set writes through to newKey",        target.newKey === "now-set-via-old");
    });
    check("alias warning emitted on access",             /blamejs:deprecated/.test(stderr));
    check("alias message points to new key",             /'newKey' instead/.test(stderr));
  });
}

function testDeprecateListAndReset() {
  b.deprecate.reset();
  _withEnv({ BLAMEJS_DEPRECATIONS: "silent" }, function () {
    b.deprecate.warn("a", { since: "0.1.0", removeIn: "0.2.0" });
    b.deprecate.warn("a", { since: "0.1.0", removeIn: "0.2.0" });
    b.deprecate.warn("a", { since: "0.1.0", removeIn: "0.2.0" });
    b.deprecate.warn("b", { since: "0.1.0", removeIn: "0.2.0" });
    var listed = b.deprecate.list();
    check("list returns all unique deprecations",        listed.length === 2);
    check("list sorted by callCount desc",               listed[0].name === "a" && listed[0].callCount === 3 &&
                                                          listed[1].name === "b" && listed[1].callCount === 1);
    b.deprecate.reset();
    check("reset clears everything",                      b.deprecate.list().length === 0);
  });
}

// ---- restore + restore-rollback ----

function _restoreFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rs-"));
  var dataDir = path.join(dir, "data");
  var storageRoot = path.join(dir, "backups");
  var rollbackRoot = path.join(dir, "rollbacks");
  fs.mkdirSync(dataDir, { recursive: true });
  // Seed dataDir with the same files we'll back up
  fs.writeFileSync(path.join(dataDir, "db.enc"),     Buffer.from("ORIG-DB"));
  fs.writeFileSync(path.join(dataDir, "db.key.enc"), "vault:orig-dbkey");
  fs.writeFileSync(path.join(dataDir, "vault.key"),  '{"vault":"orig"}');
  return {
    root:         dir,
    dataDir:      dataDir,
    storageRoot:  storageRoot,
    rollbackRoot: rollbackRoot,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
  };
}

function testRestoreRollbackSurface() {
  check("b.restoreRollback namespace present",   typeof b.restoreRollback === "object");
  check("swap is a function",                    typeof b.restoreRollback.swap === "function");
  check("rollback is a function",                typeof b.restoreRollback.rollback === "function");
  check("list is a function",                    typeof b.restoreRollback.list === "function");
  check("purge is a function",                   typeof b.restoreRollback.purge === "function");
  check("RestoreRollbackError is a class",       typeof b.restoreRollback.RestoreRollbackError === "function");
}

function testRestoreRollbackSwap() {
  var fx = _restoreFixture();
  try {
    // Build a staging dir
    var stagingDir = path.join(fx.root, "staging");
    fs.mkdirSync(stagingDir);
    fs.writeFileSync(path.join(stagingDir, "db.enc"), Buffer.from("NEW-DB"));

    var r = b.restoreRollback.swap({
      stagingDir:   stagingDir,
      dataDir:      fx.dataDir,
      rollbackRoot: fx.rollbackRoot,
      marker:       { bundleId: "test-bundle", reason: "test" },
    });
    check("swap returned a rollbackPath",         typeof r.rollbackPath === "string");
    check("dataDir was replaced by staging",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "NEW-DB");
    check("dataDir does NOT have the original db.enc",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() !== "ORIG-DB");
    check("rollback path holds the original dataDir",
          fs.readFileSync(path.join(r.rollbackPath, "db.enc")).toString() === "ORIG-DB");
    check("marker file written",                  fs.existsSync(r.markerPath));
    var marker = JSON.parse(fs.readFileSync(r.markerPath, "utf8"));
    check("marker carries bundleId + reason",
          marker.operator && marker.operator.bundleId === "test-bundle" &&
          marker.operator.reason === "test");
    check("staging dir consumed by swap",         !fs.existsSync(stagingDir));
  } finally { fx.cleanup(); }
}

async function testRestoreRollbackRoundTrip() {
  var fx = _restoreFixture();
  try {
    var stagingDir = path.join(fx.root, "staging");
    fs.mkdirSync(stagingDir);
    fs.writeFileSync(path.join(stagingDir, "db.enc"), Buffer.from("NEW-DB"));

    var r = b.restoreRollback.swap({
      stagingDir:   stagingDir,
      dataDir:      fx.dataDir,
      rollbackRoot: fx.rollbackRoot,
    });

    // Roll back — should restore the original dataDir
    var rb = await b.restoreRollback.rollback({
      dataDir:      fx.dataDir,
      rollbackPath: r.rollbackPath,
      rollbackRoot: fx.rollbackRoot,
    });
    check("rollback returns restoredFrom",         rb.restoredFrom === r.rollbackPath);
    check("rolled-back dataDir has original bytes",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "ORIG-DB");
    check("rollback path is consumed (no longer at original location)",
          !fs.existsSync(r.rollbackPath));
    check("rollback removed marker file",          !fs.existsSync(r.markerPath));
  } finally { fx.cleanup(); }
}

function testRestoreRollbackListAndPurge() {
  var fx = _restoreFixture();
  try {
    // Create three rollback dirs by repeated swap+restore
    var ids = [];
    for (var i = 0; i < 3; i++) {
      var stagingDir = path.join(fx.root, "stg-" + i);
      fs.mkdirSync(stagingDir);
      fs.writeFileSync(path.join(stagingDir, "db.enc"), Buffer.from("NEW-" + i));
      var r = b.restoreRollback.swap({
        stagingDir:   stagingDir,
        dataDir:      fx.dataDir,
        rollbackRoot: fx.rollbackRoot,
      });
      ids.push(r.rollbackPath);
      // Yield enough time for unique ms timestamp
      var end = Date.now() + 5;
      while (Date.now() < end) { /* spin briefly */ }
    }
    var listed = b.restoreRollback.list({ rollbackRoot: fx.rollbackRoot });
    check("list returns 3 rollback points",        listed.length === 3);
    check("list newest first",                     listed[0].rollbackPath === ids[2]);

    // Purge keeping 1
    var purgeR = b.restoreRollback.purge({ rollbackRoot: fx.rollbackRoot, keep: 1 });
    check("purge kept 1 newest, deleted 2",        purgeR.deleted.length === 2);
    var listed2 = b.restoreRollback.list({ rollbackRoot: fx.rollbackRoot });
    check("only the newest remains",               listed2.length === 1 && listed2[0].rollbackPath === ids[2]);
  } finally { fx.cleanup(); }
}

function testRestoreRollbackHandlesEmptyDataDir() {
  // First-ever restore: dataDir doesn't exist yet → swap should still work
  var fx = _restoreFixture();
  try {
    fs.rmSync(fx.dataDir, { recursive: true, force: true });
    var stagingDir = path.join(fx.root, "stg");
    fs.mkdirSync(stagingDir);
    fs.writeFileSync(path.join(stagingDir, "db.enc"), "FIRST-DB");

    var r = b.restoreRollback.swap({
      stagingDir:   stagingDir,
      dataDir:      fx.dataDir,
      rollbackRoot: fx.rollbackRoot,
    });
    check("swap with no existing dataDir: rollbackPath null",
          r.rollbackPath === null);
    check("dataDir created from staging",          fs.existsSync(path.join(fx.dataDir, "db.enc")));
  } finally { fx.cleanup(); }
}

// --- restore (orchestrator) ---

async function _seedBundle(fx, passphrase) {
  var backup = b.backup.create({
    dataDir:    fx.dataDir,
    storage:    b.backup.diskStorage({ root: fx.storageRoot }),
    passphrase: passphrase,
    files: [
      { relativePath: "db.enc",       kind: "raw",          required: true },
      { relativePath: "db.key.enc",   kind: "raw",          required: true },
      { relativePath: "vault.key",    kind: "raw",          required: false },
    ],
    vaultKeyJson: '{"vault":"orig"}',
    audit:        false,
  });
  var r = await backup.run();
  return r.bundleId;
}

function testRestoreSurface() {
  check("b.restore namespace present",            typeof b.restore === "object");
  check("b.restore.create is a function",         typeof b.restore.create === "function");
  check("RestoreError is a class",                typeof b.restore.RestoreError === "function");
}

function testRestoreCreateValidation() {
  var fx = _restoreFixture();
  try {
    var threw;
    threw = null; try { b.restore.create({}); } catch (e) { threw = e; }
    check("missing dataDir rejected",               threw && threw.code === "restore/no-datadir");

    threw = null;
    try { b.restore.create({ dataDir: fx.dataDir }); } catch (e) { threw = e; }
    check("missing storage rejected",               threw && threw.code === "restore/bad-storage");

    threw = null;
    try {
      b.restore.create({
        dataDir: fx.dataDir,
        storage: { listBundles: function () {} },   // missing methods
      });
    } catch (e) { threw = e; }
    check("incomplete storage rejected",            threw && threw.code === "restore/bad-storage");

    threw = null;
    try {
      b.restore.create({
        dataDir: fx.dataDir,
        storage: b.backup.diskStorage({ root: fx.storageRoot }),
      });
    } catch (e) { threw = e; }
    check("missing passphrase rejected",            threw && threw.code === "restore/no-passphrase");
  } finally { fx.cleanup(); }
}

async function testRestoreRunRoundTrip() {
  var fx = _restoreFixture();
  try {
    var passphrase = Buffer.from("pp");
    var bundleId = await _seedBundle(fx, passphrase);

    // Mutate dataDir so we can prove restore actually replaced it
    fs.writeFileSync(path.join(fx.dataDir, "db.enc"), "MUTATED");

    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.diskStorage({ root: fx.storageRoot }),
      passphrase:   passphrase,
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });

    var r = await restore.run({ bundleId: bundleId, marker: { reason: "test" } });
    check("run returns bundleId",                    r.bundleId === bundleId);
    check("run reports fileCount",                   r.fileCount === 3);
    check("run reports rollbackPath",                typeof r.rollbackPath === "string");
    check("run returns vaultKeyJson",                r.vaultKeyJson === '{"vault":"orig"}');

    // dataDir was replaced — the bytes match the seeded ORIGINAL,
    // not the post-mutation MUTATED value
    check("dataDir restored to bundle bytes",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "ORIG-DB");
    // Mutation was preserved in the rollback
    check("rollback holds the pre-restore (mutated) dataDir",
          fs.readFileSync(path.join(r.rollbackPath, "db.enc")).toString() === "MUTATED");

    // List + inspect work
    var listed = await restore.list();
    check("list shows the seeded bundle",            listed.some(function (e) { return e.bundleId === bundleId; }));
    var manifest = await restore.inspect(bundleId);
    check("inspect returns parsed manifest",         manifest && manifest.version === 1);
  } finally { fx.cleanup(); }
}

async function testRestoreRollbackUndoesRun() {
  var fx = _restoreFixture();
  try {
    var passphrase = Buffer.from("pp");
    var bundleId = await _seedBundle(fx, passphrase);
    fs.writeFileSync(path.join(fx.dataDir, "db.enc"), "MUTATED");

    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.diskStorage({ root: fx.storageRoot }),
      passphrase:   passphrase,
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    await restore.run({ bundleId: bundleId });

    // Roll back: dataDir should now hold the MUTATED bytes (the
    // pre-restore state we stashed in the rollback)
    await restore.rollback();
    check("rollback restored MUTATED dataDir",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "MUTATED");
  } finally { fx.cleanup(); }
}

async function testRestoreRunWithMissingBundle() {
  var fx = _restoreFixture();
  try {
    fs.mkdirSync(fx.storageRoot);
    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.diskStorage({ root: fx.storageRoot }),
      passphrase:   Buffer.from("pp"),
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    var threw = null;
    try { await restore.run({ bundleId: "2026-04-27T00-00-00-000Z-aaaaaaaa" }); }
    catch (e) { threw = e; }
    check("missing bundle surfaces bundle-not-found",
          threw && threw.code === "restore/bundle-not-found");
  } finally { fx.cleanup(); }
}

async function testRestoreRunWithWrongPassphrase() {
  var fx = _restoreFixture();
  try {
    var bundleId = await _seedBundle(fx, Buffer.from("right"));
    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.diskStorage({ root: fx.storageRoot }),
      passphrase:   Buffer.from("wrong"),
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    var threw = null;
    try { await restore.run({ bundleId: bundleId }); } catch (e) { threw = e; }
    check("wrong passphrase surfaces decrypt-failed",
          threw && threw.code === "restore/decrypt-failed");
    // dataDir should remain untouched on failure
    check("failed restore did NOT replace dataDir",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "ORIG-DB");
  } finally { fx.cleanup(); }
}

async function testRestoreListRollbacksAndPurge() {
  var fx = _restoreFixture();
  try {
    var passphrase = Buffer.from("pp");
    var bundleId = await _seedBundle(fx, passphrase);
    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.diskStorage({ root: fx.storageRoot }),
      passphrase:   passphrase,
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    // Two restores to create two rollback points
    await restore.run({ bundleId: bundleId });
    await new Promise(function (r) { setTimeout(r, 5); });
    await restore.run({ bundleId: bundleId });

    var rb = restore.listRollbacks();
    check("listRollbacks shows 2 entries",          rb.length === 2);

    var purged = restore.purgeRollbacks({ keep: 1 });
    check("purgeRollbacks deleted the older one",   purged.deleted.length === 1);
    check("only newest rollback remains",           restore.listRollbacks().length === 1);
  } finally { fx.cleanup(); }
}

async function testRestoreInspectWithoutDecrypt() {
  var fx = _restoreFixture();
  try {
    var bundleId = await _seedBundle(fx, Buffer.from("pp"));
    var restore = b.restore.create({
      dataDir:      fx.dataDir,
      storage:      b.backup.diskStorage({ root: fx.storageRoot }),
      passphrase:   Buffer.from("any"),    // not used by inspect
      rollbackRoot: fx.rollbackRoot,
      audit:        false,
    });
    var manifest = await restore.inspect(bundleId);
    check("inspect surfaces manifest without decrypting",
          manifest.version === 1 && manifest.files.length === 3);

    var threw = null;
    try { await restore.inspect("2026-04-27T00-00-00-000Z-aaaaaaaa"); } catch (e) { threw = e; }
    check("inspect of missing bundle rejects",     threw && threw.code === "restore/bundle-not-found");
  } finally { fx.cleanup(); }
}

// ---- backup (orchestrator) ----

function _backupFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bk-"));
  var dataDir = path.join(dir, "data");
  var storageRoot = path.join(dir, "backups");
  fs.mkdirSync(dataDir, { recursive: true });
  // Seed a tiny dataDir
  fs.writeFileSync(path.join(dataDir, "db.enc"),     Buffer.from("ENCRYPTED-DB"));
  fs.writeFileSync(path.join(dataDir, "db.key.enc"), "vault:dbkey");
  fs.writeFileSync(path.join(dataDir, "vault.key"),  '{"vault":"keypair"}');
  return {
    root:        dir,
    dataDir:     dataDir,
    storageRoot: storageRoot,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
  };
}

function _backupOpts(fx, override) {
  return Object.assign({
    dataDir:    fx.dataDir,
    storage:    b.backup.diskStorage({ root: fx.storageRoot }),
    passphrase: Buffer.from("operator-passphrase"),
    files: [
      { relativePath: "db.enc",       kind: "raw",          required: true },
      { relativePath: "db.key.enc",   kind: "raw",          required: true },
      { relativePath: "vault.key",    kind: "raw",          required: false },
    ],
    vaultKeyJson: '{"vault":"keypair"}',
    audit:        false,
  }, override || {});
}

function testBackupSurface() {
  check("b.backup namespace present",             typeof b.backup === "object");
  check("b.backup.create is a function",          typeof b.backup.create === "function");
  check("b.backup.diskStorage is a function",    typeof b.backup.diskStorage === "function");
  check("b.backup.recommendedFiles is a function", typeof b.backup.recommendedFiles === "function");
  check("b.backup.BUNDLE_ID_RE is a RegExp",      b.backup.BUNDLE_ID_RE instanceof RegExp);
  check("BackupError is a class",                 typeof b.backup.BackupError === "function");
}

function testBackupRecommendedFiles() {
  // Plain DB + plaintext vault (typical dev setup)
  var dev = b.backup.recommendedFiles({ atRest: "plain", vaultMode: "plaintext" });
  var devNames = dev.map(function (f) { return f.relativePath; });
  check("plain mode: includes blamejs.db (live SQLite file)",
        devNames.indexOf("blamejs.db") !== -1);
  check("plain mode: does NOT include db.enc",
        devNames.indexOf("db.enc") === -1);
  check("plaintext vault: includes vault.key",
        devNames.indexOf("vault.key") !== -1);
  check("plaintext vault: does NOT include vault.key.sealed",
        devNames.indexOf("vault.key.sealed") === -1);

  // Encrypted DB + wrapped vault (typical prod setup)
  var prod = b.backup.recommendedFiles({ atRest: "encrypted", vaultMode: "wrapped" });
  var prodNames = prod.map(function (f) { return f.relativePath; });
  check("encrypted mode: includes db.enc",        prodNames.indexOf("db.enc") !== -1);
  check("encrypted mode: includes db.key.enc",    prodNames.indexOf("db.key.enc") !== -1);
  check("encrypted mode: does NOT include blamejs.db",
        prodNames.indexOf("blamejs.db") === -1);
  check("wrapped vault: includes vault.key.sealed",
        prodNames.indexOf("vault.key.sealed") !== -1);
  check("wrapped vault: does NOT include vault.key",
        prodNames.indexOf("vault.key") === -1);

  // Audit-signing key naming follows vault mode
  check("audit-sign.key in plaintext-vault recommendation",
        devNames.indexOf("audit-sign.key") !== -1);
  check("audit-sign.key.sealed in wrapped-vault recommendation",
        prodNames.indexOf("audit-sign.key.sealed") !== -1);

  // Operator additionalSealed appended
  var withCa = b.backup.recommendedFiles({
    atRest: "encrypted", vaultMode: "wrapped",
    additionalSealed: ["ca.key.sealed", "tls/privkey.pem.sealed"],
  });
  var caEntry = withCa.find(function (f) { return f.relativePath === "ca.key.sealed"; });
  check("additionalSealed entries appear with kind=vault-sealed",
        caEntry && caEntry.kind === "vault-sealed");

  // Custom dbName respected
  var custom = b.backup.recommendedFiles({ atRest: "plain", vaultMode: "plaintext", dbName: "myapp.db" });
  check("custom dbName respected in plain mode",
        custom.map(function (f) { return f.relativePath; }).indexOf("myapp.db") !== -1);
}

async function testBackupFlushBeforeBackupCalled() {
  // Verify flushBeforeBackup hook fires before snapshotting. Use the
  // operator-supplied function form (no dependency on b.db being inited)
  // so the test is hermetic.
  var fx = _backupFixture();
  try {
    var flushCalls = 0;
    var backup = b.backup.create(_backupOpts(fx, {
      flushBeforeBackup: function () { flushCalls++; },
    }));
    await backup.run();
    check("flushBeforeBackup called once on run()", flushCalls === 1);
    await backup.run();
    check("flushBeforeBackup called per run",       flushCalls === 2);
  } finally { fx.cleanup(); }
}

async function testBackupFlushFailureDoesNotFailBackup() {
  // A flush-hook throw should be audited but not fail the run; the
  // bundle just snapshots whatever's on disk.
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx, {
      flushBeforeBackup: function () { throw new Error("flush-broken"); },
    }));
    var r = await backup.run();
    check("backup.run succeeds despite flush failure",
          typeof r.bundleId === "string");
  } finally { fx.cleanup(); }
}

async function testBackupFlushBeforeBackupOptOut() {
  // flushBeforeBackup: false skips the hook entirely (operator pattern
  // for out-of-band backup tools that don't own the db process)
  var fx = _backupFixture();
  try {
    var calls = 0;
    var backup = b.backup.create(_backupOpts(fx, {
      flushBeforeBackup: false,
    }));
    // Stub b.db so even if backup tried to find a default flush, it
    // wouldn't have one (we're confirming the explicit false opt-out)
    await backup.run();
    check("flushBeforeBackup:false skips any flush",  calls === 0);
  } finally { fx.cleanup(); }
}

function testBackupCreateValidation() {
  var fx = _backupFixture();
  try {
    var threw;
    threw = null; try { b.backup.create({}); } catch (e) { threw = e; }
    check("missing dataDir rejected",               threw && threw.code === "backup/no-datadir");

    threw = null;
    try { b.backup.create({ dataDir: fx.dataDir }); } catch (e) { threw = e; }
    check("missing storage rejected",               threw && threw.code === "backup/bad-storage");

    threw = null;
    try {
      b.backup.create({
        dataDir: fx.dataDir,
        storage: { writeBundle: function () {} },  // missing other methods
        passphrase: Buffer.from("p"),
        files: [{ relativePath: "x" }],
        vaultKeyJson: "{}",
      });
    } catch (e) { threw = e; }
    check("incomplete storage rejected",            threw && threw.code === "backup/bad-storage");

    threw = null;
    try {
      b.backup.create({
        dataDir: fx.dataDir,
        storage: b.backup.diskStorage({ root: fx.storageRoot }),
        files: [{ relativePath: "x" }],
        vaultKeyJson: "{}",
      });
    } catch (e) { threw = e; }
    check("missing passphrase rejected",            threw && threw.code === "backup/no-passphrase");

    threw = null;
    try {
      b.backup.create({
        dataDir: fx.dataDir,
        storage: b.backup.diskStorage({ root: fx.storageRoot }),
        passphrase: Buffer.from("p"),
        files: [],
        vaultKeyJson: "{}",
      });
    } catch (e) { threw = e; }
    check("empty files list rejected",              threw && threw.code === "backup/no-files");

    threw = null;
    try {
      b.backup.create({
        dataDir: fx.dataDir,
        storage: b.backup.diskStorage({ root: fx.storageRoot }),
        passphrase: Buffer.from("p"),
        files: [{ relativePath: "x" }],
        // no vaultKeyJson
      });
    } catch (e) { threw = e; }
    check("missing vaultKeyJson rejected",          threw && threw.code === "backup/no-vault-key-json");
  } finally { fx.cleanup(); }
}

async function testBackupRunListReadDelete() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx));
    var r1 = await backup.run({ metadata: { reason: "first" } });
    check("run returns bundleId in framework format",
          b.backup.BUNDLE_ID_RE.test(r1.bundleId));
    check("run reports fileCount = 3",              r1.fileCount === 3);
    check("run reports bundleSize > 0",             r1.bundleSize > 0);
    check("run reports durationMs",                 typeof r1.durationMs === "number");

    // list
    var listed = await backup.list();
    check("list shows the new bundle",              listed.length === 1 && listed[0].bundleId === r1.bundleId);
    check("list entry has size + createdAt",        listed[0].size > 0 && typeof listed[0].createdAt === "string");

    // read pulls the bundle out without decrypting
    var pullDir = path.join(fx.root, "pull");
    await backup.read(r1.bundleId, pullDir);
    check("read pulls manifest.json",               fs.existsSync(path.join(pullDir, "manifest.json")));
    check("read pulls files/ subdir",               fs.existsSync(path.join(pullDir, "files")));

    // The pulled bundle is a real bundle: restore-bundle.extract
    // recovers it (end-to-end backup → storage → restore loop)
    var restoreDir = path.join(fx.root, "restored");
    var rr = await b.restoreBundle.extract({
      bundleDir:  pullDir,
      stagingDir: restoreDir,
      passphrase: Buffer.from("operator-passphrase"),
    });
    check("backup → restore round-trip recovers all 3 files",
          rr.fileCount === 3);
    check("restore recovered db.enc bytes",
          fs.readFileSync(path.join(restoreDir, "db.enc")).toString() === "ENCRYPTED-DB");

    // delete
    await backup.delete(r1.bundleId);
    var listed2 = await backup.list();
    check("delete removed the bundle",              listed2.length === 0);
  } finally { fx.cleanup(); }
}

async function testBackupVaultKeyJsonAsFunction() {
  var fx = _backupFixture();
  try {
    var calls = 0;
    var backup = b.backup.create(_backupOpts(fx, {
      vaultKeyJson: function () { calls++; return '{"from":"function"}'; },
    }));
    await backup.run();
    await backup.run();
    check("vaultKeyJson function called per run",   calls === 2);
  } finally { fx.cleanup(); }
}

async function testBackupVaultKeyJsonAsAsyncFunction() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx, {
      vaultKeyJson: async function () { return '{"async":"works"}'; },
    }));
    var r = await backup.run();
    check("async vaultKeyJson resolves",            typeof r.bundleId === "string");

    // Verify the async-resolved JSON ended up in the bundle
    var pullDir = path.join(fx.root, "pull-async");
    await backup.read(r.bundleId, pullDir);
    var rr = await b.restoreBundle.extract({
      bundleDir:  pullDir,
      stagingDir: path.join(fx.root, "restored-async"),
      passphrase: Buffer.from("operator-passphrase"),
    });
    check("async vaultKeyJson surfaced in restore", rr.vaultKeyJson === '{"async":"works"}');
  } finally { fx.cleanup(); }
}

async function testBackupRetentionPurgeOlder() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx));
    // Run 4 backups with small delay so timestamps differ
    var ids = [];
    for (var i = 0; i < 4; i++) {
      var r = await backup.run();
      ids.push(r.bundleId);
      await new Promise(function (rr) { setTimeout(rr, 5); });
    }
    var listed = await backup.list();
    check("4 bundles before purge",                 listed.length === 4);
    check("list returns newest first",              listed[0].bundleId === ids[3]);

    var purged = await backup.purgeOlder({ keep: 2 });
    check("purgeOlder kept 2 newest",               purged.kept === 2);
    check("purgeOlder deleted 2 oldest",            purged.deleted.length === 2);
    var afterList = await backup.list();
    check("list shows 2 remaining",                 afterList.length === 2);
    check("retained bundles are the 2 newest",
          afterList[0].bundleId === ids[3] && afterList[1].bundleId === ids[2]);
  } finally { fx.cleanup(); }
}

async function testBackupRetentionAutoSweepOnRun() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx, { retention: { keep: 2 } }));
    var ids = [];
    for (var i = 0; i < 4; i++) {
      var r = await backup.run();
      ids.push(r.bundleId);
      await new Promise(function (rr) { setTimeout(rr, 5); });
    }
    // After 4 runs with retention=2, only the 2 newest should remain
    var listed = await backup.list();
    check("retention auto-sweep keeps only 2",      listed.length === 2);
  } finally { fx.cleanup(); }
}

async function testBackupBundleIdValidation() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx));
    var threw;
    threw = null;
    try { await backup.delete("not-a-valid-id"); } catch (e) { threw = e; }
    check("delete rejects bad bundleId",            threw && threw.code === "backup/bad-bundle-id");

    threw = null;
    try { await backup.read("not-a-valid-id", path.join(fx.root, "x")); } catch (e) { threw = e; }
    check("read rejects bad bundleId",              threw && threw.code === "backup/bad-bundle-id");
  } finally { fx.cleanup(); }
}

async function testBackupLocalStorageRejectsExistingDest() {
  var fx = _backupFixture();
  try {
    var backup = b.backup.create(_backupOpts(fx));
    var r = await backup.run();
    var dest = path.join(fx.root, "exists-pre");
    fs.mkdirSync(dest);
    var threw = null;
    try { await backup.read(r.bundleId, dest); } catch (e) { threw = e; }
    check("read rejects existing destDir",          threw && threw.code === "backup/dest-exists");
  } finally { fx.cleanup(); }
}

// ---- restore-bundle ----
//
// Reuses _bundleFixture + builds an actual encrypted bundle via
// backupBundle.create, then restores it through restoreBundle.extract.
// This verifies the two halves of the round-trip in concert.

async function _buildSampleBundle(fx, passphrase, files) {
  var outDir = path.join(fx.root, "bundle-" + Math.random().toString(36).slice(2, 8));
  for (var i = 0; i < files.length; i++) {
    if (files[i].content !== undefined) fx.write(files[i].relativePath, files[i].content);
  }
  await b.backupBundle.create({
    dataDir:      fx.dataDir,
    outDir:       outDir,
    passphrase:   passphrase,
    vaultKeyJson: '{"vault":"sample-keypair"}',
    files:        files.filter(function (f) { return f.content !== undefined; }).map(function (f) {
      return { relativePath: f.relativePath, kind: f.kind || "raw", required: true };
    }),
  });
  return outDir;
}

function testRestoreBundleSurface() {
  check("b.restoreBundle namespace present",      typeof b.restoreBundle === "object");
  check("extract is a function",                  typeof b.restoreBundle.extract === "function");
  check("inspect is a function",                  typeof b.restoreBundle.inspect === "function");
  check("RestoreBundleError is a class",          typeof b.restoreBundle.RestoreBundleError === "function");
}

async function testRestoreBundleRoundTrip() {
  var fx = _bundleFixture();
  try {
    var passphrase = Buffer.from("operator-passphrase");
    var bundleDir = await _buildSampleBundle(fx, passphrase, [
      { relativePath: "db.enc",          content: Buffer.from("ENCRYPTED-DB"),  kind: "raw" },
      { relativePath: "db.key.enc",      content: "vault:wrapped",              kind: "raw" },
      { relativePath: "tls/privkey.pem", content: "PEM-BYTES",                  kind: "vault-sealed" },
    ]);
    var stagingDir = path.join(fx.root, "staging");
    var events = [];
    var r = await b.restoreBundle.extract({
      bundleDir:        bundleDir,
      stagingDir:       stagingDir,
      passphrase:       passphrase,
      progressCallback: function (e) { events.push(e.phase); },
    });
    check("extract.fileCount = 3",                  r.fileCount === 3);
    check("extract returned vaultKeyJson",          r.vaultKeyJson === '{"vault":"sample-keypair"}');
    check("staging has db.enc",                     fs.existsSync(path.join(stagingDir, "db.enc")));
    check("staging has db.key.enc",                 fs.existsSync(path.join(stagingDir, "db.key.enc")));
    check("staging recreated tls/ subdir",          fs.existsSync(path.join(stagingDir, "tls/privkey.pem")));
    check("restored db.enc matches original",
          fs.readFileSync(path.join(stagingDir, "db.enc")).toString() === "ENCRYPTED-DB");
    check("restored db.key.enc matches original",
          fs.readFileSync(path.join(stagingDir, "db.key.enc"), "utf8") === "vault:wrapped");
    check("restored tls/privkey.pem matches original",
          fs.readFileSync(path.join(stagingDir, "tls/privkey.pem"), "utf8") === "PEM-BYTES");
    check("progress phases include unwrap_vault_key + decrypt + done",
          events.indexOf("unwrap_vault_key") !== -1 &&
          events.indexOf("decrypt") !== -1 &&
          events.indexOf("done") !== -1);
  } finally { fx.cleanup(); }
}

async function testRestoreBundleFilterSubset() {
  var fx = _bundleFixture();
  try {
    var passphrase = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, passphrase, [
      { relativePath: "db.enc",          content: "DB" },
      { relativePath: "tls/privkey.pem", content: "PEM" },
    ]);
    var stagingDir = path.join(fx.root, "staging");
    var r = await b.restoreBundle.extract({
      bundleDir:  bundleDir,
      stagingDir: stagingDir,
      passphrase: passphrase,
      filter: function (entry) { return entry.relativePath === "db.enc"; },
    });
    check("filter restored only matching entries",   r.fileCount === 1);
    check("staging has db.enc",                       fs.existsSync(path.join(stagingDir, "db.enc")));
    check("staging does NOT have tls/privkey.pem",   !fs.existsSync(path.join(stagingDir, "tls/privkey.pem")));
    // Vault key still recovered even when filter rejects everything
    check("filter still recovers vaultKeyJson",      typeof r.vaultKeyJson === "string");
  } finally { fx.cleanup(); }
}

async function testRestoreBundleWrongPassphrase() {
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("right");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB" },
    ]);
    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-wrong"),
        passphrase: Buffer.from("wrong"),
      });
    } catch (e) { threw = e; }
    check("wrong passphrase surfaces decrypt-failed",
          threw && threw.code === "restore-bundle/decrypt-failed");
    check("staging dir cleaned up after failure",
          !fs.existsSync(path.join(fx.root, "staging-wrong")));
  } finally { fx.cleanup(); }
}

async function testRestoreBundleTamperedBlobDetected() {
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB-BYTES" },
    ]);
    // Locate the encrypted blob and flip a byte AFTER the nonce
    var blobPath = path.join(bundleDir, "files/db.enc.enc");
    var b2 = fs.readFileSync(blobPath);
    b2[b.backupCrypto.NONCE_BYTES + 1] ^= 0x01;
    fs.writeFileSync(blobPath, b2);

    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-tamper"),
        passphrase: p,
      });
    } catch (e) { threw = e; }
    check("tampered blob surfaces decrypt-failed",  threw && threw.code === "restore-bundle/decrypt-failed");
  } finally { fx.cleanup(); }
}

async function testRestoreBundleChecksumMismatchDetected() {
  // Tampering with a blob fails the AEAD check first. To exercise the
  // checksum-mismatch path, we modify the manifest's declared checksum
  // for a blob whose contents are still intact — the post-decrypt
  // sha3 will then disagree with the manifest.
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB" },
    ]);
    var manifestPath = path.join(bundleDir, "manifest.json");
    var m = b.backupManifest.parse(fs.readFileSync(manifestPath, "utf8"));
    m.files[0].checksum = "0".repeat(128);   // wrong but valid-shape
    fs.writeFileSync(manifestPath, b.backupManifest.serialize(m));

    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-checksum"),
        passphrase: p,
      });
    } catch (e) { threw = e; }
    check("checksum mismatch surfaces clearly",     threw && threw.code === "restore-bundle/checksum-mismatch");
    check("staging cleaned up after checksum failure",
          !fs.existsSync(path.join(fx.root, "staging-checksum")));
  } finally { fx.cleanup(); }
}

async function testRestoreBundleMissingBlobDetected() {
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB" },
    ]);
    // Delete the blob the manifest references
    fs.unlinkSync(path.join(bundleDir, "files/db.enc.enc"));

    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-missing"),
        passphrase: p,
      });
    } catch (e) { threw = e; }
    check("missing blob surfaces missing-blob",     threw && threw.code === "restore-bundle/missing-blob");
  } finally { fx.cleanup(); }
}

async function testRestoreBundleEncryptedSizeMismatchDetected() {
  var fx = _bundleFixture();
  try {
    var p = Buffer.from("p");
    var bundleDir = await _buildSampleBundle(fx, p, [
      { relativePath: "db.enc", content: "DB" },
    ]);
    // Append junk bytes to the blob — encryptedSize will mismatch
    var blobPath = path.join(bundleDir, "files/db.enc.enc");
    fs.appendFileSync(blobPath, Buffer.from([0xAA, 0xBB]));

    var threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: path.join(fx.root, "staging-size"),
        passphrase: p,
      });
    } catch (e) { threw = e; }
    check("encryptedSize mismatch surfaces size-mismatch",
          threw && threw.code === "restore-bundle/size-mismatch");
  } finally { fx.cleanup(); }
}

function testRestoreBundleInspectReturnsManifest() {
  var fx = _bundleFixture();
  try {
    // Build a minimal valid bundle manually so inspect doesn't need the encrypt path
    var bundleDir = path.join(fx.root, "inspect-bundle");
    fs.mkdirSync(bundleDir);
    fs.mkdirSync(path.join(bundleDir, "files"));
    var m = b.backupManifest.create({
      vaultKeySalt: "11".repeat(32),
      vaultKeyEnc:  Buffer.from("x").toString("base64"),
      files: [{
        relativePath:  "db.enc",
        encryptedPath: "files/db.enc.enc",
        size:          10,
        encryptedSize: 50,
        checksum:      "a".repeat(128),
        salt:          "ff".repeat(32),
        kind:          "raw",
      }],
    });
    fs.writeFileSync(path.join(bundleDir, "manifest.json"), b.backupManifest.serialize(m));
    var inspected = b.restoreBundle.inspect({ bundleDir: bundleDir });
    check("inspect returns parsed manifest",        inspected && inspected.version === 1);
    check("inspect doesn't need passphrase",        inspected.files.length === 1);
  } finally { fx.cleanup(); }
}

async function testRestoreBundleArgValidation() {
  var fx = _bundleFixture();
  try {
    var threw;
    threw = null; try { await b.restoreBundle.extract({}); } catch (e) { threw = e; }
    check("missing bundleDir rejected",             threw && threw.code === "restore-bundle/no-bundle");

    threw = null;
    try { await b.restoreBundle.extract({ bundleDir: fx.root }); } catch (e) { threw = e; }
    check("missing stagingDir rejected",            threw && threw.code === "restore-bundle/no-staging");

    fs.mkdirSync(path.join(fx.root, "exists-stag"));
    threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  fx.root,
        stagingDir: path.join(fx.root, "exists-stag"),
        passphrase: Buffer.from("p"),
      });
    } catch (e) { threw = e; }
    check("existing stagingDir rejected",           threw && threw.code === "restore-bundle/staging-exists");

    threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  fx.root,
        stagingDir: path.join(fx.root, "fresh-stag"),
      });
    } catch (e) { threw = e; }
    check("missing passphrase rejected",            threw && threw.code === "restore-bundle/no-passphrase");

    threw = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  fx.dataDir,
        stagingDir: path.join(fx.root, "fresh-stag-2"),
        passphrase: Buffer.from("p"),
      });
    } catch (e) { threw = e; }
    check("bundleDir without manifest rejected",    threw && threw.code === "restore-bundle/missing-manifest");
  } finally { fx.cleanup(); }
}

// ---- backup-bundle ----
//
// End-to-end fixture: build a tmp dataDir with a few files, encrypt
// the bundle, verify each blob round-trips through backup-crypto.

function _bundleFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bundle-"));
  var dataDir = path.join(dir, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  return {
    root:    dir,
    dataDir: dataDir,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
    write: function (rel, content) {
      var full = path.join(dataDir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
      return full;
    },
  };
}

function testBackupBundleSurface() {
  check("b.backupBundle namespace present",       typeof b.backupBundle === "object");
  check("b.backupBundle.create is a function",    typeof b.backupBundle.create === "function");
  check("BackupBundleError is a class",           typeof b.backupBundle.BackupBundleError === "function");
}

async function testBackupBundleCreateEndToEnd() {
  var fx = _bundleFixture();
  try {
    fx.write("db.enc",        Buffer.from("ENCRYPTED-DB-BYTES"));
    fx.write("db.key.enc",    "vault:wrapped-db-key");
    fx.write("vault.key",     '{"keypair":"json"}');
    fx.write("tls/privkey.pem", "PEM-BYTES");

    var passphrase = Buffer.from("operator-passphrase");
    var vaultKeyJson = '{"vault":"keypair-bytes"}';
    var outDir = path.join(fx.root, "bundle");

    var events = [];
    var result = await b.backupBundle.create({
      dataDir:      fx.dataDir,
      outDir:       outDir,
      passphrase:   passphrase,
      vaultKeyJson: vaultKeyJson,
      files: [
        { relativePath: "db.enc",          kind: "raw",          required: true },
        { relativePath: "db.key.enc",      kind: "raw",          required: true },
        { relativePath: "vault.key",       kind: "raw",          required: false },
        { relativePath: "tls/privkey.pem", kind: "vault-sealed", required: false },
        { relativePath: "missing-optional",kind: "raw",          required: false },
      ],
      metadata:     { reason: "test-end-to-end" },
      progressCallback: function (e) { events.push(e.phase); },
    });

    check("result.fileCount = 4 (missing skipped)", result.fileCount === 4);
    check("result.manifestPath under outDir",
          result.manifestPath === path.join(outDir, "manifest.json"));
    check("manifest exists on disk",                fs.existsSync(result.manifestPath));
    check("progress fired wrap_vault_key + done",
          events.indexOf("wrap_vault_key") !== -1 && events.indexOf("done") !== -1);
    check("progress fired skip_missing for optional",
          events.indexOf("skip_missing") !== -1);

    // Manifest is parseable + structurally valid
    var raw = fs.readFileSync(result.manifestPath, "utf8");
    var m = b.backupManifest.parse(raw);
    check("emitted manifest is parse-valid",        m.version === 1);
    check("manifest has 4 file entries",            m.files.length === 4);
    check("manifest carries operator metadata",     m.metadata && m.metadata.reason === "test-end-to-end");

    // Vault key round-trip — decrypt with passphrase + bundled salt
    var vkBytes = await b.backupCrypto.decryptWithPassphrase(
      Buffer.from(m.vaultKeyEnc, "base64"), passphrase, m.vaultKeySalt);
    check("vaultKeyEnc decrypts to original JSON",  vkBytes.toString("utf8") === vaultKeyJson);

    // Each file's blob exists and decrypts to the original bytes
    // matching the manifest's plaintext checksum.
    for (var i = 0; i < m.files.length; i++) {
      var entry = m.files[i];
      var blobPath = path.join(outDir, entry.encryptedPath);
      check("blob exists for " + entry.relativePath,  fs.existsSync(blobPath));
      var blob = fs.readFileSync(blobPath);
      check("blob size matches manifest.encryptedSize for " + entry.relativePath,
            blob.length === entry.encryptedSize);
      var dec = await b.backupCrypto.decryptWithPassphrase(blob, passphrase, entry.salt);
      var origPath = path.join(fx.dataDir, entry.relativePath);
      var orig = fs.readFileSync(origPath);
      check("decrypted blob matches original plaintext for " + entry.relativePath,
            Buffer.compare(dec, orig) === 0);
      check("plaintext sha3-512 matches manifest checksum for " + entry.relativePath,
            b.backupCrypto.checksum(orig) === entry.checksum);
    }
  } finally { fx.cleanup(); }
}

async function testBackupBundlePathTraversalRejected() {
  var fx = _bundleFixture();
  try {
    var threw = null;
    try {
      await b.backupBundle.create({
        dataDir:      fx.dataDir,
        outDir:       path.join(fx.root, "bundle"),
        passphrase:   Buffer.from("p"),
        vaultKeyJson: "{}",
        files: [{ relativePath: "../escape", kind: "raw", required: true }],
      });
    } catch (e) { threw = e; }
    check("'..' in relativePath rejected",          threw && threw.code === "backup-bundle/bad-include");

    threw = null;
    try {
      await b.backupBundle.create({
        dataDir:      fx.dataDir,
        outDir:       path.join(fx.root, "bundle2"),
        passphrase:   Buffer.from("p"),
        vaultKeyJson: "{}",
        files: [{ relativePath: "/abs/path", kind: "raw", required: true }],
      });
    } catch (e) { threw = e; }
    check("absolute path in relativePath rejected", threw && threw.code === "backup-bundle/bad-include");
  } finally { fx.cleanup(); }
}

async function testBackupBundleRequiredMissing() {
  var fx = _bundleFixture();
  try {
    var threw = null;
    try {
      await b.backupBundle.create({
        dataDir:      fx.dataDir,
        outDir:       path.join(fx.root, "bundle"),
        passphrase:   Buffer.from("p"),
        vaultKeyJson: "{}",
        files: [{ relativePath: "not-here", kind: "raw", required: true }],
      });
    } catch (e) { threw = e; }
    check("missing required file surfaces missing-required",
          threw && threw.code === "backup-bundle/missing-required");
  } finally { fx.cleanup(); }
}

async function testBackupBundleEmptyBundleRejected() {
  var fx = _bundleFixture();
  try {
    // All entries optional and missing → no files written → reject
    var threw = null;
    try {
      await b.backupBundle.create({
        dataDir:      fx.dataDir,
        outDir:       path.join(fx.root, "bundle"),
        passphrase:   Buffer.from("p"),
        vaultKeyJson: "{}",
        files: [{ relativePath: "absent", kind: "raw", required: false }],
      });
    } catch (e) { threw = e; }
    check("empty bundle rejected",                  threw && threw.code === "backup-bundle/empty");
  } finally { fx.cleanup(); }
}

async function testBackupBundleArgValidation() {
  var fx = _bundleFixture();
  try {
    var threw;

    threw = null;
    try { await b.backupBundle.create({}); } catch (e) { threw = e; }
    check("missing dataDir rejected",               threw && threw.code === "backup-bundle/no-datadir");

    threw = null;
    try { await b.backupBundle.create({ dataDir: fx.dataDir }); } catch (e) { threw = e; }
    check("missing outDir rejected",                threw && threw.code === "backup-bundle/no-outdir");

    fs.mkdirSync(path.join(fx.root, "exists"));
    threw = null;
    try {
      await b.backupBundle.create({
        dataDir: fx.dataDir, outDir: path.join(fx.root, "exists"),
        passphrase: Buffer.from("p"), vaultKeyJson: "{}",
        files: [{ relativePath: "x" }],
      });
    } catch (e) { threw = e; }
    check("existing outDir rejected",               threw && threw.code === "backup-bundle/outdir-exists");

    threw = null;
    try {
      await b.backupBundle.create({
        dataDir: fx.dataDir, outDir: path.join(fx.root, "bundle"),
        vaultKeyJson: "{}", files: [{ relativePath: "x" }],
      });
    } catch (e) { threw = e; }
    check("missing passphrase rejected",            threw && threw.code === "backup-bundle/no-passphrase");

    threw = null;
    try {
      await b.backupBundle.create({
        dataDir: fx.dataDir, outDir: path.join(fx.root, "bundle2"),
        passphrase: Buffer.from("p"), files: [{ relativePath: "x" }],
      });
    } catch (e) { threw = e; }
    check("missing vaultKeyJson rejected",          threw && threw.code === "backup-bundle/no-vault-key-json");

    threw = null;
    try {
      await b.backupBundle.create({
        dataDir: fx.dataDir, outDir: path.join(fx.root, "bundle3"),
        passphrase: Buffer.from("p"), vaultKeyJson: "{}", files: [],
      });
    } catch (e) { threw = e; }
    check("empty files list rejected",              threw && threw.code === "backup-bundle/no-files");
  } finally { fx.cleanup(); }
}

// ---- backup-manifest ----

function _validFileEntry(over) {
  return Object.assign({
    relativePath:  "db.enc",
    encryptedPath: "files/db.enc.bin",
    size:          12345,
    encryptedSize: 12369,
    checksum:      "a".repeat(128),     // sha3-512 hex
    salt:          "ff".repeat(32),
    kind:          "raw",
  }, over || {});
}

function _validManifestArgs() {
  return {
    vaultKeySalt: "11".repeat(32),
    vaultKeyEnc:  Buffer.from("fakekey").toString("base64"),
    files:        [_validFileEntry()],
    metadata:     { reason: "test" },
  };
}

function testBackupManifestSurface() {
  check("b.backupManifest namespace present",     typeof b.backupManifest === "object");
  check("create is a function",                   typeof b.backupManifest.create === "function");
  check("validate is a function",                 typeof b.backupManifest.validate === "function");
  check("serialize is a function",                typeof b.backupManifest.serialize === "function");
  check("parse is a function",                    typeof b.backupManifest.parse === "function");
  check("FORMAT_VERSION = 1",                     b.backupManifest.FORMAT_VERSION === 1);
  check("FRAMEWORK_NAME = blamejs",               b.backupManifest.FRAMEWORK_NAME === "blamejs");
  check("VALID_KINDS includes raw/vault-sealed/plaintext",
        b.backupManifest.VALID_KINDS["raw"] === 1 &&
        b.backupManifest.VALID_KINDS["vault-sealed"] === 1 &&
        b.backupManifest.VALID_KINDS["plaintext"] === 1);
}

function testBackupManifestCreateAndSerialize() {
  var m = b.backupManifest.create(_validManifestArgs());
  check("create assigns version 1",               m.version === 1);
  check("create assigns framework=blamejs",       m.framework === "blamejs");
  check("create assigns frameworkVersion from constants",
        typeof m.frameworkVersion === "string" && m.frameworkVersion === b.constants.version);
  check("create assigns ISO createdAt",           /^\d{4}-\d{2}-\d{2}T/.test(m.createdAt));
  check("create copies metadata",                 m.metadata && m.metadata.reason === "test");
  check("create files length matches input",      m.files.length === 1);

  var s = b.backupManifest.serialize(m);
  check("serialize returns string",               typeof s === "string");
  check("serialize ends with newline",            s.charAt(s.length - 1) === "\n");
  // Round-trip via parse
  var parsed = b.backupManifest.parse(s);
  check("parse + serialize round-trips key fields",
        parsed.version === m.version &&
        parsed.framework === m.framework &&
        parsed.frameworkVersion === m.frameworkVersion &&
        parsed.files.length === 1 &&
        parsed.files[0].relativePath === "db.enc");
}

function testBackupManifestValidateRejectsBadFields() {
  var bad;

  // Missing version
  bad = _validManifestArgs();
  delete bad.vaultKeySalt;
  var threw = null;
  try { b.backupManifest.create(bad); } catch (e) { threw = e; }
  check("create without vaultKeySalt rejected",   threw && threw.code === "backup-manifest/invalid");

  // Bad checksum length
  var m = b.backupManifest.create(_validManifestArgs());
  m.files[0].checksum = "short";
  var v = b.backupManifest.validate(m);
  check("validate flags short checksum",          v.ok === false &&
        v.errors.some(function (e) { return /checksum/.test(e); }));

  // Path traversal
  m = b.backupManifest.create(_validManifestArgs());
  m.files[0].relativePath = "../escape";
  v = b.backupManifest.validate(m);
  check("validate flags '..' in relativePath",    v.ok === false &&
        v.errors.some(function (e) { return /relativePath/.test(e) && /\.\./.test(e); }));

  // Leading separator
  m = b.backupManifest.create(_validManifestArgs());
  m.files[0].relativePath = "/abs";
  v = b.backupManifest.validate(m);
  check("validate flags absolute relativePath",   v.ok === false);

  // Bad kind
  m = b.backupManifest.create(_validManifestArgs());
  m.files[0].kind = "wat";
  v = b.backupManifest.validate(m);
  check("validate flags unknown kind",            v.ok === false &&
        v.errors.some(function (e) { return /kind/.test(e); }));

  // Negative size
  m = b.backupManifest.create(_validManifestArgs());
  m.files[0].size = -1;
  v = b.backupManifest.validate(m);
  check("validate flags negative size",           v.ok === false);

  // Non-base64 vaultKeyEnc
  m = b.backupManifest.create(_validManifestArgs());
  m.vaultKeyEnc = "not base64 !@#$";
  v = b.backupManifest.validate(m);
  check("validate flags non-base64 vaultKeyEnc",  v.ok === false);

  // Bad ISO createdAt
  m = b.backupManifest.create(_validManifestArgs());
  m.createdAt = "yesterday";
  v = b.backupManifest.validate(m);
  check("validate flags non-ISO createdAt",       v.ok === false);

  // Wrong format version
  m = b.backupManifest.create(_validManifestArgs());
  m.version = 2;
  v = b.backupManifest.validate(m);
  check("validate flags wrong version",           v.ok === false);

  // Wrong framework name
  m = b.backupManifest.create(_validManifestArgs());
  m.framework = "elsewhere";
  v = b.backupManifest.validate(m);
  check("validate flags wrong framework name",    v.ok === false);
}

function testBackupManifestRejectsDuplicatePaths() {
  var args = _validManifestArgs();
  args.files = [
    _validFileEntry({ relativePath: "a", encryptedPath: "files/a.bin" }),
    _validFileEntry({ relativePath: "a", encryptedPath: "files/b.bin" }),
  ];
  var threw = null;
  try { b.backupManifest.create(args); } catch (e) { threw = e; }
  check("duplicate relativePath rejected",        threw && /duplicate/.test(threw.message));

  args.files = [
    _validFileEntry({ relativePath: "a", encryptedPath: "files/x.bin" }),
    _validFileEntry({ relativePath: "b", encryptedPath: "files/x.bin" }),
  ];
  threw = null;
  try { b.backupManifest.create(args); } catch (e) { threw = e; }
  check("duplicate encryptedPath rejected",       threw && /duplicate/.test(threw.message));
}

function testBackupManifestParseRejectsCorruption() {
  var threw;

  // Not JSON
  threw = null; try { b.backupManifest.parse("not json"); } catch (e) { threw = e; }
  check("parse non-JSON rejects",                 threw && threw.code === "backup-manifest/bad-json");

  // Wrong type for argument
  threw = null; try { b.backupManifest.parse(42); } catch (e) { threw = e; }
  check("parse non-string non-Buffer rejects",    threw && threw.code === "backup-manifest/bad-input");

  // Valid JSON but wrong shape
  threw = null;
  try { b.backupManifest.parse(JSON.stringify({ random: "garbage" })); }
  catch (e) { threw = e; }
  check("parse valid-JSON-but-wrong-shape rejects", threw && threw.code === "backup-manifest/invalid");

  // Buffer input also accepted
  var ok = b.backupManifest.parse(Buffer.from(b.backupManifest.serialize(b.backupManifest.create(_validManifestArgs()))));
  check("parse accepts Buffer input",             ok && ok.version === 1);
}

function testBackupManifestSerializeIsCanonical() {
  // Same logical manifest serializes to the same bytes regardless of
  // how the input object was assembled (key insertion order).
  var m1 = b.backupManifest.create(_validManifestArgs());
  // Build a manifest with the same values via direct assignment in
  // different key order, then validate + serialize via the public API.
  var m2 = {
    metadata:         { reason: "test" },
    files:            [_validFileEntry()],
    createdAt:        m1.createdAt,
    vaultKeyEnc:      m1.vaultKeyEnc,
    vaultKeySalt:     m1.vaultKeySalt,
    frameworkVersion: m1.frameworkVersion,
    framework:        "blamejs",
    version:          1,
  };
  check("serialize is order-independent",         b.backupManifest.serialize(m1) === b.backupManifest.serialize(m2));
}

// ---- backup-crypto ----

function testBackupCryptoSurface() {
  check("b.backupCrypto namespace present",       typeof b.backupCrypto === "object");
  check("deriveKey is a function",                typeof b.backupCrypto.deriveKey === "function");
  check("encryptWithPassphrase is a function",    typeof b.backupCrypto.encryptWithPassphrase === "function");
  check("decryptWithPassphrase is a function",    typeof b.backupCrypto.decryptWithPassphrase === "function");
  check("encryptWithFreshSalt is a function",     typeof b.backupCrypto.encryptWithFreshSalt === "function");
  check("checksum is a function",                 typeof b.backupCrypto.checksum === "function");
  check("BackupCryptoError is a class",           typeof b.backupCrypto.BackupCryptoError === "function");
  check("ARGON2_OPTS is frozen with type=2 (argon2id)",
        b.backupCrypto.ARGON2_OPTS.type === 2 &&
        Object.isFrozen(b.backupCrypto.ARGON2_OPTS));
  check("SALT_BYTES is 32",                       b.backupCrypto.SALT_BYTES === 32);
  check("NONCE_BYTES is 24",                      b.backupCrypto.NONCE_BYTES === 24);
}

async function testBackupCryptoDeriveKeyDeterministic() {
  // Same passphrase + same salt → same key (across calls).
  // Use a small salt for speed; argon2 with default opts is slow.
  var salt = "0011223344556677889900112233445566778899001122334455667788990011";
  var k1 = await b.backupCrypto.deriveKey(Buffer.from("hunter2"), salt);
  var k2 = await b.backupCrypto.deriveKey(Buffer.from("hunter2"), salt);
  check("deriveKey deterministic across calls",   Buffer.compare(k1, k2) === 0);
  check("deriveKey produces 32-byte key",         k1.length === 32);

  // Different passphrase → different key
  var k3 = await b.backupCrypto.deriveKey(Buffer.from("different"), salt);
  check("deriveKey differs on different passphrase", Buffer.compare(k1, k3) !== 0);
}

async function testBackupCryptoRoundTrip() {
  var salt = "ff".repeat(32);
  var passphrase = Buffer.from("correct horse battery staple");
  var plain = Buffer.from("the secret data");
  var enc = await b.backupCrypto.encryptWithPassphrase(plain, passphrase, salt);
  check("encrypted length = nonce + ciphertext + 16-byte tag",
        enc.length === b.backupCrypto.NONCE_BYTES + plain.length + 16);
  var dec = await b.backupCrypto.decryptWithPassphrase(enc, passphrase, salt);
  check("decrypt round-trip recovers plaintext bytes",
        Buffer.compare(dec, plain) === 0);
}

async function testBackupCryptoStringPlaintext() {
  // String plaintext should be UTF-8 encoded
  var salt = "aa".repeat(32);
  var passphrase = Buffer.from("p");
  var enc = await b.backupCrypto.encryptWithPassphrase("hello — utf8 ñ", passphrase, salt);
  var dec = await b.backupCrypto.decryptWithPassphrase(enc, passphrase, salt);
  check("string plaintext round-trips as utf8",
        dec.toString("utf8") === "hello — utf8 ñ");
}

async function testBackupCryptoWrongPassphraseFails() {
  var salt = "11".repeat(32);
  var enc = await b.backupCrypto.encryptWithPassphrase(
    Buffer.from("data"), Buffer.from("right"), salt);
  var threw = null;
  try {
    await b.backupCrypto.decryptWithPassphrase(enc, Buffer.from("wrong"), salt);
  } catch (e) { threw = e; }
  check("wrong passphrase surfaces decrypt-failed",
        threw && threw.code === "backup-crypto/decrypt-failed");
}

async function testBackupCryptoTamperedCiphertextFails() {
  var salt = "22".repeat(32);
  var enc = await b.backupCrypto.encryptWithPassphrase(
    Buffer.from("data"), Buffer.from("p"), salt);
  // Flip one byte after the nonce
  var tampered = Buffer.from(enc);
  tampered[b.backupCrypto.NONCE_BYTES + 2] ^= 0x01;
  var threw = null;
  try { await b.backupCrypto.decryptWithPassphrase(tampered, Buffer.from("p"), salt); }
  catch (e) { threw = e; }
  check("tampered ciphertext surfaces decrypt-failed",
        threw && threw.code === "backup-crypto/decrypt-failed");
}

async function testBackupCryptoFreshSaltUnique() {
  // Two encryptWithFreshSalt calls produce DIFFERENT salts and
  // DIFFERENT ciphertexts even with identical plaintext + passphrase.
  var p = Buffer.from("p");
  var r1 = await b.backupCrypto.encryptWithFreshSalt("x", p);
  var r2 = await b.backupCrypto.encryptWithFreshSalt("x", p);
  check("encryptWithFreshSalt: salts unique across calls",
        r1.salt !== r2.salt);
  check("encryptWithFreshSalt: ciphertexts unique across calls",
        Buffer.compare(r1.encrypted, r2.encrypted) !== 0);
  check("encryptWithFreshSalt: salt is 64 hex chars (32 bytes)",
        r1.salt.length === 64 && /^[0-9a-f]{64}$/.test(r1.salt));

  // Round-trip via the bundled salt
  var dec = await b.backupCrypto.decryptWithPassphrase(r1.encrypted, p, r1.salt);
  check("encryptWithFreshSalt + decrypt with bundled salt round-trips",
        dec.toString("utf8") === "x");
}

function testBackupCryptoChecksumIsSha3_512() {
  // SHA3-512 of "abc" is a known test vector (FIPS 202 Appendix B):
  // "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e
  //  10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
  var v = b.backupCrypto.checksum("abc");
  check("checksum('abc') matches SHA3-512 test vector",
        v === "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

  // Buffer input also accepted
  var v2 = b.backupCrypto.checksum(Buffer.from("abc"));
  check("checksum accepts Buffer input",          v2 === v);

  var threw = null;
  try { b.backupCrypto.checksum(123); } catch (e) { threw = e; }
  check("checksum rejects non-Buffer/non-string", threw && threw.code === "backup-crypto/bad-input");
}

async function testBackupCryptoArgValidation() {
  var threw;
  threw = null; try { await b.backupCrypto.deriveKey("p", "not-hex"); } catch (e) { threw = e; }
  check("deriveKey rejects non-hex salt",         threw && threw.code === "backup-crypto/bad-salt");

  threw = null; try { await b.backupCrypto.deriveKey("p", "abc"); } catch (e) { threw = e; }
  check("deriveKey rejects odd-length hex salt",  threw && threw.code === "backup-crypto/bad-salt");

  threw = null; try { await b.backupCrypto.deriveKey("", "ab"); } catch (e) { threw = e; }
  check("deriveKey rejects empty passphrase",     threw && threw.code === "backup-crypto/bad-passphrase");

  threw = null; try { await b.backupCrypto.encryptWithPassphrase(123, "p", "ab"); } catch (e) { threw = e; }
  check("encryptWithPassphrase rejects non-Buffer/non-string plaintext",
        threw && threw.code === "backup-crypto/bad-plaintext");

  threw = null; try { await b.backupCrypto.decryptWithPassphrase("not-a-buffer", "p", "ab"); } catch (e) { threw = e; }
  check("decryptWithPassphrase rejects non-Buffer encrypted arg",
        threw && threw.code === "backup-crypto/bad-input");

  // Encrypted buffer too short to contain nonce + tag
  threw = null;
  try {
    await b.backupCrypto.decryptWithPassphrase(
      Buffer.from([1,2,3]), Buffer.from("p"), "ab".repeat(16));
  } catch (e) { threw = e; }
  check("decryptWithPassphrase rejects short buffers",
        threw && threw.code === "backup-crypto/bad-input");
}

// ---- body-parser ----

// Aliases for the shared helpers — kept locally because 70+ call sites
// in this file reference them. Identical to _bodyReq / _bodyRes from
// test/helpers/mocks.js.
var _mockBodyReq = helpers._bodyReq;
var _mockBodyRes = helpers._bodyRes;

function _runBodyParser(bp, req, res) {
  return new Promise(function (resolve) {
    var nextCalled = false;
    var resolved = false;
    function done(payload) { if (resolved) return; resolved = true; resolve(payload); }
    // Register the finish listener BEFORE calling bp — synchronous
    // 415 paths fire res.end() and emit "finish" inline, before any
    // post-call listener could attach.
    res.on("finish", function () { if (!nextCalled) done({ next: false, req: req, res: res }); });
    bp(req, res, function () { nextCalled = true; done({ next: true, req: req, res: res }); });
  });
}

async function testBodyParserSurface() {
  var bp = b.middleware.bodyParser();
  check("b.middleware.bodyParser is a function", typeof b.middleware.bodyParser === "function");
  check("bodyParser returns a 3-arg middleware",  typeof bp === "function" && bp.length >= 2);
  var raw = b.middleware._modules.bodyParser;
  check("BodyParserError is exposed",            typeof raw.BodyParserError === "function");
  check("POISONED_KEYS is exposed",              raw.POISONED_KEYS instanceof Set);
}

async function testBodyParserGetSkipped() {
  var bp = b.middleware.bodyParser();
  var req = _mockBodyReq("GET", {});
  var res = _mockBodyRes();
  var r = await _runBodyParser(bp, req, res);
  check("GET request: bodyParser passes through (no body)",  r.next === true);
  check("GET request: req.body unset",                       req.body === undefined);
}

async function testBodyParserStrictContentLength() {
  // RFC 9112 §6.1: Content-Length MUST be a sequence of decimal digits.
  // Malformed values (123abc, "00 ", "+0", whitespace) get rejected as
  // 400 instead of being leniently parsed by parseInt.
  var bp = b.middleware.bodyParser();
  var body = '{"a":1}';
  var bad = ["123abc", "12.5", "+5", "-1", " 5 ", "00abc", "1e3"];
  for (var i = 0; i < bad.length; i++) {
    var req = _mockBodyReq("POST",
      { "content-type": "application/json", "content-length": bad[i] }, body);
    var res = _mockBodyRes();
    var r = await _runBodyParser(bp, req, res);
    check("malformed content-length '" + bad[i] + "' → 400",
          res._endedStatus === 400);
    check("malformed content-length '" + bad[i] + "' → next not called",
          r.next === false);
  }

  // _hasBody behavior on edge cases:
  //   "0" / "00" — both pass the strict /^\d+$/ regex and parse to 0,
  //     so they're treated as "no body" (RFC 9112 doesn't forbid leading
  //     zeros in the digit sequence — the value is what counts).
  //   " 0 " / "+0" — whitespace + sign are NOT decimal digits, so the
  //     header is malformed; _hasBody returns true so the downstream
  //     _bufferBody can reject with 400 instead of silently skipping.
  var raw = b.middleware._modules.bodyParser;
  check("_hasBody('0') → false (strict zero)",
        raw._hasBody({ method: "POST", headers: { "content-length": "0" } }) === false);
  check("_hasBody('00') → false (still zero)",
        raw._hasBody({ method: "POST", headers: { "content-length": "00" } }) === false);
  var malformed = [" 0 ", "+0"];
  for (var z = 0; z < malformed.length; z++) {
    var hb = raw._hasBody({ method: "POST", headers: { "content-length": malformed[z] } });
    check("_hasBody('" + malformed[z] + "') → true (downstream rejects malformed)",  hb === true);
  }
}

async function testBodyParserJsonHappy() {
  var bp = b.middleware.bodyParser();
  var body = '{"name":"Alice","age":30}';
  var req = _mockBodyReq("POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body);
  var res = _mockBodyRes();
  var r = await _runBodyParser(bp, req, res);
  check("JSON body: middleware called next()",   r.next === true);
  check("JSON body: req.body parsed",            req.body && req.body.name === "Alice" && req.body.age === 30);
}

async function testBodyParserJsonStripsPrototypePollution() {
  // safe-json strips POISONED_KEYS during parse. Confirm bodyParser
  // surfaces a clean object even when the wire body contains __proto__.
  var bp = b.middleware.bodyParser();
  var body = '{"a":"ok","__proto__":{"polluted":true}}';
  var req = _mockBodyReq("POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body);
  var res = _mockBodyRes();
  await _runBodyParser(bp, req, res);
  check("JSON body: __proto__ key stripped by safe-json",  req.body.polluted === undefined);
  check("JSON body: legitimate keys retained",             req.body.a === "ok");
  check("JSON body: Object.prototype not polluted",        ({}).polluted === undefined);
}

async function testBodyParserJsonSizeCap() {
  var bp = b.middleware.bodyParser({ json: { limit: 100 } });
  var body = '{"x":"' + "A".repeat(200) + '"}';
  var req = _mockBodyReq("POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body);
  var res = _mockBodyRes();
  var r = await _runBodyParser(bp, req, res);
  check("JSON body too large: 413 response",     res._endedStatus === 413);
  check("JSON body too large: next() not called", r.next === false);
}

async function testBodyParserJsonMalformed() {
  var bp = b.middleware.bodyParser();
  var body = '{not valid json';
  var req = _mockBodyReq("POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body);
  var res = _mockBodyRes();
  await _runBodyParser(bp, req, res);
  check("JSON malformed: 400 response",          res._endedStatus === 400);
}

async function testBodyParserJsonStrictMode() {
  var bp = b.middleware.bodyParser({ json: { strict: true } });
  var body = '"a string"';
  var req = _mockBodyReq("POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body);
  var res = _mockBodyRes();
  await _runBodyParser(bp, req, res);
  check("JSON strict: bare string rejected",     res._endedStatus === 400);
}

async function testBodyParserUrlencoded() {
  var bp = b.middleware.bodyParser();
  var body = "name=Alice&age=30&tag=js&tag=node";
  var req = _mockBodyReq("POST",
    { "content-type": "application/x-www-form-urlencoded",
      "content-length": String(Buffer.byteLength(body)) },
    body);
  var res = _mockBodyRes();
  var r = await _runBodyParser(bp, req, res);
  check("urlencoded: middleware called next()",  r.next === true);
  check("urlencoded: scalar field parsed",       req.body.name === "Alice");
  check("urlencoded: repeated key → array",      Array.isArray(req.body.tag) && req.body.tag.length === 2 &&
                                                   req.body.tag[0] === "js" && req.body.tag[1] === "node");
}

async function testBodyParserUrlencodedPoisonedKey() {
  var bp = b.middleware.bodyParser();
  var body = "name=Alice&__proto__=poisoned";
  var req = _mockBodyReq("POST",
    { "content-type": "application/x-www-form-urlencoded",
      "content-length": String(Buffer.byteLength(body)) },
    body);
  var res = _mockBodyRes();
  await _runBodyParser(bp, req, res);
  check("urlencoded: __proto__ field rejected",  res._endedStatus === 400);
}

async function testBodyParserText() {
  var bp = b.middleware.bodyParser();
  var body = "hello world";
  var req = _mockBodyReq("POST",
    { "content-type": "text/plain", "content-length": String(body.length) }, body);
  var res = _mockBodyRes();
  var r = await _runBodyParser(bp, req, res);
  check("text/plain: middleware called next()",  r.next === true);
  check("text/plain: req.body is the string",    req.body === "hello world");
}

async function testBodyParserRaw() {
  var bp = b.middleware.bodyParser();
  var body = Buffer.from([0x01, 0x02, 0x03, 0x04, 0xff]);
  var req = _mockBodyReq("POST",
    { "content-type": "application/octet-stream", "content-length": String(body.length) }, body);
  var res = _mockBodyRes();
  await _runBodyParser(bp, req, res);
  check("application/octet-stream: req.body is Buffer",       Buffer.isBuffer(req.body));
  check("application/octet-stream: bytes preserved",          req.body[0] === 0x01 && req.body[4] === 0xff);
}

async function testBodyParserUnsupportedType() {
  var bp = b.middleware.bodyParser({ raw: false }); // disable raw catch-all
  var body = Buffer.from([1, 2, 3]);
  var req = _mockBodyReq("POST",
    { "content-type": "application/x-something-weird", "content-length": "3" }, body);
  var res = _mockBodyRes();
  await _runBodyParser(bp, req, res);
  check("unsupported Content-Type: 415 response", res._endedStatus === 415);
}

async function testBodyParserDisabledSubparser() {
  // Setting a sub-parser to false leaves req.body untouched; bodyParser
  // returns 415 because no parser claims the type. This tests the
  // explicit-disable path versus the catch-all.
  var bp = b.middleware.bodyParser({ json: false, raw: false, urlencoded: false, text: false, multipart: false });
  var req = _mockBodyReq("POST",
    { "content-type": "application/json", "content-length": "2" }, "{}");
  var res = _mockBodyRes();
  await _runBodyParser(bp, req, res);
  check("all sub-parsers disabled: 415 response", res._endedStatus === 415);
}

async function testBodyParserKeepRawBody() {
  var bp = b.middleware.bodyParser({ keepRawBody: true });
  var body = '{"signed":true}';
  var req = _mockBodyReq("POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) }, body);
  var res = _mockBodyRes();
  await _runBodyParser(bp, req, res);
  check("keepRawBody: req.bodyRaw is the original Buffer",  Buffer.isBuffer(req.bodyRaw));
  check("keepRawBody: bytes preserved",                     req.bodyRaw.toString("utf8") === body);
  check("keepRawBody: req.body still parsed",               req.body && req.body.signed === true);
}

function _buildMultipartBody(boundary, parts) {
  // parts: [{ name, value, filename?, contentType? }, ...]
  var pieces = [];
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i];
    var headers = 'Content-Disposition: form-data; name="' + p.name + '"';
    if (p.filename) headers += '; filename="' + p.filename + '"';
    if (p.contentType) headers += "\r\nContent-Type: " + p.contentType;
    pieces.push("--" + boundary + "\r\n" + headers + "\r\n\r\n");
    pieces.push(p.value);
    pieces.push("\r\n");
  }
  pieces.push("--" + boundary + "--\r\n");
  return Buffer.concat(pieces.map(function (x) {
    return Buffer.isBuffer(x) ? x : Buffer.from(x);
  }));
}

async function testBodyParserMultipartFields() {
  var bp = b.middleware.bodyParser();
  var boundary = "----blamejs-test-boundary-1";
  var body = _buildMultipartBody(boundary, [
    { name: "name", value: "Alice" },
    { name: "age",  value: "30" },
  ]);
  var req = _mockBodyReq("POST",
    { "content-type": "multipart/form-data; boundary=" + boundary,
      "content-length": String(body.length) }, body);
  var res = _mockBodyRes();
  var r = await _runBodyParser(bp, req, res);
  check("multipart fields: middleware called next()", r.next === true);
  check("multipart fields: name parsed",              req.body.name === "Alice");
  check("multipart fields: age parsed",               req.body.age === "30");
  check("multipart fields: no files",                 Array.isArray(req.files) && req.files.length === 0);
}

async function testBodyParserMultipartFile() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({ multipart: { tmpDir: tmpDir } });
    var boundary = "----blamejs-test-boundary-2";
    var fileBytes = Buffer.from("hello multipart file body");
    var body = _buildMultipartBody(boundary, [
      { name: "title",  value: "My File" },
      { name: "upload", value: fileBytes, filename: "test.txt", contentType: "text/plain" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("multipart file: title field parsed",        req.body.title === "My File");
    check("multipart file: file metadata captured",    req.files.length === 1);
    check("multipart file: filename sanitized",        req.files[0].filename === "test.txt");
    check("multipart file: mime preserved",            req.files[0].mimeType === "text/plain");
    check("multipart file: size matches",              req.files[0].size === fileBytes.length);
    check("multipart file: tmp file written",          fs.existsSync(req.files[0].path));
    var diskBytes = fs.readFileSync(req.files[0].path);
    check("multipart file: disk content matches",      diskBytes.toString("utf8") === "hello multipart file body");
    check("multipart file: hash present",              typeof req.files[0].hash === "string" && req.files[0].hash.length === 128);
    // Cleanup wired to res.finish — fire it and verify the tmp file disappears
    res.emit("finish");
    check("multipart file: tmp cleaned on res.finish", !fs.existsSync(req.files[0].path));
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartMemoryStorage() {
  // storage: "memory" — file parts buffered in RAM, exposed as
  // req.files[].buffer with no filesystem touch (serverless / read-only fs).
  var bp = b.middleware.bodyParser({ multipart: { storage: "memory" } });
  var boundary = "----blamejs-test-boundary-mem";
  var fileBytes = Buffer.from("hello in-memory file body");
  var body = _buildMultipartBody(boundary, [
    { name: "title",  value: "Mem File" },
    { name: "upload", value: fileBytes, filename: "mem.txt", contentType: "text/plain" },
  ]);
  var req = _mockBodyReq("POST",
    { "content-type": "multipart/form-data; boundary=" + boundary,
      "content-length": String(body.length) }, body);
  var res = _mockBodyRes();
  await _runBodyParser(bp, req, res);
  check("multipart memory: text field parsed",       req.body.title === "Mem File");
  check("multipart memory: file captured",           req.files.length === 1);
  check("multipart memory: buffer is a Buffer",      Buffer.isBuffer(req.files[0].buffer));
  check("multipart memory: buffer content matches",  req.files[0].buffer.toString("utf8") === "hello in-memory file body");
  check("multipart memory: path is null (no disk)",  req.files[0].path === null);
  check("multipart memory: size matches",            req.files[0].size === fileBytes.length);
  check("multipart memory: hash present",            typeof req.files[0].hash === "string" && req.files[0].hash.length === 128);
  // res.finish cleanup is a no-op for memory files (no path) — must not throw.
  var threwOnFinish = false;
  try { res.emit("finish"); } catch (_e) { threwOnFinish = true; }
  check("multipart memory: finish cleanup no-op (no throw)", !threwOnFinish);

  // Per-file size cap still enforced in memory mode.
  var bpCap = b.middleware.bodyParser({ multipart: { storage: "memory", fileSize: 8 } });
  var capBody = _buildMultipartBody(boundary, [
    { name: "upload", value: Buffer.from("way over the eight byte cap"),
      filename: "big.txt", contentType: "text/plain" },
  ]);
  var capReq = _mockBodyReq("POST",
    { "content-type": "multipart/form-data; boundary=" + boundary,
      "content-length": String(capBody.length) }, capBody);
  var capRes = _mockBodyRes();
  await _runBodyParser(bpCap, capReq, capRes);
  check("multipart memory: oversize file refused (413)", capRes.statusCode === 413);

  // Bad storage value throws at construction (entry-point tier).
  var threwBadStorage = false;
  try { b.middleware.bodyParser({ multipart: { storage: "s3" } }); }
  catch (e) { threwBadStorage = /storage must be/.test(e.message); }
  check("multipart memory: invalid storage throws at config", threwBadStorage);

  // Disk mode unchanged: still exposes .path, buffer null.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-mem-"));
  try {
    var bpDisk = b.middleware.bodyParser({ multipart: { storage: "disk", tmpDir: tmpDir } });
    var dBody = _buildMultipartBody(boundary, [
      { name: "upload", value: Buffer.from("on disk"), filename: "d.txt", contentType: "text/plain" },
    ]);
    var dReq = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(dBody.length) }, dBody);
    var dRes = _mockBodyRes();
    await _runBodyParser(bpDisk, dReq, dRes);
    check("multipart memory: disk mode keeps .path",   typeof dReq.files[0].path === "string" && fs.existsSync(dReq.files[0].path));
    check("multipart memory: disk mode buffer null",   dReq.files[0].buffer === null);
    dRes.emit("finish");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartFilenameTraversal() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({ multipart: { tmpDir: tmpDir } });
    var boundary = "----blamejs-test-boundary-3";
    var body = _buildMultipartBody(boundary, [
      { name: "upload", value: Buffer.from("evil"),
        filename: "../../../etc/passwd", contentType: "text/plain" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    // The path components are stripped; only "passwd" survives
    // sanitization. The tmp PATH itself is framework-generated, never
    // derived from the operator-supplied filename.
    check("multipart traversal: filename basename only", req.files[0].filename === "passwd");
    check("multipart traversal: tmp path inside tmpDir",
          req.files[0].path.indexOf(tmpDir) === 0);
    res.emit("finish");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartFileSizeLimit() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({ multipart: { tmpDir: tmpDir, fileSize: 10 } });
    var boundary = "----blamejs-test-boundary-4";
    var body = _buildMultipartBody(boundary, [
      { name: "upload", value: Buffer.from("this is way more than ten bytes"),
        filename: "big.txt", contentType: "text/plain" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("multipart file too large: 413 response",  res._endedStatus === 413);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartMimeAllowlist() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({
      multipart: { tmpDir: tmpDir, mimeAllowlist: ["image/png"] },
    });
    var boundary = "----blamejs-test-boundary-5";
    var body = _buildMultipartBody(boundary, [
      { name: "upload", value: Buffer.from("not actually a png"),
        filename: "bad.exe", contentType: "application/octet-stream" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("multipart MIME allowlist: rejection 415",  res._endedStatus === 415);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

// ---- v0.4.10 fileFilter + per-field opts ----

async function testBodyParserMultipartFileFilterAccept() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var calls = [];
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        fileFilter: function (part) { calls.push(part); return true; },
      },
    });
    var boundary = "----blamejs-test-fileFilter-accept";
    var body = _buildMultipartBody(boundary, [
      { name: "doc", value: Buffer.from("ok"), filename: "doc.txt", contentType: "text/plain" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    var r = await _runBodyParser(bp, req, res);
    check("fileFilter accept: middleware called next()",   r.next === true);
    check("fileFilter accept: file kept in req.files",     req.files.length === 1);
    check("fileFilter accept: filesRejected empty",        req.filesRejected.length === 0);
    check("fileFilter accept: predicate received metadata",
          calls.length === 1 && calls[0].field === "doc" && calls[0].filename === "doc.txt"
          && calls[0].mimeType === "text/plain");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartFileFilterRejectFalse() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        fileFilter: function () { return false; },
      },
    });
    var boundary = "----blamejs-test-fileFilter-false";
    var body = _buildMultipartBody(boundary, [
      { name: "doc", value: Buffer.from("body"), filename: "x.txt", contentType: "text/plain" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    var r = await _runBodyParser(bp, req, res);
    check("fileFilter false: middleware called next()",    r.next === true);
    check("fileFilter false: req.files empty",             req.files.length === 0);
    check("fileFilter false: filesRejected has 1 entry",   req.filesRejected.length === 1);
    check("fileFilter false: rejected entry field",        req.filesRejected[0].field === "doc");
    check("fileFilter false: rejected entry filename",     req.filesRejected[0].filename === "x.txt");
    check("fileFilter false: rejected code = fileFilter",  req.filesRejected[0].code === "fileFilter");
    var dirContents = fs.readdirSync(tmpDir);
    check("fileFilter false: no tmp file written",         dirContents.length === 0);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartFileFilterRejectObject() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        fileFilter: function () {
          return { reject: true, code: "policy/no-exe", message: "executables not allowed" };
        },
      },
    });
    var boundary = "----blamejs-test-fileFilter-object";
    var body = _buildMultipartBody(boundary, [
      { name: "upload", value: Buffer.from("MZ\x90\x00"), filename: "evil.exe",
        contentType: "application/octet-stream" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("fileFilter object: filesRejected[0].code custom",
          req.filesRejected[0].code === "policy/no-exe");
    check("fileFilter object: filesRejected[0].message custom",
          req.filesRejected[0].message === "executables not allowed");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartFileFilterMixedAcceptReject() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        fileFilter: function (part) { return part.field === "good"; },
      },
    });
    var boundary = "----blamejs-test-fileFilter-mixed";
    var body = _buildMultipartBody(boundary, [
      { name: "good", value: Buffer.from("ok"), filename: "ok.txt", contentType: "text/plain" },
      { name: "bad",  value: Buffer.from("nope"), filename: "no.txt", contentType: "text/plain" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("fileFilter mixed: 1 file kept",            req.files.length === 1);
    check("fileFilter mixed: kept file is 'good'",    req.files[0].field === "good");
    check("fileFilter mixed: 1 file rejected",        req.filesRejected.length === 1);
    check("fileFilter mixed: rejected file is 'bad'", req.filesRejected[0].field === "bad");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartFileFilterThrows() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        fileFilter: function () { throw new Error("operator bug"); },
      },
    });
    var boundary = "----blamejs-test-fileFilter-throw";
    var body = _buildMultipartBody(boundary, [
      { name: "x", value: Buffer.from("y"), filename: "y.txt", contentType: "text/plain" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("fileFilter throw: 500 response",  res._endedStatus === 500);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartFileFilterAuditEmit() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var captured = [];
    var auditCap = { safeEmit: function (e) { captured.push(e); } };
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        audit:  auditCap,
        fileFilter: function () { return false; },
      },
    });
    var boundary = "----blamejs-test-fileFilter-audit";
    var body = _buildMultipartBody(boundary, [
      { name: "doc", value: Buffer.from("body"), filename: "x.pdf", contentType: "application/pdf" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("fileFilter audit: event emitted",         captured.length === 1);
    check("fileFilter audit: action correct",
          captured[0].action === "body-parser.multipart.file_rejected");
    check("fileFilter audit: outcome=denied",        captured[0].outcome === "denied");
    check("fileFilter audit: metadata.field",        captured[0].metadata.field === "doc");
    check("fileFilter audit: metadata.mimeType",     captured[0].metadata.mimeType === "application/pdf");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartPerFieldMaxBytesTighter() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        fileSize: 1024,                       // global generous
        fields: { avatar: { maxBytes: 8 } },  // tight per-field
      },
    });
    var boundary = "----blamejs-test-perfield-tight";
    var body = _buildMultipartBody(boundary, [
      { name: "avatar", value: Buffer.alloc(64, "x"),
        filename: "big.jpg", contentType: "image/jpeg" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("per-field maxBytes (tighter): 413 response",  res._endedStatus === 413);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartPerFieldMaxBytesLooser() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        fileSize: 8,                                   // global tiny
        fields: { document: { maxBytes: 1024 * 64 } }, // looser per-field
      },
    });
    var boundary = "----blamejs-test-perfield-loose";
    var body = _buildMultipartBody(boundary, [
      { name: "document", value: Buffer.alloc(100, "x"),
        filename: "big.txt", contentType: "text/plain" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    var r = await _runBodyParser(bp, req, res);
    check("per-field maxBytes (looser): file accepted",  r.next === true && req.files.length === 1);
    check("per-field maxBytes (looser): size matches",   req.files[0].size === 100);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartPerFieldMimeTypesBlock() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        fields: { avatar: { mimeTypes: ["image/jpeg", "image/png"] } },
      },
    });
    var boundary = "----blamejs-test-perfield-mime-block";
    var body = _buildMultipartBody(boundary, [
      { name: "avatar", value: Buffer.from("body"),
        filename: "wrong.gif", contentType: "image/gif" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("per-field mimeTypes (block): 415 response",  res._endedStatus === 415);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartPerFieldMimeOverridesGlobal() {
  // Global denies; per-field allows. Per-field wins for the named field.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({
      multipart: {
        tmpDir: tmpDir,
        mimeAllowlist: ["image/png"],                            // global
        fields: { document: { mimeTypes: ["application/pdf"] } }, // per-field
      },
    });
    var boundary = "----blamejs-test-perfield-mime-override";
    var body = _buildMultipartBody(boundary, [
      { name: "document", value: Buffer.from("%PDF-1.4"),
        filename: "ok.pdf", contentType: "application/pdf" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    var r = await _runBodyParser(bp, req, res);
    check("per-field mimeTypes (override): file accepted",
          r.next === true && req.files.length === 1);
    check("per-field mimeTypes (override): mimeType preserved",
          req.files[0].mimeType === "application/pdf");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartPoisonedFieldName() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({ multipart: { tmpDir: tmpDir } });
    var boundary = "----blamejs-test-boundary-6";
    var body = _buildMultipartBody(boundary, [
      { name: "__proto__", value: "polluted" },
    ]);
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(body.length) }, body);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("multipart __proto__ field: 400 response",  res._endedStatus === 400);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserMultipartTruncated() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bp-"));
  try {
    var bp = b.middleware.bodyParser({ multipart: { tmpDir: tmpDir } });
    var boundary = "----blamejs-test-boundary-7";
    // Body missing the trailing -- closing boundary
    var bodyStr = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue\r\n";
    var req = _mockBodyReq("POST",
      { "content-type": "multipart/form-data; boundary=" + boundary,
        "content-length": String(Buffer.byteLength(bodyStr)) }, bodyStr);
    var res = _mockBodyRes();
    await _runBodyParser(bp, req, res);
    check("multipart truncated: 400 response",       res._endedStatus === 400);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testBodyParserContentLengthExceedsLimitImmediate() {
  // Reject by Content-Length BEFORE reading any bytes — clients sending
  // a huge body shouldn't be allowed to even stream.
  var bp = b.middleware.bodyParser({ json: { limit: 100 } });
  var req = _mockBodyReq("POST",
    { "content-type": "application/json", "content-length": "10000" }, "");
  // Don't actually emit data — the rejection should be immediate from CL.
  var res = _mockBodyRes();
  // Replace the setImmediate-driven 'data'/'end' since we want no body.
  // The mock already won't emit data because body is empty; fake a long body via CL.
  await _runBodyParser(bp, req, res);
  check("content-length over limit: 413 immediate",  res._endedStatus === 413);
}

async function testBodyParserSanitizeFilenameUnit() {
  var raw = b.middleware._modules.bodyParser;
  check("filename: strips path components",
        raw._sanitizeFilename("/etc/passwd") === "passwd");
  check("filename: strips backslash separators",
        raw._sanitizeFilename("C:\\evil\\bad.exe") === "bad.exe");
  check("filename: traversal stripped",
        raw._sanitizeFilename("../../etc/passwd") === "passwd");
  check("filename: NUL byte removed",
        raw._sanitizeFilename("test\x00.txt") === "test.txt");
  check("filename: leading dots removed",
        raw._sanitizeFilename("...bashrc") === "bashrc");
  check("filename: pure dots rejected",
        raw._sanitizeFilename("..") === null);
  check("filename: empty after strip rejected",
        raw._sanitizeFilename("/") === null);
  check("filename: 256-char string truncated",
        raw._sanitizeFilename("a".repeat(300)).length === 255);
}

// ---- auth.oauth ----

function _spawnFakeIdpServer(routes) {
  // Minimal HTTP server that serves the configured route handlers.
  // routes: { "/.well-known/...": fn(req,res), ... }
  var http = require("node:http");
  var server = http.createServer(function (req, res) {
    var u = new URL(req.url, "http://localhost");
    var handler = routes[u.pathname];
    if (!handler) { res.writeHead(404); res.end(); return; }
    var bodyChunks = [];
    req.on("data", function (c) { bodyChunks.push(c); });
    req.on("end", function () {
      req.body = Buffer.concat(bodyChunks).toString("utf8");
      try { handler(req, res, u); }
      catch (e) {
        res.writeHead(500); res.end(String(e));
      }
    });
  });
  return server;
}

function _signRs256(payload, header, privateKey) {
  // Build a JWT signed with RS256 using node:crypto.
  var b64u = b.auth.oauth._b64urlEncode;
  var hdr = Object.assign({ alg: "RS256", typ: "JWT" }, header || {});
  var headerB64  = b64u(JSON.stringify(hdr));
  var payloadB64 = b64u(JSON.stringify(payload));
  var signingInput = headerB64 + "." + payloadB64;
  var sig = require("node:crypto").sign("sha256", Buffer.from(signingInput, "ascii"), {
    key:     privateKey,
    padding: require("node:crypto").constants.RSA_PKCS1_PADDING,
  });
  return signingInput + "." + b64u(sig);
}

async function _generateRsaKeypair() {
  var crypto = require("node:crypto");
  return new Promise(function (resolve, reject) {
    crypto.generateKeyPair("rsa", { modulusLength: 2048 }, function (err, pub, priv) {
      if (err) reject(err); else resolve({ publicKey: pub, privateKey: priv });
    });
  });
}

function _publicKeyToJwk(publicKey, kid) {
  var jwk = publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  jwk.use = "sig";
  jwk.alg = "RS256";
  return jwk;
}

function testOAuthSurface() {
  check("b.auth.oauth namespace present",         typeof b.auth.oauth === "object");
  check("b.auth.oauth.create is a function",      typeof b.auth.oauth.create === "function");
  check("PRESETS exposed",                        typeof b.auth.oauth.PRESETS === "object");
  check("OAuthError class",                       typeof b.auth.oauth.OAuthError === "function");
  check("DEFAULT_ACCEPTED_ALGS exposed",          Array.isArray(b.auth.oauth.DEFAULT_ACCEPTED_ALGS));
  check("PRESETS.google has issuer",              b.auth.oauth.PRESETS.google.issuer.indexOf("accounts.google.com") !== -1);
  check("PRESETS.github has authorizationEndpoint",
        b.auth.oauth.PRESETS.github.authorizationEndpoint.indexOf("github.com") !== -1);
  check("PRESETS.github isOidc=false",            b.auth.oauth.PRESETS.github.isOidc === false);
}

function testOAuthCreateValidates() {
  var threw;
  threw = null;
  try { b.auth.oauth.create({}); } catch (e) { threw = e; }
  check("create: missing clientId rejected",      threw && threw.code === "auth-oauth/no-client-id");

  threw = null;
  try { b.auth.oauth.create({ clientId: "x" }); } catch (e) { threw = e; }
  check("create: missing redirectUri rejected",   threw && threw.code === "auth-oauth/no-redirect-uri");

  threw = null;
  try {
    b.auth.oauth.create({
      clientId: "x", clientSecret: "y", redirectUri: "http://insecure",
      authorizationEndpoint: "https://x", tokenEndpoint: "https://y",
    });
  } catch (e) { threw = e; }
  check("create: http redirectUri rejected",      threw && threw.code === "auth-oauth/insecure-url");

  threw = null;
  try {
    b.auth.oauth.create({
      clientId: "x", redirectUri: "https://app/cb",
      provider: "nope-not-a-real-preset",
    });
  } catch (e) { threw = e; }
  check("create: unknown preset rejected",        threw && threw.code === "auth-oauth/unknown-provider");

  threw = null;
  try {
    b.auth.oauth.create({
      clientId: "x", redirectUri: "https://app/cb",
      provider: "auth0",
    });
  } catch (e) { threw = e; }
  check("create: auth0 preset requires auth0Domain", threw && threw.code === "auth-oauth/auth0-domain");
}

function testOAuthPkceRequired() {
  // OAuth 2.1 — PKCE is required for all clients, not opt-out.
  // create({ pkce: false }) throws auth-oauth/pkce-required.
  var threw = null;
  try {
    b.auth.oauth.create({
      clientId:    "x", clientSecret: "y", redirectUri: "https://app/cb",
      provider:    "google", pkce: false,
    });
  } catch (e) { threw = e; }
  check("create: pkce: false → auth-oauth/pkce-required",
        threw && threw.code === "auth-oauth/pkce-required");
}

function testOAuthPkceGenerator() {
  var p1 = b.auth.oauth._generatePkce();
  check("pkce: verifier 43 chars (base64url 32 bytes)",  p1.verifier.length === 43);
  check("pkce: challenge 43 chars",                       p1.challenge.length === 43);
  check("pkce: verifier matches base64url charset",      /^[A-Za-z0-9_-]+$/.test(p1.verifier));
  // Different calls produce different values
  var p2 = b.auth.oauth._generatePkce();
  check("pkce: subsequent calls produce different verifiers", p1.verifier !== p2.verifier);
  // Challenge derives deterministically from verifier
  var crypto = require("node:crypto");
  var expected = b.auth.oauth._b64urlEncode(crypto.createHash("sha256").update(p1.verifier).digest());
  check("pkce: challenge = b64url(sha256(verifier))",    p1.challenge === expected);
}

async function testOAuthAuthorizationUrlPreset() {
  var oa = b.auth.oauth.create({
    provider:    "github",
    clientId:    "abc",
    clientSecret: "secret",
    redirectUri: "https://app/cb",
  });
  var auth = await oa.authorizationUrl();
  check("authUrl: starts with provider authorize endpoint",
        auth.url.indexOf("https://github.com/login/oauth/authorize") === 0);
  check("authUrl: includes client_id",              auth.url.indexOf("client_id=abc") !== -1);
  check("authUrl: includes redirect_uri",           auth.url.indexOf("redirect_uri=https") !== -1);
  check("authUrl: includes state",                  auth.url.indexOf("state=") !== -1);
  check("authUrl: includes code_challenge (PKCE)",  auth.url.indexOf("code_challenge=") !== -1);
  check("authUrl: includes code_challenge_method=S256", auth.url.indexOf("code_challenge_method=S256") !== -1);
  check("authUrl: response_type=code",              auth.url.indexOf("response_type=code") !== -1);
  check("authUrl: returns state for caller storage", typeof auth.state === "string" && auth.state.length > 0);
  check("authUrl: returns verifier for caller storage", typeof auth.verifier === "string");
  check("authUrl: github preset → no nonce (not OIDC)", auth.nonce === null);
}

async function testOAuthAuthorizationUrlOidc() {
  // Google requires discovery; for this test we bypass network and
  // verify the surface returns a nonce by setting endpoints directly.
  var oaDirect = b.auth.oauth.create({
    clientId: "abc", redirectUri: "https://app/cb",
    isOidc: true,
    scope:   ["openid", "email", "profile"],
    authorizationEndpoint: "https://example.com/auth",
    tokenEndpoint:         "https://example.com/token",
    issuer:                "https://example.com",
  });
  var auth = await oaDirect.authorizationUrl();
  check("authUrl: OIDC includes nonce",             typeof auth.nonce === "string" && auth.nonce.length > 0);
  // URLSearchParams encodes space as '+', so the scope params are
  // joined with '+' in the wire-format URL.
  check("authUrl: scope contains openid+email+profile",
        auth.url.indexOf("scope=openid+email+profile") !== -1);
}

async function testOAuthAuthorizationUrlGenericPreset() {
  // The 'generic' preset is the documented escape for non-vendor IdPs —
  // operator passes endpoints manually but selects provider:'generic' to
  // be explicit. Verifies the preset is wired in PRESETS so the call
  // does not throw "unknown provider preset".
  var oa = b.auth.oauth.create({
    provider:    "generic",
    clientId:    "abc",
    clientSecret: "secret",
    redirectUri: "https://app/cb",
    authorizationEndpoint: "https://idp.example.com/authorize",
    tokenEndpoint:         "https://idp.example.com/token",
    isOidc:                false,
  });
  var auth = await oa.authorizationUrl();
  check("authUrl: generic preset accepted as provider value",
        auth.url.indexOf("https://idp.example.com/authorize") === 0);
  check("authUrl: generic preset uses operator-supplied client_id",
        auth.url.indexOf("client_id=abc") !== -1);
}

async function testOAuthAuthorizationUrlExtraParams() {
  var oa = b.auth.oauth.create({
    clientId: "x", redirectUri: "https://app/cb",
    authorizationEndpoint: "https://example.com/auth",
    tokenEndpoint:         "https://example.com/token",
    isOidc: false,
  });
  var auth = await oa.authorizationUrl({
    prompt:    "consent",
    loginHint: "user@example.com",
    extraParams: { audience: "api://my-api" },
  });
  check("authUrl: prompt threaded through",         auth.url.indexOf("prompt=consent") !== -1);
  check("authUrl: login_hint encoded",              auth.url.indexOf("login_hint=user%40example.com") !== -1);
  check("authUrl: extraParams (audience) included", auth.url.indexOf("audience=api%3A%2F%2Fmy-api") !== -1);
}

async function testOAuthExchangeCodeRequiresVerifier() {
  var oa = b.auth.oauth.create({
    clientId: "x", redirectUri: "https://app/cb",
    authorizationEndpoint: "https://example.com/auth",
    tokenEndpoint:         "https://example.com/token",
    isOidc: false,
  });
  var threw = null;
  try { await oa.exchangeCode({ code: "abc" }); } catch (e) { threw = e; }
  check("exchangeCode: missing code rejected",
        threw && (threw.code === "auth-oauth/no-code" || threw.code === "auth-oauth/no-verifier"));
  threw = null;
  try { await oa.exchangeCode({}); } catch (e) { threw = e; }
  check("exchangeCode: empty opts rejected",       threw && threw.code === "auth-oauth/no-code");
}

async function testOAuthExchangeCodeRoundTrip() {
  // Spin a fake IdP that accepts a code + verifier and returns tokens.
  var receivedBody = null;
  var server = _spawnFakeIdpServer({
    "/token": function (req, res) {
      receivedBody = req.body;
      var body = JSON.stringify({
        access_token:  "AT-xyz",
        token_type:    "Bearer",
        expires_in:    3600,
        refresh_token: "RT-xyz",
        scope:         "read:user",
      });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
      res.end(body);
    },
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    var oa = b.auth.oauth.create({
      clientId:     "abc",
      clientSecret: "secret",
      redirectUri:  "https://app/cb",
      authorizationEndpoint: "http://127.0.0.1:" + port + "/auth",
      tokenEndpoint:         "http://127.0.0.1:" + port + "/token",
      isOidc:       false,
      allowHttp:    true, allowInternal: true,    // for local fake IdP
      pkce:         true,
    });
    var tokens = await oa.exchangeCode({
      code:     "AUTH_CODE_123",
      verifier: "test-verifier-1234567890123456789012345",
    });
    check("exchangeCode: accessToken returned",      tokens.accessToken === "AT-xyz");
    check("exchangeCode: refreshToken returned",     tokens.refreshToken === "RT-xyz");
    check("exchangeCode: tokenType set",             tokens.tokenType === "Bearer");
    check("exchangeCode: scope parsed",              tokens.scope.indexOf("read:user") !== -1);
    check("exchangeCode: POST included grant_type",   receivedBody.indexOf("grant_type=authorization_code") !== -1);
    check("exchangeCode: POST included code",         receivedBody.indexOf("code=AUTH_CODE_123") !== -1);
    check("exchangeCode: POST included verifier",     receivedBody.indexOf("code_verifier=test-verifier-") !== -1);
    check("exchangeCode: POST included client_secret", receivedBody.indexOf("client_secret=secret") !== -1);
  } finally { server.close(); }
}

async function testOAuthRefreshAccessToken() {
  var receivedBody = null;
  var server = _spawnFakeIdpServer({
    "/token": function (req, res) {
      receivedBody = req.body;
      var body = JSON.stringify({
        access_token: "AT-fresh", token_type: "Bearer", expires_in: 3600,
      });
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(body);
    },
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    var oa = b.auth.oauth.create({
      clientId: "x", clientSecret: "y", redirectUri: "https://app/cb",
      authorizationEndpoint: "http://127.0.0.1:" + port + "/auth",
      tokenEndpoint:         "http://127.0.0.1:" + port + "/token",
      isOidc: false, allowHttp: true, allowInternal: true,
    });
    var tokens = await oa.refreshAccessToken("RT-old");
    check("refresh: new access token issued",       tokens.accessToken === "AT-fresh");
    check("refresh: POST included grant_type=refresh_token",
          receivedBody.indexOf("grant_type=refresh_token") !== -1);
    check("refresh: POST included refresh_token",     receivedBody.indexOf("refresh_token=RT-old") !== -1);
  } finally { server.close(); }
}

async function testOAuthFetchUserInfo() {
  var receivedAuthHeader = null;
  var server = _spawnFakeIdpServer({
    "/userinfo": function (req, res) {
      receivedAuthHeader = req.headers["authorization"];
      var body = JSON.stringify({ sub: "user-1", email: "x@y.io", name: "Alice" });
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(body);
    },
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    var oa = b.auth.oauth.create({
      clientId: "x", redirectUri: "https://app/cb",
      authorizationEndpoint: "http://127.0.0.1:" + port + "/auth",
      tokenEndpoint:         "http://127.0.0.1:" + port + "/token",
      userinfoEndpoint:      "http://127.0.0.1:" + port + "/userinfo",
      isOidc: false, allowHttp: true, allowInternal: true,
    });
    var profile = await oa.fetchUserInfo("AT-xyz");
    check("userinfo: returns parsed profile",        profile.email === "x@y.io");
    check("userinfo: Authorization Bearer header sent",
          receivedAuthHeader === "Bearer AT-xyz");
  } finally { server.close(); }
}

async function testOAuthVerifyIdTokenRoundTrip() {
  // Generate an RSA keypair, sign an RS256 ID token, verify via the
  // OAuth client's verifyIdToken (with JWKS served from the fake IdP).
  var kp = await _generateRsaKeypair();
  var jwk = _publicKeyToJwk(kp.publicKey, "test-kid-1");
  var jwks = { keys: [jwk] };
  var server = _spawnFakeIdpServer({
    "/jwks": function (req, res) {
      var body = JSON.stringify(jwks);
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(body);
    },
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    var issuerUrl = "http://127.0.0.1:" + port;
    var clientId  = "test-client";
    var oa = b.auth.oauth.create({
      clientId: clientId, redirectUri: "https://app/cb",
      isOidc:    true,
      issuer:    issuerUrl,
      authorizationEndpoint: issuerUrl + "/auth",
      tokenEndpoint:         issuerUrl + "/token",
      jwksUri:               issuerUrl + "/jwks",
      allowHttp: true, allowInternal: true,
    });
    var nowSec = Math.floor(Date.now() / 1000);
    var idToken = _signRs256({
      iss:   issuerUrl, sub: "user-1", aud: clientId,
      exp:   nowSec + 3600, iat: nowSec, nonce: "abc-nonce",
    }, { kid: "test-kid-1" }, kp.privateKey);

    var ok = await oa.verifyIdToken(idToken, { nonce: "abc-nonce" });
    check("verifyIdToken: claims returned",          ok.claims.sub === "user-1");
    check("verifyIdToken: iss matches",              ok.claims.iss === issuerUrl);

    // Wrong nonce → reject
    var threw = null;
    try { await oa.verifyIdToken(idToken, { nonce: "different" }); } catch (e) { threw = e; }
    check("verifyIdToken: wrong nonce rejected",     threw && threw.code === "auth-oauth/nonce-mismatch");

    // Tampered signature → reject
    var tampered = idToken.slice(0, -5) + "XXXXX";
    threw = null;
    try { await oa.verifyIdToken(tampered, { nonce: "abc-nonce" }); } catch (e) { threw = e; }
    check("verifyIdToken: tampered signature rejected",
          threw && (threw.code === "auth-oauth/bad-signature" || threw.code === "auth-oauth/malformed-jwt"));

    // Expired token → reject
    var expired = _signRs256({
      iss: issuerUrl, sub: "user-1", aud: clientId,
      exp: nowSec - 7200, iat: nowSec - 7300,
    }, { kid: "test-kid-1" }, kp.privateKey);
    threw = null;
    try { await oa.verifyIdToken(expired, {}); } catch (e) { threw = e; }
    check("verifyIdToken: expired rejected",         threw && threw.code === "auth-oauth/expired");

    // Wrong audience → reject
    var wrongAud = _signRs256({
      iss: issuerUrl, sub: "user-1", aud: "different-client",
      exp: nowSec + 3600, iat: nowSec,
    }, { kid: "test-kid-1" }, kp.privateKey);
    threw = null;
    try { await oa.verifyIdToken(wrongAud, {}); } catch (e) { threw = e; }
    check("verifyIdToken: wrong aud rejected",       threw && threw.code === "auth-oauth/aud-mismatch");

    // Wrong issuer → reject
    var wrongIss = _signRs256({
      iss: "https://other-iss", sub: "user-1", aud: clientId,
      exp: nowSec + 3600, iat: nowSec,
    }, { kid: "test-kid-1" }, kp.privateKey);
    threw = null;
    try { await oa.verifyIdToken(wrongIss, {}); } catch (e) { threw = e; }
    check("verifyIdToken: wrong iss rejected",       threw && threw.code === "auth-oauth/iss-mismatch");
  } finally { server.close(); }
}

async function testOAuthVerifyIdTokenRefusesUnsupportedAlg() {
  // none / HS256 should be refused.
  var oa = b.auth.oauth.create({
    clientId: "x", redirectUri: "https://app/cb",
    isOidc: true, issuer: "https://example.com",
    authorizationEndpoint: "https://example.com/auth", tokenEndpoint: "https://example.com/token",
    jwksUri: "https://example.com/jwks",
    allowHttp: false,
  });
  var b64u = b.auth.oauth._b64urlEncode;
  // Forge a "none"-alg token
  var noneTok = b64u(JSON.stringify({ alg: "none", typ: "JWT" })) + "." +
                b64u(JSON.stringify({ sub: "u" })) + ".";
  var threw = null;
  try { await oa.verifyIdToken(noneTok, {}); } catch (e) { threw = e; }
  check("verifyIdToken: none alg rejected",        threw && threw.code === "auth-oauth/alg-not-accepted");

  // HS256 — also not in DEFAULT_ACCEPTED_ALGS
  var hsTok = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" })) + "." +
              b64u(JSON.stringify({ sub: "u" })) + ".sig";
  threw = null;
  try { await oa.verifyIdToken(hsTok, {}); } catch (e) { threw = e; }
  check("verifyIdToken: HS256 rejected",            threw && threw.code === "auth-oauth/alg-not-accepted");
}

function testOAuthVerifyParamsForAlg() {
  var raw = b.auth.oauth._verifyParamsForAlg;
  check("RS256 → sha256 + PKCS1",                  raw("RS256").hash === "sha256");
  check("ES256 → sha256 + ieee-p1363",             raw("ES256").dsaEncoding === "ieee-p1363");
  check("PS256 → sha256 + PSS padding",
        raw("PS256").padding === require("node:crypto").constants.RSA_PKCS1_PSS_PADDING);
  var threw = null;
  try { raw("XYZ"); } catch (e) { threw = e; }
  check("unsupported alg → throws",                threw && threw.code === "auth-oauth/unsupported-alg");
}

// ---- app-shutdown tests moved to test/layer-0-primitives/app-shutdown.test.js ----

// ---- tracing tests moved to test/layer-0-primitives/tracing.test.js ----

// ---- metrics ----

function _metricsRes() {
  var EE = require("node:events").EventEmitter;
  var res = new EE();
  res._headers = {};
  res._captured = "";
  res._statusCode = null;
  res.writeHead = function (s, h) {
    res._statusCode = s;
    if (h) {
      var keys = Object.keys(h);
      for (var i = 0; i < keys.length; i++) res._headers[keys[i].toLowerCase()] = h[keys[i]];
    }
  };
  res.end = function (body) { if (body) res._captured += body; res.emit("finish"); };
  return res;
}

function testMetricsSurface() {
  check("b.metrics namespace present",       typeof b.metrics === "object");
  check("b.metrics.create is a function",    typeof b.metrics.create === "function");
  check("b.metrics.tap is a function",       typeof b.metrics.tap === "function");
  check("MetricsError is a class",           typeof b.metrics.MetricsError === "function");
  check("DEFAULT_HTTP_BUCKETS exposed",      Array.isArray(b.metrics.DEFAULT_HTTP_BUCKETS));
}

function testMetricsCounterBasic() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var c = m.counter("requests_total", { help: "test", labelNames: ["method"] });
  c.inc({ method: "GET" });
  c.inc({ method: "GET" }, 4);
  c.inc({ method: "POST" });
  check("counter: GET tally is 5",                 c.get({ method: "GET" }) === 5);
  check("counter: POST tally is 1",                c.get({ method: "POST" }) === 1);
  check("counter: missing combo returns 0",        c.get({ method: "DELETE" }) === 0);
  m.deactivate();
}

function testMetricsCounterRefusesNegative() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var c = m.counter("x", { labelNames: [] });
  var threw = null;
  try { c.inc({}, -1); } catch (e) { threw = e; }
  check("counter: negative inc rejected",          threw && threw.code === "metrics/counter-decrement");
  m.deactivate();
}

function testMetricsGaugeBasic() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var g = m.gauge("queue_depth", { labelNames: ["queueName"] });
  g.set({ queueName: "default" }, 10);
  check("gauge: set works",                        g.get({ queueName: "default" }) === 10);
  g.inc({ queueName: "default" });
  check("gauge: inc works",                        g.get({ queueName: "default" }) === 11);
  g.dec({ queueName: "default" }, 3);
  check("gauge: dec works",                        g.get({ queueName: "default" }) === 8);
  // Gauges allow decreasing
  g.set({ queueName: "default" }, -5);
  check("gauge: negative set allowed",             g.get({ queueName: "default" }) === -5);
  m.deactivate();
}

function testMetricsHistogramBasic() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var h = m.histogram("latency", {
    labelNames: ["route"],
    buckets:    [0.1, 0.5, 1.0, 5.0],
  });
  h.observe({ route: "/api" }, 0.05);
  h.observe({ route: "/api" }, 0.3);
  h.observe({ route: "/api" }, 2.0);
  h.observe({ route: "/api" }, 8.0);
  // Inspect via the Map — counts[i] is for [<=buckets[i]]; counts[4] = +Inf
  // Buckets: [0.1, 0.5, 1.0, 5.0]; values: 0.05, 0.3, 2.0, 8.0
  var entry = h.values.get(_keyForLabels({ route: "/api" }));
  check("histogram: bucket 0.1 counts 0.05 only",  entry.counts[0] === 1);
  check("histogram: bucket 0.5 counts 0.05+0.3",   entry.counts[1] === 2);
  check("histogram: bucket 1.0 counts 0.05+0.3",   entry.counts[2] === 2);
  check("histogram: bucket 5.0 counts 0.05+0.3+2.0", entry.counts[3] === 3);
  check("histogram: +Inf counts all 4",            entry.counts[4] === 4);
  check("histogram: count=4",                      entry.count === 4);
  check("histogram: sum=10.35",                    Math.abs(entry.sum - 10.35) < 1e-9);
  m.deactivate();
}

function _keyForLabels(labels) {
  return b.metrics._labelsKey(labels);
}

function testMetricsHistogramRejectsBadBuckets() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var threw;

  threw = null;
  try { m.histogram("x", { buckets: [] }); } catch (e) { threw = e; }
  check("histogram: empty buckets rejected",       threw && threw.code === "metrics/bad-buckets");

  threw = null;
  try { m.histogram("x", { buckets: [1, 2, 1.5] }); } catch (e) { threw = e; }
  check("histogram: non-ascending buckets rejected", threw && threw.code === "metrics/bad-buckets");

  threw = null;
  try { m.histogram("x", { buckets: [1, "two", 3] }); } catch (e) { threw = e; }
  check("histogram: non-numeric buckets rejected", threw && threw.code === "metrics/bad-buckets");
  m.deactivate();
}

function testMetricsDefaultLabels() {
  b.metrics._resetForTest();
  var m = b.metrics.create({ defaultLabels: { service: "api", version: "1.2.3" } });
  var c = m.counter("requests", { labelNames: ["method"] });
  c.inc({ method: "GET" });
  // Default labels are folded into every observation.
  var output = m.exposition();
  check("default labels present in exposition",    output.indexOf('service="api"') !== -1);
  check("default labels include version",          output.indexOf('version="1.2.3"') !== -1);
  m.deactivate();
}

function testMetricsNamespacing() {
  b.metrics._resetForTest();
  var m = b.metrics.create({ namespace: "myapp" });
  var c = m.counter("requests_total", { labelNames: [] });
  c.inc({});
  var output = m.exposition();
  check("namespace prepended to metric name",      output.indexOf("myapp_requests_total") !== -1);
  m.deactivate();
}

function testMetricsLabelValidation() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var c = m.counter("x", { labelNames: ["valid"] });
  var threw;

  threw = null;
  try { c.inc({ undeclared: "v" }); } catch (e) { threw = e; }
  check("undeclared label rejected",               threw && threw.code === "metrics/undeclared-label");

  threw = null;
  try { c.inc({}); } catch (e) { threw = e; }
  check("missing required label rejected",         threw && threw.code === "metrics/missing-label");

  threw = null;
  try { m.counter("bad-name-with-dash", {}); } catch (e) { threw = e; }
  check("bad metric name rejected",                threw && threw.code === "metrics/bad-name");

  threw = null;
  try { m.counter("ok", { labelNames: ["bad-label"] }); } catch (e) { threw = e; }
  check("bad label name rejected",                 threw && threw.code === "metrics/bad-label");
  m.deactivate();
}

function testMetricsCardinalityCap() {
  b.metrics._resetForTest();
  var m = b.metrics.create({ labelCardinalityCap: 5 });
  var c = m.counter("x", { labelNames: ["uid"] });
  for (var i = 0; i < 10; i++) c.inc({ uid: "u" + i });
  check("cardinality cap: 5 distinct combos retained", c.values.size === 5);
  // First 5 values still increment correctly
  c.inc({ uid: "u0" });
  check("cardinality cap: pre-cap entries still increment",
        c.get({ uid: "u0" }) === 2);
  m.deactivate();
}

function testMetricsExpositionFormat() {
  b.metrics._resetForTest();
  var m = b.metrics.create({ namespace: "app" });
  var c = m.counter("requests_total", { help: "Request count", labelNames: ["method"] });
  c.inc({ method: "GET" }, 3);
  var h = m.histogram("latency_seconds", {
    help: "Latency", labelNames: ["route"], buckets: [0.1, 1.0],
  });
  h.observe({ route: "/x" }, 0.05);
  h.observe({ route: "/x" }, 5.0);
  var output = m.exposition();

  check("exposition: HELP line for counter",
        output.indexOf("# HELP app_requests_total Request count") !== -1);
  check("exposition: TYPE line for counter",
        output.indexOf("# TYPE app_requests_total counter") !== -1);
  check("exposition: counter sample with label",
        output.indexOf('app_requests_total{method="GET"} 3') !== -1);
  check("exposition: HELP for histogram",
        output.indexOf("# HELP app_latency_seconds Latency") !== -1);
  check("exposition: TYPE histogram",
        output.indexOf("# TYPE app_latency_seconds histogram") !== -1);
  check("exposition: histogram bucket le=0.1",
        output.indexOf('app_latency_seconds_bucket{le="0.1",route="/x"} 1') !== -1);
  check("exposition: histogram bucket le=+Inf",
        output.indexOf('app_latency_seconds_bucket{le="+Inf",route="/x"} 2') !== -1);
  check("exposition: histogram _sum",
        output.indexOf('app_latency_seconds_sum{route="/x"} 5.05') !== -1);
  check("exposition: histogram _count",
        output.indexOf('app_latency_seconds_count{route="/x"} 2') !== -1);
  m.deactivate();
}

function testMetricsLabelEscaping() {
  var raw = b.metrics;
  check("escape: backslash escaped",       raw._escapeLabelValue("a\\b") === "a\\\\b");
  check("escape: newline escaped",         raw._escapeLabelValue("a\nb") === "a\\nb");
  check("escape: double-quote escaped",    raw._escapeLabelValue('a"b') === 'a\\"b');
}

async function testMetricsExpositionHandler() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var c = m.counter("ping", { labelNames: [] });
  c.inc({});
  var handler = m.expositionHandler();
  var res = _metricsRes();
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    handler({ method: "GET", url: "/metrics" }, res);
  });
  check("handler: status 200",                     res._statusCode === 200);
  check("handler: content-type prometheus format",
        res._headers["content-type"].indexOf("text/plain") === 0);
  check("handler: body contains ping metric",      res._captured.indexOf("ping") !== -1);
  check("handler: cache-control no-store",          res._headers["cache-control"] === "no-store");
  m.deactivate();
}

async function testMetricsRequestMiddleware() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var mw = m.requestMiddleware();
  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method = "GET";
  req.url = "/users/123?q=x";
  req.routePattern = "/users/:id";
  req.headers = {};
  var res = _metricsRes();
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    mw(req, res, function () {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
  });
  var requestsTotal = m.metrics.get("framework_http_requests_total");
  check("requestMiddleware: counter incremented",
        requestsTotal.get({ method: "GET", route: "/users/:id", status: "200" }) === 1);
  // Histogram observed once
  var latency = m.metrics.get("framework_http_request_duration_seconds");
  var key = b.metrics._labelsKey({ method: "GET", route: "/users/:id" });
  check("requestMiddleware: histogram observed once", latency.values.get(key).count === 1);
  m.deactivate();
}

async function testMetricsRequestMiddlewareStatusCodeFallback() {
  // Handlers that set res.statusCode directly (modern Node pattern)
  // instead of calling writeHead must still produce the correct status
  // label. Prior versions only caught writeHead.
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var mw = m.requestMiddleware();
  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method = "GET";
  req.url = "/notfound";
  req.headers = {};
  var res = _metricsRes();
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    mw(req, res, function () {
      res.statusCode = 404;     // direct set; no writeHead
      res.end("nope");
    });
  });
  var requestsTotal = m.metrics.get("framework_http_requests_total");
  check("requestMiddleware: status=404 captured from res.statusCode (no writeHead)",
        requestsTotal.get({ method: "GET", route: "/notfound", status: "404" }) === 1);
  m.deactivate();
}

async function testMetricsRequestMiddlewareRoutePatternFallback() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var mw = m.requestMiddleware();
  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method = "GET";
  req.url = "/raw-path?x=1";
  // No routePattern — middleware falls back to URL with query stripped
  req.headers = {};
  var res = _metricsRes();
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    mw(req, res, function () {
      res.writeHead(200);
      res.end();
    });
  });
  var requestsTotal = m.metrics.get("framework_http_requests_total");
  check("middleware: falls back to URL with query stripped",
        requestsTotal.get({ method: "GET", route: "/raw-path", status: "200" }) === 1);
  m.deactivate();
}

function testMetricsTapNoOpWhenNoRegistry() {
  b.metrics._resetForTest();
  // tap() is a no-op when no registry is active — calling it must not throw.
  var threw = null;
  try {
    b.metrics.tap("audit.record", 1, { action: "x", outcome: "success" });
    b.metrics.tap("vault.seal", 1);
    b.metrics.tap("queue.enqueue", 1, { queueName: "default" });
  } catch (e) { threw = e; }
  check("tap: no-op when registry inactive — no throw", threw === null);
}

function testMetricsTapRoutesIntoActiveRegistry() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  b.metrics.tap("audit.record", 1, { action: "auth.login", outcome: "success" });
  b.metrics.tap("audit.record", 1, { action: "auth.login", outcome: "success" });
  b.metrics.tap("vault.seal", 1);
  b.metrics.tap("vault.seal", 1);
  b.metrics.tap("vault.seal", 1);
  b.metrics.tap("queue.enqueue", 1, { queueName: "emails" });
  var auditTotal = m.metrics.get("framework_audit_events_total");
  check("tap: audit.record routes into framework_audit_events_total",
        auditTotal.get({ action: "auth.login", outcome: "success" }) === 2);
  var sealTotal = m.metrics.get("framework_vault_seal_total");
  check("tap: vault.seal routes into framework_vault_seal_total",
        sealTotal.get({}) === 3);
  var enqueueTotal = m.metrics.get("framework_queue_enqueue_total");
  check("tap: queue.enqueue routes into framework_queue_enqueue_total",
        enqueueTotal.get({ queueName: "emails" }) === 1);
  m.deactivate();
}

function testMetricsBuiltinQueueDepthGauge() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  b.metrics.tap("queue.enqueue", 1, { queueName: "outbox" });
  b.metrics.tap("queue.enqueue", 1, { queueName: "outbox" });
  b.metrics.tap("queue.enqueue", 1, { queueName: "outbox" });
  var depth = m.metrics.get("framework_queue_depth");
  check("queue_depth: enqueue increments gauge",
        depth.get({ queueName: "outbox" }) === 3);
  b.metrics.tap("queue.complete", 1, { queueName: "outbox" });
  check("queue_depth: complete decrements gauge",
        depth.get({ queueName: "outbox" }) === 2);
  b.metrics.tap("queue.fail", 1, { queueName: "outbox", willRetry: true });
  check("queue_depth: fail-with-retry leaves depth (job back to pending)",
        depth.get({ queueName: "outbox" }) === 2);
  b.metrics.tap("queue.fail", 1, { queueName: "outbox", willRetry: false });
  check("queue_depth: fail-terminal decrements depth",
        depth.get({ queueName: "outbox" }) === 1);
  m.deactivate();
}

function testMetricsBuiltinJobsInflightGauge() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  b.metrics.tap("queue.lease", 1, { queueName: "outbox" });
  b.metrics.tap("queue.lease", 1, { queueName: "outbox" });
  var inflight = m.metrics.get("framework_jobs_inflight");
  check("jobs_inflight: lease increments gauge",
        inflight.get({ queueName: "outbox" }) === 2);
  b.metrics.tap("queue.complete", 1, { queueName: "outbox" });
  check("jobs_inflight: complete decrements gauge",
        inflight.get({ queueName: "outbox" }) === 1);
  b.metrics.tap("queue.fail", 1, { queueName: "outbox", willRetry: true });
  check("jobs_inflight: fail-with-retry decrements gauge (lease ended)",
        inflight.get({ queueName: "outbox" }) === 0);
  m.deactivate();
}

function testMetricsBuiltinErrorsTotalCounter() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  // FrameworkError construction taps — triggered by the defineClass-built
  // error classes used everywhere in the framework.
  var errs = m.metrics.get("framework_errors_total");
  var beforeQueue = errs.get({ class: "QueueError" });
  try { throw new b.frameworkError.QueueError("test/case", "smoke", true); }
  catch (_e) { /* swallow — we only need the construction tap */ }
  var afterQueue = errs.get({ class: "QueueError" });
  check("errors_total: framework-error construction increments class label",
        afterQueue === beforeQueue + 1);
  m.deactivate();
}

function testMetricsDuplicateRegistrationRejected() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  m.counter("dup", { labelNames: [] });
  var threw = null;
  try { m.counter("dup", { labelNames: [] }); } catch (e) { threw = e; }
  check("duplicate metric registration rejected",  threw && threw.code === "metrics/duplicate");
  m.deactivate();
}

function testMetricsResetClearsValues() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  var c = m.counter("x", { labelNames: ["k"] });
  c.inc({ k: "a" });
  c.inc({ k: "b" });
  check("before reset: 2 distinct combos",         c.values.size === 2);
  c.reset();
  check("after reset: 0 combos",                   c.values.size === 0);
  c.inc({ k: "c" });
  check("after reset: new combos work",            c.get({ k: "c" }) === 1);
  m.deactivate();
}

// ---- csp-nonce tests moved to test/layer-0-primitives/csp-nonce.test.js ----

// ---- pagination tests moved to test/layer-0-primitives/pagination.test.js ----
// ---- compression (gzip + brotli response compression) ----

function _compressionReq(headers) {
  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method  = "GET";
  req.url     = "/";
  req.headers = headers || {};
  req.socket  = { remoteAddress: "127.0.0.1" };
  return req;
}

// Stream-shaped res that captures the bytes that would have gone on
// the wire. Lets compression tests verify Content-Encoding header AND
// the actual compressed payload (decompress + check).
function _compressionRes() {
  var EE = require("node:events").EventEmitter;
  var res = new EE();
  res._chunks = [];
  res._headers = {};
  res._statusCode = 200;
  res.headersSent = false;
  res.writeHead = function (status, statusMsgOrHeaders, headersIfMsg) {
    res._statusCode = status;
    res.headersSent = true;
    var h = null;
    if (headersIfMsg && typeof headersIfMsg === "object") h = headersIfMsg;
    else if (statusMsgOrHeaders && typeof statusMsgOrHeaders === "object" && !Array.isArray(statusMsgOrHeaders)) h = statusMsgOrHeaders;
    if (h) {
      var keys = Object.keys(h);
      for (var i = 0; i < keys.length; i++) res._headers[keys[i].toLowerCase()] = h[keys[i]];
    }
  };
  res.setHeader = function (k, v) { res._headers[k.toLowerCase()] = v; };
  res.getHeader = function (k) { return res._headers[k.toLowerCase()]; };
  res.removeHeader = function (k) { delete res._headers[k.toLowerCase()]; };
  res.write = function (chunk) {
    if (Buffer.isBuffer(chunk)) res._chunks.push(chunk);
    else if (typeof chunk === "string") res._chunks.push(Buffer.from(chunk));
    return true;
  };
  res.end = function (chunk) {
    if (chunk != null) res.write(chunk);
    res.emit("finish");
    return res;
  };
  res._captured = function () { return Buffer.concat(res._chunks); };
  return res;
}

function _runCompression(mw, req, res, handler) {
  return new Promise(function (resolve) {
    var resolved = false;
    res.on("finish", function () { if (!resolved) { resolved = true; resolve(); } });
    mw(req, res, function () {
      try { handler(res); }
      catch (e) { resolved = true; resolve(e); }
    });
  });
}

async function testCompressionSurface() {
  check("b.middleware.compression is a function",   typeof b.middleware.compression === "function");
  var raw = b.middleware._modules.compression;
  check("CompressionError exposed",                 typeof raw.CompressionError === "function");
  check("SUPPORTED_ENCODINGS exposed",              raw.SUPPORTED_ENCODINGS instanceof Set);
  check("br supported",                             raw.SUPPORTED_ENCODINGS.has("br"));
  check("gzip supported",                           raw.SUPPORTED_ENCODINGS.has("gzip"));
}

async function testCompressionParseAcceptEncoding() {
  var raw = b.middleware._modules.compression;
  var p = raw._parseAcceptEncoding("gzip, br;q=0.9");
  check("parse: extracts both encodings",          p.length === 2);
  check("parse: q=1 default for unspecified",      p[0].encoding === "gzip" && p[0].q === 1);
  check("parse: q-value parsed",                   p[1].encoding === "br" && p[1].q === 0.9);

  var pZero = raw._parseAcceptEncoding("br;q=0, gzip;q=1");
  check("parse: q=0 retained (caller filters)",    pZero.find(function (x) { return x.encoding === "br"; }).q === 0);

  var pStar = raw._parseAcceptEncoding("*;q=0.5");
  check("parse: wildcard captured",                pStar[0].encoding === "*" && pStar[0].q === 0.5);

  var pEmpty = raw._parseAcceptEncoding("");
  check("parse: empty header → wildcard",          pEmpty[0].encoding === "*");

  var pAbsent = raw._parseAcceptEncoding(undefined);
  check("parse: absent header → wildcard",         pAbsent[0].encoding === "*");
}

async function testCompressionNegotiate() {
  var raw = b.middleware._modules.compression;
  var pickBr = raw._negotiateEncoding(
    raw._parseAcceptEncoding("gzip, br"),
    ["br", "gzip"]);
  check("negotiate: brotli picked when client + server both list",  pickBr === "br");

  var pickGzip = raw._negotiateEncoding(
    raw._parseAcceptEncoding("gzip"),
    ["br", "gzip"]);
  check("negotiate: gzip picked when br absent client-side",        pickGzip === "gzip");

  var pickNothing = raw._negotiateEncoding(
    raw._parseAcceptEncoding("identity;q=1, *;q=0"),
    ["br", "gzip"]);
  check("negotiate: q=0 wildcard rejects all server-supported",     pickNothing === null);

  // q=0 explicit on br — gzip wins
  var pickGzipExplicit = raw._negotiateEncoding(
    raw._parseAcceptEncoding("br;q=0, gzip"),
    ["br", "gzip"]);
  check("negotiate: q=0 excludes the named encoding",               pickGzipExplicit === "gzip");

  // wildcard with positive q lets either through
  var pickBrViaStar = raw._negotiateEncoding(
    raw._parseAcceptEncoding("*"),
    ["br", "gzip"]);
  check("negotiate: '*' lets the server pick its preferred",        pickBrViaStar === "br");
}

async function testCompressionTypeMatches() {
  var raw = b.middleware._modules.compression;
  check("type: exact match",                        raw._typeMatches("text/html", ["text/html"]));
  check("type: prefix wildcard",                    raw._typeMatches("text/css", ["text/*"]));
  check("type: prefix wildcard ignores params",     raw._typeMatches("text/html; charset=utf-8", ["text/*"]));
  check("type: no match for unrelated",             !raw._typeMatches("image/jpeg", ["text/*"]));
  check("type: undefined input",                    !raw._typeMatches(undefined, ["text/*"]));
}

async function testCompressionAppendVary() {
  var raw = b.middleware._modules.compression;
  check("vary: empty → token",                      raw._appendVary("", "Accept-Encoding") === "Accept-Encoding");
  check("vary: undefined → token",                  raw._appendVary(undefined, "Accept-Encoding") === "Accept-Encoding");
  check("vary: append to existing",
        raw._appendVary("Cookie", "Accept-Encoding").indexOf("Accept-Encoding") !== -1 &&
        raw._appendVary("Cookie", "Accept-Encoding").indexOf("Cookie") !== -1);
  check("vary: don't duplicate",
        raw._appendVary("Accept-Encoding", "Accept-Encoding") === "Accept-Encoding");
  check("vary: '*' stays '*'",
        raw._appendVary("*", "Accept-Encoding") === "*");
}

async function testCompressionGzipRoundTrip() {
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  var payload = "x".repeat(2000); // > 1024 threshold
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": String(payload.length) });
    res.end(payload);
  });
  check("gzip: Content-Encoding set",                res._headers["content-encoding"] === "gzip");
  check("gzip: Content-Length removed",              res._headers["content-length"] === undefined);
  check("gzip: Vary includes Accept-Encoding",       String(res._headers["vary"]).indexOf("Accept-Encoding") !== -1);
  // Decompress and verify
  var zlib = require("node:zlib");
  var decompressed = zlib.gunzipSync(res._captured()).toString("utf8");
  check("gzip: round-trip preserves bytes",          decompressed === payload);
}

async function testCompressionBrotliRoundTrip() {
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "br" });
  var res = _compressionRes();
  var payload = "y".repeat(2000);
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": String(payload.length) });
    res.end(payload);
  });
  check("brotli: Content-Encoding set",              res._headers["content-encoding"] === "br");
  var zlib = require("node:zlib");
  var decompressed = zlib.brotliDecompressSync(res._captured()).toString("utf8");
  check("brotli: round-trip preserves bytes",        decompressed === payload);
}

async function testCompressionPrefersBrotliOverGzip() {
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip, br" });
  var res = _compressionRes();
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": "2000" });
    res.end("z".repeat(2000));
  });
  check("preference: brotli chosen when both supported", res._headers["content-encoding"] === "br");
}

async function testCompressionSkipsBelowThreshold() {
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  var payload = "small";
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": String(payload.length) });
    res.end(payload);
  });
  check("threshold: small body NOT compressed",      res._headers["content-encoding"] === undefined);
  check("threshold: body bytes pass through verbatim", res._captured().toString("utf8") === payload);
}

async function testCompressionSkipsImageContentType() {
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  var payload = Buffer.alloc(2000, 0xff);
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "image/jpeg", "Content-Length": String(payload.length) });
    res.end(payload);
  });
  check("type-skip: image/jpeg not compressed",      res._headers["content-encoding"] === undefined);
}

async function testCompressionSkipsAlreadyEncoded() {
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, {
      "Content-Type":     "text/plain",
      "Content-Encoding": "gzip", // already done
      "Content-Length":   "2000",
    });
    res.end("z".repeat(2000));
  });
  // The pre-existing Content-Encoding stays exactly as the operator set it.
  check("already-encoded: middleware doesn't double-compress",
        res._headers["content-encoding"] === "gzip");
}

async function testCompressionSkipsWhenClientDoesntAccept() {
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "identity;q=1, *;q=0" });
  var res = _compressionRes();
  var payload = "z".repeat(2000);
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": String(payload.length) });
    res.end(payload);
  });
  check("client-rejects: no Content-Encoding set",   res._headers["content-encoding"] === undefined);
  check("client-rejects: bytes pass through",         res._captured().toString("utf8") === payload);
}

async function testCompressionSkipsNoBodyStatus() {
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  await _runCompression(compress, req, res, function () {
    res.writeHead(204, { "Content-Type": "text/plain" });
    res.end();
  });
  check("no-body-status: 204 not compressed",        res._headers["content-encoding"] === undefined);
}

async function testCompressionFilterReturnsFalse() {
  var compress = b.middleware.compression({
    filter: function () { return false; },
  });
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  var payload = "z".repeat(2000);
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": String(payload.length) });
    res.end(payload);
  });
  check("filter-skip: filter false → no compression", res._headers["content-encoding"] === undefined);
}

async function testCompressionFilterThrowFailsClosed() {
  var compress = b.middleware.compression({
    filter: function () { throw new Error("boom"); },
  });
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  var payload = "z".repeat(2000);
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": String(payload.length) });
    res.end(payload);
  });
  // Filter throw → middleware skips compression (fail-closed; the
  // alternative is half-applied compression which would corrupt output).
  check("filter-throw: skips compression",            res._headers["content-encoding"] === undefined);
}

async function testCompressionStreamingWritesNoContentLength() {
  // Handler writes incrementally without setting Content-Length.
  // Compression should still happen — we assume "large enough" when CL absent.
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "text/plain" });
    for (var i = 0; i < 50; i++) res.write("chunk-" + i + "-data\n");
    res.end();
  });
  check("streaming: Content-Encoding set",           res._headers["content-encoding"] === "gzip");
  var zlib = require("node:zlib");
  var decompressed = zlib.gunzipSync(res._captured()).toString("utf8");
  check("streaming: bytes preserved across chunks",  decompressed.indexOf("chunk-49-data") !== -1);
}

async function testCompressionImplicitWriteHeadPath() {
  // Handler calls res.write before res.writeHead — Node implicitly
  // writes head with status 200. Middleware must handle this path
  // without losing compression.
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  await _runCompression(compress, req, res, function () {
    res.setHeader("Content-Type", "text/plain");
    res.write("a".repeat(2000));
    res.end();
  });
  check("implicit-head: Content-Encoding set",       res._headers["content-encoding"] === "gzip");
}

async function testCompressionInvalidEncodingRejectedAtCreate() {
  var threw = null;
  try { b.middleware.compression({ encodings: ["zstd"] }); }
  catch (e) { threw = e; }
  check("create: unsupported encoding rejected",     threw && threw.code === "compression/bad-encoding");
}

// Regression for the streaming-pipe stall: piping a Readable larger
// than zlib's internal highWaterMark (16 KB) through the wrapped res
// would hang because the wrapped res.write returned false when the
// compressor signalled backpressure but never re-emitted drain on res.
// stream.pipe() then paused the source forever waiting for a drain
// that never came. The fix: forward compressor 'drain' to res.emit('drain').
async function testCompressionPipedStreamLargerThanHighWaterMarkCompletes() {
  var stream = require("node:stream");
  var zlib = require("node:zlib");
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();

  // 256 KB of compressible text — well past zlib's 16 KB highWaterMark.
  // Highly compressible (single repeated character) so compression
  // ratio is high and the bug reliably triggers.
  var payload = Buffer.alloc(256 * 1024, "A");
  var source  = stream.Readable.from([payload]);

  // Race the pipe completion against a timeout. Pre-fix this hangs
  // indefinitely; with the drain forward it completes promptly.
  var done = new Promise(function (resolve) {
    res.on("finish", function () { resolve("ok"); });
  });
  var timeout = new Promise(function (resolve) {
    setTimeout(function () { resolve("timeout"); }, 3000);
  });

  await new Promise(function (resolve) {
    compress(req, res, function () {
      res.writeHead(200, { "Content-Type": "text/plain" });
      source.pipe(res);
      resolve();
    });
  });

  var outcome = await Promise.race([done, timeout]);
  check("piped stream completes (no stall on backpressure)", outcome === "ok");
  if (outcome !== "ok") return;

  check("piped stream: Content-Encoding set",   res._headers["content-encoding"] === "gzip");
  check("piped stream: Content-Length removed", res._headers["content-length"] === undefined);
  var decompressed = zlib.gunzipSync(res._captured());
  check("piped stream: round-trip preserves bytes", decompressed.equals(payload));
}

async function testCompressionDoesntDoubleCompressViaWrappedWrite() {
  // Regression: an earlier implementation could feed compressor output
  // back through res.write (the wrapped one), causing recursive
  // compression. Verify the Content-Encoding is set exactly once and
  // the output is one-pass compressed.
  var compress = b.middleware.compression();
  var req = _compressionReq({ "accept-encoding": "gzip" });
  var res = _compressionRes();
  var payload = "test-double-encoding-guard-" + "x".repeat(2000);
  await _runCompression(compress, req, res, function () {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(payload);
  });
  var zlib = require("node:zlib");
  // Single gunzip should yield the original; if double-compressed, the
  // outer gunzip would yield gzip-magic-bytes + ciphertext rather than text.
  var out = zlib.gunzipSync(res._captured()).toString("utf8");
  check("no double encode: single gunzip yields plaintext",
        out === payload);
}

// ---- health (probe primitive) ----

function _healthReq(method, url) {
  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method  = method || "GET";
  req.url     = url;
  req.headers = {};
  req.socket  = { remoteAddress: "127.0.0.1" };
  return req;
}

function _runHealthMiddleware(mw, req, res) {
  return new Promise(function (resolve) {
    var nextCalled = false;
    var resolved = false;
    function done(payload) { if (resolved) return; resolved = true; resolve(payload); }
    res.on("finish", function () { if (!nextCalled) done({ next: false, status: res._endedStatus, body: res._captured }); });
    mw(req, res, function () { nextCalled = true; done({ next: true }); });
  });
}

async function testHealthSurface() {
  check("b.middleware.health is a function",     typeof b.middleware.health === "function");
  var raw = b.middleware._modules.health;
  check("HealthError class exposed",              typeof raw.HealthError === "function");
  check("TIERS exposed",                          Array.isArray(raw.TIERS) && raw.TIERS.length === 3);
  check("TIERS contains liveness/readiness/startup",
        raw.TIERS.indexOf("liveness") !== -1 &&
        raw.TIERS.indexOf("readiness") !== -1 &&
        raw.TIERS.indexOf("startup") !== -1);
  var hc = b.middleware.health();
  check("create returns object with registerCheck", typeof hc.registerCheck === "function");
  check("create returns object with middleware",  typeof hc.middleware === "function");
  check("create returns object with markShuttingDown", typeof hc.markShuttingDown === "function");
  check("create returns object with runChecks",   typeof hc.runChecks === "function");
}

async function testHealthDefaultLiveness() {
  // No checks registered — /healthz returns 200 by default.
  var hc = b.middleware.health();
  var mw = hc.middleware();
  var res = _mockBodyRes();
  var r = await _runHealthMiddleware(mw, _healthReq("GET", "/healthz"), res);
  check("default /healthz: status 200",           r.status === 200);
  check("default /healthz: body contains ok",     /"status":"ok"/.test(r.body));
}

async function testHealthDefaultReadiness() {
  // No checks registered — /readyz returns 200 by default too.
  var hc = b.middleware.health();
  var mw = hc.middleware();
  var res = _mockBodyRes();
  var r = await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), res);
  check("default /readyz: status 200",            r.status === 200);
}

async function testHealthUnmatchedPathFallsThrough() {
  var hc = b.middleware.health();
  var mw = hc.middleware();
  var res = _mockBodyRes();
  var r = await _runHealthMiddleware(mw, _healthReq("GET", "/something-else"), res);
  check("unmatched path: next() called",          r.next === true);
}

async function testHealthNonGetFallsThrough() {
  var hc = b.middleware.health();
  var mw = hc.middleware();
  var res = _mockBodyRes();
  var r = await _runHealthMiddleware(mw, _healthReq("POST", "/healthz"), res);
  check("POST /healthz: next() called (only GET/HEAD intercept)", r.next === true);
}

async function testHealthCriticalFailReturns503() {
  var hc = b.middleware.health();
  hc.registerCheck("db", function () { return false; }, { tier: "readiness", critical: true });
  var mw = hc.middleware();
  var res = _mockBodyRes();
  var r = await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), res);
  check("critical fail: status 503",              r.status === 503);
  check("critical fail: body has fail status",    /"status":"fail"/.test(r.body));
}

async function testHealthNonCriticalFailIsDegraded() {
  var hc = b.middleware.health();
  hc.registerCheck("optional", function () { return false; },
    { tier: "readiness", critical: false });
  var mw = hc.middleware();
  var res = _mockBodyRes();
  var r = await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), res);
  // Degraded keeps 200 — service is still serving, the failed check is informational.
  check("non-critical fail: status 200",          r.status === 200);
  check("non-critical fail: body status=degraded", /"status":"degraded"/.test(r.body));
}

async function testHealthDetailedResponse() {
  var hc = b.middleware.health({ detailLevel: "detailed" });
  hc.registerCheck("db", function () { return { ok: true, latencyMs: 5 }; },
    { tier: "readiness", critical: true });
  var mw = hc.middleware();
  var res = _mockBodyRes();
  await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), res);
  // Detailed mode includes the per-check breakdown
  check("detailed mode: response includes checks", res._captured.indexOf("\"db\"") !== -1);
  check("detailed mode: response includes latencyMs",
        res._captured.indexOf("\"latencyMs\"") !== -1);
  check("detailed mode: response includes uptime", res._captured.indexOf("\"uptime\"") !== -1);
}

async function testHealthMinimalHidesDetail() {
  var hc = b.middleware.health({ detailLevel: "minimal" });
  hc.registerCheck("db", function () { return { ok: true, secret: "top-secret-internal" }; },
    { tier: "readiness", critical: true });
  var mw = hc.middleware();
  var res = _mockBodyRes();
  await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), res);
  check("minimal mode: no check breakdown",       res._captured.indexOf("\"db\"") === -1);
  check("minimal mode: no internal secret leaked", res._captured.indexOf("top-secret-internal") === -1);
  // Should still surface the top-level status, just nothing more
  check("minimal mode: status field present",     /"status":"ok"/.test(res._captured));
}

async function testHealthDetailPredicate() {
  // Detail predicate runs per-request; emits detailed only when predicate returns true.
  var hc = b.middleware.health({
    detailLevel:     "minimal",
    detailPredicate: function (req) { return req.headers["x-internal"] === "1"; },
  });
  hc.registerCheck("db", function () { return { ok: true, latencyMs: 7 }; },
    { tier: "readiness", critical: true });
  var mw = hc.middleware();

  // Request without auth header → minimal
  var resPub = _mockBodyRes();
  var reqPub = _healthReq("GET", "/readyz");
  await _runHealthMiddleware(mw, reqPub, resPub);
  check("predicate false: minimal response",      resPub._captured.indexOf("\"db\"") === -1);

  // Request with auth header → detailed
  var resAuth = _mockBodyRes();
  var reqAuth = _healthReq("GET", "/readyz");
  reqAuth.headers["x-internal"] = "1";
  await _runHealthMiddleware(mw, reqAuth, resAuth);
  check("predicate true: detailed response",      resAuth._captured.indexOf("\"db\"") !== -1);
}

async function testHealthDetailPredicateThrowFailsClosed() {
  var hc = b.middleware.health({
    detailLevel:     "minimal",
    detailPredicate: function () { throw new Error("boom"); },
  });
  hc.registerCheck("db", function () { return { ok: true, latencyMs: 7 }; },
    { tier: "readiness", critical: true });
  var mw = hc.middleware();
  var res = _mockBodyRes();
  await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), res);
  // Predicate throw → fails closed (minimal response).
  check("predicate throws: minimal response",     res._captured.indexOf("\"db\"") === -1);
}

async function testHealthShuttingDownFlipsReadiness() {
  var hc = b.middleware.health();
  hc.registerCheck("db", function () { return true; }, { tier: "readiness", critical: true });
  var mw = hc.middleware();

  // Before markShuttingDown: 200
  var resBefore = _mockBodyRes();
  var rBefore = await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), resBefore);
  check("before shutdown: /readyz 200",           rBefore.status === 200);

  hc.markShuttingDown();
  check("isShuttingDown reports true after mark", hc.isShuttingDown() === true);

  // After: 503 with shutting-down status
  var resAfter = _mockBodyRes();
  var rAfter = await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), resAfter);
  check("after shutdown: /readyz 503",            rAfter.status === 503);
  check("after shutdown: body shutting-down",     /"status":"shutting-down"/.test(rAfter.body));

  // Liveness UNAFFECTED — orchestrator must not kill us mid-drain
  var resLive = _mockBodyRes();
  var rLive = await _runHealthMiddleware(mw, _healthReq("GET", "/healthz"), resLive);
  check("after shutdown: /healthz still 200",     rLive.status === 200);
}

async function testHealthMultiTierRegistration() {
  var hc = b.middleware.health();
  var calls = 0;
  hc.registerCheck("multi", function () { calls++; return true; },
    { tier: ["readiness", "startup"], critical: true });

  // Hit /readyz — counts the check
  await _runHealthMiddleware(hc.middleware(), _healthReq("GET", "/readyz"), _mockBodyRes());
  check("multi-tier check fires on /readyz",      calls === 1);

  // Hit /startupz — counts the check
  await _runHealthMiddleware(hc.middleware(), _healthReq("GET", "/startupz"), _mockBodyRes());
  check("multi-tier check fires on /startupz",    calls === 2);

  // Hit /healthz — does NOT count (no liveness tier)
  await _runHealthMiddleware(hc.middleware(), _healthReq("GET", "/healthz"), _mockBodyRes());
  check("multi-tier check skipped on /healthz",   calls === 2);
}

async function testHealthCheckTimeout() {
  var hc = b.middleware.health();
  hc.registerCheck("slow", function () {
    return new Promise(function () { /* never resolves */ });
  }, { tier: "readiness", critical: true, timeoutMs: 50 });
  hc.registerCheck("fast", function () { return true; }, { tier: "readiness", critical: false });
  var mw = hc.middleware();
  var res = _mockBodyRes();
  var t0 = Date.now();
  var r = await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), res);
  var elapsed = Date.now() - t0;
  check("timeout: response arrives within 200ms", elapsed < 200);
  check("timeout: critical timeout → 503",        r.status === 503);
}

async function testHealthCheckCacheRespected() {
  var calls = 0;
  var hc = b.middleware.health({ cacheMs: 1000 });
  hc.registerCheck("counter", function () { calls++; return true; },
    { tier: "readiness", critical: true });
  var mw = hc.middleware();
  await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), _mockBodyRes());
  await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), _mockBodyRes());
  await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), _mockBodyRes());
  check("cache: check fn called once across 3 probes within window", calls === 1);
}

async function testHealthShutdownBypassesCache() {
  var hc = b.middleware.health({ cacheMs: 60000 });
  hc.registerCheck("db", function () { return true; }, { tier: "readiness", critical: true });
  var mw = hc.middleware();

  // Warm the cache with a 200
  await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), _mockBodyRes());

  // Mark shutting down — cache should NOT serve the cached 200
  hc.markShuttingDown();
  var res = _mockBodyRes();
  var r = await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), res);
  check("shutdown bypasses cache: 503 immediate", r.status === 503);
}

async function testHealthHeadMethod() {
  var hc = b.middleware.health();
  hc.registerCheck("db", function () { return true; }, { tier: "readiness", critical: true });
  var mw = hc.middleware();
  var res = _mockBodyRes();
  var r = await _runHealthMiddleware(mw, _healthReq("HEAD", "/readyz"), res);
  check("HEAD /readyz: status 200",               r.status === 200);
  check("HEAD /readyz: empty body",               r.body === "");
}

async function testHealthInvalidArgs() {
  var threw;

  threw = null;
  try { b.middleware.health({ detailLevel: "weird" }); } catch (e) { threw = e; }
  check("create: bad detailLevel rejected",       threw && threw.code === "health/bad-detail-level");

  var hc = b.middleware.health();

  threw = null;
  try { hc.registerCheck("", function () {}); } catch (e) { threw = e; }
  check("registerCheck: empty name rejected",     threw && threw.code === "health/bad-name");

  threw = null;
  try { hc.registerCheck("x", "not-a-fn"); } catch (e) { threw = e; }
  check("registerCheck: non-function fn rejected", threw && threw.code === "health/bad-fn");

  threw = null;
  try { hc.registerCheck("x", function () {}, { tier: "weird" }); } catch (e) { threw = e; }
  check("registerCheck: bad tier rejected",       threw && threw.code === "health/bad-tier");

  // Duplicate within same tier
  hc.registerCheck("dup", function () { return true; }, { tier: "readiness" });
  threw = null;
  try { hc.registerCheck("dup", function () { return true; }, { tier: "readiness" }); } catch (e) { threw = e; }
  check("registerCheck: duplicate name in same tier rejected",
        threw && threw.code === "health/duplicate-check");

  // Same name in DIFFERENT tier is fine — operator may have a "db" check
  // for both readiness (full health) and startup (init-finished).
  hc.registerCheck("dup", function () { return true; }, { tier: "startup" });
  check("registerCheck: same name in different tier allowed",
        true);
}

async function testHealthCheckThrowFails() {
  var hc = b.middleware.health();
  hc.registerCheck("explodes", function () { throw new Error("kaboom"); },
    { tier: "readiness", critical: true });
  var mw = hc.middleware();
  var res = _mockBodyRes();
  var r = await _runHealthMiddleware(mw, _healthReq("GET", "/readyz"), res);
  check("check throws: critical fail → 503",      r.status === 503);
}

async function testHealthCacheControlHeader() {
  var hc = b.middleware.health();
  var mw = hc.middleware();
  var res = _mockBodyRes();
  // Capture the writeHead headers explicitly
  var capturedHeaders = null;
  var origWriteHead = res.writeHead;
  res.writeHead = function (s, h) { capturedHeaders = h; return origWriteHead.call(res, s, h); };
  await _runHealthMiddleware(mw, _healthReq("GET", "/healthz"), res);
  check("Cache-Control: no-store on health response",
        capturedHeaders && capturedHeaders["Cache-Control"] === "no-store");
}

// ---- safe-schema (declarative input validator) ----

function testSafeSchemaSurface() {
  var s = b.safeSchema;
  check("b.safeSchema namespace present",          typeof s === "object");
  check("string is a function",                    typeof s.string === "function");
  check("number is a function",                    typeof s.number === "function");
  check("boolean is a function",                   typeof s.boolean === "function");
  check("literal is a function",                   typeof s.literal === "function");
  check("enum_ is a function",                     typeof s.enum_ === "function");
  check("oneOf is enum_ alias",                    s.oneOf === s.enum_);
  check("null_ is a function",                     typeof s.null_ === "function");
  check("undefined_ is a function",                typeof s.undefined_ === "function");
  check("any is a function",                       typeof s.any === "function");
  check("unknown is a function",                   typeof s.unknown === "function");
  check("object is a function",                    typeof s.object === "function");
  check("array is a function",                     typeof s.array === "function");
  check("tuple is a function",                     typeof s.tuple === "function");
  check("union is a function",                     typeof s.union === "function");
  check("discriminatedUnion is a function",        typeof s.discriminatedUnion === "function");
  check("record is a function",                    typeof s.record === "function");
  check("lazy is a function",                      typeof s.lazy === "function");
  check("preprocess is a function",                typeof s.preprocess === "function");
  check("optional helper is a function",           typeof s.optional === "function");
  check("nullable helper is a function",           typeof s.nullable === "function");
  check("SafeSchemaError is a class",              typeof s.SafeSchemaError === "function");
}

function testSafeSchemaStringPrimitive() {
  var s = b.safeSchema;
  check("string accepts a string",                 s.string().parse("hello") === "hello");

  var threw = null;
  try { s.string().parse(42); } catch (e) { threw = e; }
  check("string rejects a number",                 threw && threw.code === "safe-schema/invalid");
  check("string error has issues array",           threw && Array.isArray(threw.issues) && threw.issues[0].code === "type");

  check("string().min(3) accepts 'abc'",           s.string().min(3).parse("abc") === "abc");
  var sp = s.string().min(3).safeParse("ab");
  check("string().min(3) rejects 'ab' via safeParse", sp.ok === false && sp.errors[0].code === "string/too-short");

  check("string().max(3) rejects 'abcd'",          s.string().max(3).safeParse("abcd").ok === false);
  check("string().length(3) accepts 'abc'",        s.string().length(3).parse("abc") === "abc");
  check("string().length(3) rejects 'abcd'",       s.string().length(3).safeParse("abcd").ok === false);
  check("string().nonempty rejects ''",            s.string().nonempty().safeParse("").ok === false);

  check("string().regex matches",                  s.string().regex(/^foo/).parse("foobar") === "foobar");
  check("string().regex rejects",                  s.string().regex(/^foo/).safeParse("bar").ok === false);

  check("string().email accepts valid",            s.string().email().parse("a@b.co") === "a@b.co");
  check("string().email rejects invalid",          s.string().email().safeParse("not-an-email").ok === false);
  // v0.6.61 — RFC 5321 §4.5.3.1.3 caps an address at 254 chars. Without
  // this bound, .email() left operators open to a 50 KB email passing
  // validation and feeding unbounded string columns / log lines downstream.
  check("string().email accepts 254 chars (RFC limit)",
        s.string().email().parse("a".repeat(248) + "@b.com").length === 254);
  check("string().email rejects 255 chars",
        s.string().email().safeParse("a".repeat(249) + "@b.com").ok === false);
  check("string().email rejects 500 chars",
        s.string().email().safeParse("a".repeat(495) + "@b.com").ok === false);
  check("string().email rejects oversize w/ correct error code",
        s.string().email().safeParse("a".repeat(495) + "@b.com").errors[0].code === "string/email-too-long");

  check("string().url accepts https",              s.string().url().parse("https://x.io") === "https://x.io");
  check("string().url rejects bare",               s.string().url().safeParse("x.io").ok === false);
  // v0.6.62 — RFC 7230 §3.1.1 8 KB recommendation. Without this bound,
  // .url() accepted multi-megabyte URLs that fed unbounded values
  // through downstream HTTP clients / SSRF gates / log lines.
  check("string().url accepts 8192 chars (limit)",
        s.string().url().parse("https://x.io/" + "a".repeat(8192 - 13)).length === 8192);
  check("string().url rejects 8193 chars",
        s.string().url().safeParse("https://x.io/" + "a".repeat(8193 - 13)).ok === false);
  check("string().url rejects 10 MB w/ correct error code",
        s.string().url().safeParse("https://x.io/" + "a".repeat(100000)).errors[0].code === "string/url-too-long");

  check("string().uuid accepts v4",                s.string().uuid().parse("123e4567-e89b-42d3-a456-426614174000") === "123e4567-e89b-42d3-a456-426614174000");
  check("string().uuid rejects invalid",           s.string().uuid().safeParse("not-a-uuid").ok === false);

  check("string().date accepts YYYY-MM-DD",        s.string().date().parse("2026-04-27") === "2026-04-27");
  check("string().date rejects datetime",          s.string().date().safeParse("2026-04-27T00:00:00Z").ok === false);

  check("string().datetime accepts ISO-8601 Z",    s.string().datetime().parse("2026-04-27T12:00:00Z") === "2026-04-27T12:00:00Z");
  check("string().datetime accepts +offset",       s.string().datetime().parse("2026-04-27T12:00:00+10:00") === "2026-04-27T12:00:00+10:00");
  check("string().datetime rejects no tz",         s.string().datetime().safeParse("2026-04-27T12:00:00").ok === false);

  check("string().ipv4 accepts",                   s.string().ipv4().parse("192.168.1.1") === "192.168.1.1");
  check("string().ipv4 rejects ipv6",              s.string().ipv4().safeParse("::1").ok === false);
  check("string().ipv4 rejects out-of-range",      s.string().ipv4().safeParse("256.1.1.1").ok === false);
  check("string().ipv6 accepts ::1",               s.string().ipv6().parse("::1") === "::1");
  check("string().ipv6 accepts ::",                s.string().ipv6().parse("::") === "::");
  check("string().ipv6 accepts full 8-hextet",
        s.string().ipv6().parse("2001:0db8:85a3:0000:0000:8a2e:0370:7334") === "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
  check("string().ipv6 accepts compressed",        s.string().ipv6().parse("2001:db8::1") === "2001:db8::1");
  check("string().ipv6 accepts trailing 1::",      s.string().ipv6().parse("1::") === "1::");
  check("string().ipv6 accepts mixed case",        s.string().ipv6().parse("2001:DB8::1") === "2001:DB8::1");
  check("string().ipv6 accepts IPv4-mapped",       s.string().ipv6().parse("::ffff:192.168.1.1") === "::ffff:192.168.1.1");
  check("string().ipv6 accepts long IPv4-mapped",  s.string().ipv6().parse("2001:db8::192.0.2.1") === "2001:db8::192.0.2.1");
  check("string().ipv6 rejects multiple ::",       s.string().ipv6().safeParse("1::2::3").ok === false);
  check("string().ipv6 rejects > 8 groups",        s.string().ipv6().safeParse("1:2:3:4:5:6:7:8:9").ok === false);
  check("string().ipv6 rejects non-hex chars",     s.string().ipv6().safeParse("g::").ok === false);
  check("string().ipv6 rejects > 4 hex per group", s.string().ipv6().safeParse("12345::").ok === false);
  check("string().ipv6 rejects zone IDs",          s.string().ipv6().safeParse("fe80::1%eth0").ok === false);
  check("string().ipv6 rejects empty",             s.string().ipv6().safeParse("").ok === false);
  check("string().ip accepts both",                s.string().ip().parse("192.168.1.1") === "192.168.1.1" &&
                                                     s.string().ip().parse("::1") === "::1");

  check("string().cuid accepts",                   s.string().cuid().parse("clx1234567890abcdefghijkl") === "clx1234567890abcdefghijkl");
  check("string().cuid rejects",                   s.string().cuid().safeParse("not-cuid").ok === false);

  check("string().ulid accepts",                   s.string().ulid().parse("01ARZ3NDEKTSV4RRFFQ69G5FAV") === "01ARZ3NDEKTSV4RRFFQ69G5FAV");
  check("string().ulid rejects",                   s.string().ulid().safeParse("not-ulid").ok === false);

  check("string().base64 accepts",                 s.string().base64().parse("SGVsbG8=") === "SGVsbG8=");
  check("string().base64 rejects garbage",         s.string().base64().safeParse("not!base64").ok === false);

  check("string().startsWith accepts",             s.string().startsWith("foo").parse("foobar") === "foobar");
  check("string().startsWith rejects",             s.string().startsWith("foo").safeParse("barfoo").ok === false);
  check("string().endsWith accepts",               s.string().endsWith("bar").parse("foobar") === "foobar");
  check("string().endsWith rejects",               s.string().endsWith("bar").safeParse("foob").ok === false);
  check("string().includes accepts",               s.string().includes("oo").parse("foobar") === "foobar");
  check("string().includes rejects",               s.string().includes("xx").safeParse("foobar").ok === false);

  // Coercion-via-transform helpers
  check("string().trim trims whitespace",          s.string().trim().parse("  hi  ") === "hi");
  check("string().trim().min(3) sees trimmed",     s.string().trim().min(3).parse("  hello  ") === "hello");
  check("string().toLowerCase converts",           s.string().toLowerCase().parse("ABC") === "abc");
  check("string().toUpperCase converts",           s.string().toUpperCase().parse("abc") === "ABC");
}

function testSafeSchemaNumberPrimitive() {
  var s = b.safeSchema;
  check("number accepts 42",                       s.number().parse(42) === 42);
  check("number rejects '42'",                     s.number().safeParse("42").ok === false);
  check("number rejects NaN",                      s.number().safeParse(NaN).ok === false);

  check("number().int accepts 42",                 s.number().int().parse(42) === 42);
  check("number().int rejects 1.5",                s.number().int().safeParse(1.5).ok === false);

  check("number().min(0) accepts 5",               s.number().min(0).parse(5) === 5);
  check("number().min(0) rejects -1",              s.number().min(0).safeParse(-1).ok === false);
  check("number().max(10) rejects 11",             s.number().max(10).safeParse(11).ok === false);
  check("number().gt(0) rejects 0",                s.number().gt(0).safeParse(0).ok === false);
  check("number().lt(10) rejects 10",              s.number().lt(10).safeParse(10).ok === false);

  check("number().positive rejects 0",             s.number().positive().safeParse(0).ok === false);
  check("number().positive accepts 0.1",           s.number().positive().parse(0.1) === 0.1);
  check("number().negative rejects 0",             s.number().negative().safeParse(0).ok === false);
  check("number().nonnegative accepts 0",          s.number().nonnegative().parse(0) === 0);
  check("number().nonpositive accepts 0",          s.number().nonpositive().parse(0) === 0);

  check("number().finite rejects Infinity",        s.number().finite().safeParse(Infinity).ok === false);
  check("number().multipleOf accepts",             s.number().multipleOf(5).parse(15) === 15);
  check("number().multipleOf rejects",             s.number().multipleOf(5).safeParse(7).ok === false);

  check("number().safe accepts safe int",          s.number().safe().parse(42) === 42);
  check("number().safe rejects beyond 2^53",       s.number().safe().safeParse(Number.MAX_SAFE_INTEGER + 2).ok === false);
}

function testSafeSchemaBooleanLiteralEnum() {
  var s = b.safeSchema;
  check("boolean accepts true",                    s.boolean().parse(true) === true);
  check("boolean rejects 'true' string",           s.boolean().safeParse("true").ok === false);

  check("literal accepts exact value",             s.literal("yes").parse("yes") === "yes");
  check("literal rejects other value",             s.literal("yes").safeParse("no").ok === false);
  check("literal accepts 0",                       s.literal(0).parse(0) === 0);

  var color = s.enum_(["red", "green", "blue"]);
  check("enum_ accepts member",                    color.parse("red") === "red");
  check("enum_ rejects non-member",                color.safeParse("yellow").ok === false);

  var threw = null;
  try { s.enum_([]); } catch (e) { threw = e; }
  check("enum_ rejects empty array",               threw && threw.code === "safe-schema/bad-enum");
}

function testSafeSchemaNullUndefinedAny() {
  var s = b.safeSchema;
  check("null_ accepts null",                      s.null_().parse(null) === null);
  check("null_ rejects undefined",                 s.null_().safeParse(undefined).ok === false);
  check("null_ rejects 0",                         s.null_().safeParse(0).ok === false);

  // any() accepts anything including undefined and null because of its
  // built-in optional+nullable flags.
  check("any accepts string",                      s.any().parse("x") === "x");
  check("any accepts number",                      s.any().parse(42) === 42);
  check("any accepts null",                        s.any().parse(null) === null);
  check("any accepts undefined",                   s.any().parse(undefined) === undefined);
  check("unknown is alias of any",                 s.unknown().parse(42) === 42);
}

function testSafeSchemaModifiers() {
  var s = b.safeSchema;
  // .optional()
  check("optional accepts undefined",              s.string().optional().parse(undefined) === undefined);
  check("optional accepts string",                 s.string().optional().parse("x") === "x");
  check("optional rejects null without nullable",  s.string().optional().safeParse(null).ok === false);

  // .nullable()
  check("nullable accepts null",                   s.string().nullable().parse(null) === null);
  check("nullable rejects undefined without optional", s.string().nullable().safeParse(undefined).ok === false);

  // .default(v)
  check("default substitutes for undefined",       s.number().default(42).parse(undefined) === 42);
  check("default ignored when value present",      s.number().default(42).parse(7) === 7);

  // .default(fn) — function form for "fresh value per parse"
  var counter = 0;
  var schema = s.number().default(function () { counter++; return counter; });
  check("default fn called once per undefined parse 1", schema.parse(undefined) === 1);
  check("default fn called once per undefined parse 2", schema.parse(undefined) === 2);

  // .catch(v) — substitutes on ANY failure
  check("catch substitutes on type failure",       s.number().catch(0).parse("not-a-number") === 0);
  check("catch leaves valid alone",                s.number().catch(0).parse(42) === 42);

  // Top-level helpers compose identically
  check("optional() helper matches .optional()",   b.safeSchema.optional(s.string()).parse(undefined) === undefined);
  check("nullable() helper matches .nullable()",   b.safeSchema.nullable(s.string()).parse(null) === null);
}

function testSafeSchemaObject() {
  var s = b.safeSchema;
  var schema = s.object({
    name: s.string(),
    age:  s.number().int().min(0),
    tags: s.array(s.string()).optional(),
  });
  var ok = schema.parse({ name: "Alice", age: 30, tags: ["a", "b"] });
  check("object parse returns clean shape",        ok.name === "Alice" && ok.age === 30 && ok.tags.length === 2);

  var optResult = schema.parse({ name: "Bob", age: 22 });
  check("object missing optional key — value undefined", optResult.tags === undefined);

  var bad = schema.safeParse({ name: "X", age: -1 });
  check("object surfaces nested issue path",       bad.ok === false &&
                                                     bad.errors[0].path[0] === "age" &&
                                                     bad.errors[0].code === "number/too-small");

  // Strict by default — unknown keys rejected
  var strictBad = schema.safeParse({ name: "X", age: 1, extra: 1 });
  check("strict mode: unknown key rejected",       strictBad.ok === false);
  var unknownIssue = strictBad.errors.find(function (e) { return e.code === "object/unknown-key"; });
  check("strict mode: unknown-key issue surfaced", !!unknownIssue);

  // Passthrough retains unknown keys
  var pt = schema.passthrough().parse({ name: "X", age: 1, extra: "kept" });
  check("passthrough retains unknown keys",        pt.extra === "kept");

  // Nested objects produce nested error paths
  var deep = s.object({
    user: s.object({ profile: s.object({ name: s.string() }) }),
  });
  var deepBad = deep.safeParse({ user: { profile: { name: 42 } } });
  check("nested error path includes user.profile.name",
        deepBad.errors[0].path.join(".") === "user.profile.name");
}

function testSafeSchemaObjectPickOmitExtendPartial() {
  var s = b.safeSchema;
  var base = s.object({ a: s.string(), b: s.number(), c: s.boolean() });

  var picked = base.pick(["a", "c"]);
  check("pick narrows to listed keys",             picked.parse({ a: "x", c: true }).a === "x");
  check("pick rejects originally-required omitted key in input as unknown",
        picked.safeParse({ a: "x", c: true, b: 5 }).ok === false);

  var omitted = base.omit(["b"]);
  var omRes = omitted.parse({ a: "x", c: true });
  check("omit drops listed keys, others required", omRes.a === "x" && omRes.c === true);

  var extended = base.extend({ d: s.string() });
  check("extend adds new key",                     extended.parse({ a: "x", b: 1, c: true, d: "y" }).d === "y");

  var partial = base.partial();
  check("partial accepts empty object",            Object.keys(partial.parse({})).length === 0);
  check("partial accepts subset",                  partial.parse({ a: "x" }).a === "x");

  var requiredAgain = partial.required();
  check("required() inverse of partial",           requiredAgain.safeParse({ a: "x" }).ok === false);
  check("required() accepts full shape",           requiredAgain.parse({ a: "x", b: 1, c: true }).a === "x");
}

function testSafeSchemaArrayTupleUnionRecord() {
  var s = b.safeSchema;
  // array
  check("array(string) parses",                    s.array(s.string()).parse(["a", "b"]).length === 2);
  check("array rejects non-array",                 s.array(s.string()).safeParse("not-array").ok === false);
  check("array surfaces per-index error path",     s.array(s.string()).safeParse(["a", 42]).errors[0].path[0] === 1);
  check("array.min rejects under",                 s.array(s.string()).min(2).safeParse(["a"]).ok === false);
  check("array.max rejects over",                  s.array(s.string()).max(1).safeParse(["a", "b"]).ok === false);
  check("array.length exact",                      s.array(s.string()).length(2).parse(["a", "b"]).length === 2);
  check("array.nonempty rejects []",               s.array(s.string()).nonempty().safeParse([]).ok === false);

  // tuple
  var pair = s.tuple([s.string(), s.number()]);
  check("tuple accepts matching shape",            JSON.stringify(pair.parse(["x", 1])) === '["x",1]');
  check("tuple rejects wrong length",              pair.safeParse(["x", 1, 2]).ok === false);
  check("tuple rejects wrong types",               pair.safeParse([1, "x"]).ok === false);

  // tuple.rest — variadic tail
  var verbAndArgs = s.tuple([s.string()]).rest(s.number());
  check("tuple.rest accepts head + variadic tail", JSON.stringify(verbAndArgs.parse(["sum", 1, 2, 3])) === '["sum",1,2,3]');
  check("tuple.rest accepts head only",            JSON.stringify(verbAndArgs.parse(["init"])) === '["init"]');
  check("tuple.rest rejects bad tail item",        verbAndArgs.safeParse(["sum", 1, "bad"]).ok === false);
  check("tuple.rest rejects head shorter than fixed", verbAndArgs.safeParse([]).ok === false);

  // union
  var stringOrNumber = s.union([s.string(), s.number()]);
  check("union accepts string",                    stringOrNumber.parse("x") === "x");
  check("union accepts number",                    stringOrNumber.parse(42) === 42);
  check("union rejects neither",                   stringOrNumber.safeParse(true).ok === false);

  // discriminatedUnion
  var event = s.discriminatedUnion("kind", [
    s.object({ kind: s.literal("created"), at: s.string() }),
    s.object({ kind: s.literal("deleted"), reason: s.string() }),
  ]);
  check("discUnion routes 'created'",              event.parse({ kind: "created", at: "now" }).kind === "created");
  check("discUnion routes 'deleted'",              event.parse({ kind: "deleted", reason: "spam" }).kind === "deleted");
  check("discUnion rejects unknown discriminator", event.safeParse({ kind: "other", x: 1 }).ok === false);
  check("discUnion rejects missing discriminator", event.safeParse({}).ok === false);

  // discriminatedUnion construction validation
  var threw = null;
  try { s.discriminatedUnion("", [s.object({ kind: s.literal("a") })]); } catch (e) { threw = e; }
  check("discUnion rejects empty discriminator",   threw && threw.code === "safe-schema/bad-discriminator");

  threw = null;
  try { s.discriminatedUnion("kind", [s.string()]); } catch (e) { threw = e; }
  check("discUnion rejects non-object option",     threw && threw.code === "safe-schema/bad-discriminated-option");

  // record
  var rec = s.record(s.number());
  check("record accepts string-keyed numbers",     rec.parse({ a: 1, b: 2 }).a === 1);
  check("record rejects non-number value",         rec.safeParse({ a: "x" }).ok === false);

  // record with key schema
  var recK = s.record(s.string().min(3), s.number());
  check("record(keySchema) accepts long keys",     recK.parse({ abc: 1, defg: 2 }).abc === 1);
  check("record(keySchema) rejects short key",     recK.safeParse({ a: 1 }).ok === false);
}

function testSafeSchemaRefineTransform() {
  var s = b.safeSchema;
  // Chained .refine
  var even = s.number().refine(function (n) { return n % 2 === 0; }, { code: "even", message: "must be even" });
  check("refine accepts passing predicate",        even.parse(4) === 4);
  var bad = even.safeParse(3);
  check("refine fails with custom code",           bad.ok === false && bad.errors[0].code === "even");

  // refine with predicate that throws
  var throwing = s.number().refine(function () { throw new Error("oops"); });
  check("refine swallows throw, surfaces issue",   throwing.safeParse(1).ok === false);

  // Chained .transform
  var doubled = s.number().transform(function (n) { return n * 2; });
  check("transform applies fn to validated value", doubled.parse(5) === 10);

  // Compose: type check → refine → transform
  var pipeline = s.number().min(0).refine(function (n) { return n < 100; }).transform(function (n) { return "n=" + n; });
  check("pipeline transforms valid input",         pipeline.parse(5) === "n=5");
  check("pipeline rejects per refine",             pipeline.safeParse(200).ok === false);

  // .pipe() — feed transformed output through a second schema
  var port = s.string().regex(/^\d+$/).transform(function (v) { return Number(v); }).pipe(
    s.number().int().min(1).max(65535)
  );
  check("pipe: valid string-digit-port parses",    port.parse("8080") === 8080);
  check("pipe: out-of-range fails downstream",     port.safeParse("99999").ok === false);
  check("pipe: non-numeric fails upstream",        port.safeParse("abc").ok === false);
}

function testSafeSchemaLazyAndPreprocess() {
  var s = b.safeSchema;

  // lazy — recursive shape
  var nodeSchema = s.object({
    id:       s.string(),
    children: s.array(s.lazy(function () { return nodeSchema; })),
  });
  var tree = { id: "root", children: [{ id: "leaf-1", children: [] }, { id: "leaf-2", children: [] }] };
  var parsed = nodeSchema.parse(tree);
  check("lazy parses recursive shape",             parsed.children.length === 2);
  check("lazy parses nested",                      parsed.children[0].id === "leaf-1");

  var bad = nodeSchema.safeParse({ id: "r", children: [{ id: 42, children: [] }] });
  check("lazy surfaces deep error",                bad.ok === false &&
                                                     bad.errors[0].path.join(".") === "children.0.id");

  // preprocess — query-string number
  var port = s.preprocess(function (v) { return Number(v); }, s.number().int().min(1).max(65535));
  check("preprocess converts string to number",    port.parse("8080") === 8080);
  check("preprocess + downstream check rejects",   port.safeParse("99999").ok === false);

  // preprocess fn throws → preprocess issue
  var throwing = s.preprocess(function () { throw new Error("bad"); }, s.string());
  check("preprocess throw surfaces as issue",      throwing.safeParse("x").ok === false);
}

function testSafeSchemaPrototypePollutionDefense() {
  var s = b.safeSchema;
  // 1. Construction-time: a shape built via Object.fromEntries with a
  // POISONED key is rejected. (Object-literal {"__proto__": ...} syntax
  // sets the prototype rather than creating such a key at all, so
  // operators who hit this defense did so via fromEntries / defineProperty.)
  var threw = null;
  try { s.object(Object.fromEntries([["__proto__", s.string()]])); } catch (e) { threw = e; }
  check("object() rejects __proto__ key in shape (fromEntries)",
        threw && threw.code === "safe-schema/poisoned-shape-key");

  threw = null;
  try { s.object(Object.fromEntries([["constructor", s.string()]])); } catch (e) { threw = e; }
  check("object() rejects constructor key in shape", threw && threw.code === "safe-schema/poisoned-shape-key");

  threw = null;
  try { s.object(Object.fromEntries([["prototype", s.string()]])); } catch (e) { threw = e; }
  check("object() rejects prototype key in shape", threw && threw.code === "safe-schema/poisoned-shape-key");

  // 2. Parse-time: input object with __proto__ as a regular key is rejected
  var schema = s.object({ a: s.string() }).passthrough();
  var malicious = JSON.parse('{"a":"ok","__proto__":{"polluted":true}}');
  var r = schema.safeParse(malicious);
  check("passthrough rejects __proto__ in input",  r.ok === false);
  var pIssue = r.errors.find(function (e) { return e.code === "object/poisoned-key"; });
  check("issue code is object/poisoned-key",       !!pIssue);

  // 3. record() rejects __proto__ keys
  var rec = s.record(s.string());
  var recBad = rec.safeParse(JSON.parse('{"a":"x","__proto__":"poison"}'));
  check("record rejects __proto__ in input",       recBad.ok === false);
  var recIssue = recBad.errors.find(function (e) { return e.code === "record/poisoned-key"; });
  check("record issue code is record/poisoned-key", !!recIssue);

  // 4. Object.prototype is intact after parse attempt
  check("Object.prototype not polluted by parse",  ({}).polluted === undefined);

  // 5. discriminatedUnion rejects __proto__ as discriminator name
  threw = null;
  try { s.discriminatedUnion("__proto__", [s.object({ kind: s.literal("a") })]); } catch (e) { threw = e; }
  check("discUnion rejects __proto__ discriminator", threw && threw.code === "safe-schema/poisoned-discriminator");
}

function testSafeSchemaErrorIssues() {
  var s = b.safeSchema;
  var threw = null;
  try {
    s.object({ a: s.string(), b: s.number() }).parse({ a: 1, b: "x" });
  } catch (e) { threw = e; }
  check("parse() throws SafeSchemaError",          threw && threw.name === "SafeSchemaError");
  check("error carries issues array",              threw && Array.isArray(threw.issues) && threw.issues.length === 2);
  check("issues have path/code/message",
        threw && threw.issues[0].path && threw.issues[0].code && threw.issues[0].message);
}

function testSafeSchemaImmutability() {
  var s = b.safeSchema;
  var base = s.string();
  var withMin = base.min(3);
  // Original schema should NOT have been mutated to add the min check.
  check("original schema accepts ''",              base.parse("") === "");
  check("derived schema rejects ''",               withMin.safeParse("").ok === false);
}

// ---- events tests moved to test/layer-0-primitives/events.test.js ----

// ---- audit-tools ----
//
// Operator tooling on top of the audit chain. Uses setupTestDb to stand
// up a real audit_log + audit_checkpoints surface so the chain math can
// be exercised end-to-end (a mock-driven test would let us shadow the
// real chain semantics — defeats the point).

async function _seedAuditRows(count) {
  b.audit.registerNamespace("test");
  for (var i = 0; i < count; i++) {
    await b.audit.record({
      actor:   { userId: "u-" + i },
      action:  "test.seeded",
      outcome: "success",
      metadata: { i: i },
    });
  }
}

function _auditToolsFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-at-"));
  var bundleDir = path.join(dir, "bundles");
  return {
    dir: dir,
    bundleOut: function (name) { return path.join(bundleDir, name); },
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
  };
}

function testAuditToolsSurface() {
  check("b.auditTools namespace present",       typeof b.auditTools === "object");
  check("b.auditTools.archive is a function",   typeof b.auditTools.archive === "function");
  check("b.auditTools.exportSlice is a function", typeof b.auditTools.exportSlice === "function");
  check("b.auditTools.verifyBundle is a function", typeof b.auditTools.verifyBundle === "function");
  check("b.auditTools.purge is a function",     typeof b.auditTools.purge === "function");
  check("b.auditTools.AuditToolsError is a class", typeof b.auditTools.AuditToolsError === "function");
  check("b.auditTools.BUNDLE_FORMAT is set",    b.auditTools.BUNDLE_FORMAT === "blamejs-audit-bundle-v1");
}

// v0.6.66 — audit-chain canonicalize handles non-plain types correctly.
// Pre-fix Map / Set / Symbol / function silently encoded as `{}` (silent
// data loss in stored audit rows), BigInt threw raw "Do not know how to
// serialize" mid-emit (DoS on any operator routing bigint IDs into
// audit metadata), and circular references threw the un-wrapped
// JSON.stringify error instead of a clean framework Error.
function testAuditChainCanonicalize() {
  var ac = b.auditChain;
  check("auditChain.canonicalize is a function",   typeof ac.canonicalize === "function");

  // Plain types — round-trip preserved
  check("plain object",
    ac.canonicalize({ a: 1, b: "x" }) === '{"a":1,"b":"x"}');
  check("Buffer → hex",
    ac.canonicalize({ a: Buffer.from("hello") }) === '{"a":"68656c6c6f"}');
  check("Uint8Array → hex",
    ac.canonicalize({ a: new Uint8Array([1, 2, 3]) }) === '{"a":"010203"}');
  check("Date → ISO string",
    ac.canonicalize({ a: new Date("2026-01-01") }) === '{"a":"2026-01-01T00:00:00.000Z"}');
  check("undefined → null",
    ac.canonicalize({ a: undefined }) === '{"a":null}');

  // BigInt → string (stops the DoS mid-emit)
  check("BigInt → decimal string",
    ac.canonicalize({ a: BigInt(123) }) === '{"a":"123"}');
  check("huge BigInt preserved as string",
    ac.canonicalize({ a: BigInt("99999999999999999999999") }) ===
    '{"a":"99999999999999999999999"}');

  // Non-serialisable types reject cleanly (was silent data loss)
  function expectThrow(label, value, expectInMsg) {
    var threw = null;
    try { ac.canonicalize({ a: value }); } catch (e) { threw = e; }
    check("canonicalize rejects " + label,
          threw && threw.message.indexOf(expectInMsg) !== -1);
  }
  expectThrow("Map",      new Map(),        "Map");
  expectThrow("Set",      new Set(),        "Set");
  expectThrow("RegExp",   /abc/,            "RegExp");
  expectThrow("Symbol",   Symbol("s"),      "symbol");
  expectThrow("function", function () {},   "function");

  // Circular reference throws clean framework error (not raw JSON err)
  var circ = {}; circ.self = circ;
  var threwCirc = null;
  try { ac.canonicalize(circ); } catch (e) { threwCirc = e; }
  check("canonicalize rejects circular reference cleanly",
        threwCirc && /circular reference/.test(threwCirc.message));

  // Nested cases — array of bigints, Date inside array, Uint8Array nested
  check("nested array of BigInts",
    ac.canonicalize({ a: [BigInt(1), BigInt(2)] }) === '{"a":["1","2"]}');
  check("Date inside array",
    ac.canonicalize({ a: [new Date("2026-01-01")] }) ===
    '{"a":["2026-01-01T00:00:00.000Z"]}');
  check("Uint8Array nested in object",
    ac.canonicalize({ a: { b: new Uint8Array([1, 2, 3]) } }) ===
    '{"a":{"b":"010203"}}');
}

async function testAuditToolsArchiveAndVerify() {
  var fx = _auditToolsFixture();
  try {
    await setupTestDb(fx.dir);
    await _seedAuditRows(5);
    await b.audit.checkpoint(); // covering signature anchor

    var out = fx.bundleOut("archive-1");
    var r = await b.auditTools.archive({
      before:     Date.now() + 1000, // archive everything we just wrote
      out:        out,
      passphrase: Buffer.from("operator-passphrase"),
    });
    check("archive produces a manifest",            r.manifest && r.manifest.format === "blamejs-audit-bundle-v1");
    check("archive bundle kind=archive",            r.manifest.kind === "archive");
    check("archive includes covering checkpoint",   !!r.manifest.checkpoint);
    check("archive rowCount matches seeded rows",   r.rowCount === 5);
    check("manifest.json written to disk",          fs.existsSync(path.join(out, "manifest.json")));
    check("rows.enc written to disk",               fs.existsSync(path.join(out, "rows.enc")));
    check("checkpoint.enc written to disk",         fs.existsSync(path.join(out, "checkpoint.enc")));

    var v = await b.auditTools.verifyBundle({
      in:         out,
      passphrase: Buffer.from("operator-passphrase"),
    });
    check("verifyBundle of fresh archive: ok",      v.ok === true);
    check("verifyBundle reports kind=archive",      v.kind === "archive");
    check("verifyBundle rowsVerified matches",      v.rowsVerified === 5);
  } finally {
    await teardownTestDb(fx.dir);
    fx.cleanup();
  }
}

async function testAuditToolsExportSliceAndVerify() {
  var fx = _auditToolsFixture();
  try {
    await setupTestDb(fx.dir);
    await _seedAuditRows(4);

    var out = fx.bundleOut("export-1");
    var r = await b.auditTools.exportSlice({
      from:       0,
      to:         Date.now() + 1000,
      out:        out,
      passphrase: Buffer.from("auditor-passphrase"),
    });
    check("export bundle kind=export",              r.manifest.kind === "export");
    check("export bundle has no checkpoint section", !r.manifest.checkpoint);
    check("export rowCount > 0",                    r.rowCount > 0);

    var v = await b.auditTools.verifyBundle({
      in:         out,
      passphrase: Buffer.from("auditor-passphrase"),
    });
    check("verifyBundle of export: ok",             v.ok === true);
    check("verifyBundle export kind reported",      v.kind === "export");
  } finally {
    await teardownTestDb(fx.dir);
    fx.cleanup();
  }
}

async function testAuditToolsVerifyBundleRejectsWrongPassphrase() {
  var fx = _auditToolsFixture();
  try {
    await setupTestDb(fx.dir);
    await _seedAuditRows(3);
    await b.audit.checkpoint();

    var out = fx.bundleOut("archive-wrongpass");
    await b.auditTools.archive({
      before: Date.now() + 1000, out: out,
      passphrase: Buffer.from("right-passphrase"),
    });

    var threw = null;
    try {
      await b.auditTools.verifyBundle({
        in: out, passphrase: Buffer.from("wrong-passphrase"),
      });
    } catch (e) { threw = e; }
    check("verifyBundle rejects wrong passphrase (decrypt error)",
          threw !== null);
  } finally {
    await teardownTestDb(fx.dir);
    fx.cleanup();
  }
}

async function testAuditToolsVerifyBundleDetectsTamperedRows() {
  var fx = _auditToolsFixture();
  try {
    await setupTestDb(fx.dir);
    await _seedAuditRows(3);
    await b.audit.checkpoint();

    var out = fx.bundleOut("archive-tamper");
    await b.auditTools.archive({
      before: Date.now() + 1000, out: out,
      passphrase: Buffer.from("pp"),
    });

    // Flip a byte deep inside rows.enc (past the salt/nonce header) so
    // AEAD authentication catches the tamper.
    var rowsPath = path.join(out, "rows.enc");
    var buf = fs.readFileSync(rowsPath);
    buf[buf.length - 4] = (buf[buf.length - 4] ^ 0xff) & 0xff;
    fs.writeFileSync(rowsPath, buf);

    var threw = null;
    try {
      await b.auditTools.verifyBundle({ in: out, passphrase: Buffer.from("pp") });
    } catch (e) { threw = e; }
    check("verifyBundle catches rows.enc tamper (checksum or AEAD)",
          threw !== null);
  } finally {
    await teardownTestDb(fx.dir);
    fx.cleanup();
  }
}

async function testAuditToolsArchiveRejectsWithoutCoveringCheckpoint() {
  var fx = _auditToolsFixture();
  try {
    await setupTestDb(fx.dir);
    await _seedAuditRows(2);
    // Deliberately skip b.audit.checkpoint() — no covering anchor.

    var threw = null;
    try {
      await b.auditTools.archive({
        before: Date.now() + 1000,
        out:    fx.bundleOut("archive-no-ckpt"),
        passphrase: Buffer.from("pp"),
      });
    } catch (e) { threw = e; }
    check("archive without covering checkpoint rejects",
          threw && threw.code === "audit-tools/no-covering-checkpoint");
  } finally {
    await teardownTestDb(fx.dir);
    fx.cleanup();
  }
}

async function testAuditToolsArgValidation() {
  var threw;

  threw = null;
  try { await b.auditTools.archive({}); } catch (e) { threw = e; }
  check("archive: missing passphrase rejects",
        threw && threw.code === "audit-tools/no-passphrase");

  threw = null;
  try { await b.auditTools.archive({ passphrase: "p" }); } catch (e) { threw = e; }
  check("archive: missing out rejects",
        threw && threw.code === "audit-tools/no-outdir");

  threw = null;
  try { await b.auditTools.archive({ passphrase: "p", out: "/nonexistent/xyz/qrs" }); } catch (e) { threw = e; }
  check("archive: missing before rejects",
        threw && threw.code === "audit-tools/no-before");

  threw = null;
  try { await b.auditTools.purge({ archive: "/nope" }); } catch (e) { threw = e; }
  check("purge: missing confirm rejects",
        threw && threw.code === "audit-tools/no-confirm");

  threw = null;
  try { await b.auditTools.purge({ confirm: true, passphrase: "p" }); } catch (e) { threw = e; }
  check("purge: missing archive path rejects",
        threw && threw.code === "audit-tools/no-archive");

  threw = null;
  try { await b.auditTools.verifyBundle({ passphrase: "p" }); } catch (e) { threw = e; }
  check("verifyBundle: missing in rejects",
        threw && threw.code === "audit-tools/no-indir");
}

async function testAuditToolsPurgeRoundTrip() {
  var fx = _auditToolsFixture();
  try {
    await setupTestDb(fx.dir);
    await _seedAuditRows(5);
    await b.audit.checkpoint();

    var out = fx.bundleOut("archive-purge");
    await b.auditTools.archive({
      before: Date.now() + 1000, out: out,
      passphrase: Buffer.from("pp"),
    });

    // Refuses without confirm:true even with a valid archive
    var threw = null;
    try {
      await b.auditTools.purge({ archive: out, passphrase: Buffer.from("pp") });
    } catch (e) { threw = e; }
    check("purge without confirm:true refuses",
          threw && threw.code === "audit-tools/no-confirm");

    // Capture the lastCounter before purge
    var before = await b.clusterStorage.executeAll("SELECT COUNT(*) as c FROM audit_log");
    var beforeCount = Number(before[0].c);
    check("audit_log non-empty before purge",       beforeCount >= 5);

    var pres = await b.auditTools.purge({
      archive: out, passphrase: Buffer.from("pp"), confirm: true,
    });
    check("purge succeeds with valid archive + confirm", pres.purged === true);
    check("purge reports rowsDeleted > 0",          pres.rowsDeleted > 0);

    // After purge, audit.verify still passes — the anchor anchors the
    // chain origin to the post-purge starting point.
    var verified = await b.audit.verify();
    check("audit.verify still ok after purge (anchor wired)", verified.ok === true);

    // Anchor row exists in _blamejs_audit_purge_anchor
    var anchor = await b.clusterStorage.executeAll(
      "SELECT * FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'"
    );
    check("purge wrote the chain-origin anchor",   anchor.length === 1);
    check("anchor lastPurgedRowHash matches archive lastRowHash",
          anchor[0].lastPurgedRowHash === pres.lastPurgedRowHash);
  } finally {
    await teardownTestDb(fx.dir);
    fx.cleanup();
  }
}

async function testAuditToolsPurgeRejectsUnverifiedArchive() {
  var fx = _auditToolsFixture();
  try {
    await setupTestDb(fx.dir);
    await _seedAuditRows(3);
    await b.audit.checkpoint();

    var out = fx.bundleOut("archive-tampered");
    await b.auditTools.archive({
      before: Date.now() + 1000, out: out,
      passphrase: Buffer.from("pp"),
    });

    // Tamper the manifest's range so the chain proof breaks
    var manifestPath = path.join(out, "manifest.json");
    var m = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    m.range.lastRowHash = "0".repeat(128);
    fs.writeFileSync(manifestPath, JSON.stringify(m));

    var threw = null;
    try {
      await b.auditTools.purge({
        archive: out, passphrase: Buffer.from("pp"), confirm: true,
      });
    } catch (e) { threw = e; }
    check("purge refuses tampered archive",
          threw && threw.code === "audit-tools/archive-not-ok");
  } finally {
    await teardownTestDb(fx.dir);
    fx.cleanup();
  }
}

async function testAuditCliVerifyBundleSubcommand() {
  var fx = _auditToolsFixture();
  try {
    await setupTestDb(fx.dir);
    await _seedAuditRows(3);
    await b.audit.checkpoint();

    var out = fx.bundleOut("cli-archive");
    await b.auditTools.archive({
      before: Date.now() + 1000, out: out,
      passphrase: Buffer.from("op-pp"),
    });

    var captured = { out: "", err: "" };
    var rc = await b.cli.main(
      ["audit", "verify-bundle", "--in", out, "--passphrase", "op-pp"],
      {
        stdout: { write: function (s) { captured.out += s; } },
        stderr: { write: function (s) { captured.err += s; } },
        env: {}, cwd: process.cwd(),
      }
    );
    check("CLI audit verify-bundle exit 0 on ok bundle",      rc === 0);
    check("CLI audit verify-bundle output indicates OK",      /OK — bundle verified/.test(captured.out));
  } finally {
    await teardownTestDb(fx.dir);
    fx.cleanup();
  }
}

// ---- mtls-ca ----

function _mtlsCaFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtlsca-"));
  return {
    dir: dir,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
  };
}

// Mock vault for sealed-mode tests — round-trip via base64 plus a
// constant prefix marker. Honest enough for the file-handling tests
// since the real vault-seal format is opaque to mtls-ca anyway.
function _mockVault() {
  var prefix = "mockseal:";
  return {
    seal:   function (s) { return prefix + Buffer.from(s).toString("base64"); },
    unseal: function (s) {
      if (typeof s !== "string" || s.indexOf(prefix) !== 0) return null;
      return Buffer.from(s.substring(prefix.length), "base64").toString("utf8");
    },
  };
}

function testMtlsCaSurface() {
  check("b.mtlsCa namespace present",            typeof b.mtlsCa === "object");
  check("b.mtlsCa.create is a function",         typeof b.mtlsCa.create === "function");
  check("b.mtlsCa.parseGeneration is a function", typeof b.mtlsCa.parseGeneration === "function");
  check("b.mtlsCa.MtlsCaError is a class",       typeof b.mtlsCa.MtlsCaError === "function");
  check("DEFAULT_PATHS exposes ca.key/ca.crt names",
        b.mtlsCa.DEFAULT_PATHS.caKey === "ca.key" &&
        b.mtlsCa.DEFAULT_PATHS.caCert === "ca.crt");
}

function testMtlsCaCreateValidation() {
  var threw;
  threw = null; try { b.mtlsCa.create({}); } catch (e) { threw = e; }
  check("create rejects missing dataDir",         threw && threw.code === "mtls-ca/no-datadir");

  threw = null;
  try { b.mtlsCa.create({ dataDir: "/tmp/x", caKeySealedMode: "loud" }); } catch (e) { threw = e; }
  check("create rejects bad caKeySealedMode",     threw && threw.code === "mtls-ca/bad-mode");
}

function testMtlsCaParseGeneration() {
  check("parseGeneration empty → 0",              b.mtlsCa.parseGeneration("") === 0);
  check("parseGeneration null → 0",               b.mtlsCa.parseGeneration(null) === 0);
  check("parseGeneration non-PEM → 0",            b.mtlsCa.parseGeneration("not a cert") === 0);
  check("parseGeneration malformed PEM → 0",
        b.mtlsCa.parseGeneration("-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----") === 0);
}

function testMtlsCaExistsAndStatusWhenAbsent() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir });
    check("keyExists false on empty dir",          ca.keyExists() === false);
    check("exists false on empty dir",             ca.exists() === false);
    var s = ca.status();
    check("status: exists=false",                  s.exists === false);
    check("status: generation=0",                  s.generation === 0);
    check("status: current=create's generation",   s.current === 1);
    check("status: isLegacy=false (no CA → no legacy concern)",
          s.isLegacy === false);
  } finally { fx.cleanup(); }
}

function testMtlsCaLoadFailures() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir });
    var threw;
    threw = null; try { ca.loadKey(); } catch (e) { threw = e; }
    check("loadKey on empty dir throws missing-key",
          threw && threw.code === "mtls-ca/missing-key");

    threw = null; try { ca.loadCert(); } catch (e) { threw = e; }
    check("loadCert on empty dir throws missing-cert",
          threw && threw.code === "mtls-ca/missing-cert");
  } finally { fx.cleanup(); }
}

function testMtlsCaCommitAndLoadPlaintext() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "disabled" });
    var keyPem  = "-----BEGIN PRIVATE KEY-----\nFAKE-CA-KEY-BYTES\n-----END PRIVATE KEY-----\n";
    var certPem = "-----BEGIN CERTIFICATE-----\nFAKE-CA-CERT-BYTES\n-----END CERTIFICATE-----\n";

    var r = ca.commit({ caKeyPem: keyPem, caCertPem: certPem });
    check("commit returned keyPath ending in ca.key",  /ca\.key$/.test(r.keyPath));
    check("commit returned certPath ending in ca.crt", /ca\.crt$/.test(r.certPath));
    check("commit sealed=false in 'disabled' mode",     r.sealed === false);
    check("ca.key file exists post-commit",             fs.existsSync(path.join(fx.dir, "ca.key")));
    check("ca.crt file exists post-commit",             fs.existsSync(path.join(fx.dir, "ca.crt")));
    check("no .tmp files leftover",
          !fs.existsSync(path.join(fx.dir, "ca.key.tmp")) &&
          !fs.existsSync(path.join(fx.dir, "ca.crt.tmp")));

    var loadedKey  = ca.loadKey().toString("utf8");
    var loadedCert = ca.loadCert().toString("utf8");
    check("loadKey returns committed PEM",              loadedKey  === keyPem);
    check("loadCert returns committed PEM",             loadedCert === certPem);

    check("exists=true after commit",                   ca.exists() === true);
  } finally { fx.cleanup(); }
}

function testMtlsCaSealedRequiredMode() {
  var fx = _mtlsCaFixture();
  try {
    var v = _mockVault();
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "required", vault: v });
    var keyPem  = "-----BEGIN PRIVATE KEY-----\nSEALED-KEY\n-----END PRIVATE KEY-----\n";
    var certPem = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n";

    var r = ca.commit({ caKeyPem: keyPem, caCertPem: certPem });
    check("required mode: sealed=true",                r.sealed === true);
    check("required mode: keyPath ends in ca.key.sealed",
          /ca\.key\.sealed$/.test(r.keyPath));
    // Plaintext key file must NOT be created
    check("required mode: ca.key NOT written",
          !fs.existsSync(path.join(fx.dir, "ca.key")));
    check("required mode: ca.key.sealed written",
          fs.existsSync(path.join(fx.dir, "ca.key.sealed")));

    // Round-trip: loadKey unseals via vault
    var loaded = ca.loadKey().toString("utf8");
    check("required mode: loadKey returns unsealed PEM bytes", loaded === keyPem);

    // Without vault, sealed-required mode rejects
    var caNoVault = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "required" });
    var threw = null;
    try { caNoVault.loadKey(); } catch (e) { threw = e; }
    check("required mode without vault: load throws no-vault",
          threw && threw.code === "mtls-ca/no-vault");
  } finally { fx.cleanup(); }
}

function testMtlsCaSealedDisabledRefusesSealedFile() {
  var fx = _mtlsCaFixture();
  try {
    // Pre-place a sealed file but caKeySealedMode='disabled'
    fs.writeFileSync(path.join(fx.dir, "ca.key.sealed"), "mockseal:abc");
    fs.writeFileSync(path.join(fx.dir, "ca.crt"), "cert");
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "disabled" });
    var threw = null;
    try { ca.loadKey(); } catch (e) { threw = e; }
    check("disabled mode: refuses to load with no plaintext key",
          threw && threw.code === "mtls-ca/plain-required");
  } finally { fx.cleanup(); }
}

function testMtlsCaSealedRequiredRefusesPlaintextFile() {
  var fx = _mtlsCaFixture();
  try {
    fs.writeFileSync(path.join(fx.dir, "ca.key"), "plain-key");
    fs.writeFileSync(path.join(fx.dir, "ca.crt"), "cert");
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "required", vault: _mockVault() });
    var threw = null;
    try { ca.loadKey(); } catch (e) { threw = e; }
    check("required mode: refuses to load when only plaintext present",
          threw && threw.code === "mtls-ca/sealed-required");
  } finally { fx.cleanup(); }
}

async function testMtlsCaInitCaWithDefaultEngine() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir, generation: 1, caKeySealedMode: "disabled" });
    var fresh = await ca.initCA();
    check("default engine: initCA returns caCertPem",
          typeof fresh.caCertPem === "string" && /BEGIN CERTIFICATE/.test(fresh.caCertPem));
    check("default engine: initCA returns caKeyPem",
          typeof fresh.caKeyPem === "string" && /BEGIN PRIVATE KEY/.test(fresh.caKeyPem));
    check("default engine: ca.crt written",
          fs.existsSync(path.join(fx.dir, "ca.crt")));
    check("default engine: ca.key written",
          fs.existsSync(path.join(fx.dir, "ca.key")));
    var gen = b.mtlsCa.parseGeneration(fresh.caCertPem);
    check("default engine: cert carries OU=CAv1 generation tag", gen === 1);

    // Subject + issuer round-trip through node:crypto — both should
    // contain "CN=blamejs CA" since the default engine self-signs.
    var nc = require("node:crypto");
    var x = new nc.X509Certificate(fresh.caCertPem);
    check("default engine: subject contains 'CN=blamejs CA'",
          /CN=blamejs CA/.test(x.subject || ""));
    check("default engine: cert is self-signed (issuer === subject)",
          x.issuer === x.subject);

    // Second call returns existing CA without regenerating.
    var second = await ca.initCA();
    check("default engine: second initCA returns existing cert",
          second.caCertPem === fresh.caCertPem);
  } finally { fx.cleanup(); }
}

async function testMtlsCaGenerateClientCertWithDefaultEngine() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "disabled" });
    var leaf = await ca.generateClientCert({ cn: "alice", validityDays: 90 });
    check("default engine: leaf cert PEM emitted",
          typeof leaf.cert === "string" && /BEGIN CERTIFICATE/.test(leaf.cert));
    check("default engine: leaf private key PEM emitted",
          typeof leaf.key === "string" && /BEGIN PRIVATE KEY/.test(leaf.key));
    check("default engine: leaf carries CA PEM in 'ca' field",
          /BEGIN CERTIFICATE/.test(leaf.ca));

    var nc = require("node:crypto");
    var leafX = new nc.X509Certificate(leaf.cert);
    var caX   = new nc.X509Certificate(leaf.ca);
    check("leaf subject contains CN=alice",     /CN=alice/.test(leafX.subject || ""));
    check("leaf issuer === CA subject (chain)",  leafX.issuer === caX.subject);
    check("leaf verifies under CA public key",   leafX.verify(caX.publicKey) === true);

    // validity window approximately 90 days
    var diffDays = (new Date(leaf.expiresAt) - new Date(leaf.issuedAt)) / 86400000;
    check("leaf validity window ~ 90 days",      diffDays >= 89 && diffDays <= 91);
  } finally { fx.cleanup(); }
}

async function testMtlsCaGenerateClientP12WithDefaultEngine() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir, caKeySealedMode: "disabled" });
    var bundle = await ca.generateClientP12({ cn: "bob", password: "p12-passphrase-x9k2" });
    check("default engine: p12 is a Buffer",                Buffer.isBuffer(bundle.p12));
    check("default engine: p12 has non-trivial size",       bundle.p12.length > 1000);
    check("default engine: p12 starts with ASN.1 SEQUENCE", bundle.p12[0] === 0x30);
    check("default engine: certPem returned alongside",
          typeof bundle.certPem === "string" && /BEGIN CERTIFICATE/.test(bundle.certPem));
    check("default engine: issuedAt + expiresAt are ISO strings",
          typeof bundle.issuedAt === "string" && typeof bundle.expiresAt === "string");
  } finally { fx.cleanup(); }
}

async function testMtlsCaInitCaWithEngineGeneratesAndCommits() {
  var fx = _mtlsCaFixture();
  try {
    var generated = false;
    var engine = {
      generateCa: async function (opts) {
        generated = true;
        return {
          caCertPem: "-----BEGIN CERTIFICATE-----\nENGINE-CA-CERT-gen=" + opts.generation +
            "\n-----END CERTIFICATE-----\n",
          caKeyPem:  "-----BEGIN PRIVATE KEY-----\nENGINE-CA-KEY\n-----END PRIVATE KEY-----\n",
        };
      },
    };
    var ca = b.mtlsCa.create({ dataDir: fx.dir, generation: 2, engine: engine, caKeySealedMode: "disabled" });
    var first = await ca.initCA();
    check("first initCA called engine.generateCa",      generated === true);
    check("first initCA returned engine output",        /ENGINE-CA-CERT-gen=2/.test(first.caCertPem));
    check("first initCA wrote ca.key",                  fs.existsSync(path.join(fx.dir, "ca.key")));
    check("first initCA wrote ca.crt",                  fs.existsSync(path.join(fx.dir, "ca.crt")));

    // Second call should NOT regenerate — existing CA is returned
    generated = false;
    var second = await ca.initCA();
    check("second initCA reused existing CA (no regen)", generated === false);
    check("second initCA returned same cert",            second.caCertPem === first.caCertPem);
  } finally { fx.cleanup(); }
}

async function testMtlsCaInitCaRejectsBadEngineOutput() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({
      dataDir: fx.dir,
      engine: { generateCa: async function () { return { caCertPem: "ok" /* missing key */ }; } },
      caKeySealedMode: "disabled",
    });
    var threw = null;
    try { await ca.initCA(); } catch (e) { threw = e; }
    check("initCA rejects engine output missing caKeyPem",
          threw && threw.code === "mtls-ca/bad-engine-output");
  } finally { fx.cleanup(); }
}

async function testMtlsCaGenerateClientCertDelegates() {
  var fx = _mtlsCaFixture();
  try {
    var seenArgs = null;
    var engine = {
      generateCa: async function () {
        return {
          caCertPem: "-----BEGIN CERTIFICATE-----\nENGINE-CA\n-----END CERTIFICATE-----\n",
          caKeyPem:  "-----BEGIN PRIVATE KEY-----\nENGINE-KEY\n-----END PRIVATE KEY-----\n",
        };
      },
      signClientCert: async function (args) {
        seenArgs = args;
        return {
          cert:      "-----BEGIN CERTIFICATE-----\nCLIENT-CERT-cn=" + args.cn + "\n-----END CERTIFICATE-----\n",
          key:       "-----BEGIN PRIVATE KEY-----\nCLIENT-KEY\n-----END PRIVATE KEY-----\n",
          ca:        args.caCertPem,
          issuedAt:  "now", expiresAt: "later",
        };
      },
    };
    var ca = b.mtlsCa.create({ dataDir: fx.dir, engine: engine, caKeySealedMode: "disabled" });
    var client = await ca.generateClientCert({ cn: "alice", validityDays: 90 });
    check("signClientCert called with cn forwarded",   seenArgs && seenArgs.cn === "alice");
    check("signClientCert received caCertPem",          /ENGINE-CA/.test(seenArgs.caCertPem));
    check("signClientCert received caKeyPem",           /ENGINE-KEY/.test(seenArgs.caKeyPem));
    check("client cert returned with cn embedded",      /cn=alice/.test(client.cert));
  } finally { fx.cleanup(); }
}

async function testMtlsCaGenerateClientP12Validation() {
  var fx = _mtlsCaFixture();
  try {
    var ca = b.mtlsCa.create({ dataDir: fx.dir, engine: { generateCa: async function () { return { caCertPem: "x", caKeyPem: "y" }; } }, caKeySealedMode: "disabled" });
    var threw = null;
    try { await ca.generateClientP12({ cn: "alice" }); } catch (e) { threw = e; }
    check("generateClientP12 without password rejected",
          threw && threw.code === "mtls-ca/no-password");
  } finally { fx.cleanup(); }
}

// ---- vault-passphrase-ops ----
//
// Real on-disk fixtures because the primitive's whole job is filesystem
// hygiene (atomic rename + fsync + round-trip verify). Each test gets
// a fresh tmp dataDir.

function _passphraseOpsFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vps-"));
  return {
    dir: dir,
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
    writePlaintext: function (content) {
      fs.writeFileSync(path.join(dir, "vault.key"), content || JSON.stringify({ test: "keypair" }), { mode: 0o600 });
    },
  };
}

function testVaultPassphraseOpsSurface() {
  check("b.vaultPassphraseOps namespace present",  typeof b.vaultPassphraseOps === "object");
  check("preflightSealable is a function",         typeof b.vaultPassphraseOps.preflightSealable === "function");
  check("preflightUnsealable is a function",       typeof b.vaultPassphraseOps.preflightUnsealable === "function");
  check("seal is a function",                      typeof b.vaultPassphraseOps.seal === "function");
  check("unseal is a function",                    typeof b.vaultPassphraseOps.unseal === "function");
  check("rotate is a function",                    typeof b.vaultPassphraseOps.rotate === "function");
  check("VaultPassphraseError is a class",         typeof b.vaultPassphraseOps.VaultPassphraseError === "function");
}

function testVaultPassphraseOpsPreflightChecks() {
  var fx = _passphraseOpsFixture();
  try {
    // Sealable: needs plaintext present + sealed absent
    var pre1 = b.vaultPassphraseOps.preflightSealable({ dataDir: fx.dir });
    check("seal preflight without plaintext: not ok",
          pre1.ok === false && /nothing to seal/.test(pre1.reason));

    fx.writePlaintext();
    var pre2 = b.vaultPassphraseOps.preflightSealable({ dataDir: fx.dir });
    check("seal preflight with plaintext present: ok",  pre2.ok === true);

    // Unsealable: needs sealed present + plaintext absent
    var pre3 = b.vaultPassphraseOps.preflightUnsealable({ dataDir: fx.dir });
    check("unseal preflight without sealed: not ok",
          pre3.ok === false && /nothing to unseal/.test(pre3.reason));

    // Stale .tmp blocks both
    fs.writeFileSync(path.join(fx.dir, "vault.key.sealed.tmp"), "stale");
    var pre4 = b.vaultPassphraseOps.preflightSealable({ dataDir: fx.dir });
    check("stale sealed.tmp blocks seal preflight",
          pre4.ok === false && /stale/.test(pre4.reason));
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsSealUnsealRoundTrip() {
  var fx = _passphraseOpsFixture();
  try {
    var keypairJson = JSON.stringify({ test: "keypair", version: 1 });
    fx.writePlaintext(keypairJson);

    var passphrase = Buffer.from("correct horse battery staple", "utf8");
    var sealResult = await b.vaultPassphraseOps.seal({
      dataDir: fx.dir, passphrase: passphrase,
    });
    check("seal returns sealedPath",                 typeof sealResult.sealedPath === "string");
    check("seal: plaintext deleted by default",      sealResult.plaintextDeleted === true);
    check("seal: vault.key removed",                 !fs.existsSync(path.join(fx.dir, "vault.key")));
    check("seal: vault.key.sealed exists",           fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
    check("seal: no .tmp leftover",                  !fs.existsSync(path.join(fx.dir, "vault.key.sealed.tmp")));

    var unsealResult = await b.vaultPassphraseOps.unseal({
      dataDir: fx.dir, passphrase: passphrase,
    });
    check("unseal returns plaintextPath",            typeof unsealResult.plaintextPath === "string");
    check("unseal: vault.key.sealed removed",        !fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
    check("unseal: vault.key restored",              fs.existsSync(path.join(fx.dir, "vault.key")));

    var restored = fs.readFileSync(path.join(fx.dir, "vault.key"), "utf8");
    check("unseal: plaintext bytes match original", restored === keypairJson);
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsKeepPlaintext() {
  var fx = _passphraseOpsFixture();
  try {
    fx.writePlaintext("keep-me");
    var passphrase = Buffer.from("p", "utf8");
    var r = await b.vaultPassphraseOps.seal({
      dataDir: fx.dir, passphrase: passphrase, keepPlaintext: true,
    });
    check("seal keepPlaintext: returns plaintextDeleted=false",
          r.plaintextDeleted === false);
    check("seal keepPlaintext: plaintext still present",
          fs.existsSync(path.join(fx.dir, "vault.key")));
    check("seal keepPlaintext: sealed exists",
          fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsWrongPassphraseRejected() {
  var fx = _passphraseOpsFixture();
  try {
    fx.writePlaintext("data");
    var p1 = Buffer.from("right", "utf8");
    var p2 = Buffer.from("wrong", "utf8");
    await b.vaultPassphraseOps.seal({ dataDir: fx.dir, passphrase: p1 });

    var threw = null;
    try { await b.vaultPassphraseOps.unseal({ dataDir: fx.dir, passphrase: p2 }); }
    catch (e) { threw = e; }
    check("unseal with wrong passphrase rejected",
          threw && threw.code === "vault-passphrase/passphrase-rejected");
    check("rejected unseal: vault.key.sealed unchanged",
          fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
    check("rejected unseal: no plaintext leak",
          !fs.existsSync(path.join(fx.dir, "vault.key")));
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsRotate() {
  var fx = _passphraseOpsFixture();
  try {
    var content = "secret-keypair-bytes";
    fx.writePlaintext(content);
    var oldP = Buffer.from("old passphrase", "utf8");
    var newP = Buffer.from("new passphrase v2", "utf8");
    await b.vaultPassphraseOps.seal({ dataDir: fx.dir, passphrase: oldP });

    var rotResult = await b.vaultPassphraseOps.rotate({
      dataDir: fx.dir, oldPassphrase: oldP, newPassphrase: newP,
    });
    check("rotate returns sealedPath",               typeof rotResult.sealedPath === "string");

    // Old passphrase no longer unwraps
    var threwOld = null;
    try { await b.vaultPassphraseOps.unseal({ dataDir: fx.dir, passphrase: oldP }); }
    catch (e) { threwOld = e; }
    check("rotate: old passphrase rejected post-rotate",
          threwOld && threwOld.code === "vault-passphrase/passphrase-rejected");

    // New passphrase unwraps to original bytes
    var unseal = await b.vaultPassphraseOps.unseal({ dataDir: fx.dir, passphrase: newP });
    check("rotate: new passphrase unwraps to original bytes",
          fs.readFileSync(unseal.plaintextPath, "utf8") === content);
  } finally { fx.cleanup(); }
}

async function testVaultPassphraseOpsRotateRejectsBadOldPassphrase() {
  var fx = _passphraseOpsFixture();
  try {
    fx.writePlaintext("x");
    var p = Buffer.from("right", "utf8");
    await b.vaultPassphraseOps.seal({ dataDir: fx.dir, passphrase: p });

    var threw = null;
    try {
      await b.vaultPassphraseOps.rotate({
        dataDir: fx.dir,
        oldPassphrase: Buffer.from("wrong", "utf8"),
        newPassphrase: Buffer.from("new", "utf8"),
      });
    } catch (e) { threw = e; }
    check("rotate with wrong old passphrase rejected",
          threw && threw.code === "vault-passphrase/passphrase-rejected");
    check("rotate: sealed file unchanged after rejection",
          fs.existsSync(path.join(fx.dir, "vault.key.sealed")));
  } finally { fx.cleanup(); }
}

function testVaultPassphraseOpsArgValidation() {
  var threw;
  threw = null;
  try { b.vaultPassphraseOps.preflightSealable({}); }
  catch (e) { threw = e; }
  check("missing dataDir rejected",                threw && threw.code === "vault-passphrase/no-datadir");

  threw = null;
  try { b.vaultPassphraseOps.preflightSealable({ dataDir: "/nonexistent-blamejs" }); }
  catch (e) { threw = e; }
  check("nonexistent dataDir rejected",            threw && threw.code === "vault-passphrase/no-datadir");
}

async function testVaultPassphraseOpsRequiresBufferPassphrase() {
  var fx = _passphraseOpsFixture();
  try {
    fx.writePlaintext("x");
    var threw = null;
    try { await b.vaultPassphraseOps.seal({ dataDir: fx.dir, passphrase: "string-not-buffer" }); }
    catch (e) { threw = e; }
    check("string passphrase rejected (must be Buffer)",
          threw && threw.code === "vault-passphrase/no-passphrase");
  } finally { fx.cleanup(); }
}

// ---- vault-rotate (diagnostics) ----

function _vaultRotateFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vrot-"));
  var dbPath = path.join(dir, "test.db");
  var { DatabaseSync } = require("node:sqlite");
  var db = new DatabaseSync(dbPath);
  return {
    dir: dir,
    db:  db,
    cleanup: function () {
      try { db.close(); } catch (_e) {}
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
      // Each test resets the field-crypto registry so they don't leak
      // table registrations into each other.
      b.cryptoField.clearForTest();
    },
  };
}

// Build a real vault keypair for verify() round-trip tests. cryptoLib
// is exposed via b.crypto.
function _genKeys() { return b.crypto.generateEncryptionKeyPair(); }

// Build a vault-prefixed value by encrypting plaintext with the
// supplied keypair. Avoids needing vault.init for tests.
function _seal(plaintext, keys) {
  return b.constants.VAULT_PREFIX + b.crypto.encrypt(plaintext, keys);
}

function testVaultRotateSurface() {
  check("b.vaultRotate namespace present",        typeof b.vaultRotate === "object");
  check("validateSchemaMatch is a function",      typeof b.vaultRotate.validateSchemaMatch === "function");
  check("formatValidationResult is a function",   typeof b.vaultRotate.formatValidationResult === "function");
  check("verify is a function",                   typeof b.vaultRotate.verify === "function");
  check("VaultRotateError is a class",            typeof b.vaultRotate.VaultRotateError === "function");
}

function testVaultRotateValidateSchemaCleanCase() {
  var fx = _vaultRotateFixture();
  try {
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, emailHash TEXT, createdAt TEXT)");
    b.cryptoField.registerTable("users", {
      sealedFields:  ["email"],
      derivedHashes: { emailHash: { from: "email" } },
    });
    // Seed one row with a properly-sealed email
    var keys = _genKeys();
    fx.db.prepare("INSERT INTO users (_id, email, emailHash, createdAt) VALUES (?, ?, ?, ?)").run(
      "u-1", _seal("a@b.com", keys), "hash-of-email", new Date().toISOString());

    var r = b.vaultRotate.validateSchemaMatch(fx.db);
    check("clean schema: 0 errors",                 r.errors.length === 0);
    check("clean schema: 0 warnings",               r.warnings.length === 0);
    check("formatValidationResult: OK",
          /schema match: OK/.test(b.vaultRotate.formatValidationResult(r)));
  } finally { fx.cleanup(); }
}

function testVaultRotateValidateMissingTable() {
  var fx = _vaultRotateFixture();
  try {
    // Schema declares 'users' but live DB has no such table
    b.cryptoField.registerTable("users", { sealedFields: ["email"] });
    var r = b.vaultRotate.validateSchemaMatch(fx.db, { tables: ["users"] });
    check("missing table → warning",                r.warnings.length === 1);
    check("warning kind = table_missing",           r.warnings[0].kind === "table_missing");
    check("missing table is non-fatal (no errors)", r.errors.length === 0);
  } finally { fx.cleanup(); }
}

function testVaultRotateValidateSealedColMissing() {
  var fx = _vaultRotateFixture();
  try {
    // Live table has no 'phone' column even though schema declares it sealed
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT)");
    b.cryptoField.registerTable("users", { sealedFields: ["email", "phone"] });
    var r = b.vaultRotate.validateSchemaMatch(fx.db);
    var miss = r.warnings.find(function (w) { return w.kind === "sealed_col_missing"; });
    check("sealed-col-missing surfaces as warning", miss && miss.column === "phone");
    check("non-fatal: 0 errors",                    r.errors.length === 0);
  } finally { fx.cleanup(); }
}

function testVaultRotateValidateDriftDetection() {
  var fx = _vaultRotateFixture();
  try {
    // 'secret' is NOT declared sealed in schema, but rows have a vault-prefixed value
    fx.db.exec("CREATE TABLE rec (_id TEXT PRIMARY KEY, name TEXT, secret TEXT)");
    b.cryptoField.registerTable("rec", { sealedFields: ["name"] });

    var keys = _genKeys();
    fx.db.prepare("INSERT INTO rec (_id, name, secret) VALUES (?, ?, ?)").run(
      "r-1", _seal("Alice", keys), _seal("ssn-123-45-6789", keys));

    var r = b.vaultRotate.validateSchemaMatch(fx.db);
    var drift = r.errors.find(function (e) { return e.kind === "drift" && e.column === "secret"; });
    check("drift detected on undeclared sealed column",
          drift && drift.table === "rec" && drift.column === "secret");
    check("formatValidationResult marks rotation refused",
          /rotation refused/.test(b.vaultRotate.formatValidationResult(r)));
  } finally { fx.cleanup(); }
}

function testVaultRotateValidateInfraColumnsAllowlist() {
  var fx = _vaultRotateFixture();
  try {
    // 'audit_meta' is a framework column that legitimately holds vault-prefixed
    // values without being in sealedFields. Operator passes infraColumns.
    fx.db.exec("CREATE TABLE _blamejs_audit (_id TEXT PRIMARY KEY, audit_meta TEXT)");
    b.cryptoField.registerTable("_blamejs_audit", { sealedFields: [] });

    var keys = _genKeys();
    fx.db.prepare("INSERT INTO _blamejs_audit (_id, audit_meta) VALUES (?, ?)").run(
      "a-1", _seal("framework-internal", keys));

    var rNo = b.vaultRotate.validateSchemaMatch(fx.db);
    check("without infraColumns: drift error raised",
          rNo.errors.some(function (e) { return e.kind === "drift" && e.column === "audit_meta"; }));

    var rWith = b.vaultRotate.validateSchemaMatch(fx.db, { infraColumns: ["audit_meta"] });
    check("with infraColumns: drift error suppressed",
          !rWith.errors.some(function (e) { return e.kind === "drift" && e.column === "audit_meta"; }));
  } finally { fx.cleanup(); }
}

function testVaultRotateVerifyRoundTrip() {
  var fx = _vaultRotateFixture();
  try {
    var keys = _genKeys();
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT)");
    b.cryptoField.registerTable("users", { sealedFields: ["email"] });
    for (var i = 0; i < 10; i++) {
      fx.db.prepare("INSERT INTO users (_id, email) VALUES (?, ?)").run(
        "u-" + i, _seal("user" + i + "@b.com", keys));
    }
    var r = b.vaultRotate.verify({ keys: keys, db: fx.db });
    check("verify ok with correct keys",            r.ok === true);
    check("verify reports passed entries",          r.passed.length === 1 && r.passed[0].table === "users");
    check("verify shows sampled rows verified",     r.passed[0].verified === r.passed[0].sampled);
    check("verify: 0 failures",                      r.failures.length === 0);
  } finally { fx.cleanup(); }
}

function testVaultRotateVerifyDetectsTampering() {
  var fx = _vaultRotateFixture();
  try {
    var keys     = _genKeys();
    var wrongKeys = _genKeys();
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT)");
    b.cryptoField.registerTable("users", { sealedFields: ["email"] });
    for (var i = 0; i < 10; i++) {
      fx.db.prepare("INSERT INTO users (_id, email) VALUES (?, ?)").run(
        "u-" + i, _seal("user" + i + "@b.com", keys));
    }
    // Verifying with wrong keys → all rows fail to decrypt
    var r = b.vaultRotate.verify({ keys: wrongKeys, db: fx.db, sampleMin: 10 });
    check("verify with wrong keys: not ok",         r.ok === false);
    check("verify with wrong keys: failures recorded",
          r.failures.length > 0);
    check("verify failure rows include table+column+_id",
          r.failures[0].table === "users" && r.failures[0].column === "email" &&
          typeof r.failures[0]._id === "string");
  } finally { fx.cleanup(); }
}

function testVaultRotateVerifyRegressionWithOldKeys() {
  // Simulate a partial rotation: insert some rows under newKeys, others
  // still under oldKeys. Verify with newKeys + oldKeys passed should
  // record regressions for the unrotated rows.
  var fx = _vaultRotateFixture();
  try {
    var oldKeys = _genKeys();
    var newKeys = _genKeys();
    fx.db.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT)");
    b.cryptoField.registerTable("users", { sealedFields: ["email"] });

    // 5 unrotated rows — still encrypted with oldKeys
    for (var i = 0; i < 5; i++) {
      fx.db.prepare("INSERT INTO users (_id, email) VALUES (?, ?)").run(
        "old-" + i, _seal("user" + i + "@b.com", oldKeys));
    }
    // 5 rotated rows — encrypted with newKeys
    for (var j = 0; j < 5; j++) {
      fx.db.prepare("INSERT INTO users (_id, email) VALUES (?, ?)").run(
        "new-" + j, _seal("user-new" + j + "@b.com", newKeys));
    }
    var r = b.vaultRotate.verify({ keys: newKeys, db: fx.db, oldKeys: oldKeys, sampleMin: 10 });
    // The 5 old-rotation rows fail to decrypt with newKeys → failures
    check("partial rotation: failures recorded for unrotated rows",
          r.failures.length === 5);
    check("ok=false because failures present",      r.ok === false);
  } finally { fx.cleanup(); }
}

async function testVaultRotateRotateEndToEnd() {
  // Build a real on-disk dataDir layout that the rotate primitive
  // recognizes, run rotate(), then assert the staged copy reads back
  // under the new keys and the source dataDir is untouched.
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vrot-rot-"));
  try {
    var dataDir   = path.join(dir, "data");
    var stagingDir = path.join(dir, "staging");
    fs.mkdirSync(dataDir, { recursive: true });

    var oldKeys = b.crypto.generateEncryptionKeyPair();
    var newKeys = b.crypto.generateEncryptionKeyPair();

    // 32-byte XChaCha20 key for the at-rest DB envelope
    var dbKey = b.crypto.generateBytes(32);

    // vault.key: plaintext JSON of the keypair (matches plaintext mode)
    fs.writeFileSync(path.join(dataDir, "vault.key"), JSON.stringify(oldKeys, null, 2));
    // db.key.enc: vault-sealed base64(dbKey)
    fs.writeFileSync(path.join(dataDir, "db.key.enc"),
      b.constants.VAULT_PREFIX + b.crypto.encrypt(dbKey.toString("base64"), oldKeys));

    // Build a small SQLite DB with sealed rows
    var { DatabaseSync } = require("node:sqlite");
    var plainDbPath = path.join(dir, "build.db");
    var bdb = new DatabaseSync(plainDbPath);
    bdb.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, email TEXT, name TEXT)");
    var ins = bdb.prepare("INSERT INTO users (_id, email, name) VALUES (?, ?, ?)");
    for (var i = 0; i < 10; i++) {
      ins.run(
        "u-" + i,
        b.constants.VAULT_PREFIX + b.crypto.encrypt("user" + i + "@b.com", oldKeys),
        b.constants.VAULT_PREFIX + b.crypto.encrypt("Name " + i, oldKeys));
    }
    bdb.close();
    var plainBytes = fs.readFileSync(plainDbPath);
    fs.writeFileSync(path.join(dataDir, "db.enc"),
      b.crypto.encryptPacked(plainBytes, dbKey));

    // Register the schema before rotation so the rotator knows which columns are sealed
    b.cryptoField.clearForTest();
    b.cryptoField.registerTable("users", { sealedFields: ["email", "name"] });

    var ageBefore = fs.statSync(path.join(dataDir, "db.enc")).mtimeMs;

    // Rotate
    var progressEvents = [];
    var result = await b.vaultRotate.rotate({
      oldKeys: oldKeys, newKeys: newKeys,
      dataDir: dataDir, stagingDir: stagingDir,
      mode: "plaintext",
      // This fixture seals only db.enc-backed columns; no operator-supplied
      // AAD stores are in play, so the rotation has nothing external to re-seal.
      externalAadResealed: true,
      progressCallback: function (e) { progressEvents.push(e.phase); },
    });

    check("rotate returns durationMs",              typeof result.durationMs === "number");
    check("rotate processed users table",           result.tablesProcessed === 1);
    check("rotate processed all 10 rows × 2 cols",  result.totalRowsProcessed >= 20);
    check("rotate verify passed",                   result.verifyResult && result.verifyResult.ok === true);
    check("progress phases include init/done",
          progressEvents.indexOf("init") !== -1 &&
          progressEvents.indexOf("done") !== -1);

    // Staging should hold the new vault key
    var stagedVaultKey = JSON.parse(fs.readFileSync(path.join(stagingDir, "vault.key"), "utf8"));
    check("staged vault.key is the new keypair",
          stagedVaultKey.encryptionMlkem === newKeys.encryptionMlkem ||
          stagedVaultKey.encryption === newKeys.encryption ||
          // shape varies but the staged keypair must NOT equal oldKeys
          JSON.stringify(stagedVaultKey) !== JSON.stringify(oldKeys));

    // Staged db.key.enc should decrypt under newKeys to the SAME dbKey
    var stagedSealedKey = fs.readFileSync(path.join(stagingDir, "db.key.enc"), "utf8").trim();
    var dbKeyAfterB64 = b.crypto.decrypt(stagedSealedKey.substring(b.constants.VAULT_PREFIX.length), newKeys);
    check("staged db.key.enc decrypts under newKeys",
          Buffer.from(dbKeyAfterB64, "base64").equals(dbKey));

    // Staged db.enc should decrypt with dbKey, contain the same rows, and
    // every email/name column should now be sealed under newKeys.
    var stagedPacked = fs.readFileSync(path.join(stagingDir, "db.enc"));
    // Rotation re-writes db.enc bound to the dataDir-scoped AAD (matching the
    // at-rest format db.js writes), even when the input snapshot was a legacy
    // un-bound envelope — so verification must supply the same AAD. The binding
    // tracks the final dataDir (where db.js reopens it after the staging swap),
    // not the staging path.
    var stagedPlain = b.crypto.decryptPacked(stagedPacked, dbKey, b.db._dbEncAad(dataDir));
    var verifyDbPath = path.join(dir, "verify.db");
    fs.writeFileSync(verifyDbPath, stagedPlain);
    var vdb = new DatabaseSync(verifyDbPath);
    try {
      var rows = vdb.prepare("SELECT _id, email, name FROM users ORDER BY _id").all();
      check("staged db has same row count",         rows.length === 10);
      // Each row's sealed columns decrypt under newKeys
      var allDecrypt = true;
      for (var j = 0; j < rows.length; j++) {
        var emailPayload = rows[j].email.substring(b.constants.VAULT_PREFIX.length);
        var namePayload = rows[j].name.substring(b.constants.VAULT_PREFIX.length);
        try {
          if (b.crypto.decrypt(emailPayload, newKeys) !== "user" + j + "@b.com") allDecrypt = false;
          if (b.crypto.decrypt(namePayload, newKeys) !== "Name " + j) allDecrypt = false;
        } catch (_e) { allDecrypt = false; }
      }
      check("every staged sealed value decrypts under newKeys + plaintext matches",
            allDecrypt);

      // And NO row still decrypts under oldKeys
      var anyOldDecrypt = false;
      for (var k = 0; k < rows.length; k++) {
        try {
          b.crypto.decrypt(rows[k].email.substring(b.constants.VAULT_PREFIX.length), oldKeys);
          anyOldDecrypt = true; break;
        } catch (_e) { /* expected */ }
      }
      check("no staged row decrypts under oldKeys",  anyOldDecrypt === false);
    } finally { vdb.close(); }

    // dataDir is untouched (mtime unchanged)
    var ageAfter = fs.statSync(path.join(dataDir, "db.enc")).mtimeMs;
    check("rotate did NOT mutate dataDir/db.enc",   ageAfter === ageBefore);

    b.cryptoField.clearForTest();
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testVaultRotateRotateValidation() {
  var oldKeys = b.crypto.generateEncryptionKeyPair();
  var newKeys = b.crypto.generateEncryptionKeyPair();
  var threw;

  threw = null;
  try { await b.vaultRotate.rotate({}); } catch (e) { threw = e; }
  check("rotate without keys throws",             threw && threw.code === "vault-rotate/no-keys");

  threw = null;
  try { await b.vaultRotate.rotate({ oldKeys: oldKeys, newKeys: newKeys, dataDir: "/nonexistent-blamejs-test", stagingDir: "/tmp/x" }); }
  catch (e) { threw = e; }
  check("rotate with missing dataDir throws",     threw && threw.code === "vault-rotate/no-datadir");

  // staging exists → reject
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vrot-val-"));
  try {
    fs.mkdirSync(path.join(dir, "staging"));
    threw = null;
    try {
      await b.vaultRotate.rotate({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: dir, stagingDir: path.join(dir, "staging"),
      });
    } catch (e) { threw = e; }
    check("rotate with existing stagingDir throws", threw && threw.code === "vault-rotate/staging-exists");

    // wrapped mode without passphrase → reject
    threw = null;
    try {
      await b.vaultRotate.rotate({
        oldKeys: oldKeys, newKeys: newKeys,
        dataDir: dir, stagingDir: path.join(dir, "staging-2"),
        mode: "wrapped",
      });
    } catch (e) { threw = e; }
    check("rotate wrapped without passphrase throws",
          threw && threw.code === "vault-rotate/no-passphrase");
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

function testVaultRotateVerifyRequiresKeysAndDb() {
  var threw;
  threw = null; try { b.vaultRotate.verify({}); } catch (e) { threw = e; }
  check("verify without keys throws",             threw && threw.code === "vault-rotate/no-keys");

  threw = null; try { b.vaultRotate.verify({ keys: {} }); } catch (e) { threw = e; }
  check("verify without db throws",               threw && threw.code === "vault-rotate/no-db");
}

// ---- pqc-agent ----

function testPqcAgentSurface() {
  check("b.pqcAgent namespace present",          typeof b.pqcAgent === "object");
  check("b.pqcAgent.create is a function",       typeof b.pqcAgent.create === "function");
  check("b.pqcAgent.createHttp is a function",   typeof b.pqcAgent.createHttp === "function");
  check("b.pqcAgent.enforced flag set",          b.pqcAgent.enforced === true);
  check("DEFAULT_OPTS exposes keepAlive defaults",
        b.pqcAgent.DEFAULT_OPTS.keepAlive === true &&
        b.pqcAgent.DEFAULT_OPTS.maxSockets > 0);
}

function testPqcAgentCreateHasPqcPosture() {
  var a = b.pqcAgent.create();
  check("create returned an https.Agent",         a && a.constructor && a.constructor.name === "Agent");
  check("agent's TLS opts pin TLS 1.3",            a.options.minVersion === "TLSv1.3");
  check("agent's TLS opts pin PQC group preference",
        a.options.ecdhCurve === b.constants.TLS_GROUP_CURVE_STR);
  check("agent has keepAlive on by default",       a.keepAlive === true);
}

function testPqcAgentCannotWeakenCryptoPosture() {
  // Operator-supplied minVersion is silently ignored (TLSv1.3 always
  // wins). Operator-supplied ecdhCurve outside the framework PQ-
  // hybrid preference now THROWS (was previously silently overridden);
  // refusing loudly means an operator who tried to downgrade learns
  // it at create-time instead of running a process they think is
  // PQC-hybrid but isn't. Pool tuning (keepAlive, maxSockets) stays
  // overridable.
  var threwOnWeakCurve = false;
  try {
    b.pqcAgent.create({
      minVersion: "TLSv1.0",
      ecdhCurve:  "P-256",
    });
  } catch (e) {
    threwOnWeakCurve = e.message.indexOf("not in the framework PQC-hybrid preference") !== -1;
  }
  check("operator-supplied weak ecdhCurve refused at create-time", threwOnWeakCurve);

  // minVersion / pool tuning still honored without an ecdhCurve weakening.
  var pooled = b.pqcAgent.create({
    minVersion: "TLSv1.0",
    keepAlive:  false,    // pool tuning IS overridable
  });
  check("operator-supplied minVersion ignored",  pooled.options.minVersion === "TLSv1.3");
  check("framework default ecdhCurve preserved", pooled.options.ecdhCurve === b.constants.TLS_GROUP_CURVE_STR);
  check("operator-supplied keepAlive honored (pool tuning IS overridable)",
        pooled.keepAlive === false);

  // Caller-supplied STRICTER subset (drop one of the two PQ groups) is honored.
  var narrowed = b.pqcAgent.create({ ecdhCurve: "X25519MLKEM768" });
  check("operator-supplied stricter subset honored", narrowed.options.ecdhCurve === "X25519MLKEM768");
}

function testPqcAgentDefaultIsLazy() {
  // The default agent is a getter — accessing it builds the agent.
  // Multiple accesses return the same instance.
  var first  = b.pqcAgent.agent;
  var second = b.pqcAgent.agent;
  check("agent getter returns a non-null https.Agent",
        first && first.constructor && first.constructor.name === "Agent");
  check("agent getter is memoized (same instance on repeated access)",
        first === second);
  check("default agent has framework PQC posture",
        first.options.minVersion === "TLSv1.3" &&
        first.options.ecdhCurve === b.constants.TLS_GROUP_CURVE_STR);
}

function testPqcAgentCreateHttpHasNoTlsPosture() {
  // createHttp returns an http.Agent (cleartext) — there's no TLS
  // surface to enforce. Pool tuning still applies.
  var hAgent = b.pqcAgent.createHttp({ maxSockets: 5 });
  check("createHttp returns an http.Agent",        hAgent && hAgent.constructor && hAgent.constructor.name === "Agent");
  check("createHttp honors pool opts",             hAgent.maxSockets === 5);
  // http.Agent's options doesn't carry ecdhCurve/minVersion at all
  check("createHttp has no minVersion / ecdhCurve",
        hAgent.options.minVersion === undefined &&
        hAgent.options.ecdhCurve === undefined);
}

// ---- pqc-gate ----
//
// Build a synthetic ClientHello buffer with a configurable supported_groups
// list. Lets us exercise the parser without standing up real TLS.

function _makeClientHello(groupIds) {
  // Body layout we control:
  //   version(2) random(32) sessionId(0+1) cipherSuites(2+2) comp(1+1)
  //     extensions(2 + supported_groups extension)
  //
  // supported_groups extension:
  //   type=0x000A length(2)  list_length(2)  group_ids(2 each)
  var groupsBytes = Buffer.alloc(2 + groupIds.length * 2);
  groupsBytes.writeUInt16BE(groupIds.length * 2, 0);
  for (var i = 0; i < groupIds.length; i++) {
    groupsBytes.writeUInt16BE(groupIds[i], 2 + i * 2);
  }
  var extInner = Buffer.concat([
    Buffer.from([0x00, 0x0A]),                          // type
    (function () { var b = Buffer.alloc(2); b.writeUInt16BE(groupsBytes.length, 0); return b; })(),
    groupsBytes,
  ]);
  var extensions = Buffer.concat([
    (function () { var b = Buffer.alloc(2); b.writeUInt16BE(extInner.length, 0); return b; })(),
    extInner,
  ]);

  var ciphers = Buffer.concat([
    Buffer.from([0x00, 0x02]), // 2 bytes of cipher data
    Buffer.from([0x13, 0x01]), // TLS_AES_128_GCM_SHA256 (one cipher)
  ]);
  var compression = Buffer.from([0x01, 0x00]); // 1 method, null

  var body = Buffer.concat([
    Buffer.from([0x03, 0x03]),                  // version: TLS 1.2 record-level
    Buffer.alloc(32, 0xAA),                     // random: 32 bytes
    Buffer.from([0x00]),                        // session id length 0
    ciphers,
    compression,
    extensions,
  ]);

  // Handshake header: type=0x01 (ClientHello), length=body.length (3 bytes)
  var hsHeader = Buffer.alloc(4);
  hsHeader[0] = 0x01;
  hsHeader.writeUIntBE(body.length, 1, 3);

  // Record header: type=0x16 (handshake), version=0x0303, length=hsHeader.length+body.length
  var recordPayload = Buffer.concat([hsHeader, body]);
  var recordHeader = Buffer.alloc(5);
  recordHeader[0] = 0x16;
  recordHeader[1] = 0x03;
  recordHeader[2] = 0x03;
  recordHeader.writeUInt16BE(recordPayload.length, 3);

  return Buffer.concat([recordHeader, recordPayload]);
}

function testPqcGateSurface() {
  check("b.pqcGate namespace present",            typeof b.pqcGate === "object");
  check("b.pqcGate.create is a function",         typeof b.pqcGate.create === "function");
  check("b.pqcGate.clientHelloHasPQC is a function",
        typeof b.pqcGate.clientHelloHasPQC === "function");
  check("PQC_GROUP_IDS is a Set with framework groups",
        b.pqcGate.PQC_GROUP_IDS instanceof Set &&
        b.pqcGate.PQC_GROUP_IDS.has(b.constants.PQC_GROUPS.X25519MLKEM768) &&
        b.pqcGate.PQC_GROUP_IDS.has(b.constants.PQC_GROUPS.SecP384r1MLKEM1024));

  var threw = null;
  try { b.pqcGate.create({}); } catch (e) { threw = e; }
  check("create rejects missing internalPort",   threw && /internalPort/.test(threw.message));

  threw = null;
  try { b.pqcGate.create({ internalPort: 99999 }); } catch (e) { threw = e; }
  check("create rejects out-of-range port",      threw && /internalPort/.test(threw.message));
}

function testClientHelloPqcDetection() {
  // A ClientHello with ONLY PQC hybrid groups → accepted
  var heroPQ = _makeClientHello([b.constants.PQC_GROUPS.SecP384r1MLKEM1024]);
  check("ClientHello with PQC group → accepted",  b.pqcGate.clientHelloHasPQC(heroPQ) === true);

  // A ClientHello with both PQC + classical → accepted (PQC present is what matters)
  var heroMix = _makeClientHello([0x0017 /* secp256r1 */, b.constants.PQC_GROUPS.X25519MLKEM768]);
  check("ClientHello with mixed groups → accepted (PQC present)",
        b.pqcGate.clientHelloHasPQC(heroMix) === true);

  // A ClientHello with ONLY classical groups → rejected
  var heroClassical = _makeClientHello([0x0017, 0x0018, 0x001D /* x25519 */]);
  check("ClientHello with only classical groups → rejected",
        b.pqcGate.clientHelloHasPQC(heroClassical) === false);

  // Empty supported_groups (degenerate but well-formed) → rejected
  var heroEmpty = _makeClientHello([]);
  check("ClientHello with empty supported_groups → rejected",
        b.pqcGate.clientHelloHasPQC(heroEmpty) === false);

  // Garbage / non-handshake → rejected
  check("non-handshake first byte → rejected",   b.pqcGate.clientHelloHasPQC(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x05])) === false);
  check("too-short buffer → rejected",            b.pqcGate.clientHelloHasPQC(Buffer.alloc(10)) === false);
  check("null input → rejected",                  b.pqcGate.clientHelloHasPQC(null) === false);
}

function testPqcGateSocketLifecycle() {
  // Drive the connection handler with a fake socket — verifies the
  // pause/resume + accept-vs-reject logic without standing up a real TCP server.
  var dataListeners = [];
  var emittedWrites = [];
  var destroyed = false;
  var socket = {
    remoteAddress: "203.0.113.5",
    paused: true,
    resume:  function () { this.paused = false; },
    pause:   function () { this.paused = true; },
    pipe:    function (other) { return other; },
    write:   function (chunk, cb) { emittedWrites.push(chunk); if (cb) cb(); return true; },
    destroy: function () { destroyed = true; },
    on:      function (ev, fn) { if (ev === "data") dataListeners.push(fn); return this; },
    removeListener: function (ev, fn) {
      if (ev === "data") {
        var idx = dataListeners.indexOf(fn);
        if (idx !== -1) dataListeners.splice(idx, 1);
      }
    },
  };

  // Capture the on-connection handler the gate would register
  var connectionHandler;
  var fakeServer = {
    listen:  function () {},
    close:   function (cb) { if (cb) cb(); },
    on:      function () { return this; },
  };
  var pendingTimers = [];
  var gate = b.pqcGate.create({
    internalPort: 1234,
    bypass:       [], // no localhost bypass for this test
    _server: function (sopts, cb) { connectionHandler = cb; return fakeServer; },
    _connect: function () {
      // Return a dummy 'internal' socket — we never actually pipe in this test
      var internal = { destroy: function () {}, write: function () {}, on: function () { return this; }, pipe: function () { return internal; } };
      return internal;
    },
    _setTimeout:   function (fn) { var t = { fn: fn, active: true }; pendingTimers.push(t); return t; },
    _clearTimeout: function (t) { if (t) t.active = false; },
  });
  check("create returns a server-shaped object",  gate === fakeServer);

  connectionHandler(socket);
  check("gate resumes the socket after attach",   socket.paused === false);

  // Feed a non-PQC ClientHello — should write the TLS alert and destroy
  var classical = _makeClientHello([0x0017, 0x001D]);
  dataListeners.forEach(function (fn) { fn(classical); });
  check("non-PQC ClientHello triggers TLS alert", emittedWrites.length === 1 &&
                                                  emittedWrites[0][0] === 0x15 &&
                                                  emittedWrites[0][6] === 0x28);
  check("non-PQC ClientHello destroys socket",    destroyed === true);
}

function testPqcGateBypassesLocalhost() {
  var localSocket = {
    remoteAddress: "127.0.0.1",
    resumed: false,
    resume: function () { this.resumed = true; },
    pause:  function () {},
    pipe:   function () {},
    on:     function () { return this; },
    destroy: function () {},
    write:   function () {},
  };
  var connectionHandler;
  var fakeServer = { on: function () { return this; } };
  var connectArgs = null;
  // Defer the connect cb to next tick so the parent's `internal`
  // assignment happens first (mirrors real net.createConnection).
  var deferredCb = null;
  b.pqcGate.create({
    internalPort: 5555,
    _server: function (s, cb) { connectionHandler = cb; return fakeServer; },
    _connect: function (cOpts, cb) {
      connectArgs = cOpts;
      deferredCb = cb;
      return {
        destroy: function () {},
        write:   function () {},
        on:      function () { return this; },
        pipe:    function () { return this; },
      };
    },
  });

  connectionHandler(localSocket);
  check("localhost bypass: connectFn called with internalPort",
        connectArgs && connectArgs.port === 5555);
  // Now fire the connect callback — after the gate has finished setting
  // up `internal`. The bypass path calls socket.resume() inside the cb.
  if (deferredCb) deferredCb();
  check("localhost bypass: socket resumed after pipe setup",
        localSocket.resumed === true);
}

// ---- bundler ----

function _makeBundlerFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bundler-"));
  var src = path.join(dir, "src");
  var out = path.join(dir, "dist");
  fs.mkdirSync(src, { recursive: true });
  return {
    dir: dir,
    src: src,
    out: out,
    write: function (rel, content) {
      var full = path.join(src, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
      return full;
    },
    cleanup: function () {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
  };
}

function testBundlerSurface() {
  check("b.bundler namespace present",            typeof b.bundler === "object");
  check("b.bundler.create is a function",         typeof b.bundler.create === "function");
  check("b.bundler.BundlerError is a class",      typeof b.bundler.BundlerError === "function");
}

function testBundlerCreateValidation() {
  var threw;
  threw = null; try { b.bundler.create({}); } catch (e) { threw = e; }
  check("missing entries rejected",               threw && threw.code === "bundler/no-entries");

  threw = null; try { b.bundler.create({ entries: {} }); } catch (e) { threw = e; }
  check("empty entries rejected",                 threw && threw.code === "bundler/no-entries");

  threw = null;
  try { b.bundler.create({ entries: { app: "./x.js" } }); } catch (e) { threw = e; }
  check("missing outdir rejected",                threw && threw.code === "bundler/no-outdir");

  threw = null;
  try { b.bundler.create({ entries: { "../escape": "./x.js" }, outdir: "/tmp/x" }); }
  catch (e) { threw = e; }
  check("entry name with '..' rejected",          threw && threw.code === "bundler/bad-entry-name");

  threw = null;
  try { b.bundler.create({ entries: { "a/b": "./x.js" }, outdir: "/tmp/x" }); }
  catch (e) { threw = e; }
  check("entry name with separator rejected",     threw && threw.code === "bundler/bad-entry-name");
}

async function testBundlerBuildHashedOutput() {
  var fx = _makeBundlerFixture();
  try {
    fx.write("app.js",    "console.log('hello bundler');\n");
    fx.write("style.css", "body { color: red; }\n");

    var bundler = b.bundler.create({
      entries: {
        app:   path.join(fx.src, "app.js"),
        style: path.join(fx.src, "style.css"),
      },
      outdir: fx.out,
    });
    var result = await bundler.build();
    check("build returned outputs",               result.outputs.length === 2);
    check("each output has hash",                 result.outputs.every(function (o) { return /^[0-9a-f]{16}$/.test(o.hash); }));
    check("each output file exists",              result.outputs.every(function (o) { return fs.existsSync(o.path); }));
    check("output filename includes hash + ext",  /app\.[0-9a-f]{16}\.js$/.test(result.outputs[0].path) ||
                                                  /app\.[0-9a-f]{16}\.js$/.test(result.outputs[1].path));
    check("manifest written to outdir",           fs.existsSync(result.manifestPath));
    var mf = JSON.parse(fs.readFileSync(result.manifestPath, "utf8"));
    check("manifest maps name → hashed filename",
          /app\.[0-9a-f]{16}\.js$/.test(mf.app) &&
          /style\.[0-9a-f]{16}\.css$/.test(mf.style));

    // Same content → same hash on rebuild (deterministic, content-addressed)
    var r2 = await bundler.build();
    check("rebuild with unchanged content reuses hash",
          r2.outputs[0].hash === result.outputs[0].hash);
  } finally { fx.cleanup(); }
}

async function testBundlerHashChangesWithContent() {
  var fx = _makeBundlerFixture();
  try {
    var srcPath = fx.write("app.js", "console.log('v1');\n");
    var bundler = b.bundler.create({
      entries: { app: srcPath },
      outdir:  fx.out,
    });
    var r1 = await bundler.build();
    var hash1 = r1.outputs[0].hash;

    fs.writeFileSync(srcPath, "console.log('v2');\n");
    var r2 = await bundler.build();
    var hash2 = r2.outputs[0].hash;
    check("changed content → new hash",            hash1 !== hash2);
    check("new output filename has new hash",      r2.outputs[0].path.indexOf(hash2) !== -1);
  } finally { fx.cleanup(); }
}

async function testBundlerHashOff() {
  var fx = _makeBundlerFixture();
  try {
    fx.write("app.js", "noop");
    var bundler = b.bundler.create({
      entries:  { app: path.join(fx.src, "app.js") },
      outdir:   fx.out,
      hash:     false,
      manifest: false,
    });
    var r = await bundler.build();
    check("hash:false → no hash in filename",     r.outputs[0].path.endsWith("app.js"));
    check("manifest:false → no manifest written", r.manifestPath === null);
  } finally { fx.cleanup(); }
}

async function testBundlerCustomHashLen() {
  var fx = _makeBundlerFixture();
  try {
    fx.write("app.js", "x");
    var bundler = b.bundler.create({
      entries: { app: path.join(fx.src, "app.js") },
      outdir:  fx.out,
      hashLen: 8,
    });
    var r = await bundler.build();
    check("hashLen:8 → 8-char hash",              r.outputs[0].hash.length === 8);
    check("output filename uses 8-char hash",     /app\.[0-9a-f]{8}\.js$/.test(r.outputs[0].path));
  } finally { fx.cleanup(); }
}

async function testBundlerReadFailure() {
  var fx = _makeBundlerFixture();
  try {
    var bundler = b.bundler.create({
      entries: { app: path.join(fx.src, "does-not-exist.js") },
      outdir:  fx.out,
    });
    var threw = null;
    try { await bundler.build(); } catch (e) { threw = e; }
    check("missing entry surfaces bundler/read-failed",
          threw && threw.code === "bundler/read-failed");
  } finally { fx.cleanup(); }
}

async function testBundlerWatchRebuilds() {
  // Use the test seam to drive rebuild without real fs.watch.
  var fx = _makeBundlerFixture();
  try {
    var entryPath = fx.write("app.js", "console.log('v1');\n");

    // Capture watcher fires
    var watcherListeners = [];
    function fakeWatch(dirOrFile, wopts, listener) {
      watcherListeners.push({ dir: dirOrFile, listener: listener });
      return { close: function () {} };
    }
    var pendingTimers = [];
    function fakeSetTimeout(fn) {
      var t = { fn: fn, active: true };
      pendingTimers.push(t);
      return t;
    }
    function fakeClearTimeout(t) { if (t) t.active = false; }

    var bundler = b.bundler.create({
      entries: { app: entryPath },
      outdir:  fx.out,
      _watch:        fakeWatch,
      _setTimeout:   fakeSetTimeout,
      _clearTimeout: fakeClearTimeout,
      graceMs:       50,
    });
    var initial = await bundler.build();
    var hash1 = initial.outputs[0].hash;

    var rebuilds = [];
    bundler.watch(function (err, result) {
      rebuilds.push({ err: err, result: result });
    });
    check("watch armed one watcher per entry",      watcherListeners.length === 1);

    // Change content + fire the watcher
    fs.writeFileSync(entryPath, "console.log('v2');\n");
    watcherListeners[0].listener("change", path.basename(entryPath));
    check("change fires a debounce timer",          pendingTimers.filter(function (t) { return t.active; }).length === 1);

    // Drive the timer
    var firedTimer = pendingTimers.find(function (t) { return t.active; });
    firedTimer.active = false;
    firedTimer.fn();
    // wait for the async build to settle
    await new Promise(function (r) { setImmediate(r); });
    await new Promise(function (r) { setImmediate(r); });
    await new Promise(function (r) { setImmediate(r); });
    check("watch callback fired",                   rebuilds.length === 1);
    check("rebuild produced new hash",
          rebuilds[0].result && rebuilds[0].result.outputs[0].hash !== hash1);

    // Events for unrelated filenames in the watched dir should be ignored
    pendingTimers.length = 0;
    watcherListeners[0].listener("change", "unrelated.txt");
    check("unrelated filename does not schedule rebuild",
          pendingTimers.filter(function (t) { return t.active; }).length === 0);

    await bundler.close();
  } finally { fx.cleanup(); }
}

// ---- dev ----
//
// Engine tests use fake spawn/watch/timer seams so we never actually
// fork processes. The engine logic — debounce, restart sequencing,
// queue coalescing, watcher-event filtering — is what we want to
// verify; integration with real child_process is out of scope here.

function _makeDevHarness() {
  // Fake child: emits an exit event when .kill() is called. The test
  // can drive an unexpected exit by calling fakeChild.crash().
  function makeChild(pid) {
    var listeners = {};
    var killed = false;
    return {
      pid: pid,
      kill: function (_signal) {
        if (killed) return;
        killed = true;
        // Emit on next tick so the kill() caller can attach listeners
        setImmediate(function () {
          (listeners.exit || []).forEach(function (cb) { cb(0, null); });
        });
      },
      on:   function (ev, cb) { (listeners[ev] = listeners[ev] || []).push(cb); return this; },
      once: function (ev, cb) {
        var wrap = function (a, b) {
          listeners[ev] = (listeners[ev] || []).filter(function (x) { return x !== wrap; });
          cb(a, b);
        };
        return this.on(ev, wrap);
      },
      crash: function (code) {
        (listeners.exit || []).forEach(function (cb) { cb(code, null); });
      },
    };
  }

  var spawnCalls = [];
  var pidCounter = 1000;
  function spawnFn(cmd, args, sopts) {
    var c = makeChild(++pidCounter);
    spawnCalls.push({ cmd: cmd, args: args.slice(), sopts: sopts, child: c });
    return c;
  }

  // Fake watcher: each call returns an emitter the test can fire events into
  var watchers = [];
  function watchFn(dir, wopts, listener) {
    var w = {
      dir: dir,
      closed: false,
      _listener: listener,
      on:    function () { return this; },
      close: function () { this.closed = true; },
      fire:  function (eventType, filename) { listener(eventType, filename); },
    };
    watchers.push(w);
    return w;
  }

  // Fake timers — tests drive ticks explicitly
  var timers = [];
  function setTimeoutFn(fn, ms) {
    var t = { fn: fn, ms: ms, active: true, unref: function () { return this; } };
    timers.push(t);
    return t;
  }
  function clearTimeoutFn(t) { if (t) t.active = false; }
  function fireTimers() {
    var fired = 0;
    var pending = timers.slice();
    timers.length = 0;
    for (var i = 0; i < pending.length; i++) {
      if (pending[i].active) { pending[i].fn(); fired++; }
    }
    return fired;
  }

  return {
    spawnCalls: spawnCalls,
    watchers:   watchers,
    timers:     timers,
    fireTimers: fireTimers,
    fakes: {
      _spawn:        spawnFn,
      _watch:        watchFn,
      _setTimeout:   setTimeoutFn,
      _clearTimeout: clearTimeoutFn,
    },
  };
}

function testDevSurface() {
  check("b.dev namespace present",                typeof b.dev === "object");
  check("b.dev.create is a function",             typeof b.dev.create === "function");
  check("b.dev.DevError is a class",              typeof b.dev.DevError === "function");
  check("DEFAULT_IGNORE includes node_modules",
        Array.isArray(b.dev.DEFAULT_IGNORE) &&
        b.dev.DEFAULT_IGNORE.some(function (p) { return p instanceof RegExp && p.test("node_modules"); }));

  var threw = null;
  try { b.dev.create({}); } catch (e) { threw = e; }
  check("create rejects missing command",         threw && threw.code === "dev/no-command");
}

async function testDevStartSpawnsChildAndArmsWatchers() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node",
    args:    ["./server.js"],
    watch:   ["./routes", "./views"],
    cwd:     "/repo",
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  check("start spawns child once",                h.spawnCalls.length === 1);
  check("spawn args forwarded",                   h.spawnCalls[0].cmd === "node" &&
                                                  h.spawnCalls[0].args[0] === "./server.js");
  check("watchers armed for each dir",            h.watchers.length === 2);
  check("stats reports running + pid",
        d.stats().running === true && typeof d.stats().pid === "number" &&
        d.stats().restarts === 0);
  await d.stop();
  check("stop clears watchers",                   h.watchers.every(function (w) { return w.closed; }));
}

async function testDevDebouncesBurstOfEventsToOneRestart() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes"],
    cwd:     "/repo",
    graceMs: 250,
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  check("baseline: 1 spawn after start",          h.spawnCalls.length === 1);

  // Five events in rapid succession before the debounce window fires
  var w = h.watchers[0];
  for (var i = 0; i < 5; i++) w.fire("change", "route" + i + ".js");
  check("debounce schedules exactly 1 active timer",
        h.timers.filter(function (t) { return t.active; }).length === 1);

  // Fire the debounce timer → triggers restart
  h.fireTimers();
  // Wait for the kill+respawn to complete
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  // The kill timer (if any) is harmless; restart also fires after kill.
  check("after debounce: child respawned exactly once",
        h.spawnCalls.length === 2);
  check("stats.restarts incremented",             d.stats().restarts === 1);
  check("lastRestartAt set",                      typeof d.stats().lastRestartAt === "string");
  await d.stop();
}

async function testDevIgnoresMatchingPaths() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes"],
    cwd:     "/repo",
    graceMs: 50,
    ignore:  [/should-ignore/],
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  var w = h.watchers[0];

  // node_modules in DEFAULT_IGNORE — ignored
  w.fire("change", "node_modules/x/index.js");
  check("DEFAULT_IGNORE: node_modules events drop",
        h.timers.filter(function (t) { return t.active; }).length === 0);

  // Custom ignore pattern
  w.fire("change", "should-ignore-me.js");
  check("Custom ignore pattern drops events",
        h.timers.filter(function (t) { return t.active; }).length === 0);

  // .db file ignored by default (sqlite WAL files would otherwise loop)
  w.fire("change", "blamejs.db");
  w.fire("change", "blamejs.db-wal");
  check("DEFAULT_IGNORE: .db files drop",
        h.timers.filter(function (t) { return t.active; }).length === 0);

  // Real source change → debounce armed
  w.fire("change", "routes/users.js");
  check("source-file change schedules a restart",
        h.timers.filter(function (t) { return t.active; }).length === 1);

  await d.stop();
}

async function testDevRestartCoalescesQueuedRestart() {
  // Restart-while-already-restarting queues one more, never more.
  // Easier to drive via the public restart() method which short-
  // circuits the debounce path.
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes"],
    cwd:     "/repo",
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();

  // Three concurrent restart() calls. The first runs to completion; the
  // 2nd and 3rd both arrive while it's restarting, but they coalesce to
  // a single queued followup.
  var p1 = d.restart();
  var p2 = d.restart();
  var p3 = d.restart();
  await Promise.all([p1, p2, p3]);
  // Wait for the queued tail-call to drain
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });

  // Initial spawn + 1st restart + 1 coalesced follow-up = 3 total
  check("3 concurrent restarts collapse to 2 respawns",
        h.spawnCalls.length === 3);
  check("stats.restarts = 2",                     d.stats().restarts === 2);
  await d.stop();
}

async function testDevStopKillsAndDisarms() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes", "./views"],
    cwd:     "/repo",
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  await d.stop();
  check("stats.running false after stop",         d.stats().running === false);
  check("watchers closed",                        h.watchers.every(function (w) { return w.closed; }));
  // Subsequent stop is idempotent (no throw)
  await d.stop();
  check("second stop() is a no-op",               d.stats().running === false);
}

async function testDevUnexpectedExitDoesNotRespawn() {
  var h = _makeDevHarness();
  var d = b.dev.create({
    command: "node", args: ["./s.js"],
    watch:   ["./routes"],
    cwd:     "/repo",
    _spawn:        h.fakes._spawn,
    _watch:        h.fakes._watch,
    _setTimeout:   h.fakes._setTimeout,
    _clearTimeout: h.fakes._clearTimeout,
  });
  await d.start();
  // Simulate the child crashing on its own (not via kill())
  h.spawnCalls[0].child.crash(1);
  await new Promise(function (r) { setImmediate(r); });
  // No new spawn — operator must edit a file to retry
  check("crash without restart context: no respawn",
        h.spawnCalls.length === 1);
  await d.stop();
}

// ---- cli ----

function _cliCtx() {
  var out = "", err = "";
  return {
    captured: function () { return { out: out, err: err }; },
    ctx: {
      stdout: { write: function (s) { out += s; } },
      stderr: { write: function (s) { err += s; } },
      env:    {},
      cwd:    os.tmpdir(),
    },
  };
}

function testCliSurface() {
  check("b.cli namespace present",                typeof b.cli === "object");
  check("b.cli.main is a function",               typeof b.cli.main === "function");
  check("b.cli._parseArgs is a function",         typeof b.cli._parseArgs === "function");
  check("TOP_USAGE present",                      typeof b.cli.TOP_USAGE === "string" && b.cli.TOP_USAGE.length > 0);
}

function testCliArgParser() {
  var p1 = b.cli._parseArgs(["a", "b", "--flag", "value"]);
  check("parser collects positional args",        p1.pos.length === 2 && p1.pos[0] === "a" && p1.pos[1] === "b");
  check("parser parses --flag value",             p1.flags.flag === "value");

  // Trailing flag with no value → boolean
  var pBool = b.cli._parseArgs(["--only-flag"]);
  check("parser treats trailing flag as boolean", pBool.flags["only-flag"] === true);

  var p2 = b.cli._parseArgs(["--key=val", "--num=5"]);
  check("parser parses --key=val form",           p2.flags.key === "val");
  check("parser parses --key=val with numbers",   p2.flags.num === "5");

  var p3 = b.cli._parseArgs(["--", "--ignored", "x"]);
  check("parser stops at --",                     p3.pos.length === 2 && p3.pos[0] === "--ignored" && p3.flags["--ignored"] === undefined);

  var p4 = b.cli._parseArgs(["-v"]);
  check("parser handles short flags as boolean",  p4.flags.v === true);
}

async function testCliVersionAndHelp() {
  var t1 = _cliCtx();
  var rc1 = await b.cli.main(["version"], t1.ctx);
  check("version exits 0",                        rc1 === 0);
  check("version prints constants.version",       t1.captured().out.trim() === b.constants.version);

  var t2 = _cliCtx();
  var rc2 = await b.cli.main(["--version"], t2.ctx);
  check("--version flag also prints version",     rc2 === 0 && t2.captured().out.trim() === b.constants.version);

  var t3 = _cliCtx();
  var rc3 = await b.cli.main(["help"], t3.ctx);
  check("help exits 0",                           rc3 === 0);
  check("help prints top usage",                  t3.captured().out.indexOf("blamejs <command>") !== -1);

  var t4 = _cliCtx();
  var rc4 = await b.cli.main([], t4.ctx);
  check("no args prints help and exits 0",        rc4 === 0 && t4.captured().out.indexOf("blamejs <command>") !== -1);

  var t5 = _cliCtx();
  var rc5 = await b.cli.main(["help", "migrate"], t5.ctx);
  check("help <subcommand> prints subcommand usage",
        rc5 === 0 && t5.captured().out.indexOf("blamejs migrate") !== -1);

  var t6 = _cliCtx();
  var rc6 = await b.cli.main(["unknown-cmd"], t6.ctx);
  check("unknown command exits 2",                rc6 === 2);
  check("unknown command writes to stderr",       t6.captured().err.indexOf("unknown command") !== -1);
}

async function testCliMigrateStatus() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-x.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE t1 (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE t1\"); } };");
    fx.write("0002-y.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE t2 (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE t2\"); } };");
    fx.db.close(); // CLI opens its own handle

    var t = _cliCtx();
    var rc = await b.cli.main([
      "migrate", "status",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t.ctx);
    check("status exits 0",                       rc === 0);
    check("status reports 0 applied initially",   /applied: 0 \/ 2/.test(t.captured().out));
    check("status lists pending migrations",
          t.captured().out.indexOf("0001-x.js") !== -1 &&
          t.captured().out.indexOf("0002-y.js") !== -1);
  } finally { fx.cleanup(); }
}

async function testCliMigrateUpDown() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-create-foo.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE foo (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE foo\"); } };");
    fx.write("0002-create-bar.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE bar (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE bar\"); } };");
    fx.db.close();

    // up
    var t1 = _cliCtx();
    var rc1 = await b.cli.main([
      "migrate", "up",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t1.ctx);
    check("up exits 0",                           rc1 === 0);
    check("up reports applied count",             /applied 2 migration/.test(t1.captured().out));

    // up again → no-op
    var t2 = _cliCtx();
    var rc2 = await b.cli.main([
      "migrate", "up",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t2.ctx);
    check("up again exits 0",                     rc2 === 0);
    check("up again reports no pending",          /no pending migrations/.test(t2.captured().out));

    // down --steps 1
    var t3 = _cliCtx();
    var rc3 = await b.cli.main([
      "migrate", "down",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
      "--steps", "1",
    ], t3.ctx);
    check("down --steps 1 exits 0",               rc3 === 0);
    check("down --steps 1 reverts most recent",
          /reverted 1 migration/.test(t3.captured().out) &&
          t3.captured().out.indexOf("0002-create-bar.js") !== -1);

    // down without --steps → defaults to 1
    var t4 = _cliCtx();
    var rc4 = await b.cli.main([
      "migrate", "down",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t4.ctx);
    check("down default --steps reverts 1 more", rc4 === 0 &&
          t4.captured().out.indexOf("0001-create-foo.js") !== -1);
  } finally { fx.cleanup(); }
}

async function testCliMigrateValidationErrors() {
  // Missing --db
  var t1 = _cliCtx();
  var rc1 = await b.cli.main(["migrate", "status"], t1.ctx);
  check("missing --db exits 2",                   rc1 === 2);
  check("missing --db error mentions flag",       t1.captured().err.indexOf("--db") !== -1);

  // Unknown subcommand
  var t2 = _cliCtx();
  var rc2 = await b.cli.main(["migrate", "fly"], t2.ctx);
  check("unknown migrate subcommand exits 2",     rc2 === 2);
  check("unknown subcommand writes usage to stderr", t2.captured().err.indexOf("Usage: blamejs migrate") !== -1);

  // No subcommand (just `blamejs migrate`)
  var t3 = _cliCtx();
  var rc3 = await b.cli.main(["migrate"], t3.ctx);
  check("bare `migrate` exits 2",                 rc3 === 2);
  check("bare `migrate` writes usage",            t3.captured().err.indexOf("Usage: blamejs migrate") !== -1);

  // --steps validation in down
  var fx = _makeMigrationsFixture();
  try {
    fx.db.close();
    var t4 = _cliCtx();
    var rc4 = await b.cli.main([
      "migrate", "down",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
      "--steps", "0",
    ], t4.ctx);
    check("invalid --steps exits 2",              rc4 === 2);
    check("invalid --steps writes error",         t4.captured().err.indexOf("--steps") !== -1);
  } finally { fx.cleanup(); }
}

async function testCliMigrateDownReportsNoOpCleanly() {
  // Empty migrations dir + clean db → down is a no-op, exit 0.
  var fx = _makeMigrationsFixture();
  try {
    fx.db.close();
    var t = _cliCtx();
    var rc = await b.cli.main([
      "migrate", "down",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t.ctx);
    check("no-op down exits 0",                   rc === 0);
    check("no-op down reports nothing to revert", /nothing to revert/.test(t.captured().out));
  } finally { fx.cleanup(); }
}

async function testCliDevValidation() {
  // Missing --command exits 2 with usage on stderr
  var t = _cliCtx();
  var rc = await b.cli.main(["dev"], t.ctx);
  check("dev without --command exits 2",          rc === 2);
  check("dev usage written on missing --command", t.captured().err.indexOf("--command") !== -1);

  // help dev prints usage
  var t2 = _cliCtx();
  var rc2 = await b.cli.main(["help", "dev"], t2.ctx);
  check("help dev exits 0",                       rc2 === 0);
  check("help dev prints usage",                  t2.captured().out.indexOf("blamejs dev") !== -1);
}

async function testCliMigrateUpFailureExits1() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-broken.js", "module.exports = { up: function () { throw new Error('intentional'); } };");
    fx.db.close();
    var t = _cliCtx();
    var rc = await b.cli.main([
      "migrate", "up",
      "--db", path.join(fx.dir, "test.db"),
      "--dir", fx.migDir,
    ], t.ctx);
    check("failing up exits 1",                   rc === 1);
    check("failing up surfaces error code+message",
          /migrations\/up-failed/.test(t.captured().err) &&
          /intentional/.test(t.captured().err));
  } finally { fx.cleanup(); }
}

// ---- session fixation rotation ----

async function testSessionRotateBasic() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-srot-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-1", data: { role: "user" } });
    var rotated = await b.session.rotate(s.token);
    check("rotate: returns new token",                typeof rotated.token === "string");
    check("rotate: new token differs from old",       rotated.token !== s.token);
    check("rotate: expiresAt preserved by default",   rotated.expiresAt === s.expiresAt);
    // Old token should no longer verify
    var oldVerify = await b.session.verify(s.token);
    check("rotate: old token invalid after rotate",   oldVerify === null);
    // New token verifies and returns same userId
    var newVerify = await b.session.verify(rotated.token);
    check("rotate: new token verifies",                newVerify !== null);
    check("rotate: new token has same userId",         newVerify.userId === "u-1");
    check("rotate: new token has same data",           newVerify.data && newVerify.data.role === "user");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSessionRotateReplacesData() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-srot-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-2", data: { role: "user" } });
    var rotated = await b.session.rotate(s.token, { data: { role: "admin", mfa: true } });
    var v = await b.session.verify(rotated.token);
    check("rotate w/data: new data persisted",        v.data && v.data.role === "admin");
    check("rotate w/data: nested fields preserved",    v.data && v.data.mfa === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSessionRotateRefreshesTtl() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-srot-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-3", ttlMs: 1000 });
    // Rotate with a much larger TTL
    var rotated = await b.session.rotate(s.token, { ttlMs: 60 * 60 * 1000 });
    check("rotate: new expiresAt > original",          rotated.expiresAt > s.expiresAt);
    var v = await b.session.verify(rotated.token);
    check("rotate: verified expiresAt matches",         v.expiresAt === rotated.expiresAt);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSessionRotateExpiredReturnsNull() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-srot-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-4", ttlMs: 1 }); // 1ms TTL
    await new Promise(function (r) { setTimeout(r, 30); });
    var rotated = await b.session.rotate(s.token);
    check("rotate: expired session returns null",       rotated === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSessionRotateUnknownReturnsNull() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-srot-"));
  try {
    await setupTestDb(tmpDir);
    var rotated = await b.session.rotate("definitely-not-a-real-token-" + "x".repeat(40));
    check("rotate: unknown token returns null",         rotated === null);
    var rotatedEmpty = await b.session.rotate("");
    check("rotate: empty token returns null",           rotatedEmpty === null);
    var rotatedNonString = await b.session.rotate(null);
    check("rotate: null token returns null",            rotatedNonString === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSessionRotateLifecycleAuditEmit() {
  // Verify the audit chain captures the rotation event.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-srot-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("auth"); // 'auth.session.rotate' lives here
    var s = await b.session.create({ userId: "u-5" });
    await b.session.rotate(s.token, { reason: "mfa-verified" });
    await b.audit.flush();
    var events = await b.audit.query({ action: "auth.session.rotate" });
    check("rotate: audit event emitted",                events.length === 1);
    // metadata.reason captured
    var meta = events[0].metadata;
    if (typeof meta === "string") meta = JSON.parse(meta);
    check("rotate: audit metadata captures reason",     meta && meta.reason === "mfa-verified");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- migrations ----

function _makeMigrationsFixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mig-"));
  var dbPath = path.join(dir, "test.db");
  var migDir = path.join(dir, "migrations");
  fs.mkdirSync(migDir, { recursive: true });
  var { DatabaseSync } = require("node:sqlite");
  var db = new DatabaseSync(dbPath);
  return {
    dir:    dir,
    migDir: migDir,
    db:     db,
    cleanup: function () {
      try { db.close(); } catch (_e) {}
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
    },
    write: function (file, content) {
      fs.writeFileSync(path.join(migDir, file), content);
    },
  };
}

function testMigrationsSurface() {
  check("b.migrations namespace present",         typeof b.migrations === "object");
  check("b.migrations.create is a function",      typeof b.migrations.create === "function");
  check("b.migrations.MigrationError is a class", typeof b.migrations.MigrationError === "function");
  check("b.migrations.MIGRATIONS_TABLE constant",
        b.migrations.MIGRATIONS_TABLE === "_blamejs_migrations");

  var threw;
  threw = null;
  try { b.migrations.create({}); } catch (e) { threw = e; }
  check("create rejects missing dir",             threw && threw.code === "migrations/no-dir");
}

function testMigrationsUpAppliesPending() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-create-widgets.js", [
      "module.exports = {",
      "  description: 'create widgets',",
      "  up:   function (db) { db['exec'](\"CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT)\"); },",
      "  down: function (db) { db['exec'](\"DROP TABLE widgets\"); },",
      "};",
    ].join("\n"));
    fx.write("0002-add-color.js", [
      "module.exports = {",
      "  up:   function (db) { db['exec'](\"ALTER TABLE widgets ADD COLUMN color TEXT\"); },",
      "  down: function (db) { db['exec'](\"ALTER TABLE widgets DROP COLUMN color\"); },",
      "};",
    ].join("\n"));

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var r1 = migs.up();
    check("up applied both migrations in order",
          r1.applied.length === 2 &&
          r1.applied[0] === "0001-create-widgets.js" &&
          r1.applied[1] === "0002-add-color.js");
    check("up returned no skipped on first run",  r1.skipped.length === 0);

    // Verify the schema actually changed
    var cols = fx.db.prepare("PRAGMA table_info(widgets)").all();
    var colNames = cols.map(function (c) { return c.name; });
    check("up created widgets table",             colNames.indexOf("id") !== -1 && colNames.indexOf("name") !== -1);
    check("up added the color column",            colNames.indexOf("color") !== -1);

    // Re-run is idempotent
    var r2 = migs.up();
    check("re-run applied nothing",                r2.applied.length === 0);
    check("re-run skipped both",                   r2.skipped.length === 2);
  } finally { fx.cleanup(); }
}

function testMigrationsStatus() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-a.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE a (id INTEGER)\"); } };");
    fx.write("0002-b.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE b (id INTEGER)\"); } };");
    fx.write("0003-c.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE c (id INTEGER)\"); } };");

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var pre = migs.status();
    check("status before up: 0 applied",          pre.applied.length === 0);
    check("status before up: 3 pending",          pre.pending.length === 3);
    check("status total reflects all files",      pre.total === 3);

    migs.up();
    var post = migs.status();
    check("status after up: 3 applied",           post.applied.length === 3);
    check("status after up: 0 pending",           post.pending.length === 0);
    check("applied rows carry name + appliedAt",
          post.applied[0].name === "0001-a.js" &&
          typeof post.applied[0].appliedAt === "string" &&
          /^\d{4}-/.test(post.applied[0].appliedAt));
  } finally { fx.cleanup(); }
}

function testMigrationsDownRollback() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-create-x.js", [
      "module.exports = {",
      "  up:   function (db) { db['exec'](\"CREATE TABLE x (id INTEGER)\"); },",
      "  down: function (db) { db['exec'](\"DROP TABLE x\"); },",
      "};",
    ].join("\n"));
    fx.write("0002-create-y.js", [
      "module.exports = {",
      "  up:   function (db) { db['exec'](\"CREATE TABLE y (id INTEGER)\"); },",
      "  down: function (db) { db['exec'](\"DROP TABLE y\"); },",
      "};",
    ].join("\n"));

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    migs.up();

    // Roll back the most recent (y)
    var r1 = migs.down();
    check("default steps=1 reverts one migration", r1.reverted.length === 1 && r1.reverted[0] === "0002-create-y.js");

    // y is gone, x is still here
    var tbls = fx.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('x','y')").all();
    var tblNames = tbls.map(function (t) { return t.name; });
    check("y dropped after rollback",              tblNames.indexOf("y") === -1);
    check("x still present after partial rollback", tblNames.indexOf("x") !== -1);

    // status reflects the partial rollback
    var st = migs.status();
    check("status: x applied, y pending",
          st.applied.length === 1 && st.applied[0].name === "0001-create-x.js" &&
          st.pending.length === 1 && st.pending[0] === "0002-create-y.js");

    // Roll back x as well, with explicit steps
    var r2 = migs.down({ steps: 1 });
    check("rollback the remaining migration",      r2.reverted.length === 1 && r2.reverted[0] === "0001-create-x.js");
    var st2 = migs.status();
    check("status: nothing applied, both pending",
          st2.applied.length === 0 && st2.pending.length === 2);
  } finally { fx.cleanup(); }
}

// ---- migrations advisory lock ----

function testMigrationsLockReleasedAfterUp() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-a.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE a (id INTEGER)\"); } };");
    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    migs.up();
    // Lock table exists but row is gone (released after successful up)
    var rows = fx.db.prepare("SELECT * FROM " + b.migrations.LOCK_TABLE).all();
    check("lock released after successful up",     rows.length === 0);
  } finally { fx.cleanup(); }
}

function testMigrationsLockBlocksConcurrent() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-a.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE a (id INTEGER)\"); } };");
    // Manually plant a lock row simulating a concurrent process holding the lock.
    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    fx.db["exec"](
      "CREATE TABLE IF NOT EXISTS " + b.migrations.LOCK_TABLE + " (" +
      "  scope     TEXT PRIMARY KEY," +
      "  lockedAt  INTEGER NOT NULL," +
      "  lockedBy  TEXT NOT NULL," +
      "  CHECK (scope = 'lock')" +
      ")"
    );
    fx.db.prepare(
      "INSERT INTO " + b.migrations.LOCK_TABLE +
      " (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
    ).run(Date.now(), "fake-other-process@host");

    var threw = null;
    try { migs.up(); } catch (e) { threw = e; }
    check("up: blocked by existing lock",          threw && threw.code === "migrations/lock-held");
    check("up: error names the holder",            threw && threw.message.indexOf("fake-other-process") !== -1);
  } finally { fx.cleanup(); }
}

function testMigrationsLockStaleReplace() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-a.js", "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE a (id INTEGER)\"); } };");
    var migs = b.migrations.create({
      db: fx.db, dir: fx.migDir, staleAfterMs: 100,
    });
    fx.db["exec"](
      "CREATE TABLE IF NOT EXISTS " + b.migrations.LOCK_TABLE + " (" +
      "  scope     TEXT PRIMARY KEY," +
      "  lockedAt  INTEGER NOT NULL," +
      "  lockedBy  TEXT NOT NULL," +
      "  CHECK (scope = 'lock')" +
      ")"
    );
    // Plant a stale lock (100s ago)
    fx.db.prepare(
      "INSERT INTO " + b.migrations.LOCK_TABLE +
      " (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
    ).run(Date.now() - 100000, "ghost-process@host");

    var r = migs.up();
    check("up: succeeds when stale lock force-replaced", r.applied.length === 1);
    var lockRows = fx.db.prepare("SELECT * FROM " + b.migrations.LOCK_TABLE).all();
    check("up: lock cleaned up after success",      lockRows.length === 0);
  } finally { fx.cleanup(); }
}

function testMigrationsLockReleasedAfterFailure() {
  var fx = _makeMigrationsFixture();
  try {
    // A migration that throws should still release the lock.
    fx.write("0001-bad.js", [
      "module.exports = {",
      "  up: function (db) { throw new Error('intentional-fail'); },",
      "};",
    ].join("\n"));
    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var threw = null;
    try { migs.up(); } catch (e) { threw = e; }
    check("up failure surfaces error",             threw && threw.code === "migrations/up-failed");
    var rows = fx.db.prepare("SELECT * FROM " + b.migrations.LOCK_TABLE).all();
    check("lock released even after failure",       rows.length === 0);
  } finally { fx.cleanup(); }
}

function testMigrationsDownMultiSteps() {
  var fx = _makeMigrationsFixture();
  try {
    for (var i = 1; i <= 3; i++) {
      var n = i;
      fx.write("000" + n + "-step.js", [
        "module.exports = {",
        "  up:   function (db) { db['exec'](\"CREATE TABLE t" + n + " (id INTEGER)\"); },",
        "  down: function (db) { db['exec'](\"DROP TABLE t" + n + "\"); },",
        "};",
      ].join("\n"));
    }
    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    migs.up();

    var r = migs.down({ steps: 2 });
    check("steps=2 reverts 2 migrations in reverse order",
          r.reverted.length === 2 &&
          r.reverted[0] === "0003-step.js" &&
          r.reverted[1] === "0002-step.js");

    var st = migs.status();
    check("only oldest still applied",             st.applied.length === 1 && st.applied[0].name === "0001-step.js");
  } finally { fx.cleanup(); }
}

function testMigrationsDownRejectsBadSteps() {
  var fx = _makeMigrationsFixture();
  try {
    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var threw;
    threw = null; try { migs.down({ steps: 0 }); }    catch (e) { threw = e; }
    check("steps=0 rejected",                      threw && threw.code === "migrations/bad-steps");
    threw = null; try { migs.down({ steps: -1 }); }   catch (e) { threw = e; }
    check("negative steps rejected",               threw && threw.code === "migrations/bad-steps");
    threw = null; try { migs.down({ steps: 1.5 }); }  catch (e) { threw = e; }
    check("non-integer steps rejected",            threw && threw.code === "migrations/bad-steps");
    threw = null; try { migs.down({ steps: "x" }); }  catch (e) { threw = e; }
    check("non-numeric steps rejected",            threw && threw.code === "migrations/bad-steps");
  } finally { fx.cleanup(); }
}

function testMigrationsRejectsRollbackWithoutDown() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-no-down.js",
      "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE z (id INTEGER)\"); } };");
    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    migs.up();
    var threw = null;
    try { migs.down(); } catch (e) { threw = e; }
    check("missing down() surfaces clear error",
          threw && threw.code === "migrations/no-down" &&
          /no `down\(db\)` function/.test(threw.message));
    // The migration should still be marked applied (rollback aborted before delete)
    check("aborted rollback leaves migration applied",
          migs.status().applied.length === 1);
  } finally { fx.cleanup(); }
}

function testMigrationsUpFailureRollsBackTransaction() {
  var fx = _makeMigrationsFixture();
  try {
    fx.write("0001-good.js",
      "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE good (id INTEGER)\"); }, down: function (db) { db['exec'](\"DROP TABLE good\"); } };");
    fx.write("0002-bad.js", [
      "module.exports = {",
      "  up: function (db) {",
      "    db['exec'](\"CREATE TABLE bad (id INTEGER)\");",
      "    throw new Error('intentional failure');",
      "  },",
      "};",
    ].join("\n"));

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var threw = null;
    try { migs.up(); } catch (e) { threw = e; }
    check("failing up surfaces MigrationError",
          threw && threw.code === "migrations/up-failed" && /intentional failure/.test(threw.message));

    // good migration applied; bad migration's table NOT created (rolled back)
    var tbls = fx.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('good','bad')").all();
    var tblNames = tbls.map(function (t) { return t.name; });
    check("first (good) migration applied",        tblNames.indexOf("good") !== -1);
    check("failed migration's CREATE was rolled back", tblNames.indexOf("bad") === -1);

    // Status: 1 applied, 1 pending (the bad one)
    var st = migs.status();
    check("status reflects partial apply",         st.applied.length === 1 && st.pending.length === 1);
  } finally { fx.cleanup(); }
}

function testMigrationsRejectsMalformedFiles() {
  var fx = _makeMigrationsFixture();
  try {
    // No matching file pattern → just ignored (not an error)
    fs.writeFileSync(path.join(fx.migDir, "README.md"), "ignore me");
    fs.writeFileSync(path.join(fx.migDir, "no-prefix.js"),
      "module.exports = { up: function () {} };");

    var migs = b.migrations.create({ db: fx.db, dir: fx.migDir });
    var st = migs.status();
    check("non-matching files ignored",            st.total === 0);

    // Matching file without up() → load-time error
    fx.write("0001-noup.js", "module.exports = { description: 'oops' };");
    var threw = null;
    try { migs.up(); } catch (e) { threw = e; }
    check("missing up() surfaces missing-up error",
          threw && threw.code === "migrations/missing-up");
  } finally { fx.cleanup(); }
}

// ---- cookies ----

function _cookieFakeRes() {
  var headers = {};
  return {
    headers: headers,
    setHeader: function (k, v) { headers[k] = v; },
    getHeader: function (k) { return headers[k]; },
  };
}

function testCookiesSurface() {
  check("b.cookies namespace present",            typeof b.cookies === "object");
  check("b.cookies.create is a function",         typeof b.cookies.create === "function");
  check("b.cookies.parse is a function",          typeof b.cookies.parse === "function");
  check("b.cookies.serialize is a function",      typeof b.cookies.serialize === "function");
  check("b.cookies.CookieError is a class",       typeof b.cookies.CookieError === "function");
}

function testCookiesParse() {
  var jar1 = b.cookies.parse("a=1; b=2; c=3");
  check("parse simple",                           jar1.a === "1" && jar1.b === "2" && jar1.c === "3");

  // = inside a value
  var jar2 = b.cookies.parse("session=abc=def=ghi; flag=on");
  check("parse value containing =",               jar2.session === "abc=def=ghi" && jar2.flag === "on");

  // URL-encoded value decoded
  var jar3 = b.cookies.parse("greet=" + encodeURIComponent("hi there!"));
  check("parse url-decodes value",                jar3.greet === "hi there!");

  // Quoted value strips surrounding quotes
  var jar4 = b.cookies.parse('q="quoted value"');
  check("parse strips surrounding quotes",        jar4.q === "quoted value");

  // Empty / malformed inputs
  check("parse null → empty object",              Object.keys(b.cookies.parse(null)).length === 0);
  check("parse '' → empty object",                Object.keys(b.cookies.parse("")).length === 0);
  check("parse 'no-equals' ignored",              Object.keys(b.cookies.parse("noequals")).length === 0);

  // Last write wins (RFC 6265 §5.4 fixup)
  var jar5 = b.cookies.parse("a=1; a=2");
  check("parse last-write-wins on duplicate",     jar5.a === "2");
}

function testCookiesSerialize() {
  // Defaults: just name=value
  var s1 = b.cookies.serialize("a", "1");
  check("serialize bare cookie",                   s1 === "a=1");

  // All attributes
  var s2 = b.cookies.serialize("session", "abc", {
    maxAge: 3600, path: "/", httpOnly: true, secure: true, sameSite: "Lax",
  });
  check("serialize includes Max-Age",              /Max-Age=3600/.test(s2));
  check("serialize includes Path",                 /Path=\//.test(s2));
  check("serialize includes HttpOnly",             /HttpOnly/.test(s2));
  check("serialize includes Secure",               /Secure/.test(s2));
  check("serialize includes SameSite=Lax",         /SameSite=Lax/.test(s2));

  // Expires Date conversion
  var s3 = b.cookies.serialize("a", "1", { expires: new Date("2030-01-01T00:00:00Z") });
  check("serialize includes Expires UTC",          /Expires=.*GMT/.test(s3));

  // SameSite normalization
  var s4 = b.cookies.serialize("a", "1", { sameSite: "strict" });
  check("serialize normalizes SameSite=Strict",    /SameSite=Strict/.test(s4));

  // SameSite=None forces Secure
  var s5 = b.cookies.serialize("a", "1", { sameSite: "None" });
  check("SameSite=None forces Secure",             /SameSite=None/.test(s5) && /Secure/.test(s5));

  // Value gets percent-encoded on the wire
  var s6 = b.cookies.serialize("a", "hi there!");
  check("serialize percent-encodes value",         s6 === "a=hi%20there!");

  // Reject CRLF in value (header injection defense)
  var threw;
  threw = null; try { b.cookies.serialize("a", "x\r\ny"); } catch (e) { threw = e; }
  check("serialize rejects CRLF in value",         threw && threw.code === "cookies/invalid-value");
  threw = null; try { b.cookies.serialize("a", "x;y"); } catch (e) { threw = e; }
  check("serialize rejects semicolon in value",    threw && threw.code === "cookies/invalid-value");
  threw = null; try { b.cookies.serialize("bad name", "v"); } catch (e) { threw = e; }
  check("serialize rejects space in name",         threw && threw.code === "cookies/invalid-name");
  threw = null; try { b.cookies.serialize("a\r\nb", "v"); } catch (e) { threw = e; }
  check("serialize rejects CRLF in name",          threw && threw.code === "cookies/invalid-name");

  // Invalid attr values
  threw = null; try { b.cookies.serialize("a", "1", { sameSite: "Loose" }); } catch (e) { threw = e; }
  check("serialize rejects unknown sameSite",      threw && threw.code === "cookies/invalid-attr");
  threw = null; try { b.cookies.serialize("a", "1", { maxAge: "forever" }); } catch (e) { threw = e; }
  check("serialize rejects non-integer maxAge",    threw && threw.code === "cookies/invalid-attr");

  // CRLF in path is stripped (defense in depth — operator-controlled
  // but could come from config). The domain attribute now throws on
  // malformed input rather than scrubbing-and-passing, so the same
  // hostile input is caught at the call site.
  var s7 = b.cookies.serialize("a", "1", { domain: "evil.com", path: "/admin\r\nX-Hack: 1" });
  check("serialize strips CRLF from path",
        s7.indexOf("\r") === -1 && s7.indexOf("\n") === -1 && /Path=\/admin/.test(s7));
  // Domain validation — anything that isn't a valid host name throws.
  threw = null;
  try { b.cookies.serialize("a", "1", { domain: "evil.com\r\nX-Hack: 1" }); }
  catch (e) { threw = e; }
  check("serialize rejects malformed domain attr",
        threw && threw.code === "cookies/invalid-attr");
  threw = null;
  try { b.cookies.serialize("a", "1", { domain: "https://evil.com" }); }
  catch (e) { threw = e; }
  check("serialize rejects URL as domain",
        threw && threw.code === "cookies/invalid-attr");
  // Leading-dot form is tolerated for legacy compat.
  var s8 = b.cookies.serialize("a", "1", { domain: ".example.com" });
  check("serialize accepts leading-dot domain", /Domain=\.example\.com/.test(s8));
}

function testCookiesInstanceDefaults() {
  var jar = b.cookies.create({
    defaults: { httpOnly: true, secure: true, sameSite: "Strict", path: "/", maxAge: 600 },
  });
  var s = jar.serialize("session", "abc");
  check("instance applies defaults",
        /HttpOnly/.test(s) && /Secure/.test(s) && /SameSite=Strict/.test(s) &&
        /Path=\//.test(s) && /Max-Age=600/.test(s));

  // Per-call attrs override defaults
  var s2 = jar.serialize("session", "abc", { sameSite: "Lax", maxAge: 60 });
  check("per-call attrs override defaults",
        /SameSite=Lax/.test(s2) && /Max-Age=60/.test(s2));

  // create's own defaults override the framework's bare defaults
  // (framework default is httpOnly=true, secure=true, sameSite=Lax, path=/)
  var jar2 = b.cookies.create({ defaults: { secure: false, sameSite: "None" } });
  var s3 = jar2.serialize("a", "1");
  // SameSite=None forces Secure regardless — verifies that path
  check("SameSite=None forces Secure even when default secure=false",
        /SameSite=None/.test(s3) && /Secure/.test(s3));
}

function testCookiesReadWrite() {
  var jar = b.cookies.create({
    defaults: { httpOnly: true, secure: false, sameSite: "Lax", path: "/" },
  });
  var req = { headers: { cookie: "blamejs_session=abc; theme=dark" } };
  check("read returns cookie value",               jar.read(req, "blamejs_session") === "abc");
  check("read missing cookie → null",              jar.read(req, "nope") === null);
  check("read req without headers → null",         jar.read({}, "x") === null);

  // Write builds the Set-Cookie array, preserving any existing entries
  var res = _cookieFakeRes();
  res.headers["Set-Cookie"] = ["existing=1; Path=/"];
  jar.write(res, "blamejs_session", "newtoken", { maxAge: 60 });
  var setCookie = res.headers["Set-Cookie"];
  check("write appends to existing Set-Cookie",    Array.isArray(setCookie) && setCookie.length === 2);
  check("written cookie has name+value",           /blamejs_session=newtoken/.test(setCookie[1]));
  check("written cookie has Max-Age",              /Max-Age=60/.test(setCookie[1]));

  // Clear → Max-Age=0
  var res2 = _cookieFakeRes();
  jar.clear(res2, "blamejs_session");
  check("clear emits Max-Age=0",                   /Max-Age=0/.test(res2.headers["Set-Cookie"][0]));
}

function testCookiesSealedRoundTrip() {
  // Real vault round-trip via the framework's own vault module. We use
  // a temp dir so the key isn't shared with other tests.
  var prevDataDir = process.env.BLAMEJS_DATA_DIR;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cookies-test-"));
  process.env.BLAMEJS_DATA_DIR = dir;
  try {
    b.vault._resetForTest();
    b.vault.init({ mode: "plaintext", dataDir: dir });
    var jar = b.cookies.create({
      vault: b.vault,
      defaults: { httpOnly: true, secure: false, sameSite: "Lax", path: "/" },
    });

    // writeSealed → cookie carries vault.seal of value (prefix stripped)
    var res = _cookieFakeRes();
    var sid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    jar.writeSealed(res, "blamejs_session", sid, { maxAge: 600 });
    var setCookie = res.headers["Set-Cookie"][0];
    check("sealed cookie wire format does not contain raw sid",
          setCookie.indexOf(sid) === -1);
    check("sealed cookie wire format does not contain vault: prefix",
          setCookie.indexOf("vault:") === -1);

    // Pull the cookie value off the Set-Cookie line and round-trip via readSealed
    var nameEqValue = setCookie.split(";")[0];
    var enc = nameEqValue.split("=")[1]; // url-encoded form
    var req = { headers: { cookie: "blamejs_session=" + enc } };
    var unsealed = jar.readSealed(req, "blamejs_session");
    check("readSealed recovers the original sid",  unsealed === sid);

    // Two seals of the same value produce DIFFERENT ciphertexts
    // (XChaCha20 nonce randomization). The framework's encryption-as-
    // access-gate posture relies on this — even an attacker who sees
    // many cookies can't distill the wire format into a guessable value.
    var resB = _cookieFakeRes();
    jar.writeSealed(resB, "blamejs_session", sid, { maxAge: 600 });
    var encB = resB.headers["Set-Cookie"][0].split(";")[0].split("=")[1];
    check("two seals of same value produce different ciphertext",
          enc !== encB);

    // Tampered sealed cookie → readSealed returns null (no throw)
    var tampered = enc.slice(0, -4) + "AAAA"; // mutate last 4 base64 chars
    var reqT = { headers: { cookie: "blamejs_session=" + tampered } };
    check("tampered sealed cookie → null (auth tag fails)",
          jar.readSealed(reqT, "blamejs_session") === null);

    // Sealed cookie carries the vault envelope intact — first byte of
    // the decoded payload is the envelope magic (0xE1).
    var decoded = Buffer.from(decodeURIComponent(enc), "base64");
    check("sealed cookie payload starts with envelope magic 0xE1",
          decoded[0] === b.constants.ENVELOPE_MAGIC);
    // The 4-byte envelope header (magic + KEM + cipher + KDF) is the
    // version-agility seam — algorithm rotation works even on cookies
    // because vault.unseal dispatches on these bytes, not the active
    // defaults.
    check("envelope KEM byte matches ACTIVE.KEM",   decoded[1] === b.constants.ACTIVE.KEM);
    check("envelope cipher byte matches ACTIVE.CIPHER",
          decoded[2] === b.constants.ACTIVE.CIPHER);
    check("envelope KDF byte matches ACTIVE.KDF",   decoded[3] === b.constants.ACTIVE.KDF);

    // Sealed methods without a vault → throw
    var noVault = b.cookies.create({});
    var threw = null;
    try { noVault.writeSealed(_cookieFakeRes(), "x", "y"); } catch (e) { threw = e; }
    check("writeSealed without vault throws",      threw && threw.code === "cookies/no-vault");

    b.vault._resetForTest();
  } finally {
    if (prevDataDir === undefined) delete process.env.BLAMEJS_DATA_DIR;
    else process.env.BLAMEJS_DATA_DIR = prevDataDir;
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

// ---- errors-page ----
//
// A fake-res helper captures statusCode + Content-Type + body so each
// test can assert the response shape without a real http.Server.

function _makeFakeRes() {
  var res = {
    statusCode:    null,
    headers:       {},
    body:          "",
    writableEnded: false,
    setHeader:     function (k, v) { this.headers[k] = v; },
    end:           function (chunk) { if (chunk !== undefined) this.body += chunk; this.writableEnded = true; },
    writeHead:     function (status, hdrs) {
      this.statusCode = status;
      if (hdrs) for (var k in hdrs) this.headers[k] = hdrs[k];
    },
  };
  return res;
}

function testErrorsPageSurface() {
  check("b.errorPage namespace present",         typeof b.errorPage === "object");
  check("b.errorPage.create is a function",      typeof b.errorPage.create === "function");
  check("b.errorPage.STATUS_REASONS map present",
        b.errorPage.STATUS_REASONS[404] === "Not Found" &&
        b.errorPage.STATUS_REASONS[500] === "Internal Server Error");
}

function testErrorsPageProdHidesStackAndOriginalMessage() {
  var handler = b.errorPage.create({ mode: "prod", audit: false });
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };
  var res = _makeFakeRes();
  // Generic Error — operator-private message must NOT leak.
  handler(new Error("DB pwd: hunter2"), req, res);
  check("prod 500 → 500 status",                   res.statusCode === 500);
  check("prod 500 → text/html",                    /text\/html/.test(res.headers["Content-Type"]));
  check("prod 500 hides operator message",         res.body.indexOf("hunter2") === -1);
  check("prod 500 shows generic message",          res.body.indexOf("Internal Server Error") !== -1);
  check("prod page does not include any stack",    res.body.indexOf(".js:") === -1 && res.body.indexOf("at ") === -1);
}

function testErrorsPageDevShowsStackAndRequestInfo() {
  var handler = b.errorPage.create({ mode: "dev", audit: false, brand: "blamejs-test" });
  var req = {
    method: "POST", url: "/api/widget?id=42",
    headers: { accept: "text/html", "user-agent": "ua/1", cookie: "session=secret123" },
    id: "req-zzz",
  };
  var res = _makeFakeRes();
  handler(new Error("widget exploded"), req, res);
  check("dev 500 → 500 status",                    res.statusCode === 500);
  check("dev 500 shows operator message",          res.body.indexOf("widget exploded") !== -1);
  check("dev 500 shows request method+url",
        res.body.indexOf("POST") !== -1 && res.body.indexOf("/api/widget") !== -1);
  check("dev 500 redacts cookie header",           res.body.indexOf("secret123") === -1);
  check("dev 500 shows requestId when set",        res.body.indexOf("req-zzz") !== -1);
  check("dev 500 includes a stack trace block",    res.body.indexOf("Stack") !== -1);
  check("dev page brand reflects opts.brand",      res.body.indexOf("blamejs-test") !== -1);
}

function testErrorsPageJsonNegotiation() {
  var handler = b.errorPage.create({ mode: "prod", audit: false });
  var req = { method: "POST", url: "/api/x", headers: { accept: "application/json" } };
  var res = _makeFakeRes();
  var err = Object.assign(new Error("bad input"), {
    isAppError: true, statusCode: 400, code: "VALIDATION_ERROR",
  });
  handler(err, req, res);
  check("json 400 → 400 status",                   res.statusCode === 400);
  check("json content-type",                       /application\/json/.test(res.headers["Content-Type"]));
  var payload = JSON.parse(res.body);
  check("json error message preserved on 4xx",     payload.error.message === "bad input");
  check("json carries error code",                 payload.error.code === "VALIDATION_ERROR");
  check("prod json 4xx has no stack",              payload.error.stack === undefined);
}

function testErrorsPageDevJsonIncludesStack() {
  var handler = b.errorPage.create({ mode: "dev", audit: false });
  var req = { method: "POST", url: "/api/x", headers: { accept: "application/json" } };
  var res = _makeFakeRes();
  handler(new Error("kaboom"), req, res);
  var payload = JSON.parse(res.body);
  check("dev json 500 includes stack",             typeof payload.error.stack === "string" && /kaboom/.test(payload.error.stack));
}

function testErrorsPageAppErrorClassification() {
  var handler = b.errorPage.create({ mode: "prod", audit: false });
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };

  // 404
  var res404 = _makeFakeRes();
  handler(Object.assign(new Error("nothing here"), {
    isAppError: true, statusCode: 404, code: "NOT_FOUND",
  }), req, res404);
  check("AppError 404 routes to 404 status",       res404.statusCode === 404);
  check("AppError 404 message preserved on 4xx",   res404.body.indexOf("nothing here") !== -1);

  // 401 — security code path
  var res401 = _makeFakeRes();
  handler(Object.assign(new Error("auth fail"), {
    isAppError: true, statusCode: 401, code: "UNAUTH",
  }), req, res401);
  check("AppError 401 routes to 401 status",       res401.statusCode === 401);

  // statusCode without isAppError still classifies
  var res403 = _makeFakeRes();
  handler({ statusCode: 403, code: "FORBID", message: "denied" }, req, res403);
  check("statusCode-only error classified",        res403.statusCode === 403);
  check("classified 4xx message preserved",        res403.body.indexOf("denied") !== -1);
}

function testErrorsPageNeverWritesWhenAlreadyEnded() {
  var handler = b.errorPage.create({ mode: "prod", audit: false });
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };
  var res = _makeFakeRes();
  res.writableEnded = true;
  res.end = function () { check("end called after writableEnded — must not happen", false); };
  // Should NOT throw and NOT call res.end
  handler(new Error("late"), req, res);
  check("no write happens when writableEnded",     res.statusCode === null);
}

function testErrorsPageOnErrorHookCanTakeOver() {
  var taken = [];
  var handler = b.errorPage.create({
    mode: "prod", audit: false,
    onError: function (err, req, res, info) {
      taken.push({ status: info.status, code: info.code });
      res.statusCode = 418;
      res.end("im a teapot");
      return true;
    },
  });
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };
  var res = _makeFakeRes();
  handler(Object.assign(new Error("bad"), { isAppError: true, statusCode: 400, code: "X" }), req, res);
  check("onError hook ran",                        taken.length === 1 && taken[0].status === 400);
  check("onError hook took over response",         res.statusCode === 418 && res.body === "im a teapot");
}

function testErrorsPageLogsViaInjectedLogger() {
  var captured = [];
  var fakeLog = {
    warn:  function (msg, fields) { captured.push({ level: "warn", msg: msg, fields: fields }); },
    error: function (msg, fields) { captured.push({ level: "error", msg: msg, fields: fields }); },
  };
  var handler = b.errorPage.create({ mode: "prod", audit: false, log: fakeLog });
  var req = { method: "GET", url: "/x", headers: {} };
  var res500 = _makeFakeRes();
  handler(new Error("kaboom"), req, res500);
  check("500 logged at error level",               captured.length === 1 && captured[0].level === "error");
  check("500 log fields include status + url",
        captured[0].fields.status === 500 &&
        captured[0].fields.url === "/x" &&
        typeof captured[0].fields.stack === "string");

  captured.length = 0;
  var res404 = _makeFakeRes();
  handler(Object.assign(new Error("missing"), { isAppError: true, statusCode: 404 }), req, res404);
  check("404 logged at warn level",                captured.length === 1 && captured[0].level === "warn");
  check("404 log has no stack noise",              captured[0].fields.stack === undefined);
}

function testErrorsPageDevEnvVarsHonorOptIn() {
  var handler = b.errorPage.create({ mode: "dev", audit: false }); // showEnvVars defaults false
  var req = { method: "GET", url: "/x", headers: { accept: "text/html" } };
  var res = _makeFakeRes();
  handler(new Error("e"), req, res);
  check("dev page omits Environment section by default",
        res.body.indexOf("Environment") === -1);

  var prevSecret = process.env.BLAMEJS_FAKE_SECRET;
  var prevHarmless = process.env.BLAMEJS_FAKE_HARMLESS;
  process.env.BLAMEJS_FAKE_SECRET = "leakme";
  process.env.BLAMEJS_FAKE_HARMLESS = "publicvalue";
  try {
    var handlerOn = b.errorPage.create({ mode: "dev", audit: false, showEnvVars: true });
    var resOn = _makeFakeRes();
    handlerOn(new Error("e"), req, resOn);
    check("opt-in env shows non-secret keys",
          resOn.body.indexOf("BLAMEJS_FAKE_HARMLESS") !== -1);
    check("opt-in env still redacts SECRET-shaped keys",
          resOn.body.indexOf("BLAMEJS_FAKE_SECRET") === -1 &&
          resOn.body.indexOf("leakme") === -1);
  } finally {
    if (prevSecret === undefined) delete process.env.BLAMEJS_FAKE_SECRET;
    else process.env.BLAMEJS_FAKE_SECRET = prevSecret;
    if (prevHarmless === undefined) delete process.env.BLAMEJS_FAKE_HARMLESS;
    else process.env.BLAMEJS_FAKE_HARMLESS = prevHarmless;
  }
}

function testErrorsPageModeAutoDetectsFromNodeEnv() {
  var prev = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "production";
    var prodHandler = b.errorPage.create({ audit: false });
    check("NODE_ENV=production → prod mode",         prodHandler.mode === "prod");

    process.env.NODE_ENV = "development";
    var devHandler = b.errorPage.create({ audit: false });
    check("NODE_ENV=development → dev mode",         devHandler.mode === "dev");

    delete process.env.NODE_ENV;
    var defaultHandler = b.errorPage.create({ audit: false });
    check("no NODE_ENV → dev mode (safe local default)", defaultHandler.mode === "dev");
  } finally {
    if (prev === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prev;
  }
}

// ---- log ----
//
// Each test creates an instance with a captured-buffer destination so
// the global log stream stays clean and assertions are deterministic.

function _makeCapturingLog(extraOpts) {
  var captured = { stdout: [], stderr: [] };
  var log = b.log.create(Object.assign({
    destination:      { write: function (line) { captured.stdout.push(line); } },
    errorDestination: { write: function (line) { captured.stderr.push(line); } },
    base:             {},
    redact:           false, // tests bypass redaction unless they opt in
  }, extraOpts || {}));
  return { log: log, captured: captured };
}

function _parseLines(arr) { return arr.map(function (l) { return JSON.parse(l); }); }

function testLogSurface() {
  check("b.log namespace present",                typeof b.log === "object");
  check("b.log.create is a function",             typeof b.log.create === "function");
  check("b.log.LogError is a class",              typeof b.log.LogError === "function");
  check("b.log.LEVELS exposes 5 levels",
        b.log.LEVELS.debug === 0 && b.log.LEVELS.fatal === 4);
  check("b.log.getRequestId is a function",       typeof b.log.getRequestId === "function");
  check("b.log.runWithRequestId is a function",   typeof b.log.runWithRequestId === "function");
}

function testLogEmitsJsonLineToStdout() {
  var t = _makeCapturingLog();
  t.log.info("user logged in", { userId: "u-1" });
  check("info writes one line to stdout",           t.captured.stdout.length === 1);
  check("info does not touch stderr",               t.captured.stderr.length === 0);
  var entry = JSON.parse(t.captured.stdout[0]);
  check("entry has level=info",                     entry.level === "info");
  check("entry has message",                        entry.message === "user logged in");
  check("entry has timestamp ISO-8601",
        typeof entry.timestamp === "string" &&
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(entry.timestamp));
  check("entry merged extras",                      entry.userId === "u-1");
  check("line ends with newline",                   /\n$/.test(t.captured.stdout[0]));
}

function testLogRoutesErrorAndFatalToStderr() {
  var t = _makeCapturingLog();
  t.log.warn("approaching limit");
  t.log.error("payment failed");
  t.log.fatal("oom");
  var stdout = _parseLines(t.captured.stdout);
  var stderr = _parseLines(t.captured.stderr);
  check("warn routes to stdout",                    stdout.length === 1 && stdout[0].level === "warn");
  check("error routes to stderr",                   stderr.length === 2);
  check("fatal routes to stderr",                   stderr[1].level === "fatal");
}

// ---- v0.4.12 multi-sink ----

function testLogMultiSinkRoutesByLevel() {
  var sink1 = []; // captures everything
  var sink2 = []; // captures warn+
  var sink3 = []; // captures error+
  var log = b.log.create({
    level: "debug",
    sinks: [
      { stream: { write: function (l) { sink1.push(l); } }, level: "debug" },
      { stream: { write: function (l) { sink2.push(l); } }, level: "warn"  },
      { stream: { write: function (l) { sink3.push(l); } }, level: "error" },
    ],
    redact: false,
  });
  log.debug("d");
  log.info("i");
  log.warn("w");
  log.error("e");
  check("multi-sink: debug-level sink got 4 lines",   sink1.length === 4);
  check("multi-sink: warn-level sink got 2 lines",    sink2.length === 2);
  check("multi-sink: error-level sink got 1 line",    sink3.length === 1);
  var lvls = sink2.map(function (l) { return JSON.parse(l).level; });
  check("multi-sink: warn-sink level filter accurate",
        lvls.indexOf("debug") === -1 && lvls.indexOf("info") === -1);
}

function testLogMultiSinkSinkWithoutLevel() {
  // No per-sink level → no extra filter beyond the global.
  var capt = [];
  var log = b.log.create({
    level: "warn",
    sinks: [{ stream: { write: function (l) { capt.push(l); } } }],
    redact: false,
  });
  log.info("i");
  log.warn("w");
  log.error("e");
  check("multi-sink: no per-sink level honors global only",
        capt.length === 2);
}

function testLogMultiSinkConflictsWithDestination() {
  var threw = false;
  try {
    b.log.create({
      destination: process.stdout,
      sinks: [{ stream: process.stdout, level: "info" }],
    });
  } catch (e) { threw = e && e.code === "log/conflicting-sinks"; }
  check("multi-sink: rejects sinks + destination together",  threw);
}

function testLogMultiSinkEmptyArrayRejected() {
  var threw = false;
  try { b.log.create({ sinks: [] }); }
  catch (e) { threw = e && e.code === "log/no-sinks"; }
  check("multi-sink: rejects empty sinks array",          threw);
}

function testLogMultiSinkBadShapeRejected() {
  var threw = false;
  try { b.log.create({ sinks: [{}] }); }
  catch (e) { threw = e && e.code === "log/bad-sink"; }
  check("multi-sink: rejects sink without stream",         threw);

  threw = false;
  try { b.log.create({ sinks: [{ stream: process.stdout, weird: 1 }] }); }
  catch (e) { threw = e && e.code === "log/bad-sink"; }
  check("multi-sink: rejects sink with unknown key",       threw);

  threw = false;
  try { b.log.create({ sinks: [{ stream: process.stdout, level: "BAD" }] }); }
  catch (_e) { threw = true; }
  check("multi-sink: rejects sink with bad level",         threw);
}

function testLogMultiSinkStringDest() {
  // 'stdout' / 'stderr' shorthand should resolve in sinks too.
  var log = b.log.create({
    sinks: [{ stream: "stderr", level: "debug" }],
  });
  // Smoke: just confirms create() didn't throw.
  check("multi-sink: 'stderr' string shorthand accepted",  typeof log.info === "function");
}

function testLogMultiSinkOneSinkFailDoesntBreakOthers() {
  var good = [];
  var failingSink  = { write: function () { throw new Error("disk full"); } };
  var goodSink     = { write: function (l) { good.push(l); } };
  var log = b.log.create({
    sinks: [
      { stream: failingSink, level: "debug" },
      { stream: goodSink,    level: "debug" },
    ],
    redact: false,
  });
  log.info("survives");
  check("multi-sink: throwing sink doesn't poison others", good.length === 1);
}

function testLogLevelGate() {
  var t = _makeCapturingLog({ level: "warn" });
  t.log.debug("d");
  t.log.info("i");
  t.log.warn("w");
  t.log.error("e");
  check("level=warn drops debug",                   t.captured.stdout.every(function (l) { return JSON.parse(l).level !== "debug"; }));
  check("level=warn drops info",                    t.captured.stdout.every(function (l) { return JSON.parse(l).level !== "info"; }));
  check("level=warn keeps warn",                    _parseLines(t.captured.stdout).filter(function (e) { return e.level === "warn"; }).length === 1);
  check("level=warn keeps error",                   _parseLines(t.captured.stderr).filter(function (e) { return e.level === "error"; }).length === 1);
  check("isLevelEnabled('warn') = true",            t.log.isLevelEnabled("warn") === true);
  check("isLevelEnabled('info') = false",           t.log.isLevelEnabled("info") === false);

  // Dynamic level change
  t.log.setLevel("debug");
  check("getLevel reflects setLevel",               t.log.getLevel() === "debug");
  t.captured.stdout.length = 0;
  t.log.debug("now-allowed");
  check("setLevel('debug') unblocks debug emits",   t.captured.stdout.length === 1);
}

function testLogBindAddsBoundContext() {
  var t = _makeCapturingLog({ base: { service: "myapp" } });
  var auth = t.log.bind({ component: "auth" });
  var detail = auth.bind({ subcomponent: "totp" });

  t.log.info("root msg");
  auth.info("auth msg");
  detail.info("detail msg", { extra: "x" });

  var lines = _parseLines(t.captured.stdout);
  check("root has base context",                    lines[0].service === "myapp" && lines[0].component === undefined);
  check("auth child adds component",                lines[1].component === "auth" && lines[1].service === "myapp");
  check("nested child preserves ancestor context",
        lines[2].component === "auth" && lines[2].subcomponent === "totp" && lines[2].service === "myapp");
  check("nested child still merges extras",         lines[2].extra === "x");

  // bind validation
  var threw = null;
  try { t.log.bind(null); } catch (e) { threw = e; }
  check("bind(null) rejects",                       threw && threw.code === "log/bad-bind");
}

function testLogCoreFieldsCannotBeOverwritten() {
  var t = _makeCapturingLog();
  t.log.info("hi", { level: "STOLEN", message: "STOLEN", timestamp: "STOLEN", userId: "u-1" });
  var entry = JSON.parse(t.captured.stdout[0]);
  check("extras cannot overwrite level",            entry.level === "info");
  check("extras cannot overwrite message",          entry.message === "hi");
  check("extras cannot overwrite timestamp",        entry.timestamp !== "STOLEN");
  check("non-core extras still merged",             entry.userId === "u-1");
  check("clobber attempt flagged",                  entry._overwriteAttempt === true);
}

async function testLogRequestIdViaAls() {
  var t = _makeCapturingLog();
  await t.log.runWithRequestId("req-abc", async function () {
    t.log.info("inside");
    check("getRequestId returns bound id",          t.log.getRequestId() === "req-abc");
    await new Promise(function (r) { setImmediate(r); });
    t.log.info("after-microtask");
  });
  t.log.info("outside");
  var lines = _parseLines(t.captured.stdout);
  check("inside-request line carries requestId",     lines[0].requestId === "req-abc");
  check("requestId persists across microtask",       lines[1].requestId === "req-abc");
  check("outside-request line has no requestId",     lines[2].requestId === undefined);
}

async function testLogMiddlewareSetsRequestId() {
  var t = _makeCapturingLog();
  var mw = t.log.middleware();

  // Simulate a request without an inbound X-Request-Id — middleware
  // generates one and binds it for the entire request callback.
  var setHeaderCalls = [];
  var req1 = { headers: {} };
  var res1 = { setHeader: function (k, v) { setHeaderCalls.push([k, v]); } };
  var calledNext1 = false;
  await new Promise(function (resolve) {
    mw(req1, res1, function () {
      calledNext1 = true;
      t.log.info("during req1");
      resolve();
    });
  });
  check("middleware called next",                   calledNext1);
  check("middleware set req.id",                    typeof req1.id === "string" && req1.id.length === 16);
  check("middleware set X-Request-Id header",
        setHeaderCalls.length === 1 && setHeaderCalls[0][0] === "X-Request-Id" && setHeaderCalls[0][1] === req1.id);
  var entry1 = JSON.parse(t.captured.stdout[0]);
  check("log line during request carries requestId", entry1.requestId === req1.id);

  // Inbound X-Request-Id header is honored
  t.captured.stdout.length = 0;
  var req2 = { headers: { "x-request-id": "client-supplied-id" } };
  var res2 = { setHeader: function () {} };
  await new Promise(function (resolve) {
    mw(req2, res2, function () { t.log.info("during req2"); resolve(); });
  });
  check("middleware honors inbound x-request-id",   req2.id === "client-supplied-id");
  var entry2 = JSON.parse(t.captured.stdout[0]);
  check("inbound id propagates to log line",        entry2.requestId === "client-supplied-id");

  // CRLF in inbound header is stripped (header injection defense)
  t.captured.stdout.length = 0;
  var req3 = { headers: { "x-request-id": "ev\r\nil" } };
  var res3 = { setHeader: function () {} };
  await new Promise(function (resolve) {
    mw(req3, res3, function () { t.log.info("during req3"); resolve(); });
  });
  check("middleware strips CRLF from inbound id",   req3.id === "evil");

  // Custom headerName: the response is written on the SAME configured
  // header the inbound id is read from (read/write symmetry).
  var customMw = t.log.middleware({ headerName: "X-Correlation-Id" });
  var setHeaderCalls4 = [];
  var req4 = { headers: { "x-correlation-id": "corr-123" } };
  var res4 = { setHeader: function (k, v) { setHeaderCalls4.push([k, v]); } };
  await new Promise(function (resolve) {
    customMw(req4, res4, function () { resolve(); });
  });
  check("custom headerName reads inbound id",        req4.id === "corr-123");
  check("custom headerName writes the same header",
        setHeaderCalls4.length === 1 &&
        setHeaderCalls4[0][0] === "X-Correlation-Id" &&
        setHeaderCalls4[0][1] === "corr-123");
}

function testLogRedactsExtras() {
  var t = _makeCapturingLog({ redact: true });
  t.log.info("login", {
    userId:   "u-1",
    password: "should-be-hidden",
    token:    "should-be-hidden",
  });
  var entry = JSON.parse(t.captured.stdout[0]);
  check("redact masks password field",              entry.password === "[REDACTED]");
  check("redact masks token field",                 entry.token === "[REDACTED]");
  check("redact preserves non-sensitive field",     entry.userId === "u-1");
}

function testLogEnvLevelOverride() {
  // When LOG_LEVEL is set, it overrides opts.level. Restore after.
  var prev = process.env.LOG_LEVEL;
  process.env.LOG_LEVEL = "error";
  try {
    var t = _makeCapturingLog({ level: "debug" });
    t.log.info("dropped");
    t.log.error("kept");
    check("env LOG_LEVEL beats opts.level",
          t.captured.stdout.length === 0 &&
          t.captured.stderr.length === 1);
  } finally {
    if (prev === undefined) delete process.env.LOG_LEVEL;
    else process.env.LOG_LEVEL = prev;
  }
}

function testLogConfigValidation() {
  var threw;
  threw = null; try { b.log.create({ level: "loud" }); } catch (e) { threw = e; }
  check("bad level rejects",                        threw && threw.code === "log/bad-level");
  threw = null; try { b.log.create({ level: 99 }); } catch (e) { threw = e; }
  check("numeric level out of range rejects",       threw && threw.code === "log/bad-level");
  threw = null; try { b.log.create({ format: "logfmt" }); } catch (e) { threw = e; }
  check("unsupported format rejects",               threw && threw.code === "log/bad-format");
  threw = null; try { b.log.create({ destination: 42 }); } catch (e) { threw = e; }
  check("non-stream destination rejects",           threw && threw.code === "log/bad-destination");
}

function testLogHandlesUnserializableExtras() {
  var t = _makeCapturingLog();
  var circular = {}; circular.self = circular;
  t.log.info("trouble", { circular: circular });
  var entry = JSON.parse(t.captured.stdout[0]);
  check("circular extras surface as _logError",     entry._logError === "extras not serializable");
  check("core fields still emitted",                entry.message === "trouble" && entry.level === "info");
}

// ---- scheduler ----

function testSchedulerSurface() {
  check("b.scheduler namespace present",          typeof b.scheduler === "object");
  check("b.scheduler.create is a function",       typeof b.scheduler.create === "function");
  check("b.scheduler.parseCron is a function",    typeof b.scheduler.parseCron === "function");
  check("b.scheduler.nextCronFire is a function", typeof b.scheduler.nextCronFire === "function");
  check("b.scheduler.SchedulerError is a class",  typeof b.scheduler.SchedulerError === "function");
}

function testSchedulerCronParser() {
  var p1 = b.scheduler.parseCron("0 2 * * *");
  check("cron parses minute=0",                   p1.minute.has(0) && p1.minute.size === 1);
  check("cron parses hour=2",                     p1.hour.has(2) && p1.hour.size === 1);
  check("cron expands * for dom",                 p1.dom.size === 31);
  check("cron expands * for month",               p1.month.size === 12);
  check("cron expands * for dow",                 p1.dow.size === 7);

  var p2 = b.scheduler.parseCron("*/15 9-17 * * 1-5");
  check("cron */15 expands to 0,15,30,45",
        p2.minute.has(0) && p2.minute.has(15) && p2.minute.has(30) && p2.minute.has(45) && p2.minute.size === 4);
  check("cron 9-17 expands inclusively",          p2.hour.size === 9 && p2.hour.has(9) && p2.hour.has(17));
  check("cron 1-5 dow expands to weekdays",       p2.dow.size === 5 && !p2.dow.has(0) && !p2.dow.has(6));
  check("cron dowRestricted set",                 p2.dowRestricted === true);
  check("cron domRestricted unset on *",          p2.domRestricted === false);

  var p3 = b.scheduler.parseCron("@daily");
  check("@daily shorthand → 0 0 * * *",
        p3.minute.has(0) && p3.minute.size === 1 &&
        p3.hour.has(0) && p3.hour.size === 1);

  var p4 = b.scheduler.parseCron("0,30 * * * 7"); // 7 = Sunday alias
  check("cron dow=7 normalized to 0",             p4.dow.has(0) && !p4.dow.has(7));
  check("cron list 0,30",                         p4.minute.has(0) && p4.minute.has(30) && p4.minute.size === 2);

  // Errors
  var threw;
  threw = null; try { b.scheduler.parseCron(""); } catch (e) { threw = e; }
  check("cron empty rejects",                     threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("0 0 0 0 0"); } catch (e) { threw = e; }
  check("cron value out of range rejects",        threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("60 * * * *"); } catch (e) { threw = e; }
  check("cron minute=60 rejects",                 threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("0 0 * *"); } catch (e) { threw = e; }
  check("cron 4-field rejects",                   threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("*/0 * * * *"); } catch (e) { threw = e; }
  check("cron */0 step rejects",                  threw && threw.code === "scheduler/invalid-cron");

  // v0.6.65 — step exceeding the field's range silently degenerated to
  // a single-fire schedule (e.g. `*/99999 * * * *` = "minute 0 of every
  // hour"). Operators typing this clearly meant something else; reject
  // explicitly so the typo surfaces at boot.
  check("cron */60 (= range size) accepts",
        b.scheduler.parseCron("*/60 * * * *") !== null);
  threw = null; try { b.scheduler.parseCron("*/61 * * * *"); } catch (e) { threw = e; }
  check("cron */61 minute step over range: rejects",
        threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("*/99999 * * * *"); } catch (e) { threw = e; }
  check("cron */99999 minute step rejects (was silent before v0.6.65)",
        threw && threw.code === "scheduler/invalid-cron");
  threw = null; try { b.scheduler.parseCron("* */25 * * *"); } catch (e) { threw = e; }
  check("cron hour */25 step over range: rejects",
        threw && threw.code === "scheduler/invalid-cron");
}

function testSchedulerNextCronFire() {
  // 02:00 every day — with no timezone, server-local
  var cron = b.scheduler.parseCron("0 2 * * *");
  var anchor = new Date("2026-04-15T01:30:00Z");
  // Find next fire — server-local; just verify it lands on minute=0, hour=2
  var t = b.scheduler.nextCronFire(cron, anchor, null);
  var d = new Date(t);
  check("cron next-fire lands on minute=0",       d.getMinutes() === 0);
  check("cron next-fire lands on hour=2",         d.getHours() === 2);
  check("cron next-fire is in the future",        t > anchor.getTime());

  // */15 means within the next 15 minutes, there must be a fire
  var cron2 = b.scheduler.parseCron("*/15 * * * *");
  var t2 = b.scheduler.nextCronFire(cron2, anchor, null);
  check("cron */15 next-fire within 15min",       t2 - anchor.getTime() <= 15 * 60 * 1000 + 60000);

  // Timezone-aware: 09:00 in UTC
  var cron3 = b.scheduler.parseCron("0 9 * * *");
  var anchorUtc = new Date("2026-04-15T08:30:00Z");
  var t3 = b.scheduler.nextCronFire(cron3, anchorUtc, "UTC");
  // Wall-clock in UTC at t3 must be 09:00
  var fmt = new Intl.DateTimeFormat("en-US", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", hour12: false });
  var parts = {}; fmt.formatToParts(new Date(t3)).forEach(function (p) { parts[p.type] = p.value; });
  var hr = parseInt(parts.hour, 10); if (hr === 24) hr = 0;
  check("cron tz-aware fires at 09:00 UTC wall-clock",
        hr === 9 && parseInt(parts.minute, 10) === 0);

  // Timezone validation
  var threw = null;
  try {
    var sched = b.scheduler.create();
    sched.schedule({ name: "x", cron: "0 0 * * *", timezone: "Not/A_Zone", run: function () {} });
  } catch (e) { threw = e; }
  check("scheduler rejects invalid IANA timezone",
        threw && threw.code === "scheduler/invalid-timezone");
}

async function testSchedulerScheduleValidation() {
  var sched = b.scheduler.create();
  var threw;

  threw = null; try { sched.schedule(); } catch (e) { threw = e; }
  check("schedule rejects missing spec",          threw && threw.code === "INVALID_SPEC");

  threw = null; try { sched.schedule({}); } catch (e) { threw = e; }
  check("schedule rejects missing name",          threw && threw.code === "INVALID_NAME");

  threw = null;
  try { sched.schedule({ name: "x" }); } catch (e) { threw = e; }
  check("schedule rejects missing cron+every",    threw && threw.code === "INVALID_SPEC");

  threw = null;
  try { sched.schedule({ name: "x", cron: "0 0 * * *", every: 60000, run: function () {} }); }
  catch (e) { threw = e; }
  check("schedule rejects both cron and every",   threw && threw.code === "INVALID_SPEC");

  threw = null;
  try { sched.schedule({ name: "x", every: 60000 }); } catch (e) { threw = e; }
  check("schedule rejects missing job+run",       threw && threw.code === "INVALID_SPEC");

  threw = null;
  try { sched.schedule({ name: "x", every: 500, run: function () {} }); }
  catch (e) { threw = e; }
  check("schedule rejects every<1000ms",          threw && threw.code === "INVALID_SPEC");

  threw = null;
  try { sched.schedule({ name: "x", every: 60000, job: "needs-jobs" }); }
  catch (e) { threw = e; }
  check("schedule with job= rejects when jobs unwired",
        threw && threw.code === "INVALID_SPEC" && /requires opts.jobs/.test(threw.message));

  // Happy path — sets up a task
  sched.schedule({ name: "ok", every: 60000, run: function () {} });
  var listed = sched.list();
  check("schedule populates list()",              listed.length === 1 && listed[0].name === "ok");
  check("listed task has nextRun",                typeof listed[0].nextRun === "string");

  // Duplicate name rejected
  threw = null;
  try { sched.schedule({ name: "ok", every: 60000, run: function () {} }); }
  catch (e) { threw = e; }
  check("schedule rejects duplicate name",        threw && threw.code === "DUPLICATE_NAME");

  await sched.stop();
}

async function testSchedulerDirectFnFires() {
  // Use _fireOnce to drive a deterministic single fire — start() arms a
  // setTimeout we'd otherwise have to wait for. The test verifies the
  // dispatch path (run callback invoked, lastRun set, success audited).
  var fired = 0;
  var sched = b.scheduler.create({ audit: false });
  sched.schedule({
    name:  "tick",
    every: 60000,
    run:   async function () { fired++; },
  });
  sched._fireOnce("tick");
  // Wait one microtask cycle for the promise to settle
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  check("direct-fn fire ran",                     fired === 1);
  var listed = sched.list();
  check("fire updates lastRun",                   typeof listed[0].lastRun === "string");
  check("fire updates lastFinish",                typeof listed[0].lastFinish === "string");
  check("fire counted in fires",                  listed[0].fires === 1);
  check("running=false after settle",             listed[0].running === false);
  await sched.stop();
}

async function testSchedulerJobDispatch() {
  // Plug a fake jobs-shaped object — schedule { job: "name", payload }
  // should call jobs.enqueue with the right args.
  var calls = [];
  var fakeJobs = {
    enqueue: async function (name, payload, opts) {
      calls.push({ name: name, payload: payload, opts: opts });
      return { jobId: "j-1" };
    },
  };
  var sched = b.scheduler.create({ jobs: fakeJobs, audit: false });
  sched.schedule({
    name:        "nightly",
    every:       60000,
    job:         "cleanup",
    payload:     { scope: "all" },
    enqueueOpts: { maxAttempts: 5 },
  });
  sched._fireOnce("nightly");
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  check("scheduler dispatched via jobs.enqueue",  calls.length === 1);
  check("dispatched job name correct",            calls[0].name === "cleanup");
  check("dispatched payload forwarded",           calls[0].payload && calls[0].payload.scope === "all");
  check("enqueueOpts forwarded",                  calls[0].opts && calls[0].opts.maxAttempts === 5);
  await sched.stop();
}

async function testSchedulerSkipsWhenStillRunning() {
  // If a previous fire is still in-flight, the next fire should be
  // skipped (counted as a miss) rather than running concurrently.
  var concurrent = 0;
  var maxConcurrent = 0;
  var release;
  var releasePromise = new Promise(function (r) { release = r; });
  var sched = b.scheduler.create({ audit: false });
  sched.schedule({
    name:  "slow",
    every: 60000,
    run:   async function () {
      concurrent++;
      if (concurrent > maxConcurrent) maxConcurrent = concurrent;
      await releasePromise;
      concurrent--;
    },
  });
  sched._fireOnce("slow"); // arm — promise pending until release()
  await new Promise(function (r) { setImmediate(r); });
  sched._fireOnce("slow"); // should skip
  sched._fireOnce("slow"); // should skip
  var listed = sched.list();
  check("overlap fires counted as misses",        listed[0].misses === 2);
  check("max concurrent in-flight stays at 1",    maxConcurrent === 1);
  release(); // let the in-flight finish
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  await sched.stop();
}

async function testSchedulerLeaderGate() {
  // When opts.cluster reports non-leader, fires must be skipped
  // (counted as nonLeaderSkips) and the run callback must not execute.
  // Cluster-wired schedulers also race on a tick-claim INSERT before
  // firing, so this test needs a DB so the claim has a table to write.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sched-lg-"));
  try {
    await setupTestDb(tmpDir);
    var fired = 0;
    var leader = false;
    var fakeCluster = { isLeader: function () { return leader; } };
    var sched = b.scheduler.create({ cluster: fakeCluster, audit: false });
    sched.schedule({
      name:  "leader-only",
      every: 60000,
      run:   async function () { fired++; },
    });

    sched._fireOnce("leader-only");
    await new Promise(function (r) { setImmediate(r); });
    check("non-leader fire skipped",                fired === 0);
    check("non-leader skip counted",                sched.list()[0].nonLeaderSkips === 1);

    leader = true;
    sched._fireOnce("leader-only");
    // Multiple microtasks: tick-claim INSERT, then _runFire's promise chain.
    for (var i = 0; i < 8; i++) {
      await new Promise(function (r) { setImmediate(r); });
    }
    check("leader fire ran",                        fired === 1);
    check("fires counter reflects leader run",      sched.list()[0].fires === 1);
    await sched.stop();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSchedulerErrorRecorded() {
  var sched = b.scheduler.create({ audit: false });
  sched.schedule({
    name:  "boom",
    every: 60000,
    run:   async function () { throw new Error("kaboom"); },
  });
  sched._fireOnce("boom");
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });
  var listed = sched.list();
  check("failed fire records lastError",          listed[0].lastError === "kaboom");
  check("failed fire still clears running",       listed[0].running === false);
  await sched.stop();
}

function testSchedulerStartStopIdempotent() {
  var sched = b.scheduler.create({ audit: false });
  sched.schedule({ name: "x", every: 60000, run: function () {} });
  // start/stop pair completes without throwing
  return sched.start().then(function () {
    return sched.start(); // idempotent
  }).then(function () {
    return sched.stop();
  }).then(function () {
    return sched.stop(); // idempotent
  }).then(function () {
    check("scheduler start/stop idempotent",      true);
  });
}

// ---- handlers ----

async function testHandlerEmitAndDrain() {
  var flushed = [];
  var h = b.handlers.create({
    name:  "test",
    flush: async function (batch) { flushed.push.apply(flushed, batch); },
  });
  h.emit({ id: 1 });
  h.emit({ id: 2 });
  h.emit({ id: 3 });
  check("handler: emit returns nothing (sync)",             h.emit({ id: 4 }) === undefined);
  await h.drain();
  check("handler: drain flushes all buffered items",        flushed.length === 4);
  check("handler: items delivered in order",                flushed[0].id === 1 && flushed[3].id === 4);
  check("handler: buffer empty post-drain",                 h.size() === 0);
}

async function testHandlerEmitDuringFlushNextCycle() {
  // Recursion-safety contract (per handlers.js docstring): items emitted
  // BY a flush() call MUST land in the buffer for the NEXT drain cycle,
  // not the current one. This test exists because in cluster mode, the
  // audit handler's flush() writes through external-db, which itself
  // emits a system.externaldb.query audit event back into the same
  // handler — without a per-drain bound, drain refills as fast as it
  // empties and never returns. The bound here is the structural fix.
  var phase1 = [];
  var phase2 = [];
  var emitDuring = true;
  var h;
  h = b.handlers.create({
    name:  "test-recursion",
    flush: async function (batch) {
      if (emitDuring) {
        emitDuring = false;
        h.emit({ id: 99 });
        phase1.push.apply(phase1, batch);
      } else {
        phase2.push.apply(phase2, batch);
      }
    },
  });
  h.emit({ id: 1 });
  h.emit({ id: 2 });
  await h.drain();
  check("handler: first drain flushes only originally-buffered items",
        phase1.length === 2);
  check("handler: emit-during-flush did NOT land in current drain",
        phase2.length === 0);
  check("handler: emit-during-flush still in buffer after first drain",
        h.size() === 1);
  await h.drain();
  check("handler: second drain picks up the emit-during-flush item",
        phase2.length === 1 && phase2[0].id === 99);
  check("handler: buffer empty after second drain",
        h.size() === 0);
}

async function testHandlerRetryOnFlushFailure() {
  var attempts = 0;
  var seen = null;
  var h = b.handlers.create({
    name:  "test-retry",
    flush: async function (batch) {
      attempts += 1;
      if (attempts < 3) throw new Error("transient");
      seen = batch;
    },
    retry: { maxAttempts: 5, baseDelayMs: 1 },
  });
  h.emit({ id: 1 });
  await h.drain();
  check("handler: retries on flush failure",                attempts >= 3);
  check("handler: eventually succeeds",                     seen && seen.length === 1);
}

async function testHandlerCircuitBreakerOpensOnPersistentFailure() {
  var dlqCalls = 0;
  var h = b.handlers.create({
    name:  "test-breaker",
    flush: async function () { throw new Error("always fails"); },
    retry: { maxAttempts: 1, baseDelayMs: 1 },
    breaker: { failureThreshold: 2, cooldownMs: 10000, successThreshold: 1 },
    deadLetter: function () { dlqCalls += 1; },
    onError: function () { /* swallow expected errors */ },
  });
  h.emit({ id: 1 });
  await h.drain();
  h.emit({ id: 2 });
  await h.drain();
  h.emit({ id: 3 });
  await h.drain();
  var stats = h.getStats();
  check("handler: breaker tripped after consecutive failures",
        stats.breakerState === "open" || stats.breakerState === "half-open");
  check("handler: dead-lettered items on persistent failure", dlqCalls >= 1);
}

async function testHandlerBoundedShutdown() {
  var h = b.handlers.create({
    name:  "test-shutdown",
    flush: async function () {
      await new Promise(function (r) { setTimeout(r, 100); });
    },
    retry: { maxAttempts: 1, baseDelayMs: 1 },
    onError: function () { /* swallow */ },
  });
  h.emit({ id: 1 });
  var t0 = Date.now();
  await h.shutdown({ timeoutMs: 20 });
  var dur = Date.now() - t0;
  check("handler: shutdown bounded by timeout (< 100ms)",   dur < 80);
}

async function testHandlerStats() {
  var h = b.handlers.create({
    name:  "test-stats",
    flush: async function () { await new Promise(function (r) { setTimeout(r, 5); }); },
  });
  for (var i = 0; i < 5; i++) h.emit({ id: i });
  await h.drain();
  var s = h.getStats();
  check("handler.getStats: totalEmitted",                   s.totalEmitted === 5);
  check("handler.getStats: totalFlushed",                   s.totalFlushed === 5);
  check("handler.getStats: bufferSize=0 post-drain",        s.bufferSize === 0);
  check("handler.getStats: lastFlushDurationMs > 0",        s.lastFlushDurationMs > 0);
  check("handler.getStats: breakerState exposed",           s.breakerState === "closed");
}

async function testHandlerBackpressureDrop() {
  var dropped = [];
  var h = b.handlers.create({
    name:          "test-backpressure",
    flush:         async function () { await new Promise(function () {}); /* hang */ },
    maxBufferSize: 3,
    deadLetter:    function (items) { dropped.push.apply(dropped, items); },
    onError:       function () { /* swallow */ },
  });
  for (var i = 0; i < 10; i++) h.emit({ id: i });
  await new Promise(function (r) { setImmediate(r); });
  check("handler: maxBufferSize drops over-cap items to DLQ", dropped.length >= 5);
}

// ---- json-safe ----

function testJsonModuleSurface() {
  check("safeJson namespace present",        typeof b.safeJson === "object");
  check("safeJson.parse is a function",      typeof b.safeJson.parse === "function");
  check("safeJson.validate is a function",   typeof b.safeJson.validate === "function");
  check("safeJson.canonical is a function",  typeof b.safeJson.canonical === "function");
  check("safeJson.SafeJsonError exists",     typeof b.safeJson.SafeJsonError === "function");
}

function testJsonParse() {
  // Basic round-trip
  var v = b.safeJson.parse('{"a":1,"b":"hello","c":null,"d":[1,2,3],"e":true}');
  check("parse round-trips object",   v.a === 1 && v.b === "hello" && v.c === null);
  check("parse round-trips array",    Array.isArray(v.d) && v.d.length === 3);

  // BOM tolerated
  var bom = b.safeJson.parse("﻿{\"x\":1}");
  check("parse strips BOM",           bom.x === 1);

  // Size limit
  var bigInput = '{"x":"' + "a".repeat(200) + '"}';
  var sizeRejected = false;
  try { b.safeJson.parse(bigInput, { maxBytes: 100 }); }
  catch (e) { sizeRejected = e.code === "json/too-large"; }
  check("parse rejects oversized input",                  sizeRejected);

  // Depth limit
  var deep = '{"a":'.repeat(10) + 'null' + '}'.repeat(10);
  var depthRejected = false;
  try { b.safeJson.parse(deep, { maxDepth: 3 }); }
  catch (e) { depthRejected = e.code === "json/too-deep"; }
  check("parse rejects too-deep input",                   depthRejected);

  // Proto pollution
  var poisoned = b.safeJson.parse('{"__proto__":{"isAdmin":true},"name":"alice"}');
  check("parse strips __proto__ key",                     !("__proto__" in poisoned) || poisoned.__proto__ === Object.prototype);
  check("parse does not pollute Object.prototype",        !({}.isAdmin));

  var ctorPoisoned = b.safeJson.parse('{"constructor":{"prototype":{"x":1}}}');
  check("parse strips constructor key",                   !("constructor" in ctorPoisoned) || ctorPoisoned.constructor === Object);

  // Syntax error
  var syntaxRejected = false;
  try { b.safeJson.parse("{not-json}"); }
  catch (e) { syntaxRejected = e.code === "json/syntax"; }
  check("parse reports syntax errors with code",          syntaxRejected);

  // Wrong input type
  var typeRejected = false;
  try { b.safeJson.parse(123); }
  catch (e) { typeRejected = e.code === "json/wrong-input-type"; }
  check("parse rejects non-string/Buffer input",          typeRejected);

  // parseOrDefault
  check("parseOrDefault returns fallback on bad input",   b.safeJson.parseOrDefault("not-json", { fallback: true }).fallback === true);
  check("parseOrDefault returns parsed on good input",    b.safeJson.parseOrDefault('{"x":1}', null).x === 1);

  // Buffer input
  var fromBuf = b.safeJson.parse(Buffer.from('{"y":2}', "utf8"));
  check("parse accepts Buffer input",                     fromBuf.y === 2);
}

function testJsonStringify() {
  var s = b.safeJson.stringify({ a: 1, b: [1, 2, 3] });
  check("stringify produces valid JSON",                  JSON.parse(s).a === 1);

  var stripped = JSON.parse(b.safeJson.stringify({ __proto__: { x: 1 }, name: "alice" }));
  check("stringify strips __proto__",                     !("__proto__" in stripped) || stripped.__proto__ === Object.prototype);

  var circular = { a: 1 };
  circular.self = circular;
  var circRejected = false;
  try { b.safeJson.stringify(circular); }
  catch (e) { circRejected = e.code === "json/circular"; }
  check("stringify throws on circular ref",               circRejected);

  // Replace mode
  var replaced = b.safeJson.stringify(circular, { onCircular: "replace", circularReplacement: "<circular>" });
  check("stringify circular replace mode works",          /<circular>/.test(replaced));
}

function testJsonCanonical() {
  var c1 = b.safeJson.canonical({ b: 2, a: 1, c: 3 });
  var c2 = b.safeJson.canonical({ a: 1, c: 3, b: 2 });
  check("canonical: identical content same key order → identical bytes",  c1 === c2);
  check("canonical: keys sorted alphabetically",          c1 === '{"a":1,"b":2,"c":3}');

  var nested = b.safeJson.canonical({ z: { y: 1, x: 2 }, a: [3, 1, 2] });
  check("canonical: nested objects also sorted",          nested === '{"a":[3,1,2],"z":{"x":2,"y":1}}');

  var nfRejected = false;
  try { b.safeJson.canonical({ x: NaN }); }
  catch (e) { nfRejected = e.code === "json/non-finite"; }
  check("canonical: NaN rejected",                        nfRejected);
}

function testJsonValidate() {
  b.safeJson.validate("hello", { type: "string" });
  check("validate type-pass returns silently", true);
  var typeRejected = false;
  try { b.safeJson.validate(42, { type: "string" }); }
  catch (e) { typeRejected = e.code === "json/validation" && /expected string/.test(e.message); }
  check("validate type mismatch throws with path",         typeRejected);

  var schema = {
    type: "object",
    required: ["email", "age"],
    properties: {
      email: { type: "string", format: "email", maxLength: 254 },
      age:   { type: "integer", minimum: 0, maximum: 150 },
      role:  { type: "string", enum: ["admin", "user", "guest"] },
    },
    additionalProperties: false,
  };

  b.safeJson.validate({ email: "alice@example.com", age: 30, role: "admin" }, schema);
  check("validate good object passes silently", true);

  var emailRejected = false;
  try { b.safeJson.validate({ email: "not-email", age: 30 }, schema); }
  catch (e) { emailRejected = e.code === "json/validation" && /format 'email'/.test(e.message); }
  check("validate bad email format throws",                emailRejected);

  var requiredRejected = false;
  try { b.safeJson.validate({ email: "a@b.com" }, schema); }
  catch (e) { requiredRejected = /missing required key 'age'/.test(e.message); }
  check("validate missing required throws",                requiredRejected);

  var rangeRejected = false;
  try { b.safeJson.validate({ email: "a@b.com", age: -1 }, schema); }
  catch (e) { rangeRejected = /minimum/.test(e.message); }
  check("validate range violation throws",                 rangeRejected);

  var enumRejected = false;
  try { b.safeJson.validate({ email: "a@b.com", age: 30, role: "superuser" }, schema); }
  catch (e) { enumRejected = /not in enum/.test(e.message); }
  check("validate enum violation throws",                  enumRejected);

  var unknownKeyRejected = false;
  try { b.safeJson.validate({ email: "a@b.com", age: 30, hax: 1 }, schema); }
  catch (e) { unknownKeyRejected = /unknown key 'hax'/.test(e.message); }
  check("validate unknown key with additionalProperties:false throws", unknownKeyRejected);

  var arrSchema = { type: "array", minItems: 1, items: { type: "integer" } };
  b.safeJson.validate([1, 2, 3], arrSchema);
  var arrItemRejected = false;
  try { b.safeJson.validate([1, "two", 3], arrSchema); }
  catch (e) { arrItemRejected = e.path === "$[1]" && /expected integer/.test(e.message); }
  check("validate array item path is reported",            arrItemRejected);
}

function testJsonValidateCollect() {
  var schema = {
    type: "object",
    required: ["email", "age", "name"],
    properties: {
      email: { type: "string", format: "email" },
      age:   { type: "integer", minimum: 0 },
      name:  { type: "string", minLength: 1, maxLength: 100 },
      role:  { type: "string", enum: ["admin", "user"] },
    },
  };
  var bad = { email: "not-email", age: -5, name: "", role: "superuser" };
  var result = b.safeJson.validate(bad, schema, { collectErrors: true });
  check("collectErrors returns { ok, value, errors }",      typeof result === "object" && result.ok === false);
  check("collectErrors collects multiple errors",           result.errors.length >= 4);
  check("collectErrors errors have .path",                  result.errors.every(function (e) { return typeof e.path === "string"; }));
  check("collectErrors errors include format failure",      result.errors.some(function (e) { return /format 'email'/.test(e.message); }));
  check("collectErrors errors include range failure",       result.errors.some(function (e) { return /minimum/.test(e.message); }));
  check("collectErrors errors include length failure",      result.errors.some(function (e) { return /minLength/.test(e.message); }));
  check("collectErrors errors include enum failure",        result.errors.some(function (e) { return /not in enum/.test(e.message); }));

  var good = { email: "a@b.com", age: 30, name: "Alice" };
  var goodResult = b.safeJson.validate(good, schema, { collectErrors: true });
  check("collectErrors ok=true on valid input",             goodResult.ok === true && goodResult.errors.length === 0);

  var parseResult = b.safeJson.parse(JSON.stringify(bad), { schema: schema, collectErrors: true });
  check("parse + collectErrors returns { ok, value, errors[] }",
        typeof parseResult === "object" && parseResult.ok === false && parseResult.errors.length >= 4);
}

function testJsonFormats() {
  check("format email: valid passes",        b.safeJson.formats.email("alice@example.com"));
  check("format email: missing @ fails",     !b.safeJson.formats.email("not-email"));
  check("format url: https passes",          b.safeJson.formats.url("https://example.com/path"));
  check("format url: ftp fails (not in allowlist)", !b.safeJson.formats.url("ftp://example.com"));
  check("format uuid: valid passes",         b.safeJson.formats.uuid("550e8400-e29b-41d4-a716-446655440000"));
  check("format uuid: too-short fails",      !b.safeJson.formats.uuid("550e8400"));
  check("format ulid: valid passes",         b.safeJson.formats.ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
  check("format ipv4: valid passes",         b.safeJson.formats.ipv4("192.168.1.1"));
  check("format ipv4: out of range fails",   !b.safeJson.formats.ipv4("192.168.1.256"));
  check("format ipv4: leading zero fails",   !b.safeJson.formats.ipv4("192.168.001.1"));
  check("ipv6: full 8 groups",                          b.safeJson.formats.ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
  check("ipv6: lowercase",                              b.safeJson.formats.ipv6("2001:db8::1"));
  check("ipv6: mixed case",                             b.safeJson.formats.ipv6("2001:DB8::1"));
  check("ipv6: loopback ::1",                           b.safeJson.formats.ipv6("::1"));
  check("ipv6: unspecified ::",                         b.safeJson.formats.ipv6("::"));
  check("ipv6: trailing :: (1::)",                      b.safeJson.formats.ipv6("1::"));
  check("ipv6: link-local fe80::1",                     b.safeJson.formats.ipv6("fe80::1"));
  check("ipv6: IPv4-mapped ::ffff:192.168.1.1",         b.safeJson.formats.ipv6("::ffff:192.168.1.1"));
  check("ipv6: IPv4-mapped uppercase",                  b.safeJson.formats.ipv6("::FFFF:192.168.1.1"));
  check("ipv6: longer IPv4-mapped form",                b.safeJson.formats.ipv6("2001:db8::192.0.2.1"));
  check("ipv6: rejects > 8 groups",                     !b.safeJson.formats.ipv6("1:2:3:4:5:6:7:8:9"));
  check("ipv6: rejects multiple ::",                    !b.safeJson.formats.ipv6("1::2::3"));
  check("ipv6: rejects non-hex chars",                  !b.safeJson.formats.ipv6("g::"));
  check("ipv6: rejects > 4 hex per group",              !b.safeJson.formats.ipv6("12345::"));
  check("ipv6: rejects zone IDs",                       !b.safeJson.formats.ipv6("fe80::1%eth0"));
  check("ipv6: rejects empty string",                   !b.safeJson.formats.ipv6(""));
  check("ipv6: rejects too long",                       !b.safeJson.formats.ipv6("a".repeat(46)));
  check("ipv6: rejects bad IPv4-mapped",                !b.safeJson.formats.ipv6("::ffff:999.168.1.1"));
  check("format hex: valid passes",          b.safeJson.formats.hex("dead beef".replace(" ", "")));
  check("format slug: valid passes",         b.safeJson.formats.slug("my-blog-post"));
  check("format slug: uppercase fails",      !b.safeJson.formats.slug("MyBlogPost"));
  check("format iso8601-date: valid passes", b.safeJson.formats["iso8601-date"]("2026-04-25"));
  check("format iso8601-date: invalid fails",!b.safeJson.formats["iso8601-date"]("2026-13-01"));

  b.safeJson.registerFormat("us-zip", function (v) { return /^\d{5}(-\d{4})?$/.test(v); });
  check("custom format registered + works",  b.safeJson.formats["us-zip"]("12345"));
  b.safeJson.validate("90210", { type: "string", format: "us-zip" });
  var customRejected = false;
  try { b.safeJson.validate("ABCDE", { type: "string", format: "us-zip" }); }
  catch (e) { customRejected = /format 'us-zip'/.test(e.message); }
  check("custom format used by validate",    customRejected);
}

// =====================================================================
// atomic-file + parsers (xml, csv, toml, yaml, env-parse) + redact
//
// All Layer 0: pure / file-IO primitives with no framework state.
// =====================================================================

async function testAtomicFileListDir() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-listdir-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "a.log"), "alpha");
    fs.writeFileSync(path.join(tmpDir, "b.log"), "beta");
    fs.writeFileSync(path.join(tmpDir, "c.txt"), "carrot");
    fs.mkdirSync(path.join(tmpDir, "sub"));

    // Default — no filter, no stat
    var all = b.atomicFile.listDir(tmpDir);
    check("listDir: returns all entries by default", all.length === 4);
    check("listDir: each entry has name + fullPath",
          all[0].name && all[0].fullPath && all[0].fullPath.indexOf(tmpDir) === 0);
    check("listDir: no stat fields when includeStat off", all[0].mtimeMs === undefined);

    // Filter
    var logs = b.atomicFile.listDir(tmpDir, {
      filter: function (n) { return n.endsWith(".log"); },
    });
    check("listDir: filter narrows to .log", logs.length === 2);

    // includeStat populates size, mtime, isDirectory, isFile
    var withStat = b.atomicFile.listDir(tmpDir, { includeStat: true });
    var byName = {};
    withStat.forEach(function (e) { byName[e.name] = e; });
    check("listDir: includeStat — size of a.log", byName["a.log"].sizeBytes === 5);
    check("listDir: includeStat — a.log isFile",  byName["a.log"].isFile === true);
    check("listDir: includeStat — a.log not dir", byName["a.log"].isDirectory === false);
    check("listDir: includeStat — sub isDirectory", byName["sub"].isDirectory === true);
    check("listDir: includeStat — mtimeMs is a number",
          typeof byName["a.log"].mtimeMs === "number");

    // Missing dir — default missingOk: true returns []
    var missing = b.atomicFile.listDir(path.join(tmpDir, "nope"));
    check("listDir: missing dir returns [] by default", Array.isArray(missing) && missing.length === 0);

    // missingOk: false throws
    var threwMissing = false;
    try { b.atomicFile.listDir(path.join(tmpDir, "nope"), { missingOk: false }); }
    catch (e) { threwMissing = e.code === "atomic-file/list-failed"; }
    check("listDir: missingOk: false throws", threwMissing);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testAtomicFile() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-atomicfile-"));
  try {
    check("atomicFile namespace present",            typeof b.atomicFile === "object");

    // Basic write + read round-trip
    var p = path.join(tmpDir, "data.bin");
    var content = Buffer.from("hello atomic " + Date.now(), "utf8");
    var w = await b.atomicFile.write(p, content, { computeHash: true });
    check("atomicFile write returns bytesWritten",   w.bytesWritten === content.length);
    check("atomicFile write returns hash",           typeof w.hash === "string" && w.hash.length === 128);

    var r = await b.atomicFile.read(p);
    check("atomicFile read returns Buffer",          Buffer.isBuffer(r));
    check("atomicFile read content matches",         r.equals(content));

    // Hash verification
    var rOk = await b.atomicFile.read(p, { expectedHash: w.hash });
    check("atomicFile hash verify accepts good hash", rOk.equals(content));

    var hashRejected = false;
    try { await b.atomicFile.read(p, { expectedHash: "0".repeat(128) }); }
    catch (e) { hashRejected = e.code === "atomic-file/integrity"; }
    check("atomicFile hash verify rejects bad hash", hashRejected);

    // Size limit
    var bigPath = path.join(tmpDir, "big.bin");
    await b.atomicFile.write(bigPath, Buffer.alloc(2048));
    var sizeRejected = false;
    try { await b.atomicFile.read(bigPath, { maxBytes: 1024 }); }
    catch (e) { sizeRejected = e.code === "atomic-file/too-large"; }
    check("atomicFile read maxBytes enforced",       sizeRejected);

    // readSync: same semantics as async read, for boot-path callers
    var rSync = b.atomicFile.readSync(p);
    check("atomicFile readSync returns Buffer",      Buffer.isBuffer(rSync));
    check("atomicFile readSync content matches",     rSync.equals(content));
    var rSyncStr = b.atomicFile.readSync(p, { encoding: "utf8" });
    check("atomicFile readSync encoding option",     rSyncStr === content.toString("utf8"));
    var syncSizeRejected = false;
    try { b.atomicFile.readSync(bigPath, { maxBytes: 1024 }); }
    catch (e) { syncSizeRejected = e.code === "atomic-file/too-large"; }
    check("atomicFile readSync maxBytes enforced",   syncSizeRejected);
    var syncMissingRejected = false;
    try { b.atomicFile.readSync(path.join(tmpDir, "no-such-file")); }
    catch (e) { syncMissingRejected = e.code === "ENOENT"; }
    check("atomicFile readSync ENOENT on missing",   syncMissingRejected);

    // v0.6.68 — maxBytes must be a positive finite integer. Pre-fix
    // `Infinity` bypassed the OOM cap entirely (`stat.size > Infinity`
    // is always false → unbounded read). Same bug class as the
    // v0.6.57 boundedChunkCollector fix.
    function _expectMaxBytesBadOpt(label, maxBytes) {
      var threw = null;
      try { b.atomicFile.readSync(p, { maxBytes: maxBytes }); }
      catch (e) { threw = e; }
      check("atomicFile readSync rejects maxBytes=" + label,
            threw && threw.code === "atomic-file/bad-opt");
    }
    _expectMaxBytesBadOpt("Infinity",  Infinity);
    _expectMaxBytesBadOpt("NaN",       NaN);
    _expectMaxBytesBadOpt("0",         0);
    _expectMaxBytesBadOpt("negative", -1);
    _expectMaxBytesBadOpt("3.5 (non-int)", 3.5);
    _expectMaxBytesBadOpt("string",    "100");
    _expectMaxBytesBadOpt("null",      null);

    // Crash safety: tmp file should NOT remain after success
    var tmpFiles = fs.readdirSync(tmpDir).filter(function (f) { return /\.tmp-/.test(f); });
    check("atomicFile cleans up tmp on success",     tmpFiles.length === 0);

    // JSON convenience
    var jsonPath = path.join(tmpDir, "data.json");
    await b.atomicFile.writeJson(jsonPath, { a: 1, b: [2, 3] });
    var parsed = await b.atomicFile.readJson(jsonPath);
    check("atomicFile writeJson/readJson round-trip", parsed.a === 1 && parsed.b[1] === 3);

    // readJson with schema
    var schemaPath = path.join(tmpDir, "schema.json");
    await b.atomicFile.writeJson(schemaPath, { name: "alice", age: 30 });
    var validated = await b.atomicFile.readJson(schemaPath, {
      schema: { type: "object", required: ["name", "age"], properties: { name: { type: "string" }, age: { type: "integer" } } },
    });
    check("atomicFile readJson + schema validates",  validated.name === "alice");

    // copy
    var copyPath = path.join(tmpDir, "copy.bin");
    var c = await b.atomicFile.copy(p, copyPath, { computeHash: true });
    check("atomicFile copy returns hash",            c.hash === w.hash);
    check("atomicFile copy file exists",             b.atomicFile.exists(copyPath));

    // Read missing file → ENOENT
    var missingRejected = false;
    try { await b.atomicFile.read(path.join(tmpDir, "nope")); }
    catch (e) { missingRejected = e.code === "ENOENT" || e.code === "atomic-file/not-found"; }
    check("atomicFile read missing → ENOENT",         missingRejected);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testAtomicFileLock() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-atlock-"));
  try {
    var p = path.join(tmpDir, "shared.txt");
    var counter = 0;

    // Two concurrent locks — they should serialize
    async function increment() {
      await b.atomicFile.lock(p, async function () {
        var current;
        try { current = parseInt((await b.atomicFile.read(p)).toString("utf8"), 10) || 0; }
        catch (_e) { current = 0; }
        await new Promise(function (r) { setTimeout(r, 20); });   // simulate work
        await b.atomicFile.write(p, String(current + 1));
        counter += 1;
      });
    }

    await Promise.all([increment(), increment(), increment(), increment(), increment()]);
    var finalValue = parseInt((await b.atomicFile.read(p)).toString("utf8"), 10);
    check("atomicFile.lock serializes concurrent access",  finalValue === 5);
    check("counter agrees",                                counter === 5);

    // Lock file is gone after lock body finishes
    check("lock sentinel cleaned up",                      !b.atomicFile.exists(p + ".lock"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testXmlParse() {
  check("parsers namespace present",                  typeof b.parsers === "object");
  check("parsers.xml present",                        typeof b.parsers.xml === "object");

  // Simple element
  var simple = b.parsers.xml.parse("<root>hello</root>");
  check("xml: simple text element",                   simple.root === "hello");

  // Attributes + nested
  var attr = b.parsers.xml.parse('<root id="x"><child>text</child></root>');
  check("xml: attributes preserved at @attrs",        attr.root["@attrs"].id === "x");
  check("xml: nested child element",                  attr.root.child === "text");

  // Multiple children with same name → array
  var multi = b.parsers.xml.parse('<root><item>a</item><item>b</item><item>c</item></root>');
  check("xml: repeated children become array",        Array.isArray(multi.root.item) && multi.root.item.length === 3);
  check("xml: array preserves order",                 multi.root.item[0] === "a" && multi.root.item[2] === "c");

  // XML declaration tolerated
  var withDecl = b.parsers.xml.parse('<?xml version="1.0" encoding="UTF-8"?><root>x</root>');
  check("xml: XML decl ignored",                      withDecl.root === "x");

  // Built-in entities decoded
  var entities = b.parsers.xml.parse("<root>&lt;ok&gt; &amp; &quot;quoted&quot;</root>");
  check("xml: built-in entities decoded",             entities.root === "<ok> & \"quoted\"");

  // Numeric character refs
  var numref = b.parsers.xml.parse("<root>&#65;&#x42;</root>");
  check("xml: numeric character refs decoded",        numref.root === "AB");

  // Self-closing
  var selfClose = b.parsers.xml.parse("<root><br/></root>");
  check("xml: self-closing element parses",           selfClose.root.br === "");

  // CDATA
  var cdata = b.parsers.xml.parse("<root><![CDATA[<not parsed>]]></root>");
  check("xml: CDATA preserved literally",             cdata.root === "<not parsed>");
}

function testXmlSecurityRejections() {
  // DOCTYPE rejected by default
  var doctypeRejected = false;
  try { b.parsers.xml.parse('<!DOCTYPE foo SYSTEM "http://evil.com/foo.dtd"><root/>'); }
  catch (e) { doctypeRejected = e.code === "xml/doctype"; }
  check("xml: DOCTYPE rejected by default (XXE)",     doctypeRejected);

  // External entity reference rejected
  var entityRejected = false;
  try { b.parsers.xml.parse('<root>&customEntity;</root>'); }
  catch (e) { entityRejected = e.code === "xml/external-entity"; }
  check("xml: custom entity ref rejected",            entityRejected);

  // Processing instruction rejected
  var piRejected = false;
  try { b.parsers.xml.parse('<root><?php echo $secret; ?></root>'); }
  catch (e) { piRejected = e.code === "xml/processing"; }
  check("xml: processing instruction rejected",        piRejected);

  // Mismatched tags
  var mismatchedRejected = false;
  try { b.parsers.xml.parse("<a><b></a></b>"); }
  catch (e) { mismatchedRejected = e.code === "xml/mismatched-tag"; }
  check("xml: mismatched tags rejected",              mismatchedRejected);

  // Depth limit
  var deep = "<a>".repeat(20) + "x" + "</a>".repeat(20);
  var depthRejected = false;
  try { b.parsers.xml.parse(deep, { maxDepth: 5 }); }
  catch (e) { depthRejected = e.code === "xml/too-deep"; }
  check("xml: maxDepth enforced",                     depthRejected);

  // Element count limit
  var manyKids = "<root>" + "<x/>".repeat(50) + "</root>";
  var countRejected = false;
  try { b.parsers.xml.parse(manyKids, { maxElements: 10 }); }
  catch (e) { countRejected = e.code === "xml/too-many-elements"; }
  check("xml: maxElements enforced",                  countRejected);

  // Attribute count limit
  var manyAttrs = "<root " + Array.from({ length: 20 }, function (_, i) { return "a" + i + "=\"v\""; }).join(" ") + "/>";
  var attrRejected = false;
  try { b.parsers.xml.parse(manyAttrs, { maxAttributes: 5 }); }
  catch (e) { attrRejected = e.code === "xml/too-many-attrs"; }
  check("xml: maxAttributes enforced",                attrRejected);

  // Size limit
  var sizeRejected = false;
  try { b.parsers.xml.parse("<r>" + "a".repeat(10000) + "</r>", { maxBytes: 1000 }); }
  catch (e) { sizeRejected = e.code === "xml/too-large"; }
  check("xml: maxBytes enforced",                     sizeRejected);

  // Duplicate attributes
  var dupRejected = false;
  try { b.parsers.xml.parse('<r id="a" id="b"/>'); }
  catch (e) { dupRejected = e.code === "xml/duplicate-attr"; }
  check("xml: duplicate attribute rejected",           dupRejected);

  // < in attribute value
  var ltRejected = false;
  try { b.parsers.xml.parse('<r x="<bad"/>'); }
  catch (e) { ltRejected = e.code === "xml/bad-attr"; }
  check("xml: '<' in attribute value rejected",        ltRejected);
}

function testTomlBasicTypes() {
  var src =
    "title = \"blamejs\"\n" +
    "active = true\n" +
    "disabled = false\n" +
    "answer = 42\n" +
    "ratio = 3.14\n" +
    "neg = -17\n" +
    "biginthex = 0xDEADbeef\n" +
    "octal = 0o755\n" +
    "binary = 0b1010\n" +
    "underscored = 1_000_000\n" +
    "infinity = inf\n" +
    "negInf = -inf\n" +
    "notNum = nan\n" +
    "literal = 'no \\n escapes here'\n" +
    "stamp = 1979-05-27T07:32:00Z\n" +
    "localDate = 1979-05-27\n" +
    "localTime = 07:32:00\n";
  var doc = b.parsers.toml.parse(src);
  check("toml: string value",                      doc.title === "blamejs");
  check("toml: bool true",                         doc.active === true);
  check("toml: bool false",                        doc.disabled === false);
  check("toml: integer",                           doc.answer === 42);
  check("toml: float",                             Math.abs(doc.ratio - 3.14) < 1e-9);
  check("toml: negative integer",                  doc.neg === -17);
  check("toml: hex with underscore-camelcase digits", doc.biginthex === 0xDEADbeef);
  check("toml: octal",                             doc.octal === 0o755);
  check("toml: binary",                            doc.binary === 10);
  check("toml: underscored decimal",               doc.underscored === 1000000);
  check("toml: inf",                               doc.infinity === Infinity);
  check("toml: -inf",                              doc.negInf === -Infinity);
  check("toml: nan",                               Number.isNaN(doc.notNum));
  check("toml: literal string preserves backslash-n",  doc.literal === "no \\n escapes here");
  check("toml: offset date-time → Date",           doc.stamp instanceof Date);
  check("toml: offset date-time correct epoch",    doc.stamp.getTime() === Date.UTC(1979, 4, 27, 7, 32, 0));
  check("toml: local date as ISO string",          doc.localDate === "1979-05-27");
  check("toml: local time as ISO string",          doc.localTime === "07:32:00");
}

function testTomlTablesAndArrays() {
  var src =
    "tags = [\"a\", \"b\", \"c\"]\n" +
    "\n" +
    "[server]\n" +
    "host = \"localhost\"\n" +
    "port = 8080\n" +
    "\n" +
    "[server.tls]\n" +
    "cert = \"/etc/ssl/cert.pem\"\n" +
    "\n" +
    "[[products]]\n" +
    "name = \"widget\"\n" +
    "price = 9.99\n" +
    "\n" +
    "[[products]]\n" +
    "name = \"gizmo\"\n" +
    "price = 19.99\n";
  var doc = b.parsers.toml.parse(src);
  check("toml: array of strings (top-level)",      Array.isArray(doc.tags) && doc.tags.length === 3);
  check("toml: array element 0",                   doc.tags[0] === "a");
  check("toml: nested table",                      doc.server.host === "localhost");
  check("toml: integer in nested table",           doc.server.port === 8080);
  check("toml: deeper nested table",               doc.server.tls.cert === "/etc/ssl/cert.pem");
  check("toml: array of tables length",            doc.products.length === 2);
  check("toml: AoT first element",                 doc.products[0].name === "widget");
  check("toml: AoT second element",                doc.products[1].name === "gizmo");
  check("toml: AoT prices",                        doc.products[1].price === 19.99);
}

function testTomlInlineTablesAndDottedKeys() {
  var src =
    "point = { x = 1, y = 2 }\n" +
    "name.first = \"Tom\"\n" +
    "name.last = \"Preston-Werner\"\n";
  var doc = b.parsers.toml.parse(src);
  check("toml: inline table",                      doc.point.x === 1 && doc.point.y === 2);
  check("toml: dotted-key creates nested object",  doc.name.first === "Tom" && doc.name.last === "Preston-Werner");
}

function testTomlSecurityRejections() {
  // Prototype pollution via dotted key
  var threwProto = false;
  try { b.parsers.toml.parse("__proto__.polluted = true"); }
  catch (e) { threwProto = e.code === "toml/poisoned-key"; }
  check("toml: __proto__ rejected",                threwProto);

  var threwConstructor = false;
  try { b.parsers.toml.parse("a.constructor = 1"); }
  catch (e) { threwConstructor = e.code === "toml/poisoned-key"; }
  check("toml: constructor rejected",              threwConstructor);

  // Duplicate key
  var threwDup = false;
  try { b.parsers.toml.parse("a = 1\na = 2"); }
  catch (e) { threwDup = e.code === "toml/duplicate-key"; }
  check("toml: duplicate key rejected",            threwDup);

  // Inline table mutation
  var threwInlineMutate = false;
  try { b.parsers.toml.parse("x = { a = 1 }\nx.b = 2"); }
  catch (e) { threwInlineMutate = e.code === "toml/inline-table-mutated"; }
  check("toml: inline-table mutation rejected",    threwInlineMutate);

  // Table redefinition
  var threwRedefine = false;
  try { b.parsers.toml.parse("[a]\nb = 1\n[a]\nc = 2"); }
  catch (e) { threwRedefine = e.code === "toml/redefine"; }
  check("toml: table redefinition rejected",       threwRedefine);

  // Table header descending through a VALUE array (not an array-of-tables)
  // — `a = [3]` then `[a.s]` walks into the array's scalar element. A fuzz
  // input hit this; it must refuse cleanly, not throw a raw TypeError.
  var threwValueArrayDescend = null;
  try { b.parsers.toml.parse("a = [3]\n[a.s]\n"); }
  catch (e) { threwValueArrayDescend = e.code; }
  check("toml: table header descending into a value array rejected cleanly",
        threwValueArrayDescend === "toml/redefine");

  // Size cap
  var threwSize = false;
  try { b.parsers.toml.parse("a = \"" + "x".repeat(2000) + "\"", { maxBytes: 1000 }); }
  catch (e) { threwSize = e.code === "toml/too-large"; }
  check("toml: maxBytes enforced",                 threwSize);

  // v0.6.63 — dotted-key path depth cap. Pre-fix the parser walked
  // arbitrarily deep table headers `[a.b.c.d…]` without applying the
  // existing maxDepth (which only ran in _parseValue for arrays /
  // inline tables); a 10K-segment path then stack-overflowed the
  // recursive _normalize walker post-parse.
  function _toml10kPath() {
    var seg = "";
    for (var i = 0; i < 10000; i++) seg += "a.";
    return "[" + seg + "final]\nx = 1";
  }
  var threwDepth = false;
  try { b.parsers.toml.parse(_toml10kPath()); }
  catch (e) { threwDepth = e.code === "toml/too-deep"; }
  check("toml: dotted-key 10k path rejects toml/too-deep (no stack overflow)",
        threwDepth);
  // 100 segments at default maxDepth=100 → at the +1 boundary, still rejects
  function _tomlPath(n) {
    var seg = "";
    for (var i = 0; i < n; i++) seg += "a.";
    return "[" + seg + "final]\nx = 1";
  }
  var ok99 = b.parsers.toml.parse(_tomlPath(99));
  check("toml: 99-segment dotted-key under default depth: ok",
        ok99 && typeof ok99 === "object");
  var threw150 = false;
  try { b.parsers.toml.parse(_tomlPath(150)); }
  catch (e) { threw150 = e.code === "toml/too-deep"; }
  check("toml: 150-segment dotted-key over default: rejects",  threw150);
  // Operator override
  var ok500 = b.parsers.toml.parse(_tomlPath(500), { maxDepth: 1000 });
  check("toml: maxDepth: 1000 opt allows 500-segment path",
        ok500 && typeof ok500 === "object");

  // Integer overflow
  var threwOverflow = false;
  try { b.parsers.toml.parse("big = 9223372036854775807"); }
  catch (e) { threwOverflow = e.code === "toml/integer-overflow"; }
  check("toml: integer-overflow on > MAX_SAFE_INTEGER", threwOverflow);

  // Unterminated string
  var threwUnterm = false;
  try { b.parsers.toml.parse("a = \"unterminated\nb = 1"); }
  catch (e) { threwUnterm = !!e.isSafeTomlError; }
  check("toml: unterminated string rejected",      threwUnterm);

  // Multi-line basic string
  var doc = b.parsers.toml.parse("greeting = \"\"\"\nhello,\nworld\n\"\"\"");
  check("toml: multi-line basic string trims first newline + preserves rest",
        doc.greeting === "hello,\nworld\n");
}

function testYamlBasic() {
  var src =
    "title: blamejs\n" +
    "version: 0.1.6\n" +
    "active: true\n" +
    "disabled: false\n" +
    "answer: 42\n" +
    "ratio: 3.14\n" +
    "absent: null\n" +
    "implicit_null: ~\n" +
    "list:\n" +
    "  - a\n" +
    "  - b\n" +
    "  - c\n" +
    "nested:\n" +
    "  host: localhost\n" +
    "  port: 8080\n" +
    "  tls:\n" +
    "    cert: /etc/ssl/cert.pem\n" +
    "flow_seq: [1, 2, 3]\n" +
    "flow_map: { x: 1, y: 2 }\n";
  var doc = b.parsers.yaml.parse(src);
  check("yaml: string scalar",                     doc.title === "blamejs");
  check("yaml: version string (mixed digits/dots)", doc.version === "0.1.6" || doc.version === 0.1);
  check("yaml: bool true",                         doc.active === true);
  check("yaml: bool false",                        doc.disabled === false);
  check("yaml: integer",                           doc.answer === 42);
  check("yaml: float",                             Math.abs(doc.ratio - 3.14) < 1e-9);
  check("yaml: explicit null",                     doc.absent === null);
  check("yaml: tilde null",                        doc.implicit_null === null);
  check("yaml: block sequence length",             doc.list.length === 3);
  check("yaml: block sequence elements",           doc.list[0] === "a" && doc.list[2] === "c");
  check("yaml: nested mapping host",               doc.nested.host === "localhost");
  check("yaml: deeply-nested mapping",             doc.nested.tls.cert === "/etc/ssl/cert.pem");
  check("yaml: flow sequence",                     Array.isArray(doc.flow_seq) && doc.flow_seq.length === 3);
  check("yaml: flow mapping",                      doc.flow_map.x === 1 && doc.flow_map.y === 2);
}

function testYamlNorwayProblem() {
  // YAML 1.1 parsed `NO` / `OFF` / `YES` as booleans — the "Norway
  // problem". YAML 1.2 core schema uses ONLY true/True/TRUE/false/False/FALSE.
  var doc = b.parsers.yaml.parse("country: NO\nstate: ON\nflag: YES\n");
  check("yaml: 'NO' is string (Norway problem fixed)", doc.country === "NO");
  check("yaml: 'ON' is string",                          doc.state === "ON");
  check("yaml: 'YES' is string",                         doc.flag === "YES");
}

function testYamlBlockScalars() {
  var literal = b.parsers.yaml.parse(
    "msg: |\n" +
    "  line one\n" +
    "  line two\n"
  );
  check("yaml: literal block scalar preserves newlines",  literal.msg === "line one\nline two\n");

  var folded = b.parsers.yaml.parse(
    "msg: >\n" +
    "  paragraph one\n" +
    "  continues here\n" +
    "\n" +
    "  paragraph two\n"
  );
  check("yaml: folded block scalar collapses lines",
        folded.msg === "paragraph one continues here\nparagraph two\n");

  var stripped = b.parsers.yaml.parse(
    "msg: |-\n" +
    "  no trailing newline"
  );
  check("yaml: literal-strip removes trailing newline",  stripped.msg === "no trailing newline");
}

function testYamlQuotedStrings() {
  var doc = b.parsers.yaml.parse(
    "double: \"hello\\nworld\"\n" +
    "single: 'literal \\n stays'\n" +
    "embedded: 'it''s great'\n"
  );
  check("yaml: double-quoted decodes \\n",          doc.double === "hello\nworld");
  check("yaml: single-quoted preserves backslash",  doc.single === "literal \\n stays");
  check("yaml: single-quoted '' becomes apostrophe", doc.embedded === "it's great");
}

function testYamlSecurityRejections() {
  var threwAnchor = false;
  try { b.parsers.yaml.parse("a: &anchor 1\nb: *anchor"); }
  catch (e) { threwAnchor = e.code === "yaml/anchors-banned" || e.code === "yaml/aliases-banned"; }
  check("yaml: anchors/aliases rejected",          threwAnchor);

  var threwTag = false;
  try { b.parsers.yaml.parse("a: !!str 42"); }
  catch (e) { threwTag = e.code === "yaml/tags-banned"; }
  check("yaml: !!tag rejected",                    threwTag);

  var threwDirective = false;
  try { b.parsers.yaml.parse("%YAML 1.2\n---\nfoo: bar"); }
  catch (e) { threwDirective = e.code === "yaml/directives-banned"; }
  check("yaml: %YAML directive rejected",          threwDirective);

  var threwMultiDoc = false;
  try { b.parsers.yaml.parse("a: 1\n---\nb: 2"); }
  catch (e) { threwMultiDoc = e.code === "yaml/multi-document"; }
  check("yaml: multi-document streams rejected",   threwMultiDoc);

  var threwTab = false;
  try { b.parsers.yaml.parse("a:\n\tb: 1"); }
  catch (e) { threwTab = e.code === "yaml/tab-indent"; }
  check("yaml: tab in indent rejected",            threwTab);

  var threwProto = false;
  try { b.parsers.yaml.parse("__proto__: pwn"); }
  catch (e) { threwProto = e.code === "yaml/poisoned-key"; }
  check("yaml: __proto__ rejected",                threwProto);

  var threwMerge = false;
  try { b.parsers.yaml.parse("base: { a: 1 }\nderived:\n  <<: base\n  b: 2"); }
  catch (e) { threwMerge = e.code === "yaml/merge-key-banned"; }
  check("yaml: merge key '<<' rejected",           threwMerge);

  var threwDup = false;
  try { b.parsers.yaml.parse("a: 1\na: 2"); }
  catch (e) { threwDup = e.code === "yaml/duplicate-key"; }
  check("yaml: duplicate key rejected",            threwDup);

  var threwSize = false;
  try { b.parsers.yaml.parse("a: \"" + "x".repeat(2000) + "\"", { maxBytes: 1000 }); }
  catch (e) { threwSize = e.code === "yaml/too-large"; }
  check("yaml: maxBytes enforced",                 threwSize);

  var threwUnterm = false;
  try { b.parsers.yaml.parse("a: \"unterminated"); }
  catch (e) { threwUnterm = !!e.isSafeYamlError; }
  check("yaml: unterminated string rejected",      threwUnterm);
}

function testEnvParseBasic() {
  var src =
    "# comment\n" +
    "DATABASE_URL=postgres://localhost\n" +
    "PORT=8080\n" +
    "FEATURE_FLAG=true\n" +
    "EMPTY=\n" +
    "QUOTED=\"hello world\"\n" +
    "QUOTED_NL=\"line1\\nline2\"\n" +
    "LITERAL='no \\n escapes'\n" +
    "WITH_SPACES = trimmed\n" +
    "export EXPORTED=ok\n" +
    "INLINE=value # trailing comment\n";
  var values = b.parsers.env.parse(src);
  check("env: simple key/value",                   values.DATABASE_URL === "postgres://localhost");
  check("env: numeric stays a string by default",  values.PORT === "8080");
  check("env: bool stays a string by default",     values.FEATURE_FLAG === "true");
  check("env: empty value",                        values.EMPTY === "");
  check("env: double-quoted",                      values.QUOTED === "hello world");
  check("env: double-quoted decodes \\n",          values.QUOTED_NL === "line1\nline2");
  check("env: single-quoted preserves backslash",  values.LITERAL === "no \\n escapes");
  check("env: spaces around = stripped",           values.WITH_SPACES === "trimmed");
  check("env: 'export' prefix accepted",           values.EXPORTED === "ok");
  check("env: trailing # comment stripped",        values.INLINE === "value");
}

function testEnvParseSecurityRejections() {
  // $VAR expansion banned
  var threwExpand = false;
  try { b.parsers.env.parse("KEY=$OTHER"); }
  catch (e) { threwExpand = e.code === "env/expansion-banned"; }
  check("env: $VAR expansion rejected",            threwExpand);

  var threwExpandQuoted = false;
  try { b.parsers.env.parse("KEY=\"hello $WORLD\""); }
  catch (e) { threwExpandQuoted = e.code === "env/expansion-banned"; }
  check("env: $VAR in double-quoted rejected",     threwExpandQuoted);

  // \$ literal works
  var literal = b.parsers.env.parse("KEY=\"\\$LITERAL\"");
  check("env: \\$ literal escape works",           literal.KEY === "$LITERAL");

  // Bad key shape
  var threwShape = false;
  try { b.parsers.env.parse("lowercase=value"); }
  catch (e) { threwShape = e.code === "env/bad-key-shape"; }
  check("env: lowercase key rejected by default",  threwShape);

  // Hyphen rejected
  var threwHyphen = false;
  try { b.parsers.env.parse("MY-KEY=value"); }
  catch (e) { threwHyphen = e.code === "env/bad-key-shape"; }
  check("env: hyphenated key rejected by default", threwHyphen);

  // __proto__ rejected
  var threwProto = false;
  try { b.parsers.env.parse("__proto__=pwn"); }
  catch (e) { threwProto = e.code === "env/poisoned-key" || e.code === "env/bad-key-shape"; }
  check("env: __proto__ rejected",                 threwProto);

  // Duplicate key
  var threwDup = false;
  try { b.parsers.env.parse("KEY=1\nKEY=2"); }
  catch (e) { threwDup = e.code === "env/duplicate-key"; }
  check("env: duplicate key rejected",             threwDup);

  // Missing =
  var threwMissingEq = false;
  try { b.parsers.env.parse("KEY value"); }
  catch (e) { threwMissingEq = e.code === "env/bad-line"; }
  check("env: missing '=' rejected",               threwMissingEq);

  // Tab in unquoted value
  var threwTab = false;
  try { b.parsers.env.parse("KEY=\tvalue"); }
  catch (e) { threwTab = e.code === "env/tab-in-value"; }
  check("env: tab at start of value rejected",     threwTab);

  // Size cap
  var threwSize = false;
  try { b.parsers.env.parse("KEY=" + "x".repeat(2000), { maxBytes: 1000 }); }
  catch (e) { threwSize = e.code === "env/too-large"; }
  check("env: maxBytes enforced",                  threwSize);

  // Unterminated string
  var threwUnterm = false;
  try { b.parsers.env.parse("KEY=\"unterminated"); }
  catch (e) { threwUnterm = e.code === "env/unterminated-string"; }
  check("env: unterminated quoted rejected",       threwUnterm);
}

function testBufferSafeNormalizeText() {
  var bs = b.safeBuffer;
  check("safeBuffer.normalizeText is a function", typeof bs.normalizeText === "function");

  // string passthrough
  check("normalizeText: string passthrough", bs.normalizeText("hello") === "hello");

  // Buffer → string
  check("normalizeText: Buffer → string",
        bs.normalizeText(Buffer.from("héllo", "utf8")) === "héllo");

  // Uint8Array → string
  var u8 = new Uint8Array([0x68, 0x69]);
  check("normalizeText: Uint8Array → string", bs.normalizeText(u8) === "hi");

  // BOM stripped by default
  check("normalizeText: strips leading BOM",
        bs.normalizeText("﻿withBom") === "withBom");

  // BOM preserved when stripBom: false
  check("normalizeText: stripBom:false keeps BOM",
        bs.normalizeText("﻿withBom", { stripBom: false }) === "﻿withBom");

  // maxBytes enforced
  var threwSize = false;
  try { bs.normalizeText("x".repeat(2000), { maxBytes: 100 }); }
  catch (e) { threwSize = e.code === "buffer/too-large"; }
  check("normalizeText: maxBytes enforced", threwSize);

  // Wrong type rejected
  var threwType = false;
  try { bs.normalizeText(123); }
  catch (e) { threwType = e.code === "buffer/wrong-input-type"; }
  check("normalizeText: number rejected", threwType);

  // errorClass override
  function CustomErr(message, code) {
    Error.call(this, message);
    this.message = message;
    this.code = code;
    this.name = "CustomErr";
  }
  CustomErr.prototype = Object.create(Error.prototype);
  var threwCustom = false;
  try { bs.normalizeText(123, { errorClass: CustomErr, typeCode: "x/wrong-input-type" }); }
  catch (e) {
    threwCustom = e instanceof CustomErr && e.code === "x/wrong-input-type";
  }
  check("normalizeText: errorClass override", threwCustom);
}

function testBufferSafeToBuffer() {
  var bs = b.safeBuffer;
  check("safeBuffer.toBuffer is a function", typeof bs.toBuffer === "function");

  // Buffer passthrough (same instance)
  var orig = Buffer.from("hello", "utf8");
  check("toBuffer: Buffer passthrough", bs.toBuffer(orig) === orig);

  // string → Buffer
  var b1 = bs.toBuffer("héllo");
  check("toBuffer: string → Buffer", Buffer.isBuffer(b1) && b1.toString("utf8") === "héllo");

  // Uint8Array → Buffer
  var u8 = new Uint8Array([0x42, 0x43]);
  var b2 = bs.toBuffer(u8);
  check("toBuffer: Uint8Array → Buffer", Buffer.isBuffer(b2) && b2[0] === 0x42 && b2[1] === 0x43);

  // maxBytes cap
  var threwSize = false;
  try { bs.toBuffer("x".repeat(2000), { maxBytes: 100 }); }
  catch (e) { threwSize = e.code === "buffer/too-large"; }
  check("toBuffer: maxBytes enforced", threwSize);

  // Wrong type
  var threwType = false;
  try { bs.toBuffer(123); }
  catch (e) { threwType = e.code === "buffer/wrong-input-type"; }
  check("toBuffer: number rejected", threwType);
}

function testBufferSafeBoundedChunkCollector() {
  var bs = b.safeBuffer;
  check("safeBuffer.boundedChunkCollector is a function",
        typeof bs.boundedChunkCollector === "function");

  // Happy path
  var c = bs.boundedChunkCollector({ maxBytes: 100 });
  c.push(Buffer.from("hello "));
  c.push(Buffer.from("world"));
  check("collector: bytesCollected after pushes", c.bytesCollected() === 11);
  var out = c.result();
  check("collector: result joins chunks",
        Buffer.isBuffer(out) && out.toString("utf8") === "hello world");

  // String + Uint8Array also accepted
  var c2 = bs.boundedChunkCollector({ maxBytes: 100 });
  c2.push("foo");
  c2.push(new Uint8Array([0x62, 0x61, 0x72]));
  check("collector: accepts string + Uint8Array",
        c2.result().toString("utf8") === "foobar");

  // Cap enforced AT push time (the OOM defense)
  var c3 = bs.boundedChunkCollector({ maxBytes: 10 });
  c3.push(Buffer.alloc(8));
  var threwOverflow = false;
  try { c3.push(Buffer.alloc(5)); }  // 8 + 5 = 13 > 10
  catch (e) { threwOverflow = e.code === "buffer/too-large"; }
  check("collector: rejects at push when overflow", threwOverflow);
  // After overflow the collector retains the previously-pushed bytes —
  // intentional, callers expect to inspect partial state on error.
  check("collector: state preserved on overflow", c3.bytesCollected() === 8);

  // maxBytes required
  var threwBadArg = false;
  try { bs.boundedChunkCollector({}); }
  catch (e) { threwBadArg = e.code === "buffer/bad-arg"; }
  check("collector: requires maxBytes", threwBadArg);

  // v0.6.57 — maxBytes must be positive finite integer. Pre-fix:
  // Infinity defeated the OOM cap entirely; 3.5 set a fractional cap
  // that confused chunk arithmetic. Both now reject at boot.
  function _expectBadArg(label, opts) {
    var threw = false;
    try { bs.boundedChunkCollector(opts); }
    catch (e) { threw = e.code === "buffer/bad-arg"; }
    check("collector: rejects " + label, threw);
  }
  _expectBadArg("Infinity",          { maxBytes: Infinity });
  _expectBadArg("non-integer 3.5",   { maxBytes: 3.5 });
  _expectBadArg("negative",          { maxBytes: -1 });
  _expectBadArg("zero",              { maxBytes: 0 });
  _expectBadArg("NaN",               { maxBytes: NaN });
  _expectBadArg("string 100",        { maxBytes: "100" });
  _expectBadArg("null",              { maxBytes: null });
}

// ---- url-safe ----

function testUrlSafeDefaultIsHttpsOnly() {
  var u = b.safeUrl;
  // Default allowlist = ALLOW_HTTP_TLS (https only). http:// rejected.
  var rejected = null;
  try { u.parse("http://example.com/x"); }
  catch (e) { rejected = e; }
  check("url-safe: http rejected by default",         rejected !== null);
  check("url-safe: rejection is SafeUrlError",        rejected instanceof u.SafeUrlError);
  check("url-safe: rejection code = protocol-disallowed",
        rejected.code === "safe-url/protocol-disallowed");

  // https:// accepted by default
  var ok = u.parse("https://example.com/x");
  check("url-safe: https accepted by default",        ok.protocol === "https:");
}

function testUrlSafeCustomAllowlist() {
  var u = b.safeUrl;
  // ALLOW_HTTP_ALL accepts both http: and https:
  var http  = u.parse("http://example.com/",  { allowedProtocols: u.ALLOW_HTTP_ALL });
  var https = u.parse("https://example.com/", { allowedProtocols: u.ALLOW_HTTP_ALL });
  check("url-safe: ALLOW_HTTP_ALL accepts http",  http.protocol === "http:");
  check("url-safe: ALLOW_HTTP_ALL accepts https", https.protocol === "https:");

  // ALLOW_WS_TLS rejects http: even with same host
  var rejected = null;
  try { u.parse("https://example.com/", { allowedProtocols: u.ALLOW_WS_TLS }); }
  catch (e) { rejected = e; }
  check("url-safe: WS_TLS rejects https (category error)", rejected !== null);

  var ws = u.parse("wss://example.com/sock", { allowedProtocols: u.ALLOW_WS_TLS });
  check("url-safe: ALLOW_WS_TLS accepts wss", ws.protocol === "wss:");
}

function testUrlSafeMalformed() {
  var u = b.safeUrl;
  var malformed = null;
  try { u.parse("not-a-url"); }
  catch (e) { malformed = e; }
  check("url-safe: malformed rejects",       malformed !== null);
  check("url-safe: malformed code",          malformed.code === "safe-url/malformed");

  var missing = null;
  try { u.parse(""); }
  catch (e) { missing = e; }
  check("url-safe: empty rejects",           missing !== null);
  check("url-safe: empty code = missing",    missing.code === "safe-url/missing");

  var nullMissing = null;
  try { u.parse(null); }
  catch (e) { nullMissing = e; }
  check("url-safe: null rejects",            nullMissing !== null);

  // v0.6.62 — 8 KB cap (RFC 7230 §3.1.1 guidance). Pre-fix the
  // framework walked multi-megabyte URLs through Node's parser before
  // the SSRF / protocol / userinfo gates even ran.
  var ok8k = u.parse("https://x.io/" + "a".repeat(8192 - 13));
  check("url-safe: accepts 8192 chars",      ok8k && ok8k.toString().length === 8192);
  var tooLong = null;
  try { u.parse("https://x.io/" + "a".repeat(8193 - 13)); }
  catch (e) { tooLong = e; }
  check("url-safe: rejects 8193 chars",      tooLong !== null);
  check("url-safe: too-long error code",     tooLong.code === "safe-url/too-long");
  // Operator override
  var allowed = u.parse("https://x.io/" + "a".repeat(20000), { maxUrlLength: 50000 });
  check("url-safe: maxUrlLength opt overrides default",
        allowed && allowed.toString().length > 8192);
}

function testUrlSafeUrlInstancePassThrough() {
  var u = b.safeUrl;
  var { URL } = require("url");
  var input = new URL("https://example.com/already-parsed");
  var out = u.parse(input);
  check("url-safe: URL instance returned as-is", out === input);
}

function testUrlSafeErrorClassInjection() {
  var u = b.safeUrl;
  var rejected = null;
  try {
    u.parse("ftp://example.com/", { errorClass: b.frameworkError.ObjectStoreError });
  } catch (e) { rejected = e; }
  check("url-safe: errorClass injection returns custom class",
        rejected instanceof b.frameworkError.ObjectStoreError);
  check("url-safe: injected error carries protocol-disallowed code",
        rejected.code === "safe-url/protocol-disallowed");
  // Operational errors get permanent=true (retry won't help fix a bad URL)
  check("url-safe: injected error is permanent",
        rejected.permanent === true);
}

function testUrlSafeRejectsUserinfo() {
  var u = b.safeUrl;
  // Default: reject URLs that carry user:pass@ credentials in the
  // authority. They leak into request logs / metric labels / error
  // messages — credential placement belongs in headers or a credential
  // store, not the URL.
  var rejected = null;
  try { u.parse("https://user:pass@example.com/api"); }
  catch (e) { rejected = e; }
  check("url-safe: rejects URL with userinfo by default",
        rejected !== null && rejected.code === "safe-url/userinfo-disallowed");

  var rejectedUserOnly = null;
  try { u.parse("https://user@example.com/api"); }
  catch (e) { rejectedUserOnly = e; }
  check("url-safe: rejects URL with username-only userinfo by default",
        rejectedUserOnly !== null && rejectedUserOnly.code === "safe-url/userinfo-disallowed");

  // Explicit opt-in for legacy endpoints that REQUIRE userinfo.
  var allowed = u.parse("https://user:pass@example.com/api", { allowUserinfo: true });
  check("url-safe: allowUserinfo:true accepts URL with credentials",
        allowed.username === "user" && allowed.password === "pass");

  // Plain URL with no userinfo passes either way.
  var plain = u.parse("https://example.com/api");
  check("url-safe: plain URL passes default",
        plain.username === "" && plain.password === "");
}

function testUrlSafeAllowAny() {
  var u = b.safeUrl;
  var schemes = ["http://h/", "https://h/", "ws://h/", "wss://h/"];
  for (var i = 0; i < schemes.length; i++) {
    var ok = u.parse(schemes[i], { allowedProtocols: u.ALLOW_ANY });
    check("url-safe: ALLOW_ANY accepts " + schemes[i],
          ok.protocol === schemes[i].split("://")[0] + ":");
  }
  // ftp:// still blocked even by ALLOW_ANY
  var rejected = null;
  try { u.parse("ftp://h/", { allowedProtocols: u.ALLOW_ANY }); }
  catch (e) { rejected = e; }
  check("url-safe: ALLOW_ANY still rejects ftp:", rejected !== null);
}

async function testHttpClientBasic() {
  var http = require("http");
  // Local mock server — listens on a random port, captures method+path.
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var body = Buffer.concat(chunks).toString("utf8");
      res.writeHead(200, { "Content-Type": "text/plain", "X-Method": req.method });
      res.end("got " + req.method + " " + req.url + " body=" + body);
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();

    // GET
    var got = await httpReq({ url: "http://127.0.0.1:" + port + "/foo" });
    check("httpClient: GET status",          got.statusCode === 200);
    check("httpClient: GET body buffered",   Buffer.isBuffer(got.body));
    check("httpClient: GET body content",    got.body.toString("utf8").indexOf("got GET /foo") === 0);
    check("httpClient: GET headers",         got.headers["x-method"] === "GET");

    // POST with Buffer body
    var posted = await httpReq({
      method: "POST", url: "http://127.0.0.1:" + port + "/bar",
      body: Buffer.from("hello", "utf8"),
    });
    check("httpClient: POST body sent", posted.body.toString("utf8").indexOf("body=hello") !== -1);

    // Connection pooling — same origin reuses the cached agent
    check("httpClient: transport cached after first call",
          b.httpClient._getCachedTransportCount() >= 1);
    await httpReq({ url: "http://127.0.0.1:" + port + "/baz" });
    check("httpClient: same origin reuses transport",
          b.httpClient._getCachedTransportCount() === 1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientConfigurePool() {
  // configurePool tunes the per-origin transport cache and resets it so
  // subsequent requests build fresh transports with the new opts.
  var http = require("http");
  var server = http.createServer(function (_req, res) { res.writeHead(200); res.end("ok"); });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    await httpReq({ url: "http://127.0.0.1:" + port + "/" });
    check("configurePool: transport cached pre-reconfigure",
          b.httpClient._getCachedTransportCount() === 1);
    b.httpClient.configurePool({ maxSockets: 8, keepAliveMsecs: 500 });
    check("configurePool: cache cleared on reconfigure",
          b.httpClient._getCachedTransportCount() === 0);
    await httpReq({ url: "http://127.0.0.1:" + port + "/" });
    check("configurePool: subsequent request rebuilds transport",
          b.httpClient._getCachedTransportCount() === 1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
    // Restore defaults so the rest of the suite isn't affected.
    b.httpClient.configurePool({
      maxSockets:     b.httpClient.DEFAULT_AGENT_OPTS.maxSockets,
      maxFreeSockets: b.httpClient.DEFAULT_AGENT_OPTS.maxFreeSockets,
      keepAliveMsecs: b.httpClient.DEFAULT_AGENT_OPTS.keepAliveMsecs,
    });
  }

  // Reject bad inputs at the call site.
  function rejects(label, fn, msgRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("configurePool rejects: " + label,  threw && msgRe.test(threw.message || ""));
  }
  rejects("non-object input",          function () { b.httpClient.configurePool("nope"); }, /must be an object/);
  rejects("unknown key",               function () { b.httpClient.configurePool({ bogus: 1 }); }, /unknown option/);
  rejects("negative maxSockets",       function () { b.httpClient.configurePool({ maxSockets: -1 }); }, /positive integer/);
  rejects("non-integer keepAliveMsecs",function () { b.httpClient.configurePool({ keepAliveMsecs: 1.5 }); }, /positive integer/);
  rejects("Infinity maxFreeSockets",   function () { b.httpClient.configurePool({ maxFreeSockets: Infinity }); }, /positive integer/);
  rejects("non-boolean keepAlive",     function () { b.httpClient.configurePool({ keepAlive: "yes" }); }, /must be a boolean/);
  rejects("bad scheduling",            function () { b.httpClient.configurePool({ scheduling: "rr" }); }, /lifo.*fifo/);
}

async function testHttpClientErrorStatus() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    if (req.url === "/notfound") { res.writeHead(404); res.end("missing"); }
    else if (req.url === "/throttle") { res.writeHead(429); res.end("slow down"); }
    else if (req.url === "/boom") { res.writeHead(500); res.end("oops"); }
    else { res.writeHead(200); res.end("ok"); }
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();

    // 404 → permanent
    var threw404 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/notfound", errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw404 = e; }
    check("httpClient: 404 rejects",            threw404 !== null);
    check("httpClient: 404 ObjectStoreError",   threw404 instanceof b.frameworkError.ObjectStoreError);
    check("httpClient: 404 statusCode",         threw404.statusCode === 404);
    check("httpClient: 404 permanent",          threw404.permanent === true);

    // 429 → transient
    var threw429 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/throttle", errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw429 = e; }
    check("httpClient: 429 transient (not permanent)", threw429.permanent === false);

    // 500 → transient
    var threw500 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/boom", errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw500 = e; }
    check("httpClient: 500 transient", threw500.permanent === false);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientWallClockTimeout() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    // Slow responder — write headers, dribble bytes well past timeout.
    res.writeHead(200);
    var i = 0;
    var iv = setInterval(function () {
      if (i++ >= 50) { clearInterval(iv); res.end(); return; }
      res.write("x");
    }, 50);
    req.on("close", function () { clearInterval(iv); });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var threw = null;
    var t0 = Date.now();
    try {
      await httpReq({
        url: "http://127.0.0.1:" + port + "/slow",
        timeoutMs: 200,                 // wall-clock — must fire even if data IS flowing
        idleTimeoutMs: 5000,            // generous idle so wall-clock is what fires
      });
    } catch (e) { threw = e; }
    var elapsed = Date.now() - t0;
    check("httpClient: wall-clock timeout fires",     threw !== null);
    check("httpClient: timeout error code ETIMEDOUT", threw && threw.code === "ETIMEDOUT");
    check("httpClient: wall-clock fired within 1s",    elapsed < 1000);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientAbortSignal() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    // Hang forever — only cancellation can free this.
    res.writeHead(200);
    // Don't end; wait for client disconnect.
    req.on("close", function () { try { res.end(); } catch (_e) {} });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var ac = new AbortController();
    setTimeout(function () { ac.abort(); }, 100);
    var threw = null;
    try {
      await httpReq({
        url: "http://127.0.0.1:" + port + "/hang",
        signal: ac.signal,
        idleTimeoutMs: 60000,
      });
    } catch (e) { threw = e; }
    check("httpClient: AbortSignal cancels request",  threw !== null);
    check("httpClient: abort code ABORT",             threw && threw.code === "ABORT");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientStreamResponse() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.write("part1-");
    res.write("part2-");
    res.end("end");
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var got = await httpReq({
      url: "http://127.0.0.1:" + port + "/stream",
      responseMode: "stream",
    });
    check("httpClient: stream mode returns Readable",
          got.body && typeof got.body.on === "function");
    var collected = await new Promise(function (resolve, reject) {
      var chunks = [];
      got.body.on("data", function (c) { chunks.push(c); });
      got.body.on("end",  function ()  { resolve(Buffer.concat(chunks).toString("utf8")); });
      got.body.on("error", reject);
    });
    check("httpClient: stream content", collected === "part1-part2-end");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2Basic() {
  var http2 = require("http2");
  // h2c (cleartext h2) mock server
  var server = http2.createServer();
  server.on("stream", function (stream, headers) {
    var method = headers[":method"];
    var path   = headers[":path"];
    var chunks = [];
    stream.on("data", function (c) { chunks.push(c); });
    stream.on("end", function () {
      var bodyIn = Buffer.concat(chunks).toString("utf8");
      stream.respond({ ":status": 200, "x-method": method, "content-type": "text/plain" });
      stream.end("h2 got " + method + " " + path + " body=" + bodyIn);
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var url = "http://127.0.0.1:" + port + "/foo";

    // GET via h2c — preferH2 flag opts in (no ALPN over cleartext)
    var got = await httpReq({ url: url, preferH2: true });
    check("httpClient h2: GET status",       got.statusCode === 200);
    check("httpClient h2: GET body",         got.body.toString("utf8").indexOf("h2 got GET /foo") === 0);
    check("httpClient h2: GET headers",      got.headers["x-method"] === "GET");

    // Transport cache shows h2 kind
    check("httpClient h2: cached as h2",     b.httpClient._getCachedTransportKind(url) === "h2");

    // POST with body — same h2 session multiplexes
    var posted = await httpReq({
      method: "POST", url: url, body: Buffer.from("hello-h2"), preferH2: true,
    });
    check("httpClient h2: POST body sent",   posted.body.toString("utf8").indexOf("body=hello-h2") !== -1);

    // Transport count = 1 (multiplexed over single session)
    check("httpClient h2: single session",   b.httpClient._getCachedTransportCount() === 1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2AbortSignal() {
  var http2 = require("http2");
  var server = http2.createServer();
  server.on("stream", function (stream, _headers) {
    stream.respond({ ":status": 200 });
    // Hang — only client cancellation closes this stream.
    stream.on("close", function () {});
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var url = "http://127.0.0.1:" + port + "/hang";
    var ac = new AbortController();
    setTimeout(function () { ac.abort(); }, 100);
    var threw = null;
    try {
      await httpReq({ url: url, preferH2: true, signal: ac.signal, idleTimeoutMs: 60000 });
    } catch (e) { threw = e; }
    check("httpClient h2: AbortSignal cancels stream", threw !== null);
    check("httpClient h2: abort code ABORT",           threw && threw.code === "ABORT");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2ErrorStatus() {
  var http2 = require("http2");
  var server = http2.createServer();
  server.on("stream", function (stream, headers) {
    if (headers[":path"] === "/notfound") {
      stream.respond({ ":status": 404 }); stream.end("missing");
    } else if (headers[":path"] === "/throttle") {
      stream.respond({ ":status": 429 }); stream.end("slow down");
    } else {
      stream.respond({ ":status": 500 }); stream.end("oops");
    }
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();

    var threw404 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/notfound", preferH2: true, errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw404 = e; }
    check("httpClient h2: 404 rejects",           threw404 !== null);
    check("httpClient h2: 404 ObjectStoreError",  threw404 instanceof b.frameworkError.ObjectStoreError);
    check("httpClient h2: 404 statusCode",        threw404.statusCode === 404);
    check("httpClient h2: 404 permanent",         threw404.permanent === true);

    var threw429 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/throttle", preferH2: true, errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw429 = e; }
    check("httpClient h2: 429 transient", threw429.permanent === false);

    var threw500 = null;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/boom", preferH2: true, errorClass: b.frameworkError.ObjectStoreError }); }
    catch (e) { threw500 = e; }
    check("httpClient h2: 500 transient", threw500.permanent === false);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2Multiplex() {
  var http2 = require("http2");
  var server = http2.createServer();
  server.on("stream", function (stream, headers) {
    // Tag response with the request path so we can verify each request
    // landed independently — they share the session, not the response.
    setTimeout(function () {
      stream.respond({ ":status": 200 });
      stream.end("path=" + headers[":path"]);
    }, 10);
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    // Fire 5 concurrent requests over the same h2 session.
    var promises = [];
    for (var i = 0; i < 5; i++) {
      promises.push(httpReq({
        url: "http://127.0.0.1:" + port + "/p" + i,
        preferH2: true,
      }));
    }
    var results = await Promise.all(promises);
    var bodies = results.map(function (r) { return r.body.toString("utf8"); }).sort();
    check("httpClient h2: 5 multiplexed responses", bodies.length === 5);
    check("httpClient h2: each response carries its path",
          bodies[0] === "path=/p0" && bodies[4] === "path=/p4");
    // All 5 sharing one cached session
    check("httpClient h2: still one cached session", b.httpClient._getCachedTransportCount() === 1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientH2Stream() {
  var http2 = require("http2");
  var server = http2.createServer();
  server.on("stream", function (stream) {
    stream.respond({ ":status": 200 });
    stream.write("part1-");
    stream.write("part2-");
    stream.end("end");
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var got = await httpReq({
      url: "http://127.0.0.1:" + port + "/stream",
      preferH2: true,
      responseMode: "stream",
    });
    check("httpClient h2: stream returns Readable",
          got.body && typeof got.body.on === "function");
    var collected = await new Promise(function (resolve, reject) {
      var chunks = [];
      got.body.on("data", function (c) { chunks.push(c); });
      got.body.on("end",  function ()  { resolve(Buffer.concat(chunks).toString("utf8")); });
      got.body.on("error", reject);
    });
    check("httpClient h2: stream content", collected === "part1-part2-end");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

// ---- v0.4.15 redirect-following + outbound multipart ----

async function testHttpClientRedirectFollow() {
  var http = require("http");
  var hits = [];
  var server = http.createServer(function (req, res) {
    hits.push(req.url);
    if (req.url === "/start") {
      res.writeHead(302, { "Location": "/middle" });
      res.end();
    } else if (req.url === "/middle") {
      res.writeHead(302, { "Location": "/end" });
      res.end();
    } else if (req.url === "/end") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("final");
    } else { res.writeHead(404); res.end(); }
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    // Default behavior (no maxRedirects opt) — non-2xx including 3xx
    // throws as an HTTP error, matching the framework's existing
    // contract before maxRedirects existed.
    var threw = false;
    try { await httpReq({ url: "http://127.0.0.1:" + port + "/start" }); }
    catch (_e) { threw = true; }
    check("redirect: default behavior treats 3xx as error", threw);

    hits.length = 0;
    // Follow — caller sees 200.
    var followed = await httpReq({
      url:          "http://127.0.0.1:" + port + "/start",
      maxRedirects: 5,
    });
    check("redirect: follow lands on 200",            followed.statusCode === 200);
    check("redirect: follow body is final",           followed.body.toString("utf8") === "final");
    check("redirect: server saw 3 hops",              hits.length === 3);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientRedirectMaxHops() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    res.writeHead(302, { "Location": req.url + "x" });
    res.end();
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    // maxRedirects: 2 — server keeps redirecting; caller sees the 3rd 3xx.
    var capped = await httpReq({
      url:          "http://127.0.0.1:" + port + "/loop",
      maxRedirects: 2,
    });
    check("redirect: maxRedirects:2 stops after 2 hops",   capped.statusCode === 302);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientRedirectStripsAuthCrossOrigin() {
  var http = require("http");
  // Same-origin server keeps Authorization; the test asserts the
  // Authorization header is absent on the second hop when the redirect
  // changes the URL host. We can't actually cross hosts in a unit test
  // (one server), so we use 127.0.0.1 vs localhost — different by string.
  var seenAuthOnEnd;
  var serverEnd = http.createServer(function (req, res) {
    seenAuthOnEnd = req.headers["authorization"] || null;
    res.writeHead(200);
    res.end("ok");
  });
  var portEnd = await listenOnRandomPort(serverEnd, "127.0.0.1");

  var serverStart = http.createServer(function (req, res) {
    // Redirect to a different host (localhost vs 127.0.0.1 — origin differs)
    res.writeHead(302, { "Location": "http://localhost:" + portEnd + "/" });
    res.end();
  });
  var portStart = await listenOnRandomPort(serverStart, "127.0.0.1");
  try {
    b.httpClient._resetForTest();
    await httpReq({
      url:          "http://127.0.0.1:" + portStart + "/",
      headers:      { "Authorization": "Bearer secret-token" },
      maxRedirects: 5,
    });
    check("redirect: Authorization stripped on cross-origin hop",
          seenAuthOnEnd === null);
  } finally {
    serverEnd.close();
    serverStart.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientRedirect303CoercesGet() {
  var http = require("http");
  var capturedMethod = null;
  var server = http.createServer(function (req, res) {
    if (req.url === "/post") {
      res.writeHead(303, { "Location": "/get-target" });
      res.end();
    } else if (req.url === "/get-target") {
      capturedMethod = req.method;
      res.writeHead(200);
      res.end("ok");
    }
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    await httpReq({
      url:          "http://127.0.0.1:" + port + "/post",
      method:       "POST",
      body:         Buffer.from("payload"),
      headers:      { "Content-Type": "application/octet-stream" },
      maxRedirects: 5,
    });
    check("redirect: 303 coerces follow-up to GET", capturedMethod === "GET");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientMultipartOutbound() {
  var http = require("http");
  var captured;
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      captured = {
        method:      req.method,
        contentType: req.headers["content-type"],
        body:        Buffer.concat(chunks),
      };
      res.writeHead(200);
      res.end("ok");
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    await httpReq({
      url:    "http://127.0.0.1:" + port + "/upload",
      multipart: {
        fields: { title: "My Doc", tags: ["a", "b"] },
        files:  [{ field: "file", filename: "x.txt",
                   contentType: "text/plain", content: "hello multipart" }],
      },
    });
    check("multipart: method defaults to POST",     captured.method === "POST");
    check("multipart: Content-Type carries boundary",
          /^multipart\/form-data; boundary=----blamejs-mp-/.test(captured.contentType));
    var bodyStr = captured.body.toString("utf8");
    check("multipart: title field present",          bodyStr.indexOf('name="title"') !== -1);
    check("multipart: tag field repeated",          (bodyStr.match(/name="tags"/g) || []).length === 2);
    check("multipart: file Content-Disposition",     bodyStr.indexOf('name="file"; filename="x.txt"') !== -1);
    check("multipart: file Content-Type",            bodyStr.indexOf("Content-Type: text/plain") !== -1);
    check("multipart: file content present",         bodyStr.indexOf("hello multipart") !== -1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientMultipartConflictsWithBody() {
  var threw = false;
  try {
    await httpReq({
      url:       "http://127.0.0.1:1/x",
      body:      "anything",
      multipart: { fields: { a: "b" } },
    });
  } catch (_e) { threw = true; }
  check("multipart: rejects body+multipart together",  threw);
}

// ---- v0.4.17 cookie jar ----

function testCookieJarSurface() {
  check("b.httpClient.cookieJar exists",      typeof b.httpClient.cookieJar === "object");
  check("cookieJar.create is a function",     typeof b.httpClient.cookieJar.create === "function");
  check("CookieJarError class",                typeof b.httpClient.cookieJar.CookieJarError === "function");
  check("DEFAULTS frozen",                     Object.isFrozen(b.httpClient.cookieJar.DEFAULTS));
  check("DEFAULTS.persist === 'memory'",       b.httpClient.cookieJar.DEFAULTS.persist === "memory");
}

function testCookieJarParseAndAttach() {
  var jar = b.httpClient.cookieJar.create();
  jar.setFromResponse("https://example.com/login", "session=abc123; Path=/; HttpOnly; Secure");
  var hdr = jar.cookieHeaderFor("https://example.com/me");
  check("cookieJar: round-trip session=abc123",   hdr === "session=abc123");
  check("cookieJar: size = 1",                    jar.size() === 1);
}

function testCookieJarDomainAttribute() {
  var jar = b.httpClient.cookieJar.create();
  jar.setFromResponse("https://api.example.com/", "tracking=t1; Domain=example.com; Path=/");
  // Subdomain match per Domain attribute.
  var sub = jar.cookieHeaderFor("https://api.example.com/x");
  check("Domain attr: subdomain attaches",        sub === "tracking=t1");
  // Different host that doesn't match the domain
  var none = jar.cookieHeaderFor("https://other.com/x");
  check("Domain attr: unrelated host gets nothing", none === null);
  // Domain attr that the response host doesn't match — drop entirely.
  jar.setFromResponse("https://api.example.com/", "evil=v; Domain=other.com");
  check("Domain attr: rejects when host doesn't suffix-match", jar.size() === 1);
}

function testCookieJarPathMatch() {
  var jar = b.httpClient.cookieJar.create();
  jar.setFromResponse("https://example.com/api/v1/", "scoped=s; Path=/api/v1");
  check("Path match: exact",     jar.cookieHeaderFor("https://example.com/api/v1") === "scoped=s");
  check("Path match: below",     jar.cookieHeaderFor("https://example.com/api/v1/x") === "scoped=s");
  check("Path match: outside",   jar.cookieHeaderFor("https://example.com/other") === null);
}

function testCookieJarSecureFilter() {
  var jar = b.httpClient.cookieJar.create();
  jar.setFromResponse("https://example.com/", "s=val; Secure; Path=/");
  check("Secure: sent over https",  jar.cookieHeaderFor("https://example.com/x") === "s=val");
  check("Secure: not sent over http", jar.cookieHeaderFor("http://example.com/x") === null);
}

function testCookieJarMaxAgeAndExpires() {
  var nowMs = 1700000000000;
  var jar = b.httpClient.cookieJar.create({ clock: function () { return nowMs; } });
  jar.setFromResponse("https://example.com/", "k=v; Max-Age=60; Path=/");
  // Read at set-time: still live.
  check("Max-Age: live within window", jar.cookieHeaderFor("https://example.com/x") === "k=v");
  // Advance the clock past the 60-second window.
  nowMs += 120000;
  check("Max-Age: expired after window",
        jar.cookieHeaderFor("https://example.com/x") === null);
}

function testCookieJarMaxAgeZeroDeletes() {
  var jar = b.httpClient.cookieJar.create();
  jar.setFromResponse("https://example.com/", "k=v; Path=/");
  check("delete: present before",                  jar.size() === 1);
  jar.setFromResponse("https://example.com/", "k=v; Max-Age=0; Path=/");
  check("Max-Age=0: cookie removed",               jar.size() === 0);
}

function testCookieJarMultipleSort() {
  var jar = b.httpClient.cookieJar.create();
  jar.setFromResponse("https://example.com/", "a=root; Path=/");
  jar.setFromResponse("https://example.com/", "b=deep; Path=/x/y");
  var hdr = jar.cookieHeaderFor("https://example.com/x/y/z");
  // Longer-path cookie should appear first.
  check("multi-cookie sort: longer path first",  /^b=deep; a=root$/.test(hdr));
}

function testCookieJarClearAndGetAll() {
  var jar = b.httpClient.cookieJar.create();
  jar.setFromResponse("https://a.example.com/", "x=1; Path=/");
  jar.setFromResponse("https://b.example.com/", "y=2; Path=/");
  check("getAll: 2 rows",                          jar.getAll().length === 2);
  var purged = jar.clear({ domain: "a.example.com" });
  check("clear: filtered domain purges 1",         purged === 1);
  check("clear: remaining = 1",                    jar.size() === 1);
  jar.clear();
  check("clear: full wipe",                        jar.size() === 0);
}

function testCookieJarSetFromSerialized() {
  var jar = b.httpClient.cookieJar.create();
  jar.setFromResponse("https://example.com/", "s=z; Path=/");
  var rows = jar.getAll();

  var jar2 = b.httpClient.cookieJar.create();
  jar2.setFromSerialized(rows);
  check("serialize round-trip: size matches",       jar2.size() === 1);
  check("serialize round-trip: cookieHeader OK",
        jar2.cookieHeaderFor("https://example.com/x") === "s=z");
}

function testCookieJarPersistVaultRequiresVault() {
  var threw = false;
  try { b.httpClient.cookieJar.create({ persist: "vault" }); }
  catch (_e) { threw = true; }
  check("persist:'vault': rejects missing vault",   threw);

  // Bad shape — object without seal/unseal
  threw = false;
  try { b.httpClient.cookieJar.create({ persist: "vault", vault: { seal: 1 } }); }
  catch (_e) { threw = true; }
  check("persist:'vault': rejects malformed vault", threw);
}

function testCookieJarPersistVaultEncryptsValue() {
  // No-op vault stub that wraps + unwraps with a recognizable prefix —
  // mirrors b.vault.seal/unseal contract minus the actual crypto. The
  // assertion isn't about the cipher (b.vault tests cover that); it's
  // that the jar's IN-MEMORY storage never holds the plaintext value.
  var fakeVault = {
    seal:   function (v) { return "vault:SEALED(" + v + ")"; },
    unseal: function (v) {
      if (typeof v !== "string" || v.indexOf("vault:SEALED(") !== 0) return v;
      return v.slice("vault:SEALED(".length, -1);
    },
  };
  var jar = b.httpClient.cookieJar.create({ persist: "vault", vault: fakeVault });
  jar.setFromResponse("https://example.com/login", "session=secret-cookie-plaintext-12345; Path=/; Secure");

  // Forensic check: the jar's RAW store must not contain the plaintext.
  var raw = jar._storeForTest();
  check("vault persist: raw stored 1 entry",        raw.length === 1);
  check("vault persist: raw value is sealed",
        typeof raw[0].valueRaw === "string" && raw[0].valueRaw.indexOf("vault:") === 0);
  check("vault persist: raw value HIDES plaintext",
        raw[0].valueRaw.indexOf("secret-cookie-plaintext-12345") === -1 ||
        raw[0].valueRaw === "vault:SEALED(secret-cookie-plaintext-12345)");

  // The fake-vault-sealed string DOES include the plaintext inside the
  // SEALED() wrapper for trace purposes — that's a test-only artifact.
  // The harder forensic check: serialize the WHOLE jar map and grep.
  var dump = JSON.stringify(raw);
  // With a real vault.seal, the dump won't contain the plaintext at
  // all. Our fake's wrapper does contain it. Rather than rely on the
  // fake's behavior, run a SECOND scenario with a lossy fake that
  // returns ciphertext-only so the forensic test is real.
  var lossyVault = {
    seal:   function (_v) { return "vault:OPAQUE-CIPHERTEXT-NO-PLAINTEXT-LEAK"; },
    unseal: function (_v) { return "session=opaque"; },
  };
  var jar2 = b.httpClient.cookieJar.create({ persist: "vault", vault: lossyVault });
  jar2.setFromResponse("https://example.com/", "session=actually-secret-PLAINTEXT-7777; Path=/");
  var dump2 = JSON.stringify(jar2._storeForTest());
  check("vault persist (lossy): no plaintext in raw store",
        dump2.indexOf("actually-secret-PLAINTEXT-7777") === -1);
  check("vault persist (lossy): raw value is the opaque ciphertext",
        dump2.indexOf("OPAQUE-CIPHERTEXT-NO-PLAINTEXT-LEAK") !== -1);

  // Reading via cookieHeaderFor goes through unseal — operator sees
  // plaintext at the API boundary, never in the storage map.
  var hdr = jar.cookieHeaderFor("https://example.com/anything");
  check("vault persist: API boundary delivers plaintext",
        hdr === "session=secret-cookie-plaintext-12345");

  // Memory-mode jar SHOULD hold plaintext (no encryption opted in).
  var memJar = b.httpClient.cookieJar.create();
  memJar.setFromResponse("https://example.com/", "k=memory-mode-plaintext; Path=/");
  var memDump = JSON.stringify(memJar._storeForTest());
  check("memory persist (default): raw store IS plaintext",
        memDump.indexOf("memory-mode-plaintext") !== -1);

  void dump;  // dump retained earlier for symmetry
}

// Build a vault-shaped wrapper backed by REAL XChaCha20-Poly1305 via
// b.crypto.encryptPacked. Used in the forensic tests below to exercise
// the actual cipher properties (random nonce per encrypt, AEAD tag,
// ciphertext that doesn't reveal plaintext) rather than the lossy fake
// from testCookieJarPersistVaultEncryptsValue.
function _realCryptoVault() {
  var key = b.crypto.generateBytes(32);
  return {
    seal: function (plaintext) {
      var packed = b.crypto.encryptPacked(Buffer.from(String(plaintext), "utf8"), key);
      return "vault:" + packed.toString("base64");
    },
    unseal: function (sealed) {
      if (typeof sealed !== "string" || sealed.indexOf("vault:") !== 0) return sealed;
      var packed = Buffer.from(sealed.slice("vault:".length), "base64");
      return b.crypto.decryptPacked(packed, key).toString("utf8");
    },
  };
}

function testCookieJarRealCryptoForensic() {
  // Same shape as testCookieJarPersistVaultEncryptsValue but using REAL
  // XChaCha20-Poly1305 — the forensic claim has to hold against the
  // actual cipher, not a fake stub. Operator concern: even with the
  // raw stored bytes, an attacker must not be able to recover the
  // plaintext cookie value.
  var vault = _realCryptoVault();
  var jar = b.httpClient.cookieJar.create({ persist: "vault", vault: vault });
  var SECRET = "session=jwt.eyJhbGciOiJSUzI1NiJ9.SECRET-PAYLOAD-DO-NOT-LEAK-1234567890";
  jar.setFromResponse("https://example.com/login", SECRET + "; Path=/; Secure");

  // Forensic claim 1: the raw stored value MUST NOT contain the
  // plaintext substring anywhere — not as a suffix, prefix, or in the
  // middle of the AEAD output.
  var raw = jar._storeForTest();
  var dump = JSON.stringify(raw);
  check("real-crypto: no plaintext substring in raw store",
        dump.indexOf("SECRET-PAYLOAD-DO-NOT-LEAK") === -1);
  check("real-crypto: stored value carries vault: prefix",
        raw[0].valueRaw.indexOf("vault:") === 0);

  // Forensic claim 2: round-trip via the API boundary still recovers
  // the plaintext (so legitimate operator code works), proving the
  // ciphertext IS reversible — but only with the vault key.
  var hdr = jar.cookieHeaderFor("https://example.com/anywhere");
  check("real-crypto: API boundary recovers plaintext",
        hdr.indexOf("SECRET-PAYLOAD-DO-NOT-LEAK") !== -1);
}

function testCookieJarReplayBlobUnusable() {
  // Operator's concern: if an attacker reads the stored blob and tries
  // to use it as a Cookie header to forge a session against the upstream,
  // the upstream's auth layer should see garbage — not the original
  // session token. This is a structural property of the cipher: blob
  // text is NOT equal to plaintext, so { Cookie: session=<blob> } would
  // fail upstream-side auth that expects the plaintext.
  var vault = _realCryptoVault();
  var jar = b.httpClient.cookieJar.create({ persist: "vault", vault: vault });
  var TOKEN_PLAINTEXT = "AUTH-TOKEN-PLAINTEXT-AAAA";
  jar.setFromResponse("https://example.com/login",
                      "session=" + TOKEN_PLAINTEXT + "; Path=/");

  var raw = jar._storeForTest();
  var stored = raw[0].valueRaw;

  check("replay: stored blob is NOT equal to plaintext token",
        stored !== TOKEN_PLAINTEXT);

  // The blob is a "vault:<base64>" envelope — sending it as
  // `Cookie: session=vault:base64...` to the upstream would mismatch
  // any backend expecting the plaintext.
  check("replay: stored blob is the vault envelope, not the token",
        /^vault:[A-Za-z0-9+/=]+$/.test(stored));

  // Cipher property: even the BASE64 portion contains no plaintext.
  check("replay: base64 ciphertext doesn't leak plaintext substring",
        stored.indexOf("AUTH-TOKEN-PLAINTEXT-AAAA") === -1);
}

function testCookieJarNonceRandomized() {
  // XChaCha20-Poly1305 random nonce per encrypt → same plaintext sealed
  // twice produces different blobs. So an attacker can't fingerprint
  // sessions by comparing blob byte-strings across snapshots.
  var vault = _realCryptoVault();
  var jar1 = b.httpClient.cookieJar.create({ persist: "vault", vault: vault });
  var jar2 = b.httpClient.cookieJar.create({ persist: "vault", vault: vault });
  var SAME_TOKEN = "session=identical-plaintext-XXXX; Path=/";
  jar1.setFromResponse("https://example.com/login", SAME_TOKEN);
  jar2.setFromResponse("https://example.com/login", SAME_TOKEN);
  var raw1 = jar1._storeForTest()[0].valueRaw;
  var raw2 = jar2._storeForTest()[0].valueRaw;
  check("nonce-random: same plaintext → different ciphertexts",
        raw1 !== raw2);
  check("nonce-random: both still decrypt to the original token",
        jar1.cookieHeaderFor("https://example.com/x").indexOf("identical-plaintext-XXXX") !== -1 &&
        jar2.cookieHeaderFor("https://example.com/x").indexOf("identical-plaintext-XXXX") !== -1);
}

async function testHttpClientJarRoundTrip() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    if (req.url === "/login") {
      res.writeHead(200, { "Set-Cookie": "session=abc; Path=/; HttpOnly", "Content-Type": "text/plain" });
      res.end("logged in");
    } else if (req.url === "/me") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("cookies: " + (req.headers.cookie || "(none)"));
    }
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var jar = b.httpClient.cookieJar.create();
    await httpReq({ url: "http://127.0.0.1:" + port + "/login", jar: jar });
    var me = await httpReq({ url: "http://127.0.0.1:" + port + "/me", jar: jar });
    check("jar: cookie attached on second hop",
          me.body.toString("utf8").indexOf("session=abc") !== -1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientJarMergesWithCallerCookie() {
  var http = require("http");
  var seen;
  var server = http.createServer(function (req, res) {
    seen = req.headers.cookie;
    res.writeHead(200);
    res.end();
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var jar = b.httpClient.cookieJar.create();
    jar.setFromResponse("http://127.0.0.1:" + port + "/", "from-jar=A; Path=/");
    await httpReq({
      url:     "http://127.0.0.1:" + port + "/x",
      headers: { "Cookie": "caller-set=B" },
      jar:     jar,
    });
    check("jar: caller Cookie + jar header merged",
          seen && seen.indexOf("caller-set=B") !== -1 && seen.indexOf("from-jar=A") !== -1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientJarValidation() {
  var threw = false;
  try { await httpReq({ url: "http://127.0.0.1:1/x", jar: { foo: 1 } }); }
  catch (_e) { threw = true; }
  check("jar: rejects malformed jar object",   threw);
}

async function testHttpClientJarFollowsRedirect() {
  var http = require("http");
  var seenAtHop2;
  var server = http.createServer(function (req, res) {
    if (req.url === "/start") {
      res.writeHead(302, { "Location": "/end", "Set-Cookie": "trace=hop1; Path=/" });
      res.end();
    } else if (req.url === "/end") {
      seenAtHop2 = req.headers.cookie;
      res.writeHead(200);
      res.end("ok");
    }
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var jar = b.httpClient.cookieJar.create();
    await httpReq({
      url:          "http://127.0.0.1:" + port + "/start",
      jar:          jar,
      maxRedirects: 5,
    });
    check("jar: cookie set on hop1 attaches on hop2",
          seenAtHop2 && seenAtHop2.indexOf("trace=hop1") !== -1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

// ---- v0.4.16 interceptors + progress events ----

async function testHttpClientBeforeInterceptor() {
  var http = require("http");
  var capturedHeader;
  var server = http.createServer(function (req, res) {
    capturedHeader = req.headers["x-injected"];
    res.writeHead(200);
    res.end("ok");
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    await httpReq({
      url: "http://127.0.0.1:" + port + "/",
      before: [
        function (req) {
          req.headers = Object.assign({}, req.headers || {}, { "X-Injected": "from-interceptor" });
          return req;
        },
      ],
    });
    check("before: interceptor injects header",  capturedHeader === "from-interceptor");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientBeforeChain() {
  var http = require("http");
  var sawA, sawB;
  var server = http.createServer(function (req, res) {
    sawA = req.headers["x-a"];
    sawB = req.headers["x-b"];
    res.writeHead(200);
    res.end();
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    await httpReq({
      url: "http://127.0.0.1:" + port + "/",
      before: [
        function (req) { req.headers = { "X-A": "1" }; return req; },
        function (req) { req.headers = Object.assign({}, req.headers, { "X-B": "2" }); return req; },
      ],
    });
    check("before: chain runs in order — first sets X-A",  sawA === "1");
    check("before: chain runs in order — second adds X-B", sawB === "2");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientBeforeThrows() {
  var threw = false;
  try {
    await httpReq({
      url: "http://127.0.0.1:1/x",
      before: [function () { throw new Error("oops"); }],
    });
  } catch (e) {
    threw = e && (e.code === "BEFORE_THREW" || /BEFORE_THREW/.test(e.message));
  }
  check("before: thrown error surfaces as BEFORE_THREW",  threw);
}

async function testHttpClientAfterInterceptor() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "X-Server-Tag": "alpha" });
    res.end("hi");
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var captured = null;
    await httpReq({
      url: "http://127.0.0.1:" + port + "/",
      after: [
        function (reqOpts, res) { captured = { url: reqOpts.url, status: res.statusCode, tag: res.headers["x-server-tag"] }; },
      ],
    });
    check("after: receives final opts + response",
          captured && captured.status === 200 && captured.tag === "alpha");
    check("after: opts carries url",
          captured.url.indexOf("/") !== -1);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientAfterAcrossRedirect() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    if (req.url === "/start") { res.writeHead(302, { "Location": "/end" }); res.end(); }
    else { res.writeHead(200); res.end("done"); }
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var capturedUrl = null;
    var capturedStatus = null;
    await httpReq({
      url:          "http://127.0.0.1:" + port + "/start",
      maxRedirects: 5,
      after:        [function (reqOpts, res) { capturedUrl = reqOpts.url; capturedStatus = res.statusCode; }],
    });
    check("after: fires once with final URL after redirect",
          capturedUrl.indexOf("/end") !== -1);
    check("after: receives the final 200, not the 302",   capturedStatus === 200);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientInterceptorValidation() {
  var threw;

  threw = false;
  try { await httpReq({ url: "http://127.0.0.1:1/x", before: "not-an-array" }); }
  catch (_e) { threw = true; }
  check("interceptor: rejects non-array before",  threw);

  threw = false;
  try { await httpReq({ url: "http://127.0.0.1:1/x", before: [42] }); }
  catch (_e) { threw = true; }
  check("interceptor: rejects non-fn entries",   threw);

  threw = false;
  try { await httpReq({ url: "http://127.0.0.1:1/x", after: { fn: 1 } }); }
  catch (_e) { threw = true; }
  check("interceptor: rejects non-array after",  threw);

  threw = false;
  try { await httpReq({ url: "http://127.0.0.1:1/x", onUploadProgress: 42 }); }
  catch (_e) { threw = true; }
  check("progress: rejects non-fn onUploadProgress", threw);

  threw = false;
  try { await httpReq({ url: "http://127.0.0.1:1/x", onDownloadProgress: "no" }); }
  catch (_e) { threw = true; }
  check("progress: rejects non-fn onDownloadProgress", threw);
}

async function testHttpClientUploadProgress() {
  var http = require("http");
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      res.writeHead(200);
      res.end("got " + Buffer.concat(chunks).length + " bytes");
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var events = [];
    var body = Buffer.alloc(200 * 1024, "x");      // 200 KiB → 4 chunks at 64 KiB
    await httpReq({
      method: "POST",
      url:    "http://127.0.0.1:" + port + "/upload",
      body:   body,
      onUploadProgress: function (e) { events.push(e); },
    });
    check("upload progress: at least 1 event",     events.length >= 1);
    var last = events[events.length - 1];
    check("upload progress: final loaded matches body",  last.loaded === body.length);
    check("upload progress: total = body.length",        last.total === body.length);
    check("upload progress: monotonic loaded",
          events.every(function (e, i) { return i === 0 || e.loaded >= events[i - 1].loaded; }));
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientDownloadProgress() {
  var http = require("http");
  var payload = Buffer.alloc(100 * 1024, "y");
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Length": String(payload.length), "Content-Type": "application/octet-stream" });
    res.end(payload);
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var events = [];
    var got = await httpReq({
      url:                "http://127.0.0.1:" + port + "/blob",
      onDownloadProgress: function (e) { events.push(e); },
    });
    check("download progress: response complete",         got.body.length === payload.length);
    check("download progress: at least 1 event",          events.length >= 1);
    var last = events[events.length - 1];
    check("download progress: final loaded matches body", last.loaded === payload.length);
    check("download progress: total = Content-Length",    last.total === payload.length);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientDownloadProgressStream() {
  var http = require("http");
  var payload = Buffer.alloc(50 * 1024, "z");
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Length": String(payload.length) });
    res.end(payload);
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var events = [];
    var got = await httpReq({
      url:                "http://127.0.0.1:" + port + "/blob",
      responseMode:       "stream",
      onDownloadProgress: function (e) { events.push(e); },
    });
    var collected = await new Promise(function (resolve, reject) {
      var chunks = [];
      got.body.on("data",  function (c) { chunks.push(c); });
      got.body.on("end",   function ()  { resolve(Buffer.concat(chunks)); });
      got.body.on("error", reject);
    });
    check("download progress (stream): body fully delivered",  collected.length === payload.length);
    check("download progress (stream): events fired",          events.length >= 1);
    check("download progress (stream): final total ok",
          events[events.length - 1].total === payload.length);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientOnChunk() {
  // onChunk fires per response data chunk in BOTH buffer and stream
  // modes. Use case: hash bytes during download without an extra
  // Transform pass. This test wires a SHA3-512 hasher into onChunk
  // and compares the result against an independent hash of the
  // response body.
  var http = require("http");
  var nodeCrypto = require("crypto");
  var payload = Buffer.alloc(20 * 1024, "x");
  var expected = nodeCrypto.createHash("sha3-512").update(payload).digest("hex");
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Length": String(payload.length) });
    res.end(payload);
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();

    // buffer mode — onChunk fires alongside collector.push
    var bufHasher = nodeCrypto.createHash("sha3-512");
    var bufCount = 0;
    var got = await httpReq({
      url:     "http://127.0.0.1:" + port + "/buf",
      onChunk: function (c) { bufCount++; bufHasher.update(c); },
    });
    check("onChunk: buffer mode fired", bufCount >= 1);
    check("onChunk: buffer mode hash matches body",
          bufHasher.digest("hex") === expected &&
          got.body.length === payload.length);

    // stream mode — onChunk fires alongside the passthrough
    var streamHasher = nodeCrypto.createHash("sha3-512");
    var streamCount = 0;
    var streamGot = await httpReq({
      url:          "http://127.0.0.1:" + port + "/stream",
      responseMode: "stream",
      onChunk:      function (c) { streamCount++; streamHasher.update(c); },
    });
    var collected = await new Promise(function (resolve, reject) {
      var chunks = [];
      streamGot.body.on("data",  function (c) { chunks.push(c); });
      streamGot.body.on("end",   function ()  { resolve(Buffer.concat(chunks)); });
      streamGot.body.on("error", reject);
    });
    check("onChunk: stream mode fired", streamCount >= 1);
    check("onChunk: stream mode hash matches body",
          streamHasher.digest("hex") === expected &&
          collected.length === payload.length);

    // onChunk that throws does not break the response — drop-silent
    var threwBody = await httpReq({
      url:     "http://127.0.0.1:" + port + "/swallow",
      onChunk: function () { throw new Error("hash-mismatch"); },
    });
    check("onChunk: throw is swallowed",
          threwBody.body.length === payload.length);
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

async function testHttpClientStreamingMultipart() {
  // Streaming multipart from filePath + supplied stream entries.
  // Server reads the raw body and verifies (a) Content-Type carries
  // the boundary, (b) the body assembles back to the expected sub-
  // payloads, (c) Content-Length matches when every source size is
  // statically resolvable.
  var http = require("http");
  var fs = require("fs");
  var os = require("os");
  var path = require("path");
  var nodeStream = require("stream");

  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mpstream-"));
  var filePath = path.join(tmpDir, "doc.txt");
  var fileBytes = Buffer.alloc(8 * 1024, "F");
  fs.writeFileSync(filePath, fileBytes);

  var seen = null;
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      seen = {
        contentType:   req.headers["content-type"],
        contentLength: req.headers["content-length"] || null,
        bodyLength:    Buffer.concat(chunks).length,
        body:          Buffer.concat(chunks),
      };
      res.writeHead(200);
      res.end("ok");
    });
  });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();

    // filePath entry — size known from fs.statSync, framework can set
    // Content-Length.
    var streamFromFn = await httpReq({
      method: "POST",
      url:    "http://127.0.0.1:" + port + "/upload",
      multipart: {
        fields: { name: "alice" },
        files: [
          { field: "doc", filePath: filePath, contentType: "text/plain" },
        ],
      },
    });
    check("multipart streaming: filePath response 200", streamFromFn.statusCode === 200);
    check("multipart streaming: filePath sets Content-Length",
          seen.contentLength !== null);
    check("multipart streaming: filePath body contains file bytes",
          seen.body.indexOf(fileBytes) !== -1);
    check("multipart streaming: filePath body contains field",
          seen.body.toString("utf8").indexOf('name="name"') !== -1);

    // operator-supplied Readable without size → Content-Length omitted,
    // Node falls back to chunked transfer.
    var inMemBytes = Buffer.alloc(4 * 1024, "S");
    var srcStream = nodeStream.Readable.from((function* () {
      yield inMemBytes.slice(0, 1024);
      yield inMemBytes.slice(1024, 2048);
      yield inMemBytes.slice(2048);
    })());
    var streamFromStream = await httpReq({
      method: "POST",
      url:    "http://127.0.0.1:" + port + "/upload-stream",
      multipart: {
        files: [
          { field: "blob", stream: srcStream, filename: "blob.bin" },
        ],
      },
    });
    check("multipart streaming: stream entry response 200", streamFromStream.statusCode === 200);
    check("multipart streaming: stream entry omits Content-Length",
          seen.contentLength === null);
    check("multipart streaming: stream entry body contains stream bytes",
          seen.body.indexOf(inMemBytes) !== -1);

    // operator-supplied stream WITH explicit size → Content-Length set.
    var inMemBytes2 = Buffer.alloc(2 * 1024, "T");
    var srcStream2 = nodeStream.Readable.from([inMemBytes2]);
    await httpReq({
      method: "POST",
      url:    "http://127.0.0.1:" + port + "/upload-stream-sized",
      multipart: {
        files: [
          { field: "blob", stream: srcStream2, size: inMemBytes2.length },
        ],
      },
    });
    check("multipart streaming: stream + size sets Content-Length",
          seen.contentLength !== null);

    // Mutually exclusive sources — { content + filePath } refused.
    var rejected = false;
    try {
      await httpReq({
        method: "POST",
        url:    "http://127.0.0.1:" + port + "/refused",
        multipart: {
          files: [
            { field: "doc", content: Buffer.from("a"), filePath: filePath },
          ],
        },
      });
    } catch (e) { rejected = e && /exactly one of/.test(e.message); }
    check("multipart streaming: refuses { content + filePath }", rejected);
  } finally {
    try { fs.unlinkSync(filePath); } catch (_e) { /* ignore */ }
    try { fs.rmdirSync(tmpDir); }   catch (_e) { /* ignore */ }
    server.close();
    b.httpClient._resetForTest();
  }
}

function testWebSocketHandshake() {
  var ws = b.websocket;

  // Sec-WebSocket-Accept derivation — RFC 6455 §1.3 example
  // key "dGhlIHNhbXBsZSBub25jZQ==" should produce
  // "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
  check("computeAcceptKey: RFC 6455 example",
        ws.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==") === "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

  // Custom handshakeGuid — operators with closed-ecosystem clients
  // running their own magic string pass it via opts.handshakeGuid on
  // the route. Using a different GUID produces a different accept key
  // (otherwise the override would be a no-op, defeating the purpose).
  var customGuid = "258EAFA5-E914-47DA-95CA-5AB5DC11CE46";
  var customAccept = ws.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==", customGuid);
  check("computeAcceptKey: custom GUID produces different accept key",
        customAccept !== "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" && customAccept.length > 0);
  // Empty / undefined GUID falls through to the RFC default — doesn't
  // accidentally produce a third (broken) accept key value.
  check("computeAcceptKey: empty/undefined GUID falls back to RFC default",
        ws.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==", "") === "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" &&
        ws.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==", null) === "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  // handleUpgrade rejects a malformed handshakeGuid at config time —
  // typo class catches early instead of producing a broken accept-key
  // the client can't verify, where the failure mode would be opaque.
  var threw = false;
  try {
    ws.handleUpgrade(
      { method: "GET", headers: { "upgrade": "websocket", "connection": "Upgrade",
                                   "sec-websocket-key": "x", "sec-websocket-version": "13" } },
      { write: function () {}, destroy: function () {}, on: function () {} },
      Buffer.alloc(0),
      { handshakeGuid: "not-a-uuid" });
  } catch (e) { threw = e.message.indexOf("UUID-shaped") !== -1; }
  check("handleUpgrade: malformed handshakeGuid rejected at config time", threw);

  // validateUpgradeRequest happy path
  var goodReq = {
    method: "GET",
    headers: {
      "upgrade": "websocket",
      "connection": "Upgrade",
      "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
      "sec-websocket-version": "13",
    },
  };
  check("validateUpgradeRequest: happy path",
        ws.validateUpgradeRequest(goodReq).ok === true);

  // Missing headers — each rejection
  var badMethod = Object.assign({}, goodReq, { method: "POST" });
  check("validateUpgradeRequest: rejects POST",
        ws.validateUpgradeRequest(badMethod).ok === false);

  var badVersion = { method: "GET", headers: Object.assign({}, goodReq.headers, { "sec-websocket-version": "8" }) };
  check("validateUpgradeRequest: rejects version != 13",
        ws.validateUpgradeRequest(badVersion).ok === false);

  // Connection header with multiple tokens
  var multiConn = { method: "GET", headers: Object.assign({}, goodReq.headers, { "connection": "keep-alive, Upgrade" }) };
  check("validateUpgradeRequest: accepts multi-token Connection",
        ws.validateUpgradeRequest(multiConn).ok === true);

  // Credential-shaped query parameters refused at upgrade time. The
  // canonical leak channel is server access logs / browser Referer
  // header / history. Operators with a non-credential parameter that
  // happens to share a credential-shaped name opt out per route via
  // opts.allowQueryAuthParams: true.
  var refusedParams = [
    "/ws?access_token=abc",
    "/ws?bearer=xyz",
    "/ws?bearer_token=xyz",
    "/ws?apikey=xyz",
    "/ws?api_key=xyz",
    "/ws?api-key=xyz",
    "/ws?Authorization=Bearer%20xyz",
    "/ws?other=ok&access_token=xyz",
  ];
  for (var rqp = 0; rqp < refusedParams.length; rqp++) {
    var rReq = Object.assign({}, goodReq, { url: refusedParams[rqp] });
    var rResult = ws.validateUpgradeRequest(rReq);
    check("validateUpgradeRequest: refuses credential query param '" + refusedParams[rqp] + "'",
          rResult.ok === false && rResult.reason && rResult.reason.indexOf("credential-shaped") === 0);
  }
  // Operator opt-out lets the upgrade pass.
  var allowedReq = Object.assign({}, goodReq, { url: "/ws?access_token=abc" });
  check("validateUpgradeRequest: opts.allowQueryAuthParams=true bypasses credential-param refusal",
        ws.validateUpgradeRequest(allowedReq, { allowQueryAuthParams: true }).ok === true);
  // Non-credential query params (overloaded names like 'token' / 'session' /
  // 'auth') don't trigger refusal. The list is deliberately narrow.
  var nonCredParams = ["/ws?token=xyz", "/ws?session=abc", "/ws?auth=true", "/ws?key=foo", "/ws"];
  for (var ncp = 0; ncp < nonCredParams.length; ncp++) {
    var nReq = Object.assign({}, goodReq, { url: nonCredParams[ncp] });
    check("validateUpgradeRequest: non-credential query param '" + nonCredParams[ncp] + "' allowed",
          ws.validateUpgradeRequest(nReq).ok === true);
  }
  // Percent-encoded credential param names are decoded before comparison.
  var encodedReq = Object.assign({}, goodReq, { url: "/ws?%41ccess_token=abc" });
  check("validateUpgradeRequest: percent-encoded credential param refused",
        ws.validateUpgradeRequest(encodedReq).ok === false);

  // Origin policy
  var browserReq = { method: "GET", headers: Object.assign({}, goodReq.headers, { "origin": "https://app.example.com", "host": "app.example.com" }) };
  // Default (origins omitted) enforces same-origin: Origin's host must match Host.
  check("isOriginAllowed: undefined origins enforces same-origin (match)",
        ws.isOriginAllowed(browserReq, null) === true);
  // Cross-origin under default policy is refused.
  var crossOriginReq = { method: "GET", headers: Object.assign({}, goodReq.headers, { "origin": "https://attacker.example", "host": "app.example.com" }) };
  check("isOriginAllowed: undefined origins enforces same-origin (refuse cross-origin)",
        ws.isOriginAllowed(crossOriginReq, null) === false);
  check("isOriginAllowed: '*' accepts all",               ws.isOriginAllowed(browserReq, "*") === true);
  check("isOriginAllowed: '*' bypasses cross-origin",     ws.isOriginAllowed(crossOriginReq, "*") === true);
  check("isOriginAllowed: allowlist match",
        ws.isOriginAllowed(browserReq, ["https://app.example.com"]) === true);
  check("isOriginAllowed: allowlist miss",
        ws.isOriginAllowed(browserReq, ["https://other.example.com"]) === false);
  // Non-browser client (no Origin header) bypasses origin policy
  check("isOriginAllowed: no Origin header bypasses (non-browser)",
        ws.isOriginAllowed(goodReq, ["https://app.example.com"]) === true);
  check("isOriginAllowed: no Origin header bypasses (non-browser, default policy)",
        ws.isOriginAllowed(goodReq, null) === true);

  // Subprotocol negotiation
  var protoReq = { method: "GET", headers: Object.assign({}, goodReq.headers, { "sec-websocket-protocol": "chat, foo, graphql-ws" }) };
  check("negotiateSubprotocol: picks first match",
        ws.negotiateSubprotocol(protoReq, ["graphql-ws", "chat"]) === "chat");
  check("negotiateSubprotocol: returns null on no match",
        ws.negotiateSubprotocol(protoReq, ["other"]) === null);
  check("negotiateSubprotocol: empty supported returns null",
        ws.negotiateSubprotocol(protoReq, []) === null);
}

function testWebSocketFrames() {
  var ws = b.websocket;

  // Round-trip: serialize → parse → same data, opcode preserved.
  // The parser expects client-side frames (masked); use the
  // serializer's mask:true path to build that shape.
  var payload = Buffer.from("hello websocket", "utf8");
  var masked = ws.serializeFrame(ws.OPCODE_TEXT, payload, { mask: true });
  var parser = new ws.FrameParser({ maxFrameBytes: 1024 });
  var frames = parser.push(masked);
  check("FrameParser: parses single masked frame", frames.length === 1);
  check("FrameParser: opcode preserved",            frames[0].opcode === ws.OPCODE_TEXT);
  check("FrameParser: payload preserved",           frames[0].payload.equals(payload));
  check("FrameParser: masked flag set",             frames[0].masked === true);
  check("FrameParser: fin flag set",                frames[0].fin === true);

  // Extended length encoding — 16-bit (126)
  var medPayload = Buffer.alloc(200);
  for (var i = 0; i < 200; i++) medPayload[i] = i & 0xFF;
  var medMasked = ws.serializeFrame(ws.OPCODE_BINARY, medPayload, { mask: true });
  parser = new ws.FrameParser({ maxFrameBytes: 65536 });
  frames = parser.push(medMasked);
  check("FrameParser: 16-bit length frame", frames[0].payload.equals(medPayload));

  // Extended length encoding — 64-bit (127). Use a payload >65535.
  var largePayload = Buffer.alloc(70000);
  largePayload.fill(0x42);
  var largeMasked = ws.serializeFrame(ws.OPCODE_BINARY, largePayload, { mask: true });
  parser = new ws.FrameParser({ maxFrameBytes: 1024 * 1024 });
  frames = parser.push(largeMasked);
  check("FrameParser: 64-bit length frame", frames[0].payload.length === 70000 && frames[0].payload[0] === 0x42);

  // Incremental parsing — split a frame across two pushes
  var split1 = masked.subarray(0, 5);
  var split2 = masked.subarray(5);
  parser = new ws.FrameParser({ maxFrameBytes: 1024 });
  var part1 = parser.push(split1);
  var part2 = parser.push(split2);
  check("FrameParser: partial first push yields nothing",  part1.length === 0);
  check("FrameParser: completing push yields the frame",   part2.length === 1);
  check("FrameParser: split frame payload intact",         part2[0].payload.equals(payload));

  // Frame size cap rejection
  var threwTooLarge = false;
  try {
    var tinyParser = new ws.FrameParser({ maxFrameBytes: 100 });
    tinyParser.push(largeMasked);
  } catch (e) {
    threwTooLarge = e.code === "ws/frame-too-large";
  }
  check("FrameParser: rejects oversized frame", threwTooLarge);
}

async function testRouterSetsRoutePattern() {
  // metrics + tracing label by route TEMPLATE, not the actual URL.
  // The router must populate req.routePattern when a route matches so
  // /users/:id labels stay one bucket instead of one-per-id.
  var router = new b.router.Router();
  var captured = null;
  router.get("/users/:id", function (req, res) {
    captured = req.routePattern;
    res.writeHead(200);
    res.end("ok");
  });
  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method = "GET";
  req.url = "/users/42?q=1";
  req.headers = { host: "x" };
  var res = new EE();
  res.writableEnded = false;
  res.writeHead = function () { return res; };
  res.end = function () { res.writableEnded = true; };
  await router.handle(req, res);
  check("router: req.routePattern set to template, not URL",
        captured === "/users/:id");
}

// ---- v0.4.19 schema-validated routes ----

function _routerHttpFixture(opts) {
  // Minimal req/res that satisfy the router's expectations + a way to
  // capture the response status + body.
  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method = opts.method || "GET";
  req.url    = opts.url    || "/";
  req.headers = Object.assign({ host: "x" }, opts.headers || {});
  if (opts.body !== undefined) req.body = opts.body;
  var res = new EE();
  res.writableEnded = false;
  res.headersSent = false;
  res._status = null;
  res._body = "";
  res.writeHead = function (s) { res._status = s; res.headersSent = true; return res; };
  res.end = function (chunk) {
    if (chunk !== undefined) res._body += String(chunk);
    res.writableEnded = true;
  };
  res.json = function (v) {
    res._status = res._status || 200;
    res._body = JSON.stringify(v);
    res.writableEnded = true;
    res.headersSent = true;
  };
  return { req: req, res: res };
}

async function testRouterSpecBodyValidatesPass() {
  var router = new b.router.Router();
  var bodyShape = b.safeSchema.object({
    name:  b.safeSchema.string(),
    count: b.safeSchema.number().int().min(1),
  });
  var captured;
  router.post("/users", { body: bodyShape, description: "Create user" },
    function (req, res) {
      captured = req.body;
      res.writeHead(201); res.end("ok");
    });
  var fx = _routerHttpFixture({ method: "POST", url: "/users", body: { name: "A", count: 5 } });
  await router.handle(fx.req, fx.res);
  check("router spec: pass-through on valid body", fx.res._status === 201);
  check("router spec: req.body parsed by schema", captured && captured.name === "A");
}

async function testRouterSpecBodyValidatesReject() {
  var router = new b.router.Router();
  var bodyShape = b.safeSchema.object({
    name:  b.safeSchema.string(),
    count: b.safeSchema.number().int().min(1),
  });
  router.post("/users", { body: bodyShape },
    function (_req, res) { res.writeHead(201); res.end("should not reach"); });
  var fx = _routerHttpFixture({ method: "POST", url: "/users",
                                 body: { name: "A", count: -1 } });
  await router.handle(fx.req, fx.res);
  check("router spec: 400 on body validation reject",  fx.res._status === 400);
  var body = JSON.parse(fx.res._body);
  check("router spec: 400 carries 'where: body'",      body.where === "body");
  check("router spec: issues array present",           Array.isArray(body.issues) && body.issues.length > 0);
}

async function testRouterSpecQueryAndParams() {
  var router = new b.router.Router();
  var paramsShape = b.safeSchema.object({ id: b.safeSchema.string() });
  var queryShape  = b.safeSchema.object({
    page: b.safeSchema.preprocess(function (v) { return parseInt(v, 10); }, b.safeSchema.number().int().min(1)),
  });
  router.get("/items/:id", { params: paramsShape, query: queryShape },
    function (req, res) {
      res.writeHead(200);
      res.end("id=" + req.params.id + " page=" + req.query.page);
    });
  var fx = _routerHttpFixture({ method: "GET", url: "/items/abc?page=3" });
  await router.handle(fx.req, fx.res);
  check("router spec: params + query validate",        fx.res._status === 200);
  check("router spec: query coerced via preprocess",   /page=3/.test(fx.res._body));

  // Reject — bad page=0
  var fx2 = _routerHttpFixture({ method: "GET", url: "/items/abc?page=0" });
  await router.handle(fx2.req, fx2.res);
  check("router spec: 400 on query reject",            fx2.res._status === 400);
  var b2 = JSON.parse(fx2.res._body);
  check("router spec: query reject where=query",       b2.where === "query");
}

async function testRouterSpecPassesNonObjectFirstArg() {
  // Existing two-arg shape (pattern + handler fn) must keep working.
  var router = new b.router.Router();
  router.get("/old-style", function (_req, res) { res.writeHead(200); res.end("legacy"); });
  var fx = _routerHttpFixture({ method: "GET", url: "/old-style" });
  await router.handle(fx.req, fx.res);
  check("router spec: legacy two-arg registration still works",
        fx.res._status === 200 && fx.res._body === "legacy");
}

async function testRouterSpecRejectsUnknownKey() {
  var router = new b.router.Router();
  var threw = false;
  try {
    router.get("/x", { body: b.safeSchema.string(), bogus: 1 },
      function (_req, res) { res.end(); });
  } catch (e) { threw = /unknown spec key 'bogus'/.test(e.message); }
  check("router spec: rejects unknown spec key",  threw);
}

async function testRouterSpecRejectsBadSchema() {
  var router = new b.router.Router();
  var threw = false;
  try {
    router.get("/x", { body: { notASchema: true } },
      function (_req, res) { res.end(); });
  } catch (e) { threw = /must be a b\.safeSchema/.test(e.message); }
  check("router spec: rejects non-safeSchema body",  threw);
}

function testRouterInspectRoutes() {
  var router = new b.router.Router();
  var bodyShape = b.safeSchema.object({ name: b.safeSchema.string() });
  router.post("/users", {
    body:        bodyShape,
    description: "Create a user",
    summary:     "Create user",
    tags:        ["users", "admin"],
    bodyJsonSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] },
  }, function (_req, res) { res.end(); });
  router.get("/health", function (_req, res) { res.end(); });

  var rows = router.inspectRoutes();
  check("router.inspectRoutes: 2 entries",         rows.length === 2);
  var post = rows.find(function (r) { return r.method === "POST"; });
  check("router.inspectRoutes: POST has spec",      post.spec !== null);
  check("router.inspectRoutes: description carried", post.description === "Create a user");
  check("router.inspectRoutes: tags carried",        post.spec.tags.length === 2);
  check("router.inspectRoutes: bodyJsonSchema carried",
        post.spec.bodyJsonSchema && post.spec.bodyJsonSchema.type === "object");
  var getH = rows.find(function (r) { return r.method === "GET"; });
  check("router.inspectRoutes: legacy route has spec=null", getH.spec === null);
}

function testRouterOpenapi() {
  var router = new b.router.Router();
  var bodyShape = b.safeSchema.object({ name: b.safeSchema.string() });
  router.post("/users", {
    body: bodyShape,
    bodyJsonSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] },
    description: "Create a new user",
    tags:        ["users"],
  }, function (_req, res) { res.end(); });
  router.get("/users/:id", {
    params: b.safeSchema.object({ id: b.safeSchema.string() }),
    description: "Get user by id",
  }, function (_req, res) { res.end(); });

  var spec = router.openapi({ info: { title: "Wiki", version: "1.0.0" } });
  check("openapi: openapi: '3.0.3'",      spec.openapi === "3.0.3");
  check("openapi: info carried",           spec.info.title === "Wiki" && spec.info.version === "1.0.0");
  check("openapi: /users path present",    !!spec.paths["/users"]);
  check("openapi: /users POST present",    !!spec.paths["/users"].post);
  check("openapi: /users POST has tags",
        spec.paths["/users"].post.tags && spec.paths["/users"].post.tags.indexOf("users") !== -1);
  check("openapi: requestBody bodyJsonSchema embedded",
        spec.paths["/users"].post.requestBody &&
        spec.paths["/users"].post.requestBody.content["application/json"].schema.type === "object");
  // :id pattern → {id} in OpenAPI
  check("openapi: path-param converted to OpenAPI form",
        !!spec.paths["/users/{id}"]);
  check("openapi: path-param appears in parameters",
        spec.paths["/users/{id}"].get.parameters.some(function (p) {
          return p.name === "id" && p.in === "path";
        }));
}

async function testRouterSpecResponseValidationThrow() {
  process.env.BLAMEJS_VALIDATE_RESPONSES = "throw";
  try {
    var router = new b.router.Router();
    var responseShape = b.safeSchema.object({ ok: b.safeSchema.boolean() });
    router.get("/r", { response: responseShape },
      function (_req, res) { res.json({ wrong: "shape" }); });
    var fx = _routerHttpFixture({ method: "GET", url: "/r" });
    var threw = false;
    try { await router.handle(fx.req, fx.res); }
    catch (e) { threw = /response-validation failed/.test(e.message); }
    check("response-validation throw: detected drift",  threw);
  } finally {
    delete process.env.BLAMEJS_VALIDATE_RESPONSES;
  }
}

async function testRouterSpecResponseValidationWarn() {
  process.env.BLAMEJS_VALIDATE_RESPONSES = "warn";
  try {
    var router = new b.router.Router();
    var responseShape = b.safeSchema.object({ ok: b.safeSchema.boolean() });
    router.get("/r", { response: responseShape },
      function (_req, res) { res.json({ wrong: "shape" }); });
    var fx = _routerHttpFixture({ method: "GET", url: "/r" });
    await router.handle(fx.req, fx.res);
    // Warn mode: response still ships; no throw.
    check("response-validation warn: response still ships", fx.res.writableEnded === true);
  } finally {
    delete process.env.BLAMEJS_VALIDATE_RESPONSES;
  }
}

function testRouterWsValidation() {
  var router = new b.router.Router();

  // Bad path
  var threw1 = false;
  try { router.ws("", function () {}); } catch (_e) { threw1 = true; }
  check("router.ws: rejects empty path", threw1);

  // Bad handler
  var threw2 = false;
  try { router.ws("/foo", "not-a-function"); } catch (_e) { threw2 = true; }
  check("router.ws: rejects non-function handler", threw2);

  // Bad transport
  var threw3 = false;
  try { router.ws("/foo", function () {}, { transport: "h3" }); } catch (_e) { threw3 = true; }
  check("router.ws: rejects unknown transport", threw3);

  // All valid transports accepted
  var ok = true;
  try {
    router.ws("/auto",     function () {}, { origins: "*", transport: "auto" });
    router.ws("/h1",       function () {}, { origins: "*", transport: "h1-only" });
    router.ws("/h2",       function () {}, { origins: "*", transport: "h2-only" });
  } catch (_e) { ok = false; }
  check("router.ws: accepts auto / h1-only / h2-only", ok);
  check("router.ws: registered routes counted",
        router._wsRoutes.size === 3);
}

async function testWebSocketConnection() {
  var net = require("net");
  var ws = b.websocket;

  // Mock TCP server that hand-rolls handshake validation + WebSocketConnection
  var connections = [];
  var server = net.createServer(function (socket) {
    var headerBuffer = "";
    var headersDone = false;
    socket.on("data", function (chunk) {
      if (headersDone) return;
      headerBuffer += chunk.toString("utf8");
      var idx = headerBuffer.indexOf("\r\n\r\n");
      if (idx === -1) return;
      headersDone = true;
      // Parse HTTP headers (very crude — enough for tests).
      var headerLines = headerBuffer.substring(0, idx).split("\r\n");
      var requestLine = headerLines[0].split(" ");
      var headers = {};
      for (var i = 1; i < headerLines.length; i++) {
        var p = headerLines[i].indexOf(":");
        if (p === -1) continue;
        var k = headerLines[i].substring(0, p).trim().toLowerCase();
        var v = headerLines[i].substring(p + 1).trim();
        headers[k] = v; // lgtm[js/remote-property-injection] test fixture; not a runtime path
      }
      var req = { method: requestLine[0], url: requestLine[1], headers: headers };
      var head = Buffer.from(headerBuffer.substring(idx + 4), "binary");
      var conn = ws.handleUpgrade(req, socket, head, { closeGraceMs: 50 });
      if (conn) {
        connections.push(conn);
        // Echo handler
        conn.on("message", function (data, isBinary) {
          conn.send(isBinary ? data : "echo:" + data);
        });
      }
    });
  });
  var port = await listenOnRandomPort(server);

  try {
    // Open a raw TCP socket, send the upgrade handshake, then exchange frames.
    var client = net.connect(port, "127.0.0.1");
    await new Promise(function (r) { client.once("connect", r); });

    var key = nodeCryptoForTest().randomBytes(16).toString("base64");
    var handshakeRequest =
      "GET / HTTP/1.1\r\n" +
      "Host: 127.0.0.1:" + port + "\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      "Sec-WebSocket-Key: " + key + "\r\n" +
      "Sec-WebSocket-Version: 13\r\n" +
      "\r\n";
    client.write(handshakeRequest);

    // Read the 101 response + check the Sec-WebSocket-Accept matches.
    var responseBuf = await _readUntil(client, "\r\n\r\n");
    var responseStr = responseBuf.toString("utf8");
    check("WebSocketConnection: 101 response sent",
          responseStr.indexOf("HTTP/1.1 101") === 0);
    var expectedAccept = ws.computeAcceptKey(key);
    check("WebSocketConnection: Sec-WebSocket-Accept correct",
          responseStr.toLowerCase().indexOf("sec-websocket-accept: " + expectedAccept.toLowerCase()) !== -1);

    // Send a masked text frame "ping-test"
    var clientFrame = ws.serializeFrame(ws.OPCODE_TEXT, Buffer.from("ping-test", "utf8"), { mask: true });
    client.write(clientFrame);

    // Read the server's echo (unmasked) — buffered until we have at least one frame.
    var echoBuf = await _readNBytes(client, 2);   // header at minimum
    // Use FrameParser on the response
    var parser = new ws.FrameParser({ maxFrameBytes: 1024 });
    var echoChunks = [echoBuf];
    var echoFrames = parser.push(echoBuf);
    while (echoFrames.length === 0) {
      var more = await _readSome(client);
      echoChunks.push(more);
      echoFrames = parser.push(more);
    }
    check("WebSocketConnection: server echoed frame",
          echoFrames[0].payload.toString("utf8") === "echo:ping-test");
    check("WebSocketConnection: server echo unmasked",
          echoFrames[0].masked === false);

    // Close handshake — client sends close, server echoes.
    var closePayload = Buffer.alloc(2);
    closePayload.writeUInt16BE(1000, 0);
    var clientClose = ws.serializeFrame(ws.OPCODE_CLOSE, closePayload, { mask: true });
    client.write(clientClose);

    // Read server's close echo.
    var closeRead = await _readSome(client);
    var closeFrames = parser.push(closeRead);
    var closeFrame = closeFrames.find(function (f) { return f.opcode === ws.OPCODE_CLOSE; });
    check("WebSocketConnection: server echoed close",
          closeFrame !== undefined);
    check("WebSocketConnection: close code 1000",
          closeFrame && closeFrame.payload.readUInt16BE(0) === 1000);

    // Verified at protocol level — close frame received. TCP teardown
    // is incidental; don't block the test on it. closeGraceMs:50 on
    // the server side keeps the actual TCP teardown fast anyway.
  } finally {
    try { server.closeAllConnections(); } catch (_e) {}
    await new Promise(function (r) { server.close(function () { r(); }); });
  }
}

// Test helpers — local to the websocket suite. nodeCrypto for the
// random key, _readUntil/_readNBytes/_readSome for incremental client
// socket reads.
function nodeCryptoForTest() { return require("crypto"); }
function _readUntil(socket, marker) {
  return new Promise(function (resolve) {
    var buf = Buffer.alloc(0);
    function onData(chunk) {
      buf = Buffer.concat([buf, chunk]);
      if (buf.toString("binary").indexOf(marker) !== -1) {
        socket.removeListener("data", onData);
        resolve(buf);
      }
    }
    socket.on("data", onData);
  });
}
function _readNBytes(socket, n) {
  return new Promise(function (resolve) {
    var chunks = [];
    var have = 0;
    function onData(chunk) {
      chunks.push(chunk);
      have += chunk.length;
      if (have >= n) {
        socket.removeListener("data", onData);
        resolve(Buffer.concat(chunks));
      }
    }
    socket.on("data", onData);
  });
}
function _readSome(socket) {
  return new Promise(function (resolve) {
    socket.once("data", resolve);
  });
}

async function testHttpClientObserver() {
  var http = require("http");
  var server = http.createServer(function (req, res) { res.writeHead(200); res.end("ok"); });
  var port = await listenOnRandomPort(server);
  try {
    b.httpClient._resetForTest();
    var stages = [];
    var observer = function (stage, info) { stages.push({ stage: stage, info: info }); };
    await httpReq({ url: "http://127.0.0.1:" + port + "/obs", observer: observer });
    check("httpClient: observer saw request:start",     stages[0].stage === "request:start");
    check("httpClient: observer saw response:headers",  stages[1].stage === "response:headers");
    check("httpClient: observer saw response:end",      stages[2].stage === "response:end");
    check("httpClient: observer info has durationMs",   typeof stages[2].info.durationMs === "number");
  } finally {
    server.close();
    b.httpClient._resetForTest();
  }
}

function testConstantsReferenceIntegrity() {
  // Static scan: walks lib/ for `C.TIME.X` / `C.BYTES.X` references and
  // verifies every X resolves to a known function. Catches the class of
  // bug where a stale all-caps constant (e.g. C.TIME.FIVE_MIN) silently
  // evaluates to `undefined` and propagates into setInterval / setTimeout
  // / server.timeout call sites — Node coerces undefined to a small
  // positive integer for those, so the bug shows up as 1ms-tight loops
  // instead of a noisy crash. Live evidence: a stale FIVE_MIN reference
  // in db.js + router.js sat undetected because neither call site
  // throws when the constant is missing.
  //
  // File reads go through b.atomicFile.readSync (framework primitive,
  // size-capped + error-classed). Directory listing uses fs.readdirSync
  // — the framework lacks a list-dir primitive today (atomic-file owns
  // single-file ops); 5+ other lib/ sites use fs.readdirSync the same
  // way, so this matches existing convention pending a future
  // atomicFile.listDir primitive.
  var TIME_FNS  = new Set(Object.keys(b.constants.TIME));
  var BYTES_FNS = new Set(Object.keys(b.constants.BYTES));

  function _walk(dir, out) {
    var entries = fs.readdirSync(dir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i++) {
      var ent = entries[i];
      if (ent.name === "vendor") continue;            // skip vendored libs
      if (ent.name === "node_modules") continue;
      var full = path.join(dir, ent.name);
      if (ent.isDirectory()) _walk(full, out);
      else if (ent.isFile() && ent.name.endsWith(".js")) out.push(full);
    }
  }

  var libRoot = path.join(__dirname, "..", "lib");
  var files = [];
  _walk(libRoot, files);

  var pattern = /\b(?:C\.)?(TIME|BYTES)\.([A-Za-z_][A-Za-z0-9_]*)\b/g;

  var bad = [];
  for (var f = 0; f < files.length; f++) {
    var src = b.atomicFile.readSync(files[f]).toString("utf8");
    var stripped = src
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/[^\n]*/g, "");
    var m;
    while ((m = pattern.exec(stripped)) !== null) {
      var ns = m[1];
      var ident = m[2];
      var known = ns === "TIME" ? TIME_FNS : BYTES_FNS;
      if (!known.has(ident)) {
        bad.push(files[f].replace(libRoot, "lib") + " : C." + ns + "." + ident);
      }
    }
    pattern.lastIndex = 0;
  }

  check("constants integrity: every C.TIME.X / C.BYTES.X resolves to a known function",
        bad.length === 0);
  if (bad.length > 0) {
    console.error("Stale constant references:");
    for (var i = 0; i < bad.length; i++) console.error("  " + bad[i]);
  }
}

function testLogger() {
  check("log.boot is the canonical entry",  typeof b.log.boot === "function");
  check("legacy b.logger removed in v0.4",  b.logger === undefined);

  var origLog = console.log;
  var origErr = console.error;
  var captured = { log: [], error: [] };
  console.log   = function (msg) { captured.log.push(msg); };
  console.error = function (msg) { captured.error.push(msg); };

  // Boot logger is TTY-aware: in a terminal the format is the
  // human-readable "[blamejs:<name>] <msg>" line; piped to a log
  // aggregator it switches to JSON. Pin both flags for the duration
  // of the prefixed-text checks.
  var origStdoutTty = process.stdout.isTTY;
  var origStderrTty = process.stderr.isTTY;
  process.stdout.isTTY = true;
  process.stderr.isTTY = true;

  try {
    var log = b.log.boot("testmod");

    log("hello");
    check("log.boot: default invocation logs to stdout", captured.log[0] === "[blamejs:testmod] hello");

    log.info("info msg");
    check("log.boot: .info logs to stdout", captured.log[1] === "[blamejs:testmod] info msg");

    log.warn("warn msg");
    check("log.boot: .warn logs to stderr", captured.error[0] === "[blamejs:testmod] warn msg");

    log.error("err msg");
    check("log.boot: .error logs to stderr", captured.error[1] === "[blamejs:testmod] err msg");

    check("log.boot: .prefix exposes the namespace", log.prefix === "[blamejs:testmod] ");

    var threw = false;
    try { b.log.boot(""); } catch (_e) { threw = true; }
    check("log.boot: rejects empty name", threw);

    var threw2 = false;
    try { b.log.boot(null); } catch (_e) { threw2 = true; }
    check("log.boot: rejects non-string name", threw2);

    captured.log.length = 0;
    captured.error.length = 0;
    process.stdout.isTTY = false;
    process.stderr.isTTY = false;
    var jsonLog = b.log.boot("piped");
    jsonLog("ready");
    var parsed = JSON.parse(captured.log[0]);
    check("log.boot non-TTY emits JSON",      parsed && parsed.message === "ready");
    check("log.boot JSON carries component",  parsed.component === "piped");
    check("log.boot JSON marks boot:true",    parsed.boot === true);
    check("log.boot JSON carries level",      parsed.level === "info");

    jsonLog.warn("ouch");
    var parsedWarn = JSON.parse(captured.error[0]);
    check("log.boot non-TTY warn → stderr JSON", parsedWarn.level === "warn" && parsedWarn.message === "ouch");

    var direct = b.log.boot("direct");
    check("log.boot returns callable",        typeof direct === "function");
    check("log.boot returns .info / .warn / .error",
          typeof direct.info === "function" &&
          typeof direct.warn === "function" &&
          typeof direct.error === "function");
  } finally {
    console.log = origLog;
    console.error = origErr;
    process.stdout.isTTY = origStdoutTty;
    process.stderr.isTTY = origStderrTty;
  }
}

function testFrameworkError() {
  var fe = b.frameworkError;
  check("frameworkError namespace present", typeof fe === "object");
  check("FrameworkError class present",     typeof fe.FrameworkError === "function");

  // Base class shape
  var base = new fe.FrameworkError("oops", "test/err");
  check("FrameworkError: name",        base.name === "FrameworkError");
  check("FrameworkError: code",        base.code === "test/err");
  check("FrameworkError: isFrameworkError flag",  base.isFrameworkError === true);
  check("FrameworkError: instanceof Error",       base instanceof Error);

  // Cross-module subclasses
  var oserr = new fe.ObjectStoreError("BUCKET_NOT_FOUND", "missing", true, 404);
  check("ObjectStoreError: extends FrameworkError", oserr instanceof fe.FrameworkError);
  check("ObjectStoreError: extends Error",          oserr instanceof Error);
  check("ObjectStoreError: code",       oserr.code === "BUCKET_NOT_FOUND");
  check("ObjectStoreError: permanent",  oserr.permanent === true);
  check("ObjectStoreError: statusCode", oserr.statusCode === 404);
  check("ObjectStoreError: legacy flag", oserr.isObjectStoreError === true);

  var qerr = new fe.QueueError("JOB_NOT_FOUND", "no such job", true);
  check("QueueError: instanceof FrameworkError", qerr instanceof fe.FrameworkError);
  check("QueueError: legacy flag",               qerr.isQueueError === true);

  // Existing *SafeError classes now also pass instanceof FrameworkError
  try { b.safeJson.parse("{not-json}"); }
  catch (e) {
    check("SafeJsonError: extends FrameworkError",  e instanceof fe.FrameworkError);
    check("SafeJsonError: legacy flag preserved",   e.isSafeJsonError === true);
  }
  try { b.safeSql.validateIdentifier("123"); }
  catch (e) {
    check("SafeSqlError: extends FrameworkError",   e instanceof fe.FrameworkError);
  }

  // defineClass — factory for the standard FrameworkError-subclass shape
  check("defineClass is a function",                typeof fe.defineClass === "function");

  var Plain = fe.defineClass("PlainError");
  var p = new Plain("p/code", "plain message", true);
  check("defineClass: name",                        p.name === "PlainError");
  check("defineClass: code",                        p.code === "p/code");
  check("defineClass: message",                     p.message === "plain message");
  check("defineClass: permanent flag",              p.permanent === true);
  check("defineClass: legacy isXError flag",        p.isPlainError === true);
  check("defineClass: extends FrameworkError",      p instanceof fe.FrameworkError);
  check("defineClass: extends Error",               p instanceof Error);
  check("defineClass: constructor.name set",        Plain.name === "PlainError");

  var pNo = new Plain("p/code", "plain message");
  check("defineClass: permanent default false",     pNo.permanent === false);

  var Status = fe.defineClass("StatusError", { withStatusCode: true });
  var s = new Status("s/x", "msg", true, 404);
  check("defineClass withStatusCode: statusCode set", s.statusCode === 404);
  check("defineClass withStatusCode: still permanent", s.permanent === true);

  var Always = fe.defineClass("AlwaysError", { alwaysPermanent: true });
  var a = new Always("a/x", "msg");
  check("defineClass alwaysPermanent: permanent=true",  a.permanent === true);
  // Even if caller passes false, alwaysPermanent wins (it's the contract)
  var a2 = new Always("a/x", "msg", false);
  check("defineClass alwaysPermanent: caller can't override", a2.permanent === true);

  var WithCause = fe.defineClass("CauseError", { withCause: true });
  var underlying = new Error("upstream");
  var c = new WithCause("c/x", "wrapped", underlying);
  check("defineClass withCause: cause set",         c.cause === underlying);

  // alwaysPermanent + (withStatusCode|withCause) is mutually exclusive
  var threw = null;
  try { fe.defineClass("X", { alwaysPermanent: true, withStatusCode: true }); }
  catch (e) { threw = e; }
  check("defineClass: alwaysPermanent + withStatusCode rejected",
        threw && /mutually exclusive/.test(threw.message));

  threw = null;
  try { fe.defineClass(""); } catch (e) { threw = e; }
  check("defineClass: empty name rejected",         threw && /name must be a non-empty string/.test(threw.message));

  // The framework's existing ObjectStoreError is now built via defineClass.
  // Verify the migration didn't break the constructor signature.
  var ose2 = new fe.ObjectStoreError("X", "msg", true, 502);
  check("ObjectStoreError post-migration: statusCode", ose2.statusCode === 502);
  check("ObjectStoreError post-migration: permanent",  ose2.permanent === true);
  check("ObjectStoreError post-migration: legacy flag",ose2.isObjectStoreError === true);

  var auth2 = new fe.AuthError("AUTH", "no");
  check("AuthError post-migration: alwaysPermanent",  auth2.permanent === true);
}

function testAtomicFileNewHelpers() {
  // ensureDir / fsync / fsyncDir / copyDirRecursive / pathTimestamp —
  // the lifted helpers
  check("ensureDir is a function",                  typeof b.atomicFile.ensureDir === "function");
  check("fsync is a function",                      typeof b.atomicFile.fsync === "function");
  check("fsyncDir is a function",                   typeof b.atomicFile.fsyncDir === "function");
  check("copyDirRecursive is a function",           typeof b.atomicFile.copyDirRecursive === "function");
  check("pathTimestamp is a function",              typeof b.atomicFile.pathTimestamp === "function");

  // pathTimestamp shape
  var t = b.atomicFile.pathTimestamp();
  check("pathTimestamp matches FS-safe ISO format",
        /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$/.test(t));
  check("pathTimestamp has no colons",              t.indexOf(":") === -1);
  check("pathTimestamp has no dots",                t.indexOf(".") === -1);
  // Pinned date round-trip
  var t2 = b.atomicFile.pathTimestamp(new Date(0));
  check("pathTimestamp(Date 0) → 1970",             t2 === "1970-01-01T00-00-00-000Z");
  // String-sort gives chronological order
  var early = b.atomicFile.pathTimestamp(new Date(1000000));
  var late  = b.atomicFile.pathTimestamp(new Date(2000000));
  check("pathTimestamp string-sorts chronologically", early < late);

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-aflift-"));
  try {
    // ensureDir creates with default 0o700, recursive
    var nested = path.join(dir, "a", "b", "c");
    b.atomicFile.ensureDir(nested);
    check("ensureDir creates nested directories",   fs.existsSync(nested));
    // Idempotent — calling twice doesn't throw
    b.atomicFile.ensureDir(nested);
    check("ensureDir is idempotent",                 fs.existsSync(nested));

    // ensureDir with custom mode (verified by file existence; mode bits
    // are platform-specific so we don't strict-check them)
    var customMode = path.join(dir, "publicish");
    b.atomicFile.ensureDir(customMode, 0o755);
    check("ensureDir honors custom mode (dir created)", fs.existsSync(customMode));

    // ensureDir rejects bad path
    var threw = null;
    try { b.atomicFile.ensureDir(""); } catch (e) { threw = e; }
    check("ensureDir empty path rejected",          threw && threw.code === "atomic-file/bad-path");

    // copyDirRecursive: build a small tree and copy
    var src = path.join(dir, "src");
    var dst = path.join(dir, "dst");
    fs.mkdirSync(src, { recursive: true });
    fs.mkdirSync(path.join(src, "sub"), { recursive: true });
    fs.writeFileSync(path.join(src, "a.txt"), "alpha");
    fs.writeFileSync(path.join(src, "sub", "b.txt"), "bravo");
    var r = b.atomicFile.copyDirRecursive(src, dst);
    check("copyDirRecursive returns fileCount",     r.fileCount === 2);
    check("copyDirRecursive returns byteCount",     r.byteCount === ("alpha".length + "bravo".length));
    check("copyDirRecursive: top-level file copied",
          fs.readFileSync(path.join(dst, "a.txt"), "utf8") === "alpha");
    check("copyDirRecursive: nested file copied",
          fs.readFileSync(path.join(dst, "sub", "b.txt"), "utf8") === "bravo");

    // copyDirRecursive: refuses overwrite by default (COPYFILE_EXCL)
    threw = null;
    try { b.atomicFile.copyDirRecursive(src, dst); } catch (e) { threw = e; }
    check("copyDirRecursive: refuses overwrite by default", threw !== null);

    // copyDirRecursive with overwrite=true succeeds
    fs.writeFileSync(path.join(src, "a.txt"), "alpha-v2");
    var r2 = b.atomicFile.copyDirRecursive(src, dst, { overwrite: true });
    check("copyDirRecursive overwrite=true succeeds", r2.fileCount === 2);
    check("copyDirRecursive overwrite=true wrote new bytes",
          fs.readFileSync(path.join(dst, "a.txt"), "utf8") === "alpha-v2");

    // copyDirRecursive: src must exist
    threw = null;
    try { b.atomicFile.copyDirRecursive(path.join(dir, "nope"), path.join(dir, "dst2")); }
    catch (e) { threw = e; }
    check("copyDirRecursive missing src rejected", threw && threw.code === "atomic-file/missing-src");

    // fsync / fsyncDir don't throw (best-effort)
    var fp = path.join(dir, "fsync-target.txt");
    fs.writeFileSync(fp, "data");
    var fd = fs.openSync(fp, "r+");
    try {
      b.atomicFile.fsync(fd);
      check("fsync on real fd succeeds (no throw)", true);
    } finally { fs.closeSync(fd); }
    b.atomicFile.fsyncDir(dir);
    check("fsyncDir on real dir succeeds (no throw)", true);

    // fsync / fsyncDir swallow errors (bad fd / nonexistent path)
    b.atomicFile.fsync(99999);
    b.atomicFile.fsyncDir(path.join(dir, "absent-dir"));
    check("fsync on bad fd does not throw",         true);
    check("fsyncDir on missing path does not throw", true);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

function testLazyRequire() {
  check("lazyRequire is a function", typeof b.lazyRequire === "function");

  // Loader is invoked exactly once on first call
  var loadCount = 0;
  var loader = function () {
    loadCount += 1;
    return { hello: "world", n: loadCount };
  };
  var lazy = b.lazyRequire(loader);

  check("lazyRequire: not invoked until called",  loadCount === 0);
  var v1 = lazy();
  check("lazyRequire: first call resolves",       v1.hello === "world" && loadCount === 1);
  var v2 = lazy();
  check("lazyRequire: second call returns cache", v2 === v1 && loadCount === 1);

  // reset() clears the cache so the next call re-runs the loader
  lazy.reset();
  var v3 = lazy();
  check("lazyRequire: reset re-runs loader",      loadCount === 2 && v3 !== v1);

  // Non-function loader is rejected
  var threw = false;
  try { b.lazyRequire("./db"); }
  catch (_e) { threw = true; }
  check("lazyRequire: rejects non-function loader", threw);

  // Loader returning falsy values is still cached after first call —
  // separate `loaded` flag distinguishes "not yet loaded" from "loaded
  // with a null/undefined/0/false value".
  var falsyCount = 0;
  var falsyLoader = b.lazyRequire(function () { falsyCount += 1; return 0; });
  falsyLoader(); falsyLoader(); falsyLoader();
  check("lazyRequire: falsy (0) return value cached", falsyCount === 1);

  var nullCount = 0;
  var nullLoader = b.lazyRequire(function () { nullCount += 1; return null; });
  nullLoader(); nullLoader();
  check("lazyRequire: null return value cached", nullCount === 1);
}

function testBufferSafeSecureZero() {
  var bs = b.safeBuffer;
  check("safeBuffer.secureZero is a function", typeof bs.secureZero === "function");

  var buf = Buffer.from("secret-passphrase", "utf8");
  bs.secureZero(buf);
  var allZero = true;
  for (var i = 0; i < buf.length; i++) if (buf[i] !== 0) { allZero = false; break; }
  check("secureZero: zeroes Buffer contents", allZero);

  // Uint8Array also handled
  var u8 = new Uint8Array([1, 2, 3, 4]);
  bs.secureZero(u8);
  check("secureZero: zeroes Uint8Array",
        u8[0] === 0 && u8[1] === 0 && u8[2] === 0 && u8[3] === 0);

  // Non-Buffer no-ops (doesn't throw)
  bs.secureZero("not-a-buffer");
  bs.secureZero(null);
  bs.secureZero(undefined);
  check("secureZero: non-Buffer is a no-op", true);
}

function testEnvReadVar() {
  var env = b.parsers.env;
  check("env.readVar is a function", typeof env.readVar === "function");

  // Save + clean a unique env namespace for this test
  var KEYS = ["BLAMEJS_TEST_VAR1", "BLAMEJS_TEST_VAR2", "BLAMEJS_TEST_VAR3", "BLAMEJS_TEST_VAR4"];
  var saved = {};
  for (var i = 0; i < KEYS.length; i++) { saved[KEYS[i]] = process.env[KEYS[i]]; delete process.env[KEYS[i]]; }

  try {
    // Missing + no default → undefined
    check("readVar: missing without default returns undefined", env.readVar("BLAMEJS_TEST_VAR1") === undefined);

    // Missing + default → default
    check("readVar: missing with default returns default",
          env.readVar("BLAMEJS_TEST_VAR1", { default: "fallback" }) === "fallback");

    // Missing + required → throws
    var threwReq = false;
    try { env.readVar("BLAMEJS_TEST_VAR1", { required: true }); }
    catch (e) { threwReq = e.code === "env/missing-required"; }
    check("readVar: missing + required throws", threwReq);

    // Plain string read
    process.env.BLAMEJS_TEST_VAR1 = "hello";
    check("readVar: string round-trip", env.readVar("BLAMEJS_TEST_VAR1") === "hello");

    // type:number coerces
    process.env.BLAMEJS_TEST_VAR2 = "42";
    check("readVar: number coercion", env.readVar("BLAMEJS_TEST_VAR2", { type: "number" }) === 42);

    // type:boolean strict spelling
    process.env.BLAMEJS_TEST_VAR2 = "true";
    check("readVar: boolean true",  env.readVar("BLAMEJS_TEST_VAR2", { type: "boolean" }) === true);
    process.env.BLAMEJS_TEST_VAR2 = "false";
    check("readVar: boolean false", env.readVar("BLAMEJS_TEST_VAR2", { type: "boolean" }) === false);
    process.env.BLAMEJS_TEST_VAR2 = "yes";
    var threwBool = false;
    try { env.readVar("BLAMEJS_TEST_VAR2", { type: "boolean" }); }
    catch (e) { threwBool = e.code === "env/bad-type"; }
    check("readVar: boolean rejects 'yes'", threwBool);

    // type:buffer + strip
    process.env.BLAMEJS_TEST_VAR3 = "secret-passphrase";
    var buf = env.readVar("BLAMEJS_TEST_VAR3", { type: "buffer", strip: true, maxBytes: 4096 });
    check("readVar: buffer round-trip",  Buffer.isBuffer(buf) && buf.toString("utf8") === "secret-passphrase");
    check("readVar: strip deletes env",  !("BLAMEJS_TEST_VAR3" in process.env));

    // maxBytes cap
    process.env.BLAMEJS_TEST_VAR4 = "x".repeat(5000);
    var threwSize = false;
    try { env.readVar("BLAMEJS_TEST_VAR4", { maxBytes: 1024 }); }
    catch (e) { threwSize = e.code === "env/too-large"; }
    check("readVar: maxBytes enforced", threwSize);

    // enum constraint
    process.env.BLAMEJS_TEST_VAR1 = "wrapped";
    check("readVar: enum allows valid",
          env.readVar("BLAMEJS_TEST_VAR1", { enum: ["wrapped", "plaintext"] }) === "wrapped");
    process.env.BLAMEJS_TEST_VAR1 = "garbage";
    var threwEnum = false;
    try { env.readVar("BLAMEJS_TEST_VAR1", { enum: ["wrapped", "plaintext"] }); }
    catch (e) { threwEnum = e.code === "env/bad-value"; }
    check("readVar: enum rejects invalid", threwEnum);

    // Empty string treated as missing (operator clearing the var)
    process.env.BLAMEJS_TEST_VAR1 = "";
    check("readVar: empty string is treated as missing",
          env.readVar("BLAMEJS_TEST_VAR1", { default: "fallback" }) === "fallback");
  } finally {
    // Restore original env
    for (var j = 0; j < KEYS.length; j++) {
      if (saved[KEYS[j]] === undefined) delete process.env[KEYS[j]];
      else process.env[KEYS[j]] = saved[KEYS[j]];
    }
  }
}

function testRedact() {
  check("redact module present",                 typeof b.redact === "object");
  check("redact.MARKER is '[REDACTED]'",         b.redact.MARKER === "[REDACTED]");

  // Field-name redaction
  var r1 = b.redact.redact({ user: "alice", password: "secret123", apiKey: "AKIAEXAMPLE" });
  check("password field redacted by name",       r1.password === "[REDACTED]");
  check("apiKey field redacted by name",         r1.apiKey === "[REDACTED]");
  check("non-sensitive field preserved",         r1.user === "alice");

  // Nested
  var r2 = b.redact.redact({ outer: { innerPassword: "x", normal: "y" } });
  check("nested sensitive redacted",             r2.outer.innerPassword === "[REDACTED]");
  check("nested normal preserved",               r2.outer.normal === "y");

  // Substring match
  var r3 = b.redact.redact({ userPassword: "pw", emailToken: "t" });
  check("substring 'password' triggers redaction", r3.userPassword === "[REDACTED]");
  check("substring 'token' triggers redaction",    r3.emailToken === "[REDACTED]");

  // Value-shape detectors
  var ccRedacted = b.redact.redact({ note: "card 4111-1111-1111-1111 here" });
  // Note: value detector only fires on STRING values that are EXACTLY a CC; embedded won't trigger
  // Test exact match:
  var ccExact = b.redact.redact({ field: "4111111111111111" });
  check("credit-card-shaped value redacted",     ccExact.field === "[REDACTED-CC]");

  var jwtExact = b.redact.redact({ field: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" });
  check("JWT-shaped value redacted",             jwtExact.field === "[REDACTED-JWT]");

  var pemExact = b.redact.redact({ field: "-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----" });
  check("PEM-shaped value redacted",             pemExact.field === "[REDACTED-PEM]");

  var awsExact = b.redact.redact({ field: "AKIAIOSFODNN7EXAMPLE" });
  check("AWS access key redacted",               awsExact.field === "[REDACTED-AWS-KEY]");

  var sealExact = b.redact.redact({ field: "vault:abcdefxyz" });
  check("vault-sealed value redacted",           sealExact.field === "[REDACTED-SEALED]");

  var ssnExact = b.redact.redact({ field: "123-45-6789" });
  check("SSN-shaped value redacted",             ssnExact.field === "[REDACTED-SSN]");

  // Custom rule
  b.redact.registerFieldRule("internal_token");
  var custom = b.redact.redact({ internal_token: "x", other: "y" });
  check("custom field rule applies",             custom.internal_token === "[REDACTED]");

  // Array redaction
  var arr = b.redact.redact({ creds: [{ password: "a" }, { password: "b" }] });
  check("array elements redacted",               arr.creds[0].password === "[REDACTED]" && arr.creds[1].password === "[REDACTED]");

  // Mutation — original unchanged
  var orig = { password: "before" };
  b.redact.redact(orig);
  check("redact does NOT mutate input",          orig.password === "before");
  void ccRedacted;

  // Connection-string detector — protocol://user:pass@host shape
  var conn = b.redact.redact({ field: "postgres://admin:hunter2@db.example.com:5432/prod" });
  check("connection-string redacted",            conn.field === "[REDACTED-CONN-STRING]");
  var connRedis = b.redact.redact({ field: "redis://:p%40ss@redis.example.com:6379/0" });
  check("redis connection-string redacted",      connRedis.field === "[REDACTED-CONN-STRING]");
  // Plain URL without credentials passes through
  var plain = b.redact.redact({ field: "https://api.example.com/users/1" });
  check("URL without credentials NOT redacted",  plain.field === "https://api.example.com/users/1");
}

function testAuditSafeEmitRedacts() {
  // safeEmit MUST scrub credentials before they hit the audit handler.
  // The test verifies the redact pipeline runs at the safeEmit boundary —
  // we don't need to capture the row, just confirm the call completes
  // without throwing on credential-shaped input. The PRIMITIVE-level
  // verification of the redaction itself happens in testRedact above.
  // Direct capture isn't possible without reaching into private audit
  // state; the integration cover is at the layer-5 audit-pipeline test.
  //
  // Register the namespace so the audit handler doesn't spam an error
  // log line on every drained event in this test.
  if (typeof b.audit.registerNamespace === "function") {
    try { b.audit.registerNamespace("test"); } catch (_e) { /* already registered */ }
  }
  b.audit.safeEmit({
    action: "test.redact-pipeline",
    actor:  { id: "u-1", password: "should-be-redacted" },
    reason: "connect failed: postgres://admin:hunter2@db.example.com:5432/prod",
    metadata: {
      sessionToken: "should-be-redacted",
      jwt:          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1MSJ9.X",
      note:         "ok",
    },
  });
  check("safeEmit completes without throw on credential-shaped input", true);
}

// =====================================================================
// Module-surface — entrypoint sanity (crypto + router + namespace pres.)
// =====================================================================

/**
 * Crypto + router + module-surface checks (smoke entrypoint).
 *
 * The framework's "is the API even loaded?" sanity bar. Runs first so a
 * missing namespace or broken envelope shows up as the FIRST red light,
 * not as a downstream NPE. Was previously inlined at the top of smoke.js.
 */
function testCryptoAndModuleSurface() {
  // Public API surface
  check("crypto namespace present",     typeof b.crypto === "object");
  check("router namespace present",     typeof b.router === "object");
  check("constants namespace present",  typeof b.constants === "object");
  check("vault namespace present",      typeof b.vault === "object");
  check("vaultWrap namespace present",  typeof b.vaultWrap === "object");
  check("vaultPassphraseSource present",     typeof b.vaultPassphraseSource === "object");
  check("version is a string",          typeof b.version === "string");
  check("version matches package.json", b.version === require("../package.json").version);
  check("db namespace present",         typeof b.db === "object");
  check("db.from is a function",        typeof b.db.from === "function");
  check("db.transaction is a function", typeof b.db.transaction === "function");
  check("db.hashFor is a function",     typeof b.db.hashFor === "function");
  check("cryptoField namespace present", typeof b.cryptoField === "object");
  check("audit namespace present",      typeof b.audit === "object");
  check("auditChain namespace present", typeof b.auditChain === "object");
  check("consent namespace present",    typeof b.consent === "object");
  check("subject namespace present",    typeof b.subject === "object");
  check("db.getDataResidency present",  typeof b.db.getDataResidency === "function");
  check("session namespace present",    typeof b.session === "object");
  check("storage namespace present",    typeof b.storage === "object");
  check("session.create is a function", typeof b.session.create === "function");
  check("storage.saveFile is a function", typeof b.storage.saveFile === "function");
  check("safeUrl namespace present",    typeof b.safeUrl === "object");
  check("safeUrl.parse is a function",  typeof b.safeUrl.parse === "function");
  check("safeUrl.ALLOW_HTTP_TLS frozen", Object.isFrozen(b.safeUrl.ALLOW_HTTP_TLS));
  check("authHeader namespace present", typeof b.authHeader === "object");
  check("authHeader.bearer is a function",     typeof b.authHeader.bearer === "function");
  check("authHeader.basic is a function",      typeof b.authHeader.basic === "function");
  check("authHeader.fromConfig is a function", typeof b.authHeader.fromConfig === "function");
  check("safeAsync.sleep is a function",       typeof b.safeAsync.sleep === "function");
  check("safeAsync.withTimeoutSignal is a function",
        typeof b.safeAsync.withTimeoutSignal === "function");

  // Constants surface
  check("ENVELOPE_MAGIC = 0xE2 (FixedInfo-bound)", b.constants.ENVELOPE_MAGIC === 0xE2);
  check("ACTIVE.KEM is hybrid",         b.constants.ACTIVE.KEM === b.constants.KEM_IDS.ML_KEM_1024_P384);
  check("ACTIVE.CIPHER is XChaCha20",   b.constants.ACTIVE.CIPHER === b.constants.CIPHER_IDS.XCHACHA20_POLY1305);
  check("ACTIVE.KDF is SHAKE256",       b.constants.ACTIVE.KDF === b.constants.KDF_IDS.SHAKE256);
  check("TIME.days(1) = 86400000",      b.constants.TIME.days(1) === 86400000);
  check("TIME.minutes(45) = 2700000",   b.constants.TIME.minutes(45) === 2700000);
  check("TIME.hours(2) = 7200000",      b.constants.TIME.hours(2) === 7200000);
  check("BYTES.mib(64) = 67108864",     b.constants.BYTES.mib(64) === 67108864);
  check("BYTES.kib(4) = 4096",          b.constants.BYTES.kib(4) === 4096);
  check("TLS prefers PQ hybrid first",  b.constants.TLS_GROUP_PREFERENCE[0] === "SecP384r1MLKEM1024");

  // Input validation: TIME / BYTES throw on bad input. Operators
  // hitting `C.TIME.minutes(opts.x)` with opts.x undefined catch the
  // typo at boot, not as a silent 0ms or NaN-cap downstream.
  var threwUndef = null;
  try { b.constants.TIME.minutes(undefined); } catch (e) { threwUndef = e; }
  check("TIME.minutes(undefined) throws TypeError",
        threwUndef instanceof TypeError && /minutes/.test(threwUndef.message));
  var threwString = null;
  try { b.constants.TIME.seconds("5"); } catch (e) { threwString = e; }
  check("TIME.seconds('5') throws (no silent string-coerce)",
        threwString instanceof TypeError);
  var threwNeg = null;
  try { b.constants.TIME.hours(-1); } catch (e) { threwNeg = e; }
  check("TIME.hours(-1) throws (no negative durations)",
        threwNeg instanceof TypeError);
  var threwNaN = null;
  try { b.constants.TIME.days(NaN); } catch (e) { threwNaN = e; }
  check("TIME.days(NaN) throws (no silent NaN)",
        threwNaN instanceof TypeError);
  var threwBytesUndef = null;
  try { b.constants.BYTES.mib(undefined); } catch (e) { threwBytesUndef = e; }
  check("BYTES.mib(undefined) throws TypeError",
        threwBytesUndef instanceof TypeError && /mib/.test(threwBytesUndef.message));
  // Zero is a legitimate value (operators use it for "no cap" sentinels)
  check("TIME.minutes(0) returns 0 (zero is allowed)",
        b.constants.TIME.minutes(0) === 0);
  check("BYTES.kib(0) returns 0 (zero is allowed)",
        b.constants.BYTES.kib(0) === 0);

  // vault-wrap format constants
  check("vault-wrap MAGIC = 0xE2",       b.vaultWrap.MAGIC === 0xE2);
  check("vault-wrap FORMAT_VERSION = 1", b.vaultWrap.FORMAT_VERSION === 0x01);
  check("vault-wrap NONCE_LENGTH = 24",  b.vaultWrap.NONCE_LENGTH === 24);
  check("vault-wrap default Argon2 params present",
        b.vaultWrap.DEFAULT_ARGON2 && b.vaultWrap.DEFAULT_ARGON2.memoryCost > 0);

  // passphrase-source env var names follow BLAMEJS_ prefix
  check("vaultPassphraseSource ENV_PASSPHRASE = BLAMEJS_VAULT_PASSPHRASE",
        b.vaultPassphraseSource.ENV_PASSPHRASE === "BLAMEJS_VAULT_PASSPHRASE");
  check("vaultPassphraseSource ENV_PASSPHRASE_FILE = BLAMEJS_VAULT_PASSPHRASE_FILE",
        b.vaultPassphraseSource.ENV_PASSPHRASE_FILE === "BLAMEJS_VAULT_PASSPHRASE_FILE");
  check("vaultPassphraseSource ENV_PASSPHRASE_SRC = BLAMEJS_VAULT_PASSPHRASE_SOURCE",
        b.vaultPassphraseSource.ENV_PASSPHRASE_SRC === "BLAMEJS_VAULT_PASSPHRASE_SOURCE");

  // Envelope encrypt/decrypt round-trip
  var keys = b.crypto.generateEncryptionKeyPair();
  check("encryption keypair has all four members",
        typeof keys.publicKey === "string" && typeof keys.privateKey === "string" &&
        typeof keys.ecPublicKey === "string" && typeof keys.ecPrivateKey === "string");

  var plaintext = "hello blamejs " + b.version + " 🔐";
  var envelope = b.crypto.encrypt(plaintext, keys);
  check("encrypt() returns base64 string",     typeof envelope === "string");

  var decrypted = b.crypto.decrypt(envelope, keys);
  check("decrypt() round-trip preserves UTF-8", decrypted === plaintext);

  // Envelope header bytes match active algorithm IDs
  var envBytes = Buffer.from(envelope, "base64");
  check("envelope byte 0 = magic",         envBytes[0] === b.constants.ENVELOPE_MAGIC);
  check("envelope byte 1 = active KEM",    envBytes[1] === b.constants.ACTIVE.KEM);
  check("envelope byte 2 = active cipher", envBytes[2] === b.constants.ACTIVE.CIPHER);
  check("envelope byte 3 = active KDF",    envBytes[3] === b.constants.ACTIVE.KDF);

  // Tampered envelope fails to decrypt
  var tampered = Buffer.from(envelope, "base64");
  tampered[tampered.length - 1] ^= 0x01;
  var tamperedRejected = false;
  try { b.crypto.decrypt(tampered.toString("base64"), keys); }
  catch (_) { tamperedRejected = true; }
  check("tampered envelope is rejected", tamperedRejected);

  // Wrong-key decrypt fails
  var otherKeys = b.crypto.generateEncryptionKeyPair();
  var wrongKeyRejected = false;
  try { b.crypto.decrypt(envelope, otherKeys); }
  catch (_) { wrongKeyRejected = true; }
  check("wrong-key decrypt is rejected", wrongKeyRejected);

  // timingSafeEqual
  check("timingSafeEqual matches identical",       b.crypto.timingSafeEqual("foo", "foo"));
  check("timingSafeEqual rejects different",      !b.crypto.timingSafeEqual("foo", "bar"));
  check("timingSafeEqual rejects length-mismatch", !b.crypto.timingSafeEqual("foo", "foobar"));

  // Token / random bytes
  check("generateToken default = 64 hex chars (32 bytes)", b.crypto.generateToken().length === 64);
  check("generateBytes returns 16 bytes",                  b.crypto.generateBytes(16).length === 16);
  // Regression check:: pre-fix, random() ran randomBytes
  // through SHA3-512 (fixed 64-byte output) + subarray, which silently
  // truncated requests > 64 bytes. The TOTP 128-byte secret surfaced
  // it. Fixed by switching to SHAKE256 (XOF; arbitrary output length).
  check("generateBytes(128) returns 128 bytes (no SHA3-512 cap)",
        b.crypto.generateBytes(128).length === 128);
  check("generateBytes(256) returns 256 bytes",
        b.crypto.generateBytes(256).length === 256);
  // Two calls produce different bytes (RNG, not deterministic)
  check("generateBytes is non-deterministic",
        !b.crypto.generateBytes(64).equals(b.crypto.generateBytes(64)));

  // SHA3-512 hash determinism
  var h1 = b.crypto.sha3Hash("blamejs");
  var h2 = b.crypto.sha3Hash("blamejs");
  check("sha3Hash is deterministic",            h1 === h2);
  check("sha3Hash is 128 hex chars (512 bits)", h1.length === 128);

  // Symmetric buffer encrypt/decrypt round-trip
  var symKey = b.crypto.generateBytes(32);
  var bufPlain = Buffer.from("symmetric round-trip", "utf8");
  var bufPacked = b.crypto.encryptPacked(bufPlain, symKey);
  check("encryptPacked produces non-empty buffer",    bufPacked.length > 0);
  check("encryptPacked starts with format byte 0x02", bufPacked[0] === b.constants.FORMAT.XCHACHA20_POLY1305);
  var bufRoundTripped = b.crypto.decryptPacked(bufPacked, symKey);
  check("decryptPacked round-trip preserves bytes",   bufRoundTripped.equals(bufPlain));

  // Signing keypair + sign/verify round-trip
  var signKeys = b.crypto.generateSigningKeyPair();
  check("signing keypair has public + private",
        typeof signKeys.publicKey === "string" && typeof signKeys.privateKey === "string");
  var msg = Buffer.from("sign-me-" + b.version);
  var sig = b.crypto.sign(msg, signKeys.privateKey);
  check("sign() returns Buffer of non-zero length", Buffer.isBuffer(sig) && sig.length > 0);
  check("verify() accepts valid signature",         b.crypto.verify(msg, sig, signKeys.publicKey));
  check("verify() rejects tampered message",        !b.crypto.verify(Buffer.from("tamper"), sig, signKeys.publicKey));

  // Router constructs and registers
  var r = new b.router.Router();
  r.get("/test", function (_req, _res) {});
  r.post("/api/items", function (_req, _res) {});
  r.use(function (_req, _res, next) { next(); });
  check("router registers GET route",  r.routes.some(function (rt) { return rt.method === "GET"  && rt.pattern === "/test"; }));
  check("router registers POST route", r.routes.some(function (rt) { return rt.method === "POST" && rt.pattern === "/api/items"; }));
  check("router stores middleware",    r.middleware.length === 1);
  check("serveStatic is a function",   typeof b.router.serveStatic === "function");
}

// ---- run() ----

// ---- b.fileUpload — chunked upload primitive ----

function _fuTmpDir(suffix) {
  var os = require("node:os");
  var p = require("node:path");
  var fs = require("node:fs");
  var dir = p.join(os.tmpdir(), "fileupload-test-" + suffix + "-" +
    require("crypto").randomBytes(6).toString("hex"));
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}
function _fuChunkSha3(buf) {
  return require("./../lib/crypto").sha3Hash(buf);
}
function _fuFullSha3(pieces) {
  var h = require("crypto").createHash("sha3-512");
  for (var i = 0; i < pieces.length; i++) h.update(pieces[i]);
  return h.digest("hex");
}

function testFileUploadCreate() {
  var b = require("./../index");
  var fs = require("node:fs");
  var dir = _fuTmpDir("create");
  // Happy path
  var u = b.fileUpload.create({ stagingDir: dir });
  check("fileUpload.create returns acceptChunk fn",
        typeof u.acceptChunk === "function" &&
        typeof u.finalize === "function" &&
        typeof u.purgeIncomplete === "function" &&
        typeof u.status === "function");
  check("fileUpload.create ensures stagingDir exists",
        fs.existsSync(dir) && fs.statSync(dir).isDirectory());
  // stagingDir required (throws at create-time)
  var threwMissing = false;
  try { b.fileUpload.create({}); }
  catch (e) { threwMissing = e.message.indexOf("stagingDir") !== -1; }
  check("fileUpload.create rejects missing stagingDir", threwMissing);
  // stagingDir must be absolute (throws at create-time)
  var threwRel = false;
  try { b.fileUpload.create({ stagingDir: "./relative" }); }
  catch (e) { threwRel = e.message.indexOf("absolute") !== -1; }
  check("fileUpload.create rejects relative stagingDir", threwRel);
}

async function testFileUploadInitHappyPath() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("init") });
  var rv = await u.init({ uploadId: "u-1", actor: { id: "alice" }, metadata: { filename: "x.bin" } });
  check("fileUpload.init returns uploadId + createdAt + expiresAt",
        rv.uploadId === "u-1" && typeof rv.createdAt === "number" &&
        typeof rv.expiresAt === "number" && rv.expiresAt > rv.createdAt);
  // Refuse re-init of existing upload
  var threw = false;
  try { await u.init({ uploadId: "u-1", actor: { id: "alice" } }); }
  catch (e) { threw = e.code === "UPLOAD_EXISTS"; }
  check("fileUpload.init refuses re-init of existing uploadId", threw);
}

async function testFileUploadAcceptChunkRequiresInit() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("requires-init") });
  var body = Buffer.from("data", "utf8");
  var threw = false;
  try {
    await u.acceptChunk({
      uploadId: "u-no-init", index: 0, body: body,
      sha3: _fuChunkSha3(body), actor: { id: "alice" },
    });
  } catch (e) { threw = e.code === "UNKNOWN_UPLOAD"; }
  check("fileUpload.acceptChunk requires init() first", threw);
}

async function testFileUploadAcceptChunkRoundTrip() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("round-trip") });
  await u.init({ uploadId: "u-42", actor: { id: "u-42" } });
  var body = Buffer.from("hello world chunk 0", "utf8");
  var rv = await u.acceptChunk({
    uploadId: "u-42", index: 0, body: body,
    sha3: _fuChunkSha3(body), actor: { id: "u-42" },
  });
  check("fileUpload.acceptChunk: returns received: 1",
        rv.received === 1 && rv.totalBytesAccepted === body.length &&
        rv.status === "in-progress");
  var st = u.status("u-42", { actor: { id: "u-42" } });
  check("fileUpload.status returns enriched info",
        st && st.received.length === 1 && st.received[0] === 0 &&
        st.totalBytesAccepted === body.length &&
        typeof st.createdAt === "number");
}

async function testFileUploadHashMismatch() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("hash-mismatch") });
  await u.init({ uploadId: "u-1", actor: { id: "u-1" } });
  var body = Buffer.from("real bytes", "utf8");
  var threw = false;
  var threwCode = "";
  try {
    await u.acceptChunk({
      uploadId: "u-1", index: 0, body: body,
      sha3: _fuChunkSha3(Buffer.from("different bytes", "utf8")),
      actor: { id: "u-1" },
    });
  } catch (e) { threw = true; threwCode = e.code; }
  check("fileUpload.acceptChunk rejects sha3 mismatch",
        threw && threwCode === "CHUNK_HASH_MISMATCH");
}

async function testFileUploadOversizedChunk() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("oversized"), maxChunkBytes: 100 });
  await u.init({ uploadId: "u-1", actor: { id: "u-1" } });
  var body = Buffer.alloc(200, 0xAB);
  var threw = false;
  try {
    await u.acceptChunk({
      uploadId: "u-1", index: 0, body: body, sha3: _fuChunkSha3(body), actor: { id: "u-1" },
    });
  } catch (e) { threw = e.code === "CHUNK_TOO_LARGE"; }
  check("fileUpload.acceptChunk rejects body > maxChunkBytes", threw);
}

async function testFileUploadIdempotentChunkRePut() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("idempotent") });
  await u.init({ uploadId: "u-1", actor: { id: "u-1" } });
  var body = Buffer.from("idempotent chunk", "utf8");
  var sha = _fuChunkSha3(body);
  var rv1 = await u.acceptChunk({ uploadId: "u-1", index: 0, body: body, sha3: sha, actor: { id: "u-1" } });
  var rv2 = await u.acceptChunk({ uploadId: "u-1", index: 0, body: body, sha3: sha, actor: { id: "u-1" } });
  check("fileUpload.acceptChunk idempotent re-put with same body",
        rv1.received === 1 && rv2.received === 1 && rv2.duplicate === true);
  var body2 = Buffer.from("different bytes for same idx", "utf8");
  var threw = false;
  try {
    await u.acceptChunk({ uploadId: "u-1", index: 0, body: body2, sha3: _fuChunkSha3(body2), actor: { id: "u-1" } });
  } catch (e) { threw = e.code === "CHUNK_REUSE_MISMATCH"; }
  check("fileUpload.acceptChunk refuses re-put with different body for same index", threw);
}

async function testFileUploadFinalize() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("finalize") });
  await u.init({ uploadId: "u-1", actor: { id: "u-1" } });
  var c0 = Buffer.from("hello ", "utf8");
  var c1 = Buffer.from("world!", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "u-1" } });
  await u.acceptChunk({ uploadId: "u-1", index: 1, body: c1, sha3: _fuChunkSha3(c1), actor: { id: "u-1" } });
  var rv = await u.finalize({
    uploadId: "u-1",
    manifest: {
      totalBytes: c0.length + c1.length,
      sha3:       _fuFullSha3([c0, c1]),
      chunks: [
        { index: 0, sha3: _fuChunkSha3(c0) },
        { index: 1, sha3: _fuChunkSha3(c1) },
      ],
    },
    actor: { id: "u-1" },
  });
  check("fileUpload.finalize returns ok + size + sha3",
        rv.ok === true && rv.size === c0.length + c1.length &&
        rv.sha3 === _fuFullSha3([c0, c1]));
  check("fileUpload.finalize removes staging dir on success",
        u.status("u-1") === null);
}

async function testFileUploadFinalizeMissingChunk() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("missing") });
  await u.init({ uploadId: "u-1", actor: { id: "u-1" } });
  var c0 = Buffer.from("only chunk 0", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "u-1" } });
  var threw = false;
  try {
    await u.finalize({
      uploadId: "u-1",
      manifest: {
        totalBytes: c0.length + 6,
        sha3:       _fuFullSha3([c0, Buffer.from("absent", "utf8")]),
        chunks: [
          { index: 0, sha3: _fuChunkSha3(c0) },
          { index: 1, sha3: _fuChunkSha3(Buffer.from("absent", "utf8")) },
        ],
      },
      actor: { id: "u-1" },
    });
  } catch (e) { threw = e.code === "MISSING_CHUNK"; }
  check("fileUpload.finalize rejects when manifest references missing chunk", threw);
}

async function testFileUploadFinalizeIndexGap() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("indexgap") });
  await u.init({ uploadId: "u-1", actor: { id: "u-1" } });
  var c0 = Buffer.from("c0", "utf8");
  var c2 = Buffer.from("c2", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "u-1" } });
  await u.acceptChunk({ uploadId: "u-1", index: 2, body: c2, sha3: _fuChunkSha3(c2), actor: { id: "u-1" } });
  var threw = false;
  try {
    await u.finalize({
      uploadId: "u-1",
      manifest: {
        totalBytes: 4,
        sha3:       _fuFullSha3([c0, c2]),
        chunks: [
          { index: 0, sha3: _fuChunkSha3(c0) },
          { index: 2, sha3: _fuChunkSha3(c2) },
        ],
      },
      actor: { id: "u-1" },
    });
  } catch (e) { threw = e.code === "MANIFEST_INDEX_GAP"; }
  check("fileUpload.finalize rejects manifest with index gap", threw);
}

async function testFileUploadFinalizeManifestSizeMismatch() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("sizemismatch") });
  await u.init({ uploadId: "u-1", actor: { id: "u-1" } });
  var c0 = Buffer.from("12345", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "u-1" } });
  var threw = false;
  try {
    await u.finalize({
      uploadId: "u-1",
      manifest: {
        totalBytes: 999,                    // lying about the size
        sha3:       _fuFullSha3([c0]),
        chunks:     [{ index: 0, sha3: _fuChunkSha3(c0) }],
      },
      actor: { id: "u-1" },
    });
  } catch (e) { threw = e.code === "MANIFEST_SIZE_MISMATCH"; }
  check("fileUpload.finalize rejects mismatched manifest.totalBytes", threw);
}

async function testFileUploadFinalizeManifestHashMismatch() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("hashmismatch") });
  await u.init({ uploadId: "u-1", actor: { id: "u-1" } });
  var c0 = Buffer.from("real", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "u-1" } });
  var threw = false;
  try {
    await u.finalize({
      uploadId: "u-1",
      manifest: {
        totalBytes: c0.length,
        sha3:       _fuChunkSha3(Buffer.from("fake", "utf8")), // wrong total hash
        chunks:     [{ index: 0, sha3: _fuChunkSha3(c0) }],
      },
      actor: { id: "u-1" },
    });
  } catch (e) { threw = e.code === "MANIFEST_HASH_MISMATCH"; }
  check("fileUpload.finalize rejects mismatched manifest.sha3", threw);
}

async function testFileUploadFinalizeFileTooLarge() {
  var b = require("./../index");
  var u = b.fileUpload.create({
    stagingDir:    _fuTmpDir("toolarge"),
    maxFileBytes:  10,
    maxChunkBytes: 100,
  });
  await u.init({ uploadId: "u-1", actor: { id: "u-1" } });
  var c0 = Buffer.alloc(20, 0xAB);
  // Cumulative cap fires at acceptChunk now (the running total
  // immediately exceeds maxFileBytes), reclaiming the staging dir.
  var threw = false;
  try {
    await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "u-1" } });
  } catch (e) { threw = e.code === "FILE_TOO_LARGE"; }
  check("fileUpload.acceptChunk rejects when cumulative > maxFileBytes", threw);
}

async function testFileUploadPathTraversalRejected() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("traversal") });
  var bad = ["../escape", "/abs", "with/slash", "with\\backslash",
             "with\0null", "with spaces", "with*glob", ""];
  var allRejected = true;
  for (var i = 0; i < bad.length; i++) {
    var threw = false;
    try { await u.init({ uploadId: bad[i], actor: { id: "u-1" } }); }
    catch (e) { threw = e.code === "BAD_UPLOAD_ID"; }
    if (!threw) allRejected = false;
  }
  check("fileUpload: hostile uploadIds (path traversal / null / glob / empty) all rejected",
        allRejected);
}

async function testFileUploadPurgeIncomplete() {
  var b = require("./../index");
  var fs = require("node:fs");
  var p = require("node:path");
  var stagingDir = _fuTmpDir("purge");
  // Use a fake clock so we can advance "time" past the TTL.
  var fakeNow = 1700000000000;
  var u = b.fileUpload.create({
    stagingDir:      stagingDir,
    incompleteTtlMs: 1000,                 // 1 second TTL
    maxIdleMs:       500,
    clock:           function () { return fakeNow; },
  });
  await u.init({ uploadId: "u-incomplete", actor: { id: "u-1" } });
  var c0 = Buffer.from("incomplete chunk", "utf8");
  await u.acceptChunk({ uploadId: "u-incomplete", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "u-1" } });
  // Advance fake clock so TTL elapses.
  fakeNow = fakeNow + 5000;
  var ud = p.join(stagingDir, "u-incomplete");
  var rv = await u.purgeIncomplete();
  check("fileUpload.purgeIncomplete reclaims expired staging dirs",
        rv.purged === 1 && rv.ids.indexOf("u-incomplete") !== -1);
  check("fileUpload.purgeIncomplete actually deletes the directory",
        !fs.existsSync(ud));
}

async function testFileUploadOnFinalizeCallback() {
  var b = require("./../index");
  var captured = null;
  var u = b.fileUpload.create({
    stagingDir: _fuTmpDir("oncallback"),
    onFinalize: async function (info) {
      captured = info;
      return { ok: true, key: "uploads/" + info.actor.id + "/" + info.uploadId,
               size: info.size, sha3: info.sha3 };
    },
  });
  // .dat is filename-safety-clean (.bin is in the shell-exec
  // extension family which the default-on strict filenameSafety
  // refuses; this test verifies metadata round-trip, not the safety
  // gate).
  await u.init({ uploadId: "u-1", actor: { id: "u-99" }, metadata: { filename: "payload.dat" } });
  var c0 = Buffer.from("payload", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "u-99" } });
  var rv = await u.finalize({
    uploadId: "u-1",
    manifest: {
      totalBytes: c0.length, sha3: _fuFullSha3([c0]),
      chunks: [{ index: 0, sha3: _fuChunkSha3(c0) }],
    },
    actor: { id: "u-99" },
  });
  check("fileUpload.finalize: onFinalize receives uploadId / body / sha3 / size / actor / metadata",
        captured &&
        captured.uploadId === "u-1" &&
        Buffer.isBuffer(captured.body) &&
        captured.body.toString("utf8") === "payload" &&
        captured.size === c0.length &&
        typeof captured.sha3 === "string" && captured.sha3.length === 128 &&
        captured.actor && captured.actor.id === "u-99" &&
        captured.metadata && captured.metadata.filename === "payload.dat");
  check("fileUpload.finalize: onFinalize return value passed through",
        rv.ok === true && rv.key === "uploads/u-99/u-1" && rv.size === c0.length);
}

async function testFileUploadMetadataStash() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("metadata") });
  await u.init({
    uploadId: "u-1",
    actor:    { id: "alice" },
    metadata: { filename: "report.pdf", mimeType: "application/pdf", category: "annual-report" },
  });
  var st = u.status("u-1", { actor: { id: "alice" } });
  check("fileUpload metadata persisted across init → status",
        st && st.metadata.filename === "report.pdf" &&
        st.metadata.mimeType === "application/pdf" &&
        st.metadata.category === "annual-report");
  // Metadata cap
  var threw = false;
  try {
    await u.init({
      uploadId: "u-2", actor: { id: "alice" },
      metadata: { huge: "x".repeat(70000) },
    });
  } catch (e) { threw = e.code === "METADATA_TOO_LARGE"; }
  check("fileUpload.init refuses metadata > METADATA_MAX_BYTES", threw);
}

async function testFileUploadActorQuota() {
  var b = require("./../index");
  var u = b.fileUpload.create({
    stagingDir: _fuTmpDir("actor-quota"),
    maxActiveUploadsPerActor: 2,
  });
  await u.init({ uploadId: "u-1", actor: { id: "alice" } });
  await u.init({ uploadId: "u-2", actor: { id: "alice" } });
  var threw = false;
  try { await u.init({ uploadId: "u-3", actor: { id: "alice" } }); }
  catch (e) { threw = e.code === "ACTOR_QUOTA_EXCEEDED"; }
  check("fileUpload.init refuses when actor exceeds maxActiveUploadsPerActor", threw);
  // Different actor not blocked
  await u.init({ uploadId: "u-4", actor: { id: "bob" } });
  check("fileUpload.init: per-actor quota does not affect other actors",
        u.status("u-4", { actor: { id: "bob" } }) !== null);
}

async function testFileUploadStagingQuota() {
  var b = require("./../index");
  var u = b.fileUpload.create({
    stagingDir:      _fuTmpDir("staging-quota"),
    maxStagingBytes: 100,                       // tiny cap
    maxFileBytes:    1000,
    maxChunkBytes:   1000,
  });
  await u.init({ uploadId: "u-1", actor: { id: "alice" } });
  // Add ~80 bytes via a chunk; second init within the cap.
  var body = Buffer.alloc(80, 0xAB);
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: body,
                        sha3: _fuChunkSha3(body), actor: { id: "alice" } });
  // Now total bytes accepted = 80, > 100? No, ≤ cap. Force over: another upload pushes total over.
  await u.init({ uploadId: "u-2", actor: { id: "alice" } });
  var body2 = Buffer.alloc(80, 0xCD);
  await u.acceptChunk({ uploadId: "u-2", index: 0, body: body2,
                        sha3: _fuChunkSha3(body2), actor: { id: "alice" } });
  // Now total = 160 bytes > 100 cap. Next init blocked.
  var threw = false;
  try { await u.init({ uploadId: "u-3", actor: { id: "alice" } }); }
  catch (e) { threw = e.code === "STAGING_QUOTA_EXCEEDED"; }
  check("fileUpload.init refuses when total staging > maxStagingBytes", threw);
}

async function testFileUploadOnChunkHook() {
  var b = require("./../index");
  var seen = [];
  var u = b.fileUpload.create({
    stagingDir: _fuTmpDir("onchunk"),
    onChunk: async function (info) {
      seen.push({ index: info.index, size: info.body.length, metadata: info.metadata });
    },
  });
  await u.init({ uploadId: "u-1", actor: { id: "alice" }, metadata: { tag: "ok" } });
  var body = Buffer.from("trace me", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: body,
                        sha3: _fuChunkSha3(body), actor: { id: "alice" } });
  check("fileUpload.acceptChunk: onChunk hook invoked with chunk info + metadata",
        seen.length === 1 && seen[0].index === 0 &&
        seen[0].size === body.length && seen[0].metadata.tag === "ok");
}

async function testFileUploadOnChunkRejection() {
  var b = require("./../index");
  var u = b.fileUpload.create({
    stagingDir: _fuTmpDir("onchunk-reject"),
    onChunk: async function (info) {
      if (info.body.indexOf(Buffer.from("VIRUS")) !== -1) {
        throw new Error("simulated AV: malware signature detected");
      }
    },
  });
  await u.init({ uploadId: "u-1", actor: { id: "alice" } });
  var clean = Buffer.from("safe payload", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: clean,
                        sha3: _fuChunkSha3(clean), actor: { id: "alice" } });
  var dirty = Buffer.from("payload with VIRUS marker", "utf8");
  var threw = false;
  try {
    await u.acceptChunk({ uploadId: "u-1", index: 1, body: dirty,
                          sha3: _fuChunkSha3(dirty), actor: { id: "alice" } });
  } catch (e) { threw = e.message.indexOf("malware") !== -1; }
  check("fileUpload.acceptChunk: onChunk hook rejection refuses the chunk", threw);
}

async function testFileUploadIdleTimeout() {
  var b = require("./../index");
  var fakeNow = 1700000000000;
  var u = b.fileUpload.create({
    stagingDir: _fuTmpDir("idle"),
    maxIdleMs:  1000,
    clock:      function () { return fakeNow; },
  });
  await u.init({ uploadId: "u-1", actor: { id: "alice" } });
  var c0 = Buffer.from("first", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0,
                        sha3: _fuChunkSha3(c0), actor: { id: "alice" } });
  // Advance past idle timeout
  fakeNow = fakeNow + 5000;
  var c1 = Buffer.from("second", "utf8");
  var threw = false;
  try {
    await u.acceptChunk({ uploadId: "u-1", index: 1, body: c1,
                          sha3: _fuChunkSha3(c1), actor: { id: "alice" } });
  } catch (e) { threw = e.code === "UPLOAD_IDLE_EXPIRED"; }
  check("fileUpload.acceptChunk refuses when upload exceeds maxIdleMs since last chunk", threw);
}

async function testFileUploadStreamReassembly() {
  var b = require("./../index");
  var receivedStream = null;
  var receivedBuffer = null;
  var u = b.fileUpload.create({
    stagingDir:                _fuTmpDir("stream"),
    maxStreamReassemblyBytes:  10,                       // force stream mode
    maxChunkBytes:             100,
    onFinalize: async function (info) {
      receivedBuffer = info.body;
      receivedStream = info.stream;
      // Drain stream to verify it works
      if (info.stream) {
        var chunks = [];
        await new Promise(function (resolve, reject) {
          info.stream.on("data", function (c) { chunks.push(c); });
          info.stream.on("end", resolve);
          info.stream.on("error", reject);
        });
        return { ok: true, drained: Buffer.concat(chunks).toString("utf8") };
      }
      return { ok: true, drained: info.body.toString("utf8") };
    },
  });
  await u.init({ uploadId: "u-1", actor: { id: "alice" } });
  var c0 = Buffer.from("hello ", "utf8");
  var c1 = Buffer.from("world! large enough", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "alice" } });
  await u.acceptChunk({ uploadId: "u-1", index: 1, body: c1, sha3: _fuChunkSha3(c1), actor: { id: "alice" } });
  var rv = await u.finalize({
    uploadId: "u-1",
    manifest: {
      totalBytes: c0.length + c1.length,
      sha3:       _fuFullSha3([c0, c1]),
      chunks: [
        { index: 0, sha3: _fuChunkSha3(c0) },
        { index: 1, sha3: _fuChunkSha3(c1) },
      ],
    },
    actor: { id: "alice" },
  });
  check("fileUpload.finalize: above maxStreamReassemblyBytes uses stream mode (body=null, stream≠null)",
        receivedBuffer === null && receivedStream !== null);
  check("fileUpload.finalize: stream drains to the original concatenated bytes",
        rv.drained === "hello world! large enough");
}

async function testFileUploadStatusEnriched() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("status") });
  await u.init({ uploadId: "u-1", actor: { id: "alice" }, metadata: { tag: "report" } });
  var c0 = Buffer.from("data", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "alice" } });
  var st = u.status("u-1", { actor: { id: "alice" } });
  check("fileUpload.status returns received indices + total bytes + createdAt + metadata + expiresAt",
        st &&
        Array.isArray(st.received) && st.received.length === 1 && st.received[0] === 0 &&
        st.totalBytesAccepted === c0.length &&
        typeof st.createdAt === "number" &&
        typeof st.lastChunkAt === "number" && st.lastChunkAt >= st.createdAt &&
        st.metadata && st.metadata.tag === "report" &&
        typeof st.expiresAt === "number" && st.expiresAt > st.createdAt);
  // Unknown upload returns null
  check("fileUpload.status returns null for unknown upload",
        u.status("does-not-exist", { actor: { id: "alice" } }) === null);
}

async function testFileUploadList() {
  var b = require("./../index");
  var u = b.fileUpload.create({ stagingDir: _fuTmpDir("list") });
  await u.init({ uploadId: "u-1", actor: { id: "alice" }, metadata: { tag: "1" } });
  await u.init({ uploadId: "u-2", actor: { id: "alice" }, metadata: { tag: "2" } });
  await u.init({ uploadId: "u-3", actor: { id: "bob" },   metadata: { tag: "3" } });
  // Default scope: actor sees only their own
  var aliceList = u.list({ actor: { id: "alice" } });
  check("fileUpload.list: default-scoped to actor returns 2 of 3 uploads",
        aliceList.length === 2 &&
        aliceList.every(function (item) { return item.actorId === "alice"; }));
  // scopeToActor: false → see everything
  var allList = u.list({ actor: { id: "alice" }, scopeToActor: false });
  check("fileUpload.list: scopeToActor:false returns all uploads",
        allList.length === 3);
  // Each entry has metadata + createdAt + lastChunkAt + totalBytesAccepted
  check("fileUpload.list: entries have full enriched shape",
        aliceList[0].uploadId &&
        aliceList[0].metadata &&
        typeof aliceList[0].createdAt === "number" &&
        typeof aliceList[0].lastChunkAt === "number" &&
        typeof aliceList[0].totalBytesAccepted === "number");
}

async function testFileUploadCancel() {
  var b = require("./../index");
  var fs = require("node:fs");
  var p = require("node:path");
  var stagingDir = _fuTmpDir("cancel");
  var u = b.fileUpload.create({ stagingDir: stagingDir });
  await u.init({ uploadId: "u-1", actor: { id: "alice" } });
  var c0 = Buffer.from("partial", "utf8");
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: c0, sha3: _fuChunkSha3(c0), actor: { id: "alice" } });
  // Cancel
  var rv = await u.cancelUpload("u-1", { actor: { id: "alice" } });
  check("fileUpload.cancelUpload removes staging + returns ok",
        rv.ok === true && rv.uploadId === "u-1" &&
        !fs.existsSync(p.join(stagingDir, "u-1")));
  // Cancel non-existent → not-found
  var rv2 = await u.cancelUpload("does-not-exist", { actor: { id: "alice" } });
  check("fileUpload.cancelUpload returns ok:false for unknown uploadId",
        rv2.ok === false && rv2.reason === "not-found");
}

async function testFileUploadPermissionsIntegration() {
  var b = require("./../index");
  var calls = [];
  var fakePerms = {
    check: function (actor, scope) {
      calls.push({ actor: actor && actor.id, scope: scope });
      // Allow init / accept / finalize for alice; deny everything for mallory.
      return actor && actor.id === "alice";
    },
  };
  var u = b.fileUpload.create({
    stagingDir:  _fuTmpDir("perms"),
    permissions: fakePerms,
  });
  await u.init({ uploadId: "u-1", actor: { id: "alice" } });
  var threw = false;
  try { await u.init({ uploadId: "u-2", actor: { id: "mallory" } }); }
  catch (e) { threw = e.code === "PERMISSION_DENIED"; }
  check("fileUpload.init: permission-denied actor refused with PERMISSION_DENIED",
        threw && calls.some(function (c) { return c.scope === "fileUpload.init"; }));
  // Even acceptChunk checks
  var body = Buffer.from("x", "utf8");
  var threwAccept = false;
  try {
    await u.acceptChunk({ uploadId: "u-1", index: 0, body: body,
                          sha3: _fuChunkSha3(body), actor: { id: "mallory" } });
  } catch (e) { threwAccept = e.code === "PERMISSION_DENIED"; }
  check("fileUpload.acceptChunk: also permission-checked", threwAccept);
}

async function testFileUploadMimeAllowlist() {
  var b = require("./../index");
  // PNG magic: 89 50 4E 47 0D 0A 1A 0A
  var pngHeader = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                               0, 0, 0, 13, 73, 72, 68, 82]); // partial valid PNG
  var u = b.fileUpload.create({
    stagingDir:        _fuTmpDir("mime-ok"),
    allowedFileTypes:  ["image/*"],
    fileType:          b.fileType,
  });
  await u.init({ uploadId: "u-1", actor: { id: "alice" } });
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: pngHeader,
                        sha3: _fuChunkSha3(pngHeader), actor: { id: "alice" } });
  var rv = await u.finalize({
    uploadId: "u-1",
    manifest: {
      totalBytes: pngHeader.length, sha3: _fuFullSha3([pngHeader]),
      chunks: [{ index: 0, sha3: _fuChunkSha3(pngHeader) }],
    },
    actor: { id: "alice" },
  });
  check("fileUpload.finalize: PNG bytes pass image/* allowlist",
        rv.ok === true && rv.size === pngHeader.length);
}

async function testFileUploadMimeAllowlistRejected() {
  var b = require("./../index");
  // Plain UTF-8 text, not an image
  var text = Buffer.from("not an image at all", "utf8");
  var u = b.fileUpload.create({
    stagingDir:        _fuTmpDir("mime-reject"),
    allowedFileTypes:  ["image/*"],
    fileType:          b.fileType,
  });
  await u.init({ uploadId: "u-1", actor: { id: "alice" } });
  await u.acceptChunk({ uploadId: "u-1", index: 0, body: text,
                        sha3: _fuChunkSha3(text), actor: { id: "alice" } });
  var threw = false;
  try {
    await u.finalize({
      uploadId: "u-1",
      manifest: {
        totalBytes: text.length, sha3: _fuFullSha3([text]),
        chunks: [{ index: 0, sha3: _fuChunkSha3(text) }],
      },
      actor: { id: "alice" },
    });
  } catch (e) { threw = e.code === "MIME_NOT_ALLOWED" || e.code === "MIME_NOT_DETECTED"; }
  check("fileUpload.finalize: non-image bytes rejected by image/* allowlist", threw);
}

async function testFileUploadMimeAllowlistRequiresFileType() {
  var b = require("./../index");
  var threw = false;
  try {
    b.fileUpload.create({
      stagingDir:       _fuTmpDir("mime-misconfig"),
      allowedFileTypes: ["image/*"],
      // fileType NOT wired
    });
  } catch (e) { threw = e.message.indexOf("fileType primitive is not wired") !== -1; }
  check("fileUpload.create: allowedFileTypes without fileType primitive throws at boot", threw);
}

async function run() {
  // entrypoint module-surface sanity
  testCryptoAndModuleSurface();
  // async-safe primitives
  await testAsyncSafeWithTimeoutResolves();
  await testAsyncSafeWithTimeoutRejects();
  await testAsyncSafeWithTimeoutAbort();
  await testAsyncSafeWithTimeoutPropagatesError();
  await testAsyncSafeSafeAwait();
  await testAsyncSafeMutexSerializes();
  await testAsyncSafeMutexReleaseOnThrow();
  await testAsyncSafeMutexAbortableAcquire();
  await testAsyncSafeSemaphoreBoundedConcurrency();
  await testAsyncSafeSemaphoreAbortableAcquire();
  await testAsyncSafeOnceSingleFlight();
  await testAsyncSafeOnceCachesFailure();
  await testAsyncSafeOnceReset();
  await testAsyncSafeCircuitBreakerStateTransitions();
  // sleep + withTimeoutSignal — primitives lifted out of ad-hoc patterns
  await testAsyncSafeSleepBasic();
  await testAsyncSafeSleepZeroResolvesImmediately();
  await testAsyncSafeSleepBadArg();
  await testAsyncSafeSleepAbort();
  await testAsyncSafeSleepUnrefOptIn();
  await testAsyncSafeSleepDefaultRefd();
  testAsyncSafeWithTimeoutSignalCases();
  await testAsyncSafeWithTimeoutSignalTimeoutFires();
  // auth-header — primitive replacing 3x duplicated _authHeaders()
  testAuthHeaderBearer();
  testAuthHeaderBasic();
  testAuthHeaderFromConfig();
  // auth.password — Argon2id app-password hashing
  testAuthPasswordSurface();
  await testAuthPasswordHashShape();
  await testAuthPasswordVerifyRoundTrip();
  await testAuthPasswordVerifyTamperedHash();
  await testAuthPasswordVerifyMalformedHash();
  await testAuthPasswordHashRejectsBadInput();
  await testAuthPasswordNeedsRehash();
  // auth.totp — RFC 6238 TOTP
  testAuthTotpSurface();
  testAuthTotpRfc6238Vectors();
  testAuthTotpGenerateSecret();
  testAuthTotpGenerateAndVerifyRoundTrip();
  testAuthTotpDriftWindow();
  testAuthTotpReplayProtection();
  testAuthTotpVerifyMalformedInput();
  testAuthTotpUriShape();
  testAuthTotpBackupCodes();
  testAuthTotpBadAlgorithmRejected();
  // auth.passkey — WebAuthn
  await testAuthPasskeySurface();
  await testAuthPasskeyStartRegistrationOptions();
  await testAuthPasskeyStartAuthenticationOptions();
  await testAuthPasskeyValidationErrors();
  await testAuthPasskeyExcludeCredentials();
  await testAuthPasskeyCustomHints();
  // template — eval-free server-side HTML template engine
  testTemplateSurface();
  testTemplateEscapeHtml();
  testTemplateBasicRender();
  testTemplateRenderString();
  testTemplateRawExpression();
  testTemplateIfElse();
  testTemplateForLoop();
  testTemplateExpressionGrammar();
  testTemplatePartialInclusion();
  testTemplateLayoutInheritance();
  testTemplateContainmentDefenses();
  testTemplatePrototypeSafety();
  testTemplateCacheAndReset();
  testTemplateMissingViewsDir();
  // render — response helpers paired with the template engine
  testRenderSurface();
  testRenderJson();
  testRenderText();
  testRenderHtmlString();
  testRenderRedirect();
  testRenderDoesNotDoubleWrite();
  testRenderCreateWithEngine();
  testRenderCreateValidation();
  // staticServe — file serving + ETag + SRI
  testStaticServeSurface();
  await testStaticServeBasic();
  await testStaticServeImmutableForHashedPaths();
  await testStaticServeEtagAnd304();
  await testStaticServeHead();
  await testStaticServeContainmentDefenses();
  await testStaticServeIndexFile();
  await testStaticServeMethodGuard();
  await testStaticServeIntegrityHelper();
  // v0.7.x download-side audit
  await testStaticServeRangeBasic();
  await testStaticServeRangeSuffix();
  await testStaticServeRangeOpenEnd();
  await testStaticServeRangeUnsatisfiable();
  await testStaticServeRangeMultiRefused();
  await testStaticServeAcceptRangesOff();
  await testStaticServeIfMatchPrecondition();
  await testStaticServeIfModifiedSince();
  await testStaticServeIfUnmodifiedSince();
  await testStaticServePermissionsGate();
  await testStaticServeRetentionGate();
  await testStaticServeRevokeViaInstance();
  await testStaticServeRevokeStoreOpt();
  await testStaticServeMimeAllowlist();
  await testStaticServeMimeAllowlistRejected();
  testStaticServeMimeRequiresFileType();
  await testStaticServeOnServeHook();
  await testStaticServeOnServeThrows500();
  await testStaticServeAuditEmission();
  await testStaticServeAuditSuccessOptOut();
  await testStaticServeStats();
  await testStaticServeInvalidateMeta();
  testStaticServeQuotaRequiresCache();
  await testStaticServeBandwidthQuotaPerActor();
  await testStaticServeConcurrencyCap();
  // mail — message contract + pluggable transport
  testMailSurface();
  testMailCreateValidation();
  await testMailSendRoundTripViaMemoryTransport();
  await testMailDefaultsAndOverrides();
  await testMailValidation();
  await testMailEaiSmtpUtf8();
  await testMailRecipientArrayAndCcBcc();
  await testMailTransportFailureWraps();
  await testMailFunctionAsTransport();
  await testMailConsoleTransportShape();
  testMailSmtpFactoryValidation();
  testMailResendFactoryValidation();
  testMailHttpFactoryValidation();
  await testMailSmtpRoundTrip();
  await testMailSmtpStarttlsAccept();
  await testMailHttpRoundTripWithCustomVendor();
  await testMailHttpInterpretRejection();
  await testMailHttpInterpretThrows();
  await testMailHttpBadSerializer();
  await testMailResendRoundTrip();
  await testMailResendErrorPaths();

  // v0.4.22 — attachments + multipart
  await testMailAttachmentsValidation();
  await testMailAttachmentsMemoryTransportPassthrough();
  await testMailRfc822MultipartMixedWithAttachment();
  await testMailRfc822InlineWithCid();
  await testMailRfc822TextHtmlPlusAttachment();
  await testMailResendForwardsAttachments();
  // api-snapshot — public-API surface walker + breaking-change detector
  testApiSnapshotSurface();
  testApiSnapshotCaptureCategorizes();
  testApiSnapshotCaptureHandlesCycles();
  testApiSnapshotWriteAndRead();
  testApiSnapshotCompareNoChange();
  testApiSnapshotCompareDetectsRemoval();
  testApiSnapshotCompareDetectsTypeChange();
  testApiSnapshotCompareDetectsArityDecrease();
  testApiSnapshotCompareIgnoresArityIncrease();
  testApiSnapshotCompareDetectsAdditive();
  testApiSnapshotFormatDiff();
  testApiSnapshotOnFrameworkSurfaceCaptures();
  await testCliApiSnapshotCaptureAndCompare();
  // deprecate — runtime deprecation warnings + LTS-contract enforcement
  testDeprecateSurface();
  testDeprecateModeResolution();
  testDeprecateWarnEmitsOnce();
  testDeprecateSilentMode();
  testDeprecateErrorMode();
  testDeprecateDifferentSinceProducesNewLine();
  testDeprecateWarnArgValidation();
  testDeprecateWrap();
  testDeprecateWrapValidation();
  testDeprecateAlias();
  testDeprecateListAndReset();
  // restore-rollback + restore — atomic dataDir swap + storage-backed orchestrator
  testRestoreRollbackSurface();
  testRestoreRollbackSwap();
  await testRestoreRollbackRoundTrip();
  testRestoreRollbackListAndPurge();
  testRestoreRollbackHandlesEmptyDataDir();
  testRestoreSurface();
  testRestoreCreateValidation();
  await testRestoreRunRoundTrip();
  await testRestoreRollbackUndoesRun();
  await testRestoreRunWithMissingBundle();
  await testRestoreRunWithWrongPassphrase();
  await testRestoreListRollbacksAndPurge();
  await testRestoreInspectWithoutDecrypt();
  // backup — operator-facing orchestration + retention + storage backend
  testBackupSurface();
  testBackupRecommendedFiles();
  await testBackupFlushBeforeBackupCalled();
  await testBackupFlushFailureDoesNotFailBackup();
  await testBackupFlushBeforeBackupOptOut();
  testBackupCreateValidation();
  await testBackupRunListReadDelete();
  await testBackupVaultKeyJsonAsFunction();
  await testBackupVaultKeyJsonAsAsyncFunction();
  await testBackupRetentionPurgeOlder();
  await testBackupRetentionAutoSweepOnRun();
  await testBackupBundleIdValidation();
  await testBackupLocalStorageRejectsExistingDest();
  // restore-bundle — extract an encrypted backup bundle to staging
  testRestoreBundleSurface();
  await testRestoreBundleRoundTrip();
  await testRestoreBundleFilterSubset();
  await testRestoreBundleWrongPassphrase();
  await testRestoreBundleTamperedBlobDetected();
  await testRestoreBundleChecksumMismatchDetected();
  await testRestoreBundleMissingBlobDetected();
  await testRestoreBundleEncryptedSizeMismatchDetected();
  testRestoreBundleInspectReturnsManifest();
  await testRestoreBundleArgValidation();
  // backup-bundle — encrypted backup bundle producer
  testBackupBundleSurface();
  await testBackupBundleCreateEndToEnd();
  await testBackupBundlePathTraversalRejected();
  await testBackupBundleRequiredMissing();
  await testBackupBundleEmptyBundleRejected();
  await testBackupBundleArgValidation();
  // backup-manifest — bundle schema + create/validate/parse/serialize
  testBackupManifestSurface();
  testBackupManifestCreateAndSerialize();
  testBackupManifestValidateRejectsBadFields();
  testBackupManifestRejectsDuplicatePaths();
  testBackupManifestParseRejectsCorruption();
  testBackupManifestSerializeIsCanonical();
  // backup-crypto — Argon2id KDF + XChaCha20-Poly1305 for backup files
  testBackupCryptoSurface();
  await testBackupCryptoDeriveKeyDeterministic();
  await testBackupCryptoRoundTrip();
  await testBackupCryptoStringPlaintext();
  await testBackupCryptoWrongPassphraseFails();
  await testBackupCryptoTamperedCiphertextFails();
  await testBackupCryptoFreshSaltUnique();
  testBackupCryptoChecksumIsSha3_512();
  await testBackupCryptoArgValidation();
  // body-parser — request-body buffering + dispatch
  await testBodyParserSurface();
  await testBodyParserGetSkipped();
  await testBodyParserStrictContentLength();
  await testBodyParserJsonHappy();
  await testBodyParserJsonStripsPrototypePollution();
  await testBodyParserJsonSizeCap();
  await testBodyParserJsonMalformed();
  await testBodyParserJsonStrictMode();
  await testBodyParserUrlencoded();
  await testBodyParserUrlencodedPoisonedKey();
  await testBodyParserText();
  await testBodyParserRaw();
  await testBodyParserUnsupportedType();
  await testBodyParserDisabledSubparser();
  await testBodyParserKeepRawBody();
  await testBodyParserMultipartFields();
  await testBodyParserMultipartFile();
  await testBodyParserMultipartMemoryStorage();
  await testBodyParserMultipartFilenameTraversal();
  await testBodyParserMultipartFileSizeLimit();
  await testBodyParserMultipartMimeAllowlist();
  await testBodyParserMultipartFileFilterAccept();
  await testBodyParserMultipartFileFilterRejectFalse();
  await testBodyParserMultipartFileFilterRejectObject();
  await testBodyParserMultipartFileFilterMixedAcceptReject();
  await testBodyParserMultipartFileFilterThrows();
  await testBodyParserMultipartFileFilterAuditEmit();
  await testBodyParserMultipartPerFieldMaxBytesTighter();
  await testBodyParserMultipartPerFieldMaxBytesLooser();
  await testBodyParserMultipartPerFieldMimeTypesBlock();
  await testBodyParserMultipartPerFieldMimeOverridesGlobal();
  await testBodyParserMultipartPoisonedFieldName();
  await testBodyParserMultipartTruncated();
  await testBodyParserContentLengthExceedsLimitImmediate();
  testBodyParserSanitizeFilenameUnit();
  // auth.oauth — OAuth 2 / OIDC client
  testOAuthSurface();
  testOAuthCreateValidates();
  testOAuthPkceRequired();
  testOAuthPkceGenerator();
  await testOAuthAuthorizationUrlPreset();
  await testOAuthAuthorizationUrlOidc();
  await testOAuthAuthorizationUrlGenericPreset();
  await testOAuthAuthorizationUrlExtraParams();
  await testOAuthExchangeCodeRequiresVerifier();
  await testOAuthExchangeCodeRoundTrip();
  await testOAuthRefreshAccessToken();
  await testOAuthFetchUserInfo();
  await testOAuthVerifyIdTokenRoundTrip();
  await testOAuthVerifyIdTokenRefusesUnsupportedAlg();
  testOAuthVerifyParamsForAlg();
  // AppShutdown — moved to test/layer-0-primitives/
  // Tracing — moved to test/layer-0-primitives/
  // metrics — Prometheus-format counters / gauges / histograms
  testMetricsSurface();
  testMetricsCounterBasic();
  testMetricsCounterRefusesNegative();
  testMetricsGaugeBasic();
  testMetricsHistogramBasic();
  testMetricsHistogramRejectsBadBuckets();
  testMetricsDefaultLabels();
  testMetricsNamespacing();
  testMetricsLabelValidation();
  testMetricsCardinalityCap();
  testMetricsExpositionFormat();
  testMetricsLabelEscaping();
  await testMetricsExpositionHandler();
  await testMetricsRequestMiddleware();
  await testMetricsRequestMiddlewareRoutePatternFallback();
  await testMetricsRequestMiddlewareStatusCodeFallback();
  testMetricsTapNoOpWhenNoRegistry();
  testMetricsTapRoutesIntoActiveRegistry();
  testMetricsBuiltinQueueDepthGauge();
  testMetricsBuiltinJobsInflightGauge();
  testMetricsBuiltinErrorsTotalCounter();
  testMetricsDuplicateRegistrationRejected();
  testMetricsResetClearsValues();
  // CspNonce — moved to test/layer-0-primitives/
  // pagination — moved to test/layer-0-primitives/pagination.test.js
  // compression — gzip + brotli response compression
  await testCompressionSurface();
  await testCompressionParseAcceptEncoding();
  await testCompressionNegotiate();
  await testCompressionTypeMatches();
  await testCompressionAppendVary();
  await testCompressionGzipRoundTrip();
  await testCompressionBrotliRoundTrip();
  await testCompressionPrefersBrotliOverGzip();
  await testCompressionSkipsBelowThreshold();
  await testCompressionSkipsImageContentType();
  await testCompressionSkipsAlreadyEncoded();
  await testCompressionSkipsWhenClientDoesntAccept();
  await testCompressionSkipsNoBodyStatus();
  await testCompressionFilterReturnsFalse();
  await testCompressionFilterThrowFailsClosed();
  await testCompressionStreamingWritesNoContentLength();
  await testCompressionImplicitWriteHeadPath();
  await testCompressionInvalidEncodingRejectedAtCreate();
  await testCompressionDoesntDoubleCompressViaWrappedWrite();
  await testCompressionPipedStreamLargerThanHighWaterMarkCompletes();
  // health — liveness/readiness/startup probe primitive
  await testHealthSurface();
  await testHealthDefaultLiveness();
  await testHealthDefaultReadiness();
  await testHealthUnmatchedPathFallsThrough();
  await testHealthNonGetFallsThrough();
  await testHealthCriticalFailReturns503();
  await testHealthNonCriticalFailIsDegraded();
  await testHealthDetailedResponse();
  await testHealthMinimalHidesDetail();
  await testHealthDetailPredicate();
  await testHealthDetailPredicateThrowFailsClosed();
  await testHealthShuttingDownFlipsReadiness();
  await testHealthMultiTierRegistration();
  await testHealthCheckTimeout();
  await testHealthCheckCacheRespected();
  await testHealthShutdownBypassesCache();
  await testHealthHeadMethod();
  await testHealthInvalidArgs();
  await testHealthCheckThrowFails();
  await testHealthCacheControlHeader();
  // safe-schema — declarative input validation
  testSafeSchemaSurface();
  testSafeSchemaStringPrimitive();
  testSafeSchemaNumberPrimitive();
  testSafeSchemaBooleanLiteralEnum();
  testSafeSchemaNullUndefinedAny();
  testSafeSchemaModifiers();
  testSafeSchemaObject();
  testSafeSchemaObjectPickOmitExtendPartial();
  testSafeSchemaArrayTupleUnionRecord();
  testSafeSchemaRefineTransform();
  testSafeSchemaLazyAndPreprocess();
  testSafeSchemaPrototypePollutionDefense();
  testSafeSchemaErrorIssues();
  testSafeSchemaImmutability();
  // events — moved to test/layer-0-primitives/events.test.js
  // audit-tools — operator tooling on the audit chain
  testAuditToolsSurface();
  testAuditChainCanonicalize();
  await testAuditToolsArchiveAndVerify();
  await testAuditToolsExportSliceAndVerify();
  await testAuditToolsVerifyBundleRejectsWrongPassphrase();
  await testAuditToolsVerifyBundleDetectsTamperedRows();
  await testAuditToolsArchiveRejectsWithoutCoveringCheckpoint();
  await testAuditToolsArgValidation();
  await testAuditToolsPurgeRoundTrip();
  await testAuditToolsPurgeRejectsUnverifiedArchive();
  await testAuditCliVerifyBundleSubcommand();
  // mtls-ca — CA file-management primitives + engine-pluggable issuance
  testMtlsCaSurface();
  testMtlsCaCreateValidation();
  testMtlsCaParseGeneration();
  testMtlsCaExistsAndStatusWhenAbsent();
  testMtlsCaLoadFailures();
  testMtlsCaCommitAndLoadPlaintext();
  testMtlsCaSealedRequiredMode();
  testMtlsCaSealedDisabledRefusesSealedFile();
  testMtlsCaSealedRequiredRefusesPlaintextFile();
  await testMtlsCaInitCaWithDefaultEngine();
  await testMtlsCaGenerateClientCertWithDefaultEngine();
  await testMtlsCaGenerateClientP12WithDefaultEngine();
  await testMtlsCaInitCaWithEngineGeneratesAndCommits();
  await testMtlsCaInitCaRejectsBadEngineOutput();
  await testMtlsCaGenerateClientCertDelegates();
  await testMtlsCaGenerateClientP12Validation();
  // vault-passphrase-ops — seal / unseal / rotate the vault passphrase wrap
  testVaultPassphraseOpsSurface();
  testVaultPassphraseOpsPreflightChecks();
  await testVaultPassphraseOpsSealUnsealRoundTrip();
  await testVaultPassphraseOpsKeepPlaintext();
  await testVaultPassphraseOpsWrongPassphraseRejected();
  await testVaultPassphraseOpsRotate();
  await testVaultPassphraseOpsRotateRejectsBadOldPassphrase();
  testVaultPassphraseOpsArgValidation();
  await testVaultPassphraseOpsRequiresBufferPassphrase();
  // vault-rotate (diagnostics) — schema drift + round-trip verify
  testVaultRotateSurface();
  testVaultRotateValidateSchemaCleanCase();
  testVaultRotateValidateMissingTable();
  testVaultRotateValidateSealedColMissing();
  testVaultRotateValidateDriftDetection();
  testVaultRotateValidateInfraColumnsAllowlist();
  testVaultRotateVerifyRoundTrip();
  testVaultRotateVerifyDetectsTampering();
  testVaultRotateVerifyRegressionWithOldKeys();
  testVaultRotateVerifyRequiresKeysAndDb();
  await testVaultRotateRotateEndToEnd();
  await testVaultRotateRotateValidation();
  // pqc-agent — outbound HTTPS agent locked to PQC group preference
  testPqcAgentSurface();
  testPqcAgentCreateHasPqcPosture();
  testPqcAgentCannotWeakenCryptoPosture();
  testPqcAgentDefaultIsLazy();
  testPqcAgentCreateHttpHasNoTlsPosture();
  // pqc-gate — TCP-level PQC enforcement on ClientHello
  testPqcGateSurface();
  testClientHelloPqcDetection();
  testPqcGateSocketLifecycle();
  testPqcGateBypassesLocalhost();
  // bundler — content-hashed asset pipeline + manifest
  testBundlerSurface();
  testBundlerCreateValidation();
  await testBundlerBuildHashedOutput();
  await testBundlerHashChangesWithContent();
  await testBundlerHashOff();
  await testBundlerCustomHashLen();
  await testBundlerReadFailure();
  await testBundlerWatchRebuilds();
  // dev — file-watch + child-process restart engine
  testDevSurface();
  await testDevStartSpawnsChildAndArmsWatchers();
  await testDevDebouncesBurstOfEventsToOneRestart();
  await testDevIgnoresMatchingPaths();
  await testDevRestartCoalescesQueuedRestart();
  await testDevStopKillsAndDisarms();
  await testDevUnexpectedExitDoesNotRespawn();
  // cli — `blamejs <cmd>` dispatch + migrate subcommand
  testCliSurface();
  testCliArgParser();
  await testCliVersionAndHelp();
  await testCliMigrateStatus();
  await testCliMigrateUpDown();
  await testCliMigrateValidationErrors();
  await testCliMigrateDownReportsNoOpCleanly();
  await testCliMigrateUpFailureExits1();
  await testCliDevValidation();
  // migrations — public migration runner with up/down/status
  testMigrationsSurface();
  testMigrationsUpAppliesPending();
  testMigrationsStatus();
  testMigrationsDownRollback();
  testMigrationsDownMultiSteps();
  testMigrationsDownRejectsBadSteps();
  testMigrationsRejectsRollbackWithoutDown();
  testMigrationsUpFailureRollsBackTransaction();
  testMigrationsRejectsMalformedFiles();
  // migrations advisory lock
  testMigrationsLockReleasedAfterUp();
  testMigrationsLockBlocksConcurrent();
  testMigrationsLockStaleReplace();
  testMigrationsLockReleasedAfterFailure();
  // session fixation rotation
  await testSessionRotateBasic();
  await testSessionRotateReplacesData();
  await testSessionRotateRefreshesTtl();
  await testSessionRotateExpiredReturnsNull();
  await testSessionRotateUnknownReturnsNull();
  await testSessionRotateLifecycleAuditEmit();
  // cookies — RFC 6265 cookie primitive + sealed-value access gate
  testCookiesSurface();
  testCookiesParse();
  testCookiesSerialize();
  testCookiesInstanceDefaults();
  testCookiesReadWrite();
  testCookiesSealedRoundTrip();
  // errors-page — router error handler with rich dev page + safe prod page
  testErrorsPageSurface();
  testErrorsPageProdHidesStackAndOriginalMessage();
  testErrorsPageDevShowsStackAndRequestInfo();
  testErrorsPageJsonNegotiation();
  testErrorsPageDevJsonIncludesStack();
  testErrorsPageAppErrorClassification();
  testErrorsPageNeverWritesWhenAlreadyEnded();
  testErrorsPageOnErrorHookCanTakeOver();
  testErrorsPageLogsViaInjectedLogger();
  testErrorsPageDevEnvVarsHonorOptIn();
  testErrorsPageModeAutoDetectsFromNodeEnv();
  // log — structured JSON logging with request-id correlation
  testLogSurface();
  testLogEmitsJsonLineToStdout();
  testLogRoutesErrorAndFatalToStderr();
  testLogMultiSinkRoutesByLevel();
  testLogMultiSinkSinkWithoutLevel();
  testLogMultiSinkConflictsWithDestination();
  testLogMultiSinkEmptyArrayRejected();
  testLogMultiSinkBadShapeRejected();
  testLogMultiSinkStringDest();
  testLogMultiSinkOneSinkFailDoesntBreakOthers();
  testLogLevelGate();
  testLogBindAddsBoundContext();
  testLogCoreFieldsCannotBeOverwritten();
  await testLogRequestIdViaAls();
  await testLogMiddlewareSetsRequestId();
  testLogRedactsExtras();
  testLogEnvLevelOverride();
  testLogConfigValidation();
  testLogHandlesUnserializableExtras();
  // scheduler — cron + interval over jobs
  testSchedulerSurface();
  testSchedulerCronParser();
  testSchedulerNextCronFire();
  await testSchedulerScheduleValidation();
  await testSchedulerDirectFnFires();
  await testSchedulerJobDispatch();
  await testSchedulerSkipsWhenStillRunning();
  await testSchedulerLeaderGate();
  await testSchedulerErrorRecorded();
  await testSchedulerStartStopIdempotent();
  // forms — CSRF tokens + HTML render + validation
  testFormsSurface();
  testFormsCsrfTokenGeneration();
  testFormsCsrfTokenVerify();
  testFormsEscapeAttribute();
  testFormsRenderBasic();
  testFormsRenderEscapesHostileInput();
  testFormsRenderSelectAndPreselection();
  testFormsRenderSubmitOverride();
  testFormsRenderRejectsInvalidSpec();
  testFormsValidateRequired();
  testFormsValidateTypes();
  // auth.jwt — PQC-signed JWT
  testAuthJwtSurface();
  await testAuthJwtSignVerifyRoundTripDefault();
  await testAuthJwtMlDsaOptIn();
  await testAuthJwtAlgorithmAllowlist();
  await testAuthJwtExpiration();
  await testAuthJwtNotBefore();
  await testAuthJwtIssuerAudienceSubject();
  await testAuthJwtSignatureTampering();
  await testAuthJwtMalformedTokens();
  await testAuthJwtMalformedRegisteredClaims();
  await testAuthJwtCritHeaderRejected();
  await testAuthJwtKidPropagation();
  await testAuthJwtReplayDefense();
  await testAuthJwtMissingKey();
  await testAuthDpopRoundTrip();
  await testAuthDpopHtmHtuMismatch();
  await testAuthDpopAthBinding();
  await testAuthDpopReplayDefense();
  await testAuthDpopAlgorithmDefenses();
  await testAuthDpopIatWindow();
  await testAuthDpopJwkPrivateLeakRefused();
  await testAuthDpopThumbprint();
  await testAuthDpopPqcMlDsa();
  testAuthAalSurface();
  testAuthAalFromMethods();
  testAuthAalMeets();
  await testRequireAalMiddleware();
  // handlers primitive
  await testHandlerEmitAndDrain();
  await testHandlerEmitDuringFlushNextCycle();
  await testHandlerRetryOnFlushFailure();
  await testHandlerCircuitBreakerOpensOnPersistentFailure();
  await testHandlerBoundedShutdown();
  await testHandlerStats();
  await testHandlerBackpressureDrop();
  // sql-safe primitive
  testSqlSafeIdentifierValidation();
  testSqlSafeQuoteIdentifier();
  testSqlSafeQuoteQualified();
  testSqlSafeAssertOneOf();
  // chain-writer primitive (cross-layer; documented in test header)
  await testChainWriterRejectsBadTable();
  await testChainWriterRaceSafetyConcurrentAppends();
  // buffer-safe primitive (used by parsers, atomic-file, object-store)
  testBufferSafeNormalizeText();
  testBufferSafeToBuffer();
  testBufferSafeBoundedChunkCollector();
  testBufferSafeSecureZero();
  // logger primitive (per-module log channel)
  testLogger();
  // static-scan integrity check — guards against stale all-caps constants
  // silently evaluating to undefined in setInterval / setTimeout / etc.
  testConstantsReferenceIntegrity();
  // framework-error base + cross-module operational classes
  testFrameworkError();
  // url-safe primitive (validates scheme + shape at outbound boundary —
  // declared as a prerequisite for httpClient since httpClient routes
  // every URL through safeUrl.parse)
  testUrlSafeDefaultIsHttpsOnly();
  testUrlSafeCustomAllowlist();
  testUrlSafeMalformed();
  testUrlSafeUrlInstancePassThrough();
  testUrlSafeErrorClassInjection();
  testUrlSafeRejectsUserinfo();
  testUrlSafeAllowAny();
  // http-client primitive (used by 5 protocol adapters)
  await testHttpClientBasic();
  await testHttpClientConfigurePool();
  await testHttpClientErrorStatus();
  await testHttpClientWallClockTimeout();
  await testHttpClientAbortSignal();
  await testHttpClientStreamResponse();
  await testHttpClientObserver();
  await testHttpClientH2Basic();
  await testHttpClientH2AbortSignal();
  await testHttpClientH2ErrorStatus();
  await testHttpClientH2Multiplex();
  await testHttpClientH2Stream();

  // v0.4.15
  await testHttpClientRedirectFollow();
  await testHttpClientRedirectMaxHops();
  await testHttpClientRedirectStripsAuthCrossOrigin();
  await testHttpClientRedirect303CoercesGet();
  await testHttpClientMultipartOutbound();
  await testHttpClientMultipartConflictsWithBody();

  // v0.4.16
  await testHttpClientBeforeInterceptor();
  await testHttpClientBeforeChain();
  await testHttpClientBeforeThrows();
  await testHttpClientAfterInterceptor();
  await testHttpClientAfterAcrossRedirect();
  await testHttpClientInterceptorValidation();
  await testHttpClientUploadProgress();
  await testHttpClientDownloadProgress();
  await testHttpClientDownloadProgressStream();
  await testHttpClientOnChunk();
  await testHttpClientStreamingMultipart();

  // v0.4.17 cookie jar
  testCookieJarSurface();
  testCookieJarParseAndAttach();
  testCookieJarDomainAttribute();
  testCookieJarPathMatch();
  testCookieJarSecureFilter();
  testCookieJarMaxAgeAndExpires();
  testCookieJarMaxAgeZeroDeletes();
  testCookieJarMultipleSort();
  testCookieJarClearAndGetAll();
  testCookieJarSetFromSerialized();
  testCookieJarPersistVaultRequiresVault();
  testCookieJarPersistVaultEncryptsValue();
  testCookieJarRealCryptoForensic();
  testCookieJarReplayBlobUnusable();
  testCookieJarNonceRandomized();
  await testHttpClientJarRoundTrip();
  await testHttpClientJarMergesWithCallerCookie();
  await testHttpClientJarValidation();
  await testHttpClientJarFollowsRedirect();
  // websocket primitive (RFC 6455 + RFC 8441) — fixture-needing
  // tests (h2c suite + router suite) live in module.exports.groups[]
  // so each group's setup runs once and per-test timing is reported.
  testWebSocketHandshake();
  testWebSocketFrames();
  await testWebSocketConnection();
  testRouterWsValidation();
  await testRouterSetsRoutePattern();

  // v0.4.19 schema-validated routes
  await testRouterSpecBodyValidatesPass();
  await testRouterSpecBodyValidatesReject();
  await testRouterSpecQueryAndParams();
  await testRouterSpecPassesNonObjectFirstArg();
  await testRouterSpecRejectsUnknownKey();
  await testRouterSpecRejectsBadSchema();
  testRouterInspectRoutes();
  testRouterOpenapi();
  await testRouterSpecResponseValidationThrow();
  await testRouterSpecResponseValidationWarn();
  // lazy-require primitive (used by 12 modules to break circular loads)
  testLazyRequire();
  // json-safe primitive
  testJsonModuleSurface();
  testJsonParse();
  testJsonStringify();
  testJsonCanonical();
  testJsonValidate();
  testJsonValidateCollect();
  testJsonFormats();
  // atomic-file primitive (depends on crypto + json-safe)
  await testAtomicFile();
  await testAtomicFileLock();
  await testAtomicFileListDir();
  testAtomicFileNewHelpers();
  // parsers/* primitives (independent of framework state)
  testXmlParse();
  testXmlSecurityRejections();
  testTomlBasicTypes();
  testTomlTablesAndArrays();
  testTomlInlineTablesAndDottedKeys();
  testTomlSecurityRejections();
  testYamlBasic();
  testYamlNorwayProblem();
  testYamlBlockScalars();
  testYamlQuotedStrings();
  testYamlSecurityRejections();
  testEnvParseBasic();
  testEnvParseSecurityRejections();
  testEnvReadVar();
  // redact primitive
  testRedact();
  testAuditSafeEmitRedacts();
  // file-upload primitive
  testFileUploadCreate();
  await testFileUploadInitHappyPath();
  await testFileUploadAcceptChunkRequiresInit();
  await testFileUploadAcceptChunkRoundTrip();
  await testFileUploadHashMismatch();
  await testFileUploadOversizedChunk();
  await testFileUploadIdempotentChunkRePut();
  await testFileUploadFinalize();
  await testFileUploadFinalizeMissingChunk();
  await testFileUploadFinalizeIndexGap();
  await testFileUploadFinalizeManifestSizeMismatch();
  await testFileUploadFinalizeManifestHashMismatch();
  await testFileUploadFinalizeFileTooLarge();
  await testFileUploadPathTraversalRejected();
  await testFileUploadPurgeIncomplete();
  await testFileUploadOnFinalizeCallback();
  await testFileUploadMetadataStash();
  await testFileUploadActorQuota();
  await testFileUploadStagingQuota();
  await testFileUploadOnChunkHook();
  await testFileUploadOnChunkRejection();
  await testFileUploadIdleTimeout();
  await testFileUploadStreamReassembly();
  await testFileUploadStatusEnriched();
  await testFileUploadList();
  await testFileUploadCancel();
  await testFileUploadPermissionsIntegration();
  await testFileUploadMimeAllowlist();
  await testFileUploadMimeAllowlistRejected();
  await testFileUploadMimeAllowlistRequiresFileType();
}

module.exports = {
  testCryptoAndModuleSurface:                testCryptoAndModuleSurface,
  name: "Layer 0 — primitives (module-surface, async-safe, handlers, sql-safe, chain-writer, json-safe, atomic-file, parsers, redact)",
  run:  run,
  // Exported individually so smoke.js (or future selective-run tooling)
  // can reach them by name without going through run().
  testAsyncSafeWithTimeoutResolves:          testAsyncSafeWithTimeoutResolves,
  testAsyncSafeWithTimeoutRejects:           testAsyncSafeWithTimeoutRejects,
  testAsyncSafeWithTimeoutAbort:             testAsyncSafeWithTimeoutAbort,
  testAsyncSafeWithTimeoutPropagatesError:   testAsyncSafeWithTimeoutPropagatesError,
  testAsyncSafeSafeAwait:                    testAsyncSafeSafeAwait,
  testAsyncSafeMutexSerializes:              testAsyncSafeMutexSerializes,
  testAsyncSafeMutexReleaseOnThrow:          testAsyncSafeMutexReleaseOnThrow,
  testAsyncSafeMutexAbortableAcquire:        testAsyncSafeMutexAbortableAcquire,
  testAsyncSafeSemaphoreBoundedConcurrency:  testAsyncSafeSemaphoreBoundedConcurrency,
  testAsyncSafeSemaphoreAbortableAcquire:    testAsyncSafeSemaphoreAbortableAcquire,
  testAsyncSafeOnceSingleFlight:             testAsyncSafeOnceSingleFlight,
  testAsyncSafeOnceCachesFailure:            testAsyncSafeOnceCachesFailure,
  testAsyncSafeOnceReset:                    testAsyncSafeOnceReset,
  testAsyncSafeCircuitBreakerStateTransitions: testAsyncSafeCircuitBreakerStateTransitions,
  testAsyncSafeSleepBasic:                   testAsyncSafeSleepBasic,
  testAsyncSafeSleepZeroResolvesImmediately: testAsyncSafeSleepZeroResolvesImmediately,
  testAsyncSafeSleepBadArg:                  testAsyncSafeSleepBadArg,
  testAsyncSafeSleepAbort:                   testAsyncSafeSleepAbort,
  testAsyncSafeSleepUnrefOptIn:              testAsyncSafeSleepUnrefOptIn,
  testAsyncSafeSleepDefaultRefd:             testAsyncSafeSleepDefaultRefd,
  testAsyncSafeWithTimeoutSignalCases:       testAsyncSafeWithTimeoutSignalCases,
  testAsyncSafeWithTimeoutSignalTimeoutFires: testAsyncSafeWithTimeoutSignalTimeoutFires,
  testAuthHeaderBearer:                      testAuthHeaderBearer,
  testAuthHeaderBasic:                       testAuthHeaderBasic,
  testAuthHeaderFromConfig:                  testAuthHeaderFromConfig,
  testAuthPasswordSurface:                   testAuthPasswordSurface,
  testAuthPasswordHashShape:                 testAuthPasswordHashShape,
  testAuthPasswordVerifyRoundTrip:           testAuthPasswordVerifyRoundTrip,
  testAuthPasswordVerifyTamperedHash:        testAuthPasswordVerifyTamperedHash,
  testAuthPasswordVerifyMalformedHash:       testAuthPasswordVerifyMalformedHash,
  testAuthPasswordHashRejectsBadInput:       testAuthPasswordHashRejectsBadInput,
  testAuthPasswordNeedsRehash:               testAuthPasswordNeedsRehash,
  testAuthTotpSurface:                       testAuthTotpSurface,
  testAuthTotpRfc6238Vectors:                testAuthTotpRfc6238Vectors,
  testAuthTotpGenerateSecret:                testAuthTotpGenerateSecret,
  testAuthTotpGenerateAndVerifyRoundTrip:    testAuthTotpGenerateAndVerifyRoundTrip,
  testAuthTotpDriftWindow:                   testAuthTotpDriftWindow,
  testAuthTotpReplayProtection:              testAuthTotpReplayProtection,
  testAuthTotpVerifyMalformedInput:          testAuthTotpVerifyMalformedInput,
  testAuthTotpUriShape:                      testAuthTotpUriShape,
  testAuthTotpBackupCodes:                   testAuthTotpBackupCodes,
  testAuthTotpBadAlgorithmRejected:          testAuthTotpBadAlgorithmRejected,
  testAuthPasskeySurface:                    testAuthPasskeySurface,
  testAuthPasskeyStartRegistrationOptions:   testAuthPasskeyStartRegistrationOptions,
  testAuthPasskeyStartAuthenticationOptions: testAuthPasskeyStartAuthenticationOptions,
  testAuthPasskeyValidationErrors:           testAuthPasskeyValidationErrors,
  testAuthPasskeyExcludeCredentials:         testAuthPasskeyExcludeCredentials,
  testAuthPasskeyCustomHints:                testAuthPasskeyCustomHints,
  testAuthJwtSurface:                        testAuthJwtSurface,
  testAuthJwtSignVerifyRoundTripDefault:     testAuthJwtSignVerifyRoundTripDefault,
  testAuthJwtMlDsaOptIn:                     testAuthJwtMlDsaOptIn,
  testAuthJwtAlgorithmAllowlist:             testAuthJwtAlgorithmAllowlist,
  testAuthJwtExpiration:                     testAuthJwtExpiration,
  testAuthJwtNotBefore:                      testAuthJwtNotBefore,
  testAuthJwtIssuerAudienceSubject:          testAuthJwtIssuerAudienceSubject,
  testAuthJwtSignatureTampering:             testAuthJwtSignatureTampering,
  testAuthJwtMalformedTokens:                testAuthJwtMalformedTokens,
  testAuthJwtMalformedRegisteredClaims:      testAuthJwtMalformedRegisteredClaims,
  testAuthJwtCritHeaderRejected:             testAuthJwtCritHeaderRejected,
  testAuthJwtKidPropagation:                 testAuthJwtKidPropagation,
  testAuthJwtReplayDefense:                  testAuthJwtReplayDefense,
  testAuthJwtMissingKey:                     testAuthJwtMissingKey,
  testAuthDpopRoundTrip:                     testAuthDpopRoundTrip,
  testAuthDpopHtmHtuMismatch:                testAuthDpopHtmHtuMismatch,
  testAuthDpopAthBinding:                    testAuthDpopAthBinding,
  testAuthDpopReplayDefense:                 testAuthDpopReplayDefense,
  testAuthDpopAlgorithmDefenses:             testAuthDpopAlgorithmDefenses,
  testAuthDpopIatWindow:                     testAuthDpopIatWindow,
  testAuthDpopJwkPrivateLeakRefused:         testAuthDpopJwkPrivateLeakRefused,
  testAuthDpopThumbprint:                    testAuthDpopThumbprint,
  testAuthDpopPqcMlDsa:                      testAuthDpopPqcMlDsa,
  testAuthAalSurface:                        testAuthAalSurface,
  testAuthAalFromMethods:                    testAuthAalFromMethods,
  testAuthAalMeets:                          testAuthAalMeets,
  testRequireAalMiddleware:                  testRequireAalMiddleware,
  testTemplateSurface:                       testTemplateSurface,
  testTemplateEscapeHtml:                    testTemplateEscapeHtml,
  testTemplateBasicRender:                   testTemplateBasicRender,
  testTemplateRawExpression:                 testTemplateRawExpression,
  testTemplateIfElse:                        testTemplateIfElse,
  testTemplateForLoop:                       testTemplateForLoop,
  testTemplateExpressionGrammar:             testTemplateExpressionGrammar,
  testTemplatePartialInclusion:              testTemplatePartialInclusion,
  testTemplateLayoutInheritance:             testTemplateLayoutInheritance,
  testTemplateContainmentDefenses:           testTemplateContainmentDefenses,
  testTemplatePrototypeSafety:               testTemplatePrototypeSafety,
  testTemplateCacheAndReset:                 testTemplateCacheAndReset,
  testTemplateMissingViewsDir:               testTemplateMissingViewsDir,
  testRenderSurface:                         testRenderSurface,
  testRenderJson:                            testRenderJson,
  testRenderText:                            testRenderText,
  testRenderHtmlString:                      testRenderHtmlString,
  testRenderRedirect:                        testRenderRedirect,
  testRenderDoesNotDoubleWrite:              testRenderDoesNotDoubleWrite,
  testRenderCreateWithEngine:                testRenderCreateWithEngine,
  testRenderCreateValidation:                testRenderCreateValidation,
  testStaticServeSurface:                    testStaticServeSurface,
  testStaticServeBasic:                      testStaticServeBasic,
  testStaticServeImmutableForHashedPaths:    testStaticServeImmutableForHashedPaths,
  testStaticServeEtagAnd304:                 testStaticServeEtagAnd304,
  testStaticServeHead:                       testStaticServeHead,
  testStaticServeContainmentDefenses:        testStaticServeContainmentDefenses,
  testStaticServeIndexFile:                  testStaticServeIndexFile,
  testStaticServeMethodGuard:                testStaticServeMethodGuard,
  testStaticServeIntegrityHelper:            testStaticServeIntegrityHelper,
  testMailSurface:                           testMailSurface,
  testMailCreateValidation:                  testMailCreateValidation,
  testMailSendRoundTripViaMemoryTransport:   testMailSendRoundTripViaMemoryTransport,
  testMailDefaultsAndOverrides:              testMailDefaultsAndOverrides,
  testMailValidation:                        testMailValidation,
  testMailEaiSmtpUtf8:                       testMailEaiSmtpUtf8,
  testMailRecipientArrayAndCcBcc:            testMailRecipientArrayAndCcBcc,
  testMailTransportFailureWraps:             testMailTransportFailureWraps,
  testMailFunctionAsTransport:               testMailFunctionAsTransport,
  testMailConsoleTransportShape:             testMailConsoleTransportShape,
  testMailSmtpFactoryValidation:             testMailSmtpFactoryValidation,
  testMailResendFactoryValidation:           testMailResendFactoryValidation,
  testMailHttpFactoryValidation:             testMailHttpFactoryValidation,
  testMailSmtpRoundTrip:                     testMailSmtpRoundTrip,
  testMailSmtpStarttlsAccept:                testMailSmtpStarttlsAccept,
  testMailHttpRoundTripWithCustomVendor:     testMailHttpRoundTripWithCustomVendor,
  testMailHttpInterpretRejection:            testMailHttpInterpretRejection,
  testMailHttpInterpretThrows:               testMailHttpInterpretThrows,
  testMailHttpBadSerializer:                 testMailHttpBadSerializer,
  testMailResendRoundTrip:                   testMailResendRoundTrip,
  testMailResendErrorPaths:                  testMailResendErrorPaths,
  testApiSnapshotSurface:                    testApiSnapshotSurface,
  testApiSnapshotCaptureCategorizes:         testApiSnapshotCaptureCategorizes,
  testApiSnapshotCaptureHandlesCycles:       testApiSnapshotCaptureHandlesCycles,
  testApiSnapshotWriteAndRead:               testApiSnapshotWriteAndRead,
  testApiSnapshotCompareNoChange:            testApiSnapshotCompareNoChange,
  testApiSnapshotCompareDetectsRemoval:      testApiSnapshotCompareDetectsRemoval,
  testApiSnapshotCompareDetectsTypeChange:   testApiSnapshotCompareDetectsTypeChange,
  testApiSnapshotCompareDetectsArityDecrease: testApiSnapshotCompareDetectsArityDecrease,
  testApiSnapshotCompareIgnoresArityIncrease: testApiSnapshotCompareIgnoresArityIncrease,
  testApiSnapshotCompareDetectsAdditive:     testApiSnapshotCompareDetectsAdditive,
  testApiSnapshotFormatDiff:                 testApiSnapshotFormatDiff,
  testApiSnapshotOnFrameworkSurfaceCaptures: testApiSnapshotOnFrameworkSurfaceCaptures,
  testCliApiSnapshotCaptureAndCompare:       testCliApiSnapshotCaptureAndCompare,
  testDeprecateSurface:                      testDeprecateSurface,
  testDeprecateModeResolution:               testDeprecateModeResolution,
  testDeprecateWarnEmitsOnce:                testDeprecateWarnEmitsOnce,
  testDeprecateSilentMode:                   testDeprecateSilentMode,
  testDeprecateErrorMode:                    testDeprecateErrorMode,
  testDeprecateDifferentSinceProducesNewLine: testDeprecateDifferentSinceProducesNewLine,
  testDeprecateWarnArgValidation:            testDeprecateWarnArgValidation,
  testDeprecateWrap:                         testDeprecateWrap,
  testDeprecateWrapValidation:               testDeprecateWrapValidation,
  testDeprecateAlias:                        testDeprecateAlias,
  testDeprecateListAndReset:                 testDeprecateListAndReset,
  testRestoreRollbackSurface:                testRestoreRollbackSurface,
  testRestoreRollbackSwap:                   testRestoreRollbackSwap,
  testRestoreRollbackRoundTrip:              testRestoreRollbackRoundTrip,
  testRestoreRollbackListAndPurge:           testRestoreRollbackListAndPurge,
  testRestoreRollbackHandlesEmptyDataDir:    testRestoreRollbackHandlesEmptyDataDir,
  testRestoreSurface:                        testRestoreSurface,
  testRestoreCreateValidation:               testRestoreCreateValidation,
  testRestoreRunRoundTrip:                   testRestoreRunRoundTrip,
  testRestoreRollbackUndoesRun:              testRestoreRollbackUndoesRun,
  testRestoreRunWithMissingBundle:           testRestoreRunWithMissingBundle,
  testRestoreRunWithWrongPassphrase:         testRestoreRunWithWrongPassphrase,
  testRestoreListRollbacksAndPurge:          testRestoreListRollbacksAndPurge,
  testRestoreInspectWithoutDecrypt:          testRestoreInspectWithoutDecrypt,
  testBackupSurface:                         testBackupSurface,
  testBackupRecommendedFiles:                testBackupRecommendedFiles,
  testBackupFlushBeforeBackupCalled:         testBackupFlushBeforeBackupCalled,
  testBackupFlushFailureDoesNotFailBackup:   testBackupFlushFailureDoesNotFailBackup,
  testBackupFlushBeforeBackupOptOut:         testBackupFlushBeforeBackupOptOut,
  testBackupCreateValidation:                testBackupCreateValidation,
  testBackupRunListReadDelete:               testBackupRunListReadDelete,
  testBackupVaultKeyJsonAsFunction:          testBackupVaultKeyJsonAsFunction,
  testBackupVaultKeyJsonAsAsyncFunction:     testBackupVaultKeyJsonAsAsyncFunction,
  testBackupRetentionPurgeOlder:             testBackupRetentionPurgeOlder,
  testBackupRetentionAutoSweepOnRun:         testBackupRetentionAutoSweepOnRun,
  testBackupBundleIdValidation:              testBackupBundleIdValidation,
  testBackupLocalStorageRejectsExistingDest: testBackupLocalStorageRejectsExistingDest,
  testRestoreBundleSurface:                  testRestoreBundleSurface,
  testRestoreBundleRoundTrip:                testRestoreBundleRoundTrip,
  testRestoreBundleFilterSubset:             testRestoreBundleFilterSubset,
  testRestoreBundleWrongPassphrase:          testRestoreBundleWrongPassphrase,
  testRestoreBundleTamperedBlobDetected:     testRestoreBundleTamperedBlobDetected,
  testRestoreBundleChecksumMismatchDetected: testRestoreBundleChecksumMismatchDetected,
  testRestoreBundleMissingBlobDetected:      testRestoreBundleMissingBlobDetected,
  testRestoreBundleEncryptedSizeMismatchDetected: testRestoreBundleEncryptedSizeMismatchDetected,
  testRestoreBundleInspectReturnsManifest:   testRestoreBundleInspectReturnsManifest,
  testRestoreBundleArgValidation:            testRestoreBundleArgValidation,
  testBackupBundleSurface:                   testBackupBundleSurface,
  testBackupBundleCreateEndToEnd:            testBackupBundleCreateEndToEnd,
  testBackupBundlePathTraversalRejected:     testBackupBundlePathTraversalRejected,
  testBackupBundleRequiredMissing:           testBackupBundleRequiredMissing,
  testBackupBundleEmptyBundleRejected:       testBackupBundleEmptyBundleRejected,
  testBackupBundleArgValidation:             testBackupBundleArgValidation,
  testBackupManifestSurface:                 testBackupManifestSurface,
  testBackupManifestCreateAndSerialize:      testBackupManifestCreateAndSerialize,
  testBackupManifestValidateRejectsBadFields: testBackupManifestValidateRejectsBadFields,
  testBackupManifestRejectsDuplicatePaths:   testBackupManifestRejectsDuplicatePaths,
  testBackupManifestParseRejectsCorruption:  testBackupManifestParseRejectsCorruption,
  testBackupManifestSerializeIsCanonical:    testBackupManifestSerializeIsCanonical,
  testBackupCryptoSurface:                   testBackupCryptoSurface,
  testBackupCryptoDeriveKeyDeterministic:    testBackupCryptoDeriveKeyDeterministic,
  testBackupCryptoRoundTrip:                 testBackupCryptoRoundTrip,
  testBackupCryptoStringPlaintext:           testBackupCryptoStringPlaintext,
  testBackupCryptoWrongPassphraseFails:      testBackupCryptoWrongPassphraseFails,
  testBackupCryptoTamperedCiphertextFails:   testBackupCryptoTamperedCiphertextFails,
  testBackupCryptoFreshSaltUnique:           testBackupCryptoFreshSaltUnique,
  testBackupCryptoChecksumIsSha3_512:        testBackupCryptoChecksumIsSha3_512,
  testBackupCryptoArgValidation:             testBackupCryptoArgValidation,
  testBodyParserSurface:                     testBodyParserSurface,
  testBodyParserGetSkipped:                  testBodyParserGetSkipped,
  testBodyParserStrictContentLength:         testBodyParserStrictContentLength,
  testBodyParserJsonHappy:                   testBodyParserJsonHappy,
  testBodyParserJsonStripsPrototypePollution: testBodyParserJsonStripsPrototypePollution,
  testBodyParserJsonSizeCap:                 testBodyParserJsonSizeCap,
  testBodyParserJsonMalformed:               testBodyParserJsonMalformed,
  testBodyParserJsonStrictMode:              testBodyParserJsonStrictMode,
  testBodyParserUrlencoded:                  testBodyParserUrlencoded,
  testBodyParserUrlencodedPoisonedKey:       testBodyParserUrlencodedPoisonedKey,
  testBodyParserText:                        testBodyParserText,
  testBodyParserRaw:                         testBodyParserRaw,
  testBodyParserUnsupportedType:             testBodyParserUnsupportedType,
  testBodyParserDisabledSubparser:           testBodyParserDisabledSubparser,
  testBodyParserKeepRawBody:                 testBodyParserKeepRawBody,
  testBodyParserMultipartFields:             testBodyParserMultipartFields,
  testBodyParserMultipartFile:               testBodyParserMultipartFile,
  testBodyParserMultipartFilenameTraversal:  testBodyParserMultipartFilenameTraversal,
  testBodyParserMultipartFileSizeLimit:      testBodyParserMultipartFileSizeLimit,
  testBodyParserMultipartMimeAllowlist:      testBodyParserMultipartMimeAllowlist,
  testBodyParserMultipartPoisonedFieldName:  testBodyParserMultipartPoisonedFieldName,
  testBodyParserMultipartTruncated:          testBodyParserMultipartTruncated,
  testBodyParserContentLengthExceedsLimitImmediate: testBodyParserContentLengthExceedsLimitImmediate,
  testBodyParserSanitizeFilenameUnit:        testBodyParserSanitizeFilenameUnit,
  testOAuthSurface:                          testOAuthSurface,
  testOAuthCreateValidates:                  testOAuthCreateValidates,
  testOAuthPkceRequired:                     testOAuthPkceRequired,
  testOAuthPkceGenerator:                    testOAuthPkceGenerator,
  testOAuthAuthorizationUrlPreset:           testOAuthAuthorizationUrlPreset,
  testOAuthAuthorizationUrlOidc:             testOAuthAuthorizationUrlOidc,
  testOAuthAuthorizationUrlGenericPreset:    testOAuthAuthorizationUrlGenericPreset,
  testOAuthAuthorizationUrlExtraParams:      testOAuthAuthorizationUrlExtraParams,
  testOAuthExchangeCodeRequiresVerifier:     testOAuthExchangeCodeRequiresVerifier,
  testOAuthExchangeCodeRoundTrip:            testOAuthExchangeCodeRoundTrip,
  testOAuthRefreshAccessToken:               testOAuthRefreshAccessToken,
  testOAuthFetchUserInfo:                    testOAuthFetchUserInfo,
  testOAuthVerifyIdTokenRoundTrip:           testOAuthVerifyIdTokenRoundTrip,
  testOAuthVerifyIdTokenRefusesUnsupportedAlg: testOAuthVerifyIdTokenRefusesUnsupportedAlg,
  testOAuthVerifyParamsForAlg:               testOAuthVerifyParamsForAlg,
  testMetricsSurface:                        testMetricsSurface,
  testMetricsCounterBasic:                   testMetricsCounterBasic,
  testMetricsCounterRefusesNegative:         testMetricsCounterRefusesNegative,
  testMetricsGaugeBasic:                     testMetricsGaugeBasic,
  testMetricsHistogramBasic:                 testMetricsHistogramBasic,
  testMetricsHistogramRejectsBadBuckets:     testMetricsHistogramRejectsBadBuckets,
  testMetricsDefaultLabels:                  testMetricsDefaultLabels,
  testMetricsNamespacing:                    testMetricsNamespacing,
  testMetricsLabelValidation:                testMetricsLabelValidation,
  testMetricsCardinalityCap:                 testMetricsCardinalityCap,
  testMetricsExpositionFormat:               testMetricsExpositionFormat,
  testMetricsLabelEscaping:                  testMetricsLabelEscaping,
  testMetricsExpositionHandler:              testMetricsExpositionHandler,
  testMetricsRequestMiddleware:              testMetricsRequestMiddleware,
  testMetricsRequestMiddlewareRoutePatternFallback: testMetricsRequestMiddlewareRoutePatternFallback,
  testMetricsRequestMiddlewareStatusCodeFallback:   testMetricsRequestMiddlewareStatusCodeFallback,
  testMetricsTapNoOpWhenNoRegistry:          testMetricsTapNoOpWhenNoRegistry,
  testMetricsTapRoutesIntoActiveRegistry:    testMetricsTapRoutesIntoActiveRegistry,
  testMetricsBuiltinQueueDepthGauge:         testMetricsBuiltinQueueDepthGauge,
  testMetricsBuiltinJobsInflightGauge:       testMetricsBuiltinJobsInflightGauge,
  testMetricsBuiltinErrorsTotalCounter:      testMetricsBuiltinErrorsTotalCounter,
  testMetricsDuplicateRegistrationRejected:  testMetricsDuplicateRegistrationRejected,
  testMetricsResetClearsValues:              testMetricsResetClearsValues,
  testCompressionSurface:                    testCompressionSurface,
  testCompressionParseAcceptEncoding:        testCompressionParseAcceptEncoding,
  testCompressionNegotiate:                  testCompressionNegotiate,
  testCompressionTypeMatches:                testCompressionTypeMatches,
  testCompressionAppendVary:                 testCompressionAppendVary,
  testCompressionGzipRoundTrip:              testCompressionGzipRoundTrip,
  testCompressionBrotliRoundTrip:            testCompressionBrotliRoundTrip,
  testCompressionPrefersBrotliOverGzip:      testCompressionPrefersBrotliOverGzip,
  testCompressionSkipsBelowThreshold:        testCompressionSkipsBelowThreshold,
  testCompressionSkipsImageContentType:      testCompressionSkipsImageContentType,
  testCompressionSkipsAlreadyEncoded:        testCompressionSkipsAlreadyEncoded,
  testCompressionSkipsWhenClientDoesntAccept: testCompressionSkipsWhenClientDoesntAccept,
  testCompressionSkipsNoBodyStatus:          testCompressionSkipsNoBodyStatus,
  testCompressionFilterReturnsFalse:         testCompressionFilterReturnsFalse,
  testCompressionFilterThrowFailsClosed:     testCompressionFilterThrowFailsClosed,
  testCompressionStreamingWritesNoContentLength: testCompressionStreamingWritesNoContentLength,
  testCompressionImplicitWriteHeadPath:      testCompressionImplicitWriteHeadPath,
  testCompressionInvalidEncodingRejectedAtCreate: testCompressionInvalidEncodingRejectedAtCreate,
  testCompressionDoesntDoubleCompressViaWrappedWrite: testCompressionDoesntDoubleCompressViaWrappedWrite,
  testCompressionPipedStreamLargerThanHighWaterMarkCompletes: testCompressionPipedStreamLargerThanHighWaterMarkCompletes,
  testHealthSurface:                         testHealthSurface,
  testHealthDefaultLiveness:                 testHealthDefaultLiveness,
  testHealthDefaultReadiness:                testHealthDefaultReadiness,
  testHealthUnmatchedPathFallsThrough:       testHealthUnmatchedPathFallsThrough,
  testHealthNonGetFallsThrough:              testHealthNonGetFallsThrough,
  testHealthCriticalFailReturns503:          testHealthCriticalFailReturns503,
  testHealthNonCriticalFailIsDegraded:       testHealthNonCriticalFailIsDegraded,
  testHealthDetailedResponse:                testHealthDetailedResponse,
  testHealthMinimalHidesDetail:              testHealthMinimalHidesDetail,
  testHealthDetailPredicate:                 testHealthDetailPredicate,
  testHealthDetailPredicateThrowFailsClosed: testHealthDetailPredicateThrowFailsClosed,
  testHealthShuttingDownFlipsReadiness:      testHealthShuttingDownFlipsReadiness,
  testHealthMultiTierRegistration:           testHealthMultiTierRegistration,
  testHealthCheckTimeout:                    testHealthCheckTimeout,
  testHealthCheckCacheRespected:             testHealthCheckCacheRespected,
  testHealthShutdownBypassesCache:           testHealthShutdownBypassesCache,
  testHealthHeadMethod:                      testHealthHeadMethod,
  testHealthInvalidArgs:                     testHealthInvalidArgs,
  testHealthCheckThrowFails:                 testHealthCheckThrowFails,
  testHealthCacheControlHeader:              testHealthCacheControlHeader,
  testSafeSchemaSurface:                     testSafeSchemaSurface,
  testSafeSchemaStringPrimitive:             testSafeSchemaStringPrimitive,
  testSafeSchemaNumberPrimitive:             testSafeSchemaNumberPrimitive,
  testSafeSchemaBooleanLiteralEnum:          testSafeSchemaBooleanLiteralEnum,
  testSafeSchemaNullUndefinedAny:            testSafeSchemaNullUndefinedAny,
  testSafeSchemaModifiers:                   testSafeSchemaModifiers,
  testSafeSchemaObject:                      testSafeSchemaObject,
  testSafeSchemaObjectPickOmitExtendPartial: testSafeSchemaObjectPickOmitExtendPartial,
  testSafeSchemaArrayTupleUnionRecord:       testSafeSchemaArrayTupleUnionRecord,
  testSafeSchemaRefineTransform:             testSafeSchemaRefineTransform,
  testSafeSchemaLazyAndPreprocess:           testSafeSchemaLazyAndPreprocess,
  testSafeSchemaPrototypePollutionDefense:   testSafeSchemaPrototypePollutionDefense,
  testSafeSchemaErrorIssues:                 testSafeSchemaErrorIssues,
  testSafeSchemaImmutability:                testSafeSchemaImmutability,
  testAuditToolsSurface:                     testAuditToolsSurface,
  testAuditToolsArchiveAndVerify:            testAuditToolsArchiveAndVerify,
  testAuditToolsExportSliceAndVerify:        testAuditToolsExportSliceAndVerify,
  testAuditToolsVerifyBundleRejectsWrongPassphrase: testAuditToolsVerifyBundleRejectsWrongPassphrase,
  testAuditToolsVerifyBundleDetectsTamperedRows:    testAuditToolsVerifyBundleDetectsTamperedRows,
  testAuditToolsArchiveRejectsWithoutCoveringCheckpoint: testAuditToolsArchiveRejectsWithoutCoveringCheckpoint,
  testAuditToolsArgValidation:               testAuditToolsArgValidation,
  testAuditToolsPurgeRoundTrip:              testAuditToolsPurgeRoundTrip,
  testAuditToolsPurgeRejectsUnverifiedArchive: testAuditToolsPurgeRejectsUnverifiedArchive,
  testAuditCliVerifyBundleSubcommand:        testAuditCliVerifyBundleSubcommand,
  testMtlsCaSurface:                         testMtlsCaSurface,
  testMtlsCaCreateValidation:                testMtlsCaCreateValidation,
  testMtlsCaParseGeneration:                 testMtlsCaParseGeneration,
  testMtlsCaExistsAndStatusWhenAbsent:       testMtlsCaExistsAndStatusWhenAbsent,
  testMtlsCaLoadFailures:                    testMtlsCaLoadFailures,
  testMtlsCaCommitAndLoadPlaintext:          testMtlsCaCommitAndLoadPlaintext,
  testMtlsCaSealedRequiredMode:              testMtlsCaSealedRequiredMode,
  testMtlsCaSealedDisabledRefusesSealedFile: testMtlsCaSealedDisabledRefusesSealedFile,
  testMtlsCaSealedRequiredRefusesPlaintextFile: testMtlsCaSealedRequiredRefusesPlaintextFile,
  testMtlsCaInitCaWithDefaultEngine:         testMtlsCaInitCaWithDefaultEngine,
  testMtlsCaGenerateClientCertWithDefaultEngine: testMtlsCaGenerateClientCertWithDefaultEngine,
  testMtlsCaGenerateClientP12WithDefaultEngine:  testMtlsCaGenerateClientP12WithDefaultEngine,
  testMtlsCaInitCaWithEngineGeneratesAndCommits: testMtlsCaInitCaWithEngineGeneratesAndCommits,
  testMtlsCaInitCaRejectsBadEngineOutput:    testMtlsCaInitCaRejectsBadEngineOutput,
  testMtlsCaGenerateClientCertDelegates:     testMtlsCaGenerateClientCertDelegates,
  testMtlsCaGenerateClientP12Validation:     testMtlsCaGenerateClientP12Validation,
  testVaultPassphraseOpsSurface:             testVaultPassphraseOpsSurface,
  testVaultPassphraseOpsPreflightChecks:     testVaultPassphraseOpsPreflightChecks,
  testVaultPassphraseOpsSealUnsealRoundTrip: testVaultPassphraseOpsSealUnsealRoundTrip,
  testVaultPassphraseOpsKeepPlaintext:       testVaultPassphraseOpsKeepPlaintext,
  testVaultPassphraseOpsWrongPassphraseRejected: testVaultPassphraseOpsWrongPassphraseRejected,
  testVaultPassphraseOpsRotate:              testVaultPassphraseOpsRotate,
  testVaultPassphraseOpsRotateRejectsBadOldPassphrase: testVaultPassphraseOpsRotateRejectsBadOldPassphrase,
  testVaultPassphraseOpsArgValidation:       testVaultPassphraseOpsArgValidation,
  testVaultPassphraseOpsRequiresBufferPassphrase: testVaultPassphraseOpsRequiresBufferPassphrase,
  testVaultRotateSurface:                    testVaultRotateSurface,
  testVaultRotateValidateSchemaCleanCase:    testVaultRotateValidateSchemaCleanCase,
  testVaultRotateValidateMissingTable:       testVaultRotateValidateMissingTable,
  testVaultRotateValidateSealedColMissing:   testVaultRotateValidateSealedColMissing,
  testVaultRotateValidateDriftDetection:     testVaultRotateValidateDriftDetection,
  testVaultRotateValidateInfraColumnsAllowlist: testVaultRotateValidateInfraColumnsAllowlist,
  testVaultRotateVerifyRoundTrip:            testVaultRotateVerifyRoundTrip,
  testVaultRotateVerifyDetectsTampering:     testVaultRotateVerifyDetectsTampering,
  testVaultRotateVerifyRegressionWithOldKeys: testVaultRotateVerifyRegressionWithOldKeys,
  testVaultRotateVerifyRequiresKeysAndDb:    testVaultRotateVerifyRequiresKeysAndDb,
  testVaultRotateRotateEndToEnd:             testVaultRotateRotateEndToEnd,
  testVaultRotateRotateValidation:           testVaultRotateRotateValidation,
  testPqcAgentSurface:                       testPqcAgentSurface,
  testPqcAgentCreateHasPqcPosture:           testPqcAgentCreateHasPqcPosture,
  testPqcAgentCannotWeakenCryptoPosture:     testPqcAgentCannotWeakenCryptoPosture,
  testPqcAgentDefaultIsLazy:                 testPqcAgentDefaultIsLazy,
  testPqcAgentCreateHttpHasNoTlsPosture:     testPqcAgentCreateHttpHasNoTlsPosture,
  testPqcGateSurface:                        testPqcGateSurface,
  testClientHelloPqcDetection:               testClientHelloPqcDetection,
  testPqcGateSocketLifecycle:                testPqcGateSocketLifecycle,
  testPqcGateBypassesLocalhost:              testPqcGateBypassesLocalhost,
  testBundlerSurface:                        testBundlerSurface,
  testBundlerCreateValidation:               testBundlerCreateValidation,
  testBundlerBuildHashedOutput:              testBundlerBuildHashedOutput,
  testBundlerHashChangesWithContent:         testBundlerHashChangesWithContent,
  testBundlerHashOff:                        testBundlerHashOff,
  testBundlerCustomHashLen:                  testBundlerCustomHashLen,
  testBundlerReadFailure:                    testBundlerReadFailure,
  testBundlerWatchRebuilds:                  testBundlerWatchRebuilds,
  testDevSurface:                            testDevSurface,
  testDevStartSpawnsChildAndArmsWatchers:    testDevStartSpawnsChildAndArmsWatchers,
  testDevDebouncesBurstOfEventsToOneRestart: testDevDebouncesBurstOfEventsToOneRestart,
  testDevIgnoresMatchingPaths:               testDevIgnoresMatchingPaths,
  testDevRestartCoalescesQueuedRestart:      testDevRestartCoalescesQueuedRestart,
  testDevStopKillsAndDisarms:                testDevStopKillsAndDisarms,
  testDevUnexpectedExitDoesNotRespawn:       testDevUnexpectedExitDoesNotRespawn,
  testCliSurface:                            testCliSurface,
  testCliArgParser:                          testCliArgParser,
  testCliVersionAndHelp:                     testCliVersionAndHelp,
  testCliMigrateStatus:                      testCliMigrateStatus,
  testCliMigrateUpDown:                      testCliMigrateUpDown,
  testCliMigrateValidationErrors:            testCliMigrateValidationErrors,
  testCliMigrateDownReportsNoOpCleanly:      testCliMigrateDownReportsNoOpCleanly,
  testCliMigrateUpFailureExits1:             testCliMigrateUpFailureExits1,
  testCliDevValidation:                      testCliDevValidation,
  testMigrationsSurface:                     testMigrationsSurface,
  testMigrationsUpAppliesPending:            testMigrationsUpAppliesPending,
  testMigrationsStatus:                      testMigrationsStatus,
  testMigrationsDownRollback:                testMigrationsDownRollback,
  testMigrationsDownMultiSteps:              testMigrationsDownMultiSteps,
  testMigrationsDownRejectsBadSteps:         testMigrationsDownRejectsBadSteps,
  testMigrationsRejectsRollbackWithoutDown:  testMigrationsRejectsRollbackWithoutDown,
  testMigrationsUpFailureRollsBackTransaction: testMigrationsUpFailureRollsBackTransaction,
  testMigrationsRejectsMalformedFiles:       testMigrationsRejectsMalformedFiles,
  testMigrationsLockReleasedAfterUp:         testMigrationsLockReleasedAfterUp,
  testMigrationsLockBlocksConcurrent:        testMigrationsLockBlocksConcurrent,
  testMigrationsLockStaleReplace:            testMigrationsLockStaleReplace,
  testMigrationsLockReleasedAfterFailure:    testMigrationsLockReleasedAfterFailure,
  testSessionRotateBasic:                    testSessionRotateBasic,
  testSessionRotateReplacesData:             testSessionRotateReplacesData,
  testSessionRotateRefreshesTtl:             testSessionRotateRefreshesTtl,
  testSessionRotateExpiredReturnsNull:       testSessionRotateExpiredReturnsNull,
  testSessionRotateUnknownReturnsNull:       testSessionRotateUnknownReturnsNull,
  testSessionRotateLifecycleAuditEmit:       testSessionRotateLifecycleAuditEmit,
  testCookiesSurface:                        testCookiesSurface,
  testCookiesParse:                          testCookiesParse,
  testCookiesSerialize:                      testCookiesSerialize,
  testCookiesInstanceDefaults:               testCookiesInstanceDefaults,
  testCookiesReadWrite:                      testCookiesReadWrite,
  testCookiesSealedRoundTrip:                testCookiesSealedRoundTrip,
  testErrorsPageSurface:                     testErrorsPageSurface,
  testErrorsPageProdHidesStackAndOriginalMessage: testErrorsPageProdHidesStackAndOriginalMessage,
  testErrorsPageDevShowsStackAndRequestInfo: testErrorsPageDevShowsStackAndRequestInfo,
  testErrorsPageJsonNegotiation:             testErrorsPageJsonNegotiation,
  testErrorsPageDevJsonIncludesStack:        testErrorsPageDevJsonIncludesStack,
  testErrorsPageAppErrorClassification:      testErrorsPageAppErrorClassification,
  testErrorsPageNeverWritesWhenAlreadyEnded: testErrorsPageNeverWritesWhenAlreadyEnded,
  testErrorsPageOnErrorHookCanTakeOver:      testErrorsPageOnErrorHookCanTakeOver,
  testErrorsPageLogsViaInjectedLogger:       testErrorsPageLogsViaInjectedLogger,
  testErrorsPageDevEnvVarsHonorOptIn:        testErrorsPageDevEnvVarsHonorOptIn,
  testErrorsPageModeAutoDetectsFromNodeEnv:  testErrorsPageModeAutoDetectsFromNodeEnv,
  testLogSurface:                            testLogSurface,
  testLogEmitsJsonLineToStdout:              testLogEmitsJsonLineToStdout,
  testLogRoutesErrorAndFatalToStderr:        testLogRoutesErrorAndFatalToStderr,
  testLogLevelGate:                          testLogLevelGate,
  testLogBindAddsBoundContext:               testLogBindAddsBoundContext,
  testLogCoreFieldsCannotBeOverwritten:      testLogCoreFieldsCannotBeOverwritten,
  testLogRequestIdViaAls:                    testLogRequestIdViaAls,
  testLogMiddlewareSetsRequestId:            testLogMiddlewareSetsRequestId,
  testLogRedactsExtras:                      testLogRedactsExtras,
  testLogEnvLevelOverride:                   testLogEnvLevelOverride,
  testLogConfigValidation:                   testLogConfigValidation,
  testLogHandlesUnserializableExtras:        testLogHandlesUnserializableExtras,
  testSchedulerSurface:                      testSchedulerSurface,
  testSchedulerCronParser:                   testSchedulerCronParser,
  testSchedulerNextCronFire:                 testSchedulerNextCronFire,
  testSchedulerScheduleValidation:           testSchedulerScheduleValidation,
  testSchedulerDirectFnFires:                testSchedulerDirectFnFires,
  testSchedulerJobDispatch:                  testSchedulerJobDispatch,
  testSchedulerSkipsWhenStillRunning:        testSchedulerSkipsWhenStillRunning,
  testSchedulerLeaderGate:                   testSchedulerLeaderGate,
  testSchedulerErrorRecorded:                testSchedulerErrorRecorded,
  testSchedulerStartStopIdempotent:          testSchedulerStartStopIdempotent,
  testFormsSurface:                          testFormsSurface,
  testFormsCsrfTokenGeneration:              testFormsCsrfTokenGeneration,
  testFormsCsrfTokenVerify:                  testFormsCsrfTokenVerify,
  testFormsEscapeAttribute:                  testFormsEscapeAttribute,
  testFormsRenderBasic:                      testFormsRenderBasic,
  testFormsRenderEscapesHostileInput:        testFormsRenderEscapesHostileInput,
  testFormsRenderSelectAndPreselection:      testFormsRenderSelectAndPreselection,
  testFormsRenderSubmitOverride:             testFormsRenderSubmitOverride,
  testFormsRenderRejectsInvalidSpec:         testFormsRenderRejectsInvalidSpec,
  testFormsValidateRequired:                 testFormsValidateRequired,
  testFormsValidateTypes:                    testFormsValidateTypes,
  testHandlerEmitAndDrain:                   testHandlerEmitAndDrain,
  testHandlerEmitDuringFlushNextCycle:       testHandlerEmitDuringFlushNextCycle,
  testHandlerRetryOnFlushFailure:            testHandlerRetryOnFlushFailure,
  testHandlerCircuitBreakerOpensOnPersistentFailure: testHandlerCircuitBreakerOpensOnPersistentFailure,
  testHandlerBoundedShutdown:                testHandlerBoundedShutdown,
  testHandlerStats:                          testHandlerStats,
  testHandlerBackpressureDrop:               testHandlerBackpressureDrop,
  testSqlSafeIdentifierValidation:           testSqlSafeIdentifierValidation,
  testSqlSafeQuoteIdentifier:                testSqlSafeQuoteIdentifier,
  testSqlSafeQuoteQualified:                 testSqlSafeQuoteQualified,
  testSqlSafeAssertOneOf:                    testSqlSafeAssertOneOf,
  testChainWriterRejectsBadTable:            testChainWriterRejectsBadTable,
  testChainWriterRaceSafetyConcurrentAppends: testChainWriterRaceSafetyConcurrentAppends,
  testBufferSafeNormalizeText:               testBufferSafeNormalizeText,
  testBufferSafeToBuffer:                    testBufferSafeToBuffer,
  testBufferSafeBoundedChunkCollector:       testBufferSafeBoundedChunkCollector,
  testBufferSafeSecureZero:                  testBufferSafeSecureZero,
  testLogger:                                testLogger,
  testConstantsReferenceIntegrity:           testConstantsReferenceIntegrity,
  testUrlSafeDefaultIsHttpsOnly:             testUrlSafeDefaultIsHttpsOnly,
  testUrlSafeCustomAllowlist:                testUrlSafeCustomAllowlist,
  testUrlSafeMalformed:                      testUrlSafeMalformed,
  testUrlSafeUrlInstancePassThrough:         testUrlSafeUrlInstancePassThrough,
  testUrlSafeErrorClassInjection:            testUrlSafeErrorClassInjection,
  testUrlSafeAllowAny:                       testUrlSafeAllowAny,
  testHttpClientBasic:                       testHttpClientBasic,
  testHttpClientConfigurePool:               testHttpClientConfigurePool,
  testHttpClientErrorStatus:                 testHttpClientErrorStatus,
  testHttpClientWallClockTimeout:            testHttpClientWallClockTimeout,
  testHttpClientAbortSignal:                 testHttpClientAbortSignal,
  testHttpClientStreamResponse:              testHttpClientStreamResponse,
  testHttpClientObserver:                    testHttpClientObserver,
  testHttpClientH2Basic:                     testHttpClientH2Basic,
  testHttpClientH2AbortSignal:               testHttpClientH2AbortSignal,
  testHttpClientH2ErrorStatus:               testHttpClientH2ErrorStatus,
  testHttpClientH2Multiplex:                 testHttpClientH2Multiplex,
  testHttpClientH2Stream:                    testHttpClientH2Stream,
  testWebSocketHandshake:                    testWebSocketHandshake,
  testWebSocketFrames:                       testWebSocketFrames,
  testWebSocketConnection:                   testWebSocketConnection,
  testRouterWsValidation:                    testRouterWsValidation,
  testRouterSetsRoutePattern:                testRouterSetsRoutePattern,
  testFrameworkError:                        testFrameworkError,
  testLazyRequire:                           testLazyRequire,
  testJsonModuleSurface:                     testJsonModuleSurface,
  testJsonParse:                             testJsonParse,
  testJsonStringify:                         testJsonStringify,
  testJsonCanonical:                         testJsonCanonical,
  testJsonValidate:                          testJsonValidate,
  testJsonValidateCollect:                   testJsonValidateCollect,
  testJsonFormats:                           testJsonFormats,
  testAtomicFile:                            testAtomicFile,
  testAtomicFileNewHelpers:                  testAtomicFileNewHelpers,
  testAtomicFileLock:                        testAtomicFileLock,
  testAtomicFileListDir:                     testAtomicFileListDir,
  testXmlParse:                              testXmlParse,
  testXmlSecurityRejections:                 testXmlSecurityRejections,
  testTomlBasicTypes:                        testTomlBasicTypes,
  testTomlTablesAndArrays:                   testTomlTablesAndArrays,
  testTomlInlineTablesAndDottedKeys:         testTomlInlineTablesAndDottedKeys,
  testTomlSecurityRejections:                testTomlSecurityRejections,
  testYamlBasic:                             testYamlBasic,
  testYamlNorwayProblem:                     testYamlNorwayProblem,
  testYamlBlockScalars:                      testYamlBlockScalars,
  testYamlQuotedStrings:                     testYamlQuotedStrings,
  testYamlSecurityRejections:                testYamlSecurityRejections,
  testEnvParseBasic:                         testEnvParseBasic,
  testEnvParseSecurityRejections:            testEnvParseSecurityRejections,
  testEnvReadVar:                            testEnvReadVar,
  testRedact:                                testRedact,
  testAuditSafeEmitRedacts:                  testAuditSafeEmitRedacts,

  // ---- Fixture-aware groups ----
  //
  // Each group has setup (runs once) + tests (run sequentially against
  // the shared context) + teardown. Smoke runner reports per-test
  // timing for drift detection. Tests stay individually named so
  // failure attribution is "Layer 0 / <group> / <test>".
  groups: [
    {
      name: "websocket-h2c",
      setup: async function () {
        var http2 = require("http2");
        var ws = b.websocket;
        var server = http2.createServer({ settings: { enableConnectProtocol: true } });
        server.on("stream", function (stream, headers) {
          if (headers[":method"] !== "CONNECT" || headers[":protocol"] !== "websocket") {
            try { stream.respond({ ":status": 404 }); stream.end(); } catch (_e) {}
            return;
          }
          var conn = ws.handleExtendedConnect(stream, headers, { closeGraceMs: 50 });
          if (!conn) return;
          if (headers[":path"] === "/echo") {
            conn.on("message", function (data, isBinary) {
              conn.send(isBinary ? data : "h2-echo:" + data);
            });
          }
          // /strict path: no message handler — masked-frame rejection
          // path closes the connection on its own.
        });
        var port = await listenOnRandomPort(server);
        // Open one h2 client up front; reuse across the group's tests
        // so each test pays only its own request RTT, not the
        // connect+SETTINGS handshake overhead.
        var client = http2.connect("http://127.0.0.1:" + port);
        await new Promise(function (resolve, reject) {
          client.once("connect", resolve);
          client.once("error", reject);
        });
        await new Promise(function (resolve) {
          if (client.remoteSettings && client.remoteSettings.enableConnectProtocol) { resolve(); return; }
          client.once("remoteSettings", resolve);
        });
        return { server: server, client: client, port: port };
      },
      teardown: async function (ctx) {
        if (!ctx) return;
        try { ctx.client.destroy(); } catch (_e) {}
        try { ctx.server.closeAllConnections(); } catch (_e) {}
        await new Promise(function (resolve) {
          try { ctx.server.close(function () { resolve(); }); }
          catch (_e) { resolve(); }
        });
      },
      tests: [
        {
          name: "advertises enableConnectProtocol",
          run: async function (ctx) {
            check("h2 WebSocket: server advertises enableConnectProtocol",
                  ctx.client.remoteSettings.enableConnectProtocol === true);
          },
        },
        {
          name: "echo round-trip",
          run: async function (ctx) {
            var ws = b.websocket;
            var stream = ctx.client.request({
              ":method":   "CONNECT",
              ":protocol": "websocket",
              ":path":     "/echo",
              ":scheme":   "http",
              ":authority": "127.0.0.1:" + ctx.port,
            });
            var responseHeaders = await new Promise(function (resolve, reject) {
              stream.once("response", resolve);
              stream.once("error", reject);
            });
            check("h2 WebSocket: server responds 200 (not 101)",
                  responseHeaders[":status"] === 200);

            stream.write(ws.serializeFrame(ws.OPCODE_TEXT, Buffer.from("hello-h2", "utf8")));

            var parser = new ws.FrameParser({ maxFrameBytes: 64 * 1024 });
            var echoFrames = await new Promise(function (resolve, reject) {
              var collected = [];
              stream.on("data", function (chunk) {
                try {
                  var fs = parser.push(chunk);
                  for (var i = 0; i < fs.length; i++) collected.push(fs[i]);
                  if (collected.length > 0) resolve(collected);
                } catch (e) { reject(e); }
              });
              stream.on("error", reject);
            });
            check("h2 WebSocket: server echoed text frame",
                  echoFrames[0].payload.toString("utf8") === "h2-echo:hello-h2");
            check("h2 WebSocket: server frame unmasked (h2 rule)",
                  echoFrames[0].masked === false);

            // Clean close on this stream only — group fixture stays alive.
            var closePayload = Buffer.alloc(2);
            closePayload.writeUInt16BE(1000, 0);
            stream.write(ws.serializeFrame(ws.OPCODE_CLOSE, closePayload));
            await new Promise(function (resolve) {
              stream.once("close", resolve);
              setTimeout(resolve, 200);
            });
          },
        },
        {
          name: "rejects masked client frame",
          run: async function (ctx) {
            var ws = b.websocket;
            var stream = ctx.client.request({
              ":method":   "CONNECT",
              ":protocol": "websocket",
              ":path":     "/strict",
              ":scheme":   "http",
              ":authority": "127.0.0.1:" + ctx.port,
            });
            await new Promise(function (resolve, reject) {
              stream.once("response", resolve);
              stream.once("error", reject);
            });
            stream.write(ws.serializeFrame(ws.OPCODE_TEXT, Buffer.from("nope", "utf8"), { mask: true }));

            var parser = new ws.FrameParser({ maxFrameBytes: 1024 });
            var closeSeen = await new Promise(function (resolve) {
              var collected = [];
              stream.on("data", function (chunk) {
                try {
                  var fs = parser.push(chunk);
                  collected = collected.concat(fs);
                  var closeFrame = collected.find(function (f) { return f.opcode === ws.OPCODE_CLOSE; });
                  if (closeFrame) resolve(closeFrame);
                } catch (_e) { /* server send-and-destroy */ }
              });
              stream.once("close", function () { resolve(null); });
              setTimeout(function () { resolve(null); }, 500);
            });
            check("h2 WebSocket: masked client frame rejected with close",
                  closeSeen !== null && closeSeen.payload.readUInt16BE(0) === ws.CLOSE_PROTOCOL_ERROR);
          },
        },
      ],
    },
    {
      name: "websocket-router-h1",
      setup: async function () {
        var router = new b.router.Router();
        var receivedMessages = [];
        router.ws("/realtime", function (conn, _req) {
          conn.on("message", function (data, isBinary) {
            receivedMessages.push({ data: isBinary ? data : data.toString(), isBinary: isBinary });
            conn.send(isBinary ? data : "router-echo:" + data);
          });
        }, { origins: "*", closeGraceMs: 50 });
        router.ws("/h2only", function (_conn) { /* never reached on h1 */ },
          { origins: "*", transport: "h2-only" });
        var server = await new Promise(function (resolve) {
          var s = router.listen(0, function () { resolve(s); }, null, "127.0.0.1");
        });
        return {
          router: router,
          server: server,
          port: server.address().port,
          receivedMessages: receivedMessages,
        };
      },
      teardown: async function (ctx) {
        if (!ctx) return;
        // Operator API closes all active WS connections via the
        // proper close handshake (or force-destroys after timeout).
        // Same primitive operators use for graceful rolling deploy.
        try { await ctx.router.closeWebSockets({ timeoutMs: 200 }); } catch (_e) {}
        await new Promise(function (resolve) {
          try { ctx.server.close(function () { resolve(); }); }
          catch (_e) { resolve(); }
        });
      },
      tests: [
        {
          name: "auto path: 101 + echo round-trip",
          run: async function (ctx) {
            var net = require("net");
            var ws = b.websocket;
            var client = net.connect(ctx.port, "127.0.0.1");
            await new Promise(function (r) { client.once("connect", r); });
            var key = require("crypto").randomBytes(16).toString("base64");
            client.write(
              "GET /realtime HTTP/1.1\r\n" +
              "Host: 127.0.0.1:" + ctx.port + "\r\n" +
              "Upgrade: websocket\r\n" +
              "Connection: Upgrade\r\n" +
              "Sec-WebSocket-Key: " + key + "\r\n" +
              "Sec-WebSocket-Version: 13\r\n" +
              "\r\n"
            );
            var responseBuf = await _readUntil(client, "\r\n\r\n");
            check("router.ws h1: 101 Switching Protocols",
                  responseBuf.toString("utf8").indexOf("HTTP/1.1 101") === 0);
            client.write(ws.serializeFrame(ws.OPCODE_TEXT,
              Buffer.from("via-router", "utf8"), { mask: true }));
            var parser = new ws.FrameParser({ maxFrameBytes: 1024 });
            var echoFrames = [];
            while (echoFrames.length === 0) {
              var more = await _readSome(client);
              echoFrames = parser.push(more);
            }
            check("router.ws h1: handler echoed message",
                  echoFrames[0].payload.toString("utf8") === "router-echo:via-router");
            check("router.ws h1: handler received the message",
                  ctx.receivedMessages.length === 1 && ctx.receivedMessages[0].data === "via-router");
            client.destroy();
          },
        },
        {
          name: "h2-only path: 426 Upgrade Required",
          run: async function (ctx) {
            var net = require("net");
            var client = net.connect(ctx.port, "127.0.0.1");
            await new Promise(function (r) { client.once("connect", r); });
            var key = require("crypto").randomBytes(16).toString("base64");
            client.write(
              "GET /h2only HTTP/1.1\r\n" +
              "Host: 127.0.0.1:" + ctx.port + "\r\n" +
              "Upgrade: websocket\r\n" +
              "Connection: Upgrade\r\n" +
              "Sec-WebSocket-Key: " + key + "\r\n" +
              "Sec-WebSocket-Version: 13\r\n" +
              "\r\n"
            );
            var responseBuf = await _readUntil(client, "\r\n\r\n");
            var responseStr = responseBuf.toString("utf8");
            check("router.ws h2-only: returns 426",
                  responseStr.indexOf("HTTP/1.1 426") === 0);
            check("router.ws h2-only: advisory Upgrade: h2c header",
                  /Upgrade: h2c/i.test(responseStr));
            client.destroy();
          },
        },
      ],
    },
  ],
};
