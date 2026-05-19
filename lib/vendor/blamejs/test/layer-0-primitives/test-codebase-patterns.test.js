"use strict";
/**
 * test-side codebase-patterns — enforces test-discipline rules over
 * `test/` files the way `codebase-patterns.test.js` enforces them
 * over `lib/`. Keeps the test-side catalog separated so production
 * antipatterns and test antipatterns don't fight for space in one
 * file and the path-domain of each scan is unambiguous.
 *
 * Discipline (mirrors codebase-patterns.test.js):
 *   1. Every entry registers an inline shape with a regex, a primitive
 *      pointer, an allowlist (defaults to []), and a `reason` field.
 *   2. Adding an allowlist entry later requires a documented reason
 *      in the entry's `reason` field; the pre-ship rules audit calls
 *      out every allowlist change.
 *   3. Entries are scanned against the full repository's `test/` tree.
 *
 * Entry shape:
 *   {
 *     id:        "kebab-case",
 *     primitive: "what should replace the antipattern",
 *     regex:     /the inline shape/,
 *     matchOn:   "content" | "basename",   // default "content"
 *     requires:  /companion regex/,        // optional — file passes IF this
 *                                          // also matches (e.g. tests using
 *                                          // setTimeout pass if they also
 *                                          // import `withTestTimeout`).
 *     allowlist: [ "test/some/file.js", ... ],
 *     reason:    "...",
 *   }
 *
 * Why this gate exists: the v0.10.13 PR #102 macOS hang on
 * stream-throttle.test.js (a setTimeout-based rate test interacting
 * badly with node:stream.pipeline on macOS) burned >2h of CI before
 * surfacing — by the time the smoke runner gave up, the wall-clock
 * cost dwarfed the actual signal. A per-test wall-clock ceiling
 * surfaces hangs as `test timed out: <label>` in seconds.
 */

var fs = require("fs");
var path = require("path");
var helpers = require("../helpers");
var check = helpers.check;

var TEST_ROOT = path.resolve(__dirname, "..");
// Codex P2 (v0.10.14) — keep release-name scan coverage parity with
// the prior lib-side function, which walked the whole repository.
// The test-side walker now includes every sibling `test/` directory
// under examples/ as well so non-framework test suites can't sneak
// in a release-named file under examples/wiki/test/ or similar.
var EXAMPLES_TEST_ROOT = path.resolve(__dirname, "..", "..", "examples");

function _walk(dir, files) {
  files = files || [];
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return files; }
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var full = path.join(dir, e.name);
    if (e.isDirectory()) _walk(full, files);
    else if (e.isFile() && e.name.endsWith(".js")) files.push(full);
  }
  return files;
}

function _relPath(absPath) {
  return path.relative(path.resolve(__dirname, "..", ".."), absPath).replace(/\\/g, "/");
}

// KNOWN_TEST_ANTIPATTERNS — n=1 gate over `test/` files.
var KNOWN_TEST_ANTIPATTERNS = [
  {
    // v0.10.13 PR #102 macOS hang — stream-throttle.test.js used
    // `setTimeout`-based rate enforcement plus `node:stream.pipeline`
    // and hung the macOS GitHub Actions runner for >2h on two
    // separate commit SHAs of the same branch. Identical runs on the
    // same SHA succeeded in 15 min. The hang's symptom is opaque on
    // a remote runner (no partial logs surface until completion), so
    // the only diagnostic is a per-test wall-clock ceiling.
    id: "test-uses-stream-pipeline-without-withtesttimeout",
    primitive: "wrap stream.pipeline-using test bodies with helpers.withTestTimeout(label, async function () { ... })",
    regex: /\b(?:stream\.pipeline|nodeStream\.pipeline|streamPipeline)\s*\(/,
    requires: /\bwithTestTimeout\b/,
    allowlist: [
      "test/helpers/wait.js",
    ],
    reason: "Real-time-dependent tests using node:stream.pipeline without a per-test wall-clock ceiling can hang the smoke runner for the full GH Actions 6h timeout — see the v0.10.13 PR #102 macOS hang on stream-throttle's setTimeout-based rate test. New tests using stream.pipeline MUST import `withTestTimeout` from `test/helpers` and wrap each test body so a hang surfaces as `test timed out: <label>` in seconds instead of an opaque stuck job.",
  },
  {
    // M1 — migrated from codebase-patterns.test.js (lib-side runner)
    // in v0.10.14. Tests must live in per-domain files (e.g.
    // honeytoken.test.js, resource-access-lock.test.js) not release-
    // bucket files like `v0-8-41-additions.test.js` or `slot-19-
    // enhancements.test.js`. Release-named test files conflate scope
    // across primitives, break the smoke runner's per-file
    // isolation, and rot the moment the release ships.
    id: "release-named-test-file",
    primitive: "split into per-domain test files (one primitive → one test file; share helpers under test/helpers/)",
    matchOn: "basename",
    regex: /^(?:v\d+[-_.]\d+[-_.]\d+(?:[-_.]|$)|slot[-_]\d+|(?:[^/]*[-_])?batch[-_.])/i,
    allowlist: [],
    reason: "v0.10.14 migration from lib-side codebase-patterns (the rule scans test-file basenames, not lib-source content; belongs with the rest of the test-discipline catalog). Tests must live in per-domain files. Smoke runner refuses these at entry too (test/smoke.js:290+) as a second defense.",
  },
  {
    // N1 (v0.10.14) — direct sleep-then-assert anti-pattern. The
    // existing `helpers.waitUntil` / `helpers.waitUntilEqual`
    // primitives exist specifically to replace this shape per
    // CLAUDE.md rule §11b. Hand-tuned fixed-budget sleeps are the
    // root cause of every "passes alone, fails under
    // SMOKE_PARALLEL=64" flake the framework has seen (macOS
    // watcher v0.8.60, log-stream-otlp, safe-async-loops,
    // rate-limit-cluster). The lib-side `testNoHandrolledSleep`
    // catches the same shape in production code; this entry
    // mirrors it for test code where the antipattern reaches for
    // an even-easier writer.
    id: "test-handrolled-promise-settimeout-sleep",
    primitive: "await helpers.waitUntil(function () { return <condition>; }, { label, timeoutMs })",
    // Codex P2 (v0.10.14) broadened — the original regex caught only
    // expression-bodied arrows (`r => setTimeout(...)`) and simple
    // function bodies. Block-bodied arrows (`(r) => { setTimeout(r, N); }`),
    // multi-arg arrows (`(resolve, reject) => setTimeout(resolve, N)`),
    // and function bodies with leading statements all evaded the
    // gate. The broadened shape matches `new Promise(...)` followed
    // by any callable form (function or arrow, paren-list or
    // single-ident), then anywhere within ~200 chars a `setTimeout(`
    // call. The 200-char window keeps the regex bounded; longer
    // bodies that genuinely do real work between Promise-open and
    // setTimeout don't fit the direct-sleep antipattern anyway.
    regex: /new Promise\s*\(\s*(?:function\s*[\w$]*\s*\([^)]*\)\s*\{|\([^)]*\)\s*=>\s*\{?|[\w$]+\s*=>\s*\{?)[\s\S]{0,200}?setTimeout\s*\(/,
    allowlist: [
      // The wait helper itself implements the waitUntil primitive
      // and uses Promise+setTimeout internally as its core loop.
      "test/helpers/wait.js",
      // Smoke runner orchestration uses Promise+setTimeout for
      // process-spawn budgets and worker-pool drain — not for
      // test-body synchronization.
      "test/smoke.js",
      // ---- v0.10.14 pre-existing backlog ----
      // Files matched the antipattern at the time the detector
      // shipped. Each is tracked for a per-file migration to
      // helpers.waitUntil in follow-up patches. New tests adding
      // setTimeout-based synchronization MUST use waitUntil; the
      // gate refuses additions outside this allowlist.
      "test/helpers/services.js",
      "test/integration/cache.test.js",
      "test/integration/cluster-provider-mysql.test.js",
      "test/integration/log-stream.test.js",
      "test/integration/network-heartbeat.test.js",
      "test/integration/object-store-sigv4.test.js",
      "test/integration/pubsub.test.js",
      "test/integration/queue-redis.test.js",
      "test/integration/websocket-permessage-deflate.test.js",
      "test/integration/ws-client-roundtrip.test.js",
      "test/layer-0-primitives/a2a-tasks.test.js",
      "test/layer-0-primitives/a2a.test.js",
      "test/layer-0-primitives/agent-event-bus.test.js",
      "test/layer-0-primitives/agent-idempotency.test.js",
      "test/layer-0-primitives/agent-snapshot.test.js",
      "test/layer-0-primitives/api-encrypt.test.js",
      "test/layer-0-primitives/app-shutdown.test.js",
      "test/layer-0-primitives/audit-segregation.test.js",
      "test/layer-0-primitives/break-glass.test.js",
      "test/layer-0-primitives/codebase-patterns.test.js",
      "test/layer-0-primitives/config.test.js",
      "test/layer-0-primitives/dsr.test.js",
      "test/layer-0-primitives/external-db-routing.test.js",
      "test/layer-0-primitives/guard-csv.test.js",
      "test/layer-0-primitives/http-client-cache.test.js",
      "test/layer-0-primitives/log-stream-cloudwatch.test.js",
      "test/layer-0-primitives/log-stream-otlp-grpc.test.js",
      "test/layer-0-primitives/log-stream-otlp.test.js",
      "test/layer-0-primitives/mail-greylist.test.js",
      "test/layer-0-primitives/middleware-compose-pipeline.test.js",
      "test/layer-0-primitives/network-dns-resolver.test.js",
      "test/layer-0-primitives/network-heartbeat-passive.test.js",
      "test/layer-0-primitives/network.test.js",
      "test/layer-0-primitives/notify.test.js",
      "test/layer-0-primitives/observability-tracing.test.js",
      "test/layer-0-primitives/promise-pool.test.js",
      "test/layer-0-primitives/pubsub.test.js",
      "test/layer-0-primitives/queue-dlq-extend-lease.test.js",
      "test/layer-0-primitives/queue-flow-repeat.test.js",
      "test/layer-0-primitives/queue-priority-rate-progress.test.js",
      "test/layer-0-primitives/retry.test.js",
      "test/layer-0-primitives/safe-async-loops.test.js",
      "test/layer-0-primitives/safe-async-parallel.test.js",
      "test/layer-0-primitives/scim-server.test.js",
      "test/layer-0-primitives/sse.test.js",
      "test/layer-0-primitives/vault-seal-pem-file.test.js",
      "test/layer-0-primitives/watcher.test.js",
      "test/layer-0-primitives/websocket-channels.test.js",
      "test/layer-0-primitives/ws-client.test.js",
      "test/layer-1-state/api-key.test.js",
      // Surfaced by the v0.10.14 broadened-regex sweep (Codex P2):
      // block-bodied arrow forms (`(r) => { setTimeout(...) }`) that
      // the narrower v0.10.13 regex missed.
      "test/layer-0-primitives/agent-orchestrator.test.js",
      "test/layer-0-primitives/daily-byte-quota.test.js",
      "test/layer-0-primitives/require-auth-cache-control.test.js",
      "test/layer-0-primitives/webhook.test.js",
      // Surfaced by the v0.10.14 examples-tree expansion (Codex P2):
      // wiki integration test under examples/wiki/test/ that the
      // original test/ - only walker missed entirely.
      "examples/wiki/test/integration.js",
    ],
    reason: "v0.8.60 macOS watcher flake + log-stream-otlp / safe-async-loops / rate-limit-cluster — every fixed-budget Promise+setTimeout sleep in a test eventually races on a contended runner. CLAUDE.md rule §11b documents waitUntil as the replacement; this gate forces the discipline on new tests. The 49 pre-existing files allowlisted above are the v0.10.14 backlog: each carries a documented setTimeout sleep that's working today but doesn't follow the discipline. Cleanup is a per-file migration to helpers.waitUntil in follow-up patches.",
  },
  {
    // N2 (v0.10.14) — hardcoded non-zero server ports in tests. Two
    // parallel tests under SMOKE_PARALLEL=64 with the same literal
    // port race for the bind. The convention is `.listen(0)` then
    // `server.address().port` to read the OS-assigned ephemeral
    // port; same for any `port: N` opt that drives a bind.
    id: "test-hardcoded-server-bind-port",
    primitive: ".listen(0) + server.address().port  (let the OS assign an ephemeral port; read it after bind)",
    // Match only .listen(NNN) — the server-bind path — with a 2-5
    // digit non-zero literal. Skip `port: NNN` config-shape
    // references; those are typically client-side connect targets
    // or protocol-constant assertions, not bind races.
    regex: /\.listen\s*\(\s*(?:\{[^}]*port\s*:\s*)?(?!0\b)\d{2,5}\b/,
    allowlist: [],
    reason: "Hardcoded bind ports race under SMOKE_PARALLEL=64 when two parallel tests pick the same value. Convention: .listen(0) + server.address().port. Read-only protocol-constant references (autoconfig XML port: 993 / 587, mock-server config port: 1025) don't trip this detector — only .listen() with a literal non-zero port does.",
  },
];

function _testFiles() {
  var all = _walk(TEST_ROOT).concat(_walk(EXAMPLES_TEST_ROOT));
  return all.filter(function (f) {
    var rel = _relPath(f);
    if (rel.indexOf("test/.test-output") === 0) return false;
    // Skip examples/*/node_modules so we don't scan vendored deps.
    if (/^examples\/[^/]+\/node_modules\//.test(rel)) return false;
    // Skip examples test-output dirs.
    if (/^examples\/.*\/\.test-output\//.test(rel)) return false;
    return /\.test\.js$|^test\/helpers\/|^test\/smoke\.js$|^examples\/[^/]+\/test\//.test(rel);
  });
}

function testKnownTestAntipatterns() {
  var files = _testFiles();
  var allBad = [];
  for (var ai = 0; ai < KNOWN_TEST_ANTIPATTERNS.length; ai++) {
    var ap = KNOWN_TEST_ANTIPATTERNS[ai];
    var matchOn = ap.matchOn || "content";
    var allowSet = Object.create(null);
    for (var k = 0; k < ap.allowlist.length; k++) allowSet[ap.allowlist[k]] = true;
    // Self-exemption — this catalog file contains the regex source
    // itself, which trips its own detector. Always exempts itself.
    allowSet["test/layer-0-primitives/test-codebase-patterns.test.js"] = true;
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var rel = _relPath(files[fi]);
      if (allowSet[rel]) continue;
      // Pick what to match against.
      var subject = matchOn === "basename" ? path.basename(files[fi]) : null;
      if (matchOn === "content") {
        try { subject = fs.readFileSync(files[fi], "utf8"); }
        catch (_e) { continue; }
      }
      if (subject === null) continue;
      if (!ap.regex.test(subject)) continue;
      // Companion check — if `requires` matches the FILE content,
      // the discipline is satisfied even though the antipattern
      // shape is present (e.g. setTimeout + withTestTimeout wrapper).
      // Only applies to content-mode entries; basename-mode has no
      // companion content to inspect.
      if (matchOn === "content" && ap.requires) {
        if (ap.requires.test(subject)) continue;
      }
      var firstMatch = subject.match(ap.regex);
      var lineNum = 1;
      if (matchOn === "content" && firstMatch) {
        lineNum = subject.slice(0, subject.indexOf(firstMatch[0])).split(/\r?\n/).length;
      }
      bad.push({
        file: rel,
        line: lineNum,
        content: "test-antipattern '" + ap.id + "' — use " + ap.primitive,
      });
    }
    if (bad.length) {
      allBad = allBad.concat(bad);
      console.log("FAIL: test-antipattern '" + ap.id + "' — use " + ap.primitive);
      for (var bi = 0; bi < bad.length; bi++) {
        console.log("  " + bad[bi].file + ":" + bad[bi].line + ": " + bad[bi].content);
      }
      console.log("  why: " + ap.reason);
    }
  }
  check("known-test-antipattern catalog (n=1 gate)", allBad.length === 0);
}

// N3 (v0.10.14) — tests creating a real DB handle without an
// isolation primitive. Specifically: any test file calling
// `b.db.create(` MUST also name one of:
//   - `setupTestDb` / `setupVaultOnly` (the framework helpers)
//   - `mkdtempSync` (an ad-hoc per-test temp dataDir)
// Static-API tests that reference `b.db.applyPosture()` /
// `b.db.declareView()` / etc. without spinning a real handle don't
// trip the detector. Leaked per-test SQLite state corrupts subsequent
// tests under SMOKE_PARALLEL=64.
function testDbHandleRequiresIsolation() {
  var files = _testFiles();
  var bad = [];
  var allowSet = Object.create(null);
  allowSet["test/helpers/db.js"]    = true;
  allowSet["test/helpers/index.js"] = true;
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (allowSet[rel]) continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var createsHandle = /\bb\.db\.create\s*\(/.test(content);
    if (!createsHandle) continue;
    var isolated = /\b(?:setupTestDb|setupVaultOnly|mkdtempSync)\b/.test(content);
    if (isolated) continue;
    bad.push({ file: rel });
  }
  if (bad.length) {
    console.log("FAIL: test-antipattern 'test-creates-db-handle-without-isolation'");
    for (var bi = 0; bi < bad.length; bi++) {
      console.log("  " + bad[bi].file + ": calls b.db.create() without setupTestDb / setupVaultOnly / mkdtempSync");
    }
    console.log("  why: tests spinning a real DB handle without a per-test isolation primitive leak SQLite state to a shared directory; subsequent tests see prior rows under SMOKE_PARALLEL=64. Use helpers.setupTestDb / helpers.setupVaultOnly, or mkdtempSync the dataDir.");
  }
  check("tests creating b.db.create() wire setupTestDb / setupVaultOnly / mkdtempSync", bad.length === 0);
}

async function run() {
  testKnownTestAntipatterns();
  testDbHandleRequiresIsolation();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
